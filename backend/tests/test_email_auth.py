"""Tests for the email-authentication modules (Member 3).

Everything runs offline: DNS is served by ``FakeResolver``. DKIM test messages are signed
with the independent ``dkimpy`` library (a project dependency) so our verifier is checked
against a second implementation, not just against itself.
"""

from __future__ import annotations

import base64
import hashlib
import time

import dkim as dkimpy
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from backend.analysis import (
    EmailParseError,
    FakeResolver,
    authenticate_email,
    check_dkim,
    check_spf,
    evaluate_dmarc,
    organizational_domain,
    parse_email,
)
from backend.analysis import dkim_check as dk
from backend.analysis.dmarc_check import domains_aligned, parse_dmarc_record
from backend.analysis.email_parser import split_raw_message

GOOD_IP = "192.0.2.10"
BAD_IP = "198.51.100.66"


# ======================================================================================
# helpers
# ======================================================================================
def make_message(
    *,
    from_addr: str = "alice@example.com",
    to: str = "bob@company.test",
    subject: str = "Hello",
    body: str = "Hi Bob,\r\n\r\nLunch tomorrow?\r\n",
    extra_headers: str = "",
) -> bytes:
    return (
        f"From: Alice <{from_addr}>\r\n"
        f"To: {to}\r\n"
        f"Subject: {subject}\r\n"
        "Date: Mon, 19 Oct 2026 10:00:00 +0000\r\n"
        "Message-ID: <abc123@example.com>\r\n"
        f"{extra_headers}"
        "\r\n"
        f"{body}"
    ).encode()


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def rsa_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def rsa_dns_record(key, extra: str = "") -> str:
    der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return f"v=DKIM1; k=rsa; {extra}p={base64.b64encode(der).decode()}"


def sign_rsa(msg: bytes, key, *, domain="example.com", selector="sel1", canon=("relaxed", "relaxed"),
             algo=b"rsa-sha256", include=(b"from", b"to", b"subject", b"date")) -> bytes:
    sig = dkimpy.sign(
        msg,
        selector.encode(),
        domain.encode(),
        rsa_pem(key),
        canonicalize=(canon[0].encode(), canon[1].encode()),
        signature_algorithm=algo,
        include_headers=list(include),
    )
    return sig + msg


def dkim_resolver(key, domain="example.com", selector="sel1", extra: str = "") -> FakeResolver:
    return FakeResolver(txt={f"{selector}._domainkey.{domain}": rsa_dns_record(key, extra)})


# ======================================================================================
# email_parser
# ======================================================================================
MULTIPART = (
    b"Return-Path: <bounce@mail.example.co.uk>\r\n"
    b"Received: from mx.evil.test ([203.0.113.9]) by gw.company.test with ESMTP; Mon, 19 Oct 2026\r\n"
    b"Received: from relay.test ([8.8.4.4]) by mx.evil.test with ESMTP; Mon, 19 Oct 2026\r\n"
    b"X-Originating-IP: [8.8.8.8]\r\n"
    b"From: =?utf-8?q?Pay=C2=A0Pal?= <Security@PayPa1.com>\r\n"
    b"Reply-To: attacker@evil.test\r\n"
    b"To: Bob <bob@company.test>, carol@company.test\r\n"
    b"Subject: =?utf-8?q?Urgent_=E2=80=93_verify?=\r\n"
    b"Date: Mon, 19 Oct 2026 10:00:00 +0000\r\n"
    b"Message-ID: <m1@evil.test>\r\n"
    b"MIME-Version: 1.0\r\n"
    b'Content-Type: multipart/mixed; boundary="B"\r\n'
    b"\r\n"
    b"--B\r\n"
    b'Content-Type: multipart/alternative; boundary="A"\r\n'
    b"\r\n"
    b"--A\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nplain body\r\n"
    b"--A\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>html <b>body</b></p>\r\n"
    b"--A--\r\n"
    b"--B\r\n"
    b'Content-Type: application/pdf; name="inv.pdf"\r\n'
    b'Content-Disposition: attachment; filename="..\\..\\inv\x07oice.pdf.exe"\r\n'
    b"Content-Transfer-Encoding: base64\r\n\r\n" + base64.b64encode(b"%PDF-fake") + b"\r\n"
    b"--B--\r\n"
)


def test_parser_headers_addresses_and_bodies():
    p = parse_email(MULTIPART)
    assert p.subject == "Urgent – verify"
    assert p.from_address == "security@paypa1.com"
    assert p.from_domain == "paypa1.com"
    assert "Pay" in p.from_display
    assert p.return_path == "bounce@mail.example.co.uk"
    assert p.return_path_domain == "mail.example.co.uk"
    assert p.reply_to == ["attacker@evil.test"]
    assert p.to == ["bob@company.test", "carol@company.test"]
    assert p.message_id == "<m1@evil.test>"
    assert p.date is not None and p.date.year == 2026
    assert p.body_text.strip() == "plain body"
    assert "html" in p.body_html
    assert "html body" in p.body_html.replace("<b>", "").replace("</b>", "")
    assert p.header("subject") == p.subject
    assert p.anomalies == []


def test_parser_attachment_and_trace():
    p = parse_email(MULTIPART)
    assert len(p.attachments) == 1
    att = p.attachments[0]
    assert att.content == b"%PDF-fake"
    assert att.sha256 == hashlib.sha256(b"%PDF-fake").hexdigest()
    assert att.size == 9
    assert "\x07" not in att.safe_filename and "\\" not in att.safe_filename
    assert att.safe_filename.endswith(".pdf.exe")
    assert len(p.received) == 2
    assert p.received_ips == ["203.0.113.9", "8.8.4.4"]  # top of chain first
    assert p.x_originating_ip == "8.8.8.8"
    assert p.guess_client_ip() == "8.8.4.4"  # 203.0.113.x is a documentation range


def test_parser_to_dict_is_json_safe():
    import json

    json.dumps(parse_email(MULTIPART).to_dict())


def test_parser_text_for_analysis_falls_back_to_html():
    raw = (
        b"From: a@b.test\r\nContent-Type: text/html\r\n\r\n"
        b"<style>p{}</style><script>x()</script><p>Click <a href='x'>here</a></p>\r\n"
    )
    assert parse_email(raw).text_for_analysis == "Click here"


def test_parser_anomalies_and_null_sender():
    p = parse_email(b"Return-Path: <>\r\nSubject: x\r\n\r\nbody")
    assert p.return_path == ""
    assert "missing From header" in p.anomalies
    p2 = parse_email(b"From: a@x.test\r\nFrom: b@y.test\r\n\r\nb")
    assert "multiple From headers" in p2.anomalies


def test_parser_idn_domain_is_punycode():
    p = parse_email("From: x <user@bücher.example>\r\n\r\nhi".encode())
    assert p.from_domain == "xn--bcher-kva.example"


def test_parser_handles_lf_only_and_str_input():
    p = parse_email("From: a@x.test\nSubject: hi\n\nbody\n")
    assert p.from_domain == "x.test" and p.body_text.strip() == "body"
    assert b"\n" not in p.raw.replace(b"\r\n", b"")  # fully CRLF-normalised


@pytest.mark.parametrize("bad", [b"", b"   \r\n  ", 123])
def test_parser_rejects_unusable_input(bad):
    with pytest.raises(EmailParseError):
        parse_email(bad)


def test_split_raw_message_keeps_folding():
    headers, body = split_raw_message(b"Subject: a\r\n b\r\nFrom: x@y.test\r\n\r\nhello")
    assert [h.name for h in headers] == ["Subject", "From"]
    assert headers[0].raw == b"Subject: a\r\n b\r\n"
    assert headers[0].value == "a b"
    assert body == b"hello"


def test_parser_attached_message_is_single_attachment():
    inner = b"From: inner@x.test\r\nSubject: inner\r\n\r\ninner body\r\n"
    raw = (
        b"From: outer@x.test\r\nContent-Type: multipart/mixed; boundary=Z\r\n\r\n"
        b"--Z\r\nContent-Type: text/plain\r\n\r\nouter\r\n"
        b"--Z\r\nContent-Type: message/rfc822\r\n\r\n" + inner + b"--Z--\r\n"
    )
    p = parse_email(raw)
    assert p.body_text.strip() == "outer"
    assert len(p.attachments) == 1 and p.attachments[0].content_type == "message/rfc822"


# ======================================================================================
# SPF
# ======================================================================================
def spf(record, ip=GOOD_IP, sender="user@example.com", helo="mail.example.com", **dns):
    resolver = FakeResolver(txt={"example.com": record, **dns.pop("txt", {})}, **dns)
    return check_spf(ip, sender, helo, resolver)


def test_spf_ip4_pass_and_fail():
    assert spf("v=spf1 ip4:192.0.2.0/24 -all").result == "pass"
    r = spf("v=spf1 ip4:192.0.2.0/24 -all", ip=BAD_IP)
    assert r.result == "fail" and r.mechanism == "-all"


@pytest.mark.parametrize(
    "tail,expected", [("~all", "softfail"), ("?all", "neutral"), ("-all", "fail"), ("+all", "pass")]
)
def test_spf_qualifiers(tail, expected):
    assert spf(f"v=spf1 ip4:10.9.9.9 {tail}", ip=BAD_IP).result == expected


def test_spf_no_record_and_no_match_default():
    assert check_spf(GOOD_IP, "u@example.com", "h", FakeResolver()).result == "none"
    assert spf("v=spf1 ip4:10.9.9.9", ip=BAD_IP).result == "neutral"


def test_spf_a_mx_and_cidr():
    assert spf("v=spf1 a -all", a={"example.com": [GOOD_IP]}).result == "pass"
    assert spf("v=spf1 a:mail.example.com/24 -all", a={"mail.example.com": ["192.0.2.99"]}).result == "pass"
    assert spf("v=spf1 a -all", ip=BAD_IP, a={"example.com": [GOOD_IP]}).result == "fail"
    r = spf("v=spf1 mx -all", mx={"example.com": ["mx1.example.com"]}, a={"mx1.example.com": [GOOD_IP]})
    assert r.result == "pass" and r.mechanism == "mx:example.com"


def test_spf_ipv6_and_mapped_ipv4():
    assert spf("v=spf1 ip6:2001:db8::/32 -all", ip="2001:db8:1::5").result == "pass"
    assert spf("v=spf1 ip6:2001:db8::/32 -all", ip="2001:db9::5").result == "fail"
    assert spf("v=spf1 ip4:192.0.2.0/24 -all", ip="::ffff:192.0.2.10").result == "pass"
    assert spf("v=spf1 a -all", ip="2001:db8::1", aaaa={"example.com": ["2001:db8::1"]}).result == "pass"


def test_spf_include_semantics():
    txt = {"_spf.esp.test": "v=spf1 ip4:192.0.2.0/24 -all"}
    assert spf("v=spf1 include:_spf.esp.test -all", txt=txt).result == "pass"
    # a failing include is "no match" and evaluation continues
    assert spf("v=spf1 include:_spf.esp.test ~all", ip=BAD_IP, txt=txt).result == "softfail"
    # include of a domain without SPF is a permerror
    assert spf("v=spf1 include:nospf.test -all").result == "permerror"


def test_spf_redirect():
    txt = {"_spf.example.net": "v=spf1 ip4:192.0.2.0/24 -all"}
    assert spf("v=spf1 redirect=_spf.example.net", txt=txt).result == "pass"
    assert spf("v=spf1 redirect=missing.test").result == "permerror"


def test_spf_exists_with_macros():
    txt_rec = "v=spf1 exists:%{i}._ip.%{d} -all"
    ok = spf(txt_rec, a={"192.0.2.10._ip.example.com": ["127.0.0.2"]})
    assert ok.result == "pass"
    assert spf(txt_rec, ip=BAD_IP).result == "fail"
    # %{l} / %{o} / reversed ip
    r = spf("v=spf1 exists:%{l}.%{o}.%{ir}.x.test -all",
            a={"user.example.com.10.2.0.192.x.test": ["127.0.0.2"]})
    assert r.result == "pass"


def test_spf_lookup_limit_is_permerror():
    includes = " ".join(f"include:i{n}.test" for n in range(11))
    txt = {f"i{n}.test": "v=spf1 -all" for n in range(11)}
    r = spf(f"v=spf1 {includes} -all", txt=txt)
    assert r.result == "permerror" and "too many DNS lookups" in r.explanation


def test_spf_void_lookup_limit():
    r = spf("v=spf1 a:x1.test a:x2.test a:x3.test -all")
    assert r.result == "permerror" and "void" in r.explanation


def test_spf_recursion_loop_terminates():
    txt = {"a.test": "v=spf1 include:b.test -all", "b.test": "v=spf1 include:a.test -all"}
    assert spf("v=spf1 include:a.test -all", txt=txt).result == "permerror"


def test_spf_multiple_records_and_syntax_errors():
    r = check_spf(GOOD_IP, "u@example.com", "h",
                  FakeResolver(txt={"example.com": ["v=spf1 -all", "v=spf1 +all"]}))
    assert r.result == "permerror"
    assert spf("v=spf1 bogus:thing -all").result == "permerror"
    assert spf("v=spf1 ip4:not-an-ip -all").result == "permerror"
    assert spf("v=spf1 ip4:1.2.3.4/33 -all").result == "permerror"


def test_spf_temperror():
    r = check_spf(GOOD_IP, "u@example.com", "h", FakeResolver(temp_fail={"example.com"}))
    assert r.result == "temperror"
    r2 = spf("v=spf1 include:flaky.test -all", txt={}, temp_fail={"flaky.test"})
    assert r2.result == "temperror"


def test_spf_null_sender_uses_helo_and_invalid_ip():
    resolver = FakeResolver(txt={"mail.example.com": "v=spf1 ip4:192.0.2.0/24 -all"})
    r = check_spf(GOOD_IP, "<>", "mail.example.com", resolver)
    assert r.result == "pass" and r.sender == "postmaster@mail.example.com"
    assert check_spf("not-an-ip", "a@example.com", "h", resolver).result == "permerror"


def test_spf_ptr_mechanism():
    r = spf("v=spf1 ptr -all", ptr={GOOD_IP: ["mail.example.com"]}, a={"mail.example.com": [GOOD_IP]})
    assert r.result == "pass"
    # a PTR name whose forward lookup does not return the IP must not validate
    r2 = spf("v=spf1 ptr -all", ptr={GOOD_IP: ["mail.example.com"]}, a={"mail.example.com": ["10.0.0.1"]})
    assert r2.result == "fail"


# ======================================================================================
# DKIM - canonicalization
# ======================================================================================
def test_header_canonicalization_matches_rfc_6376_examples():
    # RFC 6376 section 3.4.5 examples
    a = b"A: X\r\n"
    b = b"B : Y\t\r\n\tZ  \r\n"
    assert dk.canonicalize_header(a, "relaxed") == b"a:X\r\n"
    assert dk.canonicalize_header(b, "relaxed") == b"b:Y Z\r\n"
    assert dk.canonicalize_header(b, "simple") == b


def test_body_canonicalization_matches_rfc_6376_examples():
    body = b" C \r\nD \t E\r\n\r\n\r\n"
    assert dk.canonicalize_body(body, "relaxed") == b" C\r\nD E\r\n"
    assert dk.canonicalize_body(body, "simple") == b" C \r\nD \t E\r\n"
    assert dk.canonicalize_body(b"", "simple") == b"\r\n"
    assert dk.canonicalize_body(b"", "relaxed") == b""
    assert dk.canonicalize_body(b"no newline", "simple") == b"no newline\r\n"
    # SHA-256 of an empty relaxed body / of CRLF (RFC 6376 / 8463 well-known constants)
    assert base64.b64encode(dk.compute_body_hash(b"", "relaxed")) == b"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    assert base64.b64encode(dk.compute_body_hash(b"", "simple")) == b"frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY="


# ======================================================================================
# DKIM - verification
# ======================================================================================
@pytest.mark.parametrize("canon", [("relaxed", "relaxed"), ("simple", "simple"),
                                   ("relaxed", "simple"), ("simple", "relaxed")])
def test_dkim_valid_signature_all_canonicalizations(rsa_key, canon):
    msg = sign_rsa(make_message(), rsa_key, canon=canon)
    result = check_dkim(msg, dkim_resolver(rsa_key))
    assert result.result == "pass", result.signatures[0].reason
    sig = result.signatures[0]
    assert sig.domain == "example.com" and sig.selector == "sel1"
    assert sig.body_hash_ok and sig.signature_ok
    assert sig.key_bits == 2048 and result.passing_domains == ["example.com"]


def test_dkim_survives_header_folding_and_lf_input(rsa_key):
    msg = sign_rsa(make_message(subject="a   spaced \r\n\t subject"), rsa_key)
    assert check_dkim(msg.replace(b"\r\n", b"\n"), dkim_resolver(rsa_key)).result == "pass"


def test_dkim_body_tamper_fails(rsa_key):
    msg = sign_rsa(make_message(), rsa_key).replace(b"Lunch tomorrow", b"Wire me $5,000")
    r = check_dkim(msg, dkim_resolver(rsa_key))
    assert r.result == "fail" and r.signatures[0].body_hash_ok is False


def test_dkim_signed_header_tamper_fails(rsa_key):
    msg = sign_rsa(make_message(), rsa_key).replace(b"Subject: Hello", b"Subject: Hacked")
    r = check_dkim(msg, dkim_resolver(rsa_key))
    assert r.result == "fail"
    assert r.signatures[0].body_hash_ok is True and r.signatures[0].signature_ok is False


def test_dkim_wrong_key_fails(rsa_key):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    msg = sign_rsa(make_message(), rsa_key)
    assert check_dkim(msg, dkim_resolver(other)).result == "fail"


def test_dkim_unsigned_message_is_none():
    assert check_dkim(make_message(), FakeResolver()).result == "none"


def test_dkim_missing_key_and_revoked_key_and_dns_error(rsa_key):
    msg = sign_rsa(make_message(), rsa_key)
    assert check_dkim(msg, FakeResolver()).result == "permerror"
    revoked = FakeResolver(txt={"sel1._domainkey.example.com": "v=DKIM1; k=rsa; p="})
    r = check_dkim(msg, revoked)
    assert r.result == "fail" and "revoked" in r.signatures[0].reason
    flaky = FakeResolver(temp_fail={"sel1._domainkey.example.com"})
    assert check_dkim(msg, flaky).result == "temperror"


def test_dkim_rsa_sha1_is_refused_by_policy(rsa_key):
    msg = sign_rsa(make_message(), rsa_key, algo=b"rsa-sha1")
    r = check_dkim(msg, dkim_resolver(rsa_key))
    assert r.result == "policy" and "rsa-sha1" in r.signatures[0].reason


def test_dkim_short_rsa_key_is_refused(monkeypatch):
    # cryptography refuses to *generate* <1024-bit keys, so raise the verifier's floor instead
    monkeypatch.setattr(dk, "MIN_RSA_BITS", 2048)
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    r = check_dkim(sign_rsa(make_message(), key), dkim_resolver(key))
    assert r.result == "policy" and "too short" in r.signatures[0].reason


def test_dkim_1024_bit_key_passes_with_warning():
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    r = check_dkim(sign_rsa(make_message(), key), dkim_resolver(key))
    assert r.result == "pass" and any("weak RSA key" in w for w in r.signatures[0].warnings)


def build_signed(signer, algo, selector, *, body=b"hi\r\n", extra_tags="", digest_first=False):
    """Hand-build a signed message with our own canonicalization helpers.

    Used where dkimpy cannot help (x= expiry, Ed25519 RFC 8463). ``signer`` maps the header
    hash input to raw signature bytes.
    """
    bh = base64.b64encode(hashlib.sha256(dk.canonicalize_body(body, "relaxed")).digest()).decode()
    value = (f"v=1; a={algo}; c=relaxed/relaxed; d=example.com; s={selector}; "
             f"{extra_tags}h=from; bh={bh}; b=")
    rest = b"From: a@example.com\r\n\r\n" + body
    hdrs, _ = split_raw_message(b"DKIM-Signature: " + value.encode() + b"\r\n" + rest)
    data = dk.compute_header_hash_input(dk.parse_signature_header(hdrs[0]), hdrs)
    sig = base64.b64encode(signer(data)).decode()
    return b"DKIM-Signature: " + (value + sig).encode() + b"\r\n" + rest


def test_dkim_expired_signature(rsa_key):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    msg = build_signed(
        lambda d: rsa_key.sign(d, padding.PKCS1v15(), hashes.SHA256()),
        "rsa-sha256", "sel1", extra_tags="t=1700000000; x=1700000100; ",
    )
    resolver = dkim_resolver(rsa_key)
    assert check_dkim(msg, resolver, now=1_700_000_050).result == "pass"
    expired = check_dkim(msg, resolver, now=1_700_000_500)
    assert expired.result == "fail" and "expired" in expired.signatures[0].reason


def test_dkim_ed25519_rfc8463():
    key = ed25519.Ed25519PrivateKey.generate()
    raw_pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    resolver = FakeResolver(txt={
        "ed._domainkey.example.com": f"v=DKIM1; k=ed25519; p={base64.b64encode(raw_pub).decode()}"
    })
    # RFC 8463: Ed25519 signs the SHA-256 digest of the canonicalized header data
    msg = build_signed(lambda d: key.sign(hashlib.sha256(d).digest()), "ed25519-sha256", "ed")
    r = check_dkim(msg, resolver)
    assert r.result == "pass", r.signatures[0].reason
    assert r.signatures[0].key_type == "ed25519"
    assert check_dkim(msg.replace(b"hi\r\n", b"ho\r\n"), resolver).result == "fail"
    # algorithm / key-type mismatch is a permerror, not a pass
    rsa_algo = msg.replace(b"a=ed25519-sha256", b"a=rsa-sha256")
    assert check_dkim(rsa_algo, resolver).result in ("fail", "permerror")


def test_dkim_malformed_signatures(rsa_key):
    base = make_message()
    for bad in (
        b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel1; h=from; bh=AAAA\r\n",  # no b=
        b"DKIM-Signature: v=2; a=rsa-sha256; b=AAAA; bh=AAAA; d=e.com; s=s; h=from\r\n",
        b"DKIM-Signature: v=1; a=rsa-sha256; b=AAAA; bh=AAAA; d=e.com; s=s; h=to\r\n",  # From unsigned
        b"DKIM-Signature: v=1; v=1; a=rsa-sha256; b=AAAA; bh=AAAA; d=e.com; s=s; h=from\r\n",
        b"DKIM-Signature: v=1; a=rsa-sha256; b=!!; bh=AAAA; d=e.com; s=s; h=from\r\n",
        b"DKIM-Signature: v=1; a=md5-fake; b=AAAA; bh=AAAA; d=e.com; s=s; h=from\r\n",
        b"DKIM-Signature: v=1; a=rsa-sha256; b=AAAA; bh=AAAA; d=e.com; s=s; h=from; i=a@evil.test\r\n",
    ):
        assert check_dkim(bad + base, FakeResolver()).result == "permerror", bad


def test_dkim_multiple_signatures_any_pass(rsa_key):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    msg = sign_rsa(make_message(), rsa_key)  # valid example.com signature
    msg = sign_rsa(msg, other, domain="relay.test", selector="r1")  # signer 2 (outermost)
    resolver = FakeResolver(txt={
        "sel1._domainkey.example.com": rsa_dns_record(rsa_key),
        "r1._domainkey.relay.test": rsa_dns_record(rsa_key),  # wrong key published -> fail
    })
    r = check_dkim(msg, resolver)
    assert r.result == "pass"
    assert sorted(s.result for s in r.signatures) == ["fail", "pass"]
    assert r.passing_domains == ["example.com"]


def test_dkim_l_tag_and_extra_from_warnings(rsa_key):
    msg = sign_rsa(make_message(), rsa_key)
    forged = b"From: ceo@example.com\r\n" + msg  # prepended extra From
    r = check_dkim(forged, dkim_resolver(rsa_key))
    assert any("'from' header appears more often" in w for w in r.signatures[0].warnings)


# ======================================================================================
# DMARC
# ======================================================================================
def test_organizational_domain():
    assert organizational_domain("mail.example.co.uk") == "example.co.uk"
    assert organizational_domain("a.b.example.com") == "example.com"
    assert organizational_domain("example.com") == "example.com"
    assert organizational_domain("localhost") == "localhost"


def test_alignment_modes():
    assert domains_aligned("mail.example.com", "example.com", "r")
    assert not domains_aligned("mail.example.com", "example.com", "s")
    assert domains_aligned("Example.COM.", "example.com", "s")
    assert not domains_aligned("example.com", "example.org", "r")
    assert not domains_aligned("", "example.org", "r")


def test_parse_dmarc_record_tags_and_defaults():
    r = parse_dmarc_record("v=DMARC1; p=Reject; sp=none; adkim=s; pct=50; rua=mailto:a@x.test,mailto:b@x.test")
    assert (r.policy, r.subdomain_policy, r.adkim, r.aspf, r.pct) == ("reject", "none", "s", "r", 50)
    assert r.rua == ["mailto:a@x.test", "mailto:b@x.test"]
    assert parse_dmarc_record("v=DMARC1; p=quarantine").subdomain_policy == "quarantine"
    assert parse_dmarc_record("v=DMARC1; p=bogus; rua=mailto:a@x.test").policy == "none"
    with pytest.raises(ValueError):
        parse_dmarc_record("v=DMARC1; p=bogus")


def _spf_pass(domain="example.com"):
    return check_spf(GOOD_IP, f"u@{domain}", "h", FakeResolver(txt={domain: f"v=spf1 ip4:{GOOD_IP} -all"}))


def _spf_fail(domain="example.com"):
    return check_spf(BAD_IP, f"u@{domain}", "h", FakeResolver(txt={domain: f"v=spf1 ip4:{GOOD_IP} -all"}))


class _Dkim:  # tiny stand-in for DKIMResult
    def __init__(self, result, domains=()):
        from backend.analysis.dkim_check import DKIMResult, DKIMSignatureResult

        sigs = [DKIMSignatureResult(result=result, reason="", domain=d) for d in domains]
        self.value = DKIMResult(result=result, signatures=sigs)


def test_dmarc_pass_via_spf_only():
    res = FakeResolver(txt={"_dmarc.example.com": "v=DMARC1; p=reject"})
    r = evaluate_dmarc("example.com", _spf_pass(), _Dkim("none").value, res)
    assert r.result == "pass" and r.spf_aligned and not r.dkim_aligned and r.disposition == "none"


def test_dmarc_pass_via_dkim_only():
    res = FakeResolver(txt={"_dmarc.example.com": "v=DMARC1; p=reject"})
    r = evaluate_dmarc("example.com", _spf_fail(), _Dkim("pass", ["example.com"]).value, res)
    assert r.result == "pass" and r.dkim_aligned and not r.spf_aligned


def test_dmarc_fail_applies_policy():
    for policy in ("none", "quarantine", "reject"):
        res = FakeResolver(txt={"_dmarc.example.com": f"v=DMARC1; p={policy}"})
        r = evaluate_dmarc("example.com", _spf_fail(), _Dkim("none").value, res)
        assert r.result == "fail" and r.disposition == policy
        assert r.enforced_failure == (policy != "none")


def test_dmarc_third_party_dkim_not_aligned():
    """A valid DKIM signature from an unrelated domain must not satisfy DMARC."""
    res = FakeResolver(txt={"_dmarc.example.com": "v=DMARC1; p=reject"})
    r = evaluate_dmarc("example.com", _spf_fail(), _Dkim("pass", ["esp-mailer.test"]).value, res)
    assert r.result == "fail" and not r.dkim_aligned
    assert any("not aligned" in why for why in r.reasons)


def test_dmarc_spf_pass_but_misaligned_mailfrom():
    res = FakeResolver(txt={"_dmarc.example.com": "v=DMARC1; p=reject"})
    r = evaluate_dmarc("example.com", _spf_pass("bounce.evil.test"), _Dkim("none").value, res)
    assert r.result == "fail" and not r.spf_aligned


def test_dmarc_strict_vs_relaxed_alignment():
    spf_sub = _spf_pass("mail.example.com")
    relaxed = FakeResolver(txt={"_dmarc.example.com": "v=DMARC1; p=reject"})
    strict = FakeResolver(txt={"_dmarc.example.com": "v=DMARC1; p=reject; aspf=s"})
    assert evaluate_dmarc("example.com", spf_sub, _Dkim("none").value, relaxed).result == "pass"
    assert evaluate_dmarc("example.com", spf_sub, _Dkim("none").value, strict).result == "fail"


def test_dmarc_org_domain_fallback_and_subdomain_policy():
    res = FakeResolver(txt={"_dmarc.example.com": "v=DMARC1; p=reject; sp=quarantine"})
    r = evaluate_dmarc("news.example.com", _spf_fail("news.example.com"), _Dkim("none").value, res)
    assert r.policy_domain == "example.com" and r.policy == "quarantine"
    assert r.result == "fail" and r.disposition == "quarantine"


def test_dmarc_none_invalid_multiple_and_temperror():
    nothing = evaluate_dmarc("example.com", _spf_pass(), _Dkim("none").value, FakeResolver())
    assert nothing.result == "none"
    multi = FakeResolver(txt={"_dmarc.example.com": ["v=DMARC1; p=none", "v=DMARC1; p=reject"]})
    assert evaluate_dmarc("example.com", _spf_fail(), _Dkim("none").value, multi).result == "none"
    bad = FakeResolver(txt={"_dmarc.example.com": "v=DMARC1; p=wat"})
    assert evaluate_dmarc("example.com", _spf_fail(), _Dkim("none").value, bad).result == "none"
    flaky = FakeResolver(temp_fail={"_dmarc.example.com"})
    assert evaluate_dmarc("example.com", _spf_fail(), _Dkim("none").value, flaky).result == "temperror"
    assert evaluate_dmarc("", None, None, FakeResolver()).result == "none"


def test_dmarc_ignores_unrelated_txt_records():
    res = FakeResolver(txt={"_dmarc.example.com": ["google-site-verification=abc", "v=DMARC1; p=reject"]})
    r = evaluate_dmarc("example.com", _spf_fail(), _Dkim("none").value, res)
    assert r.result == "fail" and r.disposition == "reject"


# ======================================================================================
# end-to-end: authenticate_email (what the pipeline calls)
# ======================================================================================
def test_authenticate_email_fully_authenticated(rsa_key):
    msg = sign_rsa(make_message(extra_headers="Return-Path: <alice@example.com>\r\n"), rsa_key)
    resolver = FakeResolver(txt={
        "example.com": f"v=spf1 ip4:{GOOD_IP} -all",
        "sel1._domainkey.example.com": rsa_dns_record(rsa_key),
        "_dmarc.example.com": "v=DMARC1; p=reject",
    })
    s = authenticate_email(msg, GOOD_IP, "mail.example.com", resolver=resolver)
    assert (s.spf.result, s.dkim.result, s.dmarc.result) == ("pass", "pass", "pass")
    assert s.verdict == "pass" and s.risk_factor == 0.0
    header = s.authentication_results_header("gw.company.test")
    assert header.startswith("gw.company.test; spf=pass") and "dkim=pass header.d=example.com" in header
    assert "dmarc=pass header.from=example.com" in header


def test_authenticate_email_spoofed_sender_is_flagged():
    """Attacker at BAD_IP sends 'From: ceo@example.com' with no signature."""
    msg = make_message(from_addr="ceo@example.com", extra_headers="Return-Path: <ceo@example.com>\r\n")
    resolver = FakeResolver(txt={
        "example.com": f"v=spf1 ip4:{GOOD_IP} -all",
        "_dmarc.example.com": "v=DMARC1; p=reject",
    })
    s = authenticate_email(msg, BAD_IP, "evil.test", resolver=resolver)
    assert (s.spf.result, s.dkim.result, s.dmarc.result) == ("fail", "none", "fail")
    assert s.verdict == "fail" and s.dmarc.enforced_failure
    assert s.risk_factor >= 0.85
    assert s.to_dict()["dmarc"]["disposition"] == "reject"


def test_authenticate_email_lookalike_domain_passes_auth_but_is_unaligned():
    """Attacker owns evil.test, so SPF passes for evil.test - yet From says example.com."""
    msg = make_message(from_addr="ceo@example.com", extra_headers="Return-Path: <x@evil.test>\r\n")
    resolver = FakeResolver(txt={
        "evil.test": f"v=spf1 ip4:{BAD_IP} -all",
        "_dmarc.example.com": "v=DMARC1; p=quarantine",
    })
    s = authenticate_email(msg, BAD_IP, "evil.test", resolver=resolver)
    assert s.spf.result == "pass" and s.dmarc.result == "fail" and not s.dmarc.spf_aligned
    assert s.dmarc.disposition == "quarantine"


def test_authenticate_email_unknown_ip_and_unauthenticated_domain():
    s = authenticate_email(make_message(), None, resolver=FakeResolver())
    assert s.spf.result == "none" and s.dmarc.result == "none"
    assert s.verdict == "unauthenticated" and 0.2 < s.risk_factor < 0.5


def test_authenticate_email_accepts_parsed_email_and_defaults_mail_from():
    p = parse_email(make_message(extra_headers="Return-Path: <alice@example.com>\r\n"))
    resolver = FakeResolver(txt={"example.com": f"v=spf1 ip4:{GOOD_IP} -all"})
    s = authenticate_email(p, GOOD_IP, resolver=resolver)
    assert s.spf.result == "pass" and s.spf.sender == "alice@example.com"


def test_clock_param_is_respected(rsa_key):
    """`now` is injectable so tests never depend on wall-clock time."""
    msg = sign_rsa(make_message(), rsa_key)
    assert check_dkim(msg, dkim_resolver(rsa_key), now=time.time()).result == "pass"
