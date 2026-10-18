"""DKIM (RFC 6376) header parsing, canonicalization and public-key verification.

Verification is implemented directly on top of the ``cryptography`` package so every step is
visible (and explainable in the UI's "Explain this" panel):

1. find every ``DKIM-Signature`` header and parse its tag=value list;
2. canonicalize the body (``simple`` / ``relaxed``), honour ``l=``, hash it, compare with ``bh=``;
3. select the signed headers listed in ``h=`` (bottom-up, as the RFC requires), canonicalize
   them plus the signature header itself (with an emptied ``b=``) and hash;
4. fetch the public key from ``<selector>._domainkey.<domain>`` via DNS and verify ``b=``.

Supported algorithms: ``rsa-sha256`` and ``ed25519-sha256`` (RFC 8463). ``rsa-sha1`` is
*recognised but refused* (RFC 8301) and RSA keys under 1024 bits are refused - the project
rule is "no SHA-1 for security".
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from backend.analysis.email_parser import RawHeader, split_raw_message
from backend.analysis.spf_check import (
    DnsPythonResolver,
    DNSResolver,
    DNSTemporaryError,
)

# DKIM result codes (subset of RFC 8601)
PASS = "pass"
FAIL = "fail"
POLICY = "policy"
NONE = "none"
TEMPERROR = "temperror"
PERMERROR = "permerror"

MAX_SIGNATURES = 5  # verify at most this many signatures per message (DoS guard)
MIN_RSA_BITS = 1024  # RFC 8301: verifiers MUST NOT accept less
RECOMMENDED_RSA_BITS = 2048

_WSP_RUN = re.compile(rb"[ \t]+")
_FOLD = re.compile(rb"\r\n(?=[ \t])")
_B_TAG_RE = re.compile(r"((?:^|;)[ \t\r\n]*b[ \t\r\n]*=)[^;]*")
_TAG_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


class DKIMError(Exception):
    """Internal: aborts verification of one signature with a given result."""

    def __init__(self, result: str, reason: str) -> None:
        super().__init__(reason)
        self.result = result
        self.reason = reason


# --------------------------------------------------------------------------------------
# Result types
# --------------------------------------------------------------------------------------
@dataclass
class DKIMSignatureResult:
    result: str
    reason: str
    domain: str | None = None  # d=
    selector: str | None = None  # s=
    identity: str | None = None  # i=
    algorithm: str | None = None  # a=
    canonicalization: str | None = None  # c=
    signed_headers: list[str] = field(default_factory=list)
    key_type: str | None = None
    key_bits: int | None = None
    body_hash_ok: bool | None = None
    signature_ok: bool | None = None
    testing: bool = False  # key published with t=y
    warnings: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.result == PASS

    def to_dict(self) -> dict[str, object]:
        return dict(self.__dict__)


@dataclass
class DKIMResult:
    result: str  # overall: pass if ANY signature passes
    signatures: list[DKIMSignatureResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.result == PASS

    @property
    def passing_domains(self) -> list[str]:
        """Signing domains (``d=``) of every signature that verified."""
        return [s.domain for s in self.signatures if s.passed and s.domain]

    def to_dict(self) -> dict[str, object]:
        return {"result": self.result, "signatures": [s.to_dict() for s in self.signatures]}


# --------------------------------------------------------------------------------------
# Tag=value parsing (used for both signatures and key records)
# --------------------------------------------------------------------------------------
def parse_tag_list(text: str) -> dict[str, str]:
    """Parse ``a=1; b = two; ...`` (RFC 6376 3.2). Raises :class:`DKIMError` on duplicates."""
    tags: dict[str, str] = {}
    for item in text.split(";"):
        if not item.strip():
            continue
        name, sep, value = item.partition("=")
        name = name.strip()
        if not sep or not _TAG_NAME_RE.match(name):
            raise DKIMError(PERMERROR, f"malformed tag {item.strip()[:40]!r}")
        if name in tags:
            raise DKIMError(PERMERROR, f"duplicate tag {name!r}")
        tags[name] = value.strip()
    return tags


@dataclass
class DKIMSignature:
    """A parsed ``DKIM-Signature`` header."""

    header: RawHeader
    version: str
    algorithm: str
    signature: bytes
    body_hash: bytes
    domain: str
    signed_headers: list[str]
    selector: str
    header_canon: str
    body_canon: str
    body_length: int | None
    identity: str | None
    timestamp: int | None
    expiration: int | None


def parse_signature_header(header: RawHeader) -> DKIMSignature:
    """Parse and validate a DKIM-Signature header (RFC 6376 3.5)."""
    tags = parse_tag_list(header.value)
    for required in ("v", "a", "b", "bh", "d", "h", "s"):
        if required not in tags:
            raise DKIMError(PERMERROR, f"missing required tag {required}=")
    if tags["v"] != "1":
        raise DKIMError(PERMERROR, f"unsupported DKIM version {tags['v']!r}")
    if tags.get("q", "dns/txt").lower() != "dns/txt":
        raise DKIMError(PERMERROR, f"unsupported query method {tags['q']!r}")

    signed = [h.strip().lower() for h in tags["h"].split(":") if h.strip()]
    if "from" not in signed:
        raise DKIMError(PERMERROR, "From header is not covered by h=")

    canon = tags.get("c", "simple/simple").lower()
    header_canon, _, body_canon = canon.partition("/")
    body_canon = body_canon or "simple"
    if header_canon not in ("simple", "relaxed") or body_canon not in ("simple", "relaxed"):
        raise DKIMError(PERMERROR, f"unknown canonicalization {canon!r}")

    try:
        signature = base64.b64decode(re.sub(r"\s+", "", tags["b"]), validate=True)
        body_hash = base64.b64decode(re.sub(r"\s+", "", tags["bh"]), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DKIMError(PERMERROR, "b= or bh= is not valid base64") from exc

    def integer(tag: str) -> int | None:
        if tag not in tags:
            return None
        if not tags[tag].isdigit():
            raise DKIMError(PERMERROR, f"{tag}= is not a number")
        return int(tags[tag])

    domain = tags["d"].lower().rstrip(".")
    identity = tags.get("i")
    if identity:
        id_domain = identity.rpartition("@")[2].lower()
        if id_domain != domain and not id_domain.endswith("." + domain):
            raise DKIMError(PERMERROR, "i= domain is not d= or a subdomain of it")

    return DKIMSignature(
        header=header,
        version=tags["v"],
        algorithm=tags["a"].lower(),
        signature=signature,
        body_hash=body_hash,
        domain=domain,
        signed_headers=signed,
        selector=tags["s"],
        header_canon=header_canon,
        body_canon=body_canon,
        body_length=integer("l"),
        identity=identity,
        timestamp=integer("t"),
        expiration=integer("x"),
    )


# --------------------------------------------------------------------------------------
# Canonicalization (RFC 6376 section 3.4)
# --------------------------------------------------------------------------------------
def canonicalize_header(raw: bytes, mode: str) -> bytes:
    """Canonicalize one raw header field (including its trailing CRLF)."""
    if mode == "simple":
        return raw
    if mode != "relaxed":
        raise ValueError(f"unknown header canonicalization {mode!r}")
    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    name, _, value = raw.partition(b":")
    value = _WSP_RUN.sub(b" ", _FOLD.sub(b"", value)).strip(b" \t")
    return name.strip().lower() + b":" + value + b"\r\n"


def canonicalize_body(body: bytes, mode: str) -> bytes:
    """Canonicalize a CRLF-normalised message body."""
    if mode == "simple":
        while body.endswith(b"\r\n\r\n"):
            body = body[:-2]
        if not body:
            return b"\r\n"
        return body if body.endswith(b"\r\n") else body + b"\r\n"
    if mode != "relaxed":
        raise ValueError(f"unknown body canonicalization {mode!r}")
    lines = body.split(b"\r\n")
    if lines and lines[-1] == b"":
        lines.pop()
    lines = [_WSP_RUN.sub(b" ", line).rstrip(b" ") for line in lines]
    while lines and lines[-1] == b"":
        lines.pop()
    return b"".join(line + b"\r\n" for line in lines)


def compute_body_hash(body: bytes, body_canon: str, length: int | None = None) -> bytes:
    canonical = canonicalize_body(body, body_canon)
    if length is not None:
        if length > len(canonical):
            raise DKIMError(FAIL, "l= is larger than the canonicalized body")
        canonical = canonical[:length]
    return hashlib.sha256(canonical).digest()


def _select_signed_headers(
    headers: list[RawHeader], names: list[str], exclude: RawHeader
) -> list[RawHeader]:
    """Pick header instances for ``h=``: for each name, the next unused one from the bottom."""
    pool: dict[str, list[RawHeader]] = {}
    for hdr in headers:
        if hdr is exclude:
            continue
        pool.setdefault(hdr.name.lower(), []).append(hdr)
    selected = []
    for name in names:
        instances = pool.get(name)
        if instances:
            selected.append(instances.pop())  # missing/exhausted names contribute nothing
    return selected


def _signature_header_for_hashing(sig: DKIMSignature) -> bytes:
    """The DKIM-Signature header with ``b=`` emptied, canonicalized, without final CRLF."""
    text = sig.header.raw.decode("latin-1")
    name_part, colon, value = text.partition(":")
    value = _B_TAG_RE.sub(r"\1", value, count=1)
    canonical = canonicalize_header((name_part + colon + value).encode("latin-1"), sig.header_canon)
    return canonical[:-2] if canonical.endswith(b"\r\n") else canonical


def compute_header_hash_input(
    sig: DKIMSignature, headers: list[RawHeader]
) -> bytes:
    """The exact byte string that the signer signed (before hashing)."""
    chosen = _select_signed_headers(headers, sig.signed_headers, sig.header)
    data = b"".join(canonicalize_header(h.raw, sig.header_canon) for h in chosen)
    return data + _signature_header_for_hashing(sig)


# --------------------------------------------------------------------------------------
# Key record handling
# --------------------------------------------------------------------------------------
@dataclass
class _PublicKey:
    key: rsa.RSAPublicKey | ed25519.Ed25519PublicKey
    key_type: str
    bits: int
    testing: bool
    strict_subdomain: bool


def fetch_public_key(selector: str, domain: str, resolver: DNSResolver) -> _PublicKey:
    """Look up and parse ``<selector>._domainkey.<domain>`` (RFC 6376 3.6)."""
    name = f"{selector}._domainkey.{domain}"
    try:
        records = resolver.txt(name)
    except DNSTemporaryError as exc:
        raise DKIMError(TEMPERROR, f"DNS failure fetching key {name}: {exc}") from exc
    if not records:
        raise DKIMError(PERMERROR, f"no DKIM key published at {name}")

    tags: dict[str, str] | None = None
    for record in records:
        try:
            candidate = parse_tag_list(record)
        except DKIMError:
            continue
        if "p" in candidate:
            tags = candidate
            break
    if tags is None:
        raise DKIMError(PERMERROR, f"no usable DKIM key record at {name}")

    if tags.get("v", "DKIM1") != "DKIM1":
        raise DKIMError(PERMERROR, f"unsupported key record version {tags['v']!r}")
    services = [s.strip() for s in tags.get("s", "*").split(":")]
    if "*" not in services and "email" not in services:
        raise DKIMError(PERMERROR, "key is not valid for the email service (s=)")
    flags = [f.strip() for f in tags.get("t", "").split(":")]

    p = re.sub(r"\s+", "", tags["p"])
    if not p:
        raise DKIMError(FAIL, "key has been revoked (empty p=)")
    try:
        der = base64.b64decode(p, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DKIMError(PERMERROR, "p= is not valid base64") from exc

    key_type = tags.get("k", "rsa").lower()
    try:
        if key_type == "rsa":
            loaded = serialization.load_der_public_key(der)
            if not isinstance(loaded, rsa.RSAPublicKey):
                raise DKIMError(PERMERROR, "k=rsa but the key is not an RSA key")
            key: rsa.RSAPublicKey | ed25519.Ed25519PublicKey = loaded
            bits = loaded.key_size
        elif key_type == "ed25519":
            key = ed25519.Ed25519PublicKey.from_public_bytes(der)
            bits = 256
        else:
            raise DKIMError(PERMERROR, f"unsupported key type k={key_type}")
    except DKIMError:
        raise
    except (ValueError, TypeError) as exc:
        raise DKIMError(PERMERROR, f"cannot parse public key: {exc}") from exc

    return _PublicKey(
        key=key,
        key_type=key_type,
        bits=bits,
        testing="y" in flags,
        strict_subdomain="s" in flags,
    )


# --------------------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------------------
def _verify_one(
    header: RawHeader,
    headers: list[RawHeader],
    body: bytes,
    resolver: DNSResolver,
    now: float,
) -> DKIMSignatureResult:
    out = DKIMSignatureResult(result=PERMERROR, reason="")
    try:
        sig = parse_signature_header(header)
        out.domain, out.selector, out.identity = sig.domain, sig.selector, sig.identity
        out.algorithm = sig.algorithm
        out.canonicalization = f"{sig.header_canon}/{sig.body_canon}"
        out.signed_headers = list(sig.signed_headers)

        if sig.algorithm == "rsa-sha1":
            raise DKIMError(POLICY, "rsa-sha1 is deprecated (RFC 8301) and is not accepted")
        if sig.algorithm not in ("rsa-sha256", "ed25519-sha256"):
            raise DKIMError(PERMERROR, f"unsupported algorithm {sig.algorithm!r}")
        if sig.expiration is not None and now > sig.expiration:
            raise DKIMError(FAIL, "signature has expired (x=)")
        if sig.body_length is not None:
            out.warnings.append(
                "l= tag present: content may have been appended to the body after signing"
            )
        # headers present more times than they are signed can be forged by prepending
        counts: dict[str, int] = {}
        for hdr in headers:
            counts[hdr.name.lower()] = counts.get(hdr.name.lower(), 0) + 1
        for name in ("from", "subject", "to"):
            if counts.get(name, 0) > sig.signed_headers.count(name):
                out.warnings.append(f"'{name}' header appears more often than it is signed")

        # 1. body hash
        body_hash = compute_body_hash(body, sig.body_canon, sig.body_length)
        out.body_hash_ok = hmac.compare_digest(body_hash, sig.body_hash)
        if not out.body_hash_ok:
            raise DKIMError(FAIL, "body hash did not verify (body was modified)")

        # 2. public key
        pub = fetch_public_key(sig.selector, sig.domain, resolver)
        out.key_type, out.key_bits, out.testing = pub.key_type, pub.bits, pub.testing
        if pub.strict_subdomain and sig.identity:
            if sig.identity.rpartition("@")[2].lower() != sig.domain:
                raise DKIMError(PERMERROR, "key has t=s but i= is a subdomain of d=")
        if (sig.algorithm == "rsa-sha256") != (pub.key_type == "rsa"):
            raise DKIMError(PERMERROR, "signature algorithm does not match key type")
        if pub.key_type == "rsa":
            if pub.bits < MIN_RSA_BITS:
                raise DKIMError(POLICY, f"RSA key too short ({pub.bits} bits < {MIN_RSA_BITS})")
            if pub.bits < RECOMMENDED_RSA_BITS:
                out.warnings.append(f"weak RSA key ({pub.bits} bits); 2048+ recommended")
        if pub.testing:
            out.warnings.append("domain is in DKIM testing mode (t=y)")

        # 3. signature over the canonicalized headers
        signed_data = compute_header_hash_input(sig, headers)
        try:
            if isinstance(pub.key, rsa.RSAPublicKey):
                pub.key.verify(sig.signature, signed_data, padding.PKCS1v15(), hashes.SHA256())
            else:  # RFC 8463: Ed25519 signs the SHA-256 digest of the header data
                pub.key.verify(sig.signature, hashlib.sha256(signed_data).digest())
            out.signature_ok = True
        except InvalidSignature:
            out.signature_ok = False
            raise DKIMError(FAIL, "signature did not verify (headers modified or wrong key)")
        out.result, out.reason = PASS, "signature verified"
    except DKIMError as err:
        out.result, out.reason = err.result, err.reason
    return out


def _overall(results: list[DKIMSignatureResult]) -> str:
    if not results:
        return NONE
    if any(r.result == PASS for r in results):
        return PASS
    for code in (TEMPERROR, FAIL, POLICY, PERMERROR):
        if any(r.result == code for r in results):
            return code
    return PERMERROR  # pragma: no cover


def check_dkim(
    raw_message: bytes | str,
    resolver: DNSResolver | None = None,
    *,
    now: float | None = None,
    max_signatures: int = MAX_SIGNATURES,
) -> DKIMResult:
    """Verify every DKIM signature of a raw message.

    The overall result is ``pass`` if at least one signature verifies, ``none`` if the message
    carries no signature, otherwise the most significant failure code.
    """
    if isinstance(raw_message, str):
        raw_message = raw_message.encode("utf-8", "surrogateescape")
    headers, body = split_raw_message(raw_message)
    sig_headers = [h for h in headers if h.name.lower() == "dkim-signature"]
    if not sig_headers:
        return DKIMResult(result=NONE)

    resolver = resolver or DnsPythonResolver()
    clock = time.time() if now is None else now
    results = [_verify_one(h, headers, body, resolver, clock) for h in sig_headers[:max_signatures]]
    if len(sig_headers) > max_signatures:
        results[-1].warnings.append(
            f"{len(sig_headers) - max_signatures} further signatures were not checked"
        )
    return DKIMResult(result=_overall(results), signatures=results)
