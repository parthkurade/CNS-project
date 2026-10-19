"""DMARC (RFC 7489) policy lookup and SPF/DKIM identifier-alignment verification.

DMARC ties the *visible* ``From:`` domain to the two authentication mechanisms:

* **SPF alignment** - SPF passed *and* the SPF-checked domain (MAIL FROM, or HELO for bounces)
  is aligned with the ``From:`` domain;
* **DKIM alignment** - at least one DKIM signature verified *and* its ``d=`` domain is aligned
  with the ``From:`` domain.

Alignment is *relaxed* (same organizational domain) or *strict* (identical domain) according
to the ``aspf`` / ``adkim`` tags. DMARC passes if either mechanism is aligned; otherwise the
domain owner's policy (``p=`` / ``sp=``) says what should happen to the message.

:func:`authenticate_email` is the one-call entry point for the pipeline: it runs SPF, DKIM and
DMARC and returns an :class:`AuthenticationSummary` with a ready-made 0-1 risk factor.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache

from backend.analysis.dkim_check import DKIMResult, check_dkim
from backend.analysis.email_parser import ParsedEmail, parse_email
from backend.analysis.spf_check import (
    DnsPythonResolver,
    DNSResolver,
    DNSTemporaryError,
    SPFResult,
    check_spf,
)

# DMARC result codes
PASS = "pass"
FAIL = "fail"
NONE = "none"
TEMPERROR = "temperror"
PERMERROR = "permerror"

_POLICIES = ("none", "quarantine", "reject")
_DMARC_PREFIX_RE = re.compile(r"^\s*v\s*=\s*DMARC1\s*(;|$)", re.IGNORECASE)


# --------------------------------------------------------------------------------------
# Organizational domain
# --------------------------------------------------------------------------------------
@lru_cache(maxsize=1)
def _extractor():  # noqa: ANN202
    import tldextract

    # suffix_list_urls=() -> use the Public Suffix List snapshot bundled with tldextract,
    # never the network; cache_dir=None -> no disk writes.
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def organizational_domain(domain: str) -> str:
    """Registrable domain ("organizational domain") of *domain* using the Public Suffix List.

    ``mail.example.co.uk -> example.co.uk``. Falls back to the last two labels if the PSL
    lookup is unavailable.
    """
    domain = domain.strip().lower().rstrip(".")
    try:
        ext = _extractor()(domain)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    except Exception:  # noqa: BLE001 - PSL problems must never break authentication
        pass
    labels = domain.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain


def domains_aligned(domain_a: str, domain_b: str, mode: str = "r") -> bool:
    """RFC 7489 3.1 identifier alignment. ``mode`` is ``"s"`` (strict) or ``"r"`` (relaxed)."""
    a, b = domain_a.strip().lower().rstrip("."), domain_b.strip().lower().rstrip(".")
    if not a or not b:
        return False
    if mode == "s":
        return a == b
    return organizational_domain(a) == organizational_domain(b)


# --------------------------------------------------------------------------------------
# Policy record
# --------------------------------------------------------------------------------------
@dataclass
class DMARCRecord:
    raw: str
    policy: str  # p=
    subdomain_policy: str  # sp= (defaults to p)
    adkim: str = "r"
    aspf: str = "r"
    pct: int = 100
    rua: list[str] = field(default_factory=list)
    ruf: list[str] = field(default_factory=list)
    failure_options: str = "0"
    report_interval: int = 86400

    def to_dict(self) -> dict[str, object]:
        return dict(self.__dict__)


def parse_dmarc_record(text: str) -> DMARCRecord:
    """Parse a DMARC TXT record. Raises ``ValueError`` if it is unusable (RFC 7489 6.3)."""
    tags: dict[str, str] = {}
    for part in text.split(";"):
        name, sep, value = part.partition("=")
        if sep and name.strip():
            tags.setdefault(name.strip().lower(), value.strip())  # first occurrence wins

    def uris(key: str) -> list[str]:
        return [u.strip() for u in tags.get(key, "").split(",") if u.strip()]

    policy = tags.get("p", "").lower()
    if policy not in _POLICIES:
        # RFC 7489 6.6.3: a record with a bad/missing p= but a valid rua= is treated as p=none
        if uris("rua"):
            policy = "none"
        else:
            raise ValueError(f"missing or invalid p= tag ({tags.get('p')!r})")
    sp = tags.get("sp", "").lower()
    if sp not in _POLICIES:
        sp = policy
    adkim = tags.get("adkim", "r").lower()
    aspf = tags.get("aspf", "r").lower()
    pct_text = tags.get("pct", "100")
    pct = int(pct_text) if pct_text.isdigit() and 0 <= int(pct_text) <= 100 else 100
    ri = tags.get("ri", "86400")
    return DMARCRecord(
        raw=text.strip(),
        policy=policy,
        subdomain_policy=sp,
        adkim=adkim if adkim in ("r", "s") else "r",
        aspf=aspf if aspf in ("r", "s") else "r",
        pct=pct,
        rua=uris("rua"),
        ruf=uris("ruf"),
        failure_options=tags.get("fo", "0"),
        report_interval=int(ri) if ri.isdigit() else 86400,
    )


@dataclass
class DMARCLookup:
    record: DMARCRecord | None
    policy_domain: str | None  # domain where the record was found
    status: str  # "found" | "none" | "temperror" | "invalid"
    reason: str = ""


def fetch_dmarc_record(from_domain: str, resolver: DNSResolver) -> DMARCLookup:
    """Fetch the DMARC record for *from_domain*, falling back to its organizational domain
    (RFC 7489 6.6.3)."""
    from_domain = from_domain.strip().lower().rstrip(".")
    org = organizational_domain(from_domain)
    candidates = [from_domain] + ([org] if org != from_domain else [])
    for domain in candidates:
        name = f"_dmarc.{domain}"
        try:
            txts = resolver.txt(name)
        except DNSTemporaryError as exc:
            return DMARCLookup(None, None, "temperror", f"DNS failure looking up {name}: {exc}")
        records = [t for t in txts if _DMARC_PREFIX_RE.match(t)]
        if not records:
            continue
        if len(records) > 1:  # RFC 7489 6.6.3: multiple records -> DMARC does not apply
            return DMARCLookup(None, domain, "invalid", f"multiple DMARC records at {name}")
        try:
            return DMARCLookup(parse_dmarc_record(records[0]), domain, "found")
        except ValueError as exc:
            return DMARCLookup(None, domain, "invalid", f"invalid DMARC record at {name}: {exc}")
    return DMARCLookup(None, None, "none", f"no DMARC record for {from_domain}")


# --------------------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------------------
@dataclass
class DMARCResult:
    result: str  # pass / fail / none / temperror / permerror
    from_domain: str
    disposition: str = "none"  # what the policy asks for: none / quarantine / reject
    policy_domain: str | None = None
    policy: str | None = None  # applicable policy (p= or sp=)
    record: DMARCRecord | None = None
    spf_aligned: bool = False
    dkim_aligned: bool = False
    spf_result: str | None = None
    dkim_result: str | None = None
    adkim: str = "r"
    aspf: str = "r"
    pct: int = 100
    reasons: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.result == PASS

    @property
    def enforced_failure(self) -> bool:
        """DMARC failed and the domain owner asked for quarantine or reject."""
        return self.result == FAIL and self.disposition in ("quarantine", "reject")

    def to_dict(self) -> dict[str, object]:
        data = dict(self.__dict__)
        data["record"] = self.record.to_dict() if self.record else None
        return data


def evaluate_dmarc(
    from_domain: str,
    spf: SPFResult | None,
    dkim: DKIMResult | None,
    resolver: DNSResolver | None = None,
) -> DMARCResult:
    """Evaluate DMARC for *from_domain* given already-computed SPF and DKIM results."""
    from_domain = (from_domain or "").strip().lower().rstrip(".")
    if not from_domain:
        return DMARCResult(NONE, "", reasons=["no usable From domain"])

    resolver = resolver or DnsPythonResolver()
    lookup = fetch_dmarc_record(from_domain, resolver)
    out = DMARCResult(
        result=NONE,
        from_domain=from_domain,
        policy_domain=lookup.policy_domain,
        spf_result=spf.result if spf else None,
        dkim_result=dkim.result if dkim else None,
    )
    if lookup.status == "temperror":
        out.result = TEMPERROR
        out.reasons.append(lookup.reason)
        return out
    if lookup.status == "invalid":
        out.result = NONE
        out.reasons.append(lookup.reason)
        return out
    if lookup.record is None:
        out.reasons.append(lookup.reason)
        return out

    record = lookup.record
    out.record = record
    out.adkim, out.aspf, out.pct = record.adkim, record.aspf, record.pct
    is_subdomain = lookup.policy_domain is not None and from_domain != lookup.policy_domain
    out.policy = record.subdomain_policy if is_subdomain else record.policy

    # SPF alignment
    if spf is not None and spf.passed:
        out.spf_aligned = domains_aligned(spf.domain, from_domain, record.aspf)
        if not out.spf_aligned:
            out.reasons.append(
                f"SPF passed for {spf.domain} but it is not aligned with {from_domain} "
                f"(aspf={record.aspf})"
            )
    else:
        out.reasons.append(f"SPF did not pass ({spf.result if spf else 'not evaluated'})")

    # DKIM alignment
    if dkim is not None and dkim.passed:
        out.dkim_aligned = any(
            domains_aligned(d, from_domain, record.adkim) for d in dkim.passing_domains
        )
        if not out.dkim_aligned:
            out.reasons.append(
                f"DKIM passed for {', '.join(dkim.passing_domains)} but is not aligned with "
                f"{from_domain} (adkim={record.adkim})"
            )
    else:
        out.reasons.append(f"DKIM did not pass ({dkim.result if dkim else 'not evaluated'})")

    if out.spf_aligned or out.dkim_aligned:
        out.result = PASS
        out.disposition = "none"
        out.reasons.append(
            "DMARC pass via " + " and ".join(
                n for n, ok in (("SPF", out.spf_aligned), ("DKIM", out.dkim_aligned)) if ok
            )
        )
    else:
        out.result = FAIL
        out.disposition = out.policy
        out.reasons.append(f"neither SPF nor DKIM is aligned; policy requests '{out.policy}'")
        if record.pct < 100:
            out.reasons.append(f"policy applies to only {record.pct}% of failing mail (pct=)")
    return out


# --------------------------------------------------------------------------------------
# One-call entry point
# --------------------------------------------------------------------------------------
_SPF_RISK = {"pass": 0.0, "neutral": 0.3, "none": 0.3, "temperror": 0.3,
             "permerror": 0.5, "softfail": 0.6, "fail": 1.0}
_DKIM_RISK = {"pass": 0.0, "none": 0.3, "temperror": 0.3, "permerror": 0.5,
              "policy": 0.5, "fail": 1.0}
_DMARC_FAIL_RISK = {"reject": 1.0, "quarantine": 0.85, "none": 0.6}


@dataclass
class AuthenticationSummary:
    spf: SPFResult
    dkim: DKIMResult
    dmarc: DMARCResult
    risk_factor: float  # 0.0 (fully authenticated) .. 1.0 (spoofed) - feeds scoring.auth_score
    verdict: str  # "pass" | "fail" | "partial" | "unauthenticated"

    def authentication_results_header(self, authserv_id: str = "phishshield.local") -> str:
        """An RFC 8601 ``Authentication-Results`` header value for the delivered message."""
        parts = [authserv_id]
        parts.append(f"spf={self.spf.result} smtp.mailfrom={self.spf.sender or 'null'}")
        if self.dkim.signatures:
            for sig in self.dkim.signatures:
                parts.append(f"dkim={sig.result} header.d={sig.domain or 'unknown'}")
        else:
            parts.append("dkim=none")
        parts.append(f"dmarc={self.dmarc.result} header.from={self.dmarc.from_domain or 'none'}")
        return "; ".join(parts)

    def to_dict(self) -> dict[str, object]:
        return {
            "spf": self.spf.to_dict(),
            "dkim": self.dkim.to_dict(),
            "dmarc": self.dmarc.to_dict(),
            "risk_factor": self.risk_factor,
            "verdict": self.verdict,
        }


def compute_risk_factor(spf: SPFResult, dkim: DKIMResult, dmarc: DMARCResult) -> float:
    """Suggested 0-1 risk for the scoring engine (``auth_score`` has weight 25 in PLAN.md)."""
    spf_risk = _SPF_RISK.get(spf.result, 0.5)
    dkim_risk = _DKIM_RISK.get(dkim.result, 0.5)
    if dmarc.result == PASS:
        risk = 0.2 * (spf_risk + dkim_risk) / 2  # aligned auth is strong evidence
    else:
        if dmarc.result == FAIL:
            dmarc_risk = _DMARC_FAIL_RISK.get(dmarc.disposition, 0.6)
        elif dmarc.result == NONE:
            dmarc_risk = 0.3
        else:
            dmarc_risk = 0.3
        risk = 0.4 * dmarc_risk + 0.3 * spf_risk + 0.3 * dkim_risk
        if dmarc.enforced_failure:
            risk = max(risk, 0.85)
    return round(min(max(risk, 0.0), 1.0), 3)


def authenticate_email(
    email: bytes | str | ParsedEmail,
    client_ip: str | None = None,
    helo: str = "",
    mail_from: str | None = None,
    resolver: DNSResolver | None = None,
    *,
    now: float | None = None,
) -> AuthenticationSummary:
    """Run SPF, DKIM and DMARC on one message.

    Args:
        email: raw message bytes/str, or an already parsed :class:`ParsedEmail`.
        client_ip: SMTP peer address from the socket. If omitted, the first public address in
            the ``Received`` chain is used as a fallback (attacker-controlled - prefer the
            real peer address).
        helo: HELO/EHLO name given by the client.
        mail_from: envelope sender; defaults to the ``Return-Path`` header, then ``From``.
        resolver: DNS backend (``FakeResolver`` for tests / simulations).
    """
    parsed = email if isinstance(email, ParsedEmail) else parse_email(email)
    resolver = resolver or DnsPythonResolver()

    ip = client_ip or parsed.guess_client_ip()
    if mail_from is None:
        mail_from = parsed.return_path if parsed.return_path is not None else parsed.from_address

    if ip:
        spf = check_spf(ip, mail_from, helo, resolver)
    else:
        spf = SPFResult(
            "none", "", mail_from or "", "", "client IP unknown; SPF could not be evaluated"
        )

    dkim = check_dkim(parsed.raw, resolver, now=now)
    dmarc = evaluate_dmarc(parsed.from_domain, spf, dkim, resolver)

    if dmarc.result == PASS:
        verdict = "pass"
    elif dmarc.result == FAIL:
        verdict = "fail"
    elif spf.passed or dkim.passed:
        verdict = "partial"
    else:
        verdict = "unauthenticated"
    return AuthenticationSummary(spf, dkim, dmarc, compute_risk_factor(spf, dkim, dmarc), verdict)
