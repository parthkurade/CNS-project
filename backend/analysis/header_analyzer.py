"""
PhishShield — Header Analyzer
==============================
Analyses email headers for anomalies including Received-chain tampering,
authentication failures, suspicious X-headers, CRLF injection attempts,
and malformed Date values.

All logic uses the Python standard library only.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

#: Extracts the first IPv4 address from a ``Received`` header value.
_IP_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

#: Extracts IPv6 addresses (simplified pattern covering bracketed forms).
_IPV6_RE = re.compile(
    r"\[?([0-9a-fA-F:]{2,39})\]?",
    re.IGNORECASE,
)

#: Detects CRLF sequences or bare CR/LF inside a single header value
#: (excluding legal RFC 2822/5322 header folding where CRLF is followed by space/tab).
_CRLF_RE = re.compile(r"(\r\n|\r|\n)(?![ \t])")

#: Suspicious X-header names that may indicate spamming tools or exploitation.
_SUSPICIOUS_X_HEADERS: frozenset[str] = frozenset(
    {
        "x-php-originating-script",
        "x-originating-script",
        "x-mailer-template",
        "x-spam-flag",
        "x-bulk-mail",
        "x-mass-mailing",
        "x-campaign",
        "x-advertisement",
        "x-advertising",
        "x-phpmailer-used",
        "x-bulkmail",
        "x-listserver",
    }
)

#: RFC 1918 private and special-use IPv4 networks.
_PRIVATE_NETWORKS: list[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("100.64.0.0/10"),
]

#: How many hours in the future a Date header must be to flag as anomalous.
_FUTURE_HOURS_THRESHOLD = 24

#: How many days old a Date header must be to flag as anomalous (very old).
_OLD_DAYS_THRESHOLD = 365 * 10  # 10 years


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass
class HeaderAnalysisResult:
    """Aggregated result of all email header analyses.

    Attributes:
        received_chain_ips: List of IPs extracted from ``Received`` headers, in
            wire order (index 0 = outermost / first hop).
        forwarding_loops: List of IPs that appear more than once in the chain,
            indicating a routing loop.
        private_ips_in_public_path: IPs from the Received chain that belong to
            RFC 1918 / special-use space, which is suspicious in public mail.
        authentication: Parsed authentication results keyed by mechanism
            (``spf``, ``dkim``, ``dmarc``) → result string.
        suspicious_x_headers: List of lower-cased X-header names that matched
            known-suspicious patterns.
        header_injection_findings: Mapping of header name → injected content
            for any header containing CRLF sequences.
        date_analysis: Dict with keys ``raw``, ``parsed``, ``is_future``,
            ``is_very_old``, ``offset_hours``.
        risk_factors: Human-readable list of all findings that elevate risk.
        score: Overall header risk score 0–100.
    """

    received_chain_ips: list[str] = field(default_factory=list)
    forwarding_loops: list[str] = field(default_factory=list)
    private_ips_in_public_path: list[str] = field(default_factory=list)
    authentication: dict[str, str] = field(default_factory=dict)
    suspicious_x_headers: list[str] = field(default_factory=list)
    header_injection_findings: dict[str, str] = field(default_factory=dict)
    date_analysis: dict[str, Any] = field(default_factory=dict)
    risk_factors: list[str] = field(default_factory=list)
    score: float = 0.0


# ---------------------------------------------------------------------------
# Individual analysis functions
# ---------------------------------------------------------------------------


def _is_private_ip(ip_str: str) -> bool:
    """Return ``True`` if *ip_str* falls within an RFC 1918 or special-use range.

    Args:
        ip_str: A dotted-decimal IPv4 address string.

    Returns:
        Boolean.
    """
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE_NETWORKS)


def analyze_received_chain(
    received_headers: list[str],
) -> tuple[list[str], list[str], list[str]]:
    """Parse Received headers to extract IPs and detect anomalies.

    Each ``Received`` header is searched for IPv4 addresses.  The function
    detects:

    * **Forwarding loops**: the same IP appearing more than once in the chain.
    * **Private/local IPs in public paths**: RFC 1918 addresses present beyond
      the first (internal relay) hop.

    Args:
        received_headers: Ordered list of raw ``Received`` header values,
            index 0 = outermost (first to receive the message).

    Returns:
        A 3-tuple of:
        * ``chain_ips`` — all extracted IP strings in chain order.
        * ``loops`` — IPs seen more than once.
        * ``private_in_public`` — private IPs at non-final hops.
    """
    chain_ips: list[str] = []
    seen: dict[str, int] = {}

    for header in received_headers:
        ips = _IP_RE.findall(header)
        for ip in ips:
            if ip not in chain_ips:
                chain_ips.append(ip)
            seen[ip] = seen.get(ip, 0) + 1

    loops = [ip for ip, count in seen.items() if count > 1]

    # Private IPs are expected only in the last hop (internal delivery).
    # Flag any private IP appearing earlier than the final hop.
    private_in_public: list[str] = []
    for ip in chain_ips[:-1]:  # Exclude final (last) hop.
        if _is_private_ip(ip):
            private_in_public.append(ip)

    return chain_ips, loops, private_in_public


def analyze_authentication_results(
    auth_results_header: str | None,
) -> dict[str, str]:
    """Parse the ``Authentication-Results`` header into a structured dict.

    Supports ``spf``, ``dkim``, and ``dmarc`` result extraction.  Unknown
    mechanisms are stored with the key ``unknown_N``.

    Args:
        auth_results_header: Raw value of the ``Authentication-Results`` header,
            or ``None`` when absent.

    Returns:
        Dict mapping mechanism name → result value, e.g.
        ``{"spf": "pass", "dkim": "fail", "dmarc": "none"}``.
    """
    if not auth_results_header:
        return {}

    result: dict[str, str] = {}
    # Patterns like: spf=pass, dkim=fail, dmarc=none (may include reason strings)
    pattern = re.compile(
        r"\b(spf|dkim|dmarc|arc|bimi)\s*=\s*([a-zA-Z]+)",
        re.IGNORECASE,
    )
    unknown_idx = 0
    for match in pattern.finditer(auth_results_header):
        mechanism = match.group(1).lower()
        value = match.group(2).lower()
        if mechanism in result:
            unknown_idx += 1
            result[f"unknown_{unknown_idx}_{mechanism}"] = value
        else:
            result[mechanism] = value

    return result


def analyze_x_headers(
    all_headers: dict[str, str],
) -> list[str]:
    """Identify X-headers associated with bulk-mail or exploit toolkits.

    Args:
        all_headers: Complete mapping of header name → value as returned by
            the email parser.

    Returns:
        List of lower-cased header names that matched known-suspicious patterns.
    """
    found: list[str] = []
    for key in all_headers:
        key_lower = key.lower()
        if key_lower in _SUSPICIOUS_X_HEADERS:
            found.append(key_lower)
    return found


def detect_header_injection(
    all_headers: dict[str, str],
) -> dict[str, str]:
    """Scan all header values for CRLF injection sequences.

    CRLF injection in header values can allow attackers to inject additional
    headers (e.g. ``Bcc:``) and is a known email injection technique.

    Args:
        all_headers: Complete mapping of header name → value.

    Returns:
        Dict of ``header_name → injected_snippet`` for any headers containing
        CR, LF, or CRLF sequences.  Empty dict if no injection is detected.
    """
    findings: dict[str, str] = {}
    for name, value in all_headers.items():
        val_clean = value.rstrip("\r\n")
        match = _CRLF_RE.search(val_clean)
        if match:
            # Capture a short snippet around the injection point.
            start = max(0, match.start() - 20)
            end = min(len(val_clean), match.end() + 40)
            snippet = repr(val_clean[start:end])
            findings[name] = snippet
    return findings


def analyze_date_header(
    raw_date: str | None,
) -> dict[str, Any]:
    """Analyse the ``Date`` header for temporal anomalies.

    Args:
        raw_date: Raw value of the ``Date`` header, or ``None``.

    Returns:
        A dict with the following keys:

        * ``raw`` (str | None): The original header value.
        * ``parsed`` (str | None): ISO-8601 representation of the parsed date.
        * ``is_future`` (bool): ``True`` when the date is more than
          :data:`_FUTURE_HOURS_THRESHOLD` hours in the future.
        * ``is_very_old`` (bool): ``True`` when the date is more than
          :data:`_OLD_DAYS_THRESHOLD` days in the past.
        * ``is_unparseable`` (bool): ``True`` when parsing failed entirely.
        * ``offset_hours`` (float | None): Hours difference from *now* (UTC);
          negative = past.
    """
    import email.utils

    result: dict[str, Any] = {
        "raw": raw_date,
        "parsed": None,
        "is_future": False,
        "is_very_old": False,
        "is_unparseable": False,
        "offset_hours": None,
    }

    if not raw_date:
        result["is_unparseable"] = True
        return result

    try:
        parsed_dt = email.utils.parsedate_to_datetime(raw_date)
    except Exception:
        result["is_unparseable"] = True
        return result

    # Ensure timezone-aware for comparison.
    if parsed_dt.tzinfo is None:
        parsed_dt = parsed_dt.replace(tzinfo=UTC)

    now = datetime.now(tz=UTC)
    delta = parsed_dt - now
    offset_hours = delta.total_seconds() / 3600.0

    result["parsed"] = parsed_dt.isoformat()
    result["offset_hours"] = round(offset_hours, 2)
    result["is_future"] = offset_hours > _FUTURE_HOURS_THRESHOLD
    result["is_very_old"] = offset_hours < -(_OLD_DAYS_THRESHOLD * 24)

    return result


# ---------------------------------------------------------------------------
# Risk score computation
# ---------------------------------------------------------------------------


def _compute_header_score(
    loops: list[str],
    private_in_public: list[str],
    auth: dict[str, str],
    suspicious_x: list[str],
    injection: dict[str, str],
    date_info: dict[str, Any],
) -> tuple[float, list[str]]:
    """Compute a 0–100 header risk score and enumerate risk factors.

    Args:
        loops: IP forwarding loops.
        private_in_public: Private IPs at non-final hops.
        auth: Authentication-Results dict.
        suspicious_x: Suspicious X-header names.
        injection: CRLF injection findings.
        date_info: Output of :func:`analyze_date_header`.

    Returns:
        ``(score, risk_factors)`` tuple.
    """
    score = 0.0
    risk_factors: list[str] = []

    # CRLF injection is critical.
    if injection:
        score += 40.0
        for hdr, snippet in injection.items():
            risk_factors.append(
                f"CRLF injection detected in header '{hdr}': {snippet}"
            )

    # Authentication failures.
    for mechanism in ("spf", "dkim", "dmarc"):
        value = auth.get(mechanism, "")
        if value in ("fail", "softfail", "hardfail", "none", "neutral", "permerror", "temperror"):
            score += 15.0
            risk_factors.append(
                f"Authentication failure: {mechanism.upper()}={value}"
            )
        elif value == "pass":
            # Pass: mild score reduction (floor at 0).
            score = max(0.0, score - 3.0)

    # Forwarding loops.
    if loops:
        score += 20.0
        risk_factors.append(
            f"Forwarding loop detected — IPs appear multiple times: {', '.join(loops)}"
        )

    # Private IPs in public path.
    if private_in_public:
        score += 15.0
        risk_factors.append(
            "Private/reserved IP(s) at non-final Received hop(s): "
            + ", ".join(private_in_public)
        )

    # Suspicious X-headers.
    if suspicious_x:
        score += min(len(suspicious_x) * 5.0, 20.0)
        risk_factors.append(
            f"Suspicious X-header(s) present: {', '.join(suspicious_x)}"
        )

    # Date anomalies.
    if date_info.get("is_unparseable"):
        score += 10.0
        risk_factors.append("Date header is absent or unparseable")
    elif date_info.get("is_future"):
        score += 15.0
        hrs = date_info.get("offset_hours", 0)
        risk_factors.append(
            f"Date header is {hrs:.1f} hours in the future"
        )
    elif date_info.get("is_very_old"):
        score += 10.0
        risk_factors.append(
            "Date header is more than 10 years in the past"
        )

    return round(min(score, 100.0), 2), risk_factors


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_headers(
    all_headers: dict[str, str],
    received_headers: list[str],
) -> HeaderAnalysisResult:
    """Run all header analyses and return a consolidated :class:`HeaderAnalysisResult`.

    Args:
        all_headers: Complete ordered mapping of header name → value as
            produced by the email parser.  Used for X-header and injection
            scanning, and for extracting the ``Date`` value.
        received_headers: Ordered list of raw ``Received`` header values in
            wire order (index 0 = first hop to receive the message).

    Returns:
        A fully populated :class:`HeaderAnalysisResult`.

    Example::

        result = analyze_headers(
            all_headers=parsed_email.all_headers,
            received_headers=parsed_email.received_chain,
        )
        if result.score > 50:
            log.warning("Header anomalies: %s", result.risk_factors)
    """
    # Received chain analysis.
    chain_ips, loops, private_in_public = analyze_received_chain(received_headers)

    # Authentication-Results.
    auth_raw = all_headers.get("Authentication-Results") or all_headers.get(
        "authentication-results"
    )
    auth = analyze_authentication_results(auth_raw)

    # X-header scan.
    suspicious_x = analyze_x_headers(all_headers)

    # Header injection scan.
    injection = detect_header_injection(all_headers)

    # Date analysis.
    raw_date = all_headers.get("Date") or all_headers.get("date")
    date_info = analyze_date_header(raw_date)

    # Aggregate score.
    score, risk_factors = _compute_header_score(
        loops=loops,
        private_in_public=private_in_public,
        auth=auth,
        suspicious_x=suspicious_x,
        injection=injection,
        date_info=date_info,
    )

    return HeaderAnalysisResult(
        received_chain_ips=chain_ips,
        forwarding_loops=loops,
        private_ips_in_public_path=private_in_public,
        authentication=auth,
        suspicious_x_headers=suspicious_x,
        header_injection_findings=injection,
        date_analysis=date_info,
        risk_factors=risk_factors,
        score=score,
    )
