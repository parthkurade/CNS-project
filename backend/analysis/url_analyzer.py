"""
PhishShield — URL Analyzer
==========================
Extracts URLs from email text and HTML bodies, computes a rich feature vector
for each URL, then aggregates a risk score and a list of top risk factors.

External dependencies:
    tldextract  (``pip install tldextract``)
    beautifulsoup4 (``pip install beautifulsoup4``)

All other logic uses the Python standard library only.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass
from html.parser import HTMLParser

try:
    import tldextract  # type: ignore[import]
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "tldextract is required: pip install tldextract"
    ) from exc


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Known URL-shortening services (30+ entries).
URL_SHORTENERS: frozenset[str] = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "adf.ly",
        "bit.do",
        "mcaf.ee",
        "su.pr",
        "twit.ac",
        "lnkd.in",
        "db.tt",
        "qr.ae",
        "po.st",
        "bc.vc",
        "u.to",
        "j.mp",
        "buzurl.com",
        "cutt.us",
        "u.bb",
        "yourls.org",
        "x.co",
        "prettylinkpro.com",
        "scrnch.me",
        "filoops.info",
        "vzturl.com",
        "qr.net",
        "1url.com",
        "tweez.me",
        "v.gd",
        "tr.im",
        "link.zip.net",
        "rb.gy",
        "shorte.st",
        "clck.ru",
        "cutt.ly",
        "tiny.cc",
        "shorturl.at",
    }
)

#: TLDs commonly associated with phishing / free hosting abuse (50+ entries).
SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "xyz",
        "top",
        "pw",
        "cc",
        "club",
        "work",
        "party",
        "gdn",
        "racing",
        "loan",
        "download",
        "stream",
        "faith",
        "science",
        "trade",
        "review",
        "country",
        "kim",
        "cricket",
        "win",
        "bid",
        "webcam",
        "accountant",
        "men",
        "date",
        "ren",
        "vip",
        "link",
        "click",
        "uno",
        "fun",
        "buzz",
        "cyou",
        "monster",
        "cfd",
        "quest",
        "sbs",
        "bar",
        "hair",
        "beauty",
        "rest",
        "moscow",
        "wang",
        "surf",
        "guru",
        "cheap",
        "rocks",
    }
)

#: Keywords in paths / query strings that indicate credential-harvesting pages.
SUSPICIOUS_KEYWORDS: frozenset[str] = frozenset(
    {
        "login",
        "signin",
        "sign-in",
        "logon",
        "log-in",
        "verify",
        "verification",
        "account",
        "password",
        "passwd",
        "pwd",
        "confirm",
        "update",
        "secure",
        "security",
        "banking",
        "billing",
        "checkout",
        "submit",
        "credential",
        "auth",
        "authenticate",
        "reset",
        "recover",
        "support",
        "helpdesk",
        "validate",
        "reactivate",
        "unlock",
        "suspended",
        "limited",
        "unusual",
        "alert",
    }
)

#: Regex that matches most URL forms in plain text.
_URL_RE = re.compile(
    r"(?:https?|ftp)://"          # scheme
    r"[^\s<>\"'(){}\[\]\\]+"      # rest of URL (greedy, stops at whitespace/markup)
    r"[^\s<>\"'(){}\[\]\\.,;:!?]",  # avoid trailing punctuation
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# HTML link extractor
# ---------------------------------------------------------------------------


class _LinkExtractor(HTMLParser):
    """Minimal HTMLParser subclass that harvests URLs from href/src/action."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: list[tuple[str, str]] = []  # (url, anchor_text)
        self._current_href: str = ""
        self._capture_text: bool = False
        self._current_text_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = dict(attrs)
        url = (
            attr_map.get("href")
            or attr_map.get("src")
            or attr_map.get("action")
            or ""
        )
        if url and url.lower().startswith(("http://", "https://", "ftp://")):
            self._current_href = url
            self._capture_text = tag == "a"
            self._current_text_parts = []

    def handle_data(self, data: str) -> None:
        if self._capture_text:
            self._current_text_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if self._capture_text and tag == "a" and self._current_href:
            anchor_text = "".join(self._current_text_parts).strip()
            self.urls.append((self._current_href, anchor_text))
            self._current_href = ""
            self._capture_text = False
            self._current_text_parts = []


def _extract_urls_from_html(html: str) -> list[tuple[str, str]]:
    """Return ``(url, anchor_text)`` pairs from an HTML string.

    Args:
        html: Raw HTML body of the email.

    Returns:
        List of ``(url, anchor_text)`` tuples.  Anchor text is empty for
        non-``<a>`` tags.
    """
    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.urls


def _extract_urls_from_text(text: str) -> list[tuple[str, str]]:
    """Return ``(url, "")`` pairs from a plain-text string using regex.

    Args:
        text: Plain-text body of the email.

    Returns:
        List of ``(url, "")`` tuples (no anchor text in plain text).
    """
    return [(_url, "") for _url in _URL_RE.findall(text)]


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class URLFeatures:
    """Per-URL feature vector used for phishing risk assessment.

    Attributes:
        url: The original URL string.
        anchor_text: The visible link text (empty for plain-text URLs).
        is_ip_address: ``True`` when the host is a raw IPv4/IPv6 address.
        uses_url_shortener: ``True`` when the registered domain matches a known
            URL-shortening service.
        has_punycode: ``True`` when the hostname contains ``xn--``.
        suspicious_tld: ``True`` when the TLD is in :data:`SUSPICIOUS_TLDS`.
        subdomain_depth: Number of subdomain labels before the registered
            domain (0 when none).
        url_length: Total character length of the URL string.
        has_at_symbol: ``True`` when ``@`` appears in the URL, which browsers
            use to set user-info, tricking users into ignoring the real host.
        has_double_slash_redirect: ``True`` when ``//`` appears in the path
            component (excluding the scheme separator).
        anchor_text_mismatch: ``True`` when the anchor text contains a domain
            that differs from the URL's registered domain.
        excessive_subdomains: ``True`` when :attr:`subdomain_depth` exceeds 3.
        has_hyphen_in_domain: ``True`` when the registered domain label
            contains a hyphen.
        query_param_count: Number of distinct query parameters.
        path_depth: Number of path segments (``/``-delimited, excluding empty).
        uses_https: ``True`` when the scheme is ``https``.
        suspicious_keywords_in_url: List of matched suspicious keywords found
            in the full URL string (lowercased).
        risk_score: Per-URL risk score 0–100 computed from the features above.
    """

    url: str
    anchor_text: str
    is_ip_address: bool
    uses_url_shortener: bool
    has_punycode: bool
    suspicious_tld: bool
    subdomain_depth: int
    url_length: int
    has_at_symbol: bool
    has_double_slash_redirect: bool
    anchor_text_mismatch: bool
    excessive_subdomains: bool
    has_hyphen_in_domain: bool
    query_param_count: int
    path_depth: int
    uses_https: bool
    suspicious_keywords_in_url: list[str]
    risk_score: float = 0.0


@dataclass
class URLAnalysisResult:
    """Aggregated result of analyzing all URLs in an email.

    Attributes:
        urls_found: Feature vectors for every URL discovered.
        risk_score: Overall URL risk score (0–100), weighted average of
            per-URL scores, biased toward the worst offender.
        top_risks: Human-readable descriptions of the most serious findings.
    """

    urls_found: list[URLFeatures]
    risk_score: float
    top_risks: list[str]


# ---------------------------------------------------------------------------
# Feature computation
# ---------------------------------------------------------------------------


def _is_ip_address(host: str) -> bool:
    """Return ``True`` if *host* is a bare IPv4 or IPv6 address."""
    # Strip surrounding brackets for IPv6 literals (e.g. [::1]).
    stripped = host.strip("[]")
    try:
        ipaddress.ip_address(stripped)
        return True
    except ValueError:
        return False


def _compute_per_url_risk(features: URLFeatures) -> float:
    """Compute a 0–100 risk score for a single URL based on its features.

    The weights below are calibrated against common phishing indicators.
    They are additive with a ceiling of 100.

    Args:
        features: A populated :class:`URLFeatures` instance.

    Returns:
        Float in [0, 100].
    """
    score = 0.0

    if features.is_ip_address:
        score += 25.0
    if features.uses_url_shortener:
        score += 20.0
    if features.has_at_symbol:
        score += 20.0
    if features.anchor_text_mismatch:
        score += 15.0
    if features.has_punycode:
        score += 15.0
    if features.suspicious_tld:
        score += 10.0
    if features.excessive_subdomains:
        score += 10.0
    if features.has_double_slash_redirect:
        score += 10.0
    if features.has_hyphen_in_domain:
        score += 5.0
    if not features.uses_https:
        score += 5.0

    # Suspicious keywords
    kw_count = len(features.suspicious_keywords_in_url)
    score += min(kw_count * 5.0, 20.0)

    # URL length heuristic (> 100 chars is suspicious)
    if features.url_length > 200:
        score += 10.0
    elif features.url_length > 100:
        score += 5.0

    # Query-parameter depth heuristic
    if features.query_param_count > 5:
        score += 5.0

    return min(score, 100.0)


def _extract_anchor_domain(anchor_text: str) -> str | None:
    """Try to extract a domain name from anchor text.

    Looks for patterns like ``https://example.com`` or bare ``example.com``
    inside the anchor text.

    Args:
        anchor_text: Visible text of an HTML anchor element.

    Returns:
        Registered domain (``example.com``) if found, else ``None``.
    """
    # Look for explicit URL in anchor text.
    url_match = _URL_RE.search(anchor_text)
    if url_match:
        extracted = tldextract.extract(url_match.group(0))
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
    # Look for bare domain-like text.
    bare = re.search(r"\b([a-zA-Z0-9-]+\.[a-zA-Z]{2,})\b", anchor_text)
    if bare:
        extracted = tldextract.extract(bare.group(1))
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
    return None


def _build_url_features(url: str, anchor_text: str) -> URLFeatures:
    """Build a :class:`URLFeatures` instance for a single URL.

    Args:
        url: The URL string to analyse.
        anchor_text: The visible link text associated with the URL (may be
            empty).

    Returns:
        A populated :class:`URLFeatures` with :attr:`~URLFeatures.risk_score`
        set.
    """
    parsed = urllib.parse.urlparse(url)
    host: str = parsed.hostname or ""
    path: str = parsed.path or ""
    query: str = parsed.query or ""

    # tldextract gives us subdomain / domain / suffix
    ext = tldextract.extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    subdomain_parts = [s for s in ext.subdomain.split(".") if s] if ext.subdomain else []
    subdomain_depth = len(subdomain_parts)

    # --- Feature flags ---
    is_ip = _is_ip_address(host)
    shortener = registered_domain.lower() in URL_SHORTENERS
    punycode = "xn--" in host.lower()
    susp_tld = ext.suffix.lower() in SUSPICIOUS_TLDS if ext.suffix else False
    at_symbol = "@" in url
    # double-slash in path (beyond leading slash)
    path_without_leading = path.lstrip("/")
    double_slash = "//" in path_without_leading
    excessive_subs = subdomain_depth > 3
    hyphen_in_domain = "-" in ext.domain

    # Query param count
    query_params: dict[str, list[str]] = urllib.parse.parse_qs(query, keep_blank_values=True)
    param_count = len(query_params)

    # Path depth
    path_segments = [p for p in path.split("/") if p]
    path_depth = len(path_segments)

    # HTTPS
    uses_https = parsed.scheme.lower() == "https"

    # Suspicious keywords in the lowercased full URL
    url_lower = url.lower()
    matched_keywords = sorted(
        kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower
    )

    # Anchor-text mismatch
    anchor_mismatch = False
    if anchor_text:
        anchor_domain = _extract_anchor_domain(anchor_text)
        if anchor_domain and anchor_domain.lower() != registered_domain.lower():
            anchor_mismatch = True

    features = URLFeatures(
        url=url,
        anchor_text=anchor_text,
        is_ip_address=is_ip,
        uses_url_shortener=shortener,
        has_punycode=punycode,
        suspicious_tld=susp_tld,
        subdomain_depth=subdomain_depth,
        url_length=len(url),
        has_at_symbol=at_symbol,
        has_double_slash_redirect=double_slash,
        anchor_text_mismatch=anchor_mismatch,
        excessive_subdomains=excessive_subs,
        has_hyphen_in_domain=hyphen_in_domain,
        query_param_count=param_count,
        path_depth=path_depth,
        uses_https=uses_https,
        suspicious_keywords_in_url=matched_keywords,
    )
    features.risk_score = _compute_per_url_risk(features)
    return features


# ---------------------------------------------------------------------------
# Risk aggregation helpers
# ---------------------------------------------------------------------------


def _aggregate_risk(url_features: list[URLFeatures]) -> tuple[float, list[str]]:
    """Compute aggregate risk score and top risk strings for all URLs.

    Strategy: take the maximum per-URL score as the baseline, then blend with
    the mean to avoid masking widespread low-severity findings.

    Args:
        url_features: List of per-URL feature objects.

    Returns:
        ``(overall_score, top_risks)`` where *overall_score* ∈ [0, 100].
    """
    if not url_features:
        return 0.0, []

    scores = [f.risk_score for f in url_features]
    max_score = max(scores)
    mean_score = sum(scores) / len(scores)
    overall = 0.7 * max_score + 0.3 * mean_score

    top_risks: list[str] = []

    # Collect notable findings across all URLs.
    ip_urls = [f.url for f in url_features if f.is_ip_address]
    if ip_urls:
        top_risks.append(
            f"Raw IP address used as host in {len(ip_urls)} URL(s): "
            + ", ".join(ip_urls[:3])
        )

    shortener_urls = [f.url for f in url_features if f.uses_url_shortener]
    if shortener_urls:
        top_risks.append(
            f"URL shortener detected in {len(shortener_urls)} URL(s): "
            + ", ".join(shortener_urls[:3])
        )

    mismatch_urls = [f.url for f in url_features if f.anchor_text_mismatch]
    if mismatch_urls:
        top_risks.append(
            f"Anchor-text/href domain mismatch in {len(mismatch_urls)} link(s)"
        )

    punycode_urls = [f.url for f in url_features if f.has_punycode]
    if punycode_urls:
        top_risks.append(
            f"Punycode (IDN homoglyph) in {len(punycode_urls)} URL(s): "
            + ", ".join(punycode_urls[:3])
        )

    susp_tld_urls = [f.url for f in url_features if f.suspicious_tld]
    if susp_tld_urls:
        top_risks.append(
            f"Suspicious TLD in {len(susp_tld_urls)} URL(s): "
            + ", ".join(susp_tld_urls[:3])
        )

    at_urls = [f.url for f in url_features if f.has_at_symbol]
    if at_urls:
        top_risks.append(
            f"@ symbol in URL (user-info spoofing) in {len(at_urls)} URL(s)"
        )

    kw_urls = [f for f in url_features if f.suspicious_keywords_in_url]
    if kw_urls:
        sample = kw_urls[0]
        top_risks.append(
            f"Suspicious keywords ({', '.join(sample.suspicious_keywords_in_url[:5])}) "
            f"found in URL: {sample.url[:80]}"
        )

    http_urls = [f.url for f in url_features if not f.uses_https]
    if http_urls:
        top_risks.append(
            f"{len(http_urls)} URL(s) use plain HTTP (not HTTPS)"
        )

    return round(min(overall, 100.0), 2), top_risks


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_urls(text_body: str, html_body: str) -> URLAnalysisResult:
    """Extract and analyze all URLs from an email's text and HTML bodies.

    URLs are deduplicated by their raw string before feature computation.
    Text-body URLs receive an empty anchor text; HTML-body ``<a>`` tags
    preserve their visible text for anchor-mismatch detection.

    Args:
        text_body: Decoded ``text/plain`` body of the email.
        html_body: Decoded ``text/html`` body of the email.

    Returns:
        A :class:`URLAnalysisResult` with per-URL features, an overall risk
        score, and a list of human-readable top-risk descriptions.

    Example::

        result = analyze_urls(email.text_body, email.html_body)
        if result.risk_score > 70:
            quarantine(email)
    """
    # Collect URLs with anchor text from both body types.
    seen: dict[str, str] = {}  # url → anchor_text (html wins over text)
    for url, anchor in _extract_urls_from_text(text_body):
        if url not in seen:
            seen[url] = anchor
    for url, anchor in _extract_urls_from_html(html_body):
        # HTML anchor text always overrides plain-text entry for same URL.
        seen[url] = anchor

    url_features: list[URLFeatures] = [
        _build_url_features(url, anchor) for url, anchor in seen.items()
    ]

    overall_score, top_risks = _aggregate_risk(url_features)

    return URLAnalysisResult(
        urls_found=url_features,
        risk_score=overall_score,
        top_risks=top_risks,
    )
