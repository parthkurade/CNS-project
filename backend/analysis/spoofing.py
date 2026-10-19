"""
PhishShield — Spoofing Detector
================================
Detects email spoofing, lookalike domains, homoglyph attacks, and header
mismatches.  All detection logic is implemented in pure Python with no
third-party dependencies beyond the standard library.

Checks performed:
    * Display-name domain spoofing
    * Lookalike domain (Levenshtein distance ≤ 2 vs. popular domains)
    * Homoglyph / unicode normalisation attack
    * Reply-To / From domain mismatch
    * Return-Path / From domain mismatch
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

#: Canonical popular domains against which inbound sender domains are compared.
POPULAR_DOMAINS: list[str] = [
    "google.com",
    "gmail.com",
    "googlemail.com",
    "microsoft.com",
    "outlook.com",
    "live.com",
    "hotmail.com",
    "office365.com",
    "apple.com",
    "icloud.com",
    "me.com",
    "paypal.com",
    "amazon.com",
    "amazonaws.com",
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "yahoo.com",
    "yahoo.co.uk",
    "ymail.com",
    "dropbox.com",
    "box.com",
    "onedrive.com",
    "sharepoint.com",
    "zoom.us",
    "docusign.com",
    "docusign.net",
    "wellsfargo.com",
    "bankofamerica.com",
    "chase.com",
    "citibank.com",
    "irs.gov",
    "fedex.com",
    "ups.com",
    "dhl.com",
    "usps.com",
    "netflix.com",
    "spotify.com",
    "adobe.com",
    "salesforce.com",
    "slack.com",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "stackoverflow.com",
    "ebay.com",
    "etsy.com",
]

#: Known homoglyph substitution pairs (confusable → canonical).
#: Extended from Unicode confusable data (a practical subset).
_HOMOGLYPH_MAP: dict[str, str] = {
    # Digits ↔ letters
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "b",
    "7": "t",
    "8": "b",
    # Cyrillic lookalikes
    "а": "a",   # U+0430 CYRILLIC SMALL LETTER A
    "е": "e",   # U+0435 CYRILLIC SMALL LETTER IE
    "о": "o",   # U+043E CYRILLIC SMALL LETTER O
    "р": "p",   # U+0440 CYRILLIC SMALL LETTER ER
    "с": "c",   # U+0441 CYRILLIC SMALL LETTER ES
    "х": "x",   # U+0445 CYRILLIC SMALL LETTER HA
    "у": "y",   # U+0443 CYRILLIC SMALL LETTER U
    "і": "i",   # U+0456 CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    "ѕ": "s",   # U+0455 CYRILLIC SMALL LETTER DZE
    # Greek lookalikes
    "α": "a",   # U+03B1 GREEK SMALL LETTER ALPHA
    "ε": "e",   # U+03B5 GREEK SMALL LETTER EPSILON
    "ο": "o",   # U+03BF GREEK SMALL LETTER OMICRON
    "ρ": "p",   # U+03C1 GREEK SMALL LETTER RHO
    "ν": "v",   # U+03BD GREEK SMALL LETTER NU
    # Common visual confusables
    "ı": "i",   # U+0131 LATIN SMALL LETTER DOTLESS I
    "ĺ": "l",
    "ł": "l",
    "ö": "o",
    "ü": "u",
    "ä": "a",
    "ñ": "n",
}

#: Bi-gram substitutions for "rn" → "m", "vv" → "w", etc.
_BIGRAM_SUBS: list[tuple[str, str]] = [
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
    ("ii", "u"),
    ("ll", "i"),
]

#: Regex to extract the domain portion from an email address.
_EMAIL_DOMAIN_RE = re.compile(r"@([\w.-]+)$")

#: Regex to find domain-like strings inside display names.
_DISPLAY_DOMAIN_RE = re.compile(
    r"\b((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})\b"
)


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass
class SpoofingResult:
    """Result of all spoofing detection checks.

    Attributes:
        is_spoofed: ``True`` if any individual check fired.
        checks: Mapping of check name → bool (``True`` = suspicious).
        details: Mapping of check name → human-readable explanation string.
    """

    is_spoofed: bool
    checks: dict[str, bool]
    details: dict[str, str]

    @property
    def reply_to_mismatch(self) -> bool:
        return self.checks.get("reply_to_mismatch", False)

    @property
    def combined_score(self) -> float:
        weights = {
            "display_name_spoofing": 40.0,
            "lookalike_domain": 50.0,
            "homoglyph_attack": 50.0,
            "reply_to_mismatch": 30.0,
            "return_path_mismatch": 20.0,
        }
        score = sum(weights.get(k, 10.0) for k, v in self.checks.items() if v)
        return min(100.0, score)


class LookalikeResult(tuple):
    """2-tuple (is_lookalike, message) that also supports dict-like key access."""

    def __new__(cls, is_lookalike: bool, message: str):
        return super().__new__(cls, (is_lookalike, message))

    def __getitem__(self, item: Any) -> Any:
        if item == "is_lookalike":
            return self[0]
        if item in ("message", "detail"):
            return self[1]
        return super().__getitem__(item)

    @property
    def is_lookalike(self) -> bool:
        return self[0]


# ---------------------------------------------------------------------------
# Levenshtein distance (pure Python, no external deps)
# ---------------------------------------------------------------------------


def _levenshtein(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings.

    Uses the classic DP formulation with O(min(|s1|, |s2|)) space.

    Args:
        s1: First string.
        s2: Second string.

    Returns:
        Non-negative integer edit distance.
    """
    if s1 == s2:
        return 0
    # Ensure s1 is the shorter string (optimises space).
    if len(s1) > len(s2):
        s1, s2 = s2, s1
    n, m = len(s1), len(s2)
    # previous row of distances
    prev = list(range(n + 1))
    curr = [0] * (n + 1)
    for j in range(1, m + 1):
        curr[0] = j
        for i in range(1, n + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            curr[i] = min(
                curr[i - 1] + 1,       # insertion
                prev[i] + 1,            # deletion
                prev[i - 1] + cost,     # substitution
            )
        prev, curr = curr, prev
    return prev[n]


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _domain_from_address(address: str) -> str:
    """Extract the domain from a bare email address string or raw domain."""
    cleaned = address.strip()
    if "@" in cleaned:
        match = _EMAIL_DOMAIN_RE.search(cleaned)
        return match.group(1).lower() if match else ""
    return cleaned.lower()


def _normalize_homoglyphs(text: str) -> str:
    """Normalise *text* by replacing known homoglyphs with ASCII equivalents.

    Applies two passes:
    1. ``unicodedata.normalize('NFKD')`` to decompose ligatures / diacritics.
    2. Character-by-character substitution using :data:`_HOMOGLYPH_MAP`.
    3. Bi-gram substitutions using :data:`_BIGRAM_SUBS`.

    Args:
        text: Input string (typically a domain name).

    Returns:
        ASCII-safe normalised string for comparison purposes.
    """
    # Step 1: Unicode normalisation.
    normalised = unicodedata.normalize("NFKD", text)
    # Step 2: Character substitution.
    chars = [_HOMOGLYPH_MAP.get(ch, ch) for ch in normalised]
    result = "".join(chars)
    # Step 3: Bi-gram substitution.
    for confused, canonical in _BIGRAM_SUBS:
        result = result.replace(confused, canonical)
    return result.lower()


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def detect_display_name_spoofing(
    from_display_name: str,
    from_address: str,
) -> tuple[bool, str]:
    """Detect when the display name embeds a domain different from the sender.

    Phishers often set the display name to ``"PayPal Security <attacker@evil.com>"``
    so that naive mail clients show only the display name.

    Args:
        from_display_name: The display name component of the ``From`` header.
        from_address: The bare sender email address.

    Returns:
        ``(is_suspicious, detail_message)`` tuple.
    """
    if not from_display_name or not from_address:
        return False, ""

    sender_domain = _domain_from_address(from_address)
    if not sender_domain:
        return False, ""

    domains_in_name = _DISPLAY_DOMAIN_RE.findall(from_display_name)
    for domain in domains_in_name:
        domain_lower = domain.lower()
        if domain_lower != sender_domain:
            return (
                True,
                (
                    f"Display name contains domain '{domain_lower}' but "
                    f"actual sender domain is '{sender_domain}'"
                ),
            )
    return False, ""


def detect_lookalike_domain(
    from_address: str,
    reference_domains: list[str] | None = None,
    max_distance: int = 2,
) -> tuple[bool, str]:
    """Flag sender domain when it closely resembles a popular trusted domain.

    Uses Levenshtein edit distance with a configurable threshold.  Only
    domains that are *different* from the reference (i.e. not an exact match)
    are flagged.

    Args:
        from_address: Bare sender email address.
        reference_domains: List of trusted domain strings to compare against.
            Defaults to :data:`POPULAR_DOMAINS`.
        max_distance: Maximum edit distance to consider a lookalike.  Default
            is ``2``.

    Returns:
        ``(is_suspicious, detail_message)`` tuple.
    """
    if reference_domains is None:
        reference_domains = POPULAR_DOMAINS

    sender_domain = _domain_from_address(from_address)
    if not sender_domain:
        return False, ""

    for ref in reference_domains:
        ref_lower = ref.lower()
        if sender_domain == ref_lower:
            # Exact match — legitimate, not a lookalike.
            continue
        distance = _levenshtein(sender_domain, ref_lower)
        if distance <= max_distance:
            return LookalikeResult(
                True,
                (
                    f"Sender domain '{sender_domain}' is a lookalike of "
                    f"'{ref_lower}' (Levenshtein distance = {distance})"
                ),
            )
    return LookalikeResult(False, "")


def detect_homoglyph(from_address: str) -> tuple[bool, str]:
    """Detect homoglyph / IDN confusable attacks in the sender's domain.

    Normalises the sender domain using :func:`_normalize_homoglyphs` and then
    applies :func:`detect_lookalike_domain` on the normalised form.  If the
    *normalised* domain is a close match to a popular domain but the *original*
    domain is not, a homoglyph attack is likely.

    Args:
        from_address: Bare sender email address.

    Returns:
        ``(is_suspicious, detail_message)`` tuple.
    """
    sender_domain = _domain_from_address(from_address)
    if not sender_domain:
        return False, ""

    normalised_domain = _normalize_homoglyphs(sender_domain)

    # Skip if normalisation produced no change.
    if normalised_domain == sender_domain:
        return False, ""

    for ref in POPULAR_DOMAINS:
        ref_lower = ref.lower()
        # After normalisation the domain might be identical or very close.
        if normalised_domain == ref_lower or _levenshtein(normalised_domain, ref_lower) <= 1:
            if sender_domain != ref_lower:
                return (
                    True,
                    (
                        f"Possible homoglyph attack: '{sender_domain}' "
                        f"normalises to '{normalised_domain}', resembling '{ref_lower}'"
                    ),
                )
    return False, ""


def detect_reply_to_mismatch(
    from_address: str,
    reply_to_addresses: list[str],
) -> tuple[bool, str]:
    """Flag when any Reply-To domain differs from the From domain.

    Attackers set Reply-To to a harvesting address so that replies go to them
    while the From field shows a legitimate-looking address.

    Args:
        from_address: Bare sender email address.
        reply_to_addresses: List of bare addresses from the ``Reply-To`` header.

    Returns:
        ``(is_suspicious, detail_message)`` tuple.
    """
    sender_domain = _domain_from_address(from_address)
    if not sender_domain or not reply_to_addresses:
        return False, ""

    mismatches: list[str] = []
    for addr in reply_to_addresses:
        rt_domain = _domain_from_address(addr)
        if rt_domain and rt_domain != sender_domain:
            mismatches.append(f"'{addr}' (domain: {rt_domain})")

    if mismatches:
        return (
            True,
            (
                f"Reply-To domain differs from From domain '{sender_domain}': "
                + ", ".join(mismatches)
            ),
        )
    return False, ""


def detect_from_return_path_mismatch(
    from_address: str,
    return_path: str | None,
) -> tuple[bool, str]:
    """Flag when Return-Path domain differs from the From domain.

    A mismatched Return-Path is a strong indicator of sender forgery (the
    envelope-from differs from the header-from).

    Args:
        from_address: Bare sender email address.
        return_path: Bare address from the ``Return-Path`` header, or ``None``.

    Returns:
        ``(is_suspicious, detail_message)`` tuple.
    """
    if not return_path:
        return False, ""

    sender_domain = _domain_from_address(from_address)
    rp_domain = _domain_from_address(return_path)

    if not sender_domain or not rp_domain:
        return False, ""

    if sender_domain != rp_domain:
        return (
            True,
            (
                f"Return-Path domain '{rp_domain}' differs from "
                f"From domain '{sender_domain}'"
            ),
        )
    return False, ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_spoofing(
    from_display_name: str,
    from_address: str,
    reply_to_addresses: list[str],
    return_path: str | None,
) -> SpoofingResult:
    """Run all spoofing checks and aggregate results into a :class:`SpoofingResult`.

    Checks performed (in order):

    1. ``display_name_spoofing``   — display name embeds a foreign domain.
    2. ``lookalike_domain``        — sender domain ≈ popular trusted domain.
    3. ``homoglyph_attack``        — sender domain uses confusable unicode.
    4. ``reply_to_mismatch``       — Reply-To domain ≠ From domain.
    5. ``return_path_mismatch``    — Return-Path domain ≠ From domain.

    Args:
        from_display_name: The display name component of the ``From`` header.
        from_address: Bare sender email address.
        reply_to_addresses: List of bare addresses from ``Reply-To``.
        return_path: Bare address from ``Return-Path``, or ``None``.

    Returns:
        A :class:`SpoofingResult` with ``is_spoofed``, ``checks``, and
        ``details`` populated.

    Example::

        result = analyze_spoofing(
            from_display_name=parsed.from_display_name,
            from_address=parsed.from_address,
            reply_to_addresses=parsed.reply_to,
            return_path=parsed.return_path,
        )
        if result.is_spoofed:
            log.warning("Spoofing detected: %s", result.details)
    """
    checks: dict[str, bool] = {}
    details: dict[str, str] = {}

    # 1. Display name spoofing
    flag, msg = detect_display_name_spoofing(from_display_name, from_address)
    checks["display_name_spoofing"] = flag
    if msg:
        details["display_name_spoofing"] = msg

    # 2. Lookalike domain
    flag, msg = detect_lookalike_domain(from_address)
    checks["lookalike_domain"] = flag
    if msg:
        details["lookalike_domain"] = msg

    # 3. Homoglyph attack
    flag, msg = detect_homoglyph(from_address)
    checks["homoglyph_attack"] = flag
    if msg:
        details["homoglyph_attack"] = msg

    # 4. Reply-To mismatch
    flag, msg = detect_reply_to_mismatch(from_address, reply_to_addresses)
    checks["reply_to_mismatch"] = flag
    if msg:
        details["reply_to_mismatch"] = msg

    # 5. Return-Path mismatch
    flag, msg = detect_from_return_path_mismatch(from_address, return_path)
    checks["return_path_mismatch"] = flag
    if msg:
        details["return_path_mismatch"] = msg

    is_spoofed = any(checks.values())

    return SpoofingResult(
        is_spoofed=is_spoofed,
        checks=checks,
        details=details,
    )


def detect_spoofing(parsed: Any) -> SpoofingResult:
    """Analyze a ParsedEmail object for spoofing and lookalike characteristics."""
    from_display = getattr(parsed, "sender_display_name", "") or getattr(parsed, "from_display_name", "") or ""
    from_addr = getattr(parsed, "sender_address", "") or getattr(parsed, "from_address", "") or ""
    reply_to = getattr(parsed, "reply_to", None)
    if isinstance(reply_to, str):
        reply_to_list = [reply_to] if reply_to else []
    elif isinstance(reply_to, list):
        reply_to_list = reply_to
    else:
        reply_to_list = []
    return_path = getattr(parsed, "return_path", None)
    return analyze_spoofing(
        from_display_name=from_display,
        from_address=from_addr,
        reply_to_addresses=reply_to_list,
        return_path=return_path,
    )

