"""
attachment.py — PhishShield Attachment Analysis Module
======================================================
Analyses email attachments for malicious indicators, including:
  - Dangerous file extensions (100+ types)
  - Double-extension spoofing (e.g. invoice.pdf.exe)
  - Office documents potentially containing macros
  - SHA-256 hash computation
  - Optional VirusTotal API v3 lookup (requires VT_API_KEY env var)

All public functionality is exposed through :func:`analyze_attachment`.
"""

import hashlib
import logging
import mimetypes
import os
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dangerous extension set (100+ entries)
# ---------------------------------------------------------------------------
_DANGEROUS_EXTENSIONS: set[str] = {
    # Executables
    ".exe", ".com", ".scr", ".pif", ".application", ".gadget",
    ".msi", ".msp", ".mst", ".msu",
    # Script files
    ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".wsc", ".ps1", ".ps2", ".psc1", ".psc2", ".psm1", ".psd1",
    ".ps1xml", ".ps2xml", ".cdxml", ".clixml",
    # HTML application / HTA
    ".hta", ".htc",
    # Registry / INF
    ".reg", ".inf",
    # Compiled / bytecode
    ".jar", ".class", ".war", ".ear",
    # Library / object
    ".dll", ".ocx", ".sys", ".drv", ".cpl", ".scf",
    # Shortcut / link
    ".lnk", ".url",
    # Macro-enabled Office
    ".xlsm", ".xltm", ".xlam", ".docm", ".dotm", ".potm", ".ppsm",
    ".pptm", ".sldm", ".accde",
    # Python / Ruby / Perl
    ".py", ".pyc", ".pyw", ".rb", ".pl", ".pm",
    # Shell scripts
    ".sh", ".bash", ".zsh", ".fish", ".ksh", ".csh", ".tcsh",
    # PHP / server-side
    ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar",
    # ASP / JSP
    ".asp", ".aspx", ".jsp", ".jspx",
    # Compiled binaries (Unix-like)
    ".elf", ".bin", ".out", ".dex", ".apk", ".ipa",
    # Archives that may auto-run
    ".iso", ".img", ".dmg", ".vhd", ".vhdx",
    # Compressed (often used to hide payloads)
    ".cab", ".ace", ".arj",
    # Macro-script / Office legacy
    ".wbk", ".xlb", ".xll",
    # Windows Installer transform / patch
    ".mst",
    # Control panel
    ".cpl",
    # Java web start
    ".jnlp",
    # XML-embedded scripts
    ".xsl", ".xslt",
    # Symbolic link / Unix
    ".desktop",
    # Compiled HTML help
    ".chm",
    # VirtualPC disk
    ".vpc",
    # XPS / OXPS (can embed scripts)
    ".xps", ".oxps",
    # PowerPoint add-in
    ".ppa", ".ppam",
    # Excel add-in
    ".xla",
    # Word template
    ".dot",
    # Excel template
    ".xlt",
    # Windows script component
    ".sct",
    # Windows Management Script
    ".msc",
    # AppX (Windows package)
    ".appx", ".appxbundle", ".msix", ".msixbundle",
    # Delphi / Borland
    ".dpl",
    # AutoHotKey
    ".ahk",
    # Visual Basic project
    ".vbp",
    # C# / .NET
    ".csx",
    # Office 2003 XML
    ".xml",  # intentionally included; context-dependent
    # Miscellaneous executable formats
    ".ex_", ".ex!", ".ex$",
    # Command files
    ".cmd",
    # Node.js
    ".mjs", ".cjs",
    # Electron / Node executable
    ".node",
    # Lua
    ".lua",
    # Tcl
    ".tcl",
    # Swift / compiled macOS
    ".swift", ".dylib",
    # Rust / C object files
    ".so", ".o", ".a",
    # Windows task / service
    ".job",
    # MSBuild project (can execute arbitrary code)
    ".csproj", ".vbproj", ".fsproj", ".proj",
}

# ---------------------------------------------------------------------------
# Extensions / MIME types for Office files that may contain macros
# ---------------------------------------------------------------------------
_MACRO_OFFICE_EXTENSIONS: set[str] = {
    ".doc", ".dot", ".xls", ".xlt", ".xlb", ".ppt", ".pot",
    ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm",
    ".ppsm", ".sldm", ".accde", ".accdb", ".accda", ".accdt",
    ".pub", ".xla", ".ppa", ".ppam", ".wbk", ".xll",
}

_MACRO_OFFICE_MIMES: set[str] = {
    "application/msword",
    "application/vnd.ms-word",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/vnd.ms-access",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.ms-officetheme",
    "application/vnd.ms-word.document.macroEnabled.12",
    "application/vnd.ms-excel.sheet.macroEnabled.12",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
}

# VirusTotal API v3 base URL
_VT_API_BASE = "https://www.virustotal.com/api/v3"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass
class AttachmentAnalysis:
    """Comprehensive analysis result for a single email attachment.

    Attributes:
        filename: The attachment filename as declared in the email.
        sha256: Hex-encoded SHA-256 digest of the attachment content.
        size_bytes: Size of the attachment in bytes.
        mime_type: MIME type guessed from filename (may be empty).
        is_dangerous_extension: True if the primary extension is in the
            dangerous-extension list.
        dangerous_extension: The dangerous extension found, or empty string.
        is_double_extension: True if a double-extension spoofing pattern
            was detected (e.g. ``invoice.pdf.exe``).
        double_extension_pattern: Description of the detected double-extension
            pattern, or empty string.
        is_macro_office: True if the file appears to be an Office document
            that may contain macros.
        macro_reason: Explanation of why the file is flagged for macros.
        vt_detection_count: Number of VirusTotal engines that flagged the
            file, or None if VT lookup was skipped / unavailable.
        vt_total_engines: Total number of engines that scanned the file on
            VirusTotal, or None if lookup was skipped.
        vt_permalink: VirusTotal report URL for the file hash, or empty string.
        risk_score: Integer 0–100 reflecting overall assessed risk.
        risk_factors: List of human-readable strings describing each risk factor
            that contributed to the risk_score.
    """

    filename: str
    sha256: str
    size_bytes: int
    mime_type: str
    is_dangerous_extension: bool = False
    dangerous_extension: str = ""
    is_double_extension: bool = False
    double_extension_pattern: str = ""
    is_macro_office: bool = False
    macro_reason: str = ""
    vt_detection_count: int | None = None
    vt_total_engines: int | None = None
    vt_permalink: str = ""
    risk_score: int = 0
    risk_factors: list[str] = field(default_factory=list)

    @property
    def virustotal_detections(self) -> int:
        return self.vt_detection_count or 0


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------

def check_dangerous_extension(filename: str) -> tuple[bool, str]:
    """Determine whether *filename* carries a known-dangerous extension.

    The comparison is case-insensitive.

    Args:
        filename: The attachment filename, including extension.

    Returns:
        A tuple ``(is_dangerous, extension)`` where *is_dangerous* is True
        if the extension is in the dangerous list, and *extension* is the
        matched extension string (e.g. ``'.exe'``), or empty string if safe.

    Examples:
        >>> check_dangerous_extension("malware.exe")
        (True, '.exe')
        >>> check_dangerous_extension("document.pdf")
        (False, '')
    """
    if not filename:
        return False, ""

    # os.path.splitext handles compound names correctly (returns last ext)
    _, ext = os.path.splitext(filename.lower())
    if ext in _DANGEROUS_EXTENSIONS:
        return True, ext
    return False, ""


def check_double_extension(filename: str) -> tuple[bool, str]:
    """Detect double-extension spoofing patterns in *filename*.

    A double extension attack disguises an executable as a harmless file
    by prepending a benign-looking extension (e.g. ``.pdf``, ``.jpg``) before
    the real dangerous extension (e.g. ``.exe``, ``.vbs``).

    Args:
        filename: The attachment filename.

    Returns:
        A tuple ``(is_double_ext, description)`` where *is_double_ext* is
        True when a suspicious double-extension is detected, and *description*
        provides the pattern found.

    Examples:
        >>> check_double_extension("invoice.pdf.exe")
        (True, "Double extension detected: disguised as '.pdf', actual '.exe'")
        >>> check_double_extension("photo.jpg")
        (False, '')
    """
    if not filename:
        return False, ""

    # Strip leading path separators for safety
    base = os.path.basename(filename)
    parts = base.split(".")

    # Need at least three parts: name, fake_ext, real_ext
    if len(parts) < 3:
        return False, ""

    # The "real" extension is the last one; the "disguise" is the second-to-last
    real_ext = f".{parts[-1].lower()}"
    disguise_ext = f".{parts[-2].lower()}"

    if real_ext in _DANGEROUS_EXTENSIONS and disguise_ext not in _DANGEROUS_EXTENSIONS:
        description = (
            f"Double extension detected: disguised as '{disguise_ext}', "
            f"actual '{real_ext}' — possible file type spoofing."
        )
        return True, description

    # Also flag when both are dangerous (chained obfuscation)
    if real_ext in _DANGEROUS_EXTENSIONS and disguise_ext in _DANGEROUS_EXTENSIONS:
        description = (
            f"Multiple dangerous extensions: '{disguise_ext}' + '{real_ext}' — "
            "possible chained obfuscation."
        )
        return True, description

    return False, ""


def check_macro_office(filename: str, mime_type: str = "") -> tuple[bool, str]:
    """Determine whether *filename* represents an Office document that may
    contain executable macros.

    Checks both the file extension and the supplied MIME type.

    Args:
        filename: The attachment filename.
        mime_type: The declared MIME type of the attachment (optional).

    Returns:
        A tuple ``(is_macro_office, reason)`` where *is_macro_office* is True
        if the file may contain macros, and *reason* describes which indicator
        triggered the flag.

    Examples:
        >>> check_macro_office("report.xlsm")
        (True, "File extension '.xlsm' is a macro-enabled Office format.")
        >>> check_macro_office("photo.jpg")
        (False, '')
    """
    _, ext = os.path.splitext(filename.lower()) if filename else ("", "")

    if ext in _MACRO_OFFICE_EXTENSIONS:
        if ext in {".xlsm", ".docm", ".pptm", ".xlam", ".dotm", ".xltm",
                   ".potm", ".ppsm", ".sldm", ".accde", ".ppa", ".ppam",
                   ".xla", ".xll"}:
            return True, (
                f"File extension '{ext}' is a macro-enabled Office format."
            )
        # Legacy binary Office formats (doc, xls, ppt) may also contain macros
        return True, (
            f"File extension '{ext}' is a legacy Office format that supports "
            "VBA macros. Treat with caution."
        )

    if mime_type:
        mime_lower = mime_type.lower().split(";")[0].strip()
        if mime_lower in _MACRO_OFFICE_MIMES:
            return True, (
                f"MIME type '{mime_lower}' indicates an Office document that "
                "may support macros."
            )

    return False, ""


def compute_hash(data: bytes) -> str:
    """Compute the SHA-256 digest of *data*.

    Args:
        data: Raw bytes of the attachment content.

    Returns:
        Lowercase hex-encoded SHA-256 digest string.

    Examples:
        >>> compute_hash(b"hello")
        '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    """
    return hashlib.sha256(data).hexdigest()


def virustotal_lookup(sha256_hash: str) -> tuple[int | None, int | None, str]:
    """Look up a file hash against the VirusTotal API v3.

    Only performs the lookup if the ``VT_API_KEY`` environment variable is
    set to a non-empty value.  Returns ``(None, None, '')`` otherwise.

    The function uses only the Python standard library (``urllib``) to avoid
    adding third-party HTTP client dependencies.

    Args:
        sha256_hash: The hex-encoded SHA-256 digest of the file to look up.

    Returns:
        A tuple ``(detection_count, total_engines, permalink)`` where:
            - *detection_count* is the number of AV engines that flagged the
              file, or None if lookup was skipped / failed.
            - *total_engines* is the total number of engines that analysed
              the file, or None if lookup was skipped / failed.
            - *permalink* is the VirusTotal report URL for the file, or empty
              string if unavailable.

    Examples:
        >>> # Without VT_API_KEY set:
        >>> virustotal_lookup("abc123")
        (None, None, '')
    """
    import json
    import urllib.error
    import urllib.request

    api_key = os.environ.get("VT_API_KEY", "").strip()
    if not api_key:
        logger.debug("VT_API_KEY not set; skipping VirusTotal lookup.")
        return None, None, ""

    url = f"{_VT_API_BASE}/files/{sha256_hash}"
    permalink = f"https://www.virustotal.com/gui/file/{sha256_hash}/detection"

    req = urllib.request.Request(
        url,
        headers={
            "x-apikey": api_key,
            "Accept": "application/json",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            body = response.read()
            data = json.loads(body)

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        detection_count = malicious + suspicious
        return detection_count, total, permalink

    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            # File not found in VT database — not necessarily malicious
            logger.info("File hash %s not found in VirusTotal database.", sha256_hash)
            return 0, 0, permalink
        logger.warning(
            "VirusTotal API returned HTTP %d for hash %s: %s",
            exc.code, sha256_hash, exc.reason,
        )
        return None, None, ""
    except urllib.error.URLError as exc:
        logger.warning("Network error contacting VirusTotal: %s", exc)
        return None, None, ""
    except (KeyError, ValueError, json.JSONDecodeError) as exc:
        logger.warning("Failed to parse VirusTotal response: %s", exc)
        return None, None, ""
    except Exception as exc:
        logger.exception("Unexpected error during VirusTotal lookup: %s", exc)
        return None, None, ""


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def _compute_risk_score(
    is_dangerous_ext: bool,
    is_double_ext: bool,
    is_macro: bool,
    vt_count: int | None,
    vt_total: int | None,
) -> tuple[int, list[str]]:
    """Calculate a 0–100 risk score from individual indicators.

    Scoring weights:
        - Dangerous extension:   +35 points
        - Double extension:      +25 points
        - Macro-enabled Office:  +20 points
        - VirusTotal detections: +20 points (scaled by detection ratio)

    Args:
        is_dangerous_ext: Whether the file has a dangerous extension.
        is_double_ext: Whether a double-extension attack was detected.
        is_macro: Whether the file may contain macros.
        vt_count: Number of VT detections, or None.
        vt_total: Total VT engines, or None.

    Returns:
        A tuple ``(score, factors)`` where *score* is an integer 0–100 and
        *factors* is a list of human-readable descriptions.
    """
    score = 0
    factors: list[str] = []

    if is_dangerous_ext:
        score += 35
        factors.append("Dangerous file extension (+35)")

    if is_double_ext:
        score += 25
        factors.append("Double-extension spoofing detected (+25)")

    if is_macro:
        score += 20
        factors.append("Office macro-capable format (+20)")

    if vt_count is not None and vt_total is not None and vt_total > 0:
        ratio = vt_count / vt_total
        vt_score = min(20, round(ratio * 20))
        if vt_score > 0:
            score += vt_score
            factors.append(
                f"VirusTotal: {vt_count}/{vt_total} engines detected malware "
                f"(+{vt_score})"
            )
        else:
            factors.append(f"VirusTotal: {vt_count}/{vt_total} detections (clean)")

    score = min(100, score)
    return score, factors


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_attachment(
    filename: str,
    data: bytes,
    mime_type: str = "",
) -> AttachmentAnalysis:
    """Perform a comprehensive security analysis on a single email attachment.

    Runs all configured checks in sequence and synthesises the results into
    an :class:`AttachmentAnalysis` dataclass, including an overall risk score.

    Args:
        filename: The attachment filename as declared in the email (including
            extension).  Used for extension and double-extension checks.
        data: The raw bytes of the attachment content.  Used for hash
            computation and future content-level checks.
        mime_type: The declared MIME type from the email's Content-Type
            header.  Optional; used for macro detection.  If not supplied,
            the function will attempt to guess it from *filename*.

    Returns:
        An :class:`AttachmentAnalysis` instance with all check results and
        a computed *risk_score*.

    Examples:
        >>> result = analyze_attachment("invoice.pdf.exe", b"MZ...", "")
        >>> result.is_dangerous_extension
        True
        >>> result.is_double_extension
        True
        >>> result.risk_score >= 60
        True
    """
    # Guess MIME type from filename if not provided
    if not mime_type:
        guessed, _ = mimetypes.guess_type(filename)
        mime_type = guessed or ""

    # Hash
    sha256 = compute_hash(data)
    size_bytes = len(data)

    # Extension checks
    is_dangerous_ext, dangerous_ext = check_dangerous_extension(filename)
    is_double_ext, double_ext_pattern = check_double_extension(filename)

    # Macro check
    is_macro, macro_reason = check_macro_office(filename, mime_type)

    # VirusTotal (only if API key is set)
    vt_count, vt_total, vt_permalink = virustotal_lookup(sha256)

    # Risk score
    risk_score, risk_factors = _compute_risk_score(
        is_dangerous_ext, is_double_ext, is_macro, vt_count, vt_total
    )

    return AttachmentAnalysis(
        filename=filename,
        sha256=sha256,
        size_bytes=size_bytes,
        mime_type=mime_type,
        is_dangerous_extension=is_dangerous_ext,
        dangerous_extension=dangerous_ext,
        is_double_extension=is_double_ext,
        double_extension_pattern=double_ext_pattern,
        is_macro_office=is_macro,
        macro_reason=macro_reason,
        vt_detection_count=vt_count,
        vt_total_engines=vt_total,
        vt_permalink=vt_permalink,
        risk_score=risk_score,
        risk_factors=risk_factors,
    )


class AttachmentAnalyzer:
    """Wrapper class used by the pipeline to analyze email attachments."""

    def __init__(self, vt_api_key: str = ""):
        self.vt_api_key = vt_api_key

    def analyze(self, attachment: Any) -> AttachmentAnalysis:
        filename = getattr(attachment, "filename", "") or ""
        data = getattr(attachment, "data", b"") or b""
        content_type = getattr(attachment, "content_type", "") or ""
        return analyze_attachment(filename=filename, data=data, mime_type=content_type)

