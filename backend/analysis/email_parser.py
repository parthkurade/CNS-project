"""RFC 5322 / MIME raw email parsing.

Turns raw RFC 5322 bytes (as received over SMTP) into a structured :class:`ParsedEmail`
that the rest of the pipeline (SPF / DKIM / DMARC, URL analysis, attachment analysis,
spoofing checks, ML) can consume.

Two views of the message are kept on purpose:

* a **semantic view** (decoded headers, addresses, text/HTML bodies, attachments), built on
  the standard library ``email`` package with ``policy.default``; and
* a **raw view** (``raw_headers`` / ``raw_body``), byte-exact apart from CRLF normalisation.
  DKIM verification hashes the original bytes, so it must never see re-serialised headers.

Parsing never raises on merely *malformed* mail (phishing mail is often malformed); problems
are recorded in ``ParsedEmail.anomalies``. :class:`EmailParseError` is raised only for input
that cannot be processed at all (wrong type, empty, oversized).
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any

MAX_EMAIL_BYTES = 25 * 1024 * 1024  # refuse to parse anything larger (DoS guard)
MAX_MIME_DEPTH = 20
MAX_MIME_PARTS = 500

_CRLF_RE = re.compile(rb"\r\n|\r|\n")
_FOLD_RE = re.compile(rb"\r\n(?=[ \t])")
_TAG_RE = re.compile(r"<[^>]*>")
_STYLE_SCRIPT_RE = re.compile(r"<(script|style)\b.*?</\1\s*>", re.IGNORECASE | re.DOTALL)
_BRACKET_IP_RE = re.compile(r"[\[(]\s*(?:IPv6:)?([0-9A-Fa-f:.]{2,45})\s*[\])]")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class EmailParseError(ValueError):
    """The input could not be parsed as an email at all."""


# --------------------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------------------
@dataclass(frozen=True)
class RawHeader:
    """One header field exactly as it appeared on the wire (CRLF-normalised).

    ``raw`` contains the field name, the colon, the (still folded) value and the final CRLF.
    """

    name: str
    raw: bytes

    @property
    def value(self) -> str:
        """Unfolded, stripped, UTF-8-decoded value (RFC 2047 words are *not* decoded)."""
        _, _, value = self.raw.partition(b":")
        value = _FOLD_RE.sub(b"", value).strip(b" \t\r\n")
        return value.decode("utf-8", "replace")


@dataclass
class Attachment:
    """A MIME leaf part that is not the message text."""

    filename: str | None  # as declared by the sender (untrusted!)
    safe_filename: str  # basename with control chars stripped; safe to log/display
    content_type: str
    disposition: str  # "attachment" or "inline"
    size: int
    sha256: str
    content: bytes = field(repr=False, default=b"")

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.safe_filename,
            "content_type": self.content_type,
            "disposition": self.disposition,
            "size": self.size,
            "sha256": self.sha256,
        }


@dataclass
class ParsedEmail:
    # --- raw view (for DKIM and forensic hashing) ---
    raw: bytes = field(repr=False, default=b"")
    raw_headers: list[RawHeader] = field(repr=False, default_factory=list)
    raw_body: bytes = field(repr=False, default=b"")
    sha256: str = ""  # SHA-256 of the CRLF-normalised raw message

    # --- decoded headers ---
    headers: list[tuple[str, str]] = field(default_factory=list)
    subject: str = ""
    message_id: str = ""
    date: datetime | None = None

    # --- addresses ---
    from_display: str = ""
    from_address: str = ""
    from_domain: str = ""
    from_addresses: list[str] = field(default_factory=list)
    sender_address: str = ""  # "Sender:" header, if any, or defaults to from_address
    sender_domain: str = ""
    return_path: str | None = None  # None = header absent, "" = null sender "<>"
    return_path_domain: str = ""
    reply_to: list[str] = field(default_factory=list)
    to: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)

    @property
    def to_addresses(self) -> list[str]:
        return self.to

    @property
    def sha256_hash(self) -> str:
        return self.sha256

    @property
    def received_chain(self) -> list[str]:
        return self.received

    @property
    def received_from_ip(self) -> str | None:
        return self.received_ips[0] if self.received_ips else None

    @property
    def sender_display_name(self) -> str:
        return self.from_display

    # --- transport trace ---
    received: list[str] = field(default_factory=list)  # top (most recent) first
    received_ips: list[str] = field(default_factory=list)  # from-clause IPs, top first
    x_originating_ip: str | None = None
    authentication_results: list[str] = field(default_factory=list)  # UNTRUSTED, as received

    # --- content ---
    body_text: str = ""
    body_html: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    content_type: str = "text/plain"

    # --- parser findings ---
    anomalies: list[str] = field(default_factory=list)

    # ---- header helpers ------------------------------------------------------------
    def header(self, name: str) -> str | None:
        """First decoded value of header *name* (case-insensitive) or ``None``."""
        lname = name.lower()
        for key, value in self.headers:
            if key.lower() == lname:
                return value
        return None

    def header_all(self, name: str) -> list[str]:
        lname = name.lower()
        return [value for key, value in self.headers if key.lower() == lname]

    # ---- derived helpers -----------------------------------------------------------
    @property
    def text_for_analysis(self) -> str:
        """Plain text if present, otherwise the HTML body with tags stripped."""
        if self.body_text.strip():
            return self.body_text
        if self.body_html:
            stripped = _STYLE_SCRIPT_RE.sub(" ", self.body_html)
            return re.sub(r"\s+", " ", _TAG_RE.sub(" ", stripped)).strip()
        return ""

    def guess_client_ip(self) -> str | None:
        """Best-effort sending IP taken from the trace headers.

        Only a *fallback*: when the gateway knows the real SMTP peer address it must use that
        instead, because ``Received`` headers added by the sender are attacker-controlled.
        Returns the first non-private address found, scanning the chain top-down.
        """
        candidates = list(self.received_ips)
        if self.x_originating_ip:
            candidates.append(self.x_originating_ip)
        for text in candidates:
            try:
                ip = ipaddress.ip_address(text)
            except ValueError:
                continue
            if not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified):
                return str(ip)
        return None

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable summary (no raw bytes, no attachment content)."""
        return {
            "sha256": self.sha256,
            "subject": self.subject,
            "message_id": self.message_id,
            "date": self.date.isoformat() if self.date else None,
            "from_display": self.from_display,
            "from_address": self.from_address,
            "from_domain": self.from_domain,
            "return_path": self.return_path,
            "reply_to": self.reply_to,
            "to": self.to,
            "cc": self.cc,
            "received_count": len(self.received),
            "received_ips": self.received_ips,
            "content_type": self.content_type,
            "body_text_length": len(self.body_text),
            "body_html_length": len(self.body_html),
            "attachments": [a.to_dict() for a in self.attachments],
            "anomalies": self.anomalies,
        }


# --------------------------------------------------------------------------------------
# Raw (byte-exact) splitting - shared with dkim_check
# --------------------------------------------------------------------------------------
def normalize_crlf(data: bytes) -> bytes:
    """Convert every line ending (CRLF, bare CR, bare LF) to CRLF."""
    return _CRLF_RE.sub(b"\r\n", data)


def split_raw_message(raw: bytes) -> tuple[list[RawHeader], bytes]:
    """Split a message into ``(raw_headers, raw_body)``.

    Input is CRLF-normalised. Folded header lines are kept folded inside ``RawHeader.raw`` so
    DKIM "simple" canonicalisation can use them verbatim. The body is everything after the
    first empty line (empty if there is none).
    """
    data = normalize_crlf(raw)
    if data.startswith(b"\r\n"):  # no headers at all
        return [], data[2:]
    idx = data.find(b"\r\n\r\n")
    if idx == -1:
        head, body = data, b""
        if not head.endswith(b"\r\n"):
            head += b"\r\n"
    else:
        head, body = data[: idx + 2], data[idx + 4 :]

    headers: list[RawHeader] = []
    current: list[bytes] = []

    def flush() -> None:
        if not current:
            return
        raw_field = b"".join(current)
        name = raw_field.split(b":", 1)[0].strip().decode("ascii", "replace")
        headers.append(RawHeader(name=name, raw=raw_field))
        current.clear()

    for line in head.split(b"\r\n")[:-1]:
        if line[:1] in (b" ", b"\t"):
            if current:  # continuation of the previous field
                current.append(line + b"\r\n")
            continue  # stray continuation with nothing to continue: drop it
        flush()
        if b":" not in line:  # not a valid header line; ignore
            continue
        current.append(line + b"\r\n")
    flush()
    return headers, body


# --------------------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------------------
def extract_domain(address: str) -> str:
    """Lower-case domain part of an address; IDN labels are converted to punycode."""
    domain = address.rpartition("@")[2].strip().strip("<>").strip().lower().rstrip(".")
    if not domain:
        return ""
    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError:
        return domain


def _address_list(value: str | None) -> list[tuple[str, str]]:
    """``[(display, addr), ...]`` with empty/garbage entries removed."""
    if not value:
        return []
    try:
        pairs = getaddresses([value])
    except Exception:  # noqa: BLE001 - never let a weird header kill the pipeline
        return []
    return [(name, addr.strip()) for name, addr in pairs if addr and addr.strip()]


def _safe_header(msg: EmailMessage, name: str) -> str | None:
    try:
        value = msg[name]
    except Exception:  # noqa: BLE001
        return None
    return None if value is None else str(value)


def _safe_filename(filename: str | None, index: int) -> str:
    if not filename:
        return f"attachment-{index}"
    base = re.split(r"[\\/]", filename)[-1]
    base = _CONTROL_RE.sub("", base).strip()
    return base[:255] or f"attachment-{index}"


def _extract_ip(received_value: str) -> str | None:
    """IP address of the client in the ``from`` clause of a Received header."""
    from_clause = re.split(r"\bby\b", received_value, maxsplit=1, flags=re.IGNORECASE)[0]
    for candidate in _BRACKET_IP_RE.findall(from_clause):
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None


# --------------------------------------------------------------------------------------
# MIME walking
# --------------------------------------------------------------------------------------
class _Collector:
    def __init__(self) -> None:
        self.text: list[str] = []
        self.html: list[str] = []
        self.attachments: list[Attachment] = []
        self.anomalies: list[str] = []
        self.parts_seen = 0

    def add_attachment(self, part: EmailMessage, content: bytes, disposition: str) -> None:
        filename = part.get_filename()
        self.attachments.append(
            Attachment(
                filename=filename,
                safe_filename=_safe_filename(filename, len(self.attachments) + 1),
                content_type=part.get_content_type(),
                disposition=disposition,
                size=len(content),
                sha256=hashlib.sha256(content).hexdigest(),
                content=content,
            )
        )


def _part_text(part: EmailMessage) -> str:
    try:
        return str(part.get_content())
    except Exception:  # noqa: BLE001 - unknown charset, bad base64, ...
        payload = part.get_payload(decode=True)
        return payload.decode("utf-8", "replace") if isinstance(payload, bytes) else ""


def _walk(part: EmailMessage, depth: int, out: _Collector) -> None:
    out.parts_seen += 1
    if out.parts_seen > MAX_MIME_PARTS:
        if "too many MIME parts" not in out.anomalies:
            out.anomalies.append("too many MIME parts")
        return
    if depth > MAX_MIME_DEPTH:
        if "MIME nesting too deep" not in out.anomalies:
            out.anomalies.append("MIME nesting too deep")
        return

    ctype = part.get_content_type()
    if ctype == "message/rfc822":  # an attached email: keep it as one opaque attachment
        try:
            inner = part.get_payload()
            content = inner[0].as_bytes() if isinstance(inner, list) and inner else b""
        except Exception:  # noqa: BLE001
            content = b""
        out.add_attachment(part, content, part.get_content_disposition() or "attachment")
        return
    if part.is_multipart():
        for sub in part.iter_parts():
            _walk(sub, depth + 1, out)
        return

    disposition = part.get_content_disposition()
    is_body_text = (
        ctype in ("text/plain", "text/html") and disposition != "attachment" and not part.get_filename()
    )
    if is_body_text:
        (out.html if ctype == "text/html" else out.text).append(_part_text(part))
        return
    payload = part.get_payload(decode=True)
    content = payload if isinstance(payload, bytes) else b""
    out.add_attachment(part, content, disposition or "attachment")


# --------------------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------------------
def parse_email(raw: bytes | str) -> ParsedEmail:
    """Parse a raw RFC 5322 message into a :class:`ParsedEmail`."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogateescape")
    elif isinstance(raw, (bytearray, memoryview)):
        raw = bytes(raw)
    if not isinstance(raw, bytes):
        raise EmailParseError(f"expected bytes or str, got {type(raw).__name__}")
    if not raw.strip():
        raise EmailParseError("empty message")
    if len(raw) > MAX_EMAIL_BYTES:
        raise EmailParseError(f"message too large ({len(raw)} bytes > {MAX_EMAIL_BYTES})")

    normalized = normalize_crlf(raw)
    raw_headers, raw_body = split_raw_message(normalized)
    msg = BytesParser(policy=policy.default).parsebytes(normalized)

    parsed = ParsedEmail(
        raw=normalized,
        raw_headers=raw_headers,
        raw_body=raw_body,
        sha256=hashlib.sha256(raw).hexdigest(),
    )

    # Decoded header list (RFC 2047 words decoded by the email package, raw as fallback).
    raw_by_order = [h.value for h in raw_headers]
    try:
        decoded = [(str(k), str(v)) for k, v in msg.items()]
    except Exception:  # noqa: BLE001
        decoded = []
    if len(decoded) != len(raw_headers):
        decoded = [(h.name, raw_by_order[i]) for i, h in enumerate(raw_headers)]
    parsed.headers = decoded

    parsed.subject = (_safe_header(msg, "Subject") or "").strip()
    parsed.message_id = (_safe_header(msg, "Message-ID") or "").strip()
    date_value = _safe_header(msg, "Date")
    if date_value:
        try:
            parsed.date = parsedate_to_datetime(date_value)
        except (TypeError, ValueError, IndexError):
            parsed.anomalies.append("unparseable Date header")

    # From
    from_headers = [h for h in raw_headers if h.name.lower() == "from"]
    if not from_headers:
        parsed.anomalies.append("missing From header")
    elif len(from_headers) > 1:
        parsed.anomalies.append("multiple From headers")
    from_pairs = _address_list(_safe_header(msg, "From"))
    if from_pairs:
        parsed.from_display = from_pairs[0][0]
        parsed.from_address = from_pairs[0][1].lower()
        parsed.from_domain = extract_domain(parsed.from_address)
        parsed.from_addresses = [a.lower() for _, a in from_pairs]
        if len(from_pairs) > 1:
            parsed.anomalies.append("multiple addresses in From")
    elif from_headers:
        parsed.anomalies.append("unparseable From header")

    sender_pairs = _address_list(_safe_header(msg, "Sender"))
    if sender_pairs:
        parsed.sender_address = sender_pairs[0][1].lower()
    else:
        parsed.sender_address = parsed.from_address
    parsed.sender_domain = extract_domain(parsed.sender_address)

    # Return-Path (envelope sender as recorded by the final MTA)
    rp = _safe_header(msg, "Return-Path")
    if rp is not None:
        rp = rp.strip()
        if rp in ("<>", ""):
            parsed.return_path = ""
        else:
            pairs = _address_list(rp)
            parsed.return_path = pairs[0][1].lower() if pairs else rp.strip("<>").lower()
            parsed.return_path_domain = extract_domain(parsed.return_path)

    parsed.reply_to = [a.lower() for _, a in _address_list(_safe_header(msg, "Reply-To"))]
    parsed.to = [a.lower() for _, a in _address_list(", ".join(parsed.header_all("To")))]
    parsed.cc = [a.lower() for _, a in _address_list(", ".join(parsed.header_all("Cc")))]

    # Trace headers
    for h in raw_headers:
        lname = h.name.lower()
        if lname == "received":
            parsed.received.append(h.value)
            ip = _extract_ip(h.value)
            if ip:
                parsed.received_ips.append(ip)
        elif lname == "authentication-results":
            parsed.authentication_results.append(h.value)
        elif lname == "x-originating-ip" and parsed.x_originating_ip is None:
            candidate = h.value.strip("[] ")
            try:
                parsed.x_originating_ip = str(ipaddress.ip_address(candidate))
            except ValueError:
                parsed.anomalies.append("invalid X-Originating-IP")

    # Body / attachments
    parsed.content_type = msg.get_content_type()
    collector = _Collector()
    _walk(msg, 0, collector)
    parsed.body_text = "\n".join(collector.text)
    parsed.body_html = "\n".join(collector.html)
    parsed.attachments = collector.attachments
    parsed.anomalies.extend(collector.anomalies)
    parsed.anomalies.extend(f"MIME defect: {type(d).__name__}" for d in msg.defects)
    return parsed
