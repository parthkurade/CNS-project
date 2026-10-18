"""Email analysis package.

This part of the package (Member 3 - email authentication) provides:

* ``email_parser``  - RFC 5322 / MIME parsing into :class:`ParsedEmail`
* ``spf_check``     - SPF (RFC 7208) + the DNS resolver abstraction (``FakeResolver`` for tests)
* ``dkim_check``    - DKIM (RFC 6376) canonicalization and signature verification
* ``dmarc_check``   - DMARC (RFC 7489) policy + alignment, and ``authenticate_email()``

Other analysis modules (URL, attachment, spoofing, header analysis) are added by other
members and are intentionally not imported here.
"""

from backend.analysis.dkim_check import DKIMResult, DKIMSignatureResult, check_dkim
from backend.analysis.dmarc_check import (
    AuthenticationSummary,
    DMARCResult,
    authenticate_email,
    evaluate_dmarc,
    organizational_domain,
)
from backend.analysis.email_parser import (
    Attachment,
    EmailParseError,
    ParsedEmail,
    parse_email,
)
from backend.analysis.spf_check import (
    DnsPythonResolver,
    DNSResolver,
    DNSTemporaryError,
    FakeResolver,
    SPFResult,
    check_spf,
)

__all__ = [
    "Attachment",
    "AuthenticationSummary",
    "DKIMResult",
    "DKIMSignatureResult",
    "DMARCResult",
    "DNSResolver",
    "DNSTemporaryError",
    "DnsPythonResolver",
    "EmailParseError",
    "FakeResolver",
    "ParsedEmail",
    "SPFResult",
    "authenticate_email",
    "check_dkim",
    "check_spf",
    "evaluate_dmarc",
    "organizational_domain",
    "parse_email",
]
