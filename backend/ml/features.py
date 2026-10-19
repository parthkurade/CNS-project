
"""Feature extraction utilities for email classification."""

from __future__ import annotations

import re
from urllib.parse import urlparse


URL_PATTERN = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)


def extract_features(text: str) -> dict[str, int]:
    """Extract simple, interpretable features from an email."""
    urls = URL_PATTERN.findall(text)
    email_addresses = EMAIL_PATTERN.findall(text)
    words = re.findall(r"\b\w+\b", text)
    lowercase_text = text.lower()

    suspicious_terms = (
        "verify",
        "urgent",
        "password",
        "account suspended",
        "click here",
        "bank account",
        "prize",
        "won",
    )

    return {
        "text_length": len(text),
        "word_count": len(words),
        "url_count": len(urls),
        "email_address_count": len(email_addresses),
        "exclamation_count": text.count("!"),
        "uppercase_count": sum(1 for char in text if char.isupper()),
        "suspicious_term_count": sum(
            lowercase_text.count(term) for term in suspicious_terms
        ),
    }
