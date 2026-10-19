
"""Download and prepare a public email dataset for phishing detection."""

from __future__ import annotations

import argparse
import csv
import email
import io
import tarfile
from pathlib import Path

import requests

DATA_DIR = Path("data")
SPAMASSASSIN_URLS = {
    "spam": "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2",
    "easy_ham": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
    "hard_ham": "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
}


def download_archive(url: str, timeout: int = 60) -> bytes:
    """Download one dataset archive."""
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    return response.content


def extract_emails(archive_bytes: bytes, archive_name: str) -> list[str]:
    """Extract email text from a SpamAssassin tar.bz2 archive."""
    messages: list[str] = []

    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:bz2") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue

            # Read files directly; do not extract untrusted archive paths.
            file_obj = archive.extractfile(member)
            if file_obj is None:
                continue

            raw = file_obj.read()
            parsed = email.message_from_bytes(raw)
            subject = parsed.get("Subject", "")
            body = parsed.get_payload()

            if isinstance(body, list):
                body_text = " ".join(
                    part.get_content() or ""
                    for part in body
                    if part.get_content_maintype() == "text"
                )
            elif isinstance(body, str):
                body_text = body
            else:
                body_text = ""

            messages.append(f"Subject: {subject}\n\n{body_text}")

    return messages


def build_dataset(output_path: Path = DATA_DIR / "emails.csv") -> Path:
    """Download SpamAssassin corpora and write labeled email examples."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rows: list[tuple[str, int]] = []

    for label, url in SPAMASSASSIN_URLS.items():
        print(f"Downloading {label} dataset...")
        archive = download_archive(url)
        emails = extract_emails(archive, label)
        is_spam = int(label == "spam")
        rows.extend((message, is_spam) for message in emails)

    with output_path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["text", "label"])
        writer.writerows(rows)

    print(f"Saved {len(rows)} emails to {output_path}")
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=DATA_DIR / "emails.csv",
        help="Output CSV path (default: data/emails.csv)",
    )
    args = parser.parse_args()
    build_dataset(args.output)


if __name__ == "__main__":
    main()
