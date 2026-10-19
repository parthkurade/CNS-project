
import io
import tarfile

from backend.ml.download_data import extract_emails


def make_test_archive(email_text: str) -> bytes:
    """Create a tiny in-memory tar.bz2 archive containing one email."""
    file_bytes = email_text.encode("utf-8")
    archive_buffer = io.BytesIO()

    with tarfile.open(fileobj=archive_buffer, mode="w:bz2") as archive:
        info = tarfile.TarInfo(name="test_email")
        info.size = len(file_bytes)
        archive.addfile(info, io.BytesIO(file_bytes))

    return archive_buffer.getvalue()


def test_extract_emails_from_simple_message():
    raw_email = (
        "Subject: Test email\n"
        "From: sender@example.com\n"
        "\n"
        "This is a test email body."
    )

    result = extract_emails(make_test_archive(raw_email), "test_archive")

    assert len(result) == 1
    assert "Test email" in result[0]
    assert "This is a test email body." in result[0]


def test_extract_emails_handles_empty_body():
    raw_email = "Subject: Empty email\n\n"

    result = extract_emails(make_test_archive(raw_email), "test_archive")

    assert len(result) == 1
    assert "Empty email" in result[0]
