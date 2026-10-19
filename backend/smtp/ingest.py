"""
PhishShield – SMTP Ingest Server (aiosmtpd).

Listens on SMTP_PORT (default 2525) with STARTTLS support.
Each received email is pushed through the full analysis pipeline.
Rejects AUTH over plaintext (requires STARTTLS before AUTH).
"""
from __future__ import annotations

import asyncio
import logging
import ssl

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP as SMTPServer
from aiosmtpd.smtp import Envelope, Session

from backend.app.config import get_settings
from backend.app.database import SessionLocal
from backend.app.pipeline import process_email
from backend.crypto.tls import build_smtp_starttls_context

logger = logging.getLogger(__name__)
settings = get_settings()


class PhishShieldSMTPHandler:
    """
    aiosmtpd handler that processes incoming emails through the PhishShield pipeline.
    """

    async def handle_RCPT(
        self, server: SMTPServer, session: Session, envelope: Envelope, address: str, rcpt_options: list
    ) -> str:
        """Accept any recipient (gateway mode — analyze everything)."""
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(
        self, server: SMTPServer, session: Session, envelope: Envelope
    ) -> str:
        """
        Called when the full email data is received.
        Sends the raw email through the analysis pipeline.
        """
        raw_email: bytes = envelope.content  # type: ignore[assignment]
        source_ip = session.peer[0] if session.peer else None

        # Extract TLS info if STARTTLS was used
        tls_info = None
        ssl_obj = getattr(session, "_ssl_protocol", None)
        if ssl_obj and hasattr(ssl_obj, "_sslobj"):
            try:
                cipher = ssl_obj._sslobj.cipher()
                tls_info = {
                    "established": True,
                    "protocol": ssl_obj._sslobj.version(),
                    "cipher_name": cipher[0] if cipher else "unknown",
                    "cipher_bits": cipher[2] if cipher else 0,
                }
            except Exception:
                tls_info = {"established": True, "protocol": "TLS", "cipher_name": "unknown"}

        try:
            db = SessionLocal()
            try:
                record = await process_email(
                    raw_email=raw_email,
                    db=db,
                    source_ip=source_ip,
                    tls_info=tls_info,
                )
                logger.info(
                    "Email processed: id=%d verdict=%s score=%.1f from=%s",
                    record.id,
                    record.verdict.value if record.verdict else "unknown",
                    record.risk_score or 0,
                    envelope.mail_from,
                )
            finally:
                db.close()
        except Exception as exc:
            logger.exception("Pipeline error processing email from %s: %s", source_ip, exc)
            # Return 451 so sending server will retry; don't lose the email
            return "451 Temporary processing error, please retry"

        return "250 Message accepted for delivery"


class PhishShieldSMTPController(Controller):
    """Extended Controller that injects STARTTLS support."""

    def __init__(self, *args, ssl_context: ssl.SSLContext | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._ssl_context = ssl_context

    def factory(self):
        """Create the SMTP server instance with STARTTLS."""
        server = SMTPServer(self.handler, require_starttls=False)
        if self._ssl_context:
            server.tls_context = self._ssl_context
        return server


def create_smtp_server() -> PhishShieldSMTPController:
    """
    Create and return the configured SMTP controller.
    Call .start() to begin listening.
    """
    handler = PhishShieldSMTPHandler()

    ssl_context = None
    try:
        ssl_context = build_smtp_starttls_context(
            cert_file=settings.tls_cert_file,
            key_file=settings.tls_key_file,
        )
        logger.info("SMTP STARTTLS enabled with cert: %s", settings.tls_cert_file)
    except FileNotFoundError as e:
        logger.warning("TLS certs not found — SMTP will run without STARTTLS: %s", e)

    controller = PhishShieldSMTPController(
        handler,
        hostname=settings.smtp_host,
        port=settings.smtp_port,
        ssl_context=ssl_context,
    )
    return controller


async def run_smtp_server() -> None:
    """Run the SMTP server until cancelled."""
    server = create_smtp_server()
    server.start()
    logger.info(
        "PhishShield SMTP ingest listening on %s:%d",
        settings.smtp_host,
        settings.smtp_port,
    )
    try:
        await asyncio.Event().wait()  # Run forever
    finally:
        server.stop()
        logger.info("SMTP server stopped")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_smtp_server())
