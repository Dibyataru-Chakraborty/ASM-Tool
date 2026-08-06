"""SMTP email delivery for scheduled scan notifications."""

from __future__ import annotations

import html
import smtplib
import ssl
from email.message import EmailMessage
from typing import Iterable

from app.config import settings


class EmailConfigurationError(RuntimeError):
    """Raised when email delivery was requested without valid SMTP settings."""


class EmailService:
    """Send simple text/HTML mail without logging credentials."""

    @staticmethod
    def configuration_status() -> dict:
        missing = []
        if not settings.smtp_host:
            missing.append("SMTP_HOST")
        if not settings.smtp_from or "yourdomain.com" in settings.smtp_from.lower():
            missing.append("SMTP_FROM")
        if settings.smtp_require_auth:
            if not settings.smtp_user:
                missing.append("SMTP_USER")
            if not settings.smtp_password:
                missing.append("SMTP_PASSWORD")

        if settings.smtp_ssl and settings.smtp_starttls:
            missing.append("Choose either SMTP_SSL or SMTP_STARTTLS")

        return {
            "configured": not missing,
            "host": settings.smtp_host or None,
            "port": settings.smtp_port,
            "transport": "ssl" if settings.smtp_ssl else (
                "starttls" if settings.smtp_starttls else "plain"
            ),
            "from_address": settings.smtp_from or None,
            "missing": missing,
        }

    @classmethod
    def require_configured(cls) -> None:
        status = cls.configuration_status()
        if not status["configured"]:
            raise EmailConfigurationError(
                "Email is not configured. Set: " + ", ".join(status["missing"])
            )

    @classmethod
    def send(
        cls,
        *,
        recipients: Iterable[str],
        subject: str,
        text_body: str,
        html_body: str | None = None,
    ) -> None:
        cls.require_configured()
        recipient_list = [address.strip() for address in recipients if address.strip()]
        if not recipient_list:
            raise EmailConfigurationError("At least one recipient is required")

        message = EmailMessage()
        message["From"] = settings.smtp_from
        message["To"] = ", ".join(recipient_list)
        message["Subject"] = subject
        message.set_content(text_body)
        if html_body:
            message.add_alternative(html_body, subtype="html")

        context = ssl.create_default_context()
        if settings.smtp_ssl:
            smtp = smtplib.SMTP_SSL(
                settings.smtp_host,
                settings.smtp_port,
                timeout=settings.smtp_timeout_seconds,
                context=context,
            )
        else:
            smtp = smtplib.SMTP(
                settings.smtp_host,
                settings.smtp_port,
                timeout=settings.smtp_timeout_seconds,
            )

        with smtp:
            if not settings.smtp_ssl:
                smtp.ehlo()
                if settings.smtp_starttls:
                    smtp.starttls(context=context)
                    smtp.ehlo()
            if settings.smtp_require_auth:
                smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.send_message(message)

    @classmethod
    def send_test(cls, recipient: str) -> None:
        cls.send(
            recipients=[recipient],
            subject="ASM Platform email test",
            text_body=(
                "Email delivery is configured correctly for the ASM Platform scheduler.\n"
                "No scan was started by this test."
            ),
            html_body=(
                "<h2>ASM Platform email test</h2>"
                "<p>Email delivery is configured correctly for the scan scheduler.</p>"
                "<p><strong>No scan was started by this test.</strong></p>"
            ),
        )

    @classmethod
    def send_schedule_result(
        cls,
        *,
        recipient: str,
        asset_name: str,
        target: str,
        scan_reference: str,
        status: str,
        discoveries: int,
        vulnerabilities: int,
        error: str | None,
    ) -> None:
        normalized_status = status.capitalize()
        subject = f"ASM scheduled scan {normalized_status}: {asset_name}"
        report_url = f"{settings.frontend_url.rstrip('/')}/scans"
        error_line = f"\nError: {error}" if error else ""
        text_body = (
            f"Scheduled scan {normalized_status}\n\n"
            f"Asset: {asset_name}\n"
            f"Target: {target}\n"
            f"Scan reference: {scan_reference}\n"
            f"Discoveries: {discoveries}\n"
            f"Vulnerabilities: {vulnerabilities}"
            f"{error_line}\n\n"
            f"Open scans: {report_url}\n"
        )
        html_error = (
            f"<p><strong>Error:</strong> {html.escape(error)}</p>" if error else ""
        )
        html_body = (
            f"<h2>Scheduled scan {html.escape(normalized_status)}</h2>"
            f"<p><strong>Asset:</strong> {html.escape(asset_name)}</p>"
            f"<p><strong>Target:</strong> {html.escape(target)}</p>"
            f"<p><strong>Scan reference:</strong> "
            f"<code>{html.escape(scan_reference)}</code></p>"
            f"<p><strong>Discoveries:</strong> {discoveries}<br>"
            f"<strong>Vulnerabilities:</strong> {vulnerabilities}</p>"
            f"{html_error}"
            f'<p><a href="{html.escape(report_url)}">Open scan history</a></p>'
        )
        cls.send(
            recipients=[recipient],
            subject=subject,
            text_body=text_body,
            html_body=html_body,
        )
