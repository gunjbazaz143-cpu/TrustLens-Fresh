"""
Email notification service.

Wraps Flask-Mail so every module can send admin alerts with a single call.
Sending is always best-effort: if SMTP credentials are not configured the
helper logs a warning and returns False instead of crashing the request.

Configure via environment variables:
    MAIL_USERNAME / MAIL_PASSWORD (e.g. a Gmail app password)
    MAIL_SERVER, MAIL_PORT, MAIL_USE_TLS, MAIL_DEFAULT_SENDER
    MAIL_ALERT_RECIPIENT (where scam reports + contact messages are delivered)
"""

import logging

from flask import current_app

logger = logging.getLogger(__name__)

_mail = None


def get_mail():
    """Lazily construct and return the Flask-Mail extension instance."""
    global _mail
    if _mail is None:
        from flask_mail import Mail

        _mail = Mail(current_app)
    return _mail


def mail_configured() -> bool:
    """True when SMTP credentials exist so a real email can be sent."""
    username = current_app.config.get("MAIL_USERNAME") or ""
    password = current_app.config.get("MAIL_PASSWORD") or ""
    server = current_app.config.get("MAIL_SERVER") or ""
    return bool(username and password and server)


def send_admin_alert(subject: str, body: str, recipient: str | None = None) -> bool:
    """
    Send an email to the admin alert recipient.

    Returns True when the message was dispatched, False when SMTP is not
    configured (so callers can decide whether to surface a note to the user).
    """
    recipient = recipient or current_app.config.get("MAIL_ALERT_RECIPIENT", "gunjbazaz143@gmail.com")
    if not mail_configured():
        logger.warning(
            "Mail alert skipped - SMTP not configured. Add MAIL_USERNAME / "
            "MAIL_PASSWORD to send admin notifications."
        )
        return False

    try:
        from flask_mail import Message

        message = Message(
            subject=subject,
            recipients=[recipient],
            body=body,
        )
        get_mail().send(message)
        logger.info("Admin alert email sent to %s: %s", recipient, subject)
        return True
    except Exception:  # noqa: BLE001
        current_app.logger.exception("Failed to send admin alert email")
        return False


def send_contact_message_email(name: str, email: str, subject: str, message: str) -> bool:
    """Compose and send the contact-form message to the admin."""
    body = (
        "A new message was submitted through the TrustLens contact form.\n"
        "------------------------------------------------------------\n"
        f"Name:    {name}\n"
        f"Email:   {email}\n"
        f"Subject: {subject}\n"
        "------------------------------------------------------------\n"
        f"Message:\n{message}\n"
    )
    return send_admin_alert(f"[TrustLens] Contact: {subject}", body)


def send_scam_report_email(report) -> bool:
    """
    Compose and send a scam-report alert to the admin.

    `report` may be the ScamReport model instance (committed to the DB) or a
    plain dict of report fields - both are supported.
    """
    data = report.to_dict() if hasattr(report, "to_dict") else dict(report)
    reporter = getattr(report, "user", None)
    reporter_email = (
        getattr(report, "reporter_email", None)
        or (reporter.email if reporter is not None else None)
        or "Not provided"
    )
    body = (
        "A new scam report was submitted on TrustLens.\n"
        "------------------------------------------------------------\n"
        f"Report ID:       {data.get('id', '-')}\n"
        f"Title:           {data.get('title', '-')}\n"
        f"Scam type:       {data.get('scam_type', '-')}\n"
        f"Reporter email:  {reporter_email}\n"
        f"Contact number:  {data.get('contact_number') or 'Not provided'}\n"
        f"Website URL:     {data.get('website_url') or 'Not provided'}\n"
        f"Date of scam:    {data.get('scam_date') or 'Not provided'}\n"
        f"Submitted on:    {data.get('created_at') or '-'}\n"
        f"Status:          {data.get('status', 'new')}\n"
        "------------------------------------------------------------\n"
        f"Description:\n{data.get('description', '-')}\n"
    )
    return send_admin_alert(f"[TrustLens] New Scam Report: {data.get('title', 'Scam report')}", body)


def send_scam_report_update_email(report, admin_message: str) -> bool:
    """
    Compose and send a "TrustLens Scam Report Update" email to the reporter.

    Uses the report's own reporter_email when present, falling back to the
    submitting account's email. Returns False when there is no recipient or
    SMTP is not configured (best-effort, never raises).
    """
    recipient = getattr(report, "reporter_email", None) or (
        report.user.email if getattr(report, "user", None) is not None else None
    )
    if not recipient:
        logger.warning("Scam report update skipped - report #%s has no reporter email.",
                       getattr(report, "id", "?"))
        return False

    report_id = getattr(report, "id", "?")
    status = getattr(report, "status_label", None) or getattr(report, "status", "-")
    body = (
        "Hello,\n"
        f"Your scam report #{report_id} has an update from the TrustLens team.\n"
        "------------------------------------------------------------\n"
        f"Current status: {status}\n"
        "------------------------------------------------------------\n"
        "Reply from TrustLens:\n"
        f"{admin_message}\n"
        "------------------------------------------------------------\n"
        "Sign in to your TrustLens dashboard to see the full history of your report.\n\n"
        "Thank you for helping keep the community safe.\n"
        "- The TrustLens Team\n"
    )
    return send_admin_alert("TrustLens Scam Report Update", body, recipient)
