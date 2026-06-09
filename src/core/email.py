
import smtplib
from email.mime.text import MIMEText

from src.core.config import get_config
from src.core.logging import get_logger

logger = get_logger(__name__)


def is_smtp_configured() -> bool:
    cfg = get_config()
    return bool(cfg.smtp_host and cfg.smtp_from)


def send_reset_email(recipient_email: str, token: str, username: str) -> bool:
    cfg = get_config()
    if not is_smtp_configured():
        logger.warning("smtp_not_configured_cannot_send_email")
        return False

    subject = "Password Reset — SOC Dashboard"
    body = (
        f"Hello {username},\n\n"
        f"A password reset was requested for your SOC Dashboard account.\n\n"
        f"Your reset code is: {token}\n\n"
        f"This code expires in 15 minutes. If you did not request this reset, please ignore this email.\n\n"
        f"Regards,\nSOC Dashboard Team"
    )

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = cfg.smtp_from
    msg["To"] = recipient_email

    try:
        with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=10) as server:
            if cfg.smtp_use_tls:
                server.starttls()
            if cfg.smtp_user:
                server.login(cfg.smtp_user, cfg.smtp_password)
            server.send_message(msg)
        logger.info("reset_email_sent", extra={"recipient": recipient_email})
        return True
    except Exception as exc:
        logger.error("reset_email_failed", extra={"error": str(exc)})
        return False
