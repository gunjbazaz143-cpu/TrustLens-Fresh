"""
Centralised logging helpers used by services and routes.
"""

import logging


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger for the given module name."""
    return logging.getLogger(name)


def log_scan(app, scan_type: str, score: int, status: str, processing_time_ms: int, user_id=None):
    """Persist an AILog row (best effort - never block the scan on failure)."""
    try:
        from models import db
        from models.admin import AILog

        log = AILog(
            user_id=user_id,
            scan_type=scan_type,
            score=score,
            status=status,
            processing_time_ms=processing_time_ms,
        )
        db.session.add(log)
        db.session.commit()
    except Exception:  # noqa: BLE001
        db.session.rollback()
        app.logger.exception("Failed to persist AI log")
