"""
Admin / operations models - blacklist and AI logs.
"""

from datetime import datetime

from models import db


class BlacklistedDomain(db.Model):
    """Domains flagged as malicious by administrators."""

    __tablename__ = "blacklisted_domains"

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), unique=True, nullable=False, index=True)
    reason = db.Column(db.Text, nullable=True)
    added_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class AILog(db.Model):
    """Audit trail of every AI scan for performance + monitoring."""

    __tablename__ = "ai_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    scan_type = db.Column(db.String(50), nullable=False, index=True)
    score = db.Column(db.Integer, nullable=False, default=0)
    status = db.Column(db.String(20), nullable=False, default="safe")
    processing_time_ms = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
