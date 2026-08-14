"""
Scam report model - private scam intelligence for admin review.

Reports are only visible to TrustLens admins and their reporter. Every report
moves through a 4-state workflow (new / under review / resolved / rejected) and
admins respond with a reply that is stored alongside a status change.
"""

from datetime import datetime

from models import db

# Workflow statuses surfaced in the admin panel and to the reporter.
REPORT_STATUSES = ("new", "under review", "resolved", "rejected")

# Human-friendly labels for the same statuses.
STATUS_LABELS = {
    "new": "New",
    "under review": "Under Review",
    "resolved": "Resolved",
    "rejected": "Rejected",
}


class ScamReport(db.Model):
    """User-submitted scam report. Private - only admins and the reporter see it."""

    __tablename__ = "scam_reports"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    # Email used to send the reporter status updates. Falls back to the
    # account email when the report was submitted while logged in.
    reporter_email = db.Column(db.String(150), nullable=True)
    title = db.Column(db.String(200), nullable=False)
    scam_type = db.Column(db.String(100), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False)
    screenshot_path = db.Column(db.String(500), nullable=True)
    contact_number = db.Column(db.String(20), nullable=True)
    website_url = db.Column(db.String(500), nullable=True)
    scam_date = db.Column(db.Date, nullable=True)
    status = db.Column(db.String(20), nullable=False, default="new")  # new|under review|resolved|rejected
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    replies = db.relationship(
        "ScamReportReply",
        backref="report",
        lazy=True,
        order_by="ScamReportReply.created_at.asc()",
    )

    # ---- Derived reporter info -------------------------------------------
    @property
    def reporter_name(self) -> str | None:
        return self.user.full_name if self.user is not None else None

    @property
    def reporter_display_email(self) -> str | None:
        if self.reporter_email:
            return self.reporter_email
        return self.user.email if self.user is not None else None

    # ---- Reply helpers ----------------------------------------------------
    @property
    def latest_reply(self) -> "ScamReportReply | None":
        return self.replies[-1] if self.replies else None

    @property
    def last_updated(self) -> datetime:
        if self.replies:
            return self.replies[-1].created_at
        return self.created_at

    @property
    def status_label(self) -> str:
        return STATUS_LABELS.get(self.status, self.status.title())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "scam_type": self.scam_type,
            "description": self.description,
            "website_url": self.website_url,
            "contact_number": self.contact_number,
            "reporter_email": self.reporter_display_email,
            "scam_date": self.scam_date.isoformat() if self.scam_date else None,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ScamReportReply(db.Model):
    """Admin response to a scam report. Every reply records a status change."""

    __tablename__ = "scam_report_replies"

    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey("scam_reports.id"), nullable=False, index=True)
    admin_message = db.Column(db.Text, nullable=False)
    status_after = db.Column(db.String(20), nullable=False, default="new")
    # Cleared once the reporter has seen the update on their dashboard.
    is_viewed = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<ScamReportReply #{self.id} report={self.report_id} status={self.status_after}>"
