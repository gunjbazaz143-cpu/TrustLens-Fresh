"""
User dashboard routes + analytics JSON API.
"""

from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user

from models import db
from models.user import User
from models.scan import (
    WebsiteScan, JobScan, EmailScan, WhatsAppScan, QRScan, PaymentScan,
    ProductScan, ClaimScan,
)
from models.report import ScamReport

dashboard_bp = Blueprint("dashboard", __name__)

SCAN_MODELS = (
    WebsiteScan, JobScan, EmailScan, WhatsAppScan, QRScan, PaymentScan,
    ProductScan, ClaimScan,
)


def _counts():
    """Return platform-wide counters for the dashboard."""
    return {
        "total_scans": sum(m.query.count() for m in SCAN_MODELS),
        "dangerous_scans": sum(
            m.query.filter_by(status="dangerous").count() for m in SCAN_MODELS
        ),
        "safe_scans": sum(
            m.query.filter_by(status="safe").count() for m in SCAN_MODELS
        ),
        "scam_reports": ScamReport.query.count(),
        "total_reports": ScamReport.query.count(),
        "users": User.query.count(),
    }


@dashboard_bp.route("/dashboard")
@login_required
def index():
    counts = _counts()
    recent_scans = (
        WebsiteScan.query.order_by(WebsiteScan.created_at.desc()).limit(6).all()
    )
    # Reports belonging to this user: submitted while signed in, or submitted
    # anonymously with their email address.
    my_reports = (
        ScamReport.query
        .outerjoin(ScamReport.user)
        .filter(
            db.or_(
                ScamReport.user_id == current_user.id,
                ScamReport.reporter_email == current_user.email,
            )
        )
        .order_by(ScamReport.created_at.desc())
        .all()
    )

    # Any unread admin reply counts as a new update. Show it to the user once,
    # then mark every reply for these reports as seen.
    new_updates = 0
    for report in my_reports:
        for reply in report.replies:
            if not reply.is_viewed:
                new_updates += 1
                reply.is_viewed = True
    if new_updates:
        db.session.commit()

    return render_template(
        "dashboard.html",
        counts=counts,
        recent_scans=recent_scans,
        my_reports=my_reports,
        new_updates=new_updates,
        user=current_user,
    )


@dashboard_bp.route("/api/dashboard-stats")
@login_required
def stats():
    """JSON statistics consumed by dashboard charts."""
    return jsonify({"success": True, **_counts()})
