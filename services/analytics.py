"""
Analytics aggregation helpers used by the admin dashboard.

Centralises every SQL query that powers the admin charts so routes stay thin
and the numbers are consistent across pages.
"""

from datetime import datetime, timedelta

from models import db
from models.user import User
from models.scan import (
    WebsiteScan,
    JobScan,
    EmailScan,
    WhatsAppScan,
    QRScan,
    PaymentScan,
    ProductScan,
    ClaimScan,
)
from models.report import ScamReport
from models.admin import AILog

# Every persistent scan model (mixin: trust_score, status, created_at).
SCAN_MODELS = [
    WebsiteScan, JobScan, EmailScan, WhatsAppScan, QRScan, PaymentScan,
    ProductScan, ClaimScan,
]


def fraud_type_counts() -> list:
    """
    Aggregate the most common fraud types across all sources of truth:
      - user-submitted ScamReports (their scam_type)
      - WhatsApp messages auto-classified as a scam category
      - remaining scanner categories (website/email/qr/payment/job) counted
        under a derived fraud label

    Returns a list of (label, count) tuples sorted by count (descending).
    """
    counts: dict = {}

    def _add(label: str, amount: int = 1) -> None:
        key = (label or "Other").strip() or "Other"
        counts[key] = counts.get(key, 0) + amount

    # 1. Community scam reports - the most explicit fraud signal.
    for (label,) in db.session.query(ScamReport.scam_type).all():
        _add(label)

    # 2. Auto-classified WhatsApp scams.
    rows = (
        WhatsAppScan.query.filter(WhatsAppScan.scam_type.isnot(None))
        .with_entities(WhatsAppScan.scam_type)
        .all()
    )
    for (label,) in rows:
        _add(label)

    # 3. Scanner categories that map to a fraud family by default.
    _add("Website/Phishing", WebsiteScan.query.count())
    _add("Email/Phishing", EmailScan.query.count())
    _add("Payment Fraud", PaymentScan.query.count())
    _add("QR Code Scam", QRScan.query.count())
    _add("Fake Job/Internship", JobScan.query.count())
    _add("Product/Ingredient", ProductScan.query.count())
    _add("Misleading Claim", ClaimScan.query.count())

    return sorted(counts.items(), key=lambda item: item[1], reverse=True)


def risk_distribution() -> dict:
    """Count scans by risk bucket (safe / warning / dangerous)."""
    return {
        "safe": sum(m.query.filter_by(status="safe").count() for m in SCAN_MODELS),
        "warning": sum(m.query.filter_by(status="warning").count() for m in SCAN_MODELS),
        "dangerous": sum(m.query.filter_by(status="dangerous").count() for m in SCAN_MODELS),
    }


def scan_volume_timeseries(days: int = 14) -> list:
    """
    Daily scan volume for the last `days` days.
    Returns a list of {date: "YYYY-MM-DD", count: int} oldest first.
    """
    start = datetime.utcnow().date() - timedelta(days=days - 1)
    rows = []
    for offset in range(days):
        day = start + timedelta(days=offset)
        day_start = datetime(day.year, day.month, day.day)
        day_end = day_start + timedelta(days=1)
        total = sum(
            m.query.filter(m.created_at >= day_start, m.created_at < day_end).count()
            for m in SCAN_MODELS
        )
        rows.append({"date": day.isoformat(), "count": total})
    return rows


def user_growth_timeseries(days: int = 14) -> list:
    """Daily new-user registrations for the last `days` days."""
    start = datetime.utcnow().date() - timedelta(days=days - 1)
    rows = []
    for offset in range(days):
        day = start + timedelta(days=offset)
        day_start = datetime(day.year, day.month, day.day)
        day_end = day_start + timedelta(days=1)
        count = User.query.filter(User.created_at >= day_start, User.created_at < day_end).count()
        rows.append({"date": day.isoformat(), "count": count})
    return rows


def category_volume() -> list:
    """Scan volume by scanner category. Returns list of (label, count)."""
    return [
        ("Website", WebsiteScan.query.count()),
        ("Job", JobScan.query.count()),
        ("Email", EmailScan.query.count()),
        ("WhatsApp", WhatsAppScan.query.count()),
        ("QR", QRScan.query.count()),
        ("Payment", PaymentScan.query.count()),
        ("Product", ProductScan.query.count()),
        ("Claim", ClaimScan.query.count()),
    ]


def scan_log_timeseries(days: int = 14) -> list:
    """Daily AI log volume (matches the AILog audit table)."""
    start = datetime.utcnow().date() - timedelta(days=days - 1)
    rows = []
    for offset in range(days):
        day = start + timedelta(days=offset)
        day_start = datetime(day.year, day.month, day.day)
        day_end = day_start + timedelta(days=1)
        count = AILog.query.filter(AILog.created_at >= day_start, AILog.created_at < day_end).count()
        rows.append({"date": day.isoformat(), "count": count})
    return rows
