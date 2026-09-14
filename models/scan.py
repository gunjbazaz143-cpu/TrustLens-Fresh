"""
Scan models. Every scanner result is persisted so analytics can stay accurate.
"""

from datetime import datetime

from models import db


class ScanMixin:
    """Shared columns for every scan type."""

    id = db.Column(db.Integer, primary_key=True)
    trust_score = db.Column(db.Integer, nullable=False, default=0)
    status = db.Column(db.String(20), nullable=False, default="safe")  # safe | warning | dangerous
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "trust_score": self.trust_score,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class WebsiteScan(ScanMixin, db.Model):
    """Result of a URL / website trust scan."""

    __tablename__ = "website_scans"

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    url = db.Column(db.String(500), nullable=False, index=True)
    https_valid = db.Column(db.Boolean, default=False)
    ssl_valid = db.Column(db.Boolean, default=False)
    suspicious_keywords = db.Column(db.Text, nullable=True)
    blacklisted = db.Column(db.Boolean, default=False)
    redirect_count = db.Column(db.Integer, default=0)
    reasons = db.Column(db.JSON, nullable=True)          # list of {severity, text}
    scan_meta = db.Column(db.JSON, nullable=True)        # details (TLD, age, etc.)

    def to_dict(self) -> dict:
        data = super().to_dict()
        data.update(
            {
                "url": self.url,
                "https_valid": self.https_valid,
                "ssl_valid": self.ssl_valid,
                "blacklisted": self.blacklisted,
                "redirect_count": self.redirect_count,
                "reasons": self.reasons or [],
            }
        )
        return data


class JobScan(ScanMixin, db.Model):
    """Result of a job / internship offer analysis."""

    __tablename__ = "job_scans"

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    job_title = db.Column(db.String(200))
    company_name = db.Column(db.String(200))
    contact_email = db.Column(db.String(150))
    salary = db.Column(db.String(100))
    website = db.Column(db.String(500))
    reasons = db.Column(db.JSON, nullable=True)
    input_snapshot = db.Column(db.JSON, nullable=True)


class EmailScan(ScanMixin, db.Model):
    """Result of an email phishing analysis."""

    __tablename__ = "email_scans"

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    email_content = db.Column(db.Text, nullable=False)
    suspicious_link_count = db.Column(db.Integer, default=0)
    urgency_count = db.Column(db.Integer, default=0)
    fake_sender = db.Column(db.Boolean, default=False)
    payment_request = db.Column(db.Boolean, default=False)
    reasons = db.Column(db.JSON, nullable=True)


class WhatsAppScan(ScanMixin, db.Model):
    """Result of a WhatsApp screenshot / message analysis."""

    __tablename__ = "whatsapp_scans"

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    screenshot_path = db.Column(db.String(500), nullable=True)
    extracted_text = db.Column(db.Text, nullable=True)
    scam_type = db.Column(db.String(100), nullable=True)
    reasons = db.Column(db.JSON, nullable=True)


class QRScan(ScanMixin, db.Model):
    """Result of a QR code decode + destination analysis."""

    __tablename__ = "qr_scans"

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    image_path = db.Column(db.String(500), nullable=True)
    decoded_url = db.Column(db.String(500), nullable=True)
    is_suspicious = db.Column(db.Boolean, default=False)
    reasons = db.Column(db.JSON, nullable=True)


class PaymentScan(ScanMixin, db.Model):
    """Result of a payment screenshot fraud analysis."""

    __tablename__ = "payment_scans"

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    screenshot_path = db.Column(db.String(500), nullable=True)
    fraud_probability = db.Column(db.Integer, nullable=False, default=0)
    edited_metadata = db.Column(db.Boolean, default=False)
    flags = db.Column(db.JSON, nullable=True)
    reasons = db.Column(db.JSON, nullable=True)


class ProductScan(ScanMixin, db.Model):
    """Result of a product ingredient label analysis."""

    __tablename__ = "product_scans"

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    input_text = db.Column(db.Text, nullable=True)
    image_path = db.Column(db.String(500), nullable=True)
    extracted_text = db.Column(db.Text, nullable=True)
    product_name = db.Column(db.String(200), nullable=True)
    product_id = db.Column(db.String(40), nullable=True, index=True)
    database_match = db.Column(db.String(20), nullable=True)   # High|Medium|Low|BrandOnly|None
    consumption_status = db.Column(db.String(60), nullable=True)
    edible_status = db.Column(db.String(20), nullable=True)    # edible|non_edible|uncertain
    usage_purpose = db.Column(db.String(60), nullable=True)    # e.g. Food, Hair, Body
    allergen_warnings = db.Column(db.JSON, nullable=True)       # list of allergen dicts
    category = db.Column(db.String(60), nullable=True)
    data_quality = db.Column(db.JSON, nullable=True)
    reliable = db.Column(db.Boolean, default=False)
    risk_level = db.Column(db.String(20), default="insufficient")
    ingredient_count = db.Column(db.Integer, default=0)
    ingredients = db.Column(db.JSON, nullable=True)
    concerns = db.Column(db.JSON, nullable=True)
    positives = db.Column(db.JSON, nullable=True)
    unknown_ingredients = db.Column(db.JSON, nullable=True)
    reasons = db.Column(db.JSON, nullable=True)
    explanation = db.Column(db.Text, nullable=True)
    trust_score_explanation = db.Column(db.Text, nullable=True)
    input_snapshot = db.Column(db.JSON, nullable=True)


class ClaimScan(ScanMixin, db.Model):
    """Result of a user-submitted claim analysis."""

    __tablename__ = "claim_scans"

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    claim_text = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=True)
    verdict = db.Column(db.String(40), nullable=True)
    confidence = db.Column(db.String(20), default="Low")
    explanation = db.Column(db.Text, nullable=True)
    evidence = db.Column(db.JSON, nullable=True)
    sources = db.Column(db.JSON, nullable=True)
    limitations = db.Column(db.Text, nullable=True)
    caution = db.Column(db.Text, nullable=True)
    reasons = db.Column(db.JSON, nullable=True)
