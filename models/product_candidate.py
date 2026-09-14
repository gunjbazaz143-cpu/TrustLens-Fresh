"""
Candidate products for database expansion.

When the Product Scanner analyses a product that is NOT in the verified
product database (database_match is None or BrandOnly), it stores a best-effort
extraction here instead of silently discarding it. This provides an audit trail
and a curated queue of real-world products that could later be promoted into the
verified Product database.

The table is intentional and additive:
  - It NEVER affects the verified Product / Ingredient tables or their seeding.
  - It never fabricates facts: fields not confidently read on the label stay NULL.
  - Duplicates are de-duplicated on a normalised product-name key so repeated
    scans of the same unknown product collapse into one candidate.

Candidates can be promoted / reviewed later but that is out of scope here.
"""

from datetime import datetime

from models import db


class ProductCandidate(db.Model):
    """One best-effort record of an unverified product analysed by the scanner."""

    __tablename__ = "product_candidates"

    id = db.Column(db.Integer, primary_key=True)
    # Stable dedupe key - normalised (lowercase, alphanumeric) product identity.
    # Falls back to a digest of the best-effort name+brand when no exact name
    # could be read, so a repeat scan still collapses into the same row.
    dedupe_key = db.Column(db.String(160), nullable=False, unique=True, index=True)

    product_name = db.Column(db.String(200), nullable=True)
    brand_name = db.Column(db.String(150), nullable=True)
    category = db.Column(db.String(100), nullable=True)
    subcategory = db.Column(db.String(100), nullable=True)
    consumption_status = db.Column(db.String(60), nullable=True)
    barcode = db.Column(db.String(40), nullable=True, index=True)   # GTIN/EAN if read
    qr_payload = db.Column(db.String(500), nullable=True)           # decoded QR if read
    # Best-effort ingredients read on the label (name -> category), if any.
    ingredients = db.Column(db.JSON, nullable=True)
    # How the product was identified on the label (brand only / OCR fallback).
    confidence_hint = db.Column(db.String(20), nullable=True)       # High | Medium | Low | BrandOnly
    source_note = db.Column(db.Text, nullable=True)                 # human note
    scan_count = db.Column(db.Integer, nullable=False, default=1)   # dedupe counter
    first_seen_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                             onupdate=datetime.utcnow)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return (
            f"<ProductCandidate {self.dedupe_key!r} "
            f"name={self.product_name!r} scans={self.scan_count}>"
        )
