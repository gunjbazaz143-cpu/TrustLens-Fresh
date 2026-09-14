"""
Normalized product + ingredient reference database.

The Product Scanner uses this relational design instead of only OCR text:

    Product 1---n ProductIngredient n---1 Ingredient

    Product 1---n ProductIdentifier
    Product 1---n ProductImage
    Product 1---n ProductAttribute
    Product 1---n ProductVerification
    Product 1---n ProductScoreFactor

    Category (self-referencing parent/child)

Each product records its own verified ingredients (never a generic
"brand -> ingredients" mapping). Each ingredient records evidence-based
safety information. Concentrations are only stored when reliably known;
unknown concentrations remain NULL rather than being guessed.

The risk categories and evidence statements come from curated, authoritative
sources (regulators, manufacturers, scientific bodies) stored on each row.
"Unknown" stays "Unknown" - an ingredient is never called dangerous simply
because it is a chemical.
"""

from datetime import datetime

from models import db


# --------------------------------------------------------------------------- #
# Reusable risk-level constants (category-independent)
# --------------------------------------------------------------------------- #
RISK_LEVELS = ("low", "moderate", "high", "unknown", "needs_verification")

VERIFICATION_STATUSES = ("verified", "partially_verified", "unverified", "needs_verification")


# --------------------------------------------------------------------------- #
# Category model (self-referencing parent/child hierarchy)
# --------------------------------------------------------------------------- #
class Category(db.Model):
    """Hierarchical product category with parent/child support."""

    __tablename__ = "categories"

    category_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    category_name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    parent_category_id = db.Column(db.Integer, db.ForeignKey("categories.category_id"), nullable=True)
    sort_order = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                           onupdate=datetime.utcnow)

    parent = db.relationship("Category", remote_side=[category_id], backref="children")

    def __repr__(self):
        return f"<Category {self.category_id} {self.category_name!r}>"

    def to_dict(self):
        return {
            "category_id": self.category_id,
            "category_name": self.category_name,
            "description": self.description,
            "parent_category_id": self.parent_category_id,
            "children": [c.to_dict() for c in self.children],
        }


# --------------------------------------------------------------------------- #
# Ingredient
# --------------------------------------------------------------------------- #
class Ingredient(db.Model):
    """One reference ingredient with evidence-based safety information."""

    __tablename__ = "ingredients"

    ingredient_id = db.Column(db.String(40), primary_key=True)      # e.g. ING-WATER
    ingredient_name = db.Column(db.String(200), nullable=False)
    normalized_name = db.Column(db.String(200), nullable=False, index=True)
    aliases = db.Column(db.JSON, nullable=True)                     # list[str]
    ingredient_type = db.Column(db.String(50), nullable=True)       # surfactant, preservative, ...
    common_function = db.Column(db.String(200), nullable=True)
    description = db.Column(db.Text, nullable=True)
    safety_information = db.Column(db.Text, nullable=True)
    potential_concerns = db.Column(db.JSON, nullable=True)          # list[str]
    ingestion_status = db.Column(db.String(120), nullable=True)
    external_use_information = db.Column(db.Text, nullable=True)
    evidence_level = db.Column(db.String(20), nullable=True)        # High | Medium | Low
    # low | moderate | higher | unknown - assigned from evidence for the
    # ingredient's intended/dominant use, never from "it is a chemical".
    risk_category = db.Column(db.String(20), default="unknown")
    # NEW fields
    category = db.Column(db.String(50), nullable=True)              # food | cosmetic | chemical | etc.
    score_impact = db.Column(db.Float, nullable=True)               # negative = concern, positive = benefit
    source = db.Column(db.String(300), nullable=True)
    source_url = db.Column(db.String(500), nullable=True)
    source_date = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                           onupdate=datetime.utcnow)

    # ---- helpers ----------------------------------------------------------- #

    def card(self) -> dict:
        """Frontend ingredient card - only fields with real information."""
        return {
            "ingredient_id": self.ingredient_id,
            "name": self.ingredient_name,
            "normalized": self.normalized_name,
            "type": self.ingredient_type,
            "category": self.risk_category or "unknown",
            "function": self.common_function,
            "description": self.description,
            "safety_information": self.safety_information,
            "concerns": self.potential_concerns or [],
            "ingestion_status": self.ingestion_status,
            "external_use_information": self.external_use_information,
            "evidence_level": self.evidence_level,
            "ingredient_category": self.category,
            "score_impact": self.score_impact,
            "source": self.source,
            "source_url": self.source_url,
        }

    def __repr__(self):
        return f"<Ingredient {self.ingredient_id} {self.ingredient_name!r}>"


# --------------------------------------------------------------------------- #
# Product
# --------------------------------------------------------------------------- #
class Product(db.Model):
    """One verified product / variant (never a generic brand placeholder)."""

    __tablename__ = "products"

    product_id = db.Column(db.String(40), primary_key=True)         # e.g. PRD-DETTOL-ANTISEPTIC
    brand_name = db.Column(db.String(150), nullable=False, index=True)
    product_name = db.Column(db.String(200), nullable=False, index=True)
    product_variant = db.Column(db.String(200), nullable=True)
    category = db.Column(db.String(100), nullable=True)
    subcategory = db.Column(db.String(100), nullable=True)
    intended_use = db.Column(db.Text, nullable=True)
    # Intended for human consumption | Not intended for human consumption |
    # External use only | Household/industrial use | Unknown
    consumption_status = db.Column(db.String(60), nullable=True)
    manufacturer = db.Column(db.String(200), nullable=True)
    market = db.Column(db.String(100), nullable=True)
    barcode = db.Column(db.String(40), nullable=True, index=True)   # GTIN/EAN when known
    warnings = db.Column(db.JSON, nullable=True)                    # list[str]
    source = db.Column(db.String(300), nullable=True)
    source_url = db.Column(db.String(500), nullable=True)
    source_date = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                           onupdate=datetime.utcnow)
    # NEW fields
    category_id = db.Column(db.Integer, db.ForeignKey("categories.category_id"), nullable=True, index=True)
    subcategory_id = db.Column(db.Integer, db.ForeignKey("categories.category_id"), nullable=True, index=True)
    product_type = db.Column(db.String(100), nullable=True)         # physical, digital, service
    description = db.Column(db.Text, nullable=True)
    gtin = db.Column(db.String(20), nullable=True, index=True)
    sku = db.Column(db.String(50), nullable=True, index=True)
    model_number = db.Column(db.String(100), nullable=True, index=True)
    product_code = db.Column(db.String(50), nullable=True, index=True)
    country = db.Column(db.String(100), nullable=True)
    edible_status = db.Column(db.String(20), nullable=True)         # edible | non_edible | uncertain
    external_use_status = db.Column(db.Boolean, nullable=True)
    verification_status = db.Column(db.String(30), nullable=False, default="verified")
    identification_confidence = db.Column(db.String(20), nullable=True)
    trust_score = db.Column(db.Integer, nullable=True)              # cached computed score
    risk_level = db.Column(db.String(20), nullable=True)

    associations = db.relationship(
        "ProductIngredient",
        back_populates="product",
        cascade="all, delete-orphan",
        order_by="ProductIngredient.id",
    )
    parent_category = db.relationship("Category", foreign_keys=[category_id])
    child_category = db.relationship("Category", foreign_keys=[subcategory_id])

    # ---- helpers ----------------------------------------------------------- #

    def ingredient_links(self) -> list:
        """(ProductIngredient association, Ingredient) pairs for this product."""
        return [
            (assoc, assoc.ingredient)
            for assoc in self.associations
            if assoc.ingredient is not None
        ]

    def to_dict(self) -> dict:
        return {
            "product_id": self.product_id,
            "brand_name": self.brand_name,
            "product_name": self.product_name,
            "product_variant": self.product_variant,
            "category": self.category,
            "subcategory": self.subcategory,
            "intended_use": self.intended_use,
            "consumption_status": self.consumption_status,
            "manufacturer": self.manufacturer,
            "market": self.market,
            "barcode": self.barcode,
            "warnings": self.warnings or [],
            "source": self.source,
            "source_url": self.source_url,
            "source_date": self.source_date,
            "product_type": self.product_type,
            "description": self.description,
            "gtin": self.gtin,
            "sku": self.sku,
            "model_number": self.model_number,
            "product_code": self.product_code,
            "country": self.country,
            "edible_status": self.edible_status,
            "external_use_status": self.external_use_status,
            "verification_status": self.verification_status,
            "identification_confidence": self.identification_confidence,
            "trust_score": self.trust_score,
            "risk_level": self.risk_level,
            "ingredient_count": len(self.ingredient_links()),
        }

    def __repr__(self):
        return f"<Product {self.product_id} {self.brand_name} {self.product_name!r}>"


# --------------------------------------------------------------------------- #
# ProductIngredient (junction)
# --------------------------------------------------------------------------- #
class ProductIngredient(db.Model):
    """Junction table linking one product to one ingredient (many-to-many)."""

    __tablename__ = "product_ingredients"

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(
        db.String(40), db.ForeignKey("products.product_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    ingredient_id = db.Column(
        db.String(40), db.ForeignKey("ingredients.ingredient_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    concentration = db.Column(db.Float, nullable=True)              # NULL when unknown
    concentration_unit = db.Column(db.String(30), nullable=True)    # e.g. w/w, %
    role = db.Column(db.String(40), nullable=True)                  # active | inactive | preservative ...
    # NEW fields
    quantity_value = db.Column(db.String(100), nullable=True)       # raw quantity text if available
    position_order = db.Column(db.Integer, nullable=True)           # order in ingredient list
    detected_from_image = db.Column(db.Boolean, nullable=True)
    verification_status = db.Column(db.String(30), nullable=True)
    source = db.Column(db.String(300), nullable=True)
    source_url = db.Column(db.String(500), nullable=True)
    source_date = db.Column(db.String(50), nullable=True)

    product = db.relationship("Product", back_populates="associations")
    ingredient = db.relationship("Ingredient")

    __table_args__ = (
        db.UniqueConstraint("product_id", "ingredient_id", name="uq_product_ingredient"),
    )

    def __repr__(self):
        return f"<ProductIngredient {self.product_id} -> {self.ingredient_id}>"


# --------------------------------------------------------------------------- #
# ProductIdentifier
# --------------------------------------------------------------------------- #
class ProductIdentifier(db.Model):
    """Multiple identifiers for a single product (barcode, GTIN, SKU, etc.)."""

    __tablename__ = "product_identifiers"

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(
        db.String(40), db.ForeignKey("products.product_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    identifier_type = db.Column(db.String(30), nullable=False)     # barcode|gtin|sku|model_number|product_code|qr_code|manufacturer_code
    identifier_value = db.Column(db.String(100), nullable=False)
    source = db.Column(db.String(300), nullable=True)
    verification_status = db.Column(db.String(30), default="unverified")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                           onupdate=datetime.utcnow)

    product = db.relationship("Product", backref="identifiers")

    __table_args__ = (
        db.UniqueConstraint("product_id", "identifier_type", "identifier_value",
                            name="uq_product_identifier"),
        db.Index("ix_identifier_value", "identifier_value"),
    )

    def __repr__(self):
        return f"<ProductIdentifier {self.identifier_type}={self.identifier_value!r}>"


# --------------------------------------------------------------------------- #
# ProductImage
# --------------------------------------------------------------------------- #
class ProductImage(db.Model):
    """Image references for a product (front, back, label, barcode, etc.)."""

    __tablename__ = "product_images"

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(
        db.String(40), db.ForeignKey("products.product_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    image_type = db.Column(db.String(30), nullable=False)          # front|back|label|ingredients|barcode|package|other
    image_reference = db.Column(db.String(500), nullable=True)     # file path or URL
    ocr_text = db.Column(db.Text, nullable=True)
    ocr_confidence = db.Column(db.Float, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    product = db.relationship("Product", backref="images")

    def __repr__(self):
        return f"<ProductImage {self.image_type} for {self.product_id}>"


# --------------------------------------------------------------------------- #
# ProductAttribute (flexible key-value)
# --------------------------------------------------------------------------- #
class ProductAttribute(db.Model):
    """Flexible key-value attributes for any product type."""

    __tablename__ = "product_attributes"

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(
        db.String(40), db.ForeignKey("products.product_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    attribute_name = db.Column(db.String(100), nullable=False)     # e.g. calories, battery, material
    attribute_value = db.Column(db.Text, nullable=True)
    attribute_type = db.Column(db.String(30), nullable=True)       # text|number|boolean|json
    source = db.Column(db.String(300), nullable=True)
    verification_status = db.Column(db.String(30), default="unverified")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                           onupdate=datetime.utcnow)

    product = db.relationship("Product", backref="attributes")

    __table_args__ = (
        db.UniqueConstraint("product_id", "attribute_name", name="uq_product_attribute"),
    )

    def __repr__(self):
        return f"<ProductAttribute {self.attribute_name}={self.attribute_value!r}>"


# --------------------------------------------------------------------------- #
# ProductVerification
# --------------------------------------------------------------------------- #
class ProductVerification(db.Model):
    """Verification records for product information claims."""

    __tablename__ = "product_verifications"

    verification_id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(
        db.String(40), db.ForeignKey("products.product_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    verification_type = db.Column(db.String(50), nullable=False)   # identity|ingredient|certification|claim|barcode
    verification_status = db.Column(db.String(30), nullable=False, default="unverified")
    confidence_score = db.Column(db.Float, nullable=True)           # 0.0 - 1.0
    verified_value = db.Column(db.Text, nullable=True)
    source = db.Column(db.String(300), nullable=True)
    explanation = db.Column(db.Text, nullable=True)
    verified_at = db.Column(db.DateTime, nullable=True)

    product = db.relationship("Product", backref="verifications")

    __table_args__ = (
        db.UniqueConstraint("product_id", "verification_type",
                            name="uq_product_verification"),
    )

    def __repr__(self):
        return f"<ProductVerification {self.verification_type}={self.verification_status}>"


# --------------------------------------------------------------------------- #
# ProductScoreFactor
# --------------------------------------------------------------------------- #
class ProductScoreFactor(db.Model):
    """Individual scoring factors explaining a product's trust score."""

    __tablename__ = "product_score_factors"

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(
        db.String(40), db.ForeignKey("products.product_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    factor_type = db.Column(db.String(50), nullable=False)         # positive|negative|neutral
    factor_name = db.Column(db.String(200), nullable=False)        # e.g. "Product identity verified"
    factor_value = db.Column(db.String(200), nullable=True)        # e.g. "High confidence", "+10", "-5"
    score_impact = db.Column(db.Float, nullable=True)              # numeric impact on score
    risk_level = db.Column(db.String(20), nullable=True)
    explanation = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    product = db.relationship("Product", backref="score_factors")

    def __repr__(self):
        return f"<ProductScoreFactor {self.factor_name}={self.score_impact}>"
