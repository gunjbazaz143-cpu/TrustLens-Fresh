"""
Idempotent seeding of the Product + Ingredient reference database.

Runs automatically at boot (via ``database.init_db``) and can be re-run:

    python database/seed_product_db.py

Rules:
  - Existing tables are never wiped. Rows are only inserted when the tables are
    empty, so admin edits and additions survive every restart.
  - Products are specific products/variants with verified ingredient records,
    never a generic "brand -> ingredients" mapping.
  - Concentrations are stored only when published by the manufacturer /
    regulator; otherwise NULL (never guessed).
  - Ingredient risk categories come from curated evidence (regulators and
    scientific bodies named on each row); "unknown" stays "unknown".
"""

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from models import db  # noqa: E402
from models.product_db import Ingredient, Product, ProductIngredient  # noqa: E402
from services.product_scanner import INGREDIENT_KB  # noqa: E402  (seed source)

logger = __import__("logging").getLogger("trustlens.seed_product_db")


def _norm(text: str) -> str:
    """Lowercase alphanumeric normalization for matching/search."""
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


# --------------------------------------------------------------------------- #
# Ingredient-type inference from the legacy knowledge base "use" text.
# --------------------------------------------------------------------------- #
_TYPE_KEYWORDS = [
    ("colour", "coloring agent"), ("color", "coloring agent"), ("dye", "coloring agent"),
    ("preserv", "preservative"),
    ("sweeten", "sweetener"),
    ("emulsif", "emulsifier"),
    ("surfactant", "surfactant"), ("foaming", "surfactant"), ("detergent", "surfactant"),
    ("humectant", "humectant"), ("moisturis", "humectant"),
    ("antioxidant", "antioxidant"),
    ("solvent", "solvent"),
    ("fragrance", "fragrance"), ("flavour", "flavoring agent"), ("flavor", "flavoring agent"),
    ("thickener", "thickening agent"), ("stabiliser", "stabilizer"), ("stabilizer", "stabilizer"),
    ("disinfectant", "disinfectant"), ("antiseptic", "disinfectant"),
    ("active", "active ingredient"), ("agent", None),
]


def _derive_type(use: str):
    low = (use or "").lower()
    for keyword, label in _TYPE_KEYWORDS:
        if keyword in low:
            return label
    return None


def _derive_evidence(reason: str, category: str) -> str:
    low = (reason or "").lower()
    if any(k in low for k in ("banned", "restricted", "warning label", "requires", "must carry")):
        return "High"
    if category == "higher":
        return "High"
    return "Medium"


# --------------------------------------------------------------------------- #
# Rich ingredient records for products whose information is product-specific.
# Concentrations come from published product information; NULL = not disclosed.
# --------------------------------------------------------------------------- #
EXTRA_INGREDIENTS = [
    {
        "ingredient_id": "ING-CHLOROXYLENOL",
        "ingredient_name": "Chloroxylenol",
        "aliases": ["chloroxylenol", "pcmx", "4-chloro-3,5-dimethylphenol"],
        "ingredient_type": "disinfectant",
        "common_function": "Antiseptic / disinfectant active ingredient",
        "description": "An antimicrobial agent used at low concentrations in household "
                       "disinfectants and antiseptic skin preparations.",
        "safety_information": "Approved for external use as an antiseptic in household "
                              "products. Toxic if swallowed; may cause skin irritation "
                              "or allergy in sensitive individuals.",
        "potential_concerns": ["Toxic if swallowed", "May cause skin irritation in sensitive individuals"],
        "ingestion_status": "Not intended for ingestion - toxic if swallowed",
        "external_use_information": "Appropriate for intended external antiseptic use at "
                                    "product concentrations when used as directed.",
        "evidence_level": "Medium",
        "risk_category": "low",
        "source": "US National Library of Medicine (PubChem); European Chemicals Agency (ECHA)",
        "source_url": "https://pubchem.ncbi.nlm.nih.gov",
        "source_date": "2026-08",
    },
    {
        "ingredient_id": "ING-PINE-OIL",
        "ingredient_name": "Pine oil",
        "aliases": ["pine oil", "pinus oil"],
        "ingredient_type": "fragrance",
        "common_function": "Disinfectant aid / fragrance in cleaning products",
        "description": "An essential oil from pine trees used for its pine scent and "
                       "disinfectant properties in cleaning and antiseptic products.",
        "safety_information": "Irritant to skin and mucous membranes at high levels; "
                              "harmful if swallowed.",
        "potential_concerns": ["Skin / eye irritant", "Harmful if swallowed in quantity"],
        "ingestion_status": "Not intended for ingestion",
        "external_use_information": "Used at low levels in household disinfectants; keep "
                                    "away from eyes and open wounds.",
        "evidence_level": "Medium",
        "risk_category": "moderate",
        "source": "US National Library of Medicine (PubChem)",
        "source_url": "https://pubchem.ncbi.nlm.nih.gov",
        "source_date": "2026-08",
    },
    {
        "ingredient_id": "ING-ISOPROPYL-ALCOHOL",
        "ingredient_name": "Isopropyl alcohol",
        "aliases": ["isopropyl alcohol", "isopropanol", "propan-2-ol", "ipa"],
        "ingredient_type": "solvent",
        "common_function": "Solvent / antiseptic",
        "description": "A common solvent and antiseptic (rubbing alcohol) used in "
                       "disinfectants and skin products.",
        "safety_information": "Flammable; irritating at high concentration; not for "
                              "ingestion.",
        "potential_concerns": ["Flammable", "Irritant at high concentrations", "Not for ingestion"],
        "ingestion_status": "Not intended for ingestion",
        "external_use_information": "Widely used for surface disinfection and skin "
                                    "antisepsis at approved concentrations.",
        "evidence_level": "High",
        "risk_category": "low",
        "source": "US National Library of Medicine (PubChem); World Health Organization",
        "source_url": "https://pubchem.ncbi.nlm.nih.gov",
        "source_date": "2026-08",
    },
    {
        "ingredient_id": "ING-CASTOR-OIL",
        "ingredient_name": "Castor oil",
        "aliases": ["castor oil", "ricinus oil"],
        "ingredient_type": "humectant",
        "common_function": "Vegetable oil base / emollient and soap feedstock",
        "description": "A vegetable oil used as an emollient and as the feedstock for "
                       "the soap in antiseptic formulations.",
        "safety_information": "Generally regarded as safe for topical use at product "
                              "levels.",
        "potential_concerns": [],
        "ingestion_status": "Intended for external use in this product",
        "external_use_information": "Common emollient; well tolerated topically.",
        "evidence_level": "High",
        "risk_category": "low",
        "source": "US FDA (GRAS); US National Library of Medicine (PubChem)",
        "source_url": "https://www.fda.gov",
        "source_date": "2026-08",
    },
    {
        "ingredient_id": "ING-POTASSIUM-CASTORATE",
        "ingredient_name": "Potassium castorate",
        "aliases": ["potassium castorate", "castor oil soap", "potassium ricinoleate"],
        "ingredient_type": "surfactant",
        "common_function": "Soap base / emulsifier",
        "description": "The soap formed from castor oil, used as the cleaning/solubilising "
                       "base in antiseptic liquids.",
        "safety_information": "Standard soap; mild skin irritation possible in sensitive "
                              "individuals.",
        "potential_concerns": ["Mild skin irritation in sensitive individuals"],
        "ingestion_status": "Not intended for ingestion",
        "external_use_information": "Typical soap functionality; rinse with water if "
                                    "irritation occurs.",
        "evidence_level": "Medium",
        "risk_category": "low",
        "source": "Dettol product label / Reckitt product information",
        "source_url": "https://www.dettol.co.in",
        "source_date": "2026-08",
    },
    {
        "ingredient_id": "ING-WATER",
        "ingredient_name": "Water",
        "aliases": ["water", "aqua", "purified water", "h2o"],
        "ingredient_type": "solvent",
        "common_function": "Base solvent / carrier",
        "description": "Water is the primary carrier/solvent in most liquid products.",
        "safety_information": "Water is safe for consumption when potable.",
        "potential_concerns": [],
        "ingestion_status": "Intended for human consumption (potable water)",
        "external_use_information": "Safe base for external products.",
        "evidence_level": "High",
        "risk_category": "low",
        "source": "World Health Organization (WHO)",
        "source_url": "https://www.who.int",
        "source_date": "2026-08",
    },
    {
        "ingredient_id": "ING-SODIUM-CHLORIDE",
        "ingredient_name": "Sodium chloride",
        "aliases": ["sodium chloride", "salt", "table salt", "nacl"],
        "ingredient_type": "flavoring agent",
        "common_function": "Seasoning / base of table salt",
        "description": "Common table salt; the principal ingredient of iodized salt.",
        "safety_information": "Safe for human consumption as a seasoning; excessive "
                              "intake is a known dietary concern.",
        "potential_concerns": ["Excessive dietary intake linked to blood pressure"],
        "ingestion_status": "Intended for human consumption",
        "external_use_information": "n/a",
        "evidence_level": "High",
        "risk_category": "low",
        "source": "World Health Organization (WHO)",
        "source_url": "https://www.who.int",
        "source_date": "2026-08",
    },
    {
        "ingredient_id": "ING-POTASSIUM-IODATE",
        "ingredient_name": "Potassium iodate",
        "aliases": ["potassium iodate", "kio3"],
        "ingredient_type": "active ingredient",
        "common_function": "Source of iodine for iodized salt",
        "description": "Potassium iodate is the iodine fortifier added to iodized "
                       "table salt at very low levels.",
        "safety_information": "Approved food additive used to prevent iodine-deficiency; "
                              "added in trace amounts.",
        "potential_concerns": [],
        "ingestion_status": "Intended for human consumption (trace fortifier)",
        "external_use_information": "n/a",
        "evidence_level": "High",
        "risk_category": "low",
        "source": "Joint FAO/WHO Expert Committee on Food Additives (JECFA)",
        "source_url": "https://www.who.int",
        "source_date": "2026-08",
    },
]

_EXTRA_INDEX = {i["ingredient_id"]: i for i in EXTRA_INGREDIENTS}


# --------------------------------------------------------------------------- #
# Verified products. Only product-specific, source-supported ingredient records.
# Concentrations below are taken from published product information (label/SDS).
# --------------------------------------------------------------------------- #
PRODUCT_SEED = [
    {
        "product_id": "PRD-DETTOL-ANTISEPTIC-IN",
        "brand_name": "Dettol",
        "product_name": "Antiseptic Disinfectant Liquid",
        "product_variant": "Liquid",
        "category": "Household & Personal Care",
        "subcategory": "Antiseptic / Disinfectant",
        "intended_use": "Antiseptic disinfectant for skin cleansing, wound antisepsis "
                        "and household disinfection.",
        "consumption_status": "Not intended for human consumption",
        "manufacturer": "Reckitt Benckiser",
        "market": "India",
        "barcode": None,
        "warnings": [
            "For external use only - not for internal use",
            "Keep out of reach of children",
            "Do not swallow - seek medical help immediately if swallowed",
            "May irritate skin in sensitive individuals - rinse with water",
            "Avoid contact with eyes",
        ],
        "source": "Dettol product label / Reckitt product information",
        "source_url": "https://www.dettol.co.in",
        "source_date": "2026-08",
        "ingredients": [
            ("ING-CHLOROXYLENOL", 4.8, "w/w", "active"),
            ("ING-PINE-OIL", 9.2, "w/w", "active"),
            ("ING-ISOPROPYL-ALCOHOL", 5.1, "w/w", "active"),
            ("ING-CASTOR-OIL", None, None, "inactive"),
            ("ING-POTASSIUM-CASTORATE", None, None, "inactive"),
            ("ING-WATER", None, None, "solvent"),
        ],
    },
    {
        "product_id": "PRD-TABLE-SALT-IODIZED",
        "brand_name": "Generic",
        "product_name": "Iodized Table Salt",
        "product_variant": "Iodized",
        "category": "Food & Beverage",
        "subcategory": "Seasoning",
        "intended_use": "Seasoning and cooking salt, fortified with iodine.",
        "consumption_status": "Intended for human consumption",
        "manufacturer": "Various (standard retail iodized salt)",
        "market": "India",
        "barcode": None,
        "warnings": ["Excessive salt intake may raise blood pressure"],
        "source": "Standard iodized salt label / food regulatory composition data",
        "source_url": "https://www.who.int",
        "source_date": "2026-08",
        "ingredients": [
            ("ING-SODIUM-CHLORIDE", None, None, "base"),
            ("ING-POTASSIUM-IODATE", None, None, "active"),
        ],
    },
    {
        "product_id": "PRD-PACKAGED-DRINKING-WATER",
        "brand_name": "Generic",
        "product_name": "Packaged Drinking Water",
        "product_variant": "",
        "category": "Food & Beverage",
        "subcategory": "Beverage",
        "intended_use": "Potable drinking water.",
        "consumption_status": "Intended for human consumption",
        "manufacturer": "Various",
        "market": "India",
        "barcode": None,
        "warnings": [],
        "source": "BIS / FSSAI packaged drinking water standards",
        "source_url": "https://www.fssai.gov.in",
        "source_date": "2026-08",
        "ingredients": [
            ("ING-WATER", None, None, "base"),
        ],
    },
]


def _build_ingredient_rows() -> list:
    """Curated extra rows + KB-derived rows. Returns unsaved Ingredient objects.

    The richer curated rows (EXTRA_INGREDIENTS) always win over a legacy
    KB-derived row that would produce the same ingredient_id. KB-derived rows
    use the ingredient's display name (never the "use" sentence) and record an
    UNKNOWN ingestion status - a consumption claim is never inferred from an
    ingredient name alone.
    """
    rows = []
    for spec in EXTRA_INGREDIENTS:
        rows.append(Ingredient(
            ingredient_id=spec["ingredient_id"],
            ingredient_name=spec["ingredient_name"],
            normalized_name=_norm(spec["ingredient_name"]),
            aliases=spec["aliases"],
            ingredient_type=spec["ingredient_type"],
            common_function=spec["common_function"],
            description=spec["description"],
            safety_information=spec["safety_information"],
            potential_concerns=spec["potential_concerns"],
            ingestion_status=spec["ingestion_status"],
            external_use_information=spec["external_use_information"],
            evidence_level=spec["evidence_level"],
            risk_category=spec["risk_category"],
            source=spec["source"],
            source_url=spec["source_url"],
            source_date=spec["source_date"],
        ))
    extra_ids = {spec["ingredient_id"] for spec in EXTRA_INGREDIENTS}

    for key, entry in INGREDIENT_KB.items():
        ingredient_id = "ING-" + _norm(key).upper()
        if ingredient_id in extra_ids:
            continue
        rows.append(Ingredient(
            ingredient_id=ingredient_id,
            ingredient_name=key.replace("_", " ").title(),
            normalized_name=_norm(key),
            aliases=entry.get("aliases") or [key.replace("_", " ")],
            ingredient_type=_derive_type(entry.get("use", "")),
            common_function=entry.get("use"),
            description=entry.get("info"),
            safety_information=entry.get("reason"),
            potential_concerns=[entry.get("reason")] if entry.get("reason") else [],
            ingestion_status=None,
            evidence_level=_derive_evidence(entry.get("reason", ""), entry.get("category", "")),
            risk_category=entry.get("category") or "unknown",
            source=", ".join(entry.get("source") or []),
            source_date="2026-08",
        ))
    return rows


def seed_product_db(app, force: bool = False) -> None:
    """Insert reference data when the tables are empty (idempotent)."""
    with app.app_context():
        ingredients_exist = Ingredient.query.count() > 0
        products_exist = Product.query.count() > 0

        if not ingredients_exist or force:
            existing_ids = {i.ingredient_id for i in Ingredient.query.with_entities(Ingredient.ingredient_id).all()}
            added = 0
            for row in _build_ingredient_rows():
                if row.ingredient_id in existing_ids:
                    continue
                db.session.add(row)
                existing_ids.add(row.ingredient_id)
                added += 1
            db.session.commit()
            app.logger.info("Product DB: seeded %s ingredient row(s).", added)

        if not products_exist or force:
            product_ids = {p.product_id for p in Product.query.with_entities(Product.product_id).all()}
            added = 0
            for spec in PRODUCT_SEED:
                if spec["product_id"] in product_ids:
                    continue
                product = Product(
                    product_id=spec["product_id"],
                    brand_name=spec["brand_name"],
                    product_name=spec["product_name"],
                    product_variant=spec["product_variant"] or None,
                    category=spec["category"],
                    subcategory=spec["subcategory"],
                    intended_use=spec["intended_use"],
                    consumption_status=spec["consumption_status"],
                    manufacturer=spec["manufacturer"],
                    market=spec["market"],
                    barcode=spec["barcode"],
                    warnings=spec["warnings"],
                    source=spec["source"],
                    source_url=spec["source_url"],
                    source_date=spec["source_date"],
                )
                db.session.add(product)
                db.session.flush()
                for ingredient_id, concentration, unit, role in spec["ingredients"]:
                    ing = Ingredient.query.get(ingredient_id)
                    if ing is None:
                        continue
                    db.session.add(ProductIngredient(
                        product_id=product.product_id,
                        ingredient_id=ingredient_id,
                        concentration=concentration,
                        concentration_unit=unit,
                        role=role,
                        source=spec["source"],
                        source_url=spec["source_url"],
                        source_date=spec["source_date"],
                    ))
                product_ids.add(product.product_id)
                added += 1
            db.session.commit()
            app.logger.info("Product DB: seeded %s product record(s).", added)


if __name__ == "__main__":
    from app_factory import create_app

    app = create_app()
    seed_product_db(app, force="--force" in sys.argv)
    with app.app_context():
        print("Ingredients:", Ingredient.query.count(), "| Products:", Product.query.count())
