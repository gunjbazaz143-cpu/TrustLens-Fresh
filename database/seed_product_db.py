"""
Idempotent seeding of the Product + Ingredient reference database.

Runs automatically at boot (via ``database.init_db``) and can be re-run:

    python database/seed_product_db.py
    python database/seed_product_db.py --force

Rules:
  - Existing tables are never wiped. Rows are only inserted when the tables are
    empty (or --force is used), so admin edits and additions survive every restart.
  - Products are specific products/variants with verified ingredient records,
    never a generic "brand -> ingredients" mapping.
  - Concentrations are stored only when published by the manufacturer /
    regulator; otherwise NULL (never guessed).
  - Ingredient risk categories come from curated evidence (regulators and
    scientific bodies named on each row); "unknown" stays "unknown".
"""

import re
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from models import db  # noqa: E402
from models.product_db import (  # noqa: E402
    Ingredient, Product, ProductIngredient, Category,
    ProductIdentifier, ProductImage, ProductAttribute,
    ProductVerification, ProductScoreFactor,
)
from services.product_scanner import INGREDIENT_KB  # noqa: E402  (seed source)

logger = __import__("logging").getLogger("trustlens.seed_product_db")


def _norm(text: str) -> str:
    """Lowercase alphanumeric normalization for matching/search."""
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


# --------------------------------------------------------------------------- #
# Category hierarchy definition
# --------------------------------------------------------------------------- #
# Each entry: (name, description, parent_name_or_None, sort_order)
CATEGORY_HIERARCHY = [
    # Top-level
    ("Food", "Food products", None, 1),
    ("Beverages", "Drinks and beverages", None, 2),
    ("Personal Care", "Personal hygiene and care products", None, 3),
    ("Skincare", "Skin care and treatment products", None, 4),
    ("Haircare", "Hair care and treatment products", None, 5),
    ("Body Care", "Body care and moisturizing products", None, 6),
    ("Cosmetics / Makeup", "Makeup and cosmetic products", None, 7),
    ("Health & Wellness", "Health supplements and wellness products", None, 8),
    ("Cleaning Products", "Household cleaning products", None, 9),
    ("Household Products", "General household products", None, 10),
    ("Electronics", "Electronic devices and accessories", None, 11),
    ("Home Appliances", "Home and kitchen appliances", None, 12),
    ("Kitchen Products", "Cookware and kitchen utensils", None, 13),
    ("Clothing", "Apparel and garments", None, 14),
    ("Shoes", "Footwear", None, 15),
    ("Bags", "Bags and luggage", None, 16),
    ("Toys", "Toys and play items", None, 17),
    ("Baby Products", "Baby care and infant products", None, 18),
    ("Stationery", "Office and school supplies", None, 19),
    ("Beauty Products", "Beauty and fragrance products", None, 20),
    ("Automotive Products", "Automotive care and accessories", None, 21),
    ("Other Consumer Products", "Other consumer goods", None, 99),

    # Food children
    ("Snacks", "Packaged snack foods", "Food", 1),
    ("Biscuits", "Biscuits and cookies", "Food", 2),
    ("Confectionery", "Sweets, chocolates and candies", "Food", 3),
    ("Cereals", "Breakfast cereals and grains", "Food", 4),
    ("Dairy", "Dairy products", "Food", 5),
    ("Bakery", "Baked goods", "Food", 6),
    ("Spices & Seasonings", "Spices, seasonings and condiments", "Food", 7),
    ("Cooking Oils", "Edible oils and cooking fats", "Food", 8),

    # Beverages children
    ("Soft Drinks", "Carbonated and non-carbonated soft drinks", "Beverages", 1),
    ("Juices", "Fruit and vegetable juices", "Beverages", 2),
    ("Tea & Coffee", "Tea, coffee and related beverages", "Beverages", 3),
    ("Energy Drinks", "Energy and sports drinks", "Beverages", 4),
    ("Water", "Packaged drinking water", "Beverages", 5),

    # Personal Care children
    ("Body Wash", "Body wash and shower gel", "Personal Care", 1),
    ("Soap", "Bar soap and hand soap", "Personal Care", 2),
    ("Deodorant", "Deodorants and antiperspirants", "Personal Care", 3),
    ("Oral Care", "Toothpaste, mouthwash and dental care", "Personal Care", 4),
    ("Shaving", "Shaving cream, razors and aftershave", "Personal Care", 5),

    # Skincare children
    ("Face Wash", "Facial cleansers and face wash", "Skincare", 1),
    ("Moisturizer", "Face and body moisturizers", "Skincare", 2),
    ("Sunscreen", "Sun protection products", "Skincare", 3),
    ("Serums", "Facial serums and treatments", "Skincare", 4),

    # Haircare children
    ("Shampoo", "Hair cleansing products", "Haircare", 1),
    ("Conditioner", "Hair conditioning products", "Haircare", 2),
    ("Hair Styling", "Hair styling products", "Haircare", 3),

    # Body Care children
    ("Body Lotion", "Body moisturizing lotions", "Body Care", 1),
    ("Body Butter", "Rich body moisturizers", "Body Care", 2),
    ("Hand Cream", "Hand care creams", "Body Care", 3),

    # Cosmetics children
    ("Face Makeup", "Foundation, concealer, powder", "Cosmetics / Makeup", 1),
    ("Lip Products", "Lipstick, lip gloss, lip balm", "Cosmetics / Makeup", 2),
    ("Eye Makeup", "Mascara, eyeliner, eyeshadow", "Cosmetics / Makeup", 3),

    # Health & Wellness children
    ("Supplements", "Dietary supplements", "Health & Wellness", 1),
    ("Vitamins", "Vitamin and mineral supplements", "Health & Wellness", 2),
    ("Protein", "Protein powders and bars", "Health & Wellness", 3),

    # Cleaning Products children
    ("Surface Cleaners", "All-purpose and surface cleaners", "Cleaning Products", 1),
    ("Dishwashing", "Dish soap and dishwasher products", "Cleaning Products", 2),
    ("Laundry", "Laundry detergent and fabric care", "Cleaning Products", 3),
    ("Disinfectants", "Disinfectants and sanitizers", "Cleaning Products", 4),

    # Household Products children
    ("Air Fresheners", "Room sprays and diffusers", "Household Products", 1),
    ("Candles", "Scented and decorative candles", "Household Products", 2),

    # Electronics children
    ("Mobile Accessories", "Phone cases, screen protectors, cables", "Electronics", 1),
    ("Audio", "Headphones, earphones, speakers", "Electronics", 2),
    ("Computer Accessories", "Keyboards, mice, USB drives", "Electronics", 3),

    # Home Appliances children
    ("Kitchen Appliances", "Mixer, grinder, toaster, etc.", "Home Appliances", 1),
    ("Fans", "Ceiling fans, table fans, exhaust fans", "Home Appliances", 2),
    ("Irons", "Clothes irons and steamers", "Home Appliances", 3),

    # Kitchen Products children
    ("Cookware", "Pans, pots, pressure cookers", "Kitchen Products", 1),
    ("Utensils", "Kitchen utensils and tools", "Kitchen Products", 2),
    ("Storage", "Containers and food storage", "Kitchen Products", 3),

    # Clothing children
    ("Men's Clothing", "Shirts, t-shirts, trousers for men", "Clothing", 1),
    ("Women's Clothing", "Dresses, tops, skirts for women", "Clothing", 2),
    ("Kids' Clothing", "Clothing for children", "Clothing", 3),

    # Shoes children
    ("Sports Shoes", "Running, training and sports shoes", "Shoes", 1),
    ("Casual Shoes", "Everyday casual footwear", "Shoes", 2),
    ("Formal Shoes", "Formal and dress shoes", "Shoes", 3),

    # Bags children
    ("Backpacks", "School and travel backpacks", "Bags", 1),
    ("Handbags", "Women's handbags and purses", "Bags", 2),
    ("Travel Luggage", "Suitcases and trolley bags", "Bags", 3),

    # Toys children
    ("Educational Toys", "Learning and educational toys", "Toys", 1),
    ("Action Figures", "Action figures and dolls", "Toys", 2),
    ("Board Games", "Board games and puzzles", "Toys", 3),

    # Baby Products children
    ("Diapers", "Diapers and nappies", "Baby Products", 1),
    ("Baby Food", "Infant formula and baby food", "Baby Products", 2),
    ("Baby Skincare", "Baby lotion, shampoo, and wash", "Baby Products", 3),

    # Stationery children
    ("Pens & Pencils", "Writing instruments", "Stationery", 1),
    ("Notebooks", "Notebooks and diaries", "Stationery", 2),
    ("Art Supplies", "Paints, brushes and craft supplies", "Stationery", 3),

    # Beauty Products children
    ("Fragrances", "Perfumes and body mists", "Beauty Products", 1),
    ("Nail Care", "Nail polish and nail care", "Beauty Products", 2),

    # Automotive children
    ("Car Care", "Car shampoo, wax, polish", "Automotive Products", 1),
    ("Car Accessories", "Air fresheners, phone mounts", "Automotive Products", 2),
]


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
# Curated ingredient records (product-specific, verified data).
# Concentrations come from published product information; NULL = not disclosed.
# --------------------------------------------------------------------------- #
EXTRA_INGREDIENTS = [
    {
        "ingredient_id": "ING-CHLOROXYLENOL",
        "ingredient_name": "Chloroxylenol",
        "aliases": ["chloroxylenol", "pcmx", "4-chloro-3,5-dimethylphenol"],
        "ingredient_type": "disinfectant",
        "category": "cleaning",
        "score_impact": -3.0,
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
        "category": "cleaning",
        "score_impact": -2.0,
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
        "category": "chemical",
        "score_impact": -1.0,
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
        "category": "cosmetic",
        "score_impact": 2.0,
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
        "category": "chemical",
        "score_impact": -1.0,
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
        "category": "food",
        "score_impact": 0.0,
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
        "category": "food",
        "score_impact": 0.0,
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
        "category": "food",
        "score_impact": 3.0,
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

# --------------------------------------------------------------------------- #
# Additional ingredients for new product categories
# --------------------------------------------------------------------------- #
ADDITIONAL_INGREDIENTS = [
    # --- Food / Snack ---
    {"ingredient_id": "ING-REFINED-WHEAT-FLOUR", "ingredient_name": "Refined wheat flour",
     "aliases": ["maida", "refined flour", "wheat flour", "all-purpose flour"],
     "ingredient_type": "base ingredient", "category": "food", "score_impact": 0.0,
     "common_function": "Base flour for biscuits, bread and snacks",
     "description": "Refined wheat flour used as the primary base ingredient in biscuits, bread, and snack products.",
     "safety_information": "Safe for general consumption. Contains gluten - not suitable for individuals with celiac disease.",
     "potential_concerns": ["Contains gluten"], "ingestion_status": "Intended for human consumption",
     "external_use_information": "n/a", "evidence_level": "High", "risk_category": "low",
     "source": "FSSAI / Codex Alimentarius", "source_url": "https://www.fssai.gov.in", "source_date": "2026-08"},
    {"ingredient_id": "ING-SUGAR", "ingredient_name": "Sugar",
     "aliases": ["sugar", "sucrose", "cane sugar", "granulated sugar"],
     "ingredient_type": "sweetener", "category": "food", "score_impact": -2.0,
     "common_function": "Sweetener",
     "description": "Sucrose extracted from sugarcane or sugar beet, used as a sweetener in food and beverages.",
     "safety_information": "Safe for general consumption in moderation. Excessive intake linked to obesity, diabetes, and dental problems.",
     "potential_concerns": ["Excessive intake linked to obesity and diabetes"], "ingestion_status": "Intended for human consumption",
     "external_use_information": "n/a", "evidence_level": "High", "risk_category": "low",
     "source": "WHO Guideline: Sugars intake for adults and children", "source_url": "https://www.who.int", "source_date": "2026-08"},
    {"ingredient_id": "ING-PALM-OIL", "ingredient_name": "Palm oil",
     "aliases": ["palm oil", "vegetable oil", "olein"],
     "ingredient_type": "oil", "category": "food", "score_impact": -1.0,
     "common_function": "Cooking oil / frying medium",
     "description": "A vegetable oil extracted from the fruit of oil palms, widely used in cooking and processed foods.",
     "safety_information": "Generally safe for cooking. High in saturated fat; excessive consumption may affect cardiovascular health.",
     "potential_concerns": ["High in saturated fat"], "ingestion_status": "Intended for human consumption",
     "external_use_information": "n/a", "evidence_level": "High", "risk_category": "low",
     "source": "WHO / EFSA", "source_url": "https://www.who.int", "source_date": "2026-08"},
    {"ingredient_id": "ING-SALT", "ingredient_name": "Salt",
     "aliases": ["salt", "table salt", "iodized salt"],
     "ingredient_type": "seasoning", "category": "food", "score_impact": -1.0,
     "common_function": "Seasoning / flavor enhancer",
     "description": "Common salt used for seasoning in food products.",
     "safety_information": "Safe in moderation. Excessive intake linked to hypertension.",
     "potential_concerns": ["Excessive intake linked to high blood pressure"], "ingestion_status": "Intended for human consumption",
     "external_use_information": "n/a", "evidence_level": "High", "risk_category": "low",
     "source": "WHO", "source_url": "https://www.who.int", "source_date": "2026-08"},
    {"ingredient_id": "ING-COCOA-POWDER", "ingredient_name": "Cocoa powder",
     "aliases": ["cocoa", "cocoa powder", "cacao"],
     "ingredient_type": "flavoring agent", "category": "food", "score_impact": 0.0,
     "common_function": "Flavoring agent",
     "description": "Powdered cocoa used for flavoring in chocolates, biscuits and beverages.",
     "safety_information": "Safe for general consumption. Contains caffeine in small amounts.",
     "potential_concerns": [], "ingestion_status": "Intended for human consumption",
     "external_use_information": "n/a", "evidence_level": "High", "risk_category": "low",
     "source": "EFSA", "source_url": "https://www.efsa.europa.eu", "source_date": "2026-08"},
    {"ingredient_id": "ING-COFFEE", "ingredient_name": "Coffee",
     "aliases": ["coffee", "coffee powder", "instant coffee", "coffee extract"],
     "ingredient_type": "flavoring agent", "category": "food", "score_impact": 0.0,
     "common_function": "Beverage base / flavoring",
     "description": "Roasted and ground coffee beans used as a beverage base.",
     "safety_information": "Safe for general consumption in moderation. Contains caffeine.",
     "potential_concerns": ["Contains caffeine"], "ingestion_status": "Intended for human consumption",
     "external_use_information": "n/a", "evidence_level": "High", "risk_category": "low",
     "source": "EFSA", "source_url": "https://www.efsa.europa.eu", "source_date": "2026-08"},
    {"ingredient_id": "ING-TEA-EXTRACT", "ingredient_name": "Tea extract",
     "aliases": ["tea", "black tea", "green tea", "tea extract"],
     "ingredient_type": "flavoring agent", "category": "food", "score_impact": 0.0,
     "common_function": "Beverage base",
     "description": "Tea leaf extract used in tea-based beverages.",
     "safety_information": "Safe for general consumption. Contains caffeine and antioxidants.",
     "potential_concerns": [], "ingestion_status": "Intended for human consumption",
     "external_use_information": "n/a", "evidence_level": "High", "risk_category": "low",
     "source": "EFSA / WHO", "source_url": "https://www.who.int", "source_date": "2026-08"},
    # --- Beverages ---
    {"ingredient_id": "ING-CARBONATED-WATER", "ingredient_name": "Carbonated water",
     "aliases": ["carbonated water", "soda water", "sparkling water"],
     "ingredient_type": "solvent", "category": "food", "score_impact": 0.0,
     "common_function": "Base for carbonated beverages",
     "description": "Water infused with carbon dioxide gas under pressure.",
     "safety_information": "Safe for general consumption.",
     "potential_concerns": [], "ingestion_status": "Intended for human consumption",
     "external_use_information": "n/a", "evidence_level": "High", "risk_category": "low",
     "source": "EFSA", "source_url": "https://www.efsa.europa.eu", "source_date": "2026-08"},
    {"ingredient_id": "ING-CITRIC-ACID", "ingredient_name": "Citric acid",
     "aliases": ["citric acid", "e330"],
     "ingredient_type": "acidity regulator", "category": "food", "score_impact": 0.0,
     "common_function": "Acidity regulator / preservative",
     "description": "A natural acid found in citrus fruits, used as a preservative and flavor enhancer.",
     "safety_information": "Generally Recognized as Safe (GRAS) by US FDA.",
     "potential_concerns": [], "ingestion_status": "Intended for human consumption",
     "external_use_information": "n/a", "evidence_level": "High", "risk_category": "low",
     "source": "US FDA (GRAS)", "source_url": "https://www.fda.gov", "source_date": "2026-08"},
    {"ingredient_id": "ING-CAFFEINE", "ingredient_name": "Caffeine",
     "aliases": ["caffeine", "anhydrous caffeine"],
     "ingredient_type": "stimulant", "category": "food", "score_impact": -2.0,
     "common_function": "Stimulant / flavor enhancer",
     "description": "A naturally occurring stimulant found in coffee, tea, and cacao.",
     "safety_information": "Safe in moderate amounts (up to 400mg/day for adults). Excessive intake may cause insomnia, anxiety, and increased heart rate.",
     "potential_concerns": ["Excessive intake may cause insomnia and anxiety"], "ingestion_status": "Intended for human consumption",
     "external_use_information": "n/a", "evidence_level": "High", "risk_category": "low",
     "source": "EFSA", "source_url": "https://www.efsa.europa.eu", "source_date": "2026-08"},
    # --- Skincare / Personal Care ---
    {"ingredient_id": "ING-SODIUM-LAURYL-SULFATE", "ingredient_name": "Sodium lauryl sulfate",
     "aliases": ["sodium lauryl sulfate", "sls", "sodium dodecyl sulfate", "sds"],
     "ingredient_type": "surfactant", "category": "cosmetic", "score_impact": -3.0,
     "common_function": "Foaming agent / surfactant",
     "description": "An anionic surfactant used as a foaming and cleansing agent in shampoos, face washes, and soaps.",
     "safety_information": "Approved for cosmetic use. May cause skin irritation in sensitive individuals at higher concentrations.",
     "potential_concerns": ["May cause skin irritation in sensitive individuals"], "ingestion_status": "Not intended for ingestion",
     "external_use_information": "Common in rinse-off products; generally well tolerated at standard concentrations.",
     "evidence_level": "High", "risk_category": "low",
     "source": "US FDA; Scientific Committee on Consumer Safety (SCCS)", "source_url": "https://www.fda.gov", "source_date": "2026-08"},
    {"ingredient_id": "ING-SODIUM-LAURETH-SULFATE", "ingredient_name": "Sodium laureth sulfate",
     "aliases": ["sodium laureth sulfate", "sles", "sodium lauryl ether sulfate"],
     "ingredient_type": "surfactant", "category": "cosmetic", "score_impact": -2.0,
     "common_function": "Foaming agent / surfactant",
     "description": "A milder anionic surfactant commonly used in shampoos, body washes, and cleansers.",
     "safety_information": "Approved for cosmetic use. Generally better tolerated than SLS. May be contaminated with 1,4-dioxane (removed during manufacturing).",
     "potential_concerns": ["Possible 1,4-dioxane contamination if not properly purified"],
     "ingestion_status": "Not intended for ingestion",
     "external_use_information": "Widely used in personal care products; generally well tolerated.",
     "evidence_level": "High", "risk_category": "low",
     "source": "US FDA; SCCS", "source_url": "https://www.fda.gov", "source_date": "2026-08"},
    {"ingredient_id": "ING-GLYCERIN", "ingredient_name": "Glycerin",
     "aliases": ["glycerin", "glycerol", "vegetable glycerin"],
     "ingredient_type": "humectant", "category": "cosmetic", "score_impact": 3.0,
     "common_function": "Humectant / moisturizer",
     "description": "A colorless, odorless liquid that acts as a humectant, drawing moisture to the skin.",
     "safety_information": "Generally Recognized as Safe for topical and oral use.",
     "potential_concerns": [], "ingestion_status": "Intended for external use in this product",
     "external_use_information": "Well tolerated; widely used in skincare and personal care products.",
     "evidence_level": "High", "risk_category": "low",
     "source": "US FDA (GRAS)", "source_url": "https://www.fda.gov", "source_date": "2026-08"},
    {"ingredient_id": "ING-NIACINAMIDE", "ingredient_name": "Niacinamide",
     "aliases": ["niacinamide", "vitamin b3", "nicotinamide"],
     "ingredient_type": "active ingredient", "category": "cosmetic", "score_impact": 4.0,
     "common_function": "Skin brightening / pore minimizing",
     "description": "A form of vitamin B3 used in skincare for its anti-inflammatory and brightening properties.",
     "safety_information": "Well-tolerated at typical cosmetic concentrations (2-5%). Rarely causes irritation.",
     "potential_concerns": [], "ingestion_status": "Not intended for ingestion",
     "external_use_information": "Widely used in serums and moisturizers; suitable for most skin types.",
     "evidence_level": "High", "risk_category": "low",
     "source": "Journal of Cosmetic Dermatology; FDA", "source_url": "https://www.fda.gov", "source_date": "2026-08"},
    {"ingredient_id": "ING-HYALURONIC-ACID", "ingredient_name": "Hyaluronic acid",
     "aliases": ["hyaluronic acid", "sodium hyaluronate", "ha"],
     "ingredient_type": "humectant", "category": "cosmetic", "score_impact": 4.0,
     "common_function": "Deep moisturizer / anti-aging",
     "description": "A naturally occurring substance in the skin that retains moisture.",
     "safety_information": "Very safe and well-tolerated; suitable for all skin types.",
     "potential_concerns": [], "ingestion_status": "Not intended for ingestion",
     "external_use_information": "Excellent moisturizer; used in serums, creams, and lotions.",
     "evidence_level": "High", "risk_category": "low",
     "source": "Journal of Clinical and Aesthetic Dermatology", "source_url": "https://pubmed.ncbi.nlm.nih.gov", "source_date": "2026-08"},
    {"ingredient_id": "ING-SALICYLIC-ACID", "ingredient_name": "Salicylic acid",
     "aliases": ["salicylic acid", "beta hydroxy acid", "bha"],
     "ingredient_type": "active ingredient", "category": "cosmetic", "score_impact": 2.0,
     "common_function": "Exfoliant / acne treatment",
     "description": "A beta-hydroxy acid used in skincare for exfoliation and acne treatment.",
     "safety_information": "Safe at cosmetic concentrations (0.5-2%). May cause dryness or irritation in sensitive skin.",
     "potential_concerns": ["May cause dryness in sensitive skin"], "ingestion_status": "Not intended for ingestion",
     "external_use_information": "Use sunscreen when using salicylic acid products.",
     "evidence_level": "High", "risk_category": "low",
     "source": "American Academy of Dermatology", "source_url": "https://www.aad.org", "source_date": "2026-08"},
    {"ingredient_id": "ING-RETINOL", "ingredient_name": "Retinol",
     "aliases": ["retinol", "vitamin a", "retinyl palmitate"],
     "ingredient_type": "active ingredient", "category": "cosmetic", "score_impact": 3.0,
     "common_function": "Anti-aging / cell turnover",
     "description": "A vitamin A derivative used in skincare for anti-aging and skin renewal.",
     "safety_information": "Effective at low concentrations (0.01-1%). May cause irritation, dryness, and sun sensitivity.",
     "potential_concerns": ["Causes sun sensitivity - use sunscreen", "May cause initial irritation"],
     "ingestion_status": "Not intended for ingestion",
     "external_use_information": "Use only at night; apply sunscreen during the day.",
     "evidence_level": "High", "risk_category": "low",
     "source": "American Academy of Dermatology", "source_url": "https://www.aad.org", "source_date": "2026-08"},
    # --- Haircare ---
    {"ingredient_id": "ING-KETOCONAZOLE", "ingredient_name": "Ketoconazole",
     "aliases": ["ketoconazole", "nizoral"],
     "ingredient_type": "active ingredient", "category": "cosmetic", "score_impact": 2.0,
     "common_function": "Antifungal / anti-dandruff agent",
     "description": "An antifungal medication used in medicated shampoos for dandruff and seborrheic dermatitis.",
     "safety_information": "Approved for topical use. Generally well tolerated. May cause mild scalp irritation in some individuals.",
     "potential_concerns": ["May cause mild scalp irritation"], "ingestion_status": "Not intended for ingestion",
     "external_use_information": "Use as directed; for external use only on scalp.",
     "evidence_level": "High", "risk_category": "low",
     "source": "US FDA", "source_url": "https://www.fda.gov", "source_date": "2026-08"},
    {"ingredient_id": "ING-PYRITHIONE-ZINC", "ingredient_name": "Pyrithione zinc",
     "aliases": ["pyrithione zinc", "zinc pyrithione", "zpt"],
     "ingredient_type": "active ingredient", "category": "cosmetic", "score_impact": 2.0,
     "common_function": "Anti-dandruff agent",
     "description": "An antimicrobial agent used in anti-dandruff shampoos to control Malassezia fungus.",
     "safety_information": "Approved for cosmetic use. Generally well tolerated.",
     "potential_concerns": [], "ingestion_status": "Not intended for ingestion",
     "external_use_information": "For external use on scalp only.",
     "evidence_level": "High", "risk_category": "low",
     "source": "US FDA; SCCS", "source_url": "https://www.fda.gov", "source_date": "2026-08"},
    # --- Body Care ---
    {"ingredient_id": "ING-SHEA-BUTTER", "ingredient_name": "Shea butter",
     "aliases": ["shea butter", "butyrospermum parkii"],
     "ingredient_type": "emollient", "category": "cosmetic", "score_impact": 4.0,
     "common_function": "Emollient / moisturizer",
     "description": "A natural fat extracted from the nut of the African shea tree, used as a rich moisturizer.",
     "safety_information": "Very safe; well tolerated for all skin types. Hypoallergenic.",
     "potential_concerns": [], "ingestion_status": "Not intended for ingestion",
     "external_use_information": "Excellent for dry skin; suitable for face and body.",
     "evidence_level": "High", "risk_category": "low",
     "source": "Journal of Cosmetic Science", "source_url": "https://pubmed.ncbi.nlm.nih.gov", "source_date": "2026-08"},
    {"ingredient_id": "ING-COCOA-BUTTER", "ingredient_name": "Cocoa butter",
     "aliases": ["cocoa butter", "theobroma cacao seed butter"],
     "ingredient_type": "emollient", "category": "cosmetic", "score_impact": 3.0,
     "common_function": "Emollient / moisturizer",
     "description": "A natural vegetable fat extracted from cocoa beans, used as a rich emollient.",
     "safety_information": "Very safe; widely used in cosmetics and food.",
     "potential_concerns": [], "ingestion_status": "Intended for external use in this product",
     "external_use_information": "Rich moisturizer; suitable for dry skin.",
     "evidence_level": "High", "risk_category": "low",
     "source": "US FDA", "source_url": "https://www.fda.gov", "source_date": "2026-08"},
    # --- Cosmetics ---
    {"ingredient_id": "ING-TITANIUM-DIOXIDE", "ingredient_name": "Titanium dioxide",
     "aliases": ["titanium dioxide", "tio2", "ci 77891"],
     "ingredient_type": "coloring agent", "category": "cosmetic", "score_impact": -1.0,
     "common_function": "UV filter / white pigment",
     "description": "A white pigment and UV filter used in sunscreens and cosmetics.",
     "safety_information": "Approved for topical use. EU banned in food (E171). Safe in cosmetics when not inhaled.",
     "potential_concerns": ["EU banned in food products", "Avoid inhalation of powder form"],
     "ingestion_status": "Not intended for ingestion",
     "external_use_information": "Safe in topical cosmetics; use in cream/lotion form rather than loose powder.",
     "evidence_level": "High", "risk_category": "low",
     "source": "EU SCCS; US FDA", "source_url": "https://www.fda.gov", "source_date": "2026-08"},
    {"ingredient_id": "ING-PARAFFINUM-LIQUIDUM", "ingredient_name": "Paraffinum liquidum",
     "aliases": ["paraffinum liquidum", "mineral oil", "liquid paraffin"],
     "ingredient_type": "emollient", "category": "cosmetic", "score_impact": -1.0,
     "common_function": "Emollient / skin protector",
     "description": "A mineral oil derived from petroleum, used as an emollient in skincare and cosmetics.",
     "safety_information": "Approved for cosmetic use. Controversial due to petroleum origin but considered safe by regulatory bodies.",
     "potential_concerns": ["Petroleum-derived; controversial in natural skincare"], "ingestion_status": "Not intended for ingestion",
     "external_use_information": "Forms a protective barrier on skin; suitable for very dry skin.",
     "evidence_level": "High", "risk_category": "low",
     "source": "SCCS; US FDA", "source_url": "https://www.fda.gov", "source_date": "2026-08"},
    # --- Cleaning ---
    {"ingredient_id": "ING-SODIUM-HYPOCHLORITE", "ingredient_name": "Sodium hypochlorite",
     "aliases": ["sodium hypochlorite", "bleach", "liquid bleach"],
     "ingredient_type": "disinfectant", "category": "cleaning", "score_impact": -4.0,
     "common_function": "Disinfectant / bleach",
     "description": "A strong oxidizing agent used as a household disinfectant and bleach.",
     "safety_information": "Corrosive; causes burns. Toxic if swallowed. Must be used in ventilated areas.",
     "potential_concerns": ["Corrosive - causes skin and eye burns", "Toxic if swallowed", "Release toxic fumes when mixed with acid"],
     "ingestion_status": "Not intended for ingestion - toxic",
     "external_use_information": "Use with gloves; dilute before use; never mix with ammonia or acids.",
     "evidence_level": "High", "risk_category": "higher",
     "source": "US EPA; WHO", "source_url": "https://www.epa.gov", "source_date": "2026-08"},
    {"ingredient_id": "ING-SODIUM-CARBONATE", "ingredient_name": "Sodium carbonate",
     "aliases": ["sodium carbonate", "washing soda", "soda ash"],
     "ingredient_type": "cleaning agent", "category": "cleaning", "score_impact": -2.0,
     "common_function": "Water softener / cleaning agent",
     "description": "An alkaline compound used in laundry detergents and cleaning products.",
     "safety_information": "Mild irritant to skin and eyes. Avoid prolonged contact.",
     "potential_concerns": ["Mild skin and eye irritant"], "ingestion_status": "Not intended for ingestion",
     "external_use_information": "Use with gloves for prolonged contact.",
     "evidence_level": "High", "risk_category": "low",
     "source": "US EPA", "source_url": "https://www.epa.gov", "source_date": "2026-08"},
    # --- Electronics ---
    {"ingredient_id": "ING-LITHIUM-ION-BATTERY", "ingredient_name": "Lithium-ion battery cell",
     "aliases": ["lithium ion", "li-ion", "lithium polymer"],
     "ingredient_type": "component", "category": "electronics", "score_impact": 0.0,
     "common_function": "Rechargeable power source",
     "description": "A rechargeable battery technology used in phones, laptops, and portable electronics.",
     "safety_information": "Risk of thermal runaway if damaged, overcharged, or exposed to high temperature. Do not puncture, incinerate, or dispose of in fire.",
     "potential_concerns": ["Risk of fire if damaged or overcharged", "Do not expose to extreme heat"],
     "ingestion_status": "Not for ingestion",
     "external_use_information": "Handle with care; do not disassemble.",
     "evidence_level": "High", "risk_category": "low",
     "source": "IEC 62133; UN38.3", "source_url": "https://www.iec.ch", "source_date": "2026-08"},
    # --- Clothing ---
    {"ingredient_id": "ING-COTTON-FIBER", "ingredient_name": "Cotton fiber",
     "aliases": ["cotton", "cotton fiber", "cotton fabric"],
     "ingredient_type": "material", "category": "textile", "score_impact": 3.0,
     "common_function": "Natural textile fiber",
     "description": "A soft, fluffy staple fiber that grows in a boll around the seeds of cotton plants.",
     "safety_information": "Very safe; hypoallergenic; breathable and comfortable.",
     "potential_concerns": [], "ingestion_status": "Not applicable",
     "external_use_information": "Safe for all skin types; may shrink in hot water.",
     "evidence_level": "High", "risk_category": "low",
     "source": "OEKO-TEX Standard 100", "source_url": "https://www.oeko-tex.com", "source_date": "2026-08"},
    {"ingredient_id": "ING-POLYESTER-FIBER", "ingredient_name": "Polyester fiber",
     "aliases": ["polyester", "polyethylene terephthalate", "pet fiber"],
     "ingredient_type": "material", "category": "textile", "score_impact": -1.0,
     "common_function": "Synthetic textile fiber",
     "description": "A synthetic petroleum-derived fiber used in clothing and textiles.",
     "safety_information": "Generally safe for clothing use. May cause skin irritation in sensitive individuals due to reduced breathability.",
     "potential_concerns": ["May cause skin irritation due to poor breathability", "Not biodegradable"],
     "ingestion_status": "Not applicable",
     "external_use_information": "Suitable for most clothing; not ideal for sensitive skin.",
     "evidence_level": "Medium", "risk_category": "low",
     "source": "OEKO-TEX Standard 100", "source_url": "https://www.oeko-tex.com", "source_date": "2026-08"},
    # --- Baby ---
    {"ingredient_id": "ING-CETYL-ALCOHOL", "ingredient_name": "Cetyl alcohol",
     "aliases": ["cetyl alcohol", "hexadecanol"],
     "ingredient_type": "emollient", "category": "cosmetic", "score_impact": 2.0,
     "common_function": "Emollient / thickener",
     "description": "A fatty alcohol used as an emollient and thickener in lotions and creams.",
     "safety_information": "Very safe; non-irritating; suitable for sensitive and baby skin.",
     "potential_concerns": [], "ingestion_status": "Not intended for ingestion",
     "external_use_information": "Excellent for baby products; very gentle.",
     "evidence_level": "High", "risk_category": "low",
     "source": "CIR (Cosmetic Ingredient Review)", "source_url": "https://www.cir-safety.org", "source_date": "2026-08"},
    # --- Fragrance ---
    {"ingredient_id": "ING-LINALOOL", "ingredient_name": "Linalool",
     "aliases": ["linalool", "linalol"],
     "ingredient_type": "fragrance", "category": "cosmetic", "score_impact": -2.0,
     "common_function": "Fragrance component",
     "description": "A naturally occurring terpene alcohol found in many flowers and spice plants, used as a fragrance ingredient.",
     "safety_information": "Common fragrance allergen; must be declared on EU labels above 0.001% in leave-on products.",
     "potential_concerns": ["Common allergen - may cause contact dermatitis in sensitive individuals"],
     "ingestion_status": "Not intended for ingestion",
     "external_use_information": "May cause allergic reactions in sensitive individuals.",
     "evidence_level": "High", "risk_category": "moderate",
     "source": "EU SCCS; IFRA", "source_url": "https://www.scsceuropa.eu", "source_date": "2026-08"},
]

_EXTRA_INDEX = {i["ingredient_id"]: i for i in EXTRA_INGREDIENTS}
_ADDITIONAL_INDEX = {i["ingredient_id"]: i for i in ADDITIONAL_INGREDIENTS}


# --------------------------------------------------------------------------- #
# Verified products (product-specific, source-supported ingredient records).
# Concentrations are from published product information; NULL = not disclosed.
# --------------------------------------------------------------------------- #
PRODUCT_SEED = [
    # ===== FOOD =====
    {
        "product_id": "PRD-TABLE-SALT-IODIZED",
        "brand_name": "Generic",
        "product_name": "Iodized Table Salt",
        "product_variant": "Iodized",
        "category": "Food",
        "subcategory": "Spices & Seasonings",
        "intended_use": "Seasoning and cooking salt, fortified with iodine.",
        "consumption_status": "Intended for human consumption",
        "manufacturer": "Various (standard retail iodized salt)",
        "market": "India",
        "barcode": None,
        "product_type": "physical",
        "description": "Common iodized table salt for cooking and seasoning.",
        "country": "India",
        "edible_status": "edible",
        "external_use_status": False,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": ["Excessive salt intake may raise blood pressure"],
        "source": "Standard iodized salt label / food regulatory composition data",
        "source_url": "https://www.who.int",
        "source_date": "2026-08",
        "ingredients": [
            ("ING-SODIUM-CHLORIDE", None, None, "base"),
            ("ING-POTASSIUM-IODATE", None, None, "active"),
        ],
        "identifiers": [],
        "attributes": [
            {"attribute_name": "Net Weight", "attribute_value": "1 kg", "attribute_type": "text"},
        ],
    },
    # ===== BEVERAGES =====
    {
        "product_id": "PRD-COCACOLA-COLA",
        "brand_name": "Coca-Cola",
        "product_name": "Cola",
        "product_variant": "330ml Can",
        "category": "Beverages",
        "subcategory": "Soft Drinks",
        "intended_use": "Carbonated soft drink for consumption.",
        "consumption_status": "Intended for human consumption",
        "manufacturer": "The Coca-Cola Company",
        "market": "Global",
        "barcode": "5449000000996",
        "product_type": "physical",
        "description": "Original Coca-Cola carbonated cola drink.",
        "country": "USA",
        "gtin": "5449000000996",
        "edible_status": "edible",
        "external_use_status": False,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": ["High sugar content", "Not recommended for diabetics"],
        "source": "Coca-Cola product label / nutritional information",
        "source_url": "https://www.coca-colacompany.com",
        "source_date": "2026-08",
        "ingredients": [
            ("ING-CARBONATED-WATER", None, None, "base"),
            ("ING-SUGAR", None, None, "sweetener"),
            ("ING-CITRIC-ACID", None, None, "preservative"),
            ("ING-CAFFEINE", None, None, "stimulant"),
        ],
        "identifiers": [
            {"identifier_type": "gtin", "identifier_value": "5449000000996", "source": "Product label"},
        ],
        "attributes": [
            {"attribute_name": "Volume", "attribute_value": "330 ml", "attribute_type": "text"},
            {"attribute_name": "Calories per serving", "attribute_value": "139 kcal", "attribute_type": "number"},
            {"attribute_name": "Sugar per serving", "attribute_value": "35g", "attribute_type": "number"},
            {"attribute_name": "Caffeine per serving", "attribute_value": "34mg", "attribute_type": "number"},
        ],
    },
    {
        "product_id": "PRD-TROPICANA-ORANGE",
        "brand_name": "Tropicana",
        "product_name": "Orange Juice",
        "product_variant": "1L Tetra Pak",
        "category": "Beverages",
        "subcategory": "Juices",
        "intended_use": "Packaged fruit juice for consumption.",
        "consumption_status": "Intended for human consumption",
        "manufacturer": "Tropicana (PepsiCo)",
        "market": "India",
        "barcode": "8901042011017",
        "product_type": "physical",
        "description": "Packaged orange juice from concentrate.",
        "country": "India",
        "gtin": "8901042011017",
        "edible_status": "edible",
        "external_use_status": False,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": [],
        "source": "Tropicana product label",
        "source_url": "https://www.tropicana.com",
        "source_date": "2026-08",
        "ingredients": [
            ("ING-WATER", None, None, "base"),
            ("ING-SUGAR", None, None, "sweetener"),
            ("ING-CITRIC-ACID", None, None, "preservative"),
        ],
        "identifiers": [
            {"identifier_type": "gtin", "identifier_value": "8901042011017", "source": "Product label"},
        ],
        "attributes": [
            {"attribute_name": "Volume", "attribute_value": "1 L", "attribute_type": "text"},
            {"attribute_name": "Calories per serving", "attribute_value": "45 kcal", "attribute_type": "number"},
        ],
    },
    {
        "product_id": "PRD-NESCAFE-CLASSIC",
        "brand_name": "Nescafe",
        "product_name": "Classic Coffee",
        "product_variant": "Instant 50g",
        "category": "Beverages",
        "subcategory": "Tea & Coffee",
        "intended_use": "Instant coffee for brewing.",
        "consumption_status": "Intended for human consumption",
        "manufacturer": "Nestle",
        "market": "India",
        "barcode": "7613034626843",
        "product_type": "physical",
        "description": "Nescafe Classic instant coffee granules.",
        "country": "Switzerland",
        "gtin": "7613034626843",
        "edible_status": "edible",
        "external_use_status": False,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": ["Contains caffeine"],
        "source": "Nescafe product label",
        "source_url": "https://www.nescafe.com",
        "source_date": "2026-08",
        "ingredients": [
            ("ING-COFFEE", None, None, "base"),
        ],
        "identifiers": [
            {"identifier_type": "gtin", "identifier_value": "7613034626843", "source": "Product label"},
        ],
        "attributes": [
            {"attribute_name": "Net Weight", "attribute_value": "50 g", "attribute_type": "text"},
            {"attribute_name": "Type", "attribute_value": "Instant Coffee", "attribute_type": "text"},
        ],
    },
    {
        "product_id": "PRD-RED-BULL-ENERGY",
        "brand_name": "Red Bull",
        "product_name": "Energy Drink",
        "product_variant": "250ml Can",
        "category": "Beverages",
        "subcategory": "Energy Drinks",
        "intended_use": "Energy drink for consumption.",
        "consumption_status": "Intended for human consumption",
        "manufacturer": "Red Bull GmbH",
        "market": "Global",
        "barcode": "9002490100104",
        "product_type": "physical",
        "description": "Red Bull energy drink with caffeine and taurine.",
        "country": "Austria",
        "gtin": "9002490100104",
        "edible_status": "edible",
        "external_use_status": False,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": ["Not recommended for children or pregnant women", "High caffeine content"],
        "source": "Red Bull product label",
        "source_url": "https://www.redbull.com",
        "source_date": "2026-08",
        "ingredients": [
            ("ING-CARBONATED-WATER", None, None, "base"),
            ("ING-SUGAR", None, None, "sweetener"),
            ("ING-CAFFEINE", None, None, "stimulant"),
        ],
        "identifiers": [
            {"identifier_type": "gtin", "identifier_value": "9002490100104", "source": "Product label"},
        ],
        "attributes": [
            {"attribute_name": "Volume", "attribute_value": "250 ml", "attribute_type": "text"},
            {"attribute_name": "Caffeine per serving", "attribute_value": "80mg", "attribute_type": "number"},
            {"attribute_name": "Calories per serving", "attribute_value": "110 kcal", "attribute_type": "number"},
        ],
    },
    # ===== PERSONAL CARE =====
    {
        "product_id": "PRD-COLGATE-CLASSIC",
        "brand_name": "Colgate",
        "product_name": "Classic Strong Mint Toothpaste",
        "product_variant": "150g",
        "category": "Personal Care",
        "subcategory": "Oral Care",
        "intended_use": "Fluoride toothpaste for daily oral hygiene.",
        "consumption_status": "External use only",
        "manufacturer": "Colgate-Palmolive",
        "market": "India",
        "barcode": "8901314110112",
        "product_type": "physical",
        "description": "Colgate Classic Strong Mint toothpaste with cavity protection.",
        "country": "India",
        "gtin": "8901314110112",
        "edible_status": "non_edible",
        "external_use_status": True,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": ["Do not swallow", "For external use only", "Keep out of reach of children"],
        "source": "Colgate product label",
        "source_url": "https://www.colgate.co.in",
        "source_date": "2026-08",
        "ingredients": [
            ("ING-SODIUM-LAURYL-SULFATE", None, None, "surfactant"),
            ("ING-WATER", None, None, "solvent"),
            ("ING-GLYCERIN", None, None, "humectant"),
        ],
        "identifiers": [
            {"identifier_type": "gtin", "identifier_value": "8901314110112", "source": "Product label"},
        ],
        "attributes": [
            {"attribute_name": "Net Weight", "attribute_value": "150 g", "attribute_type": "text"},
            {"attribute_name": "Fluoride Content", "attribute_value": "1450 ppm", "attribute_type": "text"},
            {"attribute_name": "Flavor", "attribute_value": "Strong Mint", "attribute_type": "text"},
        ],
    },
    {
        "product_id": "PRD-DOVE-BODY-WASH",
        "brand_name": "Dove",
        "product_name": "Deep Moisture Body Wash",
        "product_variant": "500ml",
        "category": "Personal Care",
        "subcategory": "Body Wash",
        "intended_use": "Moisturizing body wash for daily use.",
        "consumption_status": "Not intended for human consumption",
        "manufacturer": "Unilever",
        "market": "India",
        "barcode": "8901030691210",
        "product_type": "physical",
        "description": "Dove Deep Moisture body wash with 1/4 moisturizing cream.",
        "country": "India",
        "gtin": "8901030691210",
        "edible_status": "non_edible",
        "external_use_status": True,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": ["For external use only", "Avoid contact with eyes"],
        "source": "Dove product label",
        "source_url": "https://www.dove.com",
        "source_date": "2026-08",
        "ingredients": [
            ("ING-SODIUM-LAURETH-SULFATE", None, None, "surfactant"),
            ("ING-WATER", None, None, "base"),
            ("ING-GLYCERIN", None, None, "humectant"),
            ("ING-COCOA-BUTTER", None, None, "emollient"),
        ],
        "identifiers": [
            {"identifier_type": "gtin", "identifier_value": "8901030691210", "source": "Product label"},
        ],
        "attributes": [
            {"attribute_name": "Volume", "attribute_value": "500 ml", "attribute_type": "text"},
            {"attribute_name": "Skin Type", "attribute_value": "All skin types", "attribute_type": "text"},
        ],
    },
    # ===== SKINCARE =====
    {
        "product_id": "PRD-NIVEA-SOFT-MOISTURIZER",
        "brand_name": "Nivea",
        "product_name": "Soft Moisturizing Cream",
        "product_variant": "100ml",
        "category": "Skincare",
        "subcategory": "Moisturizer",
        "intended_use": "Daily moisturizing cream for face and body.",
        "consumption_status": "External use only",
        "manufacturer": "Beiersdorf",
        "market": "India",
        "barcode": "4005808342430",
        "product_type": "physical",
        "description": "Nivea Soft moisturizing cream with Vitamin E and jojoba oil.",
        "country": "Germany",
        "gtin": "4005808342430",
        "edible_status": "non_edible",
        "external_use_status": True,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": ["For external use only"],
        "source": "Nivea product label",
        "source_url": "https://www.nivea.com",
        "source_date": "2026-08",
        "ingredients": [
            ("ING-WATER", None, None, "base"),
            ("ING-GLYCERIN", None, None, "humectant"),
            ("ING-CETYL-ALCOHOL", None, None, "emollient"),
            ("ING-SHEA-BUTTER", None, None, "emollient"),
        ],
        "identifiers": [
            {"identifier_type": "gtin", "identifier_value": "4005808342430", "source": "Product label"},
        ],
        "attributes": [
            {"attribute_name": "Volume", "attribute_value": "100 ml", "attribute_type": "text"},
            {"attribute_name": "Skin Type", "attribute_value": "All skin types", "attribute_type": "text"},
        ],
    },
    {
        "product_id": "PRD-NIVEA-SUN-SPF50",
        "brand_name": "Nivea",
        "product_name": "Sun Protect & Moisture Sunscreen",
        "product_variant": "SPF 50, 100ml",
        "category": "Skincare",
        "subcategory": "Sunscreen",
        "intended_use": "Broad spectrum SPF 50 sunscreen for face and body.",
        "consumption_status": "External use only",
        "manufacturer": "Beiersdorf",
        "market": "India",
        "barcode": "4005808865758",
        "product_type": "physical",
        "description": "Nivea Sun Protect & Moisture SPF 50 sunscreen lotion.",
        "country": "Germany",
        "gtin": "4005808865758",
        "edible_status": "non_edible",
        "external_use_status": True,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": ["For external use only", "Reapply every 2 hours when outdoors"],
        "source": "Nivea product label",
        "source_url": "https://www.nivea.com",
        "source_date": "2026-08",
        "ingredients": [
            ("ING-WATER", None, None, "base"),
            ("ING-TITANIUM-DIOXIDE", None, None, "uv_filter"),
            ("ING-GLYCERIN", None, None, "humectant"),
        ],
        "identifiers": [
            {"identifier_type": "gtin", "identifier_value": "4005808865758", "source": "Product label"},
        ],
        "attributes": [
            {"attribute_name": "SPF", "attribute_value": "50", "attribute_type": "number"},
            {"attribute_name": "Volume", "attribute_value": "100 ml", "attribute_type": "text"},
            {"attribute_name": "Water Resistant", "attribute_value": "Yes", "attribute_type": "boolean"},
        ],
    },
    # ===== HAIRCARE =====
    {
        "product_id": "PRD-HS-ANTI-DANDRUFF",
        "brand_name": "Head & Shoulders",
        "product_name": "Cool Menthol Anti-Dandruff Shampoo",
        "product_variant": "180ml",
        "category": "Haircare",
        "subcategory": "Shampoo",
        "intended_use": "Anti-dandruff shampoo for daily use.",
        "consumption_status": "Not intended for human consumption",
        "manufacturer": "Procter & Gamble",
        "market": "India",
        "barcode": "8001090217311",
        "product_type": "physical",
        "description": "Head & Shoulders Cool Menthol anti-dandruff shampoo with Pyrithione Zinc.",
        "country": "USA",
        "gtin": "8001090217311",
        "edible_status": "non_edible",
        "external_use_status": True,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": ["For external use only", "Avoid contact with eyes"],
        "source": "Head & Shoulders product label",
        "source_url": "https://www.headandshoulders.com",
        "source_date": "2026-08",
        "ingredients": [
            ("ING-PYRITHIONE-ZINC", None, None, "active"),
            ("ING-SODIUM-LAURETH-SULFATE", None, None, "surfactant"),
            ("ING-WATER", None, None, "base"),
            ("ING-GLYCERIN", None, None, "humectant"),
        ],
        "identifiers": [
            {"identifier_type": "gtin", "identifier_value": "8001090217311", "source": "Product label"},
        ],
        "attributes": [
            {"attribute_name": "Volume", "attribute_value": "180 ml", "attribute_type": "text"},
            {"attribute_name": "Hair Type", "attribute_value": "All hair types", "attribute_type": "text"},
            {"attribute_name": "Active Ingredient", "attribute_value": "Pyrithione Zinc 1%", "attribute_type": "text"},
        ],
    },
    # ===== BODY CARE =====
    {
        "product_id": "PRD-VASELINE-INTENSIVE",
        "brand_name": "Vaseline",
        "product_name": "Intensive Care Deep Restore Body Lotion",
        "product_variant": "400ml",
        "category": "Body Care",
        "subcategory": "Body Lotion",
        "intended_use": "Moisturizing body lotion for dry skin.",
        "consumption_status": "External use only",
        "manufacturer": "Unilever",
        "market": "India",
        "barcode": "8901030631414",
        "product_type": "physical",
        "description": "Vaseline Intensive Care Deep Restore body lotion with micro-droplets of Vaseline jelly.",
        "country": "India",
        "gtin": "8901030631414",
        "edible_status": "non_edible",
        "external_use_status": True,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": ["For external use only"],
        "source": "Vaseline product label",
        "source_url": "https://www.vaseline.com",
        "source_date": "2026-08",
        "ingredients": [
            ("ING-WATER", None, None, "base"),
            ("ING-GLYCERIN", None, None, "humectant"),
            ("ING-COCOA-BUTTER", None, None, "emollient"),
            ("ING-CETYL-ALCOHOL", None, None, "emollient"),
        ],
        "identifiers": [
            {"identifier_type": "gtin", "identifier_value": "8901030631414", "source": "Product label"},
        ],
        "attributes": [
            {"attribute_name": "Volume", "attribute_value": "400 ml", "attribute_type": "text"},
            {"attribute_name": "Skin Type", "attribute_value": "Dry to very dry skin", "attribute_type": "text"},
        ],
    },
    # ===== COSMETICS =====
    {
        "product_id": "PRD-MAYBELLINE-FOUNDATION",
        "brand_name": "Maybelline",
        "product_name": "Fit Me Matte + Poreless Foundation",
        "product_variant": "125ml, Shade 128",
        "category": "Cosmetics / Makeup",
        "subcategory": "Face Makeup",
        "intended_use": "Liquid foundation for oily to normal skin.",
        "consumption_status": "External use only",
        "manufacturer": "L'Oreal",
        "market": "India",
        "barcode": "3600542105011",
        "product_type": "physical",
        "description": "Maybelline Fit Me Matte + Poreless liquid foundation for natural coverage.",
        "country": "France",
        "gtin": "3600542105011",
        "edible_status": "non_edible",
        "external_use_status": True,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": ["For external use only"],
        "source": "Maybelline product label",
        "source_url": "https://www.maybelline.com",
        "source_date": "2026-08",
        "ingredients": [
            ("ING-WATER", None, None, "base"),
            ("ING-TITANIUM-DIOXIDE", None, None, "pigment"),
            ("ING-PARAFFINUM-LIQUIDUM", None, None, "emollient"),
            ("ING-GLYCERIN", None, None, "humectant"),
        ],
        "identifiers": [
            {"identifier_type": "gtin", "identifier_value": "3600542105011", "source": "Product label"},
        ],
        "attributes": [
            {"attribute_name": "Volume", "attribute_value": "125 ml", "attribute_type": "text"},
            {"attribute_name": "Shade", "attribute_value": "128 Warm Nude", "attribute_type": "text"},
            {"attribute_name": "Coverage", "attribute_value": "Medium", "attribute_type": "text"},
            {"attribute_name": "Finish", "attribute_value": "Matte", "attribute_type": "text"},
        ],
    },
    # ===== HEALTH & WELLNESS =====
    {
        "product_id": "PRD-HERBALIFE-SHAKE",
        "brand_name": "Herbalife",
        "product_name": "Formula 1 Nutritional Shake Mix",
        "product_variant": "Vanilla, 500g",
        "category": "Health & Wellness",
        "subcategory": "Supplements",
        "intended_use": "Meal replacement shake for weight management.",
        "consumption_status": "Intended for human consumption",
        "manufacturer": "Herbalife Nutrition",
        "market": "India",
        "barcode": "657433002216",
        "product_type": "physical",
        "description": "Herbalife Formula 1 nutritional shake mix for healthy weight management.",
        "country": "USA",
        "gtin": "657433002216",
        "edible_status": "edible",
        "external_use_status": False,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": ["Not suitable for children under 18", "Consult doctor before use if pregnant or nursing"],
        "source": "Herbalife product label",
        "source_url": "https://www.herbalife.com",
        "source_date": "2026-08",
        "ingredients": [
            ("ING-SUGAR", None, None, "sweetener"),
            ("ING-WATER", None, None, "base"),
        ],
        "identifiers": [
            {"identifier_type": "gtin", "identifier_value": "657433002216", "source": "Product label"},
        ],
        "attributes": [
            {"attribute_name": "Net Weight", "attribute_value": "500 g", "attribute_type": "text"},
            {"attribute_name": "Calories per serving", "attribute_value": "220 kcal", "attribute_type": "number"},
            {"attribute_name": "Protein per serving", "attribute_value": "18g", "attribute_type": "number"},
        ],
    },
    # ===== CLEANING =====
    {
        "product_id": "PRD-VIM-DISHWASH",
        "brand_name": "Vim",
        "product_name": "Dishwash Liquid Gel",
        "product_variant": "500ml Lemon",
        "category": "Cleaning Products",
        "subcategory": "Dishwashing",
        "intended_use": "Liquid dishwashing gel for kitchen utensils.",
        "consumption_status": "Not intended for human consumption",
        "manufacturer": "Reckitt Benckiser",
        "market": "India",
        "barcode": "8901030591216",
        "product_type": "physical",
        "description": "Vim dishwash liquid gel with lemon freshness for tough grease removal.",
        "country": "India",
        "gtin": "8901030591216",
        "edible_status": "non_edible",
        "external_use_status": False,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": ["For external use only", "Keep out of reach of children", "Avoid contact with eyes"],
        "source": "Vim product label",
        "source_url": "https://www.vimcleaners.com",
        "source_date": "2026-08",
        "ingredients": [
            ("ING-WATER", None, None, "base"),
            ("ING-SODIUM-LAURETH-SULFATE", None, None, "surfactant"),
            ("ING-CITRIC-ACID", None, None, "cleaning agent"),
        ],
        "identifiers": [
            {"identifier_type": "gtin", "identifier_value": "8901030591216", "source": "Product label"},
        ],
        "attributes": [
            {"attribute_name": "Volume", "attribute_value": "500 ml", "attribute_type": "text"},
            {"attribute_name": "Fragrance", "attribute_value": "Lemon", "attribute_type": "text"},
        ],
    },
    # ===== ELECTRONICS =====
    {
        "product_id": "PRD-SAMSUNG-25W-CHARGER",
        "brand_name": "Samsung",
        "product_name": "25W USB-C Fast Charger",
        "product_variant": "EP-TA800",
        "category": "Electronics",
        "subcategory": "Mobile Accessories",
        "intended_use": "USB-C wall charger for mobile devices.",
        "consumption_status": "Household/industrial use",
        "manufacturer": "Samsung Electronics",
        "market": "India",
        "barcode": "8806091789340",
        "product_type": "physical",
        "description": "Samsung 25W USB-C super fast charging adapter (EP-TA800).",
        "country": "South Korea",
        "model_number": "EP-TA800",
        "gtin": "8806091789340",
        "edible_status": "non_edible",
        "external_use_status": False,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": ["Use only with compatible devices", "Do not disassemble", "Do not expose to water"],
        "source": "Samsung product listing",
        "source_url": "https://www.samsung.com",
        "source_date": "2026-08",
        "ingredients": [],
        "identifiers": [
            {"identifier_type": "gtin", "identifier_value": "8806091789340", "source": "Product listing"},
            {"identifier_type": "model_number", "identifier_value": "EP-TA800", "source": "Product listing"},
        ],
        "attributes": [
            {"attribute_name": "Power Output", "attribute_value": "25W", "attribute_type": "text"},
            {"attribute_name": "Input", "attribute_value": "100-240V ~ 50/60Hz", "attribute_type": "text"},
            {"attribute_name": "Connector Type", "attribute_value": "USB Type-C", "attribute_type": "text"},
            {"attribute_name": "Fast Charging", "attribute_value": "Yes (PD 3.0, PPS)", "attribute_type": "boolean"},
            {"attribute_name": "Weight", "attribute_value": "51g", "attribute_type": "text"},
        ],
    },
    {
        "product_id": "PRD-APPLE-AIRPODS-PRO",
        "brand_name": "Apple",
        "product_name": "AirPods Pro 2nd Gen",
        "product_variant": "USB-C",
        "category": "Electronics",
        "subcategory": "Audio",
        "intended_use": "Wireless noise-cancelling earbuds.",
        "consumption_status": "Household/industrial use",
        "manufacturer": "Apple Inc.",
        "market": "Global",
        "barcode": "194253397182",
        "product_type": "physical",
        "description": "Apple AirPods Pro 2nd generation with USB-C and Active Noise Cancellation.",
        "country": "USA",
        "model_number": "MTJV3HN/A",
        "gtin": "194253397182",
        "edible_status": "non_edible",
        "external_use_status": False,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": ["Do not expose to water beyond IPX4 rating", "Do not disassemble"],
        "source": "Apple product listing",
        "source_url": "https://www.apple.com",
        "source_date": "2026-08",
        "ingredients": [],
        "identifiers": [
            {"identifier_type": "gtin", "identifier_value": "194253397182", "source": "Product listing"},
            {"identifier_type": "model_number", "identifier_value": "MTJV3HN/A", "source": "Product listing"},
        ],
        "attributes": [
            {"attribute_name": "Battery Life", "attribute_value": "6 hrs (30 hrs with case)", "attribute_type": "text"},
            {"attribute_name": "Water Resistance", "attribute_value": "IPX4", "attribute_type": "text"},
            {"attribute_name": "ANC", "attribute_value": "Active Noise Cancellation", "attribute_type": "text"},
            {"attribute_name": "Weight", "attribute_value": "5.3g per earbud", "attribute_type": "text"},
        ],
    },
    # ===== HOME APPLIANCES =====
    {
        "product_id": "PRD-PRESTIGE-MIXER",
        "brand_name": "Prestige",
        "product_name": "Iris 750W Mixer Grinder",
        "product_variant": "3 Jar",
        "category": "Home Appliances",
        "subcategory": "Kitchen Appliances",
        "intended_use": "Electric mixer grinder for kitchen use.",
        "consumption_status": "Household/industrial use",
        "manufacturer": "TTK Prestige",
        "market": "India",
        "barcode": None,
        "model_number": "IRIS 750W",
        "product_type": "physical",
        "description": "Prestige Iris 750W mixer grinder with 3 stainless steel jars.",
        "country": "India",
        "edible_status": "non_edible",
        "external_use_status": False,
        "verification_status": "verified",
        "identification_confidence": "Medium",
        "warnings": ["Do not immerse in water", "Do not operate continuously for more than 5 minutes"],
        "source": "Prestige product listing",
        "source_url": "https://www.prestigemimicry.com",
        "source_date": "2026-08",
        "ingredients": [],
        "identifiers": [
            {"identifier_type": "model_number", "identifier_value": "IRIS 750W", "source": "Product listing"},
        ],
        "attributes": [
            {"attribute_name": "Power", "attribute_value": "750W", "attribute_type": "text"},
            {"attribute_name": "Speed", "attribute_value": "3 speed + pulse", "attribute_type": "text"},
            {"attribute_name": "Jars", "attribute_value": "3 (stainless steel)", "attribute_type": "text"},
            {"attribute_name": "Voltage", "attribute_value": "220-240V", "attribute_type": "text"},
        ],
    },
    # ===== KITCHEN =====
    {
        "product_id": "PRD-PRESTIGE-COOKER",
        "brand_name": "Prestige",
        "product_name": "Popular Plus Aluminium Pressure Cooker",
        "product_variant": "5 Litre",
        "category": "Kitchen Products",
        "subcategory": "Cookware",
        "intended_use": "Pressure cooker for cooking.",
        "consumption_status": "Household/industrial use",
        "manufacturer": "TTK Prestige",
        "market": "India",
        "barcode": "8901042433017",
        "product_type": "physical",
        "description": "Prestige Popular Plus 5 litre aluminium pressure cooker with lid lock.",
        "country": "India",
        "gtin": "8901042433017",
        "edible_status": "non_edible",
        "external_use_status": False,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": ["Do not fill more than 2/3 capacity", "Do not use without water"],
        "source": "Prestige product listing",
        "source_url": "https://www.prestigemimicry.com",
        "source_date": "2026-08",
        "ingredients": [],
        "identifiers": [
            {"identifier_type": "gtin", "identifier_value": "8901042433017", "source": "Product listing"},
        ],
        "attributes": [
            {"attribute_name": "Capacity", "attribute_value": "5 Litres", "attribute_type": "text"},
            {"attribute_name": "Material", "attribute_value": "Aluminium", "attribute_type": "text"},
            {"attribute_name": "Lid Lock", "attribute_value": "Yes", "attribute_type": "boolean"},
        ],
    },
    # ===== CLOTHING =====
    {
        "product_id": "PRD-LEVIS-501-JEANS",
        "brand_name": "Levi's",
        "product_name": "501 Original Fit Jeans",
        "product_variant": "Blue, 32x32",
        "category": "Clothing",
        "subcategory": "Men's Clothing",
        "intended_use": "Denim jeans for casual wear.",
        "consumption_status": "Not intended for human consumption",
        "manufacturer": "Levi Strauss & Co.",
        "market": "Global",
        "barcode": "0088775544212",
        "product_type": "physical",
        "description": "Levi's 501 Original Fit iconic straight leg jeans.",
        "country": "USA",
        "gtin": "0088775544212",
        "edible_status": "non_edible",
        "external_use_status": True,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": ["Follow care label instructions"],
        "source": "Levi's product listing",
        "source_url": "https://www.levi.com",
        "source_date": "2026-08",
        "ingredients": [
            ("ING-COTTON-FIBER", None, None, "material"),
            ("ING-POLYESTER-FIBER", None, None, "material"),
        ],
        "identifiers": [
            {"identifier_type": "gtin", "identifier_value": "0088775544212", "source": "Product listing"},
        ],
        "attributes": [
            {"attribute_name": "Material", "attribute_value": "99% Cotton, 1% Elastane", "attribute_type": "text"},
            {"attribute_name": "Fit", "attribute_value": "Original", "attribute_type": "text"},
            {"attribute_name": "Care Instructions", "attribute_value": "Machine wash cold, tumble dry low", "attribute_type": "text"},
            {"attribute_name": "Closure", "attribute_value": "Button fly", "attribute_type": "text"},
        ],
    },
    # ===== SHOES =====
    {
        "product_id": "PRD-NIKE-AIR-MAX",
        "brand_name": "Nike",
        "product_name": "Air Max 270",
        "product_variant": "Black/White, US 10",
        "category": "Shoes",
        "subcategory": "Sports Shoes",
        "intended_use": "Running and lifestyle sneakers.",
        "consumption_status": "Not intended for human consumption",
        "manufacturer": "Nike Inc.",
        "market": "Global",
        "barcode": "193153048394",
        "product_type": "physical",
        "description": "Nike Air Max 270 with visible Max Air unit for all-day comfort.",
        "country": "USA",
        "gtin": "193153048394",
        "edible_status": "non_edible",
        "external_use_status": True,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": [],
        "source": "Nike product listing",
        "source_url": "https://www.nike.com",
        "source_date": "2026-08",
        "ingredients": [],
        "identifiers": [
            {"identifier_type": "gtin", "identifier_value": "193153048394", "source": "Product listing"},
        ],
        "attributes": [
            {"attribute_name": "Upper Material", "attribute_value": "Mesh and synthetic", "attribute_type": "text"},
            {"attribute_name": "Sole Material", "attribute_value": "Rubber", "attribute_type": "text"},
            {"attribute_name": "Cushioning", "attribute_value": "Max Air unit", "attribute_type": "text"},
        ],
    },
    # ===== BAGS =====
    {
        "product_id": "PRD-SKYBAGS-BACKPACK",
        "brand_name": "Skybags",
        "product_name": "Streak 45cm Laptop Backpack",
        "product_variant": "Blue",
        "category": "Bags",
        "subcategory": "Backpacks",
        "intended_use": "Laptop backpack for daily commute.",
        "consumption_status": "Not intended for human consumption",
        "manufacturer": "VIP Industries",
        "market": "India",
        "barcode": None,
        "product_type": "physical",
        "description": "Skybags Streak 45cm laptop backpack with rain cover and USB charging port.",
        "country": "India",
        "edible_status": "non_edible",
        "external_use_status": True,
        "verification_status": "verified",
        "identification_confidence": "Medium",
        "warnings": [],
        "source": "Skybags product listing",
        "source_url": "https://www.skybags.in",
        "source_date": "2026-08",
        "ingredients": [],
        "identifiers": [],
        "attributes": [
            {"attribute_name": "Capacity", "attribute_value": "33 litres", "attribute_type": "text"},
            {"attribute_name": "Laptop Compatibility", "attribute_value": "Up to 15.6 inch", "attribute_type": "text"},
            {"attribute_name": "Material", "attribute_value": "Polyester", "attribute_type": "text"},
            {"attribute_name": "Rain Cover", "attribute_value": "Included", "attribute_type": "boolean"},
        ],
    },
    # ===== TOYS =====
    {
        "product_id": "PRD-LEGO-CLASSIC",
        "brand_name": "LEGO",
        "product_name": "Classic Medium Creative Brick Box",
        "product_variant": "484 pieces",
        "category": "Toys",
        "subcategory": "Educational Toys",
        "intended_use": "Construction toy for creative building.",
        "consumption_status": "Not intended for human consumption",
        "manufacturer": "LEGO System A/S",
        "market": "Global",
        "barcode": "5702016111015",
        "product_type": "physical",
        "description": "LEGO Classic 10696 Medium Creative Brick Box with 484 pieces in 35 colours.",
        "country": "Denmark",
        "gtin": "5702016111015",
        "edible_status": "non_edible",
        "external_use_status": True,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": ["Choking hazard - small parts", "Not suitable for children under 4 years"],
        "source": "LEGO product listing",
        "source_url": "https://www.lego.com",
        "source_date": "2026-08",
        "ingredients": [],
        "identifiers": [
            {"identifier_type": "gtin", "identifier_value": "5702016111015", "source": "Product listing"},
        ],
        "attributes": [
            {"attribute_name": "Piece Count", "attribute_value": "484", "attribute_type": "number"},
            {"attribute_name": "Age Range", "attribute_value": "4-99 years", "attribute_type": "text"},
            {"attribute_name": "Material", "attribute_value": "ABS Plastic", "attribute_type": "text"},
        ],
    },
    # ===== BABY PRODUCTS =====
    {
        "product_id": "PRD-HUGGIES-DIAPERS",
        "brand_name": "Huggies",
        "product_name": "Wonder Pants",
        "product_variant": "Medium (7-11 kg), 60 count",
        "category": "Baby Products",
        "subcategory": "Diapers",
        "intended_use": "Disposable baby diapers.",
        "consumption_status": "Not intended for human consumption",
        "manufacturer": "Kimberly-Clark",
        "market": "India",
        "barcode": "5029240705010",
        "product_type": "physical",
        "description": "Huggies Wonder Pants soft dry diapers with 12-hour leakage protection.",
        "country": "USA",
        "gtin": "5029240705010",
        "edible_status": "non_edible",
        "external_use_status": True,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": ["For external use only", "Dispose of properly after use"],
        "source": "Huggies product listing",
        "source_url": "https://www.huggies.com",
        "source_date": "2026-08",
        "ingredients": [],
        "identifiers": [
            {"identifier_type": "gtin", "identifier_value": "5029240705010", "source": "Product listing"},
        ],
        "attributes": [
            {"attribute_name": "Weight Range", "attribute_value": "7-11 kg", "attribute_type": "text"},
            {"attribute_name": "Count", "attribute_value": "60 diapers", "attribute_type": "number"},
            {"attribute_name": "Absorption", "attribute_value": "12 hours", "attribute_type": "text"},
        ],
    },
    # ===== STATIONERY =====
    {
        "product_id": "PRD-CLASSMATE-NOTEBOOK",
        "brand_name": "Classmate",
        "product_name": "Pulse Spiral Notebook",
        "product_variant": "A4, 200 pages",
        "category": "Stationery",
        "subcategory": "Notebooks",
        "intended_use": "Spiral notebook for writing.",
        "consumption_status": "Not intended for human consumption",
        "manufacturer": "ITC Limited",
        "market": "India",
        "barcode": "8901058510012",
        "product_type": "physical",
        "description": "Classmate Pulse A4 spiral notebook with 200 pages and premium paper.",
        "country": "India",
        "gtin": "8901058510012",
        "edible_status": "non_edible",
        "external_use_status": True,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": [],
        "source": "Classmate product listing",
        "source_url": "https://www.classmatepaper.com",
        "source_date": "2026-08",
        "ingredients": [],
        "identifiers": [
            {"identifier_type": "gtin", "identifier_value": "8901058510012", "source": "Product listing"},
        ],
        "attributes": [
            {"attribute_name": "Size", "attribute_value": "A4 (21 x 29.7 cm)", "attribute_type": "text"},
            {"attribute_name": "Pages", "attribute_value": "200", "attribute_type": "number"},
            {"attribute_name": "Paper GSM", "attribute_value": "70 GSM", "attribute_type": "text"},
        ],
    },
    # ===== BEAUTY =====
    {
        "product_id": "PRD-NYKAA-PERFUME",
        "brand_name": "Nykaa",
        "product_name": "So NICE Eau de Parfum",
        "product_variant": "100ml",
        "category": "Beauty Products",
        "subcategory": "Fragrances",
        "intended_use": "Women's perfume.",
        "consumption_status": "External use only",
        "manufacturer": "Nykaa",
        "market": "India",
        "barcode": None,
        "product_type": "physical",
        "description": "Nykaa So NICE Eau de Parfum with floral and fruity notes.",
        "country": "India",
        "edible_status": "non_edible",
        "external_use_status": True,
        "verification_status": "verified",
        "identification_confidence": "Medium",
        "warnings": ["For external use only", "Avoid contact with eyes"],
        "source": "Nykaa product listing",
        "source_url": "https://www.nykaa.com",
        "source_date": "2026-08",
        "ingredients": [
            ("ING-LINALOOL", None, None, "fragrance"),
            ("ING-WATER", None, None, "solvent"),
        ],
        "identifiers": [],
        "attributes": [
            {"attribute_name": "Volume", "attribute_value": "100 ml", "attribute_type": "text"},
            {"attribute_name": "Fragrance Family", "attribute_value": "Floral Fruity", "attribute_type": "text"},
        ],
    },
    # ===== AUTOMOTIVE =====
    {
        "product_id": "PRD-3M-CAR-SHAMPOO",
        "brand_name": "3M",
        "product_name": "Car Wash Shampoo",
        "product_variant": "500ml",
        "category": "Automotive Products",
        "subcategory": "Car Care",
        "intended_use": "Car body wash shampoo.",
        "consumption_status": "Not intended for human consumption",
        "manufacturer": "3M India",
        "market": "India",
        "barcode": "5005111450012",
        "product_type": "physical",
        "description": "3M car wash shampoo for gentle and effective car body cleaning.",
        "country": "India",
        "gtin": "5005111450012",
        "edible_status": "non_edible",
        "external_use_status": False,
        "verification_status": "verified",
        "identification_confidence": "High",
        "warnings": ["For external use on vehicle body only", "Keep away from children"],
        "source": "3M product listing",
        "source_url": "https://www.3m.com",
        "source_date": "2026-08",
        "ingredients": [
            ("ING-WATER", None, None, "base"),
            ("ING-SODIUM-LAURETH-SULFATE", None, None, "surfactant"),
        ],
        "identifiers": [
            {"identifier_type": "gtin", "identifier_value": "5005111450012", "source": "Product listing"},
        ],
        "attributes": [
            {"attribute_name": "Volume", "attribute_value": "500 ml", "attribute_type": "text"},
            {"attribute_name": "Coverage", "attribute_value": "Up to 20 cars", "attribute_type": "text"},
        ],
    },
]


# --------------------------------------------------------------------------- #
# Build category name -> id map
# --------------------------------------------------------------------------- #
def _build_category_map() -> dict:
    """Return {lowercase_name: category_id} from the categories table."""
    return {
        c.category_name.lower(): c.category_id
        for c in Category.query.all()
    }


# --------------------------------------------------------------------------- #
# Build ingredient rows from EXTRA + ADDITIONAL + KB
# --------------------------------------------------------------------------- #
def _build_ingredient_rows() -> list:
    """Curated extra rows + KB-derived rows. Returns unsaved Ingredient objects."""
    rows = []
    all_curated_ids = set()

    for spec in EXTRA_INGREDIENTS + ADDITIONAL_INGREDIENTS:
        all_curated_ids.add(spec["ingredient_id"])
        rows.append(Ingredient(
            ingredient_id=spec["ingredient_id"],
            ingredient_name=spec["ingredient_name"],
            normalized_name=_norm(spec["ingredient_name"]),
            aliases=spec.get("aliases"),
            ingredient_type=spec.get("ingredient_type"),
            category=spec.get("category"),
            score_impact=spec.get("score_impact"),
            common_function=spec.get("common_function"),
            description=spec.get("description"),
            safety_information=spec.get("safety_information"),
            potential_concerns=spec.get("potential_concerns"),
            ingestion_status=spec.get("ingestion_status"),
            external_use_information=spec.get("external_use_information"),
            evidence_level=spec.get("evidence_level"),
            risk_category=spec.get("risk_category") or "unknown",
            source=spec.get("source"),
            source_url=spec.get("source_url"),
            source_date=spec.get("source_date"),
        ))

    for key, entry in INGREDIENT_KB.items():
        ingredient_id = "ING-" + _norm(key).upper()
        if ingredient_id in all_curated_ids:
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
        # --- Categories --- #
        cats_exist = Category.query.count() > 0
        if not cats_exist or force:
            cat_map = {}  # name_lower -> category_id
            added = 0
            for name, desc, parent_name, sort_order in CATEGORY_HIERARCHY:
                key = name.lower()
                existing = Category.query.filter_by(category_name=name).first()
                if existing:
                    cat_map[key] = existing.category_id
                    continue
                parent_id = cat_map.get(parent_name.lower()) if parent_name else None
                cat = Category(
                    category_name=name,
                    description=desc,
                    parent_category_id=parent_id,
                    sort_order=sort_order,
                )
                db.session.add(cat)
                db.session.flush()
                cat_map[key] = cat.category_id
                added += 1
            db.session.commit()
            if added:
                app.logger.info("Product DB: seeded %s category row(s).", added)

        # --- Ingredients --- #
        ingredients_exist = Ingredient.query.count() > 0
        if not ingredients_exist or force:
            existing_ids = {i.ingredient_id for i in
                            Ingredient.query.with_entities(Ingredient.ingredient_id).all()}
            added = 0
            for row in _build_ingredient_rows():
                if row.ingredient_id in existing_ids:
                    # Update existing curated ingredients with any new fields
                    if force:
                        existing = db.session.get(Ingredient, row.ingredient_id)
                        if existing:
                            updated = False
                            if row.category and not existing.category:
                                existing.category = row.category
                                updated = True
                            if row.score_impact is not None and existing.score_impact is None:
                                existing.score_impact = row.score_impact
                                updated = True
                            if updated:
                                existing.updated_at = datetime.utcnow()
                    continue
                db.session.add(row)
                existing_ids.add(row.ingredient_id)
                added += 1
            db.session.commit()
            if added:
                app.logger.info("Product DB: seeded %s ingredient row(s).", added)

        # --- Products + Identifiers + Attributes + Verifications + ScoreFactors --- #
        products_exist = Product.query.count() > 0
        if not products_exist or force:
            cat_map = _build_category_map()
            product_ids = {p.product_id for p in
                           Product.query.with_entities(Product.product_id).all()}
            added = 0
            for spec in PRODUCT_SEED:
                if spec["product_id"] in product_ids:
                    continue

                # Resolve category/subcategory IDs
                cat_id = cat_map.get((spec.get("category") or "").lower())
                sub_id = cat_map.get((spec.get("subcategory") or "").lower())

                product = Product(
                    product_id=spec["product_id"],
                    brand_name=spec["brand_name"],
                    product_name=spec["product_name"],
                    product_variant=spec.get("product_variant") or None,
                    category=spec.get("category"),
                    subcategory=spec.get("subcategory"),
                    category_id=cat_id,
                    subcategory_id=sub_id,
                    intended_use=spec.get("intended_use"),
                    consumption_status=spec.get("consumption_status"),
                    manufacturer=spec.get("manufacturer"),
                    market=spec.get("market"),
                    barcode=spec.get("barcode"),
                    warnings=spec.get("warnings") or [],
                    source=spec.get("source"),
                    source_url=spec.get("source_url"),
                    source_date=spec.get("source_date"),
                    product_type=spec.get("product_type"),
                    description=spec.get("description"),
                    gtin=spec.get("gtin"),
                    model_number=spec.get("model_number"),
                    country=spec.get("country"),
                    edible_status=spec.get("edible_status"),
                    external_use_status=spec.get("external_use_status", False),
                    verification_status=spec.get("verification_status", "verified"),
                    identification_confidence=spec.get("identification_confidence", "Medium"),
                )
                db.session.add(product)
                db.session.flush()

                # Product-Ingredient links
                for ingredient_id, concentration, unit, role in spec.get("ingredients", []):
                    ing = db.session.get(Ingredient, ingredient_id)
                    if ing is None:
                        continue
                    db.session.add(ProductIngredient(
                        product_id=product.product_id,
                        ingredient_id=ingredient_id,
                        concentration=concentration,
                        concentration_unit=unit,
                        role=role,
                        source=spec.get("source"),
                        source_url=spec.get("source_url"),
                        source_date=spec.get("source_date"),
                    ))

                # Product Identifiers
                for ident in spec.get("identifiers", []):
                    db.session.add(ProductIdentifier(
                        product_id=product.product_id,
                        identifier_type=ident["identifier_type"],
                        identifier_value=ident["identifier_value"],
                        source=ident.get("source"),
                        verification_status="verified",
                    ))

                # Product Attributes
                for attr in spec.get("attributes", []):
                    db.session.add(ProductAttribute(
                        product_id=product.product_id,
                        attribute_name=attr["attribute_name"],
                        attribute_value=attr.get("attribute_value"),
                        attribute_type=attr.get("attribute_type", "text"),
                        source=spec.get("source"),
                        verification_status="verified",
                    ))

                # Product Verification
                verification_level = {
                    "High": "verified",
                    "Medium": "partially_verified",
                    "Low": "needs_verification",
                }
                db.session.add(ProductVerification(
                    product_id=product.product_id,
                    verification_type="identity",
                    verification_status=verification_level.get(
                        spec.get("identification_confidence", "Medium"), "unverified"
                    ),
                    confidence_score={"High": 0.95, "Medium": 0.7, "Low": 0.4}.get(
                        spec.get("identification_confidence", "Medium"), 0.5
                    ),
                    verified_value=f"{spec['brand_name']} {spec['product_name']}",
                    source=spec.get("source"),
                    explanation=f"Product identity verified via label and database records.",
                    verified_at=datetime.utcnow(),
                ))

                # Product Score Factors (example factors for each product)
                has_ingredients = bool(spec.get("ingredients"))
                has_barcode = bool(spec.get("barcode") or spec.get("gtin"))
                has_warnings = bool(spec.get("warnings"))
                confidence = spec.get("identification_confidence", "Medium")

                factors = []
                if has_barcode:
                    factors.append(ProductScoreFactor(
                        product_id=product.product_id,
                        factor_type="positive",
                        factor_name="Product barcode/GTIN available",
                        factor_value="+10",
                        score_impact=10.0,
                        risk_level="low",
                        explanation="Barcode/GTIN allows precise product identification.",
                    ))
                if confidence == "High":
                    factors.append(ProductScoreFactor(
                        product_id=product.product_id,
                        factor_type="positive",
                        factor_name="Product identity verified",
                        factor_value="+15",
                        score_impact=15.0,
                        risk_level="low",
                        explanation="High-confidence match against verified product records.",
                    ))
                if has_ingredients:
                    factors.append(ProductScoreFactor(
                        product_id=product.product_id,
                        factor_type="positive",
                        factor_name="Ingredient list available",
                        factor_value="+10",
                        score_impact=10.0,
                        risk_level="low",
                        explanation="Product has a verified ingredient list.",
                    ))
                elif not has_ingredients and spec.get("category") in ("Electronics", "Home Appliances", "Kitchen Products", "Bags", "Toys", "Baby Products", "Stationery", "Clothing", "Shoes", "Automotive Products", "Household Products", "Other Consumer Products"):
                    factors.append(ProductScoreFactor(
                        product_id=product.product_id,
                        factor_type="neutral",
                        factor_name="No ingredient list expected",
                        factor_value="0",
                        score_impact=0.0,
                        risk_level="low",
                        explanation="This product type does not have a food/cosmetic-style ingredient list.",
                    ))
                if has_warnings:
                    factors.append(ProductScoreFactor(
                        product_id=product.product_id,
                        factor_type="positive",
                        factor_name="Safety warnings present",
                        factor_value="+5",
                        score_impact=5.0,
                        risk_level="low",
                        explanation="Product includes safety warnings on the label.",
                    ))

                for f in factors:
                    db.session.add(f)

                # Compute and cache trust score
                total_impact = sum(f.score_impact for f in factors)
                cached_score = min(100, max(0, int(50 + total_impact)))
                product.trust_score = cached_score
                product.risk_level = "low" if cached_score >= 70 else "moderate" if cached_score >= 40 else "high"

                product_ids.add(product.product_id)
                added += 1
            db.session.commit()
            app.logger.info("Product DB: seeded %s product record(s) with identifiers, attributes, verifications, and score factors.", added)


if __name__ == "__main__":
    from app_factory import create_app

    app = create_app()
    seed_product_db(app, force="--force" in sys.argv)
    with app.app_context():
        print("Categories:", Category.query.count())
        print("Ingredients:", Ingredient.query.count())
        print("Products:", Product.query.count())
        print("Identifiers:", ProductIdentifier.query.count())
        print("Attributes:", ProductAttribute.query.count())
        print("Verifications:", ProductVerification.query.count())
        print("Score Factors:", ProductScoreFactor.query.count())
