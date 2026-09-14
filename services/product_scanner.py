"""
Product / ingredient label scanner - evidence-based safety analysis.

Hybrid pipeline (never OCR-only):

    IMAGE -> OCR -> PRODUCT IDENTIFICATION -> PRODUCT DATABASE MATCH
          -> INGREDIENT DATABASE -> INGREDIENT ANALYSIS
          -> SAFETY / USAGE ASSESSMENT -> DETAILED RESULT

  1. Accept pasted ingredient text and/or an uploaded label image.
  2. For images: validate + OCR the label (EasyOCR, shared with the WhatsApp
     scanner) and show the extracted text. A failed OCR is reported honestly,
     never replaced with a fabricated ingredient list.
  3. Parse the ingredient list (splits, brackets, percentages, dedupe).
  4. Identify the product against the verified Product database (brand, name,
     variant, barcode, fuzzy). A brand match alone NEVER selects a random
     product of that brand.
  5. On a database match: analyse the product's own verified ingredient
     records, cross-check them against the OCR text (found on label /
     expected from database but not visible / additional label ingredient /
     unknown), and use the product's recorded consumption status. Unknown
     concentrations stay unknown - never guessed.
  6. Without a database match: fall back to the curated ingredient knowledge
     base and say honestly that the product was not found in the verified
     product database.
  7. Compute a deterministic, transparent 0-100 safety score. Non-food
     products are assessed for their intended use, never penalised for
     "not being edible".

Honesty rules baked into the score:
  - "Unknown" NEVER counts as dangerous. Unknown ingredients only cap the
    score because we have less information, and the report says so.
  - A missing ingredient list returns
    "Insufficient information for a reliable assessment." - no manufactured
    certainty, no default 100.
  - Duplicates, capitalisation and formatting differences are normalised, so
    the same input always yields the same result.
"""

import hashlib
import re
import time

from models.product_db import Product
from services.logger import get_logger
from services.product_knowledge_base import lookup_product, product_hash
from services.scoring import classify, remap_score_to_band, STATUS_BANDS
from services.whatsapp_scanner import extract_text_ocr

logger = get_logger(__name__)

MAX_INPUT_CHARS = 5000
MAX_INGREDIENTS = 120
INSUFFICIENT_ASSESSMENT = "Insufficient information for a reliable assessment."

# --------------------------------------------------------------------------- #
# Universal product categories.
#
# The scanner classifies ANY uploaded product from the evidence actually on the
# label (OCR text + verified database record). Categories are data-driven, so
# adding a new product never requires a new if/else for that product.
# --------------------------------------------------------------------------- #
UNIVERSAL_CATEGORIES = [
    "food", "beverage", "snack", "supplement", "medicine",
    "cosmetic", "skincare", "haircare", "personal care", "soap", "toothpaste",
    "baby", "pet",
    "household cleaner", "disinfectant", "sanitizer", "laundry", "chemical",
    "electronics", "battery", "stationery", "agricultural", "automotive",
    "other", "unknown",
]

# Categories where the label's ingredient list is the relevant evidence.
CONSUMABLE_CATEGORIES = {"food", "beverage", "snack", "supplement", "medicine"}
TOPICAL_CATEGORIES = {"cosmetic", "skincare", "haircare", "personal care", "soap", "toothpaste"}
CHEMICAL_CATEGORIES = {"household cleaner", "disinfectant", "sanitizer", "laundry", "chemical"}
# Technical products: a food-style ingredient safety score is meaningless.
TECHNICAL_CATEGORIES = {"electronics", "battery", "stationery", "agricultural", "automotive"}

_CATEGORY_LABELS = {
    "food": "Food", "beverage": "Beverage", "snack": "Snack / packaged food",
    "supplement": "Supplement", "medicine": "Medicine",
    "cosmetic": "Cosmetic", "skincare": "Skincare", "haircare": "Haircare",
    "personal care": "Personal care", "soap": "Soap / cleanser", "toothpaste": "Toothpaste",
    "baby": "Baby product", "pet": "Pet product",
    "household cleaner": "Household cleaner", "disinfectant": "Disinfectant",
    "sanitizer": "Sanitizer", "laundry": "Laundry product", "chemical": "Chemical product",
    "electronics": "Electronics", "battery": "Battery", "stationery": "Stationery",
    "agricultural": "Agricultural product", "automotive": "Automotive product",
    "other": "Other", "unknown": "Unknown",
}

# Clue words/patterns (matched case-insensitively on the OCR text) used to
# classify a product. The verified-database category, when present, is mapped
# first and OCR clues only refine/confirm it.
_CATEGORY_CLUES = {
    "food": ["nutrition facts", "serving size", "calories per", "net wt", "net weight",
             "best before", "best-before", "use by", "ingredients:", "allergen",
             "chocolate", "cookies", "biscuit", "cereal", "pasta", "rice", "chips",
             "snack", "may contain", "food", "grain", "sesame", "peanut", "soy",
             "dairy", "gluten", "e102", "e110", "e211", "e330", "e951"],
    "beverage": ["drink", "beverage", "juice", "cola", "soda", "water", "milk",
                 "tea", "coffee", "energy drink", "carbonated", "isotonic",
                 "rehydrat", "ml e", "ml ", "1 litre", "1 l"],
    "snack": ["snack", "crisps", "chips", "namkeen", "popcorn", "biscuit", "cookie",
              "wafers", "flakes", "trail mix"],
    "supplement": ["supplement", "servings per container", "serving size", "vitamin ",
                   "mineral", "protein powder", "tablets", "capsules", "mg", "mcg",
                   "daily value", "recommended daily", "not intended to diagnose",
                   "dietary supplement", "omega", "probiotic"],
    "medicine": ["medicine", "medication", "tablets", "capsules", "suspension", "syrup",
                 "ointment", "cream", "drug facts", "active ingredient", "dosage",
                 "take one tablet", "consult your doctor", "do not use if",
                 "paracetamol", "ibuprofen", "aspirin", "antibiotic", "relief",
                 "pharmacist", "prescription", "mfg lic", "us 33 mg", "strip of",
                 "swallow", "store below"],
    "cosmetic": ["cosmetic", "makeup", "make-up", "foundation", "lipstick", "mascara",
                 "shade", "shade ", "paraben", "beauty", "premium cosmetics",
                 "for cosmetic"],
    "skincare": ["skincare", "skin care", "moistur", "serum", "lotion", "cream",
                 "sunscreen", "spf", "face wash", "anti-aging", "anti aging",
                 "hydrat", "toner", "retinol", "niacinamide", "hyaluronic",
                 "cleanser", "dermatologist", "non-comedogenic", "fragrance free"],
    "haircare": ["shampoo", "conditioner", "hair", "haircare", "hair care",
                 "anti-dandruff", "curl", "volume", "sulfate free", "paraben free",
                 "strengthening", "repair"],
    "personal care": ["body wash", "shower gel", "soap", "deodorant", "body lotion",
                      "hand wash", "handwash", "personal care", "bath",
                      "men care", "women care", "intimate"],
    "soap": ["soap", "bathing bar", "beauty bar", "antibacterial soap", "glycerine soap"],
    "toothpaste": ["toothpaste", "tooth paste", "dental", "cavity protection",
                   "fluoride", "whitening", "fresh breath", "oral care"],
    "baby": ["baby", "infant", "newborn", "diaper", "nappy", "baby lotion",
             "baby shampoo", "baby wash", "teether", "formula", "kids", "toddler"],
    "pet": ["pet", "dog", "cat food", "dog food", "puppy", "kitten", "pet care",
            "veterinary", "aquarium", "fish food", "bird"],
    "household cleaner": ["cleaner", "cleaning", "floor cleaner", "glass cleaner",
                          "bathroom cleaner", "kitchen cleaner", "surface", "degreaser",
                          "toilet", "multi-purpose", "multipurpose", "wipe",
                          "cleansing", "all purpose", "household"],
    "disinfectant": ["disinfect", "antiseptic", "kills 99", "kills 99.9", "germ",
                     "antibacterial", "sanitis", "sanitizer", "hygien", "dettol",
                     "savlon", "bacteria", "virus", "bactericidal"],
    "sanitizer": ["hand sanitizer", "sanitizer", "sanitising", "alcohol 70", "70%",
                  "62%", "ethanol", "isopropyl alcohol", "kills germs"],
    "laundry": ["laundry", "detergent", "fabric", "wash powder", "liquid detergent",
                "stain remover", "softener", "rinse", "front load", "top load",
                "whiteness", "brightness"],
    "chemical": ["chemical", "hazard", "corrosive", "flammable", "caution",
                 "industrial", "solvent", "acid", "alkaline", "bleach", "ammonia",
                 "pesticide", "insecticide", "herbicide", "fertilizer", "fertiliser",
                 "raw material", "contains sodium"],
    "electronics": ["electronics", "smartphone", "charger", "adapter", "earbud",
                    "earphones", "headphone", "bluetooth", "usb", "wifi", "router",
                    "power bank", "watch", "cable", "screen", "lcd", "led tv",
                    "remote", "microphone", "speaker", "voltage", "input:", "output:",
                    "input dc", "model:", "model no", "made in", "fcc", "ce "],
    "battery": ["battery", "batteries", "aa", "aaa", "9v", "volts", "v", "mhz",
                "mah", "rechargeable", "alkaline", "lithium", "lithium-ion", "li-ion",
                "ni-mh", "zinc chloride", "cell", "do not recharge", "do not dispose"],
    "stationery": ["stationery", "notebook", "pen", "pencil", "marker", "glue",
                   "stapler", "paper", "folders", "eraser", "crayons", "sketch",
                   "board", "envelope", "stickers"],
    "agricultural": ["agricultur", "fertilizer", "fertiliser", "pesticide", "insecticide",
                     "herbicide", "fungicide", "seed", "soil", "crop", "weed",
                     "urea", "n-p-k", "npk"],
    "automotive": ["automotive", "engine oil", "coolant", "brake fluid", "tyre",
                   "tire", "lubricant", "car", "vehicle", "motor oil", "sae",
                   "windshield", "car care", "petrol", "diesel"],
}

# Analysis modes drive how the UI labels the result and what evidence applies.
ANALYSIS_MODE_LABELS = {
    "consumption": "Consumption status",
    "external_use": "Consumption status",
    "chemical": "Intended use",
    "technical": "Intended use",
    "pet": "Consumption status",
    "baby": "Consumption status",
    "unknown": "Consumption status",
}


def _category_label(category: str) -> str:
    return _CATEGORY_LABELS.get(category or "unknown", "Unknown")


def classify_product_category(combined: str, db_category: str = "", db_subcategory: str = "") -> str:
    """Classify any product label into a universal category. Never raises."""
    text = (combined or "").lower()
    # Database category / subcategory, when present, is the strongest signal.
    db_map = {
        "household": "household cleaner", "personal": "personal care",
        "food": "food", "beverage": "beverage", "snack": "snack",
        "supplement": "supplement", "medicine": "medicine", "pharma": "medicine",
        "cosmetic": "cosmetic", "skincare": "skincare", "hair": "haircare",
        "baby": "baby", "pet": "pet", "cleaner": "household cleaner",
        "disinfectant": "disinfectant", "sanitizer": "sanitizer", "laundry": "laundry",
        "chemical": "chemical", "electronics": "electronics", "battery": "battery",
        "stationery": "stationery", "agricultur": "agricultural", "automotive": "automotive",
        "antiseptic": "disinfectant",
    }
    for haystack in (db_category or "", db_subcategory or ""):
        low = haystack.lower()
        for key, cat in db_map.items():
            if key in low:
                return cat

    scores = {}
    for cat, clues in _CATEGORY_CLUES.items():
        score = 0
        for clue in clues:
            if clue in text:
                score += 1
        if score:
            scores[cat] = score
    if not scores:
        return "unknown"
    best = max(scores, key=lambda c: (scores[c], -UNIVERSAL_CATEGORIES.index(c)))
    return best


def _analysis_mode_for(category: str) -> str:
    if category in CONSUMABLE_CATEGORIES:
        return "consumption"
    if category in TOPICAL_CATEGORIES:
        return "external_use"
    if category in CHEMICAL_CATEGORIES:
        return "chemical"
    if category in TECHNICAL_CATEGORIES:
        return "technical"
    if category == "pet":
        return "pet"
    if category == "baby":
        return "baby"
    return "unknown"


# Warnings / cautionary lines actually printed on the label (real OCR text).
_WARNING_HINTS = [
    r"warning", r"caution", r"danger", r"poison", r"hazard",
    r"keep out of reach of children", r"not for internal use", r"not for human consumption",
    r"for external use", r"avoid contact with eyes", r"if swallowed",
    r"seek medical", r"do not swallow", r"do not ingest", r"do not drink",
    r"do not eat", r"flammable", r"corrosive", r"irritat", r"do not use",
    r"dispose of", r"first aid", r"store below", r"do not store", r"keep away",
    r"may cause", r"not recommended", r"consult your doctor", r"pharmacist",
    r"do not exceed", r"do not take", r"do not give", r"for adult",
    r"read the label before use", r"keep away from", r"avoid inhalation",
    r"use in a well-ventilated area", r"do not mix", r"do not recharge",
    r"do not dispose of in fire", r"risk of explosion", r"choking hazard",
]


def _extract_label_warnings(text: str) -> list:
    """Return real warning/caution lines found in the OCR text (max 8)."""
    if not text:
        return []
    seen = set()
    out = []
    for line in (text or "").splitlines():
        line = line.strip().strip("•-–—*: ")
        if len(line) < 4 or len(line) > 220:
            continue
        low = line.lower()
        if not any(re.search(h, low) for h in _WARNING_HINTS):
            continue
        key = _norm(line)
        if key in seen:
            continue
        seen.add(key)
        out.append(line)
        if len(out) >= 8:
            break
    return out


# Marketing claims printed on the label. Evidence status is NEVER auto-
# "supported": a claim is only reported as what it is - a label claim.
_CLAIM_HINTS = [
    r"100\s*%\s*safe", r"chemical[-\s]*free", r"paraben[-\s]*free",
    r"sulfate[-\s]*free", r"alcohol[-\s]*free", r"sugar[-\s]*free", r"no\s+added",
    r"clinically\s+proven", r"clinically\s+tested", r"dermatolog", r"dermatologically",
    r"hypoallergenic", r"non-comedogenic", r"cruelty[-\s]*free", r"vegan",
    r"cures?", r"treats?", r"prevents?", r"boosts?", r"immunity", r"guarantee",
    r"results", r"recommended\s+by", r"no\.?\s*1", r"best", r"effective",
    r"natural", r"organic", r"antibacterial", r"kills\s+\d+\s*%", r"removes\s+\d+\s*%",
    r"instantly", r"overnight", r"whitening", r"anti-aging", r"anti aging",
    r"fat\s+burn", r"weight\s+loss", r"glow", r"radiant", r"no\s+side\s+effects",
    r"safe\s+for\s+(children|babies|kids)", r"diabetes", r"blood\s+pressure",
]


def _extract_claims(text: str) -> list:
    """Return {claim, evidence_status, note} for marketing-style lines on the label."""
    if not text:
        return []
    seen = set()
    out = []
    for line in (text or "").splitlines():
        line = line.strip().strip("•-–—*: ")
        if len(line) < 4 or len(line) > 220:
            continue
        low = line.lower()
        if not any(re.search(h, low) for h in _CLAIM_HINTS):
            continue
        key = _norm(line)
        if key in seen:
            continue
        seen.add(key)
        note = ("Marketing claim printed on the label. TrustLens cannot independently "
                "verify it from the evidence available, so it is not treated as fact.")
        out.append({
            "claim": line,
            "evidence_status": "Unverifiable",
            "note": note,
        })
        if len(out) >= 8:
            break
    return out


def _technical_specs(text: str) -> list:
    """Best-effort extraction of visible technical specifications (electronics/battery)."""
    specs = []
    if not text:
        return specs
    m = re.search(r"\b(\d+(?:[.,]\d+)?)\s*V(?:olts)?\b", text, re.IGNORECASE)
    if m:
        specs.append({"label": "Voltage", "value": m.group(1) + " V",
                      "detection": "Visible on label"})
    m = re.search(r"\b(\d+(?:[.,]\d+)?)\s*(?:mAh|mah|Ah|MAH)\b", text)
    if m:
        specs.append({"label": "Capacity", "value": m.group(1) + " mAh",
                      "detection": "Visible on label"})
    m = re.search(r"\b(lithium(?:-ion)?|li-ion|alkaline|lead-acid|ni-cd|ni-mh|nimh)\b",
                  text, re.IGNORECASE)
    if m:
        specs.append({"label": "Chemistry", "value": m.group(1),
                      "detection": "Visible on label"})
    m = re.search(r"\b(model|type|mfr\.?|model no\.?)\s*[:#]?\s*([A-Za-z0-9][A-Za-z0-9\- ]{1,18})",
                  text, re.IGNORECASE)
    if m and len(m.group(2).strip()) >= 2:
        specs.append({"label": "Model / type", "value": m.group(2).strip(),
                      "detection": "Visible on label"})
    return specs


# --------------------------------------------------------------------------- #
# Curated ingredient knowledge base.
#
# Category values:
#   low      - broadly considered safe at normal use levels
#   moderate - allowed but with real caveats (allergens, restricted levels,
#              contested evidence) that consumers should know about
#   higher   - substance of genuine concern (restricted/banned in some
#              jurisdictions, strong evidence of harm, or allowed only under
#              strict limits)
#   unknown  - not in the knowledge base (never treated as danger)
#
# "source" entries are the authoritative bodies whose assessments the
# classification is based on. They are organisation names, not fabricated URLs.
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# Common allergens - recognised food allergens that require labelling.
# The scanner detects these and warns users with known allergies.
# --------------------------------------------------------------------------- #
COMMON_ALLERGENS = {
    "milk": {
        "aliases": ["milk", "whole milk", "skim milk", "milk solids", "milk fat",
                     "butter", "ghee", "cream", "buttermilk", "whey", "casein",
                     "lactose", "milk powder", "skimmed milk powder"],
        "label": "Milk / Dairy",
        "info": "Milk is a major food allergen. People with milk allergy or lactose "
                "intolerance should avoid or check this product carefully.",
    },
    "egg": {
        "aliases": ["egg", "eggs", "egg powder", "egg white", "egg yolk",
                     "albumin", "albumen", "ovalbumin"],
        "label": "Egg",
        "info": "Egg is a major food allergen. People with egg allergy should "
                "check the label carefully.",
    },
    "peanut": {
        "aliases": ["peanut", "peanuts", "peanut butter", "groundnut",
                     "groundnuts", "peanut oil", "arachis oil", "groundnut oil"],
        "label": "Peanut",
        "info": "Peanut is a major food allergen that can cause severe allergic "
                "reactions. People with peanut allergy should avoid this product.",
    },
    "tree_nuts": {
        "aliases": ["almond", "almonds", "cashew", "cashews", "walnut", "walnuts",
                     "pistachio", "pistachios", "hazelnut", "hazelnuts", "pecan",
                     "pecans", "macadamia", "brazil nut", "brazil nuts", "pine nut",
                     "pine nuts", "chestnut"],
        "label": "Tree Nuts",
        "info": "Tree nuts are a major food allergen. People with tree nut "
                "allergy should check the specific nut type listed.",
    },
    "soy": {
        "aliases": ["soy", "soya", "soybean", "soy protein", "soya bean",
                     "soy lecithin", "soy sauce", "tofu", "edamame"],
        "label": "Soy",
        "info": "Soy is a major food allergen. People with soy allergy should "
                "check the label carefully.",
    },
    "wheat": {
        "aliases": ["wheat", "wheat flour", "wheat starch", "wheat gluten",
                     "semolina", "spelt", "durum", "bulgur", "couscous"],
        "label": "Wheat / Gluten",
        "info": "Wheat contains gluten and is a major food allergen. People with "
                "coeliac disease, gluten sensitivity, or wheat allergy should "
                "check the label carefully.",
    },
    "gluten": {
        "aliases": ["gluten", "wheat gluten", "vital wheat gluten", "barley",
                     "rye", "oats", "malt", "malt extract", "brewer's yeast"],
        "label": "Gluten",
        "info": "Gluten is found in wheat, barley and rye. People with coeliac "
                "disease or gluten sensitivity should avoid or check this product.",
    },
    "fish": {
        "aliases": ["fish", "cod", "salmon", "tuna", "anchovy", "sardine",
                     "herring", "mackerel", "basa", "surimi", "fish sauce",
                     "fish oil", "fish gelatin"],
        "label": "Fish",
        "info": "Fish is a major food allergen. People with fish allergy should "
                "check the specific fish type listed.",
    },
    "shellfish": {
        "aliases": ["shrimp", "prawn", "prawns", "crab", "lobster", "crayfish",
                     "scampi", "oyster", "oysters", "mussel", "mussels",
                     "clam", "clams", "scallop", "scallops", "squid",
                     "calamari", "shellfish"],
        "label": "Shellfish / Crustaceans",
        "info": "Shellfish and crustaceans are major food allergens. People with "
                "shellfish allergy should check the label carefully.",
    },
    "sesame": {
        "aliases": ["sesame", "sesame seed", "sesame seeds", "sesame oil",
                     "tahini", "til"],
        "label": "Sesame",
        "info": "Sesame is a recognised food allergen in many countries. People "
                "with sesame allergy should check the label carefully.",
    },
    "celery": {
        "aliases": ["celery", "celery seed", "celery salt", "celeriac"],
        "label": "Celery",
        "info": "Celery is a recognised allergen in the EU and must be declared. "
                "People with celery allergy should check the label.",
    },
    "mustard": {
        "aliases": ["mustard", "mustard seed", "mustard powder", "mustard oil",
                     "mustard flour"],
        "label": "Mustard",
        "info": "Mustard is a recognised allergen in the EU and must be declared. "
                "People with mustard allergy should check the label.",
    },
    "lupin": {
        "aliases": ["lupin", "lupin flour", "lupini", "lupini beans"],
        "label": "Lupin",
        "info": "Lupin is a recognised allergen in the EU. People with lupin "
                "allergy should check the label carefully.",
    },
    "sulphites": {
        "aliases": ["sulphite", "sulfite", "sulphites", "sulfites",
                     "sodium sulphite", "sodium sulfite", "sodium metabisulfite",
                     "potassium metabisulfite", "sodium bisulfite",
                     "sodium hydrogen sulfite", "e220", "e221", "e222",
                     "e223", "e224", "e226", "e227", "e228"],
        "label": "Sulphites / Sulfites",
        "info": "Sulphites can trigger allergic and asthmatic reactions in "
                "sensitive individuals. Mandatory disclosure above a threshold.",
    },
    "corn": {
        "aliases": ["corn", "corn starch", "corn flour", "corn syrup",
                     "corn oil", "maize", "maize flour", "high fructose corn syrup"],
        "label": "Corn",
        "info": "Corn allergy exists but is less common. People with corn "
                "allergy should check the label carefully.",
    },
}

# Index allergens by normalized alias for fast lookup.
_ALLERGEN_INDEX = {}


def _detect_allergens(ingredients: list) -> list:
    """Detect common allergens from parsed ingredient list.

    Returns a list of dicts: {allergen_key, label, detected_from, info}.
    """
    detected = []
    seen_keys = set()
    for ing in ingredients:
        norm = ing.get("normalized", "")
        if not norm:
            continue
        # Direct match
        allergen_key = _ALLERGEN_INDEX.get(norm)
        if not allergen_key:
            # Try partial match for multi-word ingredient names
            for alias_norm, akey in _ALLERGEN_INDEX.items():
                if alias_norm in norm or norm in alias_norm:
                    allergen_key = akey
                    break
        if allergen_key and allergen_key not in seen_keys:
            seen_keys.add(allergen_key)
            entry = COMMON_ALLERGENS[allergen_key]
            detected.append({
                "allergen_key": allergen_key,
                "label": entry["label"],
                "detected_from": ing.get("name", ""),
                "info": entry["info"],
            })
    return detected


# --------------------------------------------------------------------------- #
# Edible / Non-edible classification
# --------------------------------------------------------------------------- #

# Non-food category keywords that strongly indicate the product is NOT edible.
_NON_EDIBLE_CLUES = [
    r"shampoo", r"conditioner", r"hair\s*(care|oil|mask|serum|cream)",
    r"face\s*(wash|cream|pack|mask|scrub|serum|moisturiz|lotion|toner)",
    r"body\s*(wash|lotion|cream|spray|scrub|polish|butter)",
    r"moisturiz", r"sunscreen", r"sun\s*block", r"spf",
    r"lip\s*(balm|stick|gloss|liner|stick|care)",
    r"deodorant", r"antiperspirant",
    r"soap", r"bath\s*(bomb|salt|oil|foam|gel)",
    r"lotion", r"cream\s*(for|to|on|apply)",
    r"ointment", r"balm", r"salve",
    r"toothpaste", r"dental", r"mouthwash", r"floss",
    r"hand\s*(wash|sanitizer|sanitiser|cream|gel)",
    r"disinfect", r"antiseptic", r"cleaner", r"detergent",
    r"laundry", r"fabric\s*(softener|conditioner|wash)",
    r"floor\s*cleaner", r"glass\s*cleaner", r"bathroom\s*cleaner",
    r"toilet\s*(cleaner|block|freshener)",
    r"bleach", r"ammonia", r"solvent",
    r"insecticide", r"pesticide", r"herbicide", r"fungicide",
    r"engine\s*oil", r"brake\s*fluid", r"coolant", r"lubricant",
    r"battery", r"charger", r"adapter", r"earphone", r"headphone",
    r"for\s*external\s*use", r"not\s*(for|to)\s*(eat|drink|ingest|consume)",
    r"do\s*not\s*(swallow|ingest|drink|eat)", r"avoid\s*contact\s*with\s*(eyes|skin)",
    r"keep\s*out\s*of\s*reach\s*of\s*children",
    r"poison", r"hazard", r"corrosive", r"flammable",
    r"cosmetic", r"makeup", r"make-up", r"foundation", r"lipstick", r"mascara",
    r"nail\s*(polish|paint|remover|file|cutter)",
    r"perfume", r"eau\s*de", r"cologne",
    r"pet\s*(shampoo|wash|food|care|litter|scratch)",
    r"baby\s*(lotion|shampoo|wash|oil|powder|cream|diaper|nappy)",
    r"diaper", r"nappy", r"wipe",
    r"shaving\s*(cream|gel|foam|soap|lotion)",
    r"after\s*shave", r"pre\s*shave",
    r"tan\s*(lotion|cream|oil|spray| accelerator)",
    r"hair\s*(dye|color|colour|remover|straightener|relaxer|perm)",
    r"chemical\s*peel", r"retinol", r"retinoid",
]

# Non-food category words from the product categories.
_NON_EDIBLE_CATEGORIES = {
    "cosmetic", "skincare", "haircare", "personal care", "soap", "toothpaste",
    "household cleaner", "disinfectant", "sanitizer", "laundry", "chemical",
    "electronics", "battery", "stationery", "agricultural", "automotive",
}

_EDIBLE_CATEGORIES = {"food", "beverage", "snack", "supplement"}


def _classify_edible_status(category: str, combined: str, consumption_status: str = None) -> dict:
    """Classify whether a product is edible, non-edible, or uncertain.

    Returns: {status: "edible"|"non_edible"|"uncertain", label: str, reason: str}
    """
    text = (combined or "").lower()
    status_consumption = (consumption_status or "").lower()

    # If we have a verified product with consumption status, use it.
    if status_consumption:
        if "intended for human consumption" in status_consumption:
            return {"status": "edible", "label": "Edible",
                    "reason": "This product is intended for human consumption."}
        if "not intended for human consumption" in status_consumption:
            return {"status": "non_edible", "label": "Non-Edible",
                    "reason": "This product is NOT intended for human consumption."}
        if "external use only" in status_consumption:
            return {"status": "non_edible", "label": "Non-Edible",
                    "reason": "This product is intended for external/non-food use and should not be consumed."}
        if "household" in status_consumption or "industrial" in status_consumption:
            return {"status": "non_edible", "label": "Non-Edible",
                    "reason": "This product is intended for household/industrial use and should not be consumed."}

    # Category-based classification.
    if category in _EDIBLE_CATEGORIES:
        return {"status": "edible", "label": "Edible",
                "reason": "This product belongs to a food/beverage category."}
    if category in _NON_EDIBLE_CATEGORIES:
        return {"status": "non_edible", "label": "Non-Edible",
                "reason": "This product is intended for external/non-food use and should not be consumed."}

    # OCR-text-based detection for non-edible products.
    non_edible_score = 0
    edible_score = 0
    for pattern in _NON_EDIBLE_CLUES:
        if re.search(pattern, text, re.IGNORECASE):
            non_edible_score += 1
    # Positive edible signals.
    _edible_patterns = [
        r"nutrition\s*facts", r"serving\s*size", r"calories?\s*per",
        r"best\s*before", r"best-before", r"use\s*by",
        r"net\s*(wt|weight)", r"edible", r"food", r"beverage",
        r"taste", r"flavour", r"flavor", r"delicious", r"recipe",
        r"snack", r"meal", r"eat", r"drink", r"cook", r"bake",
    ]
    for pattern in _edible_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            edible_score += 1

    if non_edible_score >= 2 and non_edible_score > edible_score:
        return {"status": "non_edible", "label": "Non-Edible",
                "reason": "This product is intended for external/non-food use and should not be consumed."}
    if edible_score >= 2 and edible_score > non_edible_score:
        return {"status": "edible", "label": "Edible",
                "reason": "This product appears to be a food or beverage product."}

    return {"status": "uncertain", "label": "Uncertain",
            "reason": "Unable to confidently determine whether this product is edible from the available information."}


# Usage purpose mappings.
_USAGE_PURPOSE_MAP = {
    "food": "Food / Beverage",
    "beverage": "Food / Beverage",
    "snack": "Food / Beverage",
    "supplement": "Health / Supplement",
    "medicine": "Medicine / Health",
    "cosmetic": "Face / Skin",
    "skincare": "Face / Skin",
    "haircare": "Hair",
    "personal care": "Body",
    "soap": "Body / Hygiene",
    "toothpaste": "Oral Care",
    "baby": "Baby Care",
    "pet": "Pet Care",
    "household cleaner": "Household Cleaning",
    "disinfectant": "Household Cleaning",
    "sanitizer": "Hygiene / Sanitization",
    "laundry": "Household / Laundry",
    "chemical": "Household / Chemical",
    "electronics": "Electronics / Other",
    "battery": "Electronics / Other",
    "stationery": "Office / Stationery",
    "agricultural": "Agricultural / Other",
    "automotive": "Automotive / Other",
    "other": "Other",
    "unknown": "Unknown",
}


def _get_usage_purpose(category: str) -> str:
    """Return a human-readable usage purpose for the product."""
    return _USAGE_PURPOSE_MAP.get(category, "Unknown")


# --------------------------------------------------------------------------- #
# Product identity helpers (brand detection + user-facing name + use)
# --------------------------------------------------------------------------- #

# Well-known consumer brands recognised from OCR text. Matching is always
# word-boundary based, so "dove" never matches inside "handove".
_COMMON_BRANDS = [
    "dettol", "savlon", "lizol", "colonel", "harpic", "colgate", "closeup",
    "sensodyne", "nivea", "dove", "vaseline", "ponds", "garnier", "loreal",
    "l'oreal", "mamaearth", "cetaphil", "himalaya", "patanjali", "coca cola",
    "pepsi", "coke", "sprite", "fanta", "maggi", "lays", "kurkure", "amul",
    "parle", "britannia", "tropicana", "red bull", "monster", "nestle",
    "cadbury", "oreo", "head & shoulders", "sunsilk", "clinic plus", "rexona",
    "tide", "ariel", "surf excel", "vanish", "comfort", "daz", "lifebuoy",
    "savlon", "seabreeze", "tata", "bajaj", "samsung", "apple", "nokia",
]


def _find_brand(combined: str) -> str | None:
    """Return a recognised brand name present in the label text, or None."""
    if not combined:
        return None
    low = combined.lower()
    for brand in _COMMON_BRANDS:
        pattern = r"(?<![a-z0-9&])" + re.escape(brand) + r"(?![a-z0-9&])"
        if re.search(pattern, low):
            return brand.title()
    return None


def _is_ingredient_phrase(line: str) -> bool:
    """True if a short line is itself a bare known ingredient (e.g. 'Aqua')."""
    if not line:
        return False
    if len(line.split()) > 3:
        return False
    return lookup_ingredient(line) is not None


def _category_descriptor(category: str) -> str:
    """A short product descriptor used when only the brand is identifiable."""
    return {
        "food": "Food Product",
        "beverage": "Drink",
        "snack": "Snack Product",
        "supplement": "Supplement",
        "medicine": "Medicinal Product",
        "cosmetic": "Cosmetic Product",
        "skincare": "Skincare Product",
        "haircare": "Haircare Product",
        "personal care": "Personal Care Product",
        "soap": "Soap",
        "toothpaste": "Toothpaste",
        "baby": "Baby Care Product",
        "pet": "Pet Care Product",
        "household cleaner": "Cleaning Product",
        "disinfectant": "Hygiene / Antiseptic Product",
        "sanitizer": "Sanitising Product",
        "laundry": "Laundry Product",
        "chemical": "Chemical Product",
        "electronics": "Electronic Product",
        "battery": "Battery",
        "stationery": "Stationery Product",
        "agricultural": "Agricultural Product",
        "automotive": "Automotive Product",
    }.get(category, "Product")


def _extract_product_name(combined: str, brand: str | None = None, category: str = "") -> str | None:
    """Best-effort product name from the label text.

    Priority:
      1. A short line that contains a recognised brand AND extra words
         (e.g. "Dettol Wet Wipes").
      2. A line carrying a product-name descriptor / category phrase
         (e.g. "READY-TO-EAT SAVOURIES", "Potato Wafers").
      3. The first usable short line that is not itself an ingredient and is
         not OCR garbage (stray digits, fragments, "Oee", "P0g4ted48495").
      4. Brand + category descriptor (e.g. "Dettol Hygiene / Antiseptic Product").

    OCR garbage at the top of a scanned label must never win the product name
    just because it appears first.
    """
    if not combined:
        return None
    candidates = []
    for line in combined.splitlines():
        line = line.strip()
        if not (3 <= len(line) <= 80):
            continue
        if "," in line or ";" in line:
            continue
        low = line.lower()
        if low.startswith("ingredient") or low.startswith("contains"):
            continue
        candidates.append(line)

    def ocr_garbage(line: str) -> bool:
        # A plausible product-name line needs real words - a bare jumble of
        # digits / fragments ("Oee", "P0g4ted48495") is OCR noise.
        if not line:
            return True
        alpha = sum(1 for c in line if c.isalpha())
        digit = sum(1 for c in line if c.isdigit())
        compact = re.sub(r"\s", "", line)
        if not compact:
            return True
        if alpha < 3:
            return True
        if digit >= alpha:                     # digit-dominated -> OCR fragment
            return True
        # A long uninterrupted run of digits (e.g. "P0g4ted48495") is
        # characteristic of OCR corruption on a real product-name line.
        if re.search(r"\d{4,}", line):
            return True
        words = [w for w in re.split(r"[^a-z]+", line.lower()) if w]
        if not words:
            return True
        if alpha < len(compact) * 0.5 and digit > 0:
            return True
        return False

    # Lines that are label meta-data (manufacturer, net weight, serving info,
    # contact) must never be chosen as the product name.
    _META_RE = re.compile(
        r"\b("
            r"manufactur\w*\s+by"            # "manufactured by" (+ OCR variants)
            r"|manu\w*\s+by"                 # "Manulactured by" (OCR typo)
            r"|made\s+in"
            r"|mfd"
            r"|distribut\w*\s+by"
            r"|pack(?:aged?|ing)?\s+by"
            r"|imported\s+by"
            r"|net\s*\.?\s*(?:wt|weight)"
            r"|serving\s*(?:size)?"
            r"|best\s+before"
            r"|use\s+by"
            r"|store\s+in"
            r"|www\."
            r"|customer\s+care"
            r"|toll\s*free"
            r"|batch\s*no"
            r"|mrp"
            r"|contact\s+"
            r"|e\.?mail"
            r"|allergen\s+advice"
            r"|nutritional?\s*information"
            r"|ingredients?\s*(?:advice|declaration|information)?\b"
            r"|may\s+contain"
            r"|serving\s+size"
            r"|storage\s*(?:conditions|instructions)?"
        r")\b",
        re.IGNORECASE,
    )

    def is_label_meta(line: str) -> bool:
        return bool(_META_RE.search(line))

    # Candidate lines carrying a product descriptor / category phrase. Matching
    # is done on each comma/semicolon-separated fragment so a descriptor like
    # "POTATO WAFERS" or "READY-TO-EAT SAVOURIES" counts even when it shares a
    # line with OCR noise.
    descriptor_phrases = [
        "ready-to-eat", "ready to eat", "savoury", "savouries", "snack", "crisps",
        "chips", "wafers", "biscuit", "cookie", "cheese", "chocolate", "juice",
        "drink", "noodles", "ketchup", "sauce", "pickle", "spread", "oil",
        "flour", "atta", "rice", "paneer", "butter", "ghee", "shampoo", "soap",
        "cream", "lotion", "toothpaste", "cleaner", "detergent", "disinfectant",
        "food", "snack product",
    ]
    # First pass: a clean, non-garbage fragment containing a descriptor wins.
    # Long fragments (>60 chars) are almost never a real product name — they are
    # merged ingredient lines or similar OCR noise.
    best_desc = None
    for line in combined.splitlines():
        for frag in re.split(r"[,;]", line):
            frag = frag.strip(" .-–—\t")
            if not frag or len(frag) > 60 \
                    or ocr_garbage(frag) or _is_ingredient_phrase(frag) \
                    or is_label_meta(frag):
                continue
            low = frag.lower()
            if any(phrase in low for phrase in descriptor_phrases):
                # Prefer the most specific (longest) descriptor fragment.
                score = len(frag)
                if best_desc is None or score > best_desc[0]:
                    best_desc = (score, frag)
    if best_desc:
        return best_desc[1]

    for line in candidates:
        if len(line) > 60:                    # merged ingredient line, not a name
            continue
        low = line.lower()
        if ocr_garbage(line) or is_label_meta(line):
            continue
        if any(phrase in low for phrase in descriptor_phrases) \
                and not _is_ingredient_phrase(line):
            return line

    if brand:
        brand_norm = _norm(brand)
        for line in candidates:
            if len(line) > 60 or ocr_garbage(line) or is_label_meta(line):
                continue
            if brand_norm in _norm(line) and len(_norm_words(line).split()) >= 2 and not _is_ingredient_phrase(line):
                return line
    for line in candidates:
        if len(line) > 60 or ocr_garbage(line) or is_label_meta(line):
            continue
        if _is_ingredient_phrase(line):
            continue
        if re.match(r"^(ingredients?|ingredient\s+list|contains?|content)\b", line.lower()):
            continue
        return line
    if brand:
        return f"{brand} {_category_descriptor(category)}"
    return None


# Intended-use sentences keyed by OCR signals actually found on the label.
_INTENDED_USE_SIGNALS = [
    (r"\bwipe(?:s|r)?\b", "Used for cleaning, wiping and hygiene purposes. Follow the instructions on the product label."),
    (r"\bshampoo\b|\bhair\s*(?:wash|care|conditioner)\b", "Used for cleansing and caring for the hair. Follow the directions on the label."),
    (r"\bdish\s*wash\b|\bhand\s*wash\b|\bcleanser\b|\bface\s*wash\b", "Used for cleaning. Rinse after use and keep away from the eyes."),
    (r"\bdetergent\b|\blaundry\b|\bfabric\b", "Used for washing clothes and fabrics. Keep away from children and do not consume."),
    (r"\btoothpaste\b|\b(?:oral|dental|mouth)\s*(?:care|wash|rinse)\b", "Used for oral care. Brush/rinse as directed and do not swallow."),
    (r"\bsanitize?r?\b|\bsanitis(?:e|ing)\b", "Used to reduce germs on the hands or surfaces. Do not consume."),
    (r"\bdisinfect(?:ant?|ing)?\b|\bantiseptic\b", "Used for disinfection and hygiene purposes. Use as printed on the label and keep away from children."),
    (r"\bsoap\b|\bbody\s*wash\b|\bshower\s*gel\b|\bbath\b", "Used for personal cleansing. For external use only."),
    (r"\bdeodorant\b|\bantiperspirant\b", "Used as a personal hygiene product to reduce body odour. For external use only."),
    (r"\bbaby\b|\bnewborn\b|\binfant\b", "Baby care product. Use as directed on the label and keep out of reach of children."),
    (r"\bpet\b|\bdog\b|\bcat\b", "Pet care product. Use only as directed for the target animal."),
    (r"\bshampoo\b.*\bpet\b|\bpet\s*shampoo\b", "Used for bathing pets. Not intended for human use."),
]


def _intended_use_description(category: str, combined: str, edible_status: dict | None = None) -> str:
    """A plain-language sentence explaining the product's likely intended use."""
    text = (combined or "").lower()
    status = (edible_status or {}).get("status")

    if status == "edible" and category in (_EDIBLE_CATEGORIES | {"medicine"}):
        return ("This is a food/beverage product intended for human consumption. "
                "Check the label for serving and storage instructions.")

    for pattern, sentence in _INTENDED_USE_SIGNALS:
        if re.search(pattern, text):
            return sentence

    base = {
        "food": "Food product intended for consumption. Check the label for serving and storage instructions.",
        "beverage": "Beverage intended for drinking. Check the label for storage instructions.",
        "snack": "Packaged snack intended for consumption.",
        "supplement": "Dietary supplement. Take only as directed on the label.",
        "medicine": "Medicinal product. Use only as directed by a doctor or the label.",
        "cosmetic": "Cosmetic product for external application. Not intended for ingestion.",
        "skincare": "Skincare product for external application. Not intended for ingestion.",
        "haircare": "Hair care product. For external use only.",
        "personal care": "Personal care / hygiene product. For external use only.",
        "soap": "Personal cleansing product. For external use only.",
        "toothpaste": "Oral care product. Use as directed and do not swallow.",
        "baby": "Baby care product. Use as directed on the label.",
        "pet": "Pet care product. Use as directed for the target animal.",
        "household cleaner": "Household cleaning product. Use in a ventilated area and do not consume.",
        "disinfectant": "Disinfectant / antiseptic product. Use as printed on the label and keep away from children.",
        "sanitizer": "Hygiene / sanitising product. Do not consume.",
        "laundry": "Laundry product. Use as directed; keep away from children.",
        "chemical": "Chemical product. Handle with care and read all hazard warnings.",
        "electronics": "Electronic device / accessory. Follow the safety and usage instructions.",
        "battery": "Battery. Do not recharge (unless marked), do not dispose of in fire.",
        "stationery": "Stationery product.",
        "agricultural": "Agricultural product. Read and follow all label directions.",
        "automotive": "Automotive product. Read and follow all label directions.",
        "other": "General consumer product. Follow the instructions on the label.",
        "unknown": "General consumer product. The intended use could not be confidently "
                   "determined from the available information.",
    }
    return base.get(category, "General consumer product. Follow the instructions on the product label.")


# --------------------------------------------------------------------------- #
# Enhanced Trust Score Calculator
# --------------------------------------------------------------------------- #

def calculate_enhanced_trust_score(
    counts: dict,
    total: int,
    category: str,
    edible_status: str,
    allergen_warnings: list,
    ocr_conf: int,
    database_match: str,
    from_image: bool,
    extracted_text: str,
    product_info: dict = None,
    certifications: list = None,
    claim_consistency: list = None,
    missing_mandatory: list = None,
) -> dict:
    """Weighted trust score: ingredient safety (40%), label completeness (25%),
    certification authenticity (20%), claim-vs-ingredient consistency (15%)."""
    higher = counts.get("higher", 0)
    moderate = counts.get("moderate", 0)
    low = counts.get("low", 0)
    unknown = counts.get("unknown", 0)
    total = max(0, total)
    unknown_ratio = (unknown / total) if total else 0
    certifications = certifications or []
    claim_consistency = claim_consistency or []
    missing_mandatory = missing_mandatory or []
    why = []

    # ---- Component 1: Ingredient Safety (40%) ---- #
    if total > 0:
        classified = low + moderate + higher
        classified_ratio = classified / total if total else 0
        if higher > 0:
            penalty = min(higher * 15, 50)
            ingredient_score = max(10, 50 - penalty)
            why.append(
                f"{higher} higher-concern ingredient{'s' if higher != 1 else ''} "
                "detected (restricted/banned or strong evidence of harm)."
            )
        elif moderate > 0:
            ratio = moderate / total
            ingredient_score = max(30, 90 - int(ratio * 60) - (moderate * 5))
            why.append(
                f"{moderate} moderate-concern ingredient{'s' if moderate != 1 else ''} "
                "detected (allowed but with real caveats)."
            )
        elif unknown_ratio > 0.5:
            ingredient_score = 50
            why.append(
                "More than half of the ingredients could not be classified — "
                "too little information for a firm safety assessment."
            )
        else:
            ingredient_score = 95 if unknown == 0 else 85
            why.append("No higher- or moderate-concern ingredients were detected.")
            if unknown:
                why.append(
                    f"{unknown} unknown ingredient{'s' if unknown != 1 else ''} — "
                    "marked unknown, not dangerous."
                )
    else:
        ingredient_score = 30
        why.append("No ingredient list could be read or parsed.")

    # ---- Component 2: Label Completeness & Compliance (25%) ---- #
    if missing_mandatory is not None and total > 0:
        mandatory_fields = _MANDATORY_INFO.get(category, _MANDATORY_INFO.get("food", []))
        required_count = sum(1 for f in mandatory_fields if f.get("required"))
        missing_count = len(missing_mandatory)
        if required_count > 0:
            present_ratio = max(0, (required_count - missing_count) / required_count)
            label_score = int(present_ratio * 100)
        else:
            label_score = 80
        if missing_mandatory:
            why.append(
                f"Missing {len(missing_mandatory)} required label field(s): "
                + ", ".join(missing_mandatory[:3])
                + ("..." if len(missing_mandatory) > 3 else "")
                + "."
            )
    elif total > 0:
        label_score = 70
    else:
        label_score = 30

    # ---- Component 3: Certification Authenticity (20%) ---- #
    if certifications:
        detected_certs = [c for c in certifications if c.get("detected")]
        not_detected = [c for c in certifications if not c.get("detected")]
        if detected_certs:
            cert_score = min(100, 60 + len(detected_certs) * 15)
            why.append(
                f"{len(detected_certs)} certification(s) detected on label: "
                + ", ".join(c["name"] for c in detected_certs[:3]) + "."
            )
        else:
            cert_score = 30
            why.append("No expected certification marks were detected on the label.")
        if not_detected:
            why.append(
                f"{len(not_detected)} expected certification(s) not found: "
                + ", ".join(c["name"] for c in not_detected[:3]) + "."
            )
    else:
        cert_score = 50

    # ---- Component 4: Claim-vs-Ingredient Consistency (15%) ---- #
    if claim_consistency:
        inconsistent = [c for c in claim_consistency if c.get("status") == "inconsistent"]
        consistent = [c for c in claim_consistency if c.get("status") == "consistent"]
        if inconsistent:
            claim_score = max(10, 50 - len(inconsistent) * 20)
            for inc in inconsistent:
                why.append(
                    f"Claim '{inc['claim']}' is INCONSISTENT with ingredients: "
                    + inc.get("reason", "")
                )
        elif consistent:
            claim_score = min(100, 70 + len(consistent) * 10)
            why.append("Label claims are consistent with the listed ingredients.")
        else:
            claim_score = 60
    else:
        claim_score = 60

    # ---- Weighted final score ---- #
    score = int(
        ingredient_score * 0.40
        + label_score * 0.25
        + cert_score * 0.20
        + claim_score * 0.15
    )

    # ---- OCR quality adjustment ---- #
    ocr_penalty = 0
    if from_image and not extracted_text:
        ocr_penalty = 10
        why.append("Score reduced by 10 — image quality insufficient for reliable OCR.")
    elif from_image and extracted_text and len(extracted_text) < 40:
        ocr_penalty = 5
        why.append("Score reduced by 5 — limited text extracted from image.")
    score = max(0, min(100, score - ocr_penalty))

    # ---- Database match note ---- #
    if database_match in ("High", "Medium"):
        why.append(
            f"Verified product database match ({database_match} confidence) — "
            "ingredient data cross-referenced with reference records."
        )
    elif database_match == "None":
        why.append("Product not found in verified database — score based on ingredient analysis only.")

    # ---- Allergen note ---- #
    if allergen_warnings:
        why.append(
            f"{len(allergen_warnings)} allergen{'s' if len(allergen_warnings) != 1 else ''} "
            "detected — allergy warning shown to the user."
        )

    # ---- Non-food adjustment ---- #
    if edible_status.get("status") == "non_edible" and higher == 0 and moderate == 0:
        score = max(score, 80)
        why.append("Non-food product with no higher- or moderate-concern ingredients for external use.")

    # ---- Insufficient info override ---- #
    if total == 0 or (unknown_ratio > 0.5 and total > 0):
        score = 50

    # ---- Risk level classification ---- #
    if score >= 80:
        risk_level = "low"
        risk_label = "LOW RISK"
    elif score >= 60:
        risk_level = "moderate"
        risk_label = "MODERATE RISK"
    elif score >= 40:
        risk_level = "moderate"
        risk_label = "MODERATE RISK"
    elif score >= 20:
        risk_level = "higher"
        risk_label = "HIGH RISK"
    else:
        risk_level = "higher"
        risk_label = "VERY HIGH RISK"

    # ---- Clamp into display band ---- #
    status = classify(score)
    score = remap_score_to_band(score, status)

    # ---- Overall status / verdict ---- #
    if score >= 70:
        overall_status = "Safe"
    elif score >= 40:
        overall_status = "Use with Caution"
    else:
        overall_status = "Not Recommended"

    # ---- Recommendation ---- #
    if higher > 0:
        recommendation = (
            "Avoid this product. It contains ingredient(s) of genuine concern "
            "that are restricted or banned in some jurisdictions."
        )
    elif moderate > 0 and higher == 0:
        recommendation = (
            "Use with caution. Some ingredients require attention; "
            "check the detailed analysis above."
        )
    elif unknown_ratio > 0.5:
        recommendation = (
            "Insufficient information for a reliable assessment. "
            "Provide the full ingredient list or a clearer label image."
        )
    elif total > 0:
        if allergen_warnings:
            allergen_names = ", ".join(a["label"] for a in allergen_warnings[:3])
            recommendation = (
                f"Generally suitable based on available information. "
                f"Allergy note: contains {allergen_names} — "
                "people with the relevant allergies should check the label."
            )
        else:
            recommendation = (
                "Generally suitable based on available information. "
                "No major ingredient concern was detected."
            )
    else:
        recommendation = "Insufficient information for a reliable assessment."

    # ---- Explanation ---- #
    if total == 0:
        explanation = (
            "Unable to confidently determine the result from the available information. "
            "No ingredient list could be read or parsed."
        )
    elif higher > 0:
        explanation = (
            f"Several ingredients require caution. {higher} higher-concern "
            f"ingredient{'s' if higher != 1 else ''} were detected that are restricted "
            "or banned in some jurisdictions."
        )
    elif moderate > 0:
        explanation = (
            f"{moderate} moderate-concern ingredient{'s' if moderate != 1 else ''} detected. "
        )
        if allergen_warnings:
            explanation += (
                f"Allergen(s) detected ({', '.join(a['label'] for a in allergen_warnings[:3])}). "
            )
        explanation += "Users with specific allergies or dietary restrictions should check the complete label."
    elif unknown_ratio > 0.5:
        explanation = (
            "Most identified ingredients could not be classified from the built-in database. "
            "The Trust Score is therefore based only on the ingredients that could be identified. "
            "This does not mean the product is unsafe — it means information is insufficient."
        )
    else:
        explanation = (
            f"The detected ingredients are commonly associated with "
            f"{_category_label(category).lower()} products. "
            "No major ingredient concern was identified from the available information."
        )
        if unknown:
            explanation += (
                f" {unknown} ingredient{'s' if unknown != 1 else ''} could not be "
                "reliably classified — unknown does not mean harmful."
            )

    return {
        "score": score,
        "risk_level": risk_level,
        "risk_label": risk_label,
        "overall_status": overall_status,
        "recommendation": recommendation,
        "why": why,
        "explanation": explanation,
        "score_explanation": f"Trust Score: {score}/100 — {overall_status}.",
    }


INGREDIENT_KB = {
    # ---- Food colours -------------------------------------------------------
    "tartrazine": {
        "aliases": ["tartrazine", "e102", "yellow 5", "fd&c yellow no. 5", "fd&c yellow 5", "ci 19140"],
        "category": "moderate",
        "use": "Synthetic yellow food colour (azo dye)",
        "info": "Approved in the EU and US, but the EU requires it to carry the "
                "warning 'may have an adverse effect on activity and attention in children'. "
                "Can trigger allergic-type reactions in sensitive people.",
        "reason": "Approved but requires an allergy/hyperactivity warning label in the EU.",
        "source": ["European Food Safety Authority (EFSA)", "US FDA"],
    },
    "sunset yellow": {
        "aliases": ["sunset yellow", "sunset yellow fcf", "e110", "yellow 6", "fd&c yellow no. 6", "ci 15985"],
        "category": "moderate",
        "use": "Synthetic orange-yellow food colour",
        "info": "Approved additive. The EU requires a warning about effects on "
                "activity and attention in children.",
        "reason": "EU-mandated hyperactivity/attention warning label.",
        "source": ["European Food Safety Authority (EFSA)", "US FDA"],
    },
    "carmoisine": {
        "aliases": ["carmoisine", "azorubine", "e122"],
        "category": "moderate",
        "use": "Synthetic red food colour",
        "info": "Banned in some countries but permitted in the EU with the "
                "activity/attention warning label.",
        "reason": "Restricted in several jurisdictions; EU warning label required.",
        "source": ["European Food Safety Authority (EFSA)"],
    },
    "ponceau 4r": {
        "aliases": ["ponceau 4r", "e124"],
        "category": "moderate",
        "use": "Synthetic red food colour",
        "info": "EU-approved with the activity/attention warning label; banned in "
                "some countries.",
        "reason": "EU warning label required; not approved in several countries.",
        "source": ["European Food Safety Authority (EFSA)"],
    },
    "allura red": {
        "aliases": ["allura red", "allura red ac", "e129", "red 40", "fd&c red no. 40"],
        "category": "moderate",
        "use": "Synthetic red food colour",
        "info": "The most widely used red dye. Some studies link it to behavioural "
                "effects in children; the EU requires the hyperactivity warning label.",
        "reason": "EU hyperactivity/attention warning; contested behavioural studies.",
        "source": ["European Food Safety Authority (EFSA)", "US FDA"],
    },
    "brilliant blue": {
        "aliases": ["brilliant blue", "brilliant blue fcf", "e133", "blue 1", "fd&c blue no. 1"],
        "category": "low",
        "use": "Synthetic blue food colour",
        "info": "Widely used and considered low risk at approved levels.",
        "reason": "Generally recognised as safe at approved levels.",
        "source": ["European Food Safety Authority (EFSA)", "US FDA"],
    },
    "titanium dioxide": {
        "aliases": ["titanium dioxide", "e171", "tio2"],
        "category": "moderate",
        "use": "White colour / opacifier in foods, tablets and cosmetics",
        "info": "Banned as a food additive in the EU since 2022 (genotoxicity "
                "concerns); still permitted in the US and in many other countries.",
        "reason": "EU banned it as a food additive; elsewhere still permitted.",
        "source": ["European Food Safety Authority (EFSA)", "US FDA"],
    },
    # ---- Sweeteners ----------------------------------------------------------
    "aspartame": {
        "aliases": ["aspartame", "e951"],
        "category": "moderate",
        "use": "Intense artificial sweetener",
        "info": "WHO/IARC classified aspartame as Group 2B 'possibly carcinogenic to "
                "humans' (limited evidence) while JECFA/EFSA re-affirmed the existing "
                "acceptable daily intake. The evidence is contested and it remains "
                "approved worldwide.",
        "reason": "IARC Group 2B classification with limited evidence; regulatory "
                  "consensus still considers approved levels acceptable.",
        "source": ["WHO International Agency for Research on Cancer (IARC)", "JECFA", "EFSA", "US FDA"],
    },
    "acesulfame k": {
        "aliases": ["acesulfame k", "acesulfame potassium", "e950", "acesulfame-k", "acesulfame"],
        "category": "low",
        "use": "Artificial sweetener",
        "info": "Approved sweetener; considered acceptable within the ADI by "
                "regulators, sometimes used in blends with aspartame.",
        "reason": "Regulators consider approved levels acceptable.",
        "source": ["EFSA", "US FDA"],
    },
    "sucralose": {
        "aliases": ["sucralose", "e955"],
        "category": "low",
        "use": "Artificial sweetener (zero-calorie)",
        "info": "Widely used non-nutritive sweetener. Regulatory agencies consider "
                "it safe within the acceptable daily intake.",
        "reason": "Accepted as safe within the ADI by food-safety agencies.",
        "source": ["US FDA", "EFSA", "JECFA"],
    },
    "saccharin": {
        "aliases": ["saccharin", "saccharine", "e954"],
        "category": "low",
        "use": "Artificial sweetener",
        "info": "Historically linked to bladder tumours in high-dose rat studies. "
                "The US removed its warning label requirement (2000) and IARC lists "
                "it as Group 3 (not classifiable). Approved sweetener today.",
        "reason": "IARC Group 3; US delisted from carcinogen programme; approved.",
        "source": ["US FDA", "IARC (WHO)", "JECFA"],
    },
    "stevia": {
        "aliases": ["stevia", "steviol glycosides", "e960", "stevia extract", "rebaudioside a", "rebaudioside"],
        "category": "low",
        "use": "Plant-derived sweetener",
        "info": "Derived from the stevia plant; approved as a sweetener with an "
                "established ADI in the EU, US and other markets.",
        "reason": "Approved with an established ADI.",
        "source": ["EFSA", "US FDA", "JECFA"],
    },
    # ---- Preservatives -------------------------------------------------------
    "sodium benzoate": {
        "aliases": ["sodium benzoate", "e211"],
        "category": "moderate",
        "use": "Antimicrobial preservative",
        "info": "Common preservative. Can form small amounts of benzene when "
                "combined with ascorbic acid (vitamin C) in drinks - regulators "
                "limit levels for this reason. Also linked by some studies to "
                "behavioural effects in children.",
        "reason": "Benzene-formation risk with vitamin C; hyperactivity study "
                  "association; strictly regulated.",
        "source": ["EFSA", "US FDA"],
    },
    "potassium sorbate": {
        "aliases": ["potassium sorbate", "e202"],
        "category": "low",
        "use": "Antimicrobial preservative",
        "info": "Common, generally low-risk preservative used to inhibit mould "
                "and yeast.",
        "reason": "Generally recognised as safe at approved levels.",
        "source": ["EFSA", "US FDA"],
    },
    "sodium nitrite": {
        "aliases": ["sodium nitrite", "e250", "potassium nitrite", "e249"],
        "category": "higher",
        "use": "Preservative and colour-fixer in cured meats",
        "info": "Prevents bacterial growth (incl. botulism) but can form "
                "potentially carcinogenic nitrosamines during cooking. Regulators "
                "set strict permitted limits.",
        "reason": "Nitrosamine formation potential; strict statutory limits.",
        "source": ["WHO/JECFA", "EFSA", "US FDA"],
    },
    "sodium metabisulfite": {
        "aliases": ["sodium metabisulfite", "e223", "potassium metabisulfite", "e224", "sulphite", "sulfite", "sodium sulfite", "e221"],
        "category": "moderate",
        "use": "Preservative / antioxidant (dried fruit, wine)",
        "info": "Sulphites can trigger allergic and asthmatic reactions in "
                "sensitive individuals; labelling disclosure is mandatory when "
                "above a threshold.",
        "reason": "Well-documented allergen for sensitive people; mandatory disclosure.",
        "source": ["EFSA", "US FDA", "WHO/JECFA"],
    },
    # ---- Antioxidants ---------------------------------------------------------
    "bha": {
        "aliases": ["bha", "butylated hydroxyanisole", "e320"],
        "category": "higher",
        "use": "Antioxidant preservative (fats and oils)",
        "info": "IARC classifies BHA as Group 2B 'possibly carcinogenic to humans'. "
                "Permitted in many countries within strict limits and restricted "
                "in others.",
        "reason": "IARC Group 2B (possibly carcinogenic).",
        "source": ["IARC (WHO)", "EFSA", "US FDA"],
    },
    "bht": {
        "aliases": ["bht", "butylated hydroxytoluene", "e321"],
        "category": "moderate",
        "use": "Antioxidant preservative",
        "info": "Some animal studies raised concerns; regulators currently "
                "consider it acceptable at approved low levels.",
        "reason": "Contested animal-study evidence; approved at low levels.",
        "source": ["EFSA", "US FDA", "IARC (WHO)"],
    },
    "ascorbic acid": {
        "aliases": ["ascorbic acid", "vitamin c", "e300", "l-ascorbic acid"],
        "category": "low",
        "use": "Antioxidant / vitamin C",
        "info": "A water-soluble vitamin used as an antioxidant and nutrient.",
        "reason": "Essential nutrient; safe at normal levels.",
        "source": ["EFSA", "US FDA"],
    },
    "tocopherols": {
        "aliases": ["tocopherols", "vitamin e", "tocopherol", "e306", "e307", "e308", "e309"],
        "category": "low",
        "use": "Antioxidant / vitamin E",
        "info": "Natural vitamin E used to prevent fat oxidation.",
        "reason": "Essential nutrient; safe at normal levels.",
        "source": ["EFSA", "US FDA"],
    },
    # ---- Emulsifiers / thickeners ----------------------------------------------
    "lecithin": {
        "aliases": ["lecithin", "soy lecithin", "e322", "sunflower lecithin"],
        "category": "low",
        "use": "Emulsifier (blends oil and water)",
        "info": "A natural fat-based emulsifier derived from soy, sunflower or "
                "egg. Soy lecithin is a minor allergen source for soy-allergic "
                "people.",
        "reason": "Generally safe; possible trace soy allergen.",
        "source": ["EFSA", "US FDA"],
    },
    "xanthan gum": {
        "aliases": ["xanthan gum", "e415"],
        "category": "low",
        "use": "Thickener / stabiliser",
        "info": "Fermented polysaccharide used as a thickener. Large amounts can "
                "cause mild digestive discomfort.",
        "reason": "Safe at normal levels; mild digestive effects in excess.",
        "source": ["EFSA", "US FDA", "WHO/JECFA"],
    },
    "guar gum": {
        "aliases": ["guar gum", "e412"],
        "category": "low",
        "use": "Thickener / stabiliser",
        "info": "Plant-derived thickener widely used in foods.",
        "reason": "Safe at approved levels.",
        "source": ["EFSA", "US FDA"],
    },
    "carrageenan": {
        "aliases": ["carrageenan", "e407", "irish moss"],
        "category": "moderate",
        "use": "Thickener / gel agent (dairy and plant milks)",
        "info": "Approved food additive. Animal studies link some carrageenan "
                "forms to digestive inflammation, but regulators (EFSA/JECFA) "
                "consider food-grade carrageenan safe within limits. Consumer "
                "concern persists.",
        "reason": "Conflicting evidence: animal study concerns vs regulatory "
                  "approval at limits.",
        "source": ["EFSA", "WHO/JECFA", "US FDA"],
    },
    "mono and diglycerides": {
        "aliases": ["mono and diglycerides", "monoglycerides", "diglycerides", "e471", "mono- and diglycerides", "mono-diglycerides"],
        "category": "low",
        "use": "Emulsifier",
        "info": "Fat-derived emulsifiers; safe at normal use levels.",
        "reason": "Generally recognised as safe.",
        "source": ["EFSA", "US FDA"],
    },
    "sodium carboxymethyl cellulose": {
        "aliases": ["sodium carboxymethyl cellulose", "cmc", "e466", "carboxymethyl cellulose"],
        "category": "low",
        "use": "Thickener / stabiliser",
        "info": "Cellulose-derived thickener used widely.",
        "reason": "Safe at approved levels.",
        "source": ["EFSA", "US FDA"],
    },
    # ---- Acidity regulators / bases --------------------------------------------
    "citric acid": {
        "aliases": ["citric acid", "e330"],
        "category": "low",
        "use": "Acidity regulator / flavour",
        "info": "Naturally occurring acid found in citrus; safe at normal levels.",
        "reason": "Naturally occurring; safe at normal levels.",
        "source": ["EFSA", "US FDA"],
    },
    "sodium bicarbonate": {
        "aliases": ["sodium bicarbonate", "baking soda", "e500", "e500ii"],
        "category": "low",
        "use": "Raising agent / acidity regulator",
        "info": "Common kitchen leavening agent; safe in food amounts.",
        "reason": "Common food ingredient; safe in food amounts.",
        "source": ["EFSA", "US FDA"],
    },
    "trisodium phosphate": {
        "aliases": ["trisodium phosphate", "e339", "sodium phosphates", "sodium phosphate"],
        "category": "low",
        "use": "Acidity regulator / sequestrant",
        "info": "Phosphate additive. Safe within limits; very high dietary "
                "phosphate is a separate concern for kidney patients.",
        "reason": "Safe at approved levels for the general population.",
        "source": ["EFSA", "US FDA"],
    },
    # ---- Flavourings ------------------------------------------------------------
    "monosodium glutamate": {
        "aliases": ["monosodium glutamate", "msg", "e621"],
        "category": "low",
        "use": "Flavour enhancer",
        "info": "The sodium salt of glutamic acid, an amino acid. FDA and EFSA "
                "consider it safe at normal levels. A minority of people report "
                "sensitivity symptoms, which is not the same as toxicity.",
        "reason": "Regulatory consensus: safe at normal levels; occasional "
                  "reported sensitivity.",
        "source": ["US FDA", "EFSA", "WHO/JECFA"],
    },
    "vanillin": {
        "aliases": ["vanillin", "ethyl vanillin"],
        "category": "low",
        "use": "Vanilla flavour",
        "info": "Synthetic form of the vanilla flavour compound; safe at food levels.",
        "reason": "Widely used flavouring; safe at food levels.",
        "source": ["EFSA", "US FDA", "JECFA"],
    },
    "maltol": {
        "aliases": ["maltol", "e636", "maltol (e636)", "3-hydroxy-2-methyl-4-pyrone"],
        "category": "low",
        "use": "Flavour enhancer / sweet aroma (savoury snacks, desserts)",
        "info": "A naturally occurring pyrones compound that enhances sweetness and "
                "rounds out savoury flavours. Approved as a food flavouring in the "
                "EU, US and elsewhere at normal use levels.",
        "reason": "Widely approved flavouring; low concern at food levels.",
        "source": ["EFSA", "US FDA", "JECFA"],
    },
    "disodium guanylate": {
        "aliases": ["disodium guanylate", "e627", "ins 627", "sodium guanylate", "diguanylate"],
        "category": "low",
        "use": "Flavour enhancer (umami, often with MSG/IMP)",
        "info": "The sodium salt of guanosine monophosphate. Together with disodium "
                "inosinate it enhances savoury/umami taste. Regulatory bodies "
                "consider it safe at normal use levels; occasional reports of "
                "sensitivity exist but it is not a recognised allergen.",
        "reason": "Regulatory consensus: safe at normal use levels.",
        "source": ["EFSA", "US FDA", "JECFA"],
    },
    "disodium inosinate": {
        "aliases": ["disodium inosinate", "e631", "ins 631", "sodium inosinate", "diinosinate"],
        "category": "low",
        "use": "Flavour enhancer (umami, often with MSG)",
        "info": "The sodium salt of inosinic acid. It boosts savoury/umami flavour, "
                "frequently with disodium guanylate and MSG. Approved as safe at "
                "normal use levels across major regulators.",
        "reason": "Regulatory consensus: safe at normal use levels.",
        "source": ["EFSA", "US FDA", "JECFA"],
    },
    # ---- Caramel colours ---------------------------------------------------------
    "caramel colour": {
        "aliases": ["caramel colour", "caramel color", "e150", "e150a", "e150b", "e150c", "e150d", "plain caramel", "sulphite ammonia caramel", "ammonia caramel", "spirit caramel"],
        "category": "low",
        "use": "Brown colour (soft drinks, sauces)",
        "info": "The two ammonia-processed variants (E150c/E150d) can contain "
                "4-methylimidazole (4-MEI), which IARC classifies as Group 2B "
                "(possibly carcinogenic). California requires a warning above "
                "certain levels. The other variants are lower risk.",
        "reason": "Ammonia-processed types contain 4-MEI (IARC 2B); others are low.",
        "source": ["IARC (WHO)", "EFSA", "US FDA", "California OEHHA (Prop 65)"],
    },
    # ---- Cosmetic / skincare ingredients -------------------------------------------
    "methylparaben": {
        "aliases": ["methylparaben", "paraben", "parabens", "ethylparaben", "butylparaben", "propylparaben"],
        "category": "moderate",
        "use": "Cosmetic preservative",
        "info": "Parabens are effective preservatives but have weak oestrogenic "
                "activity; the EU restricts or bans propyl- and butylparaben in "
                "leave-on products for children under 3 and monitors them as "
                "endocrine disruptors.",
        "reason": "Endocrine-disruption concerns; EU restrictions on longer-chain parabens.",
        "source": ["EU Scientific Committee on Consumer Safety (SCCS)", "FDA"],
    },
    "sodium lauryl sulfate": {
        "aliases": ["sodium lauryl sulfate", "sodium lauryl sulphate", "sls", "sodium laureth sulfate", "sles"],
        "category": "low",
        "use": "Foaming / cleansing agent (shampoo, toothpaste, soap)",
        "info": "An effective detergent. Not a carcinogen; the main evidence-based "
                "issue is mild skin/eye irritation at higher concentrations.",
        "reason": "Mild irritant at concentration; no established carcinogenicity.",
        "source": ["US FDA", "Cosmetic Ingredient Review (CIR)"],
    },
    "propylene glycol": {
        "aliases": ["propylene glycol", "e1520", "propane-1,2-diol"],
        "category": "low",
        "use": "Humectant / solvent (cosmetics and food)",
        "info": "Holds moisture in products. Considered safe at the low "
                "concentrations used in cosmetics and food.",
        "reason": "Safe at normal use concentrations.",
        "source": ["US FDA", "Cosmetic Ingredient Review (CIR)"],
    },
    "fragrance": {
        "aliases": ["fragrance", "parfum", "perfume", "fragrance mix"],
        "category": "moderate",
        "use": "Scent (can cover dozens of undisclosed compounds)",
        "info": "Fragrance mixes can contain contact allergens and, in some "
                "markets, are disclosed only as 'fragrance'. EU regulations "
                "require listing of known allergens; some phthalates once common "
                "in fragrance are now restricted.",
        "reason": "Potential contact allergens; limited ingredient disclosure.",
        "source": ["EU Scientific Committee on Consumer Safety (SCCS)", "American Contact Dermatitis Society"],
    },
    "formaldehyde": {
        "aliases": ["formaldehyde", "dmdm hydantoin", "quaternium-15", "diazolidinyl urea", "imidazolidinyl urea", "formaldehyde releaser", "formaldehyde releasing preservatives"],
        "category": "higher",
        "use": "Preservative (or preservative that releases formaldehyde)",
        "info": "Formaldehyde is a recognised carcinogen (IARC Group 1) and contact "
                "allergen. Several preservatives release it slowly. Its direct use "
                "in cosmetics is banned/restricted in the EU.",
        "reason": "IARC Group 1 carcinogen; restricted in cosmetics in several regions.",
        "source": ["IARC (WHO)", "EU Scientific Committee on Consumer Safety (SCCS)"],
    },
    "phthalates": {
        "aliases": ["phthalate", "phthalates", "dbp", "dep", "dehp", "dibutyl phthalate", "diethyl phthalate"],
        "category": "higher",
        "use": "Plasticiser / fragrance fixative (restricted use)",
        "info": "Phthalates are endocrine-disrupting chemicals. DBP, DEP and DEHP "
                "are restricted or banned in cosmetics in the EU and in several "
                "other jurisdictions.",
        "reason": "Endocrine disruption; restricted/banned in cosmetics in the EU.",
        "source": ["EU", "US EPA", "IARC (WHO)"],
    },
    "triclosan": {
        "aliases": ["triclosan", "irgasan"],
        "category": "higher",
        "use": "Antimicrobial agent",
        "info": "The US FDA banned triclosan from over-the-counter consumer "
                "antiseptic washes (2016); concerns include endocrine disruption "
                "and antibiotic-resistance contributions.",
        "reason": "Banned from consumer antiseptic washes in the US; endocrine and "
                  "resistance concerns.",
        "source": ["US FDA", "WHO"],
    },
    "hydroquinone": {
        "aliases": ["hydroquinone", "1,4-benzenediol"],
        "category": "higher",
        "use": "Skin-lightening agent",
        "info": "Restricted or banned as a cosmetic ingredient in the EU and "
                "available by prescription in the US; overuse can cause "
                "ochronosis (permanent darkening) and there are carcinogenicity "
                "concerns.",
        "reason": "Restricted/banned in cosmetics; ochronosis and cancer concerns.",
        "source": ["EU Scientific Committee on Consumer Safety (SCCS)", "US FDA"],
    },
    # ---- Heavy metals / high-risk substances --------------------------------
    # Banned or strictly restricted in cosmetics and consumer products in most
    # jurisdictions because of well-documented toxicity.
    "mercury": {
        "aliases": ["mercury", "quicksilver", "mercury chloride", "mercuric chloride", "ammoniated mercury", "mercuric"],
        "category": "higher",
        "use": "Skin-lightening / antiseptic ingredient (banned or restricted use)",
        "info": "Mercury compounds are banned in cosmetics in the EU and "
                "restricted by the FDA because of kidney and nervous-system "
                "toxicity. Their presence on a label is a strong sign of a "
                "banned, substandard product.",
        "reason": "Banned in cosmetics in the EU; FDA-restricted; neurotoxin and "
                  "kidney toxin.",
        "source": ["EU Scientific Committee on Consumer Safety (SCCS)", "US FDA"],
    },
    "lead": {
        "aliases": ["lead", "lead acetate", "lead oxide", "lead sulfide", "lead carbonate"],
        "category": "higher",
        "use": "Contaminant or colouring agent (banned in cosmetics)",
        "info": "Lead compounds are banned or strictly limited in cosmetics and "
                "paints in most markets because lead is a cumulative neurotoxin, "
                "especially harmful to children.",
        "reason": "Lead compounds banned/restricted in cosmetics; neurotoxin.",
        "source": ["US FDA", "EU Scientific Committee on Consumer Safety (SCCS)"],
    },
    "arsenic": {
        "aliases": ["arsenic", "arsenic trioxide", "arsenic sulfide", "arsenic compound"],
        "category": "higher",
        "use": "Toxic element (banned as a cosmetic/food ingredient)",
        "info": "Arsenic is an IARC Group 1 carcinogen and is banned or "
                "stringently limited in consumer products. Its presence on a "
                "label indicates a substandard or counterfeit product.",
        "reason": "IARC Group 1 carcinogen; banned in consumer products.",
        "source": ["IARC (WHO)", "US FDA"],
    },
    # ---- Generic placeholder terms -------------------------------------------
    "preservative": {
        "aliases": ["preservative", "preservatives", "paraben mix", "preservative system"],
        "category": "moderate",
        "use": "Preservative (specific substance not identified)",
        "info": "A label listing only 'preservative' without naming the specific "
                "substance prevents a full safety check. Common preservatives "
                "range from low risk (potassium sorbate) to moderate or higher "
                "risk (parabens, formaldehyde releasers), so the generic term "
                "is treated as moderate concern pending identification.",
        "reason": "Specific preservative not disclosed; some preservatives carry "
                  "allergen, irritation or endocrine-disruption concerns.",
        "source": ["US FDA", "EU Scientific Committee on Consumer Safety (SCCS)"],
    },
    "benzoyl peroxide": {
        "aliases": ["benzoyl peroxide"],
        "category": "moderate",
        "use": "Acne treatment",
        "info": "Effective acne treatment but a strong skin irritant. FDA has "
                "proposed a warning about a possible cancer signal seen in animal "
                "tests; regulators consider it acceptable for short, controlled use.",
        "reason": "Effective but irritating; FDA animal-study cancer signal under review.",
        "source": ["US FDA", "American Academy of Dermatology"],
    },
    "salicylic acid": {
        "aliases": ["salicylic acid", "salicylate", "bha (skincare)"],
        "category": "low",
        "use": "Exfoliant / acne treatment",
        "info": "A beta-hydroxy acid used to treat acne and exfoliate. Effective "
                "and safe at cosmetic concentrations; can irritate sensitive skin.",
        "reason": "Safe at cosmetic concentrations; possible mild irritation.",
        "source": ["Cosmetic Ingredient Review (CIR)", "American Academy of Dermatology"],
    },
    "glycerin": {
        "aliases": ["glycerin", "glycerine", "glycerol", "e422"],
        "category": "low",
        "use": "Humectant (attracts moisture)",
        "info": "A simple, widely used moisturising humectant in cosmetics and foods.",
        "reason": "Safe at normal use levels.",
        "source": ["US FDA", "Cosmetic Ingredient Review (CIR)"],
    },
    "aloe vera": {
        "aliases": ["aloe vera", "aloe barbadensis", "aloe barbadensis leaf juice", "aloe extract", "aloe vera gel"],
        "category": "low",
        "use": "Skin soother / moisturiser",
        "info": "Widely used for soothing skin. Generally well tolerated; "
                "unprocessed aloe latex is different and laxative.",
        "reason": "Generally well tolerated topically.",
        "source": ["Cosmetic Ingredient Review (CIR)", "US FDA"],
    },
    "mineral oil": {
        "aliases": ["mineral oil", "liquid paraffin", "petrolatum", "petroleum jelly", "white petrolatum", "mineral oil (paraffinum liquidum)"],
        "category": "low",
        "use": "Occlusive moisturiser",
        "info": "Refined petroleum-derived oils are widely used and considered "
                "safe in cosmetics; cosmetic-grade material is highly refined.",
        "reason": "Cosmetic-grade refined mineral oils are considered safe.",
        "source": ["Cosmetic Ingredient Review (CIR)", "US FDA"],
    },
    "sodium hyaluronate": {
        "aliases": ["sodium hyaluronate", "hyaluronic acid", "hyaluronan"],
        "category": "low",
        "use": "Moisture-binding ingredient",
        "info": "A naturally occurring molecule in skin and joints; widely used "
                "and well tolerated in cosmetics.",
        "reason": "Naturally occurring; well tolerated.",
        "source": ["Cosmetic Ingredient Review (CIR)"],
    },
    "niacinamide": {
        "aliases": ["niacinamide", "vitamin b3", "nicotinamide"],
        "category": "low",
        "use": "Skin-repair / soothing ingredient",
        "info": "A form of vitamin B3 used in skincare; generally well tolerated.",
        "reason": "Generally well tolerated; useful vitamin.",
        "source": ["Cosmetic Ingredient Review (CIR)"],
    },
    "silicones": {
        "aliases": ["silicone", "silicones", "dimethicone", "cyclomethicone", "cyclotetrasiloxane", "d5", "cyclomethicone d5", "cyclopentasiloxane"],
        "category": "low",
        "use": "Smoothing / barrier ingredient",
        "info": "Create a smooth feel and water barrier. Some cyclic silicones "
                "(e.g. D5) are being phased out in Europe over environmental "
                "persistence concerns, not human-safety concerns.",
        "reason": "Safe for skin use; some cyclic types restricted on environmental grounds.",
        "source": ["EU Scientific Committee on Consumer Safety (SCCS)"],
    },
    "retinol": {
        "aliases": ["retinol", "vitamin a", "retinoid", "retinal", "retinoic acid", "tretinoin"],
        "category": "moderate",
        "use": "Anti-ageing / skin-renewal ingredient",
        "info": "Effective anti-ageing ingredient but can irritate; high-dose "
                "vitamin A is harmful in pregnancy and retinoids require pregnancy "
                "warnings and sun-protection guidance.",
        "reason": "Effective but irritating; pregnancy/sun-sensitivity cautions.",
        "source": ["Cosmetic Ingredient Review (CIR)", "US FDA"],
    },
    # ---- Common kitchen / food base ingredients --------------------------------
    "water": {
        "aliases": ["water", "aqua", "purified water", "distilled water"],
        "category": "low",
        "use": "Base solvent / diluent in foods and cosmetics",
        "info": "The most common base ingredient in food and cosmetic products.",
        "reason": "Plain water; safe.",
        "source": ["US FDA", "EFSA"],
    },
    "sugar": {
        "aliases": ["sugar", "sucrose", "cane sugar", "white sugar", "granulated sugar", "powdered sugar"],
        "category": "low",
        "use": "Sweetener / bulking agent",
        "info": "A basic carbohydrate sweetener. Not a harmful additive per se, "
                "but high sugar intake is a well-established public-health concern "
                "(obesity, dental decay).",
        "reason": "Safe as an ingredient; high overall intake is a diet concern.",
        "source": ["WHO", "US FDA"],
    },
    "sorbitol": {
        "aliases": ["sorbitol", "e420", "e420i"],
        "category": "low",
        "use": "Sweetener / humectant (sugar-free products)",
        "info": "A sugar alcohol used in sugar-free foods; large amounts can "
                "cause digestive upset (laxative effect).",
        "reason": "Safe at normal levels; mild digestive effects in excess.",
        "source": ["EFSA", "US FDA"],
    },
    "maltodextrin": {
        "aliases": ["maltodextrin", "e1400"],
        "category": "low",
        "use": "Thickener / bulking agent / carrier",
        "info": "A highly processed starch derivative used widely as a filler "
                "and carrier. Rapidly digested; not a harmful additive.",
        "reason": "Safe; a high-glycemic carbohydrate.",
        "source": ["EFSA", "US FDA"],
    },
    "glucose syrup": {
        "aliases": ["glucose syrup", "corn syrup", "corn syrup solids", "dextrose", "glucose", "fructose", "invert sugar"],
        "category": "low",
        "use": "Sweetener / binder",
        "info": "Common liquid sugar syrup. Safe as an ingredient; contributes "
                "to overall sugar intake.",
        "reason": "Safe as an ingredient; a source of added sugar.",
        "source": ["US FDA", "EFSA"],
    },
    "vegetable oil": {
        "aliases": ["vegetable oil", "edible vegetable oil", "edible oil", "sunflower oil", "canola oil", "rapeseed oil", "soybean oil", "safflower oil", "corn oil", "olive oil", "sesame oil", "coconut oil", "refined vegetable oil", "hydrogenated vegetable oil"],
        "category": "low",
        "use": "Edible fat / oil",
        "info": "Common cooking oil. Safe to eat; partially hydrogenated "
                "variants contain trans fats which are increasingly banned.",
        "reason": "Safe as a food fat; trans-fat variants are restricted.",
        "source": ["US FDA", "EFSA", "WHO"],
    },
    "cocoa": {
        "aliases": ["cocoa", "cocoa powder", "cocoa solids", "cocoa butter", "chocolate"],
        "category": "low",
        "use": "Flavour / base ingredient",
        "info": "Derived from cacao; used in chocolate and confectionery.",
        "reason": "Safe; may be a minor allergen in rare cases.",
        "source": ["US FDA", "EFSA"],
    },
    "vanilla extract": {
        "aliases": ["vanilla extract", "vanilla"],
        "category": "low",
        "use": "Flavouring",
        "info": "Natural flavouring from vanilla beans (alcohol-extracted).",
        "reason": "Safe at food levels.",
        "source": ["US FDA", "EFSA"],
    },
    "milk": {
        "aliases": ["milk", "whole milk", "skim milk", "milk solids", "milk fat", "butter", "ghee", "cream"],
        "category": "low",
        "use": "Dairy ingredient",
        "info": "Common dairy ingredient. Safe; a major allergen for "
                "milk-allergic people and the main lactose source.",
        "reason": "Safe; a labelled major allergen.",
        "source": ["US FDA", "EFSA"],
    },
    "egg": {
        "aliases": ["egg", "eggs", "egg powder", "egg white", "egg yolk", "albumin", "albumen"],
        "category": "low",
        "use": "Binder / leavening / protein ingredient",
        "info": "Common food ingredient. Safe; a labelled major allergen.",
        "reason": "Safe; a labelled major allergen.",
        "source": ["US FDA", "EFSA"],
    },
    "peanut": {
        "aliases": ["peanut", "peanuts", "peanut butter", "groundnut", "groundnuts", "peanut oil", "arachis oil", "groundnut oil"],
        "category": "low",
        "use": "Nut ingredient / oil",
        "info": "Common ingredient and oil source. Safe for most; a major "
                "allergen and a cause of severe allergic reactions.",
        "reason": "Safe; a labelled major allergen.",
        "source": ["US FDA", "EFSA"],
    },
    "tree nuts": {
        "aliases": ["almond", "almonds", "cashew", "cashews", "walnut", "walnuts", "pistachio", "pistachios", "hazelnut", "hazelnuts", "pecan", "pecans", "macadamia"],
        "category": "low",
        "use": "Nut ingredient",
        "info": "Common whole-food ingredient. Safe; a major allergen.",
        "reason": "Safe; a labelled major allergen.",
        "source": ["US FDA", "EFSA"],
    },
    "salt": {
        "aliases": ["salt", "sodium chloride", "table salt", "sea salt", "rock salt"],
        "category": "low",
        "use": "Seasoning / preservative",
        "info": "Sodium chloride, a basic seasoning. Safe in normal amounts; "
                "excess sodium is a cardiovascular concern.",
        "reason": "Safe at normal levels; excess sodium is a diet concern.",
        "source": ["WHO", "US FDA"],
    },
    "flour": {
        "aliases": ["flour", "wheat flour", "wheat", "wheat starch", "maida", "refined wheat flour", "whole wheat flour", "all purpose flour", "maize flour", "rice flour"],
        "category": "low",
        "use": "Staple baking / thickening base",
        "info": "A basic milled-grain ingredient. Refined flour is low in fibre "
                "but not a harmful additive.",
        "reason": "Staple ingredient; nutritionally neutral.",
        "source": ["US FDA", "WHO"],
    },
    "garlic": {
        "aliases": ["garlic", "garlic powder", "garlic granules", "dehydrated garlic", "garlic salt"],
        "category": "low",
        "use": "Flavouring / seasoning",
        "info": "A common savoury seasoning. Safe; generally well tolerated, "
                "though a small number of people have a garlic sensitivity.",
        "reason": "Common food ingredient; safe.",
        "source": ["US FDA", "EFSA"],
    },
    "palm oil": {
        "aliases": ["palm oil", "palmolein", "rspo palm oil", "palm fat", "palm kernel oil"],
        "category": "low",
        "use": "Edible oil / fat",
        "info": "Common vegetable fat. Safe for consumption; the main concerns "
                "are environmental (deforestation) and its saturated-fat content, "
                "not additive toxicity.",
        "reason": "Safe as a food fat; saturated-fat and environmental concerns.",
        "source": ["EFSA", "WHO"],
    },
    "milk powder": {
        "aliases": ["milk powder", "skimmed milk powder", "whole milk powder", "smp", "wmp"],
        "category": "low",
        "use": "Dairy ingredient",
        "info": "Dried milk solids. Safe; a major allergen for milk-allergic people.",
        "reason": "Safe; a labelled major allergen.",
        "source": ["US FDA", "EFSA"],
    },
    "soy": {
        "aliases": ["soy", "soya", "soybean", "soy protein", "soya bean", "soy lecithin (protein)"],
        "category": "low",
        "use": "Plant protein / ingredient",
        "info": "Common plant-protein ingredient. Safe; a labelled major allergen.",
        "reason": "Safe; a labelled major allergen.",
        "source": ["US FDA", "EFSA"],
    },
    "gluten": {
        "aliases": ["gluten", "wheat gluten", "vital wheat gluten"],
        "category": "low",
        "use": "Protein from wheat (structure in bakery/processed foods)",
        "info": "Safe for the general population; the trigger for coeliac disease "
                "and gluten sensitivity, so it must be labelled.",
        "reason": "Safe for most; a labelled allergen for coeliac/gluten-sensitive people.",
        "source": ["US FDA", "EFSA"],
    },
    # ---- Antiseptic / hygiene ingredients (wipes, sanitisers, cleansers) ------
    "benzalkonium chloride": {
        "aliases": ["benzalkonium chloride", "alkyldimethylbenzylammonium chloride", "bkc", "quaternary ammonium compound"],
        "category": "moderate",
        "use": "Antimicrobial agent / preservative (quaternary ammonium compound)",
        "info": "Used as a preservative, surfactant and antiseptic in wipes, "
                "sanitisers and some cosmetics. Can cause skin and eye irritation "
                "and contact dermatitis in sensitive people; it is not intended "
                "for ingestion.",
        "reason": "Contact irritant / allergen for sensitive skin; not for ingestion.",
        "source": ["US FDA", "EU Scientific Committee on Consumer Safety (SCCS)"],
    },
    "sorbic acid": {
        "aliases": ["sorbic acid", "e200"],
        "category": "low",
        "use": "Preservative",
        "info": "A mild, widely used antimicrobial preservative. Generally "
                "considered safe; a small minority of people report skin or "
                "digestive irritation at higher levels.",
        "reason": "Generally safe at approved levels; occasional mild irritation.",
        "source": ["EFSA", "US FDA"],
    },
    "isopropanol": {
        "aliases": ["isopropanol", "isopropyl alcohol", "ipa", "propan-2-ol", "rubbing alcohol"],
        "category": "moderate",
        "use": "Solvent / disinfectant / quick-drying agent",
        "info": "A fast-evaporating solvent and disinfectant. Safe for external "
                "use at label concentrations, but it is flammable and harmful if "
                "swallowed. Avoid contact with eyes and broken skin.",
        "reason": "Irritant to skin/mucous membranes, flammable, toxic if ingested.",
        "source": ["US FDA", "European Chemicals Agency (ECHA)"],
    },
    "tetrasodium edta": {
        "aliases": ["tetrasodium edta", "edta", "edta tetrasodium salt", "tetrasodium ethylenediaminetetraacetate", "tetrasodium ethylene diamine tetra acetate"],
        "category": "low",
        "use": "Chelating agent / stabiliser",
        "info": "Binds trace metal ions so formulas stay stable. Widely used in "
                "cosmetics and household products; considered safe at cosmetic "
                "concentrations. A small number of sensitive people may find it "
                "mildly irritating.",
        "reason": "Low concern at cosmetic concentrations.",
        "source": ["Cosmetic Ingredient Review (CIR)", "US FDA"],
    },
    "disodium phosphate": {
        "aliases": ["disodium phosphate", "disodium hydrogen phosphate", "e339ii", "sodium phosphate", "sodium phosphates"],
        "category": "low",
        "use": "Buffering / emulsifying salt",
        "info": "A food-grade phosphate salt used as a buffer and emulsifier in "
                "foods, cosmetics and cleaning products. Safe at approved levels; "
                "very high dietary phosphate is a separate concern for people "
                "with kidney disease.",
        "reason": "Safe at approved levels.",
        "source": ["EFSA", "US FDA"],
    },
    "hexyl cinnamal": {
        "aliases": ["hexyl cinnamal", "hexyl cinnamaldehyde"],
        "category": "moderate",
        "use": "Fragrance ingredient",
        "info": "A fragrance compound that is a recognised contact allergen. The "
                "EU requires it to be named on the label above a threshold "
                "because it can trigger allergic contact dermatitis.",
        "reason": "Recognised contact allergen; EU mandatory labelling.",
        "source": ["EU Scientific Committee on Consumer Safety (SCCS)"],
    },
    "citronellol": {
        "aliases": ["citronellol", "dihydrogeraniol"],
        "category": "moderate",
        "use": "Fragrance ingredient",
        "info": "A naturally occurring fragrance compound. A recognised contact "
                "allergen that must be declared on cosmetic labels in the EU "
                "above a threshold.",
        "reason": "Recognised contact allergen; EU mandatory labelling.",
        "source": ["EU Scientific Committee on Consumer Safety (SCCS)"],
    },
    # ------------------------------------------------------------------ #
    # Skincare / Haircare / Bodycare / Cosmetics / Personal care
    # ------------------------------------------------------------------ #
    "phenoxyethanol": {
        "aliases": ["phenoxyethanol", "phenoxetol", "euxyl k400"],
        "category": "moderate",
        "use": "Preservative (lotions, creams, cosmetics)",
        "info": "A widely used cosmetic preservative. Generally well tolerated but "
                "can cause irritation or contact allergy in a minority of users; "
                "EU limits it to 1% (leave-on products).",
        "reason": "Contact-allergy risk in sensitive individuals; concentration limited.",
        "source": ["EU Scientific Committee on Consumer Safety (SCCS)", "US FDA"],
    },
    "methylisothiazolinone": {
        "aliases": ["methylisothiazolinone", "methyl chloro isothiazolinone", "mit", "mci", "kathon cg"],
        "category": "higher",
        "use": "Preservative (leave-on and rinse-off cosmetics)",
        "info": "A potent preservative but also a strong skin sensitiser. EU has "
                "banned it in leave-on products and caps it in rinse-off products "
                "because of allergic contact dermatitis.",
        "reason": "Strong sensitiser; banned in leave-on products in the EU.",
        "source": ["EU Scientific Committee on Consumer Safety (SCCS)"],
    },
    "dimethicone": {
        "aliases": ["dimethicone", "polydimethylsiloxane", "dimethylpolysiloxane", "pdms"],
        "category": "low",
        "use": "Skin/hair conditioning silicone",
        "info": "A silicone that forms a smooth, non-greasy film. Regarded as low "
                "irritation; it is occlusive but not absorbed through intact skin "
                "to any significant degree.",
        "reason": "Low irritation; not significantly absorbed.",
        "source": ["Cosmetic Ingredient Review (CIR)", "US FDA"],
    },
    "cocamidopropyl betaine": {
        "aliases": ["cocamidopropyl betaine", "cocamidopropylbetaine", "capb"],
        "category": "moderate",
        "use": "Gentle foaming surfactant (shampoo, body wash)",
        "info": "A mild amphoteric surfactant widely used in baby and sensitive "
                "products. It is a recognised but uncommon contact allergen, often "
                "due to impurities (cocoamidopropylamine).",
        "reason": "Occasional contact allergy, mainly from processing impurities.",
        "source": ["Cosmetic Ingredient Review (CIR)", "EU SCCS"],
    },
    "cetyl alcohol": {
        "aliases": ["cetyl alcohol", "cetanol", "hexadecanol", "cetostearyl alcohol"],
        "category": "low",
        "use": "Emollient / thickener (creams, conditioners)",
        "info": "A fatty alcohol used as a thickening and conditioning agent. It is "
                "well tolerated and not the same as drying 'drying alcohol' "
                "(ethanol/SD alcohol).",
        "reason": "Well tolerated; not an irritant drying alcohol.",
        "source": ["Cosmetic Ingredient Review (CIR)"],
    },
    "stearyl alcohol": {
        "aliases": ["stearyl alcohol", "octadecanol", "cetostearyl alcohol"],
        "category": "low",
        "use": "Emollient / stabiliser (creams, conditioners)",
        "info": "A fatty alcohol that gives thickness and a soft feel. Well tolerated "
                "on skin; occasional reports of mild irritation exist.",
        "reason": "Well tolerated at normal use levels.",
        "source": ["Cosmetic Ingredient Review (CIR)"],
    },
    "talc": {
        "aliases": ["talc", "talcum", "hydrous magnesium silicate"],
        "category": "moderate",
        "use": "Absorbent / anti-caking (powders, cosmetics)",
        "info": "Used in body and baby powders. Asbestos-free talc is widely "
                "considered safe, but IARC classifies perineal use of talc-based "
                "powder as 'possibly carcinogenic'; some talcs have been associated "
                "with contamination/ovarian-cancer litigation.",
        "reason": "IARC 2B for perineal talc; contamination risk if not asbestos-free.",
        "source": ["IARC", "US FDA", "Cosmetic Ingredient Review (CIR)"],
    },
    "petrolatum": {
        "aliases": ["petrolatum", "petroleum jelly", "vaseline", "white petrolatum"],
        "category": "low",
        "use": "Occlusive emollient / barrier",
        "info": "A highly purified mixture of hydrocarbons used as an occlusive "
                "moisturiser. Considered safe when refined to remove impurities; "
                "the main caution is that unrefined mineral oil can contain "
                "polycyclic aromatic hydrocarbons (PAHs).",
        "reason": "Safe when highly refined; unrefined grades may contain PAHs.",
        "source": ["US FDA", "Cosmetic Ingredient Review (CIR)"],
    },
    "lanolin": {
        "aliases": ["lanolin", "wool wax", "wool fat", "adeps lanae"],
        "category": "moderate",
        "use": "Emollient (creams, lip balms, nipple creams)",
        "info": "A natural wax from sheep wool used as a moisturiser. A well-known "
                "but uncommon contact allergen; 'American lamolin' is treated to "
                "reduce allergenicity.",
        "reason": "Well-documented, uncommon contact allergen.",
        "source": ["Cosmetic Ingredient Review (CIR)", "EU SCCS"],
    },
    "hyaluronic acid": {
        "aliases": ["hyaluronic acid", "hyaluronan", "sodium hyaluronate"],
        "category": "low",
        "use": "Humectant (skin hydration serum)",
        "info": "A naturally occurring molecule that holds many times its weight in "
                "water, widely used for hydration. Very well tolerated.",
        "reason": "Highly tolerable; no significant concern at use levels.",
        "source": ["Cosmetic Ingredient Review (CIR)"],
    },
    "panthenol": {
        "aliases": ["panthenol", "provitamin b5", "d-panthenol", "dexpanthenol"],
        "category": "low",
        "use": "Skin/hair conditioning pro-vitamin",
        "info": "Converted in the skin to vitamin B5; used as a humectant and "
                "soother. Very well tolerated.",
        "reason": "Very well tolerated.",
        "source": ["Cosmetic Ingredient Review (CIR)"],
    },
    "urea": {
        "aliases": ["urea", "carbamide"],
        "category": "low",
        "use": "Humectant / keratolytic (foot creams, body lotions)",
        "info": "A natural moisturising factor that also softens dry, thick skin at "
                "higher concentrations. Generally safe; can sting if skin is broken.",
        "reason": "Generally safe; may sting on broken skin.",
        "source": ["Cosmetic Ingredient Review (CIR)"],
    },
    "octinoxate": {
        "aliases": ["octinoxate", "ethylhexyl methoxycinnamate", "ehc", "octyl methoxycinnamate"],
        "category": "moderate",
        "use": "UV-B sunscreen filter",
        "info": "A common chemical UV filter. Approved for use, but it is one of the "
                "sunscreen filters under review for coral-reef impact and hormonal "
                "effects; some regions have restricted it.",
        "reason": "Under review for hormonal/reef effects; restricted in some regions.",
        "source": ["US FDA", "EU SCCS"],
    },
    "oxybenzone": {
        "aliases": ["oxybenzone", "benzophenone-3", "bp-3"],
        "category": "higher",
        "use": "UV-A/UV-B absorber (sunscreen)",
        "info": "A very effective UV filter but a common contact allergen and "
                "endocrine-disruption concern. Banned in sunscreens in Hawaii and "
                "Key West and restricted in others due to absorption and reef "
                "damage.",
        "reason": "Contact allergen; endocrine-disruption concern; banned/restricted in several places.",
        "source": ["US FDA", "EU SCCS"],
    },
    "avobenzone": {
        "aliases": ["avobenzone", "butyl methoxydibenzoylmethane", "bmdbm", "parsol 1789"],
        "category": "moderate",
        "use": "UV-A filter (sunscreen)",
        "info": "The most common UV-A filter. Approved but photounstable; can "
                "degrade into potentially sensitising breakdown products, so it is "
                "usually paired with stabilisers.",
        "reason": "Photounstable; breakdown products may sensitise; well characterised.",
        "source": ["US FDA", "EU SCCS"],
    },
    "zinc oxide": {
        "aliases": ["zinc oxide", "zno", "ci 77947", "american zinc"],
        "category": "low",
        "use": "Mineral UV filter / skin protector",
        "info": "A mineral (physical) sunscreen and soothing ingredient. Non-nano "
                "zinc oxide is regarded as safe and very well tolerated; only "
                "inhalation of nanopowder spray forms is flagged by some bodies.",
        "reason": "Safe and well tolerated; inhalation of spray nanopowder noted.",
        "source": ["US FDA", "Cosmetic Ingredient Review (CIR)"],
    },
    "zinc pyrithione": {
        "aliases": ["zinc pyrithione", "zinc omadine", "zpt"],
        "category": "higher",
        "use": "Anti-dandruff active (shampoo)",
        "info": "An effective anti-dandruff agent, but the EU has proposed/planned "
                "restrictions due to reproductive-toxicity classification and "
                "environmental concerns. Its use in rinse-off products is limited.",
        "reason": "Reproductive-toxicity classification; restricted in the EU.",
        "source": ["EU SCCS", "ECHA"],
    },
    "selenium sulfide": {
        "aliases": ["selenium sulfide", "selenium disulphide", "selenium sulphide"],
        "category": "moderate",
        "use": "Anti-dandruff agent (shampoo, lotion)",
        "info": "A strong anti-dandruff/anti-seborrhoeic agent available OTC at low "
                "concentrations. Effective, but can irritate skin and must not be "
                "used on damaged skin; used as a scalp treatment.",
        "reason": "Can irritate skin; must avoid broken skin.",
        "source": ["US FDA OTC Monograph", "Health Canada"],
    },
    "polysorbate": {
        "aliases": ["polysorbate", "polysorbate 20", "polysorbate 80", "tween 20", "tween 80", "e433"],
        "category": "low",
        "use": "Emulsifier / solubiliser (cosmetics, foods)",
        "info": "A family of mild non-ionic emulsifiers widely used in foods and "
                "cosmetics. Considered safe at approved levels; very high intake is "
                "under study but not established as harmful at use levels.",
        "reason": "Safe at approved levels.",
        "source": ["EFSA", "Cosmetic Ingredient Review (CIR)"],
    },
    "carbomer": {
        "aliases": ["carbomer", "carbopol", "polyacrylic acid crosspolymer"],
        "category": "low",
        "use": "Gel / thickening agent (gels, serums)",
        "info": "A synthetic polymer that gives gels and serums their texture. Very "
                "well tolerated and not absorbed; generally regarded as safe.",
        "reason": "Very well tolerated; minimal absorption.",
        "source": ["Cosmetic Ingredient Review (CIR)"],
    },
    "kaolin": {
        "aliases": ["kaolin", "china clay", "aluminium silicate"],
        "category": "low",
        "use": "Clay absorbent (masks, soap)",
        "info": "A natural clay used in face masks and as an absorbent. Nontoxic "
                "when used externally; the main caution is inhalation in powder "
                "form.",
        "reason": "Safe externally; avoid inhaling powder.",
        "source": ["Cosmetic Ingredient Review (CIR)"],
    },
    "shea butter": {
        "aliases": ["shea butter", "butyrospermum parkii butter"],
        "category": "low",
        "use": "Emollient moisturiser",
        "info": "A natural plant butter rich in fatty acids and vitamins. Well "
                "tolerated; occasional allergy to latex-related proteins is rare.",
        "reason": "Very well tolerated; rare sensitivity possible.",
        "source": ["Cosmetic Ingredient Review (CIR)"],
    },
    "tea tree oil": {
        "aliases": ["tea tree oil", "melaleuca oil", "melaleuca alternifolia oil"],
        "category": "moderate",
        "use": "Antiseptic / anti-acne essential oil",
        "info": "A natural antiseptic oil. Can cause allergic contact dermatitis "
                "and irritation, and is toxic if swallowed - it must not be used "
                "internally.",
        "reason": "Contact allergy and irritation; toxic if ingested.",
        "source": ["Cosmetic Ingredient Review (CIR)"],
    },
    "ammonium lauryl sulfate": {
        "aliases": ["ammonium lauryl sulfate", "ammonium lauryl sulphate", "als"],
        "category": "low",
        "use": "Foaming surfactant (shampoo, cleanser)",
        "info": "A strong anionic surfactant used mainly in shampoos. Similar to "
                "SLS - effective but can cause mild skin/eye irritation at higher "
                "concentrations; not a meaningful cancer risk.",
        "reason": "Mild irritant at concentration; no established carcinogenicity.",
        "source": ["Cosmetic Ingredient Review (CIR)"],
    },
    "ethyl alcohol": {
        "aliases": ["ethyl alcohol", "ethanol", "alcohol denat", "sd alcohol", "denatured alcohol"],
        "category": "low",
        "use": "Solvent / quick-drying vehicle (toner, sanitiser)",
        "info": "Used as a solvent, antimicrobial and quick-drying vehicle. Strips "
                "oils and can dry or irritate skin when over-used, but is not "
                "absorbed meaningfully; safe at regulated levels.",
        "reason": "Safe at regulated levels; can dry/irritate if over-used.",
        "source": ["US FDA", "EU SCCS"],
    },
    "coco glucoside": {
        "aliases": ["coco glucoside", "cocoglucoside", "coco glycoside"],
        "category": "low",
        "use": "Gentle plant-derived surfactant",
        "info": "A mild, plant-derived (coconut + glucose) surfactant found in "
                "gentle cleansers and baby products. Very well tolerated.",
        "reason": "Very well tolerated.",
        "source": ["Cosmetic Ingredient Review (CIR)"],
    },
    "sodium lauryl ether sulfate": {
        "aliases": ["sodium lauryl ether sulfate", "sodium laureth sulfate", "sles"],
        "category": "moderate",
        "use": "Foaming surfactant (shampoo, body wash)",
        "info": "An effective detergent and the milder cousin of SLS, but it can be "
                "contaminated with 1,4-dioxane (a possible carcinogen) during "
                "manufacture, so quality control matters. Ethoxylated ingredients "
                "carry this residual risk.",
        "reason": "Possible 1,4-dioxane contamination; otherwise mild irritant.",
        "source": ["Cosmetic Ingredient Review (CIR)", "US FDA"],
    },
    "octenidine": {
        "aliases": ["octenidine", "octenidine dihydrochloride"],
        "category": "low",
        "use": "Antiseptic disinfectant",
        "info": "A modern antiseptic used in wound care and some personal care "
                "products, generally better tolerated than older antiseptics and "
                "not prone to bacterial resistance. Not for internal use.",
        "reason": "Well tolerated as an antiseptic; for external use.",
        "source": ["Cochrane reviews", "National formularies"],
    },
}


# --------------------------------------------------------------------------- #
# Certification detection from OCR text
# --------------------------------------------------------------------------- #
_CERTIFICATION_PATTERNS = {
    "food": [
        {"name": "FSSAI", "patterns": [r"\bfssai\b", r"food\s*safety\s*and\s*standards", r"fssai\s*(?:lic(?:ence|ense)?)?\s*(?:no\.?|number)?\s*[:\s]*\d"]},
        {"name": "Organic (India NPOP)", "patterns": [r"\bnpop\b", r"national\s*programme\s*for\s*organic", r"india\s*organic"]},
        {"name": "Organic (USDA)", "patterns": [r"\busda\s*organic\b"]},
        {"name": "Organic (EU)", "patterns": [r"\borganic\b.*\beu\b", r"eu\s*organic"]},
        {"name": "Halal", "patterns": [r"\bhalal\b"]},
        {"name": "Kosher", "patterns": [r"\bkosher\b"]},
        {"name": "AGMARK", "patterns": [r"\bagmark\b"]},
        {"name": "ISO 22000", "patterns": [r"\biso\s*22000\b"]},
    ],
    "cosmetic": [
        {"name": "Cruelty-Free (Leaping Bunny)", "patterns": [r"\bleaping\s*bunny\b", r"cruelty[\s-]*free", r"not\s*tested\s*on\s*animals"]},
        {"name": "Vegan Society", "patterns": [r"\bvegan\s*society\b", r"\bvegan\b"]},
        {"name": "Dermatologically Tested", "patterns": [r"\bdermatolog(?:ically|ist)\s*tested\b"]},
        {"name": "Hypoallergenic", "patterns": [r"\bhypoallergenic\b"]},
        {"name": "BIS (India)", "patterns": [r"\bis\s*:\s*\d"]},
        {"name": "FDA Registered", "patterns": [r"\bfda\s*registered\b"]},
    ],
    "personal_care": [
        {"name": "Cruelty-Free", "patterns": [r"\bcruelty[\s-]*free\b", r"not\s*tested\s*on\s*animals"]},
        {"name": "Vegan", "patterns": [r"\bvegan\b"]},
        {"name": "Dermatologically Tested", "patterns": [r"\bdermatolog(?:ically|ist)\s*tested\b"]},
        {"name": "Paraben-Free", "patterns": [r"\bparaben[\s-]*free\b"]},
        {"name": "Sulfate-Free", "patterns": [r"\bsulf(?:ate|ate)[\s-]*free\b"]},
        {"name": "SLS-Free", "patterns": [r"\bsls[\s-]*free\b"]},
    ],
    "household": [
        {"name": "BIS (India)", "patterns": [r"\bis\s*:\s*\d"]},
        {"name": "ISO 9001", "patterns": [r"\biso\s*9001\b"]},
        {"name": "EPA Registered", "patterns": [r"\bepa\s*registered\b"]},
        {"name": "CE Mark", "patterns": [r"\bce\b"]},
    ],
}
_CERT_GENERIC = [
    {"name": "ISI Mark (BIS)", "patterns": [r"\bisi\s*mark\b", r"\bisi\b.*\bcertified\b"]},
    {"name": "CE Certification", "patterns": [r"\bce\b.*\bcertif(?:ied|ication)\b"]},
    {"name": "ISO Certified", "patterns": [r"\biso\s*\d{4,}"]},
]


def _detect_certifications(text: str, category: str = "") -> list:
    """Detect certification marks from OCR text based on product category."""
    if not text:
        return []
    low = text.lower()
    results = []
    seen = set()
    cat_certs = list(_CERTIFICATION_PATTERNS.get(category or "", []))
    if category in ("beverage", "snack"):
        cat_certs = list(_CERTIFICATION_PATTERNS.get("food", [])) + cat_certs
    for cert in cat_certs + _CERT_GENERIC:
        if cert["name"] in seen:
            continue
        seen.add(cert["name"])
        found = any(re.search(p, low, re.IGNORECASE) for p in cert["patterns"])
        results.append({
            "name": cert["name"],
            "detected": found,
            "verified": "detected" if found else "not_detected",
        })
    return results


# --------------------------------------------------------------------------- #
# Claim-vs-ingredient consistency checker
# --------------------------------------------------------------------------- #
_CLAIM_INGREDIENT_CONFLICTS = {
    "sugar-free": {
        "conflicts_with": ["sugar", "sucrose", "cane sugar", "glucose syrup", "corn syrup",
                           "high fructose corn syrup", "dextrose", "invert sugar",
                           "maltodextrin", "honey", "fructose"],
        "reason": "Product claims sugar-free but contains a sugar or sugar-derived ingredient.",
    },
    "zero sugar": {
        "conflicts_with": ["sugar", "sucrose", "cane sugar", "glucose syrup", "corn syrup",
                           "high fructose corn syrup", "dextrose", "invert sugar", "honey"],
        "reason": "Product claims zero sugar but contains a sugar ingredient.",
    },
    "no added sugar": {
        "conflicts_with": ["cane sugar", "glucose syrup", "corn syrup", "high fructose corn syrup",
                           "dextrose", "invert sugar", "maltodextrin", "honey"],
        "reason": "Product claims no added sugar but contains added sweeteners.",
    },
    "paraben-free": {
        "conflicts_with": ["methylparaben", "ethylparaben", "propylparaben", "butylparaben",
                           "paraben", "parabens", "e218", "e214", "e216", "e219"],
        "reason": "Product claims paraben-free but lists a paraben preservative.",
    },
    "chemical-free": {
        "conflicts_with": ["sodium lauryl sulfate", "sodium laureth sulfate", "sls", "sles",
                           "paraben", "formaldehyde", "phthalate", "propylene glycol",
                           "sodium benzoate", "potassium sorbate", "citric acid",
                           "sodium chloride", "ascorbic acid"],
        "reason": "Product claims chemical-free but all ingredients are chemicals; this claim is misleading.",
    },
    "alcohol-free": {
        "conflicts_with": ["ethanol", "alcohol", "isopropyl alcohol", "denatured alcohol",
                           "cetyl alcohol", "stearyl alcohol", "cetearyl alcohol"],
        "reason": "Product claims alcohol-free but contains an alcohol-based ingredient.",
    },
    "100% natural": {
        "conflicts_with": ["sodium lauryl sulfate", "sodium laureth sulfate", "paraben",
                           "formaldehyde", "phthalate", "propylene glycol", "aspartame",
                           "sucralose", "saccharin", "artificial", "synthetic"],
        "reason": "Product claims 100% natural but contains synthetic ingredients.",
    },
    "organic": {
        "conflicts_with": ["artificial", "synthetic", "fd&c", "e102", "e110", "e122",
                           "e124", "e129", "aspartame", "sucralose", "msg"],
        "reason": "Product claims organic but contains synthetic additives.",
    },
    "hypoallergenic": {
        "conflicts_with": ["formaldehyde", "dmdm hydantoin", "quaternium-15",
                           "methylisothiazolinone", "methylchloroisothiazolinone"],
        "reason": "Product claims hypoallergenic but contains known allergens or irritants.",
    },
    "fragrance-free": {
        "conflicts_with": ["fragrance", "parfum", "perfume", "linalool", "limonene",
                           "geraniol", "citronellol", "eugenol"],
        "reason": "Product claims fragrance-free but lists fragrance components.",
    },
}


def _check_claim_consistency(claims: list, parsed_ingredients: list) -> list:
    """Check label claims against the ingredient list for inconsistencies."""
    if not claims or not parsed_ingredients:
        return []
    ingredient_norms = {ing.get("normalized", "") for ing in parsed_ingredients}
    ingredient_names = {ing.get("name", "").lower() for ing in parsed_ingredients}
    all_ingredients = ingredient_norms | ingredient_names
    results = []
    for claim_entry in claims:
        claim_text = (claim_entry.get("claim") or "").lower().strip()
        if not claim_text:
            continue
        matched_key = None
        for key in _CLAIM_INGREDIENT_CONFLICTS:
            if key in claim_text:
                matched_key = key
                break
        if not matched_key:
            results.append({
                "claim": claim_entry.get("claim", ""),
                "status": "unverifiable",
                "reason": "This claim cannot be verified from the ingredient list alone.",
            })
            continue
        conflict_info = _CLAIM_INGREDIENT_CONFLICTS[matched_key]
        conflicts_found = []
        for conflict in conflict_info["conflicts_with"]:
            conflict_norm = _norm(conflict)
            for ing_norm in all_ingredients:
                if conflict_norm in ing_norm or ing_norm in conflict_norm:
                    conflicts_found.append(conflict)
                    break
        if conflicts_found:
            results.append({
                "claim": claim_entry.get("claim", ""),
                "status": "inconsistent",
                "reason": conflict_info["reason"],
                "conflicting_ingredients": conflicts_found,
            })
        else:
            results.append({
                "claim": claim_entry.get("claim", ""),
                "status": "consistent",
                "reason": "No conflicting ingredients found in the ingredient list.",
            })
    return results


# --------------------------------------------------------------------------- #
# Category-specific mandatory label information
# --------------------------------------------------------------------------- #
_MANDATORY_INFO = {
    "food": [
        {"field": "ingredient_list", "label": "Ingredient list", "required": True},
        {"field": "product_name", "label": "Product name", "required": True},
        {"field": "manufacturer", "label": "Manufacturer / brand name", "required": True},
        {"field": "net_quantity", "label": "Net quantity / weight", "required": True},
        {"field": "mfg_date", "label": "Manufacturing date", "required": True},
        {"field": "expiry_date", "label": "Expiry / best-before date", "required": True},
        {"field": "batch_number", "label": "Batch / lot number", "required": True},
        {"field": "fssai_number", "label": "FSSAI licence number", "required": True},
        {"field": "nutrition_info", "label": "Nutritional information", "required": True},
        {"field": "mrp", "label": "Maximum retail price (MRP)", "required": True},
    ],
    "beverage": [
        {"field": "ingredient_list", "label": "Ingredient list", "required": True},
        {"field": "product_name", "label": "Product name", "required": True},
        {"field": "manufacturer", "label": "Manufacturer / brand name", "required": True},
        {"field": "net_quantity", "label": "Net quantity / volume", "required": True},
        {"field": "mfg_date", "label": "Manufacturing date", "required": True},
        {"field": "expiry_date", "label": "Expiry / best-before date", "required": True},
        {"field": "fssai_number", "label": "FSSAI licence number", "required": True},
        {"field": "nutrition_info", "label": "Nutritional information", "required": True},
        {"field": "mrp", "label": "Maximum retail price (MRP)", "required": True},
    ],
    "snack": [
        {"field": "ingredient_list", "label": "Ingredient list", "required": True},
        {"field": "product_name", "label": "Product name", "required": True},
        {"field": "manufacturer", "label": "Manufacturer / brand name", "required": True},
        {"field": "net_quantity", "label": "Net weight", "required": True},
        {"field": "mfg_date", "label": "Manufacturing date", "required": True},
        {"field": "expiry_date", "label": "Expiry / best-before date", "required": True},
        {"field": "fssai_number", "label": "FSSAI licence number", "required": True},
        {"field": "nutrition_info", "label": "Nutritional information", "required": True},
    ],
    "cosmetic": [
        {"field": "ingredient_list", "label": "Full INCI ingredient list", "required": True},
        {"field": "product_name", "label": "Product name", "required": True},
        {"field": "manufacturer", "label": "Manufacturer / brand name", "required": True},
        {"field": "net_quantity", "label": "Net quantity / volume", "required": True},
        {"field": "mfg_date", "label": "Manufacturing date", "required": True},
        {"field": "expiry_date", "label": "Expiry / use-by date", "required": True},
        {"field": "batch_number", "label": "Batch / lot number", "required": True},
    ],
    "skincare": [
        {"field": "ingredient_list", "label": "Full INCI ingredient list", "required": True},
        {"field": "product_name", "label": "Product name", "required": True},
        {"field": "manufacturer", "label": "Manufacturer / brand name", "required": True},
        {"field": "net_quantity", "label": "Net quantity / volume", "required": True},
        {"field": "mfg_date", "label": "Manufacturing date", "required": True},
        {"field": "expiry_date", "label": "Expiry / use-by date", "required": True},
        {"field": "batch_number", "label": "Batch / lot number", "required": True},
    ],
    "haircare": [
        {"field": "ingredient_list", "label": "Full INCI ingredient list", "required": True},
        {"field": "product_name", "label": "Product name", "required": True},
        {"field": "manufacturer", "label": "Manufacturer / brand name", "required": True},
        {"field": "net_quantity", "label": "Net quantity / volume", "required": True},
        {"field": "mfg_date", "label": "Manufacturing date", "required": True},
        {"field": "expiry_date", "label": "Expiry / use-by date", "required": True},
    ],
    "personal_care": [
        {"field": "ingredient_list", "label": "Full INCI ingredient list", "required": True},
        {"field": "product_name", "label": "Product name", "required": True},
        {"field": "manufacturer", "label": "Manufacturer / brand name", "required": True},
        {"field": "net_quantity", "label": "Net quantity / volume", "required": True},
        {"field": "mfg_date", "label": "Manufacturing date", "required": True},
        {"field": "expiry_date", "label": "Expiry / use-by date", "required": True},
    ],
    "household": [
        {"field": "product_name", "label": "Product name", "required": True},
        {"field": "manufacturer", "label": "Manufacturer / brand name", "required": True},
        {"field": "ingredient_list", "label": "Ingredient / composition list", "required": True},
        {"field": "net_quantity", "label": "Net quantity / volume", "required": True},
        {"field": "hazard_warnings", "label": "Hazard / safety warnings", "required": True},
        {"field": "usage_instructions", "label": "Usage instructions", "required": True},
    ],
}


def _check_mandatory_info(combined_text: str, category: str) -> list:
    """Check which mandatory label information is missing for the given category."""
    if not combined_text or category not in _MANDATORY_INFO:
        return []
    low = combined_text.lower()
    missing = []
    for info in _MANDATORY_INFO[category]:
        field = info["field"]
        found = False
        if field == "ingredient_list":
            found = bool(re.search(r"\bingredients?\s*[:]|contains?\s*[:]", low))
        elif field == "product_name":
            found = bool(combined_text.strip())
        elif field == "manufacturer":
            found = bool(re.search(r"\b(?:manufactured?|made|produced|packed|distributed?)\s+(?:by|at|for)\b", low))
        elif field in ("mfg_date", "expiry_date"):
            found = bool(re.search(r"\b(?:mfg|exp|best\s*before|use\s*by)\b|\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d", low))
        elif field == "batch_number":
            found = bool(re.search(r"\bbatch\s*(?:no|number|#)\s*[:\s]*\w|\blot\s*(?:no|number|#)\s*[:\s]*\w", low))
        elif field == "fssai_number":
            found = bool(re.search(r"\bfssai\b", low))
        elif field == "nutrition_info":
            found = bool(re.search(r"\bnutrition(?:al)?\s*(?:info|information|facts)\b|\bcalories?\b", low))
        elif field == "net_quantity":
            found = bool(re.search(r"\bnet\s*(?:wt|weight|qty|quantity|volume|contents)\b|\b\d+(?:\.\d+)?\s*(?:g|kg|ml|l|oz)\b", low))
        elif field == "mrp":
            found = bool(re.search(r"\bmrp\b|\bmaximum\s*retail\s*price\b", low))
        elif field == "hazard_warnings":
            found = bool(re.search(r"\bwarning\b|\bcaution\b|\bdanger\b|\bcorrosive\b|\bflammable\b", low))
        elif field == "usage_instructions":
            found = bool(re.search(r"\bhow\s+to\s+use\b|\bdirections?\s+(?:for\s+)?use\b|\busage\b|\binstructions?\b", low))
        if not found and info["required"]:
            missing.append(info["label"])
    return missing


# --------------------------------------------------------------------------- #
# Normalisation helpers
# --------------------------------------------------------------------------- #
def _norm(text: str) -> str:
    """Lowercase, alphanumeric only (handles E-numbers, case, dashes, unicode)."""
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


# Build allergen index after _norm is defined.
for _akey, _aentry in COMMON_ALLERGENS.items():
    for _aalias in _aentry["aliases"]:
        _ALLERGEN_INDEX[_norm(_aalias)] = _akey


def _strip_ingredients_header(text: str) -> str:
    """Remove a leading 'Ingredients: ...' / 'Ingredient list: ...' header."""
    m = re.match(
        r"^\s*(?:ingredients?|ingredient\s+list|ingredients?\s+in\s+(?:the\s+)?product|contains?|content|included)\s*[:\-]\s*",
        text or "", re.IGNORECASE,
    )
    if m:
        return text[m.end():]
    return text


# Section-header cues on a product label that mark the START of the
# ingredient list ("Ingredients:", "INGREDIENTS:", "Ingredients may include:").
_INGREDIENT_START_RE = re.compile(
    r"^\s*(?:ingredients?\b|ingredient\s+list|ingredients\s+may\s+include"
    r"|ingredients?\s+in\s+(?:the\s+)?product|included\b|contains?\b)\s*[:\-]?\s*",
    re.IGNORECASE,
)

# Section-header cues that mark the END of the ingredient list. Once we reach
# one of these the ingredient section is over - everything after is nutrition
# or labels info, NOT ingredients.
_INGREDIENT_STOP_RE = re.compile(
    r"^\s*(?:nutritional?\s+information|nutrition\s+(?:information|facts)"
    r"|serving\s+size|net\s*(?:wt\.?|weight)|weight\s*[:]?"
    r"|allergen\s*advice|allergens?\b"
    r"|manufactur(?:er|ed|ing)|made\s+in|packed\s+by|marketed\s+by"
    r"|best\s*(?:before|by)|use\s*by|expiry|exp\.?|best-before"
    r"|mrp\b|max\s+retail|fssai\b|batch\b|lot\s*no|l\.?n\.?"
    r"|storage\b|store\s+in|customer\s*care|toll\s*free"
    r"|address\b|regd\s*(?:office|under)|vegetarian\s*symbol|non-vegetarian\b)\b",
    re.IGNORECASE,
)


def _extract_ingredient_section(text: str) -> str:
    """Isolate the ingredient-list portion of a raw label document.

    A full OCR'd label is a document: a product name up top, then a chunk of
    ingredient text, then nutrition / allergen / manufacturer / batch blocks.
    Only the ingredient chunk should be fed to parse_ingredients() - the rest
    is OCR noise ("Oee", "P0g4ted48495", nutrition paragraphs, etc.) that would
    otherwise be misread as ingredients.

    Strategy (line based, because OCR returns paragraph lines):
      1. Locate the start of the ingredient section - either an explicit header
         ("Ingredients:", "INGREDIENTS:", "Ingredients may include:") or, when
         no header exists, the first line that looks like an ingredient list.
      2. Collect lines until a stop-section header (Nutritional Information,
         Allergen Advice, Manufacturer, Best Before, MRP, FSSAI, Batch, ...).
      3. A single-line input with no label structure is returned unchanged so a
         typed ingredient list ("Water, Glycerin, ...") is never truncated.

    Returns the ingredient-section substring ('' if none can be found).
    """
    if not text:
        return ""
    lines = [ln for ln in text.splitlines() if ln and ln.strip()]
    if not lines:
        return ""

    def is_stop(line: str) -> bool:
        return bool(_INGREDIENT_STOP_RE.match(line.strip()))

    def is_start(line: str) -> bool:
        return bool(_INGREDIENT_START_RE.match(line.strip()))

    # Find the first start-line, if any.
    start_idx = next((i for i, ln in enumerate(lines) if is_start(ln)), None)

    if start_idx is None:
        # No explicit header. For a multi-line label, begin at the first line
        # that is not clearly a stop/section header and not a tiny OCR fragment.
        begin = 0
        for i, ln in enumerate(lines):
            stripped = ln.strip()
            if not stripped or _is_section_garbage_line(stripped):
                continue
            if is_start(ln) or (looks_like_ingredient_list_line(stripped)
                                and not is_stop(ln)):
                begin = i
                break
        start_idx = begin

    collected = []
    header_line = lines[start_idx].strip()
    for idx, ln in enumerate(lines[start_idx:], start=start_idx):
        stripped = ln.strip()
        if not stripped:
            continue
        if is_stop(stripped):
            break
        # A bare header line ("Ingredients", "INGREDIENTS:") carries no
        # ingredient content of its own - drop it so it never becomes a
        # bogus ingredient. Same-line content after the colon is handled below.
        if idx == start_idx and is_start(stripped) \
                and not re.search(r"(?:ingredients?\b|may\s+include)\s*[:\-]\s*\S", stripped, re.IGNORECASE):
            continue
        collected.append(stripped)

    # Preserve newlines - parse_ingredients() treats them as delimiters, so a
    # multi-line OCR document keeps its per-line structure ("Water",
    # "Glycerin", "Sodium benzoate") instead of collapsing into one blob.
    section = "\n".join(collected) if collected else ""
    # Even within a single OCR line, a label section header (Nutritional
    # Information / Allergen Advice / Manufacturer / Best Before / Serving Size
    # / Net Weight / MRP / FSSAI / Batch / Storage) terminates the ingredient
    # list. Cut the section at the first such header wherever it appears.
    m = re.search(
        r"(?:nutritional?\s+information|nutrition\s+(?:information|facts)|"
        r"serving\s+size|net\s*(?:wt\.?|weight)|allergen\s*advice|allergens?\b|"
        r"manufactur(?:er|ed|ing)|best\s*(?:before|by)|use\s*by|expiry|"
        r"\bmrp\b|fssai\b|\bbatch\b|storage\b|vegetarian\s*symbol|"
        r"non-vegetarian\b)",
        section, re.IGNORECASE,
    )
    if m:
        section = section[:m.start()].strip()

    # Keep any content on the same line as an "Ingredients:" header.
    header_line = lines[start_idx].strip()
    m = re.search(r"(?:ingredients?\b|may\s+include)\s*[:\-]\s*(.+)$",
                  header_line, re.IGNORECASE)
    if m:
        return _strip_ocr_garbage_prefix(m.group(1).strip())
    return _strip_ocr_garbage_prefix(section)


def _is_section_garbage_line(line: str) -> bool:
    """A short OCR fragment is unlikely to be an ingredient list."""
    compact = _norm(line)
    return len(compact) < 3 or len(compact) > 60


def _is_ocr_garbage_fragment(fragment: str) -> bool:
    """True when a text fragment is OCR noise rather than a real ingredient.

    Real ingredient tokens are alphabetically dense ("VEGETABLE OIL", "Garlic").
    OCR noise is digit-dominated or contains digit-in-word jumbles
    ("P0g4ted48495", "Oee", "E1S3"). Parenthetical additive codes are kept.
    """
    frag = (fragment or "").strip()
    if not frag:
        return False
    # Additive reference codes (INS 627 / E621 / E 150d) are real tokens -
    # never treated as OCR noise even though they are digit-heavy.
    if re.search(r"\b(?:e|ins)\s*-?\s*\d{3,4}[a-z]?\b", frag, re.IGNORECASE):
        return False
    # Contains a real word (>= 4 contiguous letters)? Then it is a plausible
    # ingredient token ("Mysterypuff X23", "Zarblend-9", "EDIble VEGETABLE OIL"),
    # not pure OCR noise - even if a stray digit happens to be present.
    if re.search(r"[a-z]{4,}", frag.lower()):
        return False
    alpha = sum(1 for c in frag if c.isalpha())
    digits = sum(1 for c in frag if c.isdigit())
    if alpha == 0 and digits == 0:
        return True
    if digits >= 3 or digits >= alpha:
        return True
    if alpha < 4:
        return True
    return False


def _strip_ocr_garbage_prefix(section: str) -> str:
    """Drop leading OCR-noise fragments from the ingredient section.

    A label image often begins with stray glyphs ("Oee", "P0g4ted48495")
    BEFORE the first real ingredient. These must never become ingredients, so
    leading fragments that look like OCR noise are removed (paren-aware so
    something like "(INS 627, INS 631)" is never broken up).
    """
    if not section:
        return section
    toks = []
    cur, depth = [], 0
    for ch in section:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(depth - 1, 0)
        if depth == 0 and ch in ",;":
            toks.append(("c", "".join(cur)))
            toks.append(("s", ch))
            cur = []
        else:
            cur.append(ch)
    toks.append(("c", "".join(cur)))

    out = []
    i = 0
    started = False
    while i < len(toks):
        kind, val = toks[i]
        if kind == "c":
            if not started:
                if _is_ocr_garbage_fragment(val):
                    i += 2  # skip this leading noise fragment and its separator
                    continue
                started = True
            out.append((kind, val))
        else:
            out.append((kind, val))
        i += 1
    rebuilt = "".join(v for _, v in out)
    return rebuilt.strip(" .,;")


def looks_like_ingredient_list_line(line: str) -> bool:
    """True when a single line plausibly contains ingredient entries."""
    return bool(re.search(r"[,;]", line)) or bool(
        re.search(r"\be\s?\d{3}\b|\be\d{3}", line, re.IGNORECASE)
    )


def _looks_like_ingredient_list(text: str) -> bool:
    """Best-effort check that the input is an ingredient list, not just a name."""
    if not text:
        return False
    if len(re.split(r"[,;\n]", text)) >= 2:
        return True
    if re.search(r"\be\s?\d{3}\b|\be\d{3}", text, re.IGNORECASE):
        return True
    if re.search(r"\d+\s*%", text):
        return True
    if re.search(r"ingredients?\s*[:]|ingredient\s+list|contains?\s*[:]", text, re.IGNORECASE):
        return True
    # a known ingredient from the reference base counts as a list signal
    for part in re.split(r"[,;\n]", text):
        if lookup_ingredient(part.strip()):
            return True
    return False


# Precompute a normalized-alias -> key index once at import time.
_ALIAS_INDEX = {}
for _key, _entry in INGREDIENT_KB.items():
    for _alias in _entry["aliases"]:
        _ALIAS_INDEX[_norm(_alias)] = _key


def _display_name(key: str) -> str:
    return key.replace("_", " ").title()


# Safe OCR spelling corrections (normalised typo -> canonical display name).
# Only applied when the whole token matches - never for partial matches, so
# real ingredient names are never corrupted.
_INGREDIENT_TYPOS = {
    "parfume": "Parfum",
    "glycerine": "Glycerin",
    "tetrasodiumedta": "Tetrasodium EDTA",
    "disodiumphosphate": "Disodium Phosphate",
    "sorbicacid": "Sorbic Acid",
    "citronellol": "Citronellol",
    "hexylcinnamal": "Hexyl Cinnamal",
    "isopropanol": "Isopropanol",
    "benzalkoniumchloride": "Benzalkonium Chloride",
    "salicylicacid": "Salicylic Acid",
}


def parse_ingredients(text: str) -> list:
    """
    Split raw label text into a cleaned, de-duplicated ingredient list.
    Returns a list of dicts: {raw, name, normalized}.

    OCR text frequently collapses separators or joins the last two entries
    with " and "/"&" (e.g. "... Hexyl Cinnamal and Citronellol"). The " and "
    connector is only split when it appears AFTER the first comma-separated
    entry, so multi-word brand names like "Head & Shoulders Shampoo" (which
    OCR usually places first) are preserved. OCR mis-spellings are corrected
    only when the whole token matches a known typo.

    Delimiter-aware: commas / semicolons / newlines that occur inside
    parentheses are NOT used as ingredient separators so that entries like
    "Flavour Enhancer (INS 627, INS 631)" stay intact.
    """
    if not text:
        return []

    # Strip a leading "Ingredients:" / "INGREDIENTS:" label if present.
    text = re.sub(r"^\s*ingredients?\s*:\s*", "", text, flags=re.IGNORECASE)

    # ---- delimiter-aware split ----
    parts = []
    depth = 0
    current: list[str] = []
    for ch in text:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth = max(depth - 1, 0)
            current.append(ch)
        elif depth == 0 and ch in ",;\n\r":
            joined = "".join(current).strip()
            if joined:
                parts.append(joined)
            current = []
        else:
            current.append(ch)
    joined = "".join(current).strip()
    if joined:
        parts.append(joined)
    # ---- end split ----

    seen = set()
    out = []
    for idx, part in enumerate(parts):
        raw = part.strip()
        if not raw:
            continue
        # Split a trailing conjunct such as "A and B" / "A & B" - but ONLY in
        # a later comma-separated entry, never the (typically product-name)
        # first entry.
        chunks = [raw]
        if idx > 0 and re.search(r"\band\b|\s*&\s*", raw):
            chunks = [c.strip() for c in re.split(r"\band\b|\s*&\s*", raw) if c.strip()]
        for chunk in chunks:
            cleaned = chunk.strip(" .-–—\t")
            if not cleaned:
                continue
            if re.fullmatch(r"\d+(?:[.,]\d+)?\s*%", cleaned):
                continue
            cleaned = re.sub(r"^\d+(?:[.,]\d+)?\s*(?:%|g\b|ml\b|mg\b|kg\b|oz\b)?\s*", "", cleaned).strip()
            cleaned = re.sub(r"\s*\d+(?:[.,]\d+)?\s*%$", "", cleaned).strip()
            if not cleaned:
                continue
            norm = _norm(re.sub(r"\([^)]*\)", "", cleaned))
            if not norm or len(norm) < 2:
                continue
            if norm in _INGREDIENT_TYPOS:
                cleaned = _INGREDIENT_TYPOS[norm]
                norm = _norm(re.sub(r"\([^)]*\)", "", cleaned))
            if norm in seen:
                continue
            seen.add(norm)
            out.append({"raw": raw, "name": cleaned.strip(), "normalized": norm})
            if len(out) >= MAX_INGREDIENTS:
                break
        if len(out) >= MAX_INGREDIENTS:
            break
    return out


# Additive-reference codes (EU E-numbers and Codex INS numbers share the same
# digits for most additives). Extracted so an ingredient name such as
# "Flavour Enhancer (INS 627, INS 631)" can be matched independently.
_ADDITIVE_CODE_RE = re.compile(r"\b(?:e|ins)\s*-?\s*(\d{3,4}[a-z]?)\b", re.IGNORECASE)


def _extract_additive_codes(name: str) -> list:
    """Pull additive codes (E627 / INS 627 / E 150d) out of a name or phrase.

    Each code is normalised to the canonical 'e<number>' alias form used by the
    ingredient knowledge base, so "INS 627" and "E627" resolve to the same key.
    """
    if not name:
        return []
    codes = []
    for m in _ADDITIVE_CODE_RE.finditer(name):
        code = f"e{m.group(1).lower()}"
        if code not in codes:
            codes.append(code)
    return codes


def lookup_ingredient(name: str):
    """Return the knowledge-base entry for an ingredient name, or None.

    Looks up the full name first, then falls back to matching each additive
    reference code (E627 / INS 627 / E 150d) present ANYWHERE in the name - so
    "Flavour Enhancer (INS 627, INS 631)" is matched by whichever additive has
    a real knowledge-base entry while preserving the original ingredient name.
    An additive code with no database entry stays Unknown - it is never
    invented here.
    """
    key = _ALIAS_INDEX.get(_norm(name))
    if not key:
        # also try matching a single e-number suffix ("e102" present anywhere)
        norm = _norm(name)
        m = re.fullmatch(r"e[0-9]+", norm)
        if m:
            key = _ALIAS_INDEX.get(m.group(0))
    if not key:
        for code in _extract_additive_codes(name):
            key = _ALIAS_INDEX.get(code)
            if key:
                break
    if not key:
        return None
    entry = dict(INGREDIENT_KB[key])
    entry["key"] = key
    entry["display"] = _display_name(key)
    return entry


# --------------------------------------------------------------------------- #
# Category-aware ingredient assessment context.
#
# The SAME ingredient is not assessed identically for every product category:
# a substance used topically (e.g. a preservative in a face cream) is evaluated
# for external/skin use, while a substance in a food is evaluated for
# consumption, and a medicine-like product is handled strictly for ingredient
# information without medical advice. This module supplies a per-ingredient
# "context" that explains suitability for the detected category and, where the
# evidence clearly warrants it, a small score impact - while keeping the
# category's assessed risk band and the deterministic headline score intact.
# --------------------------------------------------------------------------- #
_CATEGORY_CONTEXT = {
    "food":        {"kind": "consumption", "label": "Food / consumption",
                    "phrase": "evaluated for consumption as a food ingredient."},
    "beverage":    {"kind": "consumption", "label": "Beverage / consumption",
                    "phrase": "evaluated for consumption as a beverage ingredient."},
    "snack":       {"kind": "consumption", "label": "Snack / consumption",
                    "phrase": "evaluated for consumption as a packaged-snack ingredient."},
    "supplement":  {"kind": "supplement",  "label": "Supplement",
                    "phrase": "evaluated for use as a dietary supplement ingredient."},
    "medicine":    {"kind": "medicine",    "label": "Medicine / health product",
                    "phrase": "used for ingredient information only - NOT medical advice."},
    "cosmetic":    {"kind": "topical",     "label": "Cosmetic / topical",
                    "phrase": "evaluated for external topical use in a cosmetic product."},
    "skincare":    {"kind": "topical",     "label": "Skincare / topical",
                    "phrase": "evaluated for external application to the skin."},
    "haircare":    {"kind": "topical",     "label": "Haircare / topical",
                    "phrase": "evaluated for use on the hair and scalp."},
    "personal care": {"kind": "topical",   "label": "Personal care / topical",
                    "phrase": "evaluated for external personal-care use."},
    "soap":        {"kind": "topical",     "label": "Soap / cleanser",
                    "phrase": "evaluated for external cleansing use."},
    "toothpaste":  {"kind": "topical",     "label": "Toothpaste / oral care",
                    "phrase": "evaluated for oral care use; not intended to be swallowed."},
    "baby":        {"kind": "topical",     "label": "Baby product",
                    "phrase": "evaluated for use on babies - handled with extra caution."},
    "pet":         {"kind": "topical",     "label": "Pet product",
                    "phrase": "evaluated for use on/for pets, not humans."},
    "household cleaner": {"kind": "chemical", "label": "Household cleaner",
                    "phrase": "evaluated for household-cleaning use, not consumption."},
    "disinfectant": {"kind": "chemical",   "label": "Disinfectant",
                    "phrase": "evaluated for disinfection use, not consumption."},
    "sanitizer":   {"kind": "chemical",    "label": "Sanitizer",
                    "phrase": "evaluated for sanitising use, not consumption."},
    "laundry":     {"kind": "chemical",    "label": "Laundry product",
                    "phrase": "evaluated for laundry use, not consumption."},
    "chemical":    {"kind": "chemical",    "label": "Chemical product",
                    "phrase": "evaluated for its chemical/intended use with caution."},
    "electronics": {"kind": "technical",   "label": "Electronic product",
                    "phrase": "technical product - no food-style ingredient scoring."},
    "battery":     {"kind": "technical",   "label": "Battery",
                    "phrase": "technical product - assessed for safe handling, not consumption."},
    "stationery":  {"kind": "technical",   "label": "Stationery",
                    "phrase": "general consumer product."},
    "agricultural": {"kind": "technical",  "label": "Agricultural product",
                    "phrase": "evaluated for agricultural use, not consumption."},
    "automotive":  {"kind": "technical",   "label": "Automotive product",
                    "phrase": "evaluated for automotive use, not consumption."},
    "other":       {"kind": "unknown",     "label": "Other product",
                    "phrase": "evaluated as a general consumer product."},
    "unknown":     {"kind": "unknown",     "label": "Unknown category",
                    "phrase": "product category not confidently determined - assessed generically."},
}

# Per-ingredient score impact points used ONLY for explanation/display (the
# deterministic headline score is driven by the aggregated risk bands, so these
# cannot move the final 0-100 band out of its earned range).
_SCORE_IMPACT = {"lower": 0, "low": 0, "moderate": -8, "higher": -20, "unknown": -3}


def _category_context(category: str) -> dict:
    return _CATEGORY_CONTEXT.get(category or "unknown", _CATEGORY_CONTEXT["unknown"])


def _risk_impact_points(category: str) -> int:
    return _SCORE_IMPACT.get(category, 0)


def _ingredient_in_context(name: str, entry: dict | None, product_category: str) -> dict:
    """Enrich an ingredient card with category-aware suitability + score impact.

    `entry` is a knowledge-base record (or None for unknown ingredients). The
    base risk category is preserved so aggregated scoring stays deterministic;
    what changes with the product category is the *suitability explanation*,
    the *context note*, and a *display score impact*.
    """
    ctx = _category_context(product_category)

    if entry is None:
        return {
            "category": "unknown",
            "verification": "Needs Verification",
            "suitable_for_category": (
                f"Could not be confidently verified, so suitability for this "
                f"{ctx['label'].lower()} cannot be judged."
            ),
            "context_note": (
                f"This ingredient could not be confidently verified. It is marked "
                f"unknown / needs verification - not automatically safe and not "
                f"automatically harmful."
            ),
            "score_impact": _risk_impact_points("unknown"),
            "score_impact_label": "Reduces confidence",
        }

    base_cat = entry["category"]
    kind = ctx["kind"]

    # Suitability phrasing by base risk + product category kind.
    if base_cat == "higher":
        suitability = (
            f"Of genuine concern for {ctx['label'].lower()} use - restricted or "
            f"banned in some jurisdictions, so NOT suitable for routine use."
        )
        context_note = f"Ingredient is flagged as higher concern in the {ctx['label'].lower()} context ({ctx['phrase']})."
    elif base_cat == "moderate":
        suitability = (
            f"Allowed for {ctx['label'].lower()} use but with real caveats - "
            f"check the specific concern before use."
        )
        context_note = f"Ingredient carries a moderate-concern rating in the {ctx['label'].lower()} context ({ctx['phrase']})."
    elif base_cat == "low":
        suitability = (
            f"Generally appropriate for {ctx['label'].lower()} use based on the "
            f"available evidence."
        )
        context_note = f"Ingredient is low concern for the {ctx['label'].lower()} context ({ctx['phrase']})."
    else:
        suitability = f"Suitability for {ctx['label'].lower()} use could not be determined."
        context_note = f"Ingredient could not be confidently verified ({ctx['phrase']})."

    # For consumption-category products, an ingredient that is normally topical
    # only is worth an explicit caution note (informational, never panic).
    extra = ""
    if kind == "consumption" and entry.get("use") and re.search(
        r"(?:topical|skin|hair|cosmetic|external|surfactant|cleanser|foaming)", entry["use"], re.IGNORECASE
    ):
        extra = " Though usually associated with external use, this ingredient is listed on a consumable label - verify against the specific food regulation."
        suitability += extra
        context_note += extra

    if kind == "medicine" and base_cat != "higher":
        context_note += " This is ingredient information only and must not be read as medical advice."

    return {
        "category": base_cat,
        "verification": "Verified",
        "suitable_for_category": suitability,
        "context_note": context_note,
        "score_impact": _risk_impact_points(base_cat),
        "score_impact_label": (
            "Low / no negative impact" if base_cat == "low"
            else "Moderate concern - reduces score" if base_cat == "moderate"
            else "High concern - strongly reduces score" if base_cat == "higher"
            else "Reduces confidence"
        ),
    }


def _classify_ingredients(ingredients: list, category: str = "") -> tuple:
    """Return (annotated, counts, unknowns, concerns).

    Each card is enriched with category-aware suitability + a display score
    impact. Unknown ingredients are never dangerous. Never raises.
    """
    counts = {"low": 0, "moderate": 0, "higher": 0, "unknown": 0}
    annotated = []
    unknowns = []
    concerns = []
    for ing in ingredients:
        entry = lookup_ingredient(ing["name"])
        if not entry:
            ctx = _ingredient_in_context(ing["name"], None, category)
            counts["unknown"] += 1
            unknowns.append(ing["name"])
            card = {
                "name": ing["name"],
                "category": "unknown",
                "use": "Not in the TrustLens ingredient database",
                "info": "No classification is possible from the built-in database. "
                        "An unknown ingredient is not proof that it is harmful.",
                "reason": "No knowledge-base entry - marked unknown, not dangerous.",
                "confidence": "Low",
                "source": [],
            }
            card.update(ctx)
            annotated.append(card)
            continue
        base_cat = entry["category"]
        ctx = _ingredient_in_context(ing["name"], entry, category)
        counts[base_cat] += 1
        card = {
            "name": ing["name"],
            "category": base_cat,
            "use": entry["use"],
            "info": entry["info"],
            "reason": entry["reason"],
            "confidence": "Medium" if base_cat in ("low", "moderate") else "High",
            "source": entry["source"],
        }
        card.update(ctx)
        annotated.append(card)
        if base_cat == "higher":
            concerns.append({
                "name": ing["name"],
                "category": "higher",
                "use": entry["use"],
                "info": entry["info"],
                "reason": entry["reason"],
                "confidence": "High",
                "source": entry["source"],
            })
    return annotated, counts, unknowns, concerns


# --------------------------------------------------------------------------- #
# Product trust score - reusable, evidence-based scoring.
#
# Three display bands (score + risk label + recommendation) are derived from
# the ingredient counts. Everything is defined here so the scoring logic can be
# tuned in ONE place:
#   HIGH RISK      20-30  -> any higher-concern ingredient
#   MODERATE RISK  50-60  -> moderate-concern ingredient(s), or >50% unknown
#   LOW RISK       80-95  -> otherwise (identifiable ingredients are low risk)
#
# Honesty rules baked in:
#   - Unknown ingredients NEVER make a product dangerous. They only cap a
#     LOW-RISK score at 85 (we have less information), or push a majority-
#     unknown label into the "unknown / insufficient evidence" bucket.
#   - The score never falls below 20 and is never a fixed verdict - every
#     value is derived from the actual ingredient counts.
# --------------------------------------------------------------------------- #
PRODUCT_SCORE_BANDS = {
    "dangerous": (20, 30),
    "moderate": (50, 60),
    "safe": (80, 95),
}

_RISK_LABELS = {
    "higher": "HIGH RISK",
    "moderate": "MODERATE RISK",
    "low": "LOW RISK",
    "unknown": "UNKNOWN / INSUFFICIENT EVIDENCE",
    "insufficient": "INSUFFICIENT EVIDENCE",
}


def calculate_product_trust_score(counts: dict, total: int) -> dict:
    """Compute the deterministic trust score + risk label for a product.

    counts: {"low": int, "moderate": int, "higher": int, "unknown": int}
    total:  number of unique ingredients parsed (0 when none).

    Returns a dict with score, risk_level, risk_label, recommendation and why.
    """
    higher = counts.get("higher", 0)
    moderate = counts.get("moderate", 0)
    unknown = counts.get("unknown", 0)
    total = max(0, total)
    unknown_ratio = (unknown / total) if total else 0
    why = []

    if higher > 0:
        # HIGH RISK: any higher-concern ingredient places the product here.
        score = 30 - min(higher * 5, 10)          # 30, 25, 20
        risk_level = "higher"
        why.append(
            f"{higher} higher-concern ingredient{'s' if higher != 1 else ''} "
            "detected (restricted/banned or strong evidence of harm)."
        )
        recommendation = (
            "Avoid this product. It contains ingredient(s) of genuine concern "
            "that are restricted or banned in some jurisdictions."
        )
    elif moderate > 0:
        # MODERATE RISK: allergens, irritants, regulated additives and similar
        # real-but-limited concerns land here.
        score = 60 - min(moderate * 5, 10)        # 60, 55, 50
        risk_level = "moderate"
        why.append(
            f"{moderate} moderate-concern ingredient{'s' if moderate != 1 else ''} "
            "detected (allowed but with real caveats)."
        )
        recommendation = (
            "Use with caution. Moderate-concern ingredient(s) are present; "
            "sensitive individuals should check the specific ingredient notes."
        )
    elif unknown_ratio > 0.5:
        # Most ingredients could not be classified - neither safe nor dangerous.
        score = 55
        risk_level = "unknown"
        why.append(
            "More than half of the ingredients could not be classified - too "
            "little information for a firm safety assessment."
        )
        recommendation = (
            "Insufficient information for a reliable assessment. Provide the "
            "full ingredient list or a clearer label image."
        )
    elif total > 0:
        # LOW RISK: every identifiable ingredient is low concern. Unknowns only
        # cap the score at 85 - they never raise it or make it dangerous.
        score = 95 if unknown == 0 else 85
        risk_level = "low"
        if unknown:
            why.append(
                f"{unknown} unknown ingredient{'s' if unknown != 1 else ''} - "
                "marked unknown, not dangerous."
            )
        recommendation = (
            "Generally safe based on the available ingredient information. "
            "No higher- or moderate-concern ingredient was detected."
        )
    else:
        score = 50
        risk_level = "insufficient"
        why.append("No ingredient list could be read or parsed.")
        recommendation = "Insufficient information for a reliable assessment."

    score = max(20, min(100, score))              # never below the floor
    return {
        "score": score,
        "risk_level": risk_level,
        "risk_label": _RISK_LABELS[risk_level],
        "recommendation": recommendation,
        "why": why,
    }


def _compute_score(counts: dict, unknowns: list, total: int, **kwargs) -> dict:
    """Deterministic safety score from the ingredient counts.

    Uses the documented, evidence-based three-band scoring model
    (HIGH 20-30 / MODERATE 50-60 / LOW 80-95), driven purely by the
    classified ingredient profile. A product that is not verified in a
    database must never collapse into a meaningless fixed score because of
    missing label meta-fields - the band always reflects the ingredients
    actually found on the label.
    """
    info = calculate_product_trust_score(counts, total)
    score = info["score"]
    status = classify(score)
    overall_status = {
        "safe": "Safe",
        "warning": "Use with Caution",
        "dangerous": "Not Recommended",
    }.get(status, status.title())
    return {
        "score": score,
        "status": status,
        "risk_level": info["risk_level"],
        "risk_label": info["risk_label"],
        "overall_status": overall_status,
        "recommendation": info["recommendation"],
        "why": info["why"],
        "explanation": f"Trust Score: {score}/100 ({overall_status.lower()}). "
        + " ".join(info["why"]),
        "score_explanation": f"Trust Score: {score}/100 - {overall_status}.",
        "capped_unknown": counts.get("unknown", 0) > 0,
        "capped_coverage": total > 0 and (counts.get("unknown", 0) / total) > 0.5,
    }


def _positive_findings(counts: dict, total: int, reasons: list) -> list:
    positives = []
    if total and counts["higher"] == 0:
        positives.append("No higher-concern ingredients detected.")
    if counts["low"] and counts["moderate"] == 0 and counts["higher"] == 0:
        positives.append("All identified ingredients are classified as low concern.")
    if total:
        positives.append(
            f"{counts['low']} low-concern, {counts['moderate']} moderate-concern, "
            f"{counts['higher']} higher-concern, {counts['unknown']} unknown "
            f"of {total} unique ingredient{'s' if total != 1 else ''}."
        )
    if reasons:
        positives.append("Every finding above is explained - no black-box scoring.")
    return positives


def _missing_info(annotated: list, product_name: str, from_image: bool) -> list:
    missing = []
    if not product_name:
        missing.append("No product name could be identified.")
    unknown_count = sum(1 for a in annotated if a["category"] == "unknown")
    if unknown_count:
        missing.append(
            f"{unknown_count} ingredient{'s' if unknown_count != 1 else ''} could not "
            "be classified (insufficient evidence in the built-in database)."
        )
    if not annotated:
        missing.append("No ingredient list could be read or parsed.")
    if from_image:
        missing.append("Manufacturer and usage information were not read from the label.")
    else:
        missing.append("No manufacturer / batch / usage details were provided.")
    return missing


# --------------------------------------------------------------------------- #
# Hybrid pipeline: product identification against the verified Product database
# --------------------------------------------------------------------------- #
_MATCH_LABELS = {
    "High": "Verified product database match (High confidence)",
    "Medium": "Product database match (Medium confidence)",
    "Low": "Possible product database match (Low confidence)",
    "BrandOnly": "Brand identified - exact product/variant not confirmed in the database",
    "None": "Product not found in the verified product database.",
}

# Confidence labels shown when the exact product could NOT be confirmed. Even a
# no-match scan still reports how confident the identification attempt was.
_IDENT_CONFIDENCE_LABELS = {
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "BrandOnly": "Medium",
    "None": "Low",
}


def _decode_product_symbols(image_path: str) -> dict:
    """Best-effort decode of barcodes (EAN/UPC/etc.) and QR codes from a label.

    Never raises. Returns:
        {
          "barcodes": [str, ...],   # decoded 1D barcode payloads (GTIN/EAN digits)
          "gtin": str|None,         # best retail barcode (13/12/8 digit) to use
          "qr_payloads": [str, ...],# decoded QR payloads (URLs, ids, GTINs, ...)
          "count": int,             # total symbologies read
        }

    The decoded identifiers are feed into product identification - exact GTIN
    digits can confirm a verified product record. QR payloads are captured so a
    product QR that encodes a GTIN or product id can also help identify it.
    """
    result = {"barcodes": [], "gtin": None, "qr_payloads": [], "count": 0}
    if not image_path:
        return result

    # Reuse the QR decoder (zxing-cpp -> pyzbar -> OpenCV) for QR/DataMatrix.
    try:
        from services.qr_scanner import decode_qr as _decode_qr

        try:
            qr = _decode_qr(image_path, report=None)
            for payload in qr or []:
                cleaned = (payload or "").strip()
                if cleaned and cleaned not in result["qr_payloads"]:
                    result["qr_payloads"].append(cleaned)
        except Exception:  # noqa: BLE001 - QR not present/unreadable is fine
            pass
    except Exception:  # noqa: BLE001
        pass

    # 1D barcodes (EAN/GTIN/UPC/Code128/...) via zxing-cpp over several
    # preprocessed variants (straight photo, upscaled, thresholded).
    try:
        import zxingcpp
        import numpy as np
        from PIL import Image, ImageOps

        try:
            pil = Image.open(image_path).convert("RGB")
        except Exception:  # noqa: BLE001
            pil = None

        variants = []
        if pil is not None:
            w, h = pil.size
            gray = np.array(ImageOps.grayscale(pil))
            variants.append(gray)
            if max(w, h) < 1200:
                scale = 2.0 if max(w, h) >= 500 else 3.0
                big = pil.resize((int(w * scale), int(h * scale)), Image.LANCZOS)
                variants.append(np.array(ImageOps.grayscale(big)))
        else:
            variants.append(image_path)

        seen = set()
        for variant in variants:
            try:
                found = zxingcpp.read_barcodes(
                    variant,
                    formats=zxingcpp.BarcodeFormat.All,
                    try_rotate=True,
                    try_downscale=True,
                    try_invert=True,
                )
            except Exception:  # noqa: BLE001 - some variants fail
                continue
            for b in found or []:
                text = (b.text or "").strip()
                if not text or not text.isdigit():
                    continue
                if text in seen:
                    continue
                seen.add(text)
                if text not in result["barcodes"]:
                    result["barcodes"].append(text)
        result["barcodes"] = result["barcodes"][:5]
    except Exception as exc:  # noqa: BLE001 - barcode decoding is best-effort
        logger.info("Barcode decode unavailable (%s): %s", type(exc).__name__, exc)

    # Pick the most useful retail identifier (longest plausible GTIN).
    gtin_candidates = [b for b in result["barcodes"] if 8 <= len(b) <= 14]
    if gtin_candidates:
        result["gtin"] = max(gtin_candidates, key=lambda b: (b.isdigit(), len(b)))
    result["count"] = len(result["barcodes"]) + len(result["qr_payloads"])
    return result


def _norm_words(text: str) -> str:
    """Lowercase, keep words, collapse whitespace (for product-name matching)."""
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", (text or "").lower())).strip()


def _token_set(text: str) -> set:
    return set(_norm_words(text).split())


def _no_db_match() -> dict:
    return {
        "level": "None",
        "product": None,
        "label": _MATCH_LABELS["None"],
        "notes": [],
        "matched_brand": None,
    }


def _identify_product(combined: str, barcode_digits: str = "") -> dict:
    """
    Match the label text against the verified Product database.

    Confidence levels:
      High      - full signature (brand + product name [+ variant]) on the label
      Medium    - brand + product name matched (variant unconfirmed), or a
                  generic product category matched by name
      Low       - weak / partial generic category overlap
      BrandOnly - brand recognised, but no exact product/variant confirmed
      None      - no brand or product matched

    A brand match alone never selects a random product of that brand.
    `barcode_digits` (optional) are GTIN/EAN digits decoded from the image,
    which can confirm a verified product record even if the digits are not in
    the OCR text.
    """
    norm = _norm_words(combined)
    if not norm and not barcode_digits:
        return _no_db_match()
    tokens = _token_set(combined)
    barcode_digits = re.sub(r"[^0-9]", "", barcode_digits or "")
    combined_barcode_digits = re.sub(r"[^0-9]", "", combined)
    # Union of digits found on the label (OCR or decoded barcode) so a barcode
    # decoded from the image is also considered for the exact match.
    all_barcode_digits = (
        combined_barcode_digits
        if combined_barcode_digits not in (barcode_digits, "")
        else barcode_digits
    )

    rank_order = {"High": 3, "Medium": 2, "Low": 1}
    best = None
    try:
        products = Product.query.all()
    except Exception:  # noqa: BLE001 - no DB context (e.g. unit tests) -> KB fallback
        products = []

    for product in products:
        generic = product.brand_name.strip().lower() == "generic"
        brand_tokens = set() if generic else _token_set(product.brand_name)
        name_tokens = _token_set(product.product_name)
        var_tokens = _token_set(product.product_variant) if product.product_variant else set()

        signature = _norm_words(
            " ".join(
                x for x in (product.brand_name, product.product_name, product.product_variant)
                if x
            )
        )
        has_brand = bool(brand_tokens) and brand_tokens <= tokens
        brand_hit = bool(brand_tokens) and bool(brand_tokens & tokens)
        name_full = bool(name_tokens) and name_tokens <= tokens
        name_overlap = len(name_tokens & tokens) / max(1, len(name_tokens))
        var_full = bool(var_tokens) and var_tokens <= tokens
        sig_match = bool(signature) and signature in norm
        barcode_match = bool(product.barcode) and product.barcode in all_barcode_digits

        level = None
        notes = []
        if sig_match:
            level, notes = "High", ["Full product name and variant matched on the label."]
        elif barcode_match:
            level, notes = "High", ["Product barcode matched the database record."]
        elif has_brand and name_full and var_full:
            level, notes = "High", ["Brand, product name and variant all matched."]
        elif has_brand and name_full:
            level, notes = "Medium", ["Brand and product name matched; variant not confirmed."]
        elif has_brand and name_overlap >= 0.5:
            level, notes = "Medium", ["Brand matched with a partial product-name match."]
        elif generic and name_full:
            level, notes = "Medium", ["Generic product category matched on the label."]
        elif generic and name_overlap >= 0.6:
            level, notes = "Low", ["Possible generic product category match - treated cautiously."]
        else:
            continue

        if best is None or rank_order.get(level, 0) > best["rank"]:
            best = {"rank": rank_order.get(level, 0), "level": level, "product": product, "notes": notes}

    if best:
        return {
            "level": best["level"],
            "product": best["product"],
            "label": _MATCH_LABELS[best["level"]],
            "notes": best["notes"],
            "matched_brand": None,
        }

    # No exact product confirmed - is the brand at least recognisable?
    for product in products:
        if product.brand_name.strip().lower() == "generic":
            continue
        brand_tokens = _token_set(product.brand_name)
        if brand_tokens and brand_tokens <= tokens:
            return {
                "level": "BrandOnly",
                "product": None,
                "label": _MATCH_LABELS["BrandOnly"],
                "notes": [
                    f"The brand '{product.brand_name}' appears on the label, but the exact "
                    "product/variant could not be confirmed, so no variant-specific "
                    "ingredient record was applied."
                ],
                "matched_brand": product.brand_name,
            }

    return _no_db_match()


def _consumption_notice(status: str) -> str:
    """Human-readable note on how a product's consumption status is treated."""
    if not status:
        return "The intended consumption status of this product is unknown."
    notices = {
        "Intended for human consumption": (
            "This product is intended for human consumption, so ingredients are "
            "assessed for food use."
        ),
        "Not intended for human consumption": (
            "This product is NOT intended for human consumption. The score assesses "
            "ingredient safety for the product's intended use; it is not penalised "
            "for not being edible."
        ),
        "External use only": (
            "This product is for external use only. The score assesses ingredient "
            "safety for topical use and is not penalised for not being edible."
        ),
        "Household/industrial use": (
            "This is a household/industrial product. The score assesses ingredient "
            "safety for that intended use; it is not penalised for not being edible."
        ),
    }
    return notices.get(status, "The intended consumption status of this product is unknown.")


def _ingredient_db_card(assoc, ing, alias_norms, parsed_norms) -> dict:
    """Frontend ingredient card from a verified product-ingredient record."""
    detected = any(
        an and (pn == an or an in pn or pn in an)
        for pn in parsed_norms
        for an in alias_norms
    )
    concerns = ing.potential_concerns or []
    return {
        "name": ing.ingredient_name,
        "category": ing.risk_category or "unknown",
        "use": ing.common_function or "Function not specified",
        "info": ing.description,
        "reason": ing.safety_information or (". ".join(concerns) if concerns else None),
        "confidence": {"High": "High", "Medium": "Medium", "Low": "Low"}.get(ing.evidence_level or "", "Medium"),
        "source": [ing.source] if ing.source else [],
        "source_url": ing.source_url,
        "source_date": ing.source_date,
        "ingredient_type": ing.ingredient_type,
        "ingestion_status": ing.ingestion_status,
        "external_use_information": ing.external_use_information,
        "evidence_level": ing.evidence_level,
        "concerns": concerns,
        "concentration": assoc.concentration,
        "concentration_unit": assoc.concentration_unit,
        "role": assoc.role,
        "detection": "Found on label" if detected else "Expected from database but not visible",
    }


# --------------------------------------------------------------------------- #
# Score explanations: Positive / Concern / Deduction factors.
#
# These are derived directly from the (already category-aware) ingredient cards,
# so they can never contradict the deterministic score. "Deductions" reflect the
# points that a concern-level ingredient would pull from a starting maximum -
# shown to make the score explainable, never to retroactively change it.
# --------------------------------------------------------------------------- #
def _score_factors(ingredients: list) -> dict:
    """Derive positive_factors / concern_factors / score_deductions from cards.

    Cards are expected to carry at least "name" and "category" (plus optional
    "suitable_for_category", "context_note", "reason"). Never raises.
    """
    positives = []
    concerns = []
    deductions = []
    for card in ingredients:
        cat = card.get("category", "unknown")
        name = card.get("name", "Ingredient")
        use = card.get("use", "") or ""
        reason = card.get("reason", "") or "See note above."
        suitability = card.get("suitable_for_category", "") or ""
        context_note = card.get("context_note", "") or ""
        impact = card.get("score_impact", _risk_impact_points(cat))

        if cat == "low":
            positives.append({
                "name": name,
                "category": cat,
                "text": (f"{name} - low-concern ingredient. {suitability}".strip()),
                "detail": use,
            })
        elif cat == "moderate":
            concerns.append({
                "name": name,
                "category": cat,
                "text": (f"{name} - moderate concern. {context_note or reason}".strip()),
                "detail": reason,
            })
            deductions.append({
                "name": name,
                "category": cat,
                "points": impact,
                "reason": reason,
                "label": "Moderate-concern ingredient",
            })
        elif cat == "higher":
            concerns.append({
                "name": name,
                "category": cat,
                "text": f"{name} - higher concern. {context_note or reason}".strip(),
                "detail": reason,
            })
            deductions.append({
                "name": name,
                "category": cat,
                "points": impact,
                "reason": reason,
                "label": "Higher-concern ingredient",
            })
        else:
            concerns.append({
                "name": name,
                "category": cat,
                "text": f"{name} - could not be verified; marked unknown/needs verification, not automatically harmful.",
                "detail": reason,
            })
            deductions.append({
                "name": name,
                "category": cat,
                "points": impact,
                "reason": reason,
                "label": "Unverified ingredient",
            })

    # De-duplicate concern/deduction entries by name (same ingredient may appear
    # once in cards already, but guards against duplicate rows in DB extras).
    seen = set()
    concerns = [c for c in concerns if not (c["name"] in seen or seen.add(c["name"]))]
    seen = set()
    deductions = [d for d in deductions if not (d["name"] in seen or seen.add(d["name"]))]
    return {"positive_factors": positives, "concern_factors": concerns, "score_deductions": deductions}


def _db_product_payload(match, combined, source, extracted_text, from_image, start) -> dict:
    """Full analysis for a product matched in the verified database."""
    product = match["product"]
    links = product.ingredient_links()

    alias_norms = set()
    for _assoc, ing in links:
        for alias in (ing.aliases or []) + [ing.ingredient_name, ing.normalized_name]:
            alias_norms.add(_norm(alias))

    parsed = parse_ingredients(combined)
    parsed_norms = [p["normalized"] for p in parsed]

    # Words that are part of the product's own name (brand/name/variant) must
    # not be mistaken for label ingredients.
    skip_norms = set()
    for chunk in (product.brand_name, product.product_name, product.product_variant):
        skip_norms |= _token_set(chunk)
    signature_norm = _norm(
        " ".join(
            x for x in (product.brand_name, product.product_name, product.product_variant)
            if x
        )
    )

    cards = [_ingredient_db_card(assoc, ing, alias_norms, parsed_norms) for assoc, ing in links]

    extras = []
    seen = set()
    if _looks_like_ingredient_list(combined) or len(parsed) > 1:
        for item in parsed:
            norm = item["normalized"]
            if norm in alias_norms or norm in skip_norms:
                continue
            if signature_norm and (signature_norm in norm or norm in signature_norm):
                continue
            if re.match(
                r"^(ingredients?|ingredient\s+list|contains?|content|included)\b",
                item["name"], re.IGNORECASE,
            ):
                continue
            if norm in seen:
                continue
            seen.add(norm)
            entry = lookup_ingredient(item["name"])
            if entry:
                extras.append({
                    "name": item["name"],
                    "category": entry["category"],
                    "use": entry["use"],
                    "info": entry["info"],
                    "reason": entry["reason"],
                    "confidence": entry.get("confidence") or "Medium",
                    "source": entry["source"],
                    "source_url": None,
                    "detection": "Additional label ingredient",
                })
            else:
                extras.append({
                    "name": item["name"],
                    "category": "unknown",
                    "use": "Not in the TrustLens ingredient database",
                    "info": "No classification is possible from the built-in database. An "
                            "unknown ingredient is not proof that it is harmful.",
                    "reason": "No knowledge-base entry - marked unknown, not dangerous.",
                    "confidence": "Low",
                    "source": [],
                    "source_url": None,
                    "detection": "Unknown ingredient on label",
                })

    ingredients = cards + extras
    total = len(ingredients)
    counts = {"low": 0, "moderate": 0, "higher": 0, "unknown": 0}
    unknowns = []
    for card in ingredients:
        counts[card["category"]] += 1
        if card["category"] == "unknown":
            unknowns.append(card["name"])

    # Build separate safe/unsafe explanation panels
    why_safe = []
    why_unsafe = []
    for card in ingredients:
        cat = card.get("category", "unknown")
        item = {
            "name": card["name"],
            "category": cat,
            "use": card.get("use", ""),
            "info": card.get("info", ""),
            "reason": card.get("reason", ""),
            "detection": card.get("detection", ""),
        }
        if cat == "low":
            why_safe.append(item)
        elif cat == "higher":
            why_unsafe.append(item)
        elif cat == "moderate":
            why_safe.append(item)
            why_unsafe.append({**item, "note": "Allowed but with real caveats"})
        else:
            why_safe.append(item)

    db_category = classify_product_category(combined, product.category or "", product.subcategory or "")
    for card in ingredients:
        entry = (None if card["category"] == "unknown"
                 else {"category": card.get("category"),
                        "use": card.get("use", ""),
                        "info": card.get("info", ""),
                        "reason": card.get("reason", "")})
        card.update(_ingredient_in_context(card["name"], entry, db_category))
    factors = _score_factors(ingredients)
    certifications = _detect_certifications(combined, db_category)
    claim_consistency = _check_claim_consistency(_extract_claims(combined), parsed)
    missing_mandatory = _check_mandatory_info(combined, db_category)
    score_info = _compute_score(
        counts, unknowns, total,
        category=db_category,
        edible_status=_classify_edible_status(db_category, combined, product.consumption_status),
        allergen_warnings=_detect_allergens(parsed),
        ocr_conf=60 if from_image and extracted_text else (100 if source == "text" else 0),
        database_match=match["level"],
        from_image=from_image,
        extracted_text=extracted_text,
        product_info=product.to_dict(),
        certifications=certifications,
        claim_consistency=claim_consistency,
        missing_mandatory=missing_mandatory,
    )

    reasons = []
    for card in ingredients:
        severity = {"low": "success", "moderate": "warning", "higher": "danger"}.get(
            card["category"], "info"
        )
        pts = {"low": 0, "moderate": -8, "higher": -25}.get(card["category"], 0)
        reasons.append({
            "severity": severity,
            "text": f"{card['name']}: {card['use']} - {card['reason'] or 'No specific concern recorded.'}",
            "points": pts,
            "detail": f"Category: {card['category']} | Detection: {card['detection']}",
        })
    reasons.append({
        "severity": "success", "points": 0,
        "text": f"Verified product database match ({match['level']} confidence).",
    })
    if product.consumption_status:
        reasons.append({
            "severity": "info", "points": 0,
            "text": f"Consumption status: {product.consumption_status} - assessed for its intended use.",
        })
    if score_info["capped_unknown"]:
        reasons.append({
            "severity": "info", "points": 0,
            "text": f"{counts['unknown']} unknown ingredient(s) - marked unknown, not dangerous.",
        })
    if score_info["capped_coverage"]:
        reasons.append({
            "severity": "warning", "points": 0,
            "text": "More than half of the ingredients could not be classified - too little information for a firm score.",
        })

    positives = []
    positives.append(
        f"Verified product record: {product.brand_name} {product.product_name}"
        + (f" ({product.product_variant})" if product.product_variant else "")
    )
    if counts["higher"] == 0 and total:
        positives.append("No higher-concern ingredients detected in the verified product record.")
    if counts["moderate"] == 0 and counts["higher"] == 0 and total:
        positives.append("All identified ingredients are classified as low concern.")
    if product.consumption_status:
        positives.append(f"Consumption status: {product.consumption_status}.")
    positives.append("Every finding is explained against the verified product database - no black-box scoring.")

    missing = []
    not_visible = [c["name"] for c in cards if c["detection"] != "Found on label"]
    if not_visible:
        missing.append(
            f"{len(not_visible)} ingredient(s) in the verified record were not read on the "
            f"label: {', '.join(not_visible)}."
        )
    if unknowns:
        missing.append(
            f"{len(unknowns)} ingredient(s) on the label are not in the verified ingredient database."
        )
    if not product.consumption_status or product.consumption_status == "Unknown":
        missing.append("The intended consumption status of this product is not recorded.")
    undisclosed = [c["name"] for c in cards if c.get("concentration") is None]
    if undisclosed:
        missing.append(
            f"Concentration is not disclosed for {len(undisclosed)} ingredient(s) - "
            "unknown concentrations are never guessed."
        )
    if from_image and not extracted_text:
        missing.append("No readable text was extracted from the uploaded image.")

    match_pct = {"High": 90, "Medium": 70, "Low": 50}[match["level"]]
    coverage = round(100 * (counts["low"] + counts["moderate"] + counts["higher"]) / total) if total else 0
    ocr_conf = 100 if not from_image else (60 if extracted_text else 0)
    overall = round(0.4 * match_pct + 0.3 * coverage + 0.3 * ocr_conf)

    risk_label = score_info["risk_label"]
    recommendation = score_info["recommendation"]

    product_name = product.product_name
    if product.brand_name.strip().lower() != "generic":
        product_name = f"{product.brand_name} {product.product_name}"
    if product.product_variant:
        product_name = f"{product_name} ({product.product_variant})"

    explanation = (
        f"Verified product '{product.brand_name} {product.product_name}' matched the "
        f"TrustLens product database ({match['level']} confidence). Based on {total} "
        f"ingredient{'s' if total != 1 else ''}, the safety score is {score_info['score']}/100 "
        f"({risk_label.lower()}). {_consumption_notice(product.consumption_status)}"
    )

    return {
        "score": score_info["score"],
        "status": score_info["status"],
        "reliable": True,
        "assessment": f"{risk_label} - safety score {score_info['score']}/100",
        "risk_level": score_info["risk_level"],
        "risk_label": risk_label,
        "recommendation": recommendation,
        "why": score_info["why"],
        "product_name": product_name,
        "input_source": source,
        "extracted_text": extracted_text,
        "ocr_failed": bool(from_image and not extracted_text),
        "ingredients": ingredients,
        "ingredient_count": total,
        "concerns": [c for c in ingredients if c["category"] == "higher"],
        "positives": positives,
        "positive_factors": factors["positive_factors"],
        "concern_factors": factors["concern_factors"],
        "score_deductions": factors["score_deductions"],
        "unknown_ingredients": unknowns,
        "missing": missing,
        "explanation": explanation,
        "why_safe": why_safe,
        "why_unsafe": why_unsafe,
        "confidence": {
            "overall": overall,
            "ingredient_coverage": coverage,
            "ocr": ocr_conf,
            "product_match": match_pct,
        },
        "reasons": reasons,
        "processing_time_ms": int((time.perf_counter() - start) * 1000),
    }


def _ocr_quality(payload: dict) -> str:
    """Summarise OCR/input quality for the data-quality panel."""
    src = payload.get("input_source")
    text = (payload.get("extracted_text") or "").strip()
    if src == "image":
        if not text:
            return "None"
        return "Good" if len(text) >= 60 else "Partial"
    if src == "text":
        return "Good"
    return "None"


def _score_decision(payload: dict, match: dict, category: str) -> tuple:
    """Return (score_available, score_not_available_reason).

    Every scan produces a deterministic 0-100 trust score derived from the
    evidence actually gathered: an ingredient-risk score for consumable,
    topical and chemical products, and a verifiability score for technical
    products. A score is therefore ALWAYS available so the UI can render the
    trust gauge. Honest caveats (product not verified in the database,
    unreadable label) are carried in the assessment text and the data-quality
    panel instead of hiding the score.
    """
    return True, None


def _technical_assessment(match: dict, combined: str, source: str, extracted_text: str,
                          from_image: bool, start: float) -> dict:
    """Limited analysis for electronics / batteries / other technical products.

    No ingredient scoring is attempted. Only information actually visible on the
    label or present in the verified product record is reported.
    """
    product = match.get("product")
    specs = _technical_specs(combined)
    label_warnings = _extract_label_warnings(combined)

    product_name = None
    if product is not None:
        product_name = f"{product.brand_name} {product.product_name}".strip()
    if not product_name and combined:
        for line in combined.splitlines():
            line = line.strip()
            if 3 <= len(line) <= 80 and "," not in line and ";" not in line:
                product_name = line
                break

    missing = []
    if not specs:
        missing.append("No technical specifications (voltage, capacity, model, chemistry) "
                       "could be read from the label.")
    if not label_warnings:
        missing.append("No safety warnings were readable from the label.")
    if product is None:
        missing.append("The product was not found in the verified product database - only "
                       "information visible on the label is reported.")
    missing.append("Battery/electronics safety also depends on certifications and handling "
                   "instructions, which this scan cannot verify from an image alone.")

    positives = []
    if product is not None:
        positives.append(f"Verified product record: {product.brand_name} {product.product_name}.")
    for spec in specs:
        positives.append(f"{spec['label']}: {spec['value']} (visible on label).")
    if not positives:
        positives.append("The scan reported only what is actually visible on the label - no "
                         "claims were inferred.")

    ocr_conf = 60 if (from_image and extracted_text) else (100 if source == "text" else 0)
    overall_conf = round(0.6 * ocr_conf)

    # For technical products an ingredient-style score is meaningless, so the
    # trust score reflects how much verifiable information was actually found.
    verifiability = 40
    if product is not None:
        verifiability += 25
    if specs:
        verifiability += 20
    if label_warnings:
        verifiability += 15
    if extracted_text or source == "text":
        verifiability += 10
    status = classify(min(100, verifiability))
    score = remap_score_to_band(min(100, verifiability), status)
    risk_label = _RISK_LABELS.get(
        {"dangerous": "higher", "warning": "moderate", "safe": "low"}[status],
        "INSUFFICIENT EVIDENCE",
    )
    recommendation = {
        "dangerous": "Avoid this product. The available evidence raises concerns about its safety.",
        "warning": "Use with caution - verify the certifications and handling instructions before use.",
        "safe": "Generally safe based on the available information. Follow the handling instructions on the label.",
    }[status]

    explanation = (
        "Limited technical analysis. An ingredient-style safety score is not meaningful "
        "for this product category, so the trust score reflects how much verifiable "
        f"information was found (specifications, warnings, verified product record): {score}/100. "
        "The assessment reports only specifications and warnings that are visible on "
        "the label or verified in the product database."
    )

    payload = {
        "score": score,
        "status": status,
        "reliable": True,
        "assessment": f"Verifiability score {score}/100 - technical product, only verified information reported.",
        "risk_level": "insufficient",
        "risk_label": risk_label,
        "recommendation": recommendation,
        "why": [],
        "product_name": product_name,
        "input_source": source,
        "extracted_text": extracted_text,
        "ocr_failed": False,
        "ingredients": [],
        "ingredient_count": 0,
        "technical_specs": specs,
        "concerns": [],
        "positives": positives,
        "unknown_ingredients": [],
        "missing": missing,
        "explanation": explanation,
        "confidence": {
            "overall": overall_conf,
            "ingredient_coverage": 0,
            "ocr": ocr_conf,
            "product_match": {"High": 90, "Medium": 70, "Low": 50}.get(match["level"]),
        },
        "reasons": [
            {"severity": "info", "text": "Technical product - only visible/verified information is reported.", "points": 0},
            {"severity": "info", "text": f"Trust score reflects verifiable information found on the label ({score}/100).", "points": 0},
        ],
        "processing_time_ms": int((time.perf_counter() - start) * 1000),
    }
    return payload


def _finalize_payload(payload: dict, match: dict, combined: str = "") -> dict:
    """
    Attach the product-match context to any payload (DB path and KB fallback):
    product record, universal category, edible status, usage purpose, allergen
    warnings, consumption status, label warnings, marketing claims, score policy,
    data quality, sources and honest notes when no product could be verified.
    """
    product = match["product"]
    level = match["level"]

    product_info = None
    if product is not None:
        product_info = product.to_dict()
        product_info["consumption_notice"] = _consumption_notice(product.consumption_status)

    category = classify_product_category(
        combined,
        (product.category if product else "") or "",
        (product.subcategory if product else "") or "",
    )
    analysis_mode = _analysis_mode_for(category)

    # Edible / non-edible classification.
    edible_status = _classify_edible_status(
        category, combined,
        product.consumption_status if product is not None else None,
    )

    # Usage purpose.
    usage_purpose = _get_usage_purpose(category)

    # Allergen detection.
    parsed = parse_ingredients(combined)
    allergen_warnings = _detect_allergens(parsed)

    missing = list(payload.get("missing") or [])
    if level == "None":
        missing.append(
            "Product not found in the verified product database — only an OCR-based "
            "analysis of the label was possible."
        )
    elif level == "BrandOnly":
        missing.append(match["label"])
    if category == "unknown":
        missing.append("The product category could not be confidently determined from the "
                       "available evidence.")

    sources = []

    def _push(name, url, date):
        if name and not any(s["source"] == name for s in sources):
            sources.append({"source": name, "source_url": url or "", "source_date": date or ""})

    if product is not None:
        _push(product.source, product.source_url, product.source_date)
    for card in payload.get("ingredients") or []:
        srcs = card.get("source") or []
        _push(srcs[0] if srcs else None, card.get("source_url"), card.get("source_date"))

    score_available, score_not_available_reason = _score_decision(payload, match, category)

    payload["database_match"] = level
    payload["database_match_label"] = match["label"]
    payload["product_match_confidence"] = level
    payload["product"] = product_info
    payload["category"] = category
    payload["category_label"] = _category_label(category)
    payload["analysis_mode"] = analysis_mode
    payload["analysis_mode_label"] = ANALYSIS_MODE_LABELS.get(analysis_mode, "Consumption status")
    payload["intended_use"] = product.intended_use if product is not None else None
    payload["consumption_status"] = (
        product.consumption_status if product is not None else None
    )
    payload["consumption_notice"] = _consumption_notice(
        product.consumption_status if product is not None else None
    )
    # Preserve edible_status if already set by KB or earlier logic
    if "edible_status" not in payload or payload.get("edible_status") is None:
        payload["edible_status"] = edible_status
    payload["usage_purpose"] = usage_purpose
    payload["allergen_warnings"] = allergen_warnings
    payload["label_warnings"] = _extract_label_warnings(combined)
    payload["claims"] = _extract_claims(combined)

    # ---- New: certifications, claim consistency, mandatory info ---- #
    certs = _detect_certifications(combined, category)
    payload["certifications"] = certs

    claims_list = payload.get("claims", [])
    parsed_ings = parse_ingredients(combined)
    claim_consistency = _check_claim_consistency(claims_list, parsed_ings)
    payload["claim_consistency"] = claim_consistency

    missing_mandatory = _check_mandatory_info(combined, category)
    payload["missing_mandatory"] = missing_mandatory

    payload["score_available"] = score_available
    payload["score_not_available_reason"] = score_not_available_reason
    payload["data_quality"] = {
        "ocr": _ocr_quality(payload),
        "database_match": level if level in ("High", "Medium", "Low", "BrandOnly") else "Not available",
        "missing": missing,
    }
    payload["sources"] = sources
    payload["missing"] = missing
    # User-facing fields shared by every analysis path (backward-compatible).
    _attach_frontend_fields(
        payload,
        combined,
        category,
        edible_status,
        payload.get("product_name"),
        level,
        match.get("matched_brand") or _find_brand(combined),
    )
    return payload


def _kb_identity_signal(kb_product: dict, combined: str) -> bool:
    """True only when the label clearly names the KB product.

    The KB entry's full product name or a multi-word alias must actually appear
    in the label text. This prevents a bare brand word like "dettol" from
    attaching the wrong verified product (e.g. Dettol Wet Wipes must NOT match
    the KB entry for Dettol Antiseptic Liquid).
    """
    if not kb_product or not combined:
        return False
    norm = _norm(combined)
    signals = [kb_product.get("name")]
    signals += [a for a in kb_product.get("aliases", []) if len(a.split()) >= 2]
    for signal in signals:
        signal_norm = _norm(signal)
        if signal_norm and signal_norm in norm:
            return True
    return False


def _attach_frontend_fields(payload: dict, combined: str, category: str,
                            edible_status: dict, product_name: str,
                            match_level: str, matched_brand: str | None = None) -> dict:
    """Add the user-facing fields shared by every analysis path.

    Additive and backward-compatible: the fields below are new keys; existing
    consumers of the payload keep working unchanged. No score/fact is invented
    here - figures are derived from the evidence already in the payload.
    """
    # ---- Intended use (plain language) ---- #
    payload["intended_use_description"] = _intended_use_description(
        category, combined, edible_status
    )

    # ---- Edible display string ---- #
    status = (edible_status or {}).get("status", "uncertain")
    if status == "edible":
        payload["edible_display"] = "Edible: YES"
    elif status == "non_edible":
        payload["edible_display"] = "Edible: NO"
    else:
        payload["edible_display"] = "Edibility: UNKNOWN / NOT ENOUGH EVIDENCE"

    # ---- Ingredient evidence summary ---- #
    ingredients = payload.get("ingredients") or []
    total = len(ingredients) or payload.get("ingredient_count") or 0
    verified = sum(1 for i in ingredients if i.get("category") in ("low", "moderate", "higher"))
    unknown = sum(1 for i in ingredients if i.get("category") == "unknown")
    payload["ingredient_evidence"] = {
        "verified": verified,
        "unknown": unknown,
        "total": total,
        "coverage_percent": round(100 * verified / total) if total else 0,
    }

    # ---- Product identification summary ---- #
    exact = match_level in ("High", "Medium", "Low")
    payload["product_identification"] = {
        "match_level": match_level,
        "product_name": product_name or "Not identified",
        "matched_brand": matched_brand,
        "exact_variant_confirmed": exact,
    }
    if not payload.get("database_match_label"):
        payload["database_match_label"] = _MATCH_LABELS.get(match_level, "")

    # ---- Confidence: separate identification vs ingredient analysis ---- #
    conf = dict(payload.get("confidence") or {})
    pm = {"High": 90, "Medium": 70, "Low": 50, "BrandOnly": 40}.get(match_level, 0)
    conf["product_match"] = pm
    conf["identification"] = pm
    payload["confidence"] = conf

    # ---- Limitations (explicit mirror of the "missing" notes) ---- #
    payload["limitations"] = list(payload.get("missing") or [])
    return payload


def _kb_product_payload(kb_product: dict, combined: str, source: str,
                         extracted_text: str, from_image: bool, start: float) -> dict:
    """Build a full scan payload from a knowledge base product entry.

    This ensures the same product always gets the same trust score,
    while different products get different scores based on their actual
    ingredient profiles.
    """
    name = kb_product["name"]
    category = kb_product.get("category", "unknown")
    edible_status = kb_product.get("edible_status", "uncertain")
    edible_reason = kb_product.get("edible_reason", "Unable to determine edible status.")
    kb_ingredients = kb_product.get("ingredients", [])
    # Normalise KB ingredient cards to the same structural contract as the
    # rest of the pipeline (confidence + source keys, source as a list).
    kb_ingredients = [
        {
            **ing,
            "use": ing.get("use", ""),
            "info": ing.get("info", ""),
            "reason": ing.get("reason", ""),
            "confidence": 90,
            "source": ["TrustLens knowledge base"],
            "detection": "Verified from knowledge base",
        }
        for ing in kb_ingredients
    ]
    kb_allergens = kb_product.get("allergens", [])

    total = len(kb_ingredients)
    counts = {"low": 0, "moderate": 0, "higher": 0, "unknown": 0}
    for ing in kb_ingredients:
        cat = ing.get("category", "unknown")
        if cat in counts:
            counts[cat] += 1

    # Compute deterministic score using the same scoring logic
    kb_edible = {"status": edible_status, "label": edible_status.replace("_", "-").title(), "reason": edible_reason}
    kb_allergen_warnings = []
    for ak in kb_allergens:
        from services.product_scanner import COMMON_ALLERGENS
        if ak in COMMON_ALLERGENS:
            kb_allergen_warnings.append({
                "allergen_key": ak,
                "label": COMMON_ALLERGENS[ak]["label"],
                "detected_from": name,
                "info": COMMON_ALLERGENS[ak]["info"],
            })

    certs = _detect_certifications(combined, category)
    claim_consistency = _check_claim_consistency(_extract_claims(combined), parse_ingredients(combined))
    missing_mandatory = _check_mandatory_info(combined, category)

    score_info = _compute_score(
        counts, [], total,
        category=category,
        edible_status=kb_edible,
        allergen_warnings=kb_allergen_warnings,
        ocr_conf=100 if source == "text" else (60 if from_image and extracted_text else 0),
        database_match="High",
        from_image=from_image,
        extracted_text=extracted_text,
        certifications=certs,
        claim_consistency=claim_consistency,
        missing_mandatory=missing_mandatory,
    )

    # Build separate safe/unsafe explanation panels
    why_safe = []
    why_unsafe = []
    for ing in kb_ingredients:
        cat = ing.get("category", "unknown")
        item = {
            "name": ing["name"],
            "category": cat,
            "use": ing.get("use", ""),
            "info": ing.get("info", ""),
            "reason": ing.get("reason", ""),
            "detection": "Verified from knowledge base",
        }
        if cat in ("low",):
            why_safe.append(item)
        elif cat in ("higher",):
            why_unsafe.append(item)
        elif cat == "moderate":
            # Moderate ingredients appear in both - they're safe but with caveats
            why_safe.append(item)
            why_unsafe.append({**item, "note": "Allowed but with real caveats"})
        else:
            why_safe.append(item)

    # Build reasons list
    reasons = []
    for ing in kb_ingredients:
        cat = ing.get("category", "unknown")
        severity = {"low": "success", "moderate": "warning", "higher": "danger"}.get(cat, "info")
        pts = {"low": 0, "moderate": -8, "higher": -25}.get(cat, 0)
        reasons.append({
            "severity": severity,
            "text": f"{ing['name']}: {ing.get('use', '')} - {ing.get('reason', 'No specific concern recorded.')}",
            "points": pts,
            "detail": f"Category: {cat} | Source: Verified knowledge base",
        })

    if kb_allergen_warnings:
        reasons.append({
            "severity": "warning",
            "text": f"{len(kb_allergen_warnings)} allergen(s) detected: {', '.join(a['label'] for a in kb_allergen_warnings)}.",
            "points": 0,
        })

    positives = [f"Verified product: {name}."]
    if counts["higher"] == 0:
        positives.append("No higher-concern ingredients detected.")
    if counts["moderate"] == 0 and counts["higher"] == 0:
        positives.append("All ingredients are classified as low concern.")
    positives.append("Every finding is explained against verified ingredient data - no black-box scoring.")

    product_name = name
    risk_label = score_info["risk_label"]
    recommendation = score_info["recommendation"]
    coverage = round(100 * (counts["low"] + counts["moderate"] + counts["higher"]) / total) if total else 0
    ocr_conf = 100 if source == "text" else (60 if from_image and extracted_text else 0)

    explanation = (
        f"Product '{name}' was identified in the TrustLens product knowledge base. "
        f"Based on {total} verified ingredient{'s' if total != 1 else ''}, the safety "
        f"score is {score_info['score']}/100 ({risk_label.lower()}). {edible_reason}"
    )

    # Deterministic hash for this product (same product always gets same hash)
    phash = product_hash(name)

    for ing in kb_ingredients:
        cat = ing.get("category", "unknown")
        entry = (None if cat == "unknown"
                 else {"category": cat,
                        "use": ing.get("use", ""),
                        "info": ing.get("info", ""),
                        "reason": ing.get("reason", "")})
        ing.update(_ingredient_in_context(ing["name"], entry, category))
    factors = _score_factors(kb_ingredients)

    payload = {
        "score": score_info["score"],
        "status": score_info["status"],
        "reliable": True,
        "assessment": f"{risk_label} - safety score {score_info['score']}/100",
        "risk_level": score_info["risk_level"],
        "risk_label": risk_label,
        "recommendation": recommendation,
        "why": score_info["why"],
        "product_name": product_name,
        "product_hash": phash,
        "input_source": source,
        "extracted_text": extracted_text,
        "ocr_failed": False,
        "ingredients": kb_ingredients,
        "ingredient_count": total,
        "concerns": [i for i in kb_ingredients if i.get("category") == "higher"],
        "positives": positives,
        "positive_factors": factors["positive_factors"],
        "concern_factors": factors["concern_factors"],
        "score_deductions": factors["score_deductions"],
        "unknown_ingredients": [],
        "missing": [],
        "explanation": explanation,
        "edible_status": kb_edible,
        "category": category,
        "category_label": _category_label(category),
        "usage_purpose": _get_usage_purpose(category),
        "allergen_warnings": kb_allergen_warnings,
        "database_match": "High",
        "database_match_label": "Verified product knowledge base match (High confidence)",
        "why_safe": why_safe,
        "why_unsafe": why_unsafe,
        "certifications": certs,
        "claim_consistency": claim_consistency,
        "missing_mandatory": missing_mandatory,
        "confidence": {
            "overall": round(0.6 * coverage + 0.4 * ocr_conf),
            "ingredient_coverage": coverage,
            "ocr": ocr_conf,
            "product_match": 90,
            "identification": 90,
        },
        "reasons": reasons,
        "processing_time_ms": int((time.perf_counter() - start) * 1000),
    }
    _attach_frontend_fields(
        payload,
        combined,
        category,
        kb_edible,
        product_name,
        "High",
        None,
    )
    return payload


# --------------------------------------------------------------------------- #
# Main entry point
# --------------------------------------------------------------------------- #
def scan_product(input_text: str = "", image_path: str = "", extracted_text: str = "") -> dict:
    """Analyse a product label from pasted text and/or an OCR'd image."""
    start = time.perf_counter()
    input_text = (input_text or "").strip()
    extracted_text = (extracted_text or "").strip()
    from_image = bool(image_path)

    source = "none"
    if input_text:
        source = "text"
    elif extracted_text:
        source = "image"

    # ---- 1. Ingredient parsing --------------------------------------------- #
    combined = "\n".join([input_text, extracted_text]).strip()

    # ---- 1a. Barcode / QR decode from the uploaded image ------------------- #
    # A label barcode (EAN/GTIN) or product QR is decoded from the image and
    # fed into product identification - an exact GTIN can confirm a verified
    # product record even when the OCR text is too noisy to read the digits.
    # This is best-effort: an unreadable/missing barcode never blocks analysis.
    symbol_info = _decode_product_symbols(image_path) if from_image else {
        "barcodes": [], "gtin": None, "qr_payloads": [], "count": 0,
    }
    barcode_hint = symbol_info.get("gtin") or ""
    qr_hint = (symbol_info.get("qr_payloads") or [None])[0] or ""

    # A QR payload may itself be a product identifier (e.g. a raw GTIN). Reuse
    # it as a barcode-digit source if it is numeric, so a product QR that
    # encodes a GTIN helps identification just like a printed barcode.
    qr_digits = re.sub(r"[^0-9]", "", qr_hint)
    symbol_digits = (barcode_hint + qr_digits) if (barcode_hint or qr_digits) else ""

    # Isolate ONLY the ingredient section of the label/document. A raw image
    # scan is a full document (product name, nutrition, allergen, manufacturer,
    # batch blocks) - feeding the whole thing to parse_ingredients() would turn
    # OCR noise and nutrition paragraphs into fake "ingredients".
    ingredient_section = _extract_ingredient_section(combined) if combined else ""
    # "Ingredients:" style headers may appear on their own line (or after a
    # product-name line on an OCR'd label) - strip them line by line first.
    if ingredient_section:
        stripped_lines = []
        for line in ingredient_section.splitlines():
            cleaned = _strip_ingredients_header(line.strip())
            if cleaned:
                stripped_lines.append(cleaned)
        ingredient_section = "\n".join(stripped_lines)
    ingredients = parse_ingredients(ingredient_section) if ingredient_section else []

    logger.info(
        "PRODUCT DEBUG | raw_ocr=%r\n"
        "PRODUCT DEBUG | cleaned_section=%r\n"
        "PRODUCT DEBUG | parsed_ingredients=%r",
        combined, ingredient_section, [i["name"] for i in ingredients],
    )

    total = len(ingredients)
    name_only = False
    if ingredients and not _looks_like_ingredient_list(ingredient_section) and total == 1:
        # a single short token with no list indicators is almost certainly a
        # product name (or a bare single ingredient) - we must not score it.
        name_only = True

    # ---- 0a. Product database identification (hybrid pipeline) ------------ #
    # The verified Product database is the most precise signal. It is checked
    # BEFORE the loose knowledge-base substring matcher so a partial text
    # (e.g. "Dettol Wet Wipes") is never mis-assigned to a different verified
    # record of the same brand (e.g. "Dettol Antiseptic Liquid").
    match = _identify_product(combined, barcode_digits=symbol_digits)
    if match["level"] in ("High", "Medium", "Low") and match["product"] is not None:
        logger.info("Product scan: matched database product %s (%s confidence)",
                    match["product"].product_id, match["level"])
        product = match["product"]
        category = classify_product_category(
            combined, product.category or "", product.subcategory or ""
        )
        if category in TECHNICAL_CATEGORIES:
            logger.info("Product scan: technical category (%s) - limited assessment",
                        category)
            return _finalize_payload(
                _technical_assessment(match, combined, source, extracted_text, from_image, start),
                match, combined,
            )
        return _finalize_payload(
            _db_product_payload(match, combined, source, extracted_text, from_image, start),
            match, combined,
        )

    # ---- 0. Product Knowledge Base identification (gated) ----------------- #
    # Unlike the verified database, the KB uses loose substring matching. It is
    # therefore only trusted when the full product name or a multi-word alias
    # actually appears in the label text AND the input carries a real
    # ingredient list - a bare product name (e.g. "Coca-Cola Classic") must
    # never be converted into a fully-scored KB analysis.
    search_text = combined
    kb_product = lookup_product(search_text)
    if kb_product and not name_only and _kb_identity_signal(kb_product, combined):
        logger.info("Product KB match: %s", kb_product["name"])
        return _kb_product_payload(kb_product, combined, source, extracted_text, from_image, start)

    # ---- 2. Product name (best effort using brand-aware extraction) -------- #
    detected_brand = _find_brand(combined)
    kb_category_lookup = classify_product_category(combined)
    product_name = _extract_product_name(combined, detected_brand, kb_category_lookup)
    if not product_name and ingredients:
        product_name = ingredients[0]["name"]

    ocr_conf = 0
    if from_image:
        ocr_conf = 60 if extracted_text else 0
    elif input_text:
        ocr_conf = 100

    # ---- 3. Insufficient information --------------------------------------- #
    if not ingredients or name_only:
        coverage = 0
        overall_conf = round(0.5 * coverage + 0.5 * ocr_conf)
        if name_only:
            explanation = (
                "Insufficient information for a reliable assessment. We received what "
                "appears to be a product name or a bare single ingredient, not an "
                "ingredient list. Paste the full ingredient list (e.g. 'Ingredients: "
                "Water, Glycerin, ...') or upload a clear label image."
            )
        else:
            explanation = (
                INSUFFICIENT_ASSESSMENT +
                (" Image quality is insufficient for reliable product analysis. "
                 "Please upload a clearer image of the front or back label."
                 if from_image and not extracted_text
                 else " We found no ingredient list to analyse. Paste the ingredient "
                      "list or upload a clear label image.")
            )
        payload = {
            "score": remap_score_to_band(50, "warning"),
            "status": "warning",
            "reliable": False,
            "assessment": INSUFFICIENT_ASSESSMENT,
            "risk_level": "insufficient",
            "risk_label": "INSUFFICIENT EVIDENCE",
            "recommendation": INSUFFICIENT_ASSESSMENT,
            "why": ["No ingredient list could be read or parsed."],
            "product_name": product_name,
            "input_source": source,
            "extracted_text": extracted_text,
            "ocr_failed": bool(from_image and not extracted_text),
            "ingredients": [],
            "ingredient_count": 0,
            "concerns": [],
            "positives": [],
            "unknown_ingredients": [],
            "missing": _missing_info([], product_name, from_image),
            "explanation": explanation,
            "why_safe": [],
            "why_unsafe": [],
            "certifications": [],
            "claim_consistency": "unverifiable",
            "missing_mandatory": [],
            "confidence": {"overall": overall_conf, "ingredient_coverage": 0, "ocr": ocr_conf},
            "reasons": [
                {"severity": "info", "text": "No ingredient list could be parsed.", "points": 0},
            ],
            "processing_time_ms": int((time.perf_counter() - start) * 1000),
        }
        logger.info("Product scan: insufficient info (source=%s, name_only=%s, ocr_failed=%s)",
                    source, name_only, bool(from_image and not extracted_text))
        return _finalize_payload(payload, match, combined)

    # ---- 4. Classify every ingredient -------------------------------------- #
    kb_category = classify_product_category(combined)
    annotated, counts, unknowns, concerns = _classify_ingredients(ingredients, kb_category)
    kb_edible_status = _classify_edible_status(kb_category, combined)
    kb_allergen_warnings = _detect_allergens(ingredients)
    certifications = _detect_certifications(combined, kb_category)
    claim_consistency = _check_claim_consistency(_extract_claims(combined), ingredients)
    missing_mandatory = _check_mandatory_info(combined, kb_category)
    score_info = _compute_score(
        counts, unknowns, total,
        category=kb_category,
        edible_status=kb_edible_status,
        allergen_warnings=kb_allergen_warnings,
        ocr_conf=ocr_conf,
        database_match=match["level"],
        from_image=from_image,
        extracted_text=extracted_text,
        certifications=certifications,
        claim_consistency=claim_consistency,
        missing_mandatory=missing_mandatory,
    )

    # ---- 4a. Technical products get a limited, non-ingredient assessment ---- #
    category = kb_category
    if category in TECHNICAL_CATEGORIES:
        logger.info("Product scan: technical category (%s) - limited assessment", category)
        return _finalize_payload(
            _technical_assessment(match, combined, source, extracted_text, from_image, start),
            match, combined,
        )

    reasons = []
    for ing in annotated:
        severity = {"low": "success", "moderate": "warning", "higher": "danger"}.get(
            ing["category"], "info"
        )
        pts = {"low": 0, "moderate": -8, "higher": -25}.get(ing["category"], 0)
        reasons.append({
            "severity": severity,
            "text": f"{ing['name']}: {ing['use']} - {ing['reason']}",
            "points": pts,
            "detail": f"Category: {ing['category']} | Source(s): {', '.join(ing['source']) if ing['source'] else 'none'}",
        })
    if counts["unknown"]:
        reasons.append({
            "severity": "info",
            "text": f"{counts['unknown']} unknown ingredient(s) - marked unknown, not dangerous.",
            "points": 0,
        })
    if score_info["capped_coverage"]:
        reasons.append({
            "severity": "warning",
            "text": "More than half of the ingredients could not be classified - too little information for a firm assessment.",
            "points": 0,
        })

    # Build separate safe/unsafe explanation panels
    why_safe = []
    why_unsafe = []
    for ing in annotated:
        cat = ing.get("category", "unknown")
        item = {
            "name": ing["name"],
            "category": cat,
            "use": ing.get("use", ""),
            "info": ing.get("info", ""),
            "reason": ing.get("reason", ""),
            "detection": ing.get("detection", ""),
        }
        if cat == "low":
            why_safe.append(item)
        elif cat == "higher":
            why_unsafe.append(item)
        elif cat == "moderate":
            why_safe.append(item)
            why_unsafe.append({**item, "note": "Allowed but with real caveats"})
        else:
            why_safe.append(item)

    positives = _positive_findings(counts, total, reasons)
    missing = _missing_info(annotated, product_name, from_image)
    missing.append(
        "The exact product could not be verified against the TrustLens product "
        "database - the trust score below reflects the ingredient analysis of the "
        "label only, not a verified product record."
    )

    coverage = round(100 * (counts["low"] + counts["moderate"] + counts["higher"]) / total)
    overall_conf = round(0.6 * coverage + 0.4 * ocr_conf)

    risk_label = score_info["risk_label"]
    recommendation = score_info["recommendation"]

    explanation = (
        f"Limited assessment. The exact product could not be verified against the "
        f"TrustLens product database, so the trust score ({score_info['score']}/100, "
        f"{risk_label.lower()}) is based on the ingredients found on the label, not on a "
        f"verified product record. "
    )
    if concerns:
        explanation += (
            f"Of the {total} detected ingredient{'s' if total != 1 else ''}, "
            f"{len(concerns)} higher-concern ingredient{'s' if len(concerns) != 1 else ''} "
            "were identified and are flagged below. "
        )
    elif counts["unknown"]:
        explanation += (
            f"Of the {total} detected ingredient{'s' if total != 1 else ''}, "
            f"{counts['unknown']} could not be classified from the built-in database; "
            "unknown does not mean harmful. "
        )
    else:
        explanation += (
            f"The {total} detected ingredient{'s' if total != 1 else ''} are all "
            "classifiable from the reference database, but this alone does not verify "
            "the exact product. "
        )

    factors = _score_factors(annotated)
    payload = {
        "score": score_info["score"],
        "status": score_info["status"],
        "overall_status": score_info.get("overall_status", ""),
        "reliable": True,
        "assessment": f"{risk_label} - safety score {score_info['score']}/100",
        "risk_level": score_info["risk_level"],
        "risk_label": risk_label,
        "recommendation": recommendation,
        "why": score_info["why"],
        "product_name": product_name,
        "input_source": source,
        "extracted_text": extracted_text,
        "ocr_failed": False,
        "ingredients": annotated,
        "ingredient_count": total,
        "concerns": concerns,
        "positives": positives,
        "positive_factors": factors["positive_factors"],
        "concern_factors": factors["concern_factors"],
        "score_deductions": factors["score_deductions"],
        "unknown_ingredients": unknowns,
        "missing": missing,
        "explanation": explanation,
        "why_safe": why_safe,
        "why_unsafe": why_unsafe,
        "certifications": certifications,
        "claim_consistency": claim_consistency,
        "missing_mandatory": missing_mandatory,
        "confidence": {"overall": overall_conf, "ingredient_coverage": coverage, "ocr": ocr_conf},
        "reasons": reasons,
        "processing_time_ms": int((time.perf_counter() - start) * 1000),
    }
    logger.info("Product scan complete (unverified): ingredients=%s coverage=%s",
                total, coverage)
    return _finalize_payload(payload, match, combined)


def persist_scan(app, user_id, input_text, image_path, extracted_text, payload: dict):
    """Persist a product scan. Never raises."""
    from models import db
    from models.scan import ProductScan

    try:
        edible = payload.get("edible_status") or {}
        scan = ProductScan(
            user_id=user_id,
            input_text=(input_text or "")[:MAX_INPUT_CHARS],
            image_path=image_path,
            extracted_text=(extracted_text or "")[:MAX_INPUT_CHARS],
            product_name=(payload.get("product_name") or "")[:200],
            product_id=(payload.get("product") or {}).get("product_id"),
            database_match=payload.get("database_match"),
            consumption_status=payload.get("consumption_status"),
            edible_status=edible.get("status"),
            usage_purpose=payload.get("usage_purpose"),
            allergen_warnings=payload.get("allergen_warnings"),
            data_quality=payload.get("data_quality"),
            reliable=bool(payload.get("reliable")),
            risk_level=payload.get("risk_level") or "insufficient",
            ingredient_count=payload.get("ingredient_count") or 0,
            ingredients=payload.get("ingredients"),
            concerns=payload.get("concerns"),
            positives=payload.get("positives"),
            unknown_ingredients=payload.get("unknown_ingredients"),
            trust_score=payload.get("score") if isinstance(payload.get("score"), int) else 0,
            status=payload.get("status") or "safe",
            reasons=payload.get("reasons"),
            category=payload.get("category"),
            explanation=payload.get("explanation"),
            trust_score_explanation=payload.get("score_explanation"),
            input_snapshot={"input_source": payload.get("input_source")},
        )
        db.session.add(scan)
        db.session.commit()
    except Exception:  # noqa: BLE001
        db.session.rollback()
        app.logger.exception("Failed to persist product scan")
