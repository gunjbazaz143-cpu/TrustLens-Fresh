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

import re
import time

from models.product_db import Product
from services.logger import get_logger
from services.scoring import classify
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
    r"100\s*%\s*safe", r"chemical\s*free", r"chemical-free", r"paraben\s*free",
    r"sulfate\s*free", r"alcohol\s*free", r"sugar\s*free", r"no\s+added",
    r"clinically\s+proven", r"clinically\s+tested", r"dermatolog", r"dermatologically",
    r"hypoallergenic", r"non-comedogenic", r"cruelty\s*free", r"vegan",
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
        "aliases": ["vanillin", "ethyl vanillin", "e621"],
        "category": "low",
        "use": "Vanilla flavour",
        "info": "Synthetic form of the vanilla flavour compound; safe at food levels.",
        "reason": "Widely used flavouring; safe at food levels.",
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
        "aliases": ["vegetable oil", "sunflower oil", "canola oil", "rapeseed oil", "soybean oil", "safflower oil", "corn oil", "olive oil", "sesame oil", "coconut oil", "refined vegetable oil", "hydrogenated vegetable oil"],
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
}


# --------------------------------------------------------------------------- #
# Normalisation helpers
# --------------------------------------------------------------------------- #
def _norm(text: str) -> str:
    """Lowercase, alphanumeric only (handles E-numbers, case, dashes, unicode)."""
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def _strip_ingredients_header(text: str) -> str:
    """Remove a leading 'Ingredients: ...' / 'Ingredient list: ...' header."""
    m = re.match(
        r"^\s*(?:ingredients?|ingredient\s+list|ingredients?\s+in\s+(?:the\s+)?product|contains?|content|included)\s*[:\-]\s*",
        text or "", re.IGNORECASE,
    )
    if m:
        return text[m.end():]
    return text


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


def parse_ingredients(text: str) -> list:
    """
    Split raw label text into a cleaned, de-duplicated ingredient list.
    Returns a list of dicts: {raw, name, normalized}.
    """
    if not text:
        return []
    parts = re.split(r"[,;\n\r]+", text)
    seen = set()
    out = []
    for part in parts:
        raw = part.strip()
        if not raw:
            continue
        # strip parenthetical qualifiers: "(2%)", "(E102)", "(for colour)"
        cleaned = re.sub(r"\([^)]*\)", "", raw)
        cleaned = cleaned.strip(" .-–—\t")
        if not cleaned:
            continue
        # skip a bare percentage token like "5%" or "2.5%"
        if re.fullmatch(r"\d+(?:[.,]\d+)?\s*%", cleaned):
            continue
        # strip leading/trailing words that are just % or quantity markers
        cleaned = re.sub(r"^\d+(?:[.,]\d+)?\s*(?:%|g\b|ml\b|mg\b|kg\b|oz\b)?\s*", "", cleaned).strip()
        cleaned = re.sub(r"\s*\d+(?:[.,]\d+)?\s*%$", "", cleaned).strip()
        if not cleaned:
            continue
        norm = _norm(cleaned)
        if not norm or len(norm) < 2:
            continue
        if norm in seen:
            continue
        seen.add(norm)
        out.append({"raw": raw, "name": cleaned.strip(), "normalized": norm})
        if len(out) >= MAX_INGREDIENTS:
            break
    return out


def lookup_ingredient(name: str):
    """Return the knowledge-base entry for an ingredient name, or None."""
    key = _ALIAS_INDEX.get(_norm(name))
    if not key:
        # also try matching a single e-number suffix ("e102" present anywhere)
        norm = _norm(name)
        m = re.fullmatch(r"e[0-9]+", norm)
        if m:
            key = _ALIAS_INDEX.get(m.group(0))
    if not key:
        return None
    entry = dict(INGREDIENT_KB[key])
    entry["key"] = key
    entry["display"] = _display_name(key)
    return entry


def _classify_ingredients(ingredients: list) -> tuple:
    """Return (annotated, counts, unknowns, concerns). Never raises."""
    counts = {"low": 0, "moderate": 0, "higher": 0, "unknown": 0}
    annotated = []
    unknowns = []
    concerns = []
    for ing in ingredients:
        entry = lookup_ingredient(ing["name"])
        if not entry:
            counts["unknown"] += 1
            unknowns.append(ing["name"])
            annotated.append({
                "name": ing["name"],
                "category": "unknown",
                "use": "Not in the TrustLens ingredient database",
                "info": "No classification is possible from the built-in database. "
                        "An unknown ingredient is not proof that it is harmful.",
                "reason": "No knowledge-base entry - marked unknown, not dangerous.",
                "confidence": "Low",
                "source": [],
            })
            continue
        category = entry["category"]
        counts[category] += 1
        annotated.append({
            "name": ing["name"],
            "category": category,
            "use": entry["use"],
            "info": entry["info"],
            "reason": entry["reason"],
            "confidence": "Medium" if category in ("low", "moderate") else "High",
            "source": entry["source"],
        })
        if category == "higher":
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


def _compute_score(counts: dict, unknowns: list, total: int) -> dict:
    """Deterministic safety score from the ingredient counts."""
    low = counts["low"]
    moderate = counts["moderate"]
    higher = counts["higher"]
    unknown = counts["unknown"]

    score = 100
    score -= min(higher * 25, 75)       # each higher-concern ingredient
    score -= min(moderate * 8, 32)      # each moderate-concern ingredient
    capped_unknown = False
    capped_coverage = False

    if unknown > 0:
        score = min(score, 85)          # some ingredients are unclassified
        capped_unknown = True
    if total and (unknown / total) > 0.5:
        score = min(score, 60)          # most ingredients unclassified
        capped_coverage = True

    score = max(0, min(100, score))

    if total and (unknown / total) > 0.5:
        risk_level = "unknown"          # most ingredients unclassified - not "safe"
    elif higher > 0:
        risk_level = "higher"
    elif moderate > 0:
        risk_level = "moderate"
    elif total > 0:
        risk_level = "low"
    else:
        risk_level = "insufficient"

    return {
        "score": score,
        "risk_level": risk_level,
        "capped_unknown": capped_unknown,
        "capped_coverage": capped_coverage,
        "status": classify(score),
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


def _identify_product(combined: str) -> dict:
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
    """
    norm = _norm_words(combined)
    if not norm:
        return _no_db_match()
    tokens = _token_set(combined)
    barcode_digits = re.sub(r"[^0-9]", "", combined)

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
        barcode_match = bool(product.barcode) and product.barcode in barcode_digits

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

    score_info = _compute_score(counts, unknowns, total)

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
            "text": f"{counts['unknown']} unknown ingredient(s) - marked unknown, not dangerous. Score capped at 85.",
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

    risk_label = {
        "low": "Low concern",
        "moderate": "Moderate concern",
        "higher": "Higher concern",
        "unknown": "Unknown / insufficient evidence",
        "insufficient": "Insufficient",
    }[score_info["risk_level"]]

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
        "product_name": product_name,
        "input_source": source,
        "extracted_text": extracted_text,
        "ocr_failed": bool(from_image and not extracted_text),
        "ingredients": ingredients,
        "ingredient_count": total,
        "concerns": [c for c in ingredients if c["category"] == "higher"],
        "positives": positives,
        "unknown_ingredients": unknowns,
        "missing": missing,
        "explanation": explanation,
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

    A numeric overall score is ONLY presented when the exact product is
    verified against the database AND the category supports an ingredient-style
    assessment. Unknown products and technical products get no overall score.
    """
    if match["level"] in ("High", "Medium", "Low") and match.get("product") is not None:
        if category in TECHNICAL_CATEGORIES:
            return False, (
                "This is a technical product - a food-style ingredient safety score "
                "is not meaningful. Only visible/verified specifications and warnings "
                "are reported."
            )
        return True, None
    return False, (
        "Unable to provide a reliable overall safety score because the exact "
        "product could not be verified."
    )


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

    explanation = (
        "Limited technical analysis. An ingredient-style safety score is not meaningful "
        "for this product category; the assessment reports only specifications and "
        "warnings that are visible on the label or verified in the product database."
    )

    payload = {
        "score": None,
        "status": "info",
        "reliable": True,
        "assessment": "Limited technical assessment - no ingredient-style score is meaningful for this category.",
        "risk_level": "insufficient",
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
        ],
        "processing_time_ms": int((time.perf_counter() - start) * 1000),
    }
    return payload


def _finalize_payload(payload: dict, match: dict, combined: str = "") -> dict:
    """
    Attach the product-match context to any payload (DB path and KB fallback):
    product record, universal category, consumption status, label warnings,
    marketing claims, score policy, data quality, sources and honest notes when
    no product could be verified.
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

    missing = list(payload.get("missing") or [])
    if level == "None":
        missing.append(
            "Product not found in the verified product database - only an OCR-based "
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
    payload["label_warnings"] = _extract_label_warnings(combined)
    payload["claims"] = _extract_claims(combined)
    payload["score_available"] = score_available
    payload["score_not_available_reason"] = score_not_available_reason
    payload["data_quality"] = {
        "ocr": _ocr_quality(payload),
        "database_match": level if level in ("High", "Medium", "Low", "BrandOnly") else "Not available",
        "missing": missing,
    }
    payload["sources"] = sources
    payload["missing"] = missing
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
    # "Ingredients:" style headers may appear on their own line (or after a
    # product-name line on an OCR'd label) - strip them line by line first.
    if combined:
        stripped_lines = []
        for line in combined.splitlines():
            cleaned = _strip_ingredients_header(line.strip())
            if cleaned:
                stripped_lines.append(cleaned)
        combined = "\n".join(stripped_lines)
    ingredients = parse_ingredients(combined) if combined else []
    total = len(ingredients)
    name_only = False
    if ingredients and not _looks_like_ingredient_list(combined) and total == 1:
        # a single short token with no list indicators is almost certainly a
        # product name (or a bare single ingredient) - we must not score it.
        name_only = True

    # ---- 0. Product database identification (hybrid pipeline) -------------- #
    match = _identify_product(combined)
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

    # ---- 2. Product name (best effort from the first short line) ----------- #
    product_name = None
    if combined:
        for line in combined.splitlines():
            line = line.strip()
            if 3 <= len(line) <= 80 and "," not in line and ";" not in line:
                product_name = line
                break
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
            "score": None,
            "status": "info",
            "reliable": False,
            "assessment": INSUFFICIENT_ASSESSMENT,
            "risk_level": "insufficient",
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
    annotated, counts, unknowns, concerns = _classify_ingredients(ingredients)
    score_info = _compute_score(counts, unknowns, total)

    # ---- 4a. Technical products get a limited, non-ingredient assessment ---- #
    category = classify_product_category(combined)
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

    positives = _positive_findings(counts, total, reasons)
    missing = _missing_info(annotated, product_name, from_image)
    missing.append(
        "Unable to provide a reliable overall safety score because the exact product "
        "could not be verified against the TrustLens product database."
    )

    coverage = round(100 * (counts["low"] + counts["moderate"] + counts["higher"]) / total)
    overall_conf = round(0.6 * coverage + 0.4 * ocr_conf)

    explanation = (
        "Limited assessment. The exact product could not be verified against the "
        "TrustLens product database, so no overall safety score is presented. "
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

    payload = {
        "score": None,
        "status": "info",
        "reliable": True,
        "assessment": ("Limited assessment - unable to provide a reliable overall safety "
                       "score because the exact product could not be verified."),
        "risk_level": score_info["risk_level"],
        "product_name": product_name,
        "input_source": source,
        "extracted_text": extracted_text,
        "ocr_failed": False,
        "ingredients": annotated,
        "ingredient_count": total,
        "concerns": concerns,
        "positives": positives,
        "unknown_ingredients": unknowns,
        "missing": missing,
        "explanation": explanation,
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
        scan = ProductScan(
            user_id=user_id,
            input_text=(input_text or "")[:MAX_INPUT_CHARS],
            image_path=image_path,
            extracted_text=(extracted_text or "")[:MAX_INPUT_CHARS],
            product_name=(payload.get("product_name") or "")[:200],
            product_id=(payload.get("product") or {}).get("product_id"),
            database_match=payload.get("database_match"),
            consumption_status=payload.get("consumption_status"),
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
            input_snapshot={"input_source": payload.get("input_source")},
        )
        db.session.add(scan)
        db.session.commit()
    except Exception:  # noqa: BLE001
        db.session.rollback()
        app.logger.exception("Failed to persist product scan")
