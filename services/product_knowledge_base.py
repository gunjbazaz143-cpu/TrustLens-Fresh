"""
Product Knowledge Base - Maps common product names to their verified ingredient profiles.

Each product entry contains:
  - name: display name
  - aliases: alternative names/brands for matching
  - category: product category
  - edible_status: edible / non_edible / uncertain
  - ingredients: list of {name, category, use, info, reason}
    category: "low" | "moderate" | "higher" | "unknown"
  - allergens: list of allergen keys
  - description: brief product description

This ensures that the same product always gets the same trust score,
while different products get different scores based on their actual
ingredient profiles.
"""

import hashlib
import re


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (text or "").lower())


def product_hash(name: str) -> str:
    """Deterministic hash for a product name - same name always yields same hash."""
    return hashlib.sha256(_norm(name).encode()).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# Product Knowledge Base
# --------------------------------------------------------------------------- #

PRODUCTS = [
    # ---- BEVERAGES ----
    {
        "name": "Coca-Cola",
        "aliases": ["coca cola", "coke", "coca-cola"],
        "category": "beverage",
        "edible_status": "edible",
        "edible_reason": "This is a carbonated soft drink intended for human consumption.",
        "ingredients": [
            {"name": "Carbonated Water", "category": "low", "use": "Base ingredient", "info": "Water infused with carbon dioxide under pressure.", "reason": "Safe; the primary ingredient."},
            {"name": "Sugar", "category": "low", "use": "Sweetener", "info": "Added sugar provides sweetness and calories.", "reason": "Safe as an ingredient; high sugar intake is a dietary concern."},
            {"name": "Caramel Colour (E150d)", "category": "moderate", "use": "Brown colour", "info": "Ammonia-processed caramel colour can contain 4-MEI (IARC 2B). California requires a warning above certain levels.", "reason": "Ammonia-processed type contains 4-MEI (IARC Group 2B); others are low risk."},
            {"name": "Phosphoric Acid (E338)", "category": "low", "use": "Acidity regulator", "info": "Provides tartness. Safe at food levels; excessive intake may affect calcium absorption.", "reason": "Safe at approved food levels."},
            {"name": "Natural Flavours", "category": "low", "use": "Flavouring", "info": "Proprietary blend of natural flavouring substances.", "reason": "Generally recognised as safe at food levels."},
            {"name": "Caffeine", "category": "low", "use": "Stimulant / flavour enhancer", "info": "Naturally occurring stimulant. 34mg per 12oz can. Safe for most adults in moderation.", "reason": "Safe at typical beverage levels; moderate intake recommended."},
        ],
        "allergens": [],
        "description": "Carbonated soft drink with sugar, caramel colour, and phosphoric acid.",
    },
    {
        "name": "Maggi Noodles",
        "aliases": ["maggi", "maggi 2-minute noodles", "maggi instant noodles", "nestle maggi"],
        "category": "food",
        "edible_status": "edible",
        "edible_reason": "This is a packaged instant noodle product intended for human consumption.",
        "ingredients": [
            {"name": "Refined Wheat Flour (Maida)", "category": "low", "use": "Base ingredient", "info": "Refined wheat flour; low in fibre but not a harmful additive.", "reason": "Staple ingredient; nutritionally neutral."},
            {"name": "Palm Oil", "category": "low", "use": "Edible oil", "info": "Common vegetable fat. Safe for consumption; saturated-fat and environmental concerns are dietary/ethical, not additive toxicity.", "reason": "Safe as a food fat."},
            {"name": "Salt", "category": "low", "use": "Seasoning", "info": "Sodium chloride. Safe in normal amounts; excess sodium is a cardiovascular concern.", "reason": "Safe at normal levels; excess sodium is a diet concern."},
            {"name": "Sugar", "category": "low", "use": "Sweetener", "info": "Added sugar for flavour balance.", "reason": "Safe as an ingredient."},
            {"name": "Monosodium Glutamate (E621)", "category": "low", "use": "Flavour enhancer", "info": "The sodium salt of glutamic acid. FDA and EFSA consider it safe at normal levels.", "reason": "Regulatory consensus: safe at normal levels."},
            {"name": "Hydrolysed Vegetable Protein", "category": "low", "use": "Flavour base", "info": "Plant-based protein hydrolysate used as a savoury flavour base.", "reason": "Generally recognised as safe."},
            {"name": "Spices and Condiments", "category": "low", "use": "Flavouring", "info": "Blend of common spices including chilli, turmeric, coriander.", "reason": "Safe; common food spices."},
            {"name": "Garlic Powder", "category": "low", "use": "Flavouring", "info": "Dehydrated garlic. Safe food ingredient.", "reason": "Safe; common food spice."},
            {"name": "Onion Powder", "category": "low", "use": "Flavouring", "info": "Dehydrated onion. Safe food ingredient.", "reason": "Safe; common food spice."},
            {"name": "Wheat Gluten", "category": "low", "use": "Protein / binder", "info": "Provides elasticity to noodles. Safe for most; a labelled allergen for coeliac/gluten-sensitive people.", "reason": "Safe for most; a labelled allergen."},
        ],
        "allergens": ["wheat", "gluten"],
        "description": "Instant noodle product with wheat flour, palm oil, and flavour enhancers.",
    },
    {
        "name": "Lay's Classic Chips",
        "aliases": ["lays", "lays chips", "lays classic", "lays potato chips", "lays wavy"],
        "category": "snack",
        "edible_status": "edible",
        "edible_reason": "This is a potato chip snack intended for human consumption.",
        "ingredients": [
            {"name": "Potatoes", "category": "low", "use": "Base ingredient", "info": "Sliced and fried potato. Safe whole-food ingredient.", "reason": "Safe; whole-food ingredient."},
            {"name": "Vegetable Oil", "category": "low", "use": "Frying medium", "info": "Typically sunflower, canola or palm oil. Safe for consumption.", "reason": "Safe as a food fat."},
            {"name": "Salt", "category": "low", "use": "Seasoning", "info": "Sodium chloride. Safe in normal amounts.", "reason": "Safe at normal levels."},
        ],
        "allergens": [],
        "description": "Potato chips fried in vegetable oil with salt.",
    },
    {
        "name": "Amul Butter",
        "aliases": ["amul butter", "amul", "amul pasteurised butter"],
        "category": "food",
        "edible_status": "edible",
        "edible_reason": "This is a butter product intended for human consumption.",
        "ingredients": [
            {"name": "Pasteurised Cream", "category": "low", "use": "Base ingredient", "info": "Cream from cow's milk, pasteurised for safety.", "reason": "Safe; primary dairy ingredient."},
            {"name": "Salt", "category": "low", "use": "Seasoning / preservative", "info": "Sodium chloride for flavour and preservation.", "reason": "Safe at normal levels."},
        ],
        "allergens": ["milk"],
        "description": "Pasteurised cream butter, commonly used in Indian cooking.",
    },
    {
        "name": "Colgate Toothpaste",
        "aliases": ["colgate", "colgate toothpaste", "colgate total", "colgate maxfresh", "colgateSensitive"],
        "category": "toothpaste",
        "edible_status": "non_edible",
        "edible_reason": "This product is intended for oral use only and should not be swallowed.",
        "ingredients": [
            {"name": "Hydrated Silica", "category": "low", "use": "Mild abrasive", "info": "Gently removes plaque and surface stains. Safe for oral use.", "reason": "Safe; standard toothpaste abrasive."},
            {"name": "Sodium Lauryl Sulfate (SLS)", "category": "low", "use": "Foaming agent", "info": "Creates foam to distribute toothpaste. Can cause mild mouth irritation in sensitive people.", "reason": "Mild irritant at concentration; no established carcinogenicity."},
            {"name": "Sodium Fluoride", "category": "low", "use": "Cavity prevention", "info": "Proven cavity-prevention agent. Safe at recommended toothpaste levels (1000-1450 ppm).", "reason": "Safe at recommended levels; well-established cavity prevention."},
            {"name": "Zinc Citrate", "category": "low", "use": "Anti-tartar agent", "info": "Helps reduce tartar buildup. Safe at toothpaste levels.", "reason": "Safe at approved levels."},
            {"name": "Tetrasodium Pyrophosphate", "category": "low", "use": "Anti-tartar agent", "info": "Prevents calcium deposits on teeth. Safe for oral use.", "reason": "Safe for oral use at approved levels."},
            {"name": "Xanthan Gum", "category": "low", "use": "Thickener", "info": "Provides texture to the paste. Safe.", "reason": "Safe at normal levels."},
            {"name": "Cocamidopropyl Betaine", "category": "low", "use": "Co-surfactant", "info": "Mild surfactant that helps clean. Well tolerated.", "reason": "Generally recognised as safe for oral care use."},
            {"name": "Titanium Dioxide (CI 77891)", "category": "low", "use": "White colourant", "info": "Provides white colour to toothpaste. Safe for oral use at cosmetic levels.", "reason": "Safe for oral use; banned as food additive in EU only."},
        ],
        "allergens": [],
        "description": "Fluoride toothpaste for cavity protection and gum health.",
    },
    {
        "name": "Dettol Antiseptic Liquid",
        "aliases": ["dettol", "dettol antiseptic", "dettol liquid"],
        "category": "disinfectant",
        "edible_status": "non_edible",
        "edible_reason": "This product is an antiseptic disinfectant and should NEVER be consumed.",
        "ingredients": [
            {"name": "Chloroxylenol (4-chloro-3,5-xylenol)", "category": "moderate", "use": "Active antiseptic agent", "info": "Kills 99.9% of bacteria. Safe for external use at recommended dilutions; harmful if swallowed.", "reason": "Safe for external use; toxic if ingested. Do not swallow."},
            {"name": "Terpineol", "category": "low", "use": "Solvent / fragrance", "info": "A naturally occurring terpene alcohol used as a solvent and fragrance component.", "reason": "Safe for external use at normal concentrations."},
            {"name": "Pinene", "category": "low", "use": "Solvent / fragrance", "info": "A naturally occurring terpene found in pine resin. Used as a solvent.", "reason": "Safe for external use."},
            {"name": "Isopropyl Myristate", "category": "low", "use": "Emollient / solvent", "info": "Helps the antiseptic spread on skin. Safe for external use.", "reason": "Safe for external use at cosmetic levels."},
            {"name": "Sodium Hydroxide", "category": "moderate", "use": "pH adjuster", "info": "Adjusts pH. Corrosive in concentrated form; safe at the dilute levels used in the product.", "reason": "Corrosive in concentrated form; safe at diluted levels used."},
            {"name": "Water", "category": "low", "use": "Diluent", "info": "Purified water used as the liquid base.", "reason": "Plain water; safe."},
        ],
        "allergens": [],
        "description": "Antiseptic disinfectant liquid for surface cleaning and first aid dilution.",
    },
    {
        "name": "Nivea Soft Moisturising Cream",
        "aliases": ["nivea soft", "nivea cream", "nivea moisturising", "nivea"],
        "category": "skincare",
        "edible_status": "non_edible",
        "edible_reason": "This product is intended for external skin use only and should not be consumed.",
        "ingredients": [
            {"name": "Aqua (Water)", "category": "low", "use": "Base solvent", "info": "Purified water as the primary base.", "reason": "Plain water; safe."},
            {"name": "Glycerin", "category": "low", "use": "Humectant", "info": "Attracts moisture to skin. Safe and well-tolerated.", "reason": "Safe at normal use levels."},
            {"name": "Cetearyl Alcohol", "category": "low", "use": "Emollient / thickener", "info": "Fatty alcohol that softens and smooths skin. Non-irritating for most people.", "reason": "Safe for topical use."},
            {"name": "Paraffinum Liquidum (Mineral Oil)", "category": "low", "use": "Occlusive moisturiser", "info": "Refined mineral oil; cosmetic-grade is highly refined and considered safe.", "reason": "Cosmetic-grade refined mineral oils are considered safe."},
            {"name": "Petrolatum (Petroleum Jelly)", "category": "low", "use": "Occlusive moisturiser", "info": "Forms a protective barrier on skin. Cosmetic-grade petrolatum is safe.", "reason": "Cosmetic-grade refined petrolatum is considered safe."},
            {"name": "Stearyl Alcohol", "category": "low", "use": "Emollient / thickener", "info": "Fatty alcohol used as an emollient and thickener. Safe for skin use.", "reason": "Safe for topical use."},
            {"name": "Simmondsia Chinensis (Jojoba) Seed Oil", "category": "low", "use": "Emollient", "info": "Natural plant oil that closely mimics skin's own sebum. Well tolerated.", "reason": "Safe; natural emollient."},
            {"name": "Magnesium Aluminum Silicate", "category": "low", "use": "Thickener / stabiliser", "info": "Natural clay mineral used as a thickener. Safe for cosmetic use.", "reason": "Safe for cosmetic use."},
            {"name": "Carbomer", "category": "low", "use": "Thickener / gelling agent", "info": "Synthetic polymer used to create gel texture. Safe for skin use.", "reason": "Safe for topical use at cosmetic levels."},
            {"name": "Methylparaben", "category": "moderate", "use": "Preservative", "info": "Effective preservative but has weak oestrogenic activity; EU restricts longer-chain parabens in leave-on products for children under 3.", "reason": "Endocrine-disruption concerns; EU restrictions on longer-chain parabens."},
        ],
        "allergens": [],
        "description": "Moisturising cream for daily skin care with jojoba oil.",
    },
    {
        "name": "Head & Shoulders Shampoo",
        "aliases": ["head and shoulders", "head & shoulders", "h&s", "head shoulders"],
        "category": "haircare",
        "edible_status": "non_edible",
        "edible_reason": "This product is a shampoo intended for hair washing only and should not be consumed.",
        "ingredients": [
            {"name": "Water", "category": "low", "use": "Base solvent", "info": "Purified water as the primary base.", "reason": "Plain water; safe."},
            {"name": "Sodium Lauryl Sulfate", "category": "low", "use": "Primary cleanser", "info": "Effective foaming detergent. Can cause mild skin/eye irritation at higher concentrations.", "reason": "Mild irritant at concentration; safe for hair wash use."},
            {"name": "Sodium Laureth Sulfate (SLES)", "category": "low", "use": "Foaming agent", "info": "Milder foaming agent than SLS. Well tolerated for shampoo use.", "reason": "Safe for shampoo use at normal levels."},
            {"name": "Zinc Pyrithione", "category": "low", "use": "Anti-dandruff active", "info": "Clinically proven anti-dandruff agent. Safe and effective at 1-2% concentration.", "reason": "Safe and effective at approved levels; well-studied anti-dandruff agent."},
            {"name": "Cocamidopropyl Betaine", "category": "low", "use": "Co-surfactant", "info": "Mild surfactant derived from coconut oil. Well tolerated.", "reason": "Safe for hair wash use."},
            {"name": "Sodium Chloride", "category": "low", "use": "Thickener", "info": "Common salt used to adjust shampoo viscosity.", "reason": "Safe; common food ingredient."},
            {"name": "Dimethicone", "category": "low", "use": "Smoothing / conditioning agent", "info": "Silicone that provides smooth feel and shine. Safe for hair use.", "reason": "Safe for hair use; some cyclic types restricted on environmental grounds."},
            {"name": "Zinc Carbonate", "category": "low", "use": "Active ingredient stabiliser", "info": "Helps stabilise the zinc pyrithione active. Safe.", "reason": "Safe at cosmetic levels."},
            {"name": "Sodium Xylenesulfonate", "category": "low", "use": "Viscosity modifier", "info": "Helps maintain shampoo consistency. Safe at cosmetic levels.", "reason": "Safe for cosmetic use at approved levels."},
            {"name": "Fragrance", "category": "moderate", "use": "Scent", "info": "Fragrance mixes can contain contact allergens. Some compounds are restricted; others are disclosed only as 'fragrance'.", "reason": "Potential contact allergens; limited ingredient disclosure."},
        ],
        "allergens": [],
        "description": "Anti-dandruff shampoo with zinc pyrithione active ingredient.",
    },
    {
        "name": "Britannia Marie Gold Biscuits",
        "aliases": ["marie gold", "britannia marie", "marie biscuit", "marie gold biscuit", "britannia marie gold"],
        "category": "food",
        "edible_status": "edible",
        "edible_reason": "This is a biscuit product intended for human consumption.",
        "ingredients": [
            {"name": "Refined Wheat Flour (Maida)", "category": "low", "use": "Base ingredient", "info": "Refined wheat flour; staple baking ingredient.", "reason": "Staple ingredient; nutritionally neutral."},
            {"name": "Sugar", "category": "low", "use": "Sweetener", "info": "Common table sugar (sucrose). Safe as an ingredient; high intake is a dietary concern.", "reason": "Safe as an ingredient."},
            {"name": "Palm Oil", "category": "low", "use": "Edible fat", "info": "Common vegetable fat used in biscuits.", "reason": "Safe as a food fat."},
            {"name": "Invert Sugar Syrup", "category": "low", "use": "Sweetener / humectant", "info": "A mixture of glucose and fructose. Safe at food levels.", "reason": "Safe; a source of added sugar."},
            {"name": "Milk Solids", "category": "low", "use": "Dairy ingredient", "info": "Dried milk solids for flavour and nutrition. Safe; a major allergen.", "reason": "Safe; a labelled major allergen for milk-allergic people."},
            {"name": "Leavening Agents (E500, E503)", "category": "low", "use": "Raising agents", "info": "Sodium and ammonium bicarbonate. Safe food-grade raising agents.", "reason": "Common food ingredients; safe."},
            {"name": "Salt", "category": "low", "use": "Seasoning", "info": "Sodium chloride. Safe in normal amounts.", "reason": "Safe at normal levels."},
            {"name": "Emulsifier (E471)", "category": "low", "use": "Emulsifier", "info": "Mono- and diglycerides of fatty acids. Safe at food levels.", "reason": "Generally recognised as safe."},
            {"name": "Artificial Flavouring", "category": "low", "use": "Flavouring", "info": "Approved artificial flavouring substances.", "reason": "Approved at food levels."},
        ],
        "allergens": ["milk", "wheat", "gluten"],
        "description": "Marie-style tea biscuit made with refined wheat flour and sugar.",
    },
    {
        "name": "Parle-G Biscuits",
        "aliases": ["parle-g", "parle g", "parle glucose"],
        "category": "food",
        "edible_status": "edible",
        "edible_reason": "This is a glucose biscuit product intended for human consumption.",
        "ingredients": [
            {"name": "Refined Wheat Flour (Maida)", "category": "low", "use": "Base ingredient", "info": "Refined wheat flour; staple baking ingredient.", "reason": "Staple ingredient; nutritionally neutral."},
            {"name": "Sugar", "category": "low", "use": "Sweetener", "info": "Common table sugar. Safe as an ingredient.", "reason": "Safe as an ingredient."},
            {"name": "Palm Oil", "category": "low", "use": "Edible fat", "info": "Common vegetable fat.", "reason": "Safe as a food fat."},
            {"name": "Glucose Syrup", "category": "low", "use": "Sweetener / binder", "info": "Corn syrup; a source of added sugar.", "reason": "Safe; a source of added sugar."},
            {"name": "Milk Solids", "category": "low", "use": "Dairy ingredient", "info": "Dried milk solids. Safe; a major allergen.", "reason": "Safe; a labelled major allergen."},
            {"name": "Leavening Agents", "category": "low", "use": "Raising agents", "info": "Food-grade raising agents.", "reason": "Safe food ingredients."},
            {"name": "Salt", "category": "low", "use": "Seasoning", "info": "Sodium chloride.", "reason": "Safe at normal levels."},
            {"name": "Emulsifier (E472)", "category": "low", "use": "Emulsifier", "info": "Food-grade emulsifier.", "reason": "Generally recognised as safe."},
            {"name": "Salt", "category": "low", "use": "Flavour enhancer", "info": "Used in small amounts for flavour balance.", "reason": "Safe at normal levels."},
        ],
        "allergens": ["milk", "wheat", "gluten"],
        "description": "Glucose biscuit, one of India's most popular tea-time snacks.",
    },
    {
        "name": "Tropicana Orange Juice",
        "aliases": ["tropicana", "tropicana orange", "tropicana juice", "tropicana ne"],
        "category": "beverage",
        "edible_status": "edible",
        "edible_reason": "This is a fruit juice beverage intended for human consumption.",
        "ingredients": [
            {"name": "Orange Juice (99.7%)", "category": "low", "use": "Base ingredient", "info": "Fresh-squeezed orange juice. Safe whole-food ingredient.", "reason": "Safe; natural fruit juice."},
            {"name": "Vitamin C (Ascorbic Acid)", "category": "low", "use": "Antioxidant / nutrient", "info": "Added vitamin C for freshness and nutrition. Safe.", "reason": "Essential nutrient; safe at normal levels."},
        ],
        "allergens": [],
        "description": "Not-from-concentrate orange juice with added vitamin C.",
    },
    {
        "name": "Dove Beauty Bar",
        "aliases": ["dove", "dove soap", "dove bar", "dove beauty bar", "dove cream bar"],
        "category": "soap",
        "edible_status": "non_edible",
        "edible_reason": "This product is a cleansing bar intended for external use only.",
        "ingredients": [
            {"name": "Sodium Lauroyl Isethionate", "category": "low", "use": "Primary cleanser", "info": "Mild surfactant that produces a gentle lather. Well tolerated by skin.", "reason": "Safe for skin cleansing use."},
            {"name": "Stearic Acid", "category": "low", "use": "Hardening agent / emollient", "info": "Naturally occurring fatty acid. Safe for skin use.", "reason": "Safe; naturally occurring fatty acid."},
            {"name": "Sodium Palmitate", "category": "low", "use": "Soap base", "info": "Sodium salt of palmitic acid, derived from palm oil. Standard soap ingredient.", "reason": "Safe; standard soap ingredient."},
            {"name": "Sodium Palm Kernelate", "category": "low", "use": "Soap base", "info": "Sodium salt of palm kernel fatty acids. Standard soap ingredient.", "reason": "Safe; standard soap ingredient."},
            {"name": "Cocamidopropyl Betaine", "category": "low", "use": "Co-surfactant", "info": "Mild surfactant derived from coconut oil. Well tolerated.", "reason": "Safe for skin use."},
            {"name": "Glycerin", "category": "low", "use": "Humectant", "info": "Attracts moisture. Safe and well-tolerated for skin.", "reason": "Safe at normal use levels."},
            {"name": "Sodium Chloride", "category": "low", "use": "Hardness adjuster", "info": "Common salt. Safe for skin use.", "reason": "Safe; common salt."},
            {"name": "Tetrasodium EDTA", "category": "low", "use": "Chelating agent", "info": "Helps maintain product stability. Safe for skin use at cosmetic levels.", "reason": "Safe for cosmetic use at approved levels."},
            {"name": "Fragrance", "category": "moderate", "use": "Scent", "info": "Proprietary fragrance blend. Can contain contact allergens.", "reason": "Potential contact allergens; limited ingredient disclosure."},
            {"name": "Titanium Dioxide (CI 77891)", "category": "low", "use": "White colourant", "info": "Provides white colour. Safe for cosmetic use.", "reason": "Safe for cosmetic use."},
        ],
        "allergens": [],
        "description": "Moisturising beauty bar with one-quarter moisturising cream.",
    },
    {
        "name": "Red Bull Energy Drink",
        "aliases": ["red bull", "redbull", "red bull energy"],
        "category": "beverage",
        "edible_status": "edible",
        "edible_reason": "This is an energy drink intended for human consumption.",
        "ingredients": [
            {"name": "Carbonated Water", "category": "low", "use": "Base ingredient", "info": "Water infused with carbon dioxide. Safe.", "reason": "Safe; primary ingredient."},
            {"name": "Sugar", "category": "low", "use": "Sweetener", "info": "Added sugar. Safe as an ingredient; high intake is a dietary concern.", "reason": "Safe as an ingredient."},
            {"name": "Glucuronolactone", "category": "low", "use": "Functional ingredient", "info": "Naturally occurring compound. Safe at the levels used in energy drinks.", "reason": "Safe at approved levels."},
            {"name": "Taurine", "category": "low", "use": "Amino acid supplement", "info": "Amino acid naturally present in the human body. Safe at beverage levels.", "reason": "Safe at beverage levels; naturally occurring in the body."},
            {"name": "Caffeine", "category": "low", "use": "Stimulant", "info": "80mg per 250ml can. Safe for most adults in moderation.", "reason": "Safe at typical beverage levels; moderate intake recommended."},
            {"name": "B Group Vitamins (Niacinamide, Vitamin B6, Vitamin B12)", "category": "low", "use": "Nutrients", "info": "Water-soluble vitamins. Safe at the levels used.", "reason": "Safe; essential nutrients."},
            {"name": "Sodium Citrate", "category": "low", "use": "Acidity regulator", "info": "Sodium salt of citric acid. Safe at food levels.", "reason": "Safe at food levels."},
            {"name": "Magnesium Carbonate", "category": "low", "use": "Mineral supplement", "info": "Source of magnesium. Safe at the levels used.", "reason": "Safe at food levels."},
        ],
        "allergens": [],
        "description": "Carbonated energy drink with caffeine, taurine, and B-group vitamins.",
    },
    {
        "name": "Vaseline Original Pure Skin Jelly",
        "aliases": ["vaseline", "vaseline jelly", "vaseline petroleum jelly", "vaseline pure"],
        "category": "skincare",
        "edible_status": "non_edible",
        "edible_reason": "This product is intended for external skin use only.",
        "ingredients": [
            {"name": "Petrolatum (Petroleum Jelly)", "category": "low", "use": "Occlusive moisturiser", "info": "Highly refined petrolatum. Forms a protective barrier on skin. Safe for skin use.", "reason": "Cosmetic-grade refined petrolatum is considered safe."},
        ],
        "allergens": [],
        "description": "Pure petroleum jelly for skin protection and moisturising.",
    },
    {
        "name": "Samsung Galaxy Phone Charger",
        "aliases": ["samsung charger", "samsung adapter", "samsung galaxy charger", "samsung travel adapter"],
        "category": "electronics",
        "edible_status": "non_edible",
        "edible_reason": "This is an electronic device and should never be consumed.",
        "ingredients": [],
        "allergens": [],
        "description": "USB travel adapter/charger for Samsung Galaxy smartphones.",
        "technical_specs": [
            {"label": "Input", "value": "100-240V ~ 50-60Hz 0.5A"},
            {"label": "Output", "value": "5V DC 2A (10W)"},
            {"label": "Connector", "value": "USB Type-A"},
            {"label": "Safety Certifications", "value": "UL, CE, FCC listed"},
        ],
        "label_warnings": [
            "Risk of fire or electric shock if exposed to rain or moisture.",
            "Do not use with damaged cord or plug.",
            "Unplug from outlet when not in use.",
        ],
    },
]


# --------------------------------------------------------------------------- #
# Lookup index
# --------------------------------------------------------------------------- #

_PRODUCT_INDEX = {}


def _build_index():
    """Build a normalised-name lookup index from the PRODUCTS list."""
    for product in PRODUCTS:
        key = _norm(product["name"])
        if key not in _PRODUCT_INDEX:
            _PRODUCT_INDEX[key] = product
        for alias in product.get("aliases", []):
            akey = _norm(alias)
            if akey not in _PRODUCT_INDEX:
                _PRODUCT_INDEX[akey] = product


_build_index()


def lookup_product(text: str) -> dict | None:
    """Try to match input text against the product knowledge base.

    Returns the product dict if found, None otherwise.
    Matching is done by normalising both the input and product names/aliases
    and checking for substring containment.
    """
    if not text:
        return None
    norm = _norm(text)
    if not norm or len(norm) < 3:
        return None

    # Exact match first
    if norm in _PRODUCT_INDEX:
        return _PRODUCT_INDEX[norm]

    # Substring match - check if input matches a product name/alias
    for pkey, product in _PRODUCT_INDEX.items():
        if len(pkey) < 4:
            continue
        if pkey in norm or norm in pkey:
            return product

    # Token overlap match
    input_tokens = set(norm.split())
    if len(input_tokens) < 2:
        return None
    best_match = None
    best_score = 0
    for pkey, product in _PRODUCT_INDEX.items():
        p_tokens = set(pkey.split())
        overlap = len(input_tokens & p_tokens)
        if overlap >= 2 and overlap > best_score:
            best_score = overlap
            best_match = product

    return best_match


def all_products() -> list:
    """Return all products in the knowledge base."""
    return PRODUCTS
