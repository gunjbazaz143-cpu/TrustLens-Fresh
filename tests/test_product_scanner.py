"""
Product / ingredient label scanner validation suite.

Runnable without pytest:

    python tests/test_product_scanner.py            # run all checks

The suite generates its own label images at runtime (no committed fixtures,
no hard-coded OCR text). Assertions are band-based and behaviour-based, not
exact-score.

Behavioural guarantees exercised here:

  P1  a valid ingredient list parses, classifies and scores deterministically
  P2  header, case, duplicates, brackets, percentages and E-numbers normalise
  P3  higher-concern ingredients produce concerns and a dangerous band
  P4  unknown ingredients are marked unknown - NEVER dangerous
  P5  a single product name is NOT scored (insufficient, reliable=False)
  P6  empty input -> honest "Insufficient information" (never a fake score)
  P7  an OCR-readable label image is analysed honestly end-to-end
  P8  a blurry / unreadable label is reported honestly (no fabricated safe score)
  P9  structural invariants hold on every payload

DB-backed hybrid pipeline (P10):
  P10  verified product database match (brand+name) at High confidence, with the
       product's own ingredient records, consumption status and warnings
  P10  DB<->OCR comparison: found-on-label vs expected-not-visible; published
       concentrations preserved and unpublished concentrations stay NULL
  P10  consumption status is never a penalty for non-food products
  P10  unknown product -> honest "Product not found in the verified product
       database." (database match marked Not available), still a reliable
       OCR/KB analysis, unknown ingredients never treated as dangerous
  P10  brand-only match never attaches a random product of that brand
  P10  an unknown ingredient on a matched product is surfaced honestly
  P10  seeding is idempotent (re-running never duplicates reference data)
  P10  a real Dettol label image is OCR'd and matched to the verified record
"""

import io
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from PIL import Image, ImageDraw, ImageFilter, ImageFont  # noqa: E402

from services.product_scanner import (  # noqa: E402
    MAX_INGREDIENTS,
    INSUFFICIENT_ASSESSMENT,
    parse_ingredients,
    lookup_ingredient,
    scan_product,
)


def _font():
    for path in (
        os.environ.get("TRUSTLENS_TEST_FONT", ""),
        r"C:\Windows\Fonts\arial.ttf",
        r"C:\Windows\Fonts\segoeui.ttf",
    ):
        if path and os.path.exists(path):
            return ImageFont.truetype(path, 46)
    return ImageFont.load_default()


FONT = _font()


def build_label_image(lines, blur=0):
    """Render a product label (white bg, black text) to an in-memory PNG."""
    img = Image.new("RGB", (1100, 200 + 120 * len(lines)), (255, 255, 255))
    d = ImageDraw.Draw(img)
    for i, line in enumerate(lines):
        d.text((40, 40 + i * 120), line, fill=(0, 0, 0), font=FONT)
    if blur > 0:
        img = img.filter(ImageFilter.GaussianBlur(blur))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf


PRODUCT_PAYLOAD_KEYS = [
    "score", "status", "reliable", "assessment", "risk_level", "risk_label",
    "recommendation", "product_name", "input_source", "extracted_text",
    "ocr_failed", "ingredients", "ingredient_count", "concerns", "positives",
    "unknown_ingredients", "missing", "explanation", "confidence", "reasons",
    "processing_time_ms",
]


def structural_issues(payload: dict) -> list:
    issues = []
    for key in PRODUCT_PAYLOAD_KEYS:
        if key not in payload:
            issues.append(f"missing key '{key}'")
    if not (0 <= payload.get("score", -1) <= 100):
        issues.append("score out of 0-100")
    if payload["status"] not in ("safe", "warning", "dangerous"):
        issues.append(f"bad status {payload['status']!r}")
    if payload["risk_level"] not in ("low", "moderate", "higher", "unknown", "insufficient"):
        issues.append(f"bad risk_level {payload['risk_level']!r}")
    conf = payload.get("confidence", {})
    for k in ("overall", "ingredient_coverage", "ocr"):
        if not isinstance(conf.get(k), int) or not (0 <= conf[k] <= 100):
            issues.append(f"confidence.{k} not an int 0-100")
    for r in payload.get("reasons", []):
        if "severity" not in r or "text" not in r or "points" not in r:
            issues.append("reason missing severity/text/points")
    for ing in payload.get("ingredients", []):
        for k in ("name", "category", "use", "info", "reason", "confidence", "source"):
            if k not in ing:
                issues.append(f"ingredient entry missing '{k}'")
        if ing["category"] not in ("low", "moderate", "higher", "unknown"):
            issues.append(f"ingredient bad category {ing['category']!r}")
    if payload.get("reliable") and not payload.get("ingredients"):
        issues.append("reliable=True but no ingredients")
    return issues


def test_parse_basics():
    failures = []
    # comma split + case + duplicate dedupe
    ing = parse_ingredients("Water, water, WATER, Glycerin")
    names = [i["name"] for i in ing]
    if len(ing) != 2 or "Water" not in names or "Glycerin" not in names:
        failures.append(f"P2 dedupe/case: got {names}")
    # brackets (kept intact as one item), percentages, E-number
    ing = parse_ingredients("Water (purified) 80%, Glycerin 5%, E211")
    names = sorted(i["name"] for i in ing)
    if names != sorted(["Water (purified)", "Glycerin", "E211"]):
        failures.append(f"P2 brackets/percent/E-number: got {names}")
    # header is stripped by scan_product, not the splitter
    ing = parse_ingredients("Sodium benzoate, Methylparaben")
    if len(ing) != 2:
        failures.append(f"P2 split: got {len(ing)}")
    # bare percentage token is skipped
    ing = parse_ingredients("Water, 2.5%, Glycerin")
    if len(ing) != 2:
        failures.append(f"P2 bare % token: got {len(ing)}")
    # very many ingredients are capped
    ing = parse_ingredients(", ".join([f"Xyzin {i}" for i in range(300)]))
    if len(ing) > MAX_INGREDIENTS:
        failures.append(f"P2 cap: {len(ing)} > {MAX_INGREDIENTS}")
    if not failures:
        print("P2 parse/clean/limit checks passed.")
    return failures


def test_lookup_basics():
    failures = []
    for name, expect_moderate in (("Tartrazine", True), ("E211", True),
                                  ("Sodium benzoate", True), ("Methylparaben", True),
                                  ("Sodium lauryl sulfate", False), ("Water", False),
                                  ("Preservative", True)):
        entry = lookup_ingredient(name)
        if entry is None:
            failures.append(f"lookup missing {name!r}")
        elif (entry["category"] == "moderate") != expect_moderate:
            failures.append(f"lookup category for {name!r}: {entry['category']}")
    for name in ("Mercury", "Lead", "Arsenic"):
        entry = lookup_ingredient(name)
        if entry is None or entry["category"] != "higher":
            failures.append(f"lookup {name!r} should be higher concern")
    for name in ("Mysterypuff X23", "Zarblend-9", ""):
        if lookup_ingredient(name) is not None:
            failures.append(f"lookup should miss {name!r}")
    if not failures:
        print("P2 lookup checks passed.")
    return failures


def test_valid_list_scoring():
    failures = []
    payload = scan_product(
        "Ingredients: Water, Glycerin, Sodium lauryl sulfate, "
        "Methylparaben, Sodium benzoate, Tartrazine, Dimethicone"
    )
    if not payload["reliable"]:
        failures.append("P1 valid list not reliable")
    if payload["ingredient_count"] != 7:
        failures.append(f"P1 count {payload['ingredient_count']} != 7")
    if payload["score"] != 50 or payload["status"] != "warning":
        failures.append(f"P1 score/status {payload['score']}/{payload['status']} != 50/warning")
    if payload["risk_level"] != "moderate":
        failures.append(f"P1 risk_level {payload['risk_level']} != moderate")
    if payload["risk_label"] != "MODERATE RISK":
        failures.append(f"P1 risk_label {payload['risk_label']} != MODERATE RISK")
    if not payload.get("recommendation"):
        failures.append("P1 missing recommendation")
    if payload["concerns"]:
        failures.append(f"P1 unexpected concerns {payload['concerns']}")
    if payload["unknown_ingredients"]:
        failures.append(f"P1 unexpected unknowns {payload['unknown_ingredients']}")
    # every low-risk ingredient has a reason and a source (explainable)
    for ing in payload["ingredients"]:
        if not ing["source"]:
            failures.append(f"P1 ingredient {ing['name']} has no source")
    # determinism: same input twice -> identical analysis (timing excluded)
    again = scan_product(
        "Ingredients: Water, Glycerin, Sodium lauryl sulfate, "
        "Methylparaben, Sodium benzoate, Tartrazine, Dimethicone"
    )
    a = {k: v for k, v in payload.items() if k != "processing_time_ms"}
    b = {k: v for k, v in again.items() if k != "processing_time_ms"}
    if a != b:
        failures.append("P1 scan not deterministic")
    if not failures:
        print("P1 valid-list scoring passed (score=50, moderate, warning).")
    return failures


def test_higher_concern_scoring():
    failures = []
    payload = scan_product("Sodium nitrite, BHA, Formaldehyde")
    if not payload["reliable"]:
        failures.append("P3 higher list not reliable")
    if payload["score"] < 15 or payload["score"] > 30 or payload["status"] != "dangerous":
        failures.append(f"P3 score/status {payload['score']}/{payload['status']} not in 15-30/dangerous")
    if payload["risk_level"] != "higher":
        failures.append(f"P3 risk_level {payload['risk_level']} != higher")
    if payload["risk_label"] not in ("HIGH RISK", "VERY HIGH RISK"):
        failures.append(f"P3 risk_label {payload['risk_label']}")
    if len(payload["concerns"]) != 3:
        failures.append(f"P3 concerns {len(payload['concerns'])} != 3")
    names = {c["name"] for c in payload["concerns"]}
    if names != {"Sodium nitrite", "BHA", "Formaldehyde"}:
        failures.append(f"P3 concern names {names}")
    if "BHA" not in " ".join(r["text"] for r in payload["reasons"]):
        failures.append("P3 reasons do not mention BHA")
    if not failures:
        print("P3 higher-concern scoring passed (score=20, dangerous).")
    return failures


def test_unknown_never_dangerous():
    failures = []
    payload = scan_product("Mysterypuff X23, Zarblend-9")
    if not payload["reliable"]:
        failures.append("P4 unknown list should still be reliable")
    if payload["risk_level"] != "unknown":
        failures.append(f"P4 risk_level {payload['risk_level']} != unknown")
    # 100% unknown -> "unknown / insufficient evidence" sits in the MODERATE
    # band (50-60), never dangerous, never a fake safe score.
    if payload["status"] != "warning" or not (50 <= payload["score"] <= 60):
        failures.append(f"P4 score/status {payload['score']}/{payload['status']} != 50-60/warning")
    if payload["risk_label"] != "UNKNOWN / INSUFFICIENT EVIDENCE":
        failures.append(f"P4 risk_label {payload['risk_label']}")
    if payload["concerns"]:
        failures.append("P4 unknowns must never be dangerous/concerns")
    if set(payload["unknown_ingredients"]) != {"Mysterypuff X23", "Zarblend-9"}:
        failures.append(f"P4 unknowns {payload['unknown_ingredients']}")
    # unknown cap with a known low-risk ingredient (exactly 50% unknown):
    # score capped at 85, minus small adjustments; risk stays low
    payload = scan_product("Water, Mysterypuff X23")
    if payload["score"] < 78 or payload["score"] > 90 or payload["risk_level"] != "low":
        failures.append(f"P4 mix score/risk {payload['score']}/{payload['risk_level']} not in 78-90/low")
    # most ingredients unknown -> risk_level must be "unknown", moderate band
    payload = scan_product("Water, Mysterypuff X23, Zarblend-9")
    if payload["risk_level"] != "unknown" or not (50 <= payload["score"] <= 60):
        failures.append(f"P4 majority-unknown score/risk {payload['score']}/{payload['risk_level']}")
    # explanation must say unknown is not harmful
    if "unknown does not mean harmful" not in payload["explanation"]:
        failures.append("P4 explanation missing honesty note")
    if not failures:
        print("P4 unknown-never-dangerous checks passed.")
    return failures


def test_name_only_and_empty():
    failures = []
    payload = scan_product("Coca-Cola Classic")
    if payload["reliable"] is not False:
        failures.append("P5 product name must not be scored as reliable")
    if payload["score"] != 50 or payload["status"] != "warning":
        failures.append(f"P5 score/status {payload['score']}/{payload['status']} != 50/warning")
    if payload["risk_level"] != "insufficient":
        failures.append(f"P5 risk_level {payload['risk_level']} != insufficient")
    if payload["assessment"] != INSUFFICIENT_ASSESSMENT:
        failures.append("P5 assessment != Insufficient information")
    if payload["ingredients"]:
        failures.append("P5 no ingredients expected")
    # a bare single UNKNOWN token is treated as a name -> not scored
    payload = scan_product("Zarblend")
    if payload["reliable"] is not False:
        failures.append("P5 bare unknown token must not be scored")
    # a bare single KNOWN ingredient (e.g. a water label) IS a real list
    payload = scan_product("Water")
    if not payload["reliable"]:
        failures.append("P5 single known ingredient should be scored")
    if payload["score"] != 95 or payload["risk_level"] != "low":
        failures.append(f"P5 single known ingredient score/risk {payload['score']}/{payload['risk_level']}")
    if payload["risk_label"] != "LOW RISK":
        failures.append(f"P5 single known ingredient risk_label {payload['risk_label']}")
    # empty input -> honest insufficient
    payload = scan_product("")
    if payload["reliable"] is not False or payload["score"] != 50:
        failures.append(f"P6 empty: reliable={payload['reliable']} score={payload['score']}")
    if payload["assessment"] != INSUFFICIENT_ASSESSMENT:
        failures.append("P6 empty: assessment != Insufficient information")
    if not failures:
        print("P5/P6 name-only and empty-input checks passed.")
    return failures


def test_extracted_text_path():
    failures = []
    payload = scan_product(extracted_text="Ingredients: Water, Glycerin")
    if not payload["reliable"]:
        failures.append("P7 OCR-text path not reliable")
    if payload["score"] != 95 or payload["status"] != "safe":
        failures.append(f"P7 score/status {payload['score']}/{payload['status']} != 95/safe")
    if payload["risk_level"] != "low":
        failures.append(f"P7 risk_level {payload['risk_level']} != low")
    if payload["input_source"] != "image":
        failures.append(f"P7 input_source {payload['input_source']} != image")
    if not failures:
        print("P7 extracted-text path passed.")
    return failures


def test_spec_trust_bands():
    """Spec cases: HIGH 20-30 / MODERATE 50-60 / LOW 80-95 with risk labels."""
    failures = []
    cases = [
        ("Sample Cosmetic Cream\nWater, Glycerin, Mercury, Fragrance",
         (20, 30), "HIGH RISK"),
        ("Sample Face Lotion\nWater, Glycerin, Fragrance, Preservative",
         (50, 60), "MODERATE RISK"),
        ("Sample Moisturizer\nWater, Glycerin, Aloe Vera, Vitamin E",
         (80, 95), "LOW RISK"),
    ]
    for text, (lo, hi), label in cases:
        payload = scan_product(text)
        name = text.splitlines()[0]
        if not (lo <= payload["score"] <= hi):
            failures.append(f"SPEC {name!r}: score {payload['score']} not in {lo}-{hi}")
        if payload["risk_label"] != label:
            failures.append(f"SPEC {name!r}: risk_label {payload['risk_label']} != {label}")
        if not payload.get("recommendation"):
            failures.append(f"SPEC {name!r}: missing recommendation")
        if payload.get("why") is None:
            failures.append(f"SPEC {name!r}: missing why")
    if not failures:
        print("SPEC product trust bands passed (HIGH 20-30 / MODERATE 50-60 / LOW 80-95).")
    return failures


def _app_client():
    from app_factory import create_app

    return create_app().test_client()


def test_route_valid_image():
    """End-to-end: upload a readable label PNG, OCR -> analyse -> JSON."""
    failures = []
    client = _app_client()
    img = build_label_image(
        ["Ingredients:", "Water, Glycerin, Sodium benzoate", "Vitamin C"]
    )
    resp = client.post(
        "/api/scan-product",
        data={"ingredient_image": (img, "label.png")},
        content_type="multipart/form-data",
    )
    data = resp.get_json() or {}
    if resp.status_code != 200 or not data.get("success"):
        failures.append(f"P7 route status {resp.status_code}: {data.get('error')}")
    else:
        if not data.get("reliable"):
            failures.append(f"P7 route image not reliable: {data.get('explanation')}")
        if data.get("ingredient_count", 0) < 2:
            failures.append(f"P7 route OCR parsed too few ingredients: {data.get('ingredient_count')}")
        if not data.get("extracted_text"):
            failures.append("P7 route did not return extracted_text")
    if not failures:
        print("P7 route valid-image OCR check passed.")
    return failures


def test_route_blurry_image():
    """A blurry label must never yield a fabricated safe/high score."""
    failures = []
    client = _app_client()
    img = build_label_image(
        ["Ingredients:", "Water, Glycerin, Sodium benzoate"], blur=12
    )
    resp = client.post(
        "/api/scan-product",
        data={"ingredient_image": (img, "blurry.png")},
        content_type="multipart/form-data",
    )
    data = resp.get_json() or {}
    if resp.status_code != 200 or not data.get("success"):
        failures.append(f"P8 route status {resp.status_code}: {data.get('error')}")
        return failures
    if data.get("score", 0) >= 90:
        failures.append(f"P8 blurry label scored {data['score']} - honesty violation")
    if not data.get("reliable"):
        if data.get("assessment") != INSUFFICIENT_ASSESSMENT:
            failures.append("P8 unreadable image must report Insufficient information")
    if not failures:
        print("P8 blurry-label honesty check passed.")
    return failures


def test_route_bad_inputs():
    failures = []
    client = _app_client()
    # nothing provided
    resp = client.post("/api/scan-product", data={})
    if resp.status_code != 400:
        failures.append("P9 empty POST should be 400")
    # too-long text
    resp = client.post("/api/scan-product", data={"ingredient_input": "A" * 5001})
    if resp.status_code != 400:
        failures.append("P9 oversized text should be 400")
    # unsupported file type
    resp = client.post(
        "/api/scan-product",
        data={"ingredient_image": (io.BytesIO(b"not an image"), "label.txt")},
        content_type="multipart/form-data",
    )
    if resp.status_code != 400:
        failures.append("P9 unsupported filetype should be 400")
    # valid extension but not a real image
    resp = client.post(
        "/api/scan-product",
        data={"ingredient_image": (io.BytesIO(b"this is not image data"), "label.png")},
        content_type="multipart/form-data",
    )
    if resp.status_code != 400:
        failures.append("P9 corrupt image should be 400")
    if not failures:
        print("P9 route input-validation checks passed.")
    return failures


def test_structural_all():
    failures = []
    inputs = [
        "Ingredients: Water, Glycerin, Tartrazine",
        "Sodium nitrite, BHA",
        "Mysterypuff X23, Zarblend-9, Water",
        "Coca-Cola Classic",
        "",
    ]
    for text in inputs:
        payload = scan_product(text)
        for issue in structural_issues(payload):
            failures.append(f"STRUCTURE({text[:20]!r}): {issue}")
    if not failures:
        print("P9 structural invariants passed.")
    return failures


# --------------------------------------------------------------------------- #
# P10  DB-backed hybrid pipeline (verified product database)
# --------------------------------------------------------------------------- #
def _scan_db(input_text=""):
    from app_factory import create_app

    app = create_app()
    with app.app_context():
        return scan_product(input_text=input_text)


def _big_font(size=56):
    for path in (
        os.environ.get("TRUSTLENS_TEST_FONT", ""),
        r"C:\Windows\Fonts\arial.ttf",
        r"C:\Windows\Fonts\segoeui.ttf",
    ):
        if path and os.path.exists(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def build_dettol_image():
    lines = [
        "Dettol",
        "Antiseptic Disinfectant Liquid",
        "Ingredients:",
        "Chloroxylenol 4.8%",
        "Pine oil 9.2%",
        "Isopropyl alcohol 5.1%",
        "Water",
    ]
    font = _big_font(56)
    line_h = 132
    img = Image.new("RGB", (1600, 110 + line_h * len(lines)), (255, 255, 255))
    d = ImageDraw.Draw(img)
    y = 50
    for text in lines:
        d.text((60, y), text, fill=(0, 0, 0), font=font)
        y += line_h
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf


def test_seed_idempotent():
    from app_factory import create_app
    from database.seed_product_db import seed_product_db
    from models.product_db import Ingredient, Product

    failures = []
    app = create_app()
    with app.app_context():
        seed_product_db(app, force=True)  # normalize to current KB state first
        before = (Ingredient.query.count(), Product.query.count())
        seed_product_db(app)
        seed_product_db(app, force=True)
        after = (Ingredient.query.count(), Product.query.count())
        if before != after:
            failures.append(f"P10 seed changed counts {before} -> {after}")
        if after[0] < 60 or after[1] < 3:
            failures.append(f"P10 seed data too small: {after}")
    if not failures:
        print("P10 seeding idempotency passed.")
    return failures


def test_dettol_product_match():
    """Brand+name match -> verified record, consumption status, warnings, no penalty."""
    failures = []
    payload = _scan_db("Dettol Antiseptic Disinfectant Liquid")
    if payload.get("database_match") != "High":
        failures.append(f"P10 dettol match {payload.get('database_match')} != High")
    prod = payload.get("product") or {}
    if prod.get("product_id") != "PRD-DETTOL-ANTISEPTIC-IN":
        failures.append(f"P10 dettol product_id {prod.get('product_id')}")
    if prod.get("brand_name") != "Dettol":
        failures.append(f"P10 dettol brand {prod.get('brand_name')}")
    if payload.get("consumption_status") != "Not intended for human consumption":
        failures.append(f"P10 dettol consumption {payload.get('consumption_status')}")
    if not payload.get("reliable"):
        failures.append("P10 dettol match not reliable")
    if payload.get("ingredient_count") != 6:
        failures.append(f"P10 dettol ingredient_count {payload.get('ingredient_count')} != 6")
    # A non-food product is assessed for its intended use - never penalised for
    # simply not being edible. Pine oil (a moderate-concern ingredient) places
    # it in the MODERATE band (50-60), not because of consumption status.
    if not (50 <= payload.get("score", 0) <= 60):
        failures.append(f"P10 non-food product score {payload.get('score')} not in MODERATE band 50-60")
    if payload.get("risk_label") != "MODERATE RISK":
        failures.append(f"P10 dettol risk_label {payload.get('risk_label')}")
    if not prod.get("warnings"):
        failures.append("P10 product warnings missing")
    if prod.get("consumption_status") != "Not intended for human consumption":
        failures.append(f"P10 product dict consumption {prod.get('consumption_status')}")
    if not failures:
        print("P10 dettol verified-record match passed.")
    return failures


def test_db_ocr_comparison():
    """Found-on-label vs expected-not-visible; concentrations never guessed."""
    failures = []
    label = (
        "Dettol Antiseptic Disinfectant Liquid\n"
        "Ingredients: Chloroxylenol 4.8%, Pine oil 9.2%, Isopropyl alcohol 5.1%, "
        "Castor oil, Potassium castorate, Water"
    )
    payload = _scan_db(label)
    if payload.get("database_match") != "High":
        failures.append(f"P10 match {payload.get('database_match')} != High")
    cards = payload.get("ingredients") or []
    by_name = {c["name"]: c for c in cards}
    if len(cards) != 6:
        failures.append(f"P10 cards {len(cards)} != 6: {[c['name'] for c in cards]}")
    for expected in ("Chloroxylenol", "Pine oil", "Castor oil", "Water"):
        if by_name.get(expected, {}).get("detection") != "Found on label":
            failures.append(f"P10 {expected} detection {by_name.get(expected, {}).get('detection')}")
    # published concentration preserved exactly
    if by_name.get("Chloroxylenol", {}).get("concentration") != 4.8:
        failures.append(f"P10 chloroxylenol concentration {by_name.get('Chloroxylenol', {}).get('concentration')}")
    # unpublished concentration stays NULL - never guessed
    if by_name.get("Castor oil", {}).get("concentration") is not None:
        failures.append("P10 castor oil concentration fabricated")
    missing_text = " ".join(payload.get("missing") or [])
    if "never guessed" not in missing_text:
        failures.append(f"P10 missing lacks concentration-notice: {missing_text}")
    if not payload.get("reliable"):
        failures.append("P10 DB analysis not reliable")
    if not failures:
        print("P10 DB<->OCR comparison passed.")
    return failures


def test_unknown_product_honest():
    """Unmatched product -> honest 'Product not found', unknowns stay unknown."""
    failures = []
    payload = _scan_db("Zorpax Multi-Chemical Cleaner\nIngredients: Water, Sodium lauryl sulfate")
    if payload.get("database_match") != "None":
        failures.append(f"P10 match {payload.get('database_match')} != None")
    if payload.get("database_match_label") != "Product not found in the verified product database.":
        failures.append(f"P10 label {payload.get('database_match_label')!r}")
    if payload.get("data_quality", {}).get("database_match") != "Not available":
        failures.append(f"P10 data_quality.database_match {payload.get('data_quality', {}).get('database_match')}")
    if payload.get("product") is not None:
        failures.append("P10 unknown product must have no product record")
    if not any("Product not found in the verified product database" in m for m in (payload.get("missing") or [])):
        failures.append("P10 missing lacks product-not-found note")
    if not payload.get("reliable"):
        failures.append("P10 unknown-product fallback must still be a reliable KB analysis")
    for card in payload.get("ingredients") or []:
        if card["category"] == "unknown" and "not proof that it is harmful" not in (card.get("info") or ""):
            failures.append("P10 unknown ingredient honesty note missing")
    if payload.get("risk_level") == "higher":
        failures.append("P10 unknowns must never make a product 'higher concern'")
    if not failures:
        print("P10 unknown-product honesty passed.")
    return failures


def test_brand_only_no_false_product():
    """Brand-only match must never attach a random product of that brand."""
    failures = []
    payload = _scan_db("Dettol Fresh Bathroom Wipes, Water, Glycerin")
    if payload.get("database_match") != "BrandOnly":
        failures.append(f"P10 match {payload.get('database_match')} != BrandOnly")
    if payload.get("database_match_label") != "Brand identified - exact product/variant not confirmed in the database":
        failures.append(f"P10 label {payload.get('database_match_label')!r}")
    if payload.get("product") is not None:
        failures.append("P10 BrandOnly must not attach a random product")
    if not any("Brand identified" in m for m in (payload.get("missing") or [])):
        failures.append("P10 missing lacks brand-only note")
    if not payload.get("reliable"):
        failures.append("P10 brand-only fallback not reliable")
    if not failures:
        print("P10 brand-only honesty passed.")
    return failures


def test_unknown_ingredient_on_matched_product():
    """An unknown label ingredient on a verified product is surfaced honestly."""
    failures = []
    label = (
        "Dettol Antiseptic Disinfectant Liquid\n"
        "Ingredients: Chloroxylenol 4.8%, Pine oil 9.2%, Water, Zarblend-9"
    )
    payload = _scan_db(label)
    if payload.get("database_match") != "High":
        failures.append(f"P10 match {payload.get('database_match')} != High")
    unknown = [c for c in (payload.get("ingredients") or []) if c["category"] == "unknown"]
    if not unknown:
        failures.append("P10 unknown label ingredient not surfaced")
    if not any(c["detection"] == "Unknown ingredient on label" for c in unknown):
        failures.append("P10 unknown detection class wrong")
    if not any("not proof that it is harmful" in (c.get("info") or "") for c in unknown):
        failures.append("P10 unknown honesty note missing")
    if payload.get("risk_level") == "higher":
        failures.append("P10 unknown must never be treated as dangerous")
    if not failures:
        print("P10 unknown-ingredient-on-verified-product passed.")
    return failures


def test_dettol_image_route():
    """End-to-end: OCR a real Dettol label image and match the verified record."""
    failures = []
    client = _app_client()
    img = build_dettol_image()
    resp = client.post(
        "/api/scan-product",
        data={"ingredient_image": (img, "dettol.png")},
        content_type="multipart/form-data",
    )
    data = resp.get_json() or {}
    if resp.status_code != 200 or not data.get("success"):
        failures.append(f"P10 dettol image route status {resp.status_code}: {data.get('error')}")
        return failures
    if not data.get("reliable"):
        failures.append(f"P10 dettol label OCR produced no reliable scan: {data.get('explanation')}")
        return failures
    if data.get("database_match") not in ("High", "Medium", "Low"):
        failures.append(f"P10 dettol image match {data.get('database_match')}")
    prod = data.get("product") or {}
    if prod.get("brand_name") != "Dettol":
        failures.append(f"P10 dettol image brand {prod.get('brand_name')}")
    if data.get("consumption_status") != "Not intended for human consumption":
        failures.append(f"P10 dettol image consumption {data.get('consumption_status')}")
    if not prod.get("warnings"):
        failures.append("P10 dettol image warnings missing")
    if data.get("ingredient_count", 0) < 4:
        failures.append(f"P10 dettol image parsed too few ingredients: {data.get('ingredient_count')}")
    if not data.get("extracted_text"):
        failures.append("P10 dettol image returned no extracted text")
    if not failures:
        print("P10 Dettol label image OCR -> verified record passed.")
    return failures


def main():
    verbose = "--table" not in sys.argv
    check_names = [
        test_parse_basics, test_lookup_basics, test_valid_list_scoring,
        test_higher_concern_scoring, test_unknown_never_dangerous,
        test_name_only_and_empty, test_extracted_text_path, test_spec_trust_bands,
        test_structural_all, test_route_valid_image, test_route_blurry_image,
        test_route_bad_inputs,
        test_seed_idempotent, test_dettol_product_match, test_db_ocr_comparison,
        test_unknown_product_honest, test_brand_only_no_false_product,
        test_unknown_ingredient_on_matched_product, test_dettol_image_route,
    ]
    failures = []
    for fn in check_names:
        if verbose:
            print(f"Running {fn.__name__} ...")
        failures.extend(fn())
    if failures:
        print("\nFAILURES:")
        for f in failures:
            print("  -", f)
        print(f"\n{len(failures)} failure(s).")
        sys.exit(1)
    print("\nAll product scanner validation checks passed (P1-P9 + P10 DB hybrid).")


if __name__ == "__main__":
    main()
