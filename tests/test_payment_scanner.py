"""
Payment screenshot scanner validation suite (evidence-based).

Runnable without pytest:

    python tests/test_payment_scanner.py            # run all checks
    python tests/test_payment_scanner.py --table    # just print the result table

The suite GENERATES every screenshot at runtime (no committed image files, no
hard-coded per-image hashes / OCR text / results), so the scanner can never be
over-fitted to fixed artefacts. Assertions are band-based and evidence-based,
not exact-score.

Behavioural guarantees exercised here (critical tests):

  T1  genuine screenshots            -> Low Risk
  T2  resized / re-compressed        -> still Low Risk (compression != fraud)
  T3  edited screenshots with real evidence -> Suspicious / High
  T4  QR vs screen mismatch          -> strictly riskier than a matching QR,
                                        with an explicit explanation in evidence
  T5  fabricated images              -> never Low (High, or honestly Unverifiable)
  T6  missing fields                 -> never raise risk (same band as full)
  T7  unreadable-but-not-blank       -> Unverifiable result type
  T8  honesty invariants             -> no "genuine" claim; transaction always
                                        unverified; risk==fraud_probability==
                                        100-score; score<=90 for readable images;
                                        single-fire signals (no double counting);
                                        evidence entries carry points + confidence.
"""

import os
import shutil
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np  # noqa: E402
import qrcode  # noqa: E402
from PIL import Image, ImageDraw, ImageFilter, ImageFont  # noqa: E402

from services.payment_scanner import _SIGNAL_DEFS, scan_payment_screenshot  # noqa: E402


# --------------------------------------------------------------------------- #
# Image generator: builds realistic UPI payment confirmation screenshots.
# --------------------------------------------------------------------------- #

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

QR_OK = "upi://pay?pa=merchant%40ybl&pn=Merchant%20Store&am=250.00&cu=INR&tn=Store%20purchase"
QR_AMT_999 = "upi://pay?pa=merchant%40ybl&pn=Merchant%20Store&am=999.00&cu=INR&tn=Store%20purchase"
QR_PAYEE_OTHER = "upi://pay?pa=other%40okaxis&pn=Other%20Shop&am=250.00&cu=INR&tn=Pay"
QR_URL = "https://example.com/verify"
QR_NO_PA = "upi://pay?pn=Merchant%20Store&am=250.00&cu=INR"


def qr_for_amount(amount: str, payee: str) -> str:
    """Build a UPI QR whose amount matches the screen amount (genuine case)."""
    am = amount.replace("Rs.", "").replace("\u20b9", "").replace(",", "").strip()
    pn = payee.replace(" ", "%20")
    return f"upi://pay?pa=merchant%40ybl&pn={pn}&am={am}&cu=INR&tn=Pay"


def make_qr(payload: str):
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=6, border=2)
    qr.add_data(payload)
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white").convert("RGB")


def build_screenshot(
    title="Payment Successful",
    status_line=None,
    amount="Rs. 250.00",
    recipient="Merchant Store",
    upi_id="merchant@ybl",
    txn="T210930123456789",
    date_line="Date: 05/08/2026   Time: 3:42 PM",
    qr_payload=QR_OK,
    include_qr=True,
    extra_to_lines=(),
    second_amount=None,
    duplicate_title=None,
    duplicate_title_pos=(60, 1400),
    header="Google Pay",
    header_color=(0, 90, 160),
    title_color=(0, 150, 0),
):
    """Render one 1080x1920 UPI payment confirmation screenshot."""
    W, H = 1080, 1920
    img = Image.new("RGB", (W, H), (255, 255, 255))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 150], fill=header_color)
    d.text((40, 40), header, fill=(255, 255, 255), font=FONT)
    d.text((60, 220), title, fill=title_color, font=FONT)
    if duplicate_title:
        d.text(duplicate_title_pos, duplicate_title, fill=(0, 0, 0), font=FONT)
    d.text((60, 330), "Amount", fill=(100, 100, 100), font=FONT)
    d.text((60, 400), amount, fill=(0, 0, 0), font=FONT)
    if second_amount:
        d.text((60, 490), second_amount, fill=(0, 0, 0), font=FONT)
    d.text((60, 580), "To", fill=(100, 100, 100), font=FONT)
    d.text((60, 650), ("To " + recipient) if extra_to_lines else recipient, fill=(0, 0, 0), font=FONT)
    for i, line in enumerate(extra_to_lines):
        d.text((60, 740 + i * 75), line, fill=(0, 0, 0), font=FONT)
    d.text((60, 920), "UPI ID", fill=(100, 100, 100), font=FONT)
    d.text((60, 990), upi_id, fill=(0, 0, 0), font=FONT)
    d.text((60, 1090), "Transaction ID", fill=(100, 100, 100), font=FONT)
    d.text((60, 1160), txn, fill=(0, 0, 0), font=FONT)
    d.text((60, 1270), date_line, fill=(0, 0, 0), font=FONT)
    if status_line:
        d.text((60, 1380), status_line, fill=(0, 0, 0), font=FONT)
    if include_qr:
        img.paste(make_qr(qr_payload), (760, 1450))
    return img


def _save(img: Image.Image, workdir: str, name: str, fmt="PNG", **kw) -> str:
    path = os.path.join(workdir, name + ("." + fmt.lower() if fmt != "PNG" else ".png"))
    if fmt == "JPEG" and kw.get("quality") is None:
        kw["quality"] = 85
    img.save(path, format=fmt, **kw)
    return path


# --------------------------------------------------------------------------- #
# Dataset construction.
# --------------------------------------------------------------------------- #

def build_dataset(workdir: str) -> dict:
    """Generate the full validation corpus. Returns {case_name: image_path}."""
    out = {}

    # ---- 10 genuine receipts (varying payee / amount / txn / date) ----------
    genuine_specs = [
        dict(recipient="Merchant Store", amount="Rs. 250.00", txn="T210930123456789", date_line="Date: 05/08/2026   Time: 3:42 PM"),
        dict(recipient="Rahul Verma", amount="Rs. 999.00", txn="T220814765432198", date_line="Date: 21/12/2025   Time: 9:15 AM"),
        dict(recipient="Priya Sharma", amount="Rs. 45.50", txn="T231105456123789", date_line="Date: 01/01/2026   Time: 12:00 PM"),
        dict(recipient="Sunil Traders", amount="Rs. 1200.00", txn="T241201789456123", date_line="Date: 30/06/2026   Time: 6:08 PM"),
        dict(recipient="Cafe Coffee Day", amount="Rs. 75.25", txn="T250301321654987", date_line="Date: 15/03/2026   Time: 11:30 AM"),
        dict(recipient="Metro Station", amount="Rs. 60.00", txn="T260710987321654", date_line="Date: 07/07/2026   Time: 8:45 PM"),
        dict(recipient="BookMyShow", amount="Rs. 550.00", txn="T270815159753486", date_line="Date: 18/09/2026   Time: 2:20 PM"),
        dict(recipient="Amazon India", amount="Rs. 1899.00", txn="T280905357951468", date_line="Date: 25/02/2026   Time: 4:55 PM"),
        dict(recipient="Swiggy", amount="Rs. 342.75", txn="T290115246813579", date_line="Date: 03/11/2026   Time: 7:05 PM"),
        dict(recipient="VARSHA SUNIL ZAROO", amount="Rs. 250.00", txn="T300120864201357", date_line="Date: 12/04/2026   Time: 10:10 AM", include_qr=False),
    ]
    for i, spec in enumerate(genuine_specs):
        kw = dict(spec)
        if kw.get("include_qr", True):
            kw["qr_payload"] = qr_for_amount(kw["amount"], kw["recipient"])
        img = build_screenshot(**kw)
        out[f"genuine_{i + 1}"] = _save(img, workdir, f"genuine_{i + 1}")

    # ---- 10 manipulated receipts (each with detectable evidence) ------------
    manip_specs = {
        "manip_exif": dict(img=build_screenshot(), exif="Adobe Photoshop 24.0"),
        "manip_dup_title": dict(img=build_screenshot(duplicate_title="Payment Successful")),
        "manip_dup_recipient": dict(img=build_screenshot(recipient="Merchant Store", extra_to_lines=("To: Merchant Store",))),
        "manip_impossible_date": dict(img=build_screenshot(date_line="Date: 44/08/2026   Time: 3:42 PM")),
        "manip_amount_conflict": dict(img=build_screenshot(second_amount="Rs. 999.00")),
        "manip_status_conflict": dict(img=build_screenshot(title="Payment Successful", status_line="Payment Failed")),
        "manip_qr_amount": dict(img=build_screenshot(qr_payload=QR_AMT_999)),
        "manip_qr_payee": dict(img=build_screenshot(qr_payload=QR_PAYEE_OTHER)),
        "manip_invalid_upi": dict(img=build_screenshot(upi_id="notanupi@@bad")),
    }
    for name, spec in manip_specs.items():
        img = spec["img"]
        if spec.get("exif"):
            ex = Image.Exif()
            ex[0x0131] = spec["exif"]
            path = os.path.join(workdir, name + ".png")
            img.save(path, format="PNG", exif=ex.tobytes())
            out[name] = path
        else:
            out[name] = _save(img, workdir, name)

    # clone-region manipulation: paste the payee name row elsewhere on screen
    cloned = build_screenshot()
    region = cloned.crop((60, 650, 420, 715))
    cloned.paste(region, (620, 1180))
    out["manip_clone"] = _save(cloned, workdir, "manip_clone")

    # ---- 10 fabricated / non-screenshot images ------------------------------
    W, H = 1080, 1920
    rng = np.random.default_rng(7)
    gib = Image.new("RGB", (W, H), (255, 255, 255))
    gd = ImageDraw.Draw(gib)
    for i, t in enumerate(["zxqw", "bvplmn", "qkwjdf", "zhbvnx", "asd", "mnb", "oiuy"]):
        gd.text((80, 100 + i * 90), t, fill=(0, 0, 0), font=FONT)
    out["fab_gibberish_text"] = _save(gib, workdir, "fab_gibberish_text")

    grad = np.tile(np.linspace(0, 255, W, dtype=np.float32).astype(np.uint8), (H, 1))
    out["fab_gradient"] = _save(Image.fromarray(np.dstack([grad, grad, grad]), "RGB"), workdir, "fab_gradient")

    yy, xx = np.mgrid[0:H, 0:W].astype(np.float32)
    dd = np.sqrt((xx - W / 2) ** 2 + (yy - H / 2) ** 2)
    radial = (dd / dd.max() * 255).astype(np.uint8)
    out["fab_radial"] = _save(Image.fromarray(np.dstack([radial, radial, radial]), "RGB"), workdir, "fab_radial")

    checker = (((np.indices((H, W)).sum(axis=0) // 40) % 2) * 255).astype(np.uint8)
    out["fab_checker"] = _save(Image.fromarray(np.dstack([checker, checker, checker]), "RGB"), workdir, "fab_checker")

    out["fab_solid"] = _save(Image.new("RGB", (W, H), (200, 200, 200)), workdir, "fab_solid")
    out["fab_black"] = _save(Image.new("RGB", (W, H), (0, 0, 0)), workdir, "fab_black")
    out["fab_noise"] = _save(Image.fromarray(rng.integers(0, 255, (H, W, 3), dtype=np.uint8), "RGB"), workdir, "fab_noise")
    mottle = np.full((H, W, 3), 128, dtype=np.uint8) + rng.integers(0, 40, (H, W, 1)).repeat(3, axis=2).astype(np.uint8)
    out["fab_mottled"] = _save(Image.fromarray(mottle, "RGB"), workdir, "fab_mottled")
    out["fab_white_noise_dark"] = _save(Image.fromarray(rng.integers(0, 90, (H, W, 3), dtype=np.uint8), "RGB"), workdir, "fab_white_noise_dark")

    # ---- 5 resized / re-compressed genuine ---------------------------------
    gen = build_screenshot()
    out["resize_50"] = _save(gen.resize((540, 960), Image.LANCZOS), workdir, "resize_50", "JPEG", quality=70)
    out["resize_30"] = _save(gen.resize((324, 576), Image.LANCZOS), workdir, "resize_30", "JPEG", quality=80)
    out["compressed_q30"] = _save(gen, workdir, "compressed_q30", "JPEG", quality=30)
    out["compressed_q50"] = _save(gen, workdir, "compressed_q50", "JPEG", quality=50)
    re1 = gen.resize((540, 960), Image.LANCZOS)
    out["resize_compress"] = _save(re1, workdir, "resize_compress", "JPEG", quality=55)

    # ---- 5 cropped genuine ------------------------------------------------
    out["crop_top"] = _save(gen.crop((0, 0, 1080, 900)), workdir, "crop_top", "JPEG", quality=85)
    out["crop_mid"] = _save(gen.crop((0, 300, 1080, 1400)), workdir, "crop_mid", "JPEG", quality=85)
    out["crop_small"] = _save(gen.crop((0, 0, 300, 400)), workdir, "crop_small")
    out["crop_left"] = _save(gen.crop((0, 0, 400, 1920)), workdir, "crop_left")
    out["crop_qr"] = _save(gen.crop((700, 1300, 1080, 1920)), workdir, "crop_qr")

    # ---- 5 low-OCR / hard-to-read -----------------------------------------
    out["low_blurred"] = _save(gen.filter(ImageFilter.GaussianBlur(6)), workdir, "low_blurred")
    out["low_heavy_blur"] = _save(gen.filter(ImageFilter.GaussianBlur(14)), workdir, "low_heavy_blur")
    out["low_dark_mode"] = _save(Image.eval(gen.convert("L").convert("RGB"), lambda v: 255 - v), workdir, "low_dark_mode")
    out["low_contrast"] = _save(Image.eval(gen.convert("L").convert("RGB"), lambda v: v * 0.25 + 110), workdir, "low_contrast")
    rot = gen.rotate(18, expand=True, fillcolor=(255, 255, 255)).crop((0, 0, 1080, 1920))
    out["low_rotated"] = _save(rot, workdir, "low_rotated")

    # ---- 5 with QR codes ---------------------------------------------------
    out["qr_consistent"] = _save(build_screenshot(), workdir, "qr_consistent")
    out["qr_amount_mismatch"] = _save(build_screenshot(qr_payload=QR_AMT_999), workdir, "qr_amount_mismatch")
    out["qr_payee_mismatch"] = _save(build_screenshot(qr_payload=QR_PAYEE_OTHER), workdir, "qr_payee_mismatch")
    out["qr_non_upi"] = _save(build_screenshot(qr_payload=QR_URL), workdir, "qr_non_upi")
    out["qr_invalid"] = _save(build_screenshot(qr_payload=QR_NO_PA), workdir, "qr_invalid")

    # ---- 5 inconsistent fields --------------------------------------------
    out["field_amount"] = _save(build_screenshot(second_amount="Rs. 999.00"), workdir, "field_amount")
    out["field_status"] = _save(build_screenshot(title="Payment Successful", status_line="Payment Failed"), workdir, "field_status")
    out["field_date"] = _save(build_screenshot(date_line="Date: 44/08/2026   Time: 3:42 PM"), workdir, "field_date")
    out["field_recipient"] = _save(build_screenshot(recipient="Merchant Store", extra_to_lines=("To: Merchant Store",)), workdir, "field_recipient")
    out["field_txn_short"] = _save(build_screenshot(txn="T123456789"), workdir, "field_txn_short")

    # ---- missing-fields screenshot (full receipt minus amount + QR) --------
    out["missing_fields"] = _save(build_screenshot(include_qr=False, amount=""), workdir, "missing_fields")

    return out


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #

PAYLOAD_KEYS = [
    "score", "status", "verdict", "result_type", "risk", "risk_level",
    "fraud_probability", "reasons", "evidence", "verification", "flags",
    "extracted_text", "qr", "details", "field_summary", "confidence",
    "processing_time_ms",
]


def structural_issues(payload: dict) -> list:
    issues = []
    for key in PAYLOAD_KEYS:
        if key not in payload:
            issues.append(f"missing key '{key}'")
    if not (0 <= payload.get("risk", -1) <= 100):
        issues.append("risk out of 0-100")
    if not (0 <= payload.get("score", -1) <= 100):
        issues.append("score out of 0-100")
    if payload.get("risk") != payload.get("fraud_probability"):
        issues.append("fraud_probability != risk")
    if payload.get("risk") != 100 - payload.get("score"):
        issues.append("score != 100 - risk")
    conf = payload.get("confidence", {})
    for k in ("overall", "ocr", "image_authenticity"):
        if not isinstance(conf.get(k), int) or not (0 <= conf[k] <= 100):
            issues.append(f"confidence.{k} not an int 0-100")
    seen = set()
    for e in payload.get("evidence", []):
        for k in ("signal", "points", "severity", "confidence", "evidence", "note"):
            if k not in e:
                issues.append(f"evidence entry missing '{k}'")
        if e["signal"] in seen:
            issues.append(f"evidence double-counted signal '{e['signal']}'")
        seen.add(e["signal"])
        if e["points"] != _SIGNAL_DEFS.get(e["signal"], (None, None))[0]:
            issues.append(f"evidence points mismatch for '{e['signal']}'")
    for r in payload.get("reasons", []):
        if "severity" not in r or "text" not in r or "points" not in r:
            issues.append("reason missing severity/text/points")
    return issues


def _run_case(path: str) -> dict:
    return scan_payment_screenshot(path)


def run_checks(verbose=True):
    failures = []
    table = []

    workdir = tempfile.mkdtemp(prefix="trustlens_paytest_")
    try:
        dataset = build_dataset(workdir)
        results = {}
        for name, path in dataset.items():
            results[name] = _run_case(path)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    def case(name):
        return results[name]

    def risk_of(name):
        return results[name]["risk"]

    def type_of(name):
        return results[name]["result_type"]

    def signals_of(name):
        return {e["signal"] for e in results[name]["evidence"]}

    # ---- structural + honesty invariants (T8) over every image -------------
    for name, payload in results.items():
        issues = structural_issues(payload)
        if issues:
            failures.append(f"[{name}] STRUCTURE: {'; '.join(issues)}")
        if payload.get("verdict") == "Genuine Payment Screenshot":
            failures.append(f"[{name}] still claims 'Genuine Payment Screenshot'")
        if "transaction_not_verified" not in signals_of(name):
            failures.append(f"[{name}] missing transaction_not_verified base signal")
        if payload.get("verification", {}).get("verified") is not False:
            failures.append(f"[{name}] verification must be False")
        if payload.get("score", 0) > 90:
            failures.append(f"[{name}] score {payload['score']} > 90 (risk can never be 0)")

    # ---- T1: genuine -> low ------------------------------------------------
    for i in range(1, 11):
        name = f"genuine_{i}"
        if risk_of(name) >= 30:
            failures.append(f"[T1 {name}] risk {risk_of(name)} should be < 30 (low)")
        if type_of(name) != "low":
            failures.append(f"[T1 {name}] type {type_of(name)} != low")
        table.append((name, "low", risk_of(name), type_of(name), signals_of(name), "genuine"))

    # ---- T2: resized / compressed -> low -----------------------------------
    for name in ("resize_50", "resize_30", "compressed_q30", "compressed_q50", "resize_compress"):
        if risk_of(name) >= 30:
            failures.append(f"[T2 {name}] risk {risk_of(name)} should be < 30 (compression/resize != fraud)")
        table.append((name, "low", risk_of(name), type_of(name), signals_of(name), "resized/compressed"))

    # ---- T3: manipulated with detectable evidence -> suspicious/high --------
    for name in ("manip_exif", "manip_dup_title", "manip_dup_recipient", "manip_impossible_date",
                 "manip_amount_conflict", "manip_status_conflict", "manip_qr_amount",
                 "manip_qr_payee", "manip_clone", "manip_invalid_upi"):
        if risk_of(name) < 30:
            failures.append(f"[T3 {name}] risk {risk_of(name)} should be >= 30 (manipulation evidence present)")
        if type_of(name) not in ("suspicious", "high"):
            failures.append(f"[T3 {name}] type {type_of(name)} not suspicious/high")
        table.append((name, ">=30", risk_of(name), type_of(name), signals_of(name), "manipulated"))

    # ---- T4: QR mismatch riskier than matching QR, with explanation --------
    qr_consistent_risk = risk_of("qr_consistent")
    for name, exp in (("qr_amount_mismatch", "qr_screen_mismatch"), ("qr_payee_mismatch", "qr_screen_mismatch")):
        if risk_of(name) <= qr_consistent_risk:
            failures.append(f"[T4 {name}] risk {risk_of(name)} not > matching QR {qr_consistent_risk}")
        if exp not in signals_of(name):
            failures.append(f"[T4 {name}] missing expected signal '{exp}'")
        note = next((e["note"] for e in results[name]["evidence"] if e["signal"] == exp), "")
        if not note:
            failures.append(f"[T4 {name}] no explanation text for {exp}")
        table.append((name, ">qr", risk_of(name), type_of(name), signals_of(name), "qr mismatch"))

    # ---- T5: fabricated -> never low ---------------------------------------
    for name in ("fab_gibberish_text", "fab_gradient", "fab_radial", "fab_checker",
                 "fab_solid", "fab_black", "fab_noise", "fab_mottled",
                 "fab_white_noise_dark"):
        if type_of(name) == "low" or risk_of(name) < 30:
            failures.append(f"[T5 {name}] fabricated image scored low/safe (risk {risk_of(name)}, type {type_of(name)})")
        table.append((name, "high/unv", risk_of(name), type_of(name), signals_of(name), "fabricated"))

    # ---- T6: missing fields never raise risk --------------------------------
    if risk_of("missing_fields") > risk_of("genuine_1") + 10:
        failures.append(f"[T6] missing_fields risk {risk_of('missing_fields')} too high vs genuine {risk_of('genuine_1')}")
    if risk_of("missing_fields") >= 30:
        failures.append(f"[T6] missing_fields risk {risk_of('missing_fields')} >= 30 (missing data != fraud)")
    table.append(("missing_fields", "low", risk_of("missing_fields"), type_of("missing_fields"), signals_of("missing_fields"), "missing fields"))

    # ---- T7: unreadable-but-not-blank -> Unverifiable -----------------------
    if type_of("fab_radial") != "unverifiable":
        failures.append(f"[T7] radial gradient type {type_of('fab_radial')} != unverifiable")
    table.append(("fab_radial", "unverifiable", risk_of("fab_radial"), type_of("fab_radial"), signals_of("fab_radial"), "unverifiable case"))

    # ---- weak-signal honesty: short txid is weak, not fraud -----------------
    if "txid_too_short" not in signals_of("field_txn_short"):
        failures.append("[weak] field_txn_short missing txid_too_short signal")
    if risk_of("field_txn_short") >= 30:
        failures.append(f"[weak] field_txn_short risk {risk_of('field_txn_short')} >= 30 (short txid alone is weak evidence)")
    table.append(("field_txn_short", "weak", risk_of("field_txn_short"), type_of("field_txn_short"), signals_of("field_txn_short"), "weak signal"))

    # ---- inconsistent fields category ---------------------------------------
    for name, exp in (
        ("field_amount", "conflicting_amounts"), ("field_status", "conflicting_status"),
        ("field_date", "impossible_date"), ("field_recipient", "duplicate_recipient"),
    ):
        if exp not in signals_of(name):
            failures.append(f"[fields {name}] missing expected signal '{exp}'")
        if risk_of(name) < 30:
            failures.append(f"[fields {name}] risk {risk_of(name)} < 30 for strong inconsistency")
        table.append((name, ">=30", risk_of(name), type_of(name), signals_of(name), "inconsistent fields"))

    # ---- QR category --------------------------------------------------------
    if "qr_consistent" not in results or results["qr_consistent"]["flags"].get("qr_detected") is not True:
        failures.append("[qr] qr_consistent should have qr_detected True")
    for name, exp in (("qr_non_upi", "qr_not_upi"), ("qr_invalid", "qr_invalid")):
        if exp not in signals_of(name):
            failures.append(f"[qr {name}] missing expected signal '{exp}'")
        if risk_of(name) >= 30:
            failures.append(f"[qr {name}] risk {risk_of(name)} >= 30 for a weak QR anomaly")
        table.append((name, "weak", risk_of(name), type_of(name), signals_of(name), "qr anomaly"))

    # ---- cropped -------------------------------------------------------------
    for name in ("crop_top", "crop_mid", "crop_small", "crop_left", "crop_qr"):
        if risk_of(name) >= 30:
            failures.append(f"[crop {name}] risk {risk_of(name)} >= 30 (cropping != fraud)")
        table.append((name, "low", risk_of(name), type_of(name), signals_of(name), "cropped"))

    # ---- low-OCR -------------------------------------------------------------
    for name in ("low_blurred", "low_heavy_blur", "low_dark_mode", "low_contrast", "low_rotated"):
        if risk_of(name) >= 60:
            failures.append(f"[lowocr {name}] risk {risk_of(name)} >= 60 (poor OCR must not be 'high risk')")
        table.append((name, "not-high", risk_of(name), type_of(name), signals_of(name), "low OCR"))

    if verbose:
        print(f"{'case':<24} {'expect':<10} {'risk':>4} {'type':<12} signals")
        print("-" * 100)
        for name, exp, risk, typ, sigs, cat in table:
            print(f"{name:<24} {exp:<10} {risk:>4} {typ:<12} {','.join(sorted(sigs))[:46]}")
        print("-" * 100)
        print(f"Total cases scanned: {len(results)}")

    return failures, results


def main():
    verbose = "--table" not in sys.argv
    failures, _results = run_checks(verbose=verbose)
    if failures:
        print("\nFAILURES:")
        for f in failures:
            print("  -", f)
        print(f"\n{len(failures)} failure(s).")
        sys.exit(1)
    print("\nAll payment scanner validation checks passed (T1-T8 + 8 categories).")


if __name__ == "__main__":
    main()
