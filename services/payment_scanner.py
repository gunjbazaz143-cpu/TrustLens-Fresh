"""
Payment screenshot analyzer (evidence-driven).

Determines whether an uploaded "payment confirmation" screenshot shows signs of
fabrication/editing by combining real signals:

  * OCR (EasyOCR)    - per-word confidence, text extraction, field detection:
                       UPI ID, amount, date, time, transaction ID, bank,
                       recipient, merchant, success message, app name
  * Image forensics  - blur, flatness, noise, JPEG blockiness, Error Level
                       Analysis (ELA), copy-move with dominant-offset clustering
  * Metadata / EXIF  - editing-tool Software tags, camera Make/Model markers
  * QR decoding      - reuses the QR pipeline (zxing/pyzbar/OpenCV), verifies
                       upi://pay payloads (pa/pn/am/tn/tr/cu) and cross-checks
                       them against the OCR text
  * Text consistency - overlapping text regions, duplicated text regions,
                       duplicate recipient labels, low-confidence rendered text
  * Field consistency- impossible dates, conflicting amounts, invalid UPI IDs,
                       conflicting status words
  * Region forensics - per-field local noise / error-level deviation (edited or
                       pasted regions usually carry a different re-compression
                       footprint than the rest of the screenshot)

RESULT MODEL (honest, evidence-based)
-------------------------------------
Risk and confidence are two independent concepts:

  * RISK  - how much manipulation / inconsistency evidence was found. Starts at
            zero and only grows from detected signals. A lack of suspicious
            evidence does NOT make a screenshot "genuine".
  * CONFIDENCE - how much the analysis could actually determine (OCR quality,
            field coverage, forensic completeness). Never reaches 100%.

Result types:
  A. LOW RISK        - no obvious manipulation detected (NOT proof of payment)
  B. SUSPICIOUS      - possible manipulation / inconsistency evidence
  C. HIGH RISK       - strong manipulation evidence
  D. UNVERIFIABLE    - insufficient readable evidence to form a judgement

The system NEVER claims a screenshot is genuinely a real-world transaction:
a visually convincing screenshot is not proof that money moved. The final
verdict always carries that caveat.

score (0-100 trust) is derived from risk as 100 - risk so the rest of TrustLens
(gauge, DB, reports) keeps working unchanged, but the UI now also surfaces risk,
result type and confidence explicitly.
"""

import concurrent.futures
import os
import re
import time
import traceback

from config import Config
from services.logger import get_logger
from services.whatsapp_scanner import _get_reader
from services.qr_scanner import decode_qr, _clean_payload, _parse_upi, UPI_ID_RE
from services.payment_forensics import copy_move_analysis, ela_analysis

logger = get_logger(__name__)

# ---- Static knowledge bases ------------------------------------------------

# Editing applications that embed marker metadata.
EDIT_TOOL_NAMES = [
    "picsart", "canva", "photopea", "snapseed", "photoshop", "pixlr",
    "adobe", "gimp", "paint", "sketch", "lightroom", "pixelcut", "photo editor",
]

# Apps that produce genuine UPI / bank screenshots.
KNOWN_APPS = [
    "google pay", "gpay", "phonepe", "paytm", "bhim", "amazon pay",
    "amazonpay", "cred", "mobikwik", "freecharge", "jupiter", "upi",
    "airtel payments", "airtel pay", "jio payments", "myjio", "mi upi",
    "slice", "kotak 811", "fampay", "nobank", "wifi", "navigator",
]

# Indian bank names that can legitimately appear on a payment confirmation.
BANK_NAMES = [
    "state bank of india", "sbi", "hdfc", "icici", "axis", "kotak", "pnb",
    "punjab national bank", "idfc", "yes bank", "union bank", "bank of baroda",
    "bank of india", "canara", "indusind", "federal bank", "rbl", "bandhan",
    "au bank", "aubank", "jupiter", "nabil", "paytm payments bank",
    "jammu & kashmir bank", "jammu and kashmir bank", "jk bank", "j&k bank",
    "central bank of india", "indian overseas bank", "indian bank",
    "idbi", "bank of maharashtra", "punjab & sind bank", "punjab and sind bank",
    "south indian bank", "tamilnad mercantile bank", "tamil nadu grama bank",
    "karur vysya bank", "city union bank", "dhanlaxmi bank", "equitas small finance bank",
    "karnataka bank", "jammu bank", "nainital bank", "bank of india",
    "airtel payments bank", "jio payments bank", "india post payments bank",
    "fino payments bank", "nsdl payments bank", "suryoday small finance bank",
    "au small finance bank", "utkarsh small finance bank", "north east small finance bank",
    "shivalik small finance bank", "northarc", "east west", "kalupur",
    "saraswat", "cosmos", "bharat cooperative", "apna bharat", "rbl bank",
]

# Words that indicate payment-related content (used to confirm the image is a
# payment screenshot rather than an arbitrary photo).
PAYMENT_KEYWORDS = [
    "upi", "transaction", "payment", "amount", "paid", "successful", "success",
    "utr", "reference", "refund", "received", "balance", "bank", "debit", "credit",
    "recipient", "payee", "beneficiary", "merchant", "google pay", "gpay",
    "phonepe", "paytm", "bhim", "rs", "inr", "completed", "money sent",
    "you paid", "cred", "amazon pay", "credited", "debited",
]

# Ordered field list shown to the user (detected / missing breakdown).
FIELD_LABELS = [
    ("amount", "Amount"),
    ("txn", "UTR / Transaction ID"),
    ("payment_status", "Payment Status"),
    ("date", "Date"),
    ("time", "Time"),
    ("recipient", "Recipient Name"),
    ("upi_id", "UPI ID"),
    ("bank", "Bank"),
    ("app", "App"),
]

# ---- OCR helpers ------------------------------------------------------------

def _preprocess_image(image_path: str) -> str | None:
    """Build an OCR-friendly variant: upscaled, denoised, contrast-enhanced."""
    import tempfile
    import uuid

    try:
        import cv2

        img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
        if img is None:
            return None
        h, w = img.shape
        if h < 800:
            scale = min(2.0, 1000 / max(h, 1))
            img = cv2.resize(img, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
        img = cv2.fastNlMeansDenoising(img, None, 8, 7, 21)
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        img = clahe.apply(img)
        out = os.path.join(tempfile.gettempdir(), f"trustlens_ocr_{uuid.uuid4().hex}.png")
        cv2.imwrite(out, img)
        return out
    except Exception:  # noqa: BLE001
        return None


def _ocr_run(reader, image_path: str) -> dict:
    """Run EasyOCR once on an image, returning a normalised result dict."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(reader.readtext, image_path, detail=1, paragraph=False)
        raw = future.result(timeout=Config.OCR_TIMEOUT_SECONDS)
    items = []
    for entry in raw:
        try:
            bbox, text, conf = entry[0], entry[1], entry[2]
            text = str(text).strip()
            if not text:
                continue
            items.append({
                "text": text,
                "conf": float(conf),
                "box": [[float(x[0]), float(x[1])] for x in bbox],
            })
        except Exception:  # noqa: BLE001
            continue
    avg_conf = (sum(i["conf"] for i in items) / len(items)) if items else 0.0
    low_conf_ratio = (sum(1 for i in items if i["conf"] < 0.5) / len(items)) if items else 1.0
    return {
        "items": items,
        "text": "\n".join(i["text"] for i in items),
        "avg_conf": avg_conf,
        "low_conf_ratio": low_conf_ratio,
        "count": len(items),
    }


def _better_result(a: dict, b: dict) -> dict:
    """Pick the OCR pass with the best confidence / coverage."""
    if not a["items"]:
        return b
    if not b["items"]:
        return a
    score_a = a["avg_conf"] * min(a["count"], 25)
    score_b = b["avg_conf"] * min(b["count"], 25)
    return a if score_a >= score_b else b


def _ocr_extract(image_path: str) -> dict:
    """Run EasyOCR with per-word confidence + bounding boxes, under a timeout.

    Uses image preprocessing (grayscale, denoise, CLAHE, upscale) when the raw
    pass is weak, so low-contrast or small screenshots still parse cleanly.
    """
    try:
        reader = _get_reader()
        try:
            result = _ocr_run(reader, image_path)
        except concurrent.futures.TimeoutError:
            result = {"items": [], "text": "", "avg_conf": 0.0, "low_conf_ratio": 1.0, "count": 0}
        if result["count"] < 5 or result["avg_conf"] < 0.6:
            prep = _preprocess_image(image_path)
            if prep:
                try:
                    result = _better_result(result, _ocr_run(reader, prep))
                except concurrent.futures.TimeoutError:
                    pass
                finally:
                    try:
                        os.remove(prep)
                    except OSError:
                        pass
        logger.info(
            "OCR completed: %d words, avg confidence %.0f%%",
            result["count"], result["avg_conf"] * 100,
        )
        return result
    except concurrent.futures.TimeoutError:
        logger.warning("OCR timed out for %s", image_path)
    except Exception:  # noqa: BLE001
        logger.error("OCR failed for %s:\n%s", image_path, traceback.format_exc())
    return {"items": [], "text": "", "avg_conf": 0.0, "low_conf_ratio": 1.0, "count": 0}


# ---- Field extraction -------------------------------------------------------

# Matches anything that looks like a UPI handle (name@bank). The domain part
# may contain stray "@" so malformed handles (e.g. "name@@bank") are still
# extracted and then REJECTED by UPI_ID_RE in _validate_fields.
_UPI_SEARCH_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\-]{0,40}@[A-Za-z0-9@._\-]{2,40}")
_AMOUNT_CUR_RE = re.compile(r"(?:₹|rs\.?|inr|rupees)\s*([\d,]+(?:\.\d{1,2})?)", re.IGNORECASE)
_AMOUNT_BARE_RE = re.compile(r"(?m)^\s*(\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?)\s*$")
_AMOUNT_R_RE = re.compile(r"(?:^|[\s:(])([₹R])\s*([\d,]+(?:\.\d{1,2})?)\b")
_DATE_RE = re.compile(
    r"\b(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b"
    r"|\b(\d{4}[/-]\d{1,2}[/-]\d{1,2})\b"
    r"|\b(\d{1,2}\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+\d{4})\b",
    re.IGNORECASE,
)
_TIME_RE = re.compile(r"\b(\d{1,2}[:.]\d{2}(?::\d{2})?(?:\s*[ap]m)?)\b", re.IGNORECASE)
_TIME_AMPM_RE = re.compile(r"\b(\d{1,2}[:.]\d{2}(?::\d{2})?\s*[ap]m)\b", re.IGNORECASE)
_TXN_RE = re.compile(
    r"\b(?:utr|ref(?:erence)?(?:\s*no\.?)?|txn(?:\s*id)?|transaction(?:\s*id)?|rrn)"
    r"\b\s*[:#]?\s*([A-Za-z0-9][A-Za-z0-9\-]{5,})",
    re.IGNORECASE,
)
_TXN_STANDALONE_RE = re.compile(r"\bT\d{8,}[A-Za-z0-9\-]*\b|\b\d{12,}\b")
_RECIPIENT_INLINE_RE = re.compile(r"(?:paid to|recipient|payee|beneficiary)\s*[:#]?\s*([A-Z][A-Za-z0-9 &.'\-]{2,40})")
_TO_LINE_RE = re.compile(r"^to:?\s+(.+)$", re.IGNORECASE)
_MERCHANT_RE = re.compile(r"(?:merchant|merchant name|pay to)\s*[:#]?\s*([A-Z][A-Za-z0-9 &.'\-]{2,40})")


def _norm_amount(value: str) -> float:
    try:
        return float(value.replace(",", ""))
    except (TypeError, ValueError):
        return 0.0


def _find_amount(text: str, items: list | None = None) -> tuple:
    """Return (normalised_amount, raw_text) or (None, None).

    Tries (in order): currency-prefixed, the largest rendered value (big-font
    heuristic used by every UPI app), a currency-misread prefix (e.g. "R200"
    for the rupee glyph), then a bare number on its own line.
    """
    match = _AMOUNT_CUR_RE.search(text)
    if match:
        return _norm_amount(match.group(1)), match.group(0).strip()

    # Big-font heuristic: UPI apps always render the amount in a large font.
    if items:
        best = None
        for it in items:
            ys = [p[1] for p in it["box"]]
            xs = [p[0] for p in it["box"]]
            height = max(ys) - min(ys)
            if height < 45:
                continue
            m = re.search(r"([\d,]+(?:\.\d{1,2})?)", it["text"])
            if not m:
                continue
            digits = re.sub(r"[^\d.]", "", m.group(1))
            value = _norm_amount(digits)
            if value <= 0 or value > 100000000:
                continue
            if best is None or height > best[0]:
                best = (height, value, it["text"].strip())
        if best:
            return best[1], best[2]

    # Currency glyph misread as "R" immediately before digits.
    match = _AMOUNT_R_RE.search(text)
    if match:
        return _norm_amount(match.group(2)), match.group(0).strip()

    match = _AMOUNT_BARE_RE.search(text)
    if match:
        return _norm_amount(match.group(1)), match.group(1)
    return None, None


def _find_time(text: str) -> str | None:
    ampm = _TIME_AMPM_RE.search(text)
    if ampm:
        return ampm.group(1)
    plain = _TIME_RE.search(text)
    return plain.group(1) if plain else None


def _find_status(text: str) -> str | None:
    """Detect the payment status shown on screen (Success/Completed/etc)."""
    low = text.lower()
    patterns = [
        (r"payment\s+(?:successful|succeeded|completed|success)", "Success"),
        (r"transaction\s+(?:successful|succeeded|completed|success)", "Success"),
        (r"credited\s+successfully", "Credited"),
        (r"money\s+sent", "Money Sent"),
        (r"you\s+paid", "Paid"),
        (r"paid\s+successfully", "Paid"),
        (r"\bcompleted\b", "Completed"),
        (r"\bsuccess(?:ful)?\b", "Success"),
        (r"\bpending\b", "Pending"),
        (r"\bfailed\b", "Failed"),
        (r"\bdebited\b", "Debited"),
        (r"\bcredited\b", "Credited"),
        (r"\breceived\b", "Received"),
        (r"\bpaid\b", "Paid"),
    ]
    for pat, label in patterns:
        if re.search(pat, low):
            return label
    return None


def _find_recipient(text: str) -> str | None:
    inline = _RECIPIENT_INLINE_RE.search(text)
    if inline:
        candidate = inline.group(1).strip()
        if not re.search(r"upi|transaction|amount|reference|date|time|@", candidate, re.IGNORECASE):
            return candidate
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for idx, line in enumerate(lines):
        if re.fullmatch(r"to\b", line, re.IGNORECASE) or line.lower().startswith("paid to"):
            rest = re.sub(r"^(?:paid to|to)\s*[:#]?\s*", "", line, flags=re.IGNORECASE)
            candidate = rest or (lines[idx + 1] if idx + 1 < len(lines) else "")
            candidate = candidate.strip()
            if candidate and not re.search(r"upi|transaction|amount|reference|rs|₹|@", candidate, re.IGNORECASE):
                return candidate
        to_line = _TO_LINE_RE.match(line)
        if to_line:
            candidate = to_line.group(1).strip()
            if candidate and not re.search(r"upi|transaction|amount|reference|rs|₹|@|from", candidate, re.IGNORECASE):
                return candidate
    excluded = {a.lower() for a in KNOWN_APPS}
    for line in lines:
        if not re.fullmatch(r"[A-Z][A-Za-z0-9 &.'\-]{2,40}", line):
            continue
        if sum(c.isalpha() for c in line) < 3:
            continue
        ll = line.lower()
        if ll in excluded:
            continue
        if re.search(
            r"upi|transaction|amount|reference|date|time|@|payment|success|rs\b|inr\b|utr|recipient",
            ll,
        ):
            continue
        return re.sub(r"^to:?\s*", "", line, flags=re.IGNORECASE).strip()
    return None


def _find_merchant(text: str) -> str | None:
    match = _MERCHANT_RE.search(text)
    if match:
        return match.group(1).strip()
    for line in text.splitlines():
        low = line.lower().strip()
        if low.startswith("merchant") and len(line.strip()) > 10:
            return re.sub(r"^merchant\s*[:#]?\s*", "", line, flags=re.IGNORECASE).strip()
    return None


def _find_bank(text: str) -> str | None:
    low = text.lower()
    best = None
    for bank in BANK_NAMES:
        if bank in low and (best is None or len(bank) > len(best)):
            best = bank
    return best.title() if best else None


def _find_app(text: str) -> str | None:
    low = text.lower()
    for app in KNOWN_APPS:
        if app in low:
            return app.title()
    return None


def _extract_fields(text: str, items: list | None = None) -> dict:
    """Pull structured transaction fields out of OCR text."""
    low = text.lower()
    status = _find_status(text)
    fields = {
        "upi_id": _UPI_SEARCH_RE.search(text),
        "amount": _find_amount(text, items),
        "date": _DATE_RE.search(text),
        "time": _find_time(text),
        "txn": _TXN_RE.search(text) or _TXN_STANDALONE_RE.search(text),
        "recipient": _find_recipient(text),
        "merchant": _find_merchant(text),
        "bank": _find_bank(text),
        "app": _find_app(text),
    }
    return {
        "upi_id": fields["upi_id"].group(0) if fields["upi_id"] else None,
        "amount": fields["amount"][0] if fields["amount"][0] is not None else None,
        "amount_raw": fields["amount"][1] if fields["amount"][1] else None,
        "date": fields["date"].group(0) if fields["date"] else None,
        "time": fields["time"],
        "txn": (
            fields["txn"].group(1)
            if fields["txn"] and fields["txn"].lastindex
            else (fields["txn"].group(0) if fields["txn"] else None)
        ),
        "recipient": fields["recipient"],
        "merchant": fields["merchant"],
        "bank": fields["bank"],
        "app": fields["app"],
        "payment_status": status,
        "success": status not in (None, "Failed", "Pending"),
        "payment_like": bool(re.search(r"|".join(re.escape(k) for k in PAYMENT_KEYWORDS), low)),
    }


# ---- Image forensics --------------------------------------------------------

def _jpeg_blockiness(gray) -> float:
    """Approximate 8x8-DCT blockiness ratio (elevated on re-compressed JPEGs)."""
    try:
        import numpy as np

        g = gray.astype(np.float32)
        h, w = g.shape
        if w < 16 or h < 16:
            return 1.0
        vb = np.abs(np.diff(g, axis=1))
        bcols = np.arange(7, w - 1, 8)
        allcols = np.arange(w - 1)
        nbcols = np.setdiff1d(allcols, bcols)
        vb_boundary = float(vb[:, bcols].mean()) if len(bcols) else 0.0
        vb_non = float(vb[:, nbcols].mean()) if len(nbcols) else 0.0
        hb = np.abs(np.diff(g, axis=0))
        brows = np.arange(7, h - 1, 8)
        allrows = np.arange(h - 1)
        nbro = np.setdiff1d(allrows, brows)
        hb_boundary = float(hb[brows, :].mean()) if len(brows) else 0.0
        hb_non = float(hb[nbro, :].mean()) if len(nbro) else 0.0
        return float((vb_boundary + hb_boundary + 1e-6) / (vb_non + hb_non + 1e-6))
    except Exception:  # noqa: BLE001
        return 1.0


def _image_metrics(gray) -> dict:
    """Return blur, flatness, noise and blockiness metrics for a grayscale image."""
    try:
        import cv2

        lap = cv2.Laplacian(gray, cv2.CV_64F)
        blur_variance = float(lap.var())
        flatness = float(gray.std())
        noise = float((gray.astype("float32") - cv2.medianBlur(gray, 5).astype("float32")).std())
        blockiness = _jpeg_blockiness(gray)
    except Exception:  # noqa: BLE001
        logger.error("Image metrics failed:\n%s", traceback.format_exc())
        return {"blur_variance": 0.0, "flatness": 0.0, "noise": 0.0, "blockiness": 1.0}
    logger.info(
        "Image metrics: blur=%.0f flatness=%.1f noise=%.3f blockiness=%.2f",
        blur_variance, flatness, noise, blockiness,
    )
    return {
        "blur_variance": round(blur_variance, 1),
        "flatness": round(flatness, 2),
        "noise": round(noise, 3),
        "blockiness": round(blockiness, 3),
    }


def _exif_analysis(image) -> dict:
    """Inspect EXIF for editing-tool or camera markers."""
    from PIL import ExifTags

    exif = image.getexif()
    has_metadata = bool(exif)
    software = make = model = None
    if has_metadata:
        for tag_id, value in exif.items():
            name = ExifTags.TAGS.get(tag_id, str(tag_id))
            if name == "Software" and value:
                software = str(value).lower()
            elif name == "Make" and value:
                make = str(value)
            elif name == "Model" and value:
                model = str(value)
    editing_tool = bool(software) and any(tool in software for tool in EDIT_TOOL_NAMES)
    camera = bool(make or model)
    logger.info(
        "Metadata checked: exif=%s software=%r camera=%s",
        has_metadata, software, camera,
    )
    return {
        "has_metadata": has_metadata,
        "software": software,
        "make": make,
        "model": model,
        "editing_tool": editing_tool,
        "camera": camera,
    }


def _text_overlap(items: list) -> dict:
    """Detect overlapping and duplicated OCR text regions (editing hints)."""
    overlaps = []
    dups = []
    seen = {}
    for i in range(len(items)):
        box_i = items[i]["box"]
        for j in range(i + 1, len(items)):
            box_j = items[j]["box"]
            try:
                xi = [p[0] for p in box_i]; yi = [p[1] for p in box_i]
                xj = [p[0] for p in box_j]; yj = [p[1] for p in box_j]
                inter_w = max(0, min(max(xi), max(xj)) - max(min(xi), min(xj)))
                inter_h = max(0, min(max(yi), max(yj)) - max(min(yi), min(yj)))
                area_i = max(1, (max(xi) - min(xi)) * (max(yi) - min(yi)))
                area_j = max(1, (max(xj) - min(xj)) * (max(yj) - min(yj)))
                ratio = (inter_w * inter_h) / min(area_i, area_j)
            except Exception:  # noqa: BLE001
                continue
            if ratio > 0.3 and len(overlaps) < 5:
                overlaps.append((items[i]["text"], items[j]["text"]))
        key = items[i]["text"].strip().lower()
        # Short duplicated strings (e.g. repeated button labels) are legitimate
        # in UI, so only flag duplicates that carry enough content to matter.
        if len(key) >= 4 and any(ch.isalpha() for ch in key):
            if key not in seen:
                seen[key] = items[i]["box"]
            elif len(dups) < 5 and sum(1 for _ in key) <= 40:
                dups.append(items[i]["text"])
    return {
        "overlaps": overlaps,
        "duplicates": list(dict.fromkeys(dups)),
    }


# ---- Field-consistency validation ------------------------------------------

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}


def _impossible_date(value: str) -> bool:
    """True when a detected date cannot exist (e.g. '44 Aug 2026')."""
    if not value:
        return False
    m = re.search(r"(\d{1,2})\s*/\s*(\d{1,2})\s*/\s*(\d{2,4})", value)
    if not m:
        m = re.search(r"(\d{4})\s*/\s*(\d{1,2})\s*/\s*(\d{1,2})", value)
        if m:
            year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
        else:
            m = re.search(r"(\d{1,2})\s+([a-z]+)[a-z]*\s+(\d{4})", value.lower())
            if not m:
                return False
            day, month_name, year = int(m.group(1)), m.group(2), int(m.group(3))
            month = _MONTHS.get(month_name[:3], 0)
            if month == 0:
                return True
    else:
        day, month, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if month > 12:
            day, month = month, day
    if month < 1 or month > 12 or day < 1 or day > 31 or year < 1970 or year > 2100:
        return True
    return False


def _amount_conflicts(text: str) -> list:
    """Every distinct currency-prefixed amount visible on screen (sanity check).

    Only explicitly currency-tagged values are considered so that transaction
    IDs, dates and times never create phantom conflicts.
    """
    values = set()
    for m in _AMOUNT_CUR_RE.finditer(text):
        v = _norm_amount(m.group(1))
        if 0 < v <= 100000000:
            values.add(round(v, 2))
    for m in _AMOUNT_R_RE.finditer(text):
        v = _norm_amount(m.group(2))
        if 0 < v <= 100000000:
            values.add(round(v, 2))
    return sorted(values)


def _recipient_label_duplicates(text: str) -> list:
    """A recipient shown in two separate 'to / paid to' label rows.

    A genuine UPI receipt has exactly one recipient label; two distinct label
    rows carrying the same name indicate the field was duplicated/edited.
    """
    labels = []
    for line in text.splitlines():
        m = re.match(
            r"^(?:to|paid to|recipient|payee|beneficiary)\s*[:#]?\s*(.+)$",
            line.strip(), re.IGNORECASE,
        )
        if not m:
            continue
        name = m.group(1).strip()
        if name and re.search(r"[A-Za-z]{2,}", name):
            labels.append(name)
    counts = {}
    for name in labels:
        key = re.sub(r"[^a-z]", "", name.lower())
        if len(key) < 5:
            continue
        counts.setdefault(key, []).append(name)
    return [names[0] for names in counts.values() if len(names) > 1]


def _validate_fields(fields: dict, text: str, items: list) -> list:
    """Return a list of (signal, evidence, note) tuples for inconsistent fields."""
    issues = []

    if fields.get("date") and _impossible_date(str(fields["date"])):
        issues.append((
            "impossible_date", fields["date"],
            f"The date shown ('{fields['date']}') is not a valid calendar date",
        ))

    amounts = _amount_conflicts(text)
    if len(amounts) > 1:
        issues.append((
            "conflicting_amounts", " / ".join(str(a) for a in amounts),
            f"Multiple different amounts appear in the screenshot: {' / '.join(str(a) for a in amounts)}",
        ))
    amt = fields.get("amount")
    if amt is not None and (amt <= 0 or amt > 100000000):
        issues.append(("amount_unrealistic", str(amt), "The detected amount is not a realistic payment value"))

    upi = fields.get("upi_id")
    if upi and not UPI_ID_RE.match(str(upi)):
        issues.append(("invalid_upi", upi, f"The UPI ID ('{upi}') does not match a valid UPI format"))

    low = text.lower()
    has_success = bool(re.search(r"\b(success|successful|completed|credited|debited|paid|sent|received)\b", low))
    has_failure = bool(re.search(r"\b(failed|pending|declined|unsuccessful)\b", low))
    if has_success and has_failure:
        issues.append(("conflicting_status", "success+failure wording",
                       "The screenshot contains both success and failure wording for the same payment"))

    txn = fields.get("txn")
    if txn and len(str(txn)) < 12 and re.search(r"\d", str(txn)):
        issues.append(("txid_too_short", str(txn),
                       f"The transaction ID ('{txn}') is unusually short for a real payment reference"))

    for name in _recipient_label_duplicates(text):
        issues.append(("duplicate_recipient", name,
                       f"The recipient '{name}' appears under two separate recipient labels"))
    return issues


# ---- Localised region forensics --------------------------------------------

def _region_stats(gray, box: list) -> dict | None:
    """Local noise floor for one OCR bounding box (dimensions + bounding box)."""
    import cv2

    try:
        xs = [p[0] for p in box]; ys = [p[1] for p in box]
        x0, x1 = max(0, int(min(xs))), int(max(xs))
        y0, y1 = max(0, int(min(ys))), int(max(ys))
        h, w = gray.shape
        x1, y1 = min(w, x1), min(h, y1)
        if x1 - x0 < 8 or y1 - y0 < 8:
            return None
        region = gray[y0:y1, x0:x1]
        med = cv2.medianBlur(region, 5)
        noise = float((region.astype("float32") - med.astype("float32")).std())
        return {"noise": noise, "box": (x0, y0, x1, y1)}
    except Exception:  # noqa: BLE001
        return None


def _region_ela(gray, box: list, quality: int = 88) -> float | None:
    """Local Error Level Analysis for a single region (double re-encode)."""
    import tempfile
    import uuid

    import cv2
    import numpy as np

    try:
        st = _region_stats(gray, box)
        if st is None:
            return None
        x0, y0, x1, y1 = st["box"]
        region = gray[y0:y1, x0:x1]
        region = cv2.resize(region, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
        path = os.path.join(tempfile.gettempdir(), f"trustlens_rela_{uuid.uuid4().hex}.jpg")
        ok, buf = cv2.imencode(".jpg", region, [cv2.IMWRITE_JPEG_QUALITY, quality])
        if not ok:
            return None
        buf.tofile(path)
        a = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
        ok, buf = cv2.imencode(".jpg", a, [cv2.IMWRITE_JPEG_QUALITY, quality])
        if not ok:
            _remove_file(path)
            return None
        buf.tofile(path)
        b = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
        _remove_file(path)
        if a is None or b is None or a.size == 0:
            return None
        return float(np.abs(a.astype(np.float32) - b.astype(np.float32)).mean())
    except Exception:  # noqa: BLE001
        return None


def _remove_file(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


_FIELD_REGION_LABELS = {
    "amount": "transaction amount",
    "recipient": "recipient",
    "txn": "transaction ID",
    "payment_status": "payment status",
    "date": "date/time",
    "time": "date/time",
    "upi_id": "UPI ID",
}


def _localized_region_anomalies(gray, ocr_items: list, fields: dict) -> list:
    """Compare each OCR text region against the image's other text regions.

    A region that was independently re-encoded (edited / pasted / re-rendered)
    usually shows a distinctly different local noise floor and Error Level than
    the rest of the screenshot. Returns human-readable notes naming the affected
    field where possible. Does NOT fire on uniform / low-signal images.
    """
    if not ocr_items or len(ocr_items) < 5:
        return []
    stats = []
    for it in ocr_items:
        st = _region_stats(gray, it["box"])
        if st is None:
            continue
        st["text"] = it["text"]
        stats.append(st)
    if len(stats) < 5:
        return []
    noises = sorted(s["noise"] for s in stats)
    med_noise = noises[len(noises) // 2]
    if med_noise <= 0:
        return []

    ela_list = []
    for s in stats:
        e = _region_ela(gray, s["box"])
        if e is not None:
            s["ela"] = e
            ela_list.append(e)
    med_ela = sorted(ela_list)[len(ela_list) // 2] if ela_list else None

    anomalous = []
    for s in stats:
        noise_ratio = s["noise"] / med_noise
        ela_ratio = (s["ela"] / med_ela) if (med_ela and s.get("ela")) else 1.0
        # Both the noise floor AND the re-compression footprint must deviate
        # strongly, which keeps genuine large-font / bold regions from firing.
        if noise_ratio > 1.6 and (ela_ratio > 2.2 or s["noise"] > 8.0):
            anomalous.append(s["text"])

    if not anomalous:
        return []
    important = {k: v for k, v in fields.items() if v not in (None, "", False)}
    attributed = []
    for text in anomalous:
        key_text = re.sub(r"[^a-z0-9]", "", text.lower())
        if not key_text:
            continue
        label = None
        for field_key, field_label in _FIELD_REGION_LABELS.items():
            val = important.get(field_key)
            if val is None:
                continue
            if isinstance(val, float) and val == int(val):
                val = int(val)
            field_key_text = re.sub(r"[^a-z0-9]", "", str(val).lower())
            if len(field_key_text) >= 3 and field_key_text in key_text:
                label = field_label
                break
        attributed.append(label or "an area of the screenshot")
    return list(dict.fromkeys(attributed))[:3]


# ---- Risk evidence board ----------------------------------------------------

# signal -> (risk points, severity). Points are the contribution to the RISK
# score (0-100, higher = more suspicious). Missing evidence never adds points.
#
# Calibration note: UI screenshots are text-heavy with large solid areas, so
# pixel-level tamper detectors (ELA / copy-move) are deliberately conservative
# - JPEG compression, resizing and normal UI repetition are NOT fraud evidence.
# The most reliable signals for payment screenshots are structural: EXIF edit
# tools, text/recipient duplication, impossible dates and QR <-> screen
# mismatches.
_SIGNAL_DEFS = {
    "transaction_not_verified": (10, "info"),
    "exif_edit_tool": (35, "danger"),
    "camera_capture": (15, "warning"),
    "ela_anomaly": (30, "danger"),
    "ela_anomaly_moderate": (12, "warning"),
    "copy_move_strong": (30, "danger"),
    "copy_move_moderate": (8, "warning"),
    "text_anomaly": (20, "danger"),
    "duplicate_recipient": (20, "warning"),
    "low_conf_text": (10, "warning"),
    "impossible_date": (20, "warning"),
    "conflicting_amounts": (25, "danger"),
    "invalid_upi": (12, "warning"),
    "txid_too_short": (8, "warning"),
    "conflicting_status": (20, "warning"),
    "qr_screen_mismatch": (25, "danger"),
    "qr_not_upi": (8, "warning"),
    "qr_invalid": (12, "warning"),
    "not_payment_like": (20, "warning"),
    "blank_image": (35, "danger"),
    "noise_glare": (30, "danger"),
    "blurry": (10, "warning"),
    "noisy": (8, "warning"),
    "very_low_resolution": (8, "warning"),
    "amount_unrealistic": (10, "warning"),
    "unverifiable": (40, "warning"),
}

# region anomalies are capped so a noisy edit cannot dominate the score alone.
_REGION_ANOMALY_CAP = 2


class RiskBoard:
    """Accumulates named evidence signals and derives risk / reasons.

    Each signal contributes once (no double counting). Reasons carry a severity
    for the UI and the risk points that produced them.
    """

    def __init__(self):
        self._evidence = []
        self._notes = []

    def add(self, signal: str, evidence: str = "", confidence: int = 90, note: str | None = None):
        if signal not in _SIGNAL_DEFS:
            return self
        # Single-fire: a signal contributes its risk points at most once, no
        # matter how many detectors observe it (no double-counting).
        if any(e["signal"] == signal for e in self._evidence):
            return self
        points, severity = _SIGNAL_DEFS[signal]
        self._evidence.append({
            "signal": signal,
            "points": points,
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence or note or signal,
            "note": note or evidence or signal,
        })
        return self

    def note(self, text: str, severity: str = "info"):
        self._notes.append({"severity": severity, "text": text, "points": 0})
        return self

    @property
    def risk(self) -> int:
        return min(100, sum(e["points"] for e in self._evidence))

    def reasons(self) -> list:
        items = [{"severity": n["severity"], "text": n["text"], "points": 0} for n in self._notes]
        items += [
            {"severity": e["severity"], "text": e["note"], "points": e["points"]}
            for e in self._evidence
        ]
        return items

    def evidence_dict(self) -> list:
        return list(self._evidence)


# ---- QR analysis ------------------------------------------------------------

def _qr_analysis(image_path: str) -> dict:
    """Decode any QR in the image and validate a UPI payload."""
    try:
        payloads = decode_qr(image_path)
    except Exception:  # noqa: BLE001
        logger.info("QR detection: no QR code found")
        return {"detected": False}
    raw = _clean_payload(payloads[0])
    low = raw.lower()
    info = {"detected": True, "raw": raw}
    params = {}
    if low.startswith("upi://pay"):
        params = _parse_upi(raw)
    elif UPI_ID_RE.match(raw.strip()):
        params = {"pa": raw.strip()}
    if params:
        pa = params.get("pa", "")
        info.update({
            "upi": True,
            "pa": pa or None,
            "pn": params.get("pn") or None,
            "am": params.get("am") or None,
            "tn": params.get("tn") or None,
            "cu": (params.get("cu") or "").upper() or None,
            "pa_valid": bool(UPI_ID_RE.match(pa)),
        })
    else:
        info.update({"upi": False, "looks_like": raw[:80]})
    logger.info(
        "QR detected: upi=%s pa=%s valid=%s", info.get("upi"), info.get("pa"), info.get("pa_valid"),
    )
    return info


# ---- Main entry point -------------------------------------------------------

def _compute_confidence(ocr: dict, fields: dict, qr_conf: int | None,
                        blurry: bool, noisy: bool, flat: bool) -> tuple:
    """Compute (ocr, forensics, overall) analysis confidence, each 0-100.

    Confidence expresses how much the analysis could actually determine, so it
    is deliberately independent from risk and capped below 100 - a clean OCR
    pass never makes the analysis "certain".
    """
    if ocr["count"] == 0:
        ocr_score = 0.0
    else:
        quality = 0.45 * ocr["avg_conf"] + 0.25 * (1 - min(1.0, ocr["low_conf_ratio"]))
        core = [fields.get(k) for k in ("amount", "txn", "payment_status", "upi_id", "recipient")]
        full = [fields.get(k) for k, _ in FIELD_LABELS]
        cov_core = sum(1 for v in core if v not in (None, "", False)) / max(1, len(core))
        cov_full = sum(1 for v in full if v not in (None, "", False)) / max(1, len(full))
        ocr_score = min(0.97, quality + 0.30 * cov_core + 0.10 * cov_full)

    forensics_score = 0.95
    if blurry:
        forensics_score -= 0.10
    if noisy:
        forensics_score -= 0.10
    if flat:
        forensics_score = 0.15
    forensics_score = max(0.15, min(0.95, forensics_score))

    if qr_conf is not None:
        overall = 0.40 * ocr_score + 0.40 * forensics_score + 0.20 * (qr_conf / 100.0)
    else:
        overall = 0.55 * ocr_score + 0.45 * forensics_score
    overall = min(0.95, overall)
    return int(ocr_score * 100), int(forensics_score * 100), int(overall * 100)


def scan_payment_screenshot(image_path: str) -> dict:
    """Analyse a payment screenshot and return an evidence-driven result.

    Risk (0-100, higher = more suspicious) is accumulated ONLY from detected
    signals; the absence of suspicious evidence never makes an image "genuine".
    The trust score, status, verdict and fraud probability are derived from it,
    and a separate confidence value reports how much the analysis could actually
    determine. The verdict is evidence-based language and always carries the
    caveat that a screenshot cannot independently prove a real transaction.
    """
    start = time.perf_counter()
    board = RiskBoard()
    flags = {}

    try:
        from PIL import Image
        import numpy as np

        with Image.open(image_path) as img:
            exif = _exif_analysis(img)
            image = img.convert("RGB")
            width, height = image.size
        gray = np.array(image.convert("L"))
    except Exception:  # noqa: BLE001
        logger.error("Could not read image %s:\n%s", image_path, traceback.format_exc())
        return {
            "score": 0, "status": "dangerous", "fraud_probability": 100,
            "result_type": "high", "risk": 100,
            "verdict": "Unreadable Image",
            "reasons": [{"severity": "danger", "text": "Unable to read the uploaded file - it may be corrupted or not a valid image.", "points": 100}],
            "evidence": [],
            "verification": {
                "verified": False,
                "reason": "The file could not be read, so no authenticity analysis was possible.",
            },
            "flags": {"readable": False},
            "extracted_text": "", "qr": {"detected": False}, "details": {},
            "confidence": {"overall": 0, "ocr": 0, "image_authenticity": 0},
            "processing_time_ms": int((time.perf_counter() - start) * 1000),
        }

    # ---- 1. Metadata / EXIF -----------------------------------------------
    flags["edited_metadata"] = exif["editing_tool"]
    flags["camera_capture"] = exif["camera"]
    flags["has_metadata"] = exif["has_metadata"]

    if exif["editing_tool"]:
        board.add("exif_edit_tool", evidence=str(exif["software"]),
                  note=f"Image metadata shows it was edited with {exif['software']} - not a native payment app screenshot")
    elif exif["camera"]:
        board.add("camera_capture", evidence=" / ".join(x for x in (exif["make"], exif["model"]) if x),
                  note="Captured by a camera (photo of a screen) rather than a native screenshot")
    else:
        board.note("No camera or editing metadata - expected for phone screenshots", "info")

    # ---- 2. Global image quality ------------------------------------------
    metrics = _image_metrics(gray)
    flags.update(metrics)

    blurry = metrics["blur_variance"] < 60
    flat = metrics["flatness"] < 15
    noisy = metrics["noise"] > 30
    glare = metrics["blur_variance"] > 6000
    blocky = metrics["blockiness"] > 2.0
    flags["blurry"] = blurry
    flags["blank_image"] = flat
    flags["noisy"] = noisy
    flags["noise_glare"] = glare
    flags["compression_artifacts"] = blocky

    if blurry:
        board.add("blurry", note="Image is too blurry to verify authenticity")
    if flat:
        board.add("blank_image", note="Image appears blank or uniformly rendered - it cannot be a real payment screenshot")
    if noisy:
        board.add("noisy", note="Excessive image noise detected")
    if glare:
        board.add("noise_glare", note="Image appears to be random noise or glare rather than a real screenshot")
    if blocky:
        # JPEG compression is NOT fraud evidence on its own.
        board.note("Compression artifacts present - image may have been re-encoded or re-saved", "warning")

    if width and height:
        if width < 400 or height < 400:
            board.add("very_low_resolution", note="Image resolution is very low - difficult to verify authenticity")
        else:
            board.note(f"Resolution looks normal ({width} x {height})", "success")

    # ---- 3. QR analysis ----------------------------------------------------
    qr = _qr_analysis(image_path)
    flags["qr_detected"] = qr["detected"]
    qr_conf = None
    if qr["detected"] and qr.get("upi"):
        flags["qr_upi_id"] = qr.get("pa") or "Invalid"
        flags["qr_amount"] = qr.get("am")
        flags["qr_payee"] = qr.get("pn")
        if qr.get("pa_valid"):
            board.note("QR encodes a valid UPI payment request", "success")
            qr_conf = 90
        else:
            board.add("qr_invalid", evidence=str(qr.get("pa") or ""),
                      note="QR encodes a UPI payment but the UPI ID format appears invalid")
            qr_conf = 60
    elif qr["detected"]:
        flags["qr_upi_id"] = "Not a UPI QR"
        board.add("qr_not_upi", evidence=str(qr.get("looks_like") or "")[:60],
                  note="A QR code is present but it does not encode a UPI payment")
        qr_conf = 55
    else:
        board.note("No QR code visible (normal for bank / app payment confirmation screens)", "info")

    # ---- 4. OCR ------------------------------------------------------------
    ocr = _ocr_extract(image_path)
    text = ocr["text"]
    fields = _extract_fields(text, ocr["items"]) if text else {}
    flags["ocr_words"] = ocr["count"]
    flags["ocr_confidence"] = f"{int(ocr['avg_conf'] * 100)}%"

    if ocr["count"] == 0:
        board.note("No readable text could be extracted from the image", "info")
    else:
        if ocr["avg_conf"] < 0.5:
            board.add("low_conf_text", confidence=45,
                      note=f"OCR confidence is low ({int(ocr['avg_conf'] * 100)}%) - text may be unreadable or re-rendered")
        else:
            board.note(f"OCR quality good ({int(ocr['avg_conf'] * 100)}% average confidence)", "success")
        if ocr["low_conf_ratio"] > 0.5:
            board.add("low_conf_text", confidence=50,
                      note="Multiple low-confidence text regions - text may be rendered rather than native")
        if text and not fields.get("payment_like"):
            board.add("not_payment_like", note="The extracted text does not resemble a payment confirmation")

    # ---- 5. Structured field checks ---------------------------------------
    if fields:
        upi_id = fields.get("upi_id")
        amount = fields.get("amount")
        date = fields.get("date")
        time_f = fields.get("time")
        txn = fields.get("txn")
        recipient = fields.get("recipient")

        flags["upi_id"] = upi_id
        flags["amount"] = fields.get("amount_raw") or amount
        flags["date"] = date
        flags["time"] = time_f
        flags["transaction_id"] = txn
        flags["recipient"] = recipient
        flags["bank"] = fields.get("bank")
        flags["app"] = fields.get("app")
        flags["merchant"] = fields.get("merchant")
        flags["payment_status"] = fields.get("payment_status")
        flags["success_message"] = fields.get("success")

        # Detected fields are positive notes (they raise confidence, not risk).
        if upi_id:
            board.note(f"UPI ID detected: {upi_id}", "success")
        if amount is not None:
            board.note(f"Payment amount found: {fields.get('amount_raw') or amount}", "success")
        if date:
            board.note(f"Date found: {date}", "success")
        if time_f:
            board.note(f"Time found: {time_f}", "success")
        if txn:
            board.note(f"Transaction ID found: {txn}", "success")
        if recipient:
            board.note(f"Recipient detected: {recipient}", "success")
        if fields.get("bank"):
            board.note(f"Bank detected: {fields['bank']}", "success")
        if fields.get("payment_status"):
            board.note(f"Payment status: {fields['payment_status']}", "success")
            if fields["payment_status"] in ("Failed", "Pending"):
                board.add("conflicting_status",
                          note=f"Payment status is '{fields['payment_status']}' - this does not confirm a completed payment")
        elif fields.get("success"):
            board.note("Success / payment-complete wording found", "success")
        if fields.get("app"):
            board.note(f"App identified: {fields.get('app')}", "success")
        if fields.get("merchant"):
            board.note(f"Merchant detected: {fields.get('merchant')}", "success")

        # Internal consistency of the extracted values.
        for signal, evidence, note in _validate_fields(fields, text, ocr["items"]):
            board.add(signal, evidence=evidence, note=note)
    else:
        board.note("No structured payment fields could be extracted", "info")

    # ---- 6. Text overlap / duplicate regions -------------------------------
    layout = {"overlaps": [], "duplicates": []}
    if ocr["items"]:
        layout = _text_overlap(ocr["items"])
        flags["text_overlap"] = bool(layout["overlaps"])
        flags["duplicate_regions"] = bool(layout["duplicates"])
        if layout["overlaps"]:
            board.add("text_anomaly", note="Overlapping text regions detected - possible editing artifact")
        elif layout["duplicates"]:
            board.add("text_anomaly", note="Duplicate text regions detected - possible copied/pasted elements")
    text_anomaly = bool(layout["overlaps"]) or bool(layout["duplicates"])
    flags["text_anomaly"] = text_anomaly

    # ---- 7. QR <-> OCR consistency ------------------------------------------
    if qr.get("detected") and qr.get("upi") and fields:
        if fields.get("upi_id") and qr.get("pa"):
            if fields["upi_id"].lower() != qr["pa"].lower():
                board.add("qr_screen_mismatch",
                          evidence=f"screen={fields['upi_id']} qr={qr['pa']}",
                          note="UPI ID shown on screen does not match the UPI ID encoded in the QR")
            else:
                board.note("UPI ID on screen matches the QR", "success")
        if fields.get("amount") is not None and qr.get("am"):
            qr_amt = _norm_amount(qr["am"])
            if abs(fields["amount"] - qr_amt) > 0.01:
                board.add("qr_screen_mismatch",
                          evidence=f"screen={fields['amount']} qr={qr_amt}",
                          note="Amount shown on screen does not match the amount encoded in the QR")
            else:
                board.note("Amount on screen matches the QR", "success")

    # ---- 8. Image forensics (ELA / copy-move / localized regions) -----------
    rgb = np.array(image)
    ela = ela_analysis(rgb)
    cm = copy_move_analysis(rgb)
    flags["ela_anomaly"] = ela["flag"]
    flags["ela_ratio"] = ela["ratio"]
    flags["copy_move"] = cm["flag"]
    flags["copy_move_blocks"] = cm["blocks"]
    flags["copy_move_offset_max"] = cm["offset_max"]

    if ela["ratio"] > 0.12:
        board.add("ela_anomaly", evidence=f"ratio={ela['ratio']:.3f}",
                  note="Error Level Analysis found heavily re-encoded regions - possible local editing or compositing")
    elif ela["ratio"] > 0.06:
        board.add("ela_anomaly_moderate", evidence=f"ratio={ela['ratio']:.3f}",
                  note="Error Level Analysis shows uneven re-compression - possible re-encoded region")
    # Copy-move is deliberately a safety net for GROSS full-region cloning.
    # Normal UI screenshots contain repeated rows/text that produce many
    # near-identical block pairs along horizontal offsets, so a moderate or
    # even high pair count alone is NOT evidence of tampering. Only extreme
    # counts (entire regions duplicated) fire here.
    if cm["offset_max"] >= 800:
        board.add("copy_move_strong", evidence=f"offset_blocks={cm['offset_max']}",
                  note="Copy-move analysis found an extreme number of blocks cloned at one offset - large pasted region")
    elif cm["offset_max"] >= 500:
        board.add("copy_move_moderate", evidence=f"offset_blocks={cm['offset_max']}",
                  note="Copy-move analysis found a very large duplicated region - possible pasted content")

    region_labels = []
    if ocr["items"]:
        # Local region ELA/noise is a DIAGNOSTIC only. It is not reliable
        # enough to raise risk (it fires on blank areas of legit low-text
        # screenshots), so it is reported in the flags but never on the board.
        region_labels = _localized_region_anomalies(gray, ocr["items"], fields)
        flags["local_region_anomalies"] = region_labels

    # ---- 9. Risk, confidence, verdict ---------------------------------------
    # Baseline risk: the transaction itself cannot be independently verified
    # from a screenshot, so even a perfect-looking image is not risk-free.
    board.add("transaction_not_verified",
              note="The transaction itself cannot be independently verified from the screenshot alone")

    ocr_conf, forensics_conf, overall_conf = _compute_confidence(
        ocr, fields, qr_conf, blurry, noisy, flat,
    )
    flags["ocr_confidence_score"] = ocr_conf
    flags["forensics_confidence"] = forensics_conf
    flags["analysis_confidence"] = overall_conf

    unverifiable = ocr["count"] == 0 and not qr.get("detected") and not flat and not glare
    if unverifiable:
        board.add("unverifiable", confidence=30,
                  note="Insufficient readable evidence - authenticity could not be verified")

    risk = board.risk
    score = max(0, min(100, 100 - risk))
    fraud_probability = risk
    processing_ms = int((time.perf_counter() - start) * 1000)

    if flat:
        result_type, status, verdict = "high", "dangerous", "Blank / Unreadable Image"
    elif glare:
        result_type, status, verdict = "high", "dangerous", "Not a Recognizable Payment Screenshot"
    elif unverifiable:
        result_type, status, verdict = "unverifiable", "warning", "Authenticity Could Not Be Conclusively Verified"
    elif risk >= 60:
        result_type, status, verdict = "high", "dangerous", "High Risk - Strong Manipulation Evidence"
    elif risk >= 30:
        result_type, status, verdict = "suspicious", "warning", "Suspicious - Possible Manipulation"
    else:
        result_type, status, verdict = "low", "safe", "Low Risk - No Obvious Manipulation Detected"

    board.note(f"Risk score: {risk}/100 - {verdict}", "info")
    board.note(f"Analysis confidence: {overall_conf}%", "info")

    field_summary = [
        {
            "name": label,
            "detected": fields.get(key) not in (None, "", False),
            "value": str(fields.get(key)) if fields.get(key) not in (None, "", False) else "",
        }
        for key, label in FIELD_LABELS
    ]

    logger.info(
        "Payment scan complete: risk=%d score=%d status=%s confidence=%d%% time=%dms",
        risk, score, status, overall_conf, processing_ms,
    )

    return {
        "score": score,
        "status": status,
        "verdict": verdict,
        "result_type": result_type,
        "risk": risk,
        "risk_level": result_type,
        "fraud_probability": fraud_probability,
        "reasons": board.reasons(),
        "evidence": board.evidence_dict(),
        "verification": {
            "verified": False,
            "reason": "A screenshot cannot independently confirm that a real-world transaction occurred. Authenticity cannot be conclusively proven from image pixels alone.",
        },
        "flags": flags,
        "extracted_text": text[:3000],
        "qr": qr,
        "details": fields,
        "field_summary": field_summary,
        "confidence": {
            "overall": overall_conf,
            "ocr": ocr_conf,
            "image_authenticity": forensics_conf,
        },
        "processing_time_ms": processing_ms,
    }


def persist_scan(app, user_id, image_path, payload: dict):
    """Persist a payment scan. Never raises."""
    from models import db
    from models.scan import PaymentScan

    try:
        flags = payload.get("flags", {})
        scan = PaymentScan(
            user_id=user_id,
            screenshot_path=image_path,
            fraud_probability=payload["fraud_probability"],
            trust_score=payload["score"],
            status=payload["status"],
            edited_metadata=flags.get("edited_metadata", False),
            flags=flags,
            reasons=payload.get("reasons"),
        )
        db.session.add(scan)
        db.session.commit()
    except Exception:  # noqa: BLE001
        db.session.rollback()
        app.logger.exception("Failed to persist payment scan")
