"""
WhatsApp scam detector.

User uploads a screenshot; EasyOCR extracts the text; a heuristic engine then
classifies the message into known scam categories:
  - Lottery scam
  - OTP scam
  - KYC scam
  - Courier scam
  - Job scam
  - Investment scam

EasyOCR (PyTorch) is heavy, so it is loaded lazily. If it is unavailable or
times out, we fall back to a lightweight PIL-based OCR attempt (no-op text)
so the pipeline never blocks the request.
"""

import concurrent.futures
import re
import time

from config import Config
from services.logger import get_logger
from services.scoring import ScoreBuilder, URGENCY_WORDS, PAYMENT_REQUEST_PHRASES, classify

logger = get_logger(__name__)

_reader = None
_reader_lock = None  # assigned lazily to avoid import-time threading surprises

# Keyword sets per scam category. A message is classified when it matches a
# category's "strong" terms or a combination of its soft terms.
SCAM_PATTERNS = {
    "Lottery Scam": {
        "strong": ["you won", "you have won", "lottery", "winner", "prize money", "claim your prize"],
        "soft": ["congratulations", "lucky", "draw", "jackpot"],
    },
    "OTP Scam": {
        "strong": ["otp", "one time password", "share your otp", "send me the otp", "verification code"],
        "soft": ["code received", "confirm code", "bank otp"],
    },
    "KYC Scam": {
        "strong": ["kyc", "update your kyc", "kyc expired", "block your account"],
        "soft": ["aadhaar", "pan card", "bank details", "verify your kyc", "link expired"],
    },
    "Courier Scam": {
        "strong": ["courier", "parcel", "package held", "customs charges", "delivery fee"],
        "soft": ["tracking", "shipment", "dhl", "fedex", "blue dart", "clearance"],
    },
    "Job Scam": {
        "strong": ["earn money", "daily income", "part time job", "work from home", "data entry job"],
        "soft": ["register now", "joining fee", "task", "telegram", "telegram group"],
    },
    "Investment Scam": {
        "strong": ["guaranteed returns", "double your money", "investment", "crypto trading", "forex"],
        "soft": ["high returns", "profit", "trading group", "sip"],
    },
}


def _get_reader():
    """Lazily build the EasyOCR reader (thread-safe)."""
    global _reader, _reader_lock
    import threading

    if _reader_lock is None:
        _reader_lock = threading.Lock()
    if _reader is None:
        with _reader_lock:
            if _reader is None:
                import easyocr

                logger.info("Loading EasyOCR (first run downloads a model)...")
                _reader = easyocr.Reader(["en"], gpu=False, verbose=False)
                logger.info("EasyOCR ready.")
    return _reader


def extract_text_ocr(image_path: str) -> str:
    """
    Extract text from an image using EasyOCR.
    Returns an empty string if OCR is unavailable or times out.
    """
    try:
        reader = _get_reader()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(reader.readtext, image_path, detail=0, paragraph=True)
            lines = future.result(timeout=Config.OCR_TIMEOUT_SECONDS)
        return "\n".join(str(line).strip() for line in lines if str(line).strip())
    except concurrent.futures.TimeoutError:
        logger.warning("OCR timed out for %s", image_path)
    except ImportError:
        logger.warning("EasyOCR not installed - skipping OCR")
    except Exception:  # noqa: BLE001
        logger.exception("OCR failed for %s", image_path)
    return ""


def _classify_scam(text: str) -> tuple:
    """Return (scam_type, matched_terms) or (None, [])."""
    low = text.lower()
    best_type, best_terms = None, []
    for scam_type, terms in SCAM_PATTERNS.items():
        strong_hits = [t for t in terms["strong"] if t in low]
        soft_hits = [t for t in terms["soft"] if t in low]
        if strong_hits or (len(soft_hits) >= 2):
            # Pick the category with the most evidence.
            if len(strong_hits) + len(soft_hits) > len(best_terms):
                best_type, best_terms = scam_type, strong_hits + soft_hits
    return best_type, best_terms


def scan_whatsapp_text(text: str) -> dict:
    """Analyse already-extracted WhatsApp text."""
    start = time.perf_counter()
    builder = ScoreBuilder()
    text = (text or "").strip()

    if not text:
        return {
            "score": 0, "status": "dangerous",
            "reasons": [{"severity": "danger", "text": "No readable text found in the image."}],
            "scam_type": None, "extracted_text": text, "processing_time_ms": 0,
        }

    scam_type, matched = _classify_scam(text)
    if scam_type:
        builder.penalty(40 + min(20, len(matched) * 5),
                        f"Detected pattern: {scam_type}", "danger")
        if matched:
            builder.penalty(0, f"Matching terms: {', '.join(matched[:5])}", "info")

    low = text.lower()
    urgency = sum(1 for w in URGENCY_WORDS if w in low)
    if urgency >= 2:
        builder.penalty(10, "Strong urgency/pressure tactics used", "warning")

    pay_hit = next((p for p in PAYMENT_REQUEST_PHRASES if p in low), None)
    if pay_hit:
        builder.penalty(20, f"Money request detected: '{pay_hit}'", "danger")

    if re.search(r"https?://", low):
        builder.penalty(5, "Contains a link - always verify before clicking", "warning")

    if "forwarded" in low:
        builder.penalty(3, "Forwarded message - lower trust by default", "warning")

    result = builder.build({"scam_type": scam_type, "matched_terms": matched})
    processing_ms = int((time.perf_counter() - start) * 1000)

    return {
        "score": result.score,
        "status": classify(result.score),
        "scam_type": scam_type,
        "extracted_text": text,
        "reasons": result.reasons,
        "details": result.extra,
        "processing_time_ms": processing_ms,
    }


def scan_whatsapp_image(image_path: str) -> dict:
    """Extract text from an uploaded screenshot and analyse it."""
    extracted = extract_text_ocr(image_path)
    return scan_whatsapp_text(extracted)


def persist_scan(app, user_id, image_path, payload: dict):
    """Persist a WhatsApp scan. Never raises."""
    from models import db
    from models.scan import WhatsAppScan

    try:
        scan = WhatsAppScan(
            user_id=user_id,
            screenshot_path=image_path,
            extracted_text=(payload.get("extracted_text") or "")[:2000],
            scam_type=payload.get("scam_type"),
            trust_score=payload["score"],
            status=payload["status"],
            reasons=payload.get("reasons"),
        )
        db.session.add(scan)
        db.session.commit()
    except Exception:  # noqa: BLE001
        db.session.rollback()
        app.logger.exception("Failed to persist WhatsApp scan")
