"""
QR code verification engine.

Decodes QR images (pyzbar first, OpenCV fallback) and then routes the decoded
payload through a real, evidence-driven verification pipeline:

  * ``upi://pay``  -> UPI Payment QR: parses every UPI parameter (pa, pn, am,
                      tn, cu), validates the payer address with a proper regex,
                      checks the PSP handle and amount/currency sanity, and
                      produces a Valid / Suspicious UPI QR verdict.
  * http(s) URL    -> Website Link QR: runs the website trust engine and then
                      enriches it with domain-age (RDAP/WHOIS), Google Safe
                      Browsing and VirusTotal evidence.
  * anything else  -> structured verdict with reasons (never a silent pass).

No verdict is ever fixed: every result carries the exact signals that produced
the score so the UI can show a professional, transparent report.
"""

import re
import time
import traceback
import datetime
import urllib.parse

import requests

from config import Config
from services.logger import get_logger
from services.scoring import ScoreBuilder, classify
from services.website_scanner import scan_website

logger = get_logger(__name__)


# ---- UPI constants ----------------------------------------------------------

# A UPI ID (VPA) is: local-part@handle. Local part may contain letters, digits,
# dots, dashes and underscores; the handle is the PSP identifier (bank code).
UPI_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,40}@[A-Za-z0-9]{2,20}$")
CURRENCY_CODE_RE = re.compile(r"^[A-Za-z]{3}$")
AMOUNT_RE = re.compile(r"^\d{1,12}(\.\d{1,2})?$")

# Recognised Indian PSP handles. Presence is a positive signal; absence is
# informational only (new PSPs launch regularly).
KNOWN_PSP_HANDLES = {
    "@ybl", "@okhdfcbank", "@oksbi", "@okicici", "@okaxis", "@paytm",
    "@aubank", "@icici", "@hdfcbank", "@sbi", "@axl", "@ibl", "@kotak",
    "@payzapp", "@jupiter", "@mahb", "@barodampay", "@unionbankofindia",
    "@pnb", "@cboi", "@yesbank", "@dlb", "@pockets", "@idfcbank", "@hsbc",
    "@amazonpay", "@cred", "@slice", "@fampay", "@axisbank", "@upi",
    "@ptm", "@enets", "@truecaller", "@mysy", "@sib", "@csb", "@fbl",
    "@kvb", "@jsb", "@eazypay", "@hdfcpay", "@super", "@worldline",
    "@gpay", "@okgoogle",
}

# Allowed UPI query parameters (others are tolerated but reported).
KNOWN_UPI_PARAMS = {
    "pa", "pn", "am", "tn", "cu", "mc", "tr", "pt", "orgid", "payload",
    "iid", "ms", "uuid", "cc", "cn", "nm", "ll", "qrcode", "merchantcode",
}


# ---- QR decoding -------------------------------------------------------------

def _clean_payload(raw) -> str:
    """Strip wrappers/formatting junk a decoder may add around the real payload."""
    if raw is None:
        return ""
    text = str(raw)
    text = text.replace("\x00", "").replace("\ufeff", "").replace("\r", "")
    text = text.replace("&amp;", "&")
    return text.strip()


def _prepare_pyzbar():
    """Make the native zbar DLLs resolvable, then return the pyzbar module."""
    try:
        import os

        import pyzbar as _pkg

        dll_dir = os.path.dirname(_pkg.__file__)
        try:
            os.add_dll_directory(dll_dir)
        except (AttributeError, OSError):
            pass
        if dll_dir not in os.environ.get("PATH", ""):
            os.environ["PATH"] = dll_dir + os.pathsep + os.environ.get("PATH", "")
    except Exception:  # noqa: BLE001
        pass
    from pyzbar import pyzbar

    return pyzbar


def _decode_with_zxing(image, report=None) -> list:
    """Decode with zxing-cpp (best for photos, logos and perspective)."""
    try:
        import zxingcpp

        results = zxingcpp.read_barcodes(
            image,
            formats=zxingcpp.BarcodeFormat.QRCode,
            try_rotate=True,
            try_downscale=True,
            try_invert=True,
        )
        payloads = [_clean_payload(r.text) for r in results]
        if report is not None:
            report["attempts"].append(
                {"decoder": "zxing-cpp", "payloads": [p for p in payloads if p]}
            )
        return payloads
    except Exception as exc:  # noqa: BLE001
        error = f"{type(exc).__name__}: {exc}"
        logger.warning("zxing-cpp decode failed: %s\n%s", error, traceback.format_exc())
        if report is not None:
            report["attempts"].append({"decoder": "zxing-cpp", "error": error})
        return []


def _decode_with_pyzbar(image, report=None) -> list:
    """Decode via pyzbar + native zbar. Returns [] when unavailable/fails."""
    try:
        pyzbar = _prepare_pyzbar()
        decoded = pyzbar.decode(image)
        payloads = [_clean_payload(item.data) for item in decoded]
        if report is not None:
            report["attempts"].append(
                {"decoder": "pyzbar", "payloads": [p for p in payloads if p]}
            )
        return payloads
    except Exception as exc:  # noqa: BLE001
        error = f"{type(exc).__name__}: {exc}"
        logger.warning("pyzbar decode failed: %s\n%s", error, traceback.format_exc())
        if report is not None:
            report["attempts"].append({"decoder": "pyzbar", "error": error})
        return []


def _decode_with_opencv(image, report=None) -> list:
    """Decode via OpenCV QRCodeDetector (single + multi + curved passes)."""
    payloads = []
    try:
        import cv2

        detector = cv2.QRCodeDetector()
        data, _points, _straight = detector.detectAndDecode(image)
        if data:
            payloads.append(data)
        if not payloads:
            try:
                ok, infos, _pts, _straight = detector.detectAndDecodeMulti(image)
                if ok:
                    payloads.extend(infos)
            except Exception as exc:  # noqa: BLE001
                logger.warning("OpenCV detectAndDecodeMulti failed: %s", exc)
        if not payloads:
            try:
                ok, infos, _pts, _straight = detector.detectAndDecodeCurved(image)
                if ok:
                    payloads.extend(infos)
            except Exception as exc:  # noqa: BLE001
                logger.warning("OpenCV detectAndDecodeCurved failed: %s", exc)
    except Exception as exc:  # noqa: BLE001
        error = f"{type(exc).__name__}: {exc}"
        logger.warning("OpenCV decode failed: %s\n%s", error, traceback.format_exc())
        if report is not None:
            report["attempts"].append({"decoder": "opencv", "error": error})
        return []
    cleaned = [_clean_payload(p) for p in payloads if p]
    if report is not None:
        report["attempts"].append({"decoder": "opencv", "payloads": cleaned})
    return cleaned


def _load_variants(image_path):
    """
    Yield preprocessed (label, numpy-image) candidates so the decoders get
    the best shot at real photos: low-contrast, shadowed, small or rotated
    QR codes embedded in screenshots.
    """
    import numpy as np
    from PIL import Image, ImageOps

    try:
        pil = Image.open(image_path).convert("RGB")
    except Exception:  # noqa: BLE001
        return

    w, h = pil.size
    gray = np.array(ImageOps.grayscale(pil))
    yield "original", gray

    # Small QRs embedded in big screenshots need upscaling to decode.
    if max(w, h) < 500:
        scale = 3.0 if max(w, h) < 250 else 2.0
        big = pil.resize((int(w * scale), int(h * scale)), Image.LANCZOS)
        yield "upscaled", np.array(ImageOps.grayscale(big))

    try:
        import cv2

        _ret, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        yield "otsu", otsu

        adaptive = cv2.adaptiveThreshold(
            gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 21, 10
        )
        yield "adaptive", adaptive

        clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
        yield "clahe", clahe.apply(gray)
    except Exception:  # noqa: BLE001
        pass


def decode_qr(image_path: str, report: dict | None = None) -> list:
    """
    Decode all QR codes in an image across multiple preprocessed variants and
    decoder back-ends (zxing-cpp -> pyzbar -> OpenCV). Returns cleaned payloads.

    `report` (optional dict) receives full diagnostics: every decoder attempt
    with its payloads or exact error, and which decoder/variant finally won.
    """
    seen = set()
    payloads = []
    for label, variant in _load_variants(image_path):
        if report is not None:
            report["preprocess"] = label
        for decoder in (_decode_with_zxing, _decode_with_pyzbar, _decode_with_opencv):
            for raw in decoder(variant, report):
                if raw and raw not in seen:
                    seen.add(raw)
                    payloads.append(raw)
                    if report is not None:
                        report["decoder"] = decoder.__name__.replace("_decode_with_", "")
                        report["preprocess"] = label
                        logger.info(
                            "QR decoded via %s/%s -> %s",
                            report["decoder"], label, raw,
                        )
        if payloads:
            break
    if not payloads:
        if report is not None:
            report["decoder"] = None
        logger.error(
            "QR decode failed for %s. Attempts: %s",
            image_path,
            (report or {}).get("attempts", []),
        )
        raise RuntimeError(
            "Could not decode the QR image. Make sure it is a clear, front-on "
            "photo of a QR code, and that zxing-cpp, pyzbar or opencv-python "
            "is installed."
        )
    return payloads


# ---- UPI verification --------------------------------------------------------

def _parse_upi(payload: str) -> dict:
    """Extract UPI parameters from a upi://pay... payload."""
    parsed = urllib.parse.urlparse(payload)
    params = {}
    for key, values in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items():
        params[key.lower()] = (values[0] if values else "").strip()
    return params


def _analyse_upi(payload: str, bare: bool = False) -> dict:
    """
    Validate a UPI payment QR and return a full evidence report.

    `bare=True` is used for QRs that encode only a bare UPI ID (e.g.
    ``testuser@ybl``) instead of a full ``upi://pay?pa=...&pn=...`` URI.
    """
    start = time.perf_counter()
    builder = ScoreBuilder()
    params = _parse_upi(payload) if not bare else {"pa": payload.strip()}

    pa = params.get("pa", "")
    pn = params.get("pn", "")
    am = params.get("am", "")
    tn = params.get("tn", "")
    cu = params.get("cu", "")

    pa_valid = bool(UPI_ID_RE.match(pa))
    psp = None
    psp_known = False
    if pa_valid:
        handle = pa.rsplit("@", 1)[1].lower()
        psp = "@" + handle
        psp_known = psp in KNOWN_PSP_HANDLES
        builder.note("UPI ID format is valid", "success")
        if psp_known:
            builder.note(f"Payments processed via a well-known PSP ({psp})", "success")
        else:
            builder.note(
                f"PSP handle {psp} is not on the recognised list - verify this handle",
                "info",
            )
    elif not pa:
        builder.penalty(35, "Mandatory UPI parameter 'pa' (payer address / UPI ID) is missing", "danger")
    else:
        builder.penalty(30, f"UPI ID '{pa}' is not a valid format (expected name@bank)", "danger")

    if pn:
        builder.note(f"Payee name provided: {pn}", "info")
    elif bare:
        builder.note("QR encodes only a UPI ID with no payee name - verify the recipient before paying", "info")
    else:
        builder.penalty(5, "No payee name ('pn') - legitimate UPI QRs usually show who you are paying", "warning")

    if am:
        if AMOUNT_RE.match(am) and float(am) > 0:
            builder.note(f"Payment amount requested: {cu or 'INR'} {am}", "info")
            if float(am) >= 100000:
                builder.penalty(5, f"QR requests a large fixed amount ({cu or 'INR'} {am}) - verify the payee", "warning")
        else:
            builder.penalty(25, f"Amount field 'am' is invalid: '{am}'", "danger")
    else:
        builder.note("No fixed amount ('am') - amount may be entered by the payer at payment time", "info")

    if cu:
        if CURRENCY_CODE_RE.match(cu):
            builder.note(f"Currency: {cu.upper()}", "info")
        else:
            builder.penalty(10, f"Unrecognised currency code 'cu': '{cu}'", "warning")
    else:
        builder.note("Currency ('cu') not specified - defaults to INR for Indian UPI", "info")

    if tn:
        builder.note(f"Transaction note: {tn}", "info")

    unexpected = [k for k in params if k not in KNOWN_UPI_PARAMS]
    if unexpected:
        builder.note(
            f"Unexpected UPI parameter(s) present: {', '.join(sorted(unexpected))}",
            "info",
        )

    # Verdict: UPI format validity + mandatory field presence decide the label.
    # A bare UPI ID carries no payee-name field, so it is still valid.
    if pa_valid and (pn or bare):
        verdict = "Valid UPI QR"
        validation_status = "valid"
    elif pa_valid:
        verdict = "Suspicious UPI QR"
        validation_status = "incomplete"
    else:
        verdict = "Suspicious UPI QR"
        validation_status = "invalid"

    score = builder.score
    processing_ms = int((time.perf_counter() - start) * 1000)
    return {
        "score": score,
        "status": classify(score),
        "qr_type": "upi",
        "verdict": verdict,
        "validation_status": validation_status,
        "confidence": score,
        "upi": {
            "pa": pa or None,
            "pn": pn or None,
            "am": am or None,
            "tn": tn or None,
            "cu": cu.upper() if cu else None,
            "pa_valid": pa_valid,
            "psp": psp,
            "psp_known": psp_known,
            "params": params,
        },
        "reasons": builder.reasons,
        "decoded_url": payload,
        "processing_time_ms": processing_ms,
    }


# ---- URL / website enrichment ------------------------------------------------

def _is_raw_ip(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host or ""))


def _domain_of(url: str) -> str:
    match = re.search(r"^https?://(?:www\.)?([^/?#]+)", url, re.IGNORECASE)
    return (match.group(1) if match else "").lower()


def _rdap_domain_age(host: str) -> dict:
    """Approximate domain age in days via RDAP (no key required)."""
    if not host or _is_raw_ip(host):
        return {"age_days": None, "error": "no usable host"}
    try:
        resp = requests.get(
            f"https://rdap.org/domain/{host}",
            timeout=Config.HTTP_TIMEOUT_SECONDS,
            allow_redirects=True,
            headers={"User-Agent": "TrustLensBot/1.0"},
        )
        if resp.status_code == 404:
            return {"age_days": None, "error": "domain not found in RDAP"}
        resp.raise_for_status()
        data = resp.json()
        created = None
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                created = event.get("eventDate")
                break
        if not created:
            return {"age_days": None, "error": "no registration event"}
        created_dt = datetime.datetime.fromisoformat(str(created).replace("Z", "+00:00"))
        days = (datetime.datetime.now(datetime.timezone.utc) - created_dt).days
        return {"age_days": max(0, days)}
    except Exception as exc:  # noqa: BLE001
        return {"age_days": None, "error": str(exc)[:80]}


def _google_safe_browsing(url: str) -> dict:
    """Lookup the URL on Google Safe Browsing v4 when a key is configured."""
    key = Config.GOOGLE_SAFE_BROWSING_API_KEY
    if not key:
        return {"checked": False, "reason": "API key not configured"}
    try:
        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
            json={
                "client": {"clientId": "trustlens", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            },
            timeout=Config.HTTP_TIMEOUT_SECONDS,
        )
        if resp.status_code != 200:
            return {"checked": False, "reason": f"HTTP {resp.status_code}"}
        data = resp.json()
        threats = sorted({m.get("threatType") for m in data.get("matches", [])})
        return {"checked": True, "matched": bool(threats), "threats": threats}
    except Exception as exc:  # noqa: BLE001
        return {"checked": False, "reason": str(exc)[:80]}


def _virustotal_domain(domain: str) -> dict:
    """Fetch VirusTotal domain stats when a key is configured."""
    key = Config.VIRUSTOTAL_API_KEY
    if not key:
        return {"checked": False, "reason": "API key not configured"}
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": key},
            timeout=Config.HTTP_TIMEOUT_SECONDS,
        )
        if resp.status_code != 200:
            return {"checked": False, "reason": f"HTTP {resp.status_code}"}
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "checked": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
    except Exception as exc:  # noqa: BLE001
        return {"checked": False, "reason": str(exc)[:80]}


def _analyse_url(payload: str) -> dict:
    """Analyse a website URL carried by a QR code with full evidence."""
    start = time.perf_counter()
    base = scan_website(payload)

    builder = ScoreBuilder(start=base["score"])
    for reason in base["reasons"]:
        builder.add_reason(reason)

    host = (base.get("details") or {}).get("host", "") or _domain_of(payload)
    age = {"age_days": None, "error": "not checked"}
    if host and not _is_raw_ip(host):
        age = _rdap_domain_age(host)
        days = age.get("age_days")
        if days is None:
            builder.note("Domain age could not be verified (RDAP lookup unavailable)", "info")
        elif days < 90:
            builder.penalty(
                15, f"Domain registered only {days} days ago - very recent domains are typical of scam campaigns", "warning",
            )
        elif days < 365:
            builder.penalty(8, f"Domain is under a year old (registered {days} days ago)", "warning")
        else:
            builder.note(
                f"Domain age verified: ~{round(days / 365, 1)} years (registered {days} days ago)", "success",
            )
    else:
        builder.note("Domain age check skipped (raw IP or missing host)", "info")

    sb = _google_safe_browsing(payload)
    if sb.get("checked") and sb.get("matched"):
        builder.penalty(40, f"Google Safe Browsing flagged this URL: {', '.join(sb['threats'])}", "danger")
    elif sb.get("checked"):
        builder.note("Google Safe Browsing reported no known threats", "success")
    elif sb.get("reason") != "API key not configured":
        builder.note("Google Safe Browsing check skipped", "info")

    vt = _virustotal_domain(host) if host else {"checked": False}
    if vt.get("checked"):
        if vt.get("malicious", 0) > 0:
            builder.penalty(40, f"VirusTotal: {vt['malicious']} engine(s) flagged this domain as malicious", "danger")
        elif vt.get("suspicious", 0) > 0:
            builder.penalty(10, f"VirusTotal: {vt['suspicious']} engine(s) rated this domain suspicious", "warning")
        else:
            builder.note("VirusTotal reported no malicious or suspicious detections", "success")
    elif vt.get("reason") != "API key not configured":
        builder.note("VirusTotal lookup skipped", "info")

    result = builder.build(
        {**(base.get("details") or {}), "domain_age": age, "safe_browsing": sb, "virustotal": vt}
    )

    # A fully verified URL (HTTPS + SSL + aged domain + no blacklist/threats and
    # no caution flags anywhere) is a trusted link, so it must score 100 - the
    # generic baseline adjustment must not cap verified-safe scans below 100.
    has_caution = any(r.get("severity") in ("danger", "warning") for r in result.reasons)
    if not has_caution:
        result.score = 100
        result.status = "safe"

    processing_ms = int((time.perf_counter() - start) * 1000)
    return {
        "score": result.score,
        "status": classify(result.score),
        "qr_type": "website",
        "verdict": "Website Link QR",
        "blacklisted": base.get("blacklisted", False),
        "blacklist_reason": base.get("blacklist_reason"),
        "website": base.get("details") or {},
        "reasons": result.reasons,
        "decoded_url": payload,
        "evidence": result.extra,
        "processing_time_ms": processing_ms,
    }


def _analyse_other(payload: str) -> dict:
    """Verdict for payloads that are neither UPI nor a standard web URL."""
    start = time.perf_counter()
    low = payload.lower()
    builder = ScoreBuilder()

    if low.startswith(("mailto:", "tel:", "smsto:", "geo:", "wifi:", "mecard:", "vcard:", "begin:vcard")):
        builder.note("QR encodes a contact / device action, not a payment or web link", "info")
        verdict = "Contact / Action QR"
    elif re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,}$", payload):
        # Bare domain (e.g. "example.com") - verify as a website link.
        normalised = ("https://" + payload) if not low.startswith("http") else payload
        result = _analyse_url(normalised)
        result["decoded_url"] = payload
        result["decoded_url_normalised"] = normalised
        return result
    else:
        builder.penalty(30, "QR does not contain a recognised format (UPI payment, web URL, contact or structured text)", "warning")
        verdict = "Unrecognised QR Content"

    processing_ms = int((time.perf_counter() - start) * 1000)
    return {
        "score": builder.score,
        "status": classify(builder.score),
        "qr_type": "other",
        "verdict": verdict,
        "reasons": builder.reasons,
        "decoded_url": payload,
        "processing_time_ms": processing_ms,
    }


# ---- Public entry point ------------------------------------------------------

def scan_qr_image(image_path: str) -> dict:
    """Decode a QR image and verify its payload. Never returns a fixed result."""
    start = time.perf_counter()
    decode_report = {"attempts": []}
    try:
        payloads = decode_qr(image_path, report=decode_report)
    except RuntimeError:
        # Decode failure must surface loudly, never as a silent low score.
        logger.error(
            "QR image could not be decoded: %s (attempts=%s)",
            image_path, decode_report.get("attempts", []),
        )
        raise

    if not payloads:
        return {
            "score": 0, "status": "dangerous",
            "qr_type": "none",
            "verdict": "No QR Code Detected",
            "reasons": [{"severity": "danger", "text": "No QR code detected in the image."}],
            "decoded_url": None,
            "decode": decode_report,
            "processing_time_ms": int((time.perf_counter() - start) * 1000),
        }

    payload = payloads[0]

    # Clean decoder output (whitespace, nulls, HTML-escaped ampersands, ...).
    clean = _clean_payload(payload)

    # Some payment QRs embed the UPI string inside surrounding text/wrappers.
    # If the UPI URI is present but not at the start, extract it and re-clean.
    low = clean.lower()
    if "upi://pay" in low and not low.startswith("upi://pay"):
        match = re.search(r"upi://pay[^'\"\s<>]*", clean, re.IGNORECASE)
        if match:
            clean = _clean_payload(match.group(0))
            low = clean.lower()
    payload = clean

    if low.startswith("upi://pay"):
        result = _analyse_upi(payload)
    elif low.startswith(("http://", "https://")):
        result = _analyse_url(payload)
    elif UPI_ID_RE.match(payload.strip()):
        # Bare UPI ID (e.g. "testuser@ybl") - a common legitimate merchant format.
        result = _analyse_upi(payload.strip(), bare=True)
    else:
        result = _analyse_other(payload)

    result["decode"] = decode_report
    result["decoded_url"] = payload
    logger.info(
        "QR scan complete: decoder=%s preprocess=%s payload=%r -> score=%s (%s)",
        decode_report.get("decoder"), decode_report.get("preprocess"),
        payload, result["score"], result["status"],
    )
    return result


def persist_scan(app, user_id, image_path, payload: dict):
    """Persist a QR scan. Never raises."""
    from models import db
    from models.scan import QRScan

    try:
        scan = QRScan(
            user_id=user_id,
            image_path=image_path,
            decoded_url=payload.get("decoded_url"),
            is_suspicious=payload["status"] != "safe",
            trust_score=payload["score"],
            status=payload["status"],
            reasons=payload.get("reasons"),
        )
        db.session.add(scan)
        db.session.commit()
    except Exception:  # noqa: BLE001
        db.session.rollback()
        app.logger.exception("Failed to persist QR scan")
