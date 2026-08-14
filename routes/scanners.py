"""
Scanner routes: pages + JSON APIs for every analysis tool.

All API handlers return JSON with the same envelope:
    { "success": bool, "error": str|None, ...payload }
No scan ever freezes the request: heavy work (OCR) runs under a timeout and
every network call is capped.
"""

import os
import re
import uuid
import traceback

from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import current_user
from werkzeug.utils import secure_filename

from services import (
    scan_website,
    scan_email,
    scan_job,
    scan_whatsapp_image,
    scan_qr_image,
    scan_payment_screenshot,
    scan_product,
    scan_claim,
    persist_website_scan,
    persist_email_scan,
    persist_job_scan,
    persist_whatsapp_scan,
    persist_qr_scan,
    persist_payment_scan,
    persist_product_scan,
    persist_claim_scan,
)
from services.logger import get_logger, log_scan

scanners_bp = Blueprint("scanners", __name__)
logger = get_logger(__name__)


# ---- Helpers ----------------------------------------------------------------

def _current_user_id():
    return current_user.id if current_user.is_authenticated else None


def _save_upload(file_storage, subfolder: str) -> str:
    """Persist an uploaded image to the uploads folder. Returns relative path."""
    original = secure_filename(file_storage.filename or "")
    name, ext = os.path.splitext(original)
    if not ext:
        ext = ".png"
    filename = f"{subfolder}_{uuid.uuid4().hex[:10]}{ext}"
    upload_dir = os.path.join(current_app.config["UPLOAD_FOLDER"], subfolder)
    os.makedirs(upload_dir, exist_ok=True)
    full_path = os.path.join(upload_dir, filename)
    file_storage.save(full_path)
    return f"uploads/{subfolder}/{filename}"


def _validate_image(file_storage) -> str | None:
    """Return an error string if the file is missing / not an image."""
    if not file_storage or not file_storage.filename:
        return "No file uploaded."
    ext = file_storage.filename.rsplit(".", 1)[-1].lower() if "." in file_storage.filename else ""
    if ext not in current_app.config["ALLOWED_IMAGE_EXTENSIONS"]:
        return "Unsupported file type. Use PNG, JPG, JPEG, GIF, WEBP or BMP."
    return None


def _verify_image_file(path: str) -> str | None:
    """
    Return an error string if the file is not a decodable image or is
    larger than the configured limit. Uses PIL's verify() so a renamed text
    file or a truncated/corrupt image is rejected server-side.
    """
    try:
        max_bytes = current_app.config.get("MAX_CONTENT_LENGTH", 16 * 1024 * 1024)
        if os.path.getsize(path) > max_bytes:
            return "File is too large (max 16 MB)."
        from PIL import Image

        with Image.open(path) as img:
            img.verify()
        return None
    except Exception:  # noqa: BLE001
        return "The uploaded file could not be read as an image. Please upload a valid PNG, JPG or WEBP image."


def _absolute_path(relative: str) -> str:
    return os.path.join(current_app.config["BASE_DIR"], "static", relative.replace("/", os.sep))


def _image_quality_issues(path: str) -> list:
    """Best-effort readability checks before OCR. Returns a list of issue labels."""
    issues = []
    try:
        from PIL import Image

        with Image.open(path) as img:
            width, height = img.size
            if min(width, height) < 250:
                issues.append("low_resolution")
            gray = img.convert("L")
            pixels = list(gray.getdata())
            mean = sum(pixels) / len(pixels)
            if mean < 40:
                issues.append("too_dark")
            variance = sum((p - mean) ** 2 for p in pixels) / len(pixels)
            if variance < 300:
                issues.append("low_contrast")
    except Exception:  # noqa: BLE001
        pass
    return issues


# ---- Pages -------------------------------------------------------------------

@scanners_bp.route("/website-scanner")
def website_scanner_page():
    return render_template("scanners/website_scanner.html")


@scanners_bp.route("/job-checker")
def job_checker_page():
    return render_template("scanners/job_checker.html")


@scanners_bp.route("/email-scanner")
def email_scanner_page():
    return render_template("scanners/email_scanner.html")


@scanners_bp.route("/whatsapp-scanner")
def whatsapp_scanner_page():
    return render_template("scanners/whatsapp_scanner.html")


@scanners_bp.route("/qr-scanner")
def qr_scanner_page():
    return render_template("scanners/qr_scanner.html")


@scanners_bp.route("/payment-analyzer")
def payment_analyzer_page():
    return render_template("scanners/payment_analyzer.html")


# ---- APIs -------------------------------------------------------------------

@scanners_bp.route("/api/scan-website", methods=["POST"])
def api_scan_website():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"success": False, "error": "URL is required."}), 400

    try:
        payload = scan_website(url)
        persist_website_scan(current_app._get_current_object(), _current_user_id(), payload)
        log_scan(current_app._get_current_object(), "website",
                 payload["score"], payload["status"], payload["processing_time_ms"], _current_user_id())
        return jsonify({"success": True, **payload})
    except Exception:  # noqa: BLE001
        current_app.logger.error("Website scan failed:\n%s", traceback.format_exc())
        return jsonify({"success": False, "error": "Scan failed. Please try again."}), 500


@scanners_bp.route("/api/scan-email", methods=["POST"])
def api_scan_email():
    data = request.get_json(silent=True) or {}
    content = (data.get("content") or "").strip()
    if not content:
        return jsonify({"success": False, "error": "Email content is required."}), 400

    try:
        payload = scan_email(content)
        persist_email_scan(current_app._get_current_object(), _current_user_id(), content, payload)
        log_scan(current_app._get_current_object(), "email",
                 payload["score"], payload["status"], payload["processing_time_ms"], _current_user_id())
        return jsonify({"success": True, **payload})
    except Exception:  # noqa: BLE001
        current_app.logger.error("Email scan failed:\n%s", traceback.format_exc())
        return jsonify({"success": False, "error": "Scan failed. Please try again."}), 500


@scanners_bp.route("/api/scan-job", methods=["POST"])
def api_scan_job():
    data = request.get_json(silent=True) or {}
    if not any((data.get(k) or "").strip() for k in ("job_title", "company_name", "email")):
        return jsonify({"success": False, "error": "Provide at least a job title, company name or email."}), 400

    try:
        payload = scan_job(data)
        persist_job_scan(current_app._get_current_object(), _current_user_id(), data, payload)
        log_scan(current_app._get_current_object(), "job",
                 payload["score"], payload["status"], payload["processing_time_ms"], _current_user_id())
        return jsonify({"success": True, **payload})
    except Exception:  # noqa: BLE001
        current_app.logger.error("Job scan failed:\n%s", traceback.format_exc())
        return jsonify({"success": False, "error": "Scan failed. Please try again."}), 500


@scanners_bp.route("/api/scan-whatsapp", methods=["POST"])
def api_scan_whatsapp():
    if "screenshot" not in request.files:
        return jsonify({"success": False, "error": "Please upload a WhatsApp screenshot."}), 400

    err = _validate_image(request.files["screenshot"])
    if err:
        return jsonify({"success": False, "error": err}), 400

    try:
        relative = _save_upload(request.files["screenshot"], "screenshots")
        image_path = _absolute_path(relative)
        payload = scan_whatsapp_image(image_path)
        persist_whatsapp_scan(current_app._get_current_object(), _current_user_id(), relative, payload)
        log_scan(current_app._get_current_object(), "whatsapp",
                 payload["score"], payload["status"], payload["processing_time_ms"], _current_user_id())
        payload["image_path"] = url_for_static(relative)
        return jsonify({"success": True, **payload})
    except Exception:  # noqa: BLE001
        current_app.logger.error("WhatsApp scan failed:\n%s", traceback.format_exc())
        return jsonify({"success": False, "error": "Scan failed. Please try again."}), 500


@scanners_bp.route("/api/scan-qr", methods=["POST"])
def api_scan_qr():
    if "image" not in request.files:
        return jsonify({"success": False, "error": "Please upload a QR code image."}), 400

    err = _validate_image(request.files["image"])
    if err:
        return jsonify({"success": False, "error": err}), 400

    try:
        relative = _save_upload(request.files["image"], "qr")
        image_path = _absolute_path(relative)
        payload = scan_qr_image(image_path)
        persist_qr_scan(current_app._get_current_object(), _current_user_id(), relative, payload)
        log_scan(current_app._get_current_object(), "qr",
                 payload["score"], payload["status"], payload["processing_time_ms"], _current_user_id())
        payload["image_path"] = url_for_static(relative)
        return jsonify({"success": True, **payload})
    except RuntimeError as exc:
        current_app.logger.error("QR decode failed:\n%s", traceback.format_exc())
        return jsonify({"success": False, "error": str(exc)}), 422
    except Exception:  # noqa: BLE001
        current_app.logger.error("QR scan failed:\n%s", traceback.format_exc())
        return jsonify({"success": False, "error": "Scan failed. Please try again."}), 500


@scanners_bp.route("/api/scan-payment", methods=["POST"])
def api_scan_payment():
    if "screenshot" not in request.files:
        return jsonify({"success": False, "error": "Please upload a payment screenshot."}), 400

    err = _validate_image(request.files["screenshot"])
    if err:
        return jsonify({"success": False, "error": err}), 400

    try:
        relative = _save_upload(request.files["screenshot"], "screenshots")
        image_path = _absolute_path(relative)
        payload = scan_payment_screenshot(image_path)
        persist_payment_scan(current_app._get_current_object(), _current_user_id(), relative, payload)
        log_scan(current_app._get_current_object(), "payment",
                 payload["score"], payload["status"], payload["processing_time_ms"], _current_user_id())
        payload["image_path"] = url_for_static(relative)
        return jsonify({"success": True, **payload})
    except Exception:  # noqa: BLE001
        current_app.logger.error("Payment scan failed:\n%s", traceback.format_exc())
        return jsonify({"success": False, "error": "Scan failed. Please try again."}), 500


def url_for_static(relative: str) -> str:
    """Convert an uploads-relative path into a static URL."""
    from flask import url_for

    return url_for("static", filename=relative.replace(os.sep, "/"))


# ---- Product scanner ---------------------------------------------------------

@scanners_bp.route("/api/scan-product", methods=["POST"])
def api_scan_product():
    """Analyse a product from pasted ingredients and/or an uploaded label image."""
    text = (request.form.get("ingredient_input") or "").strip()
    file = request.files.get("ingredient_image")

    if not text and not file:
        return jsonify({
            "success": False,
            "error": "Provide an ingredient list or upload a product label image.",
        }), 400
    if len(text) > 5000:
        return jsonify({
            "success": False,
            "error": "Ingredient text is too long (max 5,000 characters).",
        }), 400

    files = request.files.getlist("ingredient_image")
    saved_rel = []
    image_paths = []
    quality_issues = []
    extracted = ""

    if files:
        for f in files:
            err = _validate_image(f)
            if err:
                return jsonify({"success": False, "error": err}), 400
            try:
                rel = _save_upload(f, "products")
                abs_path = _absolute_path(rel)
                err = _verify_image_file(abs_path)
                if err:
                    logger.warning("Rejected invalid product image upload: %s", err)
                    return jsonify({"success": False, "error": err}), 400
                quality_issues.extend(_image_quality_issues(abs_path))
                saved_rel.append(rel)
                image_paths.append(abs_path)
                logger.info("Product image saved: %s", rel)
            except Exception:  # noqa: BLE001
                current_app.logger.error("Product image upload failed:\n%s", traceback.format_exc())
                return jsonify({
                    "success": False,
                    "error": "The image could not be processed. Please try again.",
                }), 500

    try:
        from services.whatsapp_scanner import extract_text_ocr

        if image_paths:
            all_lines = []
            seen = set()
            for abs_path in image_paths:
                logger.info("OCR started for product label %s", abs_path)
                chunk = (extract_text_ocr(abs_path) or "").strip()
                logger.info("OCR finished (chars=%s)", len(chunk))
                for line in chunk.splitlines():
                    key = re.sub(r"[^a-z0-9]+", "", line.lower())
                    if not key or key in seen:
                        continue
                    seen.add(key)
                    all_lines.append(line.strip())
            extracted = "\n".join(all_lines)

        image_path = image_paths[0] if image_paths else ""
        logger.info("Product analysis started (text=%s, images=%s)",
                    len(text), len(image_paths))
        payload = scan_product(input_text=text, image_path=image_path, extracted_text=extracted)
        payload["image_quality"] = sorted(set(quality_issues))
        payload["image_paths"] = [url_for_static(r) for r in saved_rel]
        persist_product_scan(
            current_app._get_current_object(), _current_user_id(),
            text, saved_rel[0] if saved_rel else None, extracted, payload,
        )
        log_scan(current_app._get_current_object(), "product",
                 payload.get("score") if isinstance(payload.get("score"), int) else 0,
                 payload.get("status") or "safe",
                 payload.get("processing_time_ms") or 0,
                 _current_user_id())
        if saved_rel:
            payload["image_path"] = url_for_static(saved_rel[0])
        logger.info("Product scan complete: score=%s status=%s category=%s",
                    payload.get("score"), payload.get("status"), payload.get("category"))
        return jsonify({"success": True, **payload})
    except Exception:  # noqa: BLE001
        current_app.logger.error("Product scan failed:\n%s", traceback.format_exc())
        return jsonify({"success": False, "error": "Scan failed. Please try again."}), 500


# ---- Claim scanner ------------------------------------------------------------

@scanners_bp.route("/api/scan-claim", methods=["POST"])
def api_scan_claim():
    """Analyse a user-supplied claim against the evidence base."""
    data = request.get_json(silent=True) or {}
    claim = (data.get("claim") or "").strip()
    if not claim:
        return jsonify({"success": False, "error": "Please enter a claim to analyse."}), 400
    if len(claim) > 2000:
        return jsonify({
            "success": False,
            "error": "Claim is too long (max 2,000 characters).",
        }), 400

    try:
        logger.info("Claim analysis started (chars=%s)", len(claim))
        payload = scan_claim(claim)
        persist_claim_scan(current_app._get_current_object(), _current_user_id(), claim, payload)
        log_scan(current_app._get_current_object(), "claim",
                 payload["score"], payload["status"], payload["processing_time_ms"],
                 _current_user_id())
        logger.info("Claim scan complete: verdict=%s confidence=%s",
                    payload.get("verdict"), payload.get("confidence"))
        return jsonify({"success": True, **payload})
    except Exception:  # noqa: BLE001
        current_app.logger.error("Claim scan failed:\n%s", traceback.format_exc())
        return jsonify({"success": False, "error": "Scan failed. Please try again."}), 500
