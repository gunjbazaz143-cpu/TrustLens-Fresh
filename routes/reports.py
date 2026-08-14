"""
Scam report portal: private submission + persistence API.
"""

import os
import uuid
from datetime import datetime

from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import current_user

from models import db
from models.report import ScamReport
from services.mail import send_scam_report_email

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/scam-reports")
def list_reports():
    """
    Private submission portal. Reports are only ever shown to TrustLens
    admins and their reporter - nothing is listed publicly here.
    """
    return render_template("scam_reports.html")


@reports_bp.route("/api/submit-report", methods=["POST"])
def submit_report():
    title = (request.form.get("title") or "").strip()
    scam_type = (request.form.get("scam_type") or "").strip()
    description = (request.form.get("description") or "").strip()
    contact = (request.form.get("contact_number") or "").strip()
    website = (request.form.get("website_url") or "").strip()
    scam_date_str = (request.form.get("scam_date") or "").strip()
    reporter_email = (request.form.get("reporter_email") or "").strip().lower()

    if not title or not scam_type or not description:
        return jsonify({"success": False, "error": "Title, scam type and description are required."}), 400

    # Reporter email drives the status-update notifications. Prefer the value
    # supplied on the form and fall back to the signed-in account email.
    if not reporter_email and current_user.is_authenticated:
        reporter_email = current_user.email

    screenshot_path = None
    if "screenshot" in request.files and request.files["screenshot"].filename:
        file = request.files["screenshot"]
        ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
        if ext in current_app.config["ALLOWED_IMAGE_EXTENSIONS"]:
            filename = f"report_{uuid.uuid4().hex[:10]}.{ext}"
            upload_dir = os.path.join(current_app.config["UPLOAD_FOLDER"], "screenshots")
            os.makedirs(upload_dir, exist_ok=True)
            file.save(os.path.join(upload_dir, filename))
            screenshot_path = f"uploads/screenshots/{filename}"

    try:
        scam_date = None
        if scam_date_str:
            scam_date = datetime.strptime(scam_date_str, "%Y-%m-%d").date()

        report = ScamReport(
            user_id=current_user.id if current_user.is_authenticated else None,
            reporter_email=reporter_email or None,
            title=title,
            scam_type=scam_type,
            description=description,
            screenshot_path=screenshot_path,
            contact_number=contact,
            website_url=website,
            scam_date=scam_date,
        )
        db.session.add(report)
        db.session.commit()

        # Notify the admin by email so action can be taken immediately.
        mail_sent = send_scam_report_email(report)
        return jsonify({
            "success": True,
            "message": "Report submitted. It is private and will be reviewed by a TrustLens admin.",
            "mail_sent": mail_sent,
        })
    except Exception:  # noqa: BLE001
        db.session.rollback()
        current_app.logger.exception("Failed to save scam report")
        return jsonify({"success": False, "error": "Could not save report. Please try again."}), 500
