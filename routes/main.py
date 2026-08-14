"""
Main public routes: landing page, about, awareness, contact.
"""

from flask import Blueprint, render_template, request, flash, redirect, url_for

from models import db
from models.support import ContactMessage
from services.mail import send_contact_message_email

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    return render_template("index.html")


@main_bp.route("/about")
def about():
    return render_template("about.html")


@main_bp.route("/awareness")
def awareness():
    return render_template("awareness.html")


@main_bp.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()
        if name and email and subject and message:
            db.session.add(
                ContactMessage(name=name, email=email, subject=subject, message=message)
            )
            db.session.commit()
            # Deliver the message straight to the admin mailbox.
            mail_sent = send_contact_message_email(name, email, subject, message)
            if mail_sent:
                flash("Message sent successfully. We will get back to you soon.", "success")
            else:
                flash(
                    "Message saved. Note: email delivery is not configured, "
                    "but the admin can read it in the message inbox.",
                    "warning",
                )
            return redirect(url_for("main.contact"))
        flash("Please fill in all required fields.", "danger")
    return render_template("contact.html")
@main_bp.route('/product-scanner', methods=['GET', 'POST'])
def product_scanner():
    return render_template('product_scanner.html')

@main_bp.route('/claim-checker', methods=['GET', 'POST'])
def claim_checker():
    return render_template('claim_scanner.html')