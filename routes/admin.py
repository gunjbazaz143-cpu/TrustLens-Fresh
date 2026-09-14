"""
Admin panel routes. Every route requires an authenticated admin user.
"""

from functools import wraps

from flask import Blueprint, render_template, redirect, url_for, flash, request, abort, jsonify
from flask_login import login_required, current_user

from models import db
from models.user import User
from models.report import ScamReport, ScamReportReply, REPORT_STATUSES
from models.support import ContactMessage, Feedback
from models.admin import BlacklistedDomain, AILog
from models.product_db import (
    Product, Ingredient, ProductIngredient, Category,
    ProductIdentifier, ProductAttribute, ProductVerification, ProductScoreFactor,
)
from models.scan import (
    WebsiteScan, JobScan, EmailScan, WhatsAppScan, QRScan, PaymentScan,
    ProductScan, ClaimScan,
)
from routes.dashboard import _counts
from services.analytics import (
    fraud_type_counts,
    risk_distribution,
    scan_volume_timeseries,
    user_growth_timeseries,
    category_volume,
)
from services.mail import send_scam_report_update_email

admin_bp = Blueprint("admin", __name__)


def admin_required(func):
    @wraps(func)
    @login_required
    def wrapper(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return func(*args, **kwargs)

    return wrapper


def report_stats() -> dict:
    """Counts for every report status, used by the admin dashboard and list."""
    stats = {"total": ScamReport.query.count()}
    for status in REPORT_STATUSES:
        stats[status] = ScamReport.query.filter_by(status=status).count()
    return stats


@admin_bp.route("/")
@admin_required
def index():
    counts = _counts()
    unread_messages = ContactMessage.query.filter_by(is_read=False).count()
    return render_template(
        "admin/dashboard.html",
        counts=counts,
        unread_messages=unread_messages,
        report_stats=report_stats(),
    )


@admin_bp.route("/users")
@admin_required
def users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin/users.html", users=users)


@admin_bp.route("/reports")
@admin_required
def reports():
    q = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "").strip()
    scam_type = (request.args.get("scam_type") or "").strip()

    query = ScamReport.query
    if status in REPORT_STATUSES:
        query = query.filter(ScamReport.status == status)
    if scam_type:
        query = query.filter(ScamReport.scam_type == scam_type)
    if q:
        filters = [
            ScamReport.reporter_email.ilike(f"%{q}%"),
            User.email.ilike(f"%{q}%"),
            User.full_name.ilike(f"%{q}%"),
        ]
        if q.isdigit():
            filters.append(ScamReport.id == int(q))
        query = query.outerjoin(ScamReport.user).filter(db.or_(*filters))

    reports = query.order_by(ScamReport.created_at.desc()).all()
    scam_types = [
        row[0] for row in
        db.session.query(ScamReport.scam_type).distinct().order_by(ScamReport.scam_type).all()
    ]
    return render_template(
        "admin/reports.html",
        reports=reports,
        stats=report_stats(),
        scam_types=scam_types,
        q=q,
        status=status,
        scam_type=scam_type,
    )


@admin_bp.route("/reports/<int:report_id>/reply", methods=["POST"])
@admin_required
def report_reply(report_id):
    """Save an admin reply + status change, then email the reporter."""
    report = db.session.get(ScamReport, report_id)
    if not report:
        flash("Report not found.", "danger")
        return redirect(url_for("admin.reports"))

    message = (request.form.get("admin_message") or "").strip()
    new_status = (request.form.get("status") or "").strip()
    back = {
        "q": (request.form.get("q") or "").strip(),
        "status": (request.form.get("status_filter") or "").strip(),
        "scam_type": (request.form.get("scam_type_filter") or "").strip(),
    }

    if not message:
        flash("Please write a reply message before saving.", "danger")
        return redirect(url_for("admin.reports", **back))
    if new_status not in REPORT_STATUSES:
        flash("Please choose a valid status.", "danger")
        return redirect(url_for("admin.reports", **back))

    report.status = new_status
    db.session.add(
        ScamReportReply(
            report_id=report.id,
            admin_message=message,
            status_after=new_status,
            is_viewed=False,
        )
    )
    db.session.commit()

    mail_sent = send_scam_report_update_email(report, message)
    flash_msg = f"Reply saved. Report #{report.id} marked as {new_status}."
    if mail_sent:
        flash_msg += " Update email sent to the reporter."
    else:
        flash_msg += " (Email skipped - no reporter email or SMTP not configured.)"
    flash(flash_msg, "success")
    return redirect(url_for("admin.reports", **back))


@admin_bp.route("/blacklist")
@admin_required
def blacklist():
    domains = BlacklistedDomain.query.order_by(BlacklistedDomain.created_at.desc()).all()
    return render_template("admin/blacklist.html", domains=domains)


@admin_bp.route("/blacklist/add", methods=["POST"])
@admin_required
def blacklist_add():
    domain = (request.form.get("domain") or "").strip().lower().removeprefix("http://").removeprefix("https://")
    domain = domain.split("/")[0]
    reason = (request.form.get("reason") or "").strip()
    if not domain:
        flash("Domain is required.", "danger")
    elif BlacklistedDomain.query.filter_by(domain=domain).first():
        flash("Domain is already blacklisted.", "warning")
    else:
        db.session.add(BlacklistedDomain(domain=domain, reason=reason, added_by=current_user.id))
        db.session.commit()
        flash(f"{domain} added to blacklist.", "success")
    return redirect(url_for("admin.blacklist"))


@admin_bp.route("/blacklist/<int:domain_id>/delete")
@admin_required
def blacklist_delete(domain_id):
    domain = db.session.get(BlacklistedDomain, domain_id)
    if domain:
        db.session.delete(domain)
        db.session.commit()
        flash(f"{domain.domain} removed from blacklist.", "success")
    return redirect(url_for("admin.blacklist"))


@admin_bp.route("/analytics")
@admin_required
def analytics():
    fraud = fraud_type_counts()
    return render_template(
        "admin/analytics.html",
        counts=_counts(),
        fraud_types=fraud,
        risk=risk_distribution(),
    )


@admin_bp.route("/api/analytics")
@admin_required
def analytics_api():
    """JSON feed consumed by the Chart.js charts on the admin dashboard."""
    return jsonify(
        {
            "success": True,
            "counts": _counts(),
            "fraud_types": [{"label": label, "count": count} for label, count in fraud_type_counts()],
            "risk": risk_distribution(),
            "scan_volume": scan_volume_timeseries(14),
            "user_growth": user_growth_timeseries(14),
            "categories": [{"label": label, "count": count} for label, count in category_volume()],
        }
    )


@admin_bp.route("/api/fraud-types")
@admin_required
def fraud_types_api():
    """Ranked list of the most common fraud types on the platform."""
    data = [{"label": label, "count": count} for label, count in fraud_type_counts()]
    return jsonify({"success": True, "fraud_types": data, "total": sum(item["count"] for item in data)})


@admin_bp.route("/feedback")
@admin_required
def feedback():
    feedback_list = Feedback.query.order_by(Feedback.created_at.desc()).all()
    return render_template("admin/feedback.html", feedback_list=feedback_list)


@admin_bp.route("/ai-logs")
@admin_required
def ai_logs():
    logs = AILog.query.order_by(AILog.created_at.desc()).limit(200).all()
    return render_template("admin/ai_logs.html", logs=logs)


@admin_bp.route("/messages")
@admin_required
def messages():
    messages = ContactMessage.query.order_by(ContactMessage.created_at.desc()).all()
    return render_template("admin/messages.html", messages=messages)


@admin_bp.route("/messages/<int:msg_id>/read")
@admin_required
def message_read(msg_id):
    msg = db.session.get(ContactMessage, msg_id)
    if msg:
        msg.is_read = True
        db.session.commit()
    return redirect(url_for("admin.messages"))


# --------------------------------------------------------------------------- #
# Verified product + ingredient database administration
# --------------------------------------------------------------------------- #
CONSUMPTION_OPTIONS = [
    "Intended for human consumption",
    "Not intended for human consumption",
    "External use only",
    "Household/industrial use",
    "Unknown",
]
INGREDIENT_TYPES = [
    "surfactant", "preservative", "fragrance", "solvent", "disinfectant",
    "emulsifier", "humectant", "antioxidant", "coloring agent",
    "active ingredient", "flavoring agent", "sweetener", "thickening agent",
    "stabilizer", "acidity regulator", "oil", "emollient", "material",
    "component", "stimulant", "seasoning", "cleaning agent", "uv_filter",
    "pigment", "other",
]
RISK_CATEGORIES = ["low", "moderate", "higher", "unknown"]
EVIDENCE_LEVELS = ["High", "Medium", "Low"]
INGREDIENT_DOMAINS = ["food", "cosmetic", "cleaning", "chemical", "textile", "electronics", "other"]
VERIFICATION_STATUS_OPTIONS = ["verified", "partially_verified", "unverified", "needs_verification"]


def _norm(text: str) -> str:
    import re

    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def _resolve_ingredient(name: str):
    """Find an Ingredient row by name / alias / normalised name, or None."""
    if not name:
        return None
    target = _norm(name)
    for ing in Ingredient.query.all():
        aliases = (ing.aliases or []) + [ing.ingredient_name, ing.normalized_name]
        if any(_norm(a) == target for a in aliases):
            return ing
    return None


def _parse_product_ingredients(text: str) -> tuple:
    """
    Parse the admin ingredient field. One ingredient per line, formatted as:
        IngredientName | concentration | unit | role
    Unknown names are collected as errors so nothing is ever fabricated.
    """
    import re as _re

    parsed = []
    errors = []
    for raw in (text or "").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        parts = [p.strip() for p in _re.split(r"\|", raw)]
        ing = _resolve_ingredient(parts[0])
        if ing is None:
            errors.append(f"'{parts[0]}' is not in the ingredient database")
            continue
        conc, unit, role = None, None, None
        if len(parts) > 1 and parts[1]:
            try:
                conc = float(parts[1])
            except ValueError:
                errors.append(f"Concentration '{parts[1]}' for '{parts[0]}' is not a number")
                continue
        if len(parts) > 2 and parts[2]:
            unit = parts[2]
        if len(parts) > 3 and parts[3]:
            role = parts[3]
        parsed.append((ing, conc, unit, role))
    return parsed, errors


def _product_form_dict() -> dict:
    """Collect the Product fields from a submitted form."""
    fields = {
        "brand_name": (request.form.get("brand_name") or "").strip(),
        "product_name": (request.form.get("product_name") or "").strip(),
        "product_variant": (request.form.get("product_variant") or "").strip() or None,
        "category": (request.form.get("category") or "").strip() or None,
        "subcategory": (request.form.get("subcategory") or "").strip() or None,
        "intended_use": (request.form.get("intended_use") or "").strip() or None,
        "consumption_status": (request.form.get("consumption_status") or "").strip() or None,
        "manufacturer": (request.form.get("manufacturer") or "").strip() or None,
        "market": (request.form.get("market") or "").strip() or None,
        "barcode": (request.form.get("barcode") or "").strip() or None,
        "warnings": [w.strip() for w in (request.form.get("warnings") or "").splitlines() if w.strip()],
        "source": (request.form.get("source") or "").strip() or None,
        "source_url": (request.form.get("source_url") or "").strip() or None,
        "source_date": (request.form.get("source_date") or "").strip() or None,
        # NEW fields
        "product_type": (request.form.get("product_type") or "").strip() or None,
        "description": (request.form.get("description") or "").strip() or None,
        "gtin": (request.form.get("gtin") or "").strip() or None,
        "sku": (request.form.get("sku") or "").strip() or None,
        "model_number": (request.form.get("model_number") or "").strip() or None,
        "product_code": (request.form.get("product_code") or "").strip() or None,
        "country": (request.form.get("country") or "").strip() or None,
        "edible_status": (request.form.get("edible_status") or "").strip() or None,
        "external_use_status": request.form.get("external_use_status") == "on",
        "verification_status": (request.form.get("verification_status") or "verified").strip(),
        "identification_confidence": (request.form.get("identification_confidence") or "").strip() or None,
        "category_id": None,
        "subcategory_id": None,
    }
    # Resolve category IDs from names
    cat_name = fields.get("category") or ""
    sub_name = fields.get("subcategory") or ""
    if cat_name:
        cat = Category.query.filter_by(category_name=cat_name).first()
        if cat:
            fields["category_id"] = cat.category_id
    if sub_name:
        sub = Category.query.filter_by(category_name=sub_name).first()
        if sub:
            fields["subcategory_id"] = sub.category_id
    return fields


def _apply_product_fields(product: Product, fields: dict) -> None:
    for key, value in fields.items():
        setattr(product, key, value)


def _generate_product_id(brand_name: str, product_name: str) -> str:
    base = "PRD-" + _norm(f"{brand_name} {product_name}").upper()[:36]
    candidate = base
    n = 1
    while db.session.get(Product, candidate):
        candidate = f"{base}-{n}"
        n += 1
    return candidate


def _get_top_level_categories():
    """Return top-level categories for the product form dropdown."""
    return Category.query.filter_by(parent_category_id=None).order_by(Category.sort_order).all()


def _get_subcategories(parent_name: str):
    """Return subcategories for a given parent category name."""
    parent = Category.query.filter_by(category_name=parent_name).first()
    if parent:
        return Category.query.filter_by(parent_category_id=parent.category_id).order_by(Category.sort_order).all()
    return []


@admin_bp.route("/products")
@admin_required
def products():
    products = Product.query.order_by(Product.brand_name, Product.product_name).all()
    ingredients = Ingredient.query.order_by(Ingredient.ingredient_name).all()
    return render_template(
        "admin/products.html",
        products=products,
        ingredients=ingredients,
        consumption_options=CONSUMPTION_OPTIONS,
        risk_categories=RISK_CATEGORIES,
    )


@admin_bp.route("/products/new", methods=["GET", "POST"])
@admin_required
def product_new():
    if request.method == "POST":
        fields = _product_form_dict()
        if not fields["brand_name"] or not fields["product_name"]:
            flash("Brand name and product name are required.", "danger")
            return redirect(url_for("admin.product_new"))
        parsed, errors = _parse_product_ingredients(request.form.get("ingredients") or "")
        if errors:
            for err in errors:
                flash(err, "danger")
            return redirect(url_for("admin.product_new"))
        product = Product(product_id=_generate_product_id(fields["brand_name"], fields["product_name"]), **fields)
        db.session.add(product)
        db.session.flush()
        for ing, conc, unit, role in parsed:
            db.session.add(ProductIngredient(
                product_id=product.product_id,
                ingredient_id=ing.ingredient_id,
                concentration=conc,
                concentration_unit=unit,
                role=role,
                source=fields["source"],
                source_url=fields["source_url"],
                source_date=fields["source_date"],
            ))
        db.session.commit()
        flash(f"Product '{product.brand_name} {product.product_name}' added to the verified database.", "success")
        return redirect(url_for("admin.products"))
    return render_template(
        "admin/product_form.html",
        product=None,
        product_id_hint="",
        consumption_options=CONSUMPTION_OPTIONS,
        ingredient_types=INGREDIENT_TYPES,
        risk_categories=RISK_CATEGORIES,
        evidence_levels=EVIDENCE_LEVELS,
        verification_statuses=VERIFICATION_STATUS_OPTIONS,
        ingredient_domains=INGREDIENT_DOMAINS,
        top_categories=_get_top_level_categories(),
    )


@admin_bp.route("/products/<product_id>/edit", methods=["GET", "POST"])
@admin_required
def product_edit(product_id):
    product = db.session.get(Product, product_id)
    if not product:
        flash("Product not found.", "danger")
        return redirect(url_for("admin.products"))
    if request.method == "POST":
        fields = _product_form_dict()
        if not fields["brand_name"] or not fields["product_name"]:
            flash("Brand name and product name are required.", "danger")
            return redirect(url_for("admin.product_edit", product_id=product_id))
        parsed, errors = _parse_product_ingredients(request.form.get("ingredients") or "")
        if errors:
            for err in errors:
                flash(err, "danger")
            return redirect(url_for("admin.product_edit", product_id=product_id))
        _apply_product_fields(product, fields)
        product.associations.clear()
        for ing, conc, unit, role in parsed:
            db.session.add(ProductIngredient(
                product_id=product.product_id,
                ingredient_id=ing.ingredient_id,
                concentration=conc,
                concentration_unit=unit,
                role=role,
                source=fields["source"],
                source_url=fields["source_url"],
                source_date=fields["source_date"],
            ))
        db.session.commit()
        flash(f"Product '{product.brand_name} {product.product_name}' updated.", "success")
        return redirect(url_for("admin.products"))
    current_ingredients = "\n".join(
        f"{assoc.ingredient.ingredient_name} | {assoc.concentration or ''} | {assoc.concentration_unit or ''} | {assoc.role or ''}"
        for assoc in product.associations
        if assoc.ingredient is not None
    )
    return render_template(
        "admin/product_form.html",
        product=product,
        product_id_hint=product.product_id,
        current_ingredients=current_ingredients,
        warnings_text="\n".join(product.warnings or []),
        consumption_options=CONSUMPTION_OPTIONS,
        ingredient_types=INGREDIENT_TYPES,
        risk_categories=RISK_CATEGORIES,
        evidence_levels=EVIDENCE_LEVELS,
        verification_statuses=VERIFICATION_STATUS_OPTIONS,
        ingredient_domains=INGREDIENT_DOMAINS,
        top_categories=_get_top_level_categories(),
    )


@admin_bp.route("/products/<product_id>/delete", methods=["POST"])
@admin_required
def product_delete(product_id):
    product = db.session.get(Product, product_id)
    if product:
        name = f"{product.brand_name} {product.product_name}"
        db.session.delete(product)
        db.session.commit()
        flash(f"Product '{name}' deleted.", "success")
    return redirect(url_for("admin.products"))


@admin_bp.route("/ingredients")
@admin_required
def ingredients():
    rows = Ingredient.query.order_by(Ingredient.ingredient_name).all()
    counts = dict(
        db.session.query(ProductIngredient.ingredient_id, db.func.count(ProductIngredient.id))
        .group_by(ProductIngredient.ingredient_id)
        .all()
    )
    for row in rows:
        row.product_links_count = counts.get(row.ingredient_id, 0)
    return render_template(
        "admin/ingredients.html",
        rows=rows,
        ingredient_types=INGREDIENT_TYPES,
        risk_categories=RISK_CATEGORIES,
        evidence_levels=EVIDENCE_LEVELS,
        ingredient_domains=INGREDIENT_DOMAINS,
    )


@admin_bp.route("/ingredients/add", methods=["POST"])
@admin_required
def ingredient_add():
    name = (request.form.get("ingredient_name") or "").strip()
    if not name:
        flash("Ingredient name is required.", "danger")
        return redirect(url_for("admin.ingredients"))
    existing = _resolve_ingredient(name)
    if existing:
        flash(f"'{name}' already exists in the ingredient database ({existing.ingredient_id}).", "warning")
        return redirect(url_for("admin.ingredients"))
    ingredient_id = "ING-" + _norm(name).upper()
    if db.session.get(Ingredient, ingredient_id):
        flash(f"An ingredient with id {ingredient_id} already exists.", "warning")
        return redirect(url_for("admin.ingredients"))
    aliases = [a.strip() for a in (request.form.get("aliases") or "").split(",") if a.strip()]
    concerns = [c.strip() for c in (request.form.get("concerns") or "").splitlines() if c.strip()]
    score_impact = None
    raw_impact = (request.form.get("score_impact") or "").strip()
    if raw_impact:
        try:
            score_impact = float(raw_impact)
        except ValueError:
            pass
    ing = Ingredient(
        ingredient_id=ingredient_id,
        ingredient_name=name,
        normalized_name=_norm(name),
        aliases=aliases or None,
        ingredient_type=(request.form.get("ingredient_type") or "").strip() or None,
        common_function=(request.form.get("common_function") or "").strip() or None,
        description=(request.form.get("description") or "").strip() or None,
        safety_information=(request.form.get("safety_information") or "").strip() or None,
        potential_concerns=concerns or None,
        ingestion_status=(request.form.get("ingestion_status") or "").strip() or None,
        external_use_information=(request.form.get("external_use_information") or "").strip() or None,
        evidence_level=(request.form.get("evidence_level") or "").strip() or None,
        risk_category=(request.form.get("risk_category") or "unknown").strip(),
        category=(request.form.get("ingredient_category") or "").strip() or None,
        score_impact=score_impact,
        source=(request.form.get("source") or "").strip() or None,
        source_url=(request.form.get("source_url") or "").strip() or None,
        source_date=(request.form.get("source_date") or "").strip() or None,
    )
    db.session.add(ing)
    db.session.commit()
    flash(f"Ingredient '{name}' added to the reference database.", "success")
    return redirect(url_for("admin.ingredients"))


@admin_bp.route("/ingredients/<ingredient_id>/delete", methods=["POST"])
@admin_required
def ingredient_delete(ingredient_id):
    ing = db.session.get(Ingredient, ingredient_id)
    if ing:
        in_use = ProductIngredient.query.filter_by(ingredient_id=ingredient_id).count()
        if in_use:
            flash(
                f"Ingredient '{ing.ingredient_name}' is used by {in_use} product(s) and cannot be deleted.",
                "danger",
            )
        else:
            db.session.delete(ing)
            db.session.commit()
            flash(f"Ingredient '{ing.ingredient_name}' deleted.", "success")
    return redirect(url_for("admin.ingredients"))


# --------------------------------------------------------------------------- #
# Categories administration
# --------------------------------------------------------------------------- #
@admin_bp.route("/categories")
@admin_required
def categories():
    cats = Category.query.order_by(Category.sort_order, Category.category_name).all()
    parent_map = {c.category_id: c.category_name for c in cats}
    return render_template("admin/categories.html", categories=cats, parent_map=parent_map)


@admin_bp.route("/categories/add", methods=["POST"])
@admin_required
def category_add():
    name = (request.form.get("category_name") or "").strip()
    if not name:
        flash("Category name is required.", "danger")
        return redirect(url_for("admin.categories"))
    existing = Category.query.filter_by(category_name=name).first()
    if existing:
        flash(f"Category '{name}' already exists.", "warning")
        return redirect(url_for("admin.categories"))
    parent_id = request.form.get("parent_category_id")
    parent_id = int(parent_id) if parent_id else None
    desc = (request.form.get("description") or "").strip() or None
    max_order = db.session.query(db.func.max(Category.sort_order)).scalar() or 0
    cat = Category(
        category_name=name,
        description=desc,
        parent_category_id=parent_id,
        sort_order=max_order + 1,
    )
    db.session.add(cat)
    db.session.commit()
    flash(f"Category '{name}' added.", "success")
    return redirect(url_for("admin.categories"))


@admin_bp.route("/categories/<int:category_id>/delete", methods=["POST"])
@admin_required
def category_delete(category_id):
    cat = db.session.get(Category, category_id)
    if cat:
        children = Category.query.filter_by(parent_category_id=category_id).count()
        if children:
            flash(f"Category '{cat.category_name}' has {children} subcategory(ies) and cannot be deleted.", "danger")
        else:
            in_use = Product.query.filter_by(category_id=category_id).count()
            if in_use:
                flash(f"Category '{cat.category_name}' is used by {in_use} product(s) and cannot be deleted.", "danger")
            else:
                db.session.delete(cat)
                db.session.commit()
                flash(f"Category '{cat.category_name}' deleted.", "success")
    return redirect(url_for("admin.categories"))
