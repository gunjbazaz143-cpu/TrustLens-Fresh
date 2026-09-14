"""
TrustLens models package.
Exposes a single `db` instance and every model through one import point.
"""

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

from models.product_db import (  # noqa: E402,F401
    Ingredient, Product, ProductIngredient, Category,
    ProductIdentifier, ProductImage, ProductAttribute,
    ProductVerification, ProductScoreFactor,
)
from models.product_candidate import ProductCandidate  # noqa: E402,F401


def init_admin_user(app):
    """
    Ensure the configured admin account (ADMIN_EMAIL) exists and is the
    single admin. Create it on first boot, promote it if it was registered as
    a normal user, and demote any other admin accounts so admin access is
    tied specifically to the official admin mailbox. Idempotent.
    """
    from models.user import User
    from werkzeug.security import generate_password_hash

    with app.app_context():
        admin_email = app.config["ADMIN_EMAIL"]
        existing = User.query.filter_by(email=admin_email).first()
        if existing:
            if existing.role != "admin":
                existing.role = "admin"
                db.session.commit()
                app.logger.info("Admin role assigned to: %s", admin_email)
        else:
            admin = User(
                full_name="TrustLens Admin",
                email=admin_email,
                password_hash=generate_password_hash(app.config["ADMIN_PASSWORD"]),
                role="admin",
                is_verified=True,
            )
            db.session.add(admin)
            db.session.commit()
            app.logger.info("Bootstrap admin created: %s", admin_email)

        other_admins = User.query.filter(User.role == "admin", User.email != admin_email).all()
        for other in other_admins:
            other.role = "user"
        if other_admins:
            db.session.commit()
            app.logger.info(
                "Demoted %s admin account(s) so %s is the only admin.",
                len(other_admins), admin_email,
            )
