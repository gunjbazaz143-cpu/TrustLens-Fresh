"""
TrustLens - AI Based Information Verification System
Application factory. Wires configuration, extensions, blueprints and error handlers.
"""

import logging

from flask import Flask, render_template
from flask_login import LoginManager

from config import Config
from database.init_db import init_app as init_db
from models import db, init_admin_user
from routes import register_blueprints


def create_app(config_class=Config) -> Flask:
    """Build and return the configured TrustLens application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # ---- Logging ----
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    app.logger.info("TrustLens starting up")

    # ---- Extensions ----
    db.init_app(app)

    login_manager = LoginManager(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please sign in to access this page."
    login_manager.login_message_category = "warning"

    from models.user import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # ---- Database (create tables + bootstrap admin) ----
    init_db(app)

    # ---- Blueprints ----
    register_blueprints(app)

    # ---- Error handlers ----
    @app.errorhandler(404)
    def not_found(_error):
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def server_error(_error):
        return render_template("500.html"), 500

    @app.errorhandler(413)
    def too_large(_error):
        return render_template("500.html", message="File too large (max 16 MB)."), 413

    # ---- Template globals ----
    @app.context_processor
    def inject_globals():
        return {"app_name": "TrustLens"}

    return app
