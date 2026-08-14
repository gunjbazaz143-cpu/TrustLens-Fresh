"""
Route blueprints. Register every blueprint on the app here.
"""

from routes.main import main_bp
from routes.auth import auth_bp
from routes.scanners import scanners_bp
from routes.dashboard import dashboard_bp
from routes.reports import reports_bp
from routes.admin import admin_bp


def register_blueprints(app) -> None:
    """Attach all blueprints to the Flask app."""
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(scanners_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")
