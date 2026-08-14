"""
TrustLens configuration.

Centralises all application settings so routes and services never hard-code values.
Sensitive settings can be overridden through environment variables or a .env file.
"""

import os
from datetime import timedelta
from pathlib import Path


class Config:
    """Base application configuration."""

    # ---- Core ----
    SECRET_KEY = os.environ.get("SECRET_KEY", "trustlens-secret-key-change-me")

    # ---- Database (defaults to MySQL; falls back to SQLite for instant dev runs) ----
    DB_HOST = os.environ.get("DB_HOST", "localhost")
    DB_USER = os.environ.get("DB_USER", "root")
    DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
    DB_NAME = os.environ.get("DB_NAME", "trustlens")

    if os.environ.get("DATABASE_URL"):
        SQLALCHEMY_DATABASE_URI = os.environ["DATABASE_URL"]
    elif os.environ.get("USE_MYSQL", "").lower() in {"1", "true", "yes"}:
        SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
    else:
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{Path(__file__).resolve().parent / 'database' / 'trustlens.db'}"

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True, "pool_recycle": 280}

    # ---- Session / Security ----
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_DURATION = timedelta(days=14)
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)

    # ---- Uploads ----
    BASE_DIR = Path(__file__).resolve().parent
    UPLOAD_FOLDER = str(BASE_DIR / "static" / "uploads")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
    ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "bmp"}

    # ---- Timeouts ----
    SCAN_TIMEOUT_SECONDS = 25          # hard cap for heavy AI scans
    OCR_TIMEOUT_SECONDS = 20           # EasyOCR can be slow on first run
    HTTP_TIMEOUT_SECONDS = 6           # outbound website lookups

    # ---- Threat intelligence (optional, best-effort) ----
    # Enable to enrich URL/QR verification. Empty keys skip the lookup.
    GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

    # ---- Admin bootstrap ----
    # The single admin account is tied to the official admin mailbox.
    ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "gunjbazaz143@gmail.com")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Admin@12345")

    # ---- Email (Flask-Mail) ----
    # Admin alert recipient for scam reports and contact messages.
    MAIL_ALERT_RECIPIENT = os.environ.get("MAIL_ALERT_RECIPIENT", "gunjbazaz143@gmail.com")
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "1") in {"1", "true", "yes"}
    MAIL_USE_SSL = os.environ.get("MAIL_USE_SSL", "") in {"1", "true", "yes"}
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "TrustLens <no-reply@trustlens.io>")
