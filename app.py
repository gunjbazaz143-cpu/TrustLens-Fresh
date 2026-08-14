"""
TrustLens - AI Based Information Verification System
Entry point. Builds the Flask application via the factory pattern.

Run with:
    python app.py
"""

from app_factory import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
