"""
TrustLens - AI Based Information Verification System
Development launcher. Run `python run.py` for the dev server.
"""

from app_factory import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
