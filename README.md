# TrustLens – AI Based Information Verification System

TrustLens is a production-grade web application that verifies online content
before you trust it. Users can scan websites, emails, job offers, WhatsApp
messages, QR codes and payment screenshots for scam indicators. Every scan
produces an explainable 0–100 trust score backed by real analysis — never a
fixed or random value. Community scam reports, a user dashboard, an admin
panel with analytics charts, and admin email alerts round out the platform.

---

## Project Overview

- **Backend:** Python / Flask, SQLAlchemy, SQLite (MySQL optional)
- **Frontend:** HTML5, CSS3, Bootstrap 5, vanilla JavaScript (Chart.js for admin charts)
- **AI / Analysis:** OCR (EasyOCR), OpenCV, Pillow, NumPy, heuristic scoring engine
- **Security:** Flask-Login sessions, Werkzeug password hashing, file-type/size
  validation, admin-only routes, rate-friendly timeouts, input validation

### Scanner modules

| Module | What it checks |
| --- | --- |
| Website Scanner | HTTPS, SSL, suspicious keywords/TLDs, raw-IP hosts, redirects, local blacklist |
| Email Scanner | Suspicious links, phishing phrases, urgency, sender cues, payment requests, typos |
| Job / Internship Checker | Upfront fees, free-mail HR domains, unrealistic salary, vague titles, domain mismatch |
| WhatsApp Scanner | OCR-extracted messages classified into lottery/OTP/KYC/courier/job/investment scams |
| QR Scanner | Decodes QR payloads and scores where they lead (URLs run through the website engine) |
| Payment Analyzer | EXIF/metadata, image statistics, OCR keyword checks to catch fake UPI/bank screenshots |

Every verdict includes an **AI explanation panel**: a list of reasons with
severity (safe / warning / danger) explaining exactly why the score was
assigned.

---

## Features

- 6 explainable AI scanners (website, email, job, WhatsApp, QR, payment)
- Community **scam report portal** with admin approval workflow
- **Admin email alerts** for scam reports and contact messages (Flask-Mail)
- **Blacklist engine** — admins add domains; matching scans display a prominent
  "BLACKLISTED / UNSAFE" banner
- User **dashboard** with platform statistics
- **Admin panel** — users, reports, blacklist, feedback, AI logs, messages
- **Analytics** — Chart.js charts for scan volume, risk distribution, user
  growth and a "Most Common Fraud Types" ranked breakdown
- Authentication (register / login / logout) with hashed passwords
- Responsive dark glassmorphism UI
- 404 / 500 error pages

---

## Requirements

- Python 3.10+
- pip

Core dependencies (see `requirements.txt`):

```
Flask, Flask-SQLAlchemy, Flask-Login, Flask-Mail
Werkzeug, python-dotenv
PyMySQL, cryptography
Pillow, opencv-python-headless, easyocr, numpy
pyzbar, qrcode
requests, validators
python-multipart
```

> EasyOCR downloads a model on first use. pyzbar requires the native `zbar`
> library on some systems; the QR scanner falls back to OpenCV automatically.

---

## Installation

```bash
# 1. (Recommended) create a virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # macOS / Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) configure environment
#    Copy .env.example to .env and fill in values.
#    Minimum required to enable email alerts:
#      MAIL_USERNAME=your-gmail@example.com
#      MAIL_PASSWORD=your-app-password
```

## How to Run

```bash
python app.py
```

Then open <http://localhost:5000>.

The database, schema and bootstrap admin account are created automatically on
first boot:

- Admin login: **admin@trustlens.io**
- Admin password: **Admin@12345**

> Change the admin password immediately in production, and always set a
> strong `SECRET_KEY` via environment variable.

---

## Email Alerts

Configured via environment variables (or `.env`):

| Variable | Purpose |
| --- | --- |
| `MAIL_ALERT_RECIPIENT` | Where scam reports / contact messages are delivered (default: `gunjbazaz143@gmail.com`) |
| `MAIL_SERVER` | SMTP server (default `smtp.gmail.com`) |
| `MAIL_PORT` | SMTP port (default `587`) |
| `MAIL_USERNAME` | SMTP username (e.g. your Gmail) |
| `MAIL_PASSWORD` | SMTP app password |
| `MAIL_DEFAULT_SENDER` | From header |

If SMTP is not configured the application still works; messages are saved to
the database and a friendly notice is shown instead of a crash.

---

## Project Structure

```
.
├── app.py                 # Entry point (python app.py)
├── app_factory.py         # Flask application factory
├── config.py              # Centralised configuration
├── run.py                 # Alternate entry point
├── requirements.txt
├── .env.example
├── models/                # SQLAlchemy models
│   ├── user.py            # Users + admin role
│   ├── scan.py            # Website/Job/Email/WhatsApp/QR/Payment scans
│   ├── report.py          # Community scam reports
│   ├── support.py         # Contact messages + feedback
│   └── admin.py           # Blacklist + AI audit logs
├── routes/                # Blueprints
│   ├── main.py            # Home, about, awareness, contact
│   ├── auth.py            # Login / register / logout
│   ├── scanners.py        # Scanner pages + JSON APIs
│   ├── dashboard.py       # User dashboard + stats
│   ├── reports.py         # Scam report portal + submit API
│   └── admin.py           # Admin panel + analytics APIs
├── services/              # Analysis engines & helpers
│   ├── website_scanner.py
│   ├── email_scanner.py
│   ├── job_scanner.py
│   ├── whatsapp_scanner.py
│   ├── qr_scanner.py
│   ├── payment_scanner.py
│   ├── scoring.py         # ScoreBuilder + shared heuristics
│   ├── analytics.py       # Admin chart aggregations
│   ├── mail.py            # Flask-Mail notifications
│   └── logger.py          # Centralised logging / AI audit
├── database/              # SQLite DB + bootstrap
├── templates/             # Jinja2 templates (base, scanners/, admin/, auth/)
├── static/
│   ├── css/style.css
│   ├── js/main.js
│   ├── images/
│   ├── icons/
│   └── uploads/           # User uploads (subfolders per scanner)
├── reports/               # Generated PDF reports
├── uploads/               # Document storage
└── instance/              # Flask instance folder
```

---

## Screenshots

*(Placeholders — add screenshots here for the project report.)*

| Home page | Website Scanner | Admin Dashboard |
| --- | --- | --- |
| `screenshots/home.png` | `screenshots/scanner.png` | `screenshots/admin.png` |

---

## Future Improvements

- News verification with live multi-source cross-checking
- Image tampering / reverse-image analysis
- Product ingredient scanner with OCR + safety database
- AI-generated text probability (perplexity analysis)
- PDF report generation and download
- Forgot password / password reset flow
- Google Safe Browsing + VirusTotal integration
- Two-factor authentication

---

## License

MIT License — see `LICENSE`. Free for educational and non-commercial use.
