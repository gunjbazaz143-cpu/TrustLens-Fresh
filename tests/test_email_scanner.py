"""
Email scanner regression matrix (A-L).

Runnable without pytest:

    python tests/test_email_scanner.py            # run all checks
    python tests/test_email_scanner.py --table    # just print the result table

The matrix uses *band* expectations (0-20 very low, 21-40 low, 41-60 suspicious,
61-80 high, 81-100 very high) plus relative ordering constraints. It never pins
exact scores, so the tests stay meaningful when weights evolve and they do not
over-fit to the samples.

Each sample is a realistic email that also documents WHY the expected band is
justified from its evidence - the scanner must reproduce that reasoning.
"""

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from services.email_scanner import scan_email  # noqa: E402


def band(score: int) -> str:
    if score <= 20:
        return "very_low"
    if score <= 40:
        return "low"
    if score <= 60:
        return "suspicious"
    if score <= 80:
        return "high"
    return "very_high"


BAND_MIN = {
    "very_low": 0, "low": 21, "suspicious": 41, "high": 61, "very_high": 81,
}
BAND_MAX = {
    "very_low": 20, "low": 40, "suspicious": 60, "high": 80, "very_high": 100,
}

SAMPLES = [
    # (id, expected_band, min_or_any, evidence rationale, email text)
    (
        "A",
        "very_low",
        "any",
        "Plain personal meeting email - no sender claim, no link, no security wording.",
        """From: Priya Sharma <priya.sharma@examplecorp.com>
Subject: Lunch tomorrow

Hi team,

Let's grab lunch tomorrow at 1pm at the new cafe. Please RSVP by this evening so I can book a table.

Thanks,
Priya
""",
    ),
    (
        "B",
        "low",
        "at_most",
        "Legitimate security notification: official sender + official link + explicit 'never ask' statement. Must stay below the Suspicious band.",
        """From: Microsoft Account Team <account-security-noreply@microsoft.com>
Subject: New sign-in to your account

Hi there,

We noticed a new sign-in to your Microsoft account from a new device. For your security, review your account activity at https://account.microsoft.com/security.

If this wasn't you, change your password immediately.
We will never ask for your password, OTP or personal information by email.

Thanks,
Microsoft Account Team
""",
    ),
    (
        "C",
        "suspicious",
        "any",
        "Generic verification demand with an external link and an unverifiable sender - actionable but not credential-harvesting yet.",
        """From: Account Team <no-reply@info-service.net>
Subject: Verify your account

Dear Customer,

Your account requires verification. Please verify your account details to avoid interruption of service. Click here to verify: https://info-service.net/verify

Account Team
""",
    ),
    (
        "D",
        "suspicious",
        "any",
        "Unusual-activity claim + urgency deadline + click-through to an external login page from an unverifiable sender.",
        """From: Security Team <security@alumni-portal.org>
Subject: Confirm your identity

Dear Member,

We detected unusual activity on your account. To secure your account, please login and confirm your identity within 24 hours to avoid interruption. Click here: https://members-portal.org/login

Security Team
""",
    ),
    (
        "E",
        "very_high",
        "at_least",
        "Credential phishing: asks for password AND OTP, threatens account suspension / permanent loss of access, link mimics PayPal.",
        """From: PayPal <paypal-security@paypall-secure.com>
Subject: Your account has been suspended

Dear Customer,

Your PayPal account has been suspended due to unusual activity. To restore your account, you must verify your identity immediately. Enter your email address, password and OTP on the page below within 24 hours to avoid permanent loss of access.

Click here: http://paypall-secure.com/verify/login

PayPal Security Team
""",
    ),
    (
        "F",
        "high",
        "at_least",
        "Password collection page: asks you to enter your password, link and sender both mimic Google on an unknown domain.",
        """From: Google Support <no-reply@secure-google-login.net>
Subject: Confirm your password

Dear User,

We detected unusual activity on your Google account. Your password must be re-verified to complete the security update. Enter your password now on the secure page: https://secure-google-login.net/password

Sincerely,
Google Support
""",
    ),
    (
        "G",
        "high",
        "at_least",
        "OTP harvesting: asks you to enter the OTP sent to your phone, tight deadline, lookalike Netflix domain.",
        """From: netflix@netflix-security-alerts.com
Subject: Verify your OTP

Dear Customer,

Your Netflix account requires a one-time password (OTP) to complete verification. We have sent an OTP to your phone. Enter the OTP on the page below within 10 minutes to confirm your sign-in. https://netflix-security-alerts.com/verify

Netflix Team
""",
    ),
    (
        "H",
        "high",
        "at_least",
        "Payment scam: card blocked + update card details / CVV, lookalike bank domain, plain HTTP, urgency.",
        """From: customer.service@secure-hdfc-update.com
Subject: Your card has been blocked

Dear Account Holder,

Your HDFC Bank debit card has been blocked due to security concerns. Update your card details and CVV immediately via our secure page to restore service. http://secure-hdfc-update.com/card/update

HDFC Bank
""",
    ),
    (
        "I",
        "high",
        "at_least",
        "Fake job offer: upfront registration fee, payment via gift cards, request for bank details, deadline.",
        """From: HR Department <hr@hiring-careers-services.com>
Subject: Congratulations! Job offer

Dear Candidate,

Congratulations! We are pleased to offer you the position of Software Engineer at our company. To confirm your offer, please pay a registration fee of $250 via gift cards within 48 hours. Reply with your bank details for the monthly salary deposit.

HR Team
""",
    ),
    (
        "J",
        "high",
        "at_least",
        "Tech-support scam: fake infection, call-this-number instruction, gift-card payment demand, extreme urgency.",
        """From: Tech Support <helpdesk@fix-support-online.com>
Subject: Your computer is infected

Dear User,

Your device is infected with a virus. Call this number immediately: 1800-555-0199. Our technician will connect to your computer to fix it. Please install this software so we can remove the threat. Pay the $99 service fee via a Google Play gift card to complete the repair. Act now to avoid permanent loss of your files.

Support Team
""",
    ),
    (
        "K",
        "low",
        "at_most",
        "Legitimate password-reset notice: official sender and link, reset flow only, no request to hand over credentials.",
        """From: PayPal <paypal@paypal.com>
Subject: Password reset

Hi John,

We received a request to reset the password for your PayPal account. If this was you, click the button below to choose a new password. If you did not make this request, you can safely ignore this email.

https://www.paypal.com/reset-password

PayPal
""",
    ),
    (
        "L",
        "low",
        "at_most",
        "Legitimate shipping notification from the official brand domain with a personalized greeting.",
        """From: Amazon <store-news@amazon.com>
Subject: Your order has shipped

Dear Vineet,

Your order #112-3456789-1234567 has shipped and will arrive by August 15. Track your package here: https://www.amazon.in/gp/your-account/order-details

Thank you for shopping with us,
Amazon Customer Service
""",
    ),
]


def _check_band(label, score, expected, mode):
    b = band(score)
    ok = (BAND_MIN[expected] <= score <= BAND_MAX[expected]) if mode == "any" else (
        score <= BAND_MAX[expected] if mode == "at_most" else score >= BAND_MIN[expected]
    )
    return ok, b


# The 10 indicator phrases the scanner must detect (user diagnostic Step 2).
# Each entry: (phrase, expected detector ids).
INDICATOR_PHRASES = [
    ("enter your password", ("password_request",)),
    ("enter your OTP", ("otp_request",)),
    ("send us your verification code", ("otp_request",)),
    ("your account will be suspended", ("account_threat",)),
    ("your account will be deleted", ("account_threat",)),
    ("verify immediately", ("urgency",)),
    ("act within 30 minutes", ("urgency",)),
    ("click the link below", ("click_instruction",)),
    ("confirm your bank details", ("bank_request",)),
    ("send your card information", ("bank_request",)),
    # Variants that must normalise to the same detectors.
    ("enter your one time password now", ("otp_request",)),
    ("type your O.T.P. to confirm", ("otp_request",)),
    ("your account has been permanently suspended", ("account_threat",)),
    ("failure to verify will result in permanent account deletion", ("account_threat",)),
]


def test_indicator_phrases():
    from services import email_scanner as es

    failures = []
    for phrase, expected in INDICATOR_PHRASES:
        # Mirror the production pipeline: normalize first (entities, OTP
        # variants, whitespace), then run the raw detectors.
        norm = es._normalize_text(phrase)
        hits = set()
        if es.PASSWORD_REQUEST_RE.search(norm):
            hits.add("password_request")
        if es.OTP_REQUEST_RE.search(norm):
            hits.add("otp_request")
        if es.BANK_REQUEST_RE.search(norm):
            hits.add("bank_request")
        if es.ACCOUNT_THREAT_RE.search(norm):
            hits.add("account_threat")
        if es.CLICK_INSTRUCT_RE.search(norm):
            hits.add("click_instruction")
        if len(es._urgency_signals(norm)) > 0:
            hits.add("urgency")
        if not all(e in hits for e in expected):
            failures.append(f"'{phrase}' -> {sorted(hits)} expected {list(expected)}")
    return failures


def test_negation_guards():
    from services import email_scanner as es

    failures = []
    # "We never ask..." disclaimers must NOT count as password/OTP requests.
    disclaimer = ("We will never ask for your password or OTP by email. "
                  "Please keep your credentials private.")
    payload = es.scan_email(disclaimer)
    feats = {f["fid"] for f in payload["features"]}
    if "password_request" in feats or "otp_request" in feats:
        failures.append("disclaimer email counted a credential request")
    return failures


def test_risk_bands():
    from services import email_scanner as es

    failures = []
    cases = [(0, "very_low"), (20, "very_low"), (21, "low"), (40, "low"),
             (41, "suspicious"), (60, "suspicious"), (61, "high"), (80, "high"),
             (81, "very_high"), (100, "very_high")]
    for score, expected in cases:
        got = es._risk_category(score)["category"]
        if got != expected:
            failures.append(f"score {score} -> {got} expected {expected}")
    return failures


def test_raw_to_final_normalization():
    from services import email_scanner as es

    failures = []

    def strong_collector(total):
        c = es.FeatureCollector()
        c.features["x"] = es.Feature("x", "synthetic", "strong", total, 0.8, "")
        return c

    # Strong tier must be uncapped and linear: no compression to 0-30.
    for total in [0, 10, 25, 40, 60, 80, 100]:
        got = es._combine_risk(strong_collector(total))
        if got != total:
            failures.append(f"strong raw {total} -> final {got} (expected {total})")
    if es._combine_risk(strong_collector(150)) != 100:
        failures.append("strong raw 150 did not clamp to 100")
    if es._combine_risk(strong_collector(0)) != 0:
        failures.append("strong raw 0 did not produce 0")
    return failures


def test_caps():
    from services import email_scanner as es

    failures = []

    def collector(total, tier):
        c = es.FeatureCollector()
        c.features["x"] = es.Feature("x", "synthetic", tier, total, 0.8, "")
        return c

    if es._combine_risk(collector(100, "weak")) != es.WEAK_CAP:
        failures.append("weak total not capped")
    if es._combine_risk(collector(100, "moderate")) != es.MODERATE_CAP:
        failures.append("moderate total not capped")
    return failures


def test_normalization():
    from services import email_scanner as es

    failures = []
    cases = [
        ("O.T.P.", "otp."),
        ("one-time password", "one-time password"),
        ("one time password", "one time password"),
        ("o t p", "otp"),
        ("enter&nbsp;your&nbsp;OTP", "enter your otp"),
        ("Send &amp; receive your OTP", "Send & receive your otp"),
        ("Enter your\nOTP now", "Enter your\notp now"),
        ("  Hello   world\r\n\t tab", "Hello world\ntab"),
        ("type your OTP to verify", "type your otp to verify"),
    ]
    for raw, expected in cases:
        got = es._normalize_text(raw)
        if got != expected:
            failures.append(f"normalize {raw!r} -> {got!r} expected {expected!r}")
    # End-to-end: variants must produce the otp_request feature.
    for text, label in [
        ("Please enter the O.T.P. sent to your phone.", "dotted O.T.P."),
        ("Please enter the one time password sent to your phone.", "one time password"),
        ("Enter the one-time password we sent.", "one-time password"),
        ("Type your otp to verify.", "bare otp"),
    ]:
        feats = {f["fid"] for f in es.scan_email(text)["features"]}
        if "otp_request" not in feats:
            failures.append(f"variant '{label}' did not fire otp_request")
    # HTML entities must not break URL extraction.
    with_html = "Click http://secure.example.com/login&amp;x=1 to proceed"
    links = es._extract_links(es._normalize_text(with_html))
    if not links or "secure.example.com" not in links[0]["host"]:
        failures.append("URL extraction broken after entity decoding")
    return failures


def test_strong_overrides_harmless_words():
    from services import email_scanner as es

    failures = []
    # Pleasantries / "Thank you" / "Regards" must never hide strong evidence.
    phishing = ("Dear valued customer, Thank you for contacting us. Please "
                "review your account. Regards, Security Team. Enter your "
                "password and OTP now on http://secure-login-verify.example.net/password "
                "to avoid permanent account deletion.")
    score = es.scan_email(phishing)["score"]
    if score < 61:
        failures.append(f"phishing + pleasantries scored {score} (expected high/very_high)")
    # Harmless words alone must stay very low / low.
    benign = ("Thank you for your order. Regards, Security Team. Please see "
              "our website for more details.")
    score = es.scan_email(benign)["score"]
    if score > 40:
        failures.append(f"harmless words scored {score} (expected low or lower)")
    return failures


# Job / internship scam calibration (user diagnostic): different scam phrasings
# must reach High / Very High, while legitimate internship emails that mention
# salary, documents and deadlines must stay Low or below. Nothing here is a
# hardcoded "score this exact email X" - the bands come from the evidence.
SCAM_VARIANTS = [
    (
        "V0 reported-style internship (fee + documents + bank + deadline + threat)",
        """From: HR Department <hr@hiring-careers-services.com>
Subject: Congratulations! You are selected for a paid internship

Dear Candidate,
We are pleased to inform you that you have been selected for a paid internship with a monthly stipend of Rs 40,000. To confirm your seat, a one-time registration fee of Rs 1,999 must be paid within 2 hours. Reply with your Aadhaar card, PAN card and bank account details. If you fail to pay within 2 hours, your offer will be cancelled and given to another candidate.

HR Team
""",
    ),
    (
        "V1 work-from-home data entry (free mail + fee + docs + threat)",
        """From: HR Team <hr.recruitment.team.2026@gmail.com>
Subject: Work from home data entry job - selected!

Dear Candidate,
Congratulations! You are selected for the work from home data entry position. You will earn Rs 35,000 per month. To confirm your joining, pay a registration fee of Rs 2,500 within 2 hours or your offer will be cancelled and given to another candidate. Send your Aadhaar card, PAN card and bank account details via WhatsApp.
""",
    ),
    (
        "V2 overseas visa job (salary + processing fee + withdrawn threat)",
        """From: Global Recruitment <global-recruit@overseasjobs-support.net>
Subject: Job offer - United Kingdom

Dear Applicant,
We are pleased to offer you the position of Warehouse Supervisor in London with a monthly salary of £2,200. To process your visa and work permit, you must pay a processing fee of $300 within 24 hours. Failure to pay on time will result in your offer being withdrawn.

Best regards,
Recruitment Team
""",
    ),
    (
        "V3 modelling / agency (guaranteed income + activation fee + documents)",
        """From: Talent Agency <talent@model-agenciess.net>
Subject: You are selected for a modeling assignment

Dear Model,
You have been selected for an international modeling assignment with a guaranteed income of Rs 60,000 per month. To activate your profile and confirm your booking, pay a one-time activation fee of Rs 3,000 immediately. Reply with your PAN card and passport copy.
""",
    ),
    (
        "V4 internship training fee (stipend + deposit + seats)",
        """From: placements@training-and-placements.net
Subject: Placement guaranteed internship program

Dear Student,
Join our 6-month internship program. After training, we will place you in a top company with a stipend of Rs 25,000. To reserve your seat, pay the training fee of Rs 4,000 today. Bank details for payment are below. Hurry, only 5 seats left - this is your last chance.
""",
    ),
    (
        "V5 internship fee + deadline + offer-loss threat (no bank/docs)",
        """From: placements@career-hub-jobs.net
Subject: Paid internship - immediate joining

Dear Candidate,
Congratulations, you have been selected for a paid internship at our partner firm. To confirm your seat, pay the registration fee of Rs 1,999 within 3 hours. If you fail to pay, your offer will be cancelled and given to the next candidate.
""",
    ),
    (
        "V6 consultancy pay-to-release (shortlist + appointment letter + documents)",
        """From: hr@jobplacement-consultancy.in
Subject: Final selection - HR Executive

Dear Candidate,
You have been shortlisted for the final round of selection for the HR Executive post at our consultancy. You must pay Rs 3,500 as a one-time amount to release your appointment letter and complete the joining process. This must be done within 12 hours. Reply with your bank account details and a copy of your PAN card.
""",
    ),
]

# Legitimate internship / job emails must NOT be pushed high just because they
# mention salary, documents (Aadhaar / bank details for payroll) or deadlines.
LEGIT_INTERNSHIPS = [
    (
        "L1 internship offer with payroll onboarding",
        """From: HR Team <hr@techinnovate.com>
Subject: Internship offer - Summer 2026

Dear Priya,

Congratulations on your selection for the summer internship at TechInnovate. Your monthly stipend of Rs 15,000 will be credited by the 5th of every month.

To complete your joining formalities, please submit a copy of your Aadhaar card and bank account details to the HR desk by Friday.

Report to our office on 1st June at 10 AM.

Best regards,
HR Team
""",
    ),
    (
        "L2 application acknowledgement (salary range, no money request)",
        """From: no-reply@careers.examplecorp.com
Subject: Application received - Data Analyst role

Dear Ravi,

Thank you for applying for the Data Analyst position. We have received your application and will review it over the next two weeks. The salary range for this role is Rs 6,00,000 - 8,00,000 per year. Shortlisted candidates will be contacted by 15 September.

Best regards,
Talent Acquisition
""",
    ),
]


def test_job_scam_calibration():
    failures = []

    for label, text in SCAM_VARIANTS:
        payload = es_scan(text)
        feats = {f["fid"] for f in payload["features"]}
        score = payload["score"]
        if score < 61:
            failures.append(f"[{label}] score {score} (expected high/very_high); "
                            f"indicators={payload['indicators']}")
        if "job_offer_fee" not in feats:
            failures.append(f"[{label}] did not fire job_offer_fee (core scam marker)")

    for label, text in LEGIT_INTERNSHIPS:
        payload = es_scan(text)
        score = payload["score"]
        if score > 40:
            failures.append(f"[{label}] legit internship scored {score} "
                            f"(expected low or lower)")
        feats = {f["fid"] for f in payload["features"]}
        for fid in ("job_offer_fee", "offer_loss_threat"):
            if fid in feats:
                failures.append(f"[{label}] legit email fired {fid}")
    return failures


def es_scan(text):
    from services import email_scanner as es

    return es.scan_email(text)


def run_checks(verbose=True):
    results = []
    failures = []
    payloads = {}

    for sid, expected, mode, _, text in SAMPLES:
        payload = scan_email(text)
        payloads[sid] = payload
        score = payload["score"]
        ok, b = _check_band(sid, score, expected, mode)
        results.append((sid, expected, mode, score, b, ok))

        structural_ok = True
        structural_issues = []
        for key in ("score", "status", "category", "risk_label", "risk_emoji",
                    "reasons", "indicators", "recommendation", "processing_time_ms",
                    "confidence", "features"):
            if key not in payload:
                structural_issues.append(f"missing key '{key}'")
        if not (0 <= payload.get("score", -1) <= 100):
            structural_issues.append("score out of 0-100")
        conf = payload.get("confidence")
        if not isinstance(conf, int) or not (0 <= conf <= 100):
            structural_issues.append("confidence not an int 0-100")
        for r in payload.get("reasons", []):
            if "severity" not in r or "text" not in r or "points" not in r:
                structural_issues.append("reason missing severity/text/points")
        feats = payload.get("features", [])
        if not isinstance(feats, list) or not all(
            {"fid", "label", "tier", "evidence", "contribution", "confidence"} <= set(f) for f in feats
        ):
            structural_issues.append("feature entries missing required fields")
        if structural_issues:
            structural_ok = False
            failures.append(f"[{sid}] STRUCTURE: {'; '.join(structural_issues)}")

        if not ok:
            failures.append(f"[{sid}] score {score} ({b}) not in expected band '{expected}' ({mode})")

    # Relative ordering constraints - these are the behavioral guarantees.
    def s(x):
        return payloads[x]["score"]

    order_checks = [
        ("B < C (legit notice stays below generic verification scam)", s("B") < s("C"), s("B"), s("C")),
        ("C < E (suspicious < credential phishing)", s("C") < s("E"), s("C"), s("E")),
        ("D < E (suspicious < credential phishing)", s("D") < s("E"), s("D"), s("E")),
        ("K < C (official reset below generic verification scam)", s("K") < s("C"), s("K"), s("C")),
        ("L < C (official shipping below generic verification scam)", s("L") < s("C"), s("L"), s("C")),
        ("B < D (official notice below suspicious activity email)", s("B") < s("D"), s("B"), s("D")),
    ]
    for label, ok, lo, hi in order_checks:
        if not ok:
            failures.append(f"ORDER: {label} (got {lo} !< {hi})")

    if verbose:
        print(f"{'ID':<3} {'expect':<10} {'mode':<9} {'score':>6} {'band':<11} result")
        print("-" * 60)
        for sid, expected, mode, score, b, ok in results:
            print(f"{sid:<3} {expected:<10} {mode:<9} {score:>6} {b:<11} {'PASS' if ok else 'FAIL'}")
        print("-" * 60)
        print("Ordering constraints:")
        for label, ok, lo, hi in order_checks:
            print(f"  {'PASS' if ok else 'FAIL'}  {label} ({lo} < {hi})")

    return failures, payloads, order_checks


def main():
    table_only = "--table" in sys.argv
    failures, payloads, order_checks = run_checks(verbose=not table_only)
    if table_only:
        for sid, payload in payloads.items():
            print(f"{sid}: score={payload['score']:<3} {band(payload['score']):<11} "
                  f"conf={payload['confidence']:<3} indicators={len(payload['indicators'])}")

    unit_failures = []
    unit_results = [
        ("test_indicator_phrases", test_indicator_phrases),
        ("test_negation_guards", test_negation_guards),
        ("test_risk_bands", test_risk_bands),
        ("test_raw_to_final_normalization", test_raw_to_final_normalization),
        ("test_caps", test_caps),
        ("test_normalization", test_normalization),
        ("test_strong_overrides_harmless_words", test_strong_overrides_harmless_words),
        ("test_job_scam_calibration", test_job_scam_calibration),
    ]
    if not table_only:
        print("\nUnit checks:")
    for name, fn in unit_results:
        errs = fn()
        unit_failures += [f"[{name}] {e}" for e in errs]
        if not table_only:
            print(f"  {'PASS' if not errs else 'FAIL'}  {name}" + ("" if not errs else f" ({len(errs)})"))
    failures += unit_failures

    if failures:
        print("\nFAILURES:")
        for f in failures:
            print("  -", f)
        print(f"\n{len(failures)} failure(s).")
        sys.exit(1)
    print(f"\nAll {len(SAMPLES)} samples + {len(order_checks)} ordering constraints + "
          f"{len(INDICATOR_PHRASES)} indicator phrases passed.")


if __name__ == "__main__":
    main()
