"""
Email scanner (evidence-based feature pipeline).

Produces a transparent 0-100 RISK score (higher = more dangerous) for an email
plus an explicit CONFIDENCE (how much evidence the verdict is based on).

How it works
------------
Every detection is collected as a *feature* with a stable id, a tier, the
evidence that triggered it, and a per-feature confidence. Features never
double-count the same evidence: overlapping clusters are merged or suppressed
(e.g. "verify your account" counts once and escalates when the email also
contains a link; password/OTP/bank requests suppress the generic
"requests confidential information" signal).

Tiers enforce that weak signals can never overpower strong ones:
  - weak    signals (what the email is ABOUT: security wording, activity claims,
            generic greetings, typos) ............ capped at 20 points total
  - moderate context signals (verification request with an external link,
            click-through, urgency, shorteners, external login pages) capped at 45
  - strong   signals (password/OTP/bank/payment requests, account threats,
            lookalike/deceptive domains, malicious attachments) are uncapped and
            drive the result into High / Very High.
Only strong signals can reach the top of the scale; a pile of weak ones can at
most reach the low-Suspicious area. Legitimacy indicators (official sender/link,
"never ask", personalised greeting) only ever reduce the score.

Risk categories:
    0-20   very low  (safe)      21-40  low     41-60  suspicious
    61-80  high                  81-100 very high (dangerous)

The final payload keeps the API fields the UI / route / DB rely on
(score, status, category, risk_label, risk_emoji, reasons, indicators,
recommendation, details, processing_time_ms) and adds `confidence` and a
structured `features` list so every point of the score is traceable.
"""

import html
import re
import time
from urllib.parse import urlparse

from services.logger import get_logger
from services.scoring import (
    FREE_MAIL_DOMAINS,
    PAYMENT_REQUEST_PHRASES,
    URGENCY_WORDS,
    SUSPICIOUS_TLDS,
)

logger = get_logger(__name__)

# ---- Structural extraction ------------------------------------------------

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SENDER_LINE_RE = re.compile(r"^(?:from|reply-to|sent by)\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
SENDER_HINT_RE = re.compile(
    r"(?:from|sender|reply-to|sent by)\s*[:@]?\s*([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})",
    re.IGNORECASE,
)
SUBJECT_RE = re.compile(r"^subject\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'`()\[\]]+", re.IGNORECASE)
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# ---- Topic / quality signals ----------------------------------------------

TYPO_WORDS = {
    "accout": "account", "recieve": "receive", "seperate": "separate",
    "verifcation": "verification", "payement": "payment", "immediatly": "immediately",
    "cancle": "cancel", "teh": "the", "forgetten": "forgotten", "unoffical": "unofficial",
    "suspention": "suspension", "activly": "actively", "privilage": "privilege",
}

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear sir/madam", "dear sir or madam",
    "dear valued customer", "dear valued member", "dear account holder",
    "dear member", "dear friend", "hello dear", "dear all", "greetings of the day",
    "dear candidate", "dear applicant", "dear hiring manager",
]

PERSONALIZED_GREETING_RE = re.compile(r"\bdear\s+([A-Z][a-zA-Z]{2,})\b")
NON_PERSONAL_NAMES = {
    "customer", "user", "valued", "sir", "madam", "member", "account", "friend",
    "all", "team", "support", "candidate", "applicant", "account-holder", "holder",
}

# ---- Credential / data-request clusters (each fires at most once) ----------

PASSWORD_REQUEST_RE = re.compile(
    r"\b(?:enter|type|provide|send|share|give|confirm|submit|re-?enter|verify|supply|hand\s+over)\b"
    r"[^\n]{0,60}?\b(?:password|passcode|pass\s+word)\b"
    r"|your\s+password\s+(?:is\s+)?(?:needed|required|expiring|being\s+verified)"
    r"|need\s+(?:your|the)\s+(?:current\s+)?password"
    r"|password\s+(?:needed|required)\s+(?:for|to)\b",
    re.IGNORECASE,
)
OTP_REQUEST_RE = re.compile(
    r"\b(?:otp|one[\s-]?time\s+(?:password|code|pin)|verification\s+code|security\s+code"
    r"|confirmation\s+code|activation\s+code|login\s+code|passcode|auth\s+code"
    r"|\d{1,2}-?digit\s+(?:code|otp|pin))\b"
    r"[^\n]{0,60}?(?:sent\s+to|by\s+email|on\s+your\s+(?:phone|mobile|device)|text(?:ed)?\s+to)"
    r"|\b(?:enter|type|provide|send|share|give|confirm|submit|reply\s+(?:with|the))\b"
    r"[^\n]{0,60}?\b(?:otp|one[\s-]?time\s+(?:password|code|pin)|verification\s+code|security\s+code"
    r"|confirmation\s+code|activation\s+code|login\s+code|passcode"
    r"|\d{1,2}-?digit\s+(?:code|otp|pin))\b",
    re.IGNORECASE,
)
BANK_REQUEST_RE = re.compile(
    r"bank\s+details|credit\s+card\s+number|debit\s+card\s+number|card\s+number\s+and\s+cvv"
    r"|card\s+number\s+and\s+(?:otp|pin|expiry)"
    r"|bank\s+card\s+number|bank\s+card\s+(?:details|information|pin)"
    r"|\bcvv\b|\bupi\b|net\s+banking\s+password|internet\s+banking"
    r"|online\s+banking|bank\s+account\s+number|bank\s+account\s+details|routing\s+number|wire\s+transfer|atm\s+pin"
    r"|debit\s+card\s+pin|account\s+number\s+and\s+(?:ifsc|cvv)"
    r"|confirm\s+(?:your|my)\s+bank\s+details|update\s+(?:your|my)\s+payment\s+(?:details|information)"
    r"|enter\s+(?:your|my)\s+(?:card|bank|upi)\s+details|verify\s+(?:your|my)\s+payment"
    r"|provide\s+(?:your|my)\s+(?:card|bank|payment)\s+details"
    r"|send\s+(?:us\s+)?(?:your|my|the)?\s*(?:card|credit\s+card|debit\s+card|bank|payment)\s+(?:information|details|number|data|credentials)"
    r"|share\s+(?:your|my)\s+(?:card|bank)\s+(?:details|information|number|data)"
    r"|update\s+(?:your|my)\s+card\s+(?:details|information|number)"
    r"|card\s+details\s+and\s+cvv",
    re.IGNORECASE,
)
ACCOUNT_THREAT_RE = re.compile(
    r"account\s+will\s+be\s+(?:permanently|temporarily)?\s*(?:deleted|closed|suspended|locked|disabled|terminated|deactivated)"
    r"|account\s+(?:has|has\s+been|was)\s+(?:permanently|temporarily)?\s*(?:deleted|closed|suspended|locked|disabled|terminated|deactivated)"
    r"|(?:permanently|temporarily)\s+(?:deleted|closed|suspended|locked|disabled|terminated|deactivated)"
    r"|immediately\s+(?:suspend|close|delete|lock|block|deactivate)\s+your\s+account"
    r"|(?:suspend|close|delete|lock|block|deactivate)\s+your\s+account\s+(?:immediately|within)"
    r"|access\s+(?:to\s+your\s+account\s+)?(?:has|has\s+been|will\s+be)\s+"
    r"(?:restricted|revoked|suspended|terminated|lost)"
    r"|permanent\s+loss\s+of\s+access"
    r"|permanent\s+account\s+(?:deletion|suspension|closure|termination|deactivation)"
    r"|result\s+in\s+permanent\s+(?:account\s+)?(?:deletion|suspension|closure|termination|deactivation)"
    r"|(?:reactivate|re-activate|unlock|restore)\s+your\s+account"
    r"|your\s+account\s+is\s+(?:under\s+)?(?:being\s+)?(?:suspended|restricted|locked)"
    r"|account\s+(?:will|would|may)\s+be\s+(?:closed|deleted|suspended)\s+(?:within|in|after)",
    re.IGNORECASE,
)
# Identity-document requests (Aadhaar / PAN / passport / government ID). Kept
# separate from BANK_REQUEST_RE so "reply with your Aadhaar and PAN" is evidence
# of document harvesting, not banking credentials, and so the two only double up
# when the email really asks for both.
IDENTITY_DOCUMENT_RE = re.compile(
    r"\b(?:aadhaar|aadhar|pan\s+card|pan\s+number|passport\s+(?:number|copy)|"
    r"driver(?:'s)?\s+(?:licen[cs]e|licence\s+number)|voter\s+(?:id|card)|"
    r"social\s+security\s+(?:number|card)|kyc\s+documents?|identity\s+(?:proof|documents?|card)|"
    r"photo\s+id|government\s+issued\s+id|id\s+proof)\b",
    re.IGNORECASE,
)

# Job / internship / recruitment context. On its own this is a WEAK "what the
# email is about" signal - it is the gating context that escalates the
# job-scam detectors below (fee, offer-loss threat) and that downgrades
# legitimately-expected payroll requests (bank details, Aadhaar).
JOB_CONTEXT_RE = re.compile(
    r"\b(?:internship|traineeship|trainee|job\s+offer|job\s+opening|job\s+opportunity|"
    r"position|vacancy|recruit(?:ment)?|hiring|offer\s+letter|joining\s+letter|appointment\s+letter)"
    r"|congratulations[^\n]{0,50}?(?:selected|shortlisted|chosen|selection)"
    r"|you\s+have\s+been\s+(?:selected|shortlisted|chosen)"
    r"|we\s+are\s+pleased\s+to\s+(?:inform|offer)"
    r"|work\s+from\s+home|part[- ]?time\s+(?:job|work)|data\s+entry|freelanc(?:e|ing)",
    re.IGNORECASE,
)

# Upfront money demands tied to a job / offer. Legitimate hiring never charges
# the applicant, so these are strong when a job context is present (checked in
# scan_email); a negated disclaimer ("no registration fee is required") is the
# only thing that suppresses them.
JOB_FEE_RE = re.compile(
    r"\b(?:registration|joining|processing|application|security|verification|administration|admin|"
    r"training|certificate|documentation|refundable|activation|visa)\s+(?:fee|charges?|cost|amount|deposit)"
    r"|\b(?:fee|deposit|amount|money)\b[^\n]{0,80}?(?:to|in\s+order\s+to)\s+"
    r"(?:confirm|secure|complete|activate|release|process|start|receive|unlock|get)\s+"
    r"(?:your\s+)?(?:job|offer|application|internship|selection|joining|appointment|visa|profile|seat)"
    r"|\bpay\b[^\n]{0,80}?(?:to|in\s+order\s+to)\s+"
    r"(?:confirm|secure|complete|activate|release|process|start|receive|unlock|get)\s+"
    r"(?:your\s+)?(?:job|offer|application|internship|selection|joining|appointment|visa|profile|seat)"
    r"|\bpay\b[^\n]{0,80}\b(?:registration|joining|processing|application|security|verification|"
    r"training|visa|activation)\s+(?:fee|charges?|cost|deposit)\b",
    re.IGNORECASE,
)

# "Pay now or you lose the offer" pressure. This is itself a threat construction
# so no negation guard is applied (mirrors ACCOUNT_THREAT_RE); gated on job
# context so generic "don't lose this opportunity" marketing never fires it.
OFFER_LOSS_THREAT_RE = re.compile(
    r"\b(?:job|offer|position|selection|internship|appointment)\s+(?:will\s+be|would\s+be|has\s+been|may\s+be)\s+"
    r"(?:cancelled|canceled|withdrawn|revoked|rescinded|given\s+to\s+(?:another|the\s+next)\s+candidate)"
    r"|\b(?:lose|losing|forfeit)\s+(?:this\s+)?(?:opportunity|offer|job|position|selection)"
    r"|\b(?:offer|selection|job|position)\s+(?:stands\s+)?(?:cancelled|canceled)"
    r"|\b(?:fail|failing|failure)\s+(?:to\s+)?(?:pay|complete|confirm|report|attend)\b[^\n]{0,80}\b"
    r"(?:offer|job|position|selection)\b[^\n]{0,50}\b(?:cancelled|canceled|withdrawn|given)",
    re.IGNORECASE,
)

# Claimed compensation (salary / stipend / earnings). Weak on its own; becomes
# meaningful through the compensation-fee combo when an upfront fee is present.
COMPENSATION_CLAIM_RE = re.compile(
    r"\b(?:monthly|per\s+month|a\s+month)\s+(?:salary|stipend|income|pay|earnings|wages|compensation)"
    r"|\b(?:salary|stipend|income|pay|earnings|wages|compensation)\s+of\s+(?:rs\.?|inr|rupees|usd|\$|€|£|₹)\s?[\d,]+"
    r"|\b(?:rs\.?|inr|rupees|₹|usd|\$|€|£)\s?[\d,]+\s+(?:per\s+month|monthly|/month|per\s+day|daily|per\s+week)"
    r"|\b(?:earn|make|receive|get)\s+(?:up\s+to\s+)?(?:rs\.?|inr|rupees|₹|usd|\$|€|£)\s?[\d,]+\s+(?:per|a|an)?\s*(?:month|day|hour|week)",
    re.IGNORECASE,
)

# Extreme short-fuse deadlines ("within 2 hours") that escalate urgency even
# when they are the only pressure signal.
SHORT_DEADLINE_RE = re.compile(r"\bwithin\s+(\d+)\s+(minutes?|hours?)\b", re.IGNORECASE)

UNUSUAL_INSTRUCTIONS_RE = re.compile(
    r"\b(?:provide|send|share|give|submit|enter|type|upload)\b"
    r"[^\n]{0,40}?"
    r"\b(?:personal|confidential|sensitive|bank|card|financial|billing|payment)?\s*"
    r"(?:details|information|data|documents|identification|credentials|password|otp|kyc|pan|aadhaar)\b",
    re.IGNORECASE,
)
FINANCIAL_ACTION_RE = re.compile(r"\b(?:charge|debit|withdraw|auto-?renew)\b", re.IGNORECASE)

# Pay/send money via gift cards - the classic tech-support / fee scam payload.
GIFTCARD_PAYMENT_RE = re.compile(
    r"\b(?:pay|send|complete\s+(?:the\s+)?payment|make\s+a\s+payment)\b"
    r"[^\n]{0,60}?\bgift\s+cards?\b",
    re.IGNORECASE,
)

# ---- Topic (weak) signals ---------------------------------------------------

SECURITY_NOTIFICATION_RE = re.compile(
    r"\b(?:for\s+your\s+security|as\s+a\s+security\s+measure|account\s+security"
    r"|security\s+(?:team|department|alert|settings|notice|issue|purposes|information|breach))\b",
    re.IGNORECASE,
)
NEW_DEVICE_LOGIN_RE = re.compile(
    r"(?:sign(?:ed|ning)?[- ]?in|log(?:ged|ging)?[- ]?in|login|signed\s+in)"
    r"[^\n]{0,40}\b(?:from|using|on|via)\b[^\n]{0,30}\bnew\s+device\b"
    r"|\bsign[- ]?in\s+from\s+(?:a\s+)?new\s+device\b"
    r"|\bnew\s+sign[- ]?in\b|\bnew\s+login\b|\bunrecogni[sz]ed\s+device\b",
    re.IGNORECASE,
)
ACCOUNT_ACTIVITY_RE = re.compile(
    r"\b(?:unusual|suspicious|recent|unexpected|unauthori[sz]ed)\s+activity\b"
    r"|\baccount\s+activity\b|\breview\s+your\s+(?:account|activity)\b"
    r"|\bactivity\s+on\s+your\s+account\b",
    re.IGNORECASE,
)
# Single verification-language detector. It contributes ONCE (see scan_email):
# the link context decides whether it stays weak (5/8) or escalates (15).
VERIFICATION_LANGUAGE_RE = re.compile(
    r"\b(?:verify|re-?verify|validate|confirm)\b[^\n]{0,40}"
    r"\b(?:account|identity|information|details|sign[- ]?in|login|activity)\b"
    r"|\baccount\s+verification\b|\bverification\s+(?:required|needed|process)\b",
    re.IGNORECASE,
)
ACTION_RECOMMENDED_RE = re.compile(r"\b(?:recommended\s+action|action\s+(?:recommended|needed))\b", re.IGNORECASE)

CLICK_INSTRUCT_RE = re.compile(
    r"click\s+(?:here|this\s+link|the\s+link|the\s+button|below)|"
    r"sign\s+in\s+(?:to|through|via)|login\s+(?:to|through|via)|"
    r"follow\s+the\s+link|tap\s+here|open\s+the\s+link",
    re.IGNORECASE,
)

# ---- URL analysis -----------------------------------------------------------

CREDENTIAL_URL_KEYWORDS = {
    "login", "signin", "sign-in", "verify", "verification", "secure", "security",
    "account", "update", "confirm", "auth", "authorize", "password", "credential",
    "unlock", "reactivate", "restore", "recover", "wallet", "identity",
}
EXTERNAL_LOGIN_PATH_RE = re.compile(
    r"/(?:login|signin|sign-in|verify|verification|auth|authorize|secure|password|account)(?:/|$)",
    re.IGNORECASE,
)
# Redirect-style query parameters ("?url=", "?redirect=", "?next=...") hide the
# real destination behind an open redirect.
QUERY_REDIRECT_RE = re.compile(
    r"[?&](?:url|redirect|redirect_to|return|dest|destination|next|target|link|go|to|u|r)=",
    re.IGNORECASE,
)

# Email-specific urgency / deadline patterns. Combined with the shared URGENCY_WORDS
# list (each underlying phrase is counted at most once).
EMAIL_URGENCY_RE = [
    re.compile(r"\bimmediate\w*", re.IGNORECASE),
    re.compile(r"\bwithin\s+\d+\s+(?:minutes?|hours?|days?)\b", re.IGNORECASE),
    re.compile(r"\b(?:act|verify|respond|confirm|do\s+it)\s+now\b", re.IGNORECASE),
    re.compile(r"\bfailure\s+to\b", re.IGNORECASE),
    re.compile(r"\b(?:fail|failing)\s+to\b", re.IGNORECASE),
    re.compile(r"\bpermanent\w*\s+loss\b", re.IGNORECASE),
    re.compile(r"\bfinal\s+(?:warning|notice)\b", re.IGNORECASE),
    re.compile(r"\blimited\s+time\b", re.IGNORECASE),
    re.compile(r"\blast\s+chance\b", re.IGNORECASE),
]
NEVER_ASK_RE = re.compile(
    r"(?:we|we'?ll|we\s+will|we\s+would|they|our\s+team|microsoft|google|apple|paypal|amazon|bank|your\s+bank)"
    r"[\s\S]{0,30}(?:never|won'?t|will\s+never|do\s+not|do\s+not)\s+ask"
    r"[\s\S]{0,60}(?:password|otp|one[\s-]?time|verification\s+code|personal\s+information|details|gift\s+cards?)",
    re.IGNORECASE,
)

ATTACHMENT_SUSPICIOUS_EXT = re.compile(
    r"(?:attachment|attached file|attached|open (?:the |this )?(?:attachment|file|document)|"
    r"see the (?:attached|file)|file\s+[a-z0-9_.-]+)\.(?:exe|scr|bat|cmd|vbs|js|jar|apk|msi|pif|lnk|docm|xlsm)\b",
    re.IGNORECASE,
)

# Distinct social-engineering instructions. Presence is count-scaled so a single
# mention stays moderate while several distinct instructions escalate.
SOCIAL_ENGINEERING = [
    "gift card", "itunes card", "google play card", "steam wallet",
    "western union", "moneygram", "wire transfer", "send money",
    "install this software", "download this app", "update your app",
    "update your player", "call this number", "call us on", "contact this number",
    "contact support on", "update your flash", "update your browser",
    "you need to install", "download the file", "run the file",
    "your device is infected", "security alert from your bank", "antivirus expired",
    "remote access", "screen share",
]
PRIZE_ADVANCE_FEE = [
    "you have won", "claim your prize", "lottery", "sweepstakes", "you are a winner",
    "guaranteed returns", "cryptocurrency", "bitcoin", "invest now",
    "inheritance", "unclaimed funds", "tax refund", "processing fee",
    "activation fee", "security deposit", "advance payment", "registration fee",
    "refund of your money",
]

# Phrases that are already evidence of another (stronger) cluster; skip them in
# the social-engineering / prize scans to avoid double-counting the same text.
_SE_PAYMENT_OVERLAP = {"wire transfer", "send money"}
_PRIZE_PAYMENT_OVERLAP = {"registration fee", "processing fee", "security deposit", "advance payment",
                          "activation fee"}

# Negation guard: phrases inside an explicit "we will never ask / do not / avoid"
# context are legitimacy notes, not scam signals.
NEGATION_RE = re.compile(
    r"\b(?:never|won'?t|will\s+not|do\s+not|don'?t|does\s+not|did\s+not|not\s+ask|avoid|ignore|no\s+one|refuse)\b",
    re.IGNORECASE,
)

BRAND_DOMAINS = {
    "microsoft": ("microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com"),
    "google": ("google.com", "googlemail.com", "gmail.com", "youtube.com"),
    "apple": ("apple.com", "icloud.com"),
    "paypal": ("paypal.com",),
    "amazon": ("amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.co.jp"),
    "netflix": ("netflix.com",),
    "linkedin": ("linkedin.com",),
    "facebook": ("facebook.com", "fb.com", "meta.com"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com",),
    "twitter": ("twitter.com", "x.com"),
    "telegram": ("telegram.org",),
    "flipkart": ("flipkart.com",),
    "snapchat": ("snapchat.com",),
    "paytm": ("paytm.com",),
    "phonepe": ("phonepe.com",),
    "icici": ("icicibank.com",),
    "hdfc": ("hdfcbank.com",),
    "sbi": ("sbi.co.in", "onlinesbi.sbi"),
    "axis": ("axisbank.com",),
    "kotak": ("kotak.com",),
    "fedex": ("fedex.com",),
    "dhl": ("dhl.com",),
    "ups": ("ups.com",),
    "irctc": ("irctc.co.in",),
    "dmv": ("dmv.ca.gov", "dmv.ny.gov"),
    "steam": ("steampowered.com",),
    "binance": ("binance.com",),
    "coinbase": ("coinbase.com",),
    "norton": ("norton.com",),
    "mcafee": ("mcafee.com",),
    "microsoft365": ("microsoft.com", "office.com"),
}

_CONFUSABLES = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
    "8": "b", "@": "a", "|": "l", "!": "i",
}
_CC_SUFFIXES = {
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.in", "org.in", "net.in", "ac.in", "gov.in", "co.jp", "ne.jp", "or.jp",
    "ac.jp", "co.nz", "net.nz", "org.nz", "com.br", "com.mx", "com.ar", "com.tr",
    "co.za", "co.ke", "co.ng", "com.sg", "com.hk", "com.cn", "com.tw", "co.id",
    "com.my", "co.th", "com.vn",
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "bit.do",
    "rebrand.ly", "cutt.ly", "tiny.cc", "rb.gy", "shorturl.at", "buff.ly",
    "shorte.st", "adf.ly", "t2m.io", "u.to",
}

# ---- Feature metadata -------------------------------------------------------
# fid -> (label, tier, base contribution, evidence confidence 0-1)
# Tiers: "weak" (capped), "moderate" (capped), "strong" (uncapped, drives the
# score to the top). Contributions are evidence-justified: a single strong
# request (e.g. "enter your password") alone is enough to reach High.
FEATURE_SPECS = {
    # weak / contextual
    "security_notification": ("Security-related message", "weak", 6, 0.55),
    "new_device_login": ("New-device sign-in notification", "weak", 6, 0.55),
    "account_activity": ("Unexpected account activity claim", "weak", 6, 0.55),
    "action_recommended": ("Generic action recommended", "weak", 3, 0.5),
    "generic_greeting": ("Generic greeting - common in mass phishing", "weak", 4, 0.5),
    "typos": ("Spelling / grammar errors", "weak", 3, 0.5),
    "http_only": ("Plain HTTP link (not HTTPS)", "weak", 2, 0.4),
    "query_redirect": ("Redirect-style query parameter", "weak", 4, 0.6),
    "excessive_subdomains": ("Excessive subdomain chain", "weak", 4, 0.5),
    "attachment_mention": ("Attachment present", "weak", 4, 0.5),
    "sender_unverifiable": ("Unverifiable sender domain", "weak", 6, 0.45),
    "job_context": ("Job / internship / recruitment context", "weak", 4, 0.4),
    "compensation_claim": ("Claims a salary / stipend / earning amount", "weak", 4, 0.45),
    # moderate / context-verified
    "verification_request": ("Verification / account request", "moderate", 15, 0.72),
    "click_instruction": ("Click-through instruction", "moderate", 8, 0.5),
    "urgency_mild": ("Urgency language", "moderate", 6, 0.5),
    "urgency_high": ("Strong urgency language", "moderate", 10, 0.6),
    "urgency_excessive": ("Excessive urgency / pressure language", "moderate", 14, 0.7),
    "sender_free_mail": ("Free-mail sender", "moderate", 8, 0.7),
    "brand_link_mismatch": ("Link does not match claimed organisation", "moderate", 10, 0.7),
    "shortener_link": ("Shortened link - destination hidden", "moderate", 8, 0.7),
    "unusual_instructions": ("Requests confidential information", "moderate", 10, 0.7),
    "external_login_link": ("External login page", "moderate", 10, 0.7),
    "financial_action": ("Financial action mentioned", "moderate", 6, 0.5),
    # strong / critical
    "password_request": ("Requests password", "strong", 40, 0.92),
    "otp_request": ("Requests OTP / security code", "strong", 40, 0.92),
    "bank_request": ("Requests banking / payment credentials", "strong", 35, 0.9),
    "payment_request": ("Requests payment", "strong", 30, 0.85),
    "account_threat": ("Account suspension / deletion threat", "strong", 30, 0.85),
    "credential_login_url": ("Suspicious credential login URL", "strong", 35, 0.85),
    "ip_link": ("Link uses a raw IP address", "strong", 40, 0.9),
    "suspicious_tld_link": ("Suspicious disposable link domain", "strong", 22, 0.9),
    "lookalike_link": ("Lookalike domain", "strong", 28, 0.85),
    "sender_mismatch": ("Domain does not match claimed organisation", "strong", 22, 0.85),
    "sender_deceptive": ("Deceptive sender address", "strong", 22, 0.85),
    "attachment_suspicious": ("Suspicious attachment", "strong", 22, 0.85),
    "social_engineering": ("Social-engineering instructions", "strong", 18, 0.78),
    "prize_fee": ("Prize / advance-fee scheme language", "strong", 20, 0.8),
    "giftcard_payment": ("Gift-card payment demand", "strong", 25, 0.8),
    "identity_document_request": ("Requests identity documents (Aadhaar / PAN / ID)", "strong", 25, 0.85),
    "job_offer_fee": ("Upfront fee demanded for a job / offer", "strong", 30, 0.9),
    "offer_loss_threat": ("Threatens cancellation / loss of the offer", "strong", 20, 0.85),
    "urgency_cred_combo": ("Extreme urgency combined with a credential request", "strong", 15, 0.85),
    "compensation_fee_combo": ("Unrealistic compensation combined with an upfront fee", "strong", 15, 0.9),
    "job_scam_multi": ("Multiple job-scam indicators combined", "strong", 15, 0.9),
    "critical_combo": ("Multiple strong phishing indicators together", "strong", 10, 0.8),
}

# Strong features whose co-occurrence triggers the critical-combo bonus.
COUNTED_STRONG_FIDS = {
    fid for fid, (_, tier, _, _) in FEATURE_SPECS.items()
    if tier == "strong"
    and fid not in {"urgency_cred_combo", "compensation_fee_combo", "job_scam_multi", "critical_combo"}
}

LEGIT_WEIGHTS = {
    "never_ask_password": -25,
    "sender_matches_claim": -15,
    "link_matches_claim": -10,
    "personalized_greeting": -4,
}

# Weak / moderate totals are capped so a pile of contextual signals can never
# overpower a single strong one. Strong signals are uncapped.
WEAK_CAP = 20
MODERATE_CAP = 45

RISK_CATEGORIES = [
    # (upper_bound_inclusive, key, label, emoji, status3)
    (20, "very_low", "Very Low Risk", "🟢", "safe"),
    (40, "low", "Low Risk", "🟡", "safe"),
    (60, "suspicious", "Suspicious", "🟠", "warning"),
    (80, "high", "High Risk", "🔴", "dangerous"),
    (100, "very_high", "Very High Risk", "⛔", "dangerous"),
]

RECOMMENDATIONS = {
    "very_low": "No obvious phishing indicators detected from the information provided. Still treat unexpected links and attachments with normal caution.",
    "low": "No strong phishing indicators detected. If anything is unexpected, verify the sender through an official channel before acting.",
    "suspicious": "Several warning signs found. Do not provide any passwords, OTPs, codes or payment details, and verify the sender through an official channel before taking action.",
    "high": "Strong phishing indicators detected. Do not click links or open attachments, and do not provide any personal or financial information. Verify through official channels.",
    "very_high": "Do not click the link or provide any credentials. Report this email as phishing.",
}


# ---- Feature collection -----------------------------------------------------

class Feature:
    """One detected indicator with its evidence and tiered contribution."""

    __slots__ = ("fid", "label", "tier", "base", "confidence", "evidence")

    def __init__(self, fid, label, tier, base, confidence, evidence):
        self.fid = fid
        self.label = label
        self.tier = tier
        self.base = base
        self.confidence = confidence
        self.evidence = evidence

    def to_dict(self):
        return {
            "fid": self.fid,
            "label": self.label,
            "tier": self.tier,
            "evidence": self.evidence[:90] if self.evidence else "",
            "contribution": self.base,
            "confidence": int(round(self.confidence * 100)),
        }


class FeatureCollector:
    """Registers each feature id at most once so evidence never double-counts."""

    def __init__(self):
        self.features = {}

    def add(self, fid, evidence="", base=None, tier=None, confidence=None):
        if fid in self.features:
            return
        label, default_tier, default_base, default_conf = FEATURE_SPECS[fid]
        self.features[fid] = Feature(
            fid, label,
            tier if tier is not None else default_tier,
            base if base is not None else default_base,
            confidence if confidence is not None else default_conf,
            evidence or label,
        )

    def has(self, fid):
        return fid in self.features

    def strong_count(self):
        # Count strong-tier features only. A feature whose tier was demoted by
        # context (e.g. bank/identity requests inside a job email) must not
        # count towards "N strong indicators" or drive confidence.
        return sum(1 for f in self.features.values()
                   if f.tier == "strong" and f.fid in COUNTED_STRONG_FIDS)

    def max_confidence(self):
        return max((f.confidence for f in self.features.values()), default=0.0)


# ---- Helpers ---------------------------------------------------------------

def _normalize_host(host: str) -> str:
    out = []
    for ch in (host or "").lower():
        if ch.isalnum():
            out.append(_CONFUSABLES.get(ch, ch))
    return "".join(out)


def _registrable(host: str) -> str:
    labels = (host or "").rstrip(".").lower().split(".")
    if len(labels) <= 2:
        return host.rstrip(".").lower()
    if ".".join(labels[-2:]) in _CC_SUFFIXES:
        return ".".join(labels[-3:]) if len(labels) >= 3 else host.rstrip(".").lower()
    return ".".join(labels[-2:])


def _strip_www(host: str) -> str:
    return host.lower().lstrip(".") if host.lower().startswith("www.") else host.lower()


def _extract_links(content: str):
    """Parse URLs out of the email. Returns list of link dicts."""
    results = []
    seen = set()
    for raw in URL_RE.findall(content):
        raw = raw.rstrip(".,;:!?)]}>\"'")
        low = raw.lower()
        if low.startswith("www."):
            raw = "http://" + raw
        url = urlparse(raw)
        host = url.hostname or ""
        host = _strip_www(host)
        if not host or host in seen:
            continue
        seen.add(host)
        results.append({
            "url": raw,
            "host": host,
            "registrable": _registrable(host),
            "scheme": url.scheme.lower(),
            "path": (url.path or "").lower(),
            "query": (url.query or "").lower(),
            "label_count": len(host.split(".")),
            "is_ip": bool(IP_RE.match(host)),
            "is_shortener": host in SHORTENERS,
            "suspicious_tld": any(host.endswith(t) for t in SUSPICIOUS_TLDS),
            "is_https": url.scheme.lower() == "https",
        })
    return results


def _is_trusted_registrable(host: str) -> bool:
    """True when the registrable domain belongs to a known official brand.

    Prevents well-known providers' real login pages (e.g. account.microsoft.com,
    mail.google.com, accounts.google.com) from being flagged as credential
    collection pages even when the sender header is missing.
    """
    reg = _registrable(host)
    if reg in FREE_MAIL_DOMAINS:
        return True
    for doms in BRAND_DOMAINS.values():
        if reg in doms:
            return True
    return False


def _is_credential_url(link: dict) -> bool:
    """True when a link points at a credential-collection / login page.

    Flags hosts whose subdomain/domain words include sign-in, verification or
    account keywords (e.g. secure-account-verification.example.com). Official
    brand domains and a plain registrable domain (e.g. example.com) are NOT
    flagged, because legitimate services commonly use their own domain.
    """
    host = link["host"] or ""
    if not host or _is_trusted_registrable(host):
        return False
    tokens = set()
    for label in host.lower().rstrip(".").split("."):
        tokens.update(label.replace("-", "_").split("_"))
    tokens.discard("www")
    return bool(CREDENTIAL_URL_KEYWORDS & tokens)


def _urgency_signals(content: str) -> list:
    """Return the distinct urgency/deadline phrases in the email.

    Combines the shared URGENCY_WORDS list with email-specific patterns and
    de-duplicates so the same underlying phrase is never counted twice.
    """
    low = (content or "").lower()
    hits = []
    for word in URGENCY_WORDS:
        if word in low:
            hits.append(word)
    for pattern in EMAIL_URGENCY_RE:
        match = pattern.search(content or "")
        if match:
            hits.append(match.group(0).strip().lower())
    seen = set()
    unique = []
    for hit in hits:
        if hit not in seen:
            seen.add(hit)
            unique.append(hit)
    return unique


def _extract_sender(content: str):
    """Return (display_name, email, domain) from From/Reply-To headers when present."""
    match = SENDER_LINE_RE.search(content)
    if match:
        line = match.group(1).strip()
        mail = EMAIL_RE.search(line)
        if mail:
            email = mail.group(0)
            before = line[: mail.start()].strip().strip('"<>()[]')
            before = before.replace("<", "").replace(">", "").strip()
            return (before or None, email, email.split("@")[-1].lower())
    hint = SENDER_HINT_RE.search(content)
    if hint:
        email = hint.group(1).strip()
        return (None, email, email.split("@")[-1].lower())
    return (None, None, None)


_BRAND_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(b) for b in BRAND_DOMAINS) + r")\b",
    re.IGNORECASE,
)


def _claimed_brands(display_name: str, subject_and_head: str) -> set:
    """Brands the email claims to be from.

    Evidence sources, in priority order:
      1. the sender display name ("PayPal Security Team"),
      2. a capitalised brand mention near the top of the email
         ("Your HDFC Bank debit card...") - proper-noun usage only, so generic
         lowercase mentions ("microsoft update", "buy on amazon") never claim.
    """
    claims = set()
    if display_name:
        for m in _BRAND_PATTERN.finditer(display_name):
            claims.add(m.group(1).lower())
    for m in _BRAND_PATTERN.finditer((subject_and_head or "")[:300]):
        if m.group(0)[:1].isupper() or m.group(0)[:1].isdigit():
            claims.add(m.group(1).lower())
    return claims


def _brand_official(brand: str, host: str) -> bool:
    return _registrable(host) in BRAND_DOMAINS.get(brand, ()) or _normalize_host(host) in (
        _normalize_host(d) for d in BRAND_DOMAINS.get(brand, ())
    )


def _lookalike_brand(brand: str, host: str) -> bool:
    if _brand_official(brand, host):
        return False
    return _normalize_host(brand) in _normalize_host(host)


def _is_negated(content: str, start: int, window: int = 60) -> bool:
    """True when a phrase sits inside an explicit negation context.

    Only the text BEFORE the match is inspected: legitimate "we never ask..."
    / "we will not request..." disclaimers always precede the phrase, while
    trailing text (e.g. the scam's own "avoid permanent loss of your files")
    must never suppress evidence.
    """
    low = content.lower()
    lo = max(0, start - window)
    return bool(NEGATION_RE.search(low[lo:start]))


def _risk_category(risk: int):
    for upper, key, label, emoji, status3 in RISK_CATEGORIES:
        if risk <= upper:
            return {"category": key, "label": label, "emoji": emoji, "status": status3}
    return {"category": "very_high", "label": "Very High Risk", "emoji": "⛔", "status": "dangerous"}


# ---- Scoring ----------------------------------------------------------------

def _tier_totals(collector: FeatureCollector):
    """Sum of contributions per tier: (weak, moderate, strong)."""
    weak = moderate = strong = 0
    for f in collector.features.values():
        if f.tier == "weak":
            weak += f.base
        elif f.tier == "moderate":
            moderate += f.base
        else:
            strong += f.base
    return weak, moderate, strong


def _combine_risk(collector: FeatureCollector) -> int:
    """Centralised scoring: weak/moderate totals are capped, strong uncapped."""
    weak, moderate, strong = _tier_totals(collector)
    return min(100, min(WEAK_CAP, weak) + min(MODERATE_CAP, moderate) + strong)


def _compute_confidence(collector, has_sender, has_links, has_subject) -> int:
    """How much evidence the verdict is based on (0-100), separate from risk."""
    completeness = sum((has_sender, has_links, has_subject)) / 3.0
    n = len(collector.features)
    if n == 0:
        # A clean verdict is more trustworthy when we had more channels to look at.
        return int(round(60 + 30 * completeness))
    strength = min(1.0, 0.35 * min(1.0, collector.strong_count() / 2) + 0.65 * min(1.0, n / 7))
    conf = 0.5 + 0.15 * completeness + 0.25 * strength + 0.10 * collector.max_confidence()
    return int(round(min(0.97, conf) * 100))


# ---- Main entry point ------------------------------------------------------

# Detectors that can be reported independently for a debug trace.
_TRACE_DETECTORS = (
    ("password_request", PASSWORD_REQUEST_RE),
    ("otp_request", OTP_REQUEST_RE),
    ("bank_request", BANK_REQUEST_RE),
    ("account_threat", ACCOUNT_THREAT_RE),
    ("identity_document_request", IDENTITY_DOCUMENT_RE),
    ("job_context", JOB_CONTEXT_RE),
    ("job_offer_fee", JOB_FEE_RE),
    ("offer_loss_threat", OFFER_LOSS_THREAT_RE),
    ("compensation_claim", COMPENSATION_CLAIM_RE),
    ("unusual_instructions", UNUSUAL_INSTRUCTIONS_RE),
    ("giftcard_payment", GIFTCARD_PAYMENT_RE),
    ("click_instruction", CLICK_INSTRUCT_RE),
    ("security_notification", SECURITY_NOTIFICATION_RE),
    ("new_device_login", NEW_DEVICE_LOGIN_RE),
    ("account_activity", ACCOUNT_ACTIVITY_RE),
    ("verification_request", VERIFICATION_LANGUAGE_RE),
    ("attachment_suspicious", ATTACHMENT_SUSPICIOUS_EXT),
)


def _build_trace(content, collector, urgency_hits, se_hits, links, claimed,
                 weak_raw, moderate_raw, strong_raw, risk_before_legit, legit,
                 risk, cat, confidence):
    """Structured debug view: which detectors fired, were counted, and how the
    raw contributions became the final score (input -> indicators -> raw ->
    caps -> legitimacy -> normalized -> category)."""
    detectors = {}
    for fid, regex in _TRACE_DETECTORS:
        match = regex.search(content)
        detectors[fid] = {
            "fired": bool(match),
            "counted": collector.has(fid),
            "evidence": match.group(0)[:80] if match else "",
        }
    detectors["social_engineering"] = {
        "fired": bool(se_hits),
        "counted": collector.has("social_engineering"),
        "evidence": ", ".join(se_hits)[:80],
    }
    detectors["urgency"] = {
        "fired": len(urgency_hits) > 0,
        "counted": any(collector.has(f) for f in
                       ("urgency_mild", "urgency_high", "urgency_excessive")),
        "evidence": ", ".join(urgency_hits)[:80],
    }
    cred_urls = [l["host"] + (l["path"] or "") for l in links if _is_credential_url(l)]
    detectors["credential_login_url"] = {
        "fired": bool(cred_urls),
        "counted": collector.has("credential_login_url"),
        "evidence": ", ".join(cred_urls)[:80],
    }
    return {
        "normalized_input_len": len(content),
        "detectors": detectors,
        "urgency_signal_count": len(urgency_hits),
        "link_count": len(links),
        "link_domains": [l["host"] for l in links],
        "claimed_organisation": claimed,
        "tier_totals": {"weak": weak_raw, "moderate": moderate_raw, "strong": strong_raw},
        "caps": {"weak": min(WEAK_CAP, weak_raw), "moderate": min(MODERATE_CAP, moderate_raw)},
        "raw_combined_before_legit": risk_before_legit,
        "legit_deduction": legit,
        "final_score": risk,
        "category": cat["category"],
        "confidence": confidence,
    }


# OTP spelling variants ("O.T.P.", "o t p", "one-time / one time password") are
# all normalised to the same canonical token before detection. Separators are
# matched only BETWEEN the letters so a following word/period is never eaten
# ("otp to verify" must stay "otp to verify", "O.T.P." -> "otp.").
_OTP_VARIANT_RE = re.compile(r"\bo[\s\.-]*?t[\s\.-]*?p\b", re.IGNORECASE)


def _normalize_text(content: str) -> str:
    """Normalise email text for detection while preserving line structure.

    - Decodes HTML entities (&amp;, &lt;, ...) so plain-text scanners see the
      real characters.
    - Collapses runs of spaces/tabs/nbsp and Windows CRLF so phrases split
      across line breaks still match, while real newlines are preserved so the
      line-bounded regex windows ([^\n]{0,N}) and URL extraction keep their
      semantics (URLs contain no whitespace, so they are unaffected).
    - Unifies OTP spelling variants (O.T.P., o t p, one-time password).
    Case is preserved here; scan_email lowercases a separate copy for matching.
    """
    text = html.unescape(content or "")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _OTP_VARIANT_RE.sub("otp", text)
    text = re.sub(r"[ \t\xa0]+", " ", text)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n[ \t]+", "\n", text)
    return text.strip()


def scan_email(content: str, trace: bool = False) -> dict:
    """Analyse an email and return a 0-100 risk score plus explainable reasons.

    When `trace` is True the returned payload also includes a `trace` dict that
    shows, for every detector, whether it fired and whether it was counted, plus
    the exact tier/cap/legitimacy math behind the final score.
    """
    start = time.perf_counter()
    content = _normalize_text(content)

    if not content:
        return {
            "score": 0,
            "status": "safe",
            "category": "very_low",
            "risk_label": "Very Low Risk",
            "risk_emoji": "🟢",
            "confidence": 100,
            "features": [],
            "reasons": [{"severity": "info", "text": "No email content provided."}],
            "indicators": [],
            "recommendation": RECOMMENDATIONS["very_low"],
            "details": {},
            "processing_time_ms": 0,
        }

    low = content.lower()
    collector = FeatureCollector()

    # ---- Extract structural information ----
    links = _extract_links(content)
    display_name, sender, sender_domain = _extract_sender(content)

    subject = None
    subj = SUBJECT_RE.search(content)
    if subj:
        subject = subj.group(1).strip()
    head = ((subject or "") + "\n" + content[:600])

    claims = _claimed_brands(display_name, head)
    claimed = next(iter(claims)) if claims else None

    # ========================================================================
    # 1. Topic signals (weak). Words like "account", "security" or "verification"
    #    alone are NOT danger - they only describe what the email is about.
    # ========================================================================
    security_hit = SECURITY_NOTIFICATION_RE.search(content)
    if security_hit:
        collector.add("security_notification", evidence=security_hit.group(0))
    new_device_hit = NEW_DEVICE_LOGIN_RE.search(content)
    if new_device_hit:
        collector.add("new_device_login", evidence=new_device_hit.group(0))
    activity_hit = ACCOUNT_ACTIVITY_RE.search(content)
    if activity_hit:
        collector.add("account_activity", evidence=activity_hit.group(0))
    action_hit = ACTION_RECOMMENDED_RE.search(content)
    if action_hit:
        collector.add("action_recommended", evidence=action_hit.group(0))

    # Verification wording - counted ONCE; the link context decides its strength.
    verification_hit = VERIFICATION_LANGUAGE_RE.search(content)
    security_context = bool(security_hit or activity_hit or verification_hit)

    # ========================================================================
    # 2. Credential / data-request clusters (each fires at most once).
    # ========================================================================
    if PASSWORD_REQUEST_RE.search(content):
        pw_match = PASSWORD_REQUEST_RE.search(content)
        if not _is_negated(content, pw_match.start()):
            collector.add("password_request", evidence=pw_match.group(0))
    if OTP_REQUEST_RE.search(content):
        otp_match = OTP_REQUEST_RE.search(content)
        if not _is_negated(content, otp_match.start()):
            collector.add("otp_request", evidence=otp_match.group(0))

    # Job / internship recruitment scams are context-dependent: hiring emails
    # legitimately ask for identity documents and bank details for payroll, so in
    # a job context those requests are downgraded to moderate context signals.
    # The scam markers - an upfront fee, an offer-loss threat, an extreme
    # deadline and the combination of several of these - drive the score instead.
    job_context = bool(JOB_CONTEXT_RE.search(content))
    if job_context:
        job_hit = JOB_CONTEXT_RE.search(content)
        collector.add("job_context", evidence=job_hit.group(0))

    if BANK_REQUEST_RE.search(content):
        bank_evidence = BANK_REQUEST_RE.search(content).group(0)
        if job_context:
            collector.add("bank_request", evidence=bank_evidence,
                          base=12, tier="moderate", confidence=0.6)
        else:
            collector.add("bank_request", evidence=bank_evidence)

    if IDENTITY_DOCUMENT_RE.search(content):
        id_hit = IDENTITY_DOCUMENT_RE.search(content)
        if not _is_negated(content, id_hit.start()):
            if job_context:
                collector.add("identity_document_request", evidence=id_hit.group(0),
                              base=12, tier="moderate", confidence=0.6)
            else:
                collector.add("identity_document_request", evidence=id_hit.group(0))

    # Upfront money demands are never a legitimate part of hiring. Only a negated
    # disclaimer ("no registration fee is required") suppresses them, and a job
    # context is required so prize/lottery advance-fee emails keep using the
    # prize detector instead of stacking this one.
    fee_hit = JOB_FEE_RE.search(content)
    if fee_hit and job_context and not _is_negated(content, fee_hit.start()):
        collector.add("job_offer_fee", evidence=fee_hit.group(0))

    # "Pay now or you lose the offer" is itself a threat construction (no negation
    # guard, mirroring account_threat). Gated on job context so generic marketing
    # "don't lose this opportunity" emails never fire it.
    threat_hit = OFFER_LOSS_THREAT_RE.search(content)
    if threat_hit and job_context:
        collector.add("offer_loss_threat", evidence=threat_hit.group(0))

    comp_hit = COMPENSATION_CLAIM_RE.search(content)
    if comp_hit:
        collector.add("compensation_claim", evidence=comp_hit.group(0))

    # Account suspension / deletion threats. Unlike password/OTP requests, no
    # negation guard is applied: "to avoid permanent account deletion" is itself
    # the scammer's threat construction, not a disclaimer. Genuine trust signals
    # (official sender/link, "never ask") are handled by legitimacy deductions.
    if ACCOUNT_THREAT_RE.search(content):
        threat_evidence = ", ".join(dict.fromkeys(
            m.group(0).strip() for m in ACCOUNT_THREAT_RE.finditer(content)))
        collector.add("account_threat", evidence=threat_evidence)

    bank_or_payment = collector.has("bank_request")
    payment_phrase = next((p for p in PAYMENT_REQUEST_PHRASES if p in low), None)
    if payment_phrase and not bank_or_payment and not collector.has("job_offer_fee"):
        collector.add("payment_request", evidence=payment_phrase)

    cred_requested = any(collector.has(f) for f in
                         ("password_request", "otp_request", "bank_request", "payment_request"))

    # ========================================================================
    # 3. Link analysis. Strong flags dominate; mutually exclusive flags can
    #    never both fire for the same link (no double counting).
    # ========================================================================
    link_flags = {"ip": False, "tld": False, "shortener": False, "lookalike": False,
                  "cred": False, "external": False, "http": False, "mismatch": False,
                  "query": False, "subdomains": False}
    links_trusted = False
    if links:
        links_trusted = all(
            _is_trusted_registrable(l["host"])
            or (claimed and _brand_official(claimed, l["host"]))
            for l in links
        )

    for link in links:
        official_link = bool(claimed and _brand_official(claimed, link["host"]))
        if link["is_ip"] and not link_flags["ip"]:
            link_flags["ip"] = True
            collector.add("ip_link", evidence=link["host"])
        if link["suspicious_tld"] and not link_flags["tld"]:
            link_flags["tld"] = True
            collector.add("suspicious_tld_link", evidence=link["host"])
        if link["is_shortener"] and not link_flags["shortener"]:
            link_flags["shortener"] = True
            collector.add("shortener_link", evidence=link["host"])
        if claimed and _lookalike_brand(claimed, link["host"]) and not link_flags["lookalike"]:
            link_flags["lookalike"] = True
            collector.add("lookalike_link", evidence=f"{link['host']} vs claimed '{claimed}'")
        elif claimed and not link_flags["mismatch"] and not official_link \
                and link["host"].lower().find(claimed) == -1:
            link_flags["mismatch"] = True
            collector.add("brand_link_mismatch",
                          evidence=f"{link['host']} vs claimed '{claimed}'")
        if not official_link and _is_credential_url(link) and not link_flags["cred"] \
                and not link["is_ip"]:
            link_flags["cred"] = True
            collector.add("credential_login_url", evidence=link["host"] + (link["path"] or ""))
        elif security_context and not official_link and not link_flags["cred"] \
                and not link_flags["external"] and not link["is_ip"] \
                and not _is_trusted_registrable(link["host"]) \
                and EXTERNAL_LOGIN_PATH_RE.search(link["path"]):
            link_flags["external"] = True
            collector.add("external_login_link",
                          evidence=f"{link['host']}{link['path']}")
        if not link["is_https"] and not link_flags["http"]:
            link_flags["http"] = True
            collector.add("http_only", evidence=link["url"])
        if QUERY_REDIRECT_RE.search(link["query"]) and not link_flags["query"]:
            link_flags["query"] = True
            collector.add("query_redirect", evidence=link["url"])
        if not link_flags["subdomains"] and link["label_count"] >= 4 \
                and not _is_trusted_registrable(link["host"]) and not link["is_ip"]:
            link_flags["subdomains"] = True
            collector.add("excessive_subdomains", evidence=link["host"])

    # Verification wording: escalate only when it is actionable via an
    # EXTERNAL link. Official-link or link-less wording stays weak.
    if verification_hit:
        evidence = verification_hit.group(0)
        if not links:
            collector.add("verification_request", evidence=evidence, base=5,
                          tier="weak", confidence=0.5)
        elif links_trusted:
            collector.add("verification_request", evidence=evidence, base=8,
                          tier="weak", confidence=0.55)
        else:
            collector.add("verification_request", evidence=evidence)

    # ========================================================================
    # 4. Urgency / pressure (weak alone, escalated by count).
    # ========================================================================
    urgency_hits = _urgency_signals(content)
    short_deadline = SHORT_DEADLINE_RE.search(content)
    short_hours = 0.0
    if short_deadline:
        short_hours = int(short_deadline.group(1)) / 60.0 \
            if short_deadline.group(2).startswith("minute") \
            else float(short_deadline.group(1))
    # A very short fuse ("within 2 hours") escalates even as a single signal.
    short_pressure = short_hours and short_hours <= 12.0
    if len(urgency_hits) >= 4 or (short_pressure and len(urgency_hits) >= 2):
        collector.add("urgency_excessive", evidence=", ".join(urgency_hits[:4]))
    elif len(urgency_hits) >= 2 or short_pressure:
        collector.add("urgency_high", evidence=", ".join(urgency_hits))
    elif len(urgency_hits) == 1:
        collector.add("urgency_mild", evidence=urgency_hits[0])

    # Click-through instructions only matter when there is a link to click.
    if links:
        click_hit = CLICK_INSTRUCT_RE.search(content)
        if click_hit:
            collector.add("click_instruction", evidence=click_hit.group(0))

    # ========================================================================
    # 5. Sender analysis (never trust the display name alone).
    # ========================================================================
    context_present = bool(collector.features)
    if sender:
        official_sender = bool(claimed and _brand_official(claimed, sender_domain))
        deceptive_hit = (sender_domain.count(".") >= 3
                         or IP_RE.match(sender_domain)
                         or any(sender_domain.endswith(t) for t in SUSPICIOUS_TLDS))
        if sender_domain in FREE_MAIL_DOMAINS and not official_sender and (claimed or context_present):
            collector.add("sender_free_mail", evidence=sender_domain)
        if deceptive_hit:
            if IP_RE.match(sender_domain):
                collector.add("sender_deceptive", evidence=f"IP {sender_domain}")
            elif sender_domain.count(".") >= 3:
                collector.add("sender_deceptive", evidence=sender_domain)
            else:
                collector.add("sender_deceptive", evidence=f"suspicious TLD {sender_domain}")
        if claimed and not official_sender:
            if sender_domain not in FREE_MAIL_DOMAINS:
                if _lookalike_brand(claimed, sender_domain):
                    collector.add("sender_mismatch",
                                  evidence=f"{sender_domain} mimics '{claimed}'")
                else:
                    collector.add("sender_mismatch",
                                  evidence=f"{sender_domain} vs claimed '{claimed}'")
        elif not claimed and context_present and not deceptive_hit \
                and sender_domain not in FREE_MAIL_DOMAINS:
            collector.add("sender_unverifiable", evidence=sender_domain)
    else:
        pass  # note added later

    # ========================================================================
    # 6. Greeting / typos / attachments / social engineering / prize / misc.
    # ========================================================================
    greeting = next((g for g in GENERIC_GREETINGS if g in low), None)
    if greeting:
        collector.add("generic_greeting", evidence=greeting)

    typos = [bad for bad in TYPO_WORDS if bad in low]
    if typos:
        collector.add("typos", evidence=", ".join(typos), base=min(9, 3 * len(typos)))

    attach_hit = ATTACHMENT_SUSPICIOUS_EXT.search(content)
    if attach_hit:
        collector.add("attachment_suspicious", evidence=attach_hit.group(0))
    elif re.search(r"\b(?:attachment|attached file|open the attached)\b", content, re.IGNORECASE):
        collector.add("attachment_mention",
                      evidence=re.search(r"\b(?:attachment|attached file|open the attached)\b",
                                         content, re.IGNORECASE).group(0))

    # Social engineering: count DISTINCT non-negated instructions; each extra one
    # strengthens the signal (1 -> 18, 2 -> 22, 3+ -> 30). Negated mentions
    # ("we never ask you to pay via gift card") are treated as legitimacy.
    se_hits = []
    for phrase in SOCIAL_ENGINEERING:
        if phrase in _SE_PAYMENT_OVERLAP and bank_or_payment:
            continue
        pos = low.find(phrase)
        if pos != -1 and not _is_negated(low, pos):
            se_hits.append(phrase)
    if se_hits:
        collector.add("social_engineering",
                      evidence=", ".join(se_hits),
                      base=min(30, 18 + 4 * (len(se_hits) - 1)),
                      confidence=0.75 + 0.03 * min(5, len(se_hits)))

    prize_hit = None
    for phrase in PRIZE_ADVANCE_FEE:
        if phrase in _PRIZE_PAYMENT_OVERLAP and (
                bank_or_payment or collector.has("payment_request")
                or collector.has("job_offer_fee")):
            continue
        pos = low.find(phrase)
        if pos != -1 and not _is_negated(low, pos):
            prize_hit = phrase
            break
    if prize_hit:
        collector.add("prize_fee", evidence=prize_hit)

    gift_match = GIFTCARD_PAYMENT_RE.search(content)
    if gift_match and not _is_negated(low, gift_match.start()):
        collector.add("giftcard_payment", evidence=gift_match.group(0))

    if not cred_requested:
        unusual_hit = UNUSUAL_INSTRUCTIONS_RE.search(content)
        if unusual_hit:
            collector.add("unusual_instructions", evidence=unusual_hit.group(0))

    if not bank_or_payment and not collector.has("payment_request"):
        fin_hit = FINANCIAL_ACTION_RE.search(content)
        if fin_hit:
            collector.add("financial_action", evidence=fin_hit.group(0))

    # ========================================================================
    # 7. Combination checks (co-occurrence of DIFFERENT evidence - qualitative
    #    escalation, not double counting).
    # ========================================================================
    if cred_requested and len(urgency_hits) >= 3:
        collector.add("urgency_cred_combo",
                      evidence=", ".join(urgency_hits))

    critical_count = collector.strong_count()
    if critical_count >= 2:
        collector.add("critical_combo", evidence=f"{critical_count} strong indicators")

    # Job-scam combination checks: the fee is the anchor, and it escalates when
    # it co-occurs with a compensation claim or with further recruitment-scam
    # signals (identity documents, offer-loss threat, bank details).
    if collector.has("job_offer_fee") and collector.has("compensation_claim"):
        collector.add("compensation_fee_combo",
                      evidence="generous compensation demanded alongside an upfront fee")
    job_extra = [fid for fid in ("identity_document_request", "offer_loss_threat", "bank_request")
                 if collector.has(fid)]
    if collector.has("job_offer_fee") and job_extra:
        collector.add("job_scam_multi",
                      evidence="upfront fee combined with "
                               f"{len(job_extra)} further recruitment-scam signal(s)")

    # ========================================================================
    # 8. Legitimacy / trust indicators (only ever reduce the score).
    # ========================================================================
    legit = 0
    legit_notes = []
    if NEVER_ASK_RE.search(content):
        legit += abs(LEGIT_WEIGHTS["never_ask_password"])
        legit_notes.append(("Explicitly states it will never ask for passwords/OTPs", "success"))
    if claimed and sender_domain and _brand_official(claimed, sender_domain):
        legit += abs(LEGIT_WEIGHTS["sender_matches_claim"])
        legit_notes.append((f"Sender domain matches the claimed organisation ('{claimed}')", "success"))
    if claimed and any(_brand_official(claimed, l["host"]) for l in links):
        legit += abs(LEGIT_WEIGHTS["link_matches_claim"])
        legit_notes.append((f"Link domain matches the claimed organisation ('{claimed}')", "success"))
    name_hit = PERSONALIZED_GREETING_RE.search(content)
    if name_hit and name_hit.group(1).lower() not in NON_PERSONAL_NAMES:
        legit += abs(LEGIT_WEIGHTS["personalized_greeting"])
        legit_notes.append((f"Personalised greeting detected ('Dear {name_hit.group(1)}')", "success"))

    # ========================================================================
    # 9. Finalise score / confidence / category / explanation.
    # ========================================================================
    weak_raw, moderate_raw, strong_raw = _tier_totals(collector)
    risk_before_legit = _combine_risk(collector)
    risk = max(0, min(100, risk_before_legit - legit))

    cat = _risk_category(risk)
    has_sender = bool(sender)
    has_links = bool(links)
    has_subject = bool(subject)
    confidence = _compute_confidence(collector, has_sender, has_links, has_subject)

    reasons = []
    for f in collector.features.values():
        severity = "danger" if f.tier == "strong" else "warning"
        reasons.append({"severity": severity, "text": f.label, "points": f.base})
    for text, severity in legit_notes:
        reasons.append({"severity": severity, "text": text, "points": 0})

    if links:
        if not any((link_flags["ip"], link_flags["tld"], link_flags["lookalike"],
                    link_flags["shortener"], link_flags["cred"], link_flags["external"],
                    link_flags["mismatch"])):
            reasons.append({"severity": "success",
                            "text": "Found link(s); domains look consistent with the email", "points": 0})
    else:
        reasons.append({"severity": "info",
                        "text": "No links found in the email - link analysis not possible", "points": 0})

    if not sender:
        reasons.append({"severity": "info",
                        "text": "Sender address not provided - sender analysis skipped", "points": 0})
    if not collector.features:
        reasons.append({"severity": "info",
                        "text": "No obvious phishing indicators detected from the information provided.",
                        "points": 0})
    missing = []
    if not sender:
        missing.append("sender address")
    if not links:
        missing.append("links")
    if missing:
        reasons.append({"severity": "info",
                        "text": f"Information unavailable: no {' or '.join(missing)} to analyse.",
                        "points": 0})

    indicators = [f.label for f in collector.features.values()]
    features = [f.to_dict() for f in collector.features.values()]
    processing_ms = int((time.perf_counter() - start) * 1000)

    result = {
        "score": risk,
        "status": cat["status"],
        "category": cat["category"],
        "risk_label": cat["label"],
        "risk_emoji": cat["emoji"],
        "confidence": confidence,
        "features": features,
        "reasons": reasons,
        "indicators": indicators,
        "recommendation": RECOMMENDATIONS[cat["category"]],
        "details": {
            "suspicious_link_count": sum(1 for l in links
                                         if (l["is_ip"] or l["suspicious_tld"] or l["is_shortener"]
                                              or _is_credential_url(l)
                                              or (security_context
                                                  and EXTERNAL_LOGIN_PATH_RE.search(l["path"])))),
            "link_count": len(links),
            "urgency_count": len(urgency_hits),
            "feature_count": len(collector.features),
            "fake_sender": any(collector.has(f) for f in
                               ("sender_deceptive", "sender_mismatch")),
            "payment_request": collector.has("bank_request") or collector.has("payment_request"),
            "sender": sender,
            "sender_domain": sender_domain,
            "claimed_organisation": claimed,
            "link_domains": [l["host"] for l in links],
            "risk_category": cat["category"],
        },
        "processing_time_ms": processing_ms,
    }
    if trace:
        result["trace"] = _build_trace(
            content, collector, urgency_hits, se_hits, links, claimed,
            weak_raw, moderate_raw, strong_raw, risk_before_legit, legit,
            risk, cat, confidence,
        )
    return result


def persist_scan(app, user_id, content: str, payload: dict):
    """Persist an email scan. Never raises."""
    from models import db
    from models.scan import EmailScan

    try:
        details = payload.get("details", {})
        scan = EmailScan(
            user_id=user_id,
            email_content=content[:2000],
            trust_score=payload["score"],
            status=payload["status"],
            suspicious_link_count=details.get("suspicious_link_count", 0),
            urgency_count=details.get("urgency_count", 0),
            fake_sender=details.get("fake_sender", False),
            payment_request=details.get("payment_request", False),
            reasons=payload.get("reasons"),
        )
        db.session.add(scan)
        db.session.commit()
    except Exception:  # noqa: BLE001
        db.session.rollback()
        app.logger.exception("Failed to persist email scan")
