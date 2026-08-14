"""
Website / URL scanner.

Professional additive trust scoring. The score STARTS from nothing and is built
from trusted signals that AWARD points (max 100), minus deductions for CONFIRMED
risks only:

  Awards (trusted signals, cap 100):
    HTTPS +15 | valid SSL cert +15 | domain age (>5y +15 / 1-5y +10 /
    6-12m +5 / <6m +0) | reputation (trusted +20 / unknown +10 / poor +0) |
     not blacklisted +10 | security headers (HSTS/CSP/XFO/XCTO up to +10;
     HSTS also earned via the official preload list when the header is absent) |
     About/Contact/Privacy/Terms up to +10 | content quality up to +5

  Deductions (confirmed risks only):
    phishing keywords -20 | fake login -25 | hidden iframe -15 |
    JS obfuscation -15 | suspicious redirects -20 | mixed content -10 |
    invalid SSL -25 | homograph/typosquat -30 | malware -40 | blacklisted -50

  API failures (WHOIS/RDAP, Safe Browsing, VirusTotal) are NEVER deductions:
  the affected check is marked UNKNOWN and treated as "unknown" evidence.

The score is always computed dynamically from these signals - never a fixed or
fallback constant - so google.com, a brand-new domain, a stripped page and a
phishing clone all receive very different scores.

Risk levels: 95-100 Highly Trusted | 85-94 Trusted | 70-84 Moderate Risk |
40-69 Suspicious | 0-39 High Risk.

Backward-compatible surface: `scan_website(raw_url)` and `persist_scan(...)`
keep the previous envelope shape (score/status/reasons/details) and the `checks`
array now carries {id, name, status, award, deduction, text, detail}.
"""

import re
import ssl
import time
import socket
import warnings
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin

import requests

from config import Config
from models import db
from models.admin import BlacklistedDomain
from services.logger import get_logger
from services.scoring import (
    SUSPICIOUS_TLDS,
    SUSPICIOUS_URL_KEYWORDS,
)

logger = get_logger(__name__)

USER_AGENT = "TrustLensBot/1.0 (+https://trustlens.io)"

# Top-level domains that are nearly always safe (used to reward legit structure).
TRUSTED_TLDS = {".com", ".org", ".net", ".io", ".dev", ".edu", ".gov", ".co", ".app", ".ai"}

# Registrable domains on the official HSTS preload list (curated subset of
# well-known sites). Preloaded HSTS is enforced by browsers and cannot be
# switched off by the site, so a preloaded domain earns the HSTS award even
# when its homepage response omits the header (common for large edge-cached
# sites). Only fires when the header itself is absent - never double-counts.
HSTS_PRELOADED = {
    "google.com", "gstatic.com", "googleusercontent.com", "googleapis.com",
    "googletagmanager.com", "google-analytics.com", "goo.gl",
    "microsoft.com", "bing.com",
    "github.com", "facebook.com", "instagram.com", "whatsapp.com",
    "apple.com", "netflix.com", "linkedin.com", "mozilla.org", "wikipedia.org",
    "paypal.com", "cloudflare.com", "openai.com",
}

# Two-level public suffixes so registered-domain heuristics stay accurate.
MULTI_LABEL_TLDS = {
    "co.in", "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "org.au", "net.au",
    "com.br", "com.mx", "co.jp", "com.sg", "co.nz", "com.cn", "com.hk", "com.my",
    "com.ph", "com.pk", "co.za", "com.tr", "com.vn", "co.th", "com.tw", "com.eg",
    "com.sa", "co.il", "com.pe", "com.co", "com.ng", "co.ke", "com.ar", "com.gh",
}

# Content phrases that signal high-pressure / scam intent.
CONTENT_KEYWORDS = [
    "free gift", "prize", "winner", "lottery", "congratulations", "you have been selected",
    "claim now", "claim your", "limited time", "act fast", "act now", "urgent action",
    "verify your account", "update your payment", "confirm your password", "bank details",
    "wire transfer", "western union", "money gram", "pay immediately",
    "risk of suspension", "your account has been", "unusual activity", "security alert",
    "bitcoin", "crypto giveaway", "earn money fast", "make money online",
    "get rich", "investment opportunity", "guaranteed returns", "no deposit required",
]

# Well-known brands used for both homograph detection and impersonation checks.
BRAND_DOMAINS = {
    "paypal": "paypal.com", "google": "google.com", "gmail": "gmail.com",
    "facebook": "facebook.com", "microsoft": "microsoft.com", "apple": "apple.com",
    "netflix": "netflix.com", "amazon": "amazon.com", "whatsapp": "whatsapp.com",
    "instagram": "instagram.com", "twitter": "twitter.com", "linkedin": "linkedin.com",
    "paytm": "paytm.com", "phonepe": "phonepe.com", "googlepay": "google.com",
    "hdfc": "hdfcbank.com", "icici": "icicibank.com", "axis": "axisbank.com",
    "kotak": "kotak.com", "sbi": "onlinesbi.sbi", "snapchat": "snapchat.com",
    "tiktok": "tiktok.com", "binance": "binance.com", "coinbase": "coinbase.com",
    "flipkart": "flipkart.com", "zomato": "zomato.com", "swiggy": "swiggy.com",
    "fedex": "fedex.com", "dhl": "dhl.com", "ups": "ups.com", "irctc": "irctc.co.in",
    "worldremit": "worldremit.com", "cashapp": "cash.app", "venmo": "venmo.com",
}

# Unicode look-alike characters (Cyrillic/Greek) used in homograph attacks.
_CONFUSABLE = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ѕ": "s", "ⅰ": "i", "ᴠ": "v", "ё": "e",
    "А": "a", "Е": "e", "О": "o", "Р": "p", "С": "c", "У": "y", "Х": "x",
    "І": "i", "В": "v", "Н": "h", "Т": "t", "К": "k", "М": "m", "В": "v",
})

# Phrases scammers print as "trust seals" while the page is not secure.
TRUST_BADGE_PHRASES = [
    "secure checkout", "ssl secured", "verified by", "trusted site", "trust seal",
    "mcafee secure", "norton secured", "secure payment", "verified secure",
    "trusted security", "100% secure", "secured by", "safe and secure",
]

# Known ad network hosts (excessive ads signal low-quality/abusive sites).
AD_HOSTS = [
    "doubleclick", "googlesyndication", "googletagmanager", "adservice", "adsystem",
    "adserver", "taboola", "outbrain", "adzerk", "pubmatic", "criteo", "adsense",
    "moatads", "revcontent", "adnxs", "rubiconproject", "spotxchange",
]

# Tracking / tag-manager hosts that legitimately ship hidden iframes (GTM noscript).
BENIGN_TRACKER_HOSTS = {
    "googletagmanager.com", "google-analytics.com", "tagmanager.google.com",
    "stats.g.doubleclick.net", "googleads.g.doubleclick.net", "static.doubleclick.net",
    "googletag.com", "facebook.com", "connect.facebook.net",
}

# Threat types checked against Google Safe Browsing.
_GSB_THREAT_TYPES = [
    "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
]


# ---- URL / host helpers ----------------------------------------------------

def _normalise_url(raw: str) -> str:
    """Ensure a usable scheme; strip whitespace and trailing junk."""
    url = raw.strip()
    if not url:
        raise ValueError("URL cannot be empty")
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    url = url.rstrip("/")
    return url


def _domain_of(url: str) -> str:
    match = re.search(r"^https?://(?:www\.)?([^/?#]+)", url, re.IGNORECASE)
    return (match.group(1) if match else "").lower()


def _netloc(url: str) -> str:
    m = re.search(r"^[a-z]+://([^/?#]+)", url, re.IGNORECASE)
    return (m.group(1) if m else "").lower()


def _host_port(netloc: str) -> tuple:
    """Split netloc into (host, port). Handles IPv6 brackets."""
    if not netloc:
        return "", None
    if netloc.startswith("["):
        end = netloc.find("]")
        if end == -1:
            return netloc, None
        host = netloc[1:end]
        port = None
        rest = netloc[end + 1:]
        if rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
        return host, port
    if ":" in netloc:
        host, _, port = netloc.rpartition(":")
        if port.isdigit():
            return host, int(port)
        return netloc, None
    return netloc, None


def _is_raw_ip(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))


def _registered_domain(host: str) -> str:
    """Best-effort registered (registrable) domain without a PSL dependency."""
    host = (host or "").lower().strip()
    if _is_raw_ip(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_TLDS:
        return ".".join(labels[-3:])
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) > len(b):
        a, b = b, a
    prev = list(range(len(a) + 1))
    for i, cb in enumerate(b, 1):
        cur = [i]
        for j, ca in enumerate(a, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _confusable(host: str) -> str:
    """Translate look-alike unicode characters back to ASCII for comparison."""
    return host.translate(_CONFUSABLE).lower()


# ---- TLS probe --------------------------------------------------------------

def _tls_probe(host: str, port: int, timeout: int) -> dict:
    """Validate the TLS certificate of host:port. Never raises."""
    out = {"valid": False, "not_after": None, "issuer": "", "error": ""}
    if not host:
        return out
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((host, port or 443), timeout=timeout) as sock:
            sock.settimeout(timeout)
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                out["valid"] = True
                out["not_after"] = cert.get("notAfter", "")
                subj = dict(x[0] for x in cert.get("subject", ()))
                iss = dict(x[0] for x in cert.get("issuer", ()))
                out["issuer"] = iss.get("organizationName", "") or iss.get("commonName", "")
    except ssl.SSLCertVerificationError as exc:  # noqa: BLE001
        msg = str(exc)
        if "expired" in msg.lower():
            out["error"] = "expired"
        elif "self-signed" in msg.lower():
            out["error"] = "self-signed"
        else:
            out["error"] = "untrusted"
    except (ssl.SSLError, OSError) as exc:  # noqa: BLE001
        out["error"] = "unreachable"
    except Exception:  # noqa: BLE001
        out["error"] = "unknown"
    return out


def _cert_expiry_bool(not_after: str):
    """Return (valid, expiry_date) for an asn1 'notAfter' string."""
    if not not_after:
        return False, None
    try:
        cleaned = not_after.replace(" GMT", " UTC")
        expiry = datetime.strptime(cleaned, "%b %d %H:%M:%S %Y %Z")
        return expiry > datetime.now(timezone.utc).replace(tzinfo=None), expiry
    except ValueError:
        return True, None


# ---- RDAP / WHOIS -----------------------------------------------------------

def _rdap_lookup(domain: str, timeout: int) -> dict:
    """Query RDAP for registration date / registrar. Never raises."""
    out = {"registration": None, "registrar": "", "error": ""}
    if not domain or _is_raw_ip(domain):
        out["error"] = "no-public-whois"
        return out
    for endpoint in (
        f"https://rdap.org/domain/{domain}",
        f"https://rdap.verisign.com/com/v1/domain/{domain}",
    ):
        try:
            resp = requests.get(endpoint, timeout=timeout,
                                headers={"User-Agent": USER_AGENT})
            if resp.status_code != 200:
                continue
            data = resp.json()
            for ev in data.get("events", []):
                if ev.get("eventAction") == "registration" and ev.get("eventDate"):
                    out["registration"] = ev["eventDate"]
            for ent in data.get("entities", []):
                if "registrar" in ent.get("roles", []):
                    vcard = ent.get("vcardArray", [[]])
                    for row in vcard[1] if len(vcard) > 1 else []:
                        if row and row[0] == "fn" and len(row) > 3:
                            out["registrar"] = str(row[3])
            return out
        except Exception:  # noqa: BLE001
            continue
    out["error"] = "lookup-failed"
    return out


# ---- Page fetch -------------------------------------------------------------

def _fetch_page(url: str, timeout: int) -> dict:
    """Fetch a page following redirects. Returns rich metadata. Never raises."""
    info = {
        "reachable": False,
        "final_url": url,
        "status_code": 0,
        "history": [],
        "headers": {},
        "content": b"",
        "tls_error": "",
        "fetch_error": "",
        "content_type": "",
    }
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT

    def attempt(verify):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                resp = session.get(
                    url, timeout=timeout, allow_redirects=True, verify=verify,
                )
            return resp, None
        except requests.exceptions.SSLError as exc:
            return None, f"ssl:{str(exc)}"
        except requests.exceptions.RequestException as exc:
            return None, str(exc)
        except Exception as exc:  # noqa: BLE001
            return None, str(exc)

    resp, err = attempt(True)
    if resp is None and (err or "").startswith("ssl:"):
        info["tls_error"] = "untrusted"
        resp, err = attempt(False)  # analyse content even if cert is bad

    if resp is None:
        info["fetch_error"] = err or "unreachable"
        return info

    info["reachable"] = True
    info["final_url"] = resp.url
    info["status_code"] = resp.status_code
    info["history"] = [r.url for r in resp.history]
    info["headers"] = {k.lower(): v for k, v in resp.headers.items()}
    info["content_type"] = info["headers"].get("content-type", "").split(";")[0].strip()
    info["content"] = resp.content[:3_000_000]
    return info


# ---- HTML sniffer -----------------------------------------------------------

class _HtmlSniff(HTMLParser):
    """Collect the HTML signals the checks need. Stdlib only, no bs4."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text_parts: list = []
        self.title = ""
        self.meta_refresh: list = []
        self.forms: list = []              # {action, method, password}
        self._form_stack: list = []
        self.password_fields = 0
        self.inputs = 0
        self.external_script_srcs: list = []
        self.inline_script_bodies: list = []
        self.iframes: list = []            # {src, hidden, style}
        self.links: list = []              # (text, href)
        self._a_stack: list = []
        self.img_count = 0
        self.favicon = None
        self.hidden_css_elements = 0
        self.hidden_css_rules = 0
        self.insecure_active_refs = 0
        self.insecure_anchor_refs = 0
        self.hidden_text_parts: list = []
        self._hidden_stack: list = []
        self._in_script = False
        self._in_style = False
        self._in_title = False
        self._script_buf: list = []
        self._style_buf: list = []

    @staticmethod
    def _is_hidden_style(style: str) -> bool:
        if not style:
            return False
        low = style.lower().replace(" ", "")
        return any(
            tok in low
            for tok in ("display:none", "visibility:hidden", "opacity:0",
                        "opacity:0.0", "text-indent:-9999", "left:-9999",
                        "width:0px;height:0px", "width:0;height:0")
        )

    _ACTIVE_ASSET_TAGS = {"script", "iframe", "img", "embed", "object",
                          "video", "audio", "source", "track"}
    _VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input",
                  "link", "meta", "param", "source", "track", "wbr"}

    def _process_start(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        t = tag.lower()
        elem_hidden = self._is_hidden_style(a.get("style", "")) or a.get("hidden") is not None
        if elem_hidden:
            self.hidden_css_elements += 1
        if t not in self._VOID_TAGS:
            self._hidden_stack.append(elem_hidden)
        if t == "script":
            self._in_script = True
            self._script_buf = []
            src = a.get("src", "").strip()
            if src:
                self.external_script_srcs.append(src)
        elif t == "style":
            self._in_style = True
            self._style_buf = []
        elif t == "title":
            self._in_title = True
        elif t == "meta":
            if a.get("http-equiv", "").lower() == "refresh":
                content = a.get("content", "")
                m = re.search(r"url\s*=\s*(['\"]?)([^'\";]+)\1?", content, re.I)
                self.meta_refresh.append(m.group(2) if m else content)
        elif t == "link":
            if "icon" in a.get("rel", "").lower():
                self.favicon = a.get("href", "")
            if "stylesheet" in a.get("rel", "").lower() and a.get("href", "").startswith("http://"):
                self.insecure_active_refs += 1
        elif t == "form":
            self._form_stack.append({
                "action": a.get("action", "").strip(),
                "method": a.get("method", "").upper() or "GET",
                "password": False,
            })
        elif t == "input":
            self.inputs += 1
            if a.get("type", "").lower() == "password":
                self.password_fields += 1
                if self._form_stack:
                    self._form_stack[-1]["password"] = True
        elif t == "iframe":
            style = a.get("style", "")
            hidden = (
                self._is_hidden_style(style)
                or a.get("hidden") is not None
                or a.get("aria-hidden", "").lower() == "true"
                or a.get("width") in ("0", "0px")
                or a.get("height") in ("0", "0px")
            )
            self.iframes.append({"src": a.get("src", ""), "hidden": hidden, "style": style})
        elif t == "a":
            self._a_stack.append({"href": a.get("href", "").strip(), "text": []})
            if a.get("href", "").startswith("http://"):
                self.insecure_anchor_refs += 1
        elif t == "img":
            self.img_count += 1
        if t in self._ACTIVE_ASSET_TAGS and a.get("src", "").startswith("http://"):
            self.insecure_active_refs += 1

    def handle_starttag(self, tag, attrs):
        self._process_start(tag, attrs)

    def handle_startendtag(self, tag, attrs):
        self._process_start(tag, attrs)
        if tag.lower() not in self._VOID_TAGS and self._hidden_stack:
            self._hidden_stack.pop()

    def handle_endtag(self, tag):
        t = tag.lower()
        if t == "script":
            self.inline_script_bodies.append("".join(self._script_buf))
            self._in_script = False
        elif t == "style":
            body = "".join(self._style_buf)
            self.hidden_css_rules += len(re.findall(
                r"(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0\b|"
                r"text-indent\s*:\s*-?9999|left\s*:\s*-?9999)", body, re.I))
            self._in_style = False
        elif t == "title":
            self._in_title = False
        elif t == "form":
            if self._form_stack:
                self.forms.append(self._form_stack.pop())
        elif t == "a":
            if self._a_stack:
                item = self._a_stack.pop()
                self.links.append((" ".join(item["text"]).strip(), item["href"]))
        if self._hidden_stack:
            self._hidden_stack.pop()

    def handle_data(self, data):
        if self._in_script:
            self._script_buf.append(data)
        elif self._in_style:
            self._style_buf.append(data)
        elif self._in_title:
            self.title += data
        else:
            self.text_parts.append(data)
            if self._a_stack:
                self._a_stack[-1]["text"].append(data)
            if any(self._hidden_stack):
                self.hidden_text_parts.append(data)

    @property
    def visible_text(self) -> str:
        return re.sub(r"\s+", " ", " ".join(self.text_parts)).strip()

    @property
    def scripts_joined(self) -> str:
        return "\n".join(self.inline_script_bodies)


# ---- Check result helper ----------------------------------------------------

def _chk(cid: str, name: str, status: str, award: int = 0, deduction: int = 0,
         text: str = "", detail: str = ""):
    """Build a check result for the table.

    `status` is passed/failed/info. Passed (and info) checks carry an optional
    `award` (points earned toward the trust score); failed checks carry an
    optional `deduction`. A check never carries both a positive award and a
    positive deduction at the same time.
    """
    if status == "failed":
        sev = "danger" if deduction >= 20 else "warning"
    elif status == "passed":
        sev = "success"
    else:
        sev = "info"
    return {
        "id": cid, "name": name, "status": status,
        "award": int(award), "deduction": int(deduction),
        "points": int(award) + int(deduction),
        "severity": sev, "text": text, "detail": detail,
    }


# ---- Check implementations ---------------------------------------------------

def _check_https(ctx) -> dict:
    scheme = ctx["final_url"].split(":", 1)[0].lower() if ctx["final_url"] else "http"
    if scheme == "https" and ctx["reachable"]:
        return _chk("https", "HTTPS encryption", "passed", 15, 0,
                    "Page is served over HTTPS - transport is encrypted.",
                    ctx["final_url"][:120])
    if scheme == "https":
        return _chk("https", "HTTPS encryption", "failed", 0, 0,
                    "URL uses HTTPS but the site could not be reached to verify it.")
    return _chk("https", "HTTPS encryption", "failed", 0, 0,
                "Page is NOT served over HTTPS - no HTTPS trust signal earned.")


def _check_security_headers(ctx) -> dict:
    if not ctx["reachable"]:
        return _chk("security_headers", "Security headers", "info", 0, 0,
                    "Site could not be reached - security headers cannot be inspected.")
    h = ctx.get("headers") or {}
    found = {}
    if "strict-transport-security" in h:
        found["HSTS"] = 4
    if "content-security-policy" in h or "content-security-policy-report-only" in h:
        found["CSP" + (" (report-only)" if "content-security-policy" not in h else "")] = 3
    if "x-frame-options" in h:
        found["X-Frame-Options"] = 2
    if "x-content-type-options" in h:
        found["X-Content-Type-Options"] = 1
    award = sum(found.values())
    if "strict-transport-security" not in h:
        rd = _registered_domain(ctx.get("host") or "")
        if rd in HSTS_PRELOADED:
            found["HSTS (preload)"] = 4
            award += 4
    award = min(award, 10)
    ctx["security_headers"] = sorted(found)
    if award:
        return _chk("security_headers", "Security headers", "passed", award, 0,
                    "Security hardening headers present ("
                    + ", ".join(found) + ").")
    return _chk("security_headers", "Security headers", "failed", 0, 0,
                "No security hardening headers found "
                "(HSTS / CSP / X-Frame-Options / X-Content-Type-Options).")


def _check_ssl(ctx) -> dict:
    if ctx["final_url"].split(":", 1)[0].lower() != "https":
        return _chk("ssl", "SSL certificate validity", "info", 0, 0,
                    "No HTTPS connection - SSL award not applicable.")
    if not ctx["reachable"]:
        return _chk("ssl", "SSL certificate validity", "info", 0, 0,
                    "Site could not be reached - certificate cannot be verified (UNKNOWN).")
    probe = ctx.get("tls_probe") or {}
    if probe.get("valid"):
        valid, expiry = _cert_expiry_bool(probe.get("not_after", ""))
        if not valid:
            return _chk("ssl", "SSL certificate validity", "failed", 0, 25,
                        f"SSL certificate has EXPIRED ({expiry.date()}) - "
                        "cannot confirm a secure identity.")
        issuer = probe.get("issuer") or "unknown issuer"
        return _chk("ssl", "SSL certificate validity", "passed", 15, 0,
                    "SSL certificate is valid and trusted.", f"Issuer: {issuer}")
    err = probe.get("error", "unknown")
    label = {"expired": "has expired", "self-signed": "is self-signed",
             "untrusted": "is not trusted", "unreachable": "could not be verified"}
    return _chk("ssl", "SSL certificate validity", "failed", 0, 25,
                f"SSL certificate {label.get(err, 'could not be verified')} - "
                "cannot confirm a secure identity.")


def _check_domain_age(ctx) -> dict:
    reg = ctx.get("registration_date")
    rd = ctx.get("registered_domain", "")
    if not rd or _is_raw_ip(rd) or not reg:
        return _chk("domain_age", "Domain age", "info", 0, 0,
                    "Domain age could not be verified (no WHOIS/RDAP record) - "
                    "treated as UNKNOWN.")
    try:
        dt = datetime.fromisoformat(reg.replace("Z", "+00:00"))
        days = max(0, int((datetime.now(timezone.utc) - dt).total_seconds() // 86400))
    except ValueError:
        return _chk("domain_age", "Domain age", "info", 0, 0,
                    "Domain age could not be parsed - treated as UNKNOWN.")
    ctx["domain_age_days"] = days
    reg_line = f"Registered: {dt.date()}"
    if days >= 1826:
        return _chk("domain_age", "Domain age", "passed", 15, 0,
                    f"Domain is well-established (~{round(days / 365, 1)} years old).",
                    reg_line)
    if days >= 365:
        return _chk("domain_age", "Domain age", "passed", 10, 0,
                    f"Domain is {round(days / 365, 1)} year(s) old.", reg_line)
    if days >= 183:
        return _chk("domain_age", "Domain age", "passed", 5, 0,
                    f"Domain is {days} days old (6-12 months).", reg_line)
    return _chk("domain_age", "Domain age", "failed", 0, 0,
                f"Domain is only {days} days old - very recently registered.",
                reg_line)


def _check_whois(ctx) -> dict:
    rd = ctx.get("registered_domain", "")
    if not rd or _is_raw_ip(rd):
        return _chk("whois", "WHOIS information", "info", 0, 0,
                    "No public WHOIS record for a raw IP address.")
    if ctx.get("whois_error"):
        return _chk("whois", "WHOIS information", "info", 0, 0,
                    "WHOIS registry lookup failed - ownership could not be "
                    "verified (UNKNOWN, no deduction).")
    reg = ctx.get("registrar") or "unknown registrar"
    return _chk("whois", "WHOIS information", "passed", 0, 0,
                "WHOIS record found.", f"Registrar: {reg}")


def _check_blacklist(ctx) -> dict:
    if ctx.get("blacklisted"):
        return _chk("blacklist", "Blacklist reputation", "failed", 0, 50,
                    f"Domain is blacklisted in the TrustLens threat database: "
                    f"{ctx['blacklist_domain']}.")
    return _chk("blacklist", "Blacklist reputation", "passed", 10, 0,
                "Domain is not present in the local blacklist.")


def _check_reputation(ctx) -> dict:
    """External reputation: trusted +20 / unknown +10 / poor +0.

    A failed external lookup (Safe Browsing / VirusTotal unreachable or not
    configured) is NEVER a deduction - the result is marked UNKNOWN and the
    site falls into the "unknown" reputation bucket.
    """
    rd = ctx.get("registered_domain", "")
    gsb_threats = ctx.get("gsb_threats", []) or []
    gsb_checked = ctx.get("gsb_checked", False)

    vt = {}
    if rd and not _is_raw_ip(rd):
        try:
            from services.qr_scanner import _virustotal_domain
            vt = _virustotal_domain(rd)
        except Exception:  # noqa: BLE001
            vt = {"checked": False, "reason": "lookup error"}
    ctx["virustotal"] = vt

    # ---- Poor reputation (confirmed external risk) ------------------------
    vt_malicious = vt.get("malicious", 0) if vt.get("checked") else 0
    vt_suspicious = vt.get("suspicious", 0) if vt.get("checked") else 0
    mal_deduct = 40 if ("MALWARE" in gsb_threats or vt_malicious > 0) else 0
    phish_deduct = 20 if "SOCIAL_ENGINEERING" in gsb_threats else 0
    soft_deduct = 10 if any(
        t in gsb_threats for t in ("UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION")
    ) else 0
    total_deduct = mal_deduct + phish_deduct + soft_deduct
    poor = bool(ctx.get("blacklisted")) or bool(gsb_threats) or vt_malicious > 0 or vt_suspicious >= 2

    ctx["reputation"] = "unknown"
    if poor:
        ctx["reputation"] = "poor"
        why = []
        if ctx.get("blacklisted"):
            why.append("blacklisted")
        if gsb_threats:
            why.append("Google Safe Browsing flagged: " + ", ".join(gsb_threats[:3]))
        if vt_malicious > 0:
            why.append(f"VirusTotal: {vt_malicious} malicious engine(s)")
        if vt_suspicious >= 2 and vt_malicious == 0:
            why.append(f"VirusTotal: {vt_suspicious} suspicious engine(s)")
        text = "External reputation is POOR - " + "; ".join(why[:3]) + "."
        if total_deduct:
            text += " Confirmed threat deductions applied."
        return _chk("reputation", "External reputation", "failed", 0, total_deduct, text)

    # ---- Trusted reputation (verified clean / mature domain) --------------
    gsb_clean = bool(gsb_checked) and not gsb_threats
    vt_clean = bool(vt.get("checked")) and vt_malicious == 0 and vt_suspicious == 0
    age = ctx.get("domain_age_days")
    mature = (age is not None and age >= 1826
              and bool((ctx.get("tls_probe") or {}).get("valid"))
              and not ctx.get("blacklisted"))
    if gsb_clean or vt_clean or mature:
        ctx["reputation"] = "trusted"
        return _chk("reputation", "External reputation", "passed", 20, 0,
                    "Domain reputation is TRUSTED (verified clean and / or a "
                    "mature, long-registered domain with a valid certificate).")

    # ---- Unknown reputation -----------------------------------------------
    return _chk("reputation", "External reputation", "info", 10, 0,
                "Reputation UNKNOWN - could not be independently verified "
                "(external reputation services unavailable). No deduction applied.")


def _check_keywords(ctx) -> dict:
    url_hits = [k for k in SUSPICIOUS_URL_KEYWORDS if k in ctx["url"].lower()]
    content_hits = [k for k in CONTENT_KEYWORDS if k in ctx["text_lower"]]
    ctx["suspicious_keywords"] = list(dict.fromkeys(url_hits + content_hits))
    if ctx["suspicious_keywords"]:
        shown = ", ".join(ctx["suspicious_keywords"][:5])
        return _chk("keywords", "Suspicious keywords", "failed", 0, 20,
                    f"Suspicious wording found: {shown}.",
                    f"{len(url_hits)} in URL, {len(content_hits)} in page content")
    return _chk("keywords", "Suspicious keywords", "passed", 0, 0,
                "No high-pressure or scam-style wording detected.")


def _check_hidden_iframe(ctx) -> dict:
    hidden = [f for f in ctx["iframes"] if f["hidden"]]
    ctx["hidden_iframes"] = hidden

    def _benign(iframe):
        host = _netloc(iframe.get("src", "")).split(":")[0]
        return host.removeprefix("www.") in BENIGN_TRACKER_HOSTS

    suspicious_hidden = [f for f in hidden if not _benign(f)]
    if suspicious_hidden:
        src = suspicious_hidden[0]["src"][:120] or "(inline content)"
        return _chk("hidden_iframe", "Hidden iframes", "failed", 0, 15,
                    f"{len(suspicious_hidden)} hidden iframe(s) loading content "
                    "from another party - a classic cloaking / clickjacking "
                    "technique.", src)
    if hidden:
        return _chk("hidden_iframe", "Hidden iframes", "info", 0, 0,
                    f"{len(hidden)} hidden iframe(s) from known tracking providers "
                    "only (e.g. tag managers).")
    cross = [f for f in ctx["iframes"]
             if f["src"] and _netloc(f["src"]) and _netloc(f["src"]).split(":")[0]
             != ctx["netloc_host"]]
    if ctx["iframes"]:
        if cross:
            return _chk("hidden_iframe", "Hidden iframes", "info", 0, 0,
                        f"{len(cross)} iframe(s) load content from another domain.")
        return _chk("hidden_iframe", "Hidden iframes", "passed", 0, 0,
                    "No hidden iframes; iframes load from the same site.")
    return _chk("hidden_iframe", "Hidden iframes", "passed", 0, 0,
                "No iframes detected.")


def _check_obfuscation(ctx) -> dict:
    bodies = ctx["inline_script_bodies"]
    sj = "\n".join(bodies)
    if not sj.strip():
        return _chk("obfuscation", "JavaScript obfuscation", "passed", 0, 0,
                    "No inline JavaScript to obfuscate.")
    # Confirmed obfuscation: code being DECODED or ESCAPED and then executed.
    strong = []
    for body in bodies:
        if re.search(r"\beval\s*\(", body) and re.search(
            r"(atob\s*\(|fromCharCode\s*\(|unescape\s*\(|\\x[0-9a-fA-F]{2}"
            r"|[A-Za-z0-9+/]{80,}={0,2})", body
        ):
            strong.append("eval() running decoded or escaped code")
            break
    if re.search(r"\bunescape\s*\([^)]*\\x", sj):
        strong.append("unescape() with escaped payload")
    if re.search(r"document\.write\s*\([^)]*\\x", sj):
        strong.append("escaped document.write()")
    if re.search(r"\batob\s*\(\s*['\"][^'\"]{80,}", sj):
        strong.append("runtime base64 decode of a large blob")
    # Escape-heavy plus base64 co-occurrence is a HEURISTIC: legit minified
    # bundles also contain these, so it is noted but never deducted.
    hex_esc = len(re.findall(r"\\x[0-9a-fA-F]{2}", sj))
    uni_esc = len(re.findall(r"\\u[0-9a-fA-F]{4}", sj))
    b64_blobs = len(re.findall(r"[A-Za-z0-9+/]{80,}={0,2}", sj))
    notes = []
    if (hex_esc + uni_esc) > 2000 and b64_blobs > 1:
        notes.append(f"{hex_esc + uni_esc} escaped characters plus base64 blobs")
    if b64_blobs > 12:
        notes.append("many large base64-like strings")
    if strong:
        return _chk("obfuscation", "JavaScript obfuscation", "failed", 0, 15,
                    f"Obfuscated JavaScript detected ({', '.join(strong[:3])}) - "
                    "commonly used to hide malicious behaviour.")
    if notes:
        return _chk("obfuscation", "JavaScript obfuscation", "info", 0, 0,
                    "JavaScript shows obfuscation-like patterns that are also "
                    "common in minified bundles - not counted as a confirmed risk ("
                    + "; ".join(notes[:2]) + ").")
    return _chk("obfuscation", "JavaScript obfuscation", "passed", 0, 0,
                "JavaScript is not obfuscated.")


def _check_external_scripts(ctx) -> dict:
    srcs = ctx["external_script_srcs"]
    hosts = set()
    suspicious_host = None
    for src in srcs:
        host = _netloc(urljoin(ctx["final_url"], src))
        if not host:
            continue
        hosts.add(host)
        if _is_raw_ip(host) or any(host.endswith(t) for t in SUSPICIOUS_TLDS):
            suspicious_host = suspicious_host or host
    ctx["external_script_hosts"] = sorted(hosts)
    if suspicious_host:
        return _chk("external_scripts", "External scripts", "info", 0, 0,
                    f"Script loaded from a high-risk host: {suspicious_host} - noted.")
    if len(hosts) > 15:
        return _chk("external_scripts", "External scripts", "info", 0, 0,
                    f"Page loads scripts from {len(hosts)} different hosts - "
                    "unusually many third-party scripts.")
    if len(hosts) > 8:
        return _chk("external_scripts", "External scripts", "info", 0, 0,
                    f"Page loads scripts from {len(hosts)} different hosts.")
    if not srcs:
        return _chk("external_scripts", "External scripts", "passed", 0, 0,
                    "No external scripts loaded.")
    return _chk("external_scripts", "External scripts", "passed", 0, 0,
                f"Scripts load from {len(hosts)} trusted host(s).",
                ", ".join(sorted(hosts)[:5]))


def _check_login_form(ctx) -> dict:
    if not ctx["forms"]:
        return _chk("login_form", "Login form detection", "passed", 0, 0,
                    "No forms on the page.")
    off_domain = []
    for f in ctx["forms"]:
        if not f["action"]:
            continue
        url = urljoin(ctx["final_url"], f["action"])
        if _netloc(url) and _netloc(url) != ctx["netloc_host"]:
            off_domain.append(url[:120])
    ctx["off_domain_form_actions"] = off_domain
    if off_domain:
        return _chk("login_form", "Login form detection", "failed", 0, 25,
                    "A form submits data to a DIFFERENT domain - a hallmark of "
                    "fake login pages.", off_domain[0])
    if any(f["password"] for f in ctx["forms"]):
        return _chk("login_form", "Login form detection", "passed", 0, 0,
                    "Login form detected; it submits to this same domain.")
    return _chk("login_form", "Login form detection", "passed", 0, 0,
                "Forms submit to this same domain.")


def _check_password(ctx) -> dict:
    if ctx["password_fields"] == 0:
        return _chk("password", "Password field analysis", "passed", 0, 0,
                    "No password fields on the page.")
    ctx["password_field_count"] = ctx["password_fields"]
    if ctx["final_url"].split(":", 1)[0].lower() != "https":
        return _chk("password", "Password field analysis", "failed", 0, 25,
                    "Password field present on a NON-HTTPS page - credentials "
                    "would be sent in plain text.")
    if ctx.get("off_domain_form_actions"):
        return _chk("password", "Password field analysis", "failed", 0, 25,
                    "Password field submits to a different domain - credentials "
                    "would be stolen.")
    return _chk("password", "Password field analysis", "passed", 0, 0,
                "Password fields are submitted securely to this domain.")


def _check_mixed_content(ctx) -> dict:
    if ctx["final_url"].split(":", 1)[0].lower() != "https":
        return _chk("mixed_content", "Mixed content", "info", 0, 0,
                    "Page is not HTTPS - mixed-content rule not applicable.")
    active = ctx["insecure_active_refs"]
    anchor = ctx["insecure_anchor_refs"]
    ctx["mixed_content_count"] = active
    ctx["insecure_anchor_refs"] = anchor
    if active >= 1:
        return _chk("mixed_content", "Mixed content", "failed", 0, 10,
                    f"{active} insecure (http://) active resource(s) (scripts, "
                    "iframes, images, styles) referenced from an HTTPS page - "
                    "a security downgrade browsers will block.")
    if anchor:
        return _chk("mixed_content", "Mixed content", "info", 0, 0,
                    "No active insecure resources; a few http:// hyperlinks "
                    "only (not a security risk).")
    return _chk("mixed_content", "Mixed content", "passed", 0, 0,
                "No insecure resources referenced from the HTTPS page.")


def _same_registered(a: str, b: str) -> bool:
    return _registered_domain(a) == _registered_domain(b)


def _check_redirects(ctx) -> dict:
    hops = ctx["history"]
    ctx["redirect_count"] = len(hops)
    final_host = ctx["netloc_host"]
    cross = [u for u in hops
             if _netloc(u) and not _same_registered(_netloc(u).split(":")[0], final_host)]
    meta = [u for u in ctx["meta_refresh"]
            if _netloc(u) and not _same_registered(_netloc(u).split(":")[0], final_host)]
    if len(hops) >= 5 or cross or meta:
        detail = ""
        if len(hops) >= 5:
            detail = f"{len(hops)} redirect hops"
        elif cross:
            detail = cross[0][:120]
        elif meta:
            detail = meta[0][:120]
        return _chk("redirects", "Redirect chains", "failed", 0, 20,
                    "Suspicious redirect chain - the page redirects through "
                    "another domain or an excessive number of hops, which is "
                    "used to hide the real destination.", detail)
    if len(hops) >= 2 or ctx["meta_refresh"]:
        return _chk("redirects", "Redirect chains", "info", 0, 0,
                    f"{len(hops)} redirect hop(s) within the same domain - noted, "
                    "not suspicious on its own.")
    return _chk("redirects", "Redirect chains", "passed", 0, 0,
                "No suspicious redirects.")


def _check_url_structure(ctx) -> dict:
    host = ctx["host"]
    url = ctx["url"]
    issues = []
    if _is_raw_ip(host.split(":")[0]):
        issues.append(("Raw IP address used instead of a domain", 30))
    if "@" in url:
        issues.append(("URL contains an '@' character - hides the real host", 20))
    if "xn--" in host:
        issues.append(("Punycode (IDN) domain - possible lookalike attack", 15))
    tld = next((t for t in SUSPICIOUS_TLDS if host.endswith(t)), None)
    if tld:
        issues.append((f"High-risk domain extension: {tld}", 15))
    elif any(host.endswith(t) for t in TRUSTED_TLDS):
        ctx["trusted_tld"] = True
    sub = host.count(".") - 1 if host.count(".") >= 1 else 0
    if sub > 3:
        issues.append((f"Excessive subdomains ({sub}) - unusual for legitimate sites", 10))
    if len(url) > 500:
        issues.append(("Extremely long URL - strong phishing indicator", 15))
    elif len(url) > 200:
        issues.append(("Very long URL - used to hide the real destination", 10))
    if _host_port(host)[1] is not None:
        issues.append(("URL specifies a non-standard port", 5))
    if issues:
        worst = max(issues, key=lambda x: x[1])
        return _chk("url_structure", "URL structure", "info", 0, 0,
                    worst[0], "; ".join(i[0] for i in issues))
    return _chk("url_structure", "URL structure", "passed", 0, 0,
                "URL structure looks normal.")


def _check_homograph(ctx) -> dict:
    rd = ctx.get("registered_domain", "")
    if not rd or _is_raw_ip(rd):
        return _chk("homograph", "Homograph / spoofing", "passed", 0, 0,
                    "No domain to compare (raw IP or missing).")
    rd_ascii = _confusable(rd)
    matches = []
    for brand, canon in BRAND_DOMAINS.items():
        canon_rd = _registered_domain(canon)
        if rd == canon_rd:
            continue
        if _levenshtein(rd, canon_rd) <= 2:
            matches.append(brand)
        elif canon_rd and (canon_rd in rd or rd in canon_rd) and len(rd) != len(canon_rd):
            matches.append(brand)
        elif rd_ascii == canon_rd:
            matches.append(brand)
    ctx["homograph_matches"] = matches
    if matches:
        return _chk("homograph", "Homograph / spoofing", "failed", 0, 30,
                    "Domain closely resembles a well-known brand "
                    f"({', '.join(sorted(set(matches))[:4])}) - possible "
                    "typosquatting or lookalike attack.", f"Domain: {rd}")
    return _chk("homograph", "Homograph / spoofing", "passed", 0, 0,
                "No lookalike domain patterns detected.")


def _check_content(ctx) -> dict:
    n = ctx["text_chars"]
    ctx["text_chars"] = n
    award = 0
    parts = []
    if n >= 200:
        award += 1
        parts.append("meaningful content")
        if not ctx.get("suspicious_keywords"):
            award += 1
            parts.append("no suspicious wording")
    if ctx["title"]:
        award += 1
        parts.append("clear page title (branding)")
    if award:
        return _chk("content", "Content quality", "passed", award, 0,
                    "Content quality signals earned: " + "; ".join(parts) + ".",
                    f"{n:,} characters of readable text.")
    probs = []
    if n < 200:
        probs.append(f"almost no readable text ({n} characters)")
    if not ctx["title"]:
        probs.append("no page title")
    return _chk("content", "Content quality", "failed", 0, 0, " ".join(probs))


def _missing_page_check(ctx, cid, name, tokens, award) -> dict:
    haystack = ctx["page_link_signals"]
    if any(t in haystack for t in tokens):
        return _chk(cid, name, "passed", award, 0, f"Page links to its {name.lower()}.")
    return _chk(cid, name, "failed", 0, 0, f"No {name.lower()} page found - "
                "legitimate businesses publish one.")


def _check_about(ctx) -> dict:
    return _missing_page_check(ctx, "about", "About page",
                               ("about", "about-us", "aboutus", "our-story", "company"), 2)


def _check_contact(ctx) -> dict:
    return _missing_page_check(ctx, "contact", "Contact page",
                               ("contact", "contact-us", "contactus", "get-in-touch"), 3)


def _check_privacy(ctx) -> dict:
    return _missing_page_check(ctx, "privacy", "Privacy policy",
                               ("privacy", "privacy-policy", "privacypolicy", "data-policy"), 3)


def _check_terms(ctx) -> dict:
    return _missing_page_check(ctx, "terms", "Terms & conditions",
                               ("terms", "terms-of-service", "terms-of-use", "termsandconditions",
                                "tos", "legal"), 2)


def _check_grammar(ctx) -> dict:
    text = ctx["visible_text"]
    flags = []
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    for s in sentences:
        words = re.findall(r"[A-Za-z']+", s)
        if len(words) >= 8 and s.isupper() and not s.startswith(("HTTP", "HTTPS", "WWW")):
            flags.append("ALL-CAPS sentence")
            break
    if re.search(r"!{3,}", text):
        flags.append("excessive exclamation marks")
    if re.search(r"\?{3,}", text):
        flags.append("excessive question marks")
    if re.search(r"\b(?=[a-zA-Z]{4,})[a-zA-Z]*([a-zA-Z])\1\1[a-zA-Z]*\b", text):
        flags.append("stretched/repeated characters (e.g. 'fr0000m')")
    long_sent = [s for s in sentences if len(s.strip()) > 40]
    bad_end = sum(1 for s in long_sent if not s.strip().endswith((".", "!", "?")))
    if bad_end >= 8 and long_sent and bad_end / len(long_sent) > 0.3:
        flags.append(f"{bad_end} of {len(long_sent)} long sentences missing terminal punctuation")
    if re.search(r"\b(?:l0gin|v3rify|s3cur3|p4y|m0ney|acc0unt|cl1ck|c0mplete|1nvest|fr3e|b0nus|p4ssw0rd)\b",
                 text, re.I):
        flags.append("leetspeak / altered spelling")
    ctx["grammar_flags"] = flags
    if len(text.strip()) < 80:
        return _chk("grammar", "Grammar & spelling quality", "info", 0, 0,
                    "Too little text to assess writing quality.")
    if not flags:
        return _chk("grammar", "Grammar & spelling quality", "passed", 2, 0,
                    "Writing looks professional and natural.")
    if len(flags) >= 4:
        return _chk("grammar", "Grammar & spelling quality", "failed", 0, 0,
                    f"Poor writing quality ({len(flags)} issues): {'; '.join(flags[:3])}.")
    return _chk("grammar", "Grammar & spelling quality", "failed", 0, 0,
                f"Writing quality issues detected: {'; '.join(flags[:3])}.")


def _check_brand_impersonation(ctx) -> dict:
    title_lower = (ctx["title"] or "").lower()
    found = [b for b in BRAND_DOMAINS if re.search(r"\b" + re.escape(b) + r"\b", title_lower)]
    ctx["brand_title_hits"] = found
    if not found:
        return _chk("impersonation", "Brand impersonation", "passed", 0, 0,
                    "No well-known brand claimed in the page title.")
    rd = ctx.get("registered_domain", "")
    official = any(rd == _registered_domain(BRAND_DOMAINS[b])
                   or (rd and rd.endswith("." + _registered_domain(BRAND_DOMAINS[b])))
                   for b in found)
    if official:
        return _chk("impersonation", "Brand impersonation", "passed", 0, 0,
                    "Brand in title matches the official domain.")
    login_context = ctx["password_fields"] > 0 or bool(ctx["suspicious_keywords"])
    if login_context:
        return _chk("impersonation", "Brand impersonation", "info", 0, 0,
                    f"Page claims to be {', '.join(found[:3])} but is NOT hosted on "
                    "the brand's official domain - treat any login here with extreme "
                    "caution.",
                    f"Title: {ctx['title'][:100]}")
    return _chk("impersonation", "Brand impersonation", "info", 0, 0,
                f"Page mentions {', '.join(found[:3])} in its title but the domain "
                "is unrelated - verify the address carefully.")


def _check_favicon(ctx) -> dict:
    if ctx["favicon"] or any("/favicon.ico" in u for _, u in ctx["links"]):
        return _chk("favicon", "Favicon presence", "passed", 0, 0,
                    "Site provides a favicon.")
    return _chk("favicon", "Favicon presence", "info", 0, 0,
                "No favicon detected - common on hastily-built fake sites.")


def _check_trust_badges(ctx) -> dict:
    badges = [p for p in TRUST_BADGE_PHRASES if p in ctx["text_lower"]]
    ctx["trust_badge_mentions"] = badges
    if not badges:
        return _chk("trust_badges", "Fake trust badges", "passed", 0, 0,
                    "No trust-seal claims detected.")
    secure = ctx["final_url"].split(":", 1)[0].lower() == "https"
    if not secure:
        return _chk("trust_badges", "Fake trust badges", "info", 0, 0,
                    "Page claims trust badges/security seals but is NOT served "
                    "over HTTPS - unverifiable security claims.",
                    ", ".join(badges[:4]))
    return _chk("trust_badges", "Fake trust badges", "info", 0, 0,
                "Page claims trust badges; authenticity cannot be verified "
                "server-side.")


def _check_broken_links(ctx) -> dict:
    final_url = ctx["final_url"]
    final_host = ctx["netloc_host"]
    internal = []
    seen = set()
    for _, href in ctx["links"]:
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        abs_url = urljoin(final_url, href)
        if _netloc(abs_url).split(":")[0] != final_host:
            continue
        if abs_url in seen:
            continue
        seen.add(abs_url)
        internal.append(abs_url)
        if len(internal) >= 6:
            break
    ctx["sampled_links"] = internal
    if not internal:
        return _chk("broken_links", "Broken links", "info", 0, 0,
                    "No internal links available to test.")
    broken = 0
    budget_deadline = time.perf_counter() + 7
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    for link in internal:
        if time.perf_counter() > budget_deadline:
            break
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                resp = session.get(link, timeout=2.5, allow_redirects=False, verify=False)
            if resp.status_code >= 400:
                broken += 1
        except Exception:  # noqa: BLE001
            broken += 1
    ctx["broken_link_count"] = broken
    if broken:
        return _chk("broken_links", "Broken links", "info", 0, 0,
                    f"{broken} of {len(internal)} sampled internal links failed to load - "
                    "sign of an abandoned or hastily-built site.")
    return _chk("broken_links", "Broken links", "passed", 0, 0,
                f"All {len(internal)} sampled internal links loaded successfully.")


def _check_image_only(ctx) -> dict:
    if ctx["text_chars"] < 200 and ctx["img_count"] >= 3:
        return _chk("image_only", "Image-only page", "info", 0, 0,
                    "Page has almost no text but many images - content-poor page "
                    "with no verifiable information.")
    return _chk("image_only", "Image-only page", "passed", 0, 0,
                "Page is not image-only.")


def _check_popups(ctx) -> dict:
    sj = ctx["scripts_joined"]
    n = len(re.findall(r"window\.open\s*\(|alert\s*\(|confirm\s*\(|prompt\s*\(", sj))
    ctx["popup_count"] = n
    if n >= 5:
        return _chk("popups", "Excessive popups", "info", 0, 0,
                    f"Scripts trigger popups/overlays {n} times - aggressive "
                    "ad or scam behaviour.")
    if n >= 1:
        return _chk("popups", "Excessive popups", "info", 0, 0,
                    f"Scripts may open {n} popup(s)/dialog(s).")
    return _chk("popups", "Excessive popups", "passed", 0, 0,
                "No popup-triggering scripts detected.")


def _check_ads(ctx) -> dict:
    sj_low = ctx["scripts_joined"].lower()
    n = sum(1 for s in ctx["external_script_srcs"] if any(h in s.lower() for h in AD_HOSTS))
    n += len(re.findall(r"advertisement|sponsored|ads by", ctx["text_lower"]))
    ctx["ad_markers"] = n
    if n >= 5:
        return _chk("ads", "Excessive ads", "info", 0, 0,
                    f"{n} ad network markers detected - heavy advertising is a "
                    "hallmark of low-quality or malicious pages.")
    if n >= 2:
        return _chk("ads", "Excessive ads", "info", 0, 0,
                    f"{n} ad network markers detected.")
    return _chk("ads", "Excessive ads", "passed", 0, 0,
                "No excessive advertising detected.")


def _check_hidden_css(ctx) -> dict:
    hidden_text = " ".join(ctx["hidden_text_parts"]).strip()
    ht_len = len(hidden_text)
    n = ctx["hidden_css_elements"]
    ctx["hidden_css_count"] = ht_len
    # The dangerous cloaking technique hides KEYWORD TEXT with CSS. Hiding UI
    # (modals, dropdowns, accordions, trackers) is normal on modern sites, so
    # we only flag hidden text when it is large AND stuffed with scam wording.
    hidden_kw = [k for k in CONTENT_KEYWORDS if k in hidden_text.lower()]
    if ht_len > 400 and hidden_kw:
        return _chk("hidden_css", "Hidden elements via CSS", "info", 0, 0,
                    f"{ht_len} characters of text are hidden with CSS and "
                    f"contain suspicious wording ({', '.join(hidden_kw[:3])}) - "
                    "a classic SEO-cloaking / keyword-stuffing technique.")
    if n >= 200:
        return _chk("hidden_css", "Hidden elements via CSS", "info", 0, 0,
                    f"Extreme number ({n}) of CSS-hidden elements.")
    if ht_len > 2000:
        return _chk("hidden_css", "Hidden elements via CSS", "info", 0, 0,
                    f"{ht_len:,} characters of text are hidden with CSS, but it "
                    "contains no suspicious wording - likely accordion/menu "
                    "content rendered by a modern app.")
    if ht_len > 100 or n >= 30:
        return _chk("hidden_css", "Hidden elements via CSS", "info", 0, 0,
                    f"{n} hidden element(s), {ht_len} hidden character(s) - not "
                    "enough to be suspicious on its own.")
    return _chk("hidden_css", "Hidden elements via CSS", "passed", 0, 0,
                "No unusual amount of CSS-hidden elements.")


# Order the checks for the result table.
CHECK_ORDER = [
    _check_https, _check_ssl, _check_security_headers, _check_domain_age,
    _check_whois, _check_blacklist, _check_reputation, _check_keywords,
    _check_hidden_iframe, _check_obfuscation, _check_external_scripts,
    _check_login_form, _check_password, _check_mixed_content, _check_redirects,
    _check_url_structure, _check_homograph, _check_content, _check_about,
    _check_contact, _check_privacy, _check_terms, _check_grammar,
    _check_brand_impersonation, _check_favicon, _check_trust_badges,
    _check_broken_links, _check_image_only, _check_popups, _check_ads,
    _check_hidden_css,
]


# ---- Safe Browsing ----------------------------------------------------------

def _gsb_lookup(url: str, key: str) -> dict:
    """Query Google Safe Browsing. Returns {checked, threats}. A non-200
    response or network error means `checked` is False (API failure -> UNKNOWN),
    so a failed lookup is never mistaken for a clean report."""
    out = {"checked": False, "threats": []}
    try:
        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
            json={
                "client": {"clientId": "trustlens", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": _GSB_THREAT_TYPES,
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            },
            timeout=4,
        )
        if resp.status_code != 200:
            return out
        matches = resp.json().get("matches", [])
        out["checked"] = True
        out["threats"] = list({m.get("threatType", "THREAT") for m in matches})
        return out
    except Exception:  # noqa: BLE001
        return out


# ---- Blacklist --------------------------------------------------------------

def _blacklist_entry(host: str):
    if not host:
        return None
    try:
        host_clean = host.split(":")[0]
        entry = (
            BlacklistedDomain.query.filter(
                (BlacklistedDomain.domain == host_clean)
                | (BlacklistedDomain.domain == host_clean.removeprefix("www."))
            ).first()
        )
        if entry is None:
            base = ".".join(host_clean.split(".")[-2:])
            entry = BlacklistedDomain.query.filter_by(domain=base).first()
        return entry
    except Exception:  # noqa: BLE001
        return None


# ---- Orchestrator -----------------------------------------------------------

def scan_website(raw_url: str) -> dict:
    """
    Run all 30 checks and return a JSON-serialisable result. Never raises.
    """
    start = time.perf_counter()
    timeout = Config.HTTP_TIMEOUT_SECONDS

    try:
        url = _normalise_url(raw_url)
    except ValueError as exc:
        return {
            "score": 0, "status": "dangerous", "risk_level": "High Risk",
            "verdict": "High Risk - Do Not Trust",
            "reasons": [{"severity": "danger", "text": str(exc), "points": 0}],
            "checks": [], "summary": {"passed": 0, "failed": 0, "info": 0,
                                      "points_awarded": 0, "points_deducted": 0},
            "details": {"url": raw_url},
            "processing_time_ms": 0,
        }

    host = _domain_of(url)
    netloc = _netloc(url)
    netloc_host, port = _host_port(netloc)
    final_url = url

    # ---- Gather evidence ---------------------------------------------------
    fetch = _fetch_page(url, timeout)
    final_url = fetch["final_url"]
    netloc_host_final, port_final = _host_port(_netloc(final_url))
    netloc_host_final = netloc_host_final or netloc_host
    port_final = port_final or port

    tls_probe = {}
    if final_url.split(":", 1)[0].lower() == "https" and fetch["reachable"]:
        tls_probe = _tls_probe(netloc_host_final, port_final or 443, min(3, timeout))
    elif final_url.split(":", 1)[0].lower() == "https":
        tls_probe = {"valid": False, "error": "unreachable"}

    sniff = _HtmlSniff()
    if fetch["content"]:
        try:
            sniff.feed(fetch["content"].decode("utf-8", errors="replace"))
        except Exception:  # noqa: BLE001
            logger.exception("HTML parsing failed")

    registered = _registered_domain(netloc_host_final)
    rdap = _rdap_lookup(registered, min(3, timeout))

    gsb = {"checked": False, "threats": []}
    if Config.GOOGLE_SAFE_BROWSING_API_KEY:
        gsb = _gsb_lookup(final_url, Config.GOOGLE_SAFE_BROWSING_API_KEY)
    gsb_threats = gsb["threats"]
    gsb_checked = gsb["checked"]

    entry = _blacklist_entry(netloc_host_final)

    visible_text = sniff.visible_text
    text_lower = visible_text.lower()
    page_link_signals = " ".join(
        [t for t, _ in sniff.links] + [u for _, u in sniff.links]
    ).lower()

    ctx = {
        "url": url,
        "final_url": final_url,
        "host": host,
        "netloc_host": netloc_host_final,
        "registered_domain": registered,
        "registration_date": rdap.get("registration"),
        "registrar": rdap.get("registrar"),
        "whois_error": rdap.get("error"),
        "reachable": fetch["reachable"],
        "fetch_error": fetch["fetch_error"],
        "tls_probe": tls_probe,
        "history": fetch["history"],
        "status_code": fetch["status_code"],
        "headers": fetch["headers"],
        "content_type": fetch["content_type"],
        "raw_html": fetch["content"].decode("utf-8", errors="replace"),
        "title": sniff.title.strip(),
        "visible_text": visible_text,
        "text_lower": text_lower,
        "text_chars": len(visible_text),
        "links": sniff.links,
        "page_link_signals": page_link_signals,
        "forms": sniff.forms,
        "password_fields": sniff.password_fields,
        "inputs": sniff.inputs,
        "external_script_srcs": sniff.external_script_srcs,
        "inline_script_bodies": sniff.inline_script_bodies,
        "scripts_joined": sniff.scripts_joined,
        "iframes": sniff.iframes,
        "img_count": sniff.img_count,
        "favicon": sniff.favicon,
        "meta_refresh": sniff.meta_refresh,
        "hidden_css_elements": sniff.hidden_css_elements,
        "hidden_css_rules": sniff.hidden_css_rules,
        "hidden_text_parts": sniff.hidden_text_parts,
        "insecure_active_refs": sniff.insecure_active_refs,
        "insecure_anchor_refs": sniff.insecure_anchor_refs,
        "blacklisted": bool(entry),
        "blacklist_domain": entry.domain if entry else "",
        "gsb_threats": gsb_threats,
        "gsb_checked": gsb_checked,
        "virustotal": {},
        "reputation": "unknown",
        "security_headers": [],
        "suspicious_keywords": [],
    }

    if not fetch["reachable"]:
        ctx["final_url"] = url

    # ---- Run checks --------------------------------------------------------
    checks = [fn(ctx) for fn in CHECK_ORDER]

    # Structural failure: site could not be reached at all.
    if not fetch["reachable"] and fetch["fetch_error"]:
        checks.append(_chk(
            "reachable", "Site reachability", "failed", 0, 0,
            f"Site could not be reached ({ctx['fetch_error'][:80]}) - cannot "
            "verify any content or certificate. Result is UNKNOWN."))

    # Additive score: sum of trust awards minus confirmed-risk deductions.
    award_total = sum(c["award"] for c in checks)
    deducted = sum(c["deduction"] for c in checks)
    score = max(0, min(100, award_total - deducted))

    reasons = []
    for c in checks:
        if c["status"] == "failed":
            reasons.append({"severity": c["severity"], "text": c["text"],
                            "points": c["deduction"]})
        else:
            reasons.append({"severity": c["severity"], "text": c["text"],
                            "points": c["award"]})

    summary = {
        "passed": sum(1 for c in checks if c["status"] == "passed"),
        "failed": sum(1 for c in checks if c["status"] == "failed"),
        "info": sum(1 for c in checks if c["status"] == "info"),
        "points_awarded": award_total,
        "points_deducted": deducted,
    }

    if score >= 95:
        status, risk_level, verdict = "safe", "Highly Trusted", "Highly Trusted - Likely Safe"
    elif score >= 85:
        status, risk_level, verdict = "safe", "Trusted", "Trusted - Likely Safe"
    elif score >= 70:
        status, risk_level, verdict = "warning", "Moderate Risk", "Moderate Risk - Proceed With Caution"
    elif score >= 40:
        status, risk_level, verdict = "dangerous", "Suspicious", "Suspicious - Verify Carefully"
    else:
        status, risk_level, verdict = "dangerous", "High Risk", "High Risk - Do Not Trust"

    processing_ms = int((time.perf_counter() - start) * 1000)

    details = {
        "url": ctx["final_url"],
        "input_url": url,
        "host": netloc_host_final,
        "https": final_url.split(":", 1)[0].lower() == "https",
        "ssl": bool(tls_probe.get("valid")),
        "cert": ("Valid" if tls_probe.get("valid")
                 else tls_probe.get("error", "Unknown")),
        "cert_issuer": tls_probe.get("issuer", ""),
        "redirect_count": len(fetch["history"]),
        "suspicious_keywords": ctx["suspicious_keywords"],
        "blacklisted": ctx["blacklisted"],
        "domain_age_days": ctx.get("domain_age_days"),
        "registrar": ctx.get("registrar") or "",
        "page_title": ctx["title"][:120],
        "text_chars": ctx["text_chars"],
        "external_script_hosts": ctx.get("external_script_hosts", []),
        "iframe_count": len(ctx["iframes"]),
        "hidden_iframe_count": len(ctx.get("hidden_iframes", [])),
        "form_count": len(ctx["forms"]),
        "password_field_count": ctx.get("password_field_count", 0),
        "mixed_content_count": ctx.get("mixed_content_count", 0),
        "img_count": ctx["img_count"],
        "favicon_present": bool(ctx["favicon"]),
        "ad_markers": ctx.get("ad_markers", 0),
        "popup_count": ctx.get("popup_count", 0),
        "hidden_css_count": ctx.get("hidden_css_count", 0),
        "broken_link_count": ctx.get("broken_link_count", 0),
        "grammar_flags": ctx.get("grammar_flags", []),
        "brand_title_hits": ctx.get("brand_title_hits", []),
        "homograph_matches": ctx.get("homograph_matches", []),
        "trust_badge_mentions": ctx.get("trust_badge_mentions", []),
        "gsb_threat_types": gsb_threats,
        "security_headers": ctx.get("security_headers", []),
        "reputation": ctx.get("reputation", "unknown"),
        "virustotal": ctx.get("virustotal") or {},
        "reachable": fetch["reachable"],
        "content_type": fetch["content_type"],
        "status_code": fetch["status_code"],
        "http_to_https": final_url.split(":", 1)[0].lower() == "https" and
        url.split(":", 1)[0].lower() != "https",
    }

    return {
        "score": score,
        "status": status,
        "risk_level": risk_level,
        "verdict": verdict,
        "blacklisted": ctx["blacklisted"],
        "blacklist_reason": entry.reason if entry and entry.reason else None,
        "checks": checks,
        "summary": summary,
        "reasons": reasons,
        "details": details,
        "url": ctx["final_url"],
        "input_url": url,
        "processing_time_ms": processing_ms,
    }


# ---- Persistence ------------------------------------------------------------

def persist_scan(app, user_id, payload: dict):
    """Save a website scan to the database. Never raises."""
    from models.scan import WebsiteScan

    try:
        meta = payload.get("details", {})
        scan = WebsiteScan(
            user_id=user_id,
            url=meta.get("url", payload.get("url", "")),
            trust_score=payload["score"],
            status=payload["status"],
            https_valid=meta.get("https", False),
            ssl_valid=meta.get("ssl", False),
            blacklisted=meta.get("blacklisted", False),
            redirect_count=meta.get("redirect_count", 0),
            suspicious_keywords=", ".join(meta.get("suspicious_keywords", [])) or None,
            reasons=payload.get("reasons"),
            scan_meta=meta,
        )
        db.session.add(scan)
        db.session.commit()
    except Exception:  # noqa: BLE001
        db.session.rollback()
        app.logger.exception("Failed to persist website scan")
