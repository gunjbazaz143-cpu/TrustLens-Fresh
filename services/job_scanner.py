"""
Job / internship offer scanner - trust-verification redesign.

Additive trust scoring. The score is BUILT from verified signals, never starts
high: an offer for a company that cannot be verified online can never score
high no matter how polished the posting looks.

  Verified company signals (awards, up to 50):
    official website reachable & matches company   +25
    Wikipedia article exists                       +10
    LinkedIn company page reachable                +10
    additional web presence found                  +5

  Offer signals (awards, up to 50):
    HR email on the company's own domain           +15
    professional custom email domain               +5
    recognised professional job title              +10
    salary within realistic range                  +10
    no scam phrases in the offer                   +5

  Deductions (confirmed risks only):
    scam phrase (registration/training fee, pay to join, guaranteed job,
      no interview, earn X lakh per week, immediate joining after payment,
      work-from-home + huge salary)                -20 each
    free email provider (gmail/yahoo/outlook)      -20
    suspicious HR email domain                     -15
    unrealistic salary (esp. for freshers)         -25
    vague / unrealistic job title                  -15
    website/company domain mismatch                -10
    provided website is a parked / for-sale page   -15

  Caps (never award above 90 without multiple verified trust signals):
    0 verified company signals -> hard cap 55 with reason
      "Company could not be verified - no trusted online presence found"
    1 verified signal  -> cap 70
    2 verified signals -> cap 85
    3+ verified signals -> no cap (max 100)

  External verification (official website, Wikipedia, LinkedIn, DuckDuckGo)
  uses public endpoints, short timeouts and parallel probes; any network
  failure is treated as UNVERIFIED (never as verified, never as a deduction).

Backward-compatible surface: `scan_job(data)` returns the previous envelope
{score, status, reasons, details, processing_time_ms}; reasons now carry
{award, deduction, points, detail} so the UI can explain every point.
"""

import re
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests

from config import Config
from services.logger import get_logger
from services.scoring import FREE_MAIL_DOMAINS, classify

logger = get_logger(__name__)

USER_AGENT = "TrustLensBot/1.0 (+https://trustlens.io)"
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)

# Recognised professional roles - a title containing one earns trust.
RECOGNIZED_ROLES = [
    "engineer", "developer", "analyst", "manager", "consultant", "associate",
    "officer", "executive", "specialist", "coordinator", "supervisor",
    "technician", "intern", "trainee", "apprentice", "accountant", "recruiter",
    "designer", "writer", "editor", "scientist", "architect", "lead",
    "director", "operator", "clerk", "teacher", "trainer", "nurse", "doctor",
    "agent", "advisor", "administrator", "assistant", "representative",
    "attorney", "counsel", "researcher", "analyst", "sales",
]

# Titles that are classic employment-scam bait.
VAGUE_JOB_TITLES = [
    "data entry", "form filling", "copy paste", "typing work", "captcha",
    "online task", "online earning", "mobile recharge", "youtube watching",
    "instagram liking", "like and share", "easy money", "money making",
    "part time home", "lazy work", "clicking work", "app testing no work",
]

# Scam phrases flagged by the requirements. Every hit deducts points.
SCAM_PHRASES = [
    "registration fee", "training fee", "pay to join", "pay to apply",
    "joining fee", "processing fee", "registration charges",
    "immediate joining after payment", "immediate joining", "join after payment",
    "guaranteed job", "guaranteed placement", "100% job guarantee",
    "job guarantee", "pay to get job", "pay for the job",
    "1 lakh per week", "1,00,000 per week", "rs 1 lakh per week",
    "₹1 lakh per week", "lakh per week", "crore per week",
    "no interview", "without interview", "no interview required",
    "direct joining without interview",
]

# Phrases that mark a parked / for-sale domain rather than a real company site.
PARKED_MARKERS = [
    "domain is for sale", "this domain is for sale", "buy this domain",
    "domain parked", "parked domain", "sedo", "dan.com", "godaddy",
    "afternic", "this domain has expired", "domain may be for sale",
    "this domain is parked", "for sale by owner", "domain for sale",
]

# Legal / organisational suffixes stripped when building company slugs.
# Kept conservative: "services"/"solutions"/"technologies" can be part of a
# brand name (e.g. "Tata Consultancy Services"), so they are NOT stripped.
LEGAL_SUFFIXES = [
    "corporation", "corp", "incorporated", "inc", "limited", "ltd", "private",
    "pvt", "llc", "llp", "co", "company",
]

# Two-level public suffixes for registered-domain resolution.
MULTI_LABEL_TLDS = {
    "co.in", "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "org.au", "net.au",
    "com.br", "com.mx", "co.jp", "com.sg", "co.nz", "com.cn", "com.hk", "com.my",
    "co.za", "com.tr", "com.vn", "co.th", "com.tw", "com.eg", "com.sa", "co.il",
}


# --------------------------------------------------------------------------- #
# Reason helper (mirrors website_scanner's _chk: award + deduction + points).
# --------------------------------------------------------------------------- #
def _reason(text: str, severity: str, award: int = 0, deduction: int = 0, detail: str = "") -> dict:
    d = -abs(deduction) if deduction else 0
    return {
        "severity": severity,
        "text": text,
        "award": max(0, award),
        "deduction": d,
        "points": max(0, award) + d,
        "detail": detail,
    }


# --------------------------------------------------------------------------- #
# Text helpers
# --------------------------------------------------------------------------- #
def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def _domain_of(url: str) -> str:
    try:
        if url and not re.match(r"^[a-z][a-z0-9+.\-]*://", url, re.IGNORECASE):
            url = "https://" + url
        host = urlparse(url).netloc.lower()
    except Exception:
        return ""
    host = host.split("@")[-1]
    if ":" in host and not host.endswith("]"):
        host = host.rsplit(":", 1)[0]
    return host.strip().strip(".")


def _registered_domain(host: str) -> str:
    host = (host or "").lower().strip()
    if host.startswith("www."):
        host = host[4:]
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_TLDS:
        return ".".join(labels[-3:])
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host


def _company_slugs(company: str) -> list:
    """Return [slug, acronym] candidates for a company name, best first."""
    words = [w for w in re.split(r"[^a-z0-9]+", (company or "").lower()) if w]
    if not words:
        return []
    # strip trailing legal suffixes
    changed = True
    while changed and words:
        changed = False
        for suffix in LEGAL_SUFFIXES:
            if words and words[-1] == suffix:
                words = words[:-1]
                changed = True
    if not words:
        words = [w for w in re.split(r"[^a-z0-9]+", (company or "").lower()) if w]
    slug = "".join(words)
    acronym = "".join(w[0] for w in words if len(w) > 1)
    out = []
    for cand in (slug, acronym):
        if cand and len(cand) >= 3 and cand not in out:
            out.append(cand)
    return out


def _domain_matches_company(domain: str, company: str, slugs: list) -> bool:
    rd = _registered_domain(domain)
    base = rd.split(".")[0] if rd else ""
    core = _norm(rd)
    name_core = _norm(company)
    for s in slugs:
        if len(s) >= 3 and (s in core or s == base):
            return True
    if len(name_core) >= 3 and (name_core in core or core in name_core):
        return True
    return False


# --------------------------------------------------------------------------- #
# Live company verification (never raises)
# --------------------------------------------------------------------------- #
def _probe(url: str) -> dict:
    try:
        if not re.match(r"^https?://", url, re.IGNORECASE):
            url = "https://" + url
        resp = requests.get(
            url,
            timeout=Config.HTTP_TIMEOUT_SECONDS,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
        )
        # 401/403/429/451 = the domain exists and serves a real origin (often a
        # WAF/bot-wall on legitimate corporate sites like tcs.com) but refused
        # this automated client. Still counts as the site being present.
        if resp.status_code in (401, 403, 429, 451):
            return {"ok": True, "parked": False, "blocked": True, "url": resp.url}
        if resp.status_code >= 400:
            return {"ok": False, "parked": False, "blocked": False, "url": resp.url}
        text = (resp.text or "")[:10000].lower()
        parked = any(m in text for m in PARKED_MARKERS)
        return {"ok": True, "parked": parked, "blocked": False, "url": resp.url}
    except Exception:
        return {"ok": False, "parked": False, "blocked": False, "url": None}


def _wiki_verify(company: str, slug: str):
    """Return the matching Wikipedia article title, or None."""
    try:
        resp = requests.get(
            "https://en.wikipedia.org/w/api.php",
            params={"action": "query", "format": "json", "list": "search",
                    "srsearch": company or slug, "srlimit": 3},
            timeout=Config.HTTP_TIMEOUT_SECONDS,
            headers={"User-Agent": USER_AGENT},
        )
        for hit in resp.json().get("query", {}).get("search", []):
            title = hit.get("title", "")
            t = _norm(title)
            if not t:
                continue
            if slug and len(slug) >= 3 and slug in t:
                return title
            if len(t) >= 3 and t in _norm(company):
                return title
            if len(_norm(company)) >= 3 and _norm(company) in t:
                return title
        return None
    except Exception:
        return None


def _linkedin_verify(slug: str) -> bool:
    try:
        resp = requests.get(
            "https://www.linkedin.com/company/" + slug,
            timeout=Config.HTTP_TIMEOUT_SECONDS,
            headers={"User-Agent": BROWSER_UA},
            allow_redirects=True,
        )
        if resp.status_code != 200:
            return False
        low = (resp.text or "")[:3000].lower()
        if "page not found" in low or "does not exist" in low or "unavailable" in low[:500]:
            return False
        return True
    except Exception:
        return False


def _ddg_verify(company: str) -> bool:
    try:
        resp = requests.get(
            "https://api.duckduckgo.com/",
            params={"q": company, "format": "json", "no_html": "1", "skip_disambig": "1"},
            timeout=Config.HTTP_TIMEOUT_SECONDS,
            headers={"User-Agent": USER_AGENT},
        )
        data = resp.json()
        nc = _norm(company)
        if not nc or len(nc) < 3:
            return False
        if nc in _norm(data.get("AbstractText", "")) or nc in _norm(data.get("Heading", "")):
            return True
        for topic in data.get("RelatedTopics", []):
            if "Topics" in topic:
                for sub in topic.get("Topics", []):
                    if nc in _norm(sub.get("Text", "")):
                        return True
            elif nc in _norm(topic.get("Text", "")):
                return True
        return False
    except Exception:
        return False


def _verify_company(company: str, provided_website: str) -> dict:
    """Verify a company's online presence with parallel probes. Never raises."""
    result = {
        "website": None, "website_parked": False, "website_mismatch": False,
        "wikipedia": False, "linkedin": False, "web_presence": False,
        "signals": 0, "checked": False,
    }
    company = (company or "").strip()
    if not company:
        return result
    slugs = _company_slugs(company)
    if not slugs:
        return result

    # candidate URLs (provided + slug-based discoveries)
    candidates = []
    if provided_website and provided_website.strip():
        candidates.append(provided_website.strip())
    for s in slugs:
        for tld in (".com", ".co.in", ".in", ".org"):
            candidates.append("https://" + s + tld)
            if len(candidates) >= 4:
                break
        if len(candidates) >= 4:
            break

    try:
        with ThreadPoolExecutor(max_workers=6) as pool:
            site_futures = [pool.submit(_probe, u) for u in candidates]
            wiki_future = pool.submit(_wiki_verify, company, slugs[0])
            ddg_future = pool.submit(_ddg_verify, company)

            site_results = [f.result() for f in site_futures]
            wiki_title = wiki_future.result()
            result["wikipedia"] = bool(wiki_title)
            result["web_presence"] = bool(ddg_future.result())

        # LinkedIn: try the name slug, then the Wikipedia title slug (e.g. TCS
        # uses linkedin.com/company/tata-consultancy-services, not /company/tcs).
        linkedin_slugs = [slugs[0]]
        if wiki_title:
            li_slug = re.sub(r"[^a-z0-9-]", "", wiki_title.lower().replace(" ", "-"))
            if li_slug and li_slug not in linkedin_slugs:
                linkedin_slugs.append(li_slug)
        for li_slug in linkedin_slugs:
            if _linkedin_verify(li_slug):
                result["linkedin"] = True
                break

        provided_domain = _registered_domain(_domain_of(provided_website)) if provided_website else None
        best = None
        for url, r in zip(candidates, site_results):
            if r.get("ok") and not r.get("parked"):
                dom = _registered_domain(_domain_of(url))
                if _domain_matches_company(dom, company, slugs):
                    best = (dom, url, r.get("url"))
                    break
        if best:
            result["website"] = best[0]
        else:
            # no matching live site found - check provided-website mismatch
            if provided_website:
                dom = _registered_domain(_domain_of(provided_website))
                site_ok = False
                for url, r in zip(candidates, site_results):
                    if url == provided_website and r.get("ok"):
                        site_ok = True
                        if r.get("parked"):
                            result["website_parked"] = True
                if site_ok and not _domain_matches_company(dom, company, slugs):
                    result["website_mismatch"] = True
            # any discovered parked candidate
            if not result["website"] and not result["website_mismatch"]:
                for url, r in zip(candidates, site_results):
                    if r.get("ok") and r.get("parked") and url != provided_website:
                        if _domain_matches_company(_registered_domain(_domain_of(url)), company, slugs):
                            result["website_parked"] = True
                            break
    except Exception as exc:  # noqa: BLE001
        logger.warning("Company verification failed for %s: %s", company, str(exc)[:120])
        return result

    result["signals"] = sum([
        1 if result["website"] else 0,
        1 if result["wikipedia"] else 0,
        1 if result["linkedin"] else 0,
        1 if result["web_presence"] else 0,
    ])
    result["checked"] = True
    return result


# --------------------------------------------------------------------------- #
# Salary analysis
# --------------------------------------------------------------------------- #
def _salary_red_flag(salary: str, context: str):
    """Return (is_unrealistic, explanation) for a salary string."""
    s = (salary or "").lower()
    if not s:
        return False, None
    ctx = (context or "").lower()
    fresher = bool(re.search(r"fresher|no experience|no prior|fresh graduate|entry level|0-?1\s*years", ctx))

    # huge per-week / weekly figures (any currency) - always unrealistic
    per_week = re.search(
        r"(?:rs\.?|inr|₹)?\s?[0-9]{1,3}(?:[,.][0-9]{3})+\s*(?:per\s*week|/week|weekly)|"
        r"\$\s?[0-9]{3,}\s*(?:per\s*week|/week|weekly)|"
        r"[0-9]{1,2}\s*(?:lakh|crore)\s*(?:per\s*week|/week|weekly)|"
        r"[0-9]{5,}\s*(?:per\s*week|/week|weekly)",
        s,
    )
    if per_week:
        return True, f"Unrealistic salary listed: '{per_week.group(0)}'"

    # monthly figures - flag when >= 1,00,000 INR / month
    per_month = re.search(
        r"(?:rs\.?|inr|₹)\s?[0-9]{2},[0-9]{3}\s*(?:per\s*month|/month|monthly)", s
    )
    if per_month:
        amount = int(re.sub(r"\D", "", per_month.group(0)))
        if amount >= 100000:
            return True, f"Unrealistic monthly salary listed: '{per_month.group(0)}'"

    # annual figures - only flag above 1 crore INR / year (per-annum 5-7 figure
    # salaries are normal for senior roles)
    per_annum = re.search(
        r"(?:rs\.?|inr|₹)?\s?([0-9][0-9,]*)\s*(?:per\s*annum|per\s*year|/year|/annum|\bpa\b)", s
    )
    if per_annum:
        amount = int(re.sub(r"\D", "", per_annum.group(1)))
        if amount >= 10000000:
            return True, f"Unrealistic salary listed: '{per_annum.group(0)}'"
        return False, None

    # LPA / lakh-per-annum shorthand
    m = re.search(r"([0-9]{1,2}(?:\.[0-9])?)\s*(?:lpa|lakh\s*per\s*annum)", s)
    if m:
        value = float(m.group(1))
        if value >= 50:
            return True, f"Unrealistically high salary listed: '{m.group(0)}'"
        if fresher and value >= 12:
            return True, f"Unrealistically high salary for a fresher/entry-level role: '{m.group(0)}'"
        return False, None

    # outright high figures with no unit stated (assume monthly)
    m = re.search(r"(?:rs\.?|inr|₹)\s?(?:[0-9]{1,2},[0-9]{2},[0-9]{3}|[0-9]{3},[0-9]{3}|[0-9]{6,})", s)
    if m:
        return True, f"Unrealistic salary listed: '{m.group(0)}'"
    m = re.search(r"\$\s?(?:[0-9]{3},[0-9]{3}|[0-9]{6,})", s)
    if m:
        return True, f"Unrealistic salary listed: '{m.group(0)}'"
    return False, None


# --------------------------------------------------------------------------- #
# Title analysis
# --------------------------------------------------------------------------- #
def _title_flag(title: str):
    t = (title or "").strip().lower()
    if not t:
        return "empty", None
    for vague in VAGUE_JOB_TITLES:
        if vague in t:
            return "vague", f"Vague/unrealistic job title ('{title.strip()}') - typical scam bait"
    for role in RECOGNIZED_ROLES:
        if role in t:
            return "recognized", None
    return "unknown", None


# --------------------------------------------------------------------------- #
# Main entry point
# --------------------------------------------------------------------------- #
def scan_job(data: dict) -> dict:
    """Analyse a job offer dict and return score, status, reasons."""
    start = time.perf_counter()

    job_title = (data.get("job_title") or "").strip()
    company = (data.get("company_name") or "").strip()
    email = (data.get("email") or "").strip()
    salary = (data.get("salary") or "").strip()
    website = (data.get("website") or "").strip()
    description = (data.get("description") or "").strip()

    # ---- Required fields ----
    if not company and not job_title and not email:
        return {
            "score": 0, "status": "dangerous",
            "reasons": [{"severity": "danger", "text": "Not enough information to analyse."}],
            "processing_time_ms": 0,
        }

    # Derive a company hint from the HR email domain when no name was given.
    if not company and email and "@" in email:
        dom = email.split("@")[-1].strip().lower()
        if dom and dom not in FREE_MAIL_DOMAINS:
            company = dom.split(".")[0].capitalize()

    awarded = 0
    deducted = 0
    reasons = []

    def award(text, pts, severity="success", detail=""):
        nonlocal awarded
        awarded += pts
        reasons.append(_reason(text, severity, award=pts, detail=detail))

    def deduct(text, pts, severity="danger", detail=""):
        nonlocal deducted
        deducted += pts
        reasons.append(_reason(text, severity, deduction=pts, detail=detail))

    def note(text, severity="info", detail=""):
        reasons.append(_reason(text, severity, detail=detail))

    # ---- 1. Company online verification ----------------------------------- #
    verify = _verify_company(company, website)
    signals = verify.get("signals", 0)
    verified_domain = verify.get("website")

    if verified_domain:
        award(
            "Official company website verified (" + verified_domain + ")",
            25,
            detail="A live website matching '" + company + "' was reached over HTTPS.",
        )
    else:
        note(
            "No official company website could be verified",
            "info",
            detail="Slug-based domain probes and any provided website did not yield a matching live site.",
        )
        if verify.get("website_parked"):
            deduct(
                "Provided/discovered company website appears to be a parked or for-sale domain",
                15,
            )

    if verify.get("wikipedia"):
        award("Company has a Wikipedia article", 10)
    if verify.get("linkedin"):
        award("Verified company LinkedIn page", 10)
    if verify.get("web_presence"):
        award("Additional web presence found for the company", 5)

    if verify.get("website_mismatch") and website:
        deduct(
            "Company website domain does not match the company name",
            10,
            detail="The provided website's domain does not reference '" + company + "'.",
        )

    if signals == 0:
        note(
            "Company could not be verified - no trusted online presence found "
            "(official website, Wikipedia or LinkedIn).",
            "danger",
        )
    elif signals < 3:
        note(
            "Only " + str(signals) + " of 4 company trust signals verified - score capped.",
            "info",
        )
    else:
        note("Company verified across multiple independent sources.", "success")

    # ---- 2. HR email -------------------------------------------------------- #
    if email and "@" in email:
        domain = email.split("@")[-1].strip().lower()
        if verified_domain and (
            domain == verified_domain
            or domain.endswith("." + verified_domain)
        ):
            award(
                "HR email uses the company's official domain (" + domain + ")",
                15,
            )
        elif domain in FREE_MAIL_DOMAINS:
            deduct(
                "HR contact uses a free email provider (" + domain + ") - common in scams",
                20,
            )
        elif re.match(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$", domain):
            award("HR email uses a professional custom domain (" + domain + ")", 5)
        else:
            deduct("HR email domain looks suspicious", 15, detail=domain)
    elif email:
        note("Contact email is not a valid address", "warning")

    # ---- 3. Job title -------------------------------------------------------- #
    flag, flag_note = _title_flag(job_title)
    if flag == "recognized":
        award("Recognised professional job title: '" + job_title + "'", 10)
    elif flag == "vague":
        deduct(flag_note, 15)
    elif flag == "unknown":
        note("Job title is not a recognised professional role", "info", detail=job_title)

    # ---- 4. Salary analysis --------------------------------------------------- #
    high, salary_note = _salary_red_flag(salary, job_title + " " + description)
    if high:
        deduct(salary_note, 25)
    elif salary:
        award("Salary appears within realistic range", 10, detail=salary)

    # ---- 5. Scam phrases ------------------------------------------------------ #
    joined = " ".join([job_title, company, email, salary, website, description]).lower()
    hits = [p for p in SCAM_PHRASES if p in joined]
    wfh_huge = "work from home" in joined and bool(high)
    if hits:
        deduct("Scam phrase detected: '" + hits[0] + "'", 20)
        if len(hits) > 1:
            note("Additional scam phrases: " + ", ".join(hits[1:4]), "warning")
    elif wfh_huge:
        deduct("'Work from home' paired with an unrealistically high salary", 20)
    else:
        award("No scam phrases detected in the offer", 5)

    # ---- Score: awards - deductions, then verification caps ------------------- #
    score = max(0, min(100, awarded - deducted))
    if signals == 0:
        score = min(score, 55)
    elif signals == 1:
        score = min(score, 70)
    elif signals == 2:
        score = min(score, 85)
    # 3+ signals: no cap (verified across multiple trust signals)

    result = {
        "job_title": job_title,
        "company_name": company,
        "contact_email": email,
        "salary": salary,
        "website": website,
        "company_verified": signals >= 1,
        "company_verification": {
            "verified_signals": signals,
            "official_website": verified_domain,
            "wikipedia": verify.get("wikipedia"),
            "linkedin": verify.get("linkedin"),
            "web_presence": verify.get("web_presence"),
            "website_parked": verify.get("website_parked"),
            "website_mismatch": verify.get("website_mismatch"),
        },
        "points_awarded": awarded,
        "points_deducted": deducted,
        "score_cap": 100 if signals >= 3 else (55, 70, 85)[signals],
    }
    processing_ms = int((time.perf_counter() - start) * 1000)

    return {
        "score": score,
        "status": classify(score),
        "reasons": reasons,
        "details": result,
        "processing_time_ms": processing_ms,
    }


def persist_scan(app, user_id, data: dict, payload: dict):
    """Persist a job scan. Never raises."""
    from models import db
    from models.scan import JobScan

    try:
        details = payload.get("details", {})
        scan = JobScan(
            user_id=user_id,
            job_title=details.get("job_title"),
            company_name=details.get("company_name"),
            contact_email=details.get("contact_email"),
            salary=details.get("salary"),
            website=details.get("website"),
            trust_score=payload["score"],
            status=payload["status"],
            reasons=payload.get("reasons"),
            input_snapshot=data,
        )
        db.session.add(scan)
        db.session.commit()
    except Exception:  # noqa: BLE001
        db.session.rollback()
        app.logger.exception("Failed to persist job scan")
