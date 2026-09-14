"""
Claim scanner - evidence-based verification of user-supplied claims.

Pipeline:
  USER CLAIM
    -> input validation
    -> normalization
    -> factual-assertion detection (negation aware)
    -> claim category detection
    -> curated evidence knowledge base lookup
    -> classification (verdict + confidence)
    -> explanation + evidence + sources + limitations

Honesty rules:
  - "False", "no reliable evidence found" and "unable to verify" are kept
    distinct. A claim we cannot find evidence for is NEVER called false.
  - Sources are the names of real authoritative bodies (WHO, FDA, EFSA, SEBI...)
    that back the entry. No fabricated URLs, no invented citations.
  - Medical and financial claims get an explicit caution note; the system never
    gives dosing/investment advice.
  - The result is fully deterministic: same claim in -> same verdict out.
"""

import re
import time

from services.logger import get_logger
from services.scoring import classify

logger = get_logger(__name__)

MAX_CLAIM_CHARS = 2000
MIN_CLAIM_CHARS = 8

MEDICAL_DISCLAIMER = (
    "This is general information, not medical advice. The claim has not been "
    "verified by a human clinician; consult a qualified professional before "
    "acting on any health claim."
)
FINANCIAL_DISCLAIMER = (
    "This is general information, not financial advice. Returns on investments "
    "are never guaranteed; verify any scheme with a registered financial "
    "regulator before committing money."
)

# ---- Claim categories ------------------------------------------------------- #
CATEGORY_KEYWORDS = {
    "Health/Medical": [
        "cure", "cures", "treats", "heal", "heals", "reverses", "diabetes",
        "cancer", "blood pressure", "cholesterol", "immunity", "immune",
        "virus", "infection", "detox", "weight loss", "fat loss", "acne",
        "wrinkles", "hair", "disease", "medicine", "dosage", "fever",
        "ayurveda", "herbal", "supplement", "vitamin", "oil", "pills",
        "covid", "coronavirus", "kidney", "liver", "heart", "migraine",
        "arthritis", "thyroid", "allergy", "skin",
    ],
    "Finance/Investment": [
        "invest", "investment", "investing", "returns", "profit", "money",
        "double your money", "roi", "dividend", "stock", "crypto", "forex",
        "trading", "scheme", "deposit", "interest", "wealth", "passive income",
        "income", "pension", "mutual fund", "shares", "bitcoin", "guaranteed returns",
    ],
    "Product/Beauty": [
        "cream", "lotion", "serum", "supplement", "capsule", "tablet", "powder",
        "drink", "juice", "shampoo", "soap", "cosmetic", "product", "formula",
        "oil", "gel", "spray", "detox", "anti-aging", "anti aging", "fairness",
        "whitening", "toner", "mask",
    ],
    "Jobs/Employment": [
        "job", "hiring", "salary", "interview", "work from home", "earn",
        "career", "placement", "internship", "freelance", "recruit",
    ],
    "Technology": [
        "app", "ai", "artificial intelligence", "technology", "software",
        "phone", "internet", "computer", "data", "quantum", "invention",
        "gadget", "robot",
    ],
    "Education": [
        "study", "exam", "degree", "course", "school", "college", "learn",
        "certificate", "university", "marks", "admission", "online course",
    ],
}

# Marketing / unsupported-claim red flags (raise "Unsupported" when no
# knowledge-base entry matches).
UNSUPPORTED_MARKERS = [
    "100% guaranteed", "100% guarantee", "guaranteed", "guarantee",
    "miracle", "secret cure", "one simple trick", "doctors hate",
    "instant", "overnight", "in 24 hours", "in 48 hours", "in 7 days",
    "in 3 days", "cures all", "cure all", "no side effects",
    "risk free", "risk-free", "double your money", "get rich",
    "make money fast", "proven by science", "clinically proven",
    "detox", "flush toxins", "burn fat fast", "lose weight fast",
    "permanent cure", "cure any disease", "treats all diseases",
    "money back guarantee", "limited time offer", "act now",
]

# Words that invert a cure claim ("there is no cure for...", "x does not cure y").
NEGATION_MARKERS = [
    "does not cure", "do not cure", "cannot cure", "can't cure",
    "doesn't cure", "is not a cure", "are not a cure", "no cure",
    "not cure", "won't cure", "will not cure", "not a cure",
    "does not cause", "do not cause", "cannot cause", "can't cause",
    "doesn't cause", "won't cause", "will not cause", "is not a cause",
    "are not a cause", "not a cause", "does not contain", "do not contain",
    "does not work", "do not work", "does not treat", "do not treat",
]

# ---- Knowledge base --------------------------------------------------------- #
# Each entry:
#   patterns  : substrings (matched on normalized text) that activate the entry
#   context   : substrings that must also be present
#   category  : claim category
#   verdict   : Supported | Mostly supported | Misleading | Unsupported | False
#   confidence: High | Medium | Low
#   explanation, evidence, sources, caution, negated_verdict/negated_explanation
KB_ENTRIES = [
    {
        "id": "cure_diabetes",
        "patterns": ["cure", "cures", "reverses", "reverse", "treats"],
        "context": ["diabetes"],
        "category": "Health/Medical",
        "verdict": "Unsupported",
        "confidence": "Medium",
        "explanation": "There is currently no known cure for diabetes. The claim "
                       "is not supported by medical evidence: diabetes is managed "
                       "(diet, exercise, medication) but not cured by any product.",
        "evidence": [
            "Diabetes has no cure; it is a chronic, managed condition.",
            "No food, supplement or device has been shown in reliable studies to "
            "cure diabetes.",
            "Products claiming to 'reverse' or 'cure' diabetes typically sell "
            "supplements with no clinical basis.",
        ],
        "sources": [
            {"name": "World Health Organization (WHO) - diabetes"},
            {"name": "American Diabetes Association"},
            {"name": "UK National Health Service (NHS)"},
        ],
        "caution": "medical",
        "negated_verdict": "Supported",
        "negated_confidence": "High",
        "negated_explanation": "The claim correctly states that there is no cure "
                               "for diabetes, which matches the consensus of major "
                               "health authorities.",
    },
    {
        "id": "cure_cancer",
        "patterns": ["cure", "cures", "heals", "eliminates", "defeats"],
        "context": ["cancer"],
        "category": "Health/Medical",
        "verdict": "Unsupported",
        "confidence": "Medium",
        "explanation": "No single product or remedy cures cancer. Some cancers are "
                       "treatable or manageable with evidence-based care (surgery, "
                       "radiotherapy, chemotherapy), but blanket 'cures cancer' "
                       "claims are unsupported.",
        "evidence": [
            "Cancer is a family of diseases; outcomes depend on type and stage.",
            "No alternative remedy has demonstrated a reliable cure for cancer in "
            "controlled studies.",
            "Claims of a universal 'cure' are a known marker of fake cancer treatments.",
        ],
        "sources": [
            {"name": "World Health Organization (WHO) - cancer"},
            {"name": "US National Cancer Institute (NCI)"},
        ],
        "caution": "medical",
        "negated_verdict": "Supported",
        "negated_confidence": "High",
        "negated_explanation": "The claim correctly states that there is no universal "
                               "cure for cancer, consistent with the consensus of "
                               "cancer agencies.",
    },
    {
        "id": "cure_covid",
        "patterns": ["cure", "cures", "treats", "treat", "kills", "eliminates"],
        "context": ["covid", "coronavirus", "covid-19"],
        "category": "Health/Medical",
        "verdict": "False",
        "confidence": "High",
        "explanation": "No product, food, supplement or disinfectant sold to consumers "
                       "is an established cure or treatment for COVID-19. Global "
                       "health agencies explicitly warn against self-treatment and "
                       "unproven cures.",
        "evidence": [
            "WHO and FDA have repeatedly warned that no consumer product cures "
            "COVID-19.",
            "Vaccines and approved antivirals reduce severity; they are not "
            "curative consumer products.",
            "Consuming disinfectants or unproven remedies is dangerous.",
        ],
        "sources": [
            {"name": "World Health Organization (WHO) - COVID-19"},
            {"name": "US FDA - fraud and consumer alerts"},
        ],
        "caution": "medical",
        "negated_verdict": "Supported",
        "negated_confidence": "High",
        "negated_explanation": "The claim correctly states there is no known cure "
                               "for COVID-19 from consumer products.",
    },
    {
        "id": "bleach_cure",
        "patterns": ["bleach", "hydrogen peroxide", "dettol", "disinfectant", "chlorine dioxide"],
        "context": ["cure", "cures", "drink", "drinking", "heal", "heals", "covid", "autism", "disease", "detox"],
        "category": "Health/Medical",
        "verdict": "False",
        "confidence": "High",
        "explanation": "This claim is dangerous. Drinking bleach, hydrogen peroxide "
                       "or disinfectants is toxic and can be fatal. It is not a "
                       "treatment for any disease.",
        "evidence": [
            "Disinfectants are poisons if ingested.",
            "Regulators have issued explicit public warnings that these products "
            "must never be consumed.",
            "There is no disease for which drinking disinfectants is a valid treatment.",
        ],
        "sources": [
            {"name": "US FDA - warnings on disinfectant misuse"},
            {"name": "World Health Organization (WHO)"},
        ],
        "caution": "medical",
        "negated_verdict": "Supported",
        "negated_confidence": "High",
        "negated_explanation": "The claim correctly warns that these substances are "
                               "dangerous and not cures.",
    },
    {
        "id": "acne_24h",
        "patterns": ["acne", "pimples", "pimple", "blemishes", "spots"],
        "context": ["24 hours", "24 hrs", "overnight", "in a day", "one day", "48 hours", "in 2 days"],
        "category": "Product/Beauty",
        "verdict": "Misleading",
        "confidence": "Medium",
        "explanation": "No topical treatment removes acne in 24 hours. Dermatology "
                       "guidance is that effective acne treatment takes days to "
                       "weeks, and overnight 'miracle' wording is marketing.",
        "evidence": [
            "Skin turnover and acne treatment response take days to weeks.",
            "Dermatology associations advise against expecting overnight results.",
            "Instant-result claims are a recognised marketing exaggeration.",
        ],
        "sources": [
            {"name": "American Academy of Dermatology (AAD)"},
        ],
        "caution": "medical",
    },
    {
        "id": "guaranteed_result",
        "patterns": ["100% guaranteed", "100% guarantee", "guaranteed result", "guaranteed results", "guarantee results"],
        "context": [],
        "category": "Product/Beauty",
        "verdict": "Misleading",
        "confidence": "Medium",
        "explanation": "No product can guarantee identical results for every user. "
                       "Absolute guarantees are a marketing device, not evidence of "
                       "effectiveness.",
        "evidence": [
            "Individual responses to products vary; absolute guarantees are not "
            "scientifically meaningful.",
            "Regulators discourage unqualified '100% guaranteed' health and "
            "cosmetic claims.",
        ],
        "sources": [
            {"name": "US FDA - cosmetics claims guidance"},
            {"name": "US Federal Trade Commission (FTC) - ad substantiation"},
        ],
        "caution": "product",
    },
    {
        "id": "guaranteed_returns",
        "patterns": ["guaranteed returns", "guarantee returns", "assured returns", "guaranteed profit", "guaranteed income", "guaranteed", "risk free", "risk-free", "no risk"],
        "context": ["return", "returns", "return on", "investment", "invest", "money", "profit", "scheme", "deposit", "crypto", "trading", "interest", "stock", "wealth"],
        "category": "Finance/Investment",
        "verdict": "Misleading",
        "confidence": "High",
        "explanation": "Investment returns are never guaranteed. Schemes promising "
                       "guaranteed or risk-free returns are a classic warning sign "
                       "of fraud, and regulators warn against them.",
        "evidence": [
            "All investments carry risk; 'guaranteed returns' claims are a known "
            "fraud indicator.",
            "Securities regulators repeatedly warn that guaranteed-return "
            "schemes are typically Ponzi or unregistered offerings.",
            "Seeking higher guaranteed returns is the bait in investment scams.",
        ],
        "sources": [
            {"name": "Securities and Exchange Board of India (SEBI) - investor warnings"},
            {"name": "US Securities and Exchange Commission (SEC)"},
            {"name": "US Federal Trade Commission (FTC)"},
        ],
        "caution": "financial",
    },
    {
        "id": "double_money",
        "patterns": ["double your money", "double money", "get rich quick", "get rich", "make money fast", "earn lakhs", "crore in", "triple your money"],
        "context": [],
        "category": "Finance/Investment",
        "verdict": "Unsupported",
        "confidence": "High",
        "explanation": "Guaranteed 'double your money' and get-rich-quick promises "
                       "have no legitimate basis. They are a hallmark of advance-fee "
                       "and Ponzi schemes.",
        "evidence": [
            "No legitimate investment guarantees a doubling of money in a short "
            "period.",
            "Such offers are among the most commonly reported frauds.",
            "Regulators advise treating them as scams.",
        ],
        "sources": [
            {"name": "US Federal Trade Commission (FTC)"},
            {"name": "Securities and Exchange Board of India (SEBI)"},
        ],
        "caution": "financial",
    },
    {
        "id": "weight_loss_miracle",
        "patterns": ["lose", "loses", "weight loss", "fat loss", "shed", "melt fat", "burn fat"],
        "context": ["miracle", "guaranteed", "overnight", "in 7 days", "in 3 days", "fast", "instant", "without exercise", "without diet"],
        "category": "Health/Medical",
        "verdict": "Misleading",
        "confidence": "Medium",
        "explanation": "Rapid, 'miracle' weight-loss claims are not supported by "
                       "evidence. Sustainable weight loss is gradual and based on "
                       "diet and activity, not a single product.",
        "evidence": [
            "Reliable weight loss is a gradual process; crash 'miracle' products "
            "typically cause short-term water loss only.",
            "Health authorities describe gradual change as the evidence-based "
            "approach.",
        ],
        "sources": [
            {"name": "World Health Organization (WHO) - obesity"},
            {"name": "UK National Health Service (NHS)"},
        ],
        "caution": "medical",
    },
    {
        "id": "detox_cleansing",
        "patterns": ["detox", "cleansing", "cleanse", "flush toxins", "remove toxins", "eliminate toxins"],
        "context": [],
        "category": "Health/Medical",
        "verdict": "Misleading",
        "confidence": "Medium",
        "explanation": "The body removes waste through the liver and kidneys; "
                       "'detox' products claiming to flush out toxins have no "
                       "reliable evidence behind them.",
        "evidence": [
            "Health authorities note that 'detox' products are not supported by "
            "evidence and the body manages its own clearance.",
            "Extreme cleanses can cause harm (electrolyte imbalance, dehydration).",
        ],
        "sources": [
            {"name": "UK National Health Service (NHS)"},
            {"name": "US Federal Trade Commission (FTC)"},
        ],
        "caution": "medical",
    },
    {
        "id": "immune_booster",
        "patterns": ["immune", "immunity", "boost immunity", "immune booster", "strengthen immunity"],
        "context": ["prevents", "protect", "protects", "stop", "stops", "no more", "boost", "booster"],
        "category": "Health/Medical",
        "verdict": "Misleading",
        "confidence": "Medium",
        "explanation": "No food, drink or supplement 'boosts' immunity enough to "
                       "prevent infection. Supportive nutrition is real, but "
                       "'prevents infection' claims are overstated.",
        "evidence": [
            "A healthy diet supports normal immune function but does not prevent "
            "infections.",
            "Health agencies state that no supplement can replace vaccination and "
            "hygiene.",
        ],
        "sources": [
            {"name": "World Health Organization (WHO)"},
            {"name": "US National Institutes of Health (NIH)"},
        ],
        "caution": "medical",
    },
    {
        "id": "supplement_cures_all",
        "patterns": ["cures all", "cure all", "treats all", "cures every", "panacea", "all diseases", "all illness"],
        "context": [],
        "category": "Health/Medical",
        "verdict": "Unsupported",
        "confidence": "Medium",
        "explanation": "No single supplement or product cures all diseases. "
                       "'Cures everything' claims are a recognised sign of "
                       "unsubstantiated marketing.",
        "evidence": [
            "Different diseases have different causes and treatments; a universal "
            "cure is not medically plausible.",
            "Universal-cure wording is a classic signal of fake health products.",
        ],
        "sources": [
            {"name": "US Federal Trade Commission (FTC) - health fraud"},
            {"name": "World Health Organization (WHO)"},
        ],
        "caution": "medical",
    },
    {
        "id": "herbal_cure",
        "patterns": ["herbal", "ayurveda", "natural", "homeopathic", "ayurvedic", "traditional"],
        "context": ["cure", "cures", "heals", "guaranteed", "100%", "permanent"],
        "category": "Health/Medical",
        "verdict": "Unsupported",
        "confidence": "Medium",
        "explanation": "Natural or herbal origin does not make a product a proven "
                       "cure. Claims that an herbal product 'permanently cures' a "
                       "serious disease are not supported without clinical evidence.",
        "evidence": [
            "'Natural' is not evidence of effectiveness.",
            "Unregulated herbal products can interact with medicines and cause "
            "harm.",
            "Serious-disease cure claims from herbal products are typically "
            "unsubstantiated.",
        ],
        "sources": [
            {"name": "US Food and Drug Administration (FDA)"},
            {"name": "World Health Organization (WHO)"},
        ],
        "caution": "medical",
    },
    {
        "id": "essential_oil_cures",
        "patterns": ["essential oil", "essential oils", "aromatherapy", "essential oil therapy"],
        "context": ["cure", "cures", "treat", "treats", "heals", "kills", "prevents"],
        "category": "Health/Medical",
        "verdict": "Unsupported",
        "confidence": "Medium",
        "explanation": "Essential oils may have mild supportive effects, but claims "
                       "that they cure serious conditions are not supported by "
                       "reliable studies, and several are toxic if ingested.",
        "evidence": [
            "Essential oils are not approved treatments for serious disease.",
            "Some essential oils are toxic when swallowed.",
        ],
        "sources": [
            {"name": "US National Institutes of Health (NIH)"},
        ],
        "caution": "medical",
    },
    {
        "id": "guaranteed_job",
        "patterns": ["guaranteed job", "job guarantee", "guaranteed placement", "100% placement", "guaranteed interview"],
        "context": [],
        "category": "Jobs/Employment",
        "verdict": "Misleading",
        "confidence": "Medium",
        "explanation": "No legitimate course or agency can guarantee a job. "
                       "Guaranteed-placement promises are a common advance-fee "
                       "employment-scam signal.",
        "evidence": [
            "Employment outcomes depend on the candidate and market; guarantees "
            "are not credible.",
            "Guaranteed-placement wording is a known recruitment-scam marker.",
        ],
        "sources": [
            {"name": "US Federal Trade Commission (FTC) - job scams"},
        ],
        "caution": "financial",
    },
    {
        "id": "smoking_causes_cancer",
        "patterns": ["smoking", "cigarettes", "tobacco", "smoke"],
        "context": ["cancer", "lung cancer", "causes cancer", "cause cancer"],
        "category": "Health/Medical",
        "verdict": "Supported",
        "confidence": "High",
        "explanation": "The claim matches the scientific consensus: smoking is a "
                       "leading cause of lung cancer and many other cancers.",
        "evidence": [
            "Decades of epidemiological and biological evidence link tobacco smoke "
            "to cancer.",
            "Tobacco is the single largest preventable cause of cancer death.",
        ],
        "sources": [
            {"name": "World Health Organization (WHO)"},
            {"name": "US Centers for Disease Control and Prevention (CDC)"},
            {"name": "US National Cancer Institute (NCI)"},
        ],
        "caution": "medical",
        "negated_verdict": "Unsupported",
        "negated_confidence": "Medium",
        "negated_explanation": "The claim contradicts the scientific consensus: "
                               "smoking is a leading cause of lung cancer and "
                               "many other cancers. There is no credible evidence "
                               "that smoking does not cause cancer.",
    },
    {
        "id": "vaccine_microchip",
        "patterns": ["microchip", "tracking device", "nanochip", "implant chip"],
        "context": ["vaccine", "vaccines", "vaccination", "covid"],
        "category": "Health/Medical",
        "verdict": "False",
        "confidence": "High",
        "explanation": "Vaccines do not contain microchips or tracking devices. "
                       "This is a well-documented misinformation claim repeatedly "
                       "debunked by health authorities and independent reviews of "
                       "vaccine contents.",
        "evidence": [
            "Vaccine ingredient lists are publicly available and contain no "
            "electronics.",
            "Independent imaging studies of vaccines found no microchips.",
        ],
        "sources": [
            {"name": "World Health Organization (WHO)"},
            {"name": "US Food and Drug Administration (FDA)"},
        ],
        "caution": "medical",
        "negated_verdict": "Supported",
        "negated_confidence": "High",
        "negated_explanation": "The claim correctly states that vaccines do not "
                               "contain microchips or tracking devices - consistent "
                               "with public ingredient lists and independent reviews.",
    },
    {
        "id": "antibiotics_cure_viruses",
        "patterns": ["antibiotics", "antibiotic"],
        "context": ["cure", "cures", "virus", "viral", "cold", "flu", "treat"],
        "category": "Health/Medical",
        "verdict": "False",
        "confidence": "High",
        "explanation": "Antibiotics treat bacterial infections, not viruses. "
                       "Taking antibiotics for a viral illness does not cure it "
                       "and contributes to antibiotic resistance.",
        "evidence": [
            "Antibiotics are ineffective against viruses by mechanism.",
            "Overuse drives antimicrobial resistance, a global health priority.",
        ],
        "sources": [
            {"name": "World Health Organization (WHO)"},
            {"name": "US Centers for Disease Control and Prevention (CDC)"},
        ],
        "caution": "medical",
        "negated_verdict": "Supported",
        "negated_confidence": "High",
        "negated_explanation": "The claim correctly states that antibiotics do not "
                               "cure viral infections - antibiotics act on bacteria, "
                               "not viruses.",
    },
    {
        "id": "vitamin_c_cures_cold",
        "patterns": ["vitamin c", "vitamin c", "ascorbic acid"],
        "context": ["cure", "cures", "cold", "common cold", "prevents", "prevents cold"],
        "category": "Health/Medical",
        "verdict": "Misleading",
        "confidence": "Medium",
        "explanation": "Vitamin C does not cure the common cold. It may modestly "
                       "shorten its duration for some people if taken regularly, "
                       "but it is not a cure or reliable preventive.",
        "evidence": [
            "Clinical reviews found vitamin C does not prevent colds in the "
            "general population.",
            "Regular use may shorten cold duration by a small margin; it is not "
            "a cure.",
        ],
        "sources": [
            {"name": "US National Institutes of Health (NIH)"},
            {"name": "Cochrane Review on vitamin C and the common cold"},
        ],
        "caution": "medical",
    },
    {
        "id": "aspirin_reduces_fever",
        "patterns": ["aspirin", "paracetamol", "ibuprofen"],
        "context": ["fever", "reduces", "lower", "treats", "treat", "reduce fever"],
        "category": "Health/Medical",
        "verdict": "Supported",
        "confidence": "High",
        "explanation": "This is consistent with standard medical practice: "
                       "antipyretics such as aspirin and paracetamol are used to "
                       "reduce fever.",
        "evidence": [
            "Antipyretics are widely recognised to reduce fever in adults.",
            "Dosage and context matter; not recommended for all patients (e.g. "
            "aspirin is avoided in children).",
        ],
        "sources": [
            {"name": "World Health Organization (WHO)"},
            {"name": "US National Library of Medicine (MedlinePlus)"},
        ],
        "caution": "medical",
        "negated_verdict": "Unsupported",
        "negated_confidence": "Medium",
        "negated_explanation": "The claim contradicts standard medical practice: "
                               "antipyretics such as aspirin and paracetamol are "
                               "recognised to reduce fever (with dosing caveats).",
    },
]

# Normalise patterns/context once at import time (lowercase, collapsed spaces).
for _entry in KB_ENTRIES:
    _entry["_patterns"] = [re.sub(r"\s+", " ", p.strip().lower()) for p in _entry["patterns"]]
    _entry["_context"] = [re.sub(r"\s+", " ", c.strip().lower()) for c in _entry["context"]]


# Risk ordering used to break strength ties - a claim matching both a false
# claim and a milder one should surface the more serious finding.
_RISK_RANK = {"False": 4, "Misleading": 3, "Unsupported": 3, "Mostly supported": 2, "Supported": 1}


def detect_category(text: str) -> str:
    """Return the best claim category, or 'General'."""
    low = text.lower()
    best, best_score = "General", 0
    for cat, keywords in CATEGORY_KEYWORDS.items():
        hits = sum(1 for k in keywords if k in low)
        if hits > best_score:
            best, best_score = cat, hits
    return best


def _is_negated(low: str) -> bool:
    return any(marker in low for marker in NEGATION_MARKERS)


def _match_entry(low: str, category: str):
    """
    Return the best-matching KB entry or None.

    Matching rules:
      - at least one pattern AND at least one context term must be present
        (entries with an empty context list have no topic restriction);
      - specificity wins: more context terms present => higher strength;
      - ties are broken by the riskiness of the verdict so the more serious
        finding is surfaced.
    """
    best_entry = None
    best_strength = 0
    best_rank = -1
    for entry in KB_ENTRIES:
        patterns_hit = [p for p in entry["_patterns"] if p in low]
        if not patterns_hit:
            continue
        if entry["_context"]:
            context_hit = [c for c in entry["_context"] if c in low]
            if not context_hit:
                continue
        else:
            context_hit = []
        strength = len(patterns_hit) * 2 + len(context_hit) * 2
        if entry["category"] == category:
            strength += 1
        if strength > best_strength or (
            strength == best_strength and _RISK_RANK.get(entry["verdict"], 0) > best_rank
        ):
            best_strength = strength
            best_rank = _RISK_RANK.get(entry["verdict"], 0)
            best_entry = entry
    return best_entry


# ---- Verdict -> score/status mapping ---------------------------------------- #
# Scores sit in the NORMAL display band (70-90) unless a False verdict or a
# scam-risk indicator forces the HIGH RISK band (20-30). The band scores and
# the risk-indicator logic below are the single place to tune the trust score.
VERDICT_SCORE = {
    "Supported": (90, "safe"),
    "Mostly supported": (85, "safe"),
    "Unverifiable": (78, "warning"),
    "Insufficient evidence": (75, "warning"),
    "Misleading": (72, "warning"),
    "Unsupported": (72, "warning"),
    "False": (25, "dangerous"),
}

# ---- Scam / phishing risk indicators --------------------------------------- #
# Patterns are matched (substring) on the lowercased claim text. A weighted
# total at or above RISK_INDICATOR_THRESHOLD forces the HIGH RISK band (20-30)
# regardless of the verdict. Weights and the threshold are the tunable knobs.
RISK_INDICATOR_THRESHOLD = 3

RISK_INDICATORS = [
    {
        "id": "credentials",
        "weight": 3,
        "label": "Requests OTP / PIN / banking credentials",
        "why": "Legitimate organizations never ask for your OTP, PIN, CVV or "
               "banking password. Sharing these hands over control of your account.",
        "patterns": [
            "otp", "one time password", "bank pin", "pin number", "atm pin",
            "upi pin", "cvv", "cvv2", "card number", "card details",
            "banking password", "net banking", "account number", "aadhaar",
            "pan card", "card pin", "otp number", "bank password",
        ],
    },
    {
        "id": "advance_fee",
        "weight": 3,
        "label": "Asks you to pay first / advance fee",
        "why": "Demanding a fee before delivering a prize, job, loan or refund "
               "is the classic advance-fee scam pattern.",
        "patterns": [
            "pay first", "pay a fee", "pay the fee", "registration fee",
            "processing fee", "joining fee", "advance payment", "security deposit",
            "send money", "transfer money", "money to release", "deposit to",
            "pay to receive", "fee to claim", "to receive your", "to claim your",
        ],
    },
    {
        "id": "guaranteed_returns",
        "weight": 3,
        "label": "Guaranteed / risk-free returns",
        "why": "Investment returns are never guaranteed; guaranteed or risk-free "
               "return promises are a known fraud warning sign.",
        "patterns": [
            "guaranteed", "assured returns", "assured profit", "guarantee returns",
            "guaranteed return", "guaranteed profit", "guaranteed income",
            "guaranteed payout", "risk free", "risk-free", "no risk", "no loss",
            "100% profit", "certain profit", "fixed returns", "fixed profit",
        ],
    },
    {
        "id": "get_rich_quick",
        "weight": 3,
        "label": "Get-rich-quick / unrealistic profit promise",
        "why": "Doubling money or huge profits in days has no legitimate basis "
               "and is a hallmark of Ponzi and investment fraud.",
        "patterns": [
            "double your money", "double money", "triple your money", "get rich",
            "get rich quick", "make money fast", "easy money", "earn lakhs",
            "earn crores", "profit tomorrow", "money tomorrow", "profit in a day",
            "profit in 24 hours", "profit overnight", "overnight profit",
            "multiply your money",
        ],
    },
    {
        "id": "prize_lure",
        "weight": 2,
        "label": "Prize / lottery lure",
        "why": "Official prizes are never announced by asking you to act fast or "
               "share details - unexpected prize messages are a common scam bait.",
        "patterns": [
            "you have won", "you won", "congratulations", "lottery", "win prize",
            "won a prize", "claim your prize", "receive your prize", "prize money",
            "lucky winner", "selected for a prize", "gift voucher", "cash prize",
        ],
    },
    {
        "id": "authority",
        "weight": 2,
        "label": "Impersonates an official body",
        "why": "Scammers pretend to be banks, government offices or regulators. "
               "Real officials do not solicit payments or credentials by message.",
        "patterns": [
            "tax refund", "income tax", "government scheme", "ministry",
            "bank official", "bank manager", "rbi", "sebi", "police", "court",
            "official letter", "official notice", "lottery department",
            "income tax department", "customs",
        ],
    },
    {
        "id": "urgency",
        "weight": 1,
        "label": "Urgency / deadline pressure",
        "why": "Creating artificial urgency stops you from thinking it through - "
               "a standard manipulation tactic in scams.",
        "patterns": [
            "act now", "act today", "limited time", "only today", "today only",
            "expires today", "expires soon", "last chance", "hurry", "urgent",
            "immediately", "within 24 hours", "within 48 hours", "before midnight",
            "final warning", "don't miss", "dont miss",
        ],
    },
]


def detect_risk_indicators(low_text: str) -> list:
    """Return the risk indicators matched on the lowercased claim text."""
    hits = []
    for spec in RISK_INDICATORS:
        matched = [p for p in spec["patterns"] if p in low_text]
        if matched:
            hits.append({
                "id": spec["id"],
                "label": spec["label"],
                "why": spec["why"],
                "weight": spec["weight"],
                "matched": matched[:3],
            })
    return hits


def calculate_claim_trust_score(low_text: str, verdict: str, category: str) -> dict:
    """Compute the deterministic trust score + risk label for a claim.

    Two display bands:
      HIGH RISK  20-30  -> verdict "False", or risk-indicator weight >= threshold
      LOW RISK   70-90  -> otherwise (score varies with the verdict)

    Returns dict: score, status, risk_level, risk_label, risk_indicators,
    recommended_action, verification_suggestions, why.
    """
    indicators = detect_risk_indicators(low_text or "")
    weighted = sum(i["weight"] for i in indicators)
    base_score, base_status = VERDICT_SCORE.get(verdict, (78, "warning"))

    if verdict == "False":
        # A proven-false claim is always high risk; indicators only lower it
        # further within the 20-30 band (False alone = 25).
        score = 30 - min(max(weighted, 5), 10)
        risk_level, risk_label = "high", "HIGH RISK"
        why = [i["why"] for i in indicators]
        if not why:
            why = ["The claim is false according to the evidence in the TrustLens knowledge base."]
    elif weighted >= RISK_INDICATOR_THRESHOLD:
        score = 30 - min(weighted, 10)
        risk_level, risk_label = "high", "HIGH RISK"
        why = [i["why"] for i in indicators]
    else:
        score, _status = base_score, base_status
        risk_level, risk_label = "low", "LOW RISK"
        why = [i["why"] for i in indicators]
        if not why:
            why = ["No scam-risk indicators were detected in this claim."]

    status = classify(score)

    if risk_level == "high":
        recommended_action = (
            "Do not share any personal, OTP or banking details, and do not send "
            "money. Treat the message as a likely scam, report it, and verify "
            "through an official channel."
        )
    else:
        recommended_action = (
            "No scam indicators were detected. Treat the claim as informational - "
            "verify it with official sources before acting on financial or medical advice."
        )

    verification_suggestions = [
        "Contact the official bank, company or government helpline directly (not via the message).",
        "Never share OTP, PIN, CVV or passwords with anyone, however official the message looks.",
        "Report suspicious messages to the local cybercrime or consumer helpline.",
    ]

    return {
        "score": score,
        "status": status,
        "risk_level": risk_level,
        "risk_label": risk_label,
        "risk_indicators": indicators,
        "recommended_action": recommended_action,
        "verification_suggestions": verification_suggestions,
        "why": why,
    }


# --------------------------------------------------------------------------- #
# Main entry point
# --------------------------------------------------------------------------- #
def scan_claim(claim: str) -> dict:
    """Analyse a claim and return a verdict, confidence, evidence and sources."""
    start = time.perf_counter()
    claim = (claim or "").strip()

    if not claim:
        return {
            "score": 0, "status": "dangerous", "verdict": None,
            "confidence": None, "category": "General",
            "risk_level": None, "risk_label": None,
            "risk_indicators": [], "recommended_action": None,
            "verification_suggestions": [],
            "explanation": "No claim was entered.",
            "evidence": [], "sources": [], "limitations": "Nothing to analyse.",
            "caution": None, "match": None, "reasons": [
                {"severity": "danger", "text": "No claim text was provided.", "points": 0}
            ],
            "processing_time_ms": 0,
        }

    if len(claim) < MIN_CLAIM_CHARS:
        return {
            "score": 0, "status": "dangerous", "verdict": None,
            "confidence": None, "category": "General",
            "risk_level": None, "risk_label": None,
            "risk_indicators": [], "recommended_action": None,
            "verification_suggestions": [],
            "explanation": "The claim is too short to analyse meaningfully. "
                           "Please enter a complete statement.",
            "evidence": [], "sources": [], "limitations": "Input too short.",
            "caution": None, "match": None, "reasons": [
                {"severity": "warning", "text": "Claim text too short.", "points": 0}
            ],
            "processing_time_ms": int((time.perf_counter() - start) * 1000),
        }

    truncated = len(claim) > MAX_CLAIM_CHARS
    if truncated:
        claim = claim[:MAX_CLAIM_CHARS]
        logger.info("Claim truncated to %s chars", MAX_CLAIM_CHARS)

    low = re.sub(r"\s+", " ", claim.lower()).strip()
    category = detect_category(claim)
    negated = _is_negated(low)

    entry = _match_entry(low, category)
    if entry:
        if negated and entry.get("negated_verdict"):
            verdict = entry["negated_verdict"]
            confidence = entry.get("negated_confidence", entry["confidence"])
            explanation = entry["negated_explanation"]
            evidence = entry["evidence"]
            sources = entry["sources"]
            caution = entry.get("caution")
        elif negated:
            # No explicit negated variant: a negated factual verdict must not be
            # reported as if the fact still held. Invert Supported/False safely.
            if entry["verdict"] == "Supported":
                verdict = "Unsupported"
                confidence = "Medium"
                explanation = (
                    "The claim is the negation of a well-established fact and is "
                    "not supported by the evidence available to us."
                )
            elif entry["verdict"] == "False":
                verdict = "Supported"
                confidence = "High"
                explanation = (
                    "The claim correctly denies a statement that is false according "
                    "to the evidence in our knowledge base."
                )
            else:
                verdict = entry["verdict"]
                confidence = entry["confidence"]
                explanation = entry["explanation"]
            evidence = entry["evidence"]
            sources = entry["sources"]
            caution = entry.get("caution")
        else:
            verdict = entry["verdict"]
            confidence = entry["confidence"]
            explanation = entry["explanation"]
            evidence = entry["evidence"]
            sources = entry["sources"]
            caution = entry.get("caution")
        match_kind = "knowledge_base"
    else:
        markers_hit = [m for m in UNSUPPORTED_MARKERS if m in low]
        high_risk_category = category in ("Health/Medical", "Finance/Investment", "Product/Beauty", "Jobs/Employment")
        if markers_hit and (len(markers_hit) >= 2 or high_risk_category):
            verdict = "Unsupported"
            confidence = "Low"
            explanation = (
                "We could not locate reliable evidence for this claim. It relies "
                "on unsubstantiated marketing language "
                f"('{markers_hit[0]}'). This means the claim is not supported by "
                "the evidence we have - it is NOT proof that the claim is false, "
                "and a search by a qualified professional may still be warranted."
            )
            evidence = [
                "No reliable source in the TrustLens evidence base supports this claim.",
                f"Detected unsupported marketing language: {', '.join(markers_hit[:3])}.",
            ]
            sources = []
            caution = "medical" if category == "Health/Medical" else ("financial" if category == "Finance/Investment" else None)
            match_kind = "markers"
        else:
            verdict = "Unverifiable"
            confidence = "Low"
            explanation = (
                "We could not locate reliable evidence that either supports or "
                "refutes this claim. This is NOT the same as the claim being "
                "false - it simply means we could not verify it from the sources "
                "available to us."
            )
            evidence = [
                "The claim does not match any entry in the TrustLens evidence base.",
                "No reliable sources were located for or against this specific claim.",
            ]
            sources = []
            caution = "medical" if category == "Health/Medical" else ("financial" if category == "Finance/Investment" else None)
            match_kind = "none"

    score, status = VERDICT_SCORE.get(verdict, (50, "warning"))
    if truncated:
        explanation += " (Note: the claim was longer than the analysis limit and was truncated.)"

    caution_text = {
        "medical": MEDICAL_DISCLAIMER,
        "financial": FINANCIAL_DISCLAIMER,
    }.get(caution)

    score_info = calculate_claim_trust_score(low, verdict, category)
    score, status = score_info["score"], score_info["status"]

    reasons = [{
        "severity": {"Supported": "success", "Mostly supported": "success",
                     "Misleading": "warning", "Unsupported": "warning",
                     "False": "danger", "Unverifiable": "info",
                     "Insufficient evidence": "info"}[verdict],
        "text": f"{verdict} - {category}",
        "points": 0,
        "detail": explanation[:300],
    }]

    limitations = []
    if match_kind == "none":
        limitations.append("No matching entry in the built-in evidence base - we could not "
                           "verify this claim from available sources.")
    if match_kind == "markers":
        limitations.append("Classification is based on marketing language; the underlying "
                           "topic was not verified against a source.")
    if category in ("Health/Medical", "Finance/Investment"):
        limitations.append("High-risk category - treat the result as informational only.")
    if truncated:
        limitations.append("Claim was truncated at the analysis limit.")
    if not limitations:
        limitations.append("This verdict reflects the consensus of the listed sources at "
                           "the time of writing; evidence can change.")

    payload = {
        "score": score,
        "status": status,
        "verdict": verdict,
        "confidence": confidence,
        "category": category,
        "risk_level": score_info["risk_level"],
        "risk_label": score_info["risk_label"],
        "risk_indicators": score_info["risk_indicators"],
        "recommended_action": score_info["recommended_action"],
        "verification_suggestions": score_info["verification_suggestions"],
        "explanation": explanation,
        "evidence": evidence,
        "sources": sources,
        "limitations": " ".join(limitations),
        "caution": caution_text,
        "reasons": reasons,
        "match": match_kind,
        "processing_time_ms": int((time.perf_counter() - start) * 1000),
    }
    logger.info("Claim scan complete: verdict=%s confidence=%s category=%s match=%s",
                verdict, confidence, category, match_kind)
    return payload


def persist_scan(app, user_id, claim, payload: dict):
    """Persist a claim scan. Never raises."""
    from models import db
    from models.scan import ClaimScan

    try:
        scan = ClaimScan(
            user_id=user_id,
            claim_text=claim[:MAX_CLAIM_CHARS],
            category=payload.get("category"),
            verdict=payload.get("verdict"),
            confidence=payload.get("confidence"),
            explanation=(payload.get("explanation") or ""),
            evidence=payload.get("evidence"),
            sources=payload.get("sources"),
            limitations=payload.get("limitations"),
            caution=payload.get("caution"),
            trust_score=payload["score"],
            status=payload["status"],
            reasons=payload.get("reasons"),
        )
        db.session.add(scan)
        db.session.commit()
    except Exception:  # noqa: BLE001
        db.session.rollback()
        app.logger.exception("Failed to persist claim scan")
