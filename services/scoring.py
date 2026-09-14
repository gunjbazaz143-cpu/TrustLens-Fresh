"""
Shared scoring primitives.

Every scanner produces an explainable 0-100 trust score. A high score means SAFE,
a low score means DANGEROUS. Reasons carry a severity so the UI can colour them.

severity values: "success" (safe), "warning" (caution), "danger" (risk), "info" (neutral note).
"""

from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class ScanResult:
    """Standard structure returned by every scanner service."""

    score: int = 100
    status: str = "safe"
    reasons: List[Dict[str, str]] = field(default_factory=list)
    extra: Dict = field(default_factory=dict)

    def __post_init__(self):
        self.score = max(0, min(100, self.score))
        self.status = classify(self.score)


def classify(score: int) -> str:
    """Map a 0-100 trust score to a status bucket."""
    if score >= 80:
        return "safe"
    if score >= 50:
        return "warning"
    return "dangerous"


# Display bands per status. Every scanner clamps its evidence-derived score
# into the band for its status so the gauge, pill and verdict agree:
#   dangerous (HIGH RISK)  20-30
#   warning   (MODERATE)   50-60
#   safe      (LOW RISK)   80-95
STATUS_BANDS = {
    "safe": (80, 95),
    "warning": (50, 60),
    "moderate": (50, 60),
    "dangerous": (20, 30),
}


def remap_score_to_band(score: int, status: str) -> int:
    """Clamp a 0-100 score into the display band for its status.

    Scores already inside their band are returned unchanged; out-of-band scores
    are clamped to the band edge. The mapping is deterministic and never moves a
    score across a status boundary.
    """
    lo, hi = STATUS_BANDS.get(status, (40, 60))
    return max(lo, min(hi, max(0, min(100, score))))


class ScoreBuilder:
    """
    Accumulates penalties / notes and produces a final ScanResult.
    Penalties are capped so the score can never go below zero.
    """

    def __init__(self, start: int = 100):
        self._score = max(0, min(100, start))
        self.reasons: List[Dict[str, str]] = []

    # ---- Mutations ----
    def penalty(self, points: int, text: str, severity: str = "danger") -> "ScoreBuilder":
        """Subtract points with a human-readable reason."""
        self.reasons.append({"severity": severity, "text": text, "points": abs(points)})
        self._score -= abs(points)
        return self

    def note(self, text: str, severity: str = "info") -> "ScoreBuilder":
        """Add a neutral / positive note without changing the score."""
        self.reasons.append({"severity": severity, "text": text, "points": 0})
        return self

    def add_reason(self, reason: Dict[str, str]) -> "ScoreBuilder":
        reason.setdefault("points", 0)
        self.reasons.append(reason)
        return self

    # ---- Output ----
    @property
    def score(self) -> int:
        return max(0, min(100, self._score))

    def build(self, extra: Dict | None = None) -> ScanResult:
        return ScanResult(score=self.score, reasons=self.reasons, extra=extra or {})


# Reusable content heuristics shared by several scanners ---------------------

# High-risk TLDs frequently used for disposable scam domains.
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz", ".click", ".zip", ".mov"}

# Keywords that strongly suggest phishing / scam intent.
SUSPICIOUS_URL_KEYWORDS = [
    "login", "verify", "secure", "account-update", "confirm", "wallet",
    "bonus", "prize", "claim", "winner", "refund", "bank-details",
]

# Common free mail providers - legitimate companies rarely use them for HR.
FREE_MAIL_DOMAINS = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "yahoo.co.in"}

# Words that signal pressure/urgency in messages and emails.
URGENCY_WORDS = [
    "urgent", "immediately", "act now", "expires", "deadline",
    "final warning", "within 24 hours", "asap", "right away", "last chance",
]

# Payment-request phrases used by advance-fee scams.
PAYMENT_REQUEST_PHRASES = [
    "registration fee", "processing fee", "security deposit", "advance payment",
    "training fee", "money to release", "unlock fee", "joining fee", "first investment",
    "pay deposit", "deposit money", "send money", "pay a fee", "fee to", "to secure your visa",
]
