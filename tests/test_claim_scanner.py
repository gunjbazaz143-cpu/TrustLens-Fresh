"""
Claim scanner validation suite.

Runnable without pytest:

    python tests/test_claim_scanner.py            # run all checks

Assertions are behaviour-based, not exact-text. The scanner must never call a
claim "false" without evidence, and must never claim proof it does not have.

Behavioural guarantees exercised here:

  C1  Supported fact (smoking -> cancer) scores safe
  C2  False claim (bleach cures COVID-19) is surfaced as the most serious
      finding and scores dangerous
  C3  Misleading claims (acne in 24h) score warning in the NORMAL band; claims
      carrying scam-risk indicators (guaranteed returns, double your money)
      are forced to HIGH RISK (20-30)
  C4  Unsupported claims (cures diabetes, herbal cure) score warning
  C5  Unverifiable claims are honestly "could not verify" - never "false"
  C6  negation is honoured ("no cure for diabetes" -> Supported)
  C7  empty / too-short input -> null verdict, never a fake verdict
  C8  over-long claims are truncated safely, with a visible note
  C9  medical / financial claims carry explicit caution disclaimers
  C10 determinism: same claim in -> identical result out
  C11 structural invariants on every payload (no fabricated URLs in sources)
  SPEC spec trust bands: guaranteed-profit and OTP/PIN claims -> HIGH 20-30,
       a benign savings claim -> LOW 70-90
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from services.claim_scanner import (  # noqa: E402
    MAX_CLAIM_CHARS,
    KB_ENTRIES,
    RISK_INDICATOR_THRESHOLD,
    calculate_claim_trust_score,
    detect_risk_indicators,
    scan_claim,
)

ALLOWED_VERDICTS = {"Supported", "Mostly supported", "Misleading", "Unsupported",
                    "False", "Unverifiable", "Insufficient evidence"}
ALLOWED_CONFIDENCE = {"High", "Medium", "Low"}
ALLOWED_CATEGORIES = {"General", "Health/Medical", "Finance/Investment",
                      "Product/Beauty", "Jobs/Employment", "Technology", "Education"}

CLAIM_PAYLOAD_KEYS = [
    "score", "status", "verdict", "confidence", "category", "risk_level",
    "risk_label", "risk_indicators", "recommended_action",
    "verification_suggestions", "explanation", "evidence", "sources",
    "limitations", "caution", "reasons", "match", "processing_time_ms",
]


def structural_issues(payload: dict) -> list:
    issues = []
    for key in CLAIM_PAYLOAD_KEYS:
        if key not in payload:
            issues.append(f"missing key '{key}'")
    if not (0 <= payload.get("score", -1) <= 100):
        issues.append("score out of 0-100")
    if payload["status"] not in ("safe", "warning", "dangerous"):
        issues.append(f"bad status {payload['status']!r}")
    verdict = payload.get("verdict")
    if verdict is not None:
        if verdict not in ALLOWED_VERDICTS:
            issues.append(f"bad verdict {verdict!r}")
        # the score must sit in the display band for its status:
        # HIGH RISK 20-30, NORMAL 70-90
        if payload["status"] == "dangerous":
            if not (20 <= payload["score"] <= 30):
                issues.append(f"dangerous score {payload['score']} outside 20-30")
        elif not (70 <= payload["score"] <= 90):
            issues.append(f"normal score {payload['score']} outside 70-90")
        if payload["risk_level"] not in ("high", "low"):
            issues.append(f"bad risk_level {payload['risk_level']!r}")
        if payload["risk_label"] != (("HIGH RISK" if payload["risk_level"] == "high" else "LOW RISK")):
            issues.append(f"bad risk_label {payload['risk_label']!r}")
    if payload.get("confidence") not in ALLOWED_CONFIDENCE and payload.get("confidence") is not None:
        issues.append(f"bad confidence {payload['confidence']!r}")
    if payload["category"] not in ALLOWED_CATEGORIES:
        issues.append(f"bad category {payload['category']!r}")
    for s in payload.get("sources", []):
        name = s.get("name", "") if isinstance(s, dict) else s
        if not name:
            issues.append("source entry has no name")
        elif "http" in name.lower():
            issues.append("source contains a fabricated URL")
    for r in payload.get("reasons", []):
        if "severity" not in r or "text" not in r:
            issues.append("reason missing severity/text")
    if verdict in ("Supported", "False") and payload["confidence"] != "High":
        issues.append("supported/false verdict should be High confidence")
    return issues


def test_supported_claims():
    failures = []
    for claim, expect in (
        ("Smoking causes lung cancer.", "Supported"),
        ("Aspirin reduces fever.", "Supported"),
        ("There is no cure for diabetes.", "Supported"),
    ):
        payload = scan_claim(claim)
        if payload["verdict"] != expect:
            failures.append(f"C1/C6 {claim[:30]!r}: {payload['verdict']} != {expect}")
        if payload["status"] != "safe":
            failures.append(f"C1/C6 {claim[:30]!r}: status {payload['status']} != safe")
    if not failures:
        print("C1/C6 supported claims passed (incl. negation).")
    return failures


def test_false_claims():
    failures = []
    for claim in (
        "Drinking bleach cures COVID-19.",
        "Antibiotics cure viral infections.",
        "Vaccines contain microchips to track you.",
    ):
        payload = scan_claim(claim)
        if payload["verdict"] != "False":
            failures.append(f"C2 {claim[:30]!r}: {payload['verdict']} != False")
        if payload["status"] != "dangerous":
            failures.append(f"C2 {claim[:30]!r}: status {payload['status']} != dangerous")
        if payload["score"] != 25:
            failures.append(f"C2 {claim[:30]!r}: score {payload['score']} != 25")
        if payload["match"] != "knowledge_base":
            failures.append(f"C2 {claim[:30]!r}: match {payload['match']} != knowledge_base")
    # the bleach+covid pair must surface the False finding, not the milder one
    payload = scan_claim("Drinking bleach cures COVID-19.")
    if "bleach" not in payload["explanation"].lower():
        failures.append("C2 bleach explanation missing the substance")
    if not failures:
        print("C2 false claims passed (bleach/covid, antibiotics/viruses, vaccine chips).")
    return failures


def test_misleading_claims():
    failures = []
    # plain marketing exaggeration stays in the NORMAL band (70-90 / warning)
    warning_cases = {
        "This cream removes acne in 24 hours.": ("Misleading", "Medium"),
        "This juice detoxifies your body overnight.": ("Misleading", "Medium"),
    }
    for claim, (expect_verdict, expect_conf) in warning_cases.items():
        payload = scan_claim(claim)
        if payload["verdict"] != expect_verdict:
            failures.append(f"C3/C4 {claim[:30]!r}: {payload['verdict']} != {expect_verdict}")
        if payload["confidence"] != expect_conf:
            failures.append(f"C3/C4 {claim[:30]!r}: conf {payload['confidence']} != {expect_conf}")
        if payload["status"] != "warning" or not (70 <= payload["score"] <= 90):
            failures.append(f"C3/C4 {claim[:30]!r}: status/score {payload['status']}/{payload['score']} not 70-90/warning")
    # scam-signal claims are forced into the HIGH RISK band (20-30 / dangerous)
    high_cases = {
        "This investment gives guaranteed 30% returns.": ("Misleading", "High"),
        "Double your money in 7 days with this scheme.": ("Unsupported", "High"),
    }
    for claim, (expect_verdict, expect_conf) in high_cases.items():
        payload = scan_claim(claim)
        if payload["verdict"] != expect_verdict:
            failures.append(f"C3/C4 {claim[:30]!r}: {payload['verdict']} != {expect_verdict}")
        if payload["confidence"] != expect_conf:
            failures.append(f"C3/C4 {claim[:30]!r}: conf {payload['confidence']} != {expect_conf}")
        if payload["status"] != "dangerous" or not (20 <= payload["score"] <= 30):
            failures.append(f"C3/C4 {claim[:30]!r}: status/score {payload['status']}/{payload['score']} not 20-30/dangerous")
        if payload["risk_label"] != "HIGH RISK":
            failures.append(f"C3/C4 {claim[:30]!r}: risk_label {payload['risk_label']}")
    if not failures:
        print("C3/C4 misleading/unsupported claims passed.")
    return failures


def test_unverifiable_honesty():
    failures = []
    for claim in (
        "The pyramids were built by ancient aliens.",
        "The stock market will rise next Monday.",
    ):
        payload = scan_claim(claim)
        if payload["verdict"] != "Unverifiable":
            failures.append(f"C5 {claim[:30]!r}: {payload['verdict']} != Unverifiable")
        if payload["confidence"] != "Low":
            failures.append(f"C5 {claim[:30]!r}: confidence not Low")
        if payload["match"] != "none":
            failures.append(f"C5 {claim[:30]!r}: match {payload['match']} != none")
        if "NOT the same" not in payload["explanation"]:
            failures.append("C5 explanation must distinguish unverifiable from false")
    if not failures:
        print("C5 unverifiable honesty passed.")
    return failures


def test_negation_variants():
    failures = []
    for claim, expect in (
        ("There is no cure for diabetes.", "Supported"),
        ("This product does not cure cancer.", "Supported"),
        ("Smoking does not cause cancer.", "Unsupported"),
    ):
        payload = scan_claim(claim)
        if payload["verdict"] != expect:
            failures.append(f"C6 {claim[:30]!r}: {payload['verdict']} != {expect}")
    if not failures:
        print("C6 negation variants passed.")
    return failures


def test_empty_and_short():
    failures = []
    payload = scan_claim("")
    if payload["verdict"] is not None:
        failures.append("C7 empty claim should have null verdict")
    if payload["score"] != 0:
        failures.append("C7 empty claim score != 0")
    payload = scan_claim("Hi")
    if payload["verdict"] is not None:
        failures.append("C7 short claim should have null verdict")
    if not failures:
        print("C7 empty/short input passed.")
    return failures


def test_long_claim():
    failures = []
    long_text = "This cream removes acne in 24 hours, guaranteed. " + "A" * 2200
    payload = scan_claim(long_text)
    if payload["verdict"] != "Misleading":
        failures.append(f"C8 long claim: {payload['verdict']} != Misleading")
    if "truncated" not in payload["explanation"].lower():
        failures.append("C8 long claim missing truncation note")
    if "truncated" not in payload["limitations"].lower():
        failures.append("C8 long claim limitations missing truncation")
    if not failures:
        print("C8 long-claim handling passed.")
    return failures


def test_cautions():
    failures = []
    med = scan_claim("Drinking this herbal juice cures diabetes.")
    if "medical" not in (med["caution"] or "").lower():
        failures.append("C9 medical claim missing medical caution")
    fin = scan_claim("This scheme gives guaranteed 30% returns monthly.")
    if "financial" not in (fin["caution"] or "").lower():
        failures.append("C9 financial claim missing financial caution")
    # a generic claim should not need a caution
    gen = scan_claim("The pyramids were built by ancient aliens.")
    if gen["caution"]:
        failures.append("C9 general claim should have no caution")
    if not failures:
        print("C9 medical/financial cautions passed.")
    return failures


def test_determinism():
    failures = []
    claims = [
        "Drinking bleach cures COVID-19.",
        "Smoking causes lung cancer.",
        "This cream removes acne in 24 hours.",
        "The pyramids were built by ancient aliens.",
    ]
    for claim in claims:
        first = scan_claim(claim)
        second = scan_claim(claim)
        if first != second:
            failures.append(f"C10 non-deterministic for {claim[:30]!r}")
    if not failures:
        print("C10 determinism passed.")
    return failures


def test_spec_trust_bands():
    """Spec cases: HIGH RISK 20-30 / LOW RISK 70-90."""
    failures = []
    cases = [
        ("Invest \u20b95,000 today and get guaranteed \u20b950,000 profit tomorrow.",
         (20, 30), "HIGH RISK"),
        ("Saving money regularly can help build an emergency fund.",
         (70, 90), "LOW RISK"),
        ("Send your OTP and bank PIN to receive your prize.",
         (20, 30), "HIGH RISK"),
    ]
    for claim, (lo, hi), label in cases:
        payload = scan_claim(claim)
        if not (lo <= payload["score"] <= hi):
            failures.append(f"SPEC {claim[:30]!r}: score {payload['score']} not in {lo}-{hi}")
        if payload["risk_label"] != label:
            failures.append(f"SPEC {claim[:30]!r}: risk_label {payload['risk_label']} != {label}")
        if payload["risk_level"] not in ("high", "low"):
            failures.append(f"SPEC {claim[:30]!r}: bad risk_level {payload['risk_level']}")
        if not payload.get("recommended_action"):
            failures.append(f"SPEC {claim[:30]!r}: missing recommended_action")
        if payload.get("verification_suggestions") is None:
            failures.append(f"SPEC {claim[:30]!r}: missing verification_suggestions")
    # the reusable scoring function is deterministic and threshold-based
    for claim, expect_high in (("You won a prize, send your OTP.", True),
                               ("Saving monthly builds savings.", False)):
        info = calculate_claim_trust_score(claim.lower(), "Unverifiable", "General")
        if (info["risk_level"] == "high") != expect_high:
            failures.append(f"SPEC fn {claim[:30]!r}: risk_level {info['risk_level']}")
    if detect_risk_indicators("nothing suspicious here") != []:
        failures.append("SPEC fn: clean text matched no indicators")
    if not failures:
        print("SPEC claim trust bands passed (HIGH 20-30 / LOW 70-90).")
    return failures


def test_structural_all():
    failures = []
    claims = [
        "Smoking causes lung cancer.",
        "Drinking bleach cures COVID-19.",
        "There is no cure for diabetes.",
        "This cream removes acne in 24 hours.",
        "This scheme gives guaranteed 30% returns monthly.",
        "Double your money in 7 days with this scheme.",
        "Antibiotics cure viral infections.",
        "Vaccines contain microchips to track you.",
        "The pyramids were built by ancient aliens.",
        "The stock market will rise next Monday.",
        "",
        "Hi",
    ]
    for claim in claims:
        payload = scan_claim(claim)
        for issue in structural_issues(payload):
            failures.append(f"STRUCTURE({claim[:20]!r}): {issue}")
    # KB sanity: every entry has the fields scan_claim relies on
    for entry in KB_ENTRIES:
        for key in ("patterns", "context", "category", "verdict", "confidence",
                    "explanation", "evidence", "sources"):
            if key not in entry:
                failures.append(f"KB entry {entry.get('id')} missing '{key}'")
        if entry["verdict"] not in ALLOWED_VERDICTS:
            failures.append(f"KB entry {entry.get('id')} bad verdict {entry['verdict']}")
        if entry.get("negated_verdict") and entry["negated_verdict"] not in ALLOWED_VERDICTS:
            failures.append(f"KB entry {entry.get('id')} bad negated_verdict")
    if not failures:
        print("C11 structural invariants + KB sanity passed.")
    return failures


def main():
    verbose = "--table" not in sys.argv
    check_names = [
        test_supported_claims, test_false_claims, test_misleading_claims,
        test_unverifiable_honesty, test_negation_variants,
        test_empty_and_short, test_long_claim, test_cautions,
        test_determinism, test_spec_trust_bands, test_structural_all,
    ]
    failures = []
    for fn in check_names:
        if verbose:
            print(f"Running {fn.__name__} ...")
        failures.extend(fn())
    if failures:
        print("\nFAILURES:")
        for f in failures:
            print("  -", f)
        print(f"\n{len(failures)} failure(s).")
        sys.exit(1)
    print("\nAll claim scanner validation checks passed (C1-C11).")


if __name__ == "__main__":
    main()
