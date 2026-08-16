"""
KRISIS detection-accuracy validation matrix.

Each case pins ground truth against what KRISIS actually concludes, and *why*
— a correct category reached for the wrong reason, or reached by coincidence,
is a bug even when the bare category assertion would pass (see the loop's
own "correct verdict, wrong reason = BUG" rule). Cases run through the real
CorrelationEngine + RiskEngine, fed evidence shaped exactly like the real
collectors in krisis/collectors/ produce it (same signal names, polarities,
confidences), so this exercises the actual scoring arithmetic rather than a
paraphrase of it.

Fixtures are invented ("auroratech.com") rather than real brands — see
tests/test_identity.py for why: a mechanism that only works for a famous
domain is testing a hardcoded relationship, not a mechanism. No malicious
infrastructure is contacted; everything here is synthetic evidence.

Run standalone for a full diagnostic report of every case (not just failures):
    python -m tests.validation.test_accuracy_matrix
Run as part of the suite for regression:
    pytest tests/validation/
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from krisis.collectors.identity_collector import IdentityCollector
from krisis.core.correlation import CorrelationEngine
from krisis.core.graph import EntityGraph
from krisis.core.models import (
    Coverage, Entity, EntityType, Evidence, Independence, Polarity, RiskCategory,
)
from krisis.core.risk import RiskEngine

REAL = "auroratech.com"           # the established identity being imitated
FAKE = REAL.replace("o", "0", 1)  # aur0ratech.com — a glyph substitution


# -- shared fixture builders, mirroring real collector output shapes ----------

def _ev(signal, evidence_type, polarity, confidence, source, value="x",
        independence=Independence.INDEPENDENT) -> Evidence:
    return Evidence(
        source=source, entity_id="seed", signal=signal, value=value,
        evidence_type=evidence_type, polarity=polarity, confidence=confidence,
        independence=independence,
    )


def _whois_evidence(entity_id: str, ips, age_days=None, org="") -> list[Evidence]:
    evidence = [_ev("a_record", "infrastructure", Polarity.NEUTRAL, 0.9, "dns",
                     value=list(ips))]
    evidence[-1].entity_id = entity_id
    if age_days is not None:
        signal = "newly_registered_domain" if age_days < 30 else (
            "long_lived_domain" if age_days > 720 else "domain_age_days"
        )
        e = _ev(signal, "registration",
                Polarity.SUPPORTS_THREAT if age_days < 30 else (
                    Polarity.CONTRADICTS_THREAT if age_days > 720 else Polarity.NEUTRAL
                ),
                0.55, "whois", value=age_days)
        e.entity_id = entity_id
        evidence.append(e)
    if org:
        e = _ev("registrant_org", "registration", Polarity.NEUTRAL, 0.6, "whois", value=org)
        e.entity_id = entity_id
        evidence.append(e)
    return evidence


def _identity_evidence(seed: str, probe_table: dict[str, list[Evidence]]) -> list[Evidence]:
    """Runs the real IdentityCollector — the exact component the operator-
    verification bug (Section 7 of the loop) lived in — rather than
    paraphrasing its output."""
    collector = IdentityCollector(
        probe=lambda entity: probe_table.get(entity.value, []),
        references=lambda: {REAL},
    )
    return collector.collect(Entity(value=seed, type=EntityType.DOMAIN)).evidence


def _clean_reputation() -> Evidence:
    return _ev("no_detections", "reputation", Polarity.NEUTRAL, 0.3, "virustotal", value=0)


def _weak_positive_reputation(positives=8, total=70) -> Evidence:
    ratio = positives / total
    return _ev(
        "malicious_detection", "reputation", Polarity.SUPPORTS_THREAT,
        round(min(0.95, 0.5 + ratio), 2), "virustotal", value=f"{positives}/{total}",
    )


# -- validation cases -----------------------------------------------------------

@dataclass
class ValidationCase:
    key: str
    ground_truth: str
    why: str
    build: Callable[[], list[Evidence]]
    expected_categories: frozenset[RiskCategory]
    expected_evidence: frozenset[str] = frozenset()       # signals that must appear at all
    expected_non_evidence: frozenset[str] = frozenset()   # signals that must not appear as SUPPORTS_THREAT
    expected_max_score: int | None = None                 # score must not exceed this (category alone can hide a leak)
    coverage: Coverage = field(default_factory=lambda: Coverage(
        attempted={"identity", "whois", "dns", "virustotal"},
        available={"identity", "whois", "dns", "virustotal"},
        evidence_types={"identity", "registration", "infrastructure", "reputation"},
    ))
    historical_similarity: dict | None = None
    target: str = FAKE


CASES: list[ValidationCase] = [
    ValidationCase(
        key="A_benign_same_operator_lookalike",
        target=FAKE,
        ground_truth="benign — a defensive registration by the real operator",
        why=(
            "Both domains resolve to the same IP address, which is not "
            "self-reported and cannot be faked by an attacker for the "
            "legitimate operator's own infrastructure — a verified common "
            "operator, not merely a coincidence of WHOIS text."
        ),
        build=lambda: _identity_evidence(FAKE, {
            FAKE: _whois_evidence("fake", ["198.51.100.4"], age_days=900, org="auroratech inc"),
            REAL: _whois_evidence("real", ["198.51.100.4"], age_days=4000, org="auroratech inc"),
        }) + [_clean_reputation()],
        expected_categories=frozenset({RiskCategory.LOW}),
        expected_evidence=frozenset({"same_operator_variant"}),
        expected_non_evidence=frozenset({"lookalike_domain"}),
    ),
    ValidationCase(
        key="B_true_lookalike_different_operator",
        target=FAKE,
        ground_truth="malicious — impersonation of an established identity",
        why=(
            "No shared resolved address and no registrant-org match at all: "
            "nothing here supports common ownership, and the referent is old "
            "and established. This is the paypa1.com-shaped case identity.py "
            "exists for."
        ),
        build=lambda: _identity_evidence(FAKE, {
            FAKE: _whois_evidence("fake", ["203.0.113.9"], age_days=8, org="privacy service"),
            REAL: _whois_evidence("real", ["198.51.100.4"], age_days=4000, org="auroratech inc"),
        }) + [_clean_reputation()],
        expected_categories=frozenset({RiskCategory.MEDIUM}),
        expected_evidence=frozenset({"lookalike_domain"}),
        expected_non_evidence=frozenset({"same_operator_variant"}),
    ),
    ValidationCase(
        key="B2_lookalike_with_spoofed_registrant_org",
        target=FAKE,
        ground_truth="malicious — impersonation; the matching WHOIS org is self-reported, not proof",
        why=(
            "The exact shape of the g00gle.com validation case from the loop "
            "prompt: WHOIS registrant_org matches the impersonated brand, but "
            "there is no shared resolved address. registrant_org is free text "
            "the registrant supplies and no registry verifies it, so it must "
            "not by itself suppress the impersonation finding the way a "
            "verified shared IP does (Section 7's operatorship rule)."
        ),
        build=lambda: _identity_evidence(FAKE, {
            FAKE: _whois_evidence("fake", ["203.0.113.9"], age_days=8, org="auroratech inc"),
            REAL: _whois_evidence("real", ["198.51.100.4"], age_days=4000, org="auroratech inc"),
        }) + [_clean_reputation()],
        expected_categories=frozenset({RiskCategory.MEDIUM}),
        expected_evidence=frozenset({"lookalike_domain", "claimed_registrant_org_match"}),
        expected_non_evidence=frozenset({"same_operator_variant"}),
    ),
    ValidationCase(
        key="C_lookalike_plus_suspicious_redirect",
        target=FAKE,
        ground_truth="malicious — impersonation plus a redirect off the imitated brand",
        why=(
            "Identity mismatch alone is already MEDIUM; a redirect chain "
            "leaving the seed for an unrelated organization's domain is "
            "independent corroborating behavior, not proof by itself, but it "
            "should not leave the case sitting at the identity floor either."
        ),
        build=lambda: _identity_evidence(FAKE, {
            FAKE: _whois_evidence("fake", ["203.0.113.9"], age_days=8),
            REAL: _whois_evidence("real", ["198.51.100.4"], age_days=4000, org="auroratech inc"),
        }) + [
            _clean_reputation(),
            _ev("redirect_chain", "behavior", Polarity.NEUTRAL, 0.7, "page", value=["u1", "u2"]),
            _ev("cross_domain_redirect", "behavior", Polarity.SUPPORTS_THREAT, 0.55, "page",
                value="unrelated-landing.example"),
        ],
        expected_categories=frozenset({RiskCategory.MEDIUM, RiskCategory.HIGH}),
        expected_evidence=frozenset({"lookalike_domain", "cross_domain_redirect"}),
    ),
    ValidationCase(
        key="D_lookalike_plus_credential_form",
        target=FAKE,
        ground_truth="malicious — credential phishing",
        why=(
            "Brand impersonation plus a password-collecting form on the same "
            "artifact is the actual credential-phishing pattern (each alone "
            "is common and often benign); risk.py's interaction bonus exists "
            "so this combination scores materially above either part added "
            "alone (see test_risk.py::TestSecuritySignalInteraction for the "
            "product's own >=8-point margin contract — a two-signal case with "
            "no further corroboration is not promised to cross into HIGH, "
            "only to score well above the sum of its parts, consistent with "
            "risk.py's intentionally conservative weighting)."
        ),
        build=lambda: _identity_evidence(FAKE, {
            FAKE: _whois_evidence("fake", ["203.0.113.9"], age_days=8),
            REAL: _whois_evidence("real", ["198.51.100.4"], age_days=4000, org="auroratech inc"),
        }) + [
            _clean_reputation(),
            _ev("credential_form", "behavior", Polarity.SUPPORTS_THREAT, 0.5, "page",
                value={"password": True, "payment": False}),
        ],
        expected_categories=frozenset({RiskCategory.MEDIUM, RiskCategory.HIGH, RiskCategory.CRITICAL}),
        expected_evidence=frozenset({"lookalike_domain", "credential_form"}),
    ),
    ValidationCase(
        key="E_lookalike_plus_redirect_chain_only",
        target=FAKE,
        ground_truth="malicious — impersonation with an off-brand redirect, no credential capture observed",
        why=(
            "Same shape as C without the interaction-bonus signals: redirect "
            "evidence alone must not be dismissed as noise, but must not be "
            "inflated to the credential-phishing tier either."
        ),
        build=lambda: _identity_evidence(FAKE, {
            FAKE: _whois_evidence("fake", ["203.0.113.9"], age_days=8),
            REAL: _whois_evidence("real", ["198.51.100.4"], age_days=4000, org="auroratech inc"),
        }) + [
            _clean_reputation(),
            _ev("redirect_chain", "behavior", Polarity.NEUTRAL, 0.7, "page", value=["u1", "u2"]),
            _ev("redirect_target", "behavior", Polarity.NEUTRAL, 0.6, "page",
                value="https://unrelated-landing.example/"),
        ],
        expected_categories=frozenset({RiskCategory.MEDIUM}),
        expected_evidence=frozenset({"lookalike_domain"}),
    ),
    ValidationCase(
        key="F_legitimate_brand_domain",
        target=REAL,
        ground_truth="benign — this is the identity itself, not an imitation of it",
        why=(
            "candidates() is one-directional (deceptive glyph -> the "
            "character it imitates): a name with no deceptive glyph derives "
            "no candidate, so the mechanism that flags the typosquat must not "
            "also flag the identity it imitates."
        ),
        build=lambda: _identity_evidence(REAL, {
            REAL: _whois_evidence("real", ["198.51.100.4"], age_days=4000, org="auroratech inc"),
        }) + [_clean_reputation()],
        expected_categories=frozenset({RiskCategory.LOW}),
        expected_non_evidence=frozenset({"lookalike_domain", "same_operator_variant"}),
    ),
    ValidationCase(
        key="G_old_legitimate_domain",
        target=REAL,
        ground_truth="benign — an old, unremarkable domain with clean reputation",
        why=(
            "long_lived_domain is real counter-evidence for an ordinary "
            "finding (there is no identity finding here to begin with), so "
            "age should be allowed to count normally and the case should "
            "still land LOW."
        ),
        build=lambda: [
            _ev("long_lived_domain", "registration", Polarity.CONTRADICTS_THREAT, 0.55, "whois",
                value=4000),
            _clean_reputation(),
        ],
        expected_categories=frozenset({RiskCategory.LOW}),
    ),
    ValidationCase(
        key="H_resembles_a_confirmed_benign_prior_case",
        target="newshop.example",
        ground_truth="benign — clean now, and the historical resemblance is to a case a human already cleared",
        why=(
            "Section 12: historical memory must not convert an unknown or "
            "*benign* prior outcome into malicious knowledge. A strong "
            "structural resemblance to a CONFIRMED_BENIGN prior case must "
            "contribute zero points (OUTCOME_TRUST[confirmed_benign] == 0.0), "
            "not partial credit toward suspicion."
        ),
        build=lambda: [_clean_reputation()],
        expected_categories=frozenset({RiskCategory.LOW}),
        # A tight score bound, not just the category: OUTCOME_TRUST[confirmed_benign]
        # must be exactly 0.0, so this near-perfect resemblance must add exactly zero
        # points. Category alone would hide a partial leak — a mutation that changed
        # confirmed_benign's trust from 0.0 to 0.5 still landed LOW (leaked points were
        # too small to cross the MEDIUM boundary) until this bound was added.
        expected_max_score=0,
        historical_similarity={
            "similarity": 0.95, "pattern_name": "previously cleared shape",
            "prior_outcome": "confirmed_benign", "match_type": "structural",
        },
    ),
    ValidationCase(
        key="I_weak_but_positive_reputation_flag",
        target="borderline-artifact.example",
        ground_truth="suspicious — a live reputation source flagged it, however thinly corroborated",
        why=(
            "A direct third-party detection is a determination about the "
            "artifact itself, not circumstantial evidence. Even a single "
            "weak flag with little else corroborating it must not fall "
            "through to LOW: 'flagged' must never render as 'looks safe' "
            "just because the arithmetic total is small."
        ),
        build=lambda: [_weak_positive_reputation(positives=8, total=70)],
        expected_categories=frozenset({RiskCategory.MEDIUM}),
        expected_evidence=frozenset({"malicious_detection"}),
    ),
    ValidationCase(
        key="J_reputation_provider_unavailable",
        target="unchecked-artifact.example",
        ground_truth="unknown — KRISIS could not actually check reputation for this artifact",
        why=(
            "Section 13/19: 'nobody looked' must never render as 'nothing "
            "found'. DNS resolved cleanly but the reputation provider never "
            "answered, so KRISIS has no basis to assert the artifact looks "
            "safe."
        ),
        build=lambda: [
            _ev("a_record", "infrastructure", Polarity.NEUTRAL, 0.9, "dns", value=["203.0.113.50"]),
        ],
        expected_categories=frozenset({RiskCategory.INSUFFICIENT_EVIDENCE}),
        coverage=Coverage(
            attempted={"dns", "virustotal"}, available={"dns"}, evidence_types={"infrastructure"},
        ),
    ),
]


# -- runner ---------------------------------------------------------------------

@dataclass
class CaseResult:
    case: ValidationCase
    category: RiskCategory
    score: int
    confidence: float
    supporting_signals: set[str]
    contradicting_signals: set[str]
    missing_evidence: set[str]
    unexpected_evidence: set[str]
    category_ok: bool
    evidence_ok: bool
    score_ok: bool

    @property
    def passed(self) -> bool:
        return self.category_ok and self.evidence_ok and self.score_ok

    def report(self) -> str:
        score_bound = (
            f" (must be <= {self.case.expected_max_score})"
            if self.case.expected_max_score is not None else ""
        )
        lines = [
            f"[{'PASS' if self.passed else 'FAIL'}] {self.case.key}",
            f"  TARGET:                 {self.case.target}",
            f"  GROUND TRUTH:           {self.case.ground_truth}",
            f"  KRISIS RESULT:          {self.category.value}"
            f"  (expected one of {sorted(c.value for c in self.case.expected_categories)})",
            f"  SCORE / CONFIDENCE:     {self.score} / {self.confidence:.0%}{score_bound}",
            f"  SUPPORTING SIGNALS:     {sorted(self.supporting_signals) or '(none)'}",
            f"  CONTRADICTING SIGNALS:  {sorted(self.contradicting_signals) or '(none)'}",
            f"  EXPECTED, MISSING:      {sorted(self.missing_evidence) or '(none)'}",
            f"  UNEXPECTED, PRESENT:    {sorted(self.unexpected_evidence) or '(none)'}",
            f"  WHY:                    {self.case.why}",
        ]
        return "\n".join(lines)


def run_case(case: ValidationCase) -> CaseResult:
    evidence = case.build()
    correlation = CorrelationEngine().correlate(EntityGraph(), evidence)
    result = RiskEngine().score(
        correlation, historical_similarity=case.historical_similarity, coverage=case.coverage,
    )

    supporting_signals = {e["signal"] for e in result.supporting}
    contradicting_signals = {e["signal"] for e in result.contradicting}
    all_signals = supporting_signals | contradicting_signals

    missing = set(case.expected_evidence) - all_signals
    unexpected = set(case.expected_non_evidence) & supporting_signals

    return CaseResult(
        case=case,
        category=result.category,
        score=result.score,
        confidence=result.confidence,
        supporting_signals=supporting_signals,
        contradicting_signals=contradicting_signals,
        missing_evidence=missing,
        unexpected_evidence=unexpected,
        category_ok=result.category in case.expected_categories,
        evidence_ok=not missing and not unexpected,
        score_ok=case.expected_max_score is None or result.score <= case.expected_max_score,
    )


def run_all() -> list[CaseResult]:
    return [run_case(case) for case in CASES]


def test_validation_matrix():
    """Section 16/17/19 of the loop: repeatable, diagnostic accuracy checks.
    Failures list every case that mismatched, not just the first."""
    results = run_all()
    failures = [r for r in results if not r.passed]
    if failures:
        report = "\n\n".join(r.report() for r in failures)
        raise AssertionError(f"{len(failures)}/{len(results)} validation case(s) failed:\n\n{report}")


if __name__ == "__main__":
    results = run_all()
    print("=" * 78)
    print(f"KRISIS ACCURACY VALIDATION MATRIX — {len(results)} cases")
    print("=" * 78)
    for r in results:
        print(r.report())
        print("-" * 78)
    passed = sum(r.passed for r in results)
    print(f"{passed}/{len(results)} passed")
