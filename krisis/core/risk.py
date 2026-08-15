"""
Risk Engine — deterministic, reproducible, evidence-backed. No LLM involved.

Every point of the score must be traceable to a contributing evidence item
(see RISK ENGINE in the design doc). Weights are fixed and documented here
rather than invented ad hoc, and are intentionally conservative: independence
and evidence_type diversity matter more than raw detection counts.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Optional

from .correlation import CorrelationResult
from .models import Evidence, Independence, RiskAssessment, RiskCategory

# Per-evidence-type base weight (0..1). These represent how much a single strong
# observation of this type should move the score, before confidence/independence
# scaling is applied. Documented rationale:
#  - reputation: direct third-party threat intel is the strongest single signal
#  - infrastructure: shared hosting/cert with known-bad infra is strong but indirect
#  - registration: weak alone (many legit sites are new), moderate combined
#  - behavior: redirects/heuristics observed directly by KRISIS, moderate-strong
#  - identity: brand impersonation signals, strong when present
TYPE_WEIGHTS: dict[str, float] = {
    "reputation": 1.0,
    "infrastructure": 0.8,
    "identity": 0.85,
    "behavior": 0.7,
    "registration": 0.4,
    "historical": 0.9,
    "unknown": 0.3,
}

INDEPENDENCE_MULTIPLIER: dict[str, float] = {
    Independence.INDEPENDENT.value: 1.0,
    Independence.CORRELATED.value: 0.7,
    Independence.DERIVED.value: 0.5,
    Independence.DUPLICATE.value: 0.15,
}

# Diminishing returns: the Nth piece of supporting evidence of the same type
# contributes less than the 1st (evidence stacking should not be linear).
DIMINISHING_FACTOR = 0.65


class RiskEngine:
    def score(
        self,
        correlation: CorrelationResult,
        historical_similarity: Optional[dict] = None,
    ) -> RiskAssessment:
        support_points, support_contributors = self._weighted_points(correlation.supporting)
        contra_points, _ = self._weighted_points(correlation.contradicting)

        # Historical pattern similarity to prior confirmed cases is folded in as its
        # own contributor, separate from current reputation (see CURRENT VS HISTORICAL
        # INTELLIGENCE) — a clean current reputation should not erase a strong historical
        # resemblance to known-bad infrastructure.
        historical_points = 0.0
        if historical_similarity and historical_similarity.get("similarity", 0) >= 0.6:
            historical_points = 18.0 * historical_similarity["similarity"]
            support_contributors.append(
                f"historical similarity {historical_similarity['similarity']:.0%} "
                f"to {historical_similarity.get('pattern_name', 'a prior pattern')}"
            )

        raw_score = support_points + historical_points - (0.5 * contra_points)
        # Evidence diversity acts as a confidence multiplier on the raw score rather
        # than an additive bonus — a single-source finding should not reach HIGH.
        diversity_factor = 0.6 + 0.4 * correlation.evidence_diversity
        score = max(0, min(100, round(raw_score * diversity_factor)))

        category = self._categorize(score)
        confidence = self._confidence(correlation, historical_similarity)

        top_contributors = sorted(
            support_contributors, key=lambda c: c, reverse=False
        )[:5]

        counter_notes = [
            f"{e.signal}: {e.value}" for e in correlation.contradicting[:5]
        ]

        return RiskAssessment(
            score=score,
            category=category,
            confidence=confidence,
            supporting=[e.to_dict() for e in correlation.supporting],
            contradicting=[e.to_dict() for e in correlation.contradicting],
            top_contributors=top_contributors or counter_notes[:0] or ["no strong single contributor"],
            historical_similarity=historical_similarity,
        )

    def _weighted_points(self, evidence: list[Evidence]) -> tuple[float, list[str]]:
        points = 0.0
        contributors: list[str] = []
        seen_type_counts: dict[str, int] = defaultdict(int)

        # Strongest evidence first so diminishing returns apply to the *weaker*
        # duplicates of a type, not the strongest one.
        for ev in sorted(evidence, key=lambda e: e.confidence, reverse=True):
            base = TYPE_WEIGHTS.get(ev.evidence_type, TYPE_WEIGHTS["unknown"])
            indep_mult = INDEPENDENCE_MULTIPLIER.get(ev.independence.value, 0.5)
            occurrence = seen_type_counts[ev.evidence_type]
            diminishing = DIMINISHING_FACTOR ** occurrence
            seen_type_counts[ev.evidence_type] += 1

            contribution = 20.0 * base * ev.confidence * indep_mult * diminishing
            points += contribution
            if contribution >= 3.0:
                contributors.append(f"{ev.signal} ({ev.source})")

        return points, contributors

    def _categorize(self, score: int) -> RiskCategory:
        if score >= 80:
            return RiskCategory.CRITICAL
        if score >= 60:
            return RiskCategory.HIGH
        if score >= 30:
            return RiskCategory.MEDIUM
        return RiskCategory.LOW

    def _confidence(self, correlation: CorrelationResult, historical_similarity: Optional[dict]) -> float:
        total_evidence = len(correlation.supporting) + len(correlation.contradicting) + len(correlation.neutral)
        if total_evidence == 0:
            return 0.0
        volume_factor = min(1.0, total_evidence / 8.0)
        diversity_factor = correlation.evidence_diversity
        contradiction_penalty = 0.0
        if correlation.supporting and correlation.contradicting:
            ratio = len(correlation.contradicting) / max(1, len(correlation.supporting))
            contradiction_penalty = min(0.3, ratio * 0.2)

        historical_bonus = 0.1 if (historical_similarity and historical_similarity.get("similarity", 0) >= 0.6) else 0.0

        confidence = 0.35 + 0.35 * volume_factor + 0.2 * diversity_factor + historical_bonus - contradiction_penalty
        return max(0.0, min(0.99, round(confidence, 3)))
