"""
Risk Engine — deterministic, reproducible, evidence-backed. No LLM involved.

Every point of the score must be traceable to a contributing evidence item
(see RISK ENGINE in the design doc). Weights are fixed and documented here
rather than invented ad hoc, and are intentionally conservative: independence
and evidence_type diversity matter more than raw detection counts.

Three values are computed separately and are allowed to disagree (see RISK VS
CONFIDENCE VS PATTERN SIMILARITY):
  - score/category: how strongly current evidence indicates a threat
  - confidence:     how complete and reliable the evidence behind it is
  - historical similarity: how closely this resembles prior *validated* cases
"""

from __future__ import annotations

from collections import defaultdict
from typing import Optional

from .correlation import CorrelationResult
from .models import Coverage, Evidence, Independence, Outcome, RiskAssessment, RiskCategory

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

# How much a historical resemblance is allowed to move the score, scaled by how
# well the prior case was actually validated. An unvalidated prior case is a
# lead, not proof — this is the primary defence against KRISIS poisoning its own
# memory with its own unconfirmed guesses (see PATTERN POISONING RESISTANCE).
HISTORICAL_MAX_POINTS = 18.0
OUTCOME_TRUST: dict[str, float] = {
    Outcome.CONFIRMED_MALICIOUS.value: 1.0,
    Outcome.FALSE_NEGATIVE.value: 1.0,    # was malicious and we missed it — fully trusted as malicious
    Outcome.INCONCLUSIVE.value: 0.15,
    Outcome.UNKNOWN.value: 0.15,          # never validated by a human — weak lead only
    Outcome.CONFIRMED_BENIGN.value: 0.0,  # resembling a known-good case must not raise risk
    Outcome.FALSE_POSITIVE.value: 0.0,
}

MIN_SIMILARITY_FOR_SCORING = 0.6

# Combined brand-impersonation + credential-collection evidence is materially
# stronger than either alone: a domain that merely doesn't match its page's
# claimed name, or a form that merely asks for a password, is each
# individually common and often benign; both together in the same
# investigation is the actual credential-phishing pattern. Keyed on signal
# names, same shape as NARROW_CONTRADICTIONS below, so it survives
# independently of which collector produced which signal. Kept as one small,
# capped, documented rule rather than a general interaction-rule engine.
INTERACTION_IMPERSONATION_SIGNALS = frozenset({"lookalike_domain", "brand_domain_mismatch"})
INTERACTION_CREDENTIAL_SIGNALS = frozenset({"credential_form"})
INTERACTION_BONUS_POINTS = 14.0


def outcome_trust(prior_outcome: Optional[str]) -> float:
    return OUTCOME_TRUST.get(
        prior_outcome or Outcome.UNKNOWN.value, OUTCOME_TRUST[Outcome.UNKNOWN.value]
    )


def historical_impact(match: dict) -> float:
    """How much a historical match can actually move the score: resemblance weighted
    by how well the prior case was validated.

    Callers use this to choose *which* match to score against. Ranking by raw
    similarity instead lets a strong resemblance to a confirmed-benign case outrank
    a weaker one to a confirmed-malicious case, and the malicious lead is then
    silently dropped.
    """
    return (match.get("similarity") or 0.0) * outcome_trust(match.get("prior_outcome"))

# Counter-evidence that establishes something narrower than it appears to. A
# certificate proves control of the endpoint it was issued for; it says nothing
# about whether the operator is the organization the name resembles, and any
# attacker can obtain one in minutes. Letting it net off against an identity
# finding would mean a phishing site could rebut "this imitates someone else" by
# doing what every phishing site already does.
NARROW_CONTRADICTIONS = frozenset({"valid_tls_present"})


def _identity_support(supporting: list[Evidence]) -> list[Evidence]:
    return [ev for ev in supporting if ev.evidence_type == "identity"]


def _discount_narrow_contradictions(
    supporting: list[Evidence], contradicting: list[Evidence]
) -> tuple[list[Evidence], list[str]]:
    """Drop counter-evidence from the arithmetic that does not actually counter what
    was found. Returns (evidence that scores, notes explaining each exclusion).

    The excluded items stay in the reported counter-evidence — the reader should see
    everything KRISIS saw — they simply stop cancelling a finding they do not address.
    """
    if not _identity_support(supporting):
        return contradicting, []
    kept, notes = [], []
    for ev in contradicting:
        if ev.signal in NARROW_CONTRADICTIONS:
            notes.append(
                f"'{ev.signal}' ({ev.source}) is reported but does not offset the identity "
                f"finding: a valid certificate proves control of this endpoint, not that its "
                f"operator is the organization this name resembles"
            )
        else:
            kept.append(ev)
    return kept, notes


# A supporting case must be at least this much stronger than the contradicting
# case before KRISIS calls a verdict rather than reporting the disagreement.
CONFLICT_RATIO = 0.8
# Below this, "both sides are trivial" — reporting a conflict would be noise.
CONFLICT_MIN_POINTS = 8.0


class RiskEngine:
    def score(
        self,
        correlation: CorrelationResult,
        historical_similarity: Optional[dict] = None,
        coverage: Optional[Coverage] = None,
    ) -> RiskAssessment:
        coverage = coverage or Coverage()
        support_points, support_contributors = self._weighted_points(correlation.supporting)
        scoring_contradictions, discounted = _discount_narrow_contradictions(
            correlation.supporting, correlation.contradicting
        )
        contra_points, _ = self._weighted_points(scoring_contradictions)

        # Historical pattern similarity to prior cases is folded in as its own
        # contributor, separate from current reputation (see CURRENT VS HISTORICAL
        # INTELLIGENCE) — a clean current reputation should not erase a strong
        # historical resemblance to known-bad infrastructure. It is weighted by how
        # well that prior case was validated, so resembling a confirmed-benign case
        # adds nothing and resembling an unvalidated one adds very little.
        historical_points = 0.0
        similarity = (historical_similarity or {}).get("similarity", 0.0)
        if historical_similarity and similarity >= MIN_SIMILARITY_FOR_SCORING:
            prior_outcome = historical_similarity.get("prior_outcome") or Outcome.UNKNOWN.value
            historical_points = HISTORICAL_MAX_POINTS * similarity * outcome_trust(prior_outcome)
            if historical_points > 0:
                match_type = historical_similarity.get("match_type", "indicator")
                support_contributors.append(
                    (
                        historical_points,
                        f"historical similarity {similarity:.0%} ({match_type}) to "
                        f"{historical_similarity.get('pattern_name', 'a prior pattern')} "
                        f"(prior outcome: {prior_outcome})",
                    )
                )

        # See INTERACTION_* above: applied before diversity_factor, exactly like
        # historical_points — and since every one of the new page signals shares
        # source="page", this bonus can never let the page collector alone buy
        # its own diversity boost.
        interaction_points = 0.0
        supporting_signals = {ev.signal for ev in correlation.supporting}
        if (supporting_signals & INTERACTION_IMPERSONATION_SIGNALS) and (
            supporting_signals & INTERACTION_CREDENTIAL_SIGNALS
        ):
            interaction_points = INTERACTION_BONUS_POINTS
            support_contributors.append((
                interaction_points,
                "combined brand-impersonation + credential-collection evidence "
                "(stronger together than either alone)",
            ))

        raw_score = support_points + historical_points + interaction_points - (0.5 * contra_points)
        # Evidence diversity acts as a confidence multiplier on the raw score rather
        # than an additive bonus — a single-source finding should not reach HIGH.
        diversity_factor = 0.6 + 0.4 * correlation.evidence_diversity
        score = max(0, min(100, round(raw_score * diversity_factor)))

        category, uncertainty = self._categorize(
            score, correlation, coverage, support_points, contra_points
        )
        if discounted:
            uncertainty["discounted_counter_evidence"] = discounted
        confidence = self._confidence(correlation, historical_similarity, coverage)

        # Rank by actual contribution, not alphabetically — "top contributors" has
        # to mean the evidence that moved the score most.
        top_contributors = [
            label for _, label in sorted(support_contributors, key=lambda c: c[0], reverse=True)
        ][:5]

        return RiskAssessment(
            score=score,
            category=category,
            confidence=confidence,
            supporting=[e.to_dict() for e in correlation.supporting],
            contradicting=[e.to_dict() for e in correlation.contradicting],
            top_contributors=top_contributors or ["no evidence contributed to a threat hypothesis"],
            historical_similarity=historical_similarity,
            uncertainty=uncertainty,
        )

    def _weighted_points(self, evidence: list[Evidence]) -> tuple[float, list[tuple[float, str]]]:
        """Returns (total_points, [(contribution, label)]) so callers can rank by weight."""
        points = 0.0
        contributors: list[tuple[float, str]] = []
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
                contributors.append((contribution, f"{ev.signal} ({ev.source})"))

        return points, contributors

    def _categorize(
        self,
        score: int,
        correlation: CorrelationResult,
        coverage: Coverage,
        support_points: float,
        contra_points: float,
    ) -> tuple[RiskCategory, dict]:
        """Map a score to a category, but refuse to assert a benign verdict KRISIS
        did not actually earn. Returns (category, uncertainty_detail)."""
        uncertainty: dict = {}
        if coverage.failed:
            uncertainty["unavailable_sources"] = sorted(coverage.failed)
        total_evidence = (
            len(correlation.supporting) + len(correlation.contradicting) + len(correlation.neutral)
        )

        # Nothing was observed at all. This is the single most important case to get
        # right: an empty investigation is not a clean one.
        if total_evidence == 0:
            uncertainty["reason"] = "no evidence was collected for this artifact"
            return RiskCategory.INSUFFICIENT_EVIDENCE, uncertainty

        # Sources disagree at comparable strength — report the disagreement rather
        # than silently letting the larger pile win.
        if (
            support_points >= CONFLICT_MIN_POINTS
            and contra_points >= CONFLICT_MIN_POINTS
            and contra_points >= CONFLICT_RATIO * support_points
            and score < 80
        ):
            uncertainty["reason"] = (
                f"supporting and contradicting evidence are of comparable strength "
                f"({support_points:.0f} vs {contra_points:.0f} weighted points)"
            )
            return RiskCategory.CONFLICTING_EVIDENCE, uncertainty

        if score >= 80:
            return RiskCategory.CRITICAL, uncertainty
        if score >= 60:
            return RiskCategory.HIGH, uncertainty
        if score >= 30:
            return RiskCategory.MEDIUM, uncertainty

        # Score is in the LOW band. Asserting LOW is a positive claim that the
        # artifact looks safe, and there are three ways to have no right to make it.

        # KRISIS established that this artifact imitates an established identity
        # operated by somebody else. That is a determination about the artifact's own
        # name — the part a victim actually reads — and it does not need corroborating
        # infrastructure to matter. A lookalike domain reported as "looks safe" is the
        # exact failure that made paypa1.com score LOW/0 before identity analysis existed.
        impersonation = _identity_support(correlation.supporting)
        if impersonation:
            resembles = ", ".join(sorted({str(ev.value) for ev in impersonation}))
            uncertainty["reason"] = (
                f"this artifact's name imitates an established identity operated by someone "
                f"else ({resembles}); the surrounding infrastructure looks unremarkable, which "
                f"is why the score stays low, but an artifact impersonating another identity "
                f"cannot be reported as looking safe"
            )
            return RiskCategory.MEDIUM, uncertainty

        # A threat-reputation source examined this artifact and flagged it. That is a
        # direct determination about the artifact itself, not circumstantial evidence,
        # so however thin the corroboration around it, "looks safe" is not an
        # available answer. Without this, a single-source detection that fails to
        # accumulate points is reported as LOW with reassuring advice — while KRISIS
        # simultaneously lists the detection as its top contributor.
        flagged = sorted(
            {ev.source for ev in correlation.supporting if ev.evidence_type == "reputation"}
        )
        if flagged:
            uncertainty["reason"] = (
                f"a threat-reputation source flagged this artifact ({', '.join(flagged)}) and "
                f"little else corroborates it — the score stays low for want of corroboration, "
                f"but a flagged artifact cannot be reported as looking safe"
            )
            return RiskCategory.MEDIUM, uncertainty

        # ...and the artifact must actually have been checked for threat reputation.
        # "Nobody looked" must never render as "nothing found".
        if not coverage.has_reputation_source():
            uncertainty["reason"] = (
                "no threat-reputation source was available for this artifact, so the "
                "absence of malicious findings cannot be treated as evidence of safety"
            )
            return RiskCategory.INSUFFICIENT_EVIDENCE, uncertainty

        return RiskCategory.LOW, uncertainty

    def _confidence(
        self,
        correlation: CorrelationResult,
        historical_similarity: Optional[dict],
        coverage: Coverage,
    ) -> float:
        total_evidence = len(correlation.supporting) + len(correlation.contradicting) + len(correlation.neutral)
        if total_evidence == 0:
            return 0.0
        volume_factor = min(1.0, total_evidence / 8.0)
        diversity_factor = correlation.evidence_diversity
        contradiction_penalty = 0.0
        if correlation.supporting and correlation.contradicting:
            ratio = len(correlation.contradicting) / max(1, len(correlation.supporting))
            contradiction_penalty = min(0.3, ratio * 0.2)

        # Only a *validated* prior case earns a confidence bonus.
        historical_bonus = 0.0
        if historical_similarity and historical_similarity.get("similarity", 0) >= MIN_SIMILARITY_FOR_SCORING:
            if outcome_trust(historical_similarity.get("prior_outcome")) >= 1.0:
                historical_bonus = 0.1

        # Confidence is capped by how much of the intended evidence base actually
        # answered. Volume of evidence from the sources that did respond cannot
        # compensate for the sources that did not (see UNCERTAINTY STATES).
        confidence = 0.35 + 0.35 * volume_factor + 0.2 * diversity_factor + historical_bonus - contradiction_penalty
        if coverage.attempted:
            confidence *= 0.4 + 0.6 * coverage.ratio
            if not coverage.has_reputation_source():
                confidence *= 0.75
        return max(0.0, min(0.99, round(confidence, 3)))
