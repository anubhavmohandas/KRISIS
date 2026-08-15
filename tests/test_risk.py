import unittest

from krisis.core.correlation import CorrelationResult
from krisis.core.models import (
    Coverage, Entity, EntityType, Evidence, Independence, Polarity, RiskCategory,
)
from krisis.core.recommend import recommend_action
from krisis.core.risk import RiskEngine


def _ev(signal, evidence_type, polarity, confidence=0.8, independence=Independence.INDEPENDENT, source="src"):
    return Evidence(
        source=source, entity_id="e1", signal=signal, value="x",
        evidence_type=evidence_type, polarity=polarity, confidence=confidence, independence=independence,
    )


class TestRiskEngine(unittest.TestCase):
    def test_deterministic_same_input_same_output(self):
        engine = RiskEngine()
        correlation = CorrelationResult(
            supporting=[_ev("malicious_detection", "reputation", Polarity.SUPPORTS_THREAT)],
            contradicting=[],
            evidence_diversity=0.8,
        )
        r1 = engine.score(correlation)
        r2 = engine.score(correlation)
        self.assertEqual(r1.score, r2.score)
        self.assertEqual(r1.category, r2.category)

    def test_more_supporting_evidence_raises_score(self):
        engine = RiskEngine()
        low = CorrelationResult(supporting=[_ev("a", "reputation", Polarity.SUPPORTS_THREAT)],
                                 evidence_diversity=0.8)
        high = CorrelationResult(
            supporting=[
                _ev("a", "reputation", Polarity.SUPPORTS_THREAT, source="s1"),
                _ev("b", "infrastructure", Polarity.SUPPORTS_THREAT, source="s2"),
                _ev("c", "identity", Polarity.SUPPORTS_THREAT, source="s3"),
            ],
            evidence_diversity=0.8,
        )
        self.assertLess(engine.score(low).score, engine.score(high).score)

    def test_counter_evidence_lowers_score(self):
        engine = RiskEngine()
        supporting_only = CorrelationResult(
            supporting=[_ev("a", "reputation", Polarity.SUPPORTS_THREAT)], evidence_diversity=0.8
        )
        with_counter = CorrelationResult(
            supporting=[_ev("a", "reputation", Polarity.SUPPORTS_THREAT)],
            contradicting=[_ev("b", "infrastructure", Polarity.CONTRADICTS_THREAT, confidence=0.9)],
            evidence_diversity=0.8,
        )
        self.assertGreater(engine.score(supporting_only).score, engine.score(with_counter).score)

    def test_duplicate_independence_contributes_less_than_independent(self):
        engine = RiskEngine()
        independent = CorrelationResult(
            supporting=[_ev("a", "reputation", Polarity.SUPPORTS_THREAT, independence=Independence.INDEPENDENT)],
            evidence_diversity=0.8,
        )
        duplicate = CorrelationResult(
            supporting=[_ev("a", "reputation", Polarity.SUPPORTS_THREAT, independence=Independence.DUPLICATE)],
            evidence_diversity=0.8,
        )
        self.assertGreater(engine.score(independent).score, engine.score(duplicate).score)

    def test_diminishing_returns_on_repeated_evidence_type(self):
        engine = RiskEngine()
        one = CorrelationResult(
            supporting=[_ev("a", "reputation", Polarity.SUPPORTS_THREAT, source="s1")],
            evidence_diversity=0.8,
        )
        three_same_type = CorrelationResult(
            supporting=[
                _ev("a", "reputation", Polarity.SUPPORTS_THREAT, source="s1"),
                _ev("b", "reputation", Polarity.SUPPORTS_THREAT, source="s1"),
                _ev("c", "reputation", Polarity.SUPPORTS_THREAT, source="s1"),
            ],
            evidence_diversity=0.34,  # only one distinct source among these three
        )
        # three low-diversity same-type items should not simply be 3x a single one
        single_score = engine.score(one).score
        triple_score = engine.score(three_same_type).score
        self.assertLess(triple_score, single_score * 3)

    def test_no_evidence_is_reported_as_insufficient_not_low(self):
        """An empty investigation is not a clean one. Returning LOW here would tell a
        user an artifact looks safe when KRISIS never actually managed to look at it."""
        engine = RiskEngine()
        result = engine.score(CorrelationResult())
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.score, 0)
        self.assertEqual(result.category.value, "INSUFFICIENT_EVIDENCE")
        self.assertIn("reason", result.uncertainty)

    def test_historical_similarity_contributes_even_with_clean_reputation(self):
        engine = RiskEngine()
        clean_but_similar = CorrelationResult(supporting=[], contradicting=[], evidence_diversity=0.5)
        result = engine.score(
            clean_but_similar,
            historical_similarity={
                "similarity": 0.9,
                "pattern_name": "prior phishing cluster",
                "prior_outcome": "confirmed_malicious",
            },
        )
        self.assertGreater(result.score, 0)
        self.assertTrue(any("historical" in c for c in result.top_contributors))


class TestSecuritySignalInteraction(unittest.TestCase):
    """The combination of brand-impersonation + credential-collection evidence
    must be materially stronger than the sum of its parts (see
    risk.py::INTERACTION_BONUS_POINTS). Deleting that block should make
    test_combined_signals_score_well_above_the_sum_of_the_parts fail while the
    other tests here keep passing."""

    def _score(self, *evidence):
        engine = RiskEngine()
        return engine.score(
            CorrelationResult(supporting=list(evidence), contradicting=[], evidence_diversity=0.8)
        ).score

    def test_combined_signals_score_well_above_the_sum_of_the_parts(self):
        impersonation = _ev("lookalike_domain", "identity", Polarity.SUPPORTS_THREAT, confidence=0.6)
        credential = _ev("credential_form", "behavior", Polarity.SUPPORTS_THREAT, confidence=0.5)

        only_impersonation = self._score(impersonation)
        only_credential = self._score(credential)
        combined = self._score(impersonation, credential)

        # A margin this large is only reachable via the dedicated interaction
        # bonus, not the ordinary additive weighting (which would land the
        # combined score within a point or two of the sum, from rounding alone).
        self.assertGreaterEqual(combined - only_impersonation - only_credential, 8)

    def test_credential_form_alone_does_not_trigger_the_interaction_bonus(self):
        only_credential = self._score(
            _ev("credential_form", "behavior", Polarity.SUPPORTS_THREAT, confidence=0.5)
        )
        both_credential_signals = self._score(
            _ev("credential_form", "behavior", Polarity.SUPPORTS_THREAT, confidence=0.5, source="a"),
            _ev("external_form_action", "behavior", Polarity.SUPPORTS_THREAT, confidence=0.5, source="b"),
        )
        # Two behavior-only signals, no impersonation evidence: the interaction
        # bonus must not fire just because there happen to be two of them.
        self.assertLess(both_credential_signals - only_credential, 8)

    def test_brand_domain_mismatch_does_not_inherit_the_verified_identity_carveout(self):
        """brand_domain_mismatch is an unverified page/domain-name comparison, not
        the verified (resolves + established + different-operator) relationship
        identity_collector.py produces. It must be evidence_type='behavior', not
        'identity', or every ordinary title/domain mismatch would be forced out of
        LOW by risk.py's identity carve-out — see page_collector.py."""
        engine = RiskEngine()
        coverage = Coverage(
            attempted={"virustotal"}, available={"virustotal"}, evidence_types={"reputation"}
        )
        correlation = CorrelationResult(
            supporting=[_ev("brand_domain_mismatch", "behavior", Polarity.SUPPORTS_THREAT, confidence=0.2)],
            contradicting=[],
            evidence_diversity=0.1,
        )
        result = engine.score(correlation, coverage=coverage)
        self.assertEqual(result.category, RiskCategory.LOW)


class TestHistoricalMaliciousFloor(unittest.TestCase):
    """Regression for KRISIS validation-matrix case 16: a near-perfect historical
    resemblance to a case a human confirmed malicious used to be reported LOW
    ("no strong evidence of malicious activity was found") while
    top_contributors simultaneously named that very match as its #1 contributor
    -- see risk.py's HISTORICAL_MALICIOUS_FLOOR_SIMILARITY / historical-floor
    check, deliberately modeled on the existing impersonation/flagged checks."""

    def _clean_coverage(self) -> Coverage:
        return Coverage(attempted={"virustotal"}, available={"virustotal"}, evidence_types={"reputation"})

    def _score_with_history(self, historical_similarity, contradicting=None):
        engine = RiskEngine()
        correlation = CorrelationResult(
            supporting=[],
            contradicting=contradicting or [],
            neutral=[_ev("no_detections", "reputation", Polarity.NEUTRAL, confidence=0.3)],
            evidence_diversity=0.5,
        )
        return engine.score(
            correlation, coverage=self._clean_coverage(), historical_similarity=historical_similarity
        )

    def test_strong_historical_match_to_confirmed_malicious_is_not_reported_low(self):
        result = self._score_with_history({
            "similarity": 1.0,
            "pattern_name": "shared certificate cluster",
            "prior_outcome": "confirmed_malicious",
            "match_type": "indicator",
        })
        self.assertEqual(result.category, RiskCategory.MEDIUM)
        self.assertIn("confirmed malicious", result.uncertainty["reason"])

    def test_category_top_contributor_and_recommendation_stay_consistent(self):
        """The exact inconsistency case 16 exhibited: category, top_contributors,
        and the rendered recommendation text must all agree with each other."""
        result = self._score_with_history({
            "similarity": 1.0,
            "pattern_name": "known-malicious cluster",
            "prior_outcome": "confirmed_malicious",
            "match_type": "indicator",
        })
        self.assertTrue(any("historical" in c for c in result.top_contributors))
        self.assertNotEqual(result.category, RiskCategory.LOW)
        text = recommend_action(result)
        self.assertNotIn("No strong evidence of malicious activity was found", text)
        self.assertIn("confirmed malicious", text)

    def test_weak_historical_match_does_not_force_the_floor(self):
        """Do not blindly escalate every historical match -- only a strong one."""
        result = self._score_with_history({
            "similarity": 0.5, "pattern_name": "loosely similar shape", "prior_outcome": "unknown",
        })
        self.assertEqual(result.category, RiskCategory.LOW)

    def test_strong_similarity_to_an_unvalidated_prior_case_does_not_force_the_floor(self):
        """A pattern KRISIS has only observed, never had confirmed by a human, is a
        lead, not proof (see PATTERN POISONING RESISTANCE) -- must not force a
        verdict no matter how similar it looks."""
        result = self._score_with_history({
            "similarity": 1.0, "pattern_name": "unvalidated shape", "prior_outcome": "unknown",
        })
        self.assertEqual(result.category, RiskCategory.LOW)

    def test_strong_current_contradicting_evidence_suppresses_the_historical_floor(self):
        """Current evidence showing this artifact is actually operated by the
        legitimate party it resembles (e.g. reclaimed infrastructure) must be
        allowed to outrank a possibly-stale historical match."""
        result = self._score_with_history(
            {"similarity": 1.0, "pattern_name": "shared cert", "prior_outcome": "confirmed_malicious"},
            contradicting=[_ev("same_operator_variant", "identity", Polarity.CONTRADICTS_THREAT, confidence=0.9)],
        )
        self.assertEqual(result.category, RiskCategory.LOW)

    def test_no_historical_match_is_unaffected(self):
        """Baseline: with no historical_similarity at all, behavior is unchanged."""
        result = self._score_with_history(None)
        self.assertEqual(result.category, RiskCategory.LOW)


if __name__ == "__main__":
    unittest.main()
