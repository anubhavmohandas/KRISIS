import unittest

from krisis.core.correlation import CorrelationResult
from krisis.core.models import Entity, EntityType, Evidence, Independence, Polarity
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


if __name__ == "__main__":
    unittest.main()
