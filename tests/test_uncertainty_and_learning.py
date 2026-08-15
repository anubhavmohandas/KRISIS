"""
Regression tests for the failure modes that make KRISIS give a *wrong* answer
rather than merely an incomplete one.

Each test here corresponds to a defect that was confirmed at runtime and fixed.
They are grouped by the wrong conclusion they prevent, because that is what
matters: an investigation engine that reports "safe" when it did not look, or
that treats its own unverified guesses as history, is worse than no engine.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from krisis.core.correlation import CorrelationResult
from krisis.core.graph import EntityGraph
from krisis.core.models import (
    Case,
    Coverage,
    Entity,
    EntityType,
    Evidence,
    Outcome,
    Polarity,
    RiskCategory,
)
from krisis.core.recommend import recommend_action
from krisis.core.risk import RiskEngine
from krisis.memory.case_memory import CaseMemory
from krisis.memory.pattern_memory import PatternMemory
from krisis.memory.storage import Storage


def _supporting(signal="malicious_detection", source="virustotal", etype="reputation", conf=0.95):
    return Evidence(
        source=source, entity_id="e1", signal=signal, value=30,
        evidence_type=etype, confidence=conf, polarity=Polarity.SUPPORTS_THREAT,
    )


def _contradicting(signal="long_lived_domain", source="whois", etype="registration", conf=0.9):
    return Evidence(
        source=source, entity_id="e1", signal=signal, value=6000,
        evidence_type=etype, confidence=conf, polarity=Polarity.CONTRADICTS_THREAT,
    )


class TestNotCheckedIsNotSafe(unittest.TestCase):
    """'No evidence of a threat' and 'no threat' are different claims."""

    def setUp(self):
        self.engine = RiskEngine()
        self.neutral_dns = [
            Evidence(source="dns", entity_id="e1", signal=f"record_{i}", value="v",
                     evidence_type="infrastructure", confidence=0.9)
            for i in range(8)
        ]

    def test_clean_result_without_a_reputation_source_is_insufficient(self):
        correlation = CorrelationResult(neutral=self.neutral_dns, evidence_diversity=1.0)
        no_reputation = Coverage(
            attempted={"dns", "whois", "tls", "virustotal"},
            available={"dns"},
            evidence_types={"infrastructure"},
        )
        result = self.engine.score(correlation, coverage=no_reputation)
        self.assertEqual(result.category, RiskCategory.INSUFFICIENT_EVIDENCE)
        self.assertIn("virustotal", result.uncertainty["unavailable_sources"])

    def test_same_evidence_with_full_coverage_is_low(self):
        """Control: identical evidence, but every source answered -> LOW is earned."""
        correlation = CorrelationResult(neutral=self.neutral_dns, evidence_diversity=1.0)
        full = Coverage(
            attempted={"dns", "whois", "tls", "virustotal"},
            available={"dns", "whois", "tls", "virustotal"},
            evidence_types={"infrastructure", "registration", "reputation"},
        )
        self.assertEqual(self.engine.score(correlation, coverage=full).category, RiskCategory.LOW)

    def test_missing_sources_lower_confidence(self):
        correlation = CorrelationResult(neutral=self.neutral_dns, evidence_diversity=1.0)
        partial = Coverage(attempted={"dns", "whois", "tls", "virustotal"},
                           available={"dns"}, evidence_types={"infrastructure"})
        full = Coverage(attempted={"dns", "whois", "tls", "virustotal"},
                        available={"dns", "whois", "tls", "virustotal"},
                        evidence_types={"infrastructure", "registration", "reputation"})
        self.assertLess(
            self.engine.score(correlation, coverage=partial).confidence,
            self.engine.score(correlation, coverage=full).confidence,
        )

    def test_recommendation_for_insufficient_evidence_does_not_reassure(self):
        result = self.engine.score(CorrelationResult())
        advice = recommend_action(result)
        self.assertIn("NOT a clean result", advice)


class TestAFlaggedArtifactIsNeverCalledLow(unittest.TestCase):
    """Found at runtime against a real domain that VirusTotal flags: KRISIS printed
    'malicious_detection (virustotal)' as its top contributor and, two lines later,
    'LOW risk. No strong evidence of malicious activity was found.'

    A single reputation hit does not accumulate enough weighted points to leave the
    LOW band on its own, but a reputation source is a direct determination about the
    artifact, not circumstantial evidence — so the band may keep the score low while
    the *verdict* must not claim safety.
    """

    def setUp(self):
        self.coverage = Coverage(attempted={"virustotal", "whois"},
                                 available={"virustotal", "whois"},
                                 evidence_types={"reputation", "registration"})

    def test_a_lone_reputation_detection_is_not_reported_as_low(self):
        correlation = CorrelationResult(
            supporting=[_supporting(conf=0.66)],
            contradicting=[_contradicting(conf=0.55)],
            evidence_diversity=1.0,
        )
        result = RiskEngine().score(correlation, coverage=self.coverage)

        self.assertLess(result.score, 30, "precondition: the score really is in the LOW band")
        self.assertEqual(result.category, RiskCategory.MEDIUM)
        self.assertIn("virustotal", result.uncertainty["reason"])
        self.assertNotIn("No strong evidence", recommend_action(result))

    def test_the_qualification_reaches_the_recommended_action(self):
        """A caveat the operator never sees is not a caveat."""
        result = RiskEngine().score(
            CorrelationResult(supporting=[_supporting(conf=0.66)], evidence_diversity=1.0),
            coverage=self.coverage,
        )
        self.assertIn("flagged this artifact", recommend_action(result))

    def test_circumstantial_signals_alone_still_read_as_low(self):
        """Control: the rule must key on a reputation determination, not on any
        supporting evidence at all, or every weak registration signal becomes MEDIUM."""
        weak_registration = _supporting(signal="newly_registered_domain", source="whois",
                                        etype="registration", conf=0.4)
        result = RiskEngine().score(
            CorrelationResult(supporting=[weak_registration], neutral=[
                Evidence(source="virustotal", entity_id="e1", signal="no_detections", value=0,
                         evidence_type="reputation", confidence=0.3)
            ], evidence_diversity=1.0),
            coverage=self.coverage,
        )
        self.assertEqual(result.category, RiskCategory.LOW)


class TestConflictingEvidence(unittest.TestCase):
    def test_comparable_opposing_evidence_reports_a_conflict(self):
        correlation = CorrelationResult(
            supporting=[_supporting()],
            contradicting=[_contradicting(conf=0.95, etype="reputation")],
            evidence_diversity=1.0,
        )
        result = RiskEngine().score(correlation, coverage=Coverage(
            attempted={"virustotal"}, available={"virustotal"}, evidence_types={"reputation"}))
        self.assertEqual(result.category, RiskCategory.CONFLICTING_EVIDENCE)
        self.assertIn("comparable strength", result.uncertainty["reason"])

    def test_decisive_evidence_is_not_reported_as_conflict(self):
        correlation = CorrelationResult(
            supporting=[_supporting(), _supporting(signal="phishing_url", source="urlscan",
                                                  etype="behavior")],
            contradicting=[_contradicting(conf=0.2)],
            evidence_diversity=1.0,
        )
        result = RiskEngine().score(correlation, coverage=Coverage(
            attempted={"virustotal"}, available={"virustotal"}, evidence_types={"reputation"}))
        self.assertNotEqual(result.category, RiskCategory.CONFLICTING_EVIDENCE)


class TestHistoricalMatchesRespectOutcome(unittest.TestCase):
    """Resembling a prior case only means something if that case was validated."""

    def setUp(self):
        self.engine = RiskEngine()
        self.correlation = CorrelationResult(evidence_diversity=0.5)

    def _score_for(self, outcome):
        return self.engine.score(
            self.correlation,
            historical_similarity={"similarity": 0.95, "pattern_name": "prior case",
                                   "prior_outcome": outcome},
        ).score

    def test_resembling_a_confirmed_benign_case_adds_no_risk(self):
        self.assertEqual(self._score_for("confirmed_benign"), 0)

    def test_resembling_a_false_positive_adds_no_risk(self):
        self.assertEqual(self._score_for("false_positive"), 0)

    def test_unvalidated_prior_case_counts_far_less_than_a_confirmed_one(self):
        unvalidated = self._score_for("unknown")
        confirmed = self._score_for("confirmed_malicious")
        self.assertLess(unvalidated, confirmed)

    def test_only_validated_history_earns_a_confidence_bonus(self):
        # needs real evidence present: with nothing collected, confidence is 0
        # regardless of history, which is checked separately.
        with_evidence = CorrelationResult(supporting=[_supporting()], evidence_diversity=0.5)
        unvalidated = self.engine.score(with_evidence, historical_similarity={
            "similarity": 0.95, "pattern_name": "p", "prior_outcome": "unknown"}).confidence
        confirmed = self.engine.score(with_evidence, historical_similarity={
            "similarity": 0.95, "pattern_name": "p", "prior_outcome": "confirmed_malicious"}).confidence
        self.assertLess(unvalidated, confirmed)


class TestTopContributorsRanking(unittest.TestCase):
    def test_contributors_are_ranked_by_contribution_not_alphabetically(self):
        strong = _supporting(signal="zzz_malicious_detection")
        weak = _supporting(signal="aaa_new_domain", source="whois",
                           etype="registration", conf=0.4)
        result = RiskEngine().score(
            CorrelationResult(supporting=[strong, weak], evidence_diversity=1.0)
        )
        self.assertIn("zzz_malicious_detection", result.top_contributors[0])


class TestMemoryPoisoningResistance(unittest.TestCase):
    def setUp(self):
        self.db = os.path.join(tempfile.mkdtemp(), "krisis_test.db")
        self.storage = Storage(self.db)
        self.pattern_memory = PatternMemory(self.storage)
        self.case_memory = CaseMemory(self.storage, self.pattern_memory)

    def _case_with_signal(self, seed, signal="new_domain"):
        case = Case(seed=seed, seed_type=EntityType.DOMAIN)
        ip = Entity(value="203.0.113.10", type=EntityType.IP, depth=1)
        case.entities[ip.id] = ip
        ev = Evidence(source="whois", entity_id=ip.id, signal=signal, value=3,
                      evidence_type="registration", polarity=Polarity.SUPPORTS_THREAT)
        case.evidence[ev.id] = ev
        return case

    def test_reinvestigating_the_same_artifact_does_not_match_itself(self):
        """Without this, running the same scan twice manufactures a 'historical
        pattern match' out of the tool's own prior run."""
        case = self._case_with_signal("repeat.example")
        self.case_memory.save(case)

        graph = EntityGraph()
        graph.add_entity(Entity(value="repeat.example", type=EntityType.DOMAIN, depth=0))
        graph.add_entity(Entity(value="203.0.113.10", type=EntityType.IP, depth=1))

        self.assertEqual(
            self.pattern_memory.find_similar(graph, [], exclude_seed="repeat.example"), []
        )
        # a genuinely different artifact on the same infrastructure still matches
        self.assertTrue(self.pattern_memory.find_similar(graph, [], exclude_seed="other.example"))

    def test_first_sighting_is_observed_not_trusted(self):
        self.case_memory.save(self._case_with_signal("a.example"))
        patterns = self.pattern_memory.list_patterns()
        self.assertEqual(len(patterns), 1)
        self.assertEqual(patterns[0]["stage"], "observed")

    def test_repetition_alone_never_reaches_validated(self):
        for i in range(4):
            self.case_memory.save(self._case_with_signal(f"host{i}.example"))
        stage = self.pattern_memory.list_patterns()[0]["stage"]
        self.assertEqual(stage, "repeated")

    def test_human_confirmation_advances_to_validated(self):
        case = self._case_with_signal("bad.example")
        self.case_memory.save(case)
        self.case_memory.set_outcome(case.id, "confirmed_malicious")
        self.assertEqual(self.pattern_memory.list_patterns()[0]["stage"], "validated")

    def test_inconclusive_outcome_changes_nothing(self):
        case = self._case_with_signal("maybe.example")
        self.case_memory.save(case)
        before = self.pattern_memory.list_patterns()[0]
        self.case_memory.set_outcome(case.id, "inconclusive")
        after = self.pattern_memory.list_patterns()[0]
        self.assertEqual(before["confirmed_count"], after["confirmed_count"])
        self.assertEqual(before["false_positive_count"], after["false_positive_count"])

    def test_false_positives_deprecate_a_pattern(self):
        for i, seed in enumerate(["fp1.example", "fp2.example"]):
            case = self._case_with_signal(seed)
            self.case_memory.save(case)
            self.case_memory.set_outcome(case.id, "false_positive")
        self.assertEqual(self.pattern_memory.list_patterns()[0]["stage"], "deprecated")

    def test_stored_case_json_reflects_recorded_outcome(self):
        case = self._case_with_signal("outcome.example")
        self.case_memory.save(case)
        self.case_memory.set_outcome(case.id, "confirmed_malicious")
        self.assertEqual(self.case_memory.get(case.id)["outcome"], "confirmed_malicious")


class TestEveryOutcomeIsRecordable(unittest.TestCase):
    """The CLI is the only way a human validates a case, so an outcome the CLI
    cannot express is an outcome the learning loop can never receive.

    `confirmed_benign` is the one that matters most: it is the sole outcome that
    drives OUTCOME_TRUST to 0.0 and stops a clean case from raising future risk.
    """

    def test_cli_offers_exactly_the_outcome_enum(self):
        from click.types import Choice

        from krisis.cli import outcome as outcome_cmd

        choices = next(
            p.type.choices for p in outcome_cmd.params if isinstance(getattr(p, "type", None), Choice)
        )
        self.assertEqual(set(choices), {o.value for o in Outcome})

    def test_cli_offers_no_outcome_the_engines_cannot_interpret(self):
        """A value outside the enum silently reaches OUTCOME_TRUST.get() and falls
        back to the 'unknown' weighting, which is not what the operator recorded."""
        from click.types import Choice

        from krisis.cli import outcome as outcome_cmd

        choices = next(
            p.type.choices for p in outcome_cmd.params if isinstance(getattr(p, "type", None), Choice)
        )
        for value in choices:
            Outcome(value)  # raises ValueError if the CLI can emit an unmodelled outcome


if __name__ == "__main__":
    unittest.main()
