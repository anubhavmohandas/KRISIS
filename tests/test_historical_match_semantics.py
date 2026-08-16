"""
Historical match semantics: "I have seen this exact artifact before" is a
different, stronger claim than "this shares infrastructure with a prior
case", which is in turn different from "no concrete value is shared at all,
only the shape of the investigation resembles one". A bare "historical
similarity: N%" collapses all three into one sentence a reader can only
misread as the strongest of them.

These tests hold the distinction pattern_memory.PatternMemory computes
(`indicator_kind`) and the label every renderer must use instead of inventing
its own phrasing (`risk.historical_match_label`) — see EXACT ARTIFACT VS
INFRASTRUCTURE OVERLAP in pattern_memory.py.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

from click.testing import CliRunner

from krisis.core.correlation import CorrelationResult
from krisis.core.graph import EntityGraph
from krisis.core.models import (
    Case, Coverage, Entity, EntityType, Evidence, Polarity, Relationship,
)
from krisis.core.risk import RiskEngine, historical_match_label
from krisis.cli import cli
from krisis.memory.case_memory import CaseMemory
from krisis.memory.pattern_memory import PatternMemory
from krisis.memory.storage import Storage

PHISHING_SIGNALS = [
    ("newly_registered_domain", "registration"),
    ("brand_lookalike", "identity"),
]


def _graph_of(case: Case) -> EntityGraph:
    graph = EntityGraph()
    for entity in case.entities.values():
        graph.add_entity(entity)
    for rel in case.relationships.values():
        graph.add_relationship(rel)
    return graph


def _match(memory: PatternMemory, case: Case) -> list[dict]:
    return memory.find_similar(_graph_of(case), list(case.evidence.values()), exclude_seed=case.seed)


class HistoricalMatchTest(unittest.TestCase):
    def setUp(self):
        self.storage = Storage(os.path.join(tempfile.mkdtemp(), "historical.db"))
        self.pattern_memory = PatternMemory(self.storage)
        self.case_memory = CaseMemory(self.storage, self.pattern_memory)


class TestExactPriorArtifactMatch(HistoricalMatchTest):
    def test_a_pivot_that_is_itself_a_prior_seed_is_an_exact_artifact_match(self):
        """The real shape this bug report was about: paypa1.com's identity check
        pivots to paypal.com — the organization it impersonates — and paypal.com
        was itself directly investigated before. That is not 'infrastructure
        overlap', it is 'this exact artifact was investigated before'."""
        prior = Case(seed="real-target.example", seed_type=EntityType.DOMAIN)
        prior_root = Entity(value="real-target.example", type=EntityType.DOMAIN, depth=0)
        prior.entities[prior_root.id] = prior_root
        self.case_memory.save(prior)

        current = Case(seed="typo-target.example", seed_type=EntityType.DOMAIN)
        root = Entity(value="typo-target.example", type=EntityType.DOMAIN, depth=0)
        impersonated = Entity(value="real-target.example", type=EntityType.DOMAIN, depth=1)
        current.entities[root.id] = root
        current.entities[impersonated.id] = impersonated
        current.relationships["r1"] = Relationship(
            source_entity_id=root.id, target_entity_id=impersonated.id,
            relation_type="looks_like", reason="lookalike of a known identity",
        )

        matches = _match(self.pattern_memory, current)
        self.assertTrue(matches, "the shared exact-artifact indicator did not match at all")
        best = matches[0]
        self.assertEqual(best["indicator_kind"], "exact_artifact")
        self.assertEqual(historical_match_label(best), "exact artifact seen before")
        self.assertIn("domain:real-target.example", best["matched_indicators"])

    def test_a_pivot_that_was_never_a_prior_seed_is_infrastructure_overlap_not_exact(self):
        """Counter-test: the same shared value, but the prior case only pivoted
        to it (never investigated it directly) — this must not be labeled as if
        KRISIS recognised the exact artifact."""
        prior = Case(seed="real-target.example", seed_type=EntityType.DOMAIN)
        pivoted_cert = Entity(value="AA:BB:CC", type=EntityType.CERTIFICATE, depth=1)
        prior.entities[pivoted_cert.id] = pivoted_cert
        self.case_memory.save(prior)

        current = Case(seed="typo-target.example", seed_type=EntityType.DOMAIN)
        root = Entity(value="typo-target.example", type=EntityType.DOMAIN, depth=0)
        shared_cert = Entity(value="AA:BB:CC", type=EntityType.CERTIFICATE, depth=1)
        current.entities[root.id] = root
        current.entities[shared_cert.id] = shared_cert

        matches = _match(self.pattern_memory, current)
        self.assertTrue(matches)
        best = matches[0]
        self.assertEqual(best["indicator_kind"], "infrastructure")
        self.assertEqual(historical_match_label(best), "infrastructure overlap with a prior case")


class TestSameArtifactThroughDifferentContext(HistoricalMatchTest):
    def test_a_domain_investigated_directly_before_is_recognised_inside_a_new_message(self):
        """Prior investigation: the domain itself, seeded directly. New
        investigation: a message that merely *mentions* that same domain. The
        domain is depth-0 in both graphs, but it is only the *seed* of the
        first one — it must still be recognised as the exact same artifact
        surfacing through a different context, not silently dropped because
        'depth 0' used to be treated as a proxy for 'is the seed'."""
        prior = Case(seed="evil-domain.example", seed_type=EntityType.DOMAIN)
        prior_root = Entity(value="evil-domain.example", type=EntityType.DOMAIN, depth=0)
        prior.entities[prior_root.id] = prior_root
        self.case_memory.save(prior)

        message_text = "Hey, thought you'd find this funny: https://evil-domain.example"
        current = Case(seed=message_text, seed_type=EntityType.MESSAGE)
        message_entity = Entity(value=message_text, type=EntityType.MESSAGE, depth=0)
        mentioned_domain = Entity(value="evil-domain.example", type=EntityType.DOMAIN, depth=0)
        current.entities[message_entity.id] = message_entity
        current.entities[mentioned_domain.id] = mentioned_domain
        current.relationships["r1"] = Relationship(
            source_entity_id=message_entity.id, target_entity_id=mentioned_domain.id,
            relation_type="mentions", reason="domain extracted from message text",
        )

        matches = _match(self.pattern_memory, current)
        self.assertTrue(
            matches,
            "a domain that was itself a prior investigation's seed must match when it "
            "resurfaces inside a message, even though it is depth-0 in both graphs",
        )
        best = matches[0]
        self.assertEqual(best["indicator_kind"], "exact_artifact")
        self.assertIn("domain:evil-domain.example", best["matched_indicators"])

    def test_the_messages_own_seed_value_is_still_never_matched_against_itself(self):
        """Guard against over-correcting: the fix must only stop excluding
        depth-0 entities that are NOT the seed. The message text itself (the
        actual seed of this investigation) must remain excluded."""
        message_text = "Hey, thought you'd find this funny: https://evil-domain.example"
        prior = Case(seed=message_text, seed_type=EntityType.MESSAGE)
        self.case_memory.save(prior)

        current = Case(seed=message_text, seed_type=EntityType.MESSAGE)
        message_entity = Entity(value=message_text, type=EntityType.MESSAGE, depth=0)
        current.entities[message_entity.id] = message_entity

        # MESSAGE carries no INDICATOR_WEIGHTS entry regardless, but this also
        # proves exclude_seed still suppresses a genuine re-run at the case level.
        self.assertEqual(_match(self.pattern_memory, current), [])


class TestNewArtifactWithStructuralSimilarityOnly(HistoricalMatchTest):
    def _case(self, seed, ip, cert):
        case = Case(seed=seed, seed_type=EntityType.DOMAIN)
        root = Entity(value=seed, type=EntityType.DOMAIN, depth=0)
        case.entities[root.id] = root
        ip_entity = Entity(value=ip, type=EntityType.IP, depth=1)
        cert_entity = Entity(value=cert, type=EntityType.CERTIFICATE, depth=1)
        case.entities[ip_entity.id] = ip_entity
        case.entities[cert_entity.id] = cert_entity
        case.relationships["r1"] = Relationship(
            source_entity_id=root.id, target_entity_id=ip_entity.id,
            relation_type="resolves_to", reason="observed during collection",
        )
        case.relationships["r2"] = Relationship(
            source_entity_id=root.id, target_entity_id=cert_entity.id,
            relation_type="presents_certificate", reason="observed during collection",
        )
        for signal, evidence_type in PHISHING_SIGNALS:
            ev = Evidence(
                source="test", entity_id=root.id, signal=signal, value=1,
                evidence_type=evidence_type, polarity=Polarity.SUPPORTS_THREAT, confidence=0.8,
            )
            case.evidence[ev.id] = ev
        return case

    def test_a_new_artifact_on_rotated_infrastructure_is_never_seen_before(self):
        """No shared cert, no shared IP, no shared domain — only the shape of
        the investigation resembles a prior one. This must never be reported
        as 'exact artifact' or 'infrastructure overlap': KRISIS has not
        actually seen this artifact, or anything it touches, before."""
        self.case_memory.save(self._case("phish-one.example", "203.0.113.5", "AA:11"))
        rotated = self._case("phish-two.example", "198.51.100.9", "BB:22")

        matches = _match(self.pattern_memory, rotated)
        self.assertTrue(matches, "rotated infrastructure with an identical shape did not match")
        best = matches[0]
        self.assertIsNone(best["indicator_kind"])
        self.assertEqual(
            historical_match_label(best), "structurally similar new artifact, no shared indicator"
        )


class TestZeroIndicatorPositiveStructuralSimilarity(HistoricalMatchTest):
    def test_indicator_similarity_is_exactly_zero_while_structural_similarity_is_positive(self):
        """The literal numbers a 0%-indicator / positive-structural match must
        report — and that the label built from them never claims history has
        been 'seen' rather than merely resembled."""
        case = Case(seed="phish-one.example", seed_type=EntityType.DOMAIN)
        root = Entity(value="phish-one.example", type=EntityType.DOMAIN, depth=0)
        case.entities[root.id] = root
        for signal, evidence_type in PHISHING_SIGNALS:
            ev = Evidence(
                source="test", entity_id=root.id, signal=signal, value=1,
                evidence_type=evidence_type, polarity=Polarity.SUPPORTS_THREAT, confidence=0.8,
            )
            case.evidence[ev.id] = ev
        self.case_memory.save(case)

        new_case = Case(seed="phish-two.example", seed_type=EntityType.DOMAIN)
        new_root = Entity(value="phish-two.example", type=EntityType.DOMAIN, depth=0)
        new_case.entities[new_root.id] = new_root
        for signal, evidence_type in PHISHING_SIGNALS:
            ev = Evidence(
                source="test", entity_id=new_root.id, signal=signal, value=1,
                evidence_type=evidence_type, polarity=Polarity.SUPPORTS_THREAT, confidence=0.8,
            )
            new_case.evidence[ev.id] = ev

        matches = _match(self.pattern_memory, new_case)
        self.assertTrue(matches)
        best = matches[0]
        self.assertEqual(best["indicator_similarity"], 0.0)
        self.assertGreater(best["structural_similarity"], 0.0)
        label = historical_match_label(best)
        self.assertNotIn("seen before", label)
        self.assertNotIn("infrastructure overlap", label)
        self.assertIn("structurally similar", label)


class TestCLIRendersTheDistinction(unittest.TestCase):
    """End-to-end: the same three readings, through `krisis show`'s actual
    output and its --json payload, not just the pattern_memory dict."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.runner = CliRunner()

    def _invoke(self, *args):
        with mock.patch("requests.get", side_effect=AssertionError("show must not touch the network")):
            return self.runner.invoke(cli, list(args), catch_exceptions=False)

    def _stored_case_with_match(self, indicator_kind, indicator_similarity, structural_similarity):
        storage = Storage(self.db_path)
        pattern_memory = PatternMemory(storage)
        case_memory = CaseMemory(storage, pattern_memory)

        case = Case(seed="typo-target.example", seed_type=EntityType.DOMAIN)
        root = Entity(value="typo-target.example", type=EntityType.DOMAIN, id="e1", depth=0)
        ev = Evidence(
            source="identity", entity_id="e1", signal="lookalike_domain", value="real-target.example",
            evidence_type="identity", polarity=Polarity.SUPPORTS_THREAT, confidence=0.8,
        )
        case.entities[root.id] = root
        case.evidence[ev.id] = ev
        historical_match = {
            "pattern_id": "pat_x", "pattern_name": "a prior pattern", "similarity": 0.9,
            "indicator_similarity": indicator_similarity, "structural_similarity": structural_similarity,
            "indicator_kind": indicator_kind, "matched_indicators": [], "matched_facets": [],
            "pattern_stage": "observed", "prior_outcome": "unknown",
            "match_type": (
                "indicator+structural" if indicator_similarity and structural_similarity
                else "structural" if structural_similarity else "indicator"
            ),
        }
        correlation = CorrelationResult(supporting=[ev], evidence_diversity=0.5)
        coverage = Coverage(attempted={"identity"}, available={"identity"}, evidence_types={"identity"})
        case.risk = RiskEngine().score(
            correlation, historical_similarity=historical_match, coverage=coverage
        )
        case.pattern_matches = [historical_match]
        case.explanation = "test explanation"
        case.recommendation = "test recommendation"
        case_memory.save(case)
        return case.id

    @staticmethod
    def _historical_match_line(output: str) -> str:
        """The CLI's own dedicated "Historical match: ..." line, isolated from
        the (also-correct, but separately-computed) top_contributors entry —
        a mutation that reverts only the cli.py rendering call must still be
        caught even though risk.py's contributor text still carries the label."""
        line = next((l for l in output.splitlines() if l.startswith("Historical match:")), None)
        assert line is not None, f"no 'Historical match:' line in output:\n{output}"
        return line

    def test_exact_artifact_match_reads_as_seen_before_not_generic_similarity(self):
        case_id = self._stored_case_with_match("exact_artifact", 1.0, 0.0)
        result = self._invoke("show", case_id, "--db", self.db_path)
        self.assertEqual(result.exit_code, 0)
        line = self._historical_match_line(result.output)
        self.assertIn("exact artifact seen before", line)
        # The bare, unlabeled old format ("Historical similarity: N% to X") must
        # be gone from the whole output, at any percentage — not just 100%.
        self.assertNotRegex(result.output, r"Historical similarity: \d+% to")

    def test_infrastructure_overlap_never_claims_the_exact_artifact_was_seen(self):
        case_id = self._stored_case_with_match("infrastructure", 0.6, 0.0)
        result = self._invoke("show", case_id, "--db", self.db_path)
        self.assertEqual(result.exit_code, 0)
        line = self._historical_match_line(result.output)
        self.assertIn("infrastructure overlap", line)
        self.assertNotIn("exact artifact seen before", line)

    def test_structural_only_match_never_claims_anything_was_seen_before(self):
        case_id = self._stored_case_with_match(None, 0.0, 0.7)
        result = self._invoke("show", case_id, "--db", self.db_path)
        self.assertEqual(result.exit_code, 0)
        line = self._historical_match_line(result.output)
        self.assertIn("structurally similar", line)
        self.assertNotIn("seen before", line)
        self.assertNotIn("infrastructure overlap", line)

    def test_json_carries_indicator_kind_alongside_the_raw_similarities(self):
        case_id = self._stored_case_with_match("exact_artifact", 1.0, 0.0)
        result = self._invoke("show", case_id, "--db", self.db_path, "--json")
        self.assertEqual(result.exit_code, 0)
        payload = json.loads(result.stdout)
        hs = payload["risk"]["historical_similarity"]
        self.assertEqual(hs["indicator_kind"], "exact_artifact")
        self.assertEqual(hs["indicator_similarity"], 1.0)
        self.assertEqual(hs["structural_similarity"], 0.0)


if __name__ == "__main__":
    unittest.main()
