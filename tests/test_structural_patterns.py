"""
Structural pattern matching: "have I seen this *kind* of investigation before?"

The wrong conclusions this guards against, in both directions:

  false negative — an adversary rotates every IP and certificate, and KRISIS,
                   which only ever compared concrete values, sees a brand new
                   threat instead of the same operation with new infrastructure.

  false positive — a shape is far cheaper to coincide with than a certificate
                   fingerprint, so unrestrained structural matching would relate
                   every new domain to every other new domain, and a single
                   confirmed case would become trusted intelligence.
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
    Polarity,
    Relationship,
)
from krisis.core.risk import MIN_SIMILARITY_FOR_SCORING, RiskEngine, historical_impact
from krisis.memory.case_memory import CaseMemory
from krisis.memory.pattern_memory import PatternMemory, structural_facets
from krisis.memory.storage import Storage

PHISHING_SIGNALS = [
    ("newly_registered_domain", "registration"),
    ("brand_lookalike", "identity"),
    ("credential_form", "behavior"),
]


def _case(seed, signals, ips=(), cert=None):
    """A case built the way the investigator builds one: entities, relationships
    with reasons, and polarised evidence."""
    case = Case(seed=seed, seed_type=EntityType.DOMAIN)
    root = Entity(value=seed, type=EntityType.DOMAIN, depth=0)
    case.entities[root.id] = root

    def link(entity, relation_type):
        case.entities[entity.id] = entity
        rel = Relationship(
            source_entity_id=root.id, target_entity_id=entity.id,
            relation_type=relation_type, reason="observed during collection",
        )
        case.relationships[rel.id] = rel

    for ip in ips:
        link(Entity(value=ip, type=EntityType.IP, depth=1), "resolves_to")
    if cert:
        link(Entity(value=cert, type=EntityType.CERTIFICATE, depth=1), "presents_certificate")

    for signal, evidence_type in signals:
        ev = Evidence(
            source="test", entity_id=root.id, signal=signal, value=1,
            evidence_type=evidence_type, polarity=Polarity.SUPPORTS_THREAT, confidence=0.8,
        )
        case.evidence[ev.id] = ev
    return case


def _graph_of(case):
    graph = EntityGraph()
    for entity in case.entities.values():
        graph.add_entity(entity)
    for rel in case.relationships.values():
        graph.add_relationship(rel)
    return graph


def _match(memory, case):
    return memory.find_similar(_graph_of(case), list(case.evidence.values()), exclude_seed=case.seed)


class StructuralMatchingTest(unittest.TestCase):
    def setUp(self):
        self.storage = Storage(os.path.join(tempfile.mkdtemp(), "structural.db"))
        self.pattern_memory = PatternMemory(self.storage)
        self.case_memory = CaseMemory(self.storage, self.pattern_memory)


class TestRotatedInfrastructure(StructuralMatchingTest):
    def test_same_shape_on_entirely_new_infrastructure_still_matches(self):
        """The point of the whole mechanism: no shared indicator, same operation."""
        self.case_memory.save(
            _case("phish-one.example", PHISHING_SIGNALS, ips=["203.0.113.5"], cert="AA:11")
        )
        rotated = _case("phish-two.example", PHISHING_SIGNALS, ips=["198.51.100.9"], cert="BB:22")

        matches = _match(self.pattern_memory, rotated)
        self.assertTrue(matches, "rotated infrastructure with an identical shape did not match")
        best = matches[0]
        self.assertEqual(best["indicator_similarity"], 0.0, "no indicator is actually shared")
        self.assertGreater(best["structural_similarity"], 0.0)
        self.assertEqual(best["match_type"], "structural")
        self.assertIn("signal+:identity:brand_lookalike", best["matched_facets"])

    def test_a_different_shape_does_not_match(self):
        """Counter-test: without this, "structural similarity" would just mean
        "both of these are domains"."""
        self.case_memory.save(
            _case("phish-one.example", PHISHING_SIGNALS, ips=["203.0.113.5"], cert="AA:11")
        )
        unrelated = _case(
            "corporate.example", [("expired_certificate", "infrastructure")], ips=["198.51.100.9"]
        )
        self.assertEqual(_match(self.pattern_memory, unrelated), [])

    def test_reinvestigating_one_artifact_does_not_match_its_own_shape(self):
        case = _case("repeat.example", PHISHING_SIGNALS, ips=["203.0.113.5"])
        self.case_memory.save(case)
        self.assertEqual(_match(self.pattern_memory, case), [])
        # ...while a genuinely different artifact with that shape does
        self.assertTrue(
            _match(self.pattern_memory, _case("other.example", PHISHING_SIGNALS, ips=["198.51.100.9"]))
        )

    def test_both_dimensions_are_reported_separately_when_both_fire(self):
        self.case_memory.save(
            _case("phish-one.example", PHISHING_SIGNALS, ips=["203.0.113.5"], cert="AA:11")
        )
        same_host = _case("phish-two.example", PHISHING_SIGNALS, ips=["203.0.113.5"], cert="AA:11")

        best = _match(self.pattern_memory, same_host)[0]
        self.assertEqual(best["match_type"], "indicator+structural")
        self.assertGreater(best["indicator_similarity"], 0.0)
        self.assertGreater(best["structural_similarity"], 0.0)
        self.assertGreaterEqual(best["similarity"], best["indicator_similarity"])


class TestStructuralPoisoningResistance(StructuralMatchingTest):
    """A shape is cheap to coincide with, so it must earn its influence."""

    def _sighting(self, seed):
        # Distinct IPs on purpose: these cases must resemble each other structurally
        # and *only* structurally, or the test stops testing structural matching.
        self._sightings = getattr(self, "_sightings", 0) + 1
        case = _case(seed, PHISHING_SIGNALS, ips=[f"203.0.113.{self._sightings}"])
        self.case_memory.save(case)
        return case

    def _risk_delta(self, match):
        correlation = CorrelationResult(
            supporting=[
                Evidence(source="whois", entity_id="e1", signal="newly_registered_domain",
                         value=2, evidence_type="registration", polarity=Polarity.SUPPORTS_THREAT)
            ],
            evidence_diversity=0.5,
        )
        coverage = Coverage(attempted={"whois"}, available={"whois"}, evidence_types={"registration"})
        engine = RiskEngine()
        baseline = engine.score(correlation, coverage=coverage).score
        with_history = engine.score(correlation, historical_similarity=match, coverage=coverage).score
        return with_history - baseline

    def test_a_shape_seen_once_cannot_move_the_score(self):
        self._sighting("first.example")
        best = _match(self.pattern_memory, _case("new.example", PHISHING_SIGNALS, ips=["198.51.100.9"]))[0]

        self.assertEqual(best["pattern_stage"], "observed")
        self.assertEqual(best["structural_similarity"], 1.0, "shapes are identical")
        self.assertLess(
            best["similarity"], MIN_SIMILARITY_FOR_SCORING,
            "a single unvalidated sighting must stay a lead, not evidence",
        )
        self.assertEqual(self._risk_delta(best), 0)

    def test_repeated_human_validation_is_what_earns_influence(self):
        for i in range(3):
            case = self._sighting(f"confirmed{i}.example")
            self.case_memory.set_outcome(case.id, "confirmed_malicious")

        best = _match(self.pattern_memory, _case("new.example", PHISHING_SIGNALS, ips=["198.51.100.9"]))[0]
        self.assertEqual(best["pattern_stage"], "trusted")
        self.assertEqual(best["prior_outcome"], "confirmed_malicious")
        self.assertGreaterEqual(best["similarity"], MIN_SIMILARITY_FOR_SCORING)
        self.assertGreater(self._risk_delta(best), 0)

    def test_repetition_without_validation_never_reaches_scoring_weight(self):
        """Seeing the same shape often proves KRISIS keeps seeing it, not that it
        keeps being right — the difference between 'repeated' and 'validated'."""
        for i in range(6):
            self._sighting(f"seen{i}.example")

        best = _match(self.pattern_memory, _case("new.example", PHISHING_SIGNALS, ips=["198.51.100.9"]))[0]
        self.assertEqual(best["pattern_stage"], "repeated")
        self.assertLess(best["similarity"], MIN_SIMILARITY_FOR_SCORING)

    def test_a_shape_validated_as_wrong_loses_all_influence(self):
        """One false positive becoming a trusted pattern is the failure mode that
        turns a memory into a false-positive factory."""
        for i in range(2):
            case = self._sighting(f"fp{i}.example")
            self.case_memory.set_outcome(case.id, "false_positive")

        self.assertEqual(self.pattern_memory.list_patterns()[0]["stage"], "deprecated")
        self.assertEqual(
            _match(self.pattern_memory, _case("new.example", PHISHING_SIGNALS, ips=["198.51.100.9"])),
            [],
            "a discredited shape must not keep matching",
        )

    def test_generic_structure_does_not_match_even_a_trusted_shape(self):
        """The dangerous case: once a shape *is* trusted, the only thing standing
        between it and every ordinary domain is the similarity floor. A site whose
        entire structure is "it resolves to an IP" shares that much with any
        phishing case, and must not be reported as resembling one.
        """
        for i in range(3):
            case = _case(f"confirmed{i}.example", PHISHING_SIGNALS,
                         ips=[f"203.0.113.{i}"], cert=f"AA:{i}")
            self.case_memory.save(case)
            self.case_memory.set_outcome(case.id, "confirmed_malicious")
        self.assertEqual(self.pattern_memory.list_patterns()[0]["stage"], "trusted")

        ordinary = _case("ordinary-shop.example", signals=[], ips=["198.51.100.9"])
        self.assertEqual(
            _match(self.pattern_memory, ordinary), [],
            "generic structure was reported as resembling a trusted phishing shape",
        )

    def test_a_single_facet_is_neither_remembered_nor_compared(self):
        one_facet = _case("thin.example", signals=[("newly_registered_domain", "registration")])
        self.case_memory.save(one_facet)
        self.assertEqual(self.pattern_memory.list_patterns(), [],
                         "a lone observation was stored as a pattern")

        self.case_memory.save(_case("rich.example", PHISHING_SIGNALS, ips=["203.0.113.5"]))
        self.assertEqual(_match(self.pattern_memory, one_facet), [])

    def test_ubiquitous_structure_is_weighted_down_against_rare_structure(self):
        """Every domain resolves to an IP. A facet that describes investigations in
        general must not carry the same weight as one that describes this one."""
        patterns = [
            {"signature": {"facets": ["rel:resolves_to", "signal+:identity:brand_lookalike"]},
             "observed_count": 1},
            {"signature": {"facets": ["rel:resolves_to"]}, "observed_count": 40},
        ]
        idf = PatternMemory._facet_idf(patterns)
        self.assertLess(idf("rel:resolves_to"), idf("signal+:identity:brand_lookalike"))


class TestCommodityInfrastructureCreatesNoStructure(unittest.TestCase):
    """Section 9 applies to shape as much as to values: renting the same mail
    vendor as another company is not a structural resemblance to it."""

    def test_commodity_entities_and_their_edges_are_excluded_from_the_signature(self):
        root = Entity(value="corp.example", type=EntityType.DOMAIN, depth=0)
        vendor_mx = Entity(value="corp-mail.protection.outlook.com", type=EntityType.HOSTNAME,
                           depth=1, shared_infrastructure=True)
        own_ip = Entity(value="203.0.113.11", type=EntityType.IP, depth=1)
        relationships = [
            Relationship(source_entity_id=root.id, target_entity_id=vendor_mx.id,
                         relation_type="mail_exchange", reason="MX record"),
            Relationship(source_entity_id=root.id, target_entity_id=own_ip.id,
                         relation_type="resolves_to", reason="A record"),
        ]
        facets = structural_facets([root, vendor_mx, own_ip], [], relationships)

        self.assertIn("entity:ip", facets)
        self.assertIn("rel:resolves_to", facets)
        self.assertNotIn("entity:hostname", facets)
        self.assertNotIn("rel:mail_exchange", facets)

    def test_the_seed_type_is_not_a_facet(self):
        """It is fixed by what the user typed, so it distinguishes nothing."""
        root = Entity(value="corp.example", type=EntityType.DOMAIN, depth=0)
        self.assertNotIn("entity:domain", structural_facets([root], [], []))

    def test_neutral_observations_are_not_facets(self):
        """A/NS/MX records exist for every domain; including them would make every
        investigation resemble every other one."""
        root = Entity(value="corp.example", type=EntityType.DOMAIN, depth=0)
        neutral = Evidence(source="dns", entity_id=root.id, signal="a_record", value="1.2.3.4",
                           evidence_type="infrastructure", polarity=Polarity.NEUTRAL)
        self.assertEqual(structural_facets([root], [neutral], []), [])


class TestStrongestMatchIsTheOneThatCanMoveTheVerdict(unittest.TestCase):
    """Ranking historical matches by resemblance alone lets a strong benign match
    shadow a weaker malicious one, and the malicious lead is then never scored."""

    BENIGN = {"pattern_id": "b", "similarity": 0.95, "prior_outcome": "confirmed_benign",
              "pattern_name": "benign shape"}
    MALICIOUS = {"pattern_id": "m", "similarity": 0.65, "prior_outcome": "confirmed_malicious",
                 "pattern_name": "malicious shape"}

    def test_impact_ranks_a_weaker_validated_threat_above_a_stronger_benign_match(self):
        self.assertGreater(historical_impact(self.MALICIOUS), historical_impact(self.BENIGN))
        self.assertEqual(
            max([self.BENIGN, self.MALICIOUS], key=historical_impact)["pattern_id"], "m"
        )

    def test_the_investigator_scores_against_the_impactful_match(self):
        from krisis.core.investigator import Investigator

        storage = Storage(os.path.join(tempfile.mkdtemp(), "selection.db"))
        pattern_memory = PatternMemory(storage)
        investigator = Investigator(
            collectors=[], case_memory=CaseMemory(storage, pattern_memory),
            pattern_memory=pattern_memory,
        )

        class StubMemory:
            def find_similar(self, graph, evidence, exclude_seed=None):
                # sorted by similarity, exactly as find_similar returns them
                return [TestStrongestMatchIsTheOneThatCanMoveTheVerdict.BENIGN,
                        TestStrongestMatchIsTheOneThatCanMoveTheVerdict.MALICIOUS]

        investigator.correlation_engine.pattern_memory = StubMemory()
        case, _ = investigator.investigate("target.example")

        self.assertEqual(case.risk.historical_similarity["pattern_id"], "m")


if __name__ == "__main__":
    unittest.main()
