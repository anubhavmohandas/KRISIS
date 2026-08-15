"""
Integration test that exercises the real execution path end to end
(collector -> normalization -> pivot engine -> graph -> correlation -> risk
-> explanation -> case storage) using fake, deterministic collectors instead
of real network calls (see TESTING REQUIREMENTS: test the real path, not mocks
that bypass it).

Scenario: a newly-registered domain shares a TLS certificate fingerprint with
a domain from a previously confirmed-malicious case, and VirusTotal flags it.
This exercises historical pattern matching independent of current reputation.
"""

import os
import shutil
import tempfile
import unittest

from krisis.ai.explain import Explainer
from krisis.collectors.base import CollectorResult, EvidenceCollector
from krisis.core.investigator import Investigator
from krisis.core.models import Entity, Evidence, Independence, Polarity
from krisis.core.pivot_engine import InvestigationBudget
from krisis.memory.case_memory import CaseMemory
from krisis.memory.pattern_memory import PatternMemory
from krisis.memory.storage import Storage

SHARED_CERT = "cert_fingerprint_shared_with_prior_phishing_case"


class FakeDNSCollector(EvidenceCollector):
    name = "dns"
    supports = ("domain",)

    def collect(self, entity: Entity) -> CollectorResult:
        ev = Evidence(
            source=self.name, entity_id=entity.id, signal="a_record",
            value=["185.10.10.20"], evidence_type="infrastructure",
            polarity=Polarity.NEUTRAL, confidence=0.9, independence=Independence.INDEPENDENT,
        )
        return CollectorResult(evidence=[ev], available=True)


class FakeTLSCollector(EvidenceCollector):
    name = "tls"
    supports = ("domain",)

    def collect(self, entity: Entity) -> CollectorResult:
        ev = Evidence(
            source=self.name, entity_id=entity.id, signal="certificate_fingerprint",
            value=SHARED_CERT, evidence_type="infrastructure",
            polarity=Polarity.NEUTRAL, confidence=0.85, independence=Independence.INDEPENDENT,
        )
        return CollectorResult(evidence=[ev], available=True)


class FakeVTCollector(EvidenceCollector):
    name = "virustotal"
    supports = ("domain",)

    def collect(self, entity: Entity) -> CollectorResult:
        # Deliberately CLEAN current reputation — the test is about historical
        # pattern matching catching what current reputation misses.
        ev = Evidence(
            source=self.name, entity_id=entity.id, signal="no_detections",
            value=0, evidence_type="reputation",
            polarity=Polarity.NEUTRAL, confidence=0.3, independence=Independence.INDEPENDENT,
        )
        return CollectorResult(evidence=[ev], available=True)


class FailingWHOISCollector(EvidenceCollector):
    name = "whois"
    supports = ("domain",)

    def collect(self, entity: Entity) -> CollectorResult:
        return CollectorResult(evidence=[], available=False, note="simulated provider outage")


class TestInvestigatorIntegration(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.storage = Storage(self.db_path)
        self.pattern_memory = PatternMemory(self.storage)
        self.case_memory = CaseMemory(self.storage, self.pattern_memory)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _investigator(self) -> Investigator:
        return Investigator(
            collectors=[FakeDNSCollector(), FakeTLSCollector(), FakeVTCollector(), FailingWHOISCollector()],
            case_memory=self.case_memory,
            pattern_memory=self.pattern_memory,
            budget=InvestigationBudget(max_depth=2, max_entities=20, max_external_calls=50),
            explainer=Explainer(use_llm=False),
        )

    def test_full_loop_produces_a_case_with_risk_and_explanation(self):
        investigator = self._investigator()
        case, trace = investigator.investigate("suspicious-login.com")

        self.assertIsNotNone(case.risk)
        self.assertTrue(case.explanation)
        self.assertTrue(case.recommendation)
        self.assertGreater(len(case.evidence), 0)
        self.assertGreater(len(case.pivots), 0)
        self.assertGreater(len(trace.steps), 0)

        # provider failure must be recorded, not silently treated as "clean"
        self.assertTrue(any("whois" in f for f in case.provider_failures))

        # case must be retrievable from storage
        stored = self.case_memory.get(case.id)
        self.assertIsNotNone(stored)
        self.assertEqual(stored["seed"], "suspicious-login.com")

    def test_pivot_to_ip_and_certificate_creates_graph_relationships(self):
        investigator = self._investigator()
        case, _ = investigator.investigate("suspicious-login.com")
        graph = investigator.last_graph

        ip_entities = [e for e in graph.entities() if e.type.value == "ip"]
        cert_entities = [e for e in graph.entities() if e.type.value == "certificate"]
        self.assertTrue(any(e.value == "185.10.10.20" for e in ip_entities))
        self.assertTrue(any(e.value == SHARED_CERT for e in cert_entities))

        # both should be reachable from the seed domain via a relationship
        seed = next(e for e in graph.entities() if e.depth == 0 and e.type.value == "domain")
        neighbor_values = {n.value for n, _ in graph.neighbors(seed.id)}
        self.assertIn("185.10.10.20", neighbor_values)
        self.assertIn(SHARED_CERT, neighbor_values)

    def test_historical_similarity_detected_despite_clean_current_reputation(self):
        # Seed prior "confirmed malicious" case sharing the same certificate.
        prior = self._investigator()
        prior_case, _ = prior.investigate("known-phishing-domain.com")
        self.case_memory.set_outcome(prior_case.id, "confirmed_malicious")

        # New investigation reuses the same fake collectors -> same shared cert.
        investigator = self._investigator()
        case, _ = investigator.investigate("brand-new-lookalike.com")

        self.assertTrue(case.pattern_matches, "expected a historical pattern match on the shared certificate")
        best = case.pattern_matches[0]
        self.assertEqual(best["prior_outcome"], "confirmed_malicious")
        self.assertGreater(best["similarity"], 0)
        self.assertIsNotNone(case.risk.historical_similarity)

    def test_budget_limits_are_respected(self):
        investigator = self._investigator()
        investigator.budget.max_entities = 2
        investigator.pivot_engine.budget = investigator.budget
        case, _ = investigator.investigate("suspicious-login.com")
        self.assertLessEqual(investigator.budget.entities_investigated, 2)


if __name__ == "__main__":
    unittest.main()
