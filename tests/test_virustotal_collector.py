"""
VirusTotal normalization.

The collector's job is to turn a provider payload into Evidence whose value and
provenance a sceptical reader can check against the provider. A number that
cannot be checked is worse than no number: it looks like a fact.
"""

from __future__ import annotations

import unittest
from unittest import mock

from krisis.collectors.virustotal_collector import VirusTotalCollector
from krisis.core.models import Entity, EntityType, Polarity


class _Response:
    status_code = 200

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def _collect(payload, entity_type=EntityType.DOMAIN, value="example.test"):
    collector = VirusTotalCollector(api_key="test-key")
    with mock.patch("requests.get", return_value=_Response(payload)):
        return collector.collect(Entity(value=value, type=entity_type))


class TestDomainReputationIsCheckable(unittest.TestCase):
    PAYLOAD = {
        "response_code": 1,
        # 12 + 8 = 20 detections out of 60 + 60 = 120 engine checks, over 2 known URLs
        "detected_urls": [
            {"url": "http://example.test/a", "positives": 12, "total": 60},
            {"url": "http://example.test/b", "positives": 8, "total": 60},
        ],
    }

    def _reputation(self):
        result = _collect(self.PAYLOAD)
        return next(e for e in result.evidence if e.evidence_type == "reputation")

    def test_the_reported_fraction_is_the_one_the_ratio_came_from(self):
        """Regression: the denominator used to be the *URL count*, producing
        provenance like '1528 of 100 VirusTotal engines flagged this artifact'."""
        evidence = self._reputation()
        self.assertEqual(evidence.value, "20/120")
        self.assertIn("20 of 120", evidence.provenance)
        self.assertIn("2 known URLs", evidence.provenance)

    def test_a_detection_rate_above_the_threshold_supports_a_threat(self):
        evidence = self._reputation()
        self.assertEqual(evidence.polarity, Polarity.SUPPORTS_THREAT)
        # confidence rises with the detection ratio: 0.5 + 20/120
        self.assertAlmostEqual(evidence.confidence, 0.67, places=2)

    def test_a_url_report_still_reads_as_plain_engine_votes(self):
        result = _collect({"response_code": 1, "positives": 9, "total": 70},
                          entity_type=EntityType.URL, value="http://example.test/x")
        evidence = result.evidence[0]
        self.assertEqual(evidence.value, "9/70")
        self.assertIn("9 of 70 VirusTotal engines", evidence.provenance)


class TestIPReputationIsChecked(unittest.TestCase):
    """A bare IP is a first-class KRISIS seed (see cli.py's own TARGET help text:
    'a URL, domain, IP, file hash, or a message'), and every domain resolves to
    one — IPs are the single most common pivot target in the whole graph. If
    VirusTotal never supports EntityType.IP, no IP investigation can ever earn a
    threat-reputation source, so RiskEngine can never emit anything but
    INSUFFICIENT_EVIDENCE for an IP no matter how malicious VT's own data says it
    is. That is a standing false-negative, not a graceful degradation."""

    PAYLOAD = {
        "response_code": 1,
        "detected_urls": [
            {"url": "http://1.2.3.4/a", "positives": 30, "total": 60},
        ],
        "resolutions": [
            {"hostname": "phish.example", "last_resolved": "2024-01-01"},
        ],
    }

    def test_ip_is_a_supported_entity_type(self):
        collector = VirusTotalCollector(api_key="test-key")
        self.assertTrue(collector.can_handle(Entity(value="1.2.3.4", type=EntityType.IP)))

    def test_ip_reputation_is_checkable(self):
        result = _collect(self.PAYLOAD, entity_type=EntityType.IP, value="1.2.3.4")
        self.assertTrue(result.available)
        reputation = next(e for e in result.evidence if e.evidence_type == "reputation")
        self.assertEqual(reputation.value, "30/60")
        self.assertEqual(reputation.polarity, Polarity.SUPPORTS_THREAT)

    def test_ip_resolutions_become_pivot_candidates(self):
        result = _collect(self.PAYLOAD, entity_type=EntityType.IP, value="1.2.3.4")
        domains = [e for e in result.evidence if e.signal == "vt_related_domain"]
        self.assertTrue(any(e.value == "phish.example" for e in domains))

    def test_a_clean_ip_still_reads_as_checked_not_unavailable(self):
        result = _collect({"response_code": 1}, entity_type=EntityType.IP, value="8.8.8.8")
        self.assertTrue(result.available)
        self.assertEqual(result.evidence[0].signal, "no_detections")


class TestAncillaryDataDoesNotSuppressTheReputationVerdict(unittest.TestCase):
    """Regression: a domain/IP VirusTotal has ancillary data about (subdomains,
    historical resolutions) but has never seen a flagged URL on -- the normal
    shape for most legitimate, popular artifacts -- used to produce ZERO
    reputation-typed evidence, because the no_detections fallback only fired when
    the evidence list was *completely* empty. That made
    coverage.has_reputation_source() read False even though VirusTotal was
    configured, reachable, and answered, so RiskEngine reported "no
    threat-reputation source was available" for an artifact VT had just checked.
    See KRISIS validation-matrix cases 1 (wikipedia.org) and 12 (mozilla.org)."""

    DOMAIN_PAYLOAD = {
        "response_code": 1,
        "subdomains": ["www.example.test", "mail.example.test"],
        "resolutions": [{"ip_address": "93.184.216.34", "last_resolved": "2024-01-01"}],
    }

    def test_a_domain_with_only_ancillary_data_still_produces_reputation_evidence(self):
        result = _collect(self.DOMAIN_PAYLOAD)
        self.assertTrue(result.available)
        reputation = [e for e in result.evidence if e.evidence_type == "reputation"]
        self.assertTrue(
            reputation,
            "expected a reputation-typed evidence item even though detected_urls "
            "and categories were both absent",
        )
        self.assertEqual(reputation[0].signal, "no_detections")
        self.assertEqual(reputation[0].polarity, Polarity.NEUTRAL)

    def test_infrastructure_evidence_is_still_reported_alongside_it(self):
        result = _collect(self.DOMAIN_PAYLOAD)
        signals = {e.signal for e in result.evidence}
        self.assertIn("vt_related_domain", signals)
        self.assertIn("vt_communicating_ip", signals)

    def test_an_ip_with_only_ancillary_resolutions_still_produces_reputation_evidence(self):
        payload = {
            "response_code": 1,
            "resolutions": [{"hostname": "ordinary-site.test", "last_resolved": "2024-01-01"}],
        }
        result = _collect(payload, entity_type=EntityType.IP, value="8.8.4.4")
        reputation = [e for e in result.evidence if e.evidence_type == "reputation"]
        self.assertTrue(reputation)
        self.assertEqual(reputation[0].signal, "no_detections")

    def test_actual_detections_still_take_priority_over_the_fallback(self):
        """Guards against a broken fix that always appends no_detections regardless
        of reputation_recorded -- a domain WITH real detections must report exactly
        one reputation item, the real one, not a second neutral one alongside it."""
        result = _collect(TestDomainReputationIsCheckable.PAYLOAD)
        reputation = [e for e in result.evidence if e.evidence_type == "reputation"]
        self.assertEqual(len(reputation), 1)
        self.assertEqual(reputation[0].signal, "malicious_detection")


class TestFourDistinctAvailabilityStates(unittest.TestCase):
    """provider unavailable / provider skipped / queried-clean / queried-flagged
    must stay four distinct, individually observable states. "Skipped" is a
    ProviderPlanner decision (see test_provider_planner.py), not a collector
    concern, so only the collector-level three are exercised here."""

    def test_no_api_key_is_unavailable_not_a_clean_result(self):
        collector = VirusTotalCollector(api_key=None)
        result = collector.collect(Entity(value="example.test", type=EntityType.DOMAIN))
        self.assertFalse(result.available)
        self.assertIn("no VirusTotal API key", result.note)
        self.assertEqual(result.evidence, [])

    def test_queried_with_no_malicious_findings_is_available_with_neutral_reputation_evidence(self):
        result = _collect({"response_code": 1})
        self.assertTrue(result.available)
        self.assertEqual(result.evidence[0].evidence_type, "reputation")
        self.assertEqual(result.evidence[0].polarity, Polarity.NEUTRAL)

    def test_queried_with_malicious_findings_is_available_with_supporting_reputation_evidence(self):
        result = _collect(TestDomainReputationIsCheckable.PAYLOAD)
        reputation = next(e for e in result.evidence if e.evidence_type == "reputation")
        self.assertEqual(reputation.polarity, Polarity.SUPPORTS_THREAT)


class TestUnavailableIsNotClean(unittest.TestCase):
    def test_no_data_for_the_artifact_is_reported_as_unavailable(self):
        result = _collect({"response_code": 0})
        self.assertFalse(result.available)
        self.assertIn("not checked", result.note)
        self.assertEqual(result.evidence, [])

    def test_rate_limiting_is_reported_as_unavailable(self):
        collector = VirusTotalCollector(api_key="test-key")
        response = _Response({})
        response.status_code = 204
        with mock.patch("requests.get", return_value=response):
            result = collector.collect(Entity(value="example.test", type=EntityType.DOMAIN))
        self.assertFalse(result.available)
        self.assertIn("rate limit", result.note)


if __name__ == "__main__":
    unittest.main()
