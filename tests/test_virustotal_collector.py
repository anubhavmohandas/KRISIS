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
