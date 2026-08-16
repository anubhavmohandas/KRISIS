"""
WHOISCollector unit tests — no dedicated test file existed for this collector
before this pass (it was only exercised through fixture-shaped evidence in
other tests). Mocks the `whois` module's `whois.whois()` call, same boundary
`page_collector` tests mock `requests.get` at.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from krisis.collectors.whois_collector import WHOISCollector
from krisis.core.models import Entity, EntityType

_NOW = datetime.now(timezone.utc)


def _collect(record: dict):
    collector = WHOISCollector()
    entity = Entity(value="example.test", type=EntityType.DOMAIN)
    with mock.patch("whois.whois", return_value=record):
        return collector.collect(entity)


class TestExpirationProximity(unittest.TestCase):
    def test_already_expired_but_record_still_returned(self):
        record = {"domain_name": "example.test", "expiration_date": _NOW - timedelta(days=5)}
        result = _collect(record)
        signals = {e.signal: e for e in result.evidence}
        self.assertIn("expired_domain_still_active", signals)
        ev = signals["expired_domain_still_active"]
        self.assertEqual(ev.polarity.value, "supports_threat")
        self.assertNotIn("domain_expiring_soon", signals)
        self.assertNotIn("domain_expiration_days", signals)

    def test_expiring_soon_is_neutral_not_a_threat_signal(self):
        record = {"domain_name": "example.test", "expiration_date": _NOW + timedelta(days=10)}
        result = _collect(record)
        signals = {e.signal: e for e in result.evidence}
        self.assertIn("domain_expiring_soon", signals)
        self.assertEqual(signals["domain_expiring_soon"].polarity.value, "neutral")
        self.assertNotIn("expired_domain_still_active", signals)

    def test_normal_expiration_horizon_is_neutral_observation(self):
        record = {"domain_name": "example.test", "expiration_date": _NOW + timedelta(days=400)}
        result = _collect(record)
        signals = {e.signal: e for e in result.evidence}
        self.assertIn("domain_expiration_days", signals)
        self.assertEqual(signals["domain_expiration_days"].polarity.value, "neutral")

    def test_no_expiration_date_emits_no_expiration_signal(self):
        record = {"domain_name": "example.test"}
        result = _collect(record)
        signals = {e.signal for e in result.evidence}
        self.assertFalse(signals & {"expired_domain_still_active", "domain_expiring_soon", "domain_expiration_days"})


class TestCreationDateBehaviorUnchanged(unittest.TestCase):
    """Regression guard: the pre-existing creation_date logic in the same file
    must not be disturbed by the new expiration_date block."""

    def test_new_domain_still_flagged(self):
        record = {"domain_name": "example.test", "creation_date": _NOW - timedelta(days=5)}
        result = _collect(record)
        signals = {e.signal for e in result.evidence}
        self.assertIn("newly_registered_domain", signals)

    def test_long_lived_domain_still_contradicts(self):
        record = {"domain_name": "example.test", "creation_date": _NOW - timedelta(days=4000)}
        result = _collect(record)
        signals = {e.signal: e for e in result.evidence}
        self.assertIn("long_lived_domain", signals)
        self.assertEqual(signals["long_lived_domain"].polarity.value, "contradicts_threat")


if __name__ == "__main__":
    unittest.main()
