"""
TLSCollector unit tests — no dedicated test file existed for this collector
before this pass. Mocks the ssl/socket boundary the same way page_collector
tests mock socket.getaddrinfo/requests.get.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from krisis.collectors.tls_collector import TLSCollector
from krisis.core.models import Entity, EntityType

_FUTURE = (datetime.now(timezone.utc) + timedelta(days=200)).strftime("%b %d %H:%M:%S %Y GMT")


def _rdn(org: str | None) -> tuple:
    return ((("organizationName", org),),) if org else ()


def _collect(host: str, subject_org: str | None, issuer_org: str | None = "Some CA"):
    cert_dict = {
        "notAfter": _FUTURE,
        "subject": _rdn(subject_org),
        "issuer": _rdn(issuer_org),
    }

    ssock = mock.MagicMock()
    ssock.__enter__.return_value = ssock
    ssock.__exit__.return_value = False
    ssock.getpeercert.side_effect = lambda binary_form=False: (b"der-bytes" if binary_form else cert_dict)

    sock = mock.MagicMock()
    sock.__enter__.return_value = sock
    sock.__exit__.return_value = False

    context = mock.MagicMock()
    context.wrap_socket.return_value = ssock

    with mock.patch("krisis.collectors.tls_collector.socket.create_connection", return_value=sock), \
         mock.patch("krisis.collectors.tls_collector.ssl.create_default_context", return_value=context):
        return TLSCollector().collect(Entity(value=host, type=EntityType.DOMAIN))


class TestCertificateSubjectOrg(unittest.TestCase):
    def test_absent_subject_org_emits_no_new_evidence(self):
        result = _collect("example.test", subject_org=None)
        signals = {e.signal for e in result.evidence}
        self.assertFalse(signals & {"certificate_subject_org_match", "certificate_subject_org_mismatch"})
        # regression guard: existing signals still present/unaffected
        self.assertIn("certificate_fingerprint", signals)
        self.assertIn("valid_tls_present", signals)

    def test_matching_subject_org_contradicts_threat(self):
        result = _collect("example.test", subject_org="Example Inc")
        signals = {e.signal: e for e in result.evidence}
        self.assertIn("certificate_subject_org_match", signals)
        self.assertEqual(signals["certificate_subject_org_match"].polarity.value, "contradicts_threat")
        self.assertNotIn("certificate_subject_org_mismatch", signals)

    def test_mismatched_subject_org_supports_threat(self):
        result = _collect("example.test", subject_org="Totally Unrelated Corp")
        signals = {e.signal: e for e in result.evidence}
        self.assertIn("certificate_subject_org_mismatch", signals)
        self.assertEqual(signals["certificate_subject_org_mismatch"].polarity.value, "supports_threat")
        self.assertNotIn("certificate_subject_org_match", signals)


class TestExistingSignalsUnchanged(unittest.TestCase):
    def test_fingerprint_and_issuer_signal_still_present(self):
        result = _collect("example.test", subject_org=None, issuer_org="Let's Encrypt")
        signals = {e.signal: e for e in result.evidence}
        self.assertIn("certificate_fingerprint", signals)
        self.assertIn("valid_tls_present", signals)
        self.assertEqual(signals["valid_tls_present"].confidence, 0.25)


if __name__ == "__main__":
    unittest.main()
