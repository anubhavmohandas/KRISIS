"""
DNSCollector unit tests — no dedicated test file existed for this collector
before this pass. Mocks the dns.resolver boundary the same way
test_tls_collector.py mocks the ssl/socket boundary: a fake `.resolve()`
keyed on (name, rtype), so the real per-record-type loop and the new
SPF/DMARC helpers both run against controlled input.
"""

from __future__ import annotations

import unittest
from unittest import mock

import dns.resolver

from krisis.collectors.dns_collector import DNSCollector
from krisis.core.models import Entity, EntityType


class _Rec:
    """Stand-in for a dnspython rdata object: str(r) is all the collector reads."""

    def __init__(self, text: str):
        self._text = text

    def __str__(self) -> str:
        return self._text


def _resolver(txt_records=None, dmarc_records=None, dmarc_absent="noanswer"):
    """Build a fake resolve(name, rtype) matching one collect() call's shape.

    A/root TXT always resolve (so the collector never hits its NXDOMAIN
    short-circuit); every other base record type is left unanswered
    (NoAnswer) so tests stay focused on SPF/DMARC. `txt_records`/
    `dmarc_records` are raw text *without* surrounding quotes — real
    dnspython TXT rdata stringifies with quotes, so this wraps them.
    """

    def resolve(name, rtype):
        if rtype == "A" and not name.startswith("_dmarc."):
            return [_Rec("93.184.216.34")]
        if rtype == "TXT":
            if name.startswith("_dmarc."):
                if dmarc_records is None:
                    if dmarc_absent == "nxdomain":
                        raise dns.resolver.NXDOMAIN()
                    raise dns.resolver.NoAnswer()
                return [_Rec(f'"{t}"') for t in dmarc_records]
            if txt_records is None:
                raise dns.resolver.NoAnswer()
            return [_Rec(f'"{t}"') for t in txt_records]
        raise dns.resolver.NoAnswer()

    return resolve


def _collect(**kwargs) -> list:
    fake = mock.MagicMock()
    fake.resolve.side_effect = _resolver(**kwargs)
    with mock.patch("dns.resolver.Resolver", return_value=fake):
        result = DNSCollector().collect(Entity(value="example.test", type=EntityType.DOMAIN))
    return result.evidence


class TestSPF(unittest.TestCase):
    def test_no_spf_record_is_reported_missing_not_threat(self):
        evidence = {e.signal: e for e in _collect(txt_records=None)}
        self.assertIn("spf_missing", evidence)
        self.assertEqual(evidence["spf_missing"].polarity.value, "neutral")

    def test_spf_record_present(self):
        evidence = {e.signal: e for e in _collect(txt_records=["v=spf1 include:_spf.example.com ~all"])}
        self.assertIn("spf_record", evidence)
        self.assertEqual(evidence["spf_record"].value, "v=spf1 include:_spf.example.com ~all")
        self.assertEqual(evidence["spf_record"].polarity.value, "neutral")
        self.assertNotIn("spf_missing", evidence)

    def test_multiple_spf_records_is_malformed(self):
        evidence = {e.signal: e for e in _collect(txt_records=["v=spf1 ~all", "v=spf1 -all"])}
        self.assertIn("spf_malformed", evidence)
        self.assertNotIn("spf_record", evidence)
        self.assertNotIn("spf_missing", evidence)

    def test_unrelated_txt_records_do_not_count_as_spf(self):
        evidence = {e.signal: e for e in _collect(txt_records=["google-site-verification=abc123"])}
        self.assertIn("spf_missing", evidence)
        self.assertNotIn("spf_record", evidence)

    def test_multi_segment_txt_record_concatenates_without_injecting_a_boundary(self):
        """A TXT record over 255 bytes (a long SPF record, e.g. github.com's real
        one) is split across multiple character-strings by the wire format and
        must be rejoined with no separator (RFC 7208 §3.3) — not left with a
        stray '" "' where dnspython's own str() would put the segment split."""
        first = "v=spf1 " + ("ip4:203.0.113." + "1 ") * 30  # long enough to force a real split
        second = "include:_spf.example.test ~all"

        class _MultiSegmentRec:
            strings = (first.encode(), second.encode())

            def __str__(self):
                return f'"{first}" "{second}"'

        fake = mock.MagicMock()

        def resolve(name, rtype):
            if rtype == "A":
                return [_Rec("93.184.216.34")]
            if rtype == "TXT" and not name.startswith("_dmarc."):
                return [_MultiSegmentRec()]
            raise dns.resolver.NoAnswer()

        fake.resolve.side_effect = resolve
        with mock.patch("dns.resolver.Resolver", return_value=fake):
            result = DNSCollector().collect(Entity(value="example.test", type=EntityType.DOMAIN))
        evidence = {e.signal: e for e in result.evidence}
        self.assertIn("spf_record", evidence)
        self.assertEqual(evidence["spf_record"].value, first + second)
        self.assertNotIn('" "', evidence["spf_record"].value)


class TestDMARC(unittest.TestCase):
    def test_no_dmarc_record_noanswer_is_reported_missing(self):
        evidence = {e.signal: e for e in _collect(dmarc_records=None, dmarc_absent="noanswer")}
        self.assertIn("dmarc_missing", evidence)
        self.assertEqual(evidence["dmarc_missing"].polarity.value, "neutral")

    def test_no_dmarc_record_nxdomain_is_reported_missing(self):
        evidence = {e.signal: e for e in _collect(dmarc_records=None, dmarc_absent="nxdomain")}
        self.assertIn("dmarc_missing", evidence)

    def test_dmarc_record_present(self):
        evidence = {e.signal: e for e in _collect(dmarc_records=["v=DMARC1; p=reject; rua=mailto:d@example.test"])}
        self.assertIn("dmarc_record", evidence)
        self.assertEqual(evidence["dmarc_record"].value, "v=DMARC1; p=reject; rua=mailto:d@example.test")
        self.assertEqual(evidence["dmarc_record"].polarity.value, "neutral")
        self.assertNotIn("dmarc_missing", evidence)

    def test_multiple_dmarc_records_is_malformed(self):
        evidence = {
            e.signal: e
            for e in _collect(dmarc_records=["v=DMARC1; p=reject", "v=DMARC1; p=none"])
        }
        self.assertIn("dmarc_malformed", evidence)
        self.assertNotIn("dmarc_record", evidence)
        self.assertNotIn("dmarc_missing", evidence)

    def test_queried_independently_of_root_txt(self):
        """SPF absent, DMARC present — proves _dmarc.<domain> is its own query,
        not derived from the root domain's TXT set."""
        evidence = {
            e.signal: e
            for e in _collect(txt_records=None, dmarc_records=["v=DMARC1; p=quarantine"])
        }
        self.assertIn("spf_missing", evidence)
        self.assertIn("dmarc_record", evidence)


class TestNeverAutomaticThreat(unittest.TestCase):
    """Master-loop requirement: absence of SPF/DMARC must never be scored as a
    threat signal, only reported as context. Locks polarity for every state."""

    def test_all_spf_dmarc_states_are_neutral(self):
        cases = [
            dict(txt_records=None, dmarc_records=None),
            dict(txt_records=["v=spf1 ~all"], dmarc_records=["v=DMARC1; p=reject"]),
            dict(txt_records=["v=spf1 ~all", "v=spf1 -all"], dmarc_records=["v=DMARC1; p=reject", "v=DMARC1; p=none"]),
        ]
        for kwargs in cases:
            for ev in _collect(**kwargs):
                if ev.signal.startswith("spf_") or ev.signal.startswith("dmarc_"):
                    self.assertEqual(
                        ev.polarity.value, "neutral", f"{ev.signal} must stay neutral, was {ev.polarity.value}"
                    )


class TestExistingBehaviorUnchanged(unittest.TestCase):
    def test_a_record_and_nxdomain_paths_still_work(self):
        evidence = {e.signal: e for e in _collect(txt_records=["v=spf1 ~all"])}
        self.assertIn("a_record", evidence)

        fake = mock.MagicMock()
        fake.resolve.side_effect = mock.Mock(side_effect=dns.resolver.NXDOMAIN())
        with mock.patch("dns.resolver.Resolver", return_value=fake):
            result = DNSCollector().collect(Entity(value="nx.example.test", type=EntityType.DOMAIN))
        signals = {e.signal for e in result.evidence}
        self.assertEqual(signals, {"nxdomain"})  # SPF/DMARC must not run for a domain that doesn't resolve


if __name__ == "__main__":
    unittest.main()
