"""
Investigation-queue tests: an entity reachable by several routes must be
collected exactly once.

The graph deduplicates entities, which hid this: a URL seed and its extracted
domain are the same domain entity, and two sources can pivot to the same IP.
Queuing it twice re-runs every collector against it — burning external-call
budget, and producing byte-identical evidence that the risk engine then counts
as two independent confirmations.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from collections import Counter

from krisis.collectors.base import CollectorResult, EvidenceCollector
from krisis.core.investigator import Investigator
from krisis.core.models import Entity, Evidence, Independence, Polarity
from krisis.core.pivot_engine import InvestigationBudget
from krisis.memory.case_memory import CaseMemory
from krisis.memory.pattern_memory import PatternMemory
from krisis.memory.storage import Storage


class CountingWhoisCollector(EvidenceCollector):
    """Records every entity it is asked about, so double-collection is visible."""

    name = "whois"
    supports = ("domain",)

    def __init__(self):
        self.calls: Counter = Counter()

    def collect(self, entity: Entity) -> CollectorResult:
        self.calls[entity.value] += 1
        ev = Evidence(
            source=self.name, entity_id=entity.id, signal="long_lived_domain",
            value=6000, evidence_type="registration",
            polarity=Polarity.CONTRADICTS_THREAT, confidence=0.55,
            independence=Independence.INDEPENDENT,
        )
        return CollectorResult(evidence=[ev], available=True)


class ConvergingDNSCollector(EvidenceCollector):
    """Every domain resolves to the same IP, so two entities pivot to one target."""

    name = "dns"
    supports = ("domain",)

    def collect(self, entity: Entity) -> CollectorResult:
        ev = Evidence(
            source=self.name, entity_id=entity.id, signal="a_record",
            value=["198.51.100.7"], evidence_type="infrastructure",
            polarity=Polarity.NEUTRAL, confidence=0.9,
            independence=Independence.INDEPENDENT,
        )
        return CollectorResult(evidence=[ev], available=True)


class CountingIPCollector(EvidenceCollector):
    name = "ip_whois"
    supports = ("ip",)

    def __init__(self):
        self.calls: Counter = Counter()

    def collect(self, entity: Entity) -> CollectorResult:
        self.calls[entity.value] += 1
        ev = Evidence(
            source=self.name, entity_id=entity.id, signal="asn", value="64500",
            evidence_type="infrastructure", polarity=Polarity.NEUTRAL, confidence=0.75,
            independence=Independence.INDEPENDENT,
        )
        return CollectorResult(evidence=[ev], available=True)


class TestQueueDeduplication(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        storage = Storage(os.path.join(self.tmp, "queue.db"))
        pattern_memory = PatternMemory(storage)
        self.whois = CountingWhoisCollector()
        self.ip = CountingIPCollector()
        self.investigator = Investigator(
            collectors=[ConvergingDNSCollector(), self.whois, self.ip],
            case_memory=CaseMemory(storage, pattern_memory),
            pattern_memory=pattern_memory,
            budget=InvestigationBudget(max_depth=2, max_entities=25, max_external_calls=60),
        )
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_url_seed_collects_its_domain_once(self):
        """Invariant check. A URL seed yields a url entity and a domain entity, which
        are distinct — this guards the ordinary path rather than a collision."""
        self.investigator.investigate("https://dedup-target.example/login")
        self.assertEqual(self.whois.calls["dedup-target.example"], 1, dict(self.whois.calls))

    def test_two_domains_resolving_to_one_ip_collect_that_ip_once(self):
        """Genuine convergence: two distinct domains pivot onto the same IP, so the
        IP is reachable by two routes and must still be investigated only once."""
        self.investigator.investigate(
            "compare https://first.example/a with https://second.example/b"
        )
        self.assertEqual(
            self.ip.calls["198.51.100.7"], 1,
            f"shared pivot target collected {self.ip.calls['198.51.100.7']} times",
        )

    def test_duplicate_routes_do_not_inflate_evidence(self):
        """A message whose URL and bare domain resolve to the same domain entity: the
        risk engine must not receive the same observation twice as two 'independent'
        confirmations."""
        case, _ = self.investigator.investigate(
            "verify at https://repeat.example/login or visit repeat.example directly"
        )
        entity_ids = [
            ev.entity_id for ev in case.evidence.values() if ev.signal == "long_lived_domain"
        ]
        self.assertEqual(
            len(entity_ids), len(set(entity_ids)),
            "the same entity produced multiple identical whois evidence items",
        )

    def test_message_with_repeated_indicators_collects_each_once(self):
        message = (
            "urgent: verify at https://repeat.example/login now, "
            "or reply to admin@repeat.example — https://repeat.example/login"
        )
        self.investigator.investigate(message)
        self.assertEqual(self.whois.calls["repeat.example"], 1, dict(self.whois.calls))


if __name__ == "__main__":
    unittest.main()
