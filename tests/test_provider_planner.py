"""
Provider budgeting tests.

These exist because of a real run: two seeds fanned out into a dozen entities and
KRISIS spent fourteen VirusTotal requests before the provider's rate limit
answered for it. Every test below is a rule that would have prevented part of
that, and each names the rule whose deletion must make it fail (see MUTATION
TESTING — a green suite that survives deleting the rule is not defending it).
"""

import os
import shutil
import tempfile
import unittest

from krisis.collectors.base import CollectorResult, EvidenceCollector
from krisis.core.models import Entity, EntityType, Evidence, Independence, Polarity
from krisis.core.provider_planner import ProviderPlanner, ProviderPolicy
from krisis.memory.storage import Storage

EXPENSIVE = "virustotal"


class CountingCollector(EvidenceCollector):
    supports = ("domain",)

    def __init__(self, name=EXPENSIVE, available=True, note=""):
        self.name = name
        self.calls = 0
        self._available = available
        self._note = note

    def collect(self, entity: Entity) -> CollectorResult:
        self.calls += 1
        if not self._available:
            return CollectorResult(evidence=[], available=False, note=self._note)
        return CollectorResult(
            evidence=[
                Evidence(
                    source=self.name, entity_id=entity.id, signal="malicious_detection",
                    value="3/70", evidence_type="reputation", polarity=Polarity.SUPPORTS_THREAT,
                    confidence=0.6, independence=Independence.INDEPENDENT,
                    provenance="3 of 70 engines flagged this artifact",
                )
            ],
            available=True,
        )


def domain(value, depth=0, priority=0.0, supports=False, commodity=False) -> Entity:
    return Entity(
        value=value, type=EntityType.DOMAIN, depth=depth, shared_infrastructure=commodity,
        metadata={"pivot_priority": priority, "supports_hypothesis": supports},
    )


class PlannerTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.storage = Storage(os.path.join(self.tmp, "planner.db"))
        self.now = 1_000_000.0
        self.slept = []
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def planner(self, policy: ProviderPolicy, storage=None) -> ProviderPlanner:
        return ProviderPlanner(
            policies={policy.name: policy},
            storage=self.storage if storage is None else storage,
            clock=lambda: self.now,
            sleeper=self.slept.append,
        )


class TestDeduplication(PlannerTestCase):
    def test_same_question_is_asked_once_per_investigation(self):
        """Delete the session-dedup branch in ProviderPlanner.collect and this fails.

        The same value is reachable as several graph nodes (a URL and its domain, a
        seed and a pivot that loops back to it). Asking twice spends two requests and
        yields two copies of one observation, which downstream counts as two
        independent confirmations.
        """
        collector = CountingCollector()
        planner = self.planner(ProviderPolicy(name=EXPENSIVE, cache_ttl_seconds=0))
        planner.collect(collector, domain("example.com"))
        result, decision = planner.collect(collector, domain("example.com"))

        self.assertEqual(collector.calls, 1)
        self.assertEqual(decision.action, "deduplicated")
        self.assertTrue(result.evidence, "the reused answer must still be evidence")
        self.assertEqual(planner.usage_for(EXPENSIVE).deduplicated, 1)

    def test_reused_evidence_is_rebound_to_the_entity_it_describes(self):
        collector = CountingCollector()
        planner = self.planner(ProviderPolicy(name=EXPENSIVE, cache_ttl_seconds=0))
        first = domain("example.com")
        second = domain("example.com")
        planner.collect(collector, first)
        result, _ = planner.collect(collector, second)

        self.assertEqual(result.evidence[0].entity_id, second.id)
        self.assertNotEqual(
            result.evidence[0].id, first.id,
            "reused evidence needs its own id — the case stores evidence by id",
        )


class TestCaching(PlannerTestCase):
    POLICY = ProviderPolicy(name=EXPENSIVE, cache_ttl_seconds=3600)

    def test_a_recent_answer_is_reused_across_runs(self):
        """Delete ProviderPlanner._from_cache and this fails: every CLI invocation
        would re-buy answers the previous one already paid for."""
        collector = CountingCollector()
        self.planner(self.POLICY).collect(collector, domain("example.com"))

        self.now += 60
        result, decision = self.planner(self.POLICY).collect(collector, domain("example.com"))

        self.assertEqual(collector.calls, 1)
        self.assertEqual(decision.action, "cached")
        self.assertTrue(result.evidence)

    def test_a_stale_answer_is_a_miss_not_a_result(self):
        """Old intelligence is not current intelligence. Delete the TTL comparison and
        KRISIS reports last week's reputation as today's."""
        collector = CountingCollector()
        self.planner(self.POLICY).collect(collector, domain("example.com"))

        self.now += 3601
        _, decision = self.planner(self.POLICY).collect(collector, domain("example.com"))

        self.assertEqual(collector.calls, 2)
        self.assertEqual(decision.action, "queried")

    def test_cached_evidence_never_masquerades_as_live(self):
        """Delete the freshness stamping in _evidence_from_dict and a cached answer
        becomes indistinguishable from one fetched a second ago."""
        collector = CountingCollector()
        self.planner(self.POLICY).collect(collector, domain("example.com"))

        self.now += 600
        result, _ = self.planner(self.POLICY).collect(collector, domain("example.com"))
        evidence = result.evidence[0]

        self.assertEqual(evidence.freshness, "cached")
        self.assertEqual(evidence.cache_age_seconds, 600)
        self.assertIn("cached", evidence.provenance.lower())
        self.assertIn("3 of 70 engines", evidence.provenance, "original provenance is preserved")

    def test_a_provider_failure_is_not_cached(self):
        """Caching an outage would turn one bad minute into a day of pretending the
        provider was consulted."""
        collector = CountingCollector(available=False, note="network error")
        self.planner(self.POLICY).collect(collector, domain("example.com"))
        self.now += 60
        self.planner(self.POLICY).collect(collector, domain("example.com"))
        self.assertEqual(collector.calls, 2)


class TestRateLimiting(PlannerTestCase):
    POLICY = ProviderPolicy(
        name=EXPENSIVE, cache_ttl_seconds=0, rate_per_minute=4, daily_quota=500
    )

    def _spend(self, planner, collector, n):
        for i in range(n):
            planner.collect(collector, domain(f"host{i}.example"))

    def test_the_rate_limit_is_respected_instead_of_discovered(self):
        """Delete the rate_per_minute branch in _budget_block and KRISIS goes back to
        finding the provider's limit by tripping it — which is what the live run did."""
        collector = CountingCollector()
        planner = self.planner(self.POLICY)
        self._spend(planner, collector, 4)

        result, decision = planner.collect(collector, domain("fifth.example"))

        self.assertEqual(collector.calls, 4, "the fifth request must not be sent")
        self.assertEqual(decision.action, "skipped")
        self.assertIn("rate limit", decision.reason)
        self.assertEqual(planner.usage_for(EXPENSIVE).skipped, 1)

    def test_the_window_frees_up_again(self):
        collector = CountingCollector()
        planner = self.planner(self.POLICY)
        self._spend(planner, collector, 4)
        self.now += 61
        _, decision = planner.collect(collector, domain("later.example"))
        self.assertEqual(decision.action, "queried")

    def test_the_ledger_survives_process_exit(self):
        """Rate accounting lives in the case database, so a second CLI invocation a
        second later cannot spend the same window again."""
        collector = CountingCollector()
        self._spend(self.planner(self.POLICY), collector, 4)

        _, decision = self.planner(self.POLICY).collect(collector, domain("next-run.example"))
        self.assertEqual(decision.action, "skipped")
        self.assertEqual(collector.calls, 4)

    def test_a_short_wait_may_be_taken_instead_of_skipping(self):
        policy = ProviderPolicy(
            name=EXPENSIVE, cache_ttl_seconds=0, rate_per_minute=4, max_wait_seconds=90
        )
        collector = CountingCollector()
        planner = self.planner(policy)
        self._spend(planner, collector, 4)

        _, decision = planner.collect(collector, domain("fifth.example"))
        self.assertEqual(decision.action, "queried")
        self.assertTrue(self.slept and 0 < self.slept[0] <= 60)

    def test_daily_budget_stops_further_requests(self):
        """Delete the daily_quota branch and a long session quietly consumes the whole
        day's allowance."""
        policy = ProviderPolicy(name=EXPENSIVE, cache_ttl_seconds=0, daily_quota=2)
        collector = CountingCollector()
        planner = self.planner(policy)
        self._spend(planner, collector, 2)

        _, decision = planner.collect(collector, domain("third.example"))
        self.assertEqual(decision.action, "skipped")
        self.assertIn("daily budget", decision.reason)

    def test_a_rate_limit_response_triggers_backoff(self):
        """Delete the backoff branch and KRISIS answers a 'slow down' by immediately
        asking again."""
        collector = CountingCollector(available=False, note="VirusTotal rate limit exceeded")
        policy = ProviderPolicy(name=EXPENSIVE, cache_ttl_seconds=0, backoff_seconds=300)
        planner = self.planner(policy)
        planner.collect(collector, domain("first.example"))

        self.now += 10
        _, decision = planner.collect(collector, domain("second.example"))

        self.assertEqual(collector.calls, 1)
        self.assertEqual(decision.action, "skipped")
        self.assertIn("backing off", decision.reason)
        self.assertEqual(planner.usage_for(EXPENSIVE).rate_limited, 1)


class TestValueGate(PlannerTestCase):
    POLICY = ProviderPolicy(
        name=EXPENSIVE, broad_enrichment=False, cache_ttl_seconds=0, min_pivot_priority=0.7
    )

    def test_the_seed_always_earns_a_request(self):
        collector = CountingCollector()
        _, decision = self.planner(self.POLICY).collect(collector, domain("asked-about.com"))
        self.assertEqual(decision.action, "queried")

    def test_a_weak_pivot_does_not_earn_a_scarce_request(self):
        """Delete _value_gate and every discovered subdomain buys itself a VirusTotal
        request again — the exact fan-out that exhausted the quota."""
        collector = CountingCollector()
        _, decision = self.planner(self.POLICY).collect(
            collector, domain("sandbox.asked-about.com", depth=1, priority=0.52)
        )
        self.assertEqual(collector.calls, 0)
        self.assertEqual(decision.action, "skipped")
        self.assertIn("value threshold", decision.reason)

    def test_a_strong_pivot_the_hypothesis_depends_on_does_earn_one(self):
        collector = CountingCollector()
        _, decision = self.planner(self.POLICY).collect(
            collector, domain("redirect-target.example", depth=1, priority=0.8, supports=True)
        )
        self.assertEqual(decision.action, "queried")

    def test_commodity_infrastructure_never_earns_one(self):
        collector = CountingCollector()
        _, decision = self.planner(self.POLICY).collect(
            collector,
            domain("outlook.com", depth=1, priority=0.9, supports=True, commodity=True),
        )
        self.assertEqual(collector.calls, 0)
        self.assertIn("commodity", decision.reason)

    def test_cheap_providers_still_enrich_everything(self):
        collector = CountingCollector(name="dns")
        _, decision = self.planner(ProviderPolicy(name="dns", cache_ttl_seconds=0)).collect(
            collector, domain("anything.example", depth=2, priority=0.1)
        )
        self.assertEqual(decision.action, "queried")


class TestSkippingIsNotAResult(PlannerTestCase):
    def test_a_skipped_request_reads_as_unavailable_not_clean(self):
        """The one rule that must never bend: a request KRISIS chose not to spend
        produces no evidence and available=False, exactly like a provider outage.
        Return available=True here and 'not asked' silently becomes 'nothing found'.
        """
        collector = CountingCollector()
        policy = ProviderPolicy(name=EXPENSIVE, broad_enrichment=False, cache_ttl_seconds=0)
        result, _ = self.planner(policy).collect(collector, domain("x.example", depth=1))

        self.assertFalse(result.available)
        self.assertEqual(result.evidence, [])
        self.assertTrue(result.note)

    def test_usage_summary_reports_what_was_and_was_not_spent(self):
        collector = CountingCollector()
        policy = ProviderPolicy(name=EXPENSIVE, broad_enrichment=False, cache_ttl_seconds=0)
        planner = self.planner(policy)
        planner.collect(collector, domain("seed.example"))
        planner.collect(collector, domain("weak.example", depth=1))

        summary = planner.usage_summary()[EXPENSIVE]
        self.assertEqual(summary["calls"], 1)
        self.assertEqual(summary["skipped"], 1)
        self.assertTrue(summary["skip_reasons"], "a skipped request must say why")


if __name__ == "__main__":
    unittest.main()
