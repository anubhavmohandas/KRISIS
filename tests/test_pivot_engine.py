import unittest

from krisis.core.models import Entity, EntityType, Evidence, Independence, Polarity
from krisis.core.pivot_engine import InvestigationBudget, PivotEngine


class TestPivotEngine(unittest.TestCase):
    def setUp(self):
        self.entity = Entity(value="xyz.com", type=EntityType.DOMAIN, depth=0)

    def test_generates_pivot_from_a_record(self):
        engine = PivotEngine()
        evidence = [
            Evidence(
                source="dns", entity_id=self.entity.id, signal="a_record",
                value=["185.10.10.20"], evidence_type="infrastructure",
            )
        ]
        pivots = engine.generate(self.entity, evidence)
        self.assertEqual(len(pivots), 1)
        self.assertEqual(pivots[0].entity_value, "185.10.10.20")
        self.assertEqual(pivots[0].entity_type, EntityType.IP)

    def test_certificate_pivot_scores_higher_than_ns_pivot(self):
        engine = PivotEngine()
        evidence = [
            Evidence(source="tls", entity_id=self.entity.id, signal="certificate_fingerprint",
                      value="ABC123", evidence_type="infrastructure", confidence=0.85),
            Evidence(source="dns", entity_id=self.entity.id, signal="ns_record",
                      value=["ns1.example.net"], evidence_type="infrastructure", confidence=0.9),
        ]
        pivots = engine.generate(self.entity, evidence)
        cert_pivot = next(p for p in pivots if p.entity_type == EntityType.CERTIFICATE)
        ns_pivot = next(p for p in pivots if p.entity_type == EntityType.NAMESERVER)
        self.assertGreater(cert_pivot.priority, ns_pivot.priority)

    def test_supports_threat_evidence_boosts_priority(self):
        engine = PivotEngine()
        base_evidence = Evidence(
            source="virustotal", entity_id=self.entity.id, signal="vt_related_domain",
            value="evil.com", evidence_type="infrastructure", confidence=0.6,
        )
        threat_evidence = Evidence(
            source="virustotal", entity_id=self.entity.id, signal="vt_related_domain",
            value="evil.com", evidence_type="infrastructure", confidence=0.6,
            polarity=Polarity.SUPPORTS_THREAT,
        )
        neutral_pivots = engine.generate(self.entity, [base_evidence])
        threat_pivots = engine.generate(self.entity, [threat_evidence])
        self.assertGreater(threat_pivots[0].priority, neutral_pivots[0].priority)

    def test_depth_budget_rejects_pivot_beyond_max_depth(self):
        budget = InvestigationBudget(max_depth=1)
        engine = PivotEngine(budget)
        deep_entity = Entity(value="deep.com", type=EntityType.DOMAIN, depth=1)
        evidence = [Evidence(source="dns", entity_id=deep_entity.id, signal="a_record",
                              value=["1.2.3.4"], evidence_type="infrastructure")]
        pivot = engine.generate(deep_entity, evidence)[0]  # depth becomes 2
        pivot = engine.accept_or_reject(pivot, current_depth_count=1)
        self.assertEqual(pivot.status, "rejected")
        self.assertIn("max_depth", pivot.rejection_reason)

    def test_entity_budget_exhaustion_rejects_pivot(self):
        budget = InvestigationBudget(max_entities=1)
        budget.register_entity()  # simulate the budget already being spent
        engine = PivotEngine(budget)
        evidence = [Evidence(source="dns", entity_id=self.entity.id, signal="a_record",
                              value=["1.2.3.4"], evidence_type="infrastructure")]
        pivot = engine.generate(self.entity, evidence)[0]
        pivot = engine.accept_or_reject(pivot, current_depth_count=0)
        self.assertEqual(pivot.status, "rejected")
        self.assertIn("entity budget", pivot.rejection_reason)

    def test_max_pivots_per_entity_enforced(self):
        budget = InvestigationBudget(max_pivots_per_entity=1)
        engine = PivotEngine(budget)
        evidence = [
            Evidence(source="dns", entity_id=self.entity.id, signal="a_record",
                      value=["1.1.1.1"], evidence_type="infrastructure"),
            Evidence(source="virustotal", entity_id=self.entity.id, signal="vt_communicating_ip",
                      value="2.2.2.2", evidence_type="infrastructure"),
        ]
        pivots = engine.generate(self.entity, evidence)
        results = [engine.accept_or_reject(p, current_depth_count=0) for p in pivots]
        accepted = [p for p in results if p.status == "accepted"]
        rejected = [p for p in results if p.status == "rejected"]
        self.assertEqual(len(accepted), 1)
        self.assertGreaterEqual(len(rejected), 1)

    def test_noisy_fanout_penalized(self):
        engine = PivotEngine()
        evidence = [Evidence(source="dns", entity_id=self.entity.id, signal="ns_record",
                              value=["shared-ns.example.net"], evidence_type="infrastructure")]
        pivots = engine.generate(self.entity, evidence)
        before = pivots[0].priority
        engine.penalize_noisy_fanout(pivots, fanout_counts={"shared-ns.example.net": 5000})
        self.assertLess(pivots[0].priority, before)


if __name__ == "__main__":
    unittest.main()
