import unittest

from krisis.core.correlation import CorrelationEngine
from krisis.core.graph import EntityGraph
from krisis.core.models import (
    Entity,
    EntityType,
    Evidence,
    Independence,
    Polarity,
    Relationship,
)


class TestCorrelationEngine(unittest.TestCase):
    def test_splits_evidence_by_polarity(self):
        entity = Entity(value="xyz.com", type=EntityType.DOMAIN)
        evidence = [
            Evidence(source="vt", entity_id=entity.id, signal="malicious_detection", value="5/70",
                      evidence_type="reputation", polarity=Polarity.SUPPORTS_THREAT),
            Evidence(source="tls", entity_id=entity.id, signal="valid_tls_present", value="Org",
                      evidence_type="infrastructure", polarity=Polarity.CONTRADICTS_THREAT),
            Evidence(source="whois", entity_id=entity.id, signal="registrar", value="Namecheap",
                      evidence_type="registration", polarity=Polarity.NEUTRAL),
        ]
        engine = CorrelationEngine()
        result = engine.correlate(EntityGraph(), evidence)
        self.assertEqual(len(result.supporting), 1)
        self.assertEqual(len(result.contradicting), 1)
        self.assertEqual(len(result.neutral), 1)

    def test_infrastructure_overlap_detected(self):
        graph = EntityGraph()
        d1 = graph.add_entity(Entity(value="a.com", type=EntityType.DOMAIN, depth=0))
        d2 = graph.add_entity(Entity(value="b.com", type=EntityType.DOMAIN, depth=0))
        ip = graph.add_entity(Entity(value="1.2.3.4", type=EntityType.IP, depth=1))
        graph.add_relationship(Relationship(source_entity_id=d1.id, target_entity_id=ip.id,
                                             relation_type="resolves_to", reason="A record"))
        graph.add_relationship(Relationship(source_entity_id=d2.id, target_entity_id=ip.id,
                                             relation_type="resolves_to", reason="A record"))
        engine = CorrelationEngine()
        result = engine.correlate(graph, [])
        self.assertTrue(any("1.2.3.4" in note for note in result.infrastructure_overlap))

    def test_evidence_diversity_penalizes_single_source(self):
        entity = Entity(value="xyz.com", type=EntityType.DOMAIN)
        single_source = [
            Evidence(source="vt", entity_id=entity.id, signal="a", value=1, evidence_type="reputation",
                      independence=Independence.INDEPENDENT),
            Evidence(source="vt", entity_id=entity.id, signal="b", value=2, evidence_type="reputation",
                      independence=Independence.INDEPENDENT),
        ]
        multi_source = [
            Evidence(source="vt", entity_id=entity.id, signal="a", value=1, evidence_type="reputation",
                      independence=Independence.INDEPENDENT),
            Evidence(source="dns", entity_id=entity.id, signal="b", value=2, evidence_type="infrastructure",
                      independence=Independence.INDEPENDENT),
        ]
        engine = CorrelationEngine()
        single_result = engine.correlate(EntityGraph(), single_source)
        multi_result = engine.correlate(EntityGraph(), multi_source)
        self.assertLess(single_result.evidence_diversity, multi_result.evidence_diversity)

    def test_pattern_memory_failure_does_not_crash_correlation(self):
        class BrokenPatternMemory:
            def find_similar(self, graph, evidence):
                raise RuntimeError("boom")

        engine = CorrelationEngine(pattern_memory=BrokenPatternMemory())
        result = engine.correlate(EntityGraph(), [])
        self.assertEqual(result.pattern_matches, [])


if __name__ == "__main__":
    unittest.main()
