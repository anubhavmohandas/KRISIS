import builtins
import importlib.util
import unittest

from krisis.core.graph import EntityGraph
from krisis.core.models import Entity, EntityType, Relationship

_HAS_MATPLOTLIB = importlib.util.find_spec("matplotlib") is not None


class TestEntityGraph(unittest.TestCase):
    def test_dedup_by_key(self):
        graph = EntityGraph()
        e1 = graph.add_entity(Entity(value="xyz.com", type=EntityType.DOMAIN, depth=0))
        e2 = graph.add_entity(Entity(value="XYZ.com", type=EntityType.DOMAIN, depth=1))
        self.assertEqual(e1.id, e2.id)
        self.assertEqual(graph.entity_count(), 1)
        # depth should keep the shallower value
        self.assertEqual(graph.get_entity(e1.id).depth, 0)

    def test_relationship_and_neighbors(self):
        graph = EntityGraph()
        domain = graph.add_entity(Entity(value="xyz.com", type=EntityType.DOMAIN, depth=0))
        ip = graph.add_entity(Entity(value="185.10.10.20", type=EntityType.IP, depth=1))
        rel = graph.add_relationship(
            Relationship(
                source_entity_id=domain.id,
                target_entity_id=ip.id,
                relation_type="resolves_to",
                reason="domain resolves to this IP",
            )
        )
        neighbors = graph.neighbors(domain.id)
        self.assertEqual(len(neighbors), 1)
        neighbor_entity, neighbor_rel = neighbors[0]
        self.assertEqual(neighbor_entity.id, ip.id)
        self.assertEqual(neighbor_rel.id, rel.id)

    def test_entities_shared_via(self):
        graph = EntityGraph()
        d1 = graph.add_entity(Entity(value="a.com", type=EntityType.DOMAIN, depth=0))
        d2 = graph.add_entity(Entity(value="b.com", type=EntityType.DOMAIN, depth=0))
        cert = graph.add_entity(Entity(value="ABC123", type=EntityType.CERTIFICATE, depth=1))
        graph.add_relationship(
            Relationship(source_entity_id=d1.id, target_entity_id=cert.id, relation_type="secured_by", reason="cert seen")
        )
        graph.add_relationship(
            Relationship(source_entity_id=d2.id, target_entity_id=cert.id, relation_type="secured_by", reason="cert seen")
        )
        groups = graph.entities_shared_via("secured_by")
        self.assertEqual(len(groups), 2)  # keyed by source

    def test_to_ascii_does_not_crash_on_empty_graph(self):
        graph = EntityGraph()
        self.assertEqual(graph.to_ascii(), "(empty graph)")

    def test_to_ascii_renders_root_and_child(self):
        graph = EntityGraph()
        domain = graph.add_entity(Entity(value="xyz.com", type=EntityType.DOMAIN, depth=0))
        ip = graph.add_entity(Entity(value="185.10.10.20", type=EntityType.IP, depth=1))
        graph.add_relationship(
            Relationship(source_entity_id=domain.id, target_entity_id=ip.id, relation_type="resolves_to", reason="A record")
        )
        ascii_graph = graph.to_ascii()
        self.assertIn("xyz.com", ascii_graph)
        self.assertIn("185.10.10.20", ascii_graph)

    @unittest.skipUnless(_HAS_MATPLOTLIB, "matplotlib not installed")
    def test_to_image_renders_a_png(self):
        graph = EntityGraph()
        domain = graph.add_entity(Entity(value="xyz.com", type=EntityType.DOMAIN, depth=0))
        ip = graph.add_entity(Entity(value="185.10.10.20", type=EntityType.IP, depth=1))
        graph.add_relationship(
            Relationship(source_entity_id=domain.id, target_entity_id=ip.id, relation_type="resolves_to", reason="A record")
        )
        png = graph.to_image().getvalue()
        self.assertTrue(png.startswith(b"\x89PNG\r\n\x1a\n"))

    @unittest.skipUnless(_HAS_MATPLOTLIB, "matplotlib not installed")
    def test_to_image_does_not_crash_on_empty_graph(self):
        png = EntityGraph().to_image().getvalue()
        self.assertTrue(png.startswith(b"\x89PNG\r\n\x1a\n"))

    def test_to_image_without_matplotlib_raises_a_clear_error(self):
        real_import = builtins.__import__

        def blocked(name, *args, **kwargs):
            if name == "matplotlib":
                raise ImportError("simulated missing matplotlib")
            return real_import(name, *args, **kwargs)

        graph = EntityGraph()
        graph.add_entity(Entity(value="xyz.com", type=EntityType.DOMAIN, depth=0))
        builtins.__import__ = blocked
        try:
            with self.assertRaises(RuntimeError):
                graph.to_image()
        finally:
            builtins.__import__ = real_import


if __name__ == "__main__":
    unittest.main()
