"""
EntityGraph — the relationship graph for a single investigation.

This is not decoration (see RELATIONSHIP GRAPH in the design doc). The pivot
engine, correlation engine, and CLI --show-graph view all read directly from
this structure. It answers "why did KRISIS connect these two things?" by
keeping the Relationship.reason and evidence_ids attached to every edge.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Optional

from .models import Entity, EntityType, Relationship


class EntityGraph:
    def __init__(self) -> None:
        self._entities: dict[str, Entity] = {}          # id -> Entity
        self._by_key: dict[str, str] = {}                # (type:value) -> id, for dedup
        self._relationships: dict[str, Relationship] = {}
        self._out_edges: dict[str, list[str]] = defaultdict(list)   # entity_id -> [rel_id]
        self._in_edges: dict[str, list[str]] = defaultdict(list)

    # -- entities ---------------------------------------------------------

    def add_entity(self, entity: Entity) -> Entity:
        """Add an entity, or return the existing one if already present (dedup by key)."""
        key = entity.key()
        existing_id = self._by_key.get(key)
        if existing_id:
            existing = self._entities[existing_id]
            # keep the shallower depth if we rediscover the same entity via a shorter path
            existing.depth = min(existing.depth, entity.depth)
            # If the same entity is also reachable by a route that is *not* commodity
            # infrastructure, that genuine relationship wins — an IP first seen behind a
            # shared mail provider still matters if the target also resolves to it directly.
            if not entity.shared_infrastructure:
                existing.shared_infrastructure = False
            return existing
        self._entities[entity.id] = entity
        self._by_key[key] = entity.id
        return entity

    def get_entity(self, entity_id: str) -> Optional[Entity]:
        return self._entities.get(entity_id)

    def find_entity(self, value: str, entity_type: EntityType) -> Optional[Entity]:
        key = f"{entity_type.value}:{value.lower()}"
        eid = self._by_key.get(key)
        return self._entities.get(eid) if eid else None

    def entities(self) -> Iterable[Entity]:
        return self._entities.values()

    def entity_count(self) -> int:
        return len(self._entities)

    # -- relationships ------------------------------------------------------

    def add_relationship(self, relationship: Relationship) -> Relationship:
        self._relationships[relationship.id] = relationship
        self._out_edges[relationship.source_entity_id].append(relationship.id)
        self._in_edges[relationship.target_entity_id].append(relationship.id)
        return relationship

    def relationships(self) -> Iterable[Relationship]:
        return self._relationships.values()

    def neighbors(self, entity_id: str) -> list[tuple[Entity, Relationship]]:
        """All entities directly connected to entity_id, either direction."""
        result = []
        for rel_id in self._out_edges.get(entity_id, []):
            rel = self._relationships[rel_id]
            target = self._entities.get(rel.target_entity_id)
            if target:
                result.append((target, rel))
        for rel_id in self._in_edges.get(entity_id, []):
            rel = self._relationships[rel_id]
            source = self._entities.get(rel.source_entity_id)
            if source:
                result.append((source, rel))
        return result

    def relationships_for(self, entity_id: str) -> list[Relationship]:
        ids = self._out_edges.get(entity_id, []) + self._in_edges.get(entity_id, [])
        return [self._relationships[i] for i in ids]

    def entities_shared_via(self, relation_type: str) -> dict[str, list[Entity]]:
        """Group target entities by source, for a given relation type.

        Useful for asking things like "which domains share this certificate".
        """
        groups: dict[str, list[Entity]] = defaultdict(list)
        for rel in self._relationships.values():
            if rel.relation_type == relation_type:
                target = self._entities.get(rel.target_entity_id)
                if target:
                    groups[rel.source_entity_id].append(target)
        return groups

    # -- inspection ---------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "entities": [e.to_dict() for e in self._entities.values()],
            "relationships": [r.to_dict() for r in self._relationships.values()],
        }

    def to_ascii(self, root_id: Optional[str] = None, max_lines: int = 200) -> str:
        """Render a simple indented ASCII tree starting from root_id (or any depth-0 entity)."""
        lines: list[str] = []
        visited: set[str] = set()

        roots = [root_id] if root_id else [
            e.id for e in self._entities.values() if e.depth == 0
        ]
        if not roots:
            roots = list(self._entities.keys())[:1]

        def walk(eid: str, prefix: str, is_last: bool, depth: int) -> None:
            if eid in visited or len(lines) >= max_lines:
                return
            visited.add(eid)
            entity = self._entities.get(eid)
            if not entity:
                return
            connector = "" if depth == 0 else ("`-- " if is_last else "|-- ")
            lines.append(f"{prefix}{connector}[{entity.type.value}] {entity.value}")
            child_prefix = prefix if depth == 0 else prefix + ("    " if is_last else "|   ")

            children = []
            for rel_id in self._out_edges.get(eid, []):
                rel = self._relationships[rel_id]
                if rel.target_entity_id not in visited:
                    children.append(rel)
            for i, rel in enumerate(children):
                target = self._entities.get(rel.target_entity_id)
                if not target:
                    continue
                last = i == len(children) - 1
                lines.append(f"{child_prefix}{'`-- ' if last else '|-- '}({rel.relation_type}: {rel.reason})")
                walk(rel.target_entity_id, child_prefix + ("    " if last else "|   "), True, depth + 1)

        for r in roots:
            walk(r, "", True, 0)

        return "\n".join(lines) if lines else "(empty graph)"
