"""
EntityGraph — the relationship graph for a single investigation.

This is not decoration (see RELATIONSHIP GRAPH in the design doc). The pivot
engine, correlation engine, and CLI --show-graph view all read directly from
this structure. It answers "why did KRISIS connect these two things?" by
keeping the Relationship.reason and evidence_ids attached to every edge.
"""

from __future__ import annotations

import io
from collections import defaultdict
from typing import Iterable, Optional

from .models import Entity, EntityType, Relationship

# Fixed categorical order (dataviz skill palette) so an entity type always maps
# to the same color across every render, regardless of what else is in frame.
# Types past the 8th fold into _OTHER_COLOR rather than cycling the palette.
_NODE_PALETTE = [
    "#2a78d6", "#eb6834", "#1baf7a", "#eda100",
    "#e87ba4", "#008300", "#4a3aa7", "#e34948",
]
_OTHER_COLOR = "#898781"
_EDGE_COLOR = "#c3c2b7"
_INK = "#0b0b0b"
_MUTED_INK = "#52514e"
_SURFACE = "#fcfcfb"


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

    @classmethod
    def from_dict(cls, data: dict) -> "EntityGraph":
        """Rebuild a graph from a stored Case dict (same shape as to_dict()).

        Used for case replay (`krisis show --show-graph`), where the graph
        itself is never persisted separately — only the entities and
        relationships a live investigation already stores on the Case.
        """
        graph = cls()
        for e in data.get("entities", []):
            graph.add_entity(Entity(
                value=e["value"], type=EntityType(e["type"]), id=e["id"],
                first_seen=e.get("first_seen", ""), depth=e.get("depth", 0),
                metadata=e.get("metadata") or {},
                shared_infrastructure=e.get("shared_infrastructure", False),
            ))
        for r in data.get("relationships", []):
            graph.add_relationship(Relationship(
                source_entity_id=r["source_entity_id"], target_entity_id=r["target_entity_id"],
                relation_type=r["relation_type"], reason=r["reason"], id=r["id"],
                evidence_ids=r.get("evidence_ids") or [], weight=r.get("weight", 0.5),
                created_at=r.get("created_at", ""),
            ))
        return graph

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

    def to_image(self, root_id: Optional[str] = None) -> io.BytesIO:
        """Render an actual node-link diagram (boxes + labeled arrows) via matplotlib.

        Uses the same layered, depth-based layout as to_ascii() — one row per
        depth, same traversal order — just drawn instead of indented. Returns a
        PNG in a BytesIO buffer (embeddable directly in the PDF report, or
        written to disk by the caller).
        """
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            from matplotlib.lines import Line2D
            from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
        except ImportError as exc:
            raise RuntimeError("matplotlib is required to render a graph image; pip install matplotlib") from exc

        roots = [root_id] if root_id else [
            e.id for e in self._entities.values() if e.depth == 0
        ]
        if not roots:
            roots = list(self._entities.keys())[:1]

        rows: dict[int, list[str]] = defaultdict(list)
        edges: list[tuple[str, str, str]] = []
        visited: set[str] = set()

        def walk(eid: str, depth: int) -> None:
            if eid in visited or eid not in self._entities:
                return
            visited.add(eid)
            rows[depth].append(eid)
            for rel_id in self._out_edges.get(eid, []):
                rel = self._relationships[rel_id]
                target_id = rel.target_entity_id
                if target_id not in visited and target_id in self._entities:
                    edges.append((eid, target_id, rel.relation_type))
                    walk(target_id, depth + 1)

        for r in roots:
            walk(r, 0)

        buf = io.BytesIO()
        if not visited:
            fig, ax = plt.subplots(figsize=(6, 1.6))
            ax.text(0.5, 0.5, "(empty graph)", ha="center", va="center", fontsize=12, color=_MUTED_INK)
            ax.axis("off")
            fig.savefig(buf, format="png", dpi=150, facecolor=_SURFACE)
            plt.close(fig)
            buf.seek(0)
            return buf

        # Uniform 1-unit spacing between siblings in every row (centered under
        # the widest row) — a fixed slot count/(n+1) spacing compresses a
        # near-full row until its node boxes touch.
        max_width = max(len(ids) for ids in rows.values())
        positions: dict[str, tuple[float, float]] = {}
        for depth, ids in rows.items():
            offset = (max_width - len(ids)) / 2
            for i, eid in enumerate(ids):
                positions[eid] = (offset + i + 1, -depth)

        n_rows = max(rows.keys()) + 1
        fig_w = min(28, max(6, max_width * 1.6))
        fig_h = min(20, max(3.2, n_rows * 1.7))
        fig, ax = plt.subplots(figsize=(fig_w, fig_h))
        # Transparent figure background, opaque axes background: the axes patch
        # only spans the tight ylim set below, so savefig(bbox_inches="tight")
        # crops to that plus the legend — a painted *figure* background would
        # cover the whole canvas and defeat that crop, leaving dead margin.
        fig.patch.set_alpha(0)
        ax.set_facecolor(_SURFACE)

        # Keyed and ordered by EntityType's own declared order (not the visited
        # set's arbitrary iteration order), so the legend lists types the same
        # way on every render.
        node_color: dict[EntityType, str] = {}
        for etype in EntityType:
            slot = list(EntityType).index(etype)
            if any(self._entities[eid].type == etype for eid in visited):
                node_color[etype] = _NODE_PALETTE[slot] if slot < len(_NODE_PALETTE) else _OTHER_COLOR

        # occam: edge labels are placed by a fixed offset, not true collision
        # avoidance — two same-named relations fanning from one parent to close
        # siblings can still overlap. Upgrade to adjustText (or similar) if dense
        # fan-out graphs make this common in practice.
        for parent, child, relation in edges:
            x1, y1 = positions[parent]
            x2, y2 = positions[child]
            ax.add_patch(FancyArrowPatch(
                (x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=12,
                color=_EDGE_COLOR, linewidth=1.4, zorder=1,
                connectionstyle="arc3,rad=0.08", shrinkA=18, shrinkB=18,
            ))
            # Placed 62% of the way to the child rather than at the midpoint: near a
            # parent with several children, sibling edges have barely fanned apart at
            # the midpoint, so labels there collide.
            t = 0.62
            mx, my = x1 + (x2 - x1) * t, y1 + (y2 - y1) * t
            ax.text(mx, my, relation, fontsize=7, color=_MUTED_INK, ha="center", va="center",
                    bbox=dict(boxstyle="round,pad=0.15", fc=_SURFACE, ec="none"), zorder=2)

        for eid in visited:
            entity = self._entities[eid]
            x, y = positions[eid]
            color = node_color[entity.type]
            label = entity.value if len(entity.value) <= 22 else entity.value[:19] + "..."
            ax.add_patch(FancyBboxPatch(
                (x - 0.42, y - 0.16), 0.84, 0.32,
                boxstyle="round,pad=0.02,rounding_size=0.06",
                linewidth=1.4, edgecolor=color, facecolor="white", zorder=3,
            ))
            ax.text(x, y + 0.055, entity.type.value, fontsize=7, color=color, weight="bold",
                    ha="center", va="center", zorder=4)
            ax.text(x, y - 0.075, label, fontsize=8, color=_INK, ha="center", va="center", zorder=4)

        legend_handles = [
            Line2D([0], [0], marker="s", linestyle="", markersize=10,
                   markerfacecolor="white", markeredgecolor=color, markeredgewidth=1.6, label=etype.value)
            for etype, color in node_color.items()
        ]
        # Figure-level (not axes-level) legend, anchored above the axes box rather
        # than inside its data range — otherwise the y-limits need dead space
        # reserved above row 0 just to give the legend somewhere to sit.
        legend = fig.legend(handles=legend_handles, loc="upper center", bbox_to_anchor=(0.5, 1.02),
                             ncol=min(len(legend_handles), 6), frameon=False, fontsize=8)

        # Padded tightly to the node boxes, not just given round numbers: the axes
        # facecolor rectangle paints its full ylim span, so any extra padding here
        # shows up as literal dead space above/below the graph in the saved PNG.
        ax.set_xlim(-0.5, max_width + 0.5)
        ax.set_ylim(-(n_rows - 1) - 0.24, 0.24)
        ax.axis("off")
        fig.savefig(buf, format="png", dpi=150, transparent=True,
                    bbox_inches="tight", bbox_extra_artists=[legend])
        plt.close(fig)
        buf.seek(0)
        return buf
