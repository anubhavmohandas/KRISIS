"""
Correlation Engine — the heart of KRISIS (see CORRELATION ENGINE in the design doc).

Does NOT sum provider scores. It looks at how evidence and relationships
reinforce or contradict each other, folds in historical pattern similarity,
and produces the supporting/contradicting evidence sets the Risk Engine
consumes. The correlation engine never itself outputs a final score — that is
the Risk Engine's job, kept separate so the score stays deterministic and
inspectable.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Optional

from .graph import EntityGraph
from .models import Evidence, Polarity


@dataclass
class CorrelationResult:
    supporting: list[Evidence] = field(default_factory=list)
    contradicting: list[Evidence] = field(default_factory=list)
    neutral: list[Evidence] = field(default_factory=list)
    infrastructure_overlap: list[str] = field(default_factory=list)   # human-readable notes
    evidence_diversity: float = 0.0     # 0..1, distinct independent sources / total sources
    pattern_matches: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "supporting_count": len(self.supporting),
            "contradicting_count": len(self.contradicting),
            "neutral_count": len(self.neutral),
            "infrastructure_overlap": self.infrastructure_overlap,
            "evidence_diversity": round(self.evidence_diversity, 3),
            "pattern_matches": self.pattern_matches,
        }


class CorrelationEngine:
    def __init__(self, pattern_memory: Optional[Any] = None) -> None:
        """pattern_memory: object with .find_similar(graph, evidence) -> list[dict], optional."""
        self.pattern_memory = pattern_memory

    def correlate(self, graph: EntityGraph, evidence: list[Evidence]) -> CorrelationResult:
        result = CorrelationResult()

        for ev in evidence:
            if ev.polarity == Polarity.SUPPORTS_THREAT:
                result.supporting.append(ev)
            elif ev.polarity == Polarity.CONTRADICTS_THREAT:
                result.contradicting.append(ev)
            else:
                result.neutral.append(ev)

        result.infrastructure_overlap = self._infrastructure_overlap(graph)
        result.evidence_diversity = self._evidence_diversity(evidence)

        if self.pattern_memory is not None:
            try:
                result.pattern_matches = self.pattern_memory.find_similar(graph, evidence)
            except Exception:
                # Pattern memory is an enhancement, never a hard dependency.
                result.pattern_matches = []

        return result

    def _infrastructure_overlap(self, graph: EntityGraph) -> list[str]:
        """Flag relation types where a single target is shared by multiple distinct sources
        within this case's own graph — e.g. two subdomains landing on the same IP or cert.
        """
        notes: list[str] = []
        by_relation: dict[str, Counter] = {}
        for rel in graph.relationships():
            by_relation.setdefault(rel.relation_type, Counter())[rel.target_entity_id] += 1

        for relation_type, counter in by_relation.items():
            for target_id, count in counter.items():
                if count > 1:
                    target = graph.get_entity(target_id)
                    if target:
                        notes.append(
                            f"{count} entities connected to {target.type.value} "
                            f"'{target.value}' via {relation_type}"
                        )
        return notes

    def _evidence_diversity(self, evidence: list[Evidence]) -> float:
        """0..1. Rewards having several distinct *independent* sources (saturates at 3 —
        see EVIDENCE INDEPENDENCE: quality/diversity should matter more than raw count),
        and lightly penalizes when a large share of evidence is derived/duplicate rather
        than independently observed.
        """
        if not evidence:
            return 0.0
        all_sources = {e.source for e in evidence}
        independent_sources = {e.source for e in evidence if e.independence.value == "independent"}

        saturation = 3.0
        base = min(1.0, len(independent_sources) / saturation)

        non_independent_share = 1 - (len(independent_sources) / max(1, len(all_sources)))
        return round(max(0.0, base * (1 - 0.3 * non_independent_share)), 3)
