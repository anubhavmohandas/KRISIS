"""
Pattern memory — historical pattern matching against prior investigations.

Implementation approach (see PATTERN SIMILARITY in the design doc: "Do not
force a vector database simply because it is fashionable"):

This is **structured indicator overlap matching**, not embedding similarity.
For every distinguishing entity discovered in the current investigation
(certificates, IPs, and pivoted-to domains), we look up whether that exact
indicator value was ever seen in a previously stored case, and weight the
match by how distinguishing that indicator type is:

    certificate fingerprint  -> weight 0.9  (very unlikely to collide by chance)
    IP address                -> weight 0.5  (hosting is reused, less distinguishing)
    pivoted-to domain          -> weight 0.3  (weakest signal alone)

A case's similarity score is the sum of matched weights divided by the total
possible weight of indicators we checked. This is a defensible, explainable
first-pass approximation — it will produce false negatives for infrastructure
that has rotated indicators entirely, and it cannot detect similarity in
*structure* (e.g. "the same phishing kit template") without a matching
indicator. That is an explicit, documented limitation, not a hidden one.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from ..core.graph import EntityGraph
from ..core.models import Evidence
from .storage import Storage

INDICATOR_WEIGHTS = {
    "certificate": 0.9,
    "ip": 0.5,
    "domain": 0.3,
    "hostname": 0.25,
    "email": 0.4,
    "asn": 0.15,
}

MIN_SIMILARITY_TO_REPORT = 0.15


class PatternMemory:
    def __init__(self, storage: Storage):
        self.storage = storage

    def find_similar(self, graph: EntityGraph, evidence: list[Evidence]) -> list[dict[str, Any]]:
        candidates: list[tuple[str, str, float]] = []
        for entity in graph.entities():
            weight = INDICATOR_WEIGHTS.get(entity.type.value)
            if weight is None:
                continue
            # depth-0 (the seed itself) is excluded — matching on the seed domain
            # itself would trivially "match" a re-investigation of the same domain,
            # not a genuine infrastructure resemblance.
            if entity.depth == 0 and entity.type.value == "domain":
                continue
            candidates.append((entity.type.value, entity.value, weight))

        if not candidates:
            return []

        total_possible_weight = sum(w for _, _, w in candidates)
        matches_by_case: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"weight": 0.0, "indicators": [], "outcome": None, "seed": None}
        )

        for entity_type, value, weight in candidates:
            rows = self.storage.find_indicator_matches(entity_type, value)
            for row in rows:
                case_id = row["case_id"]
                info = matches_by_case[case_id]
                info["weight"] += weight
                info["indicators"].append(f"{entity_type}:{value}")
                info["outcome"] = row.get("outcome") or info["outcome"]
                info["seed"] = row.get("seed")

        results = []
        for case_id, info in matches_by_case.items():
            similarity = min(1.0, info["weight"] / total_possible_weight) if total_possible_weight else 0.0
            if similarity < MIN_SIMILARITY_TO_REPORT:
                continue
            results.append(
                {
                    "pattern_id": case_id,
                    "pattern_name": (
                        f"infrastructure overlap with prior case for '{info['seed']}'"
                        if info["seed"] else f"infrastructure overlap with case {case_id}"
                    ),
                    "similarity": round(similarity, 3),
                    "matched_indicators": info["indicators"],
                    "prior_outcome": info["outcome"],
                }
            )

        results.sort(key=lambda r: r["similarity"], reverse=True)
        return results[:5]

    def record_case(self, case) -> None:
        """Feed every entity from a completed investigation into indicator memory
        so future investigations can match against it (see LEARNING LOOP)."""
        now = datetime.now(timezone.utc).isoformat()
        risk_category = case.risk.category.value if case.risk else None
        for entity in case.entities.values():
            self.storage.record_indicator(
                case_id=case.id,
                entity_type=entity.type.value,
                value=entity.value,
                seed=case.seed,
                outcome=case.outcome,
                risk_category=risk_category,
                created_at=now,
            )

    def apply_outcome(self, case_id: str, outcome: str) -> None:
        """Update indicator memory + any matched patterns when a case is confirmed
        or marked a false positive (see LEARNING / CLOSED-LOOP LEARNING)."""
        self.storage.set_outcome(case_id, outcome)
