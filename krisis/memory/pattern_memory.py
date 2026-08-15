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

import hashlib
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from ..core.graph import EntityGraph
from ..core.models import Evidence, Outcome, Polarity
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

    def find_similar(
        self, graph: EntityGraph, evidence: list[Evidence], exclude_seed: str | None = None
    ) -> list[dict[str, Any]]:
        """exclude_seed: the artifact currently under investigation. Prior cases seeded
        on that same artifact are excluded, otherwise re-running an investigation
        reports the domain as resembling *itself* — a self-confirming match that
        would let repeated scans manufacture a historical pattern out of nothing."""
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
            # Commodity infrastructure is not a distinguishing indicator. Two unrelated
            # companies sharing a mail vendor's IPs is a fact about the vendor, and
            # matching on it reports them as the same infrastructure cluster.
            if entity.shared_infrastructure:
                continue
            candidates.append((entity.type.value, entity.value, weight))

        if not candidates:
            return []

        total_possible_weight = sum(w for _, _, w in candidates)
        matches_by_case: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"weight": 0.0, "indicators": [], "outcome": None, "seed": None}
        )

        for entity_type, value, weight in candidates:
            rows = self.storage.find_indicator_matches(entity_type, value, exclude_seed=exclude_seed)
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
                    # An un-validated prior case must not masquerade as intelligence.
                    # Downstream scoring weights this explicitly (see risk.OUTCOME_TRUST).
                    "prior_outcome": info["outcome"] or Outcome.UNKNOWN.value,
                }
            )

        results.sort(key=lambda r: r["similarity"], reverse=True)
        return results[:5]

    # -- pattern lifecycle -----------------------------------------------------

    def signature_for(self, case) -> tuple[str, list[str]]:
        """A case's pattern signature: the sorted set of threat-supporting signal
        types it exhibited, e.g. {registration:new_domain, identity:brand_lookalike}.

        This is what generalizes across cases — the recurring *shape* of a case
        rather than its specific indicator values, which is why it lives separately
        from indicator memory.
        """
        signals = sorted(
            {
                f"{ev.evidence_type}:{ev.signal}"
                for ev in case.evidence.values()
                if ev.polarity == Polarity.SUPPORTS_THREAT
            }
        )
        digest = hashlib.sha256("|".join(signals).encode()).hexdigest()[:12]
        return f"pat_{digest}", signals

    @staticmethod
    def stage_for(pattern: dict[str, Any]) -> str:
        """Lifecycle stage, derived from counts rather than stored, so it can never
        drift out of sync with the evidence behind it (see PATTERN LIFECYCLE).

        Only human-validated outcomes can push a pattern past 'repeated'. Repetition
        alone proves KRISIS keeps seeing something, not that it keeps being right.
        """
        confirmed = pattern.get("confirmed_count") or 0
        false_positives = pattern.get("false_positive_count") or 0
        observed = pattern.get("observed_count") or 0

        if false_positives >= 2 and false_positives > confirmed:
            return "deprecated"
        if confirmed >= 3 and false_positives == 0:
            return "trusted"
        if confirmed >= 1:
            return "validated"
        if observed >= 3:
            return "repeated"
        if observed >= 2:
            return "candidate"
        return "observed"

    def record_case(self, case) -> None:
        """Feed a completed investigation into institutional memory: every entity into
        indicator memory, and the case's signal shape into pattern memory (see LEARNING
        LOOP). Both are recorded as *observations* only — neither is treated as
        validated knowledge until an outcome is confirmed."""
        now = datetime.now(timezone.utc).isoformat()
        risk_category = case.risk.category.value if case.risk else None
        for entity in case.entities.values():
            # Recording commodity infrastructure would make every future case that
            # uses the same vendor match this one.
            if entity.shared_infrastructure:
                continue
            self.storage.record_indicator(
                case_id=case.id,
                entity_type=entity.type.value,
                value=entity.value,
                seed=case.seed,
                outcome=case.outcome,
                risk_category=risk_category,
                created_at=now,
            )

        pattern_id, signals = self.signature_for(case)
        if not signals:
            return  # no threat-supporting signals: there is no pattern to remember
        self.storage.observe_pattern(
            pattern_id=pattern_id,
            name=" + ".join(s.split(":", 1)[1] for s in signals[:4]),
            description=f"co-occurring threat signals first observed in case {case.id}",
            signature={"signals": signals},
            now=now,
        )
        self.storage.link_case_pattern(case.id, pattern_id)

    def apply_outcome(self, case_id: str, outcome: str) -> None:
        """Close the learning loop for a validated case (see CLOSED-LOOP LEARNING).

        Only outcomes a human actually confirmed move pattern confidence. An
        'inconclusive' or 'unknown' result deliberately changes nothing: treating
        uncertainty as weak confirmation is exactly how a memory poisons itself.
        """
        self.storage.set_outcome(case_id, outcome)

        if outcome in (Outcome.CONFIRMED_MALICIOUS.value, Outcome.FALSE_NEGATIVE.value):
            confirmed = True
        elif outcome in (Outcome.FALSE_POSITIVE.value, Outcome.CONFIRMED_BENIGN.value):
            confirmed = False
        else:
            return

        now = datetime.now(timezone.utc).isoformat()
        for pattern_id in self.storage.patterns_for_case(case_id):
            self.storage.strengthen_pattern(pattern_id, confirmed=confirmed, now=now)

    def list_patterns(self) -> list[dict[str, Any]]:
        """Stored patterns with their derived lifecycle stage."""
        patterns = self.storage.list_patterns()
        for p in patterns:
            p["stage"] = self.stage_for(p)
        return patterns
