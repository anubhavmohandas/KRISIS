"""
Pivot Engine — turns new evidence into candidate next investigative steps,
scores them, and enforces the investigation budget.

This is the mechanism described in "THE PIVOT ENGINE" / "INVESTIGATION BUDGET":
KRISIS never blindly chases every relationship it discovers. Every candidate
pivot gets a priority; low-value pivots (e.g. a mail provider shared by 50,000
unrelated domains) are rejected with a stated reason so the decision is
auditable later via investigation replay.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .models import Entity, EntityType, Evidence, Pivot

# Entity types below this per-entity fan-out are considered "noisy" and get a
# priority penalty — e.g. a nameserver or ASN shared with thousands of domains
# is a weak pivot even though it is technically a relationship.
NOISY_FANOUT_THRESHOLD = 25


@dataclass
class InvestigationBudget:
    max_depth: int = 2
    max_entities: int = 40
    max_external_calls: int = 60
    max_pivots_per_entity: int = 5

    external_calls_made: int = 0
    entities_investigated: int = 0

    def has_call_budget(self) -> bool:
        return self.external_calls_made < self.max_external_calls

    def has_entity_budget(self) -> bool:
        return self.entities_investigated < self.max_entities

    def register_call(self) -> None:
        self.external_calls_made += 1

    def register_entity(self) -> None:
        self.entities_investigated += 1


# signal -> (entity_type produced, relation_type, base_priority, reason template)
PIVOT_RULES: dict[str, tuple[EntityType, str, float, str]] = {
    "a_record": (EntityType.IP, "resolves_to", 0.55, "domain resolves to this IP"),
    "aaaa_record": (EntityType.IP, "resolves_to", 0.5, "domain resolves to this IPv6 address"),
    "cname_record": (EntityType.HOSTNAME, "cname_to", 0.5, "domain is aliased via CNAME"),
    "ns_record": (EntityType.NAMESERVER, "uses_nameserver", 0.25, "domain uses this nameserver"),
    "mx_record": (EntityType.HOSTNAME, "uses_mailserver", 0.3, "domain uses this mail server"),
    "certificate_fingerprint": (EntityType.CERTIFICATE, "secured_by", 0.75, "certificate observed on this host"),
    "registrant_email": (EntityType.EMAIL, "registered_with", 0.6, "domain registration contact"),
    "registrant_org": (EntityType.ORGANIZATION, "registered_by", 0.45, "domain registration organization"),
    "asn": (EntityType.ASN, "hosted_on_asn", 0.35, "IP belongs to this ASN"),
    "vt_related_domain": (EntityType.DOMAIN, "vt_related", 0.7, "VirusTotal reports a direct relationship"),
    "vt_communicating_ip": (EntityType.IP, "vt_related", 0.65, "VirusTotal reports this IP as related"),
    "redirect_target": (EntityType.URL, "redirects_to", 0.7, "observed redirect destination"),
}


class PivotEngine:
    def __init__(self, budget: Optional[InvestigationBudget] = None) -> None:
        self.budget = budget or InvestigationBudget()
        self._pivots_per_entity: dict[str, int] = {}

    def generate(self, entity: Entity, evidence_items: list[Evidence]) -> list[Pivot]:
        """Given newly collected evidence about `entity`, produce scored candidate pivots."""
        candidates: list[Pivot] = []
        for ev in evidence_items:
            rule = PIVOT_RULES.get(ev.signal)
            if not rule:
                continue
            target_type, relation_type, base_priority, reason = rule
            values = ev.value if isinstance(ev.value, list) else [ev.value]
            for v in values:
                if not v:
                    continue
                priority = self._score(entity, ev, base_priority)
                candidates.append(
                    Pivot(
                        entity_value=str(v),
                        entity_type=target_type,
                        reason=reason,
                        priority=priority,
                        source_entity_id=entity.id,
                        relation_type=relation_type,
                        source_evidence_id=ev.id,
                        depth=entity.depth + 1,
                    )
                )
        candidates.sort(key=lambda p: p.priority, reverse=True)
        return candidates

    def _score(self, entity: Entity, evidence: Evidence, base_priority: float) -> float:
        score = base_priority
        # Evidence KRISIS trusts more should pivot more confidently.
        score *= (0.5 + 0.5 * evidence.confidence)
        # Evidence that already supports the threat hypothesis is worth following harder.
        if evidence.polarity.value == "supports_threat":
            score += 0.1
        return max(0.0, min(1.0, score))

    def accept_or_reject(self, pivot: Pivot, current_depth_count: int) -> Pivot:
        """Apply budget + noise rules. Mutates and returns the pivot with a final status."""
        entity_key = pivot.source_entity_id

        if pivot.depth > self.budget.max_depth:
            pivot.status = "rejected"
            pivot.rejection_reason = f"exceeds max_depth ({self.budget.max_depth})"
            return pivot

        if not self.budget.has_entity_budget():
            pivot.status = "rejected"
            pivot.rejection_reason = f"investigation entity budget exhausted ({self.budget.max_entities})"
            return pivot

        seen_for_entity = self._pivots_per_entity.get(entity_key, 0)
        if seen_for_entity >= self.budget.max_pivots_per_entity:
            pivot.status = "rejected"
            pivot.rejection_reason = (
                f"max_pivots_per_entity ({self.budget.max_pivots_per_entity}) reached for source entity"
            )
            return pivot

        if pivot.entity_type in (EntityType.NAMESERVER, EntityType.ASN) and pivot.priority < 0.35:
            pivot.status = "rejected"
            pivot.rejection_reason = "low-value shared infrastructure (likely noisy fan-out)"
            return pivot

        if pivot.priority < 0.2:
            pivot.status = "rejected"
            pivot.rejection_reason = "priority below investigative threshold"
            return pivot

        pivot.status = "accepted"
        self._pivots_per_entity[entity_key] = seen_for_entity + 1
        return pivot

    def penalize_noisy_fanout(self, pivots: list[Pivot], fanout_counts: dict[str, int]) -> None:
        """Down-rank pivots whose target value is shared by an unusually large number of entities.

        fanout_counts maps entity_value -> number of distinct sources pointing at it
        (e.g. how many domains share this one nameserver).
        """
        for p in pivots:
            count = fanout_counts.get(p.entity_value, 1)
            if count >= NOISY_FANOUT_THRESHOLD:
                p.priority *= 0.2
