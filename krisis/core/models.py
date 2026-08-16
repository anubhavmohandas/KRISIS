"""
KRISIS core data models.

Every collector, engine, and store in KRISIS speaks these types. Provider-specific
response formats are translated into these models at the collector boundary and
never leak further into the system (see NORMALIZATION in the design doc).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EntityType(str, Enum):
    DOMAIN = "domain"
    URL = "url"
    IP = "ip"
    CIDR = "cidr"
    ASN = "asn"
    CERTIFICATE = "certificate"
    HASH = "hash"
    EMAIL = "email"
    PHONE = "phone"
    ORGANIZATION = "organization"
    NAMESERVER = "nameserver"
    HOSTNAME = "hostname"
    FILE = "file"
    MESSAGE = "message"
    CASE = "case"
    PATTERN = "pattern"
    UNKNOWN = "unknown"


class Polarity(str, Enum):
    SUPPORTS_THREAT = "supports_threat"
    CONTRADICTS_THREAT = "contradicts_threat"
    NEUTRAL = "neutral"


class Independence(str, Enum):
    INDEPENDENT = "independent"
    DERIVED = "derived"
    DUPLICATE = "duplicate"
    CORRELATED = "correlated"


class RiskCategory(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    # Not-a-threat-level states. "Not checked" is not "clean": when KRISIS could
    # not actually examine the artifact, or its sources disagree, it must say so
    # rather than fall through to LOW (see UNCERTAINTY STATES in the design doc).
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
    UNKNOWN = "UNKNOWN"


# Prior-case outcomes. A historical resemblance only means something once the
# prior case was actually validated — see PATTERN LIFECYCLE / POISONING RESISTANCE.
class Outcome(str, Enum):
    CONFIRMED_MALICIOUS = "confirmed_malicious"
    CONFIRMED_BENIGN = "confirmed_benign"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    INCONCLUSIVE = "inconclusive"
    UNKNOWN = "unknown"


@dataclass
class Coverage:
    """What KRISIS actually managed to check about the seed artifact.

    Risk and confidence are both meaningless without this: a clean result from
    two sources that answered, while three were down, is not the same finding as
    a clean result from five that answered.
    """

    attempted: set[str] = field(default_factory=set)        # collector names asked about the seed
    available: set[str] = field(default_factory=set)        # collector names that answered (even with nothing to report)
    evidence_types: set[str] = field(default_factory=set)   # evidence_type values actually obtained

    @property
    def failed(self) -> set[str]:
        return self.attempted - self.available

    @property
    def ratio(self) -> float:
        return len(self.available) / len(self.attempted) if self.attempted else 0.0

    def has_reputation_source(self) -> bool:
        """True if at least one source actually offered a threat-reputation opinion.
        Without one, KRISIS has no basis to assert an artifact is low risk."""
        return "reputation" in self.evidence_types

    def to_dict(self) -> dict[str, Any]:
        return {
            "sources_attempted": sorted(self.attempted),
            "sources_available": sorted(self.available),
            "sources_unavailable": sorted(self.failed),
            "coverage_ratio": round(self.ratio, 3),
            "reputation_checked": self.has_reputation_source(),
        }


@dataclass
class Entity:
    """A node in the investigation graph: a domain, IP, certificate, etc."""

    value: str
    type: EntityType
    id: str = field(default_factory=lambda: _new_id("ent"))
    first_seen: str = field(default_factory=_now)
    depth: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    # True for commodity infrastructure the target merely rents (a shared mail
    # provider, a public nameserver and anything reached through one). Such an
    # entity is a fact about a vendor's market share, not a distinguishing trait of
    # this artifact, so it is excluded from indicator memory and pattern matching —
    # otherwise every organization using the same mail vendor looks related.
    shared_infrastructure: bool = False

    def key(self) -> str:
        """Stable dedup key: same (type, value) is always the same entity."""
        return f"{self.type.value}:{self.value.lower()}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "value": self.value,
            "type": self.type.value,
            "first_seen": self.first_seen,
            "depth": self.depth,
            "shared_infrastructure": self.shared_infrastructure,
            "metadata": self.metadata,
        }


@dataclass
class Evidence:
    """A single normalized observation about an entity.

    This is the atomic unit KRISIS reasons over. Every downstream conclusion
    (correlation, risk, explanation) must be traceable back to a list of
    Evidence ids — see EVIDENCE MODEL / NORMALIZATION in the design doc.
    """

    source: str                      # provider name, e.g. "dns", "virustotal", "whois"
    entity_id: str                   # id of the Entity this evidence is about
    signal: str                      # short machine name, e.g. "malicious_detection"
    value: Any                       # the observed value
    evidence_type: str               # category, e.g. "reputation", "infrastructure", "registration"
    polarity: Polarity = Polarity.NEUTRAL
    confidence: float = 0.5          # 0..1, how much this collector trusts its own reading
    independence: Independence = Independence.INDEPENDENT
    id: str = field(default_factory=lambda: _new_id("ev"))
    observed_at: str = field(default_factory=_now)
    provenance: str = ""             # human-readable "why we believe this"
    raw: Optional[dict[str, Any]] = None   # original provider payload, for audit only
    # When the provider actually answered, as opposed to when KRISIS used the answer.
    # A cached result is still evidence, but it is evidence about the moment it was
    # fetched — presenting it as current intelligence would be a lie of omission.
    fetched_at: str = ""             # "" means same as observed_at (fetched live)
    freshness: str = "live"          # live | cached
    cache_age_seconds: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "entity_id": self.entity_id,
            "signal": self.signal,
            "value": self.value,
            "evidence_type": self.evidence_type,
            "polarity": self.polarity.value,
            "confidence": self.confidence,
            "independence": self.independence.value,
            "observed_at": self.observed_at,
            "provenance": self.provenance,
            "fetched_at": self.fetched_at or self.observed_at,
            "freshness": self.freshness,
            "cache_age_seconds": self.cache_age_seconds,
        }


@dataclass
class Relationship:
    """A directed, reasoned edge between two entities in the graph."""

    source_entity_id: str
    target_entity_id: str
    relation_type: str               # e.g. "resolves_to", "shares_certificate", "same_asn"
    reason: str                      # why KRISIS believes this edge matters
    id: str = field(default_factory=lambda: _new_id("rel"))
    evidence_ids: list[str] = field(default_factory=list)
    weight: float = 0.5              # investigative strength of this relationship
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_entity_id": self.source_entity_id,
            "target_entity_id": self.target_entity_id,
            "relation_type": self.relation_type,
            "reason": self.reason,
            "evidence_ids": self.evidence_ids,
            "weight": self.weight,
            "created_at": self.created_at,
        }


@dataclass
class Pivot:
    """A candidate next investigative step, generated from evidence."""

    entity_value: str
    entity_type: EntityType
    reason: str
    priority: float                  # 0..1
    source_entity_id: str            # the entity that produced this pivot
    relation_type: str = "related_to"   # edge label to use if this pivot is accepted
    source_evidence_id: Optional[str] = None
    depth: int = 1
    id: str = field(default_factory=lambda: _new_id("piv"))
    status: str = "pending"          # pending | accepted | rejected | investigated
    rejection_reason: Optional[str] = None
    shared_infrastructure: bool = False   # target is commodity third-party infrastructure

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "entity_value": self.entity_value,
            "entity_type": self.entity_type.value,
            "reason": self.reason,
            "priority": round(self.priority, 3),
            "source_entity_id": self.source_entity_id,
            "depth": self.depth,
            "status": self.status,
            "rejection_reason": self.rejection_reason,
            "shared_infrastructure": self.shared_infrastructure,
        }


@dataclass
class RiskAssessment:
    score: int                       # 0..100
    category: RiskCategory
    confidence: float                # 0..1
    supporting: list[dict[str, Any]]
    contradicting: list[dict[str, Any]]
    top_contributors: list[str]
    historical_similarity: Optional[dict[str, Any]] = None
    # What KRISIS could not determine. Reported alongside the score, never folded
    # into it silently (see UNCERTAINTY STATES).
    uncertainty: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "category": self.category.value,
            "confidence": round(self.confidence, 3),
            "supporting_count": len(self.supporting),
            "contradicting_count": len(self.contradicting),
            "top_contributors": self.top_contributors,
            "historical_similarity": self.historical_similarity,
            "uncertainty": self.uncertainty,
        }


@dataclass
class Case:
    """A complete, stored investigation."""

    seed: str
    seed_type: EntityType
    id: str = field(default_factory=lambda: _new_id("case"))
    created_at: str = field(default_factory=_now)
    entities: dict[str, Entity] = field(default_factory=dict)          # id -> Entity
    evidence: dict[str, Evidence] = field(default_factory=dict)        # id -> Evidence
    relationships: dict[str, Relationship] = field(default_factory=dict)
    pivots: list[Pivot] = field(default_factory=list)
    pattern_matches: list[dict[str, Any]] = field(default_factory=list)
    risk: Optional[RiskAssessment] = None
    explanation: str = ""
    recommendation: str = ""
    outcome: Optional[str] = None    # an Outcome value, or None while never validated
    # A provider that ran and could not answer (outage, timeout, error response).
    provider_failures: list[str] = field(default_factory=list)
    # A provider request the planner chose not to spend (budget/value-gate/backoff).
    # Kept separate from provider_failures: neither is "clean", but only one is a
    # provider malfunction — collapsing them reads a deliberate decision as a fault.
    provider_skips: list[str] = field(default_factory=list)
    # Per-provider accounting: what was spent, reused, or deliberately not spent.
    # Stored with the case because "why was this provider not consulted?" is part of
    # the investigation record, not a runtime detail.
    provider_usage: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "seed": self.seed,
            "seed_type": self.seed_type.value,
            "created_at": self.created_at,
            "entities": [e.to_dict() for e in self.entities.values()],
            "evidence": [e.to_dict() for e in self.evidence.values()],
            "relationships": [r.to_dict() for r in self.relationships.values()],
            "pivots": [p.to_dict() for p in self.pivots],
            "pattern_matches": self.pattern_matches,
            "risk": self.risk.to_dict() if self.risk else None,
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "outcome": self.outcome,
            "provider_failures": self.provider_failures,
            "provider_skips": self.provider_skips,
            "provider_usage": self.provider_usage,
        }
