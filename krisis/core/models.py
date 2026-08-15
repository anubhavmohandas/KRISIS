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
    UNKNOWN = "UNKNOWN"


@dataclass
class Entity:
    """A node in the investigation graph: a domain, IP, certificate, etc."""

    value: str
    type: EntityType
    id: str = field(default_factory=lambda: _new_id("ent"))
    first_seen: str = field(default_factory=_now)
    depth: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

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

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "category": self.category.value,
            "confidence": round(self.confidence, 3),
            "supporting_count": len(self.supporting),
            "contradicting_count": len(self.contradicting),
            "top_contributors": self.top_contributors,
            "historical_similarity": self.historical_similarity,
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
    outcome: Optional[str] = None    # confirmed_malicious | false_positive | unresolved
    provider_failures: list[str] = field(default_factory=list)

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
        }
