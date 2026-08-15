"""
WHOIS / registration evidence collector.

Adapted from perform_whois() in recon_scanner.py. Domain age is one of the
weaker signals on its own (many legitimate sites are new) but combines
strongly with other evidence — see TYPE_WEIGHTS in risk.py, where
"registration" evidence is deliberately weighted low in isolation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..core.models import Entity, Evidence, Independence, Polarity
from .base import CollectorResult, EvidenceCollector

NEW_DOMAIN_THRESHOLD_DAYS = 30
YOUNG_DOMAIN_THRESHOLD_DAYS = 180


def _first(value: Any) -> Any:
    if isinstance(value, (list, tuple)) and value:
        return value[0]
    return value


class WHOISCollector(EvidenceCollector):
    name = "whois"
    supports = ("domain",)

    def collect(self, entity: Entity) -> CollectorResult:
        try:
            import whois  # lazy import: optional dependency (python-whois)
        except ImportError:
            return CollectorResult(evidence=[], available=False, note="python-whois not installed")

        try:
            record = whois.whois(entity.value)
        except Exception as exc:
            return CollectorResult(evidence=[], available=False, note=f"whois lookup failed: {exc}")

        if not record or not record.get("domain_name"):
            return CollectorResult(evidence=[], available=False, note="no WHOIS record returned")

        evidence: list[Evidence] = []

        creation_date = _first(record.get("creation_date"))
        if isinstance(creation_date, datetime):
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - creation_date).days
            if age_days < NEW_DOMAIN_THRESHOLD_DAYS:
                evidence.append(
                    Evidence(
                        source=self.name,
                        entity_id=entity.id,
                        signal="newly_registered_domain",
                        value=age_days,
                        evidence_type="registration",
                        polarity=Polarity.SUPPORTS_THREAT,
                        confidence=0.6,
                        independence=Independence.INDEPENDENT,
                        provenance=f"domain registered {age_days} days ago",
                    )
                )
            elif age_days > YOUNG_DOMAIN_THRESHOLD_DAYS * 4:
                evidence.append(
                    Evidence(
                        source=self.name,
                        entity_id=entity.id,
                        signal="long_lived_domain",
                        value=age_days,
                        evidence_type="registration",
                        polarity=Polarity.CONTRADICTS_THREAT,
                        confidence=0.55,
                        independence=Independence.INDEPENDENT,
                        provenance=f"domain registered {age_days} days ago (long-lived)",
                    )
                )
            else:
                evidence.append(
                    Evidence(
                        source=self.name,
                        entity_id=entity.id,
                        signal="domain_age_days",
                        value=age_days,
                        evidence_type="registration",
                        polarity=Polarity.NEUTRAL,
                        confidence=0.5,
                        independence=Independence.INDEPENDENT,
                        provenance=f"domain registered {age_days} days ago",
                    )
                )

        registrant_email = _first(record.get("emails"))
        if registrant_email:
            evidence.append(
                Evidence(
                    source=self.name,
                    entity_id=entity.id,
                    signal="registrant_email",
                    value=registrant_email,
                    evidence_type="registration",
                    polarity=Polarity.NEUTRAL,
                    confidence=0.7,
                    independence=Independence.INDEPENDENT,
                    provenance="registration contact email",
                )
            )

        org = _first(record.get("org"))
        if org:
            evidence.append(
                Evidence(
                    source=self.name,
                    entity_id=entity.id,
                    signal="registrant_org",
                    value=org,
                    evidence_type="registration",
                    polarity=Polarity.NEUTRAL,
                    confidence=0.6,
                    independence=Independence.INDEPENDENT,
                    provenance="registration organization",
                )
            )

        if record.get("registrar"):
            evidence.append(
                Evidence(
                    source=self.name,
                    entity_id=entity.id,
                    signal="registrar",
                    value=str(record.get("registrar")),
                    evidence_type="registration",
                    polarity=Polarity.NEUTRAL,
                    confidence=0.6,
                    independence=Independence.INDEPENDENT,
                    provenance="domain registrar",
                )
            )

        if not evidence:
            return CollectorResult(evidence=[], available=False, note="WHOIS record present but no usable fields")

        return CollectorResult(evidence=evidence, available=True)
