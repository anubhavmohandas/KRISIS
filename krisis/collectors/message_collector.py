"""
Message-behavior collector — turns a raw message body into structured
behavioral evidence (urgency, credential requests, financial lure, calls to
action). See krisis/core/message_signals.py for the deterministic extraction;
this collector only wraps it as Evidence.

Deliberately does not classify URL-path intent: any URL in the message is
already queued as its own entity and gets full page/URL-intent analysis via
PageCollector. Doing it here too would double-count the same fact under two
different sources (source="message" and source="page"), inflating evidence
diversity and double-contributing to the risk score for one observation.
"""

from __future__ import annotations

from ..core.message_signals import extract
from ..core.models import Entity, Evidence, Independence, Polarity
from .base import CollectorResult, EvidenceCollector

# Reflects how reliably the phrase pattern itself indicates the behavior, not
# how malicious the overall message is — that is for correlation/risk to
# decide once combined with everything else observed about the message.
_CONFIDENCE: dict[str, float] = {
    "urgency_language": 0.5,
    "credential_request": 0.6,
    "financial_lure": 0.5,
    "call_to_action": 0.4,
}


class MessageCollector(EvidenceCollector):
    name = "message"
    supports = ("message",)

    def collect(self, entity: Entity) -> CollectorResult:
        try:
            found = extract(entity.value)
        except Exception as exc:
            return CollectorResult(evidence=[], available=False, note=f"message analysis failed: {exc}")

        if not found:
            return CollectorResult(evidence=[], available=True, note="no behavioral signal detected")

        evidence = [
            Evidence(
                source=self.name, entity_id=entity.id, signal=category,
                value=snippets, evidence_type="behavior",
                polarity=Polarity.SUPPORTS_THREAT,
                confidence=_CONFIDENCE.get(category, 0.4),
                independence=Independence.INDEPENDENT,
                provenance=(
                    f"message text matches {category}: "
                    f"{', '.join(repr(s) for s in snippets[:3])}"
                ),
            )
            for category, snippets in found.items()
        ]
        return CollectorResult(evidence=evidence, available=True)
