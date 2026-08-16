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

from ..core.indicators import domain_from_url, extract_from_text, registrable_domain
from ..core.message_signals import extract
from ..core.models import Entity, EntityType, Evidence, Independence, Polarity
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
        evidence.extend(self._sender_url_mismatch_evidence(entity))

        if not evidence:
            return CollectorResult(evidence=[], available=True, note="no behavioral signal detected")
        return CollectorResult(evidence=evidence, available=True)

    def _sender_url_mismatch_evidence(self, entity: Entity) -> list[Evidence]:
        """Evidence that the message never links back to the organization any
        email address mentioned in it belongs to — a distinct fact from URL-path
        *intent* (see module docstring), so it does not double-count with
        PageCollector: this compares sender-vs-link *domain identity*, not
        anything about a URL's own path/query.

        Deliberately all-or-nothing (every sender domain disjoint from every
        linked domain), not "any pairwise mismatch" — an ordinary message that
        mentions one unrelated domain in passing while still linking back to
        its claimed sender elsewhere should not fire this.
        """
        found = extract_from_text(entity.value)
        emails = [v for t, v in found if t == EntityType.EMAIL]
        if not emails:
            return []

        # The domain regex also matches the domain portion of any email address
        # in the text, so a bare-DOMAIN extraction can just be an email's own
        # domain restated — exclude those, or the sender never fails to "link
        # back to itself" and this check can never fire.
        email_domains = {e.rsplit("@", 1)[-1].lower() for e in emails}
        link_hosts = [domain_from_url(v) for t, v in found if t == EntityType.URL]
        link_hosts += [
            v for t, v in found if t == EntityType.DOMAIN and v.lower() not in email_domains
        ]

        sender_orgs = {registrable_domain(e.rsplit("@", 1)[-1]) for e in emails}
        link_orgs = {registrable_domain(h) for h in link_hosts if h}
        sender_orgs.discard("")
        link_orgs.discard("")

        if not sender_orgs or not link_orgs or not sender_orgs.isdisjoint(link_orgs):
            return []

        return [Evidence(
            source=self.name, entity_id=entity.id, signal="sender_url_domain_mismatch",
            value={"sender_domains": sorted(sender_orgs), "linked_domains": sorted(link_orgs)},
            evidence_type="behavior", polarity=Polarity.SUPPORTS_THREAT, confidence=0.4,
            independence=Independence.DERIVED,
            provenance=(
                f"message mentions sender address(es) at {sorted(sender_orgs)} but links "
                f"only to unrelated domain(s) {sorted(link_orgs)} — the message never links "
                f"back to the organization it appears to be from"
            ),
        )]
