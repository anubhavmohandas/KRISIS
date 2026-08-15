"""
IP / ASN evidence collector.

Adapted from IPRangeResolver.get_ip_range() in recon_scanner.py (RDAP lookup
via ipwhois). ASN is deliberately a low-priority pivot source in
pivot_engine.PIVOT_RULES — a shared ASN is extremely common and noisy on its
own; it only matters in combination with other overlap (see NOISY_FANOUT
handling).
"""

from __future__ import annotations

from ..core.models import Entity, Evidence, Independence, Polarity
from .base import CollectorResult, EvidenceCollector


class IPCollector(EvidenceCollector):
    name = "ip_whois"
    supports = ("ip",)

    def collect(self, entity: Entity) -> CollectorResult:
        try:
            from ipwhois import IPWhois  # lazy import: optional dependency
        except ImportError:
            return CollectorResult(evidence=[], available=False, note="ipwhois not installed")

        try:
            result = IPWhois(entity.value).lookup_rdap()
        except Exception as exc:
            return CollectorResult(evidence=[], available=False, note=f"RDAP lookup failed: {exc}")

        network = result.get("network", {}) or {}
        evidence: list[Evidence] = []

        if network.get("cidr"):
            evidence.append(
                Evidence(
                    source=self.name,
                    entity_id=entity.id,
                    signal="cidr",
                    value=network["cidr"],
                    evidence_type="infrastructure",
                    polarity=Polarity.NEUTRAL,
                    confidence=0.8,
                    independence=Independence.INDEPENDENT,
                    provenance="RDAP network allocation for this IP",
                )
            )

        asn = result.get("asn")
        if asn:
            evidence.append(
                Evidence(
                    source=self.name,
                    entity_id=entity.id,
                    signal="asn",
                    value=asn,
                    evidence_type="infrastructure",
                    polarity=Polarity.NEUTRAL,
                    confidence=0.75,
                    independence=Independence.INDEPENDENT,
                    provenance=f"IP belongs to ASN {asn} ({result.get('asn_description', 'unknown')})",
                )
            )

        country = network.get("country")
        if country:
            evidence.append(
                Evidence(
                    source=self.name,
                    entity_id=entity.id,
                    signal="hosting_country",
                    value=country,
                    evidence_type="infrastructure",
                    polarity=Polarity.NEUTRAL,
                    confidence=0.7,
                    independence=Independence.INDEPENDENT,
                    provenance="RDAP-reported country of network allocation",
                )
            )

        if not evidence:
            return CollectorResult(evidence=[], available=False, note="RDAP returned no usable network data")

        return CollectorResult(evidence=evidence, available=True)
