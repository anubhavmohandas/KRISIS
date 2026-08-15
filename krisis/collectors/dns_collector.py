"""
DNS evidence collector.

Adapted from the DNSEnumerator / resolve_dns logic in recon_scanner.py, behind
the KRISIS EvidenceCollector interface. Reuses the proven record-fetching
approach (dnspython resolver, per-record-type lookups, short timeouts) but
returns normalized Evidence instead of printing to stdout — RECON observes,
KRISIS investigates (see REUSE RECON in the design doc).
"""

from __future__ import annotations

from ..core.models import Entity, Evidence, Independence, Polarity
from .base import CollectorResult, EvidenceCollector

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]

_SIGNAL_BY_RECORD = {
    "A": "a_record",
    "AAAA": "aaaa_record",
    "MX": "mx_record",
    "NS": "ns_record",
    "CNAME": "cname_record",
    "TXT": "txt_record",
    "SOA": "soa_record",
}


class DNSCollector(EvidenceCollector):
    name = "dns"
    supports = ("domain", "hostname")

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def collect(self, entity: Entity) -> CollectorResult:
        try:
            import dns.resolver  # lazy import: optional dependency
        except ImportError:
            return CollectorResult(evidence=[], available=False, note="dnspython not installed")

        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        evidence: list[Evidence] = []
        any_record_found = False

        for rtype in RECORD_TYPES:
            try:
                answers = resolver.resolve(entity.value, rtype)
            except dns.resolver.NXDOMAIN:
                evidence.append(
                    Evidence(
                        source=self.name,
                        entity_id=entity.id,
                        signal="nxdomain",
                        value=True,
                        evidence_type="infrastructure",
                        polarity=Polarity.NEUTRAL,
                        confidence=0.95,
                        independence=Independence.INDEPENDENT,
                        provenance="domain does not resolve (NXDOMAIN)",
                    )
                )
                break
            except Exception:
                continue

            values = self._parse_records(rtype, answers)
            if not values:
                continue
            any_record_found = True
            evidence.append(
                Evidence(
                    source=self.name,
                    entity_id=entity.id,
                    signal=_SIGNAL_BY_RECORD.get(rtype, rtype.lower() + "_record"),
                    value=values,
                    evidence_type="infrastructure",
                    polarity=Polarity.NEUTRAL,
                    confidence=0.9,
                    independence=Independence.INDEPENDENT,
                    provenance=f"{rtype} record(s) resolved via DNS",
                )
            )

        if not evidence:
            return CollectorResult(evidence=[], available=False, note="no DNS response / provider unreachable")

        return CollectorResult(evidence=evidence, available=True, note="ok" if any_record_found else "no records")

    def _parse_records(self, rtype: str, answers) -> list[str]:
        """Parse DNS records into normalized values, handling special cases.

        - MX: Extract only the mail server hostname (exchange), filter out "." (no mail service)
        - NS/CNAME: Use target attribute if available
        - A/AAAA/TXT/SOA: Convert to string
        """
        values = []
        for r in answers:
            if rtype == "MX":
                # MX records have preference and exchange; we only care about the exchange (mail server)
                exchange = str(r.exchange).rstrip(".")  # Remove trailing dot for consistency
                # Filter out the special "." value which means "no mail service"
                if exchange and exchange != ".":
                    values.append(exchange)
            elif rtype in ("NS", "CNAME"):
                # These have a target attribute that's the hostname
                if hasattr(r, "target"):
                    target = str(r.target).rstrip(".")
                    values.append(target)
                else:
                    values.append(str(r))
            else:
                # A, AAAA, TXT, SOA — just use string representation
                values.append(str(r))
        return values
