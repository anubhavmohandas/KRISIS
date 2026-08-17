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


def _txt_value(record) -> str:
    """Reconstruct a TXT record's actual text.

    A TXT resource record is one or more length-prefixed character-strings
    (RFC 1035 §3.3.14); anything over 255 bytes (a full-length SPF/DMARC
    record is common past that, e.g. github.com's) is split across several
    and must be concatenated with NO separator to recover the real value
    (RFC 7208 §3.3) — str(record) instead renders each segment separately
    quoted ('"first 255" "rest"'), which corrupts a long SPF string with an
    injected space+quote right at the split point.
    """
    segments = getattr(record, "strings", None)
    if segments:
        return b"".join(segments).decode("utf-8", errors="replace")
    return str(record).strip('"')


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

        nxdomain = False
        for rtype in RECORD_TYPES:
            try:
                answers = resolver.resolve(entity.value, rtype)
            except dns.resolver.NXDOMAIN:
                nxdomain = True
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

        # SPF/DMARC: mail-security posture, context only — never scored as a threat
        # signal in either direction (see risk.py's treatment of NEUTRAL evidence).
        # A domain not resolving at all makes both queries meaningless/misleading
        # ("no DMARC published" reads very differently from "domain doesn't exist").
        if not nxdomain:
            evidence.extend(self._spf_evidence(resolver, entity))
            evidence.extend(self._dmarc_evidence(resolver, entity))

        if not evidence:
            return CollectorResult(evidence=[], available=False, note="no DNS response / provider unreachable")

        return CollectorResult(evidence=evidence, available=True, note="ok" if any_record_found else "no records")

    def _spf_evidence(self, resolver, entity: Entity) -> list[Evidence]:
        """SPF posture from the domain's own TXT records (RFC 7208).

        A dedicated query (rather than reusing the main loop's TXT capture) keeps
        this fully additive — zero risk to the existing per-record-type loop above.
        """
        import dns.resolver

        try:
            answers = resolver.resolve(entity.value, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return [self._spf_missing(entity)]
        except Exception:
            return []  # genuinely unavailable — "missing" would be a claim we didn't earn

        records = [_txt_value(r) for r in answers]
        records = [r for r in records if r.lower().startswith("v=spf1")]
        if not records:
            return [self._spf_missing(entity)]
        if len(records) > 1:
            return [
                Evidence(
                    source=self.name,
                    entity_id=entity.id,
                    signal="spf_malformed",
                    value=records,
                    evidence_type="infrastructure",
                    polarity=Polarity.NEUTRAL,
                    confidence=0.55,
                    independence=Independence.DERIVED,
                    provenance=(
                        f"{len(records)} SPF (v=spf1) TXT records published — RFC 7208 permits "
                        "only one; multiple is a permerror for any validator"
                    ),
                )
            ]
        return [
            Evidence(
                source=self.name,
                entity_id=entity.id,
                signal="spf_record",
                value=records[0],
                evidence_type="infrastructure",
                polarity=Polarity.NEUTRAL,
                confidence=0.6,
                independence=Independence.DERIVED,
                provenance="SPF (v=spf1) TXT record published for this domain",
            )
        ]

    def _spf_missing(self, entity: Entity) -> Evidence:
        return Evidence(
            source=self.name,
            entity_id=entity.id,
            signal="spf_missing",
            value=True,
            evidence_type="infrastructure",
            polarity=Polarity.NEUTRAL,
            confidence=0.5,
            independence=Independence.DERIVED,
            provenance="no SPF (v=spf1) TXT record published for this domain",
        )

    def _dmarc_evidence(self, resolver, entity: Entity) -> list[Evidence]:
        """DMARC posture via the standard _dmarc.<domain> TXT lookup (RFC 7489).

        Only what a single-domain DNS query can honestly answer: whether a policy
        is published at all, and whether it's well-formed. Alignment (does this
        policy's domain match a *specific message's* From: header) needs a
        structured email input KRISIS does not have — not faked here.
        """
        import dns.resolver

        try:
            answers = resolver.resolve(f"_dmarc.{entity.value}", "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return [self._dmarc_missing(entity)]
        except Exception:
            return []

        records = [_txt_value(r) for r in answers]
        records = [r for r in records if r.lower().startswith("v=dmarc1")]
        if not records:
            return [self._dmarc_missing(entity)]
        if len(records) > 1:
            return [
                Evidence(
                    source=self.name,
                    entity_id=entity.id,
                    signal="dmarc_malformed",
                    value=records,
                    evidence_type="infrastructure",
                    polarity=Polarity.NEUTRAL,
                    confidence=0.55,
                    independence=Independence.INDEPENDENT,
                    provenance=(
                        f"{len(records)} DMARC (v=DMARC1) TXT records published at "
                        f"_dmarc.{entity.value} — RFC 7489 permits only one; multiple is a permerror"
                    ),
                )
            ]
        return [
            Evidence(
                source=self.name,
                entity_id=entity.id,
                signal="dmarc_record",
                value=records[0],
                evidence_type="infrastructure",
                polarity=Polarity.NEUTRAL,
                confidence=0.6,
                independence=Independence.INDEPENDENT,
                provenance=f"DMARC (v=DMARC1) TXT record published at _dmarc.{entity.value}",
            )
        ]

    def _dmarc_missing(self, entity: Entity) -> Evidence:
        return Evidence(
            source=self.name,
            entity_id=entity.id,
            signal="dmarc_missing",
            value=True,
            evidence_type="infrastructure",
            polarity=Polarity.NEUTRAL,
            confidence=0.5,
            independence=Independence.INDEPENDENT,
            provenance="no DMARC (_dmarc TXT) record published for this domain",
        )

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
