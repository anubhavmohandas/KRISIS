"""
TLS / certificate evidence collector.

Adapted from SSLInformation.get_ssl_details() in recon_scanner.py. The
certificate fingerprint produced here is one of the highest-value pivot
sources in KRISIS (see PIVOT_RULES in pivot_engine.py: "certificate_fingerprint"
has the highest base priority) because a shared certificate across unrelated
hostnames is a strong infrastructure-overlap signal.
"""

from __future__ import annotations

import hashlib
import re
import socket
import ssl
from datetime import datetime, timezone

from ..core.identity import label_similarity
from ..core.indicators import registrable_domain
from ..core.models import Entity, Evidence, Independence, Polarity
from .base import CollectorResult, EvidenceCollector

# Reuses page_collector.BRAND_MISMATCH_THRESHOLD's exact value rather than
# inventing a second untested cutoff — same kind of claimed-identity-vs-domain
# comparison, just sourced from a CA-vetted certificate field instead of page
# HTML. Duplicated, not imported: collector modules stay independent of one
# another so any one of them can fail without the others knowing.
SUBJECT_ORG_MISMATCH_THRESHOLD = 0.45
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]")


class TLSCollector(EvidenceCollector):
    name = "tls"
    supports = ("domain", "hostname")

    def __init__(self, port: int = 443, timeout: float = 5.0):
        self.port = port
        self.timeout = timeout

    def collect(self, entity: Entity) -> CollectorResult:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((entity.value, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=entity.value) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()
        except Exception as exc:
            return CollectorResult(evidence=[], available=False, note=f"TLS connection failed: {exc}")

        if not der_cert:
            return CollectorResult(evidence=[], available=False, note="no certificate returned")

        fingerprint = hashlib.sha256(der_cert).hexdigest()

        evidence = [
            Evidence(
                source=self.name,
                entity_id=entity.id,
                signal="certificate_fingerprint",
                value=fingerprint,
                evidence_type="infrastructure",
                polarity=Polarity.NEUTRAL,
                confidence=0.85,
                independence=Independence.INDEPENDENT,
                provenance="SHA-256 fingerprint of the presented leaf certificate",
                raw={"subject": cert_dict.get("subject"), "issuer": cert_dict.get("issuer")},
            )
        ]

        not_after = cert_dict.get("notAfter")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                if days_left < 0:
                    evidence.append(
                        Evidence(
                            source=self.name,
                            entity_id=entity.id,
                            signal="expired_certificate",
                            value=not_after,
                            evidence_type="infrastructure",
                            polarity=Polarity.SUPPORTS_THREAT,
                            confidence=0.5,
                            independence=Independence.INDEPENDENT,
                            provenance="TLS certificate is expired",
                        )
                    )
            except ValueError:
                pass

        issuer = dict(x[0] for x in cert_dict.get("issuer", []))
        if issuer.get("organizationName"):
            evidence.append(
                Evidence(
                    source=self.name,
                    entity_id=entity.id,
                    signal="valid_tls_present",
                    value=issuer.get("organizationName"),
                    evidence_type="infrastructure",
                    polarity=Polarity.CONTRADICTS_THREAT,
                    confidence=0.25,   # weak on its own: any attacker can get a valid cert
                    independence=Independence.INDEPENDENT,
                    provenance="valid TLS certificate presented (weak signal alone)",
                )
            )

        subject_evidence = self._subject_org_evidence(entity, cert_dict)
        if subject_evidence:
            evidence.append(subject_evidence)

        return CollectorResult(evidence=evidence, available=True)

    def _subject_org_evidence(self, entity: Entity, cert_dict: dict) -> Evidence | None:
        """Compares the certificate SUBJECT's organizationName (present only on
        OV/EV certs — most DV certs, including most phishing infra, carry none
        at all) against the domain's own registrable label. Absence is silent:
        it is a cost decision by the certificate holder, never a threat signal.

        A match is real, CA-vetted identity corroboration, but not ownership
        proof of the *whole* artifact — a phishing site can hold a legitimate
        OV cert for a shell company while still impersonating a different
        brand in its domain/page identity. risk.py's NARROW_CONTRADICTIONS
        keeps a match from arithmetically offsetting an identity finding it
        doesn't actually rebut.
        """
        subject = dict(x[0] for x in cert_dict.get("subject", []))
        subject_org = subject.get("organizationName")
        if not subject_org:
            return None

        domain_label = registrable_domain(entity.value).partition(".")[0]
        normalized_org = _NON_ALNUM_RE.sub("", subject_org.lower())
        if not domain_label or not normalized_org:
            return None

        similarity = label_similarity(normalized_org, domain_label)
        if similarity >= SUBJECT_ORG_MISMATCH_THRESHOLD:
            return Evidence(
                source=self.name, entity_id=entity.id, signal="certificate_subject_org_match",
                value=subject_org, evidence_type="behavior",
                polarity=Polarity.CONTRADICTS_THREAT, confidence=0.5,
                independence=Independence.INDEPENDENT,
                provenance=(
                    f"certificate subject organization '{subject_org}' (CA-vetted, OV/EV) "
                    f"resembles this domain's own name ('{domain_label}')"
                ),
            )
        return Evidence(
            source=self.name, entity_id=entity.id, signal="certificate_subject_org_mismatch",
            value=subject_org, evidence_type="behavior",
            polarity=Polarity.SUPPORTS_THREAT, confidence=0.35,
            independence=Independence.INDEPENDENT,
            provenance=(
                f"certificate subject organization '{subject_org}' does not resemble this "
                f"domain's own name ('{domain_label}') — modest signal alone, legitimate "
                f"multi-brand corporate ownership exists"
            ),
        )
