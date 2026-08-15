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
import socket
import ssl
from datetime import datetime, timezone

from ..core.models import Entity, Evidence, Independence, Polarity
from .base import CollectorResult, EvidenceCollector


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

        return CollectorResult(evidence=evidence, available=True)
