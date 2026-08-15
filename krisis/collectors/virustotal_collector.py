"""
VirusTotal evidence collector.

Adapted from VirusTotalScanner in recon_scanner.py (VT public API v2). In
recon_scanner this printed a raw report; here it is normalized into Evidence
and, importantly, VT's own relationship data (subdomains, resolved IPs) is
turned into pivot candidates rather than dead-ended — see PIVOT_RULES
"vt_related_domain" / "vt_communicating_ip" in pivot_engine.py.

VirusTotal is treated strictly as one evidence source among several (see
"VirusTotal is an evidence source. KRISIS performs an investigation." in the
design doc) — its positives/total ratio is one signal, not the verdict.
"""

from __future__ import annotations

import requests

from ..core.models import Entity, Evidence, Independence, Polarity
from .base import CollectorResult, EvidenceCollector


class VirusTotalCollector(EvidenceCollector):
    name = "virustotal"
    supports = ("domain", "url", "hash")

    BASE_URL = "https://www.virustotal.com/vtapi/v2"

    def __init__(self, api_key: str | None):
        self.api_key = api_key

    def collect(self, entity: Entity) -> CollectorResult:
        if not self.api_key:
            return CollectorResult(evidence=[], available=False, note="no VirusTotal API key configured")

        try:
            if entity.type.value == "domain":
                return self._collect_domain(entity)
            if entity.type.value == "url":
                return self._collect_url(entity)
            if entity.type.value == "hash":
                return self._collect_hash(entity)
        except requests.RequestException as exc:
            return CollectorResult(evidence=[], available=False, note=f"network error: {exc}")
        except Exception as exc:
            return CollectorResult(evidence=[], available=False, note=f"unexpected error: {exc}")

        return CollectorResult(evidence=[], available=False, note="unsupported entity type")

    # -- endpoint handlers ----------------------------------------------------

    def _collect_domain(self, entity: Entity) -> CollectorResult:
        resp = requests.get(
            f"{self.BASE_URL}/domain/report",
            params={"apikey": self.api_key, "domain": entity.value},
            timeout=10,
        )
        status = self._check_status(resp)
        if status is not None:
            return status
        data = resp.json()

        evidence: list[Evidence] = []

        detected_urls = data.get("detected_urls", [])
        if detected_urls:
            positives = sum(u.get("positives", 0) for u in detected_urls)
            total_checks = sum(u.get("total", 1) for u in detected_urls) or 1
            ratio = positives / total_checks
            evidence.append(self._reputation_evidence(entity, ratio, positives, len(detected_urls)))

        for sub in data.get("subdomains", [])[:15]:
            evidence.append(
                Evidence(
                    source=self.name,
                    entity_id=entity.id,
                    signal="vt_related_domain",
                    value=sub,
                    evidence_type="infrastructure",
                    polarity=Polarity.NEUTRAL,
                    confidence=0.5,
                    independence=Independence.DERIVED,
                    provenance="VirusTotal-reported subdomain",
                )
            )

        for res in data.get("resolutions", [])[:15]:
            ip = res.get("ip_address")
            if ip:
                evidence.append(
                    Evidence(
                        source=self.name,
                        entity_id=entity.id,
                        signal="vt_communicating_ip",
                        value=ip,
                        evidence_type="infrastructure",
                        polarity=Polarity.NEUTRAL,
                        confidence=0.6,
                        independence=Independence.INDEPENDENT,
                        provenance=f"VirusTotal-reported historical resolution ({res.get('last_resolved', 'unknown date')})",
                    )
                )

        if data.get("categories") and any("phishing" in c.lower() or "malware" in c.lower() for c in data["categories"]):
            evidence.append(
                Evidence(
                    source=self.name,
                    entity_id=entity.id,
                    signal="malicious_category",
                    value=data["categories"],
                    evidence_type="reputation",
                    polarity=Polarity.SUPPORTS_THREAT,
                    confidence=0.7,
                    independence=Independence.INDEPENDENT,
                    provenance="VirusTotal category classification flags this domain",
                )
            )

        if not evidence:
            evidence.append(
                Evidence(
                    source=self.name,
                    entity_id=entity.id,
                    signal="no_detections",
                    value=0,
                    evidence_type="reputation",
                    polarity=Polarity.NEUTRAL,
                    confidence=0.3,
                    independence=Independence.INDEPENDENT,
                    provenance="VirusTotal has no detection history for this domain (absence of evidence, not evidence of absence)",
                )
            )

        return CollectorResult(evidence=evidence, available=True)

    def _collect_url(self, entity: Entity) -> CollectorResult:
        resp = requests.get(
            f"{self.BASE_URL}/url/report",
            params={"apikey": self.api_key, "resource": entity.value},
            timeout=10,
        )
        status = self._check_status(resp)
        if status is not None:
            return status
        data = resp.json()

        positives = data.get("positives", 0)
        total = data.get("total", 0) or 1
        ratio = positives / total
        evidence = [self._reputation_evidence(entity, ratio, positives, total)]

        return CollectorResult(evidence=evidence, available=True)

    def _collect_hash(self, entity: Entity) -> CollectorResult:
        resp = requests.get(
            f"{self.BASE_URL}/file/report",
            params={"apikey": self.api_key, "resource": entity.value},
            timeout=10,
        )
        status = self._check_status(resp)
        if status is not None:
            return status
        data = resp.json()

        positives = data.get("positives", 0)
        total = data.get("total", 0) or 1
        ratio = positives / total
        evidence = [self._reputation_evidence(entity, ratio, positives, total)]

        return CollectorResult(evidence=evidence, available=True)

    # -- helpers --------------------------------------------------------------

    def _check_status(self, resp: requests.Response) -> CollectorResult | None:
        if resp.status_code == 204:
            return CollectorResult(evidence=[], available=False, note="VirusTotal rate limit exceeded")
        if resp.status_code == 403:
            return CollectorResult(evidence=[], available=False, note="VirusTotal API key invalid")
        if resp.status_code != 200:
            return CollectorResult(evidence=[], available=False, note=f"VirusTotal HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError:
            return CollectorResult(evidence=[], available=False, note="VirusTotal returned non-JSON response")
        if data.get("response_code") != 1:
            return CollectorResult(evidence=[], available=False, note="VirusTotal has no data for this artifact (not checked, not confirmed clean)")
        return None

    def _reputation_evidence(self, entity: Entity, ratio: float, positives: int, total: int) -> Evidence:
        if ratio >= 0.1:
            polarity = Polarity.SUPPORTS_THREAT
            confidence = min(0.95, 0.5 + ratio)
        elif positives == 0:
            polarity = Polarity.NEUTRAL
            confidence = 0.4
        else:
            polarity = Polarity.NEUTRAL
            confidence = 0.4

        return Evidence(
            source=self.name,
            entity_id=entity.id,
            signal="malicious_detection",
            value=f"{positives}/{total}",
            evidence_type="reputation",
            polarity=polarity,
            confidence=round(confidence, 2),
            independence=Independence.INDEPENDENT,
            provenance=f"{positives} of {total} VirusTotal engines flagged this artifact",
        )
