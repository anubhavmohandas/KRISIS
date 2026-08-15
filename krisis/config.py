"""
Configuration and default dependency wiring for KRISIS.

Keeps the "how do I build a working Investigator" logic in one place so the
CLI stays thin and tests can build their own Investigator with fake
collectors instead of real network-calling ones.

Provider policy lives here too — request rates, daily quotas and cache lifetimes
are operational configuration, not intelligence, and every one of them is
overridable by environment variable. Nothing here decides anything about a
threat; it only decides what KRISIS is allowed to spend finding out.
"""

from __future__ import annotations

import os
from typing import Optional

from . import credentials
from .collectors.base import EvidenceCollector
from .collectors.dns_collector import DNSCollector
from .collectors.identity_collector import IdentityCollector
from .collectors.ip_collector import IPCollector
from .collectors.tls_collector import TLSCollector
from .collectors.virustotal_collector import VirusTotalCollector
from .collectors.whois_collector import WHOISCollector
from .core.identity import references_from_file
from .core.models import Entity, Evidence, Outcome
from .core.provider_planner import ProviderPlanner, ProviderPolicy

# The AI layer explains a finished investigation; it never produces one, so the
# model is swappable without touching anything that decides a score.
DEFAULT_AI_MODEL = "nvidia/nemotron-3-super-120b-a12b"
DEFAULT_AI_BASE_URL = "https://integrate.api.nvidia.com/v1"

# Outcomes that disqualify a prior seed from serving as a reference identity.
# A domain KRISIS confirmed malicious is not an identity worth protecting, and
# treating it as one would let a confirmed phishing domain define what future
# artifacts are "impersonating".
_UNTRUSTED_REFERENCE_OUTCOMES = frozenset(
    {Outcome.CONFIRMED_MALICIOUS.value, Outcome.FALSE_NEGATIVE.value}
)


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


def load_api_keys(path: str = credentials.LEGACY_KEYS_FILE) -> dict[str, str]:
    """Deprecated: kept so existing callers/tests keep working. Key resolution now
    lives in krisis.credentials, which also handles the user-level store."""
    return credentials.stored_values() if path == credentials.LEGACY_KEYS_FILE else {}


def virustotal_api_key(file_keys: Optional[dict[str, str]] = None) -> Optional[str]:
    return credentials.resolve("VIRUSTOTAL_API_KEY")


def ai_model() -> str:
    return os.environ.get("KRISIS_AI_MODEL") or DEFAULT_AI_MODEL


def ai_base_url() -> str:
    return (os.environ.get("KRISIS_AI_BASE_URL") or DEFAULT_AI_BASE_URL).rstrip("/")


def provider_policies() -> dict[str, ProviderPolicy]:
    """What each provider costs KRISIS and how freely it may be spent.

    DNS, WHOIS, TLS and IP/RDAP lookups are cheap and unmetered, so they enrich
    every discovered entity. VirusTotal is metered — the free tier allows 4
    requests a minute and 500 a day — so it is reserved for the seed and for pivots
    strong enough to justify a request, cached for a day, and backed off from the
    moment it pushes back.
    """
    cheap_ttl = _env_float("KRISIS_CACHE_TTL", 3600.0)
    cheap = dict(broad_enrichment=True, cache_ttl_seconds=cheap_ttl)
    return {
        "dns": ProviderPolicy(name="dns", **cheap),
        "whois": ProviderPolicy(name="whois", **cheap),
        "tls": ProviderPolicy(name="tls", **cheap),
        "ip_whois": ProviderPolicy(name="ip_whois", **cheap),
        "identity": ProviderPolicy(name="identity", broad_enrichment=True, cache_ttl_seconds=0.0),
        "virustotal": ProviderPolicy(
            name="virustotal",
            broad_enrichment=False,
            cache_ttl_seconds=_env_float("KRISIS_VT_CACHE_TTL", 86400.0),
            rate_per_minute=_env_int("KRISIS_VT_RATE_PER_MIN", 4),
            daily_quota=_env_int("KRISIS_VT_DAILY_QUOTA", 500),
            backoff_seconds=_env_float("KRISIS_VT_BACKOFF", 300.0),
            min_pivot_priority=_env_float("KRISIS_VT_MIN_PIVOT_PRIORITY", 0.7),
            max_wait_seconds=_env_float("KRISIS_VT_MAX_WAIT", 0.0),
        ),
    }


def build_planner(storage: Optional[object] = None) -> ProviderPlanner:
    return ProviderPlanner(policies=provider_policies(), storage=storage)


def identity_references(storage: Optional[object] = None) -> set[str]:
    """Identities KRISIS can compare a name against: whatever the user configured,
    plus domains it has investigated before.

    Case memory is used deliberately rather than a shipped brand list — KRISIS
    should know about the identities its operator actually cares about, and it
    learns those by being pointed at them.
    """
    references = references_from_file()
    if storage is None:
        return references
    try:
        for row in storage.list_cases(limit=500):
            if row.get("seed_type") == "domain" and row.get("outcome") not in _UNTRUSTED_REFERENCE_OUTCOMES:
                references.add(str(row["seed"]).lower())
    except Exception:
        pass
    return references


def default_collectors(
    planner: Optional[ProviderPlanner] = None, storage: Optional[object] = None
) -> list[EvidenceCollector]:
    """The provider set KRISIS ships with. Every one degrades gracefully and
    independently if unavailable/misconfigured (see PROVIDER-AGNOSTIC ARCHITECTURE)."""
    dns, whois = DNSCollector(), WHOISCollector()

    def probe(entity: Entity) -> list[Evidence]:
        """Registration/hosting facts about a candidate identity, through the planner
        so the requests are budgeted, cached and deduplicated like any other."""
        evidence: list[Evidence] = []
        for collector in (dns, whois):
            if not collector.can_handle(entity):
                continue
            result = planner.collect(collector, entity)[0] if planner else collector.collect(entity)
            evidence.extend(result.evidence)
        return evidence

    return [
        dns,
        whois,
        TLSCollector(),
        IPCollector(),
        VirusTotalCollector(api_key=virustotal_api_key()),
        # Last: by now the seed's own DNS/WHOIS answers are already in the planner's
        # session cache, so identity verification reuses them instead of re-asking.
        IdentityCollector(probe=probe, references=lambda: identity_references(storage)),
    ]
