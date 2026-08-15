"""
Configuration and default dependency wiring for KRISIS.

Keeps the "how do I build a working Investigator" logic in one place so the
CLI stays thin and tests can build their own Investigator with fake
collectors instead of real network-calling ones.
"""

from __future__ import annotations

import os
from typing import Optional

from . import credentials
from .collectors.base import EvidenceCollector
from .collectors.dns_collector import DNSCollector
from .collectors.ip_collector import IPCollector
from .collectors.tls_collector import TLSCollector
from .collectors.virustotal_collector import VirusTotalCollector
from .collectors.whois_collector import WHOISCollector


def load_api_keys(path: str = credentials.LEGACY_KEYS_FILE) -> dict[str, str]:
    """Deprecated: kept so existing callers/tests keep working. Key resolution now
    lives in krisis.credentials, which also handles the user-level store."""
    return credentials.stored_values() if path == credentials.LEGACY_KEYS_FILE else {}


def virustotal_api_key(file_keys: Optional[dict[str, str]] = None) -> Optional[str]:
    return credentials.resolve("VIRUSTOTAL_API_KEY")


def default_collectors() -> list[EvidenceCollector]:
    """The provider set KRISIS ships with. Every one degrades gracefully and
    independently if unavailable/misconfigured (see PROVIDER-AGNOSTIC ARCHITECTURE)."""
    return [
        DNSCollector(),
        WHOISCollector(),
        TLSCollector(),
        IPCollector(),
        VirusTotalCollector(api_key=virustotal_api_key()),
    ]
