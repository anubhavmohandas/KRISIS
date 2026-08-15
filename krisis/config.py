"""
Configuration and default dependency wiring for KRISIS.

Keeps the "how do I build a working Investigator" logic in one place so the
CLI stays thin and tests can build their own Investigator with fake
collectors instead of real network-calling ones.
"""

from __future__ import annotations

import os
from typing import Optional

from .collectors.base import EvidenceCollector
from .collectors.dns_collector import DNSCollector
from .collectors.ip_collector import IPCollector
from .collectors.tls_collector import TLSCollector
from .collectors.virustotal_collector import VirusTotalCollector
from .collectors.whois_collector import WHOISCollector


def load_api_keys(path: str = "api_keys.txt") -> dict[str, str]:
    """Load KEY=VALUE pairs from a local file (never committed) as a fallback
    when the corresponding environment variable isn't set."""
    keys: dict[str, str] = {}
    if os.path.exists(path):
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    keys[k.strip()] = v.strip()
    return keys


def virustotal_api_key(file_keys: Optional[dict[str, str]] = None) -> Optional[str]:
    if os.environ.get("VIRUSTOTAL_API_KEY"):
        return os.environ["VIRUSTOTAL_API_KEY"]
    file_keys = file_keys or load_api_keys()
    return file_keys.get("VIRUSTOTAL_API_KEY")


def default_collectors() -> list[EvidenceCollector]:
    """The provider set KRISIS ships with. Every one degrades gracefully and
    independently if unavailable/misconfigured (see PROVIDER-AGNOSTIC ARCHITECTURE)."""
    file_keys = load_api_keys()
    return [
        DNSCollector(),
        WHOISCollector(),
        TLSCollector(),
        IPCollector(),
        VirusTotalCollector(api_key=virustotal_api_key(file_keys)),
    ]
