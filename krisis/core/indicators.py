"""
Indicator extraction (see PRIMARY INPUTS / secondary indicator extraction in the
design doc). Deliberately simple regex-based extraction for the first
implementation — the architecture (returning a list of (EntityType, value))
lets more sophisticated extractors be swapped in later without touching the
investigator.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from .models import EntityType

_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)
_URL_RE = re.compile(r"\bhttps?://[^\s<>\"']+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_HASH_RE = {
    32: re.compile(r"\b[a-fA-F0-9]{32}\b"),   # md5
    40: re.compile(r"\b[a-fA-F0-9]{40}\b"),   # sha1
    64: re.compile(r"\b[a-fA-F0-9]{64}\b"),   # sha256
}


def classify_seed(raw: str) -> tuple[EntityType, str]:
    """Determine the seed's entity type from a single raw CLI argument."""
    raw = raw.strip()

    if raw.lower().startswith(("http://", "https://")):
        return EntityType.URL, raw

    try:
        ipaddress.ip_address(raw)
        return EntityType.IP, raw
    except ValueError:
        pass

    for length, pattern in _HASH_RE.items():
        if len(raw) == length and pattern.fullmatch(raw):
            return EntityType.HASH, raw.lower()

    if _EMAIL_RE.fullmatch(raw):
        return EntityType.EMAIL, raw

    if _DOMAIN_RE.fullmatch(raw):
        return EntityType.DOMAIN, raw.lower()

    # Fall back to treating unrecognized multi-line / free text as a message to mine.
    return EntityType.MESSAGE, raw


def extract_from_text(text: str) -> list[tuple[EntityType, str]]:
    """Pull secondary indicators (URLs, domains, emails, hashes) out of free text,
    e.g. a suspicious SMS/email body."""
    found: list[tuple[EntityType, str]] = []
    seen: set[str] = set()

    for match in _URL_RE.findall(text):
        key = f"url:{match.lower()}"
        if key not in seen:
            seen.add(key)
            found.append((EntityType.URL, match))

    for match in _DOMAIN_RE.findall(text):
        key = f"domain:{match.lower()}"
        if key not in seen:
            seen.add(key)
            found.append((EntityType.DOMAIN, match.lower()))

    for match in _EMAIL_RE.findall(text):
        key = f"email:{match.lower()}"
        if key not in seen:
            seen.add(key)
            found.append((EntityType.EMAIL, match))

    for length, pattern in _HASH_RE.items():
        for match in pattern.findall(text):
            key = f"hash:{match.lower()}"
            if key not in seen:
                seen.add(key)
                found.append((EntityType.HASH, match.lower()))

    return found


def domain_from_url(url: str) -> str | None:
    try:
        parsed = urlparse(url)
        return parsed.hostname
    except Exception:
        return None


# Multi-label public suffixes common enough to matter for registrable-domain
# comparison. This is a deliberate approximation of the Public Suffix List.
# occam: static suffix list, swap for the `tldextract` package if suffix accuracy
# starts producing real misclassifications — the failure mode is only that two
# hosts under an unusual multi-part ccTLD look like different organizations.
_MULTI_LABEL_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "net.nz", "org.nz", "govt.nz",
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
        "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in",
        "com.br", "net.br", "org.br", "gov.br",
        "co.za", "org.za", "gov.za",
        "com.cn", "net.cn", "org.cn", "gov.cn",
        "com.sg", "com.hk", "com.mx", "com.tr", "com.ar", "com.tw",
    }
)


def registrable_domain(host: str) -> str:
    """Approximate eTLD+1 — the part of a hostname that identifies an organization.

    Used to tell "this host belongs to the same organization as the seed" from
    "this host belongs to a third party", which is what separates a meaningful
    infrastructure relationship from a shared commodity service.
    """
    host = (host or "").strip().strip(".").lower()
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return host  # an IP is its own identity; it has no registrable domain
    except ValueError:
        pass

    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def same_organization(host_a: str, host_b: str) -> bool:
    """True if two hostnames sit under the same registrable domain."""
    a, b = registrable_domain(host_a), registrable_domain(host_b)
    return bool(a) and a == b
