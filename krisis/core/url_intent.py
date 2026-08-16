"""
URL-intent analysis — what does a URL's path/query *say* it does?

A signal, never a verdict: "/login" on a bank's own domain is completely
normal. Intent only becomes meaningful once correlated with identity/behavior
evidence elsewhere in the pipeline (see risk.py's interaction bonus). No brand
list here either — this only reads the URL's own path and query, nothing
about who registered it.
"""

from __future__ import annotations

import ipaddress
import os
import re
from urllib.parse import urlparse

# Token -> intent category. Configuration about how authentication/financial
# flows are shaped, not a judgment about any particular URL. Extend with
# KRISIS_URL_INTENT_TOKENS="token:category,token:category".
DEFAULT_INTENT_TOKENS: dict[str, str] = {
    "login": "authentication_intent", "signin": "authentication_intent",
    "logon": "authentication_intent", "verify": "authentication_intent",
    "verification": "authentication_intent", "authenticate": "authentication_intent",
    "auth": "authentication_intent", "account": "authentication_intent",
    "session": "authentication_intent", "2fa": "authentication_intent",
    "otp": "authentication_intent", "mfa": "authentication_intent",
    "password": "credential_intent", "passwd": "credential_intent",
    "credential": "credential_intent", "credentials": "credential_intent",
    "payment": "financial_intent", "payments": "financial_intent",
    "billing": "financial_intent", "invoice": "financial_intent",
    "wallet": "financial_intent", "checkout": "financial_intent",
    "bank": "financial_intent", "refund": "financial_intent",
    "recover": "recovery_intent", "recovery": "recovery_intent",
    "unlock": "recovery_intent", "restore": "recovery_intent",
    "security": "recovery_intent", "suspended": "recovery_intent",
    "locked": "recovery_intent",
}

_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def intent_tokens() -> dict[str, str]:
    extra = os.environ.get("KRISIS_URL_INTENT_TOKENS", "")
    if not extra:
        return DEFAULT_INTENT_TOKENS
    merged = dict(DEFAULT_INTENT_TOKENS)
    for pair in extra.split(","):
        token, _, category = pair.partition(":")
        token, category = token.strip().lower(), category.strip()
        if token and category:
            merged[token] = category
    return merged


def classify(url: str) -> dict[str, list[str]]:
    """intent category -> matched tokens, for a single URL's path+query.

    Empty dict means no recognizable intent token was present — an entirely
    ordinary finding for most URLs, not evidence of anything on its own.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return {}
    haystack = f"{parsed.path} {parsed.query}".lower()
    tokens = [t for t in _TOKEN_SPLIT_RE.split(haystack) if t]
    table = intent_tokens()

    found: dict[str, list[str]] = {}
    for token in tokens:
        category = table.get(token)
        if category:
            bucket = found.setdefault(category, [])
            if token not in bucket:
                bucket.append(token)
    return found


def is_ip_literal_host(url: str) -> bool:
    """True if `url`'s host is a literal IP address rather than a domain name —
    a classic way to dodge domain-based reputation/identity checks entirely."""
    try:
        host = urlparse(url).hostname
    except Exception:
        return False
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def has_userinfo(url: str) -> bool:
    """True if `url` embeds userinfo before the host ('https://paypal.com@evil.tld/') —
    a deprecated URL feature with essentially no legitimate modern use, kept alive
    almost exclusively to make an attacker's real host look like a path on the
    brand named before the '@'."""
    try:
        return urlparse(url).username is not None
    except Exception:
        return False
