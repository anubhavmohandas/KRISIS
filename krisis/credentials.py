"""
Credential resolution and on-disk storage for optional provider API keys.

KRISIS runs with zero keys configured — every collector degrades independently
(see PROVIDER FAILURE). Keys only ever *add* evidence sources. This module owns
three things and nothing else:

  1. what keys exist, what each one buys, and where a user gets one
  2. resolving a key from env -> user config -> legacy project file
  3. persisting a key, or persisting the fact that the user declined it

Declining is recorded explicitly (an empty value in the store) so KRISIS can
tell "the user chose to skip this" from "we never asked", and report the former
in its output instead of silently pretending the source did not exist.

The CLI owns all interaction; this module never prompts.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from typing import Optional

LEGACY_KEYS_FILE = "api_keys.txt"


@dataclass(frozen=True)
class ProviderKey:
    provider: str          # collector name this key enables, e.g. "virustotal"
    env_var: str
    label: str
    purpose: str           # what KRISIS can do with it
    impact_if_missing: str  # what the investigation loses without it
    signup_url: str
    steps: tuple[str, ...]
    free_tier: str = ""
    # False for components that do not contribute evidence. The AI layer only
    # rewrites a finished investigation, so listing it among evidence sources would
    # misrepresent where KRISIS's conclusions come from.
    is_evidence_source: bool = True


# Only keys that a shipped component actually reads. Nothing speculative:
# virustotal -> VirusTotalCollector, anthropic -> ai.explain.Explainer.
PROVIDER_KEYS: tuple[ProviderKey, ...] = (
    ProviderKey(
        provider="virustotal",
        env_var="VIRUSTOTAL_API_KEY",
        label="VirusTotal",
        purpose="Threat reputation for domains, URLs, IPs and file hashes, plus "
                "VirusTotal's own related-domain and resolved-IP data as pivot candidates.",
        impact_if_missing="KRISIS has no threat-reputation source. A clean-looking artifact "
                          "will be reported as INSUFFICIENT_EVIDENCE rather than LOW risk, "
                          "because nothing actually checked its reputation.",
        signup_url="https://www.virustotal.com/gui/join-us",
        steps=(
            "Open https://www.virustotal.com/gui/join-us and sign up (or sign in)",
            "Click your avatar in the top-right corner",
            "Choose 'API key' from the menu",
            "Copy the 64-character key",
        ),
        free_tier="Free tier: 4 requests/min, 500/day — enough for CLI investigations.",
    ),
    ProviderKey(
        provider="nvidia",
        env_var="NVIDIA_API_KEY",
        label="NVIDIA NIM (AI explanation layer)",
        purpose="Rewrites the completed investigation into plain-language prose using "
                "Nemotron. It only ever explains evidence KRISIS already collected, and "
                "never sees the artifact — only the finished findings.",
        impact_if_missing="Explanations fall back to the built-in deterministic template. "
                          "Risk scoring, correlation and evidence are completely unaffected — "
                          "the AI layer never detects anything.",
        signup_url="https://build.nvidia.com",
        steps=(
            "Open https://build.nvidia.com and sign in",
            "Open any model page and click 'Get API Key'",
            "Copy the key (it starts with 'nvapi-')",
        ),
        free_tier="Free credits on signup; usage is a few thousand tokens per investigation. "
                  "Override the model with KRISIS_AI_MODEL.",
        is_evidence_source=False,
    ),
)

PROVIDER_KEYS_BY_NAME = {p.provider: p for p in PROVIDER_KEYS}


def krisis_home() -> str:
    """Where KRISIS keeps user-level state. Override with KRISIS_HOME."""
    return os.environ.get("KRISIS_HOME") or os.path.join(os.path.expanduser("~"), ".krisis")


def keys_file() -> str:
    return os.path.join(krisis_home(), "api_keys.txt")


def _read_key_file(path: str) -> dict[str, str]:
    """Parse KEY=VALUE lines. An empty value is meaningful: it records that the
    user was asked for this key and chose to skip it."""
    values: dict[str, str] = {}
    if not os.path.exists(path):
        return values
    try:
        with open(path, "r") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
    except OSError:
        return {}
    return values


def stored_values() -> dict[str, str]:
    """User store layered over the legacy project-local file."""
    merged = _read_key_file(os.path.join(os.getcwd(), LEGACY_KEYS_FILE))
    merged.update(_read_key_file(keys_file()))
    return merged


def resolve(env_var: str) -> Optional[str]:
    """The effective key value, or None if unset/skipped.

    Environment always wins so CI and one-off overrides never fight the stored file.
    """
    from_env = os.environ.get(env_var)
    if from_env:
        return from_env.strip() or None
    return stored_values().get(env_var) or None


def was_declined(env_var: str) -> bool:
    """True if the user explicitly skipped this key.

    Only the KRISIS-managed store counts. The legacy project-local api_keys.txt ships
    as a template with blank values, which mean "not filled in" — reading those as a
    deliberate decline would stop KRISIS ever offering to configure the key.
    """
    if os.environ.get(env_var):
        return False
    values = _read_key_file(keys_file())
    return env_var in values and not values[env_var]


def needs_prompt(env_var: str) -> bool:
    """True only if we have neither a key nor a recorded decision."""
    return resolve(env_var) is None and not was_declined(env_var)


def save(env_var: str, value: str) -> str:
    """Persist a key (or a skip, when value is empty) to the user store.

    Returns the path written. The file holds credentials, so it is created 0600
    and the directory 0700 — a world-readable API key in a home directory is a
    real leak, not a theoretical one.
    """
    home = krisis_home()
    os.makedirs(home, exist_ok=True)
    try:
        os.chmod(home, stat.S_IRWXU)
    except OSError:
        pass

    path = keys_file()
    existing = _read_key_file(path)
    existing[env_var] = value.strip()

    header = (
        "# KRISIS provider credentials.\n"
        "# Managed by `krisis setup`. Environment variables of the same name win.\n"
        "# An empty value means the key was deliberately skipped; KRISIS reports it\n"
        "# as skipped rather than pretending the source was checked.\n"
    )
    # Write with restrictive permissions from the start rather than chmod-ing after,
    # so the key is never briefly readable by other users.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w") as fh:
        fh.write(header)
        for key, val in sorted(existing.items()):
            fh.write(f"{key}={val}\n")
    return path


def mask(value: str) -> str:
    """Render a key for confirmation without printing it in full."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def verify(spec: ProviderKey, value: str, timeout: int = 10) -> tuple[bool, str]:
    """Check a key against the provider, using the same endpoint the collector uses
    so a passing check actually predicts a working collector.

    Returns (ok, message). Network problems return ok=True with a note — refusing a
    key because the user is briefly offline would be worse than accepting it.
    """
    try:
        import requests
    except ImportError:
        return True, "could not verify (requests not installed)"

    try:
        if spec.provider == "virustotal":
            resp = requests.get(
                "https://www.virustotal.com/vtapi/v2/domain/report",
                params={"apikey": value, "domain": "google.com"},
                timeout=timeout,
            )
            if resp.status_code == 200:
                return True, "key verified against VirusTotal"
            if resp.status_code in (401, 403):
                return False, "VirusTotal rejected this key (401/403)"
            if resp.status_code == 204:
                return True, "key accepted (rate limit reached during check)"
            return True, f"could not verify (HTTP {resp.status_code})"

        if spec.provider == "nvidia":
            from .config import ai_base_url

            resp = requests.get(
                f"{ai_base_url()}/models",
                headers={"Authorization": f"Bearer {value}"},
                timeout=timeout,
            )
            if resp.status_code == 200:
                return True, "key verified against the NVIDIA API"
            if resp.status_code in (401, 403):
                return False, "NVIDIA rejected this key (401/403)"
            return True, f"could not verify (HTTP {resp.status_code})"
    except Exception as exc:
        return True, f"could not verify (network error: {exc})"

    return True, "no verification available for this provider"
