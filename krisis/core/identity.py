"""
Identity analysis — what identity does this artifact appear to claim?

KRISIS could investigate the infrastructure around `paypa1.com` and still report
LOW, because nothing in the pipeline looked at the name itself. Infrastructure
answers "what is this connected to". Identity answers "who is this pretending to
be", and for consumer-facing fraud that is usually the whole attack.

This module is deliberately value-free: it derives *candidate* identities an
artifact may be imitating, and says exactly how each candidate was derived. It
never decides that a candidate relationship is malicious — that requires
verifying the referent actually exists, predates the artifact, and belongs to
someone else, which is evidence collection, not string manipulation
(krisis/collectors/identity_collector.py).

Three general mechanisms, no brand list anywhere:

  1. confusable characters — glyphs chosen to be misread ("1" for "l", Cyrillic
     "а" for "a", "rn" for "m"), plus IDN/punycode decoding. Mapping is strictly
     one-directional, deceptive glyph -> the character it imitates, so a name
     containing no deceptive glyph produces no candidates at all. That is what
     keeps a legitimate domain from being accused of impersonating itself.
  2. decoration tokens — "<something>-login", "secure-<something>". The
     decoration lexicon is a configured knowledge source, not a brand map: it
     describes how phishing hostnames are *built*, and says nothing about who is
     being impersonated.
  3. reference similarity — near-identical labels against known identities,
     which come from case memory and user configuration at runtime.

A hardcoded "paypa1.com -> PayPal" rule would be exactly the fake intelligence
this system exists to avoid. Every relationship here is derived, then verified.
"""

from __future__ import annotations

import difflib
import os
from dataclasses import dataclass

from .indicators import registrable_domain

# Deceptive glyph -> the ASCII character(s) it imitates, most likely reading first.
# One-directional by design. Several glyphs are genuinely ambiguous — "1" passes for
# both "l" and "i", which is why `netfl1x` has to be read as `netflix` and not only
# as `netfllx` — so each reading is generated and then verified separately.
# occam: hand-picked subset of the Unicode confusables table, extend when a real
# case shows a substitution KRISIS missed — the failure mode is a missed
# candidate, never a fabricated one.
CONFUSABLE_CHARS: dict[str, str] = {
    "0": "o", "1": "li", "3": "e", "4": "a", "5": "s", "6": "gb", "7": "t", "8": "b",
    "9": "gq", "$": "s", "|": "li", "!": "il",
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
    "с": "c", "т": "t", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d",
    # Greek
    "α": "a", "ε": "e", "ι": "i", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "ν": "v",
}

# Multi-character substitutions that survive a glance at a browser bar.
CONFUSABLE_SEQUENCES: dict[str, str] = {"rn": "m", "vv": "w"}

# Words that decorate an impersonated name rather than identify anyone. Extend
# with KRISIS_DECORATION_TOKENS (comma-separated) — it is configuration about
# attacker grammar, not about any particular brand.
DEFAULT_DECORATION_TOKENS = frozenset({
    "login", "signin", "sign", "log", "account", "accounts", "secure", "security",
    "verify", "verification", "confirm", "update", "support", "help", "service",
    "services", "billing", "payment", "payments", "pay", "wallet", "auth", "id",
    "portal", "online", "web", "mail", "alert", "notice", "recovery", "unlock",
    "customer", "care", "official", "app", "mobile", "access", "center", "centre",
})

# A token shorter than this is not a recognisable identity on its own.
MIN_TOKEN_LENGTH = 4
# How alike two labels must be before one is treated as imitating the other.
MIN_REFERENCE_SIMILARITY = 0.82


@dataclass(frozen=True)
class LookalikeCandidate:
    """An identity the artifact may be imitating, and exactly how KRISIS got there."""

    value: str          # the candidate referent, e.g. "example.com"
    method: str         # confusable_characters | decoration_token | reference_similarity
    similarity: float   # 0..1 label similarity between artifact and candidate
    derivation: str     # human-readable derivation, carried into evidence provenance

    def to_dict(self) -> dict:
        return {
            "value": self.value, "method": self.method,
            "similarity": round(self.similarity, 3), "derivation": self.derivation,
        }


def decoration_tokens() -> frozenset[str]:
    extra = os.environ.get("KRISIS_DECORATION_TOKENS", "")
    if not extra:
        return DEFAULT_DECORATION_TOKENS
    return DEFAULT_DECORATION_TOKENS | {t.strip().lower() for t in extra.split(",") if t.strip()}


def decode_idn(host: str) -> str:
    """Punycode -> the Unicode the user actually sees. An `xn--` label is opaque in
    ASCII, which is the point of using one to impersonate."""
    labels = []
    for label in (host or "").split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except Exception:
                pass
        labels.append(label)
    return ".".join(labels)


# An ambiguous glyph doubles the number of readings, so a label full of them would
# explode combinatorially. The cap keeps the most likely readings and drops the rest.
MAX_READINGS = 8


def canonical_label(label: str) -> str:
    """The label as a reader is most likely to perceive it, deceptive glyphs resolved."""
    return canonical_readings(label)[0]


def canonical_readings(label: str) -> list[str]:
    """Every plausible reading of a label, most likely first.

    Ambiguity is preserved rather than guessed at: each reading becomes a candidate
    that must independently survive verification, so the wrong reading of a glyph
    costs a cheap DNS lookup instead of a wrong conclusion.
    """
    readings = [""]
    for ch in label.lower():
        alternatives = CONFUSABLE_CHARS.get(ch, ch)
        readings = [prefix + alt for prefix in readings for alt in alternatives][:MAX_READINGS]
    for sequence, replacement in CONFUSABLE_SEQUENCES.items():
        readings += [r.replace(sequence, replacement) for r in readings if sequence in r]
    # dict.fromkeys: de-duplicate while keeping "most likely first" ordering
    return list(dict.fromkeys(readings))[:MAX_READINGS] or [label.lower()]


def _split(host: str) -> tuple[str, str]:
    """(name, suffix) of the registrable domain — 'paypa1', 'com'."""
    registrable = registrable_domain(decode_idn(host))
    name, _, suffix = registrable.partition(".")
    return name, suffix


def label_similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a.lower(), b.lower()).ratio()


def _core_tokens(name: str) -> list[str]:
    """Identity-bearing tokens of a decorated label: 'paypal' from 'paypal-login'.

    Only fires when at least one *other* token is a known decoration word. Without
    that test, 'my-company.com' would be read as imitating 'company.com', which is
    an ordinary hostname, not an impersonation.
    """
    tokens = [t for t in name.replace("_", "-").split("-") if t]
    if len(tokens) < 2:
        return []
    decorations = decoration_tokens()
    if not any(t in decorations for t in tokens):
        return []
    return [t for t in tokens if t not in decorations and len(t) >= MIN_TOKEN_LENGTH]


def candidates(host: str, references: set[str] | None = None) -> list[LookalikeCandidate]:
    """Identities `host` may be imitating, strongest first.

    references: identities KRISIS already knows about — prior case seeds and any
    user-configured list. They only ever *add* cross-TLD candidates; the confusable
    and decoration mechanisms work on an empty database, which matters because the
    first investigation of a typosquat has no history to lean on.
    """
    name, suffix = _split(host)
    if not name or not suffix:
        return []

    found: dict[str, LookalikeCandidate] = {}

    def offer(value: str, method: str, derivation: str) -> None:
        value = value.lower()
        if not value or value == f"{name}.{suffix}".lower() or value == (host or "").lower():
            return
        similarity = label_similarity(name, _split(value)[0])
        existing = found.get(value)
        if existing is None or similarity > existing.similarity:
            found[value] = LookalikeCandidate(value, method, similarity, derivation)

    # 1. confusable characters, under the artifact's own suffix
    readings = canonical_readings(name)
    resolved = readings[0]
    substituted = sorted({ch for ch in name.lower() if CONFUSABLE_CHARS.get(ch)})
    for reading in readings:
        if reading == name.lower():
            continue
        offer(
            f"{reading}.{suffix}", "confusable_characters",
            f"'{name}' reads as '{reading}' once look-alike character(s) "
            f"{', '.join(repr(c) for c in substituted) or 'sequence'} are resolved",
        )

    # 2. decoration tokens, under the artifact's own suffix
    for token in _core_tokens(name):
        offer(
            f"{token}.{suffix}", "decoration_token",
            f"'{name}' is '{token}' plus decoration wording that carries no identity",
        )
        # A decorated name is often also glyph-substituted: paypa1-login.
        token_resolved = canonical_label(token)
        if token_resolved != token:
            offer(
                f"{token_resolved}.{suffix}", "decoration_token",
                f"'{name}' is '{token}' plus decoration wording, and '{token}' itself "
                f"reads as '{token_resolved}' once look-alike characters are resolved",
            )

    # 3. known identities, which unlocks cross-TLD matches the above cannot see
    for reference in references or set():
        ref_name, ref_suffix = _split(reference)
        if not ref_name or not ref_suffix or (ref_name, ref_suffix) == (name, suffix):
            continue
        if canonical_label(ref_name) == resolved and ref_name != name.lower():
            offer(
                f"{ref_name}.{ref_suffix}", "confusable_characters",
                f"'{name}' and the known identity '{ref_name}.{ref_suffix}' are the same "
                f"string once look-alike characters are resolved",
            )
        elif any(token == ref_name for token in _core_tokens(name)):
            offer(
                f"{ref_name}.{ref_suffix}", "decoration_token",
                f"'{name}' is the known identity '{ref_name}' plus decoration wording",
            )
        else:
            similarity = label_similarity(name, ref_name)
            if similarity >= MIN_REFERENCE_SIMILARITY:
                offer(
                    f"{ref_name}.{ref_suffix}", "reference_similarity",
                    f"'{name}' is {similarity:.0%} identical to the known identity "
                    f"'{ref_name}.{ref_suffix}'",
                )

    return sorted(found.values(), key=lambda c: c.similarity, reverse=True)


def references_from_file(path: str | None = None) -> set[str]:
    """User-configured identities to compare against. Absent by default: KRISIS ships
    with no opinion about which brands exist."""
    path = path or os.environ.get("KRISIS_IDENTITY_REFERENCES") or os.path.join(
        os.environ.get("KRISIS_HOME") or os.path.join(os.path.expanduser("~"), ".krisis"),
        "identity_references.txt",
    )
    references: set[str] = set()
    if not os.path.exists(path):
        return references
    try:
        with open(path, "r", errors="ignore") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip().lower()
                if line:
                    references.add(line)
    except OSError:
        pass
    return references
