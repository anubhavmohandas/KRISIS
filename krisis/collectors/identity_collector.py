"""
Identity evidence collector — turns a derived lookalike candidate into evidence,
or refuses to.

krisis/core/identity.py can tell you that `paypa1.com` reads as `paypal.com`.
That alone is a string observation, not a finding: `exarnple.com` reads as
`example.com` whether or not anyone registered the latter. Before KRISIS will
call a name relationship evidence of impersonation, three things have to be
true, and each is checked against the world rather than assumed:

  1. the referent exists       — it resolves
  2. the referent came first   — it is established and materially older
  3. someone else operates it  — no shared resolved address (verified; see
     same_operator()). A matching WHOIS registrant organization is self-reported
     and unverified — it is reported alongside a finding, never in place of one
     (see claimed_same_operator()).

Fail (1) and there is nothing to impersonate. Fail (2) and KRISIS may have the
direction backwards. Fail (3), verified, and this is a brand's own defensive
registration, which is the opposite of a threat — and is reported as
counter-evidence strong enough to stand alone.

The probes reuse the DNS/WHOIS collectors through the provider planner, so
verification costs cheap requests only, is deduplicated against the requests the
investigation already made, and never touches a quota-limited provider.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from ..core.identity import LookalikeCandidate, candidates, decode_idn, mixed_script_label
from ..core.indicators import is_bank_in_namespace, registrable_domain
from ..core.models import Entity, EntityType, Evidence, Independence, Polarity
from .base import CollectorResult, EvidenceCollector

# An identity worth impersonating has to have existed long enough to be worth
# impersonating. Below this, "older" is noise between two recent registrations.
ESTABLISHED_MIN_AGE_DAYS = 730
# How much older the referent must be before KRISIS accepts which of the two is
# the imitation. Registrations days apart cannot settle that question.
AGE_MARGIN_DAYS = 365
# Verifying more than a handful of candidates spends requests on diminishing
# returns; candidates arrive sorted by similarity.
MAX_CANDIDATES_VERIFIED = 3


@dataclass
class DomainFacts:
    """The few registration/hosting facts an identity comparison needs."""

    ips: set[str] = field(default_factory=set)
    nameservers: set[str] = field(default_factory=set)
    age_days: Optional[int] = None
    org: str = ""
    checked: bool = False       # False when no probe could be made at all

    @property
    def resolves(self) -> bool:
        return bool(self.ips)


_AGE_SIGNALS = ("newly_registered_domain", "long_lived_domain", "domain_age_days")


def facts_from_evidence(evidence: list[Evidence]) -> DomainFacts:
    facts = DomainFacts(checked=True)
    for ev in evidence:
        values = ev.value if isinstance(ev.value, list) else [ev.value]
        if ev.signal in ("a_record", "aaaa_record"):
            facts.ips.update(str(v) for v in values if v)
        elif ev.signal == "ns_record":
            facts.nameservers.update(registrable_domain(str(v)) for v in values if v)
        elif ev.signal in _AGE_SIGNALS:
            try:
                facts.age_days = int(ev.value)
            except (TypeError, ValueError):
                pass
        elif ev.signal == "registrant_org":
            facts.org = str(ev.value).strip().lower()
    return facts


def same_operator(a: DomainFacts, b: DomainFacts) -> str:
    """Why these two domains are *verifiably* run by the same operator, or "" if
    that is not established.

    Shared resolution is the only signal here because it is not self-reported:
    an attacker's server cannot also be the legitimate operator's server. Shared
    nameservers do not count either — two unrelated domains behind the same DNS
    vendor would then "prove" common ownership, and this test's whole job is to
    suppress an impersonation finding, so a false match here silently deletes a
    real one. registrant_org is deliberately excluded: see claimed_same_operator.
    """
    shared_ips = a.ips & b.ips
    if shared_ips:
        return f"both resolve to {', '.join(sorted(shared_ips))}"
    return ""


def claimed_same_operator(a: DomainFacts, b: DomainFacts) -> str:
    """Why WHOIS *claims* these two domains share an operator, or "" if it does not.

    registrant_org is free text the registrant supplies; no registry verifies it.
    An attacker registering a lookalike can type the impersonated brand's own
    organization name into it as easily as the brand's own defensive registration
    can — so a match here is a lead, not proof, and must never by itself suppress
    an impersonation finding the way same_operator()'s verified match does (see
    NARROW_CONTRADICTIONS in risk.py, where this signal is discounted).

    occam: compared as a plain string, so 'PayPal Inc.' and 'PayPal, Inc' read as
    different owners. Normalise if real cases show the miss; the failure direction
    is a retained finding, not a suppressed one.
    """
    if a.org and b.org and a.org == b.org:
        return f"both registered to '{a.org}'"
    return ""


class IdentityCollector(EvidenceCollector):
    name = "identity"
    supports = ("domain",)

    def __init__(
        self,
        probe: Optional[Callable[[Entity], list[Evidence]]] = None,
        references: Optional[Callable[[], set[str]]] = None,
    ) -> None:
        """probe(entity) -> evidence about that domain, normally DNS + WHOIS routed
        through the provider planner. Without one, candidates are still reported, but
        only as unverified leads — KRISIS will not claim impersonation it could not check.
        """
        self.probe = probe
        self.references = references or (lambda: set())

    def collect(self, entity: Entity) -> CollectorResult:
        # Namespace/script context is evidence about this artifact's own domain,
        # independent of whether it also happens to derive a lookalike candidate
        # against someone else — so it is collected before, and regardless of,
        # that derivation.
        context = [self._bank_namespace_evidence(entity), self._mixed_script_evidence(entity)]
        context = [ev for ev in context if ev is not None]

        try:
            found = candidates(entity.value, self._references())
        except Exception as exc:
            return CollectorResult(evidence=[], available=False, note=f"identity analysis failed: {exc}")

        if not found:
            return CollectorResult(
                evidence=context, available=True,
                note="no lookalike candidate derived from this name",
            )

        if self.probe is None:
            return CollectorResult(
                evidence=context + [self._unverified(entity, c) for c in found[:MAX_CANDIDATES_VERIFIED]],
                available=True,
                note="candidates derived but not verified (no probe configured)",
            )

        subject = self._facts(entity.value)
        evidence: list[Evidence] = list(context)
        for candidate in found[:MAX_CANDIDATES_VERIFIED]:
            evidence.extend(self._verdict(entity, candidate, subject))
        return CollectorResult(evidence=evidence, available=True)

    # -- internals -------------------------------------------------------------

    def _references(self) -> set[str]:
        try:
            return self.references() or set()
        except Exception:
            return set()

    def _facts(self, domain: str) -> DomainFacts:
        try:
            return facts_from_evidence(self.probe(Entity(value=domain, type=EntityType.DOMAIN)))
        except Exception:
            return DomainFacts(checked=False)

    def _verdict(self, entity: Entity, candidate: LookalikeCandidate, subject: DomainFacts) -> list[Evidence]:
        referent = self._facts(candidate.value)

        if not referent.checked:
            return [self._unverified(entity, candidate, "the referent could not be checked")]
        if not referent.resolves:
            return [self._unverified(
                entity, candidate,
                f"'{candidate.value}' does not resolve, so there is no established "
                f"identity here to impersonate",
            )]

        shared = same_operator(subject, referent)
        if shared:
            return [Evidence(
                source=self.name, entity_id=entity.id, signal="same_operator_variant",
                value=candidate.value, evidence_type="identity",
                polarity=Polarity.CONTRADICTS_THREAT, confidence=0.6,
                independence=Independence.INDEPENDENT,
                provenance=(
                    f"{candidate.derivation}, but the two are operated by the same party "
                    f"({shared}) — consistent with a defensive registration by the identity's "
                    f"own owner rather than impersonation of it"
                ),
            )]

        established = referent.age_days is not None and referent.age_days >= ESTABLISHED_MIN_AGE_DAYS
        older = (
            referent.age_days is not None
            and (subject.age_days is None or referent.age_days - subject.age_days >= AGE_MARGIN_DAYS)
        )
        if not (established and older):
            return [self._unverified(
                entity, candidate,
                self._why_unproven(subject, referent, established, older, candidate.value),
            )]

        age_note = (
            f"'{candidate.value}' has been registered {referent.age_days} days against this "
            f"artifact's {subject.age_days}"
            if subject.age_days is not None
            else f"'{candidate.value}' has been registered {referent.age_days} days, while this "
                 f"artifact's own registration date could not be established"
        )
        verdict = [Evidence(
            source=self.name, entity_id=entity.id, signal="lookalike_domain",
            value=candidate.value, evidence_type="identity",
            polarity=Polarity.SUPPORTS_THREAT,
            confidence=self._confidence(candidate, subject),
            independence=Independence.INDEPENDENT,
            provenance=(
                f"{candidate.derivation}; {age_note}, and the two share no verified operator "
                f"(no common resolved address) — this artifact resembles an established "
                f"identity operated by someone else"
            ),
        )]

        # A matching WHOIS organization name is a lead, not proof (see
        # claimed_same_operator) — it rides alongside the finding above rather than
        # replacing it, so a self-reported string can never be the sole reason a
        # real lookalike scores as safe. risk.py's NARROW_CONTRADICTIONS keeps it
        # from arithmetically offsetting the finding it does not actually rebut.
        claimed = claimed_same_operator(subject, referent)
        if claimed:
            verdict.append(Evidence(
                source=self.name, entity_id=entity.id, signal="claimed_registrant_org_match",
                value=candidate.value, evidence_type="identity",
                polarity=Polarity.CONTRADICTS_THREAT, confidence=0.3,
                independence=Independence.INDEPENDENT,
                provenance=(
                    f"WHOIS lists {candidate.value} under a matching registrant organization "
                    f"({claimed}), but that field is self-reported and unverified by any "
                    f"registry — an attacker can enter any organization name into it as "
                    f"easily as a genuine defensive registration can, so this does not "
                    f"establish common ownership the way a shared resolved address would"
                ),
            ))
        return verdict

    @staticmethod
    def _why_unproven(
        subject: DomainFacts, referent: DomainFacts, established: bool, older: bool, value: str
    ) -> str:
        if referent.age_days is None:
            return f"'{value}' resolves, but its registration date is unavailable"
        if not established:
            return (
                f"'{value}' resolves but is itself only {referent.age_days} days old — too new "
                f"to be an established identity worth impersonating"
            )
        if not older and subject.age_days is not None:
            return (
                f"'{value}' is {referent.age_days} days old against this artifact's "
                f"{subject.age_days} — not enough of a gap to establish which imitates which"
            )
        return f"the relationship to '{value}' could not be verified"

    @staticmethod
    def _confidence(candidate: LookalikeCandidate, subject: DomainFacts) -> float:
        """How sure KRISIS is that this name imitates that identity.

        Built from what was actually established: how alike the labels are, whether
        the resemblance required deliberate glyph substitution (accidents do not
        substitute Cyrillic 'а'), and whether the artifact's own age is known.
        """
        confidence = 0.45 + 0.25 * candidate.similarity
        if candidate.method == "confusable_characters":
            confidence += 0.15
        if subject.age_days is not None:
            confidence += 0.1
        return round(min(0.9, confidence), 2)

    def _bank_namespace_evidence(self, entity: Entity) -> Optional[Evidence]:
        """India's RBI reserves .bank.in for regulated banks specifically to cut
        digital-payment phishing (see indicators.is_bank_in_namespace). Membership
        is real authenticity evidence about the *namespace*, weighed by the risk
        engine like any other counter-evidence — never a safe/unsafe override, and
        no claim about which specific institution operates this domain.
        """
        if not is_bank_in_namespace(entity.value):
            return None
        return Evidence(
            source=self.name, entity_id=entity.id, signal="verified_bank_namespace",
            value=registrable_domain(entity.value), evidence_type="identity",
            polarity=Polarity.CONTRADICTS_THREAT, confidence=0.75,
            independence=Independence.INDEPENDENT,
            provenance=(
                f"'{entity.value}' sits in India's restricted .bank.in namespace, which "
                f"RBI reserves for regulated banks and directed banks to migrate to in "
                f"order to reduce digital-payment phishing — this supports the namespace's "
                f"authenticity, not that this specific institution, page, or message is safe"
            ),
        )

    def _mixed_script_evidence(self, entity: Entity) -> Optional[Evidence]:
        """A label mixing Unicode scripts (Latin 'p' next to Cyrillic 'а') is a
        deceptive-glyph pattern the confusable-character table won't always
        catch on its own — it only maps a curated subset of homoglyphs, while
        this catches script mixing generically. Never fires for a label
        written entirely in one script, non-Latin included (see
        identity.mixed_script_label).
        """
        labels = decode_idn(entity.value).split(".")
        mixed = [label for label in labels if mixed_script_label(label)]
        if not mixed:
            return None
        return Evidence(
            source=self.name, entity_id=entity.id, signal="mixed_script_domain",
            value=mixed, evidence_type="identity",
            polarity=Polarity.SUPPORTS_THREAT, confidence=0.45,
            independence=Independence.INDEPENDENT,
            provenance=(
                f"label(s) {mixed} of '{entity.value}' mix letters from more than one "
                f"Unicode script — a common way to construct a visually deceptive glyph "
                f"substitution not present in the curated confusable-character table"
            ),
        )

    def _unverified(self, entity: Entity, candidate: LookalikeCandidate, why: str = "") -> Evidence:
        """A derived-but-unproven candidate. Neutral on purpose: it is a lead worth
        showing in the trace, and it must not move the score in either direction."""
        return Evidence(
            source=self.name, entity_id=entity.id, signal="lookalike_candidate",
            value=candidate.value, evidence_type="identity",
            polarity=Polarity.NEUTRAL, confidence=0.3,
            independence=Independence.INDEPENDENT,
            provenance=(
                f"{candidate.derivation} — unverified" + (f": {why}" if why else "")
            ),
        )
