"""
Provider planner — decides whether spending a provider request on an entity is
worth it, before any collector runs.

The live pipeline exposed the gap this closes: two user-entered seeds fanned out
into a dozen discovered entities, and every collector ran against every one of
them. Fourteen VirusTotal requests later the provider's rate limit answered for
us. Discovering a quota by exhausting it is not budgeting.

So the planner sits between pivot discovery and provider execution:

    entity discovered -> pivot relevance -> PLANNER -> collector

and answers, in this order:

    already asked this provider this exact question?     -> reuse, no request
    answered recently enough to still be true?           -> cache, no request
    is this entity worth an expensive request at all?    -> value gate
    is the provider inside its rate limit / daily quota? -> defer or skip
    did the provider just tell us to back off?           -> honour it

Every outcome is recorded with a reason, because "VirusTotal was not consulted
for this entity" is part of the investigation record. What the planner never
does is convert any of those outcomes into evidence of safety: a skipped request
produces no evidence at all, and CollectorResult.available stays False.

Policy is configuration, not intelligence: costs, limits and TTLs come from
krisis.config (env-overridable), never from anything KRISIS concluded.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..collectors.base import CollectorResult, EvidenceCollector
from .models import Entity, Evidence, Independence, Polarity


@dataclass(frozen=True)
class ProviderPolicy:
    """What one provider costs and how freely KRISIS may spend it."""

    name: str
    # True for providers cheap enough to run against every discovered entity.
    # False means the provider is scarce and must be justified per entity.
    broad_enrichment: bool = True
    cache_ttl_seconds: float = 3600.0
    rate_per_minute: Optional[int] = None
    daily_quota: Optional[int] = None
    # How long to stay off a provider that answered with a rate-limit response.
    backoff_seconds: float = 300.0
    # Value gate for non-broad providers: how strong a pivot must be to earn a request.
    min_pivot_priority: float = 0.7
    # How long the planner may block waiting for a rate-limit window to free a slot.
    # 0 means never block — defer the request and say so instead.
    max_wait_seconds: float = 0.0


@dataclass
class Decision:
    provider: str
    entity: str
    action: str          # queried | cached | deduplicated | skipped
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"provider": self.provider, "entity": self.entity, "action": self.action, "reason": self.reason}


@dataclass
class ProviderUsage:
    calls: int = 0
    cached: int = 0
    deduplicated: int = 0
    skipped: int = 0
    rate_limited: int = 0
    skip_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "calls": self.calls,
            "cached": self.cached,
            "deduplicated": self.deduplicated,
            "skipped": self.skipped,
            "rate_limited": self.rate_limited,
            # Deduplicated so a provider skipped for the same reason across ten pivots
            # reads as one policy decision rather than ten incidents.
            "skip_reasons": sorted(set(self.skip_reasons)),
        }


DEFAULT_POLICY = ProviderPolicy(name="default")


class ProviderPlanner:
    def __init__(
        self,
        policies: Optional[dict[str, ProviderPolicy]] = None,
        storage: Optional[Any] = None,
        clock: Callable[[], float] = time.time,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        """storage: optional Storage. Without it the planner still deduplicates within
        one investigation but keeps no cross-run cache or rate ledger — which is the
        right behaviour for tests and for a KRISIS run with no database."""
        self.policies = policies or {}
        self.storage = storage
        self.clock = clock
        self.sleeper = sleeper
        self.usage: dict[str, ProviderUsage] = {}
        self.decisions: list[Decision] = []
        self._session: dict[tuple[str, str, str], CollectorResult] = {}

    def policy_for(self, provider: str) -> ProviderPolicy:
        return self.policies.get(provider, DEFAULT_POLICY)

    def usage_for(self, provider: str) -> ProviderUsage:
        return self.usage.setdefault(provider, ProviderUsage())

    def usage_summary(self) -> dict[str, dict[str, Any]]:
        return {name: usage.to_dict() for name, usage in sorted(self.usage.items())}

    # -- the one entry point ---------------------------------------------------

    def collect(self, collector: EvidenceCollector, entity: Entity) -> tuple[CollectorResult, Decision]:
        policy = self.policy_for(collector.name)
        usage = self.usage_for(collector.name)
        key = (collector.name, entity.type.value, entity.value.lower())
        now = self.clock()

        cached_session = self._session.get(key)
        if cached_session is not None:
            usage.deduplicated += 1
            return self._rebind(cached_session, entity), self._decide(
                collector.name, entity, "deduplicated",
                "already asked this provider about this exact value in this investigation",
            )

        stored = self._from_cache(collector.name, entity, policy, now)
        if stored is not None:
            usage.cached += 1
            self._session[key] = stored
            return self._rebind(stored, entity), self._decide(
                collector.name, entity, "cached",
                f"reusing a {stored.note} (within this provider's "
                f"{int(policy.cache_ttl_seconds)}s cache window)",
            )

        blocked = self._budget_block(collector.name, entity, policy, now)
        if blocked:
            usage.skipped += 1
            usage.skip_reasons.append(blocked)
            # No evidence, and available=False: a request KRISIS chose not to spend
            # must read downstream exactly like a provider that could not answer,
            # never like a provider that answered "nothing found".
            return (
                CollectorResult(evidence=[], available=False, note=blocked),
                self._decide(collector.name, entity, "skipped", blocked),
            )

        result = collector.collect(entity)
        usage.calls += 1
        self._record_event(collector.name, "call", now)

        if _is_rate_limited(result):
            usage.rate_limited += 1
            self._record_event(collector.name, "rate_limited", now)
        elif result.available:
            self._to_cache(collector.name, entity, result, now)

        self._session[key] = result
        return result, self._decide(collector.name, entity, "queried", "request spent")

    # -- budget rules ----------------------------------------------------------

    def _budget_block(
        self, provider: str, entity: Entity, policy: ProviderPolicy, now: float
    ) -> Optional[str]:
        """The reason this request must not be made, or None to go ahead."""
        if not policy.broad_enrichment:
            gate = self._value_gate(entity, policy)
            if gate:
                return gate

        if self.storage is None:
            return None

        if policy.backoff_seconds:
            last = self.storage.last_provider_event(provider, "rate_limited")
            if last is not None and now - last < policy.backoff_seconds:
                return (
                    f"{provider} returned a rate-limit response {int(now - last)}s ago; "
                    f"backing off for {int(policy.backoff_seconds)}s rather than hammering it"
                )

        if policy.daily_quota:
            spent_today = self.storage.count_provider_events(provider, "call", now - 86400)
            if spent_today >= policy.daily_quota:
                return (
                    f"{provider} daily budget exhausted ({spent_today}/{policy.daily_quota} "
                    f"requests in the last 24h)"
                )

        if policy.rate_per_minute:
            window_start = now - 60.0
            recent = self.storage.count_provider_events(provider, "call", window_start)
            if recent >= policy.rate_per_minute:
                oldest = self.storage.oldest_provider_event(provider, "call", window_start) or now
                wait = max(0.0, 60.0 - (now - oldest))
                if wait <= policy.max_wait_seconds:
                    self.sleeper(wait)
                    return None
                return (
                    f"{provider} rate limit reached ({recent}/{policy.rate_per_minute} requests "
                    f"in the last minute); next slot in {wait:.0f}s"
                )
        return None

    @staticmethod
    def _value_gate(entity: Entity, policy: ProviderPolicy) -> Optional[str]:
        """Would spending a scarce request here materially improve the investigation?

        The seed always earns one: it is the thing the user asked about. Beyond it,
        a discovered entity has to carry its own justification — a strong pivot that
        the threat hypothesis actually depends on. Without this, one seed's subdomain
        list quietly becomes a dozen requests about infrastructure nobody asked about.
        """
        if entity.depth == 0:
            return None
        if entity.shared_infrastructure:
            return (
                f"commodity infrastructure — a scarce provider request buys nothing about "
                f"'{entity.value}' that is specific to this investigation"
            )
        priority = float(entity.metadata.get("pivot_priority", 0.0))
        supports = bool(entity.metadata.get("supports_hypothesis", False))
        if priority >= policy.min_pivot_priority and supports:
            return None
        return (
            f"discovered entity below the value threshold for a scarce provider "
            f"(pivot priority {priority:.2f} < {policy.min_pivot_priority:.2f}"
            f"{'' if supports else ', and no evidence here supports the threat hypothesis'})"
        )

    # -- cache -----------------------------------------------------------------

    def _from_cache(
        self, provider: str, entity: Entity, policy: ProviderPolicy, now: float
    ) -> Optional[CollectorResult]:
        if self.storage is None or policy.cache_ttl_seconds <= 0:
            return None
        try:
            row = self.storage.cache_get(provider, entity.type.value, entity.value)
        except Exception:
            return None
        if not row:
            return None
        age = now - float(row["fetched_at"])
        if age > policy.cache_ttl_seconds:
            return None   # stale is a miss, not a result: old intelligence is not current

        payload = row["payload"]
        evidence = [
            _evidence_from_dict(item, entity, provider, age) for item in payload.get("evidence", [])
        ]
        return CollectorResult(
            evidence=evidence,
            available=bool(payload.get("available", True)),
            note=f"cached response, {int(age)}s old",
        )

    def _to_cache(self, provider: str, entity: Entity, result: CollectorResult, now: float) -> None:
        if self.storage is None or self.policy_for(provider).cache_ttl_seconds <= 0:
            return
        try:
            self.storage.cache_put(
                provider,
                entity.type.value,
                entity.value,
                now,
                {"available": result.available, "note": result.note,
                 "evidence": [ev.to_dict() for ev in result.evidence]},
            )
        except Exception:
            pass   # a cache write must never fail an investigation

    # -- helpers ---------------------------------------------------------------

    def _record_event(self, provider: str, kind: str, ts: float) -> None:
        if self.storage is None:
            return
        try:
            self.storage.record_provider_event(provider, kind, ts)
        except Exception:
            pass

    def _decide(self, provider: str, entity: Entity, action: str, reason: str) -> Decision:
        decision = Decision(provider=provider, entity=entity.value, action=action, reason=reason)
        self.decisions.append(decision)
        return decision

    @staticmethod
    def _rebind(result: CollectorResult, entity: Entity) -> CollectorResult:
        """Re-point reused evidence at the entity being investigated now.

        The same value can be reached as a different graph node, and evidence whose
        entity_id points at a node from an earlier lookup would detach the observation
        from the thing it is about. Each rebinding gets a fresh evidence id: the case
        stores evidence by id, so reusing one would silently drop the earlier copy.
        """
        rebound = [
            Evidence(**{k: v for k, v in ev.__dict__.items() if k != "id"} | {"entity_id": entity.id})
            for ev in result.evidence
        ]
        return CollectorResult(evidence=rebound, available=result.available, note=result.note)


def _is_rate_limited(result: CollectorResult) -> bool:
    return not result.available and "rate limit" in (result.note or "").lower()


def _evidence_from_dict(data: dict[str, Any], entity: Entity, provider: str, age: float) -> Evidence:
    """Rehydrate a cached observation, stamped with when it was actually fetched.

    Freshness travels with the evidence rather than being noted once at the top of
    the report, so nothing downstream can read a cached observation as a live one.
    """
    fetched_at = data.get("fetched_at") or data.get("observed_at", "")
    return Evidence(
        source=data.get("source", provider),
        entity_id=entity.id,
        signal=data.get("signal", ""),
        value=data.get("value"),
        evidence_type=data.get("evidence_type", "unknown"),
        polarity=Polarity(data.get("polarity", Polarity.NEUTRAL.value)),
        confidence=float(data.get("confidence", 0.5)),
        independence=Independence(data.get("independence", Independence.INDEPENDENT.value)),
        provenance=(
            f"{data.get('provenance', '')} [cached response from {fetched_at}, "
            f"{int(age)}s old — not re-verified]"
        ).strip(),
        fetched_at=fetched_at,
        freshness="cached",
        cache_age_seconds=int(age),
    )
