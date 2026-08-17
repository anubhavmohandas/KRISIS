"""
Investigator — orchestrates the full KRISIS loop described in the design doc:

    INPUT -> INDICATOR EXTRACTION -> EVIDENCE COLLECTION -> NORMALIZATION
    -> PIVOT GENERATION -> PIVOT PRIORITIZATION -> INVESTIGATION QUEUE
    -> ENTITY/RELATIONSHIP GRAPH -> PATTERN + CASE MEMORY -> CORRELATION
    -> SUPPORTING + CONTRADICTING EVIDENCE -> RISK + CONFIDENCE
    -> AI EXPLANATION -> RECOMMENDED ACTION -> CASE STORAGE -> PATTERN UPDATE

This module contains no provider-specific logic and no scoring logic — it only
sequences the engines defined elsewhere. That separation is what keeps the
risk score deterministic/reproducible independent of which collectors happen
to be configured.
"""

from __future__ import annotations

import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Optional

from ..ai.explain import Explainer
from ..collectors.base import EvidenceCollector
from ..memory.case_memory import CaseMemory
from ..memory.pattern_memory import PatternMemory
from .correlation import CorrelationEngine
from .graph import EntityGraph
from .indicators import classify_seed, domain_from_url, extract_from_text
from .models import Case, Coverage, Entity, EntityType, Evidence, Relationship
from .pivot_engine import InvestigationBudget, PivotEngine
from .provider_planner import ProviderPlanner
from .recommend import recommend_action
from .risk import RiskEngine, historical_impact


@dataclass
class InvestigationTrace:
    """A step-by-step, replayable log of what the investigator did and why
    (see INVESTIGATION REPLAY / DEBUG-TRANSPARENCY MODES)."""

    steps: list[dict] = field(default_factory=list)

    def log(self, stage: str, **details) -> None:
        self.steps.append({"stage": stage, **details})


class Investigator:
    def __init__(
        self,
        collectors: list[EvidenceCollector],
        case_memory: CaseMemory,
        pattern_memory: PatternMemory,
        budget: Optional[InvestigationBudget] = None,
        explainer: Optional[Explainer] = None,
        planner: Optional[ProviderPlanner] = None,
    ):
        self.collectors = collectors
        self.case_memory = case_memory
        self.pattern_memory = pattern_memory
        self.budget = budget or InvestigationBudget()
        # Every provider request goes through the planner: it decides what is worth
        # spending, reuses what was already asked, and records why anything was not
        # consulted. Default has no storage, so it deduplicates within the run but
        # keeps no cross-run cache — the CLI passes one wired to the case database.
        self.planner = planner or ProviderPlanner()
        # The pivot engine consults indicator memory to recognise commodity
        # infrastructure by observation, not just by name.
        self.pivot_engine = PivotEngine(
            self.budget, case_count_lookup=self._prior_case_count
        )
        self.correlation_engine = CorrelationEngine(pattern_memory=pattern_memory)
        self.risk_engine = RiskEngine()
        self.explainer = explainer or Explainer()

    def investigate(self, raw_input: str) -> tuple[Case, InvestigationTrace]:
        trace = InvestigationTrace()
        seed_type, seed_value = classify_seed(raw_input)
        trace.log("indicator_extraction", seed=seed_value, seed_type=seed_type.value)

        case = Case(seed=seed_value, seed_type=seed_type)
        graph = EntityGraph()
        # Coverage is tracked for the seed artifact only. Whether a mail server three
        # hops away answered says nothing about how well KRISIS examined the thing the
        # user actually asked about.
        coverage = Coverage()

        seed_entities, seed_edges = self._seed_entities(seed_type, seed_value, trace)
        queue: deque[Entity] = deque()
        # The graph deduplicates entities, but the queue must too: the same entity is
        # reachable by several routes (a URL and its extracted domain, or two sources
        # pivoting to one IP). Queuing it twice re-runs every collector against it,
        # burning external-call budget and producing identical evidence that would
        # then be counted as two independent confirmations.
        queued: set[str] = set()

        def enqueue(entity: Entity) -> None:
            if entity.id not in queued:
                queued.add(entity.id)
                queue.append(entity)

        # key() -> the (possibly deduplicated) Entity actually stored in the graph,
        # so a message that mentions the same domain twice still resolves both
        # edges to the one surviving node.
        key_to_entity: dict[str, Entity] = {}
        for e in seed_entities:
            added = graph.add_entity(e)
            case.entities[added.id] = added
            key_to_entity[e.key()] = added
            enqueue(added)

        # Seed extraction (message -> URL, URL -> its domain) is itself an observed
        # relationship (see GRAPH IS PART OF THE REASONING) — without these edges the
        # graph shows the message and everything found in it as unconnected islands.
        for source_key, target_key, relation_type, reason in seed_edges:
            source = key_to_entity.get(source_key)
            target = key_to_entity.get(target_key)
            if not source or not target or source.id == target.id:
                continue
            rel = Relationship(
                source_entity_id=source.id, target_entity_id=target.id,
                relation_type=relation_type, reason=reason,
            )
            graph.add_relationship(rel)
            case.relationships[rel.id] = rel

        fanout_counter: Counter = Counter()

        while queue:
            entity = queue.popleft()
            if not self.budget.has_entity_budget():
                trace.log("budget_exhausted", limit="max_entities", entity=entity.value)
                break

            self.budget.register_entity()
            evidence_items = self._collect_for_entity(entity, case, trace, coverage)

            pivots = self.pivot_engine.generate(entity, evidence_items)
            self.pivot_engine.penalize_noisy_fanout(pivots, fanout_counter)

            for pivot in pivots:
                pivot = self.pivot_engine.accept_or_reject(pivot, current_depth_count=entity.depth)
                case.pivots.append(pivot)
                trace.log(
                    "pivot_evaluated",
                    pivot=pivot.entity_value,
                    type=pivot.entity_type.value,
                    priority=round(pivot.priority, 3),
                    status=pivot.status,
                    reason=pivot.rejection_reason or pivot.reason,
                )
                if pivot.status != "accepted":
                    continue

                fanout_counter[pivot.entity_value] += 1
                source_evidence = case.evidence.get(pivot.source_evidence_id or "")
                target_entity = Entity(
                    value=pivot.entity_value,
                    type=pivot.entity_type,
                    depth=pivot.depth,
                    # Carried so the provider planner can tell a lead the threat
                    # hypothesis depends on from one more discovered hostname. Without
                    # it, a scarce provider is spent on whatever the graph happened to
                    # reach rather than on what the investigation actually turns on.
                    metadata={
                        "pivot_priority": round(pivot.priority, 3),
                        "supports_hypothesis": bool(
                            source_evidence
                            and source_evidence.polarity.value == "supports_threat"
                        ),
                        "pivot_reason": pivot.reason,
                    },
                    # Anything reached *through* commodity infrastructure is itself
                    # commodity infrastructure: the IPs behind a shared mail provider
                    # belong to that provider, not to the artifact under investigation.
                    shared_infrastructure=pivot.shared_infrastructure or entity.shared_infrastructure,
                )
                target_entity = graph.add_entity(target_entity)
                case.entities[target_entity.id] = target_entity

                rel = Relationship(
                    source_entity_id=entity.id,
                    target_entity_id=target_entity.id,
                    relation_type=pivot.relation_type,
                    reason=pivot.reason,
                    evidence_ids=[pivot.source_evidence_id] if pivot.source_evidence_id else [],
                    weight=pivot.priority,
                )
                graph.add_relationship(rel)
                case.relationships[rel.id] = rel

                if target_entity.depth <= self.budget.max_depth:
                    enqueue(target_entity)

        # -- correlation, risk, explanation, recommendation --------------------
        all_evidence = list(case.evidence.values())
        correlation = self.correlation_engine.correlate(graph, all_evidence, exclude_seed=case.seed)
        trace.log("correlation", **correlation.to_dict())

        # The match that scores is the one with the most impact, not the one that
        # merely resembles hardest: a strong resemblance to a confirmed-benign case
        # carries no threat weight and must not displace a weaker match to a
        # confirmed-malicious one.
        historical = max(correlation.pattern_matches, key=historical_impact, default=None)
        case.pattern_matches = correlation.pattern_matches

        trace.log("coverage", **coverage.to_dict())
        risk = self.risk_engine.score(correlation, historical_similarity=historical, coverage=coverage)
        case.risk = risk
        trace.log("risk_assessment", **risk.to_dict())

        # Recorded before the explanation so the AI layer can be told what KRISIS spent
        # and what it declined to spend, and before storage so the case answers "why
        # was this provider not consulted?" when it is read back months later.
        case.provider_usage = self.planner.usage_summary()
        trace.log("provider_usage", **case.provider_usage)

        case.explanation = self.explainer.explain(case, graph, correlation)
        case.explanation_source = self.explainer.last_source
        case.plain_summary = self.explainer.last_plain_summary
        case.recommendation = recommend_action(risk)
        trace.log("recommendation", text=case.recommendation)

        self.case_memory.save(case)
        trace.log("case_stored", case_id=case.id)

        self._graph = graph  # kept for CLI --show-graph without recomputation
        return case, trace

    @property
    def last_graph(self) -> Optional[EntityGraph]:
        return getattr(self, "_graph", None)

    # -- internals ----------------------------------------------------------

    def _prior_case_count(self, entity_type: str, value: str) -> int:
        """How many distinct prior artifacts produced this indicator. Never fatal:
        pattern memory is an enhancement to pivot scoring, not a dependency."""
        try:
            return self.pattern_memory.storage.count_cases_for_indicator(entity_type, value)
        except Exception:
            return 0

    def _seed_entities(
        self, seed_type: EntityType, seed_value: str, trace: InvestigationTrace
    ) -> tuple[list[Entity], list[tuple[str, str, str, str]]]:
        """Entities extracted from the raw input, plus the edges between them as
        (source_key, target_key, relation_type, reason) — Entity.key() pairs,
        resolved to ids by the caller once every seed entity has been added to the
        graph (dedup can decide which id a key ultimately resolves to)."""
        seed = Entity(value=seed_value, type=seed_type, depth=0)
        entities = [seed]
        edges: list[tuple[str, str, str, str]] = []

        if seed_type == EntityType.URL:
            domain = domain_from_url(seed_value)
            if domain:
                domain_entity = Entity(value=domain, type=EntityType.DOMAIN, depth=0)
                entities.append(domain_entity)
                edges.append((seed.key(), domain_entity.key(), "has_domain", "domain component of this URL"))

        if seed_type == EntityType.MESSAGE:
            extracted = extract_from_text(seed_value)
            trace.log("secondary_extraction", found=[f"{t.value}:{v}" for t, v in extracted])
            for etype, value in extracted:
                item = Entity(value=value, type=etype, depth=0)
                entities.append(item)
                edges.append((seed.key(), item.key(), "mentions", f"{etype.value} extracted from message text"))
                if etype == EntityType.URL:
                    domain = domain_from_url(value)
                    if domain:
                        domain_entity = Entity(value=domain, type=EntityType.DOMAIN, depth=0)
                        entities.append(domain_entity)
                        edges.append(
                            (item.key(), domain_entity.key(), "has_domain", "domain component of this URL")
                        )

        return entities, edges

    def _collect_for_entity(
        self, entity: Entity, case: Case, trace: InvestigationTrace, coverage: Coverage
    ) -> list[Evidence]:
        collected: list[Evidence] = []
        is_seed = entity.depth == 0
        for collector in self.collectors:
            if not collector.can_handle(entity):
                continue
            if not self.budget.has_call_budget():
                trace.log("budget_exhausted", limit="max_external_calls", collector=collector.name)
                break
            if is_seed:
                # Attempted, whatever the planner decides. A provider the planner
                # declined to spend is a source that did not answer about the seed,
                # and coverage exists precisely to stop that reading as "nothing found".
                coverage.attempted.add(collector.name)

            result, decision = self.planner.collect(collector, entity)
            trace.log("provider_decision", **decision.to_dict())
            # Only a request actually sent to a provider consumes the investigation's
            # external-call budget — reusing a cached answer costs nobody anything.
            if decision.action == "queried":
                self.budget.register_call()

            if not result.available:
                if decision.action == "skipped":
                    # The planner chose not to spend this request (budget, value gate,
                    # backoff) — a policy decision, not a provider malfunction. Reusing
                    # provider_failures here would report a scarce-budget rule working
                    # as intended as though the provider were down.
                    case.provider_skips.append(f"{collector.name} skipped for {entity.value}: {decision.reason}")
                    trace.log("collector_skipped", collector=collector.name, entity=entity.value, reason=decision.reason)
                else:
                    case.provider_failures.append(f"{collector.name} unavailable for {entity.value}: {result.note}")
                    trace.log("collector_unavailable", collector=collector.name, entity=entity.value, note=result.note)
                continue

            # result.available is already True here (checked above): the collector
            # ran and answered, whether or not it found anything to report. A domain
            # with no lookalike candidate or a message with no urgency language is a
            # real, clean check (see identity_collector/message_collector) — treating
            # it as "not checked" would turn a genuine negative into a false gap.
            if is_seed:
                coverage.available.add(collector.name)
                if result.evidence:
                    coverage.evidence_types.update(ev.evidence_type for ev in result.evidence)

            for ev in result.evidence:
                case.evidence[ev.id] = ev
                collected.append(ev)
            trace.log(
                "evidence_collected",
                collector=collector.name,
                entity=entity.value,
                count=len(result.evidence),
            )
        return collected
