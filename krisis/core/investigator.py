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
    ):
        self.collectors = collectors
        self.case_memory = case_memory
        self.pattern_memory = pattern_memory
        self.budget = budget or InvestigationBudget()
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

        seed_entities = self._seed_entities(seed_type, seed_value, trace)
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

        for e in seed_entities:
            added = graph.add_entity(e)
            case.entities[added.id] = added
            enqueue(added)

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
                target_entity = Entity(
                    value=pivot.entity_value,
                    type=pivot.entity_type,
                    depth=pivot.depth,
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

        case.explanation = self.explainer.explain(case, graph, correlation)
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

    def _seed_entities(self, seed_type: EntityType, seed_value: str, trace: InvestigationTrace) -> list[Entity]:
        entities = [Entity(value=seed_value, type=seed_type, depth=0)]

        if seed_type == EntityType.URL:
            domain = domain_from_url(seed_value)
            if domain:
                entities.append(Entity(value=domain, type=EntityType.DOMAIN, depth=0))

        if seed_type == EntityType.MESSAGE:
            extracted = extract_from_text(seed_value)
            trace.log("secondary_extraction", found=[f"{t.value}:{v}" for t, v in extracted])
            for etype, value in extracted:
                entities.append(Entity(value=value, type=etype, depth=0))
                if etype == EntityType.URL:
                    domain = domain_from_url(value)
                    if domain:
                        entities.append(Entity(value=domain, type=EntityType.DOMAIN, depth=0))

        return entities

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
            self.budget.register_call()
            if is_seed:
                coverage.attempted.add(collector.name)

            result = collector.collect(entity)
            if not result.available:
                case.provider_failures.append(f"{collector.name} unavailable for {entity.value}: {result.note}")
                trace.log("collector_unavailable", collector=collector.name, entity=entity.value, note=result.note)
                continue

            if is_seed and result.evidence:
                coverage.available.add(collector.name)
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
