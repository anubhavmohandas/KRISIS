"""
Pattern memory — historical matching against prior investigations, on two
independent dimensions (see PATTERN SIMILARITY in the design doc: "Do not force
a vector database simply because it is fashionable").

1. INDICATOR similarity — "have I seen these exact values before?"
   For every distinguishing entity discovered in the current investigation
   (certificates, IPs, pivoted-to domains), look up whether that exact value was
   ever seen in a stored case, weighted by how distinguishing the type is:

       certificate fingerprint  -> weight 0.9  (very unlikely to collide by chance)
       IP address                -> weight 0.5  (hosting is reused, less distinguishing)
       pivoted-to domain          -> weight 0.3  (weakest signal alone)

   Strong evidence when it fires, but blind to an adversary who rotates
   infrastructure: change every IP and certificate and the resemblance vanishes.

2. STRUCTURAL similarity — "have I seen this *kind* of investigation before?"
   Compares the shape of the case — which threat-relevant signals fired, which
   contradicted, which relationship types were followed, which classes of entity
   the pivots reached — against the signatures of stored cases. Concrete values
   are deliberately absent from the signature, which is exactly what lets it
   survive indicator rotation.

   Facets are weighted by inverse document frequency computed over stored cases
   at query time, so a facet that appears in nearly every investigation (every
   domain resolves to an IP) contributes almost nothing, while a rare
   co-occurrence dominates. That is the same principle as commodity-
   infrastructure suppression, applied to structure instead of to values, and it
   is derived from the corpus rather than declared in a list.

Structural resemblance is weaker proof than a shared certificate — shapes
coincide, fingerprints do not — so it is discounted (STRUCTURAL_WEIGHT) and
further scaled by the matched pattern's lifecycle stage. A shape seen once has
almost no influence no matter how well it matches; only repeated, human-
validated shapes reach full weight (see PATTERN LIFECYCLE / POISONING
RESISTANCE).
"""

from __future__ import annotations

import hashlib
import math
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Iterable

from ..core.graph import EntityGraph
from ..core.models import Entity, Evidence, Outcome, Polarity, Relationship
from .storage import Storage

INDICATOR_WEIGHTS = {
    "certificate": 0.9,
    "ip": 0.5,
    "domain": 0.3,
    "hostname": 0.25,
    "email": 0.4,
    "asn": 0.15,
}

MIN_SIMILARITY_TO_REPORT = 0.15

# A structural match must share a meaningful share of the weighted structure.
# Below this, the overlap is the structure investigations have in common — every
# domain resolves to an IP — rather than anything about these two cases.
MIN_STRUCTURAL_SIMILARITY = 0.35
# One facet is not a shape: it is a single observation, and neither worth
# remembering as a pattern nor worth comparing against one.
MIN_FACETS_FOR_A_SHAPE = 2

# How much shape-only resemblance is allowed to count relative to a shared
# concrete indicator. Below 1.0 because infrastructure rotates but shapes also
# genuinely coincide between unrelated cases.
STRUCTURAL_WEIGHT = 0.8

# Lifecycle stage -> how much of the structural resemblance is usable. This is
# what stops one case from becoming trusted intelligence: the stage itself is
# derived from observation and validation counts, never assigned.
STAGE_WEIGHT: dict[str, float] = {
    "observed": 0.25,
    "candidate": 0.4,
    "repeated": 0.6,
    "validated": 0.8,
    "trusted": 1.0,
    "deprecated": 0.0,   # discredited by validated false positives — no influence at all
}


def structural_facets(
    entities: Iterable[Entity],
    evidence: Iterable[Evidence],
    relationships: Iterable[Relationship],
) -> list[str]:
    """The shape of an investigation, with every concrete value stripped out.

    Included:
      - polarised evidence signals: what actually argued for or against a threat
      - relationship types followed: the investigative structure
      - classes of entity the pivots reached (depth > 0)

    Excluded, deliberately:
      - indicator values, which are what indicator memory already covers and what
        an adversary rotates
      - neutral evidence: every domain has A/NS/MX records, so including them
        would make every investigation resemble every other one
      - the seed entity, whose type is fixed by the input and carries no information
      - anything commodity: a shared mail vendor is a fact about the vendor, so it
        must not contribute structure any more than it contributes indicators
    """
    facets: set[str] = set()

    for ev in evidence:
        if ev.polarity == Polarity.SUPPORTS_THREAT:
            facets.add(f"signal+:{ev.evidence_type}:{ev.signal}")
        elif ev.polarity == Polarity.CONTRADICTS_THREAT:
            facets.add(f"signal-:{ev.evidence_type}:{ev.signal}")

    by_id: dict[str, Entity] = {}
    for entity in entities:
        by_id[entity.id] = entity
        if entity.depth > 0 and not entity.shared_infrastructure:
            facets.add(f"entity:{entity.type.value}")

    for rel in relationships:
        target = by_id.get(rel.target_entity_id)
        if target is not None and target.shared_infrastructure:
            continue
        facets.add(f"rel:{rel.relation_type}")

    return sorted(facets)


class PatternMemory:
    def __init__(self, storage: Storage):
        self.storage = storage

    def find_similar(
        self, graph: EntityGraph, evidence: list[Evidence], exclude_seed: str | None = None
    ) -> list[dict[str, Any]]:
        """Historical matches on both dimensions, merged per prior case.

        exclude_seed: the artifact currently under investigation. Prior cases seeded
        on that same artifact are excluded on both dimensions, otherwise re-running an
        investigation reports the domain as resembling *itself* — a self-confirming
        match that would let repeated scans manufacture history out of nothing.
        """
        indicator = self._indicator_matches(graph, exclude_seed)
        facets = structural_facets(graph.entities(), evidence, graph.relationships())
        structural = self._structural_matches(facets, exclude_seed)
        return self._merge(indicator, structural)

    # -- dimension 1: concrete indicator overlap --------------------------------

    def _indicator_matches(
        self, graph: EntityGraph, exclude_seed: str | None
    ) -> list[dict[str, Any]]:
        candidates: list[tuple[str, str, float]] = []
        for entity in graph.entities():
            weight = INDICATOR_WEIGHTS.get(entity.type.value)
            if weight is None:
                continue
            # The current investigation's own seed cannot meaningfully match itself.
            # This must compare against the literal seed *value*, not "any depth-0
            # domain": a message investigation extracts URLs/domains as depth-0
            # entities too, and those are real artifacts, not the seed — excluding
            # them by depth alone silently threw away the case that matters most:
            # "this exact artifact was investigated directly before, and now shows
            # up again inside a message" (see EXACT ARTIFACT VS INFRASTRUCTURE
            # OVERLAP below).
            if exclude_seed and entity.value.lower() == exclude_seed.lower():
                continue
            # Commodity infrastructure is not a distinguishing indicator. Two unrelated
            # companies sharing a mail vendor's IPs is a fact about the vendor, and
            # matching on it reports them as the same infrastructure cluster.
            if entity.shared_infrastructure:
                continue
            candidates.append((entity.type.value, entity.value, weight))

        if not candidates:
            return []

        total_possible_weight = sum(w for _, _, w in candidates)
        matches_by_case: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"weight": 0.0, "indicators": [], "exact_indicators": [],
                     "outcome": None, "seed": None}
        )

        for entity_type, value, weight in candidates:
            rows = self.storage.find_indicator_matches(entity_type, value, exclude_seed=exclude_seed)
            for row in rows:
                case_id = row["case_id"]
                info = matches_by_case[case_id]
                info["weight"] += weight
                info["indicators"].append(f"{entity_type}:{value}")
                # EXACT ARTIFACT VS INFRASTRUCTURE OVERLAP: a matched value that was
                # itself the *seed* of the prior case means this investigation is
                # looking at the very same artifact that prior case was about — "I
                # have seen this exact artifact before". A matched value that was
                # merely something the prior case *pivoted to* (a shared cert, a
                # shared IP, an infrastructure neighbor) is a weaker claim —
                # "infrastructure overlap" — and the two must not be reported as the
                # same thing just because both produce an indicator_similarity > 0.
                if (row.get("seed") or "").lower() == value.lower():
                    info["exact_indicators"].append(f"{entity_type}:{value}")
                info["outcome"] = row.get("outcome") or info["outcome"]
                info["seed"] = row.get("seed")

        results = []
        for case_id, info in matches_by_case.items():
            similarity = min(1.0, info["weight"] / total_possible_weight) if total_possible_weight else 0.0
            indicator_kind = "exact_artifact" if info["exact_indicators"] else "infrastructure"
            pattern_name = (
                (f"the same artifact investigated before as '{info['seed']}'" if info["exact_indicators"]
                 else f"infrastructure overlap with prior case for '{info['seed']}'")
                if info["seed"] else f"prior case {case_id}"
            )
            results.append(
                {
                    "pattern_id": case_id,
                    "case_ids": {case_id},
                    "pattern_name": pattern_name,
                    "indicator_similarity": round(similarity, 3),
                    "structural_similarity": 0.0,
                    "matched_indicators": info["indicators"],
                    # Which of matched_indicators are the exact prior-case artifact,
                    # as opposed to shared downstream infrastructure. See CLI/risk
                    # rendering (historical_match_label) for how this becomes the
                    # "exact artifact seen before" vs "infrastructure overlap" text.
                    "indicator_kind": indicator_kind,
                    "matched_facets": [],
                    "pattern_stage": None,
                    "maturity": 1.0,   # a concrete shared indicator needs no maturing
                    # An un-validated prior case must not masquerade as intelligence.
                    # Downstream scoring weights this explicitly (see risk.OUTCOME_TRUST).
                    "prior_outcome": info["outcome"] or Outcome.UNKNOWN.value,
                }
            )
        return results

    # -- dimension 2: structural resemblance -------------------------------------

    def _structural_matches(
        self, facets: list[str], exclude_seed: str | None
    ) -> list[dict[str, Any]]:
        if len(facets) < MIN_FACETS_FOR_A_SHAPE:
            return []
        patterns = self.storage.list_patterns_with_cases()
        if not patterns:
            return []

        idf = self._facet_idf(patterns)
        current = set(facets)
        results = []

        for pattern in patterns:
            stored = set(_facets_of(pattern))
            if not stored:
                continue
            # Prior cases on the same artifact cannot corroborate a re-run of it.
            cases = [c for c in pattern["cases"] if c["seed"] != exclude_seed]
            if not cases:
                continue

            shared = current & stored
            union_weight = sum(idf(f) for f in current | stored)
            similarity = (sum(idf(f) for f in shared) / union_weight) if union_weight else 0.0
            if similarity < MIN_STRUCTURAL_SIMILARITY:
                continue

            stage = self.stage_for(pattern)
            results.append(
                {
                    "pattern_id": pattern["id"],
                    "case_ids": {c["id"] for c in cases},
                    "pattern_name": f"structural pattern '{pattern['name']}'",
                    "indicator_similarity": 0.0,
                    "structural_similarity": round(similarity, 3),
                    "matched_indicators": [],
                    # No shared concrete value at all on this dimension — never
                    # "exact_artifact" or "infrastructure" on its own; _merge()
                    # fills this in from the indicator dimension if that also fired.
                    "indicator_kind": None,
                    "matched_facets": sorted(shared),
                    "pattern_stage": stage,
                    "maturity": STAGE_WEIGHT.get(stage, 0.0),
                    "prior_outcome": _pattern_outcome(pattern, cases),
                }
            )
        return results

    @staticmethod
    def _facet_idf(patterns: list[dict[str, Any]]):
        """Inverse document frequency over stored observations.

        A facet present in almost every case describes investigations in general,
        not this one, and is weighted accordingly. Frequencies are counted in
        observations (a pattern seen 40 times counts 40) so a common shape cannot
        hide behind being stored once.
        """
        total = 0
        document_freq: dict[str, int] = defaultdict(int)
        for pattern in patterns:
            observations = max(1, pattern.get("observed_count") or 1)
            total += observations
            for facet in _facets_of(pattern):
                document_freq[facet] += observations

        def idf(facet: str) -> float:
            # +0.5 smoothing: a facet never seen before is maximally distinguishing
            # but must not divide by zero.
            return math.log((total + 1) / (document_freq.get(facet, 0) + 0.5))

        return idf

    # -- merge -------------------------------------------------------------------

    def _merge(
        self, indicator: list[dict[str, Any]], structural: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """One entry per prior case, carrying both dimensions where both fired."""
        merged: dict[str, dict[str, Any]] = {m["pattern_id"]: m for m in indicator}

        for s in structural:
            target = next((merged[c] for c in s["case_ids"] if c in merged), None)
            if target is None:
                merged[s["pattern_id"]] = s
                continue
            target["structural_similarity"] = s["structural_similarity"]
            target["matched_facets"] = s["matched_facets"]
            target["pattern_stage"] = s["pattern_stage"]
            target["maturity"] = s["maturity"]
            # The specific prior case is more informative than the pattern's
            # aggregate, except when that case was never validated and the shape was.
            if target["prior_outcome"] == Outcome.UNKNOWN.value:
                target["prior_outcome"] = s["prior_outcome"]

        results = []
        for match in merged.values():
            match.pop("case_ids", None)
            maturity = match.pop("maturity", 1.0)
            structural_component = STRUCTURAL_WEIGHT * maturity * match["structural_similarity"]
            # Noisy-OR: two weak, independent resemblances add up to a little more
            # than either alone, and neither can push the total past 1.
            overall = 1 - (1 - match["indicator_similarity"]) * (1 - structural_component)
            if overall < MIN_SIMILARITY_TO_REPORT:
                continue
            match["similarity"] = round(overall, 3)
            match["match_type"] = _match_type(match)
            results.append(match)

        results.sort(key=lambda r: r["similarity"], reverse=True)
        return results[:5]

    # -- pattern lifecycle -----------------------------------------------------

    def signature_for(self, case) -> tuple[str, list[str]]:
        """A case's structural signature and its stable id.

        This is what generalizes across cases — the recurring *shape* of a case
        rather than its specific indicator values, which is why it lives separately
        from indicator memory.
        """
        facets = structural_facets(
            case.entities.values(), case.evidence.values(), case.relationships.values()
        )
        digest = hashlib.sha256("|".join(facets).encode()).hexdigest()[:12]
        return f"pat_{digest}", facets

    @staticmethod
    def stage_for(pattern: dict[str, Any]) -> str:
        """Lifecycle stage, derived from counts rather than stored, so it can never
        drift out of sync with the evidence behind it (see PATTERN LIFECYCLE).

        Only human-validated outcomes can push a pattern past 'repeated'. Repetition
        alone proves KRISIS keeps seeing something, not that it keeps being right.
        """
        confirmed = pattern.get("confirmed_count") or 0
        false_positives = pattern.get("false_positive_count") or 0
        observed = pattern.get("observed_count") or 0

        # >= rather than a strict >: a pattern that has been wrong as often as it
        # has been right is a coin flip, not "validated" — it must not carry the
        # same scoring weight as a spotless record (see PATTERN POISONING
        # RESISTANCE). The false_positives >= 2 floor is a sample-size guard, not
        # a leniency toward ties: one lone false positive against one lone
        # confirmation is too little data to deprecate on either count.
        if false_positives >= 2 and false_positives >= confirmed:
            return "deprecated"
        if confirmed >= 3 and false_positives == 0:
            return "trusted"
        if confirmed >= 1:
            return "validated"
        if observed >= 3:
            return "repeated"
        if observed >= 2:
            return "candidate"
        return "observed"

    def record_case(self, case) -> None:
        """Feed a completed investigation into institutional memory: every entity into
        indicator memory, and the case's structural shape into pattern memory (see
        LEARNING LOOP). Both are recorded as *observations* only — neither is treated
        as validated knowledge until an outcome is confirmed."""
        now = datetime.now(timezone.utc).isoformat()
        risk_category = case.risk.category.value if case.risk else None
        for entity in case.entities.values():
            # Recording commodity infrastructure would make every future case that
            # uses the same vendor match this one.
            if entity.shared_infrastructure:
                continue
            self.storage.record_indicator(
                case_id=case.id,
                entity_type=entity.type.value,
                value=entity.value,
                seed=case.seed,
                outcome=case.outcome,
                risk_category=risk_category,
                created_at=now,
            )

        pattern_id, facets = self.signature_for(case)
        # Benign shapes *are* recorded: recognising "this looks like a long-lived
        # legitimate domain" is intelligence too, and OUTCOME_TRUST keeps a benign
        # resemblance from raising anyone's risk.
        if len(facets) < MIN_FACETS_FOR_A_SHAPE:
            return
        self.storage.observe_pattern(
            pattern_id=pattern_id,
            name=_pattern_name(facets),
            description=f"co-occurring case structure first observed in case {case.id}",
            signature={"facets": facets},
            now=now,
        )
        self.storage.link_case_pattern(case.id, pattern_id)

    def apply_outcome(self, case_id: str, outcome: str) -> None:
        """Close the learning loop for a validated case (see CLOSED-LOOP LEARNING).

        Only outcomes a human actually confirmed move pattern confidence. An
        'inconclusive' or 'unknown' result deliberately changes nothing: treating
        uncertainty as weak confirmation is exactly how a memory poisons itself.
        """
        self.storage.set_outcome(case_id, outcome)

        if outcome in (Outcome.CONFIRMED_MALICIOUS.value, Outcome.FALSE_NEGATIVE.value):
            confirmed = True
        elif outcome in (Outcome.FALSE_POSITIVE.value, Outcome.CONFIRMED_BENIGN.value):
            confirmed = False
        else:
            return

        now = datetime.now(timezone.utc).isoformat()
        for pattern_id in self.storage.patterns_for_case(case_id):
            self.storage.strengthen_pattern(pattern_id, confirmed=confirmed, now=now)

    def list_patterns(self) -> list[dict[str, Any]]:
        """Stored patterns with their derived lifecycle stage."""
        patterns = self.storage.list_patterns()
        for p in patterns:
            p["stage"] = self.stage_for(p)
        return patterns


def _facets_of(pattern: dict[str, Any]) -> list[str]:
    signature = pattern.get("signature") or {}
    # "signals" is the pre-structural-matching key; such rows simply never match,
    # which is the correct outcome for a signature written under different rules.
    return signature.get("facets") or signature.get("signals") or []


def _pattern_name(facets: list[str]) -> str:
    """Readable name from the most meaningful facets: what argued for a threat,
    else what argued against one, else the bare shape of the investigation."""
    for prefix in ("signal+:", "signal-:"):
        labels = [f.split(":", 2)[-1] for f in facets if f.startswith(prefix)]
        if labels:
            return " + ".join(labels[:4])
    return " + ".join(f.split(":", 1)[-1] for f in facets[:4])


def _pattern_outcome(pattern: dict[str, Any], cases: list[dict[str, Any]]) -> str:
    """The outcome a structural match should be judged by.

    Any validated-malicious confirmation dominates, because a shape that has ever
    been confirmed malicious stays worth flagging; the deprecation rule in
    stage_for() is what neutralises shapes that keep turning out benign.
    """
    if (pattern.get("confirmed_count") or 0) > 0:
        return Outcome.CONFIRMED_MALICIOUS.value
    outcomes = [c["outcome"] for c in cases if c["outcome"]]
    return outcomes[0] if len(set(outcomes)) == 1 else Outcome.UNKNOWN.value


def _match_type(match: dict[str, Any]) -> str:
    if match["indicator_similarity"] and match["structural_similarity"]:
        return "indicator+structural"
    return "structural" if match["structural_similarity"] else "indicator"
