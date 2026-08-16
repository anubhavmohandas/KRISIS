"""
AI explanation layer (see AI LAYER / EXPLAINABILITY in the design doc).

The correct flow is Evidence -> Correlation -> Risk -> Explanation. This module
sits strictly after the risk engine and receives only the structured findings
it already computed — it is never given raw internet access or asked to
"decide" anything. Its job is translation into plain language, not detection.

Two modes:
  - template mode (default, always available): builds the explanation directly
    from the structured Case/CorrelationResult data with simple string
    formatting. Deterministic, zero hallucination risk, no dependency.
  - model mode (optional, used only if an API key is configured): sends the same
    structured findings to the configured model — by default NVIDIA's
    nvidia/nemotron-3-super-120b-a12b, over an OpenAI-compatible endpoint — with
    an explicit instruction not to add, infer, or embellish evidence beyond what
    is given. Falls back to template mode on any failure.

What the model receives is a *summary* of the completed investigation, not its
raw contents: the risk assessment, the evidence that carried weight, what
contradicted it, what matched historically, what was uncertain, and what each
provider cost. A large context window is headroom, not a reason to paste
thousands of observations in and hope the model finds the point.

    KRISIS investigates. The model translates.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from ..core.correlation import CorrelationResult
from ..core.graph import EntityGraph
from ..core.models import Case, RiskCategory
from ..core.risk import historical_match_label

SYSTEM_PROMPT = (
    "You are the explanation layer of KRISIS, a threat-investigation engine. "
    "You will be given the structured findings of a completed investigation: "
    "extracted evidence, supporting/contradicting evidence, relationships discovered, "
    "historical pattern matches, provider usage, and a computed risk score and confidence. "
    "Explain the finding for a non-expert reader.\n"
    "Rules:\n"
    "- Use ONLY the evidence provided. Never invent, assume, or infer evidence not given.\n"
    "- Never claim a source was consulted if it is not present in the findings. If a "
    "provider was skipped, unavailable or rate limited, that is not a clean result.\n"
    "- The risk score, category and confidence are already decided. Explain them; never "
    "dispute, recompute or replace them.\n"
    "- If the risk category is INSUFFICIENT_EVIDENCE or CONFLICTING_EVIDENCE, do NOT "
    "present the artifact as safe. State clearly that KRISIS could not reach a verdict, "
    "and why, using the 'uncertainty' field. A low score in these states means "
    "'not established', never 'clean'.\n"
    "- Explicitly separate current reputation, identity/impersonation findings, and "
    "historical pattern similarity where more than one exists.\n"
    "- Mention both supporting and contradicting evidence, even if one side is empty.\n"
    "Respond with ONLY a JSON object, no code fences, no commentary:\n"
    '{"summary": "<=120 words of plain prose", "key_findings": ["..."], '
    '"uncertainties": ["..."], "recommended_actions": ["..."]}'
)


class Explainer:
    def __init__(self, use_llm: bool = True, model: Optional[str] = None):
        from ..credentials import resolve   # local: keeps the import graph flat

        self.api_key = resolve("NVIDIA_API_KEY")
        self.model = model
        self.use_llm = use_llm and bool(self.api_key)
        self.last_source = "deterministic"

    def explain(self, case: Case, graph: EntityGraph, correlation: CorrelationResult) -> str:
        # Recorded so a downstream consumer (the PDF report) can label the stored
        # explanation "plain-language" vs "deterministic" truthfully instead of
        # guessing from whether NVIDIA_API_KEY happens to be configured now.
        if self.use_llm:
            model_result = self._explain_with_model(case, correlation)
            if model_result:
                self.last_source = "ai"
                return model_result
        self.last_source = "deterministic"
        return self._explain_with_template(case, correlation)

    # -- deterministic fallback / default ------------------------------------

    def _explain_with_template(self, case: Case, correlation: CorrelationResult) -> str:
        risk = case.risk
        if risk is None:
            return "Investigation did not complete far enough to reach a risk assessment."

        lines: list[str] = []
        if risk.category in (RiskCategory.INSUFFICIENT_EVIDENCE, RiskCategory.CONFLICTING_EVIDENCE,
                             RiskCategory.UNKNOWN):
            headline = risk.category.value.replace("_", " ").lower()
            lines.append(
                f"KRISIS reached no verdict for '{case.seed}' — {headline} "
                f"(score so far {risk.score}/100, confidence {risk.confidence:.0%}). "
                f"This is not a clean result."
            )
            if risk.uncertainty.get("reason"):
                lines.append(f"{risk.uncertainty['reason'].capitalize()}.")
        else:
            lines.append(
                f"{risk.category.value} RISK ({risk.score}/100, confidence {risk.confidence:.0%}) "
                f"for '{case.seed}'."
            )

        if correlation.supporting:
            top = ", ".join(f"{e.signal} ({e.source})" for e in correlation.supporting[:4])
            lines.append(f"Supporting evidence: {top}.")
        else:
            lines.append("No evidence directly supporting a threat hypothesis was found.")

        if correlation.contradicting:
            top = ", ".join(f"{e.signal} ({e.source})" for e in correlation.contradicting[:4])
            lines.append(f"Contradicting evidence: {top}.")
            # See risk._discount_narrow_contradictions: some of the above is listed
            # for completeness but was not allowed to offset the finding above it —
            # without saying so, a reader has no way to tell the two apart.
            for note in risk.uncertainty.get("discounted_counter_evidence") or []:
                lines.append(note + ".")
        else:
            lines.append("No contradicting evidence was found.")

        if case.pattern_matches:
            best = case.pattern_matches[0]
            # Name which dimension matched, and — critically — whether the shared
            # indicator (if any) was the exact artifact a prior case investigated,
            # or merely infrastructure it happened to touch. "Resembles a prior
            # case" means something very different in each of those readings, and
            # collapsing them into one generic "historical similarity" is exactly
            # the ambiguity this line exists to remove.
            lines.append(
                f"Historical match — {historical_match_label(best)}: {best['similarity']:.0%} to "
                f"{best['pattern_name']}"
                f"{' (prior outcome: ' + best['prior_outcome'] + ')' if best.get('prior_outcome') else ''}, "
                f"independent of current reputation."
            )

        if case.provider_failures:
            lines.append(
                f"{len(case.provider_failures)} evidence source(s) were unavailable during this "
                f"investigation; absence of their data was not treated as a clean result."
            )

        return " ".join(lines)

    # -- optional model enhancement -------------------------------------------

    @staticmethod
    def findings(case: Case, correlation: CorrelationResult) -> dict[str, Any]:
        """The investigation, summarised for explanation.

        Deliberately not the graph: only what a reader needs to understand the
        verdict — what was found, what argued against it, what matched history, what
        stayed unknown, and what each provider was actually asked.
        """
        return {
            "seed": case.seed,
            "seed_type": case.seed_type.value,
            "risk": case.risk.to_dict() if case.risk else None,
            "uncertainty": case.risk.uncertainty if case.risk else {},
            "supporting_evidence": [
                {k: e.to_dict()[k] for k in ("source", "signal", "value", "evidence_type",
                                             "confidence", "provenance", "freshness")}
                for e in correlation.supporting
            ],
            "contradicting_evidence": [
                {k: e.to_dict()[k] for k in ("source", "signal", "value", "evidence_type",
                                             "confidence", "provenance", "freshness")}
                for e in correlation.contradicting
            ],
            "relationships": [
                {"type": r.relation_type, "reason": r.reason} for r in case.relationships.values()
            ][:20],
            "pattern_matches": case.pattern_matches,
            "provider_failures": case.provider_failures,
            "provider_usage": case.provider_usage,
            "entities_investigated": len(case.entities),
            "recommended_action": case.recommendation,
        }

    def _explain_with_model(self, case: Case, correlation: CorrelationResult) -> Optional[str]:
        try:
            import requests

            from ..config import ai_base_url, ai_model
        except ImportError:
            return None

        try:
            resp = requests.post(
                f"{ai_base_url()}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "content-type": "application/json",
                },
                json={
                    "model": self.model or ai_model(),
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": json.dumps(
                            self.findings(case, correlation), default=str)},
                    ],
                    # Low temperature: this is a translation task with a fixed input,
                    # and creative variation in a security explanation is a defect.
                    "temperature": 0.2,
                    "top_p": 0.95,
                    "max_tokens": 900,
                    "chat_template_kwargs": {"enable_thinking": False},
                },
                timeout=45,
            )
            if resp.status_code != 200:
                return None
            content = (
                resp.json().get("choices", [{}])[0].get("message", {}).get("content") or ""
            ).strip()
        except Exception:
            return None

        return _render_structured(content) if content else None


def _render_structured(content: str) -> Optional[str]:
    """Turn the model's JSON answer into the prose the CLI prints.

    Structured output is requested because it keeps the model inside its lane —
    summary, findings, uncertainties, actions — but KRISIS must not break when a
    model returns prose anyway, so unparseable output is used as-is rather than
    discarded. Either way nothing here can change a score: this function only ever
    formats text that arrives after the risk engine has finished.
    """
    text = content.strip()
    if text.startswith("```"):
        text = text.split("```")[1] if "```" in text[3:] else text.strip("`")
        text = text.split("\n", 1)[-1] if text.lower().startswith("json") else text
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return content or None
    if not isinstance(data, dict):
        return content or None

    lines = [str(data.get("summary", "")).strip()]
    for label, key in (
        ("Key findings", "key_findings"),
        ("Uncertain", "uncertainties"),
        ("Recommended", "recommended_actions"),
    ):
        items = [str(i).strip() for i in data.get(key) or [] if str(i).strip()]
        if items:
            lines.append(f"{label}: " + "; ".join(items) + ".")
    rendered = " ".join(line for line in lines if line).strip()
    return rendered or None
