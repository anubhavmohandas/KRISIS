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
  - llm mode (optional, used only if an API key is configured): sends the same
    structured findings to Claude with an explicit instruction not to add,
    infer, or embellish evidence beyond what's given, and to say so if
    evidence is thin. Falls back to template mode on any failure.
"""

from __future__ import annotations

import json
import os
from typing import Optional

from ..core.correlation import CorrelationResult
from ..core.graph import EntityGraph
from ..core.models import Case, RiskCategory

SYSTEM_PROMPT = (
    "You are the explanation layer of KRISIS, a threat-investigation engine. "
    "You will be given the structured findings of a completed investigation: "
    "extracted evidence, supporting/contradicting evidence, relationships discovered, "
    "historical pattern matches, and a computed risk score and confidence. "
    "Write a short, clear explanation of the finding for a non-expert reader. "
    "Rules:\n"
    "- Use ONLY the evidence provided. Never invent, assume, or infer evidence not given.\n"
    "- Never claim a source was consulted if it is not present in the findings.\n"
    "- If evidence is thin or a provider was unavailable, say so plainly.\n"
    "- If the risk category is INSUFFICIENT_EVIDENCE or CONFLICTING_EVIDENCE, do NOT "
    "present the artifact as safe. State clearly that KRISIS could not reach a verdict, "
    "and why, using the 'uncertainty' field. A low score in these states means "
    "'not established', never 'clean'.\n"
    "- Explicitly separate current reputation from historical pattern similarity if both exist.\n"
    "- Mention both supporting and contradicting evidence, even if one side is empty.\n"
    "- End with why the confidence level is what it is.\n"
    "- Keep it under 180 words. No headers, no bullet spam — plain prose."
)


class Explainer:
    def __init__(self, use_llm: bool = True):
        self.use_llm = use_llm and bool(os.environ.get("ANTHROPIC_API_KEY"))

    def explain(self, case: Case, graph: EntityGraph, correlation: CorrelationResult) -> str:
        if self.use_llm:
            llm_result = self._explain_with_llm(case, correlation)
            if llm_result:
                return llm_result
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
        else:
            lines.append("No contradicting evidence was found.")

        if case.pattern_matches:
            best = case.pattern_matches[0]
            # Name which dimension matched: "resembles a prior case" means something
            # very different when no concrete indicator is shared at all.
            basis = {
                "indicator": "shared infrastructure",
                "structural": "case structure alone, with no shared infrastructure",
                "indicator+structural": "shared infrastructure and case structure",
            }.get(best.get("match_type", "indicator"), "shared infrastructure")
            lines.append(
                f"Historical similarity: {best['similarity']:.0%} to {best['pattern_name']} "
                f"via {basis}"
                f"{' (prior outcome: ' + best['prior_outcome'] + ')' if best.get('prior_outcome') else ''}, "
                f"independent of current reputation."
            )

        if case.provider_failures:
            lines.append(
                f"{len(case.provider_failures)} evidence source(s) were unavailable during this "
                f"investigation; absence of their data was not treated as a clean result."
            )

        return " ".join(lines)

    # -- optional LLM enhancement ---------------------------------------------

    def _explain_with_llm(self, case: Case, correlation: CorrelationResult) -> Optional[str]:
        try:
            import requests
        except ImportError:
            return None

        findings = {
            "seed": case.seed,
            "risk": case.risk.to_dict() if case.risk else None,
            "uncertainty": case.risk.uncertainty if case.risk else {},
            "supporting_evidence": [e.to_dict() for e in correlation.supporting],
            "contradicting_evidence": [e.to_dict() for e in correlation.contradicting],
            "pattern_matches": case.pattern_matches,
            "provider_failures": case.provider_failures,
            "entities_investigated": len(case.entities),
            "relationships_discovered": len(case.relationships),
        }

        try:
            resp = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": os.environ["ANTHROPIC_API_KEY"],
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-sonnet-4-6",
                    "max_tokens": 400,
                    "system": SYSTEM_PROMPT,
                    "messages": [
                        {"role": "user", "content": json.dumps(findings, default=str)}
                    ],
                },
                timeout=20,
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            text_blocks = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
            text = "\n".join(text_blocks).strip()
            return text or None
        except Exception:
            return None
