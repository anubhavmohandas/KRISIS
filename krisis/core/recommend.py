"""
Recommendation / Action Engine (see RECOMMENDATION / ACTION ENGINE in the
design doc). Advisory only in this CLI phase — KRISIS never automatically
blocks or deletes anything.
"""

from __future__ import annotations

from .models import RiskAssessment, RiskCategory

_ACTIONS = {
    RiskCategory.LOW: (
        "LOW risk. No strong evidence of malicious activity was found. "
        "Normal caution still applies for any unfamiliar site or message."
    ),
    RiskCategory.MEDIUM: (
        "MEDIUM risk. Some suspicious signals were found but the evidence is not "
        "conclusive. Verify the organization or sender through an independent channel "
        "before entering credentials, payment details, or personal information."
    ),
    RiskCategory.HIGH: (
        "HIGH risk. Multiple independent signals support a threat hypothesis. "
        "Do not enter credentials or personal/financial information. "
        "Verify through a separately known-good channel before interacting further."
    ),
    RiskCategory.CRITICAL: (
        "CRITICAL risk. Strong, corroborated evidence of malicious infrastructure or intent. "
        "Do not interact with this artifact. Preserve evidence (do not delete the message/file), "
        "and report it through your organization's security channel or the relevant platform."
    ),
    RiskCategory.INSUFFICIENT_EVIDENCE: (
        "INSUFFICIENT EVIDENCE. KRISIS could not gather enough evidence to judge this "
        "artifact — this is NOT a clean result, and it must not be read as one. "
        "Treat the artifact as unverified: do not enter credentials or personal "
        "information, and verify through an independently known-good channel."
    ),
    RiskCategory.CONFLICTING_EVIDENCE: (
        "CONFLICTING EVIDENCE. Sources disagree at comparable strength, so no single "
        "verdict is supportable from what was collected. Review the supporting and "
        "contradicting evidence below before acting, and avoid submitting sensitive "
        "information until the conflict is resolved."
    ),
    RiskCategory.UNKNOWN: (
        "Insufficient evidence was collected to reach a confident conclusion. "
        "Treat the artifact with caution and avoid providing sensitive information until "
        "more evidence is available."
    ),
}

_INDECISIVE = (
    RiskCategory.INSUFFICIENT_EVIDENCE,
    RiskCategory.CONFLICTING_EVIDENCE,
    RiskCategory.UNKNOWN,
)


def recommend_action(risk: RiskAssessment) -> str:
    base = _ACTIONS.get(risk.category, _ACTIONS[RiskCategory.UNKNOWN])

    # A reassuring verdict reached on weak evidence is the one failure mode with a
    # real-world cost, so low confidence downgrades the advice rather than the score.
    if risk.confidence < 0.25 and risk.category in (RiskCategory.LOW, RiskCategory.MEDIUM):
        base = (
            f"{_ACTIONS[RiskCategory.INSUFFICIENT_EVIDENCE]} "
            f"(Confidence in this specific assessment was low: {risk.confidence:.0%}.)"
        )

    reason = risk.uncertainty.get("reason") if risk.uncertainty else None
    if reason and risk.category in _INDECISIVE:
        base = f"{base} Reason: {reason}."

    unavailable = risk.uncertainty.get("unavailable_sources") if risk.uncertainty else None
    if unavailable:
        base = f"{base} Sources that could not be checked: {', '.join(unavailable)}."
    return base
