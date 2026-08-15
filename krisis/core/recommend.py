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
    RiskCategory.UNKNOWN: (
        "Insufficient evidence was collected to reach a confident conclusion. "
        "Treat the artifact with caution and avoid providing sensitive information until "
        "more evidence is available."
    ),
}


def recommend_action(risk: RiskAssessment) -> str:
    if risk.confidence < 0.25 and risk.category in (RiskCategory.LOW, RiskCategory.MEDIUM):
        return (
            f"{_ACTIONS[RiskCategory.UNKNOWN]} "
            f"(Confidence in this specific assessment was low: {risk.confidence:.0%}.)"
        )
    return _ACTIONS.get(risk.category, _ACTIONS[RiskCategory.UNKNOWN])
