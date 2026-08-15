"""
AI explanation layer tests.

The model is downstream of every decision: it receives a finished investigation
and writes prose. These tests hold that boundary — that the model is never asked
to parse the raw case, never consulted without a key, and can never be the reason
an explanation fails to appear.
"""

import json
import os
import unittest
from unittest import mock

from krisis import config
from krisis.ai.explain import Explainer, _render_structured
from krisis.core.correlation import CorrelationResult
from krisis.core.graph import EntityGraph
from krisis.core.models import (
    Case, Entity, EntityType, Evidence, Independence, Polarity, Relationship,
    RiskAssessment, RiskCategory,
)


def _case() -> tuple[Case, CorrelationResult]:
    case = Case(seed="lookalike.example", seed_type=EntityType.DOMAIN)
    for i in range(40):
        entity = Entity(value=f"host{i}.example", type=EntityType.DOMAIN, depth=1)
        case.entities[entity.id] = entity
        rel = Relationship(
            source_entity_id="root", target_entity_id=entity.id,
            relation_type="resolves_to", reason="observed",
        )
        case.relationships[rel.id] = rel
    supporting = [
        Evidence(
            source="identity", entity_id="root", signal="lookalike_domain",
            value="real.example", evidence_type="identity",
            polarity=Polarity.SUPPORTS_THREAT, confidence=0.9,
            independence=Independence.INDEPENDENT, provenance="derived and verified",
        )
    ]
    case.risk = RiskAssessment(
        score=39, category=RiskCategory.MEDIUM, confidence=0.7,
        supporting=[e.to_dict() for e in supporting], contradicting=[],
        top_contributors=["lookalike_domain (identity)"],
        uncertainty={"reason": "imitates an established identity"},
    )
    case.provider_usage = {"virustotal": {"calls": 1, "skipped": 4}}
    case.recommendation = "verify through an independent channel"
    return case, CorrelationResult(supporting=supporting, evidence_diversity=0.5)


class TestFindingsPayload(unittest.TestCase):
    def test_the_model_receives_a_summary_not_the_raw_case(self):
        """Send case.to_dict() instead and the model is handed forty entities and every
        observation to sift through. A large context window is headroom, not a reason
        to make the model do the investigator's reading."""
        case, correlation = _case()
        findings = Explainer.findings(case, correlation)

        self.assertNotIn("entities", findings)
        self.assertNotIn("evidence", findings)
        self.assertNotIn("pivots", findings)
        self.assertLessEqual(len(findings["relationships"]), 20)

    def test_the_summary_carries_what_the_verdict_rests_on(self):
        case, correlation = _case()
        findings = Explainer.findings(case, correlation)

        self.assertEqual(findings["risk"]["score"], 39)
        self.assertTrue(findings["uncertainty"])
        self.assertEqual(findings["supporting_evidence"][0]["signal"], "lookalike_domain")
        self.assertIn("provenance", findings["supporting_evidence"][0])
        self.assertIn("freshness", findings["supporting_evidence"][0])
        self.assertEqual(findings["provider_usage"]["virustotal"]["skipped"], 4)


class TestStructuredOutput(unittest.TestCase):
    def test_structured_json_is_rendered_into_prose(self):
        rendered = _render_structured(json.dumps({
            "summary": "This domain imitates another.",
            "key_findings": ["glyph substitution"],
            "uncertainties": ["TLS unavailable"],
            "recommended_actions": ["verify independently"],
        }))
        self.assertIn("This domain imitates another.", rendered)
        self.assertIn("glyph substitution", rendered)
        self.assertIn("TLS unavailable", rendered)

    def test_a_fenced_response_is_still_parsed(self):
        rendered = _render_structured('```json\n{"summary": "Fenced."}\n```')
        self.assertEqual(rendered, "Fenced.")

    def test_prose_instead_of_json_is_used_as_written(self):
        """A model that ignores the format instruction must not cost the user their
        explanation."""
        self.assertEqual(_render_structured("Just prose."), "Just prose.")


class TestModelBoundary(unittest.TestCase):
    def test_without_a_key_the_deterministic_template_is_used(self):
        case, correlation = _case()
        with mock.patch("requests.post", side_effect=AssertionError("must not be called")):
            explanation = Explainer(use_llm=False).explain(case, EntityGraph(), correlation)
        self.assertIn("MEDIUM", explanation)

    def test_discounted_counter_evidence_is_not_silently_dropped(self):
        """A counter-evidence item the risk engine excluded from the score
        arithmetic (e.g. a valid certificate that does not rebut an identity
        finding) must say so in the fallback explanation — the one path every
        user sees whether or not an AI key is configured. Otherwise the reader
        sees 'Contradicting evidence: valid_tls_present' with no hint that it was
        never allowed to offset the finding above it."""
        case, correlation = _case()
        tls = Evidence(
            source="tls", entity_id="root", signal="valid_tls_present", value="Some CA",
            evidence_type="infrastructure", polarity=Polarity.CONTRADICTS_THREAT,
            confidence=0.25, independence=Independence.INDEPENDENT,
        )
        correlation.contradicting = [tls]
        case.risk.contradicting = [tls.to_dict()]
        case.risk.uncertainty["discounted_counter_evidence"] = [
            "'valid_tls_present' (tls) is reported but does not offset the identity "
            "finding: a valid certificate proves control of this endpoint, not that its "
            "operator is the organization this name resembles"
        ]
        explanation = Explainer(use_llm=False).explain(case, EntityGraph(), correlation)
        self.assertIn("does not offset the identity finding", explanation)

    def test_a_failing_model_falls_back_instead_of_failing_the_case(self):
        """Delete the fallback in explain() and a provider outage takes out the
        explanation of an investigation that already completed."""
        case, correlation = _case()
        explainer = Explainer(use_llm=False)
        explainer.use_llm, explainer.api_key = True, "test-key"
        with mock.patch("requests.post", side_effect=OSError("connection reset")):
            explanation = explainer.explain(case, EntityGraph(), correlation)
        self.assertIn("MEDIUM", explanation)

    def test_the_model_is_configured_in_one_place(self):
        """A model id scattered through the codebase cannot be swapped; KRISIS_AI_MODEL
        is the only thing that decides which model explains an investigation."""
        with mock.patch.dict(os.environ, {"KRISIS_AI_MODEL": "vendor/some-other-model"}):
            self.assertEqual(config.ai_model(), "vendor/some-other-model")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("KRISIS_AI_MODEL", None)
            self.assertEqual(config.ai_model(), config.DEFAULT_AI_MODEL)

    def test_the_request_carries_the_findings_and_the_configured_model(self):
        case, correlation = _case()
        explainer = Explainer(use_llm=False)
        explainer.use_llm, explainer.api_key = True, "test-key"
        response = mock.Mock(status_code=200)
        response.json.return_value = {
            "choices": [{"message": {"content": '{"summary": "Explained."}'}}]
        }
        with mock.patch("requests.post", return_value=response) as post:
            explanation = explainer.explain(case, EntityGraph(), correlation)

        self.assertEqual(explanation, "Explained.")
        body = post.call_args.kwargs["json"]
        self.assertEqual(body["model"], config.ai_model())
        self.assertEqual(post.call_args.kwargs["headers"]["Authorization"], "Bearer test-key")
        sent = json.loads(body["messages"][-1]["content"])
        self.assertEqual(sent["risk"]["score"], 39, "the model must be told what was decided")


if __name__ == "__main__":
    unittest.main()
