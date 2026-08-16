"""
PDF case-report tests.

Before this, a completed investigation lived only in the terminal or as JSON —
there was no way to hand someone a self-contained case report (see CASE REPORT
EXPORT in the design doc). These tests hold three things: the PDF is generated
from the stored case alone (no network, no case mutation, no re-investigation),
its content is faithful to that stored case (not a second, independently
computed summary), and the historical-match / provider-skip-vs-failure
distinctions the CLI and JSON renderers already guarantee survive into the PDF
too.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from click.testing import CliRunner
from pypdf import PdfReader

from krisis.cli import cli
from krisis.core.models import (
    Case, Coverage, Entity, EntityType, Evidence, Independence, Pivot, Polarity, Relationship,
)
from krisis.core.risk import RiskEngine
from krisis.core.correlation import CorrelationResult
from krisis.memory.case_memory import CaseMemory
from krisis.memory.pattern_memory import PatternMemory
from krisis.memory.storage import Storage
from krisis import pdf_report


def _build_case(explanation_source: str = "deterministic") -> Case:
    """A synthetic case exercising every section the PDF has to render:
    supporting + contradicting evidence with provenance, an accepted and a
    rejected pivot, distinct provider skips/failures, and two historical
    matches on different semantic dimensions (exact-artifact and
    structural-only). No real target, no real secrets."""
    case = Case(seed="netflix-login.example", seed_type=EntityType.DOMAIN)

    identity_ev = Evidence(
        source="identity", entity_id="e1", signal="lookalike_domain", value="netflix.example",
        evidence_type="identity", polarity=Polarity.SUPPORTS_THREAT, confidence=0.8,
        independence=Independence.INDEPENDENT, provenance="homoglyph match against known brand",
    )
    tls_ev = Evidence(
        source="tls", entity_id="e1", signal="valid_tls_present", value="Some CA",
        evidence_type="infrastructure", polarity=Polarity.CONTRADICTS_THREAT, confidence=0.25,
        independence=Independence.INDEPENDENT, provenance="certificate chain validated",
    )
    entity = Entity(value="netflix-login.example", type=EntityType.DOMAIN, id="e1", depth=0)
    pivot_target = Entity(value="203.0.113.9", type=EntityType.IP, id="e2", depth=1)
    case.entities[entity.id] = entity
    case.entities[pivot_target.id] = pivot_target
    case.evidence[identity_ev.id] = identity_ev
    case.evidence[tls_ev.id] = tls_ev
    case.relationships["r1"] = Relationship(
        source_entity_id="e1", target_entity_id="e2", relation_type="resolves_to",
        reason="domain resolves to this IP", id="r1",
    )
    case.pivots.append(Pivot(
        entity_value="203.0.113.9", entity_type=EntityType.IP, reason="domain resolves to this IP",
        priority=0.6, source_entity_id="e1", status="accepted",
    ))
    case.pivots.append(Pivot(
        entity_value="mail.example.net", entity_type=EntityType.DOMAIN, reason="shared mail provider",
        priority=0.15, source_entity_id="e1", status="rejected",
        rejection_reason="commodity infrastructure, below value threshold",
    ))

    correlation = CorrelationResult(supporting=[identity_ev], contradicting=[tls_ev], evidence_diversity=0.5)
    coverage = Coverage(attempted={"identity", "tls", "whois"}, available={"identity", "tls"},
                         evidence_types={"identity", "infrastructure"})
    case.risk = RiskEngine().score(correlation, coverage=coverage)
    case.explanation = "test explanation text unique-marker-9f3a"
    case.explanation_source = explanation_source
    case.recommendation = "test recommendation unique-marker-7c1b"
    case.provider_usage = {
        "identity": {"calls": 1, "cached": 0, "deduplicated": 0, "skipped": 0, "rate_limited": 0, "skip_reasons": []},
        "tls": {"calls": 1, "cached": 0, "deduplicated": 0, "skipped": 0, "rate_limited": 0, "skip_reasons": []},
        "virustotal": {"calls": 0, "cached": 0, "deduplicated": 0, "skipped": 1, "rate_limited": 0,
                       "skip_reasons": ["virustotal skipped for mail.example.net: below value threshold"]},
    }
    case.provider_failures = ["whois unavailable for netflix-login.example: timeout-marker-aa11"]
    case.provider_skips = ["virustotal skipped for mail.example.net: below value threshold"]
    case.pattern_matches = [
        {
            "pattern_id": "case_prior_exact", "pattern_name": "the same artifact investigated before as 'netflix-login.example'",
            "indicator_similarity": 0.9, "structural_similarity": 0.0,
            "matched_indicators": ["domain:netflix-login.example"], "indicator_kind": "exact_artifact",
            "matched_facets": [], "pattern_stage": None, "prior_outcome": "confirmed_malicious",
            "similarity": 0.9, "match_type": "indicator",
        },
        {
            "pattern_id": "case_prior_structural", "pattern_name": "structural pattern 'credential-phish-shape'",
            "indicator_similarity": 0.0, "structural_similarity": 0.7,
            "matched_indicators": [], "indicator_kind": None,
            "matched_facets": ["identity:lookalike", "infra:new_registration"], "pattern_stage": "repeated",
            "prior_outcome": "unknown", "similarity": 0.42, "match_type": "structural",
        },
    ]
    return case


def _stored_case_id(db_path: str, **kwargs) -> str:
    storage = Storage(db_path)
    pattern_memory = PatternMemory(storage)
    case_memory = CaseMemory(storage, pattern_memory)
    case = _build_case(**kwargs)
    case_memory.save(case)
    return case.id


class TestGeneratePdfDirect(unittest.TestCase):
    """Unit-level: pdf_report.generate_pdf() against a case dict, no CLI/storage
    involved — pins the module's own contract independent of how it's invoked."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.case_dict = _build_case().to_dict()

    def test_generation_succeeds_and_returns_the_written_path(self):
        out = os.path.join(self.tmpdir, "out.pdf")
        path = pdf_report.generate_pdf(self.case_dict, out)
        self.assertEqual(path, out)
        self.assertTrue(os.path.isfile(out))
        self.assertGreater(os.path.getsize(out), 0)

    def test_default_output_path_is_deterministic(self):
        self.assertEqual(
            pdf_report.default_output_path("case_abc123"),
            os.path.join("reports", "case_abc123.pdf"),
        )
        # calling twice with no override must not vary
        self.assertEqual(
            pdf_report.default_output_path("case_abc123"),
            pdf_report.default_output_path("case_abc123"),
        )

    def test_generation_does_not_mutate_the_case_dict(self):
        import copy
        before = copy.deepcopy(self.case_dict)
        pdf_report.generate_pdf(self.case_dict, os.path.join(self.tmpdir, "out.pdf"))
        self.assertEqual(self.case_dict, before)

    def test_stored_case_alone_is_sufficient_no_extra_lookups(self):
        """A case dict with no risk/evidence/graph at all (the minimum a stored
        case could ever be) must still render rather than crash — replay must
        never depend on anything beyond what to_dict() produced."""
        minimal = {"id": "case_min", "seed": "x.example", "seed_type": "domain", "created_at": ""}
        out = os.path.join(self.tmpdir, "min.pdf")
        path = pdf_report.generate_pdf(minimal, out)
        self.assertTrue(os.path.isfile(path))


def _extract_text(path: str) -> str:
    return "\n".join(page.extract_text() or "" for page in PdfReader(path).pages)


class TestShowPdfCommand(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.runner = CliRunner()

    def _invoke(self, *args):
        # Same guard test_cli.py uses for `show`: PDF export must never touch
        # the network, so any call to either requests entry point is a bug.
        with mock.patch("requests.get", side_effect=AssertionError("PDF export must not touch the network")), \
             mock.patch("requests.post", side_effect=AssertionError("PDF export must not touch the network")):
            return self.runner.invoke(cli, list(args), catch_exceptions=False)

    def test_pdf_flag_documented_in_show_help(self):
        result = self.runner.invoke(cli, ["show", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("--pdf", result.output)
        self.assertIn("--output", result.output)

    def test_pdf_export_succeeds_with_explicit_output(self):
        case_id = _stored_case_id(self.db_path)
        out = os.path.join(self.tmpdir, "case.pdf")
        result = self._invoke("show", case_id, "--db", self.db_path, "--pdf", "--output", out)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Case report exported", result.output)
        self.assertIn(out, result.output)
        self.assertTrue(os.path.isfile(out))

    def test_pdf_export_uses_deterministic_default_path(self):
        case_id = _stored_case_id(self.db_path)
        cwd = os.getcwd()
        os.chdir(self.tmpdir)
        try:
            result = self._invoke("show", case_id, "--db", self.db_path, "--pdf")
            self.assertEqual(result.exit_code, 0)
            expected = os.path.join("reports", f"{case_id}.pdf")
            self.assertTrue(os.path.isfile(expected))
        finally:
            os.chdir(cwd)

    def test_pdf_export_does_not_alter_the_stored_case(self):
        case_id = _stored_case_id(self.db_path)
        before = Storage(self.db_path).get_case(case_id)
        out = os.path.join(self.tmpdir, "case.pdf")
        self._invoke("show", case_id, "--db", self.db_path, "--pdf", "--output", out)
        after = Storage(self.db_path).get_case(case_id)
        self.assertEqual(before, after)

    def test_pdf_content_matches_the_stored_case(self):
        case_id = _stored_case_id(self.db_path)
        out = os.path.join(self.tmpdir, "case.pdf")
        self._invoke("show", case_id, "--db", self.db_path, "--pdf", "--output", out)
        text = _extract_text(out)
        self.assertIn(case_id, text)
        self.assertIn("netflix-login.example", text)
        self.assertIn("MEDIUM", text)
        self.assertIn("Confidence:", text)
        self.assertIn("test recommendation unique-marker-7c1b", text)
        self.assertIn("test explanation text unique-marker-9f3a", text)
        self.assertIn("lookalike_domain", text)
        self.assertIn("valid_tls_present", text)

    def test_pdf_labels_deterministic_explanation_correctly(self):
        case_id = _stored_case_id(self.db_path, explanation_source="deterministic")
        out = os.path.join(self.tmpdir, "case.pdf")
        self._invoke("show", case_id, "--db", self.db_path, "--pdf", "--output", out)
        text = _extract_text(out)
        self.assertIn("Deterministic Explanation", text)
        self.assertNotIn("Plain-Language Explanation", text)

    def test_pdf_labels_ai_explanation_correctly(self):
        case_id = _stored_case_id(self.db_path, explanation_source="ai")
        out = os.path.join(self.tmpdir, "case.pdf")
        self._invoke("show", case_id, "--db", self.db_path, "--pdf", "--output", out)
        text = _extract_text(out)
        self.assertIn("Plain-Language Explanation", text)

    def test_pdf_keeps_provider_skips_distinct_from_failures(self):
        case_id = _stored_case_id(self.db_path)
        out = os.path.join(self.tmpdir, "case.pdf")
        self._invoke("show", case_id, "--db", self.db_path, "--pdf", "--output", out)
        text = " ".join(_extract_text(out).split())
        self.assertIn("virustotal skipped for mail.example.net: below value threshold", text)
        self.assertIn("whois unavailable for netflix-login.example: timeout-marker-aa11", text)
        # the two must be shown under their own headings, not merged into one
        self.assertIn("Provider requests skipped", text)
        self.assertIn("Provider requests unavailable", text)

    def test_pdf_historical_match_semantics_are_not_generic(self):
        case_id = _stored_case_id(self.db_path)
        out = os.path.join(self.tmpdir, "case.pdf")
        self._invoke("show", case_id, "--db", self.db_path, "--pdf", "--output", out)
        text = " ".join(_extract_text(out).split())
        self.assertIn("exact artifact seen before", text)
        self.assertIn("structurally similar new artifact", text)
        # the old, ambiguous "Historical similarity: N%" phrasing this replaced
        # (see historical_match_label's docstring) must never reappear
        self.assertNotIn("Historical similarity:", text)

    def test_pdf_export_makes_zero_provider_events(self):
        """End-to-end proof the CRITICAL REPLAY RULE holds: exporting a PDF must
        not add a single row to the provider budget ledger, the same ledger a
        live investigation writes to on every real request."""
        import sqlite3

        case_id = _stored_case_id(self.db_path)

        def count_events() -> int:
            conn = sqlite3.connect(self.db_path)
            try:
                return conn.execute("SELECT COUNT(*) FROM provider_events").fetchone()[0]
            finally:
                conn.close()

        before = count_events()
        out = os.path.join(self.tmpdir, "case.pdf")
        self._invoke("show", case_id, "--db", self.db_path, "--pdf", "--output", out)
        self.assertEqual(before, count_events())

    def test_pdf_unknown_case_fails_clearly(self):
        result = self._invoke("show", "case_does_not_exist", "--db", self.db_path, "--pdf")
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("No such case", result.output)


if __name__ == "__main__":
    unittest.main()
