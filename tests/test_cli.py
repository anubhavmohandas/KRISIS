"""
CLI tests.

Before `show`, a stored case was reachable only as one summary line from
`krisis cases` — the risk, evidence, and explanation an investigation actually
produced were gone the moment the process exited (see CASE STORAGE / "every
investigation should become a replayable case" in the design doc). These tests
hold that a stored case can actually be read back, in both the human and the
machine-readable form, and that the CLI never touches the network to do it —
`show` reads storage only.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

from click.testing import CliRunner

from krisis.cli import cli
from krisis.core.models import Case, Coverage, Entity, EntityType, Evidence, Independence, Polarity
from krisis.core.risk import RiskEngine
from krisis.core.correlation import CorrelationResult
from krisis.memory.case_memory import CaseMemory
from krisis.memory.pattern_memory import PatternMemory
from krisis.memory.storage import Storage


def _stored_case_id(db_path: str) -> str:
    """A real case, saved the same way Investigator.investigate() does — no
    network involved, so this exercises exactly what `show` has to render."""
    storage = Storage(db_path)
    pattern_memory = PatternMemory(storage)
    case_memory = CaseMemory(storage, pattern_memory)

    case = Case(seed="netflix-login.example", seed_type=EntityType.DOMAIN)
    identity_ev = Evidence(
        source="identity", entity_id="e1", signal="lookalike_domain", value="netflix.example",
        evidence_type="identity", polarity=Polarity.SUPPORTS_THREAT, confidence=0.8,
        independence=Independence.INDEPENDENT,
    )
    tls_ev = Evidence(
        source="tls", entity_id="e1", signal="valid_tls_present", value="Some CA",
        evidence_type="infrastructure", polarity=Polarity.CONTRADICTS_THREAT, confidence=0.25,
        independence=Independence.INDEPENDENT,
    )
    entity = Entity(value="netflix-login.example", type=EntityType.DOMAIN, id="e1", depth=0)
    case.entities[entity.id] = entity
    case.evidence[identity_ev.id] = identity_ev
    case.evidence[tls_ev.id] = tls_ev

    correlation = CorrelationResult(
        supporting=[identity_ev], contradicting=[tls_ev], evidence_diversity=0.5
    )
    coverage = Coverage(attempted={"identity", "tls"}, available={"identity", "tls"},
                        evidence_types={"identity", "infrastructure"})
    case.risk = RiskEngine().score(correlation, coverage=coverage)
    case.explanation = "test explanation"
    case.recommendation = "test recommendation"
    case.provider_usage = {"identity": {"calls": 1}, "tls": {"calls": 1}}

    case_memory.save(case)
    return case.id


class TestShowCommand(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.runner = CliRunner()

    def _invoke(self, *args):
        # `investigate` prompts for missing keys unless stdin isn't a tty; CliRunner's
        # stdin isn't one, so this is only exercised by commands that don't prompt.
        with mock.patch("requests.get", side_effect=AssertionError("show must not touch the network")):
            return self.runner.invoke(cli, list(args), catch_exceptions=False)

    def test_show_renders_a_stored_case(self):
        case_id = _stored_case_id(self.db_path)
        result = self._invoke("show", case_id, "--db", self.db_path)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("MEDIUM", result.output)
        self.assertIn("lookalike_domain", result.output)
        self.assertIn("test explanation", result.output)
        self.assertIn("test recommendation", result.output)
        # The discounted-counter-evidence note must survive a round trip through
        # storage exactly like it does for a just-completed investigation.
        self.assertIn("does not offset the identity finding", result.output)

    def test_show_json_round_trips_the_stored_case(self):
        case_id = _stored_case_id(self.db_path)
        result = self._invoke("show", case_id, "--db", self.db_path, "--json")
        self.assertEqual(result.exit_code, 0)
        # The startup banner goes to stderr specifically so --json stdout stays
        # pipeable (see cli._print_banner) — assert that promise, not just parse.
        data = json.loads(result.stdout)
        self.assertEqual(data["id"], case_id)
        self.assertEqual(data["risk"]["category"], "MEDIUM")

    def test_show_unknown_case_fails_clearly(self):
        result = self._invoke("show", "case_does_not_exist", "--db", self.db_path)
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("No such case", result.output)


if __name__ == "__main__":
    unittest.main()
