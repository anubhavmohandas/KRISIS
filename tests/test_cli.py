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

import click
from click.testing import CliRunner

from krisis.cli import cli
from krisis.core.models import (
    Case, Coverage, Entity, EntityType, Evidence, Independence, Pivot, Polarity, Relationship,
)
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
    pivot_target = Entity(value="203.0.113.9", type=EntityType.IP, id="e2", depth=1)
    case.entities[entity.id] = entity
    case.entities[pivot_target.id] = pivot_target
    case.evidence[identity_ev.id] = identity_ev
    case.evidence[tls_ev.id] = tls_ev
    rel = Relationship(
        source_entity_id="e1", target_entity_id="e2",
        relation_type="resolves_to", reason="domain resolves to this IP", id="r1",
    )
    case.relationships[rel.id] = rel
    case.pivots.append(Pivot(
        entity_value="203.0.113.9", entity_type=EntityType.IP, reason="domain resolves to this IP",
        priority=0.6, source_entity_id="e1", status="accepted",
    ))

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
        # storage exactly like it does for a just-completed investigation. Line-wrapped
        # output can hard-wrap inside the phrase, so compare with whitespace collapsed.
        self.assertIn("does not offset the identity finding", " ".join(result.output.split()))

    def test_show_json_round_trips_the_stored_case(self):
        case_id = _stored_case_id(self.db_path)
        result = self._invoke("show", case_id, "--db", self.db_path, "--json")
        self.assertEqual(result.exit_code, 0)
        # The startup banner goes to stderr specifically so --json stdout stays
        # pipeable (see cli._print_banner) — assert that promise, not just parse.
        data = json.loads(result.stdout)
        self.assertEqual(data["id"], case_id)
        self.assertEqual(data["risk"]["category"], "MEDIUM")

    def test_show_graph_replays_entities_and_relationships(self):
        # investigate --show-graph prints the graph live; show --show-graph must
        # reproduce it from storage — same command surface, same information.
        case_id = _stored_case_id(self.db_path)
        result = self._invoke("show", case_id, "--db", self.db_path, "--show-graph")
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Investigation Graph", result.output)
        self.assertIn("netflix-login.example", result.output)
        self.assertIn("203.0.113.9", result.output)
        self.assertIn("resolves_to", result.output)

    def test_show_evidence_lists_every_evidence_item(self):
        case_id = _stored_case_id(self.db_path)
        result = self._invoke("show", case_id, "--db", self.db_path, "--show-evidence")
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Evidence", result.output)
        self.assertIn("lookalike_domain", result.output)
        self.assertIn("valid_tls_present", result.output)

    def test_show_pivots_lists_every_pivot(self):
        case_id = _stored_case_id(self.db_path)
        result = self._invoke("show", case_id, "--db", self.db_path, "--show-pivots")
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Pivots", result.output)
        self.assertIn("203.0.113.9", result.output)
        self.assertIn("accepted", result.output)

    def test_show_patterns_reports_none_when_no_match(self):
        case_id = _stored_case_id(self.db_path)
        result = self._invoke("show", case_id, "--db", self.db_path, "--show-patterns")
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Historical Pattern Matches", result.output)
        self.assertIn("none", result.output)

    def test_show_verbose_includes_every_section(self):
        case_id = _stored_case_id(self.db_path)
        result = self._invoke("show", case_id, "--db", self.db_path, "--verbose")
        self.assertEqual(result.exit_code, 0)
        for heading in ("Investigation Graph", "Evidence", "Pivots", "Historical Pattern Matches"):
            self.assertIn(heading, result.output)

    def test_show_unknown_case_fails_clearly(self):
        result = self._invoke("show", "case_does_not_exist", "--db", self.db_path)
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("No such case", result.output)

    def test_show_distinguishes_skipped_from_unavailable_providers(self):
        """A deliberately skipped provider request must never render under
        'evidence source(s) unavailable' — that heading is for providers that
        actually ran and failed. investigate and show share one renderer
        (_render_provider_failures), so this covers both surfaces."""
        case_id = _stored_case_id(self.db_path)
        storage = Storage(self.db_path)
        data = storage.get_case(case_id)
        data["provider_failures"] = ["tls unavailable for netflix-login.example: timeout"]
        data["provider_skips"] = ["virustotal skipped for netflix-login.example: daily budget exhausted"]
        storage.save_case(data)

        result = self._invoke("show", case_id, "--db", self.db_path)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("1 evidence source(s) unavailable", result.output)
        self.assertIn("tls unavailable for netflix-login.example: timeout", result.output)
        self.assertIn("1 provider request(s) deliberately skipped", result.output)
        self.assertIn("virustotal skipped for netflix-login.example: daily budget exhausted", result.output)

        # the skip must not be counted or listed under the failure heading
        unavailable_section = result.output.split("evidence source(s) unavailable")[1]
        unavailable_section = unavailable_section.split("provider request(s) deliberately skipped")[0]
        self.assertNotIn("virustotal", unavailable_section)

    def test_show_json_keeps_skips_and_failures_as_distinct_lists(self):
        case_id = _stored_case_id(self.db_path)
        storage = Storage(self.db_path)
        data = storage.get_case(case_id)
        data["provider_failures"] = ["tls unavailable for netflix-login.example: timeout"]
        data["provider_skips"] = ["virustotal skipped for netflix-login.example: daily budget exhausted"]
        storage.save_case(data)

        result = self._invoke("show", case_id, "--db", self.db_path, "--json")
        self.assertEqual(result.exit_code, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["provider_failures"], ["tls unavailable for netflix-login.example: timeout"])
        self.assertEqual(
            payload["provider_skips"],
            ["virustotal skipped for netflix-login.example: daily budget exhausted"],
        )


class TestTopLevelHelp(unittest.TestCase):
    """Before this, `krisis --help` listed commands but not their flags — finding
    e.g. --show-graph meant a second `krisis investigate --help` call. These pin
    that the top-level help surfaces investigate/show's important options directly."""

    def setUp(self):
        self.runner = CliRunner()

    def test_bare_command_and_help_flag_show_common_options(self):
        for args in ([], ["--help"]):
            result = self.runner.invoke(cli, args)
            self.assertEqual(result.exit_code, 0, args)
            self.assertIn("Common / Important Options", result.output)
            self.assertIn("INVESTIGATE", result.output)
            self.assertIn("SHOW", result.output)
            for flag in (
                "--file", "--hash", "--show-graph", "--show-evidence", "--show-pivots",
                "--show-patterns", "--show-trace", "--explain", "--json", "--verbose",
            ):
                self.assertIn(flag, result.output)
            self.assertIn("krisis investigate --help", result.output)
            self.assertIn("krisis show --help", result.output)

    def test_common_options_are_real_flags_of_their_command(self):
        """Guards against the summary drifting from reality if a flag is ever
        renamed or removed from `investigate`/`show`."""
        from krisis.cli import _COMMON_OPTIONS

        for cmd_name, flags in _COMMON_OPTIONS.items():
            command = cli.commands[cmd_name.lower()]
            actual = {p.opts[0] for p in command.params if isinstance(p, click.Option)}
            for flag in flags:
                self.assertIn(flag, actual, f"{flag} listed for {cmd_name} but not a real option")


if __name__ == "__main__":
    unittest.main()
