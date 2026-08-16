"""
KRISIS CLI.

    krisis investigate xyz.com
    krisis investigate xyz.com --show-graph --show-evidence
    krisis investigate message.txt --file
    krisis investigate --hash <sha256>
    krisis cases
    krisis show <case_id> --verbose
    krisis outcome <case_id> confirmed_malicious

The CLI is intentionally thin: it wires config -> Investigator, runs one
investigation, and renders the Case. All actual intelligence lives in
krisis.core / krisis.collectors / krisis.memory (see CLI IS THE PRODUCT FOR NOW
in the design doc).
"""

from __future__ import annotations

import json
import os
import sys

import click

from . import credentials
from .config import build_planner, default_collectors
from .core.graph import EntityGraph
from .core.investigator import Investigator
from .core.models import Outcome, RiskCategory
from .core.recommend import INDECISIVE
from .core.risk import historical_match_label
from .memory.case_memory import CaseMemory
from .memory.pattern_memory import PatternMemory
from .memory.storage import DEFAULT_DB_PATH, Storage
from .core.pivot_engine import InvestigationBudget

_BANNER = r"""  ██╗  ██╗██████╗ ██╗███████╗██╗███████╗
  ██║ ██╔╝██╔══██╗██║██╔════╝██║██╔════╝
  █████╔╝ ██████╔╝██║███████╗██║███████╗
  ██╔═██╗ ██╔══██╗██║╚════██║██║╚════██║
  ██║  ██╗██║  ██║██║███████║██║███████║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝╚══════╝"""

# xterm-256 deep-blue -> bright-cyan ramp, mirrored in setup.sh.
_RAMP = (27, 33, 39, 45, 51, 87)


def _gradient(art: str) -> str:
    """Paint art with a diagonal ramp — darkest top-left, brightest bottom-right."""
    lines = art.splitlines()
    span = max(map(len, lines)) + len(lines)
    return "\n".join(
        "".join(
            click.style(ch, fg=_RAMP[(row + col) * len(_RAMP) // span], bold=True)
            for col, ch in enumerate(line)
        )
        for row, line in enumerate(lines)
    )


def _print_banner(err: bool = True) -> None:
    """Startup banner. Defaults to stderr so `--json` stdout stays pipeable;
    help screens pass err=False since they have no machine output to protect."""
    click.echo("\n" + _gradient(_BANNER), err=err)
    click.secho(
        "   🔎 Knowledge-Driven Risk Intelligence  ·  Evidence · Correlation · Risk · Memory",
        dim=True, err=err,
    )
    click.echo(err=err)
    click.echo(
        click.style("  ─────────────◇  ", fg=39)
        + click.style("A N U B H A V   M O H A N D A S", fg=51, bold=True)
        + click.style("  ◇─────────────", fg=39),
        err=err,
    )
    click.echo(err=err)


_CATEGORY_COLOR = {
    RiskCategory.LOW: "green",
    RiskCategory.MEDIUM: "yellow",
    RiskCategory.HIGH: "red",
    RiskCategory.CRITICAL: "bright_red",
    RiskCategory.INSUFFICIENT_EVIDENCE: "bright_magenta",
    RiskCategory.CONFLICTING_EVIDENCE: "bright_yellow",
    RiskCategory.UNKNOWN: "white",
}


# -- colorized help ---------------------------------------------------------
#
# click's HelpFormatter measures column widths via term_len(), which strips
# ANSI escapes before counting — so styled text lines up exactly like plain
# text would. That means every heading/flag/command name below can carry
# color for free, with no custom table layout needed.

def _section(title: str) -> None:
    """Colored header for an output block, replacing the old plain '--- X ---'."""
    click.echo()
    click.secho(title, fg="bright_cyan", bold=True)
    click.secho("─" * len(title), fg="bright_black")


def _echo_wrapped(text: str, prefix: str, *, fg: str | None = None, width: int = 70) -> None:
    """Word-wrap free-form text under a label, continuation lines hang-indented to
    align under it — the pattern _render_provider_usage already used for skip
    reasons, reused everywhere else a long line (evidence note, explanation,
    historical match) would otherwise spill raw past the terminal edge."""
    if not text:
        return
    pad = " " * len(prefix)
    for i, line in enumerate(click.wrap_text(text, width=width).splitlines()):
        click.secho(f"{prefix if i == 0 else pad}{line}", fg=fg)


def _truncate(text: str, width: int) -> str:
    """Ellipsize instead of letting a long field (e.g. a phishing message used
    as the seed) blow past its column and wreck every row's alignment."""
    return text if len(text) <= width else text[: width - 1] + "…"


class _ColorFormatter(click.HelpFormatter):
    def write_usage(self, prog: str, args: str = "", prefix: str | None = None) -> None:
        super().write_usage(prog, args, prefix=click.style("Usage", fg="cyan", bold=True) + ": ")

    def write_heading(self, heading: str) -> None:
        self.write(f"{'':>{self.current_indent}}{click.style(heading + ':', fg='cyan', bold=True)}\n")


class _KrisisContext(click.Context):
    formatter_class = _ColorFormatter


class _KrisisCommand(click.Command):
    """Colorizes flag names in the Options table; every subcommand uses this."""

    context_class = _KrisisContext

    def format_options(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        opts = []
        for param in self.get_params(ctx):
            rv = param.get_help_record(ctx)
            if rv is not None:
                name, help_text = rv
                opts.append((click.style(name, fg="green"), help_text))
        if opts:
            with formatter.section("Options"):
                formatter.write_dl(opts)


class _KrisisGroup(_KrisisCommand, click.Group):
    """Top-level `krisis` group: banner + colorized, untruncated command list."""

    def format_options(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        _KrisisCommand.format_options(self, ctx, formatter)
        self.format_commands(ctx, formatter)

    def format_commands(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        commands = []
        for name in self.list_commands(ctx):
            cmd = self.get_command(ctx, name)
            if cmd is None or cmd.hidden:
                continue
            commands.append((name, cmd))
        if not commands:
            return
        # limit=300 disables get_short_help_str's "..." truncation for any
        # one-line docstring realistic here — the full description shows,
        # wrapped by write_dl instead of cut short.
        rows = [
            (click.style(name, fg="cyan", bold=True), cmd.get_short_help_str(limit=300))
            for name, cmd in commands
        ]
        with formatter.section("Commands"):
            formatter.write_dl(rows)

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        _print_banner(err=False)
        super().format_help(ctx, formatter)


_EXAMPLES_EPILOG = click.style("Examples:", fg="cyan", bold=True) + "\n\n\b\n" + "\n".join(
    click.style("  " + line, fg="bright_black")
    for line in (
        "krisis investigate xyz.com",
        "krisis investigate xyz.com --show-graph --show-evidence",
        "krisis investigate message.txt --file",
        "krisis investigate --hash <sha256>",
        "krisis cases",
        "krisis show <case_id> --verbose",
        "krisis outcome <case_id> confirmed_malicious",
        "krisis setup",
    )
) + "\n\n" + click.style(
    "Each command has its own flags (e.g. --explain, --show-graph, --json) — "
    "run `krisis COMMAND --help` to see them.", fg="bright_black"
)


# -- credential onboarding -----------------------------------------------------

def _prompt_for_key(spec: credentials.ProviderKey) -> bool:
    """Walk the user through obtaining one provider key. Returns True if a key was
    saved. Skipping is a first-class outcome: it is recorded so KRISIS can report
    the source as deliberately skipped rather than silently absent."""
    click.echo()
    click.secho("  " + "─" * 66, fg="bright_black")
    click.secho(f"  {spec.label} API key not configured", fg="yellow", bold=True)
    click.secho("  " + "─" * 66, fg="bright_black")
    click.echo()
    click.secho("  What KRISIS uses it for", bold=True)
    for line in click.wrap_text(spec.purpose, width=64).splitlines():
        click.echo(f"    {line}")
    click.echo()
    click.secho("  If you skip it", bold=True)
    for line in click.wrap_text(spec.impact_if_missing, width=64).splitlines():
        click.echo(f"    {line}")
    click.echo()
    click.secho("  How to get one", bold=True)
    for i, step in enumerate(spec.steps, 1):
        click.echo(f"    {i}. {step}")
    if spec.free_tier:
        click.echo()
        click.secho(f"    {spec.free_tier}", fg="bright_black")
    click.echo()

    value = click.prompt(
        click.style("  Paste key (input hidden), or press Enter to skip", fg="cyan"),
        default="",
        show_default=False,
        hide_input=True,
    ).strip()

    if not value:
        path = credentials.save(spec.env_var, "")
        click.secho(f"  ○ Skipped. Recorded in {path} — KRISIS will not ask again.", fg="yellow")
        click.secho(f"    Add it later with:  krisis setup --provider {spec.provider}", fg="bright_black")
        return False

    click.echo(f"  Checking key {credentials.mask(value)} ...")
    ok, message = credentials.verify(spec, value)
    if not ok:
        click.secho(f"  ✗ {message}", fg="red")
        if not click.confirm(click.style("  Save it anyway?", fg="yellow"), default=False):
            click.secho("  ○ Not saved.", fg="yellow")
            return False
    else:
        click.secho(f"  ✓ {message}", fg="green")

    path = credentials.save(spec.env_var, value)
    click.secho(f"  ✓ Saved to {path} (permissions 0600)", fg="green")
    return True


def _ensure_credentials(interactive: bool) -> None:
    """Ask once about any key we have neither a value nor a recorded decision for.

    Never prompts when stdin is not a terminal, so piped/scripted runs cannot hang.
    """
    pending = [spec for spec in credentials.PROVIDER_KEYS if credentials.needs_prompt(spec.env_var)]
    if not pending:
        return
    if not interactive or not sys.stdin.isatty():
        for spec in pending:
            # stderr: this is a note to the operator, and --json runs are piped into
            # a parser that must receive nothing but the case.
            click.secho(
                f"[!] {spec.label} key not configured — that evidence source will be skipped. "
                f"Run `krisis setup` to add it.",
                fg="yellow",
                err=True,
            )
        return

    click.secho("[*] First-time setup: KRISIS can use optional evidence sources.", fg="cyan")
    click.secho("    Each one is optional — skip any of them and the investigation still runs.",
                fg="bright_black")
    for spec in pending:
        _prompt_for_key(spec)


def _status_for(spec: credentials.ProviderKey) -> str:
    if credentials.resolve(spec.env_var):
        return click.style("configured", fg="green")
    if credentials.was_declined(spec.env_var):
        return click.style("SKIPPED — no API key configured (you chose to skip)", fg="yellow")
    return click.style("SKIPPED — no API key found", fg="yellow")


def _render_source_status() -> None:
    """Report every optional provider's state, so a skipped source is visible in the
    output rather than quietly missing from it."""
    sources = [s for s in credentials.PROVIDER_KEYS if s.is_evidence_source]
    others = [s for s in credentials.PROVIDER_KEYS if not s.is_evidence_source]

    _section("Optional evidence sources")
    for spec in sources:
        click.echo(f"  {spec.label:<34} {_status_for(spec)}")
    if others:
        _section("Optional components (not evidence sources)")
        for spec in others:
            click.echo(f"  {spec.label:<34} {_status_for(spec)}")


def _build_investigator(db_path: str, max_depth: int, max_entities: int, max_external_calls: int) -> Investigator:
    storage = Storage(db_path)
    pattern_memory = PatternMemory(storage)
    case_memory = CaseMemory(storage, pattern_memory)
    budget = InvestigationBudget(
        max_depth=max_depth, max_entities=max_entities, max_external_calls=max_external_calls
    )
    # The planner shares the case database: provider caching and rate accounting have
    # to survive process exit, or every CLI invocation starts its quota from zero and
    # rediscovers the provider's limit the hard way.
    planner = build_planner(storage)
    return Investigator(
        collectors=default_collectors(planner=planner, storage=storage),
        case_memory=case_memory,
        pattern_memory=pattern_memory,
        budget=budget,
        planner=planner,
    )


@click.group(cls=_KrisisGroup, invoke_without_command=True, epilog=_EXAMPLES_EPILOG)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """KRISIS — Knowledge-driven Risk Intelligence & Security Investigation System."""
    if ctx.invoked_subcommand is None:
        # Bare `krisis`: show the same colorized help --help gives, on stdout
        # with a clean exit — not click's default stderr "Missing command" error.
        click.echo(ctx.get_help())
        ctx.exit()
    _print_banner()


@cli.command(cls=_KrisisCommand)
@click.argument("target")
@click.option("--file", "is_file", is_flag=True, help="Treat TARGET as a path to a message/text file to investigate.")
@click.option("--hash", "is_hash", is_flag=True, help="Treat TARGET as a file hash (sha256/sha1/md5).")
@click.option("--show-graph", is_flag=True, help="Print the investigation graph as ASCII.")
@click.option("--show-evidence", is_flag=True, help="Print all collected evidence.")
@click.option("--show-pivots", is_flag=True, help="Print every pivot considered, accepted or rejected.")
@click.option("--show-patterns", is_flag=True, help="Print historical pattern matches.")
@click.option("--show-trace", is_flag=True, help="Print the full step-by-step investigation trace.")
@click.option("--explain", "explain_only", is_flag=True, help="Print only the plain-language explanation.")
@click.option("--json", "as_json", is_flag=True, help="Output the full case as JSON instead of formatted text.")
@click.option("--verbose", is_flag=True, help="Show everything (graph, evidence, pivots, patterns, trace).")
@click.option("--max-depth", default=2, show_default=True)
@click.option("--max-entities", default=40, show_default=True)
@click.option("--max-external-calls", default=60, show_default=True)
@click.option("--db", "db_path", default=DEFAULT_DB_PATH, show_default=True, help="Path to the case/pattern SQLite store.")
@click.option("--no-prompt", is_flag=True, help="Never ask for missing API keys; skip those sources.")
def investigate(
    target, is_file, is_hash, show_graph, show_evidence, show_pivots, show_patterns,
    show_trace, explain_only, as_json, verbose, max_depth, max_entities, max_external_calls, db_path,
    no_prompt,
):
    """Investigate TARGET — a URL, domain, IP, file hash, or a message to mine for indicators."""
    if is_file:
        if not os.path.exists(target):
            click.secho(f"[-] File not found: {target}", fg="red")
            sys.exit(1)
        with open(target, "r", errors="ignore") as f:
            raw_input = f.read()
    elif is_hash:
        raw_input = target.strip()
    else:
        raw_input = target

    # Ask about missing keys before collecting, so a key added now is used by this
    # very run. --json output stays machine-clean because prompts go to the terminal.
    _ensure_credentials(interactive=not (no_prompt or as_json))

    investigator = _build_investigator(db_path, max_depth, max_entities, max_external_calls)

    click.secho(f"[*] Investigating: {target}", fg="cyan", err=True)
    case, trace = investigator.investigate(raw_input)
    graph = investigator.last_graph

    if as_json:
        click.echo(json.dumps(case.to_dict(), indent=2, default=str))
        return

    if explain_only:
        click.echo(case.explanation)
        return

    if verbose:
        show_graph = show_evidence = show_pivots = show_patterns = show_trace = True

    case_dict = case.to_dict()
    _render_case(case_dict)

    if show_evidence:
        _render_evidence(case_dict)
    if show_pivots:
        _render_pivots(case_dict)
    if show_patterns:
        _render_patterns(case.pattern_matches)
    if show_graph and graph is not None:
        _render_graph(graph)
    if show_trace:
        _render_trace(trace)

    _render_provider_usage(case.provider_usage)
    _render_source_status()
    _render_provider_failures(case.provider_failures, case.provider_skips)

    click.secho(f"\n[+] Case stored: {case.id}", fg="cyan")


@cli.command(cls=_KrisisCommand)
@click.option("--provider", help="Configure only this provider (e.g. virustotal, anthropic).")
@click.option("--reset", is_flag=True, help="Re-ask about keys you previously skipped.")
@click.option("--show", is_flag=True, help="Show which keys are configured, without changing anything.")
def setup(provider, reset, show):
    """Configure optional provider API keys. Every key is optional and skippable."""
    if provider and provider not in credentials.PROVIDER_KEYS_BY_NAME:
        click.secho(
            f"[-] Unknown provider '{provider}'. Known: "
            f"{', '.join(credentials.PROVIDER_KEYS_BY_NAME)}",
            fg="red",
        )
        sys.exit(1)

    specs = (
        [credentials.PROVIDER_KEYS_BY_NAME[provider]] if provider else list(credentials.PROVIDER_KEYS)
    )

    if show:
        _render_source_status()
        click.secho(f"\n  Key store: {credentials.keys_file()}", fg="bright_black")
        return

    for spec in specs:
        current = credentials.resolve(spec.env_var)
        if current and not reset:
            click.secho(
                f"\n  {spec.label}: already configured ({credentials.mask(current)})", fg="green"
            )
            if not click.confirm(click.style("  Replace it?", fg="cyan"), default=False):
                continue
        elif credentials.was_declined(spec.env_var) and not reset and not provider:
            click.secho(
                f"\n  {spec.label}: previously skipped. "
                f"Use `krisis setup --provider {spec.provider}` to add it.",
                fg="yellow",
            )
            continue
        _prompt_for_key(spec)

    click.echo()
    _render_source_status()


@cli.command(cls=_KrisisCommand)
@click.option("--db", "db_path", default=DEFAULT_DB_PATH, show_default=True)
@click.option("--limit", default=20, show_default=True)
def cases(db_path, limit):
    """List stored investigations."""
    storage = Storage(db_path)
    rows = storage.list_cases(limit=limit)
    if not rows:
        click.echo("No cases stored yet.")
        return
    click.secho(
        f"  {'ID':<18} {'CREATED':<20} {'SEED':<32} {'RISK':<16} OUTCOME",
        fg="bright_black", bold=True,
    )
    for row in rows:
        color = _CATEGORY_COLOR.get(RiskCategory(row["risk_category"]), "white") if row["risk_category"] else "white"
        risk_text = f"{row['risk_category'] or 'N/A'} ({row['risk_score']})"
        click.echo(
            f"  {row['id']:<18} {row['created_at'][:19]:<20} {_truncate(row['seed'], 32):<32} "
            + click.style(f"{risk_text:<16}", fg=color)
            + f" {row['outcome'] or '-'}"
        )


@cli.command(cls=_KrisisCommand)
@click.argument("case_id")
@click.option("--show-graph", is_flag=True, help="Print the investigation graph as ASCII.")
@click.option("--show-evidence", is_flag=True, help="Print all collected evidence.")
@click.option("--show-pivots", is_flag=True, help="Print every pivot considered, accepted or rejected.")
@click.option("--show-patterns", is_flag=True, help="Print historical pattern matches.")
@click.option("--explain", "explain_only", is_flag=True, help="Print only the plain-language explanation.")
@click.option("--verbose", is_flag=True, help="Show everything (graph, evidence, pivots, patterns).")
@click.option("--db", "db_path", default=DEFAULT_DB_PATH, show_default=True)
@click.option("--json", "as_json", is_flag=True, help="Print the full stored case as JSON.")
def show(case_id, show_graph, show_evidence, show_pivots, show_patterns, explain_only, verbose, db_path, as_json):
    """Show a previously stored investigation (see `krisis cases` for ids).

    `krisis cases` only ever printed one summary line per case — there was no way
    to look back at what an old investigation actually found. This replays it from
    what was stored: risk, evidence, provider usage, graph, and the explanation.
    It never re-runs collection — everything shown comes from the stored case.
    """
    data = Storage(db_path).get_case(case_id)
    if not data:
        click.secho(f"[-] No such case: {case_id}", fg="red")
        sys.exit(1)
    if as_json:
        click.echo(json.dumps(data, indent=2, default=str))
        return
    if explain_only:
        click.echo(data.get("explanation", ""))
        return

    if verbose:
        show_graph = show_evidence = show_pivots = show_patterns = True

    _render_case(data)
    if show_evidence:
        _render_evidence(data)
    if show_pivots:
        _render_pivots(data)
    if show_patterns:
        _render_patterns(data.get("pattern_matches") or [])
    if show_graph:
        graph = EntityGraph.from_dict(data)
        if graph.entity_count():
            _render_graph(graph)

    _render_provider_usage(data.get("provider_usage") or {})
    _render_provider_failures(data.get("provider_failures") or [], data.get("provider_skips") or [])

    click.secho(f"\n[case: {data['id']}, seed: {data['seed']}]", fg="bright_black")


@cli.command(cls=_KrisisCommand)
@click.argument("case_id")
@click.argument("outcome", type=click.Choice([o.value for o in Outcome]))
@click.option("--db", "db_path", default=DEFAULT_DB_PATH, show_default=True)
def outcome(case_id, outcome, db_path):
    """Record the real-world outcome of a case, closing the learning loop."""
    storage = Storage(db_path)
    pattern_memory = PatternMemory(storage)
    case_memory = CaseMemory(storage, pattern_memory)
    if not case_memory.get(case_id):
        click.secho(f"[-] No such case: {case_id}", fg="red")
        sys.exit(1)
    case_memory.set_outcome(case_id, outcome)
    click.secho(f"[+] Case {case_id} marked as {outcome}. Future investigations sharing its indicators will reflect this.", fg="green")


# -- rendering -----------------------------------------------------------------
#
# All rendering below reads a Case in its to_dict() shape (plain dicts/strings,
# enums as .value). `investigate` builds that shape from the case it just produced
# and `show` reads it back from storage — one renderer, so the two commands cannot
# drift apart the way _render_case/_render_stored_case once did.

def _render_case(data: dict) -> None:
    risk = data.get("risk") or {}
    if not risk:
        click.secho("[-] No risk assessment available for this case.", fg="red")
        return

    color = _CATEGORY_COLOR.get(RiskCategory(risk["category"]), "white")
    click.echo()
    click.secho(f"Risk: {risk['category']}", fg=color, bold=True, nl=False)
    click.echo(f"   Score: {risk['score']}/100   Confidence: {risk['confidence']:.0%}")

    # An indecisive verdict has to explain itself, or a reader will round it down
    # to "probably fine" — which is the exact failure this state exists to prevent.
    uncertainty = risk.get("uncertainty") or {}
    if uncertainty.get("reason"):
        label = "Why this is not a verdict" if risk["category"] in (
            c.value for c in INDECISIVE
        ) else "Why this verdict was qualified"
        click.echo()
        _echo_wrapped(f"{uncertainty['reason']}.", f"{label}: ", fg=color)
    if uncertainty.get("unavailable_sources"):
        _echo_wrapped(
            ", ".join(uncertainty["unavailable_sources"])
            + "  (absence of data from these is not evidence of safety)",
            "Not checked: ", fg="yellow",
        )

    if risk.get("top_contributors"):
        click.echo()
        click.secho("Primary contributors:", fg="bright_cyan", bold=True)
        for c in risk["top_contributors"]:
            _echo_wrapped(c, "  - ", fg=color)

    entities_by_id = {e["id"]: e for e in data.get("entities", [])}
    contradicting = [ev for ev in data.get("evidence", []) if ev.get("polarity") == "contradicts_threat"]
    if contradicting:
        click.echo()
        click.secho("Counter-evidence:", fg="bright_cyan", bold=True)
        for c in contradicting[:5]:
            entity = entities_by_id.get(c.get("entity_id"))
            # Name the entity: several extracted indicators often produce the same
            # signal, and identical unattributed lines read as duplicated evidence.
            subject = f" [{entity['value']}]" if entity else ""
            _echo_wrapped(f"{c['signal']}{subject}: {c['value']}", "  - ", fg="green")
        # Some of the above is listed for completeness but was excluded from the
        # score arithmetic (see risk._discount_narrow_contradictions) — without this,
        # it reads as evidence that offsets the finding above it, when it does not.
        for note in uncertainty.get("discounted_counter_evidence") or []:
            _echo_wrapped(note, "    note: ", fg="bright_black")

    if risk.get("historical_similarity"):
        hs = risk["historical_similarity"]
        # Never print a bare "historical similarity: N%" — that phrasing lets a
        # reader assume "I have seen this exact artifact before" when the match
        # may really be "this merely resembles a prior shape" or "this shares
        # infrastructure with something else". historical_match_label spells out
        # which one KRISIS actually means (see EXACT ARTIFACT VS INFRASTRUCTURE
        # OVERLAP in pattern_memory.py).
        click.echo()
        click.secho(f"Historical match: {historical_match_label(hs)} — {hs['similarity']:.0%}", fg="magenta", bold=True)
        _echo_wrapped(
            f"prior case: {hs['pattern_name']} (prior outcome: {hs.get('prior_outcome') or 'unknown'})",
            "  ", fg="bright_black",
        )

    click.echo()
    _echo_wrapped(data.get("explanation", ""), "", width=78)
    click.echo()
    click.secho("Recommended action:", fg="bright_cyan", bold=True)
    _echo_wrapped(data.get("recommendation", ""), "  ", fg=color, width=76)


def _render_evidence(data: dict) -> None:
    entities_by_id = {e["id"]: e for e in data.get("entities", [])}
    _section("Evidence")
    for ev in data.get("evidence", []):
        entity = entities_by_id.get(ev["entity_id"])
        target = entity["value"] if entity else ev["entity_id"]
        click.echo(
            f"  [{ev['polarity']:<20}] {ev['source']:<12} {ev['signal']:<28} "
            f"{target:<30} = {ev['value']} (conf {ev['confidence']:.2f}, {ev['independence']})"
        )


def _render_pivots(data: dict) -> None:
    _section("Pivots")
    for p in data.get("pivots", []):
        marker = "+" if p["status"] == "accepted" else "-"
        click.echo(
            f"  [{marker}] {p['entity_type']:<12} {p['entity_value']:<30} "
            f"priority={p['priority']:.2f} status={p['status']}"
            + (f" ({p['rejection_reason']})" if p.get("rejection_reason") else f" ({p['reason']})")
        )


def _render_patterns(pattern_matches: list) -> None:
    _section("Historical Pattern Matches")
    if not pattern_matches:
        click.echo("  none")
        return
    for m in pattern_matches:
        click.echo(
            f"  {historical_match_label(m)} — overall {m['similarity']:.0%}  "
            f"(indicator {m.get('indicator_similarity', 0):.0%} / "
            f"structural {m.get('structural_similarity', 0):.0%})  {m['pattern_name']}"
        )
        click.echo(
            f"      prior_outcome={m.get('prior_outcome') or 'unknown'}"
            + (f"  pattern_stage={m['pattern_stage']}" if m.get("pattern_stage") else "")
        )
        if m.get("matched_indicators"):
            click.echo(f"      shared indicators: {', '.join(m['matched_indicators'])}")
        if m.get("matched_facets"):
            click.echo(f"      shared structure:  {', '.join(m['matched_facets'])}")


def _render_provider_usage(usage_by_provider: dict) -> None:
    """What each provider cost this investigation, and what KRISIS chose not to spend.

    Shown by default rather than behind a flag: the live runs that motivated the
    planner burned a provider's quota without anything in the output saying so.
    """
    if not usage_by_provider:
        return
    _section("Provider Usage")
    for name, usage in usage_by_provider.items():
        parts = [f"calls {usage['calls']}"]
        for label, key in (("cached", "cached"), ("reused", "deduplicated"),
                           ("skipped", "skipped"), ("rate limited", "rate_limited")):
            if usage.get(key):
                parts.append(f"{label} {usage[key]}")
        click.echo(f"  {name:<14} " + "  ".join(parts))
        for reason in usage.get("skip_reasons", []):
            _echo_wrapped(reason, "      not spent: ", fg="bright_black")


def _render_provider_failures(failures: list, skips: list) -> None:
    """Genuine provider failures and deliberate planner skips, kept visibly separate.

    A skip is a budget/value-gate decision working as intended; a failure is a
    provider that ran and could not answer. Merging them under one "unavailable"
    label makes a scarce-provider policy read as nine broken evidence sources.
    """
    if failures:
        click.secho(f"\n[!] {len(failures)} evidence source(s) unavailable:", fg="yellow")
        for note in failures:
            _echo_wrapped(note, "    - ", fg="yellow")
    if skips:
        click.secho(f"\n[i] {len(skips)} provider request(s) deliberately skipped:", fg="bright_black")
        for note in skips:
            _echo_wrapped(note, "    - ", fg="bright_black")


def _render_graph(graph) -> None:
    _section("Investigation Graph")
    click.echo(graph.to_ascii())


def _render_trace(trace) -> None:
    _section("Investigation Trace")
    for i, step in enumerate(trace.steps, 1):
        stage = step.pop("stage")
        click.echo(f"  {i:>3}. {stage:<22} {step}")


def main():
    cli()


if __name__ == "__main__":
    main()
