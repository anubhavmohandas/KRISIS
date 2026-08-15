"""
KRISIS CLI.

    krisis investigate xyz.com
    krisis investigate xyz.com --show-graph --show-evidence
    krisis investigate message.txt --file
    krisis investigate --hash <sha256>
    krisis cases
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
from .config import default_collectors
from .core.investigator import Investigator
from .core.models import RiskCategory
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


def _print_banner() -> None:
    """Startup banner, written to stderr so `--json` stdout stays pipeable."""
    click.echo("\n" + _gradient(_BANNER), err=True)
    click.secho(
        "   🔎 Knowledge-Driven Risk Intelligence  ·  Evidence · Correlation · Risk · Memory",
        dim=True, err=True,
    )
    click.echo(err=True)
    click.echo(
        click.style("  ─────────────◇  ", fg=39)
        + click.style("A N U B H A V   M O H A N D A S", fg=51, bold=True)
        + click.style("  ◇─────────────", fg=39),
        err=True,
    )
    click.echo(err=True)


_CATEGORY_COLOR = {
    RiskCategory.LOW: "green",
    RiskCategory.MEDIUM: "yellow",
    RiskCategory.HIGH: "red",
    RiskCategory.CRITICAL: "bright_red",
    RiskCategory.INSUFFICIENT_EVIDENCE: "bright_magenta",
    RiskCategory.CONFLICTING_EVIDENCE: "bright_yellow",
    RiskCategory.UNKNOWN: "white",
}


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
            click.secho(
                f"[!] {spec.label} key not configured — that evidence source will be skipped. "
                f"Run `krisis setup` to add it.",
                fg="yellow",
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

    click.echo("\n--- Optional evidence sources ---")
    for spec in sources:
        click.echo(f"  {spec.label:<34} {_status_for(spec)}")
    if others:
        click.echo("\n--- Optional components (not evidence sources) ---")
        for spec in others:
            click.echo(f"  {spec.label:<34} {_status_for(spec)}")


def _build_investigator(db_path: str, max_depth: int, max_entities: int, max_external_calls: int) -> Investigator:
    storage = Storage(db_path)
    pattern_memory = PatternMemory(storage)
    case_memory = CaseMemory(storage, pattern_memory)
    budget = InvestigationBudget(
        max_depth=max_depth, max_entities=max_entities, max_external_calls=max_external_calls
    )
    return Investigator(
        collectors=default_collectors(),
        case_memory=case_memory,
        pattern_memory=pattern_memory,
        budget=budget,
    )


@click.group()
def cli():
    """KRISIS — Knowledge-driven Risk Intelligence & Security Investigation System."""
    _print_banner()


@cli.command()
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

    _render_case(case)

    if show_evidence:
        _render_evidence(case)
    if show_pivots:
        _render_pivots(case)
    if show_patterns:
        _render_patterns(case)
    if show_graph and graph is not None:
        _render_graph(graph)
    if show_trace:
        _render_trace(trace)

    _render_source_status()

    if case.provider_failures:
        click.secho(f"\n[!] {len(case.provider_failures)} evidence source(s) unavailable:", fg="yellow")
        for note in case.provider_failures:
            click.echo(f"    - {note}")

    click.secho(f"\n[+] Case stored: {case.id}", fg="cyan")


@cli.command()
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


@cli.command()
@click.option("--db", "db_path", default=DEFAULT_DB_PATH, show_default=True)
@click.option("--limit", default=20, show_default=True)
def cases(db_path, limit):
    """List stored investigations."""
    storage = Storage(db_path)
    rows = storage.list_cases(limit=limit)
    if not rows:
        click.echo("No cases stored yet.")
        return
    for row in rows:
        color = _CATEGORY_COLOR.get(RiskCategory(row["risk_category"]), "white") if row["risk_category"] else "white"
        click.echo(
            f"{row['id']}  {row['created_at'][:19]}  {row['seed']:<30} "
            + click.style(f"{row['risk_category'] or 'N/A'} ({row['risk_score']})", fg=color)
            + f"  outcome={row['outcome'] or '-'}"
        )


@cli.command()
@click.argument("case_id")
@click.argument("outcome", type=click.Choice(["confirmed_malicious", "false_positive", "unresolved"]))
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

def _render_case(case) -> None:
    risk = case.risk
    if risk is None:
        click.secho("[-] Investigation did not produce a risk assessment.", fg="red")
        return

    color = _CATEGORY_COLOR.get(risk.category, "white")
    click.echo()
    click.secho(f"Risk: {risk.category.value}", fg=color, bold=True, nl=False)
    click.echo(f"   Score: {risk.score}/100   Confidence: {risk.confidence:.0%}")

    # An indecisive verdict has to explain itself, or a reader will round it down
    # to "probably fine" — which is the exact failure this state exists to prevent.
    if risk.uncertainty:
        if risk.uncertainty.get("reason"):
            click.secho(f"\nWhy this is not a verdict: {risk.uncertainty['reason']}.", fg=color)
        if risk.uncertainty.get("unavailable_sources"):
            click.echo(
                "Not checked: " + ", ".join(risk.uncertainty["unavailable_sources"])
                + "  (absence of data from these is not evidence of safety)"
            )

    if risk.top_contributors:
        click.echo("\nPrimary contributors:")
        for c in risk.top_contributors:
            click.echo(f"  - {c}")

    if risk.contradicting:
        click.echo("\nCounter-evidence:")
        for c in risk.contradicting[:5]:
            entity = case.entities.get(c.get("entity_id"))
            # Name the entity: several extracted indicators often produce the same
            # signal, and identical unattributed lines read as duplicated evidence.
            subject = f" [{entity.value}]" if entity else ""
            click.echo(f"  - {c['signal']}{subject}: {c['value']}")

    if risk.historical_similarity:
        hs = risk.historical_similarity
        click.echo(f"\nHistorical similarity: {hs['similarity']:.0%} to {hs['pattern_name']}")

    click.echo(f"\n{case.explanation}")
    click.echo()
    click.secho("Recommended action:", bold=True)
    click.echo(f"  {case.recommendation}")


def _render_evidence(case) -> None:
    click.echo("\n--- Evidence ---")
    for ev in case.evidence.values():
        entity = case.entities.get(ev.entity_id)
        target = entity.value if entity else ev.entity_id
        click.echo(
            f"  [{ev.polarity.value:<20}] {ev.source:<12} {ev.signal:<28} "
            f"{target:<30} = {ev.value} (conf {ev.confidence:.2f}, {ev.independence.value})"
        )


def _render_pivots(case) -> None:
    click.echo("\n--- Pivots ---")
    for p in case.pivots:
        marker = "+" if p.status == "accepted" else "-"
        click.echo(
            f"  [{marker}] {p.entity_type.value:<12} {p.entity_value:<30} "
            f"priority={p.priority:.2f} status={p.status}"
            + (f" ({p.rejection_reason})" if p.rejection_reason else f" ({p.reason})")
        )


def _render_patterns(case) -> None:
    click.echo("\n--- Historical Pattern Matches ---")
    if not case.pattern_matches:
        click.echo("  none")
        return
    for m in case.pattern_matches:
        click.echo(
            f"  {m['similarity']:.0%}  {m['pattern_name']}  "
            f"matched_on={m['matched_indicators']}  prior_outcome={m.get('prior_outcome') or 'unknown'}"
        )


def _render_graph(graph) -> None:
    click.echo("\n--- Investigation Graph ---")
    click.echo(graph.to_ascii())


def _render_trace(trace) -> None:
    click.echo("\n--- Investigation Trace ---")
    for i, step in enumerate(trace.steps, 1):
        stage = step.pop("stage")
        click.echo(f"  {i:>3}. {stage:<22} {step}")


def main():
    cli()


if __name__ == "__main__":
    main()
