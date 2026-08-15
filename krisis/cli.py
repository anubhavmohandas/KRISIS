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

from .config import default_collectors
from .core.investigator import Investigator
from .core.models import RiskCategory
from .memory.case_memory import CaseMemory
from .memory.pattern_memory import PatternMemory
from .memory.storage import DEFAULT_DB_PATH, Storage
from .core.pivot_engine import InvestigationBudget

_CATEGORY_COLOR = {
    RiskCategory.LOW: "green",
    RiskCategory.MEDIUM: "yellow",
    RiskCategory.HIGH: "red",
    RiskCategory.CRITICAL: "bright_red",
    RiskCategory.UNKNOWN: "white",
}


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
def investigate(
    target, is_file, is_hash, show_graph, show_evidence, show_pivots, show_patterns,
    show_trace, explain_only, as_json, verbose, max_depth, max_entities, max_external_calls, db_path,
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

    investigator = _build_investigator(db_path, max_depth, max_entities, max_external_calls)

    click.secho(f"[*] Investigating: {target}", fg="cyan")
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

    if case.provider_failures:
        click.secho(f"\n[!] {len(case.provider_failures)} evidence source(s) unavailable:", fg="yellow")
        for note in case.provider_failures:
            click.echo(f"    - {note}")

    click.secho(f"\n[+] Case stored: {case.id}", fg="cyan")


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

    if risk.top_contributors:
        click.echo("\nPrimary contributors:")
        for c in risk.top_contributors:
            click.echo(f"  - {c}")

    if risk.contradicting:
        click.echo("\nCounter-evidence:")
        for c in risk.contradicting[:5]:
            click.echo(f"  - {c['signal']}: {c['value']}")

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
