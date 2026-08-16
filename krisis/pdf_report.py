"""
PDF case-report renderer.

Reads a stored case dict — the exact shape `Case.to_dict()` produces and
`Storage.get_case()` reads back, the same dict the CLI text renderer and
`--json` already consume — and writes a PDF. This module performs no
investigation, no correlation, and no risk computation of its own; it is a
third renderer over the one existing report model (see cli.py's
`_render_case` / `--json`), not a second source of truth.

Never touches the network, never re-runs collection or pivots, never
mutates the case or provider cache. `krisis show <case_id> --pdf` is the
only caller.
"""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime
from typing import Any, Optional

from fpdf import FPDF
from fpdf.fonts import FontFace

from .core.graph import EntityGraph
from .core.risk import historical_match_label

_NAVY = (25, 40, 75)
_CYAN = (30, 110, 150)
_GRAY_DARK = (55, 55, 55)
_GRAY_MED = (110, 110, 110)
_GRAY_LIGHT = (205, 205, 205)
_GREEN = (30, 135, 70)
_AMBER = (175, 130, 10)
_RED = (185, 45, 45)
_BRIGHT_RED = (150, 0, 0)
_MAGENTA = (140, 55, 140)

_CATEGORY_RGB = {
    "LOW": _GREEN,
    "MEDIUM": _AMBER,
    "HIGH": _RED,
    "CRITICAL": _BRIGHT_RED,
    "INSUFFICIENT_EVIDENCE": _MAGENTA,
    "CONFLICTING_EVIDENCE": _AMBER,
    "UNKNOWN": _GRAY_MED,
}

_PAGE_WIDTH_MM = 180  # A4 minus 15mm margins each side


def default_output_path(case_id: str) -> str:
    """Deterministic default so `krisis show <id> --pdf` never has to ask where."""
    return os.path.join("reports", f"{case_id}.pdf")


def generate_pdf(case: dict[str, Any], output_path: Optional[str] = None) -> str:
    """Render `case` (a stored case dict) to a PDF and return the path written.

    Pure function of the dict passed in: no I/O other than creating the output
    directory and writing the one file, no network access, no case mutation.
    """
    path = output_path or default_output_path(case.get("id", "case"))
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    pdf = _ReportPDF(case)
    pdf.build()
    pdf.output(path)
    return path


# -- text helpers -------------------------------------------------------------

_ASCII_PUNCTUATION = str.maketrans({
    "—": "-", "–": "-",       # em dash, en dash
    "‘": "'", "’": "'",       # curly single quotes
    "“": '"', "”": '"',       # curly double quotes
    "…": "...",                     # ellipsis
    "→": "->", "←": "<-",     # arrows
    "•": "-",                       # bullet
})


def _clean(value: Any) -> str:
    """Core PDF fonts only support latin-1. Case data (message bodies, IDN
    domains, AI prose) can legitimately contain anything, so every string that
    reaches the PDF is sanitized here rather than trusted to already fit.
    Common "smart" punctuation is transliterated to plain ASCII first — the
    generic replace fallback below turns anything still unsupported (e.g. CJK
    text) into '?' rather than crashing, but a stray '?' in place of a normal
    dash in KRISIS's own explanation prose would look like a rendering bug."""
    text = "" if value is None else str(value)
    text = text.translate(_ASCII_PUNCTUATION)
    return text.encode("latin-1", "replace").decode("latin-1")


def _fmt_value(value: Any) -> str:
    if isinstance(value, (dict, list)):
        import json
        text = json.dumps(value, default=str)
    else:
        text = str(value)
    return _clean(text)[:300]


def _fmt_pct(value: Any) -> str:
    return f"{value:.0%}" if isinstance(value, (int, float)) else "N/A"


def _fmt_timestamp(value: str) -> str:
    if not value:
        return "unknown"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return value
    return dt.strftime("%Y-%m-%d %H:%M UTC" if dt.tzinfo else "%Y-%m-%d %H:%M")


def _evidence_rows(case: dict[str, Any], polarity: str) -> list[tuple[str, ...]]:
    """Evidence items of one polarity, strongest first — the same derivation
    cli.py._render_case uses for counter-evidence, extended to supporting
    evidence too. Reusing it (rather than re-deriving from risk.supporting,
    which to_dict() only stores as a count) keeps the PDF and CLI/JSON
    reporting the identical set of items for the identical case."""
    entities_by_id = {e["id"]: e for e in case.get("entities") or []}
    items = [ev for ev in (case.get("evidence") or []) if ev.get("polarity") == polarity]
    items.sort(key=lambda e: e.get("confidence") or 0, reverse=True)
    rows = []
    for ev in items:
        entity = entities_by_id.get(ev.get("entity_id"))
        target = entity["value"] if entity else (ev.get("entity_id") or "")
        rows.append((
            ev.get("evidence_type", ""), ev.get("signal", ""), target,
            _fmt_value(ev.get("value")), _fmt_pct(ev.get("confidence")),
            ev.get("source", ""), ev.get("provenance", ""),
        ))
    return rows


class _ReportPDF(FPDF):
    def __init__(self, case: dict[str, Any]):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.case = case
        self.set_auto_page_break(auto=True, margin=22)
        self.set_margins(15, 18, 15)
        self.alias_nb_pages()
        self.set_title(_clean(f"KRISIS Investigation Report - {case.get('seed', '')}"))

    # -- running header/footer (skipped on the cover page) --------------------

    def header(self) -> None:
        if self.page_no() == 1:
            return
        self.set_y(8)
        self.set_font("helvetica", "B", 8)
        self.set_text_color(*_GRAY_MED)
        self.cell(90, 6, _clean("KRISIS INVESTIGATION REPORT"))
        self.set_font("helvetica", "", 8)
        self.cell(90, 6, _clean(self.case.get("id", "")), align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*_GRAY_LIGHT)
        self.line(15, 15, 195, 15)
        self.set_y(20)

    def footer(self) -> None:
        if self.page_no() == 1:
            return
        self.set_y(-15)
        self.set_font("helvetica", "", 8)
        self.set_text_color(*_GRAY_MED)
        self.cell(0, 10, _clean(f"Page {self.page_no()} / {{nb}}"), align="C")

    # -- layout primitives ------------------------------------------------------

    def h1(self, text: str) -> None:
        self.set_x(self.l_margin)
        self.set_font("helvetica", "B", 15)
        self.set_text_color(*_NAVY)
        self.cell(0, 10, _clean(text), new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*_CYAN)
        self.set_line_width(0.6)
        self.line(self.l_margin, self.get_y(), self.l_margin + 28, self.get_y())
        self.set_line_width(0.2)
        self.ln(4)

    def h2(self, text: str) -> None:
        self.set_x(self.l_margin)
        self.set_font("helvetica", "B", 11)
        self.set_text_color(*_CYAN)
        self.cell(0, 7, _clean(text), new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def line_label(self, text: str, size: float = 10, color=_GRAY_MED) -> None:
        self.set_x(self.l_margin)
        self.set_font("helvetica", "B", size)
        self.set_text_color(*color)
        self.cell(0, size * 0.6, _clean(text), new_x="LMARGIN", new_y="NEXT")

    def line_value(self, text: Any, size: float = 10.5, color=_GRAY_DARK) -> None:
        self.set_x(self.l_margin)
        self.set_font("helvetica", "", size)
        self.set_text_color(*color)
        shown = _clean(text) if text not in (None, "") else "-"
        self.multi_cell(0, size * 0.58, shown, new_x="LMARGIN", new_y="NEXT")

    def kv_block(self, rows: list[tuple[str, Any]], size: float = 10) -> None:
        for label, value in rows:
            self.line_label(str(label).upper() + ":", size=size)
            self.line_value(value, size=size + 0.5)
            self.ln(1)

    def bullet(self, text: str, color=_GRAY_DARK) -> None:
        self.set_x(self.l_margin + 3)
        self.set_font("helvetica", "", 9.5)
        self.set_text_color(*color)
        self.multi_cell(0, 5.3, "- " + _clean(text), new_x="LMARGIN", new_y="NEXT")

    def render_table(self, headers, rows, col_widths, font_size: float = 8.5) -> None:
        """Wraps FPDF's table() with our styling; falls back to a plain note
        when there is nothing to show rather than an empty ruled box."""
        if not rows:
            self.line_value("none")
            return
        self.set_x(self.l_margin)
        self.set_font("helvetica", "", font_size)
        with self.table(
            col_widths=col_widths, text_align="LEFT",
            headings_style=FontFace(emphasis="BOLD", color=255, fill_color=_CYAN),
        ) as fpdf_table:
            row = fpdf_table.row()
            for h in headers:
                row.cell(_clean(h))
            for r in rows:
                row = fpdf_table.row()
                for c in r:
                    row.cell(_clean(c))

    # -- report sections ---------------------------------------------------------

    def build(self) -> None:
        self.add_page()
        self._cover()
        self.add_page()
        self._executive_summary()
        self._primary_evidence()
        self._counter_evidence()
        self._evidence_coverage()
        self._provider_usage()
        self._investigation_graph()
        self._investigation_trace()
        self._historical_memory()
        self._risk_and_confidence()
        self._recommendation()
        self._explanation()
        self._case_metadata()

    def _cover(self) -> None:
        case = self.case
        self.set_y(28)
        self.set_font("helvetica", "B", 28)
        self.set_text_color(*_NAVY)
        self.cell(0, 14, "KRISIS", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_font("helvetica", "", 11)
        self.set_text_color(*_GRAY_MED)
        self.multi_cell(
            0, 6,
            _clean("Knowledge-driven Risk Intelligence & Security Investigation System"),
            align="C",
        )
        self.ln(6)
        self.set_font("helvetica", "B", 17)
        self.set_text_color(*_CYAN)
        self.cell(0, 10, "Investigation Report", align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(16)

        self.kv_block([
            ("Case ID", case.get("id", "")),
            ("Target", case.get("seed", "")),
            ("Target type", case.get("seed_type", "")),
            ("Date / time", _fmt_timestamp(case.get("created_at", ""))),
        ])
        self.ln(6)

        risk = case.get("risk") or {}
        category = risk.get("category", "UNKNOWN")
        color = _CATEGORY_RGB.get(category, _GRAY_MED)
        y0 = self.get_y()
        self.set_draw_color(*color)
        self.set_line_width(0.8)
        self.rect(self.l_margin, y0, _PAGE_WIDTH_MM, 32)
        self.set_line_width(0.2)
        self.set_xy(self.l_margin + 6, y0 + 5)
        self.set_font("helvetica", "B", 14)
        self.set_text_color(*color)
        self.cell(0, 8, _clean(f"Verdict: {category}"), new_x="LMARGIN", new_y="NEXT")
        self.set_x(self.l_margin + 6)
        self.set_font("helvetica", "", 11)
        self.set_text_color(*_GRAY_DARK)
        self.cell(0, 7, _clean(f"Risk score: {risk.get('score', 'N/A')}/100"), new_x="LMARGIN", new_y="NEXT")
        self.set_x(self.l_margin + 6)
        self.cell(0, 7, _clean(f"Confidence: {_fmt_pct(risk.get('confidence'))}"))
        self.set_y(y0 + 40)

    def _executive_summary(self) -> None:
        self.h1("Executive Summary")
        case = self.case
        risk = case.get("risk") or {}
        uncertainty = risk.get("uncertainty") or {}

        summary = (
            f"KRISIS investigated '{case.get('seed', '')}' ({case.get('seed_type', '')}) and "
            f"reached a deterministic verdict of {risk.get('category', 'UNKNOWN')} "
            f"(score {risk.get('score', 'N/A')}/100, confidence {_fmt_pct(risk.get('confidence'))})."
        )
        self.line_value(summary)
        self.ln(1)
        if risk.get("top_contributors"):
            self.line_label("MAIN REASON:")
            self.line_value("; ".join(risk["top_contributors"][:3]))
            self.ln(1)
        if uncertainty.get("reason"):
            self.line_label("MAJOR UNCERTAINTY:")
            self.line_value(uncertainty["reason"])
            self.ln(1)
        self.h2("Recommended action")
        self.line_value(case.get("recommendation") or "(none recorded)")

    def _primary_evidence(self) -> None:
        self.h1("Primary Evidence (Supporting)")
        rows = _evidence_rows(self.case, "supports_threat")
        if not rows:
            self.line_value("No evidence directly supporting a threat hypothesis was found.")
            return
        self.render_table(
            ("Type", "Signal", "Entity", "Value", "Conf.", "Source", "Provenance"),
            rows[:15], (20, 26, 30, 28, 13, 18, 45),
        )
        if len(rows) > 15:
            self.line_value(f"... and {len(rows) - 15} more supporting item(s) (see --json for the full list).")

    def _counter_evidence(self) -> None:
        self.h1("Counter-Evidence")
        rows = _evidence_rows(self.case, "contradicts_threat")
        if not rows:
            self.line_value("No contradicting evidence was found.")
        else:
            self.render_table(
                ("Type", "Signal", "Entity", "Value", "Conf.", "Source", "Provenance"),
                rows[:15], (20, 26, 30, 28, 13, 18, 45),
            )
            if len(rows) > 15:
                self.line_value(f"... and {len(rows) - 15} more contradicting item(s).")
        notes = ((self.case.get("risk") or {}).get("uncertainty") or {}).get("discounted_counter_evidence") or []
        if notes:
            self.h2("Notes")
            self.line_value(
                "Some counter-evidence above was excluded from the risk score for the reason(s) "
                "below - it does not rebut the finding it appears to contradict.",
                color=_GRAY_MED,
            )
            for note in notes:
                self.bullet(note, color=_GRAY_MED)

    def _evidence_coverage(self) -> None:
        self.h1("Evidence Coverage")
        self.line_value(
            "A source that was deliberately skipped (a budget or value-gate decision) is not "
            "the same as a source that was unavailable (it ran and could not answer); neither "
            "means the artifact is clean.",
            color=_GRAY_MED,
        )
        self.ln(1)
        case = self.case
        usage = case.get("provider_usage") or {}
        collected = sorted({ev.get("source") for ev in (case.get("evidence") or []) if ev.get("source")})
        cached = sorted(n for n, u in usage.items() if u.get("cached"))
        reused = sorted(n for n, u in usage.items() if u.get("deduplicated"))
        skipped = sorted(n for n, u in usage.items() if u.get("skipped"))
        rate_limited = sorted(n for n, u in usage.items() if u.get("rate_limited"))
        unavailable = sorted(((case.get("risk") or {}).get("uncertainty") or {}).get("unavailable_sources") or [])

        for label, names, color in (
            ("Collected", collected, _GREEN),
            ("Cached", cached, _CYAN),
            ("Reused (deduplicated)", reused, _CYAN),
            ("Skipped (deliberate)", skipped, _GRAY_MED),
            ("Rate-limited", rate_limited, _AMBER),
            ("Unavailable", unavailable, _RED),
        ):
            self.line_label(f"{label}:", color=color)
            self.line_value(", ".join(names) if names else "none")
            self.ln(1)

    def _provider_usage(self) -> None:
        self.h1("Provider Usage")
        usage = self.case.get("provider_usage") or {}
        rows = [
            (name, u.get("calls", 0), u.get("cached", 0), u.get("deduplicated", 0),
             u.get("skipped", 0), u.get("rate_limited", 0))
            for name, u in usage.items()
        ]
        self.render_table(("Provider", "Calls", "Cached", "Reused", "Skipped", "Rate-limited"),
                   rows, (34, 25, 25, 25, 30, 41))
        skip_reasons = [r for u in usage.values() for r in (u.get("skip_reasons") or [])]
        if skip_reasons:
            self.h2("Why requests were skipped")
            for reason in skip_reasons:
                self.bullet(reason, color=_GRAY_MED)

    def _investigation_graph(self) -> None:
        case = self.case
        if not case.get("entities"):
            self.h1("Investigation Graph")
            self.line_value("No graph was recorded for this case.")
            return
        graph = EntityGraph.from_dict(case)

        # A real node-link diagram needs room a mid-page slot won't give it, so
        # this section always opens on its own page rather than wherever the
        # previous section happened to end.
        self.add_page()
        self.h1("Investigation Graph")
        try:
            image = graph.to_image()
        except RuntimeError:
            self._investigation_graph_text(graph)
            return
        self.image(image, x=self.l_margin, w=_PAGE_WIDTH_MM)

    def _investigation_graph_text(self, graph: EntityGraph) -> None:
        """Indented text fallback for when matplotlib isn't installed."""
        children: dict[str, list] = defaultdict(list)
        for rel in graph.relationships():
            children[rel.source_entity_id].append(rel)
        roots = [e for e in graph.entities() if e.depth == 0] or list(graph.entities())[:1]
        visited: set[str] = set()

        def walk(entity, indent: int) -> None:
            if entity.id in visited:
                return
            visited.add(entity.id)
            self.set_x(self.l_margin + indent)
            self.set_font("helvetica", "B", 10)
            self.set_text_color(*_NAVY)
            self.cell(0, 6, _clean(f"[{entity.type.value}] {entity.value}"), new_x="LMARGIN", new_y="NEXT")
            for rel in children.get(entity.id, []):
                target = graph.get_entity(rel.target_entity_id)
                if not target or target.id in visited:
                    continue
                self.set_x(self.l_margin + indent + 6)
                self.set_font("helvetica", "I", 9)
                self.set_text_color(*_CYAN)
                self.multi_cell(0, 5.2, _clean(f"-> {rel.relation_type}: {rel.reason}"),
                                 new_x="LMARGIN", new_y="NEXT")
                walk(target, indent + 12)

        for root in roots:
            walk(root, 0)
            self.ln(2)

    def _investigation_trace(self) -> None:
        self.h1("Investigation Trace")
        self.line_value(
            "The full step-by-step trace is a live-execution artifact and is not stored with "
            "the case, so it is not part of replay. This section reconstructs the major "
            "recorded decisions from what is stored: pivots, and provider skips/failures.",
            color=_GRAY_MED,
        )
        self.ln(1)
        case = self.case
        pivots = case.get("pivots") or []
        if pivots:
            self.h2("Pivot decisions")
            rows = [
                (p.get("entity_type", ""), p.get("entity_value", ""),
                 p.get("status", ""), p.get("rejection_reason") or p.get("reason") or "")
                for p in pivots
            ]
            self.render_table(("Entity type", "Entity value", "Decision", "Reason"), rows, (26, 46, 24, 84))
        if case.get("provider_skips"):
            self.h2("Provider requests skipped")
            for note in case["provider_skips"]:
                self.bullet(note, color=_GRAY_MED)
        if case.get("provider_failures"):
            self.h2("Provider requests unavailable")
            for note in case["provider_failures"]:
                self.bullet(note, color=_RED)

    def _historical_memory(self) -> None:
        self.h1("Historical Memory")
        matches = self.case.get("pattern_matches") or []
        if not matches:
            self.line_value("No historical or structural pattern match was found for this case.")
            return
        for m in matches:
            label = historical_match_label(m)
            self.set_x(self.l_margin)
            self.set_font("helvetica", "B", 11)
            self.set_text_color(*_NAVY)
            self.multi_cell(0, 6.5, _clean(f"{label} - overall similarity {m.get('similarity', 0):.0%}"),
                             new_x="LMARGIN", new_y="NEXT")
            self.kv_block([
                ("Indicator similarity", f"{m.get('indicator_similarity', 0):.0%}"),
                ("Structural similarity", f"{m.get('structural_similarity', 0):.0%}"),
                ("Prior outcome", m.get("prior_outcome") or "unknown"),
                ("Pattern / case reference", m.get("pattern_name") or m.get("pattern_id") or ""),
            ] + ([("Pattern stage", m["pattern_stage"])] if m.get("pattern_stage") else []), size=9)
            if m.get("matched_indicators"):
                self.line_label("SHARED INDICATORS:", size=9)
                self.line_value(", ".join(m["matched_indicators"]), size=9.5)
            if m.get("matched_facets"):
                self.line_label("SHARED STRUCTURE:", size=9)
                self.line_value(", ".join(m["matched_facets"]), size=9.5)
                if not m.get("matched_indicators"):
                    self.h2("Structural pattern learning")
                    self.line_value(
                        "The current artifact does not share concrete infrastructure with the "
                        "matched prior case above - only the shape of the investigation "
                        f"resembles it (indicator overlap {m.get('indicator_similarity', 0):.0%}, "
                        f"structural similarity {m.get('structural_similarity', 0):.0%}).",
                        color=_GRAY_MED,
                    )
            self.ln(3)

    def _risk_and_confidence(self) -> None:
        self.h1("Risk and Confidence")
        risk = self.case.get("risk") or {}
        if not risk:
            self.line_value("No risk assessment is available for this case.")
            return
        category = risk.get("category", "UNKNOWN")
        color = _CATEGORY_RGB.get(category, _GRAY_MED)
        self.set_x(self.l_margin)
        self.set_font("helvetica", "B", 13)
        self.set_text_color(*color)
        self.cell(0, 8, _clean(f"Category: {category}"), new_x="LMARGIN", new_y="NEXT")
        self.line_value(
            f"Score: {risk.get('score', 'N/A')}/100 - a deterministic, evidence-weighted score, "
            f"not a probability of attack. Confidence: {_fmt_pct(risk.get('confidence'))} - how "
            f"complete and reliable the underlying evidence is, scored independently of the score."
        )
        uncertainty = risk.get("uncertainty") or {}
        if uncertainty.get("unavailable_sources"):
            self.ln(1)
            self.line_value(
                "Not checked: " + ", ".join(uncertainty["unavailable_sources"]) +
                " (absence of data from these is not evidence of safety).",
                color=_AMBER,
            )
        if risk.get("top_contributors"):
            self.h2("Primary contributors")
            for c in risk["top_contributors"]:
                self.bullet(c)

    def _recommendation(self) -> None:
        self.h1("Recommendation")
        self.line_value(self.case.get("recommendation") or "(no recommendation recorded)")

    def _explanation(self) -> None:
        source = self.case.get("explanation_source", "deterministic")
        self.h1("Plain-Language Explanation" if source == "ai" else "Deterministic Explanation")
        self.line_value(self.case.get("explanation") or "(no explanation recorded)")

    def _case_metadata(self) -> None:
        self.h1("Case Metadata")
        case = self.case
        self.kv_block([
            ("Case ID", case.get("id", "")),
            ("Seed / target", case.get("seed", "")),
            ("Seed type", case.get("seed_type", "")),
            ("Investigation timestamp", _fmt_timestamp(case.get("created_at", ""))),
            ("Outcome", case.get("outcome") or "unknown / not yet validated"),
            ("Entities", len(case.get("entities") or [])),
            ("Relationships", len(case.get("relationships") or [])),
            ("Evidence items", len(case.get("evidence") or [])),
            ("Pivots considered", len(case.get("pivots") or [])),
            ("Historical matches", len(case.get("pattern_matches") or [])),
        ])
