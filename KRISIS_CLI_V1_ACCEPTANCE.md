# KRISIS CLI v1 — Acceptance Record

## 1. What KRISIS CLI is

KRISIS is a CLI-first investigation engine for suspicious URLs, domains, IPs,
file hashes, and messages. Given a target, it collects evidence from several
independent sources, decides what discovered relationships are worth
following, correlates what it finds, checks the target against previously
investigated cases, weighs supporting evidence against contradicting
evidence, and produces a deterministic, explainable risk score with a
recommended action. An optional language model can translate the finished
finding into plain language; it never participates in the decision.

## 2. What problem it solves

A single reputation score ("31/70 engines flagged this") is a black box:
flagged why, related to what, seen before, how sure is the tool of its own
answer. KRISIS exists to answer those questions explicitly rather than
collapse them into one number. It also refuses to silently convert "I
couldn't check" into "looks clean" — a distinction most reputation wrappers
do not make.

## 3. Final architecture

```
INPUT  -> indicator extraction (domain / IP / hash / URL / message)
       -> Investigator: collectors -> pivot engine -> graph
       -> Correlation (supporting vs contradicting, diversity)
       -> Pattern memory (indicator + structural historical match)
       -> Risk engine (deterministic score, category, confidence, uncertainty)
       -> Recommendation
       -> Explanation (template, or optional Nemotron translation)
       -> Storage (SQLite case + indicator/pattern memory)
       -> (on demand, replaying storage only) CLI text / --json / --pdf
```

Every stage after collection operates only on structured data produced by the
stage before it. The CLI (`krisis/cli.py`) is a thin renderer over
`krisis.core` / `krisis.collectors` / `krisis.memory` / `krisis.ai` — it
performs no investigation logic itself. `krisis/pdf_report.py` is a third
renderer of the same kind, alongside the CLI text renderer and `--json`: it
reads a stored case back and formats it, and — like both of those — never
re-enters the pipeline above (see §14, Case Report Export).

## 4. Investigation workflow

1. Seed a target (domain, URL, IP, hash, or message body/file).
2. Extract initial indicators and register the seed entity in the graph.
3. Run configured collectors against the seed, budgeted by
   `InvestigationBudget` (max depth, max entities, max external calls).
4. Each collector's findings are evaluated as pivot candidates; the pivot
   engine accepts or rejects each one with a stated reason (priority,
   commodity-infrastructure suppression, per-entity pivot cap, budget
   exhaustion).
5. Accepted pivots are investigated in turn, subject to the same budget.
6. Evidence is correlated into supporting/contradicting sets.
7. Pattern memory checks the resulting graph and evidence against every
   prior stored case on two independent dimensions (indicator, structural).
8. The risk engine combines correlation, historical impact, and coverage
   into a score, category, confidence, and uncertainty.
9. A recommendation and an explanation are generated.
10. The case (entities, relationships, evidence, pivots, pattern matches,
    risk, explanation, recommendation, provider usage/failures/skips) is
    persisted to SQLite and printed.

## 5. Evidence sources

Independently optional collectors, present in `krisis/collectors/`:

- `DNSCollector` — resolution records
- `WHOISCollector` — registration age, registrant, registrar
- `TLSCollector` — certificate identity and validity
- `IPCollector` — IP/ASN ownership (`ip_whois`)
- `VirusTotalCollector` — third-party reputation (rate-limited, budgeted)
- `IdentityCollector` — confusable/homoglyph/decoration-token derivation,
  verified against resolution, registration age and operator
- `PageCollector` — page fetch with SSRF guard, scheme allowlist, redirect-
  chain tracking and limits
- `MessageCollector` — indicator extraction from message/text bodies

Each collector runs with zero required API keys; VirusTotal and the AI
explanation layer are the only two credentialed integrations
(`krisis setup --show` reports which are configured).

## 6. Provider-planning model

`krisis/core/provider_planner.py` sits between pivot discovery and provider
execution and answers, in order: already asked this exact question (reuse),
answered recently enough (cache), is this entity worth a scarce request
(value gate), inside the rate limit and daily quota (defer/skip), did the
provider just say back off (honour it). Policy — rate, quota, cache TTL,
value threshold — is configuration (`config.provider_policies()`), env-
overridable, not hardcoded intelligence.

Every decision is recorded. A declined request still returns
`available=False` with a reason so "not asked" never silently reads as
"nothing found," but it is reported through a separate channel from a real
failure: `case.provider_skips` (`[i] N provider request(s) deliberately
skipped`) versus `case.provider_failures` (`[!] N evidence source(s)
unavailable`). The two lists are structurally distinct in the `Case` model,
in storage, in the CLI renderer, and in `--json` output — a budget rule
working as designed can never render as a broken evidence source. Verified
live: investigating `github.com` produced 1 real VirusTotal call plus 10
value-gate skips and zero failures, rendered under the correct, separate
headings; re-running against the same store produced zero new external
calls (full cache/dedup reuse) except where TTLs had not yet been read from
cache at trace-log time.

## 7. Graph model

`krisis/core/graph.py` (`EntityGraph`) stores entities and typed
relationships (`resolves_to`, `secured_by`, `registered_by`, `looks_like`,
`vt_related`, `mentions`, ...), each relationship carrying a reason string.
`--show-graph` renders it as ASCII with entity type, value, and the
relationship that connects it to its parent — both on a live `investigate`
run and on a stored-case `show --show-graph` replay, with identical
structure between the two. `EntityGraph.to_image()` renders the same stored
structure as an actual node-link diagram (matplotlib: boxes, labeled
arrows, a per-entity-type color legend) rather than an indented tree — used
by the PDF case report's Investigation Graph section (§14); it raises
`RuntimeError` if matplotlib isn't installed, which the PDF renderer catches
and falls back to a text-tree rendering for, so `--pdf` never hard-depends
on the graphing library being present.

## 8. Historical-memory model

`krisis/memory/pattern_memory.py` computes indicator similarity: does the
current investigation share a concrete value (certificate, IP, domain, ...)
with a prior stored case, weighted by how distinguishing that indicator type
is. A fired indicator match is further classified, never left generic:

- `indicator_kind = "exact_artifact"` — the shared value was itself the
  prior case's own seed. This is the same artifact investigated before.
- `indicator_kind = "infrastructure"` — the prior case only pivoted to that
  value (a shared cert, a shared IP). A materially weaker claim.
- `indicator_kind = None` with only structural similarity firing — no
  concrete value is shared at all; only the shape of the investigation
  resembles a prior one.

`risk.historical_match_label()` is the single place that turns this into
prose ("exact artifact seen before" / "infrastructure overlap with a prior
case" / "structurally similar new artifact, no shared indicator"), and every
renderer — CLI (`show`, `investigate`), `--json`, and the AI template
explanation — calls it rather than inventing its own phrasing. Regression
coverage: `tests/test_historical_match_semantics.py` (10 tests), including
an end-to-end CLI/JSON check that the old generic "Historical similarity:
N%" phrasing is gone from the output at any percentage.

## 9. Structural-pattern model

Independent of indicator similarity: each case stores a signature of its
*shape* with all concrete values stripped — which signal categories argued
for/against a threat, which relationship types were followed, which entity
classes the pivots reached. Facets are weighted by inverse document
frequency computed over stored cases at query time, so structure common to
every investigation contributes almost nothing while a rare co-occurrence
dominates. This is what lets KRISIS recognise a domain on rotated
infrastructure that shares no IP, certificate, or nameserver with anything
seen before. A shape's influence on scoring is scaled by its pattern
lifecycle stage (`observed -> candidate -> repeated -> validated ->
trusted`, or `deprecated`), which only advances past `repeated` via a
human-confirmed `krisis outcome`.

## 10. Risk/confidence model

`krisis/core/risk.py` (`RiskEngine`) combines evidence-diversity-scaled
support/contradiction weights, historical impact (similarity × outcome
trust of the matched prior case), and coverage (what was actually checked)
into a score and category. "Not checked" is never "clean": no evidence at
all, or a low score with no reputation source reachable, both land in
`INSUFFICIENT_EVIDENCE` rather than `LOW`; comparable supporting and
contradicting weight lands in `CONFLICTING_EVIDENCE`; a flagged-but-
uncorroborated reputation hit is floored at `MEDIUM`, never `LOW`. A
historical match to a confirmed-malicious prior case cannot be reported as
clean regardless of current reputation (`_historical_malicious_floor`).
Confidence is scaled by coverage independently of the score, so risk and
confidence can and do disagree when that is the honest state. Verified live
against `github.com`: `LOW / 0 / confidence 90%`, with the actual counter-
evidence and zero contradictory labeling.

## 11. AI boundary

`krisis/ai/explain.py` (`Explainer`) sits strictly downstream of the risk
engine. Default (and always-available) mode builds the explanation directly
from structured `Case`/`CorrelationResult` data with simple string
formatting — deterministic, no model call, zero hallucination risk. If
`NVIDIA_API_KEY` is configured, the same structured summary (risk, weighted
evidence, counter-evidence, historical match, uncertainty, provider usage —
never the raw graph or network access) is sent to a configured model with a
system prompt that forbids inventing evidence, disputing or recomputing the
score, or claiming an unconsulted source was checked. Any call failure,
non-200 response, or unparseable output falls back to the deterministic
template. This was exercised live in this pass: the configured
`NVIDIA_API_KEY` currently returns `401 Unauthorized` from the endpoint (an
expired/invalid credential, not a code defect), and `krisis investigate
github.com --explain` correctly fell back to the identical deterministic
explanation with no crash and no degraded output — the exact behavior the
architecture specifies for "AI unavailable."

## 12. CLI commands

`krisis`, `krisis --help`, `krisis investigate --help`, `krisis show
--help`, `krisis cases --help`, `krisis setup --help`, `krisis outcome
--help` all render a colorized banner/usage/options block; the bare
no-argument form exits 0 with the same help content instead of an
argument-parsing error. Commands: `investigate`, `show`, `cases`, `setup`,
`outcome`. `investigate` and `show` share `--show-graph`, `--show-evidence`,
`--show-pivots`, `--show-patterns`, `--explain`, `--verbose`, `--json`;
`investigate` additionally has `--show-trace` (a live-execution artifact,
not persisted, so it is not part of replay) and collection-budget flags
(`--max-depth`, `--max-entities`, `--max-external-calls`, `--no-prompt`).
`show` additionally has `--pdf` (export the stored case as a PDF report;
see §14) and `--output <path>` (override the default `./reports/<id>.pdf`).

Top-level help discoverability: `krisis` / `krisis --help` used to list only
the five commands, so finding `--show-graph` or `--explain` meant a second
`krisis investigate --help` call. A "Common / Important Options" block
(`krisis/cli.py::_KrisisGroup.format_common_options`) now renders directly
under the command list — `investigate`'s and `show`'s important flags, one
per line, colorized (cyan subheadings, green flag names) consistent with the
rest of the CLI's help styling — with the epilog pointing to `krisis
investigate --help` / `krisis show --help` for the complete, per-command
option lists including the budget controls (`--max-depth`, `--max-entities`,
`--max-external-calls`) that are intentionally left out of the summary. No
investigation, risk, or provider logic changed; no new flags were added —
every option shown already existed. Regression coverage:
`tests/test_cli.py::TestTopLevelHelp` (both the bare `krisis` and
`krisis --help` forms show the summary and the flags it lists are asserted
to be real options of their command, not just strings that could drift).

## 13. Example investigation

```
$ krisis investigate github.com

Risk: LOW   Score: 0/100   Confidence: 90%

Primary contributors:
  - no evidence contributed to a threat hypothesis

Counter-evidence:
  - long_lived_domain [github.com]: 6885
  - valid_tls_present [github.com]: Sectigo Limited
  ...

LOW RISK (0/100, confidence 90%) for 'github.com'. No evidence directly
supporting a threat hypothesis was found. Contradicting evidence:
long_lived_domain (whois), valid_tls_present (tls), ...

Recommended action:
  LOW risk. No strong evidence of malicious activity was found. Normal
  caution still applies for any unfamiliar site or message.

Provider Usage
  dns 5  identity 5  ip_whois 6  tls 5  virustotal 1 skipped 10  whois 5

[i] 10 provider request(s) deliberately skipped:
    - virustotal skipped for octodex.github.com: discovered entity below the
      value threshold for a scarce provider (pivot priority 0.53 < 0.70, and
      no evidence here supports the threat hypothesis)
    ...

[+] Case stored: case_aedcd6da2a1e
```

This was a real, live run against the actual VirusTotal API during this
acceptance pass, not a fixture. `krisis show case_aedcd6da2a1e` (and its
`--show-graph`/`--show-evidence`/`--show-pivots`/`--show-patterns`/
`--explain`/`--json` variants) reproduced identical conclusions from
storage, confirmed to issue zero network calls during replay.

## 14. Case Report Export

A completed investigation can be exported as a professional PDF case report
without rerunning it:

```
krisis show <case_id> --pdf [--output <path>]
```

Default output path is deterministic: `./reports/<case_id>.pdf` (directory
created if needed). `--output` overrides it. Example:

```
$ krisis show case_06c38858bbdd --pdf
[+] Case report exported:
    reports/case_06c38858bbdd.pdf
```

**Architecture.** `krisis/pdf_report.py` renders directly from the same
stored-case dict `Storage.get_case()` / `Case.to_dict()` already produce —
the exact shape the CLI text renderer and `--json` consume. It is a third
renderer over that one report model, not a second, independently computed
summary:

```
Stored Case
    |
InvestigationReport (the stored case dict itself)
    +-- CLI renderer      (cli.py _render_*)
    +-- JSON renderer     (--json)
    +-- PDF renderer      (pdf_report.py, this feature)
```

No new risk calculation, no new correlation logic, no new provider calls —
`pdf_report.py` imports only `krisis.core.graph.EntityGraph` (to replay the
stored graph, same as `show --show-graph`) and `krisis.core.risk.
historical_match_label` (the one place historical-match phrasing is decided,
also the source `_render_case`/`_render_patterns` already call). It never
imports `requests`.

**Stored-case-only / no-network guarantee.** PDF generation reads the case
dict passed to it and writes one file; it does not call any collector,
provider, or the AI explanation layer. Verified three ways: (1) `requests.
get` and `requests.post` are both patched to raise `AssertionError` around
every `show --pdf` CLI test — if a network call happened, the test would
fail with that assertion, not a generation error; (2) a live case (`krisis
investigate wikipedia.org`, `case_06c38858bbdd`) had its `provider_events`
row count read from SQLite before and after `krisis show <id> --pdf` —
identical (735 before, 735 after); (3) `pdf_report.generate_pdf()` is proven
not to mutate the case dict it's given (`test_generation_does_not_mutate_the_
case_dict`, a `copy.deepcopy` equality check before/after).

**PDF contents.** Cover page (case ID, target, type, timestamp, verdict,
score, confidence in a colored box matching the CLI's risk-category
colors); Executive Summary; Primary Evidence (supporting) and Counter-
Evidence tables — signal, entity, observed value, confidence, source,
provenance, derived from `case["evidence"]` filtered by polarity, the same
derivation `_render_case` already uses for counter-evidence, extended to
supporting evidence; Evidence Coverage (collected / cached / reused /
skipped / rate-limited / unavailable, explicitly stated as non-equivalent);
Provider Usage table; Investigation Graph — a real node-link diagram
(`EntityGraph.to_image()`, matplotlib, boxes + labeled arrows + a per-
entity-type color legend) rendered from the stored graph, with an
indented-text-tree fallback if matplotlib is not installed; Investigation
Trace — reconstructed from `pivots`/`provider_skips`/`provider_failures`
(the actual live per-event trace is a live-execution artifact and, like
`investigate --show-trace`, is not persisted, so it is explicitly out of
scope for replay and the report says so rather than pretending to include
it); Historical Memory using `historical_match_label()` per match — never
a bare "Historical similarity: N%" — plus a Structural Pattern Learning
interpretation sentence for matches with no shared indicator; Risk and
Confidence (score is explicitly labeled not-a-probability); Recommendation;
an Explanation section labeled "Plain-Language Explanation" when the stored
case's `explanation_source == "ai"` or "Deterministic Explanation"
otherwise (see below); Case Metadata (counts only — no keys, no credential
material, nothing beyond what `to_dict()` already exposes).

**`explanation_source` field.** The stored case previously had no way to
tell whether `case.explanation` came from the NVIDIA model or the
deterministic template — both were just `case.explanation: str`. A one-
field addition (`Case.explanation_source`, set from `Explainer.
last_source` right after `case.explanation = self.explainer.explain(...)`
in `investigator.py`) lets the report label the explanation truthfully
without guessing from whether a key happens to be configured *now*. This
does not call the AI layer during report generation — it reads what was
already decided and stored at investigation time.

**Quality.** Cover page, running header/footer with page numbers
(`Page N / {nb}`), colored section headings, tables with wrapped long
values (evidence provenance, DNS/certificate strings) via fpdf2's
`table()`, an em/en-dash and curly-quote-to-ASCII transliteration pass
(`pdf_report._clean`) so KRISIS's own prose renders correctly under the
core Helvetica font rather than emitting stray `?` glyphs, and the graph
diagram fit to the page width with an added page break when needed so nothing overflows a page boundary.

**Dependencies.** `fpdf2` (core, required — the PDF renderer). `matplotlib`
(optional `report`/`graph` extra — the graph *image*; `to_image()` raises
`RuntimeError` without it, which the PDF renderer catches and falls back to
an indented text tree, so `--pdf` still works without it installed).
`pypdf` (dev-only — PDF report tests read the generated file's text back to
assert on its content).

## 15. Validation summary

- Working tree inspected before any change; all uncommitted modifications
  (provider-skip/failure split, exact-artifact/infrastructure/structural
  historical semantics, colorized CLI help/output) reviewed and understood
  as coherent in-progress fixes, not reverted.
- Full pytest and `unittest discover` suites green: 286/286, both runners.
- All CLI help screens (`krisis`, `--help`, and every subcommand's
  `--help`) verified to render useful, non-error output.
- Live `krisis investigate github.com` run against real collectors and the
  real VirusTotal API: verdict/score/confidence/evidence/recommendation all
  internally consistent, no `LOW + confirmed malicious` or `unavailable +
  clean` contradiction.
- `provider_skips` vs `provider_failures` distinction verified live, in
  storage, and in `--json`, plus mutation-tested (reverting the
  skip/failure branch in `investigator.py` makes the dedicated regression
  test fail).
- Exact-artifact / infrastructure-overlap / structural-only historical
  match semantics verified via the dedicated 10-test file, plus mutation-
  tested on both the classification logic (`risk.py`) and the seed-
  exclusion fix (`pattern_memory.py`).
- Case replay (`krisis show`) confirmed to reproduce the live case exactly
  and to make zero network calls (explicitly asserted via a mocked
  `requests.get`/`requests.post` that raises on any call).
- Case persistence confirmed across process boundaries: `investigate` and
  `show` were run as separate OS processes against the same SQLite store.
- `.bank.in` namespace behavior: existing dedicated tests
  (`TestBankNamespaceSignal`, `TestBankInNamespace`) pass unmodified; no
  new bank-specific hardcoding added.
- AI explanation boundary verified by code inspection (score computed and
  fixed before any model call; system prompt forbids inventing evidence or
  disputing the score; any failure falls back to template) and by a live
  failure case (expired key -> clean fallback, no crash).
- Collector security protections (SSRF guard, scheme allowlist, redirect
  limits, timeouts in `page_collector.py`) confirmed present and untouched.
- README cross-checked against actual behavior; one real gap found and
  fixed (see below) — no other stale claims found.
- PDF report export (`krisis show <id> --pdf`) added as a third renderer
  over the stored case (§14). Verified: generation succeeds from a stored
  case alone; the default output path is deterministic; `--output`
  overrides it; the case dict is not mutated by generation (`copy.deepcopy`
  equality check); zero network calls (both `requests.get`/`requests.post`
  patched to raise, plus a live before/after `provider_events` row-count
  check against a real case — 735 before, 735 after); PDF content contains
  case ID, target, risk category/score/confidence, recommendation,
  explanation, and evidence table rows sourced from `case["evidence"]`
  (not merely echoed via `risk.top_contributors`); provider skips and
  provider failures render under distinct headings, never merged; historical
  matches render via `historical_match_label()`, never a bare percentage.
  Live acceptance: `krisis investigate wikipedia.org` -> `case_06c38858bbdd`
  -> `krisis show case_06c38858bbdd --pdf` -> visually inspected (cover,
  evidence tables, node-link graph diagram, historical memory, risk section)
  -> cross-checked against `krisis show` (text) and `--json` for the same
  case: identical id/seed/risk category/score/confidence across all three
  surfaces.

## 16. Test count

**286 / 286 passing**, under both `pytest` and `python3 -m unittest discover
-s tests`. This count includes `tests/test_historical_match_semantics.py`
(10 tests), the extended `test_cli.py` / `test_investigator_integration.py`
coverage for the provider-skip/failure split, `TestTopLevelHelp` (2 tests)
for the top-level help UX pass, `tests/test_pdf_report.py` (16 tests: PDF
generation, deterministic default path, no-mutation, no-network, content
fidelity, explanation-source labeling, provider-skip/failure distinctness,
historical-match semantics, zero provider events), and 3 new
`tests/test_graph.py` cases for `EntityGraph.to_image()` (PNG output, empty
graph, and the no-matplotlib `RuntimeError` fallback path).

## 17. Mutation-testing summary

Material fixes were mutation-tested during this pass by temporarily
reverting each to its prior (buggy) behavior and confirming the relevant
test(s) fail, then restoring the original code:

| Mutation | Result |
|---|---|
| Force `historical_match_label` to never classify `exact_artifact` | 2 tests failed as expected |
| Revert `pattern_memory.py`'s seed-exclusion from value-based back to `depth == 0` | 1 test failed as expected |
| Revert `investigator.py`'s skip/failure branch to always report `provider_failures` | 1 test failed as expected |
| `pdf_report.py`: drop `provider_skips`/`provider_failures` from the Investigation Trace section | `test_pdf_keeps_provider_skips_distinct_from_failures` failed as expected |
| `pdf_report.py`: replace `historical_match_label(m)` with a generic `f"Historical similarity: {sim:.0%}"` | `test_pdf_historical_match_semantics_are_not_generic` failed as expected |
| `pdf_report.py`: force `_evidence_rows()` to always return `[]` (evidence dropped from the report) | `test_pdf_evidence_table_reflects_stored_evidence_items` failed as expected — this replaced an initial, weaker mutation test that checked only signal names, which turned out to also be echoed via `risk.top_contributors` and so didn't fail; the strengthened test checks fields (observed value, provenance) that exist *only* in the evidence table |

All were restored to their working state immediately after verification
(`git checkout --`, since the pre-mutation state was a clean commit); the
full suite was re-run clean (286/286) afterward. This is in addition to the
project's existing, larger body of mutation-verified rules documented in
`README.md` (commodity-infrastructure suppression, structural-similarity
weighting, provider budgeting, identity verification, and more).

## 18. Known limitations

Carried forward from the current, honest README scope statement — not
resolved or claimed resolved by this pass:

- No URL-scanning/redirect-chain collector for the page-fetch half of a
  credential-phishing shape; only the impersonation half is observable.
- Referent *legitimacy* is not modeled — the identity layer verifies a
  referent is established and resolving, not that it is the "real" brand
  versus an older squatter.
- Registrant organisation strings are compared literally (`PayPal Inc.` vs
  `PayPal, Inc` read as different owners).
- No temporal-shape signature dimension (burst timing, event ordering).
- Cases stored before structural matching existed carry indicators only,
  with no backfill.
- Only one third-party reputation provider (VirusTotal) is integrated.
- The JSON case payload uses `id`/`seed`/`pattern_matches` as field names;
  it does not expose a separate `hypotheses` list (KRISIS reasons about a
  single threat hypothesis, supported/contradicted by polarity-tagged
  evidence, not multiple named hypotheses) or a standalone `coverage`
  object (coverage is consumed internally by the risk engine and surfaces
  through `risk.confidence` and `risk.uncertainty` rather than as its own
  top-level key). Neither is a missing capability; both are naming
  differences from a forward-looking JSON sketch, not gaps in what is
  actually reported.

## 19. Explicit future work

Deliberately not built in this pass, per the acceptance scope:

- Shodan, AbuseIPDB, URLScan, PhishTank, or any additional reputation
  provider
- Additional AI models beyond the single configured explanation model
- Desktop UI, browser extension, or any collector unrelated to the
  existing investigation loop
- A dedicated URL-scanning/page-render collector for the credential-
  harvesting half of phishing detection
- A `hypotheses`/`coverage` JSON schema expansion, if a future consumer
  actually needs it as its own field rather than derived from existing ones

## 20. Why KRISIS is not merely a reputation-service wrapper

A reputation wrapper returns one opaque number from one source and stops.
KRISIS: (1) collects from multiple independent, individually optional
sources and states which ones actually answered; (2) builds and shows an
entity/relationship graph, not a flat list; (3) checks two independent
historical dimensions — has this exact artifact, or infrastructure it
touches, been seen before, versus does this merely resemble the *shape* of
a prior case — and reports which one fired, never conflating them; (4)
scores deterministically from evidence polarity, diversity, historical
impact, and coverage, and refuses to let an absent check read as a clean
verdict; (5) applies identity/lookalike reasoning verified against
resolution, age, and operatorship before it becomes evidence; (6) records
what a scarce provider was and was not asked, and why, as part of the
permanent case record; (7) keeps an optional LLM strictly downstream of a
score it cannot see until after that score is fixed. Live evidence from
this pass: `github.com` was investigated using one real VirusTotal call and
ten correctly-recorded value-gate skips — a plain reputation wrapper would
either have spent all ten or reported nothing about why it didn't.

## 21. CLI v1 completion statement

KRISIS CLI v1 — COMPLETE

The CLI can investigate, persist, replay, explain, inspect, and export a
complete investigation case as a PDF without rerunning external evidence
collection.

The investigation engine, evidence model, provider planning, graph,
historical memory, structural reasoning, deterministic risk, case replay,
JSON interface, CLI UX, AI explanation boundary, and PDF case report export
have been validated.

No release-blocking defect remains.

Future providers and interfaces are optional v2 capabilities, not
incomplete CLI requirements.
