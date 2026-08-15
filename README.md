# KRISIS

**Knowledge-driven Risk Intelligence & Security Investigation System.**

A CLI-first investigation engine for suspicious URLs, domains, IPs, hashes,
and messages. KRISIS does not ask "does one security vendor think this is
bad?" — it collects evidence from multiple sources, decides what relationships
are worth following, correlates what it finds, checks it against previously
investigated cases, weighs supporting evidence against contradicting evidence,
and produces a deterministic, explainable risk score with a recommended
action.

```
VirusTotal / WHOIS / DNS / TLS  = evidence sources (witnesses)
KRISIS                          = the investigator
AI                               = explains the investigator's findings, in plain language
```

## Why this exists (vs. "just use VirusTotal")

A single provider score is a black box: *"31/70 engines flagged this."* Flagged
why? Related to what? Seen before? KRISIS exposes the evidence chain: which
observations support the conclusion, which contradict it, which relationships
were followed and why, whether this resembles infrastructure from a previously
confirmed case even when *today's* reputation is clean, and how confident the
system actually is in its own conclusion.

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e .

krisis investigate suspicious-domain.example --verbose
```

On first run KRISIS asks about optional provider keys, one at a time — what
each one buys, what you lose without it, and where to get it. Paste a key and
it is verified against the provider and saved to `~/.krisis/api_keys.txt`
(`0600`); press Enter to skip and it records the decision and never asks
again. Manage it any time:

```bash
krisis setup                              # walk through every unconfigured key
krisis setup --provider virustotal        # just one
krisis setup --show                       # what's configured, what's skipped
krisis investigate xyz.com --no-prompt    # never ask (scripts/CI)
```

Environment variables (`VIRUSTOTAL_API_KEY`, `ANTHROPIC_API_KEY`) always take
priority over the stored file.

Every collector is optional and independent: KRISIS runs with zero API keys and
zero of the optional `dnspython` / `python-whois` / `ipwhois` / `pyOpenSSL`
packages installed. What it will *not* do is convert a source it couldn't reach
into a clean verdict — a skipped source is reported as skipped in the output,
and a result that rests on unchecked reputation is reported as
`INSUFFICIENT_EVIDENCE` rather than `LOW`.

## CLI

```bash
krisis investigate xyz.com                       # basic
krisis investigate xyz.com --show-graph           # ASCII investigation graph
krisis investigate xyz.com --show-evidence        # every normalized evidence item
krisis investigate xyz.com --show-pivots          # every pivot considered, accepted or rejected, and why
krisis investigate xyz.com --show-patterns        # historical case similarity
krisis investigate xyz.com --show-trace           # full step-by-step replay log
krisis investigate xyz.com --verbose              # all of the above
krisis investigate xyz.com --json                 # full case as JSON
krisis investigate xyz.com --explain              # just the plain-language explanation

krisis investigate message.txt --file             # mine a message body for URLs/domains/emails
krisis investigate <sha256> --hash                # investigate a file hash

krisis cases                                      # list stored investigations
krisis outcome <case_id> confirmed_malicious       # close the learning loop
krisis outcome <case_id> false_positive
```

Budget flags (`--max-depth`, `--max-entities`, `--max-external-calls`) prevent
graph explosion — see `krisis/core/pivot_engine.py::InvestigationBudget`.

## Architecture

```
INPUT
  -> indicator extraction        krisis/core/indicators.py
  -> evidence collection         krisis/collectors/*  (provider-agnostic, each optional)
  -> normalization                (done inside each collector -> krisis/core/models.py::Evidence)
  -> pivot generation/priority   krisis/core/pivot_engine.py
  -> investigation queue/budget  krisis/core/investigator.py
  -> entity/relationship graph   krisis/core/graph.py
  -> pattern + case memory       krisis/memory/*  (SQLite)
  -> correlation                 krisis/core/correlation.py
  -> supporting/contradicting    (part of correlation output)
  -> risk + confidence           krisis/core/risk.py   (deterministic, no LLM)
  -> AI explanation              krisis/ai/explain.py  (template by default, optional LLM)
  -> recommended action          krisis/core/recommend.py
  -> case storage                krisis/memory/case_memory.py
  -> pattern/knowledge update    krisis/memory/pattern_memory.py + `krisis outcome`
```

`krisis/core/investigator.py::Investigator` is the only place that sequences
these — it contains no scoring or provider logic itself, which is what keeps
the risk score reproducible independent of which collectors happen to be
configured.

### Collectors reuse `recon_scanner.py`'s proven logic, not its code

DNS (`dnspython`), WHOIS, TLS/certificate, and IP/ASN (`ipwhois`) collection
approaches were adapted from the reconnaissance script this project started
from — the *approach* (resolver settings, timeout handling, RDAP lookups) is
reused, but every collector was rewritten from scratch behind
`krisis/collectors/base.py::EvidenceCollector` so the core engine never sees
provider-specific formats, and so a collector can fail without taking the
investigation down (`CollectorResult(available=False, note=...)`, never an
exception escaping `collect()`). RECON observes; KRISIS investigates.

### Pivot engine

Not every discovered relationship is worth following (a shared nameserver
tells you almost nothing; a shared TLS certificate tells you a lot). Each
signal type has a base priority in `pivot_engine.PIVOT_RULES`, scaled by the
originating evidence's confidence and polarity, then accepted or rejected
against the investigation budget and a noisy-fan-out penalty
(`penalize_noisy_fanout`). Every rejection carries a reason string, visible via
`--show-pivots` and in the replay trace (`--show-trace`).

### Risk engine

Deterministic and separate from the LLM (`krisis/core/risk.py`). Each evidence
item's contribution is `type_weight × confidence × independence_multiplier ×
diminishing_returns_for_repeated_type`; historical pattern similarity is added
as its own contributor so a clean *current* reputation doesn't erase a strong
resemblance to previously confirmed infrastructure. The final raw score is
scaled by an evidence-diversity factor so a single-source finding cannot reach
HIGH/CRITICAL. Weights are documented in-line in `TYPE_WEIGHTS` with the
reasoning for each.

**"Not checked" is never "clean".** The engine takes a `Coverage` record of what
actually answered *about the seed artifact*, and refuses to assert a benign
verdict it didn't earn:

| Situation | Category |
|---|---|
| No evidence collected at all | `INSUFFICIENT_EVIDENCE` |
| Low score, but no reputation source was reachable | `INSUFFICIENT_EVIDENCE` |
| Supporting and contradicting evidence of comparable weight | `CONFLICTING_EVIDENCE` |
| Low score with reputation actually checked | `LOW` |

Confidence is scaled by coverage separately from the score, so risk, confidence
and pattern similarity can disagree — which is the point: *"resembles known-bad
infrastructure, but live evidence is incomplete"* is a real and reportable state.

### Commodity-infrastructure suppression

A domain "using Microsoft for mail" is a fact about Microsoft's market share,
not a lead about the domain. Left unchecked it is actively harmful: the vendor's
IPs land in indicator memory, and every later investigation touching that vendor
matches them — merging unrelated organizations into one fake cluster.

KRISIS flags such entities via two independent tests (`pivot_engine.py`):
structural (the target sits under a different registrable domain, reached via
MX/NS/CNAME — works on an empty database) and historical (the indicator already
appears across ≥3 unrelated prior artifacts — catches vendors the naming doesn't
reveal). Flagged entities are deprioritised as pivots, propagate the flag to
anything discovered through them, and are excluded from indicator memory and
pattern matching. Genuine shared hosting still matches normally.

### Pattern lifecycle

Patterns move `observed → candidate → repeated → validated → trusted`, with
`deprecated` for those that keep producing false positives. **Repetition alone
never advances past `repeated`** — only a human-confirmed outcome via
`krisis outcome` reaches `validated`. An `inconclusive` outcome deliberately
changes nothing. A historical match's weight in scoring is gated on the prior
case's outcome (`OUTCOME_TRUST` in `risk.py`): resembling a *confirmed benign*
case adds zero risk, and resembling an unvalidated one counts for very little.
Re-investigating the same artifact cannot match its own earlier run.

### Historical pattern matching (`krisis/memory/pattern_memory.py`)

Deliberately **not** a vector database. It is structured indicator-overlap
matching: every certificate/IP/domain discovered in the current investigation
is checked against `indicators` recorded from every prior case, weighted by
how distinguishing that indicator type is (certificate fingerprint match is
much stronger evidence than an IP match). This is a defensible first-pass
approximation with an explicitly documented limitation: it cannot detect
structural similarity (e.g. "same phishing kit template") without a matching
concrete indicator. See the module docstring for the full reasoning.

### AI explanation layer

Strictly downstream of the risk engine (`krisis/ai/explain.py`). Default mode
builds the explanation directly from structured case data with no model call
at all — zero hallucination risk. If `ANTHROPIC_API_KEY` is set, the same
structured findings are sent to Claude with an explicit system prompt
forbidding it from inventing or embellishing evidence; any failure falls back
to the deterministic template.

## Testing

No mocks that bypass the real path — every test drives the actual
collector -> pivot -> graph -> correlation -> risk -> explanation -> storage
chain (`tests/test_investigator_integration.py` uses fake *collectors*, not a
faked investigator). Run:

```bash
python3 -m unittest discover -s tests -v
```

27 tests covering: graph dedup/traversal, pivot budget/depth/noisy-fanout
enforcement, evidence polarity/diversity correlation, risk determinism/
counter-evidence/diminishing-returns, provider-failure handling (never
silently treated as "clean"), and — the core differentiator — historical
pattern matching that flags a domain as suspicious via shared infrastructure
even when its *current* VirusTotal reputation is clean.

## Current scope and honest limitations

This is the first working slice of the full loop described in the design
docs, not the finished system. Implemented for real, end to end:

- URL/domain/IP/hash/message investigation with real indicator extraction
- DNS, WHOIS, TLS, IP/ASN, and VirusTotal collectors (each independently optional)
- Budget-limited pivot engine with accept/reject reasoning
- Entity/relationship graph with ASCII visualization (`--show-graph`)
- Correlation engine (supporting/contradicting/infrastructure-overlap/diversity)
- Deterministic risk engine with documented weights
- SQLite case + indicator memory, with structured historical similarity matching
- Learning loop via `krisis outcome` (feeds back into future matching)
- Template-based explanation (always) + optional LLM explanation
- Advisory-only recommendation engine

Not yet implemented (explicitly out of scope for this pass, see design docs
§25 and self-critique checklist):

- Higher-level "pattern" abstraction beyond indicator-overlap matching
  (e.g. detecting "new domain + brand impersonation + credential harvesting"
  as a named recurring pattern rather than via shared concrete indicators)
- URL-scanning/redirect-chain collector and brand-impersonation heuristics
- Additional threat-intel provider adapters beyond VirusTotal
- Desktop app / browser extension (explicitly future phases per the design doc)
- Evidence-independence classification beyond the collector-declared default
  (currently each collector marks its own evidence's independence; a
  cross-provider "these two sources actually derive from the same upstream
  feed" detector does not yet exist)

## Directory layout

```
krisis/
  core/          models, graph, indicators, pivot_engine, correlation, risk, recommend, investigator
  collectors/    base interface + dns/whois/tls/ip/virustotal adapters
  memory/        sqlite storage, pattern_memory, case_memory
  ai/            explanation layer
  cli.py         click CLI
  config.py      default collector wiring, API key loading
tests/           27 tests against the real execution path
```
