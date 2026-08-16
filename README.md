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

Environment variables (`VIRUSTOTAL_API_KEY`, `NVIDIA_API_KEY`) always take
priority over the stored file. `NVIDIA_API_KEY` powers the explanation layer
only — it explains a finished investigation and never contributes to one.

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
krisis show <case_id>                             # replay a stored investigation (risk, evidence, explanation)
krisis show <case_id> --show-graph                # replay also accepts the same --show-* / --explain / --verbose flags as investigate
krisis show <case_id> --verbose                   # graph, evidence, pivots, and patterns, from storage — no network calls
krisis show <case_id> --json                      # ...as the full stored case JSON
krisis show <case_id> --pdf                       # export the stored case as a PDF case report
krisis show <case_id> --pdf --output out.pdf      # ...to a custom path (default: ./reports/<case_id>.pdf)
krisis outcome <case_id> confirmed_malicious      # close the learning loop
krisis outcome <case_id> confirmed_benign         # the only outcome that neutralises future risk
```

`outcome` accepts every state the engines model: `confirmed_malicious`,
`confirmed_benign`, `false_positive`, `false_negative`, `inconclusive`,
`unknown`. Only human-confirmed outcomes move pattern strength — `inconclusive`
and `unknown` deliberately change nothing.

Budget flags (`--max-depth`, `--max-entities`, `--max-external-calls`) prevent
graph explosion — see `krisis/core/pivot_engine.py::InvestigationBudget`.

## Architecture

```
INPUT
  -> indicator extraction        krisis/core/indicators.py
  -> evidence collection         krisis/collectors/*  (provider-agnostic, each optional)
  -> identity/lookalike analysis krisis/core/identity.py + collectors/identity_collector.py
  -> normalization                (done inside each collector -> krisis/core/models.py::Evidence)
  -> pivot generation/priority   krisis/core/pivot_engine.py
  -> provider planning/budget    krisis/core/provider_planner.py
  -> investigation queue/budget  krisis/core/investigator.py
  -> entity/relationship graph   krisis/core/graph.py
  -> pattern + case memory       krisis/memory/*  (SQLite)
  -> correlation                 krisis/core/correlation.py
  -> supporting/contradicting    (part of correlation output)
  -> risk + confidence           krisis/core/risk.py   (deterministic, no LLM)
  -> AI explanation              krisis/ai/explain.py  (template by default, optional Nemotron)
  -> recommended action          krisis/core/recommend.py
  -> case storage                krisis/memory/case_memory.py
  -> pattern/knowledge update    krisis/memory/pattern_memory.py + `krisis outcome`
  -> (on demand) replay/export   krisis/cli.py text+JSON, krisis/pdf_report.py PDF
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
| Low score, but a reputation source *flagged* the artifact | `MEDIUM` |
| Low score with reputation actually checked and clean | `LOW` |

The flagged-but-uncorroborated row exists because of a real run: `malware.wicar.org`
is flagged by VirusTotal. A single reputation hit is no longer enough to land in
the LOW band — the reputation floor (fixed in `070a9b5`) blocks that — so KRISIS
scores it `MEDIUM 11/100, confidence 62%`, with `malicious_detection (virustotal)`
as the one supporting contributor and `long_lived_domain` (the domain's multi-year
registration age) as the only counter-evidence; the `tls` source couldn't be
reached (certificate hostname mismatch) and is reported as unavailable rather than
folded into "clean". A reputation source is a direct determination about the
artifact rather than circumstantial evidence, so a single flagged hit is barred
from ever reading as LOW, with the qualification stated in the output and carried
into the recommended action.

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

The same rule covers WHOIS registration contacts. `github.com` and `google.com`
both publish `abusecomplaints@markmonitor.com` — their registrar's role mailbox,
attached to every domain it sells. Because indicator memory weights `email` at
0.4 (second only to certificates), treating it as distinguishing reported those
two as a 44% infrastructure overlap. A registration contact is therefore flagged
commodity when its domain matches the registrar's own domain, derived at runtime
from the `registrar_url` / `whois_server` fields in the same WHOIS record.

The test is deliberately narrow: a registrant address anywhere *else* keeps full
pivot priority, because one mailbox reused across several suspicious
registrations is among the strongest links WHOIS can provide. Both directions
are mutation-tested in `tests/test_commodity_infrastructure.py`.

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

Deliberately **not** a vector database. Two independent dimensions are computed
and reported separately, then combined:

**Indicator similarity** — *"have I seen these exact values before?"* Every
certificate/IP/domain discovered in the current investigation is checked against
`indicators` recorded from prior cases, weighted by how distinguishing that type
is (a certificate fingerprint is much stronger than an IP). Strong when it fires,
but blind to an adversary who rotates infrastructure. A fired match is further
split into two readings, never collapsed into one: `exact_artifact` — the shared
value was itself the prior case's own seed, i.e. this is the very same artifact
investigated before — versus `infrastructure` — the prior case only pivoted to
that value (a shared cert, a shared IP), a weaker claim. `historical_match_label()`
is the one place every renderer (CLI, replay, JSON, AI template) gets this
phrasing from, so the distinction can't drift out of sync between surfaces.

**Structural similarity** — *"have I seen this **kind** of investigation before?"*
Each case also stores a signature of its **shape**, with every concrete value
stripped out: which signals argued for a threat, which argued against, which
relationship types were followed, which classes of entity the pivots reached.
Concrete values are deliberately absent, which is exactly what lets the match
survive indicator rotation. Facets are weighted by inverse document frequency
computed over stored cases *at query time*, so structure common to all
investigations ("it resolves to an IP") contributes almost nothing while a rare
co-occurrence dominates — the same principle as commodity-infrastructure
suppression, applied to structure instead of values, and derived from the corpus
rather than declared in a list. Neutral observations, the seed's own type, and
anything commodity are excluded from the signature.

```
Historical Pattern Matches
───────────────────────────
  structurally similar new artifact, no shared indicator — overall 64%  (indicator 0% / structural 100%)  structural pattern 'valid_tls_present + long_lived_domain'
      prior_outcome=confirmed_malicious  pattern_stage=validated
      shared structure:  entity:certificate, entity:ip, rel:resolves_to, ...
```

That output is a real run: a domain sharing **no** IP, certificate, or nameserver
with any stored case, recognised through its structure alone.

A shape is far cheaper to coincide with than a certificate fingerprint, so
structural resemblance is discounted against indicator overlap and scaled by the
matched pattern's lifecycle stage before the two are combined. A shape seen once
has almost no influence however perfectly it matches; only repeated, human-
validated shapes reach full weight, and a `deprecated` one reaches zero. The
match that feeds the score is the one with the most *impact* — resemblance ×
outcome trust — not the one that merely resembles hardest, so a strong benign
match cannot shadow a weaker match to a confirmed-malicious case.

### Provider budgeting (`krisis/core/provider_planner.py`)

Written in response to a real run. Two seeds fanned out into a dozen discovered
entities, every collector ran against every one of them, and fourteen VirusTotal
requests later the provider's rate limit answered for KRISIS. Discovering a quota
by exhausting it is not budgeting.

The planner now sits between pivot discovery and provider execution, and answers
in order:

```
already asked this provider this exact question?     -> reuse, no request
answered recently enough to still be true?           -> cache, no request
is this entity worth a scarce request at all?        -> value gate
inside the rate limit and the daily quota?           -> defer or skip
did the provider just say back off?                  -> honour it
```

The value gate is the part that mattered most: a scarce provider is spent on the
seed — the thing the user actually asked about — and otherwise only on a pivot
strong enough *and* load-bearing for the threat hypothesis. A discovered
subdomain no longer buys itself a reputation lookup. Measured on the same two
targets that motivated this:

```
before   14 VirusTotal requests from 2 seeds, ending in a rate limit
after     1 VirusTotal request per seed, 0 rate limits
          re-running the same target: 0 requests, entirely from cache
```

Policy is configuration, never intelligence: request rates, daily quotas, cache
lifetimes and the value threshold live in `config.provider_policies()` and are
env-overridable (`KRISIS_VT_RATE_PER_MIN`, `KRISIS_VT_DAILY_QUOTA`,
`KRISIS_VT_CACHE_TTL`, `KRISIS_VT_MIN_PIVOT_PRIORITY`, `KRISIS_CACHE_TTL`).
Defaults match VirusTotal's free tier: 4 requests/minute, 500/day.

Two rules hold the line on honesty. A request KRISIS declined to spend still
returns `available=False` with the reason, so "not asked" can never silently
become "nothing found" — but it is recorded and reported separately from a
genuine collector failure: a deliberate skip lands in `case.provider_skips`
(printed as `[i] N provider request(s) deliberately skipped`), while an actual
outage or error lands in `case.provider_failures` (`[!] N evidence source(s)
unavailable`). A scarce-budget rule working as designed must never read as a
broken evidence source. And a cached answer travels as evidence stamped
`freshness=cached` with its age and original fetch time, so it cannot be read
as current intelligence. Every decision appears in `--show-trace`, and the
per-provider ledger prints on every run:

```
Provider Usage
───────────────
  dns            calls 0  cached 9  reused 9
  virustotal     calls 0  cached 1  skipped 4
      not spent: discovered entity below the value threshold for a scarce provider
                 (pivot priority 0.53 < 0.70, and no evidence here supports the
                 threat hypothesis)
```

### Identity intelligence (`krisis/core/identity.py`)

The same live run scored `paypa1.com` as LOW / 0. KRISIS had investigated the
infrastructure around the name and never looked at the name itself — and for
consumer fraud, the name usually *is* the attack.

Identity analysis derives candidate identities an artifact may be imitating by
three general mechanisms, with no brand list anywhere:

- **confusable characters** — glyphs chosen to be misread (`1` for `l`, Cyrillic
  `а` for `a`, `rn` for `m`), plus punycode/IDN decoding. The mapping is strictly
  one-directional, deceptive glyph -> the character it imitates, which is what
  keeps a legitimate name from being accused of imitating a variant of itself.
  Ambiguous glyphs keep every reading: `1` passes for both `l` and `i`, so
  `netfl1x` is read as `netflix` as well as `netfllx`, and each reading is
  verified separately.
- **decoration tokens** — `<name>-login`, `secure-<name>`. The lexicon describes
  how phishing hostnames are *built*, not who is impersonated, and is extendable
  with `KRISIS_DECORATION_TOKENS`. Without a decoration word present,
  `my-company.com` is just a hostname, not an impersonation of `company.com`.
- **reference similarity** — near-identical labels against identities KRISIS
  already knows: domains it has investigated before, plus anything in
  `~/.krisis/identity_references.txt` (`KRISIS_IDENTITY_REFERENCES`).

A derived candidate is a string observation, not a finding. Before KRISIS calls
it evidence, three things must be verified against the world with cheap DNS and
WHOIS lookups routed through the planner:

```
the referent resolves            -> else there is nothing to impersonate
it is established and older      -> else the direction of imitation is unknown
a different party operates it    -> else this is a defensive registration
```

That third check is not a formality. Investigating `paypa1.com` live, KRISIS
derived `paypal.com`, then found both registered to `PayPal Inc.` — a defensive
registration by the brand itself. The result is reported as *counter*-evidence,
and the verdict stays LOW for a stated reason rather than by omission.

When the checks pass, the relationship becomes evidence *and* a `looks_like`
edge in the graph, so identity and infrastructure can reinforce each other. A
verified impersonation also cannot be reported as LOW however unremarkable its
hosting is (`risk.py::_categorize`), and a valid certificate does not offset it:
a certificate proves control of an endpoint, not that its operator is the
organization the name resembles.

Live, `1inkedin.com` scores MEDIUM 39/100 with `lookalike_domain` as its top
contributor, while `paypal.com` and `linkedin.com` produce no identity finding
at all from the same mechanism.

**`.bank.in` namespace context.** India's RBI reserves `.bank.in` as a
restricted second-level namespace for regulated banks and directs banks to
migrate to it specifically to cut digital-payment phishing. `registrable_domain`
(`krisis/core/indicators.py`) treats `bank.in` as a public-suffix-style
namespace exactly like `co.in`, so `hdfc.bank.in` and `sbi.bank.in` register as
two organizations rather than collapsing to the shared suffix. `IdentityCollector`
then emits `verified_bank_namespace` as ordinary `CONTRADICTS_THREAT` identity
evidence for an exact registrable match — never for a substring or subdomain
trick (`hdfcbank.in`, `hdfc.bank.in.attacker.com`) and never for the bare
namespace root (`bank.in`). It is real, risk-engine-weighted counter-evidence,
not a safe override: a genuine impersonation + credential-form finding on a
`.bank.in` domain still out-scores it (see `TestBankNamespaceSignal` in
`tests/test_identity.py` and `TestBankInNamespace` in
`tests/test_commodity_infrastructure.py`, both mutation-tested). Institution
identity (does *this* `.bank.in` domain actually match the brand a page
claims?) needs no bank-specific code at all — it falls out of the existing,
generic `brand_domain_mismatch` check in `page_collector.py` once
`registrable_domain` parses the suffix correctly.

### AI explanation layer

Strictly downstream of the risk engine (`krisis/ai/explain.py`). Default mode
builds the explanation directly from structured case data with no model call
at all — zero hallucination risk. If `NVIDIA_API_KEY` is set, the same
structured findings are sent to `nvidia/nemotron-3-super-120b-a12b` (override
with `KRISIS_AI_MODEL`, endpoint with `KRISIS_AI_BASE_URL`) with a system prompt
forbidding it from inventing evidence, disputing the score, or claiming a source
was consulted; it answers as JSON (`summary`, `key_findings`, `uncertainties`,
`recommended_actions`) and any failure falls back to the deterministic template.

What it receives is a *summary* of the finished investigation — risk, the
evidence that carried weight, counter-evidence, historical matches, uncertainty,
provider usage — never the raw graph. A large context window is headroom, not a
reason to make the model do the investigator's reading.

    KRISIS investigates. The model translates.

## Testing

No mocks that bypass the real path — every test drives the actual
collector -> pivot -> graph -> correlation -> risk -> explanation -> storage
chain (`tests/test_investigator_integration.py` uses fake *collectors*, not a
faked investigator). Run:

```bash
python3 -m unittest discover -s tests -v
```

286 tests covering: graph dedup/traversal, pivot budget/depth/noisy-fanout
enforcement, evidence polarity/diversity correlation, risk determinism/
counter-evidence/diminishing-returns, provider-failure handling (never
silently treated as "clean", and never conflated with a deliberate planner
skip), provider-payload normalization, provider
budgeting (dedup, cache, TTL, rate limit, daily quota, backoff, value gate),
identity derivation and verification, and — the core differentiator —
historical pattern matching that recognises a domain through shared
infrastructure *or* through case structure alone, even when its current
VirusTotal reputation is clean.

The count is not the point; **wrong-conclusion coverage** is. Every security
rule is mutation-tested: deleting the rule from the source must make a specific
named test fail. Currently verified this way — commodity entities and their
edges entering a signature, the seed's own type entering a signature, neutral
evidence entering a signature, self-match exclusion, the structural similarity
floor, one-facet "shapes", IDF weighting, structural resemblance being treated
as strong as a shared certificate, a first sighting or unvalidated repetition
being fully trusted, a discredited shape retaining influence, a benign prior
outcome raising risk, ranking matches by similarity instead of impact, a
flagged artifact being called LOW, that rule firing on non-reputation evidence,
the qualification being dropped from the advice, and the VirusTotal denominator
regressing to the URL count.

Added with provider budgeting and identity intelligence, each verified the same
way — delete the rule, watch the named test fail: provider deduplication, the
cross-run cache, stale cache being reused as fresh, cached evidence losing its
`cached` stamp, the rate limiter, the daily quota, rate-limit backoff, the value
gate, a skipped request reporting as available, one-directional glyph mapping,
dropping the secondary reading of an ambiguous glyph, the decoration-lexicon
test, the referent-resolves check, the age-margin check, same-operator
suppression, the identity risk floor, valid TLS offsetting an identity finding,
the `looks_like` pivot rule, and an impersonated identity being dismissed as
commodity infrastructure because it appears in many prior cases.

## Current scope and honest limitations

This is the first working slice of the full loop described in the design
docs, not the finished system. Implemented for real, end to end:

- URL/domain/IP/hash/message investigation with real indicator extraction
- DNS, WHOIS, TLS, IP/ASN, and VirusTotal collectors (each independently optional)
- Budget-limited pivot engine with accept/reject reasoning
- Provider planner: per-provider policy, cross-run response cache, in-run
  deduplication, sliding-window rate limiting, daily quota, rate-limit backoff,
  and a value gate that reserves scarce providers for leads worth them
- Identity analysis: confusable/homoglyph/IDN and decoration-token derivation,
  verified against resolution, registration age and operator before it becomes
  evidence, and entering the graph as a `looks_like` edge
- Entity/relationship graph with ASCII visualization (`--show-graph`)
- Correlation engine (supporting/contradicting/infrastructure-overlap/diversity)
- Deterministic risk engine with documented weights
- SQLite case + indicator memory, with historical matching on both concrete
  indicators and case structure
- Learning loop via `krisis outcome` (feeds back into future matching)
- Template-based explanation (always) + optional Nemotron explanation over an
  OpenAI-compatible endpoint, receiving a summary rather than the raw case
- Advisory-only recommendation engine
- PDF case report export (`krisis show <case_id> --pdf`): a third renderer
  over the same stored case the CLI text and `--json` renderers use — cover
  page, evidence tables, provider usage, investigation graph (real node-link
  diagram via matplotlib, text-tree fallback if unavailable), historical
  memory, risk/recommendation/explanation. Reads stored case state only —
  zero network calls, zero mutation

Not yet implemented (explicitly out of scope for this pass, see design docs
§25 and self-critique checklist):

- URL-scanning/redirect-chain collector. Identity evidence now enters structural
  signatures automatically, so the "brand impersonation + credential harvesting"
  shape is half observable — the impersonation half. Nothing yet observes the
  credential-harvesting half, because no collector fetches the page
- Referent *legitimacy*. The identity layer verifies that a referent is
  established, resolving and separately operated; it cannot tell a legitimate
  brand from an older squatter, so `1inkedin.com` is reported as resembling both
  `linkedin.com` and `iinkedin.com`. Both statements are true; only one is
  interesting. Populating `identity_references.txt` is the current answer
- Registrant organisations are compared as plain strings, so `PayPal Inc.` and
  `PayPal, Inc` read as different owners. The failure direction is a retained
  finding rather than a suppressed one
- Temporal shape (burst timing, ordering of first-seen events) as a signature
  dimension; the timestamps are stored, but the signature does not read them yet
- Cases stored before structural matching existed contribute indicators only.
  There is no backfill: their shape is recorded the next time they are
  investigated
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
  pdf_report.py  PDF case report renderer (stored case -> PDF, no network)
tests/           286 tests against the real execution path, mutation-verified
```
