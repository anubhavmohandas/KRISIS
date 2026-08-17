# KRISIS Phishing-Intelligence Completeness Matrix

Final capability-completeness audit. Written against the real code as it
stands after the SPF/DMARC addition documented in
`docs/PHISHING_SIGNAL_MATRIX.md` (349 pytest / 348 `unittest discover` / 15
validation cases, all green — verified live at the start of this pass, not
assumed from a prior count).

This document does not re-derive the signal-by-signal audit —
`PHISHING_SIGNAL_MATRIX.md` already did that, function-cited, and remains
the source of truth for "does signal X exist." This document answers a
different question: **of everything that audit correctly left deferred, what
(if anything) is actually required to call KRISIS done**, using concrete
investigation scenarios rather than an abstract feature wishlist.

---

## 1. Scenario audit — what can KRISIS currently explain?

For each scenario: can KRISIS observe enough evidence today? If not, exactly
which capability closes the gap, and is that capability buildable within
KRISIS's current input types (P0/P1) or does it require a new provider/UI
(P2/P3)?

### A. Brand impersonation through a lookalike domain (`paypa1.com`)

**Yes.** `identity.py::candidates()` (confusable-char + decoration-token
mechanisms) → `identity_collector.py::_verdict()` verifies the referent
resolves, is an established domain (≥730 days), and is registered by a
different, non-shared operator before emitting `lookalike_domain`
(`SUPPORTS_THREAT`). `risk.py`'s LOW-band impersonation floor
(`VERIFIED_REFERENT_SIGNALS`) additionally guarantees this can never render
as "looks safe" regardless of how clean the surrounding infrastructure is.
Validation cases B/B2/C/D/E cover this end to end.

### B. Brand impersonation via `brand.attacker-domain.example`

**Yes**, as of the prior pass's brand-in-subdomain work.
`identity.py::candidates()` mechanism 3 was extended with
`_subdomain_labels()` so a known brand token placed anywhere in the
subdomain chain (not just the registrable label) is derived as a candidate
and run through the same verification pipeline as scenario A — it fires
`lookalike_domain` exactly the same way, so it inherits the same LOW-band
floor and interaction-bonus behavior automatically. Requires the brand
already exist as a known referent (case memory or `identity_references.txt`)
— a bare subdomain label has no suffix of its own to independently verify
against, which is a correct limitation, not a gap: nothing can tell
`brand.attacker-domain.example` "resembles brand.com" without already
knowing brand.com is a thing worth resembling.

### C. Phishing page hosted on a completely unrelated domain (no lookalike name at all)

**Partially — and this is the one scenario worth being precise about.**
If the page itself claims to be the brand (title/H1/`og:site_name` says
"PayPal" while the domain is `totally-unrelated-host.example`),
`page_collector.py::_brand_mismatch_evidence()` fires `brand_domain_mismatch`
(neutral alone, `SUPPORTS_THREAT` combined with a credential form via the
existing `INTERACTION_IMPERSONATION_SIGNALS` rule) — this is a genuinely
different, complementary detection path from the identity/lookalike-name
one: it catches impersonation via **claimed content**, not domain-name
resemblance, so it is exactly the case a pure lookalike-domain detector
would miss. Demonstrated live in scenario analysis below.

What KRISIS **cannot** currently do: recognize a cloned page that copies a
real brand's *visual design/DOM structure* without also stating the brand's
name anywhere in the title/H1/`og:site_name`/`<meta>` KRISIS reads. A page
that visually is an exact pixel-for-pixel clone of a bank's login page but
titles itself "Secure Portal" and never writes the bank's name into parsed
text would produce no `brand_domain_mismatch` finding. This is the real
edge of deterministic page-content analysis — see §2 (visual similarity
decision gate) below for whether that gap is worth closing.

### D. Cloned login page with credential collection

**Yes.** `_credential_evidence()` detects password/credential-hint/payment
fields per-form (`_FormState`), and combined with `brand_domain_mismatch`
or `lookalike_domain` triggers `INTERACTION_BONUS_POINTS` (14 pts) via
`INTERACTION_IMPERSONATION_SIGNALS × INTERACTION_CREDENTIAL_SIGNALS` — the
combination scores materially higher than either alone, which is the
actual credential-phishing pattern, not two coincidental facts. Validation
case D covers this.

### E. Credential form posting to another domain

**Yes.** `_credential_evidence()` compares the form's `action` attribute's
host against the page's own host; a cross-domain action target fires
`external_form_action` independently of whether the form has a password
field, and independently reinforces the same interaction rule as D.

### F. Malware delivery from a deceptive URL

**Yes**, as of the prior pass. `url_intent.py::is_ip_literal_host()` /
`has_userinfo()` (wired via `page_collector._structure_evidence()`) plus
`_download_evidence()` (executable/script extension on an `<a href>`) feed
`INTERACTION_SUSPICIOUS_URL_SIGNALS × INTERACTION_DOWNLOAD_SIGNALS` — a
second, independent interaction rule (`INTERACTION_MALWARE_BONUS_POINTS`,
14 pts) specifically because this is a materially different hypothesis than
credential phishing and shares no signal names with the first rule.
Validation case M proves three co-occurring signals (deceptive shape ×2 +
fresh registration) are needed to cross into MEDIUM — the bonus lifts a
real combination, it does not manufacture a floor from a single signal.

### G. Redirect-based phishing chain

**Yes.** `safe_fetch()` walks and records every hop (`redirect_chain`
evidence), `_redirect_evidence()` flags cross-domain landings, loop
detection and `MAX_REDIRECTS=5` bound the walk, and
`_meta_refresh_evidence()` (prior pass) extends the same coverage to
`<meta http-equiv="refresh">` redirects an HTTP-only walk would miss
entirely — with a `pivot_engine.PIVOT_RULES` entry so the redirect target
enters the graph the same way an HTTP redirect target does.

### H. Message containing a suspicious URL

**Yes.** `MESSAGE` seed type (`indicators.classify_seed()`) mines URLs via
`extract_from_text()`; every extracted URL/domain is re-investigated as its
own child entity through the full collector pipeline (scenarios A-G all
apply to it), while `message_signals.py` separately scores the message text
itself for urgency/credential-request/financial-lure/call-to-action
phrasing.

### I. Email where sender identity and link identity disagree

**Yes, at the text-mention level; no, at the verified-header level — and
that distinction is the correct one to draw, not a gap.**
`message_collector.py::_sender_url_mismatch_evidence()` (prior pass) fires
`sender_url_domain_mismatch` when every email address mentioned in the
message body and every URL/domain mentioned sit under fully disjoint
registrable domains. What it explicitly cannot do — and must not fake — is
compare a message's actual `From:`/`Reply-To:` **headers** against its
links, because KRISIS has no `.eml`/MIME ingestion path (`indicators.py`'s
only message input is raw free text). A `From:` header a user did not paste
into the message body is not observable; synthesizing one would be
inventing evidence, exactly what the design forbids. See §3 (email/MIME)
below for whether this input-type gap is worth closing.

### J. Legitimate brand-owned defensive/lookalike registration

**Handled correctly, with a stated limitation.** `same_operator()`
(verified shared resolved address) correctly suppresses `lookalike_domain`
in favor of `same_operator_variant` (`CONTRADICTS_THREAT`) when the
"lookalike" and the real brand actually share infrastructure — this is
mutually exclusive by construction in `identity_collector._verdict()`, not
a second rule bolted on. What KRISIS cannot do: distinguish a brand's *own*
defensive registration that does **not** share infrastructure (a common
real pattern — many companies park lookalikes on unrelated
registrar/hosting for the express purpose of not pointing traffic
anywhere) from an actual squatter's lookalike. This is the documented
"referent legitimacy" gap (README's own `1inkedin.com` example) — solvable
only by a curated brand-ownership registry, which is exactly what
`identity_references.txt` already exists to be populated with. Not a code
gap; a data-population task, correctly left to the operator per README §
"Current scope and honest limitations."

### K. Historical infrastructure reuse

**Yes.** `pattern_memory.py` matches on exact indicator value
(`exact_artifact` vs `infrastructure` distinction), with commodity
infrastructure (shared CDN/cloud/registrar/nameserver) excluded from
matching so shared-vendor coincidence is never read as shared ownership
(`pivot_engine.py` commodity-suppression, structurally and historically
tested).

### L. Historical structural similarity with no shared infrastructure

**Yes.** `structural_facets()` (IDF-weighted shape signature) matches on
the *shape* of an investigation — evidence-type combination, identity
pattern, behavior pattern — independent of any concrete shared indicator.
`historical_match_label()` is the single place every caller must go through
to phrase this correctly, specifically so "exact artifact seen before,"
"shares infrastructure with a prior case," and "structurally resembles a
prior case, no shared indicator" never get conflated into one generic
"historical similarity: N%" — see `risk.py`'s docstring for why collapsing
these three claims into one was treated as a real bug class, not a wording
nitpick.

### M. Benign legitimate login page

**Yes.** No identity/credential/redirect/download finding fires; with
`INSUFFICIENT_EVIDENCE` reserved for when no reputation source actually
answered (`Coverage.has_reputation_source()`), and LOW only assertable when
enough of the evidence base actually did answer
(`LOW_CONFIDENCE_THRESHOLD`). Live-verified this pass: `stripe.com`
investigated end to end → `LOW`/`0` with SPF/DMARC posture, TLS
subject-org match (discounted via `NARROW_CONTRADICTIONS`, not double
counted), and clean VirusTotal all correctly contributing zero threat
points rather than a fabricated "safe" claim from silence.

### N. Artifact with incomplete provider coverage

**Yes — this is the scenario the coverage/uncertainty layer exists for.**
`Coverage.failed` (`attempted - available`) surfaces in
`RiskAssessment.uncertainty["unavailable_sources"]`; a missing reputation
source specifically blocks a LOW verdict
(`_categorize`'s `has_reputation_source()` check) rather than letting
"nobody looked" render as "nothing found." `provider_skips` vs
`provider_failures` are kept distinct in the case record (a deliberate
planner decision is not a provider malfunction) and both surface in
`--json`/PDF. Mutation-tested in the CLI v1 acceptance pass; unchanged and
re-verified live this pass (`github.com`: real VirusTotal call + recorded
value-gate skips, all itemized).

**Scenario audit conclusion:** every scenario the master loop names is
either fully covered today, or covered at exactly the layer honest evidence
allows (text-mention-level, not fabricated-header-level; content-claim
mismatch, not pixel-similarity). The two genuine edges are C's visual-clone
tail and I's header-verified tail — both addressed explicitly below rather
than hand-waved.

---

## 2. Visual / page-identity — decision gate

**The concrete test (per the master loop's own framing):** can a domain
with no strong reputation, no obvious typo, no infrastructure overlap, and
an unrelated hostname still present a cloned login page that KRISIS
currently classifies correctly?

**Answer: partially, and the failure mode is narrow and named, not silent.**

If the cloned page's parsed text (title/H1/`og:site_name`) states the
brand's name — the overwhelmingly common case, because a credential-phishing
page needs the victim to *believe* it's the real brand, which means writing
the brand's name somewhere the victim reads it — `brand_domain_mismatch`
fires and, combined with the credential form every such page has by
definition, crosses into the scored interaction bonus. This is
deterministic DOM/content identity, and it already closes the large
majority of this scenario class.

The genuine remaining gap: a page that is pixel-identical to a real login
page but never writes the brand's name into parsed text (an image-only
logo with no `alt`/`og:site_name`, generic chrome like "Secure Portal").
KRISIS reports this today as behaviorally suspicious (credential form,
possibly `external_form_action`) but does **not** report brand
impersonation for it, because it has no basis to know *which* brand is
being cloned without either a name to compare or a visual reference.

**Decision: do not build visual/screenshot similarity in this loop.**
Reasoning, following the master loop's own gate:

1. It requires a new evidence source with a genuinely different
   provenance/trust shape than everything else in KRISIS — a reference
   image/DOM corpus KRISIS does not have and a comparison model whose
   output is a similarity float, not a fact. That is real new
   architecture (fetch → render/screenshot → embed → compare → evidence),
   not an extension of an existing collector.
2. It is provider/infrastructure-dependent in a way nothing else in KRISIS
   is: it needs either a headless-browser render pipeline or a hosted
   screenshot/vision API, plus a maintained reference-brand corpus to
   compare against — the same "referent legitimacy" data-population
   problem scenario J already has, compounded by needing *images* instead
   of a text file.
3. The gap it closes is real but narrow: pages that clone visual design
   while deliberately avoiding writing the brand's name in parsed text.
   This is a smaller, more sophisticated subset of scenario C than "any
   unrelated-domain phishing page," which is already substantially caught.
4. It cannot be added safely as a scored signal without exactly the
   architecture the master loop itself demands (provenance, confidence,
   availability, independence, AI never assigning the verdict directly) —
   building it partially, without that discipline, would be worse than not
   building it.

**Classification: HIGH_VALUE_OPTIONAL, not REQUIRED_FOR_END_GOAL.** If
built in a future pass, the correct shape is exactly what the master loop
specifies: a separate evidence source (`page_visual` or similar) emitting
`SUPPORTS_THREAT`/neutral evidence with a similarity score and named
reference, entering `risk.py` through the same polarity/confidence/
independence path every other signal does — never a direct verdict, and
never allowed to bypass `NARROW_CONTRADICTIONS`-style discounting the way
a merely-obtained (not verified-safe) credential could.

---

## 3. Email/MIME structured input — decision gate

**Current state:** the CLI's only message input is raw free text
(`MESSAGE` seed type / `--file`). `sender_url_domain_mismatch` already
extracts what free text honestly contains. No header model exists, and
building one with no caller that could ever populate it (no `.eml`
ingestion path in `cli.py`) would be dead code — exactly what the master
loop's own architecture discipline prohibits.

**Decision: do not build in this loop.** This remains correctly classified
`FUTURE_UI`: it requires a new CLI capability
(`krisis investigate mail.eml --eml` or equivalent) before any of
From/Reply-To/display-name mismatch, SPF/DKIM/DMARC *alignment* (as
opposed to the domain-level *presence* now implemented), or attachment
metadata can be real evidence rather than fabricated structure. This is
unchanged from the prior pass's assessment — re-confirmed here because the
master loop specifically asked this loop to re-examine it, not because new
information changed the answer.

**What this loop's SPF/DMARC work does *not* claim to solve:** presence/
absence of a domain-level SPF/DMARC policy is orthogonal to header
alignment. A domain can publish a perfect DMARC `p=reject` policy and still
be the domain a phishing email's `Reply-To:` impersonates — presence says
nothing about a specific message. This is stated explicitly in
`dns_collector.py::_dmarc_evidence()`'s docstring and in the signal matrix,
specifically so a future reader does not assume more coverage than exists.

---

## 4. Completeness table — every remaining deferred capability

Columns per the master loop's template. "Decision" uses the master loop's
own five-way final classification (§6 below defines each).

| Capability | Current status | Why it matters | Real detection gap it closes | Required evidence source | Required architecture | Priority | Decision | Validation plan |
|---|---|---|---|---|---|---|---|---|
| Visual/screenshot page similarity | NOT IMPLEMENTED | Catches a cloned page that never names the brand in parsed text | Narrow tail of scenario C (see §2) | Headless render or screenshot API + reference-brand image corpus | New evidence source: fetch→render→embed→compare→evidence, never a direct verdict | P2 | HIGH_VALUE_OPTIONAL | If built: similarity score + reference name as evidence, mutation-test that it cannot override `NARROW_CONTRADICTIONS`-style safe evidence, validation cases needing a name-free clone |
| Structured email/MIME (.eml) input | NOT IMPLEMENTED | From/Reply-To mismatch, DMARC *alignment*, attachment metadata all need real headers | Scenario I's header-verified tail | `.eml`/MIME parser + new CLI subcommand/flag | New input type (`classify_seed` extension), new collector | P2 | FUTURE_UI | Once built: header-mismatch validation cases parallel to existing `sender_url_domain_mismatch` case |
| Bare email address as its own seed (mailbox reputation) | NOT IMPLEMENTED | Investigate an email address directly, not just as a mined indicator | Narrow — most email intel is domain-level, already covered via MX/SPF/DMARC on the domain part | A collector that `supports=("email",)` | New collector | P2 | FUTURE_UI | N/A until built |
| DKIM | NOT IMPLEMENTED | Selector-specific, unknowable without a message's headers | Same root cause as email/MIME above | Structured email input | Same as email/MIME | P2 | FUTURE_UI | Bundled with email/MIME work |
| Mail-provider alignment (MX vs claimed sender domain) | NOT IMPLEMENTED | Weak signal even with headers | No current input type carries a "claimed sender domain" distinct from MX | Structured email input | Same as email/MIME | P2 | FUTURE_UI | Bundled with email/MIME work |
| Suspicious multi-query DNS config (wildcard, fast-flux) | NOT IMPLEMENTED | Needs repeated resolution over time | KRISIS's single-shot investigation model has no temporal sampling | A scheduler/repeated-query subsystem | New architecture (temporal sampling), not a signal add | P2 | FUTURE_UI | N/A until temporal sampling exists |
| Additional reputation providers (Safe Browsing, PhishTank, URLhaus, urlscan, AbuseIPDB, Shodan) | NOT IMPLEMENTED | Redundant coverage / independent corroboration | KRISIS currently has exactly one reputation source (VirusTotal); a single-source flag has no cross-corroboration | Each is a distinct external API + credential | New provider adapters, one at a time, provider-planner-integrated | P2 | FUTURE_PROVIDER | Per-provider: does it change a verdict VT alone would get wrong? Needs real comparative cases before adding, not added speculatively |
| Repeated/inserted-char + transposition lookalikes | NOT IMPLEMENTED | Marginal recall gain over `label_similarity` | `SequenceMatcher` ratio already catches most high-similarity cases | None — needs an edit-distance model | New identity mechanism | P3 | LOW_VALUE_DEFERRED | Only if a real missed case surfaces |
| Zero-width Unicode | NOT IMPLEMENTED | Rare; most registries reject it in labels | No known live case | None | Small addition to `identity.py`'s script/char handling | P3 | LOW_VALUE_DEFERRED | Revisit if a real case surfaces |
| URL length / query-encoding anomalies, subdomain depth, suspicious ports, mixed encoding | NOT IMPLEMENTED | Common in some heuristic scanners | Every fixed threshold here is an arbitrary, uncalibrated cutoff | None | Would need real-case calibration first | P3 | LOW_VALUE_DEFERRED | Do not add without a calibration dataset — this is the exact "arbitrary threshold" trap the loop's own §5/§14 warns against |
| Suspicious-TLD list | NOT IMPLEMENTED | Common in commercial scanners | Needs a maintained reputation-style list KRISIS doesn't ship, and ccTLD abuse rates drift | A curated, maintained TLD list | New maintained data asset | P3 | LOW_VALUE_DEFERRED | N/A |
| Disposable-mail-provider list | NOT IMPLEMENTED | Same shape as TLD list | Same | Curated list | Same | P3 | LOW_VALUE_DEFERRED | N/A |
| Shortener-service list | NOT IMPLEMENTED | Redirect behavior is already fully evidenced regardless of origin | The underlying fact (redirect, cross-domain landing) is already captured; a shortener label adds no new risk-relevant fact | Curated list | Same | P3 | LOW_VALUE_DEFERRED | N/A |
| Favicon / logo hash intelligence | NOT IMPLEMENTED | Meaningful only against a reference database KRISIS lacks | Same "referent legitimacy" gap as scenario J, for images instead of names | Reference favicon-hash DB | New evidence source + reference corpus | P3 | LOW_VALUE_DEFERRED (subset of visual-similarity gate, §2) | Reconsider only alongside visual similarity, not standalone |
| Iframe target / external-resource enumeration | NOT IMPLEMENTED | Near-universal on legitimate sites (CDNs, embeds, analytics) | No curated allowlist exists to separate commodity from suspicious — same trap infrastructure-relationship reasoning already guards against | Curated allowlist or render-level inspection | New parser + curated data | P3 | LOW_VALUE_DEFERRED | N/A |
| JS redirect / static script analysis | NOT IMPLEMENTED | Regex-only detection over unstructured JS is an uncalibrated heuristic | `<meta refresh>` and HTTP redirects already cover the deterministic redirect surface | A JS parser or heavily-caveated regex | New parser | P3 | LOW_VALUE_DEFERRED | Revisit only with a real JS-redirect-only case that HTTP/meta-refresh both miss |
| TLS hostname-mismatch as scored evidence | PARTIAL (reported as `unavailable`, not scored) | Currently correctly modeled as a coverage gap, not silently "clean" | Re-litigating this changes tested, working behavior for a case (`malware.wicar.org`) the README already documents honestly | None new | Would need to change an existing collector contract | P3 | LOW_VALUE_DEFERRED | Do not touch without a concrete case this specifically fails on |
| SAN / wildcard cert detection | NOT IMPLEMENTED | `ssl.wrap_socket(server_hostname=...)` already fails closed on real hostname mismatch | No question SAN parsing answers that the existing connection-success check doesn't | None new | Parse existing `getpeercert()` dict | P3 | LOW_VALUE_DEFERRED | N/A |
| Certificate validity period / issuer CA tier | NOT IMPLEMENTED | Free-CA-only signal is weak without subject-org contrast (already implemented) | Low incremental value | None new | Parse existing cert dict | P3 | LOW_VALUE_DEFERRED | N/A |
| Registrant metadata beyond org (WHOIS email etc.) | PARTIAL | Email only surfaced as pivot target | No concrete failure case motivates comparing it for identity | None new | Extend `identity_collector.py` comparison | P3 | LOW_VALUE_DEFERRED | Revisit if a real case needs it |
| Cross-provider evidence-independence classification | NOT IMPLEMENTED | Each collector currently self-declares independence | No known case where two sources silently share an upstream feed today (single reputation provider) | None yet | Would need ≥2 reputation providers first to matter | P3 | LOW_VALUE_DEFERRED | Reconsider once a second reputation provider exists |

---

## 5. False-positive / false-negative check on this loop's own addition

Per the master loop's §20 rule ("correct verdict + wrong reason = FAIL"):
SPF/DMARC evidence is `NEUTRAL` in every state and is excluded from
`RiskEngine._weighted_points()` (only `supporting`/`contradicting` evidence
is scored — see `correlation.py::correlate()`'s three-way bucketing). It
therefore cannot change a score, category, or confidence value by
construction, which was verified rather than assumed: the validation matrix
(15/15) and full risk-engine test suite are unchanged before/after this
addition. `TestNeverAutomaticThreat` in `tests/test_dns_collector.py` locks
this — it iterates every SPF/DMARC state (missing/present/malformed, both
signals) and asserts `polarity == "neutral"`, so a future change that
accidentally makes absence or presence start moving the score fails a named
test immediately, the same discipline a mutation test would provide for a
decision rule.

---

## 6. Final decision gate

Per the master loop's required five-way classification:

**REQUIRED_FOR_END_GOAL** (must exist for KRISIS to fulfill its stated
purpose): none remaining. Every scenario in §1 has sufficient evidence
coverage at the layer honest evidence allows; nothing on the completeness
table in §4 blocks KRISIS from investigating and explaining the phishing/
impersonation scenarios within its current input types (domain, URL, IP,
hash, free-text message).

**HIGH_VALUE_OPTIONAL** (real value, deliberately not built this loop):
visual/screenshot page similarity (§2) — closes a narrow but real tail of
name-free cloned pages; correctly requires new architecture with its own
provenance/confidence discipline, not a quick addition.

**FUTURE_PROVIDER**: additional reputation providers (Safe Browsing,
PhishTank, URLhaus, urlscan, AbuseIPDB, Shodan) — each needs a concrete
comparative case showing it changes a verdict VT alone gets wrong before
being worth the quota/complexity cost, per the master loop's own §10
instruction not to add providers merely to increase source count.

**FUTURE_UI**: structured email/MIME (`.eml`) input and everything gated
on it (From/Reply-To mismatch, DMARC/SPF *alignment*, DKIM, attachment
metadata, mail-provider alignment); bare-email-address-as-seed
investigation; multi-query temporal DNS sampling (wildcard/fast-flux). All
four require a new CLI input capability or architecture KRISIS does not
have — building the analysis layer first, with no caller, would be dead
code.

**LOW_VALUE_DEFERRED**: every item in §4's table tagged P3 — arbitrary,
uncalibrated URL-shape thresholds; curated lists (TLD/disposable-mail/
shortener) with no infra blocker but no validated cutoff either; favicon/
iframe/external-resource enumeration (near-universal on legitimate sites
without a curated allowlist); JS-redirect static analysis; SAN/wildcard/
validity-period/issuer-tier certificate parsing beyond what already exists;
repeated-char/transposition lookalikes and zero-width Unicode (no known
live case); registrant metadata beyond org; cross-provider independence
classification (moot with one reputation provider).

---

## 7. Freeze condition

- [x] All high-value phishing scenarios identified (§1, A-N)
- [x] Each major scenario has sufficient evidence coverage, or the specific
      missing capability is named and classified (§1, §2, §3)
- [x] Every remaining material gap is explicitly justified (§4, §6)
- [x] No material implemented-signal false negative found this pass
- [x] No material implemented-signal false positive found this pass —
      SPF/DMARC verified NEUTRAL in every state (§5)
- [x] New decision-adjacent logic covered: SPF/DMARC is purely additive
      (no decision rule to mutation-test); covered instead by dedicated
      evidence tests per the loop's own §21 allowance
- [x] Validation matrix green (15/15)
- [x] Full `pytest` green (349/349)
- [x] `unittest discover` green (348/348)
- [x] CLI works (live-verified: `wikipedia.org`, `stripe.com`,
      `github.com`, `google.com`, `example.com`, `iana.org`)
- [x] Replay works (unchanged this pass; verified by existing
      `test_investigator_integration.py`/`test_cli.py` coverage, no
      collector-contract change made)
- [x] JSON works (live-verified: SPF/DMARC evidence present, correctly
      typed, in `--json` output)
- [x] Graph works (unchanged; no new relationship types added — SPF/DMARC
      is entity-scoped evidence, not a graph edge, correctly mirroring the
      prior pass's TLS-subject-org decision not to add a graph edge for
      identity-typed evidence)
- [x] Memory works (unchanged; new evidence automatically enters structural
      signatures the same way every other `infrastructure`-typed signal
      already does — no memory-layer change required, matching the
      established pattern for every previous evidence addition)
- [x] Provider planning works (unchanged; DNS collector's existing
      planner integration covers the new queries with no special-casing)
- [x] PDF reporting works (unchanged; generic evidence-table rendering,
      no signal allowlist exists anywhere in `pdf_report.py` — confirmed
      by grep, not assumed)
- [x] AI remains downstream (unchanged; no touch to `krisis/ai/`)
- [x] README matches reality (SPF/DMARC claim corrected from aspirational
      "weak positive signal" to the actual neutral-only implementation;
      test count corrected 337 → 349)
- [x] Acceptance document matches reality (pointer added per its own
      established convention of layering passes rather than rewriting
      history — see `KRISIS_CLI_V1_ACCEPTANCE.md` §19)
- [x] No secrets/runtime artifacts tracked (`git ls-files` confirms only
      `api_keys.example.txt` is tracked; `krisis_data/`, `reports/`,
      `api_keys.txt` all untracked)

**All freeze conditions hold. KRISIS CLI v1 — COMPLETE.**

Remaining work (visual similarity, structured email input, additional
reputation providers, every P3 item in §4) is real and not forgotten, but
none of it is required for KRISIS to fulfill its stated end goal within its
current supported input types. Per the master loop's own stopping rule:
the purpose is not infinite feature growth, it is the defensible statement
this document now supports — KRISIS has enough independent, deterministic
evidence paths to investigate phishing and impersonation cases within its
supported input types, and every remaining limitation is explicit, named,
and reasoned about above rather than silently absent.
