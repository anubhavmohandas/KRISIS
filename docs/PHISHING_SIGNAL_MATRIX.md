# KRISIS Phishing Signal Matrix

Master evidence taxonomy for the phishing-intelligence coverage/accuracy loop.
Built by reading every collector and core reasoning file directly (not by
re-describing README claims — two stale claims were found and are noted
in §15). Status values follow the loop's own vocabulary:

- **IMPLEMENTED** — produces real `Evidence` today, verified by test/citation
- **PARTIAL** — some part of the signal exists; gap stated explicitly
- **NOT IMPLEMENTED** — no code path produces this signal
- **FUTURE PROVIDER** — needs a curated list or third-party feed KRISIS does not ship
- **FUTURE UI** — needs a CLI/input-type capability KRISIS does not expose today

"Independence" and "Polarity" describe the *typical* value a collector assigns
when the signal fires; several signals are polarity-conditional (e.g.
`brand_domain_mismatch` is `NEUTRAL` alone, `SUPPORTS_THREAT` combined with a
credential form) — noted inline.

This document has two layers: the original audit (line numbers verified
against commit `dadf514`, the tree before this pass's implementation work —
citations for signals this pass didn't touch remain accurate against that
line numbering, though may drift by a few lines as unrelated code around
them changes over time) and, layered on top after two rounds of review, the
P0/P1/P2/P3 priority classification (see below) and implementation-status
updates for every signal this pass actually built — those are tagged
**IMPLEMENTED** in bold with a function/method-name citation rather than a
line number, specifically so they stay accurate as the surrounding file
changes.

---

## 1. IDENTITY

| Signal | Status | Evidence source | Polarity | Independence | Confidence | Risk relevance | Priority | v1 decision |
|---|---|---|---|---|---|---|---|---|
| Brand/lookalike label similarity (`SequenceMatcher`) | IMPLEMENTED | `identity.py:150 label_similarity()` | n/a (scoring input) | — | — | High | — | done |
| Homoglyph/confusable-char substitution (digit, Cyrillic, Greek) | IMPLEMENTED | `identity.py:49-57 CONFUSABLE_CHARS`, one-directional | supports (via `lookalike_domain`) | independent | 0.45-0.9 (`_confidence`) | High | — | done |
| Multi-char substitution (`rn`→`m`, `vv`→`w`) | IMPLEMENTED | `identity.py:60 CONFUSABLE_SEQUENCES` | supports | independent | as above | Medium | — | done |
| Repeated/inserted characters (`paypall.com`) | NOT IMPLEMENTED | none — only char-substitution + incidental `SequenceMatcher` overlap | — | — | — | Medium | P3 | `label_similarity` already catches most cases with high ratio; a dedicated insertion/deletion (edit-distance) model adds complexity for marginal recall gain over what reference-similarity already offers |
| Transposition (`paypla.com`) | NOT IMPLEMENTED | none | — | — | — | Low-Medium | P3 | same reasoning |
| Punycode/IDN decoding | IMPLEMENTED | `identity.py:102 decode_idn()`, called from `_split()` line 145 | n/a (normalization) | — | — | High | — | done |
| Mixed-script domains (Latin+Cyrillic same label) | **IMPLEMENTED** | `identity.py::mixed_script_label()` (stdlib `unicodedata`, no curated script-range table), wired via `identity_collector.py::_mixed_script_evidence()`; signal `mixed_script_domain` | supports | independent | 0.45 | Medium | P0 | done — catches a real technique confusable-char mapping alone can miss (a Cyrillic char outside the curated `CONFUSABLE_CHARS` table); flags script *mixing within one label* only, never a label written entirely in one non-Latin script (validation case L, live-verified: `falбconhub.example`). Also required a correctness fix to `risk.py`'s LOW-band impersonation floor, which previously assumed any identity-type `SUPPORTS_THREAT` evidence named a verified referent — see `VERIFIED_REFERENT_SIGNALS` in `risk.py` |
| Zero-width/invisible Unicode | NOT IMPLEMENTED | confirmed via grep, no handling anywhere | — | — | — | Low | P3 | genuinely rare in domain labels (most registries reject them); revisit if a real case surfaces one |
| Decoration-token subdomain/label placement (`brand-login`, `secure-brand`, concatenated) | IMPLEMENTED | `identity.py:154-184 _core_tokens()` | supports | independent | as `lookalike_domain` | High | — | done |
| Brand token mismatch (page-claimed org vs domain) | IMPLEMENTED | `page_collector.py:415-447 _brand_mismatch_evidence()` | neutral alone / supports with credential form | derived | 0.3 / 0.55 | High | — | done |
| Claimed (page) org vs domain identity | IMPLEMENTED | same as above | — | — | — | High | — | done |
| Verified operatorship (shared resolved IP) | IMPLEMENTED | `identity_collector.py:85-99 same_operator()` — strictly shared resolved address | contradicts (`same_operator_variant`) | independent | 0.6 | High | — | done |
| Claimed (unverified) operatorship (WHOIS org string match) | IMPLEMENTED, deliberately non-suppressing | `identity_collector.py:102-118 claimed_same_operator()`; discounted from offsetting a finding in `risk.py:166-182 NARROW_CONTRADICTIONS` | contradicts, capped | independent | 0.3 | Medium | — | done — this is the fix landed in `dadf514` |
| Registrant metadata beyond org | PARTIAL | only `registrant_org` string compared (`whois_collector.py:133-147`); email surfaced only as a pivot target, never compared for identity | — | — | — | Low | P3 | no concrete failure case motivates it yet |
| Certificate subject identity | **IMPLEMENTED** (documented limitation, now resolved) | `tls_collector.py::_subject_org_evidence()`; signals `certificate_subject_org_match`/`certificate_subject_org_mismatch` | contradicts (match, conf 0.5) / supports (mismatch, conf 0.35) | independent | 0.5 / 0.35 | Medium-High | P1 | done — emits only when the cert actually carries a subject org (OV/EV; absence, the DV-cert majority case, stays silent), compared against the domain's own registrable label via `identity.label_similarity()` reusing `page_collector.BRAND_MISMATCH_THRESHOLD`'s 0.45 cutoff. A match is added to `risk.py NARROW_CONTRADICTIONS` so it cannot arithmetically offset an identity finding (a CA-vetted cert for *some* org doesn't disprove impersonation of a *different* one) — mutation-tested. Live-verified: absent on `github.com`/`wikipedia.org`/`python.org` (all DV), present+matching on `stripe.com` ("Stripe, LLC") |
| Page-claimed-org vs domain identity | IMPLEMENTED | see brand token mismatch | — | — | — | High | — | done |
| Established-referent age gate | IMPLEMENTED | `identity_collector.py:40-43 ESTABLISHED_MIN_AGE_DAYS=730, AGE_MARGIN_DAYS=365` | gates `lookalike_domain` emission | — | — | High | — | done |
| `.bank.in` restricted-namespace credit | IMPLEMENTED | `identity_collector.py:294-314`, `indicators.py is_bank_in_namespace()` | contradicts | independent | 0.75 | Medium (namespace-specific) | — | done |
| Brand buried in **subdomain** (not just registrable label) | **IMPLEMENTED** | `identity.py::candidates()` mechanism 3 extended with `_subdomain_labels()` — no changes needed to `identity_collector.py`, subdomain-derived candidates flow through the same `_verdict()` verification pipeline | supports (`lookalike_domain`) | independent | as `lookalike_domain` | High | P0 | done — only fires against a *known* reference (case memory or `identity_references.txt`), since a bare subdomain label has no suffix of its own to pair with; ties directly to URL/DOMAIN STRUCTURE §2 |

## 2. URL / DOMAIN STRUCTURE

| Signal | Status | Evidence source | Polarity | Independence | Confidence | Risk relevance | Priority | v1 decision |
|---|---|---|---|---|---|---|---|---|
| IP address used as host | **IMPLEMENTED** | `url_intent.py::is_ip_literal_host()`, wired via `page_collector.py::_structure_evidence()`; signal `ip_literal_host` | supports | independent | 0.5 | High | P0 | done — zero arbitrary threshold (either `ipaddress.ip_address(hostname)` parses or it doesn't); live-verified via the malware-delivery interaction rule (§13) |
| Excessive subdomain depth | NOT IMPLEMENTED | no label-count heuristic | — | — | — | Low-Medium | P3 | any fixed depth threshold is exactly the "arbitrary threshold without testing" the loop prohibits (§5); not built without real-case calibration |
| Deceptive subdomain structure (brand as subdomain of unrelated domain) | **IMPLEMENTED** | see IDENTITY table (`identity.py::candidates()` mechanism 3 extension, `_subdomain_labels()`) | — | — | — | High | P0 | done — same work item as the IDENTITY row below |
| Suspicious path/query tokens | IMPLEMENTED | `url_intent.py` — `authentication_intent`, `credential_intent`, `financial_intent`, `recovery_intent` | neutral (context signal) | derived | 0.4 | Medium | — | done |
| URL length anomaly | NOT IMPLEMENTED | none | — | — | — | Low | P3 | arbitrary threshold, no validated cutoff; §5 prohibits inventing one untested |
| Encoded URL components (percent-encoding abuse) | NOT IMPLEMENTED | none | — | — | — | Low-Medium | P3 | same arbitrary-threshold concern |
| @-userinfo URL trick | **IMPLEMENTED** | `url_intent.py::has_userinfo()`, wired via `page_collector.py::_structure_evidence()`; signal `url_userinfo_present` | supports | independent | 0.6 | Medium | P0 | done — deterministic presence check (`urlparse(url).username is not None`), classic obfuscation technique (`https://paypal.com@evil.tld/`) |
| Suspicious port usage | NOT IMPLEMENTED | none | — | — | — | Low-Medium | P3 | nonstandard ports are common for legitimate self-hosted services; without calibration this is a false-positive generator, not a signal |
| Mixed encoding | NOT IMPLEMENTED | none | — | — | — | Low | P3 | — |
| Punycode at URL level (not just identity-candidate derivation) | PARTIAL | `decode_idn` only invoked from the identity path | — | — | — | Medium | P3 | already reachable via IDENTITY's punycode decoding whenever the host is a domain; a bare "this hostname is punycode" flag independent of identity derivation was considered and rejected as redundant (Occam: don't duplicate an existing signal under a new name) |
| Suspicious TLD | NOT IMPLEMENTED | none | — | — | — | Low-Medium | P3 | meaningfully distinguishing "suspicious" TLDs requires a maintained reputation-style list (ccTLD abuse statistics); no infra blocker, just not worth maintaining unvalidated |
| Shortener/intermediate redirect URL | PARTIAL | redirect chains fully tracked (`page_collector.py:331-369`) but no shortener-service list | — | — | — | Low | P3 | the underlying behavior (redirect, cross-domain landing) is already evidenced regardless of whether the origin is a known shortener; a shortener list adds no new *risk-relevant* fact, only a label |
| Domain age | IMPLEMENTED | `whois_collector.py:69-115`, `NEW_DOMAIN_THRESHOLD_DAYS=30`, `YOUNG_DOMAIN_THRESHOLD_DAYS=180` (×4 for long-lived) | supports/neutral/contradicts | independent | 0.5-0.6 | Medium | — | done |
| Registration timing vs referent | IMPLEMENTED | `identity_collector.py:208-212` | gates `lookalike_domain` | — | — | High | — | done |
| Expiration proximity | **IMPLEMENTED** | `whois_collector.py::collect()`, signals `expired_domain_still_active`/`domain_expiring_soon`/`domain_expiration_days`, `EXPIRING_SOON_THRESHOLD_DAYS` reused from `NEW_DOMAIN_THRESHOLD_DAYS` | supports/neutral | independent | 0.3-0.5 | Low-Medium | P1 | done — mirrors the existing `creation_date` age-threshold pattern exactly; live-verified against `stripe.com` (`domain_expiration_days = 390`) |

## 3. DNS / MAIL

| Signal | Status | Evidence source | Polarity | Independence | Confidence | Risk relevance | Priority | v1 decision |
|---|---|---|---|---|---|---|---|---|
| A / AAAA / CNAME / MX / NS / TXT / SOA records | IMPLEMENTED | `dns_collector.py:16-26` | neutral | independent | 0.9 | — | — | done |
| SPF (TXT `v=spf1`) | NOT IMPLEMENTED | TXT record captured raw, never parsed | — | — | — | Low-Medium | P1 | deferred this pass — an earlier draft of this plan included it (P1: evidence source already exists), but the priority-framework review round replaced it with `sender_url_domain_mismatch` (§10) as the higher-value P0 item for the same "email context" focus area; not implemented, revisit as a standalone follow-up |
| DMARC (`_dmarc.<domain>` TXT) | NOT IMPLEMENTED | no dedicated query | — | — | — | Low-Medium | P1 | deferred this pass, same reasoning as SPF above |
| DKIM | NOT IMPLEMENTED | none | — | — | — | Low | P2 | DKIM selectors are unknowable without a specific message's headers — needs the same structured-email-parser capability §10's P2 items need |
| Mail-provider alignment (MX vs claimed sender domain) | NOT IMPLEMENTED | MX collected as pivot only | — | — | — | Low | P2 | no structured sender-domain field exists for any current input type; see §10 |
| Domain-to-IP relationships | IMPLEMENTED | `pivot_engine.py:79-80 resolves_to` | — | — | — | — | — | done |
| Nameserver relationships | IMPLEMENTED | `pivot_engine.py:82 uses_nameserver`, commodity-penalized | — | — | — | — | — | done |
| Suspicious DNS config (wildcard, fast-flux, no MX) | NOT IMPLEMENTED | none | — | — | — | Low | P2 | needs multi-query correlation (repeated resolves over time) KRISIS's single-shot model doesn't support — new infrastructure, not a signal add |
| Disposable-mail infrastructure | NOT IMPLEMENTED | none | — | — | — | Low | P3 | requires a maintained disposable-domain list — no infra blocker, just not worth maintaining yet |

## 4. INFRASTRUCTURE / RELATIONSHIP / GRAPH

Relationship types the graph actually creates today (`pivot_engine.py:78-92 PIVOT_RULES` + seed edges in `investigator.py:259,267,274`):

`resolves_to`, `cname_to`, `uses_nameserver`, `uses_mailserver`, `secured_by`,
`registered_with`, `registered_by`, `hosted_on_asn`, `vt_related`,
`redirects_to`, `looks_like`, plus seed-derived `has_domain`/`mentions`.

| Item | Status | Notes | Priority | v1 decision |
|---|---|---|---|---|
| Commodity-infrastructure suppression | IMPLEMENTED | `pivot_engine.py:149-203`, structural + historical tests, mutation-tested | — | done, must not regress |
| Infrastructure overlap in correlation | IMPLEMENTED | `correlation.py:74-92 _infrastructure_overlap()` | — | done |
| `domain → organization` via cert subject | NOT IMPLEMENTED | falls out of the TLS-subject work above if implemented | Medium | tracked under TLS §5, no separate graph work needed — `registered_by` already exists as the pattern to follow for a new `certified_as`-style relation if the subject-org signal is added; **decision: do not add a new relation type in v1** — the subject-org signal enters as `identity` evidence directly (mirrors `_brand_mismatch_evidence`) rather than a graph edge, keeping the graph change surface at zero for this pass |
| `domain → ASN` direct edge | NOT IMPLEMENTED (two-hop only, via IP) | not a gap — ASN is properly a property of the IP, not the domain; a direct edge would duplicate the existing two-hop path | — | no change |

## 5. TLS / CERTIFICATE

Confirmed by direct read of `krisis/collectors/tls_collector.py` (98 lines).
Extracted today: `certificate_fingerprint` (line 43-58), `expired_certificate`
(line 60-80, `notAfter` only), `valid_tls_present` (line 82-96, **issuer**
`organizationName` only, confidence deliberately capped at 0.25 — "any
attacker can get a valid cert").

| Signal | Status | Evidence source | Priority | v1 decision |
|---|---|---|---|---|
| Certificate **subject** organizationName | **IMPLEMENTED** | `tls_collector.py::_subject_org_evidence()`; signals `certificate_subject_org_match`/`_mismatch` | P1 | done — see §1 IDENTITY for full detail and live-verification results. Discounted from offsetting an identity finding via `risk.py NARROW_CONTRADICTIONS`, mutation-tested |
| SANs (subjectAltName) | NOT IMPLEMENTED | `ssock.getpeercert()` return dict includes `subjectAltName` but it's never read | P3 | no concrete question it answers that fingerprint + hostname connection success doesn't already cover; `ssl.wrap_socket(server_hostname=...)` already fails closed on hostname mismatch (see below), so a redundant SAN parse adds no new signal |
| Wildcard cert detection | NOT IMPLEMENTED | — | P3 | no clear polarity — wildcards are extremely common on legitimate infra |
| Hostname/cert mismatch | IMPLEMENTED implicitly, PARTIAL as evidence | `ssl.create_default_context()` + `wrap_socket(server_hostname=entity.value)` (line 32-34) already raises on hostname mismatch — the collector reports it as `CollectorResult(available=False, ...)` (line 37-38), i.e. as an *unavailable* source, not as positive `SUPPORTS_THREAT` evidence of an anomaly | P3 | changing an unavailable-source outcome into scored evidence changes existing, tested behavior (`README.md`'s own `malware.wicar.org` example documents this exact path: TLS unavailable due to hostname mismatch, reported as coverage gap, not folded into "clean" *or* into "malicious"). Re-litigating that is out of scope for this pass and risks the "unavailable → malicious" mirror-image of the "unavailable → safe" bug the loop explicitly guards against (§19) |
| Validity period / notBefore | NOT IMPLEMENTED | only `notAfter` read | P3 | low incremental value over existing `expired_certificate` |
| Issuer CA tier (free vs EV) | NOT IMPLEMENTED | — | P3 | same reasoning as subject-org scoping above; a free-CA-only signal without the subject-org contrast is weak alone |

## 6. WEBPAGE / CONTENT

`page_collector.py` `_PageParser` (line 210-269).

| Signal | Status | Evidence source | Priority | v1 decision |
|---|---|---|---|---|
| Title / `og:site_name` / H1 (claimed org derivation) | IMPLEMENTED | line 233-261, `_claimed_org_name()` line 272-288 | — | done |
| Password field | IMPLEMENTED | line 249-250 | — | done |
| Credential-field heuristic (username/email inputs) | IMPLEMENTED | line 251, `_CRED_FIELD_HINTS` | — | done |
| Payment field | IMPLEMENTED | line 253, `_PAYMENT_FIELD_HINTS` | — | done |
| Per-form scoping | IMPLEMENTED | `_FormState` per `<form>`, tested `test_page_collector.py:189-207` | — | done |
| External form action | IMPLEMENTED | `_credential_evidence()` line 383-413 | — | done |
| Favicon | NOT IMPLEMENTED | no `<link rel="icon">` parsing | P3 | meaningful only against a favicon-hash reference database KRISIS does not have (same "referent legitimacy" gap README already documents honestly); extracting it without a comparison target produces no polarity, just noise |
| Meta description tag | NOT IMPLEMENTED | only `og:site_name` read, not `<meta name="description">` | P3 | `_claimed_org_name()` already has three fallback sources; a fourth adds surface area without a case it uniquely resolves |
| Meta-refresh redirect (`<meta http-equiv="refresh">`) | **IMPLEMENTED** | `page_collector.py::_meta_refresh_evidence()`, `_PageParser` captures the `content` attribute; signal `meta_refresh_target`, also a `pivot_engine.PIVOT_RULES` entry reusing the `redirects_to` relation | supports (cross-domain, 0.5) / neutral (same-org, 0.4) | independent | 0.4-0.5 | P0 | done — extends the existing, already-scored redirect machinery (`_redirect_evidence`) with a technique a pure HTTP-redirect walk misses entirely |
| Iframe target | NOT IMPLEMENTED | `_PageParser` has no iframe handling | P3 | clickjacking/overlay analysis needs render-level inspection (z-index, visibility) a static HTML parse can't do; a bare "page contains a cross-domain iframe" flag alone is common on legitimate sites (embeds, payment widgets) and would be a false-positive generator without that context |
| External resource enumeration (scripts/images from other domains) | NOT IMPLEMENTED | none | P3 | near-universal on legitimate sites (CDNs, fonts, analytics); no curated allowlist exists to separate commodity from suspicious, same trap §7 of the loop warns about for infrastructure |
| Download / executable link detection | **IMPLEMENTED** | `page_collector.py::_download_evidence()`, `_EXECUTABLE_EXTENSIONS`; signal `executable_download` | supports | independent | 0.5 | P1 | done — `<a href>` ending in an executable/script extension (`.exe .scr .bat .cmd .msi .jar .apk .dmg .vbs .ps1 .jse .wsf`); deterministic extension check on the path only (a query-string value is not treated as a direct download link), directly serves the malware-delivery hypothesis via `risk.py`'s new interaction rule (§13) |

## 7. WEB BEHAVIOR

| Signal | Status | Evidence source | Priority | v1 decision |
|---|---|---|---|---|
| Redirect chain capture (all hops) | IMPLEMENTED | `safe_fetch()` line 138-198 | — | done |
| Cross-domain redirect | IMPLEMENTED | `_redirect_evidence()` line 359-368 | — | done |
| Redirect count | IMPLEMENTED (as chain length, inspectable) | `redirect_chain` evidence value | — | done |
| Redirect loop detection | IMPLEMENTED | line 149-152 | — | done |
| Max redirect depth enforcement | IMPLEMENTED | `MAX_REDIRECTS=5` | — | done |
| Meta-refresh redirect | **IMPLEMENTED** | see §6 | P0 | done (same item as §6) |
| JS redirect (`window.location`, etc.) | NOT IMPLEMENTED | `_PageParser` never captures `<script>` body content at all | P3 | reliable detection needs a JS parser or heuristic regex over inline script bodies; regex-only detection over unstructured JS is exactly the "arbitrary heuristic without testing" the loop warns against, and a full JS parse is out of proportion to this pass |
| Form submission destination (external) | IMPLEMENTED | see §6 | — | done |
| Download / executable detection | **IMPLEMENTED** | see §6 | P1 | done (same item) |
| URL-intent classification of final URL | IMPLEMENTED | `_intent_evidence()` line 371-381 | — | done |

## 8. CREDENTIAL COLLECTION

Fully covered by §6/§7 — no separate signals exist outside the page collector's
form analysis. `credential_form`, `external_form_action`, and the
impersonation+credential interaction bonus (§13 below) already implement this
category coherently. No gaps identified beyond what's tracked above.

## 9. REDIRECT / NAVIGATION

Fully covered by §7, including the new meta-refresh signal — no remaining gap.

## 10. MESSAGE / EMAIL CONTEXT

`message_collector.py` wraps `message_signals.py` for phrase-pattern
extraction; it now also derives one cross-referenced fact from the same raw
text. No MIME/header parser exists anywhere in the codebase — the CLI's only
message input path remains raw free text (`MESSAGE` seed type via
`classify_seed()`, `indicators.py:29-53`) or a file of raw text (`--file`).

| Signal | Status | Evidence source | Priority | v1 decision |
|---|---|---|---|---|
| Urgency language | IMPLEMENTED | `message_signals.py:19-25` | — | done |
| Credential request phrasing | IMPLEMENTED | line 26-32 | — | done |
| Financial lure | IMPLEMENTED | line 33-37 | — | done |
| Call to action | IMPLEMENTED | line 38-42 | — | done |
| URL/domain/email/hash extraction from message body | IMPLEMENTED | `indicators.py:56-87 extract_from_text()` | — | done |
| Sender/URL domain mismatch (within free text, no headers needed) | **IMPLEMENTED** | `message_collector.py::_sender_url_mismatch_evidence()`; signal `sender_url_domain_mismatch` | supports | derived | 0.4 | P0 | done — reuses `extract_from_text()`'s already-extracted EMAIL/URL/DOMAIN entities (no new parser); fires only when *every* email address mentioned and *every* URL/domain mentioned sit under fully disjoint registrable domains (all-or-nothing, not any-pairwise-mismatch, to avoid firing on a message that mentions one unrelated domain in passing while still linking back to its claimed sender elsewhere). Explicitly the P0 item the priority-framework review named ("sender/URL mismatch when the input contains email context") in place of the header-dependent signals below |
| Display-name mismatch | NOT IMPLEMENTED | no header model | — | P2 |
| From / Reply-To mismatch | NOT IMPLEMENTED | no header model | — | P2 |
| Sender-domain vs claimed-org mismatch (header-verified, not just text-mentioned) | NOT IMPLEMENTED | no header model | — | P2 |
| SPF/DKIM/DMARC alignment against a specific message | NOT IMPLEMENTED | no header model | — | P2 |
| Attachment metadata / hash / suspicious extension | NOT IMPLEMENTED | `--hash` treats a hash as its own artifact seed, not as "this message's attachment" | — | P2 |

**Decision for the remaining P2 items: no code changes.** There is no
`.eml`/MIME ingestion path anywhere in `cli.py`, so every signal above would
need a new structured-header input type invented from nothing — exactly what
§12 of the loop instructs against ("do not require email-specific fields when
the user only supplied a URL"). Building header parsing with no caller that
can ever populate it would be dead code. These are explicitly blocked on a
CLI capability (`krisis investigate mail.eml --eml` or equivalent) that does
not exist yet and is out of scope for this pass — real and valuable, not
silently dropped.

## 11. REPUTATION

| Item | Status | Notes |
|---|---|---|
| VirusTotal (domain/url/hash/ip) | IMPLEMENTED | `virustotal_collector.py`, v2 API |
| Any other provider (Safe Browsing, PhishTank, URLhaus, urlscan, AbuseIPDB, Shodan) | NOT IMPLEMENTED | **FUTURE PROVIDER**, explicitly out of scope per §13 of the loop — "DO NOT implement all of them now" |

The core investigator remains fully functional with zero reputation providers
configured (`INSUFFICIENT_EVIDENCE` rather than a silent LOW — `risk.py:438-443`).

## 12. HISTORICAL MEMORY

| Item | Status | Notes |
|---|---|---|
| Indicator (exact-value) matching | IMPLEMENTED | `pattern_memory.py:154-238` |
| `exact_artifact` vs `infrastructure` distinction | IMPLEMENTED | line 195-211 |
| Structural (shape-only) matching | IMPLEMENTED | `structural_facets()` line 89-130, IDF-weighted |
| Pattern lifecycle stages | IMPLEMENTED | `STAGE_WEIGHT` line 79-86 |
| Outcome-trust gating | IMPLEMENTED | `risk.py OUTCOME_TRUST`, `pattern_memory.py:399-454` |
| Self-match exclusion | IMPLEMENTED | `exclude_seed` threaded through `find_similar` |

No gaps identified. New signals added by this pass (subdomain-brand, TLS
subject-org, meta-refresh, download links, expiration proximity, SPF/DMARC)
automatically enter structural signatures the same way every other `identity`/
`behavior`/`registration`-typed signal already does — no memory-layer change
required.

## 13. HYPOTHESIS MODEL / COMBINATION LOGIC

Combination rules, `risk.py:95-112` (two, after this pass — up from one):
```python
INTERACTION_IMPERSONATION_SIGNALS = frozenset({"lookalike_domain", "brand_domain_mismatch"})
INTERACTION_CREDENTIAL_SIGNALS = frozenset({"credential_form"})
INTERACTION_BONUS_POINTS = 14.0

INTERACTION_SUSPICIOUS_URL_SIGNALS = frozenset({"ip_literal_host", "url_userinfo_present"})
INTERACTION_DOWNLOAD_SIGNALS = frozenset({"executable_download"})
INTERACTION_MALWARE_BONUS_POINTS = 14.0
```

| Hypothesis (loop §11) | Status | Notes |
|---|---|---|
| Impersonation + login form + external form action → credential-phishing | IMPLEMENTED | interaction bonus above + independently-scored `external_form_action` evidence; diversity factor further rewards the combination without a second hardcoded rule |
| Impersonation + same verified operator → benign variant | IMPLEMENTED | `same_operator_variant` (`CONTRADICTS_THREAT`) already produced instead of `lookalike_domain` — mutually exclusive by construction in `identity_collector._verdict()`, not a second rule needed |
| Suspicious URL + download → malware delivery | **IMPLEMENTED** | P0 | `INTERACTION_SUSPICIOUS_URL_SIGNALS × INTERACTION_DOWNLOAD_SIGNALS`, mirrors the existing rule's shape exactly, same file. Mutation-tested (`tests/test_risk.py::TestSecuritySignalInteraction::test_malware_delivery_signals_score_well_above_the_sum_of_the_parts`). This is the **only** new interaction rule this pass adds — every other new signal (`mixed_script_domain`, brand-in-subdomain-derived `lookalike_domain`, `certificate_subject_org_match`/`_mismatch`, `domain_expiring_soon`, `sender_url_domain_mismatch`, `meta_refresh_target`) was individually checked against existing evidence combinations and found to already be adequately expressed by ordinary polarity/confidence/independence/diversity scoring, or by an *existing* rule (brand-in-subdomain's `lookalike_domain` is the same signal name the original mechanism produces, so it's already covered by everything that already keys on it). Adding a bonus per signal pair would be exactly the "cluster of correlated signals counted as independent confirmations" failure §17 of the loop warns against — validated live: validation-matrix case M needed *three* co-occurring signals (deceptive URL shape × 2 + a fresh-registration signal) to cross into MEDIUM, confirming the bonus lifts a real combination rather than manufacturing a floor from thin air. |

## 14. COVERAGE / UNCERTAINTY

Already implemented, not audited as a gap category — `models.py:83-117 Coverage`
(attempted/available/evidence_types, `has_reputation_source()`), consumed by
`risk.py::_categorize` to produce `INSUFFICIENT_EVIDENCE`/`CONFLICTING_EVIDENCE`
rather than ever letting "not checked" render as "clean". No new signal in
this pass changes this layer; each new collector output (TLS subject-org
absence, SPF/DMARC absence) follows the same "silence is not a threat
finding" discipline already established by `valid_tls_present`'s confidence
cap and the reputation-floor rule.

## 15. PROVIDER PLANNING

`provider_planner.py` (347 lines). Actual `Decision.action` values in code:
`"queried"`, `"cached"`, `"deduplicated"`, `"skipped"` — not the 6-state
vocabulary ("queried/cached/reused/skipped/unavailable/rate-limited/deferred")
the loop prompt names. Reconciliation:
- "reused" = `"deduplicated"` (in-run) or `"cached"` (cross-run) — already two
  distinct, already-correct states, just different names than the prompt used
- "rate-limited" is a `ProviderUsage` counter (`usage.rate_limited`), a
  post-hoc classification of a `"queried"` call's *result*, not a `Decision`
  state — correctly modeled, no change needed
- "unavailable" is `CollectorResult.available`, orthogonal to planner
  decisions by design (a `"queried"` request can still fail) — correct
- "deferred" has no distinct state; `_budget_block` either sleeps-then-proceeds
  or returns `"skipped"` — this is the one place the prompt's vocabulary and
  the code genuinely diverge

**v1 decision: no change.** The existing 4-state model plus the two
orthogonal `available`/`rate_limited` flags already expresses every
distinction the loop's §18 requires (value gate, cache, dedup, backoff, quota
all separately reported per the README's own worked example). Renaming
`"skipped"` decisions that came from `_budget_block`'s sleep-then-timeout path
into a fifth `"deferred"` state would be surface-only churn with no behavior
or reporting change — skipped per Occam ladder rung 1 (does this need to
exist at all?).

## 16. CLI INPUT TYPES

`indicators.py:29-53 classify_seed()`: `URL`, `IP`, `HASH`, `EMAIL`, `DOMAIN`,
`MESSAGE` (free-text fallback, mines secondary indicators via
`extract_from_text()`).

| Input type | Collector coverage | Gap |
|---|---|---|
| Domain | DNS, WHOIS, TLS, Identity, VT | none |
| URL | Page (+ domain component split off as child entity), VT | none |
| IP | IPCollector (RDAP), VT | none |
| Hash | VT only | none — by design, nothing else can examine a bare hash |
| Raw message/text | MessageCollector (phrase-matching) + extracted-entity re-investigation | no structured header parsing — see §10, FUTURE UI |
| Bare email address | Classified, extracted, never itself collected against (`supports=("email",)` matches no collector in `default_collectors()`) | **FUTURE UI/PROVIDER** — investigating an email address as its own seed (mailbox reputation, MX-based inference) is a distinct capability nothing in this pass adds; noted, not built |

---

## Priority classification (P0/P1/P2/P3)

This audit's original "Priority: High/Medium/Low" + "v1 decision:
implement/defer" columns were superseded mid-review by an explicit
P0/P1/P2/P3 framework (the tags now used throughout the tables above):

- **P0** — materially improves phishing/impersonation reasoning using
  evidence KRISIS can already collect safely; required-focus items with a
  real gap
- **P1** — the collector/input already exists; only the analytical layer
  was missing
- **P2** — genuinely blocked on a new provider, external service, UI/input
  capability, or infrastructure KRISIS doesn't have (email-parser,
  passive-DNS, temporal sampling, ...)
- **P3** — no infrastructure blocker; not implemented because of
  arbitrary-threshold risk or marginal value relative to what's already
  covered

Only P0/P1 items were built this pass. No P2/P3 item was implemented.

## v1 Implementation Scope — IMPLEMENTED (this pass)

Nine work items, all landed, tested, and (where they're decision rules
rather than plain evidence emission) mutation-tested:

**P0:**
1. **Mixed-script domain detection** — `identity.py::mixed_script_label()` + `identity_collector.py::_mixed_script_evidence()`. Stdlib `unicodedata`, no curated script table. Surfaced and fixed a real bug in the process: `risk.py`'s LOW-band impersonation floor previously fired on *any* identity-type `SUPPORTS_THREAT` evidence, which would have worded a bare mixed-script finding as "imitates an established identity" — a claim only `lookalike_domain` (verified referent) can honestly make. Fixed via `VERIFIED_REFERENT_SIGNALS`, mutation-tested.
2. **Brand-in-subdomain derivation** — `identity.py::candidates()` mechanism 3 extended with `_subdomain_labels()`. Zero changes to `identity_collector.py` — subdomain-derived candidates reuse the existing verification pipeline untouched.
3. **URL-structure signals** — `url_intent.py::is_ip_literal_host()` / `has_userinfo()`, wired into `page_collector.py::_structure_evidence()` (fetch-success path only, so the failure-path contract stays untouched).
4. **Meta-refresh redirect** — `page_collector.py::_meta_refresh_evidence()`, plus a `pivot_engine.PIVOT_RULES["meta_refresh_target"]` entry.
5. **Sender/URL domain mismatch in message context** — `message_collector.py::_sender_url_mismatch_evidence()`. Reuses `indicators.extract_from_text()`, no new parser. Replaces the header-dependent message signals an earlier draft of this plan considered (SPF/DMARC domain-level presence, both dropped — see below) as the higher-value P0 item for the same "email context" focus area.

**P1:**
6. **WHOIS expiration proximity** — `whois_collector.py`, mirrors the existing `creation_date` three-way pattern exactly.
7. **TLS certificate subject organization** — `tls_collector.py::_subject_org_evidence()`. Added to `risk.py NARROW_CONTRADICTIONS` (a fourth entry, same shape as the existing three) so a match can't arithmetically offset an identity finding it doesn't actually rebut — mutation-tested.
8. **Executable-download link detection** — `page_collector.py::_download_evidence()`.
9. **Malware-delivery interaction rule** — `risk.py`, second `INTERACTION_*` block, depends on (3)+(8). Mutation-tested.

Plus: `tests/validation/test_accuracy_matrix.py` expanded from 11 to 15 cases
(Cyrillic homoglyph, mixed-script-without-confusable-match, malware-delivery
interaction, message sender/URL mismatch) — all 15 pass; `README.md` and
`KRISIS_CLI_V1_ACCEPTANCE.md`'s stale "no URL-scanning/redirect-chain
collector" claims corrected (false since `de22907`, which predates the
doc-finalize commit `4a61257`); test count corrected 286 → 337 where it
describes current state (`KRISIS_CLI_V1_ACCEPTANCE.md`'s own dated §15-17
snapshot, accurate as of its own commit, is left alone).

**Dropped between drafts:** DNS SPF/DMARC presence (§3) was in an earlier
version of this plan as P1 (evidence source exists) but was cut when the
priority-framework review round explicitly named
`sender_url_domain_mismatch` (item 5) as the higher-value P0 signal for the
same focus area; SPF/DMARC remains a reasonable, low-effort standalone
follow-up, not silently forgotten.

## P2/P3 — explicitly not built this pass

Every item tagged P2 or P3 in the tables above, by category:

- **P2** (needs new provider/UI/infra): additional reputation providers;
  full email header/MIME parsing (From/Reply-To/display-name mismatch,
  SPF/DKIM/DMARC alignment against a *specific* message, attachment
  metadata); bare-email-address-as-seed investigation; mail-provider
  alignment via MX; DKIM; suspicious multi-query DNS config (wildcard/
  fast-flux)
- **P3** (no infra blocker, not worth it yet): URL length/query-encoding
  anomalies, subdomain depth, suspicious ports, mixed encoding,
  suspicious-TLD list, disposable-mail list, shortener-service list,
  favicon, meta description, iframe/external-resource enumeration,
  JS-redirect static analysis, TLS hostname-mismatch-as-scored-evidence,
  wildcard cert, SAN parsing, validity period, issuer CA tier,
  repeated/inserted-char + transposition lookalikes, zero-width Unicode,
  registrant metadata beyond org

Each has its specific reasoning recorded inline in the category tables
above — nothing here is a bare "later," every deferral states why.
