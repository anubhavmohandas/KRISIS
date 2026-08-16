# KRISIS vs. VirusTotal — Comparative Investigation Validation

**Question tested:** does KRISIS provide investigation intelligence that
materially differs from what VirusTotal alone gives an investigator, or is
KRISIS a VirusTotal wrapper with extra formatting?

**Method:** real `krisis investigate` runs against a live VirusTotal key
(public API v2, `~/.krisis/api_keys.txt`), reusing already-stored cases from
prior sessions where they already covered a required scenario (no case was
re-run just to pad this document), plus the project's own mutation-tested
test suite where reproducing a scenario live would require standing up real
malicious infrastructure. Every number below is either a live API response
captured during this session or an exact test file/line already in the repo
— nothing is invented. No production code was changed to produce these
results (per phase instructions, §16); one learning-loop action was taken
(`krisis outcome`, §22 below) because it is a normal product operation, not
a code change.

**Provider budget used for this comparison:** 3 new seeds investigated live
(`malware.wicar.org`, `https://github.com/login`,
`"Hey, thought you'd find this funny: https://1inkedin.com"`). Combined VT
cost: 3 fresh calls, 5 reused-from-cache, 14 skipped by the value gate below
threshold. A same-seed re-run of `malware.wicar.org` afterward cost **0**
further calls (100% cache reuse, confirmed in trace step 8 below). Daily VT
usage for the whole session: 21 of 500 calls. Nothing was spent solely to
produce this document.

---

## 1. The comparative matrix

| # | Scenario | What VirusTotal alone shows | What KRISIS adds |
|---|---|---|---|
| A | Known-malicious test domain — `malware.wicar.org` (live) | `1528/9277` engine detections on URLs seen at this domain — a ratio, no context | `MEDIUM 11/100, confidence 62%`. Explicitly refuses both extremes: won't call it CRITICAL off one corroborating source, won't call it safe either. States *why* the score is only 11 (domain registered 5,030 days — "long_lived_domain" — the only counter-evidence) and names the one source it couldn't check (`tls`, cert hostname mismatch) rather than silently treating that gap as clean. |
| B | Brand lookalike, thin reputation — `1inkedin.com` (stored case `case_b11079116a2c`) | `32/644` (~5%) — below VT's own "malicious" bar, reads as basically clean | `MEDIUM 39/100`. Top contributor is `lookalike_domain` (identity), not the VT ratio. KRISIS derived `linkedin.com` from confusable glyphs (`1`→`l`), verified it resolves, is older, and is operated by someone else — *then* called it evidence. VT's low detection count never enters the top-contributor list. |
| C | Credential phishing shape (impersonation + credential form) | No live malicious credential-harvesting page was fetched for this comparison — deliberately: doing so would mean interacting with real attacker infrastructure, out of scope for a validation exercise. Proven instead via the exact production code path, mutation-tested: `tests/test_page_collector.py:240-251` — a page claiming to be "GlorpTech" on an unrelated domain with a password field is emitted as `brand_domain_mismatch` at `SUPPORTS_THREAT` (not `NEUTRAL`, which is what the *same* mismatch gets without a credential form — `test_page_collector.py:230-238`), and `risk.py:87-97` adds a further +14-point interaction bonus only when both an impersonation signal *and* `credential_form` co-occur. | Live negative control below (D) proves this mechanism is calibrated, not trigger-happy: the same `credential_form` detector fires on a real password field and does **not** elevate risk when nothing else corroborates it. |
| D | Legitimate login page — `https://github.com/login` (live) | Clean; VT has no opinion about the presence of a login form at all — that's not what it measures | `LOW 0/100, confidence 60%`. PageCollector genuinely fetched the page and detected a real password field (`credential_form`, `SUPPORTS_THREAT`, conf 0.5) — the *identical* signal that would matter in a phishing case — but no `brand_domain_mismatch`, no `external_form_action`, no `cross_domain_redirect`, and a 93%-similarity historical match to KRISIS's own prior `github.com` investigation. Ten pieces of counter-evidence outweigh the one behavioral signal. This is the mechanism from row C, live, correctly *not* firing. |
| E | Legitimate artifact + urgent message — `"URGENT: verify your account now at https://www.wikipedia.org/login or it will be suspended"` (stored `case_500fdd393689`) | Two separate clean/near-clean VT lookups (`0/97`, `1/88`) on `wikipedia.org` | `LOW 9/100`. Top contributors are `urgency_language` and `credential_request` — both `source=message`, i.e. attributed to the *communication*, not to `wikipedia.org` the artifact. The artifact stays LOW; the score moves 9 points for the message context alone. Artifact risk and context risk are reported as distinct contributors, not merged into one undifferentiated number. |
| F | Suspicious artifact + benign wording — `"Hey, thought you'd find this funny: https://1inkedin.com"` (live, this session) | N/A (VT doesn't process message text) | `MEDIUM 45/100`. No `message`-sourced evidence fired at all (no urgency, no credential-request language — checked: the evidence list contains zero `source=message` items). The artifact-level `lookalike_domain` finding drives the score exactly as it did standalone (row B, 39) plus historical reinforcement (45). Harmless wording did not launder the infrastructure/identity finding. |
| G / brand-new | `"URGENT: Your account will be suspended! Verify now at http://secure-verify-account.test-portal.xyz/login..."` (stored `case_d461425d8d33`) | VT: *"has no data for this artifact"* — response_code 0, for both the URL and the domain | `INSUFFICIENT_EVIDENCE 13`, reason given verbatim: *"no threat-reputation source was available for this artifact, so the absence of malicious findings cannot be treated as evidence of safety."* Note the score (13) and the category disagree on purpose — message-level urgency/credential-request language still contributed 13 points, but the category refuses to call anything "LOW" when no reputation source ever answered. |
| H | Indicator-rotated structural match | VT: no relationship between two domains that share no IP, certificate, or nameserver — there is nothing for it to correlate | Two independent proofs: **(1) live, unprompted**, four different real seeds this session matched a *prior stored case* purely on shape, at 0% indicator overlap — see §2 table below (`g00gle.com`↔prior case, 82% structural / 0% indicator; `github.com`↔prior, 100%/0%; the `paypal-recover.example.com` case ↔ prior, 82%/0%). **(2)** the exact "confirmed-malicious-prior + rotated infra" scenario — different IPs, different certs, identical attack shape — is reproduced and mutation-tested at `tests/test_structural_patterns.py:94-108`: `indicator_similarity == 0.0`, `structural_similarity > 0`, matched on `signal+:identity:brand_lookalike`. |

---

## 2. Live proof of §H, unprompted, from real API responses this session

These four structural matches were not engineered for this document — they
are what four *unrelated* live/stored investigations, run for other rows of
this matrix, happened to match against in the case memory, with **zero**
shared IP/certificate/domain:

| Seed | Matched prior case (by shape only) | Structural similarity | Indicator similarity |
|---|---|---|---|
| `g00gle.com` | prior case, pattern `same_operator_variant + long_lived_domain` | 82% | **0%** |
| `github.com` | prior case, pattern `valid_tls_present + long_lived_domain` | 100% | **0%** |
| `paypal-recover.example.com` (from the message case) | prior case, pattern `valid_tls_present + long_lived_domain` | 82% | **0%** |
| `http://bit.ly/3xW9k2p` | prior case, pattern `same_operator_variant + valid_tls_present + long_lived_domain` | 39% | **0%** |

VirusTotal has no equivalent of this — it correlates URLs/IPs/domains it has
seen *together* before (shared resolution, shared hash), never "this
investigation had the same kind of shape as that one."

**Honest caveat, stated plainly:** every `prior_outcome` above reads
`unknown` — no case in this database had ever been marked
`confirmed_malicious`/`confirmed_benign` before this session, so per
`OUTCOME_TRUST` (`risk.py:58-65`) none of these matches were allowed to move
a score by more than a token amount (by design — an unvalidated resemblance
is a lead, not proof; this is the pattern-poisoning-resistance property, not
a bug). To close that loop for real rather than only in the unit test, this
session ran `krisis outcome case_a6407c045766 confirmed_malicious` against
the live `malware.wicar.org` case (§1, row A) — a fact independently true
(it's a public, deliberately-malicious antivirus test domain), not an
invented label. Future investigations that structurally resemble it now
carry a validated prior, and — per the mutation-tested rule at
`risk.py:373-390` — a ≥75% structural resemblance to it can no longer be
reported as LOW even with clean current reputation. No second live domain
was manufactured to force that rule to fire; doing so would mean standing up
real malicious-shaped infrastructure, which is out of scope here.

---

## 3. The four required experiments

**Experiment 1 — reputation absent, KRISIS finds risk anyway.**
Row B (`1inkedin.com`, VT 32/644 ≈ 5%, reads clean) → KRISIS MEDIUM 39,
driven entirely by verified identity impersonation. **Confirmed.**

**Experiment 2 — reputation exists, KRISIS contextualizes rather than
copies.** Row A (`malware.wicar.org`, VT 1528/9277 ≈ 16%) → KRISIS does not
escalate to CRITICAL/HIGH; it explains the one corroborating source and the
one piece of counter-evidence and lands MEDIUM 11 with a stated reason.
Separately, `paypa1.com` (stored, VT domain-aggregate 819/9086 ≈ 9%) →
KRISIS's identity layer found both `paypa1.com` and `paypal.com` registered
to PayPal Inc. (`same_operator_variant`, `CONTRADICTS_THREAT`) — a defensive
registration — and reports LOW *for that stated reason*, not by ignoring the
VT number. **Confirmed**, twice, in opposite directions (one case where
KRISIS is more cautious than the raw ratio suggests, one where it is less).

**Experiment 3 — VT unknown ≠ safe.** Row G: VT `response_code: 0` (no data)
→ KRISIS `INSUFFICIENT_EVIDENCE`, not LOW, with the reason spelled out.
**Confirmed.**

**Experiment 4 — historical structure survives indicator rotation.** §2
table (live, 0% indicator overlap, real structural matches) plus
`test_structural_patterns.py:94-108` (synthetic, mutation-tested, same
production `PatternMemory.find_similar` code path) for the confirmed-prior
variant. **Confirmed**, with the honest caveat above about validation state
prior to this session's `krisis outcome` call.

---

## 4. Case-level vs. artifact-level risk (§8)

Two real runs prove KRISIS keeps these separate rather than laundering one
into the other:

- **Legitimate artifact + suspicious message** (row E, `wikipedia.org`):
  artifact evidence stays clean; `urgency_language` and `credential_request`
  are attributed to `source=message` and move the score from 0 to 9 — not to
  MEDIUM, not to "wikipedia.org is malicious." The urgency is real and
  reported; the domain's own reputation is not spent to inflate it.
- **Suspicious artifact + benign message** (row F, `1inkedin.com` wrapped in
  "thought you'd find this funny"): zero message-level evidence fired, and
  the artifact-level MEDIUM verdict (39→45 with reinforcement) survived
  completely unlaundered by the harmless wording.

VirusTotal has no concept of "message" at all — this distinction does not
exist for it to get right or wrong.

---

## 5. Investigation trace as the differentiator (§9–10)

A real trace excerpt (`malware.wicar.org`, re-run to also demonstrate cache
behavior — see step 8):

```
1. indicator_extraction   seed=malware.wicar.org, seed_type=domain
2. provider_decision      dns: cached (277s old, within 3600s window)
6. provider_decision      tls: queried — request spent
7. collector_unavailable  tls: CERTIFICATE_VERIFY_FAILED — hostname mismatch
8. provider_decision      virustotal: cached (274s old, within 86400s window)
12-21. pivot_evaluated    5 IPs accepted, 2 IPs + 1 email + 1 hostname rejected
                          (max_pivots_per_entity reached — noisy fan-out cap)
24-45. provider_decision  virustotal: skipped ×5 — "below the value threshold
                          for a scarce provider (priority 0.52 < 0.70)"
47. correlation           support=1, contradict=1, neutral=24, diversity=1.0
48. coverage               reputation_checked=True, sources_unavailable=[tls]
49. risk_assessment        MEDIUM 11, confidence 62%, reason stated
52. case_stored             case_394a0951d816
```

This is what a reputation lookup cannot produce: not just a number, but
*what was checked, what was deliberately not spent and why, what failed and
was reported as failed rather than folded into "clean," and which single
piece of evidence the final number rests on.* VT's own dashboard shows
detections; it does not show "5 IPs were discovered and I declined to spend
a scarce lookup on any of them because none supported the threat
hypothesis" — that reasoning is KRISIS's, and it is exactly the kind of
statement an investigator needs to trust the number instead of just reading
it.

---

## 6. Verdict

**Not a wrapper.** Every row in §1 shows KRISIS's output diverging from a
plain VT read in a specific, explainable, evidence-grounded way — sometimes
more cautious than the ratio (row A), sometimes catching what the ratio
misses entirely (row B), sometimes refusing to let "unknown" pass as "safe"
(row G), sometimes structurally correlating cases VT has no mechanism to
relate at all (row H). None of these required inventing a scenario; four of
eight rows came from cases already sitting in the database from unrelated
prior work, and the rest cost three additional live API calls.

**What VirusTotal already does, and does well:** it is the strongest single
reputation signal KRISIS has (`TYPE_WEIGHTS["reputation"] = 1.0`, the
highest weight in the risk engine) and KRISIS does not attempt to replace
it — every row above still uses the real VT ratio as a load-bearing input.

**Where the overlap is real:** for an artifact VT already has strong,
unambiguous, corroborated detections on (not represented cleanly in this
run — everything sampled here was VT-ambiguous or VT-silent, which is the
harder and more interesting case), KRISIS and VT will often agree on
direction, if not on how the verdict is explained.

**Strongest single demonstration case:** row B / Experiment 1
(`1inkedin.com`) — VT reads it as essentially clean (5%), and KRISIS's only
disagreement is *entirely correct*: a verified homoglyph impersonation of
LinkedIn that no reputation engine had cause to flag yet.

**Remaining limitations, stated plainly (not new — already in
`README.md`'s scope section, reconfirmed here):**
- No live credential-phishing artifact was exercised end-to-end in this
  session (row C) — validated at the mutation-tested collector/risk-engine
  level only, not against real attacker infrastructure, by design.
- The historical-malicious floor (`risk.py:373-390`) was validated against
  one real confirmed prior (`malware.wicar.org`, marked this session) but
  not yet triggered by a second, independently-indicator-rotated live case —
  doing so honestly requires either waiting for a second real match to
  surface naturally or accepting the mutation-tested synthetic proof as
  sufficient, which is what this document does.
- `README.md`'s "flagged-but-uncorroborated → LOW" example (`malware.wicar.org`)
  is now stale prose: current behavior (confirmed live, row A) is
  `MEDIUM`, per the reputation-floor fix already landed in commit `070a9b5`.
  Worth a one-line README correction; not a functional gap.

**Next highest-value capability to prove** (not built now, per §16 —
this is a recommendation, not a gap requiring a code change): a second,
independently-sourced structurally-matching confirmed-malicious case,
reached organically through normal use (`krisis outcome` on a second real
investigation) rather than synthetically — that would be the first fully
live, end-to-end demonstration of indicator-rotation detection with two
*validated* human-confirmed priors instead of one, closing the last gap
between "the mechanism is correct" (proven here) and "the mechanism has
been exercised twice with real outcomes" (not yet true of this dataset).
