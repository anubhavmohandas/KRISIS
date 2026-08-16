"""
Identity / lookalike intelligence tests.

Motivated by a live run in which `paypa1.com` scored LOW / 0: KRISIS investigated
the infrastructure around the name and never looked at the name itself. The
fixture brand here is deliberately invented (`glorptech`) — nothing in KRISIS
knows any real brand, and a test that only passes for a famous domain would be
testing a hardcoded relationship rather than a mechanism.

Each test names the rule whose deletion must make it fail.
"""

import os
import shutil
import tempfile
import unittest

from krisis.collectors.identity_collector import IdentityCollector, facts_from_evidence
from krisis.core.correlation import CorrelationResult
from krisis.core.identity import canonical_label, candidates, decode_idn, mixed_script_label
from krisis.core.investigator import Investigator
from krisis.core.models import (
    Coverage, Entity, EntityType, Evidence, Independence, Polarity, RiskCategory,
)
from krisis.core.pivot_engine import InvestigationBudget
from krisis.core.risk import RiskEngine
from krisis.ai.explain import Explainer
from krisis.collectors.base import CollectorResult, EvidenceCollector
from krisis.memory.case_memory import CaseMemory
from krisis.memory.pattern_memory import PatternMemory
from krisis.memory.storage import Storage

REAL = "glorptech.com"        # the established identity
FAKE = "glorptech.com".replace("l", "1")   # g1orptech.com — a glyph substitution


def _ev(signal, value, entity_id="e1", source="probe"):
    return Evidence(
        source=source, entity_id=entity_id, signal=signal, value=value,
        evidence_type="infrastructure", polarity=Polarity.NEUTRAL, confidence=0.8,
        independence=Independence.INDEPENDENT,
    )


def facts(ips, age_days=None, org="", nameservers=()):
    """Evidence as the DNS/WHOIS collectors would emit it for one domain."""
    evidence = [_ev("a_record", list(ips))]
    if age_days is not None:
        evidence.append(_ev("domain_age_days", age_days))
    if org:
        evidence.append(_ev("registrant_org", org))
    if nameservers:
        evidence.append(_ev("ns_record", list(nameservers)))
    return evidence


class TestCandidateDerivation(unittest.TestCase):
    def test_a_digit_substitution_is_read_as_the_letter_it_imitates(self):
        derived = candidates(FAKE)
        self.assertIn(REAL, [c.value for c in derived])
        self.assertEqual(derived[0].method, "confusable_characters")

    def test_a_legitimate_name_derives_no_candidate_at_all(self):
        """The control. Delete the one-directional confusable mapping — map letters to
        digits as well as digits to letters — and every ordinary domain starts
        'impersonating' a variant of itself.
        """
        self.assertEqual(candidates(REAL), [])
        self.assertEqual(candidates("example.com"), [])
        self.assertEqual(candidates("some-university.ac.uk"), [])

    def test_both_readings_of_an_ambiguous_glyph_are_offered(self):
        """Keep only the most likely reading of an ambiguous glyph and the correct
        identity is never derived: '1' passes for both 'l' and 'i', so `netfl1x` has
        to be read as `netflix` and not only as `netfllx`. A live probe found exactly
        this miss. Each reading is verified separately, so the wrong one costs a DNS
        lookup rather than a wrong conclusion.
        """
        derived = [c.value for c in candidates("gl1ptech.com")]
        self.assertIn("gliptech.com", derived)
        self.assertIn("gllptech.com", derived)

    def test_a_cyrillic_homoglyph_is_resolved(self):
        self.assertEqual(canonical_label("glоrptech"), "glorptech")
        self.assertIn(REAL, [c.value for c in candidates("glоrptech.com")])

    def test_punycode_is_decoded_before_comparison(self):
        punycode = "glоrptech.com".encode("idna").decode()   # gl<cyrillic o>rptech.com
        self.assertTrue(punycode.startswith("xn--"), punycode)
        self.assertIn("о", decode_idn(punycode))
        self.assertIn(REAL, [c.value for c in candidates(punycode)])

    def test_decoration_wording_is_stripped_to_the_identity_it_decorates(self):
        derived = [c.value for c in candidates("glorptech-login.com")]
        self.assertIn(REAL, derived)

    def test_decoration_wording_with_no_separator_is_also_stripped(self):
        """Concatenated brand+decoration ("paypallogin.com", "accountpaypal.com")
        is at least as common a phishing naming pattern as the hyphenated form,
        and must not be invisible to derivation just because there is no '-'."""
        self.assertIn(REAL, [c.value for c in candidates("glorptechlogin.com")])
        self.assertIn(REAL, [c.value for c in candidates("accountglorptech.com")])
        self.assertIn(REAL, [c.value for c in candidates("glorptechsecure.com")])

    def test_a_short_generic_word_does_not_match_unseparated(self):
        """'id'/'log'/'pay' are real decoration tokens, but matching them inside
        an ordinary word by coincidence (no separator to anchor the split) would
        manufacture impersonation candidates out of unrelated domains."""
        self.assertEqual(candidates("rapid.com"), [])
        self.assertEqual(candidates("display.com"), [])

    def test_an_ordinary_compound_name_is_not_treated_as_decoration(self):
        """Delete the decoration-lexicon test in _core_tokens and 'my-company.com'
        becomes an impersonation of 'company.com', which is just a hostname."""
        self.assertEqual(candidates("my-company.com"), [])
        self.assertEqual(candidates("smith-and-sons.com"), [])

    def test_known_identities_unlock_cross_tld_candidates(self):
        derived = candidates("g1orptech.net", references={REAL})
        self.assertIn(REAL, [c.value for c in derived])

    def test_an_artifact_never_impersonates_itself(self):
        self.assertNotIn(REAL, [c.value for c in candidates(REAL, references={REAL})])

    def test_a_known_identity_placed_as_a_subdomain_label_is_derived(self):
        """'glorptech.attacker.example' places the known identity's own name as a
        subdomain label of an unrelated domain — a distinct deceptive pattern
        from every registrable-label mechanism above, and only reachable via a
        known reference (there is no natural suffix to pair a bare subdomain
        label with)."""
        derived = candidates("glorptech.attacker.example", references={REAL})
        self.assertIn(REAL, [c.value for c in derived])

    def test_a_decorated_subdomain_label_is_also_derived(self):
        derived = candidates("secure-glorptech.attacker.example", references={REAL})
        self.assertIn(REAL, [c.value for c in derived])

    def test_a_glyph_substituted_subdomain_label_is_also_derived(self):
        derived = candidates("g1orptech.attacker.example", references={REAL})
        self.assertIn(REAL, [c.value for c in derived])

    def test_no_reference_configured_means_no_subdomain_candidate(self):
        """Honest scope limit: unlike the registrable-label mechanisms, subdomain
        placement has no suffix of its own to pair a bare label with — it can only
        ever match a *known* reference."""
        self.assertEqual(candidates("glorptech.attacker.example"), [])

    def test_an_unrelated_subdomain_label_is_not_treated_as_impersonation(self):
        derived = candidates("www.attacker.example", references={REAL})
        self.assertNotIn(REAL, [c.value for c in derived])


class TestMixedScriptDetection(unittest.TestCase):
    """Script-*mixing within one label* is the deceptive pattern (Latin 'p' next
    to Cyrillic 'а'); a label written entirely in one script — including a
    non-Latin one — must never be flagged just for not being Latin."""

    def test_a_script_mixed_label_is_detected(self):
        self.assertTrue(mixed_script_label("pаypal"))  # Latin + one Cyrillic 'а'

    def test_a_pure_latin_label_is_not_flagged(self):
        self.assertFalse(mixed_script_label("paypal"))

    def test_a_pure_cyrillic_label_is_not_flagged(self):
        self.assertFalse(mixed_script_label("яндекс"))

    def test_a_pure_greek_label_is_not_flagged(self):
        self.assertFalse(mixed_script_label("αβγδ"))

    def test_digits_and_hyphens_do_not_count_as_a_second_script(self):
        self.assertFalse(mixed_script_label("glorptech-2024"))

    def test_collector_emits_mixed_script_domain_for_a_script_mixed_label(self):
        """Delete IdentityCollector._mixed_script_evidence and a script-mixed
        label that isn't in the curated confusable-character table gets no
        credit at all."""
        entity = Entity(value="pаypal-secure.example", type=EntityType.DOMAIN)
        evidence = IdentityCollector(probe=None, references=lambda: set()).collect(entity).evidence
        finding = next(e for e in evidence if e.signal == "mixed_script_domain")
        self.assertEqual(finding.polarity, Polarity.SUPPORTS_THREAT)
        self.assertEqual(finding.evidence_type, "identity")

    def test_collector_emits_nothing_for_a_pure_script_domain(self):
        entity = Entity(value="glorptech.com", type=EntityType.DOMAIN)
        evidence = IdentityCollector(probe=None, references=lambda: set()).collect(entity).evidence
        self.assertFalse([e for e in evidence if e.signal == "mixed_script_domain"])

    def test_a_bare_mixed_script_finding_does_not_force_the_verified_impersonation_floor(self):
        """mixed_script_domain is evidence_type='identity' like lookalike_domain,
        but unlike it, is unverified and names no external referent — its .value
        is the artifact's *own* label. Reusing risk.py's LOW-band impersonation
        floor for it would word the reason as 'imitates an established identity
        operated by someone else (<the artifact's own mixed label>)', which is
        simply false. Delete risk.py's VERIFIED_REFERENT_SIGNALS scoping (revert
        _categorize to call _identity_support instead of _verified_impersonation)
        and this test fails."""
        mixed_script = Evidence(
            source="identity", entity_id="e1", signal="mixed_script_domain", value=["aurбoratech"],
            evidence_type="identity", polarity=Polarity.SUPPORTS_THREAT, confidence=0.45,
            independence=Independence.INDEPENDENT,
        )
        clean_reputation = Evidence(
            source="virustotal", entity_id="e1", signal="no_detections", value=0,
            evidence_type="reputation", polarity=Polarity.NEUTRAL, confidence=0.3,
            independence=Independence.INDEPENDENT,
        )
        coverage = Coverage(
            attempted={"virustotal"}, available={"virustotal"}, evidence_types={"reputation"}
        )
        result = RiskEngine().score(
            CorrelationResult(supporting=[mixed_script], neutral=[clean_reputation], evidence_diversity=0.3),
            coverage=coverage,
        )
        self.assertNotIn("established identity operated by someone else", result.uncertainty.get("reason", ""))


class TestVerification(unittest.TestCase):
    """Derivation alone is a string observation; these are the checks that turn it
    into evidence, or refuse to."""

    def collector(self, probe_table):
        return IdentityCollector(
            probe=lambda entity: probe_table.get(entity.value, []),
            references=lambda: {REAL},
        )

    def collect(self, probe_table, seed=FAKE):
        entity = Entity(value=seed, type=EntityType.DOMAIN)
        return self.collector(probe_table).collect(entity).evidence

    @staticmethod
    def _for(evidence, referent):
        """The finding about one referent. An ambiguous glyph has several readings
        ('1' passes for both 'l' and 'i'), so each is verified separately and the
        assertions have to name which one they are about."""
        return next(e for e in evidence if e.value == referent)

    def test_an_established_referent_with_a_different_operator_is_evidence(self):
        evidence = self.collect({
            FAKE: facts(["203.0.113.9"], age_days=8, org="privacy service"),
            REAL: facts(["198.51.100.4"], age_days=4000, org="glorptech inc"),
        })
        finding = next(e for e in evidence if e.signal == "lookalike_domain")
        self.assertEqual(finding.polarity, Polarity.SUPPORTS_THREAT)
        self.assertEqual(finding.evidence_type, "identity")
        self.assertEqual(finding.value, REAL)
        self.assertIn("4000", finding.provenance)

    def test_a_referent_that_does_not_exist_is_not_impersonated(self):
        """Delete the resolves check and a registered-but-dark domain — old enough and
        owned by someone else — becomes proof of an impersonation of something nobody
        can actually reach.
        """
        evidence = self.collect({
            FAKE: facts(["203.0.113.9"], age_days=8),
            REAL: [_ev("domain_age_days", 4000)],   # WHOIS answers, DNS does not
        })
        self.assertEqual({e.signal for e in evidence}, {"lookalike_candidate"})
        self.assertEqual({e.polarity for e in evidence}, {Polarity.NEUTRAL})
        self.assertIn("does not resolve", self._for(evidence, REAL).provenance)

    def test_a_referent_with_no_data_at_all_is_not_impersonated(self):
        evidence = self.collect({FAKE: facts(["203.0.113.9"], age_days=8), REAL: []})
        self.assertEqual({e.signal for e in evidence}, {"lookalike_candidate"})

    def test_a_referent_no_older_than_the_artifact_settles_nothing(self):
        """Delete the age-margin check and KRISIS asserts a direction of imitation it
        cannot know — the older domain could be the imitation."""
        evidence = self.collect({
            FAKE: facts(["203.0.113.9"], age_days=3000),
            REAL: facts(["198.51.100.4"], age_days=3100),
        })
        self.assertEqual({e.signal for e in evidence}, {"lookalike_candidate"})
        self.assertIn("which imitates which", self._for(evidence, REAL).provenance)

    def test_a_recent_referent_is_not_an_established_identity(self):
        evidence = self.collect({
            FAKE: facts(["203.0.113.9"], age_days=5),
            REAL: facts(["198.51.100.4"], age_days=200),
        })
        self.assertEqual({e.signal for e in evidence}, {"lookalike_candidate"})
        self.assertIn("too new", self._for(evidence, REAL).provenance)

    def test_a_shared_operator_is_counter_evidence_not_evidence(self):
        """Delete same_operator and a brand's own defensive registration of its
        typosquat is reported as an attack on itself."""
        evidence = self.collect({
            FAKE: facts(["198.51.100.4"], age_days=900, org="glorptech inc"),
            REAL: facts(["198.51.100.4"], age_days=4000, org="glorptech inc"),
        })
        finding = self._for(evidence, REAL)
        self.assertEqual(finding.signal, "same_operator_variant")
        self.assertEqual(finding.polarity, Polarity.CONTRADICTS_THREAT)

    def test_a_shared_registrant_org_string_alone_does_not_prove_one_operator(self):
        """WHOIS 'Organization' is free text the registrant supplies; no registry
        verifies it. Treating a matching string as proof of common operatorship
        would let an attacker suppress a real impersonation finding just by typing
        the impersonated brand's name into a field nobody checks — this is the
        conflation KRISIS must not make between 'registration metadata resembles
        the brand' and 'verified same operator'. Restore same_operator() to treat
        an org-string match the same as a shared IP and this fails: the lookalike
        would disappear instead of merely picking up weak, discounted
        counter-evidence alongside it.
        """
        evidence = self.collect({
            FAKE: facts(["203.0.113.9"], age_days=900, org="glorptech inc"),
            REAL: facts(["198.51.100.4"], age_days=4000, org="glorptech inc"),
        })
        findings = [e for e in evidence if e.value == REAL]
        signals = {e.signal for e in findings}
        self.assertIn("lookalike_domain", signals, "an unverified org-name match erased the finding")
        lookalike = next(e for e in findings if e.signal == "lookalike_domain")
        self.assertEqual(lookalike.polarity, Polarity.SUPPORTS_THREAT)
        claimed = next(e for e in findings if e.signal == "claimed_registrant_org_match")
        self.assertEqual(claimed.polarity, Polarity.CONTRADICTS_THREAT)
        self.assertLess(claimed.confidence, lookalike.confidence)

    def test_a_shared_ip_alone_is_still_enough_to_show_one_operator(self):
        """Contrast with the org-string case above: a common resolved address is
        not self-reported, so it stays sufficient on its own to fully suppress the
        lookalike finding."""
        evidence = self.collect({
            FAKE: facts(["198.51.100.4"], age_days=900),
            REAL: facts(["198.51.100.4"], age_days=4000),
        })
        finding = self._for(evidence, REAL)
        self.assertEqual(finding.signal, "same_operator_variant")
        self.assertEqual(finding.polarity, Polarity.CONTRADICTS_THREAT)

    def test_an_unverifiable_candidate_stays_neutral(self):
        """No probe configured: the lead is still reported, but it moves nothing."""
        entity = Entity(value=FAKE, type=EntityType.DOMAIN)
        evidence = IdentityCollector(probe=None, references=lambda: {REAL}).collect(entity).evidence
        self.assertTrue(evidence)
        self.assertTrue(all(e.polarity == Polarity.NEUTRAL for e in evidence))

    def test_a_legitimate_domain_produces_no_identity_evidence(self):
        """Test C from the loop: the same mechanism that flags the typosquat must not
        flag the identity it imitates."""
        entity = Entity(value=REAL, type=EntityType.DOMAIN)
        result = self.collector({REAL: facts(["198.51.100.4"], age_days=4000)}).collect(entity)
        self.assertEqual(result.evidence, [])
        self.assertTrue(result.available)

    def test_facts_are_read_from_whichever_age_signal_whois_emitted(self):
        for signal in ("newly_registered_domain", "long_lived_domain", "domain_age_days"):
            parsed = facts_from_evidence([_ev(signal, 42)])
            self.assertEqual(parsed.age_days, 42, signal)


class TestRiskTreatmentOfIdentity(unittest.TestCase):
    def _identity(self):
        return Evidence(
            source="identity", entity_id="e1", signal="lookalike_domain", value=REAL,
            evidence_type="identity", polarity=Polarity.SUPPORTS_THREAT, confidence=0.9,
            independence=Independence.INDEPENDENT,
        )

    def _tls(self):
        return Evidence(
            source="tls", entity_id="e1", signal="valid_tls_present", value="Some CA",
            evidence_type="infrastructure", polarity=Polarity.CONTRADICTS_THREAT,
            confidence=0.25, independence=Independence.INDEPENDENT,
        )

    def _age(self):
        return Evidence(
            source="whois", entity_id="e1", signal="long_lived_domain", value=1200,
            evidence_type="registration", polarity=Polarity.CONTRADICTS_THREAT,
            confidence=0.55, independence=Independence.INDEPENDENT,
        )

    def _claimed_org(self):
        return Evidence(
            source="identity", entity_id="e1", signal="claimed_registrant_org_match", value=REAL,
            evidence_type="identity", polarity=Polarity.CONTRADICTS_THREAT,
            confidence=0.3, independence=Independence.INDEPENDENT,
        )

    def _cert_subject_org(self):
        return Evidence(
            source="tls", entity_id="e1", signal="certificate_subject_org_match", value=REAL,
            evidence_type="behavior", polarity=Polarity.CONTRADICTS_THREAT,
            confidence=0.5, independence=Independence.INDEPENDENT,
        )

    def test_an_impersonating_artifact_is_never_reported_as_low(self):
        """Delete the identity branch in RiskEngine._categorize and a verified
        typosquat with unremarkable infrastructure is reported as looking safe — the
        exact LOW/0 verdict that motivated this layer."""
        result = RiskEngine().score(
            CorrelationResult(supporting=[self._identity()], evidence_diversity=0.4)
        )
        self.assertLess(result.score, 30, "the fixture is a low-scoring case by design")
        self.assertEqual(result.category, RiskCategory.MEDIUM)
        self.assertIn("imitates", result.uncertainty["reason"])

    def test_a_valid_certificate_does_not_offset_an_identity_finding(self):
        """Delete _discount_narrow_contradictions and any phishing site can rebut
        'this imitates someone else' by presenting the certificate it already has."""
        engine = RiskEngine()
        alone = engine.score(CorrelationResult(supporting=[self._identity()], evidence_diversity=0.4))
        with_tls = engine.score(
            CorrelationResult(
                supporting=[self._identity()], contradicting=[self._tls()], evidence_diversity=0.4
            )
        )
        self.assertEqual(alone.score, with_tls.score)
        self.assertTrue(with_tls.uncertainty["discounted_counter_evidence"])
        self.assertEqual(
            len(with_tls.contradicting), 1,
            "the discounted item must still be reported to the reader",
        )

    def test_a_certificate_still_counts_against_an_ordinary_finding(self):
        """The discount is scoped to identity findings, not a blanket exemption."""
        engine = RiskEngine()
        infrastructure = Evidence(
            source="vt", entity_id="e1", signal="malicious_detection", value="4/70",
            evidence_type="reputation", polarity=Polarity.SUPPORTS_THREAT, confidence=0.9,
            independence=Independence.INDEPENDENT,
        )
        alone = engine.score(CorrelationResult(supporting=[infrastructure], evidence_diversity=0.4))
        with_tls = engine.score(
            CorrelationResult(
                supporting=[infrastructure], contradicting=[self._tls()], evidence_diversity=0.4
            )
        )
        self.assertLess(with_tls.score, alone.score)

    def test_domain_age_does_not_offset_an_identity_finding_either(self):
        """Same defect class as the certificate case, different signal: how long a
        domain has existed says nothing about who runs it, and identity_collector
        already confirmed the operator does not match before lookalike_domain was
        ever emitted. Delete 'long_lived_domain' from NARROW_CONTRADICTIONS and a
        years-old typosquat quietly scores lower than a freshly-registered one for
        no reason connected to who operates it."""
        engine = RiskEngine()
        alone = engine.score(CorrelationResult(supporting=[self._identity()], evidence_diversity=0.4))
        with_age = engine.score(
            CorrelationResult(
                supporting=[self._identity()], contradicting=[self._age()], evidence_diversity=0.4
            )
        )
        self.assertEqual(alone.score, with_age.score)
        self.assertTrue(with_age.uncertainty["discounted_counter_evidence"])
        self.assertEqual(
            len(with_age.contradicting), 1,
            "the discounted item must still be reported to the reader",
        )

    def test_a_claimed_registrant_org_match_does_not_offset_an_identity_finding(self):
        """Regression for the operator-verification conflation in
        identity_collector.same_operator(): a matching WHOIS registrant
        organization is self-reported and unverified, so it must not let a real
        lookalike score as though a verified same-operator variant suppressed it.
        Delete 'claimed_registrant_org_match' from NARROW_CONTRADICTIONS and an
        attacker who simply types the impersonated brand's name into their own
        WHOIS record dilutes the identity floor with a field nobody checks."""
        engine = RiskEngine()
        alone = engine.score(CorrelationResult(supporting=[self._identity()], evidence_diversity=0.4))
        with_claim = engine.score(
            CorrelationResult(
                supporting=[self._identity()], contradicting=[self._claimed_org()], evidence_diversity=0.4
            )
        )
        self.assertEqual(alone.score, with_claim.score)
        self.assertEqual(with_claim.category, RiskCategory.MEDIUM)
        self.assertTrue(with_claim.uncertainty["discounted_counter_evidence"])

    def test_a_certificate_subject_org_match_does_not_offset_an_identity_finding(self):
        """A CA-vetted subject organization confirms *some* real-world entity
        controls this endpoint — not that this artifact isn't impersonating a
        *different* brand elsewhere in its identity. A phishing site can hold a
        legitimate OV/EV certificate for a shell company while still imitating
        an unrelated target. Delete 'certificate_subject_org_match' from
        NARROW_CONTRADICTIONS and a lookalike domain with an unrelated OV cert
        dilutes the identity floor the same way a bare valid_tls_present
        already cannot."""
        engine = RiskEngine()
        alone = engine.score(CorrelationResult(supporting=[self._identity()], evidence_diversity=0.4))
        with_subject_org = engine.score(
            CorrelationResult(
                supporting=[self._identity()], contradicting=[self._cert_subject_org()],
                evidence_diversity=0.4,
            )
        )
        self.assertEqual(alone.score, with_subject_org.score)
        self.assertEqual(with_subject_org.category, RiskCategory.MEDIUM)
        self.assertTrue(with_subject_org.uncertainty["discounted_counter_evidence"])

    def test_certificate_subject_org_match_still_counts_against_an_ordinary_finding(self):
        """The discount is scoped to identity findings, not a blanket exemption."""
        engine = RiskEngine()
        infrastructure = Evidence(
            source="vt", entity_id="e1", signal="malicious_detection", value="4/70",
            evidence_type="reputation", polarity=Polarity.SUPPORTS_THREAT, confidence=0.9,
            independence=Independence.INDEPENDENT,
        )
        alone = engine.score(CorrelationResult(supporting=[infrastructure], evidence_diversity=0.4))
        with_subject_org = engine.score(
            CorrelationResult(
                supporting=[infrastructure], contradicting=[self._cert_subject_org()],
                evidence_diversity=0.4,
            )
        )
        self.assertLess(with_subject_org.score, alone.score)

    def test_domain_age_still_counts_against_an_ordinary_finding(self):
        """The discount is scoped to identity findings, not a blanket exemption —
        a long-lived domain is still legitimate counter-evidence for e.g. a raw
        VirusTotal detection, which age genuinely does argue against."""
        engine = RiskEngine()
        infrastructure = Evidence(
            source="vt", entity_id="e1", signal="malicious_detection", value="4/70",
            evidence_type="reputation", polarity=Polarity.SUPPORTS_THREAT, confidence=0.9,
            independence=Independence.INDEPENDENT,
        )
        alone = engine.score(CorrelationResult(supporting=[infrastructure], evidence_diversity=0.4))
        with_age = engine.score(
            CorrelationResult(
                supporting=[infrastructure], contradicting=[self._age()], evidence_diversity=0.4
            )
        )
        self.assertLess(with_age.score, alone.score)


class TestBankNamespaceSignal(unittest.TestCase):
    """India's RBI restricts the .bank.in namespace to regulated banks
    specifically to cut phishing (indicators.is_bank_in_namespace). Fixture
    institution is invented ('glorpbank'), same reasoning as REAL/FAKE above:
    nothing about a real bank may be hardcoded anywhere in this mechanism.
    """

    BANK = "glorpbank.bank.in"

    def collector(self):
        return IdentityCollector(probe=None, references=lambda: set())

    def test_a_domain_in_the_namespace_earns_contradicting_identity_evidence(self):
        """Delete IdentityCollector._bank_namespace_evidence and a legitimate bank
        domain gets no credit at all for sitting in the restricted namespace."""
        entity = Entity(value=self.BANK, type=EntityType.DOMAIN)
        evidence = self.collector().collect(entity).evidence
        finding = next(e for e in evidence if e.signal == "verified_bank_namespace")
        self.assertEqual(finding.polarity, Polarity.CONTRADICTS_THREAT)
        self.assertEqual(finding.evidence_type, "identity")

    def test_the_signal_does_not_fire_on_a_lookalike_of_the_namespace(self):
        for host in ("glorpbankonline.in", "glorpbank-secure.in", "glorpbank.bank.in.attacker.com"):
            evidence = self.collector().collect(Entity(value=host, type=EntityType.DOMAIN)).evidence
            self.assertFalse(
                [e for e in evidence if e.signal == "verified_bank_namespace"], host,
            )

    def test_namespace_credit_reduces_but_does_not_erase_an_impersonation_finding(self):
        """Section 10 of the design doc: .bank.in must materially help (section 9)
        without becoming an unquestionable-safe override. A genuine identity +
        credential-phishing finding on the same case must still out-argue it."""
        lookalike = Evidence(
            source="identity", entity_id="e1", signal="lookalike_domain", value="glorpbank.com",
            evidence_type="identity", polarity=Polarity.SUPPORTS_THREAT, confidence=0.8,
            independence=Independence.INDEPENDENT,
        )
        cred_form = Evidence(
            source="page", entity_id="e1", signal="credential_form", value={},
            evidence_type="behavior", polarity=Polarity.SUPPORTS_THREAT, confidence=0.5,
            independence=Independence.INDEPENDENT,
        )
        namespace_evidence = self.collector().collect(Entity(value=self.BANK, type=EntityType.DOMAIN)).evidence

        engine = RiskEngine()
        without_namespace = engine.score(
            CorrelationResult(supporting=[lookalike, cred_form], evidence_diversity=0.6)
        )
        with_namespace = engine.score(
            CorrelationResult(
                supporting=[lookalike, cred_form], contradicting=namespace_evidence,
                evidence_diversity=0.6,
            )
        )
        self.assertLess(with_namespace.score, without_namespace.score)
        self.assertNotEqual(with_namespace.category, RiskCategory.LOW)


# -- end-to-end: identity becomes a graph edge --------------------------------

class ProbeDNS(EvidenceCollector):
    name = "dns"
    supports = ("domain",)
    TABLE = {FAKE: ["203.0.113.9"], REAL: ["198.51.100.4"]}

    def collect(self, entity):
        ips = self.TABLE.get(entity.value)
        if not ips:
            return CollectorResult(evidence=[], available=False, note="NXDOMAIN")
        return CollectorResult(evidence=[_ev("a_record", ips, entity.id, "dns")], available=True)


class ProbeWHOIS(EvidenceCollector):
    name = "whois"
    supports = ("domain",)
    AGES = {FAKE: 6, REAL: 4200}

    def collect(self, entity):
        age = self.AGES.get(entity.value)
        if age is None:
            return CollectorResult(evidence=[], available=False, note="no record")
        signal = "newly_registered_domain" if age < 30 else "long_lived_domain"
        evidence = [
            Evidence(
                source="whois", entity_id=entity.id, signal=signal, value=age,
                evidence_type="registration",
                polarity=Polarity.SUPPORTS_THREAT if age < 30 else Polarity.CONTRADICTS_THREAT,
                confidence=0.6, independence=Independence.INDEPENDENT,
            )
        ]
        return CollectorResult(evidence=evidence, available=True)


class TestIdentityBecomesAPivot(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        storage = Storage(os.path.join(self.tmp, "identity.db"))
        self.pattern_memory = PatternMemory(storage)
        self.case_memory = CaseMemory(storage, self.pattern_memory)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _investigator(self):
        dns, whois = ProbeDNS(), ProbeWHOIS()

        def probe(entity):
            evidence = []
            for collector in (dns, whois):
                evidence.extend(collector.collect(entity).evidence)
            return evidence

        return Investigator(
            collectors=[dns, whois, IdentityCollector(probe=probe, references=lambda: {REAL})],
            case_memory=self.case_memory,
            pattern_memory=self.pattern_memory,
            budget=InvestigationBudget(max_depth=2, max_entities=15, max_external_calls=40),
            explainer=Explainer(use_llm=False),
        )

    def test_the_identity_relationship_enters_the_graph(self):
        """Delete the 'lookalike_domain' PIVOT_RULE and the impersonated identity stays
        an isolated string instead of a node the investigation can reason about."""
        case, _ = self._investigator().investigate(FAKE)
        graph = self._investigator().last_graph  # noqa: F841  (kept for symmetry)

        edges = [r for r in case.relationships.values() if r.relation_type == "looks_like"]
        self.assertTrue(edges, "expected a looks_like edge to the impersonated identity")
        target = case.entities[edges[0].target_entity_id]
        self.assertEqual(target.value, REAL)

    def test_a_widely_impersonated_identity_is_not_dismissed_as_commodity(self):
        """Delete IDENTITY_RELATIONS from the commodity test in the pivot engine and
        this fails. An identity that shows up in many unrelated investigations does so
        *because* it is worth impersonating — the ordinary "seen everywhere, therefore
        uninteresting" rule would delete the strongest edge in exactly the cases where
        identity matters most.
        """
        for i in range(4):
            self.pattern_memory.storage.record_indicator(
                case_id=f"case_prior_{i}", entity_type="domain", value=REAL,
                seed=f"unrelated-{i}.example", outcome=None, risk_category="LOW",
                created_at="2026-01-01T00:00:00+00:00",
            )
        case, _ = self._investigator().investigate(FAKE)
        self.assertTrue(
            [r for r in case.relationships.values() if r.relation_type == "looks_like"],
            "the identity edge was suppressed as commodity infrastructure",
        )

    def test_the_typosquat_is_not_reported_as_low_risk(self):
        case, _ = self._investigator().investigate(FAKE)
        self.assertNotEqual(case.risk.category, RiskCategory.LOW)
        self.assertTrue(
            any(e.evidence_type == "identity" and e.polarity == Polarity.SUPPORTS_THREAT
                for e in case.evidence.values())
        )

    def test_the_legitimate_domain_is_not_flagged_by_the_same_mechanism(self):
        case, _ = self._investigator().investigate(REAL)
        self.assertFalse(
            [e for e in case.evidence.values() if e.evidence_type == "identity"
             and e.polarity == Polarity.SUPPORTS_THREAT],
            "the identity mechanism must not fire on the identity being imitated",
        )


if __name__ == "__main__":
    unittest.main()
