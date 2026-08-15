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
from krisis.core.identity import canonical_label, candidates, decode_idn
from krisis.core.investigator import Investigator
from krisis.core.models import (
    Entity, EntityType, Evidence, Independence, Polarity, RiskCategory,
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

    def test_a_shared_registrant_alone_is_enough_to_show_one_operator(self):
        evidence = self.collect({
            FAKE: facts(["203.0.113.9"], age_days=900, org="glorptech inc"),
            REAL: facts(["198.51.100.4"], age_days=4000, org="glorptech inc"),
        })
        self.assertEqual(self._for(evidence, REAL).polarity, Polarity.CONTRADICTS_THREAT)

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
