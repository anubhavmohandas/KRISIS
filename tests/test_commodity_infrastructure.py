"""
Tests for commodity-infrastructure suppression.

Without this, any two organizations that happen to use the same mail vendor,
CDN or DNS host get reported as sharing infrastructure — and because those
vendor IPs land in indicator memory, every future investigation touching that
vendor matches them too. The failure compounds: one popular vendor is enough to
merge thousands of unrelated artifacts into a single fake "cluster".
"""

from __future__ import annotations

import os
import tempfile
import unittest

from krisis.core.graph import EntityGraph
from krisis.core.indicators import registrable_domain, same_organization
from krisis.core.models import Case, Entity, EntityType, Evidence, Polarity
from krisis.core.pivot_engine import InvestigationBudget, PivotEngine
from krisis.memory.case_memory import CaseMemory
from krisis.memory.pattern_memory import PatternMemory
from krisis.memory.storage import Storage


class TestRegistrableDomain(unittest.TestCase):
    def test_plain_domains(self):
        self.assertEqual(registrable_domain("github.com"), "github.com")
        self.assertEqual(registrable_domain("www.github.com"), "github.com")
        self.assertEqual(registrable_domain("a.b.c.github.com"), "github.com")

    def test_multi_label_public_suffixes(self):
        self.assertEqual(registrable_domain("www.bbc.co.uk"), "bbc.co.uk")
        self.assertEqual(registrable_domain("ns-1707.awsdns-21.co.uk"), "awsdns-21.co.uk")

    def test_trailing_dot_and_case_are_normalized(self):
        self.assertEqual(registrable_domain("GitHub.COM."), "github.com")

    def test_ip_addresses_are_their_own_identity(self):
        self.assertEqual(registrable_domain("20.207.73.82"), "20.207.73.82")

    def test_empty_input_is_not_an_organization_match(self):
        self.assertFalse(same_organization("", ""))
        self.assertFalse(same_organization("github.com", ""))

    def test_same_organization(self):
        self.assertTrue(same_organization("github.com", "mail.github.com"))
        self.assertFalse(same_organization("github.com", "github-com.mail.protection.outlook.com"))


def _mx_evidence(entity_id, value):
    return Evidence(source="dns", entity_id=entity_id, signal="mx_record", value=[value],
                    evidence_type="infrastructure", confidence=0.9)


def _a_evidence(entity_id, value):
    return Evidence(source="dns", entity_id=entity_id, signal="a_record", value=[value],
                    evidence_type="infrastructure", confidence=0.9)


class TestPivotCommodityPenalty(unittest.TestCase):
    def setUp(self):
        self.engine = PivotEngine(InvestigationBudget())
        self.seed = Entity(value="github.com", type=EntityType.DOMAIN, depth=0)

    def test_third_party_mail_server_is_flagged_and_downweighted(self):
        pivots = self.engine.generate(
            self.seed, [_mx_evidence(self.seed.id, "github-com.mail.protection.outlook.com")]
        )
        self.assertEqual(len(pivots), 1)
        self.assertTrue(pivots[0].shared_infrastructure)
        self.assertLess(pivots[0].priority, 0.2)
        self.assertIn("third-party", pivots[0].reason)

    def test_own_mail_server_is_not_penalized(self):
        pivots = self.engine.generate(self.seed, [_mx_evidence(self.seed.id, "mail.github.com")])
        self.assertFalse(pivots[0].shared_infrastructure)
        self.assertGreater(pivots[0].priority, 0.2)

    def test_direct_a_record_is_never_treated_as_commodity(self):
        """Resolution is a real property of the target, not a rented service."""
        pivots = self.engine.generate(self.seed, [_a_evidence(self.seed.id, "20.207.73.82")])
        self.assertFalse(pivots[0].shared_infrastructure)

    def test_rejection_reason_explains_the_investigative_judgement(self):
        pivots = self.engine.generate(
            self.seed, [_mx_evidence(self.seed.id, "x.mail.protection.outlook.com")]
        )
        decided = self.engine.accept_or_reject(pivots[0], current_depth_count=0)
        self.assertEqual(decided.status, "rejected")
        self.assertIn("third-party", decided.rejection_reason)

    def test_indicator_seen_across_many_prior_cases_is_treated_as_commodity(self):
        """Cold-start structural rules cannot catch every vendor; observation does."""
        engine = PivotEngine(InvestigationBudget(), case_count_lookup=lambda t, v: 12)
        pivots = engine.generate(self.seed, [_a_evidence(self.seed.id, "203.0.113.7")])
        self.assertTrue(pivots[0].shared_infrastructure)
        self.assertIn("12 unrelated prior investigations", pivots[0].reason)

    def test_lookup_failure_is_not_fatal(self):
        def boom(entity_type, value):
            raise RuntimeError("storage down")

        engine = PivotEngine(InvestigationBudget(), case_count_lookup=boom)
        pivots = engine.generate(self.seed, [_a_evidence(self.seed.id, "203.0.113.7")])
        self.assertEqual(len(pivots), 1)
        self.assertFalse(pivots[0].shared_infrastructure)


class TestGraphFlagResolution(unittest.TestCase):
    def test_a_genuine_route_clears_the_commodity_flag(self):
        graph = EntityGraph()
        graph.add_entity(Entity(value="1.2.3.4", type=EntityType.IP, depth=2,
                                shared_infrastructure=True))
        # rediscovered as a direct A record of the seed
        merged = graph.add_entity(Entity(value="1.2.3.4", type=EntityType.IP, depth=1,
                                         shared_infrastructure=False))
        self.assertFalse(merged.shared_infrastructure)
        self.assertEqual(merged.depth, 1)

    def test_commodity_flag_survives_rediscovery_by_another_commodity_route(self):
        graph = EntityGraph()
        graph.add_entity(Entity(value="1.2.3.4", type=EntityType.IP, depth=2,
                                shared_infrastructure=True))
        merged = graph.add_entity(Entity(value="1.2.3.4", type=EntityType.IP, depth=3,
                                         shared_infrastructure=True))
        self.assertTrue(merged.shared_infrastructure)


class TestCommodityInfraDoesNotPoisonMemory(unittest.TestCase):
    def setUp(self):
        self.db = os.path.join(tempfile.mkdtemp(), "commodity.db")
        self.storage = Storage(self.db)
        self.pattern_memory = PatternMemory(self.storage)
        self.case_memory = CaseMemory(self.storage, self.pattern_memory)

    def _corp_case(self, seed):
        """A benign company using a shared mail vendor, plus one IP it really owns."""
        case = Case(seed=seed, seed_type=EntityType.DOMAIN)
        for entity in [
            Entity(value=f"{seed}-mail.protection.outlook.com", type=EntityType.HOSTNAME,
                   depth=1, shared_infrastructure=True),
            Entity(value="52.101.11.15", type=EntityType.IP, depth=2,
                   shared_infrastructure=True),
            Entity(value="52.101.40.24", type=EntityType.IP, depth=2,
                   shared_infrastructure=True),
            Entity(value=f"203.0.113.{len(seed)}", type=EntityType.IP, depth=1),
        ]:
            case.entities[entity.id] = entity
        return case

    def test_vendor_infrastructure_is_not_recorded_as_an_indicator(self):
        self.case_memory.save(self._corp_case("bigcorp.com"))
        values = {
            row["value"]
            for row in self.storage.find_indicator_matches("ip", "52.101.11.15")
        }
        self.assertEqual(self.storage.find_indicator_matches("ip", "52.101.11.15"), [])
        self.assertTrue(self.storage.find_indicator_matches("ip", "203.0.113.11"))
        self.assertEqual(values, set())

    def test_unrelated_companies_sharing_a_mail_vendor_do_not_match(self):
        self.case_memory.save(self._corp_case("bigcorp.com"))

        graph = EntityGraph()
        graph.add_entity(Entity(value="unrelated-shop.net", type=EntityType.DOMAIN, depth=0))
        graph.add_entity(Entity(value="unrelated-shop-mail.protection.outlook.com",
                                type=EntityType.HOSTNAME, depth=1, shared_infrastructure=True))
        graph.add_entity(Entity(value="52.101.11.15", type=EntityType.IP, depth=2,
                                shared_infrastructure=True))
        graph.add_entity(Entity(value="52.101.40.24", type=EntityType.IP, depth=2,
                                shared_infrastructure=True))

        matches = self.pattern_memory.find_similar(graph, [], exclude_seed="unrelated-shop.net")
        self.assertEqual(matches, [], f"unrelated orgs matched on vendor infra: {matches}")

    def test_legacy_indicators_recorded_before_the_fix_still_do_not_match(self):
        """Defence in depth for the matching side.

        Databases written before commodity suppression existed already contain vendor
        IPs as indicators. Excluding them only at record time would leave those rows
        matching forever, so the query side must skip commodity entities too.
        """
        self.storage.record_indicator(
            case_id="case_legacy", entity_type="ip", value="52.101.11.15",
            seed="legacy-corp.com", outcome=None, risk_category="LOW",
            created_at="2026-01-01T00:00:00+00:00",
        )
        # sanity: the legacy row really is there and is matchable in principle
        self.assertTrue(self.storage.find_indicator_matches("ip", "52.101.11.15"))

        graph = EntityGraph()
        graph.add_entity(Entity(value="newshop.example", type=EntityType.DOMAIN, depth=0))
        graph.add_entity(Entity(value="52.101.11.15", type=EntityType.IP, depth=2,
                                shared_infrastructure=True))

        matches = self.pattern_memory.find_similar(graph, [], exclude_seed="newshop.example")
        self.assertEqual(matches, [], f"matched a legacy commodity indicator: {matches}")

    def test_genuinely_shared_hosting_still_matches(self):
        """The suppression must not blind KRISIS to real infrastructure overlap."""
        self.case_memory.save(self._corp_case("bigcorp.com"))

        graph = EntityGraph()
        graph.add_entity(Entity(value="lookalike.example", type=EntityType.DOMAIN, depth=0))
        # same non-commodity IP the prior case actually owned
        graph.add_entity(Entity(value="203.0.113.11", type=EntityType.IP, depth=1))

        matches = self.pattern_memory.find_similar(graph, [], exclude_seed="lookalike.example")
        self.assertTrue(matches, "a real shared-IP relationship should still be reported")


def _registrant_email_evidence(entity_id, value):
    return Evidence(source="whois", entity_id=entity_id, signal="registrant_email",
                    value=value, evidence_type="registration", confidence=0.7)


def _registrar_domain_evidence(entity_id, value):
    return Evidence(source="whois", entity_id=entity_id, signal="registrar_domain",
                    value=value, evidence_type="registration", confidence=0.6)


class TestRegistrarRoleMailbox(unittest.TestCase):
    """A registrar's own contact address is published for every domain it sells.

    Observed live: github.com and google.com both return
    abusecomplaints@markmonitor.com. Indicator memory weights `email` at 0.4 —
    second only to certificates — so treating it as distinguishing clusters two
    unrelated organizations by nothing more than who sold them the domain.
    """

    def setUp(self):
        self.engine = PivotEngine(InvestigationBudget())
        self.seed = Entity(value="github.com", type=EntityType.DOMAIN, depth=0)

    def test_registrar_mailbox_is_flagged_and_downweighted(self):
        pivots = self.engine.generate(self.seed, [
            _registrant_email_evidence(self.seed.id, "abusecomplaints@markmonitor.com"),
            _registrar_domain_evidence(self.seed.id, "markmonitor.com"),
        ])
        email_pivot = next(p for p in pivots if p.entity_type == EntityType.EMAIL)
        self.assertTrue(email_pivot.shared_infrastructure)
        self.assertIn("registrar role mailbox", email_pivot.reason)
        self.assertLess(email_pivot.priority, 0.2)

    def test_registrant_mailbox_elsewhere_keeps_full_priority(self):
        """The fix must stay narrow: a mailbox reused across suspicious registrations
        is one of the strongest links WHOIS offers, and must not be suppressed."""
        pivots = self.engine.generate(self.seed, [
            _registrant_email_evidence(self.seed.id, "attacker@protonmail.com"),
            _registrar_domain_evidence(self.seed.id, "namecheap.com"),
        ])
        email_pivot = next(p for p in pivots if p.entity_type == EntityType.EMAIL)
        self.assertFalse(email_pivot.shared_infrastructure)
        self.assertGreater(email_pivot.priority, 0.2)
        self.assertEqual(
            self.engine.accept_or_reject(email_pivot, current_depth_count=0).status, "accepted"
        )

    def test_subdomain_of_registrar_still_counts_as_the_registrar(self):
        pivots = self.engine.generate(self.seed, [
            _registrant_email_evidence(self.seed.id, "abuse@corp.mail.markmonitor.com"),
            _registrar_domain_evidence(self.seed.id, "markmonitor.com"),
        ])
        email_pivot = next(p for p in pivots if p.entity_type == EntityType.EMAIL)
        self.assertTrue(email_pivot.shared_infrastructure)

    def test_missing_registrar_domain_does_not_penalize(self):
        """Registries that name the registrar only by company name give nothing to
        compare against; guessing would suppress real leads."""
        pivots = self.engine.generate(
            self.seed, [_registrant_email_evidence(self.seed.id, "abusecomplaints@markmonitor.com")]
        )
        email_pivot = next(p for p in pivots if p.entity_type == EntityType.EMAIL)
        self.assertFalse(email_pivot.shared_infrastructure)

    def test_unrelated_orgs_sharing_a_registrar_mailbox_do_not_cluster(self):
        """End-to-end: the real github.com / google.com collision must not become
        a historical infrastructure match."""
        db = os.path.join(tempfile.mkdtemp(), "registrar.db")
        storage = Storage(db)
        pattern_memory = PatternMemory(storage)
        case_memory = CaseMemory(storage, pattern_memory)

        prior = Case(seed="google.com", seed_type=EntityType.DOMAIN)
        for entity in [
            Entity(value="abusecomplaints@markmonitor.com", type=EntityType.EMAIL,
                   depth=1, shared_infrastructure=True),
            Entity(value="142.250.180.14", type=EntityType.IP, depth=1),
        ]:
            prior.entities[entity.id] = entity
        case_memory.save(prior)

        graph = EntityGraph()
        graph.add_entity(Entity(value="github.com", type=EntityType.DOMAIN, depth=0))
        graph.add_entity(Entity(value="abusecomplaints@markmonitor.com", type=EntityType.EMAIL,
                                depth=1, shared_infrastructure=True))

        matches = pattern_memory.find_similar(graph, [], exclude_seed="github.com")
        self.assertEqual(matches, [], f"unrelated orgs clustered by registrar mailbox: {matches}")


class TestRegistrarDomainDerivation(unittest.TestCase):
    def test_derives_from_registrar_url(self):
        from krisis.collectors.whois_collector import _registrar_domain

        self.assertEqual(
            _registrar_domain({"registrar_url": "http://www.markmonitor.com"}), "markmonitor.com"
        )

    def test_falls_back_to_whois_server(self):
        from krisis.collectors.whois_collector import _registrar_domain

        self.assertEqual(
            _registrar_domain({"whois_server": "whois.namecheap.com"}), "namecheap.com"
        )

    def test_company_name_only_yields_nothing_to_compare(self):
        from krisis.collectors.whois_collector import _registrar_domain

        self.assertEqual(_registrar_domain({"registrar": "MarkMonitor, Inc."}), "")


if __name__ == "__main__":
    unittest.main()
