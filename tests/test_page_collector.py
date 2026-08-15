"""
URL-intent classification (krisis/core/url_intent.py) and the page/redirect
collector (krisis/collectors/page_collector.py) — the "what does this URL
actually do" layer described in the project design doc's SECURITY-SIGNAL LAYER
section. Covers both the pure classification module and the collector that
uses it, the same way test_identity.py covers core/identity.py alongside
collectors/identity_collector.py.

Fixture identities are invented ("GlorpTech") — nothing here knows any real
brand. Each test names the rule whose deletion should make it fail.
"""

from __future__ import annotations

import unittest
from unittest import mock

from krisis.collectors.page_collector import (
    PageCollector, _check_hop, _SchemeError, _SSRFError, safe_fetch,
)
from krisis.core.models import Entity, EntityType, Polarity
from krisis.core.url_intent import classify


def _public_addrinfo(*_a, **_kw):
    return [(2, 1, 6, "", ("93.184.216.34", 0))]


def _private_addrinfo(*_a, **_kw):
    return [(2, 1, 6, "", ("10.0.0.5", 0))]


def _mock_dns(side_effect=_public_addrinfo):
    return mock.patch("krisis.collectors.page_collector.socket.getaddrinfo", side_effect=side_effect)


class _FakeResponse:
    def __init__(self, status_code=200, headers=None, body=b"", encoding="utf-8"):
        self.status_code = status_code
        self.headers = headers or {}
        self._body = body
        self.encoding = encoding

    def iter_content(self, chunk_size=8192):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i : i + chunk_size]

    def close(self):
        pass


def _redirect(location, status=302):
    return _FakeResponse(status_code=status, headers={"Location": location})


def _page(body, status=200):
    return _FakeResponse(status_code=status, body=body.encode("utf-8"))


def _collect(url, responses):
    with _mock_dns(), mock.patch("requests.get", side_effect=responses):
        return PageCollector().collect(Entity(value=url, type=EntityType.URL))


class TestUrlIntentClassification(unittest.TestCase):
    def test_login_path_is_authentication_intent(self):
        found = classify("https://example.test/login")
        self.assertIn("authentication_intent", found)
        self.assertIn("login", found["authentication_intent"])

    def test_payment_path_is_financial_intent(self):
        found = classify("https://example.test/account/payment?method=card")
        self.assertIn("financial_intent", found)

    def test_ordinary_path_produces_no_intent(self):
        self.assertEqual(classify("https://example.test/articles/2024/summer-recipes"), {})

    def test_no_false_positive_on_substring_inside_a_longer_word(self):
        # "logins" as a whole path segment is not the token "login" — token
        # matching is on split segments, not substring search.
        found = classify("https://example.test/catalogins/item")
        self.assertEqual(found, {})


class TestSSRFAndSchemeGuard(unittest.TestCase):
    def test_private_address_is_rejected(self):
        with _mock_dns(side_effect=_private_addrinfo):
            with self.assertRaises(_SSRFError):
                _check_hop("http://internal.test/x")

    def test_public_address_is_accepted(self):
        with _mock_dns():
            _check_hop("http://example.test/x")  # must not raise

    def test_non_http_scheme_is_rejected(self):
        with self.assertRaises(_SchemeError):
            _check_hop("file:///etc/passwd")

    def test_redirect_hop_to_a_non_http_scheme_aborts_the_fetch(self):
        with _mock_dns(), mock.patch(
            "requests.get", side_effect=[_redirect("javascript:alert(1)")]
        ):
            result = safe_fetch("http://example.test/start")
        self.assertTrue(result.error)
        self.assertIn("scheme", result.error)

    def test_redirect_to_a_private_address_is_rejected_even_mid_chain(self):
        with _mock_dns(side_effect=[_public_addrinfo(), _private_addrinfo()]), mock.patch(
            "requests.get", side_effect=[_redirect("http://internal.test/x")]
        ):
            result = safe_fetch("http://example.test/start")
        self.assertTrue(result.error)


class TestRedirectLoopAndDepth(unittest.TestCase):
    def test_a_redirect_loop_is_detected_rather_than_followed_forever(self):
        with _mock_dns(), mock.patch(
            "requests.get", side_effect=[_redirect("http://example.test/a")] * 2
        ):
            result = safe_fetch("http://example.test/a")
        self.assertIn("loop", result.error)

    def test_a_chain_deeper_than_the_limit_is_refused_not_followed(self):
        hops = [_redirect(f"http://example.test/{i+1}") for i in range(6)]
        with _mock_dns(), mock.patch("requests.get", side_effect=hops):
            result = safe_fetch("http://example.test/0")
        self.assertIn("max redirect depth", result.error)


class TestUnavailableIsNotClean(unittest.TestCase):
    def test_a_connection_failure_reports_unavailable_not_clean(self):
        import requests

        with _mock_dns(), mock.patch("requests.get", side_effect=requests.ConnectionError("refused")):
            result = _collect("http://example.test/", [])
        self.assertFalse(result.available)
        self.assertTrue(result.note)


class TestRedirectChainEvidence(unittest.TestCase):
    def test_a_cross_domain_redirect_chain_is_reported_as_evidence(self):
        responses = [
            _redirect("http://step2.test/x"),
            _page("<html><head><title>Landing</title></head><body></body></html>"),
        ]
        result = _collect("http://example.test/start", responses)
        signals = {e.signal: e for e in result.evidence}
        self.assertIn("redirect_chain", signals)
        self.assertIn("redirect_target", signals)
        self.assertEqual(signals["redirect_target"].value, "http://step2.test/x")
        self.assertIn("cross_domain_redirect", signals)
        self.assertEqual(signals["cross_domain_redirect"].polarity, Polarity.SUPPORTS_THREAT)

    def test_a_same_site_redirect_does_not_claim_cross_domain(self):
        responses = [
            _redirect("http://example.test/final"),
            _page("<html><head><title>Final</title></head><body></body></html>"),
        ]
        result = _collect("http://example.test/start", responses)
        self.assertNotIn("cross_domain_redirect", {e.signal for e in result.evidence})


class TestCredentialFormDetection(unittest.TestCase):
    BENIGN_LOGIN_PAGE = """
    <html><head><title>Sign in - Example</title></head><body>
    <form action="/login" method="post">
      <input type="text" name="username">
      <input type="password" name="password">
    </form>
    </body></html>
    """

    def test_a_benign_same_domain_login_form_is_not_flagged_as_suspicious(self):
        result = _collect("http://example.test/login", [_page(self.BENIGN_LOGIN_PAGE)])
        signals = {e.signal: e for e in result.evidence}
        self.assertIn("credential_form", signals)
        self.assertNotIn("external_form_action", signals)
        self.assertNotIn("brand_domain_mismatch", signals)

    def test_a_password_field_is_required_to_flag_credential_form(self):
        no_password = """
        <html><head><title>Newsletter</title></head><body>
        <form action="/subscribe"><input type="email" name="email"></form>
        </body></html>
        """
        result = _collect("http://example.test/", [_page(no_password)])
        self.assertNotIn("credential_form", {e.signal for e in result.evidence})

    def test_two_forms_one_external_one_not_are_not_conflated(self):
        """Regression for form-scoping: a real (same-domain) login form and an
        unrelated external newsletter form on the same page must not be misread
        as one form that is both credential-collecting and externally-submitting."""
        page = """
        <html><head><title>GlorpTech</title></head><body>
        <form action="/login" method="post">
          <input type="text" name="username">
          <input type="password" name="password">
        </form>
        <form action="https://newsletter.external.test/subscribe" method="post">
          <input type="email" name="email">
        </form>
        </body></html>
        """
        result = _collect("http://glorptech.test/", [_page(page)])
        signals = {e.signal for e in result.evidence}
        self.assertIn("credential_form", signals)
        self.assertNotIn("external_form_action", signals)

    def test_an_external_form_action_on_the_credential_form_itself_is_flagged(self):
        page = """
        <html><head><title>GlorpTech</title></head><body>
        <form action="https://attacker-collect.test/submit" method="post">
          <input type="text" name="username">
          <input type="password" name="password">
        </form>
        </body></html>
        """
        result = _collect("http://glorptech.test/", [_page(page)])
        signals = {e.signal: e for e in result.evidence}
        self.assertIn("external_form_action", signals)
        self.assertEqual(signals["external_form_action"].polarity, Polarity.SUPPORTS_THREAT)


class TestBrandDomainMismatch(unittest.TestCase):
    def test_a_matching_title_and_domain_produce_no_mismatch(self):
        page = '<html><head><title>Sign in - Example</title></head><body></body></html>'
        result = _collect("http://example.test/", [_page(page)])
        self.assertNotIn("brand_domain_mismatch", {e.signal for e in result.evidence})

    def test_a_claimed_org_name_unrelated_to_the_domain_is_neutral_without_a_credential_form(self):
        page = (
            '<html><head><meta property="og:site_name" content="GlorpTech">'
            "<title>Welcome</title></head><body>no forms here</body></html>"
        )
        result = _collect("http://totally-unrelated-xyz.test/", [_page(page)])
        signals = {e.signal: e for e in result.evidence}
        self.assertIn("brand_domain_mismatch", signals)
        self.assertEqual(signals["brand_domain_mismatch"].polarity, Polarity.NEUTRAL)

    def test_the_same_mismatch_becomes_supporting_once_a_credential_form_is_present(self):
        page = (
            '<html><head><meta property="og:site_name" content="GlorpTech"></head><body>'
            '<form action="/login" method="post">'
            '<input type="text" name="username"><input type="password" name="password">'
            "</form></body></html>"
        )
        result = _collect("http://totally-unrelated-xyz.test/", [_page(page)])
        signals = {e.signal: e for e in result.evidence}
        self.assertIn("brand_domain_mismatch", signals)
        self.assertEqual(signals["brand_domain_mismatch"].polarity, Polarity.SUPPORTS_THREAT)
        self.assertEqual(signals["brand_domain_mismatch"].value, "GlorpTech")


if __name__ == "__main__":
    unittest.main()
