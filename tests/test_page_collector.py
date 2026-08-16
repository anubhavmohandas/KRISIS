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
from krisis.core.url_intent import classify, has_userinfo, is_ip_literal_host


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


class TestUrlStructureFunctions(unittest.TestCase):
    def test_ip_literal_host_is_detected(self):
        self.assertTrue(is_ip_literal_host("http://203.0.113.5/login"))

    def test_ipv6_literal_host_is_detected(self):
        self.assertTrue(is_ip_literal_host("http://[2001:db8::1]/login"))

    def test_ordinary_domain_host_is_not_an_ip_literal(self):
        self.assertFalse(is_ip_literal_host("https://example.test/login"))

    def test_userinfo_before_host_is_detected(self):
        self.assertTrue(has_userinfo("https://paypal.com@evil.test/login"))

    def test_no_userinfo_is_the_ordinary_case(self):
        self.assertFalse(has_userinfo("https://example.test/login"))


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


class TestStructureSignals(unittest.TestCase):
    def test_ip_literal_host_is_reported_as_evidence(self):
        result = _collect(
            "http://203.0.113.5/login",
            [_page("<html><head><title>Login</title></head><body></body></html>")],
        )
        signals = {e.signal: e for e in result.evidence}
        self.assertIn("ip_literal_host", signals)
        self.assertEqual(signals["ip_literal_host"].polarity, Polarity.SUPPORTS_THREAT)

    def test_userinfo_trick_is_reported_as_evidence(self):
        result = _collect(
            "http://paypal.com@evil.test/login",
            [_page("<html><head><title>Login</title></head><body></body></html>")],
        )
        signals = {e.signal: e for e in result.evidence}
        self.assertIn("url_userinfo_present", signals)
        self.assertEqual(signals["url_userinfo_present"].polarity, Polarity.SUPPORTS_THREAT)

    def test_ordinary_url_reports_neither_structure_signal(self):
        result = _collect(
            "http://example.test/login",
            [_page("<html><head><title>Login</title></head><body></body></html>")],
        )
        signals = {e.signal for e in result.evidence}
        self.assertFalse(signals & {"ip_literal_host", "url_userinfo_present"})

    def test_a_failed_fetch_still_reports_unavailable_not_partial_evidence(self):
        """Regression guard: structure evidence is only computed in the fetch
        success path (see page_collector.PageCollector.collect) — a connection
        failure must keep returning available=False with zero evidence, not a
        partial result carrying only the structure signals."""
        import requests

        with _mock_dns(), mock.patch("requests.get", side_effect=requests.ConnectionError("refused")):
            result = _collect("http://203.0.113.5/login", [])
        self.assertFalse(result.available)
        self.assertEqual(result.evidence, [])


class TestMetaRefreshRedirect(unittest.TestCase):
    def test_a_cross_domain_meta_refresh_is_reported_as_supporting_evidence(self):
        page = (
            '<html><head><meta http-equiv="refresh" content="0;url=http://attacker.test/x">'
            "</head><body></body></html>"
        )
        result = _collect("http://example.test/", [_page(page)])
        signals = {e.signal: e for e in result.evidence}
        self.assertIn("meta_refresh_target", signals)
        self.assertEqual(signals["meta_refresh_target"].polarity, Polarity.SUPPORTS_THREAT)
        self.assertEqual(signals["meta_refresh_target"].value, "http://attacker.test/x")

    def test_a_same_site_meta_refresh_is_neutral(self):
        page = (
            '<html><head><meta http-equiv="refresh" content="0;url=/next-page">'
            "</head><body></body></html>"
        )
        result = _collect("http://example.test/start", [_page(page)])
        signals = {e.signal: e for e in result.evidence}
        self.assertIn("meta_refresh_target", signals)
        self.assertEqual(signals["meta_refresh_target"].polarity, Polarity.NEUTRAL)

    def test_no_meta_refresh_tag_emits_no_evidence(self):
        result = _collect("http://example.test/", [_page("<html><body>plain page</body></html>")])
        self.assertNotIn("meta_refresh_target", {e.signal for e in result.evidence})


class TestExecutableDownload(unittest.TestCase):
    def test_an_executable_link_is_reported_as_supporting_evidence(self):
        page = '<html><body><a href="/files/invoice.exe">Download</a></body></html>'
        result = _collect("http://example.test/", [_page(page)])
        signals = {e.signal: e for e in result.evidence}
        self.assertIn("executable_download", signals)
        self.assertEqual(signals["executable_download"].polarity, Polarity.SUPPORTS_THREAT)
        self.assertIn("http://example.test/files/invoice.exe", signals["executable_download"].value)

    def test_an_ordinary_document_link_is_not_flagged(self):
        page = '<html><body><a href="/files/invoice.pdf">Download</a></body></html>'
        result = _collect("http://example.test/", [_page(page)])
        self.assertNotIn("executable_download", {e.signal for e in result.evidence})

    def test_a_query_string_trailing_a_real_executable_path_is_still_detected(self):
        page = '<html><body><a href="/files/invoice.exe?id=1">Download</a></body></html>'
        result = _collect("http://example.test/", [_page(page)])
        self.assertIn("executable_download", {e.signal for e in result.evidence})

    def test_an_extension_only_inside_a_query_value_is_not_a_direct_download_link(self):
        # The path itself is "/get" — "payload.exe" only appears as a query
        # *value*, not as the literal linked file, so this is not the same
        # deterministic signal as an actual executable path.
        page = '<html><body><a href="/get?file=payload.exe&id=1">Download</a></body></html>'
        result = _collect("http://example.test/", [_page(page)])
        self.assertNotIn("executable_download", {e.signal for e in result.evidence})


if __name__ == "__main__":
    unittest.main()
