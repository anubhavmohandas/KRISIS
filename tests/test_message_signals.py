"""
Message-behavior signal extraction (krisis/core/message_signals.py) and the
collector that turns it into Evidence (krisis/collectors/message_collector.py).
Deterministic/regex-based by design — never LLM-decided (see AI INPUT/OUTPUT
in the project design doc: the model explains a finished investigation, it
never produces one).
"""

from __future__ import annotations

import unittest

from krisis.collectors.message_collector import MessageCollector
from krisis.core.message_signals import extract
from krisis.core.models import Entity, EntityType, Polarity


class TestMessageSignalExtraction(unittest.TestCase):
    def test_urgency_language_is_detected(self):
        found = extract("Your account will be suspended immediately unless you act now.")
        self.assertIn("urgency_language", found)

    def test_credential_request_is_detected(self):
        found = extract("Please verify your account details to continue.")
        self.assertIn("credential_request", found)

    def test_financial_lure_is_detected(self):
        found = extract("Your payment of $250 was declined. An invoice is attached.")
        self.assertIn("financial_lure", found)

    def test_call_to_action_is_detected(self):
        found = extract("Click here to resolve this issue.")
        self.assertIn("call_to_action", found)

    def test_a_benign_transactional_message_produces_no_signal(self):
        found = extract("Your package was delivered on Tuesday at 2:15pm.")
        self.assertEqual(found, {})

    def test_matched_snippets_are_carried_for_provenance(self):
        found = extract("Act now — your account will be locked.")
        self.assertTrue(any("act now" in s.lower() for s in found["urgency_language"]))


class TestMessageCollector(unittest.TestCase):
    def test_a_phishing_style_message_produces_behavior_evidence(self):
        text = (
            "Urgent: your account will be suspended today. "
            "Click here to verify your account details."
        )
        result = MessageCollector().collect(Entity(value=text, type=EntityType.MESSAGE))
        self.assertTrue(result.available)
        signals = {e.signal for e in result.evidence}
        self.assertIn("urgency_language", signals)
        self.assertIn("credential_request", signals)
        self.assertIn("call_to_action", signals)
        for ev in result.evidence:
            self.assertEqual(ev.evidence_type, "behavior")
            self.assertEqual(ev.polarity, Polarity.SUPPORTS_THREAT)

    def test_a_benign_message_produces_no_evidence_but_is_still_available(self):
        result = MessageCollector().collect(
            Entity(value="Thanks for your order, it ships tomorrow.", type=EntityType.MESSAGE)
        )
        self.assertTrue(result.available)
        self.assertEqual(result.evidence, [])

    def test_url_path_intent_is_not_duplicated_by_the_message_collector(self):
        """The URL in the message is queued as its own entity and gets full
        url-intent classification via PageCollector; MessageCollector must not
        re-derive it from the raw text, which would double-count the same fact
        under two different sources (see krisis/collectors/message_collector.py)."""
        text = "Verify your account now: https://example.test/login"
        result = MessageCollector().collect(Entity(value=text, type=EntityType.MESSAGE))
        signals = {e.signal for e in result.evidence}
        self.assertNotIn("authentication_intent", signals)


if __name__ == "__main__":
    unittest.main()
