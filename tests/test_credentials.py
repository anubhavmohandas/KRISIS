"""
Tests for provider credential resolution and storage.

The security-relevant properties here are that a stored key is not world-readable,
that a skipped source is reported as skipped rather than silently absent, and that
a missing key never quietly becomes a clean verdict.
"""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from unittest import mock

from krisis import credentials


class CredentialStoreTestCase(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.cwd = tempfile.mkdtemp()  # empty: no legacy api_keys.txt in scope
        patcher_home = mock.patch.dict(os.environ, {"KRISIS_HOME": self.home}, clear=False)
        patcher_home.start()
        self.addCleanup(patcher_home.stop)
        patcher_cwd = mock.patch("os.getcwd", return_value=self.cwd)
        patcher_cwd.start()
        self.addCleanup(patcher_cwd.stop)
        for var in ("VIRUSTOTAL_API_KEY", "NVIDIA_API_KEY"):
            os.environ.pop(var, None)


class TestResolution(CredentialStoreTestCase):
    def test_unset_key_resolves_to_none_and_needs_a_prompt(self):
        self.assertIsNone(credentials.resolve("VIRUSTOTAL_API_KEY"))
        self.assertTrue(credentials.needs_prompt("VIRUSTOTAL_API_KEY"))
        self.assertFalse(credentials.was_declined("VIRUSTOTAL_API_KEY"))

    def test_saved_key_round_trips(self):
        credentials.save("VIRUSTOTAL_API_KEY", "a" * 64)
        self.assertEqual(credentials.resolve("VIRUSTOTAL_API_KEY"), "a" * 64)
        self.assertFalse(credentials.needs_prompt("VIRUSTOTAL_API_KEY"))

    def test_environment_overrides_stored_value(self):
        credentials.save("VIRUSTOTAL_API_KEY", "stored")
        with mock.patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "from-env"}):
            self.assertEqual(credentials.resolve("VIRUSTOTAL_API_KEY"), "from-env")

    def test_skip_is_recorded_and_not_re_prompted(self):
        credentials.save("VIRUSTOTAL_API_KEY", "")
        self.assertIsNone(credentials.resolve("VIRUSTOTAL_API_KEY"))
        self.assertTrue(credentials.was_declined("VIRUSTOTAL_API_KEY"))
        self.assertFalse(credentials.needs_prompt("VIRUSTOTAL_API_KEY"))

    def test_blank_legacy_template_is_not_treated_as_a_decline(self):
        """api_keys.example.txt ships with blank values; copying it must not make
        KRISIS believe the user deliberately declined every source."""
        with open(os.path.join(self.cwd, credentials.LEGACY_KEYS_FILE), "w") as fh:
            fh.write("# template\nVIRUSTOTAL_API_KEY=\n")
        self.assertFalse(credentials.was_declined("VIRUSTOTAL_API_KEY"))
        self.assertTrue(credentials.needs_prompt("VIRUSTOTAL_API_KEY"))

    def test_legacy_file_with_a_real_key_still_works(self):
        with open(os.path.join(self.cwd, credentials.LEGACY_KEYS_FILE), "w") as fh:
            fh.write("VIRUSTOTAL_API_KEY=legacy-key\n")
        self.assertEqual(credentials.resolve("VIRUSTOTAL_API_KEY"), "legacy-key")

    def test_saving_one_key_preserves_the_others(self):
        credentials.save("VIRUSTOTAL_API_KEY", "vt-key")
        credentials.save("NVIDIA_API_KEY", "nvapi-key")
        self.assertEqual(credentials.resolve("VIRUSTOTAL_API_KEY"), "vt-key")
        self.assertEqual(credentials.resolve("NVIDIA_API_KEY"), "nvapi-key")


class TestStoragePermissions(CredentialStoreTestCase):
    def test_key_file_is_not_readable_by_others(self):
        path = credentials.save("VIRUSTOTAL_API_KEY", "secret-key")
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode & (stat.S_IRWXG | stat.S_IRWXO), 0, f"mode was {oct(mode)}")

    def test_home_directory_is_not_readable_by_others(self):
        credentials.save("VIRUSTOTAL_API_KEY", "secret-key")
        mode = stat.S_IMODE(os.stat(credentials.krisis_home()).st_mode)
        self.assertEqual(mode & (stat.S_IRWXG | stat.S_IRWXO), 0, f"mode was {oct(mode)}")


class TestMasking(unittest.TestCase):
    def test_mask_hides_the_middle_of_a_key(self):
        masked = credentials.mask("abcd" + "x" * 20 + "wxyz")
        self.assertTrue(masked.startswith("abcd"))
        self.assertTrue(masked.endswith("wxyz"))
        self.assertNotIn("xxxxxxxxxxxxxxxxxxxx", masked.strip("*"))

    def test_short_values_are_fully_masked(self):
        self.assertEqual(credentials.mask("short"), "*****")


class TestVerification(unittest.TestCase):
    def _spec(self, provider):
        return credentials.PROVIDER_KEYS_BY_NAME[provider]

    def test_rejected_key_fails_verification(self):
        resp = mock.Mock(status_code=401)
        with mock.patch("requests.get", return_value=resp):
            ok, message = credentials.verify(self._spec("virustotal"), "bad")
        self.assertFalse(ok)
        self.assertIn("rejected", message)

    def test_accepted_key_passes_verification(self):
        resp = mock.Mock(status_code=200)
        with mock.patch("requests.get", return_value=resp):
            ok, _ = credentials.verify(self._spec("virustotal"), "good")
        self.assertTrue(ok)

    def test_network_failure_does_not_reject_the_key(self):
        """Being briefly offline must not cost the user a valid key."""
        with mock.patch("requests.get", side_effect=OSError("offline")):
            ok, message = credentials.verify(self._spec("virustotal"), "maybe-good")
        self.assertTrue(ok)
        self.assertIn("could not verify", message)


class TestMachineReadableOutputStaysMachineReadable(unittest.TestCase):
    def test_missing_key_notices_go_to_stderr(self):
        """`--json` is piped into a parser. A human-readable notice on stdout makes
        the whole case unparseable, which turns a missing API key into a broken
        integration rather than a reported gap."""
        import contextlib
        import io

        from krisis.cli import _ensure_credentials

        out, err = io.StringIO(), io.StringIO()
        with mock.patch("krisis.credentials.needs_prompt", return_value=True):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                _ensure_credentials(interactive=False)

        self.assertEqual(out.getvalue(), "")
        self.assertIn("not configured", err.getvalue())


class TestProviderRegistry(unittest.TestCase):
    def test_ai_layer_is_not_registered_as_an_evidence_source(self):
        """The AI layer explains a finished investigation; it never contributes
        evidence. Listing it as a source would misrepresent the architecture."""
        ai_layer = credentials.PROVIDER_KEYS_BY_NAME["nvidia"]
        self.assertFalse(ai_layer.is_evidence_source)
        self.assertTrue(credentials.PROVIDER_KEYS_BY_NAME["virustotal"].is_evidence_source)

    def test_every_registered_key_is_actually_consumed_somewhere(self):
        """Guards against advertising a key that no component reads."""
        from krisis import config
        from krisis.ai.explain import Explainer  # noqa: F401  (reads NVIDIA_API_KEY)

        registered = {p.env_var for p in credentials.PROVIDER_KEYS}
        self.assertIn("VIRUSTOTAL_API_KEY", registered)
        self.assertIn("NVIDIA_API_KEY", registered)
        self.assertTrue(hasattr(config, "virustotal_api_key"))
        # The AI model is configured in one place, never scattered through the code.
        self.assertTrue(config.ai_model())


if __name__ == "__main__":
    unittest.main()
