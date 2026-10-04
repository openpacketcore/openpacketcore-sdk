#!/usr/bin/env python3
"""Fail-closed selection and failure propagation for opt-in latency gates."""

import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

SPEC = importlib.util.spec_from_file_location(
    "performance", Path(__file__).with_name("performance-tests.py")
)
assert SPEC is not None and SPEC.loader is not None
PERFORMANCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PERFORMANCE)


class PerformanceGateTests(unittest.TestCase):
    def test_rejects_empty_duplicate_and_wrong_inventory(self):
        for output in ("0 tests", "chosen: test\nchosen: test\n", "other: test\n"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                PERFORMANCE.require_exact_inventory(output, "chosen")
        PERFORMANCE.require_exact_inventory("chosen: test\n1 test, 0 benchmarks\n", "chosen")

    def test_profiles_preserve_feature_and_optimization_choices(self):
        for profile in PERFORMANCE.PROFILES:
            command, env, name = PERFORMANCE.selection(profile)
            with self.subTest(profile=profile):
                self.assertIn("--locked", command)
                self.assertIn("--lib", command)
                self.assertEqual(env["CARGO_INCREMENTAL"], "0")
                if profile.endswith("protected"):
                    self.assertEqual(name, PERFORMANCE.PROTECTED)
                    self.assertEqual(env["CARGO_PROFILE_TEST_OPT_LEVEL"], "1")
                else:
                    self.assertEqual(name, PERFORMANCE.SELECTOR)
                    self.assertNotIn("CARGO_PROFILE_TEST_OPT_LEVEL", env)
                if profile.startswith("core-"):
                    self.assertIn("--workspace", command)
                    self.assertIn("--all-features", command)
                    self.assertEqual(env["CARGO_PROFILE_TEST_DEBUG"], "0")
                if profile == "unsupported-selector":
                    self.assertIn("--no-default-features", command)
                    self.assertEqual(env["RUSTFLAGS"], "--cfg opc_linux_gtpu_sys_force_unsupported")
                if profile == "i686-protected":
                    self.assertIn("i686-unknown-linux-gnu", command)
                    self.assertEqual(env["RUSTFLAGS"], "-C link-arg=-m32")

    def test_failure_is_recorded_and_never_retried(self):
        child = MagicMock()
        child.__enter__.return_value = child
        child.stdout = io.StringIO("test failed: original deadline\n")
        child.wait.return_value = 23
        inventory = subprocess.CompletedProcess([], 0, PERFORMANCE.PROTECTED + ": test\n")
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(PERFORMANCE.platform, "platform", return_value="test host"), \
                patch.object(PERFORMANCE.subprocess, "check_output", side_effect=["head\n", b"", "rustc\n"]), \
                patch.object(PERFORMANCE.subprocess, "run", return_value=inventory) as listing, \
                patch.object(PERFORMANCE.subprocess, "Popen", return_value=child) as execution, \
                patch("sys.stdout", new_callable=io.StringIO):
            output = Path(directory)
            self.assertEqual(PERFORMANCE.run("core-protected", output), 23)
            record = json.loads((output / "result.json").read_text())
            self.assertEqual(record["exit_code"], 23)
            self.assertEqual(record["budget_us"], 100_000)
            self.assertEqual((output / "test.log").read_text(), "test failed: original deadline\n")
            listing.assert_called_once()
            execution.assert_called_once()
            self.assertIn("--ignored", listing.call_args.args[0])
            self.assertIn("--ignored", execution.call_args.args[0])
            self.assertIn("--exact", execution.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
