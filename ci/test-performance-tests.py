#!/usr/bin/env python3
"""Fail-closed selection, measurement and nightly latency classification."""

import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import nightly_qualification as NIGHTLY

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


class PerformanceNightlyTests(unittest.TestCase):
    repository = "owner/repository"
    issue = {"number": 7, "html_url": "https://github.com/owner/repository/issues/7"}

    def artifact(self, directory, profile, exit_code):
        path = directory / f"cnf-performance-{profile}" / "result.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "profile": profile, "head": "qualified-source", "test": "chosen",
            "exit_code": exit_code,
            "budget_us": 100_000 if profile.endswith("protected") else 1_000_000,
        }))
        return path

    def test_reporting_covers_every_measurement_profile(self):
        self.assertEqual(NIGHTLY.PERFORMANCE_PROFILES, PERFORMANCE.PROFILES)

    def test_report_preserves_each_profile_failure_and_original_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for profile in PERFORMANCE.PROFILES:
                self.artifact(directory, profile, 101 if profile == "core-selector" else 0)
            body = NIGHTLY.performance_report_body(directory, "workflow-link", "failure")
        for profile in PERFORMANCE.PROFILES:
            self.assertIn(f"`{profile}`:", body)
        self.assertIn("`core-selector`: **failed (exit 101)**", body)
        self.assertIn("budget 100000 us", body)
        self.assertIn("budget 1000000 us", body)
        self.assertIn("qualified-source", body)
        self.assertIn("workflow-link", body)
        self.assertIn("Merge hold", body)
        self.assertNotIn("no usable result", body)

    def test_missing_malformed_and_mismatched_artifacts_remain_failures(self):
        for invalid in (None, "{", "[]", '{"profile": "core-selector"}'):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                if invalid is not None:
                    path = self.artifact(directory, "core-protected", 0)
                    path.write_text(invalid)
                body = NIGHTLY.performance_report_body(directory, "run", "failure")
                self.assertEqual(body.count("no usable result artifact"), len(PERFORMANCE.PROFILES))
                self.assertIn("Merge hold", body)

    def test_failed_matrix_opens_or_extends_the_shared_merge_hold(self):
        for existing in ([], [self.issue]):
            for conclusion in ("failure", "cancelled", "skipped"):
                with self.subTest(existing=bool(existing), conclusion=conclusion), \
                        tempfile.TemporaryDirectory() as temporary, \
                        patch.dict(os.environ, GITHUB_EVENT_NAME="schedule", GITHUB_REF="refs/heads/main", GITHUB_RUN_ID="9"), \
                        patch.object(NIGHTLY, "open_issues", return_value=existing), \
                        patch.object(NIGHTLY, "api", return_value=self.issue) as api, \
                        patch.object(NIGHTLY.subprocess, "run"), \
                        patch("sys.stdout", new_callable=io.StringIO):
                    # A successful profile must not hide failed or absent siblings.
                    directory = Path(temporary)
                    self.artifact(directory, "core-protected", 0)
                    self.assertEqual(NIGHTLY.report(self.repository, directory, conclusion, "performance"), 0)
                    api.assert_called_once()
                    endpoint, payload = api.call_args.args
                    self.assertEqual(endpoint, f"repos/{self.repository}/issues" + ("/7/comments" if existing else ""))
                    self.assertIn("CNF performance", payload["body"])
                    self.assertIn("/actions/runs/9", payload["body"])
                    self.assertIn("no usable result artifact", payload["body"])
                    if not existing:
                        self.assertEqual(payload["labels"], ["nightly-qualification"])
                with patch.object(NIGHTLY, "open_issues", return_value=[self.issue]), \
                        patch("sys.stdout", new_callable=io.StringIO):
                    self.assertEqual(NIGHTLY.check(self.repository), 1)

    def test_single_extracted_artifact_does_not_stand_in_for_missing_profiles(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = self.artifact(directory, "core-protected", 101)
            path.rename(directory / "result.json")
            body = NIGHTLY.performance_report_body(directory, "run", "failure")
        self.assertIn("`core-protected`: **failed (exit 101)**", body)
        self.assertEqual(body.count("no usable result artifact"), len(PERFORMANCE.PROFILES) - 1)

    def test_all_passing_artifacts_cannot_erase_a_failed_job(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for profile in PERFORMANCE.PROFILES:
                self.artifact(directory, profile, 0)
            body = NIGHTLY.performance_report_body(directory, "run", "failure")
        self.assertIn("**failure**", body)
        self.assertIn("Merge hold", body)
        self.assertIn("setup, runner, or reporting failure", body)

    def test_performance_reports_reject_prs_non_main_and_success(self):
        for event, ref, conclusion in (("pull_request", "refs/pull/1/merge", "failure"),
                                       ("schedule", "refs/heads/other", "failure"),
                                       ("schedule", "refs/heads/main", "success")):
            with self.subTest(event=event, ref=ref, conclusion=conclusion), \
                    patch.dict(os.environ, GITHUB_EVENT_NAME=event, GITHUB_REF=ref, GITHUB_RUN_ID="9"), \
                    patch.object(NIGHTLY, "api") as api, self.assertRaises(ValueError):
                NIGHTLY.report(self.repository, Path("absent"), conclusion, "performance")
            api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
