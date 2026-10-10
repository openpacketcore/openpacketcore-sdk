#!/usr/bin/env python3
"""Exact selection, sticky failures, and nightly classification regressions."""

import copy
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import nightly_qualification as NIGHTLY
import realtime_qualification as QUALIFICATION


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(QUALIFICATION.MANIFEST.read_text())

    def load(self, manifest):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            path.write_text(json.dumps(manifest))
            return QUALIFICATION.load_manifest(path)

    def test_every_entry_is_exact_and_explained(self):
        entries = self.load(self.manifest)
        for entry in entries:
            self.assertTrue(entry["name"])
            self.assertGreater(entry["issue"], 0)
            self.assertTrue(entry["reason"].strip())
        self.assertNotIn("isolated_scale::original::original_schedule_and_percentiles_preserve_submillisecond_boundaries",
                         [entry["name"] for entry in entries])

    def test_unknown_schema_and_target_fail_closed(self):
        invalid = [None, [], {}, dict(self.manifest, version=2),
                   dict(self.manifest, version=True), dict(self.manifest, tests={}),
                   dict(self.manifest, target="other"), dict(self.manifest, package="other"),
                   dict(self.manifest, baseline_evidence=""), dict(self.manifest, extra=True)]
        for manifest in invalid:
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                self.load(manifest)

    def test_duplicate_missing_reason_missing_issue_and_patterns_fail_closed(self):
        entry = self.manifest["tests"][0]
        invalid = [
            [entry, entry], [dict(entry, reason=" ")], [dict(entry, issue=0)],
            [dict(entry, issue=True)], [dict(entry, name="isolated_scale::*")],
            [dict(entry, name="--skip")], [dict(entry, name="name\nother")],
            [dict(entry, issue=None)], [{"name": entry["name"]}], ["name"],
        ]
        for entries in invalid:
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                self.load(dict(self.manifest, tests=entries))

    def test_list_can_shrink_to_empty(self):
        self.assertEqual(self.load(dict(self.manifest, tests=[])), [])

    def test_live_inventory_rejects_zero_duplicate_and_prefix_matches(self):
        for output in ("0 tests", "chosen: test\nchosen: test\n", "chosen_future: test\n"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                QUALIFICATION.require_inventory(output, ["chosen"])
        QUALIFICATION.require_inventory("chosen: test\n1 test, 0 benchmarks\n", ["chosen"])


class QualificationRunnerTests(unittest.TestCase):
    entries = [{"name": "chosen", "issue": 923, "reason": "real I/O deadline"}]
    passed = "test chosen ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n"
    failed = "test chosen ... FAILED\nfailures:\n    chosen\ntest result: FAILED. 0 passed; 1 failed; 0 ignored;\n"

    def run_fixture(self, measurements, *, inventory="chosen: test\n", ignored=""):
        calls = []
        measurements = iter(measurements)

        def capture(command, path):
            calls.append(command)
            if "--list" in command:
                result = (0, ignored if "--ignored" in command else inventory)
            else:
                result = next(measurements)
            path.write_text(result[1])
            return result

        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(QUALIFICATION, "capture", side_effect=capture), \
                patch.object(QUALIFICATION.subprocess, "check_output", return_value="source\n"), \
                patch("sys.stderr", new_callable=io.StringIO):
            output = Path(temporary) / "results"
            code = QUALIFICATION.run(self.entries, 2, output)
            return code, json.loads((output / "result.json").read_text()), calls

    def test_later_pass_does_not_erase_an_earlier_failure(self):
        code, record, calls = self.run_fixture([(101, self.failed), (0, self.passed)])
        self.assertEqual(code, 1)
        self.assertFalse(record["passed"])
        self.assertEqual([run["passed"] for run in record["runs"]], [False, True])
        self.assertEqual(record["runs"][0]["failed_tests"], ["chosen"])
        self.assertEqual(len(calls), 4)  # two lists and exactly two requested measurements
        for command in calls:
            self.assertEqual(command[:len(QUALIFICATION.SELECTION)], QUALIFICATION.SELECTION)
            self.assertIn("--exact", command)
        self.assertIn("--test-threads=4", calls[-1])
        self.assertNotIn("--ignored", calls[-1])

    def test_complete_passing_measurements_succeed(self):
        code, record, _ = self.run_fixture([(0, self.passed), (0, self.passed)])
        self.assertEqual(code, 0)
        self.assertTrue(record["passed"])
        self.assertEqual(len(record["runs"]), 2)

    def test_stale_and_ignored_entries_never_execute(self):
        for overrides in ({"inventory": ""}, {"ignored": "chosen: test\n"}):
            with self.subTest(overrides=overrides):
                code, record, calls = self.run_fixture([], **overrides)
                self.assertEqual(code, 1)
                self.assertFalse(record["passed"])
                self.assertEqual(record["runs"], [])
                self.assertTrue(all("--list" in command for command in calls))

    def test_zero_ignored_and_incomplete_measurements_fail_without_repetition(self):
        for output in ("test result: ok. 0 passed; 0 failed; 0 ignored;\n",
                       "test result: ok. 0 passed; 0 failed; 1 ignored;\n",
                       "compiler failed before tests\n"):
            with self.subTest(output=output):
                code, record, calls = self.run_fixture([(0, output)])
                self.assertEqual(code, 1)
                self.assertTrue(record["runs"][0]["incomplete"])
                self.assertEqual(len(calls), 3)

    def test_process_failure_without_named_test_is_never_green(self):
        result = QUALIFICATION.outcome(self.passed, ["chosen"], 9)
        self.assertFalse(result["passed"])

    def test_ambiguous_failure_summary_is_incomplete(self):
        result = QUALIFICATION.outcome(self.failed + self.passed, ["chosen"], 101)
        self.assertFalse(result["passed"])
        self.assertTrue(result["incomplete"])

    def test_empty_manifest_is_explicit_and_does_not_run_unfiltered_target(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(QUALIFICATION, "capture") as capture, \
                patch.object(QUALIFICATION.subprocess, "check_output", return_value="source\n"), \
                patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(QUALIFICATION.run([], 10, Path(temporary) / "results"), 0)
            capture.assert_not_called()


class NightlyPolicyTests(unittest.TestCase):
    repository = "owner/repository"
    issue = {"number": 7, "html_url": "https://github.com/owner/repository/issues/7"}
    result = {
        "head": "source", "requested_repetitions": 10, "error": None,
        "tests": [{"name": "chosen", "issue": 923}],
        "runs": [{"failed_tests": ["chosen"], "incomplete": False}],
    }

    def test_open_nightly_issue_blocks_merging(self):
        with patch.object(NIGHTLY, "open_issues", return_value=[self.issue]), \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(NIGHTLY.check(self.repository), 1)
            self.assertIn(self.issue["html_url"], output.getvalue())

    def test_no_open_classification_issue_allows_the_gate(self):
        with patch.object(NIGHTLY, "open_issues", return_value=[]), \
                patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(NIGHTLY.check(self.repository), 0)

    def test_api_failure_does_not_clear_the_hold(self):
        with patch.object(NIGHTLY, "open_issues", side_effect=subprocess.CalledProcessError(1, ["gh"])), \
                self.assertRaises(subprocess.CalledProcessError):
            NIGHTLY.check(self.repository)

    def test_pagination_includes_all_issues_and_excludes_pull_requests(self):
        pages = [[dict(self.issue, pull_request={})], [self.issue]]
        with patch.object(NIGHTLY.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(pages))) as run:
            self.assertEqual(NIGHTLY.open_issues(self.repository), [self.issue])
            self.assertIn("--paginate", run.call_args.args[0])

    def test_report_links_run_issue_and_each_failing_test(self):
        result = copy.deepcopy(self.result)
        result["runs"].append(result["runs"][0])
        body = NIGHTLY.report_body(result, "https://github.com/owner/repository/actions/runs/9", "failure")
        self.assertIn("/actions/runs/9", body)
        self.assertIn("`chosen`: 2 failed repetition(s); #923", body)
        self.assertIn("Merge hold", body)
        self.assertIn("2/10", body)

    def test_missing_or_successful_artifact_does_not_hide_failed_job(self):
        body = NIGHTLY.report_body(None, "run", "cancelled")
        self.assertIn("No result artifact", body)
        result = copy.deepcopy(self.result)
        result["runs"][0]["failed_tests"] = []
        body = NIGHTLY.report_body(result, "run", "failure")
        self.assertIn("infrastructure and reporting failures also require classification", body)

    def test_report_opens_or_comments_without_real_api_calls(self):
        for existing in ([], [self.issue]):
            with self.subTest(existing=bool(existing)), tempfile.TemporaryDirectory() as temporary, \
                    patch.dict(os.environ, GITHUB_EVENT_NAME="schedule", GITHUB_REF="refs/heads/main", GITHUB_RUN_ID="9"), \
                    patch.object(NIGHTLY, "open_issues", return_value=existing), \
                    patch.object(NIGHTLY, "api", return_value=self.issue) as api, \
                    patch.object(NIGHTLY.subprocess, "run") as command, \
                    patch("sys.stdout", new_callable=io.StringIO):
                result = Path(temporary) / "result.json"
                result.write_text(json.dumps(self.result))
                self.assertEqual(NIGHTLY.report(self.repository, result, "failure"), 0)
                expected = f"repos/{self.repository}/issues" + ("/7/comments" if existing else "")
                self.assertEqual(api.call_args.args[0], expected)
                self.assertIn("/actions/runs/9", api.call_args.args[1]["body"])
                self.assertIn("nightly-qualification", command.call_args.args[0])

    def test_pull_requests_and_non_main_runs_cannot_publish_issues(self):
        for event, ref in (("pull_request", "refs/pull/1/merge"), ("schedule", "refs/heads/other")):
            with self.subTest(event=event), patch.dict(os.environ, GITHUB_EVENT_NAME=event, GITHUB_REF=ref), \
                    patch.object(NIGHTLY, "api") as api, self.assertRaises(ValueError):
                NIGHTLY.report(self.repository, Path("absent.json"), "failure")
            api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
