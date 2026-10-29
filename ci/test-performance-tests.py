#!/usr/bin/env python3
"""Fail-closed selection, measurement and nightly latency classification."""

import ast
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
import yaml

SPEC = importlib.util.spec_from_file_location(
    "performance", Path(__file__).with_name("performance-tests.py")
)
assert SPEC is not None and SPEC.loader is not None
PERFORMANCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PERFORMANCE)


def workflow_condition(expression, event, job, ref="refs/heads/main", result="failure", variable=""):
    """Evaluate only the boolean subset used by the nightly job conditions."""
    for key, value in (("github.event_name", event), ("github.ref", ref),
                       (f"needs.{job}.result", result), ("vars.OPC_PERFORMANCE_GATES", variable)):
        expression = expression.replace(key, repr(value))
    expression = expression.replace("always()", "True").replace("&&", " and ").replace("||", " or ")
    tree = ast.parse(expression, mode="eval")
    allowed = (ast.Expression, ast.BoolOp, ast.Or, ast.And, ast.Compare, ast.Eq, ast.NotEq, ast.Constant)
    if not all(isinstance(node, allowed) for node in ast.walk(tree)):
        raise ValueError(f"unsupported workflow condition: {expression}")
    return eval(compile(tree, "workflow-condition", "eval"), {"__builtins__": {}}, {})


class NightlyWorkflowTests(unittest.TestCase):
    workflows = (("performance.yml", "latency", "performance"),
                 ("realtime-qualification.yml", "qualification", "realtime"))

    def workflow(self, name):
        path = Path(__file__).resolve().parents[1] / ".github/workflows" / name
        # BaseLoader preserves GitHub's `on` key instead of treating it as a YAML 1.1 boolean.
        return yaml.load(path.read_text(), Loader=yaml.BaseLoader)

    def test_nightly_triggers_run_without_a_repository_variable(self):
        for name, job_name, _ in self.workflows:
            with self.subTest(workflow=name):
                workflow = self.workflow(name)
                schedule = workflow["on"].get("schedule", [])
                self.assertTrue(schedule, "nightly schedule must remain enabled")
                self.assertTrue(all(entry.get("cron", "").strip() for entry in schedule))
                job = workflow["jobs"][job_name]
                for variable in ("", "false"):
                    self.assertTrue(workflow_condition(job["if"], "schedule", job_name, variable=variable))
                self.assertEqual(job.get("continue-on-error", "false"), "false")
        latency = self.workflow("performance.yml")["jobs"]["latency"]
        self.assertTrue(workflow_condition(latency["if"], "workflow_dispatch", "latency"))
        self.assertFalse(workflow_condition(latency["if"], "push", "latency"))
        self.assertTrue(workflow_condition(latency["if"], "push", "latency", variable="true"))
        self.assertEqual(latency["strategy"]["fail-fast"], "false")
        self.assertEqual(latency["strategy"]["matrix"]["profile"], list(PERFORMANCE.PROFILES))

    def test_failed_or_incomplete_nights_report_the_shared_merge_hold(self):
        for name, job_name, kind in self.workflows:
            with self.subTest(workflow=name):
                workflow = self.workflow(name)
                report = workflow["jobs"]["report-nightly"]
                self.assertEqual(report["needs"], job_name)
                self.assertIn("always()", report["if"], "report even when the dependency fails")
                for result in ("failure", "cancelled", "skipped"):
                    self.assertTrue(workflow_condition(report["if"], "schedule", job_name, result=result))
                for event, ref, result in (("schedule", "refs/heads/main", "success"),
                                          ("schedule", "refs/heads/other", "failure"),
                                          ("pull_request", "refs/pull/1/merge", "failure"),
                                          ("push", "refs/heads/main", "failure"),
                                          ("workflow_dispatch", "refs/heads/main", "failure")):
                    self.assertFalse(workflow_condition(report["if"], event, job_name, ref, result))
                self.assertEqual(report["permissions"]["issues"], "write")
                self.assertNotIn("issues", workflow["permissions"])
                self.assertEqual(report.get("continue-on-error", "false"), "false")
                steps = [step for step in report["steps"]
                         if "python3 ci/nightly_qualification.py report" in step.get("run", "")]
                self.assertEqual(len(steps), 1)
                step = steps[0]
                self.assertNotIn("if", step)
                self.assertEqual(step.get("continue-on-error", "false"), "false")
                self.assertEqual(step["env"]["QUALIFICATION_RESULT"], "${{ needs." + job_name + ".result }}")
                self.assertIn('--conclusion "$QUALIFICATION_RESULT"', step["run"])
                if kind == "performance":
                    self.assertIn("nightly_qualification.py report --kind performance", step["run"])

    def test_required_rust_gates_check_the_hold_and_workflow_controls(self):
        gates = self.workflow("ci.yml")["jobs"]["rust-gates"]
        steps = gates["steps"]
        for command in ("python3 ci/nightly_qualification.py check", "python3 ci/test-performance-tests.py"):
            matching = [step for step in steps if command in step.get("run", "").splitlines()]
            self.assertEqual(len(matching), 1, command)
            self.assertNotIn("if", matching[0])
            self.assertEqual(matching[0].get("continue-on-error", "false"), "false")


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


class DurableScratchWorkflowTests(unittest.TestCase):
    # These jobs execute file-backed persistence/recovery tests, including the
    # ordinary, unsupported and qualification owners of the durable selector.
    jobs = {
        "ci.yml": ("rust-tests", "rust-native-log-proofs", "rust-libraries",
                   "rust-persist", "rust-gtpu-cfg", "session-net-i686-tests",
                   "rust-local-kernel-lifecycle"),
        "egress-fence.yml": ("host-tests", "host-native-log-proofs", "host-proofs", "installer"),
        "ipsec-lb.yml": ("conformance",),
        "ipsec-xfrm.yml": ("conformance", "privileged"),
        "gtpu-privileged.yml": ("privileged-gtpu-regressions", "privileged-gtpu-resets", "privileged-gtpu"),
        "release.yml": ("validate",),
        "performance.yml": ("latency",),
        "realtime-qualification.yml": ("qualification",),
    }

    @classmethod
    def setUpClass(cls):
        # Keep positive fixtures on the checkout disk even if /tmp is tmpfs.
        (Path(__file__).resolve().parents[1] / "target").mkdir(exist_ok=True)

    def test_durable_jobs_keep_private_disk_scratch_until_unconditional_cleanup(self):
        root = Path(__file__).resolve().parents[1]
        for filename, names in self.jobs.items():
            workflow = yaml.load((root / ".github/workflows" / filename).read_text(), Loader=yaml.BaseLoader)
            for name in names:
                with self.subTest(workflow=filename, job=name), tempfile.TemporaryDirectory(dir=root / "target") as temporary:
                    steps = workflow["jobs"][name]["steps"]
                    prepare = [(i, s) for i, s in enumerate(steps) if s.get("name") == "Prepare disk-backed scratch"]
                    cleanup = [(i, s) for i, s in enumerate(steps) if s.get("name") == "Remove disk-backed scratch"]
                    self.assertEqual(len(prepare), 1, "durable job needs job-scoped disk scratch")
                    self.assertEqual(len(cleanup), 1, "durable job must remove its scratch")
                    before, setup = prepare[0]
                    after, teardown = cleanup[0]
                    self.assertEqual(before, 1, "prepare immediately after checkout, before any gate")
                    self.assertEqual(after, len(steps) - 1, "keep scratch through every test/artifact step")
                    self.assertEqual(teardown.get("if"), "always()", "remove scratch even after a failed test")
                    self.assertNotIn("if", setup)
                    self.assertNotIn("continue-on-error", setup)
                    self.assertNotIn("continue-on-error", teardown)
                    runner = Path(temporary)
                    github_env = runner / "github-env"
                    env = dict(os.environ, RUNNER_TEMP=str(runner), GITHUB_ENV=str(github_env))
                    subprocess.run(["bash", "-e", "-o", "pipefail", "-c", setup["run"]], cwd=root, env=env, check=True)
                    exported = dict(line.split("=", 1) for line in github_env.read_text().splitlines())
                    scratch = Path(exported["TMPDIR"])
                    self.assertEqual(scratch.parent, runner)
                    self.assertEqual(scratch.stat().st_mode & 0o777, 0o700)
                    self.assertEqual(exported["OPC_CI_DISK_TMPDIR"], str(scratch))
                    # Exercise real child inheritance and cleanup, not source-line spelling.
                    env.update(exported)
                    observed = subprocess.check_output(["python3", "-c", "import tempfile; print(tempfile.gettempdir())"], env=env, text=True).strip()
                    self.assertEqual(observed, str(scratch))
                    (scratch / "test-output").write_text("retained until job cleanup")
                    subprocess.run(["bash", "-e", "-o", "pipefail", "-c", teardown["run"]], cwd=root, env=env, check=True)
                    self.assertFalse(scratch.exists())
                    self.assertTrue(github_env.exists(), "cleanup must not remove its runner parent")

    def test_every_fsverity_gate_also_keeps_mutable_scratch_on_disk(self):
        root = Path(__file__).resolve().parents[1]
        for path in (root / ".github/workflows").glob("*.yml"):
            workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
            for name, job in workflow.get("jobs", {}).items():
                if any("ci/setup-fsverity-tmp.sh" in step.get("shell", "") for step in job.get("steps", [])):
                    self.assertIn(name, self.jobs.get(path.name, ()), (path.name, name))

    def test_job_cleanup_preserves_another_jobs_private_scratch(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(dir=root / "target") as temporary:
            runner = Path(temporary)
            prepared = []
            for index in range(2):
                github_env = runner / f"github-env-{index}"
                env = dict(os.environ, RUNNER_TEMP=str(runner), GITHUB_ENV=str(github_env))
                subprocess.run(["bash", "ci/disk-scratch.sh", "prepare"], cwd=root, env=env, check=True)
                prepared.append(dict(line.split("=", 1) for line in github_env.read_text().splitlines()))
            first, second = (Path(record["TMPDIR"]) for record in prepared)
            self.assertNotEqual(first, second)
            for record, retired, remaining in ((prepared[0], first, second), (prepared[1], second, github_env)):
                subprocess.run(["bash", "ci/disk-scratch.sh", "cleanup"], cwd=root,
                               env=dict(os.environ, RUNNER_TEMP=str(runner), **record), check=True)
                self.assertFalse(retired.exists())
                self.assertTrue(remaining.exists())

    def test_prepare_rejects_ram_backed_runner_scratch(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(dir="/dev/shm") as temporary:
            runner = Path(temporary)
            env = dict(os.environ, RUNNER_TEMP=str(runner), GITHUB_ENV=str(runner / "github-env"))
            result = subprocess.run(["bash", "ci/disk-scratch.sh", "prepare"], cwd=root, env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("disk-backed", result.stderr)
            self.assertEqual(list(runner.iterdir()), [], "reject and clean up before exporting a RAM directory")

    def test_cleanup_cannot_remove_an_unrelated_runner_directory(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            runner = Path(temporary)
            sentinel = runner / "other-job"
            sentinel.mkdir()
            (sentinel / "keep").write_text("foreign output")
            env = dict(os.environ, RUNNER_TEMP=str(runner), OPC_CI_DISK_TMPDIR=str(sentinel))
            result = subprocess.run(["bash", "ci/disk-scratch.sh", "cleanup"], cwd=root, env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue((sentinel / "keep").exists())


if __name__ == "__main__":
    unittest.main()
