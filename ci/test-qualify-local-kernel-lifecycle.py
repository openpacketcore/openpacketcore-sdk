#!/usr/bin/env python3
"""Regress source-bound guest qualification and fail-closed native case evidence."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "lifecycle_qualification", Path(__file__).with_name("qualify-local-kernel-lifecycle.py")
)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.cases = {"crate-a": ["native::first", "native::second"]}
        for name in RUNNER.RUNNER_FILES:
            path = self.bundle / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((RUNNER.ROOT / name).read_bytes())
        (self.bundle / RUNNER.RUNNER_FILES[1]).write_text(json.dumps(self.cases))
        binary = self.bundle / "binaries/crate-a"
        binary.parent.mkdir()
        binary.write_bytes(b"fixture native executable")
        files = {name: RUNNER.sha256(self.bundle / name) for name in RUNNER.RUNNER_FILES}
        files["binaries/crate-a"] = RUNNER.sha256(binary)
        sources = {name: files[name] for name in RUNNER.RUNNER_FILES}
        for name in ["build.jsonl", "build.log"]:
            (self.bundle / name).write_text("fixture compiler output\n")
            files[name] = RUNNER.sha256(self.bundle / name)
        self.record = {
            "head": "fixture-head", "source": sources,
            "rustc": "fixture compiler", "cargo": "fixture cargo", "build_command": ["cargo", "test"],
            "build.jsonl_sha256": files["build.jsonl"], "build.log_sha256": files["build.log"],
            "source_digest": RUNNER.source_digest(sources),
            "source_unchanged": True, "build_complete": True, "build_exit_code": 0,
            "bundle_files": files, "full_manifest": True, "selected": self.cases,
            "manifest_sha256": files[RUNNER.RUNNER_FILES[1]],
            "binaries": {"crate-a": {"path": "binaries/crate-a", "sha256": files["binaries/crate-a"]}},
            "kernel": {"release": "build-host"}, "cases": [], "complete": False, "passed": False,
        }
        self.write_record()

    def write_record(self):
        (self.bundle / "bundle.json").write_text(json.dumps(self.record))

    def test_changed_binary_or_runner_is_refused(self):
        RUNNER.verify_bundle(self.bundle, self.record)
        for name in ["binaries/crate-a", "ci/deny-bpf-enumeration.py"]:
            with self.subTest(name=name):
                path = self.bundle / name
                original = path.read_bytes()
                path.write_bytes(original + b"changed")
                with self.assertRaisesRegex(ValueError, "bundle member changed"):
                    RUNNER.verify_bundle(self.bundle, self.record)
                path.write_bytes(original)

    def test_partial_manifest_and_missing_binary_are_refused(self):
        record = copy.deepcopy(self.record)
        record["selected"]["crate-a"].pop()
        with self.assertRaisesRegex(ValueError, "complete committed manifest"):
            RUNNER.verify_bundle(self.bundle, record)
        record = copy.deepcopy(self.record)
        record["binaries"].clear()
        with self.assertRaisesRegex(ValueError, "every required test binary"):
            RUNNER.verify_bundle(self.bundle, record)

    def test_changed_manifest_cannot_shrink_the_build_contract(self):
        path = self.bundle / RUNNER.RUNNER_FILES[1]
        path.write_text(json.dumps({"crate-a": ["native::first"]}))
        self.record["bundle_files"][RUNNER.RUNNER_FILES[1]] = RUNNER.sha256(path)
        with self.assertRaisesRegex(ValueError, "does not match compiled source"):
            RUNNER.verify_bundle(self.bundle, self.record)

    def test_failed_build_and_changed_source_digest_are_refused(self):
        for field, value in [("build_exit_code", 1), ("source_unchanged", False), ("source_digest", "wrong")]:
            with self.subTest(field=field):
                record = copy.deepcopy(self.record)
                record[field] = value
                with self.assertRaises(ValueError):
                    RUNNER.verify_bundle(self.bundle, record)

    def test_missing_build_log_cannot_be_omitted_from_the_bundle_manifest(self):
        self.record["bundle_files"].pop("build.log")
        (self.bundle / "build.log").unlink()
        with self.assertRaisesRegex(ValueError, "missing build evidence"):
            RUNNER.verify_bundle(self.bundle, self.record)

    def test_skips_empty_runs_and_failed_processes_are_not_passes(self):
        success = "test result: ok. 1 passed; 0 failed; 0 ignored; 9 filtered out\n"
        self.assertTrue(RUNNER.case_passed(0, success))
        for code, output in [
            (1, success), (0, "test result: ok. 0 passed; 0 failed; 0 ignored;"),
            (0, "skipping: capability missing\n" + success),
            (0, "OPC_GTPU_CASE_SKIPPED: unsupported\n" + success),
        ]:
            with self.subTest(code=code, output=output):
                self.assertFalse(RUNNER.case_passed(code, output))

    def run_guest(self, code=0, listed=None, kernel="5.14.0-427.20.1.el9_4.x86_64"):
        evidence = self.root / "evidence"
        argv = ["qualify", "--run-bundle", str(self.bundle), "--evidence-dir", str(evidence),
                "--require-kernel", r"5\.14\.0-427\..*\.el9_4\.x86_64"]
        invocations = []

        def check_output(command, **_kwargs):
            self.assertEqual(command[1:], ["--ignored", "--list"])
            cases = self.cases["crate-a"] if listed is None else listed
            return "".join(case + ": test\n" for case in cases)

        def run(command, stdout, **_kwargs):
            invocations.append(command)
            self.assertIn("OPC_GTPU_RUN_PRIVILEGED=1", command)
            self.assertIn(str(self.bundle / "ci/deny-bpf-enumeration.py"), command)
            self.assertIn("--exact", command)
            stdout.write("test result: ok. 1 passed; 0 failed; 0 ignored;\n" if code == 0
                         else "test result: FAILED. 0 passed; 1 failed; 0 ignored;\n")
            return subprocess.CompletedProcess(command, code)

        with patch.object(RUNNER.sys, "argv", argv), patch.object(RUNNER.platform, "release", return_value=kernel), \
                patch.object(RUNNER.platform, "system", return_value="Linux"), \
                patch.object(RUNNER.platform, "uname", return_value=SimpleNamespace(_asdict=lambda: {"release": kernel})), \
                patch.object(RUNNER.subprocess, "check_output", side_effect=check_output), \
                patch.object(RUNNER.subprocess, "run", side_effect=run), \
                patch.object(RUNNER, "source", side_effect=AssertionError("guest must not require Git")):
            result = RUNNER.main()
        return result, json.loads((evidence / "result.json").read_text()), invocations

    def test_guest_runs_every_committed_case_without_cargo_or_git(self):
        code, record, invocations = self.run_guest()
        self.assertEqual(code, 0)
        self.assertEqual(len(invocations), 2)
        self.assertTrue(record["complete"] and record["passed"] and record["bundle_unchanged"])
        self.assertIsNone(record["source_unchanged"])
        self.assertEqual(record["source"], self.record["source"])
        self.assertEqual(record["build_kernel"], {"release": "build-host"})

    def test_guest_failure_is_retained_and_stops_the_suite(self):
        code, record, invocations = self.run_guest(code=101)
        self.assertEqual(code, 1)
        self.assertEqual(len(invocations), 1)
        self.assertFalse(record["complete"] or record["passed"])
        self.assertEqual(record["cases"][0]["exit_code"], 101)
        self.assertTrue((self.root / "evidence" / record["cases"][0]["log"]).is_file())

    def test_guest_refuses_a_binary_missing_a_committed_case(self):
        code, record, invocations = self.run_guest(listed=["native::first"])
        self.assertEqual(code, 1)
        self.assertEqual(invocations, [])
        self.assertIn("required native cases missing", record["error"])

    def test_wrong_guest_kernel_fails_before_execution(self):
        code, record, invocations = self.run_guest(kernel="6.8.0-ubuntu")
        self.assertEqual(code, 1)
        self.assertEqual(invocations, [])
        self.assertIn("does not match", record["error"])


if __name__ == "__main__":
    unittest.main()
