#!/usr/bin/env python3
"""Regress source-bound guest qualification and fail-closed native case evidence."""

import copy
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "lifecycle_qualification", Path(__file__).with_name("qualify-local-kernel-lifecycle.py")
)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)

CLEANUP_SPEC = importlib.util.spec_from_file_location(
    "lifecycle_cleanup", Path(__file__).with_name("check-local-kernel-lifecycle-cleanup.py")
)
CLEANUP = importlib.util.module_from_spec(CLEANUP_SPEC)
CLEANUP_SPEC.loader.exec_module(CLEANUP)


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.before = {
            "net": ["100", "101"], "mnt": ["200", "201"],
            "named_netns": [], "bpffs_entries": ["existing d 12"],
            "bpffs_mounts": [], "interfaces": ["lo", "eth0"],
        }
        self.init = {"pid": 1, "ppid": 0, "start_time": 1, "state": "S", "comm": "init",
                     "cgroup": ["0::/"], "namespaces": {"net": {}, "mnt": {}}}

    def run_cleanup(self):
        # Expected negative fixtures must not emit GitHub error annotations.
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), \
                patch.object(os, "geteuid", return_value=0):
            return CLEANUP.main()

    def owner_fixture(self, directory):
        evidence = Path(directory)
        baseline = json.dumps(self.before, indent=2) + "\n"
        (evidence / "before.json").write_text(baseline)
        (evidence / "ownership.json").write_text(json.dumps({
            "version": 1, "id": "fixture-owner",
            "baseline_sha256": hashlib.sha256(baseline.encode()).hexdigest(),
        }))
        (evidence / "run-fixture.json").write_text(json.dumps({
            "version": 1, "owner_id": "fixture-owner", "status": "complete",
            "root": {"pid": 10, "start_time": 100},
            "command": ["qualification-fixture"], "exit_code": 0,
            "survivors": [], "cleanup_passed": True,
        }))

    def test_descendant_signaling_pins_identity_and_rejects_unrelated_ancestry(self):
        selected = {"pid": 30, "ppid": 10, "start_time": 300}
        root = {"pid": 10, "ppid": 1, "start_time": 100}
        for current, ancestry, owned in [
            (selected, [selected, root, self.init], True),
            ({**selected, "start_time": 301}, [selected, root, self.init], False),
            (selected, [selected, self.init], False),
        ]:
            with self.subTest(current=current, owned=owned), \
                    patch.object(CLEANUP.os, "pidfd_open", return_value=55) as opened, \
                    patch.object(CLEANUP, "read_stat", return_value=current), \
                    patch.object(CLEANUP, "current_ancestry", return_value=iter(ancestry)), \
                    patch.object(CLEANUP.os, "close") as closed:
                self.assertEqual(CLEANUP.pin_owned_process(selected, (10, 100)), 55 if owned else None)
                opened.assert_called_once_with(30)
                if owned:
                    closed.assert_not_called()
                else:
                    closed.assert_called_once_with(55)

    def test_descendant_ancestry_rejects_reused_parent_identity(self):
        child = {"pid": 30, "ppid": 10, "start_time": 300}
        with patch.object(CLEANUP, "read_stat", return_value={"pid": 10, "ppid": 1, "start_time": 301}):
            with self.assertRaisesRegex(ValueError, "parent identity changed"):
                list(CLEANUP.current_ancestry(child))

    def test_descendant_disposal_escalates_with_a_bound_and_keeps_failure_sticky(self):
        root = {"pid": 10, "ppid": 1, "start_time": 100}
        child = {"pid": 30, "ppid": 10, "start_time": 300, "state": "S"}
        with tempfile.TemporaryDirectory() as directory:
            self.owner_fixture(directory)
            with patch.object(CLEANUP, "read_stat", return_value=root), \
                    patch.object(CLEANUP, "current_ancestry", return_value=iter([root, self.init])), \
                    patch.object(CLEANUP, "owned_descendants", return_value=[child]), \
                    patch.object(CLEANUP, "direct_children", return_value={30}), \
                    patch.object(CLEANUP, "pin_owned_process", return_value=55), \
                    patch.object(CLEANUP.select, "select", return_value=([], [], [])), \
                    patch.object(CLEANUP.signal, "pidfd_send_signal") as sent, \
                    patch.object(CLEANUP.os, "close") as closed, \
                    patch.object(CLEANUP.time, "monotonic", side_effect=[0, 0, 2.1, 5.1, 5.1]), \
                    patch.object(CLEANUP.time, "sleep"):
                self.assertEqual(CLEANUP.dispose_descendants(Path(directory), "fixture"), 1)
            self.assertEqual([call.args for call in sent.call_args_list], [(55, signal.SIGTERM), (55, signal.SIGKILL)])
            closed.assert_called_once_with(55)
            result = json.loads((Path(directory) / "disposal-fixture.json").read_text())
            self.assertFalse(result["passed"])
            self.assertEqual(result["remaining"], [child])
            self.assertIn("owned descendants did not exit within the disposal deadline", result["errors"])
            self.assertFalse(json.loads((Path(directory) / "run-fixture.json").read_text())["cleanup_passed"])

    def test_descendant_disposal_rescans_an_orphan_adopted_after_inventory(self):
        root = {"pid": 10, "ppid": 1, "start_time": 100}
        child = {"pid": 30, "ppid": 10, "start_time": 300, "state": "S"}
        with tempfile.TemporaryDirectory() as directory:
            self.owner_fixture(directory)
            with patch.object(CLEANUP, "read_stat", return_value=root), \
                    patch.object(CLEANUP, "current_ancestry", return_value=iter([root, self.init])), \
                    patch.object(CLEANUP, "owned_descendants", side_effect=[[], [child], []]) as scanned, \
                    patch.object(CLEANUP, "direct_children", side_effect=[{30}, set()]), \
                    patch.object(CLEANUP, "pin_owned_process", return_value=55), \
                    patch.object(CLEANUP.select, "select", side_effect=[([], [], []), ([55], [], [])]), \
                    patch.object(CLEANUP.signal, "pidfd_send_signal") as sent, \
                    patch.object(CLEANUP.os, "close") as closed, \
                    patch.object(CLEANUP.time, "monotonic", side_effect=[0, 0, 0.1, 0.2, 0.2]), \
                    patch.object(CLEANUP.time, "sleep"):
                self.assertEqual(CLEANUP.dispose_descendants(Path(directory), "fixture"), 1)
            self.assertEqual(scanned.call_count, 3)
            sent.assert_called_once_with(55, signal.SIGTERM)
            closed.assert_called_once_with(55)
            result = json.loads((Path(directory) / "disposal-fixture.json").read_text())
            self.assertTrue(result["passed"])
            self.assertTrue(result["had_live_descendants"])
            self.assertFalse(json.loads((Path(directory) / "run-fixture.json").read_text())["cleanup_passed"])

    def test_unrelated_service_arrival_is_attributed_without_failing_cleanup(self):
        after = copy.deepcopy(self.before)
        after["net"].append("102")
        after["mnt"].append("202")
        service = {
            "pid": 20, "ppid": 1, "start_time": 200, "state": "S",
            "comm": "systemd-hostnamed",
            "cgroup": ["0::/system.slice/systemd-hostnamed.service"],
            "namespaces": {"net": {"102": ["task:20"]}, "mnt": {"202": ["task:20"]}},
        }
        with tempfile.TemporaryDirectory() as directory:
            self.owner_fixture(directory)
            with patch.object(CLEANUP, "snapshot", return_value=after), \
                    patch.object(CLEANUP, "process_inventory", return_value=({1: self.init, 20: service}, []), create=True), \
                    patch.object(CLEANUP.sys, "argv", ["cleanup", "verify", directory]):
                self.assertEqual(self.run_cleanup(), 0,
                                 "an unrelated host service's namespaces are not qualification leaks")
            result = json.loads((Path(directory) / "result.json").read_text())
            self.assertTrue(result["passed"])
            self.assertEqual(result["differences"], {})
            for kind, identity in [("net", "102"), ("mnt", "202")]:
                attribution = result["namespace_owners"][kind][identity]
                self.assertEqual(attribution["status"], "unrelated")
                self.assertEqual(attribution["owners"][0]["pid"], 20)
                self.assertEqual(attribution["owners"][0]["comm"], "systemd-hostnamed")

    def test_qualification_child_namespace_still_fails_cleanup(self):
        after = copy.deepcopy(self.before)
        after["net"].append("102")
        root = {"pid": 10, "ppid": 1, "start_time": 100, "state": "S",
                "comm": "qualification-fixture", "cgroup": ["0::/qualification"],
                "namespaces": {"net": {"100": ["task:10"]}, "mnt": {"200": ["task:10"]}}}
        child = {"pid": 30, "ppid": 10, "start_time": 300, "state": "S",
                 "comm": "leaked-child", "cgroup": ["0::/qualification"],
                 "namespaces": {"net": {"102": ["task:30"]}, "mnt": {"200": ["task:30"]}}}
        with tempfile.TemporaryDirectory() as directory:
            self.owner_fixture(directory)
            with patch.object(CLEANUP, "snapshot", return_value=after), \
                    patch.object(CLEANUP, "process_inventory", return_value=({10: root, 30: child}, []), create=True), \
                    patch.object(CLEANUP.sys, "argv", ["cleanup", "verify", directory]):
                self.assertEqual(self.run_cleanup(), 1)
            result = json.loads((Path(directory) / "result.json").read_text())
            self.assertFalse(result["passed"])
            self.assertEqual(result["differences"]["net"]["added"], ["102"])
            owner = result["namespace_owners"]["net"]["102"]["owners"][0]
            self.assertEqual(owner["pid"], 30)
            self.assertTrue(owner["qualification_owned"])

    def verify_fixture(self, directory, after, processes=None, errors=None):
        with patch.object(CLEANUP, "snapshot", return_value=after), \
                patch.object(CLEANUP, "process_inventory", return_value=(processes or {}, errors or [])), \
                patch.object(CLEANUP.sys, "argv", ["cleanup", "verify", directory]):
            code = self.run_cleanup()
        return code, json.loads((Path(directory) / "result.json").read_text())

    def test_reused_owner_pid_and_shared_cgroup_do_not_own_a_service(self):
        after = copy.deepcopy(self.before)
        after["net"].append("102")
        service = {**self.init, "pid": 10, "ppid": 1, "start_time": 900,
                   "comm": "other-process", "cgroup": ["0::/qualification"],
                   "namespaces": {"net": {"102": ["task:10"]}, "mnt": {}}}
        with tempfile.TemporaryDirectory() as directory:
            self.owner_fixture(directory)
            code, result = self.verify_fixture(directory, after, {1: self.init, 10: service})
            self.assertEqual(code, 0)
            self.assertFalse(result["namespace_owners"]["net"]["102"]["owners"][0]["qualification_owned"])
            # The same service can subsequently exit without invalidating cleanup.
            self.assertEqual(self.verify_fixture(directory, self.before)[0], 0)

    def test_reparented_survivor_is_still_owned_and_failed_run_stays_failed(self):
        after = copy.deepcopy(self.before)
        after["net"].append("102")
        child = {**self.init, "pid": 30, "ppid": 1, "start_time": 300,
                 "namespaces": {"net": {"102": ["fd:30:7"]}, "mnt": {}}}
        with tempfile.TemporaryDirectory() as directory:
            self.owner_fixture(directory)
            path = Path(directory) / "run-fixture.json"
            record = json.loads(path.read_text())
            record.update(cleanup_passed=False, survivors=[{"pid": 30, "start_time": 300}])
            path.write_text(json.dumps(record))
            code, result = self.verify_fixture(directory, after, {1: self.init, 30: child})
            self.assertEqual(code, 1)
            self.assertEqual(result["namespace_owners"]["net"]["102"]["status"], "qualification")
            self.assertEqual(self.verify_fixture(directory, self.before)[0], 1)

    def test_missing_or_racing_ownership_cannot_exempt_a_namespace(self):
        after = copy.deepcopy(self.before)
        after["net"].append("102")
        holder = {**self.init, "pid": 20, "ppid": 99, "start_time": 200,
                  "namespaces": {"net": {"102": ["task:20"]}, "mnt": {}}}
        for processes, errors in [({}, []), ({20: holder}, []),
                                  ({20: {**holder, "ppid": 1}, 1: self.init}, ["unreadable pid 30"]),
                                  ({20: holder, 99: {**self.init, "pid": 99, "start_time": 500}}, [])]:
            with self.subTest(processes=processes, errors=errors), tempfile.TemporaryDirectory() as directory:
                self.owner_fixture(directory)
                with patch.object(CLEANUP, "namespace_inventory", return_value=after):
                    code, result = self.verify_fixture(directory, after, processes, errors)
                self.assertEqual(code, 1)
                self.assertEqual(result["namespace_owners"]["net"]["102"]["status"], "unknown")

    def test_namespace_that_vanishes_during_inventory_is_reported(self):
        after = copy.deepcopy(self.before)
        after["net"].append("102")
        with tempfile.TemporaryDirectory() as directory:
            self.owner_fixture(directory)
            with patch.object(CLEANUP, "namespace_inventory", return_value=self.before):
                code, result = self.verify_fixture(directory, after)
            self.assertEqual(code, 0)
            self.assertEqual(result["namespace_owners"]["net"]["102"], {"status": "gone", "owners": []})

    def test_incomplete_corrupt_and_mismatched_ownership_fail_closed(self):
        for fault in ["interrupted", "missing", "bad-json", "wrong-type", "baseline"]:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                self.owner_fixture(directory)
                evidence = Path(directory)
                record = evidence / "run-fixture.json"
                if fault == "interrupted":
                    value = json.loads(record.read_text())
                    value["status"] = "running"
                    record.write_text(json.dumps(value))
                elif fault == "missing":
                    (evidence / "ownership.json").unlink()
                elif fault in {"bad-json", "wrong-type"}:
                    record.write_text("{" if fault == "bad-json" else "[]")
                else:
                    (evidence / "before.json").write_text(json.dumps(self.before) + " ")
                self.assertEqual(self.verify_fixture(directory, self.before)[0], 1)

    def test_failure_to_save_completed_owner_cannot_report_pass(self):
        run_id = "a" * 32
        root = {**self.init, "pid": 10, "ppid": 1, "start_time": 100}
        verifier = {**self.init, "pid": os.getpid(), "ppid": 10, "start_time": 200}
        with tempfile.TemporaryDirectory() as directory:
            self.owner_fixture(directory)
            path = Path(directory) / ("run-" + run_id + ".json")
            original = Path(directory) / "run-fixture.json"
            record = json.loads(original.read_text())
            record["status"] = "running"
            original.unlink()
            path.write_text(json.dumps(record))
            save = CLEANUP.write_json

            def fail_record(path, value):
                if path.name.startswith("run-"):
                    raise OSError("cannot save completed owner")
                save(path, value)

            with patch.object(CLEANUP, "snapshot", return_value=self.before), \
                    patch.object(CLEANUP, "process_inventory", return_value=({1: self.init, 10: root,
                                                                             os.getpid(): verifier}, [])), \
                    patch.object(CLEANUP, "direct_children", return_value={os.getpid()}), \
                    patch.object(CLEANUP, "write_json", side_effect=fail_record), \
                    patch.object(CLEANUP.sys, "argv", ["cleanup", "verify", directory, "--run-id", run_id,
                                                       "--command-exit-code", "0"]):
                self.assertEqual(self.run_cleanup(), 1)
            result = json.loads((Path(directory) / ("attribution-" + run_id + ".json")).read_text())
            self.assertFalse(result["passed"])
            self.assertIn("cannot save completed owner", result["errors"])

    def test_reparenting_during_inventory_cannot_hide_a_live_child(self):
        run_id = "a" * 32
        root = {**self.init, "pid": 10, "ppid": 1, "start_time": 100}
        verifier = {**self.init, "pid": os.getpid(), "ppid": 10, "start_time": 200}
        # This PPID became stale during collection: the kernel's children list
        # now puts the child directly under the still-live subreaper.
        child = {**self.init, "pid": 30, "ppid": 99, "start_time": 300}
        with tempfile.TemporaryDirectory() as directory:
            self.owner_fixture(directory)
            original = Path(directory) / "run-fixture.json"
            record = json.loads(original.read_text())
            record["status"] = "running"
            original.unlink()
            (Path(directory) / ("run-" + run_id + ".json")).write_text(json.dumps(record))
            with patch.object(CLEANUP, "snapshot", return_value=self.before), \
                    patch.object(CLEANUP, "process_inventory", return_value=({1: self.init, 10: root,
                                                                             30: child, os.getpid(): verifier}, [])), \
                    patch.object(CLEANUP, "direct_children", return_value={os.getpid(), 30}), \
                    patch.object(CLEANUP.sys, "argv", ["cleanup", "verify", directory, "--run-id", run_id,
                                                       "--command-exit-code", "0"]):
                self.assertEqual(self.run_cleanup(), 1)
            result = json.loads((Path(directory) / ("attribution-" + run_id + ".json")).read_text())
            self.assertEqual([process["pid"] for process in result["surviving_processes"]], [30])

    def test_missing_metadata_for_a_surviving_process_fails_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            process = proc / "30"
            process.mkdir()
            (process / "stat").write_text("30 (fixture) S 1 " + "0 " * 17 + "300")
            processes, errors = CLEANUP.process_inventory(proc_root=proc)
            self.assertEqual(processes, {})
            self.assertEqual(len(errors), 1)
            self.assertIn("pid 30", errors[0])
            (process / "stat").unlink()
            self.assertEqual(CLEANUP.process_inventory(proc_root=proc), ({}, []))

    def test_inventory_finds_nonleader_threads_and_namespace_descriptors(self):
        def stat(pid, ppid, start, state="S"):
            return f"{pid} (name with ) parentheses) {state} {ppid} " + "0 " * 17 + str(start)

        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            process = proc / "30"
            process.mkdir()
            (process / "stat").write_text(stat(30, 10, 300))
            (process / "cgroup").write_text("0::/fixture\n")
            for tid in [30, 31]:
                task = process / "task" / str(tid)
                (task / "ns").mkdir(parents=True)
                (task / "fd").mkdir()
                (task / "stat").write_text(stat(tid, 10, 300))
                (task / "ns/net").symlink_to("net:[102]" if tid == 31 else "net:[100]")
                (task / "ns/mnt").symlink_to("mnt:[200]")
            (process / "task/30/fd/7").symlink_to("mnt:[202]")
            processes, errors = CLEANUP.process_inventory({"net": {"102"}, "mnt": {"202"}}, proc)
            self.assertEqual(errors, [])
            self.assertEqual(processes[30]["start_time"], 300)
            self.assertEqual(processes[30]["namespaces"], {
                "net": {"102": ["task:31"]}, "mnt": {"202": ["fd:30:7"]},
            })

    def test_surviving_namespaces_and_host_residue_fail_cleanup(self):
        for kind, value in [
            ("net", "102"), ("mnt", "202"), ("named_netns", "leaked-netns"),
            ("bpffs_entries", "leaked-pin f 13"), ("bpffs_mounts", "new bpffs mount"),
            ("interfaces", "leaked-veth"),
        ]:
            with self.subTest(kind=kind):
                after = copy.deepcopy(self.before)
                after[kind].append(value)
                self.assertEqual(CLEANUP.differences(self.before, after), {
                    kind: {"added": [value], "removed": []},
                })

    def test_only_unrelated_namespace_departure_is_allowed(self):
        after = copy.deepcopy(self.before)
        after["net"].pop()
        after["mnt"].pop()
        self.assertEqual(CLEANUP.differences(self.before, after), {})
        after["bpffs_entries"].clear()
        self.assertIn("bpffs_entries", CLEANUP.differences(self.before, after))

    def test_missing_or_incomplete_baseline_fails(self):
        with self.assertRaises(ValueError):
            CLEANUP.differences({}, self.before)
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(CLEANUP, "snapshot", return_value=self.before), \
                patch.object(CLEANUP.sys, "argv", ["cleanup", "verify", directory]):
            self.assertEqual(self.run_cleanup(), 1)

    def test_baseline_cannot_be_overwritten_and_failed_cleanup_is_retained(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(CLEANUP, "snapshot", return_value=self.before), \
                patch.object(CLEANUP.sys, "argv", ["cleanup", "snapshot", directory]):
            self.assertEqual(self.run_cleanup(), 0)
            baseline = (Path(directory) / "before.json").read_bytes()
            self.assertEqual(self.run_cleanup(), 1)
            self.assertEqual((Path(directory) / "before.json").read_bytes(), baseline)
            with patch.object(CLEANUP.sys, "argv", ["cleanup", "verify", directory]):
                self.assertEqual(self.run_cleanup(), 0)
                self.before["net"].append("leaked")
                self.assertEqual(self.run_cleanup(), 1)
            result = json.loads((Path(directory) / "result.json").read_text())
            self.assertFalse(result["passed"])
            self.assertIn("net", result["differences"])

    def test_missing_namespace_inventory_is_an_error(self):
        with patch.object(CLEANUP.subprocess, "check_output", return_value=""):
            with self.assertRaisesRegex(ValueError, "incomplete net namespace inventory"):
                CLEANUP.snapshot()


def workflow_jobs(name):
    workflow = (RUNNER.ROOT / ".github/workflows" / name).read_text()
    parts = re.split(r"^  ([a-z][a-z0-9-]+):\n", workflow.split("\njobs:\n", 1)[1], flags=re.M)
    return dict(zip(parts[1::2], parts[2::2]))


class WorkflowTests(unittest.TestCase):
    def test_host_qualification_has_one_owner_with_its_own_preflight_and_cleanup(self):
        jobs = workflow_jobs("ci.yml")
        host = jobs["rust-local-kernel-lifecycle"]
        legacy = workflow_jobs("gtpu-privileged.yml")["privileged-gtpu"]
        self.assertNotIn("qualify-local-kernel-lifecycle.py", legacy)
        self.assertIn("timeout-minutes: 30\n", legacy)
        self.assertIn("runs-on: ubuntu-latest\n", host)
        self.assertLessEqual(int(re.search(r"timeout-minutes: (\d+)", host)[1]), 45)
        self.assertNotRegex(host, r"(?m)^    (needs|if):")
        self.assertNotIn("continue-on-error", host)
        self.assertNotIn("CARGO_PROFILE_", host)
        self.assertIn("shared-key: opc-local-kernel-lifecycle\n", host)
        self.assertIn("workspaces: . -> target/local-kernel-lifecycle\n", host)
        self.assertIn("CARGO_TARGET_DIR: ${{ github.workspace }}/target/local-kernel-lifecycle\n", host)
        steps = re.split(r"^      - name: ", host, flags=re.M)[1:]
        qualify = next(step for step in steps if step.startswith("Qualify exact local kernel lifecycle\n"))
        self.assertEqual(sum("ci/qualify-local-kernel-lifecycle.py" in step for step in steps), 1)
        self.assertEqual(qualify.split("        run: |\n", 1)[1].strip(),
                         'python3 ci/check-local-kernel-lifecycle-cleanup.py run \\\n'
                         '            "${RUNNER_TEMP}/local-kernel-lifecycle-cleanup" -- \\\n'
                         '            python3 ci/qualify-local-kernel-lifecycle.py \\\n'
                         '            --evidence-dir "${RUNNER_TEMP}/local-kernel-lifecycle"')
        cleanup = next(step for step in steps if step.startswith("Require local kernel lifecycle cleanup\n"))
        self.assertIn("if: always()\n", cleanup)
        self.assertIn("check-local-kernel-lifecycle-cleanup.py verify", cleanup)
        upload = next(step for step in steps if step.startswith("Upload local kernel lifecycle evidence\n"))
        self.assertIn("if: always()\n", upload)
        self.assertIn("overwrite: true\n", upload)
        self.assertIn("local-kernel-lifecycle-cleanup", upload)
        self.assertLess(host.index("sudo modprobe ip_gre"), host.index("cleanup.py snapshot"))
        self.assertLess(host.index("cleanup.py snapshot"), host.index("sudo unshare"))
        self.assertLess(host.index("Check local kernel lifecycle support"), host.index("Qualify exact"))
        self.assertIn("unshare -n -m --propagation private", host)
        self.assertEqual(host.count("check-local-kernel-lifecycle-cleanup.py run"), 4)
        self.assertLess(host.index('mkdir -p "${RUNNER_TEMP}/local-kernel-lifecycle-cleanup"'),
                        host.index("cleanup.py snapshot"))

    def test_both_workflows_keep_the_same_unfiltered_triggers(self):
        workflows = [(RUNNER.ROOT / ".github/workflows" / name).read_text()
                     for name in ["ci.yml", "gtpu-privileged.yml"]]
        triggers = [text.split("\non:\n", 1)[1].split("\npermissions:\n", 1)[0] for text in workflows]
        self.assertEqual(triggers[0], triggers[1])
        self.assertNotIn("paths", triggers[0])

    def test_existing_required_aggregate_rejects_lifecycle_failure_cancel_and_skip(self):
        aggregate = workflow_jobs("ci.yml")["rust"]
        self.assertIn("if: always()\n", aggregate)
        self.assertIn("      - rust-local-kernel-lifecycle\n", aggregate)
        command = textwrap.dedent(aggregate.split("        run: |\n", 1)[1])
        for status in ["success", "failure", "cancelled", "skipped"]:
            with self.subTest(status=status):
                env = dict(os.environ, LANE_RESULTS=json.dumps({
                    "rust-gates": {"result": "success"},
                    "rust-local-kernel-lifecycle": {"result": status},
                }))
                result = subprocess.run(["bash", "-e", "-c", command], env=env, capture_output=True, check=False)
                self.assertEqual(result.returncode == 0, status == "success", result.stderr)


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

    def run_guest(self, code=0, listed=None, kernel="5.14.0-427.20.1.el9_4.x86_64", keep_going=False):
        evidence = self.root / "evidence"
        argv = ["qualify", "--run-bundle", str(self.bundle), "--evidence-dir", str(evidence),
                "--require-kernel", r"5\.14\.0-427\..*\.el9_4\.x86_64"]
        if keep_going:
            argv.append("--keep-going")
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
            exit_code = code[len(invocations) - 1] if isinstance(code, list) else code
            stdout.write("test result: ok. 1 passed; 0 failed; 0 ignored;\n" if exit_code == 0
                         else "test result: FAILED. 0 passed; 1 failed; 0 ignored;\n")
            return subprocess.CompletedProcess(command, exit_code)

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

    def test_keep_going_runs_later_cases_and_retains_the_failed_result(self):
        code, record, invocations = self.run_guest(code=[101, 0], keep_going=True)
        self.assertEqual(code, 1)
        self.assertEqual(len(invocations), 2)
        self.assertEqual([case["test"] for case in record["cases"]], self.cases["crate-a"])
        self.assertEqual([case["exit_code"] for case in record["cases"]], [101, 0])
        self.assertEqual([case["passed"] for case in record["cases"]], [False, True])
        self.assertTrue(record["complete"] and record["bundle_unchanged"])
        self.assertFalse(record["passed"])
        for case in record["cases"]:
            log = self.root / "evidence" / case["log"]
            self.assertTrue(log.is_file())
            self.assertEqual(case["log_sha256"], RUNNER.sha256(log))

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
