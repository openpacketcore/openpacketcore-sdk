#!/usr/bin/env python3
"""Coverage, profile and required-check regressions for the egress job split."""

import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch


# The workflow runs this test with -I; import only the explicit CI module path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
SPEC = importlib.util.spec_from_file_location(
    "egress_fence_tests", Path(__file__).with_name("egress-fence-tests.py"))
assert SPEC is not None and SPEC.loader is not None
FENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FENCE)


def fixture():
    rows = []
    for name in FENCE.ISOLATED_TESTS:
        integration = name in FENCE.ISOLATED_INTEGRATION
        rows.append({"package": "opc-session-store",
                     "target": "consensus_openraft" if integration else "opc_session_store",
                     "kind": ["test"] if integration else ["lib"],
                     "name": name, "ignored": False, "shard": FENCE.owner(name)})
    for number in range(300):
        name = f"module::ordinary_{number}"
        rows.append({"package": "opc-session-store", "target": "opc_session_store",
                     "kind": ["lib"], "name": name, "ignored": number % 11 == 0,
                     "shard": FENCE.owner(name)})
    # A duplicate name in a different harness is valid. Both must use the
    # same shard because Cargo passes the harness exclusions to every binary.
    row = dict(rows[-1], package="opc-runtime", target="opc_runtime")
    rows.append(row)
    # A sibling of an isolated name must not be swallowed by a prefix skip.
    name = FENCE.OPTIMIZED_LIB[0] + "_new_sibling"
    rows.append(dict(rows[-1], name=name, shard=FENCE.owner(name), ignored=False))
    return rows


def ordinary(commands):
    return next(command for command in commands if command["name"] == "ordinary")


def skips(command):
    argv = command["argv"]
    return {argv[i + 1] for i, value in enumerate(argv) if value == "--skip"}


class ScopePayloadSerialPhaseTests(unittest.TestCase):
    NAMES = (
        "consensus::store::sequential_wal_sdk_tests::scope_payload_cost::"
        "scope_large_child_write_decodes_one_payload_per_voter_independent_of_history",
        "consensus::store::sequential_wal_sdk_tests::scope_child_read::"
        "scope_child_read_three_large_children_refuse_the_whole_observation",
    )

    def setUp(self):
        packages = [{
            "id": name, "name": name, "version": "0.1.0", "targets": [
                {"name": name.replace("-", "_"), "kind": ["lib"], "test": True},
            ],
        } for name in (*FENCE.PACKAGES, "opc-session-testkit")]
        for package, target in (("opc-session-store", "consensus_openraft"),
                                ("opc-session-testkit", "qualification_profile")):
            next(p for p in packages if p["name"] == package)["targets"].append(
                {"name": target, "kind": ["test"], "test": True})
        metadata = {"workspace_root": str(FENCE.ROOT), "packages": packages,
                    "workspace_members": [p["id"] for p in packages],
                    "workspace_default_members": [p["id"] for p in packages]}
        patcher = patch.object(FENCE.cargo_test_selection, "workspace_metadata", return_value=metadata)
        patcher.start()
        self.addCleanup(patcher.stop)

    def rows(self):
        return [row for row in fixture() if row["name"] not in self.NAMES] + [
            {"package": "opc-session-store", "target": "opc_session_store",
             "kind": ["lib"], "name": name, "ignored": False, "shard": 1}
            for name in self.NAMES
        ]

    def test_serial_phase_runs_first_once_and_preserves_original_selection(self):
        plans = {shard: FENCE.plans(self.rows(), shard) for shard in FENCE.SHARDS}
        self.assertEqual(plans[1][:len(self.NAMES)], [{"name": name, "env": {}, "argv": [
            "cargo", "test", *FENCE.SELECTION, "--quiet", "--lib", "--",
            "--test-threads=1", "--nocapture", "--exact", name,
        ]} for name in self.NAMES])
        exact = [(shard, command) for shard, plan in plans.items()
                 for command in plan if command["name"] in self.NAMES]
        self.assertEqual(exact, [(1, command) for command in plans[1][:len(self.NAMES)]])
        self.assertEqual(plans[1][len(self.NAMES)]["name"], "ordinary")
        for shard in FENCE.ORDINARY_SHARDS:
            ordinary = next(c for c in plans[shard] if c["name"] == "ordinary")
            self.assertIn("--exact", ordinary["argv"])
            for name in self.NAMES:
                self.assertEqual(ordinary["argv"].count(name), 1)
                self.assertIn(name, skips(ordinary))
        FENCE.verify_plans(plans)

    def test_missing_ignored_duplicate_or_wrong_harness_fails(self):
        for name in self.NAMES:
            for mutation in ("missing", "ignored", "duplicate", "target", "package", "kind"):
                rows = self.rows()
                row = next(row for row in rows if row["name"] == name)
                if mutation == "missing":
                    rows.remove(row)
                elif mutation == "duplicate":
                    rows.append(dict(row, package="another-package"))
                elif mutation == "ignored":
                    row["ignored"] = True
                else:
                    row[mutation] = ["test"] if mutation == "kind" else "other"
                with self.subTest(test=name, mutation=mutation), self.assertRaises(ValueError):
                    FENCE.verify(rows)

    def test_missing_duplicate_late_or_overlapping_serial_commands_fail(self):
        for serial_index, name in enumerate(self.NAMES):
            for mutation in ("missing", "duplicate", "renamed-duplicate", "late", "overlap", "threads", "profile"):
                plans = {shard: FENCE.plans(self.rows(), shard) for shard in FENCE.SHARDS}
                ordinary_index = len(self.NAMES)
                if mutation == "missing":
                    plans[1].pop(serial_index)
                elif mutation == "duplicate":
                    plans[1].insert(serial_index, copy.deepcopy(plans[1][serial_index]))
                elif mutation == "renamed-duplicate":
                    duplicate = copy.deepcopy(plans[1][serial_index])
                    duplicate["name"] = "another-command"
                    plans[0].append(duplicate)
                elif mutation == "late":
                    plans[1][serial_index], plans[1][ordinary_index] = plans[1][ordinary_index], plans[1][serial_index]
                elif mutation == "overlap":
                    argv = plans[1][ordinary_index]["argv"]
                    index = argv.index(name)
                    del argv[index - 1:index + 1]
                elif mutation == "threads":
                    argv = plans[1][serial_index]["argv"]
                    argv[argv.index("--test-threads=1")] = "--test-threads=4"
                else:
                    plans[1][serial_index]["env"]["CARGO_PROFILE_TEST_OPT_LEVEL"] = "1"
                with self.subTest(test=name, mutation=mutation), self.assertRaises(ValueError):
                    FENCE.verify_plans(plans)

    def test_equivalent_cargo_selectors_cannot_duplicate_a_serial_test(self):
        for name in self.NAMES:
            for selector in ([], ["--lib"], ["--tests"], ["--all-targets"]):
                plans = {shard: FENCE.plans(self.rows(), shard) for shard in FENCE.SHARDS}
                plans[0].append({"name": "second-scope-execution", "env": {}, "argv": [
                    "cargo", "test", *FENCE.SELECTION, "--quiet", *selector,
                    "--", "--test-threads=4", "--exact", name,
                ]})
                with self.subTest(test=name, selector=selector), self.assertRaises(ValueError):
                    FENCE.verify_plans(plans)

    def test_same_filter_in_another_package_does_not_duplicate_the_library_test(self):
        for name in self.NAMES:
            plans = {shard: FENCE.plans(self.rows(), shard) for shard in FENCE.SHARDS}
            plans[0].append({"name": "another-package", "env": {}, "argv": [
                "cargo", "test", "--locked", "--package=opc-runtime", "--all-features",
                "--lib", "--", "--test-threads=4", "--exact", name,
            ]})
            with self.subTest(test=name):
                FENCE.verify_plans(plans)

    def test_cargo_filters_and_libtest_value_spellings_cannot_hide_overlap(self):
        for name in self.NAMES:
            for suffix in (["--", "--test-threads", "4", "--exact", name],
                           [name, "--", "--exact", "--test-threads=4"],
                           ["--", "--skip=unrelated", "--exact", name]):
                plans = {shard: FENCE.plans(self.rows(), shard) for shard in FENCE.SHARDS}
                plans[0].append({"name": "second-scope-execution", "env": {}, "argv": [
                    "cargo", "test", *FENCE.SELECTION, "--tests", *suffix,
                ]})
                with self.subTest(test=name, suffix=suffix), self.assertRaises(ValueError):
                    FENCE.verify_plans(plans)

    def test_non_library_targets_and_skipped_names_do_not_overlap(self):
        for name in self.NAMES:
            for suffix in (["--test=consensus_*", "--", "--exact", name],
                           ["--all-targets", "--", "--exact", "--skip=" + name, name],
                           ["--doc", "--", "--exact", name],
                           ["--lib", "--no-run", "--", "--exact", name]):
                plans = {shard: FENCE.plans(self.rows(), shard) for shard in FENCE.SHARDS}
                plans[0].append({"name": "another-command", "env": {}, "argv": [
                    "cargo", "test", *FENCE.SELECTION, *suffix,
                ]})
                with self.subTest(test=name, suffix=suffix):
                    FENCE.verify_plans(plans)

    def test_unmodeled_target_selector_is_rejected(self):
        plans = {shard: FENCE.plans(self.rows(), shard) for shard in FENCE.SHARDS}
        plans[0].append({"name": "unknown-selection", "env": {}, "argv": [
            "cargo", "test", *FENCE.SELECTION, "--future-selector",
        ]})
        with self.assertRaisesRegex(ValueError, "unsupported Cargo test option"):
            FENCE.verify_plans(plans)


class NativeLogBoundPhaseTests(unittest.TestCase):
    NAMES = FENCE.native_log_bound.TESTS
    setUp = ScopePayloadSerialPhaseTests.setUp

    def rows(self):
        return [row for row in fixture() if row["name"] not in self.NAMES] + [
            {"package": "opc-session-store", "target": "opc_session_store",
             "kind": ["lib"], "name": name, "ignored": False,
             "shard": FENCE.owner(name)}
            for name in self.NAMES
        ]

    def test_full_native_bounds_run_once_on_dedicated_parallel_shards(self):
        plans = {shard: FENCE.plans(self.rows(), shard) for shard in FENCE.SHARDS}
        for name in self.NAMES:
            owner = 4 + self.NAMES.index(name)
            selected = [(shard, index, command) for shard, commands in plans.items()
                        for index, command in enumerate(commands) if command["name"] == name]
            with self.subTest(name=name):
                self.assertEqual(len(selected), 1)
                shard, index, command = selected[0]
                self.assertEqual(shard, owner)
                self.assertEqual(index, 0)
                self.assertEqual(len(plans[owner]), 1)
                self.assertEqual(command["env"], {"CARGO_PROFILE_TEST_OPT_LEVEL": "1"})
                self.assertEqual(command["argv"], [
                    "cargo", "test", *FENCE.SELECTION, "--quiet", "--lib", "--",
                    "--test-threads=1", "--nocapture", "--exact", name,
                ])
                for shard in FENCE.ORDINARY_SHARDS:
                    self.assertIn(name, skips(ordinary(plans[shard])))
        FENCE.verify_plans(plans)

    def test_full_native_inventory_requires_enabled_unique_library_tests(self):
        for name in self.NAMES:
            for mutation in ("missing", "ignored", "duplicate", "kind"):
                rows = self.rows()
                row = next(row for row in rows if row["name"] == name)
                if mutation == "missing":
                    rows.remove(row)
                elif mutation == "ignored":
                    row["ignored"] = True
                elif mutation == "duplicate":
                    rows.append(dict(row, package="another-package"))
                else:
                    row["kind"] = ["test"]
                with self.subTest(name=name, mutation=mutation), self.assertRaises(ValueError):
                    FENCE.verify(rows)

    def test_full_native_precheck_rejects_missing_ambiguous_or_ignored_optimized_names(self):
        plans = {shard: FENCE.plans(self.rows(), shard) for shard in FENCE.SHARDS}
        name = self.NAMES[0]
        command = {"name": name, "env": {"CARGO_PROFILE_TEST_OPT_LEVEL": "1"}, "argv": [
            "cargo", "test", *FENCE.SELECTION, "--quiet", "--lib", "--",
            "--test-threads=1", "--nocapture", "--exact", name,
        ]}
        for output in ("", f"{name}: test\n{name}: test\n", f"{name}_future: test\n"):
            with self.subTest(output=output), patch.object(FENCE, "capture", return_value=output), \
                    self.assertRaises(ValueError):
                FENCE.precheck_native_log_bound([command])
        with patch.object(FENCE, "capture", side_effect=[f"{name}: test\n", f"{name}: test\n"]), \
                self.assertRaises(ValueError):
            FENCE.precheck_native_log_bound([command])
        with patch.object(FENCE, "capture", side_effect=[f"{name}: test\n", ""]) as capture:
            FENCE.precheck_native_log_bound([command])
        self.assertEqual(capture.call_count, 2)
        for call in capture.call_args_list:
            self.assertEqual(call.args[0][:len(command["argv"])], command["argv"])
            self.assertIn("--list", call.args[0])
            self.assertEqual(call.kwargs["env"]["CARGO_PROFILE_TEST_OPT_LEVEL"], "1")
        with patch.object(FENCE, "capture") as capture:
            FENCE.precheck_native_log_bound([ordinary(plans[0])])
            capture.assert_not_called()

    def test_missing_optimized_name_stops_the_entrypoint_before_any_suite_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "test-map.json"
            with (
                patch.object(sys, "argv", ["egress-fence-tests.py", "--shard", "4", "--output", str(output)]),
                patch.object(FENCE, "inventory", return_value=self.rows()),
                patch.object(FENCE, "capture", side_effect=lambda argv, **kwargs:
                             "f" * 40 if argv[0] == "git" else ""),
                patch.object(FENCE.subprocess, "run") as execute,
                self.assertRaisesRegex(ValueError, "resolve exactly once at O1"),
            ):
                FENCE.main()
            execute.assert_not_called()
            self.assertTrue(output.is_file())

    def test_dedicated_native_entrypoint_builds_only_its_optimized_profile(self):
        name = self.NAMES[0]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "mapping.json"
            with (
                patch.object(sys, "argv", ["egress-fence-tests.py", "--shard", "4", "--output", str(output)]),
                patch.object(FENCE, "inventory", side_effect=AssertionError("ordinary profile must not compile")),
                patch.object(FENCE, "capture", side_effect=["f" * 40, f"{name}: test\n", ""]) as capture,
                patch.object(FENCE, "run_commands") as execute,
            ):
                self.assertEqual(FENCE.main(), 0)
            execute.assert_called_once_with([FENCE.native_log_bound_command(name)])
            self.assertEqual(capture.call_count, 3)
            self.assertTrue(all(call.kwargs["env"]["CARGO_PROFILE_TEST_OPT_LEVEL"] == "1"
                                for call in capture.call_args_list[1:]))
            self.assertTrue(output.is_file())

    def test_ordinary_entrypoint_does_not_precompile_any_full_bound_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "mapping.json"
            with (
                patch.object(sys, "argv", ["egress-fence-tests.py", "--shard", "2", "--output", str(output)]),
                patch.object(FENCE, "inventory", return_value=self.rows()),
                patch.object(FENCE, "capture", return_value="f" * 40) as capture,
                patch.object(FENCE, "run_commands") as execute,
            ):
                self.assertEqual(FENCE.main(), 0)
            capture.assert_called_once_with(["git", "rev-parse", "HEAD"])
            self.assertTrue(all(command["env"] == {} for command in execute.call_args.args[0]))
            self.assertFalse(any(command["name"] in self.NAMES for command in execute.call_args.args[0]))

    def test_full_native_plan_rejects_lost_duplicate_early_and_overlapping_execution(self):
        for name in self.NAMES:
            owner = FENCE.owner(name)
            for mutation in ("missing", "duplicate", "ordinary-owner", "overlap", "threads", "profile"):
                plans = {shard: FENCE.plans(self.rows(), shard) for shard in FENCE.SHARDS}
                command = next((command for command in plans[owner] if command["name"] == name), None)
                self.assertIsNotNone(command)
                if mutation == "missing":
                    plans[owner].remove(command)
                elif mutation == "duplicate":
                    plans[owner].append(copy.deepcopy(command))
                elif mutation == "ordinary-owner":
                    plans[owner].remove(command)
                    plans[1].append(command)
                elif mutation == "overlap":
                    duplicate = copy.deepcopy(command)
                    duplicate["name"] = "concealed-overlap"
                    plans[owner].append(duplicate)
                elif mutation == "threads":
                    command["argv"][command["argv"].index("--test-threads=1")] = "--test-threads=4"
                else:
                    command["env"] = {}
                with self.subTest(name=name, mutation=mutation), self.assertRaises(ValueError):
                    FENCE.verify_plans(plans)


class PartitionTests(unittest.TestCase):
    def test_every_old_harness_test_runs_on_exactly_one_shard(self):
        rows = fixture()
        plans = {shard: FENCE.plans(rows, shard) for shard in FENCE.SHARDS}
        for row in rows:
            with self.subTest(name=row["name"], target=row["target"]):
                ordinary_owners = [i for i in FENCE.ORDINARY_SHARDS if row["name"] not in skips(ordinary(plans[i]))]
                isolated = [i for i, plan in plans.items()
                            if any(c["name"] == row["name"] for c in plan)]
                self.assertEqual(ordinary_owners + isolated, [row["shard"]])

    def test_new_tests_and_same_prefix_siblings_are_included(self):
        rows = fixture()
        for prefix in [FENCE.OPTIMIZED_LIB[0], *FENCE.SERIAL_LIB_TESTS, "new_module"]:
            name = prefix + "::new_test"
            row = dict(rows[-1], name=name, shard=FENCE.owner(name))
            rows.append(row)
            self.assertNotIn(name, skips(ordinary(FENCE.plans(rows, row["shard"]))))
            for shard in set(FENCE.ORDINARY_SHARDS) - {row["shard"]}:
                self.assertIn(name, skips(ordinary(FENCE.plans(rows, shard))))

    def test_every_ordinary_shard_keeps_feature_unification_and_exact_skips(self):
        for shard in FENCE.ORDINARY_SHARDS:
            command = ordinary(FENCE.plans(fixture(), shard))
            argv = command["argv"]
            self.assertEqual(argv[:2 + len(FENCE.SELECTION)], ["cargo", "test", *FENCE.SELECTION])
            self.assertIn("--tests", argv)
            self.assertIn("--test-threads=4", argv)
            self.assertIn("--exact", argv)
            self.assertNotIn("--ignored", argv)
            self.assertEqual(command["env"], {})
            self.assertTrue(set(FENCE.SPECIAL).issubset(skips(command)))

    def test_existing_isolation_and_optimized_profile_are_retained(self):
        commands = [c for shard in FENCE.SHARDS for c in FENCE.plans(fixture(), shard)]
        exact = [c for c in commands if c["name"] in FENCE.SPECIAL]
        self.assertEqual({c["name"] for c in exact}, set(FENCE.SPECIAL))
        self.assertEqual(len(exact), 14)
        self.assertEqual(FENCE.plans(fixture(), FENCE.PROOF_SHARD), exact)
        self.assertTrue(all(FENCE.owner(c["name"]) == FENCE.PROOF_SHARD for c in exact))
        for command in exact:
            argv = command["argv"]
            self.assertEqual(argv[argv.index("-p") + 1], "opc-session-store")
            self.assertEqual(argv.count("-p"), 1)
            self.assertIn("--all-features", argv)
            self.assertEqual(argv[-3:], ["--test-threads=1", "--exact", command["name"]])
            optimized = command["name"] in FENCE.OPTIMIZED_LIB
            self.assertEqual(command["env"], {"CARGO_PROFILE_TEST_OPT_LEVEL": "1"} if optimized else {})
            if command["name"] in FENCE.ISOLATED_INTEGRATION:
                self.assertEqual(argv[argv.index("--test") + 1], "consensus_openraft")
            else:
                self.assertIn("--lib", argv)

    def test_examples_doctests_and_qualification_each_have_one_owner(self):
        all_commands = [c for shard in FENCE.SHARDS for c in FENCE.plans(fixture(), shard)]
        for name in ["examples", "doctests", "qualification-profile"]:
            self.assertEqual(sum(c["name"] == name for c in all_commands), 1)
            self.assertIn(name, {c["name"] for c in FENCE.plans(fixture(), 1)})
        examples = next(c for c in all_commands if c["name"] == "examples")
        self.assertEqual(examples["argv"], ["cargo", "build", *FENCE.SELECTION, "--quiet", "--examples"])
        docs = next(c for c in all_commands if c["name"] == "doctests")
        self.assertIn("--doc", docs["argv"])
        self.assertEqual(skips(docs), set(FENCE.SPECIAL))
        qualification = next(c for c in all_commands if c["name"] == "qualification-profile")
        self.assertEqual(qualification["argv"], [
            "cargo", "test", "--locked", "-p", "opc-session-testkit", "--test",
            "qualification_profile", "--quiet", "--", "--test-threads=1"])

    def test_missing_renamed_ignored_or_ambiguous_isolated_test_fails(self):
        for mutation in ["missing", "renamed", "ignored", "ambiguous", "target", "kind", "package"]:
            rows = fixture()
            if mutation == "missing":
                rows.pop(0)
            elif mutation == "renamed":
                rows[0]["name"] += "_renamed"
            elif mutation == "ignored":
                rows[0]["ignored"] = True
            elif mutation == "ambiguous":
                rows.append(dict(rows[0], target="other"))
            elif mutation == "kind":
                rows[0]["kind"] = ["test"]
            else:
                rows[0][mutation] = "other"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                FENCE.verify(rows)

    def test_missing_duplicate_or_wrongly_assigned_inventory_fails(self):
        rows = fixture()
        for broken in [[], rows + [rows[0]], [dict(r, shard=99) for r in rows]]:
            with self.assertRaises(ValueError):
                FENCE.verify(broken)
        with self.assertRaises(ValueError):
            FENCE.plans(rows, max(FENCE.SHARDS) + 1)

    def test_libtest_inventory_rejects_unrecognized_and_duplicate_output(self):
        self.assertEqual(FENCE.listing("alpha: test\nbeta: test\n\n2 tests, 0 benchmarks\n"), ["alpha", "beta"])
        self.assertEqual(FENCE.listing("0 tests, 0 benchmarks\n"), [])
        for output in ["alpha: test\nalpha: test\n", "custom harness ran successfully\n", "alpha: benchmark\n"]:
            with self.assertRaises(ValueError):
                FENCE.listing(output)


class RequiredCheckTests(unittest.TestCase):
    def needs(self, result="success", decision="true", qualification="success"):
        return {"changes": {"result": result, "outputs": {"run": decision}},
                **{name: {"result": qualification} for name in FENCE.REQUIRED_JOBS}}

    def test_every_new_job_failure_cancellation_skip_or_missing_result_blocks(self):
        for job in FENCE.REQUIRED_JOBS:
            for result in ["failure", "cancelled", "skipped", None, ""]:
                needs = self.needs()
                needs[job]["result"] = result
                with self.subTest(job=job, result=result), self.assertRaises(ValueError):
                    FENCE.require_jobs(needs)

    def test_only_successful_explicit_skip_accepts_skipped_jobs(self):
        FENCE.require_jobs(self.needs(decision="false", qualification="skipped"))
        for result in ["failure", "cancelled", "skipped", ""]:
            with self.assertRaises(ValueError):
                FENCE.require_jobs(self.needs(result=result, decision="false", qualification="skipped"))
        for decision in [None, "", False, "False", "true"]:
            with self.assertRaises(ValueError):
                FENCE.require_jobs(self.needs(decision=decision, qualification="skipped"))

    def test_failed_or_missing_decision_requires_full_success(self):
        for result in ["success", "failure", "cancelled", "skipped"]:
            for decision in [None, "", "true"]:
                FENCE.require_jobs(self.needs(result=result, decision=decision))
        needs = self.needs()
        del needs["changes"]["outputs"]
        FENCE.require_jobs(needs)

    def test_skip_decision_cannot_mask_a_qualification_failure(self):
        needs = self.needs(decision="false", qualification="skipped")
        needs["oracles"]["result"] = "failure"
        with self.assertRaises(ValueError):
            FENCE.require_jobs(needs)

    def test_aggregate_rejects_a_missing_or_unaccounted_job(self):
        needs = self.needs()
        FENCE.require_jobs(needs)
        for key in needs:
            broken = copy.deepcopy(needs)
            del broken[key]
            with self.assertRaises(ValueError):
                FENCE.require_jobs(broken)
        with self.assertRaises(ValueError):
            FENCE.require_jobs(dict(needs, forgotten={"result": "success"}))


class WorkflowTests(unittest.TestCase):
    def assert_native_proof_matrix(self, native):
        self.assertIn(f"shard: {list(FENCE.native_log_bound.EGRESS_SHARDS)}\n", native)

    def test_new_registered_proof_requires_a_matching_workflow_shard(self):
        workflow = (FENCE.ROOT / ".github/workflows/egress-fence.yml").read_text()
        native = workflow.split("\n  host-native-log-proofs:\n", 1)[1]
        old_shards = FENCE.native_log_bound.EGRESS_SHARDS
        proofs = (*FENCE.native_log_bound.TESTS, "fixture::additional_full_native_proof")
        shards = tuple(range(old_shards[0], old_shards[0] + len(proofs)))
        with patch.object(FENCE.native_log_bound, "TESTS", proofs), \
                patch.object(FENCE.native_log_bound, "EGRESS_SHARDS", shards):
            with self.assertRaises(AssertionError):
                self.assert_native_proof_matrix(native)
            native = native.replace(f"shard: {list(old_shards)}\n",
                                    f"shard: {list(shards)}\n", 1)
            self.assert_native_proof_matrix(native)

    def test_cache_targets_match_each_jobs_actual_compilation_directories(self):
        workflow = (FENCE.ROOT / ".github/workflows/egress-fence.yml").read_text()
        parts = re.split(r"^  ([a-z][a-z-]+):\n", workflow.split("\njobs:\n", 1)[1],
                         flags=re.MULTILINE)
        jobs = dict(zip(parts[1::2], parts[2::2]))
        for name in FENCE.REQUIRED_JOBS:
            with self.subTest(job=name):
                # rust-cache joins target paths onto each workspace root.
                # Absolute runner.temp paths would be joined incorrectly.
                caches = set()
                for mapping in re.findall(r"workspaces: ([^\n]+)", jobs[name]):
                    workspace, target = mapping.split(" -> ")
                    self.assertFalse(Path(target).is_absolute())
                    # Compare configured paths, not this developer's physical
                    # cache symlinks (which may point at a memory filesystem).
                    caches.add(Path(os.path.abspath(FENCE.ROOT / workspace / target)))
                builds = {FENCE.ROOT / relative for relative in re.findall(
                    r'export CARGO_TARGET_DIR="\$\{GITHUB_WORKSPACE\}/([^"\n]+)"', jobs[name])}
                self.assertTrue(builds)
                self.assertEqual(caches, builds)
                self.assertTrue(all(p.is_relative_to(FENCE.ROOT) for p in caches))
        self.assertIn("shared-key: egress-fence-tests-${{ matrix.shard }}\n", jobs["host-tests"])
        self.assertIn("shared-key: egress-fence-proofs\n", jobs["host-proofs"])
        for name in ["host-tests", "host-proofs"]:
            self.assertNotIn("shared-key: egress-fence-host\n", jobs[name])

    def test_cache_mapping_check_is_independent_of_local_cache_symlinks(self):
        workflow = (FENCE.ROOT / ".github/workflows/egress-fence.yml").read_text()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "worktree"
            (root / ".github/workflows").mkdir(parents=True)
            (root / ".github/workflows/egress-fence.yml").write_text(workflow)
            (root / "target").mkdir()
            cache = Path(directory) / "memory-cache"
            cache.mkdir()
            (root / "target/egress-fence-host").symlink_to(cache, target_is_directory=True)
            with patch.object(FENCE, "ROOT", root):
                self.test_cache_targets_match_each_jobs_actual_compilation_directories()

    def test_both_artifact_uploads_allow_reruns_to_replace_existing_artifacts(self):
        workflow = (FENCE.ROOT / ".github/workflows/egress-fence.yml").read_text()
        uploads = [step for step in workflow.split("      - name: ")
                   if "uses: actions/upload-artifact@" in step]
        self.assertEqual(len(uploads), 3)
        for step in uploads:
            self.assertIn("          overwrite: true\n", step)

    def test_every_workload_blocks_the_existing_check_under_the_old_condition(self):
        # Keep this dependency-free: actionlint separately parses the YAML.
        # These checks bind the tested aggregate logic to the actual workflow.
        workflow = (FENCE.ROOT / ".github/workflows/egress-fence.yml").read_text()
        parts = re.split(r"^  ([a-z][a-z-]+):\n", workflow.split("\njobs:\n", 1)[1],
                         flags=re.MULTILINE)
        jobs = dict(zip(parts[1::2], parts[2::2]))
        self.assertEqual(set(jobs), {"changes", "root-cgroup-egress", *FENCE.REQUIRED_JOBS})
        condition = "if: ${{ !cancelled() && (needs.changes.result != 'success' || needs.changes.outputs.run != 'false') }}"
        for name in FENCE.REQUIRED_JOBS:
            with self.subTest(job=name):
                self.assertIn(condition, jobs[name])
                timeout = ("${{ matrix.shard == 4 && 120 || 75 }}"
                           if name == "host-native-log-proofs" else "45")
                self.assertIn(f"timeout-minutes: {timeout}\n", jobs[name])
                self.assertRegex(jobs[name], r"needs: (changes|\[changes, sources\])\n")
                self.assertIn("if: always()\n        run: bash ci/egress-fence-cleanup.sh", jobs[name])
        aggregate = jobs["root-cgroup-egress"]
        self.assertIn("name: Root-cgroup egress fence\n", aggregate)
        self.assertIn("if: always()\n", aggregate)
        dependencies = re.search(r"needs: \[([^]]+)\]", aggregate)
        self.assertIsNotNone(dependencies)
        self.assertEqual(set(dependencies[1].split(", ")), {"changes", *FENCE.REQUIRED_JOBS})
        self.assertIn("EGRESS_JOB_RESULTS: ${{ toJSON(needs) }}", aggregate)
        self.assertIn("run: python3 ci/egress-fence-tests.py --check-jobs", aggregate)
        host = jobs["host-tests"]
        self.assertIn("fail-fast: false\n", host)
        self.assertIn("shard: [0, 1, 2]\n", host)
        self.assertIn("run: ci/setup-fsverity-tmp.sh\n", host)
        self.assertIn("--shard '${{ matrix.shard }}'", host)
        native = jobs["host-native-log-proofs"]
        self.assert_native_proof_matrix(native)
        self.assertIn("fail-fast: false\n", native)
        self.assertIn("run: ci/setup-fsverity-tmp.sh\n", native)
        self.assertIn("--shard '${{ matrix.shard }}'", native)
        proofs = jobs["host-proofs"]
        self.assertIn("run: ci/setup-fsverity-tmp.sh\n", proofs)
        self.assertIn(f"--shard {FENCE.PROOF_SHARD} \\\n", proofs)
        for name in ["oracles", "installer"]:
            self.assertIn("bash ci/egress-fence-kernel.sh", jobs[name])
        self.assertIn("python3 -I ci/test-egress-fence-tests.py", jobs["sources"])


if __name__ == "__main__":
    unittest.main()
