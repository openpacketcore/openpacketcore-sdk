#!/usr/bin/env python3
"""Regression coverage for the test-shard manifest/source audit."""

from __future__ import annotations

import copy
import importlib.util
import io
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("test-shards.py")
SPEC = importlib.util.spec_from_file_location("test_shards", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
TEST_SHARDS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TEST_SHARDS)


class CargoTestSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        (cls.root / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["store", "other", "disabled"]\n'
            'default-members = ["other"]\nresolver = "2"\n'
        )
        for directory, package in (("store", "opc-session-store"),
                                   ("other", "another-package"),
                                   ("disabled", "disabled-library")):
            root = cls.root / directory
            (root / "src").mkdir(parents=True)
            (root / "Cargo.toml").write_text(
                f'[package]\nname = "{package}"\nversion = "0.1.0"\nedition = "2021"\n'
                f'[lib]\nname = "{directory}_library"\n'
                + ('test = false\n' if directory == "disabled" else '')
            )
            (root / "src/lib.rs").write_text(
                'mod consensus { mod store { mod sequential_wal_sdk_tests {\n'
                + ''.join(
                    f'mod {module} {{ #[test] fn {name}() {{ println!("{directory} library ran"); }} }}\n'
                    for module, name in (
                        ("scope_payload_cost", "scope_large_child_write_decodes_one_payload_per_voter_independent_of_history"),
                        ("scope_child_read", "scope_child_read_three_large_children_refuse_the_whole_observation"),
                    )
                ) + '} } }\n'
            )
        # A same-name test in a different target must not count as a library run.
        (cls.root / "store/tests").mkdir()
        (cls.root / "store/tests/another_harness.rs").write_text(
            (cls.root / "store/src/lib.rs").read_text().replace("store library ran", "integration ran")
        )
        for kind in ("bin", "example"):
            with (cls.root / "store/Cargo.toml").open("a") as manifest:
                manifest.write(f'[[{kind}]]\nname = "disabled_{kind}"\npath = "src/{kind}.rs"\ntest = false\n')
            (cls.root / f"store/src/{kind}.rs").write_text(
                'fn main() {}\n' + (cls.root / "store/src/lib.rs").read_text().replace(
                    "store library ran", kind + " ran")
            )
        cls.environment = dict(os.environ, CARGO_TARGET_DIR=str(TEST_SHARDS.ROOT / "target/cargo-test-selection"))
        subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=cls.root,
                       env=cls.environment, check=True, capture_output=True)
        cls.metadata = TEST_SHARDS.cargo_test_selection.workspace_metadata(cls.root)

    def resolve(self, *args):
        return TEST_SHARDS.cargo_test_selection.resolve(["cargo", "test", *args], self.metadata)

    def test_real_cargo_runs_both_serial_names_under_each_equivalent_selector(self) -> None:
        for name in ScopePayloadSerialPhaseTests.NAMES:
            for selector in ([], ["--lib"], ["--tests"], ["--all-targets"]):
                argv = ["cargo", "test", "--locked", "--offline", "-p", "opc-session-store",
                        "--quiet", *selector, "--", "--exact", name, "--nocapture"]
                with self.subTest(name=name, selector=selector):
                    result = subprocess.run(argv, cwd=self.root, env=self.environment,
                                            check=True, capture_output=True, text=True)
                    self.assertEqual(result.stdout.count("store library ran"), 1)
                    resolved = TEST_SHARDS.cargo_test_selection.resolve(argv, self.metadata)
                    self.assertTrue(resolved.selects("opc-session-store", "store_library", ("lib",), name))

    def test_manifest_test_false_is_respected_unless_library_is_explicit(self) -> None:
        name = ScopePayloadSerialPhaseTests.NAMES[0]
        for selector, expected in (([], False), (["--tests"], False),
                                   (["--lib"], True), (["--all-targets"], True)):
            argv = ["cargo", "test", "--locked", "--offline", "-p", "disabled-library",
                    "--quiet", *selector, "--", "--exact", name, "--nocapture"]
            with self.subTest(selector=selector):
                result = subprocess.run(argv, cwd=self.root, env=self.environment,
                                        check=True, capture_output=True, text=True)
                self.assertEqual(result.stdout.count("disabled library ran"), int(expected))
                resolved = TEST_SHARDS.cargo_test_selection.resolve(argv, self.metadata)
                self.assertEqual(resolved.selects("disabled-library", "disabled_library", ("lib",), name), expected)

    def test_named_integration_target_does_not_run_the_same_named_library_test(self) -> None:
        name = ScopePayloadSerialPhaseTests.NAMES[0]
        argv = ["cargo", "test", "--locked", "--offline", "--package=opc-session-store",
                "--test=another_*", "--quiet", "--", "--exact", name, "--nocapture"]
        result = subprocess.run(argv, cwd=self.root, env=self.environment,
                                check=True, capture_output=True, text=True)
        self.assertEqual(result.stdout.count("integration ran"), 1)
        self.assertNotIn("store library ran", result.stdout)
        resolved = TEST_SHARDS.cargo_test_selection.resolve(argv, self.metadata)
        self.assertFalse(resolved.has_library())
        self.assertEqual(resolved.targets, frozenset())

    def test_non_library_target_flags_match_cargos_library_selection(self) -> None:
        name = ScopePayloadSerialPhaseTests.NAMES[0]
        for kind in ("bin", "example"):
            for selector in ([], ["--tests"], ["--all-targets"], ["--" + kind + "s"],
                             ["--" + kind + "=disabled_" + kind]):
                argv = ["cargo", "test", "--locked", "--offline", "-p", "opc-session-store",
                        "--quiet", *selector, "--", "--exact", name, "--nocapture"]
                with self.subTest(kind=kind, selector=selector):
                    result = subprocess.run(argv, cwd=self.root, env=self.environment,
                                            check=True, capture_output=True, text=True)
                    actual = result.stdout.count(kind + " ran")
                    self.assertIn(actual, (0, 1))
                    library_runs = result.stdout.count("store library ran")
                    self.assertIn(library_runs, (0, 1))
                    resolved = TEST_SHARDS.cargo_test_selection.resolve(argv, self.metadata)
                    self.assertEqual(resolved.selects("opc-session-store", "store_library", ("lib",), name), bool(library_runs))

    def test_metadata_controls_default_members_package_aliases_and_exclusions(self) -> None:
        self.assertEqual(self.resolve().targets, frozenset({("another-package", "other_library", ("lib",))}))
        for package in (["-p", "opc-session-store"], ["-popc-session-store"],
                        ["--package", "opc-session-store"], ["--package=opc-session-store"],
                        ["--package=opc-session-*"]):
            with self.subTest(package=package):
                self.assertEqual(self.resolve(*package, "--lib").targets,
                                 frozenset({("opc-session-store", "store_library", ("lib",))}))
        for workspace in ("--workspace", "--all"):
            selection = self.resolve(workspace, "--exclude=opc-session-*", "--lib")
            self.assertNotIn(("opc-session-store", "store_library", ("lib",)), selection.targets)
            self.assertIn(("another-package", "other_library", ("lib",)), selection.targets)

    def test_libtest_values_are_not_filters_and_cargo_filter_is_forwarded(self) -> None:
        name = ScopePayloadSerialPhaseTests.NAMES[0]
        for harness in (["--test-threads", "4", "--exact", name],
                        ["--test-threads=4", "--exact", name],
                        ["--skip=unrelated", "--exact", name]):
            selection = self.resolve("-popc-session-store", "--tests", "--", *harness)
            self.assertTrue(selection.selects("opc-session-store", "store_library", ("lib",), name))
        selection = self.resolve("-popc-session-store", name, "--", "--exact", "--test-threads", "4")
        self.assertTrue(selection.selects("opc-session-store", "store_library", ("lib",), name))
        for args in (["--", "--skip", name], ["--", "--skip=" + name],
                     ["--", "--ignored"], ["--", "--list"], ["--no-run"], ["--doc"]):
            selection = self.resolve("-popc-session-store", *args)
            self.assertFalse(selection.selects("opc-session-store", "store_library", ("lib",), name))

    def test_unmodeled_or_malformed_command_forms_fail_closed(self) -> None:
        for args in (["--future-selector"], ["--benches"], ["--config", "build.target='other'"],
                     ["--manifest-path", "other/Cargo.toml"], ["--package"],
                     ["--package=missing"], ["--exclude=opc-session-store"],
                     ["--", "--skip"], ["--", "--future-harness-option"]):
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.resolve(*args)


class ManifestTestSourceAuditTests(unittest.TestCase):
    """Direct integration sources must stay represented in Cargo metadata."""

    def package(self, root: Path, targets: list[dict]) -> dict:
        manifest = root / "Cargo.toml"
        manifest.write_text("[package]\nname = 'fixture'\n")
        return {
            "name": "fixture",
            "manifest_path": str(manifest),
            "targets": targets,
        }

    def test_rejects_a_direct_source_missing_from_cargo_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tests = root / "tests"
            tests.mkdir()
            source = tests / "forgotten.rs"
            source.touch()

            errors = TEST_SHARDS.manifest_test_source_errors(
                [self.package(root, [])], private_sources={}
            )

        self.assertEqual(
            errors,
            [
                "integration-test source fixture:tests/forgotten.rs is absent "
                "from Cargo metadata; register it in Cargo.toml or add a narrow "
                "private-module exemption"
            ],
        )

    def test_accepts_a_registered_direct_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tests = root / "tests"
            tests.mkdir()
            source = tests / "registered.rs"
            source.touch()
            package = self.package(
                root,
                [
                    {
                        "kind": ["test"],
                        "src_path": str(source),
                        "test": True,
                    }
                ],
            )

            errors = TEST_SHARDS.manifest_test_source_errors(
                [package], private_sources={}
            )

        self.assertEqual(errors, [])

    def test_accepts_the_exact_private_module_exemption(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tests = root / "tests"
            tests.mkdir()
            source = tests / "stateless_quorum_consumer.rs"
            source.touch()
            package = {
                "name": "opc-session-net",
                "manifest_path": str(root / "Cargo.toml"),
                "targets": [],
            }

            errors = TEST_SHARDS.manifest_test_source_errors(
                [package],
                private_sources={
                    (
                        "opc-session-net",
                        "tests/stateless_quorum_consumer.rs",
                    ): "fixture private module"
                },
            )

        self.assertEqual(errors, [])

    def test_rejects_a_stale_private_module_exemption(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tests = root / "tests"
            tests.mkdir()
            source = tests / "stateless_quorum_consumer.rs"
            source.touch()
            package = {
                "name": "opc-session-net",
                "manifest_path": str(root / "Cargo.toml"),
                "targets": [
                    {
                        "kind": ["test"],
                        "src_path": str(source),
                        "test": True,
                    }
                ],
            }

            errors = TEST_SHARDS.manifest_test_source_errors([package])

        self.assertEqual(
            errors,
            [
                "private integration-test exemption "
                "opc-session-net:tests/stateless_quorum_consumer.rs is now a "
                "Cargo target; remove the exemption"
            ],
        )


class I686TargetAuditTests(unittest.TestCase):
    def package(self, targets: list[dict]) -> dict:
        return {"name": "opc-session-net", "targets": targets}

    def target(self, kind: str, tested: bool = True) -> dict:
        return {"name": "future_" + kind, "kind": [kind], "test": tested}

    def test_accepts_every_supported_current_and_future_test_target(self) -> None:
        targets = [self.target(kind) for kind in ("lib", "bin", "test")]
        errors = TEST_SHARDS.i686_test_target_errors([self.package(targets)])
        self.assertEqual(errors, [])

    def test_rejects_test_enabled_examples_benches_and_unknown_kinds(self) -> None:
        for kind in ("example", "bench", "future-cargo-kind"):
            with self.subTest(kind=kind):
                errors = TEST_SHARDS.i686_test_target_errors(
                    [self.package([self.target(kind)])]
                )
                self.assertEqual(len(errors), 1)
                self.assertIn("future_" + kind, errors[0])
                self.assertIn("i686", errors[0])

    def test_compile_only_targets_do_not_need_a_test_shard(self) -> None:
        targets = [self.target(kind, False) for kind in ("example", "bench", "custom-build")]
        self.assertEqual(TEST_SHARDS.i686_test_target_errors([self.package(targets)]), [])

    def test_audit_does_not_restrict_other_packages(self) -> None:
        package = {"name": "another-package", "targets": [self.target("example")]}
        self.assertEqual(TEST_SHARDS.i686_test_target_errors([package]), [])

    def test_required_manifest_audit_rejects_uncovered_i686_targets(self) -> None:
        package = self.package([self.target("example")])
        with patch.object(TEST_SHARDS, "manifest_test_source_errors", return_value=[]), \
                self.assertRaisesRegex(SystemExit, "i686.*future_example"):
            TEST_SHARDS.integration_targets([package])


class ScopePayloadSerialPhaseTests(unittest.TestCase):
    NAMES = (
        "consensus::store::sequential_wal_sdk_tests::scope_payload_cost::"
        "scope_large_child_write_decodes_one_payload_per_voter_independent_of_history",
        "consensus::store::sequential_wal_sdk_tests::scope_child_read::"
        "scope_child_read_three_large_children_refuse_the_whole_observation",
    )

    def setUp(self) -> None:
        self.plan = TEST_SHARDS.load_plan()
        self.targets = [self.plan["heavy"]["target"], *(f"fixture_{i}" for i in range(9))]

    def test_exact_serial_phase_precedes_parallel_tests_with_original_selection(self) -> None:
        commands = TEST_SHARDS.commands(self.plan, "misc", self.targets)
        self.assertEqual(commands[:len(self.NAMES)], [TEST_SHARDS.SELECTION + [
            "--lib", "--", "--test-threads=1", "--nocapture", "--exact", name,
        ] for name in self.NAMES])
        ordinary = commands[len(self.NAMES)]
        self.assertIn("--test-threads=4", ordinary)
        self.assertIn("--exact", ordinary)
        for serial in self.NAMES:
            self.assertEqual(ordinary.count(serial), 1)
            self.assertEqual(ordinary[ordinary.index(serial) - 1], "--skip")
            for name in (serial, serial + "_future"):
                selected = [
                    shard for shard in TEST_SHARDS.shard_ids(self.plan)
                    for command in TEST_SHARDS.commands(self.plan, shard, self.targets)
                    if "--lib" in command and LibraryGroupPlanTests.selected(command, name)
                ]
                self.assertEqual(selected, ["misc"])

    def test_missing_ignored_or_duplicate_live_test_fails(self) -> None:
        for broken in self.NAMES:
            for names, ignored in (([], []), ([broken] * 2, []), ([broken], [broken])):
                outputs = [subprocess.CompletedProcess(
                    [], 0, stdout="\n".join(f"{name}: test" for name in selected)
                ) for name in self.NAMES
                    for selected in ((names, ignored) if name == broken else ([name], []))]
                with self.subTest(test=broken, names=names, ignored=ignored), \
                        patch.object(TEST_SHARDS.subprocess, "run", side_effect=outputs), \
                        self.assertRaisesRegex(SystemExit, "serial.*exactly once|serial.*ignored"):
                    TEST_SHARDS.verify_serial_lib_tests()

    def test_enabled_live_test_is_checked_with_full_selection_and_ignored_inventory(self) -> None:
        outputs = [subprocess.CompletedProcess([], 0, stdout=text) for text in (
            value for name in self.NAMES
            for value in (name + ": test\n", "0 tests, 0 benchmarks\n")
        )]
        with patch.object(TEST_SHARDS.subprocess, "run", side_effect=outputs) as run:
            TEST_SHARDS.verify_serial_lib_tests()
        self.assertEqual(run.call_count, 2 * len(self.NAMES))
        for index, call in enumerate(run.call_args_list):
            argv = call.args[0]
            self.assertEqual(argv[:len(TEST_SHARDS.SELECTION)], TEST_SHARDS.SELECTION)
            self.assertIn("--list", argv)
            self.assertIn("--exact", argv)
            self.assertIn(self.NAMES[index // 2], argv)
            self.assertEqual("--ignored" in argv, bool(index % 2))

    def test_misc_precheck_requires_the_live_serial_inventory(self) -> None:
        with patch.object(TEST_SHARDS, "integration_targets", return_value=self.targets), \
                patch.object(TEST_SHARDS, "verify"), \
                patch.object(TEST_SHARDS, "verify_heavy"), \
                patch.object(TEST_SHARDS, "verify_serial_lib_tests", side_effect=SystemExit("serial inventory")) as audit, \
                self.assertRaisesRegex(SystemExit, "serial inventory"):
            TEST_SHARDS.precheck(self.plan, "misc")
        audit.assert_called_once_with()

    def test_missing_duplicate_late_or_overlapping_serial_commands_fail(self) -> None:
        original = TEST_SHARDS.commands
        for serial_index, name in enumerate(self.NAMES):
            for mutation in ("missing", "duplicate", "late", "overlap", "threads", "profile"):
                def changed(plan, shard, targets):
                    commands = copy.deepcopy(original(plan, shard, targets))
                    if shard == "misc":
                        ordinary_index = len(self.NAMES)
                        if mutation == "missing":
                            commands.pop(serial_index)
                        elif mutation == "duplicate":
                            commands.insert(serial_index, commands[serial_index].copy())
                        elif mutation == "late":
                            commands[serial_index], commands[ordinary_index] = commands[ordinary_index], commands[serial_index]
                        elif mutation == "overlap":
                            index = commands[ordinary_index].index(name)
                            del commands[ordinary_index][index - 1:index + 1]
                        elif mutation == "threads":
                            index = commands[serial_index].index("--test-threads=1")
                            commands[serial_index][index] = "--test-threads=4"
                        else:
                            commands[serial_index] = ["env", "CARGO_PROFILE_TEST_OPT_LEVEL=1", *commands[serial_index]]
                    return commands

                with self.subTest(test=name, mutation=mutation), \
                        patch.object(TEST_SHARDS, "commands", side_effect=changed), \
                        self.assertRaises(SystemExit):
                    TEST_SHARDS.verify_commands(self.plan, self.targets)

    def test_equivalent_cargo_selectors_cannot_duplicate_a_serial_test(self) -> None:
        targets = TEST_SHARDS.integration_targets()
        original = TEST_SHARDS.commands
        for name in self.NAMES:
            for selector in ([], ["--lib"], ["--tests"], ["--all-targets"]):
                extra = TEST_SHARDS.SELECTION + selector + [
                    "--", "--test-threads=4", "--exact", name,
                ]

                def changed(plan, shard, targets):
                    commands = copy.deepcopy(original(plan, shard, targets))
                    if shard == "misc":
                        commands.insert(-1, extra)
                    return commands

                with self.subTest(test=name, selector=selector), \
                        patch.object(TEST_SHARDS, "commands", side_effect=changed), \
                        self.assertRaises(SystemExit):
                    TEST_SHARDS.verify(self.plan, targets)

    def test_repeated_ordinary_library_command_is_not_exempt_from_overlap_checks(self) -> None:
        original = TEST_SHARDS.commands
        ordinary = original(self.plan, "misc", self.targets)[len(self.NAMES)]

        def changed(plan, shard, targets):
            commands = copy.deepcopy(original(plan, shard, targets))
            if shard == "it-2":
                commands.append(ordinary.copy())
            return commands

        with patch.object(TEST_SHARDS, "commands", side_effect=changed), self.assertRaises(SystemExit):
            TEST_SHARDS.verify_commands(self.plan, self.targets)

    def test_unmodeled_target_selector_cannot_hide_a_library_command(self) -> None:
        original = TEST_SHARDS.commands

        def changed(plan, shard, targets):
            commands = copy.deepcopy(original(plan, shard, targets))
            if shard == "it-1":
                commands.append(TEST_SHARDS.SELECTION + ["--future-selector"])
            return commands

        with patch.object(TEST_SHARDS, "commands", side_effect=changed), \
                self.assertRaisesRegex(SystemExit, "unsupported.*selection"):
            TEST_SHARDS.verify_commands(self.plan, self.targets)


class QuiescentShardPlanTests(unittest.TestCase):
    """The protected private-lib contracts must remain total and disjoint."""

    def test_plan_stdout_contains_only_executable_commands(self) -> None:
        for shard in TEST_SHARDS.shard_ids(TEST_SHARDS.load_plan()):
            with self.subTest(shard=shard):
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), "plan", "--shard", shard],
                    cwd=SCRIPT.parent.parent,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                commands = result.stdout.splitlines()
                self.assertTrue(commands, "CI must receive a nonempty plan")
                for command in commands:
                    self.assertIn(shlex.split(command)[0], {"cargo", "env"})
                self.assertIn("manifest test-source audit ok:", result.stderr)

    def test_selector_contract_keeps_one_exact_ordinary_profile_run(self) -> None:
        name = (
            "ebpf::tests::remote_selector_regression::"
            "singleton_public_protected_flow_preserves_durable_state"
        )
        commands = TEST_SHARDS.commands(
            {"heavy": {"target": "fixture", "shards": []}}, "misc", []
        )
        mentions = [command for command in commands if name in command]

        # The broad process excludes exactly this test; the following command
        # executes it once, with the same packages, features and test profile.
        self.assertEqual(len(mentions), 2)
        self.assertEqual(mentions[0], commands[len(TEST_SHARDS.SERIAL_LIB_TESTS)])
        self.assertEqual(mentions[0].count(name), 1)
        self.assertEqual(mentions[0][mentions[0].index(name) - 1], "--skip")
        self.assertIn("--exact", mentions[0])
        self.assertEqual(
            mentions[1],
            [
                "cargo", "test", "--locked", "--workspace", "--exclude",
                "opc-persist", "--all-features", "--quiet", "--lib", "--",
                "--test-threads=1", "--exact", name,
            ],
        )

    def test_void_call_lifetime_contracts_keep_exact_isolated_runs(self) -> None:
        module = "authenticated_consumer_fixture::v2_facade_tests::void_tests"
        names = (
            "consumer_void_lost_before_bind_drains_the_row_and_resolves_the_live_handle",
            "consumer_void_keeps_a_waiting_call_then_drains_after_cancellation",
            "consumer_void_drains_after_the_leader_loses_authority_during_the_original_call",
            "consumer_void_unknown_response_retains_until_exact_status_confirms_it",
            "consumer_void_unavailable_row_advances_past_status_resolvable_rows_and_wraps",
            "consumer_void_available_rows_drain_in_one_sweep_after_cursor_wrap",
        )
        plan = TEST_SHARDS.load_plan()
        ordinary = TEST_SHARDS.commands(plan, "misc", [])
        isolated = TEST_SHARDS.commands(plan, "heavy-1", [])
        commands = ordinary + isolated
        for suffix in names:
            with self.subTest(test=suffix):
                name = f"{module}::{suffix}"
                mentions = [command for command in commands if name in command]
                self.assertEqual(len(mentions), 2)
                self.assertEqual(mentions[0], commands[len(TEST_SHARDS.SERIAL_LIB_TESTS)])
                self.assertEqual(mentions[0].count(name), 1)
                self.assertEqual(mentions[0][mentions[0].index(name) - 1], "--skip")
                self.assertIn("--exact", mentions[0])
                self.assertIn(mentions[1], isolated)
                self.assertEqual(
                    mentions[1],
                    [
                        "cargo", "test", "--locked", "--workspace", "--exclude",
                        "opc-persist", "--all-features", "--quiet", "--lib", "--",
                        "--test-threads=1", "--exact", name,
                    ],
                )

    def test_optimized_contracts_have_a_dedicated_shard(self) -> None:
        plan = TEST_SHARDS.load_plan()
        assignments = [
            name
            for shard in TEST_SHARDS.shard_ids(plan)
            for name in TEST_SHARDS.quiescent_lib_tests_for_shard(shard, plan)
        ]
        optimized = TEST_SHARDS.quiescent_lib_tests_for_shard(
            TEST_SHARDS.OPTIMIZED_QUIESCENT_SHARD, plan
        )

        self.assertCountEqual(assignments, TEST_SHARDS.QUIESCENT_LIB_TESTS)
        self.assertEqual(
            set(optimized), TEST_SHARDS.OPTIMIZED_QUIESCENT_LIB_TESTS
        )

    def test_rebalanced_ordinary_contracts_remain_serial_on_it_0(self) -> None:
        plan = TEST_SHARDS.load_plan()
        names = [
            name for name in TEST_SHARDS.QUIESCENT_LIB_TESTS
            if name not in TEST_SHARDS.OPTIMIZED_QUIESCENT_LIB_TESTS
            and name not in TEST_SHARDS.QUIESCENT_VOID_LIB_TESTS
        ]
        targets = [plan["heavy"]["target"], *(f"fixture_{i}" for i in range(9))]
        for name in names:
            command = TEST_SHARDS.quiescent_lib_command(name)
            with self.subTest(name=name):
                owners = [
                    shard for shard in TEST_SHARDS.shard_ids(plan)
                    for actual in TEST_SHARDS.commands(plan, shard, targets)
                    if actual == command
                ]
                self.assertEqual(owners, ["it-0"])
                self.assertEqual(command[0], "cargo")
                self.assertIn("--exact", command)
                self.assertIn("--test-threads=1", command)

    def test_scope_scan_tls_contracts_run_once_on_the_serial_shard(self) -> None:
        plan = TEST_SHARDS.load_plan()
        targets = [plan["heavy"]["target"], *(f"fixture_{i}" for i in range(9))]
        names = [
            "native_scope_scan_tls_keeps_one_cut_and_locally_revalidates_fresh_proofs",
            "native_scope_scan_tls_queued_open_releases_running_and_shutdown_drains",
            "native_scope_scan_tls_rejects_a_superseded_boot_on_existing_and_new_channels",
        ]
        for name in names:
            short = "scope_transport::scans::" + name
            full = "stateless_quorum_consumer::" + short
            with self.subTest(name=full):
                self.assertIn(short, TEST_SHARDS.QUIESCENT_LIB_TESTS)
                command = TEST_SHARDS.quiescent_lib_command(short)
                owners = [
                    shard for shard in TEST_SHARDS.shard_ids(plan)
                    for actual in TEST_SHARDS.commands(plan, shard, targets)
                    if actual == command
                ]
                self.assertEqual(owners, ["it-0"])
                self.assertIn("--test-threads=1", command)
                self.assertIn("--exact", command)

    def test_scope_child_read_contracts_run_once_on_the_serial_shard(self) -> None:
        plan = TEST_SHARDS.load_plan()
        targets = [plan["heavy"]["target"], *(f"fixture_{i}" for i in range(9))]
        names = {
            "child_reads": [
                "native_scope_child_read_client_keeps_one_barrier_on_fresh_and_reused_connections",
                "native_scope_child_read_builder_reuses_running_credit_and_bounds_all_exchanges",
                "native_scope_completion_provenance_rejects_forged_ports_and_early_ack",
            ],
            "child_read_guards": [
                "native_scope_quorum_revision_signals_distinguish_alerts_from_authenticated_frames",
                "native_scope_child_read_peer_close_releases_cut_and_proof_while_admission_is_held",
                "native_scope_child_read_ten_second_cut_bound_returns_retry_and_releases_ownership",
                "native_scope_child_read_promotes_only_after_current_cut_and_clears_stale_hint",
            ],
            "child_read_revocation": [
                "native_scope_child_read_held_policy_revocation_returns_unauthorized_without_observation",
            ],
        }
        for module, tests in names.items():
            for name in tests:
                short = f"scope_transport::{module}::{name}"
                with self.subTest(name=short):
                    self.assertIn(short, TEST_SHARDS.QUIESCENT_LIB_TESTS)
                    command = TEST_SHARDS.quiescent_lib_command(short)
                    owners = [
                        shard for shard in TEST_SHARDS.shard_ids(plan)
                        for actual in TEST_SHARDS.commands(plan, shard, targets)
                        if actual == command
                    ]
                    self.assertEqual(owners, ["it-0"])
                    self.assertIn("--test-threads=1", command)
                    self.assertIn("--exact", command)

    def test_protected_transition_runs_once_in_the_optimized_shard(self) -> None:
        name = (
            "stateless_quorum_consumer::"
            "protected_consumer_chain_after_activation_elides_outer_capability_wire_calls"
        )
        plan = {"heavy": {"target": "fixture", "shards": []}}
        ordinary = TEST_SHARDS.commands(plan, "misc", [])
        optimized = TEST_SHARDS.commands(
            plan, TEST_SHARDS.OPTIMIZED_QUIESCENT_SHARD, []
        )
        mentions = [command for command in ordinary + optimized if name in command]

        self.assertEqual(len(mentions), 2)
        self.assertEqual(mentions[0], ordinary[len(TEST_SHARDS.SERIAL_LIB_TESTS)])
        self.assertEqual(mentions[0].count(name), 1)
        self.assertEqual(mentions[0][mentions[0].index(name) - 1], "--skip")
        self.assertEqual(
            mentions[1],
            [
                "env", "CARGO_PROFILE_TEST_OPT_LEVEL=1", "cargo", "test",
                "--locked", "--workspace", "--exclude", "opc-persist",
                "--all-features", "--quiet", "--lib", "--",
                "--test-threads=1", "--exact", name,
            ],
        )

    def test_full_journal_opt_in_proof_is_not_scheduled_in_hosted_shards(self) -> None:
        name = "consumer_full_journal_void_reclaims_all_inherited_unbound_rows"
        plan = TEST_SHARDS.load_plan()
        targets = [plan["heavy"]["target"], *(f"fixture_{i}" for i in range(9))]
        for shard in TEST_SHARDS.shard_ids(plan):
            for command in TEST_SHARDS.commands(plan, shard, targets):
                self.assertFalse(any(name in argument for argument in command))

    def test_optimized_shard_preserves_exact_o1_commands(self) -> None:
        plan = {"heavy": {"shards": []}}
        optimized = TEST_SHARDS.quiescent_lib_tests_for_shard(
            TEST_SHARDS.OPTIMIZED_QUIESCENT_SHARD, plan
        )

        commands = TEST_SHARDS.commands(
            plan, TEST_SHARDS.OPTIMIZED_QUIESCENT_SHARD, []
        )

        self.assertEqual(
            commands,
            [
                TEST_SHARDS.quiescent_lib_command(name)
                for name in optimized
            ],
        )
        self.assertTrue(
            all(
                command[:2] == ["env", "CARGO_PROFILE_TEST_OPT_LEVEL=1"]
                for command in commands
            )
        )
        self.assertTrue(
            all(
                "--test-threads=1" in command and "--exact" in command
                for command in commands
            )
        )
        listed = TEST_SHARDS.quiescent_lib_list_command(optimized[0])
        self.assertEqual(
            listed,
            [*commands[0][:-2], "--list", *commands[0][-2:]],
        )


class LibraryGroupPlanTests(unittest.TestCase):
    NATIVE_FULL_BOUND = (
        "consensus::store::sequential_wal_sdk_tests::native_log_bound::"
        "native_leader_full_bound_reproposes_one_idempotent_request_and_reopens",
        "consensus::storage::tests::native_log_retained_bound::"
        "native_log_retained_bound_survives_snapshot_purge_and_restart",
        "consensus::storage::tests::native_log_retained_bound::"
        "native_log_retained_bound_survives_snapshot_purge_and_restart_async",
        "consensus::native::lease_deferral_tests::"
        "native_lease_deferral_lost_journal_cannot_pin_the_full_retained_window",
        "sqlite::consensus::tests::lease_deferral::"
        "sqlite_lease_deferral_lost_journal_cannot_pin_the_full_retained_window",
        "consensus::native::lease_deferral_tests::"
        "native_lease_deferral_grouped_retirement_validates_a_surviving_resolution",
        "consensus::native::lease_deferral_tests::"
        "native_lease_deferral_retirement_rejects_unexpired_removed_and_surviving_receipts",
        "consensus::native::lease_deferral_tests::"
        "native_lease_deferral_full_closed_epoch_retires_after_completion_or_abandonment",
        "consensus::native::lease_deferral_tests::"
        "review_cohort_native_resolution_retirement_grouped",
        "consensus::native::lease_deferral_tests::"
        "review_cohort_native_resolution_retirement_separate",
        "consensus::native::generation::catalog::tests::lease_deferral_tests::"
        "native_catalog_lease_deferral_retirement_grouped_apply_and_checkpoint",
        "consensus::native::generation::catalog::tests::lease_deferral_tests::"
        "native_catalog_lease_deferral_retirement_separate_apply_one_checkpoint",
        "consensus::native::generation::catalog::tests::lease_deferral_tests::"
        "native_catalog_lease_deferral_retirement_separate_checkpoints",
        "consensus::native::generation::catalog::tests::lease_deferral_tests::"
        "native_catalog_lease_deferral_retirement_rejects_false_deletion_witnesses",
    )

    def setUp(self) -> None:
        self.plan = TEST_SHARDS.load_plan()
        self.targets = [
            self.plan["heavy"]["target"], *(f"fixture_{i}" for i in range(9))
        ]

    @staticmethod
    def selected(command: list[str], name: str) -> bool:
        """Model libtest exact positive/skip filters, independently of the planner."""
        args = command[command.index("--") + 1 :]
        skips = [args[i + 1] for i, arg in enumerate(args[:-1]) if arg == "--skip"]
        positive = [
            arg for i, arg in enumerate(args)
            if not arg.startswith("--") and (i == 0 or args[i - 1] != "--skip")
        ]
        return (not positive or name in positive) and name not in skips

    def test_every_moved_test_and_future_sibling_runs_once(self) -> None:
        commands = {
            shard: [
                command for command in TEST_SHARDS.commands(self.plan, shard, self.targets)
                if "--lib" in command
            ]
            for shard in TEST_SHARDS.shard_ids(self.plan)
        }
        for group in self.plan["lib_groups"]:
            for name in TEST_SHARDS.lib_group_names(group):
                for candidate, owner in [(name, group["shard"]), (name + "_future", "misc")]:
                    with self.subTest(name=candidate):
                        selected = [
                            shard for shard, invocations in commands.items()
                            for command in invocations if self.selected(command, candidate)
                        ]
                        self.assertEqual(selected, [owner])
                        self.assertTrue(all("--exact" in c for cs in commands.values() for c in cs))

    def test_binary_tests_are_not_filtered_by_library_names(self) -> None:
        commands = TEST_SHARDS.commands(self.plan, "misc", self.targets)
        binary = [command for command in commands if "--bins" in command]
        self.assertEqual(binary, [TEST_SHARDS.SELECTION + ["--bins", "--", *TEST_SHARDS.HARNESS]])

    def test_full_native_bounds_have_dedicated_owners_and_optimized_serial_execution(self) -> None:
        invocations = [(shard, command)
                       for shard in TEST_SHARDS.shard_ids(self.plan)
                       for command in TEST_SHARDS.commands(self.plan, shard, self.targets)
                       if "--lib" in command]
        for name in self.NATIVE_FULL_BOUND:
            selected = [(shard, command) for shard, command in invocations
                        if self.selected(command, name)]
            with self.subTest(name=name):
                self.assertEqual(len(selected), 1)
                shard, command = selected[0]
                self.assertEqual(shard, f"native-log-{self.NATIVE_FULL_BOUND.index(name)}")
                self.assertEqual(command[:2], ["env", "CARGO_PROFILE_TEST_OPT_LEVEL=1"])
                self.assertEqual(command[2:2 + len(TEST_SHARDS.SELECTION)], TEST_SHARDS.SELECTION)
                self.assertIn("--test-threads=1", command)
                self.assertIn("--nocapture", command)
                self.assertNotIn("--ignored", command)
                siblings = [(owner, invocation) for owner, invocation in invocations
                            if self.selected(invocation, name + "_future")]
                self.assertEqual([owner for owner, _ in siblings], ["misc"])
                self.assertNotIn("CARGO_PROFILE_TEST_OPT_LEVEL=1", siblings[0][1])

    def test_full_native_bounds_cannot_disappear_move_or_change_an_ordinary_group_profile(self) -> None:
        for mutation in ("missing", "owner", "mixed"):
            plan = copy.deepcopy(self.plan)
            group = next(group for group in plan["lib_groups"]
                         if self.NATIVE_FULL_BOUND[0] in TEST_SHARDS.lib_group_names(group))
            if mutation == "missing":
                plan["lib_groups"].remove(group)
            elif mutation == "owner":
                group["shard"] = "it-1"
            else:
                group["tests"].append("an_ordinary_future_sibling")
            with self.subTest(mutation=mutation), self.assertRaises(SystemExit):
                TEST_SHARDS.verify_lib_plan(plan)

    def test_full_native_precheck_resolves_the_enabled_names_in_the_execution_profile(self) -> None:
        calls = []

        def listed(command, **kwargs):
            calls.append(command)
            names = command[command.index("--exact") + 1:]
            if "--ignored" in command:
                names = []
            return subprocess.CompletedProcess(command, 0,
                stdout="\n".join(f"{name}: test" for name in names))

        with (
            patch.object(TEST_SHARDS, "integration_targets", return_value=self.targets),
            patch.object(TEST_SHARDS, "verify"),
            patch.object(TEST_SHARDS, "quiescent_lib_tests_for_shard", return_value=()),
            patch.object(TEST_SHARDS, "list_heavy_tests", return_value=self.plan["heavy"]["shards"][1]),
            patch.object(TEST_SHARDS.subprocess, "run", side_effect=listed),
        ):
            TEST_SHARDS.precheck(self.plan, "heavy-1")
            for shard in TEST_SHARDS.native_log_bound.CORE_SHARDS:
                TEST_SHARDS.precheck(self.plan, shard)
        for name in self.NATIVE_FULL_BOUND:
            selected = [command for command in calls if name in command]
            with self.subTest(name=name):
                self.assertEqual(len(selected), 2)
                self.assertTrue(all(command[:2] == ["env", "CARGO_PROFILE_TEST_OPT_LEVEL=1"]
                                    for command in selected))
                self.assertEqual(sum("--ignored" in command for command in selected), 1)
        ordinary = [command for command in calls
                    if not any(name in command for name in self.NATIVE_FULL_BOUND)]
        self.assertTrue(ordinary)
        self.assertTrue(all(command[:len(TEST_SHARDS.SELECTION)] == TEST_SHARDS.SELECTION
                            for command in ordinary))

    def test_empty_duplicate_unknown_and_optimized_groups_are_rejected(self) -> None:
        invalid = []
        empty = copy.deepcopy(self.plan)
        empty["lib_groups"][0]["tests"] = []
        invalid.append(empty)
        duplicate = copy.deepcopy(self.plan)
        duplicate["lib_groups"].append(copy.deepcopy(duplicate["lib_groups"][0]))
        invalid.append(duplicate)
        for owner in ("missing", "misc", "quiescent-o1"):
            plan = copy.deepcopy(self.plan)
            plan["lib_groups"][0]["shard"] = owner
            invalid.append(plan)
        for plan in invalid:
            with self.subTest(plan=plan["lib_groups"][0]):
                with self.assertRaises(SystemExit):
                    TEST_SHARDS.verify_lib_plan(plan)

    def test_child_parent_declarations_must_name_distinct_members_of_one_group(self) -> None:
        for mutation in ("unknown-child", "unknown-parent", "self-parent", "child-parent-chain", "not-a-map"):
            plan = copy.deepcopy(self.plan)
            group = plan["lib_groups"][0]
            child, parent = group["tests"][:2]
            group["child_parents"] = {
                "unknown-child": {"missing": parent},
                "unknown-parent": {child: "missing"},
                "self-parent": {child: child},
                "child-parent-chain": {child: parent, parent: child},
                "not-a-map": [child],
            }[mutation]
            with self.subTest(mutation=mutation), self.assertRaises(SystemExit):
                TEST_SHARDS.verify_lib_plan(plan)

    def test_timing_contract_cannot_join_an_ordinary_group(self) -> None:
        self.plan["lib_groups"].append({
            "module": TEST_SHARDS.QUIESCENT_VOID_LIB_MODULE,
            "tests": [TEST_SHARDS.QUIESCENT_VOID_LIB_TESTS[0]],
            "shard": "it-1",
        })
        with self.assertRaisesRegex(SystemExit, "claimed more than once"):
            TEST_SHARDS.verify_lib_plan(self.plan)

    def test_precheck_rejects_missing_or_ambiguous_library_names(self) -> None:
        names = [
            name for group in self.plan["lib_groups"] if group["shard"] == "it-1"
            for name in TEST_SHARDS.lib_group_names(group)
        ]
        for selected in (names[1:], names + [names[0]]):
            with self.subTest(count=len(selected)):
                output = subprocess.CompletedProcess(
                    [], 0, stdout="\n".join(f"{name}: test" for name in selected)
                )
                with (
                    patch.object(TEST_SHARDS, "integration_targets", return_value=self.targets),
                    patch.object(TEST_SHARDS, "verify"),
                    patch.object(TEST_SHARDS.subprocess, "run", return_value=output),
                    self.assertRaisesRegex(SystemExit, "do not resolve exactly once"),
                ):
                    TEST_SHARDS.precheck(self.plan, "it-1")

    def test_optimized_profile_and_unknown_timing_overrides_are_rejected(self) -> None:
        for name in ("missing", next(iter(TEST_SHARDS.OPTIMIZED_QUIESCENT_LIB_TESTS))):
            with self.subTest(name=name):
                plan = copy.deepcopy(self.plan)
                plan["quiescent_lib_shards"][name] = "it-1"
                with self.assertRaises(SystemExit):
                    TEST_SHARDS.verify_lib_plan(plan)


class RealtimeQualificationPartitionTests(unittest.TestCase):
    NAME = (
        "isolated_scale::original::"
        "original_encrypted_durable_batches_preserve_receipts_and_scope"
    )

    def setUp(self) -> None:
        self.plan = TEST_SHARDS.load_plan()
        self.plan["qualification"] = [{"name": self.NAME}]
        self.targets = [
            self.plan["heavy"]["target"], *(f"fixture_{i}" for i in range(9))
        ]

    def test_only_the_listed_full_name_leaves_required_shards(self) -> None:
        invocations = {
            shard: [
                command
                for command in TEST_SHARDS.commands(self.plan, shard, self.targets)
                if self.plan["heavy"]["target"] in command
            ]
            for shard in TEST_SHARDS.shard_ids(self.plan)
        }
        for name, expected in (
            (self.NAME, []),
            (self.NAME + "_future", ["misc"]),
            ("isolated_scale::unlisted_future_test", ["misc"]),
        ):
            with self.subTest(name=name):
                owners = [
                    shard for shard, commands in invocations.items()
                    for command in commands
                    if LibraryGroupPlanTests.selected(command, name)
                ]
                self.assertEqual(owners, expected)

    def test_removed_qualification_name_fails_the_live_partition_check(self) -> None:
        named = [name for group in self.plan["heavy"]["shards"] for name in group]
        inventory = [*named, "an_unlisted_required_test"]

        def listed(_plan, arguments):
            command = ["--", *arguments]
            return {
                name for name in inventory
                if LibraryGroupPlanTests.selected(command, name)
            }

        with (
            patch.object(TEST_SHARDS, "list_heavy_tests", side_effect=listed),
            self.assertRaisesRegex(SystemExit, "qualification"),
        ):
            TEST_SHARDS.verify_heavy(self.plan)

    def test_live_partition_keeps_unlisted_and_prefix_tests_required(self) -> None:
        named = [name for group in self.plan["heavy"]["shards"] for name in group]
        inventory = [*named, self.NAME, self.NAME + "_future", "isolated_scale::future"]

        def listed(_plan, arguments):
            if "--ignored" in arguments:
                return []
            return [name for name in inventory
                    if LibraryGroupPlanTests.selected(["--", *arguments], name)]

        with patch.object(TEST_SHARDS, "list_heavy_tests", side_effect=listed), \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            TEST_SHARDS.verify_heavy(self.plan)
        self.assertIn("2 on 'misc'", output.getvalue())
        self.assertIn("1 real-time qualification tests", output.getvalue())

    def test_live_partition_rejects_duplicate_or_ignored_names(self) -> None:
        named = [name for group in self.plan["heavy"]["shards"] for name in group]
        inventory = [*named, self.NAME]
        for duplicate, ignored in ((True, False), (False, True)):
            def listed(_plan, arguments):
                if not arguments and duplicate:
                    return [*inventory, self.NAME]
                if "--ignored" in arguments:
                    return [self.NAME] if ignored else []
                return [name for name in inventory
                        if LibraryGroupPlanTests.selected(["--", *arguments], name)]

            with self.subTest(duplicate=duplicate, ignored=ignored), \
                    patch.object(TEST_SHARDS, "list_heavy_tests", side_effect=listed), \
                    self.assertRaisesRegex(SystemExit, "ambiguous|ignored"):
                TEST_SHARDS.verify_heavy(self.plan)

    def test_misc_precheck_audits_live_qualification_before_suite_execution(self) -> None:
        with patch.object(TEST_SHARDS, "integration_targets", return_value=self.targets), \
                patch.object(TEST_SHARDS, "verify"), \
                patch.object(TEST_SHARDS, "verify_heavy", side_effect=SystemExit("stale qualification")) as audit, \
                self.assertRaisesRegex(SystemExit, "stale qualification"):
            TEST_SHARDS.precheck(self.plan, "misc")
        audit.assert_called_once_with(self.plan)

    def test_manifest_cannot_overlap_required_heavy_groups(self) -> None:
        self.plan["qualification"] = [{"name": self.plan["heavy"]["shards"][0][0]}]
        with self.assertRaisesRegex(SystemExit, "required shard"):
            TEST_SHARDS.verify_commands(self.plan, self.targets)



class HostedLibraryTransferTests(unittest.TestCase):
    def setUp(self):
        self.plan = TEST_SHARDS.load_plan()
        self.targets = [self.plan["heavy"]["target"], *(f"fixture_{i}" for i in range(9))]

    def test_hosted_misc_preserves_every_non_library_command_and_transfers_the_complete_library_phase(self):
        logical = TEST_SHARDS.commands(self.plan, "misc", self.targets)
        support = TEST_SHARDS.hosted_commands(self.plan, "misc", self.targets)
        self.assertEqual(support, logical[len(TEST_SHARDS.SERIAL_LIB_TESTS) + 1:])
        self.assertEqual(len(support), 4)
        self.assertFalse(any("--lib" in command for command in support))
        for shard in TEST_SHARDS.shard_ids(self.plan):
            if shard != "misc":
                self.assertEqual(TEST_SHARDS.hosted_commands(self.plan, shard, self.targets),
                                 TEST_SHARDS.commands(self.plan, shard, self.targets))

    def test_hosted_misc_precheck_leaves_serial_resolution_to_library_inventory(self):
        with (
            patch.object(TEST_SHARDS, "integration_targets", return_value=self.targets),
            patch.object(TEST_SHARDS, "verify"),
            patch.object(TEST_SHARDS, "verify_heavy") as heavy,
            patch.object(TEST_SHARDS, "verify_serial_lib_tests") as serial,
            patch.object(TEST_SHARDS, "list_quiescent_lib_test") as isolated,
        ):
            TEST_SHARDS.precheck(self.plan, "misc", split_libraries=True)
        heavy.assert_called_once_with(self.plan)
        serial.assert_not_called()
        isolated.assert_not_called()

    def test_missing_matrix_execution_or_required_dependency_cannot_strand_the_transfer(self):
        text = TEST_SHARDS.WORKFLOW.read_text()
        native_shards = TEST_SHARDS.native_log_bound.CORE_SHARDS
        native_matrix = "shard: [" + ", ".join(native_shards) + "]"
        replacements = (
            ("shard: [0, 1]", "shard: [0]"),
            *((native_matrix, "shard: [" + ", ".join(
                shard for shard in native_shards if shard != missing
            ) + "]") for missing in native_shards),
            ("      - rust-libraries\n", ""),
            ("      - rust-native-log-proofs\n", ""),
            ("test-shards.py run-libraries --shard", "test-shards.py verify --shard"),
            ("precheck --shard '${{ matrix.shard }}' --split-libraries", "precheck --shard '${{ matrix.shard }}'"),
            ("plan --shard '${{ matrix.shard }}' --split-libraries", "plan --shard '${{ matrix.shard }}'"),
        )
        for old, new in replacements:
            self.assertIn(old, text)
            with self.subTest(mutation=old), tempfile.TemporaryDirectory() as directory:
                workflow = Path(directory) / "ci.yml"
                workflow.write_text(text.replace(old, new))
                with patch.object(TEST_SHARDS, "WORKFLOW", workflow), self.assertRaises(SystemExit):
                    TEST_SHARDS.verify_workflow(self.plan)

    def test_dedicated_proof_cannot_inherit_an_ordinary_timing_contract(self):
        plan = copy.deepcopy(self.plan)
        name = next(iter(plan["quiescent_lib_shards"]))
        plan["quiescent_lib_shards"][name] = "native-log-0"
        with self.assertRaises(SystemExit):
            TEST_SHARDS.verify_lib_plan(plan)

    def test_library_entrypoint_executes_the_verified_serial_and_ordinary_commands(self):
        metadata = TEST_SHARDS.cargo_test_selection.workspace_metadata(TEST_SHARDS.ROOT)
        module = "fenced_transition_journal::recovery::void_ownership_tests"
        children = {
            f"{module}::owned_journal_creation_child": f"{module}::owned_journal_creation_is_crash_atomic",
            f"{module}::owned_journal_process_child": f"{module}::owned_journal_void_excludes_another_process_and_recovers_after_crash",
        }
        names = [*TEST_SHARDS.moved_lib_names(self.plan), *(f"new_module::future_{i}" for i in range(120))]
        rows = [{"package": "opc-session-store", "target": "opc_session_store", "kind": ["lib"],
                 "name": name, "ignored": name in children} for name in names]
        for shard in TEST_SHARDS.library_partition.SHARDS:
            with self.subTest(shard=shard), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "mapping.json"
                with (
                    patch.object(TEST_SHARDS, "integration_targets", return_value=self.targets),
                    patch.object(TEST_SHARDS, "verify"),
                    patch.object(TEST_SHARDS.library_partition, "inventory", return_value=(rows, metadata)),
                    patch.object(TEST_SHARDS.subprocess, "check_output", return_value="f" * 40),
                    patch.object(TEST_SHARDS.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as execute,
                ):
                    TEST_SHARDS.run_libraries(self.plan, shard, output)
                import json
                report = json.loads(output.read_text())
                self.assertEqual(report["child_parents"], children)
                self.assertTrue(all(report["named_test_owners"][child] == "it-1" for child in children))
                self.assertEqual([call.args[0] for call in execute.call_args_list], report["plans"][str(shard)])
                self.assertEqual(execute.call_count, 3 if shard == 0 else 1)
                if shard == 0:
                    self.assertEqual(report["plans"]["0"][:2],
                                     [TEST_SHARDS.serial_lib_command(name) for name in TEST_SHARDS.SERIAL_LIB_TESTS])


if __name__ == "__main__":
    unittest.main()
