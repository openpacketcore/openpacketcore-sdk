#!/usr/bin/env python3
"""Regression coverage for the test-shard manifest/source audit."""

from __future__ import annotations

import copy
import importlib.util
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
        self.assertEqual(mentions[0], commands[0])
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
                self.assertEqual(mentions[0], commands[0])
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
        self.assertEqual(mentions[0], ordinary[0])
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


if __name__ == "__main__":
    unittest.main()
