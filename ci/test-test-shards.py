#!/usr/bin/env python3
"""Regression coverage for the test-shard manifest/source audit."""

from __future__ import annotations

import importlib.util
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


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
            "singleton_public_protected_flow_keeps_original_request_deadline"
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

    def test_optimized_contracts_have_a_dedicated_shard(self) -> None:
        ordinary = TEST_SHARDS.quiescent_lib_tests_for_shard("misc")
        optimized = TEST_SHARDS.quiescent_lib_tests_for_shard(
            TEST_SHARDS.OPTIMIZED_QUIESCENT_SHARD
        )

        self.assertEqual((*ordinary, *optimized), TEST_SHARDS.QUIESCENT_LIB_TESTS)
        self.assertEqual(set(ordinary) & set(optimized), set())
        self.assertEqual(
            set(optimized), TEST_SHARDS.OPTIMIZED_QUIESCENT_LIB_TESTS
        )

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

    def test_optimized_shard_preserves_exact_o1_commands(self) -> None:
        plan = {"heavy": {"shards": []}}
        optimized = TEST_SHARDS.quiescent_lib_tests_for_shard(
            TEST_SHARDS.OPTIMIZED_QUIESCENT_SHARD
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


if __name__ == "__main__":
    unittest.main()
