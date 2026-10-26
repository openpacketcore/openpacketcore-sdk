#!/usr/bin/env python3
"""Exercise the workflow's real i686 selectors with future Cargo targets."""

from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/ci.yml"
SLICES = ("ordinary", "ordinary-authority", "ordinary-integration", "contracts")
SELECTION = ["cargo", "test", "--locked", "-p", "opc-session-net", "--all-features",
             "--target", "i686-unknown-linux-gnu", "--quiet"]
ORDINARY_CONTRACTS = (
    "persistent_three_voter_consumer_write_does_not_spend_budget_on_a_read_quorum",
    "persistent_three_voter_first_transition_has_one_leader_activation_proof",
)
OPTIMIZED_CONTRACTS = (
    "protected_consumer_chain_after_activation_elides_outer_capability_wire_calls",
    "persistent_three_voter_fenced_status_converges_after_response_loss_and_compaction",
    "persistent_three_voter_protected_roster_creates_absent_record_then_established_terminal",
    "persistent_three_voter_protected_roster_aborted_exact_bytes_survive_snapshot_and_full_restart",
    "persistent_three_voter_protected_roster_commits_maximum_plan_and_result_then_established_terminal",
    "persistent_three_voter_protected_roster_survives_real_os_process_loss",
    "persistent_three_voter_snapshot_maintenance_with_concurrent_read_barriers_keeps_engines_running",
    "persistent_three_voter_protected_roster_exact_bytes_survive_snapshot_and_full_restart",
)
CONTRACTS = tuple("stateless_quorum_consumer::" + name
                  for name in ORDINARY_CONTRACTS + OPTIMIZED_CONTRACTS)
AUTHORITY_PREFIX = "stateless_quorum_consumer::publication_authority_failover::"
CRASH_MATRIX = "stateless_quorum_consumer::persistent_three_voter_protected_roster_durable_crash_cut_matrix"
FIXTURE_LIBRARY_NAMES = ("library_probe", *CONTRACTS, CRASH_MATRIX,
                         AUTHORITY_PREFIX + "existing_authority_probe",
                         AUTHORITY_PREFIX + "future_authority_probe",
                         CRASH_MATRIX + "_future",
                         "stateless_quorum_consumer::publication_authority_failover_future::adjacent_namespace_probe")


def workflow_commands(directory: Path, slice_name: str, *,
                      inventory: str | None = None, list_exit: int = 0) -> list[list[str]]:
    """Capture shell-expanded argv from the required workflow step."""
    matches = re.findall(
        r"^      - name: Run opc-session-net tests on i686\n"
        r"(?:(?:        (?:#[^\n]*|shell: [^\n]*)|)\n)*        run: \|\n"
        r"((?:(?:          [^\n]*|)\n)+)",
        WORKFLOW.read_text(),
        re.MULTILINE,
    )
    if len(matches) != 1:
        raise AssertionError("expected exactly one i686 session-net run step")
    script = "\n".join(line[10:] for line in matches[0].splitlines())
    capture = directory / "capture"
    capture.mkdir(exist_ok=True)
    cargo = capture / "cargo"
    cargo.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "with open(os.environ['I686_CAPTURE'], 'a') as output:\n"
        "    output.write(json.dumps(['cargo', *sys.argv[1:]]) + '\\n')\n"
        "with open(os.environ['I686_CAPTURE'] + '.profiles', 'a') as output:\n"
        "    output.write(json.dumps(os.environ.get('CARGO_PROFILE_TEST_OPT_LEVEL')) + '\\n')\n"
        "if '--list' in sys.argv:\n"
        "    print(os.environ['I686_LIBRARY_INVENTORY'])\n"
        "    raise SystemExit(int(os.environ['I686_LIST_EXIT']))\n"
    )
    cargo.chmod(0o755)
    output = directory / f"{slice_name}.jsonl"
    subprocess.run(
        ["bash", "-euc", script],
        cwd=ROOT,
        env={
            **os.environ,
            "PATH": str(capture) + os.pathsep + os.environ["PATH"],
            "I686_SLICE": slice_name,
            "I686_CAPTURE": str(output),
            "I686_LIBRARY_INVENTORY": inventory if inventory is not None else
                "\n".join(name + ": test" for name in FIXTURE_LIBRARY_NAMES),
            "I686_LIST_EXIT": str(list_exit),
        },
        check=True,
    )
    return [argv for line in output.read_text().splitlines()
            if "--list" not in (argv := json.loads(line))]


class I686TargetSelectionTests(unittest.TestCase):
    def test_wrapped_shell_keeps_the_same_cargo_selections(self) -> None:
        wrapped = WORKFLOW.read_text()
        ordinary = re.sub(r"^        shell: .*setup-fsverity-tmp\.sh.*\n", "", wrapped,
                          flags=re.MULTILINE)
        self.assertNotEqual(wrapped, ordinary, "exercise the workflow's actual wrapped shell")
        with tempfile.TemporaryDirectory(prefix="i686-wrapped-selection-") as temporary:
            root = Path(temporary)
            workflow = root / "ci.yml"
            selections = []
            for index, source in enumerate((ordinary, wrapped)):
                workflow.write_text(source)
                directory = root / str(index)
                directory.mkdir()
                with patch(__name__ + ".WORKFLOW", workflow):
                    selections.append({name: workflow_commands(directory, name)
                                       for name in SLICES})
            self.assertEqual(selections[0], selections[1])

    def test_every_slice_remains_required_with_its_own_cache_and_original_limit(self) -> None:
        source = WORKFLOW.read_text()
        job = source.split("\n  session-net-i686-tests:\n", 1)[1].split("\n  session-net-i686:\n", 1)[0]
        entries = re.findall(r"^          - slice: ([^\n]+)\n            cache_key: ([^\n]+)$", job, re.MULTILINE)
        self.assertEqual([name for name, _ in entries], list(SLICES))
        self.assertEqual(len({key for _, key in entries}), len(SLICES))
        self.assertIn("    timeout-minutes: 30\n", job)
        self.assertIn("      fail-fast: false\n", job)
        aggregate = source.split("\n  session-net-i686:\n", 1)[1].split("\n  feature-powerset:\n", 1)[0]
        self.assertIn("    if: always()\n", aggregate)
        self.assertIn("    needs: [session-net-i686-tests]\n", aggregate)
        self.assertIn("I686_TESTS_RESULT: ${{ needs.session-net-i686-tests.result }}", aggregate)

    def test_timing_contracts_keep_their_exact_profiles_and_fresh_processes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="i686-contract-selection-") as temporary:
            root = Path(temporary)
            commands = workflow_commands(root, "contracts")
            self.assertEqual(commands, [
                [*SELECTION, "--lib", "--", "--test-threads=1", "--exact", name]
                for name in CONTRACTS
            ])
            profiles = [json.loads(line) for line in
                        (root / "contracts.jsonl.profiles").read_text().splitlines()]
            self.assertEqual(profiles, [None] * len(ORDINARY_CONTRACTS)
                             + ["1"] * len(OPTIMIZED_CONTRACTS))

    def test_invalid_inventory_stops_before_running_a_library_partition(self) -> None:
        valid = "\n".join(name + ": test" for name in FIXTURE_LIBRARY_NAMES)
        invalid = {
            "empty": "",
            "duplicate": valid + "\nlibrary_probe: test",
            "malformed": valid + "\nunexpected inventory output",
            "missing_crash_matrix": valid.replace(CRASH_MATRIX + ": test\n", ""),
            "missing_authority_module": "\n".join(
                line for line in valid.splitlines() if not line.startswith(AUTHORITY_PREFIX)),
            "missing_timing_contract": valid.replace(CONTRACTS[0] + ": test\n", ""),
        }
        for slice_name in SLICES[:2]:
            for label, inventory in invalid.items():
                with self.subTest(slice=slice_name, defect=label), tempfile.TemporaryDirectory(
                        prefix="i686-invalid-inventory-") as temporary:
                    root = Path(temporary)
                    with self.assertRaises(subprocess.CalledProcessError):
                        workflow_commands(root, slice_name, inventory=inventory)
                    self.assertTrue((root / f"{slice_name}.jsonl").exists(),
                                    "the partition must resolve its Cargo inventory")
                    calls = [json.loads(line) for line in
                             (root / f"{slice_name}.jsonl").read_text().splitlines()]
                    self.assertTrue(calls)
                    self.assertTrue(all("--list" in argv for argv in calls))

    def test_failed_inventory_command_cannot_become_a_passing_empty_partition(self) -> None:
        for slice_name in SLICES[:2]:
            with self.subTest(slice=slice_name), tempfile.TemporaryDirectory(
                    prefix="i686-failed-inventory-") as temporary:
                root = Path(temporary)
                with self.assertRaises(subprocess.CalledProcessError) as caught:
                    workflow_commands(root, slice_name, list_exit=19)
                self.assertEqual(caught.exception.returncode, 19)
                calls = [json.loads(line) for line in
                         (root / f"{slice_name}.jsonl").read_text().splitlines()]
                self.assertTrue(all("--list" in argv for argv in calls))

    def test_future_binary_and_integration_tests_run_exactly_once(self) -> None:
        # This dependency-free fixture reproduces the reviewer's missing
        # auto-discovered executable unit test using real i686 Cargo selection.
        sources = {
            "Cargo.toml": '''[package]
name = "opc-session-net"
version = "0.0.0"
edition = "2021"
autotests = false
[workspace]
[[test]]
name = "existing_integration"
path = "tests/existing_integration.rs"
[[test]]
name = "future_integration"
path = "tests/future_integration.rs"
''',
            "src/lib.rs": '''/// ```
/// assert_eq!(opc_session_net::value(), 7);
/// ```
pub fn value() -> u8 { 7 }
#[test] fn library_probe() { assert_eq!(value(), 7); }
mod stateless_quorum_consumer {
''' + "".join(f"#[test] fn {name}() {{}}\n" for name in
                (*ORDINARY_CONTRACTS, *OPTIMIZED_CONTRACTS,
                 CRASH_MATRIX.rsplit("::", 1)[1], CRASH_MATRIX.rsplit("::", 1)[1] + "_future")) + '''
    mod publication_authority_failover {
        #[test] fn existing_authority_probe() {}
        #[test] fn future_authority_probe() {}
    }
    mod publication_authority_failover_future {
        #[test] fn adjacent_namespace_probe() {}
    }
}
''',
            "tests/existing_integration.rs":
                "#[test] fn existing_integration_probe() {}\n",
            "tests/future_integration.rs":
                "#[test] fn future_integration_probe() {}\n",
            "src/bin/future_binary.rs":
                "fn main() {}\n#[test] fn future_binary_unit_probe() {}\n",
        }
        with tempfile.TemporaryDirectory(prefix="i686-selection-") as temporary:
            root = Path(temporary)
            for name, content in sources.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            # A stable worktree-local cache is separate from fixture scratch.
            env = {
                **os.environ,
                "CARGO_TARGET_DIR": str(ROOT / "target/i686-selector-probe"),
            }
            subprocess.run(
                ["cargo", "generate-lockfile", "--offline"],
                cwd=root, env=env, check=True,
            )
            inventory = subprocess.run(
                [*SELECTION, "--lib", "--", "--list", "--format=terse"],
                cwd=root, env=env, text=True, capture_output=True, check=True,
            ).stdout
            ordinary = workflow_commands(root, "ordinary", inventory=inventory)
            authority = workflow_commands(root, "ordinary-authority", inventory=inventory)
            integration = workflow_commands(root, "ordinary-integration")
            self.assertEqual(len(ordinary), 1)
            self.assertEqual(len(authority), 1)
            # The pre-split command retains every feature, target, harness flag
            # and the ten timing exclusions. Its selection is the oracle.
            baseline = [*SELECTION, "--", "--test-threads=1", "--exact",
                        *(arg for name in CONTRACTS for arg in ("--skip", name))]

            def listed(command: list[str]) -> Counter:
                result = subprocess.run(
                    [*command, "--list"],
                    cwd=root, env=env, text=True, capture_output=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                names = re.findall(r"^(.+): test$", result.stdout, re.MULTILINE)
                print(json.dumps({"argv": command, "listed_tests": names}), flush=True)
                return Counter(names)

            before = listed(baseline)
            ordinary_names = listed(ordinary[0])
            authority_names = listed(authority[0])
            after = ordinary_names + authority_names + sum(
                (listed(command) for command in integration), Counter())
            self.assertEqual(authority_names, Counter({CRASH_MATRIX: 1,
                             AUTHORITY_PREFIX + "existing_authority_probe": 1,
                             AUTHORITY_PREFIX + "future_authority_probe": 1}))
            self.assertEqual(ordinary_names[CRASH_MATRIX + "_future"], 1)
            self.assertEqual(ordinary_names[
                "stateless_quorum_consumer::publication_authority_failover_future::adjacent_namespace_probe"], 1)
            self.assertEqual(before["future_binary_unit_probe"], 1)
            self.assertEqual(before["future_integration_probe"], 1)
            self.assertEqual(before["existing_integration_probe"], 1)
            self.assertEqual(before["library_probe"], 1)
            self.assertEqual(sum(before.values()), 10, "include future library members and the doctest")
            self.assertEqual(after, before, "ordinary shards must be total and disjoint")


if __name__ == "__main__":
    unittest.main()
