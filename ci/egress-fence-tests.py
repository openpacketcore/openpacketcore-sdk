#!/usr/bin/env python3
"""Partition the egress host tests by exact libtest name, without narrowing features.

Every ordinary shard retains the old six-package/all-features selection. Cargo still
launches every harness with its original working directory and environment.
Only exact test-name exclusions differ. Existing isolated proofs retain their
package selection, single-test processes and (where prescribed) O1 profile.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
PACKAGES = (
    "opc-egress-fence", "opc-egress-fence-common", "opc-linux-gtpu-sys",
    "opc-linux-xfrm-sys", "opc-runtime", "opc-session-store",
)
SELECTION = ["--locked", *[arg for name in PACKAGES for arg in ("-p", name)],
             "--all-features"]
ORDINARY_SHARDS = (0, 1, 2)
PROOF_SHARD = 3
SHARDS = (*ORDINARY_SHARDS, PROOF_SHARD)
REQUIRED_JOBS = ("sources", "oracles", "installer", "host-tests", "host-proofs")
ISOLATED_LIB = (
    "consensus::storage::tests::promoted_mismatch_never_unlinks_a_same_name_replacement",
    "consensus::raft_adapter::tests::raw_fixed_handler_uses_one_durable_authority_check_for_each_engine_family",
    "consensus::store::membership_tests::protected_roster_ingress_has_two_mutations_and_read_only_status_paths",
)
ISOLATED_INTEGRATION = (
    "lagging_replica_installs_compacted_snapshot_without_losing_committed_state",
    "fenced_transition_snapshot_install_preserves_exact_replay_without_second_effect",
    "compacted_successor_snapshot_catches_up_predecessor_voter_and_survives_full_restart",
)
OPTIMIZED_LIB = (
    "sqlite::consensus::tests::protected_roster_retirement_uses_a_1024_row_global_prefix_then_final_partial_batch",
    "sqlite::consensus::tests::due_protected_roster_maintenance_reclaims_the_oldest_bounded_prefix_only",
    "sqlite::consensus::tests::fenced_transition_v2_capacity_opens_successor_and_bounds_eight_exact_epochs",
    "sqlite::consensus::tests::fenced_transition_v2_floor_reclaims_oldest_while_successor_remains_writable",
    "sqlite::consensus::tests::fenced_transition_v2_post_reclaim_deletion_keeps_retired_and_conflict_closed",
    "sqlite::consensus::tests::fenced_transition_v2_reclaims_exactly_1024_then_opens_next_epoch",
    "sqlite::consensus::tests::fenced_transition_v2_revoked_authority_masks_nonactive_epoch_in_apply_and_projection",
    "sqlite::consensus::tests::fenced_transition_v2_snapshot_during_reclaim_preserves_cursor_and_rejects_regression",
)
SPECIAL = (*ISOLATED_LIB, *ISOLATED_INTEGRATION, *OPTIMIZED_LIB)


def owner(name: str) -> int:
    """The same name in two harnesses must have the same owner: skips are global."""
    if name in SPECIAL:
        return PROOF_SHARD
    return int.from_bytes(hashlib.sha256(name.encode()).digest()[:8], "big") % len(ORDINARY_SHARDS)


def listing(output: str) -> list[str]:
    names = []
    for line in output.splitlines():
        if line.endswith(": test"):
            names.append(line.removesuffix(": test"))
        elif line.strip() and not re.fullmatch(r"\d+ tests?, \d+ benchmarks?", line):
            raise ValueError("unexpected libtest inventory line: " + line)
    if len(names) != len(set(names)):
        raise ValueError("duplicate name in a test harness")
    return names


def capture(command: list[str], cwd: Path = ROOT) -> str:
    return subprocess.run(command, cwd=cwd, check=True, text=True,
                          stdout=subprocess.PIPE).stdout


def inventory() -> list[dict]:
    metadata = json.loads(capture(["cargo", "metadata", "--locked", "--no-deps",
                                   "--format-version=1"]))
    packages = {p["id"]: p for p in metadata["packages"] if p["name"] in PACKAGES}
    if {p["name"] for p in packages.values()} != set(PACKAGES):
        raise ValueError("missing host package")
    expected = {
        (p["id"], t["name"], tuple(t["kind"]))
        for p in packages.values() for t in p["targets"]
        if t.get("test", True) and set(t["kind"]) & {"lib", "bin", "test"}
    }
    output = capture(["cargo", "test", *SELECTION, "--tests", "--no-run",
                      "--message-format=json"])
    binaries = {}
    for line in output.splitlines():
        message = json.loads(line)
        if message.get("reason") != "compiler-artifact" or not message["profile"]["test"]:
            continue
        if message["package_id"] not in packages or not message.get("executable"):
            continue
        key = (message["package_id"], message["target"]["name"], tuple(message["target"]["kind"]))
        if key in binaries:
            raise ValueError("duplicate compiled test target")
        binaries[key] = message["executable"]
    if set(binaries) != expected:
        raise ValueError(f"compiled test targets differ from Cargo metadata: {set(binaries) ^ expected}")
    rows = []
    for (package_id, target, kind), binary in sorted(binaries.items()):
        package = packages[package_id]
        cwd = Path(package["manifest_path"]).parent
        names = listing(capture([binary, "--list", "--format=terse"], cwd))
        ignored = set(listing(capture([binary, "--ignored", "--list", "--format=terse"], cwd)))
        if not ignored.issubset(names):
            raise ValueError("ignored inventory is not a subset of the full inventory")
        rows.extend({"package": package["name"], "target": target, "kind": list(kind),
                     "name": name, "ignored": name in ignored, "shard": owner(name)}
                    for name in names)
    verify(rows)
    return rows


def verify(rows: list[dict]) -> None:
    if not rows:
        raise ValueError("empty test inventory")
    identities = [(r["package"], r["target"], tuple(r["kind"]), r["name"]) for r in rows]
    if len(identities) != len(set(identities)):
        raise ValueError("duplicate test identity")
    for name in SPECIAL:
        matches = [r for r in rows if r["name"] == name]
        target = "consensus_openraft" if name in ISOLATED_INTEGRATION else "opc_session_store"
        kind = ["test"] if name in ISOLATED_INTEGRATION else ["lib"]
        if len(matches) != 1 or matches[0]["package"] != "opc-session-store" or \
                matches[0]["target"] != target or matches[0]["kind"] != kind or matches[0]["ignored"]:
            raise ValueError("isolated test must resolve exactly once and remain enabled: " + name)
    for row in rows:
        if row["shard"] != owner(row["name"]):
            raise ValueError("test assigned to the wrong shard")
    for shard in ORDINARY_SHARDS:
        if not any(r["shard"] == shard and not r["ignored"] and r["name"] not in SPECIAL for r in rows):
            raise ValueError("empty ordinary shard")


def plans(rows: list[dict], shard: int) -> list[dict]:
    if shard not in SHARDS:
        raise ValueError("unknown shard")
    verify(rows)
    commands = []
    if shard in ORDINARY_SHARDS:
        skipped = sorted({r["name"] for r in rows if r["name"] in SPECIAL or r["shard"] != shard})
        commands.append({"name": "ordinary", "env": {}, "argv": [
            "cargo", "test", *SELECTION, "--quiet", "--tests", "--", "--test-threads=4",
            "--exact", *[arg for name in skipped for arg in ("--skip", name)],
        ]})
    if shard == PROOF_SHARD:
        for name in (*ISOLATED_INTEGRATION, *ISOLATED_LIB):
            target = ["--test", "consensus_openraft"] if name in ISOLATED_INTEGRATION else ["--lib"]
            commands.append({"name": name, "env": {}, "argv": [
                "cargo", "test", "--locked", "-p", "opc-session-store", "--all-features",
                "--quiet", *target, "--", "--test-threads=1", "--exact", name,
            ]})
    if shard == 1:
        # Unfiltered cargo test compiled examples in ordinary build mode and
        # ran doctests. --tests excludes both, so retain each here exactly once.
        commands.extend([
            {"name": "examples", "env": {}, "argv": ["cargo", "build", *SELECTION, "--quiet", "--examples"]},
            {"name": "doctests", "env": {}, "argv": [
                "cargo", "test", *SELECTION, "--quiet", "--doc", "--", "--test-threads=4",
                "--exact", *[arg for name in SPECIAL for arg in ("--skip", name)],
            ]},
            {"name": "qualification-profile", "env": {}, "argv": [
                "cargo", "test", "--locked", "-p", "opc-session-testkit", "--test",
                "qualification_profile", "--quiet", "--", "--test-threads=1",
            ]},
        ])
    if shard == PROOF_SHARD:
        for name in OPTIMIZED_LIB:
            commands.append({"name": name, "env": {"CARGO_PROFILE_TEST_OPT_LEVEL": "1"}, "argv": [
                "cargo", "test", "--locked", "-p", "opc-session-store", "--lib", "--all-features",
                "--quiet", "--", "--test-threads=1", "--exact", name,
            ]})
    return commands


def require_jobs(needs: dict) -> None:
    if set(needs) != {"changes", *REQUIRED_JOBS}:
        raise ValueError("missing or unexpected qualification job")
    changes = needs["changes"]
    skip = changes.get("result") == "success" and changes.get("outputs", {}).get("run") == "false"
    expected = "skipped" if skip else "success"
    for name in REQUIRED_JOBS:
        if needs[name].get("result") != expected:
            raise ValueError(f"{name}: expected {expected}, got {needs[name].get('result')}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard", type=int, choices=SHARDS)
    parser.add_argument("--inventory-only", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check-jobs", action="store_true")
    args = parser.parse_args()
    if args.check_jobs:
        require_jobs(json.loads(os.environ["EGRESS_JOB_RESULTS"]))
        print("Every required egress-fence job has the expected result.")
        return 0
    if args.output is None or (not args.inventory_only and args.shard is None):
        parser.error("--output and either --shard or --inventory-only are required")
    rows = inventory()
    plan = {str(shard): plans(rows, shard) for shard in SHARDS}
    report = {"head": capture(["git", "rev-parse", "HEAD"]).strip(), "tests": rows,
              "ordinary_selection": SELECTION, "plans": plan,
              "isolated_proofs_shard": PROOF_SHARD,
              "doctests_shard": 1, "examples_shard": 1, "qualification_profile_shard": 1}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("Exact test-name partition:", dict(sorted(Counter(r["shard"] for r in rows).items())), flush=True)
    if not args.inventory_only:
        for command in plan[str(args.shard)]:
            print("egress-fence:", command["name"], shlex.join(command["argv"]), flush=True)
            subprocess.run(command["argv"], cwd=ROOT, env=dict(os.environ, **command["env"]), check=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, subprocess.CalledProcessError) as error:
        print("egress-fence test plan failed:", error, file=sys.stderr)
        raise SystemExit(1) from error
