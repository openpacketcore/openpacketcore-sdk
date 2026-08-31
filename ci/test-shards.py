#!/usr/bin/env python3
"""Split the workspace test run across CI runners without changing coverage.

Every shard runs the identical package selection

    cargo test --locked --workspace --exclude opc-persist --all-features ...

and differs only in cargo *target* filters (``--lib``/``--bins``/``--doc``/
``--test NAME``). Under ``resolver = "2"`` the resolved feature set of every
dependency is a function of the selected *packages*, not of the selected
targets, so each shard compiles its test binaries against byte-identical
dependency configurations. Filtering by package instead (``-p X``) would
silently narrow those features -- for example ``-p opc-diameter-transport``
builds opc-proto-diameter without any ``app-*`` feature, while the workspace
selection builds it with ``all-apps``.

Cargo launches the test binaries itself, so the harness argv, working
directory and every ``CARGO_*`` variable a test may read stay exactly what the
single-job run provided, except for the explicitly enumerated protected-roster
and snapshot/restart proofs that compile at test profile O1 without changing
their literal authority bounds.

Usage:
    test-shards.py ids                 # shard ids, one per line (CI matrix)
    test-shards.py plan --shard ID     # shell commands for one shard
    test-shards.py verify              # prove the partition is total+disjoint
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLAN_PATH = ROOT / "ci" / "test-shards.json"

# Identical in every shard: this is what pins feature unification.
PACKAGES = [
    "--locked",
    "--workspace",
    "--exclude",
    "opc-persist",
    "--all-features",
]
SELECTION = ["cargo", "test", *PACKAGES, "--quiet"]
# The unfiltered `cargo test` also compiled every example, in ordinary build
# mode, purely as a compile check. `cargo test --examples` is NOT the same
# thing: an explicit target filter switches examples to CompileMode::Test, so
# they build with cfg(test) on and run as test binaries. `cargo build` keeps
# the original semantics.
EXAMPLES = ["cargo", "build", *PACKAGES, "--quiet", "--examples"]
HARNESS = ["--test-threads=4"]

# These tests intentionally prove literal authority or operation budgets.
# Running them beside unrelated Tokio runtimes makes the assertion measure
# process scheduling and fixture teardown instead of the request path. Keep
# the production bounds exact and give each timing contract its own process.
# This historical suite is deliberately compiled as a crate-private lib test
# module. It exercises raw physical adapters which must not be public merely
# to keep an old integration target compiling. Its sensitive contracts remain
# isolated, but use their libtest-qualified names below.
QUIESCENT_LIB_MODULE = "stateless_quorum_consumer"
QUIESCENT_LIB_TESTS = (
    "persistent_three_voter_consumer_write_does_not_spend_budget_on_a_read_quorum",
    "persistent_three_voter_fenced_status_converges_after_response_loss_and_compaction",
    "persistent_three_voter_first_transition_has_one_leader_activation_proof",
    "protected_consumer_chain_after_activation_elides_outer_capability_wire_calls",
    "persistent_three_voter_protected_roster_survives_real_os_process_loss",
    "persistent_three_voter_protected_roster_creates_absent_record_then_established_terminal",
    "persistent_three_voter_protected_roster_aborted_exact_bytes_survive_snapshot_and_full_restart",
    "persistent_three_voter_protected_roster_commits_maximum_plan_and_result_then_established_terminal",
    "persistent_three_voter_snapshot_maintenance_with_concurrent_read_barriers_keeps_engines_running",
    "persistent_three_voter_protected_roster_exact_bytes_survive_snapshot_and_full_restart",
)
QUIESCENT_CONSENSUS_OPENRAFT_TARGET = "consensus_openraft"
QUIESCENT_CONSENSUS_OPENRAFT_TESTS = (
    "lagging_replica_installs_compacted_snapshot_without_losing_committed_state",
    "fenced_transition_snapshot_install_preserves_exact_replay_without_second_effect",
)
OPTIMIZED_QUIESCENT_LIB_TESTS = frozenset(
    {
        "persistent_three_voter_protected_roster_creates_absent_record_then_established_terminal",
        "persistent_three_voter_protected_roster_aborted_exact_bytes_survive_snapshot_and_full_restart",
        "persistent_three_voter_protected_roster_commits_maximum_plan_and_result_then_established_terminal",
        "persistent_three_voter_snapshot_maintenance_with_concurrent_read_barriers_keeps_engines_running",
        "persistent_three_voter_protected_roster_exact_bytes_survive_snapshot_and_full_restart",
    }
)
if not OPTIMIZED_QUIESCENT_LIB_TESTS.issubset(QUIESCENT_LIB_TESTS):
    raise RuntimeError("optimized timing tests must also be isolated timing tests")
# Keep O1 confined to the snapshot/restart roster proofs.
# Applying it to unrelated expiry/fault tests changes their lifecycle timing
# and would no longer qualify the repository's ordinary test profile.

# A partition that collapses to a handful of targets would still be "total and
# disjoint" if metadata were misread, so hold a floor on the real inventory
# (verify the live inventory with `test-shards.py verify`; keep this floor
# deliberately below it).
MIN_INTEGRATION_TARGETS = 240


def load_plan() -> dict:
    return json.loads(PLAN_PATH.read_text())


def integration_targets() -> list[str]:
    """Every integration-test target name in the workspace, minus opc-persist.

    Names are deduplicated: several crates define e.g. tests/corpus_replay.rs,
    and ``--test corpus_replay`` selects all of them, so they form one
    indivisible partition unit.
    """
    raw = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout
    names: set[str] = set()
    for package in json.loads(raw)["packages"]:
        if package["name"] == "opc-persist":
            continue
        for target in package["targets"]:
            # `test = false` keeps a target compiling but excluded from
            # `cargo test`; naming it with --test would force it to run, so
            # honour the manifest exactly as the unfiltered run did.
            if "test" in target["kind"] and target.get("test", True):
                names.add(target["name"])
    if len(names) < MIN_INTEGRATION_TARGETS:
        sys.exit(
            f"only {len(names)} integration targets discovered "
            f"(expected >= {MIN_INTEGRATION_TARGETS}); refusing to shard a "
            "selection this small, since it would silently skip tests"
        )
    return sorted(names)


def assign(plan: dict, targets: list[str]) -> dict[str, list[str]]:
    """Longest-processing-time-first packing.

    A pure function of (sorted target names, weights, shard count), so every
    shard and the verifier independently compute the same assignment.
    """
    heavy = plan["heavy"]["target"]
    weights = plan["weights"]
    default = float(plan["default_weight"])
    count = int(plan["integration_shards"])

    buckets: dict[str, list[str]] = {f"it-{i}": [] for i in range(count)}
    load = [0.0] * count
    ordered = sorted(
        (t for t in targets if t != heavy),
        key=lambda t: (-float(weights.get(t, default)), t),
    )
    for target in ordered:
        i = min(range(count), key=lambda j: (load[j], j))
        buckets[f"it-{i}"].append(target)
        load[i] += float(weights.get(target, default))
    for names in buckets.values():
        names.sort()
    return buckets


def shard_ids(plan: dict) -> list[str]:
    ids = ["misc"]
    ids += [f"it-{i}" for i in range(int(plan["integration_shards"]))]
    ids += [f"heavy-{i}" for i in range(len(plan["heavy"]["shards"]))]
    return ids


def qualified_quiescent_lib_test(name: str) -> str:
    return f"{QUIESCENT_LIB_MODULE}::{name}"


def quiescent_lib_command(name: str) -> list[str]:
    """Run one private-lib timing contract in its exact isolated profile."""
    profile = (
        ["env", "CARGO_PROFILE_TEST_OPT_LEVEL=1"]
        if name in OPTIMIZED_QUIESCENT_LIB_TESTS
        else []
    )
    return profile + SELECTION + [
        "--lib",
        "--",
        "--test-threads=1",
        "--exact",
        qualified_quiescent_lib_test(name),
    ]


def quiescent_consensus_openraft_command(name: str) -> list[str]:
    """Run one snapshot contract alone with no competing test runtime."""
    return SELECTION + [
        "--test",
        QUIESCENT_CONSENSUS_OPENRAFT_TARGET,
        "--",
        "--test-threads=1",
        "--exact",
        name,
    ]


def quiescent_contracts() -> tuple:
    """Integration-target contracts that require a fresh test process."""
    return (
        (
            QUIESCENT_CONSENSUS_OPENRAFT_TARGET,
            QUIESCENT_CONSENSUS_OPENRAFT_TESTS,
            quiescent_consensus_openraft_command,
        ),
    )


def commands(plan: dict, shard: str, targets: list[str]) -> list[list[str]]:
    """The cargo invocations for one shard."""
    heavy = plan["heavy"]
    named = [name for group in heavy["shards"] for name in group]

    if shard == "misc":
        # Unit tests, binary tests, the example compile check, doctests, plus
        # every test in the heavy target that is not claimed by a heavy-N
        # shard. --exact makes the skips exact-match: libtest skips by
        # substring by default, which would also swallow a future test whose
        # name merely starts with a fleet test's name.
        skips = [arg for name in named for arg in ("--skip", name)]
        # The raw-adapter qualification module is now crate-private, so it
        # runs inside this ordinary --lib process. Exclude each timing
        # contract here and run it below in its own --lib process; otherwise
        # its literal timing bounds become a process-concurrency test.
        lib_skips = [
            arg
            for name in QUIESCENT_LIB_TESTS
            for arg in ("--skip", qualified_quiescent_lib_test(name))
        ]
        return [
            SELECTION + ["--lib", "--bins", "--", *HARNESS, "--exact", *lib_skips],
            *[quiescent_lib_command(name) for name in QUIESCENT_LIB_TESTS],
            list(EXAMPLES),
            SELECTION + ["--doc", "--", *HARNESS],
            SELECTION
            + ["--test", heavy["target"], "--", *HARNESS, "--exact", *skips],
        ]

    if shard.startswith("heavy-"):
        group = heavy["shards"][int(shard.split("-", 1)[1])]
        # --exact with explicit names: this shard runs these tests and nothing
        # else, so the groups cannot overlap.
        return [
            SELECTION
            + ["--test", heavy["target"], "--", *HARNESS, "--exact", *group]
        ]


    buckets = assign(plan, targets)
    if shard not in buckets:
        sys.exit(f"unknown shard id: {shard}")
    selected = [arg for name in buckets[shard] for arg in ("--test", name)]
    if not selected:
        sys.exit(f"shard {shard} selected no targets; the plan is broken")
    contracts = [
        contract
        for contract in quiescent_contracts()
        if contract[0] in buckets[shard]
    ]
    if not contracts:
        return [SELECTION + selected + ["--", *HARNESS]]

    # libtest's skip filter is substring-based unless --exact is present. The
    # ordinary invocation still runs every other test in this target, while a
    # fresh process runs each timing contract alone with no competing runtime.
    skips = [
        arg
        for _, names, _ in contracts
        for name in names
        for arg in ("--skip", name)
    ]
    ordinary = (
        SELECTION
        + selected
        + ["--", *HARNESS, "--exact", *skips]
    )
    isolated = [
        command(name)
        for _, names, command in contracts
        for name in names
    ]
    return [ordinary, *isolated]


WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def verify_workflow(plan: dict) -> None:
    """Fail if ci.yml drifted from this plan.

    Two ways to silently stop testing something: change the plan without the
    matrix (a slice of the suite stops running), or add a Rust lane without
    adding it to the aggregator's `needs` (the lane can fail while the single
    "Rust workspace" check stays green).
    """
    text = WORKFLOW.read_text()

    body = text.split("\n  rust-tests:", 1)
    if len(body) != 2:
        sys.exit(f"no `rust-tests` job found in {WORKFLOW}")
    match = re.search(r"^\s*shard:\s*\[([^\]]*)\]", body[1], re.M)
    if not match:
        sys.exit(f"no `shard: [...]` matrix in the rust-tests job of {WORKFLOW}")
    declared = [item.strip() for item in match.group(1).split(",") if item.strip()]
    expected = shard_ids(plan)
    if declared != expected:
        sys.exit(
            f"{WORKFLOW.name} runs shards {declared} but the plan defines "
            f"{expected}"
        )

    lanes = set(re.findall(r"^  (rust-[a-z0-9-]+):$", text, re.M))
    aggregator = text.split("\n  rust:\n", 1)
    if len(aggregator) != 2:
        sys.exit(f"no `rust` aggregator job found in {WORKFLOW}")
    needed = set(re.findall(r"^      - (rust-[a-z0-9-]+)$", aggregator[1], re.M))
    unguarded = lanes - needed
    if unguarded:
        sys.exit(
            f"Rust lanes missing from the aggregator's needs: "
            f"{sorted(unguarded)}. They could fail while 'Rust workspace' "
            f"stays green."
        )
    print(
        f"workflow ok: {len(expected)} shards, {len(lanes)} lanes all guarded "
        f"by the aggregator"
    )


def verify_commands(plan: dict, targets: list[str]) -> None:
    """Fail if a shard would run less than its definition promises.

    The partition check proves which *targets* belong to which shard; this
    proves the shard actually issues the invocations that cover them, so
    dropping (say) the doctest command cannot pass unnoticed.
    """
    misc_commands = commands(plan, "misc", targets)
    misc = [" ".join(command) for command in misc_commands]
    required = {
        "unit tests": " --lib --bins ",
        "example compile check": "cargo build ",
        "doctests": " --doc ",
        "heavy remainder": f" --test {plan['heavy']['target']} ",
    }
    for label, fragment in required.items():
        if not any(fragment in f"{command} " for command in misc):
            sys.exit(f"the misc shard no longer runs {label}")
    if len(QUIESCENT_LIB_TESTS) != len(set(QUIESCENT_LIB_TESTS)):
        sys.exit("private-lib isolated timing contracts are duplicated")
    lib_skip = ["--exact"] + [
        arg
        for name in QUIESCENT_LIB_TESTS
        for arg in ("--skip", qualified_quiescent_lib_test(name))
    ]
    if misc_commands[0][-len(lib_skip) :] != lib_skip:
        sys.exit(
            "the misc ordinary --lib process must skip every private-lib "
            "timing contract exactly once"
        )
    expected_lib_isolated = [quiescent_lib_command(name) for name in QUIESCENT_LIB_TESTS]
    if misc_commands[1 : 1 + len(expected_lib_isolated)] != expected_lib_isolated:
        sys.exit(
            "the misc shard must run private-lib timing contracts once each, "
            "in their declared module-qualified name order"
        )
    for index, group in enumerate(plan["heavy"]["shards"]):
        if not group:
            # `--exact` with no names disables filtering, so an empty group
            # would silently re-run the entire heavy target.
            sys.exit(f"heavy-{index} names no tests; remove the group instead")

    buckets = assign(plan, targets)
    declared_names: set[str] = set()
    for target, names, _ in quiescent_contracts():
        if not names:
            sys.exit(f"{target!r} has no isolated timing contracts")
        if len(names) != len(set(names)):
            sys.exit(f"{target!r} repeats an isolated timing contract")
        if target not in targets:
            sys.exit(f"isolated timing-contract target {target!r} does not exist")
        duplicate = declared_names & set(names)
        if duplicate:
            sys.exit(f"isolated timing contracts are duplicated: {sorted(duplicate)}")
        declared_names.update(names)

        owners = [
            bucket_shard
            for bucket_shard, bucket_targets in buckets.items()
            if target in bucket_targets
        ]
        if len(owners) != 1:
            sys.exit(
                f"{target!r} must belong to exactly one integration shard, "
                f"found {owners}"
            )
        owner = owners[0]
        owner_contracts = [
            contract
            for contract in quiescent_contracts()
            if contract[0] in buckets[owner]
        ]
        owner_commands = commands(plan, owner, targets)
        expected_isolated = [
            command(name)
            for _, contract_names, command in owner_contracts
            for name in contract_names
        ]
        if owner_commands[1:] != expected_isolated:
            sys.exit(
                f"{owner} must run isolated timing contracts once each, in "
                "their declared target and name order"
            )
        skip = ["--exact"] + [
            arg
            for _, contract_names, _ in owner_contracts
            for name in contract_names
            for arg in ("--skip", name)
        ]
        if owner_commands[0][-len(skip) :] != skip:
            sys.exit(
                f"{owner} must skip every isolated timing contract exactly "
                "once in its ordinary multi-test process"
            )
    print(f"shard commands ok: misc issues {len(misc)} invocations")


def verify(plan: dict, targets: list[str]) -> None:
    """Prove every target runs exactly once across the shard set."""
    verify_workflow(plan)
    verify_commands(plan, targets)
    buckets = assign(plan, targets)
    heavy = plan["heavy"]["target"]

    seen: dict[str, str] = {}
    for shard, names in buckets.items():
        for name in names:
            if name in seen:
                sys.exit(f"{name} is assigned to both {seen[name]} and {shard}")
            seen[name] = shard

    expected = {t for t in targets if t != heavy}
    missing = expected - set(seen)
    if missing:
        sys.exit(f"integration targets assigned to no shard: {sorted(missing)}")
    extra = set(seen) - expected
    if extra:
        sys.exit(f"shards claim targets that do not exist: {sorted(extra)}")
    if heavy not in targets:
        sys.exit(
            f"heavy target {heavy!r} no longer exists; update {PLAN_PATH.name}"
        )

    named = [name for group in plan["heavy"]["shards"] for name in group]
    if len(named) != len(set(named)):
        sys.exit("a heavy test name is claimed by more than one shard")

    print(
        f"partition ok: {len(expected)} integration targets across "
        f"{len(buckets)} shards, plus {heavy!r} split over "
        f"{len(plan['heavy']['shards'])} shards with the remainder on 'misc'"
    )
    weights = plan["weights"]
    default = float(plan["default_weight"])
    for shard in sorted(buckets):
        total = sum(float(weights.get(n, default)) for n in buckets[shard])
        print(f"  {shard}: {len(buckets[shard]):3d} targets, ~{total:.0f}s")


def list_heavy_tests(plan: dict, extra: list[str]) -> set[str]:
    """Ask the built heavy binary which tests a given filter selects."""
    command = (
        SELECTION
        + ["--test", plan["heavy"]["target"], "--", "--list"]
        + extra
    )
    out = subprocess.run(
        command, cwd=ROOT, text=True, stdout=subprocess.PIPE, check=True
    ).stdout
    return {
        line.rsplit(":", 1)[0]
        for line in out.splitlines()
        if line.endswith(": test")
    }


def list_quiescent_test(target: str, name: str) -> list[str]:
    """Resolve the isolated timing contract using its exact CI invocation."""
    command = SELECTION + [
        "--test",
        target,
        "--",
        "--list",
        "--exact",
        name,
    ]
    out = subprocess.run(
        command, cwd=ROOT, text=True, stdout=subprocess.PIPE, check=True
    ).stdout
    return [
        line.rsplit(":", 1)[0]
        for line in out.splitlines()
        if line.endswith(": test")
    ]


def list_quiescent_lib_test(name: str) -> list[str]:
    """Resolve one private-lib contract with its exact CI invocation."""
    qualified = qualified_quiescent_lib_test(name)
    command = SELECTION + ["--lib", "--", "--list", "--exact", qualified]
    out = subprocess.run(
        command, cwd=ROOT, text=True, stdout=subprocess.PIPE, check=True
    ).stdout
    return [
        line.rsplit(":", 1)[0]
        for line in out.splitlines()
        if line.endswith(": test")
    ]


def precheck(plan: dict, shard: str) -> None:
    """Fail a heavy shard whose named tests no longer resolve.

    libtest exits 0 when a filter matches nothing, so a renamed test would
    otherwise turn a heavy shard into a green no-op. Coverage would survive
    (``misc`` stops skipping the old name and runs the test, and verify-heavy
    fails), but the lane would burn a runner proving nothing, and a reviewer
    reading a green matrix would have no signal. Resolve the names first.
    """
    # Every shard re-checks the plan itself: rust-tests legs start alongside
    # rust-gates rather than after it, so without this a broken plan would
    # burn six runners before the gates job reported it.
    targets = integration_targets()
    verify(plan, targets)
    if shard == "misc":
        for name in QUIESCENT_LIB_TESTS:
            qualified = qualified_quiescent_lib_test(name)
            selected = list_quiescent_lib_test(name)
            if selected != [qualified]:
                sys.exit(
                    "misc private-lib timing contract does not resolve exactly "
                    f"once: expected {qualified!r}, selected {selected!r}"
                )
        print(
            "misc private-lib timing contracts resolve exactly once: "
            f"{len(QUIESCENT_LIB_TESTS)}"
        )
    buckets = assign(plan, targets)
    if shard in buckets:
        contracts = [
            contract
            for contract in quiescent_contracts()
            if contract[0] in buckets[shard]
        ]
        for target, names, _ in contracts:
            for name in names:
                selected = list_quiescent_test(target, name)
                if selected != [name]:
                    sys.exit(
                        f"{shard} cannot resolve isolated test {name!r} in "
                        f"{target!r} exactly once; selected {selected}"
                    )
        if contracts:
            count = sum(len(names) for _, names, _ in contracts)
            print(f"{shard} isolated timing contracts resolve exactly once: {count}")
    if not shard.startswith("heavy-"):
        return
    group = plan["heavy"]["shards"][int(shard.split("-", 1)[1])]
    selected = list_heavy_tests(plan, ["--exact", *group])
    if selected != set(group):
        missing = sorted(set(group) - selected)
        sys.exit(
            f"{shard} names tests that no longer exist: {missing}. They were "
            f"renamed or removed; update ci/test-shards.json."
        )
    print(f"{shard} precheck ok: {len(group)} tests resolve")


def verify_heavy(plan: dict) -> None:
    """Prove the heavy target's own tests partition exactly.

    Runs on the shard that already built the binary, so this costs three
    ``--list`` invocations and nothing else.
    """
    groups = plan["heavy"]["shards"]
    named = [name for group in groups for name in group]
    # Mirrors the real misc invocation exactly, --exact included: verifying a
    # different filter than the one that runs would prove nothing.
    skips = ["--exact"] + [arg for name in named for arg in ("--skip", name)]

    everything = list_heavy_tests(plan, [])
    remainder = list_heavy_tests(plan, skips)
    claimed: set[str] = set()
    for index, group in enumerate(groups):
        selected = list_heavy_tests(plan, ["--exact", *group])
        if selected != set(group):
            sys.exit(
                f"heavy-{index} selects {sorted(selected)} but the plan names "
                f"{sorted(group)}; a test was renamed or removed"
            )
        if claimed & selected:
            sys.exit(f"heavy-{index} overlaps an earlier shard")
        claimed |= selected

    if remainder & claimed:
        sys.exit(f"'misc' also runs {sorted(remainder & claimed)}")
    if remainder | claimed != everything:
        lost = everything - (remainder | claimed)
        sys.exit(f"tests in the heavy target run on no shard: {sorted(lost)}")

    print(
        f"heavy partition ok: {len(everything)} tests = {len(remainder)} on "
        f"'misc' + {len(claimed)} across {len(groups)} heavy shards"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("ids")
    plan_cmd = sub.add_parser("plan")
    plan_cmd.add_argument("--shard", required=True)
    sub.add_parser("verify")
    sub.add_parser("verify-heavy")
    precheck_cmd = sub.add_parser("precheck")
    precheck_cmd.add_argument("--shard", required=True)
    args = parser.parse_args()

    plan = load_plan()

    if args.command == "ids":
        print("\n".join(shard_ids(plan)))
        return

    if args.command == "verify-heavy":
        verify_heavy(plan)
        return

    if args.command == "precheck":
        precheck(plan, args.shard)
        return

    targets = integration_targets()

    if args.command == "verify":
        verify(plan, targets)
        return

    for command in commands(plan, args.shard, targets):
        print(shlex.join(command))


if __name__ == "__main__":
    main()
