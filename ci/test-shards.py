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
import math
import re
import shlex
import subprocess
import sys
from collections import Counter
from pathlib import Path

import realtime_qualification
import cargo_test_selection
import library_partition
import native_log_bound

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

# Run before any parallel tests on misc, with the same package/features/profile.
# The operation and all-voter apply deadlines remain unchanged in the test.
SERIAL_LIB_TESTS = (
    "consensus::store::sequential_wal_sdk_tests::scope_payload_cost::"
    "scope_large_child_write_decodes_one_payload_per_voter_independent_of_history",
    "consensus::store::sequential_wal_sdk_tests::scope_child_read::"
    "scope_child_read_three_large_children_refuse_the_whole_observation",
)

# These tests intentionally prove literal authority or operation budgets.
# Running them beside unrelated Tokio runtimes makes the assertion measure
# process scheduling and fixture teardown instead of the request path. Keep
# the production bounds exact and give each timing contract its own process.
# This historical suite is deliberately compiled as a crate-private lib test
# module. It exercises raw physical adapters which must not be public merely
# to keep an old integration target compiling. Its sensitive contracts remain
# isolated, but use their libtest-qualified names below.
# The composed selector request also has one literal end-to-end budget. Its
# module serializes its own durable labs, but unrelated lib tests still compete
# with that request unless it runs in a separate process like these contracts.
QUIESCENT_LIB_MODULE = "stateless_quorum_consumer"
QUIESCENT_SELECTOR_LIB_MODULE = "ebpf::tests::remote_selector_regression"
QUIESCENT_SELECTOR_LIB_TEST = (
    "singleton_public_protected_flow_preserves_durable_state"
)
# These call-lifetime assertions use 250 ms physical attempts while another
# request is deliberately stalled. Like the contracts above, they need a
# separate process so unrelated TLS/consensus fixtures cannot spend that cap.
QUIESCENT_VOID_LIB_MODULE = "authenticated_consumer_fixture::v2_facade_tests::void_tests"
QUIESCENT_VOID_LIB_TESTS = (
    "consumer_void_lost_before_bind_drains_the_row_and_resolves_the_live_handle",
    "consumer_void_keeps_a_waiting_call_then_drains_after_cancellation",
    "consumer_void_drains_after_the_leader_loses_authority_during_the_original_call",
    "consumer_void_unknown_response_retains_until_exact_status_confirms_it",
    "consumer_void_unavailable_row_advances_past_status_resolvable_rows_and_wraps",
    "consumer_void_available_rows_drain_in_one_sweep_after_cursor_wrap",
)
# These three-minute arrival-rate proofs measure signed production work. Keep
# their literal load and backlog bounds in the checked O1 timing profile.
# The completion-congestion proofs also retain their literal operation budgets
# while draining a deliberately held wave of signed requests.
QUIESCENT_ROSTER_LIB_MODULE = "consensus::store::sequential_wal_sdk_tests"
QUIESCENT_ROSTER_LIB_TESTS = (
    "roster_maintenance_native_keeps_up_with_ten_due_rows_per_second",
    "roster_maintenance_sqlite_keeps_up_with_ten_due_rows_per_second",
    "roster_completion::roster_completion_native_ordinary_wave_does_not_delay_emergency_admission",
    "roster_completion::roster_completion_native_ordinary_wave_does_not_delay_emergency_completion",
    "roster_completion::roster_completion_native_ordinary_wave_consumes_normal_quota",
    "roster_completion::roster_completion_sqlite_ordinary_wave_does_not_delay_emergency_admission",
    "roster_completion::roster_completion_sqlite_ordinary_wave_does_not_delay_emergency_completion",
    "roster_completion::roster_completion_sqlite_ordinary_wave_consumes_normal_quota",
)
QUIESCENT_LIB_TESTS = (
    "persistent_three_voter_consumer_write_does_not_spend_budget_on_a_read_quorum",
    "persistent_three_voter_fenced_status_converges_after_response_loss_and_compaction",
    "persistent_three_voter_first_transition_has_one_leader_activation_proof",
    "persistent_three_voter_protected_roster_survives_real_os_process_loss",
    QUIESCENT_SELECTOR_LIB_TEST,
    *QUIESCENT_VOID_LIB_TESTS,
    *QUIESCENT_ROSTER_LIB_TESTS,
    "protected_consumer_chain_after_activation_elides_outer_capability_wire_calls",
    "persistent_three_voter_protected_roster_creates_absent_record_then_established_terminal",
    "persistent_three_voter_protected_roster_aborted_exact_bytes_survive_snapshot_and_full_restart",
    "persistent_three_voter_protected_roster_commits_maximum_plan_and_result_then_established_terminal",
    "persistent_three_voter_snapshot_maintenance_with_concurrent_read_barriers_keeps_engines_running",
    "persistent_three_voter_protected_roster_exact_bytes_survive_snapshot_and_full_restart",
    # These boot-key tests use isolated OS children and bounded held proof/reply
    # credits. Run each alone so another native fleet cannot spend those bounds.
    "scope_transport::native_scope_tls_admission_receipt_after_ticket_change_and_irreversible_close",
    "scope_transport::native_scope_tls_boot_binding_survives_snapshot_leader_loss_and_full_reopen",
    "scope_transport::batch::native_scope_batch_emergency_survives_normal_and_unproven_pressure",
    "scope_transport::cross_slot::native_scope_shared_identity_cannot_sign_for_another_slots_boot",
    "scope_transport::scans::native_scope_scan_tls_keeps_one_cut_and_locally_revalidates_fresh_proofs",
    "scope_transport::scans::native_scope_scan_tls_queued_open_releases_running_and_shutdown_drains",
    "scope_transport::scans::native_scope_scan_tls_rejects_a_superseded_boot_on_existing_and_new_channels",
    "scope_transport::child_reads::native_scope_child_read_client_keeps_one_barrier_on_fresh_and_reused_connections",
    "scope_transport::child_reads::native_scope_child_read_builder_reuses_running_credit_and_bounds_all_exchanges",
    "scope_transport::child_reads::native_scope_completion_provenance_rejects_forged_ports_and_early_ack",
    "scope_transport::child_read_guards::native_scope_quorum_revision_signals_distinguish_alerts_from_authenticated_frames",
    "scope_transport::child_read_guards::native_scope_child_read_peer_close_releases_cut_and_proof_while_admission_is_held",
    "scope_transport::child_read_guards::native_scope_child_read_ten_second_cut_bound_returns_retry_and_releases_ownership",
    "scope_transport::child_read_guards::native_scope_child_read_promotes_only_after_current_cut_and_clears_stale_hint",
    "scope_transport::child_read_revocation::native_scope_child_read_held_policy_revocation_returns_unauthorized_without_observation",
)
QUIESCENT_CONSENSUS_OPENRAFT_TARGET = "consensus_openraft"
QUIESCENT_CONSENSUS_OPENRAFT_TESTS = (
    "lagging_replica_installs_compacted_snapshot_without_losing_committed_state",
    "fenced_transition_snapshot_install_preserves_exact_replay_without_second_effect",
    "compacted_successor_snapshot_catches_up_predecessor_voter_and_survives_full_restart",
)
OPTIMIZED_QUIESCENT_LIB_TESTS = frozenset(
    {
        *QUIESCENT_ROSTER_LIB_TESTS,
        "protected_consumer_chain_after_activation_elides_outer_capability_wire_calls",
        "persistent_three_voter_protected_roster_creates_absent_record_then_established_terminal",
        "persistent_three_voter_protected_roster_aborted_exact_bytes_survive_snapshot_and_full_restart",
        "persistent_three_voter_protected_roster_commits_maximum_plan_and_result_then_established_terminal",
        "persistent_three_voter_snapshot_maintenance_with_concurrent_read_barriers_keeps_engines_running",
        "persistent_three_voter_protected_roster_exact_bytes_survive_snapshot_and_full_restart",
    }
)
if not OPTIMIZED_QUIESCENT_LIB_TESTS.issubset(QUIESCENT_LIB_TESTS):
    raise RuntimeError("optimized timing tests must also be isolated timing tests")
# Keep O1 confined to protected-transition, roster-rate and snapshot/restart proofs.
# Its functional counterpart uses the same optimized execution, debug
# assertions, and overflow checks as the separate 100 ms performance gate.
# Match the IPsec/i686 lanes.
# Applying it to unrelated expiry/fault tests changes their lifecycle timing
# and would no longer qualify the repository's ordinary test profile.
OPTIMIZED_QUIESCENT_SHARD = "quiescent-o1"

# A partition that collapses to a handful of targets would still be "total and
# disjoint" if metadata were misread, so hold a floor on the real inventory
# (verify the live inventory with `test-shards.py verify`; keep this floor
# deliberately below it).
MIN_INTEGRATION_TARGETS = 240

# Cargo normally discovers every direct ``tests/*.rs`` source automatically.
# ``opc-session-net`` deliberately opts out so its raw physical-adapter suite
# can remain a crate-private lib module. Once automatic discovery is disabled,
# however, a newly added sibling source is otherwise absent from both Cargo
# metadata and this sharder. Keep that one intentional private module explicit
# and reject every other unregistered direct test source.
PRIVATE_INTEGRATION_TEST_SOURCES = {
    (
        "opc-session-net",
        "tests/stateless_quorum_consumer.rs",
    ): "raw physical adapters are exercised only through the crate-private lib module",
}


def load_plan() -> dict:
    plan = json.loads(PLAN_PATH.read_text())
    plan["qualification"] = realtime_qualification.load_manifest()
    return plan


def qualification_names(plan: dict) -> list[str]:
    return [entry["name"] for entry in plan.get("qualification", [])]


def workspace_packages() -> list[dict]:
    """Return the workspace package metadata used by every shard check."""
    raw = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout
    return json.loads(raw)["packages"]


def manifest_test_source_errors(
    packages: list[dict],
    private_sources: dict[tuple[str, str], str] | None = None,
) -> list[str]:
    """List direct integration sources Cargo would silently omit from CI.

    Nested ``tests/**/mod.rs`` files are support modules rather than Cargo
    integration targets, so this intentionally audits only direct
    ``tests/*.rs`` sources. An exemption must remain both present and
    unregistered; that makes the deliberate crate-private module visible to
    review while preventing it from turning into an open-ended exclusion.
    """
    if private_sources is None:
        private_sources = PRIVATE_INTEGRATION_TEST_SOURCES
    errors: list[str] = []
    matched_exemptions: set[tuple[str, str]] = set()
    for package in packages:
        name = package["name"]
        root = Path(package["manifest_path"]).parent
        tests = root / "tests"
        if not tests.is_dir():
            continue
        cargo_test_sources = {
            Path(target["src_path"]).resolve()
            for target in package["targets"]
            if "test" in target["kind"] and target.get("test", True)
        }
        for source in sorted(tests.glob("*.rs")):
            relative = source.relative_to(root).as_posix()
            exemption = (name, relative)
            registered = source.resolve() in cargo_test_sources
            if exemption in private_sources:
                matched_exemptions.add(exemption)
                if registered:
                    errors.append(
                        f"private integration-test exemption {name}:{relative} "
                        "is now a Cargo target; remove the exemption"
                    )
            elif not registered:
                errors.append(
                    f"integration-test source {name}:{relative} is absent from "
                    "Cargo metadata; register it in Cargo.toml or add a narrow "
                    "private-module exemption"
                )
    stale = set(private_sources) - matched_exemptions
    for name, relative in sorted(stale):
        errors.append(
            f"private integration-test exemption {name}:{relative} does not "
            "match an unregistered direct tests/*.rs source"
        )
    return errors


def i686_test_target_errors(packages: list[dict]) -> list[str]:
    """Reject test target kinds the required i686 selectors do not cover."""
    return [
        f"i686 test target {package['name']}:{target['name']} has uncovered "
        f"kind {target['kind']!r}; assign it to a required shard"
        for package in packages if package["name"] == "opc-session-net"
        for target in package["targets"]
        if target.get("test", True) and target["kind"] not in (["lib"], ["bin"], ["test"])
    ]


def verify_manifest_test_sources(packages: list[dict]) -> None:
    """Fail closed if a direct integration source cannot reach any shard."""
    errors = manifest_test_source_errors(packages) + i686_test_target_errors(packages)
    if errors:
        sys.exit("\n".join(errors))
    print(
        "manifest test-source audit ok: every direct tests/*.rs source is a "
        "Cargo target or one explicit crate-private module",
        file=sys.stderr,
    )


def integration_targets(packages: list[dict] | None = None) -> list[str]:
    """Every integration-test target name in the workspace, minus opc-persist.

    Names are deduplicated: several crates define e.g. tests/corpus_replay.rs,
    and ``--test corpus_replay`` selects all of them, so they form one
    indivisible partition unit.
    """
    if packages is None:
        packages = workspace_packages()
    verify_manifest_test_sources(packages)
    names: set[str] = set()
    for package in packages:
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

    Reserve the measured fixed work before packing target remainders. Every
    shard and the verifier independently compute the same assignment.
    """
    heavy = plan["heavy"]["target"]
    weights = plan["weights"]
    default = float(plan["default_weight"])
    count = int(plan["integration_shards"])

    buckets: dict[str, list[str]] = {f"it-{i}": [] for i in range(count)}
    load = [
        float(plan.get("fixed_weights", {}).get(f"it-{i}", 0))
        + sum(float(group["weight"]) for group in plan.get("integration_groups", [])
              if group["shard"] == f"it-{i}")
        for i in range(count)
    ]
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
    ids = ["misc", OPTIMIZED_QUIESCENT_SHARD]
    ids += [f"it-{i}" for i in range(int(plan["integration_shards"]))]
    ids += [f"heavy-{i}" for i in range(len(plan["heavy"]["shards"]))]
    ids += list(native_log_bound.CORE_SHARDS)
    return ids


def qualified_quiescent_lib_test(name: str) -> str:
    if name == QUIESCENT_SELECTOR_LIB_TEST:
        return f"{QUIESCENT_SELECTOR_LIB_MODULE}::{name}"
    if name in QUIESCENT_VOID_LIB_TESTS:
        return f"{QUIESCENT_VOID_LIB_MODULE}::{name}"
    if name in QUIESCENT_ROSTER_LIB_TESTS:
        return f"{QUIESCENT_ROSTER_LIB_MODULE}::{name}"
    return f"{QUIESCENT_LIB_MODULE}::{name}"


def quiescent_lib_command(name: str) -> list[str]:
    """Run one private-lib timing contract in its exact isolated profile."""
    profile = (
        ["env", "CARGO_PROFILE_TEST_OPT_LEVEL=1"]
        if name in OPTIMIZED_QUIESCENT_LIB_TESTS
        else []
    )
    if name in QUIESCENT_ROSTER_LIB_TESTS:
        profile += ["CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true",
                    "CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true"]
    return profile + SELECTION + [
        "--lib",
        "--",
        "--test-threads=1",
        "--exact",
        qualified_quiescent_lib_test(name),
    ]


def quiescent_lib_list_command(name: str) -> list[str]:
    """List one private-lib contract using its isolated CI profile."""
    command = quiescent_lib_command(name)
    command.insert(-2, "--list")
    return command


def quiescent_lib_tests_for_shard(shard: str, plan: dict) -> tuple[str, ...]:
    """Return the private-lib timing contracts owned by one serial shard."""
    overrides = plan.get("quiescent_lib_shards", {})
    return tuple(
        name
        for name in QUIESCENT_LIB_TESTS
        if overrides.get(
            name,
            OPTIMIZED_QUIESCENT_SHARD
            if name in OPTIMIZED_QUIESCENT_LIB_TESTS
            else "misc",
        ) == shard
    )


def lib_group_names(group: dict) -> list[str]:
    """Named tests move together; future unlisted tests still run on misc."""
    return [f"{group['module']}::{name}" for name in group["tests"]]


def moved_lib_names(plan: dict) -> list[str]:
    return [*SERIAL_LIB_TESTS, *(
        qualified_quiescent_lib_test(name) for name in QUIESCENT_LIB_TESTS
    )] + [
        name for group in plan.get("lib_groups", []) for name in lib_group_names(group)
    ]


def lib_child_parents(plan: dict) -> dict[str, str]:
    return {f"{group['module']}::{child}": f"{group['module']}::{parent}"
            for group in plan.get("lib_groups", [])
            for child, parent in group.get("child_parents", {}).items()}


def serial_lib_command(name: str) -> list[str]:
    return SELECTION + [
        "--lib", "--", "--test-threads=1", "--nocapture", "--exact", name,
    ]


def lib_group_command(group: dict) -> list[str]:
    names = lib_group_names(group)
    native = next((name for name in names if name in native_log_bound.TESTS), None)
    if native is not None:
        profile = native_log_bound.profile_env(native)
        return ["env", *(f"{key}={value}" for key, value in profile.items()), *SELECTION,
                "--lib", "--", "--test-threads=1", "--nocapture", "--exact",
                *names]
    return SELECTION + ["--lib", "--", *HARNESS, "--exact", *lib_group_names(group)]


def extra_lib_commands(plan: dict, shard: str) -> list[list[str]]:
    return [
        lib_group_command(group)
        for group in plan.get("lib_groups", [])
        if group["shard"] == shard
    ] + [
        quiescent_lib_command(name)
        for name in quiescent_lib_tests_for_shard(shard, plan)
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


def integration_group_command(group: dict) -> list[str]:
    return SELECTION + [
        "--test", group["target"], "--", *HARNESS, "--exact", *group["tests"],
    ]


def integration_remainder_command(plan: dict, target: str) -> list[str]:
    names = [name for group in plan.get("integration_groups", [])
             if group["target"] == target for name in group["tests"]]
    return SELECTION + [
        "--test", target, "--", *HARNESS, "--exact",
        *[arg for name in names for arg in ("--skip", name)],
    ]


def integration_commands(plan: dict, shard: str, targets: list[str]) -> list[list[str]]:
    """Keep named slices disjoint, including future tests on the remainder."""
    buckets = assign(plan, targets)
    if shard not in buckets:
        sys.exit(f"unknown shard id: {shard}")
    groups = plan.get("integration_groups", [])
    split_targets = {group["target"] for group in groups}
    ordinary_targets = [name for name in buckets[shard] if name not in split_targets]
    contracts = [contract for contract in quiescent_contracts()
                 if contract[0] in ordinary_targets]
    result = []
    if ordinary_targets:
        selected = [arg for name in ordinary_targets for arg in ("--test", name)]
        skips = [arg for _, names, _ in contracts for name in names
                 for arg in ("--skip", name)]
        result.append(SELECTION + selected + ["--", *HARNESS]
                      + (["--exact", *skips] if contracts else []))
        result.extend(command(name) for _, names, command in contracts for name in names)
    # A skip for one target must never filter an unrelated target's same-named
    # test. Run each split target's remainder in its own Cargo invocation.
    result.extend(integration_remainder_command(plan, target)
                  for target in buckets[shard] if target in split_targets)
    result.extend(integration_group_command(group) for group in groups
                  if group["shard"] == shard)
    return result


def verify_integration_groups(plan: dict, targets: list[str]) -> None:
    shards = {f"it-{i}" for i in range(int(plan["integration_shards"]))}
    if not shards:
        sys.exit("the integration plan must have at least one shard")

    def weight(value):
        if not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            sys.exit("shard weights must be finite nonnegative seconds")

    weight(plan["default_weight"])
    for value in plan["weights"].values():
        weight(value)
    for shard, value in plan.get("fixed_weights", {}).items():
        if shard not in shards:
            sys.exit(f"fixed weight names unknown shard {shard!r}")
        weight(value)
    excluded = {plan["heavy"]["target"], *(row[0] for row in quiescent_contracts())}
    seen = set()
    for group in plan.get("integration_groups", []):
        if group["shard"] not in shards:
            sys.exit("integration group names an unknown shard")
        if group["target"] not in targets or group["target"] in excluded:
            sys.exit("integration group target is absent or already has a specialized partition")
        weight(group["weight"])
        if not group["tests"]:
            sys.exit("integration groups must name at least one exact test")
        for name in group["tests"]:
            identity = group["target"], name
            if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*(?:::[A-Za-z_][A-Za-z_0-9]*)*", name):
                sys.exit("integration groups require literal Rust test names")
            if identity in seen:
                sys.exit("an integration test is claimed by more than one group")
            seen.add(identity)


def list_integration_tests(target: str, filters: list[str]) -> list[str]:
    output = subprocess.run(
        SELECTION + ["--test", target, "--", "--list", *filters],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, check=True,
    ).stdout
    return [line.removesuffix(": test") for line in output.splitlines()
            if line.endswith(": test")]


def verify_grouped_integration(plan: dict, target: str) -> None:
    """Resolve the real libtest filters before either half starts executing."""
    groups = [group for group in plan.get("integration_groups", [])
              if group["target"] == target]
    inventory = list_integration_tests(target, [])
    if not inventory or len(inventory) != len(set(inventory)):
        sys.exit(f"{target}: empty or ambiguous integration inventory")
    remainder = integration_remainder_command(plan, target)
    selected = Counter(list_integration_tests(target, remainder[remainder.index("--") + 1:]))
    for group in groups:
        names = list_integration_tests(target, ["--exact", *group["tests"]])
        if Counter(names) != Counter(group["tests"]):
            sys.exit(f"{target}: integration group names are stale or ambiguous")
        if list_integration_tests(target, ["--ignored", "--exact", *group["tests"]]):
            sys.exit(f"{target}: named integration tests must remain enabled")
        selected.update(names)
    if selected != Counter(inventory):
        sys.exit(f"{target}: integration groups overlap or leave tests without an owner")
    print(f"{target}: exact integration partition verified for {len(inventory)} tests")


def commands(plan: dict, shard: str, targets: list[str]) -> list[list[str]]:
    """The cargo invocations for one shard."""
    heavy = plan["heavy"]
    named = [name for group in heavy["shards"] for name in group]
    extra = extra_lib_commands(plan, shard)

    if shard == "misc":
        # Unit tests, binary tests, the example compile check, doctests, plus
        # every test in the heavy target that is not claimed by a heavy-N
        # shard. --exact makes the skips exact-match: libtest skips by
        # substring by default, which would also swallow a future test whose
        # name merely starts with a fleet or qualification test's name.
        skips = [
            arg for name in [*named, *qualification_names(plan)]
            for arg in ("--skip", name)
        ]
        # The raw-adapter qualification module is now crate-private, so it
        # runs inside this ordinary --lib process. Exclude each timing
        # contract here and run it below in its own --lib process; otherwise
        # its literal timing bounds become a process-concurrency test.
        lib_skips = [
            arg
            for name in moved_lib_names(plan)
            for arg in ("--skip", name)
        ]
        return [
            *(serial_lib_command(name) for name in SERIAL_LIB_TESTS),
            SELECTION + ["--lib", "--", *HARNESS, "--exact", *lib_skips],
            *extra,
            # Library names must never filter a binary's unrelated tests.
            SELECTION + ["--bins", "--", *HARNESS],
            list(EXAMPLES),
            SELECTION + ["--doc", "--", *HARNESS],
            SELECTION
            + ["--test", heavy["target"], "--", *HARNESS, "--exact", *skips],
        ]

    if shard == OPTIMIZED_QUIESCENT_SHARD or shard in native_log_bound.CORE_SHARDS:
        # The O1 snapshot/restart proofs retain their exact serial commands,
        # but compile once on their own runner. Keeping them behind misc's
        # broad lib/bin run exceeded that job's hard 60-minute budget before
        # the first O1 test process could start.
        return extra

    if shard.startswith("heavy-"):
        group = heavy["shards"][int(shard.split("-", 1)[1])]
        # --exact with explicit names: this shard runs these tests and nothing
        # else, so the groups cannot overlap.
        return [
            SELECTION
            + ["--test", heavy["target"], "--", *HARNESS, "--exact", *group],
            *extra,
        ]


    selected = integration_commands(plan, shard, targets)
    if not selected and not extra:
        sys.exit(f"shard {shard} selected no targets; the plan is broken")
    return [*selected, *extra]


def hosted_commands(plan: dict, shard: str, targets: list[str]) -> list[list[str]]:
    """Transfer misc's whole library phase to the required library runners.

    `commands` remains the logical coverage plan. Both this support phase and
    run_libraries derive from it, so an added lib command cannot be stranded.
    """
    return [command for command in commands(plan, shard, targets)
            if shard != "misc" or "--lib" not in command]


def run_libraries(plan: dict, shard: int, output: Path) -> None:
    targets = integration_targets()
    verify(plan, targets)
    phase = [command for command in commands(plan, "misc", targets) if "--lib" in command]
    print("Compile and inventory the complete workspace library selection", flush=True)
    rows, metadata = library_partition.inventory(SELECTION, ROOT)
    planned = {index: library_partition.commands(phase, len(SERIAL_LIB_TESTS), rows, index)
               for index in library_partition.SHARDS}
    library_partition.verify(phase, len(SERIAL_LIB_TESTS), rows, planned, metadata)
    all_libraries = {f"library-{index}": invocations for index, invocations in planned.items()}
    all_libraries.update({owner: [command for command in commands(plan, owner, targets) if "--lib" in command]
                          for owner in shard_ids(plan) if owner != "misc"})
    child_parents = lib_child_parents(plan)
    named_owners = library_partition.verify_named_owners(
        rows, tuple(moved_lib_names(plan)), child_parents, all_libraries, metadata)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "tests": rows, "logical_library_phase": phase, "plans": planned,
        "child_parents": child_parents, "named_test_owners": named_owners,
    }, indent=2) + "\n")
    print(f"Exact library partition verified: {len(rows)} test identities; mapping: {output}", flush=True)
    for index, command in enumerate(planned[shard]):
        print(f"library shard {shard}: invocation {index + 1}/{len(planned[shard])}", flush=True)
        result = subprocess.run(command, cwd=ROOT)
        if result.returncode:
            sys.exit(f"library shard {shard} invocation {index + 1}: exit {result.returncode}; see {output} for argv")


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
    expected = [shard for shard in shard_ids(plan) if shard not in native_log_bound.CORE_SHARDS]
    if declared != expected:
        sys.exit(
            f"{WORKFLOW.name} runs shards {declared} but the plan defines "
            f"{expected}"
        )

    native_job = text.split("\n  rust-native-log-proofs:", 1)
    native_matrix = re.search(r"^\s*shard:\s*\[([^\]]*)\]", native_job[1], re.M) if len(native_job) == 2 else None
    if native_matrix is None or [item.strip() for item in native_matrix.group(1).split(",")] != list(native_log_bound.CORE_SHARDS):
        sys.exit("the dedicated native log proof matrix must run each full-bound shard")

    # Bind the logical library transfer to actual required hosted invocations.
    job_parts = re.split(r"^  ([a-z][a-z0-9-]+):\n", text.split("\njobs:\n", 1)[1], flags=re.M)
    jobs = dict(zip(job_parts[1::2], job_parts[2::2]))
    for operation in ("precheck", "plan"):
        if f"test-shards.py {operation} --shard '${{{{ matrix.shard }}}}'" not in jobs.get("rust-native-log-proofs", ""):
            sys.exit("native log proof runners must precheck and execute their exact shard")
    library_job = jobs.get("rust-libraries", "")
    library_matrix = re.search(r"^\s*shard:\s*\[([^\]]*)\]", library_job, re.M)
    if library_matrix is None or [int(item.strip()) for item in library_matrix.group(1).split(",")] != list(library_partition.SHARDS):
        sys.exit("the dedicated library matrix must cover every library shard")
    if "test-shards.py run-libraries --shard '${{ matrix.shard }}'" not in library_job:
        sys.exit("the dedicated library runners must execute their exact partition")
    for operation in ("precheck", "plan"):
        if f"test-shards.py {operation} --shard '${{{{ matrix.shard }}}}' --split-libraries" not in jobs["rust-tests"]:
            sys.exit("ordinary hosted shards must transfer misc's library phase")

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
    verify_lib_plan(plan)
    verify_integration_groups(plan, targets)
    if plan["heavy"]["target"] != realtime_qualification.TARGET:
        sys.exit("real-time qualification manifest target differs from the heavy target")
    named = [name for group in plan["heavy"]["shards"] for name in group]
    qualification = qualification_names(plan)
    if len(set(qualification)) != len(qualification) or set(qualification) & set(named):
        sys.exit("qualification names are duplicated or also assigned to a required shard")
    misc_commands = commands(plan, "misc", targets)
    serial = [serial_lib_command(name) for name in SERIAL_LIB_TESTS]
    if misc_commands[:len(serial)] != serial:
        sys.exit("misc must run its exact serial library phase before parallel tests")
    ordinary_index = len(serial)
    ordinary = misc_commands[ordinary_index]
    heavy_remainder = SELECTION + [
        "--test", plan["heavy"]["target"], "--", *HARNESS, "--exact",
        *[arg for name in [*named, *qualification] for arg in ("--skip", name)],
    ]
    if misc_commands[-1] != heavy_remainder:
        sys.exit("required heavy remainder must exclude exactly the declared test names")
    if realtime_qualification.SELECTION != SELECTION + ["--test", plan["heavy"]["target"]]:
        sys.exit("qualification must preserve required CI's package and feature selection")
    misc = [" ".join(command) for command in misc_commands]
    required = {
        "unit tests": " --lib ",
        "binary tests": " --bins ",
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
        for name in moved_lib_names(plan)
        for arg in ("--skip", name)
    ]
    if ordinary[-len(lib_skip) :] != lib_skip:
        sys.exit(
            "the misc ordinary --lib process must skip every private-lib "
            "timing contract and moved library test exactly once"
        )
    expected_misc_isolated = [
        quiescent_lib_command(name)
        for name in quiescent_lib_tests_for_shard("misc", plan)
    ]
    if misc_commands[ordinary_index + 1 : ordinary_index + 1 + len(expected_misc_isolated)] != expected_misc_isolated:
        sys.exit(
            "the misc shard must run its private-lib timing contracts once each, "
            "in their declared module-qualified name order"
        )
    optimized_commands = commands(plan, OPTIMIZED_QUIESCENT_SHARD, targets)
    expected_optimized_isolated = [
        quiescent_lib_command(name)
        for name in quiescent_lib_tests_for_shard(OPTIMIZED_QUIESCENT_SHARD, plan)
    ]
    if optimized_commands != expected_optimized_isolated:
        sys.exit(
            "the optimized private-lib shard must run its timing contracts "
            "once each, in their declared module-qualified name order"
        )
    # Build this contract directly from the manifest, not the command helpers
    # being checked: a generator defect must not change both sides of the audit.
    buckets = assign(plan, targets)
    split_targets = {group["target"] for group in plan.get("integration_groups", [])}
    expected_split = Counter()
    for shard, names in buckets.items():
        for target in sorted(split_targets.intersection(names)):
            skips = [arg for group in plan["integration_groups"] if group["target"] == target
                     for name in group["tests"] for arg in ("--skip", name)]
            command = SELECTION + ["--test", target, "--", *HARNESS, "--exact", *skips]
            expected_split[shard, tuple(command)] += 1
    for group in plan.get("integration_groups", []):
        command = SELECTION + [
            "--test", group["target"], "--", *HARNESS, "--exact", *group["tests"],
        ]
        expected_split[group["shard"], tuple(command)] += 1
    actual_split = Counter()
    metadata = cargo_test_selection.workspace_metadata(ROOT)
    for shard in shard_ids(plan):
        actual = commands(plan, shard, targets)
        try:
            library_commands = [
                command for index, command in enumerate(actual)
                if cargo_test_selection.resolve(command, metadata).has_library()
                and (shard, index) != ("misc", ordinary_index)
            ]
        except ValueError as error:
            sys.exit(f"{shard} has an unsupported test selection: {error}")
        expected = (serial if shard == "misc" else []) + extra_lib_commands(plan, shard)
        if library_commands != expected:
            sys.exit(f"{shard} must run every assigned library group exactly once")
        for command in actual:
            cargo = command[:command.index("--")] if "--" in command else command
            if any(option == "--test" and target in split_targets
                   for option, target in zip(cargo, cargo[1:])):
                actual_split[shard, tuple(command)] += 1
    if actual_split != expected_split:
        sys.exit("split integration targets must run each exact remainder and named group once on its assigned shard")
    for index, group in enumerate(plan["heavy"]["shards"]):
        if not group:
            # `--exact` with no names disables filtering, so an empty group
            # would silently re-run the entire heavy target.
            sys.exit(f"heavy-{index} names no tests; remove the group instead")

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
        if owner_commands[1 : 1 + len(expected_isolated)] != expected_isolated:
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
    print(
        "shard commands ok: "
        f"misc issues {len(misc)} invocations; "
        f"{OPTIMIZED_QUIESCENT_SHARD} issues {len(optimized_commands)}"
    )


def verify_lib_plan(plan: dict) -> None:
    """Keep exact library filters disjoint and timing profiles unchanged."""
    if len(SERIAL_LIB_TESTS) != len(set(SERIAL_LIB_TESTS)):
        sys.exit("serial library tests are duplicated")
    group_shards = set(shard_ids(plan)) - {"misc", OPTIMIZED_QUIESCENT_SHARD}
    ordinary_shards = group_shards - set(native_log_bound.CORE_SHARDS)
    overrides = plan.get("quiescent_lib_shards", {})
    for name, shard in overrides.items():
        if name not in QUIESCENT_LIB_TESTS or name in OPTIMIZED_QUIESCENT_LIB_TESTS:
            sys.exit(f"invalid ordinary timing-contract override: {name!r}")
        if shard not in ordinary_shards:
            sys.exit(f"invalid ordinary timing-contract shard: {shard!r}")
    claimed = {qualified_quiescent_lib_test(name) for name in QUIESCENT_LIB_TESTS}
    if claimed & set(SERIAL_LIB_TESTS):
        sys.exit("serial library test also belongs to an isolated timing contract")
    claimed.update(SERIAL_LIB_TESTS)
    rust_path = re.compile(r"[A-Za-z_][A-Za-z_0-9]*(?:::[A-Za-z_][A-Za-z_0-9]*)*")
    for group in plan.get("lib_groups", []):
        if group["shard"] not in group_shards:
            sys.exit(f"invalid library-group shard: {group['shard']!r}")
        if not group["tests"]:
            sys.exit("library groups must name at least one test")
        if not rust_path.fullmatch(group["module"]) or any(
            not rust_path.fullmatch(name) for name in group["tests"]
        ):
            sys.exit("library groups require module-qualified Rust test names")
        names = lib_group_names(group)
        children = group.get("child_parents", {})
        if not isinstance(children, dict) or any(
            child not in group["tests"] or parent not in group["tests"] or parent in children
            for child, parent in children.items()
        ):
            sys.exit("subprocess children require enabled parents in the same library group")
        if any(name in native_log_bound.TESTS for name in names):
            if len(names) != 1 or group["shard"] != native_log_bound.CORE_SHARDS[native_log_bound.TESTS.index(names[0])]:
                sys.exit("full native log proofs must each own one dedicated parallel shard")
        elif group["shard"] in native_log_bound.CORE_SHARDS:
            sys.exit("dedicated native log proof shards cannot carry ordinary tests")
        for name in lib_group_names(group):
            if name in claimed:
                sys.exit(f"library test is claimed more than once: {name!r}")
            claimed.add(name)
    if not set(native_log_bound.TESTS).issubset(claimed):
        sys.exit("full native log proofs are missing from the heavy library groups")


def verify(plan: dict, targets: list[str]) -> None:
    """Verify target ownership and the exact command partition."""
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
        total += float(plan.get("fixed_weights", {}).get(shard, 0))
        total += sum(float(group["weight"]) for group in plan.get("integration_groups", [])
                     if group["shard"] == shard)
        print(f"  {shard}: {len(buckets[shard]):3d} target remainders, ~{total:.0f}s including fixed work")


def list_heavy_tests(plan: dict, extra: list[str]) -> list[str]:
    """Ask the built heavy binary which tests a given filter selects."""
    command = (
        SELECTION
        + ["--test", plan["heavy"]["target"], "--", "--list"]
        + extra
    )
    out = subprocess.run(
        command, cwd=ROOT, text=True, stdout=subprocess.PIPE, check=True
    ).stdout
    return [
        line.rsplit(":", 1)[0]
        for line in out.splitlines()
        if line.endswith(": test")
    ]


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
    command = quiescent_lib_list_command(name)
    out = subprocess.run(
        command, cwd=ROOT, text=True, stdout=subprocess.PIPE, check=True
    ).stdout
    return [
        line.rsplit(":", 1)[0]
        for line in out.splitlines()
        if line.endswith(": test")
    ]


def verify_serial_lib_tests() -> None:
    """A renamed, ignored or ambiguous filter must never pass as a no-op."""
    for name in SERIAL_LIB_TESTS:
        inventories = []
        for flags in ([], ["--ignored"]):
            output = subprocess.run(
                serial_lib_command(name) + ["--list", *flags],
                cwd=ROOT, text=True, stdout=subprocess.PIPE, check=True,
            ).stdout
            inventories.append([
                line.rsplit(":", 1)[0] for line in output.splitlines()
                if line.endswith(": test")
            ])
        selected, ignored = inventories
        if selected != [name]:
            sys.exit(f"serial library test must resolve exactly once: {name!r}, got {selected!r}")
        if ignored:
            sys.exit(f"serial library test must not be ignored: {name!r}")
    print(f"serial library tests resolve exactly once and remain enabled: {len(SERIAL_LIB_TESTS)}")


def precheck(plan: dict, shard: str, *, split_libraries: bool = False) -> None:
    """Fail a heavy shard whose named tests no longer resolve.

    libtest exits 0 when a filter matches nothing, so a renamed test would
    otherwise turn a heavy shard into a green no-op. Coverage would survive
    (``misc`` stops skipping the old name and runs the test, and verify-heavy
    fails), but the lane would burn a runner proving nothing, and a reviewer
    reading a green matrix would have no signal. Resolve the names first.
    """
    # Every shard re-checks the plan itself: rust-tests legs start alongside
    # rust-gates rather than after it, so without this a broken plan would
    # burn the entire runner matrix before the gates job reported it.
    targets = integration_targets()
    verify(plan, targets)
    if shard == "misc":
        # Run before the suite: a stale exclusion must fail even if another
        # required test would stop the shard before its final partition audit.
        verify_heavy(plan)
        if not split_libraries:
            verify_serial_lib_tests()
    groups = [group for group in plan.get("lib_groups", []) if group["shard"] == shard]
    if groups:
        # Resolve each profile independently. Keep multisets: a duplicate
        # full name in another library must not hide behind a set.
        by_profile: dict[tuple[str, ...], list[str]] = {}
        for group in groups:
            command = lib_group_command(group)
            prefix = tuple(command[:command.index("--")])
            by_profile.setdefault(prefix, []).extend(lib_group_names(group))
        for prefix, names in by_profile.items():
            command = [*prefix, "--", "--list", "--exact", *names]
            profile = next((f"O{arg.split('=', 1)[1]}" for arg in prefix
                            if arg.startswith("CARGO_PROFILE_TEST_OPT_LEVEL=")), "ordinary")
            print(f"{shard}: compile/list {len(names)} library test(s) with {profile} profile", flush=True)
            output = subprocess.run(
                command, cwd=ROOT, text=True, stdout=subprocess.PIPE, check=True
            ).stdout
            selected = Counter(
                line.rsplit(":", 1)[0]
                for line in output.splitlines()
                if line.endswith(": test")
            )
            if selected != Counter(names):
                sys.exit(
                    f"{shard} library groups do not resolve exactly once: "
                    f"missing {dict(Counter(names) - selected)}, "
                    f"unexpected {dict(selected - Counter(names))}"
                )
            if any(name in native_log_bound.TESTS for name in names):
                output = subprocess.run(
                    [*command, "--ignored"], cwd=ROOT, text=True,
                    stdout=subprocess.PIPE, check=True
                ).stdout
                if any(line.endswith(": test") for line in output.splitlines()):
                    sys.exit("full native log proofs must remain enabled in their execution profile")
        print(f"{shard} library groups resolve exactly once: {sum(map(len, by_profile.values()))} tests")
    isolated_lib_tests = () if shard == "misc" and split_libraries else quiescent_lib_tests_for_shard(shard, plan)
    if isolated_lib_tests:
        for name in isolated_lib_tests:
            qualified = qualified_quiescent_lib_test(name)
            selected = list_quiescent_lib_test(name)
            if selected != [qualified]:
                sys.exit(
                    f"{shard} private-lib timing contract does not resolve "
                    f"exactly once: expected {qualified!r}, selected {selected!r}"
                )
        print(
            f"{shard} private-lib timing contracts resolve exactly once: "
            f"{len(isolated_lib_tests)}"
        )
    buckets = assign(plan, targets)
    if shard in buckets:
        grouped = {
            group["target"] for group in plan.get("integration_groups", [])
            if group["shard"] == shard or group["target"] in buckets[shard]
        }
        for target in sorted(grouped):
            verify_grouped_integration(plan, target)
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
    if Counter(selected) != Counter(group):
        missing = sorted(set(group) - set(selected))
        sys.exit(
            f"{shard} names tests that no longer exist: {missing}. They were "
            f"renamed or removed; update ci/test-shards.json."
        )
    print(f"{shard} precheck ok: {len(group)} tests resolve")


def verify_heavy(plan: dict) -> None:
    """Prove the heavy target's own tests partition exactly.

    Required shards and the separate qualification job are disjoint and
    together cover every test, including future tests outside the manifest.
    """
    groups = plan["heavy"]["shards"]
    named = [name for group in groups for name in group]
    # Mirrors the real misc invocation exactly, --exact included: verifying a
    # different filter than the one that runs would prove nothing.
    qualification = qualification_names(plan)
    skips = ["--exact"] + [
        arg for name in [*named, *qualification] for arg in ("--skip", name)
    ]

    inventory = list_heavy_tests(plan, [])
    if len(inventory) != len(set(inventory)):
        sys.exit("heavy target contains ambiguous test names")
    everything = set(inventory)
    remainder = set(list_heavy_tests(plan, skips))
    qualified = set()
    if qualification:
        selected = list_heavy_tests(plan, ["--exact", *qualification])
        if Counter(selected) != Counter(qualification):
            sys.exit("qualification manifest contains stale or ambiguous test names")
        if list_heavy_tests(plan, ["--ignored", "--exact", *qualification]):
            sys.exit("qualification manifest contains ignored tests; retain executable coverage")
        qualified = set(selected)
    claimed: set[str] = set()
    for index, group in enumerate(groups):
        listed = list_heavy_tests(plan, ["--exact", *group])
        selected = set(listed)
        if Counter(listed) != Counter(group):
            sys.exit(
                f"heavy-{index} selects {sorted(selected)} but the plan names "
                f"{sorted(group)}; a test was renamed or removed"
            )
        if claimed & selected:
            sys.exit(f"heavy-{index} overlaps an earlier shard")
        claimed |= selected

    if qualified & (remainder | claimed):
        sys.exit("qualification tests also run in a required shard")
    if remainder & claimed:
        sys.exit(f"'misc' also runs {sorted(remainder & claimed)}")
    if remainder | claimed | qualified != everything:
        lost = everything - (remainder | claimed | qualified)
        sys.exit(f"tests in the heavy target run on no shard: {sorted(lost)}")

    print(
        f"heavy partition ok: {len(everything)} tests = {len(remainder)} on "
        f"'misc' + {len(claimed)} across {len(groups)} heavy shards "
        f"+ {len(qualified)} real-time qualification tests"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("ids")
    plan_cmd = sub.add_parser("plan")
    plan_cmd.add_argument("--shard", required=True)
    plan_cmd.add_argument("--split-libraries", action="store_true")
    sub.add_parser("verify")
    sub.add_parser("verify-heavy")
    precheck_cmd = sub.add_parser("precheck")
    precheck_cmd.add_argument("--shard", required=True)
    precheck_cmd.add_argument("--split-libraries", action="store_true")
    libraries = sub.add_parser("run-libraries")
    libraries.add_argument("--shard", type=int, choices=library_partition.SHARDS, required=True)
    libraries.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    plan = load_plan()

    if args.command == "ids":
        print("\n".join(shard_ids(plan)))
        return

    if args.command == "verify-heavy":
        verify_heavy(plan)
        return

    if args.command == "precheck":
        precheck(plan, args.shard, split_libraries=args.split_libraries)
        return

    if args.command == "run-libraries":
        run_libraries(plan, args.shard, args.output)
        return

    targets = integration_targets()

    if args.command == "verify":
        verify(plan, targets)
        return

    selected_commands = hosted_commands if args.split_libraries else commands
    for command in selected_commands(plan, args.shard, targets):
        print(shlex.join(command))


if __name__ == "__main__":
    main()
