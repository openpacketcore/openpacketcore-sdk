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
single-job run provided.

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
SELECTION = [
    "cargo",
    "test",
    "--locked",
    "--workspace",
    "--exclude",
    "opc-persist",
    "--all-features",
    "--quiet",
]
HARNESS = ["--test-threads=4"]

# A partition that collapses to a handful of targets would still be "total and
# disjoint" if metadata were misread, so hold a floor on the real inventory.
MIN_INTEGRATION_TARGETS = 200


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
            if "test" in target["kind"]:
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


def commands(plan: dict, shard: str, targets: list[str]) -> list[list[str]]:
    """The cargo invocations for one shard."""
    heavy = plan["heavy"]
    named = [name for group in heavy["shards"] for name in group]

    if shard == "misc":
        # Unit tests, binary tests, doctests, plus every test in the heavy
        # target that is not claimed by a heavy-N shard. The --skip list is
        # what makes the heavy target's partition total: a test added to that
        # file lands here without anyone updating this plan.
        # --examples keeps the compile check the unfiltered `cargo test` did:
        # it built every example even though none is a test.
        skips = [arg for name in named for arg in ("--skip", name)]
        return [
            SELECTION + ["--lib", "--bins", "--examples", "--", *HARNESS],
            SELECTION + ["--doc", "--", *HARNESS],
            SELECTION
            + ["--test", heavy["target"], "--", *HARNESS, *skips],
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
    return [SELECTION + selected + ["--", *HARNESS]]


def verify_workflow_matrix(plan: dict) -> None:
    """Fail if the workflow's shard matrix drifted from this plan.

    Without this, adding a shard here and forgetting the matrix (or the
    reverse) silently stops running a slice of the suite.
    """
    workflow = ROOT / ".github" / "workflows" / "ci.yml"
    match = re.search(r"^\s*shard:\s*\[([^\]]*)\]", workflow.read_text(), re.M)
    if not match:
        sys.exit(f"no `shard: [...]` matrix found in {workflow}")
    declared = [item.strip() for item in match.group(1).split(",") if item.strip()]
    expected = shard_ids(plan)
    if declared != expected:
        sys.exit(
            f"{workflow.name} runs shards {declared} but the plan defines "
            f"{expected}"
        )
    print(f"workflow matrix ok: {len(expected)} shards")


def verify(plan: dict, targets: list[str]) -> None:
    """Prove every target runs exactly once across the shard set."""
    verify_workflow_matrix(plan)
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


def verify_heavy(plan: dict) -> None:
    """Prove the heavy target's own tests partition exactly.

    Runs on the shard that already built the binary, so this costs three
    ``--list`` invocations and nothing else.
    """
    groups = plan["heavy"]["shards"]
    named = [name for group in groups for name in group]
    skips = [arg for name in named for arg in ("--skip", name)]

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
    args = parser.parse_args()

    plan = load_plan()

    if args.command == "ids":
        print("\n".join(shard_ids(plan)))
        return

    if args.command == "verify-heavy":
        verify_heavy(plan)
        return

    targets = integration_targets()

    if args.command == "verify":
        verify(plan, targets)
        return

    for command in commands(plan, args.shard, targets):
        print(shlex.join(command))


if __name__ == "__main__":
    main()
