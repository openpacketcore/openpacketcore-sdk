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

# A partition that collapses to a handful of targets would still be "total and
# disjoint" if metadata were misread, so hold a floor on the real inventory
# (249 today).
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
        return [
            SELECTION + ["--lib", "--bins", "--", *HARNESS],
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
    return [SELECTION + selected + ["--", *HARNESS]]


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
    misc = [" ".join(command) for command in commands(plan, "misc", targets)]
    required = {
        "unit tests": " --lib --bins ",
        "example compile check": "cargo build ",
        "doctests": " --doc ",
        "heavy remainder": f" --test {plan['heavy']['target']} ",
    }
    for label, fragment in required.items():
        if not any(fragment in f"{command} " for command in misc):
            sys.exit(f"the misc shard no longer runs {label}")
    for index, group in enumerate(plan["heavy"]["shards"]):
        if not group:
            # `--exact` with no names disables filtering, so an empty group
            # would silently re-run the entire heavy target.
            sys.exit(f"heavy-{index} names no tests; remove the group instead")
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
    verify(plan, integration_targets())
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
