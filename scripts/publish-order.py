#!/usr/bin/env python3
"""Compute the crates.io publish order for the OpenPacketCore workspace.

Publishable crates (those without `publish = false`) must be published in
topological order of their intra-workspace dependencies, because cargo
verifies each crate's dependencies against the registry at publish time.

Usage:
    scripts/publish-order.py            # print `cargo publish -p <crate>` order
    scripts/publish-order.py --names    # print bare crate names, one per line
                                        # (for scripting publish loops)
    scripts/publish-order.py --check    # validate graph only (CI mode):
                                        #   - dependency graph is acyclic
                                        #   - every intra-workspace [dependencies]
                                        #     path dep carries a version key
Exit code is non-zero on any validation failure.
"""

import json
import subprocess
import sys
from collections import deque
from pathlib import Path


OPENRAFT_GIT_SOURCE = (
    "git+https://github.com/openpacketcore/openraft"
    "?rev=f607e636406b16bd0ad7925dbb631da1b7a4cd96"
)
FROZEN_SESSION_HA_V2_SOURCE_BUILD_ONLY = {
    "opc-alarm",
    "opc-alarm-k8s",
    "opc-alarm-testkit",
    "opc-alarm-yang",
    "opc-amf-lite",
    "opc-amf-lite-testkit",
    "opc-config-bus",
    "opc-consensus",
    "opc-gnmi-server",
    "opc-ipsec-lb",
    "opc-mgmt-authz",
    "opc-mgmt-transport",
    "opc-netconf-server",
    "opc-persist",
    "opc-runtime",
    "opc-sa-mirror",
    "opc-sbi",
    "opc-sdk",
    "opc-sdk-integration",
    "opc-session-cache",
    "opc-session-net",
    "opc-session-store",
    "opc-session-testkit",
    "operator-controller",
    "operator-lifecycle",
    "operator-lifecycle-cli",
}
POST_V2_SOURCE_BUILD_ONLY_ADDITIONS = {"opc-config-bus-consensus"}
SOURCE_BUILD_ONLY = (
    FROZEN_SESSION_HA_V2_SOURCE_BUILD_ONLY | POST_V2_SOURCE_BUILD_ONLY_ADDITIONS
)
SOURCE_BUILD_REMOVAL_CONDITION = (
    "official stable Openraft release containing the fix, registry pin and "
    "checksum, and full issue #143 requalification"
)


def cargo_metadata() -> dict:
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(out.stdout)


def main() -> int:
    check_only = "--check" in sys.argv[1:]
    names_only = "--names" in sys.argv[1:]
    meta = cargo_metadata()

    workspace_members = set(meta["workspace_members"])
    packages = {
        package["name"]: package
        for package in meta["packages"]
        if package["id"] in workspace_members
    }
    publishable = {
        name for name, p in packages.items() if p.get("publish") is None
    }

    errors: list[str] = []

    consensus_dependencies = {
        dependency["name"]: dependency
        for dependency in packages["opc-consensus"]["dependencies"]
    }
    openraft = consensus_dependencies.get("openraft")
    if (
        openraft is None
        or openraft.get("source") != OPENRAFT_GIT_SOURCE
        or openraft.get("req") != "=0.9.24"
    ):
        errors.append(
            "opc-consensus: Openraft is not pinned to the approved version and full git rev"
        )
    resolved_fork_source = (
        f"{OPENRAFT_GIT_SOURCE}#f607e636406b16bd0ad7925dbb631da1b7a4cd96"
    )
    fork_packages = {
        (package["name"], package["version"])
        for package in meta["packages"]
        if package.get("source") == resolved_fork_source
    }
    if fork_packages != {("openraft", "0.9.24"), ("openraft-macros", "0.9.24")}:
        errors.append("resolved Openraft fork package set/version/source is not exact")

    computed_source_closure = {"opc-consensus", "opc-persist", "opc-session-store"}
    changed = True
    while changed:
        changed = False
        for name, package in packages.items():
            if name in computed_source_closure:
                continue
            if any(
                dependency["kind"] is None
                and dependency["name"] in computed_source_closure
                for dependency in package["dependencies"]
            ):
                computed_source_closure.add(name)
                changed = True
    if computed_source_closure != SOURCE_BUILD_ONLY:
        errors.append("Openraft source-build normal reverse-dependency closure drifted")

    for name in sorted(SOURCE_BUILD_ONLY):
        if packages.get(name, {}).get("publish") != []:
            errors.append(f"{name}: must remain publish=false while the Openraft fork is pinned")

    profile_path = Path("crates/opc-session-testkit/qualification/v2/session-ha-profile.json")
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    source_gate = profile.get("source_build_gate", {})
    if (
        set(source_gate.get("affected_workspace_crates", []))
        != FROZEN_SESSION_HA_V2_SOURCE_BUILD_ONLY
    ):
        errors.append("frozen v2 session HA profile source-build crate closure drifted")
    if source_gate.get("openraft_rev") != OPENRAFT_GIT_SOURCE.rsplit("=", 1)[-1]:
        errors.append("session HA profile Openraft revision is not exact")
    if source_gate.get("removal_condition") != SOURCE_BUILD_REMOVAL_CONDITION:
        errors.append("session HA profile source-build removal condition drifted")
    if source_gate.get("crates_io_check_date") != "2026-07-13":
        errors.append("session HA profile crates.io check date drifted")
    if source_gate.get("crates_io_exact_matches") != []:
        errors.append("session HA profile must not claim an exact crates.io match")
    profiled_publish = {
        artifact.get("crate_name"): artifact.get("publish")
        for artifact in profile.get("artifacts", [])
    }
    for name in ["openraft", "opc-consensus", "opc-persist", "opc-session-store"]:
        if profiled_publish.get(name) is not False:
            errors.append(f"session HA profile: {name} must remain source-build only")

    # Build the intra-workspace dependency graph over publishable crates,
    # and validate version keys on normal (non-dev) path dependencies.
    deps: dict[str, set[str]] = {name: set() for name in publishable}
    for name in publishable:
        for dep in packages[name]["dependencies"]:
            if dep["name"] not in packages:
                continue  # external crate
            if dep["kind"] == "dev":
                # dev-dependencies are stripped on publish; version keys
                # are not required there.
                continue
            if dep.get("path") and dep.get("req") in (None, "*"):
                errors.append(
                    f"{name}: path dependency on {dep['name']} has no version key"
                )
            if dep["name"] in publishable:
                deps[name].add(dep["name"])
            elif dep["kind"] is None:
                errors.append(
                    f"{name} (publishable) depends on non-publishable {dep['name']}"
                )
            if dep["kind"] is None and dep["name"] in SOURCE_BUILD_ONLY:
                errors.append(
                    f"{name} (publishable) depends on source-build-only {dep['name']}"
                )

    # Kahn's algorithm for a deterministic topological order.
    indegree = {name: 0 for name in publishable}
    for name in publishable:
        for _ in deps[name]:
            indegree[name] += 1
    ready = deque(sorted(n for n, d in indegree.items() if d == 0))
    order: list[str] = []
    dependents: dict[str, set[str]] = {n: set() for n in publishable}
    for name in publishable:
        for d in deps[name]:
            dependents[d].add(name)
    while ready:
        n = ready.popleft()
        order.append(n)
        for m in sorted(dependents[n]):
            indegree[m] -= 1
            if indegree[m] == 0:
                ready.append(m)

    if len(order) != len(publishable):
        cyclic = sorted(set(publishable) - set(order))
        errors.append(f"dependency cycle involving: {', '.join(cyclic)}")

    if errors:
        for e in dict.fromkeys(errors):  # dedup, preserve order
            print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if check_only:
        print(f"OK: {len(order)} publishable crates, graph acyclic, version keys present")
        return 0

    if names_only:
        for name in order:
            print(name)
        return 0

    print("# Publish in this order (each must be live on crates.io before the next):")
    for name in order:
        print(f"cargo publish -p {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
