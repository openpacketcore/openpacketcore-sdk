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


def cargo_metadata() -> dict:
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(out.stdout)


def main() -> int:
    check_only = "--check" in sys.argv[1:]
    names_only = "--names" in sys.argv[1:]
    meta = cargo_metadata()

    packages = {p["name"]: p for p in meta["packages"]}
    publishable = {
        name for name, p in packages.items() if p.get("publish") is None
    }

    errors: list[str] = []

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
