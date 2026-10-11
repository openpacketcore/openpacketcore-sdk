#!/usr/bin/env python3
"""Decide whether egress-fence qualification is needed; uncertainty means run.

Run with Python 3.11+ and -I. Cargo tree selects the actual packages/features
for each qualification profile; metadata supplies opaque source identities and
path manifests. Workspace-wide metadata alone unifies unrelated features.
Snapshots are temporary git archives, not worktrees or compilation caches.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass
import fnmatch
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import tomllib


# Root selections mirror the fence's host gates, installer and object oracles.
# Only roots are listed: Cargo derives every transitive/build/dev dependency.
HOST_PACKAGES = (
    "opc-egress-fence", "opc-egress-fence-common", "opc-linux-gtpu-sys",
    "opc-linux-xfrm-sys", "opc-runtime", "opc-session-store",
)
HOST = "x86_64-unknown-linux-gnu"
BPF = "bpfel-unknown-none"
EBPF_MANIFEST = "crates/opc-egress-fence-ebpf/Cargo.toml"
PROFILES = (
    ("host-gates", "Cargo.toml", HOST_PACKAGES, ("--all-features",), HOST),
    # Isolated store proofs must not inherit feature unification from other roots.
    ("isolated-store", "Cargo.toml", ("opc-session-store",), ("--all-features",), HOST),
    ("installer", "Cargo.toml", ("opc-egress-fence",), (), HOST),
    ("ebpf-production", EBPF_MANIFEST, ("opc-egress-fence-ebpf",), (), BPF),
    ("ebpf-delete", EBPF_MANIFEST, ("opc-egress-fence-ebpf",),
     ("--features", "fault-inject-delete"), BPF),
    ("ebpf-deadline", EBPF_MANIFEST, ("opc-egress-fence-ebpf",),
     ("--features", "mutation-bypass-deadline"), BPF),
    ("ebpf-gate", EBPF_MANIFEST, ("opc-egress-fence-ebpf",),
     ("--no-default-features", "--features", "mutation-bypass-gate"), BPF),
    ("oracle", EBPF_MANIFEST, ("opc-egress-fence-object-oracle",), (), HOST),
)

# Preserve the workflow's fence-owned paths and non-crate qualification inputs.
# The qualification_profile fixture is an explicit extra, not a root that
# expands this fence-specific trigger to all session-testkit consumers.
# Main CI runs the test targets that read inputs outside these crates on every
# PR (shards it-1 and it-2), covering those inputs when this job is skipped.
EXPLICIT_PATHS = (
    "crates/opc-egress-fence/**",
    "crates/opc-egress-fence-common/**",
    "crates/opc-egress-fence-ebpf/**",
    "crates/opc-session-testkit/qualification/v6/session-ha-profile.json",
    "crates/opc-session-testkit/qualification/v6/session-ha-profile.schema.json",
    "crates/opc-session-testkit/tests/qualification_profile.rs",
    "scripts/build-egress-fence-ebpf.sh",
    "scripts/publish-order.py",
    "ci/setup-fsverity-tmp.sh",
    "ci/egress-fence-changes.py",
    "ci/test-egress-fence-changes.py",
    "ci/egress-fence-tests.py",
    "ci/test-egress-fence-tests.py",
    "ci/egress-fence-tools.sh",
    "ci/egress-fence-kernel.sh",
    "ci/egress-fence-cleanup.sh",
    ".github/workflows/egress-fence.yml",
    ".cargo/config", ".cargo/config.toml", "rust-toolchain", "rust-toolchain.toml",
    # The eBPF steps run Cargo from crates/opc-egress-fence-ebpf, and Cargo
    # reads configuration from every ancestor of its working directory.
    "crates/.cargo/config", "crates/.cargo/config.toml",
    # rustfmt and Clippy read configuration from each source or manifest
    # directory upwards. The pinned-nightly eBPF fmt step (cargo fmt --all)
    # also formats every root-workspace member reached through path
    # dependencies, and stable rustfmt ignores nightly-only options, so a
    # formatter or lint configuration anywhere can change a fence-only gate.
    "rustfmt.toml", ".rustfmt.toml", "*/rustfmt.toml", "*/.rustfmt.toml",
    "clippy.toml", ".clippy.toml", "*/clippy.toml", "*/.clippy.toml",
)


def command(repo: Path, *args: str) -> str:
    return subprocess.run(args, cwd=repo, check=True, text=True,
                          capture_output=True, timeout=120).stdout


def commit(repo: Path, revision: str) -> str:
    if not revision or set(revision) == {"0"}:
        raise ValueError("unknown revision")
    return command(repo, "git", "rev-parse", "--verify", "--end-of-options",
                   revision + "^{commit}").strip()


def comparison_base(repo: Path, event: str, base: str, head: str) -> str:
    before, after = commit(repo, base), commit(repo, head)
    if event == "pull_request":
        return command(repo, "git", "merge-base", before, after).strip()
    return before


def project_tree(metadata: dict, tree: str, selected_roots: tuple[str, ...]) -> dict:
    """Project Cargo's selected tree onto its machine-readable package catalog.

    The explicit tree format contains depth, package display and features.
    Ambiguous name/version pairs or a changed output format cannot justify skip.
    Source IDs themselves remain opaque; they are read only from metadata.
    """
    catalog = defaultdict(list)
    for package in metadata["packages"]:
        catalog[(package["name"], package["version"])].append(package)
    nodes, roots, stack = {}, [], []
    root_names = set()
    for line in tree.splitlines():
        if not line:
            continue
        match = re.fullmatch(r"(\d+)([^ |]+) v([^ |]+)(?: [^|]*)?\|(.*)", line)
        if match is None:
            raise ValueError("unrecognized Cargo tree output")
        depth, name, version, features = match.groups()
        depth = int(depth)
        candidates = catalog[(name, version)]
        if len(candidates) != 1 or depth > len(stack):
            raise ValueError("incomplete or ambiguous Cargo tree")
        package_id = candidates[0]["id"]
        node = nodes.setdefault(package_id, {"features": set(), "dependencies": set()})
        features = features.removesuffix(" (*)").strip()
        # One entry per build context: a package built both for the target
        # and for build scripts/proc-macros can differ in features, and a
        # union would hide a feature moving into the context that lacked it.
        node["features"].add(",".join(sorted(filter(None, features.split(",")))))
        if depth == 0:
            roots.append(package_id)
            root_names.add(name)
        else:
            nodes[stack[depth - 1]]["dependencies"].add(package_id)
        stack[depth:] = [package_id]
    if root_names != set(selected_roots):
        raise ValueError("Cargo tree did not resolve the requested roots")
    return {
        "metadata": {
            "packages": metadata["packages"],
            "resolve": {"nodes": [
                {"id": key, "features": sorted(value["features"]),
                 "dependencies": sorted(value["dependencies"])}
                for key, value in nodes.items()
            ]},
        },
        "roots": roots,
    }


def closure(profile: dict, repository_root: str) -> tuple[dict, set[str]]:
    metadata = profile["metadata"]
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    if len(packages) != len(metadata["packages"]) or len(nodes) != len(metadata["resolve"]["nodes"]):
        raise ValueError("duplicate Cargo package IDs")
    pending = list(profile["roots"])
    if not pending:
        raise ValueError("empty dependency roots")
    result, directories, visited = {}, set(), set()
    root = Path(repository_root).resolve()
    while pending:
        package_id = pending.pop()
        if package_id in visited:
            continue
        visited.add(package_id)
        package, node = packages[package_id], nodes[package_id]
        source = package["source"]
        if source is None:
            relative = Path(package["manifest_path"]).resolve().parent.relative_to(root).as_posix()
            directories.add(relative)
            source = "path:" + relative
        identity = (package["name"], package["version"], source)
        features = node["features"]
        if not isinstance(features, list) or not all(isinstance(item, str) for item in features):
            raise ValueError("missing resolved features")
        result[identity] = (tuple(sorted(features)), package.get("edition"), package.get("rust_version"))
        pending.extend(node["dependencies"])
    return result, directories


@dataclass(frozen=True)
class Decision:
    run: bool
    reason: str


def decide(base: dict, head: dict, changed_paths: list[str]) -> Decision:
    for path in changed_paths:
        if any(fnmatch.fnmatchcase(path, pattern) for pattern in EXPLICIT_PATHS):
            return Decision(True, "explicit qualification input: " + path)
    try:
        before_profiles, after_profiles = base["profiles"], head["profiles"]
        if not before_profiles or before_profiles.keys() != after_profiles.keys():
            raise ValueError("missing qualification profiles")
        if base["settings"] != head["settings"]:
            return Decision(True, "shared Cargo build settings changed")
        directories = set()
        for name in before_profiles:
            before, old_paths = closure(before_profiles[name], base["repository_root"])
            after, new_paths = closure(after_profiles[name], head["repository_root"])
            if before != after:
                return Decision(True, "resolved dependency closure changed: " + name)
            directories.update(old_paths | new_paths)
        for path in changed_paths:
            if any(directory == "." or path.startswith(directory + "/") for directory in directories):
                return Decision(True, "path dependency changed: " + path)
    except (KeyError, TypeError, ValueError) as error:
        return Decision(True, "incomplete metadata: " + str(error))
    return Decision(False, "fence inputs and resolved dependency closures are unchanged")


def shared_settings(repo: Path) -> dict:
    """Resolution covers dependency tables; retain global compiler/lint inputs."""
    with (repo / "Cargo.toml").open("rb") as stream:
        settings = tomllib.load(stream)
    workspace = dict(settings.get("workspace", {}))
    for key in ("dependencies", "members", "default-members", "exclude"):
        workspace.pop(key, None)
    settings["workspace"] = workspace
    # Used patches/replacements appear in the resolved source IDs. An unused
    # patch elsewhere in the workspace must not force a fence run.
    settings.pop("patch", None)
    settings.pop("replace", None)
    return settings


def snapshot(repo: Path) -> dict:
    catalogs, profiles = {}, {}
    for name, manifest, packages, features, target in PROFILES:
        if manifest not in catalogs:
            catalogs[manifest] = json.loads(command(
                repo, "cargo", "metadata", "--locked", "--format-version", "1",
                "--all-features", "--manifest-path", str(repo / manifest),
            ))
        selection = [argument for package in packages for argument in ("--package", package)]
        tree = command(repo, "cargo", "tree", "--locked", "--manifest-path", str(repo / manifest),
                       *selection, *features, "--target", target, "--edges", "normal,build,dev",
                       "--prefix", "depth", "--format", "{p}|{f}", "--color", "never")
        profiles[name] = project_tree(catalogs[manifest], tree, packages)
    return {"repository_root": str(repo), "profiles": profiles, "settings": shared_settings(repo)}


def archive(repo: Path, revision: str, destination: Path) -> None:
    destination.mkdir()
    path = destination.with_suffix(".tar")
    command(repo, "git", "archive", "--format=tar", "--output=" + str(path), revision)
    with tarfile.open(path) as stream:
        stream.extractall(destination, filter="data")


def run(repo: Path, event: str, base: str, head: str) -> tuple[Decision, str, str]:
    if event in ("schedule", "workflow_dispatch"):
        return Decision(True, "scheduled or manual full qualification"), base, head
    if event not in ("pull_request", "push"):
        return Decision(True, "unknown event; full qualification required"), base, head
    try:
        base = comparison_base(repo, event, base, head)
        head = commit(repo, head)
        paths = command(repo, "git", "diff", "--name-only", "--no-renames", "-z", base, head, "--")
        changed = [path for path in paths.split("\0") if path]
        if any(fnmatch.fnmatchcase(path, pattern) for path in changed for pattern in EXPLICIT_PATHS):
            return decide({}, {}, changed), base, head
        with tempfile.TemporaryDirectory(prefix="egress-fence-changes-") as temporary:
            before, after = Path(temporary) / "base", Path(temporary) / "head"
            archive(repo, base, before)
            archive(repo, head, after)
            decision = decide(snapshot(before), snapshot(after), changed)
        return decision, base, head
    except Exception as error:  # No resolution or process failure may justify skipping qualification.
        return Decision(True, "unable to resolve inputs: " + type(error).__name__ + ": " + str(error)[:300]), base, head


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--event", default=os.environ.get("GITHUB_EVENT_NAME", "push"))
    parser.add_argument("--base")
    parser.add_argument("--head")
    args = parser.parse_args()
    base, head = args.base or "", args.head or ""
    try:
        if args.event not in ("schedule", "workflow_dispatch") and not (base and head):
            with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as stream:
                event = json.load(stream)
            if args.event == "pull_request":
                base = base or event["pull_request"]["base"]["sha"]
                head = head or event["pull_request"]["head"]["sha"]
            else:
                base = base or event["before"]
                head = head or event["after"]
        decision, base, head = run(args.repo.resolve(), args.event, base, head)
    except Exception as error:
        decision = Decision(True, "unavailable event data: " + type(error).__name__)
    print(json.dumps({"run": decision.run, "reason": decision.reason, "base": base, "head": head}, sort_keys=True))
    if output := os.environ.get("GITHUB_OUTPUT"):
        with open(output, "a", encoding="utf-8") as stream:
            stream.write(f"run={str(decision.run).lower()}\n")


if __name__ == "__main__":
    main()
