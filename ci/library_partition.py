"""Split a library phase by exact names while preserving Cargo's selection.

Each runner compiles/lists all selected libraries, then lets Cargo execute the
unchanged package/feature selection with complementary libtest exclusions.
This preserves Cargo's working directories and environment, including for
test=false libraries explicitly selected by --lib and process-child fixtures.
"""

import hashlib
import json
from pathlib import Path
import re
import subprocess

import cargo_test_selection


SHARDS = (0, 1)


def owner(name: str) -> int:
    # Exclusions are passed to every harness, so repeated names across
    # libraries must share an owner. Identities remain distinct in the audit.
    return int.from_bytes(hashlib.sha256(name.encode()).digest()[:8], "big") % len(SHARDS)


def listing(output: str) -> list[str]:
    names = []
    for line in output.splitlines():
        if line.endswith(": test"):
            names.append(line.removesuffix(": test"))
        elif line.strip() and not re.fullmatch(r"\d+ tests?, \d+ benchmarks?", line):
            raise ValueError("unexpected library inventory line: " + line)
    if len(names) != len(set(names)):
        raise ValueError("duplicate test name within one library")
    return names


def inventory(selection: list[str], root: Path, *, env: dict | None = None) -> tuple[list[dict], dict]:
    def capture(argv: list[str], cwd: Path = root) -> str:
        return subprocess.run(argv, cwd=cwd, env=env, check=True, text=True,
                              stdout=subprocess.PIPE).stdout

    metadata = json.loads(capture(["cargo", "metadata", "--locked", "--no-deps", "--format-version=1"]))
    expected = cargo_test_selection.resolve([*selection, "--lib"], metadata).targets
    packages = {package["id"]: package for package in metadata["packages"]}
    # Leave compiler progress visible on stderr during a cold hosted build.
    output = capture([*(arg for arg in selection if arg != "--quiet"),
                      "--lib", "--no-run", "--message-format=json"])
    binaries = {}
    for line in output.splitlines():
        artifact = json.loads(line)
        if artifact.get("reason") != "compiler-artifact" or not artifact["profile"]["test"] or not artifact.get("executable"):
            continue
        package = packages.get(artifact["package_id"])
        if package is None:
            raise ValueError("unexpected test binary outside the selected workspace")
        key = (package["name"], artifact["target"]["name"], tuple(artifact["target"]["kind"]))
        if key in binaries:
            raise ValueError("duplicate compiled library")
        binaries[key] = (artifact["executable"], Path(package["manifest_path"]).parent)
    if set(binaries) != expected:
        raise ValueError(f"compiled libraries differ from Cargo selection: {set(binaries) ^ expected}")
    rows = []
    for (package, target, kind), (binary, cwd) in sorted(binaries.items()):
        names = listing(capture([binary, "--list", "--format=terse"], cwd))
        ignored = set(listing(capture([binary, "--ignored", "--list", "--format=terse"], cwd)))
        if not ignored.issubset(names):
            raise ValueError("ignored library tests are absent from the full inventory")
        rows.extend({"package": package, "target": target, "kind": list(kind),
                     "name": name, "ignored": name in ignored} for name in names)
    validate_rows(rows)
    return rows, metadata


def validate_rows(rows: list[dict], isolated: tuple[str, ...] = ()) -> None:
    if not rows:
        raise ValueError("empty library inventory")
    identities = [(row["package"], row["target"], tuple(row["kind"]), row["name"]) for row in rows]
    if len(identities) != len(set(identities)):
        raise ValueError("duplicate library test identity")
    if any(not cargo_test_selection.LIBRARY_KINDS.intersection(row["kind"]) for row in rows):
        raise ValueError("non-library target in the library inventory")
    for name in isolated:
        matches = [row for row in rows if row["name"] == name]
        if len(matches) != 1 or matches[0]["ignored"]:
            raise ValueError("isolated library test must resolve exactly once and stay enabled: " + name)


def verify_named_owners(rows: list[dict], names: tuple[str, ...], child_parents: dict[str, str],
                        planned: dict[str, list[list[str]]], metadata: dict) -> dict[str, str]:
    """Require one enabled owner for each moved test, including child parents.

    Ignored helpers are explicit exceptions, never inferred from their names.
    Their enabled parent owns execution; its internal crash scenarios may spawn
    the helper more than once. No CI command may also run ignored helpers.
    """
    if len(names) != len(set(names)) or not set(child_parents).issubset(names):
        raise ValueError("duplicate named test or undeclared subprocess child")
    if any(parent not in names or parent in child_parents for parent in child_parents.values()):
        raise ValueError("subprocess child must name an enabled, non-child parent")
    validate_rows(rows, tuple(name for name in names if name not in child_parents))
    named_rows = {name: [row for row in rows if row["name"] == name] for name in names}
    for child, parent in child_parents.items():
        matches = named_rows[child]
        if len(matches) != 1 or not matches[0]["ignored"]:
            raise ValueError("subprocess child must resolve exactly once and remain ignored: " + child)
        if any(matches[0][key] != named_rows[parent][0][key] for key in ("package", "target", "kind")):
            raise ValueError("subprocess child and parent must use the same library harness: " + child)
    selections = []
    for shard, commands in planned.items():
        for argv in commands:
            selection = cargo_test_selection.resolve(argv, metadata)
            harness = argv[argv.index("--") + 1:] if "--" in argv else []
            if selection.has_library() and {"--ignored", "--include-ignored"}.intersection(harness):
                raise ValueError("library plans must leave ignored subprocess execution to its parent")
            selections.append((shard, selection))
    owners = {}
    for name in names:
        row = named_rows[child_parents.get(name, name)][0]
        identity = (row["package"], row["target"], tuple(row["kind"]), row["name"])
        selected = [shard for shard, selection in selections if selection.selects(*identity)]
        if len(selected) != 1:
            raise ValueError(f"named library test must have exactly one enabled owner: {name}: {selected}")
        owners[name] = selected[0]
    return owners


def commands(phase: list[list[str]], ordinary_index: int, rows: list[dict], shard: int) -> list[list[str]]:
    if shard not in SHARDS:
        raise ValueError("unknown library shard")
    validate_rows(rows)
    ordinary = list(phase[ordinary_index])
    if "--lib" not in ordinary or "--exact" not in ordinary or "--test-threads=4" not in ordinary:
        raise ValueError("ordinary library phase must retain its exact filters and four test threads")
    skipped = {ordinary[index + 1] for index, arg in enumerate(ordinary[:-1]) if arg == "--skip"}
    extra = sorted({row["name"] for row in rows if owner(row["name"]) != shard} - skipped)
    ordinary.extend(arg for name in extra for arg in ("--skip", name))
    # Preserve all isolated commands and their ordering on one runner. The
    # ordinary command keeps its relative position between those phases.
    return [*(phase[:ordinary_index] if shard == 0 else []), ordinary,
            *(phase[ordinary_index + 1:] if shard == 0 else [])]


def verify(phase: list[list[str]], ordinary_index: int, rows: list[dict], planned: dict[int, list[list[str]]], metadata: dict) -> None:
    validate_rows(rows)
    if set(planned) != set(SHARDS):
        raise ValueError("missing or unexpected library shard")
    for shard in SHARDS:
        if planned[shard] != commands(phase, ordinary_index, rows, shard):
            raise ValueError("library phase changed selection, profile, ordering or exact ownership")
    before = [cargo_test_selection.resolve(argv, metadata) for argv in phase]
    after = [cargo_test_selection.resolve(argv, metadata) for shard in SHARDS for argv in planned[shard]]
    for row in rows:
        identity = (row["package"], row["target"], tuple(row["kind"]), row["name"])
        expected = sum(selection.selects(*identity) for selection in before)
        actual = sum(selection.selects(*identity) for selection in after)
        if actual != expected or actual > 1:
            raise ValueError(f"library partition changes coverage for {identity}: {expected} -> {actual}")
