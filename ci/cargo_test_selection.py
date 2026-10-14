"""Resolve Cargo library test harnesses and libtest filters for CI command plans.

Only understood command forms are accepted. In particular, a new Cargo option
must not silently turn a command that runs library tests into an empty selection.
Doctests and compile-only commands do not execute library unit-test harnesses.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
import json
from pathlib import Path
import re
import subprocess


LIBRARY_KINDS = frozenset({"lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"})
TARGET_FLAGS = {"--lib", "--bins", "--examples", "--tests", "--all-targets", "--doc"}
NAMED_TARGETS = {"--bin": "bin", "--example": "example", "--test": "test", "--bench": "bench"}
CARGO_FLAGS = {
    "--locked", "--offline", "--frozen", "--all-features", "--no-default-features",
    "--quiet", "-q", "--verbose", "-v", "-vv", "--release", "-r",
    "--no-fail-fast", "--ignore-rust-version", "--future-incompat-report", "--timings",
}
CARGO_VALUES = {"--features", "-F", "--profile", "--target", "--target-dir", "--message-format", "--color"}
HARNESS_FLAGS = {
    "--exact", "--nocapture", "--no-capture", "--show-output", "--quiet", "-q",
    "--ignored", "--include-ignored", "--list", "--test", "--bench",
}
HARNESS_VALUES = {"--test-threads", "--format", "--color", "--logfile", "--shuffle-seed"}


def workspace_metadata(root: Path) -> dict:
    return json.loads(subprocess.run(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version=1"],
        cwd=root, check=True, text=True, stdout=subprocess.PIPE,
    ).stdout)


def option_value(args: list[str], index: int) -> tuple[str, int]:
    option, separator, value = args[index].partition("=")
    if separator:
        if value:
            return value, index + 1
    elif index + 1 < len(args) and not args[index + 1].startswith("-"):
        return args[index + 1], index + 2
    raise ValueError("missing value for " + option)


@dataclass(frozen=True)
class Selection:
    # Only library unit-test harnesses: binaries, integration targets and
    # doctests cannot execute the library tests protected by these guards.
    targets: frozenset[tuple[str, str, tuple[str, ...]]]
    filters: tuple[str, ...]
    skips: tuple[str, ...]
    exact: bool
    runs_enabled_tests: bool

    def has_library(self) -> bool:
        return any(LIBRARY_KINDS.intersection(kind) for _, _, kind in self.targets)

    def selects(self, package: str, target: str, kind: tuple[str, ...], name: str) -> bool:
        def matches(value: str) -> bool:
            return name == value if self.exact else value in name

        return (
            self.runs_enabled_tests
            and (package, target, kind) in self.targets
            and (not self.filters or any(matches(value) for value in self.filters))
            and not any(matches(value) for value in self.skips)
        )


def resolve(argv: list[str], metadata: dict) -> Selection:
    """Resolve the selected libraries against the workspace's Cargo metadata.

    The plans run from the workspace root. Foreign manifests, Cargo config
    overrides and unsupported flags are refused instead of guessed. Cargo
    metadata does not expose `bench = false`, so `--benches` is also refused;
    `--all-targets` explicitly includes the library regardless of that flag.
    """
    args = list(argv)
    if args[:1] == ["env"]:
        args.pop(0)
        while args and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*=.*", args[0]):
            args.pop(0)
    if not args or args.pop(0) != "cargo":
        raise ValueError("unsupported test-plan command: " + repr(argv))
    if args and args[0].startswith("+"):
        args.pop(0)
    if not args or args[0] not in {"test", "t", "build", "b"}:
        raise ValueError("unsupported Cargo command: " + repr(argv))
    operation = args.pop(0)
    cut = args.index("--") if "--" in args else len(args)
    cargo, harness = args[:cut], args[cut + 1:]
    packages, excluded, filters, skips = [], [], [], []
    flags, named = set(), []
    workspace = False
    no_run = operation in {"build", "b"}
    index = 0
    while index < len(cargo):
        arg = cargo[index]
        option = arg.split("=", 1)[0]
        if arg in TARGET_FLAGS:
            flags.add(arg)
        elif option in NAMED_TARGETS:
            value, index = option_value(cargo, index)
            named.append((NAMED_TARGETS[option], value))
            continue
        elif arg in {"--workspace", "--all"}:
            workspace = True
        elif option in {"-p", "--package", "--exclude"}:
            value, index = option_value(cargo, index)
            (excluded if option == "--exclude" else packages).append(value)
            continue
        elif arg.startswith("-p") and not arg.startswith("--"):
            packages.append(arg[2:])
        elif arg == "--no-run":
            no_run = True
        elif arg in CARGO_FLAGS:
            pass
        elif option in CARGO_VALUES:
            _, index = option_value(cargo, index)
            continue
        elif arg.startswith("-F") and not arg.startswith("--"):
            pass
        elif option == "--manifest-path":
            value, index = option_value(cargo, index)
            root = Path(metadata["workspace_root"])
            if (root / value).resolve() != root / "Cargo.toml":
                raise ValueError("test plan selects a different Cargo manifest")
            continue
        elif arg.startswith("-"):
            raise ValueError("unsupported Cargo test option: " + arg)
        else:
            filters.append(arg)
        index += 1
    if len(filters) > 1:
        raise ValueError("Cargo accepts only one test-name filter before --")
    if excluded and not workspace:
        raise ValueError("Cargo package exclusions require --workspace")
    if workspace and packages:
        raise ValueError("combined workspace and package selectors are not supported")
    if "--doc" in flags and (len(flags) != 1 or named):
        raise ValueError("doctests cannot be combined with other target selectors")

    harness_flags = set()
    index = 0
    while index < len(harness):
        arg = harness[index]
        option = arg.split("=", 1)[0]
        if arg in HARNESS_FLAGS:
            harness_flags.add(arg)
        elif option == "--skip":
            value, index = option_value(harness, index)
            skips.append(value)
            continue
        elif option in HARNESS_VALUES:
            _, index = option_value(harness, index)
            continue
        elif arg.startswith("-"):
            raise ValueError("unsupported libtest option: " + arg)
        else:
            filters.append(arg)
        index += 1

    members = {p["id"]: p for p in metadata["packages"] if p["id"] in metadata["workspace_members"]}

    def matching(spec: str) -> set[str]:
        matches = {
            identity for identity, package in members.items()
            if spec == identity or fnmatchcase(package["name"], spec)
            or spec == package["name"] + "@" + package["version"]
        }
        if not matches:
            raise ValueError("Cargo package selector matches no workspace member: " + spec)
        return matches

    selected = set(members) if workspace else (
        set().union(*(matching(spec) for spec in packages)) if packages
        else set(metadata["workspace_default_members"])
    )
    for spec in excluded:
        selected.difference_update(matching(spec))
    targets = set()
    if not no_run and "--doc" not in flags:
        for identity in selected:
            package = members[identity]
            for target in package["targets"]:
                kind = tuple(target["kind"])
                if kind == ("custom-build",):
                    continue
                library = bool(LIBRARY_KINDS.intersection(kind))
                if not library and kind not in {("bin",), ("test",), ("example",), ("bench",)}:
                    raise ValueError("unsupported Cargo target kind: " + repr(kind))
                if library and (
                    "--all-targets" in flags
                    or "--lib" in flags
                    or ("--tests" in flags or not flags and not named) and target["test"]
                ):
                    targets.add((package["name"], target["name"], kind))
    runs = not (
        "--list" in harness_flags
        or "--ignored" in harness_flags and "--include-ignored" not in harness_flags
        or "--bench" in harness_flags and "--test" not in harness_flags
    )
    return Selection(frozenset(targets), tuple(filters), tuple(skips), "--exact" in harness_flags, runs)
