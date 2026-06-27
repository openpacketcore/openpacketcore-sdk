#!/usr/bin/env python3
"""Check management-plane dependency and unsafe-code boundaries.

This script backs ADR 0016 and ADR 0017 while those decisions are still gated by
human acceptance. It enforces two mechanical invariants:

* `tonic`, `prost`, `prost-types`, and `tonic-build` stay scoped to
  `opc-gnmi-server`.
* Rust `unsafe` tokens stay scoped to explicitly reviewed Linux UAPI sys
  crates, where each token must be documented by a nearby `SAFETY:` comment
  and a local unsafe lint policy must be declared.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import deque
from dataclasses import dataclass
from pathlib import Path


GRPC_STACK = {"tonic", "prost", "prost-types", "tonic-build"}
GRPC_ALLOWED_ROOTS = {"opc-gnmi-server"}
UNSAFE_ALLOWED_ROOTS = {"opc-libsctp-sys", "opc-linux-xfrm-sys"}


@dataclass(frozen=True)
class Violation:
    location: str
    message: str

    def render(self) -> str:
        return f"{self.location}: {self.message}"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def run_cargo_metadata(root: Path) -> dict:
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked"],
        cwd=root,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise SystemExit(result.returncode)
    return json.loads(result.stdout)


def workspace_packages(metadata: dict) -> list[dict]:
    member_ids = set(metadata["workspace_members"])
    return [pkg for pkg in metadata["packages"] if pkg["id"] in member_ids]


def check_grpc_boundary(metadata: dict) -> list[Violation]:
    violations: list[Violation] = []
    packages_by_id = {pkg["id"]: pkg for pkg in metadata["packages"]}
    workspace_ids = set(metadata["workspace_members"])

    for pkg in workspace_packages(metadata):
        if pkg["name"] in GRPC_ALLOWED_ROOTS:
            for dep in pkg.get("dependencies", []):
                if dep.get("name") == "tonic-build" and dep.get("kind") != "build":
                    violations.append(
                        Violation(
                            pkg["manifest_path"],
                            "`tonic-build` is allowed only as a build dependency "
                            "of `opc-gnmi-server`",
                        )
                    )
            continue

        for dep in pkg.get("dependencies", []):
            dep_name = dep.get("name")
            if dep_name in GRPC_STACK:
                kind = dep.get("kind") or "normal"
                violations.append(
                    Violation(
                        pkg["manifest_path"],
                        f"`{dep_name}` {kind} dependency is outside the ADR 0016 "
                        "`opc-gnmi-server` allow-list",
                    )
                )

    resolve = metadata.get("resolve") or {}
    nodes_by_id = {node["id"]: node for node in resolve.get("nodes", [])}
    grpc_package_ids = {
        pkg_id
        for pkg_id, pkg in packages_by_id.items()
        if pkg["name"] in GRPC_STACK or pkg["name"] in GRPC_ALLOWED_ROOTS
    }

    for root_id in sorted(workspace_ids):
        root_pkg = packages_by_id[root_id]
        if root_pkg["name"] in GRPC_ALLOWED_ROOTS:
            continue
        hit = first_reachable_package(root_id, grpc_package_ids, nodes_by_id, packages_by_id)
        if hit is not None:
            violations.append(
                Violation(
                    root_pkg["manifest_path"],
                    f"transitively reaches `{hit['name']}`, outside the ADR 0016 "
                    "`opc-gnmi-server` boundary",
                )
            )

    return dedupe_violations(violations)


def first_reachable_package(
    root_id: str,
    targets: set[str],
    nodes_by_id: dict[str, dict],
    packages_by_id: dict[str, dict],
) -> dict | None:
    seen = {root_id}
    queue: deque[str] = deque([root_id])

    while queue:
        current = queue.popleft()
        node = nodes_by_id.get(current)
        if node is None:
            continue
        for dep in node.get("deps", []):
            dep_id = dep["pkg"]
            if dep_id in seen:
                continue
            if dep_id in targets:
                return packages_by_id[dep_id]
            seen.add(dep_id)
            queue.append(dep_id)
    return None


def check_unsafe_boundary(metadata: dict) -> list[Violation]:
    violations: list[Violation] = []
    for pkg in workspace_packages(metadata):
        root = Path(pkg["manifest_path"]).parent
        if pkg["name"] in UNSAFE_ALLOWED_ROOTS:
            violations.extend(check_sys_crate_lints(pkg, root))
            violations.extend(check_sys_crate_unsafe_comments(root))
            continue
        for source in rust_sources(root):
            for token in unsafe_tokens(source):
                violations.append(
                    Violation(
                        f"{source}:{token.line}:{token.column}",
                        "`unsafe` token is outside the ADR 0017 Linux UAPI sys-crate "
                        "allow-list",
                    )
                )
    return violations


def check_sys_crate_unsafe_comments(root: Path) -> list[Violation]:
    violations: list[Violation] = []
    for source in rust_sources(root):
        text = source.read_text(encoding="utf-8")
        for token in unsafe_tokens_in_text(text):
            if not has_safety_comment(text, token):
                violations.append(
                    Violation(
                        f"{source}:{token.line}:{token.column}",
                        "`unsafe` token in an allowed Linux UAPI sys crate must be "
                        "documented by an adjacent `SAFETY:` comment",
                    )
                )
    return violations


def check_sys_crate_lints(pkg: dict, root: Path) -> list[Violation]:
    manifest = Path(pkg["manifest_path"])
    text = manifest.read_text(encoding="utf-8")
    package_name = pkg["name"]
    violations: list[Violation] = []

    if inherits_workspace_lints(text):
        violations.append(
            Violation(
                str(manifest),
                f"`{package_name}` must not inherit `[workspace.lints]`; ADR 0017 "
                "requires a local unsafe policy",
            )
        )

    sources = rust_sources(root)
    if not sources:
        violations.append(
            Violation(
                str(manifest),
                f"`{package_name}` exists but has no Rust source to audit",
            )
        )
        return violations

    source_texts = [source.read_text(encoding="utf-8") for source in sources]
    if not has_local_unsafe_code_allow(text, source_texts):
        violations.append(
            Violation(
                str(manifest),
                f"`{package_name}` must declare a local `unsafe_code = \"allow\"` "
                "policy or crate-level `#![allow(unsafe_code)]`",
            )
        )
    if not has_unsafe_op_in_unsafe_fn_deny(text, source_texts):
        violations.append(
            Violation(
                str(manifest),
                f"`{package_name}` must deny `unsafe_op_in_unsafe_fn` locally",
            )
        )

    return violations

def inherits_workspace_lints(manifest_text: str) -> bool:
    return (
        re.search(
            r"(?ms)^\[lints\]\s*(?:(?!^\[).)*^\s*workspace\s*=\s*true\s*$",
            manifest_text,
        )
        is not None
    )


def has_local_unsafe_code_allow(manifest_text: str, source_texts: list[str]) -> bool:
    return (
        re.search(r'(?m)^\s*unsafe_code\s*=\s*"?allow"?\s*$', manifest_text)
        is not None
        or any(
            "#![allow(unsafe_code)]" in source_text for source_text in source_texts
        )
    )


def has_unsafe_op_in_unsafe_fn_deny(
    manifest_text: str, source_texts: list[str]
) -> bool:
    return (
        re.search(
            r'(?m)^\s*unsafe_op_in_unsafe_fn\s*=\s*"?deny"?\s*$',
            manifest_text,
        )
        is not None
        or any(
            "#![deny(unsafe_op_in_unsafe_fn)]" in source_text
            for source_text in source_texts
        )
    )


def has_safety_comment(text: str, token: UnsafeToken) -> bool:
    lines = text.splitlines()
    index = token.line - 2
    saw_comment = False

    while index >= 0:
        stripped = lines[index].strip()
        if not stripped:
            if saw_comment:
                break
            index -= 1
            continue

        if is_comment_line(stripped):
            saw_comment = True
            if "SAFETY:" in stripped:
                return True
            index -= 1
            continue

        return False

    return False


def is_comment_line(stripped: str) -> bool:
    return (
        stripped.startswith("//")
        or stripped.startswith("/*")
        or stripped.startswith("*")
        or stripped.endswith("*/")
    )


def rust_sources(root: Path) -> list[Path]:
    skip = {".git", "target"}
    return sorted(
        path
        for path in root.rglob("*.rs")
        if not any(part in skip for part in path.parts)
    )


@dataclass(frozen=True)
class UnsafeToken:
    line: int
    column: int


def unsafe_tokens(path: Path) -> list[UnsafeToken]:
    text = path.read_text(encoding="utf-8")
    return unsafe_tokens_in_text(text)


def unsafe_tokens_in_text(text: str) -> list[UnsafeToken]:
    tokens: list[UnsafeToken] = []
    i = 0
    line = 1
    column = 1

    def advance(count: int = 1) -> None:
        nonlocal i, line, column
        for _ in range(count):
            if i >= len(text):
                return
            if text[i] == "\n":
                line += 1
                column = 1
            else:
                column += 1
            i += 1

    def skip_quoted(open_len: int) -> None:
        advance(open_len)
        while i < len(text):
            if text[i] == "\\":
                advance(2)
            elif text[i] == '"':
                advance()
                return
            else:
                advance()

    def raw_prefix_at(pos: int) -> tuple[int, int] | None:
        start = pos
        if text.startswith("br", pos) or text.startswith("cr", pos):
            pos += 2
        elif pos < len(text) and text[pos] == "r":
            pos += 1
        else:
            return None
        hashes_start = pos
        while pos < len(text) and text[pos] == "#":
            pos += 1
        if pos < len(text) and text[pos] == '"':
            return pos - start + 1, pos - hashes_start
        return None

    def skip_raw(prefix_len: int, hashes: int) -> None:
        advance(prefix_len)
        terminator = '"' + ("#" * hashes)
        while i < len(text):
            if text.startswith(terminator, i):
                advance(len(terminator))
                return
            advance()

    def skip_block_comment() -> None:
        depth = 1
        advance(2)
        while i < len(text) and depth > 0:
            if text.startswith("/*", i):
                depth += 1
                advance(2)
            elif text.startswith("*/", i):
                depth -= 1
                advance(2)
            else:
                advance()

    while i < len(text):
        if text.startswith("//", i):
            while i < len(text) and text[i] != "\n":
                advance()
            continue
        if text.startswith("/*", i):
            skip_block_comment()
            continue

        raw_prefix = raw_prefix_at(i)
        if raw_prefix is not None:
            skip_raw(*raw_prefix)
            continue

        if (
            text.startswith("r#", i)
            and i + 2 < len(text)
            and is_ident_start(text[i + 2])
        ):
            advance(2)
            while i < len(text) and is_ident_continue(text[i]):
                advance()
            continue

        if text.startswith('b"', i) or text.startswith('c"', i):
            skip_quoted(2)
            continue
        if text[i] == '"':
            skip_quoted(1)
            continue

        if text.startswith("b'", i):
            skip_char_literal(advance, lambda: i < len(text) and text[i], open_len=2)
            continue
        if text[i] == "'":
            if looks_like_char_literal(text, i):
                skip_char_literal(advance, lambda: i < len(text) and text[i], open_len=1)
            else:
                advance()
                while i < len(text) and is_ident_continue(text[i]):
                    advance()
            continue

        if is_ident_start(text[i]):
            start_line = line
            start_column = column
            start = i
            while i < len(text) and is_ident_continue(text[i]):
                advance()
            if text[start:i] == "unsafe":
                tokens.append(UnsafeToken(start_line, start_column))
            continue

        advance()

    return tokens


def skip_char_literal(advance, current_char, open_len: int) -> None:
    advance(open_len)
    while current_char():
        ch = current_char()
        if ch == "\\":
            advance(2)
        elif ch == "'":
            advance()
            return
        else:
            advance()


def looks_like_char_literal(text: str, pos: int) -> bool:
    if pos + 1 >= len(text):
        return False
    if text[pos + 1] == "\\":
        return True
    if pos + 2 < len(text) and text[pos + 2] == "'":
        return True
    return not is_ident_start(text[pos + 1])


def is_ident_start(ch: str) -> bool:
    return ch == "_" or ch.isalpha()


def is_ident_continue(ch: str) -> bool:
    return ch == "_" or ch.isalnum()


def dedupe_violations(violations: list[Violation]) -> list[Violation]:
    seen: set[tuple[str, str]] = set()
    deduped: list[Violation] = []
    for violation in violations:
        key = (violation.location, violation.message)
        if key not in seen:
            seen.add(key)
            deduped.append(violation)
    return deduped


def grpc_policy_fixture(
    workspace_members: list[str],
    package_deps: dict[str, list[tuple[str, str | None]]],
    resolve_deps: dict[str, list[str]],
) -> dict:
    package_names = set(workspace_members) | set(package_deps) | set(resolve_deps)
    for deps in package_deps.values():
        package_names.update(dep_name for dep_name, _kind in deps)
    for deps in resolve_deps.values():
        package_names.update(deps)

    packages = []
    for name in sorted(package_names):
        packages.append(
            {
                "id": name,
                "name": name,
                "manifest_path": f"/fixture/{name}/Cargo.toml",
                "dependencies": [
                    {"name": dep_name, "kind": kind}
                    for dep_name, kind in package_deps.get(name, [])
                ],
            }
        )

    return {
        "packages": packages,
        "workspace_members": workspace_members,
        "resolve": {
            "nodes": [
                {
                    "id": name,
                    "deps": [{"pkg": dep_name} for dep_name in resolve_deps.get(name, [])],
                }
                for name in sorted(package_names)
            ]
        },
    }


def assert_grpc_policy_fragments(
    case_name: str, metadata: dict, expected_fragments: list[str]
) -> None:
    rendered = [violation.render() for violation in check_grpc_boundary(metadata)]
    if not expected_fragments and rendered:
        raise SystemExit(
            f"gRPC boundary self-test failed for {case_name}: expected no "
            f"violations, got {rendered}"
        )

    missing = [
        fragment
        for fragment in expected_fragments
        if not any(fragment in violation for violation in rendered)
    ]
    if missing:
        raise SystemExit(
            f"gRPC boundary self-test failed for {case_name}: missing {missing}; "
            f"got {rendered}"
        )


def run_self_test() -> None:
    assert_grpc_policy_fragments(
        "opc-gnmi-server direct gRPC deps allowed",
        grpc_policy_fixture(
            ["opc-gnmi-server"],
            {
                "opc-gnmi-server": [
                    ("prost", None),
                    ("prost-types", None),
                    ("tonic", None),
                    ("tonic-build", "build"),
                ]
            },
            {"opc-gnmi-server": ["prost", "prost-types", "tonic", "tonic-build"]},
        ),
        [],
    )
    assert_grpc_policy_fragments(
        "tonic-build is build-only",
        grpc_policy_fixture(
            ["opc-gnmi-server"],
            {"opc-gnmi-server": [("tonic-build", None)]},
            {"opc-gnmi-server": ["tonic-build"]},
        ),
        ["`tonic-build` is allowed only as a build dependency"],
    )
    assert_grpc_policy_fragments(
        "workspace crate cannot directly depend on tonic",
        grpc_policy_fixture(
            ["opc-core"],
            {"opc-core": [("tonic", None)]},
            {"opc-core": ["tonic"]},
        ),
        ["`tonic` normal dependency is outside the ADR 0016"],
    )
    assert_grpc_policy_fragments(
        "workspace crate cannot transitively reach tonic",
        grpc_policy_fixture(
            ["opc-core"],
            {"opc-core": [("third-party-helper", None)]},
            {
                "opc-core": ["third-party-helper"],
                "third-party-helper": ["tonic"],
            },
        ),
        ["transitively reaches `tonic`"],
    )
    assert_grpc_policy_fragments(
        "workspace crate cannot re-export opc-gnmi-server",
        grpc_policy_fixture(
            ["opc-core", "opc-gnmi-server"],
            {"opc-core": [("opc-gnmi-server", None)]},
            {"opc-core": ["opc-gnmi-server"]},
        ),
        ["transitively reaches `opc-gnmi-server`"],
    )

    unsafe_cases = {
        "unsafe { call(); }": [(1, 1)],
        "fn unsafe_name() {}\nlet x = unsafe { y };": [(2, 9)],
        "// unsafe\nfn main() {}": [],
        "/* unsafe */\nfn main() {}": [],
        "/* outer /* unsafe */ still comment */ fn main() {}": [],
        '"unsafe" r#"unsafe"# br##"unsafe"##': [],
        "'u' b'u' 'unsafe": [],
        "#![forbid(unsafe_code)]": [],
        "let r#unsafe = 1;": [],
    }
    for source, expected in unsafe_cases.items():
        actual = [(token.line, token.column) for token in unsafe_tokens_in_text(source)]
        if actual != expected:
            raise SystemExit(
                f"self-test failed for {source!r}: expected {expected}, got {actual}"
            )

    safety_cases = {
        "// SAFETY: call is valid for this fixture.\nunsafe { call(); }": [],
        "let value = {\n    // SAFETY: pointer is non-null in this fixture.\n    unsafe { read(); }\n};": [],
        "/* SAFETY:\n * declaration matches the C ABI fixture.\n */\nunsafe extern \"C\" {}": [],
        "unsafe { call(); }": [(1, 1)],
        "// unrelated\nunsafe { call(); }": [(2, 1)],
    }
    for source, expected in safety_cases.items():
        actual = [
            (token.line, token.column)
            for token in unsafe_tokens_in_text(source)
            if not has_safety_comment(source, token)
        ]
        if actual != expected:
            raise SystemExit(
                f"safety self-test failed for {source!r}: expected {expected}, got {actual}"
            )

    manifest_with_workspace_lints = """
[package]
name = "opc-libsctp-sys"

[lints]
workspace = true
"""
    if not inherits_workspace_lints(manifest_with_workspace_lints):
        raise SystemExit("self-test failed: workspace lints inheritance not detected")

    manifest_with_local_policy = """
[package]
name = "opc-libsctp-sys"

[lints.rust]
unsafe_code = "allow"
unsafe_op_in_unsafe_fn = "deny"
"""
    if not has_local_unsafe_code_allow(manifest_with_local_policy, []):
        raise SystemExit("self-test failed: local unsafe_code allow not detected")
    if not has_unsafe_op_in_unsafe_fn_deny(manifest_with_local_policy, []):
        raise SystemExit(
            "self-test failed: local unsafe_op_in_unsafe_fn deny not detected"
        )

    source_with_crate_lints = """
#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
"""
    if not has_local_unsafe_code_allow("", [source_with_crate_lints]):
        raise SystemExit("self-test failed: crate unsafe_code allow not detected")
    if not has_unsafe_op_in_unsafe_fn_deny("", [source_with_crate_lints]):
        raise SystemExit(
            "self-test failed: crate unsafe_op_in_unsafe_fn deny not detected"
        )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="check the workspace policy gates",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the local Rust-token scanner self-test",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if not args.check and not args.self_test:
        args.check = True

    if args.self_test:
        run_self_test()
        print("management-plane policy self-test: ok")

    if args.check:
        root = repo_root()
        metadata = run_cargo_metadata(root)
        violations = check_grpc_boundary(metadata)
        violations.extend(check_unsafe_boundary(metadata))
        if violations:
            print("management-plane policy violations:", file=sys.stderr)
            for violation in violations:
                print(f"  - {violation.render()}", file=sys.stderr)
            return 1
        print("management-plane policy check: ok")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
