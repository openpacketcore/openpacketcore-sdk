#!/usr/bin/env python3
"""Read-only N3IWF catalog gate; Rust owns the shared schema validation."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "crates/opc-n3iwf-fixtures/fixtures"


def run(*command: str) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


def git(*args: str) -> str:
    return subprocess.check_output(
        ["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
    ).strip()


def publication_matches_content() -> bool:
    """The content commit precedes the stamp; only the stamp may differ.

    This avoids a self-referential Git object while validating actual content,
    ancestry, and tree identity, not merely the shape of a SHA string.
    """
    publication = json.loads((FIXTURE_ROOT / "PUBLIC_SDK.json").read_text())
    base, head, tree = (publication[key] for key in ("base", "head", "tree"))
    if any(
        not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value)
        for value in (base, head, tree)
    ):
        return False
    prefix = "crates/opc-n3iwf-fixtures/fixtures"
    if publication["tree_path"] != prefix:
        return False
    if (
        git("rev-parse", head + "^{commit}") != head
        or git("rev-parse", head + ":" + prefix) != tree
    ):
        return False
    git("merge-base", "--is-ancestor", base, head)
    git("merge-base", "--is-ancestor", head, "HEAD")
    expected = {}
    entries = subprocess.check_output(
        ["git", "ls-tree", "-rz", head, "--", prefix], cwd=ROOT
    )
    for entry in entries.split(b"\0"):
        if not entry:
            continue
        meta, name = entry.split(b"\t", 1)
        mode, kind, digest = meta.split()
        path = name.decode().removeprefix(prefix + "/")
        if path == "PUBLIC_SDK.json":
            continue
        if mode != b"100644" or kind != b"blob":
            return False
        expected[path] = digest.decode()
    actual = {}
    for path in FIXTURE_ROOT.rglob("*"):
        if path.is_symlink():
            return False
        if (
            path.is_file()
            and path.relative_to(FIXTURE_ROOT).as_posix() != "PUBLIC_SDK.json"
        ):
            raw = path.read_bytes()
            actual[path.relative_to(FIXTURE_ROOT).as_posix()] = hashlib.sha1(
                b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False
            ).hexdigest()
    return bool(expected) and actual == expected


def main() -> int:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        # These modes generate into temporary directories and never touch evidence.
        run(
            sys.executable,
            "scripts/generate-n3iwf-fixtures.py",
            "--self-test" if args.self_test else "--check",
        )
        if args.self_test:
            run(sys.executable, "scripts/test-n3iwf-fixture-contracts.py")
        run(
            "cargo",
            "run",
            "--locked",
            "--quiet",
            "-p",
            "opc-n3iwf-fixtures",
            "--bin",
            "check-n3iwf-fixtures",
        )
        run(sys.executable, "scripts/n3iwf_fixture_oracles.py")
        run(sys.executable, "scripts/n3iwf_key_reference.py")
        run(sys.executable, "scripts/n3iwf_key_lifecycle_reference.py", "--check")
        run(sys.executable, "scripts/n3iwf_roster_lifecycle_reference.py", "--check")
        run(sys.executable, "scripts/n3iwf_child_sa_relocation_reference.py", "--check")
        run(sys.executable, "scripts/n3iwf_child_sa_profile_reference.py", "--check")
        run(sys.executable, "scripts/n3iwf_dtls_lifecycle_reference.py", "--check")
        run(sys.executable, "scripts/n3iwf_dtls_profile_reference.py", "--check")
        # Cryptographic source regeneration belongs to the existing audited-DTLS
        # job with its pinned Python environment. This gate verifies their exact
        # source bytes and value-free projections without adding dependencies.
        run(sys.executable, "crates/opc-diameter-transport/tests/fixtures/rfc6083/streams.py", "--check")
        run(sys.executable, "vendor/dimpl/tests/dtls12/rfc5746_binding_reference.py", "--check")
        run(sys.executable, "crates/opc-gtpu-dataplane/tests/n3_reference.py", "--check")
        run(sys.executable, "scripts/n3iwf_gtpu_reference.py")
        run(
            "cargo",
            "test",
            "--locked",
            "--quiet",
            "-p",
            "opc-n3iwf-fixtures",
            "--test",
            "wire_codecs",
            "--test",
            "gre_packets",
            "--test",
            "ngap_messages",
            "--test",
            "protocol_key_known_answers",
        )
        if not publication_matches_content():
            print("n3iwf_fixture_publication_mismatch", file=sys.stderr)
            return 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError):
        # Do not include input, paths, JSON contents, or a subprocess exception.
        print("n3iwf_fixture_gate_failed", file=sys.stderr)
        return 1
    print("n3iwf_fixture_contracts_valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
