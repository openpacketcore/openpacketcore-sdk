#!/usr/bin/env python3
"""Repository gate for N3IWF fixture contracts (issue 784)."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "crates" / "opc-n3iwf-fixtures" / "fixtures"
GENERATOR = ROOT / "scripts" / "generate-n3iwf-fixtures.py"
SUBSETS = [
    "eap5g",
    "nwu-ike",
    "ngap",
    "n2-sctp",
    "gre-qfi",
    "n3-gtpu",
    "protocol-key",
    "nas-tcp",
    "xfrm-roster",
    "n2-dtls",
]
REQUIRED = {
    "positive",
    "malformed",
    "duplicate",
    "unknown-critical",
    "ordering",
    "truncation",
    "bounded-overflow",
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def check_catalog() -> list[str]:
    errors: list[str] = []
    publication = load_json(FIXTURE_ROOT / "PUBLIC_SDK.json")
    if publication.get("repository") != "https://github.com/openpacketcore/openpacketcore-sdk":
        errors.append("publication repository mismatch")
    if publication.get("runtime_claim") is True:
        errors.append("publication must not claim runtime")
    if "do not prove external interoperability" not in publication.get(
        "interoperability_note", ""
    ):
        errors.append("publication missing interoperability limit")
    head = publication.get("head", "")
    tree = publication.get("tree", "")
    if head != "landing-revision" and not (
        isinstance(head, str) and len(head) == 40 and all(ch in "0123456789abcdef" for ch in head)
    ):
        errors.append("publication head is not a public SHA or landing-revision")
    if tree and not (
        isinstance(tree, str) and len(tree) == 40 and all(ch in "0123456789abcdef" for ch in tree)
    ):
        errors.append("publication tree is not a 40-hex object id")

    for subset in SUBSETS:
        directory = FIXTURE_ROOT / subset
        completion = load_json(directory / "COMPLETION.json")
        if completion.get("status") != "complete" or completion.get("runtime_claim") is not False:
            errors.append(f"{subset}: completion is not dependable")
        if set(REQUIRED) - set(completion.get("case_classes", [])):
            errors.append(f"{subset}: completion missing required case classes")
        classes = set()
        for path in sorted(directory.glob("*.json")):
            if path.name == "COMPLETION.json":
                continue
            manifest = load_json(path)
            required_fields = (
                "sdk_fixture_id",
                "source",
                "direction",
                "role",
                "prerequisite",
                "provenance",
                "sanitized_fields",
                "wire",
                "semantic_assertions",
                "expected_outcome",
            )
            for field in required_fields:
                if not manifest.get(field):
                    errors.append(f"{path.name}: missing {field}")
            if manifest.get("runtime_claim") is not False:
                errors.append(f"{path.name}: runtime_claim must be false")
            classes.add(manifest.get("case_class"))
            text = path.read_text(encoding="utf-8").lower()
            if "aaron" in text or "chartier" in text or "-----begin" in text:
                errors.append(f"{path.name}: forbidden content")
            wire_rel = (manifest.get("wire") or {}).get("path")
            digest = (manifest.get("wire") or {}).get("digest_sha256")
            if not wire_rel or not digest:
                errors.append(f"{path.name}: missing wire locator")
                continue
            wire_path = directory / wire_rel
            if not wire_path.is_file():
                errors.append(f"{path.name}: missing wire file")
                continue
            tokens = wire_path.read_text(encoding="utf-8").split()
            try:
                raw = bytes(int(token, 16) for token in tokens)
            except ValueError:
                errors.append(f"{path.name}: unreadable wire hex")
                continue
            if hashlib.sha256(raw).hexdigest() != digest:
                errors.append(f"{path.name}: digest mismatch")
        if REQUIRED - classes:
            errors.append(f"{subset}: missing {sorted(REQUIRED - classes)}")
        readme = directory / "README.md"
        if readme.is_file():
            data = readme.read_bytes()
            if data.endswith(b"\n\n") or not data.endswith(b"\n"):
                errors.append(f"{subset}: README has invalid trailing newlines")

    ngap_completion = load_json(FIXTURE_ROOT / "ngap" / "COMPLETION.json")
    if not ngap_completion.get("admitted_outcomes") or not ngap_completion.get("matrices"):
        errors.append("ngap: missing admitted_outcomes or matrices")
    for rel in ngap_completion.get("matrices", []):
        matrix_path = FIXTURE_ROOT / "ngap" / rel
        if not matrix_path.is_file():
            errors.append(f"ngap: missing matrix {rel}")
            continue
        matrix = load_json(matrix_path)
        if not matrix.get("ies") or not matrix.get("message"):
            errors.append(f"{rel}: incomplete matrix")
        if matrix.get("source", {}).get("release") != "V18.10.0":
            errors.append(f"{rel}: TS 38.413 release must be V18.10.0")
        if matrix.get("application", {}).get("release") != "V18.5.0":
            errors.append(f"{rel}: TS 29.413 release must be V18.5.0")
        if matrix.get("constructed_send") is True:
            errors.append(f"{rel}: constructed send must stay unsupported")
        if "5.3 RAN-specific ignore is not encoded" not in matrix.get(
            "n3iwf_content_exceptions", ""
        ):
            errors.append(f"{rel}: missing 5.3 non-encoding note")
    if "first-cnf-typed-subset" not in ngap_completion.get("admission_scope", ""):
        errors.append("ngap: admission_scope must stay first-CNF typed subset")

    def has_id_fragment(subset: str, fragment: str) -> bool:
        return any(
            fragment in path.name
            for path in (FIXTURE_ROOT / subset).glob("*.json")
            if path.name != "COMPLETION.json"
        )

    for subset, fragment in (
        ("eap5g", "positive-notification"),
        ("eap5g", "positive-stop"),
        ("nwu-ike", "create-child-sa"),
        ("nwu-ike", "modify-child-sa"),
        ("nas-tcp", "eof-loss-incomplete-frame"),
        ("n2-dtls", "reliable-delivery-data"),
        ("n2-dtls", "rotation-generation-3"),
        ("ngap", "unsupported-paging-5-4"),
    ):
        if not has_id_fragment(subset, fragment):
            errors.append(f"{subset}: missing {fragment}")
    return errors


def self_test() -> int:
    result = subprocess.run(
        [sys.executable, str(GENERATOR), "--self-test"],
        cwd=ROOT,
        check=False,
    )
    if result.returncode != 0:
        return result.returncode
    errors = check_catalog()
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    if (ROOT / ".git").exists():
        diff = subprocess.run(
            ["git", "diff", "--exit-code", "--", str(FIXTURE_ROOT)],
            cwd=ROOT,
            check=False,
        )
        if diff.returncode != 0:
            print("generator rewrote committed N3IWF fixtures", file=sys.stderr)
            return 1
    print("check-n3iwf-fixture-contracts self-test ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    errors = check_catalog()
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("n3iwf fixture contracts ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
