#!/usr/bin/env python3
"""Repository gate for N3IWF fixture contracts (issue 784)."""

from __future__ import annotations

import argparse
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
            if manifest.get("runtime_claim") is not False:
                errors.append(f"{path.name}: runtime_claim must be false")
            classes.add(manifest.get("case_class"))
            text = path.read_text(encoding="utf-8").lower()
            if "aaron" in text or "chartier" in text or "-----begin" in text:
                errors.append(f"{path.name}: forbidden content")
        if REQUIRED - classes:
            errors.append(f"{subset}: missing {sorted(REQUIRED - classes)}")
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
