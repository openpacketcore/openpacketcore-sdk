#!/usr/bin/env python3
"""Keep ordinary XFRM consumers independent of the durable scope store."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STORE_PACKAGES = {
    "opc-session-store", "opc-consensus", "opc-persist", "rusqlite", "libsqlite3-sys",
}


def packages(features: list[str]) -> set[str]:
    tree = subprocess.check_output(
        [
            "cargo", "tree", "--locked", "--package", "opc-ipsec-xfrm",
            "--edges", "normal,build", "--prefix", "none", "--format", "{p}",
            *features,
        ],
        cwd=ROOT,
        text=True,
    )
    names = {line.split()[0] for line in tree.splitlines() if line.strip()}
    if "opc-ipsec-xfrm" not in names or "opc-linux-xfrm-sys" not in names:
        raise SystemExit("the XFRM dependency graph was not resolved")
    return names


def main() -> None:
    for label, features in [
        ("default", []),
        ("ikev2", ["--features", "ikev2"]),
    ]:
        unexpected = packages(features) & STORE_PACKAGES
        if unexpected:
            raise SystemExit(f"XFRM {label} pulls in durable storage: {sorted(unexpected)}")
        print(f"XFRM {label}: no store, consensus or SQLite build dependency")
    enabled = packages(["--features", "scope-store"])
    if not {"opc-local-kernel-lifecycle", "opc-session-store"} <= enabled:
        raise SystemExit("the explicit scope-store feature lost its store adapter")
    print("XFRM scope-store: the durable scope adapter is explicitly enabled")


if __name__ == "__main__":
    main()
