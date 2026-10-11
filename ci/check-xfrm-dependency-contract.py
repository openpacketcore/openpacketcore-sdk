#!/usr/bin/env python3
"""Keep local kernel consumers independent of optional storage and transport."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STORE_PACKAGES = {
    "opc-session-store", "opc-consensus", "opc-persist", "rusqlite", "libsqlite3-sys",
}
TRANSPORT_PACKAGES = {"opc-session-net"}
TLS_PACKAGES = {"opc-tls"}


def packages(package: str, features: list[str]) -> set[str]:
    tree = subprocess.check_output(
        [
            "cargo", "tree", "--locked", "--package", package,
            "--edges", "normal,build", "--prefix", "none", "--format", "{p}",
            *features,
        ],
        cwd=ROOT,
        text=True,
    )
    names = {line.split()[0] for line in tree.splitlines() if line.strip()}
    if package not in names:
        raise SystemExit(f"the {package} dependency graph was not resolved")
    if package == "opc-ipsec-xfrm" and "opc-linux-xfrm-sys" not in names:
        raise SystemExit("the XFRM dependency graph lost its native backend")
    return names


def main() -> None:
    for label, features in [
        ("default", []),
        ("ikev2", ["--features", "ikev2"]),
    ]:
        unexpected = packages("opc-ipsec-xfrm", features) & (
            STORE_PACKAGES | TRANSPORT_PACKAGES | TLS_PACKAGES
        )
        if unexpected:
            raise SystemExit(f"XFRM {label} pulls in durable storage: {sorted(unexpected)}")
        print(f"XFRM {label}: no store, consensus or SQLite build dependency")
    enabled = packages("opc-ipsec-xfrm", ["--features", "scope-store"])
    if not {"opc-local-kernel-lifecycle", "opc-session-store"} <= enabled:
        raise SystemExit("the explicit scope-store feature lost its store adapter")
    print("XFRM scope-store: the durable scope adapter is explicitly enabled")
    for package, modes in [
        ("opc-ipsec-xfrm", ["scope-store"]),
        ("opc-local-kernel-lifecycle", ["store"]),
        ("opc-gtpu-dataplane", [""]),
    ]:
        for mode in modes:
            features = ["--features", mode] if mode else []
            unexpected = packages(package, features) & TRANSPORT_PACKAGES
            if unexpected:
                raise SystemExit(f"{package} {mode or 'default'} pulls in native transport: {sorted(unexpected)}")
            print(f"{package} {mode or 'default'}: no native scope transport dependency")
    # The existing store adapter already reaches TLS through opc-key. Only the
    # default lifecycle/XFRM graphs are TLS-free; native-scope must remain the
    # explicit switch for the new scope transport in every consumer.
    unexpected = packages("opc-local-kernel-lifecycle", []) & (
        STORE_PACKAGES | TRANSPORT_PACKAGES | TLS_PACKAGES
    )
    if unexpected:
        raise SystemExit(f"default lifecycle pulls in storage or transport: {sorted(unexpected)}")
    print("default lifecycle: no store, native scope transport or TLS dependency")
    for package in ["opc-local-kernel-lifecycle", "opc-ipsec-xfrm", "opc-gtpu-dataplane"]:
        enabled = packages(package, ["--features", "native-scope"])
        if not {
            "opc-local-kernel-lifecycle", "opc-session-store", *TRANSPORT_PACKAGES, *TLS_PACKAGES,
        } <= enabled:
            raise SystemExit(f"{package} native-scope lost the concrete authenticated adapter")
        print(f"{package} native-scope: the authenticated transport is explicitly enabled")


if __name__ == "__main__":
    main()
