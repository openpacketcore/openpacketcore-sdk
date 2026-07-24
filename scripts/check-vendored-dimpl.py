#!/usr/bin/env python3
"""Prove external SDK consumers resolve the audited vendored dimpl fork."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path


def main() -> None:
    repo = Path(__file__).resolve().parent.parent
    expected_manifest = (repo / "vendor" / "dimpl" / "Cargo.toml").resolve()

    with tempfile.TemporaryDirectory(prefix="opc-dimpl-consumer-") as temp:
        consumer = Path(temp)
        manifest = consumer / "Cargo.toml"
        source = consumer / "src" / "lib.rs"
        source.parent.mkdir()
        manifest.write_text(
            "\n".join(
                (
                    "[package]",
                    'name = "opc-dimpl-consumer-probe"',
                    'version = "0.0.0"',
                    'edition = "2021"',
                    "",
                    "[dependencies]",
                    (
                        'opc-diameter-transport = { path = "'
                        f'{(repo / "crates" / "opc-diameter-transport").as_posix()}'
                        '" }'
                    ),
                    "",
                )
            ),
            encoding="utf-8",
        )
        source.write_text(
            "pub use opc_diameter_transport::MAX_DTLS_SCTP_MESSAGE_BYTES;\n",
            encoding="utf-8",
        )

        metadata = subprocess.run(
            (
                "cargo",
                "metadata",
                "--format-version",
                "1",
                "--manifest-path",
                str(manifest),
            ),
            check=True,
            capture_output=True,
            text=True,
        )
        graph = json.loads(metadata.stdout)
        packages = graph["packages"]
        dimpl = [package for package in packages if package["name"] == "dimpl"]
        if len(dimpl) != 1:
            raise SystemExit(
                f"expected exactly one dimpl package, resolved {len(dimpl)}"
            )

        resolved_manifest = Path(dimpl[0]["manifest_path"]).resolve()
        if resolved_manifest != expected_manifest:
            raise SystemExit(
                "external consumer did not resolve the audited vendored dimpl: "
                f"{resolved_manifest}"
            )
        if dimpl[0]["version"] != "0.7.2" or dimpl[0]["source"] is not None:
            raise SystemExit(
                "external consumer resolved an unpinned or registry-backed dimpl"
            )
        resolved_nodes = [
            node
            for node in graph["resolve"]["nodes"]
            if node["id"] == dimpl[0]["id"]
        ]
        if len(resolved_nodes) != 1:
            raise SystemExit("external consumer has no unique resolved dimpl node")
        features = set(resolved_nodes[0]["features"])
        if "rust-crypto" not in features or features.intersection(
            {"aws-lc-rs", "rcgen"}
        ):
            raise SystemExit(
                "external consumer did not retain the audited RustCrypto-only "
                f"dimpl feature contract: {sorted(features)}"
            )

        subprocess.run(
            (
                "cargo",
                "check",
                "--manifest-path",
                str(manifest),
            ),
            check=True,
        )


if __name__ == "__main__":
    main()
