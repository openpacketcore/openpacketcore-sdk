#!/usr/bin/env python3
"""Regenerate crates/opc-proto-ngap/src/generated.rs from 3GPP NGAP ASN.1.

Inputs are fetched from Wireshark's asn1/ngap dissector files. The output is
patched to work around rasn-compiler 0.16 import-emission issues, then
formatted and written to the crate source tree.

Requires `rasn_compiler_cli` (cargo install rasn-compiler --features cli).
"""

import argparse
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

WIRESHARK_BASE = (
    "https://raw.githubusercontent.com/wireshark/wireshark/{sha}/epan/dissectors/asn1/ngap"
)
ASN_FILES = [
    "NGAP-CommonDataTypes.asn",
    "NGAP-Constants.asn",
    "NGAP-Containers.asn",
    "NGAP-IEs.asn",
    "NGAP-PDU-Contents.asn",
    "NGAP-PDU-Descriptions.asn",
]
PINNED_WIRESHARK_SHA = "d296f939b42891994714939384adc3deaef3f180"


def fetch_asn(sha: str, out_dir: Path) -> None:
    for name in ASN_FILES:
        url = f"{WIRESHARK_BASE.format(sha=sha)}/{name}"
        dest = out_dir / name
        with urllib.request.urlopen(url) as resp, dest.open("wb") as f:
            f.write(resp.read())


def run_compiler(asn_dir: Path, output: Path) -> None:
    rasn_compiler = shutil.which("rasn_compiler_cli")
    if rasn_compiler is None:
        print("error: rasn_compiler_cli not found; run:", file=sys.stderr)
        print("  cargo install rasn-compiler --features cli", file=sys.stderr)
        sys.exit(1)

    subprocess.run(
        [rasn_compiler, "-d", str(asn_dir), "-o", str(output)],
        check=True,
    )


def run_rustfmt(output: Path) -> None:
    rustfmt = shutil.which("rustfmt")
    if rustfmt is None:
        print("error: rustfmt not found; install the Rust rustfmt component", file=sys.stderr)
        sys.exit(1)

    subprocess.run([rustfmt, str(output)], check=True)


def patch_generated(source: Path) -> str:
    text = source.read_text()

    # rasn-compiler 0.16 omits PrivateIEID and ProtocolExtensionID imports in
    # ngap_pdu_contents and ngap_ies. Add them so the generated bindings compile.
    text = text.replace(
        "use super::ngap_common_data_types::{Criticality, Presence, ProtocolIEID};",
        "use super::ngap_common_data_types::{Criticality, Presence, PrivateIEID, ProtocolIEID};",
    )
    text = text.replace(
        "use super::ngap_common_data_types::{\n        Criticality, ProcedureCode, ProtocolIEID, TriggeringMessage,\n    };",
        "use super::ngap_common_data_types::{\n        Criticality, Presence, PrivateIEID, ProcedureCode, ProtocolExtensionID, ProtocolIEID,\n        TriggeringMessage,\n    };",
    )

    # Allow clippy and missing-docs lints in generated code.
    text = '#![allow(clippy::all, missing_docs)]\n\n' + text
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--wireshark-sha",
        default=PINNED_WIRESHARK_SHA,
        help=(
            "Wireshark Git SHA to fetch ASN.1 files from "
            f"(default: pinned {PINNED_WIRESHARK_SHA})"
        ),
    )
    parser.add_argument(
        "--output",
        default="crates/opc-proto-ngap/src/generated.rs",
        help="Output path for generated bindings",
    )
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        asn_dir = Path(tmp) / "asn"
        asn_dir.mkdir()
        raw_output = Path(tmp) / "generated.rs"

        print(f"Fetching ASN.1 files from Wireshark {args.wireshark_sha} ...")
        fetch_asn(args.wireshark_sha, asn_dir)

        print("Running rasn-compiler ...")
        run_compiler(asn_dir, raw_output)
        run_rustfmt(raw_output)

        print("Patching generated imports ...")
        patched = patch_generated(raw_output)

        print(f"Writing {output} ...")
        output.write_text(patched)
        run_rustfmt(output)

    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
