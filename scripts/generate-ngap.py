#!/usr/bin/env python3
"""Regenerate crates/opc-proto-ngap/src/generated.rs from 3GPP NGAP ASN.1.

Inputs are fetched from Wireshark's asn1/ngap dissector files. The output is
patched to work around rasn-compiler 0.16 import-emission issues, then
formatted and written to the crate source tree.

Requires `rasn_compiler_cli` (cargo install rasn-compiler --features cli).
"""

import argparse
import hashlib
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

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
FETCH_RETRIES = 5
FETCH_TRANSIENT_HTTP_STATUS = {429, 500, 502, 503, 504}
FETCH_USER_AGENT = "openpacketcore-sdk-ngap-generator/1.0"
EXPECTED_ASN_SHA256 = {
    "NGAP-CommonDataTypes.asn": "03b1692171ec9f3c999a444eae6f82e4b10f9c02d8d81b5765dd67dbe6ce1b6c",
    "NGAP-Constants.asn": "bcd1e18bd11a40e805c25c4b54a8b7cd2fa963e452d690f2afb6219d8d202d2f",
    "NGAP-Containers.asn": "69a44bef80e3f720b6e89d5c8f97507b5a062bb5da7de19e8cfc8a5710766a48",
    "NGAP-IEs.asn": "b9b0e24422c1c23dbbe7495fda56dd10b0f79e43bd86350319091e15b6ced90b",
    "NGAP-PDU-Contents.asn": "0d620cbd5fec5ba2c54a222e1b4a483cdeb5fad549ac0aaf71ae69a8b29c0d5a",
    "NGAP-PDU-Descriptions.asn": "9d37156b97c412468420b2682761f4ebd216d30c972a334eb70e66385413ef82",
}


def verify_asn(name: str, data: bytes) -> None:
    expected = EXPECTED_ASN_SHA256.get(name)
    if expected is None:
        raise SystemExit(f"error: missing expected SHA-256 for {name}")
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise SystemExit(
            f"error: hash mismatch for {name}: expected {expected}, got {actual}"
        )


def fetch_asn(sha: str, out_dir: Path) -> None:
    for name in ASN_FILES:
        url = f"{WIRESHARK_BASE.format(sha=sha)}/{name}"
        dest = out_dir / name
        data = fetch_url(url)
        verify_asn(name, data)
        dest.write_bytes(data)


def fetch_url(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": FETCH_USER_AGENT})
    for attempt in range(FETCH_RETRIES):
        try:
            with urllib.request.urlopen(request, timeout=30) as resp:
                return resp.read()
        except urllib.error.HTTPError as error:
            if error.code not in FETCH_TRANSIENT_HTTP_STATUS or attempt == FETCH_RETRIES - 1:
                raise
            retry_after = retry_after_seconds(error)
            delay = retry_after if retry_after is not None else 2**attempt
        except urllib.error.URLError:
            if attempt == FETCH_RETRIES - 1:
                raise
            delay = 2**attempt

        print(
            f"warning: transient fetch failure for {url}; retrying in {delay}s",
            file=sys.stderr,
        )
        time.sleep(delay)

    raise RuntimeError(f"unreachable fetch retry state for {url}")


def retry_after_seconds(error: urllib.error.HTTPError) -> Optional[int]:
    retry_after = error.headers.get("Retry-After")
    if retry_after is None:
        return None
    try:
        return max(0, min(int(retry_after), 60))
    except ValueError:
        return None


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
    text = replace_required(
        text,
        "use super::ngap_common_data_types::{Criticality, Presence, ProtocolIEID};",
        "use super::ngap_common_data_types::{Criticality, Presence, PrivateIEID, ProtocolIEID};",
        "ngap_pdu_contents PrivateIEID import",
    )
    text = replace_required(
        text,
        "use super::ngap_common_data_types::{\n        Criticality, ProcedureCode, ProtocolIEID, TriggeringMessage,\n    };",
        "use super::ngap_common_data_types::{\n        Criticality, Presence, PrivateIEID, ProcedureCode, ProtocolExtensionID, ProtocolIEID,\n        TriggeringMessage,\n    };",
        "ngap_ies private/protocol extension imports",
    )

    # Allow clippy and missing-docs lints in generated code.
    text = '#![allow(clippy::all, missing_docs)]\n\n' + text
    return text


def replace_required(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        raise SystemExit(f"error: generated patch did not match: {label}")
    return text.replace(old, new)


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
