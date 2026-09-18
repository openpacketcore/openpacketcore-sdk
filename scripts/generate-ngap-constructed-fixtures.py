#!/usr/bin/env python3
"""Reproduce NGAP container length/fragmentation evidence with independent PER.

Requires the pinned local Release 18 PDF and the oracle's exact tool versions.
No SDK encoder, decoder or generated Rust schema is used. These are structural
containers with an unknown ignore-criticality IE, not complete NGAP procedures.
"""

import argparse
import hashlib
import json
from pathlib import Path
import tempfile

from n3iwf_ngap_reference import SPEC_SHA256, VERSIONS, compile_reference


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cases = []
    with tempfile.TemporaryDirectory(prefix="ngap-constructed-reference-") as temporary:
        reference = compile_reference(args.spec.read_bytes(), Path(temporary))
        for outcome, message in (
            ("initiatingMessage", "NGSetupRequest"),
            ("successfulOutcome", "NGSetupResponse"),
            ("unsuccessfulOutcome", "NGSetupFailure"),
        ):
            for size in (
                0,
                1,
                120,
                121,
                127,
                128,
                16375,
                16376,
                16383,
                16384,
                16385,
                32767,
                32768,
                49152,
                65535,
                65536,
                65537,
                131072,
            ):
                value = bytes((index * 17 + 3) % 256 for index in range(size))
                pdu = (
                    outcome,
                    {
                        "procedureCode": 21,
                        "criticality": "reject",
                        "value": (
                            message,
                            {
                                "protocolIEs": [
                                    {
                                        "id": 65535,
                                        "criticality": "ignore",
                                        "value": ("_unk_004", value),
                                    }
                                ]
                            },
                        ),
                    },
                )
                wire = reference.encode(pdu)
                cases.append(
                    {
                        "message": message,
                        "value_len": size,
                        "wire_len": len(wire),
                        "wire_sha256": hashlib.sha256(wire).hexdigest(),
                    }
                )
    output = {
        "schema_version": 1,
        "source_sha256": SPEC_SHA256,
        "reference_tools": VERSIONS,
        "scope": "Root NGAP-PDU and ProtocolIE-Container APER framing only; no semantic admission",
        "ie_id": 65535,
        "ie_criticality": "ignore",
        "value_recipe": "octet[i] = (i * 17 + 3) % 256",
        "cases": cases,
    }
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print(f"Produced {len(cases)} independent structural framing cases")


if __name__ == "__main__":
    main()
