#!/usr/bin/env python3
"""Independent root GUAMI, allowed-slice and construction-only security masks."""

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
    rows = []
    with tempfile.TemporaryDirectory(
        prefix="ngap-context-field-reference-"
    ) as temporary:
        ref = compile_reference(args.spec.read_bytes(), Path(temporary))

        def field(kind, value, model):
            target = getattr(ref.schema.NGAP_IEs, kind)
            target.set_val(value)
            wire = target.to_aper()
            target.from_aper(wire)
            assert target.get_val() == value
            rows.append(
                {
                    "type": kind,
                    "model": model,
                    "wire_hex": wire.hex(),
                    "wire_sha256": hashlib.sha256(wire).hexdigest(),
                }
            )

        for network, plmn in (
            ("001-01", bytes.fromhex("00f110")),
            ("310-260", bytes.fromhex("130062")),
        ):
            for region, amf_set, pointer in (
                (0, 0, 0),
                (255, 1023, 63),
                (128, 512, 32),
                (1, 1, 1),
            ):
                model = {
                    "plmn": network,
                    "region": region,
                    "set": amf_set,
                    "pointer": pointer,
                }
                field(
                    "GUAMI",
                    {
                        "pLMNIdentity": plmn,
                        "aMFRegionID": (region, 8),
                        "aMFSetID": (amf_set, 10),
                        "aMFPointer": (pointer, 6),
                    },
                    model,
                )
        for count in range(1, 9):
            for mode in range(3):
                model = [
                    {
                        "sst": (i * 37) % 256,
                        "sd": (
                            f"{i*0x234567:06x}"
                            if (mode == 2 or (mode == 1 and i % 2))
                            else None
                        ),
                    }
                    for i in range(count)
                ]
                value = [
                    {
                        "s-NSSAI": {
                            "sST": bytes([item["sst"]]),
                            **(
                                {"sD": bytes.fromhex(item["sd"])}
                                if item["sd"] is not None
                                else {}
                            ),
                        }
                    }
                    for item in model
                ]
                field("AllowedNSSAI", value, model)
        names = (
            "nRencryptionAlgorithms",
            "nRintegrityProtectionAlgorithms",
            "eUTRAencryptionAlgorithms",
            "eUTRAintegrityProtectionAlgorithms",
        )
        masks = [[0] * 4, [65535] * 4]
        for group in range(4):
            for shift in range(16):
                values = [0] * 4
                values[group] = 1 << shift
                masks.append(values)
        for model in masks:
            field(
                "UESecurityCapabilities",
                {name: (value, 16) for name, value in zip(names, model)},
                model,
            )
    args.output.write_text(
        json.dumps(
            {"source_sha256": SPEC_SHA256, "reference_tools": VERSIONS, "fields": rows},
            indent=2,
        )
        + "\n"
    )
    print("Wrote", len(rows), "independent context fields")


if __name__ == "__main__":
    main()
