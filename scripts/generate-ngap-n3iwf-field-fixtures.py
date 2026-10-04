#!/usr/bin/env python3
"""Reproduce synthetic N3IWF leaf vectors from the independent Release 18 ASN.1.

No SDK encoder, decoder or generated Rust schema is used. The PDF, compiler
versions and six extracted modules are checked by the existing oracle loader.
"""

import argparse
import hashlib
import ipaddress
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
    with tempfile.TemporaryDirectory(prefix="ngap-field-reference-") as temporary:
        reference = compile_reference(args.spec.read_bytes(), Path(temporary))

        def record(name, asn_name, value, recipe):
            field = getattr(reference.schema.NGAP_IEs, asn_name)
            field.set_val(value)
            wire = field.to_aper()
            row = {
                "name": name,
                "type": asn_name,
                "recipe": recipe,
                "wire_len": len(wire),
                "wire_sha256": hashlib.sha256(wire).hexdigest(),
            }
            if len(wire) <= 128:
                row["wire_hex"] = wire.hex()
            cases.append(row)

        for field, sizes in (
            (
                "RAN_UE_NGAP_ID",
                (0, 1, 255, 256, 65535, 65536, 16777215, 16777216, 4294967295),
            ),
            (
                "AMF_UE_NGAP_ID",
                (
                    0,
                    1,
                    255,
                    256,
                    65535,
                    65536,
                    16777215,
                    16777216,
                    4294967295,
                    4294967296,
                    1099511627775,
                ),
            ),
        ):
            for index, value in enumerate(sizes):
                record(f"{field}-{index}", field, value, {"integer": value})
        for size in (
            0,
            1,
            127,
            128,
            16383,
            16384,
            16385,
            32768,
            65535,
            65536,
            65537,
            131072,
        ):
            raw = bytes((i * 17 + 3) % 256 for i in range(size))
            record(
                f"nas-{size}",
                "NAS_PDU",
                raw,
                {"length": size, "octet": "(i * 17 + 3) % 256"},
            )
        key = bytes(range(32))
        record(
            "security-key-nonzero",
            "SecurityKey",
            (int.from_bytes(key, "big"), 256),
            {"octet": "i"},
        )
        for mnc, plmn in (
            ("01", bytes.fromhex("00f110")),
            ("001", bytes.fromhex("001100")),
        ):
            tai = {"pLMNIdentity": plmn, "tAC": bytes.fromhex("000001")}
            record(
                f"tai-{mnc}", "TAI", tai, {"mcc": "001", "mnc": mnc, "tac": "000001"}
            )
            for address in ("192.0.2.1", "2001:db8::1"):
                ip = ipaddress.ip_address(address)
                for port in (None, 4500):
                    for with_tai in (False, True):
                        body = {"iPAddress": (int(ip), ip.max_prefixlen)}
                        if port is not None:
                            body["portNumber"] = port.to_bytes(2, "big")
                            if with_tai:
                                body["iE-Extensions"] = [
                                    {
                                        "id": 213,
                                        "criticality": "ignore",
                                        "extensionValue": ("TAI", tai),
                                    }
                                ]
                            value = (
                                "userLocationInformationN3IWF-with-PortNumber",
                                body,
                            )
                        else:
                            if with_tai:
                                body["tAI"] = tai
                            value = (
                                "choice-Extensions",
                                {
                                    "id": 439,
                                    "criticality": "ignore",
                                    "value": (
                                        "UserLocationInformationN3IWF-without-PortNumber",
                                        body,
                                    ),
                                },
                            )
                        record(
                            f"location-{mnc}-{ip.version}-{port}-{with_tai}",
                            "UserLocationInformation",
                            value,
                            {
                                "address": address,
                                "port": port,
                                "tai": with_tai,
                                "mcc": "001",
                                "mnc": mnc,
                            },
                        )
    args.output.write_text(
        json.dumps(
            {
                "source_sha256": SPEC_SHA256,
                "reference_tools": VERSIONS,
                "scope": "Synthetic individual IE values; no complete procedure admission",
                "cases": cases,
            },
            indent=2,
        )
        + "\n"
    )
    print(f"Produced {len(cases)} independent field cases")


if __name__ == "__main__":
    main()
