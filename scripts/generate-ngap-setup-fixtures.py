#!/usr/bin/env python3
"""Independent Release 18 NG Setup root fields and complete messages."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import tempfile

from n3iwf_ngap_reference import (
    Invalid,
    SPEC_SHA256,
    VERSIONS,
    compile_reference,
    unpack,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    published = json.loads(
        (
            root / "crates/opc-n3iwf-fixtures/oracles/ngap-rel18-messages.json"
        ).read_text()
    )
    recipes = {}
    for name in (
        "complete-ng-setup-request",
        "complete-ng-setup-response",
        "complete-ng-setup-failure",
    ):
        row = next(row for row in published["cases"] if row["name"] == name)
        recipes[row["message"]] = row["pdu"]
    fields, messages = [], []

    def entries(recipe):
        return recipe["value"]["value"]["value"]["protocolIEs"]

    def plmn(value):
        mcc, mnc = value.split("-")
        return bytes(
            (
                int(mcc[1] + mcc[0], 16),
                int(("f" if len(mnc) == 2 else mnc[2]) + mcc[2], 16),
                int(mnc[1] + mnc[0], 16),
            )
        )

    def slices(model):
        return [
            {
                "s-NSSAI": {
                    "sST": bytes([row["sst"]]),
                    **(
                        {"sD": bytes.fromhex(row["sd"])}
                        if row.get("sd") is not None
                        else {}
                    ),
                }
            }
            for row in model
        ]

    def plmns(model, key):
        return [
            {"pLMNIdentity": plmn(row["plmn"]), key: slices(row["slices"])}
            for row in model
        ]

    def value(kind, model):
        if kind == "GlobalRANNodeID":
            return (
                "globalN3IWF-ID",
                {
                    "pLMNIdentity": plmn(model["plmn"]),
                    "n3IWF-ID": ("n3IWF-ID", (model["id"], 16)),
                },
            )
        if kind == "SupportedTAList":
            return [
                {
                    "tAC": bytes.fromhex(row["tac"]),
                    "broadcastPLMNList": plmns(row["plmns"], "tAISliceSupportList"),
                }
                for row in model
            ]
        if kind == "PLMNSupportList":
            return plmns(model, "sliceSupportList")
        if kind == "ServedGUAMIList":
            return [
                {
                    "gUAMI": {
                        "pLMNIdentity": plmn(row["plmn"]),
                        "aMFRegionID": (row["region"], 8),
                        "aMFSetID": (row["set"], 10),
                        "aMFPointer": (row["pointer"], 6),
                    }
                }
                for row in model
            ]
        return model

    def record(wire):
        return {"wire_hex": wire.hex(), "wire_sha256": hashlib.sha256(wire).hexdigest()}

    with tempfile.TemporaryDirectory(prefix="ngap-setup-reference-") as temporary:
        reference = compile_reference(args.spec.read_bytes(), Path(temporary))

        def message(name, recipe, **attributes):
            wire = reference.encode(unpack(recipe))
            error = None
            try:
                reference.decode(wire)
            except Invalid as exc:
                error = str(exc)
            messages.append(
                {
                    "name": name,
                    "message": recipe["value"]["value"]["type"],
                    "reference_error": error,
                    **record(wire),
                    **attributes,
                }
            )

        for kind, original in recipes.items():
            message(f"base-{kind}", original, construct=True)
            for row in reference.rows(kind):
                if row["presence"] == "mandatory":
                    recipe = copy.deepcopy(original)
                    entries(recipe)[:] = [
                        ie for ie in entries(recipe) if ie["id"] != row["id"]
                    ]
                    message(f"missing-{kind}-{row['id']}", recipe, missing_id=row["id"])
                    assert messages[-1]["reference_error"] == "missing-mandatory-ie"
            recipe = copy.deepcopy(original)
            entries(recipe).insert(0, copy.deepcopy(entries(recipe)[0]))
            message(f"duplicate-{kind}", recipe, duplicate=True)
            assert messages[-1]["reference_error"] == "duplicate-ie"
            for criticality in ("ignore", "notify", "reject"):
                recipe = copy.deepcopy(original)
                entries(recipe).append(
                    {
                        "id": 65530,
                        "criticality": criticality,
                        "value": {"type": "_unk_004", "value": {"hex": "abcd"}},
                    }
                )
                message(
                    f"unknown-{kind}-{criticality}",
                    recipe,
                    unknown_criticality=criticality,
                )
                assert messages[-1]["reference_error"] == (
                    "unknown-critical-ie" if criticality == "reject" else None
                )

        def field(kind, model, message_kind, ie_id):
            name = f"{kind}-{len(fields)}"
            target = getattr(reference.schema.NGAP_IEs, kind)
            target.set_val(value(kind, model))
            wire = target.to_aper()
            target.from_aper(wire)
            assert target.get_val() == value(kind, model)
            fields.append({"name": name, "type": kind, "model": model, **record(wire)})
            # The complete-message encoder consumes the independent typed value,
            # rather than inserting the just-produced bytes as an opaque IE.
            typed = unpack(copy.deepcopy(recipes[message_kind]))
            ies = typed[1]["value"][1]["protocolIEs"]
            next(ie for ie in ies if ie["id"] == ie_id)["value"] = (
                kind,
                value(kind, model),
            )
            encoded = reference.encode(typed)
            reference.decode(encoded)
            messages.append(
                {
                    "name": name,
                    "message": message_kind,
                    "reference_error": None,
                    "construct": True,
                    "field_index": len(fields) - 1,
                    **record(encoded),
                }
            )

        for network in ("001-01", "310-260"):
            for identifier in (0, 1, 127, 128, 255, 256, 32767, 32768, 65535):
                field(
                    "GlobalRANNodeID",
                    {"plmn": network, "id": identifier},
                    "NGSetupRequest",
                    27,
                )
        for count in (1, 2, 256):
            model = [
                {
                    "plmn": "001-01" if i % 2 == 0 else "310-260",
                    "region": (i * 255) % 256,
                    "set": (i * 1023) % 1024,
                    "pointer": (i * 63) % 64,
                }
                for i in range(count)
            ]
            field("ServedGUAMIList", model, "NGSetupResponse", 96)
        for count in (1, 2, 3, 15, 16, 255, 256, 1023, 1024):
            model = [
                {
                    "plmn": "310-260",
                    "slices": [
                        {"sst": i % 256, "sd": f"{i:06x}" if i % 3 else None}
                        for i in range(count)
                    ],
                }
            ]
            field("PLMNSupportList", model, "NGSetupResponse", 80)
            field(
                "SupportedTAList",
                [{"tac": "fedcba", "plmns": model}],
                "NGSetupRequest",
                102,
            )
        for count in (2, 12):
            model = [
                {
                    "plmn": "001-01" if i % 2 else "310-260",
                    "slices": [
                        {"sst": 255, "sd": "ffffff"},
                        {"sst": 0, "sd": None},
                        {"sst": 1, "sd": "000000"},
                    ],
                }
                for i in range(count)
            ]
            field("PLMNSupportList", model, "NGSetupResponse", 80)
            field(
                "SupportedTAList",
                [
                    {"tac": "000000", "plmns": model},
                    {"tac": "ffffff", "plmns": list(reversed(model))},
                ],
                "NGSetupRequest",
                102,
            )
        model = [
            {
                "tac": f"{i:06x}",
                "plmns": [{"plmn": "001-01", "slices": [{"sst": i % 256, "sd": None}]}],
            }
            for i in range(256)
        ]
        field("SupportedTAList", model, "NGSetupRequest", 102)
        for name in ("a", "z" * 150, "AZaz09 '()+,-./:=?"):
            field("AMFName", name, "NGSetupResponse", 1)
        for capacity in (0, 1, 127, 128, 254, 255):
            field("RelativeAMFCapacity", capacity, "NGSetupResponse", 86)
        for paging in ("v32", "v64", "v128", "v256"):
            field("PagingDRX", paging, "NGSetupRequest", 21)
        for delay in ("v1s", "v2s", "v5s", "v10s", "v20s", "v60s"):
            field("TimeToWait", delay, "NGSetupFailure", 107)
        recipe = copy.deepcopy(recipes["NGSetupFailure"])
        entries(recipe)[:] = [ie for ie in entries(recipe) if ie["id"] != 107]
        message("failure-without-wait", recipe, construct=True, no_wait=True)
        assert all(
            row["reference_error"] is None for row in messages if row.get("construct")
        )
    args.output.write_text(
        json.dumps(
            {
                "source_sha256": SPEC_SHA256,
                "reference_tools": VERSIONS,
                "fields": fields,
                "messages": messages,
            },
            indent=2,
        )
        + "\n"
    )
    print(f"Wrote {len(fields)} fields and {len(messages)} complete messages")


if __name__ == "__main__":
    main()
