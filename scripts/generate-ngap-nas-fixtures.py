#!/usr/bin/env python3
"""Independent Release 18 complete NAS-message admission vectors.

Extends synthetic recipes without SDK codecs or the generated Rust schema.
The independent schema and mandatory-IE validator determine wire validity.
"""

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
        "complete-initial-ue-message",
        "complete-downlink-nas-transport",
        "complete-uplink-nas-transport",
    ):
        case = next(row for row in published["cases"] if row["name"] == name)
        recipes[case["message"]] = case["pdu"]
    cases = []
    with tempfile.TemporaryDirectory(prefix="ngap-nas-reference-") as temporary:
        reference = compile_reference(args.spec.read_bytes(), Path(temporary))

        def fields(recipe):
            return recipe["value"]["value"]["value"]["protocolIEs"]

        def record(name, recipe, **attributes):
            pdu = unpack(recipe)
            wire = reference.encode(pdu)
            error = None
            try:
                reference.decode(wire)
            except Invalid as exc:
                error = str(exc)
            cases.append(
                {
                    "name": name,
                    "message": recipe["value"]["value"]["type"],
                    "reference_error": error,
                    "wire_hex": wire.hex(),
                    "wire_sha256": hashlib.sha256(wire).hexdigest(),
                    **attributes,
                }
            )

        for message, original in recipes.items():
            record(f"base-{message}", original, construct=True)
            mandatory = [
                row["id"]
                for row in reference.rows(message)
                if row["presence"] == "mandatory"
            ]
            for ident in mandatory:
                recipe = copy.deepcopy(original)
                fields(recipe)[:] = [ie for ie in fields(recipe) if ie["id"] != ident]
                record(f"missing-{message}-{ident}", recipe, missing_id=ident)
                assert cases[-1]["reference_error"] == "missing-mandatory-ie"
            recipe = copy.deepcopy(original)
            duplicate = copy.deepcopy(fields(recipe)[0])
            duplicate["value"]["value"] = 34
            fields(recipe).insert(0, duplicate)
            record(f"duplicate-{message}", recipe, duplicate_id=duplicate["id"])
            assert cases[-1]["reference_error"] == "duplicate-ie"
            for criticality in ("ignore", "notify", "reject"):
                recipe = copy.deepcopy(original)
                fields(recipe).append(
                    {
                        "id": 65530,
                        "criticality": criticality,
                        "value": {"type": "_unk_004", "value": {"hex": "abcd"}},
                    }
                )
                record(
                    f"unknown-{message}-{criticality}",
                    recipe,
                    unknown_criticality=criticality,
                )
                assert cases[-1]["reference_error"] == (
                    "unknown-critical-ie" if criticality == "reject" else None
                )
        causes = (
            "emergency",
            "highPriorityAccess",
            "mt-Access",
            "mo-Signalling",
            "mo-Data",
            "mo-VoiceCall",
            "mo-VideoCall",
            "mo-SMS",
            "mps-PriorityAccess",
            "mcs-PriorityAccess",
            "notAvailable",
            "mo-ExceptionData",
        )
        for index, cause in enumerate(causes):
            recipe = copy.deepcopy(recipes["InitialUEMessage"])
            next(ie for ie in fields(recipe) if ie["id"] == 90)["value"][
                "value"
            ] = cause
            record(f"cause-{index}", recipe, construct=True, cause=cause)
        recipe = copy.deepcopy(recipes["InitialUEMessage"])
        fields(recipe).append(
            {
                "id": 112,
                "criticality": "ignore",
                "value": {"type": "UEContextRequest", "value": "requested"},
            }
        )
        record("context-requested", recipe, construct=True, context_requested=True)
        recipe = copy.deepcopy(recipes["InitialUEMessage"])
        fields(recipe)[:] = [ie for ie in fields(recipe) if ie["id"] != 174]
        record("selected-plmn-absent", recipe, construct=True, selected_plmn=False)
        for index, (downlink, uplink) in enumerate(
            (
                (0, 0),
                (1, 2),
                (1_000_000_000, 500_000_000),
                (4_000_000_000_000, 4_000_000_000_000),
            )
        ):
            recipe = copy.deepcopy(recipes["DownlinkNASTransport"])
            fields(recipe).append(
                {
                    "id": 110,
                    "criticality": "ignore",
                    "value": {
                        "type": "UEAggregateMaximumBitRate",
                        "value": {
                            "uEAggregateMaximumBitRateDL": downlink,
                            "uEAggregateMaximumBitRateUL": uplink,
                        },
                    },
                }
            )
            record(
                f"ambr-{index}",
                recipe,
                construct=True,
                downlink=downlink,
                uplink=uplink,
            )
        assert all(
            row["reference_error"] is None for row in cases if row.get("construct")
        )

        # These independently encoded optional fields reuse existing SDK leaf
        # contracts only after whole-message admission is qualified. Establish
        # each binding directly from the pinned Release 18 object set.
        for message, ident, name in (
            ("InitialUEMessage", 0, "AllowedNSSAI"),
            ("DownlinkNASTransport", 0, "AllowedNSSAI"),
            ("DownlinkNASTransport", 48, "AMFName"),
        ):
            row = next(row for row in reference.rows(message) if row["id"] == ident)
            assert row["presence"] == "optional"
            assert row["criticality"] == "reject"
            assert row["Value"]._typeref.called[1] == name

        def allowed_field(model):
            return {
                "id": 0,
                "criticality": "reject",
                "value": {
                    "type": "AllowedNSSAI",
                    "value": [
                        {
                            "s-NSSAI": {
                                "sST": {"hex": f"{item['sst']:02x}"},
                                **({"sD": {"hex": item["sd"]}} if item["sd"] is not None else {}),
                            }
                        }
                        for item in model
                    ],
                },
            }

        def old_amf_field(name):
            return {"id": 48, "criticality": "reject", "value": {"type": "AMFName", "value": name}}

        for message in ("InitialUEMessage", "DownlinkNASTransport"):
            for count in range(1, 9):
                for mode in range(3):
                    model = [
                        {"sst": (index * 37) % 256, "sd": (
                            ("000000" if index % 2 == 0 else "ffffff")
                            if mode == 2 or (mode == 1 and index % 2) else None
                        )}
                        for index in range(count)
                    ]
                    recipe = copy.deepcopy(recipes[message])
                    fields(recipe).append(allowed_field(model))
                    record(f"allowed-{message}-{count}-{mode}", recipe,
                           construct=True, optional_fields=True, allowed_nssai=model)
        for length in (1, 2, 127, 128, 149, 150):
            name = "A" * length
            recipe = copy.deepcopy(recipes["DownlinkNASTransport"])
            fields(recipe).append(old_amf_field(name))
            record(f"old-amf-{length}", recipe, construct=True, optional_fields=True, old_amf=name)
        model = [{"sst": 255, "sd": "ffffff"}, {"sst": 0, "sd": None}]
        recipe = copy.deepcopy(recipes["DownlinkNASTransport"])
        fields(recipe).extend([allowed_field(model), old_amf_field("AMF-TEST-1")])
        record("allowed-and-old-amf", recipe, construct=True, optional_fields=True,
               allowed_nssai=model, old_amf="AMF-TEST-1")
        fields(recipe).reverse()
        record("allowed-and-old-amf-reordered", recipe, optional_fields=True,
               allowed_nssai=model, old_amf="AMF-TEST-1")

        for message, field in (
            ("InitialUEMessage", allowed_field(model)),
            ("DownlinkNASTransport", allowed_field(model)),
            ("DownlinkNASTransport", old_amf_field("AMF-TEST-1")),
        ):
            for criticality in ("ignore", "notify"):
                recipe = copy.deepcopy(recipes[message])
                changed = copy.deepcopy(field)
                changed["criticality"] = criticality
                fields(recipe).append(changed)
                record(f"optional-criticality-{message}-{field['id']}-{criticality}",
                       recipe, optional_fields=True, invalid_optional_id=field["id"])
                assert cases[-1]["reference_error"] == "ie-criticality"
            recipe = copy.deepcopy(recipes[message])
            first = copy.deepcopy(field)
            if field["id"] == 0:
                first_model = [{"sst": 1, "sd": "010203"}]
                first = allowed_field(first_model)
                expectations = {"first_allowed_nssai": first_model, "last_allowed_nssai": model}
            else:
                first = old_amf_field("AMF-OTHER")
                expectations = {"first_old_amf": "AMF-OTHER", "last_old_amf": "AMF-TEST-1"}
            fields(recipe).extend([first, copy.deepcopy(field)])
            record(f"optional-duplicate-{message}-{field['id']}", recipe,
                   optional_fields=True, duplicate_id=field["id"], **expectations)
            assert cases[-1]["reference_error"] == "duplicate-ie"
        assert all(row["reference_error"] is None for row in cases if row.get("construct"))
    args.output.write_text(
        json.dumps(
            {"source_sha256": SPEC_SHA256, "reference_tools": VERSIONS, "cases": cases},
            indent=2,
        )
        + "\n"
    )
    print(f"Produced {len(cases)} independent complete-message cases")


if __name__ == "__main__":
    main()
