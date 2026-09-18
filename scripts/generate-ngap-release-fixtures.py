#!/usr/bin/env python3
"""Independent Release 18 UE release messages and identifier/cause fields."""

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
        "complete-ue-context-release-command",
        "complete-ue-context-release-complete",
    ):
        row = next(row for row in published["cases"] if row["name"] == name)
        recipes[row["message"]] = row["pdu"]
    fields = []
    messages = []
    with tempfile.TemporaryDirectory(prefix="ngap-release-reference-") as temporary:
        reference = compile_reference(args.spec.read_bytes(), Path(temporary))

        def entries(recipe):
            return recipe["value"]["value"]["value"]["protocolIEs"]

        def wire_record(wire):
            return {
                "wire_hex": wire.hex(),
                "wire_sha256": hashlib.sha256(wire).hexdigest(),
            }

        def field_record(name, asn_name, value, **attributes):
            field = getattr(reference.schema.NGAP_IEs, asn_name)
            field.set_val(value)
            wire = field.to_aper()
            field.from_aper(wire)
            assert field.get_val() == value
            fields.append(
                {"name": name, "type": asn_name, **wire_record(wire), **attributes}
            )

        def message_record(name, recipe, **attributes):
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
                    **wire_record(wire),
                    **attributes,
                }
            )

        for message, original in recipes.items():
            message_record(f"base-{message}", original, construct=True)
            for row in reference.rows(message):
                if row["presence"] != "mandatory":
                    continue
                recipe = copy.deepcopy(original)
                entries(recipe)[:] = [
                    ie for ie in entries(recipe) if ie["id"] != row["id"]
                ]
                message_record(
                    f"missing-{message}-{row['id']}", recipe, missing_id=row["id"]
                )
                assert messages[-1]["reference_error"] == "missing-mandatory-ie"
            recipe = copy.deepcopy(original)
            entries(recipe).insert(0, copy.deepcopy(entries(recipe)[0]))
            message_record(f"duplicate-{message}", recipe, duplicate=True)
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
                message_record(
                    f"unknown-{message}-{criticality}",
                    recipe,
                    unknown_criticality=criticality,
                )
                assert messages[-1]["reference_error"] == (
                    "unknown-critical-ie" if criticality == "reject" else None
                )

        for group, name in (
            ("radioNetwork", "CauseRadioNetwork"),
            ("transport", "CauseTransport"),
            ("nas", "CauseNas"),
            ("protocol", "CauseProtocol"),
            ("misc", "CauseMisc"),
        ):
            enum = getattr(reference.schema.NGAP_IEs, name)
            for label in enum._root:
                code = enum._cont[label]
                field_record(
                    f"cause-{group}-{code}",
                    "Cause",
                    (group, label),
                    group=group,
                    code=code,
                )
                recipe = copy.deepcopy(recipes["UEContextReleaseCommand"])
                next(ie for ie in entries(recipe) if ie["id"] == 15)["value"][
                    "value"
                ] = {
                    "type": group,
                    "value": label,
                }
                message_record(
                    f"cause-{group}-{code}",
                    recipe,
                    construct=True,
                    group=group,
                    code=code,
                )

        amfs = (
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
        )
        rans = amfs[:9]
        pairs = list(
            dict.fromkeys(
                [(amf, rans[-1]) for amf in amfs] + [(amfs[-1], ran) for ran in rans]
            )
        )
        for index, (amf, ran) in enumerate(pairs + [(amf, None) for amf in amfs]):
            choice = (
                ("aMF-UE-NGAP-ID", amf)
                if ran is None
                else ("uE-NGAP-ID-pair", {"aMF-UE-NGAP-ID": amf, "rAN-UE-NGAP-ID": ran})
            )
            field_record(
                f"identifiers-{index}", "UE_NGAP_IDs", choice, amf=amf, ran=ran
            )
            recipe = copy.deepcopy(recipes["UEContextReleaseCommand"])
            next(ie for ie in entries(recipe) if ie["id"] == 114)["value"]["value"] = {
                "type": choice[0],
                "value": choice[1],
            }
            message_record(
                f"identifiers-{index}", recipe, construct=True, amf=amf, ran=ran
            )
        recipe = copy.deepcopy(recipes["UEContextReleaseComplete"])
        entries(recipe)[:] = [ie for ie in entries(recipe) if ie["id"] != 121]
        message_record(
            "complete-without-location", recipe, construct=True, location=False
        )
        assert all(
            row["reference_error"] is None for row in messages if row.get("construct")
        )
    result = {
        "source_sha256": SPEC_SHA256,
        "reference_tools": VERSIONS,
        "fields": fields,
        "messages": messages,
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Wrote {len(fields)} fields and {len(messages)} complete messages")


if __name__ == "__main__":
    main()
