#!/usr/bin/env python3
"""Independent optional diagnostics in seven already-qualified NGAP responses."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--sdk-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.sdk_root / "scripts"))
    from n3iwf_ngap_reference import SPEC_SHA256, VERSIONS, compile_reference

    fixtures = args.sdk_root / "crates/opc-proto-ngap/tests/fixtures"
    inputs = {}

    def load(name):
        data = (fixtures / name).read_bytes()
        inputs[name] = hashlib.sha256(data).hexdigest()
        return json.loads(data)

    original = [
        v
        for v in load("n3iwf-reset-fields.json")["cases"]
        if v["type"] == "CriticalityDiagnostics"
    ]
    recipes = [
        ("NGSetupResponse", "n3iwf-setup.json", "messages", []),
        ("NGSetupFailure", "n3iwf-setup.json", "messages", [107]),
        ("InitialContextSetupResponse", "n3iwf-resource-setup.json", "cases", [72, 55]),
        ("InitialContextSetupFailure", "n3iwf-resource-setup.json", "cases", [132]),
        ("PDUSessionResourceSetupResponse", "n3iwf-resource-setup.json", "cases", []),
        (
            "PDUSessionResourceReleaseResponse",
            "n3iwf-resource-release.json",
            "messages",
            [],
        ),
        ("UEContextReleaseComplete", "n3iwf-release.json", "messages", [121]),
    ]
    cases, diagnostics = [], {}
    with tempfile.TemporaryDirectory(prefix="ngap-response-diagnostics-") as tmp:
        ref = compile_reference(args.spec.read_bytes(), Path(tmp))

        def encode(target, value):
            target.set_val(copy.deepcopy(value))
            wire = target.to_aper_ws()
            assert target.to_aper() == wire
            target.from_aper_ws(wire)
            assert target.get_val() == value
            assert target.to_aper_ws() == wire
            return wire

        target = ref.schema.NGAP_IEs.CriticalityDiagnostics
        reference_values = {}
        for row in original:
            wire = bytes.fromhex(row["wire_hex"])
            target.from_aper_ws(wire)
            value = copy.deepcopy(target.get_val())
            assert encode(target, value) == wire
            name = row["name"]
            diagnostics[name] = dict(
                model=row["model"],
                wire_hex=wire.hex(),
                admitted=(
                    row["admitted"]
                    and "procedureCode" not in value
                    and "triggeringMessage" not in value
                ),
            )
            reference_values[name] = value
            if name.startswith("items-"):
                # Same independent root recipe at every count, with only the
                # fields permitted in a same-procedure response.
                value = copy.deepcopy(value)
                value.pop("procedureCode")
                value.pop("triggeringMessage")
                model = {
                    k: v
                    for k, v in row["model"].items()
                    if k not in ("procedure_code", "trigger")
                }
                name = "response-" + name
                wire = encode(target, value)
                diagnostics[name] = dict(
                    model=model, wire_hex=wire.hex(), admitted=True
                )
                reference_values[name] = value

        for kind, filename, key, omitted in recipes:
            base = next(v for v in load(filename)[key] if v["name"] == "base-" + kind)
            base_wire = bytes.fromhex(base["wire_hex"])
            ref.pdu.from_aper_ws(base_wire)
            value = copy.deepcopy(ref.pdu.get_val())
            assert encode(ref.pdu, value) == base_wire
            assert value[1]["value"][0] == kind
            rows = ref.rows(kind)
            order = {v["id"]: i for i, v in enumerate(rows)}
            metadata = {v["id"]: v for v in rows}
            assert metadata[19]["criticality"] == "ignore"
            assert metadata[19]["presence"] == "optional"
            assert all(v["id"] != 19 for v in value[1]["value"][1]["protocolIEs"])

            def add(name, message, admitted, diagnostic=None):
                wire = encode(ref.pdu, message)
                ref.pdu.from_aper_ws(wire)
                decoded = copy.deepcopy(ref.pdu.get_val())
                assert encode(ref.pdu, decoded) == wire
                fs = decoded[1]["value"][1]["protocolIEs"]
                encoded = []
                for ie in fs:
                    field_wire = encode(metadata[ie["id"]]["Value"], ie["value"][1])
                    if ie["id"] == 19 and diagnostic is not None:
                        assert field_wire.hex() == diagnostics[diagnostic]["wire_hex"]
                    encoded.append(
                        dict(
                            id=ie["id"],
                            criticality=ie["criticality"],
                            wire_hex=field_wire.hex(),
                        )
                    )
                cases.append(
                    dict(
                        name=kind + "-" + name,
                        kind=kind,
                        admitted=admitted,
                        wire_hex=wire.hex(),
                        fields=encoded,
                        diagnostics=diagnostic,
                    )
                )

            def message_with(base, name):
                message = copy.deepcopy(base)
                fs = message[1]["value"][1]["protocolIEs"]
                fs.append(
                    dict(
                        id=19,
                        criticality="ignore",
                        value=("CriticalityDiagnostics", reference_values[name]),
                    )
                )
                fs.sort(key=lambda v: order[v["id"]])
                return message

            add("absent", value, True)
            for name, diagnostic in diagnostics.items():
                add(name, message_with(value, name), diagnostic["admitted"], name)
            if omitted:
                minimal = copy.deepcopy(value)
                minimal[1]["value"][1]["protocolIEs"] = [
                    ie
                    for ie in minimal[1]["value"][1]["protocolIEs"]
                    if ie["id"] not in omitted
                ]
                add("minimal-absent", minimal, True)
                for name in ["presence-0", "response-items-1", "response-items-256"]:
                    add("minimal-" + name, message_with(minimal, name), True, name)
            empty = message_with(value, "presence-0")
            wrong = copy.deepcopy(empty)
            next(v for v in wrong[1]["value"][1]["protocolIEs"] if v["id"] == 19)[
                "criticality"
            ] = "reject"
            add("wrong-criticality", wrong, False, "presence-0")
            duplicate = copy.deepcopy(empty)
            duplicate[1]["value"][1]["protocolIEs"].append(
                dict(
                    id=19,
                    criticality="ignore",
                    value=("CriticalityDiagnostics", dict(procedureCode=21)),
                )
            )
            add("duplicate-last-inapplicable", duplicate, False)
        result = dict(
            source_sha256=SPEC_SHA256,
            reference_tools=VERSIONS,
            source_corpora=inputs,
            diagnostics=diagnostics,
            cases=cases,
        )
        # Shared diagnostic models and compact rows avoid repeating thousands
        # of list-item lines for each of the seven envelopes.
        rendered = json.dumps(result, separators=(",", ":"))
        rendered = rendered.replace('},{"name":', '},\n{"name":')
        assert json.loads(rendered) == result
        args.output.write_text(rendered + "\n")
        admitted = sum(v["admitted"] for v in cases)
        print(
            "Verified",
            len(cases),
            "complete messages;",
            admitted,
            "admitted;",
            len(cases) - admitted,
            "negative",
        )


if __name__ == "__main__":
    main()
