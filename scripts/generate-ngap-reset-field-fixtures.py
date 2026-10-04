#!/usr/bin/env python3
"""Independent Release 18 Reset and Criticality Diagnostics field vectors."""

import argparse
import copy
import hashlib
import itertools
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
    with tempfile.TemporaryDirectory(prefix="ngap-reset-reference-") as temporary:
        ref = compile_reference(args.spec.read_bytes(), Path(temporary))

        def emit(kind, name, model, value, admitted=True):
            target = getattr(ref.schema.NGAP_IEs, kind)
            target.set_val(copy.deepcopy(value))
            wire = target.to_aper_ws()
            plain_encoder = True
            try:
                assert target.to_aper() == wire
            except AttributeError as exc:
                assert "encode_pas" in str(exc)
                plain_encoder = False
            target.from_aper_ws(wire)
            assert target.get_val() == value, (kind, name, "reference-values")
            assert target.to_aper_ws() == wire, (kind, name, "reference-reencode")
            if plain_encoder:
                assert target.to_aper() == wire
            cases.append(
                dict(
                    type=kind,
                    name=name,
                    model=model,
                    admitted=admitted,
                    plain_encoder=plain_encoder,
                    wire_hex=wire.hex(),
                    wire_sha256=hashlib.sha256(wire).hexdigest(),
                )
            )

        def connection_value(model):
            return [
                {
                    key: value
                    for key, value in [
                        ("aMF-UE-NGAP-ID", v.get("amf")),
                        ("rAN-UE-NGAP-ID", v.get("ran")),
                    ]
                    if value is not None
                }
                for v in model
            ]

        def connections(name, model, recipe=None):
            value = connection_value(model)
            stored = model if recipe is None else recipe
            emit("UE_associatedLogicalNG_connectionList", "list-" + name, stored, value)
            emit(
                "ResetType",
                "partial-" + name,
                dict(connections=stored),
                ("partOfNG-Interface", value),
            )

        emit("ResetType", "reset-all", dict(all=True), ("nG-Interface", "reset-all"))
        for amf in [
            None,
            0,
            255,
            256,
            65535,
            65536,
            16777215,
            16777216,
            4294967295,
            4294967296,
            1099511627775,
        ]:
            for ran in [
                None,
                0,
                255,
                256,
                65535,
                65536,
                16777215,
                16777216,
                4294967295,
            ]:
                connections(
                    "widths-" + str(amf) + "-" + str(ran), [dict(amf=amf, ran=ran)]
                )
        for count in [*range(1, 257), 257, 1024]:
            models = [
                {},
                dict(amf=0x8123456789),
                dict(ran=0x87654321),
                dict(amf=7, ran=3),
            ]
            connections("count-" + str(count), [models[i % 4] for i in range(count)])
        for count in [65535, 65536]:
            # Dense empty items exercise the maximum root count and every
            # half-octet boundary without manufacturing a huge peer dataset.
            connections(
                "empty-count-" + str(count),
                [{} for _ in range(count)],
                dict(count=count, cycle=[{}]),
            )
        for count in [16383, 16384, 16385, 32768, 49152, 65536]:
            cycle = [
                dict(amf=7),
                dict(ran=257),
                dict(amf=0x8123456789, ran=0x87654321),
                {},
            ]
            connections(
                "fragment-count-" + str(count),
                [cycle[i % 4] for i in range(count)],
                dict(count=count, cycle=cycle),
            )
        connections("duplicates", [dict(amf=7, ran=3), dict(amf=7, ran=3)])

        def diagnostic_value(model):
            result = {}
            for key, asn_name in [
                ("procedure_code", "procedureCode"),
                ("trigger", "triggeringMessage"),
                ("criticality", "procedureCriticality"),
            ]:
                if key in model:
                    result[asn_name] = model[key]
            if "items" in model:
                result["iEsCriticalityDiagnostics"] = [
                    {
                        "iECriticality": v["criticality"],
                        "iE-ID": v["id"],
                        "typeOfError": v["error"],
                    }
                    for v in model["items"]
                ]
            return result

        def diagnostics(name, model, admitted=True):
            emit(
                "CriticalityDiagnostics", name, model, diagnostic_value(model), admitted
            )

        for mask in range(16):
            model = {}
            for bit, (key, value) in enumerate(
                [
                    ("procedure_code", 20),
                    ("trigger", "initiating-message"),
                    ("criticality", "reject"),
                    ("items", [dict(criticality="notify", id=65535, error="missing")]),
                ]
            ):
                if mask & (1 << bit):
                    model[key] = value
            diagnostics("presence-" + str(mask), model)
        for proc, trigger, crit in itertools.product(
            [0, 1, 127, 128, 255],
            ["initiating-message", "successful-outcome", "unsuccessful-outcome"],
            ["reject", "ignore", "notify"],
        ):
            diagnostics(
                "header-" + str(proc) + "-" + trigger + "-" + crit,
                dict(procedure_code=proc, trigger=trigger, criticality=crit),
            )
        for ident, criticality, error in itertools.product(
            [0, 1, 255, 256, 32767, 32768, 65535],
            ["reject", "ignore", "notify"],
            ["not-understood", "missing"],
        ):
            model = dict(items=[dict(id=ident, criticality=criticality, error=error)])
            diagnostics(
                "item-" + str(ident) + "-" + criticality + "-" + error,
                model,
                criticality != "ignore",
            )
        for count in range(1, 257):
            model = dict(
                procedure_code=20,
                trigger="unsuccessful-outcome",
                criticality="ignore",
                items=[
                    dict(
                        id=(i * 257) % 65536,
                        criticality="reject" if i % 2 else "notify",
                        error="missing" if i % 3 else "not-understood",
                    )
                    for i in range(count)
                ],
            )
            diagnostics("items-" + str(count), model)
        diagnostics(
            "duplicate-ids",
            dict(
                items=[
                    dict(id=7, criticality="notify", error="missing"),
                    dict(id=7, criticality="reject", error="not-understood"),
                ]
            ),
        )
    document = dict(
        source_sha256=SPEC_SHA256,
        reference_tools=VERSIONS,
        reference_decoder="from_aper_ws; to_aper_ws primary; plain to_aper unavailable for fragmented lists (encode_pas typo)",
        cases=cases,
    )
    # Compact each model so the maximum-count root does not create hundreds
    # of thousands of formatting-only lines. Parsed content remains exact.
    rendered = json.dumps(document, indent=2)
    for row in cases:
        expanded = json.dumps(row["model"], indent=2).replace("\n", "\n      ")
        rendered = rendered.replace(
            '"model": ' + expanded,
            '"model": ' + json.dumps(row["model"], separators=(",", ":")),
            1,
        )
    assert json.loads(rendered) == document
    args.output.write_text(rendered + "\n")
    counts = {}
    for row in cases:
        key = row["type"]
        counts[key] = counts.get(key, 0) + 1
    print("Independent field counts:", counts)
    print(
        "Admitted:",
        sum(v["admitted"] for v in cases),
        "negative:",
        sum(not v["admitted"] for v in cases),
    )


if __name__ == "__main__":
    main()
