#!/usr/bin/env python3
"""Independent Release 18 Initial Context optional-field APER messages.

The pinned ASN.1 and explicit 8.3.1.4 slice conditions provide expected bytes
and outcomes. No SDK encoder, decoder or fixture writer supplies the oracle.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import tempfile

from n3iwf_ngap_reference import Invalid, SPEC_SHA256, VERSIONS, compile_reference, unpack

DEPTHS = ["minimum", "medium", "maximum", "minimumWithoutVendorSpecificExtension",
          "mediumWithoutVendorSpecificExtension", "maximumWithoutVendorSpecificExtension"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    published = json.loads((root / "crates/opc-n3iwf-fixtures/oracles/ngap-rel18-messages.json").read_text())
    base = unpack(next(row["pdu"] for row in published["cases"]
                       if row["name"] == "complete-initial-context-setup-request"))
    kind = "InitialContextSetupRequest"
    cases = []

    def entries(value):
        return value[1]["value"][1]["protocolIEs"]

    entries(base)[:] = [ie for ie in entries(base) if ie["id"] not in (71, 110, 38)]
    with tempfile.TemporaryDirectory(prefix="ngap-context-optionals-") as temporary:
        ref = compile_reference(args.spec.read_bytes(), Path(temporary))
        rows = {row["id"]: row for row in ref.rows(kind)}
        for ident, criticality, name in [(48, "reject", "AMFName"), (108, "ignore", "TraceActivation"),
                                        (34, "ignore", "MaskedIMEISV"), (414, "ignore", "Partially-Allowed-NSSAI"),
                                        (443, "ignore", "Extended-AMFName")]:
            assert rows[ident]["criticality"] == criticality and rows[ident]["presence"] == "optional"
            assert rows[ident]["Value"]._typeref.called[1] == name
        order = {row["id"]: index for index, row in enumerate(ref.rows(kind))}

        def field(ident, value):
            row = rows[ident]
            return dict(id=ident, criticality=row["criticality"], value=(row["Value"]._typeref.called[1], value))

        def slices(values):
            return [{"s-NSSAI": {"sST": bytes([v["sst"]]),
                                 **({"sD": bytes.fromhex(v["sd"])} if v.get("sd") is not None else {})}}
                    for v in values]

        def recipe(model):
            value = copy.deepcopy(base)
            ies = entries(value)
            next(ie for ie in ies if ie["id"] == 0)["value"] = ("AllowedNSSAI", slices(model.get("allowed", [{"sst": 1}])))
            if "old_amf" in model:
                ies.append(field(48, model["old_amf"]))
            if "extended" in model:
                ies.append(field(443, {"aMFName" + ("VisibleString" if k == "visible" else "UTF8String"): v
                                       for k, v in model["extended"].items()}))
            if "masked" in model:
                ies.append(field(34, (int(model["masked"], 16), 64)))
            if "partial" in model:
                ies.append(field(414, slices(model["partial"])))
            if "trace" in model:
                trace = model["trace"]
                ies.append(field(108, {"nGRANTraceID": bytes.fromhex(trace["id"]),
                                      "interfacesToTrace": (trace["interfaces"], 8),
                                      "traceDepth": DEPTHS[trace["depth"]],
                                      "traceCollectionEntityIPAddress": (int(trace["address"], 16), trace["bits"])}))
            ies.sort(key=lambda ie: order[ie["id"]])
            return value

        def encode(value):
            wire = ref.encode(value)
            ref.pdu.set_val(copy.deepcopy(value))
            assert ref.pdu.to_aper_ws() == wire
            return wire

        def record(name, model, value=None, admit=True, construct=True, **extra):
            value = recipe(model) if value is None else value
            wire = encode(value)
            error = None
            try:
                ref.pdu.from_aper_ws(wire)
                decoded = copy.deepcopy(ref.pdu.get_val())
                if ref.pdu.to_aper_ws() != wire:
                    raise Invalid("aper-canonical-or-trailing")
                body = decoded[1]["value"][1]
                ref.validate_container(kind, body, 256)
                ref.validate_n3iwf(kind, body)
                selected = {ie["id"]: ie["value"][1] for ie in body["protocolIEs"] if ie["id"] in rows}
                if 414 in selected:
                    allowed, partial = selected[0], selected[414]
                    if len(allowed) + len(partial) > 8:
                        raise Invalid("combined-slice-count")
                    if any(item["s-NSSAI"] == other["s-NSSAI"] for item in partial for other in allowed):
                        raise Invalid("overlapping-slice-lists")
            except Invalid as exc:
                error = str(exc)
            except Exception:
                error = "aper-decode"
            assert (admit or extra.get("unsupported", False)) == (error is None), (name, error)
            cases.append(dict(name=name, model=model, admit=admit, construct=construct and admit,
                              reference_error=error, wire_hex=wire.hex(),
                              wire_sha256=hashlib.sha256(wire).hexdigest(), **extra))
            if "trace" in model and admit and not extra:
                cases[-1]["trace_wire_hex"] = next(row["value_hex"] for row in ref.encoded_fields(value) if row["id"] == 108)

        base_wire = encode(recipe({})).hex()
        caps = next(ie["value"][1] for ie in entries(base) if ie["id"] == 119)
        masks = [caps[name][0] for name in ("nRencryptionAlgorithms", "nRintegrityProtectionAlgorithms",
                                          "eUTRAencryptionAlgorithms", "eUTRAintegrityProtectionAlgorithms")]
        for index, name in enumerate(["a", "A" * 150, "AZaz09 '()+,-./:=?"]):
            record(f"old-amf-{index}", {"old_amf": name})
        for index, value in enumerate([{}, {"visible": "AMF"}, {"utf8": "AMF 界"},
                                       {"visible": "V" * 150, "utf8": "🙂" * 150},
                                       {"visible": "".join(chr(c) for c in range(32, 127))}]):
            record(f"extended-{index}", {"extended": value})
        for number in [0, (1 << 64) - 1, 0x0123456789abcdef] + [1 << i for i in range(64)]:
            record(f"masked-{number:016x}", {"masked": f"{number:016x}"})
        for a in range(1, 9):
            for p in range(1, 9):
                record(f"slices-{a}-{p}", {"allowed": [{"sst": i} for i in range(a)],
                                          "partial": [{"sst": 128+i, "sd": "010203"} for i in range(p)]},
                       admit=a+p <= 8)
        for sd in [None, "010203"]:
            record(f"overlap-{sd}", {"allowed": [{"sst": 1, "sd": sd}],
                                     "partial": [{"sst": 1, "sd": sd}]}, admit=False)
        for index, (a, p) in enumerate([(None, "010203"), ("010203", None), ("000000", "ffffff")]):
            record(f"distinct-sd-{index}", {"allowed": [{"sst": 1, "sd": a}],
                                           "partial": [{"sst": 1, "sd": p}]})

        def trace(bits, depth, interfaces=0x80):
            # Bit strings carry opaque transport information. For 32/128 bits
            # use documentation addresses; other root widths probe framing.
            value = int.from_bytes(bytes([0xa5]) * ((bits+7)//8), "big") >> ((8-bits%8)%8)
            if bits == 32:
                value = int.from_bytes(bytes([192, 0, 2, 1]), "big")
            if bits == 128:
                value = int("20010db8000000000000000000000001", 16)
            return dict(id="00f1100102030405", interfaces=interfaces, depth=depth, bits=bits, address=f"{value:x}")
        for bits in range(1, 161):
            record(f"trace-width-{bits}", {"trace": trace(bits, bits % 6)})
        for depth in range(6):
            for bits in (1, 8, 16, 32, 128, 160):
                for interfaces in (0, 0xf8, 0xff):
                    record(f"trace-depth-{depth}-{bits}-{interfaces}", {"trace": trace(bits, depth, interfaces)})
        all_fields = dict(old_amf="synthetic-old.example", extended={"visible": "Old AMF", "utf8": "Old AMF 界"},
                          partial=[{"sst": 2, "sd": "010203"}], masked="0123456789abcdef", trace=trace(128, 5))
        record("combined", all_fields)
        for ident in (48, 108, 34, 414, 443):
            for criticality in ("reject", "ignore", "notify"):
                if criticality == rows[ident]["criticality"]:
                    continue
                changed = recipe(all_fields)
                next(ie for ie in entries(changed) if ie["id"] == ident)["criticality"] = criticality
                record(f"criticality-{ident}-{criticality}", all_fields, changed, False)
            changed = recipe(all_fields)
            last_model = copy.deepcopy(all_fields)
            if ident == 48: last_model["old_amf"] = "last"
            if ident == 108: last_model["trace"] = trace(32, 0, 0)
            if ident == 34: last_model["masked"] = "0000000000000000"
            if ident == 414: last_model["partial"] = [{"sst": 3}]
            if ident == 443: last_model["extended"] = {"utf8": "last"}
            entries(changed).append(next(ie for ie in entries(recipe(last_model)) if ie["id"] == ident))
            record(f"duplicate-{ident}", all_fields, changed, False, duplicate=ident, last_model=last_model)
        for reason in ("overlap", "count"):
            changed = recipe(all_fields)
            last_model = copy.deepcopy(all_fields)
            last_model["partial"] = ([{"sst": 1}] if reason == "overlap" else
                                     [{"sst": 128+i} for i in range(8)])
            entries(changed).append(next(ie for ie in entries(recipe(last_model)) if ie["id"] == 414))
            record("duplicate-partial-"+reason, all_fields, changed, False,
                   duplicate=414, last_model=last_model, last_reject=True)
        for criticality in ("ignore", "notify", "reject"):
            changed = recipe(all_fields)
            entries(changed).append(dict(id=65530, criticality=criticality, value=("_unk_004", b"\xff")))
            record(f"unknown-{criticality}", all_fields, changed, criticality != "reject", False, unknown=criticality)
        changed = recipe(all_fields)
        entries(changed).reverse()
        record("reordered", all_fields, changed, True, False)
        leaf = bytes.fromhex(next(row["value_hex"] for row in ref.encoded_fields(recipe({"trace": trace(32, 0)})) if row["id"] == 108))
        malformed = [(f"truncated-{i}", leaf[:i]) for i in range(len(leaf))] + [("trailing", leaf+b"\0")]
        for offset, mask in [(0, 1), (11, 1)]:
            changed = bytearray(leaf);changed[offset] |= mask;malformed.append((f"padding-{offset}", bytes(changed)))
        for name, raw in malformed:
            changed = recipe(all_fields)
            next(ie for ie in entries(changed) if ie["id"] == 108)["value"] = ("_unk_004", raw)
            record("trace-"+name, all_fields, changed, False)
    args.output.write_text(json.dumps(dict(source_sha256=SPEC_SHA256, reference_tools=VERSIONS,
                                          clauses=["8.3.1.2", "8.3.1.4", "9.2.2.1", "9.3.1.14", "9.3.2.4"],
                                          base_wire_hex=base_wire, capabilities=masks, cases=cases), indent=2)+"\n")
    print(f"Wrote {len(cases)} independent Initial Context optional-field messages")


if __name__ == "__main__":
    main()
