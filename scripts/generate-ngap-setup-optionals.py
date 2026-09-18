#!/usr/bin/env python3
"""Independent TS 38.413 V18.10.0 NG Setup optional root-field messages.

Uses only the pinned specification, unmodified Pycrate and semantic recipes.
No SDK codec or catalog writer participates in expected bytes or outcomes.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import tempfile

from n3iwf_ngap_reference import Invalid, SPEC_SHA256, VERSIONS, compile_reference, unpack


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    published = json.loads((root / "crates/opc-n3iwf-fixtures/oracles/ngap-rel18-messages.json").read_text())
    recipes = {row["message"]: unpack(row["pdu"]) for row in published["cases"]
               if row["name"] in ("complete-ng-setup-request", "complete-ng-setup-response")}
    cases = []
    with tempfile.TemporaryDirectory(prefix="ngap-setup-optionals-") as temporary:
        ref = compile_reference(args.spec.read_bytes(), Path(temporary))

        def entries(recipe):
            return recipe[1]["value"][1]["protocolIEs"]

        def field(kind, ident, value):
            row = next(row for row in ref.rows(kind) if row["id"] == ident)
            return dict(id=ident, criticality=row["criticality"],
                        value=(row["Value"]._typeref.called[1], value))

        def recipe(kind, model):
            value = copy.deepcopy(recipes[kind])
            ies = entries(value)
            if "name" in model:
                ies.append(field(kind, 82, model["name"]))
            if model.get("retention"):
                ies.append(field(kind, 147, "ues-retained"))
            if "extended" in model:
                prefix = "rANNodeName" if kind == "NGSetupRequest" else "aMFName"
                extended = {prefix + ("VisibleString" if key == "visible" else "UTF8String"): text
                            for key, text in model["extended"].items()}
                ies.append(field(kind, 273 if kind == "NGSetupRequest" else 274, extended))
            if "backups" in model:
                served = next(ie for ie in ies if ie["id"] == 96)
                base = served["value"][1][0]
                values = []
                for name in model["backups"]:
                    item = copy.deepcopy(base)
                    if name is not None:
                        item["backupAMFName"] = name
                    values.append(item)
                served["value"] = ("ServedGUAMIList", values)
            order = {row["id"]: i for i, row in enumerate(ref.rows(kind))}
            ies.sort(key=lambda item: order[item["id"]])
            return value

        def record(name, kind, model, value=None, admit=True, construct=True, **extra):
            value = recipe(kind, model) if value is None else value
            ref.pdu.set_val(copy.deepcopy(value))
            wire = ref.pdu.to_aper_ws()
            # The ordinary Pycrate open-type fragment writer has a known
            # >16KiB length defect; the structured path retains fragments.
            if len(wire) < 16384:
                assert ref.encode(value) == wire
            error = None
            try:
                ref.pdu.from_aper_ws(wire)
                decoded = copy.deepcopy(ref.pdu.get_val())
                if ref.pdu.to_aper_ws() != wire:
                    raise Invalid("aper-canonical-or-trailing")
                ref.validate_container(kind, decoded[1]["value"][1], 256)
                ref.validate_n3iwf(kind, decoded[1]["value"][1])
            except Invalid as exc:
                error = str(exc)
            except Exception:
                error = "aper-decode"
            assert (admit or extra.get("unsupported_extension", False)) == (error is None), (name, error)
            cases.append(dict(name=name, message=kind, model=model, admit=admit,
                              construct=construct and admit, reference_error=error,
                              wire_hex=wire.hex(), wire_sha256=hashlib.sha256(wire).hexdigest(), **extra))

        for kind in recipes:
            short = "request" if kind == "NGSetupRequest" else "response"
            record(short + "-retention", kind, {"retention": True})
            if kind == "NGSetupRequest":
                for i, name in enumerate(("a", "Z" * 150, "AZaz09 '()+,-./:=?")):
                    record(f"request-name-{i}", kind, {"name": name})
            extended = [{}]
            for width, char in enumerate(("A", "é", "界", "🙂"), 1):
                for length in (1, 31, 32, 127, 128, 149, 150):
                    extended.append({"utf8": char * length})
            for length in (1, 31, 32, 127, 128, 149, 150):
                extended.append({"visible": "V" * length})
                extended.append({"visible": "V" * length, "utf8": "🙂" * length})
            extended.append({"visible": "".join(chr(c) for c in range(32, 127))})
            for i, names in enumerate(extended):
                record(f"{short}-extended-{i}", kind, {"extended": names})
            for mask in range(8 if kind == "NGSetupRequest" else 4):
                model = {}
                if mask & 1:
                    model["retention"] = True
                if mask & 2:
                    model["extended"] = {"visible": "Visible name", "utf8": "UTF8 name 界"}
                if mask & 4:
                    model["name"] = "Synthetic node"
                record(f"{short}-combined-{mask}", kind, model)
            model = {"retention": True, "extended": {"utf8": "first"}}
            if kind == "NGSetupRequest":
                model["name"] = "first"
            else:
                model["backups"] = ["backup", None]
            base = recipe(kind, model)
            ids = [147, 273 if kind == "NGSetupRequest" else 274]
            if kind == "NGSetupRequest":
                ids.append(82)
            for ident in ids:
                for criticality in ("reject", "notify"):
                    changed = copy.deepcopy(base)
                    next(ie for ie in entries(changed) if ie["id"] == ident)["criticality"] = criticality
                    record(f"{short}-criticality-{ident}-{criticality}", kind, model, changed, False)
                changed = copy.deepcopy(base)
                second = "ues-retained" if ident == 147 else ("last" if ident == 82 else
                         {("rANNodeName" if kind == "NGSetupRequest" else "aMFName") + "UTF8String": "last"})
                entries(changed).append(field(kind, ident, second))
                record(f"{short}-duplicate-{ident}", kind, model, changed, False, duplicate=ident)
            for criticality in ("ignore", "notify", "reject"):
                changed = copy.deepcopy(base)
                entries(changed).append(dict(id=65530, criticality=criticality, value=("_unk_004", b"\xff")))
                record(f"{short}-unknown-{criticality}", kind, model, changed,
                       criticality != "reject", False, unknown=criticality)
            changed = copy.deepcopy(base)
            entries(changed).reverse()
            record(short + "-reordered", kind, model, changed, True, False)
            for ident, bad in [(147, b""), (147, b"\x80"), (147, b"\x01"), (147, b"\0\0"),
                               (273 if kind == "NGSetupRequest" else 274, b"\x80"),
                               (273 if kind == "NGSetupRequest" else 274, b"\x10"),
                               (273 if kind == "NGSetupRequest" else 274, b"\x20\x01\xff")]:
                changed = copy.deepcopy(base)
                next(ie for ie in entries(changed) if ie["id"] == ident)["value"] = ("_unk_004", bad)
                record(f"{short}-malformed-{ident}-{bad.hex()}", kind, model, changed, False,
                       unsupported_extension=ident == 147 and bad == b"\x80")
        for count in (1, 2, 256):
            for length in (1, 150):
                model = {"backups": ["B" * length] * count}
                record(f"response-backups-{count}-{length}", "NGSetupResponse", model)
        record("response-backups-mixed", "NGSetupResponse",
               {"backups": [None, "AZaz09 '()+,-./:=?", None, "Z" * 150],
                "retention": True, "extended": {"visible": "AMF", "utf8": "AMF 界"}})
        model = {"backups": ["B"]}
        base = recipe("NGSetupResponse", model)
        leaf = bytes.fromhex(next(row for row in ref.encoded_fields(base) if row["id"] == 96)["value_hex"])
        assert len(leaf) == 11
        mutations = [("truncated-" + str(i), leaf[:i]) for i in range(len(leaf))]
        mutations += [("trailing", leaf + b"\0"), ("name-padding", leaf[:9] + bytes([leaf[9] | 1]) + leaf[10:])]
        for name, bad in mutations:
            changed = copy.deepcopy(base)
            next(ie for ie in entries(changed) if ie["id"] == 96)["value"] = ("_unk_004", bad)
            record("response-backup-malformed-" + name, "NGSetupResponse", model, changed, False)
    args.output.write_text(json.dumps(dict(source_sha256=SPEC_SHA256, reference_tools=VERSIONS,
                                          clauses=["8.7.1", "9.2.6.1", "9.2.6.2"],
                                          cases=cases), indent=2) + "\n")
    print(f"Wrote {len(cases)} independent NG Setup optional-field messages")


if __name__ == "__main__":
    main()
