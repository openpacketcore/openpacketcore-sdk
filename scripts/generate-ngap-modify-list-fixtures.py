#!/usr/bin/env python3
"""Independent Release 18 Modify session lists and contained transfers."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import tempfile

from n3iwf_ngap_reference import Invalid, SPEC_SHA256, VERSIONS, compile_reference

KINDS = {
    "PDUSessionResourceModifyListModReq": (
        "request",
        "PDUSessionResourceModifyRequestTransfer",
        "pDUSessionResourceModifyRequestTransfer",
    ),
    "PDUSessionResourceModifyListModRes": (
        "response",
        "PDUSessionResourceModifyResponseTransfer",
        "pDUSessionResourceModifyResponseTransfer",
    ),
    "PDUSessionResourceFailedToModifyListModRes": (
        "failure",
        "PDUSessionResourceModifyUnsuccessfulTransfer",
        "pDUSessionResourceModifyUnsuccessfulTransfer",
    ),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    inputs = {
        name: (args.fixtures / f"n3iwf-modify-{name}.json").read_bytes()
        for name in ["request", "results"]
    }
    source = {name: json.loads(data) for name, data in inputs.items()}
    assert all(v["source_sha256"] == SPEC_SHA256 for v in source.values())
    choices = {
        "request": ("request", "presence-15"),
        "request-empty": ("request", "presence-0"),
        "request-max": ("request", "request-parameters-64"),
        "request-ignore": ("request", "unknown-ignore"),
        "request-notify": ("request", "unknown-notify-fragment"),
        "request-reject": ("request", "unknown-reject"),
        "request-overlap": ("request", "overlap"),
        "request-duplicate": ("request", "duplicate-130"),
        "response": ("results", "presence-15"),
        "response-empty": ("results", "presence-0"),
        "response-max": ("results", "accepted-count-64"),
        "response-partial": ("results", "disjoint-32"),
        "failure": ("results", "failure-misc-5"),
        "failure-diagnostics": ("results", "diagnostic-count-256"),
    }
    bases = {
        name: next(v for v in source[key]["cases"] if v["name"] == row)
        for name, (key, row) in choices.items()
    }
    cases = []
    with tempfile.TemporaryDirectory(prefix="ngap-modify-lists-") as tmp:
        ref = compile_reference(args.spec.read_bytes(), Path(tmp))
        nested = {}
        for name, row in bases.items():
            category = name.split("-", 1)[0]
            kind = next(v[1] for v in KINDS.values() if v[0] == category)
            target = getattr(ref.schema.NGAP_IEs, kind)
            wire = bytes.fromhex(row["wire_hex"])
            target.from_aper_ws(wire)
            assert target.to_aper_ws() == wire
            assert target.to_aper() == wire
            nested[name] = copy.deepcopy(target.get_val())

        def nas(length):
            return b"".join(
                hashlib.sha256(f"modify-nas-{i}".encode()).digest()
                for i in range((length + 31) // 32)
            )[:length]

        def value(kind, model, canonical=False):
            category, transfer_kind, transfer_key = KINDS[kind]
            leaf = copy.deepcopy(nested[model["transfer"]])
            if canonical and model["transfer"] in ["request-ignore", "request-notify"]:
                leaf["protocolIEs"] = [
                    v for v in leaf["protocolIEs"] if v["id"] != 65530
                ]
            items = []
            for ident in model["ids"]:
                item = {
                    "pDUSessionID": ident,
                    transfer_key: (transfer_kind, copy.deepcopy(leaf)),
                }
                if category == "request":
                    if model["nas_length"] is not None:
                        item["nAS-PDU"] = nas(model["nas_length"])
                    if model["slice"] is not None:
                        recipe = model["slice"]
                        s = {"sST": bytes([recipe["sst"]])}
                        if recipe["sd"] is not None:
                            s["sD"] = bytes.fromhex(recipe["sd"])
                        item["iE-Extensions"] = [
                            {
                                "id": 148,
                                "criticality": "reject",
                                "extensionValue": ("S-NSSAI", s),
                            }
                        ]
                items.append(item)
            return items

        def semantic(kind, values, model):
            seen = set()
            for v in values:
                if v["pDUSessionID"] in seen:
                    raise Invalid("duplicate-session")
                seen.add(v["pDUSessionID"])
                extensions = v.get("iE-Extensions", [])
                if extensions and (
                    KINDS[kind][0] != "request"
                    or len(extensions) != 1
                    or extensions[0]["id"] != 148
                    or extensions[0]["criticality"] != "reject"
                ):
                    raise Invalid("unsupported-item-extension")
            if not bases[model["transfer"]]["admitted"]:
                raise Invalid("inadmissible-contained-transfer")

        def encode(kind, values):
            target = getattr(ref.schema.NGAP_IEs, kind)
            target.set_val(copy.deepcopy(values))
            wire = target.to_aper_ws()
            assert target.to_aper() == wire
            target.from_aper_ws(wire)
            assert target.get_val() == values
            assert target.to_aper_ws() == wire
            return wire

        def record(name, kind, model, admitted=True, override=None):
            values = value(kind, model) if override is None else override
            wire = encode(kind, values)
            error = None
            try:
                semantic(kind, values, model)
            except Invalid as e:
                error = str(e)
            assert (error is None) == admitted, (name, error)
            canonical = encode(kind, value(kind, model, True)) if admitted else wire
            cases.append(
                dict(
                    name=f"{KINDS[kind][0]}-{name}",
                    type=kind,
                    category=KINDS[kind][0],
                    model=model,
                    admitted=admitted,
                    reference_error=error,
                    wire_hex=wire.hex(),
                    wire_sha256=hashlib.sha256(wire).hexdigest(),
                    canonical_wire_hex=canonical.hex(),
                )
            )

        for kind, (category, _, _) in KINDS.items():

            def model(ids, **extra):
                return dict(
                    ids=ids, nas_length=None, slice=None, transfer=category, **extra
                )

            for count in range(1, 257):
                record(f"count-{count}", kind, model(list(range(count))))
            record("unordered-boundaries", kind, model([255, 0, 254, 1]))
            record("duplicate-session", kind, model([1, 1]), False)
            for transfer in choices:
                if transfer.startswith(category + "-"):
                    m = model([0, 255])
                    m["transfer"] = transfer
                    record(transfer, kind, m, bases[transfer]["admitted"])
            if category == "request":
                for length in [
                    0,
                    1,
                    127,
                    128,
                    16383,
                    16384,
                    16385,
                    32767,
                    32768,
                    32769,
                    49151,
                    49152,
                    49153,
                    65535,
                    65536,
                    65537,
                ]:
                    m = model([255])
                    m["nas_length"] = length
                    m["slice"] = dict(sst=1, sd="abcdef")
                    record(f"nas-{length}", kind, m)
                for sst in range(256):
                    m = model([sst])
                    m["slice"] = dict(
                        sst=sst,
                        sd=None if sst % 2 else "000000" if sst % 4 else "ffffff",
                    )
                    record(f"slice-{sst}", kind, m)
                m = model([0])
                m["slice"] = dict(sst=255, sd="ffffff")
                v = value(kind, m)
                v[0]["iE-Extensions"][0]["criticality"] = "ignore"
                record("slice-wrong-criticality", kind, m, False, v)
                v = value(kind, m)
                v[0]["iE-Extensions"] *= 2
                record("duplicate-slice-extension", kind, m, False, v)
            v = value(kind, model([0]))
            v[0]["iE-Extensions"] = [
                {
                    "id": 65530,
                    "criticality": "ignore",
                    "extensionValue": ("_unk_004", b"\xa5\x5a"),
                }
            ]
            record("unsupported-item-extension", kind, model([0]), False, v)
    args.output.write_text(
        json.dumps(
            dict(
                source_sha256=SPEC_SHA256,
                reference_tools=VERSIONS,
                input_sha256={
                    key: hashlib.sha256(v).hexdigest() for key, v in inputs.items()
                },
                base_transfers={
                    key: {
                        "wire_hex": v["wire_hex"],
                        "model": v.get("model"),
                        "fields": v.get("fields"),
                        "admitted": v["admitted"],
                    }
                    for key, v in bases.items()
                },
                cases=cases,
            ),
            indent=2,
        )
        + "\n"
    )
    print(
        f"Wrote {len(cases)} session lists; {sum(v['admitted'] for v in cases)} admitted"
    )


if __name__ == "__main__":
    main()
