#!/usr/bin/env python3
"""Independent Release 18 complete Modify Request/Response messages."""

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
    fixture = root / "crates/opc-proto-ngap/tests/fixtures/n3iwf-modify-lists.json"
    data = fixture.read_bytes()
    lists = json.loads(data)
    published = json.loads(
        (
            root / "crates/opc-n3iwf-fixtures/oracles/ngap-rel18-messages.json"
        ).read_text()
    )
    cases = []
    with tempfile.TemporaryDirectory(prefix="ngap-modify-message-") as tmp:
        ref = compile_reference(args.spec.read_bytes(), Path(tmp))

        def encode(target, value):
            target.set_val(copy.deepcopy(value))
            wire = target.to_aper_ws()
            assert target.to_aper() == wire
            return wire

        def independent(name):
            row = next(v for v in lists["cases"] if v["name"] == name)
            target = getattr(ref.schema.NGAP_IEs, row["type"])
            wire = bytes.fromhex(row["wire_hex"])
            target.from_aper_ws(wire)
            assert target.to_aper_ws() == wire
            return copy.deepcopy(target.get_val())

        def entries(value):
            return value[1]["value"][1]["protocolIEs"]

        for kind in [
            "PDUSessionResourceModifyRequest",
            "PDUSessionResourceModifyResponse",
        ]:
            rows = {v["id"]: v for v in ref.rows(kind)}

            def field(ident, value):
                r = rows[ident]
                return dict(
                    id=ident,
                    criticality=r["criticality"],
                    value=(r["Value"]._typeref.called[1], value),
                )

            def make(values):
                choice, code, crit = ref.procedures[kind]
                return choice, dict(
                    procedureCode=code,
                    criticality=crit,
                    value=(kind, dict(protocolIEs=[field(i, v) for i, v in values])),
                )

            def metadata(value):
                return [
                    dict(
                        id=v["id"],
                        criticality=v["criticality"],
                        wire_hex=(
                            v["value"][1]
                            if v["value"][0].startswith("_unk_")
                            else encode(rows[v["id"]]["Value"], v["value"][1])
                        ).hex(),
                    )
                    for v in entries(value)
                ]

            def semantic(decoded):
                fs = {v["id"]: v["value"][1] for v in decoded["protocolIEs"]}
                if kind.endswith("Response"):
                    if 65 not in fs and 54 not in fs:
                        raise Invalid("missing-session-results")
                    ids = [
                        v["pDUSessionID"]
                        for ident in [65, 54]
                        for v in fs.get(ident, [])
                    ]
                    if len(ids) != len(set(ids)):
                        raise Invalid("conflicting-sessions")
                    d = fs.get(19, {})
                    if "procedureCode" in d or "triggeringMessage" in d:
                        raise Invalid("response-diagnostic-header")
                for item in fs.get(64, []):
                    t = item["pDUSessionResourceModifyRequestTransfer"][1]
                    ref.validate_container(
                        "PDUSessionResourceModifyRequestTransfer", t, 256
                    )
                    q = [
                        v["qosFlowIdentifier"]
                        for ie in t["protocolIEs"]
                        if ie["id"] in [135, 137]
                        for v in ie["value"][1]
                    ]
                    if len(q) != len(set(q)):
                        raise Invalid("conflicting-qfis")

            def canonical(value):
                v = copy.deepcopy(value)
                entries(v)[:] = [ie for ie in entries(v) if ie["id"] not in [65530, 83]]
                for ie in entries(v):
                    if ie["id"] == 64:
                        for item in ie["value"][1]:
                            fields = item["pDUSessionResourceModifyRequestTransfer"][1][
                                "protocolIEs"
                            ]
                            fields[:] = [x for x in fields if x["id"] != 65530]
                return v

            def record(name, value, admitted=True, mode="valid"):
                value = copy.deepcopy(value)
                order = {ident: i for i, ident in enumerate(rows)}
                entries(value).sort(key=lambda x: order.get(x["id"], 65536))
                wire = encode(ref.pdu, value)
                err = None
                try:
                    ref.pdu.from_aper_ws(wire)
                    decoded = copy.deepcopy(ref.pdu.get_val()[1]["value"][1])
                    assert ref.pdu.to_aper_ws() == wire
                    ref.validate_container(kind, decoded, 256)
                    ref.validate_n3iwf(kind, decoded)
                    semantic(decoded)
                except Invalid as e:
                    err = str(e)
                except Exception:
                    err = "reference-framing-or-value"
                assert (err is None) == admitted, (kind, name, err)
                c = canonical(value)
                cases.append(
                    dict(
                        name=kind + "-" + name,
                        kind=kind,
                        admitted=admitted,
                        mode=mode,
                        reference_error=err,
                        wire_hex=wire.hex(),
                        wire_sha256=hashlib.sha256(wire).hexdigest(),
                        fields=metadata(value),
                        canonical_fields=metadata(c),
                        canonical_wire_hex=encode(ref.pdu, c).hex(),
                    )
                )

            ids = [(10, 0x0102030405), (85, 0x01020304)]
            request = kind.endswith("Request")
            primary = 64 if request else 65
            category = "request" if request else "response"
            base = make(ids + [(primary, independent(category + "-count-1"))])
            for count in [1, 2, 127, 128, 255, 256]:
                record(
                    "sessions-" + str(count),
                    make(
                        ids
                        + [(primary, independent(category + "-count-" + str(count)))]
                    ),
                )
            names = (
                [
                    "request-request-empty",
                    "request-request-max",
                    "request-request-ignore",
                    "request-request-notify",
                    "request-nas-65537",
                    "request-slice-0",
                    "request-slice-1",
                ]
                if request
                else [
                    "response-response-empty",
                    "response-response-max",
                    "response-response-partial",
                ]
            )
            for name in names:
                record(name, make(ids + [(primary, independent(name))]))
            if request:
                record(
                    "paging-ignored",
                    make(ids + [(83, 256), (64, independent("request-count-1"))]),
                    mode="ignored",
                )
                for name in [
                    "request-request-reject",
                    "request-request-overlap",
                    "request-request-duplicate",
                ]:
                    record(name, make(ids + [(64, independent(name))]), False, "nested")
            else:
                for name in [
                    "failure-count-1",
                    "failure-count-256",
                    "failure-failure-diagnostics",
                ]:
                    record(name, make(ids + [(54, independent(name))]))
                success = independent("response-count-1")
                failed = independent("failure-count-1")
                failed[0]["pDUSessionID"] = 255
                record("partial", make(ids + [(65, success), (54, failed)]))
                failed[0]["pDUSessionID"] = 0
                record(
                    "overlap",
                    make(ids + [(65, success), (54, failed)]),
                    False,
                    "overlap",
                )
                record("no-results", make(ids), False, "missing")
                for d in [
                    {},
                    {"procedureCriticality": "reject"},
                    {
                        "iEsCriticalityDiagnostics": [
                            {
                                "iECriticality": "reject",
                                "iE-ID": 64,
                                "typeOfError": "missing",
                            }
                        ]
                    },
                ]:
                    record(
                        "diagnostics-" + str(len(cases)),
                        make(ids + [(65, success), (19, d)]),
                    )
                for d in [
                    {"procedureCode": 26},
                    {"triggeringMessage": "initiating-message"},
                ]:
                    record(
                        "inapplicable-diagnostics-" + str(len(cases)),
                        make(ids + [(65, success), (19, d)]),
                        False,
                        "diagnostics",
                    )
                source = next(
                    v
                    for v in published["cases"]
                    if v["name"] == "complete-initial-ue-message"
                )
                loc = next(v for v in entries(unpack(source["pdu"])) if v["id"] == 121)[
                    "value"
                ][1]
                record("location", make(ids + [(65, success), (121, loc)]))
            for ident in [10, 85] + ([64] if request else []):
                v = copy.deepcopy(base)
                entries(v)[:] = [x for x in entries(v) if x["id"] != ident]
                record("missing-" + str(ident), v, False, "missing")
            record(
                "duplicate-session",
                make(ids + [(primary, independent(category + "-duplicate-session"))]),
                False,
                "nested",
            )
            for criticality in ["ignore", "notify", "reject"]:
                v = copy.deepcopy(base)
                entries(v).append(
                    dict(
                        id=65530,
                        criticality=criticality,
                        value=("_unk_004", b"\x7c\x01"),
                    )
                )
                record("unknown-" + criticality, v, criticality != "reject", "unknown")
            for ident in [10, 85, primary]:
                v = copy.deepcopy(base)
                e = next(x for x in entries(v) if x["id"] == ident)
                dup = copy.deepcopy(e)
                dup["value"] = (
                    (dup["value"][0], 1)
                    if ident in [10, 85]
                    else field(ident, independent(category + "-count-2"))["value"]
                )
                entries(v).append(dup)
                record("duplicate-" + str(ident), v, False, "duplicate")
                v = copy.deepcopy(base)
                e = next(x for x in entries(v) if x["id"] == ident)
                e["criticality"] = (
                    "ignore" if e["criticality"] == "reject" else "reject"
                )
                record("criticality-" + str(ident), v, False, "criticality")
    args.output.write_text(
        json.dumps(
            dict(
                source_sha256=SPEC_SHA256,
                reference_tools=VERSIONS,
                list_sha256=hashlib.sha256(data).hexdigest(),
                cases=cases,
            ),
            indent=2,
        )
        + "\n"
    )
    print(f'Wrote {len(cases)} messages; {sum(v["admitted"] for v in cases)} admitted')


if __name__ == "__main__":
    main()
