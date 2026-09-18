#!/usr/bin/env python3
"""Independent Release 18 complete PDU Session Resource Notify messages."""

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

KIND = "PDUSessionResourceNotify"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    fields_corpus = json.loads(
        (
            root / "crates/opc-proto-ngap/tests/fixtures/n3iwf-notify-fields.json"
        ).read_text()
    )
    assert fields_corpus["source_sha256"] == SPEC_SHA256
    published = json.loads(
        (
            root / "crates/opc-n3iwf-fixtures/oracles/ngap-rel18-messages.json"
        ).read_text()
    )
    cases = []
    with tempfile.TemporaryDirectory(prefix="ngap-notify-message-reference-") as tmp:
        ref = compile_reference(args.spec.read_bytes(), Path(tmp))
        rows = {v["id"]: v for v in ref.rows(KIND)}

        def encode(target, value):
            target.set_val(copy.deepcopy(value))
            wire = target.to_aper_ws()
            assert target.to_aper() == wire
            return wire

        def field(ident, value):
            row = rows[ident]
            return dict(
                id=ident,
                criticality=row["criticality"],
                value=(row["Value"]._typeref.called[1], value),
            )

        def entries(value):
            return value[1]["value"][1]["protocolIEs"]

        def make(values):
            choice, code, crit = ref.procedures[KIND]
            return choice, dict(
                procedureCode=code,
                criticality=crit,
                value=(KIND, dict(protocolIEs=[field(i, v) for i, v in values])),
            )

        def independent_list(name):
            row = next(v for v in fields_corpus["cases"] if v["name"] == name)
            target = getattr(ref.schema.NGAP_IEs, row["type"])
            wire = bytes.fromhex(row["wire_hex"])
            assert hashlib.sha256(wire).hexdigest() == row["wire_sha256"]
            target.from_aper_ws(wire)
            assert target.to_aper_ws() == wire
            return copy.deepcopy(target.get_val())

        def metadata(value):
            result = []
            for item in entries(value):
                wire = (
                    item["value"][1]
                    if item["value"][0].startswith("_unk_")
                    else encode(rows[item["id"]]["Value"], item["value"][1])
                )
                result.append(
                    dict(
                        id=item["id"],
                        criticality=item["criticality"],
                        wire_hex=wire.hex(),
                    )
                )
            return result

        def semantic(decoded):
            ies = {v["id"]: v["value"][1] for v in decoded["protocolIEs"]}
            if 66 not in ies and 67 not in ies:
                raise Invalid("missing-session-reports")
            ids = []
            for item in ies.get(66, []):
                ids.append(item["pDUSessionID"])
                transfer = item["pDUSessionResourceNotifyTransfer"][1]
                flows = [
                    v["qosFlowIdentifier"]
                    for v in transfer.get("qosFlowNotifyList", [])
                ]
                flows += [
                    v["qosFlowIdentifier"]
                    for v in transfer.get("qosFlowReleasedList", [])
                ]
                if not flows or len(flows) != len(set(flows)):
                    raise Invalid("empty-or-conflicting-flow-reports")
            ids += [v["pDUSessionID"] for v in ies.get(67, [])]
            if len(ids) != len(set(ids)):
                raise Invalid("conflicting-session-reports")

        def record(name, value, admitted=True, mode="valid"):
            value = copy.deepcopy(value)
            order = {ident: i for i, ident in enumerate(rows)}
            entries(value).sort(key=lambda v: order.get(v["id"], 65536))
            wire = encode(ref.pdu, value)
            error = None
            try:
                ref.pdu.from_aper_ws(wire)
                assert ref.pdu.to_aper_ws() == wire
                decoded = ref.pdu.get_val()[1]["value"][1]
                ref.validate_container(KIND, decoded, 256)
                ref.validate_n3iwf(KIND, decoded)
                semantic(decoded)
            except Invalid as exc:
                error = str(exc)
            except Exception:
                error = "reference-framing-or-value"
            assert (error is None) == admitted, (name, error, admitted)
            canonical = copy.deepcopy(value)
            entries(canonical)[:] = [v for v in entries(canonical) if v["id"] != 65530]
            cases.append(
                dict(
                    name=name,
                    admitted=admitted,
                    mode=mode,
                    reference_error=error,
                    wire_hex=wire.hex(),
                    wire_sha256=hashlib.sha256(wire).hexdigest(),
                    fields=metadata(value),
                    canonical_fields=metadata(canonical),
                    canonical_wire_hex=encode(ref.pdu, canonical).hex(),
                )
            )

        amf, ran = 0x0102030405, 0x01020304
        ids = [(10, amf), (85, ran)]
        base = make(ids + [(66, independent_list("notified-sessions-1"))])
        for ident, prefix in [(66, "notified"), (67, "released")]:
            for count in [1, 2, 127, 128, 255, 256]:
                record(
                    f"{prefix}-{count}",
                    make(
                        ids + [(ident, independent_list(f"{prefix}-sessions-{count}"))]
                    ),
                )
        for count in [1, 2, 64, 256]:
            record(
                f"maximum-{count}",
                make(ids + [(66, independent_list(f"maximum-flows-{count}"))]),
            )
        notified = independent_list("notified-sessions-1")
        released = independent_list("released-sessions-1")
        released[0]["pDUSessionID"] = 255
        record("mixed-sessions", make(ids + [(66, notified), (67, released)]))
        released[0]["pDUSessionID"] = notified[0]["pDUSessionID"]
        record(
            "overlap-sessions",
            make(ids + [(66, notified), (67, released)]),
            False,
            "overlap",
        )
        record("missing-reports", make(ids), False, "missing")
        for ident in [10, 85]:
            value = copy.deepcopy(base)
            entries(value)[:] = [v for v in entries(value) if v["id"] != ident]
            record(f"missing-{ident}", value, False, "missing")
        for ident, name in [
            (66, "duplicate-notified-session"),
            (67, "duplicate-released-session"),
            (66, "empty-nested-transfer"),
        ]:
            record(name, make(ids + [(ident, independent_list(name))]), False, "nested")
        for ident, typ in [
            (66, "PDUSessionResourceNotifyList"),
            (67, "PDUSessionResourceReleasedListNot"),
        ]:
            value = copy.deepcopy(base)
            entries(value)[:] = [v for v in entries(value) if v["id"] != 66]
            entries(value).append(
                dict(
                    id=ident,
                    criticality=rows[ident]["criticality"],
                    value=("_unk_004", b"\x00"),
                )
            )
            record(f"truncated-list-{typ}", value, False, "framing")
        for criticality in ["ignore", "notify", "reject"]:
            value = copy.deepcopy(base)
            entries(value).append(
                dict(id=65530, criticality=criticality, value=("_unk_004", b"\x7c\x01"))
            )
            record("unknown-" + criticality, value, criticality != "reject", "unknown")
        for ident in [10, 85, 66]:
            value = copy.deepcopy(base)
            entry = next(v for v in entries(value) if v["id"] == ident)
            duplicate = copy.deepcopy(entry)
            if ident in (10, 85):
                duplicate["value"] = (duplicate["value"][0], 1)
            else:
                duplicate = field(66, independent_list("notified-sessions-2"))
            entries(value).append(duplicate)
            record(f"duplicate-{ident}", value, False, "duplicate")
            value = copy.deepcopy(base)
            entry = next(v for v in entries(value) if v["id"] == ident)
            entry["criticality"] = "ignore"
            record(f"criticality-{ident}", value, False, "criticality")
        for a, r in [
            (0, 0),
            (255, 255),
            (256, 256),
            (65535, 65535),
            (65536, 65536),
            ((1 << 40) - 1, (1 << 32) - 1),
        ]:
            record(f"ids-{a}-{r}", make([(10, a), (85, r), (66, notified)]))
        for name in ["complete-initial-ue-message", "complete-n3iwf-ipv6-without-port"]:
            source = next(v for v in published["cases"] if v["name"] == name)
            location = next(v for v in entries(unpack(source["pdu"])) if v["id"] == 121)
            value = copy.deepcopy(base)
            entries(value).append(field(121, location["value"][1]))
            record("location-" + name, value)
    args.output.write_text(
        json.dumps(
            dict(source_sha256=SPEC_SHA256, reference_tools=VERSIONS, cases=cases),
            indent=2,
        )
        + "\n"
    )
    print(f"Wrote {len(cases)} messages; {sum(v['admitted'] for v in cases)} admitted")


if __name__ == "__main__":
    main()
