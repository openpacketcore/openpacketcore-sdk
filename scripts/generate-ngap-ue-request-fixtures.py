#!/usr/bin/env python3
"""Independent Release 18 NAS Non-Delivery and UE Release Request messages."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import tempfile

from n3iwf_ngap_reference import Invalid, SPEC_SHA256, VERSIONS, compile_reference

NAS = "NASNonDeliveryIndication"
RELEASE = "UEContextReleaseRequest"
LIST = "PDUSessionResourceListCxtRelReq"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cases, messages, causes = [], [], []
    with tempfile.TemporaryDirectory(prefix="ngap-ue-request-reference-") as temporary:
        ref = compile_reference(args.spec.read_bytes(), Path(temporary))
        for group, name in (
            ("radioNetwork", "CauseRadioNetwork"),
            ("transport", "CauseTransport"),
            ("nas", "CauseNas"),
            ("protocol", "CauseProtocol"),
            ("misc", "CauseMisc"),
        ):
            enum = getattr(ref.schema.NGAP_IEs, name)
            for label in enum._root:
                causes.append((group, label))

        def encode_leaf(target, value):
            target.set_val(copy.deepcopy(value))
            wire = target.to_aper()
            assert target.to_aper_ws() == wire
            target.from_aper_ws(wire)
            assert target.get_val() == value
            assert target.to_aper() == wire
            return wire

        def items(ids):
            return [{"pDUSessionID": ident} for ident in ids]

        for count in range(1, 257):
            ids = [(index * 73 + count) % 256 for index in range(count)]
            wire = encode_leaf(getattr(ref.schema.NGAP_IEs, LIST), items(ids))
            cases.append(
                dict(
                    name=f"count-{count}",
                    model=ids,
                    admitted=True,
                    wire_hex=wire.hex(),
                    wire_sha256=hashlib.sha256(wire).hexdigest(),
                )
            )
        wire = encode_leaf(getattr(ref.schema.NGAP_IEs, LIST), items([2, 2]))
        cases.append(
            dict(
                name="duplicate-session",
                model=[2, 2],
                admitted=False,
                wire_hex=wire.hex(),
                wire_sha256=hashlib.sha256(wire).hexdigest(),
            )
        )

        def field(kind, ident, value):
            row = next(v for v in ref.rows(kind) if v["id"] == ident)
            return dict(
                id=ident,
                criticality=row["criticality"],
                value=(row["Value"]._typeref.called[1], value),
            )

        def entries(value):
            return value[1]["value"][1]["protocolIEs"]

        def replace(value, item):
            entries(value)[:] = [v for v in entries(value) if v["id"] != item["id"]]
            entries(value).append(copy.deepcopy(item))

        def make(kind, values):
            choice, code, crit = ref.procedures[kind]
            return (
                choice,
                dict(
                    procedureCode=code,
                    criticality=crit,
                    value=(
                        kind,
                        dict(
                            protocolIEs=[
                                field(kind, ident, value) for ident, value in values
                            ]
                        ),
                    ),
                ),
            )

        def sort(value):
            order = {
                row["id"]: i for i, row in enumerate(ref.rows(value[1]["value"][0]))
            }
            entries(value).sort(key=lambda v: order.get(v["id"], 65536))

        def fields(value):
            rows = {row["id"]: row for row in ref.rows(value[1]["value"][0])}
            result = []
            for item in entries(value):
                wire = (
                    item["value"][1]
                    if item["value"][0].startswith("_unk_")
                    else encode_leaf(rows[item["id"]]["Value"], item["value"][1])
                )
                result.append(
                    dict(
                        id=item["id"],
                        criticality=item["criticality"],
                        wire_hex=wire.hex(),
                    )
                )
            return result

        def record(name, value, admitted=True, mode="valid", **extra):
            value = copy.deepcopy(value)
            kind = value[1]["value"][0]
            sort(value)
            ref.pdu.set_val(value)
            wire = ref.pdu.to_aper()
            assert ref.pdu.to_aper_ws() == wire
            error = None
            try:
                ref.pdu.from_aper_ws(wire)
                assert ref.pdu.to_aper() == wire
                decoded = ref.pdu.get_val()[1]["value"][1]
                ref.validate_container(kind, decoded, 256)
                ref.validate_n3iwf(kind, decoded)
            except Invalid as exc:
                error = str(exc)
            except Exception:
                error = "reference-framing-or-value"
            if admitted:
                assert error is None, (name, error)
            canonical = copy.deepcopy(value)
            entries(canonical)[:] = [v for v in entries(canonical) if v["id"] != 65530]
            ref.pdu.set_val(copy.deepcopy(canonical))
            canonical_wire = ref.pdu.to_aper()
            assert ref.pdu.to_aper_ws() == canonical_wire
            messages.append(
                dict(
                    name=name,
                    kind=kind,
                    admitted=admitted,
                    mode=mode,
                    reference_error=error,
                    wire_hex=wire.hex(),
                    wire_sha256=hashlib.sha256(wire).hexdigest(),
                    fields=fields(value),
                    canonical_fields=fields(canonical),
                    canonical_wire_hex=canonical_wire.hex(),
                    **extra,
                )
            )

        bases = {
            NAS: make(
                NAS,
                [
                    (10, 0x8123456789),
                    (85, 0x87654321),
                    (38, b"\x7e\x00\x42"),
                    (15, causes[0]),
                ],
            ),
            RELEASE: make(
                RELEASE, [(10, 0x8123456789), (85, 0x87654321), (15, causes[0])]
            ),
        }
        for kind, original in bases.items():
            record("base-" + kind, original)
            for cause in causes:
                value = copy.deepcopy(original)
                replace(value, field(kind, 15, cause))
                record(f"cause-{kind}-{cause[0]}-{cause[1]}", value)
                wire = bytearray(encode_leaf(ref.schema.NGAP_IEs.Cause, cause))
                wire[-1] |= 1
                replace(
                    value,
                    dict(id=15, criticality="ignore", value=("_unk_004", bytes(wire))),
                )
                record(f"padding-{kind}-{cause[0]}-{cause[1]}", value, False, "padding")
                assert messages[-1]["reference_error"] == "reference-framing-or-value"
            for row in ref.rows(kind):
                if row["presence"] != "mandatory":
                    continue
                value = copy.deepcopy(original)
                entries(value)[:] = [v for v in entries(value) if v["id"] != row["id"]]
                record(f"missing-{kind}-{row['id']}", value, False, "missing")
                assert messages[-1]["reference_error"] == "missing-mandatory-ie"
            value = copy.deepcopy(original)
            first = copy.deepcopy(entries(value)[0])
            first["value"] = (first["value"][0], 7)
            entries(value).insert(0, first)
            record("duplicate-" + kind, value, False, "duplicate")
            for criticality in ("ignore", "notify", "reject"):
                value = copy.deepcopy(original)
                entries(value).append(
                    dict(
                        id=65530,
                        criticality=criticality,
                        value=("_unk_004", b"\xff\x00"),
                    )
                )
                record(
                    f"unknown-{kind}-{criticality}",
                    value,
                    criticality != "reject",
                    "unknown",
                    criticality=criticality,
                )
            for original_ie in entries(original):
                value = copy.deepcopy(original)
                next(v for v in entries(value) if v["id"] == original_ie["id"])[
                    "criticality"
                ] = "notify"
                record(
                    f"criticality-{kind}-{original_ie['id']}",
                    value,
                    False,
                    "criticality",
                )

        for length in (0, 3, 16383, 16384, 16385, 65535):
            value = copy.deepcopy(bases[NAS])
            nas = b"".join(
                hashlib.sha256(f"non-delivery-nas-{i}".encode()).digest()
                for i in range((length + 31) // 32)
            )[:length]
            replace(value, field(NAS, 38, nas))
            record(f"nas-length-{length}", value)
        for count in (1, 2, 255, 256):
            ids = next(row["model"] for row in cases if row["name"] == f"count-{count}")
            value = copy.deepcopy(bases[RELEASE])
            replace(value, field(RELEASE, 133, items(ids)))
            record(f"sessions-{count}", value)
        value = copy.deepcopy(bases[RELEASE])
        replace(value, field(RELEASE, 133, items([2, 2])))
        record("duplicate-session-message", value, False, "list-duplicate")

        procedures = {kind: list(ref.procedures[kind]) for kind in bases}
        profiles = {
            kind: [
                dict(
                    id=row["id"],
                    criticality=row["criticality"],
                    presence=row["presence"],
                )
                for row in ref.rows(kind)
            ]
            for kind in bases
        }
    document = dict(
        source_sha256=SPEC_SHA256,
        reference_tools=VERSIONS,
        reference_decoder="from_aper_ws; both encoders agree",
        procedures=procedures,
        profiles=profiles,
        cases=cases,
        messages=messages,
    )
    rendered = json.dumps(document, indent=2)
    for case in cases:
        expanded = json.dumps(case["model"], indent=2).replace("\n", "\n      ")
        rendered = rendered.replace(
            '"model": ' + expanded, '"model": ' + json.dumps(case["model"]), 1
        )
    assert json.loads(rendered) == document
    args.output.write_text(rendered + "\n")
    print(
        "Wrote",
        len(cases),
        "independent session lists and",
        len(messages),
        "complete UE requests",
    )


if __name__ == "__main__":
    main()
