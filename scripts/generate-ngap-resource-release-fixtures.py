#!/usr/bin/env python3
"""Independent Release 18 resource release transfers, lists and messages."""

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

COMMAND = "PDUSessionResourceReleaseCommand"
RESPONSE = "PDUSessionResourceReleaseResponse"
LISTS = {
    COMMAND: "PDUSessionResourceToReleaseListRelCmd",
    RESPONSE: "PDUSessionResourceReleasedListRelRes",
}
TRANSFERS = {kind: kind + "Transfer" for kind in LISTS}


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
    cases, messages, causes, labels = [], [], [], {}

    def entries(pdu):
        return pdu[1]["value"][1]["protocolIEs"]

    with tempfile.TemporaryDirectory(
        prefix="ngap-resource-release-reference-"
    ) as temporary:
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
                code = enum._cont[label]
                causes.append({"class": group, "code": code})
                labels[group, code] = label

        def transfer(kind, model):
            if kind == RESPONSE:
                return {}
            return {"cause": (model["class"], labels[model["class"], model["code"]])}

        def items(kind, model):
            return [
                {
                    "pDUSessionID": item["id"],
                    "pDUSessionResourceRelease"
                    + ("Command" if kind == COMMAND else "Response")
                    + "Transfer": (TRANSFERS[kind], transfer(kind, item.get("cause"))),
                }
                for item in model
            ]

        def encoded(target, value):
            target.set_val(copy.deepcopy(value))
            wire = target.to_aper()
            assert target.to_aper_ws() == wire
            target.from_aper_ws(wire)
            assert target.get_val() == value
            assert target.to_aper() == wire
            return wire

        def leaf(name, typ, value, model, admitted=True):
            wire = encoded(getattr(ref.schema.NGAP_IEs, typ), value)
            cases.append(
                dict(
                    name=name,
                    type=typ,
                    model=model,
                    admitted=admitted,
                    wire_hex=wire.hex(),
                    wire_sha256=hashlib.sha256(wire).hexdigest(),
                )
            )

        for cause in causes:
            leaf(
                f"command-{cause['class']}-{cause['code']}",
                TRANSFERS[COMMAND],
                transfer(COMMAND, cause),
                cause,
            )
        leaf("response-root", TRANSFERS[RESPONSE], {}, None)
        for kind in LISTS:
            for count in range(1, 257):
                model = [
                    dict(
                        id=(index * 73 + count) % 256, cause=causes[index % len(causes)]
                    )
                    for index in range(count)
                ]
                leaf(f"count-{count}-{kind}", LISTS[kind], items(kind, model), model)
            duplicate = [dict(id=2, cause=causes[0])] * 2
            leaf(
                f"duplicate-{kind}",
                LISTS[kind],
                items(kind, duplicate),
                duplicate,
                False,
            )

        bases = {}
        for kind, suffix in ((COMMAND, "command"), (RESPONSE, "response")):
            name = "complete-pdu-session-resource-release-" + suffix
            bases[kind] = unpack(
                next(v["pdu"] for v in published["cases"] if v["name"] == name)
            )

        def replace(value, item):
            entries(value)[:] = [v for v in entries(value) if v["id"] != item["id"]]
            entries(value).append(copy.deepcopy(item))

        def field(kind, ident, value):
            row = next(v for v in ref.rows(kind) if v["id"] == ident)
            return dict(
                id=ident,
                criticality=row["criticality"],
                value=(row["Value"]._typeref.called[1], value),
            )

        def fields(value):
            rows = {row["id"]: row for row in ref.rows(value[1]["value"][0])}
            result = []
            for item in entries(value):
                if item["value"][0].startswith("_unk_"):
                    wire = item["value"][1]
                else:
                    wire = encoded(rows[item["id"]]["Value"], item["value"][1])
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
            if admitted and mode != "ignored":
                assert error is None, (name, error)
            canonical = copy.deepcopy(value)
            entries(canonical)[:] = [
                v for v in entries(canonical) if v["id"] not in (83, 65530)
            ]
            order = {row["id"]: i for i, row in enumerate(ref.rows(kind))}
            entries(canonical).sort(key=lambda v: order.get(v["id"], 65536))
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

        for kind, original in bases.items():
            record("base-" + kind, original)
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
            for prefix in ("count-256-", "duplicate-"):
                case = next(c for c in cases if c["name"] == prefix + kind)
                value = copy.deepcopy(original)
                replace(
                    value,
                    field(
                        kind, 79 if kind == COMMAND else 70, items(kind, case["model"])
                    ),
                )
                record(prefix + "message-" + kind, value, case["admitted"], "list")

        for length in (0, 3, 16385, 65535):
            value = copy.deepcopy(bases[COMMAND])
            nas = b"".join(
                hashlib.sha256(f"release-nas-{i}".encode()).digest()
                for i in range((length + 31) // 32)
            )[:length]
            replace(value, field(COMMAND, 38, nas))
            record(f"nas-{length}", value)
        value = copy.deepcopy(bases[COMMAND])
        replace(value, dict(id=83, criticality="ignore", value=("_unk_004", b"")))
        record("ignored-paging", value, True, "ignored")
        value = copy.deepcopy(bases[RESPONSE])
        replace(value, dict(id=19, criticality="ignore", value=("_unk_004", b"")))
        record("unsupported-diagnostics", value, False, "unsupported")
        for source in (
            "complete-initial-ue-message",
            "complete-n3iwf-ipv6-without-port",
        ):
            matching = next(v for v in published["cases"] if v["name"] == source)
            location = next(
                v for v in entries(unpack(matching["pdu"])) if v["id"] == 121
            )
            value = copy.deepcopy(bases[RESPONSE])
            replace(value, field(RESPONSE, 121, location["value"][1]))
            record("location-" + source, value)

    document = dict(
        source_sha256=SPEC_SHA256,
        reference_tools=VERSIONS,
        reference_decoder="from_aper_ws; both encoders agree",
        cases=cases,
        messages=messages,
    )
    rendered = json.dumps(document, indent=2)
    # Keep each exhaustive list model together, alongside its independent wire.
    # Formatting does not change any model or reference bytes.
    for case in cases:
        model = case["model"]
        if isinstance(model, list):
            expanded = json.dumps(model, indent=2).replace("\n", "\n      ")
            rendered = rendered.replace(
                '"model": ' + expanded, '"model": ' + json.dumps(model), 1
            )
    assert json.loads(rendered) == document
    args.output.write_text(rendered + "\n")
    print(
        "Wrote",
        len(cases),
        "independent release fields and",
        len(messages),
        "complete messages",
    )


if __name__ == "__main__":
    main()
