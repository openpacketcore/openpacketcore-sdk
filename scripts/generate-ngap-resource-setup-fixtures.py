#!/usr/bin/env python3
"""Independent Release 18 Initial Context/PDU Session Setup messages."""

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

KINDS = {
    "InitialContextSetupRequest": "complete-initial-context-setup-request",
    "InitialContextSetupResponse": "complete-initial-context-setup-response",
    "InitialContextSetupFailure": "complete-initial-context-setup-failure",
    "PDUSessionResourceSetupRequest": "complete-pdu-session-resource-setup-request",
    "PDUSessionResourceSetupResponse": "complete-pdu-session-resource-setup-response",
}
IGNORED_CONTEXT = [
    18,
    36,
    117,
    31,
    24,
    91,
    118,
    146,
    33,
    165,
    177,
    199,
    205,
    206,
    209,
    216,
    215,
    218,
    217,
    219,
    222,
    234,
    254,
    264,
    119,
    326,
    328,
    334,
    335,
    345,
    346,
    367,
    373,
    374,
    375,
    376,
    377,
    378,
    400,
    347,
]


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
    lists = json.loads(
        (
            root / "crates/opc-proto-ngap/tests/fixtures/n3iwf-session-lists.json"
        ).read_text()
    )
    bases = {
        kind: unpack(next(v["pdu"] for v in published["cases"] if v["name"] == name))
        for kind, name in KINDS.items()
    }
    cases = []

    def entries(value):
        return value[1]["value"][1]["protocolIEs"]

    def remove(value, ids):
        entries(value)[:] = [v for v in entries(value) if v["id"] not in ids]

    with tempfile.TemporaryDirectory(
        prefix="ngap-resource-setup-reference-"
    ) as temporary:
        ref = compile_reference(args.spec.read_bytes(), Path(temporary))
        capabilities = copy.deepcopy(
            next(
                v
                for v in entries(bases["InitialContextSetupRequest"])
                if v["id"] == 119
            )
        )
        masks = [
            capabilities["value"][1][key][0]
            for key in (
                "nRencryptionAlgorithms",
                "nRintegrityProtectionAlgorithms",
                "eUTRAencryptionAlgorithms",
                "eUTRAintegrityProtectionAlgorithms",
            )
        ]
        location = unpack(
            next(
                v["pdu"]
                for v in published["cases"]
                if v["name"] == "complete-initial-ue-message"
            )
        )
        location = copy.deepcopy(next(v for v in entries(location) if v["id"] == 121))

        def field(kind, ident, value):
            row = next(v for v in ref.rows(kind) if v["id"] == ident)
            return {
                "id": ident,
                "criticality": row["criticality"],
                "value": (row["Value"]._typeref.called[1], value),
            }

        def replace(value, item):
            remove(value, [item["id"]])
            entries(value).append(copy.deepcopy(item))

        def sort(value):
            rows = {
                row["id"]: i for i, row in enumerate(ref.rows(value[1]["value"][0]))
            }
            entries(value).sort(key=lambda v: rows.get(v["id"], 65536))

        def canonical_nested(value):
            # An incoming transfer may use any IE order. Typed construction
            # uses the independently compiled ASN.1 object-set order.
            if isinstance(value, tuple) and isinstance(value[0], str):
                name, body = value
                if (
                    name.endswith("Transfer")
                    and isinstance(body, dict)
                    and "protocolIEs" in body
                ):
                    order = {row["id"]: i for i, row in enumerate(ref.rows(name))}
                    body["protocolIEs"] = [
                        item for item in body["protocolIEs"] if item["id"] in order
                    ]
                    body["protocolIEs"].sort(
                        key=lambda item: order.get(item["id"], 65536)
                    )
                canonical_nested(body)
            elif isinstance(value, dict):
                for item in value.values():
                    canonical_nested(item)
            elif isinstance(value, list):
                for item in value:
                    canonical_nested(item)

        def encoded_fields(value):
            kind = value[1]["value"][0]
            rows = {row["id"]: row for row in ref.rows(kind)}
            result = []
            for item in entries(value):
                if item["value"][0].startswith("_unk_"):
                    wire = item["value"][1]
                else:
                    target = rows[item["id"]]["Value"]
                    target.set_val(copy.deepcopy(item["value"][1]))
                    wire = target.to_aper()
                    assert target.to_aper_ws() == wire
                result.append(
                    {
                        "id": item["id"],
                        "criticality": item["criticality"],
                        "wire_hex": wire.hex(),
                    }
                )
            return result

        def encode(value):
            ref.pdu.set_val(copy.deepcopy(value))
            wire = ref.pdu.to_aper()
            assert ref.pdu.to_aper_ws() == wire
            return wire

        def record(name, value, admitted=True, mode="valid", **extra):
            value = copy.deepcopy(value)
            kind = value[1]["value"][0]
            wire = encode(value)
            error = None
            try:
                ref.pdu.from_aper_ws(wire)
                decoded = copy.deepcopy(ref.pdu.get_val())
                assert ref.pdu.to_aper() == wire
                ref.validate_container(kind, decoded[1]["value"][1], 256)
                ref.validate_n3iwf(kind, decoded[1]["value"][1])
            except Invalid as exc:
                error = str(exc)
            except Exception:
                error = "reference-framing-or-value"
            canonical = copy.deepcopy(value)
            ignored = (
                IGNORED_CONTEXT
                if kind == "InitialContextSetupRequest"
                else ([83, 335] if kind == "PDUSessionResourceSetupRequest" else [])
            )
            remove(canonical, [i for i in ignored if i != 119] + [65530])
            if kind == "InitialContextSetupRequest":
                replace(canonical, capabilities)
            sort(canonical)
            canonical_nested(canonical)
            if admitted and mode != "ignored":
                assert error is None, (name, error)
            cases.append(
                {
                    "name": name,
                    "kind": kind,
                    "admitted": admitted,
                    "mode": mode,
                    "reference_error": error,
                    "wire_hex": wire.hex(),
                    "wire_sha256": hashlib.sha256(wire).hexdigest(),
                    "fields": encoded_fields(value),
                    "canonical_fields": encoded_fields(canonical),
                    "canonical_wire_hex": encode(canonical).hex(),
                    "capabilities": masks,
                    **extra,
                }
            )

        for kind, original in bases.items():
            sort(original)
            record("base-" + kind, original)
            for row in ref.rows(kind):
                if row["presence"] == "mandatory":
                    value = copy.deepcopy(original)
                    remove(value, [row["id"]])
                    record(
                        f"missing-{kind}-{row['id']}",
                        value,
                        False,
                        "missing",
                        missing_id=row["id"],
                    )
                    assert cases[-1]["reference_error"] == "missing-mandatory-ie"
            value = copy.deepcopy(original)
            first = copy.deepcopy(entries(value)[0])
            first["value"] = (first["value"][0], 7)
            entries(value).insert(0, first)
            record("duplicate-" + kind, value, False, "duplicate")
            assert cases[-1]["reference_error"] == "duplicate-ie"
            for criticality in ("ignore", "notify", "reject"):
                value = copy.deepcopy(original)
                entries(value).append(
                    {
                        "id": 65530,
                        "criticality": criticality,
                        "value": ("_unk_004", b"\xff\x00"),
                    }
                )
                record(
                    f"unknown-{kind}-{criticality}",
                    value,
                    criticality != "reject",
                    "unknown",
                    criticality=criticality,
                )

        for kind in ("InitialContextSetupRequest", "PDUSessionResourceSetupRequest"):
            original = bases[kind]
            ident = 71 if kind == "InitialContextSetupRequest" else 74
            list_type = (
                "PDUSessionResourceSetupListCxtReq"
                if ident == 71
                else "PDUSessionResourceSetupListSUReq"
            )
            for prefix in (
                "count-256-",
                "nas-length-16385-",
                "nas-length-65535-",
                "request-max-",
                "request-notify-",
                "request-ignore-",
                "request-reject-",
                "duplicate-session-",
            ):
                row = next(
                    v
                    for v in lists["cases"]
                    if v["name"].startswith(prefix) and v["type"] == list_type
                )
                target = getattr(ref.schema.NGAP_IEs, list_type)
                target.from_aper_ws(bytes.fromhex(row["wire_hex"]))
                value = copy.deepcopy(original)
                replace(value, field(kind, ident, copy.deepcopy(target.get_val())))
                sort(value)
                record(
                    prefix + kind,
                    value,
                    row["admitted"],
                    "list",
                    nested_unknown=row["model"]["transfer"],
                )
            for length in (0, 3, 16385):
                value = copy.deepcopy(original)
                nas = b"".join(
                    hashlib.sha256(f"top-nas-block-{i}".encode()).digest()
                    for i in range((length + 31) // 32)
                )[:length]
                replace(value, field(kind, 38, nas))
                if kind == "PDUSessionResourceSetupRequest":
                    rate = copy.deepcopy(
                        next(
                            v
                            for v in entries(bases["InitialContextSetupRequest"])
                            if v["id"] == 110
                        )
                    )
                    rate["criticality"] = "ignore"
                    replace(value, rate)
                sort(value)
                record(f"top-nas-{length}-{kind}", value)
            ignored = IGNORED_CONTEXT if ident == 71 else [83, 335]
            for ie_id in ignored:
                value = copy.deepcopy(original)
                row = next(v for v in ref.rows(kind) if v["id"] == ie_id)
                replace(
                    value,
                    {
                        "id": ie_id,
                        "criticality": row["criticality"],
                        "value": ("_unk_004", b""),
                    },
                )
                record(
                    f"ignored-{kind}-{ie_id}", value, True, "ignored", ignored_id=ie_id
                )
            for ie_id in ([108, 48, 238] if ident == 71 else []):
                value = copy.deepcopy(original)
                row = next(v for v in ref.rows(kind) if v["id"] == ie_id)
                replace(
                    value,
                    {
                        "id": ie_id,
                        "criticality": row["criticality"],
                        "value": ("_unk_004", b""),
                    },
                )
                record(
                    f"unsupported-{kind}-{ie_id}",
                    value,
                    False,
                    "unsupported",
                    unsupported_id=ie_id,
                )

        value = copy.deepcopy(bases["InitialContextSetupRequest"])
        remove(value, [110])
        record("missing-conditional-ambr", value, False, "conditional")
        assert cases[-1]["reference_error"] == "missing-ue-ambr"
        remove(value, [71])
        record("context-without-resources", value)
        value = copy.deepcopy(bases["InitialContextSetupFailure"])
        remove(value, [132])
        record("context-failure-without-session-list", value)

        for kind, yes, no in [
            ("InitialContextSetupResponse", 72, 55),
            ("PDUSessionResourceSetupResponse", 75, 58),
        ]:
            for omitted in ([yes], [no], [yes, no]):
                value = copy.deepcopy(bases[kind])
                remove(value, omitted)
                record(
                    f"omit-{kind}-{'-'.join(map(str, omitted))}",
                    value,
                    kind == "InitialContextSetupResponse" or len(omitted) == 1,
                    "result-presence",
                )
            value = copy.deepcopy(bases[kind])
            items = {v["id"]: v["value"][1] for v in entries(value)}
            items[no][0]["pDUSessionID"] = items[yes][0]["pDUSessionID"]
            record("conflict-" + kind, value, False, "conflict")
            value = copy.deepcopy(bases[kind])
            entries(value).append(
                {"id": 19, "criticality": "ignore", "value": ("_unk_004", b"")}
            )
            record(
                "unsupported-diagnostics-" + kind,
                value,
                False,
                "unsupported",
                unsupported_id=19,
            )
        value = copy.deepcopy(bases["PDUSessionResourceSetupResponse"])
        replace(
            value, field("PDUSessionResourceSetupResponse", 121, location["value"][1])
        )
        sort(value)
        record("session-response-location", value)

    args.output.write_text(
        json.dumps(
            {
                "source_sha256": SPEC_SHA256,
                "reference_tools": VERSIONS,
                "reference_decoder": "from_aper_ws; both encoders must agree",
                "cases": cases,
            },
            indent=2,
        )
        + "\n"
    )
    print("Wrote", len(cases), "independent resource setup messages")


if __name__ == "__main__":
    main()
