#!/usr/bin/env python3
"""Independent Release 18 Reset/Acknowledge/Error Indication messages."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from n3iwf_ngap_reference import Invalid, SPEC_SHA256, VERSIONS, compile_reference

KINDS = ("NGReset", "NGResetAcknowledge", "ErrorIndication")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cases = []
    with tempfile.TemporaryDirectory(
        prefix="ngap-reset-message-reference-"
    ) as temporary:
        ref = compile_reference(args.spec.read_bytes(), Path(temporary))
        causes = []
        for group, name in [
            ("radioNetwork", "CauseRadioNetwork"),
            ("transport", "CauseTransport"),
            ("nas", "CauseNas"),
            ("protocol", "CauseProtocol"),
            ("misc", "CauseMisc"),
        ]:
            for label in getattr(ref.schema.NGAP_IEs, name)._root:
                causes.append((group, label))

        def encode(target, value):
            target.set_val(copy.deepcopy(value))
            wire = target.to_aper_ws()
            plain = True
            try:
                assert target.to_aper() == wire
            except AttributeError as exc:
                assert "encode_pas" in str(exc)
                plain = False
            return wire, plain

        def entries(value):
            return value[1]["value"][1]["protocolIEs"]

        def field(kind, ident, value):
            row = next(v for v in ref.rows(kind) if v["id"] == ident)
            return dict(
                id=ident,
                criticality=row["criticality"],
                value=(row["Value"]._typeref.called[1], value),
            )

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

        def replace(value, ident, content):
            entries(value)[:] = [v for v in entries(value) if v["id"] != ident]
            entries(value).append(field(value[1]["value"][0], ident, content))

        def fields(value):
            rows = {v["id"]: v for v in ref.rows(value[1]["value"][0])}
            result = []
            for item in entries(value):
                wire = (
                    item["value"][1]
                    if item["value"][0].startswith("_unk_")
                    else encode(rows[item["id"]]["Value"], item["value"][1])[0]
                )
                result.append(
                    dict(
                        id=item["id"],
                        criticality=item["criticality"],
                        wire_hex=wire.hex(),
                    )
                )
            return result

        def semantic(kind, decoded, signalling):
            if kind != "ErrorIndication" and signalling != "non-ue":
                raise Invalid("reset-requires-non-ue-signalling")
            ies = {item["id"]: item["value"][1] for item in decoded["protocolIEs"]}
            if kind == "ErrorIndication":
                if 15 not in ies and 19 not in ies:
                    raise Invalid("missing-error-basis")
                if signalling == "ue" and (10 not in ies or 85 not in ies):
                    raise Invalid("missing-ue-error-identifiers")
            if 19 in ies:
                diag = ies[19]
                if kind == "NGResetAcknowledge" and (
                    "procedureCode" in diag or "triggeringMessage" in diag
                ):
                    raise Invalid("response-diagnostic-header")
                if any(
                    v["iECriticality"] == "ignore"
                    for v in diag.get("iEsCriticalityDiagnostics", [])
                ):
                    raise Invalid("non-applicable-diagnostic-criticality")
            if 26 in ies:
                raise Invalid("outside-sdk-admitted-field-subset")

        def record(
            name, value, admitted=True, mode="valid", signalling="non-ue", **extra
        ):
            value = copy.deepcopy(value)
            kind = value[1]["value"][0]
            order = {row["id"]: i for i, row in enumerate(ref.rows(kind))}
            entries(value).sort(key=lambda v: order.get(v["id"], 65536))
            wire, plain = encode(ref.pdu, value)
            error = None
            try:
                ref.pdu.from_aper_ws(wire)
                assert ref.pdu.to_aper_ws() == wire
                decoded = ref.pdu.get_val()[1]["value"][1]
                ref.validate_container(kind, decoded, 65536)
                ref.validate_n3iwf(kind, decoded)
                semantic(kind, decoded, signalling)
            except Invalid as exc:
                error = str(exc)
            except Exception:
                error = "reference-framing-or-value"
            if admitted:
                assert error is None, (name, error)
            else:
                assert error is not None, (name, "negative-not-detected")
            canonical = copy.deepcopy(value)
            entries(canonical)[:] = [v for v in entries(canonical) if v["id"] != 65530]
            canonical_wire, _ = encode(ref.pdu, canonical)
            connection_items = []
            for item in entries(value):
                if item["id"] == 111:
                    connection_items = item["value"][1]
                if item["id"] == 88 and item["value"][1][0] == "partOfNG-Interface":
                    connection_items = item["value"][1][1]
            empty_connections = sum(
                "aMF-UE-NGAP-ID" not in item and "rAN-UE-NGAP-ID" not in item
                for item in connection_items
            )
            cases.append(
                dict(
                    name=name,
                    empty_connections=empty_connections,
                    connection_count=len(connection_items),
                    kind=kind,
                    admitted=admitted,
                    mode=mode,
                    signalling=signalling,
                    reference_error=error,
                    plain_encoder=plain,
                    wire_hex=wire.hex(),
                    wire_sha256=hashlib.sha256(wire).hexdigest(),
                    fields=fields(value),
                    canonical_fields=fields(canonical),
                    canonical_wire_hex=canonical_wire.hex(),
                    **extra
                )
            )

        bases = {
            "NGReset": make(
                "NGReset", [(15, causes[0]), (88, ("nG-Interface", "reset-all"))]
            ),
            "NGResetAcknowledge": make("NGResetAcknowledge", []),
            "ErrorIndication": make("ErrorIndication", [(15, causes[0])]),
        }
        for kind, original in bases.items():
            record("base-" + kind, original)
            if kind != "ErrorIndication":
                record("ue-scope-" + kind, original, False, "signalling", "ue")
            for row in ref.rows(kind):
                if row["presence"] == "mandatory":
                    value = copy.deepcopy(original)
                    entries(value)[:] = [
                        v for v in entries(value) if v["id"] != row["id"]
                    ]
                    record(
                        "missing-" + kind + "-" + str(row["id"]),
                        value,
                        False,
                        "missing",
                    )
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
                    "unknown-" + kind + "-" + criticality,
                    value,
                    criticality != "reject",
                    "unknown",
                    criticality=criticality,
                )
            for item in entries(original):
                value = copy.deepcopy(original)
                next(v for v in entries(value) if v["id"] == item["id"])[
                    "criticality"
                ] = "notify"
                record(
                    "criticality-" + kind + "-" + str(item["id"]),
                    value,
                    False,
                    "criticality",
                )
            value = copy.deepcopy(original)
            ident = 19 if kind == "NGResetAcknowledge" else 15
            if kind == "NGResetAcknowledge":
                replace(value, 19, dict(procedureCriticality="notify"))
            first = field(
                kind,
                ident,
                (
                    dict(procedureCriticality="reject")
                    if ident == 19
                    else ("transport", "unspecified")
                ),
            )
            entries(value).insert(0, first)
            record("duplicate-" + kind, value, False, "duplicate")
        for kind in ("NGReset", "ErrorIndication"):
            for index, cause in enumerate(causes):
                value = copy.deepcopy(bases[kind])
                replace(value, 15, cause)
                record("cause-" + kind + "-" + str(index), value)
        for count in (1, 2, 256, 16384, 16385, 65536):
            cycle = [
                {},
                dict(aMF_UE_NGAP_ID=7),
                dict(rAN_UE_NGAP_ID=257),
                dict(aMF_UE_NGAP_ID=0x8123456789, rAN_UE_NGAP_ID=0x87654321),
            ]
            model = [
                {key.replace("_", "-"): value for key, value in cycle[i % 4].items()}
                for i in range(count)
            ]
            for kind, ident, content in [
                ("NGReset", 88, ("partOfNG-Interface", model)),
                ("NGResetAcknowledge", 111, model),
            ]:
                value = copy.deepcopy(bases[kind])
                replace(value, ident, content)
                record("connections-" + kind + "-" + str(count), value)
        for kind in ("NGResetAcknowledge", "ErrorIndication"):
            for diagnostic in (
                {},
                dict(procedureCriticality="ignore"),
                dict(
                    iEsCriticalityDiagnostics=[
                        dict(
                            iECriticality="notify",
                            **{"iE-ID": 65535},
                            typeOfError="missing"
                        )
                    ]
                ),
            ):
                value = copy.deepcopy(bases[kind])
                replace(value, 19, diagnostic)
                record("diagnostics-" + kind + "-" + str(len(cases)), value)
            for header in (
                dict(procedureCode=20),
                dict(triggeringMessage="successful-outcome"),
            ):
                value = copy.deepcopy(bases[kind])
                replace(value, 19, header)
                record(
                    "diagnostic-header-" + kind + "-" + str(len(cases)),
                    value,
                    kind == "ErrorIndication",
                    "header",
                )
            value = copy.deepcopy(bases[kind])
            replace(
                value,
                19,
                dict(
                    iEsCriticalityDiagnostics=[
                        dict(
                            iECriticality="ignore",
                            **{"iE-ID": 15},
                            typeOfError="missing"
                        )
                    ]
                ),
            )
            record("diagnostic-ignore-" + kind, value, False, "diagnostic")
            value = copy.deepcopy(bases[kind])
            entries(value).append(
                dict(id=19, criticality="ignore", value=("_unk_004", b"\x01"))
            )
            record("diagnostic-padding-" + kind, value, False, "padding")
        for signalling in ("non-ue", "ue"):
            for mask in range(4):
                value = copy.deepcopy(bases["ErrorIndication"])
                if mask & 1:
                    replace(value, 10, 0x8123456789)
                if mask & 2:
                    replace(value, 85, 0x87654321)
                record(
                    "error-identifiers-" + signalling + "-" + str(mask),
                    value,
                    signalling == "non-ue" or mask == 3,
                    "signalling",
                    signalling,
                )
        for mask in range(4):
            values = []
            if mask & 1:
                values.append((15, causes[0]))
            if mask & 2:
                values.append((19, {}))
            record(
                "error-basis-" + str(mask),
                make("ErrorIndication", values),
                mask != 0,
                "basis",
            )
        value = copy.deepcopy(bases["ErrorIndication"])
        replace(
            value,
            26,
            dict(
                aMFSetID=(0, 10),
                aMFPointer=(0, 6),
                **{"fiveG-TMSI": b"\x01\x02\x03\x04"}
            ),
        )
        record("unsupported-fiveg-stmsi", value, False, "unsupported")
        profiles = {
            kind: [
                dict(id=v["id"], criticality=v["criticality"], presence=v["presence"])
                for v in ref.rows(kind)
            ]
            for kind in KINDS
        }
        procedures = {kind: list(ref.procedures[kind]) for kind in KINDS}
    doc = dict(
        source_sha256=SPEC_SHA256,
        reference_tools=VERSIONS,
        reference_decoder="from_aper_ws; to_aper_ws primary; plain encoder checked where its fragmented-list path succeeds",
        profiles=profiles,
        procedures=procedures,
        cases=cases,
    )
    args.output.write_text(json.dumps(doc, indent=2) + "\n")
    print(
        "Independent messages:",
        len(cases),
        "admitted:",
        sum(v["admitted"] for v in cases),
        "negative:",
        sum(not v["admitted"] for v in cases),
    )


if __name__ == "__main__":
    main()
