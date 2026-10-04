#!/usr/bin/env python3
"""Independent N3IWF request-transfer fields and negative APER containers."""

import argparse
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import tempfile

from n3iwf_ngap_reference import Invalid, SPEC_SHA256, VERSIONS, compile_reference


def flow(model):
    return {
        "qosFlowIdentifier": model["qfi"],
        "qosFlowLevelQosParameters": {
            "qosCharacteristics": ("nonDynamic5QI", {"fiveQI": 9}),
            "allocationAndRetentionPriority": {
                "priorityLevelARP": model["priority"],
                "pre-emptionCapability": (
                    "may-trigger-pre-emption"
                    if model["may_preempt"]
                    else "shall-not-trigger-pre-emption"
                ),
                "pre-emptionVulnerability": (
                    "pre-emptable" if model["preemptable"] else "not-pre-emptable"
                ),
            },
        },
    }


def tunnel(model):
    address = ipaddress.ip_address(model["address"])
    return (
        "gTPTunnel",
        {
            "transportLayerAddress": (int(address), address.max_prefixlen),
            "gTP-TEID": model["teid"].to_bytes(4, "big"),
        },
    )


def rate(model):
    return {
        "pDUSessionAggregateMaximumBitRateDL": model["downlink"],
        "pDUSessionAggregateMaximumBitRateUL": model["uplink"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    fields, transfers = [], []
    with tempfile.TemporaryDirectory(prefix="ngap-resource-reference-") as temporary:
        ref = compile_reference(args.spec.read_bytes(), Path(temporary))

        def encode(kind, value):
            target = getattr(ref.schema.NGAP_IEs, kind)
            target.set_val(copy.deepcopy(value))
            wire = target.to_aper()
            target.from_aper(wire)
            assert target.get_val() == value
            assert target.to_aper() == wire
            return {
                "wire_hex": wire.hex(),
                "wire_sha256": hashlib.sha256(wire).hexdigest(),
            }

        def field(kind, value, model):
            fields.append({"type": kind, "model": model, **encode(kind, value)})

        addresses = [
            "0.0.0.0",
            "198.51.100.17",
            "255.255.255.255",
            "::",
            "2001:db8::1234",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ]
        for address in addresses:
            for teid in (0, 1, 0x11223344, 0xFFFFFFFF):
                model = {"address": address, "teid": teid}
                field("UPTransportLayerInformation", tunnel(model), model)
        for downlink, uplink in (
            (0, 0),
            (1, 2),
            (255, 256),
            (65535, 65536),
            (2**32 - 1, 2**32),
            (4_000_000_000_000, 0),
            (0, 4_000_000_000_000),
            (4_000_000_000_000, 4_000_000_000_000),
        ):
            model = {"downlink": downlink, "uplink": uplink}
            field("PDUSessionAggregateMaximumBitRate", rate(model), model)
        session_types = ["ipv4", "ipv6", "ipv4v6", "ethernet", "unstructured"]
        for kind in session_types:
            field("PDUSessionType", kind, kind)

        def flows(count):
            return [
                {
                    "qfi": i,
                    "priority": i % 15 + 1,
                    "may_preempt": bool(i & 1),
                    "preemptable": bool(i & 2),
                }
                for i in range(count)
            ]

        for qfi in range(64):
            model = [dict(flows(1)[0], qfi=qfi)]
            field("QosFlowSetupRequestList", [flow(item) for item in model], model)
        for priority in range(1, 16):
            for flags in range(4):
                model = [
                    {
                        "qfi": 63,
                        "priority": priority,
                        "may_preempt": bool(flags & 1),
                        "preemptable": bool(flags & 2),
                    }
                ]
                field("QosFlowSetupRequestList", [flow(item) for item in model], model)
        for count in range(1, 65):
            model = flows(count)
            field("QosFlowSetupRequestList", [flow(item) for item in model], model)
        name = "PDUSessionResourceSetupRequestTransfer"
        rows = ref.rows(name)
        metadata = [
            {
                "id": row["id"],
                "criticality": row["criticality"],
                "type": row["Value"]._typeref.called[1],
                "presence": row["presence"],
            }
            for row in rows
        ]
        indexed = {row["id"]: row for row in metadata}

        def body(model):
            values = [
                (130, rate(model["ambr"])),
                (139, tunnel(model["uplink"])),
                (134, model["session_type"]),
                (136, [flow(item) for item in model["flows"]]),
            ]
            return {
                "protocolIEs": [
                    {
                        "id": ident,
                        "criticality": indexed[ident]["criticality"],
                        "value": (indexed[ident]["type"], value),
                    }
                    for ident, value in values
                ]
            }

        def transfer(mode, value, model=None):
            error = None
            try:
                ref.validate_container(name, value, 256)
                ref.validate_session_setup(value)
            except (Invalid, KeyError) as problem:
                error = (
                    str(problem) if isinstance(problem, Invalid) else "missing-field"
                )
            transfers.append(
                {
                    "mode": mode,
                    "model": model,
                    "reference_error": error,
                    "canonical_wire_hex": (
                        encode(name, body(model))["wire_hex"]
                        if model is not None
                        else None
                    ),
                    **encode(name, value),
                }
            )

        base_model = {
            "uplink": {"address": "198.51.100.1", "teid": 0x11223344},
            "ambr": {"downlink": 1_000_000, "uplink": 2_000_000},
            "session_type": "ipv4",
            "flows": flows(1),
        }
        for address in (addresses[1], addresses[4]):
            for kind in session_types:
                for count in (1, 2, 64):
                    model = dict(
                        base_model,
                        uplink={"address": address, "teid": 0x11223344},
                        session_type=kind,
                        flows=flows(count),
                    )
                    transfer("construct", body(model), model)
        base = body(base_model)
        for ident in (130, 139, 134, 136):
            value = copy.deepcopy(base)
            value["protocolIEs"] = [
                ie for ie in value["protocolIEs"] if ie["id"] != ident
            ]
            transfer("missing", value)
        for ident in (130, 139, 134, 136):
            value = copy.deepcopy(base)
            value["protocolIEs"].append(
                copy.deepcopy(
                    next(ie for ie in value["protocolIEs"] if ie["id"] == ident)
                )
            )
            transfer("duplicate", value)
        for criticality in ("reject", "ignore", "notify"):
            value = copy.deepcopy(base)
            value["protocolIEs"].append(
                {
                    "id": 65535,
                    "criticality": criticality,
                    "value": ("_unk_004", b"\xff\x00"),
                }
            )
            transfer("unknown-" + criticality, value, base_model)
        for criticality, length in (("ignore", 16384), ("notify", 65536)):
            value = copy.deepcopy(base)
            value["protocolIEs"].append(
                {
                    "id": 65535,
                    "criticality": criticality,
                    "value": ("_unk_004", bytes([165]) * length),
                }
            )
            transfer("unknown-" + criticality + "-fragment", value, base_model)
        for ident in (130, 139, 134, 136):
            value = copy.deepcopy(base)
            next(ie for ie in value["protocolIEs"] if ie["id"] == ident)[
                "criticality"
            ] = "ignore"
            transfer("wrong-criticality", value)
        value = body(dict(base_model, flows=[*flows(1), *flows(1)]))
        transfer("duplicate-qfi", value)
        value = body(base_model)
        next(ie for ie in value["protocolIEs"] if ie["id"] == 136)["value"][1][0][
            "qosFlowLevelQosParameters"
        ]["qosCharacteristics"][1]["fiveQI"] = 8
        transfer("unsupported-qos", value)
    args.output.write_text(
        json.dumps(
            {
                "source_sha256": SPEC_SHA256,
                "reference_tools": VERSIONS,
                "request_ie_metadata": metadata,
                "fields": fields,
                "transfers": transfers,
            },
            indent=2,
        )
        + "\n"
    )
    print("Wrote", len(fields), "fields and", len(transfers), "transfers")


if __name__ == "__main__":
    main()
