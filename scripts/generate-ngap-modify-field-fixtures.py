#!/usr/bin/env python3
"""Independent Release 18 root fields for PDU Session Resource Modify."""

import argparse
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import tempfile
from n3iwf_ngap_reference import SPEC_SHA256, VERSIONS, compile_reference

REQUEST = "QosFlowAddOrModifyRequestList"
RESPONSE = "QosFlowAddOrModifyResponseList"
CAUSES = "QosFlowListWithCause"
TUNNELS = "UL_NGU_UP_TNLModifyList"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cases, causes, labels = [], [], {}
    with tempfile.TemporaryDirectory(prefix="ngap-modify-fields-") as tmp:
        ref = compile_reference(args.spec.read_bytes(), Path(tmp))
        for group, typ in (
            ("radioNetwork", "CauseRadioNetwork"),
            ("transport", "CauseTransport"),
            ("nas", "CauseNas"),
            ("protocol", "CauseProtocol"),
            ("misc", "CauseMisc"),
        ):
            enum = getattr(ref.schema.NGAP_IEs, typ)
            for label in enum._root:
                code = enum._cont[label]
                labels[group, code] = label
                causes.append(dict(group=group, code=code))

        def parameters(model):
            return dict(
                qosCharacteristics=(
                    "nonDynamic5QI",
                    dict(fiveQI=model.get("five_qi", 9)),
                ),
                allocationAndRetentionPriority=dict(
                    priorityLevelARP=model["priority"],
                    pre_emptionCapability=(
                        "may-trigger-pre-emption"
                        if model["may_preempt"]
                        else "shall-not-trigger-pre-emption"
                    ),
                    pre_emptionVulnerability=(
                        "pre-emptable" if model["preemptable"] else "not-pre-emptable"
                    ),
                ),
            )

        def transport(model):
            address = ipaddress.ip_address(model["address"])
            return "gTPTunnel", {
                "transportLayerAddress": (int(address), address.max_prefixlen),
                "gTP-TEID": model["teid"].to_bytes(4, "big"),
            }

        def value_for(kind, model):
            result = []
            for item in model:
                if kind == TUNNELS:
                    result.append(
                        {
                            "uL-NGU-UP-TNLInformation": transport(item["uplink"]),
                            "dL-NGU-UP-TNLInformation": transport(item["downlink"]),
                        }
                    )
                    continue
                entry = dict(qosFlowIdentifier=item["qfi"])
                if kind == REQUEST:
                    if item["parameters"] is not None:
                        qos = parameters(item["parameters"])
                        arp = qos["allocationAndRetentionPriority"]
                        arp["pre-emptionCapability"] = arp.pop("pre_emptionCapability")
                        arp["pre-emptionVulnerability"] = arp.pop(
                            "pre_emptionVulnerability"
                        )
                        entry["qosFlowLevelQosParameters"] = qos
                    if "e_rab" in item:
                        entry["e-RAB-ID"] = item["e_rab"]
                elif kind == CAUSES:
                    cause = item["cause"]
                    entry["cause"] = (
                        cause["group"],
                        labels[cause["group"], cause["code"]],
                    )
                result.append(entry)
            return result

        def emit(kind, name, model, admitted=True, mode="valid"):
            target = getattr(ref.schema.NGAP_IEs, kind)
            value = value_for(kind, model)
            target.set_val(copy.deepcopy(value))
            wire = target.to_aper_ws()
            assert target.to_aper() == wire, (name, "plain encoder")
            target.from_aper_ws(wire)
            assert target.get_val() == value, (name, "decoded values")
            assert target.to_aper_ws() == wire, (name, "structured encoder")
            cases.append(
                dict(
                    name=name,
                    type=kind,
                    model=model,
                    admitted=admitted,
                    mode=mode,
                    wire_hex=wire.hex(),
                    wire_sha256=hashlib.sha256(wire).hexdigest(),
                )
            )

        def params(index):
            return dict(
                priority=index % 15 + 1,
                may_preempt=bool(index & 1),
                preemptable=bool(index & 2),
            )

        for count in range(1, 65):
            for pattern in ("identifiers", "parameters", "mixed"):
                emit(
                    REQUEST,
                    f"request-{pattern}-{count}",
                    [
                        dict(
                            qfi=i,
                            parameters=(
                                params(i)
                                if pattern == "parameters"
                                or pattern == "mixed"
                                and i % 2
                                else None
                            ),
                        )
                        for i in range(count)
                    ],
                )
            emit(
                RESPONSE, f"response-count-{count}", [dict(qfi=i) for i in range(count)]
            )
            emit(
                CAUSES,
                f"cause-count-{count}",
                [dict(qfi=i, cause=causes[i]) for i in range(count)],
            )
        for qfi in range(64):
            for present in [False, True]:
                emit(
                    REQUEST,
                    f"request-qfi-{qfi}-{present}",
                    [dict(qfi=qfi, parameters=params(qfi) if present else None)],
                )
            emit(RESPONSE, f"response-qfi-{qfi}", [dict(qfi=qfi)])
        for priority in range(1, 16):
            for flags in range(4):
                p = params(flags)
                p["priority"] = priority
                emit(REQUEST, f"arp-{priority}-{flags}", [dict(qfi=29, parameters=p)])
        for index, cause in enumerate(causes):
            emit(CAUSES, f"cause-root-{index}", [dict(qfi=23, cause=cause)])
        widest = dict(group="radioNetwork", code=0)
        emit(
            CAUSES,
            "cause-maximum-width",
            [dict(qfi=i, cause=widest) for i in range(64)],
        )

        for count in range(1, 5):
            for pattern in range(4):
                model = []
                for i in range(count):
                    model.append(
                        dict(
                            uplink=dict(
                                address=(
                                    f"2001:db8::{i + 1}"
                                    if pattern & 1
                                    else f"192.0.2.{i + 1}"
                                ),
                                teid=(i * 0x1020304 + 1),
                            ),
                            downlink=dict(
                                address=(
                                    f"2001:db8:1::{i + 1}"
                                    if pattern & 2
                                    else f"198.51.100.{i + 1}"
                                ),
                                teid=(i * 0x1020304 + 2),
                            ),
                        )
                    )
                emit(TUNNELS, f"tunnels-{count}-{pattern}", model)
        for address in (
            "0.0.0.0",
            "255.255.255.255",
            "::",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ):
            for teid in (0, 1, 255, 256, 65535, 65536, 0xFFFFFFFF):
                endpoint = dict(address=address, teid=teid)
                emit(
                    TUNNELS,
                    f"endpoint-{len(cases)}",
                    [dict(uplink=endpoint, downlink=endpoint)],
                )
        pair = dict(
            uplink=dict(address="192.0.2.1", teid=1),
            downlink=dict(address="198.51.100.2", teid=2),
        )
        emit(TUNNELS, "repeated-tunnel-pairs", [pair, pair])
        emit(
            REQUEST,
            "duplicate-request",
            [dict(qfi=7, parameters=None), dict(qfi=7, parameters=params(1))],
            False,
            "duplicate",
        )
        emit(
            RESPONSE,
            "duplicate-response",
            [dict(qfi=7), dict(qfi=7)],
            False,
            "duplicate",
        )
        emit(
            CAUSES,
            "duplicate-causes",
            [dict(qfi=7, cause=causes[0]), dict(qfi=7, cause=causes[1])],
            False,
            "duplicate",
        )
        p = params(1)
        p["five_qi"] = 8
        emit(
            REQUEST,
            "unsupported-five-qi",
            [dict(qfi=7, parameters=p)],
            False,
            "unsupported",
        )
        emit(
            REQUEST,
            "unsupported-e-rab",
            [dict(qfi=7, parameters=None, e_rab=3)],
            False,
            "unsupported",
        )

    result = dict(source_sha256=SPEC_SHA256, reference_tools=VERSIONS, cases=cases)
    rendered = json.dumps(result, indent=2)
    for case in cases:
        expanded = json.dumps(case["model"], indent=2).replace("\n", "\n      ")
        rendered = rendered.replace(
            '"model": ' + expanded, '"model": ' + json.dumps(case["model"]), 1
        )
    assert json.loads(rendered) == result
    args.output.write_text(rendered + "\n")
    print(f"Wrote {len(cases)} fields; {sum(v['admitted'] for v in cases)} admitted")


if __name__ == "__main__":
    main()
