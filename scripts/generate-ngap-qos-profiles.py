#!/usr/bin/env python3
"""Independent Release 18 root QoS descriptors in Setup and Modify lists.

This author uses only the hash-pinned ETSI schema and unmodified Pycrate
encoders. It neither imports SDK code nor reproduces its bit writer.
"""

import argparse
import copy
import hashlib
import itertools
import json
from pathlib import Path
import tempfile

from n3iwf_ngap_reference import SPEC_SHA256, VERSIONS, compile_reference


def parameters(model):
    descriptor = model["descriptor"]
    if descriptor["kind"] == "non_dynamic":
        value = {"fiveQI": descriptor["five_qi"]}
        kind = "nonDynamic5QI"
    else:
        value = {
            "priorityLevelQos": descriptor["priority"],
            "packetDelayBudget": descriptor["delay"],
            "packetErrorRate": {
                "pERScalar": descriptor["scalar"],
                "pERExponent": descriptor["exponent"],
            },
        }
        kind = "dynamic5QI"
        if "five_qi" in descriptor:
            value["fiveQI"] = descriptor["five_qi"]
        if "delay_critical" in descriptor:
            value["delayCritical"] = (
                "delay-critical" if descriptor["delay_critical"] else "non-delay-critical"
            )
    for source, target in (
        ("priority", "priorityLevelQos"),
        ("window", "averagingWindow"),
        ("burst", "maximumDataBurstVolume"),
    ):
        if source in descriptor:
            value[target] = descriptor[source]
    arp = model["arp"]
    result = {
        "qosCharacteristics": (kind, value),
        "allocationAndRetentionPriority": {
            "priorityLevelARP": arp["priority"],
            "pre-emptionCapability": (
                "may-trigger-pre-emption" if arp["may_preempt"] else "shall-not-trigger-pre-emption"
            ),
            "pre-emptionVulnerability": (
                "pre-emptable" if arp["preemptable"] else "not-pre-emptable"
            ),
        },
    }
    if "gbr" in model:
        gbr = model["gbr"]
        value = {target: gbr[source] for source, target in (
            ("max_dl", "maximumFlowBitRateDL"), ("max_ul", "maximumFlowBitRateUL"),
            ("guaranteed_dl", "guaranteedFlowBitRateDL"),
            ("guaranteed_ul", "guaranteedFlowBitRateUL"),
        )}
        for source, target in (("loss_dl", "maximumPacketLossRateDL"), ("loss_ul", "maximumPacketLossRateUL")):
            if source in gbr:
                value[target] = gbr[source]
        if gbr.get("notification", False):
            value["notificationControl"] = "notification-requested"
        result["gBR-QosInformation"] = value
    if model.get("reflective", False):
        result["reflectiveQosAttribute"] = "subject-to"
    if model.get("additional", False):
        result["additionalQosFlowInformation"] = "more-likely"
    return result


def item(model):
    result = {"qosFlowIdentifier": model["qfi"]}
    if "parameters" in model:
        result["qosFlowLevelQosParameters"] = parameters(model["parameters"])
    if "erab" in model:
        result["e-RAB-ID"] = model["erab"]
    return result


def condition(model, gbr_type):
    """Clause conditions, independent of ASN.1 encode/decode and SDK code."""
    if gbr_type and "gbr" not in model:
        return "missing-gbr"
    d = model["descriptor"]
    if d["kind"] == "dynamic":
        if "gbr" in model:
            if "delay_critical" not in d:
                return "missing-delay-critical"
            if "window" not in d:
                return "missing-window"
        if d.get("delay_critical") and "burst" not in d:
            return "missing-burst"
    return "admitted"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    rows = []
    arp = {"priority": 8, "may_preempt": True, "preemptable": False}
    base = {"descriptor": {"kind": "non_dynamic", "five_qi": 9}, "arp": arp}
    profiles = []

    def add(name, descriptor, **optional):
        profiles.append((name, {"descriptor": descriptor, "arp": arp, **optional}))

    for five_qi in range(256):
        add(f"non-dynamic-{five_qi}", {"kind": "non_dynamic", "five_qi": five_qi})
    for flags in range(8):
        for boundary in (False, True):
            descriptor = dict(base["descriptor"])
            for bit, name, low, high in ((1, "priority", 1, 127), (2, "window", 0, 4095), (4, "burst", 0, 4095)):
                if flags & bit:
                    descriptor[name] = high if boundary else low
            add(f"non-dynamic-optionals-{flags}-{int(boundary)}", descriptor)
    for flags in range(16):
        for boundary in (False, True):
            descriptor = {"kind": "dynamic", "priority": 127 if boundary else 1,
                          "delay": 1023 if boundary else 0, "scalar": 9 if boundary else 0,
                          "exponent": 0 if boundary else 9}
            for bit, name, low, high in ((1, "five_qi", 0, 255), (2, "delay_critical", False, True),
                                       (4, "window", 0, 4095), (8, "burst", 0, 4095)):
                if flags & bit:
                    descriptor[name] = high if boundary else low
            add(f"dynamic-optionals-{flags}-{int(boundary)}", descriptor)
    for scalar, exponent in itertools.product(range(10), repeat=2):
        add(f"packet-error-{scalar}-{exponent}", {"kind": "dynamic", "priority": 1,
             "delay": 1, "scalar": scalar, "exponent": exponent})
    for flags in range(8):
        d = {"kind": "dynamic", "priority": 9, "delay": 50, "scalar": 1, "exponent": 6}
        if flags & 1:
            d["delay_critical"] = True
        if flags & 2:
            d["window"] = 2000
        if flags & 4:
            d["burst"] = 1000
        add(f"dynamic-gbr-conditions-{flags}", d, gbr={"max_dl": 1000, "max_ul": 1000,
            "guaranteed_dl": 1000, "guaranteed_ul": 1000})
    for flags in range(32):
        for rate in (0, 1, 255, 256, 65535, 65536, 2**32-1, 2**32, 4_000_000_000_000):
            gbr = {"max_dl": rate, "max_ul": 4_000_000_000_000,
                   "guaranteed_dl": rate, "guaranteed_ul": 0}
            if flags & 1:
                gbr["notification"] = True
            if flags & 2:
                gbr["loss_dl"] = 0
            if flags & 4:
                gbr["loss_ul"] = 1000
            add(f"gbr-{flags}-{rate}", {"kind": "non_dynamic", "five_qi": 1}, gbr=gbr,
                reflective=bool(flags & 8), additional=bool(flags & 16))
    for dynamic in (False, True):
        descriptor = ({"kind": "dynamic", "priority": 9, "delay": 50, "scalar": 1,
                       "exponent": 6, "five_qi": 2, "delay_critical": True,
                       "window": 2000, "burst": 4095} if dynamic else
                      {"kind": "non_dynamic", "five_qi": 2, "priority": 7,
                       "window": 2000, "burst": 4095})
        add(f"all-optionals-{int(dynamic)}", descriptor, gbr={"max_dl": 50000, "max_ul": 30000,
            "guaranteed_dl": 20000, "guaranteed_ul": 10000, "notification": True,
            "loss_dl": 1000, "loss_ul": 1000}, reflective=True, additional=True)

    with tempfile.TemporaryDirectory(prefix="ngap-qos-reference-") as temporary:
        ref = compile_reference(args.spec.read_bytes(), Path(temporary))

        def encode(name, kind, model, accept=True):
            value = parameters(model) if kind == "QosFlowLevelQosParameters" else [item(v) for v in model]
            obj = getattr(ref.schema.NGAP_IEs, kind)
            obj.set_val(copy.deepcopy(value))
            wire = obj.to_aper()
            assert obj.to_aper_ws() == wire
            obj.from_aper(wire)
            assert obj.get_val() == value and obj.to_aper() == wire
            rows.append({"name": name, "type": kind, "model": copy.deepcopy(model), "accept": accept,
                         "wire_hex": wire.hex(), "wire_sha256": hashlib.sha256(wire).hexdigest()})
            if kind == "QosFlowLevelQosParameters":
                rows[-1]["resource_conditions"] = {"non_gbr": condition(model, False), "gbr": condition(model, True)}

        for index, (name, model) in enumerate(profiles):
            encode(name, "QosFlowLevelQosParameters", model)
            # Different item offsets expose alignment bugs hidden by leaf round trips.
            for count in (1, 2, 3):
                flows = [{"qfi": i, "parameters": model} for i in range(count)]
                if index % 2:
                    flows[-1]["erab"] = index % 16
                encode(f"setup-{name}-{count}", "QosFlowSetupRequestList", flows)
                flows.insert(0, {"qfi": 63})
                encode(f"modify-{name}-{count}", "QosFlowAddOrModifyRequestList", flows)
        for count in range(1, 65):
            flows = [{"qfi": i, "parameters": profiles[i % len(profiles)][1]} for i in range(count)]
            encode(f"count-{count}", "QosFlowSetupRequestList", flows)
            encode(f"count-{count}", "QosFlowAddOrModifyRequestList", flows)
        for erab in range(16):
            encode(f"identifier-erab-{erab}", "QosFlowAddOrModifyRequestList", [{"qfi": 63, "erab": erab}])
        for kind in ("QosFlowSetupRequestList", "QosFlowAddOrModifyRequestList"):
            encode("duplicate-qfi", kind, [{"qfi": 1, "parameters": base}] * 2, False)
    result = {"source_sha256": SPEC_SHA256, "versions": VERSIONS,
              "clauses": ["8.2.1.4", "8.2.3.4", "9.3.1.10", "9.3.1.12", "9.3.1.13", "9.3.1.18", "9.3.1.19", "9.3.1.28", "9.3.4.1", "9.3.4.3"], "cases": rows}
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"cases": len(rows), "sha256": hashlib.sha256(args.output.read_bytes()).hexdigest()}))


if __name__ == "__main__":
    main()
