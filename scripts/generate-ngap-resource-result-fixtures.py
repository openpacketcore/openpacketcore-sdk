#!/usr/bin/env python3
"""Independent Release 18 setup-response and unsuccessful transfer vectors."""

import argparse
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import tempfile

from n3iwf_ngap_reference import SPEC_SHA256, VERSIONS, compile_reference


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    cases = []
    with tempfile.TemporaryDirectory(prefix="ngap-result-reference-") as temporary:
        ref = compile_reference(args.spec.read_bytes(), Path(temporary))
        causes = []
        labels = {}
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

        def cause(model):
            return (model["class"], labels[model["class"], model["code"]])

        def response(model):
            address = ipaddress.ip_address(model["downlink"]["address"])
            result = {
                "dLQosFlowPerTNLInformation": {
                    "uPTransportLayerInformation": (
                        "gTPTunnel",
                        {
                            "transportLayerAddress": (
                                int(address),
                                address.max_prefixlen,
                            ),
                            "gTP-TEID": model["downlink"]["teid"].to_bytes(4, "big"),
                        },
                    ),
                    "associatedQosFlowList": [
                        {"qosFlowIdentifier": qfi} for qfi in model["accepted"]
                    ],
                }
            }
            if model["failed"]:
                result["qosFlowFailedToSetupList"] = [
                    {"qosFlowIdentifier": item["qfi"], "cause": cause(item["cause"])}
                    for item in model["failed"]
                ]
            return result

        def record(name, kind, value, model, admitted=True):
            target = getattr(ref.schema.NGAP_IEs, kind)
            target.set_val(copy.deepcopy(value))
            wire = target.to_aper()
            target.from_aper(wire)
            assert target.get_val() == value
            assert target.to_aper() == wire
            cases.append(
                {
                    "name": name,
                    "type": kind,
                    "admitted": admitted,
                    "model": model,
                    "wire_hex": wire.hex(),
                    "wire_sha256": hashlib.sha256(wire).hexdigest(),
                }
            )

        failure_kind = "PDUSessionResourceSetupUnsuccessfulTransfer"
        for item in causes:
            record(
                f"failure-{item['class']}-{item['code']}",
                failure_kind,
                {"cause": cause(item)},
                item,
            )
        failure = {"cause": cause(causes[0])}
        failure["criticalityDiagnostics"] = {}
        record("unsupported-diagnostics", failure_kind, failure, None, False)

        response_kind = "PDUSessionResourceSetupResponseTransfer"
        base = {
            "downlink": {"address": "198.51.100.17", "teid": 0x11223344},
            "accepted": [0],
            "failed": [],
        }
        for address in (
            "0.0.0.0",
            "198.51.100.17",
            "255.255.255.255",
            "::",
            "2001:db8::1234",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ):
            for teid in (0, 1, 0x11223344, 0xFFFFFFFF):
                model = dict(base, downlink={"address": address, "teid": teid})
                record(
                    f"tunnel-{address}-{teid}", response_kind, response(model), model
                )
        for qfi in range(64):
            model = dict(base, accepted=[qfi])
            record(f"qfi-{qfi}", response_kind, response(model), model)
        for count in range(1, 65):
            model = dict(base, accepted=list(range(count)))
            record(f"accepted-count-{count}", response_kind, response(model), model)
        # Every count of failed flows, with the other flows accepted. This
        # covers offsets across byte boundaries and the full 64-QFI domain.
        for count in range(1, 64):
            model = dict(
                base,
                accepted=list(range(64 - count)),
                failed=[
                    {"qfi": qfi, "cause": causes[qfi]} for qfi in range(64 - count, 64)
                ],
            )
            record(f"partial-count-{count}", response_kind, response(model), model)
        # Every root Cause at all four possible offsets after 10-bit items.
        for count in range(1, 5):
            for item in causes:
                model = dict(
                    base,
                    accepted=list(range(count)),
                    failed=[{"qfi": 63, "cause": item}],
                )
                record(
                    f"partial-cause-{count}-{item['class']}-{item['code']}",
                    response_kind,
                    response(model),
                    model,
                )
        for mode, model in (
            ("duplicate-accepted", dict(base, accepted=[1, 1])),
            (
                "duplicate-failed",
                dict(base, failed=[{"qfi": 2, "cause": causes[0]}] * 2),
            ),
            ("conflicting-result", dict(base, failed=[{"qfi": 0, "cause": causes[0]}])),
        ):
            record(mode, response_kind, response(model), model, False)
        for direction in ("ul", "dl"):
            value = response(base)
            value["dLQosFlowPerTNLInformation"]["associatedQosFlowList"][0][
                "qosFlowMappingIndication"
            ] = direction
            record(
                f"unsupported-mapping-{direction}", response_kind, value, None, False
            )
        value = response(base)
        value["securityResult"] = {
            "integrityProtectionResult": "performed",
            "confidentialityProtectionResult": "not-performed",
        }
        record("unsupported-security-result", response_kind, value, None, False)
        value = response(base)
        value["additionalDLQosFlowPerTNLInformation"] = [
            {
                "qosFlowPerTNLInformation": copy.deepcopy(
                    value["dLQosFlowPerTNLInformation"]
                )
            }
        ]
        record("unsupported-additional-tunnel", response_kind, value, None, False)
        for count in (0, 1, 31, 63):
            model = dict(
                base,
                downlink={"address": "2001:db8::1234", "teid": 0xFFFFFFFF},
                accepted=list(range(64 - count)),
                failed=[
                    {"qfi": qfi, "cause": causes[qfi]} for qfi in range(64 - count, 64)
                ],
            )
            record(f"ipv6-partial-{count}", response_kind, response(model), model)
    args.output.write_text(
        json.dumps(
            {"source_sha256": SPEC_SHA256, "reference_tools": VERSIONS, "cases": cases},
            indent=2,
        )
        + "\n"
    )
    print("Wrote", len(cases), "independent resource-result vectors")


if __name__ == "__main__":
    main()
