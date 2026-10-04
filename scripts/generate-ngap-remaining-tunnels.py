#!/usr/bin/env python3
"""Independent Release 18 additional UL requests and Modify DL associations.

Compile the pinned publication with unmodified Pycrate codecs. Admission rules
are the root codec subset: IPv4/IPv6, unique QFIs within each association list,
and disjoint successful/failed modifications. Associations describe bearers and
do not independently assert successful modification of every associated flow.
Request correspondence, allocation and abnormal-condition handling are external.
"""

import argparse
import copy
import hashlib
import ipaddress
import itertools
import json
from pathlib import Path
import tempfile

from n3iwf_ngap_reference import SPEC_SHA256, VERSIONS, compile_reference


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    fixtures = Path(__file__).resolve().parents[1] / "crates/opc-proto-ngap/tests/fixtures"
    inputs = {}

    def source(name):
        raw = (fixtures / name).read_bytes()
        inputs[name] = hashlib.sha256(raw).hexdigest()
        value = json.loads(raw)
        assert value["source_sha256"] == SPEC_SHA256
        return value

    setup = source("n3iwf-resource-request.json")["transfers"][0]
    outer_setup = source("n3iwf-resource-setup.json")["cases"]
    outer_modify = source("n3iwf-modify.json")["cases"]
    cases, messages = [], []
    with tempfile.TemporaryDirectory(prefix="ngap-remaining-tunnels-") as temporary:
        ref = compile_reference(args.spec.read_bytes(), Path(temporary))

        def encode(obj, value):
            obj.set_val(copy.deepcopy(value))
            wire = obj.to_aper()
            assert obj.to_aper_ws() == wire
            obj.from_aper(wire)
            assert obj.get_val() == value
            obj.from_aper_ws(wire)
            assert obj.get_val() == value and obj.to_aper() == wire
            return wire

        def transport(model):
            address = ipaddress.ip_address(model["address"])
            return ("gTPTunnel", {"transportLayerAddress": (int(address), address.max_prefixlen), "gTP-TEID": model["teid"].to_bytes(4, "big")})

        def endpoint(address="198.51.100.17", teid=0x11223344):
            return dict(address=address, teid=teid)

        def tunnel(count=1, mapping=None, ipv6=False):
            return dict(**endpoint("2001:db8::1234" if ipv6 else "198.51.100.18"), flows=[dict(qfi=i, mapping=mapping) for i in range(count)])

        def association(model):
            flows = []
            for flow in model["flows"]:
                value = {"qosFlowIdentifier": flow["qfi"]}
                if flow["mapping"] is not None:
                    value["qosFlowMappingIndication"] = flow["mapping"]
                flows.append(value)
            return {"qosFlowPerTNLInformation": {"uPTransportLayerInformation": transport(model), "associatedQosFlowList": flows}}

        causes = []
        labels = {}
        for group in ["radioNetwork", "transport", "nas", "protocol", "misc"]:
            enum = getattr(ref.schema.NGAP_IEs, "Cause" + group[0].upper() + group[1:])
            for label in enum._root:
                code = enum._cont[label]
                causes.append(dict(kind=group, code=code))
                labels[group, code] = label

        def record(name, kind, model, value, depth, count, admitted=True):
            wire = encode(getattr(ref.schema.NGAP_IEs, kind), value)
            case = dict(name=name, kind=kind, model=copy.deepcopy(model), depth=depth, count=count, admitted=admitted, wire_hex=wire.hex(), wire_sha256=hashlib.sha256(wire).hexdigest())
            cases.append(case)
            return case

        request_values = {}
        for short, kind in [("setup", "PDUSessionResourceSetupRequestTransfer"), ("modify", "PDUSessionResourceModifyRequestTransfer")]:
            target = getattr(ref.schema.NGAP_IEs, kind)
            rules = {row["id"]: row for row in ref.rows(kind)}
            order = {ident: index for index, ident in enumerate(rules)}
            assert rules[126]["Value"]._typeref.called[1] == "UPTransportLayerInformationList"
            assert rules[126]["criticality"] == "reject" and rules[126]["presence"] == "optional"
            if short == "setup":
                target.from_aper(bytes.fromhex(setup["canonical_wire_hex"]))
                base = copy.deepcopy(target.get_val())
            else:
                base = {"protocolIEs": []}
            for count in range(1, 4):
                for addresses in itertools.product(["198.51.100.17", "2001:db8::1234"], repeat=count):
                    for teid in [0, 1, 0x11223344, 0xFFFFFFFF]:
                        model = [endpoint(address, teid) for address in addresses]
                        values = [{"nGU-UP-TNLInformation": transport(item)} for item in model]
                        leaf = encode(ref.schema.NGAP_IEs.UPTransportLayerInformationList, values)
                        value = copy.deepcopy(base)
                        rule = rules[126]
                        value["protocolIEs"].append(dict(id=126, criticality=rule["criticality"], value=(rule["Value"]._typeref.called[1], values)))
                        value["protocolIEs"].sort(key=lambda item: order[item["id"]])
                        case = record(f"{short}-{len(cases)}", kind, model, value, 10 if short == "setup" else 9, max(len(value["protocolIEs"]), count))
                        case["leaf_hex"] = leaf.hex()
                        request_values[case["name"]] = value

        response_values = {}

        def response(name, model):
            value = {}
            for key, field in [("downlink", "dL-NGU-UP-TNLInformation"), ("uplink", "uL-NGU-UP-TNLInformation")]:
                if model[key] is not None:
                    value[field] = transport(model[key])
            if model["accepted"]:
                value["qosFlowAddOrModifyResponseList"] = [{"qosFlowIdentifier": qfi} for qfi in model["accepted"]]
            value["additionalDLQosFlowPerTNLInformation"] = [association(item) for item in model["additional"]]
            if model["failed"]:
                value["qosFlowFailedToAddOrModifyList"] = [{"qosFlowIdentifier": item["qfi"], "cause": (item["cause"]["kind"], labels[item["cause"]["kind"], item["cause"]["code"]])} for item in model["failed"]]
            failed = [item["qfi"] for item in model["failed"]]
            valid = len(set(model["accepted"])) == len(model["accepted"]) and len(set(failed)) == len(failed) and not set(failed).intersection(model["accepted"])
            valid &= all(len({f["qfi"] for f in t["flows"]}) == len(t["flows"]) for t in model["additional"])
            count = len(model["accepted"]) + len(failed) + len(model["additional"]) + sum(len(t["flows"]) for t in model["additional"])
            case = record(name, "PDUSessionResourceModifyResponseTransfer", model, value, 8, count, valid)
            response_values[name] = value
            return case

        base = dict(downlink=None, uplink=None, accepted=[], additional=[tunnel()], failed=[])
        for qfi in range(64):
            for mapping in [None, "ul", "dl"]:
                model = copy.deepcopy(base)
                model["additional"][0]["flows"] = [dict(qfi=qfi, mapping=mapping)]
                response(f"mapping-{qfi}-{mapping}", model)
        for count in range(1, 65):
            for additional in range(1, 4):
                model = copy.deepcopy(base)
                model["additional"] = [tunnel(count, [None, "ul", "dl"][i], i % 2 == 0) for i in range(additional)]
                response(f"associations-{additional}-{count}", model)
        for mask in range(16):
            for offset in range(4):
                model = copy.deepcopy(base)
                if mask & 1:
                    model["downlink"] = endpoint("2001:db8::1")
                if mask & 2:
                    model["uplink"] = endpoint()
                if mask & 4:
                    model["accepted"] = list(range(offset + 1))
                if mask & 8:
                    model["failed"] = [dict(qfi=63, cause=causes[offset])]
                model["additional"] = [tunnel(offset + 1, "dl")]
                response(f"presence-{mask}-{offset}", model)
        for index, cause in enumerate(causes):
            model = copy.deepcopy(base)
            model["accepted"] = [0, 1, 2]
            model["additional"] = [tunnel(index % 4 + 1, "ul")]
            model["failed"] = [dict(qfi=63, cause=cause)]
            response(f"cause-{cause['kind']}-{cause['code']}", model)
        model = copy.deepcopy(base)
        model["additional"] = [tunnel(64, "dl", True) for _ in range(3)]
        model["accepted"] = list(range(32))
        model["failed"] = [dict(qfi=qfi, cause=causes[0]) for qfi in range(32, 64)]
        model["downlink"] = endpoint("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 0xFFFFFFFF)
        model["uplink"] = endpoint("::", 0)
        response("maximum-associations-with-partial-modification", model)
        for at in range(3):
            model = copy.deepcopy(base)
            model["additional"] = [tunnel() for _ in range(3)]
            model["additional"][at]["flows"].append(dict(qfi=0, mapping="dl"))
            response(f"duplicate-association-{at}", model)
        for key in ["accepted", "failed", "overlap"]:
            model = copy.deepcopy(base)
            if key != "failed":
                model["accepted"] = [0, 0] if key == "accepted" else [0]
            if key != "accepted":
                model["failed"] = [dict(qfi=0, cause=causes[0])] * (2 if key == "failed" else 1)
            response(f"duplicate-{key}", model)

        def outer(name, list_id, transfer_key, case, value):
            original = next(row for row in outer_setup + outer_modify if row["kind"] == name and row["admitted"])
            ref.pdu.from_aper(bytes.fromhex(original["canonical_wire_hex"]))
            pdu = copy.deepcopy(ref.pdu.get_val())
            fields = pdu[1]["value"][1]["protocolIEs"]
            items = next(field["value"][1] for field in fields if field["id"] == list_id)
            items[:] = items[:1]
            items[0][transfer_key] = (case["kind"], copy.deepcopy(value))
            rules = {rule["id"]: rule for rule in ref.rows(name)}
            order = {ident: index for index, ident in enumerate(rules)}
            fields.sort(key=lambda field: order[field["id"]])
            assert all(field["criticality"] == rules[field["id"]]["criticality"] for field in fields)
            assert all(rule["id"] in {field["id"] for field in fields} for rule in rules.values() if rule["presence"] == "mandatory")
            assert pdu[0] == ref.procedures[name][0] and pdu[1]["criticality"] == ref.procedures[name][2]
            wire = encode(ref.pdu, pdu)
            messages.append(dict(kind=name, transfer=case["name"], admitted=case["admitted"], depth=case["depth"] + 7, wire_hex=wire.hex(), wire_sha256=hashlib.sha256(wire).hexdigest()))

        for case in cases:
            if case["name"] in request_values and (case["name"].endswith("-0") or len(case["model"]) == 3 and case["model"][0]["teid"] == 0xFFFFFFFF):
                if case["name"].startswith("setup"):
                    for name, ident in [("InitialContextSetupRequest", 71), ("PDUSessionResourceSetupRequest", 74)]:
                        outer(name, ident, "pDUSessionResourceSetupRequestTransfer", case, request_values[case["name"]])
                else:
                    outer("PDUSessionResourceModifyRequest", 64, "pDUSessionResourceModifyRequestTransfer", case, request_values[case["name"]])
            elif case["name"] in response_values and (case["name"].startswith(("duplicate-", "maximum-")) or case["name"] in ["mapping-63-dl", "presence-15-3"]):
                outer("PDUSessionResourceModifyResponse", 65, "pDUSessionResourceModifyResponseTransfer", case, response_values[case["name"]])
    document = dict(source_sha256=SPEC_SHA256, tools=VERSIONS, input_sha256=inputs, cases=cases, messages=messages)
    args.output.write_text(json.dumps(document, indent=2) + "\n")
    print(json.dumps(dict(transfers=len(cases), admitted=sum(case["admitted"] for case in cases), messages=len(messages), sha256=hashlib.sha256(args.output.read_bytes()).hexdigest())))


if __name__ == "__main__":
    main()
