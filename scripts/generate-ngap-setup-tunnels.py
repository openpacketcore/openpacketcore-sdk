#!/usr/bin/env python3
"""Independent Release 18 setup-result root tunnel and flow mapping vectors."""

import argparse
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import tempfile

from n3iwf_ngap_reference import SPEC_SHA256, VERSIONS, compile_reference


def classify(model):
    """Reported associations are local to each TNL; failures exclude their union.

    TS 38.413 8.2.1 permits an additional bearer for some or all requested flows.
    Request correspondence and allocation are outside this independent codec gate.
    """
    if len(model["additional"]) > 3:
        return False
    accepted = set()
    for tunnel in [model["primary"]] + model["additional"]:
        identifiers = [flow["qfi"] for flow in tunnel["flows"]]
        if not 1 <= len(identifiers) <= 64 or len(set(identifiers)) != len(identifiers):
            return False
        accepted.update(identifiers)
    failed = [flow["qfi"] for flow in model["failed"]]
    return len(set(failed)) == len(failed) and not accepted.intersection(failed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    cases, messages = [], []
    with tempfile.TemporaryDirectory(prefix="ngap-setup-tunnels-") as temporary:
        ref = compile_reference(args.spec.read_bytes(), Path(temporary))
        target = ref.schema.NGAP_IEs.PDUSessionResourceSetupResponseTransfer
        causes = []
        labels = {}
        for group, name in [("radioNetwork", "CauseRadioNetwork"), ("transport", "CauseTransport"), ("nas", "CauseNas"), ("protocol", "CauseProtocol"), ("misc", "CauseMisc")]:
            enum = getattr(ref.schema.NGAP_IEs, name)
            for label in enum._root:
                code = enum._cont[label]
                causes.append(dict(kind=group, code=code))
                labels[group, code] = label

        def tunnel(model):
            address = ipaddress.ip_address(model["address"])
            flows = []
            for flow in model["flows"]:
                value = {"qosFlowIdentifier": flow["qfi"]}
                if flow["mapping"] is not None:
                    value["qosFlowMappingIndication"] = flow["mapping"]
                flows.append(value)
            return {"uPTransportLayerInformation": ("gTPTunnel", {"transportLayerAddress": (int(address), address.max_prefixlen), "gTP-TEID": model["teid"].to_bytes(4, "big")}), "associatedQosFlowList": flows}

        def encode(model):
            value = {"dLQosFlowPerTNLInformation": tunnel(model["primary"])}
            if model["additional"]:
                value["additionalDLQosFlowPerTNLInformation"] = [{"qosFlowPerTNLInformation": tunnel(item)} for item in model["additional"]]
            if model["security"] is not None:
                value["securityResult"] = dict(zip(["integrityProtectionResult", "confidentialityProtectionResult"], model["security"]))
            if model["failed"]:
                value["qosFlowFailedToSetupList"] = [{"qosFlowIdentifier": item["qfi"], "cause": (item["cause"]["kind"], labels[item["cause"]["kind"], item["cause"]["code"]])} for item in model["failed"]]
            target.set_val(copy.deepcopy(value))
            wire = target.to_aper()
            assert target.to_aper_ws() == wire
            target.from_aper(wire)
            assert target.get_val() == value
            target.from_aper_ws(wire)
            assert target.get_val() == value and target.to_aper() == wire
            return wire, value

        def record(name, model):
            wire, _ = encode(model)
            count = len(model["additional"]) + len(model["failed"]) + sum(len(t["flows"]) for t in [model["primary"]] + model["additional"])
            case = dict(name=name, model=copy.deepcopy(model), admitted=classify(model), depth=8 if model["additional"] else 6, count=count, wire_hex=wire.hex(), wire_sha256=hashlib.sha256(wire).hexdigest())
            cases.append(case)
            return case

        def endpoint(count=1, mapping=None, address="198.51.100.17", teid=0x11223344):
            return dict(address=address, teid=teid, flows=[dict(qfi=i, mapping=mapping) for i in range(count)])

        base = dict(primary=endpoint(), additional=[], security=None, failed=[])
        for qfi in range(64):
            for mapping in [None, "ul", "dl"]:
                model = copy.deepcopy(base)
                model["primary"]["flows"] = [dict(qfi=qfi, mapping=mapping)]
                record(f"mapping-{qfi}-{mapping}", model)
        for count in range(1, 65):
            model = copy.deepcopy(base)
            model["primary"] = endpoint(count)
            for index, flow in enumerate(model["primary"]["flows"]):
                flow["mapping"] = [None, "ul", "dl"][index % 3]
            record(f"mixed-mapping-count-{count}", model)
        for additional in range(1, 4):
            for count in range(1, 65):
                for ipv6 in [False, True]:
                    model = copy.deepcopy(base)
                    model["primary"] = endpoint(count, "dl" if ipv6 else "ul")
                    for index in range(additional):
                        model["additional"].append(endpoint(count, [None, "ul", "dl"][index], "2001:db8::1234" if ipv6 else "198.51.100.18", index))
                    record(f"tunnels-{additional}-{count}-{ipv6}", model)
        for count in range(1, 5):
            for index, cause in enumerate(causes):
                model = copy.deepcopy(base)
                model["primary"] = endpoint(count, [None, "ul", "dl"][index % 3])
                model["additional"] = [endpoint(count, "dl"), endpoint(count, "ul", "2001:db8::1")]
                model["failed"] = [dict(qfi=63, cause=cause)]
                model["security"] = [["performed", "performed"], ["performed", "not-performed"], ["not-performed", "performed"], ["not-performed", "not-performed"]][index % 4]
                record(f"partial-{count}-{cause['kind']}-{cause['code']}", model)
        for address in ["0.0.0.0", "255.255.255.255", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]:
            for teid in [0, 1, 0x11223344, 0xFFFFFFFF]:
                model = copy.deepcopy(base)
                model["additional"] = [endpoint(1, "dl", address, teid)]
                record(f"address-{address}-{teid}", model)
        for integrity in ["performed", "not-performed"]:
            for confidentiality in ["performed", "not-performed"]:
                model = copy.deepcopy(base)
                model["primary"] = endpoint(64, "dl", "2001:db8::1", 0xFFFFFFFF)
                model["additional"] = [endpoint(64, "ul", "2001:db8::2", 0xFFFFFFFF) for _ in range(3)]
                model["security"] = [integrity, confidentiality]
                record(f"maximum-{integrity}-{confidentiality}", model)
        for at in range(4):
            model = copy.deepcopy(base)
            model["additional"] = [endpoint() for _ in range(3)]
            [model["primary"], *model["additional"]][at]["flows"].append(dict(qfi=0, mapping="dl"))
            record(f"duplicate-within-{at}", model)
            model = copy.deepcopy(base)
            model["additional"] = [endpoint(1) for _ in range(3)]
            [model["primary"], *model["additional"]][at]["flows"][0]["qfi"] = 63
            model["failed"] = [dict(qfi=63, cause=causes[0])]
            record(f"accepted-failed-{at}", model)
        model = copy.deepcopy(base)
        model["failed"] = [dict(qfi=63, cause=causes[0])] * 2
        record("duplicate-failure", model)

        selected = [cases[1], cases[2], cases[255], cases[383], cases[511], cases[639], cases[-10], *cases[-9:]]
        for case in selected:
            for name, list_id, list_name in [("InitialContextSetupResponse", 72, "PDUSessionResourceSetupListCxtRes"), ("PDUSessionResourceSetupResponse", 75, "PDUSessionResourceSetupListSURes")]:
                choice, procedure, criticality = ref.procedures[name]
                wire, transfer = encode(case["model"])
                assert wire.hex() == case["wire_hex"]
                item = {"pDUSessionID": 255, "pDUSessionResourceSetupResponseTransfer": ("PDUSessionResourceSetupResponseTransfer", transfer)}
                rules = {rule["id"]: rule for rule in ref.rows(name)}

                def field(ident, payload):
                    rule = rules[ident]
                    return dict(id=ident, criticality=rule["criticality"],
                                value=(rule["Value"]._typeref.called[1], payload))

                assert rules[list_id]["Value"]._typeref.called[1] == list_name
                fields = [field(10, 1), field(85, 2), field(list_id, [item])]
                order = {ident: index for index, ident in enumerate(rules)}
                fields.sort(key=lambda entry: order[entry["id"]])
                assert all(rule["id"] in {entry["id"] for entry in fields}
                           for rule in rules.values() if rule["presence"] == "mandatory")
                value = (choice, {"procedureCode": procedure, "criticality": criticality, "value": (name, {"protocolIEs": fields})})
                encoded = ref.encode(value)
                assert ref.pdu.to_aper_ws() == encoded
                ref.pdu.from_aper(encoded)
                assert ref.pdu.get_val() == value
                ref.pdu.from_aper_ws(encoded)
                assert ref.pdu.get_val() == value
                messages.append(dict(name=name, transfer=case["name"], admitted=case["admitted"], wire_hex=encoded.hex(), wire_sha256=hashlib.sha256(encoded).hexdigest()))
    document = dict(source_sha256=SPEC_SHA256, tools=VERSIONS, cases=cases, messages=messages)
    args.output.write_text(json.dumps(document, indent=2) + "\n")
    print(json.dumps(dict(transfers=len(cases), admitted=sum(c["admitted"] for c in cases), messages=len(messages), sha256=hashlib.sha256(args.output.read_bytes()).hexdigest())))


if __name__ == "__main__":
    main()
