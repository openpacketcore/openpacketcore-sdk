#!/usr/bin/env python3
"""Independent complete Setup requests with caller-authored QoS classifications.

The caller classifications are synthetic local inputs, not ASN.1 wire fields.
TS 38.413 8.2.1.4 controls the conditional Session AMBR decision; the pinned
Release 18 schema and unmodified Pycrate encoders supply all wire bytes.
"""

import argparse
import copy
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import tempfile

from n3iwf_ngap_reference import SPEC_SHA256, VERSIONS, compile_reference, unpack


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = root / "crates/opc-proto-ngap/tests/fixtures/n3iwf-qos-profiles.json"
    leaves = {row["name"]: row["model"] for row in json.loads(source.read_text())["cases"]
              if row["type"] == "QosFlowLevelQosParameters"}
    helper_spec = importlib.util.spec_from_file_location("qos_reference", Path(__file__).with_name("generate-ngap-qos-profiles.py"))
    helper = importlib.util.module_from_spec(helper_spec)
    helper_spec.loader.exec_module(helper)
    recipes = json.loads((root / "crates/opc-n3iwf-fixtures/oracles/ngap-rel18-messages.json").read_text())
    profiles = [("non-gbr", leaves["non-dynamic-9"], "non_gbr"),
                ("gbr", leaves["gbr-0-256"], "gbr"),
                ("gbr-missing-information", leaves["non-dynamic-1"], "gbr")]
    ignored = copy.deepcopy(leaves["gbr-31-256"])
    ignored["descriptor"]["five_qi"] = 9
    profiles.append(("non-gbr-with-ignored-information", ignored, "non_gbr"))
    profiles += [(f"dynamic-conditions-{i}", leaves[f"dynamic-gbr-conditions-{i}"], "gbr") for i in range(8)]
    profiles += [(f"all-optionals-{i}", leaves[f"all-optionals-{i}"], "gbr") for i in range(2)]
    transfers, messages = [], []
    with tempfile.TemporaryDirectory(prefix="ngap-qos-admission-") as temporary:
        ref = compile_reference(args.spec.read_bytes(), Path(temporary))
        kind = "PDUSessionResourceSetupRequestTransfer"
        rows = {row["id"]: row for row in ref.rows(kind)}
        order = {ident: index for index, ident in enumerate(rows)}

        def field(ident, value):
            row = rows[ident]
            return dict(id=ident, criticality=row["criticality"], value=(row["Value"]._typeref.called[1], value))

        def transfer(flows, ambr):
            fields = [field(139, ("gTPTunnel", dict(transportLayerAddress=(int(ipaddress.ip_address("198.51.100.17")), 32),
                                                    **{"gTP-TEID": bytes.fromhex("11223344")}))),
                      field(134, "ipv4"), field(136, [helper.item(flow) for flow in flows])]
            if ambr:
                fields.append(field(130, dict(pDUSessionAggregateMaximumBitRateDL=1000000,
                                              pDUSessionAggregateMaximumBitRateUL=2000000)))
            fields.sort(key=lambda row: order[row["id"]])
            return dict(protocolIEs=fields)

        def encode(kind, value):
            target = getattr(ref.schema.NGAP_IEs, kind)
            target.set_val(copy.deepcopy(value))
            wire = target.to_aper()
            assert target.to_aper_ws() == wire
            target.from_aper_ws(wire)
            assert target.get_val() == value and target.to_aper_ws() == wire
            return wire

        def record(wire):
            return dict(wire_hex=wire.hex(), wire_sha256=hashlib.sha256(wire).hexdigest())

        def container(kind, body):
            # The older reference's recursive semantic classifier deliberately
            # supports only 5QI 9. Check schema headers here; the conditional
            # classifier below covers this newly authored resource-type matrix.
            rules = {row["id"]: row for row in ref.rows(kind)}
            entries = body["protocolIEs"]
            ids = [entry["id"] for entry in entries]
            assert len(ids) == len(set(ids))
            assert all(row["id"] in ids for row in rules.values() if row["presence"] == "mandatory")
            for entry in entries:
                rule = rules[entry["id"]]
                assert entry["criticality"] == rule["criticality"]
                assert entry["value"][0] == rule["Value"]._typeref.called[1]

        for name, profile, classification in profiles:
            for count in (1, 2, 3, 64):
                for mixed in (False, True):
                    flows = [{"qfi": i, "parameters": copy.deepcopy(profile), "resource_type": classification} for i in range(count)]
                    if mixed:
                        flows[-1] = dict(qfi=count-1, parameters=copy.deepcopy(leaves["non-dynamic-9"]), resource_type="non_gbr")
                    for ambr in (False, True):
                        value = transfer(flows, ambr)
                        wire = encode(kind, value)
                        container(kind, value)
                        admitted = ambr or all(flow["resource_type"] == "gbr" for flow in flows)
                        candidate = dict(name=f"{name}-{count}-{int(mixed)}-{int(ambr)}", flows=flows,
                                         ambr=ambr, admit=admitted,
                                         flow_conditions=[helper.condition(flow["parameters"], flow["resource_type"] == "gbr") for flow in flows],
                                         **record(wire))
                        transfers.append(candidate)
                        if count > 2:
                            continue
                        for message_kind, recipe, ident in [
                            ("InitialContextSetupRequest", "complete-initial-context-setup-request", 71),
                            ("PDUSessionResourceSetupRequest", "complete-pdu-session-resource-setup-request", 74),
                        ]:
                            pdu = copy.deepcopy(unpack(next(row["pdu"] for row in recipes["cases"] if row["name"] == recipe)))
                            entries = pdu[1]["value"][1]["protocolIEs"]
                            sessions = next(e for e in entries if e["id"] == ident)["value"][1]
                            assert len(sessions) == 1
                            sessions[0]["pDUSessionID"] = 1
                            sessions[0]["pDUSessionResourceSetupRequestTransfer"] = (kind, value)
                            second = copy.deepcopy(sessions[0])
                            second["pDUSessionID"] = 255
                            second["pDUSessionResourceSetupRequestTransfer"] = (kind, transfer([
                                dict(qfi=0, parameters=leaves["non-dynamic-9"], resource_type="non_gbr")], True))
                            sessions.append(second)
                            message_order = {row["id"]: i for i, row in enumerate(ref.rows(message_kind))}
                            entries.sort(key=lambda row: message_order[row["id"]])
                            wire = ref.encode(pdu)
                            ref.pdu.set_val(copy.deepcopy(pdu))
                            assert ref.pdu.to_aper_ws() == wire
                            ref.pdu.from_aper_ws(wire)
                            assert ref.pdu.get_val() == pdu and ref.pdu.to_aper_ws() == wire
                            container(message_kind, pdu[1]["value"][1])
                            messages.append(dict(kind=message_kind, transfer=candidate["name"], admit=admitted, **record(wire)))
    result = dict(source_sha256=SPEC_SHA256, versions=VERSIONS,
                  profiles_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                  classifications="caller-authored synthetic resource types; not inferred from GBR information",
                  clauses=["8.2.1.4", "8.3.1", "9.3.1.18", "9.3.4.1"], transfers=transfers, messages=messages)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(dict(transfers=len(transfers), messages=len(messages), sha256=hashlib.sha256(args.output.read_bytes()).hexdigest())))


if __name__ == "__main__":
    main()
