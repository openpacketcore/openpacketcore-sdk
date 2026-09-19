#!/usr/bin/env python3
"""Independent Release 18 session-transfer security root qualification.

The pinned ASN.1 and TS 38.413 9.3.1.27 supply the bytes and conditional
integrity-rate obligation. No SDK encoder, decoder or catalog writer is used.
"""
import argparse
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import tempfile

from n3iwf_ngap_reference import Invalid, SPEC_SHA256, VERSIONS, compile_reference, unpack

REQUEST = "PDUSessionResourceSetupRequestTransfer"
RESPONSE = "PDUSessionResourceSetupResponseTransfer"
REQUIREMENTS = ["required", "preferred", "not-needed"]
RATES = [None, "bitrate64kbs", "maximum-UE-rate"]
RESULTS = ["performed", "not-performed"]


def indication(model):
    value = dict(integrityProtectionIndication=REQUIREMENTS[model["integrity"]],
                 confidentialityProtectionIndication=REQUIREMENTS[model["confidentiality"]])
    if model["rate"]:
        value["maximumIntegrityProtectedDataRate-UL"] = RATES[model["rate"]]
    return value


def result(model):
    return dict(integrityProtectionResult=RESULTS[model["integrity"]],
                confidentialityProtectionResult=RESULTS[model["confidentiality"]])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    oracle = json.loads((root / "crates/opc-n3iwf-fixtures/oracles/ngap-rel18-messages.json").read_text())
    fields, requests, responses, messages = [], [], [], []
    with tempfile.TemporaryDirectory(prefix="ngap-resource-security-") as temporary:
        ref = compile_reference(args.spec.read_bytes(), Path(temporary))
        rows = {row["id"]: row for row in ref.rows(REQUEST)}
        order = {row["id"]: index for index, row in enumerate(ref.rows(REQUEST))}
        for ident, kind in [(138, "SecurityIndication"), (129, "NetworkInstance"),
                            (127, "DataForwardingNotPossible")]:
            assert rows[ident]["criticality"] == "reject" and rows[ident]["presence"] == "optional"
            assert rows[ident]["Value"]._typeref.called[1] == kind

        def encode(kind, value):
            target = getattr(ref.schema.NGAP_IEs, kind)
            target.set_val(copy.deepcopy(value))
            wire = target.to_aper()
            assert target.to_aper_ws() == wire
            target.from_aper_ws(wire)
            assert target.get_val() == value and target.to_aper_ws() == wire
            return wire

        def wire_record(wire):
            return dict(wire_hex=wire.hex(), wire_sha256=hashlib.sha256(wire).hexdigest())

        def leaf(kind, model, value, admit=True):
            fields.append(dict(kind=kind, model=model, admit=admit, **wire_record(encode(kind, value))))

        security_models = []
        for integrity in range(3):
            for confidentiality in range(3):
                for rate in range(3):
                    model = dict(integrity=integrity, confidentiality=confidentiality, rate=rate)
                    security_models.append(model)
                    leaf("SecurityIndication", model, indication(model), integrity == 2 or rate != 0)
        result_models = []
        for integrity in range(2):
            for confidentiality in range(2):
                model = dict(integrity=integrity, confidentiality=confidentiality)
                result_models.append(model)
                leaf("SecurityResult", model, result(model))
        for value in range(1, 257):
            leaf("NetworkInstance", value, value)

        def ie(ident, value):
            row = rows[ident]
            return dict(id=ident, criticality=row["criticality"], value=(row["Value"]._typeref.called[1], value))

        # Fixed public documentation endpoint, non-GBR flow and rates, authored
        # directly from the schema. The optional fields never grant resources.
        def request(model):
            value = dict(protocolIEs=[
                ie(130, dict(pDUSessionAggregateMaximumBitRateDL=1000000,
                             pDUSessionAggregateMaximumBitRateUL=2000000)),
                ie(139, ("gTPTunnel", dict(transportLayerAddress=(int(ipaddress.ip_address("198.51.100.17")), 32),
                                         **{"gTP-TEID": bytes.fromhex("11223344")}))),
                ie(134, "ipv4"),
                ie(136, [dict(qosFlowIdentifier=9, qosFlowLevelQosParameters=dict(
                    qosCharacteristics=("nonDynamic5QI", dict(fiveQI=9)),
                    allocationAndRetentionPriority=dict(priorityLevelARP=8,
                        **{"pre-emptionCapability": "shall-not-trigger-pre-emption",
                           "pre-emptionVulnerability": "not-pre-emptable"})))])])
            if "security" in model:
                value["protocolIEs"].append(ie(138, indication(model["security"])))
            if "network" in model:
                value["protocolIEs"].append(ie(129, model["network"]))
            if model.get("forwarding", False):
                value["protocolIEs"].append(ie(127, "data-forwarding-not-possible"))
            value["protocolIEs"].sort(key=lambda entry: order[entry["id"]])
            return value

        def validate_request(value):
            ref.validate_container(REQUEST, value, 256)
            ref.validate_session_setup(value)
            for entry in value["protocolIEs"]:
                if entry["id"] == 129 and not 1 <= entry["value"][1] <= 256:
                    raise Invalid("unsupported-network-instance-extension")
            security = next((entry["value"][1] for entry in value["protocolIEs"] if entry["id"] == 138), None)
            if security is not None and security["integrityProtectionIndication"] != "not-needed":
                if "maximumIntegrityProtectedDataRate-UL" not in security:
                    raise Invalid("missing-conditional-integrity-rate-ul")

        def request_record(name, model, value=None, admit=True, construct=True, **extra):
            value = request(model) if value is None else value
            target = getattr(ref.schema.NGAP_IEs, REQUEST)
            target.set_val(copy.deepcopy(value))
            wire = target.to_aper()
            assert target.to_aper_ws() == wire
            error = None
            try:
                # 9.3.4.1 requires Data Forwarding Not Possible to be ignored
                # outside Handover Request. Check its container criticality
                # and multiplicity, but do not decode the irrelevant value.
                envelope = copy.deepcopy(value)
                for entry in envelope["protocolIEs"]:
                    if entry["id"] == 127:
                        entry["value"] = ("DataForwardingNotPossible", "data-forwarding-not-possible")
                ref.validate_container(REQUEST, envelope, 256)
                selected = copy.deepcopy(value)
                selected["protocolIEs"] = [entry for entry in selected["protocolIEs"] if entry["id"] != 127]
                target.set_val(selected)
                selected_wire = target.to_aper_ws()
                target.from_aper_ws(selected_wire)
                decoded = copy.deepcopy(target.get_val())
                if target.to_aper_ws() != selected_wire:
                    raise Invalid("aper-canonical-or-trailing")
                validate_request(decoded)
            except Invalid as problem:
                error = str(problem)
            except Exception:
                error = "aper-decode"
            assert admit == (error is None), (name, error)
            requests.append(dict(name=name, model=model, admit=admit, construct=construct and admit,
                                 canonical_wire_hex=encode(REQUEST, request(dict(model, forwarding=False))).hex() if admit else None,
                                 receiver_ignored=1 if model.get("forwarding", False) else 0,
                                 reference_error=error, **wire_record(wire), **extra))

        for index, model in enumerate(security_models):
            request_record(f"security-{index}", dict(security=model),
                           admit=model["integrity"] == 2 or model["rate"] != 0)
        for value in range(1, 257):
            request_record(f"network-{value}", dict(network=value))
        request_record("forwarding", dict(forwarding=True))
        for index, model in enumerate(security_models):
            if model["integrity"] != 2 and model["rate"] == 0:
                continue
            for network in (1, 128, 256):
                request_record(f"combined-{index}-{network}", dict(security=model, network=network, forwarding=True))
        combined = dict(security=dict(integrity=0, confidentiality=1, rate=1), network=256, forwarding=True)
        for ident in (138, 129, 127):
            for criticality in ("ignore", "notify"):
                changed = request(combined)
                next(entry for entry in changed["protocolIEs"] if entry["id"] == ident)["criticality"] = criticality
                request_record(f"criticality-{ident}-{criticality}", combined, changed, False)
            last = copy.deepcopy(combined)
            if ident == 138:
                last["security"] = dict(integrity=2, confidentiality=2, rate=0)
            if ident == 129:
                last["network"] = 1
            changed = request(combined)
            changed["protocolIEs"].append(next(entry for entry in request(last)["protocolIEs"] if entry["id"] == ident))
            request_record(f"duplicate-{ident}", combined, changed, False, duplicate=ident, last_model=last)
        changed = request(combined)
        invalid_last = copy.deepcopy(combined)
        invalid_last["security"]["rate"] = 0
        changed["protocolIEs"].append(next(entry for entry in request(invalid_last)["protocolIEs"] if entry["id"] == 138))
        request_record("duplicate-invalid-security", combined, changed, False,
                       duplicate=138, last_model=invalid_last, last_reject=True)
        for criticality in ("ignore", "notify", "reject"):
            changed = request(combined)
            changed["protocolIEs"].append(dict(id=65530, criticality=criticality, value=("_unk_004", b"\xff")))
            request_record(f"unknown-{criticality}", combined, changed, criticality != "reject", False, unknown=criticality)
        changed = request(combined)
        changed["protocolIEs"].reverse()
        request_record("reordered", combined, changed, True, False)
        for ident, kind, value in [(138, "SecurityIndication", indication(combined["security"])),
                                   (129, "NetworkInstance", 256),
                                   (127, "DataForwardingNotPossible", "data-forwarding-not-possible")]:
            raw = encode(kind, value)
            malformed = [(f"truncated-{i}", raw[:i]) for i in range(len(raw))] + [("trailing", raw+b"\0")]
            for offset, mask in [(0, 0x80), (len(raw)-1, 1)]:
                mutated = bytearray(raw)
                mutated[offset] ^= mask
                # For NetworkInstance the final octet is the complete root
                # value and has no padding. Its first-octet low bit is padding.
                if kind == "NetworkInstance" and offset == len(raw)-1:
                    mutated = bytearray(raw); mutated[0] |= 1
                malformed.append((f"framing-{offset}-{mask}", bytes(mutated)))
            for name, raw in malformed:
                changed = request(combined)
                next(entry for entry in changed["protocolIEs"] if entry["id"] == ident)["value"] = ("_unk_004", raw)
                request_record(f"malformed-{ident}-{name}", combined, changed, ident == 127, False)

        causes, labels = [], {}
        for group, kind in [("radioNetwork", "CauseRadioNetwork"), ("transport", "CauseTransport"),
                            ("nas", "CauseNas"), ("protocol", "CauseProtocol"), ("misc", "CauseMisc")]:
            enum = getattr(ref.schema.NGAP_IEs, kind)
            for label in enum._root:
                code = enum._cont[label]
                causes.append(dict(class_=group, code=code))
                labels[group, code] = label

        def response(model):
            value = dict(dLQosFlowPerTNLInformation=dict(
                uPTransportLayerInformation=("gTPTunnel", dict(
                    transportLayerAddress=(int(ipaddress.ip_address(model.get("address", "198.51.100.17"))),
                                           128 if ":" in model.get("address", "") else 32),
                    **{"gTP-TEID": bytes.fromhex("11223344")})),
                associatedQosFlowList=[dict(qosFlowIdentifier=qfi) for qfi in model["accepted"]]),
                securityResult=result(model["security"]))
            if model["failed"]:
                value["qosFlowFailedToSetupList"] = [dict(qosFlowIdentifier=item["qfi"],
                    cause=(item["cause"]["class_"], labels[item["cause"]["class_"], item["cause"]["code"]]))
                    for item in model["failed"]]
            return value

        def response_record(name, model):
            responses.append(dict(name=name, model=model, admit=True, **wire_record(encode(RESPONSE, response(model)))))

        for index, security in enumerate(result_models):
            for count in range(1, 65):
                response_record(f"result-{index}-accepted-{count}", dict(security=security, accepted=list(range(count)), failed=[]))
            for count in range(1, 64):
                response_record(f"result-{index}-partial-{count}", dict(security=security,
                    accepted=list(range(64-count)),
                    failed=[dict(qfi=qfi, cause=causes[qfi]) for qfi in range(64-count, 64)]))
            # Every root cause at all four bit offsets after 10-bit flow items.
            for count in range(1, 5):
                for cause in causes:
                    response_record(f"result-{index}-cause-{count}-{cause['class_']}-{cause['code']}",
                        dict(security=security, accepted=list(range(count)), failed=[dict(qfi=63, cause=cause)]))
            response_record(f"result-{index}-ipv6", dict(security=security, address="2001:db8::17",
                accepted=[0, 1, 2], failed=[dict(qfi=63, cause=causes[-1])]))

        for name, row_id, transfer_kind, candidates in [
            ("complete-initial-context-setup-request", 71, REQUEST, requests[:27] + [requests[27], requests[282], requests[283]]),
            ("complete-pdu-session-resource-setup-request", 74, REQUEST, requests[:27] + [requests[27], requests[282], requests[283]]),
            ("complete-initial-context-setup-response", 72, RESPONSE, [r for r in responses if r["name"].endswith(("accepted-1", "accepted-2", "accepted-3", "accepted-4", "partial-63", "ipv6"))]),
            ("complete-pdu-session-resource-setup-response", 75, RESPONSE, [r for r in responses if r["name"].endswith(("accepted-1", "accepted-2", "accepted-3", "accepted-4", "partial-63", "ipv6"))])]:
            base = unpack(next(row["pdu"] for row in oracle["cases"] if row["name"] == name))
            kind = base[1]["value"][0]
            message_order = {row["id"]: index for index, row in enumerate(ref.rows(kind))}
            for candidate in candidates:
                value = copy.deepcopy(base)
                ies = value[1]["value"][1]["protocolIEs"]
                # Keep one explicitly checked session, without unrelated
                # failed-session lists obscuring the contained transfer.
                ies[:] = [entry for entry in ies if entry["id"] not in (55, 58)]
                item = next(entry for entry in ies if entry["id"] == row_id)["value"][1][0]
                field_name = "pDUSessionResourceSetup" + ("Request" if transfer_kind == REQUEST else "Response") + "Transfer"
                leaf_value = request(candidate["model"]) if transfer_kind == REQUEST else response(candidate["model"])
                item[field_name] = (transfer_kind, leaf_value)
                ies.sort(key=lambda entry: message_order[entry["id"]])
                wire = ref.encode(value)
                ref.pdu.set_val(copy.deepcopy(value))
                assert ref.pdu.to_aper_ws() == wire
                ref.pdu.from_aper_ws(wire)
                assert ref.pdu.get_val() == value and ref.pdu.to_aper_ws() == wire
                ref.validate_container(kind, value[1]["value"][1], 256)
                ref.validate_n3iwf(kind, value[1]["value"][1])
                if transfer_kind == REQUEST:
                    try:
                        validate_request(leaf_value)
                        admit = True
                    except Invalid:
                        admit = False
                    assert admit == candidate["admit"]
                canonical = copy.deepcopy(value)
                if transfer_kind == REQUEST:
                    canonical_item = next(entry for entry in canonical[1]["value"][1]["protocolIEs"] if entry["id"] == row_id)["value"][1][0]
                    canonical_item[field_name] = (REQUEST, request(dict(candidate["model"], forwarding=False)))
                messages.append(dict(name=kind+"-"+candidate["name"], kind=kind,
                    transfer_kind=transfer_kind, model=candidate["model"], admit=candidate["admit"],
                    transfer_wire_hex=candidate.get("canonical_wire_hex", candidate["wire_hex"]),
                    canonical_wire_hex=ref.encode(canonical).hex() if candidate["admit"] else None,
                    **wire_record(wire)))
    payload = dict(source_sha256=SPEC_SHA256, reference_tools=VERSIONS,
                   clauses=["9.3.1.27", "9.3.1.59", "9.3.1.63", "9.3.1.113", "9.3.4.1", "9.3.4.2"],
                   fields=fields, requests=requests, responses=responses, messages=messages)
    args.output.write_text(json.dumps(payload, indent=2)+"\n")
    print("Wrote independent resource-security vectors:", {k: len(payload[k]) for k in ("fields", "requests", "responses", "messages")})


if __name__ == "__main__":
    main()
