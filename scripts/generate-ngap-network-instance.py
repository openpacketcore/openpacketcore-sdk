#!/usr/bin/env python3
"""Independent Release 18 network-instance field and transfer qualification.

The pinned ASN.1 supplies APER bytes and the two transfer IE sets. TS 38.413
8.2.1.2/8.2.3.2 give Common Network Instance precedence. Its unconstrained
octets carry a TS 29.244 8.2.4 identifier; they are not universally DNS/APN.
No SDK codec, generated Rust schema or catalog writer is imported.
"""
import argparse
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import tempfile

from n3iwf_ngap_reference import Invalid, SPEC_SHA256, VERSIONS, compile_reference, unpack

SETUP = "PDUSessionResourceSetupRequestTransfer"
MODIFY = "PDUSessionResourceModifyRequestTransfer"


def octets(model):
    return bytes((model["seed"] + 17 * i) % 256 for i in range(model["length"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    oracle = json.loads((root / "crates/opc-n3iwf-fixtures/oracles/ngap-rel18-messages.json").read_text())
    fields, transfers, messages = [], [], []
    with tempfile.TemporaryDirectory(prefix="ngap-network-instance-") as temporary:
        ref = compile_reference(args.spec.read_bytes(), Path(temporary))
        rows = {kind: {row["id"]: row for row in ref.rows(kind)} for kind in [SETUP, MODIFY]}
        order = {kind: {ident: index for index, ident in enumerate(rows[kind])} for kind in rows}
        for kind in rows:
            for ident, name, criticality in [(129, "NetworkInstance", "reject"),
                                              (166, "CommonNetworkInstance", "ignore")]:
                row = rows[kind][ident]
                assert row["criticality"] == criticality and row["presence"] == "optional"
                assert row["Value"]._typeref.called[1] == name

        def encode(kind, value):
            target = getattr(ref.schema.NGAP_IEs, kind)
            target.set_val(copy.deepcopy(value))
            wire = target.to_aper()
            assert target.to_aper_ws() == wire
            return wire

        def wire_record(wire):
            return dict(wire_hex=wire.hex(), wire_sha256=hashlib.sha256(wire).hexdigest())

        def decode(kind, wire):
            target = getattr(ref.schema.NGAP_IEs, kind)
            target.from_aper_ws(wire)
            value = copy.deepcopy(target.get_val())
            if target.to_aper_ws() != wire:
                raise Invalid("aper-canonical-or-trailing")
            return value

        lengths = [0, 2, 8, 63, 127, 128, 255, 256, 16383, 16384, 16385,
                   32768, 49152, 65536, 65537]
        for model in ([dict(length=1, seed=n) for n in range(256)]
                      + [dict(length=n, seed=49) for n in lengths]):
            wire = encode("CommonNetworkInstance", octets(model))
            assert decode("CommonNetworkInstance", wire) == octets(model)
            fields.append(dict(model=model, **wire_record(wire)))

        def ie(kind, ident, value):
            row = rows[kind][ident]
            return dict(id=ident, criticality=row["criticality"],
                        value=(row["Value"]._typeref.called[1], value))

        def transfer(kind, model):
            entries = []
            if kind == SETUP:
                entries = [
                    ie(kind, 130, dict(pDUSessionAggregateMaximumBitRateDL=1000000,
                                       pDUSessionAggregateMaximumBitRateUL=2000000)),
                    ie(kind, 139, ("gTPTunnel", dict(
                        transportLayerAddress=(int(ipaddress.ip_address("198.51.100.17")), 32),
                        **{"gTP-TEID": bytes.fromhex("11223344")}))),
                    ie(kind, 134, "ipv4"),
                    ie(kind, 136, [dict(qosFlowIdentifier=9, qosFlowLevelQosParameters=dict(
                        qosCharacteristics=("nonDynamic5QI", dict(fiveQI=9)),
                        allocationAndRetentionPriority=dict(priorityLevelARP=8,
                            **{"pre-emptionCapability": "shall-not-trigger-pre-emption",
                               "pre-emptionVulnerability": "not-pre-emptable"})))])]
            if "network" in model:
                entries.append(ie(kind, 129, model["network"]))
            if "common" in model:
                entries.append(ie(kind, 166, octets(model["common"])))
            entries.sort(key=lambda entry: order[kind][entry["id"]])
            return dict(protocolIEs=entries)

        def validate(kind, value):
            ref.validate_container(kind, value, 256)
            for entry in value["protocolIEs"]:
                if entry["id"] == 129 and not 1 <= entry["value"][1] <= 256:
                    raise Invalid("unsupported-network-instance-extension")
            if kind == SETUP:
                ref.validate_session_setup(value)

        def record(kind, name, model, value=None, admit=True, construct=True, **extra):
            value = transfer(kind, model) if value is None else value
            wire = encode(kind, value)
            error = None
            try:
                validate(kind, decode(kind, wire))
            except Invalid as problem:
                error = str(problem)
            except Exception:
                error = "aper-decode"
            assert admit == (error is None), (kind, name, error)
            transfers.append(dict(kind=kind, name=name, model=model, admit=admit,
                construct=construct and admit, reference_error=error,
                preference="common" if "common" in model else "network" if "network" in model else None,
                canonical_wire_hex=encode(kind, transfer(kind, model)).hex() if admit else None,
                **wire_record(wire), **extra))

        for kind in [SETUP, MODIFY]:
            record(kind, "absent", {})
            for value in range(1, 257) if kind == MODIFY else [1, 128, 256]:
                record(kind, f"network-{value}", dict(network=value))
            for length in [0, 1, 8, 127, 128, 256, 16384]:
                model = dict(common=dict(length=length, seed=49))
                record(kind, f"common-{length}", model)
                for value in [1, 256]:
                    record(kind, f"both-{length}-{value}", dict(model, network=value))
            combined = dict(network=256, common=dict(length=8, seed=49))
            changed = transfer(kind, combined)
            changed["protocolIEs"].reverse()
            record(kind, "reordered", combined, changed, construct=False)
            for ident in [129, 166]:
                correct = rows[kind][ident]["criticality"]
                for criticality in ["reject", "ignore", "notify"]:
                    if criticality == correct:
                        continue
                    changed = transfer(kind, combined)
                    next(e for e in changed["protocolIEs"] if e["id"] == ident)["criticality"] = criticality
                    record(kind, f"criticality-{ident}-{criticality}", combined, changed, False)
                last = copy.deepcopy(combined)
                if ident == 129:
                    last["network"] = 1
                else:
                    last["common"] = dict(length=0, seed=0)
                changed = transfer(kind, combined)
                changed["protocolIEs"].append(next(e for e in transfer(kind, last)["protocolIEs"] if e["id"] == ident))
                record(kind, f"duplicate-{ident}", combined, changed, False,
                       duplicate=ident, last_model=last,
                       first_wire_hex=encode(kind, transfer(kind, combined)).hex(),
                       last_wire_hex=encode(kind, transfer(kind, last)).hex())
                raw = encode("NetworkInstance", 256) if ident == 129 else encode("CommonNetworkInstance", octets(combined["common"]))
                malformed = [(f"truncated-{i}", raw[:i]) for i in range(len(raw))]
                malformed.append(("trailing", raw + b"\0"))
                if ident == 129:
                    malformed += [("padding", b"\x01\xff"),
                                  ("extension", encode("NetworkInstance", 257))]
                else:
                    malformed += [("reserved-fragment", b"\xc0"), ("oversize-fragment", b"\xc5"),
                                  ("unterminated-fragment", b"\xc1" + bytes(16384)),
                                  ("nonminimal-length", b"\x80\x08" + octets(combined["common"]))]
                for name, raw in malformed:
                    changed = transfer(kind, combined)
                    next(e for e in changed["protocolIEs"] if e["id"] == ident)["value"] = ("_unk_004", raw)
                    record(kind, f"malformed-{ident}-{name}", combined, changed, False)
                changed = transfer(kind, combined)
                wrong = copy.deepcopy(next(e for e in changed["protocolIEs"] if e["id"] == ident))
                wrong["value"] = ("_unk_004", b"")
                changed["protocolIEs"].append(wrong)
                record(kind, f"duplicate-invalid-{ident}", combined, changed, False,
                       duplicate=ident, last_reject=True,
                       first_wire_hex=encode(kind, transfer(kind, combined)).hex())
            for criticality in ["reject", "ignore", "notify"]:
                changed = transfer(kind, combined)
                changed["protocolIEs"].append(dict(id=65530, criticality=criticality, value=("_unk_004", b"\xff")))
                record(kind, f"unknown-{criticality}", combined, changed, criticality != "reject",
                       False, unknown=criticality)

        # Complete messages use explicit published synthetic recipes. Nested
        # transfer bytes come from this schema, never an SDK round trip.
        for kind, recipe, ident, transfer_kind in [
            ("InitialContextSetupRequest", "complete-initial-context-setup-request", 71, SETUP),
            ("PDUSessionResourceSetupRequest", "complete-pdu-session-resource-setup-request", 74, SETUP),
            ("PDUSessionResourceModifyRequest", None, 64, MODIFY)]:
            if recipe:
                base = unpack(next(row["pdu"] for row in oracle["cases"] if row["name"] == recipe))
            else:
                message_rows = {row["id"]: row for row in ref.rows(kind)}
                def field(i, value):
                    row = message_rows[i]
                    return dict(id=i, criticality=row["criticality"], value=(row["Value"]._typeref.called[1], value))
                choice, code, criticality = ref.procedures[kind]
                base = (choice, dict(procedureCode=code, criticality=criticality,
                    value=(kind, dict(protocolIEs=[field(10, 42), field(85, 24), field(64, [dict(
                        pDUSessionID=1, pDUSessionResourceModifyRequestTransfer=(MODIFY, transfer(MODIFY, {})))])]))))
            for name in ["network-256", "common-0", "common-128", "both-8-256", "both-16384-256"]:
                candidate = next(row for row in transfers if row["kind"] == transfer_kind and row["name"] == name)
                value = copy.deepcopy(base)
                entries = value[1]["value"][1]["protocolIEs"]
                item = next(e for e in entries if e["id"] == ident)["value"][1][0]
                transfer_name = "p" + transfer_kind[1:]
                item[transfer_name] = (transfer_kind, transfer(transfer_kind, candidate["model"]))
                message_order = {row["id"]: index for index, row in enumerate(ref.rows(kind))}
                entries.sort(key=lambda e: message_order[e["id"]])
                wire = ref.encode(value)
                ref.pdu.set_val(copy.deepcopy(value))
                assert ref.pdu.to_aper_ws() == wire
                ref.pdu.from_aper_ws(wire)
                assert ref.pdu.get_val() == value and ref.pdu.to_aper_ws() == wire
                ref.validate_container(kind, value[1]["value"][1], 256)
                ref.validate_n3iwf(kind, value[1]["value"][1])
                validate(transfer_kind, item[transfer_name][1])
                messages.append(dict(kind=kind, name=name, model=candidate["model"],
                    transfer_kind=transfer_kind, transfer_wire_hex=candidate["wire_hex"], **wire_record(wire)))
    payload = dict(source_sha256=SPEC_SHA256, reference_tools=VERSIONS,
        clauses=["8.2.1.2", "8.2.3.2", "9.3.1.113", "9.3.1.120", "9.3.4.1", "9.3.4.3"],
        common_value_semantics="opaque TS 29.244 8.2.4 network identifier; resolution is caller-owned",
        fields=fields, transfers=transfers, messages=messages)
    args.output.write_text(json.dumps(payload, indent=2) + "\n")
    print("Independent network-instance vectors:", {key: len(payload[key]) for key in ["fields", "transfers", "messages"]})


if __name__ == "__main__":
    main()
