#!/usr/bin/env python3
"""Independent Setup unsuccessful transfers and all three enclosing outcomes.

Reuse the independently authored diagnostic models, never SDK wire output.
Compile TS 38.413 V18.10.0 and independently encode the Setup ASN.1 type,
then prove its common root layout against the existing Modify reference.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import tempfile

from n3iwf_ngap_reference import SPEC_SHA256, VERSIONS, compile_reference


def semantic(value):
    if "iE-Extensions" in value:
        return "unsupported-transfer-extension"
    diagnostics = value.get("criticalityDiagnostics", {})
    if "procedureCode" in diagnostics or "triggeringMessage" in diagnostics:
        return "response-diagnostic-header"
    if any(item["iECriticality"] == "ignore"
           for item in diagnostics.get("iEsCriticalityDiagnostics", [])):
        return "inapplicable-diagnostic-criticality"
    return None


def record(wire):
    return dict(wire_hex=wire.hex(), wire_sha256=hashlib.sha256(wire).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = root / "crates/opc-proto-ngap/tests/fixtures/n3iwf-modify-results.json"
    rows = json.loads(source.read_text())["cases"]
    cases, messages = [], []
    with tempfile.TemporaryDirectory(prefix="ngap-setup-failure-") as temporary:
        ref = compile_reference(args.spec.read_bytes(), Path(temporary))
        modify = ref.schema.NGAP_IEs.PDUSessionResourceModifyUnsuccessfulTransfer
        setup = ref.schema.NGAP_IEs.PDUSessionResourceSetupUnsuccessfulTransfer
        for row in rows:
            if row["type"] != "PDUSessionResourceModifyUnsuccessfulTransfer":
                continue
            modify.from_aper_ws(bytes.fromhex(row["wire_hex"]))
            value = copy.deepcopy(modify.get_val())
            setup.set_val(copy.deepcopy(value))
            wire = setup.to_aper_ws()
            assert setup.to_aper() == wire
            setup.from_aper_ws(wire)
            assert setup.get_val() == value and setup.to_aper_ws() == wire
            assert wire.hex() == row["wire_hex"], row["name"]
            error = semantic(value)
            assert (error is None) == row["admitted"]
            cases.append(dict(name=row["name"], model=row["model"],
                              admitted=error is None, reference_error=error, **record(wire)))
            name = row["name"]
            selected = (not row["admitted"] or "-0-" in name or name in {
                "diagnostic-count-1", "diagnostic-count-2", "diagnostic-count-127",
                "diagnostic-count-128", "diagnostic-count-255", "diagnostic-count-256"})
            if not selected:
                continue
            for kind, code, outcome, ident in [
                ("InitialContextSetupResponse", 14, "successfulOutcome", 55),
                ("InitialContextSetupFailure", 14, "unsuccessfulOutcome", 132),
                ("PDUSessionResourceSetupResponse", 29, "successfulOutcome", 58),
            ]:
                rules = {rule["id"]: rule for rule in ref.rows(kind)}

                def field(ident, payload):
                    rule = rules[ident]
                    return dict(id=ident, criticality=rule["criticality"],
                                value=(rule["Value"]._typeref.called[1], payload))

                failed = [{"pDUSessionID": 255,
                           "pDUSessionResourceSetupUnsuccessfulTransfer":
                               ("PDUSessionResourceSetupUnsuccessfulTransfer", value)}]
                fields = [field(10, 1), field(85, 2), field(ident, failed)]
                if outcome == "unsuccessfulOutcome":
                    fields.append(field(15, ("radioNetwork", "unspecified")))
                order = {ident: i for i, ident in enumerate(rules)}
                fields.sort(key=lambda item: order[item["id"]])
                pdu = (outcome, dict(procedureCode=code, criticality="reject",
                                     value=(kind, dict(protocolIEs=fields))))
                wire = ref.encode(pdu)
                ref.pdu.set_val(copy.deepcopy(pdu))
                assert ref.pdu.to_aper_ws() == wire
                ref.pdu.from_aper_ws(wire)
                assert ref.pdu.get_val() == pdu and ref.pdu.to_aper_ws() == wire
                # Check outer mandatory/criticality bindings independently;
                # the generic older classifier intentionally excludes diagnostics.
                assert all(rule["id"] in {f["id"] for f in fields}
                           for rule in rules.values() if rule["presence"] == "mandatory")
                messages.append(dict(kind=kind, transfer=name, admitted=error is None,
                                     **record(wire)))
    result = dict(source_sha256=SPEC_SHA256, reference_tools=VERSIONS,
                  diagnostic_models_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                  clauses=["9.3.1.3", "9.3.4.16", "9.2.2.2", "9.2.2.3", "9.2.1.2"],
                  cases=cases, messages=messages)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(dict(transfers=len(cases), admitted=sum(v["admitted"] for v in cases),
                          messages=len(messages), sha256=hashlib.sha256(args.output.read_bytes()).hexdigest())))


if __name__ == "__main__":
    main()
