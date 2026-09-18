#!/usr/bin/env python3
"""Independent Release 18 N3IWF routing envelopes, not field admission vectors."""

import argparse
import copy
import hashlib
import io
import json
from pathlib import Path
import re
import tempfile
from n3iwf_ngap_reference import SPEC_SHA256, VERSIONS, compile_reference

APPLICABILITY_SHA256 = (
    "c207c2042c6fe60fa98ace159855013b9afb1320ac34a17279530d4b75369953"
)
# TS 29.413 5.2 membership; TS 38.413 clause directions and signalling.
# The final column records the current SDK codec subset, not a standards rule.
RECIPES = """
PDUSessionResourceSetupRequest n3iwf ue 8.2.1 qualified
PDUSessionResourceSetupResponse amf ue 8.2.1 qualified
PDUSessionResourceReleaseCommand n3iwf ue 8.2.2 qualified
PDUSessionResourceReleaseResponse amf ue 8.2.2 qualified
PDUSessionResourceModifyRequest n3iwf ue 8.2.3 qualified
PDUSessionResourceModifyResponse amf ue 8.2.3 qualified
PDUSessionResourceNotify amf ue 8.2.4 qualified
InitialContextSetupRequest n3iwf ue 8.3.1 qualified
InitialContextSetupResponse amf ue 8.3.1 qualified
InitialContextSetupFailure amf ue 8.3.1 qualified
UEContextReleaseRequest amf ue 8.3.2 qualified
UEContextReleaseCommand n3iwf ue 8.3.3 qualified
UEContextReleaseComplete amf ue 8.3.3 qualified
UEContextModificationRequest n3iwf ue 8.3.4 handler
UEContextModificationResponse amf ue 8.3.4 handler
UEContextModificationFailure amf ue 8.3.4 handler
InitialUEMessage amf ue 8.6.1 qualified
DownlinkNASTransport n3iwf ue 8.6.2 qualified
UplinkNASTransport amf ue 8.6.3 qualified
NASNonDeliveryIndication amf ue 8.6.4 qualified
RerouteNASRequest n3iwf ue 8.6.5 handler
NGSetupRequest amf non-ue 8.7.1 qualified
NGSetupResponse n3iwf non-ue 8.7.1 qualified
NGSetupFailure n3iwf non-ue 8.7.1 qualified
RANConfigurationUpdate amf non-ue 8.7.2 handler
RANConfigurationUpdateAcknowledge n3iwf non-ue 8.7.2 handler
RANConfigurationUpdateFailure n3iwf non-ue 8.7.2 handler
AMFConfigurationUpdate n3iwf non-ue 8.7.3 handler
AMFConfigurationUpdateAcknowledge amf non-ue 8.7.3 handler
AMFConfigurationUpdateFailure amf non-ue 8.7.3 handler
NGReset either non-ue 8.7.4 qualified
NGResetAcknowledge either non-ue 8.7.4 qualified
ErrorIndication either either 8.7.5 qualified
AMFStatusIndication n3iwf non-ue 8.7.6 handler
OverloadStart n3iwf non-ue 8.7.7 handler
OverloadStop n3iwf non-ue 8.7.8 handler
UETNLABindingReleaseRequest n3iwf ue 8.13.1 handler
TraceStart n3iwf ue 8.11.1 handler
TraceFailureIndication amf ue 8.11.2 handler
DeactivateTrace n3iwf ue 8.11.3 handler
"""
OUTCOMES = ("initiatingMessage", "successfulOutcome", "unsuccessfulOutcome")
CRITICALITIES = ("reject", "ignore", "notify")


def main():
    from pypdf import PdfReader

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--applicability-spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.applicability_spec.read_bytes()
    assert len(source) < 2 * 1024 * 1024
    assert hashlib.sha256(source).hexdigest() == APPLICABILITY_SHA256
    text = "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(source)).pages)
    normalized = re.sub("[^A-Z0-9]", "", text.upper())
    start = normalized.rindex("52NGAPMESSAGESUSEDFORNON3GPPACCESS")
    end = normalized.index("53EXCEPTIONSFORNGAP", start)
    applicability = normalized[start:end]
    recipes = [row.split() for row in RECIPES.splitlines() if row.strip()]
    assert len(recipes) == 40
    assert all(name.upper() in applicability for name, *_ in recipes)
    with tempfile.TemporaryDirectory(prefix="ngap-applicability-") as tmp:
        ref = compile_reference(args.spec.read_bytes(), Path(tmp))
        metadata = []
        for name, (outcome, code, criticality) in sorted(ref.procedures.items()):
            metadata.append(
                dict(
                    name=name,
                    outcome=outcome,
                    procedure_code=code,
                    criticality=criticality,
                )
            )
        assert len(metadata) == 131
        codes = {v["procedure_code"] for v in metadata}
        assert codes == set(range(81))
        defined = {(v["outcome"], v["procedure_code"]): v for v in metadata}
        applicable = []
        for name, receiver, association, clause, support in recipes:
            row = next(v for v in metadata if v["name"] == name)
            applicable.append(
                dict(
                    **row,
                    receiver=receiver,
                    association=association,
                    clause=clause,
                    support=support,
                    fields=[
                        dict(
                            id=r["id"],
                            criticality=r["criticality"],
                            presence=r["presence"],
                        )
                        for r in ref.rows(name)
                    ],
                )
            )
        applicable_map = {(v["outcome"], v["procedure_code"]): v for v in applicable}

        def encode(target, value):
            target.set_val(copy.deepcopy(value))
            wire = target.to_aper_ws()
            assert target.to_aper() == wire
            return wire

        cases = []

        def add(name, outcome, code, criticality, payload):
            value = (
                outcome,
                dict(
                    procedureCode=code,
                    criticality=criticality,
                    value=("_unk_" + str(code), payload),
                ),
            )
            wire = encode(ref.pdu, value)
            # PrivateMessage has a different body layout. Deliberately opaque
            # routing vectors do not claim it (or mandatory IE semantics) valid.
            body_decodable = not (code == 31 and outcome == "initiatingMessage")
            if body_decodable:
                ref.pdu.from_aper_ws(wire)
                decoded = ref.pdu.get_val()
                assert decoded[0] == outcome
                assert decoded[1]["procedureCode"] == code
                assert decoded[1]["criticality"] == criticality
                assert ref.pdu.to_aper_ws() == wire
            known = defined.get((outcome, code))
            app = applicable_map.get((outcome, code))
            route = {}
            invalid = code in codes and (
                known is None or known["criticality"] != criticality
            )
            for receiver in ["n3iwf", "amf"]:
                if invalid:
                    route[receiver] = "metadata-error"
                elif app:
                    route[receiver] = (
                        app["support"]
                        if app["receiver"] in [receiver, "either"]
                        else "direction-error"
                    )
                else:
                    route[receiver] = "unsupported-" + criticality
            diagnostics = None
            if not invalid and not app and criticality != "ignore":
                d = dict(
                    procedureCode=code,
                    triggeringMessage={
                        "initiatingMessage": "initiating-message",
                        "successfulOutcome": "successful-outcome",
                        "unsuccessfulOutcome": "unsuccessful-outcome",
                    }[outcome],
                    procedureCriticality=criticality,
                )
                target = ref.schema.NGAP_IEs.CriticalityDiagnostics
                diagnostics = encode(target, d).hex()
                target.from_aper_ws(bytes.fromhex(diagnostics))
                assert target.get_val() == d
            cases.append(
                dict(
                    name=name,
                    outcome=outcome,
                    procedure_code=code,
                    criticality=criticality,
                    wire_hex=wire.hex(),
                    payload_length=len(payload),
                    reference_body_decodable=body_decodable,
                    reference_known=code in codes,
                    applicable_name=app["name"] if app else None,
                    route=route,
                    diagnostics_wire_hex=diagnostics,
                )
            )

        for code in range(256):
            for outcome in OUTCOMES:
                for criticality in CRITICALITIES:
                    add(
                        f"code-{code}-{outcome}-{criticality}",
                        outcome,
                        code,
                        criticality,
                        b"\x00\x00\x00",
                    )
        lengths = [
            0,
            1,
            127,
            128,
            16383,
            16384,
            16385,
            32767,
            32768,
            32769,
            49151,
            49152,
            49153,
            65535,
            65536,
            65537,
            131072,
        ]
        payload = b"".join(
            hashlib.sha256(f"routing-{i}".encode()).digest() for i in range(4096)
        )
        for i, length in enumerate(lengths):
            add(
                f"framing-{length}",
                OUTCOMES[i % 3],
                250,
                CRITICALITIES[i % 3],
                payload[:length],
            )
        result = dict(
            source_sha256=SPEC_SHA256,
            applicability_source_sha256=APPLICABILITY_SHA256,
            reference_tools=VERSIONS,
            scope="envelope routing only; opaque bodies are not field admission or complete-message conformance",
            procedures=metadata,
            applicable=applicable,
            cases=cases,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(
            f"Verified {len(cases)} envelopes; 81 procedures, 131 defined outcomes, 40 applicable outcomes"
        )


if __name__ == "__main__":
    main()
