#!/usr/bin/env python3
"""Independent Release 18 Modify response and unsuccessful transfer vectors."""

import argparse
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import tempfile

from n3iwf_ngap_reference import Invalid, SPEC_SHA256, VERSIONS, compile_reference


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cases = []
    with tempfile.TemporaryDirectory(prefix="ngap-modify-result-") as tmp:
        ref = compile_reference(args.spec.read_bytes(), Path(tmp))
        labels, causes = {}, []
        for group, kind in [
            ("radioNetwork", "CauseRadioNetwork"),
            ("transport", "CauseTransport"),
            ("nas", "CauseNas"),
            ("protocol", "CauseProtocol"),
            ("misc", "CauseMisc"),
        ]:
            enum = getattr(ref.schema.NGAP_IEs, kind)
            for label in enum._root:
                code = enum._cont[label]
                labels[group, code] = label
                causes.append(dict(group=group, code=code))

        def cause(v):
            return v["group"], labels[v["group"], v["code"]]

        def transport(v):
            ip = ipaddress.ip_address(v["address"])
            return "gTPTunnel", {
                "transportLayerAddress": (int(ip), ip.max_prefixlen),
                "gTP-TEID": v["teid"].to_bytes(4, "big"),
            }

        def diagnostics(v):
            result = {}
            for key, field in [
                ("procedure_code", "procedureCode"),
                ("trigger", "triggeringMessage"),
                ("criticality", "procedureCriticality"),
            ]:
                if v[key] is not None:
                    result[field] = v[key]
            if v["items"] is not None:
                result["iEsCriticalityDiagnostics"] = [
                    {
                        "iECriticality": x["criticality"],
                        "iE-ID": x["id"],
                        "typeOfError": x["error"],
                    }
                    for x in v["items"]
                ]
            return result

        response_kind = "PDUSessionResourceModifyResponseTransfer"
        failure_kind = "PDUSessionResourceModifyUnsuccessfulTransfer"

        def value(kind, model):
            if kind == failure_kind:
                result = {"cause": cause(model["cause"])}
                if model["diagnostics"] is not None:
                    result["criticalityDiagnostics"] = diagnostics(model["diagnostics"])
                return result
            result = {}
            for direction in ["downlink", "uplink"]:
                if model[direction] is not None:
                    result[
                        (
                            "dL-NGU-UP-TNLInformation"
                            if direction == "downlink"
                            else "uL-NGU-UP-TNLInformation"
                        )
                    ] = transport(model[direction])
            if model["accepted"] is not None:
                result["qosFlowAddOrModifyResponseList"] = [
                    {"qosFlowIdentifier": qfi} for qfi in model["accepted"]
                ]
            if model["failed"] is not None:
                result["qosFlowFailedToAddOrModifyList"] = [
                    {"qosFlowIdentifier": v["qfi"], "cause": cause(v["cause"])}
                    for v in model["failed"]
                ]
            return result

        def semantic(kind, v):
            if "iE-Extensions" in v:
                raise Invalid("unsupported-transfer-extension")
            if kind == failure_kind:
                d = v.get("criticalityDiagnostics", {})
                if "procedureCode" in d or "triggeringMessage" in d:
                    raise Invalid("response-diagnostic-header")
                if any(
                    x["iECriticality"] == "ignore"
                    for x in d.get("iEsCriticalityDiagnostics", [])
                ):
                    raise Invalid("inapplicable-diagnostic-criticality")
            else:
                if "additionalDLQosFlowPerTNLInformation" in v:
                    raise Invalid("unsupported-additional-tunnel")
                seen = set()
                for key in [
                    "qosFlowAddOrModifyResponseList",
                    "qosFlowFailedToAddOrModifyList",
                ]:
                    for item in v.get(key, []):
                        if "iE-Extensions" in item:
                            raise Invalid("unsupported-flow-extension")
                        qfi = item["qosFlowIdentifier"]
                        if qfi in seen:
                            raise Invalid("duplicate-or-conflicting-qfi")
                        seen.add(qfi)

        def record(name, kind, model, admitted=True, override=None):
            v = value(kind, model) if override is None else override
            target = getattr(ref.schema.NGAP_IEs, kind)
            target.set_val(copy.deepcopy(v))
            wire = target.to_aper_ws()
            assert target.to_aper() == wire
            target.from_aper_ws(wire)
            decoded = copy.deepcopy(target.get_val())
            assert decoded == v
            assert target.to_aper_ws() == wire
            error = None
            try:
                semantic(kind, decoded)
            except Invalid as e:
                error = str(e)
            assert (error is None) == admitted, (name, error)
            cases.append(
                dict(
                    name=name,
                    type=kind,
                    model=model,
                    admitted=admitted,
                    reference_error=error,
                    wire_hex=wire.hex(),
                    wire_sha256=hashlib.sha256(wire).hexdigest(),
                )
            )

        base = dict(downlink=None, uplink=None, accepted=None, failed=None)
        dl = dict(address="198.51.100.11", teid=0x11223344)
        ul = dict(address="2001:db8::abcd", teid=0x55667788)
        defaults = [dl, ul, [0], [dict(qfi=63, cause=causes[0])]]
        for mask in range(16):
            model = {
                key: defaults[i] if mask & 1 << i else None
                for i, key in enumerate(base)
            }
            record(f"presence-{mask}", response_kind, model)
        for direction in ["downlink", "uplink"]:
            for index, address in enumerate(
                [
                    "0.0.0.0",
                    "198.51.100.11",
                    "255.255.255.255",
                    "::",
                    "2001:db8::abcd",
                    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                ]
            ):
                for teid in [0, 1, 0x12345678, 0xFFFFFFFF]:
                    model = dict(base, **{direction: dict(address=address, teid=teid)})
                    record(f"{direction}-{index}-{teid}", response_kind, model)
        for dl_ip in ["198.51.100.11", "2001:db8::1"]:
            for ul_ip in ["198.51.100.22", "2001:db8::2"]:
                for mask in range(4):
                    model = dict(
                        base,
                        downlink=dict(address=dl_ip, teid=0),
                        uplink=dict(address=ul_ip, teid=0xFFFFFFFF),
                        accepted=[1] if mask & 1 else None,
                        failed=[dict(qfi=63, cause=causes[-1])] if mask & 2 else None,
                    )
                    record(f"families-{len(cases)}", response_kind, model)
        for count in range(1, 65):
            record(
                f"accepted-count-{count}",
                response_kind,
                dict(base, accepted=list(range(count))),
            )
            record(
                f"failed-count-{count}",
                response_kind,
                dict(
                    base,
                    failed=[
                        dict(qfi=n, cause=causes[n % len(causes)]) for n in range(count)
                    ],
                ),
            )
        for split in range(1, 64):
            record(
                f"disjoint-{split}",
                response_kind,
                dict(
                    base,
                    accepted=list(range(split)),
                    failed=[
                        dict(qfi=n, cause=causes[n % len(causes)])
                        for n in range(split, 64)
                    ],
                ),
            )
        for qfi in range(64):
            record(f"qfi-{qfi}", response_kind, dict(base, accepted=[qfi]))
        for count in range(1, 9):
            for c in causes:
                record(
                    f"cause-offset-{count}-{c['group']}-{c['code']}",
                    response_kind,
                    dict(
                        base,
                        accepted=list(range(count)),
                        failed=[dict(qfi=63, cause=c)],
                    ),
                )
        for name, model in [
            ("duplicate-accepted", dict(base, accepted=[1, 1])),
            ("duplicate-failed", dict(base, failed=[dict(qfi=1, cause=causes[0])] * 2)),
            (
                "overlap",
                dict(base, accepted=[1], failed=[dict(qfi=1, cause=causes[0])]),
            ),
        ]:
            record(name, response_kind, model, False)
        model = dict(base, downlink=dl)
        v = value(response_kind, model)
        v["additionalDLQosFlowPerTNLInformation"] = [
            {
                "qosFlowPerTNLInformation": {
                    "uPTransportLayerInformation": transport(ul),
                    "associatedQosFlowList": [{"qosFlowIdentifier": 1}],
                }
            }
        ]
        record("unsupported-additional-tunnel", response_kind, model, False, v)
        v = value(response_kind, base)
        v["iE-Extensions"] = [
            {
                "id": 65530,
                "criticality": "ignore",
                "extensionValue": ("_unk_004", b"\xa5\x5a"),
            }
        ]
        record("unsupported-response-extension", response_kind, base, False, v)

        empty = dict(procedure_code=None, trigger=None, criticality=None, items=None)
        item = dict(criticality="reject", id=130, error="missing")
        for c in causes:
            record(
                f"failure-{c['group']}-{c['code']}",
                failure_kind,
                dict(cause=c, diagnostics=None),
            )
            for i, d in enumerate(
                [
                    empty,
                    dict(empty, criticality="ignore"),
                    dict(empty, items=[item]),
                    dict(
                        empty,
                        criticality="reject",
                        items=[dict(item, criticality="notify", id=65535)],
                    ),
                ]
            ):
                record(
                    f"diagnostic-cause-{c['group']}-{c['code']}-{i}",
                    failure_kind,
                    dict(cause=c, diagnostics=d),
                )
        for count in range(1, 257):
            d = dict(
                empty,
                criticality=[None, "reject", "ignore", "notify"][count % 4],
                items=[
                    dict(
                        criticality="reject" if n % 2 else "notify",
                        id=[0, 65535, 135][n % 3],
                        error="missing" if n % 2 else "not-understood",
                    )
                    for n in range(count)
                ],
            )
            record(
                f"diagnostic-count-{count}",
                failure_kind,
                dict(cause=causes[count % len(causes)], diagnostics=d),
            )
        for key, values in [
            ("procedure_code", [0, 26, 255]),
            (
                "trigger",
                ["initiating-message", "successful-outcome", "unsuccessful-outcome"],
            ),
            ("items", [[dict(item, criticality="ignore")]]),
        ]:
            for i, v in enumerate(values):
                record(
                    f"inapplicable-{key}-{i}",
                    failure_kind,
                    dict(cause=causes[0], diagnostics=dict(empty, **{key: v})),
                    False,
                )
        model = dict(cause=causes[0], diagnostics=None)
        v = value(failure_kind, model)
        v["iE-Extensions"] = [
            {
                "id": 65530,
                "criticality": "ignore",
                "extensionValue": ("_unk_004", b"\xa5\x5a"),
            }
        ]
        record("unsupported-failure-extension", failure_kind, model, False, v)
    args.output.write_text(
        json.dumps(
            dict(source_sha256=SPEC_SHA256, reference_tools=VERSIONS, cases=cases),
            indent=2,
        )
        + "\n"
    )
    print(f"Wrote {len(cases)} transfers; {sum(v['admitted'] for v in cases)} admitted")


if __name__ == "__main__":
    main()
