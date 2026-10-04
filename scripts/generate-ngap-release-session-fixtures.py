#!/usr/bin/env python3
"""Independent UE Context Release Complete session-list and message vectors."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--sdk-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.sdk_root / "scripts"))
    from n3iwf_ngap_reference import compile_reference, SPEC_SHA256, VERSIONS

    source = (
        args.sdk_root / "crates/opc-proto-ngap/tests/fixtures/n3iwf-release.json"
    ).read_bytes()
    original = json.loads(source)
    rows, messages = {}, []
    with tempfile.TemporaryDirectory(prefix="ngap-release-session-reference-") as tmp:
        ref = compile_reference(args.spec.read_bytes(), Path(tmp))
        typ = "PDUSessionResourceListCxtRelCpl"
        target = getattr(ref.schema.NGAP_IEs, typ)

        def encoded(target, value):
            target.set_val(copy.deepcopy(value))
            wire = target.to_aper_ws()
            assert target.to_aper() == wire
            target.from_aper_ws(wire)
            assert target.get_val() == value
            assert target.to_aper_ws() == wire
            return wire

        def transfer():
            return dict(
                id=145,
                criticality="ignore",
                extensionValue=(
                    "OCTET STRING",
                    ("PDUSessionResourceReleaseResponseTransfer", {}),
                ),
            )

        def values(model):
            result = []
            for item in model:
                value = dict(pDUSessionID=item["id"])
                if item["transfer"]:
                    value["iE-Extensions"] = [transfer()]
                result.append(value)
            return result

        reference_values = {}

        def emit(name, model, value=None, admitted=True):
            value = values(model) if value is None else value
            wire = encoded(target, value)
            rows[name] = dict(model=model, admitted=admitted, wire_hex=wire.hex())
            reference_values[name] = value

        for count in range(1, 257):
            for mode in ["absent", "present", "mixed"]:
                model = [
                    dict(
                        id=(i * 73 + count) % 256,
                        transfer=(
                            mode == "present" or (mode == "mixed" and i % 2 == 0)
                        ),
                    )
                    for i in range(count)
                ]
                emit(mode + "-count-" + str(count), model)
        for ident in range(256):
            for present in [False, True]:
                emit(
                    "single-" + str(ident) + "-" + str(int(present)),
                    [dict(id=ident, transfer=present)],
                )
        emit(
            "duplicate-session",
            [dict(id=7, transfer=False), dict(id=7, transfer=True)],
            admitted=False,
        )
        model = [dict(id=7, transfer=True)]
        for crit in ["reject", "notify"]:
            value = values(model)
            value[0]["iE-Extensions"][0]["criticality"] = crit
            emit("wrong-transfer-criticality-" + crit, model, value, False)
        value = values(model)
        value[0]["iE-Extensions"].append(transfer())
        emit("duplicate-transfer", model, value, False)
        for crit in ["reject", "ignore", "notify"]:
            value = values(model)
            value[0]["iE-Extensions"] = [
                dict(
                    id=65530, criticality=crit, extensionValue=("_unk_004", b"\xa5\x5a")
                )
            ]
            emit("unsupported-extension-" + crit, model, value, False)
        base = next(
            r
            for r in original["messages"]
            if r["name"] == "base-UEContextReleaseComplete"
        )
        ref.pdu.from_aper_ws(bytes.fromhex(base["wire_hex"]))
        base_value = copy.deepcopy(ref.pdu.get_val())
        assert encoded(ref.pdu, base_value).hex() == base["wire_hex"]
        schema = ref.rows("UEContextReleaseComplete")
        order = {v["id"]: i for i, v in enumerate(schema)}
        metadata = {v["id"]: v for v in schema}
        assert (
            metadata[60]["criticality"] == "reject"
            and metadata[60]["presence"] == "optional"
        )

        def message(
            name,
            session,
            location=True,
            diagnostic=None,
            duplicate=False,
            criticality="reject",
        ):
            value = copy.deepcopy(base_value)
            fs = value[1]["value"][1]["protocolIEs"]
            if not location:
                fs[:] = [v for v in fs if v["id"] != 121]
            if session is not None:
                fs.append(
                    dict(
                        id=60,
                        criticality=criticality,
                        value=(typ, reference_values[session]),
                    )
                )
            if duplicate:
                fs.append(
                    dict(
                        id=60,
                        criticality="reject",
                        value=(typ, reference_values["single-9-1"]),
                    )
                )
            if diagnostic is not None:
                fs.append(
                    dict(
                        id=19,
                        criticality="ignore",
                        value=("CriticalityDiagnostics", diagnostic),
                    )
                )
            fs.sort(key=lambda v: order[v["id"]])
            wire = encoded(ref.pdu, value)
            fields = [
                dict(
                    id=v["id"],
                    criticality=v["criticality"],
                    wire_hex=encoded(metadata[v["id"]]["Value"], v["value"][1]).hex(),
                )
                for v in fs
            ]
            messages.append(
                dict(
                    name=name,
                    sessions=session,
                    admitted=(session is None or rows[session]["admitted"])
                    and not duplicate
                    and criticality == "reject",
                    wire_hex=wire.hex(),
                    fields=fields,
                )
            )

        for name in rows:
            message(name, name)
        for location in [False, True]:
            for session in [None, "single-7-0", "single-7-1"]:
                for label, diag in [
                    ("absent", None),
                    ("empty", {}),
                    (
                        "items",
                        {
                            "iEsCriticalityDiagnostics": [
                                {
                                    "iECriticality": "notify",
                                    "iE-ID": 19,
                                    "typeOfError": "missing",
                                }
                            ]
                        },
                    ),
                ]:
                    message(
                        "presence-"
                        + str(int(location))
                        + "-"
                        + str(session)
                        + "-"
                        + label,
                        session,
                        location,
                        diag,
                    )
        message("duplicate-session-list", "single-7-0", duplicate=True)
        for criticality in ["ignore", "notify"]:
            message(
                "wrong-list-criticality-" + criticality,
                "single-7-0",
                criticality=criticality,
            )
        result = dict(
            source_sha256=SPEC_SHA256,
            reference_tools=VERSIONS,
            source_corpora={"n3iwf-release.json": hashlib.sha256(source).hexdigest()},
            fields=rows,
            messages=messages,
        )
        args.output.write_text(
            json.dumps(result, separators=(",", ":")).replace(
                '},{"name":', '},\n{"name":'
            )
            + "\n"
        )
        print(
            "Verified",
            len(rows),
            "fields;",
            sum(v["admitted"] for v in rows.values()),
            "admitted;",
            len(messages),
            "messages;",
            sum(v["admitted"] for v in messages),
            "admitted",
        )


if __name__ == "__main__":
    main()
