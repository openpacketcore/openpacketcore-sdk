#!/usr/bin/env python3
"""Independent Release 18 Modify Request Transfer containers and conditions."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from n3iwf_ngap_reference import Invalid, SPEC_SHA256, VERSIONS, compile_reference

KIND = "PDUSessionResourceModifyRequestTransfer"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--fields",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "crates/opc-proto-ngap/tests/fixtures/n3iwf-modify-fields.json",
    )
    args = parser.parse_args()
    data = args.fields.read_bytes()
    corpus = json.loads(data)
    assert corpus["source_sha256"] == SPEC_SHA256
    cases = []
    with tempfile.TemporaryDirectory(prefix="ngap-modify-request-") as tmp:
        ref = compile_reference(args.spec.read_bytes(), Path(tmp))
        target = getattr(ref.schema.NGAP_IEs, KIND)
        rows = {v["id"]: v for v in ref.rows(KIND)}
        metadata = [
            dict(
                id=i,
                criticality=v["criticality"],
                presence=v["presence"],
                type=v["Value"]._typeref.called[1],
            )
            for i, v in rows.items()
        ]
        order = {i: n for n, i in enumerate(rows)}

        def encode(obj, value):
            obj.set_val(copy.deepcopy(value))
            wire = obj.to_aper_ws()
            assert obj.to_aper() == wire
            return wire

        def independent(name):
            row = next(v for v in corpus["cases"] if v["name"] == name)
            obj = getattr(ref.schema.NGAP_IEs, row["type"])
            wire = bytes.fromhex(row["wire_hex"])
            assert hashlib.sha256(wire).hexdigest() == row["wire_sha256"]
            obj.from_aper_ws(wire)
            assert obj.to_aper_ws() == wire
            return copy.deepcopy(obj.get_val())

        def rate(dl, ul):
            return {
                "pDUSessionAggregateMaximumBitRateDL": dl,
                "pDUSessionAggregateMaximumBitRateUL": ul,
            }

        def field(i, value):
            return dict(
                id=i,
                criticality=rows[i]["criticality"],
                value=(rows[i]["Value"]._typeref.called[1], value),
            )

        def body(values):
            return dict(protocolIEs=[field(i, v) for i, v in values])

        def fields(value):
            result = []
            for v in value["protocolIEs"]:
                raw = (
                    v["value"][1]
                    if v["value"][0].startswith("_unk_")
                    else encode(rows[v["id"]]["Value"], v["value"][1])
                )
                result.append(
                    dict(id=v["id"], criticality=v["criticality"], wire_hex=raw.hex())
                )
            return result

        def semantic(value):
            seen = set()
            for entry in value["protocolIEs"]:
                ident = entry["id"]
                items = entry["value"][1]
                if ident in rows and ident not in [130, 140, 135, 137]:
                    raise Invalid("unsupported-known-field")
                if ident not in [135, 137]:
                    continue
                for v in items:
                    qfi = v["qosFlowIdentifier"]
                    if qfi in seen:
                        raise Invalid("duplicate-or-conflicting-qfi")
                    seen.add(qfi)
                    if ident == 135:
                        if "e-RAB-ID" in v or "iE-Extensions" in v:
                            raise Invalid("unsupported-flow-field")
                        q = v.get("qosFlowLevelQosParameters")
                        if q is not None and (
                            q["qosCharacteristics"][0] != "nonDynamic5QI"
                            or q["qosCharacteristics"][1]["fiveQI"] != 9
                        ):
                            raise Invalid("unsupported-qos-profile")

        def record(name, value, admitted=True, mode="valid"):
            value = copy.deepcopy(value)
            value["protocolIEs"].sort(key=lambda v: order.get(v["id"], 65536))
            wire = encode(target, value)
            error = None
            try:
                target.from_aper_ws(wire)
                decoded = copy.deepcopy(target.get_val())
                assert target.to_aper_ws() == wire
                ref.validate_container(KIND, decoded, 256)
                semantic(decoded)
            except Invalid as e:
                error = str(e)
            assert (error is None) == admitted, (name, error, admitted)
            canonical = copy.deepcopy(value)
            canonical["protocolIEs"][:] = [
                v for v in canonical["protocolIEs"] if v["id"] in rows
            ]
            cases.append(
                dict(
                    name=name,
                    admitted=admitted,
                    mode=mode,
                    reference_error=error,
                    wire_hex=wire.hex(),
                    wire_sha256=hashlib.sha256(wire).hexdigest(),
                    fields=fields(value),
                    canonical_fields=fields(canonical),
                    canonical_wire_hex=encode(target, canonical).hex(),
                )
            )

        release_one = independent("cause-count-1")
        release_one[0]["qosFlowIdentifier"] = 63
        defaults = [
            (130, rate(1000000, 2000000)),
            (140, independent("tunnels-1-3")),
            (135, independent("request-parameters-1")),
            (137, release_one),
        ]
        for mask in range(16):
            record(
                f"presence-{mask}",
                body([v for n, v in enumerate(defaults) if mask & 1 << n]),
            )
        for count in range(1, 65):
            for pattern in ["identifiers", "parameters", "mixed"]:
                record(
                    f"request-{pattern}-{count}",
                    body([(135, independent(f"request-{pattern}-{count}"))]),
                )
            record(
                f"release-{count}", body([(137, independent(f"cause-count-{count}"))])
            )
        for split in range(1, 64):
            added = independent(f"request-mixed-{split}")
            released = independent(f"cause-count-{64-split}")
            for n, v in enumerate(released):
                v["qosFlowIdentifier"] = split + n
            record(f"disjoint-{split}", body([(135, added), (137, released)]))
        for dl, ul in [
            (0, 0),
            (1, 2),
            (255, 256),
            (65535, 65536),
            (2**32 - 1, 2**32),
            (4000000000000, 0),
            (0, 4000000000000),
            (4000000000000, 4000000000000),
        ]:
            record(f"ambr-{dl}-{ul}", body([(130, rate(dl, ul))]))
        for count in range(1, 5):
            for pattern in range(4):
                record(
                    f"tunnels-{count}-{pattern}",
                    body([(140, independent(f"tunnels-{count}-{pattern}"))]),
                )
        for ident, name in [
            (135, "duplicate-request"),
            (135, "unsupported-five-qi"),
            (135, "unsupported-e-rab"),
            (137, "duplicate-causes"),
        ]:
            record(name, body([(ident, independent(name))]), False)
        record(
            "overlap",
            body(
                [
                    (135, independent("request-parameters-1")),
                    (137, independent("cause-count-1")),
                ]
            ),
            False,
        )
        alternatives = {
            130: rate(7, 11),
            140: independent("tunnels-2-0"),
            135: independent("request-identifiers-2"),
            137: independent("cause-count-2"),
        }
        for ident, value in defaults:
            record(
                f"duplicate-{ident}",
                body([(ident, value), (ident, alternatives[ident])]),
                False,
                "duplicate",
            )
            bad = body([(ident, value)])
            bad["protocolIEs"][0]["criticality"] = "ignore"
            record(f"criticality-{ident}", bad, False)
        for ident, value in [(129, 1), (129, 256), (166, b"\x01\x02")]:
            record(
                f"unsupported-known-{ident}-{len(cases)}",
                body([(ident, value)]),
                False,
                "unsupported",
            )
        for criticality in ["ignore", "notify", "reject"]:
            value = body(defaults)
            value["protocolIEs"].append(
                dict(id=65530, criticality=criticality, value=("_unk_004", b"\xa5\x5a"))
            )
            record(
                "unknown-" + criticality,
                value,
                criticality != "reject",
                "unknown-" + criticality,
            )
        for criticality, length in [("ignore", 16384), ("notify", 65536)]:
            value = body(defaults)
            value["protocolIEs"].append(
                dict(
                    id=65530,
                    criticality=criticality,
                    value=("_unk_004", bytes([165]) * length),
                )
            )
            record(
                "unknown-" + criticality + "-fragment",
                value,
                True,
                "unknown-" + criticality,
            )
    result = dict(
        source_sha256=SPEC_SHA256,
        reference_tools=VERSIONS,
        field_corpus_sha256=hashlib.sha256(data).hexdigest(),
        request_ie_metadata=metadata,
        cases=cases,
    )
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Wrote {len(cases)} transfers; {sum(v['admitted'] for v in cases)} admitted")


if __name__ == "__main__":
    main()
