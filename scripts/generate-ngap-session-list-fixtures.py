#!/usr/bin/env python3
"""Independent Release 18 session setup lists with qualified contained transfers."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import tempfile

from n3iwf_ngap_reference import SPEC_SHA256, VERSIONS, compile_reference

KINDS = {
    "PDUSessionResourceSetupListCxtReq": ("request", "nAS-PDU"),
    "PDUSessionResourceSetupListSUReq": ("request", "pDUSessionNAS-PDU"),
    "PDUSessionResourceSetupListCxtRes": ("response", None),
    "PDUSessionResourceSetupListSURes": ("response", None),
    "PDUSessionResourceFailedToSetupListCxtFail": ("failure", None),
    "PDUSessionResourceFailedToSetupListCxtRes": ("failure", None),
    "PDUSessionResourceFailedToSetupListSURes": ("failure", None),
}
TRANSFERS = {
    "request": "PDUSessionResourceSetupRequestTransfer",
    "response": "PDUSessionResourceSetupResponseTransfer",
    "failure": "PDUSessionResourceSetupUnsuccessfulTransfer",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    fixtures = root / "crates/opc-proto-ngap/tests/fixtures"
    requests = json.loads((fixtures / "n3iwf-resource-request.json").read_text())[
        "transfers"
    ]
    results = json.loads((fixtures / "n3iwf-resource-results.json").read_text())[
        "cases"
    ]
    bases = {
        "request": next(row for row in requests if row["mode"] == "construct"),
        "request-max": next(
            row
            for row in requests
            if row["mode"] == "construct" and len(row["model"]["flows"]) == 64
        ),
        "request-notify": next(
            row for row in requests if row["mode"] == "unknown-notify-fragment"
        ),
        "request-ignore": next(
            row for row in requests if row["mode"] == "unknown-ignore"
        ),
        "request-reject": next(
            row for row in requests if row["mode"] == "unknown-reject"
        ),
        "response": next(row for row in results if row["name"] == "accepted-count-1"),
        "response-partial": next(
            row for row in results if row["name"] == "ipv6-partial-31"
        ),
        "failure": next(row for row in results if row["name"] == "failure-misc-5"),
    }
    cases = []
    with tempfile.TemporaryDirectory(
        prefix="ngap-session-list-reference-"
    ) as temporary:
        ref = compile_reference(args.spec.read_bytes(), Path(temporary))
        contained = {}
        for name, row in bases.items():
            kind = name.split("-", 1)[0]
            target = getattr(ref.schema.NGAP_IEs, TRANSFERS[kind])
            target.from_aper(bytes.fromhex(row["wire_hex"]))
            contained[name] = copy.deepcopy(target.get_val())
            assert target.to_aper().hex() == row["wire_hex"]

        def value(kind, model, canonical=False):
            category, nas_key = KINDS[kind]
            name = TRANSFERS[category]
            leaf = copy.deepcopy(contained[model["transfer"]])
            if canonical and model["transfer"] in ("request-notify", "request-ignore"):
                leaf["protocolIEs"] = [
                    ie for ie in leaf["protocolIEs"] if ie["id"] != 65535
                ]
            items = []
            for ident in model["ids"]:
                item = {
                    "pDUSessionID": ident,
                    "pDUSessionResourceSetup"
                    + {
                        "request": "Request",
                        "response": "Response",
                        "failure": "Unsuccessful",
                    }[category]
                    + "Transfer": (name, copy.deepcopy(leaf)),
                }
                if category == "request":
                    item["s-NSSAI"] = {"sST": bytes([ident])}
                    if model["sd"] is not None:
                        item["s-NSSAI"]["sD"] = bytes.fromhex(model["sd"])
                    if model["nas_hex"] is not None:
                        item[nas_key] = bytes.fromhex(model["nas_hex"])
                items.append(item)
            return items

        def encode(kind, values):
            target = getattr(ref.schema.NGAP_IEs, kind)
            target.set_val(copy.deepcopy(values))
            wire = target.to_aper()
            # Pycrate 0.8.1's plain fragment decoder advances its alignment
            # offset by remainder octets rather than bits. Its independent
            # structured decoder accounts correctly for a following field.
            # Require both unmodified reference encoders to produce the bytes.
            assert target.to_aper_ws() == wire
            target.from_aper_ws(wire)
            assert target.get_val() == values
            assert target.to_aper() == wire
            return wire

        def record(name, kind, model, admitted=True):
            try:
                wire = encode(kind, value(kind, model))
            except Exception as error:
                raise RuntimeError(
                    f"reference roundtrip failed: {name}/{kind}"
                ) from error
            canonical = encode(kind, value(kind, model, canonical=True))
            cases.append(
                {
                    "name": name + "-" + kind,
                    "type": kind,
                    "category": KINDS[kind][0],
                    "model": model,
                    "admitted": admitted,
                    "wire_hex": wire.hex(),
                    "wire_sha256": hashlib.sha256(wire).hexdigest(),
                    "canonical_wire_hex": canonical.hex(),
                }
            )

        for kind, (category, _) in KINDS.items():

            def model(ids, **extra):
                return dict(ids=ids, sd=None, nas_hex=None, transfer=category, **extra)

            for count in (1, 2, 15, 16, 255, 256):
                record(f"count-{count}", kind, model(list(range(count))))
            record("unordered-boundaries", kind, model([255, 0, 254, 1]))
            record("duplicate-session", kind, model([1, 1]), admitted=False)
            if category == "request":
                for length in (
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
                ):
                    m = model([255])
                    m["nas_hex"] = b"".join(
                        hashlib.sha256(f"synthetic-nas-block-{i}".encode()).digest()
                        for i in range((length + 31) // 32)
                    )[:length].hex()
                    m["sd"] = "abcdef"
                    record(f"nas-length-{length}", kind, m)
                for sd in ("000000", "ffffff"):
                    m = model([0, 255, 1])
                    m["sd"] = sd
                    record("sd-" + sd, kind, m)
                for leaf in (
                    "request-max",
                    "request-notify",
                    "request-ignore",
                    "request-reject",
                ):
                    m = model([2])
                    m["transfer"] = leaf
                    record(leaf, kind, m, admitted=leaf != "request-reject")
            elif category == "response":
                m = model([0, 255])
                m["transfer"] = "response-partial"
                record("partial-flows", kind, m)
    args.output.write_text(
        json.dumps(
            {
                "source_sha256": SPEC_SHA256,
                "reference_tools": VERSIONS,
                "reference_decoder": "from_aper_ws; both to_aper and to_aper_ws must agree",
                "base_transfers": {
                    name: {"model": row["model"], "wire_hex": row["wire_hex"]}
                    for name, row in bases.items()
                },
                "cases": cases,
            },
            indent=2,
        )
        + "\n"
    )
    print("Wrote", len(cases), "independent session-list cases")


if __name__ == "__main__":
    main()
