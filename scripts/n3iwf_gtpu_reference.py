#!/usr/bin/env python3
"""Bind the PSC catalog to unchanged independent N3 packet cases, not the writer.

This is synthetic wire/field evidence only, with no forwarding/backend claim.
The separately executable source generator imports no SDK codec or catalog.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "crates/opc-gtpu-dataplane/tests/n3_reference.tsv"
DIGEST = "31da0a1658218432817bc181be4233fadd4fd1f36c36f3d29f087bc131b8424a"
PREFIX = "opc.n3iwf.n3-gtpu.v1.reference-"


class Invalid(Exception):
    """Constant, redacted validation reason."""


def require(value, reason):
    if not value:
        raise Invalid(reason)


def selected_cases():
    cases = {f"dl-9-{r}-{p}" for r in (0, 1) for p in (None, *range(8))}
    return cases | {"dl-0-1-7", "dl-63-1-7", "ul-0", "ul-63"}


def reference_rows():
    path = ROOT / SOURCE
    require(not path.is_symlink(), "psc-reference-path")
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == DIGEST, "psc-reference-digest")
    rows = {}
    for line in data.decode().splitlines():
        if line.startswith("#"):
            continue
        row = line.split("\t")
        require(len(row) == 8 and row[0] not in rows, "psc-reference-shape")
        rows[row[0]] = row
    return rows


def validate(manifest, wire, rows):
    source = manifest["context"]["source_vector"]
    require(source["path"] == SOURCE, "psc-reference-path")
    require(source["sha256"] == DIGEST, "psc-reference-digest")
    case = source["case"]
    require(case in selected_cases(), "psc-reference-case")
    require(manifest["sdk_fixture_id"] == PREFIX + case.lower(), "psc-reference-case")
    row = rows[case]
    require(row[2] == "accept" and manifest["expected_outcome"] == "receive", "psc-reference-outcome")
    require(wire == bytes.fromhex(row[7]), "psc-reference-wire")
    require(manifest["wire"]["digest_sha256"] == hashlib.sha256(wire).hexdigest(), "psc-wire-digest")
    direction = "uplink" if row[1] == "ul" else "downlink"
    model = {"pdu_type": int(row[1] == "ul"), "qfi": int(row[3]),
             "rqi": row[4] == "1", "ppi": None if row[5] == "-" else int(row[5])}
    require(json.dumps(manifest["context"]["psc"], sort_keys=True) == json.dumps(model, sort_keys=True), "psc-reference-fields")
    claims = [f"direction={direction}", f"pdu_type={model['pdu_type']}",
              f"qfi={model['qfi']}", f"rqi={int(model['rqi'])}",
              "ppi=" + ("absent" if row[5] == "-" else row[5]),
              "payload=opaque-synthetic", "forwarding_claim=false"]
    require(manifest["semantic_assertions"] == claims, "psc-reference-claims")
    require(manifest["direction"] == "n3-" + direction, "psc-reference-direction")
    require(manifest["provenance"]["referenced_public_vector"] == SOURCE + "#" + case, "psc-reference-provenance")
    require(manifest["provenance"]["class"] == "referenced-public-vector", "psc-reference-provenance")
    require(manifest["provenance"]["synthetic"] is True and manifest["provenance"]["independent_capture"] is False, "psc-reference-provenance")
    require(manifest["source"] == {"document": "3GPP TS 38.415", "release": "V18.2.0", "clauses": ["5.5.2", "5.5.3.1-7", "TS 29.281 V18.4.0 5.1/5.2.1/5.2.2.7"]}, "psc-reference-authority")
    require(manifest["runtime_claim"] is False, "psc-runtime-claim")


def main():
    try:
        rows = reference_rows()
        directory = ROOT / "crates/opc-n3iwf-fixtures/fixtures/n3-gtpu"
        observed = set()
        for path in directory.glob("reference-*.json"):
            require(not path.is_symlink(), "psc-catalog-path")
            manifest = json.loads(path.read_text())
            require(manifest["wire"]["path"] == "wire/" + path.stem + ".hex", "psc-catalog-path")
            wire_path = directory / manifest["wire"]["path"]
            require(not wire_path.is_symlink(), "psc-catalog-path")
            wire = bytes.fromhex(wire_path.read_text())
            validate(manifest, wire, rows)
            require(manifest["sdk_fixture_id"] not in observed, "psc-reference-duplicate")
            observed.add(manifest["sdk_fixture_id"])
        require(observed == {PREFIX + name.lower() for name in selected_cases()}, "psc-reference-inventory")
    except (Invalid, OSError, ValueError, KeyError, TypeError, IndexError):
        print("n3iwf_psc_reference_mismatch")
        return 1
    print(f"n3iwf_psc_reference_valid: {len(observed)} unchanged independent packets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
