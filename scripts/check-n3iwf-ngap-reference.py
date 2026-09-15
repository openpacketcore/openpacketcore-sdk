#!/usr/bin/env python3
"""Recompile the pinned independent schema and verify published NGAP evidence."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
import tempfile
import urllib.request
from pathlib import Path

from n3iwf_ngap_reference import (
    Invalid,
    MAX_SPEC_BYTES,
    MAX_WIRE_BYTES,
    MODULE_SHA256,
    SPEC_SHA256,
    SPEC_URL,
    VERSIONS,
    compile_reference,
    extract_modules,
    require,
    unpack,
)

ROOT = Path(__file__).resolve().parents[1]
ORACLES = ROOT / "crates/opc-n3iwf-fixtures/oracles"
FIXTURES = ROOT / "crates/opc-n3iwf-fixtures/fixtures/ngap"


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate-json-key")
        result[key] = value
    return result


def read_bounded(path: Path, limit: int) -> bytes:
    require(not path.is_symlink() and path.is_file(), "reference-file")
    with path.open("rb") as source:
        content = source.read(limit + 1)
    require(len(content) <= limit, "reference-file-size")
    return content


def read_json(path: Path):
    return json.loads(read_bounded(path, 256 * 1024), object_pairs_hook=unique_pairs)


def read_spec(path: Path | None) -> bytes:
    if path is not None:
        return read_bounded(path, MAX_SPEC_BYTES)
    # The URL and digest are compile-time pins, never taken from a manifest.
    # ETSI rejects urllib's default client identity with HTTP 403.
    request = urllib.request.Request(
        SPEC_URL, headers={"User-Agent": "OpenPacketCore-SDK-reference/1.0"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        require(response.url.startswith("https://"), "spec-transport")
        return response.read(MAX_SPEC_BYTES + 1)


def expect_rejection(
    reference, wire: bytes, reason: str | None = None, max_ies: int = 256
):
    try:
        reference.decode(wire, max_ies)
    except Invalid as error:
        require(reason is None or str(error) == reason, "reference-error-mismatch")
        return
    raise Invalid("reference-accepted-negative")


def check_matrices(reference, matrices: dict) -> None:
    for name, expected in matrices["messages"].items():
        rows = reference.rows(name)
        actual = [(row["id"], row["criticality"], row["presence"]) for row in rows]
        require(
            actual
            == [(row["id"], row["criticality"], row["presence"]) for row in expected],
            "matrix-independent-schema",
        )
        choice, code, criticality = reference.procedures[name]
        dispatch = matrices["dispatch"][name]
        require(code == dispatch["procedure_code"], "matrix-procedure")
        require(
            choice
            == {
                "initiating": "initiatingMessage",
                "successful": "successfulOutcome",
                "unsuccessful": "unsuccessfulOutcome",
            }[dispatch["outcome"]],
            "matrix-outcome",
        )
        require(
            {"reject": 0, "ignore": 64, "notify": 128}[criticality]
            == dispatch["criticality_octet"],
            "matrix-criticality",
        )


def check_case(reference, case: dict) -> None:
    name = case["name"]
    require(
        isinstance(name, str) and re.fullmatch(r"[a-z0-9-]{1,96}", name) is not None,
        "case-name",
    )
    value = unpack(case["pdu"])
    require(value[1]["value"][0] == case["message"], "case-message")
    require(
        reference.encoded_fields(value) == case["encoded_ies"], "reference-ie-encoding"
    )
    encoded = reference.encode(value)
    if "wire_transform" in case:
        require(case["wire_transform"] == "truncate-final-octet", "wire-transform")
        encoded = encoded[:-1]
    wire = bytes.fromhex(case["wire_hex"])
    require(encoded == wire, "reference-encoding")
    require(hashlib.sha256(wire).hexdigest() == case["wire_sha256"], "reference-digest")
    published = bytes.fromhex(
        read_bounded(FIXTURES / "wire" / (name + ".hex"), MAX_WIRE_BYTES * 3).decode(
            "ascii"
        )
    )
    require(published == wire, "published-wire")
    manifest = read_json(FIXTURES / (name + ".json"))
    require(manifest["validation_scope"] == "ngap-release18-message", "published-scope")
    require(manifest["context"]["message"] == case["message"], "published-message")
    require(
        manifest["context"]["independent_asn1_validation"] is True,
        "published-reference",
    )
    require(
        manifest["context"]["sdk_structural_outcome"] == case["sdk_structural_outcome"],
        "published-sdk-outcome",
    )
    require(
        manifest["context"]["reference_error"] == case["reference_error"],
        "published-error",
    )
    require(manifest["context"]["max_ies"] == case["max_ies"], "published-bound")
    require(manifest["runtime_claim"] is False, "published-runtime-claim")
    require(
        manifest["context"]["sdk_semantic_validation"] is False,
        "published-sdk-semantic-claim",
    )
    require(manifest["case_class"] == case["case_class"], "published-case-class")
    require(
        manifest["wire"]["digest_sha256"] == case["wire_sha256"], "published-digest"
    )
    require(
        manifest["expected_outcome"]
        == ("reject" if case["reference_error"] else "receive"),
        "published-outcome",
    )
    if case["reference_error"] is None:
        decoded = reference.decode(wire, case["max_ies"])
        require(decoded == value, "reference-decoded-fields")
    else:
        expect_rejection(reference, wire, case["reference_error"], case["max_ies"])


def mutation_checks(reference, cases: list[dict]) -> dict[str, int]:
    """Re-encode bad values independently; digests cannot catch these tests."""
    counts = {
        "missing_mandatory": 0,
        "duplicate_ie": 0,
        "wrong_criticality": 0,
        "truncated_prefix": 0,
    }
    seen = set()
    for case in cases:
        name = case["message"]
        if case["reference_error"] is not None or name in seen:
            continue
        seen.add(name)
        value = unpack(case["pdu"])
        fields = value[1]["value"][1]["protocolIEs"]
        for row in reference.rows(name):
            if row["presence"] == "mandatory":
                changed = copy.deepcopy(value)
                items = changed[1]["value"][1]["protocolIEs"]
                items[:] = [item for item in items if item["id"] != row["id"]]
                expect_rejection(
                    reference, reference.encode(changed), "missing-mandatory-ie"
                )
                counts["missing_mandatory"] += 1
        for index in range(len(fields)):
            changed = copy.deepcopy(value)
            items = changed[1]["value"][1]["protocolIEs"]
            items.append(copy.deepcopy(items[index]))
            expect_rejection(reference, reference.encode(changed), "duplicate-ie")
            counts["duplicate_ie"] += 1
            changed = copy.deepcopy(value)
            item = changed[1]["value"][1]["protocolIEs"][index]
            item["criticality"] = (
                "ignore" if item["criticality"] == "reject" else "reject"
            )
            expect_rejection(reference, reference.encode(changed), "ie-criticality")
            counts["wrong_criticality"] += 1
        wire = reference.encode(value)
        for size in range(len(wire)):
            expect_rejection(reference, wire[:size])
            counts["truncated_prefix"] += 1
    require(len(seen) == 15 and all(counts.values()), "mutation-coverage")
    try:
        extract_modules(b"synthetic-wrong-publication")
    except Invalid as error:
        require(str(error) == "spec-digest", "spec-negative")
    else:
        raise Invalid("spec-accepted-negative")
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--spec",
        type=Path,
        help="local copy of the exact pinned PDF; otherwise download it",
    )
    parser.add_argument(
        "--report", type=Path, help="write a report of versions, hashes and test counts"
    )
    args = parser.parse_args()
    try:
        corpus = read_json(ORACLES / "ngap-rel18-messages.json")
        require(corpus["schema_version"] == 1, "corpus-version")
        require(
            corpus["source_sha256"] == SPEC_SHA256 and corpus["source_url"] == SPEC_URL,
            "corpus-source",
        )
        require(corpus["module_sha256"] == list(MODULE_SHA256), "corpus-modules")
        require(
            corpus["reference_tools"] == VERSIONS and corpus["runtime_claim"] is False,
            "corpus-tools",
        )
        cases = corpus["cases"]
        names = {case["name"] for case in cases}
        require(len(names) == len(cases), "corpus-duplicate")
        completion = read_json(FIXTURES / "COMPLETION.json")
        positive = {
            case["message"]
            for case in cases
            if case["reference_error"] is None and case["case_class"] == "positive"
        }
        require(
            positive == set(completion["admitted_outcomes"]) and len(positive) == 15,
            "corpus-admitted-outcomes",
        )
        published = {
            manifest["sdk_fixture_id"].split(".v1.")[1]
            for path in FIXTURES.glob("*.json")
            if path.name != "COMPLETION.json"
            and (manifest := read_json(path))["validation_scope"]
            == "ngap-release18-message"
        }
        require(names == published, "corpus-inventory")
        with tempfile.TemporaryDirectory(
            prefix="ngap-release18-reference-"
        ) as directory:
            reference = compile_reference(read_spec(args.spec), Path(directory))
            check_matrices(reference, read_json(ORACLES / "ngap-rel18.json"))
            for case in cases:
                check_case(reference, case)
            mutations = mutation_checks(reference, cases)
        report = {
            "source_sha256": SPEC_SHA256,
            "module_sha256": list(MODULE_SHA256),
            "reference_tools": VERSIONS,
            "complete_outcomes": len(positive),
            "cases": len(cases),
            "mutations": mutations,
            "runtime_claim": False,
            "result": "pass",
        }
        if args.report:
            args.report.write_text(
                json.dumps(report, indent=2) + "\n", encoding="utf-8"
            )
        print(json.dumps(report, sort_keys=True))
        return 0
    except Invalid as error:
        # Invalid carries only the constant reasons defined in this gate.
        print(f"n3iwf_ngap_independent_reference_failed: {error}", file=sys.stderr)
        return 1
    except Exception:
        # Parser and reference-tool exceptions can contain full input values.
        print("n3iwf_ngap_independent_reference_failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
