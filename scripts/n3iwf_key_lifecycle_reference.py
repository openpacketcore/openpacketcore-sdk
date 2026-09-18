#!/usr/bin/env python3
"""Independent schedules for the SDK's volatile custody contract, not wire policy.

No SDK codec, runtime or catalog writer is imported. Expected results are
explicitly authored obligations. AUTH values reuse the independent RFC recipe;
opaque public refusal is not evidence of memory erasure.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCOPE = "protocol-key-lifecycle"
SOURCE = "crates/opc-n3iwf-fixtures/oracles/key-lifecycle.json"
PREFIX = "opc.n3iwf.protocol-key.v1.custody-"
SOURCES = {
    "crates/opc-proto-ikev2/src/protocol_key.rs": "782b456e3a17fe51be226d9c0920f89e53cb341e9ddc58ac0b36dd35bef5ec7a",
    "crates/opc-proto-ikev2/src/protocol_key/tests.rs": "b12635232fc117e33bd2c49ac82cd1eda2df986682dd8a33f32d9661fe5dc24f",
    "crates/opc-n3iwf-fixtures/oracles/ike-auth-sha256.json": "e1db7a997007bd2341226d770db34d0c76e89cf56418e92497c63f0e0422667f",
}


class Invalid(Exception):
    """Constant, value-free evidence refusal."""


def require(condition, reason):
    if not condition:
        raise Invalid(reason)


def step(action, expect="ok", **fields):
    return dict(action=action, expect=expect, **fields)


def begin(slot=0, generation=1, operation=1, owner=0, expect="ok"):
    return step("begin", expect, owner=owner, slot=slot, generation=generation, operation=operation)


def imported(slot=0, key=0, length=32, purpose="n3iwf", expect="ok"):
    return step("import", expect, slot=slot, key=key, length=length, purpose=purpose)


def consume(key=0, slot=0, expect="ok", **kw):
    return step("consume", expect, key=key, slot=slot, **kw)


def cases():
    # Errors are the published value-free API names. They are never obtained
    # from a runtime execution or inferred from a catalog's expected outcome.
    retired = "protocol_key_retired"
    generation = "protocol_key_generation_mismatch"
    mismatch = "protocol_key_operation_mismatch"
    released = "protocol_key_released"
    records = []
    def add(name, actions):
        records.append(dict(name=name, initial_generation=1, steps=actions))
    start = [begin(), imported()]
    add("consume-once", start + [consume(), consume(expect=retired)])
    add("wrong-generation-begin", [begin(generation=2, expect=generation)] + start + [consume()])
    for name, old, new in [("wrong-expected-generation", 2, 3), ("non-increasing-generation", 1, 1)]:
        add(name, start + [step("replace", generation, owner=0, current=old, replacement=new), consume()])
    add("replacement", start + [step("replace", owner=0, current=1, replacement=2),
        consume(expect=generation), imported(key=1, expect=generation), begin(1, 2), imported(1, 1),
        consume(0, 1, mismatch), step("drop-operation", slot=0), step("drop-key", key=0), consume(1, 1)])
    add("foreign-association", start + [step("new-owner", owner=1, generation=1),
        begin(1, owner=1), imported(1, 1), consume(0, 1, mismatch), consume(1, 0, mismatch), consume(), consume(1, 1)])
    add("duplicate-import", start + [imported(key=1, expect=retired), consume()])
    add("pending-operation", start + [begin(1, operation=2, expect="protocol_key_operation_pending"), consume()])
    for length in [0, 1, 31, 33, 4096]:
        add(f"invalid-width-{length}", [begin(), imported(length=length, expect="protocol_key_invalid_length"),
            imported(expect=retired), step("cancel", slot=0), begin(1, operation=2), imported(1, 1), consume(1, 1)])
    add("wrong-purpose", [begin(), imported(purpose="unsupported", expect="protocol_key_unsupported_purpose"), imported(expect=retired)])
    add("input-limit", start + [consume(expect="protocol_key_input_limit", max_input_bytes=0), consume(expect=retired)])
    add("wrong-transcript-direction", start + [consume(expect="protocol_key_invalid_auth_inputs", wrong_direction=True), consume(expect=retired)])
    add("drop-key", start + [step("drop-key", key=0), imported(key=1, expect=retired),
        begin(1, operation=2), imported(1, 1), consume(1, 1)])
    add("drop-operation", start + [step("drop-operation", slot=0), begin(1, operation=2),
        imported(1, 1), consume(0, 1, mismatch), step("drop-key", key=0), consume(1, 1)])
    add("drop-association", start + [step("drop-owner", owner=0), consume(expect=released), imported(key=1, expect=released)])
    add("release", start + [step("release", owner=0), step("release", owner=0), consume(expect=released),
        imported(key=1, expect=released), begin(1, operation=2, expect=released),
        step("replace", released, owner=0, current=1, replacement=2)])
    add("cancel-successor", start + [step("cancel", slot=0), consume(expect=retired),
        begin(1, operation=2), imported(1, 1), step("cancel", slot=0), step("drop-operation", slot=0),
        step("drop-key", key=0), consume(1, 1)])
    add("cancel-future", start + [step("cancel-future", slot=0), begin(1, operation=2),
        imported(1, 1), consume(0, 1, mismatch), step("drop-key", key=0), consume(1, 1)])
    add("operation-reuse", [begin(), step("cancel", slot=0), begin(1, expect="protocol_key_operation_reused"),
        begin(1, operation=2), imported(1, 1), consume(1, 1)])
    maximum = 2**64 - 1
    add("generation-exhaustion", start + [step("replace", owner=0, current=1, replacement=maximum),
        consume(expect=generation), begin(1, maximum), imported(1, 1),
        step("replace", generation, owner=0, current=maximum, replacement=1), consume(1, 1)])
    add("concurrent-consume-once", start + [step("concurrent-consume", key=0, slot=0,
        outcomes=["ok", retired]), consume(expect=retired)])
    assert len(records) == 25 and len({r["name"] for r in records}) == len(records)
    return records


def wire(case):
    return (json.dumps(case, sort_keys=True, separators=(",", ":")) + "\n").encode()


def reference_bytes():
    data = dict(schema_version=1, scope=SCOPE, policy="SDK volatile custody; not a wire-standard obligation",
        sources=SOURCES, key_recipe="32 zero octets; independent synthetic NGAP placeholder only",
        auth_cases=["auth-initiator-known-answer", "auth-responder-known-answer"],
        memory_erasure_evidence="Existing private pre-release zeroization audit, separately executed; no public-memory observation",
        cases=cases())
    return (json.dumps(data, indent=2) + "\n").encode()


def check_sources():
    for relative, digest in SOURCES.items():
        path = ROOT / relative
        require(not path.is_symlink(), "custody-source-path")
        require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, "custody-source-digest")


def validate(manifest, data):
    reference = reference_bytes()
    source = manifest["context"]["source_vector"]
    require(source["path"] == SOURCE, "custody-reference-path")
    require(source["sha256"] == hashlib.sha256(reference).hexdigest(), "custody-reference-digest")
    rows = {c["name"]: c for c in cases()}
    name = source["case"]
    require(name in rows and manifest["sdk_fixture_id"] == PREFIX + name, "custody-reference-case")
    require(data == wire(rows[name]), "custody-reference-wire")
    require(manifest["wire"]["digest_sha256"] == hashlib.sha256(data).hexdigest(), "custody-wire-digest")
    context = dict(source_vector=source, key_recipe="32-zero-octets", sdk_custody_validation=True,
        live_peer_validation=False, public_memory_erasure_observation=False)
    require(json.dumps(manifest["context"], sort_keys=True) == json.dumps(context, sort_keys=True), "custody-reference-context")
    require(manifest["encoding"] == "scenario-record" and manifest["validation_scope"] == SCOPE, "custody-reference-scope")
    require(manifest["source"] == dict(document="RFC 7296", release="Published RFC (2014)",
        clauses=["2.15", "2.16", "TS 33.501 V18.12.0 7.2.1", "SDK volatile protocol_key custody contract"]), "custody-reference-authority")
    require(manifest["semantic_assertions"] == ["scenario=" + name, "key_recipe=32-zero-octets",
        "sdk_custody_validation=true", "live_peer_validation=false", "public_memory_erasure_observation=false"], "custody-reference-claims")
    require(manifest["direction"] == "local" and manifest["role"] == "n3iwf", "custody-reference-direction")
    require(manifest["provenance"]["referenced_public_vector"] == SOURCE + "#" + name
        and manifest["provenance"]["class"] == "referenced-public-vector"
        and manifest["provenance"]["synthetic"] is True
        and manifest["provenance"]["independent_capture"] is False, "custody-reference-provenance")
    require(manifest["expected_outcome"] == "constructed" and manifest["runtime_claim"] is False, "custody-reference-outcome")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        check_sources()
        reference = reference_bytes()
        target = ROOT / SOURCE
        require(not target.is_symlink(), "custody-reference-path")
        if args.write:
            target.write_bytes(reference)
        else:
            require(target.read_bytes() == reference, "custody-reference-digest")
            directory = ROOT / "crates/opc-n3iwf-fixtures/fixtures/protocol-key"
            observed = set()
            for path in directory.glob("custody-*.json"):
                require(not path.is_symlink(), "custody-catalog-path")
                manifest = json.loads(path.read_text())
                require(manifest["wire"]["path"] == "wire/" + path.stem + ".hex", "custody-catalog-path")
                payload = directory / manifest["wire"]["path"]
                require(not payload.is_symlink(), "custody-catalog-path")
                validate(manifest, bytes.fromhex(payload.read_text()))
                require(manifest["sdk_fixture_id"] not in observed, "custody-reference-duplicate")
                observed.add(manifest["sdk_fixture_id"])
            require(observed == {PREFIX + c["name"] for c in cases()}, "custody-reference-inventory")
    except (Invalid, OSError, ValueError, KeyError, TypeError, IndexError):
        print("n3iwf_custody_reference_mismatch")
        return 1
    print(f"n3iwf_custody_reference_valid: {len(cases())} authored schedules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
