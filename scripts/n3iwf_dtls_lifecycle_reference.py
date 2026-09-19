#!/usr/bin/env python3
"""Independent obligations for the existing SDK RFC 6083 stream-zero profile.

No runtime or catalog-writer imports. The separate Python X.509 reference owns
certificate expectations; this model owns bounded SDK lifecycle schedules.
No encrypted records, keys, identities or deployment values are emitted.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "crates/opc-n3iwf-fixtures/oracles/dtls-lifecycle.json"
TABLE = "crates/opc-diameter-transport/tests/fixtures/rfc6083/lifecycle.tsv"
CERTIFICATES = "crates/opc-diameter-transport/tests/fixtures/rfc6083/certificates.tsv"
CERTIFICATE_DIGEST = "f8dff321905c79f06c752b477bc56fc7f2d7a5e67acda40cc2a774bd708f416b"
CONTRACT = "docs/rfc6083-generic-transport.md"
CONTRACT_END = "## Evidence and reproduction\n"
CONTRACT_DIGEST = "308f661f2f868b693f476200b95e0cfe06b59531cbc3b8a6c2838a5acc6d6f5f"
SCOPE = "rfc6083-stream-zero-lifecycle"
PREFIX = "opc.n3iwf.n2-dtls.v1.lifecycle-"
FAMILIES = ("certificate", "records", "limits", "cancellation", "deadline",
            "retirement", "carrier", "close", "metadata", "cleartext")
COLUMNS = ("name", "family", "side", "argument", "expected")
CERTIFICATE_CASES = (
    ("valid", "admit"), ("wrong-identity", "identity"),
    ("missing-identity", "authentication"), ("expired", "authentication"),
    ("not-yet-valid", "authentication"), ("wrong-role", "authentication"),
    ("untrusted", "authentication"), ("corrupt-signature", "authentication"),
)


class Invalid(Exception):
    """A bounded, value-free reference refusal."""


def require(condition, reason):
    if not condition:
        raise Invalid(reason)


def cases():
    result = []
    def add(family, side, argument, expected):
        result.append(dict(name=f"{family}-{side}-{argument}", family=family,
                           side=side, argument=str(argument), expected=expected))
    for name, expected in CERTIFICATE_CASES:
        add("certificate", "acceptor", name, expected)
    for side in ("connector", "acceptor"):
        for size in (0, 1, 19, 16347):
            add("records", side, size, "delivered")
        for operation in ("send", "receive"):
            add("limits", side, operation, "rfc6083_message_limit")
            add("deadline", side, operation, "rfc6083_deadline_exceeded")
            add("cancellation", side, "unpolled-" + operation, "active")
            add("cancellation", side, "polled-" + operation, "rfc6083_connection_closed")
        add("cancellation", side, "polled-close", "rfc6083_connection_closed")
        for change in ("replacement", "trust", "withdrawal"):
            add("retirement", side, change, "rfc6083_retired")
        for change in ("abort", "queued-abort"):
            add("carrier", side, change, "rfc6083_connection_closed")
        for operation, expected in (("reciprocal", "rfc6083_peer_closed"),
                                    ("silent", "rfc6083_deadline_exceeded"),
                                    ("pending", "rfc6083_transport_failed")):
            add("close", side, operation, expected)
        for stage in ("before", "after"):
            for fault in ("stream-one", "stream-max", "unordered", "payload-truncated",
                          "control-truncated", "notification"):
                add("metadata", side, stage + ":" + fault, "rfc6083_transport_failed")
            for ppid in (0, 47, 60):
                add("cleartext", side, stage + ":" + str(ppid), "rfc6083_cleartext_rejected")
    assert len(result) == 86 and len({row["name"] for row in result}) == 86
    return result


def check_sources():
    contract = (ROOT / CONTRACT).read_text().split(CONTRACT_END, 1)[0].encode()
    require(hashlib.sha256(contract).hexdigest() == CONTRACT_DIGEST, "dtls-contract-digest")
    certificates = (ROOT / CERTIFICATES).read_bytes()
    require(hashlib.sha256(certificates).hexdigest() == CERTIFICATE_DIGEST, "dtls-certificate-digest")
    rows = [line.split("\t") for line in certificates.decode().splitlines() if not line.startswith("#")]
    require(all(len(row) == 6 for row in rows), "dtls-certificate-width")
    require([(row[0], row[1]) for row in rows] == list(CERTIFICATE_CASES), "dtls-certificate-expectations")


def reference_bytes():
    value = dict(schema_version=1, scope=SCOPE, protected_ppid=66, ordered_stream=0,
        policy="Existing SDK bounded stream-zero profile; size/age/duplicate policy is not a standards mandate",
        contract=dict(path=CONTRACT, before=CONTRACT_END.strip(), sha256=CONTRACT_DIGEST),
        certificate_reference=dict(path=CERTIFICATES, sha256=CERTIFICATE_DIGEST),
        initial_auth_epoch=dict(initial_key_id=0, exporter_key_id=1, exporter_bytes=64,
            change_cipher_spec_key_id=0, finished_key_id=1, finished_dtls_epoch=1),
        limitations=["in-memory SCTP with real mutual DTLS", "separate Linux qualification",
            "no multistream or in-place rekey", "no CRL/OCSP or full 3GPP PKI", "no restart/multihoming guarantee"],
        cases=cases())
    return (json.dumps(value, indent=2) + "\n").encode()


def table_bytes():
    rows = ["# Independent SDK obligations; synthetic labels and lengths only.", "# " + "\t".join(COLUMNS)]
    rows += ["\t".join(str(row[column]) for column in COLUMNS) for row in cases() if row["family"] != "certificate"]
    return ("\n".join(rows) + "\n").encode()


def wire(family):
    require(family in FAMILIES, "dtls-reference-family")
    selected = [row for row in cases() if row["family"] == family]
    return (json.dumps(dict(family=family, cases=selected), sort_keys=True, separators=(",", ":")) + "\n").encode()


def validate(manifest, data):
    source = manifest["context"]["source_vector"]
    require(source["path"] == SOURCE and set(source) == {"path", "sha256", "case"}, "dtls-reference-path")
    require(source["sha256"] == hashlib.sha256(reference_bytes()).hexdigest(), "dtls-reference-digest")
    family = source["case"]
    require(family in FAMILIES and manifest["sdk_fixture_id"] == PREFIX + family, "dtls-reference-family")
    require(data == wire(family), "dtls-reference-wire")
    require(manifest["wire"]["digest_sha256"] == hashlib.sha256(data).hexdigest(), "dtls-wire-digest")
    count = sum(row["family"] == family for row in cases())
    context = dict(source_vector=source, schedules=count, sdk_transport_validation=True,
        carrier="in-memory-sctp", protected_ppid=66, ordered_stream=0, kernel_validation=False,
        in_place_rekey=False, revocation=False, external_interoperability=False)
    require(json.dumps(manifest["context"], sort_keys=True) == json.dumps(context, sort_keys=True), "dtls-reference-context")
    require(manifest["encoding"] == "scenario-record" and manifest["validation_scope"] == SCOPE, "dtls-reference-scope")
    require(manifest["source"] == dict(document="IETF RFC 6083", release="RFC 6083",
        clauses=["4.1", "4.3", "4.4", "4.5", "4.7", "4.8", "4.9", "SDK stream-zero lifecycle contract"]), "dtls-reference-authority")
    require(manifest["semantic_assertions"] == ["family=" + family, "schedules=" + str(count),
        "sdk_transport_validation=true", "carrier=in-memory-sctp", "protected_ppid=66", "ordered_stream=0",
        "kernel_validation=false", "in_place_rekey=false", "revocation=false", "external_interoperability=false"], "dtls-reference-claims")
    require(manifest["direction"] == "local-transport" and manifest["role"] == "dtls-sctp-endpoint", "dtls-reference-direction")
    require(manifest["provenance"]["referenced_public_vector"] == SOURCE + "#" + family
        and manifest["provenance"]["class"] == "referenced-public-vector"
        and manifest["provenance"]["synthetic"] is True
        and manifest["provenance"]["independent_capture"] is False, "dtls-reference-provenance")
    require(manifest["expected_outcome"] == "constructed" and manifest["runtime_claim"] is False, "dtls-reference-outcome")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        check_sources()
        for relative, data in ((SOURCE, reference_bytes()), (TABLE, table_bytes())):
            target = ROOT / relative
            require(not target.is_symlink(), "dtls-reference-path")
            if args.write:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            else:
                require(target.read_bytes() == data, "dtls-reference-content")
        if args.check:
            directory = ROOT / "crates/opc-n3iwf-fixtures/fixtures/n2-dtls"
            observed = set()
            for path in directory.glob("lifecycle-*.json"):
                require(not path.is_symlink(), "dtls-catalog-path")
                manifest = json.loads(path.read_text())
                require(manifest["wire"]["path"] == "wire/" + path.stem + ".hex", "dtls-catalog-path")
                payload = directory / manifest["wire"]["path"]
                require(not payload.is_symlink(), "dtls-catalog-path")
                validate(manifest, bytes.fromhex(payload.read_text()))
                require(manifest["sdk_fixture_id"] not in observed, "dtls-reference-duplicate")
                observed.add(manifest["sdk_fixture_id"])
            require(observed == {PREFIX + family for family in FAMILIES}, "dtls-reference-inventory")
    except (Invalid, OSError, ValueError, KeyError, TypeError, IndexError):
        print("n3iwf_dtls_reference_mismatch")
        return 1
    print(f"n3iwf_dtls_reference_valid: {len(cases())} independent schedules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
