#!/usr/bin/env python3
"""Independent, value-free projections of the bounded RFC 6083 evidence.

This model imports neither the catalog writer nor an SDK transport. Vector
projections retain source row numbers and expectations, never keys, certificate
blobs, encrypted records or endpoint names. Authored lifecycle obligations name
separately qualified runtime tests; loading a reference does not execute them.
"""

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "crates/opc-n3iwf-fixtures/oracles/dtls-profiles.json"
SCOPE = "rfc6083-profile-evidence-reference"
PREFIX = "opc.n3iwf.n2-dtls.v1.profile-"
TABLE_ROOT = "crates/opc-diameter-transport/tests/fixtures/rfc6083/"
VENDOR_ROOT = "vendor/dimpl/tests/dtls12/"
TEST_ROOT = "crates/opc-diameter-transport/src/dtls_tests/generic/"
VECTORS = {
    "certificate-profile": (TABLE_ROOT + "nds_certificates.tsv", "1a9968c0889344ec64f8ef30d2ff1d3f2ec50c60ed13a98c3cb1856795ea6f09", 146, 8),
    "crl-profile": (TABLE_ROOT + "revocation.tsv", "52869f0cb4242bce8d2e49d06b63042637a8536b49cdc0a636537dbb247a8f2c", 52, 8),
    "stream-framing": (TABLE_ROOT + "streams.tsv", "9d6bf635d944770d97d6577691cf9a5cbebf4287c015dbfad87f085f9a9b7369", 18560, 10),
    "rekey-binding": (VENDOR_ROOT + "rfc5746_binding_reference.tsv", "5fd96cca2217123dbe4e9157761366882785557f18b1125ca6bdad27260f5d1e", 100, 5),
    "rekey-hello": (VENDOR_ROOT + "rfc5746_hello_reference.tsv", "c309c45f83cf4c442de014e29ad3049c10998daa1883866f5f6549a01b527ab0", 13, 4),
    "server-name": (VENDOR_ROOT + "rfc6066_reference.tsv", "987802915ffc4be74421a2c770f1d17253e1cc8a2db9699710e3741ba2a10517", 109, 6),
}
LIFECYCLES = {
    "coordinated-rekey": (
        "rekey.rs",
        "2aa4a2c17b9acf361532bd86eda3473865d8a96c516f876ea05623676d0f9e8a", [
        "coordinated_rekey_preserves_queued_streams_and_rotates_each_auth_boundary",
        "rekey_requires_opt_in_and_cancellation_closes_the_association",
        "rekey_never_renews_the_absolute_association_lifetime",
        "credential_withdrawal_interrupts_a_pending_rekey_in_both_roles",
    ]),
    "publication-retirement": ("revocation.rs", "8020ee31dd384d6c76d5227bc31d116219691ec95e98ac2dd392f21742c8753a", [
        "publication_changes_retire_readback_and_queued_delivery_synchronously",
        "withdrawn_crls_interrupt_an_in_place_rekey_in_both_roles",
    ]),
    "native-path-loss": ("paths.rs", "ced2020f9bb5748cd32ed54be61d4174cfaddd8db1aa1747a1e1cd70f14d05ea", [
        "generic_kernel_multihoming_preserves_protection_and_bounds_total_path_loss",
    ]),
    "native-process-restart": ("restart.rs", "9c0c8d95612550b06ce6017e3c998d465a7afb42f477b9a9f8441215007e342c", [
        "generic_kernel_process_restart_requires_fresh_mutual_authentication",
    ]),
}
FAMILIES = tuple(sorted(VECTORS | LIFECYCLES))


class Invalid(Exception):
    """A bounded, value-free reference refusal."""


def require(condition, reason):
    if not condition:
        raise Invalid(reason)


def read_pinned(path, digest):
    target = ROOT / path
    require(not target.is_symlink(), "dtls-profile-source-path")
    raw = target.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == digest, "dtls-profile-source-digest")
    return raw.decode()


def projected_vectors(family):
    path, digest, count, width = VECTORS[family]
    rows = [line.split("\t") for line in read_pinned(path, digest).splitlines()
            if line and not line.startswith("#")]
    require(len(rows) == count and all(len(row) == width for row in rows), "dtls-profile-source-shape")
    result = []
    for index, row in enumerate(rows, 1):
        value = dict(row=index)
        if family in ("certificate-profile", "crl-profile"):
            value.update(role=row[0], case=row[1], expected=row[2])
        elif family == "stream-framing":
            # Every admitted shape plus a fixed negative cross section. The
            # full 18,560-row source remains digest-bound and checked separately.
            count, ppid, stream, order, fault, kind, epoch, shape, version, expected = row
            if expected != "framing-admitted" and not (
                count == "2" and stream in ("0", "1", "65535")
                and kind == "23" and epoch == "1"
                and ((ppid == "66" and order == "ordered")
                     or (fault == "none" and shape == "complete"))
            ):
                continue
            value.update(zip(("stream_count", "ppid", "stream", "order", "fault", "record_type",
                              "epoch", "shape", "version", "expected"), row))
        elif family == "rekey-binding":
            value.update(role=row[0], phase=row[1], scsv=row[2] == "1", expected="admit" if row[4] == "1" else "reject")
        elif family == "rekey-hello":
            value.update(role=row[0], case=row[1], expected="admit" if row[2] == "1" else "reject")
        else:
            value.update(role=row[0], configured=row[1] != "-", case=row[2], expected="admit" if row[3] == "1" else "reject")
        result.append(value)
    return dict(kind="independent-vector-projection", reference=dict(path=path, sha256=digest,
                corpus_cases=len(rows)), cases=result)


def lifecycle(family):
    name, digest, functions = LIFECYCLES[family]
    path = TEST_ROOT + name
    source = read_pinned(path, digest)
    require(all(source.count("fn " + name + "(") == 1 for name in functions), "dtls-profile-test-inventory")
    cases = []
    def add(role, name, steps, expected):
        cases.append(dict(role=role, case=name, steps=steps.split(","), expected=expected))
    for role in ("connector", "acceptor"):
        if family == "coordinated-rekey":
            for cipher in ("aes128-gcm", "aes256-gcm", "chacha20-poly1305"):
                for epoch in (2, 3, 4):
                    add(role, f"{cipher}-epoch-{epoch}", "mutual-handshake,queue-streams-1-15-0,coordinate-rekey,receive-queued,send-stream-2",
                        "same-material-and-peer;old-key-ccs;new-key-finished;exact-queued-streams")
            if role == "connector":
                add(role, "no-opt-in", "mutual-handshake,attempt-rekey,readback-both-roles", "policy-rejected;both-connections-closed")
            add(role, "polled-cancellation", "mutual-handshake,poll-blocked-rekey,drop-rekey,readback-both-roles", "both-connections-closed")
            add(role, "original-lifetime", "mutual-handshake,advance-six-seconds,coordinate-rekey,advance-five-seconds,readback", "retired-at-original-ten-second-age")
            add(role, "credential-withdrawal", "mutual-handshake,poll-blocked-rekey,withdraw-credentials,await-rekey,readback-both-roles", "local-retired;peer-connection-closed")
        elif family == "publication-retirement":
            for action in ("replace", "identical", "withdraw", "drop", "malformed", "rollback", "credential"):
                add(role, action, "required-crls,queue-records,consume-one," + action + ",readback-without-yield,receive,send,republish",
                    "retired;no-further-delivery;no-revival")
            add(role, "withdraw-during-rekey", "required-crls,pending-rekey,withdraw", "retired;association-closed")
        elif family == "native-path-loss":
            for name, steps, expected in (
                ("non-data-control", "block-one-path,observe-no-ppid66-data", "does-not-qualify-protected-path-loss"),
                ("one-active-path", "mutual-handshake,block-active-destination,require-ppid66-data-drops,exchange-streams-0-1-2-15", "delivered;protection-readback-unchanged"),
                ("all-paths", "block-all-four-destinations,send-both-directions,require-ppid66-data-drops,absolute-receive-deadline", "no-plaintext;both-readbacks-terminal"),
                ("restored-paths", "remove-fault,old-send,old-receive,new-association,new-mutual-handshake,exchange,reciprocal-close", "old-connection-closed;new-delivery-and-close"),
            ):
                add(role, name, steps, expected)
        else:
            for name, steps, expected in (
                ("crash", "separate-peer-process,mutual-handshake,exchange,queue-record,sigkill,require-signal-9,observe-carrier-without-receive", "connection-closed;queued-record-not-delivered"),
                ("wrong-replacement", "new-pid,same-listener,valid-chain-wrong-exact-peer,new-mutual-handshake", "authentication-refused"),
                ("correct-replacement", "new-pid,same-listener,new-credentials-same-peer,new-mutual-handshake,exchange-new-generation,reciprocal-close", "new-delivery;old-readback-and-send-refused"),
            ):
                add(role, name, steps, expected)
    return dict(kind="authored-runtime-test-obligations", reference=dict(path=path, sha256=digest,
                functions=functions), cases=cases)


def reference():
    return dict(schema_version=1, scope=SCOPE, execution_claim=False, external_interoperability=False,
                families={name: projected_vectors(name) if name in VECTORS else lifecycle(name) for name in FAMILIES})


def reference_bytes():
    return (json.dumps(reference(), indent=2) + "\n").encode()


def wire(family):
    require(family in FAMILIES, "dtls-profile-family")
    value = reference()["families"][family]
    return (json.dumps(dict(family=family, **value), sort_keys=True, separators=(",", ":")) + "\n").encode()


def validate(manifest, data):
    source = manifest["context"]["source_vector"]
    require(set(source) == {"path", "sha256", "case"} and source["path"] == SOURCE, "dtls-profile-path")
    require(source["sha256"] == hashlib.sha256(reference_bytes()).hexdigest(), "dtls-profile-digest")
    family = source["case"]
    require(family in FAMILIES and manifest["sdk_fixture_id"] == PREFIX + family, "dtls-profile-family")
    require(data == wire(family), "dtls-profile-wire")
    require(manifest["wire"]["digest_sha256"] == hashlib.sha256(data).hexdigest(), "dtls-profile-wire-digest")
    value = reference()["families"][family]
    expected = dict(source_vector=source, cases=len(value["cases"]), evidence_kind=value["kind"],
                    execution_claim=False, requires_separate_runtime_qualification=True,
                    protected_ppid=66, external_interoperability=False)
    require(json.dumps(manifest["context"], sort_keys=True) == json.dumps(expected, sort_keys=True), "dtls-profile-context")
    require(manifest["encoding"] == "scenario-record" and manifest["validation_scope"] == SCOPE, "dtls-profile-scope")
    require(manifest["source"] == dict(document="IETF RFC 6083 and bounded SDK profile", release="RFC 6083",
            clauses=["4.1", "4.4", "4.5", "4.6", "4.7", "4.8", "4.9", "SDK evidence-reference contract"]), "dtls-profile-authority")
    require(manifest["semantic_assertions"] == ["family=" + family, "cases=" + str(len(value["cases"])),
            "execution_claim=false", "requires_separate_runtime_qualification=true", "external_interoperability=false"], "dtls-profile-claims")
    require(manifest["direction"] == "local-transport" and manifest["role"] == "dtls-sctp-endpoint", "dtls-profile-direction")
    provenance = manifest["provenance"]
    require(provenance["class"] == "referenced-public-vector" and provenance["synthetic"] is True
            and provenance["independent_capture"] is False and provenance["referenced_public_vector"] == SOURCE + "#" + family, "dtls-profile-provenance")
    require(manifest["expected_outcome"] == "constructed" and manifest["runtime_claim"] is False, "dtls-profile-outcome")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        target = ROOT / SOURCE
        require(not target.is_symlink(), "dtls-profile-path")
        if args.write:
            target.write_bytes(reference_bytes())
        else:
            require(target.read_bytes() == reference_bytes(), "dtls-profile-model")
            directory = ROOT / "crates/opc-n3iwf-fixtures/fixtures/n2-dtls"
            observed = set()
            for path in directory.glob("profile-*.json"):
                require(not path.is_symlink(), "dtls-profile-path")
                manifest = json.loads(path.read_text())
                require(manifest["wire"]["path"] == "wire/" + path.stem + ".hex", "dtls-profile-path")
                payload = directory / manifest["wire"]["path"]
                require(not payload.is_symlink(), "dtls-profile-path")
                validate(manifest, bytes.fromhex(payload.read_text()))
                require(manifest["sdk_fixture_id"] not in observed, "dtls-profile-duplicate")
                observed.add(manifest["sdk_fixture_id"])
            require(observed == {PREFIX + family for family in FAMILIES}, "dtls-profile-inventory")
    except (Invalid, OSError, ValueError, KeyError, TypeError, IndexError):
        print("n3iwf_dtls_profile_reference_mismatch")
        return 1
    print(f"n3iwf_dtls_profile_reference_valid: {len(FAMILIES)} bounded evidence families")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
