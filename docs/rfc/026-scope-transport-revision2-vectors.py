#!/usr/bin/env python3
"""Independent RFC 026 revision-2 implementation vectors; Python standard library only.

This is a reference byte generator, not a production protocol/crypto library.
Scalar 1/2 and the exporter secret come from public synthetic revision-1
fixtures. No real credentials, TLS session or Rust codec are used.
"""
import argparse
import copy
import hashlib
import hmac
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
AUTH = HERE / "026-scope-authenticated-transport-vectors.json"
BATCH = HERE / "026-scope-authenticated-transport-batch-vectors.json"
OUTPUT = HERE / "026-scope-transport-revision2-vectors.json"
FRAME_CAP = 2 * 1024 * 1024 + 512
BODY_CAP = FRAME_CAP - 128 - 69
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = (
    0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
    0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
)


def sha(value):
    return hashlib.sha256(value).digest()


def unhex(value):
    return bytes.fromhex(value)


def uint(value, width):
    return value.to_bytes(width, "big")


def lp(value, width=2):
    return uint(len(value), width) + value


def varint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def point_add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x, y = left
    u, v = right
    if x == u:
        if (y + v) % P == 0:
            return None
        slope = (3 * x * x - 3) * pow(2 * y, -1, P) % P
    else:
        slope = (v - y) * pow(u - x, -1, P) % P
    nx = (slope * slope - x - u) % P
    return nx, (slope * (x - nx) - y) % P


def multiply(scalar, point=G):
    result = None
    while scalar:
        if scalar & 1:
            result = point_add(result, point)
        point = point_add(point, point)
        scalar >>= 1
    return result


def mac(key, value):
    return hmac.new(key, value, hashlib.sha256).digest()


def sign(value, scalar):
    """RFC6979 SHA-256 ECDSA, fixed r||s, low-S; public test scalars only."""
    digest = sha(value)
    seed = uint(scalar, 32) + uint(int.from_bytes(digest, "big") % N, 32)
    k, v = bytes(32), bytes([1]) * 32
    k = mac(k, v + b"\0" + seed)
    v = mac(k, v)
    k = mac(k, v + b"\1" + seed)
    v = mac(k, v)
    while True:
        v = mac(k, v)
        nonce = int.from_bytes(v, "big")
        if 1 <= nonce < N:
            r = multiply(nonce)[0] % N
            s = (pow(nonce, -1, N) * (int.from_bytes(digest, "big") + r * scalar)) % N
            if r and s:
                s = min(s, N - s)
                # Verify independently with the public point.
                inv = pow(s, -1, N)
                check = point_add(
                    multiply(int.from_bytes(digest, "big") * inv % N),
                    multiply(r * inv % N, multiply(scalar)),
                )
                assert check[0] % N == r
                return uint(r, 32) + uint(s, 32)
        k = mac(k, v + b"\0")
        v = mac(k, v)


def expand(secret, label, context):
    label = b"tls13 " + label
    info = uint(32, 2) + lp(label, 1) + lp(context, 1)
    return mac(secret, info + b"\1")  # one SHA-256 block


def exporters(source):
    result = copy.deepcopy(source["exporters"])
    for item in result:
        if item["alpn"] != "opc-scope/1":
            continue
        item["alpn"] = "opc-scope/2"
        context = b"".join(lp(item[key].encode()) for key in (
            "alpn", "purpose", "client_spiffe", "server_spiffe"
        ))
        context += lp(unhex(source["scope"]["installation_hex"]))
        context += lp(unhex(source["scope"]["transport_bytes_hex"]))
        context_hash = sha(context)
        secret = unhex(source["tls_reference"]["exporter_master_secret_hex"])
        derived = expand(secret, source["tls_reference"]["label"].encode(), sha(b""))
        item.update(
            context_bytes_hex=context.hex(), context_sha256=context_hash.hex(),
            tls_context_hash_hex=sha(context_hash).hex(), derived_secret_hex=derived.hex(),
            binding_hex=expand(derived, b"exporter", sha(context_hash)).hex(),
        )
    return result


def header(kind, method, request_id, digest, payload, scope, work_class=0, bucket=0):
    return (
        uint(124 + len(payload), 4) + uint(2, 2)
        + bytes([kind, work_class, bucket, method]) + bytes(2)
        + unhex(scope["installation_hex"]) + unhex(scope["scope_commitment_hex"])
        + request_id + digest + uint(len(payload), 4)
    )


def frame(name, kind, method, request_id, digest, payload, scope, work_class=0, bucket=0):
    fixed = header(kind, method, request_id, digest, payload, scope, work_class, bucket)
    assert len(fixed) == 128
    return dict(
        name=name, header_hex=fixed.hex(), payload_hex=payload.hex(),
        frame_hex=(fixed + payload).hex(), frame_length=len(fixed + payload),
        remaining_length=124 + len(payload), payload_length=len(payload),
        kind=kind, **{"class": work_class}, emergency_bucket=bucket, method=method,
    )


def reframe(old, scope, payload=None):
    fixed = unhex(old["header_hex"])
    return frame(
        old["name"], old["kind"], old["method"], fixed[76:92], fixed[92:124],
        unhex(old["payload_hex"]) if payload is None else payload,
        scope, old["class"], old["emergency_bucket"],
    )


def rebound(old, old_header, new_header, binding):
    raw = unhex(old["input_hex"])
    assert raw.count(old_header) == 1
    return raw.replace(old_header, new_header)[:-32] + binding


def response_binding(fixed, nonce, status, body, binding, own=bytes(32)):
    raw = (
        b"openpacketcore/scope/response-binding/v1\0" + uint(1, 2) + b"\1"
        + fixed + nonce + bytes([status]) + own + sha(body) + binding
    )
    return dict(input_hex=raw.hex(), digest_hex=sha(raw).hex())


def generate():
    source = json.loads(AUTH.read_text())
    batches = json.loads(BATCH.read_text())
    revised = copy.deepcopy(source)
    revised["transport_revision"] = 2
    revised["exporters"] = exporters(source)
    bindings = {item["purpose"]: unhex(item["binding_hex"]) for item in revised["exporters"]}
    # Validate the independent signer against every original scope proof.
    for proof in source["startup_proofs"]:
        assert sign(unhex(proof["input_hex"]), 1).hex() == proof["signature_hex"]
    assert sign(unhex(source["scope_possession"]["input_hex"]), 2).hex() == source["scope_possession"]["signature_hex"]
    for proof in revised["startup_proofs"]:
        raw = unhex(proof["input_hex"])[:-32] + bindings[proof["name"]]
        signature = sign(raw, 1)
        proof.update(input_hex=raw.hex(), input_sha256=sha(raw).hex(), signature_hex=signature.hex())
        proof["proof_body_hex"] = (
            lp(source["startup_credential"]["raw_ascii"].encode()) + lp(raw, 4) + signature
        ).hex()

    old_frames = {item["name"]: item for item in source["frames"]}
    revised["frames"] = [reframe(item, source["scope"]) for item in source["frames"]]
    new_frames = {item["name"]: item for item in revised["frames"]}
    name = "succession_call"
    raw = rebound(
        source["scope_possession"], unhex(old_frames[name]["header_hex"]),
        unhex(new_frames[name]["header_hex"]), bindings["scope-request"],
    )
    signature = sign(raw, 2)
    revised["scope_possession"].update(
        input_hex=raw.hex(), input_sha256=sha(raw).hex(), signature_hex=signature.hex()
    )
    proof_frame = reframe(old_frames["succession_proof"], source["scope"], lp(raw, 4) + signature)
    revised["frames"] = [proof_frame if item["name"] == proof_frame["name"] else item for item in revised["frames"]]
    name = "succession_committed_result"
    raw = rebound(
        source["response_binding"], unhex(old_frames[name]["header_hex"]),
        unhex(new_frames[name]["header_hex"]), bindings["scope-response"],
    )
    revised["response_binding"].update(input_hex=raw.hex(), digest_hex=sha(raw).hex())
    candidate_signature = unhex(revised["startup_proofs"][1]["signature_hex"])
    revised["negative_vectors"][0]["signature_hex"] = (
        candidate_signature[:32] + uint(N - int.from_bytes(candidate_signature[32:], "big"), 32)
    ).hex()

    # Startup framing and notices were implicit in the old JSON. Pin them now.
    revised["startup_frames"] = []
    candidate_request = None
    for request, proof in zip(source["startup_requests"], revised["startup_proofs"]):
        request_id, digest = unhex(request["request_id_hex"]), unhex(request["digest_hex"])
        revised["startup_frames"].append(frame(
            proof["name"] + "_call", 1, proof["method"], request_id, digest,
            unhex(source["caller_nonce_hex"]) + lp(unhex(request["canonical_request_hex"]), 4),
            source["scope"],
        ))
        revised["startup_frames"].append(frame(
            proof["name"] + "_proof", 3, proof["method"], request_id, digest,
            unhex(proof["proof_body_hex"]), source["scope"],
        ))
        if proof["method"] == 8:
            candidate_request = request
    revised["startup_frame_caller_nonce_hex"] = source["caller_nonce_hex"]
    revised["notice_frames"] = [
        frame(
            item.get("name", "ticket_notice"), 5, 8,
            unhex(candidate_request["request_id_hex"]), unhex(candidate_request["digest_hex"]),
            unhex(item["payload_hex"]), source["scope"],
        )
        for item in [source["ticket_notice"], *source["ticket_notice_refreshes"]]
    ]
    boot = source["executions"][0]
    revised["refusal_binding"] = dict(
        attempt_nonce_hex=source["caller_nonce_hex"],
        process_nonce_hex=boot["process_hex"],
        boot_key_digest_hex=boot["boot_key_digest_hex"],
    )
    revised["refusal_frames"] = [
        frame(
            "boot_refusal_" + reason, 6, 8,
            unhex(candidate_request["request_id_hex"]), unhex(candidate_request["digest_hex"]),
            unhex(source["caller_nonce_hex"]) + unhex(boot["process_hex"])
            + unhex(boot["boot_key_digest_hex"]) + bytes([code]), source["scope"],
        )
        for code, reason in [(1, "platform_invalid"), (2, "platform_changed"), (3, "prerequisite_refused")]
    ]

    revised_batch = copy.deepcopy(batches)
    revised_batch["transport_revision"] = 2
    for item in revised_batch["methods"]:
        for prefix, kind in [("call", 1), ("result", 4)]:
            old = unhex(item[prefix + "_header_hex"])
            item[prefix + "_header_hex"] = header(
                kind, item["method"], old[76:92], old[92:124],
                unhex(item[prefix + "_payload_hex"]), source["scope"],
                old[7], old[8],
            ).hex()
        payload = unhex(item["result_payload_hex"])
        item["response_binding"] = response_binding(
            unhex(item["result_header_hex"]), payload[:32], payload[32],
            payload[69:], bindings["scope-response"], payload[33:65],
        )

    stamp = unhex(batches["inputs"]["stamp_hex"])
    namespace = unhex(source["scope"]["postcard_bytes_hex"]) + varint(1)
    keys = [bytes([0x71]) * 32, bytes([0x72]) * 32]
    request_id, nonce, challenge = bytes([0x73]) * 16, bytes([0x74]) * 32, bytes([0x75]) * 32
    request = lp(stamp) + bytes([len(keys)]) + b"".join(keys)
    digest_input = b"openpacketcore/scope/child-read/v1\0" + b"\x11" + request_id + request
    digest = sha(digest_input)
    call = frame("child_read_call", 1, 17, request_id, digest, nonce + lp(request, 4), source["scope"], 2)
    challenge_frame = frame("child_read_challenge", 2, 17, request_id, digest, challenge, source["scope"], 2)
    initial = source["executions"][0]
    possession = (
        b"openpacketcore/scope/process-possession/v1\0" + uint(1, 2) + b"\0"
        + unhex(call["header_hex"]) + nonce + unhex(initial["execution_digest_hex"])
        + unhex(initial["public_key_hex"]) + b"\0" + challenge + bindings["scope-request"]
    )
    signature = sign(possession, 1)
    proof_frame = frame("child_read_proof", 3, 17, request_id, digest, lp(possession, 4) + signature, source["scope"], 2)

    # Shape-valid RFC003 envelope with synthetic unauthenticated ciphertext.
    envelope = b"OPCE" + uint(1, 2) + uint(1, 2) + uint(7, 2) + uint(12, 2) + uint(0, 4)
    envelope += b"fixture" + bytes([0x76]) * 12 + bytes([0x77]) * 16
    def record(key, ns=namespace, birth=b"\1", generation=b"\2", revision=b"\3"):
        claims = [bytes([key[0] + 7]) * 32]
        return ns + key + birth + generation + revision + b"\1" + varint(len(envelope)) + envelope + varint(len(claims)) + b"".join(claims)

    records = [record(key) for key in keys]

    def observation(values, ns=namespace, echo_keys=keys):
        return b"\0" + lp(ns) + bytes([len(values)]) + b"".join(
            key + (b"\0" if value is None else b"\1" + lp(value, 4))
            for key, value in zip(echo_keys, values)
        )

    def result(name, body, expected, status=7):
        payload = nonce + bytes([status]) + bytes(32) + lp(body, 4)
        item = frame(name, 4, 17, request_id, digest, payload, source["scope"], 2)
        item.update(body_hex=body.hex(), expected=expected)
        item["response_binding"] = response_binding(
            unhex(item["header_hex"]), nonce, status, body, bindings["scope-response"]
        )
        return item

    positives = [
        result("all_present", observation(records), "two_present_records"),
        result("all_missing", observation([None, None]), "two_absent_entries"),
        result("mixed", observation([records[0], None]), "present_then_absent"),
        result("too_large", b"\1", "ObservationTooLarge"),
    ]
    missing = observation([None, None])
    prefix_length = 1 + 2 + len(namespace) + 1
    wrong_namespace = namespace[:-1] + b"\2"
    negatives = [
        result("echo_namespace", observation(records, ns=wrong_namespace), "Batch(Unavailable)"),
        result("echo_key_order", observation(records, echo_keys=list(reversed(keys))), "Batch(Unavailable)"),
        result("record_namespace", observation([record(keys[0], ns=wrong_namespace), None]), "Batch(Unavailable)"),
        result("record_key", observation([records[1], None]), "Batch(Unavailable)"),
        result("noncanonical_birth", observation([record(keys[0], birth=b"\x81\0"), None]), "Batch(Unavailable)"),
        result("zero_generation", observation([record(keys[0], generation=b"\0"), None]), "Batch(Unavailable)"),
        result("zero_batch_revision", observation([record(keys[0], revision=b"\0"), None]), "Batch(Unavailable)"),
        result("trailing_record_byte", observation([records[0] + b"\0", None]), "Batch(Unavailable)"),
        result("unknown_kind", b"\2", "Batch(Unavailable)"),
        result("unknown_presence", missing[:prefix_length + 32] + b"\2" + missing[prefix_length + 33:], "Batch(Unavailable)"),
        result("wrong_count", missing[:prefix_length - 1] + b"\1" + missing[prefix_length:], "Batch(Unavailable)"),
        result("too_large_with_entries", b"\1" + missing, "Batch(Unavailable)"),
        result("oversized_record_declaration", missing[:prefix_length] + keys[0] + b"\1" + uint(1024 * 1024 + 8193, 4), "Batch(Unavailable)"),
    ]
    oversized_header = bytearray(unhex(positives[0]["header_hex"]))
    oversized_header[:4] = uint(FRAME_CAP - 4 + 1, 4)
    oversized_header[124:] = uint(FRAME_CAP - 128 + 1, 4)
    negatives.append(dict(name="oversized_frame_prefix", header_hex=oversized_header.hex(), expected="Batch(Unavailable); reject before payload allocation"))
    version_one = bytearray(unhex(call["header_hex"]))
    version_one[4:6] = uint(1, 2)
    negatives.append(dict(name="revision_1_on_revision_2", header_hex=version_one.hex(), expected="TransportRevisionMismatch"))
    invalid_requests = []
    for name, data in [
        ("zero_count", lp(stamp) + b"\0"),
        ("count_33", lp(stamp) + b"\x21"),
        ("duplicate_keys", lp(stamp) + b"\2" + keys[0] * 2),
        ("zero_key", lp(stamp) + b"\1" + bytes(32)),
    ]:
        raw = b"openpacketcore/scope/child-read/v1\0" + b"\x11" + request_id + data
        invalid_requests.append(dict(name=name, request_hex=data.hex(), digest_hex=sha(raw).hex(), expected="Batch(InvalidRequest)"))

    # Existing immutable/stored inputs and non-scope bindings did not change.
    for key in [
        "scope", "executions", "authority_requests", "closure_fixture_digests",
        "startup_observation", "startup_credential", "local_contexts", "management_proofs",
        "closure_evidence", "read_requests", "startup_requests", "result_bodies",
        "ticket_notice", "ticket_notice_refreshes",
    ]:
        assert revised[key] == source[key], key
    for old, new in zip(source["exporters"], revised["exporters"]):
        if old["alpn"] != "opc-scope/1":
            assert old == new
    for old, new in zip(batches["methods"], revised_batch["methods"]):
        for key in ["canonical_hex", "digest_hex", "call_payload_hex", "result_body_hex", "result_payload_hex"]:
            assert old[key] == new[key], key
    for item in positives + [item for item in negatives if "frame_hex" in item]:
        assert item["frame_length"] <= FRAME_CAP
    return dict(
        format="rfc026-transport-revision-2-vectors",
        notice="Implementation fixtures with synthetic public inputs and unauthenticated envelope ciphertext; not credentials, a real TLS transcript, or runtime qualification.",
        sources={path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in [AUTH, BATCH]},
        authority_startup=revised, batch=revised_batch,
        child_read=dict(
            frame_cap=FRAME_CAP, result_body_cap=BODY_CAP, count_limit=32,
            request_id_hex=request_id.hex(), stamp_hex=stamp.hex(), namespace_hex=namespace.hex(),
            keys_hex=[key.hex() for key in keys], request_hex=request.hex(),
            digest_input_hex=digest_input.hex(), digest_hex=digest.hex(),
            envelope_hex=envelope.hex(), record_hex=[value.hex() for value in records],
            possession_input_hex=possession.hex(), possession_signature_hex=signature.hex(),
            frames=[call, challenge_frame, proof_frame], results=positives,
            negative_responses=negatives, negative_requests=invalid_requests,
        ),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare generated bytes without changing files")
    args = parser.parse_args()
    encoded = json.dumps(generate(), indent=2) + "\n"
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != encoded:
            raise SystemExit("revision-2 implementation vectors differ")
        print("revision-2 implementation vectors match")
    else:
        OUTPUT.write_text(encoded)
        print("wrote " + OUTPUT.name)


if __name__ == "__main__":
    main()
