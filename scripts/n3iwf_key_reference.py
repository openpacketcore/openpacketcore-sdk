#!/usr/bin/env python3
"""Independent synthetic IKE AUTH answers; no SDK or fixture-writer imports.

Only this one declared SHA-256/AES-GCM-256/P-256 profile is admitted. Public
test scalars, nonces, identities and the zero NGAP placeholder never come
from a subscriber or peer. This is evidence tooling, not a custody API.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "crates/opc-n3iwf-fixtures/fixtures"
REFERENCE = ROOT / "crates/opc-n3iwf-fixtures/oracles/ike-auth-sha256.json"
PROFILE = "prf-hmac-sha256-aes-gcm16-256-ecp256"
SCOPE = "ike-auth-known-answer"
KEY_LENGTHS = dict(sk_d=32, sk_ai=0, sk_ar=0, sk_ei=36, sk_er=36, sk_pi=32, sk_pr=32)
INPUT_FIELDS = {
    "initiator_spi",
    "responder_spi",
    "initiator_nonce",
    "responder_nonce",
    "dh_shared",
    "signing_peer",
    "ike_sa_init_message",
    "peer_nonce",
    "identity_payload_body",
    "auth_keying_material",
}


class Invalid(ValueError):
    """Constant diagnostic codes, with no input or subprocess rendering."""


def require(condition, code):
    if not condition:
        raise Invalid(code)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate-json-key")
        result[key] = value
    return result


def read_bounded(path, limit):
    require(path.is_file() and not path.is_symlink(), "reference-file")
    with path.open("rb") as source:
        data = source.read(limit + 1)
    require(len(data) <= limit, "reference-size")
    return data


def read_json(path):
    return json.loads(read_bounded(path, 256 * 1024), object_pairs_hook=unique_pairs)


def octets(text, exact=None, limit=4096):
    require(isinstance(text, str) and len(text) <= 2 * limit, "hex-bound")
    require(len(text) % 2 == 0 and re.fullmatch("[0-9a-f]*", text) is not None, "hex")
    data = bytes.fromhex(text)
    require(exact is None or len(data) == exact, "input-length")
    return data


def answer_octets(values, exact):
    """Known answers use explicit JSON octets, including empty AEAD auth keys."""
    require(isinstance(values, list) and len(values) == exact, "answer-length")
    require(
        all(type(value) is int and 0 <= value <= 255 for value in values),
        "answer-octet",
    )
    return bytes(values)


def prf(key, data):
    return hmac.digest(key, data, "sha256")


def derive(inputs):
    """RFC 7296 2.13/2.14; GCM key material includes a four-octet salt."""
    ni = octets(inputs["initiator_nonce"], 32)
    nr = octets(inputs["responder_nonce"], 32)
    seed = (
        ni
        + nr
        + octets(inputs["initiator_spi"], 8)
        + octets(inputs["responder_spi"], 8)
    )
    skeyseed = prf(ni + nr, octets(inputs["dh_shared"], 32))
    stream, previous = b"", b""
    for counter in range(1, 1 + (sum(KEY_LENGTHS.values()) + 31) // 32):
        previous = prf(skeyseed, previous + seed + bytes([counter]))
        stream += previous
    result = {"skeyseed": skeyseed}
    for name, length in KEY_LENGTHS.items():
        result[name], stream = stream[:length], stream[length:]
    return result


def auth(inputs):
    require(set(inputs) == INPUT_FIELDS, "input-fields")
    require(inputs["signing_peer"] in ("initiator", "responder"), "signing-peer")
    key = octets(inputs["auth_keying_material"], limit=32)
    require(bool(key), "authentication-key-empty")
    require(len(key) == 32, "profile-key-length")
    keys = derive(inputs)
    message = octets(inputs["ike_sa_init_message"])
    identity = octets(inputs["identity_payload_body"], limit=256)
    require(len(message) >= 28 and len(identity) >= 4, "transcript-length")
    nonce = octets(inputs["peer_nonce"], 32)
    sk_p = keys["sk_pi" if inputs["signing_peer"] == "initiator" else "sk_pr"]
    signed = message + nonce + prf(sk_p, identity)
    return prf(prf(key, b"Key Pad for IKEv2"), signed)


def observe(data, context):
    try:
        require(len(data) >= 4, "authentication-too-short")
        require(data[0] == 2, "unsupported-authentication-method")
        # AUTH reserved bytes are receiver-ignored. ID reserved bytes, by
        # contrast, are included in the signed transcript exactly as received.
        expected = auth(context["inputs"])
        require(len(data[4:]) == 32, "authentication-data-length")
        require(hmac.compare_digest(expected, data[4:]), "authentication-failed")
        return "accept", None
    except Invalid as error:
        return "reject", str(error)


def validate(manifest, data):
    require(bool(data), "authentication-too-short")
    require(manifest["validation_scope"] == SCOPE, "published-scope")
    require(manifest["runtime_claim"] is False, "runtime-claim")
    require(manifest["encoding"] == "protocol-wire", "published-encoding")
    require(manifest["context"]["crypto_profile"] == PROFILE, "published-profile")
    require(manifest["context"]["sdk_custody_validation"] is False, "custody-claim")
    require(
        manifest["semantic_assertions"]
        == [f"AUTH_method={data[0]}", "PRF=HMAC-SHA256", "custody_validation=false"],
        "published-assertions",
    )
    outcome, reason = observe(data, manifest["context"])
    require(
        manifest["expected_outcome"] == ("receive" if reason is None else "reject"),
        "published-outcome",
    )
    expected = "accept" if manifest["expected_outcome"] == "receive" else "reject"
    require(outcome == expected, "outcome-mismatch")
    require(reason == manifest["context"]["reference_error"], "reason-mismatch")


def sa_init(inputs, public, initiator):
    """Independently assemble the declared RFC 7296 3.3 proposal and chain."""
    transforms = b""
    for more, kind, value, attrs in [
        (3, 1, 20, struct.pack("!HH", 0x800E, 256)),
        (3, 2, 5, b""),
        (0, 4, 19, b""),
    ]:
        transforms += (
            struct.pack("!BBHBBH", more, 0, 8 + len(attrs), kind, 0, value) + attrs
        )
    proposal = (
        struct.pack("!BBHBBBB", 0, 0, 8 + len(transforms), 1, 1, 0, 3) + transforms
    )
    nonce = octets(inputs["initiator_nonce" if initiator else "responder_nonce"], 32)
    body = b""
    for next_payload, content in [
        (34, proposal),
        (40, struct.pack("!HH", 19, 0) + public),
        (0, nonce),
    ]:
        body += struct.pack("!BBH", next_payload, 0, 4 + len(content)) + content
    return (
        struct.pack(
            "!8s8sBBBBII",
            octets(inputs["initiator_spi"], 8),
            bytes(8) if initiator else octets(inputs["responder_spi"], 8),
            33,
            0x20,
            34,
            8 if initiator else 0x20,
            0,
            28 + len(body),
        )
        + body
    )


def check_test_dh(corpus, common):
    """Reproduce the public synthetic scalar-1/scalar-2 inputs with OpenSSL."""
    with tempfile.TemporaryDirectory(prefix="n3iwf-public-test-scalars-") as directory:
        root = Path(directory)

        def openssl(*args):
            return subprocess.run(
                ["openssl", *args],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=10,
            ).stdout

        for peer, scalar in [("initiator", 1), ("responder", 2)]:
            key = root / (peer + ".der")
            key.write_bytes(
                bytes.fromhex("30310201010420")
                + scalar.to_bytes(32, "big")
                + bytes.fromhex("a00a06082a8648ce3d030107")
            )
            public = openssl(
                "pkey", "-inform", "DER", "-in", str(key), "-pubout", "-outform", "DER"
            )
            (root / (peer + "-public.der")).write_bytes(public)
            require(
                public[-65:] == b"\x04" + octets(corpus["public_values"][peer], 64),
                "public-test-point",
            )
        for peer, other in [("initiator", "responder"), ("responder", "initiator")]:
            shared = openssl(
                "pkeyutl",
                "-derive",
                "-keyform",
                "DER",
                "-inkey",
                str(root / (peer + ".der")),
                "-peerform",
                "DER",
                "-peerkey",
                str(root / (other + "-public.der")),
            )
            require(shared == octets(common["dh_shared"], 32), "public-test-agreement")
    return subprocess.run(
        ["openssl", "version"], check=True, capture_output=True, text=True, timeout=10
    ).stdout.strip()


def check_mutations(positives):
    counts = dict(
        mic_bits=0,
        key_bits=0,
        transcript_octets=0,
        identity_octets=0,
        nonce_octets=0,
        truncated_prefixes=0,
    )
    for case in positives:
        data = octets(case["wire_hex"])
        context = {"inputs": case["inputs"]}
        for index in range(32):
            for bit in range(8):
                changed = bytearray(data)
                changed[4 + index] ^= 1 << bit
                require(
                    observe(changed, context) == ("reject", "authentication-failed"),
                    "mic-mutation",
                )
                counts["mic_bits"] += 1
        for name, count_name in [
            ("auth_keying_material", "key_bits"),
            ("ike_sa_init_message", "transcript_octets"),
            ("identity_payload_body", "identity_octets"),
            ("peer_nonce", "nonce_octets"),
        ]:
            original = octets(case["inputs"][name])
            for index in range(len(original)):
                for bit in range(8 if name == "auth_keying_material" else 1):
                    changed = copy.deepcopy(context)
                    value = bytearray(original)
                    value[index] ^= 1 << bit
                    changed["inputs"][name] = value.hex()
                    require(
                        observe(data, changed) == ("reject", "authentication-failed"),
                        "input-mutation",
                    )
                    counts[count_name] += 1
        for size in range(len(data)):
            require(observe(data[:size], context)[0] == "reject", "truncation-mutation")
            counts["truncated_prefixes"] += 1
    return counts


def check_case_recipes(corpus):
    """A rejection is not provenance: even negative input bytes are constrained."""
    positives = {
        case["auth_peer"]: case
        for case in corpus["cases"]
        if case["case_class"] == "positive"
    }
    require(set(positives) == {"initiator", "responder"}, "recipe-peers")

    def flip(text, offset=0):
        data = bytearray(octets(text))
        data[offset] ^= 1
        return data.hex()

    for case in corpus["cases"]:
        peer = case["auth_peer"]
        require(peer in positives, "recipe-peer")
        prefix = "auth-" + peer + "-"
        require(case["name"].startswith(prefix), "recipe-name")
        name = case["name"][len(prefix) :]
        inputs = copy.deepcopy(positives[peer]["inputs"])
        data = octets(positives[peer]["wire_hex"])
        if name == "wrong-key":
            inputs["auth_keying_material"] = flip(inputs["auth_keying_material"])
        elif name == "empty-key":
            inputs["auth_keying_material"] = ""
        elif name in ("changed-transcript", "changed-spi"):
            inputs["ike_sa_init_message"] = flip(
                inputs["ike_sa_init_message"], -1 if name == "changed-transcript" else 0
            )
        elif name == "wrong-peer-nonce":
            inputs["peer_nonce"] = inputs[
                "initiator_nonce" if peer == "initiator" else "responder_nonce"
            ]
        elif name in ("changed-identity", "changed-id-reserved"):
            inputs["identity_payload_body"] = flip(
                inputs["identity_payload_body"], -1 if name == "changed-identity" else 1
            )
        elif name == "wrong-direction-key":
            inputs["signing_peer"] = "responder" if peer == "initiator" else "initiator"
        elif name == "changed-dh-input":
            inputs["dh_shared"] = flip(inputs["dh_shared"])
        elif name == "changed-mic":
            data = octets(flip(data.hex(), 4))
        elif name == "short-mic":
            data = data[:-1]
        elif name == "short-header":
            data = data[:3]
        elif name == "unsupported-method":
            data = b"\x03" + data[1:]
        elif name == "auth-reserved":
            data = b"\x02\x80\x40\x20" + data[4:]
        else:
            require(name == "known-answer", "recipe-case")
        require(
            case["inputs"] == inputs and octets(case["wire_hex"]) == data,
            "synthetic-case-recipe",
        )
    for positive in positives.values():
        inputs = positive["inputs"]
        for field, value in {
            "initiator_spi": bytes(range(1, 9)),
            "responder_spi": bytes(range(17, 25)),
            "initiator_nonce": bytes(range(1, 33)),
            "responder_nonce": bytes(range(33, 65)),
        }.items():
            require(octets(inputs[field]) == value, "synthetic-base-recipe")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        # Published RFC 4231 4.2 answer checks the independent HMAC primitive.
        require(
            prf(b"\x0b" * 20, b"Hi There").hex()
            == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            "rfc4231-answer",
        )
        corpus = read_json(REFERENCE)
        require(
            corpus["schema_version"] == 1
            and corpus["profile"] == PROFILE
            and corpus["runtime_claim"] is False,
            "corpus-profile",
        )
        names, positives = set(), []
        require(
            isinstance(corpus["cases"], list) and len(corpus["cases"]) == 30,
            "case-bound",
        )
        check_case_recipes(corpus)
        for case in corpus["cases"]:
            name = case["name"]
            require(
                isinstance(name, str)
                and re.fullmatch(r"auth-(?:initiator|responder)-[a-z0-9-]{1,60}", name)
                is not None
                and name not in names,
                "case-name",
            )
            names.add(name)
            data = octets(case["wire_hex"])
            require(
                hashlib.sha256(data).hexdigest() == case["wire_sha256"],
                "reference-digest",
            )
            manifest = read_json(FIXTURES / "protocol-key" / (name + ".json"))
            require(
                manifest["context"]
                == dict(
                    inputs=case["inputs"],
                    auth_peer=case["auth_peer"],
                    reference_error=case["reference_error"],
                    crypto_profile=PROFILE,
                    sdk_custody_validation=False,
                ),
                "published-inputs",
            )
            require(
                manifest["case_class"] == case["case_class"], "published-case-class"
            )
            published = bytes.fromhex(
                read_bounded(
                    FIXTURES / "protocol-key/wire" / (name + ".hex"), 4096
                ).decode("ascii")
            )
            require(
                published == data
                and manifest["wire"]["digest_sha256"] == case["wire_sha256"],
                "published-wire",
            )
            validate(manifest, data)
            if case["case_class"] == "positive":
                positives.append(case)
        require(
            len(positives) == 2
            and {c["auth_peer"] for c in positives} == {"initiator", "responder"}
            and len(names) == 30,
            "case-coverage",
        )
        published_names = set()
        for path in (FIXTURES / "protocol-key").glob("*.json"):
            if path.name != "COMPLETION.json":
                item = read_json(path)
                require(
                    item["validation_scope"] in (SCOPE, "handle-lifecycle-contract"),
                    "unknown-key-scope",
                )
                if item["validation_scope"] == SCOPE:
                    published_names.add(item["sdk_fixture_id"].split(".v1.")[1])
        require(names == published_names, "corpus-inventory")
        require(
            isinstance(corpus["expected_octets"], dict)
            and set(corpus["expected_octets"])
            == {"skeyseed", "auth_initiator", "auth_responder", *KEY_LENGTHS},
            "answer-fields",
        )
        for case in positives:
            inputs, peer = case["inputs"], case["auth_peer"]
            require(inputs["signing_peer"] == peer, "positive-role")
            for name, value in derive(inputs).items():
                require(
                    value == answer_octets(corpus["expected_octets"][name], len(value)),
                    "derived-known-answer",
                )
            require(
                b"\x02\0\0\0" + auth(inputs)
                == answer_octets(corpus["expected_octets"]["auth_" + peer], 36)
                == octets(case["wire_hex"]),
                "auth-known-answer",
            )
            require(
                octets(inputs["ike_sa_init_message"])
                == sa_init(
                    inputs,
                    octets(corpus["public_values"][peer], 64),
                    peer == "initiator",
                ),
                "sa-init-recipe",
            )
            require(
                inputs["peer_nonce"]
                == inputs[
                    "responder_nonce" if peer == "initiator" else "initiator_nonce"
                ],
                "positive-nonce-role",
            )
            identity = octets(inputs["identity_payload_body"])
            require(
                identity
                == (
                    b"\x0b\0\0\0" + bytes(range(0x80, 0x90))
                    if peer == "initiator"
                    else b"\x02\0\0\0n3iwf.example"
                ),
                "synthetic-identity",
            )
            require(
                octets(inputs["auth_keying_material"]) == bytes(32), "ngap-placeholder"
            )
        version = check_test_dh(corpus, positives[0]["inputs"])
        report = dict(
            result="pass",
            profile=PROFILE,
            reference_sha256=hashlib.sha256(
                read_bounded(REFERENCE, 256 * 1024)
            ).hexdigest(),
            cases=len(names),
            positive_peers=2,
            rfc4231_answers=1,
            openssl=version,
            mutations=check_mutations(positives),
            runtime_claim=False,
        )
        if args.report:
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, sort_keys=True))
        return 0
    except Invalid as error:
        print(f"n3iwf_key_reference_failed: {error}", file=sys.stderr)
    except Exception:
        print("n3iwf_key_reference_failed", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
