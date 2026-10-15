#!/usr/bin/env python3
"""Independent synthetic RFC 7296 initiator known-answer vector.

No SDK code, subprocess, or network access is used. Python hashlib/hmac implement
PRF/PRF+; cryptography's OpenSSL backend implements P-256 ECDH and AES-GCM.
Run --write to regenerate, --check to compare, or no argument to print JSON.
All values are public test material, never credentials or deployment keys.
"""

import argparse
import hashlib
import hmac
import json
import platform
import struct
from pathlib import Path

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PINNED = {
    "python": "3.14.6",
    "cryptography": "49.0.0",
    "openssl": "OpenSSL 3.5.7 9 Jun 2026",
}


def prf(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def prf_plus(key, data, length):
    result, previous = b"", b""
    for counter in range(1, 256):
        previous = prf(key, previous + data + bytes([counter]))
        result += previous
        if len(result) >= length:
            return result[:length]
    raise ValueError("PRF+ length exceeds one-octet counter")


def chain(entries):
    result = b""
    for index, (_, body) in enumerate(entries):
        following = entries[index + 1][0] if index + 1 < len(entries) else 0
        result += struct.pack("!BBH", following, 0, len(body) + 4) + body
    return entries[0][0], result


def header(spi_i, spi_r, first, exchange, flags, message_id, body_length):
    return spi_i + spi_r + struct.pack(
        "!BBBBII", first, 0x20, exchange, flags, message_id, 28 + body_length
    )


def transform(more, kind, identifier, attributes=b""):
    return struct.pack("!BBHBBH", more, 0, 8 + len(attributes), kind, 0, identifier) + attributes


def vector():
    actual = {
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "openssl": backend.openssl_version_text(),
    }
    if actual != PINNED:
        raise RuntimeError(f"reference environment differs: expected {PINNED}, found {actual}")
    out = {
        "provenance": "Synthetic RFC 7296 mechanism fixture; no captured traffic or wire interoperability claim",
        "reference_python": actual["python"],
        "reference_cryptography": actual["cryptography"],
        "reference_openssl": actual["openssl"],
        "input_recipe": "P-256 scalars 1 and 2; ascending-byte SPIs/nonces/MSK; fixed example.test identities; ordinary IV counters 1, 2, 3",
        "profile": "ENCR_AES_GCM_16(128), PRF_HMAC_SHA2_256, ECP_256; no separate INTEG",
    }

    def remember(name, value):
        out[name] = value.hex()
        return value

    spi_i = remember("spi_i", bytes(range(1, 9)))
    spi_r = remember("spi_r", bytes(range(17, 25)))
    ni = remember("ni", bytes(range(32, 64)))
    nr = remember("nr", bytes(range(64, 96)))
    private_i = ec.derive_private_key(1, ec.SECP256R1())
    private_r = ec.derive_private_key(2, ec.SECP256R1())
    remember("scalar_i", (1).to_bytes(32, "big"))
    remember("scalar_r", (2).to_bytes(32, "big"))

    def public(key):
        point = key.public_key().public_numbers()
        return point.x.to_bytes(32, "big") + point.y.to_bytes(32, "big")

    ke_i = remember("ke_i", public(private_i))
    ke_r = remember("ke_r", public(private_r))
    shared = remember("dh_shared", private_i.exchange(ec.ECDH(), private_r.public_key()))
    assert shared == private_r.exchange(ec.ECDH(), private_i.public_key())
    skeyseed = remember("skeyseed", prf(ni + nr, shared))
    material = prf_plus(skeyseed, ni + nr + spi_i + spi_r, 32 + 20 + 20 + 32 + 32)
    keys, offset = {}, 0
    for name, size in [("sk_d", 32), ("sk_ai", 0), ("sk_ar", 0), ("sk_ei", 20), ("sk_er", 20), ("sk_pi", 32), ("sk_pr", 32)]:
        keys[name] = remember(name, material[offset:offset + size])
        offset += size
    assert offset == len(material)
    transforms = transform(3, 1, 20, struct.pack("!HH", 0x800E, 128))
    transforms += transform(3, 2, 5) + transform(0, 4, 19)
    sa = struct.pack("!BBHBBBB", 0, 0, 8 + len(transforms), 1, 1, 0, 3) + transforms

    def sa_init(responder):
        first, payloads = chain([(33, sa), (34, b"\x00\x13\x00\x00" + (ke_r if responder else ke_i)), (40, nr if responder else ni)])
        return header(spi_i, spi_r if responder else bytes(8), first, 34, 0x20 if responder else 0x08, 0, len(payloads)) + payloads

    init_i = remember("sa_init_request", sa_init(False))
    init_r = remember("sa_init_response", sa_init(True))
    id_i = remember("id_i_body", b"\x02\x00\x00\x00initiator.example.test")
    id_r = remember("id_r_body", b"\x02\x00\x00\x00responder.example.test")
    shared_auth = remember("psk", bytes(range(128, 160)))
    msk = remember("eap_msk", bytes(range(160, 224)))

    def auth(shared_key, responder):
        transcript = (init_r + ni + prf(keys["sk_pr"], id_r)) if responder else (init_i + nr + prf(keys["sk_pi"], id_i))
        return prf(prf(shared_key, b"Key Pad for IKEv2"), transcript)

    auth_i = remember("psk_auth_i", auth(shared_auth, False))
    auth_r = remember("psk_auth_r", auth(shared_auth, True))
    eap_auth_i = remember("eap_auth_i", auth(msk, False))
    eap_auth_r = remember("eap_auth_r", auth(msk, True))

    def seal(name, responder, message_id, counter, entries):
        first, cleartext = chain(entries)
        remember(name + "_cleartext", cleartext)
        key = keys["sk_er" if responder else "sk_ei"]
        iv = counter.to_bytes(8, "big")
        plaintext = cleartext + b"\x00"  # zero padding octets, Pad Length = 0
        body_length = 4 + 8 + len(plaintext) + 16
        prefix = header(spi_i, spi_r, 46, 35, 0x20 if responder else 0x08, message_id, body_length)
        prefix += struct.pack("!BBH", first, 0, body_length)
        encrypted = AESGCM(key[:16]).encrypt(key[16:] + iv, plaintext, prefix)
        assert AESGCM(key[:16]).decrypt(key[16:] + iv, encrypted, prefix) == plaintext
        remember(name, prefix + iv + encrypted)

    seal("psk_request", False, 1, 1, [(35, id_i), (39, b"\x02\x00\x00\x00" + auth_i)])
    seal("psk_response", True, 1, 1, [(36, id_r), (39, b"\x02\x00\x00\x00" + auth_r)])
    # A synthetic EAP transcript exercises the transport/AUTH composition only.
    # EAP server authentication, method cryptography and Child SA negotiation
    # belong to callers and are deliberately not claimed by this vector.
    seal("eap_start_request", False, 1, 1, [(35, id_i)])
    seal("eap_identity_request", True, 1, 1, [(48, b"\x01\x01\x00\x05\x01")])
    seal("eap_identity_response", False, 2, 2, [(48, b"\x02\x01\x00\x09\x01test")])
    seal("eap_success", True, 2, 2, [(48, b"\x03\x01\x00\x04")])
    seal("eap_auth_request", False, 3, 3, [(39, b"\x02\x00\x00\x00" + eap_auth_i)])
    seal("eap_auth_response", True, 3, 3, [(39, b"\x02\x00\x00\x00" + eap_auth_r)])
    return json.dumps(out, indent=2) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    output = vector()
    path = Path(__file__).with_suffix(".json")
    if args.write:
        path.write_text(output, encoding="utf-8")
    elif args.check:
        if path.read_text(encoding="utf-8") != output:
            raise SystemExit("independent vector does not match committed JSON")
        print("Independent initiator vector matches (Python, cryptography and OpenSSL pins verified).")
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
