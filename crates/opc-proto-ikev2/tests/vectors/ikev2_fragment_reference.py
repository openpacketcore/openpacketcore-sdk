#!/usr/bin/env python3
"""Independent RFC 7383 framing/reassembly reference, using OpenSSL cryptography.

Public synthetic keys only. No SDK imports or subprocesses. --write creates the
TSV fixture; --check regenerates it; --verify-export checks SDK-emitted packets.
The latter accepts random CBC IVs and verifies every fragment's MAC and padding.
"""
import argparse
import hashlib
import hmac
import json
import platform
import struct
from pathlib import Path

import cryptography
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).parent
PINNED = ("3.14.5", "49.0.0", "OpenSSL 4.0.1 9 Jun 2026")


def qualify_crypto():
    # Previously pinned published NIST CAVP examples, independent of SDK packets.
    samples = json.loads((ROOT.parent / "data/canonical_empty_v1.provenance.json").read_text())
    for row in samples["representative_published_cases"]:
        value = lambda key: bytes.fromhex(row[key])
        assert AESGCM(value("Key")).encrypt(value("IV"), value("PT"), value("AAD")) == value("CT") + value("Tag")
    # NIST SP 800-38A F.2.1, first AES-128-CBC block.
    encrypt = Cipher(algorithms.AES(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")), modes.CBC(bytes(range(16)))).encryptor()
    assert encrypt.update(bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")) + encrypt.finalize() == bytes.fromhex("7649abac8119b246cee98e9b12e9197d")


def protect(cipher, key, auth, prefix, body, serial):
    if cipher == "gcm":
        iv = serial.to_bytes(8, "big")
        return iv + AESGCM(key[:-4]).encrypt(key[-4:] + iv, body + b"\0", prefix)
    iv = (0xABC000 + serial).to_bytes(16, "big")
    padding = 15 - len(body) % 16
    encrypt = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    data = iv + encrypt.update(body + bytes(padding) + bytes([padding])) + encrypt.finalize()
    return data + hmac.digest(auth, prefix + data, "sha256")[:16]


def packet_length(cipher, count):
    return 36 + (8 + count + 1 + 16 if cipher == "gcm" else 16 + ((count + 16) // 16) * 16 + 16)


def open_set(fields, packets):
    cipher, _, direction, ki, kr, ai, ar, clear = fields
    key, auth = (bytes.fromhex(ki), bytes.fromhex(ai)) if direction == "I" else (bytes.fromhex(kr), bytes.fromhex(ar))
    chunks, identity = {}, None
    for wire in packets:
        if len(wire) < 61 or wire[16:20] != bytes([53, 32, 37, 8 if direction == "I" else 0]):
            raise ValueError("header")
        if int.from_bytes(wire[24:28], "big") != len(wire) or int.from_bytes(wire[30:32], "big") != len(wire) - 28:
            raise ValueError("length")
        if cipher == "gcm":
            body = AESGCM(key[:-4]).decrypt(key[-4:] + wire[36:44], wire[44:], wire[:36])
        else:
            if not hmac.compare_digest(hmac.digest(auth, wire[:-16], "sha256")[:16], wire[-16:]):
                raise ValueError("ICV")
            decrypt = Cipher(algorithms.AES(key), modes.CBC(wire[36:52])).decryptor()
            body = decrypt.update(wire[52:-16]) + decrypt.finalize()
        if not body or body[-1] >= len(body):
            raise ValueError("padding")
        number, total = struct.unpack("!HH", wire[32:36])
        if not 1 <= number <= total == len(packets) <= 256 or number in chunks:
            raise ValueError("numbering")
        if wire[28] != (42 if number == 1 else 0):
            raise ValueError("Next Payload")
        if identity is not None and identity != wire[:16] + wire[17:24]:
            raise ValueError("mixed message")
        identity = wire[:16] + wire[17:24]
        chunks[number] = body[:len(body) - body[-1] - 1]
    actual = b"".join(chunks[number] for number in range(1, len(packets) + 1))
    if actual != bytes.fromhex(clear):
        raise ValueError("reassembled payload")


def vectors():
    rows = ["# cipher bits original_sender SK_ei SK_er SK_ai SK_ar cleartext packets..."]
    body = struct.pack("!BBHBBH", 0, 0, 1208, 3, 4, 300) + b"".join(struct.pack("!I", spi) for spi in range(1, 301))
    negatives = 0
    for cipher in ("gcm", "cbc"):
        for bits in (128, 192, 256):
            for direction in ("I", "R"):
                ki, kr = bytes(range(bits // 8)), bytes(range(128, 128 + bits // 8))
                tag = (1 if direction == "I" else 2) + (0 if cipher == "gcm" else 4)
                ki, kr = bytes([ki[0] ^ tag]) + ki[1:], bytes([kr[0] ^ tag]) + kr[1:]
                if cipher == "gcm":
                    ki, kr = ki + bytes.fromhex("01020304"), kr + bytes.fromhex("a1a2a3a4")
                ai, ar = (b"", b"") if cipher == "gcm" else (bytes([0x31]) * 32, bytes([0x32]) * 32)
                # '-' represents an empty integrity key in the whitespace-separated fixture.
                fields = [cipher, str(bits), direction, ki.hex(), kr.hex(), ai.hex(), ar.hex(), body.hex()]
                width = max(n for n in range(1, 545) if packet_length(cipher, n) <= 544)
                parts = [body[start:start + width] for start in range(0, len(body), width)]
                packets = []
                for index, part in enumerate(parts):
                    length = packet_length(cipher, len(part))
                    prefix = struct.pack("!QQBBBBIIBBHHH", 0x0102030405060708, 0x1112131415161718, 53, 32, 37,
                                         8 if direction == "I" else 0, 0, length, 42 if index == 0 else 0, 0, length - 28, index + 1, len(parts))
                    key, auth = (ki, ai) if direction == "I" else (kr, ar)
                    packets.append(prefix + protect(cipher, key, auth, prefix, part, index))
                open_set(fields, list(reversed(packets)))
                for byte in range(len(packets[0])):
                    changed = bytearray(packets[0]); changed[byte] ^= 1
                    try:
                        open_set(fields, [bytes(changed), *packets[1:]])
                    except (ValueError, InvalidTag):
                        negatives += 1
                    else:
                        raise AssertionError("mutated protected packet accepted")
                rows.append(" ".join([value or "-" for value in fields] + [wire.hex() for wire in packets]))
    return "\n".join(rows) + "\n", negatives


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--verify-export", type=Path)
    args = parser.parse_args()
    actual = (platform.python_version(), cryptography.__version__, backend.openssl_version_text())
    if actual != PINNED:
        raise RuntimeError(f"reference environment differs: {actual}")
    qualify_crypto()
    content, negatives = vectors()
    path = ROOT / "ikev2_fragments.tsv"
    if args.write:
        path.write_text(content)
    else:
        assert path.read_text() == content
    if args.verify_export:
        lines = args.verify_export.read_text().splitlines()
        assert len(lines) == 12
        for line in lines:
            values = [x if x != "-" else "" for x in line.split()]
            open_set(values[:8], [bytes.fromhex(wire) for wire in values[8:]])
    print(json.dumps({"python": actual[0], "cryptography": actual[1], "openssl": actual[2], "vectors": 12,
                      "mutated_packets_rejected": negatives, "fixture_sha256": hashlib.sha256(content.encode()).hexdigest(),
                      "reference_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      "sdk_export_verified": bool(args.verify_export)}, sort_keys=True))

if __name__ == "__main__":
    main()
