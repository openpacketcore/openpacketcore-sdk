#!/usr/bin/env python3
"""Independent synthetic AES-128-GCM records; no dimpl/SDK import.

RFC 4279 section 2 (test premaster), RFC 7627 section 4 (test EMS),
RFC 5246 sections 5/6.2.3.3/6.3 (PRF, AAD, key block), RFC 5288 section 3
(nonce), and RFC 6347 section 4.1 (record header). The fixed PSK context
initializes a record-layer test, not a certificate-authenticated handshake.
Python cryptography supplies AES-GCM independently of the Rust providers.
"""

import argparse
import hashlib
import hmac
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def prf(secret, label, seed, length):
    seed = label + seed
    a = seed
    result = b""
    while len(result) < length:
        a = hmac.digest(secret, a, "sha256")
        result += hmac.digest(secret, a + seed, "sha256")
    return result[:length]


def render():
    psk = bytes([0xA5]) * 32
    premaster = b"\x00\x20" + bytes(32) + b"\x00\x20" + psk
    master = prf(premaster, b"extended master secret", bytes([0x11]) * 32, 48)
    block = prf(master, b"key expansion", bytes([0x33]) * 32 + bytes([0x22]) * 32, 40)
    cipher = AESGCM(block[:16])
    lines = ["# epoch\tsequence\tplaintext_hex\trecord_hex"]
    for sequence, length in [(0, 0), (1, 1), (255, 17), (65536, 31),
                             (0x010203040506, 257), ((1 << 48) - 1, 1024)]:
        number = b"\x00\x01" + sequence.to_bytes(6, "big")
        plaintext = bytes((i * 73 + length) % 256 for i in range(length))
        aad = number + b"\x17\xfe\xfd" + length.to_bytes(2, "big")
        fragment = number + cipher.encrypt(block[32:36] + number, plaintext, aad)
        record = b"\x17\xfe\xfd" + number + len(fragment).to_bytes(2, "big") + fragment
        lines.append(f"1\t{sequence}\t{plaintext.hex()}\t{record.hex()}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = Path(__file__).with_suffix(".tsv")
    expected = render()
    if args.check:
        if path.read_text() != expected:
            raise SystemExit("independent RFC 6083 record reference differs")
    else:
        path.write_text(expected)
    print("6 synthetic records; sha256=" + hashlib.sha256(expected.encode()).hexdigest())
