#!/usr/bin/env python3
"""Independent protected RFC 5746 Hellos in the synthetic record-test context.

Valid AES-GCM tags let malformed bindings reach both production Hello checks.
These fixed keys are not certificate-authentication or SCTP-AUTH evidence.
"""
import argparse
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from rfc6083_record_reference import prf


def u16(n):
    return n.to_bytes(2, "big")


def render():
    master = prf(b"\x00\x20" + bytes(32) + b"\x00\x20" + bytes([0xA5]) * 32,
                 b"extended master secret", bytes([0x11]) * 32, 48)
    block = prf(master, b"key expansion", bytes([0x33]) * 32 + bytes([0x22]) * 32, 40)
    rows = ["# receiver\tcase\tbinding_valid\trecord_hex"]
    for role in ("client", "server"):
        binding = bytes(range(12)) + (bytes(range(240, 252)) if role == "client" else b"")
        good = bytes([len(binding)]) + binding
        changed = bytes([good[0], good[1] ^ 1]) + good[2:]
        cases = [("valid", [good], False), ("wrong-finished", [changed], False),
                 ("missing", [], False), ("initial-empty", [b"\x00"], False),
                 ("duplicate", [good, good], False), ("wrong-length", [b"\x00" + binding], False)]
        if role == "server":
            cases.append(("renegotiation-scsv", [good], True))
        for name, bodies, scsv in cases:
            extensions = b"\x00\x17\x00\x00" + b"".join(
                b"\xff\x01" + u16(len(body)) + body for body in bodies)
            body = b"\xfe\xfd" + bytes([0x42]) * 32 + b"\x00"
            if role == "server":
                suites = b"\xc0\x2b" + (b"\x00\xff" if scsv else b"")
                body += b"\x00" + u16(len(suites)) + suites + b"\x01\x00"
            else:
                body += b"\xc0\x2b\x00"
            body += u16(len(extensions)) + extensions
            length = len(body).to_bytes(3, "big")
            handshake = bytes([1 if role == "server" else 2]) + length + bytes(5) + length + body
            number = b"\x00\x01" + (1).to_bytes(6, "big")
            aad = number + b"\x16\xfe\xfd" + u16(len(handshake))
            key = block[:16] if role == "server" else block[16:32]
            iv = block[32:36] if role == "server" else block[36:40]
            fragment = number + AESGCM(key).encrypt(iv + number, handshake, aad)
            wire = b"\x16\xfe\xfd" + number + u16(len(fragment)) + fragment
            rows.append(f"{role}\t{name}\t{int(name == 'valid')}\t{wire.hex()}")
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = Path(__file__).with_suffix(".tsv")
    expected = render()
    if args.check:
        if path.read_text() != expected:
            raise SystemExit("independent protected RFC 5746 Hellos differ")
    else:
        path.write_text(expected)
    print("13 protected Hello fixtures; sha256=" + hashlib.sha256(expected.encode()).hexdigest())
