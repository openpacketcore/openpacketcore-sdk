#!/usr/bin/env python3
"""Reproduce the frozen CBC recovery fingerprints independently of SDK code.

Uses only Python's standard library. Three published SHA-256 known answers
qualify hashlib before generating the 48 profile triples in both directions.
The synthetic keys match the canonical packet fixture's input schedule.
Run without arguments to verify; --create writes an absent fixture only.
"""

import argparse
import hashlib
import struct
from pathlib import Path


def qualify_sha256():
    for message, expected in (
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (b"a" * 1_000_000,
         "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
    ):
        assert hashlib.sha256(message).hexdigest() == expected


def lp(value):
    return struct.pack("!H", len(value)) + value


def pattern(start, length):
    return bytes((start + offset) % 256 for offset in range(length))


def generate():
    lines = [
        "# CBC-V1 K4 fingerprints; generated independently by cbc_epoch_fingerprints_v1.py",
        "# bits INTEG PRF direction ledger_key binding",
        "# SPIi=0102030405060708 SPIr=1112131415161718 marker=01",
        "# SK_ei=00+i SK_er=40+i SK_ai=80+i SK_ar=20+i SK_d=d0+i (mod 256)",
    ]
    for bits in (128, 192, 256):
        for integ, a_len in ((2, 20), (12, 32), (13, 48), (14, 64)):
            for prf, d_len in ((2, 20), (5, 32), (6, 48), (7, 64)):
                ei, er = pattern(0, bits // 8), pattern(0x40, bits // 8)
                ai, ar, d = pattern(0x80, a_len), pattern(0x20, a_len), pattern(0xd0, d_len)
                for direction, label in ((0, "I"), (1, "R")):
                    e, a = (ei, ai) if direction == 0 else (er, ar)
                    ledger = (b"opc-ikev2-canonical-cbc-ledger-key-v1\0"
                              + struct.pack("!HHH", 12, bits, integ) + lp(e) + lp(a))
                    binding = (b"opc-ikev2-canonical-cbc-binding-v1\0"
                               + struct.pack("!QQBHHHHB", 0x0102030405060708,
                                             0x1112131415161718, direction,
                                             12, bits, integ, prf, 1)
                               + b"".join(map(lp, (ei, er, ai, ar, d))))
                    lines.append(f"{bits} {integ} {prf} {label} "
                                 f"{hashlib.sha256(ledger).hexdigest()} "
                                 f"{hashlib.sha256(binding).hexdigest()}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--create", action="store_true")
    args = parser.parse_args()
    qualify_sha256()
    expected = generate()
    fixture = Path(__file__).parents[2] / "src/recovery/cbc_epoch_v1.txt"
    if args.create:
        with fixture.open("x") as output:
            output.write(expected)
    assert fixture.read_text() == expected
    print(f"3 SHA-256 known answers; 96 frozen fingerprints verified; "
          f"sha256={hashlib.sha256(expected.encode()).hexdigest()}")
