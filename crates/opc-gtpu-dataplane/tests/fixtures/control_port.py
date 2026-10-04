#!/usr/bin/env python3
"""Independent synthetic TS 29.281 V18.4.0 receive/response byte corpus.

Clauses 5.1, 5.2.1, 7.2, 7.3 and 8.2; no SDK imports or encoder calls.
C=typed control, G=framed G-PDU, R=required unknown extension,
U=unmodelled message, M=malformed. '-' means no Echo response plan.
"""
import argparse
import hashlib
from pathlib import Path


def frame(kind, body=b"", *, flags=0x32, teid=0, sequence=0x1234):
    optional = sequence.to_bytes(2, "big") + b"\x00\x00" if flags & 7 else b""
    payload = optional + body
    return bytes([flags, kind]) + len(payload).to_bytes(2, "big") + teid.to_bytes(4, "big") + payload


def corpus():
    rows = ["# name\tkind\twire\techo-response"]
    def add(name, kind, wire, response=None):
        rows.append(f"{name}\t{kind}\t{wire.hex()}\t{response.hex() if response is not None else '-'}")
    echo = frame(1)
    reply = frame(2, b"\x0e\x00")
    add("echo", "C", echo, reply)
    for sequence in [0, 1, 255, 256, 32767, 32768, 65534, 65535]:
        add(f"sequence-{sequence}", "C", frame(1, sequence=sequence), frame(2, b"\x0e\x00", sequence=sequence))
    for flags in [0x32, 0x33, 0x3a, 0x3b]:
        for npdu in [0, 1, 255]:
            wire = bytearray(frame(1, flags=flags))
            wire[10] = npdu
            add(f"ignored-{flags}-{npdu}", "C", wire, reply)
    for recovery in range(256):
        add(f"recovery-{recovery}", "C", frame(2, bytes([14, recovery])))
    error = frame(26, bytes.fromhex("10010203048500047f000002"))
    marker = frame(254, flags=0x30, teid=0x01020304)
    add("error", "C", error)
    add("end-marker", "C", marker)
    notifications = []
    for count in [0, 1, 2, 255]:
        wire = frame(31, bytes([141, count]) + bytes(range(1, count + 1)))
        notifications.append(wire)
        add(f"notification-{count}", "C", wire)
    gpdu = frame(255, b"\x45", flags=0x30, teid=0x01020304)
    add("gpdu", "G", gpdu)
    for kind in range(256):
        if kind not in [1, 2, 26, 31, 254, 255]:
            add(f"unmodelled-{kind}", "U", frame(kind, b"\x45", flags=0x30, teid=0x01020304))
    for extension in range(1, 256):
        wire = bytearray(frame(255, b"\x01\x00\x00\x00\x45", flags=0x34, teid=0x01020304))
        wire[11] = extension
        add(f"extension-{extension}", "R" if extension >= 128 and extension != 0x85 else "G", wire)
    for index, seed in enumerate([echo, reply, error, marker, gpdu, *notifications]):
        for length in range(len(seed)):
            add(f"trunc-{index}-{length}", "M", seed[:length])
        for tail in [b"\x00", b"\x01", b"\xff\xff"]:
            add(f"tail-{index}-{tail.hex()}", "M", seed + tail)
    for index in [0, 2, 3, 4, 5, 6, 7]:
        wire = bytearray(echo)
        wire[index] ^= 2 if index == 0 else 1
        add(f"malformed-echo-{index}", "M", wire)
    return ("\n".join(rows) + "\n").encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = Path(__file__).with_suffix(".tsv")
    expected = corpus()
    if args.check:
        if path.read_bytes() != expected:
            raise SystemExit("control-port reference corpus differs")
    else:
        path.write_bytes(expected)
    print(f"{len(expected.decode().splitlines()) - 1} cases; sha256={hashlib.sha256(expected).hexdigest()}")


if __name__ == "__main__":
    main()
