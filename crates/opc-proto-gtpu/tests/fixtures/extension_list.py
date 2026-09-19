#!/usr/bin/env python3
"""Independent synthetic TS 29.281 V18.4.0 figure 8.5-1 wire corpus.

No SDK imports, encoder calls, packet captures or external dependencies.
IE 141 has a one-octet list count. Other TLVs retain two-octet lengths.
Source: https://www.etsi.org/deliver/etsi_ts/129200_129299/129281/18.04.00_60/ts_129281v180400p.pdf
"""
import argparse
import hashlib
from pathlib import Path


def packet(body):
    return bytes([0x32, 31]) + (4 + len(body)).to_bytes(2, "big") + bytes(8) + body


def corpus():
    rows = ["# name\tadmit\twire"]
    def add(name, admit, wire):
        rows.append(f"{name}\t{int(admit)}\t{wire.hex()}")
    for count in range(256):
        values = bytes(range(1, count + 1))
        body = bytes([141, count]) + values
        wire = packet(body)
        add(f"count-{count}", True, wire)
        add(f"private-{count}", True, packet(body + bytes([255, 0, 3, 0x12, 0x34, 0xa5])))
        add(f"old-wide-{count}", False, packet(bytes([141, 0, count]) + values))
        add(f"duplicate-ie-{count}", False, packet(body + bytes([141, 0])))
        add(f"tail-{count}", False, wire + b"\x00")
        add(f"truncated-{count}", False, wire[:-1])
        if count:
            add(f"under-count-{count}", False, packet(bytes([141, count - 1]) + values))
            add(f"zero-type-{count}", False, packet(bytes([141, count]) + values[:-1] + b"\x00"))
        if count < 255:
            add(f"over-count-{count}", False, packet(bytes([141, count + 1]) + values))
        if count > 1:
            add(f"duplicate-type-{count}", False, packet(bytes([141, count]) + values[:-1] + values[-2:-1]))
    return ("\n".join(rows) + "\n").encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = corpus()
    path = Path(__file__).with_suffix(".tsv")
    if args.check:
        if path.read_bytes() != expected:
            raise SystemExit("extension-list reference corpus differs")
    else:
        path.write_bytes(expected)
    rows = expected.decode().splitlines()[1:]
    admitted = sum(row.split("\t")[1] == "1" for row in rows)
    print(f"{len(rows)} cases; {admitted} admitted; {len(rows)-admitted} refused; sha256={hashlib.sha256(expected).hexdigest()}")


if __name__ == "__main__":
    main()
