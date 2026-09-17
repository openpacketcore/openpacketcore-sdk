#!/usr/bin/env python3
"""Independent synthetic TS 24.502/RFC 2784/RFC 2890 NWu reference vectors.

No SDK imports, subprocesses, network, or runtime encoder. RFC bits are indexed
from the high bit; Key field positions use TS octet/bit numbers. --check never
repairs committed evidence. These are constructed examples, not peer captures.
"""

import argparse
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def set_bit(data, rfc_bit):
    data[rfc_bit // 8] |= 1 << (7 - rfc_bit % 8)


def canonical(qfi, rqi):
    data = bytearray(9)
    set_bit(data, 2)  # RFC 2890 Key Present
    data[4] = qfi  # TS table 9.3.3-3
    data[7] = rqi << 7
    data[8] = 0x5A  # opaque synthetic user packet
    return data


def observe(data, direction):
    if len(data) <= 8:
        return None
    bits = [(data[i // 8] >> (7 - i % 8)) & 1 for i in range(16)]
    if not bits[2] or any(bits[i] for i in [0, 1, 3, 4, 5, 13, 14, 15]):
        return None
    qfi = sum(((data[4] >> i) & 1) << i for i in range(6))
    rqi = (data[7] >> 7) & 1
    if direction == "U" and rqi:
        return None
    normalized = canonical(qfi, rqi)[:8] + data[8:]
    return qfi, rqi, normalized


def vectors():
    rows = []

    def add(direction, data):
        result = observe(data, direction)
        qfi, rqi, encoded = result if result is not None else ("-", "-", None)
        rows.append("\t".join([direction, str(qfi), str(rqi),
                               encoded.hex() if encoded is not None else "-", data.hex() or "-"]))

    # All QFIs and three legal directional combinations, with five received
    # Protocol Types. Construction assertions use the independently built canon.
    for direction, rqi in [("U", 0), ("D", 0), ("D", 1)]:
        for qfi in range(64):
            for protocol in [0, 1, 0x0800, 0x86DD, 0xFFFF]:
                data = canonical(qfi, rqi)
                data[2:4] = protocol.to_bytes(2, "big")
                add(direction, data)
    for ignored in range(1, 128):
        data = canonical(63, 1)
        for bit in range(7):
            if ignored & (1 << bit):
                set_bit(data, 6 + bit)
        add("D", data)
    # Key spare acceptance is an SDK receive choice; it is not derived from
    # the EAP-5G-only spare rule in TS 24.502 9.3.2.1.
    for octet, bits in [(4, range(6, 8)), (5, range(8)), (6, range(8)), (7, range(7))]:
        data = canonical(1, 0)
        for bit in bits:
            candidate = bytearray(data)
            candidate[octet] |= 1 << bit
            add("U", candidate)
    for bit in [0, 1, 3, 4, 5, 13, 14, 15]:
        for direction in ["U", "D"]:
            data = canonical(1, 0)
            set_bit(data, bit)
            add(direction, data)
    data = canonical(1, 0)
    data[0] = 0  # mandatory Key omitted
    add("U", data)
    for length in range(9):
        add("D", canonical(1, 0)[:length])
    for qfi in range(64):
        add("U", canonical(qfi, 1))
    add("D", canonical(63, 1)[:8] + canonical(1, 0))
    return ("# direction\tqfi\trqi\tcanonical_hex_or_reject\tinput_hex\n" + "\n".join(rows) + "\n").encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = vectors()
    files = {ROOT / "fixtures/nwu.tsv": data,
             ROOT / "fixtures/nwu.sha256": (hashlib.sha256(data).hexdigest() + "\n").encode()}
    for path, content in files.items():
        if args.write:
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(content)
        elif path.read_bytes() != content:
            raise SystemExit("NWu reference vector drift")
    print(f"NWu synthetic reference: {len(data.splitlines()) - 1} rows; sha256 {hashlib.sha256(data).hexdigest()}")


if __name__ == "__main__":
    main()
