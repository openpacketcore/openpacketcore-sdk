#!/usr/bin/env python3
"""Independent RFC 5746 sections 3.4--3.7 extension fixtures.

These synthetic previous Finished values exercise connection binding, not
certificate authentication. No SDK or dimpl code generates expected bytes.
"""

import argparse
import hashlib
import struct
from pathlib import Path


def render():
    client = bytes(range(12))
    server = bytes(range(240, 252))
    rows = ["# receiver\tphase\tscsv\textensions_hex\taccept"]

    def add(role, phase, scsv, bodies, accept):
        wire = b"".join(b"\xff\x01" + struct.pack("!H", len(b)) + b for b in bodies)
        rows.append(f"{role}\t{phase}\t{int(scsv)}\t{wire.hex() or '-'}\t{int(accept)}")

    for role in ("client", "server"):
        add(role, "initial", False, [b"\x00"], True)
        add(role, "initial", False, [], False)
        add(role, "initial", True, [], role == "server")
        add(role, "initial", False, [b""], False)
        add(role, "initial", False, [b"\x00", b"\x00"], False)
        binding = client + server if role == "client" else client
        good = bytes([len(binding)]) + binding
        add(role, "rekey", False, [good], True)
        add(role, "rekey", True, [good], False)
        add(role, "rekey", False, [], False)
        add(role, "rekey", False, [b"\x00"], False)
        add(role, "rekey", False, [good, good], False)
        add(role, "rekey", False, [good + b"\x00"], False)
        add(role, "initial", False, [good], False)
        for i in range(len(good)):
            altered = bytearray(good)
            altered[i] ^= 1
            add(role, "rekey", False, [bytes(altered)], False)
            add(role, "rekey", False, [good[:i]], False)
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = Path(__file__).with_suffix(".tsv")
    expected = render()
    if args.check:
        if path.read_text() != expected:
            raise SystemExit("independent RFC 5746 binding fixtures differ")
    else:
        path.write_text(expected)
    print(f"{len(expected.splitlines()) - 1} binding fixtures; sha256=" +
          hashlib.sha256(expected.encode()).hexdigest())
