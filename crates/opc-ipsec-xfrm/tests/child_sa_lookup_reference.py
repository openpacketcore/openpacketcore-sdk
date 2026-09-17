#!/usr/bin/env python3
"""Independent exact-profile Linux SA lookup-domain intersection vectors.

No SDK imports. The two stored masks have a common incoming lookup value iff
their constrained bits agree: ((value_a ^ value_b) & (mask_a & mask_b)) == 0.
An absent mark stores value=mask=0. Interface IDs do not enter SA lookup.
This models identity ambiguity only, not kernel installation or packet trust.
"""

import argparse
import hashlib
import itertools
from pathlib import Path


def reference():
    lines = ["# dst_a dst_b spi_b mark_a mark_b if_a if_b ambiguous\n"]
    marks = [(0, 0), (0, 0xFFFFFFFF), (11, 0xFFFFFFFF), (12, 0xFFFFFFFF)]
    # Destination indices select two documentation IPv4 and two IPv6 addresses.
    for a, b, spi, ma, mb, ia, ib in itertools.product(
        range(4), range(4), range(2), range(4), range(4), range(3), range(3)
    ):
        va, mask_a = marks[ma]
        vb, mask_b = marks[mb]
        ambiguous = a == b and spi == 0 and ((va ^ vb) & (mask_a & mask_b)) == 0
        lines.append(f"{a}\t{b}\t{spi}\t{ma}\t{mb}\t{ia}\t{ib}\t{int(ambiguous)}\n")
    return "".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = Path(__file__).with_name("child_sa_lookup_cases.tsv")
    expected = reference()
    if args.check:
        if path.read_text() != expected:
            raise SystemExit("Child-SA lookup reference mismatch")
    else:
        path.write_text(expected)
    rows = expected.splitlines()[1:]
    print(
        f"{len(rows)} rows; {sum(row.endswith(chr(9) + '1') for row in rows)} ambiguous; "
        f"SHA-256 {hashlib.sha256(expected.encode()).hexdigest()}"
    )


if __name__ == "__main__":
    main()
