#!/usr/bin/env python3
"""Independent carrier-framing obligations; no SDK imports or encryption claim.

RFC 6083 sections 4.1, 4.4 and 4.5 define record framing, control streams and
authenticated DATA metadata. Ordered application delivery, a configured stream
range, exact PPID selection and terminal refusal are explicit SDK profile rules.
The bodies in this table denote framing shapes, not valid AEAD ciphertext.
Actual mutual-authentication, record correlation and kernel tests are separate.
Protected records in the opt-in multistream profile require the DTLS 1.2
version from RFC 6347 section 4.1. Initial handshake compatibility and the
legacy stream-zero framing validator remain separate from engine admission.
"""

import argparse
import itertools
from pathlib import Path


def reference():
    rows = [
        "# RFC 6083 carrier framing, https://www.rfc-editor.org/rfc/rfc6083.html",
        "# DTLS 1.2 record version, https://www.rfc-editor.org/rfc/rfc6347.html#section-4.1",
        "# count ppid stream order fault type epoch shape version result (tab separated)",
        "# synthetic framing only; neither decrypted records nor interoperability evidence",
    ]
    ordinary = itertools.product(
        [1, 2, 16, 65535], [66, 47, 60], [0, 1, 15, 16, 65534, 65535],
        ["ordered", "unordered"], ["none", "payload", "control", "notification"],
        [20, 21, 22, 23], [0, 1], ["complete", "short", "trailing", "oversized"],
    )
    cases = [(*case, "fefd") for case in ordinary]
    cases.extend(
        (count, 66, stream, "ordered", "none", kind, epoch, "complete", version)
        for count, stream, kind, epoch, version in itertools.product(
            [1, 2], [0, 1], [20, 21, 22, 23], [0, 1],
            ["fefd", "feff", "fefc", "0303"],
        )
    )
    admitted = rejected = 0
    for count, ppid, stream, order, fault, kind, epoch, shape, version in cases:
        if ppid != 66:
            result = "rfc6083_cleartext_rejected"
        elif (stream >= count or order != "ordered" or fault != "none"
              or shape != "complete" or (stream != 0 and (kind != 23 or epoch == 0))
              or (count > 1 and epoch != 0 and version != "fefd")):
            result = "rfc6083_transport_failed"
        else:
            result = "framing-admitted"
        admitted += result == "framing-admitted"
        rejected += result != "framing-admitted"
        rows.append("\t".join(map(str, [
            count, ppid, stream, order, fault, kind, epoch, shape, version, result,
        ])))
    return "\n".join(rows) + "\n", admitted, rejected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    corpus, admitted, rejected = reference()
    path = Path(__file__).with_suffix(".tsv")
    if args.check:
        if path.read_text() != corpus:
            raise SystemExit("stream framing reference drift")
    else:
        path.write_text(corpus)
    print(f"{admitted + rejected} framing cases: {admitted} admitted, {rejected} refused")


if __name__ == "__main__":
    main()
