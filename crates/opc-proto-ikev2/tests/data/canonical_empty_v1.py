#!/usr/bin/env python3
"""Independently qualify and verify the immutable canonical IKE V1 vectors.

Requires Python cryptography (OpenSSL backend) and the NIST CAVP archive:
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip

Usage: python3 canonical_empty_v1.py NIST_ARCHIVE [--create]
--create only creates absent fixtures; it never replaces an existing V1 file.
The SDK/Rust implementation and reviewer calculations are not imported.
"""

import argparse
import hashlib
import json
import platform
import struct
import zipfile
from pathlib import Path

import cryptography
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def cases(contents):
    parameters, current = {}, {}
    for line in contents.splitlines() + [""]:
        line = line.strip()
        if not line or line.startswith("#"):
            if current:
                yield parameters.copy(), current
                current = {}
        elif line.startswith("["):
            name, value = line[1:-1].split(" = ")
            parameters[name] = int(value)
        else:
            name, value = line.split("=", 1)
            current[name.strip()] = value.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--create", action="store_true")
    args = parser.parse_args()
    archive_bytes = args.archive.read_bytes()
    validated = {}
    representative_cases = []
    with zipfile.ZipFile(args.archive) as archive:
        for bits in (128, 192, 256):
            name = f"gcmEncryptExtIV{bits}.rsp"
            count = 0
            for parameters, case in cases(archive.read(name).decode("ascii")):
                if parameters["IVlen"] != 96 or parameters["Taglen"] != 128:
                    continue
                key, iv, plaintext, aad, ciphertext, tag = (
                    bytes.fromhex(case[field])
                    for field in ("Key", "IV", "PT", "AAD", "CT", "Tag")
                )
                computed = AESGCM(key).encrypt(iv, plaintext, aad)
                assert computed == ciphertext + tag, (name, parameters, case["Count"])
                assert AESGCM(key).decrypt(iv, computed, aad) == plaintext
                count += 1
                if case["Count"] == "0" and len(representative_cases) < (bits // 64 - 1) * 3:
                    representative_cases.append({"file": name, "parameters": parameters, **case})
            assert count > 0
            validated[name] = count

    # Only after published-vector qualification may this tool calculate V1.
    rows = ["# Immutable V1: bits direction message_id key_and_salt full_ike_wire"]
    negatives = 0
    for bits in (128, 192, 256):
        for direction, offset, salt in (("I", 0, bytes.fromhex("01020304")),
                                        ("R", 128, bytes.fromhex("a1a2a3a4"))):
            key = bytes(range(offset, offset + bits // 8))
            for message_id in (0, 1, 0x11223344, 0xFFFFFFFF):
                aad = struct.pack(
                    "!QQBBBBII BBH", 0x0102030405060708, 0x1112131415161718,
                    46, 0x20, 37, 0x28 if direction == "I" else 0x20,
                    message_id, 57, 0, 0, 29,
                )
                iv = struct.pack("!II", 0xFFFFFFFF, message_id)
                nonce = salt + iv
                encrypted = AESGCM(key).encrypt(nonce, b"\0", aad)
                wire = aad + iv + encrypted
                assert len(aad) == 32 and len(wire) == 57
                assert AESGCM(key).decrypt(nonce, wire[40:], aad) == b"\0"
                wrong_aads = [wire[:28], wire[:40]]
                for bit in range(256):
                    changed = bytearray(aad)
                    changed[bit // 8] ^= 1 << (bit % 8)
                    wrong_aads.append(bytes(changed))
                for wrong in wrong_aads:
                    try:
                        AESGCM(key).decrypt(nonce, encrypted, wrong)
                    except InvalidTag:
                        negatives += 1
                    else:
                        raise AssertionError("changed AAD authenticated")
                rows.append(f"{bits} {direction} {message_id:08x} {(key + salt).hex()} {wire.hex()}")
    contents = "\n".join(rows) + "\n"
    target = Path(__file__).resolve().parents[2] / "src/canonical/v1.txt"
    if args.create and not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="ascii")
    assert target.read_text(encoding="ascii") == contents, "V1 bytes changed: do not replace fixtures"
    report = {
        "tool": "tests/data/canonical_empty_v1.py",
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "openssl": backend.openssl_version_text(),
        "nist_source": "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip",
        "nist_archive_sha256": hashlib.sha256(archive_bytes).hexdigest(),
        "published_96_bit_iv_128_bit_tag_cases_passed": validated,
        "representative_published_cases": representative_cases,
        "v1_vectors": len(rows) - 1,
        "wrong_aad_authentication_failures": negatives,
        "v1_sha256": hashlib.sha256(contents.encode("ascii")).hexdigest(),
        "qualification_preceded_v1_calculation": True,
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
