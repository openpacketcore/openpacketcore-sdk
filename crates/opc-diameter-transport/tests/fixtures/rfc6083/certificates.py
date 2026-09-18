#!/usr/bin/env python3
"""Independent synthetic X.509 vectors; no SDK code or production credentials.

Reproduced with Python cryptography 49.0.0. Deterministic P-256 test scalars are public.
Generate: python3 certificates.py --write
Verify:   python3 certificates.py
"""
from datetime import datetime, timezone
from pathlib import Path
import argparse
import hashlib

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CLIENT = "spiffe://example.test/tenant/tenant-a/ns/core/sa/diameter/nf/smf/instance/client-0"
OTHER = CLIENT[:-1] + "1"
UTC = timezone.utc
ENC = serialization.Encoding.DER


def date(year):
    return datetime(year, 1, 1, tzinfo=UTC)


def issuer(scalar, serial):
    key = ec.derive_private_key(scalar, ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Synthetic RFC6083 CA {serial}")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(serial)
            .not_valid_before(date(2010)).not_valid_after(date(2100))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .sign(key, hashes.SHA256(), ecdsa_deterministic=True))
    return key, cert


def vectors():
    key, ca = issuer(0x79401, 1)
    foreign_key, foreign_ca = issuer(0x79403, 3)
    leaf_key = ec.derive_private_key(0x79402, ec.SECP256R1())
    private = leaf_key.private_bytes(ENC, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()).hex()
    rows = []
    cases = [
        ("valid", CLIENT, 2010, 2100, ExtendedKeyUsageOID.CLIENT_AUTH, "admit"),
        ("wrong-identity", OTHER, 2010, 2100, ExtendedKeyUsageOID.CLIENT_AUTH, "identity"),
        ("missing-identity", None, 2010, 2100, ExtendedKeyUsageOID.CLIENT_AUTH, "authentication"),
        ("expired", CLIENT, 2010, 2020, ExtendedKeyUsageOID.CLIENT_AUTH, "authentication"),
        ("not-yet-valid", CLIENT, 2090, 2100, ExtendedKeyUsageOID.CLIENT_AUTH, "authentication"),
        ("wrong-role", CLIENT, 2010, 2100, ExtendedKeyUsageOID.SERVER_AUTH, "authentication"),
        ("untrusted", CLIENT, 2010, 2100, ExtendedKeyUsageOID.CLIENT_AUTH, "authentication"),
    ]
    for serial, (label, identity, first, last, eku, expected) in enumerate(cases, 10):
        signer, root = (foreign_key, foreign_ca) if label == "untrusted" else (key, ca)
        builder = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic RFC6083 peer")]))
                   .issuer_name(root.subject).public_key(leaf_key.public_key()).serial_number(serial)
                   .not_valid_before(date(first)).not_valid_after(date(last))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([eku]), critical=False))
        if identity is not None:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(identity)]), critical=False)
        cert = builder.sign(signer, hashes.SHA256(), ecdsa_deterministic=True)
        rows.append((label, expected, cert.public_bytes(ENC).hex(), private,
                     root.public_bytes(ENC).hex(), ca.public_bytes(ENC).hex()))
    corrupt = bytearray.fromhex(rows[0][2])
    corrupt[-1] ^= 1  # Preserve all fields and corrupt one ECDSA signature bit.
    rows.append(("corrupt-signature", "authentication", corrupt.hex(), private,
                 ca.public_bytes(ENC).hex(), ca.public_bytes(ENC).hex()))
    return rows


def classify(row):
    """Separate X.509 signature/URI/time/EKU decision at a fixed synthetic time."""
    _, _, cert_hex, _, _, anchor_hex = row
    cert = x509.load_der_x509_certificate(bytes.fromhex(cert_hex))
    anchor = x509.load_der_x509_certificate(bytes.fromhex(anchor_hex))
    try:
        anchor.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                                   ec.ECDSA(cert.signature_hash_algorithm))
    except InvalidSignature:
        return "authentication"
    if not cert.not_valid_before_utc <= date(2026) < cert.not_valid_after_utc:
        return "authentication"
    if ExtendedKeyUsageOID.CLIENT_AUTH not in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
        return "authentication"
    try:
        identities = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier)
    except x509.ExtensionNotFound:
        return "authentication"
    return "admit" if identities == [CLIENT] else "identity"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    rows = vectors()
    assert all(classify(row) == row[1] for row in rows)
    content = ("# Public synthetic deterministic P-256 keys; NEVER use outside tests.\n"
               "# case\texpected\tleaf_der_hex\tpkcs8_hex\tpresented_ca_hex\ttrusted_ca_hex\n"
               + "".join("\t".join(row) + "\n" for row in rows))
    path = Path(__file__).with_suffix(".tsv")
    if args.write:
        path.write_text(content)
    else:
        actual = path.read_text()
        actual_rows = [line.split("\t") for line in actual.splitlines() if not line.startswith("#")]
        assert len(actual_rows) == 8 and all(len(row) == 6 for row in actual_rows)
        assert all(classify(row) == row[1] for row in actual_rows), "independent certificate semantics changed"
        assert actual == content, "independent certificate vectors changed"
    print(f"{len(rows)} independent certificate cases verified; sha256={hashlib.sha256(content.encode()).hexdigest()}")


if __name__ == "__main__":
    main()
