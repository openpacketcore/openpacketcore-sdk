#!/usr/bin/env python3
"""Independent direct, complete CRL profile; public synthetic P-256 test keys.

Requires cryptography==49.0.0. No SDK imports. --write regenerates the TSV;
otherwise independently classify and compare every deterministic certificate/CRL.
RFC 5280 sections 5 and 6.3 supply CRL semantics. The limited extension profile,
one complete CRL per issuer and numeric/byte budgets are SDK policy choices.
"""
import argparse
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ExtensionOID

ENC = serialization.Encoding.DER
PREFIX = "spiffe://example.test/tenant/tenant-a/ns/core/sa/diameter/nf/"


def date(year):
    return datetime(year, 1, 1, tzinfo=timezone.utc)


def key(scalar):
    return ec.derive_private_key(scalar, ec.SECP256R1())


def certificate(name, public_key, serial, issuer=None, signer=None, depth=None, role=None, crl_sign=True):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (x509.CertificateBuilder().subject_name(subject)
               .issuer_name(subject if issuer is None else issuer.subject)
               .public_key(public_key.public_key()).serial_number(serial)
               .not_valid_before(date(2010)).not_valid_after(date(2100))
               .add_extension(x509.BasicConstraints(ca=role is None, path_length=depth), True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key.public_key()), False)
               .add_extension(x509.KeyUsage(role is not None, False, False, False, False,
                                            role is None, role is None and crl_sign, False, False), True))
    if role:
        identity = PREFIX + ("smf/instance/client-0" if role == "client" else "aaa/instance/server-0")
        builder = (builder.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(identity)]), False)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]), False))
    return builder.sign(signer or public_key, hashes.SHA256(), ecdsa_deterministic=True)


def crl(issuer, signer, *, revoked=(), first=2010, last=2100, number=1, aki=True, extra=None):
    builder = (x509.CertificateRevocationListBuilder().issuer_name(issuer.subject)
               .last_update(date(first)).next_update(date(last)))
    if number is not None:
        builder = builder.add_extension(x509.CRLNumber(number), False)
    if aki:
        identifier = (x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()) if aki is True
                      else x509.AuthorityKeyIdentifier(aki, None, None))
        builder = builder.add_extension(identifier, False)
    if extra:
        builder = builder.add_extension(*extra)
    for serial in revoked:
        builder = builder.add_revoked_certificate(x509.RevokedCertificateBuilder()
                    .serial_number(serial).revocation_date(date(2015)).build())
    return builder.sign(signer, hashes.SHA256(), ecdsa_deterministic=True).public_bytes(ENC)


def vectors():
    root_key, inter_key, peer_key, foreign_key = [key(0x794100 + i) for i in range(4)]
    root = certificate("Synthetic N3 CRL root", root_key, 100, depth=1)
    inter = certificate("Synthetic N3 CRL intermediate", inter_key, 101, root, root_key, depth=0)
    foreign = certificate("Synthetic N3 foreign CRL root", foreign_key, 103, depth=1)
    root_crl = crl(root, root_key)
    rows = []
    for role in ["client", "server"]:
        leaf = certificate("Synthetic N3 CRL peer", peer_key, 102, inter, inter_key, role=role)
        good = crl(inter, inter_key)
        damaged = bytearray(good)
        damaged[-1] ^= 1
        cases = [
            ("valid", "admit", [root_crl, good]),
            ("revoked-leaf", "authentication", [root_crl, crl(inter, inter_key, revoked=[102])]),
            ("revoked-intermediate", "authentication", [crl(root, root_key, revoked=[101]), good]),
            ("missing-root", "authentication", [good]),
            ("missing-intermediate", "authentication", [root_crl]),
            ("wrong-issuer", "authentication", [root_crl, crl(foreign, foreign_key)]),
            ("wrong-key", "authentication", [root_crl, crl(inter, foreign_key)]),
            ("wrong-aki", "authentication", [root_crl, crl(inter, inter_key, aki=b"synthetic-wrong-identifier")]),
            ("stale", "profile", [root_crl, crl(inter, inter_key, last=2020)]),
            ("future", "profile", [root_crl, crl(inter, inter_key, first=2090)]),
            ("signature-corrupt", "authentication", [root_crl, bytes(damaged)]),
            ("truncated", "profile", [root_crl, good[:-1]]),
            ("trailing", "profile", [root_crl, good + b"\x00"]),
            ("duplicate-issuer", "profile", [root_crl, good, good]),
            ("conflicting-issuer", "profile", [root_crl, good, crl(inter, inter_key, revoked=[102])]),
            ("delta", "profile", [root_crl, crl(inter, inter_key, extra=(x509.DeltaCRLIndicator(0), True))]),
            ("indirect", "profile", [root_crl, crl(inter, inter_key, extra=(
                x509.IssuingDistributionPoint(None, None, False, False, None, True, False), True))]),
            ("unknown-critical", "profile", [root_crl, crl(inter, inter_key, extra=(
                x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.55555.794"), b"\x05\x00"), True))]),
            ("missing-aki", "profile", [root_crl, crl(inter, inter_key, aki=False)]),
            ("missing-number", "profile", [root_crl, crl(inter, inter_key, number=None)]),
            ("duplicate-serial", "profile", [root_crl, crl(inter, inter_key, revoked=[104, 104])]),
            ("unrelated-revoked", "admit", [root_crl, crl(inter, inter_key, revoked=[104, 105])]),
            ("reversed-order", "admit", [good, root_crl]),
            ("newer", "admit", [crl(root, root_key, first=2020, number=2), crl(inter, inter_key, first=2020, number=2)]),
        ]
        private = peer_key.private_bytes(ENC, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        for name, expected, lists in cases:
            rows.append((role, name, expected, leaf.public_bytes(ENC).hex(), private.hex(),
                         inter.public_bytes(ENC).hex(), root.public_bytes(ENC).hex(), ",".join(c.hex() for c in lists)))
        for name, changed_inter, changed_root in [
            ("issuer-no-crl-sign", certificate("Synthetic N3 CRL intermediate", inter_key, 101, root, root_key, depth=0, crl_sign=False), root),
            ("root-no-crl-sign", inter, certificate("Synthetic N3 CRL root", root_key, 100, depth=1, crl_sign=False)),
        ]:
            rows.append((role, name, "authentication", leaf.public_bytes(ENC).hex(), private.hex(),
                         changed_inter.public_bytes(ENC).hex(), changed_root.public_bytes(ENC).hex(),
                         ",".join(c.hex() for c in [root_crl, good])))
    return rows


def classify(row):
    """Independent chain/signature/coverage/freshness and revoked-serial decision."""
    role, _, _, leaf, _, intermediate, root, crls = row
    certs = [x509.load_der_x509_certificate(bytes.fromhex(c)) for c in [leaf, intermediate, root]]
    allowed = {ExtensionOID.AUTHORITY_KEY_IDENTIFIER, ExtensionOID.CRL_NUMBER}
    parsed = []
    try:
        for encoded in crls.split(","):
            raw = bytes.fromhex(encoded)
            candidate = x509.load_der_x509_crl(raw)
            assert candidate.public_bytes(ENC) == raw
            assert candidate.last_update_utc <= date(2026) < candidate.next_update_utc
            assert {e.oid for e in candidate.extensions} == allowed
            assert all(not e.critical for e in candidate.extensions)
            assert candidate.issuer not in [c.issuer for c in parsed]
            serials = [c.serial_number for c in candidate]
            assert len(serials) == len(set(serials))
            parsed.append(candidate)
    except (ValueError, AssertionError):
        return "profile"
    for cert, issuer in zip(certs, certs[1:]):
        try:
            assert cert.issuer == issuer.subject
            assert issuer.extensions.get_extension_for_class(x509.KeyUsage).value.crl_sign
            issuer.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
            current = next(c for c in parsed if c.issuer == issuer.subject)
            issuer.public_key().verify(current.signature, current.tbs_certlist_bytes, ec.ECDSA(current.signature_hash_algorithm))
            assert current.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier == issuer.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
            assert current.get_revoked_certificate_by_serial_number(cert.serial_number) is None
        except (AssertionError, InvalidSignature, StopIteration):
            return "authentication"
    usage = ExtendedKeyUsageOID.CLIENT_AUTH if role == "client" else ExtendedKeyUsageOID.SERVER_AUTH
    assert usage in certs[0].extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    return "admit"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    rows = vectors()
    for row in rows:
        assert classify(row) == row[2], row[:3]
    content = ("# PUBLIC synthetic deterministic P-256 keys; NEVER use outside tests.\n"
               "# role\tcase\texpected\tleaf_der\tpkcs8\tintermediate_der\troot_der\tcrl_der_csv\n"
               + "".join("\t".join(row) + "\n" for row in rows))
    path = Path(__file__).with_suffix(".tsv")
    if args.write:
        path.write_text(content)
    else:
        assert path.read_text() == content
    print(f"{len(rows)} independently verified CRL cases; sha256={hashlib.sha256(content.encode()).hexdigest()}")


if __name__ == "__main__":
    main()
