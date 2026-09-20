#!/usr/bin/env python3
"""Independent bounded NDS/AF ECDSA certificate profile, cryptography 49.0.0.

TS 33.310 V18.8.0 clauses 6.1.1, 6.1.2, 6.1.3a and 6.1.4a provide
certificate constraints; the documented ECDSA/DER-name/direct-CRL subset is
SDK policy. This generator/classifier imports no SDK or catalog implementation.
All keys are PUBLIC synthetic fixed scalars, NEVER usable outside tests.
"""
import argparse
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID as EKU, NameOID as DN, ExtensionOID as EXT
from cryptography.x509.name import _ASN1Type

ENC = serialization.Encoding.DER
PREFIX = "spiffe://example.test/tenant/tenant-a/ns/core/sa/diameter/nf/"
IDS = {"client": PREFIX + "smf/instance/client-0", "server": PREFIX + "aaa/instance/server-0"}
NAME = "amf.example.test"


def date(year):
    return datetime(year, 1, 1, tzinfo=timezone.utc)


def name(label, form="organization"):
    if form == "domain":
        return x509.Name([x509.NameAttribute(DN.DOMAIN_COMPONENT, "test"),
                          x509.NameAttribute(DN.DOMAIN_COMPONENT, "example"),
                          x509.NameAttribute(DN.ORGANIZATIONAL_UNIT_NAME, "servers"),
                          x509.NameAttribute(DN.COMMON_NAME, label.replace(" ", "-"))])
    values = [x509.NameAttribute(DN.ORGANIZATION_NAME, "Synthetic operator"),
              x509.NameAttribute(DN.COMMON_NAME, label)]
    if form == "country":
        values.insert(0, x509.NameAttribute(DN.COUNTRY_NAME, "CA"))
    elif form == "missing-organization":
        values = values[-1:]
    elif form == "printable-organization":
        values[0] = x509.NameAttribute(DN.ORGANIZATION_NAME, "Synthetic operator", _type=_ASN1Type.PrintableString)
    elif form == "extra-name":
        values.insert(0, x509.NameAttribute(DN.LOCALITY_NAME, "Synthetic"))
    elif form == "wrong-order":
        values.reverse()
    return x509.Name(values)


def key(index, bits=256):
    curve = {224: ec.SECP224R1, 256: ec.SECP256R1, 384: ec.SECP384R1, 521: ec.SECP521R1}[bits]
    return ec.derive_private_key(0x794C000 + index, curve())


def certificate(label, public, serial, issuer=None, signer=None, role=None, depth=None, options=None):
    opts = options or {}
    subject = name(label, opts.get("name", "organization"))
    builder = (x509.CertificateBuilder().subject_name(subject)
               .issuer_name(subject if issuer is None else issuer.subject)
               .public_key(public.public_key()).serial_number(serial)
               .not_valid_before(date(opts.get("first", 2010))).not_valid_after(date(opts.get("last", 2100))))
    extensions = [
        (x509.SubjectKeyIdentifier.from_public_key(public.public_key()), False),
        (x509.AuthorityKeyIdentifier.from_issuer_public_key((signer or public).public_key()), False),
        (x509.KeyUsage(role is not None and opts.get("ds", True), False, False, False, False,
                       role is None and opts.get("cert-sign", True),
                       role is None and opts.get("crl-sign", True), False, False), True),
    ]
    if role is None:
        extensions.append((x509.BasicConstraints(ca=True, path_length=opts.get("depth", depth)), True))
    else:
        identity = opts.get("identity", IDS[role])
        extensions.extend([
            (x509.BasicConstraints(ca=False, path_length=None), False),
            (x509.SubjectAlternativeName([x509.UniformResourceIdentifier(identity), x509.DNSName(NAME)]), False),
            (x509.ExtendedKeyUsage(opts.get("eku", ([EKU.CLIENT_AUTH if role == "client" else EKU.SERVER_AUTH] if opts.get("role-eku") else [EKU.SERVER_AUTH if role == "client" else EKU.CLIENT_AUTH] if opts.get("other-role-eku") else [EKU.CLIENT_AUTH, EKU.SERVER_AUTH]))), False),
            (x509.CRLDistributionPoints([x509.DistributionPoint(
                [x509.UniformResourceIdentifier("ldap://crl.example.test/synthetic")], None, None, None)]), False),
        ])
    if opts.get("extra"):
        extensions.append(opts["extra"])
    for value, critical in extensions:
        if value.oid == opts.get("omit"):
            continue
        if value.oid == opts.get("critical"):
            critical = True
        if value.oid == opts.get("noncritical"):
            critical = False
        builder = builder.add_extension(value, critical)
    return builder.sign(signer or public, opts.get("hash", hashes.SHA256)(), ecdsa_deterministic=True)


def crl(issuer, signer, revoked=()):
    builder = (x509.CertificateRevocationListBuilder().issuer_name(issuer.subject)
               .last_update(date(2010)).next_update(date(2100))
               .add_extension(x509.CRLNumber(1), False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), False))
    for serial in revoked:
        builder = builder.add_revoked_certificate(x509.RevokedCertificateBuilder()
                    .serial_number(serial).revocation_date(date(2015)).build())
    return builder.sign(signer, hashes.SHA256(), ecdsa_deterministic=True).public_bytes(ENC)


def cases():
    result = [
        ("valid", "admit", {}),
        ("single-role-eku", "admit", {"leaf": {"role-eku": True}}),
        ("opposite-role-eku", "refuse", {"leaf": {"other-role-eku": True}}),
        ("anchor-expiry", "admit", {"root": {"last": 2050}}),
        ("p384", "admit", {"bits": (384, 384, 384)}),
        ("stronger-issuer", "admit", {"bits": (384, 384, 256)}),
        ("sha384", "admit", {"all": {"hash": hashes.SHA384}}),
        ("country-name", "admit", {"all": {"name": "country"}}),
        ("domain-name", "admit", {"all": {"name": "domain"}}),
        ("optional-eku-absent", "admit", {"leaf": {"omit": EXT.EXTENDED_KEY_USAGE}}),
        ("direct-tls-anchor", "admit", {"direct": True}),
        ("root-unlimited", "admit", {"root": {"depth": None}}),
        ("issuer-too-weak", "refuse", {"bits": (256, 256, 384)}),
        ("root-too-weak", "refuse", {"bits": (256, 384, 256)}),
        ("leaf-p224", "refuse", {"bits": (256, 256, 224)}),
        ("leaf-p521", "refuse", {"bits": (521, 521, 521)}),
        ("leaf-no-digital-signature", "refuse", {"leaf": {"ds": False}}),
        ("leaf-wrong-eku", "refuse", {"leaf": {"eku": [EKU.CODE_SIGNING]}}),
        ("leaf-any-eku", "refuse", {"leaf": {"eku": [EKU.ANY_EXTENDED_KEY_USAGE]}}),
        ("tls-ca-unlimited", "refuse", {"ca": {"depth": None}}),
        ("tls-ca-depth-one", "refuse", {"ca": {"depth": 1}}),
        ("root-depth-zero", "refuse", {"root": {"depth": 0}}),
        ("revoked-leaf", "refuse", {"revoked": True}),
        ("ambiguous-anchor", "refuse", {"ambiguous": True}),
    ]
    for scope in ["leaf", "ca", "root"]:
        for case, options in [
            ("missing-ku", {"omit": EXT.KEY_USAGE}),
            ("noncritical-ku", {"noncritical": EXT.KEY_USAGE}),
            ("critical-ski", {"critical": EXT.SUBJECT_KEY_IDENTIFIER}),
            ("critical-aki", {"critical": EXT.AUTHORITY_KEY_IDENTIFIER}),
            ("missing-organization", {"name": "missing-organization"}),
            ("printable-organization", {"name": "printable-organization"}),
            ("extra-name", {"name": "extra-name"}),
            ("wrong-name-order", {"name": "wrong-order"}),
            ("sha512", {"hash": hashes.SHA512}),
            ("expired", {"last": 2020}),
            ("future", {"first": 2090}),
            ("unknown-critical", {"extra": (x509.UnrecognizedExtension(
                x509.ObjectIdentifier("1.3.6.1.4.1.55555.794"), b"\x05\x00"), True)}),
        ]:
            result.append((scope + "-" + case, "refuse", {scope: options}))
    for scope in ["ca", "root"]:
        for case, options in [
            ("missing-bc", {"omit": EXT.BASIC_CONSTRAINTS}),
            ("noncritical-bc", {"noncritical": EXT.BASIC_CONSTRAINTS}),
            ("missing-cert-sign", {"cert-sign": False}),
            ("missing-crl-sign", {"crl-sign": False}),
        ]:
            result.append((scope + "-" + case, "refuse", {scope: options}))
    for case, options in [
        ("missing-crldp", {"omit": EXT.CRL_DISTRIBUTION_POINTS}),
        ("critical-crldp", {"critical": EXT.CRL_DISTRIBUTION_POINTS}),
        ("critical-eku", {"critical": EXT.EXTENDED_KEY_USAGE}),
        ("critical-san", {"critical": EXT.SUBJECT_ALTERNATIVE_NAME}),
        ("critical-leaf-bc", {"critical": EXT.BASIC_CONSTRAINTS}),
    ]:
        result.append((case, "refuse", {"leaf": options}))
    return result


def vector(role, case, expected, opts):
    bits = opts.get("bits", (256, 256, 256))
    root_key, ca_key, leaf_key = [key(i, b) for i, b in enumerate(bits)]
    common = opts.get("all", {})
    root_opts, ca_opts, leaf_opts = [common | opts.get(scope, {}) for scope in ["root", "ca", "leaf"]]
    prefix = role + " NDS synthetic "
    root = certificate(prefix + "root", root_key, 100, depth=1, options=root_opts)
    ca = certificate(prefix + "TLS CA", ca_key, 101, root, root_key, depth=0, options=ca_opts)
    direct = opts.get("direct", False)
    if direct:
        root = certificate(prefix + "root", root_key, 100, depth=0, options=root_opts)
        ca, ca_key = root, root_key
    leaf = certificate(prefix + "entity", leaf_key, 102, ca, ca_key, role=role, options=leaf_opts)
    roots = [root.public_bytes(ENC)]
    if opts.get("ambiguous"):
        roots.append(certificate(prefix + "root", root_key, 199, depth=2).public_bytes(ENC))
    lists = [crl(ca, ca_key, [102] if opts.get("revoked") else [])]
    if not direct:
        lists.append(crl(root, root_key))
    private = leaf_key.private_bytes(ENC, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return (role, case, expected, leaf.public_bytes(ENC).hex(), private.hex(),
            "" if direct else ca.public_bytes(ENC).hex(), ",".join(v.hex() for v in roots),
            ",".join(v.hex() for v in lists))


def check_name(value):
    assert all(len(rdn) == 1 for rdn in value.rdns)
    attrs = list(value)
    types = [attr.oid for attr in attrs]
    assert all(attr.value for attr in attrs)
    if types in [[DN.ORGANIZATION_NAME, DN.COMMON_NAME], [DN.COUNTRY_NAME, DN.ORGANIZATION_NAME, DN.COMMON_NAME]]:
        for attr in attrs:
            if attr.oid == DN.COUNTRY_NAME:
                assert attr._type.name == "PrintableString" and len(attr.value) == 2 and attr.value.isascii() and attr.value.isalpha()
            else:
                assert attr._type.name == "UTF8String"
    else:
        domains = 0
        for attr in attrs:
            if attr.oid != DN.DOMAIN_COMPONENT:
                break
            assert attr._type.name == "IA5String" and 1 <= len(attr.value) <= 63
            assert attr.value.isascii() and all(c.isalnum() or c == "-" for c in attr.value)
            assert not attr.value.startswith("-") and not attr.value.endswith("-")
            domains += 1
        assert domains >= 2 and types[domains:] in [[DN.COMMON_NAME], [DN.ORGANIZATIONAL_UNIT_NAME, DN.COMMON_NAME]]
        assert all(a._type.name == "UTF8String" for a in attrs[domains:])


def classify(row):
    role, _, _, leaf, _, intermediate, roots, lists = row
    try:
        anchors = [x509.load_der_x509_certificate(bytes.fromhex(v)) for v in roots.split(",")]
        assert len(anchors) == 1
        certs = [x509.load_der_x509_certificate(bytes.fromhex(leaf))]
        if intermediate:
            certs.append(x509.load_der_x509_certificate(bytes.fromhex(intermediate)))
        certs += anchors
        crls = [x509.load_der_x509_crl(bytes.fromhex(v)) for v in lists.split(",")]
        usage = EKU.CLIENT_AUTH if role == "client" else EKU.SERVER_AUTH
        for position, cert in enumerate(certs):
            assert cert.version == x509.Version.v3
            assert cert.signature_algorithm_oid.dotted_string in ["1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3"]
            assert isinstance(cert.public_key(), ec.EllipticCurvePublicKey)
            assert cert.public_key().curve.name in ["secp256r1", "secp384r1"]
            check_name(cert.subject)
            check_name(cert.issuer)
            assert cert.not_valid_before_utc <= date(2026) < cert.not_valid_after_utc
            ca = position > 0
            for extension in cert.extensions:
                assert extension.critical == (extension.oid == EXT.KEY_USAGE or (ca and extension.oid == EXT.BASIC_CONSTRAINTS))
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
            if ca:
                bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
                assert ku.key_cert_sign and ku.crl_sign and bc.ca
                assert (bc.path_length == 0 if position == 1 else bc.path_length is None or bc.path_length >= position - 1)
            else:
                assert ku.digital_signature
                points = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
                assert len(points) and all(p.full_name or p.relative_name for p in points)
                assert all(p.reasons is None and p.crl_issuer is None for p in points)
            try:
                assert usage in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            except x509.ExtensionNotFound:
                pass
        for child, issuer in zip(certs, certs[1:]):
            assert child.issuer == issuer.subject
            assert issuer.public_key().key_size >= child.public_key().key_size
            issuer.public_key().verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
            crl_value = next(v for v in crls if v.issuer == issuer.subject)
            issuer.public_key().verify(crl_value.signature, crl_value.tbs_certlist_bytes, ec.ECDSA(crl_value.signature_hash_algorithm))
            assert crl_value.get_revoked_certificate_by_serial_number(child.serial_number) is None
        return "admit"
    except (ValueError, AssertionError, InvalidSignature, x509.ExtensionNotFound, StopIteration):
        return "refuse"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    rows = [vector(role, case, expected, opts) for role in ["client", "server"] for case, expected, opts in cases()]
    for row in rows:
        assert classify(row) == row[2], row[:3]
    content = ("# PUBLIC synthetic deterministic keys; NEVER use outside tests.\n"
               "# role\tcase\texpected\tleaf_der\tpkcs8\tintermediate_der\troot_der_csv\tcrl_der_csv\n"
               + "".join("\t".join(row) + "\n" for row in rows))
    path = Path(__file__).with_suffix(".tsv")
    if args.write:
        path.write_text(content)
    else:
        assert path.read_text() == content
    admitted = sum(row[2] == "admit" for row in rows)
    print(f"{len(rows)} cases: {admitted} admissions, {len(rows) - admitted} refusals; sha256 {hashlib.sha256(content.encode()).hexdigest()}")


if __name__ == "__main__":
    main()
