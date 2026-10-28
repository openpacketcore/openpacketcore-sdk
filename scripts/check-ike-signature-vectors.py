#!/usr/bin/env python3
"""Verify committed IKE signature vectors with OpenSSL, independently of Rust."""

from pathlib import Path
import os
import subprocess
import tempfile


DATA = Path(__file__).resolve().parents[1] / "crates/opc-proto-ikev2/tests/data"
OPENSSL = os.environ.get("OPENSSL", "openssl")


def run(*args, succeeds=True):
    result = subprocess.run([OPENSSL, *map(str, args)], capture_output=True, check=False)
    if (result.returncode == 0) != succeeds:
        raise RuntimeError(f"OpenSSL result differed for {args}: {result.stderr.decode()}")
    return result.stdout


def der(tag, value):
    size = len(value)
    length = bytes([size]) if size < 128 else bytes([0x81, size])
    return bytes([tag]) + length + value


def main():
    with tempfile.TemporaryDirectory(prefix="opc-ike-vectors-") as directory:
        tmp = Path(directory)
        public = tmp / "public.pem"
        for key in ("p521", "rfc8032_ed25519"):
            derived = run("pkey", "-inform", "DER", "-in", DATA / f"{key}_pkcs8.der", "-pubout", "-outform", "DER")
            if derived != (DATA / f"{key}_spki.der").read_bytes():
                raise RuntimeError(f"Public fixture does not match {key} private fixture")
        public.write_bytes(run("pkey", "-pubin", "-inform", "DER", "-in", DATA / "rsa2048_spki.der", "-pubout"))
        for label, digest, salt, mgf in [
            ("sha256", "sha256", 32, "sha256"),
            ("sha384", "sha384", 48, "sha384"),
            ("sha512", "sha512", 64, "sha512"),
            ("wrong_salt", "sha256", 20, "sha256"),
            ("wrong_mgf", "sha256", 32, "sha384"),
        ]:
            args = ["dgst", "-" + digest, "-verify", public, "-signature", DATA / f"rsa_pss_{label}.sig", "-sigopt", "rsa_padding_mode:pss", "-sigopt", f"rsa_pss_saltlen:{salt}", "-sigopt", f"rsa_mgf1_md:{mgf}"]
            run(*args, DATA / "rsa_pss_message.bin")
            if label.startswith("wrong_"):
                run(*args, "-sigopt", "rsa_pss_saltlen:32", "-sigopt", "rsa_mgf1_md:sha256", DATA / "rsa_pss_message.bin", succeeds=False)

        message = tmp / "message.bin"
        message.write_bytes(b"r")
        signature = run("pkeyutl", "-sign", "-rawin", "-inkey", DATA / "rfc8032_ed25519_pkcs8.der", "-keyform", "DER", "-in", message)
        if signature != (DATA / "ed25519_rfc8032.sig").read_bytes():
            raise RuntimeError("Ed25519 signature differs from RFC 8032 section 7.1 test 2")
        run("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", DATA / "rfc8032_ed25519_spki.der", "-keyform", "DER", "-in", message, "-sigfile", DATA / "ed25519_rfc8032.sig")

        # RFC 4754 section 8 signs 'abc'; its fixed-width r || s is converted
        # independently to the DER representation consumed by OpenSSL.
        for curve, digest, curve_oid in [
            (256, "sha256", "2a8648ce3d030107"),
            (384, "sha384", "2b81040022"),
            (521, "sha512", "2b81040023"),
        ]:
            point = (DATA / f"rfc4754_p{curve}_public.bin").read_bytes()
            raw = (DATA / f"rfc4754_p{curve}_signature.bin").read_bytes()
            width = (curve + 7) // 8
            if len(raw) != 2 * width or len(point) != 1 + 2 * width:
                raise RuntimeError(f"Wrong RFC 4754 width for P-{curve}")
            algorithm = der(0x30, bytes.fromhex("06072a8648ce3d0201") + der(6, bytes.fromhex(curve_oid)))
            spki = tmp / "ec.der"
            spki.write_bytes(der(0x30, algorithm + der(3, b"\0" + point)))
            public.write_bytes(run("pkey", "-pubin", "-inform", "DER", "-in", spki, "-pubout"))
            scalars = []
            for scalar in (raw[:width], raw[width:]):
                scalar = scalar.lstrip(b"\0")
                if scalar[0] & 0x80:
                    scalar = b"\0" + scalar
                scalars.append(der(2, scalar))
            sig = tmp / "ec.sig"
            sig.write_bytes(der(0x30, b"".join(scalars)))
            message.write_bytes(b"abc")
            run("dgst", "-" + digest, "-verify", public, "-signature", sig, message)
            message.write_bytes(b"abd")
            run("dgst", "-" + digest, "-verify", public, "-signature", sig, message, succeeds=False)
    print("IKE signature vectors: OpenSSL positive and negative checks passed")


if __name__ == "__main__":
    main()
