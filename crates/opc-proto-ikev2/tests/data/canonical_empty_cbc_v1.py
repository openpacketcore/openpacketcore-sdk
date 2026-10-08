#!/usr/bin/env python3
"""Independently qualify and reproduce canonical CBC-V1 known answers.

Requires Python cryptography (OpenSSL backend) and NIST's IKEv2 archive:
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/800-135testvectors/ikev2.zip

Usage: python3 canonical_empty_cbc_v1.py IKEV2_ARCHIVE [--create]
--create writes only an absent fixture. It never replaces frozen bytes.
This tool imports neither SDK code nor reviewer-generated expected packets.
All published-vector checks finish before any CBC-V1 packet is calculated.
"""

import argparse
import hashlib
import hmac
import json
import platform
import struct
import zipfile
from collections import Counter
from pathlib import Path

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

NIST_ARCHIVE_SHA256 = "813c9fa9bf99a78659143d1898b3adffd09ad235be1580cf0ba8cd3663ae2950"


def hx(value):
    return bytes.fromhex(value)


def encrypt(key, plaintext, iv=None):
    mode = modes.ECB() if iv is None else modes.CBC(iv)
    operation = Cipher(algorithms.AES(key), mode).encryptor()
    return operation.update(plaintext) + operation.finalize()


def decrypt(key, ciphertext, iv=None):
    mode = modes.ECB() if iv is None else modes.CBC(iv)
    operation = Cipher(algorithms.AES(key), mode).decryptor()
    return operation.update(ciphertext) + operation.finalize()


def prf(name, key, data):
    return hmac.digest(key, data, name)


def prf_plus(name, key, seed, length):
    block_size = hashlib.new(name).digest_size
    assert 0 <= length <= 255 * block_size
    previous, stream = b"", b""
    for counter in range(1, (length + block_size - 1) // block_size + 1):
        previous = prf(name, key, previous + seed + bytes([counter]))
        stream += previous
    return stream[:length]


def qualify_published():
    counts = Counter()

    def aes_case(source, key, plaintext, ciphertext, iv=None):
        assert encrypt(key, plaintext, iv) == ciphertext, source
        assert decrypt(key, ciphertext, iv) == plaintext, source
        counts[source] += 2

    # FIPS 197 (2001) Appendix C.1-C.3.
    for width, expected in (
        (16, "69c4e0d86a7b0430d8cdb78070b4c55a"),
        (24, "dda97ca4864cdfe06eaf70a0ec0d7191"),
        (32, "8ea2b7ca516745bfeafc49904b496089"),
    ):
        aes_case("FIPS197-C", bytes(range(width)),
                 hx("00112233445566778899aabbccddeeff"), hx(expected))

    # SP 800-38A F.1.1-F.1.6 and F.2.1-F.2.6, all four blocks.
    plaintext = hx(
        "6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51 "
        "30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710")
    iv = bytes(range(16))
    for key, ecb, cbc in (
        ("2b7e151628aed2a6abf7158809cf4f3c",
         "3ad77bb40d7a3660a89ecaf32466ef97 f5d3d58503b9699de785895a96fdbaaf "
         "43b1cd7f598ece23881b00e3ed030688 7b0c785e27e8ad3f8223207104725dd4",
         "7649abac8119b246cee98e9b12e9197d 5086cb9b507219ee95db113a917678b2 "
         "73bed6b8e3c1743b7116e69e22229516 3ff1caa1681fac09120eca307586e1a7"),
        ("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
         "bd334f1d6e45f25ff712a214571fa5cc 974104846d0ad3ad7734ecb3ecee4eef "
         "ef7afd2270e2e60adce0ba2face6444e 9a4b41ba738d6c72fb16691603c18e0e",
         "4f021db243bc633d7178183a9fa071e8 b4d9ada9ad7dedf4e5e738763f69145a "
         "571b242012fb7ae07fa9baac3df102e0 08b0e27988598881d920a9e64f5615cd"),
        ("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
         "f3eed1bdb5d2a03c064b5a7e3db181f8 591ccb10d410ed26dc5ba74a31362870 "
         "b6ed21b99ca6f4f9f153e7b1beafed1d 23304b7a39f9f3ff067d8d8f9e24ecc7",
         "f58c4c04d6e5f1ba779eabfb5f7bfbd6 9cfc4e967edb808d679f777bc6702c7d "
         "39f23369a9d9bacfa530e26304231461 b2eb05e2c39be9fcda6c19078c6a9d1b"),
    ):
        aes_case("SP800-38A-F1", hx(key), plaintext, hx(ecb))
        aes_case("SP800-38A-F2", hx(key), plaintext, hx(cbc), iv)

    # RFC 3602 section 4 cases 1-4; its ESP packet format is not used by IKE.
    for key, iv, plaintext, ciphertext in (
        ("06a9214036b8a15b512e03d534120006", "3dafba429d9eb430b422da802c9fac41",
         b"Single block msg", "e353779c1079aeb82708942dbe77181a"),
        ("c286696d887c9aa0611bbb3e2025a45a", "562e17996d093d28ddb3ba695a2e6f58",
         bytes(range(32)), "d296cd94c2cccf8a3a863028b5e1dc0a7586602d253cfff91b8266bea6d61ab1"),
        ("6c3ea0477630ce21a2ce334aa746c2cd", "c782dc4c098c66cbd9cd27d825682c81",
         b"This is a 48-byte message (exactly 3 AES blocks)",
         "d0a02b3836451753d493665d33f0e8862dea54cdb293abc7506939276772f8d5"
         "021c19216bad525c8579695d83ba2684"),
        ("56e47a38c5598974bc46903dba290349", "8ce82eefbea0da3c44699ed7db51b7d9",
         bytes(range(0xa0, 0xe0)),
         "c30e32ffedc0774e6aff6af0869f71aa0f3af07a9a31a9c684db207eb0ef8e4e"
         "35907aa632c3ffdf868bb7b29d3d46ad83ce9f9a102ee99d49a53e87f4c3da55"),
    ):
        aes_case("RFC3602-4", hx(key), plaintext, hx(ciphertext), hx(iv))

    # RFC 2202 case 1 and RFC 4231 case 1 / RFC 4868 PRF-1.
    for name, expected in (
        ("sha1", "b617318655057264e28bc0b6fb378c8ef146be00"),
        ("sha256", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        ("sha384", "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c"
         "faea9ea9076ede7f4af152e8b2fa9cb6"),
        ("sha512", "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
         "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"),
    ):
        assert prf(name, b"\x0b" * 20, b"Hi There") == hx(expected), name
        counts["RFC2202-4231-4868-PRF"] += 1

    for name, keylen, taglen, expected in (
        ("sha256", 32, 16, "198a607eb44bfbc69903a0f1cf2bbdc5"),
        ("sha384", 48, 24, "b6a8d5636f5c6a7224f9977dcf7ee6c7fb6d0c48cbdee973"),
        ("sha512", 64, 32, "637edc6e01dce7e6742a99451aae82df23da3e92439e590e43e761b33e910fb8"),
    ):
        assert prf(name, b"\x0b" * keylen, b"Hi There")[:taglen] == hx(expected)
        counts["RFC4868-AUTH"] += 1
    assert prf("sha1", b"\x0c" * 20, b"Test With Truncation")[:12] == hx(
        "4c1a03424b55e07fe7f27be1")
    counts["RFC2202-2404-SHA1-96"] += 1

    # SDK-pinned independent prf+ and full-message fixtures, copied as literals.
    assert prf_plus("sha1", b"\x0b" * 20, b"Hi There", 60) == hx(
        "29e6e7119ecc3640f21fd6bd787a4a512a309f870712afe9b04b22bc233fa36f1766a6750ea37cb0"
        "74047bec7a361429df72abf51101d23b75b4d2ca")
    ni, nr = bytes(range(32)), bytes(range(0xa0, 0xc0))
    skeyseed = prf("sha512", ni + nr, bytes(range(256)))
    assert skeyseed == hx(
        "be6bee7f3a87542831303538d74f1d0f3a0a43476538969db0ec73b87ca2e732"
        "9246e4c25cfc6d20dff6081d6305e18d2b0bf073ecef0b8b97354a865faf0374")
    spis = hx("01020304050607081112131415161718")
    assert prf_plus("sha512", skeyseed, ni + nr + spis, 384) == hx(
        "3a6780f9b7988b52b3640daa79e5b31254c8626ef3a8d5a99ea2a9eaa2d16b8b"
        "729b3469ef799357a90ce554942c209bf192c8f39295b727a9eb1681a097f89e"
        "77f1ee6d2350595a0de2a98b516ad4d7271c6ead856cdd0b41cff6cbe70378c6"
        "4dd8d0f6ddc99175e5d24b280ff06533aa5b1e2883480a55bdf00c91c5965eed"
        "19973371058ed48a8aca918ea0ca6558db708cf43dedc71346087d26571312c2"
        "3804aa1862746430c0831684b6f2d0609835a49860704d9de9603633e3f30652"
        "e8d7681465f7bb4b2a38526b8d6d9e85b07f4d02038a30cc629af84f1beea3d1"
        "05bbff5bbdb0e310ca533a87326779a8438d70b699d27514ef0bffe69d286405"
        "5f5ca92e01d475e94bcf891d030ad5375af225315d7a0538416dd5e6fa9b3c92"
        "a91ac1f1745ad930d43985490e04ce2031503ba369809d3ce5fd812fe762c54e"
        "ab498746f6e2f55fd41801101a531174d6f0e5bc7a0b50bb5b205cec3717176c"
        "bd2cdf6ffe4de67d396d83877e958c214fe84e6766788041bc906d90bbeea9eb")
    counts["SDK-prf-plus"] += 3
    prefix = hx("010203040506070811121314151617182e202308000000010000006023000044")
    iv = bytes(range(0xa0, 0xb0))
    plaintext = hx("0000000801020304") + bytes(7) + b"\x07"
    ciphertext = encrypt(bytes(range(0x40, 0x60)), plaintext, iv)
    assert ciphertext == hx("20c0fc6c0a479a0c6c084eae4dc1b303")
    assert prf("sha512", bytes(range(64)), prefix + iv + ciphertext)[:32] == hx(
        "f247045d7dbfa00fea352a456097fd6db341db4b46adda5e55e2f1963953462b")
    assert decrypt(bytes(range(0x40, 0x60)), ciphertext, iv) == plaintext
    counts["SDK-complete-message"] += 3
    return counts


def qualify_cavp(archive):
    # The CAVP SKEYSEED and DKM fields independently test HMAC and prf+.
    counts, skipped = Counter(), Counter()
    name, case = None, {}

    def check():
        if not case:
            return
        if name not in ("sha1", "sha256", "sha384", "sha512"):
            skipped[name] += 1
            return
        ni, nr = hx(case["Ni"]), hx(case["Nr"])
        skeyseed = prf(name, ni + nr, hx(case["g^ir"]))
        assert skeyseed == hx(case["SKEYSEED"]), (name, case["COUNT"], "SKEYSEED")
        expected = hx(case["DKM"])
        seed = ni + nr + hx(case["SPIi"]) + hx(case["SPIr"])
        assert prf_plus(name, skeyseed, seed, len(expected)) == expected, (
            name, case["COUNT"], "DKM")
        counts[name] += 1

    with zipfile.ZipFile(archive) as inputs:
        for line in inputs.read("ikev2.rsp").decode("ascii").splitlines() + [""]:
            line = line.strip()
            if not line:
                check()
                case = {}
            elif line.startswith("[SHA-"):
                assert not case
                name = line[1:-1].lower().replace("-", "")
            elif not line.startswith(("[", "#")):
                key, value = line.split(" = ", 1)
                case[key] = value
    assert counts == {"sha1": 40, "sha256": 60, "sha384": 60, "sha512": 60}
    assert skipped == {"sha224": 60}
    return dict(counts), dict(skipped)


def canonical_rows():
    spis = hx("01020304050607081112131415161718")
    rows = ["# CBC-V1: bits integ prf direction message_id sk_d sk_e sk_a k_iv iv full_ike_wire"]
    for bits in (128, 192, 256):
        for integ, mac_name, taglen in ((2, "sha1", 12), (12, "sha256", 16),
                                       (13, "sha384", 24), (14, "sha512", 32)):
            for prf_id, prf_name in ((2, "sha1"), (5, "sha256"), (6, "sha384"), (7, "sha512")):
                sk_d = bytes((0xd0 + i) & 0xff for i in range(hashlib.new(prf_name).digest_size))
                for direction, enc_start, mac_start in ((0, 0, 0x80), (1, 0x40, 0x20)):
                    sk_e = bytes(range(enc_start, enc_start + bits // 8))
                    sk_a = bytes(range(mac_start, mac_start + hashlib.new(mac_name).digest_size))
                    seed = (b"opc-ikev2-canonical-cbc-iv-key-v1\0" + spis
                            + struct.pack("!BHHHHB", direction, 12, bits, integ, prf_id, 1))
                    assert len(seed) == 60
                    k_iv = prf_plus(prf_name, sk_d, seed, bits // 8)
                    for message_id in (0, 1, 0x12345678, 0xffffffff):
                        block = b"opc-cbc-iv-1" + message_id.to_bytes(4, "big")
                        iv = encrypt(k_iv, block)
                        assert encrypt(k_iv, block, bytes(16)) == iv
                        assert decrypt(k_iv, iv, bytes(16)) == block
                        prefix = spis + struct.pack("!BBBBIIBBH", 46, 0x20, 37,
                                                    0x28 if direction == 0 else 0x20,
                                                    message_id, 64 + taglen, 0, 0, 36 + taglen)
                        ciphertext = encrypt(sk_e, bytes(15) + b"\x0f", iv)
                        mac_input = prefix + iv + ciphertext
                        tag = prf(mac_name, sk_a, mac_input)[:taglen]
                        packet = mac_input + tag
                        assert len(packet) == 64 + taglen
                        assert decrypt(sk_e, ciphertext, iv) == bytes(15) + b"\x0f"
                        rows.append(f"{bits} {integ} {prf_id} {'I' if direction == 0 else 'R'} "
                                    f"{message_id:08x} {sk_d.hex()} {sk_e.hex()} {sk_a.hex()} "
                                    f"{k_iv.hex()} {iv.hex()} {packet.hex()}")
    assert len(rows) == 385
    return "\n".join(rows) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--create", action="store_true")
    args = parser.parse_args()
    assert __debug__, "qualification requires assertions; do not run with -O"
    assert hashlib.sha256(args.archive.read_bytes()).hexdigest() == NIST_ARCHIVE_SHA256
    published = qualify_published()
    cavp, skipped = qualify_cavp(args.archive)
    # Deliberately after every independently pinned check above.
    contents = canonical_rows()
    target = Path(__file__).resolve().parents[2] / "src/canonical/cbc_v1.txt"
    if args.create and not target.exists():
        with target.open("x", encoding="ascii") as destination:
            destination.write(contents)
    assert target.read_text(encoding="ascii") == contents, "CBC-V1 changed: never replace fixtures"
    report = {
        "tool": "tests/data/canonical_empty_cbc_v1.py",
        "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "python": platform.python_version(), "cryptography": cryptography.__version__,
        "openssl": backend.openssl_version_text(),
        "nist_ikev2_source": "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/800-135testvectors/ikev2.zip",
        "nist_ikev2_sha256": hashlib.sha256(args.archive.read_bytes()).hexdigest(),
        "published_checks": dict(published), "cavp_skeyseed_and_dkm_cases": cavp,
        "cavp_skipped_not_supported_by_sdk": skipped,
        "profile_triples": 48, "cbc_v1_vectors": 384,
        "cbc_v1_sha256": hashlib.sha256(contents.encode("ascii")).hexdigest(),
        "qualification_preceded_cbc_v1_calculation": True,
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
