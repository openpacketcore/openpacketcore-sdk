#!/usr/bin/env python3
"""Independent RFC 6066 section 3 names and protected DTLS 1.2 Hellos.

Explicit expected outcomes describe the SDK's single exact-name profile.
Python struct and AES-GCM author the bytes independently of dimpl. Synthetic
record keys exercise production Hello parsing, not certificate authentication.
"""
import argparse
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from rfc6083_record_reference import prf


def u16(value):
    return value.to_bytes(2, "big")


def name_body(name):
    entry = b"\0" + u16(len(name)) + name
    return u16(len(entry)) + entry


def render():
    name = b"amf.example.test"
    good = name_body(name)
    cases = []

    def add(role, configured, label, bodies, admitted):
        extensions = b"".join(b"\0\0" + u16(len(body)) + body for body in bodies)
        cases.append((role, configured, label, extensions, admitted))

    for configured in (name.decode(), "-"):
        for label, bodies, named in [
            ("missing", [], False), ("empty-ack", [b""], True),
            ("nonempty-ack", [b"\0"], False),
            ("name-in-ack", [good], False), ("duplicate", [b"", b""], False),
        ]:
            add("client", configured, label, bodies,
                named if configured != "-" else label == "missing")

    for configured in (name.decode(), "-"):
        add("server", configured, "missing", [], configured == "-")
        add("server", configured, "valid", [good], True)
        add("server", configured, "mixed-case", [name_body(b"AMF.Example.TEST")], True)
        add("server", configured, "other-name", [name_body(b"other.example.test")], configured == "-")
        add("server", configured, "duplicate", [good, good], False)
        entries = good[2:] * 2
        add("server", configured, "duplicate-host", [u16(len(entries)) + entries], False)
        entries = good[2:] + b"\x01\x00\x01a"
        add("server", configured, "unknown-second-type", [u16(len(entries)) + entries], False)
        for length in range(len(good)):
            add("server", configured, f"truncated-{length}", [good[:length]], False)
        for offset in range(5):
            changed = bytearray(good)
            changed[offset] ^= 1
            add("server", configured, f"field-{offset}", [bytes(changed)], False)
        add("server", configured, "trailing", [good + b"\0"], False)
        for label, invalid in [
            ("empty-host", b""), ("wildcard", b"*.example.test"),
            ("ipv4", b"127.0.0.1"), ("ipv6", b"::1"), ("trailing-dot", name + b"."),
            ("empty-label", b"a..test"), ("leading-hyphen", b"-a.test"),
            ("trailing-hyphen", b"a-.test"), ("underscore", b"a_b.test"),
            ("nul", b"a\0.test"), ("non-ascii", b"a\xff.test"),
            ("space", b"a b.test"), ("long-label", b"a" * 64 + b".test"),
            ("long-name", b".".join([b"a" * 63] * 3 + [b"b" * 62])),
        ]:
            add("server", configured, label, [name_body(invalid)], False)
    for value in [b"a", b"xn--bcher-kva.example", b".".join([b"a" * 63] * 3 + [b"b" * 61])]:
        add("server", value.decode(), "accepted-boundary", [name_body(value)], True)

    master = prf(b"\x00\x20" + bytes(32) + b"\x00\x20" + bytes([0xA5]) * 32,
                 b"extended master secret", bytes([0x11]) * 32, 48)
    block = prf(master, b"key expansion", bytes([0x33]) * 32 + bytes([0x22]) * 32, 40)
    rows = ["# receiver\tconfigured\tcase\tadmit\textensions_hex\tprotected_record_hex"]
    for role, configured, label, sni, admitted in cases:
        binding = bytes(range(12)) + (bytes(range(240, 252)) if role == "client" else b"")
        ri = bytes([len(binding)]) + binding
        extensions = b"\x00\x17\x00\x00\xff\x01" + u16(len(ri)) + ri + sni
        body = b"\xfe\xfd" + bytes([0x42]) * 32 + b"\0"
        body += b"\x00\x00\x02\xc0\x2b\x01\x00" if role == "server" else b"\xc0\x2b\x00"
        body += u16(len(extensions)) + extensions
        length = len(body).to_bytes(3, "big")
        handshake = bytes([1 if role == "server" else 2]) + length + bytes(5) + length + body
        number = b"\x00\x01" + (1).to_bytes(6, "big")
        aad = number + b"\x16\xfe\xfd" + u16(len(handshake))
        key = block[:16] if role == "server" else block[16:32]
        iv = block[32:36] if role == "server" else block[36:40]
        fragment = number + AESGCM(key).encrypt(iv + number, handshake, aad)
        record = b"\x16\xfe\xfd" + number + u16(len(fragment)) + fragment
        rows.append(f"{role}\t{configured}\t{label}\t{int(admitted)}\t{sni.hex() or '-'}\t{record.hex()}")
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = Path(__file__).with_suffix(".tsv")
    expected = render()
    if args.check:
        if path.read_text() != expected:
            raise SystemExit("independent RFC 6066 fixtures differ")
    else:
        path.write_text(expected)
    print(f"{len(expected.splitlines()) - 1} SNI extension/protected Hello fixtures; sha256=" +
          hashlib.sha256(expected.encode()).hexdigest())
