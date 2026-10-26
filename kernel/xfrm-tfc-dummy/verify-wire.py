#!/usr/bin/env python3
"""Independently authenticate/decrypt the public-fixture ESP captures using OpenSSL."""

import argparse
from collections import Counter
import hashlib
import hmac
import json
from pathlib import Path
import platform
import struct
import sys

import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


if sys.flags.optimize:
    raise RuntimeError("qualification requires Python assertions enabled")


def self_check():
    # GCM specification test case 2; SP800-38A F.2.1 first block; RFC4231 case 1.
    assert (
        AESGCM(bytes(16)).encrypt(bytes(12), bytes(16), None).hex()
        == "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"
    )
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    cipher = Cipher(algorithms.AES(key), modes.CBC(bytes(range(16)))).encryptor()
    assert (
        cipher.update(plain) + cipher.finalize()
    ).hex() == "7649abac8119b246cee98e9b12e9197d"
    assert (
        hmac.digest(bytes([11]) * 20, b"Hi There", "sha256").hex()
        == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    )


def checksum(data):
    padded = data + bytes(len(data) % 2)
    total = sum(struct.unpack("!%dH" % (len(padded) // 2), padded))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def ip_body(packet):
    if packet[0] >> 4 == 4:
        header = (packet[0] & 15) * 4
        length = int.from_bytes(packet[2:4], "big")
        assert checksum(packet[:header]) == 65535
        protocol = packet[9]
    else:
        assert packet[0] >> 4 == 6
        header, length, protocol = (
            40,
            40 + int.from_bytes(packet[4:6], "big"),
            packet[6],
        )
    assert header <= length <= len(packet)
    return protocol, packet[header:length], length


def verify(record):
    count = record["expected_dummy"] + record["expected_control"]
    assert len(record["wire"]) == count
    assert record["udp"] == [b"control".hex()] * record["expected_control"]
    assert all(not record[field] for field in ("raw59", "plaintext59", "icmp_errors"))
    start = (
        (7 << 32) + 0xFFFFFFFE
        if record["scenario"] == "esn"
        else (0xFFFFFFFE if record["scenario"] == "wrap" else 0)
    )
    sequence_numbers = list(range(start + 1, start + 1 + count))
    expected = {sequence & 0xFFFFFFFF: sequence >> 32 for sequence in sequence_numbers}
    seen, ivs, headers, lengths = [], [], [], []
    for encoded in record["wire"]:
        packet = bytes.fromhex(encoded)
        protocol, esp, length = ip_body(packet)
        assert length == len(packet)
        if record["scenario"] == "natt":
            assert protocol == 17 and esp[:4] == struct.pack("!HH", 4500, 4500)
            assert int.from_bytes(esp[4:6], "big") == len(esp)
            if packet[0] >> 4 == 6:
                assert esp[6:8] != bytes(2)
                pseudo = (
                    packet[8:40] + len(esp).to_bytes(4, "big") + bytes(3) + bytes([17])
                )
                assert checksum(pseudo + esp) == 65535
            elif esp[6:8] != bytes(2):
                pseudo = packet[12:20] + bytes([0, 17]) + len(esp).to_bytes(2, "big")
                assert checksum(pseudo + esp) == 65535
            esp = esp[8:]
        else:
            assert protocol == 50
        spi, sequence = struct.unpack("!II", esp[:8])
        assert spi == 0x124400 and sequence in expected
        seen.append(sequence)
        high = expected[sequence]
        esn = record["scenario"] == "esn"
        if record["algorithm"] == "gcm":
            iv = esp[8:16]
            aad = esp[:4] + struct.pack("!II", high, sequence) if esn else esp[:8]
            cipher = AESGCM(bytes(range(16)))
            nonce = bytes(range(16, 20)) + iv
            plain = cipher.decrypt(nonce, esp[16:], aad)
            corrupt = esp[16:-1] + bytes([esp[-1] ^ 1])
            try:
                cipher.decrypt(nonce, corrupt, aad)
            except cryptography.exceptions.InvalidTag:
                pass
            else:
                raise AssertionError("corrupted GCM authentication tag accepted")
        else:
            iv = esp[8:24]
            authenticated = esp[:-16] + (struct.pack("!I", high) if esn else b"")
            tag = hmac.digest(bytes(range(32)), authenticated, "sha256")[:16]
            assert hmac.compare_digest(tag, esp[-16:])
            assert not hmac.compare_digest(tag, esp[-16:-1] + bytes([esp[-1] ^ 1]))
            cipher = Cipher(algorithms.AES(bytes(range(16))), modes.CBC(iv)).decryptor()
            plain = cipher.update(esp[24:-16]) + cipher.finalize()
        ivs.append(iv)
        padding, header = plain[-2:]
        assert padding + 2 <= len(plain)
        assert plain[len(plain) - 2 - padding : -2] == bytes(range(1, padding + 1))
        body = plain[: len(plain) - padding - 2]
        headers.append(header)
        if record["mode"] == "tunnel":
            inner_protocol, payload, inner_length = ip_body(body)
            assert body[inner_length:] == bytes(len(body) - inner_length)
            assert inner_protocol == (59 if header == 59 else 17)
            assert header in (59, 4 if record["family"] == 2 else 41)
        else:
            payload = body
            assert header in (59, 17)
        if header == 59:
            assert payload == bytes(len(payload))
            lengths.append(len(payload))
        else:
            assert int.from_bytes(payload[2:4], "big") == 9000
            assert int.from_bytes(payload[4:6], "big") == len(payload)
            assert payload[8:] == b"control"
    assert sorted(seen) == sorted(expected)
    assert len(set(ivs)) == count, "repeated explicit IV on one SA"
    assert headers.count(59) == record["expected_dummy"]
    expected_lengths = (
        [1, 32, 512]
        if record["scenario"] in ("normal", "esn", "natt")
        else [32] * record["expected_dummy"]
    )
    assert Counter(lengths) == Counter(expected_lengths)
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("serial_log", type=Path)
    parser.add_argument("--transport-only", action="store_true")
    args = parser.parse_args()
    self_check()
    lines = args.serial_log.read_text().splitlines()
    assert "OPC_TFC_PROBE_EXIT=0" in lines
    captures = [
        line.removeprefix("OPC_TFC_WIRE=")
        for line in lines
        if line.startswith("OPC_TFC_WIRE=")
    ]
    assert len(captures) == 1
    records = json.loads(captures[0])
    expected = {
        (family, mode, algorithm, scenario)
        for family in (2, 10)
        for mode in (("transport",) if args.transport_only else ("transport", "tunnel"))
        for algorithm, scenario in [("gcm", "normal"), ("cbc", "normal")]
        + [
            ("gcm", s)
            for s in ("esn", "wrap", "expiry", "delete", "missing", "natt", "stress")
        ]
    }
    assert len(records) == len(expected)
    assert {
        (r["family"], r["mode"], r["algorithm"], r["scenario"]) for r in records
    } == expected
    packets = sum(verify(record) for record in records)
    print(
        json.dumps(
            dict(
                cases=len(records),
                authenticated_packets=packets,
                tag_mutations_rejected=packets,
                python=platform.python_version(),
                cryptography=cryptography.__version__,
                openssl=default_backend().openssl_version_text(),
                capture_sha256=hashlib.sha256(captures[0].encode()).hexdigest(),
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
