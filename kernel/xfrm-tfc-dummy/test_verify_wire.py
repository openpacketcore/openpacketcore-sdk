#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Authenticated captures must prove TFC length on dummy and ordinary traffic."""

import hashlib
import hmac
import importlib.util
from pathlib import Path
import struct
import unittest

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SPEC = importlib.util.spec_from_file_location("verify_wire", Path(__file__).with_name("verify-wire.py"))
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


def ip_packet(family, protocol, body):
    if family == 2:
        header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, protocol, 0, bytes([192, 0, 2, 10]), bytes([192, 0, 2, 20])))
        header[10:12] = (65535 - VERIFIER.checksum(header)).to_bytes(2, "big")
    else:
        header = struct.pack("!IHBB16s16s", 6 << 28, len(body), protocol, 64, bytes.fromhex("20010db800000000000000000000000010"), bytes.fromhex("20010db800000000000000000000000020"))
    return bytes(header) + body


def record(family, algorithm, dummy_padding, control_padding, path_mtu=1500, padded_length=256):
    packets = []
    for sequence, (dummy, padded) in enumerate(((True, dummy_padding), (False, control_padding)), 1):
        payload = bytes(32) if dummy else struct.pack("!HHHH", 8000, 9000, 15, 0) + b"control"
        inner = ip_packet(family, 59 if dummy else 17, payload)
        body = inner + bytes(max(0, padded_length - len(inner))) if padded else inner
        header = 59 if dummy else (4 if family == 2 else 41)
        block = 4 if algorithm == "gcm" else 16
        padding = (-(len(body) + 2)) % block
        plain = body + bytes(range(1, padding + 1)) + bytes([padding, header])
        esp = struct.pack("!II", 0x124400, sequence)
        if algorithm == "gcm":
            iv = sequence.to_bytes(8, "big")
            esp += iv + AESGCM(bytes(range(16))).encrypt(bytes(range(16, 20)) + iv, plain, esp)
        else:
            iv = sequence.to_bytes(16, "big")
            cipher = Cipher(algorithms.AES(bytes(range(16))), modes.CBC(iv)).encryptor()
            esp += iv + cipher.update(plain) + cipher.finalize()
            esp += hmac.digest(bytes(range(32)), esp, hashlib.sha256)[:16]
        packets.append(ip_packet(family, 50, esp).hex())
    return dict(capture_version=1, family=family, mode="tunnel", algorithm=algorithm, scenario="stress", path_mtu=path_mtu, tfc_padding=256, expected_dummy=1, expected_control=1, wire=packets, udp=[b"control".hex()], raw59=[], plaintext59=[], icmp_errors=[])


class TfcWireLengthTests(unittest.TestCase):
    def test_each_tunnel_packet_requires_padding_in_both_families_and_ciphers(self):
        for family in (2, 10):
            for algorithm in ("gcm", "cbc"):
                with self.subTest(family=family, algorithm=algorithm, padded=True):
                    self.assertEqual(VERIFIER.verify(record(family, algorithm, True, True)), 2)
                for dummy, control in ((False, True), (True, False), (False, False)):
                    with self.subTest(family=family, algorithm=algorithm, dummy=dummy, control=control):
                        with self.assertRaises(AssertionError):
                            VERIFIER.verify(record(family, algorithm, dummy, control))

    def test_padding_uses_linux_path_mtu_cap(self):
        # Pinned xfrm_state_mtu: align(300 - outer20 - ESP8 - IV8 - tag16, 4) - 2.
        self.assertEqual(VERIFIER.verify(record(2, "gcm", True, True, 300, 246)), 2)
        with self.assertRaises(AssertionError):
            VERIFIER.verify(record(2, "gcm", True, True, 300, 245))


if __name__ == "__main__":
    unittest.main()
