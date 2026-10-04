#!/usr/bin/env python3
"""Observe real AUTH key IDs during the isolated native RFC 6083 rekey test.

RFC 4895 section 5.1, RFC 4960 section 3.3.1, RFC 6347 section 4.1.
Only synthetic loopback traffic is captured; no transport internals are read.
This checks wire metadata, not HMAC computation or kernel key deletion.
"""

import argparse
import collections
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import time

CASE = "dtls_tests::generic::rekey::generic_kernel_rekey_preserves_multistream_records_and_rotates_keys"
SNI_CASE = "dtls_tests::generic::sni::generic_kernel_sni_preserves_name_through_rekey_and_delivery"


def records(frame):
    if len(frame) < 34 or frame[12:14] != b"\x08\x00":
        return []
    ip = frame[14:]
    if ip[0] >> 4 != 4 or ip[9] != 132:
        return []
    assert ip[12:20] == b"\x7f\x00\x00\x01" * 2, "loopback only"
    assert int.from_bytes(ip[6:8], "big") & 0x3FFF == 0, "unfragmented fixture"
    sctp = ip[(ip[0] & 15) * 4:int.from_bytes(ip[2:4], "big")]
    assert len(sctp) >= 12
    source, destination, tag = struct.unpack("!HHI", sctp[:8])
    result = []
    auth = None
    offset = 12
    while offset < len(sctp):
        kind, flags, length = struct.unpack("!BBH", sctp[offset:offset + 4])
        assert length >= 4 and offset + length <= len(sctp)
        chunk = sctp[offset:offset + length]
        if kind == 15:
            assert length >= 8
            auth = int.from_bytes(chunk[4:6], "big")
        elif kind == 0:
            assert flags & 7 == 3, "whole reliable ordered DATA fixture"
            assert length >= 29
            assert int.from_bytes(chunk[12:16], "big") == 66, "protected PPID"
            record = chunk[16:]
            assert len(record) == 13 + int.from_bytes(record[11:13], "big")
            epoch = int.from_bytes(record[3:5], "big")
            assert auth is not None and auth == epoch, "actual AUTH key must match the record epoch"
            stream = int.from_bytes(chunk[8:10], "big")
            assert record[0] == 23 or stream == 0, "control stream zero"
            result.append(dict(source=source, destination=destination, tag=tag,
                               auth=auth, epoch=epoch, content=record[0], stream=stream,
                               initial_handshake=record[13:].hex() if epoch == 0 and record[0] == 22 else None))
        offset += (length + 3) & ~3
    return result


def verify_initial_sni(direction):
    hellos = 0
    kinds = set()
    for record in direction:
        if not record["initial_handshake"]:
            continue
        handshake = bytes.fromhex(record["initial_handshake"])
        if handshake[0] not in (1, 2):
            continue
        assert len(handshake) >= 12
        assert int.from_bytes(handshake[1:4], "big") == len(handshake) - 12
        assert handshake[6:9] == bytes(3), "whole fixture Hello"
        assert int.from_bytes(handshake[9:12], "big") == len(handshake) - 12
        body = handshake[12:]
        assert body[:2] == b"\xfe\xfd"
        offset = 35 + body[34]  # version, random, session ID
        if handshake[0] == 1:
            offset += 1 + body[offset]  # cookie
            offset += 2 + int.from_bytes(body[offset:offset + 2], "big")  # suites
            offset += 1 + body[offset]  # compression methods
        else:
            offset += 3  # selected cipher and null compression
        assert offset + 2 <= len(body)
        assert int.from_bytes(body[offset:offset + 2], "big") == len(body) - offset - 2
        offset += 2
        names = []
        while offset < len(body):
            assert offset + 4 <= len(body)
            kind, length = struct.unpack("!HH", body[offset:offset + 4])
            offset += 4
            assert offset + length <= len(body)
            if kind == 0:
                names.append(body[offset:offset + length])
            offset += length
        expected = b"\x00\x13\x00\x00\x10amf.example.test" if handshake[0] == 1 else b""
        assert names == [expected], "exact independently observed SNI name/empty acknowledgement"
        kinds.add(handshake[0])
        hellos += 1
    assert hellos >= 1 and len(kinds) == 1, "one Hello direction including any cookie exchange"
    return kinds.pop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--sni", action="store_true", help="qualify the named endpoint fixture")
    args = parser.parse_args()
    case = SNI_CASE if args.sni else CASE
    epochs = 4 if args.sni else 5
    assert os.geteuid() == 0
    assert os.readlink("/proc/self/ns/net") != os.readlink("/proc/1/ns/net")
    inventory = subprocess.check_output([str(args.binary), "--list", "--ignored", "--format", "terse"], text=True)
    assert inventory.splitlines().count(case + ": test") == 1
    args.output.mkdir(parents=True, exist_ok=True)
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    capture.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    capture.bind(("lo", 0))
    capture.setblocking(False)
    observed = []
    captured = 0
    with (args.output / "rekey.pcap").open("wb") as pcap:
        pcap.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        process = subprocess.Popen([str(args.binary), "--ignored", "--exact", case,
                                    "--test-threads=1", "--nocapture"])
        deadline = time.monotonic() + 55
        try:
            while True:
                assert time.monotonic() < deadline, "bounded native capture"
                if select.select([capture], [], [], 0.05)[0]:
                    frame, address = capture.recvfrom(65535)
                    if address[2] != socket.PACKET_OUTGOING:
                        continue
                    # Preserve complete synthetic SCTP frames for independent replay.
                    if len(frame) >= 34 and frame[12:14] == b"\x08\x00" and frame[23] == 132:
                        captured += len(frame)
                        assert captured <= 4 * 1024 * 1024, "bounded capture"
                        now = time.time_ns()
                        pcap.write(struct.pack("<IIII", now // 10**9, now % 10**9 // 1000,
                                               len(frame), len(frame)) + frame)
                        observed.extend(records(frame))
                elif process.poll() is not None:
                    break
            assert process.wait() == 0, "native Rust test failed"
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    packets, drops = struct.unpack("II", capture.getsockopt(263, 6, 8))
    capture.close()
    assert drops == 0, "capture loss invalidates key transition evidence"
    directions = collections.defaultdict(list)
    for record in observed:
        directions[(record["source"], record["destination"], record["tag"])].append(record)
    assert len(directions) == 6, "three associations, both directions"
    hello_kinds = collections.Counter()
    for direction in directions.values():
        assert {r["auth"] for r in direction} == set(range(epochs))
        assert {r["epoch"] for r in direction if r["content"] == 20} == set(range(epochs - 1))
        assert {r["epoch"] for r in direction if r["content"] == 23} == set(range(1, epochs))
        for epoch in range(1, epochs):
            assert next(r for r in direction if r["auth"] == epoch)["content"] == 22
        if args.sni:
            hello_kinds[verify_initial_sni(direction)] += 1
    (args.output / "rekey-wire.json").write_text(json.dumps(
        dict(packets=packets, drops=drops, directions=len(directions), records=observed), indent=2) + "\n")
    if args.sni:
        assert hello_kinds == {1: 3, 2: 3}
        print("native SNI wire verified: 3 named ClientHellos, 3 acknowledged ServerHellos, key IDs 0..3, 0 capture drops", flush=True)
    else:
        print("native SCTP-AUTH rekey wire verified: 6 directions, key IDs 0..4, 0 capture drops", flush=True)


if __name__ == "__main__":
    main()
