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
                               auth=auth, epoch=epoch, content=record[0], stream=stream))
        offset += (length + 3) & ~3
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0
    assert os.readlink("/proc/self/ns/net") != os.readlink("/proc/1/ns/net")
    inventory = subprocess.check_output([str(args.binary), "--list", "--ignored", "--format", "terse"], text=True)
    assert inventory.splitlines().count(CASE + ": test") == 1
    args.output.mkdir(parents=True, exist_ok=True)
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    capture.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    capture.bind(("lo", 0))
    capture.setblocking(False)
    observed = []
    captured = 0
    with (args.output / "rekey.pcap").open("wb") as pcap:
        pcap.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        process = subprocess.Popen([str(args.binary), "--ignored", "--exact", CASE,
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
    for direction in directions.values():
        assert {r["auth"] for r in direction} == set(range(5))
        assert {r["epoch"] for r in direction if r["content"] == 20} == set(range(4))
        assert {r["epoch"] for r in direction if r["content"] == 23} == set(range(1, 5))
        for epoch in range(1, 5):
            assert next(r for r in direction if r["auth"] == epoch)["content"] == 22
    (args.output / "rekey-wire.json").write_text(json.dumps(
        dict(packets=packets, drops=drops, directions=len(directions), records=observed), indent=2) + "\n")
    print("native SCTP-AUTH rekey wire verified: 6 directions, key IDs 0..4, 0 capture drops", flush=True)


if __name__ == "__main__":
    main()
