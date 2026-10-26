#!/usr/bin/env python3
"""Independently capture SCTP ABORT and graceful shutdown on private loopback.

RFC 9260 sections 3.3.7, 3.3.8 and 3.3.10.12; RFC 6458 section 8.1.4.
The Rust fixtures check application behavior; this checks actual wire chunks.
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


def chunks(frame):
    if len(frame) < 34 or frame[12:14] != b"\x08\x00" or frame[23] != 132:
        return []
    ip = frame[14:]
    assert ip[0] >> 4 == 4 and ip[12:20] == b"\x7f\x00\x00\x01" * 2
    assert int.from_bytes(ip[6:8], "big") & 0x3FFF == 0
    packet = ip[(ip[0] & 15) * 4:int.from_bytes(ip[2:4], "big")]
    assert len(packet) >= 12
    source, destination = struct.unpack("!HH", packet[:4])
    offset = 12
    result = []
    while offset < len(packet):
        assert offset + 4 <= len(packet)
        kind, flags, length = struct.unpack("!BBH", packet[offset:offset + 4])
        assert length >= 4 and offset + length <= len(packet)
        if kind == 6:
            assert flags == 0, "established association ABORT uses its own verification tag"
            assert packet[offset + 4:offset + length] == b"\x00\x0c\x00\x04", "User-Initiated Abort cause without custom text"
        result.append((source, destination, kind))
        offset += (length + 3) & ~3
    assert offset == len(packet)
    return result


def qualify(binary, case, output, expected_aborts, expected_shutdowns):
    inventory = subprocess.check_output([str(binary), "--list", "--ignored", "--format", "terse"], text=True)
    assert inventory.splitlines().count(case + ": test") == 1
    output.mkdir(parents=True, exist_ok=True)
    observed = []
    captured = 0
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as capture:
        capture.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        capture.bind(("lo", 0))
        capture.setblocking(False)
        with (output / "wire.pcap").open("wb") as pcap, (output / "test.log").open("w") as log:
            pcap.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            process = subprocess.Popen([str(binary), "--ignored", "--exact", case, "--test-threads=1", "--nocapture"], stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 60
                quiet_since = time.monotonic()
                while True:
                    assert time.monotonic() < deadline, "bounded capture"
                    if select.select([capture], [], [], 0.05)[0]:
                        frame, address = capture.recvfrom(65535)
                        if address[2] != socket.PACKET_OUTGOING:
                            continue
                        records = chunks(frame)
                        if not records:
                            continue
                        captured += len(frame)
                        assert captured <= 4 * 1024 * 1024, "bounded fixture traffic"
                        now = time.time_ns()
                        pcap.write(struct.pack("<IIII", now // 10**9, now % 10**9 // 1000, len(frame), len(frame)) + frame)
                        observed.extend(records)
                        quiet_since = time.monotonic()
                    elif process.poll() is not None and time.monotonic() - quiet_since >= 1:
                        # close(2) returns before the kernel's delayed SACK/SHUTDOWN.
                        break
                assert process.wait() == 0, f"native fixture failed: {output / 'test.log'}"
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        _, drops = struct.unpack("II", capture.getsockopt(263, 6, 8))
    assert "test result: ok. 1 passed; 0 failed; 0 ignored;" in (output / "test.log").read_text()
    assert drops == 0, "capture loss invalidates teardown evidence"
    associations = collections.defaultdict(set)
    for source, destination, kind in observed:
        associations[tuple(sorted((source, destination)))].add(kind)
    aborted = sum(6 in kinds for kinds in associations.values())
    orderly = sum({7, 8, 14}.issubset(kinds) for kinds in associations.values())
    assert len(associations) == expected_aborts + expected_shutdowns, associations
    assert aborted == expected_aborts and orderly == expected_shutdowns, associations
    assert all(not (6 in kinds and kinds & {7, 8, 14}) for kinds in associations.values()), associations
    report = dict(case=case, associations=len(associations), aborted=aborted, orderly=orderly, capture_drops=drops)
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sctp_binary", type=Path)
    parser.add_argument("diameter_binary", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0
    assert os.readlink("/proc/self/ns/net") != os.readlink("/proc/1/ns/net")
    qualify(args.sctp_binary, "tests::loopback_wire_abort_closes_with_live_handles_and_pending_receive", args.output / "explicit-abort", 1, 0)
    qualify(args.sctp_binary, "tests::loopback_recv_diameter_payload_surfaces_close_after_shutdown", args.output / "queued-shutdown", 0, 3)
    qualify(args.diameter_binary, "dtls_tests::wire_abort::kernel_malformed_diameter_frames_abort_sequential_and_runtime_associations", args.output / "malformed-diameter", 6, 0)
    qualify(args.diameter_binary, "dtls_tests::kernel_loopback_completes_real_rfc6083_handshake_and_reciprocal_close", args.output / "dtls-close", 0, 4)


if __name__ == "__main__":
    main()
