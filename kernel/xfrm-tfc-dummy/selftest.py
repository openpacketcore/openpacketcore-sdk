#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Privileged packet tests in disposable namespaces; keys are public test fixtures."""

import argparse
import contextlib
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import time

if sys.flags.optimize:
    raise RuntimeError("qualification requires Python assertions enabled")

SPI = 0x124400
KEY = bytes(range(20))
AUTH_KEY = bytes(range(32))


def run(*args):
    result = subprocess.run(
        [str(a) for a in args], capture_output=True, text=True, timeout=15
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def policy(c):
    p = bytearray(232)
    for offset, address in (
        (0, c["dst"]),
        (16, c["src"]),
        (168, c["dst"]),
        (196, c["src"]),
    ):
        address = socket.inet_pton(c["family"], address)
        p[offset : offset + len(address)] = address
    struct.pack_into("=H", p, 40, c["family"])
    p[42:45] = bytes([32 if c["family"] == 2 else 128] * 2 + [59])
    for offset in (56, 64, 72, 80):
        struct.pack_into("=Q", p, offset, 2**64 - 1)
    p[160], p[162] = 1, 8 if c["mode"] == "tunnel" else 0
    struct.pack_into("!I", p, 184, SPI)
    p[188] = 50
    struct.pack_into("=H", p, 192, c["family"])
    struct.pack_into("=I", p, 212, 42)
    p[216] = int(c["mode"] == "tunnel")
    for offset in (220, 224, 228):
        struct.pack_into("=I", p, offset, 2**32 - 1)
    return p


def policy_option(c):
    return (0, 17) if c["family"] == 2 else (41, 35)


def invalid(c):
    p = policy(dict(c, mode="tunnel"))
    cases = []
    for offset, value in (
        (44, 17),
        (160, 0),
        (161, 1),
        (162, 9),
        (188, 51),
        (216, 4),
        (218, 1),
        (32, 1),
        (36, 1),
    ):
        wrong = p.copy()
        wrong[offset] = value
        cases.append(wrong)
    wrong = p.copy()
    wrong[184:188] = bytes(4)
    cases += [wrong, p + b"\0", p + p[168:]]
    for wrong in cases:
        with socket.socket(c["family"], socket.SOCK_RAW, 59) as sock:
            try:
                sock.setsockopt(*policy_option(c), wrong)
            except OSError:
                continue
            raise AssertionError("invalid dummy policy accepted")
    # The flag is reserved for a private socket policy, never the global SPD.
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 6) as netlink:
        netlink.settimeout(2)
        netlink.bind((0, 0))
        request = struct.pack("=IHHII", 16 + 168, 19, 5, 99, 0) + p[:168]
        assert netlink.sendto(request, (0, 0)) == len(request)
        response = netlink.recv(4096)
        assert struct.unpack_from("=H", response, 4)[0] == 2
        assert struct.unpack_from("=i", response, 16)[0] == -95
    print("rejected=13")


def receive(c):
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    capture.setsockopt(socket.SOL_SOCKET, 33, 4 * 1024 * 1024)  # SO_RCVBUFFORCE
    capture.bind(("vethr", 0))
    raw = socket.socket(c["family"], socket.SOCK_RAW, 59)
    raw.bind((c["dst"], 0))
    udp = socket.socket(c["family"], socket.SOCK_DGRAM)
    udp.bind((c["dst"], 9000))
    if c["scenario"] == "natt":
        natt = socket.socket(c["family"], socket.SOCK_DGRAM)
        natt.setsockopt(17, 100, 2)  # UDP_ENCAP_ESPINUDP
        natt.bind((c["dst"], 4500))
    result = dict(wire=[], raw59=[], udp=[], plaintext59=[], icmp_errors=[])
    print("ready", flush=True)
    finished, until = False, time.monotonic() + 20
    while time.monotonic() < until:
        for sock in select.select(
            [capture, raw, udp] + ([] if finished else [sys.stdin]), [], [], 0.05
        )[0]:
            if sock is sys.stdin:
                os.read(sys.stdin.fileno(), 16)
                finished, until = True, time.monotonic() + 0.25
                continue
            data = sock.recv(65535)
            if sock is raw:
                result["raw59"].append(data.hex())
            elif sock is udp:
                result["udp"].append(data.hex())
            elif len(data) >= 34 and data[12:14] in (b"\x08\x00", b"\x86\xdd"):
                ip = data[14:]
                proto, offset = (
                    (ip[9], (ip[0] & 15) * 4) if ip[0] >> 4 == 4 else (ip[6], 40)
                )
                if proto == 50 or (
                    proto == 17
                    and ip[offset : offset + 4] == struct.pack("!HH", 4500, 4500)
                ):
                    result["wire"].append(ip.hex())
                elif proto == 59:
                    result["plaintext59"].append(ip.hex())
                elif (proto == 1 and ip[offset] in (3, 11, 12)) or (
                    proto == 58 and ip[offset] < 128
                ):
                    result["icmp_errors"].append(ip.hex())
    assert finished, "sender deadline expired"
    assert struct.unpack("=II", capture.getsockopt(263, 6, 8))[1] == 0, "capture drops"
    result["xfrm_stats"] = {
        key: int(value)
        for key, value in (
            line.split()
            for line in Path("/proc/net/xfrm_stat").read_text().splitlines()
        )
        if int(value)
    }
    result["ipv6_stats"] = {
        key: int(value)
        for key, value in (
            line.split() for line in Path("/proc/net/snmp6").read_text().splitlines()
        )
        if "Error" in key or "Discard" in key
    }
    print(json.dumps(result), flush=True)


def command(sender, c, length, count=1, threads=1):
    return [
        sender,
        c["mode"],
        c["src"],
        c["dst"],
        str(SPI),
        "42",
        str(length),
        str(count),
        str(threads),
    ]


def case(sender, version, mode, algorithm, scenario, index):
    src, dst = (
        ("192.0.2.10", "192.0.2.20")
        if version == 4
        else ("2001:db8::10", "2001:db8::20")
    )
    c = dict(
        capture_version=1,
        path_mtu=1500,
        tfc_padding=256 if mode == "tunnel" else 0,
        family=2 if version == 4 else 10,
        src=src,
        dst=dst,
        mode=mode,
        algorithm=algorithm,
        scenario=scenario,
    )
    left, right = f"tfcl{os.getpid()}-{index}", f"tfcr{os.getpid()}-{index}"
    created, children = [], []
    try:
        for ns in (left, right):
            run("ip", "netns", "add", ns)
            created.append(ns)
        run(
            "ip",
            "link",
            "add",
            "vethl",
            "netns",
            left,
            "type",
            "veth",
            "peer",
            "name",
            "vethr",
            "netns",
            right,
        )
        for ns, link, address in ((left, "vethl", src), (right, "vethr", dst)):
            run("ip", "-n", ns, "link", "set", "lo", "up")
            run(
                "ip",
                "-n",
                ns,
                "addr",
                "add",
                address + ("/24" if version == 4 else "/64"),
                "dev",
                link,
                *([] if version == 4 else ["nodad"]),
            )
            run("ip", "-n", ns, "link", "set", link, "mtu", str(c["path_mtu"]), "up")
            state = [
                "ip",
                "-n",
                ns,
                "xfrm",
                "state",
                "add",
                "src",
                src,
                "dst",
                dst,
                "proto",
                "esp",
                "spi",
                str(SPI),
                "reqid",
                "42",
                "mode",
                mode,
            ]
            if algorithm == "gcm":
                state += ["aead", "rfc4106(gcm(aes))", "0x" + KEY.hex(), "128"]
            else:
                state += [
                    "enc",
                    "cbc(aes)",
                    "0x" + KEY[:16].hex(),
                    "auth-trunc",
                    "hmac(sha256)",
                    "0x" + AUTH_KEY.hex(),
                    "128",
                ]
            state += ["replay-window", "128" if scenario == "esn" else "32"]
            if mode == "tunnel":
                state += ["tfcpad", str(c["tfc_padding"])]
            if scenario == "esn":
                state += [
                    "flag",
                    "esn",
                    "replay-oseq",
                    "4294967294",
                    "replay-oseq-hi",
                    "7",
                    "replay-seq",
                    "4294967294",
                    "replay-seq-hi",
                    "7",
                ]
            elif scenario == "wrap" and ns == left:
                state += ["replay-oseq", "4294967294"]
            elif scenario == "expiry" and ns == left:
                state += ["limit", "packet-hard", "1"]
            if scenario == "natt":
                state += [
                    "encap",
                    "espinudp",
                    "4500",
                    "4500",
                    "0.0.0.0" if version == 4 else "::",
                ]
            if scenario != "missing":
                run(*state)
            run(
                "ip",
                "-n",
                ns,
                "xfrm",
                "policy",
                "add",
                "dir",
                "out" if ns == left else "in",
                "src",
                src,
                "dst",
                dst,
                "proto",
                "17",
                "dport",
                "9000",
                "tmpl",
                "src",
                src,
                "dst",
                dst,
                "proto",
                "esp",
                "spi",
                str(SPI),
                "reqid",
                "42",
                "mode",
                mode,
                "level",
                "required",
            )
        # Resolve layer two explicitly; IPv6 DAD/ND timing is outside this ESP test.
        left_mac = json.loads(run("ip", "-j", "-n", left, "link", "show", "vethl"))[0][
            "address"
        ]
        right_mac = json.loads(run("ip", "-j", "-n", right, "link", "show", "vethr"))[
            0
        ]["address"]
        run(
            "ip",
            "-n",
            left,
            "neigh",
            "replace",
            dst,
            "lladdr",
            right_mac,
            "nud",
            "permanent",
            "dev",
            "vethl",
        )
        run(
            "ip",
            "-n",
            right,
            "neigh",
            "replace",
            src,
            "lladdr",
            left_mac,
            "nud",
            "permanent",
            "dev",
            "vethr",
        )
        if mode == "tunnel":
            assert (
                run(
                    "ip",
                    "netns",
                    "exec",
                    left,
                    sys.executable,
                    __file__,
                    "invalid",
                    json.dumps(c),
                ).strip()
                == "rejected=13"
            )
        receiver = subprocess.Popen(
            [
                "ip",
                "netns",
                "exec",
                right,
                sys.executable,
                __file__,
                "receive",
                json.dumps(c),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        children.append(receiver)
        ready = receiver.stdout.readline().strip()
        assert ready == "ready", (ready, receiver.stderr.read())
        dummy, control = 3, 3
        if scenario in ("wrap", "expiry", "missing"):
            if scenario == "missing" and mode == "tunnel":
                run(
                    "ip",
                    "netns",
                    "exec",
                    left,
                    sys.executable,
                    __file__,
                    "missing",
                    json.dumps(c),
                    sender,
                )
                result = None
            else:
                result = subprocess.run(
                    ["ip", "netns", "exec", left, *command(sender, c, 32, 2)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            if result is not None:
                assert result.returncode != 0, result.stdout
            dummy, control = (0 if scenario == "missing" else 1), 0
            if scenario == "missing":
                assert (
                    run("ip", "-n", left, "xfrm", "state", "count").strip()
                    == "SAD count 0"
                )
        elif scenario == "delete":
            run(
                "ip",
                "netns",
                "exec",
                left,
                sys.executable,
                __file__,
                "delete",
                json.dumps(c),
            )
            dummy, control = 1, 0
        elif scenario == "stress":
            worker = subprocess.Popen(
                ["ip", "netns", "exec", left, *command(sender, c, 32, 32, 4)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            children.append(worker)
            code = (
                "import socket; s=socket.socket(%d,socket.SOCK_DGRAM); s.bind(('%s',0)); [s.sendto(b'control',('%s',9000)) for _ in range(128)]"
                % (c["family"], src, dst)
            )
            run("ip", "netns", "exec", left, sys.executable, "-c", code)
            stdout, stderr = worker.communicate(timeout=10)
            assert worker.returncode == 0 and stdout.strip() == "submitted=128", stderr
            dummy = control = 128
        else:
            for length in (1, 32, 512):
                assert (
                    run(
                        "ip", "netns", "exec", left, *command(sender, c, length)
                    ).strip()
                    == "submitted=1"
                )
                code = (
                    "import socket; s=socket.socket(%d,socket.SOCK_DGRAM); s.bind(('%s',0)); s.sendto(b'control',('%s',9000))"
                    % (c["family"], src, dst)
                )
                run("ip", "netns", "exec", left, sys.executable, "-c", code)
        receiver.stdin.close()
        receiver.stdin = None
        stdout, stderr = receiver.communicate(timeout=10)
        assert receiver.returncode == 0, stderr
        result = json.loads(stdout)
        assert len(result["wire"]) == dummy + control, (c, result)
        assert result["udp"] == [b"control".hex()] * control, (c, result)
        assert (
            not result["raw59"]
            and not result["plaintext59"]
            and not result["icmp_errors"]
        ), (c, result)
        result.update(c, expected_dummy=dummy, expected_control=control)
        return result
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.wait()
        for ns in reversed(created):
            run("ip", "netns", "delete", ns)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sender", required=True, type=Path)
    parser.add_argument(
        "--transport-only", action="store_true", help="qualify the stock-kernel sender"
    )
    args = parser.parse_args()
    cpus = len(os.sched_getaffinity(0))
    assert cpus >= 2, "qualification requires two online CPUs"
    print(f"kernel={os.uname().release} online_cpus={cpus}", flush=True)
    results = []
    for version in (4, 6):
        for mode in ("transport",) if args.transport_only else ("transport", "tunnel"):
            for algorithm, scenario in [("gcm", "normal"), ("cbc", "normal")] + [
                ("gcm", s)
                for s in (
                    "esn",
                    "wrap",
                    "expiry",
                    "delete",
                    "missing",
                    "natt",
                    "stress",
                )
            ]:
                results.append(
                    case(
                        str(args.sender.resolve()),
                        version,
                        mode,
                        algorithm,
                        scenario,
                        len(results),
                    )
                )
                print(f"PASS ipv{version} {mode} {algorithm} {scenario}", flush=True)
    print("OPC_TFC_WIRE=" + json.dumps(results), flush=True)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("receive", "invalid", "delete", "missing"):
        c = json.loads(sys.argv[2])
        if sys.argv[1] == "receive":
            receive(c)
        elif sys.argv[1] == "invalid":
            invalid(c)
        elif sys.argv[1] == "missing":
            with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 6) as listener:
                listener.bind((0, 1))  # XFRMNLGRP_ACQUIRE is now listening.
                result = subprocess.run(
                    command(sys.argv[3], c, 32),
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                assert result.returncode != 0, result.stdout
                assert not select.select([listener], [], [], 0.1)[0], (
                    "dummy triggered ACQUIRE"
                )
                assert run("ip", "xfrm", "state", "count").strip() == "SAD count 0"
        else:
            with socket.socket(c["family"], socket.SOCK_RAW, 59) as sock:
                sock.setsockopt(*policy_option(c), policy(c))
                sock.bind((c["src"], 0))
                sock.connect((c["dst"], 0))
                assert sock.send(bytes(32)) == 32
                run(
                    "ip",
                    "xfrm",
                    "state",
                    "delete",
                    "src",
                    c["src"],
                    "dst",
                    c["dst"],
                    "proto",
                    "esp",
                    "spi",
                    str(SPI),
                )
                with contextlib.suppress(OSError):
                    sock.send(bytes(32))
    else:
        main()
