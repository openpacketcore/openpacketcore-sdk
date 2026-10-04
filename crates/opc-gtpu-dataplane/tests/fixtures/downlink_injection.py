#!/usr/bin/env python3
"""Independent synthetic ESP peer and wire observer for the native Rust test.

Only the Rust injector sends test traffic. This process configures two private
network namespaces and reports wire bytes to the test over its private pipes.
It needs Python 3.9+, iproute2, nftables, util-linux and namespace default
XFRM policy support; no optional interface, migration or sub-policy support
is used.
"""

import json
import os
import select
import socket
import subprocess
import sys
import time


LOCAL = "192.0.2.1"
PEER = "192.0.2.2"
SOURCE = "198.51.100.7"
DESTINATION = "203.0.113.7"
KEY = "0x" + "11" * 20  # Synthetic AES-GCM key; never used outside this test.


def run(*arguments):
    result = subprocess.run(arguments, capture_output=True, text=True, check=False, timeout=5)
    if result.returncode != 0:
        raise RuntimeError("namespace fixture command failed")
    return result.stdout


def reply(value):
    print(json.dumps(value), flush=True)


def collect(capture):
    trace = []
    deadline = time.monotonic() + 0.12
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([capture], [], [], remaining)[0]:
            break
        packet, address = capture.recvfrom(65535)
        trace.append({"device": address[0], "protocol": address[1],
                      "packet_type": address[2], "packet": packet.hex()})
    return trace


# Kept inline so the Rust unit-test executable can carry this fixture into
# pinned-kernel guests without copying source files or depending on __file__.
PEER_PROGRAM = r'''
import json, select, socket, subprocess, sys, time

def run(*arguments):
    result = subprocess.run(arguments, capture_output=True, check=False, timeout=5)
    if result.returncode:
        raise RuntimeError("peer fixture command failed")

def reply(value):
    print(json.dumps(value), flush=True)

reply({"namespace_ready": True})
for line in sys.stdin:
    operation = json.loads(line)["op"]
    if operation == "setup":
        run("ip", "link", "set", "lo", "up")
        run("ip", "address", "add", "192.0.2.2/24", "dev", "observe0")
        run("ip", "address", "add", "203.0.113.7/32", "dev", "lo")
        run("ip", "link", "set", "observe0", "up")
        run("ip", "route", "add", "198.51.100.7/32", "via", "192.0.2.1")
        for spi in ["0x100", "0x101"]:
            run("ip", "xfrm", "state", "add", "src", "192.0.2.1", "dst", "192.0.2.2",
                "proto", "esp", "spi", spi, "reqid", "7", "mode", "tunnel",
                "aead", "rfc4106(gcm(aes))", "0x" + "11" * 20, "128")
        run("ip", "xfrm", "policy", "add", "dir", "in", "src", "198.51.100.7/32",
            "dst", "203.0.113.7/32", "tmpl", "src", "192.0.2.1", "dst", "192.0.2.2",
            "proto", "esp", "mode", "tunnel", "reqid", "7", "level", "required")
        capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        capture.bind(("observe0", 0))
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.bind(("203.0.113.7", 32001))
        receiver.setblocking(False)
        reply({"ready": True})
    elif operation == "observe":
        packets = []
        deadline = time.monotonic() + 0.12
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([capture], [], [], remaining)[0]:
                break
            frame = capture.recv(65535)
            if len(frame) >= 34 and frame[12:14] == b"\x08\x00":
                ip = frame[14:]
                if ip[9] == 17 and ip[16:20] == socket.inet_aton("203.0.113.7"):
                    packets.append(ip[:int.from_bytes(ip[2:4], "big")].hex())
        payloads = []
        while select.select([receiver], [], [], 0)[0]:
            payloads.append(receiver.recv(65535).hex())
        reply({"inner": packets, "payloads": payloads})
    elif operation == "quit":
        break
    else:
        raise RuntimeError("unknown peer fixture operation")
'''


def main():
    if os.geteuid() != 0 or os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        raise RuntimeError("a fresh privileged network namespace is required")
    if run("ip", "xfrm", "state", "list").strip() or run("ip", "xfrm", "policy", "list").strip():
        raise RuntimeError("fixture requires an empty private XFRM namespace")
    peer = subprocess.Popen(
        ["unshare", "--net", "--", sys.executable, "-u", "-c", PEER_PROGRAM],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
    )
    created_link = False
    created_table = False
    saved_sysctls = {}

    def set_ipv4_conf(device, option, value):
        path = "/proc/sys/net/ipv4/conf/" + device + "/" + option
        if path not in saved_sysctls:
            with open(path) as source:
                saved_sysctls[path] = source.read()
        with open(path, "w") as output:
            output.write(str(value))

    def enable_xfrm():
        for device in ("all", "inject0"):
            set_ipv4_conf(device, "disable_xfrm", 0)
            set_ipv4_conf(device, "disable_policy", 0)

    def peer_call(operation):
        peer.stdin.write(json.dumps({"op": operation}) + "\n")
        peer.stdin.flush()
        response = peer.stdout.readline()
        if not response:
            raise RuntimeError("peer fixture stopped")
        return json.loads(response)

    def guard():
        run("ip", "xfrm", "policy", "add", "dir", "out", "dst", "203.0.113.0/24",
            "priority", "10000", "action", "block")

    def policies():
        for mark in [0, 37]:
            run("ip", "xfrm", "policy", "add", "dir", "out", "src", SOURCE + "/32",
                "dst", DESTINATION + "/32", "priority", "100", "mark", str(mark),
                "mask", "0xffffffff", "tmpl", "src", LOCAL, "dst", PEER, "proto", "esp",
                "mode", "tunnel", "reqid", "7", "level", "required")

    try:
        if not json.loads(peer.stdout.readline()).get("namespace_ready"):
            raise RuntimeError("peer namespace startup failed")
        run("ip", "link", "set", "lo", "up")
        run("ip", "link", "add", "inject0", "type", "veth", "peer", "name", "observe0")
        created_link = True
        run("ip", "link", "set", "observe0", "netns", str(peer.pid))
        run("ip", "address", "add", LOCAL + "/24", "dev", "inject0")
        run("ip", "link", "set", "inject0", "up")
        enable_xfrm()
        run("ip", "route", "add", DESTINATION + "/32", "via", PEER, "dev", "inject0")
        # ICMP errors quote injected bytes and use an ordinary route toward
        # the inner source. Absence of this route would hide those errors.
        run("ip", "route", "add", SOURCE + "/32", "via", PEER, "dev", "inject0")
        # Keep potential ICMP output observable even under default OUT block.
        run("ip", "xfrm", "policy", "add", "dir", "out", "dst", SOURCE + "/32",
            "action", "allow")
        if not peer_call("setup").get("ready"):
            raise RuntimeError("peer setup failed")
        for mark, spi in [(0, "0x100"), (37, "0x101")]:
            run("ip", "xfrm", "state", "add", "src", LOCAL, "dst", PEER, "proto", "esp",
                "spi", spi, "reqid", "7", "mode", "tunnel", "mark", str(mark),
                "mask", "0xffffffff", "aead", "rfc4106(gcm(aes))", KEY, "128")
        guard()
        policies()
        # Ensure the NODEFRAG assertion exercises actual conntrack defrag,
        # even on kernels where loading the module alone does not enable it.
        run("nft", "add", "table", "inet", "injection_test")
        created_table = True
        run("nft", "add", "chain", "inet", "injection_test", "out",
            "{", "type", "filter", "hook", "output", "priority", "0", ";", "}")
        run("nft", "add", "rule", "inet", "injection_test", "out", "ct", "state", "new", "counter")
        run("nft", "add", "rule", "inet", "injection_test", "out",
            "ip", "frag-off", "&", "0x1fff", "!=", "0", "ct", "state", "invalid",
            "counter", "comment", "raw_invalid_fragments")
        # All protocols on every device, without an address filter. DGRAM
        # strips each device's link header, including headerless XFRM links.
        capture = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3))
        reply({"ready": True})
        for line in sys.stdin:
            operation = json.loads(line)["op"]
            if operation == "observe":
                trace = collect(capture)
                result = peer_call("observe")
                result["trace"] = trace
                result["wire"] = [entry["packet"] for entry in trace
                                  if entry["device"] == "inject0"
                                  and entry["protocol"] == 0x800
                                  and entry["packet_type"] == socket.PACKET_OUTGOING]
                reply(result)
            elif operation == "remove_bearers":
                # The selector-specific delete leaves the pool block installed
                # continuously. deleteall also handles zero-valued marks on
                # iproute2 versions whose singular delete omits that attribute.
                run("ip", "xfrm", "policy", "deleteall", "dir", "out",
                    "src", SOURCE + "/32", "dst", DESTINATION + "/32")
                found = run("ip", "xfrm", "policy", "get", "dir", "out", "dst", "203.0.113.0/24")
                reply({"block_present": "action block" in found})
            elif operation == "query_block":
                found = run("ip", "xfrm", "policy", "get", "dir", "out", "dst", "203.0.113.0/24")
                reply({"block_present": "action block" in found})
            elif operation in ("bypass_device", "bypass_all"):
                enable_xfrm()
                device = "inject0" if operation == "bypass_device" else "all"
                set_ipv4_conf(device, "disable_xfrm", 1)
                with open("/proc/sys/net/ipv4/conf/" + device + "/disable_policy") as source:
                    disable_policy = int(source.read())
                reply({"done": True, "disable_policy": disable_policy})
            elif operation == "enable_xfrm":
                enable_xfrm()
                reply({"done": True})
            elif operation == "invalid_count":
                listing = json.loads(run("nft", "-j", "list", "table", "inet", "injection_test"))
                matching = [entry["rule"] for entry in listing["nftables"]
                            if entry.get("rule", {}).get("comment") == "raw_invalid_fragments"]
                if len(matching) != 1:
                    raise RuntimeError("missing invalid-fragment counter")
                count = sum(expression["counter"]["packets"] for expression in matching[0]["expr"]
                            if "counter" in expression)
                reply({"invalid": count})
            elif operation == "drop_invalid":
                run("nft", "add", "chain", "inet", "injection_test", "invalid",
                    "{", "type", "filter", "hook", "output", "priority", "10", ";", "}")
                run("nft", "add", "rule", "inet", "injection_test", "invalid",
                    "ct", "state", "invalid", "counter", "drop")
                reply({"done": True})
            elif operation == "allow_invalid":
                run("nft", "flush", "chain", "inet", "injection_test", "invalid")
                run("nft", "delete", "chain", "inet", "injection_test", "invalid")
                reply({"done": True})
            elif operation in ("default_block", "default_accept"):
                action = "block" if operation == "default_block" else "accept"
                run("ip", "xfrm", "policy", "setdefault", "out", action)
                if not any(line.split() == ["out:", action] for line in
                           run("ip", "xfrm", "policy", "getdefault").splitlines()):
                    raise RuntimeError("namespace default policy readback differs")
                reply({"done": True})
            elif operation == "allow_plaintext":
                run("ip", "xfrm", "policy", "add", "dir", "out", "dst", DESTINATION + "/32",
                    "priority", "10", "action", "allow")
                reply({"done": True})
            elif operation == "remove_plaintext_allow":
                run("ip", "xfrm", "policy", "delete", "dir", "out", "dst", DESTINATION + "/32")
                reply({"done": True})
            elif operation == "remove_block":
                run("ip", "xfrm", "policy", "delete", "dir", "out", "dst", "203.0.113.0/24")
                reply({"done": True})
            elif operation == "restore":
                guard()
                policies()
                reply({"done": True})
            elif operation == "quit":
                break
            else:
                raise RuntimeError("unknown fixture operation")
    finally:
        # All objects belong to the asserted-empty private namespace. Closing
        # the peer's input also tears it down on a Rust assertion failure.
        for path, value in saved_sysctls.items():
            with open(path, "w") as output:
                output.write(value)
        if created_link:
            run("ip", "link", "delete", "inject0")
        peer.stdin.close()
        peer.wait(timeout=5)
        if created_table:
            run("nft", "delete", "table", "inet", "injection_test")
        run("ip", "xfrm", "policy", "flush")
        run("ip", "xfrm", "state", "flush")
        run("ip", "xfrm", "policy", "setdefault", "out", "accept")


if __name__ == "__main__":
    main()
