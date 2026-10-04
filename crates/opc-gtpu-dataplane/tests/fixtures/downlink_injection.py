#!/usr/bin/env python3
"""Independent synthetic ESP peer and wire observer for the native Rust test.

Only the Rust injector sends test traffic. This process configures two private
network namespaces and reports wire bytes to the test over its private pipes.
It needs Python 3.9+, iproute2, nftables, util-linux and namespace default
XFRM policy support. Interface mode requires XFRM interfaces or proves
constructor refusal after an explicit unsupported kernel result. Neither
mode needs migration or sub-policy support.
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


def unsupported_link(probe):
    # rtnl_newlink returns EOPNOTSUPP with this extack for an unknown kind.
    # Older iproute2 versions can show only the errno instead of the extack.
    return probe.returncode == 2 and probe.stderr.strip() in (
        "Error: Unknown device type.", "RTNETLINK answers: Operation not supported",
    )


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
        # Do not reflect the observed ICMP errors back toward the sender on
        # hosts whose fresh namespaces inherit enabled IPv4 forwarding.
        with open("/proc/sys/net/ipv4/ip_forward", "w") as output:
            output.write("0")
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
    elif operation == "inbound":
        run("ip", "xfrm", "state", "add", "src", "192.0.2.2", "dst", "192.0.2.1",
            "proto", "esp", "spi", "0x200", "reqid", "8", "mode", "tunnel",
            "aead", "rfc4106(gcm(aes))", "0x" + "11" * 20, "128")
        run("ip", "xfrm", "policy", "add", "dir", "out", "src", "203.0.113.7/32",
            "dst", "192.0.2.1/32", "tmpl", "src", "192.0.2.2", "dst", "192.0.2.1",
            "proto", "esp", "mode", "tunnel", "reqid", "8", "level", "required")
        for _ in range(8):
            receiver.sendto(b"inbound socket-filter proof", ("192.0.2.1", 32002))
        reply({"sent": 8})
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
    interface_mode = len(sys.argv) > 1 and sys.argv[1] == "interface"
    interface_created = False
    interface_index = None
    interface_supported = False
    saved_sysctls = {}

    def set_sysctl(path, value):
        if path not in saved_sysctls:
            with open(path) as source:
                saved_sysctls[path] = source.read()
        with open(path, "w") as output:
            output.write(str(value))

    def set_ipv4_conf(device, option, value):
        set_sysctl("/proc/sys/net/ipv4/conf/" + device + "/" + option, value)

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
        if interface_mode:
            return
        run("ip", "xfrm", "policy", "add", "dir", "out", "dst", "203.0.113.0/24",
            "priority", "10000", "action", "block")

    def policies():
        selector = ["proto", "udp"] if interface_mode else []
        interface = ["if_id", "19"] if interface_mode else []
        for mark in [0, 37]:
            run("ip", "xfrm", "policy", "add", "dir", "out", "src", SOURCE + "/32",
                "dst", DESTINATION + "/32", *selector, "priority", "100", "mark", str(mark),
                "mask", "0xffffffff", *interface, "tmpl", "src", LOCAL, "dst", PEER, "proto", "esp",
                "mode", "tunnel", "reqid", "7", "level", "required")

    def states():
        selector = ["if_id", "19"] if interface_mode else []
        for mark, spi in [(0, "0x100"), (37, "0x101")]:
            run("ip", "xfrm", "state", "add", "src", LOCAL, "dst", PEER, "proto", "esp",
                "spi", spi, "reqid", "7", "mode", "tunnel", "mark", str(mark),
                "mask", "0xffffffff", *selector, "aead", "rfc4106(gcm(aes))", KEY, "128")

    def replace_interface(kind):
        nonlocal interface_created
        if interface_created:
            run("ip", "link", "delete", "xfrm0")
            interface_created = False
        details = ["dev", "inject0", "if_id", "19"] if kind == "xfrm" else []
        run("ip", "link", "add", "xfrm0", "index", str(interface_index), "type", kind, *details)
        interface_created = True
        run("ip", "link", "set", "xfrm0", "up")
        if socket.if_nametoindex("xfrm0") != interface_index:
            raise RuntimeError("replacement index differs")

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
        if interface_mode:
            # Only the kernel's explicit EOPNOTSUPP result qualifies the
            # unsupported branch; privilege, syntax and resource errors fail.
            probe = subprocess.run(
                ["ip", "link", "add", "xfrm0", "type", "xfrm", "dev", "inject0", "if_id", "19"],
                capture_output=True, text=True, check=False, timeout=5,
                env=dict(os.environ, LC_ALL="C"),
            )
            if probe.returncode == 0:
                interface_supported = True
            elif unsupported_link(probe):
                run("ip", "link", "add", "xfrm0", "type", "dummy")
            else:
                raise RuntimeError("XFRM interface probe failed unexpectedly")
            interface_created = True
            interface_index = socket.if_nametoindex("xfrm0")
            run("ip", "link", "set", "xfrm0", "up")
            if interface_supported:
                run("ip", "route", "replace", DESTINATION + "/32", "dev", "xfrm0")
        if not interface_mode or interface_supported:
            states()
            guard()
            policies()
        # Ensure the NODEFRAG assertion exercises actual conntrack defrag,
        # even on kernels where loading the module alone does not enable it.
        run("nft", "add", "table", "inet", "injection_test")
        created_table = True
        run("nft", "add", "chain", "inet", "injection_test", "out",
            "{", "type", "filter", "hook", "output", "priority", "0", ";", "}")
        run("nft", "add", "rule", "inet", "injection_test", "out", "ct", "state", "new", "counter")
        # Deterministic ICMP positive controls must not be hidden by rate
        # limiting. This private-namespace setting is restored in finally.
        set_sysctl("/proc/sys/net/ipv4/icmp_ratemask", 0)
        run("nft", "add", "rule", "inet", "injection_test", "out",
            "ip", "frag-off", "&", "0x1fff", "!=", "0", "ct", "state", "invalid",
            "counter", "comment", "raw_invalid_fragments")
        run("nft", "add", "chain", "inet", "injection_test", "post",
            "{", "type", "filter", "hook", "postrouting", "priority", "0", ";", "}")
        for chain, comment in [("out", "inner_output"), ("post", "inner_postrouting")]:
            run("nft", "add", "rule", "inet", "injection_test", chain,
                "ip", "saddr", SOURCE, "ip", "daddr", DESTINATION, "ip", "protocol", "udp",
                "counter", "comment", comment)
        run("nft", "add", "rule", "inet", "injection_test", "post",
            "ip", "saddr", SOURCE, "ip", "daddr", DESTINATION, "ip", "protocol", "udp",
            "ct", "state", "invalid", "counter", "comment", "inner_invalid")
        # All protocols on every device, without an address filter. DGRAM
        # strips each device's link header, including headerless XFRM links.
        capture = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3))
        reply({"ready": True, "interface_supported": interface_supported,
               "interface_index": interface_index, "physical_index": socket.if_nametoindex("inject0")})
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
            elif operation == "hooks":
                listing = json.loads(run("nft", "-j", "list", "table", "inet", "injection_test"))
                counters = {}
                for entry in listing["nftables"]:
                    rule = entry.get("rule", {})
                    if rule.get("comment") in ("inner_output", "inner_postrouting", "inner_invalid",
                                               "icmp_quote_drop"):
                        counters[rule["comment"]] = sum(
                            expression["counter"]["packets"] for expression in rule["expr"]
                            if "counter" in expression)
                if not {"inner_output", "inner_postrouting", "inner_invalid"} <= counters.keys():
                    raise RuntimeError("missing plaintext hook counters")
                reply(counters)
            elif operation == "unknown_kind":
                probe = subprocess.run(
                    ["ip", "link", "add", "absent0", "type", "opc_absent"],
                    capture_output=True, text=True, check=False, timeout=5,
                    env=dict(os.environ, LC_ALL="C"),
                )
                if not unsupported_link(probe):
                    raise RuntimeError("unknown-kind result was not recognized")
                reply({"unsupported": True, "diagnostic": probe.stderr.strip()})
            elif operation == "inbound":
                run("ip", "xfrm", "state", "add", "src", PEER, "dst", LOCAL,
                    "proto", "esp", "spi", "0x200", "reqid", "8", "mode", "tunnel", "if_id", "19",
                    "aead", "rfc4106(gcm(aes))", KEY, "128")
                run("ip", "xfrm", "policy", "add", "dir", "in", "src", DESTINATION + "/32",
                    "dst", LOCAL + "/32", "if_id", "19", "tmpl", "src", PEER, "dst", LOCAL,
                    "proto", "esp", "mode", "tunnel", "reqid", "8", "level", "required")
                receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                receiver.bind((LOCAL, 32002))
                receiver.settimeout(2)
                if peer_call("inbound")["sent"] != 8:
                    raise RuntimeError("inbound sender failed")
                for _ in range(8):
                    if receiver.recv(65535) != b"inbound socket-filter proof":
                        raise RuntimeError("inbound payload differs")
                receiver.close()
                reply({"received": 8})
            elif operation == "suppress_icmp":
                run("nft", "add", "chain", "inet", "injection_test", "icmp_guard",
                    "{", "type", "filter", "hook", "output", "priority", "-300", ";", "}")
                # ICMP's eight-byte header plus offset 16 in the quoted IPv4
                # header: its destination, independent of original IHL/mark.
                run("nft", "add", "rule", "inet", "injection_test", "icmp_guard",
                    "icmp", "type", "destination-unreachable",
                    "@th,192,32", "&", "0xffffff00", "==", "0xcb007100",
                    "counter", "drop", "comment", "icmp_quote_drop")
                reply({"done": True})
            elif operation == "allow_icmp":
                run("nft", "flush", "chain", "inet", "injection_test", "icmp_guard")
                run("nft", "delete", "chain", "inet", "injection_test", "icmp_guard")
                reply({"done": True})
            elif operation == "remove_bearers":
                # The selector-specific delete leaves the pool block installed
                # continuously. deleteall also handles zero-valued marks on
                # iproute2 versions whose singular delete omits that attribute.
                run("ip", "xfrm", "policy", "deleteall", "dir", "out",
                    "src", SOURCE + "/32", "dst", DESTINATION + "/32")
                found = "" if interface_mode else run(
                    "ip", "xfrm", "policy", "get", "dir", "out", "dst", "203.0.113.0/24")
                reply({"done": True, "block_present": "action block" in found})
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
            elif operation in ("drop_invalid", "drop_invalid_post"):
                hook = "postrouting" if operation == "drop_invalid_post" else "output"
                run("nft", "add", "chain", "inet", "injection_test", "invalid",
                    "{", "type", "filter", "hook", hook, "priority", "10", ";", "}")
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
            elif operation == "remove_states":
                run("ip", "xfrm", "state", "flush")
                reply({"done": True})
            elif operation == "restore_states":
                run("ip", "xfrm", "state", "flush")
                states()
                reply({"done": True})
            elif operation == "replace_route":
                run("ip", "route", "replace", DESTINATION + "/32", "via", PEER, "dev", "inject0")
                reply({"done": True})
            elif operation == "delete_interface":
                run("ip", "link", "delete", "xfrm0")
                interface_created = False
                reply({"done": True})
            elif operation in ("interface_down", "interface_up"):
                run("ip", "link", "set", "xfrm0", operation.removeprefix("interface_"))
                reply({"done": True})
            elif operation == "replace_interface_dummy":
                replace_interface("dummy")
                reply({"done": True})
            elif operation == "replace_interface_xfrm":
                replace_interface("xfrm")
                run("ip", "route", "replace", DESTINATION + "/32", "dev", "xfrm0")
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
        if interface_created:
            run("ip", "link", "delete", "xfrm0")
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
