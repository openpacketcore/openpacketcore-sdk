#!/usr/bin/env python3
"""Exercise real unrelated services and leaked descendants; requires Linux root."""

import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time


SCRIPT = Path(__file__).resolve()
CHECKER = SCRIPT.with_name("check-local-kernel-lifecycle-cleanup.py")
SPEC = importlib.util.spec_from_file_location("cleanup", CHECKER)
CLEANUP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLEANUP)


def syscall(name, *args):
    libc = ctypes.CDLL(None, use_errno=True)
    if getattr(libc, name)(*args) != 0:
        raise OSError(ctypes.get_errno(), name)


def fixture(address, orphan, descriptors):
    # The launcher exits only after its orphan has created the namespaces and
    # connected to the test. No sleeps are used to guess when the leak exists.
    ready_read, ready_write = os.pipe()
    if orphan:
        if os.fork():
            os.close(ready_write)
            if os.read(ready_read, 1) != b"1":
                raise RuntimeError("orphan failed before readiness")
            return
        os.close(ready_read)
        os.setsid()
        if os.fork():
            os._exit(0)
    original = {kind: os.open("/proc/self/ns/" + kind, os.O_RDONLY) for kind in CLEANUP.KINDS}
    syscall("unshare", 0x40000000 | 0x00020000)  # CLONE_NEWNET | CLONE_NEWNS
    namespaces = {kind: os.readlink("/proc/self/ns/" + kind).split("[")[1][:-1]
                  for kind in CLEANUP.KINDS}
    retained = []
    if descriptors:
        for kind in CLEANUP.KINDS:
            retained.append(os.open("/proc/self/ns/" + kind, os.O_RDONLY))
            syscall("setns", original[kind], 0)
    for fd in original.values():
        os.close(fd)
    with socket.socket(socket.AF_UNIX) as control:
        control.connect(address)
        process = CLEANUP.read_stat(Path("/proc/self/stat"))
        control.sendall((json.dumps({"pid": process["pid"], "start_time": process["start_time"],
                                    "namespaces": namespaces}) + "\n").encode())
        if orphan:
            os.write(ready_write, b"1")
        # Keep the fixture finite even if its supervising test is interrupted.
        control.settimeout(60)
        control.recv(1)
    for fd in retained:
        os.close(fd)


def check(command, log, expected=0):
    with log.open("w") as stream:
        result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=45, check=False)
    if result.returncode != expected:
        raise AssertionError(f"expected exit {expected}, got {result.returncode}: {log}")


def run_case(evidence, orphan, descriptors):
    evidence.mkdir()
    cleanup = evidence / "cleanup"
    command = [sys.executable, str(CHECKER)]
    check(command + ["snapshot", str(cleanup)], evidence / "snapshot.log")
    with tempfile.TemporaryDirectory(prefix="namespace-owner-") as directory, \
            socket.socket(socket.AF_UNIX) as listener, (evidence / "fixture.log").open("w") as output:
        address = str(Path(directory) / "control.sock")
        listener.bind(address)
        listener.listen(1)
        listener.settimeout(20)
        child_command = [sys.executable, str(SCRIPT), "--fixture", address]
        if descriptors:
            child_command.append("--descriptors")
        if orphan:
            child_command.append("--orphan")
            child_command = command + ["run", str(cleanup), "--"] + child_command
        launcher = subprocess.Popen(child_command, stdout=output, stderr=subprocess.STDOUT)
        control, held_pid = None, None
        try:
            control, _address = listener.accept()
            control.settimeout(20)
            with control.makefile("rb") as stream:
                holder = json.loads(stream.readline())
            held_pid = os.pidfd_open(holder["pid"])
            (evidence / "holder.json").write_text(json.dumps(holder, indent=2) + "\n")
            if orphan:
                assert launcher.wait(timeout=45) == 1, "leaked qualification child was accepted"
                try:
                    current = CLEANUP.read_stat(Path(f"/proc/{holder['pid']}/stat"))
                except FileNotFoundError:
                    current = None
                assert current is None or CLEANUP.identity(current) != (
                    holder["pid"], holder["start_time"]), "owner returned before reaping its leaked child"
            else:
                check(command + ["run", str(cleanup), "--", sys.executable, "-c", "pass"],
                      evidence / "unrelated-run.log")
                assert CLEANUP.identity(CLEANUP.read_stat(Path(f"/proc/{holder['pid']}/stat"))) == (
                    holder["pid"], holder["start_time"]), "cleanup disposed of an unrelated process"
            records = list(cleanup.glob("attribution-*.json"))
            assert len(records) == 1
            result = json.loads(records[0].read_text())
            assert result["passed"] is not orphan
            for kind, namespace in holder["namespaces"].items():
                attribution = result["namespace_owners"][kind][namespace]
                assert attribution["status"] == ("qualification" if orphan else "unrelated")
                owner = next(owner for owner in attribution["owners"] if owner["pid"] == holder["pid"])
                assert owner["qualification_owned"] is orphan
                assert owner["start_time"] == holder["start_time"]
                assert any(source.startswith("fd:" if descriptors else "task:") for source in owner["sources"])
            check(command + ["verify", str(cleanup)], evidence / "retained-verify.log", 1 if orphan else 0)
        finally:
            if control:
                control.close()
            # A pidfd targets this fixture even if its numeric PID is reused.
            if held_pid is not None:
                try:
                    signal.pidfd_send_signal(held_pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                os.close(held_pid)
            if launcher.poll() is None:
                launcher.terminate()
            launcher.wait(timeout=10)
            deadline = time.monotonic() + 10
            while True:
                try:
                    pid, _status = os.waitpid(-1, os.WNOHANG)
                except ChildProcessError:
                    break
                if not pid:
                    if time.monotonic() >= deadline:
                        raise AssertionError("fixture descendants did not exit")
                    time.sleep(0.01)
    # Prior failure must remain fatal after the leaked process exits. A foreign
    # service exiting must leave a passing baseline and ownership record.
    check(command + ["verify", str(cleanup)], evidence / "departed-verify.log", 1 if orphan else 0)
    print(f"PASS {evidence.name}", flush=True)


def run_interface_case(evidence, owned, renamed=False, replacement=False):
    evidence.mkdir()
    cleanup = evidence / "cleanup"
    command = [sys.executable, str(CHECKER)]
    check(command + ["snapshot", str(cleanup)], evidence / "snapshot.log")
    name = "owned-veth" if owned else "unrelated-veth"
    live_name = "renamed-veth" if renamed else name
    residue = owned and not replacement
    try:
        if owned:
            # Declare the exact fixture name in the owner ledger before its
            # creating command runs. The route belongs to this same interface.
            check(command + ["run", "--owned-interface", name, str(cleanup), "--",
                             "sh", "-ec", 'ip link add "$1" type dummy; '
                             'ip link set "$1" up; '
                             'ip route add 198.18.0.0/24 dev "$1"; '
                             'if [ "$1" != "$2" ]; then ip link set "$1" name "$2"; fi; '
                             'if [ "$3" = replace ]; then ip link del "$2"; fi',
                             "fixture", name, live_name, "replace" if replacement else "keep"],
                  evidence / "owned-run.log", 1 if residue else 0)
            if replacement:
                # After the owned lifetime is gone and its creator has exited,
                # a foreign interface may reuse the same name.
                subprocess.run(["ip", "link", "add", name, "type", "dummy"], check=True)
        else:
            # This process is outside the registered command's ownership tree.
            subprocess.run(["ip", "link", "add", name, "type", "dummy"], check=True)
            check(command + ["run", str(cleanup), "--", sys.executable, "-c", "pass"],
                  evidence / "unrelated-run.log")
        check(command + ["verify", str(cleanup)], evidence / "post-run-verify.log", 1 if residue else 0)
        result = json.loads((cleanup / "result.json").read_text())
        assert result["passed"] is not residue
        assert result["host_interface_changes"]["added"] == [live_name]
        assert (live_name in result["interface_owners"]) is residue
        if owned:
            record = json.loads(next(cleanup.glob("run-*.json")).read_text())
            assert record["link_capture_complete"] and not record["interface_errors"]
            assert len(record["owned_links"]) == 1
            link = record["owned_links"][0]
            live = CLEANUP.link_inventory()
            current = next(value for value in live["links"] if value["ifname"] == live_name)
            assert link["namespace"] == current["namespace"]
            assert link["declared_name"] == name
            assert link["deleted"] is replacement
            assert (link["ifindex"] == current["ifindex"]) is not replacement
            (evidence / "identity.json").write_text(json.dumps({"recorded": link, "current": current,
                        "replacement": replacement, "refused": residue}, indent=2) + "\n")
        if residue:
            assert result["differences"]["interfaces"]["added"] == [live_name]
            routes = subprocess.check_output(["ip", "route", "show", "dev", live_name], text=True)
            assert "198.18.0.0/24" in routes, "the negative fixture lost its owned route"
        else:
            assert not result["differences"], result
    finally:
        subprocess.run(["ip", "link", "del", live_name], check=True)
    check(command + ["verify", str(cleanup)], evidence / "departed-verify.log", 1 if residue else 0)
    print(f"PASS {evidence.name}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--fixture")
    parser.add_argument("--orphan", action="store_true")
    parser.add_argument("--descriptors", action="store_true")
    parser.add_argument("--interface-case", choices=["renamed", "replacement"])
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("root is required; unsupported namespace operations must fail")
    if args.fixture:
        fixture(args.fixture, args.orphan, args.descriptors)
        return
    if args.evidence_dir is None:
        parser.error("--evidence-dir is required")
    # These cases audit our fixtures, not the shared runner's network setup.
    # A new unrelated host interface must not invalidate their baseline. Sysfs
    # retains its mounting network namespace, so unsharing net alone is not
    # sufficient: mount a private read-only view for the isolated namespace.
    syscall("unshare", 0x40000000 | 0x00020000)  # CLONE_NEWNET | CLONE_NEWNS
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "sysfs", "-o", "ro,nosuid,nodev,noexec", "sysfs", "/sys"],
                   check=True)
    args.evidence_dir.mkdir(parents=True, exist_ok=False)
    syscall("prctl", 36, 1, 0, 0, 0)  # Adopt only this test's exited fixture orphans.
    if args.interface_case:
        run_interface_case(args.evidence_dir / (args.interface_case + "-interface"), True,
                           renamed=args.interface_case == "renamed", replacement=args.interface_case == "replacement")
        return
    for orphan in [False, True]:
        for descriptors in [False, True]:
            name = ("qualification-orphan" if orphan else "unrelated-service")
            name += "-descriptors" if descriptors else "-namespaces"
            run_case(args.evidence_dir / name, orphan, descriptors)
    for owned in [False, True]:
        run_interface_case(args.evidence_dir / ("owned-interface" if owned else "unrelated-interface"), owned)
    run_interface_case(args.evidence_dir / "renamed-interface", True, renamed=True)
    run_interface_case(args.evidence_dir / "replacement-interface", True, replacement=True)


if __name__ == "__main__":
    main()
