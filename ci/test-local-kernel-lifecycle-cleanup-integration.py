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
            else:
                check(command + ["run", str(cleanup), "--", sys.executable, "-c", "pass"],
                      evidence / "unrelated-run.log")
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--fixture")
    parser.add_argument("--orphan", action="store_true")
    parser.add_argument("--descriptors", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("root is required; unsupported namespace operations must fail")
    if args.fixture:
        fixture(args.fixture, args.orphan, args.descriptors)
        return
    if args.evidence_dir is None:
        parser.error("--evidence-dir is required")
    args.evidence_dir.mkdir(parents=True, exist_ok=False)
    syscall("prctl", 36, 1, 0, 0, 0)  # Adopt only this test's exited fixture orphans.
    for orphan in [False, True]:
        for descriptors in [False, True]:
            name = ("qualification-orphan" if orphan else "unrelated-service")
            name += "-descriptors" if descriptors else "-namespaces"
            run_case(args.evidence_dir / name, orphan, descriptors)


if __name__ == "__main__":
    main()
