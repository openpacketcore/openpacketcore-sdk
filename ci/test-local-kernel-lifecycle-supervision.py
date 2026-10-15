#!/usr/bin/env python3
"""Require the unprivileged ownership wrapper to dispose of its descendants."""

import argparse
import ctypes
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time


SCRIPT = Path(__file__).resolve()
CHECKER = SCRIPT.with_name("check-local-kernel-lifecycle-cleanup.py")


def process(pid):
    text = Path(f"/proc/{pid}/stat").read_text()
    fields = text[text.rindex(")") + 2:].split()
    return {"pid": pid, "state": fields[0], "ppid": int(fields[1]), "start_time": int(fields[19])}


def same_process(expected):
    try:
        current = process(expected["pid"])
    except FileNotFoundError:
        return None
    return current if current["start_time"] == expected["start_time"] else None


def wait_file(path):
    deadline = time.monotonic() + 15
    while not path.exists():
        if time.monotonic() >= deadline:
            raise AssertionError(f"fixture readiness deadline: {path}")
        time.sleep(0.01)


def fixture(directory, mode):
    primary = process(os.getpid())
    ready_read, ready_write = os.pipe()
    if os.fork():
        os.close(ready_write)
        assert os.read(ready_read, 1) == b"1"
        os.close(ready_read)
        if mode != "return":
            deadline = time.monotonic() + 45
            while not (directory / "release").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
        return
    os.close(ready_read)
    os.setsid()
    if os.fork():
        os._exit(0)
    # Force the wrapper to exercise escalation, including for a root child.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    with (directory / "holder.tmp").open("w") as output:
        json.dump({"holder": process(os.getpid()), "primary": primary}, output)
    (directory / "holder.tmp").replace(directory / "holder.json")
    os.write(ready_write, b"1")
    os.close(ready_write)
    deadline = time.monotonic() + 45
    while not (directory / "release").exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    os._exit(0)


def dispose_fixture(expected):
    """Fallback only; never turn an observed leftover into a passing result."""
    try:
        pidfd = os.pidfd_open(expected["pid"])
    except ProcessLookupError:
        return
    try:
        if same_process(expected):
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
    finally:
        os.close(pidfd)


def reap_fixture_children():
    deadline = time.monotonic() + 10
    reaped = []
    while True:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return reaped
        if pid:
            reaped.append({"pid": pid, "status": status})
        elif time.monotonic() >= deadline:
            raise AssertionError("fixture children did not exit")
        else:
            time.sleep(0.01)


def check(command, log, expected=0):
    with log.open("w") as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT,
                                check=False, timeout=30)
    assert result.returncode == expected, f"expected {expected}, got {result.returncode}: {log}"


def run_case(directory, mode, root_child):
    directory.mkdir()
    cleanup = directory / "cleanup"
    cleanup.mkdir()  # The unprivileged owner must be able to save its record.
    privileged = ["sudo", "-n", sys.executable, str(CHECKER)]
    check(privileged + ["snapshot", str(cleanup)], directory / "snapshot.log")
    child = [sys.executable, str(SCRIPT), "--fixture", str(directory), "--mode", mode]
    if root_child:
        child = ["sudo", "-n"] + child
    command = [sys.executable, str(CHECKER), "run", str(cleanup), "--"] + child
    owner, pidfd, identities = None, None, {}
    result = {"command": command, "mode": mode, "root_child": root_child}
    try:
        with (directory / "run.log").open("w") as output:
            owner = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
            wait_file(directory / "holder.json")
            identities = json.loads((directory / "holder.json").read_text())
            pidfd = os.pidfd_open(identities["holder"]["pid"])
            if mode != "return":
                owner.send_signal(getattr(signal, mode))
            result["wrapper_exit"] = owner.wait(timeout=30)
        result["after_wrapper_exit"] = {name: same_process(value) for name, value in identities.items()}
        result["holder_exited"] = bool(select.select([pidfd], [], [], 0)[0])
        result["records"] = [json.loads(path.read_text()) for path in cleanup.glob("run-*.json")]
        result["attributions"] = [json.loads(path.read_text()) for path in cleanup.glob("attribution-*.json")]
        # These observations precede every release, signal and fallback reap.
        assert not any(result["after_wrapper_exit"].values()), (
            "wrapper exited before disposing and reaping owned descendants: "
            + json.dumps(result["after_wrapper_exit"]))
        assert result["holder_exited"]
        assert result["wrapper_exit"] == (1 if mode == "return" else 128 + getattr(signal, mode))
        assert len(result["records"]) == len(result["attributions"]) == 1
        assert not result["records"][0]["cleanup_passed"]
        attribution = result["attributions"][0]
        assert not attribution["passed"]
        assert "qualification command left live descendant processes" in attribution["errors"]
        assert any(child["pid"] == identities["holder"]["pid"]
                   and child["start_time"] == identities["holder"]["start_time"]
                   for child in attribution["surviving_processes"])
        check(privileged + ["verify", str(cleanup)], directory / "verify.log", 1)
        assert not json.loads((cleanup / "result.json").read_text())["passed"]
        result["passed"] = True
    finally:
        (directory / "release").write_text("release\n")
        if owner is not None and owner.poll() is None:
            owner.terminate()
            owner.wait(timeout=30)
        for expected in identities.values():
            if same_process(expected):
                subprocess.run(["sudo", "-n", sys.executable, str(SCRIPT), "--dispose",
                                str(expected["pid"]), str(expected["start_time"])], check=True, timeout=10)
        if pidfd is not None:
            os.close(pidfd)
        result["fallback_reaped"] = reap_fixture_children()
        result["fixture_children_remaining"] = Path(f"/proc/self/task/{os.getpid()}/children").read_text().split()
        (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    assert not result["fixture_children_remaining"]
    print(f"PASS {directory.name}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--mode", choices=["return", "SIGTERM", "SIGINT"], default="return")
    parser.add_argument("--dispose", type=int, nargs=2)
    parser.add_argument("--case", choices=["return-user", "SIGTERM-user", "SIGINT-user",
                                           "return-root", "SIGTERM-root", "SIGINT-root"])
    args = parser.parse_args()
    if args.fixture:
        return fixture(args.fixture, args.mode)
    if args.dispose:
        return dispose_fixture(dict(zip(["pid", "start_time"], args.dispose)))
    if args.evidence_dir is None or os.geteuid() == 0:
        parser.error("--evidence-dir and an unprivileged owner with noninteractive sudo are required")
    args.evidence_dir.mkdir(parents=True, exist_ok=False)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "cannot adopt fixture orphans")
    for root_child in [False, True]:
        for mode in ["return", "SIGTERM", "SIGINT"]:
            name = mode + ("-root" if root_child else "-user")
            if args.case is None or args.case == name:
                run_case(args.evidence_dir / name, mode, root_child)


if __name__ == "__main__":
    main()
