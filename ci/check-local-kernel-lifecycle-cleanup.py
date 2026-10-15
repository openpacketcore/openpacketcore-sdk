#!/usr/bin/env python3
"""Attribute native lifecycle namespace residue and require host-state cleanup.

Run namespace-creating commands through the run mode. Its child subreaper keeps
orphaned descendants attributable until cleanup, including children of sudo.
Unrelated processes may create or release namespaces on a shared host. Pins,
mounts, named namespaces and interfaces must still match the original baseline.
"""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import time
import uuid


KINDS = ("net", "mnt")
SCRIPT = Path(__file__).resolve()
TERM_GRACE_SECONDS = 2
KILL_GRACE_SECONDS = 3


def lines(command: list[str]) -> list[str]:
    return sorted(set(subprocess.check_output(command, text=True).splitlines()))


def namespace_ids(kind: str) -> list[str]:
    values = lines(["lsns", "--type", kind, "--noheadings", "--output", "NS"])
    values = sorted(value.strip() for value in values)
    if not values or not all(value.isdecimal() for value in values):
        raise ValueError(f"incomplete {kind} namespace inventory")
    return values


def namespace_inventory() -> dict[str, list[str]]:
    namespaces = {kind: set(namespace_ids(kind)) for kind in KINDS}
    # lsns alone can miss a namespace kept alive solely by an open descriptor.
    processes, errors = process_inventory()
    if errors:
        raise ValueError("incomplete process namespace inventory: " + "; ".join(errors))
    for process in processes.values():
        for kind in KINDS:
            namespaces[kind].update(process["namespaces"][kind])
    return {kind: sorted(values) for kind, values in namespaces.items()}


def snapshot() -> dict[str, list[str]]:
    return {
        **namespace_inventory(),
        "named_netns": lines(["ip", "netns", "list"]),
        "bpffs_entries": lines(["find", "/sys/fs/bpf", "-mindepth", "1", "-printf", "%P %y %i\n"]),
        "bpffs_mounts": sorted(line for line in Path("/proc/self/mountinfo").read_text().splitlines()
                               if " - bpf " in line),
        "interfaces": sorted(path.name for path in Path("/sys/class/net").iterdir()),
    }


def differences(before: dict, after: dict) -> dict:
    required = {"net", "mnt", "named_netns", "bpffs_entries", "bpffs_mounts", "interfaces"}
    for inventory in [before, after]:
        if set(inventory) != required or any(
            not isinstance(values, list) or any(not isinstance(value, str) for value in values)
            for values in inventory.values()
        ) or any(not inventory[kind] for kind in ["net", "mnt"]):
            raise ValueError("incomplete cleanup inventory")
    changed = {}
    for name in sorted(required):
        added = sorted(set(after[name]) - set(before[name]))
        # Unrelated system services may finish and release their namespaces.
        # Host-visible pins, mounts, names and interfaces must remain exact.
        removed = [] if name in {"net", "mnt"} else sorted(set(before[name]) - set(after[name]))
        if added or removed:
            changed[name] = {"added": added, "removed": removed}
    return changed


def read_stat(path: Path) -> dict:
    text = path.read_text()
    end = text.rindex(")")
    fields = text[end + 2:].split()
    return {"pid": int(text.split(" ", 1)[0]), "comm": text[text.index("(") + 1:end],
            "state": fields[0], "ppid": int(fields[1]), "start_time": int(fields[19])}


def identity(process: dict) -> tuple[int, int]:
    pid, start = process["pid"], process["start_time"]
    if type(pid) is not int or type(start) is not int or pid <= 0 or start < 0:
        raise ValueError("invalid process identity")
    return pid, start


def process_inventory(wanted=None, proc_root=Path("/proc")) -> tuple[dict, list[str]]:
    """Read process identities and every task/fd holding a candidate namespace.

    A process that exits during collection contributes no inventory error. A
    surviving unreadable process does: absence of ownership evidence is never
    permission to classify a namespace as unrelated.
    """
    processes, errors = {}, []
    for directory in sorted(proc_root.iterdir()):
        if not directory.name.isdecimal():
            continue
        local_errors = []
        try:
            before = read_stat(directory / "stat")
            process = {**before, "cgroup": (directory / "cgroup").read_text().splitlines(),
                       "namespaces": {kind: {} for kind in KINDS}, "live": False}
            tasks = list((directory / "task").iterdir())
            for task in tasks:
                try:
                    state = read_stat(task / "stat")["state"]
                    process["live"] |= state not in {"Z", "X"}
                    if wanted == {}:
                        continue
                    paths = [(task / "ns" / kind, f"task:{task.name}") for kind in KINDS]
                    paths.extend((fd, f"fd:{task.name}:{fd.name}") for fd in (task / "fd").iterdir())
                    for path, source in paths:
                        try:
                            value = os.readlink(path)
                        except FileNotFoundError:
                            continue  # A task or fd closed during collection.
                        except OSError as error:
                            local_errors.append(f"pid {before['pid']} {source}: {error}")
                            continue
                        match = re.fullmatch(r"(net|mnt):\[([0-9]+)\]", value)
                        if match and (wanted is None or match[2] in wanted.get(match[1], set())):
                            sources = process["namespaces"][match[1]].setdefault(match[2], [])
                            if source not in sources:
                                sources.append(source)
                except FileNotFoundError:
                    continue
                except OSError as error:
                    local_errors.append(f"pid {before['pid']} task {task.name}: {error}")
            after = read_stat(directory / "stat")
            if identity(before) != identity(after):
                errors.append(f"pid {before['pid']} changed identity during collection")
                continue
            process.update(after)
            processes[process["pid"]] = process
            errors.extend(local_errors)
        except FileNotFoundError as error:
            if (directory / "stat").exists():
                errors.append(f"pid {directory.name}: {error}")
        except (OSError, ValueError, IndexError) as error:
            # Recheck exit after a permissions/metadata race before retaining it.
            if (directory / "stat").exists():
                errors.append(f"pid {directory.name}: {error}")
    return processes, errors


def ancestors(pid: int, processes: dict):
    seen = set()
    while pid in processes and pid not in seen:
        seen.add(pid)
        process = processes[pid]
        yield process
        pid = process["ppid"]


def belongs_to(process: dict, roots: set, processes: dict) -> bool:
    return any(identity(ancestor) in roots for ancestor in ancestors(process["pid"], processes))


def known_ancestry(process: dict, processes: dict) -> bool:
    """A disappearing/reused parent cannot prove that a holder is unrelated."""
    for ancestor in ancestors(process["pid"], processes):
        parent = ancestor["ppid"]
        if parent == 0 or ancestor["pid"] == 1:
            return True
        if parent not in processes or processes[parent]["start_time"] > ancestor["start_time"]:
            return False
    return False


def direct_children(pid: int) -> set[int]:
    return {int(value) for value in Path(f"/proc/{pid}/task/{pid}/children").read_text().split()}


def write_json(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("x") as output:
            json.dump(value, output, indent=2)
            output.write("\n")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def ownership(evidence: Path) -> tuple[dict, dict]:
    context = json.loads((evidence / "ownership.json").read_text())
    baseline = hashlib.sha256((evidence / "before.json").read_bytes()).hexdigest()
    if not isinstance(context, dict) or context.get("version") != 1 \
            or not isinstance(context.get("id"), str) or not context["id"] \
            or context.get("baseline_sha256") != baseline:
        raise ValueError("namespace ownership does not match the cleanup baseline")
    records = {}
    for path in sorted(evidence.glob("run-*.json")):
        record = json.loads(path.read_text())
        if not isinstance(record, dict) or record.get("version") != 1 or record.get("owner_id") != context["id"] \
                or record.get("status") not in {"running", "complete"} \
                or not isinstance(record.get("command"), list) or not record["command"]:
            raise ValueError(f"invalid namespace ownership record: {path.name}")
        identity(record["root"])
        if record["status"] == "complete":
            if type(record.get("exit_code")) is not int or type(record.get("cleanup_passed")) is not bool \
                    or not isinstance(record.get("survivors"), list):
                raise ValueError(f"incomplete namespace ownership record: {path.name}")
            for process in record["survivors"]:
                identity(process)
        records[path.name] = record
    return context, records


def verify(evidence: Path, run_id=None, command_exit_code=None) -> int:
    suffix = "" if run_id is None else "-" + run_id
    result_path = evidence / ("result.json" if run_id is None else "attribution" + suffix + ".json")
    result = {"passed": False, "differences": {}, "namespace_owners": {}, "errors": []}
    current_record = None
    try:
        current = snapshot()
        write_json(evidence / ("after" + suffix + ".json"), current)
        result["differences"] = differences(json.loads((evidence / "before.json").read_text()), current)
        _context, records = ownership(evidence)
        current_name = None if run_id is None else "run-" + run_id + ".json"
        if current_name is not None:
            current_record = records[current_name]
            if current_record["status"] != "running" or command_exit_code is None:
                raise ValueError("ownership run is not awaiting cleanup")
        roots = {identity(record["root"]) for record in records.values()}
        roots.update(identity(process) for record in records.values() for process in record.get("survivors", []))
        for name, record in records.items():
            if name != current_name and (record["status"] != "complete" or not record["cleanup_passed"]):
                result["errors"].append(f"ownership run incomplete or previously failed cleanup: {name}")
        wanted = {kind: set(result["differences"].get(kind, {}).get("added", [])) for kind in KINDS}
        wanted = {kind: values for kind, values in wanted.items() if values}
        processes, errors = process_inventory(wanted) if wanted or current_record else ({}, [])
        result["errors"].extend(errors)
        survivors = []
        if current_record:
            if command_exit_code < 0:
                result["errors"].append(f"qualification command interrupted by signal {-command_exit_code}")
            root = identity(current_record["root"])
            verification_chain = list(ancestors(os.getpid(), processes))
            if root not in {identity(process) for process in verification_chain}:
                raise ValueError("cleanup verifier is not a child of the registered owner")
            # The controller and this verification/sudo chain are still running
            # deliberately. Every other live descendant is unfinished test work.
            excluded = {process["pid"] for process in verification_chain}
            # A parent may exit while /proc is scanned. The subreaper's direct
            # children then prove ownership even if a child's saved PPID still
            # names that vanished parent. Missing child metadata fails closed.
            children = direct_children(root[0]) - excluded
            if not children.issubset(processes):
                raise ValueError("qualification child changed during process inventory")
            current_roots = {root} | {identity(processes[pid]) for pid in children}
            roots.update(current_roots)
            survivors = [process for process in processes.values()
                         if process["pid"] not in excluded
                         and process.get("live", process["state"] not in {"Z", "X"})
                         and belongs_to(process, current_roots, processes)]
            if survivors:
                result["errors"].append("qualification command left live descendant processes")
            result["surviving_processes"] = survivors
        for kind, values in wanted.items():
            result["namespace_owners"][kind] = {}
            retained = []
            remaining = None
            for value in sorted(values):
                owners = []
                for process in processes.values():
                    sources = process["namespaces"].get(kind, {}).get(value, [])
                    if sources:
                        owners.append({key: process[key] for key in
                                       ["pid", "ppid", "start_time", "comm", "cgroup"]} | {
                                           "sources": sources,
                                           "qualification_owned": belongs_to(process, roots, processes),
                                           "ancestry_complete": known_ancestry(process, processes),
                                       })
                if any(owner["qualification_owned"] for owner in owners):
                    status = "qualification"
                elif not records or result["errors"] or any(not owner["ancestry_complete"] for owner in owners):
                    status = "unknown"
                elif owners:
                    status = "unrelated"
                else:
                    if remaining is None:
                        remaining = set(namespace_inventory()[kind])
                    status = "gone" if value not in remaining else "unknown"
                result["namespace_owners"][kind][value] = {"status": status, "owners": owners}
                if status in {"qualification", "unknown"}:
                    retained.append(value)
            if retained:
                result["differences"][kind]["added"] = retained
            else:
                result["differences"].pop(kind, None)
        result["passed"] = not result["differences"] and not result["errors"]
        if current_record:
            current_record.update(status="complete", exit_code=command_exit_code,
                                  survivors=survivors, cleanup_passed=result["passed"],
                                  attribution=result_path.name)
            write_json(evidence / current_name, current_record)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result["passed"] = False
        result["errors"].append(str(error))
    write_json(result_path, result)
    if not result["passed"]:
        print("::error::native lifecycle cleanup failed; inspect namespace ownership evidence", file=sys.stderr)
        return 1
    print("local kernel lifecycle cleanup: PASS")
    return 0


def current_ancestry(process: dict):
    """Read ancestry afresh; a reused parent cannot establish ownership."""
    seen = set()
    while process["pid"] not in seen:
        seen.add(process["pid"])
        yield process
        if process["ppid"] == 0:
            return
        parent = read_stat(Path(f"/proc/{process['ppid']}/stat"))
        if parent["start_time"] > process["start_time"]:
            raise ValueError("parent identity changed during descendant cleanup")
        process = parent


def pin_owned_process(process: dict, root: tuple[int, int]):
    """Pin the selected identity before checking its current owner ancestry."""
    descriptor = os.pidfd_open(process["pid"])
    retained = False
    try:
        current = read_stat(Path(f"/proc/{process['pid']}/stat"))
        if identity(current) != identity(process) \
                or root not in {identity(parent) for parent in current_ancestry(current)}:
            return None
        retained = True
        return descriptor
    finally:
        # A successful caller owns the descriptor until disposal finishes.
        if not retained:
            os.close(descriptor)


def owned_descendants(root: tuple[int, int], excluded: set) -> list[dict]:
    if identity(read_stat(Path(f"/proc/{root[0]}/stat"))) != root:
        raise ValueError("registered namespace owner changed identity")
    pending, seen, descendants = [root[0]], set(), []
    while pending:
        parent = pending.pop()
        if parent in seen:
            continue
        seen.add(parent)
        try:
            tasks = list(Path(f"/proc/{parent}/task").iterdir())
        except FileNotFoundError:
            continue
        for task in tasks:
            try:
                children = (task / "children").read_text().split()
            except FileNotFoundError:
                continue
            for child in children:
                try:
                    process = read_stat(Path(f"/proc/{child}/stat"))
                    if identity(process) in excluded:
                        continue
                    if root not in {identity(ancestor) for ancestor in current_ancestry(process)}:
                        continue
                except (FileNotFoundError, ValueError):
                    # Reparenting or PID reuse can invalidate this observation.
                    # Rescan; never signal a process whose owner is uncertain.
                    continue
                if process["pid"] not in {child["pid"] for child in descendants}:
                    descendants.append(process)
                    pending.append(process["pid"])
    return descendants


def dispose_descendants(evidence: Path, run_id: str) -> int:
    """Bounded disposal runs as root while the owner stays alive and reaps."""
    result = {"passed": False, "targets": [], "remaining": [], "errors": [],
              "had_live_descendants": False,
              "term_grace_seconds": TERM_GRACE_SECONDS, "kill_grace_seconds": KILL_GRACE_SECONDS}
    pinned = {}
    record = None
    started = time.monotonic()
    try:
        _context, records = ownership(evidence)
        record = records["run-" + run_id + ".json"]
        root = identity(record["root"])
        chain = list(current_ancestry(read_stat(Path("/proc/self/stat"))))
        if root not in {identity(process) for process in chain}:
            raise ValueError("descendant disposer is not a child of the registered owner")
        excluded = {identity(process) for process in chain}
        while True:
            remaining = owned_descendants(root, excluded)
            for process in remaining:
                key = identity(process)
                if key in pinned:
                    continue
                try:
                    descriptor = pin_owned_process(process, root)
                except ProcessLookupError:
                    continue
                except FileNotFoundError:
                    continue
                if descriptor is None:
                    continue
                target = {"pid": key[0], "start_time": key[1], "signals": []}
                result["targets"].append(target)
                pinned[key] = descriptor, target
            elapsed = time.monotonic() - started
            signum = signal.SIGTERM if elapsed < TERM_GRACE_SECONDS else signal.SIGKILL
            live = False
            for descriptor, target in pinned.values():
                if select.select([descriptor], [], [], 0)[0]:
                    continue
                live = True
                result["had_live_descendants"] = True
                if signum not in target["signals"]:
                    try:
                        signal.pidfd_send_signal(descriptor, signum)
                        target["signals"].append(signum)
                    except ProcessLookupError:
                        pass
            if not remaining and not live:
                # A parent may exit during the scan and leave a newly adopted
                # child outside that snapshot. The owner cannot finish until
                # its kernel child list contains only this verifier's chain.
                if not direct_children(root[0]) - {process["pid"] for process in chain}:
                    result["passed"] = True
                    break
            if elapsed >= TERM_GRACE_SECONDS + KILL_GRACE_SECONDS:
                result["remaining"] = remaining
                result["unreaped_child_pids"] = sorted(
                    direct_children(root[0]) - {process["pid"] for process in chain})
                result["errors"].append("owned descendants did not exit within the disposal deadline")
                break
            time.sleep(0.02)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result["errors"].append(str(error))
    finally:
        for descriptor, _target in pinned.values():
            os.close(descriptor)
        result["elapsed_seconds"] = time.monotonic() - started
        path = evidence / ("disposal-" + run_id + ".json")
        write_json(path, result)
        if record is not None:
            record["disposal"] = path.name
            # Disposal must never forgive a leak, even if it appeared after
            # the attribution inventory or the disposer itself failed.
            if result["had_live_descendants"] or not result["passed"]:
                record["cleanup_passed"] = False
            write_json(evidence / ("run-" + run_id + ".json"), record)
    return 0 if result["passed"] and not result["had_live_descendants"] else 1


def reap_finished_children(excluded: set[int]) -> None:
    for pid in direct_children(os.getpid()) - excluded:
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass


def run_owned_command(evidence: Path, command: list[str]) -> int:
    context, _records = ownership(evidence)
    # An orphan stays in our process tree until verification. PID start times
    # prevent later PID reuse from inheriting this ownership after we exit.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "cannot become namespace-owner subreaper")
    run_id = uuid.uuid4().hex
    root = read_stat(Path("/proc/self/stat"))
    record = {"version": 1, "owner_id": context["id"], "status": "running",
              "root": {"pid": root["pid"], "start_time": root["start_time"]}, "command": command}
    with (evidence / ("run-" + run_id + ".json")).open("x") as output:
        json.dump(record, output, indent=2)
        output.write("\n")
    interrupted = None

    def interrupt(signum, _frame):
        nonlocal interrupted
        if interrupted is None:
            interrupted = signum

    handlers = {signum: signal.signal(signum, interrupt) for signum in [signal.SIGTERM, signal.SIGINT]}
    primary = None
    try:
        try:
            primary = subprocess.Popen(command)
            while primary.poll() is None and interrupted is None:
                reap_finished_children({primary.pid})
                time.sleep(0.02)
            code = -interrupted if interrupted is not None else primary.returncode
        except OSError:
            code = 127
        # Capture the original leak before disposal, including an interrupted
        # primary command. The verifier has permission to signal sudo children.
        reap_finished_children({primary.pid} if primary else set())
        privileged = [] if os.geteuid() == 0 else ["sudo", "-n"]
        check = privileged + [sys.executable, str(SCRIPT), "verify", str(evidence),
                              "--run-id", run_id, "--command-exit-code", str(code),
                              "--dispose-descendants"]
        # A process-group interruption must not interrupt the cleanup helper.
        verifier = subprocess.Popen(check, start_new_session=True)
        while verifier.poll() is None:
            if primary:
                primary.poll()
            reap_finished_children({verifier.pid} | ({primary.pid} if primary else set()))
            time.sleep(0.02)
        if primary:
            primary.poll()
        reap_finished_children(set())
        cleanup = verifier.returncode or bool(direct_children(os.getpid()))
        if interrupted is not None:
            # A signal can arrive during verification/disposal. Keep that
            # interruption sticky without replacing the original attribution.
            path = evidence / ("run-" + run_id + ".json")
            record = json.loads(path.read_text())
            record.update(interrupted_signal=interrupted, cleanup_passed=False)
            write_json(path, record)
            return 128 + interrupted
        return (code if code > 0 else 128 - code) if code else int(cleanup)
    finally:
        for signum, handler in handlers.items():
            signal.signal(signum, handler)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    for name in ["snapshot", "verify", "run"]:
        mode = modes.add_parser(name)
        mode.add_argument("evidence_dir", type=Path)
        if name == "verify":
            mode.add_argument("--run-id")
            mode.add_argument("--command-exit-code", type=int)
            mode.add_argument("--dispose-descendants", action="store_true")
        if name == "run":
            mode.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    baseline = args.evidence_dir / "before.json"
    try:
        if args.mode == "run":
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            if not command:
                parser.error("run requires a namespace-creating command")
            return run_owned_command(args.evidence_dir, command)
        if os.geteuid() != 0:
            raise ValueError("snapshot and verify require root to attribute every process namespace")
        if args.mode == "snapshot":
            current = snapshot()
            # Never replace the baseline after preflight or a failed test.
            with baseline.open("x") as output:
                json.dump(current, output, indent=2)
                output.write("\n")
            with (args.evidence_dir / "ownership.json").open("x") as output:
                json.dump({"version": 1, "id": uuid.uuid4().hex,
                           "baseline_sha256": hashlib.sha256(baseline.read_bytes()).hexdigest()},
                          output, indent=2)
                output.write("\n")
            return 0
        if args.run_id is not None and not re.fullmatch(r"[0-9a-f]{32}", args.run_id):
            raise ValueError("invalid ownership run identifier")
        if args.dispose_descendants and args.run_id is None:
            raise ValueError("descendant disposal requires an ownership run identifier")
        disposal = 0
        try:
            result = verify(args.evidence_dir, args.run_id, args.command_exit_code)
        finally:
            if args.dispose_descendants:
                disposal = dispose_descendants(args.evidence_dir, args.run_id)
        return result or disposal
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
