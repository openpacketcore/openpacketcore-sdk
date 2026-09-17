#!/usr/bin/env python3
"""Temporary, external-only #856 observation; never retry a failing sample."""

import argparse
from contextlib import suppress
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time


TARGET = "stateless_quorum_consumer::persistent_three_voter_fenced_status_converges_after_response_loss_and_compaction"
COMMAND = ["cargo", "test", "--locked", "--workspace", "--exclude", "opc-persist",
           "--all-features", "--quiet", "--lib", "--", "--test-threads=1", "--exact", TARGET]


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def git(source, *arguments):
    return subprocess.check_output(["git", *arguments], cwd=source, text=True).strip()


def identity(pid):
    """Retain the kernel start time as well as PID to reject PID reuse."""
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return pid, int(fields[19])


def same_process(expected, group):
    try:
        return identity(expected[0]) == expected and os.getpgid(expected[0]) == group
    except (OSError, ValueError, IndexError):
        return False


def find_target(parent):
    """Inspect only descendants in the process group this invocation created."""
    pending = [parent]
    visited = set()
    while pending:
        pid = pending.pop()
        if pid in visited:
            continue
        visited.add(pid)
        try:
            if os.getpgid(pid) != parent:
                continue
            command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            if (command and Path(os.fsdecode(command[0])).name.startswith("opc_session_net-")
                    and TARGET.encode() in command):
                return identity(pid)
            children = Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
            pending.extend(int(child) for child in children)
        except (OSError, ValueError, IndexError):
            continue
    return None


def counters(expected, group):
    if not same_process(expected, group):
        return {"process_gone": True}
    result = {"pid": expected[0], "start_ticks": expected[1]}
    for name in ["stat", "io"]:
        with suppress(OSError):
            result[name] = Path(f"/proc/{expected[0]}/{name}").read_text()
    allowed = {"State", "Threads", "VmRSS", "VmSize", "voluntary_ctxt_switches",
               "nonvoluntary_ctxt_switches"}
    with suppress(OSError):
        result["status"] = [line for line in Path(f"/proc/{expected[0]}/status").read_text().splitlines()
                            if line.split(":", 1)[0] in allowed]
    for name in ["cpu", "io", "memory"]:
        with suppress(OSError):
            result[f"pressure_{name}"] = Path(f"/proc/pressure/{name}").read_text()
    with suppress(OSError):
        result["loadavg"] = Path("/proc/loadavg").read_text()
    return result


def outlier_stack(expected, group, output):
    """One bounded stack-only observation, with no argument/value dumping."""
    if not same_process(expected, group):
        return {"result": "process_gone"}
    threads = {}
    for path in Path(f"/proc/{expected[0]}/task").glob("*"):
        with suppress(OSError):
            threads[path.name] = (path / "wchan").read_text()
    write_json(output.with_suffix(".threads.json"), threads)
    debugger = shutil.which("gdb")
    if debugger is None or shutil.which("sudo") is None:
        return {"result": "debugger_unavailable", "thread_wait_channels_recorded": True}
    # timeout and gdb run under the same sudo-owned command. The timeout owns
    # its debugger child and kills it after the grace period if needed.
    command = ["sudo", "-n", "timeout", "--foreground", "--signal=TERM", "--kill-after=5", "15",
               debugger, "--nx", "--nh", "--batch",
               "-ex", "set pagination off", "-ex", "set auto-load off",
               "-ex", "set debuginfod enabled off",
               "-ex", "set print frame-arguments none",
               "-ex", "set print entry-values no", "-ex", "set print address off",
               "-ex", f"attach {expected[0]}",
               "-ex", "thread apply all bt 24", "-ex", "detach"]
    started = time.monotonic()
    result_path = output.with_name(output.name.removesuffix(".stack.log") + ".stack-result.json")
    result = {"result": "debugger_attempted", "scheduling_intrusion": True,
              "argument_values_enabled": False, "cleanup_complete": False}
    # Preserve the intervention marker before Popen/attach, including if the
    # debugger or cleanup raises. A post-attach timeout is not pristine timing.
    write_json(result_path, result)
    process = None
    try:
        with output.open("w") as log:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                       stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                result["exit_code"] = process.wait(timeout=25)
            except subprocess.TimeoutExpired:
                result["outer_debugger_timeout"] = True
                result["exit_code"] = 124
    finally:
        try:
            if process is not None and process.poll() is None:
                # The inner elevated timeout owns gdb. This fallback addresses
                # only the separate group created for this debugger invocation.
                with output.open("a") as log:
                    subprocess.run(["sudo", "-n", "kill", "-KILL", "--", f"-{process.pid}"],
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                   timeout=5, check=False)
                process.wait(timeout=5)
            result["cleanup_complete"] = True
        finally:
            # Even cleanup failure must attempt to resume the exact owned
            # target. The enclosing sample then fails and cleans its own group.
            try:
                if same_process(expected, group):
                    with suppress(ProcessLookupError):
                        os.kill(expected[0], signal.SIGCONT)
                result["resume_checked"] = True
            finally:
                result["seconds"] = round(time.monotonic() - started, 3)
                write_json(result_path, result)
    return result


def terminate_owned(process):
    """Reap this invocation and kill its process group even if its parent exits."""
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    with suppress(subprocess.TimeoutExpired):
        process.wait(timeout=10)
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    if process.returncode is None:
        process.wait(timeout=5)


def run_sample(command, source, output, seconds, observe=True, probe_after=240):
    started = time.monotonic()
    deadline = started + seconds
    target = None
    target_found_at = None
    next_observation = started
    probe = None
    timed_out = False
    with output.open("w") as log, output.with_suffix(".external.jsonl").open("w") as observations:
        process = subprocess.Popen(command, cwd=source, stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            while process.poll() is None:
                now = time.monotonic()
                if now >= deadline:
                    timed_out = True
                    break
                if observe and target is None:
                    target = find_target(process.pid)
                    if target is not None:
                        target_found_at = now
                if target is not None and now >= next_observation:
                    observation = counters(target, process.pid)
                    observation["seconds_since_target_seen"] = round(now - target_found_at, 3)
                    observations.write(json.dumps(observation) + "\n")
                    observations.flush()
                    next_observation = now + 10
                if target is not None and probe is None and now - target_found_at >= probe_after:
                    probe = outlier_stack(target, process.pid, output.with_suffix(".stack.log"))
                    write_json(output.with_suffix(".stack-result.json"), probe)
                time.sleep(min(1, max(0, deadline - time.monotonic())))
            code = 124 if timed_out else process.returncode
        finally:
            # Successful Cargo exit does not prove every descendant exited.
            # Always reap/clean this group, while preserving Cargo's exit code.
            terminate_owned(process)
    return {"command": command, "exit_code": code, "outer_timeout": timed_out,
            "seconds": round(time.monotonic() - started, 3), "target_seen": target is not None,
            "stack_probe": probe, "log_sha256": hashlib.sha256(output.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=16)
    args = parser.parse_args()
    if not 1 <= args.samples <= 16:
        parser.error("samples must be in 1..16")
    source = args.source.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(exist_ok=False)
    if git(source, "status", "--porcelain"):
        raise SystemExit("source checkout is not clean")
    metadata = {"source_head": git(source, "rev-parse", "HEAD"),
                "source_tree": git(source, "rev-parse", "HEAD^{tree}"),
                "source_status": "clean", "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
                "target_command": COMMAND, "requested_samples": args.samples,
                "workload_guard_seconds": 300, "outer_sample_guard_seconds": 600,
                "outlier_probe_after_target_seen_seconds": 240,
                "experiment_budget_seconds": 3300, "sample_admission_reserve_seconds": 670,
                "rust_source_modified": False,
                "observer": "separate_os_process_proc_counters_and_outlier_only_stack",
                "observation_scope": ["owned_target_process_counters_and_threads",
                                      "aggregate_host_cpu_io_memory_pressure_and_load"]}
    metadata["clock_ticks_per_second"] = os.sysconf("SC_CLK_TCK")
    metadata["logical_cpus"] = os.cpu_count()
    metadata["harness_head"] = git(Path(__file__).resolve().parent.parent, "rev-parse", "HEAD")
    metadata["harness_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    write_json(output / "metadata.json", metadata)
    experiment_deadline = time.monotonic() + 3300
    results = []
    selection = run_sample(COMMAND + ["--list"], source, output / "selection.log", 1200, observe=False)
    results.append({"sample": "selection", **selection})
    write_json(output / "results.json", results)
    if selection["exit_code"]:
        raise SystemExit(selection["exit_code"])
    selected = (output / "selection.log").read_text()
    if selected.splitlines().count(TARGET + ": test") != 1:
        raise SystemExit("exact target does not resolve once")
    for index in range(1, args.samples + 1):
        # 600s sample + <=35s outlier probe + <=15s cleanup, with margin.
        if experiment_deadline - time.monotonic() < 670:
            write_json(output / "incomplete.json", {"reason": "experiment_budget", "next_sample": index})
            raise SystemExit("Incomplete experiment; no sample started without its guard budget")
        result = run_sample(COMMAND, source, output / f"sample-{index:02d}.log", 600)
        result["successful_target_results"] = re.findall(
            r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 602 filtered out; finished in ([0-9.]+)s",
            (output / f"sample-{index:02d}.log").read_text(errors="replace"),
        )
        results.append({"sample": index, **result})
        write_json(output / "results.json", results)
        print(json.dumps(results[-1]), flush=True)
        if result["exit_code"]:
            raise SystemExit(result["exit_code"])
        if not result["target_seen"]:
            raise SystemExit("target process not observed; refusing incomplete evidence")
        if len(result["successful_target_results"]) != 1:
            raise SystemExit("exact target pass was not proven once")
        if git(source, "status", "--porcelain") or git(source, "rev-parse", "HEAD") != metadata["source_head"]:
            raise SystemExit("source changed during experiment")
    print("All requested samples passed unchanged source; this is not a causal fix.", flush=True)


if __name__ == "__main__":
    main()
