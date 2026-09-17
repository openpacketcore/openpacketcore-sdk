#!/usr/bin/env python3
"""Temporary, bounded #856 recurrence experiment; never retry a failed sample."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
from contextlib import suppress

out = Path("diagnostic-856")
out.mkdir(exist_ok=False)
experiment_deadline = time.monotonic() + 3000


def run_bounded(command, log, seconds):
    """Reap only this invocation if teardown outlives the inner test guard."""
    with log.open("w") as stream:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                   stdout=stream, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            return process.wait(timeout=seconds), False
        except subprocess.TimeoutExpired:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            # A parent may exit before a descendant in its owned group.
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            if process.returncode is None:
                process.wait()
            return 124, True

name = "stateless_quorum_consumer::persistent_three_voter_fenced_status_converges_after_response_loss_and_compaction"
base = ["cargo", "test", "--locked", "--workspace", "--exclude", "opc-persist", "--all-features", "--quiet", "--lib", "--", "--test-threads=1", "--exact", name]
metadata = {
    "head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
    "tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True).strip(),
    "source_baseline": "be7b580986b7efaf87b7aa79b13f55d5d32956c1",
    "observer": "separate_task_without_workload_repoll",
    "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
    "command": base + ["--nocapture"],
    "workload_guard_seconds": 300,
    "maximum_samples": 8,
    "outer_sample_guard_seconds": 600,
    "outer_selection_guard_seconds": 1200,
    "experiment_budget_seconds": 3000,
    "production_behavior_changed": False,
}
(out / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
selection_log = out / "selection.log"
selection_code, selection_timed_out = run_bounded(base + ["--list"], selection_log, 1200)
(out / "selection.json").write_text(json.dumps({"exit_code": selection_code, "outer_timeout": selection_timed_out}, indent=2) + "\n")
if selection_code or selection_log.read_text().splitlines().count(name + ": test") != 1:
    raise SystemExit("exact test must resolve once before any sample")
results = []
for ordinal in range(1, 9):
    log = out / f"sample-{ordinal}.log"
    start = time.monotonic()
    print(f"sample {ordinal}/8 starting", flush=True)
    if experiment_deadline - start < 610:
        (out / "incomplete.json").write_text(json.dumps({"reason": "insufficient_remaining_experiment_budget", "next_sample": ordinal}) + "\n")
        raise SystemExit("Experiment budget exhausted; incomplete evidence, no retry")
    (out / "current-sample.json").write_text(json.dumps({"sample": ordinal, "status": "running"}) + "\n")
    code, outer_timeout = run_bounded(base + ["--nocapture"], log, 600)
    observation = {
        "sample": ordinal,
        "exit_code": code,
        "outer_timeout": outer_timeout,
        "seconds": round(time.monotonic() - start, 3),
        "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
    }
    (out / "current-sample.json").write_text(json.dumps({"sample": ordinal, "status": "finished"}) + "\n")
    results.append(observation)
    (out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(observation), flush=True)
    if code:
        print("Failure preserved; no further sample or retry.", flush=True)
        raise SystemExit(code)
print("No recurrence in this bounded sample. This is not a root-cause or fix claim.", flush=True)
