#!/usr/bin/env python3
"""Temporary #856 original-shard-prefix experiment; never retry any failure."""
import hashlib
import json
import os
from pathlib import Path
import signal
import shlex
import subprocess
import time
from contextlib import suppress

out = Path("diagnostic-856")
out.mkdir(exist_ok=False)
experiment_deadline = time.monotonic() + 3300


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
    "target_command": base,
    "experiment": "original_misc_shard_prefix_through_target_once",
    "workload_guard_seconds": 300,
    "maximum_target_samples": 1,
    "outer_target_guard_seconds": 600,
    "outer_precheck_guard_seconds": 1200,
    "experiment_budget_seconds": 3300,
    "production_behavior_changed": False,
}
# Actions has already constructed this diagnostic-only job graph. Restore the
# exact original workflow as file input to the unchanged original precheck;
# this cannot dispatch the historical jobs. Retain the file and its hash so the
# tested checkout's sole runtime source substitution is explicit in evidence.
workflow_source = subprocess.check_output([
    "git", "show", metadata["source_baseline"] + ":.github/workflows/ci.yml"
])
(out / "original-workflow.yml").write_bytes(workflow_source)
Path(".github/workflows/ci.yml").write_bytes(workflow_source)
metadata["runtime_workflow_substitution"] = {
    "path": ".github/workflows/ci.yml",
    "from_commit": metadata["source_baseline"],
    "sha256": hashlib.sha256(workflow_source).hexdigest(),
    "purpose": "unchanged_original_precheck_input_only",
}
(out / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
results = []


def run_step(label, command, maximum_seconds, minimum_remaining=15):
    """Stop at the first failed prefix command, preserving its exact evidence."""
    log = out / f"{label}.log"
    start = time.monotonic()
    remaining = experiment_deadline - start
    if remaining < minimum_remaining:
        (out / "incomplete.json").write_text(json.dumps({"reason": "insufficient_remaining_experiment_budget", "next_step": label}) + "\n")
        raise SystemExit("Experiment budget exhausted; incomplete evidence, no retry")
    guard = min(maximum_seconds, remaining - 10)
    print(f"{label} starting: {shlex.join(command)}", flush=True)
    (out / "current-step.json").write_text(json.dumps({"step": label, "status": "running", "command": command, "outer_guard_seconds": guard}) + "\n")
    code, outer_timeout = run_bounded(command, log, guard)
    observation = {
        "step": label,
        "command": command,
        "exit_code": code,
        "outer_timeout": outer_timeout,
        "outer_guard_seconds": guard,
        "seconds": round(time.monotonic() - start, 3),
        "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
    }
    (out / "current-step.json").write_text(json.dumps({"step": label, "status": "finished"}) + "\n")
    results.append(observation)
    (out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(observation), flush=True)
    if code:
        print("Failure preserved; no further command or retry. A prefix failure is not a target recurrence.", flush=True)
        raise SystemExit(code)
    return log


# Use exactly the original workflow's precheck before its generated commands.
run_step("precheck", ["python3", "ci/test-shards.py", "precheck", "--shard", "misc"], 1200)
plan_log = run_step("plan", ["python3", "ci/test-shards.py", "plan", "--shard", "misc"], 60)
# The plan's manifest audit is on stderr, which the diagnostic log also retains.
commands = [shlex.split(line) for line in plan_log.read_text().splitlines() if line.startswith("cargo ")]
target_indices = [index for index, command in enumerate(commands) if command == base]
if target_indices != [2] or len(commands) != 9:
    raise SystemExit("original misc prefix shape changed; refusing an inferred workload")
prefix = commands[:3]
previous = base[:-1] + ["stateless_quorum_consumer::persistent_three_voter_consumer_write_does_not_spend_budget_on_a_read_quorum"]
if prefix[1] != previous or "--bins" not in prefix[0] or "--test-threads=4" not in prefix[0] or "--skip" not in prefix[0]:
    raise SystemExit("original preceding commands changed; refusing an inferred workload")
(out / "prefix.json").write_text(json.dumps(prefix, indent=2) + "\n")
run_step("ordinary-libs-bins", prefix[0], 2400)
run_step("preceding-isolated-contract", prefix[1], 600)
# Preserve libtest's original captured-output mode, as well as its 300s guard.
run_step("target", prefix[2], 600, minimum_remaining=610)
print("Original shard prefix and target passed once. This is not a root-cause or fix claim.", flush=True)
