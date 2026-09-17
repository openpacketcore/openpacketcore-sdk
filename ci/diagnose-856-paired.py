#!/usr/bin/env python3
"""Temporary same-host #856 runtime comparison; not a merge candidate or fix."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time


ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("external856", ROOT / "diagnose-856-external.py")
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)
EXPECTED = {
    "runtime-1": ("64c2ccda4ee5714025f25a458019272349d5e3d1", "6fdb93bc1437986bda023d5aa97457d14749acca"),
    "current-main": ("75044f43852cd816d9734d03914515395bf20c69", "f7f9c93c476e18d69093f8fa49b0865f4932dde5"),
}
# Equal sample counts with both orders represented, specified before any result.
PLAN = ["current-main", "runtime-1", "runtime-1", "current-main"]
PASS = r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 602 filtered out; finished in ([0-9.]+)s"


def verify_source(profile, source):
    actual = (harness.git(source, "rev-parse", "HEAD"),
              harness.git(source, "rev-parse", "HEAD^{tree}"))
    if actual != EXPECTED[profile] or harness.git(source, "status", "--porcelain"):
        raise SystemExit(f"{profile}: fixed source identity or cleanliness changed")
    return {"head": actual[0], "tree": actual[1], "clean": True}


def run_plan(sources, output):
    output.mkdir(exist_ok=False)
    deadline = time.monotonic() + 3300
    metadata = {
        "sources": {profile: verify_source(profile, source) for profile, source in sources.items()},
        "plan": PLAN,
        "command": harness.COMMAND,
        "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "logical_cpus": os.cpu_count(),
        "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
        "workload_guard_seconds": 300,
        "outer_sample_guard_seconds": 600,
        "experiment_budget_seconds": 3300,
        "sample_admission_reserve_seconds": 670,
        "same_host": True,
        "same_storage_setup": True,
        "separate_build_directories": True,
        "build_both_before_sampling": True,
        "runtime_attribute_only_variant": True,
        "all_other_source_bytes_identical": True,
        "observer": "external_proc_counters_and_outlier_only_stack",
        "outlier_probe_after_target_seen_seconds": 240,
        "harness_head": harness.git(ROOT.parent, "rev-parse", "HEAD"),
        "harness_hashes": {
            name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in ["diagnose-856-external.py", "diagnose-856-paired.py"]
        },
    }
    harness.write_json(output / "metadata.json", metadata)
    results = []

    def execute(profile, label, selection=False):
        source = sources[profile]
        verify_source(profile, source)
        # Separate targets preserve both compiled source trees. Target output is
        # outside either clean source checkout, with all profile flags unchanged.
        os.environ["CARGO_TARGET_DIR"] = str(output.parent / f"target-paired-{profile}")
        command = harness.COMMAND + (["--list"] if selection else [])
        result = harness.run_sample(command, source, output / f"{label}.log",
                                    1200 if selection else 600, observe=not selection)
        result.update({"profile": profile, "sample": label,
                       "source_after": verify_source(profile, source)})
        log = (output / f"{label}.log").read_text(errors="replace")
        if selection:
            result["selected_target_count"] = log.splitlines().count(harness.TARGET + ": test")
        else:
            result["successful_target_results"] = re.findall(PASS, log)
        results.append(result)
        harness.write_json(output / "results.json", results)
        print(json.dumps(result), flush=True)
        if result["exit_code"]:
            raise SystemExit(result["exit_code"])
        if selection:
            if result["selected_target_count"] != 1:
                raise SystemExit("exact target does not resolve once")
        elif not result["target_seen"] or len(result["successful_target_results"]) != 1:
            raise SystemExit("one observed successful target result was not proven")

    for profile in sources:
        if deadline - time.monotonic() < 1250:
            harness.write_json(output / "incomplete.json", {"reason": "build_budget", "next_profile": profile})
            raise SystemExit("Incomplete comparison; insufficient build/cleanup budget")
        execute(profile, f"selection-{profile}", selection=True)
    for index, profile in enumerate(PLAN, start=1):
        if deadline - time.monotonic() < 670:
            harness.write_json(output / "incomplete.json", {"reason": "sample_budget", "next_sample": index})
            raise SystemExit("Incomplete comparison; insufficient sample/cleanup budget")
        execute(profile, f"sample-{index:02d}-{profile}")
    harness.write_json(output / "complete.json", {"completed_samples": len(PLAN), "target_failures": 0})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sources = {"current-main": args.current.resolve(strict=True),
               "runtime-1": args.variant.resolve(strict=True)}
    if sources["runtime-1"] == sources["current-main"]:
        parser.error("two distinct source checkouts are required")
    changed = harness.git(sources["current-main"], "diff", "--name-only",
                          EXPECTED["current-main"][0], EXPECTED["runtime-1"][0]).splitlines()
    target_file = "crates/opc-session-net/tests/stateless_quorum_consumer.rs"
    if changed != [target_file]:
        parser.error("runtime variant changes additional source files")
    baseline = (sources["current-main"] / target_file).read_bytes()
    before = b'#[tokio::test]\nasync fn persistent_three_voter_fenced_status_converges_after_response_loss_and_compaction()'
    after = b'#[tokio::test(flavor = "multi_thread", worker_threads = 1)]\nasync fn persistent_three_voter_fenced_status_converges_after_response_loss_and_compaction()'
    if baseline.count(before) != 1 or baseline.replace(before, after) != (sources["runtime-1"] / target_file).read_bytes():
        parser.error("runtime variant is not the exact expected attribute-only change")
    run_plan(sources, args.output.resolve())


if __name__ == "__main__":
    main()
