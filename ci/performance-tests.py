#!/usr/bin/env python3
"""Run one explicit CNF latency qualification, once, in its CI build profile.

The ignored tests share their entire durable scenario with required functional
tests. Only their observer deadlines differ. A failed measurement remains a
failure; no retry, percentile, or continue-on-error converts it into a pass.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
PROTECTED = (
    "stateless_quorum_consumer::"
    "protected_consumer_chain_after_activation_meets_100ms_request_deadline"
)
SELECTOR = (
    "ebpf::tests::remote_selector_regression::"
    "singleton_public_protected_flow_keeps_original_request_deadline"
)
PROFILES = (
    "core-protected", "core-selector", "native-protected",
    "i686-protected", "unsupported-selector",
)


def selection(profile: str) -> tuple[list[str], dict[str, str], str]:
    """Match the packages, features, cfg, and optimization of functional CI."""
    environment = {"CARGO_INCREMENTAL": "0"}
    if profile.startswith("core-"):
        packages = ["--workspace", "--exclude", "opc-persist", "--all-features"]
    elif profile == "unsupported-selector":
        packages = ["-p", "opc-linux-gtpu-sys", "-p", "opc-gtpu-dataplane",
                    "--no-default-features"]
        environment["RUSTFLAGS"] = "--cfg opc_linux_gtpu_sys_force_unsupported"
    else:
        packages = ["-p", "opc-session-net", "--all-features"]
    if profile.startswith("core-") or profile == "unsupported-selector":
        environment.update(CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0")
    if profile == "i686-protected":
        packages += ["--target", "i686-unknown-linux-gnu"]
        environment.update(RUSTFLAGS="-C link-arg=-m32", TARGET_CFLAGS="-m32")
    if profile.endswith("protected"):
        environment["CARGO_PROFILE_TEST_OPT_LEVEL"] = "1"
        name = PROTECTED
    else:
        name = SELECTOR
    return ["cargo", "test", "--locked", *packages, "--quiet", "--lib"], environment, name


def require_exact_inventory(output: str, name: str) -> None:
    selected = [line.removesuffix(": test") for line in output.splitlines()
                if line.endswith(": test")]
    if selected != [name]:
        raise ValueError(f"performance test must resolve exactly once: {selected!r}")


def run(profile: str, output: Path) -> int:
    output.mkdir(parents=True, exist_ok=True)
    command, overrides, name = selection(profile)
    environment = os.environ.copy()
    # Do not accidentally qualify a locally inherited optimization or cfg.
    for key in list(environment):
        if key.startswith("CARGO_PROFILE_") or key == "RUSTFLAGS":
            environment.pop(key)
    environment.update(overrides)
    record = {
        "profile": profile, "test": name, "environment": overrides,
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "dirty": bool(subprocess.check_output(["git", "diff", "HEAD"], cwd=ROOT)),
        "host": platform.platform(), "machine": platform.machine(),
        "runner": os.environ.get("RUNNER_NAME"),
        "rustc": subprocess.check_output(["rustc", "-Vv"], text=True).strip(),
        "budget_us": 100_000 if profile.endswith("protected") else 1_000_000,
        "commands": [], "exit_code": 1,
    }
    code = 1
    try:
        # --ignored matters: a rename or lost ignore attribute cannot silently
        # turn this performance qualification into a zero-test success.
        inventory_command = command + ["--", "--ignored", "--list", "--exact", name]
        record["commands"].append(inventory_command)
        inventory = subprocess.run(inventory_command, cwd=ROOT, env=environment,
                                   text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (output / "inventory.log").write_text(inventory.stdout)
        print(inventory.stdout, end="", flush=True)
        if inventory.returncode:
            code = inventory.returncode
            return code
        require_exact_inventory(inventory.stdout, name)
        execution = command + ["--", "--ignored", "--exact", name,
                               "--test-threads=1", "--nocapture"]
        record["commands"].append(execution)
        with (output / "test.log").open("w") as log:
            with subprocess.Popen(execution, cwd=ROOT, env=environment, text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as child:
                assert child.stdout is not None
                for line in child.stdout:
                    log.write(line)
                    print(line, end="", flush=True)
                code = child.wait()
        return code
    finally:
        record["exit_code"] = code
        record["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (output / "result.json").write_text(json.dumps(record, indent=2) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    return run(args.profile, args.output or ROOT / "target" / "performance" / args.profile)


if __name__ == "__main__":
    sys.exit(main())
