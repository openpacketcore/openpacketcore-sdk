#!/usr/bin/env python3
"""Run the exact real-time qualification manifest without turning failures green."""

from __future__ import annotations

import argparse
from collections import Counter
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "ci" / "realtime-qualification.json"
PACKAGE = "opc-session-testkit"
TARGET = "qualification_mtls_multiprocess"
# Match required CI's package selection and feature unification exactly.
SELECTION = [
    "cargo", "test", "--locked", "--workspace", "--exclude", "opc-persist",
    "--all-features", "--quiet", "--test", TARGET,
]


def load_manifest(path: Path = MANIFEST) -> list[dict]:
    manifest = json.loads(path.read_text())
    if (not isinstance(manifest, dict)
            or set(manifest) != {"version", "package", "target", "baseline_evidence", "tests"}
            or type(manifest["version"]) is not int or manifest["version"] != 1
            or manifest["package"] != PACKAGE or manifest["target"] != TARGET
            or not isinstance(manifest["baseline_evidence"], str)
            or not manifest["baseline_evidence"].strip()
            or not isinstance(manifest["tests"], list)):
        raise ValueError("invalid real-time qualification manifest")
    entries = manifest["tests"]
    names = []
    for entry in entries:
        if (not isinstance(entry, dict) or set(entry) != {"name", "issue", "reason"}
                or not isinstance(entry["name"], str)
                or not re.fullmatch(r"[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*", entry["name"])
                or type(entry["issue"]) is not int or entry["issue"] <= 0
                or not isinstance(entry["reason"], str) or not entry["reason"].strip()):
            raise ValueError("qualification entries require an exact name, issue and reason")
        names.append(entry["name"])
    if len(names) != len(set(names)):
        raise ValueError("duplicate real-time qualification name")
    return entries


def listed_tests(output: str) -> Counter:
    return Counter(line.removesuffix(": test") for line in output.splitlines()
                   if line.endswith(": test"))


def require_inventory(output: str, names: list[str]) -> None:
    selected = listed_tests(output)
    if selected != Counter(names):
        raise ValueError(
            "qualification names must resolve exactly once: "
            f"missing={dict(Counter(names) - selected)}, "
            f"unexpected={dict(selected - Counter(names))}"
        )


def outcome(output: str, names: list[str], returncode: int) -> dict:
    """Count actual executions; zero tests or an ignored entry cannot pass."""
    summaries = re.findall(
        r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;",
        output,
    )
    failed = sorted(name for name in names if re.search(
        rf"^(?:test {re.escape(name)} \.\.\. FAILED|    {re.escape(name)})\s*$",
        output, re.M,
    ))
    counts = tuple(map(int, summaries[0])) if len(summaries) == 1 else None
    complete = counts is not None and counts[0] + counts[1] == len(names) and counts[2] == 0
    return {
        "passed": returncode == 0 and complete and counts == (len(names), 0, 0),
        "counts": counts, "failed_tests": failed,
        "incomplete": not complete or (counts is not None and len(failed) != counts[1]),
    }


def capture(command: list[str], path: Path) -> tuple[int, str]:
    with path.open("w") as log:
        with subprocess.Popen(command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL) as child:
            assert child.stdout is not None
            for line in child.stdout:
                log.write(line)
                print(line, end="", flush=True)
            code = child.wait()
    return code, path.read_text()


def run(entries: list[dict], repetitions: int, output: Path) -> int:
    output.mkdir(parents=True, exist_ok=False)
    names = [entry["name"] for entry in entries]
    record = {
        "tests": entries, "requested_repetitions": repetitions,
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "environment": {key: os.environ.get(key) for key in (
            "CARGO_INCREMENTAL", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG",
            "TMPDIR", "OPC_FS_VERITY_SNAPSHOT_ROOT", "OPC_FS_VERITY_QUALIFICATION",
        )},
        "commands": [], "runs": [], "passed": False, "error": None,
    }

    def save() -> None:
        temporary = output / "result.json.tmp"
        temporary.write_text(json.dumps(record, indent=2) + "\n")
        temporary.replace(output / "result.json")

    def execute(arguments: list[str], label: str) -> tuple[int, str]:
        command = SELECTION + ["--", *arguments]
        record["commands"].append(command)
        save()
        code, content = capture(command, output / f"{label}.log")
        return code, content

    try:
        save()
        if not names:
            print("qualification manifest is empty; all tests remain in required CI")
            record["passed"] = True
            return 0
        code, inventory = execute(["--list", "--exact", *names], "inventory")
        if code:
            raise ValueError(f"qualification inventory command failed: {code}")
        require_inventory(inventory, names)
        code, ignored = execute(["--list", "--ignored", "--exact", *names], "ignored")
        if code or listed_tests(ignored):
            raise ValueError("qualification manifest includes ignored tests or ignored-list failed")
        # These are scheduled measurements, not retries: any red measurement
        # makes the entire run red even when subsequent repetitions pass.
        for iteration in range(1, repetitions + 1):
            code, content = execute(
                ["--test-threads=4", "--exact", *names, "--nocapture"],
                f"repetition-{iteration:03}",
            )
            result = outcome(content, names, code)
            result.update(iteration=iteration, exit_code=code,
                          log_sha256=hashlib.sha256(content.encode()).hexdigest())
            record["runs"].append(result)
            save()
            if result["incomplete"]:
                raise ValueError("qualification execution was incomplete; inspect its retained log")
        record["passed"] = all(result["passed"] for result in record["runs"])
        return 0 if record["passed"] else 1
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        record["error"] = str(error)
        print(f"qualification failed: {error}", file=sys.stderr)
        return 1
    finally:
        record["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--output", type=Path, default=ROOT / "qualification-results")
    args = parser.parse_args()
    if not 1 <= args.repetitions <= 100:
        parser.error("repetitions must be between 1 and 100")
    return run(load_manifest(), args.repetitions, args.output)


if __name__ == "__main__":
    sys.exit(main())
