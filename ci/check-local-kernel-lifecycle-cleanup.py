#!/usr/bin/env python3
"""Require native lifecycle cases to leave the dedicated CI runner unchanged.

Cases own private network/mount namespaces and bpffs mounts. Comparing the
runner before namespace probes and after qualification catches surviving namespaces
as well as accidental host-visible state, without enumerating BPF object IDs.
"""

import argparse
import json
from pathlib import Path
import subprocess
import sys


def lines(command: list[str]) -> list[str]:
    return sorted(set(subprocess.check_output(command, text=True).splitlines()))


def snapshot() -> dict[str, list[str]]:
    namespaces = {}
    for kind in ["net", "mnt"]:
        values = lines(["lsns", "--type", kind, "--noheadings", "--output", "NS"])
        values = sorted(value.strip() for value in values)
        if not values or not all(value.isdecimal() for value in values):
            raise ValueError(f"incomplete {kind} namespace inventory")
        namespaces[kind] = values
    return {
        **namespaces,
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["snapshot", "verify"])
    parser.add_argument("evidence_dir", type=Path)
    args = parser.parse_args()
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    baseline = args.evidence_dir / "before.json"
    try:
        current = snapshot()
        if args.mode == "snapshot":
            # Never replace the baseline after preflight or a failed test.
            with baseline.open("x") as output:
                json.dump(current, output, indent=2)
            return 0
        (args.evidence_dir / "after.json").write_text(json.dumps(current, indent=2) + "\n")
        changed = differences(json.loads(baseline.read_text()), current)
        result = {"passed": not changed, "differences": changed}
        (args.evidence_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        if changed:
            raise ValueError("native lifecycle left runner state changed; inspect cleanup evidence")
        print("local kernel lifecycle cleanup: PASS")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
