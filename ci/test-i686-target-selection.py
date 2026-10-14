#!/usr/bin/env python3
"""Exercise the workflow's real i686 selectors with future Cargo targets."""

from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/ci.yml"


def workflow_commands(directory: Path, slice_name: str) -> list[list[str]]:
    """Capture shell-expanded argv from the required workflow step."""
    matches = re.findall(
        r"^      - name: Run opc-session-net tests on i686\n"
        r"(?:(?:        #[^\n]*|)\n)*        run: \|\n"
        r"((?:(?:          [^\n]*|)\n)+)",
        WORKFLOW.read_text(),
        re.MULTILINE,
    )
    if len(matches) != 1:
        raise AssertionError("expected exactly one i686 session-net run step")
    script = "\n".join(line[10:] for line in matches[0].splitlines())
    capture = directory / "capture"
    capture.mkdir(exist_ok=True)
    cargo = capture / "cargo"
    cargo.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "with open(os.environ['I686_CAPTURE'], 'a') as output:\n"
        "    output.write(json.dumps(['cargo', *sys.argv[1:]]) + '\\n')\n"
    )
    cargo.chmod(0o755)
    output = directory / f"{slice_name}.jsonl"
    subprocess.run(
        ["bash", "-euc", script],
        cwd=ROOT,
        env={
            **os.environ,
            "PATH": str(capture) + os.pathsep + os.environ["PATH"],
            "I686_SLICE": slice_name,
            "I686_CAPTURE": str(output),
        },
        check=True,
    )
    return [json.loads(line) for line in output.read_text().splitlines()]


class I686TargetSelectionTests(unittest.TestCase):
    def test_future_binary_and_integration_tests_run_exactly_once(self) -> None:
        # This dependency-free fixture reproduces the reviewer's missing
        # auto-discovered executable unit test using real i686 Cargo selection.
        sources = {
            "Cargo.toml": '''[package]
name = "opc-session-net"
version = "0.0.0"
edition = "2021"
autotests = false
[workspace]
[[test]]
name = "existing_integration"
path = "tests/existing_integration.rs"
[[test]]
name = "future_integration"
path = "tests/future_integration.rs"
''',
            "src/lib.rs": '''/// ```
/// assert_eq!(opc_session_net::value(), 7);
/// ```
pub fn value() -> u8 { 7 }
#[test] fn library_probe() { assert_eq!(value(), 7); }
''',
            "tests/existing_integration.rs":
                "#[test] fn existing_integration_probe() {}\n",
            "tests/future_integration.rs":
                "#[test] fn future_integration_probe() {}\n",
            "src/bin/future_binary.rs":
                "fn main() {}\n#[test] fn future_binary_unit_probe() {}\n",
        }
        with tempfile.TemporaryDirectory(prefix="i686-selection-") as temporary:
            root = Path(temporary)
            for name, content in sources.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            # A stable worktree-local cache is separate from fixture scratch.
            env = {
                **os.environ,
                "CARGO_TARGET_DIR": str(ROOT / "target/i686-selector-probe"),
            }
            subprocess.run(
                ["cargo", "generate-lockfile", "--offline"],
                cwd=root, env=env, check=True,
            )
            ordinary = workflow_commands(root, "ordinary")
            integration = workflow_commands(root, "ordinary-integration")
            self.assertEqual(len(ordinary), 1)
            # Reconstruct the original unfiltered command, retaining every
            # feature, platform, harness flag and exact timing exclusion.
            baseline = ordinary[0].copy()
            baseline.remove("--lib")

            def listed(command: list[str]) -> Counter:
                result = subprocess.run(
                    [*command, "--list"],
                    cwd=root, env=env, text=True, capture_output=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                names = re.findall(r"^(.+): test$", result.stdout, re.MULTILINE)
                print(json.dumps({"argv": command, "listed_tests": names}), flush=True)
                return Counter(names)

            before = listed(baseline)
            after = sum((listed(command) for command in ordinary + integration), Counter())
            self.assertEqual(before["future_binary_unit_probe"], 1)
            self.assertEqual(before["future_integration_probe"], 1)
            self.assertEqual(before["existing_integration_probe"], 1)
            self.assertEqual(before["library_probe"], 1)
            self.assertEqual(sum(before.values()), 5, "include the library doctest")
            self.assertEqual(after, before, "ordinary shards must be total and disjoint")


if __name__ == "__main__":
    unittest.main()
