#!/usr/bin/env python3
"""Report failed nightly qualification and enforce its classification hold."""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import subprocess
import sys

LABEL = "nightly-qualification"
PERFORMANCE_PROFILES = (
    "core-protected", "core-selector", "native-protected",
    "i686-protected", "unsupported-selector",
)


def api(path: str, payload: dict | None = None):
    command = ["gh", "api", path]
    if payload is None:
        command += ["--paginate", "--slurp"]
    else:
        command += ["--method", "POST", "--input", "-"]
    completed = subprocess.run(command, text=True, check=True, stdout=subprocess.PIPE,
                               input=json.dumps(payload) if payload is not None else None)
    value = json.loads(completed.stdout)
    return [item for page in value for item in page] if payload is None else value


def open_issues(repository: str) -> list[dict]:
    return [issue for issue in api(
        f"repos/{repository}/issues?state=open&labels={LABEL}&per_page=100"
    ) if "pull_request" not in issue]


def check(repository: str) -> int:
    issues = open_issues(repository)
    if issues:
        for issue in issues:
            print(f"merge hold: nightly qualification needs classification: {issue['html_url']}")
        return 1
    print("no open nightly-qualification classification hold")
    return 0


def report_header(kind: str, run_url: str, conclusion: str) -> list[str]:
    return [
        f"Nightly {kind} qualification is **{conclusion}**: [workflow run]({run_url}).",
        "", "**Merge hold:** classify every failure before closing this issue. "
        "Link the known flake issue, or the regression's fix/revert and its verification. "
        "A later passing repetition or nightly does not clear this hold.", "",
    ]


def report_body(result: dict | None, run_url: str, conclusion: str) -> str:
    lines = report_header("real-time", run_url, conclusion)
    if result is None:
        lines.append("No result artifact was available. Inspect the run for setup, build, "
                     "runner, or artifact failures; the missing report is not a passing qualification.")
    else:
        lines.append(f"Source: `{result['head']}`. Completed repetitions: "
                     f"{len(result['runs'])}/{result['requested_repetitions']}.")
        failures = Counter(name for run in result["runs"] for name in run["failed_tests"])
        issues = {entry["name"]: entry["issue"] for entry in result["tests"]}
        if failures:
            lines += ["", "Failing tests:", ""]
            lines += [f"- `{name}`: {count} failed repetition(s); #{issues[name]}."
                      for name, count in sorted(failures.items())]
        if result.get("error") or any(run["incomplete"] for run in result["runs"]):
            lines += ["", "Qualification was incomplete; inspect the retained inventory and test logs."]
        if not failures:
            lines += ["", "No named test failure was recorded. Inspect the failed job and artifacts; "
                      "infrastructure and reporting failures also require classification."]
    return "\n".join(lines) + "\n"


def performance_report_body(directory: Path, run_url: str, conclusion: str) -> str:
    lines = report_header("CNF performance", run_url, conclusion)
    lines += ["Profile results (original caller budgets):", ""]
    for profile in PERFORMANCE_PROFILES:
        path = directory / f"cnf-performance-{profile}" / "result.json"
        if not path.exists():
            # gh can extract a single downloaded artifact directly into --dir.
            # Its embedded profile still has to match the expected matrix row.
            path = directory / "result.json"
        try:
            result = json.loads(path.read_text())
            if (not isinstance(result, dict) or result.get("profile") != profile
                    or not isinstance(result.get("head"), str)
                    or not isinstance(result.get("test"), str)
                    or type(result.get("exit_code")) is not int
                    or result.get("budget_us") != (100_000 if profile.endswith("protected") else 1_000_000)):
                raise ValueError("incomplete or mismatched performance result")
        except (OSError, ValueError, TypeError):
            lines.append(f"- `{profile}`: no usable result artifact; inspect setup, build, runner and artifact logs.")
            continue
        outcome = "passed" if result["exit_code"] == 0 else f"failed (exit {result['exit_code']})"
        lines.append(f"- `{profile}`: **{outcome}**; `{result['test']}`; "
                     f"budget {result['budget_us']} us; source `{result['head']}`.")
    lines += ["", "A passing profile does not clear this failed nightly. "
              "Classify failed measurements and any setup, runner, or reporting failure in the linked run."]
    return "\n".join(lines) + "\n"


def report(repository: str, result_path: Path, conclusion: str, kind: str = "real-time") -> int:
    # PR code, including code from forks, never receives the issue-write path.
    if os.environ.get("GITHUB_EVENT_NAME") != "schedule" or os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise ValueError("nightly issue reporting is restricted to scheduled main runs")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not run_id.isdigit() or conclusion == "success":
        raise ValueError("report requires a failed nightly run and its run ID")
    run_url = f"https://github.com/{repository}/actions/runs/{run_id}"
    if kind == "performance":
        body = performance_report_body(result_path, run_url, conclusion)
        title = "Nightly CNF performance qualification needs classification"
    elif kind == "real-time":
        try:
            result = json.loads(result_path.read_text())
            body = report_body(result, run_url, conclusion)
        except (OSError, ValueError, KeyError, TypeError):
            body = report_body(None, run_url, conclusion)
        title = "Nightly real-time qualification needs classification"
    else:
        raise ValueError("unknown qualification kind")
    # The workflow token needs issues:write only in this scheduled-main job.
    subprocess.run([
        "gh", "label", "create", LABEL, "--repo", repository, "--force",
        "--color", "B60205", "--description", "Merges paused until nightly failures are classified",
    ], check=True)
    issues = open_issues(repository)
    if issues:
        issue = min(issues, key=lambda item: item["number"])
        api(f"repos/{repository}/issues/{issue['number']}/comments", {"body": body})
        print(f"updated nightly merge hold: {issue['html_url']}")
    else:
        issue = api(f"repos/{repository}/issues", {
            "title": title,
            "body": body, "labels": [LABEL],
        })
        print(f"created nightly merge hold: {issue['html_url']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["check", "report"])
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--result", type=Path, default=Path("qualification-results/result.json"))
    parser.add_argument("--conclusion", default="failure")
    parser.add_argument("--kind", choices=["real-time", "performance"], default="real-time")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
        parser.error("repository must be owner/name")
    if args.command == "check":
        return check(args.repository)
    return report(args.repository, args.result, args.conclusion, args.kind)


if __name__ == "__main__":
    sys.exit(main())
