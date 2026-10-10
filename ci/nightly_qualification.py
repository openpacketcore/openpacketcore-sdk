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


def report_body(result: dict | None, run_url: str, conclusion: str) -> str:
    lines = [
        f"Nightly real-time qualification is **{conclusion}**: [workflow run]({run_url}).",
        "", "**Merge hold:** classify every failure before closing this issue. "
        "Link the known flake issue, or the regression's fix/revert and its verification. "
        "A later passing repetition or nightly does not clear this hold.", "",
    ]
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


def report(repository: str, result_path: Path, conclusion: str) -> int:
    # PR code, including code from forks, never receives the issue-write path.
    if os.environ.get("GITHUB_EVENT_NAME") != "schedule" or os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise ValueError("nightly issue reporting is restricted to scheduled main runs")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not run_id.isdigit() or conclusion == "success":
        raise ValueError("report requires a failed nightly run and its run ID")
    run_url = f"https://github.com/{repository}/actions/runs/{run_id}"
    try:
        result = json.loads(result_path.read_text())
        body = report_body(result, run_url, conclusion)
    except (OSError, ValueError, KeyError, TypeError):
        body = report_body(None, run_url, conclusion)
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
            "title": "Nightly real-time qualification needs classification",
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
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
        parser.error("repository must be owner/name")
    if args.command == "check":
        return check(args.repository)
    return report(args.repository, args.result, args.conclusion)


if __name__ == "__main__":
    sys.exit(main())
