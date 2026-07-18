#!/usr/bin/env python3
"""Verify the additive retained workload schedule for one v5 candidate bundle.

This verifier is separate from the frozen concurrent-history v5 checker. It
binds the publisher-generated workload schedule to the existing closed
candidate evidence without changing the historical checker name, version, or
bytes. It never upgrades candidate evidence into production qualification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

VERIFIER_NAME = "check-session-ha-kubernetes-concurrent-v5-workload-v1.py"
VERIFIER_VERSION = "1"
MAX_INPUT_BYTES = 256 * 1024
MAX_JSON_INTEGER_DIGITS = 20
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
WORKLOAD_OPERATIONS = [
    "preacquire_leases",
    "prove_empty_restore_scope",
    "register_watch",
    "execute_partial_success_batch_once",
    "observe_ready_before_fault",
    "isolate_all_consensus_rpc_pairs",
    "observe_not_ready",
    "restore_all_consensus_rpc_pairs",
    "observe_ready_after_fault",
    "finish_watch_and_restore_concurrently",
    "cleanup",
]
WORKLOAD_FIELDS = {
    "isolated_digest_namespace",
    "initial_state_empty",
    "initial_journal_head",
    "complete_write_history",
    "serialized_batch_invocations",
    "exclusive_application_journal_window",
    "records_non_expiring_through_campaign",
    "state_class",
    "state_type_sha256",
    "no_lease_mutations_in_history_window",
    "preacquired_leases",
}


class InputError(Exception):
    """An input violates the closed, bounded verifier contract."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise InputError("duplicate JSON object field")
        value[key] = item
    return value


def parse_bounded_int(raw: str) -> int:
    digits = raw[1:] if raw.startswith("-") else raw
    if not digits or len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise InputError("JSON integer token is outside checker bounds")
    return int(raw)


def reject_json_number(_: str) -> None:
    raise InputError("non-integer JSON number")


def reject_json_constant(_: str) -> None:
    raise InputError("non-standard JSON constant")


def parse_json(raw: bytes) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicate_keys,
            parse_int=parse_bounded_int,
            parse_float=reject_json_number,
            parse_constant=reject_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        InputError,
        ValueError,
        RecursionError,
    ) as error:
        raise InputError("invalid JSON") from error


def read_bounded(path: Path) -> bytes:
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_INPUT_BYTES + 1)
    except OSError as error:
        raise InputError("input unavailable") from error
    if not raw or len(raw) > MAX_INPUT_BYTES:
        raise InputError("input size is outside checker bounds")
    return raw


def exact_fields(value: dict[str, Any], expected: set[str]) -> None:
    if set(value) != expected:
        raise InputError("object fields do not match the closed schema")


def exact_sha256(value: Any) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise InputError("digest is not an exact lowercase SHA-256")
    return value


def sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def exact_json_equal(left: Any, right: Any) -> bool:
    """Compare parsed JSON without Python's bool/int equality coercion."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(
            exact_json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            exact_json_equal(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    return left == right


def validate(evidence_raw: bytes, schedule_raw: bytes) -> None:
    evidence = parse_json(evidence_raw)
    schedule = parse_json(schedule_raw)
    if not isinstance(evidence, dict) or not isinstance(schedule, dict):
        raise InputError("input is not an object")
    if (
        evidence.get("schema_version") != "opc-session-ha-candidate-evidence/v5"
        or evidence.get("profile_id") != "opc-session-openraft-ha/v5-candidate"
        or evidence.get("experimental") is not True
        or evidence.get("qualification_complete") is not False
        or evidence.get("counts_for_production") is not False
    ):
        raise InputError("evidence makes an unsupported maturity claim")
    artifact = evidence.get("artifact")
    workload = evidence.get("workload")
    if (
        not isinstance(artifact, dict)
        or artifact.get("exact_release_artifact") is not False
        or not isinstance(workload, dict)
    ):
        raise InputError("candidate binding is not honest")
    exact_fields(workload, WORKLOAD_FIELDS | {"schedule_sha256"})
    if exact_sha256(workload["schedule_sha256"]) != sha256(schedule_raw):
        raise InputError("workload schedule digest does not match evidence")
    exact_fields(schedule, WORKLOAD_FIELDS | {"schema_version", "operations"})
    if (
        schedule["schema_version"]
        != "opc-session-kubernetes-concurrent-v5-workload/v1"
        or schedule["operations"] != WORKLOAD_OPERATIONS
    ):
        raise InputError("workload schedule identity is not exact")
    for field in WORKLOAD_FIELDS:
        if not exact_json_equal(schedule[field], workload[field]):
            raise InputError("workload schedule contradicts evidence")


def emit(status: str, exit_code: int) -> int:
    payload = {
        "verifier": VERIFIER_NAME,
        "verifier_version": VERIFIER_VERSION,
        "status": status,
        "violation_codes": [],
    }
    sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    return exit_code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify one retained Kubernetes concurrent-v5 workload schedule"
    )
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--workload-schedule", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    os.umask(0o077)
    args = parse_args()
    try:
        validate(read_bounded(args.evidence), read_bounded(args.workload_schedule))
    except (InputError, ValueError, RecursionError):
        return emit("invalid_input", 3)
    return emit("pass", 0)


if __name__ == "__main__":
    raise SystemExit(main())
