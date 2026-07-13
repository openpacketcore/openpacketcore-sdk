#!/usr/bin/env python3
"""Independently check one bounded, sequential session-HA history.

The checker intentionally uses only Python's standard library and does not
import SDK code. It binds every completed history row to an immutable workload
schedule before evaluating the lease, fencing, CAS, and read state machine.
Unknown outcomes and missing invocations are never discarded: they make the
result inconclusive.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CHECKER_VERSION = "1"
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_OPERATIONS = 10_000
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class InputError(Exception):
    """A bounded input violates the checker contract."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise InputError("duplicate JSON object field")
        value[key] = item
    return value


def load_jsonl(
    path: Path, *, allow_empty: bool = False
) -> tuple[bytes, list[dict[str, Any]]]:
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_INPUT_BYTES + 1)
    except OSError as error:
        raise InputError("input unavailable") from error
    if not raw and allow_empty:
        return raw, []
    if not raw or len(raw) > MAX_INPUT_BYTES or not raw.endswith(b"\n"):
        raise InputError("input size or canonical newline is invalid")
    try:
        lines = raw.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise InputError("input is not UTF-8") from error
    if not (1 <= len(lines) <= MAX_OPERATIONS):
        raise InputError("operation count is outside checker bounds")
    rows: list[dict[str, Any]] = []
    for line in lines:
        if not line or len(line.encode("utf-8")) > MAX_LINE_BYTES:
            raise InputError("JSON line is outside checker bounds")
        try:
            row = json.loads(line, object_pairs_hook=reject_duplicate_keys)
        except (json.JSONDecodeError, InputError) as error:
            raise InputError("invalid JSON line") from error
        if not isinstance(row, dict):
            raise InputError("JSON line is not an object")
        rows.append(row)
    return raw, rows


def exact_fields(value: dict[str, Any], expected: set[str]) -> None:
    if set(value) != expected:
        raise InputError("object fields do not match the closed schema")


def bounded_string(value: Any, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise InputError("identifier is outside checker bounds")
    return value


def bounded_int(value: Any, minimum: int = 0, maximum: int = (1 << 64) - 1) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise InputError("integer is outside checker bounds")
    return value


def optional_generation(value: Any) -> int | None:
    if value is None:
        return None
    return bounded_int(value)


def exact_sha256(value: Any) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise InputError("digest is not an exact lowercase SHA-256")
    return value


def digest(kind: str, value: str) -> str:
    encoded = f"opc-session-ha/{kind}/v1\0{value}".encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def validate_schedule(rows: list[dict[str, Any]]) -> tuple[str, int]:
    first = rows[0]
    schedule_id = bounded_string(first.get("schedule_id"), 128)
    count = bounded_int(first.get("schedule_operation_count"), 1, MAX_OPERATIONS)
    if count != len(rows):
        raise InputError("schedule omits an invocation")
    operation_ids: set[str] = set()
    for offset, row in enumerate(rows, start=1):
        exact_fields(
            row,
            {
                "schema_version",
                "schedule_id",
                "operation_index",
                "schedule_operation_count",
                "operation_id",
                "process_id",
                "operation",
            },
        )
        if (
            row["schema_version"] != "opc-session-ha-schedule/v1"
            or row["schedule_id"] != schedule_id
            or row["schedule_operation_count"] != count
            or row["operation_index"] != offset
        ):
            raise InputError("schedule envelope is inconsistent")
        operation_id = bounded_string(row["operation_id"], 128)
        bounded_string(row["process_id"], 128)
        if operation_id in operation_ids:
            raise InputError("schedule operation ID is duplicated")
        operation_ids.add(operation_id)
        validate_scheduled_operation(row["operation"])
    return schedule_id, count


def validate_scheduled_operation(operation: Any) -> None:
    if not isinstance(operation, dict):
        raise InputError("scheduled operation is not an object")
    kind = operation.get("kind")
    if kind == "lease_acquire":
        exact_fields(operation, {"kind", "key", "owner", "ttl_millis"})
        bounded_string(operation["key"], 64)
        bounded_string(operation["owner"], 128)
        bounded_int(operation["ttl_millis"], 1, 31_536_000_000)
    elif kind == "compare_and_set":
        exact_fields(
            operation,
            {
                "kind",
                "key",
                "lease_operation_id",
                "expected_generation",
                "new_generation",
                "value",
            },
        )
        bounded_string(operation["key"], 64)
        bounded_string(operation["lease_operation_id"], 128)
        optional_generation(operation["expected_generation"])
        bounded_int(operation["new_generation"], 1)
        if (
            not isinstance(operation["value"], str)
            or len(operation["value"].encode("utf-8")) > 512
        ):
            raise InputError("scheduled value is outside checker bounds")
    elif kind == "read":
        exact_fields(operation, {"kind", "key"})
        bounded_string(operation["key"], 64)
    elif kind == "lease_release":
        exact_fields(operation, {"kind", "key", "lease_operation_id"})
        bounded_string(operation["key"], 64)
        bounded_string(operation["lease_operation_id"], 128)
    else:
        raise InputError("scheduled operation kind is unsupported")


def validate_history(
    rows: list[dict[str, Any]],
    schedule_id: str,
    schedule_count: int,
    schedule_sha256: str,
) -> dict[str, dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    previous_index = 0
    previous_completed = 0
    for row in rows:
        exact_fields(
            row,
            {
                "schema_version",
                "schedule_sha256",
                "history_id",
                "operation_index",
                "history_operation_count",
                "operation_id",
                "process_id",
                "started_ns",
                "completed_ns",
                "operation",
            },
        )
        index = bounded_int(row["operation_index"], 1, schedule_count)
        started = bounded_int(row["started_ns"])
        completed = bounded_int(row["completed_ns"])
        operation_id = bounded_string(row["operation_id"], 128)
        bounded_string(row["process_id"], 128)
        if (
            row["schema_version"] != "opc-session-ha-history/v1"
            or row["schedule_sha256"] != schedule_sha256
            or row["history_id"] != schedule_id
            or row["history_operation_count"] != schedule_count
            or index <= previous_index
            or started > completed
            or started < previous_completed
            or operation_id in by_id
        ):
            raise InputError("history envelope is inconsistent")
        previous_index = index
        previous_completed = completed
        validate_history_operation(row["operation"])
        by_id[operation_id] = row
    return by_id


def validate_history_operation(operation: Any) -> None:
    if not isinstance(operation, dict):
        raise InputError("history operation is not an object")
    kind = operation.get("kind")
    if kind == "lease_acquire":
        exact_fields(
            operation, {"kind", "key_sha256", "owner_sha256", "outcome", "fence"}
        )
        exact_sha256(operation["key_sha256"])
        exact_sha256(operation["owner_sha256"])
        if operation["outcome"] not in {
            "success",
            "rejected",
            "indeterminate",
            "unavailable",
        }:
            raise InputError("lease outcome is unsupported")
        if operation["outcome"] == "success":
            bounded_int(operation["fence"], 1)
        elif operation["fence"] is not None:
            raise InputError("non-successful lease acquisition carries a fence")
    elif kind == "compare_and_set":
        exact_fields(
            operation,
            {
                "kind",
                "key_sha256",
                "owner_sha256",
                "fence",
                "expected_generation",
                "new_generation",
                "value_sha256",
                "outcome",
            },
        )
        for name in ("key_sha256", "owner_sha256", "value_sha256"):
            exact_sha256(operation[name])
        bounded_int(operation["fence"], 1)
        optional_generation(operation["expected_generation"])
        bounded_int(operation["new_generation"], 1)
        if operation["outcome"] not in {
            "success",
            "conflict",
            "rejected",
            "indeterminate",
            "unavailable",
        }:
            raise InputError("CAS outcome is unsupported")
    elif kind == "read":
        exact_fields(operation, {"kind", "key_sha256", "outcome", "record"})
        exact_sha256(operation["key_sha256"])
        if operation["outcome"] not in {"success", "indeterminate", "unavailable"}:
            raise InputError("read outcome is unsupported")
        record = operation["record"]
        if operation["outcome"] != "success" and record is not None:
            raise InputError("unknown read outcome carries a record")
        if record is not None:
            if not isinstance(record, dict):
                raise InputError("read record is not an object")
            exact_fields(
                record, {"generation", "owner_sha256", "fence", "value_sha256"}
            )
            bounded_int(record["generation"], 1)
            exact_sha256(record["owner_sha256"])
            bounded_int(record["fence"], 1)
            exact_sha256(record["value_sha256"])
    elif kind == "lease_release":
        exact_fields(
            operation, {"kind", "key_sha256", "owner_sha256", "fence", "outcome"}
        )
        exact_sha256(operation["key_sha256"])
        exact_sha256(operation["owner_sha256"])
        bounded_int(operation["fence"], 1)
        if operation["outcome"] not in {
            "success",
            "rejected",
            "indeterminate",
            "unavailable",
        }:
            raise InputError("release outcome is unsupported")
    else:
        raise InputError("history operation kind is unsupported")


@dataclass
class KeyState:
    active_lease: tuple[str, int, int, int] | None = None
    record: dict[str, Any] | None = None
    maximum_fence: int = 0


@dataclass
class CheckResult:
    violations: set[str] = field(default_factory=set)
    inconclusive: set[str] = field(default_factory=set)
    checked: int = 0


def same_record(left: dict[str, Any] | None, right: dict[str, Any] | None) -> bool:
    return left == right


def evaluate(
    schedule: list[dict[str, Any]], history_by_id: dict[str, dict[str, Any]]
) -> CheckResult:
    result = CheckResult()
    states: dict[str, KeyState] = {}
    leases: dict[str, tuple[str, str, int, int, int]] = {}
    uncertain_keys: set[str] = set()
    scheduled_ids = {row["operation_id"] for row in schedule}
    if set(history_by_id) - scheduled_ids:
        result.violations.add("unexpected_history_operation")

    for scheduled in schedule:
        operation_id = scheduled["operation_id"]
        key = scheduled["operation"]["key"]
        history = history_by_id.get(operation_id)
        if history is None:
            result.inconclusive.add("missing_history_operation")
            uncertain_keys.add(key)
            continue
        if (
            history["operation_index"] != scheduled["operation_index"]
            or history["process_id"] != scheduled["process_id"]
            or history["operation"]["kind"] != scheduled["operation"]["kind"]
        ):
            result.violations.add("schedule_history_mismatch")
            continue
        invocation = scheduled["operation"]
        observed = history["operation"]
        if key in uncertain_keys:
            result.inconclusive.add("dependent_on_unknown_outcome")
            continue
        state = states.setdefault(key, KeyState())
        if observed["key_sha256"] != digest("key", key):
            result.violations.add("schedule_history_mismatch")
            continue
        outcome = observed["outcome"]
        if outcome in {"indeterminate", "unavailable"}:
            result.inconclusive.add("unknown_operation_outcome")
            uncertain_keys.add(key)
            continue

        if invocation["kind"] == "lease_acquire":
            if observed["owner_sha256"] != digest("owner", invocation["owner"]):
                result.violations.add("schedule_history_mismatch")
                continue
            expected = "success" if state.active_lease is None else "rejected"
            if outcome != expected:
                result.violations.add("lease_state_violation")
                continue
            if outcome == "success":
                fence = observed["fence"]
                if fence <= state.maximum_fence:
                    result.violations.add("fence_monotonicity_violation")
                    continue
                state.maximum_fence = fence
                state.active_lease = (
                    invocation["owner"],
                    fence,
                    history["completed_ns"],
                    invocation["ttl_millis"],
                )
                leases[operation_id] = (
                    key,
                    invocation["owner"],
                    fence,
                    history["completed_ns"],
                    invocation["ttl_millis"],
                )
        elif invocation["kind"] == "compare_and_set":
            source = leases.get(invocation["lease_operation_id"])
            if source is None or source[0] != key:
                result.violations.add("lease_reference_violation")
                continue
            _, owner, fence, acquired_ns, ttl_millis = source
            if history["started_ns"] - acquired_ns >= ttl_millis * 1_000_000:
                result.inconclusive.add("lease_expiry_ambiguity")
                continue
            if (
                observed["owner_sha256"] != digest("owner", owner)
                or observed["fence"] != fence
                or observed["expected_generation"] != invocation["expected_generation"]
                or observed["new_generation"] != invocation["new_generation"]
                or observed["value_sha256"] != digest("value", invocation["value"])
            ):
                result.violations.add("schedule_history_mismatch")
                continue
            active = state.active_lease
            authorized = (
                active is not None and active[0] == owner and active[1] == fence
            )
            current_generation = (
                None if state.record is None else state.record["generation"]
            )
            if not authorized:
                expected = "rejected"
            elif current_generation != invocation["expected_generation"]:
                expected = "conflict"
            else:
                expected = "success"
            if outcome != expected:
                result.violations.add("cas_state_violation")
                continue
            if outcome == "success":
                state.record = {
                    "generation": invocation["new_generation"],
                    "owner_sha256": digest("owner", owner),
                    "fence": fence,
                    "value_sha256": digest("value", invocation["value"]),
                }
        elif invocation["kind"] == "read":
            if outcome != "success" or not same_record(
                observed["record"], state.record
            ):
                result.violations.add("linearizable_read_violation")
                continue
        elif invocation["kind"] == "lease_release":
            source = leases.get(invocation["lease_operation_id"])
            if source is None or source[0] != key:
                result.violations.add("lease_reference_violation")
                continue
            _, owner, fence, acquired_ns, ttl_millis = source
            if history["started_ns"] - acquired_ns >= ttl_millis * 1_000_000:
                result.inconclusive.add("lease_expiry_ambiguity")
                continue
            if (
                observed["owner_sha256"] != digest("owner", owner)
                or observed["fence"] != fence
            ):
                result.violations.add("schedule_history_mismatch")
                continue
            active = state.active_lease
            expected = (
                "success"
                if active is not None and active[0] == owner and active[1] == fence
                else "rejected"
            )
            if outcome != expected:
                result.violations.add("lease_state_violation")
                continue
            if outcome == "success":
                state.active_lease = None
        result.checked += 1
    return result


def emit(status: str, exit_code: int, result: CheckResult | None = None) -> int:
    payload = {
        "checker": "check-session-ha-history.py",
        "checker_version": CHECKER_VERSION,
        "status": status,
        "operations_checked": 0 if result is None else result.checked,
        "violation_codes": [] if result is None else sorted(result.violations),
        "inconclusive_codes": [] if result is None else sorted(result.inconclusive),
    }
    sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    return exit_code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check bounded session-HA schedule/history evidence"
    )
    parser.add_argument("--schedule", required=True, type=Path)
    parser.add_argument("--history", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    os.umask(0o077)
    args = parse_args()
    try:
        schedule_raw, schedule = load_jsonl(args.schedule)
        _, history = load_jsonl(args.history, allow_empty=True)
        schedule_id, schedule_count = validate_schedule(schedule)
        schedule_sha256 = "sha256:" + hashlib.sha256(schedule_raw).hexdigest()
        history_by_id = validate_history(
            history, schedule_id, schedule_count, schedule_sha256
        )
        result = evaluate(schedule, history_by_id)
    except InputError:
        return emit("invalid_input", 3)
    if result.violations:
        return emit("fail", 1, result)
    if result.inconclusive:
        return emit("inconclusive", 2, result)
    return emit("pass", 0, result)


if __name__ == "__main__":
    raise SystemExit(main())
