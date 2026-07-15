#!/usr/bin/env python3
"""Check one bounded concurrent session-HA candidate history.

This checker is deliberately independent of the Rust SDK.  It consumes a
closed evidence document and a digest-bound JSONL history, then checks atomic
batch serialization, gap-free watches, exact restore snapshots, and continuous
fail-closed readiness sampling.  It never upgrades candidate evidence into a
production qualification claim.
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

CHECKER_NAME = "check-session-ha-concurrent-history.py"
CHECKER_VERSION = "3"
MAX_EVIDENCE_BYTES = 256 * 1024
MAX_HISTORY_BYTES = 8 * 1024 * 1024
MAX_LINE_BYTES = 256 * 1024
MAX_OPERATIONS = 10_000
MAX_BATCH_OPERATIONS = 64
MAX_BATCH_MUTATIONS = 16
MAX_WATCH_EVENTS = 4_096
MAX_RESTORE_RECORDS = 4_096
MAX_JSON_INTEGER_DIGITS = 20
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
REMAINING_ACCEPTANCE = [
    "deployed_kubernetes_3_5",
    "real_network_and_storage_faults",
    "crash_point_matrix",
    "version_migration_and_rollback",
    "platform_resource_soak",
    "remote_hkms_rotation",
    "live_alert_fire_and_clear",
    "signed_release_bundle",
]


class InputError(Exception):
    """An input violates the closed, bounded checker contract."""


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


def read_bounded(path: Path, maximum: int) -> bytes:
    try:
        with path.open("rb") as source:
            raw = source.read(maximum + 1)
    except OSError as error:
        raise InputError("input unavailable") from error
    if not raw or len(raw) > maximum:
        raise InputError("input size is outside checker bounds")
    return raw


def load_history(path: Path) -> tuple[bytes, list[dict[str, Any]]]:
    raw = read_bounded(path, MAX_HISTORY_BYTES)
    if not raw.endswith(b"\n"):
        raise InputError("history lacks its canonical final newline")
    lines = raw.splitlines()
    if not 1 <= len(lines) <= MAX_OPERATIONS:
        raise InputError("history operation count is outside checker bounds")
    rows: list[dict[str, Any]] = []
    for line in lines:
        if not line or len(line) > MAX_LINE_BYTES:
            raise InputError("history line is outside checker bounds")
        row = parse_json(line)
        if not isinstance(row, dict):
            raise InputError("history line is not an object")
        rows.append(row)
    return raw, rows


def exact_fields(value: dict[str, Any], expected: set[str]) -> None:
    if set(value) != expected:
        raise InputError("object fields do not match the closed schema")


def bounded_string(value: Any, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise InputError("string is outside checker bounds")
    return value


def bounded_int(value: Any, minimum: int = 0, maximum: int = (1 << 64) - 1) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise InputError("integer is outside checker bounds")
    return value


def optional_int(value: Any, minimum: int = 0) -> int | None:
    if value is None:
        return None
    return bounded_int(value, minimum)


def exact_bool(value: Any) -> bool:
    if not isinstance(value, bool):
        raise InputError("value is not a boolean")
    return value


def exact_sha256(value: Any) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise InputError("digest is not an exact lowercase SHA-256")
    return value


def sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def bounded_list(value: Any, minimum: int, maximum: int) -> list[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise InputError("array is outside checker bounds")
    return value


@dataclass(frozen=True)
class Contract:
    history_id: str
    operation_count: int
    campaign_started_ns: int
    campaign_completed_ns: int
    process_ids: tuple[str, ...]
    max_readiness_gap_ns: int


def validate_evidence(value: Any, history_raw: bytes, checker_raw: bytes) -> Contract:
    if not isinstance(value, dict):
        raise InputError("evidence is not an object")
    exact_fields(
        value,
        {
            "schema_version",
            "profile_id",
            "experimental",
            "qualification_complete",
            "counts_for_production",
            "source_revision",
            "source_tree_status",
            "artifact",
            "execution",
            "workload",
            "history",
            "checker",
            "coverage",
            "remaining_acceptance",
        },
    )
    if (
        value["schema_version"] != "opc-session-ha-candidate-evidence/v3"
        or value["profile_id"] != "opc-session-openraft-ha/v3-candidate"
        or value["experimental"] is not True
        or value["qualification_complete"] is not False
        or value["counts_for_production"] is not False
    ):
        raise InputError("evidence makes an unsupported maturity claim")
    if not isinstance(value["source_revision"], str) or REVISION_RE.fullmatch(
        value["source_revision"]
    ) is None:
        raise InputError("source revision is not exact")
    if value["source_tree_status"] not in {"clean", "dirty_unqualified"}:
        raise InputError("source tree status is unsupported")

    artifact = value["artifact"]
    if not isinstance(artifact, dict):
        raise InputError("artifact is not an object")
    exact_fields(
        artifact,
        {"name", "version", "sha256", "exact_release_artifact"},
    )
    bounded_string(artifact["name"], 128)
    bounded_string(artifact["version"], 64)
    exact_sha256(artifact["sha256"])
    exact_bool(artifact["exact_release_artifact"])

    execution = value["execution"]
    if not isinstance(execution, dict):
        raise InputError("execution is not an object")
    exact_fields(
        execution,
        {
            "history_id",
            "campaign_started_ns",
            "campaign_completed_ns",
            "topology_members",
            "process_ids",
            "max_readiness_gap_ns",
            "fault_schedule_sha256",
        },
    )
    history_id = bounded_string(execution["history_id"], 128)
    started = bounded_int(execution["campaign_started_ns"])
    completed = bounded_int(execution["campaign_completed_ns"], started + 1)
    members = bounded_int(execution["topology_members"], 3, 5)
    if members not in {3, 5}:
        raise InputError("topology is outside the candidate contract")
    raw_process_ids = bounded_list(execution["process_ids"], members, members)
    process_ids = tuple(bounded_string(item, 128) for item in raw_process_ids)
    if len(set(process_ids)) != members:
        raise InputError("process identities are not exact and distinct")
    max_gap = bounded_int(
        execution["max_readiness_gap_ns"], 1, 60_000_000_000
    )
    exact_sha256(execution["fault_schedule_sha256"])

    workload = value["workload"]
    if not isinstance(workload, dict):
        raise InputError("workload is not an object")
    exact_fields(
        workload,
        {
            "schedule_sha256",
            "isolated_digest_namespace",
            "complete_write_history",
        },
    )
    exact_sha256(workload["schedule_sha256"])
    if (
        workload["isolated_digest_namespace"] is not True
        or workload["complete_write_history"] is not True
    ):
        raise InputError("history cannot prove namespace completeness")

    history = value["history"]
    if not isinstance(history, dict):
        raise InputError("history binding is not an object")
    exact_fields(
        history,
        {"schema_version", "sha256", "operation_count", "required_kinds"},
    )
    if history["schema_version"] != "opc-session-ha-concurrent-history/v3":
        raise InputError("history schema version is unsupported")
    if exact_sha256(history["sha256"]) != sha256(history_raw):
        raise InputError("history digest does not match evidence")
    operation_count = bounded_int(history["operation_count"], 1, MAX_OPERATIONS)
    required_kinds = bounded_list(history["required_kinds"], 4, 4)
    if required_kinds != ["batch", "watch", "restore", "readiness"]:
        raise InputError("required history kinds are not canonical")

    checker = value["checker"]
    if not isinstance(checker, dict):
        raise InputError("checker binding is not an object")
    exact_fields(checker, {"name", "version", "sha256"})
    if (
        checker["name"] != CHECKER_NAME
        or checker["version"] != CHECKER_VERSION
        or exact_sha256(checker["sha256"]) != sha256(checker_raw)
    ):
        raise InputError("checker identity does not match evidence")

    coverage = value["coverage"]
    if not isinstance(coverage, dict):
        raise InputError("coverage is not an object")
    exact_fields(
        coverage,
        {
            "atomic_batch_serialization",
            "gap_free_watch",
            "exact_restore_snapshot",
            "continuous_readiness_gating",
        },
    )
    if any(item is not True for item in coverage.values()):
        raise InputError("candidate coverage is incomplete")

    remaining = bounded_list(value["remaining_acceptance"], 8, 8)
    remaining_values = [bounded_string(item, 64) for item in remaining]
    if remaining_values != REMAINING_ACCEPTANCE:
        raise InputError("remaining acceptance is not exact and unique")

    return Contract(
        history_id=history_id,
        operation_count=operation_count,
        campaign_started_ns=started,
        campaign_completed_ns=completed,
        process_ids=process_ids,
        max_readiness_gap_ns=max_gap,
    )


def validate_mutation(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InputError("batch mutation is not an object")
    exact_fields(
        value,
        {
            "key_sha256",
            "expected_generation",
            "new_generation",
            "owner_sha256",
            "fence",
            "value_sha256",
        },
    )
    exact_sha256(value["key_sha256"])
    expected = optional_int(value["expected_generation"])
    new_generation = bounded_int(value["new_generation"], 1)
    if expected is not None and new_generation <= expected:
        raise InputError("batch generation does not advance")
    exact_sha256(value["owner_sha256"])
    bounded_int(value["fence"], 1)
    exact_sha256(value["value_sha256"])
    return value


def validate_batch(value: dict[str, Any]) -> None:
    exact_fields(value, {"kind", "outcome", "linearization_index", "mutations"})
    if value["outcome"] not in {"success", "conflict", "indeterminate", "unavailable"}:
        raise InputError("batch outcome is unsupported")
    mutations = bounded_list(value["mutations"], 1, MAX_BATCH_MUTATIONS)
    validated = [validate_mutation(item) for item in mutations]
    if len({item["key_sha256"] for item in validated}) != len(validated):
        raise InputError("batch mutation keys are duplicated")
    if value["outcome"] in {"success", "conflict"}:
        bounded_int(value["linearization_index"], 1)
    elif value["linearization_index"] is not None:
        raise InputError("unknown batch outcome claims a linearization index")


def validate_watch_event(value: Any) -> None:
    if not isinstance(value, dict):
        raise InputError("watch event is not an object")
    exact_fields(
        value,
        {
            "commit_index",
            "batch_operation_id",
            "mutation_offset",
            "key_sha256",
            "generation",
            "owner_sha256",
            "fence",
            "value_sha256",
        },
    )
    bounded_int(value["commit_index"], 1)
    bounded_string(value["batch_operation_id"], 128)
    bounded_int(value["mutation_offset"], 1, MAX_BATCH_MUTATIONS)
    exact_sha256(value["key_sha256"])
    bounded_int(value["generation"], 1)
    exact_sha256(value["owner_sha256"])
    bounded_int(value["fence"], 1)
    exact_sha256(value["value_sha256"])


def validate_watch(value: dict[str, Any]) -> None:
    exact_fields(
        value,
        {
            "kind",
            "outcome",
            "subscription_id",
            "requested_after_index",
            "complete_through_index",
            "events",
        },
    )
    bounded_string(value["subscription_id"], 128)
    if value["outcome"] not in {"success", "indeterminate", "unavailable"}:
        raise InputError("watch outcome is unsupported")
    requested = bounded_int(value["requested_after_index"])
    events = bounded_list(value["events"], 0, MAX_WATCH_EVENTS)
    for event in events:
        validate_watch_event(event)
    if value["outcome"] == "success":
        bounded_int(value["complete_through_index"], requested)
    elif value["complete_through_index"] is not None or events:
        raise InputError("unknown watch outcome carries completed events")


def validate_restore_record(value: Any) -> None:
    if not isinstance(value, dict):
        raise InputError("restore record is not an object")
    exact_fields(
        value,
        {"key_sha256", "generation", "owner_sha256", "fence", "value_sha256"},
    )
    exact_sha256(value["key_sha256"])
    bounded_int(value["generation"], 1)
    exact_sha256(value["owner_sha256"])
    bounded_int(value["fence"], 1)
    exact_sha256(value["value_sha256"])


def validate_restore(value: dict[str, Any]) -> None:
    exact_fields(value, {"kind", "outcome", "snapshot_index", "records"})
    if value["outcome"] not in {"success", "indeterminate", "unavailable"}:
        raise InputError("restore outcome is unsupported")
    records = bounded_list(value["records"], 0, MAX_RESTORE_RECORDS)
    for record in records:
        validate_restore_record(record)
    if value["outcome"] == "success":
        bounded_int(value["snapshot_index"])
    elif value["snapshot_index"] is not None or records:
        raise InputError("unknown restore outcome carries a snapshot")


def validate_readiness(value: dict[str, Any]) -> None:
    exact_fields(
        value,
        {
            "kind",
            "sample_sequence",
            "expected_quorum",
            "state",
            "term",
            "commit_index",
            "applied_index",
        },
    )
    bounded_int(value["sample_sequence"], 1)
    exact_bool(value["expected_quorum"])
    if value["state"] not in {"ready", "not_ready"}:
        raise InputError("readiness state is unsupported")
    if value["state"] == "ready":
        bounded_int(value["term"], 1)
        bounded_int(value["commit_index"])
        bounded_int(value["applied_index"])
    elif any(value[field] is not None for field in ("term", "commit_index", "applied_index")):
        raise InputError("not-ready sample carries authority")


def validate_history(rows: list[dict[str, Any]], contract: Contract) -> list[dict[str, Any]]:
    if len(rows) != contract.operation_count:
        raise InputError("history omits an operation")
    operation_ids: set[str] = set()
    counts = {"batch": 0, "watch": 0, "restore": 0, "readiness": 0}
    for row in rows:
        exact_fields(
            row,
            {
                "schema_version",
                "history_id",
                "history_operation_count",
                "operation_id",
                "process_id",
                "started_ns",
                "completed_ns",
                "operation",
            },
        )
        operation_id = bounded_string(row["operation_id"], 128)
        process_id = bounded_string(row["process_id"], 128)
        started = bounded_int(row["started_ns"], contract.campaign_started_ns)
        completed = bounded_int(
            row["completed_ns"], started, contract.campaign_completed_ns
        )
        if (
            row["schema_version"] != "opc-session-ha-concurrent-history/v3"
            or row["history_id"] != contract.history_id
            or row["history_operation_count"] != contract.operation_count
            or operation_id in operation_ids
            or process_id not in contract.process_ids
        ):
            raise InputError("history envelope is inconsistent")
        operation_ids.add(operation_id)
        operation = row["operation"]
        if not isinstance(operation, dict):
            raise InputError("history operation is not an object")
        kind = operation.get("kind")
        if kind == "batch":
            validate_batch(operation)
        elif kind == "watch":
            validate_watch(operation)
        elif kind == "restore":
            validate_restore(operation)
        elif kind == "readiness":
            validate_readiness(operation)
        else:
            raise InputError("history operation kind is unsupported")
        counts[kind] += 1
    if any(count == 0 for count in counts.values()) or counts["batch"] > MAX_BATCH_OPERATIONS:
        raise InputError("history kind coverage is outside checker bounds")
    return rows


@dataclass
class CheckResult:
    violations: set[str] = field(default_factory=set)
    inconclusive: set[str] = field(default_factory=set)
    checked: int = 0
    counts: dict[str, int] = field(
        default_factory=lambda: {"batch": 0, "watch": 0, "restore": 0, "readiness": 0}
    )


def record_from_mutation(mutation: dict[str, Any]) -> dict[str, Any]:
    return {
        "key_sha256": mutation["key_sha256"],
        "generation": mutation["new_generation"],
        "owner_sha256": mutation["owner_sha256"],
        "fence": mutation["fence"],
        "value_sha256": mutation["value_sha256"],
    }


def state_through(
    successes: list[dict[str, Any]], linearization_index: int
) -> dict[str, dict[str, Any]]:
    state: dict[str, dict[str, Any]] = {}
    for row in successes:
        operation = row["operation"]
        if operation["linearization_index"] > linearization_index:
            break
        for mutation in operation["mutations"]:
            state[mutation["key_sha256"]] = record_from_mutation(mutation)
    return state


def mutation_expectations_match(
    state: dict[str, dict[str, Any]], mutations: list[dict[str, Any]]
) -> bool:
    for mutation in mutations:
        current = state.get(mutation["key_sha256"])
        generation = None if current is None else current["generation"]
        if generation != mutation["expected_generation"]:
            return False
    return True


def evaluate_batches(rows: list[dict[str, Any]], result: CheckResult) -> list[dict[str, Any]]:
    batches = [row for row in rows if row["operation"]["kind"] == "batch"]
    result.counts["batch"] = len(batches)
    unknown = [
        row
        for row in batches
        if row["operation"]["outcome"] in {"indeterminate", "unavailable"}
    ]
    if unknown:
        result.inconclusive.add("unknown_batch_outcome")
        result.inconclusive.add("state_depends_on_unknown_batch")

    determinate = [row for row in batches if row not in unknown]
    successes = sorted(
        (row for row in determinate if row["operation"]["outcome"] == "success"),
        key=lambda row: row["operation"]["linearization_index"],
    )
    indices = [row["operation"]["linearization_index"] for row in successes]
    if len(indices) != len(set(indices)):
        result.violations.add("conflicting_commit_index")

    for left in determinate:
        for right in determinate:
            left_index = left["operation"]["linearization_index"]
            right_index = right["operation"]["linearization_index"]
            if (
                left["completed_ns"] < right["started_ns"]
                and (
                    left_index > right_index
                    or (
                        left_index == right_index
                        and right["operation"]["outcome"] == "success"
                    )
                )
            ):
                result.violations.add("real_time_order_violation")

    state: dict[str, dict[str, Any]] = {}
    for row in successes:
        operation = row["operation"]
        if not mutation_expectations_match(state, operation["mutations"]):
            result.violations.add("batch_atomicity_violation")
            continue
        for mutation in operation["mutations"]:
            state[mutation["key_sha256"]] = record_from_mutation(mutation)
        result.checked += 1

    for row in determinate:
        operation = row["operation"]
        if operation["outcome"] != "conflict":
            continue
        observed_state = state_through(successes, operation["linearization_index"])
        if mutation_expectations_match(observed_state, operation["mutations"]):
            result.violations.add("batch_conflict_violation")
        else:
            result.checked += 1
    return successes


def expected_watch_events(
    successes: list[dict[str, Any]], requested: int, completed: int
) -> list[dict[str, Any]]:
    expected: list[dict[str, Any]] = []
    for row in successes:
        operation = row["operation"]
        commit_index = operation["linearization_index"]
        if not requested < commit_index <= completed:
            continue
        for offset, mutation in enumerate(operation["mutations"], start=1):
            expected.append(
                {
                    "commit_index": commit_index,
                    "batch_operation_id": row["operation_id"],
                    "mutation_offset": offset,
                    "key_sha256": mutation["key_sha256"],
                    "generation": mutation["new_generation"],
                    "owner_sha256": mutation["owner_sha256"],
                    "fence": mutation["fence"],
                    "value_sha256": mutation["value_sha256"],
                }
            )
    return expected


def evaluate_watches(
    rows: list[dict[str, Any]], successes: list[dict[str, Any]], state_known: bool, result: CheckResult
) -> None:
    watches = [row for row in rows if row["operation"]["kind"] == "watch"]
    result.counts["watch"] = len(watches)
    for row in watches:
        operation = row["operation"]
        if operation["outcome"] != "success":
            result.inconclusive.add("unknown_watch_outcome")
            continue
        if not state_known:
            continue
        complete_through = operation["complete_through_index"]
        if any(
            item["started_ns"] > row["completed_ns"]
            and item["operation"]["linearization_index"] <= complete_through
            for item in successes
        ):
            result.violations.add("watch_future_commit_violation")
            continue
        acknowledged_during_watch = [
            item["operation"]["linearization_index"]
            for item in successes
            if item["completed_ns"] < row["completed_ns"]
        ]
        if acknowledged_during_watch and complete_through < max(acknowledged_during_watch):
            result.violations.add("watch_completion_head_violation")
            continue
        expected = expected_watch_events(
            successes, operation["requested_after_index"], complete_through
        )
        if operation["events"] != expected:
            result.violations.add("watch_gap_or_reorder")
            continue
        result.checked += 1


def evaluate_restores(
    rows: list[dict[str, Any]], successes: list[dict[str, Any]], state_known: bool, result: CheckResult
) -> None:
    restores = [row for row in rows if row["operation"]["kind"] == "restore"]
    result.counts["restore"] = len(restores)
    for row in restores:
        operation = row["operation"]
        if operation["outcome"] != "success":
            result.inconclusive.add("unknown_restore_outcome")
            continue
        if not state_known:
            continue
        snapshot_index = operation["snapshot_index"]
        if any(
            item["completed_ns"] < row["started_ns"]
            and item["operation"]["linearization_index"] > snapshot_index
            for item in successes
        ) or any(
            item["started_ns"] > row["completed_ns"]
            and item["operation"]["linearization_index"] <= snapshot_index
            for item in successes
        ):
            result.violations.add("restore_real_time_violation")
            continue
        expected = sorted(
            state_through(successes, snapshot_index).values(),
            key=lambda record: record["key_sha256"],
        )
        if operation["records"] != expected:
            result.violations.add("restore_state_violation")
            continue
        result.checked += 1


def evaluate_readiness(
    rows: list[dict[str, Any]], successes: list[dict[str, Any]], contract: Contract, result: CheckResult
) -> None:
    samples = [row for row in rows if row["operation"]["kind"] == "readiness"]
    result.counts["readiness"] = len(samples)
    by_process: dict[str, list[dict[str, Any]]] = {
        process_id: [] for process_id in contract.process_ids
    }
    for sample in samples:
        by_process[sample["process_id"]].append(sample)

    for process_id in contract.process_ids:
        process_samples = sorted(
            by_process[process_id], key=lambda row: row["operation"]["sample_sequence"]
        )
        if not process_samples:
            result.violations.add("readiness_coverage_violation")
            continue
        if [row["operation"]["sample_sequence"] for row in process_samples] != list(
            range(1, len(process_samples) + 1)
        ):
            result.violations.add("readiness_sequence_violation")
        timestamps = [row["started_ns"] for row in process_samples]
        if any(right <= left for left, right in zip(timestamps, timestamps[1:])):
            result.violations.add("readiness_sampling_order_violation")
        if (
            timestamps[0] - contract.campaign_started_ns > contract.max_readiness_gap_ns
            or contract.campaign_completed_ns - timestamps[-1]
            > contract.max_readiness_gap_ns
            or any(
                right - left > contract.max_readiness_gap_ns
                for left, right in zip(timestamps, timestamps[1:])
            )
        ):
            result.violations.add("readiness_sampling_gap")

        last_term = 0
        last_commit = 0
        last_applied = 0
        for sample in process_samples:
            operation = sample["operation"]
            if operation["state"] == "not_ready":
                continue
            if not operation["expected_quorum"]:
                result.violations.add("readiness_gating_violation")
                continue
            term = operation["term"]
            commit_index = operation["commit_index"]
            applied_index = operation["applied_index"]
            if any(
                row["started_ns"] > sample["completed_ns"]
                and row["operation"]["linearization_index"] <= commit_index
                for row in successes
            ):
                result.violations.add("readiness_future_commit_violation")
                continue
            required_commit = max(
                (
                    row["operation"]["linearization_index"]
                    for row in successes
                    if row["completed_ns"] < sample["started_ns"]
                ),
                default=0,
            )
            if (
                applied_index < commit_index
                or commit_index < required_commit
                or term < last_term
                or commit_index < last_commit
                or applied_index < last_applied
            ):
                result.violations.add("readiness_authority_violation")
                continue
            last_term = term
            last_commit = commit_index
            last_applied = applied_index
            result.checked += 1


def evaluate(rows: list[dict[str, Any]], contract: Contract) -> CheckResult:
    result = CheckResult()
    successes = evaluate_batches(rows, result)
    state_known = "state_depends_on_unknown_batch" not in result.inconclusive
    evaluate_watches(rows, successes, state_known, result)
    evaluate_restores(rows, successes, state_known, result)
    evaluate_readiness(rows, successes, contract, result)
    return result


def emit(status: str, exit_code: int, result: CheckResult | None = None) -> int:
    counts = (
        {"batch": 0, "readiness": 0, "restore": 0, "watch": 0}
        if result is None
        else result.counts
    )
    payload = {
        "checker": CHECKER_NAME,
        "checker_version": CHECKER_VERSION,
        "history_operations_checked": 0 if result is None else result.checked,
        "inconclusive_codes": [] if result is None else sorted(result.inconclusive),
        "operation_counts": counts,
        "status": status,
        "violation_codes": [] if result is None else sorted(result.violations),
    }
    sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    return exit_code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check bounded concurrent session-HA candidate evidence"
    )
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--history", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    os.umask(0o077)
    args = parse_args()
    try:
        checker_raw = read_bounded(Path(__file__), MAX_EVIDENCE_BYTES)
        evidence_raw = read_bounded(args.evidence, MAX_EVIDENCE_BYTES)
        history_raw, history_rows = load_history(args.history)
        evidence = parse_json(evidence_raw)
        contract = validate_evidence(evidence, history_raw, checker_raw)
        rows = validate_history(history_rows, contract)
        result = evaluate(rows, contract)
    except (InputError, ValueError, RecursionError):
        return emit("invalid_input", 3)
    if result.violations:
        return emit("fail", 1, result)
    if result.inconclusive:
        return emit("inconclusive", 2, result)
    return emit("pass", 0, result)


if __name__ == "__main__":
    raise SystemExit(main())
