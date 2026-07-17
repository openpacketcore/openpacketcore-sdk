#!/usr/bin/env python3
"""Check one bounded per-slot session-HA candidate history.

This checker is deliberately independent of the Rust SDK. It consumes a
closed evidence document, digest-bound JSONL history, and digest-bound fault
schedule, then checks the actual per-slot CAS batch contract under fixed
campaign-valid lease guards, the committed application-journal watch stream,
complete restore state, and schedule-derived fail-closed readiness sampling.
Openraft term/log indices and application-journal sequences remain separate
domains. The checker never upgrades candidate evidence into production
qualification.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CHECKER_NAME = "check-session-ha-concurrent-history-v5.py"
CHECKER_VERSION = "5"
MAX_EVIDENCE_BYTES = 256 * 1024
MAX_FAULT_SCHEDULE_BYTES = 256 * 1024
MAX_HISTORY_BYTES = 8 * 1024 * 1024
MAX_LINE_BYTES = 256 * 1024
MAX_OPERATIONS = 10_000
MAX_BATCH_OPERATIONS = 64
MAX_BATCH_SLOTS = 16
MAX_WATCH_EVENTS = 4_096
MAX_RESTORE_RECORDS = 4_096
MAX_FAULT_INTERVALS = 1_024
MAX_PREACQUIRED_LEASES = MAX_BATCH_OPERATIONS * MAX_BATCH_SLOTS
MAX_JSON_INTEGER_DIGITS = 20
MAX_U64 = (1 << 64) - 1
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


def exact_enum(value: Any, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise InputError("value is not a supported enum member")
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
    initial_journal_head: int
    state_type_sha256: str
    preacquired_leases: dict[str, "LeaseBinding"]


@dataclass(frozen=True)
class LeaseBinding:
    key_sha256: str
    owner_sha256: str
    fence: int
    valid_from_ns: int
    valid_through_ns: int


@dataclass(frozen=True)
class FaultInterval:
    started_ns: int
    completed_ns: int
    running_process_ids: frozenset[str]
    available_pairs: frozenset[tuple[str, str]]

    def expected_quorum(self, process_id: str, member_count: int) -> bool:
        if process_id not in self.running_process_ids:
            return False
        reachable = 1 + sum(process_id in pair for pair in self.available_pairs)
        return reachable >= member_count // 2 + 1


@dataclass(frozen=True)
class FaultSchedule:
    intervals: tuple[FaultInterval, ...]
    interval_starts: tuple[int, ...]

    def interval_for(self, started_ns: int, completed_ns: int) -> FaultInterval | None:
        index = bisect.bisect_right(self.interval_starts, started_ns) - 1
        if index < 0:
            return None
        interval = self.intervals[index]
        if completed_ns > interval.completed_ns:
            return None
        return interval


def validate_lease_binding(value: Any) -> LeaseBinding:
    if not isinstance(value, dict):
        raise InputError("pre-acquired lease is not an object")
    exact_fields(
        value,
        {
            "key_sha256",
            "owner_sha256",
            "fence",
            "valid_from_ns",
            "valid_through_ns",
        },
    )
    return LeaseBinding(
        key_sha256=exact_sha256(value["key_sha256"]),
        owner_sha256=exact_sha256(value["owner_sha256"]),
        fence=bounded_int(value["fence"], 1),
        valid_from_ns=bounded_int(value["valid_from_ns"]),
        valid_through_ns=bounded_int(value["valid_through_ns"]),
    )


def validate_evidence(
    value: Any, history_raw: bytes, checker_raw: bytes, fault_schedule_raw: bytes
) -> Contract:
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
        value["schema_version"] != "opc-session-ha-candidate-evidence/v5"
        or value["profile_id"] != "opc-session-openraft-ha/v5-candidate"
        or value["experimental"] is not True
        or value["qualification_complete"] is not False
        or value["counts_for_production"] is not False
    ):
        raise InputError("evidence makes an unsupported maturity claim")
    if not isinstance(value["source_revision"], str) or REVISION_RE.fullmatch(
        value["source_revision"]
    ) is None:
        raise InputError("source revision is not exact")
    exact_enum(value["source_tree_status"], {"clean", "dirty_unqualified"})

    artifact = value["artifact"]
    if not isinstance(artifact, dict):
        raise InputError("artifact is not an object")
    exact_fields(artifact, {"name", "version", "sha256", "exact_release_artifact"})
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
    completed = bounded_int(execution["campaign_completed_ns"], started + 1, MAX_U64 - 1)
    members = bounded_int(execution["topology_members"], 3, 5)
    if members not in {3, 5}:
        raise InputError("topology is outside the candidate contract")
    raw_process_ids = bounded_list(execution["process_ids"], members, members)
    process_ids = tuple(bounded_string(item, 128) for item in raw_process_ids)
    if len(set(process_ids)) != members:
        raise InputError("process identities are not exact and distinct")
    max_gap = bounded_int(execution["max_readiness_gap_ns"], 1, 60_000_000_000)
    if exact_sha256(execution["fault_schedule_sha256"]) != sha256(fault_schedule_raw):
        raise InputError("fault schedule digest does not match evidence")

    workload = value["workload"]
    if not isinstance(workload, dict):
        raise InputError("workload is not an object")
    exact_fields(
        workload,
        {
            "schedule_sha256",
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
        },
    )
    exact_sha256(workload["schedule_sha256"])
    initial_journal_head = bounded_int(workload["initial_journal_head"])
    if any(
        workload[field] is not True
        for field in (
            "isolated_digest_namespace",
            "initial_state_empty",
            "complete_write_history",
            "serialized_batch_invocations",
            "exclusive_application_journal_window",
            "records_non_expiring_through_campaign",
            "no_lease_mutations_in_history_window",
        )
    ):
        raise InputError("history cannot prove the bounded journal namespace")
    if workload["state_class"] != "authoritative-session":
        raise InputError("workload state class is not authoritative")
    state_type_sha256 = exact_sha256(workload["state_type_sha256"])
    raw_leases = bounded_list(
        workload["preacquired_leases"], 1, MAX_PREACQUIRED_LEASES
    )
    leases = [validate_lease_binding(item) for item in raw_leases]
    lease_keys = [lease.key_sha256 for lease in leases]
    if lease_keys != sorted(lease_keys) or len(lease_keys) != len(set(lease_keys)):
        raise InputError("pre-acquired leases are not canonical and unique")
    if any(
        lease.valid_from_ns > started or lease.valid_through_ns <= completed
        for lease in leases
    ):
        raise InputError("pre-acquired lease does not cover the campaign")

    history = value["history"]
    if not isinstance(history, dict):
        raise InputError("history binding is not an object")
    exact_fields(history, {"schema_version", "sha256", "operation_count", "required_kinds"})
    if history["schema_version"] != "opc-session-ha-concurrent-history/v5":
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
            "cas_batch_per_slot_outcomes",
            "gap_free_application_journal_watch",
            "restore_state_within_call_interval",
            "separate_raft_and_journal_domains",
            "fault_schedule_derived_readiness_gating",
            "fixed_campaign_lease_guards",
            "authoritative_non_expiring_records",
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
        initial_journal_head=initial_journal_head,
        state_type_sha256=state_type_sha256,
        preacquired_leases={lease.key_sha256: lease for lease in leases},
    )


def validate_fault_pair(
    value: Any,
    process_positions: dict[str, int],
    running_process_ids: frozenset[str],
) -> tuple[str, str]:
    if not isinstance(value, dict):
        raise InputError("fault-schedule pair is not an object")
    exact_fields(value, {"left_process_id", "right_process_id"})
    left = bounded_string(value["left_process_id"], 128)
    right = bounded_string(value["right_process_id"], 128)
    if (
        left not in process_positions
        or right not in process_positions
        or process_positions[left] >= process_positions[right]
        or left not in running_process_ids
        or right not in running_process_ids
    ):
        raise InputError("fault-schedule pair is not canonical and available")
    return left, right


def validate_fault_schedule(value: Any, contract: Contract) -> FaultSchedule:
    if not isinstance(value, dict):
        raise InputError("fault schedule is not an object")
    exact_fields(
        value,
        {
            "schema_version",
            "history_id",
            "campaign_started_ns",
            "campaign_completed_ns",
            "process_ids",
            "intervals",
        },
    )
    campaign_started_ns = bounded_int(value["campaign_started_ns"])
    campaign_completed_ns = bounded_int(value["campaign_completed_ns"])
    if (
        value["schema_version"] != "opc-session-ha-fault-schedule/v5"
        or value["history_id"] != contract.history_id
        or campaign_started_ns != contract.campaign_started_ns
        or campaign_completed_ns != contract.campaign_completed_ns
        or value["process_ids"] != list(contract.process_ids)
    ):
        raise InputError("fault schedule envelope does not match evidence")

    process_positions = {
        process_id: index for index, process_id in enumerate(contract.process_ids)
    }
    raw_intervals = bounded_list(value["intervals"], 1, MAX_FAULT_INTERVALS)
    intervals: list[FaultInterval] = []
    expected_start = contract.campaign_started_ns
    for expected_sequence, raw_interval in enumerate(raw_intervals, start=1):
        if not isinstance(raw_interval, dict):
            raise InputError("fault-schedule interval is not an object")
        exact_fields(
            raw_interval,
            {
                "interval_sequence",
                "started_ns",
                "completed_ns",
                "running_process_ids",
                "available_bidirectional_pairs",
            },
        )
        if bounded_int(raw_interval["interval_sequence"], 1) != expected_sequence:
            raise InputError("fault-schedule interval sequence is not contiguous")
        started = bounded_int(
            raw_interval["started_ns"],
            contract.campaign_started_ns,
            contract.campaign_completed_ns,
        )
        completed = bounded_int(
            raw_interval["completed_ns"], started, contract.campaign_completed_ns
        )
        if started != expected_start:
            raise InputError("fault-schedule intervals do not cover the campaign")
        raw_running = bounded_list(
            raw_interval["running_process_ids"], 0, len(contract.process_ids)
        )
        running = [bounded_string(item, 128) for item in raw_running]
        if any(process_id not in process_positions for process_id in running):
            raise InputError("fault schedule names an unknown process")
        if running != sorted(running, key=lambda item: process_positions[item]) or len(
            running
        ) != len(set(running)):
            raise InputError("fault-schedule running processes are not canonical")
        running_set = frozenset(running)
        maximum_pairs = len(contract.process_ids) * (len(contract.process_ids) - 1) // 2
        raw_pairs = bounded_list(
            raw_interval["available_bidirectional_pairs"], 0, maximum_pairs
        )
        pairs = [
            validate_fault_pair(pair, process_positions, running_set)
            for pair in raw_pairs
        ]
        canonical_pairs = sorted(
            pairs,
            key=lambda pair: (process_positions[pair[0]], process_positions[pair[1]]),
        )
        if pairs != canonical_pairs or len(pairs) != len(set(pairs)):
            raise InputError("fault-schedule pairs are not canonical and unique")
        intervals.append(
            FaultInterval(
                started_ns=started,
                completed_ns=completed,
                running_process_ids=running_set,
                available_pairs=frozenset(pairs),
            )
        )
        expected_start = completed + 1
    if expected_start != contract.campaign_completed_ns + 1:
        raise InputError("fault-schedule intervals do not end with the campaign")

    for process_id in contract.process_ids:
        derived = [
            interval.expected_quorum(process_id, len(contract.process_ids))
            for interval in intervals
        ]
        if not derived[0] or True not in derived or False not in derived:
            raise InputError("fault schedule lacks initial quorum and quorum loss")
        first_loss = derived.index(False)
        if True not in derived[first_loss + 1 :]:
            raise InputError("fault schedule lacks quorum recovery")

    return FaultSchedule(
        intervals=tuple(intervals),
        interval_starts=tuple(interval.started_ns for interval in intervals),
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
            "state_class",
            "state_type_sha256",
            "expires_at_ns",
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
    if value["state_class"] != "authoritative-session":
        raise InputError("batch mutation state class is not authoritative")
    exact_sha256(value["state_type_sha256"])
    if value["expires_at_ns"] is not None:
        raise InputError("batch mutation is not non-expiring")
    exact_sha256(value["value_sha256"])
    return value


def validate_batch_slot(value: Any, expected_index: int) -> None:
    if not isinstance(value, dict):
        raise InputError("batch slot is not an object")
    exact_fields(value, {"slot_index", "outcome", "journal_sequence", "mutation"})
    if bounded_int(value["slot_index"], 1, MAX_BATCH_SLOTS) != expected_index:
        raise InputError("batch slot indices are not contiguous")
    exact_enum(
        value["outcome"], {"success", "conflict", "indeterminate", "unavailable"}
    )
    if value["outcome"] == "success":
        bounded_int(value["journal_sequence"], 1)
    elif value["journal_sequence"] is not None:
        raise InputError("non-successful batch slot claims a journal sequence")
    validate_mutation(value["mutation"])


def validate_batch(value: dict[str, Any]) -> None:
    exact_fields(value, {"kind", "invocation_sequence", "outcome", "slots"})
    bounded_int(value["invocation_sequence"], 1, MAX_BATCH_OPERATIONS)
    exact_enum(value["outcome"], {"completed", "indeterminate", "unavailable"})
    slots = bounded_list(value["slots"], 1, MAX_BATCH_SLOTS)
    for index, slot in enumerate(slots, start=1):
        validate_batch_slot(slot, index)
    if value["outcome"] != "completed" and any(
        slot["outcome"] != value["outcome"] for slot in slots
    ):
        raise InputError("unknown batch invocation carries determinate slots")


def validate_watch_event(value: Any) -> None:
    if not isinstance(value, dict):
        raise InputError("watch event is not an object")
    exact_fields(
        value,
        {
            "journal_sequence",
            "batch_operation_id",
            "slot_index",
            "key_sha256",
            "generation",
            "owner_sha256",
            "fence",
            "state_class",
            "state_type_sha256",
            "expires_at_ns",
            "value_sha256",
        },
    )
    bounded_int(value["journal_sequence"], 1)
    bounded_string(value["batch_operation_id"], 128)
    bounded_int(value["slot_index"], 1, MAX_BATCH_SLOTS)
    exact_sha256(value["key_sha256"])
    bounded_int(value["generation"], 1)
    exact_sha256(value["owner_sha256"])
    bounded_int(value["fence"], 1)
    if value["state_class"] != "authoritative-session":
        raise InputError("watch event state class is not authoritative")
    exact_sha256(value["state_type_sha256"])
    if value["expires_at_ns"] is not None:
        raise InputError("watch event is not non-expiring")
    exact_sha256(value["value_sha256"])


def validate_watch(value: dict[str, Any]) -> None:
    exact_fields(
        value,
        {
            "kind",
            "outcome",
            "subscription_id",
            "requested_after_journal_sequence",
            "complete_through_journal_sequence",
            "events",
        },
    )
    bounded_string(value["subscription_id"], 128)
    exact_enum(value["outcome"], {"success", "indeterminate", "unavailable"})
    requested = bounded_int(value["requested_after_journal_sequence"])
    events = bounded_list(value["events"], 0, MAX_WATCH_EVENTS)
    for event in events:
        validate_watch_event(event)
    if value["outcome"] == "success":
        completed = bounded_int(value["complete_through_journal_sequence"], requested)
        if completed - requested > MAX_WATCH_EVENTS:
            raise InputError("watch journal window is outside checker bounds")
    elif value["complete_through_journal_sequence"] is not None or events:
        raise InputError("unknown watch outcome carries completed events")


def validate_restore_record(value: Any) -> None:
    if not isinstance(value, dict):
        raise InputError("restore record is not an object")
    exact_fields(
        value,
        {
            "key_sha256",
            "generation",
            "owner_sha256",
            "fence",
            "state_class",
            "state_type_sha256",
            "expires_at_ns",
            "value_sha256",
        },
    )
    exact_sha256(value["key_sha256"])
    bounded_int(value["generation"], 1)
    exact_sha256(value["owner_sha256"])
    bounded_int(value["fence"], 1)
    if value["state_class"] != "authoritative-session":
        raise InputError("restore record state class is not authoritative")
    exact_sha256(value["state_type_sha256"])
    if value["expires_at_ns"] is not None:
        raise InputError("restore record is not non-expiring")
    exact_sha256(value["value_sha256"])


def validate_restore(value: dict[str, Any]) -> None:
    exact_fields(value, {"kind", "outcome", "complete", "records"})
    exact_enum(value["outcome"], {"success", "indeterminate", "unavailable"})
    exact_bool(value["complete"])
    records = bounded_list(value["records"], 0, MAX_RESTORE_RECORDS)
    for record in records:
        validate_restore_record(record)
    keys = [record["key_sha256"] for record in records]
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise InputError("restore records are not canonical and unique")
    if value["outcome"] == "success":
        if value["complete"] is not True:
            raise InputError("successful restore is not complete")
    elif value["complete"] is not False or records:
        raise InputError("unknown restore outcome carries complete records")


def validate_readiness(value: dict[str, Any]) -> None:
    exact_fields(
        value,
        {
            "kind",
            "sample_sequence",
            "expected_quorum",
            "state",
            "raft_term",
            "raft_commit_index",
            "raft_applied_index",
            "journal_head",
        },
    )
    bounded_int(value["sample_sequence"], 1)
    exact_bool(value["expected_quorum"])
    exact_enum(value["state"], {"ready", "not_ready"})
    authority_fields = (
        "raft_term",
        "raft_commit_index",
        "raft_applied_index",
        "journal_head",
    )
    if value["state"] == "ready":
        bounded_int(value["raft_term"], 1)
        for field in authority_fields[1:]:
            bounded_int(value[field])
    elif any(value[field] is not None for field in authority_fields):
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
        bounded_int(row["completed_ns"], started, contract.campaign_completed_ns)
        if (
            row["schema_version"] != "opc-session-ha-concurrent-history/v5"
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
        "state_class": mutation["state_class"],
        "state_type_sha256": mutation["state_type_sha256"],
        "expires_at_ns": mutation["expires_at_ns"],
        "value_sha256": mutation["value_sha256"],
    }


def generation_for(state: dict[str, dict[str, Any]], key: str) -> int | None:
    current = state.get(key)
    return None if current is None else current["generation"]


def successful_mutation(
    row: dict[str, Any], slot: dict[str, Any]
) -> dict[str, Any]:
    return {
        "journal_sequence": slot["journal_sequence"],
        "batch_operation_id": row["operation_id"],
        "slot_index": slot["slot_index"],
        "mutation": slot["mutation"],
        "started_ns": row["started_ns"],
        "completed_ns": row["completed_ns"],
    }


def evaluate_batches(
    rows: list[dict[str, Any]], contract: Contract, result: CheckResult
) -> tuple[list[dict[str, Any]], bool]:
    batches = sorted(
        (row for row in rows if row["operation"]["kind"] == "batch"),
        key=lambda row: row["operation"]["invocation_sequence"],
    )
    result.counts["batch"] = len(batches)
    if [row["operation"]["invocation_sequence"] for row in batches] != list(
        range(1, len(batches) + 1)
    ):
        result.violations.add("batch_invocation_sequence_violation")
    if any(
        right["started_ns"] < left["completed_ns"]
        for left, right in zip(batches, batches[1:])
    ):
        result.violations.add("overlapping_batch_invocations")

    observed_keys = {
        slot["mutation"]["key_sha256"]
        for row in batches
        for slot in row["operation"]["slots"]
    }
    if observed_keys != set(contract.preacquired_leases):
        result.violations.add("lease_contract_violation")

    partial_batch_observed = any(
        row["operation"]["outcome"] == "completed"
        and len(row["operation"]["slots"]) > 1
        and {slot["outcome"] for slot in row["operation"]["slots"]}
        >= {"success", "conflict"}
        for row in batches
    )
    if not partial_batch_observed:
        result.violations.add("partial_batch_coverage_violation")

    successes: list[dict[str, Any]] = []
    has_unknown = False
    contract_valid = observed_keys == set(contract.preacquired_leases)
    for row in batches:
        operation = row["operation"]
        if operation["outcome"] != "completed":
            has_unknown = True
            result.inconclusive.add("unknown_batch_invocation_outcome")
        for slot in operation["slots"]:
            mutation = slot["mutation"]
            lease = contract.preacquired_leases.get(mutation["key_sha256"])
            lease_matches_contract = (
                lease is not None
                and mutation["owner_sha256"] == lease.owner_sha256
                and mutation["fence"] == lease.fence
            )
            record_matches_contract = (
                mutation["state_type_sha256"] == contract.state_type_sha256
            )
            if not lease_matches_contract:
                contract_valid = False
                result.violations.add("lease_contract_violation")
            if not record_matches_contract:
                contract_valid = False
                result.violations.add("record_contract_violation")
            if slot["outcome"] == "success":
                successes.append(successful_mutation(row, slot))
            elif slot["outcome"] in {"indeterminate", "unavailable"}:
                has_unknown = True
                result.inconclusive.add("unknown_batch_slot_outcome")

    sequences = [item["journal_sequence"] for item in successes]
    if any(right <= left for left, right in zip(sequences, sequences[1:])):
        result.violations.add("application_journal_order_violation")
    if not has_unknown:
        if sequences and sequences[0] != contract.initial_journal_head + 1:
            result.violations.add("initial_journal_head_mismatch")
        if any(right != left + 1 for left, right in zip(sequences, sequences[1:])):
            result.violations.add("application_journal_gap")

    state: dict[str, dict[str, Any]] = {}
    state_known = True
    modeled_valid = contract_valid
    for row in batches:
        operation = row["operation"]
        batch_known = operation["outcome"] == "completed" and all(
            slot["outcome"] in {"success", "conflict"} for slot in operation["slots"]
        )
        if not state_known or not batch_known:
            state_known = False
            continue
        valid = True
        for slot in operation["slots"]:
            mutation = slot["mutation"]
            current_generation = generation_for(state, mutation["key_sha256"])
            expectation_matches = current_generation == mutation["expected_generation"]
            generation_advances = (
                current_generation is None
                or mutation["new_generation"] > current_generation
            )
            would_succeed = expectation_matches and generation_advances
            if slot["outcome"] == "success":
                if not would_succeed:
                    result.violations.add("batch_slot_success_violation")
                    valid = False
                state[mutation["key_sha256"]] = record_from_mutation(mutation)
            elif would_succeed:
                result.violations.add("batch_slot_conflict_violation")
                valid = False
        if valid:
            result.checked += 1
        else:
            modeled_valid = False
    return successes, state_known and not has_unknown and modeled_valid


def watch_event_from_success(success: dict[str, Any]) -> dict[str, Any]:
    mutation = success["mutation"]
    return {
        "journal_sequence": success["journal_sequence"],
        "batch_operation_id": success["batch_operation_id"],
        "slot_index": success["slot_index"],
        "key_sha256": mutation["key_sha256"],
        "generation": mutation["new_generation"],
        "owner_sha256": mutation["owner_sha256"],
        "fence": mutation["fence"],
        "state_class": mutation["state_class"],
        "state_type_sha256": mutation["state_type_sha256"],
        "expires_at_ns": mutation["expires_at_ns"],
        "value_sha256": mutation["value_sha256"],
    }


def evaluate_watches(
    rows: list[dict[str, Any]],
    successes: list[dict[str, Any]],
    state_known: bool,
    initial_journal_head: int,
    result: CheckResult,
) -> None:
    watches = [row for row in rows if row["operation"]["kind"] == "watch"]
    result.counts["watch"] = len(watches)
    terminal_head = (
        successes[-1]["journal_sequence"] if successes else initial_journal_head
    )
    terminal_watch_observed = False
    for row in watches:
        operation = row["operation"]
        if operation["outcome"] != "success":
            result.inconclusive.add("unknown_watch_outcome")
            continue
        if not state_known:
            continue
        requested = operation["requested_after_journal_sequence"]
        completed = operation["complete_through_journal_sequence"]
        required_at_start = max(
            (
                success["journal_sequence"]
                for success in successes
                if success["completed_ns"] <= row["started_ns"]
            ),
            default=initial_journal_head,
        )
        possible_at_start = max(
            (
                success["journal_sequence"]
                for success in successes
                if success["started_ns"] <= row["started_ns"]
            ),
            default=initial_journal_head,
        )
        possible_at_completion = max(
            (
                success["journal_sequence"]
                for success in successes
                if success["started_ns"] < row["completed_ns"]
            ),
            default=initial_journal_head,
        )
        if (
            requested < initial_journal_head
            or requested > possible_at_start
            or completed > possible_at_completion
        ):
            result.violations.add("watch_future_journal_violation")
            continue
        if completed < max(requested, required_at_start):
            result.violations.add("watch_completion_head_violation")
            continue
        expected = [
            watch_event_from_success(success)
            for success in successes
            if requested < success["journal_sequence"] <= completed
        ]
        observed_sequences = [event["journal_sequence"] for event in operation["events"]]
        complete_sequence = list(range(requested + 1, completed + 1))
        if operation["events"] != expected or observed_sequences != complete_sequence:
            result.violations.add("watch_gap_or_reorder")
            continue
        if requested == initial_journal_head and completed == terminal_head:
            terminal_watch_observed = True
        result.checked += 1
    if state_known and not terminal_watch_observed:
        result.violations.add("watch_terminal_coverage_violation")


RECORD_FIELDS = (
    "key_sha256",
    "generation",
    "owner_sha256",
    "fence",
    "state_class",
    "state_type_sha256",
    "expires_at_ns",
    "value_sha256",
)


def canonical_state_key(records: list[dict[str, Any]]) -> tuple[tuple[Any, ...], ...]:
    return tuple(tuple(record[field] for field in RECORD_FIELDS) for record in records)


@dataclass(frozen=True)
class PrefixStateIndex:
    heads_by_state: dict[tuple[tuple[Any, ...], ...], tuple[int, ...]]
    terminal_head: int


def build_prefix_state_index(
    successes: list[dict[str, Any]], initial_journal_head: int
) -> PrefixStateIndex:
    state: dict[str, dict[str, Any]] = {}
    mutable_heads: dict[tuple[tuple[Any, ...], ...], list[int]] = {(): [initial_journal_head]}
    terminal_head = initial_journal_head
    for success in successes:
        mutation = success["mutation"]
        state[mutation["key_sha256"]] = record_from_mutation(mutation)
        canonical = sorted(state.values(), key=lambda record: record["key_sha256"])
        key = canonical_state_key(canonical)
        terminal_head = success["journal_sequence"]
        mutable_heads.setdefault(key, []).append(terminal_head)
    return PrefixStateIndex(
        heads_by_state={key: tuple(heads) for key, heads in mutable_heads.items()},
        terminal_head=terminal_head,
    )


def evaluate_restores(
    rows: list[dict[str, Any]],
    successes: list[dict[str, Any]],
    state_known: bool,
    initial_journal_head: int,
    prefix_index: PrefixStateIndex,
    result: CheckResult,
) -> None:
    restores = [row for row in rows if row["operation"]["kind"] == "restore"]
    result.counts["restore"] = len(restores)
    last_batch_completed_ns = max(
        row["completed_ns"]
        for row in rows
        if row["operation"]["kind"] == "batch"
    )
    terminal_restore_observed = False
    for row in restores:
        operation = row["operation"]
        if operation["outcome"] != "success":
            result.inconclusive.add("unknown_restore_outcome")
            continue
        if not state_known:
            continue
        baseline = initial_journal_head
        lower = max(
            (
                success["journal_sequence"]
                for success in successes
                if success["completed_ns"] <= row["started_ns"]
            ),
            default=baseline,
        )
        future = [
            success["journal_sequence"]
            for success in successes
            if success["started_ns"] >= row["completed_ns"]
        ]
        upper = min(future) - 1 if future else prefix_index.terminal_head
        if lower > upper:
            result.violations.add("restore_real_time_violation")
            continue
        observed_state = canonical_state_key(operation["records"])
        candidate_heads = prefix_index.heads_by_state.get(observed_state, ())
        candidate_index = bisect.bisect_left(candidate_heads, lower)
        if candidate_index == len(candidate_heads) or candidate_heads[candidate_index] > upper:
            result.violations.add("restore_state_violation")
            continue
        if (
            row["started_ns"] >= last_batch_completed_ns
            and prefix_index.terminal_head in candidate_heads
        ):
            terminal_restore_observed = True
        result.checked += 1
    if state_known and not terminal_restore_observed:
        result.violations.add("restore_terminal_coverage_violation")


def evaluate_readiness(
    rows: list[dict[str, Any]],
    successes: list[dict[str, Any]],
    state_known: bool,
    contract: Contract,
    fault_schedule: FaultSchedule,
    result: CheckResult,
) -> None:
    samples = [row for row in rows if row["operation"]["kind"] == "readiness"]
    result.counts["readiness"] = len(samples)
    by_process: dict[str, list[dict[str, Any]]] = {
        process_id: [] for process_id in contract.process_ids
    }
    for sample in samples:
        by_process[sample["process_id"]].append(sample)

    modeled_end_head = (
        successes[-1]["journal_sequence"]
        if successes
        else contract.initial_journal_head
    )
    batch_rows = [row for row in rows if row["operation"]["kind"] == "batch"]
    first_batch_started_ns = min(row["started_ns"] for row in batch_rows)
    last_batch_completed_ns = max(row["completed_ns"] for row in batch_rows)
    for process_id in contract.process_ids:
        process_samples = sorted(
            by_process[process_id],
            key=lambda row: row["operation"]["sample_sequence"],
        )
        if not process_samples:
            result.violations.add("readiness_coverage_violation")
            continue
        if [row["operation"]["sample_sequence"] for row in process_samples] != list(
            range(1, len(process_samples) + 1)
        ):
            result.violations.add("readiness_sequence_violation")
        if any(
            right["started_ns"] < left["completed_ns"]
            for left, right in zip(process_samples, process_samples[1:])
        ):
            result.violations.add("readiness_sampling_order_violation")
        completion_timestamps = [row["completed_ns"] for row in process_samples]
        if (
            completion_timestamps[0] - contract.campaign_started_ns
            > contract.max_readiness_gap_ns
            or contract.campaign_completed_ns - completion_timestamps[-1]
            > contract.max_readiness_gap_ns
            or any(
                right - left > contract.max_readiness_gap_ns
                for left, right in zip(
                    completion_timestamps, completion_timestamps[1:]
                )
            )
            or any(
                sample["completed_ns"] - sample["started_ns"]
                > contract.max_readiness_gap_ns
                for sample in process_samples
            )
        ):
            result.violations.add("readiness_sampling_gap")

        first = process_samples[0]
        first_operation = first["operation"]
        if not (
            first["completed_ns"] <= first_batch_started_ns
            and first_operation["state"] == "ready"
            and first_operation["journal_head"] == contract.initial_journal_head
        ):
            result.violations.add("initial_authority_observation_violation")

        terminal_authority_observed = False

        sample_intervals = [
            fault_schedule.interval_for(sample["started_ns"], sample["completed_ns"])
            for sample in process_samples
        ]
        previous_expected_quorum = fault_schedule.intervals[0].expected_quorum(
            process_id, len(contract.process_ids)
        )
        for interval in fault_schedule.intervals[1:]:
            expected_quorum = interval.expected_quorum(
                process_id, len(contract.process_ids)
            )
            if expected_quorum == previous_expected_quorum:
                continue
            observation_deadline = min(
                interval.completed_ns,
                interval.started_ns + contract.max_readiness_gap_ns,
            )
            expected_state = "ready" if expected_quorum else "not_ready"
            transition_observed = any(
                sample_interval == interval
                and sample["completed_ns"] <= observation_deadline
                and sample["operation"]["state"] == expected_state
                for sample, sample_interval in zip(process_samples, sample_intervals)
            )
            if not transition_observed:
                result.violations.add(
                    "readiness_recovery_observation_violation"
                    if expected_quorum
                    else "readiness_loss_observation_violation"
                )
            previous_expected_quorum = expected_quorum
        next_ready_by_interval: dict[FaultInterval, int] = {}
        next_ready_completion: list[int | None] = [None] * len(process_samples)
        for index in range(len(process_samples) - 1, -1, -1):
            interval = sample_intervals[index]
            if interval is None:
                continue
            next_ready_completion[index] = next_ready_by_interval.get(interval)
            if process_samples[index]["operation"]["state"] == "ready":
                next_ready_by_interval[interval] = process_samples[index]["completed_ns"]

        last_term = 0
        last_commit = 0
        last_applied = 0
        last_journal = contract.initial_journal_head
        for sample_index, sample in enumerate(process_samples):
            operation = sample["operation"]
            interval = sample_intervals[sample_index]
            if interval is None:
                result.violations.add("readiness_fault_interval_violation")
                continue
            expected_quorum = interval.expected_quorum(
                process_id, len(contract.process_ids)
            )
            if operation["expected_quorum"] is not expected_quorum:
                result.violations.add("readiness_schedule_mismatch")
            if operation["state"] == "not_ready":
                if expected_quorum:
                    recovery_deadline = min(
                        sample["completed_ns"] + contract.max_readiness_gap_ns,
                        interval.completed_ns,
                    )
                    recovered_at = next_ready_completion[sample_index]
                    recovered = (
                        recovered_at is not None
                        and sample["completed_ns"] < recovered_at <= recovery_deadline
                    )
                    if not recovered:
                        result.violations.add("readiness_recovery_violation")
                result.checked += 1
                continue
            if not expected_quorum:
                result.violations.add("readiness_gating_violation")
                continue
            raft_term = operation["raft_term"]
            raft_commit = operation["raft_commit_index"]
            raft_applied = operation["raft_applied_index"]
            journal_head = operation["journal_head"]
            required_journal = max(
                (
                    success["journal_sequence"]
                    for success in successes
                    if success["completed_ns"] <= sample["started_ns"]
                ),
                default=contract.initial_journal_head,
            )
            possible_journal = max(
                (
                    success["journal_sequence"]
                    for success in successes
                    if success["started_ns"] < sample["completed_ns"]
                ),
                default=contract.initial_journal_head,
            )
            journal_outside_modeled_history = state_known and (
                journal_head < required_journal or journal_head > possible_journal
            )
            if (
                raft_applied < raft_commit
                or raft_term < last_term
                or raft_commit < last_commit
                or raft_applied < last_applied
                or journal_outside_modeled_history
                or journal_head < last_journal
            ):
                result.violations.add("readiness_authority_violation")
                continue
            last_term = raft_term
            last_commit = raft_commit
            last_applied = raft_applied
            last_journal = journal_head
            if (
                state_known
                and sample_index == len(process_samples) - 1
                and sample["started_ns"] >= last_batch_completed_ns
                and contract.campaign_completed_ns - sample["completed_ns"]
                <= contract.max_readiness_gap_ns
                and journal_head == modeled_end_head
            ):
                terminal_authority_observed = True
            result.checked += 1
        if state_known and not terminal_authority_observed:
            result.violations.add("end_of_campaign_journal_head_violation")


def evaluate(
    rows: list[dict[str, Any]], contract: Contract, fault_schedule: FaultSchedule
) -> CheckResult:
    result = CheckResult()
    successes, state_known = evaluate_batches(rows, contract, result)
    evaluate_watches(
        rows,
        successes,
        state_known,
        contract.initial_journal_head,
        result,
    )
    prefix_index = build_prefix_state_index(successes, contract.initial_journal_head)
    evaluate_restores(
        rows,
        successes,
        state_known,
        contract.initial_journal_head,
        prefix_index,
        result,
    )
    evaluate_readiness(
        rows, successes, state_known, contract, fault_schedule, result
    )
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
        description="Check bounded per-slot concurrent session-HA candidate evidence"
    )
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--fault-schedule", required=True, type=Path)
    parser.add_argument("--history", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    os.umask(0o077)
    args = parse_args()
    try:
        checker_raw = read_bounded(Path(__file__), MAX_EVIDENCE_BYTES)
        evidence_raw = read_bounded(args.evidence, MAX_EVIDENCE_BYTES)
        fault_schedule_raw = read_bounded(
            args.fault_schedule, MAX_FAULT_SCHEDULE_BYTES
        )
        history_raw, history_rows = load_history(args.history)
        evidence = parse_json(evidence_raw)
        contract = validate_evidence(
            evidence, history_raw, checker_raw, fault_schedule_raw
        )
        fault_schedule = validate_fault_schedule(
            parse_json(fault_schedule_raw), contract
        )
        rows = validate_history(history_rows, contract)
        result = evaluate(rows, contract, fault_schedule)
    except (InputError, ValueError, RecursionError):
        return emit("invalid_input", 3)
    if result.violations:
        return emit("fail", 1, result)
    if result.inconclusive:
        return emit("inconclusive", 2, result)
    return emit("pass", 0, result)


if __name__ == "__main__":
    raise SystemExit(main())
