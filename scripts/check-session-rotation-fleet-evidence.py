#!/usr/bin/env python3
"""Independent checker for opc.session-net.rotation-fault-evidence.v1.

Validates the deterministic evidence documents emitted by the in-process
quorum-fleet mTLS rotation fault-matrix campaigns
(crates/opc-session-net/tests/rotation_fault_matrix.rs). The checker is the
independent second implementation of the qualification contract: it rejects
any document that is structurally open, digest-unbound, stale, over its
numeric SLOs, or inconsistent with the exact acknowledged-write accounting.

Usage: check-session-rotation-fleet-evidence.py EVIDENCE.json [--now-epoch N]

--now-epoch overrides the freshness reference (seconds since the UTC epoch);
the rotation_fault_matrix tests pass the campaign finish time so repeated
runs over archived documents stay deterministic. Without it, the current
wall clock is used.

Exit status: 0 and "ok: <campaign_id>" on acceptance; 1 with "reject:
<reason>" on stderr otherwise. The checker never upgrades a document: it
only validates the in-process campaign evidence class, which does not by
itself complete the deployed/signed qualification gates of issue #164.
"""

import argparse
import hashlib
import json
import sys
import time

MAX_EVIDENCE_BYTES = 256 * 1024
SCHEMA = "opc.session-net.rotation-fault-evidence.v1"
CHECKER_PATH = "scripts/check-session-rotation-fleet-evidence.py"

# Freshness window for finished_epoch_seconds relative to --now-epoch:
# [now - FRESHNESS_BEHIND_SECONDS, now + FRESHNESS_AHEAD_SECONDS]. Mirrors
# the operator campaign's capture-then-validate ordering (runbook section
# 7.2), with a wider behind bound for busy CI hosts.
FRESHNESS_BEHIND_SECONDS = 60
FRESHNESS_AHEAD_SECONDS = 5

# Pinned qualification configuration. A change to any of these values is a
# requalification event: the evidence only proves the campaign under the
# exact lifecycle and durable-consensus timing profile it records.
EXPECTED_LIFECYCLE = {
    "max_connection_age_seconds": 60,
    "drain_window_millis": 100,
    "reconnect_min_millis": 1,
    "reconnect_max_millis": 20,
}
EXPECTED_TIMING_PROFILE = {
    "cold_connect_timeout_millis": 1500,
    "heartbeat_millis": 2000,
    "election_timeout_max_millis": 8000,
    "operation_timeout_millis": 10000,
}

# Per-phase-kind duration SLOs (milliseconds). The transition and recovery
# envelopes are the profile-derived runbook values (two election windows
# plus one operation timeout, plus one backend operation and one delivery
# second for recovery). Traffic rounds are bounded by one committed write
# plus one linearizable read per reachable member, each within the operation
# timeout.
FAULT_SLO_MILLIS = 10_000
ROTATION_SLO_MILLIS = 26_000
RECOVERY_SLO_MILLIS = 37_000
BOUNDS_SLO_MILLIS = 10_000
PHASE_KINDS = ("fault", "rotation", "traffic", "recovery", "bounds")

FD_ALLOWANCE_MAX = 8
# Per-transition handshake-rate allowance: lane replacements, directed
# probes, and any late retirement redial attributable to an earlier
# transition (plan section 6; measured campaigns total at most 10).
RESOLVER_DELTA_ALLOWANCE_MAX = 16
# Per-directed-path campaign replacement allowance: two cached lanes plus
# one bounded retry per endpoint rotation of the path's two members, over
# three rotation cycles per member (3 x 2 x 3 = 18; measured campaigns total
# 9-13 per path). A reconnect storm exceeds it by orders of magnitude.
PATH_TOTAL_ALLOWANCE_MAX = 18
MAX_INT_DIGITS = 20


class Reject(Exception):
    pass


def reject(reason):
    raise Reject(reason)


def check_bool_free_int(value, field, minimum=0, maximum=None):
    if isinstance(value, bool) or not isinstance(value, int):
        reject(f"{field} is not an integer")
    if len(str(abs(value))) > MAX_INT_DIGITS:
        reject(f"{field} exceeds {MAX_INT_DIGITS} digits")
    if value < minimum:
        reject(f"{field} below {minimum}")
    if maximum is not None and value > maximum:
        reject(f"{field} above {maximum}")
    return value


def check_string(value, field, maximum=64):
    if not isinstance(value, str) or not value or len(value) > maximum:
        reject(f"{field} is not a bounded string")
    for char in value:
        if char not in "abcdefghijklmnopqrstuvwxyz0123456789-./_":
            reject(f"{field} has an unsafe character")
    return value


def check_digest(value, field):
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        reject(f"{field} is not a lowercase sha256 hex digest")
    return value


def check_exact_keys(obj, expected, context):
    if not isinstance(obj, dict):
        reject(f"{context} is not an object")
    if set(obj.keys()) != set(expected):
        reject(f"{context} keys are not exactly {sorted(expected)}")


def load_bounded_document(path):
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_EVIDENCE_BYTES + 1)
    except OSError as error:
        reject(f"cannot read evidence: {error}")
    if len(raw) > MAX_EVIDENCE_BYTES:
        reject("evidence exceeds the byte bound")

    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                reject(f"duplicate key {key!r}")
            result[key] = value
        return result

    def no_floats(value):
        if isinstance(value, float):
            reject("floating-point values are not representable in this contract")
        return value

    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=no_duplicates,
            parse_float=no_floats,
            parse_constant=lambda constant: reject(f"invalid constant {constant}"),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        reject(f"evidence is not one bounded JSON document: {error}")
    if not isinstance(document, dict):
        reject("evidence is not a JSON object")
    return document


def plan_digest(document):
    phases = document["phases"]
    plan = "{}|{}|".format(document["campaign_id"], document["topology"]["members"])
    entries = []
    for phase in phases:
        member = "-" if phase["member"] is None else str(phase["member"])
        entries.append("{}:{}:{}".format(phase["name"], phase["kind"], member))
    plan += ",".join(entries)
    return hashlib.sha256(plan.encode("utf-8")).hexdigest()


def self_digest():
    try:
        with open(__file__, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    except OSError as error:
        reject(f"cannot read checker for provenance binding: {error}")


def phase_slo_millis(kind, members):
    if kind == "fault":
        return FAULT_SLO_MILLIS
    if kind == "rotation":
        return ROTATION_SLO_MILLIS
    if kind == "traffic":
        return (members + 1) * EXPECTED_TIMING_PROFILE["operation_timeout_millis"]
    if kind == "recovery":
        return RECOVERY_SLO_MILLIS
    if kind == "bounds":
        return BOUNDS_SLO_MILLIS
    reject(f"unknown phase kind {kind!r}")


def validate(document, now_epoch):
    check_exact_keys(
        document,
        [
            "schema",
            "campaign_id",
            "topology",
            "artifacts",
            "configuration",
            "plan_sha256",
            "started_epoch_seconds",
            "finished_epoch_seconds",
            "phases",
            "bounds",
            "outcome",
        ],
        "document",
    )
    if document["schema"] != SCHEMA:
        reject("schema is not {}".format(SCHEMA))
    check_string(document["campaign_id"], "campaign_id")

    topology = document["topology"]
    check_exact_keys(
        topology, ["members", "cluster", "failure_budget_unavailable"], "topology"
    )
    members = check_bool_free_int(topology["members"], "topology.members")
    if members not in (3, 5):
        reject("topology.members is not a supported quorum size")
    check_string(topology["cluster"], "topology.cluster")
    budget = check_bool_free_int(
        topology["failure_budget_unavailable"], "topology.failure_budget_unavailable"
    )
    if budget != (members - 1) // 2:
        reject("failure budget is not floor((members - 1) / 2)")

    artifacts = document["artifacts"]
    check_exact_keys(
        artifacts,
        [
            "test_binary_sha256",
            "checker_path",
            "checker_sha256",
            "trust_anchor_digests",
        ],
        "artifacts",
    )
    test_binary_digest = artifacts["test_binary_sha256"]
    if test_binary_digest is not None:
        check_digest(test_binary_digest, "artifacts.test_binary_sha256")
    if artifacts["checker_path"] != CHECKER_PATH:
        reject("artifacts.checker_path is not the pinned checker path")
    check_digest(artifacts["checker_sha256"], "artifacts.checker_sha256")
    if artifacts["checker_sha256"] != self_digest():
        reject("checker provenance digest does not match the running checker")
    trust_anchor_digests = artifacts["trust_anchor_digests"]
    if (
        not isinstance(trust_anchor_digests, list)
        or not 1 <= len(trust_anchor_digests) <= 3
    ):
        reject("artifacts.trust_anchor_digests is not a bounded non-empty array")
    for digest in trust_anchor_digests:
        check_digest(digest, "artifacts.trust_anchor_digests entry")
    if trust_anchor_digests != sorted(set(trust_anchor_digests)):
        reject("artifacts.trust_anchor_digests is not sorted and unique")

    configuration = document["configuration"]
    check_exact_keys(configuration, ["lifecycle", "timing_profile"], "configuration")
    check_exact_keys(configuration["lifecycle"], EXPECTED_LIFECYCLE.keys(), "lifecycle")
    for key, expected in EXPECTED_LIFECYCLE.items():
        value = check_bool_free_int(configuration["lifecycle"][key], f"lifecycle.{key}")
        if value != expected:
            reject(f"lifecycle.{key} is not the pinned qualification value {expected}")
    check_exact_keys(
        configuration["timing_profile"], EXPECTED_TIMING_PROFILE.keys(), "timing_profile"
    )
    for key, expected in EXPECTED_TIMING_PROFILE.items():
        value = check_bool_free_int(
            configuration["timing_profile"][key], f"timing_profile.{key}"
        )
        if value != expected:
            reject(f"timing_profile.{key} is not the pinned profile value {expected}")

    check_digest(document["plan_sha256"], "plan_sha256")
    started = check_bool_free_int(document["started_epoch_seconds"], "started_epoch_seconds")
    finished = check_bool_free_int(
        document["finished_epoch_seconds"], "finished_epoch_seconds"
    )
    if finished < started:
        reject("finished_epoch_seconds precedes started_epoch_seconds")
    if finished > now_epoch + FRESHNESS_AHEAD_SECONDS:
        reject("evidence is from the future")
    if finished < now_epoch - FRESHNESS_BEHIND_SECONDS:
        reject("evidence is stale")

    phases = document["phases"]
    if not isinstance(phases, list) or not phases:
        reject("phases is not a non-empty array")
    if plan_digest(document) != document["plan_sha256"]:
        reject("plan digest does not match the recorded phase plan")

    previous_generation = None
    traffic_phases = 0
    for index, phase in enumerate(phases):
        check_exact_keys(
            phase,
            [
                "name",
                "kind",
                "member",
                "canary_generation",
                "fresh_handshake_paths",
                "ready_members",
                "duration_millis",
                "completed_epoch_seconds",
            ],
            f"phase {index}",
        )
        check_string(phase["name"], f"phase {index} name")
        kind = phase["kind"]
        if kind not in PHASE_KINDS:
            reject(f"phase {index} kind is not a closed enumeration value")
        member = phase["member"]
        if member is not None:
            check_bool_free_int(member, f"phase {index} member", 0, members - 1)
        generation = check_bool_free_int(
            phase["canary_generation"], f"phase {index} canary_generation", 1
        )
        check_bool_free_int(
            phase["fresh_handshake_paths"],
            f"phase {index} fresh_handshake_paths",
            0,
            members * (members - 1),
        )
        ready = phase["ready_members"]
        if not isinstance(ready, list):
            reject(f"phase {index} ready_members is not an array")
        if len(set(ready)) != len(ready):
            reject(f"phase {index} ready_members has duplicates")
        for voter in ready:
            check_bool_free_int(voter, f"phase {index} ready member", 0, members - 1)
        duration = check_bool_free_int(phase["duration_millis"], f"phase {index} duration_millis")
        if duration > phase_slo_millis(kind, members):
            reject(
                f"phase {index} ({kind}) exceeded its {phase_slo_millis(kind, members)} ms SLO"
            )
        completed = check_bool_free_int(
            phase["completed_epoch_seconds"], f"phase {index} completed_epoch_seconds"
        )
        if completed < started or completed > finished:
            reject(f"phase {index} completed outside the campaign window")

        if previous_generation is None:
            if generation != 1:
                reject("the first phase does not seed the canary at generation 1")
        elif kind == "traffic":
            if generation != previous_generation + 1:
                reject(
                    f"traffic phase {index} does not advance the acknowledged canary by exactly one"
                )
            traffic_phases += 1
        elif generation != previous_generation:
            reject(f"non-traffic phase {index} changed the canary generation")
        previous_generation = generation
    if previous_generation is None or traffic_phases == 0:
        reject("the campaign records no traffic beyond the seed")

    bounds = document["bounds"]
    check_exact_keys(
        bounds,
        [
            "fd_growth",
            "fd_allowance",
            "max_transition_resolver_deltas",
            "resolver_delta_allowance",
            "max_path_total_resolver_deltas",
            "path_total_allowance",
            "final_quiet_window_deltas",
            "authentication_failure_outcomes",
            "rejected_reload_retentions",
        ],
        "bounds",
    )
    fd_growth = bounds["fd_growth"]
    if fd_growth is not None:
        check_bool_free_int(fd_growth, "bounds.fd_growth")
    fd_allowance = check_bool_free_int(bounds["fd_allowance"], "bounds.fd_allowance")
    if fd_allowance > FD_ALLOWANCE_MAX:
        reject("fd_allowance exceeds the approved bound")
    if fd_growth is not None and fd_growth > fd_allowance:
        reject("observed descriptor growth exceeds the declared allowance")
    check_bool_free_int(
        bounds["max_transition_resolver_deltas"], "bounds.max_transition_resolver_deltas"
    )
    resolver_allowance = check_bool_free_int(
        bounds["resolver_delta_allowance"], "bounds.resolver_delta_allowance"
    )
    if resolver_allowance > RESOLVER_DELTA_ALLOWANCE_MAX:
        reject("resolver_delta_allowance exceeds the approved bound")
    if bounds["max_transition_resolver_deltas"] > resolver_allowance:
        reject("observed per-transition handshake rate exceeds the declared allowance")
    check_bool_free_int(
        bounds["max_path_total_resolver_deltas"], "bounds.max_path_total_resolver_deltas"
    )
    path_total_allowance = check_bool_free_int(
        bounds["path_total_allowance"], "bounds.path_total_allowance"
    )
    if path_total_allowance > PATH_TOTAL_ALLOWANCE_MAX:
        reject("path_total_allowance exceeds the approved bound")
    if bounds["max_path_total_resolver_deltas"] > path_total_allowance:
        reject("observed per-path campaign handshake total exceeds the declared allowance")
    if bounds["final_quiet_window_deltas"] != 0:
        reject("a lane redialed after the campaign settled")
    if bounds["authentication_failure_outcomes"] != 0:
        reject("the campaign recorded an authentication failure outcome")
    check_bool_free_int(
        bounds["rejected_reload_retentions"], "bounds.rejected_reload_retentions"
    )

    if document["outcome"] != "pass":
        reject("outcome is not pass; only passing campaigns produce valid evidence")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", help="path to the evidence JSON document")
    parser.add_argument(
        "--now-epoch",
        type=int,
        default=int(time.time()),
        help="freshness reference in seconds since the UTC epoch",
    )
    args = parser.parse_args()
    try:
        document = load_bounded_document(args.evidence)
        validate(document, args.now_epoch)
    except Reject as error:
        print(f"reject: {error}", file=sys.stderr)
        return 1
    except (KeyError, TypeError, IndexError, AttributeError, ValueError) as error:
        # Structurally invalid input fails closed with a diagnostic, never a
        # traceback that could be mistaken for a checker malfunction.
        print(f"reject: structurally invalid document ({error!r})", file=sys.stderr)
        return 1
    print(f"ok: {document['campaign_id']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
