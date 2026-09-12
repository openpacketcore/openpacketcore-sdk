//! Explicit test-control volatile storage with independent coalesced persistence.
//!
//! Foreground admission validates/publishes resident state and completes its
//! original storage callback. Real OpenRaft quorum and application still own
//! public completion. It never queues a WAL request or waits for disk progress.
//! One existing writer captures the existing native after-image journal at most
//! four times per second. The journal/scratch share the unchanged process-wide
//! 128 MiB reservation; no request-count queue exists. Resident rows retain the
//! native table/count/value bounds and are never evicted by this experiment.
//! Background generations are capped at 8 GiB per voter (below the original
//! per-voter database ceiling), covering the complete 1.01M workload. They are verified
//! after-image bytes, deliberately NOT a selected production recovery cut.
//! Original fs-verity snapshot creation remains asynchronous and unchanged.

use super::*;

const CAPTURE_INTERVAL: Duration = Duration::from_millis(250);
// The bounded measurement produced about437 MiB per98,496 outcomes. Eight
// GiB provides finite space for the original1.01M workload and its preload.
pub(super) const MAX_GENERATION_BYTES: u64 = 8 * 1024 * 1024 * 1024;

pub(super) struct Observation {
    activation_sequence: u64,
    acknowledged_requests: u64,
    generation: u64,
    persisted_generation: u64,
    captured_generation: Option<u64>,
    persisted_sequence: u64,
    persisted_committed: Option<LogId<SessionConsensusNodeId>>,
    persisted_applied: Option<LogId<SessionConsensusNodeId>>,
    dirty_wal_equivalent_bytes: u64,
    maximum_dirty_wal_equivalent_bytes: u64,
    background_captures: u64,
    background_bytes: u64,
    background_elapsed: Duration,
    background_maximum: Duration,
    capture_maximum: Duration,
    snapshots: u64,
    background_error: Option<String>,
}

impl Wal {
    pub(crate) fn enable_volatile_memory_experiment_for_test(&self) -> io::Result<()> {
        let mut state = lock_state(&self.shared)?;
        if state.status != Status::Running || state.native.is_none() {
            return Err(invalid_data(
                "volatile experiment requires a running native voter",
            ));
        }
        if state.volatile_experiment.is_some() {
            return Err(invalid_data("volatile experiment was already enabled"));
        }
        state.volatile_experiment = Some(Observation {
            activation_sequence: state.sequence,
            acknowledged_requests: 0,
            generation: 1,
            persisted_generation: 0,
            captured_generation: None,
            persisted_sequence: state.base_sequence,
            persisted_committed: state.durable_committed,
            persisted_applied: state.authority.frozen_applied,
            dirty_wal_equivalent_bytes: 0,
            maximum_dirty_wal_equivalent_bytes: 0,
            background_captures: 0,
            background_bytes: 0,
            background_elapsed: Duration::ZERO,
            background_maximum: Duration::ZERO,
            capture_maximum: Duration::ZERO,
            snapshots: 0,
            background_error: None,
        });
        self.shared.ready.notify_all();
        Ok(())
    }
}

pub(super) fn dirty(state: &mut State) {
    if let Some(observation) = &mut state.volatile_experiment {
        // Saturation cannot authorize a different state: exhaustion is beyond
        // the ordinary u64 operation lifetime. The next admission rejects it.
        observation.generation = observation.generation.saturating_add(1);
    }
}

pub(super) fn admit(
    wal: &Wal,
    state: &mut State,
    operation: &Operation,
    mut completion: Completion,
    charge: usize,
) -> io::Result<()> {
    if state.status != Status::Running || state.snapshot.is_some() || state.native_install_pending {
        return Err(io::Error::other("volatile native owner unavailable"));
    }
    let sequence = state
        .sequence
        .checked_add(1)
        .ok_or_else(|| invalid_data("volatile operation sequence exhausted"))?;
    if state
        .volatile_experiment
        .as_ref()
        .is_none_or(|value| value.generation == u64::MAX)
    {
        return Err(invalid_data("volatile generation exhausted"));
    }
    application::project_operation(state, wal.binding, operation)?;
    state.sequence = sequence;
    dirty(state);
    if let Some(observation) = &mut state.volatile_experiment {
        observation.acknowledged_requests += 1;
        observation.dirty_wal_equivalent_bytes = observation
            .dirty_wal_equivalent_bytes
            .saturating_add(charge as u64);
        observation.maximum_dirty_wal_equivalent_bytes = observation
            .maximum_dirty_wal_equivalent_bytes
            .max(observation.dirty_wal_equivalent_bytes);
    }
    // No pending callback, operation buffer, WAL sequence or byte charge is
    // transferred to the background writer. The resident journal owns changes.
    completion.finish(Ok(sequence));
    wal.shared.ready.notify_all();
    Ok(())
}

pub(super) fn snapshot_published(state: &mut State) {
    if let Some(observation) = &mut state.volatile_experiment {
        observation.snapshots += 1;
    }
    dirty(state);
}

pub(super) fn write_loop(
    shared: &Arc<Shared>,
    basis: &mut native_basis::Owner,
    binding: Binding,
    control: &IoControl,
) -> io::Result<()> {
    let mut next_capture = Instant::now() + CAPTURE_INTERVAL;
    loop {
        let mut state = lock_state(shared)?;
        loop {
            ensure_readable(&state)?;
            let observation = state
                .volatile_experiment
                .as_ref()
                .ok_or_else(|| invalid_data("volatile writer lost its mode"))?;
            let dirty = observation.generation != observation.persisted_generation;
            let failed = observation.background_error.is_some();
            if state.status != Status::Running {
                if !dirty || failed {
                    state.status = Status::Closed;
                    shared.ready.notify_all();
                    return Ok(());
                }
                break;
            }
            if dirty && !failed && Instant::now() >= next_capture {
                break;
            }
            if !dirty || failed {
                state = shared
                    .ready
                    .wait(state)
                    .map_err(|_| io::Error::other("volatile background wait poisoned"))?;
            } else {
                state = shared
                    .ready
                    .wait_timeout(
                        state,
                        next_capture.saturating_duration_since(Instant::now()),
                    )
                    .map_err(|_| io::Error::other("volatile background schedule poisoned"))?
                    .0;
            }
        }
        let capture_started = Instant::now();
        let sequence = state.sequence;
        let native = state
            .native
            .as_mut()
            .ok_or_else(|| invalid_data("volatile capture owner missing"))?;
        let committed = native.log.committed;
        let applied = native.business.applied();
        let changes = native.take_changes()?;
        let observation = state
            .volatile_experiment
            .as_mut()
            .ok_or_else(|| invalid_data("volatile capture observation missing"))?;
        let generation = observation.generation;
        observation.captured_generation = Some(generation);
        observation.dirty_wal_equivalent_bytes = 0;
        observation.capture_maximum = observation.capture_maximum.max(capture_started.elapsed());
        drop(state);
        // All encoding, verification, file writes and fsync run with no State
        // guard. Admissions/applications do not consult this writer's progress.
        let started = Instant::now();
        next_capture = started + CAPTURE_INTERVAL;
        let result = basis.persist_volatile(changes, binding, generation, sequence, control);
        let elapsed = started.elapsed();
        let mut state = lock_state(shared)?;
        let observation = state
            .volatile_experiment
            .as_mut()
            .ok_or_else(|| invalid_data("volatile publication observation missing"))?;
        observation.captured_generation = None;
        observation.background_elapsed += elapsed;
        observation.background_maximum = observation.background_maximum.max(elapsed);
        match result {
            Ok(bytes) => {
                observation.background_captures += 1;
                observation.background_bytes = bytes;
                observation.persisted_generation = generation;
                observation.persisted_sequence = sequence;
                observation.persisted_committed = committed;
                observation.persisted_applied = applied;
            }
            Err(error) => {
                // Volatile resident state remains authoritative. Retain and
                // disclose a stopped persistence lane; never replay or claim
                // this captured generation persisted after an I/O failure.
                observation.background_error = Some(error.to_string());
            }
        }
        shared.ready.notify_all();
    }
}

pub(super) fn observe(state: &State, mut value: serde_json::Value) -> serde_json::Value {
    let Some(observation) = &state.volatile_experiment else {
        return value;
    };
    value["volatile_experiment"] = serde_json::json!({
        "acknowledgment": "resident_admission_then_real_quorum_and_apply",
        "cold_restart_durability": false,
        "background_wal_and_snapshots": false,
        "background_native_generations_and_snapshots": true,
        "persistence": "coalesced_native_after_images_without_CURRENT_selection_or_resident_eviction",
        "activation_sequence": observation.activation_sequence,
        "acknowledged_requests": observation.acknowledged_requests,
        "per_operation_background_queue_capacity": 0,
        "foreground_background_capacity_waits": 0,
        "journal_and_verification_process_limit_bytes": 128 * 1024 * 1024,
        "maximum_active_background_captures_per_voter": 1,
        "minimum_capture_interval_ms": CAPTURE_INTERVAL.as_millis(),
        "maximum_background_generation_bytes_per_voter": MAX_GENERATION_BYTES,
        "outstanding_pre_activation_wal_requests": state.outstanding,
        "outstanding_pre_activation_wal_bytes": state.outstanding_bytes,
        "generation": observation.generation,
        "persisted_generation": observation.persisted_generation,
        "captured_generation": observation.captured_generation,
        "persisted_operation_sequence": observation.persisted_sequence,
        "resident_operation_sequence": state.sequence,
        "dirty_wal_equivalent_bytes": observation.dirty_wal_equivalent_bytes,
        "maximum_dirty_wal_equivalent_bytes": observation.maximum_dirty_wal_equivalent_bytes,
        "background_captures": observation.background_captures,
        "background_bytes": observation.background_bytes,
        "background_elapsed_us": observation.background_elapsed.as_micros(),
        "background_maximum_us": observation.background_maximum.as_micros(),
        "resident_capture_maximum_us": observation.capture_maximum.as_micros(),
        "background_error": observation.background_error,
        "snapshot_publications": observation.snapshots,
        "resident_committed_index": state.native.as_ref().and_then(|native| native.log.committed).map(|id| id.index),
        "last_durable_wal_committed_index": state.durable_committed.map(|id| id.index),
        "persisted_generation_committed_index": observation.persisted_committed.map(|id| id.index),
        "persisted_generation_applied_index": observation.persisted_applied.map(|id| id.index),
        "resident_applied_index": state.native.as_ref().and_then(|native| native.business.applied()).map(|id| id.index),
    });
    if let Some(object) = value.as_object_mut() {
        if let Some(total) = object.remove("submit_to_callback_us") {
            object.insert("pre_activation_submit_to_wal_publication_us".into(), total);
        }
        if let Some(slowest) = object
            .get_mut("slowest_request")
            .and_then(|item| item.as_object_mut())
        {
            if let Some(total) = slowest.remove("submit_to_callback_us") {
                slowest.insert("pre_activation_submit_to_wal_publication_us".into(), total);
            }
        }
    }
    value
}
