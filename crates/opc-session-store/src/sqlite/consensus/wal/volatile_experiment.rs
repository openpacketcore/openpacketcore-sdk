//! Explicit benchmark-only volatile storage model, compiled with test-control.
//!
//! Ordinary construction leaves this mode absent. An integration benchmark
//! must enable it on each live native voter before its offered workload.
//! Successful storage completion then means resident ordered admission, not
//! disk persistence. OpenRaft still replicates to its real quorum and returns
//! real applied results. Cold-crash recovery is outside this experiment.
//!
//! The existing bounded writer, snapshots and retention backpressure remain.
//! This models volatile acknowledgments with background persistence; it is
//! not a claim that all file/lock dependencies have disappeared.

use super::{invalid_data, lock_state, Completion, State, Status, Wal};
use std::io;

pub(super) struct Observation {
    activation_sequence: u64,
    acknowledged_requests: u64,
    maximum_outstanding_requests: usize,
    maximum_outstanding_bytes: usize,
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
            maximum_outstanding_requests: state.outstanding,
            maximum_outstanding_bytes: state.outstanding_bytes,
        });
        Ok(())
    }
}

pub(super) fn complete_admission(
    state: &mut State,
    mut completion: Completion,
    sequence: u64,
) -> Completion {
    if let Some(observation) = &mut state.volatile_experiment {
        observation.acknowledged_requests += 1;
        observation.maximum_outstanding_requests = observation
            .maximum_outstanding_requests
            .max(state.outstanding);
        observation.maximum_outstanding_bytes = observation
            .maximum_outstanding_bytes
            .max(state.outstanding_bytes);
        // Projection and bounds have succeeded under the same owner mutex.
        // The queued request retains its ordinary writer lifetime and charge,
        // but no longer owns a pending storage callback or metadata receiver.
        completion.finish(Ok(sequence));
    }
    completion
}

pub(super) fn observe(state: &State, mut value: serde_json::Value) -> serde_json::Value {
    let Some(observation) = &state.volatile_experiment else {
        return value;
    };
    value["volatile_experiment"] = serde_json::json!({
        "acknowledgment": "resident_admission_then_real_quorum_and_apply",
        "cold_restart_durability": false,
        "background_wal_and_snapshots": true,
        "activation_sequence": observation.activation_sequence,
        "acknowledged_requests": observation.acknowledged_requests,
        "outstanding_requests": state.outstanding,
        "outstanding_bytes": state.outstanding_bytes,
        "maximum_outstanding_requests": observation.maximum_outstanding_requests,
        "maximum_outstanding_bytes": observation.maximum_outstanding_bytes,
        "resident_committed_index": state.native.as_ref().and_then(|native| native.log.committed).map(|id| id.index),
        "durable_committed_index": state.durable_committed.map(|id| id.index),
        "resident_applied_index": state.native.as_ref().and_then(|native| native.business.applied()).map(|id| id.index),
    });
    // These pre-existing writer timings end at disk publication, which is
    // no longer the experimental callback boundary. Label them accordingly.
    if let Some(object) = value.as_object_mut() {
        if let Some(total) = object.remove("submit_to_callback_us") {
            object.insert("submit_to_background_publication_us".into(), total);
        }
        if let Some(slowest) = object
            .get_mut("slowest_request")
            .and_then(|item| item.as_object_mut())
        {
            if let Some(total) = slowest.remove("submit_to_callback_us") {
                slowest.insert("submit_to_background_publication_us".into(), total);
            }
        }
    }
    value
}
