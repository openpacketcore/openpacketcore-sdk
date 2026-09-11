//! Public persistence selection and passive local health observations.

use serde::Serialize;

/// Storage acknowledgement policy selected when constructing a fixed quorum.
///
/// The choice is independent of snapshot integrity. Every voter in one quorum
/// must use the same policy. Existing durable constructors retain `Durable`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub enum SessionPersistenceMode {
    /// Acknowledgements retain the durable log, quorum and application boundary.
    #[default]
    Durable,
    /// Acknowledgements follow validated resident storage, quorum replication
    /// and application. Background persistence may lag acknowledged results.
    /// Loss of the volatile quorum can lose those results; a completed local
    /// generation alone is not proof of current quorum authority.
    Async,
}

/// Current lifecycle of the local native storage owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum SessionStorageState {
    /// The owner accepts work.
    Running,
    /// The owner is joining accepted work during shutdown.
    Draining,
    /// The owner has finished shutdown.
    Closed,
    /// A storage failure fenced this owner.
    Failed,
    /// Native storage is absent or its state could not be observed.
    Unavailable,
}

/// Fixed category of the operation which first fenced native storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum SessionStorageFailureStage {
    /// A storage invariant outside a more specific recorded stage failed.
    Storage,
    /// The persistence writer failed.
    Persistence,
    /// Native snapshot capture or export failed.
    SnapshotExport,
    /// Installation of an authenticated snapshot failed.
    SnapshotInstall,
    /// State-machine application failed.
    Application,
}

/// Redaction-safe category of a storage error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum SessionStorageFailureKind {
    /// Invalid data or an ownership/lineage invariant.
    InvalidData,
    /// An operation reached its I/O deadline.
    TimedOut,
    /// The operating system or a bounded allocator refused memory.
    OutOfMemory,
    /// Storage refused additional capacity, including a SQLite page limit.
    /// This category alone does not identify an exhausted filesystem.
    StorageFull,
    /// An operation was interrupted.
    Interrupted,
    /// A worker unwound unexpectedly.
    Panicked,
    /// Another I/O or storage error; no more specific category was retained.
    Other,
}

/// First recorded storage fence, without paths, payloads or raw error text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SessionStorageFailure {
    /// The stage which observed the original failure.
    pub stage: SessionStorageFailureStage,
    /// Fixed category of that failure.
    pub kind: SessionStorageFailureKind,
    /// Original operating-system error number, when supplied by the OS.
    pub os_error: Option<i32>,
}

#[cfg(target_os = "linux")]
impl SessionStorageFailure {
    pub(crate) fn from_io(stage: SessionStorageFailureStage, error: &std::io::Error) -> Self {
        let kind = match error.kind() {
            std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput => {
                SessionStorageFailureKind::InvalidData
            }
            std::io::ErrorKind::TimedOut => SessionStorageFailureKind::TimedOut,
            std::io::ErrorKind::OutOfMemory => SessionStorageFailureKind::OutOfMemory,
            std::io::ErrorKind::StorageFull => SessionStorageFailureKind::StorageFull,
            std::io::ErrorKind::Interrupted => SessionStorageFailureKind::Interrupted,
            _ => SessionStorageFailureKind::Other,
        };
        Self {
            stage,
            kind,
            os_error: error.raw_os_error(),
        }
    }

    pub(crate) const fn panic(stage: SessionStorageFailureStage) -> Self {
        Self {
            stage,
            kind: SessionStorageFailureKind::Panicked,
            os_error: None,
        }
    }
}

/// Passive local observation, never a quorum/readiness or durability proof.
///
/// Engine and storage observations can race subsequent work. Authoritative
/// operations still perform their own admission and quorum checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SessionPersistenceHealth {
    /// Configured acknowledgement policy.
    pub mode: SessionPersistenceMode,
    /// Whether the local consensus engine reports a running state.
    pub engine_running: bool,
    /// Current native storage lifecycle.
    pub storage_state: SessionStorageState,
    /// First recorded native storage fence, if any.
    pub storage_failure: Option<SessionStorageFailure>,
    /// Background progress for `Async`; absent for a durable owner.
    pub asynchronous: Option<SessionAsyncPersistenceProgress>,
    /// Cold-voter admission posture for `Async`; absent for durable storage.
    pub recovery: Option<SessionAsyncRecoveryState>,
}

/// Local asynchronous voter admission, independent of background disk lag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum SessionAsyncRecoveryState {
    /// A fresh member or a caught-up member may participate in consensus.
    /// Application traffic still needs the ordinary exact quorum checks.
    Active,
    /// An existing root awaits a new commit by a surviving live quorum.
    /// Votes, elections and replication acknowledgements are withheld.
    AwaitingLiveQuorum,
    /// A live quorum supplied a fresh cut; only its leader may repair this
    /// member. Votes, elections and application traffic remain withheld.
    CatchingUp,
}

/// Passive progress of the single coalescing background persistence owner.
/// A completed generation is selected for local reopen; these counters do
/// not grant quorum, traffic, or Recovery authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SessionAsyncPersistenceProgress {
    /// Current resident change generation.
    pub resident_generation: u64,
    /// Latest verified generation whose durable selector completed.
    pub completed_generation: u64,
    /// The one detached generation being prepared, if any.
    pub captured_generation: Option<u64>,
    /// Current resident storage sequence.
    pub resident_sequence: u64,
    /// Storage sequence covered by the completed generation.
    pub completed_sequence: u64,
    /// Local committed log index covered by that generation.
    pub completed_committed_index: Option<u64>,
    /// Local applied log index covered by that generation.
    pub completed_applied_index: Option<u64>,
    /// Milliseconds since persistence last covered all resident changes.
    pub lag_millis: u64,
    /// Bytes in the latest completed generation's verified prefix.
    pub completed_bytes: u64,
    /// Finite per-voter generation extent limit.
    pub generation_limit_bytes: u64,
    /// Whether the background lane exhausted its bounded resources.
    pub saturated: bool,
    /// First background failure, without paths, payloads, or raw error text.
    pub background_failure: Option<SessionStorageFailure>,
}

/// Failure to complete an explicitly requested local Async persistence cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionPersistenceDrainError {
    /// The store uses the durable acknowledgement policy.
    #[error("asynchronous persistence is not selected")]
    NotAsync,
    /// The local native storage owner is unavailable or no longer running.
    #[error("local persistence owner is unavailable")]
    Unavailable,
    /// A background or storage failure prevents the requested drain.
    #[error("local persistence failed")]
    Failed(SessionStorageFailure),
    /// The original operation deadline elapsed; the writer retains its work.
    #[error("local persistence drain deadline elapsed")]
    DeadlineExceeded,
}
