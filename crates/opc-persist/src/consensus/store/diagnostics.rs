//! Observation-only diagnostics, compiled only for tests or explicit test control.

use std::fmt;
use std::io::Write;

use opc_consensus::engine::Vote;
use tokio::time::Instant;

use super::*;

pub(super) struct DeadlineDiagnostic {
    name: &'static str,
    started: Instant,
    wall_started: std::time::Instant,
    pub(super) stage: &'static str,
    pub(super) deadline: Option<Instant>,
}

impl DeadlineDiagnostic {
    pub(super) fn new(name: &'static str, stage: &'static str) -> Self {
        Self {
            name,
            started: Instant::now(),
            wall_started: std::time::Instant::now(),
            stage,
            deadline: None,
        }
    }

    pub(super) fn emit(&self, details: fmt::Arguments<'_>) {
        let now = Instant::now();
        // A diagnostic write failure must never replace the typed result.
        let _ = writeln!(
            std::io::stderr().lock(),
            "{}: stage={} elapsed={:?} wall_elapsed={:?} deadline={:?} remaining={:?} overdue={:?} expired={:?} {}",
            self.name,
            self.stage,
            now.saturating_duration_since(self.started),
            self.wall_started.elapsed(),
            self.deadline,
            self.deadline.map(|deadline| deadline.saturating_duration_since(now)),
            self.deadline.map(|deadline| now.saturating_duration_since(deadline)),
            self.deadline.map(|deadline| now >= deadline),
            details,
        );
    }
}

pub(super) struct ShutdownDiagnostic {
    pub(super) timing: DeadlineDiagnostic,
    pub(super) successor: Option<ConsensusNodeId>,
    pub(super) from_term: Option<u64>,
    pub(super) required_log: Option<LogId<ConsensusNodeId>>,
    pub(super) successor_vote: Option<Vote<ConsensusNodeId>>,
    pub(super) read_state: &'static str,
    pub(super) read_reply: Option<ReadBarrierReply>,
    pub(super) read_error: Option<crate::PersistErrorKind>,
    pub(super) current_matches: Option<bool>,
}

impl ShutdownDiagnostic {
    pub(super) fn new(deadline: Instant) -> Self {
        let mut timing = DeadlineDiagnostic::new("config_consensus_shutdown", "recovery-drain");
        timing.deadline = Some(deadline);
        Self {
            timing,
            successor: None,
            from_term: None,
            required_log: None,
            successor_vote: None,
            read_state: "not-attempted",
            read_reply: None,
            read_error: None,
            current_matches: None,
        }
    }

    pub(super) fn emit(
        &self,
        store: &ConsensusConfigStore,
        result: &Result<
            opc_consensus::PlannedShutdownOutcome,
            opc_consensus::PlannedShutdownFallback,
        >,
        outer_timeout: bool,
    ) {
        let metrics = store.inner.raft.metrics();
        self.timing.emit(format_args!(
            "node={:?} preparation_timeout={:?} result={:?} outer_timeout={} successor={:?} from_term={:?} required_log={:?} successor_vote={:?} read_state={} read_reply={:?} read_error={:?} current_matches={:?} committed_index={:?} metrics={:?}",
            store.inner.local_node_id,
            opc_consensus::planned_shutdown_timeout(store.inner.operation_timeout),
            result,
            outer_timeout,
            self.successor,
            self.from_term,
            self.required_log,
            self.successor_vote,
            self.read_state,
            self.read_reply,
            self.read_error,
            self.current_matches,
            store.inner.durable_progress.committed_index(),
            *metrics.borrow(),
        ));
    }
}
