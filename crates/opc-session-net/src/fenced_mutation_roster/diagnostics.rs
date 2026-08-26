//! Fixed-cardinality, process-local diagnostics for protected rosters.
//!
//! This module deliberately retains only numeric aggregates.  It neither
//! accepts nor stores caller, authority, roster, member, provider, or backend
//! identifiers.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

const LATENCY_BUCKETS: usize = 16;

/// Numeric, nonidentifying protected-roster diagnostics.
///
/// Every field is process-local. `roster_width` contains one counter for each
/// accepted immutable roster width from one through eight, in that order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FencedMutationRosterDiagnostics {
    /// Admission mutations sent to the consensus adapter.
    pub admission_calls: u64,
    /// Admissions proven not to have crossed transport.
    pub admission_not_transmitted: u64,
    /// Admissions whose transport result was ambiguous.
    pub admission_outcome_unknown: u64,
    /// Admissions with a conclusive adapter reply.
    pub admission_conclusive: u64,
    /// Exact readbacks for an ambiguous admission.
    pub admission_status_calls: u64,
    /// Successor recovery reads.
    pub recovery_calls: u64,
    /// Exact prepared-terminal status reads.
    pub terminal_status_calls: u64,
    /// Member prepare provider calls.
    pub member_prepare_calls: u64,
    /// Member execute provider calls.
    pub member_execute_calls: u64,
    /// Member status provider calls.
    pub member_status_calls: u64,
    /// Member adoption provider calls.
    pub member_adopt_calls: u64,
    /// Member compensation provider calls.
    pub member_compensate_calls: u64,
    /// Conclusive member provider observations.
    pub member_conclusive: u64,
    /// Member observations that remain ready for a first prepare attempt.
    pub member_ready_to_prepare: u64,
    /// Member observations that retain a prepared, not-yet-run state.
    pub member_prepared_not_run: u64,
    /// Member provider calls proven not to have transmitted.
    pub member_not_transmitted: u64,
    /// Member provider observations requiring recovery.
    pub member_ambiguous: u64,
    /// Member calls refused by the fixed process-wide provider gate.
    pub member_provider_busy: u64,
    /// Local terminal preparation attempts.
    pub terminal_prepare_calls: u64,
    /// Atomic terminal mutations sent to the consensus adapter.
    pub terminalize_calls: u64,
    /// Terminal mutations proven not to have crossed transport.
    pub terminalize_not_transmitted: u64,
    /// Terminal mutations whose outcome must be read back.
    pub terminalize_outcome_unknown: u64,
    /// Exact terminal replies whose protected payload was already compacted.
    pub terminal_payload_compacted: u64,
    /// Committed or replayed established terminal receipts.
    pub terminalize_committed_established: u64,
    /// Committed or replayed aborted terminal receipts.
    pub terminalize_committed_aborted: u64,
    /// Terminal replies that conflict with the prepared body.
    pub terminalize_conflict: u64,
    /// Publication provider status calls.
    pub publication_status_calls: u64,
    /// Publication provider begin-intent calls.
    pub publication_begin_calls: u64,
    /// Publication provider adoption calls.
    pub publication_adopt_calls: u64,
    /// Publication begin-intent calls proven not to have transmitted.
    pub publication_begin_not_transmitted: u64,
    /// Validated publication acknowledgements.
    pub publication_acknowledged: u64,
    /// Publication observations or validation failures requiring recovery.
    pub publication_recovery_required: u64,
    /// Publication provider payload conflicts.
    pub publication_conflict: u64,
    /// Publication calls refused by the fixed process-wide provider gate.
    pub publication_provider_busy: u64,
    /// Provider calls currently inside a member or publication provider boundary.
    pub provider_in_flight: u64,
    /// Largest observed concurrent provider call count.
    pub provider_in_flight_max: u64,
    /// Accepted admission widths, indexed by roster width minus one (one through eight).
    pub roster_width: [u64; 8],
    /// Admission mutation round-trip latency, logarithmic millisecond buckets.
    /// Bucket zero is below one millisecond; bucket `n` covers
    /// `[2^(n-1), 2^n)` milliseconds; the final bucket includes all larger values.
    pub admission_round_trip_latency_millis: [u64; LATENCY_BUCKETS],
    /// Terminal mutation round-trip latency, using the same buckets as admission.
    pub terminalize_round_trip_latency_millis: [u64; LATENCY_BUCKETS],
}

pub(crate) type RosterDiagnostics = Arc<RosterDiagnosticsInner>;

pub(crate) struct RosterDiagnosticsInner {
    admission_calls: AtomicU64,
    admission_not_transmitted: AtomicU64,
    admission_outcome_unknown: AtomicU64,
    admission_conclusive: AtomicU64,
    admission_status_calls: AtomicU64,
    recovery_calls: AtomicU64,
    terminal_status_calls: AtomicU64,
    member_prepare_calls: AtomicU64,
    member_execute_calls: AtomicU64,
    member_status_calls: AtomicU64,
    member_adopt_calls: AtomicU64,
    member_compensate_calls: AtomicU64,
    member_conclusive: AtomicU64,
    member_ready_to_prepare: AtomicU64,
    member_prepared_not_run: AtomicU64,
    member_not_transmitted: AtomicU64,
    member_ambiguous: AtomicU64,
    member_provider_busy: AtomicU64,
    terminal_prepare_calls: AtomicU64,
    terminalize_calls: AtomicU64,
    terminalize_not_transmitted: AtomicU64,
    terminalize_outcome_unknown: AtomicU64,
    terminal_payload_compacted: AtomicU64,
    terminalize_committed_established: AtomicU64,
    terminalize_committed_aborted: AtomicU64,
    terminalize_conflict: AtomicU64,
    publication_status_calls: AtomicU64,
    publication_begin_calls: AtomicU64,
    publication_adopt_calls: AtomicU64,
    publication_begin_not_transmitted: AtomicU64,
    publication_acknowledged: AtomicU64,
    publication_recovery_required: AtomicU64,
    publication_conflict: AtomicU64,
    publication_provider_busy: AtomicU64,
    provider_in_flight: AtomicU64,
    provider_in_flight_max: AtomicU64,
    roster_width: [AtomicU64; 8],
    admission_round_trip_latency_millis: [AtomicU64; LATENCY_BUCKETS],
    terminalize_round_trip_latency_millis: [AtomicU64; LATENCY_BUCKETS],
}

impl RosterDiagnosticsInner {
    pub(crate) fn new() -> RosterDiagnostics {
        Arc::new(Self {
            admission_calls: AtomicU64::new(0),
            admission_not_transmitted: AtomicU64::new(0),
            admission_outcome_unknown: AtomicU64::new(0),
            admission_conclusive: AtomicU64::new(0),
            admission_status_calls: AtomicU64::new(0),
            recovery_calls: AtomicU64::new(0),
            terminal_status_calls: AtomicU64::new(0),
            member_prepare_calls: AtomicU64::new(0),
            member_execute_calls: AtomicU64::new(0),
            member_status_calls: AtomicU64::new(0),
            member_adopt_calls: AtomicU64::new(0),
            member_compensate_calls: AtomicU64::new(0),
            member_conclusive: AtomicU64::new(0),
            member_ready_to_prepare: AtomicU64::new(0),
            member_prepared_not_run: AtomicU64::new(0),
            member_not_transmitted: AtomicU64::new(0),
            member_ambiguous: AtomicU64::new(0),
            member_provider_busy: AtomicU64::new(0),
            terminal_prepare_calls: AtomicU64::new(0),
            terminalize_calls: AtomicU64::new(0),
            terminalize_not_transmitted: AtomicU64::new(0),
            terminalize_outcome_unknown: AtomicU64::new(0),
            terminal_payload_compacted: AtomicU64::new(0),
            terminalize_committed_established: AtomicU64::new(0),
            terminalize_committed_aborted: AtomicU64::new(0),
            terminalize_conflict: AtomicU64::new(0),
            publication_status_calls: AtomicU64::new(0),
            publication_begin_calls: AtomicU64::new(0),
            publication_adopt_calls: AtomicU64::new(0),
            publication_begin_not_transmitted: AtomicU64::new(0),
            publication_acknowledged: AtomicU64::new(0),
            publication_recovery_required: AtomicU64::new(0),
            publication_conflict: AtomicU64::new(0),
            publication_provider_busy: AtomicU64::new(0),
            provider_in_flight: AtomicU64::new(0),
            provider_in_flight_max: AtomicU64::new(0),
            roster_width: std::array::from_fn(|_| AtomicU64::new(0)),
            admission_round_trip_latency_millis: std::array::from_fn(|_| AtomicU64::new(0)),
            terminalize_round_trip_latency_millis: std::array::from_fn(|_| AtomicU64::new(0)),
        })
    }

    pub(crate) fn snapshot(&self) -> FencedMutationRosterDiagnostics {
        FencedMutationRosterDiagnostics {
            admission_calls: load(&self.admission_calls),
            admission_not_transmitted: load(&self.admission_not_transmitted),
            admission_outcome_unknown: load(&self.admission_outcome_unknown),
            admission_conclusive: load(&self.admission_conclusive),
            admission_status_calls: load(&self.admission_status_calls),
            recovery_calls: load(&self.recovery_calls),
            terminal_status_calls: load(&self.terminal_status_calls),
            member_prepare_calls: load(&self.member_prepare_calls),
            member_execute_calls: load(&self.member_execute_calls),
            member_status_calls: load(&self.member_status_calls),
            member_adopt_calls: load(&self.member_adopt_calls),
            member_compensate_calls: load(&self.member_compensate_calls),
            member_conclusive: load(&self.member_conclusive),
            member_ready_to_prepare: load(&self.member_ready_to_prepare),
            member_prepared_not_run: load(&self.member_prepared_not_run),
            member_not_transmitted: load(&self.member_not_transmitted),
            member_ambiguous: load(&self.member_ambiguous),
            member_provider_busy: load(&self.member_provider_busy),
            terminal_prepare_calls: load(&self.terminal_prepare_calls),
            terminalize_calls: load(&self.terminalize_calls),
            terminalize_not_transmitted: load(&self.terminalize_not_transmitted),
            terminalize_outcome_unknown: load(&self.terminalize_outcome_unknown),
            terminal_payload_compacted: load(&self.terminal_payload_compacted),
            terminalize_committed_established: load(&self.terminalize_committed_established),
            terminalize_committed_aborted: load(&self.terminalize_committed_aborted),
            terminalize_conflict: load(&self.terminalize_conflict),
            publication_status_calls: load(&self.publication_status_calls),
            publication_begin_calls: load(&self.publication_begin_calls),
            publication_adopt_calls: load(&self.publication_adopt_calls),
            publication_begin_not_transmitted: load(&self.publication_begin_not_transmitted),
            publication_acknowledged: load(&self.publication_acknowledged),
            publication_recovery_required: load(&self.publication_recovery_required),
            publication_conflict: load(&self.publication_conflict),
            publication_provider_busy: load(&self.publication_provider_busy),
            provider_in_flight: load(&self.provider_in_flight),
            provider_in_flight_max: load(&self.provider_in_flight_max),
            roster_width: self.roster_width.each_ref().map(load),
            admission_round_trip_latency_millis: self
                .admission_round_trip_latency_millis
                .each_ref()
                .map(load),
            terminalize_round_trip_latency_millis: self
                .terminalize_round_trip_latency_millis
                .each_ref()
                .map(load),
        }
    }

    pub(crate) fn increment(&self, counter: Counter) {
        counter.atomic(self).fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn record_width(&self, width: usize) {
        if let Some(counter) = self.roster_width.get(width.saturating_sub(1)) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub(crate) fn record_latency(&self, latency: Latency, duration: Duration) {
        let milliseconds = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        let bucket = latency_bucket(milliseconds);
        latency.atomic(self)[bucket].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn provider_in_flight(self: &RosterDiagnostics) -> ProviderInFlight {
        let current = self
            .provider_in_flight
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let mut maximum = self.provider_in_flight_max.load(Ordering::Relaxed);
        while current > maximum {
            match self.provider_in_flight_max.compare_exchange_weak(
                maximum,
                current,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => maximum = observed,
            }
        }
        ProviderInFlight {
            diagnostics: Arc::clone(self),
        }
    }
}

fn load(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

pub(crate) struct ProviderInFlight {
    diagnostics: RosterDiagnostics,
}
impl Drop for ProviderInFlight {
    fn drop(&mut self) {
        self.diagnostics
            .provider_in_flight
            .fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Counter {
    AdmissionCalls,
    AdmissionNotTransmitted,
    AdmissionOutcomeUnknown,
    AdmissionConclusive,
    AdmissionStatusCalls,
    RecoveryCalls,
    TerminalStatusCalls,
    MemberPrepareCalls,
    MemberExecuteCalls,
    MemberStatusCalls,
    MemberAdoptCalls,
    MemberCompensateCalls,
    MemberConclusive,
    MemberReadyToPrepare,
    MemberPreparedNotRun,
    MemberNotTransmitted,
    MemberAmbiguous,
    MemberProviderBusy,
    TerminalPrepareCalls,
    TerminalizeCalls,
    TerminalizeNotTransmitted,
    TerminalizeOutcomeUnknown,
    TerminalPayloadCompacted,
    TerminalizeCommittedEstablished,
    TerminalizeCommittedAborted,
    TerminalizeConflict,
    PublicationStatusCalls,
    PublicationBeginCalls,
    PublicationAdoptCalls,
    PublicationBeginNotTransmitted,
    PublicationAcknowledged,
    PublicationRecoveryRequired,
    PublicationConflict,
    PublicationProviderBusy,
}
impl Counter {
    fn atomic(self, d: &RosterDiagnosticsInner) -> &AtomicU64 {
        match self {
            Self::AdmissionCalls => &d.admission_calls,
            Self::AdmissionNotTransmitted => &d.admission_not_transmitted,
            Self::AdmissionOutcomeUnknown => &d.admission_outcome_unknown,
            Self::AdmissionConclusive => &d.admission_conclusive,
            Self::AdmissionStatusCalls => &d.admission_status_calls,
            Self::RecoveryCalls => &d.recovery_calls,
            Self::TerminalStatusCalls => &d.terminal_status_calls,
            Self::MemberPrepareCalls => &d.member_prepare_calls,
            Self::MemberExecuteCalls => &d.member_execute_calls,
            Self::MemberStatusCalls => &d.member_status_calls,
            Self::MemberAdoptCalls => &d.member_adopt_calls,
            Self::MemberCompensateCalls => &d.member_compensate_calls,
            Self::MemberConclusive => &d.member_conclusive,
            Self::MemberReadyToPrepare => &d.member_ready_to_prepare,
            Self::MemberPreparedNotRun => &d.member_prepared_not_run,
            Self::MemberNotTransmitted => &d.member_not_transmitted,
            Self::MemberAmbiguous => &d.member_ambiguous,
            Self::MemberProviderBusy => &d.member_provider_busy,
            Self::TerminalPrepareCalls => &d.terminal_prepare_calls,
            Self::TerminalizeCalls => &d.terminalize_calls,
            Self::TerminalizeNotTransmitted => &d.terminalize_not_transmitted,
            Self::TerminalizeOutcomeUnknown => &d.terminalize_outcome_unknown,
            Self::TerminalPayloadCompacted => &d.terminal_payload_compacted,
            Self::TerminalizeCommittedEstablished => &d.terminalize_committed_established,
            Self::TerminalizeCommittedAborted => &d.terminalize_committed_aborted,
            Self::TerminalizeConflict => &d.terminalize_conflict,
            Self::PublicationStatusCalls => &d.publication_status_calls,
            Self::PublicationBeginCalls => &d.publication_begin_calls,
            Self::PublicationAdoptCalls => &d.publication_adopt_calls,
            Self::PublicationBeginNotTransmitted => &d.publication_begin_not_transmitted,
            Self::PublicationAcknowledged => &d.publication_acknowledged,
            Self::PublicationRecoveryRequired => &d.publication_recovery_required,
            Self::PublicationConflict => &d.publication_conflict,
            Self::PublicationProviderBusy => &d.publication_provider_busy,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Latency {
    AdmissionRoundTrip,
    TerminalizeRoundTrip,
}

impl Latency {
    fn atomic(self, d: &RosterDiagnosticsInner) -> &[AtomicU64; LATENCY_BUCKETS] {
        match self {
            Self::AdmissionRoundTrip => &d.admission_round_trip_latency_millis,
            Self::TerminalizeRoundTrip => &d.terminalize_round_trip_latency_millis,
        }
    }
}

fn latency_bucket(milliseconds: u64) -> usize {
    if milliseconds == 0 {
        return 0;
    }
    let bucket = (u64::BITS - milliseconds.leading_zeros()) as usize;
    bucket.min(LATENCY_BUCKETS - 1)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Counter, Latency, RosterDiagnosticsInner};

    #[test]
    fn snapshot_is_fixed_numeric_and_shared() {
        let diagnostics = RosterDiagnosticsInner::new();
        let clone = diagnostics.clone();
        diagnostics.increment(Counter::MemberCompensateCalls);
        diagnostics.increment(Counter::MemberReadyToPrepare);
        clone.increment(Counter::MemberPreparedNotRun);
        clone.increment(Counter::TerminalPayloadCompacted);
        clone.increment(Counter::PublicationAcknowledged);
        diagnostics.record_width(8);
        diagnostics.record_latency(Latency::AdmissionRoundTrip, Duration::ZERO);
        clone.record_latency(Latency::TerminalizeRoundTrip, Duration::from_millis(8));
        let first = diagnostics.provider_in_flight();
        let second = clone.provider_in_flight();
        let snapshot = clone.snapshot();
        assert_eq!(snapshot.member_compensate_calls, 1);
        assert_eq!(snapshot.member_conclusive, 0);
        assert_eq!(snapshot.member_ready_to_prepare, 1);
        assert_eq!(snapshot.member_prepared_not_run, 1);
        assert_eq!(snapshot.terminal_payload_compacted, 1);
        assert_eq!(snapshot.publication_acknowledged, 1);
        assert_eq!(snapshot.provider_in_flight, 2);
        assert_eq!(snapshot.provider_in_flight_max, 2);
        assert_eq!(snapshot.roster_width, [0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(snapshot.admission_round_trip_latency_millis[0], 1);
        assert_eq!(snapshot.terminalize_round_trip_latency_millis[4], 1);
        let exported = format!("{snapshot:?}");
        assert!(!exported.contains("tenant-secret"));
        assert!(!exported.contains("roster-secret"));
        drop((first, second));
        assert_eq!(diagnostics.snapshot().provider_in_flight, 0);
    }
}
