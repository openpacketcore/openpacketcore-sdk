//! Pure, bounded collector state for the candidate v5 concurrent HA history.
//!
//! This module does not perform Kubernetes I/O or implement another consensus
//! path. It admits already bounded, typed qualification-node observations and
//! projects them into the frozen v5 independent-checker contract. Successful
//! batch slots receive an application-journal sequence only after an exact
//! match with a real watch event. Openraft indexes and application-journal
//! positions remain separate domains throughout.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::qualification::{
    qualification_concurrent_state_type, qualification_state_type_sha256,
    QualificationConcurrentBatchOutcome, QualificationConcurrentBatchSlotOutcome,
    QualificationConcurrentBatchSlotResult, QualificationConcurrentMutationSnapshot,
    QualificationConcurrentRecordSnapshot, QualificationConcurrentSubscriptionId,
    QualificationConcurrentWatchEvent, QualificationNodeReply, QualificationReadinessCode,
    QUALIFICATION_CONCURRENT_BATCH_MAX_SLOTS, QUALIFICATION_CONCURRENT_COLLECTOR_MAX_RECORDS,
    QUALIFICATION_CONCURRENT_HISTORY_ID_MAX_BYTES,
};

/// Frozen row-schema identifier consumed by the independent v5 checker.
pub const QUALIFICATION_CONCURRENT_HISTORY_V5_SCHEMA: &str = "opc-session-ha-concurrent-history/v5";
/// Frozen fault-schedule schema identifier consumed by the v5 checker.
pub const QUALIFICATION_CONCURRENT_FAULT_SCHEDULE_V5_SCHEMA: &str =
    "opc-session-ha-fault-schedule/v5";
/// Maximum number of rows admitted by the frozen v5 evidence contract.
pub const QUALIFICATION_CONCURRENT_HISTORY_V5_MAX_OPERATIONS: usize = 10_000;
/// Maximum complete JSONL artifact accepted by the frozen v5 checker.
pub const QUALIFICATION_CONCURRENT_HISTORY_V5_MAX_BYTES: usize = 8 * 1024 * 1024;
/// Maximum compact JSON bytes in one v5 history row.
pub const QUALIFICATION_CONCURRENT_HISTORY_V5_MAX_LINE_BYTES: usize = 256 * 1024;
/// Maximum serialized batch invocations admitted by the frozen v5 checker.
pub const QUALIFICATION_CONCURRENT_HISTORY_V5_MAX_BATCHES: usize = 64;
/// Maximum number of fault intervals admitted by the frozen v5 contract.
pub const QUALIFICATION_CONCURRENT_FAULT_V5_MAX_INTERVALS: usize = 1_024;
/// Maximum byte envelope accepted by the typed v5 fault-schedule decoder.
pub const QUALIFICATION_CONCURRENT_FAULT_SCHEDULE_V5_MAX_BYTES: usize = 256 * 1024;
/// Maximum checker-supported interval between readiness observations.
pub const QUALIFICATION_CONCURRENT_READINESS_V5_MAX_GAP_NS: u64 = 60_000_000_000;
/// Maximum fixed lease inventory for the bounded v5 workload.
pub const QUALIFICATION_CONCURRENT_LEASE_V5_MAX_BINDINGS: usize =
    QUALIFICATION_CONCURRENT_HISTORY_V5_MAX_BATCHES * QUALIFICATION_CONCURRENT_BATCH_MAX_SLOTS;

/// One immutable lease guard covering a v5 qualification campaign.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct QualificationConcurrentLeaseBindingV5 {
    key_sha256: String,
    owner_sha256: String,
    fence: u64,
    valid_from_ns: u64,
    valid_through_ns: u64,
}

impl QualificationConcurrentLeaseBindingV5 {
    /// Construct one digest-only, positively fenced lease interval.
    pub fn try_new(
        key_sha256: impl Into<String>,
        owner_sha256: impl Into<String>,
        fence: u64,
        valid_from_ns: u64,
        valid_through_ns: u64,
    ) -> Result<Self, QualificationConcurrentV5Error> {
        let key_sha256 = key_sha256.into();
        let owner_sha256 = owner_sha256.into();
        if !is_exact_sha256(&key_sha256)
            || !is_exact_sha256(&owner_sha256)
            || fence == 0
            || valid_through_ns <= valid_from_ns
        {
            return Err(QualificationConcurrentV5Error::Lease);
        }
        Ok(Self {
            key_sha256,
            owner_sha256,
            fence,
            valid_from_ns,
            valid_through_ns,
        })
    }

    /// Domain-separated record-key digest protected by this lease.
    pub fn key_sha256(&self) -> &str {
        &self.key_sha256
    }

    /// Domain-separated expected lease-owner digest.
    pub fn owner_sha256(&self) -> &str {
        &self.owner_sha256
    }

    /// Fixed campaign fencing token.
    pub const fn fence(&self) -> u64 {
        self.fence
    }

    /// First campaign-clock instant covered by the lease.
    pub const fn valid_from_ns(&self) -> u64 {
        self.valid_from_ns
    }

    /// Last exclusive campaign-clock instant covered by the lease.
    pub const fn valid_through_ns(&self) -> u64 {
        self.valid_through_ns
    }
}

impl fmt::Debug for QualificationConcurrentLeaseBindingV5 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationConcurrentLeaseBindingV5")
            .field("fence", &self.fence)
            .field("valid_from_ns", &self.valid_from_ns)
            .field("valid_through_ns", &self.valid_through_ns)
            .field("identifiers", &"<redacted>")
            .finish()
    }
}

/// Immutable workload contract against which every v5 observation is checked.
#[derive(Clone, PartialEq, Eq)]
pub struct QualificationConcurrentHistoryContractV5 {
    initial_journal_head: u64,
    max_readiness_gap_ns: u64,
    state_type_sha256: String,
    preacquired_leases: Vec<QualificationConcurrentLeaseBindingV5>,
}

impl QualificationConcurrentHistoryContractV5 {
    /// Construct a bounded contract with a canonical unique lease inventory.
    pub fn try_new(
        history_id: &str,
        initial_journal_head: u64,
        max_readiness_gap_ns: u64,
        mut preacquired_leases: Vec<QualificationConcurrentLeaseBindingV5>,
    ) -> Result<Self, QualificationConcurrentV5Error> {
        validate_history_id(history_id).map_err(|_| QualificationConcurrentV5Error::Contract)?;
        let state_type = qualification_concurrent_state_type(history_id)
            .map_err(|_| QualificationConcurrentV5Error::Contract)?;
        let state_type_sha256 = qualification_state_type_sha256(state_type.as_str());
        if initial_journal_head == u64::MAX
            || max_readiness_gap_ns == 0
            || max_readiness_gap_ns > QUALIFICATION_CONCURRENT_READINESS_V5_MAX_GAP_NS
            || preacquired_leases.is_empty()
            || preacquired_leases.len() > QUALIFICATION_CONCURRENT_LEASE_V5_MAX_BINDINGS
        {
            return Err(QualificationConcurrentV5Error::Contract);
        }
        preacquired_leases.sort_by(|left, right| left.key_sha256.cmp(&right.key_sha256));
        if preacquired_leases
            .windows(2)
            .any(|pair| pair[0].key_sha256 == pair[1].key_sha256)
        {
            return Err(QualificationConcurrentV5Error::Lease);
        }
        Ok(Self {
            initial_journal_head,
            max_readiness_gap_ns,
            state_type_sha256,
            preacquired_leases,
        })
    }

    /// Journal cursor before any workload mutation is invoked.
    pub const fn initial_journal_head(&self) -> u64 {
        self.initial_journal_head
    }

    /// Maximum permitted readiness call duration and sampling gap.
    pub const fn max_readiness_gap_ns(&self) -> u64 {
        self.max_readiness_gap_ns
    }

    /// Exact state-type digest required from every attempted and committed record.
    pub fn state_type_sha256(&self) -> &str {
        &self.state_type_sha256
    }

    /// Canonical fixed lease inventory for the isolated workload namespace.
    pub fn preacquired_leases(&self) -> &[QualificationConcurrentLeaseBindingV5] {
        &self.preacquired_leases
    }
}

impl fmt::Debug for QualificationConcurrentHistoryContractV5 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationConcurrentHistoryContractV5")
            .field("initial_journal_head", &self.initial_journal_head)
            .field("max_readiness_gap_ns", &self.max_readiness_gap_ns)
            .field("lease_count", &self.preacquired_leases.len())
            .field("digests", &"<redacted>")
            .finish()
    }
}

/// One exact process identity used by a candidate v5 history.
#[derive(Clone, PartialEq, Eq)]
pub struct QualificationConcurrentProcessV5 {
    process_id: String,
    node_id: u64,
}

impl QualificationConcurrentProcessV5 {
    /// Construct one bounded process identifier and nonzero Openraft node ID.
    pub fn try_new(
        process_id: impl Into<String>,
        node_id: u64,
    ) -> Result<Self, QualificationConcurrentV5Error> {
        let process_id = process_id.into();
        validate_identifier(&process_id)?;
        if node_id == 0 {
            return Err(QualificationConcurrentV5Error::Identity);
        }
        Ok(Self {
            process_id,
            node_id,
        })
    }

    /// Stable process identifier written to the digest-only history.
    pub fn process_id(&self) -> &str {
        &self.process_id
    }

    /// Exact manifest-derived Openraft node ID expected from this process.
    pub const fn node_id(&self) -> u64 {
        self.node_id
    }
}

impl fmt::Debug for QualificationConcurrentProcessV5 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationConcurrentProcessV5")
            .field("identity", &"<redacted>")
            .finish()
    }
}

/// One canonical undirected bidirectional path in a v5 fault interval.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationConcurrentFaultPairV5 {
    /// Lower topology-ordered process identifier.
    pub left_process_id: String,
    /// Higher topology-ordered process identifier.
    pub right_process_id: String,
}

/// One inclusive, contiguous fault-schedule interval.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationConcurrentFaultIntervalV5 {
    /// One-based contiguous interval sequence.
    pub interval_sequence: usize,
    /// Inclusive campaign-clock start.
    pub started_ns: u64,
    /// Inclusive campaign-clock completion.
    pub completed_ns: u64,
    /// Canonical topology-ordered running processes.
    pub running_process_ids: Vec<String>,
    /// Canonical topology-ordered available bidirectional pairs.
    pub available_bidirectional_pairs: Vec<QualificationConcurrentFaultPairV5>,
}

/// Complete, closed v5 fault schedule used to derive expected quorum.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationConcurrentFaultScheduleV5 {
    /// Frozen schedule schema identifier.
    pub schema_version: String,
    /// Bounded campaign identifier shared with every history row.
    pub history_id: String,
    /// First inclusive campaign-clock instant.
    pub campaign_started_ns: u64,
    /// Last inclusive campaign-clock instant.
    pub campaign_completed_ns: u64,
    /// Exact topology process order.
    pub process_ids: Vec<String>,
    /// Complete contiguous fault partition.
    pub intervals: Vec<QualificationConcurrentFaultIntervalV5>,
}

impl fmt::Debug for QualificationConcurrentFaultScheduleV5 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationConcurrentFaultScheduleV5")
            .field("member_count", &self.process_ids.len())
            .field("interval_count", &self.intervals.len())
            .field("identifiers", &"<redacted>")
            .finish()
    }
}

impl QualificationConcurrentFaultScheduleV5 {
    /// Decode and validate one closed schedule inside the frozen 256-KiB
    /// artifact envelope. Direct unbounded deserialization is intentionally
    /// unavailable.
    pub fn from_json(document: &[u8]) -> Result<Self, QualificationConcurrentV5Error> {
        if document.len() > QUALIFICATION_CONCURRENT_FAULT_SCHEDULE_V5_MAX_BYTES {
            return Err(QualificationConcurrentV5Error::DocumentTooLarge);
        }
        let decoded: QualificationConcurrentFaultScheduleV5Document =
            serde_json::from_slice(document)
                .map_err(|_| QualificationConcurrentV5Error::FaultSchedule)?;
        let schedule = decoded.into_schedule();
        schedule.validate()?;
        Ok(schedule)
    }

    /// Encode the one canonical compact schedule artifact after enforcing the
    /// same 256-KiB envelope used by the independent checker.
    pub fn encode_json(&self) -> Result<Vec<u8>, QualificationConcurrentV5Error> {
        self.validate()?;
        encode_bounded_json(self, QUALIFICATION_CONCURRENT_FAULT_SCHEDULE_V5_MAX_BYTES)
    }

    /// Validate the complete frozen schedule envelope, canonical topology
    /// ordering, contiguous campaign coverage, and quorum-loss lifecycle.
    pub fn validate(&self) -> Result<(), QualificationConcurrentV5Error> {
        validate_fault_schedule(self)
    }

    /// Derive whether one process has a direct static majority throughout an
    /// observation interval. The observation must fit wholly within one fault
    /// interval; a transition-straddling observation is rejected.
    pub fn expected_quorum_for(
        &self,
        process_id: &str,
        started_ns: u64,
        completed_ns: u64,
    ) -> Result<bool, QualificationConcurrentV5Error> {
        self.validate()?;
        self.expected_quorum_for_validated(process_id, started_ns, completed_ns)
    }

    fn expected_quorum_for_validated(
        &self,
        process_id: &str,
        started_ns: u64,
        completed_ns: u64,
    ) -> Result<bool, QualificationConcurrentV5Error> {
        validate_interval(started_ns, completed_ns)?;
        if !self
            .process_ids
            .iter()
            .any(|candidate| candidate == process_id)
        {
            return Err(QualificationConcurrentV5Error::Process);
        }
        let interval = self
            .intervals
            .iter()
            .find(|interval| {
                started_ns >= interval.started_ns && completed_ns <= interval.completed_ns
            })
            .ok_or(QualificationConcurrentV5Error::FaultSchedule)?;
        if !interval
            .running_process_ids
            .iter()
            .any(|candidate| candidate == process_id)
        {
            return Ok(false);
        }
        let reachable_peers = interval
            .available_bidirectional_pairs
            .iter()
            .filter(|pair| {
                pair.left_process_id == process_id || pair.right_process_id == process_id
            })
            .count();
        Ok(reachable_peers >= self.process_ids.len() / 2)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationConcurrentFaultPairV5Document {
    left_process_id: String,
    right_process_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationConcurrentFaultIntervalV5Document {
    interval_sequence: usize,
    started_ns: u64,
    completed_ns: u64,
    running_process_ids: Vec<String>,
    available_bidirectional_pairs: Vec<QualificationConcurrentFaultPairV5Document>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationConcurrentFaultScheduleV5Document {
    schema_version: String,
    history_id: String,
    campaign_started_ns: u64,
    campaign_completed_ns: u64,
    process_ids: Vec<String>,
    intervals: Vec<QualificationConcurrentFaultIntervalV5Document>,
}

impl QualificationConcurrentFaultScheduleV5Document {
    fn into_schedule(self) -> QualificationConcurrentFaultScheduleV5 {
        QualificationConcurrentFaultScheduleV5 {
            schema_version: self.schema_version,
            history_id: self.history_id,
            campaign_started_ns: self.campaign_started_ns,
            campaign_completed_ns: self.campaign_completed_ns,
            process_ids: self.process_ids,
            intervals: self
                .intervals
                .into_iter()
                .map(|interval| QualificationConcurrentFaultIntervalV5 {
                    interval_sequence: interval.interval_sequence,
                    started_ns: interval.started_ns,
                    completed_ns: interval.completed_ns,
                    running_process_ids: interval.running_process_ids,
                    available_bidirectional_pairs: interval
                        .available_bidirectional_pairs
                        .into_iter()
                        .map(|pair| QualificationConcurrentFaultPairV5 {
                            left_process_id: pair.left_process_id,
                            right_process_id: pair.right_process_id,
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

/// Checked builder for a contiguous candidate v5 fault schedule.
pub struct QualificationConcurrentFaultScheduleV5Builder {
    history_id: String,
    process_ids: Vec<String>,
    campaign_started_ns: u64,
    next_started_ns: u64,
    intervals: Vec<QualificationConcurrentFaultIntervalV5>,
}

impl fmt::Debug for QualificationConcurrentFaultScheduleV5Builder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationConcurrentFaultScheduleV5Builder")
            .field("member_count", &self.process_ids.len())
            .field("interval_count", &self.intervals.len())
            .field("identifiers", &"<redacted>")
            .finish()
    }
}

impl QualificationConcurrentFaultScheduleV5Builder {
    /// Start a schedule for one exact three- or five-process topology.
    pub fn new(
        history_id: impl Into<String>,
        processes: &[QualificationConcurrentProcessV5],
        campaign_started_ns: u64,
    ) -> Result<Self, QualificationConcurrentV5Error> {
        let history_id = history_id.into();
        validate_history_id(&history_id)?;
        validate_processes(processes)?;
        Ok(Self {
            history_id,
            process_ids: processes
                .iter()
                .map(|process| process.process_id.clone())
                .collect(),
            campaign_started_ns,
            next_started_ns: campaign_started_ns,
            intervals: Vec::new(),
        })
    }

    /// Append the next inclusive interval using topology indexes.
    pub fn push_interval(
        &mut self,
        completed_ns: u64,
        running_process_indexes: &[usize],
        available_pair_indexes: &[(usize, usize)],
    ) -> Result<(), QualificationConcurrentV5Error> {
        let maximum_pair_count = self
            .process_ids
            .len()
            .checked_mul(self.process_ids.len().saturating_sub(1))
            .and_then(|product| product.checked_div(2))
            .ok_or(QualificationConcurrentV5Error::Overflow)?;
        if self.intervals.len() >= QUALIFICATION_CONCURRENT_FAULT_V5_MAX_INTERVALS
            || completed_ns < self.next_started_ns
            || running_process_indexes.len() > self.process_ids.len()
            || available_pair_indexes.len() > maximum_pair_count
        {
            return Err(QualificationConcurrentV5Error::FaultSchedule);
        }
        let running = canonical_process_subset(&self.process_ids, running_process_indexes)?;
        let running_set = running.iter().collect::<BTreeSet<_>>();
        let mut pair_indexes = BTreeSet::new();
        for &(first, second) in available_pair_indexes {
            if first == second
                || first >= self.process_ids.len()
                || second >= self.process_ids.len()
            {
                return Err(QualificationConcurrentV5Error::FaultSchedule);
            }
            let (left, right) = if first < second {
                (first, second)
            } else {
                (second, first)
            };
            let left_process_id = &self.process_ids[left];
            let right_process_id = &self.process_ids[right];
            if !running_set.contains(left_process_id) || !running_set.contains(right_process_id) {
                return Err(QualificationConcurrentV5Error::FaultSchedule);
            }
            if !pair_indexes.insert((left, right)) {
                return Err(QualificationConcurrentV5Error::FaultSchedule);
            }
        }
        let pairs: Vec<_> = pair_indexes
            .into_iter()
            .map(|(left, right)| QualificationConcurrentFaultPairV5 {
                left_process_id: self.process_ids[left].clone(),
                right_process_id: self.process_ids[right].clone(),
            })
            .collect();
        let interval_sequence = self
            .intervals
            .len()
            .checked_add(1)
            .ok_or(QualificationConcurrentV5Error::Overflow)?;
        let next_started_ns = completed_ns
            .checked_add(1)
            .ok_or(QualificationConcurrentV5Error::Overflow)?;
        self.intervals.push(QualificationConcurrentFaultIntervalV5 {
            interval_sequence,
            started_ns: self.next_started_ns,
            completed_ns,
            running_process_ids: running,
            available_bidirectional_pairs: pairs,
        });
        self.next_started_ns = next_started_ns;
        Ok(())
    }

    /// Finish a nonempty schedule after its final inclusive interval.
    pub fn finish(
        self,
    ) -> Result<QualificationConcurrentFaultScheduleV5, QualificationConcurrentV5Error> {
        let campaign_completed_ns = self
            .intervals
            .last()
            .map(|interval| interval.completed_ns)
            .ok_or(QualificationConcurrentV5Error::FaultSchedule)?;
        let schedule = QualificationConcurrentFaultScheduleV5 {
            schema_version: QUALIFICATION_CONCURRENT_FAULT_SCHEDULE_V5_SCHEMA.to_owned(),
            history_id: self.history_id,
            campaign_started_ns: self.campaign_started_ns,
            campaign_completed_ns,
            process_ids: self.process_ids,
            intervals: self.intervals,
        };
        schedule.validate()?;
        Ok(schedule)
    }
}

/// One v5 batch slot after exact watch correlation.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationConcurrentBatchSlotV5 {
    /// One-based slot position in the protected-store batch.
    pub slot_index: usize,
    /// Typed protected-store outcome.
    pub outcome: QualificationConcurrentBatchSlotOutcome,
    /// Real committed application-journal sequence for a successful slot.
    pub journal_sequence: Option<u64>,
    /// Digest-only attempted mutation.
    pub mutation: QualificationConcurrentMutationSnapshot,
}

/// One watch event with its exact originating batch slot.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationConcurrentWatchEventV5 {
    /// Real application-journal position.
    pub journal_sequence: u64,
    /// Exact collector-assigned batch operation identifier.
    pub batch_operation_id: String,
    /// Exact one-based originating batch slot.
    pub slot_index: usize,
    /// Domain-separated committed key digest.
    pub key_sha256: String,
    /// Committed record generation.
    pub generation: u64,
    /// Domain-separated committed owner digest.
    pub owner_sha256: String,
    /// Committed fencing token.
    pub fence: u64,
    /// Fixed authoritative state class.
    pub state_class: crate::qualification::QualificationConcurrentStateClass,
    /// Domain-separated state-type digest.
    pub state_type_sha256: String,
    /// Candidate v5 records are non-expiring.
    pub expires_at_ns: Option<i64>,
    /// Domain-separated committed value digest.
    pub value_sha256: String,
}

/// Exact retained-watch identity and initial cursor captured before dispatch.
#[derive(Clone, PartialEq, Eq)]
pub struct QualificationConcurrentWatchExpectationV5 {
    subscription_id: QualificationConcurrentSubscriptionId,
    requested_after_journal_sequence: u64,
}

impl QualificationConcurrentWatchExpectationV5 {
    /// Bind one typed subscription identity to its exact requested cursor.
    pub const fn new(
        subscription_id: QualificationConcurrentSubscriptionId,
        requested_after_journal_sequence: u64,
    ) -> Self {
        Self {
            subscription_id,
            requested_after_journal_sequence,
        }
    }

    /// Exact subscription identity expected in the completion reply.
    pub const fn subscription_id(&self) -> &QualificationConcurrentSubscriptionId {
        &self.subscription_id
    }

    /// Exact journal cursor used when the retained watch was started.
    pub const fn requested_after_journal_sequence(&self) -> u64 {
        self.requested_after_journal_sequence
    }
}

impl fmt::Debug for QualificationConcurrentWatchExpectationV5 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationConcurrentWatchExpectationV5")
            .field(
                "requested_after_journal_sequence",
                &self.requested_after_journal_sequence,
            )
            .field("subscription_id", &"<redacted>")
            .finish()
    }
}

/// Frozen v5 operation union.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum QualificationConcurrentOperationV5 {
    /// One serialized protected-store batch.
    Batch {
        /// One-based contiguous invocation order.
        invocation_sequence: usize,
        /// Aggregate protected-store result.
        outcome: QualificationConcurrentBatchOutcome,
        /// Per-slot results in request order.
        slots: Vec<QualificationConcurrentBatchSlotV5>,
    },
    /// One bounded real watch result.
    Watch {
        /// Typed collector outcome.
        outcome: QualificationConcurrentObservationOutcomeV5,
        /// Bounded redacted subscription identifier.
        subscription_id: String,
        /// Cursor used to start the real watch.
        requested_after_journal_sequence: u64,
        /// Last journal sequence conclusively consumed.
        complete_through_journal_sequence: Option<u64>,
        /// Exact correlated events in journal order.
        events: Vec<QualificationConcurrentWatchEventV5>,
    },
    /// One complete bounded restore view.
    Restore {
        /// Typed collector outcome.
        outcome: QualificationConcurrentObservationOutcomeV5,
        /// Whether the bounded view is complete.
        complete: bool,
        /// Digest-only records in canonical key order.
        records: Vec<QualificationConcurrentRecordSnapshot>,
    },
    /// One strict readiness observation.
    Readiness {
        /// Per-process contiguous sequence.
        sample_sequence: usize,
        /// Expected quorum derived from the fault schedule.
        expected_quorum: bool,
        /// Ready or fail-closed not-ready.
        state: QualificationConcurrentReadinessStateV5,
        /// Openraft authority, present only when ready.
        raft_term: Option<u64>,
        /// Openraft commit index, present only when ready.
        raft_commit_index: Option<u64>,
        /// Openraft applied index, present only when ready.
        raft_applied_index: Option<u64>,
        /// Application-journal head, present only when ready.
        journal_head: Option<u64>,
    },
}

/// Closed result vocabulary for watch and restore observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationConcurrentObservationOutcomeV5 {
    /// The observation completed conclusively.
    Success,
    /// A dispatched operation may have completed but was not observed.
    Indeterminate,
    /// The operation failed before a conclusive result was available.
    Unavailable,
}

/// Closed readiness state vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationConcurrentReadinessStateV5 {
    /// Fresh durable authority and a journal head were proven.
    Ready,
    /// Authority was not proven and every authority field is absent.
    NotReady,
}

/// One exact JSONL row in the frozen v5 history.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationConcurrentHistoryRowV5 {
    /// Frozen row-schema identifier.
    pub schema_version: String,
    /// Bounded campaign identifier.
    pub history_id: String,
    /// Exact total row count repeated in every row.
    pub history_operation_count: usize,
    /// Unique bounded operation identifier.
    pub operation_id: String,
    /// Exact topology process identifier.
    pub process_id: String,
    /// Monotonic campaign-clock start.
    pub started_ns: u64,
    /// Monotonic campaign-clock completion.
    pub completed_ns: u64,
    /// Typed operation payload.
    pub operation: QualificationConcurrentOperationV5,
}

impl fmt::Debug for QualificationConcurrentHistoryRowV5 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationConcurrentHistoryRowV5")
            .field("started_ns", &self.started_ns)
            .field("completed_ns", &self.completed_ns)
            .field("identifiers", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Finalized checker-ready candidate v5 history and its bound fault schedule.
#[derive(Clone)]
pub struct QualificationConcurrentHistoryV5 {
    rows: Vec<QualificationConcurrentHistoryRowV5>,
    fault_schedule: QualificationConcurrentFaultScheduleV5,
    contract: QualificationConcurrentHistoryContractV5,
}

impl QualificationConcurrentHistoryV5 {
    /// Canonical rows ready for newline-delimited JSON encoding.
    pub fn rows(&self) -> &[QualificationConcurrentHistoryRowV5] {
        &self.rows
    }

    /// Exact schedule from which readiness expectations were derived.
    pub const fn fault_schedule(&self) -> &QualificationConcurrentFaultScheduleV5 {
        &self.fault_schedule
    }

    /// Exact journal, cadence, state-type, and lease contract for these rows.
    pub const fn contract(&self) -> &QualificationConcurrentHistoryContractV5 {
        &self.contract
    }

    /// Encode deterministic newline-delimited JSON with a trailing newline.
    pub fn encode_json_lines(&self) -> Result<Vec<u8>, QualificationConcurrentV5Error> {
        encode_history_rows(&self.rows)
    }
}

struct BoundedHistoryWriter {
    bytes: Vec<u8>,
    line_bytes: usize,
    exceeded: bool,
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    max_bytes: usize,
    exceeded: bool,
}

impl BoundedJsonWriter {
    fn new(max_bytes: usize) -> Self {
        Self {
            bytes: Vec::new(),
            max_bytes,
            exceeded: false,
        }
    }
}

impl io::Write for BoundedJsonWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self
            .bytes
            .len()
            .checked_add(buffer.len())
            .is_none_or(|length| length > self.max_bytes)
        {
            self.exceeded = true;
            return Err(io::Error::other("qualification JSON bound exceeded"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_bounded_json<T: Serialize>(
    value: &T,
    max_bytes: usize,
) -> Result<Vec<u8>, QualificationConcurrentV5Error> {
    let mut writer = BoundedJsonWriter::new(max_bytes);
    if serde_json::to_writer(&mut writer, value).is_err() {
        return Err(if writer.exceeded {
            QualificationConcurrentV5Error::DocumentTooLarge
        } else {
            QualificationConcurrentV5Error::Encoding
        });
    }
    Ok(writer.bytes)
}

impl BoundedHistoryWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            line_bytes: 0,
            exceeded: false,
        }
    }

    fn finish_line(&mut self) -> Result<(), QualificationConcurrentV5Error> {
        if self.bytes.len() >= QUALIFICATION_CONCURRENT_HISTORY_V5_MAX_BYTES {
            self.exceeded = true;
            return Err(QualificationConcurrentV5Error::DocumentTooLarge);
        }
        self.bytes.push(b'\n');
        self.line_bytes = 0;
        Ok(())
    }
}

impl io::Write for BoundedHistoryWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let total = self.bytes.len().checked_add(buffer.len());
        let line = self.line_bytes.checked_add(buffer.len());
        if total.is_none_or(|length| length > QUALIFICATION_CONCURRENT_HISTORY_V5_MAX_BYTES)
            || line.is_none_or(|length| length > QUALIFICATION_CONCURRENT_HISTORY_V5_MAX_LINE_BYTES)
        {
            self.exceeded = true;
            return Err(io::Error::other("qualification history bound exceeded"));
        }
        self.bytes.extend_from_slice(buffer);
        self.line_bytes += buffer.len();
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_history_rows(
    rows: &[QualificationConcurrentHistoryRowV5],
) -> Result<Vec<u8>, QualificationConcurrentV5Error> {
    let mut writer = BoundedHistoryWriter::new();
    for row in rows {
        if serde_json::to_writer(&mut writer, row).is_err() {
            return Err(if writer.exceeded {
                QualificationConcurrentV5Error::DocumentTooLarge
            } else {
                QualificationConcurrentV5Error::Encoding
            });
        }
        writer.finish_line()?;
    }
    Ok(writer.bytes)
}

impl fmt::Debug for QualificationConcurrentHistoryV5 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationConcurrentHistoryV5")
            .field("operation_count", &self.rows.len())
            .field("member_count", &self.fault_schedule.process_ids.len())
            .field("lease_count", &self.contract.preacquired_leases.len())
            .field("identifiers", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
struct PendingBatchV5 {
    operation_id: String,
    process_id: String,
    started_ns: u64,
    completed_ns: u64,
    invocation_sequence: usize,
    outcome: QualificationConcurrentBatchOutcome,
    slots: Vec<QualificationConcurrentBatchSlotResult>,
}

#[derive(Clone)]
struct PendingWatchV5 {
    operation_id: String,
    process_id: String,
    started_ns: u64,
    completed_ns: u64,
    subscription_id: String,
    requested_after: u64,
    complete_through: u64,
    events: Vec<QualificationConcurrentWatchEvent>,
}

#[derive(Clone)]
struct PendingRestoreV5 {
    operation_id: String,
    process_id: String,
    started_ns: u64,
    completed_ns: u64,
    records: Vec<QualificationConcurrentRecordSnapshot>,
}

/// Checked collector for typed qualification-node observations.
pub struct QualificationConcurrentHistoryV5Builder {
    history_id: String,
    processes: Vec<QualificationConcurrentProcessV5>,
    fault_schedule: QualificationConcurrentFaultScheduleV5,
    contract: QualificationConcurrentHistoryContractV5,
    operation_ids: BTreeSet<String>,
    batches: Vec<PendingBatchV5>,
    watch: Option<PendingWatchV5>,
    restore: Option<PendingRestoreV5>,
    readiness: Vec<QualificationConcurrentHistoryRowV5>,
    readiness_sequences: BTreeMap<String, usize>,
    last_batch_completed_ns: Option<u64>,
}

impl fmt::Debug for QualificationConcurrentHistoryV5Builder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationConcurrentHistoryV5Builder")
            .field("member_count", &self.processes.len())
            .field("batch_count", &self.batches.len())
            .field("readiness_count", &self.readiness.len())
            .field("identifiers", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl QualificationConcurrentHistoryV5Builder {
    /// Start one collector whose topology and fault schedule are already fixed.
    pub fn new(
        history_id: impl Into<String>,
        processes: Vec<QualificationConcurrentProcessV5>,
        fault_schedule: QualificationConcurrentFaultScheduleV5,
        contract: QualificationConcurrentHistoryContractV5,
    ) -> Result<Self, QualificationConcurrentV5Error> {
        let history_id = history_id.into();
        validate_history_id(&history_id)?;
        validate_processes(&processes)?;
        let process_ids = processes
            .iter()
            .map(|process| process.process_id.clone())
            .collect::<Vec<_>>();
        fault_schedule.validate()?;
        if fault_schedule.history_id != history_id || fault_schedule.process_ids != process_ids {
            return Err(QualificationConcurrentV5Error::FaultSchedule);
        }
        let expected_state_type_sha256 = qualification_concurrent_state_type(&history_id)
            .map(|state_type| qualification_state_type_sha256(state_type.as_str()))
            .map_err(|_| QualificationConcurrentV5Error::Contract)?;
        if contract.state_type_sha256 != expected_state_type_sha256 {
            return Err(QualificationConcurrentV5Error::Contract);
        }
        if contract.preacquired_leases.iter().any(|lease| {
            lease.valid_from_ns > fault_schedule.campaign_started_ns
                || lease.valid_through_ns <= fault_schedule.campaign_completed_ns
        }) {
            return Err(QualificationConcurrentV5Error::Lease);
        }
        Ok(Self {
            history_id,
            processes,
            fault_schedule,
            contract,
            operation_ids: BTreeSet::new(),
            batches: Vec::new(),
            watch: None,
            restore: None,
            readiness: Vec::new(),
            readiness_sequences: BTreeMap::new(),
            last_batch_completed_ns: None,
        })
    }

    /// Admit one at-most-once protected-store batch reply after matching every
    /// slot to the exact digest-only mutation contract captured before
    /// dispatch.
    pub fn record_batch(
        &mut self,
        operation_id: impl Into<String>,
        process_id: &str,
        started_ns: u64,
        completed_ns: u64,
        expected_mutations: &[QualificationConcurrentMutationSnapshot],
        reply: &QualificationNodeReply,
    ) -> Result<(), QualificationConcurrentV5Error> {
        self.validate_observation(process_id, started_ns, completed_ns)?;
        if self
            .last_batch_completed_ns
            .is_some_and(|previous| started_ns < previous)
        {
            return Err(QualificationConcurrentV5Error::BatchOrder);
        }
        if self.batches.len() >= QUALIFICATION_CONCURRENT_HISTORY_V5_MAX_BATCHES {
            return Err(QualificationConcurrentV5Error::Overflow);
        }
        let operation_id = self.validate_operation_id(operation_id)?;
        let QualificationNodeReply::ConcurrentBatch { outcome, slots } = reply else {
            return Err(QualificationConcurrentV5Error::Reply);
        };
        if expected_mutations.is_empty()
            || expected_mutations.len() > QUALIFICATION_CONCURRENT_BATCH_MAX_SLOTS
            || slots.len() != expected_mutations.len()
        {
            return Err(QualificationConcurrentV5Error::Reply);
        }
        for (index, (slot, expected)) in slots.iter().zip(expected_mutations).enumerate() {
            validate_mutation_snapshot(&self.contract, expected)?;
            if slot.slot_index != index + 1 || slot.mutation != *expected {
                return Err(QualificationConcurrentV5Error::Reply);
            }
            validate_mutation_snapshot(&self.contract, &slot.mutation)?;
        }
        let coherent = match outcome {
            QualificationConcurrentBatchOutcome::Completed => true,
            QualificationConcurrentBatchOutcome::Indeterminate => slots
                .iter()
                .all(|slot| slot.outcome == QualificationConcurrentBatchSlotOutcome::Indeterminate),
            QualificationConcurrentBatchOutcome::Unavailable => slots
                .iter()
                .all(|slot| slot.outcome == QualificationConcurrentBatchSlotOutcome::Unavailable),
        };
        if !coherent {
            return Err(QualificationConcurrentV5Error::Reply);
        }
        let invocation_sequence = self
            .batches
            .len()
            .checked_add(1)
            .ok_or(QualificationConcurrentV5Error::Overflow)?;
        self.commit_operation_id(operation_id.clone())?;
        self.batches.push(PendingBatchV5 {
            operation_id,
            process_id: process_id.to_owned(),
            started_ns,
            completed_ns,
            invocation_sequence,
            outcome: *outcome,
            slots: slots.clone(),
        });
        self.last_batch_completed_ns = Some(completed_ns);
        Ok(())
    }

    /// Admit the single complete watch that covers the exclusive journal window.
    pub fn record_watch(
        &mut self,
        operation_id: impl Into<String>,
        process_id: &str,
        started_ns: u64,
        completed_ns: u64,
        expectation: &QualificationConcurrentWatchExpectationV5,
        reply: &QualificationNodeReply,
    ) -> Result<(), QualificationConcurrentV5Error> {
        self.validate_observation(process_id, started_ns, completed_ns)?;
        if self.watch.is_some() {
            return Err(QualificationConcurrentV5Error::DuplicateObservation);
        }
        let operation_id = self.validate_operation_id(operation_id)?;
        let QualificationNodeReply::ConcurrentWatchFinished {
            subscription_id,
            complete_through_journal_sequence,
            events,
        } = reply
        else {
            return Err(QualificationConcurrentV5Error::Reply);
        };
        let requested_after_journal_sequence = expectation.requested_after_journal_sequence;
        if subscription_id != &expectation.subscription_id
            || requested_after_journal_sequence != self.contract.initial_journal_head
            || *complete_through_journal_sequence < requested_after_journal_sequence
            || complete_through_journal_sequence.saturating_sub(requested_after_journal_sequence)
                > QUALIFICATION_CONCURRENT_COLLECTOR_MAX_RECORDS as u64
            || events.len() > QUALIFICATION_CONCURRENT_COLLECTOR_MAX_RECORDS
        {
            return Err(QualificationConcurrentV5Error::Watch);
        }
        let mut expected_sequence = requested_after_journal_sequence;
        for event in events {
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(QualificationConcurrentV5Error::Overflow)?;
            if event.journal_sequence != expected_sequence {
                return Err(QualificationConcurrentV5Error::Watch);
            }
            validate_record_snapshot(&self.contract, &event.record)?;
        }
        if expected_sequence != *complete_through_journal_sequence {
            return Err(QualificationConcurrentV5Error::Watch);
        }
        self.commit_operation_id(operation_id.clone())?;
        self.watch = Some(PendingWatchV5 {
            operation_id,
            process_id: process_id.to_owned(),
            started_ns,
            completed_ns,
            subscription_id: subscription_id.as_str().to_owned(),
            requested_after: requested_after_journal_sequence,
            complete_through: *complete_through_journal_sequence,
            events: events.clone(),
        });
        Ok(())
    }

    /// Admit the single complete terminal restore observation.
    pub fn record_restore(
        &mut self,
        operation_id: impl Into<String>,
        process_id: &str,
        started_ns: u64,
        completed_ns: u64,
        reply: &QualificationNodeReply,
    ) -> Result<(), QualificationConcurrentV5Error> {
        self.validate_observation(process_id, started_ns, completed_ns)?;
        if self.restore.is_some() {
            return Err(QualificationConcurrentV5Error::DuplicateObservation);
        }
        let operation_id = self.validate_operation_id(operation_id)?;
        let QualificationNodeReply::ConcurrentRestore { complete, records } = reply else {
            return Err(QualificationConcurrentV5Error::Reply);
        };
        if !*complete || records.len() > QUALIFICATION_CONCURRENT_COLLECTOR_MAX_RECORDS {
            return Err(QualificationConcurrentV5Error::Restore);
        }
        let mut previous = None;
        for record in records {
            validate_record_snapshot(&self.contract, record)?;
            if previous
                .as_ref()
                .is_some_and(|key: &String| key >= &record.key_sha256)
            {
                return Err(QualificationConcurrentV5Error::Restore);
            }
            previous = Some(record.key_sha256.clone());
        }
        self.commit_operation_id(operation_id.clone())?;
        self.restore = Some(PendingRestoreV5 {
            operation_id,
            process_id: process_id.to_owned(),
            started_ns,
            completed_ns,
            records: records.clone(),
        });
        Ok(())
    }

    /// Admit one strict readiness reply, deriving expected quorum only from
    /// the bound fault schedule.
    pub fn record_readiness(
        &mut self,
        operation_id: impl Into<String>,
        process_id: &str,
        started_ns: u64,
        completed_ns: u64,
        reply: &QualificationNodeReply,
    ) -> Result<(), QualificationConcurrentV5Error> {
        self.validate_observation(process_id, started_ns, completed_ns)?;
        let operation_id = self.validate_operation_id(operation_id)?;
        let expected_quorum = self.fault_schedule.expected_quorum_for_validated(
            process_id,
            started_ns,
            completed_ns,
        )?;
        let process = self
            .processes
            .iter()
            .find(|process| process.process_id == process_id)
            .ok_or(QualificationConcurrentV5Error::Process)?;
        let QualificationNodeReply::ConcurrentReadiness { status } = reply else {
            return Err(QualificationConcurrentV5Error::Reply);
        };
        let mut voter_ids = self
            .processes
            .iter()
            .map(QualificationConcurrentProcessV5::node_id)
            .collect::<Vec<_>>();
        voter_ids.sort_unstable();
        if status.node_id != process.node_id
            || status.configured_voters != self.processes.len()
            || status.configured_voter_ids != voter_ids
            || status.required_quorum != self.processes.len() / 2 + 1
            || status.fresh_reachable_voters > self.processes.len()
            || status.agreeing_voters > self.processes.len()
            || status.agreeing_voters > status.fresh_reachable_voters
        {
            return Err(QualificationConcurrentV5Error::Readiness);
        }
        let (state, raft_term, raft_commit_index, raft_applied_index, journal_head) =
            if status.ready {
                let ready = status.reason_code == QualificationReadinessCode::Ready
                    && expected_quorum
                    && status.fresh_reachable_voters == status.required_quorum
                    && status.agreeing_voters == status.required_quorum
                    && status.raft_term.is_some_and(|term| term != 0)
                    && status
                        .raft_leader_id
                        .is_some_and(|leader| voter_ids.binary_search(&leader).is_ok())
                    && status
                        .raft_applied_index
                        .zip(status.raft_commit_index)
                        .is_some_and(|(applied, committed)| applied >= committed)
                    && status.journal_head.is_some();
                if !ready {
                    return Err(QualificationConcurrentV5Error::Readiness);
                }
                (
                    QualificationConcurrentReadinessStateV5::Ready,
                    status.raft_term,
                    status.raft_commit_index,
                    status.raft_applied_index,
                    status.journal_head,
                )
            } else {
                if status.reason_code == QualificationReadinessCode::Ready
                    || !expected_quorum
                        && (status.fresh_reachable_voters >= status.required_quorum
                            || status.agreeing_voters >= status.required_quorum)
                    || status.raft_term.is_some()
                    || status.raft_leader_id.is_some()
                    || status.raft_commit_index.is_some()
                    || status.raft_applied_index.is_some()
                    || status.journal_head.is_some()
                {
                    return Err(QualificationConcurrentV5Error::Readiness);
                }
                (
                    QualificationConcurrentReadinessStateV5::NotReady,
                    None,
                    None,
                    None,
                    None,
                )
            };
        let previous = self
            .readiness
            .iter()
            .rev()
            .find(|row| row.process_id == process_id);
        let gap = self.contract.max_readiness_gap_ns;
        if completed_ns.saturating_sub(started_ns) > gap
            || previous.is_none()
                && completed_ns.saturating_sub(self.fault_schedule.campaign_started_ns) > gap
            || previous.is_some_and(|row| {
                started_ns < row.completed_ns || completed_ns.saturating_sub(row.completed_ns) > gap
            })
        {
            return Err(QualificationConcurrentV5Error::Readiness);
        }
        if state == QualificationConcurrentReadinessStateV5::Ready {
            let previous_authority = self.readiness.iter().rev().find_map(|row| {
                let QualificationConcurrentOperationV5::Readiness {
                    state: QualificationConcurrentReadinessStateV5::Ready,
                    raft_term,
                    raft_commit_index,
                    raft_applied_index,
                    journal_head,
                    ..
                } = &row.operation
                else {
                    return None;
                };
                (row.process_id == process_id).then_some((
                    *raft_term,
                    *raft_commit_index,
                    *raft_applied_index,
                    *journal_head,
                ))
            });
            if previous_authority.is_some_and(|(term, commit, applied, journal)| {
                raft_term < term
                    || raft_commit_index < commit
                    || raft_applied_index < applied
                    || journal_head < journal
            }) {
                return Err(QualificationConcurrentV5Error::Readiness);
            }
        }
        let sample_sequence = self
            .readiness_sequences
            .get(process_id)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(QualificationConcurrentV5Error::Overflow)?;
        self.commit_operation_id(operation_id.clone())?;
        self.readiness_sequences
            .insert(process_id.to_owned(), sample_sequence);
        self.readiness.push(QualificationConcurrentHistoryRowV5 {
            schema_version: QUALIFICATION_CONCURRENT_HISTORY_V5_SCHEMA.to_owned(),
            history_id: self.history_id.clone(),
            history_operation_count: 0,
            operation_id,
            process_id: process_id.to_owned(),
            started_ns,
            completed_ns,
            operation: QualificationConcurrentOperationV5::Readiness {
                sample_sequence,
                expected_quorum,
                state,
                raft_term,
                raft_commit_index,
                raft_applied_index,
                journal_head,
            },
        });
        Ok(())
    }

    /// Correlate batch successes with the real journal, validate the terminal
    /// restore, and freeze every row count.
    pub fn finish(
        self,
    ) -> Result<QualificationConcurrentHistoryV5, QualificationConcurrentV5Error> {
        let watch = self
            .watch
            .ok_or(QualificationConcurrentV5Error::MissingCoverage)?;
        let restore = self
            .restore
            .ok_or(QualificationConcurrentV5Error::MissingCoverage)?;
        if self.batches.is_empty()
            || self.readiness_sequences.len() != self.processes.len()
            || self.processes.iter().any(|process| {
                self.readiness_sequences
                    .get(&process.process_id)
                    .copied()
                    .unwrap_or(0)
                    < 2
            })
        {
            return Err(QualificationConcurrentV5Error::MissingCoverage);
        }
        let observed_keys = self
            .batches
            .iter()
            .flat_map(|batch| batch.slots.iter())
            .map(|slot| slot.mutation.key_sha256.as_str())
            .collect::<BTreeSet<_>>();
        let lease_keys = self
            .contract
            .preacquired_leases
            .iter()
            .map(|lease| lease.key_sha256.as_str())
            .collect::<BTreeSet<_>>();
        if observed_keys != lease_keys {
            return Err(QualificationConcurrentV5Error::Lease);
        }
        if self.batches.iter().any(|batch| {
            batch.outcome != QualificationConcurrentBatchOutcome::Completed
                || batch.slots.iter().any(|slot| {
                    !matches!(
                        slot.outcome,
                        QualificationConcurrentBatchSlotOutcome::Success
                            | QualificationConcurrentBatchSlotOutcome::Conflict
                    )
                })
        }) {
            return Err(QualificationConcurrentV5Error::MissingCoverage);
        }
        let partial_batch_observed =
            self.batches.iter().any(|batch| {
                batch.outcome == QualificationConcurrentBatchOutcome::Completed
                    && batch.slots.len() > 1
                    && batch.slots.iter().any(|slot| {
                        slot.outcome == QualificationConcurrentBatchSlotOutcome::Success
                    })
                    && batch.slots.iter().any(|slot| {
                        slot.outcome == QualificationConcurrentBatchSlotOutcome::Conflict
                    })
            });
        if !partial_batch_observed {
            return Err(QualificationConcurrentV5Error::MissingCoverage);
        }
        let first_batch_started = self.batches[0].started_ns;
        let last_batch_completed = self
            .batches
            .last()
            .map(|batch| batch.completed_ns)
            .ok_or(QualificationConcurrentV5Error::MissingCoverage)?;
        if watch.started_ns > first_batch_started
            || watch.completed_ns < last_batch_completed
            || restore.started_ns < last_batch_completed
        {
            return Err(QualificationConcurrentV5Error::CoverageOrder);
        }

        let mut correlated = BTreeMap::<(usize, usize), u64>::new();
        let mut expected_sequence = watch.requested_after;
        let mut projected_events = Vec::with_capacity(watch.events.len());
        for event in &watch.events {
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(QualificationConcurrentV5Error::Overflow)?;
            if event.journal_sequence != expected_sequence
                || event.journal_sequence > watch.complete_through
            {
                return Err(QualificationConcurrentV5Error::Watch);
            }
            let matches = self
                .batches
                .iter()
                .enumerate()
                .flat_map(|(batch_index, batch)| {
                    batch
                        .slots
                        .iter()
                        .enumerate()
                        .filter_map(move |(slot_index, slot)| {
                            slot.matches_committed_watch_event(event)
                                .then_some((batch_index, slot_index))
                        })
                })
                .collect::<Vec<_>>();
            let [(batch_index, slot_index)] = matches.as_slice() else {
                return Err(QualificationConcurrentV5Error::Correlation);
            };
            if correlated
                .insert((*batch_index, *slot_index), event.journal_sequence)
                .is_some()
            {
                return Err(QualificationConcurrentV5Error::Correlation);
            }
            let batch = &self.batches[*batch_index];
            let slot = &batch.slots[*slot_index];
            projected_events.push(project_watch_event(
                event,
                &batch.operation_id,
                slot.slot_index,
            ));
        }
        if expected_sequence != watch.complete_through {
            return Err(QualificationConcurrentV5Error::Watch);
        }
        for (batch_index, batch) in self.batches.iter().enumerate() {
            for (slot_index, slot) in batch.slots.iter().enumerate() {
                let has_sequence = correlated.contains_key(&(batch_index, slot_index));
                if (slot.outcome == QualificationConcurrentBatchSlotOutcome::Success)
                    != has_sequence
                {
                    return Err(QualificationConcurrentV5Error::Correlation);
                }
            }
        }

        let mut ordered_sequence = self.contract.initial_journal_head;
        for (batch_index, batch) in self.batches.iter().enumerate() {
            for (slot_index, slot) in batch.slots.iter().enumerate() {
                if slot.outcome != QualificationConcurrentBatchSlotOutcome::Success {
                    continue;
                }
                ordered_sequence = ordered_sequence
                    .checked_add(1)
                    .ok_or(QualificationConcurrentV5Error::Overflow)?;
                if correlated.get(&(batch_index, slot_index)).copied() != Some(ordered_sequence) {
                    return Err(QualificationConcurrentV5Error::Correlation);
                }
            }
        }
        if ordered_sequence != watch.complete_through {
            return Err(QualificationConcurrentV5Error::Watch);
        }

        let terminal = modeled_terminal_records(&self.batches)?
            .ok_or(QualificationConcurrentV5Error::MissingCoverage)?;
        let restored = record_map(&restore.records)?;
        if terminal != restored {
            return Err(QualificationConcurrentV5Error::Restore);
        }

        validate_boundary_readiness(ReadinessValidationContext {
            processes: &self.processes,
            fault_schedule: &self.fault_schedule,
            contract: &self.contract,
            rows: &self.readiness,
            batches: &self.batches,
            correlated: &correlated,
            first_batch_started,
            last_batch_completed,
            terminal_journal_head: watch.complete_through,
        })?;

        let mut rows = Vec::new();
        for (batch_index, batch) in self.batches.into_iter().enumerate() {
            let slots = batch
                .slots
                .into_iter()
                .enumerate()
                .map(|(slot_index, slot)| QualificationConcurrentBatchSlotV5 {
                    slot_index: slot.slot_index,
                    outcome: slot.outcome,
                    journal_sequence: correlated.get(&(batch_index, slot_index)).copied(),
                    mutation: slot.mutation,
                })
                .collect();
            rows.push(QualificationConcurrentHistoryRowV5 {
                schema_version: QUALIFICATION_CONCURRENT_HISTORY_V5_SCHEMA.to_owned(),
                history_id: self.history_id.clone(),
                history_operation_count: 0,
                operation_id: batch.operation_id,
                process_id: batch.process_id,
                started_ns: batch.started_ns,
                completed_ns: batch.completed_ns,
                operation: QualificationConcurrentOperationV5::Batch {
                    invocation_sequence: batch.invocation_sequence,
                    outcome: batch.outcome,
                    slots,
                },
            });
        }
        rows.push(QualificationConcurrentHistoryRowV5 {
            schema_version: QUALIFICATION_CONCURRENT_HISTORY_V5_SCHEMA.to_owned(),
            history_id: self.history_id.clone(),
            history_operation_count: 0,
            operation_id: watch.operation_id,
            process_id: watch.process_id,
            started_ns: watch.started_ns,
            completed_ns: watch.completed_ns,
            operation: QualificationConcurrentOperationV5::Watch {
                outcome: QualificationConcurrentObservationOutcomeV5::Success,
                subscription_id: watch.subscription_id,
                requested_after_journal_sequence: watch.requested_after,
                complete_through_journal_sequence: Some(watch.complete_through),
                events: projected_events,
            },
        });
        rows.push(QualificationConcurrentHistoryRowV5 {
            schema_version: QUALIFICATION_CONCURRENT_HISTORY_V5_SCHEMA.to_owned(),
            history_id: self.history_id.clone(),
            history_operation_count: 0,
            operation_id: restore.operation_id,
            process_id: restore.process_id,
            started_ns: restore.started_ns,
            completed_ns: restore.completed_ns,
            operation: QualificationConcurrentOperationV5::Restore {
                outcome: QualificationConcurrentObservationOutcomeV5::Success,
                complete: true,
                records: restore.records,
            },
        });
        rows.extend(self.readiness);
        if rows.is_empty() || rows.len() > QUALIFICATION_CONCURRENT_HISTORY_V5_MAX_OPERATIONS {
            return Err(QualificationConcurrentV5Error::Overflow);
        }
        let operation_count = rows.len();
        for row in &mut rows {
            row.history_operation_count = operation_count;
        }
        let history = QualificationConcurrentHistoryV5 {
            rows,
            fault_schedule: self.fault_schedule,
            contract: self.contract,
        };
        let _ = history.encode_json_lines()?;
        Ok(history)
    }

    fn validate_observation(
        &self,
        process_id: &str,
        started_ns: u64,
        completed_ns: u64,
    ) -> Result<(), QualificationConcurrentV5Error> {
        validate_interval(started_ns, completed_ns)?;
        if !self
            .processes
            .iter()
            .any(|process| process.process_id == process_id)
        {
            return Err(QualificationConcurrentV5Error::Process);
        }
        if started_ns < self.fault_schedule.campaign_started_ns
            || completed_ns > self.fault_schedule.campaign_completed_ns
        {
            return Err(QualificationConcurrentV5Error::Interval);
        }
        Ok(())
    }

    fn validate_operation_id(
        &self,
        operation_id: impl Into<String>,
    ) -> Result<String, QualificationConcurrentV5Error> {
        let operation_id = operation_id.into();
        validate_identifier(&operation_id)?;
        if self.operation_ids.contains(&operation_id) {
            return Err(QualificationConcurrentV5Error::DuplicateOperation);
        }
        if self.operation_ids.len() >= QUALIFICATION_CONCURRENT_HISTORY_V5_MAX_OPERATIONS {
            return Err(QualificationConcurrentV5Error::Overflow);
        }
        Ok(operation_id)
    }

    fn commit_operation_id(
        &mut self,
        operation_id: String,
    ) -> Result<(), QualificationConcurrentV5Error> {
        if self.operation_ids.insert(operation_id) {
            Ok(())
        } else {
            Err(QualificationConcurrentV5Error::DuplicateOperation)
        }
    }
}

/// Stable, redaction-safe collector failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum QualificationConcurrentV5Error {
    /// The topology is not exactly three or five unique processes.
    #[error("qualification v5 topology is invalid")]
    Topology,
    /// A process or Openraft identity is invalid or duplicated.
    #[error("qualification v5 identity contract is invalid")]
    Identity,
    /// A bounded history or operation identifier is invalid.
    #[error("qualification v5 identifier is invalid")]
    Identifier,
    /// An observation names a process outside the fixed topology.
    #[error("qualification v5 process is invalid")]
    Process,
    /// An observation interval is invalid or outside the campaign.
    #[error("qualification v5 interval is invalid")]
    Interval,
    /// The workload-wide journal, cadence, or state-type contract is invalid.
    #[error("qualification v5 workload contract is invalid")]
    Contract,
    /// A fixed campaign lease binding is invalid or was not honored.
    #[error("qualification v5 lease contract is invalid")]
    Lease,
    /// The fault schedule is incomplete, noncanonical, or contradictory.
    #[error("qualification v5 fault schedule is invalid")]
    FaultSchedule,
    /// An operation identifier was reused.
    #[error("qualification v5 operation identifier is duplicated")]
    DuplicateOperation,
    /// More than one watch or restore observation was supplied.
    #[error("qualification v5 observation is duplicated")]
    DuplicateObservation,
    /// A typed node reply did not match the requested operation.
    #[error("qualification v5 node reply is invalid")]
    Reply,
    /// Batch invocations overlapped or were out of order.
    #[error("qualification v5 batch order is invalid")]
    BatchOrder,
    /// A watch cursor, sequence, or bounded result is invalid.
    #[error("qualification v5 watch result is invalid")]
    Watch,
    /// A successful batch slot did not correlate exactly once with the journal.
    #[error("qualification v5 journal correlation failed")]
    Correlation,
    /// A complete restore result was absent or contradicted terminal state.
    #[error("qualification v5 restore result is invalid")]
    Restore,
    /// A readiness observation violated the strict authority contract.
    #[error("qualification v5 readiness result is invalid")]
    Readiness,
    /// Required batch/watch/restore/readiness evidence is absent.
    #[error("qualification v5 coverage is incomplete")]
    MissingCoverage,
    /// Required observations are not ordered around the exclusive window.
    #[error("qualification v5 coverage order is invalid")]
    CoverageOrder,
    /// Checked arithmetic or a frozen collection bound overflowed.
    #[error("qualification v5 bound was exceeded")]
    Overflow,
    /// An input or emitted artifact exceeded its frozen byte envelope.
    #[error("qualification v5 document is too large")]
    DocumentTooLarge,
    /// Deterministic JSON encoding failed.
    #[error("qualification v5 encoding failed")]
    Encoding,
}

fn validate_history_id(value: &str) -> Result<(), QualificationConcurrentV5Error> {
    if value.len() > QUALIFICATION_CONCURRENT_HISTORY_ID_MAX_BYTES {
        return Err(QualificationConcurrentV5Error::Identifier);
    }
    validate_identifier(value)
}

fn is_exact_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn validate_identifier(value: &str) -> Result<(), QualificationConcurrentV5Error> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(QualificationConcurrentV5Error::Identifier);
    }
    Ok(())
}

fn validate_interval(
    started_ns: u64,
    completed_ns: u64,
) -> Result<(), QualificationConcurrentV5Error> {
    if completed_ns < started_ns {
        Err(QualificationConcurrentV5Error::Interval)
    } else {
        Ok(())
    }
}

fn validate_processes(
    processes: &[QualificationConcurrentProcessV5],
) -> Result<(), QualificationConcurrentV5Error> {
    if !matches!(processes.len(), 3 | 5) {
        return Err(QualificationConcurrentV5Error::Topology);
    }
    let process_ids = processes
        .iter()
        .map(|process| process.process_id.as_str())
        .collect::<BTreeSet<_>>();
    let node_ids = processes
        .iter()
        .map(QualificationConcurrentProcessV5::node_id)
        .collect::<BTreeSet<_>>();
    if process_ids.len() != processes.len() || node_ids.len() != processes.len() {
        return Err(QualificationConcurrentV5Error::Identity);
    }
    Ok(())
}

fn validate_fault_schedule(
    schedule: &QualificationConcurrentFaultScheduleV5,
) -> Result<(), QualificationConcurrentV5Error> {
    validate_history_id(&schedule.history_id)
        .map_err(|_| QualificationConcurrentV5Error::FaultSchedule)?;
    if schedule.schema_version != QUALIFICATION_CONCURRENT_FAULT_SCHEDULE_V5_SCHEMA
        || !matches!(schedule.process_ids.len(), 3 | 5)
        || schedule.campaign_completed_ns <= schedule.campaign_started_ns
        || schedule.campaign_completed_ns == u64::MAX
        || schedule.intervals.is_empty()
        || schedule.intervals.len() > QUALIFICATION_CONCURRENT_FAULT_V5_MAX_INTERVALS
    {
        return Err(QualificationConcurrentV5Error::FaultSchedule);
    }

    let mut process_positions = BTreeMap::new();
    for (position, process_id) in schedule.process_ids.iter().enumerate() {
        validate_identifier(process_id)
            .map_err(|_| QualificationConcurrentV5Error::FaultSchedule)?;
        if process_positions
            .insert(process_id.as_str(), position)
            .is_some()
        {
            return Err(QualificationConcurrentV5Error::FaultSchedule);
        }
    }

    let mut expected_start = schedule.campaign_started_ns;
    for (position, interval) in schedule.intervals.iter().enumerate() {
        if interval.interval_sequence != position + 1
            || interval.started_ns != expected_start
            || interval.completed_ns < interval.started_ns
            || interval.completed_ns > schedule.campaign_completed_ns
            || interval.running_process_ids.len() > schedule.process_ids.len()
        {
            return Err(QualificationConcurrentV5Error::FaultSchedule);
        }

        let mut previous_running_position = None;
        let mut running = BTreeSet::new();
        for process_id in &interval.running_process_ids {
            let process_position = process_positions
                .get(process_id.as_str())
                .copied()
                .ok_or(QualificationConcurrentV5Error::FaultSchedule)?;
            if previous_running_position.is_some_and(|previous| previous >= process_position)
                || !running.insert(process_id.as_str())
            {
                return Err(QualificationConcurrentV5Error::FaultSchedule);
            }
            previous_running_position = Some(process_position);
        }

        let maximum_pairs = schedule
            .process_ids
            .len()
            .saturating_mul(schedule.process_ids.len().saturating_sub(1))
            / 2;
        if interval.available_bidirectional_pairs.len() > maximum_pairs {
            return Err(QualificationConcurrentV5Error::FaultSchedule);
        }
        let mut previous_pair = None;
        for pair in &interval.available_bidirectional_pairs {
            let left = process_positions
                .get(pair.left_process_id.as_str())
                .copied()
                .ok_or(QualificationConcurrentV5Error::FaultSchedule)?;
            let right = process_positions
                .get(pair.right_process_id.as_str())
                .copied()
                .ok_or(QualificationConcurrentV5Error::FaultSchedule)?;
            let ordered = (left, right);
            if left >= right
                || !running.contains(pair.left_process_id.as_str())
                || !running.contains(pair.right_process_id.as_str())
                || previous_pair.is_some_and(|previous| previous >= ordered)
            {
                return Err(QualificationConcurrentV5Error::FaultSchedule);
            }
            previous_pair = Some(ordered);
        }

        expected_start = interval
            .completed_ns
            .checked_add(1)
            .ok_or(QualificationConcurrentV5Error::FaultSchedule)?;
    }
    if expected_start != schedule.campaign_completed_ns + 1 {
        return Err(QualificationConcurrentV5Error::FaultSchedule);
    }

    let required_quorum = schedule.process_ids.len() / 2 + 1;
    for process_id in &schedule.process_ids {
        let expected = schedule
            .intervals
            .iter()
            .map(|interval| {
                interval
                    .running_process_ids
                    .iter()
                    .any(|candidate| candidate == process_id)
                    && interval
                        .available_bidirectional_pairs
                        .iter()
                        .filter(|pair| {
                            pair.left_process_id == *process_id
                                || pair.right_process_id == *process_id
                        })
                        .count()
                        .saturating_add(1)
                        >= required_quorum
            })
            .collect::<Vec<_>>();
        let first_loss = expected
            .iter()
            .position(|has_quorum| !has_quorum)
            .ok_or(QualificationConcurrentV5Error::FaultSchedule)?;
        if !expected.first().copied().unwrap_or(false)
            || !expected[first_loss.saturating_add(1)..]
                .iter()
                .any(|has_quorum| *has_quorum)
        {
            return Err(QualificationConcurrentV5Error::FaultSchedule);
        }
    }
    let _ = encode_bounded_json(
        schedule,
        QUALIFICATION_CONCURRENT_FAULT_SCHEDULE_V5_MAX_BYTES,
    )?;
    Ok(())
}

fn canonical_process_subset(
    process_ids: &[String],
    indexes: &[usize],
) -> Result<Vec<String>, QualificationConcurrentV5Error> {
    if indexes.len() > process_ids.len() {
        return Err(QualificationConcurrentV5Error::FaultSchedule);
    }
    let original_len = indexes.len();
    let mut indexes = indexes.to_vec();
    indexes.sort_unstable();
    indexes.dedup();
    if indexes.len() != original_len || indexes.iter().any(|index| *index >= process_ids.len()) {
        return Err(QualificationConcurrentV5Error::FaultSchedule);
    }
    indexes
        .into_iter()
        .map(|index| {
            process_ids
                .get(index)
                .cloned()
                .ok_or(QualificationConcurrentV5Error::FaultSchedule)
        })
        .collect()
}

fn validate_mutation_snapshot(
    contract: &QualificationConcurrentHistoryContractV5,
    mutation: &QualificationConcurrentMutationSnapshot,
) -> Result<(), QualificationConcurrentV5Error> {
    if !is_exact_sha256(&mutation.key_sha256)
        || !is_exact_sha256(&mutation.owner_sha256)
        || !is_exact_sha256(&mutation.state_type_sha256)
        || !is_exact_sha256(&mutation.value_sha256)
        || mutation.new_generation == 0
        || mutation
            .expected_generation
            .is_some_and(|expected| mutation.new_generation <= expected)
        || mutation.fence == 0
        || mutation.expires_at_ns.is_some()
        || mutation.state_type_sha256 != contract.state_type_sha256
    {
        return Err(QualificationConcurrentV5Error::Reply);
    }
    let lease = contract
        .preacquired_leases
        .binary_search_by(|lease| lease.key_sha256.as_str().cmp(&mutation.key_sha256))
        .ok()
        .and_then(|position| contract.preacquired_leases.get(position))
        .ok_or(QualificationConcurrentV5Error::Lease)?;
    if mutation.owner_sha256 != lease.owner_sha256 || mutation.fence != lease.fence {
        return Err(QualificationConcurrentV5Error::Lease);
    }
    Ok(())
}

fn validate_record_snapshot(
    contract: &QualificationConcurrentHistoryContractV5,
    record: &QualificationConcurrentRecordSnapshot,
) -> Result<(), QualificationConcurrentV5Error> {
    if !is_exact_sha256(&record.key_sha256)
        || !is_exact_sha256(&record.owner_sha256)
        || !is_exact_sha256(&record.state_type_sha256)
        || !is_exact_sha256(&record.value_sha256)
        || record.generation == 0
        || record.fence == 0
        || record.expires_at_ns.is_some()
        || record.state_type_sha256 != contract.state_type_sha256
    {
        return Err(QualificationConcurrentV5Error::Reply);
    }
    let lease = contract
        .preacquired_leases
        .binary_search_by(|lease| lease.key_sha256.as_str().cmp(&record.key_sha256))
        .ok()
        .and_then(|position| contract.preacquired_leases.get(position))
        .ok_or(QualificationConcurrentV5Error::Lease)?;
    if record.owner_sha256 != lease.owner_sha256 || record.fence != lease.fence {
        return Err(QualificationConcurrentV5Error::Lease);
    }
    Ok(())
}

fn project_watch_event(
    event: &QualificationConcurrentWatchEvent,
    batch_operation_id: &str,
    slot_index: usize,
) -> QualificationConcurrentWatchEventV5 {
    QualificationConcurrentWatchEventV5 {
        journal_sequence: event.journal_sequence,
        batch_operation_id: batch_operation_id.to_owned(),
        slot_index,
        key_sha256: event.record.key_sha256.clone(),
        generation: event.record.generation,
        owner_sha256: event.record.owner_sha256.clone(),
        fence: event.record.fence,
        state_class: event.record.state_class,
        state_type_sha256: event.record.state_type_sha256.clone(),
        expires_at_ns: event.record.expires_at_ns,
        value_sha256: event.record.value_sha256.clone(),
    }
}

fn modeled_terminal_records(
    batches: &[PendingBatchV5],
) -> Result<
    Option<BTreeMap<String, QualificationConcurrentRecordSnapshot>>,
    QualificationConcurrentV5Error,
> {
    let mut records = BTreeMap::new();
    let mut conclusive = true;
    for batch in batches {
        for slot in &batch.slots {
            let current_generation = records
                .get(&slot.mutation.key_sha256)
                .map(|record: &QualificationConcurrentRecordSnapshot| record.generation);
            match slot.outcome {
                QualificationConcurrentBatchSlotOutcome::Success => {
                    if current_generation != slot.mutation.expected_generation {
                        return Err(QualificationConcurrentV5Error::Restore);
                    }
                    records.insert(
                        slot.mutation.key_sha256.clone(),
                        QualificationConcurrentRecordSnapshot {
                            key_sha256: slot.mutation.key_sha256.clone(),
                            generation: slot.mutation.new_generation,
                            owner_sha256: slot.mutation.owner_sha256.clone(),
                            fence: slot.mutation.fence,
                            state_class: slot.mutation.state_class,
                            state_type_sha256: slot.mutation.state_type_sha256.clone(),
                            expires_at_ns: slot.mutation.expires_at_ns,
                            value_sha256: slot.mutation.value_sha256.clone(),
                        },
                    );
                }
                QualificationConcurrentBatchSlotOutcome::Conflict => {
                    if current_generation == slot.mutation.expected_generation {
                        return Err(QualificationConcurrentV5Error::Restore);
                    }
                }
                QualificationConcurrentBatchSlotOutcome::Indeterminate
                | QualificationConcurrentBatchSlotOutcome::Unavailable => {
                    conclusive = false;
                }
            }
        }
    }
    Ok(conclusive.then_some(records))
}

fn record_map(
    records: &[QualificationConcurrentRecordSnapshot],
) -> Result<BTreeMap<String, QualificationConcurrentRecordSnapshot>, QualificationConcurrentV5Error>
{
    let mut mapped = BTreeMap::new();
    for record in records {
        if mapped
            .insert(record.key_sha256.clone(), record.clone())
            .is_some()
        {
            return Err(QualificationConcurrentV5Error::Restore);
        }
    }
    Ok(mapped)
}

struct ReadinessValidationContext<'a> {
    processes: &'a [QualificationConcurrentProcessV5],
    fault_schedule: &'a QualificationConcurrentFaultScheduleV5,
    contract: &'a QualificationConcurrentHistoryContractV5,
    rows: &'a [QualificationConcurrentHistoryRowV5],
    batches: &'a [PendingBatchV5],
    correlated: &'a BTreeMap<(usize, usize), u64>,
    first_batch_started: u64,
    last_batch_completed: u64,
    terminal_journal_head: u64,
}

fn validate_boundary_readiness(
    context: ReadinessValidationContext<'_>,
) -> Result<(), QualificationConcurrentV5Error> {
    let ReadinessValidationContext {
        processes,
        fault_schedule,
        contract,
        rows,
        batches,
        correlated,
        first_batch_started,
        last_batch_completed,
        terminal_journal_head,
    } = context;
    for process in processes {
        let mut samples = rows
            .iter()
            .filter(|row| row.process_id == process.process_id)
            .collect::<Vec<_>>();
        samples.sort_by_key(|row| match row.operation {
            QualificationConcurrentOperationV5::Readiness {
                sample_sequence, ..
            } => sample_sequence,
            _ => 0,
        });
        let first = samples
            .first()
            .ok_or(QualificationConcurrentV5Error::MissingCoverage)?;
        let last = samples
            .last()
            .ok_or(QualificationConcurrentV5Error::MissingCoverage)?;
        if samples.iter().enumerate().any(|(index, row)| {
            !matches!(
                row.operation,
                QualificationConcurrentOperationV5::Readiness {
                    sample_sequence,
                    ..
                } if sample_sequence == index + 1
            )
        }) || samples.windows(2).any(|pair| {
            pair[1].started_ns < pair[0].completed_ns
                || pair[1].completed_ns.saturating_sub(pair[0].completed_ns)
                    > contract.max_readiness_gap_ns
        }) || first
            .completed_ns
            .saturating_sub(fault_schedule.campaign_started_ns)
            > contract.max_readiness_gap_ns
            || fault_schedule
                .campaign_completed_ns
                .saturating_sub(last.completed_ns)
                > contract.max_readiness_gap_ns
            || first.completed_ns > first_batch_started
            || last.started_ns < last_batch_completed
        {
            return Err(QualificationConcurrentV5Error::CoverageOrder);
        }
        let head = |row: &QualificationConcurrentHistoryRowV5| match &row.operation {
            QualificationConcurrentOperationV5::Readiness {
                expected_quorum,
                state,
                journal_head,
                ..
            } if *expected_quorum && *state == QualificationConcurrentReadinessStateV5::Ready => {
                *journal_head
            }
            _ => None,
        };
        if head(first) != Some(contract.initial_journal_head)
            || head(last) != Some(terminal_journal_head)
        {
            return Err(QualificationConcurrentV5Error::Readiness);
        }

        let interval_indexes = samples
            .iter()
            .map(|sample| {
                fault_schedule
                    .intervals
                    .iter()
                    .position(|interval| {
                        sample.started_ns >= interval.started_ns
                            && sample.completed_ns <= interval.completed_ns
                    })
                    .ok_or(QualificationConcurrentV5Error::Readiness)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut previous_expected = true;
        for (interval_index, interval) in fault_schedule.intervals.iter().enumerate().skip(1) {
            let expected = fault_schedule.expected_quorum_for_validated(
                &process.process_id,
                interval.started_ns,
                interval.completed_ns,
            )?;
            if expected != previous_expected {
                let deadline = interval
                    .started_ns
                    .saturating_add(contract.max_readiness_gap_ns)
                    .min(interval.completed_ns);
                let expected_state = if expected {
                    QualificationConcurrentReadinessStateV5::Ready
                } else {
                    QualificationConcurrentReadinessStateV5::NotReady
                };
                let observed = samples
                    .iter()
                    .zip(&interval_indexes)
                    .any(|(sample, index)| {
                        *index == interval_index
                            && sample.completed_ns <= deadline
                            && matches!(
                                sample.operation,
                                QualificationConcurrentOperationV5::Readiness { state, .. }
                                    if state == expected_state
                            )
                    });
                if !observed {
                    return Err(QualificationConcurrentV5Error::Readiness);
                }
            }
            previous_expected = expected;
        }

        let mut previous_authority = None;
        for (sample_index, (sample, interval_index)) in
            samples.iter().zip(&interval_indexes).enumerate()
        {
            let expected = fault_schedule.expected_quorum_for_validated(
                &process.process_id,
                sample.started_ns,
                sample.completed_ns,
            )?;
            let QualificationConcurrentOperationV5::Readiness {
                expected_quorum,
                state,
                raft_term,
                raft_commit_index,
                raft_applied_index,
                journal_head,
                ..
            } = &sample.operation
            else {
                return Err(QualificationConcurrentV5Error::Readiness);
            };
            if *expected_quorum != expected {
                return Err(QualificationConcurrentV5Error::Readiness);
            }
            if *state == QualificationConcurrentReadinessStateV5::NotReady {
                if expected {
                    let interval = &fault_schedule.intervals[*interval_index];
                    let deadline = sample
                        .completed_ns
                        .saturating_add(contract.max_readiness_gap_ns)
                        .min(interval.completed_ns);
                    let recovered = samples
                        .iter()
                        .zip(&interval_indexes)
                        .skip(sample_index + 1)
                        .any(|(candidate, candidate_interval)| {
                            candidate_interval == interval_index
                                && candidate.completed_ns > sample.completed_ns
                                && candidate.completed_ns <= deadline
                                && matches!(
                                    candidate.operation,
                                    QualificationConcurrentOperationV5::Readiness {
                                        state: QualificationConcurrentReadinessStateV5::Ready,
                                        ..
                                    }
                                )
                        });
                    if !recovered {
                        return Err(QualificationConcurrentV5Error::Readiness);
                    }
                }
                continue;
            }
            if !expected {
                return Err(QualificationConcurrentV5Error::Readiness);
            }
            let authority = raft_term
                .zip(*raft_commit_index)
                .zip(*raft_applied_index)
                .zip(*journal_head)
                .map(|(((term, commit), applied), journal)| (term, commit, applied, journal))
                .ok_or(QualificationConcurrentV5Error::Readiness)?;
            if authority.2 < authority.1
                || previous_authority.is_some_and(|previous: (u64, u64, u64, u64)| {
                    authority.0 < previous.0
                        || authority.1 < previous.1
                        || authority.2 < previous.2
                        || authority.3 < previous.3
                })
            {
                return Err(QualificationConcurrentV5Error::Readiness);
            }
            previous_authority = Some(authority);

            let required_journal = correlated
                .iter()
                .filter_map(|(&(batch_index, _), &sequence)| {
                    batches
                        .get(batch_index)
                        .filter(|batch| batch.completed_ns <= sample.started_ns)
                        .map(|_| sequence)
                })
                .max()
                .unwrap_or(contract.initial_journal_head);
            let possible_journal = correlated
                .iter()
                .filter_map(|(&(batch_index, _), &sequence)| {
                    batches
                        .get(batch_index)
                        .filter(|batch| batch.started_ns < sample.completed_ns)
                        .map(|_| sequence)
                })
                .max()
                .unwrap_or(contract.initial_journal_head);
            if authority.3 < required_journal || authority.3 > possible_journal {
                return Err(QualificationConcurrentV5Error::Readiness);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use super::*;
    use crate::qualification::QualificationConcurrentReadiness;
    use sha2::{Digest, Sha256};

    fn digest(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn processes() -> Vec<QualificationConcurrentProcessV5> {
        ["node-z", "node-a", "node-m"]
            .into_iter()
            .enumerate()
            .map(|(index, process_id)| {
                QualificationConcurrentProcessV5::try_new(process_id, index as u64 + 1)
                    .expect("valid process")
            })
            .collect()
    }

    fn schedule(
        processes: &[QualificationConcurrentProcessV5],
    ) -> QualificationConcurrentFaultScheduleV5 {
        let mut builder =
            QualificationConcurrentFaultScheduleV5Builder::new("history-v5", processes, 0)
                .expect("valid schedule builder");
        builder
            .push_interval(19, &[2, 0, 1], &[(1, 2), (2, 0), (1, 0)])
            .expect("initial quorum interval");
        builder
            .push_interval(39, &[0, 1, 2], &[])
            .expect("quorum-loss interval");
        builder
            .push_interval(100, &[0, 1, 2], &[(2, 1), (0, 2), (0, 1)])
            .expect("quorum-recovery interval");
        builder.finish().expect("complete schedule")
    }

    fn lease(
        key_character: char,
        owner_character: char,
        fence: u64,
    ) -> QualificationConcurrentLeaseBindingV5 {
        QualificationConcurrentLeaseBindingV5::try_new(
            digest(key_character),
            digest(owner_character),
            fence,
            0,
            101,
        )
        .expect("valid lease")
    }

    fn contract() -> QualificationConcurrentHistoryContractV5 {
        QualificationConcurrentHistoryContractV5::try_new(
            "history-v5",
            0,
            25,
            vec![lease('a', 'd', 7), lease('b', 'e', 8)],
        )
        .expect("valid contract")
    }

    fn state_type_digest() -> String {
        let state_type =
            qualification_concurrent_state_type("history-v5").expect("history state type");
        qualification_state_type_sha256(state_type.as_str())
    }

    fn mutation(
        key_character: char,
        owner_character: char,
        fence: u64,
        expected_generation: Option<u64>,
        new_generation: u64,
    ) -> QualificationConcurrentMutationSnapshot {
        QualificationConcurrentMutationSnapshot {
            key_sha256: digest(key_character),
            expected_generation,
            new_generation,
            owner_sha256: digest(owner_character),
            fence,
            state_class:
                crate::qualification::QualificationConcurrentStateClass::AuthoritativeSession,
            state_type_sha256: state_type_digest(),
            expires_at_ns: None,
            value_sha256: digest(key_character),
        }
    }

    fn record(
        mutation: &QualificationConcurrentMutationSnapshot,
    ) -> QualificationConcurrentRecordSnapshot {
        QualificationConcurrentRecordSnapshot {
            key_sha256: mutation.key_sha256.clone(),
            generation: mutation.new_generation,
            owner_sha256: mutation.owner_sha256.clone(),
            fence: mutation.fence,
            state_class: mutation.state_class,
            state_type_sha256: mutation.state_type_sha256.clone(),
            expires_at_ns: mutation.expires_at_ns,
            value_sha256: mutation.value_sha256.clone(),
        }
    }

    fn partial_batch_reply() -> QualificationNodeReply {
        QualificationNodeReply::ConcurrentBatch {
            outcome: QualificationConcurrentBatchOutcome::Completed,
            slots: vec![
                QualificationConcurrentBatchSlotResult {
                    slot_index: 1,
                    outcome: QualificationConcurrentBatchSlotOutcome::Success,
                    mutation: mutation('a', 'd', 7, None, 1),
                },
                QualificationConcurrentBatchSlotResult {
                    slot_index: 2,
                    outcome: QualificationConcurrentBatchSlotOutcome::Conflict,
                    mutation: mutation('b', 'e', 8, Some(1), 2),
                },
            ],
        }
    }

    fn batch_mutations(
        reply: &QualificationNodeReply,
    ) -> Vec<QualificationConcurrentMutationSnapshot> {
        let QualificationNodeReply::ConcurrentBatch { slots, .. } = reply else {
            panic!("typed fixture is a batch")
        };
        slots.iter().map(|slot| slot.mutation.clone()).collect()
    }

    fn readiness_reply(
        process_index: usize,
        ready: bool,
        journal_head: u64,
    ) -> QualificationNodeReply {
        QualificationNodeReply::ConcurrentReadiness {
            status: QualificationConcurrentReadiness {
                ready,
                reason_code: if ready {
                    QualificationReadinessCode::Ready
                } else {
                    QualificationReadinessCode::NoQuorum
                },
                node_id: process_index as u64 + 1,
                configured_voters: 3,
                configured_voter_ids: vec![1, 2, 3],
                fresh_reachable_voters: if ready { 2 } else { 0 },
                agreeing_voters: if ready { 2 } else { 0 },
                required_quorum: 2,
                raft_term: ready.then_some(2),
                raft_leader_id: ready.then_some(1),
                raft_commit_index: ready.then_some(9),
                raft_applied_index: ready.then_some(9),
                journal_head: ready.then_some(journal_head),
            },
        }
    }

    fn add_readiness(
        builder: &mut QualificationConcurrentHistoryV5Builder,
        terminal_journal_head: u64,
    ) {
        for process_index in 0..3 {
            let process_id = ["node-z", "node-a", "node-m"][process_index];
            for (sequence, (started_ns, completed_ns, ready, journal_head)) in [
                (0, 1, true, 0),
                (20, 21, false, 0),
                (40, 41, true, terminal_journal_head),
                (60, 61, true, terminal_journal_head),
                (80, 81, true, terminal_journal_head),
            ]
            .into_iter()
            .enumerate()
            {
                builder
                    .record_readiness(
                        format!("ready-{process_index}-{sequence}"),
                        process_id,
                        started_ns,
                        completed_ns,
                        &readiness_reply(process_index, ready, journal_head),
                    )
                    .expect("valid readiness sample");
            }
        }
    }

    fn complete_builder() -> QualificationConcurrentHistoryV5Builder {
        let processes = processes();
        let mut builder = QualificationConcurrentHistoryV5Builder::new(
            "history-v5",
            processes.clone(),
            schedule(&processes),
            contract(),
        )
        .expect("valid history builder");
        let batch = partial_batch_reply();
        let expected_mutations = batch_mutations(&batch);
        builder
            .record_batch("batch-1", "node-z", 5, 6, &expected_mutations, &batch)
            .expect("valid partial batch");
        let QualificationNodeReply::ConcurrentBatch { slots, .. } = &batch else {
            unreachable!("typed fixture is a batch")
        };
        let committed = record(&slots[0].mutation);
        let subscription_id =
            QualificationConcurrentSubscriptionId::new("watch-sub").expect("valid subscription");
        let watch_expectation =
            QualificationConcurrentWatchExpectationV5::new(subscription_id.clone(), 0);
        builder
            .record_watch(
                "watch-1",
                "node-a",
                4,
                7,
                &watch_expectation,
                &QualificationNodeReply::ConcurrentWatchFinished {
                    subscription_id: subscription_id.clone(),
                    complete_through_journal_sequence: 1,
                    events: vec![QualificationConcurrentWatchEvent {
                        journal_sequence: 1,
                        record: committed.clone(),
                    }],
                },
            )
            .expect("valid complete watch");
        builder
            .record_restore(
                "restore-1",
                "node-m",
                7,
                8,
                &QualificationNodeReply::ConcurrentRestore {
                    complete: true,
                    records: vec![committed],
                },
            )
            .expect("valid terminal restore");
        add_readiness(&mut builder, 1);
        builder
    }

    #[test]
    fn schedule_and_history_are_canonical_and_deterministic() {
        let processes = processes();
        let schedule = schedule(&processes);
        let pairs = &schedule.intervals[0].available_bidirectional_pairs;
        assert_eq!(
            pairs
                .iter()
                .map(|pair| (
                    pair.left_process_id.as_str(),
                    pair.right_process_id.as_str()
                ))
                .collect::<Vec<_>>(),
            vec![
                ("node-z", "node-a"),
                ("node-z", "node-m"),
                ("node-a", "node-m")
            ]
        );
        let encoded_schedule = serde_json::to_vec(&schedule).expect("schedule JSON");
        let decoded_schedule = QualificationConcurrentFaultScheduleV5::from_json(&encoded_schedule)
            .expect("bounded schedule decode");
        assert!(decoded_schedule == schedule);
        assert_eq!(
            QualificationConcurrentFaultScheduleV5::from_json(&vec![
                b' ';
                QUALIFICATION_CONCURRENT_FAULT_SCHEDULE_V5_MAX_BYTES
                    + 1
            ])
            .err(),
            Some(QualificationConcurrentV5Error::DocumentTooLarge)
        );

        let history = complete_builder().finish().expect("checker-ready history");
        let first = history.encode_json_lines().expect("history JSONL");
        let second = history
            .encode_json_lines()
            .expect("deterministic history JSONL");
        assert_eq!(first, second);
        assert!(first.len() <= QUALIFICATION_CONCURRENT_HISTORY_V5_MAX_BYTES);
        assert_eq!(history.rows().len(), 18);
        assert_eq!(history.contract().initial_journal_head(), 0);
    }

    #[test]
    fn typed_schedule_construction_enforces_collection_and_artifact_bounds() {
        let topology = processes();
        let mut rejected =
            QualificationConcurrentFaultScheduleV5Builder::new("history-v5", &topology, 0)
                .expect("schedule builder");
        let excessive_indexes = vec![0; 100_000];
        assert_eq!(
            rejected.push_interval(0, &excessive_indexes, &[]),
            Err(QualificationConcurrentV5Error::FaultSchedule)
        );
        let excessive_pairs = vec![(0, 1); 100_000];
        assert_eq!(
            rejected.push_interval(0, &[0, 1, 2], &excessive_pairs),
            Err(QualificationConcurrentV5Error::FaultSchedule)
        );
        assert!(rejected.intervals.is_empty());

        let long_processes = (0..5)
            .map(|index| {
                let prefix = format!("node-{index}-");
                let process_id = format!("{prefix}{}", "x".repeat(128 - prefix.len()));
                QualificationConcurrentProcessV5::try_new(process_id, index as u64 + 1)
                    .expect("maximum-length process identity")
            })
            .collect::<Vec<_>>();
        let history_prefix = "history-";
        let history_id = format!("{history_prefix}{}", "h".repeat(128 - history_prefix.len()));
        let all_pairs = (0..5)
            .flat_map(|left| (left + 1..5).map(move |right| (left, right)))
            .collect::<Vec<_>>();
        let mut oversized =
            QualificationConcurrentFaultScheduleV5Builder::new(history_id, &long_processes, 0)
                .expect("long schedule builder");
        oversized
            .push_interval(0, &[0, 1, 2, 3, 4], &all_pairs)
            .expect("initial quorum interval");
        oversized
            .push_interval(1, &[0, 1, 2, 3, 4], &[])
            .expect("quorum-loss interval");
        for completed_ns in 2..=80 {
            oversized
                .push_interval(completed_ns, &[0, 1, 2, 3, 4], &all_pairs)
                .expect("quorum-recovery interval");
        }
        assert_eq!(
            oversized.finish().err(),
            Some(QualificationConcurrentV5Error::DocumentTooLarge)
        );
    }

    #[test]
    fn history_encoder_enforces_per_line_and_total_artifact_bounds() {
        let long_identifier = "i".repeat(128);
        let record = QualificationConcurrentRecordSnapshot {
            key_sha256: digest('a'),
            generation: u64::MAX,
            owner_sha256: digest('d'),
            fence: u64::MAX,
            state_class:
                crate::qualification::QualificationConcurrentStateClass::AuthoritativeSession,
            state_type_sha256: digest('e'),
            expires_at_ns: None,
            value_sha256: digest('f'),
        };
        let row = QualificationConcurrentHistoryRowV5 {
            schema_version: QUALIFICATION_CONCURRENT_HISTORY_V5_SCHEMA.to_owned(),
            history_id: long_identifier.clone(),
            history_operation_count: 1_000,
            operation_id: long_identifier.clone(),
            process_id: long_identifier,
            started_ns: u64::MAX,
            completed_ns: u64::MAX,
            operation: QualificationConcurrentOperationV5::Restore {
                outcome: QualificationConcurrentObservationOutcomeV5::Success,
                complete: true,
                records: vec![record.clone(); QUALIFICATION_CONCURRENT_COLLECTOR_MAX_RECORDS],
            },
        };
        let one_line = encode_history_rows(std::slice::from_ref(&row)).expect("bounded row");
        assert!(one_line.len() <= QUALIFICATION_CONCURRENT_HISTORY_V5_MAX_LINE_BYTES);
        assert_eq!(
            encode_history_rows(&vec![row.clone(); 1_000]).err(),
            Some(QualificationConcurrentV5Error::DocumentTooLarge)
        );

        let mut oversized_line = row;
        let QualificationConcurrentOperationV5::Restore { records, .. } =
            &mut oversized_line.operation
        else {
            unreachable!("typed fixture is a restore")
        };
        *records = vec![record; 1_000];
        assert_eq!(
            encode_history_rows(&[oversized_line]).err(),
            Some(QualificationConcurrentV5Error::DocumentTooLarge)
        );
    }

    #[test]
    fn malformed_public_schedule_is_rejected() {
        let topology = processes();
        let mut overflow =
            QualificationConcurrentFaultScheduleV5Builder::new("history-v5", &topology, 0)
                .expect("schedule builder");
        assert_eq!(
            overflow.push_interval(u64::MAX, &[0, 1, 2], &[(0, 1), (0, 2), (1, 2)]),
            Err(QualificationConcurrentV5Error::Overflow)
        );
        assert!(overflow.intervals.is_empty());

        let mut malformed = schedule(&topology);
        malformed.intervals[1].started_ns = 21;
        assert_eq!(
            malformed.validate(),
            Err(QualificationConcurrentV5Error::FaultSchedule)
        );
        assert_eq!(
            malformed.expected_quorum_for("node-z", 0, 1),
            Err(QualificationConcurrentV5Error::FaultSchedule)
        );
        assert_eq!(
            QualificationConcurrentHistoryV5Builder::new(
                "history-v5",
                topology,
                malformed,
                contract(),
            )
            .err(),
            Some(QualificationConcurrentV5Error::FaultSchedule)
        );

        let isolated_for_another_history = QualificationConcurrentHistoryContractV5::try_new(
            "other-history",
            0,
            25,
            vec![lease('a', 'd', 7), lease('b', 'e', 8)],
        )
        .expect("other isolated contract");
        let fresh_topology = processes();
        assert_eq!(
            QualificationConcurrentHistoryV5Builder::new(
                "history-v5",
                fresh_topology.clone(),
                schedule(&fresh_topology),
                isolated_for_another_history,
            )
            .err(),
            Some(QualificationConcurrentV5Error::Contract)
        );
    }

    #[test]
    fn invalid_reply_does_not_consume_operation_id() {
        let processes = processes();
        let mut builder = QualificationConcurrentHistoryV5Builder::new(
            "history-v5",
            processes.clone(),
            schedule(&processes),
            contract(),
        )
        .expect("valid history builder");
        let valid_batch = partial_batch_reply();
        let expected_mutations = batch_mutations(&valid_batch);
        assert_eq!(
            builder.record_batch(
                "batch-1",
                "node-z",
                5,
                6,
                &expected_mutations,
                &QualificationNodeReply::Initialized
            ),
            Err(QualificationConcurrentV5Error::Reply)
        );
        assert!(builder
            .record_batch("batch-1", "node-z", 5, 6, &expected_mutations, &valid_batch,)
            .is_ok());

        let expected_subscription =
            QualificationConcurrentSubscriptionId::new("expected-sub").expect("subscription");
        let watch_expectation =
            QualificationConcurrentWatchExpectationV5::new(expected_subscription.clone(), 0);
        let wrong_subscription =
            QualificationConcurrentSubscriptionId::new("wrong-sub").expect("subscription");
        assert_eq!(
            builder.record_watch(
                "watch-1",
                "node-a",
                4,
                7,
                &watch_expectation,
                &QualificationNodeReply::ConcurrentWatchFinished {
                    subscription_id: wrong_subscription,
                    complete_through_journal_sequence: 0,
                    events: Vec::new(),
                },
            ),
            Err(QualificationConcurrentV5Error::Watch)
        );
        assert!(builder
            .record_watch(
                "watch-1",
                "node-a",
                4,
                7,
                &watch_expectation,
                &QualificationNodeReply::ConcurrentWatchFinished {
                    subscription_id: expected_subscription.clone(),
                    complete_through_journal_sequence: 0,
                    events: Vec::new(),
                },
            )
            .is_ok());

        let mut impossible_agreement = readiness_reply(0, false, 0);
        let QualificationNodeReply::ConcurrentReadiness { status } = &mut impossible_agreement
        else {
            unreachable!("readiness fixture")
        };
        status.fresh_reachable_voters = 1;
        status.agreeing_voters = 2;
        assert_eq!(
            builder.record_readiness("ready-0-0", "node-z", 0, 1, &impossible_agreement,),
            Err(QualificationConcurrentV5Error::Readiness)
        );
        assert!(builder
            .record_readiness("ready-0-0", "node-z", 0, 1, &readiness_reply(0, true, 0),)
            .is_ok());
    }

    #[test]
    fn batch_reply_must_match_every_dispatched_slot_transactionally() {
        let processes = processes();
        let mut builder = QualificationConcurrentHistoryV5Builder::new(
            "history-v5",
            processes.clone(),
            schedule(&processes),
            contract(),
        )
        .expect("valid history builder");
        let valid_batch = partial_batch_reply();
        let expected_mutations = batch_mutations(&valid_batch);

        let mut omitted = valid_batch.clone();
        let QualificationNodeReply::ConcurrentBatch { slots, .. } = &mut omitted else {
            unreachable!("typed fixture is a batch")
        };
        slots.pop();
        assert_eq!(
            builder.record_batch("batch-1", "node-z", 5, 6, &expected_mutations, &omitted,),
            Err(QualificationConcurrentV5Error::Reply)
        );

        let mut reordered = valid_batch.clone();
        let QualificationNodeReply::ConcurrentBatch { slots, .. } = &mut reordered else {
            unreachable!("typed fixture is a batch")
        };
        slots.swap(0, 1);
        assert_eq!(
            builder.record_batch("batch-1", "node-z", 5, 6, &expected_mutations, &reordered,),
            Err(QualificationConcurrentV5Error::Reply)
        );

        let mut substituted = valid_batch.clone();
        let QualificationNodeReply::ConcurrentBatch { slots, .. } = &mut substituted else {
            unreachable!("typed fixture is a batch")
        };
        slots[0].mutation.value_sha256 = digest('f');
        assert_eq!(
            builder.record_batch("batch-1", "node-z", 5, 6, &expected_mutations, &substituted,),
            Err(QualificationConcurrentV5Error::Reply)
        );

        assert!(builder
            .record_batch("batch-1", "node-z", 5, 6, &expected_mutations, &valid_batch,)
            .is_ok());
    }

    #[test]
    fn future_readiness_journal_head_is_rejected_at_finalization() {
        let mut builder = complete_builder();
        let last = builder
            .readiness
            .iter_mut()
            .rev()
            .find(|row| row.process_id == "node-m")
            .expect("terminal node-m readiness");
        let QualificationConcurrentOperationV5::Readiness { journal_head, .. } =
            &mut last.operation
        else {
            unreachable!("readiness row")
        };
        *journal_head = Some(2);
        assert_eq!(
            builder.finish().err(),
            Some(QualificationConcurrentV5Error::Readiness)
        );
    }

    #[test]
    fn unused_lease_or_inconclusive_batch_cannot_finalize() {
        let mut unused_lease = complete_builder();
        unused_lease
            .contract
            .preacquired_leases
            .push(lease('f', 'f', 9));
        unused_lease
            .contract
            .preacquired_leases
            .sort_by(|left, right| left.key_sha256.cmp(&right.key_sha256));
        assert_eq!(
            unused_lease.finish().err(),
            Some(QualificationConcurrentV5Error::Lease)
        );

        let mut inconclusive = complete_builder();
        inconclusive.batches[0].outcome = QualificationConcurrentBatchOutcome::Indeterminate;
        for slot in &mut inconclusive.batches[0].slots {
            slot.outcome = QualificationConcurrentBatchSlotOutcome::Indeterminate;
        }
        assert_eq!(
            inconclusive.finish().err(),
            Some(QualificationConcurrentV5Error::MissingCoverage)
        );
    }

    #[test]
    fn watch_sequences_must_follow_serialized_batch_slot_order() {
        let mut builder = complete_builder();
        let second_mutation = mutation('b', 'e', 8, None, 1);
        builder.batches.push(PendingBatchV5 {
            operation_id: "batch-2".to_owned(),
            process_id: "node-a".to_owned(),
            started_ns: 9,
            completed_ns: 10,
            invocation_sequence: 2,
            outcome: QualificationConcurrentBatchOutcome::Completed,
            slots: vec![QualificationConcurrentBatchSlotResult {
                slot_index: 1,
                outcome: QualificationConcurrentBatchSlotOutcome::Success,
                mutation: second_mutation.clone(),
            }],
        });
        builder.last_batch_completed_ns = Some(10);
        let first_record = match &builder.watch {
            Some(watch) => watch.events[0].record.clone(),
            None => panic!("complete fixture watch"),
        };
        let second_record = record(&second_mutation);
        let watch = builder.watch.as_mut().expect("complete fixture watch");
        watch.completed_ns = 11;
        watch.complete_through = 2;
        watch.events = vec![
            QualificationConcurrentWatchEvent {
                journal_sequence: 1,
                record: second_record.clone(),
            },
            QualificationConcurrentWatchEvent {
                journal_sequence: 2,
                record: first_record.clone(),
            },
        ];
        let restore = builder.restore.as_mut().expect("complete fixture restore");
        restore.started_ns = 11;
        restore.completed_ns = 12;
        restore.records = vec![first_record, second_record];
        restore
            .records
            .sort_by(|left, right| left.key_sha256.cmp(&right.key_sha256));
        assert_eq!(
            builder.finish().err(),
            Some(QualificationConcurrentV5Error::Correlation)
        );
    }

    #[test]
    fn every_quorum_loss_transition_requires_a_bounded_sample() {
        let mut builder = complete_builder();
        builder.contract.max_readiness_gap_ns = 60;
        builder
            .readiness
            .retain(|row| !(20..=21).contains(&row.started_ns));
        for sequence in builder.readiness_sequences.values_mut() {
            *sequence = sequence.saturating_sub(1);
        }
        for process_id in ["node-z", "node-a", "node-m"] {
            let mut sequence = 0;
            for row in builder
                .readiness
                .iter_mut()
                .filter(|row| row.process_id == process_id)
            {
                sequence += 1;
                let QualificationConcurrentOperationV5::Readiness {
                    sample_sequence, ..
                } = &mut row.operation
                else {
                    unreachable!("readiness row")
                };
                *sample_sequence = sequence;
            }
        }
        assert_eq!(
            builder.finish().err(),
            Some(QualificationConcurrentV5Error::Readiness)
        );
    }

    #[test]
    fn same_completion_instant_does_not_prove_readiness_recovery() {
        let mut builder = complete_builder();
        builder.contract.max_readiness_gap_ns = 60;
        {
            let mut node_rows = builder
                .readiness
                .iter_mut()
                .filter(|row| row.process_id == "node-z");
            let recovery = node_rows.nth(2).expect("recovery sample");
            let QualificationConcurrentOperationV5::Readiness {
                state,
                raft_term,
                raft_commit_index,
                raft_applied_index,
                journal_head,
                ..
            } = &mut recovery.operation
            else {
                unreachable!("readiness row")
            };
            *state = QualificationConcurrentReadinessStateV5::NotReady;
            *raft_term = None;
            *raft_commit_index = None;
            *raft_applied_index = None;
            *journal_head = None;
            let recovery_completed_ns = recovery.completed_ns;
            let equal_completion = node_rows.next().expect("next ready sample");
            equal_completion.started_ns = recovery_completed_ns;
            equal_completion.completed_ns = recovery_completed_ns;
        }
        builder.readiness.retain(|row| {
            row.process_id != "node-z"
                || matches!(
                    row.operation,
                    QualificationConcurrentOperationV5::Readiness {
                        sample_sequence,
                        ..
                    } if sample_sequence <= 4
                )
        });
        builder.readiness_sequences.insert("node-z".to_owned(), 4);

        assert_eq!(
            builder.finish().err(),
            Some(QualificationConcurrentV5Error::Readiness)
        );
    }

    fn assert_frozen_checker_passes(history: &QualificationConcurrentHistoryV5) {
        let history_bytes = history.encode_json_lines().expect("history JSONL");
        let schedule_bytes = history
            .fault_schedule()
            .encode_json()
            .expect("bounded canonical fault schedule JSON");
        let schedule = history.fault_schedule();
        let contract = history.contract();
        let checker_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/check-session-ha-concurrent-history-v5.py");
        let checker_bytes = fs::read(&checker_path).expect("frozen checker bytes");
        let exact_sha256 = |raw: &[u8]| format!("sha256:{:x}", Sha256::digest(raw));

        let mut evidence: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/session-ha/candidate-evidence-v5.json"
        ))
        .expect("candidate evidence fixture");
        evidence["execution"]["history_id"] = serde_json::json!(schedule.history_id.as_str());
        evidence["execution"]["campaign_started_ns"] =
            serde_json::json!(schedule.campaign_started_ns);
        evidence["execution"]["campaign_completed_ns"] =
            serde_json::json!(schedule.campaign_completed_ns);
        evidence["execution"]["topology_members"] = serde_json::json!(schedule.process_ids.len());
        evidence["execution"]["process_ids"] = serde_json::json!(&schedule.process_ids);
        evidence["execution"]["max_readiness_gap_ns"] =
            serde_json::json!(contract.max_readiness_gap_ns());
        evidence["execution"]["fault_schedule_sha256"] =
            serde_json::json!(exact_sha256(&schedule_bytes));
        evidence["workload"]["initial_journal_head"] =
            serde_json::json!(contract.initial_journal_head());
        evidence["workload"]["state_type_sha256"] = serde_json::json!(contract.state_type_sha256());
        evidence["workload"]["preacquired_leases"] =
            serde_json::to_value(history.contract().preacquired_leases()).expect("lease evidence");
        evidence["history"]["sha256"] = serde_json::json!(exact_sha256(&history_bytes));
        evidence["history"]["operation_count"] = serde_json::json!(history.rows().len());
        evidence["checker"]["sha256"] = serde_json::json!(exact_sha256(&checker_bytes));

        let directory = tempfile::tempdir().expect("checker directory");
        let history_path = directory.path().join("history.jsonl");
        let schedule_path = directory.path().join("fault-schedule.json");
        let evidence_path = directory.path().join("evidence.json");
        fs::write(&history_path, &history_bytes).expect("write history");
        fs::write(&schedule_path, &schedule_bytes).expect("write schedule");
        fs::write(
            &evidence_path,
            serde_json::to_vec_pretty(&evidence).expect("evidence JSON"),
        )
        .expect("write evidence");

        let output = Command::new("python3")
            .arg(checker_path)
            .arg("--evidence")
            .arg(evidence_path)
            .arg("--fault-schedule")
            .arg(schedule_path)
            .arg("--history")
            .arg(history_path)
            .output()
            .expect("run frozen checker");
        assert!(
            output.status.success(),
            "checker rejected collector output: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let result: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("checker output JSON");
        assert_eq!(result["status"], "pass");
    }

    #[test]
    fn finalized_history_passes_the_frozen_independent_checker() {
        let history = complete_builder().finish().expect("checker-ready history");
        assert_frozen_checker_passes(&history);
    }

    #[test]
    fn five_node_nonzero_multi_batch_history_passes_the_frozen_checker() {
        let history_id = "history-v5-five";
        let process_ids = ["node-z", "node-a", "node-m", "node-b", "node-y"];
        let processes = process_ids
            .iter()
            .enumerate()
            .map(|(index, process_id)| {
                QualificationConcurrentProcessV5::try_new(*process_id, index as u64 + 1)
                    .expect("five-node process")
            })
            .collect::<Vec<_>>();
        let all_pairs = (0..processes.len())
            .flat_map(|left| (left + 1..processes.len()).map(move |right| (right, left)))
            .collect::<Vec<_>>();
        let mut schedule_builder =
            QualificationConcurrentFaultScheduleV5Builder::new(history_id, &processes, 0)
                .expect("five-node schedule");
        schedule_builder
            .push_interval(19, &[4, 2, 0, 3, 1], &all_pairs)
            .expect("initial five-node quorum");
        schedule_builder
            .push_interval(39, &[0, 1, 2, 3, 4], &[])
            .expect("five-node quorum loss");
        schedule_builder
            .push_interval(100, &[0, 1, 2, 3, 4], &all_pairs)
            .expect("five-node quorum recovery");

        let contract = QualificationConcurrentHistoryContractV5::try_new(
            history_id,
            10,
            25,
            vec![lease('a', 'd', 7), lease('b', 'e', 8)],
        )
        .expect("five-node contract");
        let state_type_sha256 = contract.state_type_sha256().to_owned();
        let mutation = |key_character: char,
                        owner_character: char,
                        fence: u64,
                        expected_generation: Option<u64>,
                        new_generation: u64| {
            QualificationConcurrentMutationSnapshot {
                key_sha256: digest(key_character),
                expected_generation,
                new_generation,
                owner_sha256: digest(owner_character),
                fence,
                state_class:
                    crate::qualification::QualificationConcurrentStateClass::AuthoritativeSession,
                state_type_sha256: state_type_sha256.clone(),
                expires_at_ns: None,
                value_sha256: digest(key_character),
            }
        };
        let first_a = mutation('a', 'd', 7, None, 1);
        let conflict_b = mutation('b', 'e', 8, Some(1), 2);
        let second_a = mutation('a', 'd', 7, Some(1), 2);
        let first_batch_expectations = vec![first_a.clone(), conflict_b.clone()];
        let second_batch_expectations = vec![second_a.clone()];
        let mut builder = QualificationConcurrentHistoryV5Builder::new(
            history_id,
            processes,
            schedule_builder.finish().expect("five-node fault schedule"),
            contract,
        )
        .expect("five-node collector");
        builder
            .record_batch(
                "batch-1",
                "node-z",
                5,
                6,
                &first_batch_expectations,
                &QualificationNodeReply::ConcurrentBatch {
                    outcome: QualificationConcurrentBatchOutcome::Completed,
                    slots: vec![
                        QualificationConcurrentBatchSlotResult {
                            slot_index: 1,
                            outcome: QualificationConcurrentBatchSlotOutcome::Success,
                            mutation: first_a.clone(),
                        },
                        QualificationConcurrentBatchSlotResult {
                            slot_index: 2,
                            outcome: QualificationConcurrentBatchSlotOutcome::Conflict,
                            mutation: conflict_b.clone(),
                        },
                    ],
                },
            )
            .expect("five-node partial batch");
        builder
            .record_batch(
                "batch-2",
                "node-a",
                7,
                8,
                &second_batch_expectations,
                &QualificationNodeReply::ConcurrentBatch {
                    outcome: QualificationConcurrentBatchOutcome::Completed,
                    slots: vec![QualificationConcurrentBatchSlotResult {
                        slot_index: 1,
                        outcome: QualificationConcurrentBatchSlotOutcome::Success,
                        mutation: second_a.clone(),
                    }],
                },
            )
            .expect("same-key generation advance");
        let subscription_id =
            QualificationConcurrentSubscriptionId::new("watch-five").expect("subscription");
        let watch_expectation =
            QualificationConcurrentWatchExpectationV5::new(subscription_id.clone(), 10);
        builder
            .record_watch(
                "watch-1",
                "node-m",
                4,
                9,
                &watch_expectation,
                &QualificationNodeReply::ConcurrentWatchFinished {
                    subscription_id: subscription_id.clone(),
                    complete_through_journal_sequence: 12,
                    events: vec![
                        QualificationConcurrentWatchEvent {
                            journal_sequence: 11,
                            record: record(&first_a),
                        },
                        QualificationConcurrentWatchEvent {
                            journal_sequence: 12,
                            record: record(&second_a),
                        },
                    ],
                },
            )
            .expect("five-node watch");
        builder
            .record_restore(
                "restore-1",
                "node-b",
                9,
                10,
                &QualificationNodeReply::ConcurrentRestore {
                    complete: true,
                    records: vec![record(&second_a)],
                },
            )
            .expect("five-node terminal restore");

        for (process_index, process_id) in process_ids.iter().enumerate() {
            for (sequence, (started_ns, completed_ns, ready, journal_head)) in [
                (0, 1, true, 10),
                (20, 21, false, 0),
                (40, 41, true, 12),
                (60, 61, true, 12),
                (80, 81, true, 12),
            ]
            .into_iter()
            .enumerate()
            {
                builder
                    .record_readiness(
                        format!("ready-five-{process_index}-{sequence}"),
                        process_id,
                        started_ns,
                        completed_ns,
                        &QualificationNodeReply::ConcurrentReadiness {
                            status: QualificationConcurrentReadiness {
                                ready,
                                reason_code: if ready {
                                    QualificationReadinessCode::Ready
                                } else {
                                    QualificationReadinessCode::NoQuorum
                                },
                                node_id: process_index as u64 + 1,
                                configured_voters: 5,
                                configured_voter_ids: vec![1, 2, 3, 4, 5],
                                fresh_reachable_voters: if ready { 3 } else { 0 },
                                agreeing_voters: if ready { 3 } else { 0 },
                                required_quorum: 3,
                                raft_term: ready.then_some(3),
                                raft_leader_id: ready.then_some(1),
                                raft_commit_index: ready.then_some(14),
                                raft_applied_index: ready.then_some(14),
                                journal_head: ready.then_some(journal_head),
                            },
                        },
                    )
                    .expect("five-node readiness");
            }
        }

        let history = builder.finish().expect("five-node checker-ready history");
        assert_eq!(history.contract().initial_journal_head(), 10);
        assert_eq!(history.rows().len(), 29);
        assert_frozen_checker_passes(&history);
    }
}
