//! Bounded, backend-neutral traffic-continuity assessment.
//!
//! This crate is **not** a traffic authority and does not issue a production
//! proof. Any caller can construct [`TrafficContinuityRecord`] input and a
//! successful [`TrafficContinuityAssessment`] says only that those supplied
//! records satisfy this bounded structural continuity policy. A trusted
//! dataplane adapter must independently authenticate its source, perform its
//! kernel readback and revocation checks, and then decide whether to wrap an
//! assessment in an adapter-owned authority.
//!
//! Inputs deliberately contain no addresses, TEIDs, SPIs, subscriber fields,
//! or packet contents. Opaque identity diagnostics are redacted.

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::fmt;
use std::num::{NonZeroU128, NonZeroU64, NonZeroUsize};
use std::time::Duration;

/// Absolute upper bound for policy durations.
pub const MAX_POLICY_DURATION: Duration = Duration::from_secs(24 * 60 * 60);
/// Absolute upper bound for records retained by one assessment.
pub const MAX_RETAINED_EVENTS: usize = 4096;

/// Binding dimension that was invalid or did not exactly match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BindingField {
    /// Stable logical session or group identity.
    SessionGroupIdentity,
    /// Stable device or attachment identity.
    DeviceAttachmentIdentity,
    /// Exact dataplane session generation.
    DataplaneSessionGeneration,
    /// Product owner generation.
    ProductOwnerGeneration,
    /// Caller ownership and reconciliation fence.
    CallerOwnershipFence,
    /// Reconciliation revision.
    ReconcileRevision,
    /// Backend process or attachment incarnation.
    BackendIncarnation,
    /// Observation-source epoch.
    SourceEpoch,
    /// Origin of the adapter's monotonic clock.
    ClockOriginIdentity,
}

macro_rules! opaque_u128 {
    ($name:ident, $description:literal, $field:ident) => {
        #[doc = $description]
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(NonZeroU128);

        impl $name {
            #[doc = concat!("Construct a nonzero ", $description, ".")]
            pub fn new(value: u128) -> Result<Self, TrafficContinuityError> {
                NonZeroU128::new(value)
                    .map(Self)
                    .ok_or(TrafficContinuityError::InvalidBinding {
                        field: BindingField::$field,
                    })
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!("<redacted-", stringify!($name), ">"))
            }
        }
    };
}

macro_rules! opaque_u64 {
    ($name:ident, $description:literal, $field:ident) => {
        #[doc = $description]
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(NonZeroU64);

        impl $name {
            #[doc = concat!("Construct a nonzero ", $description, ".")]
            pub fn new(value: u64) -> Result<Self, TrafficContinuityError> {
                NonZeroU64::new(value)
                    .map(Self)
                    .ok_or(TrafficContinuityError::InvalidBinding {
                        field: BindingField::$field,
                    })
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!("<redacted-", stringify!($name), ">"))
            }
        }
    };
}

opaque_u128!(
    SessionGroupIdentity,
    "opaque stable logical session or group identity",
    SessionGroupIdentity
);
opaque_u128!(
    DeviceAttachmentIdentity,
    "opaque stable device or attachment identity",
    DeviceAttachmentIdentity
);
opaque_u64!(
    DataplaneSessionGeneration,
    "opaque exact dataplane session generation",
    DataplaneSessionGeneration
);
opaque_u64!(
    ProductOwnerGeneration,
    "opaque product owner generation",
    ProductOwnerGeneration
);
opaque_u128!(
    CallerOwnershipFence,
    "opaque caller ownership and reconciliation fence",
    CallerOwnershipFence
);
opaque_u64!(
    ReconcileRevision,
    "opaque reconciliation revision",
    ReconcileRevision
);
opaque_u64!(
    BackendIncarnation,
    "opaque backend incarnation",
    BackendIncarnation
);
opaque_u64!(SourceEpoch, "opaque source epoch", SourceEpoch);
opaque_u128!(
    ClockOriginIdentity,
    "opaque monotonic clock-origin identity",
    ClockOriginIdentity
);

/// Opaque, nonzero flow correlation supplied by an owning adapter.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowCorrelation(NonZeroU128);

impl FlowCorrelation {
    /// Construct a nonzero opaque flow correlation.
    pub fn new(value: u128) -> Result<Self, TrafficContinuityError> {
        NonZeroU128::new(value)
            .map(Self)
            .ok_or(TrafficContinuityError::InvalidFlowCorrelation)
    }
}

impl fmt::Debug for FlowCorrelation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FlowCorrelation(<redacted>)")
    }
}

impl fmt::Display for FlowCorrelation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-flow-correlation>")
    }
}

/// Exact opaque binding required of every supplied traffic event.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrafficBinding {
    session_group_identity: SessionGroupIdentity,
    device_attachment_identity: DeviceAttachmentIdentity,
    dataplane_session_generation: DataplaneSessionGeneration,
    product_owner_generation: ProductOwnerGeneration,
    caller_ownership_fence: CallerOwnershipFence,
    reconcile_revision: ReconcileRevision,
    backend_incarnation: BackendIncarnation,
    source_epoch: SourceEpoch,
    clock_origin_identity: ClockOriginIdentity,
}

impl TrafficBinding {
    /// Construct the complete exact binding for one assessment attempt.
    ///
    /// Each dimension remains an explicit argument so an adapter cannot omit
    /// a generation or substitute an unrelated opaque aggregate.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        session_group_identity: SessionGroupIdentity,
        device_attachment_identity: DeviceAttachmentIdentity,
        dataplane_session_generation: DataplaneSessionGeneration,
        product_owner_generation: ProductOwnerGeneration,
        caller_ownership_fence: CallerOwnershipFence,
        reconcile_revision: ReconcileRevision,
        backend_incarnation: BackendIncarnation,
        source_epoch: SourceEpoch,
        clock_origin_identity: ClockOriginIdentity,
    ) -> Self {
        Self {
            session_group_identity,
            device_attachment_identity,
            dataplane_session_generation,
            product_owner_generation,
            caller_ownership_fence,
            reconcile_revision,
            backend_incarnation,
            source_epoch,
            clock_origin_identity,
        }
    }

    fn mismatch_field(&self, observed: &Self) -> Option<BindingField> {
        if self.session_group_identity != observed.session_group_identity {
            Some(BindingField::SessionGroupIdentity)
        } else if self.device_attachment_identity != observed.device_attachment_identity {
            Some(BindingField::DeviceAttachmentIdentity)
        } else if self.dataplane_session_generation != observed.dataplane_session_generation {
            Some(BindingField::DataplaneSessionGeneration)
        } else if self.product_owner_generation != observed.product_owner_generation {
            Some(BindingField::ProductOwnerGeneration)
        } else if self.caller_ownership_fence != observed.caller_ownership_fence {
            Some(BindingField::CallerOwnershipFence)
        } else if self.reconcile_revision != observed.reconcile_revision {
            Some(BindingField::ReconcileRevision)
        } else if self.backend_incarnation != observed.backend_incarnation {
            Some(BindingField::BackendIncarnation)
        } else if self.source_epoch != observed.source_epoch {
            Some(BindingField::SourceEpoch)
        } else if self.clock_origin_identity != observed.clock_origin_identity {
            Some(BindingField::ClockOriginIdentity)
        } else {
            None
        }
    }
}

impl fmt::Debug for TrafficBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrafficBinding(<redacted>)")
    }
}

/// Direction that independently requires sustained continuity evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrafficDirection {
    /// Traffic from the access network toward the core.
    AccessToCore,
    /// Traffic from the core toward the access network.
    CoreToAccess,
}

/// Adapter-provided monotonic time from its bound clock origin.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonotonicTime(Duration);

impl MonotonicTime {
    /// Create a timestamp relative to the adapter's clock origin.
    #[must_use]
    pub const fn from_duration_since_origin(value: Duration) -> Self {
        Self(value)
    }

    fn elapsed_since(self, earlier: Self) -> Option<Duration> {
        self.0.checked_sub(earlier.0)
    }

    fn checked_add(self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration).map(Self)
    }
}

impl fmt::Debug for MonotonicTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MonotonicTime(<monotonic>)")
    }
}

/// Bounded immutable policy used for one continuity assessment.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TrafficContinuityPolicy {
    minimum_samples_per_direction: NonZeroUsize,
    minimum_window_per_direction: Duration,
    maximum_freshness: Duration,
    maximum_evidence_age: Duration,
    maximum_assessment_lifetime: Duration,
    maximum_retained_events: NonZeroUsize,
}

impl TrafficContinuityPolicy {
    /// Create a bounded policy.
    ///
    /// At least two samples per direction and a non-zero window are required
    /// so every accepted policy can prove elapsed continuity. No stronger
    /// production-grade lower bound is imposed here: the owning trusted
    /// adapter is responsible for selecting and comparing an adequate policy.
    /// A returned assessment retains this exact immutable policy and exposes
    /// [`TrafficContinuityAssessment::matches_policy`] for that comparison.
    pub fn new(
        minimum_samples_per_direction: usize,
        minimum_window_per_direction: Duration,
        maximum_freshness: Duration,
        maximum_evidence_age: Duration,
        maximum_assessment_lifetime: Duration,
        maximum_retained_events: usize,
    ) -> Result<Self, TrafficContinuityError> {
        let samples = NonZeroUsize::new(minimum_samples_per_direction).ok_or(
            TrafficContinuityError::InvalidPolicy {
                code: "minimum_samples_zero",
            },
        )?;
        if samples.get() < 2 {
            return Err(TrafficContinuityError::InvalidPolicy {
                code: "minimum_samples_shorter_than_window",
            });
        }
        if minimum_window_per_direction.is_zero() {
            return Err(TrafficContinuityError::InvalidPolicy {
                code: "minimum_window_zero",
            });
        }
        if maximum_freshness.is_zero() {
            return Err(TrafficContinuityError::InvalidPolicy {
                code: "maximum_freshness_zero",
            });
        }
        if maximum_evidence_age.is_zero() {
            return Err(TrafficContinuityError::InvalidPolicy {
                code: "maximum_evidence_age_zero",
            });
        }
        if maximum_assessment_lifetime.is_zero() {
            return Err(TrafficContinuityError::InvalidPolicy {
                code: "maximum_assessment_lifetime_zero",
            });
        }
        let retained = NonZeroUsize::new(maximum_retained_events).ok_or(
            TrafficContinuityError::InvalidPolicy {
                code: "maximum_retained_events_zero",
            },
        )?;
        if [
            minimum_window_per_direction,
            maximum_freshness,
            maximum_evidence_age,
            maximum_assessment_lifetime,
        ]
        .into_iter()
        .any(|duration| duration > MAX_POLICY_DURATION)
        {
            return Err(TrafficContinuityError::InvalidPolicy {
                code: "duration_exceeds_bound",
            });
        }
        if maximum_evidence_age < minimum_window_per_direction {
            return Err(TrafficContinuityError::InvalidPolicy {
                code: "evidence_age_shorter_than_window",
            });
        }
        if retained.get() > MAX_RETAINED_EVENTS {
            return Err(TrafficContinuityError::InvalidPolicy {
                code: "maximum_retained_events_exceeds_bound",
            });
        }
        let required_bidirectional_samples =
            samples
                .get()
                .checked_mul(2)
                .ok_or(TrafficContinuityError::InvalidPolicy {
                    code: "minimum_samples_exceed_retention",
                })?;
        if required_bidirectional_samples > retained.get() {
            return Err(TrafficContinuityError::InvalidPolicy {
                code: "minimum_samples_exceed_retention",
            });
        }
        Ok(Self {
            minimum_samples_per_direction: samples,
            minimum_window_per_direction,
            maximum_freshness,
            maximum_evidence_age,
            maximum_assessment_lifetime,
            maximum_retained_events: retained,
        })
    }

    /// Minimum samples required in each direction of one correlated flow.
    #[must_use]
    pub const fn minimum_samples_per_direction(self) -> usize {
        self.minimum_samples_per_direction.get()
    }

    /// Minimum span required in each direction of one correlated flow.
    #[must_use]
    pub const fn minimum_window_per_direction(self) -> Duration {
        self.minimum_window_per_direction
    }

    /// Maximum age of the freshest sample in either direction.
    #[must_use]
    pub const fn maximum_freshness(self) -> Duration {
        self.maximum_freshness
    }

    /// Maximum age of any sample retained for the assessment.
    #[must_use]
    pub const fn maximum_evidence_age(self) -> Duration {
        self.maximum_evidence_age
    }

    /// Maximum lifetime of a successful assessment.
    ///
    /// Actual expiry is the earliest of this cap, both directional freshness
    /// deadlines, and the retained-evidence deadline.
    #[must_use]
    pub const fn maximum_assessment_lifetime(self) -> Duration {
        self.maximum_assessment_lifetime
    }

    /// Maximum number of events accepted by one assessment.
    ///
    /// Construction requires capacity for at least the minimum sample count
    /// in both directions, so the policy cannot be impossible by definition.
    #[must_use]
    pub const fn maximum_retained_events(self) -> usize {
        self.maximum_retained_events.get()
    }
}

impl fmt::Debug for TrafficContinuityPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrafficContinuityPolicy")
            .field(
                "minimum_samples_per_direction",
                &self.minimum_samples_per_direction,
            )
            .field(
                "minimum_window_per_direction",
                &self.minimum_window_per_direction,
            )
            .field("maximum_freshness", &self.maximum_freshness)
            .field("maximum_evidence_age", &self.maximum_evidence_age)
            .field(
                "maximum_assessment_lifetime",
                &self.maximum_assessment_lifetime,
            )
            .field("maximum_retained_events", &self.maximum_retained_events)
            .finish()
    }
}

/// Explicit non-event condition supplied by an adapter source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceOutcome {
    /// The source lost one or more observations.
    Loss,
    /// The source reset and continuity cannot be established.
    Reset,
    /// The source overflowed a bounded producer queue or map.
    Overflow,
    /// The source detected a gap in its own record stream.
    Gap,
    /// The source detected configuration, ownership, or attachment drift.
    Drift,
    /// The source has terminally failed.
    Terminal,
    /// The source deliberately ended this assessment input.
    Idle,
}

/// Structural input event for the non-authoritative evaluator.
///
/// Any caller may construct this value. It carries no provenance assertion;
/// trusted-source authentication belongs to the adapter that uses the result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrafficContinuityEvent {
    binding: TrafficBinding,
    direction: TrafficDirection,
    flow_correlation: FlowCorrelation,
    cursor: NonZeroU128,
    observed_at: MonotonicTime,
}

impl TrafficContinuityEvent {
    /// Construct a structural continuity input event.
    ///
    /// Cursor zero and the terminal cursor value are refused. The evaluator
    /// requires every later value to be strictly greater, so an adapter may
    /// supply either a producer cursor or an exact monotonic source sequence.
    /// Sparse values are valid: a source that can detect missing records must
    /// report [`SourceOutcome::Gap`] explicitly, and an authoritative adapter
    /// must independently detect producer loss before accepting an assessment.
    pub fn new(
        binding: TrafficBinding,
        direction: TrafficDirection,
        flow_correlation: FlowCorrelation,
        cursor: u128,
        observed_at: MonotonicTime,
    ) -> Result<Self, TrafficContinuityError> {
        let cursor = NonZeroU128::new(cursor).ok_or(TrafficContinuityError::CursorGap)?;
        if cursor.get() == u128::MAX {
            return Err(TrafficContinuityError::CursorExhausted);
        }
        Ok(Self {
            binding,
            direction,
            flow_correlation,
            cursor,
            observed_at,
        })
    }
}

/// Public, constructible input record for [`TrafficContinuitySource`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrafficContinuityRecord {
    /// A structural traffic event.
    Event(TrafficContinuityEvent),
    /// An explicit source condition.
    Outcome(SourceOutcome),
}

/// Generic record source used by an owning adapter.
///
/// The source must emit [`SourceOutcome::Idle`] to finish an assessment.
/// There is intentionally no `Option`/EOF success path. Cursor continuity
/// covers only records this source presents; producer loss, reset, overflow,
/// and drift must be surfaced as a non-idle [`SourceOutcome`] or rejected by
/// the owning adapter before it wraps an assessment.
pub trait TrafficContinuitySource {
    /// Return the next input record.
    fn next_record(&mut self) -> TrafficContinuityRecord;
}

/// Fail-closed result of a structural continuity assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrafficContinuityError {
    /// A binding component was zero.
    InvalidBinding {
        /// The invalid component.
        field: BindingField,
    },
    /// A flow correlation was zero.
    InvalidFlowCorrelation,
    /// A policy was zero, inconsistent, or exceeded a hard bound.
    InvalidPolicy {
        /// Stable, value-free error code.
        code: &'static str,
    },
    /// An event binding differed from the expected exact binding.
    BindingMismatch {
        /// The first mismatching component.
        field: BindingField,
    },
    /// A non-idle source condition was received.
    SourceOutcome {
        /// The reported source condition.
        outcome: SourceOutcome,
    },
    /// A zero cursor was supplied; detected producer gaps use `SourceOutcome::Gap`.
    CursorGap,
    /// A cursor repeated or moved backwards.
    CursorReordered,
    /// A terminal cursor value was supplied or successor cursor cannot exist.
    CursorExhausted,
    /// Event timestamps moved backwards.
    TimestampRegression,
    /// An event timestamp is later than adapter-provided assessment time.
    FutureTimestamp,
    /// One direction has no events.
    OneWayEvidence,
    /// At least one retained event exceeded the maximum evidence age.
    EvidenceExpired,
    /// A complete bidirectional window no longer met the freshness bound.
    FreshnessExpired,
    /// No single opaque flow satisfies both directional sample/window gates.
    UnpairedFlowCorrelation,
    /// The bounded retained-event capacity was exceeded.
    RetentionExceeded,
    /// Assessment expiry could not be represented.
    AssessmentExpiryOverflow,
    /// This evaluator has already returned an assessment or an error.
    EvaluatorClosed,
}

impl fmt::Display for TrafficContinuityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::InvalidBinding { .. } => "invalid_binding",
            Self::InvalidFlowCorrelation => "invalid_flow_correlation",
            Self::InvalidPolicy { code } => code,
            Self::BindingMismatch { .. } => "binding_mismatch",
            Self::SourceOutcome { .. } => "source_outcome",
            Self::CursorGap => "cursor_gap",
            Self::CursorReordered => "cursor_reordered",
            Self::CursorExhausted => "cursor_exhausted",
            Self::TimestampRegression => "timestamp_regression",
            Self::FutureTimestamp => "future_timestamp",
            Self::OneWayEvidence => "one_way_evidence",
            Self::EvidenceExpired => "evidence_expired",
            Self::FreshnessExpired => "freshness_expired",
            Self::UnpairedFlowCorrelation => "unpaired_flow_correlation",
            Self::RetentionExceeded => "retention_exceeded",
            Self::AssessmentExpiryOverflow => "assessment_expiry_overflow",
            Self::EvaluatorClosed => "evaluator_closed",
        };
        formatter.write_str(code)
    }
}

impl Error for TrafficContinuityError {}

/// Redaction-safe summary of a completed continuity assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficContinuityAssessmentSummary {
    access_to_core_samples: usize,
    core_to_access_samples: usize,
    issued_at: MonotonicTime,
    expires_at: MonotonicTime,
}

impl TrafficContinuityAssessmentSummary {
    /// Number of structural access-to-core samples considered.
    #[must_use]
    pub const fn access_to_core_samples(self) -> usize {
        self.access_to_core_samples
    }

    /// Number of structural core-to-access samples considered.
    #[must_use]
    pub const fn core_to_access_samples(self) -> usize {
        self.core_to_access_samples
    }

    /// Adapter-provided monotonic time at which assessment completed.
    #[must_use]
    pub const fn issued_at(self) -> MonotonicTime {
        self.issued_at
    }

    /// Exclusive adapter-provided monotonic expiry time.
    #[must_use]
    pub const fn expires_at(self) -> MonotonicTime {
        self.expires_at
    }
}

/// Non-authoritative, non-cloneable result of one successful evaluation.
///
/// It is not unforgeable evidence. A trusted adapter must check both
/// [`Self::matches_binding`] and [`Self::matches_policy`] while also enforcing
/// trusted-source, kernel-readback, clock-origin, and revocation state.
pub struct TrafficContinuityAssessment {
    binding: TrafficBinding,
    policy: TrafficContinuityPolicy,
    summary: TrafficContinuityAssessmentSummary,
}

impl TrafficContinuityAssessment {
    /// Return a redaction-safe assessment summary.
    #[must_use]
    pub const fn summary(&self) -> TrafficContinuityAssessmentSummary {
        self.summary
    }

    /// Return whether this assessment retained the exact supplied binding.
    #[must_use]
    pub fn matches_binding(&self, binding: TrafficBinding) -> bool {
        self.binding == binding
    }

    /// Return whether this assessment retained the exact supplied policy.
    ///
    /// Policy strength is the adapter's responsibility; this comparison only
    /// prevents accidentally wrapping an assessment under a different policy.
    #[must_use]
    pub fn matches_policy(&self, policy: TrafficContinuityPolicy) -> bool {
        self.policy == policy
    }

    /// Return whether caller-provided monotonic time is in `[issued, expiry)`.
    ///
    /// This is only a convenience check because the caller supplies time. A
    /// trusted adapter must use its bound kernel boot-monotonic clock and also
    /// enforce revocation state before treating any result as authoritative.
    #[must_use]
    pub fn is_valid_at(&self, now: MonotonicTime) -> bool {
        self.summary.issued_at <= now && now < self.summary.expires_at
    }
}

impl fmt::Debug for TrafficContinuityAssessment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrafficContinuityAssessment")
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

/// One-shot bounded evaluator of caller-supplied structural records.
pub struct TrafficContinuityEvaluator {
    expected: TrafficBinding,
    policy: TrafficContinuityPolicy,
    retained: VecDeque<TrafficContinuityEvent>,
    last_cursor: Option<NonZeroU128>,
    last_observed_at: Option<MonotonicTime>,
    closed: bool,
}

impl TrafficContinuityEvaluator {
    /// Construct an open one-shot evaluator for one exact binding and policy.
    #[must_use]
    pub fn new(expected: TrafficBinding, policy: TrafficContinuityPolicy) -> Self {
        Self {
            expected,
            policy,
            retained: VecDeque::with_capacity(policy.maximum_retained_events.get()),
            last_cursor: None,
            last_observed_at: None,
            closed: false,
        }
    }

    /// Consume records until explicit idle and return one structural assessment.
    ///
    /// This method permanently closes after either success or any error. That
    /// prevents a later retry from using a retained valid prefix.
    pub fn evaluate<S: TrafficContinuitySource>(
        &mut self,
        source: &mut S,
        now: MonotonicTime,
    ) -> Result<TrafficContinuityAssessment, TrafficContinuityError> {
        if self.closed {
            return Err(TrafficContinuityError::EvaluatorClosed);
        }
        let result = self.evaluate_open(source, now);
        self.closed = true;
        result
    }

    fn evaluate_open<S: TrafficContinuitySource>(
        &mut self,
        source: &mut S,
        now: MonotonicTime,
    ) -> Result<TrafficContinuityAssessment, TrafficContinuityError> {
        loop {
            match source.next_record() {
                TrafficContinuityRecord::Event(event) => self.accept(event)?,
                TrafficContinuityRecord::Outcome(SourceOutcome::Idle) => break,
                TrafficContinuityRecord::Outcome(outcome) => {
                    return Err(TrafficContinuityError::SourceOutcome { outcome });
                }
            }
        }
        self.assess(now)
    }

    fn accept(&mut self, event: TrafficContinuityEvent) -> Result<(), TrafficContinuityError> {
        if let Some(field) = self.expected.mismatch_field(&event.binding) {
            return Err(TrafficContinuityError::BindingMismatch { field });
        }
        if self
            .last_cursor
            .is_some_and(|cursor| event.cursor <= cursor)
        {
            return Err(TrafficContinuityError::CursorReordered);
        }
        if let Some(previous) = self.last_observed_at {
            if event.observed_at < previous {
                return Err(TrafficContinuityError::TimestampRegression);
            }
        }
        if self.retained.len() == self.policy.maximum_retained_events.get() {
            return Err(TrafficContinuityError::RetentionExceeded);
        }
        self.last_cursor = Some(event.cursor);
        self.last_observed_at = Some(event.observed_at);
        self.retained.push_back(event);
        Ok(())
    }

    fn assess(
        &self,
        now: MonotonicTime,
    ) -> Result<TrafficContinuityAssessment, TrafficContinuityError> {
        let mut flows = HashMap::<FlowCorrelation, FlowWindow>::new();
        let mut saw_access = false;
        let mut saw_core = false;
        for event in &self.retained {
            let age = now
                .elapsed_since(event.observed_at)
                .ok_or(TrafficContinuityError::FutureTimestamp)?;
            if age >= self.policy.maximum_evidence_age {
                return Err(TrafficContinuityError::EvidenceExpired);
            }
            let flow = flows.entry(event.flow_correlation).or_default();
            match event.direction {
                TrafficDirection::AccessToCore => {
                    saw_access = true;
                    flow.access_to_core.observe(event.observed_at);
                }
                TrafficDirection::CoreToAccess => {
                    saw_core = true;
                    flow.core_to_access.observe(event.observed_at);
                }
            }
        }
        if !saw_access || !saw_core {
            return Err(TrafficContinuityError::OneWayEvidence);
        }
        let mut paired = flows.values().filter(|flow| {
            self.direction_satisfies_samples_and_window(&flow.access_to_core)
                && self.direction_satisfies_samples_and_window(&flow.core_to_access)
        });
        let mut saw_complete_stale_window = false;
        let qualifying = paired.find(|flow| {
            let fresh = self.direction_is_fresh(&flow.access_to_core, now)
                && self.direction_is_fresh(&flow.core_to_access, now);
            saw_complete_stale_window |= !fresh;
            fresh
        });
        let Some(qualifying) = qualifying else {
            if saw_complete_stale_window {
                return Err(TrafficContinuityError::FreshnessExpired);
            }
            return Err(TrafficContinuityError::UnpairedFlowCorrelation);
        };
        let lifetime_deadline = now
            .checked_add(self.policy.maximum_assessment_lifetime)
            .ok_or(TrafficContinuityError::AssessmentExpiryOverflow)?;
        let access_freshness_deadline = qualifying
            .access_to_core
            .last
            .and_then(|last| last.checked_add(self.policy.maximum_freshness))
            .ok_or(TrafficContinuityError::AssessmentExpiryOverflow)?;
        let core_freshness_deadline = qualifying
            .core_to_access
            .last
            .and_then(|last| last.checked_add(self.policy.maximum_freshness))
            .ok_or(TrafficContinuityError::AssessmentExpiryOverflow)?;
        let evidence_deadline = self
            .retained
            .front()
            .and_then(|event| {
                event
                    .observed_at
                    .checked_add(self.policy.maximum_evidence_age)
            })
            .ok_or(TrafficContinuityError::AssessmentExpiryOverflow)?;
        let expires_at = lifetime_deadline
            .min(access_freshness_deadline)
            .min(core_freshness_deadline)
            .min(evidence_deadline);
        if expires_at <= now {
            return Err(TrafficContinuityError::EvidenceExpired);
        }
        Ok(TrafficContinuityAssessment {
            binding: self.expected,
            policy: self.policy,
            summary: TrafficContinuityAssessmentSummary {
                access_to_core_samples: qualifying.access_to_core.count,
                core_to_access_samples: qualifying.core_to_access.count,
                issued_at: now,
                expires_at,
            },
        })
    }

    fn direction_satisfies_samples_and_window(&self, window: &DirectionWindow) -> bool {
        if window.count < self.policy.minimum_samples_per_direction.get() {
            return false;
        }
        let (Some(first), Some(last)) = (window.first, window.last) else {
            return false;
        };
        last.elapsed_since(first)
            .is_some_and(|span| span >= self.policy.minimum_window_per_direction)
    }

    fn direction_is_fresh(&self, window: &DirectionWindow, now: MonotonicTime) -> bool {
        window.last.is_some_and(|last| {
            now.elapsed_since(last)
                .is_some_and(|freshness| freshness < self.policy.maximum_freshness)
        })
    }
}

#[derive(Default)]
struct DirectionWindow {
    count: usize,
    first: Option<MonotonicTime>,
    last: Option<MonotonicTime>,
}

impl DirectionWindow {
    fn observe(&mut self, observed_at: MonotonicTime) {
        self.count += 1;
        self.first.get_or_insert(observed_at);
        self.last = Some(observed_at);
    }
}

#[derive(Default)]
struct FlowWindow {
    access_to_core: DirectionWindow,
    core_to_access: DirectionWindow,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ScriptedSource {
        records: VecDeque<TrafficContinuityRecord>,
    }

    impl ScriptedSource {
        fn new(records: impl IntoIterator<Item = TrafficContinuityRecord>) -> Self {
            Self {
                records: records.into_iter().collect(),
            }
        }
    }

    impl TrafficContinuitySource for ScriptedSource {
        fn next_record(&mut self) -> TrafficContinuityRecord {
            self.records
                .pop_front()
                .unwrap_or(TrafficContinuityRecord::Outcome(SourceOutcome::Terminal))
        }
    }

    fn time(seconds: u64) -> MonotonicTime {
        MonotonicTime::from_duration_since_origin(Duration::from_secs(seconds))
    }

    fn binding(seed: u128) -> TrafficBinding {
        let counter = u64::try_from(seed).expect("small test seed");
        TrafficBinding::new(
            SessionGroupIdentity::new(seed).expect("test identity"),
            DeviceAttachmentIdentity::new(seed).expect("test attachment"),
            DataplaneSessionGeneration::new(counter).expect("test generation"),
            ProductOwnerGeneration::new(counter).expect("test owner generation"),
            CallerOwnershipFence::new(seed).expect("test fence"),
            ReconcileRevision::new(counter).expect("test revision"),
            BackendIncarnation::new(counter).expect("test incarnation"),
            SourceEpoch::new(counter).expect("test epoch"),
            ClockOriginIdentity::new(seed).expect("test clock origin"),
        )
    }

    fn correlation(seed: u128) -> FlowCorrelation {
        FlowCorrelation::new(seed).expect("test correlation")
    }

    fn policy() -> TrafficContinuityPolicy {
        TrafficContinuityPolicy::new(
            2,
            Duration::from_secs(2),
            Duration::from_secs(5),
            Duration::from_secs(20),
            Duration::from_secs(3),
            8,
        )
        .expect("test policy")
    }

    fn event(
        binding: TrafficBinding,
        direction: TrafficDirection,
        correlation: FlowCorrelation,
        cursor: u128,
        at: u64,
    ) -> TrafficContinuityRecord {
        TrafficContinuityRecord::Event(
            TrafficContinuityEvent::new(binding, direction, correlation, cursor, time(at))
                .expect("test event"),
        )
    }

    fn valid_records(expected: TrafficBinding) -> Vec<TrafficContinuityRecord> {
        let flow = correlation(1);
        vec![
            event(expected, TrafficDirection::AccessToCore, flow, 1, 10),
            event(expected, TrafficDirection::CoreToAccess, flow, 2, 11),
            event(expected, TrafficDirection::AccessToCore, flow, 3, 12),
            event(expected, TrafficDirection::CoreToAccess, flow, 4, 13),
            TrafficContinuityRecord::Outcome(SourceOutcome::Idle),
        ]
    }

    fn assert_error(
        result: Result<TrafficContinuityAssessment, TrafficContinuityError>,
        expected: TrafficContinuityError,
    ) {
        assert_eq!(result.err(), Some(expected));
    }

    #[test]
    fn assesses_sustained_paired_bidirectional_continuity() {
        let expected = binding(1);
        let selected_policy = policy();
        let mut source = ScriptedSource::new(valid_records(expected));
        let mut evaluator = TrafficContinuityEvaluator::new(expected, selected_policy);
        let assessment = evaluator
            .evaluate(&mut source, time(14))
            .expect("assessment");
        assert_eq!(assessment.summary().access_to_core_samples(), 2);
        assert_eq!(assessment.summary().core_to_access_samples(), 2);
        assert!(assessment.matches_binding(expected));
        assert!(assessment.matches_policy(selected_policy));
        assert!(assessment.is_valid_at(time(14)));
        assert!(assessment.is_valid_at(time(16)));
        assert!(!assessment.is_valid_at(time(17)));
    }

    #[test]
    fn packet_freshness_caps_a_longer_requested_assessment_lifetime() {
        let expected = binding(1);
        let selected_policy = TrafficContinuityPolicy::new(
            2,
            Duration::from_secs(2),
            Duration::from_secs(5),
            Duration::from_secs(20),
            Duration::from_secs(30),
            8,
        )
        .expect("test policy");
        let mut source = ScriptedSource::new(valid_records(expected));
        let mut evaluator = TrafficContinuityEvaluator::new(expected, selected_policy);
        let assessment = evaluator
            .evaluate(&mut source, time(14))
            .expect("assessment");

        // Access-to-core's last sample is at t=12, so its exclusive t=17
        // freshness deadline wins over both the requested t=44 lifetime and
        // the later core-to-access deadline.
        assert!(assessment.is_valid_at(time(16)));
        assert!(!assessment.is_valid_at(time(17)));
    }

    #[test]
    fn red_exact_binding_comparison_cannot_be_removed() {
        let expected = binding(1);
        let mut source = ScriptedSource::new([
            event(
                binding(2),
                TrafficDirection::AccessToCore,
                correlation(1),
                1,
                1,
            ),
            TrafficContinuityRecord::Outcome(SourceOutcome::Idle),
        ]);
        let mut evaluator = TrafficContinuityEvaluator::new(expected, policy());
        assert_error(
            evaluator.evaluate(&mut source, time(2)),
            TrafficContinuityError::BindingMismatch {
                field: BindingField::SessionGroupIdentity,
            },
        );
    }

    #[test]
    fn red_paired_correlation_check_cannot_be_removed() {
        let expected = binding(1);
        let mut source = ScriptedSource::new([
            event(
                expected,
                TrafficDirection::AccessToCore,
                correlation(1),
                1,
                10,
            ),
            event(
                expected,
                TrafficDirection::CoreToAccess,
                correlation(2),
                2,
                11,
            ),
            event(
                expected,
                TrafficDirection::AccessToCore,
                correlation(1),
                3,
                12,
            ),
            event(
                expected,
                TrafficDirection::CoreToAccess,
                correlation(2),
                4,
                13,
            ),
            TrafficContinuityRecord::Outcome(SourceOutcome::Idle),
        ]);
        let mut evaluator = TrafficContinuityEvaluator::new(expected, policy());
        assert_error(
            evaluator.evaluate(&mut source, time(14)),
            TrafficContinuityError::UnpairedFlowCorrelation,
        );
    }

    #[test]
    fn adversarial_unrelated_traffic_cannot_stretch_one_correlated_pair() {
        let expected = binding(1);
        let paired = correlation(1);
        let access_only = correlation(2);
        let core_only = correlation(3);
        let mut source = ScriptedSource::new([
            event(expected, TrafficDirection::AccessToCore, access_only, 1, 10),
            event(expected, TrafficDirection::CoreToAccess, core_only, 2, 10),
            event(expected, TrafficDirection::AccessToCore, paired, 3, 11),
            event(expected, TrafficDirection::CoreToAccess, paired, 4, 11),
            event(expected, TrafficDirection::AccessToCore, access_only, 5, 13),
            event(expected, TrafficDirection::CoreToAccess, core_only, 6, 13),
            TrafficContinuityRecord::Outcome(SourceOutcome::Idle),
        ]);
        let mut evaluator = TrafficContinuityEvaluator::new(expected, policy());
        assert_error(
            evaluator.evaluate(&mut source, time(14)),
            TrafficContinuityError::UnpairedFlowCorrelation,
        );
    }

    #[test]
    fn rejects_every_exact_binding_dimension() {
        let expected = binding(9);
        let fields = [
            (binding(10), BindingField::SessionGroupIdentity),
            (
                TrafficBinding::new(
                    SessionGroupIdentity::new(9).expect("test"),
                    DeviceAttachmentIdentity::new(10).expect("test"),
                    DataplaneSessionGeneration::new(9).expect("test"),
                    ProductOwnerGeneration::new(9).expect("test"),
                    CallerOwnershipFence::new(9).expect("test"),
                    ReconcileRevision::new(9).expect("test"),
                    BackendIncarnation::new(9).expect("test"),
                    SourceEpoch::new(9).expect("test"),
                    ClockOriginIdentity::new(9).expect("test"),
                ),
                BindingField::DeviceAttachmentIdentity,
            ),
            (
                TrafficBinding::new(
                    SessionGroupIdentity::new(9).expect("test"),
                    DeviceAttachmentIdentity::new(9).expect("test"),
                    DataplaneSessionGeneration::new(10).expect("test"),
                    ProductOwnerGeneration::new(9).expect("test"),
                    CallerOwnershipFence::new(9).expect("test"),
                    ReconcileRevision::new(9).expect("test"),
                    BackendIncarnation::new(9).expect("test"),
                    SourceEpoch::new(9).expect("test"),
                    ClockOriginIdentity::new(9).expect("test"),
                ),
                BindingField::DataplaneSessionGeneration,
            ),
            (
                TrafficBinding::new(
                    SessionGroupIdentity::new(9).expect("test"),
                    DeviceAttachmentIdentity::new(9).expect("test"),
                    DataplaneSessionGeneration::new(9).expect("test"),
                    ProductOwnerGeneration::new(10).expect("test"),
                    CallerOwnershipFence::new(9).expect("test"),
                    ReconcileRevision::new(9).expect("test"),
                    BackendIncarnation::new(9).expect("test"),
                    SourceEpoch::new(9).expect("test"),
                    ClockOriginIdentity::new(9).expect("test"),
                ),
                BindingField::ProductOwnerGeneration,
            ),
            (
                TrafficBinding::new(
                    SessionGroupIdentity::new(9).expect("test"),
                    DeviceAttachmentIdentity::new(9).expect("test"),
                    DataplaneSessionGeneration::new(9).expect("test"),
                    ProductOwnerGeneration::new(9).expect("test"),
                    CallerOwnershipFence::new(10).expect("test"),
                    ReconcileRevision::new(9).expect("test"),
                    BackendIncarnation::new(9).expect("test"),
                    SourceEpoch::new(9).expect("test"),
                    ClockOriginIdentity::new(9).expect("test"),
                ),
                BindingField::CallerOwnershipFence,
            ),
            (
                TrafficBinding::new(
                    SessionGroupIdentity::new(9).expect("test"),
                    DeviceAttachmentIdentity::new(9).expect("test"),
                    DataplaneSessionGeneration::new(9).expect("test"),
                    ProductOwnerGeneration::new(9).expect("test"),
                    CallerOwnershipFence::new(9).expect("test"),
                    ReconcileRevision::new(10).expect("test"),
                    BackendIncarnation::new(9).expect("test"),
                    SourceEpoch::new(9).expect("test"),
                    ClockOriginIdentity::new(9).expect("test"),
                ),
                BindingField::ReconcileRevision,
            ),
            (
                TrafficBinding::new(
                    SessionGroupIdentity::new(9).expect("test"),
                    DeviceAttachmentIdentity::new(9).expect("test"),
                    DataplaneSessionGeneration::new(9).expect("test"),
                    ProductOwnerGeneration::new(9).expect("test"),
                    CallerOwnershipFence::new(9).expect("test"),
                    ReconcileRevision::new(9).expect("test"),
                    BackendIncarnation::new(10).expect("test"),
                    SourceEpoch::new(9).expect("test"),
                    ClockOriginIdentity::new(9).expect("test"),
                ),
                BindingField::BackendIncarnation,
            ),
            (
                TrafficBinding::new(
                    SessionGroupIdentity::new(9).expect("test"),
                    DeviceAttachmentIdentity::new(9).expect("test"),
                    DataplaneSessionGeneration::new(9).expect("test"),
                    ProductOwnerGeneration::new(9).expect("test"),
                    CallerOwnershipFence::new(9).expect("test"),
                    ReconcileRevision::new(9).expect("test"),
                    BackendIncarnation::new(9).expect("test"),
                    SourceEpoch::new(10).expect("test"),
                    ClockOriginIdentity::new(9).expect("test"),
                ),
                BindingField::SourceEpoch,
            ),
            (
                TrafficBinding::new(
                    SessionGroupIdentity::new(9).expect("test"),
                    DeviceAttachmentIdentity::new(9).expect("test"),
                    DataplaneSessionGeneration::new(9).expect("test"),
                    ProductOwnerGeneration::new(9).expect("test"),
                    CallerOwnershipFence::new(9).expect("test"),
                    ReconcileRevision::new(9).expect("test"),
                    BackendIncarnation::new(9).expect("test"),
                    SourceEpoch::new(9).expect("test"),
                    ClockOriginIdentity::new(10).expect("test"),
                ),
                BindingField::ClockOriginIdentity,
            ),
        ];
        for (observed, field) in fields {
            let mut source = ScriptedSource::new([
                event(
                    observed,
                    TrafficDirection::AccessToCore,
                    correlation(1),
                    1,
                    1,
                ),
                TrafficContinuityRecord::Outcome(SourceOutcome::Idle),
            ]);
            let mut evaluator = TrafficContinuityEvaluator::new(expected, policy());
            assert_error(
                evaluator.evaluate(&mut source, time(2)),
                TrafficContinuityError::BindingMismatch { field },
            );
        }
    }

    #[test]
    fn rejects_explicit_loss_reset_overflow_gap_drift_and_terminal() {
        for outcome in [
            SourceOutcome::Loss,
            SourceOutcome::Reset,
            SourceOutcome::Overflow,
            SourceOutcome::Gap,
            SourceOutcome::Drift,
            SourceOutcome::Terminal,
        ] {
            let mut source = ScriptedSource::new([TrafficContinuityRecord::Outcome(outcome)]);
            let mut evaluator = TrafficContinuityEvaluator::new(binding(1), policy());
            assert_error(
                evaluator.evaluate(&mut source, time(1)),
                TrafficContinuityError::SourceOutcome { outcome },
            );
        }
    }

    #[test]
    fn accepts_sparse_monotonic_sequence_and_rejects_reordering_and_terminal_cursor() {
        let expected = binding(1);
        let flow = correlation(1);
        let mut sparse = ScriptedSource::new([
            event(expected, TrafficDirection::AccessToCore, flow, 10, 1),
            event(expected, TrafficDirection::CoreToAccess, flow, 20, 1),
            event(expected, TrafficDirection::AccessToCore, flow, 30, 3),
            event(expected, TrafficDirection::CoreToAccess, flow, 40, 3),
            TrafficContinuityRecord::Outcome(SourceOutcome::Idle),
        ]);
        assert!(TrafficContinuityEvaluator::new(expected, policy())
            .evaluate(&mut sparse, time(3))
            .is_ok());

        let scenarios = [
            (
                vec![
                    event(expected, TrafficDirection::AccessToCore, flow, 1, 1),
                    event(expected, TrafficDirection::CoreToAccess, flow, 1, 2),
                ],
                TrafficContinuityError::CursorReordered,
            ),
            (
                vec![
                    event(expected, TrafficDirection::AccessToCore, flow, 3, 1),
                    event(expected, TrafficDirection::CoreToAccess, flow, 2, 2),
                ],
                TrafficContinuityError::CursorReordered,
            ),
        ];
        for (records, expected_error) in scenarios {
            let mut source = ScriptedSource::new(records);
            let mut evaluator = TrafficContinuityEvaluator::new(expected, policy());
            assert_error(evaluator.evaluate(&mut source, time(3)), expected_error);
        }
        assert_eq!(
            TrafficContinuityEvent::new(expected, TrafficDirection::AccessToCore, flow, 0, time(1))
                .err(),
            Some(TrafficContinuityError::CursorGap)
        );
        assert_eq!(
            TrafficContinuityEvent::new(
                expected,
                TrafficDirection::AccessToCore,
                flow,
                u128::MAX,
                time(1)
            )
            .err(),
            Some(TrafficContinuityError::CursorExhausted)
        );
    }

    #[test]
    fn rejects_one_way_and_per_direction_compressed_window() {
        let expected = binding(1);
        let flow = correlation(1);
        let mut one_way = ScriptedSource::new([
            event(expected, TrafficDirection::AccessToCore, flow, 1, 10),
            event(expected, TrafficDirection::AccessToCore, flow, 2, 12),
            TrafficContinuityRecord::Outcome(SourceOutcome::Idle),
        ]);
        let mut evaluator = TrafficContinuityEvaluator::new(expected, policy());
        assert_error(
            evaluator.evaluate(&mut one_way, time(13)),
            TrafficContinuityError::OneWayEvidence,
        );

        let mut compressed = ScriptedSource::new([
            event(expected, TrafficDirection::AccessToCore, flow, 1, 10),
            event(expected, TrafficDirection::AccessToCore, flow, 2, 10),
            event(expected, TrafficDirection::CoreToAccess, flow, 3, 11),
            event(expected, TrafficDirection::CoreToAccess, flow, 4, 13),
            TrafficContinuityRecord::Outcome(SourceOutcome::Idle),
        ]);
        let mut evaluator = TrafficContinuityEvaluator::new(expected, policy());
        assert_error(
            evaluator.evaluate(&mut compressed, time(14)),
            TrafficContinuityError::UnpairedFlowCorrelation,
        );
    }

    #[test]
    fn rejects_timestamp_regression_future_stale_events_and_stale_direction() {
        let expected = binding(1);
        let flow = correlation(1);
        let mut regression = ScriptedSource::new([
            event(expected, TrafficDirection::AccessToCore, flow, 1, 20),
            event(expected, TrafficDirection::CoreToAccess, flow, 2, 1),
            event(expected, TrafficDirection::AccessToCore, flow, 3, 21),
        ]);
        let mut evaluator = TrafficContinuityEvaluator::new(expected, policy());
        assert_error(
            evaluator.evaluate(&mut regression, time(22)),
            TrafficContinuityError::TimestampRegression,
        );

        let mut future = ScriptedSource::new(valid_records(expected));
        let mut evaluator = TrafficContinuityEvaluator::new(expected, policy());
        assert_error(
            evaluator.evaluate(&mut future, time(12)),
            TrafficContinuityError::FutureTimestamp,
        );

        let mut stale_earlier = ScriptedSource::new([
            event(expected, TrafficDirection::AccessToCore, flow, 1, 1),
            event(expected, TrafficDirection::CoreToAccess, flow, 2, 12),
            event(expected, TrafficDirection::AccessToCore, flow, 3, 13),
            event(expected, TrafficDirection::CoreToAccess, flow, 4, 14),
            TrafficContinuityRecord::Outcome(SourceOutcome::Idle),
        ]);
        let short_age = TrafficContinuityPolicy::new(
            2,
            Duration::from_secs(1),
            Duration::from_secs(5),
            Duration::from_secs(10),
            Duration::from_secs(2),
            8,
        )
        .expect("policy");
        let mut evaluator = TrafficContinuityEvaluator::new(expected, short_age);
        assert_error(
            evaluator.evaluate(&mut stale_earlier, time(15)),
            TrafficContinuityError::EvidenceExpired,
        );

        let mut stale_access = ScriptedSource::new([
            event(expected, TrafficDirection::AccessToCore, flow, 1, 10),
            event(expected, TrafficDirection::AccessToCore, flow, 2, 12),
            event(expected, TrafficDirection::CoreToAccess, flow, 3, 20),
            event(expected, TrafficDirection::CoreToAccess, flow, 4, 22),
            TrafficContinuityRecord::Outcome(SourceOutcome::Idle),
        ]);
        let mut evaluator = TrafficContinuityEvaluator::new(expected, policy());
        assert_error(
            evaluator.evaluate(&mut stale_access, time(24)),
            TrafficContinuityError::FreshnessExpired,
        );
    }

    #[test]
    fn freshness_deadline_is_exclusive_and_invalidates_completed_windows() {
        let expected = binding(1);
        for now in [time(17), time(18)] {
            let mut source = ScriptedSource::new(valid_records(expected));
            let mut evaluator = TrafficContinuityEvaluator::new(expected, policy());
            assert_error(
                evaluator.evaluate(&mut source, now),
                TrafficContinuityError::FreshnessExpired,
            );
        }
    }

    #[test]
    fn assessment_validity_is_half_open_and_rejects_clock_rollback() {
        let expected = binding(1);
        let mut source = ScriptedSource::new(valid_records(expected));
        let mut evaluator = TrafficContinuityEvaluator::new(expected, policy());
        let assessment = evaluator
            .evaluate(&mut source, time(14))
            .expect("assessment");
        assert!(!assessment.is_valid_at(time(13)));
        assert!(assessment.is_valid_at(assessment.summary().issued_at()));
        assert!(!assessment.is_valid_at(assessment.summary().expires_at()));
    }

    #[test]
    fn rejects_monotonic_expiry_overflow_near_clock_limit() {
        let expected = binding(1);
        let flow = correlation(1);
        let now_duration = Duration::MAX
            .checked_sub(Duration::from_secs(2))
            .expect("bounded test time");
        let first = MonotonicTime::from_duration_since_origin(
            now_duration
                .checked_sub(Duration::from_secs(1))
                .expect("bounded test time"),
        );
        let last = MonotonicTime::from_duration_since_origin(now_duration);
        let at = |direction, cursor, observed_at| {
            TrafficContinuityRecord::Event(
                TrafficContinuityEvent::new(expected, direction, flow, cursor, observed_at)
                    .expect("test event"),
            )
        };
        let mut source = ScriptedSource::new([
            at(TrafficDirection::AccessToCore, 1, first),
            at(TrafficDirection::CoreToAccess, 2, first),
            at(TrafficDirection::AccessToCore, 3, last),
            at(TrafficDirection::CoreToAccess, 4, last),
            TrafficContinuityRecord::Outcome(SourceOutcome::Idle),
        ]);
        let overflow_policy = TrafficContinuityPolicy::new(
            2,
            Duration::from_secs(1),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
            4,
        )
        .expect("test policy");
        let mut evaluator = TrafficContinuityEvaluator::new(expected, overflow_policy);
        assert_error(
            evaluator.evaluate(&mut source, last),
            TrafficContinuityError::AssessmentExpiryOverflow,
        );
    }

    #[test]
    fn permanently_closes_after_success_or_any_fail_closed_prefix() {
        let expected = binding(1);
        let flow = correlation(1);
        let mut success_source = ScriptedSource::new(valid_records(expected));
        let mut success = TrafficContinuityEvaluator::new(expected, policy());
        assert!(success.evaluate(&mut success_source, time(14)).is_ok());
        assert_error(
            success.evaluate(&mut success_source, time(14)),
            TrafficContinuityError::EvaluatorClosed,
        );

        let failing_cases = [
            (
                vec![
                    event(expected, TrafficDirection::AccessToCore, flow, 1, 10),
                    event(expected, TrafficDirection::CoreToAccess, flow, 2, 11),
                    event(expected, TrafficDirection::AccessToCore, flow, 3, 12),
                    event(binding(2), TrafficDirection::CoreToAccess, flow, 4, 13),
                ],
                TrafficContinuityError::BindingMismatch {
                    field: BindingField::SessionGroupIdentity,
                },
                policy(),
            ),
            (
                vec![
                    event(expected, TrafficDirection::AccessToCore, flow, 1, 10),
                    event(expected, TrafficDirection::CoreToAccess, flow, 2, 11),
                    event(expected, TrafficDirection::AccessToCore, flow, 3, 12),
                    event(expected, TrafficDirection::CoreToAccess, flow, 3, 13),
                ],
                TrafficContinuityError::CursorReordered,
                policy(),
            ),
            (
                vec![
                    event(expected, TrafficDirection::AccessToCore, flow, 1, 10),
                    event(expected, TrafficDirection::CoreToAccess, flow, 2, 11),
                    event(expected, TrafficDirection::AccessToCore, flow, 3, 12),
                    TrafficContinuityRecord::Outcome(SourceOutcome::Terminal),
                ],
                TrafficContinuityError::SourceOutcome {
                    outcome: SourceOutcome::Terminal,
                },
                policy(),
            ),
            (
                vec![
                    event(expected, TrafficDirection::AccessToCore, flow, 1, 10),
                    event(expected, TrafficDirection::CoreToAccess, flow, 2, 11),
                    event(expected, TrafficDirection::AccessToCore, flow, 3, 12),
                    event(expected, TrafficDirection::CoreToAccess, flow, 4, 13),
                    event(expected, TrafficDirection::AccessToCore, flow, 5, 14),
                ],
                TrafficContinuityError::RetentionExceeded,
                TrafficContinuityPolicy::new(
                    2,
                    Duration::from_secs(2),
                    Duration::from_secs(5),
                    Duration::from_secs(20),
                    Duration::from_secs(3),
                    4,
                )
                .expect("policy"),
            ),
        ];
        for (records, expected_error, selected_policy) in failing_cases {
            let mut source = ScriptedSource::new(records);
            let mut evaluator = TrafficContinuityEvaluator::new(expected, selected_policy);
            assert_error(evaluator.evaluate(&mut source, time(14)), expected_error);
            assert_error(
                evaluator.evaluate(&mut source, time(14)),
                TrafficContinuityError::EvaluatorClosed,
            );
        }
    }

    #[test]
    fn rejects_zero_and_out_of_bounds_policy_values() {
        assert!(TrafficContinuityPolicy::new(
            0,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            1
        )
        .is_err());
        assert_eq!(
            TrafficContinuityPolicy::new(
                1,
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
                2,
            )
            .unwrap_err(),
            TrafficContinuityError::InvalidPolicy {
                code: "minimum_samples_shorter_than_window",
            }
        );
        assert!(TrafficContinuityPolicy::new(
            2,
            Duration::ZERO,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            4
        )
        .is_err());
        assert!(TrafficContinuityPolicy::new(
            2,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            MAX_RETAINED_EVENTS + 1
        )
        .is_err());
        assert_eq!(
            TrafficContinuityPolicy::new(
                3,
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
                5,
            )
            .unwrap_err(),
            TrafficContinuityError::InvalidPolicy {
                code: "minimum_samples_exceed_retention",
            }
        );
        assert!(TrafficContinuityPolicy::new(
            MAX_RETAINED_EVENTS / 2,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            MAX_RETAINED_EVENTS,
        )
        .is_ok());
    }

    #[test]
    fn evaluator_and_assessment_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TrafficContinuityEvaluator>();
        assert_send_sync::<TrafficContinuityAssessment>();
    }
}
