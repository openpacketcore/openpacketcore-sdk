//! Finite, durably charged ordinary-IV block attempts for genuine operation work.
//!
//! Charge persistence precedes block preparation. If either write is uncertain,
//! the runtime stays quiescent until all old writes are fenced/settled and the
//! latest operation and IV records are read back. Restoring loses permits, never
//! refunds an attempt. This module owns no store, sleep, clock or transmit loop.

use std::{error::Error as StdError, fmt};

use crate::{
    Ikev2AesGcmIvAllocator, Ikev2AesGcmIvDomain, Ikev2AesGcmIvPurpose, Ikev2AesGcmIvRecord,
    Ikev2AesGcmIvReservationError, Ikev2AesGcmPreparedIvReservation,
};

/// Immutable retry policy persisted with a single real operation.
///
/// Times are milliseconds since the Unix epoch. Use a clock that reports steps;
/// any detected step (either direction) expires the operation. The consumer must
/// retain that event across restart until the operation is terminal, not resume
/// an expired operation with a new clock sample or a replacement policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ikev2ReservationRetryPolicy {
    started_unix_ms: u64,
    deadline_unix_ms: u64,
    max_attempts: u8,
    backoff_ms: u64,
}
impl Ikev2ReservationRetryPolicy {
    /// Fix the operation's start, deadline, positive backoff and at most three attempts.
    ///
    /// Every attempted fresh block consumes an attempt, even after a failed write,
    /// cancellation or a crash before the block was prepared. Choose adequately
    /// sized blocks for the operation. This is an SDK limit, not an RFC requirement.
    /// # Errors
    /// Rejects empty/reversed lifetime, zero backoff, or attempts outside 1..=3.
    pub fn new(
        started_unix_ms: u64,
        deadline_unix_ms: u64,
        max_attempts: u8,
        backoff_ms: u64,
    ) -> Result<Self, Ikev2ReservationRetryError> {
        if started_unix_ms >= deadline_unix_ms
            || !(1..=3).contains(&max_attempts)
            || backoff_ms == 0
        {
            return Err(Ikev2ReservationRetryError::InvalidRecord);
        }
        Ok(Self {
            started_unix_ms,
            deadline_unix_ms,
            max_attempts,
            backoff_ms,
        })
    }
    /// Original operation start, never reset after restart.
    pub const fn started_unix_ms(self) -> u64 {
        self.started_unix_ms
    }
    /// Fixed exclusive deadline; a later policy cannot extend this operation.
    pub const fn deadline_unix_ms(self) -> u64 {
        self.deadline_unix_ms
    }
    /// Maximum fresh-block attempts, including abandoned committed charges.
    pub const fn max_attempts(self) -> u8 {
        self.max_attempts
    }
    /// Minimum delay between attempts; the caller waits without spinning.
    pub const fn backoff_ms(self) -> u64 {
        self.backoff_ms
    }
}

/// Retry fields stored atomically with the fenced operation they belong to.
///
/// The consumer allocates a unique operation identity within this key epoch and
/// retains its original policy. DPD, replay probes, keepalives and empty-request
/// replies cannot create such work. A new record is not evidence that a new real
/// operation occurred; do not reset an unfinished operation by calling `initial`.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2ReservationRetryRecord {
    domain: Ikev2AesGcmIvDomain,
    operation: u64,
    policy: Ikev2ReservationRetryPolicy,
    attempts: u8,
    last_attempt_unix_ms: Option<u64>,
}
impl Ikev2ReservationRetryRecord {
    /// Initial record to persist with a new real operation before retry handling.
    pub const fn initial(
        domain: Ikev2AesGcmIvDomain,
        operation: u64,
        policy: Ikev2ReservationRetryPolicy,
    ) -> Self {
        Self {
            domain,
            operation,
            policy,
            attempts: 0,
            last_attempt_unix_ms: None,
        }
    }
    /// Rebuild the latest trusted operation record, never an older saved copy.
    /// # Errors
    /// Rejects counts beyond the policy, missing/extra attempt time or a time
    /// outside the original operation lifetime.
    pub fn from_persisted(
        domain: Ikev2AesGcmIvDomain,
        operation: u64,
        policy: Ikev2ReservationRetryPolicy,
        attempts: u8,
        last_attempt_unix_ms: Option<u64>,
    ) -> Result<Self, Ikev2ReservationRetryError> {
        if attempts > policy.max_attempts
            || (attempts == 0) != last_attempt_unix_ms.is_none()
            || last_attempt_unix_ms.is_some_and(|time| {
                time < policy.started_unix_ms || time >= policy.deadline_unix_ms
            })
        {
            return Err(Ikev2ReservationRetryError::InvalidRecord);
        }
        Ok(Self {
            domain,
            operation,
            policy,
            attempts,
            last_attempt_unix_ms,
        })
    }
    /// Exact sending key domain to persist with this operation.
    pub const fn domain(&self) -> &Ikev2AesGcmIvDomain {
        &self.domain
    }
    /// Consumer's stable operation identity within the key epoch.
    pub const fn operation(&self) -> u64 {
        self.operation
    }
    /// Immutable budget/deadline/backoff fields.
    pub const fn policy(&self) -> Ikev2ReservationRetryPolicy {
        self.policy
    }
    /// Number of durably charged fresh-block attempts.
    pub const fn attempts(&self) -> u8 {
        self.attempts
    }
    /// Time at which the last attempt was charged.
    pub const fn last_attempt_unix_ms(&self) -> Option<u64> {
        self.last_attempt_unix_ms
    }
}

/// Non-accepting reservation retry result. None grants IV or transmission authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ikev2ReservationRetryError {
    /// Retry policy or persisted fields are inconsistent.
    InvalidRecord,
    /// Wrong key domain or operation identity.
    RecordMismatch,
    /// Acknowledgement differs from the exact attempted charge.
    CommitMismatch,
    /// Resolve both charge/block writes and restore latest readback before retrying.
    CommitUncertain,
    /// Positive backoff has not elapsed; wait without writing another charge/block.
    Backoff,
    /// Budget/deadline exhausted or clock discontinuity: close this operation.
    Closed,
    /// Underlying reservation rejected the operation; no new IV was released.
    Iv(Ikev2AesGcmIvReservationError),
}
impl fmt::Display for Ikev2ReservationRetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidRecord => "ike_reservation_retry_invalid_record",
            Self::RecordMismatch => "ike_reservation_retry_record_mismatch",
            Self::CommitMismatch => "ike_reservation_retry_commit_mismatch",
            Self::CommitUncertain => "ike_reservation_retry_commit_uncertain",
            Self::Backoff => "ike_reservation_retry_backoff",
            Self::Closed => "ike_reservation_retry_closed",
            Self::Iv(_) => "ike_reservation_retry_iv_failure",
        })
    }
}
impl StdError for Ikev2ReservationRetryError {}

/// Single-operation retry guard; no implicit retry loop or reserve-ahead.
///
/// Restore only after reconciling all older writes. A successful block commit
/// unquiesces the guard, but another charge is refused until the block is empty.
/// Never use bare allocator reservation calls to bypass this operation's budget.
pub struct Ikev2ReservationRetry {
    record: Ikev2ReservationRetryRecord,
    quiescent: bool,
    closed: bool,
    last_observed_unix_ms: u64,
}
impl Ikev2ReservationRetry {
    /// Restore a latest fenced operation record without refunding charges or time.
    /// # Errors
    /// Rejects another operation or key domain. Freshness/durability remain caller-owned.
    pub fn restore(
        expected: &Ikev2AesGcmIvDomain,
        operation: u64,
        record: &Ikev2ReservationRetryRecord,
    ) -> Result<Self, Ikev2ReservationRetryError> {
        if expected != &record.domain || operation != record.operation {
            return Err(Ikev2ReservationRetryError::RecordMismatch);
        }
        Ok(Self {
            record: record.clone(),
            quiescent: false,
            closed: false,
            last_observed_unix_ms: record
                .last_attempt_unix_ms
                .unwrap_or(record.policy.started_unix_ms),
        })
    }
    /// Last acknowledged charge. Quiescence requires readback, not blind reuse of this copy.
    pub const fn record(&self) -> &Ikev2ReservationRetryRecord {
        &self.record
    }

    fn check_time(
        &mut self,
        now_unix_ms: u64,
        clock_stepped: bool,
    ) -> Result<(), Ikev2ReservationRetryError> {
        if self.closed
            || clock_stepped
            || now_unix_ms < self.last_observed_unix_ms
            || now_unix_ms >= self.record.policy.deadline_unix_ms
        {
            self.closed = true;
            return Err(Ikev2ReservationRetryError::Closed);
        }
        self.last_observed_unix_ms = now_unix_ms;
        Ok(())
    }

    /// Prepare one durable attempt charge, before allocating or burning an IV block.
    ///
    /// Persist its exact record first. Backoff and deadline are checked without
    /// sleeping; the caller schedules future work. `clock_stepped` must reflect
    /// any discontinuity since operation start, including one before a restart.
    /// # Errors
    /// Refuses active blocks without charging, foreign allocators, unresolved writes,
    /// backoff, exhausted budget and expired/discontinuous time. Closed is terminal.
    pub fn prepare_attempt(
        &mut self,
        allocator: &Ikev2AesGcmIvAllocator,
        now_unix_ms: u64,
        clock_stepped: bool,
    ) -> Result<Ikev2PreparedReservationAttempt<'_>, Ikev2ReservationRetryError> {
        use Ikev2ReservationRetryError as Error;
        if self.closed {
            return Err(Error::Closed);
        }
        if self.quiescent {
            return Err(Error::CommitUncertain);
        }
        self.check_time(now_unix_ms, clock_stepped)?;
        if self.record.attempts >= self.record.policy.max_attempts {
            self.closed = true;
            return Err(Error::Closed);
        }
        if let Some(last) = self.record.last_attempt_unix_ms {
            let Some(next) = last.checked_add(self.record.policy.backoff_ms) else {
                self.closed = true;
                return Err(Error::Closed);
            };
            if now_unix_ms < next {
                return Err(Error::Backoff);
            }
        }
        allocator
            .check_reservation_available(&self.record.domain)
            .map_err(Error::Iv)?;
        let mut record = self.record.clone();
        record.attempts += 1; // Policy permits at most three attempts.
        record.last_attempt_unix_ms = Some(now_unix_ms);
        self.quiescent = true;
        Ok(Ikev2PreparedReservationAttempt {
            retry: self,
            record,
        })
    }
}

/// Charge awaiting an exact durable acknowledgement; no block has been prepared.
#[must_use = "commit the attempt charge before preparing a fresh block"]
pub struct Ikev2PreparedReservationAttempt<'a> {
    retry: &'a mut Ikev2ReservationRetry,
    record: Ikev2ReservationRetryRecord,
}
impl<'a> Ikev2PreparedReservationAttempt<'a> {
    /// Persist this record atomically with the same fenced operation.
    pub const fn record(&self) -> &Ikev2ReservationRetryRecord {
        &self.record
    }
    /// Confirm the exact durable charge and release one block-preparation permit.
    ///
    /// The caller supplies persistence truth; record equality cannot prove it.
    /// Dropping the returned permit consumes the charge and remains quiescent.
    /// # Errors
    /// Mismatch releases no permit and requires fenced readback.
    pub fn commit_after_durable(
        self,
        committed: &Ikev2ReservationRetryRecord,
    ) -> Result<Ikev2ReservationAttempt<'a>, Ikev2ReservationRetryError> {
        if committed != &self.record {
            return Err(Ikev2ReservationRetryError::CommitMismatch);
        }
        self.retry.record = self.record;
        Ok(Ikev2ReservationAttempt { retry: self.retry })
    }
}

/// Single-use charged permit, retaining the retry guard's exclusive borrow.
///
/// ```compile_fail
/// use opc_proto_ikev2::recovery::Ikev2ReservationAttempt;
/// fn duplicate(permit: Ikev2ReservationAttempt<'_>) { let _ = permit.clone(); }
/// ```
#[must_use = "abandoning this permit retains the consumed attempt and quiesces the guard"]
pub struct Ikev2ReservationAttempt<'a> {
    retry: &'a mut Ikev2ReservationRetry,
}
impl<'a> Ikev2ReservationAttempt<'a> {
    /// Consume the committed charge to prepare one slice-3 reservation.
    ///
    /// The guard stays quiescent until that reservation commits. Revalidate time
    /// after charge I/O. `Ordinary`/`Control` retain their existing exhaustive meaning.
    /// # Errors
    /// Refuses expired time, foreign allocators, reserve-ahead or slice-3 limits.
    pub fn prepare<'b>(
        self,
        allocator: &'b mut Ikev2AesGcmIvAllocator,
        count: u64,
        purpose: Ikev2AesGcmIvPurpose,
        now_unix_ms: u64,
        clock_stepped: bool,
    ) -> Result<Ikev2PreparedRetryReservation<'a, 'b>, Ikev2ReservationRetryError> {
        self.retry.check_time(now_unix_ms, clock_stepped)?;
        allocator
            .check_reservation_available(&self.retry.record.domain)
            .map_err(Ikev2ReservationRetryError::Iv)?;
        let reservation = allocator
            .prepare(count, purpose)
            .map_err(Ikev2ReservationRetryError::Iv)?;
        Ok(Ikev2PreparedRetryReservation {
            retry: self.retry,
            reservation,
        })
    }
}

/// IV reservation whose attempt is already durably charged; no IV is active yet.
#[must_use = "commit the exact high-water and recheck the deadline before activation"]
pub struct Ikev2PreparedRetryReservation<'a, 'b> {
    retry: &'a mut Ikev2ReservationRetry,
    reservation: Ikev2AesGcmPreparedIvReservation<'b>,
}
impl Ikev2PreparedRetryReservation<'_, '_> {
    /// Exact IV record to persist with this same SA/operation and existing charge.
    pub const fn record(&self) -> &Ikev2AesGcmIvRecord {
        self.reservation.record()
    }
    /// Activate only after exact durable block commitment and a fresh clock check.
    ///
    /// Persisting this block must not overwrite its already committed charge with
    /// an older operation record. Failed, uncertain or late completion releases
    /// no IV and requires reconciliation, never an immediate fresh-block retry.
    /// # Errors
    /// Rejects clock/deadline failure or a mismatching reservation acknowledgement.
    pub fn activate_after_commit(
        self,
        committed: &Ikev2AesGcmIvRecord,
        now_unix_ms: u64,
        clock_stepped: bool,
    ) -> Result<(), Ikev2ReservationRetryError> {
        self.retry.check_time(now_unix_ms, clock_stepped)?;
        self.reservation
            .activate_after_commit(committed)
            .map_err(Ikev2ReservationRetryError::Iv)?;
        self.retry.quiescent = false;
        Ok(())
    }
}

macro_rules! redacted_debug {
    ($($ty:ty),* $(,)?) => { $(impl fmt::Debug for $ty {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct(stringify!($ty)).finish_non_exhaustive()
        }
    })* };
}
redacted_debug!(
    Ikev2ReservationRetryRecord,
    Ikev2ReservationRetry,
    Ikev2PreparedReservationAttempt<'_>,
    Ikev2ReservationAttempt<'_>,
    Ikev2PreparedRetryReservation<'_, '_>
);
