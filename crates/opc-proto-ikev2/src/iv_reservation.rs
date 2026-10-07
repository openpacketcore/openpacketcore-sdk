//! Durable reservation ordering for ordinary local AES-GCM IVs.
//!
//! The consumer owns atomic persistence of the SA keys, descriptor, limits and
//! exclusive reservation end, and fences a single writer. These helpers cannot
//! prove a storage acknowledgement or prevent rollback of a consumer's record.
//! Reservations belong to initial key setup or state-changing work, never a
//! periodic liveness write. Replaying committed bytes needs no allocation.
//! No canonical reply, Message-ID window or complete recovery lifecycle is enabled.

use std::{error::Error, fmt};

use crate::Ikev2ProtectedPayloadCryptoError;

mod domain;
pub use domain::{Ikev2AesGcmIvAllocation, Ikev2AesGcmIvDomain};

/// Conservative SDK ceiling on reserved ordinary IV positions per direction key.
///
/// This 2^32 ceiling is a local policy, not an RFC-mandated invocation count.
/// Skipped positions count against it. Callers may select a lower ceiling.
/// It is independent of the much higher ordinary/canonical wire partition.
pub const IKEV2_AES_GCM_MAX_RESERVED_ALLOCATIONS: u64 = 1_u64 << 32;

/// Immutable per-key usage and rekey/Delete headroom limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ikev2AesGcmIvLimits {
    hard_ceiling: u64,
    control_reserve: u64,
    control_budget: (u32, u32, u32),
}

impl Ikev2AesGcmIvLimits {
    /// Derive headroom from bounded newly sealed outbound control traffic.
    ///
    /// `control_messages` is the maximum messages per attempt, at least two for
    /// IKE rekey and Delete; every message can use `max_fragments` fresh IVs and
    /// every attempt can create new bytes. Exact-byte retransmits use no IVs.
    /// The caller must account for all outbound requests and responses in these
    /// budgets. They are immutable for this key epoch, including after restore.
    ///
    /// # Errors
    /// Returns `InvalidLimits` for zero/overflowing budgets, insufficient ordinary
    /// space, or a hard ceiling above [`IKEV2_AES_GCM_MAX_RESERVED_ALLOCATIONS`].
    pub fn new(
        hard_ceiling: u64,
        control_messages: u32,
        max_fragments: u32,
        attempts: u32,
    ) -> Result<Self, Ikev2AesGcmIvReservationError> {
        let control_reserve = u64::from(control_messages)
            .checked_mul(u64::from(max_fragments))
            .and_then(|value| value.checked_mul(u64::from(attempts)))
            .ok_or(Ikev2AesGcmIvReservationError::InvalidLimits)?;
        if control_messages < 2
            || max_fragments == 0
            || attempts == 0
            || hard_ceiling > IKEV2_AES_GCM_MAX_RESERVED_ALLOCATIONS
            || control_reserve >= hard_ceiling
        {
            return Err(Ikev2AesGcmIvReservationError::InvalidLimits);
        }
        Ok(Self {
            hard_ceiling,
            control_reserve,
            control_budget: (control_messages, max_fragments, attempts),
        })
    }

    /// Exclusive end of all ordinary and control allocations under this key.
    pub const fn hard_ceiling(self) -> u64 {
        self.hard_ceiling
    }

    /// Number of positions reserved for bounded rekey/Delete traffic.
    pub const fn control_reserve(self) -> u64 {
        self.control_reserve
    }

    /// Original `(control_messages, max_fragments, attempts)` inputs to persist.
    ///
    /// Rebuild with these inputs and [`Self::hard_ceiling`] using [`Self::new`].
    pub const fn control_budget(self) -> (u32, u32, u32) {
        self.control_budget
    }

    /// Exclusive end for ordinary allocations; reaching it requires rekey.
    pub const fn soft_threshold(self) -> u64 {
        self.hard_ceiling - self.control_reserve
    }

    fn check_position(
        self,
        value: u64,
        purpose: Ikev2AesGcmIvPurpose,
    ) -> Result<(), Ikev2AesGcmIvReservationError> {
        if value >= self.hard_ceiling {
            Err(Ikev2AesGcmIvReservationError::Exhausted)
        } else if purpose == Ikev2AesGcmIvPurpose::Ordinary && value >= self.soft_threshold() {
            Err(Ikev2AesGcmIvReservationError::RekeyRequired)
        } else {
            Ok(())
        }
    }
}

/// Purpose of newly sealed traffic, distinct from exact-byte retransmission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2AesGcmIvPurpose {
    /// Ordinary traffic must stop at the soft threshold.
    Ordinary,
    /// Bounded IKE rekey/Delete traffic may consume the remaining headroom.
    ///
    /// The caller owns exchange-class admission; this value alone grants none.
    Control,
}

/// Persistable reservation fields, stored atomically with the established SA.
///
/// Rebuild the descriptor from that same record's SPI pair, direction, profile
/// and keys. Persist the inputs to the immutable limits and `exclusive_end`.
/// This type defines no serialization or storage-format version. Only trusted,
/// current-format, latest fenced state may be supplied to `from_persisted`.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2AesGcmIvRecord {
    domain: Ikev2AesGcmIvDomain,
    limits: Ikev2AesGcmIvLimits,
    exclusive_end: u64,
}

impl Ikev2AesGcmIvRecord {
    /// Rebuild validated fields from the consumer's durable SA record.
    ///
    /// # Errors
    /// Returns `InvalidRecord` if the high-water exceeds the hard ceiling.
    /// Construction does not prove durability or release an allocation.
    pub fn from_persisted(
        domain: Ikev2AesGcmIvDomain,
        limits: Ikev2AesGcmIvLimits,
        exclusive_end: u64,
    ) -> Result<Self, Ikev2AesGcmIvReservationError> {
        if exclusive_end > limits.hard_ceiling {
            return Err(Ikev2AesGcmIvReservationError::InvalidRecord);
        }
        Ok(Self {
            domain,
            limits,
            exclusive_end,
        })
    }

    /// Domain that must be persisted with this reservation.
    pub const fn domain(&self) -> &Ikev2AesGcmIvDomain {
        &self.domain
    }

    /// Immutable usage limits for this key epoch.
    pub const fn limits(&self) -> Ikev2AesGcmIvLimits {
        self.limits
    }

    /// All positions below this exclusive end are discarded on restore.
    pub const fn exclusive_end(&self) -> u64 {
        self.exclusive_end
    }
}

/// Single-writer, non-cloneable ordinary-IV reservation allocator.
///
/// Writer fencing and no storage rollback are mandatory consumer preconditions.
/// Do not mix this allocator with raw-IV or legacy-counter sealing under the
/// same key epoch. Cloning records or restoring twice does not create a second
/// independent writer. Neither allocation nor sealing commits an exchange.
///
/// ```compile_fail
/// use opc_proto_ikev2::Ikev2AesGcmIvAllocator;
/// fn duplicate(allocator: Ikev2AesGcmIvAllocator) { let _ = allocator.clone(); }
/// ```
pub struct Ikev2AesGcmIvAllocator {
    domain: Ikev2AesGcmIvDomain,
    limits: Ikev2AesGcmIvLimits,
    next: u64,
    end: u64,
}

impl Ikev2AesGcmIvAllocator {
    /// Begin with unused keys and no allocated IVs; a reservation is still required.
    ///
    /// The caller must establish a fresh key epoch. Old keys with unknown IV
    /// history cannot be relabelled fresh: obtain new IKE keys through rekey.
    /// Commit the descriptor and limits with the first reservation before use.
    pub const fn fresh(domain: Ikev2AesGcmIvDomain, limits: Ikev2AesGcmIvLimits) -> Self {
        Self {
            domain,
            limits,
            next: 0,
            end: 0,
        }
    }

    /// Restore the latest fenced record and discard its entire unused tail.
    ///
    /// No IV is available until a higher reservation is committed. `expected`
    /// comes from the intended established SA, not unchecked snapshot metadata.
    ///
    /// # Errors
    /// Returns `DomainMismatch` for another key/salt, algorithm, SPI pair or direction.
    pub fn restore(
        expected: &Ikev2AesGcmIvDomain,
        record: &Ikev2AesGcmIvRecord,
    ) -> Result<Self, Ikev2AesGcmIvReservationError> {
        if expected != &record.domain {
            return Err(Ikev2AesGcmIvReservationError::DomainMismatch);
        }
        Ok(Self {
            domain: record.domain.clone(),
            limits: record.limits,
            next: record.exclusive_end,
            end: record.exclusive_end,
        })
    }

    /// Prepare an exclusive high-water record without releasing any IV.
    ///
    /// Preparation burns the proposed range locally even if the token is dropped,
    /// a commit fails, or its result is uncertain. On uncertainty, resolve the latest
    /// fenced record or commit a higher end only after older writes cannot land.
    /// While this token exists its exclusive borrow prevents allocation.
    ///
    /// # Errors
    /// Rejects zero count, replacement of an unconsumed active block, overflow,
    /// and requests crossing the applicable soft/hard limit. Rejected preparation
    /// changes no state. Smaller blocks may still fit before the threshold.
    pub fn prepare(
        &mut self,
        count: u64,
        purpose: Ikev2AesGcmIvPurpose,
    ) -> Result<Ikev2AesGcmPreparedIvReservation<'_>, Ikev2AesGcmIvReservationError> {
        if count == 0 {
            return Err(Ikev2AesGcmIvReservationError::InvalidCount);
        }
        if self.next != self.end {
            return Err(Ikev2AesGcmIvReservationError::ActiveReservation);
        }
        self.limits.check_position(self.end, purpose)?;
        let start = self.end;
        let end = start
            .checked_add(count)
            .ok_or(Ikev2AesGcmIvReservationError::Exhausted)?;
        self.limits.check_position(end - 1, purpose)?;
        let record = Ikev2AesGcmIvRecord {
            domain: self.domain.clone(),
            limits: self.limits,
            exclusive_end: end,
        };
        self.next = end;
        self.end = end;
        Ok(Ikev2AesGcmPreparedIvReservation {
            allocator: self,
            start,
            record,
        })
    }

    /// Consume one committed IV position and return a single-use sealing token.
    ///
    /// Dropping the token or a failed seal burns the IV. No storage write occurs.
    ///
    /// # Errors
    /// `ReservationRequired` means no committed block remains. `RekeyRequired`
    /// stops ordinary traffic but preserves bounded control headroom. `Exhausted`
    /// requires closing this key epoch if rekey has not already completed.
    pub fn allocate(
        &mut self,
        purpose: Ikev2AesGcmIvPurpose,
    ) -> Result<Ikev2AesGcmIvAllocation<'_>, Ikev2AesGcmIvReservationError> {
        self.limits.check_position(self.next, purpose)?;
        if self.next == self.end {
            return Err(Ikev2AesGcmIvReservationError::ReservationRequired);
        }
        let value = self.next;
        self.next += 1; // Bounded above by the validated hard ceiling, at most 2^32.
        Ok(Ikev2AesGcmIvAllocation::new(&self.domain, value))
    }
}

/// Non-cloneable reservation awaiting the caller's durable commit acknowledgement.
#[must_use = "a prepared reservation grants no IV until its exact record is committed and activated"]
pub struct Ikev2AesGcmPreparedIvReservation<'a> {
    allocator: &'a mut Ikev2AesGcmIvAllocator,
    start: u64,
    record: Ikev2AesGcmIvRecord,
}

impl Ikev2AesGcmPreparedIvReservation<'_> {
    /// Exact record to persist atomically with the descriptor's SA keys and limits.
    pub const fn record(&self) -> &Ikev2AesGcmIvRecord {
        &self.record
    }

    /// Activate only after this exact record was durably committed by the fenced owner.
    ///
    /// Supplying a clone is not proof of storage success: the caller must provide
    /// that fact and prevent any older write from rolling it back. Never call on
    /// failed/uncertain commit. Dropping the token releases no IV.
    ///
    /// # Errors
    /// Returns `CommitMismatch` if any descriptor, limit or high-water field differs;
    /// the prepared range remains burned. This token cannot be activated twice.
    pub fn activate_after_commit(
        self,
        committed: &Ikev2AesGcmIvRecord,
    ) -> Result<(), Ikev2AesGcmIvReservationError> {
        if committed != &self.record {
            return Err(Ikev2AesGcmIvReservationError::CommitMismatch);
        }
        self.allocator.next = self.start;
        Ok(())
    }
}

/// Redaction-safe validation, allocation and sealing failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ikev2AesGcmIvReservationError {
    /// Invalid SPI/profile/key material, including identical directional key/salt pairs.
    InvalidDomain,
    /// Actual SA or sealing inputs differ from the descriptor.
    DomainMismatch,
    /// Invalid, overflowing or insufficient per-key/control budget.
    InvalidLimits,
    /// Persisted exclusive high-water exceeds the key's ceiling.
    InvalidRecord,
    /// Empty reservation was requested.
    InvalidCount,
    /// An active committed block still contains unused IVs.
    ActiveReservation,
    /// A new block must be committed before allocating.
    ReservationRequired,
    /// Commit acknowledgement did not match the prepared record.
    CommitMismatch,
    /// Ordinary allocation must stop while control headroom remains.
    RekeyRequired,
    /// No adequate representable IV budget remains; do not seal under this key.
    Exhausted,
    /// The existing admitted protected-payload sealer rejected the operation.
    Crypto(Ikev2ProtectedPayloadCryptoError),
}

impl fmt::Display for Ikev2AesGcmIvReservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidDomain => "IKEv2 IV reservation invalid domain",
            Self::DomainMismatch => "IKEv2 IV reservation domain mismatch",
            Self::InvalidLimits => "IKEv2 IV reservation invalid limits",
            Self::InvalidRecord => "IKEv2 IV reservation invalid record",
            Self::InvalidCount => "IKEv2 IV reservation invalid count",
            Self::ActiveReservation => "IKEv2 IV reservation block still active",
            Self::ReservationRequired => "IKEv2 IV reservation required",
            Self::CommitMismatch => "IKEv2 IV reservation commit mismatch",
            Self::RekeyRequired => "IKEv2 IV reservation requires rekey",
            Self::Exhausted => "IKEv2 IV reservation exhausted",
            Self::Crypto(_) => "IKEv2 IV reservation sealing failed",
        })
    }
}

impl Error for Ikev2AesGcmIvReservationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Crypto(error) => Some(error),
            _ => None,
        }
    }
}

impl fmt::Debug for Ikev2AesGcmIvRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2AesGcmIvRecord")
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for Ikev2AesGcmIvAllocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2AesGcmIvAllocator")
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for Ikev2AesGcmPreparedIvReservation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2AesGcmPreparedIvReservation")
            .finish_non_exhaustive()
    }
}
