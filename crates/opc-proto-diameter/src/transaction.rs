//! Loss-safe pending-request failover transactions (RFC 6733 §5.1, §5.5.4).
//!
//! This module provides the reusable [`PendingRequestTable`] /
//! [`DiameterRequestTransaction`] primitive for origin-node request failover.
//! It owns wire correctness, answer correlation across alternate connections,
//! live at-most-once completion, and a stable restored-delivery identity:
//!
//! - The first attempt carries a Hop-by-Hop identifier allocated uniquely on
//!   its connection with the T bit clear. Every failover attempt preserves the
//!   canonical request AVPs byte-for-byte, keeps the exact original End-to-End
//!   identifier and Origin-Host, sets T=1, and draws a fresh Hop-by-Hop
//!   identifier that is unique on the selected alternate connection. All
//!   attempt identifiers are retained so a late answer from either path is
//!   still recognized.
//! - Answers are correlated by (connection, Hop-by-Hop), then validated
//!   against the request's End-to-End identifier, command code, and
//!   application. Exactly one terminal completion is produced while a live
//!   transaction exists; late, duplicated, reordered, or simultaneous answers
//!   only update bounded evidence and never re-deliver a completion.
//! - Write dispositions distinguish failure before write, uncertain or
//!   partial write, successful write followed by transport loss, fixed
//!   `Destination-Host` with no valid alternate, retry exhaustion, and
//!   indeterminate completion.
//! - [`PendingRequestTable::snapshot`] emits a versioned, explicitly
//!   sensitive byte form that a consumer may place in encrypted storage.
//!   Restored pending records retransmit with T=1 and keep a stable
//!   completion token and generation. Restored delivery is at-least-once
//!   unless the consumer adds a durable claim/ack protocol (for example a
//!   compare-and-set on the completion token and generation); see
//!   [`PendingRequestTable::restore`].
//!
//! End-to-End identifiers are allocated outside this module, normally by the
//! origin-scoped [`crate::end_to_end::DiameterEndToEndIdentifierAuthority`]:
//! the consumer allocates exactly one affine identity per logical request and
//! retains it across every retry and failover attempt. This table is that
//! retention point — it never allocates or rewrites the identifier, only
//! preserves it immutably. Its duplicate-End-to-End rejection at track time
//! is a defense-in-depth invariant over its own pending set, catching
//! consumers that bypass the authority; it is not a substitute for the
//! authority's origin-scoped, time-fenced allocation.
//!
//! Attempt limits, deadlines, peer selection, and whether an alternate is
//! routable remain caller policy. Peer discovery, realm routing, load
//! balancing, watchdog timing, unencrypted persistence, consumer-side
//! idempotency, and requests whose application semantics prohibit failover
//! are out of scope. The API is synchronous and executor-neutral: the
//! terminal state transition and the completion hand-off are one atomic
//! `&mut self` call, so dropping a caller-side future can never split the
//! transition from the delivery or re-arm a completed transaction.
//! Dropping the table itself discards every in-flight transaction without
//! notification; consumers that must survive teardown persist
//! [`PendingRequestTable::snapshot`] first.
//!
//! No `Debug`, error, or evidence representation exposes EAP payloads,
//! User-Name, Session-Id, realm or destination identities, or raw request
//! bytes.
//!
//! @spec IETF RFC6733 3
//! @spec IETF RFC6733 5.1
//! @spec IETF RFC6733 5.5.4
//! @req REQ-IETF-RFC6733-SCAFFOLD-001
//! @conformance scaffold — see CONFORMANCE.md

use std::collections::HashMap;
use std::fmt;
use std::num::{NonZeroU128, NonZeroU64};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use opc_protocol::DecodeContext;
use zeroize::Zeroizing;

use crate::base;
use crate::{
    ApplicationId, CommandCode, CommandFlags, Header, Message, OwnedMessage, DIAMETER_HEADER_LEN,
    DIAMETER_VERSION, MAX_U24,
};

const SNAPSHOT_MAGIC: u32 = 0x4450_5453; // "DPTS"
const SNAPSHOT_VERSION: u16 = 2;
const COMPLETION_DELIVERY_MAGIC: u32 = 0x4450_444c; // "DPDL"
const COMPLETION_DELIVERY_VERSION: u16 = 1;
const COMPLETION_DELIVERY_ENCODED_LEN: usize = 72;
const MAX_SERIALIZED_COUNT: usize = u16::MAX as usize;
const SNAPSHOT_HEADER_LEN: usize = 4 + 2 + 16 + 8 + 2;
const SNAPSHOT_RECORD_FIXED_LEN: usize = 16 + 8 + 4 + 4 + 4 + 1 + 2 + 4;
const SNAPSHOT_ATTEMPT_LEN: usize = 8 + 4 + 1 + 8 + 8 + 8;
const MAX_SNAPSHOT_BYTES: usize = 1 << 30;
const MICROS_SENTINEL_NONE: u64 = u64::MAX;

/// Opaque identity of one transport connection lifetime.
///
/// The caller allocates a process-unique nonzero value whenever a peer
/// connection is established; reconnect and failover must allocate a new
/// token. The value is redacted from diagnostics so it cannot become a
/// high-cardinality connection label.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DiameterConnectionToken(NonZeroU64);

impl DiameterConnectionToken {
    /// Wrap one transport-owned, process-unique connection identity.
    #[must_use]
    pub const fn new(value: NonZeroU64) -> Self {
        Self(value)
    }

    /// Return the raw caller-allocated identity value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl fmt::Debug for DiameterConnectionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DiameterConnectionToken(<redacted>)")
    }
}

/// Caller-supplied durable identity of one pending transaction.
///
/// The value must never be reused within one [`PendingSnapshotEpoch`] while
/// any snapshot, completion-delivery record, replayable intent, or
/// acknowledgement tombstone from that epoch may still exist. This stronger
/// epoch-wide rule prevents retire/restart ABA during durable reconciliation.
/// It is redacted from diagnostics; use [`Self::get`] when storing it durably.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CompletionTokenValue(NonZeroU128);

impl CompletionTokenValue {
    /// Wrap one consumer-allocated nonzero token value.
    #[must_use]
    pub const fn new(value: NonZeroU128) -> Self {
        Self(value)
    }

    /// Return the raw token value for durable storage.
    #[must_use]
    pub const fn get(self) -> u128 {
        self.0.get()
    }
}

impl fmt::Debug for CompletionTokenValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompletionTokenValue(<redacted>)")
    }
}

/// Stable completion identity of one transaction across restores.
///
/// The `value` is allocated by the consumer at track time. The `generation`
/// is `0` while the transaction is pending and transitions to `1` exactly
/// once, at the terminal completion. Both are preserved verbatim by
/// snapshot/restore, so a consumer can durably claim delivery with a
/// compare-and-set on `(value, generation)` before applying completion side
/// effects, making restored delivery idempotent.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompletionToken {
    value: CompletionTokenValue,
    generation: u64,
}

impl CompletionToken {
    /// Return the consumer-allocated token value.
    #[must_use]
    pub const fn value(self) -> CompletionTokenValue {
        self.value
    }

    /// Return the completion generation (`0` pending, `1` completed).
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

impl fmt::Debug for CompletionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletionToken")
            .field("value", &self.value)
            .field("generation", &self.generation)
            .finish()
    }
}

/// Caller-owned identity of one durable pending-table snapshot lineage.
///
/// Allocate one nonzero value for the lifetime of a logical table and retain
/// it in rollback-resistant durable metadata. A restored snapshot from a
/// different lineage is rejected before any record is installed. The value
/// is redacted from diagnostics.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PendingSnapshotEpoch(NonZeroU128);

impl PendingSnapshotEpoch {
    /// Wrap one caller-allocated nonzero snapshot-lineage identity.
    #[must_use]
    pub const fn new(value: NonZeroU128) -> Self {
        Self(value)
    }

    /// Return the raw identity for durable storage.
    #[must_use]
    pub const fn get(self) -> u128 {
        self.0.get()
    }
}

impl fmt::Debug for PendingSnapshotEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingSnapshotEpoch(<redacted>)")
    }
}

/// Monotonic revision within one [`PendingSnapshotEpoch`].
///
/// Revisions are caller allocated and must strictly increase for every
/// snapshot emitted by one live or restored table. Persist the highest
/// committed revision outside the snapshot bytes in rollback-resistant
/// metadata; pass that exact committed head back to
/// [`PendingRequestTable::restore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PendingSnapshotRevision(NonZeroU64);

impl PendingSnapshotRevision {
    /// Wrap one nonzero monotonic snapshot revision.
    #[must_use]
    pub const fn new(value: NonZeroU64) -> Self {
        Self(value)
    }

    /// Return the raw revision for durable storage.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Durable identity and rollback fence of one pending-table snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PendingSnapshotCheckpoint {
    epoch: PendingSnapshotEpoch,
    revision: PendingSnapshotRevision,
}

impl PendingSnapshotCheckpoint {
    /// Construct a checkpoint from its caller-owned lineage and revision.
    #[must_use]
    pub const fn new(epoch: PendingSnapshotEpoch, revision: PendingSnapshotRevision) -> Self {
        Self { epoch, revision }
    }

    /// Return the snapshot lineage.
    #[must_use]
    pub const fn epoch(self) -> PendingSnapshotEpoch {
        self.epoch
    }

    /// Return the monotonic revision within the lineage.
    #[must_use]
    pub const fn revision(self) -> PendingSnapshotRevision {
        self.revision
    }
}

/// Table-issued proof that the caller attested one emitted snapshot as the
/// rollback-resistant committed head.
///
/// Obtain this only through [`PendingRequestTable::confirm_snapshot_committed`]
/// after the snapshot bytes are fully written and synced and the protected
/// head has been advanced with exact compare-and-swap. The type has no public
/// constructor so ordinary send code cannot accidentally bypass the
/// persist-before-dispatch boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommittedPendingSnapshot {
    checkpoint: PendingSnapshotCheckpoint,
}

impl CommittedPendingSnapshot {
    /// Return the exact committed checkpoint represented by this proof.
    #[must_use]
    pub const fn checkpoint(self) -> PendingSnapshotCheckpoint {
        self.checkpoint
    }
}

/// Caller-owned identity of one completion-delivery claim.
///
/// Generate a fresh nonzero value for every claim or recovery claim. The
/// value is redacted from diagnostics and is used only to fence stale workers
/// in a caller-provided durable compare-and-swap store.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompletionClaimValue(NonZeroU128);

impl CompletionClaimValue {
    /// Wrap one caller-allocated nonzero claim identity.
    #[must_use]
    pub const fn new(value: NonZeroU128) -> Self {
        Self(value)
    }

    /// Return the raw identity for durable storage.
    #[must_use]
    pub const fn get(self) -> u128 {
        self.0.get()
    }
}

impl fmt::Debug for CompletionClaimValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompletionClaimValue(<redacted>)")
    }
}

/// Durable namespace and terminal identity of one completion delivery.
///
/// The epoch prevents completion-token reuse in another table lineage from
/// colliding with an older durable acknowledgement.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompletionDeliveryKey {
    epoch: PendingSnapshotEpoch,
    completion: CompletionToken,
}

impl CompletionDeliveryKey {
    /// Return the snapshot lineage that namespaces the completion.
    #[must_use]
    pub const fn epoch(self) -> PendingSnapshotEpoch {
        self.epoch
    }

    /// Return the stable terminal completion identity.
    #[must_use]
    pub const fn completion(self) -> CompletionToken {
        self.completion
    }
}

impl fmt::Debug for CompletionDeliveryKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletionDeliveryKey")
            .field("epoch", &self.epoch)
            .field("completion", &self.completion)
            .finish()
    }
}

/// Fencing proof returned when a completion-delivery claim is acquired.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompletionDeliveryClaim {
    key: CompletionDeliveryKey,
    generation: NonZeroU64,
    value: CompletionClaimValue,
}

impl CompletionDeliveryClaim {
    /// Return the durable delivery key protected by this claim.
    #[must_use]
    pub const fn key(self) -> CompletionDeliveryKey {
        self.key
    }

    /// Return the strictly increasing claim generation.
    #[must_use]
    pub const fn generation(self) -> NonZeroU64 {
        self.generation
    }

    /// Return the caller-owned claim operation identity.
    #[must_use]
    pub const fn value(self) -> CompletionClaimValue {
        self.value
    }
}

impl fmt::Debug for CompletionDeliveryClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletionDeliveryClaim")
            .field("key", &self.key)
            .field("generation", &self.generation)
            .field("value", &self.value)
            .finish()
    }
}

/// Durable state of one terminal-completion delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompletionDeliveryState {
    /// No worker currently owns delivery.
    Ready,
    /// A worker owns delivery but has not durably acknowledged the side effect.
    Claimed,
    /// The application side effect and acknowledgement are durably committed.
    Acknowledged,
}

/// Compare-and-swap value for crash-safe terminal-completion delivery.
///
/// Persist this record together with an encrypted replayable completion
/// outcome/effect intent in a durable store keyed by
/// [`CompletionDeliveryKey`]. Apply every transition with compare-and-swap
/// from the exact old encoded value to the returned new value. A persisted
/// [`CompletionDeliveryState::Claimed`] state is unfinished work, not proof
/// that the side effect ran: after proving or fencing the old worker dead,
/// recover it with [`Self::reclaim`] and retry. The effect sink must honor the
/// monotonically increasing claim generation when stale workers can still
/// execute.
///
/// Acknowledge only after the side effect is durable. To close the unavoidable
/// crash-after-effect / before-ack duplicate window, either commit the side
/// effect and acknowledgement in one durable transaction or make the side
/// effect idempotent using [`CompletionDeliveryKey`]. Until acknowledgement,
/// keep the last committed pending snapshot authoritative; only afterward
/// publish a newer checkpoint that omits the request.
///
/// This record contains no answer bytes or subscriber data. It models the
/// external durable protocol; it is not itself a persistence backend.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompletionDeliveryRecord {
    key: CompletionDeliveryKey,
    claim_generation: u64,
    claim: Option<CompletionClaimValue>,
    acknowledged: bool,
}

impl CompletionDeliveryRecord {
    /// Fixed encoded length of one version-1 delivery record.
    pub const ENCODED_LEN: usize = COMPLETION_DELIVERY_ENCODED_LEN;

    /// Create the initial ready record for a terminal completion in `epoch`.
    pub fn new(
        epoch: PendingSnapshotEpoch,
        completion: CompletionToken,
    ) -> Result<Self, CompletionDeliveryError> {
        if completion.generation() != 1 {
            return Err(CompletionDeliveryError::CompletionNotTerminal);
        }
        Ok(Self {
            key: CompletionDeliveryKey { epoch, completion },
            claim_generation: 0,
            claim: None,
            acknowledged: false,
        })
    }

    /// Return the durable epoch-namespaced delivery key.
    #[must_use]
    pub const fn key(self) -> CompletionDeliveryKey {
        self.key
    }

    /// Return the highest claim generation allocated by this record.
    #[must_use]
    pub const fn claim_generation(self) -> u64 {
        self.claim_generation
    }

    /// Return the current durable delivery state.
    #[must_use]
    pub const fn state(self) -> CompletionDeliveryState {
        if self.acknowledged {
            CompletionDeliveryState::Acknowledged
        } else if self.claim.is_some() {
            CompletionDeliveryState::Claimed
        } else {
            CompletionDeliveryState::Ready
        }
    }

    /// Acquire a ready record with a fresh caller-owned claim identity.
    ///
    /// Persist the returned record with compare-and-swap before applying any
    /// side effect. A concurrent claimant that loses the compare-and-swap must
    /// discard its claim and reload the durable record.
    pub fn claim(
        self,
        value: CompletionClaimValue,
    ) -> Result<(Self, CompletionDeliveryClaim), CompletionDeliveryError> {
        match self.state() {
            CompletionDeliveryState::Ready => {
                let generation = self.next_claim_generation()?;
                let claim = CompletionDeliveryClaim {
                    key: self.key,
                    generation,
                    value,
                };
                Ok((
                    Self {
                        key: self.key,
                        claim_generation: generation.get(),
                        claim: Some(value),
                        acknowledged: false,
                    },
                    claim,
                ))
            }
            CompletionDeliveryState::Claimed => Err(CompletionDeliveryError::AlreadyClaimed),
            CompletionDeliveryState::Acknowledged => {
                Err(CompletionDeliveryError::AlreadyAcknowledged)
            }
        }
    }

    /// Replace a persisted unfinished claim after its previous worker is
    /// fenced.
    ///
    /// Caller policy decides when takeover is safe. Persist the returned state
    /// with compare-and-swap from this exact record before retrying the side
    /// effect; an acknowledgement from the stale claim will then fail closed.
    pub fn reclaim(
        self,
        value: CompletionClaimValue,
    ) -> Result<(Self, CompletionDeliveryClaim), CompletionDeliveryError> {
        match self.state() {
            CompletionDeliveryState::Claimed => {
                if self.claim == Some(value) {
                    return Err(CompletionDeliveryError::DuplicateClaim);
                }
                let generation = self.next_claim_generation()?;
                let claim = CompletionDeliveryClaim {
                    key: self.key,
                    generation,
                    value,
                };
                Ok((
                    Self {
                        key: self.key,
                        claim_generation: generation.get(),
                        claim: Some(value),
                        acknowledged: false,
                    },
                    claim,
                ))
            }
            CompletionDeliveryState::Ready => Err(CompletionDeliveryError::NotClaimed),
            CompletionDeliveryState::Acknowledged => {
                Err(CompletionDeliveryError::AlreadyAcknowledged)
            }
        }
    }

    /// Return an unfinished claim to the ready state after proving no side
    /// effect was committed.
    pub fn release(self, claim: CompletionDeliveryClaim) -> Result<Self, CompletionDeliveryError> {
        self.verify_claim(claim)?;
        Ok(Self {
            key: self.key,
            claim_generation: self.claim_generation,
            claim: None,
            acknowledged: false,
        })
    }

    /// Mark delivery acknowledged after the side effect is durable.
    ///
    /// Persist this transition with compare-and-swap. If the side effect
    /// cannot share the transaction, it must be idempotent by completion
    /// token so a crash before this acknowledgement remains safely retryable.
    pub fn acknowledge(
        self,
        claim: CompletionDeliveryClaim,
    ) -> Result<Self, CompletionDeliveryError> {
        self.verify_claim(claim)?;
        Ok(Self {
            key: self.key,
            claim_generation: self.claim_generation,
            claim: None,
            acknowledged: true,
        })
    }

    /// Encode this record into its strict, fixed-width version-1 form.
    ///
    /// The bytes contain only redacted identifiers and state, not the
    /// replayable completion outcome. Persist that outcome atomically beside
    /// this record.
    #[must_use]
    pub fn encode(self) -> CompletionDeliveryBytes {
        let mut encoded = [0_u8; COMPLETION_DELIVERY_ENCODED_LEN];
        encoded[0..4].copy_from_slice(&COMPLETION_DELIVERY_MAGIC.to_be_bytes());
        encoded[4..6].copy_from_slice(&COMPLETION_DELIVERY_VERSION.to_be_bytes());
        encoded[6] = match self.state() {
            CompletionDeliveryState::Ready => 0,
            CompletionDeliveryState::Claimed => 1,
            CompletionDeliveryState::Acknowledged => 2,
        };
        encoded[7] = 0;
        encoded[8..24].copy_from_slice(&self.key.epoch.get().to_be_bytes());
        encoded[24..40].copy_from_slice(&self.key.completion.value().get().to_be_bytes());
        encoded[40..48].copy_from_slice(&self.key.completion.generation().to_be_bytes());
        encoded[48..56].copy_from_slice(&self.claim_generation.to_be_bytes());
        if let Some(claim) = self.claim {
            encoded[56..72].copy_from_slice(&claim.get().to_be_bytes());
        }
        CompletionDeliveryBytes { encoded }
    }

    /// Decode one exact version-1 record, rejecting truncation, trailing
    /// bytes, unsupported versions, and impossible state combinations.
    pub fn decode(bytes: &[u8]) -> Result<Self, CompletionDeliveryError> {
        if bytes.len() != COMPLETION_DELIVERY_ENCODED_LEN {
            return Err(CompletionDeliveryError::MalformedRecord);
        }
        let magic = u32::from_be_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| CompletionDeliveryError::MalformedRecord)?,
        );
        if magic != COMPLETION_DELIVERY_MAGIC {
            return Err(CompletionDeliveryError::MalformedRecord);
        }
        let version = u16::from_be_bytes(
            bytes[4..6]
                .try_into()
                .map_err(|_| CompletionDeliveryError::MalformedRecord)?,
        );
        if version != COMPLETION_DELIVERY_VERSION {
            return Err(CompletionDeliveryError::UnsupportedVersion);
        }
        if bytes[7] != 0 {
            return Err(CompletionDeliveryError::InvalidState);
        }
        let epoch_bits = u128::from_be_bytes(
            bytes[8..24]
                .try_into()
                .map_err(|_| CompletionDeliveryError::MalformedRecord)?,
        );
        let token_bits = u128::from_be_bytes(
            bytes[24..40]
                .try_into()
                .map_err(|_| CompletionDeliveryError::MalformedRecord)?,
        );
        let completion_generation = u64::from_be_bytes(
            bytes[40..48]
                .try_into()
                .map_err(|_| CompletionDeliveryError::MalformedRecord)?,
        );
        let claim_generation = u64::from_be_bytes(
            bytes[48..56]
                .try_into()
                .map_err(|_| CompletionDeliveryError::MalformedRecord)?,
        );
        let claim_bits = u128::from_be_bytes(
            bytes[56..72]
                .try_into()
                .map_err(|_| CompletionDeliveryError::MalformedRecord)?,
        );
        let epoch = PendingSnapshotEpoch::new(
            NonZeroU128::new(epoch_bits).ok_or(CompletionDeliveryError::InvalidState)?,
        );
        let token_value = CompletionTokenValue::new(
            NonZeroU128::new(token_bits).ok_or(CompletionDeliveryError::InvalidState)?,
        );
        if completion_generation != 1 {
            return Err(CompletionDeliveryError::InvalidState);
        }
        let completion = CompletionToken {
            value: token_value,
            generation: completion_generation,
        };
        let (claim, acknowledged) = match bytes[6] {
            0 if claim_bits == 0 => (None, false),
            1 if claim_generation > 0 => (
                Some(CompletionClaimValue::new(
                    NonZeroU128::new(claim_bits).ok_or(CompletionDeliveryError::InvalidState)?,
                )),
                false,
            ),
            2 if claim_generation > 0 && claim_bits == 0 => (None, true),
            _ => return Err(CompletionDeliveryError::InvalidState),
        };
        Ok(Self {
            key: CompletionDeliveryKey { epoch, completion },
            claim_generation,
            claim,
            acknowledged,
        })
    }

    fn verify_claim(self, claim: CompletionDeliveryClaim) -> Result<(), CompletionDeliveryError> {
        match self.state() {
            CompletionDeliveryState::Ready => Err(CompletionDeliveryError::NotClaimed),
            CompletionDeliveryState::Acknowledged => {
                Err(CompletionDeliveryError::AlreadyAcknowledged)
            }
            CompletionDeliveryState::Claimed
                if claim.key != self.key
                    || claim.generation.get() != self.claim_generation
                    || self.claim != Some(claim.value) =>
            {
                Err(CompletionDeliveryError::StaleClaim)
            }
            CompletionDeliveryState::Claimed => Ok(()),
        }
    }

    fn next_claim_generation(self) -> Result<NonZeroU64, CompletionDeliveryError> {
        let next = self
            .claim_generation
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or(CompletionDeliveryError::ClaimGenerationExhausted)?;
        Ok(next)
    }
}

impl fmt::Debug for CompletionDeliveryRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletionDeliveryRecord")
            .field("key", &self.key)
            .field("state", &self.state())
            .field("claim_generation", &self.claim_generation)
            .field("claim", &self.claim.map(|_| "<redacted>"))
            .finish()
    }
}

/// Fixed-width encoded durable completion-delivery record.
pub struct CompletionDeliveryBytes {
    encoded: [u8; COMPLETION_DELIVERY_ENCODED_LEN],
}

impl CompletionDeliveryBytes {
    /// Borrow the exact versioned bytes for durable compare-and-swap storage.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

impl fmt::Debug for CompletionDeliveryBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletionDeliveryBytes")
            .field("version", &COMPLETION_DELIVERY_VERSION)
            .field("len", &self.encoded.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// Stable, redaction-safe completion-delivery transition failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionDeliveryError {
    /// A pending token (`generation == 0`) cannot be delivered.
    CompletionNotTerminal,
    /// The record already has an unfinished claim.
    AlreadyClaimed,
    /// Recovery attempted to reuse the current claim identity.
    DuplicateClaim,
    /// The record has no claim to release or acknowledge.
    NotClaimed,
    /// The supplied claim belongs to an older owner or another completion.
    StaleClaim,
    /// Delivery was already durably acknowledged.
    AlreadyAcknowledged,
    /// The monotonic claim generation reached `u64::MAX`.
    ClaimGenerationExhausted,
    /// The encoded record is truncated, has trailing bytes, or has bad magic.
    MalformedRecord,
    /// The encoded record version is unsupported.
    UnsupportedVersion,
    /// The encoded record contains an impossible state combination.
    InvalidState,
    /// Reconciliation requires an acknowledged record.
    NotAcknowledged,
    /// The delivery record belongs to another snapshot epoch.
    EpochMismatch,
    /// The table retains no transaction for this completion.
    UnknownCompletion,
    /// The retained transaction has not reached terminal completion.
    CompletionStillPending,
}

impl CompletionDeliveryError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CompletionNotTerminal => "diameter_completion_not_terminal",
            Self::AlreadyClaimed => "diameter_completion_already_claimed",
            Self::DuplicateClaim => "diameter_completion_duplicate_claim",
            Self::NotClaimed => "diameter_completion_not_claimed",
            Self::StaleClaim => "diameter_completion_stale_claim",
            Self::AlreadyAcknowledged => "diameter_completion_already_acknowledged",
            Self::ClaimGenerationExhausted => "diameter_completion_claim_generation_exhausted",
            Self::MalformedRecord => "diameter_completion_record_malformed",
            Self::UnsupportedVersion => "diameter_completion_record_unsupported_version",
            Self::InvalidState => "diameter_completion_record_invalid_state",
            Self::NotAcknowledged => "diameter_completion_not_acknowledged",
            Self::EpochMismatch => "diameter_completion_epoch_mismatch",
            Self::UnknownCompletion => "diameter_completion_unknown",
            Self::CompletionStillPending => "diameter_completion_still_pending",
        }
    }
}

impl fmt::Display for CompletionDeliveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for CompletionDeliveryError {}

/// Injectable monotonic clock for attempt timing evidence.
///
/// Implementations return a monotonic [`Duration`] since an opaque epoch.
/// Only differences between two readings of the same clock are meaningful.
/// Deadlines and retransmission timing remain caller policy; the clock is
/// used solely for bounded per-attempt evidence. Test clocks should advance
/// deterministically.
pub trait PendingRequestClock: fmt::Debug + Send + Sync {
    /// Return the current monotonic timestamp since this clock's epoch.
    fn now(&self) -> Duration;
}

/// Monotonic clock anchored at process [`Instant`] creation time.
#[derive(Debug, Clone)]
pub struct MonotonicClock {
    anchor: Instant,
}

impl MonotonicClock {
    /// Anchor the clock at the current monotonic instant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            anchor: Instant::now(),
        }
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingRequestClock for MonotonicClock {
    fn now(&self) -> Duration {
        self.anchor.elapsed()
    }
}

/// Bounds for one [`PendingRequestTable`].
///
/// Every table is bounded: pending records, retained completed records,
/// attempts per transaction, registered connections, and the accepted
/// canonical request size are all capped here. Every count bound is capped at
/// 65,535 so an oversized legal configuration cannot turn table scans or
/// eviction into a CPU-amplification knob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingRequestTableConfig {
    /// Maximum simultaneously pending transactions. Also the snapshot record
    /// bound; must fit the 16-bit serialized record count.
    pub max_pending_transactions: usize,
    /// Maximum completed transactions retained for late-answer evidence.
    /// Older completions are evicted in completion order beyond this bound.
    pub max_retained_completions: usize,
    /// Maximum attempts (initial plus failover and restored retransmissions)
    /// recorded for one transaction. This bound survives crash recovery, so a
    /// restore-and-retransmit loop cannot grow attempts without limit.
    pub max_attempts_per_transaction: usize,
    /// Maximum simultaneously registered connection lifetimes. Closed
    /// lifetimes keep their slot until [`PendingRequestTable::retire_connection`]
    /// releases them, and release is refused while any retained record still
    /// holds an attempt on the token.
    pub max_connections: usize,
    /// Maximum canonical request size accepted by [`PendingRequestTable::track`].
    pub max_message_len: usize,
    /// Maximum aggregate encoded pending-table snapshot size.
    pub max_snapshot_bytes: usize,
}

impl Default for PendingRequestTableConfig {
    fn default() -> Self {
        Self {
            max_pending_transactions: 256,
            max_retained_completions: 256,
            max_attempts_per_transaction: 8,
            max_connections: 64,
            max_message_len: 8192,
            max_snapshot_bytes: 8 * 1024 * 1024,
        }
    }
}

impl PendingRequestTableConfig {
    fn validate(&self) -> Result<(), PendingRequestConfigError> {
        if self.max_pending_transactions == 0
            || self.max_pending_transactions > MAX_SERIALIZED_COUNT
        {
            return Err(PendingRequestConfigError::PendingBoundOutOfRange);
        }
        if self.max_retained_completions == 0
            || self.max_retained_completions > MAX_SERIALIZED_COUNT
        {
            return Err(PendingRequestConfigError::CompletionBoundOutOfRange);
        }
        if self.max_attempts_per_transaction == 0
            || self.max_attempts_per_transaction > MAX_SERIALIZED_COUNT
        {
            return Err(PendingRequestConfigError::AttemptBoundOutOfRange);
        }
        if self.max_connections == 0 || self.max_connections > MAX_SERIALIZED_COUNT {
            return Err(PendingRequestConfigError::ConnectionBoundOutOfRange);
        }
        if self.max_message_len < DIAMETER_HEADER_LEN || self.max_message_len > MAX_U24 as usize {
            return Err(PendingRequestConfigError::MessageBoundOutOfRange);
        }
        if self.max_snapshot_bytes < SNAPSHOT_HEADER_LEN
            || self.max_snapshot_bytes > MAX_SNAPSHOT_BYTES
        {
            return Err(PendingRequestConfigError::SnapshotBoundOutOfRange);
        }
        Ok(())
    }
}

/// Stable, redaction-safe table configuration failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingRequestConfigError {
    /// The pending-transaction bound is zero or exceeds the serialized bound.
    PendingBoundOutOfRange,
    /// The retained-completion bound is zero or exceeds the count bound.
    CompletionBoundOutOfRange,
    /// The per-transaction attempt bound is zero or exceeds the serialized bound.
    AttemptBoundOutOfRange,
    /// The connection bound is zero or exceeds the count bound.
    ConnectionBoundOutOfRange,
    /// The message bound cannot hold a Diameter header or exceeds 24-bit length.
    MessageBoundOutOfRange,
    /// The aggregate snapshot bound is too small for its header or exceeds the
    /// SDK hard cap.
    SnapshotBoundOutOfRange,
}

impl PendingRequestConfigError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PendingBoundOutOfRange => "diameter_pending_config_pending_bound",
            Self::CompletionBoundOutOfRange => "diameter_pending_config_completion_bound",
            Self::AttemptBoundOutOfRange => "diameter_pending_config_attempt_bound",
            Self::ConnectionBoundOutOfRange => "diameter_pending_config_connection_bound",
            Self::MessageBoundOutOfRange => "diameter_pending_config_message_bound",
            Self::SnapshotBoundOutOfRange => "diameter_pending_config_snapshot_bound",
        }
    }
}

impl fmt::Display for PendingRequestConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for PendingRequestConfigError {}

/// Hop-local identity of one attempt, used for answer correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttemptId {
    connection: DiameterConnectionToken,
    hop_by_hop_identifier: u32,
}

impl AttemptId {
    /// Return the connection lifetime this attempt was written to.
    #[must_use]
    pub const fn connection(self) -> DiameterConnectionToken {
        self.connection
    }

    /// Return the Hop-by-Hop identifier unique on this attempt's connection.
    #[must_use]
    pub const fn hop_by_hop_identifier(self) -> u32 {
        self.hop_by_hop_identifier
    }
}

/// Single-use, connection-bound wire dispatch for one prepared attempt.
///
/// This value is returned only after the table consumes a prepared attempt
/// behind a committed-snapshot fence. Its `Debug` representation redacts the
/// complete Diameter message.
pub struct AttemptDispatch {
    attempt: AttemptId,
    message: OwnedMessage,
}

impl AttemptDispatch {
    /// Return the exact attempt identity, including its connection lifetime.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Borrow the complete wire message for transport encoding.
    #[must_use]
    pub const fn message(&self) -> &OwnedMessage {
        &self.message
    }

    /// Consume the receipt and return its attempt identity and wire message.
    #[must_use]
    pub fn into_parts(self) -> (AttemptId, OwnedMessage) {
        (self.attempt, self.message)
    }

    /// Consume the receipt and return the complete wire message.
    #[must_use]
    pub fn into_message(self) -> OwnedMessage {
        self.message
    }
}

impl fmt::Debug for AttemptDispatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttemptDispatch")
            .field("attempt", &self.attempt)
            .field("message", &"<redacted>")
            .finish()
    }
}

/// Write/answer disposition of one attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttemptDisposition {
    /// The attempt exists but has not been dispatched. It becomes sendable
    /// only after a snapshot containing it is committed.
    Prepared,
    /// The single-use dispatch was taken and the write outcome is not yet
    /// known.
    InFlight,
    /// The complete request was written successfully and the attempt is
    /// awaiting an answer.
    WrittenAwaitingAnswer,
    /// The transport proved the request was never written.
    FailedBeforeWrite,
    /// The write outcome is unknown or partial; the peer may have received it.
    FailedUncertainWrite,
    /// The complete request was written, then the transport failed before an
    /// answer arrived.
    TransportLostAfterWrite,
    /// A validated answer was correlated to this attempt.
    Answered,
}

impl AttemptDisposition {
    /// Stable machine-readable disposition code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::InFlight => "in_flight",
            Self::WrittenAwaitingAnswer => "written_awaiting_answer",
            Self::FailedBeforeWrite => "failed_before_write",
            Self::FailedUncertainWrite => "failed_uncertain_write",
            Self::TransportLostAfterWrite => "transport_lost_after_write",
            Self::Answered => "answered",
        }
    }

    /// Return whether this attempt is still awaiting its full-write outcome.
    #[must_use]
    pub const fn is_in_flight(self) -> bool {
        matches!(self, Self::InFlight)
    }

    const fn can_receive_answer(self) -> bool {
        !matches!(self, Self::Prepared | Self::FailedBeforeWrite)
    }
}

/// Transport-reported failure classification for one attempt.
///
/// The distinction matters for evidence and for the caller's failover
/// policy: after [`Self::BeforeWrite`] the request provably never left, while
/// [`Self::UncertainWrite`] and [`Self::TransportLostAfterWrite`] mean the
/// peer may apply the request, so the eventual completion is potentially a
/// duplicate the server must suppress through End-to-End duplicate
/// detection. Every failover attempt sets T=1 regardless of disposition, as
/// RFC 6733 §5.5.4 requires for forwarded pending requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttemptFailure {
    /// The transport proved the request was never written.
    BeforeWrite,
    /// The write was partial or its disposition is unknown.
    UncertainWrite,
    /// The complete request was written before the transport failed.
    TransportLostAfterWrite,
}

impl AttemptFailure {
    fn disposition(self) -> AttemptDisposition {
        match self {
            Self::BeforeWrite => AttemptDisposition::FailedBeforeWrite,
            Self::UncertainWrite => AttemptDisposition::FailedUncertainWrite,
            Self::TransportLostAfterWrite => AttemptDisposition::TransportLostAfterWrite,
        }
    }
}

/// Bounded evidence for one transmission attempt.
///
/// Timestamps come from the table's injected clock and are meaningful only
/// relative to that clock's epoch. Attempts recorded before a
/// snapshot/restore keep timestamps from the previous clock's epoch.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AttemptEvidence {
    attempt_index: usize,
    connection: DiameterConnectionToken,
    hop_by_hop_identifier: u32,
    retransmission: bool,
    disposition: AttemptDisposition,
    started_at: Duration,
    written_at: Option<Duration>,
    ended_at: Option<Duration>,
    snapshotted_at: Option<PendingSnapshotRevision>,
}

impl AttemptEvidence {
    /// Return the zero-based position of this attempt in the transaction.
    #[must_use]
    pub const fn attempt_index(&self) -> usize {
        self.attempt_index
    }

    /// Return the hop-local attempt identity used for correlation.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        AttemptId {
            connection: self.connection,
            hop_by_hop_identifier: self.hop_by_hop_identifier,
        }
    }

    /// Return the connection lifetime this attempt was written to.
    #[must_use]
    pub const fn connection(&self) -> DiameterConnectionToken {
        self.connection
    }

    /// Return the Hop-by-Hop identifier unique on this attempt's connection.
    #[must_use]
    pub const fn hop_by_hop_identifier(&self) -> u32 {
        self.hop_by_hop_identifier
    }

    /// Return whether this attempt carries the RFC 6733 T (potentially
    /// retransmitted) bit. Every attempt after the first sets T=1.
    #[must_use]
    pub const fn is_retransmission(&self) -> bool {
        self.retransmission
    }

    /// Return the current write/answer disposition.
    #[must_use]
    pub const fn disposition(&self) -> AttemptDisposition {
        self.disposition
    }

    /// Return the table-clock timestamp when this attempt was created.
    #[must_use]
    pub const fn started_at(&self) -> Duration {
        self.started_at
    }

    /// Return when the transport reported a complete successful write.
    ///
    /// An answer itself proves the complete request left the origin, so this
    /// is also populated when an answer wins a race with the write callback.
    #[must_use]
    pub const fn written_at(&self) -> Option<Duration> {
        self.written_at
    }

    /// Return the table-clock timestamp when this attempt terminated.
    #[must_use]
    pub const fn ended_at(&self) -> Option<Duration> {
        self.ended_at
    }

    /// Return the first emitted snapshot revision that contains this attempt.
    ///
    /// Emission alone is not durability. The attempt becomes dispatchable only
    /// when a current [`CommittedPendingSnapshot`] covers this revision.
    #[must_use]
    pub const fn snapshotted_at(&self) -> Option<PendingSnapshotRevision> {
        self.snapshotted_at
    }
}

impl fmt::Debug for AttemptEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttemptEvidence")
            .field("attempt_index", &self.attempt_index)
            .field("connection", &self.connection)
            .field("hop_by_hop_identifier", &self.hop_by_hop_identifier)
            .field("retransmission", &self.retransmission)
            .field("disposition", &self.disposition)
            .field("started_at", &self.started_at)
            .field("written_at", &self.written_at)
            .field("ended_at", &self.ended_at)
            .field("snapshotted_at", &self.snapshotted_at)
            .finish()
    }
}

/// Caller assertion about whether the selected alternate can serve the
/// request's routing identity.
///
/// Peer selection and alternate routability are caller policy. A request
/// carrying an explicit `Destination-Host` may only be failed over to an
/// alternate the caller asserts can reach that host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlternateRoutability {
    /// The alternate is an ordinary realm-routed agent. Rejected for requests
    /// with an explicit `Destination-Host`.
    RealmRouted,
    /// The caller asserts the alternate can deliver to the request's fixed
    /// `Destination-Host`. Meaningless but harmless when no fixed destination
    /// is present.
    DestinationAsserted,
}

/// Reason a transaction could not be delivered at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UndeliverableReason {
    /// The request pins a `Destination-Host` and no valid alternate exists.
    /// The destination is never silently dropped or rewritten.
    FixedDestinationNoAlternate,
    /// No routable alternate connection is available.
    NoAlternateRoutable,
}

impl UndeliverableReason {
    /// Stable machine-readable reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FixedDestinationNoAlternate => "fixed_destination_no_alternate",
            Self::NoAlternateRoutable => "no_alternate_routable",
        }
    }
}

/// Reason a transaction completed without a provable outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndeterminateReason {
    /// The last attempt's write disposition is uncertain and no further
    /// attempt will be made; the peer may or may not have applied the request.
    UncertainWriteDisposition,
    /// The caller stopped waiting for an answer (for example a caller-owned
    /// deadline) without evidence the request arrived.
    CallerWithdrawn,
}

impl IndeterminateReason {
    /// Stable machine-readable reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UncertainWriteDisposition => "uncertain_write_disposition",
            Self::CallerWithdrawn => "caller_withdrawn",
        }
    }
}

/// Payload-free classification of a terminal completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompletionKind {
    /// A validated answer was correlated to one attempt.
    Answered,
    /// The request could not be delivered (typed inability-to-deliver).
    Undeliverable,
    /// The caller's retry policy was exhausted.
    Exhausted,
    /// The outcome cannot be proven either way.
    Indeterminate,
}

impl CompletionKind {
    /// Stable machine-readable completion code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Answered => "answered",
            Self::Undeliverable => "undeliverable",
            Self::Exhausted => "exhausted",
            Self::Indeterminate => "indeterminate",
        }
    }
}

/// The single terminal completion of one live transaction.
///
/// This value is produced exactly once per transaction: by
/// [`PendingRequestTable::correlate_answer`] for a validated answer, or by
/// one of the `finish_*` methods for a caller-driven terminal outcome. After
/// it is produced, further answers only update bounded evidence. Dropping
/// this value does not re-arm the transaction.
pub enum TransactionCompletion {
    /// A validated answer was correlated to the recorded attempt. The answer
    /// is handed to the application exactly once; its contents are sensitive
    /// and never appear in diagnostics.
    Answered {
        /// Stable completion identity with generation `1`.
        token: CompletionToken,
        /// The answer message as received on the completing connection.
        answer: OwnedMessage,
        /// Evidence of the attempt the answer was correlated to.
        attempt: AttemptEvidence,
    },
    /// The request could not be delivered at all.
    Undeliverable {
        /// Stable completion identity with generation `1`.
        token: CompletionToken,
        /// Typed inability-to-deliver reason.
        reason: UndeliverableReason,
        /// Number of attempts recorded before giving up.
        attempts: usize,
    },
    /// The caller's retry policy was exhausted without an answer.
    Exhausted {
        /// Stable completion identity with generation `1`.
        token: CompletionToken,
        /// Number of attempts recorded before giving up.
        attempts: usize,
    },
    /// The outcome cannot be proven; side effects must be reconciled by the
    /// consumer's own policy.
    Indeterminate {
        /// Stable completion identity with generation `1`.
        token: CompletionToken,
        /// Why no provable outcome exists.
        reason: IndeterminateReason,
        /// Number of attempts recorded before giving up.
        attempts: usize,
    },
}

impl TransactionCompletion {
    /// Return the stable completion identity carried by this outcome.
    #[must_use]
    pub const fn token(&self) -> CompletionToken {
        match self {
            Self::Answered { token, .. }
            | Self::Undeliverable { token, .. }
            | Self::Exhausted { token, .. }
            | Self::Indeterminate { token, .. } => *token,
        }
    }

    /// Return the payload-free classification of this outcome.
    #[must_use]
    pub const fn kind(&self) -> CompletionKind {
        match self {
            Self::Answered { .. } => CompletionKind::Answered,
            Self::Undeliverable { .. } => CompletionKind::Undeliverable,
            Self::Exhausted { .. } => CompletionKind::Exhausted,
            Self::Indeterminate { .. } => CompletionKind::Indeterminate,
        }
    }
}

impl fmt::Debug for TransactionCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = formatter.debug_struct("TransactionCompletion");
        out.field("token", &self.token())
            .field("kind", &self.kind());
        match self {
            Self::Answered { attempt, .. } => {
                out.field("attempt", attempt).field("answer", &"<redacted>");
            }
            Self::Undeliverable {
                reason, attempts, ..
            } => {
                out.field("reason", reason).field("attempts", attempts);
            }
            Self::Exhausted { attempts, .. } => {
                out.field("attempts", attempts);
            }
            Self::Indeterminate {
                reason, attempts, ..
            } => {
                out.field("reason", reason).field("attempts", attempts);
            }
        }
        out.finish()
    }
}

/// Bounded evidence recorded when an answer arrives after completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LateAnswerEvidence {
    /// The attempt the late answer was correlated to.
    pub attempt: AttemptId,
    /// The kind of completion the transaction already delivered.
    pub completion: CompletionKind,
    /// Bounded count of late answers observed for this transaction.
    pub late_answer_count: u32,
}

/// Evidence for an answer that matches no retained attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnmatchedAnswerEvidence {
    /// The connection the answer arrived on.
    pub connection: DiameterConnectionToken,
    /// The answer's Hop-by-Hop identifier.
    pub hop_by_hop_identifier: u32,
}

/// Why an answer that matched a live attempt failed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnswerRejectionReason {
    /// The message carries the request (R) bit and is not an answer.
    NotAnAnswer,
    /// The answer does not use Diameter version 1.
    UnsupportedVersion,
    /// The declared length does not exactly match the owned AVP region or
    /// exceeds the configured message bound.
    InvalidLength,
    /// Reserved command bits are set or the answer illegally carries T=1.
    InvalidFlags,
    /// Another fixed-header field is structurally invalid.
    MalformedHeader,
    /// RFC 6733 §6.2 requires the answer P bit to equal the request P bit.
    ProxiableMismatch,
    /// The answer AVP framing is malformed.
    MalformedAvps,
    /// The answer's End-to-End identifier differs from the request's.
    EndToEndMismatch,
    /// The answer's command code or application differs from the request's.
    CommandMismatch,
    /// The correlated attempt was proven not to have written any request.
    AttemptNotAnswerEligible,
}

impl AnswerRejectionReason {
    /// Stable machine-readable rejection code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAnAnswer => "not_an_answer",
            Self::UnsupportedVersion => "unsupported_version",
            Self::InvalidLength => "invalid_length",
            Self::InvalidFlags => "invalid_flags",
            Self::MalformedHeader => "malformed_header",
            Self::ProxiableMismatch => "proxiable_mismatch",
            Self::MalformedAvps => "malformed_avps",
            Self::EndToEndMismatch => "end_to_end_mismatch",
            Self::CommandMismatch => "command_mismatch",
            Self::AttemptNotAnswerEligible => "attempt_not_answer_eligible",
        }
    }
}

/// Bounded evidence for a matched but invalid answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnswerRejection {
    /// The attempt the invalid answer claimed to match.
    pub attempt: AttemptId,
    /// Why the answer was rejected.
    pub reason: AnswerRejectionReason,
    /// Bounded count of rejected answers observed for this transaction.
    pub rejected_answer_count: u32,
}

/// Disposition of one inbound answer after correlation.
///
/// Only [`Self::Completed`] carries a completion, and it is produced at most
/// once per transaction. Every other variant is bounded evidence only: no
/// application callback, no EAP advancement, no second session mutation may
/// be derived from them.
#[derive(Debug)]
pub enum AnswerDisposition {
    /// The transaction reached its single terminal completion.
    Completed(TransactionCompletion),
    /// The answer correlated to a retained attempt but the transaction
    /// already completed. Bounded evidence only.
    LateAnswer(LateAnswerEvidence),
    /// The answer matches no retained attempt on any connection.
    Unmatched(UnmatchedAnswerEvidence),
    /// The answer matched a retained attempt's identity but failed
    /// validation. Validation runs before the completion-state check, so this
    /// variant is also returned for invalid messages that arrive after the
    /// transaction completed; it never changes completion state and a pending
    /// transaction's attempt remains in flight. Bounded evidence only.
    Rejected(AnswerRejection),
}

/// Stable, redaction-safe failure of [`PendingRequestTable::track`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackError {
    /// The pending-transaction bound is reached.
    TableFull,
    /// The completion token value is already tracked or retained.
    DuplicateCompletionToken,
    /// Another pending transaction already uses this End-to-End identifier.
    /// This is a defense-in-depth invariant over the table's pending set;
    /// End-to-End allocation itself belongs to the origin-scoped
    /// [`crate::end_to_end::DiameterEndToEndIdentifierAuthority`].
    DuplicateEndToEnd,
    /// The connection token is not registered.
    UnknownConnection,
    /// The connection lifetime was closed.
    ConnectionClosed,
    /// The connection's Hop-by-Hop allocation space is exhausted.
    HopByHopSpaceExhausted,
    /// The allocated (connection, Hop-by-Hop) attempt identity is already
    /// retained. This cannot occur through the public API while connections
    /// honor their allocated partition; it fails closed instead of silently
    /// overwriting correlation evidence.
    AttemptIdentifierConflict,
    /// The message is not a Diameter request (R bit clear).
    NotARequest,
    /// The request header or AVP region is malformed, or the message exceeds
    /// the configured size bound.
    MalformedRequest,
    /// The request does not use Diameter version 1.
    UnsupportedVersion,
    /// The request already carries the T (potentially retransmitted) bit.
    /// [`PendingRequestTable::track`] starts a new transaction; a T-set
    /// request is by definition a retransmission and must be recovered
    /// through [`PendingRequestTable::restore`], which re-arms it with T=1,
    /// instead of silently dropping RFC 6733 §3's duplicate-detection signal.
    AlreadyRetransmitted,
    /// The request lacks exactly one non-empty Origin-Host AVP.
    OriginHostInvalid,
}

impl TrackError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TableFull => "diameter_pending_track_table_full",
            Self::DuplicateCompletionToken => "diameter_pending_track_duplicate_token",
            Self::DuplicateEndToEnd => "diameter_pending_track_duplicate_end_to_end",
            Self::UnknownConnection => "diameter_pending_track_unknown_connection",
            Self::ConnectionClosed => "diameter_pending_track_connection_closed",
            Self::HopByHopSpaceExhausted => "diameter_pending_track_hop_by_hop_exhausted",
            Self::AttemptIdentifierConflict => "diameter_pending_track_attempt_conflict",
            Self::NotARequest => "diameter_pending_track_not_a_request",
            Self::MalformedRequest => "diameter_pending_track_malformed_request",
            Self::UnsupportedVersion => "diameter_pending_track_unsupported_version",
            Self::AlreadyRetransmitted => "diameter_pending_track_already_retransmitted",
            Self::OriginHostInvalid => "diameter_pending_track_origin_host_invalid",
        }
    }
}

impl fmt::Display for TrackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for TrackError {}

/// Stable, redaction-safe failure of [`PendingRequestTable::failover`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailoverError {
    /// No transaction with this completion token value exists.
    UnknownTransaction,
    /// The transaction already reached its terminal completion.
    NotPending,
    /// The per-transaction attempt bound is reached. Map this to
    /// [`PendingRequestTable::finish_exhausted`] when the caller's retry
    /// policy is also exhausted.
    AttemptLimitReached,
    /// The alternate connection token is not registered.
    UnknownConnection,
    /// The alternate connection lifetime was closed.
    ConnectionClosed,
    /// The alternate connection's Hop-by-Hop allocation space is exhausted.
    HopByHopSpaceExhausted,
    /// The request pins a `Destination-Host`; the caller must assert the
    /// alternate can reach it ([`AlternateRoutability::DestinationAsserted`])
    /// or finish the transaction as undeliverable.
    FixedDestinationRequiresAssertion,
    /// The allocated (connection, Hop-by-Hop) attempt identity is already
    /// retained. This cannot occur through the public API while connections
    /// honor their allocated partition; it fails closed instead of silently
    /// overwriting correlation evidence.
    AttemptIdentifierConflict,
}

impl FailoverError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownTransaction => "diameter_pending_failover_unknown_transaction",
            Self::NotPending => "diameter_pending_failover_not_pending",
            Self::AttemptLimitReached => "diameter_pending_failover_attempt_limit",
            Self::UnknownConnection => "diameter_pending_failover_unknown_connection",
            Self::ConnectionClosed => "diameter_pending_failover_connection_closed",
            Self::HopByHopSpaceExhausted => "diameter_pending_failover_hop_by_hop_exhausted",
            Self::FixedDestinationRequiresAssertion => {
                "diameter_pending_failover_fixed_destination_requires_assertion"
            }
            Self::AttemptIdentifierConflict => "diameter_pending_failover_attempt_conflict",
        }
    }
}

impl fmt::Display for FailoverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for FailoverError {}

/// Stable, redaction-safe failure of connection registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionTableError {
    /// The connection bound is reached.
    TableFull,
    /// The connection token is already registered, or still appears in a
    /// retained transaction's attempt history. Connection tokens must be
    /// unique per transport lifetime: reusing a token that restored records
    /// still reference could allocate a duplicate Hop-by-Hop identifier on
    /// one connection, breaking RFC 6733 §3 correlation.
    DuplicateConnection,
    /// The connection token is not registered.
    UnknownConnection,
    /// The connection cannot be retired: at least one pending or retained
    /// transaction still holds an attempt on this token. Attempt identities
    /// must stay registered for late-answer evidence; completed records age
    /// out through the retention bound, after which the token becomes
    /// removable.
    ConnectionInUse,
}

impl ConnectionTableError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TableFull => "diameter_pending_connection_table_full",
            Self::DuplicateConnection => "diameter_pending_connection_duplicate",
            Self::UnknownConnection => "diameter_pending_connection_unknown",
            Self::ConnectionInUse => "diameter_pending_connection_in_use",
        }
    }
}

impl fmt::Display for ConnectionTableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for ConnectionTableError {}

/// Stable, redaction-safe failure of transaction-scoped operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionAccessError {
    /// No transaction with this completion token value exists.
    UnknownTransaction,
    /// The transaction already reached its terminal completion.
    NotPending,
    /// No attempt with this identity exists on the transaction.
    UnknownAttempt,
    /// The attempt already terminated and cannot change disposition.
    AttemptNotInFlight,
    /// The requested write-state transition contradicts already recorded
    /// evidence.
    InvalidAttemptTransition,
    /// The transaction has no in-flight attempt to produce wire bytes for.
    /// Restored attempts recovered by a snapshot never count as live; re-arm
    /// the record with [`PendingRequestTable::failover`] first.
    NoLiveAttempt,
    /// The supplied committed-snapshot proof is not the table's current
    /// committed head.
    SnapshotProofMismatch,
    /// The prepared attempt was not included in the supplied committed
    /// snapshot, so dispatch could be lost or repeated across a crash.
    AttemptNotDurablySnapshotted,
    /// The attempt's connection lifetime is absent or already closed.
    ConnectionNotOpen,
}

impl TransactionAccessError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownTransaction => "diameter_pending_access_unknown_transaction",
            Self::NotPending => "diameter_pending_access_not_pending",
            Self::UnknownAttempt => "diameter_pending_access_unknown_attempt",
            Self::AttemptNotInFlight => "diameter_pending_access_attempt_not_in_flight",
            Self::InvalidAttemptTransition => "diameter_pending_access_invalid_attempt_transition",
            Self::NoLiveAttempt => "diameter_pending_access_no_live_attempt",
            Self::SnapshotProofMismatch => "diameter_pending_access_snapshot_proof_mismatch",
            Self::AttemptNotDurablySnapshotted => {
                "diameter_pending_access_attempt_not_durably_snapshotted"
            }
            Self::ConnectionNotOpen => "diameter_pending_access_connection_not_open",
        }
    }
}

impl fmt::Display for TransactionAccessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for TransactionAccessError {}

/// Stable, redaction-safe failure to create a rollback-fenced snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotCreateError {
    /// A live or restored table is already bound to another snapshot lineage.
    EpochMismatch,
    /// The supplied revision does not strictly advance the table high-water.
    RevisionNotAdvanced,
    /// The encoded snapshot would exceed the configured aggregate bound.
    SizeLimitExceeded,
    /// The bounded scratch allocation could not be reserved.
    AllocationFailed,
    /// A terminal completion has not been durably acknowledged, so publishing
    /// a pending-only snapshot would lose its replay source.
    UnacknowledgedCompletion,
    /// A previously emitted snapshot has not been confirmed or explicitly
    /// abandoned, so another candidate cannot be emitted safely.
    UncommittedSnapshotOutstanding,
}

impl SnapshotCreateError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EpochMismatch => "diameter_pending_snapshot_epoch_mismatch",
            Self::RevisionNotAdvanced => "diameter_pending_snapshot_revision_not_advanced",
            Self::SizeLimitExceeded => "diameter_pending_snapshot_size_limit",
            Self::AllocationFailed => "diameter_pending_snapshot_allocation_failed",
            Self::UnacknowledgedCompletion => "diameter_pending_snapshot_unacknowledged_completion",
            Self::UncommittedSnapshotOutstanding => {
                "diameter_pending_snapshot_uncommitted_outstanding"
            }
        }
    }
}

impl fmt::Display for SnapshotCreateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for SnapshotCreateError {}

/// Stable, redaction-safe failure to attest an emitted snapshot as committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotCommitError {
    /// No snapshot has been emitted by this table.
    NoEmittedSnapshot,
    /// The supplied checkpoint is not the table's latest emitted snapshot.
    CheckpointMismatch,
    /// The supplied checkpoint would move the committed head backward.
    CommittedHeadRegression,
}

impl SnapshotCommitError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoEmittedSnapshot => "diameter_pending_snapshot_no_emitted_snapshot",
            Self::CheckpointMismatch => "diameter_pending_snapshot_commit_checkpoint_mismatch",
            Self::CommittedHeadRegression => "diameter_pending_snapshot_commit_regression",
        }
    }
}

impl fmt::Display for SnapshotCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for SnapshotCommitError {}

/// Stable, redaction-safe snapshot restore failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotRestoreError {
    /// The snapshot bytes are truncated, internally inconsistent, or carry
    /// trailing garbage.
    Malformed,
    /// The snapshot version is not supported by this build.
    UnsupportedVersion,
    /// The snapshot exceeds the configured table bounds.
    LimitExceeded,
    /// A record fails request validation or internal consistency checks.
    InvalidRecord,
    /// The encoded snapshot belongs to another caller-owned lineage.
    EpochMismatch,
    /// The encoded revision is older than the caller's durable high-water.
    Stale,
    /// The encoded revision is newer than the caller's committed checkpoint.
    Uncommitted,
}

impl SnapshotRestoreError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "diameter_pending_snapshot_malformed",
            Self::UnsupportedVersion => "diameter_pending_snapshot_unsupported_version",
            Self::LimitExceeded => "diameter_pending_snapshot_limit_exceeded",
            Self::InvalidRecord => "diameter_pending_snapshot_invalid_record",
            Self::EpochMismatch => "diameter_pending_snapshot_epoch_mismatch",
            Self::Stale => "diameter_pending_snapshot_stale",
            Self::Uncommitted => "diameter_pending_snapshot_uncommitted",
        }
    }
}

impl fmt::Display for SnapshotRestoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for SnapshotRestoreError {}

/// Versioned, explicitly sensitive snapshot of all pending transactions.
///
/// The encoded form contains canonical request bytes, which may carry EAP
/// payloads, User-Name, Session-Id, realm, and destination identities. Store
/// it only in encrypted, integrity-protected storage; this crate deliberately
/// provides no plaintext persistence backend. The value is held in zeroizing
/// memory and its `Debug` representation is redacted.
///
/// Snapshots capture *pending* records only. Completed records are live-only
/// late-answer evidence and are never serialized.
pub struct PendingTableSnapshot {
    checkpoint: PendingSnapshotCheckpoint,
    encoded: Zeroizing<Vec<u8>>,
}

impl PendingTableSnapshot {
    /// The snapshot format version emitted by this build.
    pub const VERSION: u16 = SNAPSHOT_VERSION;

    /// Return the lineage and monotonic revision encoded in this snapshot.
    #[must_use]
    pub const fn checkpoint(&self) -> PendingSnapshotCheckpoint {
        self.checkpoint
    }

    /// Borrow the encoded snapshot bytes for encrypted storage.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Return the encoded length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.encoded.len()
    }

    /// Return whether the encoded form is empty (it never is).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.encoded.is_empty()
    }
}

impl fmt::Debug for PendingTableSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingTableSnapshot")
            .field("version", &Self::VERSION)
            .field("checkpoint", &self.checkpoint)
            .field("len", &self.encoded.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordState {
    Pending,
    Completed { kind: CompletionKind, sequence: u64 },
}

impl RecordState {
    fn is_pending(self) -> bool {
        matches!(self, Self::Pending)
    }
}

struct TransactionRecord {
    token_value: CompletionTokenValue,
    generation: u64,
    command_code: CommandCode,
    application_id: ApplicationId,
    proxiable: bool,
    end_to_end_identifier: u32,
    fixed_destination: bool,
    raw_avps: Bytes,
    attempts: Vec<AttemptEvidence>,
    /// Number of leading attempts recovered by a snapshot restore. Those
    /// attempts belong to dead connection lifetimes: they remain correlation
    /// and audit evidence, but their pre-crash wire bytes are never served
    /// for sending again. The first attempt at or after this index is a
    /// post-restore re-arm.
    restored_baseline: usize,
    state: RecordState,
    completion_delivery_acknowledged: bool,
    late_answer_count: u32,
    rejected_answer_count: u32,
}

impl TransactionRecord {
    fn completion_token(&self) -> CompletionToken {
        CompletionToken {
            value: self.token_value,
            generation: self.generation,
        }
    }

    fn wire_message(&self, attempt: &AttemptEvidence) -> OwnedMessage {
        let mut bits = CommandFlags::request(self.proxiable).bits();
        if attempt.retransmission {
            bits |= CommandFlags::POTENTIALLY_RETRANSMITTED;
        }
        // Track-time validation bounds raw_avps to the configured message
        // limit, which never exceeds the 24-bit wire length field.
        let length = (DIAMETER_HEADER_LEN + self.raw_avps.len()) as u32;
        OwnedMessage {
            header: Header::new(
                CommandFlags::from_bits(bits),
                self.command_code,
                self.application_id,
                attempt.hop_by_hop_identifier,
                self.end_to_end_identifier,
            )
            .with_length(length),
            raw_avps: self.raw_avps.clone(),
        }
    }
}

/// Read-only view of one tracked pending-request transaction.
///
/// The view exposes the immutable request identity, the bounded attempt
/// history, and the completion state without exposing sensitive AVP values.
pub struct DiameterRequestTransaction<'a> {
    record: &'a TransactionRecord,
}

impl DiameterRequestTransaction<'_> {
    /// Return the stable completion identity and its current generation.
    #[must_use]
    pub fn completion_token(&self) -> CompletionToken {
        self.record.completion_token()
    }

    /// Return the immutable End-to-End identifier shared by every attempt.
    #[must_use]
    pub const fn end_to_end_identifier(&self) -> u32 {
        self.record.end_to_end_identifier
    }

    /// Return the immutable command code of the canonical request.
    #[must_use]
    pub const fn command_code(&self) -> CommandCode {
        self.record.command_code
    }

    /// Return the immutable application identifier of the canonical request.
    #[must_use]
    pub const fn application_id(&self) -> ApplicationId {
        self.record.application_id
    }

    /// Return whether the canonical request is proxiable (P bit).
    #[must_use]
    pub const fn is_proxiable(&self) -> bool {
        self.record.proxiable
    }

    /// Return whether the canonical request pins an explicit Destination-Host.
    #[must_use]
    pub const fn has_fixed_destination(&self) -> bool {
        self.record.fixed_destination
    }

    /// Return the bounded attempt history in attempt order.
    #[must_use]
    pub fn attempts(&self) -> &[AttemptEvidence] {
        &self.record.attempts
    }

    /// Return the completion classification once the transaction terminated.
    #[must_use]
    pub fn completion_kind(&self) -> Option<CompletionKind> {
        match self.record.state {
            RecordState::Pending => None,
            RecordState::Completed { kind, .. } => Some(kind),
        }
    }

    /// Return the bounded count of late answers observed after completion.
    #[must_use]
    pub const fn late_answer_count(&self) -> u32 {
        self.record.late_answer_count
    }

    /// Return the bounded count of matched-but-invalid answers observed.
    #[must_use]
    pub const fn rejected_answer_count(&self) -> u32 {
        self.record.rejected_answer_count
    }

    /// Return whether an answer for `candidate` matches the immutable
    /// Origin-Host of the canonical request.
    ///
    /// This is an equality oracle only; the Origin-Host value itself never
    /// leaves the transaction through a diagnostic representation.
    #[must_use]
    pub fn has_origin_host(&self, candidate: &str) -> bool {
        origin_host_matches(&self.record.raw_avps, candidate)
    }
}

impl fmt::Debug for DiameterRequestTransaction<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterRequestTransaction")
            .field("completion_token", &self.record.completion_token())
            .field("command_code", &self.record.command_code)
            .field("application_id", &self.record.application_id)
            .field("proxiable", &self.record.proxiable)
            .field("end_to_end_identifier", &self.record.end_to_end_identifier)
            .field("fixed_destination", &self.record.fixed_destination)
            .field("attempts", &self.record.attempts)
            .field("completion_kind", &self.completion_kind())
            .field("late_answer_count", &self.record.late_answer_count)
            .field("rejected_answer_count", &self.record.rejected_answer_count)
            .field("raw_avps", &"<redacted>")
            .finish()
    }
}

struct ConnectionEntry {
    next_hop_by_hop: u32,
    exhausted: bool,
    open: bool,
    /// Number of attempts in retained records (pending or completed) that
    /// reference this connection. Guards `retire_connection` so attempt
    /// identities stay correlated for late-answer evidence.
    live_attempts: usize,
}

type AttemptKey = (u64, u32);

/// Bounded, cancellation-safe table of loss-safe pending-request failover
/// transactions.
///
/// The table owns RFC 6733 wire correctness for failover: per-connection
/// Hop-by-Hop uniqueness, T-bit handling, immutable End-to-End/Origin-Host
/// identity, answer correlation across every retained attempt, live
/// at-most-once completion, and the versioned sensitive snapshot form.
/// Attempt limits beyond the evidence bound, deadlines, peer selection, and
/// alternate routability remain caller policy.
///
/// Every operation is synchronous and takes `&mut self`; a terminal
/// completion is handed to the caller atomically with the state transition.
/// No future or callback is involved at this layer, so cancelling caller-side
/// work can neither lose the at-most-once guarantee nor re-deliver a
/// completion. After a crash, restored pending records deliver their
/// completion at-least-once unless the consumer durably claims delivery with
/// a compare-and-set on the [`CompletionToken`] before applying side effects.
pub struct PendingRequestTable {
    config: PendingRequestTableConfig,
    clock: Arc<dyn PendingRequestClock>,
    snapshot_epoch: PendingSnapshotEpoch,
    records: HashMap<CompletionTokenValue, TransactionRecord>,
    suppressed_deliveries: HashMap<CompletionTokenValue, CompletionToken>,
    attempt_index: HashMap<AttemptKey, CompletionTokenValue>,
    pending_end_to_end: HashMap<u32, CompletionTokenValue>,
    connections: HashMap<u64, ConnectionEntry>,
    pending_count: usize,
    unacknowledged_completion_count: usize,
    completed_count: usize,
    completion_sequence: u64,
    evicted_completions: u64,
    unmatched_answers: u64,
    snapshot_checkpoint: Option<PendingSnapshotCheckpoint>,
    uncommitted_snapshot_checkpoint: Option<PendingSnapshotCheckpoint>,
    committed_snapshot_checkpoint: Option<PendingSnapshotCheckpoint>,
}

impl fmt::Debug for PendingRequestTable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingRequestTable")
            .field("config", &self.config)
            .field("snapshot_epoch", &self.snapshot_epoch)
            .field("pending_count", &self.pending_count)
            .field(
                "unacknowledged_completion_count",
                &self.unacknowledged_completion_count,
            )
            .field(
                "suppressed_delivery_count",
                &self.suppressed_deliveries.len(),
            )
            .field("retained_completed_count", &self.completed_count)
            .field("connection_count", &self.connections.len())
            .field("evicted_completions", &self.evicted_completions)
            .field("unmatched_answers", &self.unmatched_answers)
            .field("snapshot_checkpoint", &self.snapshot_checkpoint)
            .field(
                "uncommitted_snapshot_checkpoint",
                &self.uncommitted_snapshot_checkpoint,
            )
            .field(
                "committed_snapshot_checkpoint",
                &self.committed_snapshot_checkpoint,
            )
            .finish()
    }
}

impl PendingRequestTable {
    /// Create an empty bounded table with an injected clock.
    pub fn new(
        config: PendingRequestTableConfig,
        clock: Arc<dyn PendingRequestClock>,
        snapshot_epoch: PendingSnapshotEpoch,
    ) -> Result<Self, PendingRequestConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            clock,
            snapshot_epoch,
            records: HashMap::new(),
            suppressed_deliveries: HashMap::new(),
            attempt_index: HashMap::new(),
            pending_end_to_end: HashMap::new(),
            connections: HashMap::new(),
            pending_count: 0,
            unacknowledged_completion_count: 0,
            completed_count: 0,
            completion_sequence: 0,
            evicted_completions: 0,
            unmatched_answers: 0,
            snapshot_checkpoint: None,
            uncommitted_snapshot_checkpoint: None,
            committed_snapshot_checkpoint: None,
        })
    }

    /// Return the durable lineage that namespaces snapshots and completion
    /// delivery keys for this table.
    #[must_use]
    pub const fn snapshot_epoch(&self) -> PendingSnapshotEpoch {
        self.snapshot_epoch
    }

    /// Return the latest snapshot emitted by this table, whether or not the
    /// caller has committed it externally.
    #[must_use]
    pub const fn latest_emitted_snapshot(&self) -> Option<PendingSnapshotCheckpoint> {
        self.snapshot_checkpoint
    }

    /// Return a proof for the current caller-attested committed head.
    #[must_use]
    pub const fn committed_snapshot(&self) -> Option<CommittedPendingSnapshot> {
        match self.committed_snapshot_checkpoint {
            Some(checkpoint) => Some(CommittedPendingSnapshot { checkpoint }),
            None => None,
        }
    }

    /// Attest that the latest emitted snapshot is now the exact durable head.
    ///
    /// Call this only after writing and syncing the snapshot bytes, then
    /// advancing rollback-resistant head metadata with exact compare-and-swap.
    /// The returned unforgeable proof gates the single-use attempt dispatch.
    /// This method does no I/O and cannot verify a false caller attestation.
    pub fn confirm_snapshot_committed(
        &mut self,
        checkpoint: PendingSnapshotCheckpoint,
    ) -> Result<CommittedPendingSnapshot, SnapshotCommitError> {
        if self.committed_snapshot_checkpoint == Some(checkpoint)
            && self.uncommitted_snapshot_checkpoint.is_none()
        {
            return Ok(CommittedPendingSnapshot { checkpoint });
        }
        let emitted = self
            .uncommitted_snapshot_checkpoint
            .ok_or(SnapshotCommitError::NoEmittedSnapshot)?;
        if emitted != checkpoint {
            return Err(SnapshotCommitError::CheckpointMismatch);
        }
        if self.committed_snapshot_checkpoint.is_some_and(|committed| {
            committed.epoch != checkpoint.epoch || committed.revision > checkpoint.revision
        }) {
            return Err(SnapshotCommitError::CommittedHeadRegression);
        }
        self.committed_snapshot_checkpoint = Some(checkpoint);
        self.uncommitted_snapshot_checkpoint = None;
        Ok(CommittedPendingSnapshot { checkpoint })
    }

    /// Abandon an emitted candidate whose bytes/head were not committed.
    ///
    /// Use this only after proving the protected durable head did not advance
    /// to `checkpoint`. The emitted revision remains consumed, so the next
    /// snapshot must use a strictly greater revision. This method exists to
    /// recover from storage or compare-and-swap failure without allowing two
    /// outstanding candidates.
    pub fn abandon_uncommitted_snapshot(
        &mut self,
        checkpoint: PendingSnapshotCheckpoint,
    ) -> Result<(), SnapshotCommitError> {
        let emitted = self
            .uncommitted_snapshot_checkpoint
            .ok_or(SnapshotCommitError::NoEmittedSnapshot)?;
        if emitted != checkpoint {
            return Err(SnapshotCommitError::CheckpointMismatch);
        }
        self.uncommitted_snapshot_checkpoint = None;
        Ok(())
    }

    /// Register one connection lifetime with its caller-seeded Hop-by-Hop
    /// allocation start.
    ///
    /// The caller owns the Hop-by-Hop space of a connection outside this
    /// table (for example watchdog traffic); `first_hop_by_hop` must start a
    /// partition reserved for pending-request traffic. Within that partition
    /// the table allocates strictly increasing identifiers, which proves
    /// uniqueness on the connection for every attempt it emits.
    ///
    /// A token that still appears in any retained transaction's attempt
    /// history — including records recovered by [`Self::restore`] — is
    /// rejected as [`ConnectionTableError::DuplicateConnection`]: reusing it
    /// could allocate a Hop-by-Hop identifier already outstanding on a
    /// previous lifetime of the "same" connection and silently break
    /// correlation. Such tokens become reusable only after every referencing
    /// record has been retired or evicted.
    pub fn add_connection(
        &mut self,
        token: DiameterConnectionToken,
        first_hop_by_hop: u32,
    ) -> Result<(), ConnectionTableError> {
        if self.connections.contains_key(&token.get()) {
            return Err(ConnectionTableError::DuplicateConnection);
        }
        if self.connections.len() >= self.config.max_connections {
            return Err(ConnectionTableError::TableFull);
        }
        let referenced = self
            .records
            .values()
            .flat_map(|record| record.attempts.iter())
            .any(|attempt| attempt.connection == token);
        if referenced {
            return Err(ConnectionTableError::DuplicateConnection);
        }
        self.connections.insert(
            token.get(),
            ConnectionEntry {
                next_hop_by_hop: first_hop_by_hop,
                exhausted: false,
                open: true,
                live_attempts: 0,
            },
        );
        Ok(())
    }

    /// Mark a connection lifetime closed. New attempts on it are rejected;
    /// in-flight attempts keep their evidence until the caller classifies
    /// them with [`Self::record_attempt_failure`] or
    /// [`Self::fail_connection_attempts`]. A closed lifetime keeps its slot
    /// until [`Self::retire_connection`] releases it.
    pub fn close_connection(
        &mut self,
        token: DiameterConnectionToken,
    ) -> Result<(), ConnectionTableError> {
        let entry = self
            .connections
            .get_mut(&token.get())
            .ok_or(ConnectionTableError::UnknownConnection)?;
        entry.open = false;
        let now = self.clock.now();
        for record in self.records.values_mut() {
            for attempt in &mut record.attempts {
                if attempt.connection == token
                    && attempt.disposition == AttemptDisposition::Prepared
                {
                    attempt.disposition = AttemptDisposition::FailedBeforeWrite;
                    attempt.ended_at = Some(now);
                }
            }
        }
        Ok(())
    }

    /// Release one closed connection lifetime, freeing its registration slot.
    ///
    /// Removal is refused with [`ConnectionTableError::ConnectionInUse`]
    /// while any pending or retained transaction still holds an attempt on
    /// this token: those attempt identities must stay registered so late
    /// answers still correlate to bounded evidence. Completed records age out
    /// through the retention bound (or [`Self::retire`]), so a token becomes
    /// naturally removable once its last referencing record is gone.
    pub fn retire_connection(
        &mut self,
        token: DiameterConnectionToken,
    ) -> Result<(), ConnectionTableError> {
        let entry = self
            .connections
            .get(&token.get())
            .ok_or(ConnectionTableError::UnknownConnection)?;
        if entry.live_attempts > 0 {
            return Err(ConnectionTableError::ConnectionInUse);
        }
        self.connections.remove(&token.get());
        Ok(())
    }

    /// Track a canonical request on a registered connection.
    ///
    /// The request must be a Diameter request carrying exactly one non-empty
    /// Origin-Host and a clear T bit; its AVP bytes become the immutable
    /// canonical form every attempt reuses. Allocate the End-to-End
    /// identifier from the origin-scoped
    /// [`crate::end_to_end::DiameterEndToEndIdentifierAuthority`] (one
    /// affine identity per logical request, retained across failover); this
    /// table preserves it and never allocates one. A T-set request is a
    /// retransmission by definition and is rejected with
    /// [`TrackError::AlreadyRetransmitted`] rather than silently dropping
    /// RFC 6733 §3's duplicate-detection signal — recover it through
    /// [`Self::restore`] instead. The first attempt is created immediately
    /// with T clear and a connection-unique Hop-by-Hop identifier. The
    /// caller-supplied token value becomes the durable identity of the
    /// transaction.
    pub fn track(
        &mut self,
        request: OwnedMessage,
        connection: DiameterConnectionToken,
        token_value: CompletionTokenValue,
    ) -> Result<CompletionToken, TrackError> {
        if self.records.contains_key(&token_value)
            || self.suppressed_deliveries.contains_key(&token_value)
        {
            return Err(TrackError::DuplicateCompletionToken);
        }
        if self
            .pending_count
            .saturating_add(self.unacknowledged_completion_count)
            >= self.config.max_pending_transactions
        {
            return Err(TrackError::TableFull);
        }
        let facts = inspect_request(&request, self.decode_context())?;
        if self
            .pending_end_to_end
            .contains_key(&facts.end_to_end_identifier)
        {
            return Err(TrackError::DuplicateEndToEnd);
        }
        let hop_by_hop_identifier = self.allocate_hop_by_hop(connection)?;
        if self
            .attempt_index
            .contains_key(&(connection.get(), hop_by_hop_identifier))
        {
            return Err(TrackError::AttemptIdentifierConflict);
        }
        let now = self.clock.now();
        let attempt = AttemptEvidence {
            attempt_index: 0,
            connection,
            hop_by_hop_identifier,
            retransmission: false,
            disposition: AttemptDisposition::Prepared,
            started_at: now,
            written_at: None,
            ended_at: None,
            snapshotted_at: None,
        };
        let record = TransactionRecord {
            token_value,
            generation: 0,
            command_code: facts.command_code,
            application_id: facts.application_id,
            proxiable: facts.proxiable,
            end_to_end_identifier: facts.end_to_end_identifier,
            fixed_destination: facts.fixed_destination,
            raw_avps: request.raw_avps,
            attempts: vec![attempt],
            restored_baseline: 0,
            state: RecordState::Pending,
            completion_delivery_acknowledged: false,
            late_answer_count: 0,
            rejected_answer_count: 0,
        };
        self.attempt_index
            .insert((connection.get(), hop_by_hop_identifier), token_value);
        self.pending_end_to_end
            .insert(facts.end_to_end_identifier, token_value);
        if let Some(entry) = self.connections.get_mut(&connection.get()) {
            entry.live_attempts += 1;
        }
        self.records.insert(token_value, record);
        self.pending_count += 1;
        Ok(CompletionToken {
            value: token_value,
            generation: 0,
        })
    }

    /// Borrow a read-only view of one tracked transaction.
    #[must_use]
    pub fn transaction(
        &self,
        token: CompletionTokenValue,
    ) -> Option<DiameterRequestTransaction<'_>> {
        self.records
            .get(&token)
            .map(|record| DiameterRequestTransaction { record })
    }

    /// Reconcile a durable completion-delivery record before network re-arm.
    ///
    /// Call this immediately after [`Self::restore`] for every atomically
    /// loaded delivery record and replayable intent. A Ready or Claimed record
    /// proves an application outcome already exists, so the matching pending
    /// network request is suppressed and snapshot advancement stays blocked
    /// until an Acknowledged record arrives. Acknowledged removes the matching
    /// pending, retained, or suppressed record outright.
    ///
    /// This precedence prevents recovery from concurrently replaying an
    /// application outcome and retransmitting the request that produced it.
    /// Claimed remains unfinished work: fence the old worker, reclaim, replay
    /// the durable intent, and acknowledge according to the delivery-record
    /// contract.
    pub fn reconcile_completion_delivery(
        &mut self,
        durable: CompletionDeliveryRecord,
    ) -> Result<bool, CompletionDeliveryError> {
        if durable.key().epoch() != self.snapshot_epoch {
            return Err(CompletionDeliveryError::EpochMismatch);
        }
        let completion = durable.key().completion();
        let token = completion.value();

        if durable.state() == CompletionDeliveryState::Acknowledged {
            let suppressed = match self.suppressed_deliveries.get(&token) {
                Some(retained) if *retained == completion => {
                    self.suppressed_deliveries.remove(&token);
                    self.unacknowledged_completion_count =
                        self.unacknowledged_completion_count.saturating_sub(1);
                    true
                }
                Some(_) => return Err(CompletionDeliveryError::UnknownCompletion),
                None => false,
            };
            let retained = self.records.contains_key(&token);
            if retained {
                self.remove_record(token);
            }
            return Ok(suppressed || retained);
        }

        if let Some(retained) = self.suppressed_deliveries.get(&token) {
            if *retained != completion {
                return Err(CompletionDeliveryError::UnknownCompletion);
            }
            return Ok(true);
        }

        let Some(record) = self.records.get(&token) else {
            return Ok(false);
        };
        if !record.state.is_pending() {
            if record.completion_token() != completion {
                return Err(CompletionDeliveryError::UnknownCompletion);
            }
            return Ok(true);
        }

        self.remove_record(token);
        self.suppressed_deliveries.insert(token, completion);
        self.unacknowledged_completion_count =
            self.unacknowledged_completion_count.saturating_add(1);
        Ok(true)
    }

    /// Reconcile a durably acknowledged completion against a restored table.
    ///
    /// Call this immediately after [`Self::restore`] and before re-arming any
    /// request. It removes the matching pending or retained record without
    /// emitting a completion, so an older still-authoritative pending snapshot
    /// cannot reapply an effect that was atomically acknowledged before the
    /// crash. The record must decode as acknowledged and belong to this
    /// table's snapshot epoch. Returns whether a matching transaction existed.
    pub fn reconcile_acknowledged(
        &mut self,
        acknowledged: CompletionDeliveryRecord,
    ) -> Result<bool, CompletionDeliveryError> {
        if acknowledged.state() != CompletionDeliveryState::Acknowledged {
            return Err(CompletionDeliveryError::NotAcknowledged);
        }
        self.reconcile_completion_delivery(acknowledged)
    }

    /// Record that a retained live completion and its replayable application
    /// intent were durably acknowledged.
    ///
    /// The supplied record must be in the acknowledged state and belong to
    /// this table's epoch. Until every completion is acknowledged,
    /// [`Self::snapshot`] fails closed so a newer pending-only checkpoint
    /// cannot discard the sole replay source.
    pub fn acknowledge_completion_delivery(
        &mut self,
        acknowledged: CompletionDeliveryRecord,
    ) -> Result<(), CompletionDeliveryError> {
        if acknowledged.state() != CompletionDeliveryState::Acknowledged {
            return Err(CompletionDeliveryError::NotAcknowledged);
        }
        if acknowledged.key().epoch() != self.snapshot_epoch {
            return Err(CompletionDeliveryError::EpochMismatch);
        }
        let completion = acknowledged.key().completion();
        if let Some(suppressed) = self.suppressed_deliveries.get(&completion.value()) {
            if *suppressed != completion {
                return Err(CompletionDeliveryError::UnknownCompletion);
            }
            self.suppressed_deliveries.remove(&completion.value());
            self.unacknowledged_completion_count =
                self.unacknowledged_completion_count.saturating_sub(1);
            return Ok(());
        }
        let record = self
            .records
            .get_mut(&completion.value())
            .ok_or(CompletionDeliveryError::UnknownCompletion)?;
        if record.state.is_pending() {
            return Err(CompletionDeliveryError::CompletionStillPending);
        }
        if record.completion_token() != completion {
            return Err(CompletionDeliveryError::UnknownCompletion);
        }
        if !record.completion_delivery_acknowledged {
            record.completion_delivery_acknowledged = true;
            self.unacknowledged_completion_count =
                self.unacknowledged_completion_count.saturating_sub(1);
            self.enforce_completion_retention();
        }
        Ok(())
    }

    /// Take the exact wire message for the latest prepared attempt once.
    ///
    /// The returned message reuses the canonical AVP bytes unchanged and only
    /// rewrites the header: the attempt's Hop-by-Hop identifier, the T bit for
    /// failover attempts, and the recomputed length. The caller writes these
    /// bytes to the attempt's connection and reports the outcome through
    /// [`Self::record_attempt_write_success`] or
    /// [`Self::record_attempt_failure`]. Taking the message atomically changes
    /// the attempt from [`AttemptDisposition::Prepared`] to
    /// [`AttemptDisposition::InFlight`], so the live-send API cannot return
    /// the same T-clear or retransmission attempt twice.
    ///
    /// `committed` must be the table's current proof returned by
    /// [`Self::confirm_snapshot_committed`], and that committed snapshot must
    /// contain the attempt. This persist-before-dispatch fence ensures a crash
    /// can recover every attempt that may have reached a peer and prevents
    /// restore/send loops from bypassing the configured attempt bound.
    ///
    /// Attempts recovered by [`Self::restore`] are evidence of dead connection
    /// lifetimes: they are never served here, even when still marked in
    /// flight. Re-arm the record with [`Self::failover`] first — the
    /// re-armed attempt carries T=1 as RFC 6733 §5.5.4 requires — otherwise
    /// this returns [`TransactionAccessError::NoLiveAttempt`]. Use
    pub fn take_attempt_dispatch(
        &mut self,
        token: CompletionTokenValue,
        committed: CommittedPendingSnapshot,
    ) -> Result<AttemptDispatch, TransactionAccessError> {
        if self.committed_snapshot_checkpoint != Some(committed.checkpoint) {
            return Err(TransactionAccessError::SnapshotProofMismatch);
        }
        let (attempt_index, attempt, message) = {
            let record = self
                .records
                .get(&token)
                .ok_or(TransactionAccessError::UnknownTransaction)?;
            if !record.state.is_pending() {
                return Err(TransactionAccessError::NotPending);
            }
            let attempt_index = record
                .attempts
                .iter()
                .rposition(|attempt| {
                    attempt.disposition == AttemptDisposition::Prepared
                        && attempt.attempt_index >= record.restored_baseline
                })
                .ok_or(TransactionAccessError::NoLiveAttempt)?;
            let attempt = record.attempts[attempt_index];
            (attempt_index, attempt, record.wire_message(&attempt))
        };
        if attempt
            .snapshotted_at
            .is_none_or(|revision| revision > committed.checkpoint.revision)
        {
            return Err(TransactionAccessError::AttemptNotDurablySnapshotted);
        }
        let connection_open = self
            .connections
            .get(&attempt.connection.get())
            .is_some_and(|connection| connection.open);
        if !connection_open {
            if let Some(record) = self.records.get_mut(&token) {
                let slot = &mut record.attempts[attempt_index];
                slot.disposition = AttemptDisposition::FailedBeforeWrite;
                slot.ended_at = Some(self.clock.now());
            }
            return Err(TransactionAccessError::ConnectionNotOpen);
        }
        let record = self
            .records
            .get_mut(&token)
            .ok_or(TransactionAccessError::UnknownTransaction)?;
        record.attempts[attempt_index].disposition = AttemptDisposition::InFlight;
        Ok(AttemptDispatch {
            attempt: attempt.attempt_id(),
            message,
        })
    }

    /// Record that one attempt was written completely and is awaiting an
    /// answer.
    ///
    /// This transition is distinct from [`AttemptDisposition::InFlight`],
    /// which means the write outcome is not yet known. It is retained in
    /// snapshot evidence so recovery can distinguish a queued/partial write
    /// from a request known to have reached the transport.
    pub fn record_attempt_write_success(
        &mut self,
        token: CompletionTokenValue,
        attempt: AttemptId,
    ) -> Result<AttemptEvidence, TransactionAccessError> {
        let record = self
            .records
            .get_mut(&token)
            .ok_or(TransactionAccessError::UnknownTransaction)?;
        if !record.state.is_pending() {
            return Err(TransactionAccessError::NotPending);
        }
        let slot = record
            .attempts
            .iter_mut()
            .find(|slot| slot.attempt_id() == attempt)
            .ok_or(TransactionAccessError::UnknownAttempt)?;
        if slot.disposition != AttemptDisposition::InFlight {
            return Err(TransactionAccessError::InvalidAttemptTransition);
        }
        let now = self.clock.now();
        slot.disposition = AttemptDisposition::WrittenAwaitingAnswer;
        slot.written_at = Some(now);
        Ok(*slot)
    }

    /// Record the transport-reported failure classification of one attempt.
    ///
    /// The attempt must still be in flight. This only updates bounded
    /// evidence; whether and where to retransmit remains caller policy.
    pub fn record_attempt_failure(
        &mut self,
        token: CompletionTokenValue,
        attempt: AttemptId,
        failure: AttemptFailure,
    ) -> Result<AttemptEvidence, TransactionAccessError> {
        let record = self
            .records
            .get_mut(&token)
            .ok_or(TransactionAccessError::UnknownTransaction)?;
        let slot = record
            .attempts
            .iter_mut()
            .find(|slot| slot.attempt_id() == attempt)
            .ok_or(TransactionAccessError::UnknownAttempt)?;
        match (slot.disposition, failure) {
            (AttemptDisposition::InFlight, _) => {}
            (AttemptDisposition::Prepared, AttemptFailure::BeforeWrite) => {}
            (
                AttemptDisposition::WrittenAwaitingAnswer,
                AttemptFailure::TransportLostAfterWrite,
            ) => {}
            (AttemptDisposition::WrittenAwaitingAnswer, _) => {
                return Err(TransactionAccessError::InvalidAttemptTransition);
            }
            _ => return Err(TransactionAccessError::AttemptNotInFlight),
        }
        let now = self.clock.now();
        if failure == AttemptFailure::TransportLostAfterWrite && slot.written_at.is_none() {
            slot.written_at = Some(now);
        }
        slot.disposition = failure.disposition();
        slot.ended_at = Some(now);
        Ok(*slot)
    }

    /// Classify every in-flight attempt on a lost connection at once.
    ///
    /// Returns the number of attempts marked. Use
    /// [`Self::record_attempt_failure`] when the transport knows individual
    /// write outcomes.
    pub fn fail_connection_attempts(
        &mut self,
        connection: DiameterConnectionToken,
        failure: AttemptFailure,
    ) -> usize {
        let now = self.clock.now();
        let mut marked = 0usize;
        for record in self.records.values_mut() {
            for attempt in &mut record.attempts {
                let compatible = match (attempt.disposition, failure) {
                    (AttemptDisposition::InFlight, _) => true,
                    (AttemptDisposition::Prepared, AttemptFailure::BeforeWrite) => true,
                    (
                        AttemptDisposition::WrittenAwaitingAnswer,
                        AttemptFailure::TransportLostAfterWrite,
                    ) => true,
                    _ => false,
                };
                if attempt.connection == connection && compatible {
                    if failure == AttemptFailure::TransportLostAfterWrite
                        && attempt.written_at.is_none()
                    {
                        attempt.written_at = Some(now);
                    }
                    attempt.disposition = failure.disposition();
                    attempt.ended_at = Some(now);
                    marked += 1;
                }
            }
        }
        marked
    }

    /// Start a failover (or restored) retransmission attempt on an alternate
    /// connection.
    ///
    /// The new attempt preserves the canonical request and End-to-End
    /// identifier, always sets T=1, and allocates a Hop-by-Hop identifier
    /// unique on the selected connection. A request pinning a
    /// `Destination-Host` requires
    /// [`AlternateRoutability::DestinationAsserted`]; otherwise the caller
    /// must finish the transaction with
    /// [`UndeliverableReason::FixedDestinationNoAlternate`]. The previous
    /// attempt need not be failed first: parallel in-flight attempts are
    /// legal, and only the first validated answer completes the transaction.
    pub fn failover(
        &mut self,
        token: CompletionTokenValue,
        connection: DiameterConnectionToken,
        routability: AlternateRoutability,
    ) -> Result<AttemptEvidence, FailoverError> {
        let (fixed_destination, attempt_index) = {
            let record = self
                .records
                .get(&token)
                .ok_or(FailoverError::UnknownTransaction)?;
            if !record.state.is_pending() {
                return Err(FailoverError::NotPending);
            }
            if record.attempts.len() >= self.config.max_attempts_per_transaction {
                return Err(FailoverError::AttemptLimitReached);
            }
            (record.fixed_destination, record.attempts.len())
        };
        if fixed_destination && routability == AlternateRoutability::RealmRouted {
            return Err(FailoverError::FixedDestinationRequiresAssertion);
        }
        let hop_by_hop_identifier = self.allocate_hop_by_hop(connection)?;
        if self
            .attempt_index
            .contains_key(&(connection.get(), hop_by_hop_identifier))
        {
            return Err(FailoverError::AttemptIdentifierConflict);
        }
        let now = self.clock.now();
        let attempt = AttemptEvidence {
            attempt_index,
            connection,
            hop_by_hop_identifier,
            retransmission: true,
            disposition: AttemptDisposition::Prepared,
            started_at: now,
            written_at: None,
            ended_at: None,
            snapshotted_at: None,
        };
        let record = self
            .records
            .get_mut(&token)
            .ok_or(FailoverError::UnknownTransaction)?;
        record.attempts.push(attempt);
        self.attempt_index
            .insert((connection.get(), hop_by_hop_identifier), token);
        if let Some(entry) = self.connections.get_mut(&connection.get()) {
            entry.live_attempts += 1;
        }
        Ok(attempt)
    }

    /// Correlate one inbound answer to its pending transaction.
    ///
    /// The answer is matched by (connection, Hop-by-Hop), then validated
    /// against the request's End-to-End identifier, command code, and
    /// application. The first validated answer produces the transaction's
    /// single terminal completion; every later answer — late, duplicated,
    /// reordered, or arriving on the other connection — is bounded evidence
    /// only and never re-delivers a completion.
    pub fn correlate_answer(
        &mut self,
        connection: DiameterConnectionToken,
        answer: OwnedMessage,
    ) -> AnswerDisposition {
        let attempt_key = (connection.get(), answer.header.hop_by_hop_identifier);
        let Some(token) = self.attempt_index.get(&attempt_key).copied() else {
            self.unmatched_answers = self.unmatched_answers.saturating_add(1);
            return AnswerDisposition::Unmatched(UnmatchedAnswerEvidence {
                connection,
                hop_by_hop_identifier: answer.header.hop_by_hop_identifier,
            });
        };
        let attempt_id = AttemptId {
            connection,
            hop_by_hop_identifier: answer.header.hop_by_hop_identifier,
        };
        let now = self.clock.now();
        let decode_context = self.decode_context();
        let record = match self.records.get_mut(&token) {
            Some(record) => record,
            None => {
                self.unmatched_answers = self.unmatched_answers.saturating_add(1);
                return AnswerDisposition::Unmatched(UnmatchedAnswerEvidence {
                    connection,
                    hop_by_hop_identifier: answer.header.hop_by_hop_identifier,
                });
            }
        };
        let attempt_disposition = record
            .attempts
            .iter()
            .find(|slot| slot.attempt_id() == attempt_id)
            .map(|slot| slot.disposition);
        let Some(attempt_disposition) = attempt_disposition else {
            self.unmatched_answers = self.unmatched_answers.saturating_add(1);
            return AnswerDisposition::Unmatched(UnmatchedAnswerEvidence {
                connection,
                hop_by_hop_identifier: attempt_id.hop_by_hop_identifier,
            });
        };
        let rejection = inspect_answer(&answer, record, decode_context).or_else(|| {
            (!attempt_disposition.can_receive_answer())
                .then_some(AnswerRejectionReason::AttemptNotAnswerEligible)
        });
        if let Some(reason) = rejection {
            record.rejected_answer_count = record.rejected_answer_count.saturating_add(1);
            return AnswerDisposition::Rejected(AnswerRejection {
                attempt: attempt_id,
                reason,
                rejected_answer_count: record.rejected_answer_count,
            });
        }
        match record.state {
            RecordState::Pending => {
                let attempt_slot = record
                    .attempts
                    .iter_mut()
                    .find(|slot| slot.attempt_id() == attempt_id);
                let Some(slot) = attempt_slot else {
                    self.unmatched_answers = self.unmatched_answers.saturating_add(1);
                    return AnswerDisposition::Unmatched(UnmatchedAnswerEvidence {
                        connection,
                        hop_by_hop_identifier: attempt_id.hop_by_hop_identifier,
                    });
                };
                if slot.written_at.is_none() {
                    slot.written_at = Some(now);
                }
                slot.disposition = AttemptDisposition::Answered;
                slot.ended_at = Some(now);
                let attempt = *slot;
                record.generation = 1;
                let token_with_generation = record.completion_token();
                self.complete(token, CompletionKind::Answered);
                AnswerDisposition::Completed(TransactionCompletion::Answered {
                    token: token_with_generation,
                    answer,
                    attempt,
                })
            }
            RecordState::Completed { kind, .. } => {
                record.late_answer_count = record.late_answer_count.saturating_add(1);
                AnswerDisposition::LateAnswer(LateAnswerEvidence {
                    attempt: attempt_id,
                    completion: kind,
                    late_answer_count: record.late_answer_count,
                })
            }
        }
    }

    /// Terminate the transaction as undeliverable with a typed reason.
    ///
    /// Use [`UndeliverableReason::FixedDestinationNoAlternate`] when the
    /// request pins a `Destination-Host` and no valid alternate exists; the
    /// primitive never silently drops or rewrites the destination.
    pub fn finish_undeliverable(
        &mut self,
        token: CompletionTokenValue,
        reason: UndeliverableReason,
    ) -> Result<TransactionCompletion, TransactionAccessError> {
        let (completion_token, attempts) = self.begin_terminal(token)?;
        self.complete(token, CompletionKind::Undeliverable);
        Ok(TransactionCompletion::Undeliverable {
            token: completion_token,
            reason,
            attempts,
        })
    }

    /// Terminate the transaction because the caller's retry policy is
    /// exhausted.
    pub fn finish_exhausted(
        &mut self,
        token: CompletionTokenValue,
    ) -> Result<TransactionCompletion, TransactionAccessError> {
        let (completion_token, attempts) = self.begin_terminal(token)?;
        self.complete(token, CompletionKind::Exhausted);
        Ok(TransactionCompletion::Exhausted {
            token: completion_token,
            attempts,
        })
    }

    /// Terminate the transaction without a provable outcome.
    pub fn finish_indeterminate(
        &mut self,
        token: CompletionTokenValue,
        reason: IndeterminateReason,
    ) -> Result<TransactionCompletion, TransactionAccessError> {
        let (completion_token, attempts) = self.begin_terminal(token)?;
        self.complete(token, CompletionKind::Indeterminate);
        Ok(TransactionCompletion::Indeterminate {
            token: completion_token,
            reason,
            attempts,
        })
    }

    /// Drop one completed transaction and its attempt correlation evidence.
    ///
    /// Pending and durably unacknowledged completions cannot be retired.
    /// Acknowledgement metadata and replayable intent remain caller-owned and
    /// must not be garbage-collected until a newer exact committed snapshot
    /// excludes the request. Returns whether an acknowledged completed record
    /// was removed.
    pub fn retire(&mut self, token: CompletionTokenValue) -> bool {
        let Some(record) = self.records.get(&token) else {
            return false;
        };
        if record.state.is_pending() || !record.completion_delivery_acknowledged {
            return false;
        }
        self.remove_record(token);
        true
    }

    /// Return the number of pending transactions.
    #[must_use]
    pub const fn pending_count(&self) -> usize {
        self.pending_count
    }

    /// Return the number of terminal completions whose replayable intent has
    /// not yet been durably acknowledged.
    #[must_use]
    pub const fn unacknowledged_completion_count(&self) -> usize {
        self.unacknowledged_completion_count
    }

    /// Return the number of completed transactions retained for late-answer
    /// evidence.
    #[must_use]
    pub const fn retained_completed_count(&self) -> usize {
        self.completed_count
    }

    /// Return the number of registered connection lifetimes.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Return the bounded count of completed records evicted to hold the
    /// retention bound.
    #[must_use]
    pub const fn evicted_completion_count(&self) -> u64 {
        self.evicted_completions
    }

    /// Return the bounded count of answers that matched no retained attempt.
    #[must_use]
    pub const fn unmatched_answer_count(&self) -> u64 {
        self.unmatched_answers
    }

    /// Encode every pending transaction into a rollback-fenced, explicitly
    /// sensitive snapshot form.
    ///
    /// The snapshot contains canonical request bytes and must be stored only
    /// in encrypted, integrity-protected storage. Completed records are
    /// live-only and never serialized. `checkpoint` must use the existing
    /// lineage, if any, and strictly advance its revision. Persist the encoded
    /// bytes and checkpoint together, then advance a separately protected
    /// durable high-water to this revision. The high-water is required at
    /// restore time; encryption and integrity alone cannot detect rollback.
    /// Records are encoded in completion-token order so identical table states
    /// at one checkpoint produce identical bytes.
    pub fn snapshot(
        &mut self,
        checkpoint: PendingSnapshotCheckpoint,
    ) -> Result<PendingTableSnapshot, SnapshotCreateError> {
        if self.uncommitted_snapshot_checkpoint.is_some() {
            return Err(SnapshotCreateError::UncommittedSnapshotOutstanding);
        }
        if checkpoint.epoch != self.snapshot_epoch {
            return Err(SnapshotCreateError::EpochMismatch);
        }
        if let Some(previous) = self.snapshot_checkpoint {
            if previous.epoch != checkpoint.epoch {
                return Err(SnapshotCreateError::EpochMismatch);
            }
            if checkpoint.revision <= previous.revision {
                return Err(SnapshotCreateError::RevisionNotAdvanced);
            }
        }
        if self.unacknowledged_completion_count > 0 {
            return Err(SnapshotCreateError::UnacknowledgedCompletion);
        }
        let mut pending: Vec<&TransactionRecord> = self
            .records
            .values()
            .filter(|record| record.state.is_pending())
            .collect();
        pending.sort_by_key(|record| record.token_value);
        let encoded_len = pending
            .iter()
            .try_fold(SNAPSHOT_HEADER_LEN, |total, record| {
                let attempts_len = record
                    .attempts
                    .len()
                    .checked_mul(SNAPSHOT_ATTEMPT_LEN)
                    .ok_or(SnapshotCreateError::SizeLimitExceeded)?;
                total
                    .checked_add(SNAPSHOT_RECORD_FIXED_LEN)
                    .and_then(|value| value.checked_add(attempts_len))
                    .and_then(|value| value.checked_add(record.raw_avps.len()))
                    .ok_or(SnapshotCreateError::SizeLimitExceeded)
            })?;
        if encoded_len > self.config.max_snapshot_bytes {
            return Err(SnapshotCreateError::SizeLimitExceeded);
        }
        let mut encoded = Zeroizing::new(Vec::new());
        encoded
            .try_reserve_exact(encoded_len)
            .map_err(|_| SnapshotCreateError::AllocationFailed)?;
        encoded.extend_from_slice(&SNAPSHOT_MAGIC.to_be_bytes());
        encoded.extend_from_slice(&SNAPSHOT_VERSION.to_be_bytes());
        encoded.extend_from_slice(&checkpoint.epoch.get().to_be_bytes());
        encoded.extend_from_slice(&checkpoint.revision.get().to_be_bytes());
        push_count(&mut encoded, pending.len());
        for record in pending {
            encoded.extend_from_slice(&record.token_value.get().to_be_bytes());
            encoded.extend_from_slice(&record.generation.to_be_bytes());
            encoded.extend_from_slice(&record.end_to_end_identifier.to_be_bytes());
            encoded.extend_from_slice(&record.command_code.get().to_be_bytes());
            encoded.extend_from_slice(&record.application_id.get().to_be_bytes());
            let mut flags = 0_u8;
            if record.fixed_destination {
                flags |= 0x01;
            }
            if record.proxiable {
                flags |= 0x02;
            }
            encoded.push(flags);
            push_count(&mut encoded, record.attempts.len());
            for attempt in &record.attempts {
                encoded.extend_from_slice(&attempt.connection.get().to_be_bytes());
                encoded.extend_from_slice(&attempt.hop_by_hop_identifier.to_be_bytes());
                encoded.push(attempt.disposition.as_snapshot_code());
                encoded.extend_from_slice(&micros_of(attempt.started_at).to_be_bytes());
                match attempt.written_at {
                    Some(written) => {
                        encoded.extend_from_slice(&micros_of(written).to_be_bytes());
                    }
                    None => {
                        encoded.extend_from_slice(&MICROS_SENTINEL_NONE.to_be_bytes());
                    }
                }
                match attempt.ended_at {
                    Some(ended) => {
                        encoded.extend_from_slice(&micros_of(ended).to_be_bytes());
                    }
                    None => {
                        encoded.extend_from_slice(&MICROS_SENTINEL_NONE.to_be_bytes());
                    }
                }
            }
            encoded.extend_from_slice(&(record.raw_avps.len() as u32).to_be_bytes());
            encoded.extend_from_slice(&record.raw_avps);
        }
        for record in self
            .records
            .values_mut()
            .filter(|record| record.state.is_pending())
        {
            for attempt in &mut record.attempts {
                if attempt.snapshotted_at.is_none() {
                    attempt.snapshotted_at = Some(checkpoint.revision);
                }
            }
        }
        self.snapshot_checkpoint = Some(checkpoint);
        self.uncommitted_snapshot_checkpoint = Some(checkpoint);
        Ok(PendingTableSnapshot {
            checkpoint,
            encoded,
        })
    }

    /// Restore a table from snapshot bytes previously written to durable
    /// (encrypted) storage.
    ///
    /// `expected_checkpoint` is the caller's rollback-resistant committed
    /// head. A snapshot from another lineage, an older rollback, or a newer
    /// orphan that was written without committing the head is rejected with a
    /// typed error before any record is installed.
    /// Malformed, truncated, trailing-garbage, unsupported-version,
    /// bound-violating, and internally inconsistent records are likewise
    /// rejected atomically. Restored records retain full attempt evidence;
    /// re-arm each one with [`Self::failover`] onto a fresh connection, which
    /// retransmits with T=1 while preserving the End-to-End identifier and
    /// canonical request.
    ///
    /// Delivery of a restored completion is **at-least-once**: the consumer
    /// may already have applied it before a crash. Use
    /// [`CompletionDeliveryRecord`] in a durable compare-and-swap store:
    /// claim before application, acknowledge only after the side effect is
    /// durable, and recover (rather than skip) an unfinished claim. Exactly
    /// once requires either atomic side-effect-plus-ack commit or an
    /// idempotent side effect keyed by [`CompletionToken`].
    pub fn restore(
        bytes: &[u8],
        expected_checkpoint: PendingSnapshotCheckpoint,
        config: PendingRequestTableConfig,
        clock: Arc<dyn PendingRequestClock>,
    ) -> Result<Self, SnapshotRestoreError> {
        config
            .validate()
            .map_err(|_| SnapshotRestoreError::LimitExceeded)?;
        if bytes.len() > config.max_snapshot_bytes {
            return Err(SnapshotRestoreError::LimitExceeded);
        }
        let mut table = Self {
            config,
            clock,
            snapshot_epoch: expected_checkpoint.epoch,
            records: HashMap::new(),
            suppressed_deliveries: HashMap::new(),
            attempt_index: HashMap::new(),
            pending_end_to_end: HashMap::new(),
            connections: HashMap::new(),
            pending_count: 0,
            unacknowledged_completion_count: 0,
            completed_count: 0,
            completion_sequence: 0,
            evicted_completions: 0,
            unmatched_answers: 0,
            snapshot_checkpoint: None,
            uncommitted_snapshot_checkpoint: None,
            committed_snapshot_checkpoint: None,
        };
        let mut cursor = SnapshotCursor::new(bytes);
        if cursor.u32()? != SNAPSHOT_MAGIC {
            return Err(SnapshotRestoreError::Malformed);
        }
        if cursor.u16()? != SNAPSHOT_VERSION {
            return Err(SnapshotRestoreError::UnsupportedVersion);
        }
        let epoch = PendingSnapshotEpoch::new(
            NonZeroU128::new(cursor.u128()?).ok_or(SnapshotRestoreError::InvalidRecord)?,
        );
        if epoch != expected_checkpoint.epoch {
            return Err(SnapshotRestoreError::EpochMismatch);
        }
        let revision = PendingSnapshotRevision::new(
            NonZeroU64::new(cursor.u64()?).ok_or(SnapshotRestoreError::InvalidRecord)?,
        );
        if revision < expected_checkpoint.revision {
            return Err(SnapshotRestoreError::Stale);
        }
        if revision > expected_checkpoint.revision {
            return Err(SnapshotRestoreError::Uncommitted);
        }
        let checkpoint = PendingSnapshotCheckpoint { epoch, revision };
        table.snapshot_checkpoint = Some(checkpoint);
        table.committed_snapshot_checkpoint = Some(checkpoint);
        let record_count = cursor.count()?;
        if record_count > config.max_pending_transactions {
            return Err(SnapshotRestoreError::LimitExceeded);
        }
        for _ in 0..record_count {
            let record = table.restore_record(&mut cursor)?;
            table.index_restored_record(record)?;
            table.pending_count += 1;
        }
        if !cursor.is_exhausted() {
            return Err(SnapshotRestoreError::Malformed);
        }
        Ok(table)
    }

    fn decode_context(&self) -> DecodeContext {
        DecodeContext {
            max_message_len: self.config.max_message_len,
            ..DecodeContext::conservative()
        }
    }

    fn allocate_hop_by_hop(
        &mut self,
        connection: DiameterConnectionToken,
    ) -> Result<u32, HopByHopAllocateError> {
        let entry = self
            .connections
            .get_mut(&connection.get())
            .ok_or(HopByHopAllocateError::UnknownConnection)?;
        if !entry.open {
            return Err(HopByHopAllocateError::ConnectionClosed);
        }
        if entry.exhausted {
            return Err(HopByHopAllocateError::Exhausted);
        }
        let allocated = entry.next_hop_by_hop;
        if allocated == u32::MAX {
            entry.exhausted = true;
        } else {
            entry.next_hop_by_hop = allocated + 1;
        }
        Ok(allocated)
    }

    fn begin_terminal(
        &mut self,
        token: CompletionTokenValue,
    ) -> Result<(CompletionToken, usize), TransactionAccessError> {
        let record = self
            .records
            .get_mut(&token)
            .ok_or(TransactionAccessError::UnknownTransaction)?;
        if !record.state.is_pending() {
            return Err(TransactionAccessError::NotPending);
        }
        record.generation = 1;
        Ok((record.completion_token(), record.attempts.len()))
    }

    fn complete(&mut self, token: CompletionTokenValue, kind: CompletionKind) {
        self.completion_sequence = self.completion_sequence.saturating_add(1);
        let sequence = self.completion_sequence;
        if let Some(record) = self.records.get_mut(&token) {
            record.state = RecordState::Completed { kind, sequence };
        }
        self.pending_count = self.pending_count.saturating_sub(1);
        self.unacknowledged_completion_count =
            self.unacknowledged_completion_count.saturating_add(1);
        self.completed_count = self.completed_count.saturating_add(1);
        if let Some(record) = self.records.get(&token) {
            self.pending_end_to_end
                .remove(&record.end_to_end_identifier);
        }
        self.enforce_completion_retention();
    }

    fn enforce_completion_retention(&mut self) {
        let live_unacknowledged = self
            .unacknowledged_completion_count
            .saturating_sub(self.suppressed_deliveries.len());
        while self.completed_count.saturating_sub(live_unacknowledged)
            > self.config.max_retained_completions
        {
            let Some(oldest) = self
                .records
                .iter()
                .filter_map(|(value, record)| match record.state {
                    RecordState::Completed { sequence, .. }
                        if record.completion_delivery_acknowledged =>
                    {
                        Some((*value, sequence))
                    }
                    RecordState::Pending => None,
                    RecordState::Completed { .. } => None,
                })
                .min_by_key(|(_, sequence)| *sequence)
                .map(|(value, _)| value)
            else {
                break;
            };
            self.remove_record(oldest);
            self.evicted_completions = self.evicted_completions.saturating_add(1);
        }
    }

    fn remove_record(&mut self, token: CompletionTokenValue) {
        if let Some(record) = self.records.remove(&token) {
            for attempt in &record.attempts {
                self.attempt_index
                    .remove(&(attempt.connection.get(), attempt.hop_by_hop_identifier));
                if let Some(entry) = self.connections.get_mut(&attempt.connection.get()) {
                    entry.live_attempts = entry.live_attempts.saturating_sub(1);
                }
            }
            self.pending_end_to_end
                .remove(&record.end_to_end_identifier);
            if record.state.is_pending() {
                self.pending_count = self.pending_count.saturating_sub(1);
            } else {
                if !record.completion_delivery_acknowledged {
                    self.unacknowledged_completion_count =
                        self.unacknowledged_completion_count.saturating_sub(1);
                }
                self.completed_count = self.completed_count.saturating_sub(1);
            }
        }
    }

    fn restore_record(
        &self,
        cursor: &mut SnapshotCursor<'_>,
    ) -> Result<TransactionRecord, SnapshotRestoreError> {
        let token_bits = cursor.u128()?;
        let token_value = CompletionTokenValue::new(
            NonZeroU128::new(token_bits).ok_or(SnapshotRestoreError::InvalidRecord)?,
        );
        let generation = cursor.u64()?;
        if generation != 0 {
            return Err(SnapshotRestoreError::InvalidRecord);
        }
        let end_to_end_identifier = cursor.u32()?;
        let command_code = CommandCode::new(cursor.u32()?);
        if !command_code.fits_wire() {
            return Err(SnapshotRestoreError::InvalidRecord);
        }
        let application_id = ApplicationId::new(cursor.u32()?);
        let flags = cursor.u8()?;
        if flags & !0x03 != 0 {
            return Err(SnapshotRestoreError::InvalidRecord);
        }
        let fixed_destination = flags & 0x01 != 0;
        let proxiable = flags & 0x02 != 0;
        let attempt_count = cursor.count()?;
        if attempt_count == 0 {
            return Err(SnapshotRestoreError::InvalidRecord);
        }
        if attempt_count > self.config.max_attempts_per_transaction {
            return Err(SnapshotRestoreError::LimitExceeded);
        }
        let mut attempts = Vec::with_capacity(attempt_count);
        for attempt_index in 0..attempt_count {
            let connection_bits = cursor.u64()?;
            let connection = DiameterConnectionToken::new(
                NonZeroU64::new(connection_bits).ok_or(SnapshotRestoreError::InvalidRecord)?,
            );
            let hop_by_hop_identifier = cursor.u32()?;
            let disposition = AttemptDisposition::from_snapshot_code(cursor.u8()?)?;
            if disposition == AttemptDisposition::Answered {
                return Err(SnapshotRestoreError::InvalidRecord);
            }
            let started_at = Duration::from_micros(cursor.u64()?);
            let written_bits = cursor.u64()?;
            let written_at = if written_bits == MICROS_SENTINEL_NONE {
                None
            } else {
                Some(Duration::from_micros(written_bits))
            };
            let ended_bits = cursor.u64()?;
            let ended_at = if ended_bits == MICROS_SENTINEL_NONE {
                None
            } else {
                Some(Duration::from_micros(ended_bits))
            };
            let open = matches!(
                disposition,
                AttemptDisposition::Prepared
                    | AttemptDisposition::InFlight
                    | AttemptDisposition::WrittenAwaitingAnswer
            );
            if ended_at.is_none() != open
                || (matches!(
                    disposition,
                    AttemptDisposition::WrittenAwaitingAnswer
                        | AttemptDisposition::TransportLostAfterWrite
                ) && written_at.is_none())
                || (matches!(
                    disposition,
                    AttemptDisposition::Prepared
                        | AttemptDisposition::InFlight
                        | AttemptDisposition::FailedBeforeWrite
                        | AttemptDisposition::FailedUncertainWrite
                ) && written_at.is_some())
                || written_at.is_some_and(|written| written < started_at)
                || ended_at.is_some_and(|ended| ended < started_at)
                || matches!((written_at, ended_at), (Some(written), Some(ended)) if ended < written)
            {
                return Err(SnapshotRestoreError::InvalidRecord);
            }
            attempts.push(AttemptEvidence {
                attempt_index,
                connection,
                hop_by_hop_identifier,
                retransmission: attempt_index > 0,
                disposition,
                started_at,
                written_at,
                ended_at,
                snapshotted_at: Some(
                    self.snapshot_checkpoint
                        .ok_or(SnapshotRestoreError::InvalidRecord)?
                        .revision,
                ),
            });
        }
        let request_len = cursor.u32()? as usize;
        if request_len > self.config.max_message_len {
            return Err(SnapshotRestoreError::LimitExceeded);
        }
        let raw_avps = Bytes::copy_from_slice(cursor.take(request_len)?);
        let message_len = DIAMETER_HEADER_LEN
            .checked_add(raw_avps.len())
            .and_then(|length| u32::try_from(length).ok())
            .ok_or(SnapshotRestoreError::InvalidRecord)?;
        let request = OwnedMessage {
            header: Header::new(
                CommandFlags::request(proxiable),
                command_code,
                application_id,
                0,
                end_to_end_identifier,
            )
            .with_length(message_len),
            raw_avps,
        };
        let facts = inspect_request(&request, self.decode_context())
            .map_err(|_| SnapshotRestoreError::InvalidRecord)?;
        if facts.fixed_destination != fixed_destination
            || facts.end_to_end_identifier != end_to_end_identifier
            || facts.command_code != command_code
            || facts.application_id != application_id
            || facts.proxiable != proxiable
        {
            return Err(SnapshotRestoreError::InvalidRecord);
        }
        let restored_baseline = attempts.len();
        Ok(TransactionRecord {
            token_value,
            generation,
            command_code,
            application_id,
            proxiable,
            end_to_end_identifier,
            fixed_destination,
            raw_avps: request.raw_avps,
            attempts,
            restored_baseline,
            state: RecordState::Pending,
            completion_delivery_acknowledged: false,
            late_answer_count: 0,
            rejected_answer_count: 0,
        })
    }

    fn index_restored_record(
        &mut self,
        record: TransactionRecord,
    ) -> Result<(), SnapshotRestoreError> {
        if self.records.contains_key(&record.token_value)
            || self
                .pending_end_to_end
                .contains_key(&record.end_to_end_identifier)
        {
            return Err(SnapshotRestoreError::InvalidRecord);
        }
        for attempt in &record.attempts {
            let key = (attempt.connection.get(), attempt.hop_by_hop_identifier);
            if self.attempt_index.contains_key(&key) {
                return Err(SnapshotRestoreError::InvalidRecord);
            }
            self.attempt_index.insert(key, record.token_value);
        }
        self.pending_end_to_end
            .insert(record.end_to_end_identifier, record.token_value);
        self.records.insert(record.token_value, record);
        Ok(())
    }
}

enum HopByHopAllocateError {
    UnknownConnection,
    ConnectionClosed,
    Exhausted,
}

impl From<HopByHopAllocateError> for TrackError {
    fn from(error: HopByHopAllocateError) -> Self {
        match error {
            HopByHopAllocateError::UnknownConnection => Self::UnknownConnection,
            HopByHopAllocateError::ConnectionClosed => Self::ConnectionClosed,
            HopByHopAllocateError::Exhausted => Self::HopByHopSpaceExhausted,
        }
    }
}

impl From<HopByHopAllocateError> for FailoverError {
    fn from(error: HopByHopAllocateError) -> Self {
        match error {
            HopByHopAllocateError::UnknownConnection => Self::UnknownConnection,
            HopByHopAllocateError::ConnectionClosed => Self::ConnectionClosed,
            HopByHopAllocateError::Exhausted => Self::HopByHopSpaceExhausted,
        }
    }
}

impl AttemptDisposition {
    fn as_snapshot_code(self) -> u8 {
        match self {
            Self::Prepared => 0,
            Self::InFlight => 1,
            Self::WrittenAwaitingAnswer => 2,
            Self::FailedBeforeWrite => 3,
            Self::FailedUncertainWrite => 4,
            Self::TransportLostAfterWrite => 5,
            Self::Answered => 6,
        }
    }

    fn from_snapshot_code(code: u8) -> Result<Self, SnapshotRestoreError> {
        match code {
            0 => Ok(Self::Prepared),
            1 => Ok(Self::InFlight),
            2 => Ok(Self::WrittenAwaitingAnswer),
            3 => Ok(Self::FailedBeforeWrite),
            4 => Ok(Self::FailedUncertainWrite),
            5 => Ok(Self::TransportLostAfterWrite),
            6 => Ok(Self::Answered),
            _ => Err(SnapshotRestoreError::InvalidRecord),
        }
    }
}

struct RequestFacts {
    command_code: CommandCode,
    application_id: ApplicationId,
    proxiable: bool,
    end_to_end_identifier: u32,
    fixed_destination: bool,
}

fn inspect_request(request: &OwnedMessage, ctx: DecodeContext) -> Result<RequestFacts, TrackError> {
    let header = &request.header;
    if header.version != DIAMETER_VERSION {
        return Err(TrackError::UnsupportedVersion);
    }
    if !header.flags.is_request() {
        return Err(TrackError::NotARequest);
    }
    if header.flags.is_error()
        || header.flags.reserved_bits() != 0
        || !header.command_code.fits_wire()
    {
        return Err(TrackError::MalformedRequest);
    }
    if header.flags.is_potentially_retransmitted() {
        // A T-set request is a retransmission by definition. Tracking it as a
        // new transaction and emitting attempt 0 with T clear would silently
        // drop RFC 6733 §3's duplicate-detection signal; recover such
        // requests through snapshot/restore, which re-arms them with T=1.
        return Err(TrackError::AlreadyRetransmitted);
    }
    let expected_len = DIAMETER_HEADER_LEN
        .checked_add(request.raw_avps.len())
        .ok_or(TrackError::MalformedRequest)?;
    if expected_len > ctx.max_message_len
        || expected_len > MAX_U24 as usize
        || header.length as usize != expected_len
    {
        return Err(TrackError::MalformedRequest);
    }
    // Duplicate occurrences are classified per-AVP below so an Origin-Host
    // duplication is reported as the identity violation it is, not as a
    // generic framing error.
    let framing_ctx = DecodeContext {
        duplicate_ie_policy: opc_protocol::DuplicateIePolicy::First,
        ..ctx
    };
    let borrowed = Message {
        header: header.clone(),
        raw_avps: &request.raw_avps,
        tail: &[],
    };
    borrowed
        .validate_avps(framing_ctx)
        .map_err(|_| TrackError::MalformedRequest)?;
    let mut origin_host_count = 0usize;
    let mut origin_host_nonempty = false;
    let mut fixed_destination = false;
    for avp in borrowed.avps(framing_ctx) {
        let avp = avp.map_err(|_| TrackError::MalformedRequest)?;
        if avp.header.vendor_id.is_none() && avp.header.code == base::AVP_ORIGIN_HOST {
            origin_host_count += 1;
            origin_host_nonempty = !avp.value.is_empty();
        }
        if avp.header.vendor_id.is_none() && avp.header.code == base::AVP_DESTINATION_HOST {
            fixed_destination = true;
        }
    }
    if origin_host_count != 1 || !origin_host_nonempty {
        return Err(TrackError::OriginHostInvalid);
    }
    Ok(RequestFacts {
        command_code: header.command_code,
        application_id: header.application_id,
        proxiable: header.flags.is_proxiable(),
        end_to_end_identifier: header.end_to_end_identifier,
        fixed_destination,
    })
}

fn inspect_answer(
    answer: &OwnedMessage,
    record: &TransactionRecord,
    ctx: DecodeContext,
) -> Option<AnswerRejectionReason> {
    let header = &answer.header;
    if header.flags.is_request() {
        return Some(AnswerRejectionReason::NotAnAnswer);
    }
    if header.version != DIAMETER_VERSION {
        return Some(AnswerRejectionReason::UnsupportedVersion);
    }
    let expected_len = match DIAMETER_HEADER_LEN.checked_add(answer.raw_avps.len()) {
        Some(length) => length,
        None => return Some(AnswerRejectionReason::InvalidLength),
    };
    if expected_len > ctx.max_message_len
        || expected_len > MAX_U24 as usize
        || header.length as usize != expected_len
    {
        return Some(AnswerRejectionReason::InvalidLength);
    }
    if header.flags.is_potentially_retransmitted() || header.flags.reserved_bits() != 0 {
        return Some(AnswerRejectionReason::InvalidFlags);
    }
    if !header.command_code.fits_wire() {
        return Some(AnswerRejectionReason::MalformedHeader);
    }
    if header.flags.is_proxiable() != record.proxiable {
        return Some(AnswerRejectionReason::ProxiableMismatch);
    }
    let framing_ctx = DecodeContext {
        duplicate_ie_policy: opc_protocol::DuplicateIePolicy::First,
        ..ctx
    };
    let borrowed = Message {
        header: header.clone(),
        raw_avps: &answer.raw_avps,
        tail: &[],
    };
    if borrowed.validate_avps(framing_ctx).is_err() {
        return Some(AnswerRejectionReason::MalformedAvps);
    }
    if header.end_to_end_identifier != record.end_to_end_identifier {
        return Some(AnswerRejectionReason::EndToEndMismatch);
    }
    if header.command_code != record.command_code || header.application_id != record.application_id
    {
        return Some(AnswerRejectionReason::CommandMismatch);
    }
    None
}

fn origin_host_matches(raw_avps: &[u8], candidate: &str) -> bool {
    let ctx = DecodeContext::conservative();
    let message = Message {
        header: Header::new(
            CommandFlags::request(true),
            CommandCode::new(0),
            ApplicationId::new(0),
            0,
            0,
        ),
        raw_avps,
        tail: &[],
    };
    for avp in message.avps(ctx) {
        let Ok(avp) = avp else {
            return false;
        };
        if avp.header.vendor_id.is_none() && avp.header.code == base::AVP_ORIGIN_HOST {
            return avp.value == candidate.as_bytes();
        }
    }
    false
}

fn micros_of(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn push_count(encoded: &mut Vec<u8>, count: usize) {
    // Config validation caps every serialized count at u16::MAX.
    debug_assert!(count <= MAX_SERIALIZED_COUNT);
    encoded.extend_from_slice(&(count as u16).to_be_bytes());
}

struct SnapshotCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SnapshotCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_exhausted(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], SnapshotRestoreError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(SnapshotRestoreError::Malformed)?;
        if end > self.bytes.len() {
            return Err(SnapshotRestoreError::Malformed);
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, SnapshotRestoreError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, SnapshotRestoreError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| SnapshotRestoreError::Malformed)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, SnapshotRestoreError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| SnapshotRestoreError::Malformed)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, SnapshotRestoreError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| SnapshotRestoreError::Malformed)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn u128(&mut self) -> Result<u128, SnapshotRestoreError> {
        let bytes: [u8; 16] = self
            .take(16)?
            .try_into()
            .map_err(|_| SnapshotRestoreError::Malformed)?;
        Ok(u128::from_be_bytes(bytes))
    }

    fn count(&mut self) -> Result<usize, SnapshotRestoreError> {
        Ok(usize::from(self.u16()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use bytes::BytesMut;
    use opc_protocol::{Encode, EncodeContext};

    #[derive(Debug, Default)]
    struct ManualClock(Mutex<Duration>);

    impl ManualClock {
        fn advance(&self, by: Duration) {
            let mut guard = match self.0.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            *guard += by;
        }
    }

    impl PendingRequestClock for ManualClock {
        fn now(&self) -> Duration {
            let guard = match self.0.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            *guard
        }
    }

    const CONNECTION_A: DiameterConnectionToken = DiameterConnectionToken::new(NonZeroU64::MIN);
    const CONNECTION_B: DiameterConnectionToken =
        DiameterConnectionToken::new(match NonZeroU64::new(2) {
            Some(value) => value,
            None => panic!("nonzero"),
        });
    const COMMAND: CommandCode = CommandCode::new(302);
    const APPLICATION: ApplicationId = ApplicationId::new(100);
    const SESSION_ID: &str = "session;private;unit";
    const ORIGIN_HOST: &str = "epdg.private.example";
    const USER_NAME: &str = "subscriber-private@example.invalid";
    const DESTINATION_HOST: &str = "aaa.private.example";
    const EAP_MARKER: [u8; 4] = [0xE4, 0xA9, 0x00, 0x11];
    const SNAPSHOT_EPOCH: PendingSnapshotEpoch = PendingSnapshotEpoch::new(NonZeroU128::MIN);

    fn token(value: u128) -> CompletionTokenValue {
        match NonZeroU128::new(value) {
            Some(value) => CompletionTokenValue::new(value),
            None => panic!("test token must be nonzero"),
        }
    }

    fn table(config: PendingRequestTableConfig) -> PendingRequestTable {
        match PendingRequestTable::new(config, Arc::new(ManualClock::default()), SNAPSHOT_EPOCH) {
            Ok(table) => table,
            Err(error) => panic!("default config must be valid: {error}"),
        }
    }

    fn checkpoint(revision: u64) -> PendingSnapshotCheckpoint {
        let revision = match NonZeroU64::new(revision) {
            Some(value) => PendingSnapshotRevision::new(value),
            None => panic!("snapshot revision must be nonzero"),
        };
        PendingSnapshotCheckpoint::new(SNAPSHOT_EPOCH, revision)
    }

    fn snapshot_at(table: &mut PendingRequestTable, revision: u64) -> PendingTableSnapshot {
        let snapshot = table
            .snapshot(checkpoint(revision))
            .unwrap_or_else(|error| panic!("snapshot: {error}"));
        table
            .confirm_snapshot_committed(snapshot.checkpoint())
            .unwrap_or_else(|error| panic!("commit snapshot: {error}"));
        snapshot
    }

    fn commit_next(table: &mut PendingRequestTable) -> CommittedPendingSnapshot {
        let revision = table
            .latest_emitted_snapshot()
            .map_or(1, |checkpoint| checkpoint.revision().get() + 1);
        let snapshot = snapshot_at(table, revision);
        table
            .committed_snapshot()
            .unwrap_or_else(|| panic!("snapshot {:?} must be committed", snapshot.checkpoint()))
    }

    fn dispatch(table: &mut PendingRequestTable, token: CompletionTokenValue) -> OwnedMessage {
        let committed = commit_next(table);
        table
            .take_attempt_dispatch(token, committed)
            .map(AttemptDispatch::into_message)
            .unwrap_or_else(|error| panic!("dispatch: {error}"))
    }

    fn restore_snapshot(
        snapshot: &PendingTableSnapshot,
        config: PendingRequestTableConfig,
    ) -> PendingRequestTable {
        PendingRequestTable::restore(
            snapshot.as_bytes(),
            snapshot.checkpoint(),
            config,
            Arc::new(ManualClock::default()),
        )
        .unwrap_or_else(|error| panic!("restore: {error}"))
    }

    fn acknowledged_delivery(completion: &TransactionCompletion) -> CompletionDeliveryRecord {
        let ready = CompletionDeliveryRecord::new(SNAPSHOT_EPOCH, completion.token())
            .unwrap_or_else(|error| panic!("delivery record: {error}"));
        let claim_value = CompletionClaimValue::new(
            NonZeroU128::new(0xCA11).unwrap_or_else(|| panic!("claim value")),
        );
        let (claimed, claim) = ready
            .claim(claim_value)
            .unwrap_or_else(|error| panic!("claim: {error}"));
        claimed
            .acknowledge(claim)
            .unwrap_or_else(|error| panic!("acknowledge: {error}"))
    }

    fn wire_avp(code: u32, value: &[u8]) -> Vec<u8> {
        let length = 8 + value.len();
        let mut wire = Vec::with_capacity((length + 3) & !3);
        wire.extend_from_slice(&code.to_be_bytes());
        wire.push(0x40);
        wire.extend_from_slice(&(length as u32).to_be_bytes()[1..]);
        wire.extend_from_slice(value);
        wire.resize((length + 3) & !3, 0);
        wire
    }

    const E2E: u32 = 0x0BAD_CAFE;

    fn canonical_request(destination_host: Option<&str>) -> OwnedMessage {
        canonical_request_on(destination_host, E2E)
    }

    fn canonical_request_on(destination_host: Option<&str>, end_to_end: u32) -> OwnedMessage {
        let mut avps = Vec::new();
        avps.extend(wire_avp(263, SESSION_ID.as_bytes()));
        avps.extend(wire_avp(264, ORIGIN_HOST.as_bytes()));
        avps.extend(wire_avp(296, b"private.realm.example"));
        avps.extend(wire_avp(283, b"home.private.example"));
        if let Some(host) = destination_host {
            avps.extend(wire_avp(293, host.as_bytes()));
        }
        avps.extend(wire_avp(1, USER_NAME.as_bytes()));
        avps.extend(wire_avp(462, &EAP_MARKER));
        let length = (DIAMETER_HEADER_LEN + avps.len()) as u32;
        OwnedMessage {
            header: Header::new(
                CommandFlags::request(true),
                COMMAND,
                APPLICATION,
                0,
                end_to_end,
            )
            .with_length(length),
            raw_avps: Bytes::copy_from_slice(&avps),
        }
    }

    fn answer_message(hop_by_hop: u32, end_to_end: u32) -> OwnedMessage {
        let mut avps = Vec::new();
        avps.extend(wire_avp(263, SESSION_ID.as_bytes()));
        avps.extend(wire_avp(264, DESTINATION_HOST.as_bytes()));
        avps.extend(wire_avp(296, b"home.private.example"));
        avps.extend(wire_avp(268, &2001_u32.to_be_bytes()));
        let length = (DIAMETER_HEADER_LEN + avps.len()) as u32;
        OwnedMessage {
            header: Header::new(
                CommandFlags::answer(true, false),
                COMMAND,
                APPLICATION,
                hop_by_hop,
                end_to_end,
            )
            .with_length(length),
            raw_avps: Bytes::copy_from_slice(&avps),
        }
    }

    fn encode(message: &OwnedMessage) -> BytesMut {
        let mut out = BytesMut::new();
        if let Err(error) = message.encode(&mut out, EncodeContext::default()) {
            panic!("test message must encode: {error}");
        }
        out
    }

    fn err_of<T, E>(result: Result<T, E>) -> E {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(error) => error,
        }
    }

    fn rejection_reason(disposition: AnswerDisposition) -> AnswerRejectionReason {
        match disposition {
            AnswerDisposition::Rejected(rejection) => rejection.reason,
            other => panic!("expected rejected answer, got {other:?}"),
        }
    }

    #[test]
    fn first_attempt_is_canonical_and_connection_unique() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|error| panic!("connection registration: {error}"));
        let first = table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|error| panic!("track: {error}"));
        let second = table
            .track(canonical_request_on(None, E2E + 1), CONNECTION_A, token(2))
            .unwrap_or_else(|error| panic!("track: {error}"));
        assert_eq!(first.generation(), 0);
        assert_eq!(second.generation(), 0);

        let first_wire = dispatch(&mut table, first.value());
        let second_wire = dispatch(&mut table, second.value());
        assert_eq!(first_wire.header.hop_by_hop_identifier, 100);
        assert_eq!(second_wire.header.hop_by_hop_identifier, 101);
        assert!(!first_wire.header.flags.is_potentially_retransmitted());
        assert!(first_wire.header.flags.is_request());
        assert!(first_wire.header.flags.is_proxiable());
        assert_eq!(first_wire.header.end_to_end_identifier, 0x0BAD_CAFE);
        let canonical = canonical_request(None);
        assert_eq!(first_wire.raw_avps, canonical.raw_avps);
        // The encoded form is a complete, self-consistent Diameter message.
        assert_eq!(
            first_wire.header.length as usize,
            DIAMETER_HEADER_LEN + first_wire.raw_avps.len()
        );
        let encoded = encode(&first_wire);
        assert_eq!(encoded.len(), first_wire.header.length as usize);
    }

    #[test]
    fn failover_sets_t_and_preserves_semantic_identity() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .add_connection(CONNECTION_B, 900)
            .unwrap_or_else(|e| panic!("{e}"));
        let tracked = table
            .track(
                canonical_request(Some(DESTINATION_HOST)),
                CONNECTION_A,
                token(7),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        let initial = dispatch(&mut table, tracked.value());
        let attempt = table
            .failover(
                tracked.value(),
                CONNECTION_B,
                AlternateRoutability::DestinationAsserted,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(attempt.is_retransmission());
        assert_eq!(attempt.hop_by_hop_identifier(), 900);
        assert_eq!(attempt.attempt_index(), 1);
        let alternate_wire = dispatch(&mut table, tracked.value());
        assert!(alternate_wire.header.flags.is_potentially_retransmitted());
        assert_eq!(
            alternate_wire.header.end_to_end_identifier,
            initial.header.end_to_end_identifier
        );
        assert_eq!(alternate_wire.raw_avps, initial.raw_avps);
        let view = table
            .transaction(tracked.value())
            .unwrap_or_else(|| panic!("transaction view"));
        assert!(view.has_origin_host(ORIGIN_HOST));
        assert!(!view.has_origin_host("other.example"));
        assert!(view.has_fixed_destination());
        assert_eq!(view.attempts().len(), 2);
    }

    #[test]
    fn fixed_destination_requires_caller_assertion() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .add_connection(CONNECTION_B, 900)
            .unwrap_or_else(|e| panic!("{e}"));
        let tracked = table
            .track(
                canonical_request(Some(DESTINATION_HOST)),
                CONNECTION_A,
                token(8),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        let error = err_of(table.failover(
            tracked.value(),
            CONNECTION_B,
            AlternateRoutability::RealmRouted,
        ));
        assert_eq!(error, FailoverError::FixedDestinationRequiresAssertion);
        let completion = table
            .finish_undeliverable(
                tracked.value(),
                UndeliverableReason::FixedDestinationNoAlternate,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(completion.kind(), CompletionKind::Undeliverable);
        assert_eq!(completion.token().generation(), 1);
    }

    #[test]
    fn duplicate_token_and_end_to_end_are_rejected() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            err_of(table.track(canonical_request(None), CONNECTION_A, token(1))),
            TrackError::DuplicateCompletionToken
        );
        assert_eq!(
            err_of(table.track(canonical_request(None), CONNECTION_A, token(2))),
            TrackError::DuplicateEndToEnd
        );
    }

    #[test]
    fn request_validation_rejects_non_requests_and_bad_origin_host() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            err_of(table.track(answer_message(1, 2), CONNECTION_A, token(1))),
            TrackError::NotARequest
        );
        let mut missing_origin = canonical_request(None);
        missing_origin.raw_avps = Bytes::copy_from_slice(&wire_avp(263, b"session"));
        missing_origin.header.length = (DIAMETER_HEADER_LEN + missing_origin.raw_avps.len()) as u32;
        assert_eq!(
            err_of(table.track(missing_origin, CONNECTION_A, token(2))),
            TrackError::OriginHostInvalid
        );
        let mut duplicate_origin = Vec::new();
        duplicate_origin.extend(wire_avp(264, b"a.example"));
        duplicate_origin.extend(wire_avp(264, b"b.example"));
        let duplicate = OwnedMessage {
            header: Header::new(CommandFlags::request(true), COMMAND, APPLICATION, 0, 9)
                .with_length((DIAMETER_HEADER_LEN + duplicate_origin.len()) as u32),
            raw_avps: Bytes::copy_from_slice(&duplicate_origin),
        };
        assert_eq!(
            err_of(table.track(duplicate, CONNECTION_A, token(3))),
            TrackError::OriginHostInvalid
        );
        let mut error_flagged = canonical_request(None);
        error_flagged.header.flags =
            CommandFlags::from_bits(CommandFlags::request(true).bits() | CommandFlags::ERROR);
        assert_eq!(
            err_of(table.track(error_flagged, CONNECTION_A, token(4))),
            TrackError::MalformedRequest
        );
    }

    #[test]
    fn hop_by_hop_allocation_is_strictly_increasing_per_connection() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, u32::MAX)
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            err_of(table.track(canonical_request_on(None, E2E + 1), CONNECTION_A, token(2))),
            TrackError::HopByHopSpaceExhausted
        );
    }

    #[test]
    fn pending_bound_is_enforced() {
        let config = PendingRequestTableConfig {
            max_pending_transactions: 1,
            ..PendingRequestTableConfig::default()
        };
        let mut table = table(config);
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            err_of(table.track(canonical_request(None), CONNECTION_A, token(2))),
            TrackError::TableFull
        );
    }

    #[test]
    fn snapshot_round_trip_preserves_pending_records_and_identity() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .add_connection(CONNECTION_B, 900)
            .unwrap_or_else(|e| panic!("{e}"));
        let first = table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|e| panic!("{e}"));
        let second = table
            .track(
                canonical_request_on(Some(DESTINATION_HOST), E2E + 1),
                CONNECTION_A,
                token(2),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .failover(
                first.value(),
                CONNECTION_B,
                AlternateRoutability::RealmRouted,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        let first_attempt_id = {
            let view = table
                .transaction(first.value())
                .unwrap_or_else(|| panic!("view"));
            view.attempts()[0].attempt_id()
        };
        table
            .record_attempt_failure(
                first.value(),
                first_attempt_id,
                AttemptFailure::TransportLostAfterWrite,
            )
            .unwrap_or_else(|e| panic!("{e}"));

        let snapshot = snapshot_at(&mut table, 1);
        let restored = restore_snapshot(&snapshot, PendingRequestTableConfig::default());
        assert_eq!(restored.pending_count(), 2);
        let view = restored
            .transaction(first.value())
            .unwrap_or_else(|| panic!("restored view"));
        assert_eq!(view.completion_token(), first);
        assert_eq!(view.attempts().len(), 2);
        assert!(view.attempts()[1].is_retransmission());
        assert_eq!(
            view.attempts()[0].disposition(),
            AttemptDisposition::TransportLostAfterWrite
        );
        let fixed = restored
            .transaction(second.value())
            .unwrap_or_else(|| panic!("restored view"));
        assert!(fixed.has_fixed_destination());
        assert!(fixed.has_origin_host(ORIGIN_HOST));
        // Restored retransmission sets T=1 on a fresh connection.
        let mut restored = restored;
        restored
            .add_connection(
                DiameterConnectionToken::new(NonZeroU64::new(3).unwrap_or_else(|| panic!("nz"))),
                5000,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        let attempt = restored
            .failover(
                first.value(),
                DiameterConnectionToken::new(NonZeroU64::new(3).unwrap_or_else(|| panic!("nz"))),
                AlternateRoutability::RealmRouted,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(attempt.is_retransmission());
        assert_eq!(attempt.hop_by_hop_identifier(), 5000);
        let wire = dispatch(&mut restored, first.value());
        assert!(wire.header.flags.is_potentially_retransmitted());
        assert_eq!(wire.header.end_to_end_identifier, 0x0BAD_CAFE);
        assert_eq!(wire.raw_avps, canonical_request(None).raw_avps);
    }

    #[test]
    fn snapshot_excludes_completed_records() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        let tracked = table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|e| panic!("{e}"));
        let wire = dispatch(&mut table, tracked.value());
        let completion = match table.correlate_answer(
            CONNECTION_A,
            answer_message(wire.header.hop_by_hop_identifier, 0x0BAD_CAFE),
        ) {
            AnswerDisposition::Completed(completion) => completion,
            other => panic!("expected completion, got {other:?}"),
        };
        let acknowledged = acknowledged_delivery(&completion);
        table
            .acknowledge_completion_delivery(acknowledged)
            .unwrap_or_else(|error| panic!("acknowledge delivery: {error}"));
        let snapshot = snapshot_at(&mut table, 2);
        let restored = restore_snapshot(&snapshot, PendingRequestTableConfig::default());
        assert_eq!(restored.pending_count(), 0);
    }

    #[test]
    fn restore_rejects_malformed_stale_and_tampered_snapshots() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|e| panic!("{e}"));
        let snapshot = snapshot_at(&mut table, 1);
        let bytes = snapshot.as_bytes().to_vec();

        let mut bad_magic = bytes.clone();
        bad_magic[0] ^= 0xFF;
        assert!(matches!(
            PendingRequestTable::restore(
                &bad_magic,
                checkpoint(1),
                PendingRequestTableConfig::default(),
                Arc::new(ManualClock::default())
            ),
            Err(SnapshotRestoreError::Malformed)
        ));

        let mut stale = bytes.clone();
        stale[4] = 0xFF;
        stale[5] = 0xFE;
        assert!(matches!(
            PendingRequestTable::restore(
                &stale,
                checkpoint(1),
                PendingRequestTableConfig::default(),
                Arc::new(ManualClock::default())
            ),
            Err(SnapshotRestoreError::UnsupportedVersion)
        ));

        for cut in [bytes.len() - 1, bytes.len() / 2, 7] {
            assert!(matches!(
                PendingRequestTable::restore(
                    &bytes[..cut],
                    checkpoint(1),
                    PendingRequestTableConfig::default(),
                    Arc::new(ManualClock::default())
                ),
                Err(SnapshotRestoreError::Malformed)
                    | Err(SnapshotRestoreError::LimitExceeded)
                    | Err(SnapshotRestoreError::InvalidRecord)
            ));
        }

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            PendingRequestTable::restore(
                &trailing,
                checkpoint(1),
                PendingRequestTableConfig::default(),
                Arc::new(ManualClock::default())
            ),
            Err(SnapshotRestoreError::Malformed)
        ));

        // A zero completion token value is invalid.
        let mut zero_token = bytes.clone();
        for byte in &mut zero_token[32..48] {
            *byte = 0;
        }
        assert!(matches!(
            PendingRequestTable::restore(
                &zero_token,
                checkpoint(1),
                PendingRequestTableConfig::default(),
                Arc::new(ManualClock::default())
            ),
            Err(SnapshotRestoreError::InvalidRecord)
        ));

        // A pending record must not contain an answered attempt.
        let mut answered = bytes.clone();
        // Layout: magic(4) version(2) epoch(16) revision(8) count(2),
        // token(16), generation(8), e2e(4),
        // command(4) app(4) flags(1) attempts(2) conn(8) hbh(4) disposition(1)
        let disposition_offset = 32 + 16 + 8 + 4 + 4 + 4 + 1 + 2 + 8 + 4;
        answered[disposition_offset] = 5;
        assert!(matches!(
            PendingRequestTable::restore(
                &answered,
                checkpoint(1),
                PendingRequestTableConfig::default(),
                Arc::new(ManualClock::default())
            ),
            Err(SnapshotRestoreError::InvalidRecord)
        ));

        // Restore into a smaller table is a bound violation.
        let tight = PendingRequestTableConfig {
            max_pending_transactions: 0,
            ..PendingRequestTableConfig::default()
        };
        assert!(matches!(
            PendingRequestTable::restore(
                snapshot.as_bytes(),
                snapshot.checkpoint(),
                tight,
                Arc::new(ManualClock::default())
            ),
            Err(SnapshotRestoreError::LimitExceeded)
        ));
    }

    #[test]
    fn token_and_generation_are_stable_across_repeated_restores() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        let tracked = table
            .track(canonical_request(None), CONNECTION_A, token(42))
            .unwrap_or_else(|e| panic!("{e}"));
        let first_snapshot = snapshot_at(&mut table, 1);
        let mut first_restore =
            restore_snapshot(&first_snapshot, PendingRequestTableConfig::default());
        let second_snapshot = snapshot_at(&mut first_restore, 2);
        let second_restore =
            restore_snapshot(&second_snapshot, PendingRequestTableConfig::default());
        let view = second_restore
            .transaction(tracked.value())
            .unwrap_or_else(|| panic!("view"));
        assert_eq!(view.completion_token(), tracked);
        assert_eq!(view.completion_token().generation(), 0);
    }

    #[test]
    fn diagnostics_never_disclose_sensitive_values() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        let tracked = table
            .track(
                canonical_request(Some(DESTINATION_HOST)),
                CONNECTION_A,
                token(1),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        let wire = dispatch(&mut table, tracked.value());
        let snapshot = snapshot_at(&mut table, 2);
        let completion = match table.correlate_answer(
            CONNECTION_A,
            answer_message(wire.header.hop_by_hop_identifier, E2E),
        ) {
            AnswerDisposition::Completed(completion) => completion,
            other => panic!("expected completion, got {other:?}"),
        };
        let view = table
            .transaction(tracked.value())
            .unwrap_or_else(|| panic!("view"));
        let rendered = format!(
            "{table:?} {view:?} {completion:?} {snapshot:?} {:?} {:?}",
            view.attempts()[0],
            tracked
        );
        for marker in [
            SESSION_ID,
            ORIGIN_HOST,
            USER_NAME,
            DESTINATION_HOST,
            "private.realm.example",
            "home.private.example",
        ] {
            assert!(
                !rendered.contains(marker),
                "diagnostic representation leaked {marker}: {rendered}"
            );
        }
        // Raw request bytes (for example the EAP payload) must never appear
        // as a diagnostic byte sequence either.
        let eap_sequence = format!("{:?}", EAP_MARKER);
        let eap_inner = eap_sequence
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or_else(|| panic!("slice debug shape"));
        assert!(
            !rendered.contains(eap_inner),
            "leaked raw bytes: {rendered}"
        );
        // Snapshot bytes themselves hold the sensitive canonical request; only
        // the Debug representation is redacted.
        assert!(snapshot
            .as_bytes()
            .windows(SESSION_ID.len())
            .any(|window| window == SESSION_ID.as_bytes()));
    }

    #[test]
    fn config_validation_rejects_out_of_range_bounds() {
        for config in [
            PendingRequestTableConfig {
                max_pending_transactions: 0,
                ..PendingRequestTableConfig::default()
            },
            PendingRequestTableConfig {
                max_retained_completions: 0,
                ..PendingRequestTableConfig::default()
            },
            PendingRequestTableConfig {
                max_attempts_per_transaction: 0,
                ..PendingRequestTableConfig::default()
            },
            PendingRequestTableConfig {
                max_connections: 0,
                ..PendingRequestTableConfig::default()
            },
            PendingRequestTableConfig {
                max_message_len: DIAMETER_HEADER_LEN - 1,
                ..PendingRequestTableConfig::default()
            },
            PendingRequestTableConfig {
                max_snapshot_bytes: SNAPSHOT_HEADER_LEN - 1,
                ..PendingRequestTableConfig::default()
            },
        ] {
            assert!(PendingRequestTable::new(
                config,
                Arc::new(ManualClock::default()),
                SNAPSHOT_EPOCH
            )
            .is_err());
        }
    }

    #[test]
    fn retire_removes_only_completed_records() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        let tracked = table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(!table.retire(tracked.value()));
        let completion = table
            .finish_exhausted(tracked.value())
            .unwrap_or_else(|e| panic!("{e}"));
        let acknowledged = acknowledged_delivery(&completion);
        table
            .acknowledge_completion_delivery(acknowledged)
            .unwrap_or_else(|error| panic!("acknowledge: {error}"));
        assert!(table.retire(tracked.value()));
        assert!(table.transaction(tracked.value()).is_none());
    }

    #[test]
    fn connection_loss_marks_in_flight_attempts_with_typed_disposition() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .add_connection(CONNECTION_B, 900)
            .unwrap_or_else(|e| panic!("{e}"));
        let tracked = table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .failover(
                tracked.value(),
                CONNECTION_B,
                AlternateRoutability::RealmRouted,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            table.fail_connection_attempts(CONNECTION_A, AttemptFailure::UncertainWrite),
            1
        );
        let (first_disposition, second_disposition, first_attempt_id) = {
            let view = table
                .transaction(tracked.value())
                .unwrap_or_else(|| panic!("view"));
            (
                view.attempts()[0].disposition(),
                view.attempts()[1].disposition(),
                view.attempts()[0].attempt_id(),
            )
        };
        assert_eq!(first_disposition, AttemptDisposition::FailedUncertainWrite);
        assert!(second_disposition.is_in_flight());
        // Already-terminated attempts are not reclassified.
        assert_eq!(
            table.fail_connection_attempts(CONNECTION_A, AttemptFailure::BeforeWrite),
            0
        );
        let error = match table.record_attempt_failure(
            tracked.value(),
            first_attempt_id,
            AttemptFailure::BeforeWrite,
        ) {
            Ok(_) => panic!("terminated attempt must reject reclassification"),
            Err(error) => error,
        };
        assert_eq!(error, TransactionAccessError::AttemptNotInFlight);
    }

    #[test]
    fn deterministic_clock_drives_attempt_evidence() {
        let clock = Arc::new(ManualClock::default());
        let mut table = match PendingRequestTable::new(
            PendingRequestTableConfig::default(),
            clock.clone(),
            SNAPSHOT_EPOCH,
        ) {
            Ok(table) => table,
            Err(error) => panic!("{error}"),
        };
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .add_connection(CONNECTION_B, 900)
            .unwrap_or_else(|e| panic!("{e}"));
        let tracked = table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|e| panic!("{e}"));
        clock.advance(Duration::from_millis(25));
        table
            .failover(
                tracked.value(),
                CONNECTION_B,
                AlternateRoutability::RealmRouted,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        clock.advance(Duration::from_millis(10));
        let (first_started, second_started, second_attempt_id) = {
            let view = table
                .transaction(tracked.value())
                .unwrap_or_else(|| panic!("view"));
            (
                view.attempts()[0].started_at(),
                view.attempts()[1].started_at(),
                view.attempts()[1].attempt_id(),
            )
        };
        assert_eq!(first_started, Duration::ZERO);
        assert_eq!(second_started, Duration::from_millis(25));
        let evidence = table
            .record_attempt_failure(
                tracked.value(),
                second_attempt_id,
                AttemptFailure::BeforeWrite,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(evidence.ended_at(), Some(Duration::from_millis(35)));
    }

    fn conn(value: u64) -> DiameterConnectionToken {
        match NonZeroU64::new(value) {
            Some(value) => DiameterConnectionToken::new(value),
            None => panic!("connection token must be nonzero"),
        }
    }

    #[test]
    fn connection_retirement_frees_slots_and_refuses_while_referenced() {
        let config = PendingRequestTableConfig {
            max_connections: 1,
            ..PendingRequestTableConfig::default()
        };
        let mut table = table(config);
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        let tracked = table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .close_connection(CONNECTION_A)
            .unwrap_or_else(|e| panic!("{e}"));
        // The pending record still references the lifetime.
        assert_eq!(
            err_of(table.retire_connection(CONNECTION_A)),
            ConnectionTableError::ConnectionInUse
        );
        // Completion alone does not release it: the retained completed record
        // still provides late-answer evidence.
        let wire = dispatch(&mut table, tracked.value());
        let completion = match table.correlate_answer(
            CONNECTION_A,
            answer_message(wire.header.hop_by_hop_identifier, E2E),
        ) {
            AnswerDisposition::Completed(completion) => completion,
            other => panic!("expected completion, got {other:?}"),
        };
        assert_eq!(
            err_of(table.retire_connection(CONNECTION_A)),
            ConnectionTableError::ConnectionInUse
        );
        // Once the record is retired, the token becomes removable.
        table
            .acknowledge_completion_delivery(acknowledged_delivery(&completion))
            .unwrap_or_else(|error| panic!("acknowledge: {error}"));
        assert!(table.retire(tracked.value()));
        table
            .retire_connection(CONNECTION_A)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(table.connection_count(), 0);

        // 64 connect/close/retire cycles with one slot never brick the table.
        for cycle in 0..64_u64 {
            let lifetime = conn(cycle + 10);
            table
                .add_connection(lifetime, 1)
                .unwrap_or_else(|e| panic!("{e}"));
            table
                .close_connection(lifetime)
                .unwrap_or_else(|e| panic!("{e}"));
            table
                .retire_connection(lifetime)
                .unwrap_or_else(|e| panic!("{e}"));
        }
        assert_eq!(table.connection_count(), 0);
        // Retiring an unknown lifetime is a typed error, not a panic.
        assert_eq!(
            err_of(table.retire_connection(conn(9_999))),
            ConnectionTableError::UnknownConnection
        );
    }

    #[test]
    fn add_connection_rejects_tokens_referenced_by_restored_history() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .add_connection(CONNECTION_B, 900)
            .unwrap_or_else(|e| panic!("{e}"));
        let tracked = table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .failover(
                tracked.value(),
                CONNECTION_B,
                AlternateRoutability::RealmRouted,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        let snapshot = snapshot_at(&mut table, 1);
        let mut restored = restore_snapshot(&snapshot, PendingRequestTableConfig::default());
        // Both historical lifetimes are rejected: re-registering either could
        // allocate a duplicate Hop-by-Hop identifier on one connection.
        assert_eq!(
            err_of(restored.add_connection(CONNECTION_A, 100)),
            ConnectionTableError::DuplicateConnection
        );
        assert_eq!(
            err_of(restored.add_connection(CONNECTION_B, 900)),
            ConnectionTableError::DuplicateConnection
        );
        // A genuinely fresh lifetime registers fine, and once the referencing
        // record is gone the historical tokens become reusable.
        restored
            .add_connection(conn(3), 5000)
            .unwrap_or_else(|e| panic!("{e}"));
        let completion = restored
            .finish_indeterminate(tracked.value(), IndeterminateReason::CallerWithdrawn)
            .unwrap_or_else(|e| panic!("{e}"));
        restored
            .acknowledge_completion_delivery(acknowledged_delivery(&completion))
            .unwrap_or_else(|error| panic!("acknowledge: {error}"));
        assert!(restored.retire(tracked.value()));
        restored
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
    }

    #[test]
    fn track_rejects_retransmitted_requests() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        let mut retransmitted = canonical_request(None);
        retransmitted.header.flags = CommandFlags::from_bits(
            CommandFlags::request(true).bits() | CommandFlags::POTENTIALLY_RETRANSMITTED,
        );
        assert_eq!(
            err_of(table.track(retransmitted, CONNECTION_A, token(1))),
            TrackError::AlreadyRetransmitted
        );
        // The rejection is fail-closed without side effects: the same token
        // and End-to-End remain usable for an ordinary request.
        table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|e| panic!("{e}"));
    }

    #[test]
    fn restored_in_flight_attempts_require_rearm_before_sending() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        let tracked = table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|e| panic!("{e}"));
        let snapshot = snapshot_at(&mut table, 1);
        let mut restored = restore_snapshot(&snapshot, PendingRequestTableConfig::default());
        // The restored attempt is still marked in flight, but its connection
        // lifetime is dead: its pre-crash T-clear bytes are never re-served.
        let committed = restored
            .committed_snapshot()
            .unwrap_or_else(|| panic!("restored committed proof"));
        assert_eq!(
            err_of(restored.take_attempt_dispatch(tracked.value(), committed)),
            TransactionAccessError::NoLiveAttempt
        );
        // Historical state remains inspectable without exposing a second
        // sendable OwnedMessage.
        let historical = restored
            .transaction(tracked.value())
            .unwrap_or_else(|| panic!("view"))
            .attempts()[0]
            ;
        assert_eq!(historical.attempt_id().connection(), CONNECTION_A);
        assert!(!historical.is_retransmission());
        assert_eq!(historical.snapshotted_at(), Some(checkpoint(1).revision()));
        // Re-arming through failover produces the sendable T=1 form.
        restored
            .add_connection(conn(3), 5000)
            .unwrap_or_else(|e| panic!("{e}"));
        restored
            .failover(tracked.value(), conn(3), AlternateRoutability::RealmRouted)
            .unwrap_or_else(|e| panic!("{e}"));
        let rearmed = dispatch(&mut restored, tracked.value());
        assert!(rearmed.header.flags.is_potentially_retransmitted());
        assert_eq!(rearmed.header.end_to_end_identifier, E2E);
    }

    #[test]
    fn terminal_state_never_exposes_a_sendable_attempt() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|error| panic!("connection A: {error}"));
        table
            .add_connection(CONNECTION_B, 900)
            .unwrap_or_else(|error| panic!("connection B: {error}"));
        let tracked = table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|error| panic!("track: {error}"));
        let _initial_wire = dispatch(&mut table, tracked.value());
        let parallel = table
            .failover(
                tracked.value(),
                CONNECTION_B,
                AlternateRoutability::RealmRouted,
            )
            .unwrap_or_else(|error| panic!("parallel attempt: {error}"));

        let completion = table.correlate_answer(CONNECTION_A, answer_message(100, E2E));
        assert!(matches!(completion, AnswerDisposition::Completed(_)));

        let committed = table
            .committed_snapshot()
            .unwrap_or_else(|| panic!("committed proof"));
        assert_eq!(
            err_of(table.take_attempt_dispatch(tracked.value(), committed)),
            TransactionAccessError::NotPending
        );
        assert_eq!(
            err_of(table.failover(
                tracked.value(),
                CONNECTION_B,
                AlternateRoutability::RealmRouted
            )),
            FailoverError::NotPending
        );
        assert_eq!(
            err_of(table.record_attempt_write_success(tracked.value(), parallel.attempt_id())),
            TransactionAccessError::NotPending
        );
        assert_eq!(
            table
                .transaction(tracked.value())
                .unwrap_or_else(|| panic!("terminal view"))
                .attempts()[1]
                .attempt_id(),
            parallel.attempt_id()
        );
    }

    #[test]
    fn answer_admission_validates_the_complete_header_and_avp_region() {
        let mut pending_table = table(PendingRequestTableConfig::default());
        pending_table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|error| panic!("connection: {error}"));
        let tracked = pending_table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|error| panic!("track: {error}"));

        let mut wrong_p = answer_message(100, E2E);
        wrong_p.header.flags = CommandFlags::answer(false, false);
        assert_eq!(
            rejection_reason(pending_table.correlate_answer(CONNECTION_A, wrong_p)),
            AnswerRejectionReason::ProxiableMismatch
        );

        let mut t_set = answer_message(100, E2E);
        t_set.header.flags = CommandFlags::from_bits(
            t_set.header.flags.bits() | CommandFlags::POTENTIALLY_RETRANSMITTED,
        );
        assert_eq!(
            rejection_reason(pending_table.correlate_answer(CONNECTION_A, t_set)),
            AnswerRejectionReason::InvalidFlags
        );

        let mut reserved = answer_message(100, E2E);
        reserved.header.flags = CommandFlags::from_bits(reserved.header.flags.bits() | 0x01);
        assert_eq!(
            rejection_reason(pending_table.correlate_answer(CONNECTION_A, reserved)),
            AnswerRejectionReason::InvalidFlags
        );

        let mut wrong_version = answer_message(100, E2E);
        wrong_version.header.version = DIAMETER_VERSION + 1;
        assert_eq!(
            rejection_reason(pending_table.correlate_answer(CONNECTION_A, wrong_version)),
            AnswerRejectionReason::UnsupportedVersion
        );

        let mut bad_length = answer_message(100, E2E);
        bad_length.header.length = bad_length.header.length.saturating_sub(1);
        assert_eq!(
            rejection_reason(pending_table.correlate_answer(CONNECTION_A, bad_length)),
            AnswerRejectionReason::InvalidLength
        );

        let mut bad_command = answer_message(100, E2E);
        bad_command.header.command_code = CommandCode::new(MAX_U24 + 1);
        assert_eq!(
            rejection_reason(pending_table.correlate_answer(CONNECTION_A, bad_command)),
            AnswerRejectionReason::MalformedHeader
        );

        let mut malformed_avp = answer_message(100, E2E);
        malformed_avp.raw_avps = Bytes::copy_from_slice(&[0, 0, 0, 1, 0x40, 0, 0, 7]);
        malformed_avp.header.length = (DIAMETER_HEADER_LEN + malformed_avp.raw_avps.len()) as u32;
        assert_eq!(
            rejection_reason(pending_table.correlate_answer(CONNECTION_A, malformed_avp)),
            AnswerRejectionReason::MalformedAvps
        );

        assert_eq!(
            pending_table
                .transaction(tracked.value())
                .unwrap_or_else(|| panic!("pending view"))
                .rejected_answer_count(),
            7
        );
        assert!(matches!(
            pending_table.correlate_answer(CONNECTION_A, answer_message(100, E2E)),
            AnswerDisposition::Completed(_)
        ));

        let mut second = table(PendingRequestTableConfig::default());
        second
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|error| panic!("connection: {error}"));
        let tracked = second
            .track(canonical_request(None), CONNECTION_A, token(2))
            .unwrap_or_else(|error| panic!("track: {error}"));
        let attempt = second
            .transaction(tracked.value())
            .unwrap_or_else(|| panic!("view"))
            .attempts()[0]
            .attempt_id();
        second
            .record_attempt_failure(tracked.value(), attempt, AttemptFailure::BeforeWrite)
            .unwrap_or_else(|error| panic!("failure: {error}"));
        assert_eq!(
            rejection_reason(second.correlate_answer(CONNECTION_A, answer_message(100, E2E))),
            AnswerRejectionReason::AttemptNotAnswerEligible
        );
        assert_eq!(second.pending_count(), 1);
    }

    #[test]
    fn tracking_rejects_non_v1_requests_before_allocating_an_attempt() {
        let mut pending_table = table(PendingRequestTableConfig::default());
        pending_table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|error| panic!("connection: {error}"));
        let mut request = canonical_request(None);
        request.header.version = DIAMETER_VERSION + 1;
        assert_eq!(
            err_of(pending_table.track(request, CONNECTION_A, token(1))),
            TrackError::UnsupportedVersion
        );
        assert_eq!(pending_table.pending_count(), 0);
        // Rejection did not consume the token, End-to-End identity, or first
        // Hop-by-Hop allocation.
        let tracked = pending_table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|error| panic!("ordinary request: {error}"));
        let wire = dispatch(&mut pending_table, tracked.value());
        assert_eq!(wire.header.hop_by_hop_identifier, 100);
    }

    #[test]
    fn successful_full_write_is_distinct_and_survives_restore() {
        let clock = Arc::new(ManualClock::default());
        let mut table = PendingRequestTable::new(
            PendingRequestTableConfig::default(),
            clock.clone(),
            SNAPSHOT_EPOCH,
        )
        .unwrap_or_else(|error| panic!("table: {error}"));
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|error| panic!("connection: {error}"));
        let tracked = table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|error| panic!("track: {error}"));
        let attempt = table
            .transaction(tracked.value())
            .unwrap_or_else(|| panic!("view"))
            .attempts()[0]
            .attempt_id();
        let _wire = dispatch(&mut table, tracked.value());
        clock.advance(Duration::from_millis(7));
        let written = table
            .record_attempt_write_success(tracked.value(), attempt)
            .unwrap_or_else(|error| panic!("write success: {error}"));
        assert_eq!(
            written.disposition(),
            AttemptDisposition::WrittenAwaitingAnswer
        );
        assert_eq!(written.written_at(), Some(Duration::from_millis(7)));
        let committed = table
            .committed_snapshot()
            .unwrap_or_else(|| panic!("committed proof"));
        assert_eq!(
            err_of(table.take_attempt_dispatch(tracked.value(), committed)),
            TransactionAccessError::NoLiveAttempt
        );
        assert_eq!(
            err_of(table.record_attempt_failure(
                tracked.value(),
                attempt,
                AttemptFailure::BeforeWrite
            )),
            TransactionAccessError::InvalidAttemptTransition
        );

        let snapshot = snapshot_at(&mut table, 2);
        let mut restored = restore_snapshot(&snapshot, PendingRequestTableConfig::default());
        let restored_attempt = restored
            .transaction(tracked.value())
            .unwrap_or_else(|| panic!("restored view"))
            .attempts()[0];
        assert_eq!(
            restored_attempt.disposition(),
            AttemptDisposition::WrittenAwaitingAnswer
        );
        assert_eq!(
            restored_attempt.written_at(),
            Some(Duration::from_millis(7))
        );
        let committed = restored
            .committed_snapshot()
            .unwrap_or_else(|| panic!("restored committed proof"));
        assert_eq!(
            err_of(restored.take_attempt_dispatch(tracked.value(), committed)),
            TransactionAccessError::NoLiveAttempt
        );
        restored
            .add_connection(CONNECTION_B, 900)
            .unwrap_or_else(|error| panic!("alternate: {error}"));
        restored
            .failover(
                tracked.value(),
                CONNECTION_B,
                AlternateRoutability::RealmRouted,
            )
            .unwrap_or_else(|error| panic!("rearm: {error}"));
        let committed = commit_next(&mut restored);
        assert!(restored
            .take_attempt_dispatch(tracked.value(), committed)
            .unwrap_or_else(|error| panic!("rearmed wire: {error}"))
            .message()
            .header
            .flags
            .is_potentially_retransmitted());

        let lost = table
            .record_attempt_failure(
                tracked.value(),
                attempt,
                AttemptFailure::TransportLostAfterWrite,
            )
            .unwrap_or_else(|error| panic!("transport loss: {error}"));
        assert_eq!(
            lost.disposition(),
            AttemptDisposition::TransportLostAfterWrite
        );
        assert_eq!(lost.written_at(), Some(Duration::from_millis(7)));
    }

    #[test]
    fn snapshot_checkpoint_is_exact_monotonic_and_size_bounded() {
        let mut pending_table = table(PendingRequestTableConfig::default());
        pending_table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|error| panic!("connection A: {error}"));
        pending_table
            .add_connection(CONNECTION_B, 900)
            .unwrap_or_else(|error| panic!("connection B: {error}"));
        let tracked = pending_table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|error| panic!("track: {error}"));
        let first = snapshot_at(&mut pending_table, 1);
        pending_table
            .failover(
                tracked.value(),
                CONNECTION_B,
                AlternateRoutability::RealmRouted,
            )
            .unwrap_or_else(|error| panic!("failover: {error}"));
        let second = snapshot_at(&mut pending_table, 2);

        assert_eq!(
            PendingRequestTable::restore(
                first.as_bytes(),
                checkpoint(2),
                PendingRequestTableConfig::default(),
                Arc::new(ManualClock::default())
            )
            .err(),
            Some(SnapshotRestoreError::Stale)
        );
        assert_eq!(
            PendingRequestTable::restore(
                second.as_bytes(),
                checkpoint(1),
                PendingRequestTableConfig::default(),
                Arc::new(ManualClock::default())
            )
            .err(),
            Some(SnapshotRestoreError::Uncommitted)
        );
        assert!(PendingRequestTable::restore(
            second.as_bytes(),
            checkpoint(2),
            PendingRequestTableConfig::default(),
            Arc::new(ManualClock::default())
        )
        .is_ok());
        let other_epoch =
            PendingSnapshotEpoch::new(NonZeroU128::new(2).unwrap_or_else(|| panic!("other epoch")));
        assert_eq!(
            PendingRequestTable::restore(
                second.as_bytes(),
                PendingSnapshotCheckpoint::new(other_epoch, checkpoint(2).revision()),
                PendingRequestTableConfig::default(),
                Arc::new(ManualClock::default())
            )
            .err(),
            Some(SnapshotRestoreError::EpochMismatch)
        );

        assert_eq!(
            pending_table.snapshot(checkpoint(2)).err(),
            Some(SnapshotCreateError::RevisionNotAdvanced)
        );
        assert_eq!(
            pending_table.snapshot(checkpoint(1)).err(),
            Some(SnapshotCreateError::RevisionNotAdvanced)
        );
        assert!(pending_table.snapshot(checkpoint(3)).is_ok());

        let mut legacy = first.as_bytes().to_vec();
        legacy[4..6].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            PendingRequestTable::restore(
                &legacy,
                checkpoint(1),
                PendingRequestTableConfig::default(),
                Arc::new(ManualClock::default())
            )
            .err(),
            Some(SnapshotRestoreError::UnsupportedVersion)
        );

        let exact_config = PendingRequestTableConfig {
            max_snapshot_bytes: first.len(),
            ..PendingRequestTableConfig::default()
        };
        let mut exact = table(exact_config);
        exact
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|error| panic!("exact connection: {error}"));
        exact
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|error| panic!("exact track: {error}"));
        assert_eq!(snapshot_at(&mut exact, 1).len(), first.len());

        let tight_config = PendingRequestTableConfig {
            max_snapshot_bytes: first.len() - 1,
            ..PendingRequestTableConfig::default()
        };
        let mut tight = table(tight_config);
        tight
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|error| panic!("tight connection: {error}"));
        tight
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|error| panic!("tight track: {error}"));
        assert_eq!(
            tight.snapshot(checkpoint(1)).err(),
            Some(SnapshotCreateError::SizeLimitExceeded)
        );
        assert_eq!(
            PendingRequestTable::restore(
                first.as_bytes(),
                checkpoint(1),
                tight_config,
                Arc::new(ManualClock::default())
            )
            .err(),
            Some(SnapshotRestoreError::LimitExceeded)
        );
    }

    #[test]
    fn completion_delivery_record_fences_claims_and_has_a_strict_codec() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|error| panic!("connection: {error}"));
        let tracked = table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|error| panic!("track: {error}"));
        let completion = table
            .finish_exhausted(tracked.value())
            .unwrap_or_else(|error| panic!("finish: {error}"));
        let ready = CompletionDeliveryRecord::new(SNAPSHOT_EPOCH, completion.token())
            .unwrap_or_else(|error| panic!("ready: {error}"));
        assert_eq!(ready.state(), CompletionDeliveryState::Ready);
        assert_eq!(
            CompletionDeliveryRecord::decode(ready.encode().as_bytes()),
            Ok(ready)
        );
        assert_eq!(
            ready.encode().as_bytes().len(),
            CompletionDeliveryRecord::ENCODED_LEN
        );

        let epoch_two = PendingSnapshotEpoch::new(
            NonZeroU128::new(2).unwrap_or_else(|| panic!("second epoch")),
        );
        let other_epoch = CompletionDeliveryRecord::new(epoch_two, completion.token())
            .unwrap_or_else(|error| panic!("other epoch: {error}"));
        assert_ne!(ready.key(), other_epoch.key());

        let claim_a =
            CompletionClaimValue::new(NonZeroU128::new(0xA).unwrap_or_else(|| panic!("claim A")));
        let claim_b =
            CompletionClaimValue::new(NonZeroU128::new(0xB).unwrap_or_else(|| panic!("claim B")));
        let (claimed_a, proof_a) = ready
            .claim(claim_a)
            .unwrap_or_else(|error| panic!("claim A: {error}"));
        let (claimed_b, _) = ready
            .claim(claim_b)
            .unwrap_or_else(|error| panic!("claim B: {error}"));
        // Two contenders may compute candidates, but exact-byte CAS admits
        // only the one whose expected Ready bytes still match.
        let expected = ready.encode().as_bytes().to_vec();
        let mut durable = expected.clone();
        if durable == expected {
            durable = claimed_a.encode().as_bytes().to_vec();
        }
        assert_ne!(durable, expected);
        assert_ne!(durable, claimed_b.encode().as_bytes());

        let recovered = CompletionDeliveryRecord::decode(&durable)
            .unwrap_or_else(|error| panic!("decode claimed: {error}"));
        let (reclaimed, proof_b) = recovered
            .reclaim(claim_b)
            .unwrap_or_else(|error| panic!("reclaim: {error}"));
        assert_eq!(proof_b.generation().get(), 2);
        assert_eq!(
            reclaimed.acknowledge(proof_a).err(),
            Some(CompletionDeliveryError::StaleClaim)
        );
        let released = reclaimed
            .release(proof_b)
            .unwrap_or_else(|error| panic!("release: {error}"));
        let (claimed_again, proof_again) = released
            .claim(claim_a)
            .unwrap_or_else(|error| panic!("claim after release: {error}"));
        assert_eq!(proof_again.generation().get(), 3);
        let acknowledged = claimed_again
            .acknowledge(proof_again)
            .unwrap_or_else(|error| panic!("acknowledge: {error}"));
        assert_eq!(
            CompletionDeliveryRecord::decode(acknowledged.encode().as_bytes()),
            Ok(acknowledged)
        );

        let mut malformed = ready.encode().as_bytes().to_vec();
        assert_eq!(
            CompletionDeliveryRecord::decode(&malformed[..malformed.len() - 1]),
            Err(CompletionDeliveryError::MalformedRecord)
        );
        malformed.push(0);
        assert_eq!(
            CompletionDeliveryRecord::decode(&malformed),
            Err(CompletionDeliveryError::MalformedRecord)
        );
        let mut unsupported = ready.encode().as_bytes().to_vec();
        unsupported[4..6].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            CompletionDeliveryRecord::decode(&unsupported),
            Err(CompletionDeliveryError::UnsupportedVersion)
        );
        let mut impossible = ready.encode().as_bytes().to_vec();
        impossible[6] = 1;
        assert_eq!(
            CompletionDeliveryRecord::decode(&impossible),
            Err(CompletionDeliveryError::InvalidState)
        );
        let mut exhausted = ready.encode().as_bytes().to_vec();
        exhausted[48..56].copy_from_slice(&u64::MAX.to_be_bytes());
        let exhausted = CompletionDeliveryRecord::decode(&exhausted)
            .unwrap_or_else(|error| panic!("max generation record: {error}"));
        assert_eq!(
            exhausted.claim(claim_a).err(),
            Some(CompletionDeliveryError::ClaimGenerationExhausted)
        );

        let debug = format!("{ready:?} {:?}", ready.encode());
        assert!(!debug.contains(&SNAPSHOT_EPOCH.get().to_string()));
        assert!(!debug.contains(&completion.token().value().get().to_string()));
    }

    #[test]
    fn acknowledged_delivery_gates_snapshot_and_reconciles_the_old_head() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|error| panic!("connection: {error}"));
        let tracked = table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|error| panic!("track: {error}"));
        let old_head = snapshot_at(&mut table, 1);
        let completion = table
            .finish_exhausted(tracked.value())
            .unwrap_or_else(|error| panic!("finish: {error}"));
        assert_eq!(table.unacknowledged_completion_count(), 1);
        assert_eq!(
            table.snapshot(checkpoint(2)).err(),
            Some(SnapshotCreateError::UnacknowledgedCompletion)
        );
        assert!(!table.retire(tracked.value()));

        let ready = CompletionDeliveryRecord::new(SNAPSHOT_EPOCH, completion.token())
            .unwrap_or_else(|error| panic!("ready: {error}"));
        assert_eq!(
            table.acknowledge_completion_delivery(ready).err(),
            Some(CompletionDeliveryError::NotAcknowledged)
        );
        let acknowledged = acknowledged_delivery(&completion);
        table
            .acknowledge_completion_delivery(acknowledged)
            .unwrap_or_else(|error| panic!("table acknowledgement: {error}"));
        assert_eq!(table.unacknowledged_completion_count(), 0);
        let new_head = snapshot_at(&mut table, 2);

        // Crash after the side effect plus Ack became durable but before the
        // pending-only head advanced: restore the still-authoritative old head
        // and reconcile Ack before any retransmission.
        let mut recovered = restore_snapshot(&old_head, PendingRequestTableConfig::default());
        assert_eq!(recovered.reconcile_acknowledged(acknowledged), Ok(true));
        assert_eq!(recovered.pending_count(), 0);
        assert!(recovered.transaction(tracked.value()).is_none());
        let recovered_head = snapshot_at(&mut recovered, 2);
        assert_eq!(recovered_head.as_bytes(), new_head.as_bytes());
        assert_eq!(
            PendingRequestTable::restore(
                old_head.as_bytes(),
                checkpoint(2),
                PendingRequestTableConfig::default(),
                Arc::new(ManualClock::default())
            )
            .err(),
            Some(SnapshotRestoreError::Stale)
        );
        assert!(table.retire(tracked.value()));
    }

    /// Encode one snapshot record in the versioned on-disk form.
    fn snapshot_record(
        token_value: u128,
        generation: u64,
        end_to_end: u32,
        flags: u8,
        attempts: &[(u64, u32, u8, u64, u64)],
        raw_avps: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&token_value.to_be_bytes());
        out.extend_from_slice(&generation.to_be_bytes());
        out.extend_from_slice(&end_to_end.to_be_bytes());
        out.extend_from_slice(&302_u32.to_be_bytes());
        out.extend_from_slice(&100_u32.to_be_bytes());
        out.push(flags);
        out.extend_from_slice(&(attempts.len() as u16).to_be_bytes());
        for (connection, hop_by_hop, disposition, started, ended) in attempts {
            out.extend_from_slice(&connection.to_be_bytes());
            out.extend_from_slice(&hop_by_hop.to_be_bytes());
            let disposition = match disposition {
                0 => 0,
                1 => 2,
                2 => 3,
                3 => 4,
                4 => 5,
                other => *other,
            };
            out.push(disposition);
            out.extend_from_slice(&started.to_be_bytes());
            let written = if disposition == 4 { *started } else { u64::MAX };
            out.extend_from_slice(&written.to_be_bytes());
            out.extend_from_slice(&ended.to_be_bytes());
        }
        out.extend_from_slice(&(raw_avps.len() as u32).to_be_bytes());
        out.extend_from_slice(raw_avps);
        out
    }

    fn snapshot_bytes(records: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x4450_5453_u32.to_be_bytes());
        out.extend_from_slice(&SNAPSHOT_VERSION.to_be_bytes());
        out.extend_from_slice(&SNAPSHOT_EPOCH.get().to_be_bytes());
        out.extend_from_slice(&1_u64.to_be_bytes());
        out.extend_from_slice(&(records.len() as u16).to_be_bytes());
        for record in records {
            out.extend_from_slice(record);
        }
        out
    }

    fn minimal_avps() -> Vec<u8> {
        wire_avp(264, b"host.example")
    }

    fn restore_error(bytes: &[u8], config: PendingRequestTableConfig) -> SnapshotRestoreError {
        match PendingRequestTable::restore(
            bytes,
            checkpoint(1),
            config,
            Arc::new(ManualClock::default()),
        ) {
            Ok(_) => panic!("tampered snapshot must be rejected"),
            Err(error) => error,
        }
    }

    #[test]
    fn restore_tamper_matrix_is_rejected() {
        const NONE: u64 = u64::MAX;
        let config = PendingRequestTableConfig::default();
        let baseline = snapshot_bytes(&[snapshot_record(
            1,
            0,
            E2E,
            0x02,
            &[(1, 100, 0, 0, NONE)],
            &minimal_avps(),
        )]);
        PendingRequestTable::restore(
            &baseline,
            checkpoint(1),
            config,
            Arc::new(ManualClock::default()),
        )
        .unwrap_or_else(|e| panic!("baseline must restore: {e}"));

        // A nonzero completion generation is impossible for a pending record.
        let bad_generation = snapshot_bytes(&[snapshot_record(
            1,
            1,
            E2E,
            0x02,
            &[(1, 100, 0, 0, NONE)],
            &minimal_avps(),
        )]);
        assert_eq!(
            restore_error(&bad_generation, config),
            SnapshotRestoreError::InvalidRecord
        );

        // A fixed-destination flag with no Destination-Host AVP is a lie.
        let flag_lie = snapshot_bytes(&[snapshot_record(
            1,
            0,
            E2E,
            0x03,
            &[(1, 100, 0, 0, NONE)],
            &minimal_avps(),
        )]);
        assert_eq!(
            restore_error(&flag_lie, config),
            SnapshotRestoreError::InvalidRecord
        );

        // Reserved flag bits are rejected.
        let bad_flags = snapshot_bytes(&[snapshot_record(
            1,
            0,
            E2E,
            0x10,
            &[(1, 100, 0, 0, NONE)],
            &minimal_avps(),
        )]);
        assert_eq!(
            restore_error(&bad_flags, config),
            SnapshotRestoreError::InvalidRecord
        );

        // Duplicate completion tokens across records.
        let duplicate_tokens = snapshot_bytes(&[
            snapshot_record(1, 0, E2E, 0x02, &[(1, 100, 0, 0, NONE)], &minimal_avps()),
            snapshot_record(
                1,
                0,
                E2E + 1,
                0x02,
                &[(1, 101, 0, 0, NONE)],
                &minimal_avps(),
            ),
        ]);
        assert_eq!(
            restore_error(&duplicate_tokens, config),
            SnapshotRestoreError::InvalidRecord
        );

        // Duplicate End-to-End identifiers across records.
        let duplicate_e2e = snapshot_bytes(&[
            snapshot_record(1, 0, E2E, 0x02, &[(1, 100, 0, 0, NONE)], &minimal_avps()),
            snapshot_record(2, 0, E2E, 0x02, &[(1, 101, 0, 0, NONE)], &minimal_avps()),
        ]);
        assert_eq!(
            restore_error(&duplicate_e2e, config),
            SnapshotRestoreError::InvalidRecord
        );

        // Duplicate attempt identities within one record.
        let duplicate_attempt_within = snapshot_bytes(&[snapshot_record(
            1,
            0,
            E2E,
            0x02,
            &[(1, 100, 1, 0, 5), (1, 100, 0, 6, NONE)],
            &minimal_avps(),
        )]);
        assert_eq!(
            restore_error(&duplicate_attempt_within, config),
            SnapshotRestoreError::InvalidRecord
        );

        // Duplicate attempt identities across records.
        let duplicate_attempt_across = snapshot_bytes(&[
            snapshot_record(1, 0, E2E, 0x02, &[(1, 100, 0, 0, NONE)], &minimal_avps()),
            snapshot_record(
                2,
                0,
                E2E + 1,
                0x02,
                &[(1, 100, 0, 0, NONE)],
                &minimal_avps(),
            ),
        ]);
        assert_eq!(
            restore_error(&duplicate_attempt_across, config),
            SnapshotRestoreError::InvalidRecord
        );

        // An in-flight attempt must not carry an end timestamp.
        let in_flight_ended = snapshot_bytes(&[snapshot_record(
            1,
            0,
            E2E,
            0x02,
            &[(1, 100, 0, 0, 7)],
            &minimal_avps(),
        )]);
        assert_eq!(
            restore_error(&in_flight_ended, config),
            SnapshotRestoreError::InvalidRecord
        );

        // A terminated attempt must carry an end timestamp.
        let failed_open = snapshot_bytes(&[snapshot_record(
            1,
            0,
            E2E,
            0x02,
            &[(1, 100, 1, 0, NONE)],
            &minimal_avps(),
        )]);
        assert_eq!(
            restore_error(&failed_open, config),
            SnapshotRestoreError::InvalidRecord
        );

        // A pending record must hold at least one attempt.
        let no_attempts = snapshot_bytes(&[snapshot_record(1, 0, E2E, 0x02, &[], &minimal_avps())]);
        assert_eq!(
            restore_error(&no_attempts, config),
            SnapshotRestoreError::InvalidRecord
        );

        // A pending record must not contain an answered attempt.
        let answered = snapshot_bytes(&[snapshot_record(
            1,
            0,
            E2E,
            0x02,
            &[(1, 100, 4, 0, 5)],
            &minimal_avps(),
        )]);
        assert_eq!(
            restore_error(&answered, config),
            SnapshotRestoreError::InvalidRecord
        );

        // Attempt history exceeding the restored table's per-record bound.
        let two_attempts = snapshot_bytes(&[snapshot_record(
            1,
            0,
            E2E,
            0x02,
            &[(1, 100, 1, 0, 5), (2, 900, 0, 6, NONE)],
            &minimal_avps(),
        )]);
        let tight_attempts = PendingRequestTableConfig {
            max_attempts_per_transaction: 1,
            ..PendingRequestTableConfig::default()
        };
        assert_eq!(
            restore_error(&two_attempts, tight_attempts),
            SnapshotRestoreError::LimitExceeded
        );

        // Record count exceeding the restored table's pending bound.
        let two_records = snapshot_bytes(&[
            snapshot_record(1, 0, E2E, 0x02, &[(1, 100, 0, 0, NONE)], &minimal_avps()),
            snapshot_record(
                2,
                0,
                E2E + 1,
                0x02,
                &[(1, 101, 0, 0, NONE)],
                &minimal_avps(),
            ),
        ]);
        let tight_pending = PendingRequestTableConfig {
            max_pending_transactions: 1,
            ..PendingRequestTableConfig::default()
        };
        assert_eq!(
            restore_error(&two_records, tight_pending),
            SnapshotRestoreError::LimitExceeded
        );
    }
}
