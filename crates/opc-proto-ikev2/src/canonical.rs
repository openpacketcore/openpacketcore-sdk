//! Frozen V1 AES-GCM replies to authenticated empty INFORMATIONAL requests.
//!
//! This primitive reproduces one immutable transcript; it supplies no receive
//! window admission, transmission authority, liveness or durable outcome. The
//! zero-write handler and volatile receive floor remain separate. A deployment
//! unable to qualify this path must reject DPD-sending peer configurations;
//! there is no fallback. See `docs/ikev2-canonical-empty-replies.md` for the
//! conditional nonce argument and the departure from SP 800-38D §9.1 item 3.
//! No validated-module or FIPS 140-3 claim is made.

use std::{
    error::Error as StdError,
    fmt,
    sync::{Arc, Mutex},
};

use crate::{
    recovery::{Ikev2AuthenticatedOrdinary, Ikev2CommittedWindowDomain},
    Ikev2AesGcmIvDomain, Ikev2AesGcmIvRecord, Ikev2EncryptionAlgorithm,
};

use zeroize::Zeroizing;

mod ledger;
mod qualification;
mod wire;

#[cfg(test)]
mod qualification_tests;

pub(crate) const V1: u8 = 1;

/// Maximum concurrently retained directional key ledgers per process.
///
/// This live-SA concurrency bound must exceed the consumer's largest per-Pod
/// session count, including overlapping old/new SAs and recovery headroom.
/// Undeleted ledgers count even without a live capability; they are never evicted.
/// Delete an epoch's state only once that SA is deleted. Tombstones count against
/// their separate bound, so deletion churn never spends this capacity.
pub const IKEV2_CANONICAL_MAX_TRACKED_KEYS: usize = 1_048_576;

/// Maximum recent deletion/trust-loss fingerprints retained in FIFO order.
///
/// Older tombstones are evicted; duplicate deletion does not refresh FIFO age.
/// Deletion history imposes no lifetime SA limit. Consumers must never restore
/// deleted records, even after their tombstones expire.
pub const IKEV2_CANONICAL_MAX_TOMBSTONES: usize = 1_048_576;

/// Dedicated opt-in for the canonical restart rule, independent of admission.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ikev2CanonicalPolicy {
    allow_declared_validated: bool,
}

impl Ikev2CanonicalPolicy {
    /// Explicitly accept the documented departure for a declared-validated module.
    ///
    /// This confers no validation claim and overrides neither module policy nor
    /// qualification, readiness or packet checks. Default policy refuses it.
    pub const fn explicitly_allow_declared_validated() -> Self {
        Self {
            allow_declared_validated: true,
        }
    }
}

/// A canonical refusal. No variant carries keys, packets or provider diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ikev2CanonicalError {
    /// No fresh durable activation; restored allocation alone grants no capability.
    NotCommitted,
    /// Missing, unknown or incompatible immutable format marker.
    FormatUnavailable,
    /// Window lifecycle currently withholds ordinary/canonical send authority.
    LifecycleBlocked,
    /// Packet or record belongs to another complete immutable epoch binding.
    BindingMismatch,
    /// This authenticated packet is not a peer empty INFORMATIONAL request.
    InvalidRequest,
    /// Trust was withdrawn; discard all recipe bytes and establish fresh keys.
    Invalidated,
    /// A capability already owns the in-memory cache for this sending key/salt.
    CapabilityActive,
    /// The ID was released or retired and its bytes are no longer in this cache.
    AlreadyReleased,
    /// Three evaluations were withheld in this process; no fourth is allowed.
    AttemptsExhausted,
    /// Canonical use of the declared-validated module needs the dedicated opt-in.
    ValidationOptInRequired,
    /// Frozen known-answer qualification failed and is latched for this algorithm.
    QualificationFailed,
    /// Current admitted module/algorithm is unavailable or a ledger was poisoned.
    Unavailable,
    /// The concurrent live-ledger cap is full; deletion history does not count.
    RegistryFull,
    /// A withheld output failed prefix, size, authentication or raw-plaintext checks.
    InvalidOutput,
}

impl fmt::Display for Ikev2CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotCommitted => "ike_canonical_not_committed",
            Self::FormatUnavailable => "ike_canonical_format_unavailable",
            Self::LifecycleBlocked => "ike_canonical_lifecycle_blocked",
            Self::BindingMismatch => "ike_canonical_binding_mismatch",
            Self::InvalidRequest => "ike_canonical_invalid_request",
            Self::Invalidated => "ike_canonical_invalidated",
            Self::CapabilityActive => "ike_canonical_capability_active",
            Self::AlreadyReleased => "ike_canonical_id_retired",
            Self::AttemptsExhausted => "ike_canonical_attempts_exhausted",
            Self::ValidationOptInRequired => "ike_canonical_validation_opt_in_required",
            Self::QualificationFailed => "ike_canonical_qualification_failed",
            Self::Unavailable => "ike_canonical_unavailable",
            Self::RegistryFull => "ike_canonical_registry_full",
            Self::InvalidOutput => "ike_canonical_invalid_output",
        })
    }
}
impl StdError for Ikev2CanonicalError {}

/// Non-cloneable, record-derived canonical recipe and volatile exact-byte cache.
///
/// Creation is private to the checked window's empty-reply handler. Neither
/// raw keys nor a separately constructed descriptor can mint this type. Every
/// reply still requires surrounding receive admission and current send authority.
/// Check [`crate::recovery::Ikev2CommittedWindow::ready`] for every reply, including
/// cached bytes: an existing capability does not track subsequent window changes.
/// On untrusted/mixed state or unknown key/IV provenance, call
/// [`crate::recovery::Ikev2CommittedWindow::delete`] or [`Self::delete_epoch`],
/// discard consumer-held copies and withhold sending. A doubted immutable binding
/// requires a fresh SA; do not "reconcile" it while retaining its keys.
///
/// The process ledger retains only fingerprints, counters and verified ciphertext.
/// Its key material is owned by the live capability and zeroized on drop. The
/// owning window advances retirement to compact ID history into a
/// closed floor; recreation cannot reopen closed IDs or reset attempts above it.
/// On permanent SA deletion, use the window's `delete()` or [`Self::delete_epoch`] to
/// remove all ID state. A bounded FIFO retains recent fingerprint tombstones;
/// older tombstones are evicted. [`IKEV2_CANONICAL_MAX_TRACKED_KEYS`] bounds only
/// live ledgers, which are never evicted. Deletion churn cannot exhaust that cap.
/// Consumers must not restore a deleted SA after its tombstone ages out: that
/// bug can create a fresh ledger, though the same persisted binding still fixes
/// the identical V1 transcript. A changed binding violates the key-use contract,
/// with the same exposure as restoring such a changed binding after process loss.
///
/// ```compile_fail
/// use opc_proto_ikev2::canonical::Ikev2CanonicalEmptyReplies;
/// fn duplicate(value: Ikev2CanonicalEmptyReplies) { let _ = value.clone(); }
/// ```
///
/// The receive handler owns this primitive; public replies must use
/// [`crate::recovery::Ikev2CommittedWindow::enable_empty_replies`] and
/// [`crate::recovery::Ikev2CommittedWindow::reply_empty`]. A persisted record
/// cannot bypass that checked route:
/// ```compile_fail
/// use opc_proto_ikev2::{Ikev2AesGcmIvRecord, canonical::*};
/// fn unchecked(record: &Ikev2AesGcmIvRecord) {
///     let _ = Ikev2CanonicalEmptyReplies::from_record(record, Ikev2CanonicalPolicy::default());
/// }
/// ```
///
/// No raw or widened Message ID can replace authenticated request evidence:
/// ```compile_fail
/// use opc_proto_ikev2::canonical::Ikev2CanonicalEmptyReplies;
/// fn widened(value: &Ikev2CanonicalEmptyReplies, id: u64) { let _ = value.reply(id); }
/// ```
///
/// Output plaintext/header/IV/padding/key/tag overrides are unavailable:
/// ```compile_fail
/// use opc_proto_ikev2::{canonical::Ikev2CanonicalEmptyReplies, recovery::Ikev2AuthenticatedOrdinary};
/// fn varied(value: &Ikev2CanonicalEmptyReplies, request: &Ikev2AuthenticatedOrdinary) {
///     let _ = value.reply(request, &[1, 2, 3]);
/// }
/// ```
pub struct Ikev2CanonicalEmptyReplies {
    ledger: Arc<Mutex<ledger::Ledger>>,
    // Only the live capability owns these zeroizing key copies, never a static.
    binding: Ikev2CommittedWindowDomain,
    instance: Arc<()>,
    policy: Ikev2CanonicalPolicy,
}

impl Ikev2CanonicalEmptyReplies {
    /// Qualify each intended algorithm before admitting DPD-sending peer configurations.
    ///
    /// Frozen public test keys are used once per process and algorithm. A cached
    /// success never skips current module identity, readiness or validation checks.
    /// No key epoch or persistence is required for this configuration preflight.
    /// # Errors
    /// Refuses unadmitted/unavailable algorithms, declared validation without opt-in,
    /// or a latched known-answer failure. There is no alternate provider/IV path.
    pub fn preflight(
        algorithm: Ikev2EncryptionAlgorithm,
        policy: Ikev2CanonicalPolicy,
    ) -> Result<(), Ikev2CanonicalError> {
        qualification::preflight(algorithm, policy)
    }

    pub(crate) fn from_record(
        record: &Ikev2AesGcmIvRecord,
        policy: Ikev2CanonicalPolicy,
    ) -> Result<Self, Ikev2CanonicalError> {
        if record.canonical_format() != Some(V1) {
            invalidate_binding(record.domain());
            return Err(Ikev2CanonicalError::FormatUnavailable);
        }
        let binding = Ikev2CommittedWindowDomain::from_iv_record(record);
        let (ledger, instance) = ledger::acquire(&binding)?;
        let capability = Self {
            ledger,
            binding,
            instance,
            policy,
        };
        Self::preflight(record.domain().encryption(), policy)?;
        Ok(capability)
    }

    pub(crate) fn check_live(&self) -> Result<(), Ikev2CanonicalError> {
        self.ledger
            .lock()
            .map_err(|_| Ikev2CanonicalError::Unavailable)?
            .check_instance(&self.instance)
    }

    /// Produce or reuse the exact V1 reply to an authenticated same-binding request.
    ///
    /// The input must come from `Ikev2CommittedWindow::open_peer`. This checks its
    /// empty INFORMATIONAL class, not receive floors, reconstruction or lifecycle
    /// admission. Request padding/ignored bits never enter the output. Message ID
    /// is already a wire `u32`; no narrowing, exhaustion sentinel or wrap is accepted.
    /// The consumer must check current receive admission and
    /// [`crate::recovery::Ikev2CommittedWindow::ready`] on every reply, even a cache
    /// hit. Retain current send authority through transmission; an owned reply or
    /// previously minted capability cannot establish it after the window changes.
    ///
    /// At most three attempts and one newly released packet per sending key/salt/ID
    /// while its undeleted ledger is retained in this process. After release, only
    /// cached bytes can be returned. No storage,
    /// random draw, ordinary IV allocation or retry loop occurs here. Withheld
    /// output never leaves the zeroizing private buffer or enters diagnostics.
    /// # Errors
    /// Refuses foreign/nonempty/wrong-class requests, invalidated bindings, module
    /// failures, failed self-checks, retired IDs and exhausted attempt budgets.
    pub(crate) fn reply(
        &self,
        request: &Ikev2AuthenticatedOrdinary,
    ) -> Result<Ikev2CanonicalReply, Ikev2CanonicalError> {
        let mut state = self
            .ledger
            .lock()
            .map_err(|_| Ikev2CanonicalError::Unavailable)?;
        state.check_instance(&self.instance)?;
        let id = request.canonical_message_id(&self.binding)?;
        Self::preflight(self.binding.send.encryption(), self.policy)?;
        if state.closed_through.is_some_and(|floor| id <= floor) {
            return Err(Ikev2CanonicalError::AlreadyReleased);
        }
        if let Some(entry) = state.entries.get(&id) {
            if let Some(bytes) = &entry.bytes {
                return Ok(Ikev2CanonicalReply {
                    bytes: bytes.clone(),
                });
            }
            if entry.released {
                return Err(Ikev2CanonicalError::AlreadyReleased);
            }
            if entry.attempts >= 3 {
                return Err(Ikev2CanonicalError::AttemptsExhausted);
            }
        }
        // Charge before entering the module. A panic poisons the ledger rather
        // than refunding the attempt or making a fresh capability bypass it.
        state.entries.entry(id).or_default().attempts += 1;
        let packet = wire::seal(wire::Inputs::from_domain(&self.binding.send), id)?;
        let entry = state
            .entries
            .get_mut(&id)
            .ok_or(Ikev2CanonicalError::Unavailable)?;
        entry.released = true;
        let bytes: Zeroizing<[u8; 57]> = Zeroizing::new(
            packet
                .as_slice()
                .try_into()
                .map_err(|_| Ikev2CanonicalError::InvalidOutput)?,
        );
        entry.bytes = Some(bytes.clone());
        Ok(Ikev2CanonicalReply { bytes })
    }

    /// Discard one cached reply without restoring its sealing eligibility.
    ///
    /// Unknown IDs have no cached bytes to retire. Use [`Self::retire_through`]
    /// to compact history and close previously unseen IDs as the window advances.
    /// # Errors
    /// Refuses an invalidated capability or poisoned process ledger.
    #[cfg(test)]
    pub(crate) fn retire(&self, message_id: u32) -> Result<(), Ikev2CanonicalError> {
        let mut state = self
            .ledger
            .lock()
            .map_err(|_| Ikev2CanonicalError::Unavailable)?;
        state.check_instance(&self.instance)?;
        if let Some(entry) = state.entries.get_mut(&message_id) {
            entry.bytes = None;
            entry.released = true;
        }
        Ok(())
    }

    /// Permanently close every ID at or below `message_id` and free its entries.
    ///
    /// Call as receive admission advances beyond replies that must be retained.
    /// The floor never moves backward, including after capability recreation.
    /// Previously unseen IDs below it also refuse. Entries above it retain their
    /// attempt/release history. At MAX every ID is closed without arithmetic wrap.
    /// # Errors
    /// Refuses an invalidated capability or poisoned process ledger.
    pub(crate) fn retire_through(&self, message_id: u32) -> Result<(), Ikev2CanonicalError> {
        let mut state = self
            .ledger
            .lock()
            .map_err(|_| Ikev2CanonicalError::Unavailable)?;
        state.check_instance(&self.instance)?;
        state.retire_through(message_id);
        Ok(())
    }

    /// Withdraw canonical trust and permanently revoke this key's current ledger.
    ///
    /// Discard consumer-held copies too. All per-ID state is dropped, leaving
    /// a recent fingerprint tombstone. Its eventual FIFO eviction does not restore
    /// trust or make this capability usable. A doubted binding requires a fresh SA.
    pub(crate) fn invalidate(&self) {
        ledger::revoke(&self.binding.send, true);
    }

    /// Delete this epoch's canonical state and zeroize this capability's keys.
    ///
    /// Call once the SA is deleted; after rekey, retain the old epoch until the old
    /// SA is deleted. A recent fingerprint tombstone refuses re-admission until it
    /// ages out. Discard consumer-held replies and the outer SA/key records too;
    /// never restore a deleted SA, even after its tombstone expires.
    pub(crate) fn delete(self) {
        self.invalidate();
    }

    /// Delete an epoch even when no live capability remains (for example after an error).
    ///
    /// Use its trusted IV record once the SA is deleted, including the old SA
    /// after rekey. This clears all canonical ID/cache state and retains only a
    /// recent fingerprint tombstone. Its eventual eviction grants no authority
    /// to restore a deleted record.
    pub fn delete_epoch(record: &Ikev2AesGcmIvRecord) {
        ledger::revoke(record.domain(), true);
    }
}

impl Drop for Ikev2CanonicalEmptyReplies {
    fn drop(&mut self) {
        let mut state = self
            .ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.owns(&self.instance) {
            state.revoke(false);
        }
    }
}

impl fmt::Debug for Ikev2CanonicalEmptyReplies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2CanonicalEmptyReplies")
            .finish_non_exhaustive()
    }
}

/// Owned verified ciphertext; not receive-window or transmission authority.
///
/// Owns exactly 57 IKE octets and no ledger lock or key material. It can cross
/// threads. The consumer must discard copies when trust or lifecycle authority
/// is lost. Held-back evaluations cannot construct this type.
pub struct Ikev2CanonicalReply {
    bytes: Zeroizing<[u8; 57]>,
}

impl Ikev2CanonicalReply {
    /// The exact immutable 57 IKE octets, without transport framing.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..]
    }
}

impl fmt::Debug for Ikev2CanonicalReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2CanonicalReply")
            .finish_non_exhaustive()
    }
}

pub(crate) fn invalidate_binding(domain: &Ikev2AesGcmIvDomain) {
    ledger::revoke(domain, true);
}
