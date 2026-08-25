//! Startup-owned executor for protected fenced-mutation roster providers.
//!
//! This is deliberately a control-plane layer, rather than a second roster
//! protocol. The durable backend owns the two quorum mutations and their
//! authority validation; provider ambiguity and prepared terminal bodies stay
//! local to this executor. The executor owns one provider selected at process
//! startup and one shared concurrency limit.
//! Consequently no request can substitute a provider, and no subscriber
//! creates a task, channel, connection, or semaphore of its own.

use super::{
    canonical::{
        decode_frame, encode_frame, session_key_canonical_digest_input, Admission,
        EstablishedPublicationCall, Member, MemberCall, MemberProvider, Phase, ProviderCallOutcome,
        ProviderCallOutcomeParts, ProviderOutcome, RequestId, RosterId, Scope,
        TerminalConflictTombstone, TerminalRecord, TerminalSlotId, COMMITTED_TERMINAL_FRAME_DOMAIN,
        COMMITTED_TERMINAL_FRAME_MAGIC, MAX_COMMITTED_TERMINAL_CODEC_BYTES, MAX_PLAN_BYTES,
        MAX_STATUS_BYTES, PROOF_BINDING_DOMAIN, PROOF_CREDENTIAL_DOMAIN, PROOF_DESCRIPTOR_DOMAIN,
        PROOF_DOMAIN, PROOF_OWNER_DOMAIN, PROVIDER_OPERATION_ADOPT_TAG,
        PROVIDER_OPERATION_COMPENSATE_TAG, PROVIDER_OPERATION_EXECUTE_TAG,
        PROVIDER_OPERATION_PREPARE_TAG, PROVIDER_OPERATION_STATUS_TAG, PROVIDER_SCHEDULING_DOMAIN,
        TERMINAL_COMMITTING_GUARD_DOMAIN, TERMINAL_RECEIPT_COMMITMENT_DOMAIN,
        TERMINAL_RECORD_COMMITMENT_DOMAIN,
    },
    diagnostics::{
        Counter as DiagnosticsCounter, Latency as DiagnosticsLatency, RosterDiagnostics,
        RosterDiagnosticsInner,
    },
    scheduler::ProviderWorkScheduler,
};
use async_trait::async_trait;
use opc_session_store::fenced_mutation_roster::{
    RosterAttestationCertificateRoleV1, RosterAttestationLeafCertificatePartsV1,
    RosterAttestationLeafCertificateV1, RosterAttestationTrustRootV1,
    RosterExecutorMemberProofPartsV1, RosterExecutorProofBundleV1, RosterProviderOperationV1,
    RosterProviderOutcomeV1, RosterTerminalAttestationSigningInputV1,
};
use opc_session_store::{Clock, FenceToken, Generation, OwnerId, SessionKey, SystemClock};
use opc_types::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fmt,
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{Duration, Instant},
};
use tokio::sync::Mutex as AsyncMutex;

const PROVIDER_EFFECT_DEADLINE: Duration = Duration::from_secs(30);
/// One process-wide provider gate can never exceed the durable live-roster cap.
const MAX_PROVIDER_IN_FLIGHT: usize = super::canonical::MAX_LIVE_ROSTERS;
/// Authority entries are durable-operation capabilities, not concurrent
/// provider work. Bound their independent ledger by the profile's aggregate
/// live-plus-retained population so terminal-but-unexpired capabilities cannot
/// consume the 1,024 provider-work allowance.
const MAX_LOCAL_AUTHORITY_ENTRIES: usize = super::canonical::MAX_RESERVED_AND_RETAINED;
/// The local authority ledger must never serialize unrelated tenant/scope
/// provider effects behind one process-wide lock. Keep this aligned with the
/// fixed provider-work scheduler shard count.
const LOCAL_AUTHORITY_SHARDS: usize = 16;
/// A fixed provider operation authorized by the durable control plane.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ProviderOperation {
    /// Durably retain the exact request without crossing its effect boundary.
    Prepare,
    /// Transmit the one exact member effect.
    Execute,
    /// Read the exact effect after an ambiguity boundary.
    Status,
    /// Adopt an exact provider-side effect after an ambiguity boundary.
    Adopt,
    /// Compensate one exact SDK-proven applied member under the current fence.
    Compensate,
}

impl ProviderOperation {
    fn tag(self) -> u8 {
        match self {
            Self::Prepare => PROVIDER_OPERATION_PREPARE_TAG,
            Self::Execute => PROVIDER_OPERATION_EXECUTE_TAG,
            Self::Status => PROVIDER_OPERATION_STATUS_TAG,
            Self::Adopt => PROVIDER_OPERATION_ADOPT_TAG,
            Self::Compensate => PROVIDER_OPERATION_COMPENSATE_TAG,
        }
    }
}

/// Fixed, redaction-safe executor failure classification.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
#[doc(hidden)]
pub enum ExecutorError {
    /// Registration input is malformed or contradicts its immutable admission.
    InvalidRegistration,
    /// A member ordinal is not part of the registered immutable roster.
    InvalidMember,
    /// The backend rejected scope, tenant, key, owner, fence, credential, or generation.
    AuthorityRejected,
    /// The local attempt has crossed an ambiguity boundary and must not execute again.
    RecoveryRequired,
    /// Local terminal preparation has locked member calls for this registration.
    TerminalLocked,
    /// A different terminal body conflicts with the same durable registration.
    TerminalConflict,
    /// The provider response was malformed or incompatible with its operation kind.
    InvalidProviderResponse,
    /// The provider boundary could have crossed without an SDK-issued proof.
    OutcomeUnknown,
    /// The terminal phase, complete proof set, or checkpoint is invalid.
    InvalidTerminal,
    /// The shared executor was shut down while a caller waited for capacity.
    ExecutorUnavailable,
    /// The fixed shared provider capacity is currently exhausted.
    ExecutorBusy,
    /// The durable authority backend failed without exposing adapter details.
    BackendUnavailable,
    /// The startup-fixed executor attestor refused or could not complete a
    /// typed terminal proof. Its cause, key material, and provider evidence
    /// never enter diagnostics.
    AttestationUnavailable,
    /// No admission request byte crossed the transport boundary.
    AdmissionNotTransmitted,
    /// Admission may have committed and requires exact-body readback.
    AdmissionOutcomeUnknown,
    /// Terminal submission may have committed; use exact terminal status/readback only.
    TerminalizeOutcomeUnknown,
    /// No terminal request byte crossed the transport boundary.
    TerminalizeNotTransmitted,
    /// The exact terminal payload aged out; only nonpublishing conflict status remains.
    TerminalPayloadCompacted,
    /// Admission's required present session record was not available.
    AdmissionRecordMissing,
    /// Admission's required present session generation differed.
    AdmissionGenerationConflict,
    /// Admission rejected a Put whose successor generation would overflow.
    AdmissionGenerationExhausted,
    /// Another live admission already reserves this protected business key.
    AdmissionBusinessKeyReserved,
    /// Admission rejected an invalid exact protected checkpoint.
    AdmissionInvalidProtectedCheckpoint,
    /// Admission could not reserve deterministic aggregate terminal storage.
    AdmissionAggregateBytesFull,
    /// Admission could not reserve a bounded live roster slot.
    AdmissionLiveFull,
    /// Admission could not reserve a bounded retained-history slot.
    AdmissionHistoryFull,
}

impl fmt::Display for ExecutorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRegistration => "invalid roster executor registration",
            Self::InvalidMember => "invalid roster executor member",
            Self::AuthorityRejected => "roster executor authority rejected",
            Self::RecoveryRequired => "roster executor recovery required",
            Self::TerminalLocked => "roster executor terminal locked",
            Self::TerminalConflict => "roster executor terminal conflict",
            Self::InvalidProviderResponse => "invalid roster provider response",
            Self::OutcomeUnknown => "roster executor outcome unknown",
            Self::InvalidTerminal => "invalid roster executor terminal",
            Self::ExecutorUnavailable => "roster executor unavailable",
            Self::ExecutorBusy => "roster executor busy",
            Self::BackendUnavailable => "roster executor backend unavailable",
            Self::AttestationUnavailable => "roster executor attestation unavailable",
            Self::AdmissionNotTransmitted => "roster admission not transmitted",
            Self::AdmissionOutcomeUnknown => "roster admission outcome unknown",
            Self::TerminalizeOutcomeUnknown => "roster executor terminalization outcome unknown",
            Self::TerminalizeNotTransmitted => "roster executor terminalization not transmitted",
            Self::TerminalPayloadCompacted => "roster terminal payload compacted",
            Self::AdmissionRecordMissing => "roster admission record missing",
            Self::AdmissionGenerationConflict => "roster admission generation conflict",
            Self::AdmissionGenerationExhausted => "roster admission generation exhausted",
            Self::AdmissionBusinessKeyReserved => "roster admission business key reserved",
            Self::AdmissionInvalidProtectedCheckpoint => {
                "roster admission protected checkpoint rejected"
            }
            Self::AdmissionAggregateBytesFull => "roster admission aggregate capacity full",
            Self::AdmissionLiveFull => "roster admission live capacity full",
            Self::AdmissionHistoryFull => "roster admission history capacity full",
        })
    }
}

impl std::error::Error for ExecutorError {}

/// Startup-owned HSM/KMS seam for terminal attestation.
///
/// This narrow interface deliberately accepts only a store-defined, typed
/// terminal preimage. It exposes neither a generic signing operation nor a
/// consensus, administrative, or root-private-key capability. The executor
/// freezes the returned root and Executor leaf once for each preparation.
#[doc(hidden)]
#[async_trait]
pub trait FencedMutationRosterExecutorAttestor: Send + Sync + 'static {
    /// Return the topology-provisioned public trust root used to verify the
    /// already-root-signed Executor leaf.
    fn trust_root(&self) -> RosterAttestationTrustRootV1;

    /// Return one already root-signed Executor leaf certificate.
    fn executor_certificate(
        &self,
    ) -> Result<RosterAttestationLeafCertificatePartsV1, ExecutorError>;

    /// Sign exactly one SDK-constructed terminal member preimage.
    async fn sign_terminal(
        &self,
        input: &RosterTerminalAttestationSigningInputV1,
    ) -> Result<[u8; 64], ExecutorError>;
}

#[derive(Clone)]
struct FrozenExecutorAttestation {
    root: RosterAttestationTrustRootV1,
    certificate: RosterAttestationLeafCertificatePartsV1,
}

fn freeze_executor_attestation(
    attestor: &dyn FencedMutationRosterExecutorAttestor,
    admission: &Admission,
) -> Result<FrozenExecutorAttestation, ExecutorError> {
    let root = attestor.trust_root();
    let certificate = attestor.executor_certificate()?;
    let issued =
        RosterAttestationLeafCertificateV1::issue_from_signed_parts(&root, certificate.clone())
            .map_err(|_| ExecutorError::AttestationUnavailable)?;
    if issued
        .role()
        .map_err(|_| ExecutorError::AttestationUnavailable)?
        != RosterAttestationCertificateRoleV1::Executor
        || certificate.scope != admission.scope().digest()
    {
        return Err(ExecutorError::AttestationUnavailable);
    }
    Ok(FrozenExecutorAttestation { root, certificate })
}

/// Authenticated authority metadata bound to a registration by the backend.
///
/// The tenant is derived from `key` rather than accepted as a second
/// caller-supplied string. The admission/recovery and terminal quorum
/// mutations receive this complete binding and MUST compare it exactly with
/// durable state. Provider-local work uses the startup-owned permit derived
/// from this binding instead of making a quorum read.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AuthorityBinding {
    scope: Scope,
    key: SessionKey,
    owner: OwnerId,
    fence: FenceToken,
    credential_id: u64,
    generation: Generation,
    // These are authenticated lease-manager values. Backends compare them to
    // their own logical clock/lease row. The executor's injected clock uses
    // them only as a conservative process-local expiry/revocation gate; it is
    // never a source of distributed authority.
    acquired_at: Timestamp,
    expires_at: Timestamp,
}

#[derive(Clone, Copy)]
pub(crate) struct LeaseMetadata {
    acquired_at: Timestamp,
    expires_at: Timestamp,
}

impl LeaseMetadata {
    pub(crate) const fn new(acquired_at: Timestamp, expires_at: Timestamp) -> Self {
        Self {
            acquired_at,
            expires_at,
        }
    }
}

impl AuthorityBinding {
    /// Build the binding for an immutable admission and one lease credential.
    pub(crate) fn for_admission(
        admission: &Admission,
        owner: OwnerId,
        fence: FenceToken,
        credential_id: u64,
        generation: Generation,
        acquired_at: Timestamp,
        expires_at: Timestamp,
    ) -> Result<Self, ExecutorError> {
        if credential_id == 0
            || fence.get() == 0
            || &owner != admission.logical_owner()
            || fence != admission.admission_fence()
            || generation != admission.expected_generation()
            || expires_at <= acquired_at
        {
            return Err(ExecutorError::InvalidRegistration);
        }
        Ok(Self {
            scope: admission.scope(),
            key: admission.key().clone(),
            owner,
            fence,
            credential_id,
            generation,
            acquired_at,
            expires_at,
        })
    }

    /// Build the replacement binding after a strictly higher-fence takeover.
    ///
    /// The immutable admission retains the original owner and fence as its
    /// historical provenance.  A recovered registration instead binds the
    /// backend's current successor owner, credential, and strictly higher
    /// fence while keeping the same key, scope, and expected generation.
    fn for_successor(
        admission: &Admission,
        owner: OwnerId,
        fence: FenceToken,
        credential_id: u64,
        generation: Generation,
        acquired_at: Timestamp,
        expires_at: Timestamp,
    ) -> Result<Self, ExecutorError> {
        if credential_id == 0
            || fence <= admission.admission_fence()
            || generation != admission.expected_generation()
            || expires_at <= acquired_at
        {
            return Err(ExecutorError::InvalidRegistration);
        }
        Ok(Self {
            scope: admission.scope(),
            key: admission.key().clone(),
            owner,
            fence,
            credential_id,
            generation,
            acquired_at,
            expires_at,
        })
    }

    /// Build current authority for a recovery lookup before the backend has
    /// returned its consensus-retained immutable admission.
    fn for_recovery(
        scope: Scope,
        key: SessionKey,
        owner: OwnerId,
        fence: FenceToken,
        credential_id: u64,
        generation: Generation,
        lease: LeaseMetadata,
    ) -> Result<Self, ExecutorError> {
        if credential_id == 0 || fence.get() == 0 || lease.expires_at <= lease.acquired_at {
            return Err(ExecutorError::InvalidRegistration);
        }
        Ok(Self {
            scope,
            key,
            owner,
            fence,
            credential_id,
            generation,
            acquired_at: lease.acquired_at,
            expires_at: lease.expires_at,
        })
    }

    /// Authenticated tenant derived from the exact protected session key.
    pub(crate) fn tenant(&self) -> &opc_types::TenantId {
        &self.key.tenant
    }

    /// Authenticated least-authority scope commitment.
    pub(crate) const fn scope(&self) -> Scope {
        self.scope
    }

    /// Exact protected session key, including tenant.
    pub(crate) fn key(&self) -> &SessionKey {
        &self.key
    }

    /// Exact authenticated owner.
    pub(crate) fn owner(&self) -> &OwnerId {
        &self.owner
    }

    /// Exact authenticated fence token.
    pub(crate) const fn fence(&self) -> FenceToken {
        self.fence
    }

    /// Exact authenticated lease credential sequence.
    pub(crate) const fn credential_id(&self) -> u64 {
        self.credential_id
    }

    /// Exact authoritative generation.
    pub(crate) const fn generation(&self) -> Generation {
        self.generation
    }

    /// Lease issuance metadata to compare with backend-owned logical time.
    pub(crate) const fn acquired_at(&self) -> Timestamp {
        self.acquired_at
    }

    /// Lease expiry metadata to compare with backend-owned logical time.
    pub(crate) const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
}

impl fmt::Debug for AuthorityBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityBinding(<redacted>)")
    }
}

/// Startup-owned, process-local authority ledger for provider-local effects.
///
/// Admission and successor recovery are the only operations that install an
/// entry.  The ledger is deliberately not a second source of distributed
/// authority: the admission/recovery mutation authenticates the binding and
/// the terminal mutation authenticates it again durably.  It is instead the
/// local revocation and expiry gate between those two quorum points.  That
/// makes provider I/O and publication stay provider-local on the fresh path
/// while preventing an in-flight stale capability from producing a proof or
/// ACK after a same-process successor has been installed.
#[derive(Clone)]
pub(crate) struct LocalAuthorityRegistry {
    inner: Arc<LocalAuthorityRegistryInner>,
}

struct LocalAuthorityRegistryInner {
    clock: Arc<dyn Clock>,
    /// Each immutable roster binding has exactly one shard. There is no global
    /// registry mutex: a lock collision can affect only one fixed shard.
    entries: [Mutex<HashMap<LocalAuthorityKey, LocalAuthorityEntry>>; LOCAL_AUTHORITY_SHARDS],
    /// Reservations are made while holding an individual shard lock, but this
    /// atomic total closes the inter-shard race at the durable live-roster
    /// limit. It owns no waiters and never evicts current authority.
    entry_count: AtomicUsize,
    /// Starting shard for the next bounded expiry sweep. Advancing this
    /// cursor avoids coupling repeated capacity probes to one tenant shard.
    expiry_sweep_cursor: AtomicUsize,
}

/// One immutable roster identity. The remaining current-authority fields are
/// stored in the entry and copied into an opaque permit at issuance.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct LocalAuthorityKey {
    scope: Scope,
    key_digest: [u8; 32],
    roster_id: RosterId,
    admission_commitment: [u8; 32],
}

impl LocalAuthorityKey {
    fn for_admission(admission: &Admission) -> Self {
        Self {
            scope: admission.scope(),
            key_digest: admission.key().digest(),
            roster_id: admission.roster_id(),
            admission_commitment: admission.body_commitment(),
        }
    }
}

struct LocalAuthorityEntry {
    /// `None` is a pre-mutation reservation. It is installed before PollAdmit
    /// and deliberately survives cancellation or OutcomeUnknown so a durable
    /// success can always be recovered without a second remote mutation.
    registration: Option<BackendRegistration>,
    authority: AuthorityBinding,
    /// This is incremented before replacing a lower-fence permit. It is a
    /// process-local revocation generation and is never caller supplied.
    generation: u64,
}

/// Exact process-local admission capacity reserved before PollAdmit.
///
/// Dropping this token never releases its ledger row: cancellation is an
/// ambiguity boundary. Only an explicit NotTransmitted or deterministic
/// backend rejection calls the exact release path.
struct LocalAdmissionReservation {
    key: LocalAuthorityKey,
    authority: AuthorityBinding,
    generation: u64,
}

/// Non-forgeable process-local capability attached only to a [`Registration`]
/// or reconstructed from an SDK-issued established publication capsule.
///
/// The fields stay private so callers cannot attach a current generation to an
/// arbitrary body, owner, fence, or provider result.
#[derive(Clone)]
pub(crate) struct LocalAuthorityPermit {
    key: LocalAuthorityKey,
    registration: BackendRegistration,
    authority: AuthorityBinding,
    generation: u64,
}

impl fmt::Debug for LocalAuthorityPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalAuthorityPermit(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LocalAuthorityCheck {
    Current,
    RevokedOrExpired,
}

impl LocalAuthorityRegistry {
    pub(crate) fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            inner: Arc::new(LocalAuthorityRegistryInner {
                clock,
                entries: std::array::from_fn(|_| Mutex::new(HashMap::new())),
                entry_count: AtomicUsize::new(0),
                expiry_sweep_cursor: AtomicUsize::new(0),
            }),
        }
    }

    /// Reserve the exact local authority row before any PollAdmit byte can be
    /// transmitted. A full or contended ledger therefore fails before the
    /// remote mutation boundary, never after a durable admission.
    fn reserve_admission(
        &self,
        request: &RegistrationRequest,
    ) -> Result<LocalAdmissionReservation, ExecutorError> {
        let key = LocalAuthorityKey::for_admission(request.admission());
        let mut entries = self
            .lock_entries(&key)
            .map_err(|_| ExecutorError::AuthorityRejected)?;
        self.prune_expired_locked(&mut entries);
        if let Some(entry) = entries.get(&key) {
            return if entry.authority == *request.authority() {
                Err(ExecutorError::RecoveryRequired)
            } else {
                Err(ExecutorError::AuthorityRejected)
            };
        }
        if !self.reserve_entry() {
            return Err(ExecutorError::ExecutorBusy);
        }
        let generation = 1;
        entries.insert(
            key,
            LocalAuthorityEntry {
                registration: None,
                authority: request.authority().clone(),
                generation,
            },
        );
        Ok(LocalAdmissionReservation {
            key,
            authority: request.authority().clone(),
            generation,
        })
    }

    /// Convert a pre-mutation reservation after a backend-issued durable
    /// registration. This uses the short blocking shard lock because failure
    /// is no longer an admissible outcome after FreshlyAdmitted. No network or
    /// provider operation ever runs while this lock is held.
    fn finalize_admission(
        &self,
        reservation: LocalAdmissionReservation,
        registration: BackendRegistration,
        admission: &Admission,
    ) -> Result<LocalAuthorityPermit, ExecutorError> {
        registration.validate_for(admission)?;
        let key = LocalAuthorityKey::for_admission(admission);
        if key != reservation.key {
            return Err(ExecutorError::InvalidRegistration);
        }
        let mut entries = self.lock_entries_after_durable_read(&key);
        self.prune_expired_locked(&mut entries);
        let entry = entries
            .get_mut(&key)
            .ok_or(ExecutorError::AdmissionOutcomeUnknown)?;
        if entry.authority != reservation.authority
            || entry.generation != reservation.generation
            || !self.current_at(&entry.authority)
            || entry
                .registration
                .is_some_and(|retained| retained != registration)
        {
            return Err(ExecutorError::AdmissionOutcomeUnknown);
        }
        entry.registration = Some(registration);
        Ok(LocalAuthorityPermit {
            key,
            registration,
            authority: reservation.authority,
            generation: reservation.generation,
        })
    }

    /// Install or finalize the exact original authority after read-only
    /// admission status. This path cannot fail merely because another short
    /// authority operation currently owns the same fixed shard.
    fn install_admission(
        &self,
        registration: BackendRegistration,
        admission: &Admission,
        authority: &AuthorityBinding,
    ) -> Result<LocalAuthorityPermit, ExecutorError> {
        registration.validate_for(admission)?;
        let key = LocalAuthorityKey::for_admission(admission);
        let mut entries = self.lock_entries_after_durable_read(&key);
        self.prune_expired_locked(&mut entries);
        if let Some(entry) = entries.get_mut(&key) {
            if entry.authority != *authority
                || entry
                    .registration
                    .is_some_and(|retained| retained != registration)
                || !self.current_at(&entry.authority)
            {
                return Err(ExecutorError::AuthorityRejected);
            }
            entry.registration = Some(registration);
            return Ok(LocalAuthorityPermit {
                key,
                registration,
                authority: authority.clone(),
                generation: entry.generation,
            });
        }
        if !self.reserve_entry() {
            return Err(ExecutorError::ExecutorBusy);
        }
        let generation = 1;
        entries.insert(
            key,
            LocalAuthorityEntry {
                registration: Some(registration),
                authority: authority.clone(),
                generation,
            },
        );
        Ok(LocalAuthorityPermit {
            key,
            registration,
            authority: authority.clone(),
            generation,
        })
    }

    fn release_admission_reservation(&self, reservation: &LocalAdmissionReservation) {
        let mut entries = self.lock_entries_after_durable_read(&reservation.key);
        self.prune_expired_locked(&mut entries);
        let removable = entries.get(&reservation.key).is_some_and(|entry| {
            entry.registration.is_none()
                && entry.authority == reservation.authority
                && entry.generation == reservation.generation
        });
        if removable {
            entries.remove(&reservation.key);
            self.inner.entry_count.fetch_sub(1, Ordering::AcqRel);
        }
    }

    fn install_successor(
        &self,
        registration: BackendRegistration,
        admission: &Admission,
        authority: &AuthorityBinding,
    ) -> Result<LocalAuthorityPermit, ExecutorError> {
        let key = LocalAuthorityKey::for_admission(admission);
        let mut entries = self.lock_entries_after_durable_read(&key);
        self.prune_expired_locked(&mut entries);
        if let Some(entry) = entries.get_mut(&key) {
            match authority.fence().cmp(&entry.authority.fence()) {
                std::cmp::Ordering::Less => return Err(ExecutorError::AuthorityRejected),
                std::cmp::Ordering::Equal => {
                    if entry.authority != *authority
                        || entry
                            .registration
                            .is_some_and(|retained| retained != registration)
                    {
                        return Err(ExecutorError::AuthorityRejected);
                    }
                    entry.registration = Some(registration);
                    return Ok(LocalAuthorityPermit {
                        key,
                        registration,
                        authority: authority.clone(),
                        generation: entry.generation,
                    });
                }
                std::cmp::Ordering::Greater => {
                    entry.generation = entry
                        .generation
                        .checked_add(1)
                        .ok_or(ExecutorError::AuthorityRejected)?;
                    entry.registration = Some(registration);
                    entry.authority = authority.clone();
                    return Ok(LocalAuthorityPermit {
                        key,
                        registration,
                        authority: authority.clone(),
                        generation: entry.generation,
                    });
                }
            }
        }
        if !self.reserve_entry() {
            return Err(ExecutorError::ExecutorBusy);
        }
        let generation = 1;
        entries.insert(
            key,
            LocalAuthorityEntry {
                registration: Some(registration),
                authority: authority.clone(),
                generation,
            },
        );
        Ok(LocalAuthorityPermit {
            key,
            registration,
            authority: authority.clone(),
            generation,
        })
    }

    fn check(&self, permit: &LocalAuthorityPermit) -> LocalAuthorityCheck {
        let mut entries = match self.lock_entries(&permit.key) {
            Ok(entries) => entries,
            Err(_) => return LocalAuthorityCheck::RevokedOrExpired,
        };
        self.prune_expired_locked(&mut entries);
        if self.is_current_locked(&entries, permit) {
            LocalAuthorityCheck::Current
        } else {
            LocalAuthorityCheck::RevokedOrExpired
        }
    }

    /// Hold the exact authority shard while committing the local post-provider
    /// state and constructing any proof/ACK. A successor cannot revoke the
    /// permit in the gap between a successful postcheck and that local
    /// transition; contention is fail-closed because `lock_entries` uses
    /// `try_lock`.
    fn linearize_current<T>(
        &self,
        permit: &LocalAuthorityPermit,
        complete: impl FnOnce() -> Result<T, ExecutorError>,
    ) -> Result<T, ExecutorError> {
        let mut entries = self
            .lock_entries(&permit.key)
            .map_err(|_| ExecutorError::OutcomeUnknown)?;
        self.prune_expired_locked(&mut entries);
        if !self.is_current_locked(&entries, permit) {
            return Err(ExecutorError::OutcomeUnknown);
        }
        complete()
    }

    fn is_current_locked(
        &self,
        entries: &HashMap<LocalAuthorityKey, LocalAuthorityEntry>,
        permit: &LocalAuthorityPermit,
    ) -> bool {
        let Some(entry) = entries.get(&permit.key) else {
            return false;
        };
        entry.registration == Some(permit.registration)
            && entry.authority == permit.authority
            && entry.generation == permit.generation
            && self.current_at(&entry.authority)
    }

    /// Release a terminal capability that can no longer authorize any local
    /// effect. Aborted receipts use this immediately; Established retains its
    /// entry until a provider-validated publication acknowledgement.
    fn release_terminal_permit(&self, permit: &LocalAuthorityPermit) {
        let mut entries = self.lock_entries_after_durable_read(&permit.key);
        self.prune_expired_locked(&mut entries);
        if self.is_current_locked(&entries, permit) {
            entries.remove(&permit.key);
            self.inner.entry_count.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Reconstruct a permit only after comparing the complete SDK-issued
    /// established publication identity to a locally installed authority.
    /// This does not consult consensus and cannot mint a publication proof.
    pub(crate) fn permit_for_publication(
        &self,
        call: &EstablishedPublicationCall<'_>,
    ) -> Result<LocalAuthorityPermit, ()> {
        let publication = call.authority();
        let current = publication.current_authority();
        let key = LocalAuthorityKey {
            scope: current.scope(),
            key_digest: current.key().digest(),
            roster_id: publication.roster_id(),
            admission_commitment: publication.admission_commitment(),
        };
        let mut entries = self.lock_entries(&key).map_err(|_| ())?;
        self.prune_expired_locked(&mut entries);
        let entry = entries.get(&key).ok_or(())?;
        if entry.registration != Some(publication.current_registration())
            || entry.authority != *current
            || call.roster_id() != publication.roster_id()
            || call.admission_commitment() != publication.admission_commitment()
            || call.terminal_body_commitment() != publication.terminal_body_commitment()
            || call.receipt_commitment() != publication.receipt_commitment()
            || call.current_fence() != current.fence()
            || !self.current_at(&entry.authority)
        {
            return Err(());
        }
        Ok(LocalAuthorityPermit {
            key,
            registration: publication.current_registration(),
            authority: entry.authority.clone(),
            generation: entry.generation,
        })
    }

    /// Hold the exact publication authority shard while accepting provider
    /// evidence into an ACK. A successor cannot revoke the capability in the
    /// gap between the post-provider check and that acknowledgement.
    pub(crate) fn linearize_publication<T>(
        &self,
        call: &EstablishedPublicationCall<'_>,
        complete: impl FnOnce() -> Result<T, ()>,
    ) -> Result<T, ()> {
        let publication = call.authority();
        let current = publication.current_authority();
        let key = LocalAuthorityKey {
            scope: current.scope(),
            key_digest: current.key().digest(),
            roster_id: publication.roster_id(),
            admission_commitment: publication.admission_commitment(),
        };
        let mut entries = self.lock_entries(&key)?;
        self.prune_expired_locked(&mut entries);
        let entry = entries.get(&key).ok_or(())?;
        if entry.registration != Some(publication.current_registration())
            || entry.authority != *current
            || call.roster_id() != publication.roster_id()
            || call.admission_commitment() != publication.admission_commitment()
            || call.terminal_body_commitment() != publication.terminal_body_commitment()
            || call.receipt_commitment() != publication.receipt_commitment()
            || call.current_fence() != current.fence()
            || !self.current_at(&entry.authority)
        {
            return Err(());
        }
        let value = complete()?;
        entries.remove(&key).ok_or(())?;
        self.inner.entry_count.fetch_sub(1, Ordering::AcqRel);
        Ok(value)
    }

    fn current_at(&self, authority: &AuthorityBinding) -> bool {
        let now = self.inner.clock.now_utc();
        authority.acquired_at() <= now && now < authority.expires_at()
    }

    fn prune_expired_locked(&self, entries: &mut HashMap<LocalAuthorityKey, LocalAuthorityEntry>) {
        let now = self.inner.clock.now_utc();
        let before = entries.len();
        entries.retain(|_, entry| now < entry.authority.expires_at());
        let removed = before.saturating_sub(entries.len());
        if removed != 0 {
            self.inner.entry_count.fetch_sub(removed, Ordering::AcqRel);
        }
    }

    fn lock_entries(
        &self,
        key: &LocalAuthorityKey,
    ) -> Result<MutexGuard<'_, HashMap<LocalAuthorityKey, LocalAuthorityEntry>>, ()> {
        // Authority gating is fail-closed and never queues an unrelated
        // provider task behind a contended shard. Callers map contention to a
        // bounded retryable executor failure before provider I/O.
        self.inner.entries[self.shard_index(key)]
            .try_lock()
            .map_err(|_| ())
    }

    /// Post-consensus readback/commit conversion cannot report a false local
    /// failure. These critical sections contain no await, provider call, or
    /// user callback, and recover a poisoned lock without exposing internals.
    fn lock_entries_after_durable_read(
        &self,
        key: &LocalAuthorityKey,
    ) -> MutexGuard<'_, HashMap<LocalAuthorityKey, LocalAuthorityEntry>> {
        self.inner.entries[self.shard_index(key)]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn shard_index(&self, key: &LocalAuthorityKey) -> usize {
        // Every component is an immutable binding commitment. This does not
        // inspect caller-controlled display text or any mutable lease field.
        usize::from(key.key_digest[0] ^ key.admission_commitment[0]) & (LOCAL_AUTHORITY_SHARDS - 1)
    }

    fn reserve_entry(&self) -> bool {
        if self
            .inner
            .entry_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_LOCAL_AUTHORITY_ENTRIES).then_some(count + 1)
            })
            .is_ok()
        {
            return true;
        }
        // A full entry total can include expired bindings in unrelated
        // shards. Sweep every fixed shard in a rotating order, never waiting
        // for a contended one, then reserve once more. This preserves the
        // aggregate hard cap while ensuring an old tenant shard cannot
        // permanently consume the process-wide allowance.
        self.sweep_expired_all_shards();
        self.inner
            .entry_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_LOCAL_AUTHORITY_ENTRIES).then_some(count + 1)
            })
            .is_ok()
    }

    fn sweep_expired_all_shards(&self) {
        let start = self
            .inner
            .expiry_sweep_cursor
            .fetch_add(1, Ordering::Relaxed)
            & (LOCAL_AUTHORITY_SHARDS - 1);
        for offset in 0..LOCAL_AUTHORITY_SHARDS {
            let index = (start + offset) & (LOCAL_AUTHORITY_SHARDS - 1);
            if let Ok(mut entries) = self.inner.entries[index].try_lock() {
                self.prune_expired_locked(&mut entries);
            }
        }
    }
}

impl fmt::Debug for LocalAuthorityRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalAuthorityRegistry(<redacted>)")
    }
}

/// Registration input for the startup-owned executor.
#[derive(Clone)]
pub(crate) struct RegistrationRequest {
    admission: Arc<Admission>,
    authority: AuthorityBinding,
}

impl RegistrationRequest {
    /// Legacy test constructor with a positive synthetic lease window.
    #[cfg(test)]
    pub(crate) fn new(
        admission: Admission,
        owner: OwnerId,
        fence: FenceToken,
        credential_id: u64,
        generation: Generation,
    ) -> Result<Self, ExecutorError> {
        let issued_at = Timestamp::now_utc()
            .add_seconds(-1)
            .ok_or(ExecutorError::InvalidRegistration)?;
        Self::new_with_lease_metadata(
            admission,
            owner,
            fence,
            credential_id,
            generation,
            issued_at,
            issued_at
                .add_seconds(60)
                .ok_or(ExecutorError::InvalidRegistration)?,
        )
    }

    /// Bind immutable admission bytes to the complete lease credential.
    pub(crate) fn new_with_lease_metadata(
        admission: Admission,
        owner: OwnerId,
        fence: FenceToken,
        credential_id: u64,
        generation: Generation,
        acquired_at: Timestamp,
        expires_at: Timestamp,
    ) -> Result<Self, ExecutorError> {
        let admission = Arc::new(admission);
        let authority = AuthorityBinding::for_admission(
            &admission,
            owner,
            fence,
            credential_id,
            generation,
            acquired_at,
            expires_at,
        )?;
        Ok(Self {
            admission,
            authority,
        })
    }

    /// Exact immutable admission that must be persisted atomically by registration.
    pub(crate) fn admission(&self) -> &Admission {
        &self.admission
    }

    /// Exact authorization values which the durable backend must bind.
    pub(crate) fn authority(&self) -> &AuthorityBinding {
        &self.authority
    }
}

impl fmt::Debug for RegistrationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RegistrationRequest(<redacted>)")
    }
}

/// Read-only exact-admission lookup after an ambiguous register reply.
///
/// Unlike successor recovery, this carries the original canonical admission
/// and original authority binding.  It can therefore only read back the
/// exact request that may have crossed the register boundary.
pub(crate) struct AdmissionStatusRequest<'a> {
    registration: &'a RegistrationRequest,
}

impl AdmissionStatusRequest<'_> {
    pub(crate) fn registration(&self) -> &RegistrationRequest {
        self.registration
    }
}

impl fmt::Debug for AdmissionStatusRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdmissionStatusRequest(<redacted>)")
    }
}

/// Stable durable lookup key for recovery of one exact immutable admission.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RecoveryLookup {
    scope: Scope,
    roster_id: super::canonical::RosterId,
}

impl RecoveryLookup {
    pub(crate) fn new(scope: Scope, roster_id: super::canonical::RosterId) -> Self {
        Self { scope, roster_id }
    }

    /// Exact least-authority scope for the durable lookup.
    pub(crate) const fn scope(&self) -> Scope {
        self.scope
    }

    /// Stable caller-owned roster identity.
    pub(crate) const fn roster_id(&self) -> super::canonical::RosterId {
        self.roster_id
    }
}

impl fmt::Debug for RecoveryLookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryLookup(<redacted>)")
    }
}

/// Successor-takeover input which retains one already-admitted exact body.
#[derive(Clone)]
pub(crate) struct RecoveryRequest {
    lookup: RecoveryLookup,
    authority: AuthorityBinding,
}

impl RecoveryRequest {
    #[cfg(test)]
    pub(crate) fn new(
        scope: Scope,
        roster_id: super::canonical::RosterId,
        key: SessionKey,
        owner: OwnerId,
        fence: FenceToken,
        credential_id: u64,
        generation: Generation,
    ) -> Result<Self, ExecutorError> {
        let issued_at = Timestamp::now_utc()
            .add_seconds(-1)
            .ok_or(ExecutorError::InvalidRegistration)?;
        Self::new_with_lease_metadata(
            RecoveryLookup::new(scope, roster_id),
            key,
            owner,
            fence,
            credential_id,
            generation,
            LeaseMetadata::new(
                issued_at,
                issued_at
                    .add_seconds(60)
                    .ok_or(ExecutorError::InvalidRegistration)?,
            ),
        )
    }

    pub(crate) fn new_with_lease_metadata(
        lookup: RecoveryLookup,
        key: SessionKey,
        owner: OwnerId,
        fence: FenceToken,
        credential_id: u64,
        generation: Generation,
        lease: LeaseMetadata,
    ) -> Result<Self, ExecutorError> {
        Ok(Self {
            lookup,
            authority: AuthorityBinding::for_recovery(
                lookup.scope(),
                key,
                owner,
                fence,
                credential_id,
                generation,
                lease,
            )?,
        })
    }

    /// Stable durable lookup key; no prior in-memory capability is required.
    pub(crate) const fn lookup(&self) -> RecoveryLookup {
        self.lookup
    }

    /// Current successor authority the backend must validate exactly.
    pub(crate) fn authority(&self) -> &AuthorityBinding {
        &self.authority
    }
}

impl fmt::Debug for RecoveryRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryRequest(<redacted>)")
    }
}

/// Backend-issued opaque registration handle.
///
/// Its crate-private constructor is intentionally available only to the
/// durable server/backend side of this crate.  It is never caller-minted and
/// its bytes are never rendered in diagnostics.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct BackendRegistration {
    handle: [u8; 32],
    request_id: RequestId,
    terminal_slot_id: TerminalSlotId,
}

impl BackendRegistration {
    /// Issue a nonzero opaque registration handle after durable admission.
    pub(crate) fn issue(
        bytes: [u8; 32],
        request_id: RequestId,
        admission: &Admission,
    ) -> Result<Self, ExecutorError> {
        if bytes == [0; 32]
            || admission.profile().validate().is_err()
            || admission.protected_plan().len() > MAX_PLAN_BYTES
        {
            return Err(ExecutorError::InvalidRegistration);
        }
        request_id
            .validate_for(admission)
            .map_err(|_| ExecutorError::InvalidRegistration)?;
        let terminal_slot_id = request_id
            .terminal_slot_id(admission)
            .map_err(|_| ExecutorError::InvalidRegistration)?;
        Ok(Self {
            handle: bytes,
            request_id,
            terminal_slot_id,
        })
    }

    /// Rehydrate an opaque registration retained in consensus state.
    pub(crate) fn from_consensus_parts(
        handle: [u8; 32],
        request_id: RequestId,
        admission: &Admission,
    ) -> Result<Self, ExecutorError> {
        Self::issue(handle, request_id, admission)
    }

    /// Return the exact opaque handle, request identity, and terminal slot for
    /// bounded consensus encoding. These values never enter diagnostics.
    pub(crate) const fn consensus_parts(self) -> ([u8; 32], RequestId, TerminalSlotId) {
        (self.handle, self.request_id, self.terminal_slot_id)
    }

    fn request_id(self) -> RequestId {
        self.request_id
    }

    fn terminal_slot_id(self) -> TerminalSlotId {
        self.terminal_slot_id
    }

    fn validate_for(self, admission: &Admission) -> Result<(), ExecutorError> {
        self.request_id
            .validate_for(admission)
            .map_err(|_| ExecutorError::InvalidRegistration)?;
        if self.terminal_slot_id
            != self
                .request_id
                .terminal_slot_id(admission)
                .map_err(|_| ExecutorError::InvalidRegistration)?
        {
            return Err(ExecutorError::InvalidRegistration);
        }
        Ok(())
    }
}

impl fmt::Debug for BackendRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BackendRegistration(<redacted>)")
    }
}

/// Authenticated opaque capability returned only after durable registration.
///
/// It has no public constructor, carries no provider reference, and cannot be
/// converted into an applied proof by callers.
pub(crate) struct Registration {
    backend_registration: BackendRegistration,
    admission: Arc<Admission>,
    authority: AuthorityBinding,
    authority_permit: LocalAuthorityPermit,
    local: Arc<Mutex<LocalExecutionState>>,
    member_calls: Vec<Arc<AsyncMutex<()>>>,
}

impl Registration {
    fn issue(
        request: RegistrationRequest,
        backend_registration: BackendRegistration,
        reservation: LocalAdmissionReservation,
        local_authority: &LocalAuthorityRegistry,
    ) -> Result<Self, ExecutorError> {
        backend_registration.validate_for(&request.admission)?;
        let member_calls = member_call_guards(&request.admission);
        let authority_permit = local_authority.finalize_admission(
            reservation,
            backend_registration,
            &request.admission,
        )?;
        Ok(Self {
            backend_registration,
            local: LocalExecutionState::fresh(&request.admission),
            admission: request.admission,
            authority: request.authority,
            authority_permit,
            member_calls,
        })
    }

    /// Immutable admission protected by this opaque capability.
    pub(crate) fn admission(&self) -> &Admission {
        &self.admission
    }

    fn backend_registration(&self) -> BackendRegistration {
        self.backend_registration
    }

    fn authority(&self) -> &AuthorityBinding {
        &self.authority
    }

    fn recover(
        request: RecoveryRequest,
        admission: Arc<Admission>,
        backend_registration: BackendRegistration,
        local_authority: &LocalAuthorityRegistry,
    ) -> Result<Self, ExecutorError> {
        backend_registration.validate_for(&admission)?;
        let member_calls = member_call_guards(&admission);
        let authority_permit = local_authority.install_successor(
            backend_registration,
            &admission,
            &request.authority,
        )?;
        Ok(Self {
            backend_registration,
            local: LocalExecutionState::recovered(&admission),
            admission,
            authority: request.authority,
            authority_permit,
            member_calls,
        })
    }

    /// Rehydrate an exact original admission after a lost admission reply.
    /// The original guard remains authenticated, but provider state is never
    /// assumed: all members begin status/adopt-only.
    fn readback(
        request: RegistrationRequest,
        backend_registration: BackendRegistration,
        local_authority: &LocalAuthorityRegistry,
    ) -> Result<Self, ExecutorError> {
        backend_registration.validate_for(&request.admission)?;
        let member_calls = member_call_guards(&request.admission);
        let authority_permit = local_authority.install_admission(
            backend_registration,
            &request.admission,
            &request.authority,
        )?;
        Ok(Self {
            backend_registration,
            local: LocalExecutionState::recovered(&request.admission),
            admission: request.admission,
            authority: request.authority,
            authority_permit,
            member_calls,
        })
    }
}

fn member_call_guards(admission: &Admission) -> Vec<Arc<AsyncMutex<()>>> {
    (0..admission.members().len())
        .map(|_| Arc::new(AsyncMutex::new(())))
        .collect()
}

impl fmt::Debug for Registration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Registration(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LocalAttempt {
    ReadyToPrepare,
    ReadyToExecute,
    OutcomeUnknown,
    Conclusive,
}

impl LocalAttempt {
    fn permits(self, operation: ProviderOperation) -> bool {
        match operation {
            ProviderOperation::Prepare => self == Self::ReadyToPrepare,
            ProviderOperation::Execute => self == Self::ReadyToExecute,
            // Status is always safe and is the sole operation that can recover
            // a durable pre-effect stage after process loss.
            ProviderOperation::Status => true,
            ProviderOperation::Adopt => {
                matches!(self, Self::OutcomeUnknown | Self::Conclusive)
            }
            ProviderOperation::Compensate => self == Self::Conclusive,
        }
    }
}

struct LocalExecutionState {
    attempts: Vec<LocalAttempt>,
    proof_epochs: Vec<u64>,
    first_conclusive: Vec<Option<ConclusiveObservation>>,
    compensations: Vec<Option<ConclusiveObservation>>,
    // Recovery intentionally begins without SDK-local proof history. This
    // marker permits Status/Adopt to reconstruct a provider-durable final
    // compensation, but never authorizes a new direct compensation.
    recovered_members: Vec<bool>,
    terminal: LocalTerminalState,
}

#[derive(Clone, PartialEq, Eq)]
struct ConclusiveObservation {
    outcome: ProviderOutcome,
    evidence_commitment: [u8; 32],
    // The provider's canonical conclusive evidence is part of the terminal
    // attestation, not merely an input to a commitment. Retain it privately
    // so terminal preparation can sign the exact observed bytes and reject a
    // later same-commitment-but-different-byte provider response.
    evidence: Vec<u8>,
}

enum LocalTerminalState {
    Open,
    /// A locally prepared body has not crossed the terminal transport.
    Prepared,
    /// A terminalization request may have crossed transport. Its exact outcome
    /// is recoverable only through read-only terminal status.
    StatusOnly,
}

impl LocalTerminalState {
    fn is_locked(&self) -> bool {
        !matches!(self, Self::Open)
    }

    fn may_terminalize(&self) -> bool {
        matches!(self, Self::Prepared)
    }
}

impl LocalExecutionState {
    fn fresh(admission: &Admission) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            attempts: vec![LocalAttempt::ReadyToPrepare; admission.members().len()],
            proof_epochs: vec![0; admission.members().len()],
            first_conclusive: vec![None; admission.members().len()],
            compensations: vec![None; admission.members().len()],
            recovered_members: vec![false; admission.members().len()],
            terminal: LocalTerminalState::Open,
        }))
    }

    fn recovered(admission: &Admission) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            attempts: vec![LocalAttempt::OutcomeUnknown; admission.members().len()],
            proof_epochs: vec![0; admission.members().len()],
            first_conclusive: vec![None; admission.members().len()],
            compensations: vec![None; admission.members().len()],
            recovered_members: vec![true; admission.members().len()],
            terminal: LocalTerminalState::Open,
        }))
    }

    /// Permit a provider-side compensation only after this executor has a
    /// complete, conclusive local view of the roster and that view is already
    /// irreversibly aborting. This prevents a single Applied member from
    /// reconstructively changing an otherwise Established terminal into an
    /// Aborted one. The provider remains the durable source of each stable
    /// member observation; this mutex only serializes the local decision made
    /// before compensation I/O.
    fn permits_compensation(&self, ordinal: usize) -> bool {
        let target_is_uncompensated_applied =
            matches!(
                self.first_conclusive.get(ordinal).and_then(Option::as_ref),
                Some(ConclusiveObservation {
                    outcome: ProviderOutcome::AppliedExecuted | ProviderOutcome::AppliedAdopted,
                    ..
                })
            ) && matches!(self.compensations.get(ordinal), Some(None));
        if !target_is_uncompensated_applied {
            return false;
        }

        let mut abort_locked = false;
        for ordinal in 0..self.attempts.len() {
            let Some(observation) = self
                .compensations
                .get(ordinal)
                .and_then(Option::as_ref)
                .or_else(|| self.first_conclusive.get(ordinal).and_then(Option::as_ref))
            else {
                return false;
            };
            abort_locked |= matches!(
                observation.outcome,
                ProviderOutcome::NotAppliedReconciled | ProviderOutcome::CompensatedReconciled
            );
        }
        abort_locked
    }
}

/// Durable backend rejection without provider, tenant, or credential detail.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum BackendRejection {
    /// Any exact authority binding component was stale or cross-scoped.
    Authority,
    /// Another execution would be a blind replay.
    RecoveryRequired,
    /// A different terminal body conflicts with the persisted lock.
    TerminalConflict,
    /// Admission found no exact present protected business record.
    RecordMissing,
    /// Admission found a different protected business generation.
    GenerationConflict,
    /// Admission cannot produce a checked successor generation for Put.
    GenerationExhausted,
    /// A live admission already reserves the exact protected business key.
    BusinessKeyReserved,
    /// The proposed protected checkpoint cannot become the authoritative record.
    InvalidProtectedCheckpoint,
    /// Aggregate reservation for admission plus retained terminal data is full.
    AggregateBytesFull,
    /// The bounded live-roster reservation is full.
    LiveFull,
    /// The bounded retained-history reservation is full.
    HistoryFull,
}

impl From<BackendRejection> for ExecutorError {
    fn from(value: BackendRejection) -> Self {
        match value {
            BackendRejection::Authority => Self::AuthorityRejected,
            BackendRejection::RecoveryRequired => Self::RecoveryRequired,
            BackendRejection::TerminalConflict => Self::TerminalConflict,
            BackendRejection::RecordMissing => Self::AdmissionRecordMissing,
            BackendRejection::GenerationConflict => Self::AdmissionGenerationConflict,
            BackendRejection::GenerationExhausted => Self::AdmissionGenerationExhausted,
            BackendRejection::BusinessKeyReserved => Self::AdmissionBusinessKeyReserved,
            BackendRejection::InvalidProtectedCheckpoint => {
                Self::AdmissionInvalidProtectedCheckpoint
            }
            BackendRejection::AggregateBytesFull => Self::AdmissionAggregateBytesFull,
            BackendRejection::LiveFull => Self::AdmissionLiveFull,
            BackendRejection::HistoryFull => Self::AdmissionHistoryFull,
        }
    }
}

/// Atomic result of durable registration-time authentication.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum RegistrationDecision {
    /// The immutable admission was durably created by this exact mutation.
    FreshlyAdmitted(BackendRegistration),
    /// The same immutable admission already exists and requires recovery flow.
    AdmissionReplayed,
    /// The backend proved that no admission request byte crossed transport.
    NotTransmitted,
    /// A read-only successor lookup returned a nonterminal retained body.
    PollAdmitted {
        registration: BackendRegistration,
        admission: Arc<Admission>,
    },
    /// A read-only successor lookup returned an exact committed terminal row.
    Terminal {
        /// Current higher-fence handle for the exact retained request identity.
        registration: BackendRegistration,
        /// Consensus-retained immutable admission bytes.
        admission: Arc<Admission>,
        /// Consensus-retained atomic terminal receipt and business mutation.
        committed: Box<CommittedTerminal>,
    },
    /// A read-only successor lookup found only the exact conflict tombstone.
    Compacted {
        /// History epoch needed to validate the exact compact binding.
        history_epoch: u64,
        /// Bounded terminal conflict/status metadata with no protected payload.
        tombstone: TerminalConflictTombstone,
    },
    /// Registration was rejected before any provider effect.
    Reject(BackendRejection),
}

/// Read-only recovery result for a new process or pod.
#[derive(Debug)]
pub(crate) enum RecoveryResult {
    /// Provider-side member state is ambiguous after process loss.
    PollAdmitted(Box<PollAdmittedRecovery>),
    /// The exact retained established terminal requires no provider call.
    Established(TerminalCommitReceipt),
    /// The exact retained aborted terminal requires no provider call.
    Aborted(TerminalCommitReceipt),
    /// The terminal payload aged out, but its irreversible phase and conflict
    /// commitment remain durable. This never contains publication authority.
    Compacted,
}

/// Recovery state for a nonterminal admitted roster.
#[derive(Debug)]
pub(crate) struct PollAdmittedRecovery {
    /// Current higher-fence capability for this exact admitted roster.
    pub(crate) registration: Registration,
}

/// Immutable exact metadata checked by every provider-validation operation.
#[derive(Clone, Copy)]
pub(crate) struct CallBinding<'a> {
    registration: BackendRegistration,
    admission: &'a Admission,
    authority: &'a AuthorityBinding,
    member: &'a Member,
    operation: ProviderOperation,
}

impl fmt::Debug for CallBinding<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CallBinding(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Observation {
    NotTransmitted,
    OutcomeUnknown,
    NotFound,
    Pending,
    ReadyToPrepare,
    PreparedNotRun,
    Conclusive {
        outcome: ProviderOutcome,
        evidence_commitment: [u8; 32],
        evidence: Vec<u8>,
    },
}

impl fmt::Debug for Observation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Observation(<redacted>)")
    }
}

/// An SDK-issued, non-caller-constructible conclusive provider proof.
///
/// It is intentionally module-private: callers can receive it only from an
/// executor call and can use it only by moving it into terminal preparation.
/// In particular, no API accepts a caller-authored `Applied` assertion.
#[derive(Clone)]
pub(crate) struct AppliedProof {
    registration: BackendRegistration,
    ordinal: u8,
    operation: ProviderOperation,
    outcome: ProviderOutcome,
    proof_epoch: u64,
    evidence_commitment: [u8; 32],
    evidence: Vec<u8>,
    binding_commitment: [u8; 32],
}

impl fmt::Debug for AppliedProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AppliedProof(<redacted>)")
    }
}

/// Result of an executor provider operation.
#[derive(Debug)]
pub(crate) enum CallResult {
    /// A conclusive proof issued only after post-call authority validation.
    Conclusive(Box<AppliedProof>),
    /// No request byte crossed the provider boundary.
    NotTransmitted,
    /// A provider effect may have crossed and must be recovered, not replayed.
    OutcomeUnknown,
    /// Non-exclusionary provider absence observation.
    NotFound,
    /// Provider state remains unresolved.
    Pending,
    /// Provider durably excludes preparation and execution under older fences.
    ReadyToPrepare,
    /// Provider durably retains the exact request and proves execution never began.
    PreparedNotRun,
}

impl CallResult {
    fn from_observation(
        observation: Observation,
        proof: Option<AppliedProof>,
    ) -> Result<Self, ExecutorError> {
        match (observation, proof) {
            (Observation::Conclusive { .. }, Some(proof)) => Ok(Self::Conclusive(Box::new(proof))),
            (Observation::NotTransmitted, None) => Ok(Self::NotTransmitted),
            (Observation::OutcomeUnknown, None) => Ok(Self::OutcomeUnknown),
            (Observation::NotFound, None) => Ok(Self::NotFound),
            (Observation::Pending, None) => Ok(Self::Pending),
            (Observation::ReadyToPrepare, None) => Ok(Self::ReadyToPrepare),
            (Observation::PreparedNotRun, None) => Ok(Self::PreparedNotRun),
            _ => Err(ExecutorError::InvalidProviderResponse),
        }
    }
}

/// Exact process-local prepared terminal body whose bytes feed terminalization.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TerminalBody {
    record: TerminalRecord,
    phase: Phase,
    // Only a locally prepared terminal carries its root-certified executor
    // evidence. Consensus retains the stable record alone after success.
    bundle: Option<RosterExecutorProofBundleV1>,
}

impl TerminalBody {
    fn build(
        registration: BackendRegistration,
        admission: &Admission,
        authority: &AuthorityBinding,
        proofs: &[AppliedProof],
    ) -> Result<Self, ExecutorError> {
        if proofs.len() != admission.members().len() {
            return Err(ExecutorError::InvalidTerminal);
        }

        let mut proof_commitments = Vec::with_capacity(proofs.len());
        let mut phase = None;
        for (index, proof) in proofs.iter().enumerate() {
            let expected_member = admission
                .members()
                .get(index)
                .ok_or(ExecutorError::InvalidTerminal)?;
            let binding = CallBinding {
                registration,
                admission,
                authority,
                member: expected_member,
                operation: proof.operation,
            };
            if proof.registration != registration
                || expected_member.ordinal() != index as u8
                || proof.ordinal != index as u8
                || evidence_commitment(&proof.evidence) != proof.evidence_commitment
                || proof.binding_commitment
                    != proof_binding_commitment(
                        &binding,
                        proof.outcome,
                        proof.proof_epoch,
                        proof.evidence_commitment,
                    )
            {
                return Err(ExecutorError::InvalidTerminal);
            }
            let proof_phase = match proof.outcome {
                ProviderOutcome::AppliedExecuted | ProviderOutcome::AppliedAdopted => {
                    Phase::Established
                }
                ProviderOutcome::NotAppliedReconciled | ProviderOutcome::CompensatedReconciled => {
                    Phase::Aborted
                }
            };
            if phase
                .replace(proof_phase)
                .is_some_and(|value| value != proof_phase)
            {
                return Err(ExecutorError::InvalidTerminal);
            }
            proof_commitments.push(stable_terminal_proof_commitment(
                registration,
                admission,
                expected_member,
                proof_phase,
                proof.outcome,
                proof.evidence_commitment,
            )?);
        }
        let phase = phase.ok_or(ExecutorError::InvalidTerminal)?;
        let record = TerminalRecord::new(
            admission,
            registration.request_id(),
            phase,
            proof_commitments,
        )
        .map_err(|_| ExecutorError::InvalidTerminal)?;
        Ok(Self {
            record,
            phase,
            bundle: None,
        })
    }

    /// Rehydrate a canonical terminal body retained by a durable backend.
    pub(crate) fn from_record(
        record: TerminalRecord,
        admission: &Admission,
    ) -> Result<Self, ExecutorError> {
        record
            .validate_for(admission)
            .map_err(|_| ExecutorError::InvalidTerminal)?;
        let phase = record.phase().map_err(|_| ExecutorError::InvalidTerminal)?;
        Ok(Self {
            record,
            phase,
            bundle: None,
        })
    }

    /// Chosen terminal phase.
    pub(crate) const fn phase(&self) -> Phase {
        self.phase
    }

    /// Exact protected checkpoint retained in the terminal body.
    #[cfg(test)]
    pub(crate) fn protected_checkpoint(&self) -> &[u8] {
        self.record.protected_checkpoint()
    }

    /// Exact pre-admitted terminal result.
    #[cfg(test)]
    pub(crate) fn protected_result(&self) -> &[u8] {
        self.record.protected_result()
    }

    /// Exact commitment the backend locks before commit.
    pub(crate) const fn commitment(&self) -> [u8; 32] {
        self.record.body_commitment()
    }

    /// Canonical domain terminal record persisted by the backend.
    pub(crate) fn record(&self) -> &TerminalRecord {
        &self.record
    }

    /// Exact bounded root-certified evidence carried only by a prepared
    /// terminal transport request.
    pub(crate) fn bundle(&self) -> Result<&RosterExecutorProofBundleV1, ExecutorError> {
        self.bundle.as_ref().ok_or(ExecutorError::InvalidTerminal)
    }

    fn with_bundle(mut self, bundle: RosterExecutorProofBundleV1) -> Self {
        self.bundle = Some(bundle);
        self
    }
}

impl fmt::Debug for TerminalBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TerminalBody(<redacted>)")
    }
}

/// Opaque SDK capability for submitting one process-local exact body.
///
/// Only a transport-proven `NotTransmitted` result permits another identical
/// submission; every possibly transmitted request becomes status-only.
#[derive(Clone)]
pub(crate) struct PreparedTerminal {
    registration: BackendRegistration,
    body: TerminalBody,
}

impl fmt::Debug for PreparedTerminal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedTerminal(<redacted>)")
    }
}

/// Canonical business materialization coupled to one committed terminal.
///
/// This is intentionally separate from [`TerminalBody`]. A body proves the
/// provider outcome to be terminal; this value proves what the same atomic
/// backend transaction did to the protected session state.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum TerminalMaterialization {
    /// An established roster atomically materialized its admitted mutation.
    Established(EstablishedMaterialization),
    /// An aborted roster atomically wrote only its terminal receipt.
    Aborted,
}

impl TerminalMaterialization {
    fn for_body(admission: &Admission, body: &TerminalBody) -> Result<Self, ExecutorError> {
        match body.phase() {
            Phase::Established => Ok(Self::Established(
                EstablishedMaterialization::for_admission(admission)?,
            )),
            Phase::Aborted => Ok(Self::Aborted),
        }
    }

    fn validate_for(
        &self,
        admission: &Admission,
        body: &TerminalBody,
    ) -> Result<(), ExecutorError> {
        if *self != Self::for_body(admission, body)? {
            return Err(ExecutorError::InvalidTerminal);
        }
        Ok(())
    }

    fn update_receipt_commitment(&self, hasher: &mut Sha256) {
        match self {
            Self::Established(materialization) => {
                hasher.update([1]);
                materialization.update_receipt_commitment(hasher);
            }
            Self::Aborted => hasher.update([2]),
        }
    }
}

impl fmt::Debug for TerminalMaterialization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TerminalMaterialization(<redacted>)")
    }
}

/// Exact session mutation written by an established terminal transaction.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum EstablishedMaterialization {
    /// The admitted checkpoint became the authoritative session record.
    Updated {
        /// Exact expected generation reserved by admission.
        from: Generation,
        /// Checked successor generation written by the transaction.
        to: Generation,
        /// Commitment to the immutable authoritative record header and bytes.
        record_commitment: [u8; 32],
    },
    /// The admitted present-generation record was deleted.
    Deleted {
        /// Exact generation deleted by the transaction.
        generation: Generation,
    },
    /// The transaction retained the admitted present-generation record.
    NoOp {
        /// Exact generation retained by the transaction.
        generation: Generation,
    },
}

impl EstablishedMaterialization {
    fn for_admission(admission: &Admission) -> Result<Self, ExecutorError> {
        let mutation = admission.established_mutation();
        if mutation == &super::canonical::EstablishedMutation::delete() {
            return Ok(Self::Deleted {
                generation: admission.expected_generation(),
            });
        }
        if mutation == &super::canonical::EstablishedMutation::no_op() {
            return Ok(Self::NoOp {
                generation: admission.expected_generation(),
            });
        }

        let state_type = mutation
            .state_type()
            .ok_or(ExecutorError::InvalidTerminal)?;
        let from = admission.expected_generation();
        let to = from.next().ok_or(ExecutorError::InvalidTerminal)?;
        Ok(Self::Updated {
            from,
            to,
            record_commitment: terminal_record_commitment(admission, to, state_type.as_str()),
        })
    }

    fn update_receipt_commitment(&self, hasher: &mut Sha256) {
        match self {
            Self::Updated {
                from,
                to,
                record_commitment,
            } => {
                hasher.update([1]);
                hasher.update(from.get().to_be_bytes());
                hasher.update(to.get().to_be_bytes());
                hasher.update(record_commitment);
            }
            Self::Deleted { generation } => {
                hasher.update([2]);
                hasher.update(generation.get().to_be_bytes());
            }
            Self::NoOp { generation } => {
                hasher.update([3]);
                hasher.update(generation.get().to_be_bytes());
            }
        }
    }
}

impl fmt::Debug for EstablishedMaterialization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EstablishedMaterialization(<redacted>)")
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
enum TerminalMaterializationWire {
    Updated {
        from: Generation,
        to: Generation,
        record_commitment: [u8; 32],
    },
    Deleted {
        generation: Generation,
    },
    NoOp {
        generation: Generation,
    },
    Aborted,
}

impl From<&TerminalMaterialization> for TerminalMaterializationWire {
    fn from(materialization: &TerminalMaterialization) -> Self {
        match materialization {
            TerminalMaterialization::Established(EstablishedMaterialization::Updated {
                from,
                to,
                record_commitment,
            }) => Self::Updated {
                from: *from,
                to: *to,
                record_commitment: *record_commitment,
            },
            TerminalMaterialization::Established(EstablishedMaterialization::Deleted {
                generation,
            }) => Self::Deleted {
                generation: *generation,
            },
            TerminalMaterialization::Established(EstablishedMaterialization::NoOp {
                generation,
            }) => Self::NoOp {
                generation: *generation,
            },
            TerminalMaterialization::Aborted => Self::Aborted,
        }
    }
}

impl From<TerminalMaterializationWire> for TerminalMaterialization {
    fn from(materialization: TerminalMaterializationWire) -> Self {
        match materialization {
            TerminalMaterializationWire::Updated {
                from,
                to,
                record_commitment,
            } => Self::Established(EstablishedMaterialization::Updated {
                from,
                to,
                record_commitment,
            }),
            TerminalMaterializationWire::Deleted { generation } => {
                Self::Established(EstablishedMaterialization::Deleted { generation })
            }
            TerminalMaterializationWire::NoOp { generation } => {
                Self::Established(EstablishedMaterialization::NoOp { generation })
            }
            TerminalMaterializationWire::Aborted => Self::Aborted,
        }
    }
}

/// Consensus-derived coordinates for the terminal linearization point.
///
/// The production adapter mints this value only from an applied quorum
/// response. Keeping construction crate-private prevents an SDK consumer from
/// choosing the retention clock, while embedding it in the committed terminal
/// frame makes restart, snapshot, and follower replay validate one exact
/// terminal timestamp rather than a separate mutable column.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsensusCommitMetadata {
    sequence: u64,
    raft_log_index: u64,
    committed_at: Timestamp,
}

impl ConsensusCommitMetadata {
    #[cfg(test)]
    pub(crate) fn issue(
        sequence: u64,
        raft_log_index: u64,
        committed_at: Timestamp,
    ) -> Result<Self, ExecutorError> {
        let value = Self {
            sequence,
            raft_log_index,
            committed_at,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(self) -> Result<(), ExecutorError> {
        if self.sequence == 0
            || self.raft_log_index == 0
            || self.committed_at.as_offset_datetime().unix_timestamp() < 0
        {
            return Err(ExecutorError::InvalidTerminal);
        }
        Ok(())
    }

    /// Validate that the consensus linearization occurred while the exact
    /// committing lease was live. A self-consistent old timestamp must never
    /// make a terminal immediately reclaimable or authenticate a stale guard.
    fn validate_for_authority(self, authority: &AuthorityBinding) -> Result<(), ExecutorError> {
        self.validate()?;
        if self.committed_at < authority.acquired_at()
            || self.committed_at >= authority.expires_at()
        {
            return Err(ExecutorError::InvalidTerminal);
        }
        Ok(())
    }

    fn update_commitment(self, hasher: &mut Sha256) {
        hasher.update(self.sequence.to_be_bytes());
        hasher.update(self.raft_log_index.to_be_bytes());
        hasher.update(
            self.committed_at
                .as_offset_datetime()
                .unix_timestamp_nanos()
                .to_be_bytes(),
        );
    }
}

impl fmt::Debug for ConsensusCommitMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConsensusCommitMetadata(<redacted>)")
    }
}

#[derive(Serialize)]
struct CommittedTerminalWireRef<'a> {
    record: &'a TerminalRecord,
    commit_metadata: ConsensusCommitMetadata,
    committing_registration_handle: [u8; 32],
    committing_registration_request_id: RequestId,
    committing_registration_terminal_slot_id: [u8; 32],
    committing_authority_scope: [u8; 32],
    committing_authority_key: &'a SessionKey,
    committing_authority_owner: &'a OwnerId,
    committing_authority_fence: FenceToken,
    committing_authority_credential_id: u64,
    committing_authority_generation: Generation,
    committing_authority_acquired_at: Timestamp,
    committing_authority_expires_at: Timestamp,
    committing_guard_commitment: [u8; 32],
    materialization: TerminalMaterializationWire,
    receipt_commitment: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct CommittedTerminalWire {
    record: TerminalRecord,
    commit_metadata: ConsensusCommitMetadata,
    committing_registration_handle: [u8; 32],
    committing_registration_request_id: RequestId,
    committing_registration_terminal_slot_id: [u8; 32],
    committing_authority_scope: [u8; 32],
    committing_authority_key: SessionKey,
    committing_authority_owner: OwnerId,
    committing_authority_fence: FenceToken,
    committing_authority_credential_id: u64,
    committing_authority_generation: Generation,
    committing_authority_acquired_at: Timestamp,
    committing_authority_expires_at: Timestamp,
    committing_guard_commitment: [u8; 32],
    materialization: TerminalMaterializationWire,
    receipt_commitment: [u8; 32],
}

/// Backend-issued result of the one atomic terminal transaction.
///
/// It binds the canonical terminal record, the guard that committed it, and
/// the business materialization into one receipt. The executor never mints
/// publication authority from a prepared body; it first validates this exact
/// stored composite against the current request.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CommittedTerminal {
    record: TerminalRecord,
    commit_metadata: ConsensusCommitMetadata,
    committing_registration: BackendRegistration,
    committing_authority: AuthorityBinding,
    committing_guard_commitment: [u8; 32],
    materialization: TerminalMaterialization,
    receipt_commitment: [u8; 32],
}

impl CommittedTerminal {
    /// Build the exact durable composite while the backend holds its terminal
    /// transaction lock. This is crate-private so production adapters can use
    /// the same contract without exposing a caller-side proof constructor.
    #[cfg(test)]
    pub(crate) fn issue(
        registration: BackendRegistration,
        admission: &Admission,
        authority: &AuthorityBinding,
        body: &TerminalBody,
        commit_metadata: ConsensusCommitMetadata,
    ) -> Result<Self, ExecutorError> {
        validate_terminal_request_shape(registration, admission, authority, body)?;
        commit_metadata.validate_for_authority(authority)?;
        let materialization = TerminalMaterialization::for_body(admission, body)?;
        let committing_guard_commitment =
            terminal_committing_guard_commitment(registration, admission, authority);
        let record = body.record().clone();
        let receipt_commitment = terminal_receipt_commitment(
            registration,
            admission,
            &record,
            authority.fence(),
            committing_guard_commitment,
            &materialization,
            commit_metadata,
        );
        Ok(Self {
            record,
            commit_metadata,
            committing_registration: registration,
            committing_authority: authority.clone(),
            committing_guard_commitment,
            materialization,
            receipt_commitment,
        })
    }

    /// Encode the exact historical terminal composite for consensus storage,
    /// snapshots, and cross-node replay. Protected bytes are copied verbatim
    /// from the committed terminal record; this path never reseals them.
    pub(crate) fn to_canonical_bytes(
        &self,
        admission: &Admission,
    ) -> Result<Vec<u8>, ExecutorError> {
        let body = TerminalBody::from_record(self.record.clone(), admission)?;
        self.validate_for_terminal_commit(
            self.committing_registration,
            admission,
            &self.committing_authority,
            &body,
        )?;
        let wire = CommittedTerminalWireRef {
            record: &self.record,
            commit_metadata: self.commit_metadata,
            committing_registration_handle: self.committing_registration.handle,
            committing_registration_request_id: self.committing_registration.request_id(),
            committing_registration_terminal_slot_id: *self
                .committing_registration
                .terminal_slot_id()
                .as_bytes(),
            committing_authority_scope: self.committing_authority.scope().digest(),
            committing_authority_key: self.committing_authority.key(),
            committing_authority_owner: self.committing_authority.owner(),
            committing_authority_fence: self.committing_authority.fence(),
            committing_authority_credential_id: self.committing_authority.credential_id(),
            committing_authority_generation: self.committing_authority.generation(),
            committing_authority_acquired_at: self.committing_authority.acquired_at(),
            committing_authority_expires_at: self.committing_authority.expires_at(),
            committing_guard_commitment: self.committing_guard_commitment,
            materialization: TerminalMaterializationWire::from(&self.materialization),
            receipt_commitment: self.receipt_commitment,
        };
        encode_frame(
            COMMITTED_TERMINAL_FRAME_MAGIC,
            COMMITTED_TERMINAL_FRAME_DOMAIN,
            &wire,
            MAX_COMMITTED_TERMINAL_CODEC_BYTES,
        )
        .map_err(|_| ExecutorError::InvalidTerminal)
    }

    /// Rehydrate and fully revalidate one exact consensus-retained terminal
    /// composite. The original committing guard remains historical provenance;
    /// a successor's current higher guard is validated separately on read.
    pub(crate) fn from_canonical_bytes(
        bytes: &[u8],
        admission: &Admission,
    ) -> Result<Self, ExecutorError> {
        let wire: CommittedTerminalWire = decode_frame(
            bytes,
            COMMITTED_TERMINAL_FRAME_MAGIC,
            COMMITTED_TERMINAL_FRAME_DOMAIN,
            MAX_COMMITTED_TERMINAL_CODEC_BYTES,
        )
        .map_err(|_| ExecutorError::InvalidTerminal)?;
        let committing_registration = BackendRegistration::issue(
            wire.committing_registration_handle,
            wire.committing_registration_request_id,
            admission,
        )?;
        wire.commit_metadata.validate()?;
        if wire.committing_registration_terminal_slot_id
            != *committing_registration.terminal_slot_id().as_bytes()
        {
            return Err(ExecutorError::InvalidTerminal);
        }
        let committing_authority = AuthorityBinding::for_recovery(
            Scope::from_digest(wire.committing_authority_scope),
            wire.committing_authority_key,
            wire.committing_authority_owner,
            wire.committing_authority_fence,
            wire.committing_authority_credential_id,
            wire.committing_authority_generation,
            LeaseMetadata::new(
                wire.committing_authority_acquired_at,
                wire.committing_authority_expires_at,
            ),
        )?;
        let value = Self {
            record: wire.record,
            commit_metadata: wire.commit_metadata,
            committing_registration,
            committing_authority,
            committing_guard_commitment: wire.committing_guard_commitment,
            materialization: wire.materialization.into(),
            receipt_commitment: wire.receipt_commitment,
        };
        let body = TerminalBody::from_record(value.record.clone(), admission)?;
        value.validate_for_terminal_commit(
            value.committing_registration,
            admission,
            &value.committing_authority,
            &body,
        )?;
        if value.to_canonical_bytes(admission)? != bytes {
            return Err(ExecutorError::InvalidTerminal);
        }
        Ok(value)
    }

    fn validate_common(
        &self,
        registration: BackendRegistration,
        admission: &Admission,
        authority: &AuthorityBinding,
        body: &TerminalBody,
    ) -> Result<(), ExecutorError> {
        validate_terminal_request_shape(registration, admission, authority, body)?;
        self.commit_metadata
            .validate_for_authority(&self.committing_authority)?;
        let committed_body = TerminalBody::from_record(self.record.clone(), admission)?;
        validate_terminal_request_shape(
            self.committing_registration,
            admission,
            &self.committing_authority,
            &committed_body,
        )?;
        // The root-certified proof bundle is request-only evidence. Consensus
        // verifies it before the atomic mutation, then retains the exact
        // terminal record rather than duplicating the bounded proof payload.
        // Receipt validation must therefore compare the immutable record and
        // phase, not the transient `Some(bundle)`/`None` representation.
        if committed_body.record != body.record
            || committed_body.phase != body.phase
            || self.record.request_id() != registration.request_id()
            || self.committing_guard_commitment == [0; 32]
            || self.committing_guard_commitment
                != terminal_committing_guard_commitment(
                    self.committing_registration,
                    admission,
                    &self.committing_authority,
                )
            || self
                .materialization
                .validate_for(admission, &committed_body)
                .is_err()
            || self.receipt_commitment
                != terminal_receipt_commitment(
                    registration,
                    admission,
                    &self.record,
                    self.committing_authority.fence(),
                    self.committing_guard_commitment,
                    &self.materialization,
                    self.commit_metadata,
                )
        {
            return Err(ExecutorError::InvalidTerminal);
        }
        Ok(())
    }

    /// Validate a freshly committed decision: its historical guard must be
    /// exactly the authority that submitted this irreversible transaction.
    fn validate_for_terminal_commit(
        &self,
        registration: BackendRegistration,
        admission: &Admission,
        authority: &AuthorityBinding,
        body: &TerminalBody,
    ) -> Result<(), ExecutorError> {
        self.validate_common(registration, admission, authority, body)?;
        if self.committing_registration != registration || self.committing_authority != *authority {
            return Err(ExecutorError::InvalidTerminal);
        }
        Ok(())
    }

    /// Validate a retained composite under current authority. A higher-fence
    /// status/recovery request authenticates independently and deliberately
    /// does not rewrite the historical committing guard.
    fn validate_for_terminal_read(
        &self,
        registration: BackendRegistration,
        admission: &Admission,
        authority: &AuthorityBinding,
        body: &TerminalBody,
    ) -> Result<(), ExecutorError> {
        self.validate_common(registration, admission, authority, body)?;
        if authority.fence() == self.committing_authority.fence() {
            if self.committing_authority != *authority {
                return Err(ExecutorError::InvalidTerminal);
            }
        } else if authority.fence() <= self.committing_authority.fence() {
            return Err(ExecutorError::InvalidTerminal);
        }
        Ok(())
    }

    fn receipt(
        &self,
        admission: &Admission,
        current_registration: BackendRegistration,
        current_authority: &AuthorityBinding,
    ) -> Result<TerminalCommitReceipt, ExecutorError> {
        let publication_binding = matches!(
            self.materialization,
            TerminalMaterialization::Established(_)
        )
        .then(|| PublicationAuthority {
            committing_registration: self.committing_registration,
            current_registration,
            roster_id: admission.roster_id(),
            admission_commitment: admission.body_commitment(),
            terminal_body_commitment: self.record.body_commitment(),
            receipt_commitment: self.receipt_commitment,
            logical_owner: admission.logical_owner().clone(),
            admission_fence: admission.admission_fence(),
            committing_fence: self.committing_authority.fence(),
            committing_authority: self.committing_authority.clone(),
            current_authority: current_authority.clone(),
            commit_metadata: self.commit_metadata,
        });
        let receipt = TerminalCommitReceipt {
            phase: match self.materialization {
                TerminalMaterialization::Established(_) => Phase::Established,
                TerminalMaterialization::Aborted => Phase::Aborted,
            },
            protected_checkpoint: self.record.protected_checkpoint().to_vec(),
            protected_result: self.record.protected_result().to_vec(),
            body_commitment: self.record.body_commitment(),
            receipt_commitment: self.receipt_commitment,
            publication_authority: publication_binding,
        };
        if let Some(authority) = receipt.publication_authority() {
            authority.validate_for(
                current_registration,
                admission,
                current_authority,
                receipt.body_commitment,
                receipt.receipt_commitment,
            )?;
        }
        Ok(receipt)
    }

    pub(crate) fn record(&self) -> &TerminalRecord {
        &self.record
    }
}

impl fmt::Debug for CommittedTerminal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CommittedTerminal(<redacted>)")
    }
}

/// SDK receipt for an exact committed terminal body.
///
/// The receipt exposes the immutable terminal bytes to its authorized caller.
/// Only an established receipt contains the nonconstructible publication
/// capability; an aborted terminal still exposes its exact retained bytes but
/// can never authorize publication.
#[derive(PartialEq, Eq)]
pub(crate) struct TerminalCommitReceipt {
    phase: Phase,
    protected_checkpoint: Vec<u8>,
    protected_result: Vec<u8>,
    body_commitment: [u8; 32],
    receipt_commitment: [u8; 32],
    publication_authority: Option<PublicationAuthority>,
}

impl TerminalCommitReceipt {
    /// Irreversible terminal phase.
    pub(crate) const fn phase(&self) -> Phase {
        self.phase
    }

    /// Exact protected checkpoint copied from immutable admission bytes.
    pub(crate) fn protected_checkpoint(&self) -> &[u8] {
        &self.protected_checkpoint
    }

    /// Exact protected result copied from immutable admission bytes.
    pub(crate) fn protected_result(&self) -> &[u8] {
        &self.protected_result
    }

    /// SDK publication authority, present only for an established terminal.
    pub(crate) fn publication_authority(&self) -> Option<&PublicationAuthority> {
        self.publication_authority.as_ref()
    }
}

impl fmt::Debug for TerminalCommitReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TerminalCommitReceipt(<redacted>)")
    }
}

/// Nonconstructible proof that one exact established terminal may be published.
///
/// The authority is move-only and carries the exact committed identity plus
/// the current guard under which the receipt was read. Publication integration
/// must revalidate that guard immediately before local or on-wire publication;
/// neither protected bytes nor a unit marker can be detached and reused for a
/// different tenant, scope, roster, body, or fence.
#[derive(PartialEq, Eq)]
pub(crate) struct PublicationAuthority {
    committing_registration: BackendRegistration,
    current_registration: BackendRegistration,
    roster_id: RosterId,
    admission_commitment: [u8; 32],
    terminal_body_commitment: [u8; 32],
    receipt_commitment: [u8; 32],
    logical_owner: OwnerId,
    admission_fence: FenceToken,
    committing_fence: FenceToken,
    committing_authority: AuthorityBinding,
    current_authority: AuthorityBinding,
    commit_metadata: ConsensusCommitMetadata,
}

impl PublicationAuthority {
    pub(crate) const fn current_registration(&self) -> BackendRegistration {
        self.current_registration
    }

    pub(crate) const fn roster_id(&self) -> RosterId {
        self.roster_id
    }

    pub(crate) const fn admission_commitment(&self) -> [u8; 32] {
        self.admission_commitment
    }

    pub(crate) const fn terminal_body_commitment(&self) -> [u8; 32] {
        self.terminal_body_commitment
    }

    pub(crate) const fn receipt_commitment(&self) -> [u8; 32] {
        self.receipt_commitment
    }

    pub(crate) fn current_authority(&self) -> &AuthorityBinding {
        &self.current_authority
    }

    pub(crate) fn validate_for(
        &self,
        current_registration: BackendRegistration,
        admission: &Admission,
        current_authority: &AuthorityBinding,
        terminal_body_commitment: [u8; 32],
        receipt_commitment: [u8; 32],
    ) -> Result<(), ExecutorError> {
        if self.current_registration != current_registration
            || self.committing_registration.request_id() != current_registration.request_id()
            || self.committing_registration.terminal_slot_id()
                != current_registration.terminal_slot_id()
            || self.roster_id != admission.roster_id()
            || self.admission_commitment != admission.body_commitment()
            || self.terminal_body_commitment != terminal_body_commitment
            || self.receipt_commitment != receipt_commitment
            || self.logical_owner != *admission.logical_owner()
            || self.admission_fence != admission.admission_fence()
            || self.committing_fence < self.admission_fence
            || self.committing_authority.fence() != self.committing_fence
            || self
                .commit_metadata
                .validate_for_authority(&self.committing_authority)
                .is_err()
            || self.current_authority != *current_authority
            || self.current_authority.scope() != admission.scope()
            || self.current_authority.key() != admission.key()
            || self.current_authority.generation() != admission.expected_generation()
            || (self.current_authority.fence() == self.committing_fence
                && self.current_authority != self.committing_authority)
            || self.current_authority.fence() < self.committing_fence
        {
            return Err(ExecutorError::InvalidTerminal);
        }
        Ok(())
    }
}

impl fmt::Debug for PublicationAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicationAuthority(<redacted>)")
    }
}

fn validate_terminal_request_shape(
    registration: BackendRegistration,
    admission: &Admission,
    authority: &AuthorityBinding,
    body: &TerminalBody,
) -> Result<(), ExecutorError> {
    registration.validate_for(admission)?;
    body.record()
        .validate_for(admission)
        .map_err(|_| ExecutorError::InvalidTerminal)?;
    if body.record().request_id() != registration.request_id()
        || body
            .record()
            .request_id()
            .terminal_slot_id(admission)
            .map_err(|_| ExecutorError::InvalidTerminal)?
            != registration.terminal_slot_id()
        || authority.scope() != admission.scope()
        || authority.key() != admission.key()
        || authority.generation() != admission.expected_generation()
        || authority.credential_id() == 0
        || authority.fence().get() == 0
        || authority.expires_at() <= authority.acquired_at()
        || (authority.fence() == admission.admission_fence()
            && authority.owner() != admission.logical_owner())
        || authority.fence() < admission.admission_fence()
    {
        return Err(ExecutorError::InvalidTerminal);
    }
    Ok(())
}

fn terminal_committing_guard_commitment(
    registration: BackendRegistration,
    admission: &Admission,
    authority: &AuthorityBinding,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TERMINAL_COMMITTING_GUARD_DOMAIN);
    hasher.update(admission.profile().schema().to_be_bytes());
    hasher.update(admission.profile().consumer_revision().to_be_bytes());
    hasher.update(admission.profile().digest());
    hasher.update(registration.handle);
    hasher.update(registration.request_id().to_bytes());
    hasher.update(registration.terminal_slot_id().as_bytes());
    hasher.update(admission.body_commitment());
    hasher.update(authority.scope().digest());
    update_terminal_commitment_bytes(
        &mut hasher,
        &session_key_canonical_digest_input(authority.key()),
    );
    update_terminal_commitment_bytes(&mut hasher, authority.owner().as_str().as_bytes());
    hasher.update(authority.fence().get().to_be_bytes());
    hasher.update(authority.credential_id().to_be_bytes());
    hasher.update(authority.generation().get().to_be_bytes());
    hasher.update(
        authority
            .acquired_at()
            .as_offset_datetime()
            .unix_timestamp_nanos()
            .to_be_bytes(),
    );
    hasher.update(
        authority
            .expires_at()
            .as_offset_datetime()
            .unix_timestamp_nanos()
            .to_be_bytes(),
    );
    hasher.finalize().into()
}

fn terminal_record_commitment(
    admission: &Admission,
    generation: Generation,
    state_type: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TERMINAL_RECORD_COMMITMENT_DOMAIN);
    hasher.update(admission.profile().schema().to_be_bytes());
    hasher.update(admission.profile().consumer_revision().to_be_bytes());
    hasher.update(admission.profile().digest());
    hasher.update(admission.body_commitment());
    hasher.update(admission.scope().digest());
    update_terminal_commitment_bytes(
        &mut hasher,
        &session_key_canonical_digest_input(admission.key()),
    );
    update_terminal_commitment_bytes(&mut hasher, admission.logical_owner().as_str().as_bytes());
    hasher.update(admission.admission_fence().get().to_be_bytes());
    hasher.update(generation.get().to_be_bytes());
    update_terminal_commitment_bytes(&mut hasher, b"authoritative-session");
    update_terminal_commitment_bytes(&mut hasher, state_type.as_bytes());
    hasher.update([0]); // no expiry is part of the immutable V1 record header
    update_terminal_commitment_bytes(&mut hasher, admission.terminal_checkpoint());
    hasher.finalize().into()
}

fn terminal_receipt_commitment(
    registration: BackendRegistration,
    admission: &Admission,
    record: &TerminalRecord,
    committing_fence: FenceToken,
    committing_guard_commitment: [u8; 32],
    materialization: &TerminalMaterialization,
    commit_metadata: ConsensusCommitMetadata,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TERMINAL_RECEIPT_COMMITMENT_DOMAIN);
    hasher.update(admission.profile().schema().to_be_bytes());
    hasher.update(admission.profile().consumer_revision().to_be_bytes());
    hasher.update(admission.profile().digest());
    hasher.update(registration.request_id().to_bytes());
    hasher.update(registration.terminal_slot_id().as_bytes());
    hasher.update(admission.body_commitment());
    hasher.update(record.body_commitment());
    hasher.update(match record.phase() {
        Ok(Phase::Established) => [1],
        Ok(Phase::Aborted) => [2],
        Err(_) => [0],
    });
    hasher.update(committing_fence.get().to_be_bytes());
    hasher.update(committing_guard_commitment);
    commit_metadata.update_commitment(&mut hasher);
    materialization.update_receipt_commitment(&mut hasher);
    hasher.finalize().into()
}

fn update_terminal_commitment_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

/// Atomic result of the single durable terminalization mutation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum TerminalizeDecision {
    /// The exact body, authoritative checkpoint, result, and receipt were written.
    Terminalized(CommittedTerminal),
    /// The same exact body was already terminalized and returned its stored composite.
    Replayed(CommittedTerminal),
    /// The exact terminal payload has aged out and cannot authorize publication.
    Compacted {
        history_epoch: u64,
        tombstone: TerminalConflictTombstone,
    },
    /// The backend proved no request byte crossed its transport boundary.
    NotTransmitted,
    /// The prepared body, authority, or registration did not match.
    Reject(BackendRejection),
}

/// Exact input for the sole durable terminalization mutation.
pub(crate) struct TerminalizeRequest<'a> {
    registration: BackendRegistration,
    admission: &'a Admission,
    authority: &'a AuthorityBinding,
    body: &'a TerminalBody,
}

impl TerminalizeRequest<'_> {
    /// Opaque durable registration identity.
    pub(crate) const fn registration(&self) -> BackendRegistration {
        self.registration
    }

    /// Exact immutable admission that must match the registered canonical body.
    pub(crate) fn admission(&self) -> &Admission {
        self.admission
    }

    /// Exact authority binding to revalidate at irreversible commit time.
    pub(crate) fn authority(&self) -> &AuthorityBinding {
        self.authority
    }

    /// Exact terminal body built from SDK-issued proofs.
    pub(crate) fn body(&self) -> &TerminalBody {
        self.body
    }
}

impl fmt::Debug for TerminalizeRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TerminalizeRequest(<redacted>)")
    }
}

/// Result of a read-only exact-terminal status query.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum TerminalStatusDecision {
    /// The roster remains admitted at the linearizable read barrier.
    Admitted,
    /// The exact terminal is committed and its retained composite is returned.
    Recorded(Box<CommittedTerminal>),
    /// The exact terminal payload aged out; only nonpublishing conflict status remains.
    Compacted {
        history_epoch: u64,
        tombstone: Box<TerminalConflictTombstone>,
    },
    /// Scope, authority, admission, terminal slot, or exact body did not match.
    Reject(BackendRejection),
}

/// Validated read-only terminal status returned by the executor.
#[derive(Debug)]
pub(crate) enum TerminalStatusResult {
    /// The roster remains admitted at the linearizable read barrier.
    Admitted,
    /// The exact committed body was validated and converted to an SDK receipt.
    Recorded(Box<TerminalCommitReceipt>),
    /// The exact compact conflict binding was validated without payload recovery.
    Compacted,
}

/// Read-only lookup of one exact terminal body under current authority.
pub(crate) struct TerminalStatusRequest<'a> {
    registration: BackendRegistration,
    admission: &'a Admission,
    authority: &'a AuthorityBinding,
    body: &'a TerminalBody,
}

impl TerminalStatusRequest<'_> {
    pub(crate) const fn registration(&self) -> BackendRegistration {
        self.registration
    }

    pub(crate) fn admission(&self) -> &Admission {
        self.admission
    }

    pub(crate) fn authority(&self) -> &AuthorityBinding {
        self.authority
    }

    pub(crate) fn body(&self) -> &TerminalBody {
        self.body
    }
}

impl fmt::Debug for TerminalStatusRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TerminalStatusRequest(<redacted>)")
    }
}

/// Two-mutation roster control-plane contract.
///
/// `register` is the first and `terminalize` the second durable roster
/// mutation.  Recovery and terminal status are read only. Implementors own
/// exact tenant, scope, key, owner, fence, credential, and generation
/// validation at admission/recovery/terminalization. Provider-local work is
/// guarded by the startup-owned local permit registry rather than quorum
/// reads. `register` already atomically
/// reserves the exact present-generation business precondition and the
/// deterministic peak storage needed through terminal retention. Therefore
/// `terminalize` has no normal RecordMissing, GenerationConflict, HistoryFull,
/// or RetentionExhausted result: any such mismatch is invariant corruption,
/// rolls back both terminal and business changes, and returns no receipt or
/// publication authority. `terminalize` MUST atomically revalidate all
/// bindings, persist a [`CommittedTerminal`], and replay only that exact
/// composite for an identical terminal body. Established writes the canonical
/// terminal record, receipt, session mutation, and durable fence floor in one
/// transaction. Aborted writes only terminal record and receipt and never
/// publishes.
#[async_trait]
pub(crate) trait RosterExecutorBackend: Send + Sync {
    /// Adapter-local backend error whose contents never enter SDK diagnostics.
    type Error: Send + Sync + 'static;

    /// Persist and authenticate an immutable admission plus exact authority binding.
    ///
    /// In one linearization this MUST authenticate the full binding, select
    /// and bind the current V2 history epoch above the durable exact-scope
    /// retirement floor, key the admission-command slot by
    /// epoch/scope/session-key/roster ID, reserve both live and eventual
    /// terminal-history capacity, and write the exact canonical admission.
    /// Byte-identical replay returns `AdmissionReplayed` without minting a
    /// fresh execution capability; a different body at the same slot
    /// conflicts. Capacity and floor failures happen here before any provider
    /// call and can never be deferred to terminalization.
    async fn register(
        &self,
        request: &RegistrationRequest,
    ) -> Result<RegistrationDecision, Self::Error>;

    /// Read back one exact original admission without mutation.
    ///
    /// The backend MUST compare the canonical admission and its original
    /// owner/fence/generation/credential/lease window to retained state, and
    /// validate the original guard against backend-owned time.  This is not a
    /// successor recovery API and must never accept a roster ID alone.
    async fn admission_status(
        &self,
        request: AdmissionStatusRequest<'_>,
    ) -> Result<RegistrationDecision, Self::Error>;

    /// Look up an existing exact admission under current successor authority.
    ///
    /// This is read-only: it MUST reject a fence that is not strictly above
    /// the immutable admission fence or does not equal the backend's current
    /// durable lease fence. Repeated recovery under that same current lease
    /// may replay only the same scoped capability; it must not mint another.
    /// `RecoveryLookup` and the full `Admission` must identify an already-
    /// registered exact body.
    async fn recover(&self, request: &RecoveryRequest)
        -> Result<RegistrationDecision, Self::Error>;

    /// Read one exact terminal slot at a linearizable barrier without mutation.
    async fn terminal_status(
        &self,
        request: TerminalStatusRequest<'_>,
    ) -> Result<TerminalStatusDecision, Self::Error>;

    /// Perform the one atomic terminal roster/session mutation.
    ///
    /// The backend must validate the exact terminal body and apply the
    /// `CommittedTerminal` receipt plus its materialization atomically.
    /// A higher current fence may authorize a previously admitted terminal,
    /// but must retain the admission's original owner/fence/checkpoint in an
    /// Established Put; only the durable execution-fence floor advances.
    /// Impossible precondition mismatches must roll back all writes rather
    /// than being represented as a normal terminal decision.
    ///
    /// Payload compaction after terminal retention is a distinct bounded
    /// maintenance operation. In one linearization it MUST delete every full
    /// admission and terminal copy and persist only the exact
    /// conflict tombstone; it never touches a live or ambiguous roster.
    async fn terminalize(
        &self,
        request: TerminalizeRequest<'_>,
    ) -> Result<TerminalizeDecision, Self::Error>;
}

/// Startup-owned shared provider executor and its bounded global work gate.
///
/// Cloning an executor shares the same provider, backend, and semaphore.  No
/// operation accepts a provider argument, so every registration is forced
/// through the provider fixed at construction.
pub(crate) struct RosterExecutor<P, B> {
    provider: Arc<P>,
    backend: Arc<B>,
    attestor: Arc<dyn FencedMutationRosterExecutorAttestor>,
    scheduler: ProviderWorkScheduler,
    local_authority: LocalAuthorityRegistry,
    diagnostics: RosterDiagnostics,
}

impl<P, B> Clone for RosterExecutor<P, B> {
    fn clone(&self) -> Self {
        Self {
            provider: Arc::clone(&self.provider),
            backend: Arc::clone(&self.backend),
            attestor: Arc::clone(&self.attestor),
            scheduler: self.scheduler.clone(),
            local_authority: self.local_authority.clone(),
            diagnostics: self.diagnostics.clone(),
        }
    }
}

impl<P, B> RosterExecutor<P, B>
where
    P: MemberProvider,
    B: RosterExecutorBackend + 'static,
{
    /// Fix one provider and backend for this process-owned executor.
    pub(crate) fn new(
        provider: Arc<P>,
        backend: Arc<B>,
        attestor: Arc<dyn FencedMutationRosterExecutorAttestor>,
        max_in_flight: NonZeroUsize,
    ) -> Self {
        Self::new_with_clock(
            provider,
            backend,
            attestor,
            max_in_flight,
            Arc::new(SystemClock),
        )
    }

    /// Fix one provider/backend pair and an injectable local expiry clock.
    ///
    /// Production construction uses [`SystemClock`] through [`Self::new`].
    /// Tests and embedding startup composition can supply a deterministic
    /// crate clock without giving callers a way to mint or refresh permits.
    pub(crate) fn new_with_clock(
        provider: Arc<P>,
        backend: Arc<B>,
        attestor: Arc<dyn FencedMutationRosterExecutorAttestor>,
        max_in_flight: NonZeroUsize,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let max_in_flight = max_in_flight.get().min(MAX_PROVIDER_IN_FLIGHT);
        let scheduler = ProviderWorkScheduler::new(max_in_flight)
            .expect("nonzero clamped provider capacity is within the live-roster limit");
        Self {
            provider,
            backend,
            attestor,
            scheduler,
            local_authority: LocalAuthorityRegistry::new(clock),
            diagnostics: RosterDiagnosticsInner::new(),
        }
    }

    pub(crate) fn diagnostics(&self) -> RosterDiagnostics {
        self.diagnostics.clone()
    }

    /// Build a publication adapter that shares this executor's startup-owned
    /// provider scheduler and local authority registry. It performs no backend
    /// reads or writes around provider-local publication.
    pub(crate) fn publication_adapter<Q>(
        &self,
        provider: Arc<Q>,
    ) -> super::publication::PublicationAdapter<Q>
    where
        Q: super::canonical::EstablishedPublicationProvider,
    {
        super::publication::PublicationAdapter::new(
            provider,
            self.scheduler.clone(),
            self.local_authority.clone(),
            self.diagnostics.clone(),
        )
    }

    /// Register an immutable admission and receive one opaque authenticated capability.
    pub(crate) async fn register(
        &self,
        request: RegistrationRequest,
    ) -> Result<Registration, ExecutorError> {
        let reservation = self.local_authority.reserve_admission(&request)?;
        self.diagnostics
            .increment(DiagnosticsCounter::AdmissionCalls);
        let round_trip_started = Instant::now();
        let backend_result = self.backend.register(&request).await;
        self.diagnostics.record_latency(
            DiagnosticsLatency::AdmissionRoundTrip,
            round_trip_started.elapsed(),
        );
        let decision = match backend_result {
            Ok(RegistrationDecision::NotTransmitted) => {
                self.diagnostics
                    .increment(DiagnosticsCounter::AdmissionNotTransmitted);
                self.local_authority
                    .release_admission_reservation(&reservation);
                return Err(ExecutorError::AdmissionNotTransmitted);
            }
            Ok(decision) => {
                self.diagnostics
                    .increment(DiagnosticsCounter::AdmissionConclusive);
                decision
            }
            // The reservation deliberately remains installed. Cancellation or
            // any transport ambiguity can only proceed through exact status.
            Err(_) => {
                self.diagnostics
                    .increment(DiagnosticsCounter::AdmissionOutcomeUnknown);
                return Err(ExecutorError::AdmissionOutcomeUnknown);
            }
        };
        match decision {
            RegistrationDecision::FreshlyAdmitted(registration) => {
                self.diagnostics
                    .record_width(request.admission().members().len());
                Registration::issue(request, registration, reservation, &self.local_authority)
                    .map_err(|_| ExecutorError::AdmissionOutcomeUnknown)
            }
            RegistrationDecision::AdmissionReplayed => Err(ExecutorError::RecoveryRequired),
            RegistrationDecision::NotTransmitted => unreachable!("handled above"),
            RegistrationDecision::PollAdmitted { .. }
            | RegistrationDecision::Terminal { .. }
            | RegistrationDecision::Compacted { .. } => Err(ExecutorError::AdmissionOutcomeUnknown),
            RegistrationDecision::Reject(rejection) => {
                self.local_authority
                    .release_admission_reservation(&reservation);
                Err(rejection.into())
            }
        }
    }

    /// Recover a successor-owned capability by stable scope/key/roster lookup.
    ///
    /// This is the only recovery path.  The caller does not supply an
    /// admission body: the backend returns the consensus-retained canonical
    /// body only after validating the exact scope, key, roster ID, and current
    /// successor authority.  Thus a new pod cannot reconstruct or substitute
    /// plan, member, checkpoint, or result bytes after restart.
    pub(crate) async fn recover(
        &self,
        request: RecoveryRequest,
    ) -> Result<RecoveryResult, ExecutorError> {
        self.diagnostics
            .increment(DiagnosticsCounter::RecoveryCalls);
        let decision = self
            .backend
            .recover(&request)
            .await
            .map_err(|_| ExecutorError::BackendUnavailable)?;
        if let RegistrationDecision::Compacted {
            history_epoch,
            tombstone,
        } = decision
        {
            tombstone
                .validate_lookup(
                    history_epoch,
                    request.lookup().scope(),
                    request.authority().key(),
                    request.lookup().roster_id(),
                    request.authority().fence(),
                    request.authority().generation(),
                )
                .map_err(|_| ExecutorError::AuthorityRejected)?;
            return Ok(RecoveryResult::Compacted);
        }
        let (backend_registration, admission, committed_terminal) = match decision {
            RegistrationDecision::PollAdmitted {
                registration,
                admission,
            } => (registration, admission, None),
            RegistrationDecision::Terminal {
                registration,
                admission,
                committed,
            } => (registration, admission, Some(*committed)),
            RegistrationDecision::FreshlyAdmitted(_)
            | RegistrationDecision::AdmissionReplayed
            | RegistrationDecision::NotTransmitted => {
                return Err(ExecutorError::InvalidRegistration);
            }
            RegistrationDecision::Compacted { .. } => unreachable!("handled compacted result"),
            RegistrationDecision::Reject(rejection) => return Err(rejection.into()),
        };
        let recovered_authority = AuthorityBinding::for_successor(
            &admission,
            request.authority.owner.clone(),
            request.authority.fence,
            request.authority.credential_id,
            request.authority.generation,
            request.authority.acquired_at,
            request.authority.expires_at,
        )?;
        if recovered_authority != request.authority
            || admission.scope() != request.lookup.scope()
            || admission.roster_id() != request.lookup.roster_id()
        {
            return Err(ExecutorError::InvalidRegistration);
        }
        let registration = Registration::recover(
            request,
            admission,
            backend_registration,
            &self.local_authority,
        )?;
        if let Some(committed) = committed_terminal {
            let body =
                TerminalBody::from_record(committed.record().clone(), registration.admission())?;
            committed.validate_for_terminal_read(
                registration.backend_registration(),
                registration.admission(),
                registration.authority(),
                &body,
            )?;
            let receipt = self.receipt_for_registration(&registration, &committed)?;
            return match receipt.phase() {
                Phase::Established if receipt.publication_authority().is_some() => {
                    Ok(RecoveryResult::Established(receipt))
                }
                Phase::Aborted if receipt.publication_authority().is_none() => {
                    Ok(RecoveryResult::Aborted(receipt))
                }
                Phase::Established | Phase::Aborted => Err(ExecutorError::InvalidTerminal),
            };
        }
        Ok(RecoveryResult::PollAdmitted(Box::new(
            PollAdmittedRecovery { registration },
        )))
    }

    /// Read back the exact original admission after `register` lost its reply.
    pub(crate) async fn admission_status(
        &self,
        request: RegistrationRequest,
    ) -> Result<RecoveryResult, ExecutorError> {
        self.diagnostics
            .increment(DiagnosticsCounter::AdmissionStatusCalls);
        let decision = self
            .backend
            .admission_status(AdmissionStatusRequest {
                registration: &request,
            })
            .await
            .map_err(|_| ExecutorError::BackendUnavailable)?;
        let (backend_registration, admission, committed_terminal) = match decision {
            RegistrationDecision::PollAdmitted {
                registration,
                admission,
            } => (registration, admission, None),
            RegistrationDecision::Terminal {
                registration,
                admission,
                committed,
            } => (registration, admission, Some(*committed)),
            RegistrationDecision::Reject(rejection) => return Err(rejection.into()),
            RegistrationDecision::Compacted { .. } => {
                return Err(ExecutorError::TerminalPayloadCompacted);
            }
            RegistrationDecision::FreshlyAdmitted(_)
            | RegistrationDecision::AdmissionReplayed
            | RegistrationDecision::NotTransmitted => {
                return Err(ExecutorError::InvalidRegistration);
            }
        };
        if admission
            .to_canonical_bytes()
            .map_err(|_| ExecutorError::InvalidRegistration)?
            != request
                .admission()
                .to_canonical_bytes()
                .map_err(|_| ExecutorError::InvalidRegistration)?
        {
            return Err(ExecutorError::AuthorityRejected);
        }
        let registration =
            Registration::readback(request, backend_registration, &self.local_authority)?;
        if let Some(committed) = committed_terminal {
            let body =
                TerminalBody::from_record(committed.record().clone(), registration.admission())?;
            committed.validate_for_terminal_read(
                registration.backend_registration(),
                registration.admission(),
                registration.authority(),
                &body,
            )?;
            let receipt = self.receipt_for_registration(&registration, &committed)?;
            return match receipt.phase() {
                Phase::Established if receipt.publication_authority().is_some() => {
                    Ok(RecoveryResult::Established(receipt))
                }
                Phase::Aborted if receipt.publication_authority().is_none() => {
                    Ok(RecoveryResult::Aborted(receipt))
                }
                _ => Err(ExecutorError::InvalidTerminal),
            };
        }
        Ok(RecoveryResult::PollAdmitted(Box::new(
            PollAdmittedRecovery { registration },
        )))
    }

    fn receipt_for_registration(
        &self,
        registration: &Registration,
        committed: &CommittedTerminal,
    ) -> Result<TerminalCommitReceipt, ExecutorError> {
        let receipt = committed.receipt(
            registration.admission(),
            registration.backend_registration(),
            registration.authority(),
        )?;
        if receipt.phase() == Phase::Aborted {
            self.local_authority
                .release_terminal_permit(&registration.authority_permit);
        }
        Ok(receipt)
    }

    /// Durably prepare one exact member in the provider-local journal.
    ///
    /// This performs local pre/post permit checks around provider-local work
    /// and never reads or writes roster consensus.
    pub(crate) async fn prepare(
        &self,
        registration: &Registration,
        ordinal: u8,
    ) -> Result<CallResult, ExecutorError> {
        self.call(registration, ordinal, ProviderOperation::Prepare)
            .await
    }

    /// Attempt one exact member effect under local pre/post permit validation.
    pub(crate) async fn execute(
        &self,
        registration: &Registration,
        ordinal: u8,
    ) -> Result<CallResult, ExecutorError> {
        self.call(registration, ordinal, ProviderOperation::Execute)
            .await
    }

    /// Read one exact member only after local state has become ambiguous.
    pub(crate) async fn status(
        &self,
        registration: &Registration,
        ordinal: u8,
    ) -> Result<CallResult, ExecutorError> {
        self.call(registration, ordinal, ProviderOperation::Status)
            .await
    }

    /// Adopt one exact member only after local state has become ambiguous.
    pub(crate) async fn adopt(
        &self,
        registration: &Registration,
        ordinal: u8,
    ) -> Result<CallResult, ExecutorError> {
        self.call(registration, ordinal, ProviderOperation::Adopt)
            .await
    }

    /// Compensate one exact SDK-proven Applied member without touching
    /// consensus. An ambiguous attempt remains status/adopt-only.
    pub(crate) async fn compensate_member(
        &self,
        registration: &Registration,
        ordinal: u8,
    ) -> Result<CallResult, ExecutorError> {
        self.call(registration, ordinal, ProviderOperation::Compensate)
            .await
    }

    /// Consume SDK-issued proofs into one process-local terminal handle.
    ///
    /// This performs no roster/session mutation. It first locks local member
    /// execution, then freezes the exact canonical body locally. The
    /// subsequent [`Self::terminalize`] call is the sole terminal
    /// authority-bearing mutation; a restarted executor must recover provider
    /// state before preparing its own body.
    pub(crate) async fn prepare_terminal(
        &self,
        registration: &Registration,
        proofs: Vec<AppliedProof>,
    ) -> Result<PreparedTerminal, ExecutorError> {
        self.diagnostics
            .increment(DiagnosticsCounter::TerminalPrepareCalls);
        let mut _member_barrier = Vec::with_capacity(registration.member_calls.len());
        for member_call in &registration.member_calls {
            _member_barrier.push(
                Arc::clone(member_call)
                    .try_lock_owned()
                    .map_err(|_| ExecutorError::ExecutorBusy)?,
            );
        }
        if proofs
            .iter()
            .any(|proof| proof.registration != registration.backend_registration())
        {
            return Err(ExecutorError::InvalidTerminal);
        }
        let body = {
            let mut local = registration
                .local
                .lock()
                .map_err(|_| ExecutorError::OutcomeUnknown)?;
            if local.terminal.is_locked()
                || !proofs
                    .iter()
                    .all(|proof| retained_conclusive_matches(&local, proof))
            {
                return Err(ExecutorError::InvalidTerminal);
            }
            let body = TerminalBody::build(
                registration.backend_registration(),
                registration.admission(),
                registration.authority(),
                &proofs,
            )?;
            // Signing now crosses an asynchronous HSM/KMS boundary. Lock the
            // member lanes before that await and fail closed: a cancelled,
            // timed-out, revoked, or rejected signature never restores a
            // prepare/execute capability.
            local.terminal = LocalTerminalState::StatusOnly;
            body
        };
        let frozen = freeze_executor_attestation(self.attestor.as_ref(), registration.admission())?;
        let mut signed_parts = Vec::with_capacity(proofs.len());
        for proof in &proofs {
            self.validate_terminal_signing_state(registration, proof)?;
            let input = terminal_attestation_signing_input(
                registration,
                &body,
                proof,
                &frozen.certificate,
            )?;
            input
                .digest()
                .map_err(|_| ExecutorError::AttestationUnavailable)?;
            let signature = tokio::time::timeout(
                PROVIDER_EFFECT_DEADLINE,
                self.attestor.sign_terminal(&input),
            )
            .await
            .map_err(|_| ExecutorError::AttestationUnavailable)??;
            self.validate_terminal_signing_state(registration, proof)?;
            signed_parts.push(RosterExecutorMemberProofPartsV1 {
                ordinal: proof.ordinal,
                provider_operation: attested_operation(proof.operation),
                outcome: attested_outcome(proof.outcome),
                proof_epoch: proof.proof_epoch,
                evidence: proof.evidence.clone(),
                signature,
            });
        }
        let bundle = RosterExecutorProofBundleV1::issue_from_signed_parts(
            &frozen.root,
            frozen.certificate,
            signed_parts,
        )
        .map_err(|_| ExecutorError::AttestationUnavailable)?;
        self.local_authority
            .linearize_current(&registration.authority_permit, || {
                let mut local = registration
                    .local
                    .lock()
                    .map_err(|_| ExecutorError::OutcomeUnknown)?;
                if !matches!(local.terminal, LocalTerminalState::StatusOnly)
                    || !proofs
                        .iter()
                        .all(|proof| retained_conclusive_matches(&local, proof))
                {
                    return Err(ExecutorError::AuthorityRejected);
                }
                local.terminal = LocalTerminalState::Prepared;
                Ok(())
            })?;
        Ok(PreparedTerminal {
            registration: registration.backend_registration(),
            body: body.with_bundle(bundle),
        })
    }

    fn validate_terminal_signing_state(
        &self,
        registration: &Registration,
        proof: &AppliedProof,
    ) -> Result<(), ExecutorError> {
        if self.local_authority.check(&registration.authority_permit)
            != LocalAuthorityCheck::Current
        {
            return Err(ExecutorError::AuthorityRejected);
        }
        let local = registration
            .local
            .lock()
            .map_err(|_| ExecutorError::OutcomeUnknown)?;
        if !matches!(local.terminal, LocalTerminalState::StatusOnly)
            || !retained_conclusive_matches(&local, proof)
        {
            return Err(ExecutorError::AuthorityRejected);
        }
        Ok(())
    }

    /// Read exact terminal status without issuing a roster mutation.
    pub(crate) async fn terminal_status(
        &self,
        registration: &Registration,
        prepared: &PreparedTerminal,
    ) -> Result<TerminalStatusResult, ExecutorError> {
        if prepared.registration != registration.backend_registration() {
            return Err(ExecutorError::InvalidTerminal);
        }
        prepared.body.bundle()?;
        self.diagnostics
            .increment(DiagnosticsCounter::TerminalStatusCalls);
        match self
            .backend
            .terminal_status(TerminalStatusRequest {
                registration: registration.backend_registration(),
                admission: registration.admission(),
                authority: registration.authority(),
                body: &prepared.body,
            })
            .await
            .map_err(|_| ExecutorError::BackendUnavailable)?
        {
            TerminalStatusDecision::Recorded(committed) => {
                committed.validate_for_terminal_read(
                    registration.backend_registration(),
                    registration.admission(),
                    registration.authority(),
                    &prepared.body,
                )?;
                Ok(TerminalStatusResult::Recorded(Box::new(
                    self.receipt_for_registration(registration, &committed)?,
                )))
            }
            TerminalStatusDecision::Compacted {
                history_epoch,
                tombstone,
            } => {
                let status = tombstone
                    .validate_admission(history_epoch, registration.admission())
                    .map_err(|_| ExecutorError::TerminalConflict)?;
                if status.phase() != prepared.body.phase()
                    || status.terminal_body_commitment() != prepared.body.commitment()
                {
                    return Err(ExecutorError::TerminalConflict);
                }
                Ok(TerminalStatusResult::Compacted)
            }
            TerminalStatusDecision::Admitted => Ok(TerminalStatusResult::Admitted),
            TerminalStatusDecision::Reject(rejection) => Err(rejection.into()),
        }
    }

    /// Perform the sole atomic terminal mutation for one durable exact body.
    pub(crate) async fn terminalize(
        &self,
        registration: &Registration,
        prepared: &PreparedTerminal,
    ) -> Result<TerminalCommitReceipt, ExecutorError> {
        if prepared.registration != registration.backend_registration() {
            return Err(ExecutorError::InvalidTerminal);
        }
        // A missing proof bundle is a local construction failure, never a
        // reason to invoke terminal status or the terminal mutation backend.
        prepared.body.bundle()?;
        self.local_authority
            .linearize_current(&registration.authority_permit, || {
                let mut local = registration
                    .local
                    .lock()
                    .map_err(|_| ExecutorError::TerminalizeOutcomeUnknown)?;
                if !local.terminal.may_terminalize() {
                    return Err(ExecutorError::RecoveryRequired);
                }
                // Do this before the await: every result except a transport-proven
                // NotTransmitted is status-only and cannot authorize a resend.
                local.terminal = LocalTerminalState::StatusOnly;
                Ok(())
            })?;
        self.diagnostics
            .increment(DiagnosticsCounter::TerminalizeCalls);
        let round_trip_started = Instant::now();
        let backend_result = self
            .backend
            .terminalize(TerminalizeRequest {
                registration: registration.backend_registration(),
                admission: registration.admission(),
                authority: registration.authority(),
                body: &prepared.body,
            })
            .await;
        self.diagnostics.record_latency(
            DiagnosticsLatency::TerminalizeRoundTrip,
            round_trip_started.elapsed(),
        );
        let decision = match backend_result {
            Ok(decision) => decision,
            Err(_) => {
                self.diagnostics
                    .increment(DiagnosticsCounter::TerminalizeOutcomeUnknown);
                return Err(ExecutorError::TerminalizeOutcomeUnknown);
            }
        };
        match decision {
            TerminalizeDecision::Terminalized(committed) => {
                committed.validate_for_terminal_commit(
                    registration.backend_registration(),
                    registration.admission(),
                    registration.authority(),
                    &prepared.body,
                )?;
                let receipt = self.receipt_for_registration(registration, &committed)?;
                self.diagnostics.increment(match prepared.body.phase() {
                    Phase::Established => DiagnosticsCounter::TerminalizeCommittedEstablished,
                    Phase::Aborted => DiagnosticsCounter::TerminalizeCommittedAborted,
                });
                Ok(receipt)
            }
            TerminalizeDecision::Replayed(committed) => {
                committed.validate_for_terminal_read(
                    registration.backend_registration(),
                    registration.admission(),
                    registration.authority(),
                    &prepared.body,
                )?;
                let receipt = self.receipt_for_registration(registration, &committed)?;
                self.diagnostics.increment(match prepared.body.phase() {
                    Phase::Established => DiagnosticsCounter::TerminalizeCommittedEstablished,
                    Phase::Aborted => DiagnosticsCounter::TerminalizeCommittedAborted,
                });
                Ok(receipt)
            }
            TerminalizeDecision::Compacted {
                history_epoch,
                tombstone,
            } => {
                let status = tombstone
                    .validate_admission(history_epoch, registration.admission())
                    .map_err(|_| {
                        self.diagnostics
                            .increment(DiagnosticsCounter::TerminalizeConflict);
                        ExecutorError::TerminalConflict
                    })?;
                if status.phase() != prepared.body.phase()
                    || status.terminal_body_commitment() != prepared.body.commitment()
                {
                    self.diagnostics
                        .increment(DiagnosticsCounter::TerminalizeConflict);
                    return Err(ExecutorError::TerminalConflict);
                }
                self.diagnostics
                    .increment(DiagnosticsCounter::TerminalPayloadCompacted);
                Err(ExecutorError::TerminalPayloadCompacted)
            }
            TerminalizeDecision::NotTransmitted => {
                self.diagnostics
                    .increment(DiagnosticsCounter::TerminalizeNotTransmitted);
                self.local_authority
                    .linearize_current(&registration.authority_permit, || {
                        let mut local = registration
                            .local
                            .lock()
                            .map_err(|_| ExecutorError::TerminalizeOutcomeUnknown)?;
                        if !matches!(local.terminal, LocalTerminalState::StatusOnly) {
                            return Err(ExecutorError::RecoveryRequired);
                        }
                        local.terminal = LocalTerminalState::Prepared;
                        Ok(())
                    })?;
                Err(ExecutorError::TerminalizeNotTransmitted)
            }
            TerminalizeDecision::Reject(rejection) => {
                if rejection == BackendRejection::TerminalConflict {
                    self.diagnostics
                        .increment(DiagnosticsCounter::TerminalizeConflict);
                }
                Err(rejection.into())
            }
        }
    }

    async fn call(
        &self,
        registration: &Registration,
        ordinal: u8,
        operation: ProviderOperation,
    ) -> Result<CallResult, ExecutorError> {
        let member = registration
            .admission()
            .members()
            .get(ordinal as usize)
            .ok_or(ExecutorError::InvalidMember)?;
        if member.ordinal() != ordinal {
            return Err(ExecutorError::InvalidMember);
        }
        // Both guards are acquired synchronously before spawn. The detached
        // child owns them through both local permit checks and the provider
        // operation, so dropping the caller future cannot cancel the
        // safety-critical sequence or create an unbounded waiter. No member
        // operation reads or writes consensus. The shared scheduler also caps
        // one exact tenant and scope below global capacity, leaving progress
        // capacity for an unrelated tenant.
        let concurrency_permit = match self
            .scheduler
            .try_acquire(provider_scheduling_digest(registration.authority()))
        {
            Ok(permit) => permit,
            Err(_) => {
                self.diagnostics
                    .increment(DiagnosticsCounter::MemberProviderBusy);
                return Err(ExecutorError::ExecutorBusy);
            }
        };
        let member_call = match registration
            .member_calls
            .get(ordinal as usize)
            .ok_or(ExecutorError::InvalidMember)?
            .clone()
            .try_lock_owned()
        {
            Ok(member_call) => member_call,
            Err(_) => {
                self.diagnostics
                    .increment(DiagnosticsCounter::MemberProviderBusy);
                return Err(ExecutorError::ExecutorBusy);
            }
        };
        let proof_epoch = {
            let local = registration
                .local
                .lock()
                .map_err(|_| ExecutorError::OutcomeUnknown)?;
            if local.terminal.is_locked() {
                return Err(ExecutorError::TerminalLocked);
            }
            let index = ordinal as usize;
            let attempt = local
                .attempts
                .get(index)
                .ok_or(ExecutorError::InvalidMember)?;
            if !attempt.permits(operation) {
                return Err(ExecutorError::RecoveryRequired);
            }
            if operation == ProviderOperation::Compensate && !local.permits_compensation(index) {
                return Err(ExecutorError::RecoveryRequired);
            }
            let epoch = local
                .proof_epochs
                .get(index)
                .ok_or(ExecutorError::InvalidMember)?;
            if (*attempt == LocalAttempt::Conclusive && operation != ProviderOperation::Compensate)
                || (*attempt == LocalAttempt::OutcomeUnknown
                    && matches!(
                        local.first_conclusive.get(index).cloned().flatten(),
                        Some(ConclusiveObservation {
                            outcome: ProviderOutcome::AppliedExecuted
                                | ProviderOutcome::AppliedAdopted,
                            ..
                        })
                    )
                    && matches!(local.compensations.get(index), Some(None)))
            {
                *epoch
            } else {
                epoch.checked_add(1).ok_or(ExecutorError::OutcomeUnknown)?
            }
        };
        let provider = Arc::clone(&self.provider);
        let admission = Arc::clone(&registration.admission);
        let authority = registration.authority.clone();
        let authority_permit = registration.authority_permit.clone();
        let local_authority = self.local_authority.clone();
        let local = Arc::clone(&registration.local);
        let backend_registration = registration.backend_registration();
        let diagnostics = self.diagnostics.clone();
        let task = tokio::spawn(async move {
            let _bounded_lifetime = (concurrency_permit, member_call);
            run_provider_call(ProviderCallTask {
                provider,
                admission,
                authority,
                authority_permit,
                local_authority,
                local,
                registration: backend_registration,
                ordinal,
                operation,
                proof_epoch,
                diagnostics,
            })
            .await
        });
        task.await.map_err(|_| ExecutorError::OutcomeUnknown)?
    }
}

struct ProviderCallTask<P> {
    provider: Arc<P>,
    admission: Arc<Admission>,
    authority: AuthorityBinding,
    authority_permit: LocalAuthorityPermit,
    local_authority: LocalAuthorityRegistry,
    local: Arc<Mutex<LocalExecutionState>>,
    registration: BackendRegistration,
    ordinal: u8,
    operation: ProviderOperation,
    proof_epoch: u64,
    diagnostics: RosterDiagnostics,
}

impl<P> ProviderCallTask<P> {
    fn binding<'a>(&'a self, member: &'a Member) -> CallBinding<'a> {
        CallBinding {
            registration: self.registration,
            admission: &self.admission,
            authority: &self.authority,
            member,
            operation: self.operation,
        }
    }
}

async fn run_provider_call<P>(task: ProviderCallTask<P>) -> Result<CallResult, ExecutorError>
where
    P: MemberProvider,
{
    let member = task
        .admission
        .members()
        .get(task.ordinal as usize)
        .ok_or(ExecutorError::InvalidMember)?;
    let binding = task.binding(member);
    let prior_attempt = {
        let mut local = task
            .local
            .lock()
            .map_err(|_| ExecutorError::OutcomeUnknown)?;
        if local.terminal.is_locked() {
            return Err(ExecutorError::TerminalLocked);
        }
        let index = task.ordinal as usize;
        let prior_attempt = *local
            .attempts
            .get(index)
            .ok_or(ExecutorError::InvalidMember)?;
        if !prior_attempt.permits(task.operation) {
            return Err(ExecutorError::RecoveryRequired);
        }
        if task.operation == ProviderOperation::Compensate && !local.permits_compensation(index) {
            return Err(ExecutorError::RecoveryRequired);
        }
        let attempt = local
            .attempts
            .get_mut(index)
            .ok_or(ExecutorError::InvalidMember)?;
        if prior_attempt != LocalAttempt::Conclusive
            || task.operation == ProviderOperation::Compensate
        {
            // Transition before the first await. A dropped caller can never
            // retain a prepare/execute capability after possible transmission.
            *attempt = LocalAttempt::OutcomeUnknown;
        }
        let recovering_compensation = prior_attempt == LocalAttempt::OutcomeUnknown
            && matches!(
                local.first_conclusive.get(index).cloned().flatten(),
                Some(ConclusiveObservation {
                    outcome: ProviderOutcome::AppliedExecuted | ProviderOutcome::AppliedAdopted,
                    ..
                })
            )
            && matches!(local.compensations.get(index), Some(None));
        let epoch = local
            .proof_epochs
            .get_mut(index)
            .ok_or(ExecutorError::InvalidMember)?;
        if (prior_attempt == LocalAttempt::Conclusive
            && task.operation != ProviderOperation::Compensate)
            || recovering_compensation
        {
            if *epoch != task.proof_epoch
                || (local
                    .first_conclusive
                    .get(index)
                    .cloned()
                    .flatten()
                    .is_none()
                    && local.compensations.get(index).cloned().flatten().is_none())
            {
                return Err(ExecutorError::OutcomeUnknown);
            }
        } else {
            if epoch.checked_add(1) != Some(task.proof_epoch) {
                return Err(ExecutorError::OutcomeUnknown);
            }
            *epoch = task.proof_epoch;
        }
        prior_attempt
    };

    if task.local_authority.check(&task.authority_permit) != LocalAuthorityCheck::Current {
        return Err(ExecutorError::AuthorityRejected);
    }
    let provider_call = MemberCall::from_executor(
        &task.admission,
        member,
        task.authority.fence(),
        task.authority.acquired_at(),
        task.authority.expires_at(),
    );
    task.diagnostics.increment(match task.operation {
        ProviderOperation::Prepare => DiagnosticsCounter::MemberPrepareCalls,
        ProviderOperation::Execute => DiagnosticsCounter::MemberExecuteCalls,
        ProviderOperation::Status => DiagnosticsCounter::MemberStatusCalls,
        ProviderOperation::Adopt => DiagnosticsCounter::MemberAdoptCalls,
        ProviderOperation::Compensate => DiagnosticsCounter::MemberCompensateCalls,
    });
    let _provider_in_flight = task.diagnostics.provider_in_flight();
    let (observation, response_error) = match tokio::time::timeout(
        PROVIDER_EFFECT_DEADLINE,
        invoke_provider_operation(task.provider.as_ref(), task.operation, &provider_call),
    )
    .await
    {
        Ok(result) => normalize_provider_result(task.operation, result),
        Err(_) => (
            Observation::OutcomeUnknown,
            Some(ExecutorError::OutcomeUnknown),
        ),
    };
    drop(_provider_in_flight);
    task.diagnostics.increment(match observation {
        Observation::Conclusive { .. } => DiagnosticsCounter::MemberConclusive,
        Observation::ReadyToPrepare => DiagnosticsCounter::MemberReadyToPrepare,
        Observation::PreparedNotRun => DiagnosticsCounter::MemberPreparedNotRun,
        Observation::NotTransmitted => DiagnosticsCounter::MemberNotTransmitted,
        Observation::OutcomeUnknown | Observation::NotFound | Observation::Pending => {
            DiagnosticsCounter::MemberAmbiguous
        }
    });

    // A same-process takeover, explicit local revocation, or local expiry may
    // happen while the provider future is in flight. Linearize the exact
    // post-effect authority check with the local transition and proof
    // construction, so a successor cannot revoke the permit in between.
    let proof = task
        .local_authority
        .linearize_current(&task.authority_permit, || {
            let mut local = task
                .local
                .lock()
                .map_err(|_| ExecutorError::OutcomeUnknown)?;
            let index = task.ordinal as usize;
            if local.proof_epochs.get(index).copied() != Some(task.proof_epoch) {
                return Err(ExecutorError::OutcomeUnknown);
            }
            let observed_conclusive = match &observation {
                Observation::Conclusive {
                    outcome,
                    evidence_commitment,
                    evidence,
                } => Some(ConclusiveObservation {
                    outcome: *outcome,
                    evidence_commitment: *evidence_commitment,
                    evidence: evidence.clone(),
                }),
                _ => None,
            };
            let first_conclusive = local
                .first_conclusive
                .get(index)
                .cloned()
                .ok_or(ExecutorError::InvalidMember)?;
            let compensation = local
                .compensations
                .get(index)
                .cloned()
                .ok_or(ExecutorError::InvalidMember)?;
            let recovered_member = local
                .recovered_members
                .get(index)
                .copied()
                .ok_or(ExecutorError::InvalidMember)?;
            match (first_conclusive, compensation, observed_conclusive) {
                (
                    Some(ConclusiveObservation {
                        outcome: ProviderOutcome::AppliedExecuted | ProviderOutcome::AppliedAdopted,
                        ..
                    }),
                    None,
                    Some(
                        observed @ ConclusiveObservation {
                            outcome: ProviderOutcome::CompensatedReconciled,
                            ..
                        },
                    ),
                ) if matches!(
                    task.operation,
                    ProviderOperation::Compensate
                        | ProviderOperation::Status
                        | ProviderOperation::Adopt
                ) =>
                {
                    *local
                        .compensations
                        .get_mut(index)
                        .ok_or(ExecutorError::InvalidMember)? = Some(observed);
                }
                // Once compensation is conclusive, the compensation proof is
                // the sole terminal contribution. A later old Applied status
                // observation must never mint a second established proof at
                // the compensation epoch.
                (Some(_), Some(_), Some(observed))
                    if observed.outcome != ProviderOutcome::CompensatedReconciled =>
                {
                    return Err(ExecutorError::InvalidProviderResponse);
                }
                (None, Some(_), Some(observed))
                    if observed.outcome != ProviderOutcome::CompensatedReconciled =>
                {
                    return Err(ExecutorError::InvalidProviderResponse);
                }
                (Some(_), Some(existing), Some(observed))
                    if observed.outcome == ProviderOutcome::CompensatedReconciled
                        && existing != observed =>
                {
                    return Err(ExecutorError::InvalidProviderResponse);
                }
                (Some(_), Some(existing), Some(observed))
                    if observed.outcome == ProviderOutcome::CompensatedReconciled
                        && existing == observed
                        && matches!(
                            task.operation,
                            ProviderOperation::Status | ProviderOperation::Adopt
                        ) => {}
                (None, Some(existing), Some(observed))
                    if observed.outcome == ProviderOutcome::CompensatedReconciled
                        && existing == observed
                        && matches!(
                            task.operation,
                            ProviderOperation::Status | ProviderOperation::Adopt
                        ) => {}
                (None, Some(_), Some(observed))
                    if observed.outcome == ProviderOutcome::CompensatedReconciled =>
                {
                    return Err(ExecutorError::InvalidProviderResponse);
                }
                // Compensation is a one-way transition only from an SDK
                // retained Applied proof. It cannot reinterpret a not-applied
                // member or replace arbitrary first conclusive evidence.
                (Some(_), _, Some(observed))
                    if observed.outcome == ProviderOutcome::CompensatedReconciled =>
                {
                    return Err(ExecutorError::InvalidProviderResponse);
                }
                (Some(first), _, Some(observed)) if first != observed => {
                    // A trusted provider must make its first conclusive outcome
                    // immutable. Preserve the original proof epoch and state so a
                    // contradictory later observation cannot change terminal phase
                    // or destroy a previously issued proof.
                    return Err(ExecutorError::InvalidProviderResponse);
                }
                (Some(_), _, None)
                    if response_error.is_none()
                        && task.operation != ProviderOperation::Compensate
                        && !matches!(&observation, Observation::NotTransmitted) =>
                {
                    // A provider that has durably classified this exact member may
                    // not later report a successful pending/absent/pre-effect state.
                    return Err(ExecutorError::InvalidProviderResponse);
                }
                (None, None, Some(observed))
                    if observed.outcome == ProviderOutcome::CompensatedReconciled
                        && recovered_member
                        && matches!(
                            task.operation,
                            ProviderOperation::Status | ProviderOperation::Adopt
                        ) =>
                {
                    // A successor has no SDK-local Applied proof, but the
                    // provider has durably reached the final compensation
                    // stage. Retain only that final proof; it cannot restore
                    // an effect-capable lane or be replaced by stale Applied.
                    *local
                        .compensations
                        .get_mut(index)
                        .ok_or(ExecutorError::InvalidMember)? = Some(observed);
                }
                (None, _, Some(observed))
                    if observed.outcome == ProviderOutcome::CompensatedReconciled =>
                {
                    return Err(ExecutorError::InvalidProviderResponse);
                }
                (None, _, Some(observed)) => {
                    *local
                        .first_conclusive
                        .get_mut(index)
                        .ok_or(ExecutorError::InvalidMember)? = Some(observed);
                }
                (Some(_), _, Some(_)) | (Some(_), _, None) | (None, _, None) => {}
            }
            let first_conclusive = local
                .first_conclusive
                .get(index)
                .cloned()
                .ok_or(ExecutorError::InvalidMember)?;
            let compensation = local
                .compensations
                .get(index)
                .cloned()
                .ok_or(ExecutorError::InvalidMember)?;
            if task.operation == ProviderOperation::Compensate
                && matches!(observation, Observation::NotTransmitted)
            {
                // A transport-proven non-transmission is the only direct
                // compensation result that restores the exact Applied proof
                // and permits an identical same-body retry.
                *local
                    .proof_epochs
                    .get_mut(index)
                    .ok_or(ExecutorError::InvalidMember)? = task
                    .proof_epoch
                    .checked_sub(1)
                    .ok_or(ExecutorError::OutcomeUnknown)?;
                *local
                    .attempts
                    .get_mut(index)
                    .ok_or(ExecutorError::InvalidMember)? = LocalAttempt::Conclusive;
                return Ok(None);
            }
            let compensation_pending = matches!(
                first_conclusive,
                Some(ConclusiveObservation {
                    outcome: ProviderOutcome::AppliedExecuted | ProviderOutcome::AppliedAdopted,
                    ..
                })
            ) && compensation.is_none()
                && (prior_attempt == LocalAttempt::OutcomeUnknown
                    || task.operation == ProviderOperation::Compensate);
            let has_conclusive = first_conclusive.is_some();
            let attempt = local
                .attempts
                .get_mut(index)
                .ok_or(ExecutorError::InvalidMember)?;
            *attempt = if compensation_pending {
                LocalAttempt::OutcomeUnknown
            } else if has_conclusive {
                LocalAttempt::Conclusive
            } else {
                match &observation {
                    Observation::NotTransmitted if task.operation == ProviderOperation::Prepare => {
                        LocalAttempt::ReadyToPrepare
                    }
                    Observation::NotTransmitted if task.operation == ProviderOperation::Execute => {
                        LocalAttempt::ReadyToExecute
                    }
                    // Status can identify an old durable pre-effect stage, but it
                    // never restores prepare/execute authority after this exact
                    // member crossed an ambiguity boundary. That lane is
                    // status/adopt-only until it becomes conclusive.
                    Observation::ReadyToPrepare
                        if task.operation == ProviderOperation::Status
                            && prior_attempt == LocalAttempt::OutcomeUnknown =>
                    {
                        LocalAttempt::OutcomeUnknown
                    }
                    Observation::PreparedNotRun
                        if task.operation == ProviderOperation::Status
                            && prior_attempt == LocalAttempt::OutcomeUnknown =>
                    {
                        LocalAttempt::OutcomeUnknown
                    }
                    Observation::ReadyToPrepare => LocalAttempt::ReadyToPrepare,
                    Observation::PreparedNotRun => LocalAttempt::ReadyToExecute,
                    Observation::Conclusive { .. } => LocalAttempt::Conclusive,
                    Observation::NotTransmitted
                    | Observation::OutcomeUnknown
                    | Observation::NotFound
                    | Observation::Pending => LocalAttempt::OutcomeUnknown,
                }
            };
            Ok(match &observation {
                Observation::Conclusive {
                    outcome,
                    evidence_commitment,
                    evidence,
                } => Some(AppliedProof {
                    registration: task.registration,
                    ordinal: task.ordinal,
                    operation: task.operation,
                    outcome: *outcome,
                    proof_epoch: task.proof_epoch,
                    evidence_commitment: *evidence_commitment,
                    evidence: evidence.clone(),
                    binding_commitment: proof_binding_commitment(
                        &binding,
                        *outcome,
                        task.proof_epoch,
                        *evidence_commitment,
                    ),
                }),
                _ => None,
            })
        })?;
    if let Some(error) = response_error {
        return Err(error);
    }
    CallResult::from_observation(observation, proof)
}

async fn invoke_provider_operation<P: MemberProvider>(
    provider: &P,
    operation: ProviderOperation,
    call: &MemberCall<'_>,
) -> Result<ProviderCallOutcome, P::Error> {
    match operation {
        ProviderOperation::Prepare => provider.prepare(call).await,
        ProviderOperation::Execute => provider.execute(call).await,
        ProviderOperation::Status => provider.status(call).await,
        ProviderOperation::Adopt => provider.adopt(call).await,
        ProviderOperation::Compensate => provider.compensate_member(call).await,
    }
}

fn normalize_provider_result<E>(
    operation: ProviderOperation,
    result: Result<ProviderCallOutcome, E>,
) -> (Observation, Option<ExecutorError>) {
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(_) => {
            return (
                Observation::OutcomeUnknown,
                Some(ExecutorError::OutcomeUnknown),
            );
        }
    };
    match outcome.into_parts() {
        ProviderCallOutcomeParts::NotTransmitted => (Observation::NotTransmitted, None),
        ProviderCallOutcomeParts::OutcomeUnknown => (Observation::OutcomeUnknown, None),
        ProviderCallOutcomeParts::NotFound => (Observation::NotFound, None),
        ProviderCallOutcomeParts::PreparedNotRun
            if matches!(
                operation,
                ProviderOperation::Prepare | ProviderOperation::Status
            ) =>
        {
            (Observation::PreparedNotRun, None)
        }
        ProviderCallOutcomeParts::ReadyToPrepare if operation == ProviderOperation::Status => {
            (Observation::ReadyToPrepare, None)
        }
        ProviderCallOutcomeParts::Pending(evidence) if evidence.len() <= MAX_STATUS_BYTES => {
            (Observation::Pending, None)
        }
        ProviderCallOutcomeParts::Conclusive { outcome, evidence }
            if !evidence.is_empty()
                && evidence.len() <= MAX_STATUS_BYTES
                && provider_outcome_allowed(operation, outcome) =>
        {
            (
                Observation::Conclusive {
                    outcome,
                    evidence_commitment: evidence_commitment(&evidence),
                    evidence,
                },
                None,
            )
        }
        ProviderCallOutcomeParts::Pending(_)
        | ProviderCallOutcomeParts::PreparedNotRun
        | ProviderCallOutcomeParts::ReadyToPrepare
        | ProviderCallOutcomeParts::Conclusive { .. }
        | ProviderCallOutcomeParts::Malformed => (
            Observation::OutcomeUnknown,
            Some(ExecutorError::InvalidProviderResponse),
        ),
    }
}

fn provider_outcome_allowed(operation: ProviderOperation, outcome: ProviderOutcome) -> bool {
    match operation {
        // A prepare never issues terminal evidence. A prior same-identity
        // effect must be re-observed through status/adopt after this local
        // call becomes ambiguous, so its proof operation cannot be confused
        // with a provider-side effect boundary.
        ProviderOperation::Prepare => false,
        ProviderOperation::Execute => matches!(
            outcome,
            ProviderOutcome::AppliedExecuted | ProviderOutcome::NotAppliedReconciled
        ),
        // Recovery operations report the provider's immutable first
        // conclusive classification. They must therefore be able to reproduce
        // an Executed observation (and its exact terminal commitment) rather
        // than translating it into Adopted merely because a successor read it.
        ProviderOperation::Status | ProviderOperation::Adopt => {
            matches!(
                outcome,
                ProviderOutcome::AppliedExecuted
                    | ProviderOutcome::AppliedAdopted
                    | ProviderOutcome::NotAppliedReconciled
                    | ProviderOutcome::CompensatedReconciled
            )
        }
        ProviderOperation::Compensate => outcome == ProviderOutcome::CompensatedReconciled,
    }
}

fn provider_outcome_tag(outcome: ProviderOutcome) -> u8 {
    outcome.tag()
}

fn evidence_commitment(evidence: &[u8]) -> [u8; 32] {
    opc_session_store::fenced_mutation_roster::roster_executor_evidence_commitment(evidence)
}

/// Immutable member contribution retained in a terminal record.
///
/// This deliberately excludes the current authority, proof epoch, leaf
/// certificate, and signature. Those live inputs are bound only by the
/// SDK-issued attestation preimage. Keeping this contribution fence-neutral
/// lets a successor reproduce the same terminal body after recovery.
fn stable_terminal_proof_commitment(
    registration: BackendRegistration,
    admission: &Admission,
    member: &Member,
    phase: Phase,
    outcome: ProviderOutcome,
    evidence: [u8; 32],
) -> Result<[u8; 32], ExecutorError> {
    if evidence == [0; 32] || registration.validate_for(admission).is_err() {
        return Err(ExecutorError::InvalidTerminal);
    }
    let (_, request_id, terminal_slot) = registration.consensus_parts();
    let binding = admission
        .binding_key(request_id.history_epoch())
        .map_err(|_| ExecutorError::InvalidTerminal)?;
    let descriptor = member.descriptor();
    let mut hasher = Sha256::new();
    hasher.update(b"openpacketcore/session-store/roster-attestation-stable-proof/v1\0");
    hasher.update([1]);
    hasher.update(binding.to_bytes());
    hasher.update(request_id.to_bytes());
    hasher.update(terminal_slot.as_bytes());
    hasher.update(admission.roster_id().as_bytes());
    hasher.update(admission.body_commitment());
    hasher.update([match phase {
        Phase::Established => 1,
        Phase::Aborted => 2,
    }]);
    hasher.update([member.ordinal()]);
    hasher.update(member.operation_id().as_bytes());
    hasher.update((descriptor.len() as u64).to_be_bytes());
    hasher.update(descriptor);
    hasher.update(stable_descriptor_commitment(descriptor));
    hasher.update(member.expected_version().to_be_bytes());
    hasher.update(admission.expected_generation().get().to_be_bytes());
    hasher.update([provider_outcome_tag(outcome)]);
    hasher.update(evidence);
    Ok(hasher.finalize().into())
}

fn retained_conclusive_matches(local: &LocalExecutionState, proof: &AppliedProof) -> bool {
    let index = proof.ordinal as usize;
    let observed = ConclusiveObservation {
        outcome: proof.outcome,
        evidence_commitment: proof.evidence_commitment,
        evidence: proof.evidence.clone(),
    };
    local.proof_epochs.get(index).copied() == Some(proof.proof_epoch)
        && match proof.outcome {
            ProviderOutcome::CompensatedReconciled => {
                local.compensations.get(index).cloned().flatten() == Some(observed)
            }
            _ => {
                matches!(local.compensations.get(index), Some(None))
                    && local.first_conclusive.get(index).cloned().flatten() == Some(observed)
            }
        }
}

fn terminal_attestation_signing_input(
    registration: &Registration,
    body: &TerminalBody,
    proof: &AppliedProof,
    certificate: &RosterAttestationLeafCertificatePartsV1,
) -> Result<RosterTerminalAttestationSigningInputV1, ExecutorError> {
    if certificate.role != RosterAttestationCertificateRoleV1::Executor
        || certificate.scope != registration.admission().scope().digest()
    {
        return Err(ExecutorError::AttestationUnavailable);
    }
    let member = registration
        .admission()
        .members()
        .get(proof.ordinal as usize)
        .ok_or(ExecutorError::InvalidTerminal)?;
    let (handle, request_id, terminal_slot) = registration.backend_registration().consensus_parts();
    let authority = registration.authority();
    let binding = registration
        .admission()
        .binding_key(request_id.history_epoch())
        .map_err(|_| ExecutorError::InvalidTerminal)?;
    Ok(RosterTerminalAttestationSigningInputV1 {
        profile: opc_session_store::fenced_mutation_roster::Profile::v1(),
        configuration_identity: certificate.configuration_identity,
        certificate_subject_identity_commitment: certificate.subject_identity_commitment,
        certificate_role: RosterAttestationCertificateRoleV1::Executor,
        binding: binding.to_bytes(),
        registration_handle: handle,
        registration_request_id: request_id.to_bytes(),
        registration_terminal_slot: *terminal_slot.as_bytes(),
        roster_id: *registration.admission().roster_id().as_bytes(),
        admission_commitment: registration.admission().body_commitment(),
        terminal_phase: match body.phase() {
            Phase::Established => opc_session_store::fenced_mutation_roster::Phase::Established,
            Phase::Aborted => opc_session_store::fenced_mutation_roster::Phase::Aborted,
        },
        terminal_body_commitment: body.commitment(),
        ordinal: member.ordinal(),
        member_operation_id: *member.operation_id().as_bytes(),
        descriptor: member.descriptor().to_vec(),
        descriptor_commitment: stable_descriptor_commitment(member.descriptor()),
        expected_member_version: member.expected_version(),
        admission_generation: registration.admission().expected_generation().get(),
        authority_scope: authority.scope().digest(),
        authority_key_canonical: session_key_canonical_digest_input(authority.key()),
        authority_owner: authority.owner().as_str().as_bytes().to_vec(),
        authority_fence: authority.fence().get(),
        authority_credential_id: authority.credential_id(),
        authority_generation: authority.generation().get(),
        authority_acquired_at: authority.acquired_at(),
        authority_expires_at: authority.expires_at(),
        proof_epoch: proof.proof_epoch,
        provider_operation: attested_operation(proof.operation),
        outcome: attested_outcome(proof.outcome),
        evidence: proof.evidence.clone(),
    })
}

fn attested_operation(operation: ProviderOperation) -> RosterProviderOperationV1 {
    match operation {
        ProviderOperation::Execute => RosterProviderOperationV1::Execute,
        ProviderOperation::Status => RosterProviderOperationV1::Status,
        ProviderOperation::Adopt => RosterProviderOperationV1::Adopt,
        ProviderOperation::Compensate => RosterProviderOperationV1::Compensate,
        ProviderOperation::Prepare => RosterProviderOperationV1::Prepare,
    }
}

fn attested_outcome(outcome: ProviderOutcome) -> RosterProviderOutcomeV1 {
    match outcome {
        ProviderOutcome::AppliedExecuted => RosterProviderOutcomeV1::AppliedExecuted,
        ProviderOutcome::AppliedAdopted => RosterProviderOutcomeV1::AppliedAdopted,
        ProviderOutcome::NotAppliedReconciled => RosterProviderOutcomeV1::NotAppliedReconciled,
        ProviderOutcome::CompensatedReconciled => RosterProviderOutcomeV1::CompensatedReconciled,
    }
}

fn stable_descriptor_commitment(descriptor: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"opc/session-store/protected-roster/descriptor/v1\0");
    hasher.update((descriptor.len() as u64).to_be_bytes());
    hasher.update(descriptor);
    hasher.finalize().into()
}

/// Bind an SDK-issued proof to every immutable provider-call input and the
/// current authenticated execution authority.  Only this digest is retained
/// in the opaque proof, keeping diagnostics and terminal bodies free of raw
/// descriptors, keys, owners, and credentials.
fn proof_binding_commitment(
    binding: &CallBinding<'_>,
    outcome: ProviderOutcome,
    proof_epoch: u64,
    evidence: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROOF_DOMAIN);
    hasher.update(PROOF_BINDING_DOMAIN);
    hasher.update(binding.registration.handle);
    hasher.update(binding.admission.roster_id().as_bytes());
    hasher.update(binding.admission.body_commitment());
    hasher.update([binding.member.ordinal()]);
    hasher.update(binding.member.operation_id().as_bytes());
    let descriptor = binding.member.descriptor();
    hasher.update((descriptor.len() as u64).to_be_bytes());
    hasher.update(descriptor);
    hasher.update(descriptor_commitment(descriptor));
    hasher.update(binding.member.expected_version().to_be_bytes());
    hasher.update(binding.admission.expected_generation().get().to_be_bytes());
    hasher.update(binding.authority.scope().digest());
    hasher.update(binding.authority.key().digest());
    hasher.update(owner_commitment(binding.authority.owner()));
    hasher.update(binding.authority.fence().get().to_be_bytes());
    hasher.update(credential_commitment(binding.authority.credential_id()));
    hasher.update(binding.authority.generation().get().to_be_bytes());
    hasher.update(
        binding
            .authority
            .acquired_at()
            .as_offset_datetime()
            .unix_timestamp_nanos()
            .to_be_bytes(),
    );
    hasher.update(
        binding
            .authority
            .expires_at()
            .as_offset_datetime()
            .unix_timestamp_nanos()
            .to_be_bytes(),
    );
    hasher.update(proof_epoch.to_be_bytes());
    hasher.update([binding.operation.tag(), provider_outcome_tag(outcome)]);
    hasher.update(evidence);
    hasher.finalize().into()
}

fn descriptor_commitment(descriptor: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROOF_DOMAIN);
    hasher.update(PROOF_DESCRIPTOR_DOMAIN);
    hasher.update((descriptor.len() as u64).to_be_bytes());
    hasher.update(descriptor);
    hasher.finalize().into()
}

fn owner_commitment(owner: &OwnerId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROOF_DOMAIN);
    hasher.update(PROOF_OWNER_DOMAIN);
    hasher.update((owner.as_str().len() as u64).to_be_bytes());
    hasher.update(owner.as_str().as_bytes());
    hasher.finalize().into()
}

fn credential_commitment(credential_id: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROOF_DOMAIN);
    hasher.update(PROOF_CREDENTIAL_DOMAIN);
    hasher.update(credential_id.to_be_bytes());
    hasher.finalize().into()
}

pub(crate) fn provider_scheduling_digest(authority: &AuthorityBinding) -> [u8; 32] {
    let tenant = authority.tenant().as_str().as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(PROVIDER_SCHEDULING_DOMAIN);
    hasher.update(authority.scope().digest());
    hasher.update((tenant.len() as u64).to_be_bytes());
    hasher.update(tenant);
    hasher.finalize().into()
}

#[cfg(test)]
mod local_authority_registry_tests {
    use super::*;
    use crate::fenced_mutation_roster::canonical::{
        AdmissionProposal, EstablishedMutation, MemberOperationId, Profile,
    };
    use bytes::Bytes;
    use opc_session_store::{SessionKeyType, StableId};
    use opc_types::{NetworkFunctionKind, TenantId};

    fn registration_request(roster_byte: u8) -> RegistrationRequest {
        let owner = OwnerId::new("owner").expect("bounded owner");
        let proposal = AdmissionProposal::new(
            Profile::v1(),
            RosterId::from_bytes([roster_byte; 16]).expect("nonzero roster ID"),
            vec![Member::new(
                0,
                MemberOperationId::from_bytes([roster_byte.wrapping_add(1); 16])
                    .expect("nonzero member operation ID"),
                vec![roster_byte],
                1,
            )
            .expect("bounded member")],
            EstablishedMutation::no_op(),
            vec![],
            vec![],
            vec![],
        )
        .expect("bounded proposal");
        let admission = Admission::authenticate(
            proposal,
            SessionKey {
                tenant: TenantId::from_static("tenant"),
                nf_kind: NetworkFunctionKind::smf(),
                key_type: SessionKeyType::PduSession,
                stable_id: StableId::new(Bytes::from(vec![roster_byte]))
                    .expect("bounded stable ID"),
            },
            Scope::from_digest([0xA1; 32]),
            owner.clone(),
            FenceToken::new(1),
            Generation::new(1),
        )
        .expect("authenticated admission");
        RegistrationRequest::new(admission, owner, FenceToken::new(1), 1, Generation::new(1))
            .expect("current original authority")
    }

    fn backend_registration(request: &RegistrationRequest) -> BackendRegistration {
        BackendRegistration::issue(
            [0xB1; 32],
            RequestId::bind(1, request.admission()).expect("bound request ID"),
            request.admission(),
        )
        .expect("backend registration")
    }

    #[test]
    fn conclusive_observation_requires_byte_exact_evidence() {
        let first = ConclusiveObservation {
            outcome: ProviderOutcome::AppliedExecuted,
            evidence_commitment: evidence_commitment(b"provider-evidence-a"),
            evidence: b"provider-evidence-a".to_vec(),
        };
        let same_commitment_different_bytes = ConclusiveObservation {
            outcome: ProviderOutcome::AppliedExecuted,
            evidence_commitment: first.evidence_commitment,
            evidence: b"provider-evidence-b".to_vec(),
        };
        assert!(
            first != same_commitment_different_bytes,
            "terminal proof preparation must retain and compare raw provider evidence"
        );
    }

    #[test]
    fn evidence_commitment_matches_terminal_bundle_verifier() {
        let evidence = b"provider-terminal-evidence";
        assert_eq!(
            evidence_commitment(evidence),
            opc_session_store::fenced_mutation_roster::roster_executor_evidence_commitment(
                evidence,
            )
        );
    }

    #[test]
    fn prepare_conclusive_is_not_a_terminal_proof() {
        assert!(!provider_outcome_allowed(
            ProviderOperation::Prepare,
            ProviderOutcome::AppliedExecuted,
        ));
        let (observation, error) = normalize_provider_result::<()>(
            ProviderOperation::Prepare,
            Ok(ProviderCallOutcome::conclusive(
                super::super::canonical::MemberDisposition::Applied,
                super::super::canonical::MemberAdoption::Executed,
                b"provider-proof".to_vec(),
            )
            .expect("bounded evidence")),
        );
        assert!(matches!(observation, Observation::OutcomeUnknown));
        assert_eq!(error, Some(ExecutorError::InvalidProviderResponse));
    }

    fn immutable_key(
        tenant_scoped_key_commitment: u8,
        admission_commitment: u8,
        roster_byte: u8,
    ) -> LocalAuthorityKey {
        LocalAuthorityKey {
            scope: Scope::from_digest([0xA1; 32]),
            // This is the digest of the complete immutable SessionKey, whose
            // input length-prefixes the tenant. The test uses distinct values
            // to model unrelated tenant/key bindings without retaining names.
            key_digest: [tenant_scoped_key_commitment; 32],
            roster_id: RosterId::from_bytes([roster_byte; 16]).expect("nonzero roster ID"),
            admission_commitment: [admission_commitment; 32],
        }
    }

    #[test]
    fn unrelated_tenant_bindings_make_progress_on_independent_shards() {
        let registry = LocalAuthorityRegistry::new(Arc::new(SystemClock));
        let first = immutable_key(0x41, 0x40, 0x51);
        let second = immutable_key(0x42, 0x40, 0x52);
        assert_ne!(registry.shard_index(&first), registry.shard_index(&second));

        let _first_shard = registry.lock_entries(&first).expect("first shard lock");
        assert!(
            registry.lock_entries(&second).is_ok(),
            "an unrelated tenant/scope/roster binding must not wait behind another shard"
        );
    }

    #[test]
    fn authority_shard_collision_is_local_and_has_no_global_lock() {
        let registry = LocalAuthorityRegistry::new(Arc::new(SystemClock));
        let first = immutable_key(0x41, 0x40, 0x61);
        let second = immutable_key(0x51, 0x50, 0x62);
        assert!(first != second);
        assert_eq!(registry.shard_index(&first), registry.shard_index(&second));

        let _held = registry.lock_entries(&first).expect("first shard lock");
        assert!(matches!(
            registry.inner.entries[registry.shard_index(&second)].try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
    }

    #[test]
    fn admission_reservation_precedes_contention_and_survives_ambiguity() {
        let registry = LocalAuthorityRegistry::new(Arc::new(SystemClock));
        let request = registration_request(0x21);
        let key = LocalAuthorityKey::for_admission(request.admission());

        let held = registry.lock_entries(&key).expect("test shard lock");
        assert!(matches!(
            registry.reserve_admission(&request),
            Err(ExecutorError::AuthorityRejected)
        ));
        assert_eq!(registry.inner.entry_count.load(Ordering::Acquire), 0);
        drop(held);

        let reservation = registry
            .reserve_admission(&request)
            .expect("pre-mutation reservation");
        assert_eq!(registry.inner.entry_count.load(Ordering::Acquire), 1);
        drop(reservation);
        assert_eq!(
            registry.inner.entry_count.load(Ordering::Acquire),
            1,
            "dropping an ambiguous call cannot release its recovery authority"
        );

        let permit = registry
            .install_admission(
                backend_registration(&request),
                request.admission(),
                request.authority(),
            )
            .expect("exact readback finalizes the retained reservation");
        assert!(registry.check(&permit) == LocalAuthorityCheck::Current);
    }

    #[test]
    fn postcommit_conversion_waits_for_its_short_shard_section_and_cannot_fail() {
        let registry = LocalAuthorityRegistry::new(Arc::new(SystemClock));
        let request = registration_request(0x22);
        let reservation = registry
            .reserve_admission(&request)
            .expect("pre-mutation reservation");
        let registration = backend_registration(&request);
        let key = LocalAuthorityKey::for_admission(request.admission());
        let held = registry.lock_entries(&key).expect("test shard lock");
        let admission = request.admission().clone();
        let converting_registry = registry.clone();
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let conversion = std::thread::spawn(move || {
            started_tx.send(()).expect("signal conversion start");
            converting_registry.finalize_admission(reservation, registration, &admission)
        });
        started_rx.recv().expect("conversion started");
        drop(held);
        let permit = conversion
            .join()
            .expect("conversion thread does not panic")
            .expect("postcommit conversion cannot fail on transient shard contention");
        assert!(registry.check(&permit) == LocalAuthorityCheck::Current);
    }

    #[test]
    fn terminal_authority_entries_do_not_consume_provider_live_capacity() {
        let registry = LocalAuthorityRegistry::new(Arc::new(SystemClock));
        let exemplar = registration_request(0x23);
        for value in 1..=MAX_PROVIDER_IN_FLIGHT {
            let mut roster_bytes = [0u8; 16];
            roster_bytes.copy_from_slice(&(value as u128).to_be_bytes());
            let key = LocalAuthorityKey {
                scope: Scope::from_digest([0xA2; 32]),
                key_digest: [(value & 0xff) as u8; 32],
                roster_id: RosterId::from_bytes(roster_bytes).expect("nonzero roster ID"),
                admission_commitment: [((value >> 8) as u8).wrapping_add(1); 32],
            };
            assert!(registry.reserve_entry());
            registry.lock_entries_after_durable_read(&key).insert(
                key,
                LocalAuthorityEntry {
                    registration: None,
                    authority: exemplar.authority().clone(),
                    generation: 1,
                },
            );
        }
        assert_eq!(
            registry.inner.entry_count.load(Ordering::Acquire),
            MAX_PROVIDER_IN_FLIGHT
        );

        let next = registration_request(0x24);
        let reservation = registry
            .reserve_admission(&next)
            .expect("the independent bounded authority ledger has remaining capacity");
        assert_eq!(
            registry.inner.entry_count.load(Ordering::Acquire),
            MAX_PROVIDER_IN_FLIGHT + 1
        );
        registry.release_admission_reservation(&reservation);
    }
}

#[cfg(test)]
mod production_runtime_cut_matrix_tests {
    use super::*;
    use crate::fenced_mutation_roster::canonical::{
        AdmissionProposal, EstablishedMutation, MemberAdoption, MemberCall, MemberDisposition,
        MemberOperationId, Profile,
    };
    use async_trait::async_trait;
    use bytes::Bytes;
    use opc_consensus::{derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch};
    use opc_session_store::{SessionConsensusIdentity, SessionKeyType, StableId};
    use opc_types::{NetworkFunctionKind, TenantId};
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::SigningKey;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Copy)]
    enum Cut {
        PreparePending,
        PreparedBeforeRun,
        AppliedBeforeFinalize,
        FiveProofsBeforeSixthEffect,
        AllSixBeforeTerminalRequest,
    }

    impl Cut {
        const ALL: [Self; 5] = [
            Self::PreparePending,
            Self::PreparedBeforeRun,
            Self::AppliedBeforeFinalize,
            Self::FiveProofsBeforeSixthEffect,
            Self::AllSixBeforeTerminalRequest,
        ];

        const fn name(self) -> &'static str {
            match self {
                Self::PreparePending => "prepare-pending",
                Self::PreparedBeforeRun => "prepared-before-run",
                Self::AppliedBeforeFinalize => "applied-before-finalize",
                Self::FiveProofsBeforeSixthEffect => "five-proofs-before-sixth-effect",
                Self::AllSixBeforeTerminalRequest => "all-six-before-terminal-request",
            }
        }
    }

    struct CutProvider {
        prepare_pending: bool,
        prepare_calls: AtomicUsize,
        execute_calls: AtomicUsize,
        status_calls: AtomicUsize,
        adopt_calls: AtomicUsize,
        calls: Mutex<Vec<(ProviderOperation, u8, [u8; 16])>>,
    }

    impl CutProvider {
        fn for_cut(cut: Cut) -> Self {
            Self {
                prepare_pending: matches!(cut, Cut::PreparePending),
                prepare_calls: AtomicUsize::new(0),
                execute_calls: AtomicUsize::new(0),
                status_calls: AtomicUsize::new(0),
                adopt_calls: AtomicUsize::new(0),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn record(&self, operation: ProviderOperation, call: &MemberCall<'_>) {
            self.calls.lock().expect("test provider call ledger").push((
                operation,
                call.ordinal(),
                *call.operation_id().as_bytes(),
            ));
        }

        fn applied(call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
            ProviderCallOutcome::conclusive(
                MemberDisposition::Applied,
                MemberAdoption::Executed,
                vec![0xC0, call.ordinal()],
            )
            .map_err(|_| ())
        }
    }

    #[async_trait]
    impl MemberProvider for CutProvider {
        type Error = ();

        async fn prepare(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, Self::Error> {
            self.prepare_calls.fetch_add(1, Ordering::SeqCst);
            self.record(ProviderOperation::Prepare, call);
            if self.prepare_pending {
                ProviderCallOutcome::pending(vec![0xB0, call.ordinal()]).map_err(|_| ())
            } else {
                Ok(ProviderCallOutcome::prepared_not_run())
            }
        }

        async fn execute(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, Self::Error> {
            self.execute_calls.fetch_add(1, Ordering::SeqCst);
            self.record(ProviderOperation::Execute, call);
            Self::applied(call)
        }

        async fn status(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, Self::Error> {
            self.status_calls.fetch_add(1, Ordering::SeqCst);
            self.record(ProviderOperation::Status, call);
            Self::applied(call)
        }

        async fn adopt(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, Self::Error> {
            self.adopt_calls.fetch_add(1, Ordering::SeqCst);
            self.record(ProviderOperation::Adopt, call);
            Self::applied(call)
        }
    }

    #[derive(Clone, Copy)]
    enum CompensationMode {
        AllApplied,
        Conclusive,
        NotTransmittedThenConclusive,
        OutcomeUnknownThenStatusCompensated,
        ConclusiveThenStaleAppliedStatus,
    }

    struct CompensationProvider {
        mode: CompensationMode,
        compensate_calls: AtomicUsize,
        status_calls: AtomicUsize,
    }

    impl CompensationProvider {
        fn new(mode: CompensationMode) -> Self {
            Self {
                mode,
                compensate_calls: AtomicUsize::new(0),
                status_calls: AtomicUsize::new(0),
            }
        }

        fn applied(call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
            ProviderCallOutcome::conclusive(
                MemberDisposition::Applied,
                MemberAdoption::Executed,
                vec![0xD4, call.ordinal()],
            )
            .map_err(|_| ())
        }

        fn not_applied(call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
            ProviderCallOutcome::conclusive(
                MemberDisposition::NotApplied,
                MemberAdoption::Reconciled,
                vec![0xD5, call.ordinal()],
            )
            .map_err(|_| ())
        }

        fn compensated(call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
            ProviderCallOutcome::conclusive(
                MemberDisposition::Compensated,
                MemberAdoption::Reconciled,
                vec![0xD6, call.ordinal()],
            )
            .map_err(|_| ())
        }
    }

    #[async_trait]
    impl MemberProvider for CompensationProvider {
        type Error = ();

        async fn prepare(
            &self,
            _call: &MemberCall<'_>,
        ) -> Result<ProviderCallOutcome, Self::Error> {
            Ok(ProviderCallOutcome::prepared_not_run())
        }

        async fn execute(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, Self::Error> {
            if call.ordinal() == 0 || matches!(self.mode, CompensationMode::AllApplied) {
                Self::applied(call)
            } else {
                Self::not_applied(call)
            }
        }

        async fn status(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, Self::Error> {
            self.status_calls.fetch_add(1, Ordering::SeqCst);
            if call.ordinal() != 0 {
                if matches!(self.mode, CompensationMode::AllApplied) {
                    return Self::applied(call);
                }
                return Self::not_applied(call);
            }
            match self.mode {
                CompensationMode::AllApplied => Self::applied(call),
                CompensationMode::ConclusiveThenStaleAppliedStatus => Self::applied(call),
                CompensationMode::Conclusive
                | CompensationMode::OutcomeUnknownThenStatusCompensated => Self::compensated(call),
                CompensationMode::NotTransmittedThenConclusive => Self::applied(call),
            }
        }

        async fn adopt(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, Self::Error> {
            self.status(call).await
        }

        async fn compensate_member(
            &self,
            call: &MemberCall<'_>,
        ) -> Result<ProviderCallOutcome, Self::Error> {
            let attempt = self.compensate_calls.fetch_add(1, Ordering::SeqCst);
            match self.mode {
                CompensationMode::NotTransmittedThenConclusive if attempt == 0 => {
                    Ok(ProviderCallOutcome::not_transmitted())
                }
                CompensationMode::OutcomeUnknownThenStatusCompensated => {
                    Ok(ProviderCallOutcome::outcome_unknown())
                }
                _ => Self::compensated(call),
            }
        }
    }

    #[derive(Default)]
    struct CutBackendState {
        admission: Option<Arc<Admission>>,
        registration: Option<BackendRegistration>,
        current_authority: Option<AuthorityBinding>,
        committed: Option<CommittedTerminal>,
        compact_next_terminal: bool,
        durable_mutations: usize,
    }

    #[derive(Default)]
    struct CutBackend {
        state: Mutex<CutBackendState>,
    }

    impl CutBackend {
        fn mutations(&self) -> usize {
            self.state
                .lock()
                .expect("test backend state")
                .durable_mutations
        }

        fn compact_next_terminal(&self) {
            self.state
                .lock()
                .expect("test backend state")
                .compact_next_terminal = true;
        }

        fn current(
            state: &CutBackendState,
            admission: &Admission,
            registration: BackendRegistration,
            authority: &AuthorityBinding,
        ) -> bool {
            state.admission.as_deref() == Some(admission)
                && state.registration == Some(registration)
                && state.current_authority.as_ref() == Some(authority)
        }
    }

    #[async_trait]
    impl RosterExecutorBackend for CutBackend {
        type Error = ();

        async fn register(
            &self,
            request: &RegistrationRequest,
        ) -> Result<RegistrationDecision, Self::Error> {
            let mut state = self.state.lock().expect("test backend state");
            if state.admission.is_some() {
                return Ok(RegistrationDecision::AdmissionReplayed);
            }
            let registration = BackendRegistration::issue(
                [0xA5; 32],
                RequestId::bind(1, request.admission()).expect("test request ID"),
                request.admission(),
            )
            .expect("test registration");
            state.admission = Some(Arc::clone(&request.admission));
            state.registration = Some(registration);
            state.current_authority = Some(request.authority.clone());
            state.durable_mutations += 1;
            Ok(RegistrationDecision::FreshlyAdmitted(registration))
        }

        async fn admission_status(
            &self,
            request: AdmissionStatusRequest<'_>,
        ) -> Result<RegistrationDecision, Self::Error> {
            let state = self.state.lock().expect("test backend state");
            match (
                &state.admission,
                state.registration,
                &state.current_authority,
            ) {
                (Some(admission), Some(registration), Some(authority))
                    if admission.as_ref() == request.registration().admission()
                        && authority == request.registration().authority() =>
                {
                    if let Some(committed) = state.committed.clone() {
                        Ok(RegistrationDecision::Terminal {
                            registration,
                            admission: Arc::clone(admission),
                            committed: Box::new(committed),
                        })
                    } else {
                        Ok(RegistrationDecision::PollAdmitted {
                            registration,
                            admission: Arc::clone(admission),
                        })
                    }
                }
                _ => Ok(RegistrationDecision::Reject(BackendRejection::Authority)),
            }
        }

        async fn recover(
            &self,
            request: &RecoveryRequest,
        ) -> Result<RegistrationDecision, Self::Error> {
            let mut state = self.state.lock().expect("test backend state");
            let Some(admission) = state.admission.as_ref() else {
                return Ok(RegistrationDecision::Reject(BackendRejection::Authority));
            };
            let Some(registration) = state.registration else {
                return Ok(RegistrationDecision::Reject(BackendRejection::Authority));
            };
            let Some(current) = state.current_authority.as_ref() else {
                return Ok(RegistrationDecision::Reject(BackendRejection::Authority));
            };
            if request.lookup().scope() != admission.scope()
                || request.lookup().roster_id() != admission.roster_id()
                || request.authority().key() != admission.key()
                || request.authority().fence() <= admission.admission_fence()
                || request.authority().fence() < current.fence()
                || request.authority().acquired_at() > Timestamp::now_utc()
                || request.authority().expires_at() <= Timestamp::now_utc()
            {
                return Ok(RegistrationDecision::Reject(BackendRejection::Authority));
            }
            if request.authority().fence() > current.fence() {
                state.current_authority = Some(request.authority().clone());
            }
            let admission = Arc::clone(state.admission.as_ref().expect("admission retained"));
            if let Some(committed) = state.committed.clone() {
                Ok(RegistrationDecision::Terminal {
                    registration,
                    admission,
                    committed: Box::new(committed),
                })
            } else {
                Ok(RegistrationDecision::PollAdmitted {
                    registration,
                    admission,
                })
            }
        }

        async fn terminal_status(
            &self,
            request: TerminalStatusRequest<'_>,
        ) -> Result<TerminalStatusDecision, Self::Error> {
            let state = self.state.lock().expect("test backend state");
            if !Self::current(
                &state,
                request.admission(),
                request.registration(),
                request.authority(),
            ) {
                return Ok(TerminalStatusDecision::Reject(BackendRejection::Authority));
            }
            Ok(match state.committed.clone() {
                Some(committed) => TerminalStatusDecision::Recorded(Box::new(committed)),
                None => TerminalStatusDecision::Admitted,
            })
        }

        async fn terminalize(
            &self,
            request: TerminalizeRequest<'_>,
        ) -> Result<TerminalizeDecision, Self::Error> {
            let mut state = self.state.lock().expect("test backend state");
            if !Self::current(
                &state,
                request.admission(),
                request.registration(),
                request.authority(),
            ) {
                return Ok(TerminalizeDecision::Reject(BackendRejection::Authority));
            }
            if let Some(committed) = state.committed.clone() {
                return Ok(TerminalizeDecision::Replayed(committed));
            }
            let committed = CommittedTerminal::issue(
                request.registration(),
                request.admission(),
                request.authority(),
                request.body(),
                ConsensusCommitMetadata::issue(2, 2, Timestamp::now_utc())
                    .expect("test commit metadata"),
            )
            .expect("validated test terminal");
            if state.compact_next_terminal {
                state.compact_next_terminal = false;
                let tombstone =
                    TerminalConflictTombstone::new(request.admission(), committed.record())
                        .expect("validated compact terminal binding");
                return Ok(TerminalizeDecision::Compacted {
                    history_epoch: committed.record().request_id().history_epoch(),
                    tombstone,
                });
            }
            state.committed = Some(committed.clone());
            state.durable_mutations += 1;
            Ok(TerminalizeDecision::Terminalized(committed))
        }
    }

    struct CutAttestor {
        root: RosterAttestationTrustRootV1,
        key: SigningKey,
        certificate: RosterAttestationLeafCertificatePartsV1,
    }

    impl CutAttestor {
        fn new(scope: Scope) -> Arc<Self> {
            let root_key = SigningKey::from_bytes((&[0x31; 32]).into()).expect("root key");
            let key = SigningKey::from_bytes((&[0x32; 32]).into()).expect("executor key");
            let root = RosterAttestationTrustRootV1::new(
                [0x71; 32],
                Self::compressed_key(root_key.verifying_key()),
            )
            .expect("test root");
            let cluster = ConsensusClusterId::new("runtime-cut-matrix").expect("cluster ID");
            let epoch = ConsensusConfigurationEpoch::new(1).expect("configuration epoch");
            let configuration = derive_configuration_id(cluster, epoch, &[]);
            let now = Timestamp::now_utc();
            let mut certificate = RosterAttestationLeafCertificatePartsV1 {
                root_id: root.root_id(),
                role: RosterAttestationCertificateRoleV1::Executor,
                configuration_identity: SessionConsensusIdentity::new(
                    cluster,
                    configuration,
                    epoch,
                ),
                scope: scope.digest(),
                subject_identity_commitment: [0x72; 32],
                leaf_epoch: 1,
                key_id: [0x73; 32],
                not_before: now.add_seconds(-60).expect("not before"),
                not_after: now.add_seconds(60).expect("not after"),
                public_key: Self::compressed_key(key.verifying_key()),
                root_signature: [0; 64],
            };
            certificate.root_signature = Self::sign(
                &root_key,
                RosterAttestationLeafCertificateV1::signing_digest(&certificate)
                    .expect("certificate digest"),
            );
            Arc::new(Self {
                root,
                key,
                certificate,
            })
        }

        fn compressed_key(key: &p256::ecdsa::VerifyingKey) -> [u8; 33] {
            key.to_sec1_point(true)
                .as_bytes()
                .try_into()
                .expect("compressed P-256 key")
        }

        fn sign(key: &SigningKey, digest: [u8; 32]) -> [u8; 64] {
            let signature: p256::ecdsa::Signature = key.sign_prehash(&digest).expect("sign digest");
            signature.normalize_s().to_bytes().into()
        }
    }

    #[async_trait]
    impl FencedMutationRosterExecutorAttestor for CutAttestor {
        fn trust_root(&self) -> RosterAttestationTrustRootV1 {
            self.root.clone()
        }

        fn executor_certificate(
            &self,
        ) -> Result<RosterAttestationLeafCertificatePartsV1, ExecutorError> {
            Ok(self.certificate.clone())
        }

        async fn sign_terminal(
            &self,
            input: &RosterTerminalAttestationSigningInputV1,
        ) -> Result<[u8; 64], ExecutorError> {
            Ok(Self::sign(
                &self.key,
                input
                    .digest()
                    .map_err(|_| ExecutorError::AttestationUnavailable)?,
            ))
        }
    }

    fn request() -> RegistrationRequest {
        request_with_members(6)
    }

    fn request_with_members(width: u8) -> RegistrationRequest {
        let owner = OwnerId::new("runtime-cut-owner").expect("owner");
        let members = (0_u8..width)
            .map(|ordinal| {
                Member::new(
                    ordinal,
                    MemberOperationId::from_bytes([ordinal + 1; 16]).expect("operation ID"),
                    vec![0xD0, ordinal],
                    u64::from(ordinal) + 1,
                )
                .expect("member")
            })
            .collect();
        let proposal = AdmissionProposal::new(
            Profile::v1(),
            RosterId::from_bytes([0xD1; 16]).expect("roster ID"),
            members,
            EstablishedMutation::no_op(),
            b"runtime-cut-plan".to_vec(),
            b"runtime-cut-checkpoint".to_vec(),
            b"runtime-cut-result".to_vec(),
        )
        .expect("proposal");
        let admission = Admission::authenticate(
            proposal,
            SessionKey {
                tenant: TenantId::from_static("runtime-cut-tenant"),
                nf_kind: NetworkFunctionKind::smf(),
                key_type: SessionKeyType::PduSession,
                stable_id: StableId::new(Bytes::from_static(b"runtime-cut-key"))
                    .expect("stable ID"),
            },
            Scope::from_digest([0xD2; 32]),
            owner.clone(),
            FenceToken::new(1),
            Generation::new(1),
        )
        .expect("admission");
        RegistrationRequest::new(admission, owner, FenceToken::new(1), 7, Generation::new(1))
            .expect("registration request")
    }

    fn successor(request: &RegistrationRequest, fence: u64) -> RecoveryRequest {
        RecoveryRequest::new(
            request.admission().scope(),
            request.admission().roster_id(),
            request.admission().key().clone(),
            OwnerId::new("runtime-cut-successor").expect("successor owner"),
            FenceToken::new(fence),
            8,
            Generation::new(1),
        )
        .expect("successor recovery")
    }

    fn expired_successor(request: &RegistrationRequest) -> RecoveryRequest {
        let expires_at = Timestamp::now_utc()
            .add_seconds(-60)
            .expect("expired lease timestamp");
        RecoveryRequest::new_with_lease_metadata(
            RecoveryLookup::new(request.admission().scope(), request.admission().roster_id()),
            request.admission().key().clone(),
            OwnerId::new("runtime-cut-expired").expect("expired owner"),
            FenceToken::new(3),
            9,
            Generation::new(1),
            LeaseMetadata::new(
                expires_at
                    .add_seconds(-60)
                    .expect("expired lease acquired timestamp"),
                expires_at,
            ),
        )
        .expect("expired successor shape")
    }

    fn executor(
        provider: Arc<CutProvider>,
        backend: Arc<CutBackend>,
        scope: Scope,
    ) -> RosterExecutor<CutProvider, CutBackend> {
        RosterExecutor::new(
            provider,
            backend,
            CutAttestor::new(scope),
            NonZeroUsize::new(6).expect("provider capacity"),
        )
    }

    fn compensation_executor(
        provider: Arc<CompensationProvider>,
        backend: Arc<CutBackend>,
        scope: Scope,
    ) -> RosterExecutor<CompensationProvider, CutBackend> {
        RosterExecutor::new(
            provider,
            backend,
            CutAttestor::new(scope),
            NonZeroUsize::new(2).expect("provider capacity"),
        )
    }

    fn conclusive(result: CallResult) -> AppliedProof {
        match result {
            CallResult::Conclusive(proof) => *proof,
            _ => panic!("expected SDK-issued conclusive proof"),
        }
    }

    fn recovered(result: RecoveryResult) -> Registration {
        match result {
            RecoveryResult::PollAdmitted(recovered) => recovered.registration,
            _ => panic!("expected nonterminal admitted recovery"),
        }
    }

    #[tokio::test]
    async fn production_runtime_recovery_cut_matrix_preserves_two_mutation_boundary() {
        for cut in Cut::ALL {
            let cut_name = cut.name();
            let request = request();
            let provider = Arc::new(CutProvider::for_cut(cut));
            let backend = Arc::new(CutBackend::default());
            let first = executor(
                Arc::clone(&provider),
                Arc::clone(&backend),
                request.admission().scope(),
            );
            let registration = first.register(request.clone()).await.expect(cut_name);
            assert_eq!(
                backend.mutations(),
                1,
                "{}: PollAdmitted is the sole durable mutation",
                cut.name()
            );
            assert_eq!(
                registration.admission().roster_id(),
                request.admission().roster_id()
            );
            assert_eq!(
                registration.admission().members(),
                request.admission().members()
            );
            assert_eq!(
                registration.admission().protected_plan(),
                request.admission().protected_plan()
            );

            match cut {
                Cut::PreparePending => {
                    // A local pending prepare does not create a second quorum mutation.
                    assert!(matches!(
                        first.prepare(&registration, 0).await,
                        Ok(CallResult::Pending)
                    ));
                    let second = executor(
                        Arc::clone(&provider),
                        Arc::clone(&backend),
                        request.admission().scope(),
                    );
                    let recovery = successor(&request, 2);
                    let recovered = recovered(second.recover(recovery).await.expect(cut_name));
                    assert!(matches!(
                        second.execute(&recovered, 0).await,
                        Err(ExecutorError::RecoveryRequired)
                    ));
                    assert!(matches!(
                        second.status(&recovered, 0).await,
                        Ok(CallResult::Conclusive(_))
                    ));
                    assert_eq!(
                        provider.execute_calls.load(Ordering::SeqCst),
                        0,
                        "{}: recovery cannot replay execute",
                        cut.name()
                    );
                }
                Cut::PreparedBeforeRun => {
                    assert!(matches!(
                        first.prepare(&registration, 0).await,
                        Ok(CallResult::PreparedNotRun)
                    ));
                    assert!(matches!(
                        first.execute(&registration, 0).await,
                        Ok(CallResult::Conclusive(_))
                    ));
                    assert_eq!(
                        backend.mutations(),
                        1,
                        "{}: provider work is local",
                        cut.name()
                    );
                }
                Cut::AppliedBeforeFinalize => {
                    let mut proofs = Vec::with_capacity(6);
                    for ordinal in 0_u8..6 {
                        assert!(matches!(
                            first.prepare(&registration, ordinal).await,
                            Ok(CallResult::PreparedNotRun)
                        ));
                        proofs.push(conclusive(
                            first.execute(&registration, ordinal).await.expect(cut_name),
                        ));
                    }
                    let old_prepared = first
                        .prepare_terminal(&registration, proofs.clone())
                        .await
                        .expect("complete old-fence body");
                    let second = executor(
                        Arc::clone(&provider),
                        Arc::clone(&backend),
                        request.admission().scope(),
                    );
                    let recovered = recovered(
                        second
                            .recover(successor(&request, 2))
                            .await
                            .expect(cut_name),
                    );
                    assert_eq!(
                        recovered.admission().roster_id(),
                        registration.admission().roster_id(),
                        "{}: successor recovers the caller-owned stable roster ID",
                        cut.name()
                    );
                    assert_eq!(
                        recovered.admission().members(),
                        registration.admission().members(),
                        "{}: successor recovers the exact immutable member roster",
                        cut.name()
                    );
                    assert!(matches!(
                        first.terminalize(&registration, &old_prepared).await,
                        Err(ExecutorError::AuthorityRejected)
                    ));
                    assert!(matches!(
                        second.recover(expired_successor(&request)).await,
                        Err(ExecutorError::AuthorityRejected)
                    ));
                    proofs.clear();
                    for ordinal in 0_u8..6 {
                        proofs.push(conclusive(
                            second.status(&recovered, ordinal).await.expect(cut_name),
                        ));
                    }
                    let prepared = second
                        .prepare_terminal(&recovered, proofs)
                        .await
                        .expect(cut_name);
                    assert_eq!(
                        prepared.body.commitment(),
                        old_prepared.body.commitment(),
                        "{}: successor proof bindings change but terminal body remains stable",
                        cut.name()
                    );
                    assert_eq!(backend.mutations(), 1, "{}: preparing is local", cut.name());
                    assert!(
                        matches!(
                            first.recover(successor(&request, 1)).await,
                            Err(ExecutorError::AuthorityRejected)
                        ),
                        "{}: stale authority is rejected",
                        cut.name()
                    );
                    assert_eq!(
                        second
                            .terminalize(&recovered, &prepared)
                            .await
                            .expect(cut_name)
                            .phase(),
                        Phase::Established
                    );
                }
                Cut::FiveProofsBeforeSixthEffect => {
                    for ordinal in 0_u8..5 {
                        assert!(matches!(
                            first.prepare(&registration, ordinal).await,
                            Ok(CallResult::PreparedNotRun)
                        ));
                        let _ = conclusive(
                            first.execute(&registration, ordinal).await.expect(cut_name),
                        );
                    }
                    let second = executor(
                        Arc::clone(&provider),
                        Arc::clone(&backend),
                        request.admission().scope(),
                    );
                    let recovered = recovered(
                        second
                            .recover(successor(&request, 2))
                            .await
                            .expect(cut_name),
                    );
                    assert!(matches!(
                        second.execute(&recovered, 5).await,
                        Err(ExecutorError::RecoveryRequired)
                    ));
                    assert!(matches!(
                        second.adopt(&recovered, 5).await,
                        Ok(CallResult::Conclusive(_))
                    ));
                    assert_eq!(
                        provider.execute_calls.load(Ordering::SeqCst),
                        5,
                        "{}: sixth effect is never replayed",
                        cut.name()
                    );
                }
                Cut::AllSixBeforeTerminalRequest => {
                    let mut proofs = Vec::with_capacity(6);
                    for ordinal in 0_u8..6 {
                        assert!(matches!(
                            first.prepare(&registration, ordinal).await,
                            Ok(CallResult::PreparedNotRun)
                        ));
                        proofs.push(conclusive(
                            first.execute(&registration, ordinal).await.expect(cut_name),
                        ));
                    }
                    assert!(
                        matches!(
                            first
                                .prepare_terminal(&registration, proofs[..5].to_vec())
                                .await,
                            Err(ExecutorError::InvalidTerminal)
                        ),
                        "{}: terminalization requires all SDK proofs",
                        cut.name()
                    );
                    let prepared = first
                        .prepare_terminal(&registration, proofs)
                        .await
                        .expect(cut_name);
                    assert_eq!(
                        prepared.body.record().request_id(),
                        registration.backend_registration().request_id()
                    );
                    assert_eq!(
                        prepared.body.protected_checkpoint(),
                        request.admission().terminal_checkpoint()
                    );
                    assert_eq!(
                        prepared.body.protected_result(),
                        request.admission().terminal_result()
                    );
                    assert_eq!(
                        backend.mutations(),
                        1,
                        "{}: all local proofs converge before terminal request",
                        cut.name()
                    );
                    assert_eq!(
                        first
                            .terminalize(&registration, &prepared)
                            .await
                            .expect(cut_name)
                            .phase(),
                        Phase::Established
                    );
                }
            }
            if matches!(
                cut,
                Cut::AppliedBeforeFinalize | Cut::AllSixBeforeTerminalRequest
            ) {
                assert_eq!(
                    backend.mutations(),
                    2,
                    "{}: exactly one atomic terminalization follows PollAdmitted",
                    cut.name()
                );
            } else {
                assert_eq!(
                    backend.mutations(),
                    1,
                    "{}: no terminal request crossed the quorum boundary",
                    cut.name()
                );
            }
        }
    }

    #[tokio::test]
    async fn compacted_terminal_is_not_counted_as_outcome_unknown() {
        let request = request_with_members(1);
        let provider = Arc::new(CompensationProvider::new(CompensationMode::AllApplied));
        let backend = Arc::new(CutBackend::default());
        let executor =
            compensation_executor(provider, Arc::clone(&backend), request.admission().scope());
        let registration = executor.register(request).await.expect("registered");
        assert!(matches!(
            executor.prepare(&registration, 0).await,
            Ok(CallResult::PreparedNotRun)
        ));
        let proof = conclusive(executor.execute(&registration, 0).await.expect("applied"));
        let prepared = executor
            .prepare_terminal(&registration, vec![proof])
            .await
            .expect("established terminal body");

        backend.compact_next_terminal();
        assert!(matches!(
            executor.terminalize(&registration, &prepared).await,
            Err(ExecutorError::TerminalPayloadCompacted)
        ));
        let diagnostics = executor.diagnostics().snapshot();
        assert_eq!(diagnostics.terminalize_calls, 1);
        assert_eq!(diagnostics.terminal_payload_compacted, 1);
        assert_eq!(diagnostics.terminalize_outcome_unknown, 0);
    }

    #[tokio::test]
    async fn compensate_not_transmitted_restores_identical_compensation_retry_and_original_applied_proof(
    ) {
        let request = request_with_members(2);
        let provider = Arc::new(CompensationProvider::new(
            CompensationMode::NotTransmittedThenConclusive,
        ));
        let backend = Arc::new(CutBackend::default());
        let executor = compensation_executor(
            Arc::clone(&provider),
            Arc::clone(&backend),
            request.admission().scope(),
        );
        let registration = executor.register(request).await.expect("registered");
        assert!(matches!(
            executor.prepare(&registration, 0).await,
            Ok(CallResult::PreparedNotRun)
        ));
        let _applied = conclusive(executor.execute(&registration, 0).await.expect("applied"));
        let not_applied = conclusive(
            executor
                .status(&registration, 1)
                .await
                .expect("complete aborting roster observation"),
        );

        assert!(matches!(
            executor.compensate_member(&registration, 0).await,
            Ok(CallResult::NotTransmitted)
        ));
        assert_eq!(provider.compensate_calls.load(Ordering::SeqCst), 1);

        let compensated = conclusive(
            executor
                .compensate_member(&registration, 0)
                .await
                .expect("identical compensation retry"),
        );
        assert_eq!(provider.compensate_calls.load(Ordering::SeqCst), 2);
        let diagnostics = executor.diagnostics().snapshot();
        assert_eq!(diagnostics.member_compensate_calls, 2);
        assert_eq!(diagnostics.member_not_transmitted, 1);
        assert_eq!(diagnostics.member_conclusive, 3);
        assert_eq!(diagnostics.member_prepared_not_run, 1);
        assert_eq!(diagnostics.roster_width, [0, 1, 0, 0, 0, 0, 0, 0]);
        // The retry began from the retained original Applied proof rather
        // than a newly minted execution capability.
        assert!(matches!(
            executor.execute(&registration, 0).await,
            Err(ExecutorError::RecoveryRequired)
        ));
        assert_eq!(
            executor
                .prepare_terminal(&registration, vec![compensated, not_applied])
                .await
                .expect("compensated terminal body")
                .body
                .phase(),
            Phase::Aborted
        );
    }

    #[tokio::test]
    async fn compensated_proof_supersedes_applied_and_stale_applied_status_cannot_prepare_established(
    ) {
        let request = request_with_members(2);
        let provider = Arc::new(CompensationProvider::new(
            CompensationMode::ConclusiveThenStaleAppliedStatus,
        ));
        let backend = Arc::new(CutBackend::default());
        let executor = compensation_executor(
            Arc::clone(&provider),
            Arc::clone(&backend),
            request.admission().scope(),
        );
        let registration = executor.register(request).await.expect("registered");
        let mut proofs = Vec::with_capacity(2);
        for ordinal in 0..2 {
            assert!(matches!(
                executor.prepare(&registration, ordinal).await,
                Ok(CallResult::PreparedNotRun)
            ));
            proofs.push(conclusive(
                executor
                    .execute(&registration, ordinal)
                    .await
                    .expect("conclusive partial member"),
            ));
        }
        let applied = proofs.remove(0);
        let not_applied = proofs.remove(0);
        let compensated = conclusive(
            executor
                .compensate_member(&registration, 0)
                .await
                .expect("compensated applied member"),
        );
        let stale_status = executor.status(&registration, 0).await;
        assert!(
            matches!(stale_status, Err(ExecutorError::InvalidProviderResponse)),
            "{stale_status:?}"
        );
        assert_eq!(provider.status_calls.load(Ordering::SeqCst), 1);
        assert!(matches!(
            executor
                .prepare_terminal(&registration, vec![applied, not_applied.clone()])
                .await,
            Err(ExecutorError::InvalidTerminal)
        ));
        let prepared = executor
            .prepare_terminal(
                &registration,
                vec![compensated.clone(), not_applied.clone()],
            )
            .await
            .expect("complete aborted body after partial application compensation");
        assert_eq!(prepared.body.phase(), Phase::Aborted);

        assert!(matches!(
            executor.status(&registration, 0).await,
            Err(ExecutorError::TerminalLocked)
        ));
        assert_eq!(provider.status_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn compensation_outcome_unknown_requires_status_or_adopt_before_any_retry() {
        let request = request_with_members(2);
        let provider = Arc::new(CompensationProvider::new(
            CompensationMode::OutcomeUnknownThenStatusCompensated,
        ));
        let backend = Arc::new(CutBackend::default());
        let executor =
            compensation_executor(Arc::clone(&provider), backend, request.admission().scope());
        let registration = executor.register(request).await.expect("registered");
        assert!(matches!(
            executor.prepare(&registration, 0).await,
            Ok(CallResult::PreparedNotRun)
        ));
        let _ = conclusive(executor.execute(&registration, 0).await.expect("applied"));
        let _ = conclusive(
            executor
                .status(&registration, 1)
                .await
                .expect("complete aborting roster observation"),
        );
        let outcome = executor.compensate_member(&registration, 0).await;
        assert!(
            matches!(outcome, Ok(CallResult::OutcomeUnknown)),
            "{outcome:?}"
        );
        assert!(matches!(
            executor.compensate_member(&registration, 0).await,
            Err(ExecutorError::RecoveryRequired)
        ));
        assert_eq!(provider.compensate_calls.load(Ordering::SeqCst), 1);
        assert!(matches!(
            executor.status(&registration, 0).await,
            Ok(CallResult::Conclusive(_))
        ));
        assert_eq!(provider.status_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn lost_compensated_response_is_recovered_by_exact_status_and_prepares_aborted_terminal()
    {
        let request = request_with_members(2);
        let provider = Arc::new(CompensationProvider::new(CompensationMode::Conclusive));
        let backend = Arc::new(CutBackend::default());
        let executor =
            compensation_executor(Arc::clone(&provider), backend, request.admission().scope());
        let registration = executor.register(request).await.expect("registered");
        assert!(matches!(
            executor.prepare(&registration, 0).await,
            Ok(CallResult::PreparedNotRun)
        ));
        let _ = conclusive(executor.execute(&registration, 0).await.expect("applied"));
        let not_applied = conclusive(
            executor
                .status(&registration, 1)
                .await
                .expect("complete aborting roster observation"),
        );
        // The provider finishes compensation, but the SDK caller loses that
        // one response. A status replay must reproduce the exact retained
        // compensation proof; it must not authorize a second compensate.
        let _lost_response = executor
            .compensate_member(&registration, 0)
            .await
            .expect("provider compensation completed");
        let recovered = conclusive(
            executor
                .status(&registration, 0)
                .await
                .expect("exact compensated status"),
        );
        assert_eq!(provider.compensate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            executor
                .prepare_terminal(&registration, vec![recovered, not_applied])
                .await
                .expect("recovered aborted terminal")
                .body
                .phase(),
            Phase::Aborted
        );
    }

    #[tokio::test]
    async fn successor_status_reconstructs_precrash_compensated_proof_and_aborts_without_recompensating(
    ) {
        let request = request_with_members(2);
        let provider = Arc::new(CompensationProvider::new(CompensationMode::Conclusive));
        let backend = Arc::new(CutBackend::default());
        let first = compensation_executor(
            Arc::clone(&provider),
            Arc::clone(&backend),
            request.admission().scope(),
        );
        let registration = first.register(request.clone()).await.expect("registered");
        assert!(matches!(
            first.prepare(&registration, 0).await,
            Ok(CallResult::PreparedNotRun)
        ));
        let _ = conclusive(first.execute(&registration, 0).await.expect("applied"));
        let _ = conclusive(
            first
                .status(&registration, 1)
                .await
                .expect("complete aborting roster observation"),
        );
        let _ = conclusive(
            first
                .compensate_member(&registration, 0)
                .await
                .expect("provider compensation completed before crash"),
        );
        assert_eq!(provider.compensate_calls.load(Ordering::SeqCst), 1);
        drop(registration);
        drop(first);

        let second =
            compensation_executor(Arc::clone(&provider), backend, request.admission().scope());
        let recovered = recovered(
            second
                .recover(successor(&request, 2))
                .await
                .expect("higher-fence recovery"),
        );
        let proof = conclusive(
            second
                .status(&recovered, 0)
                .await
                .expect("provider-durable compensation status"),
        );
        let not_applied = conclusive(
            second
                .status(&recovered, 1)
                .await
                .expect("provider-durable non-applied status"),
        );
        assert_eq!(provider.compensate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            second
                .prepare_terminal(&recovered, vec![proof, not_applied])
                .await
                .expect("reconstructed aborted terminal")
                .body
                .phase(),
            Phase::Aborted
        );
    }

    #[tokio::test]
    async fn successor_adopt_reconstructs_precrash_compensated_proof_and_aborts_without_recompensating(
    ) {
        let request = request_with_members(2);
        let provider = Arc::new(CompensationProvider::new(CompensationMode::Conclusive));
        let backend = Arc::new(CutBackend::default());
        let first = compensation_executor(
            Arc::clone(&provider),
            Arc::clone(&backend),
            request.admission().scope(),
        );
        let registration = first.register(request.clone()).await.expect("registered");
        assert!(matches!(
            first.prepare(&registration, 0).await,
            Ok(CallResult::PreparedNotRun)
        ));
        let _ = conclusive(first.execute(&registration, 0).await.expect("applied"));
        let _ = conclusive(
            first
                .status(&registration, 1)
                .await
                .expect("complete aborting roster observation"),
        );
        let _ = conclusive(
            first
                .compensate_member(&registration, 0)
                .await
                .expect("provider compensation completed before crash"),
        );
        assert_eq!(provider.compensate_calls.load(Ordering::SeqCst), 1);
        drop(registration);
        drop(first);

        let second =
            compensation_executor(Arc::clone(&provider), backend, request.admission().scope());
        let recovered = recovered(
            second
                .recover(successor(&request, 2))
                .await
                .expect("higher-fence recovery"),
        );
        let proof = conclusive(
            second
                .adopt(&recovered, 0)
                .await
                .expect("provider-durable compensation adoption"),
        );
        let not_applied = conclusive(
            second
                .status(&recovered, 1)
                .await
                .expect("provider-durable non-applied status"),
        );
        assert_eq!(provider.compensate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            second
                .prepare_terminal(&recovered, vec![proof, not_applied])
                .await
                .expect("reconstructed aborted terminal")
                .body
                .phase(),
            Phase::Aborted
        );
    }

    #[tokio::test]
    async fn compensation_waits_for_complete_roster() {
        let request = request_with_members(2);
        let provider = Arc::new(CompensationProvider::new(CompensationMode::Conclusive));
        let backend = Arc::new(CutBackend::default());
        let executor =
            compensation_executor(Arc::clone(&provider), backend, request.admission().scope());
        let registration = executor.register(request).await.expect("registered");
        assert!(matches!(
            executor.prepare(&registration, 0).await,
            Ok(CallResult::PreparedNotRun)
        ));
        let _ = conclusive(executor.execute(&registration, 0).await.expect("applied"));

        assert!(matches!(
            executor.compensate_member(&registration, 0).await,
            Err(ExecutorError::RecoveryRequired)
        ));
        assert_eq!(provider.compensate_calls.load(Ordering::SeqCst), 0);

        let _ = conclusive(
            executor
                .status(&registration, 1)
                .await
                .expect("complete aborting roster observation"),
        );
        assert!(matches!(
            executor.compensate_member(&registration, 0).await,
            Ok(CallResult::Conclusive(_))
        ));
        assert_eq!(provider.compensate_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn all_applied_forbids_compensation_and_successor_rebuilds_identical_established() {
        let request = request_with_members(2);
        let provider = Arc::new(CompensationProvider::new(CompensationMode::AllApplied));
        let backend = Arc::new(CutBackend::default());
        let first = compensation_executor(
            Arc::clone(&provider),
            Arc::clone(&backend),
            request.admission().scope(),
        );
        let registration = first.register(request.clone()).await.expect("registered");
        let mut proofs = Vec::with_capacity(2);
        for ordinal in 0..2 {
            assert!(matches!(
                first.prepare(&registration, ordinal).await,
                Ok(CallResult::PreparedNotRun)
            ));
            proofs.push(conclusive(
                first
                    .execute(&registration, ordinal)
                    .await
                    .expect("applied member"),
            ));
        }
        assert!(matches!(
            first.compensate_member(&registration, 0).await,
            Err(ExecutorError::RecoveryRequired)
        ));
        assert_eq!(provider.compensate_calls.load(Ordering::SeqCst), 0);
        let established = first
            .prepare_terminal(&registration, proofs)
            .await
            .expect("established terminal body");
        assert_eq!(established.body.phase(), Phase::Established);
        drop(registration);
        drop(first);

        let second =
            compensation_executor(Arc::clone(&provider), backend, request.admission().scope());
        let recovered = recovered(
            second
                .recover(successor(&request, 2))
                .await
                .expect("higher-fence recovery"),
        );
        let rebuilt = second
            .prepare_terminal(
                &recovered,
                vec![
                    conclusive(
                        second
                            .status(&recovered, 0)
                            .await
                            .expect("first applied status"),
                    ),
                    conclusive(
                        second
                            .status(&recovered, 1)
                            .await
                            .expect("second applied status"),
                    ),
                ],
            )
            .await
            .expect("rebuilt established terminal body");
        assert_eq!(rebuilt.body.phase(), Phase::Established);
        assert_eq!(rebuilt.body.commitment(), established.body.commitment());
    }

    #[tokio::test]
    async fn not_applied_locks_abort_and_successor_rebuilds_identical_aborted() {
        let request = request_with_members(2);
        let provider = Arc::new(CompensationProvider::new(CompensationMode::Conclusive));
        let backend = Arc::new(CutBackend::default());
        let first = compensation_executor(
            Arc::clone(&provider),
            Arc::clone(&backend),
            request.admission().scope(),
        );
        let registration = first.register(request.clone()).await.expect("registered");
        let mut proofs = Vec::with_capacity(2);
        for ordinal in 0..2 {
            assert!(matches!(
                first.prepare(&registration, ordinal).await,
                Ok(CallResult::PreparedNotRun)
            ));
            proofs.push(conclusive(
                first
                    .execute(&registration, ordinal)
                    .await
                    .expect("conclusive member"),
            ));
        }
        let not_applied = proofs.pop().expect("second not-applied proof");
        let _applied = proofs.pop().expect("first applied proof");
        let compensated = conclusive(
            first
                .compensate_member(&registration, 0)
                .await
                .expect("compensate after abort direction locks"),
        );
        let aborted = first
            .prepare_terminal(&registration, vec![compensated, not_applied])
            .await
            .expect("aborted terminal body");
        assert_eq!(aborted.body.phase(), Phase::Aborted);
        drop(registration);
        drop(first);

        let second =
            compensation_executor(Arc::clone(&provider), backend, request.admission().scope());
        let recovered = recovered(
            second
                .recover(successor(&request, 2))
                .await
                .expect("higher-fence recovery"),
        );
        let rebuilt = second
            .prepare_terminal(
                &recovered,
                vec![
                    conclusive(
                        second
                            .status(&recovered, 0)
                            .await
                            .expect("compensated status"),
                    ),
                    conclusive(
                        second
                            .status(&recovered, 1)
                            .await
                            .expect("non-applied status"),
                    ),
                ],
            )
            .await
            .expect("rebuilt aborted terminal body");
        assert_eq!(rebuilt.body.phase(), Phase::Aborted);
        assert_eq!(rebuilt.body.commitment(), aborted.body.commitment());
    }
}
