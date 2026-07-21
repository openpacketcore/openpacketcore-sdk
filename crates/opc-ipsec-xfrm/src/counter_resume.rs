//! Applied outbound ESP counter authority for same-SPI failover.
//!
//! Numeric counter values are declarations, not evidence. Production issuance
//! is sealed to [`NamespaceBoundLinuxXfrmBackend`] and requires an opaque
//! [`InstalledOutboundSaBinding`]. One namespace-actor command validates the
//! exact outbound policy and SA, compares the kernel's last-assigned outbound
//! sequence, conditionally advances it, performs exact post-readback, and only
//! then records an opaque receipt.
//!
//! Exact transient key comparison is mandatory during preflight and final
//! issuance readback. Receipts retain no keys and expose no counter values.
//! Their later, short-lived proof
//! validation checks exact policy/SA metadata and replay state; every generic
//! mutation admitted through the same namespace actor invalidates all receipts
//! before it executes, including failed mutations. Applications must preserve
//! the crate's existing exclusive-writer contract, keep the successor SA
//! quiescent until the receipt has crossed its required publication boundary,
//! and must not mutate the same namespace through a second raw-netlink writer
//! while a receipt is live.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::num::{NonZeroU128, NonZeroU64};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::model::sa_uses_esn;
use crate::namespace::{NamespaceActorBinding, NamespaceBoundLinuxXfrmBackend};
use crate::outbound_binding::OutboundSaPolicyExpectation;
use crate::{
    InstalledOutboundSaBinding, LinuxXfrmBackend, OutboundSaBindingError, OutboundSaBindingId,
    SaParameters, SaReplayState, SaState, XfrmError,
};

/// Maximum number of live counter receipts retained by one namespace actor.
pub const MAX_ESP_COUNTER_RECEIPTS: usize = 1024;

/// Maximum age of a receipt before the caller must repeat the idempotent
/// actor-local readback operation.
pub const ESP_COUNTER_RECEIPT_MAX_AGE: Duration = Duration::from_secs(30);

/// Maximum number of counter receipts accepted by one bounded proof set.
pub const MAX_ESP_COUNTER_PROOF_SET_SIZE: usize = 64;

/// Durable, key-free correlation for one outbound ESP counter operation.
//
// This value is not evidence. Only an [`AppliedEspCounterReceipt`] returned by
// the namespace-bound production backend can authorize a proof boundary.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EspCounterResumeBinding {
    operation_id: NonZeroU128,
    fence_generation: NonZeroU64,
    outbound_sa: OutboundSaBindingId,
    requested_next: NonZeroU64,
}

impl EspCounterResumeBinding {
    /// Bind a durable operation and fence generation to one exact outbound SA
    /// and the next ESP sequence number that the successor must emit.
    pub fn new(
        operation_id: u128,
        fence_generation: u64,
        outbound_sa: OutboundSaBindingId,
        requested_next: u64,
    ) -> Result<Self, EspCounterResumeError> {
        Ok(Self {
            operation_id: NonZeroU128::new(operation_id).ok_or(
                EspCounterResumeError::InvalidRequest {
                    code: "esp_counter_operation_id_zero",
                },
            )?,
            fence_generation: NonZeroU64::new(fence_generation).ok_or(
                EspCounterResumeError::InvalidRequest {
                    code: "esp_counter_fence_generation_zero",
                },
            )?,
            outbound_sa,
            requested_next: NonZeroU64::new(requested_next).ok_or(
                EspCounterResumeError::InvalidRequest {
                    code: "esp_counter_requested_next_zero",
                },
            )?,
        })
    }

    /// Return the exact durable outbound-SA correlation ID.
    #[must_use]
    pub const fn outbound_sa_binding_id(self) -> OutboundSaBindingId {
        self.outbound_sa
    }

    pub(crate) const fn requested_last_assigned(self) -> u64 {
        // Construction proves requested_next is non-zero.
        self.requested_next.get() - 1
    }
}

impl fmt::Debug for EspCounterResumeBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EspCounterResumeBinding(<redacted>)")
    }
}

/// Opaque, process-local correlation for the intended live XFRM actor and
/// outbound SA binding.
///
/// [`OutboundSaBindingId`] deliberately remains stable across process and
/// network-namespace restart, so it cannot by itself distinguish two live
/// namespaces with identical SA/policy configuration. This target is derived
/// only from an [`InstalledOutboundSaBinding`] and binds proof validation to
/// that exact live actor without exposing or persisting namespace identity.
/// It is not serializable and is not evidence by itself.
#[derive(Clone)]
pub struct OutboundEspCounterTarget {
    actor: NamespaceActorBinding,
    outbound_sa: OutboundSaBindingId,
}

impl OutboundEspCounterTarget {
    fn new(authority: &InstalledOutboundSaBinding) -> Self {
        Self {
            actor: authority.actor_binding(),
            outbound_sa: authority.id(),
        }
    }

    fn matches(&self, other: &Self) -> bool {
        self.actor == other.actor && self.outbound_sa == other.outbound_sa
    }

    /// Return the durable, key-free SA correlation carried by this live
    /// target. The returned ID remains correlation only, not authority.
    #[must_use]
    pub const fn outbound_sa_binding_id(&self) -> OutboundSaBindingId {
        self.outbound_sa
    }
}

impl fmt::Debug for OutboundEspCounterTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OutboundEspCounterTarget(<redacted>)")
    }
}

impl InstalledOutboundSaBinding {
    /// Bind subsequent counter-proof validation to this exact live namespace
    /// actor without changing the durable [`OutboundSaBindingId`].
    #[must_use]
    pub fn outbound_esp_counter_target(&self) -> OutboundEspCounterTarget {
        OutboundEspCounterTarget::new(self)
    }
}

/// Complete transient request for an outbound counter operation.
//
// The replay counters in `parameters` are never accepted as authority. The
// actor reads the current replay state and changes only its outbound sequence.
// Key material remains in this zeroizing SA request and is never copied into a
// receipt or actor journal.
#[derive(Clone)]
pub struct EspCounterResumeApplyRequest {
    binding: EspCounterResumeBinding,
    parameters: SaParameters,
}

impl EspCounterResumeApplyRequest {
    /// Build a transient request using the exact SA installation parameters.
    #[must_use]
    pub const fn new(binding: EspCounterResumeBinding, parameters: SaParameters) -> Self {
        Self {
            binding,
            parameters,
        }
    }

    /// Return the key-free durable operation binding.
    #[must_use]
    pub const fn binding(&self) -> EspCounterResumeBinding {
        self.binding
    }
}

impl fmt::Debug for EspCounterResumeApplyRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspCounterResumeApplyRequest")
            .field("binding", &"<redacted>")
            .field("parameters", &"<redacted>")
            .finish()
    }
}

/// Transient exact-SA request for rebuilding a receipt after committed
/// ownership survives process loss.
//
// This is a distinct API rather than a caller-selected mode on the mutation
// request. It never updates Linux state and can issue only a receipt capped to
// [`EspCounterProofRequirement::CommittedRecovery`].
#[derive(Clone)]
pub struct EspCounterResumeRecoveryRequest {
    binding: EspCounterResumeBinding,
    parameters: SaParameters,
}

impl EspCounterResumeRecoveryRequest {
    /// Build a read-only committed-recovery request with exact transient SA
    /// key material.
    #[must_use]
    pub const fn new(binding: EspCounterResumeBinding, parameters: SaParameters) -> Self {
        Self {
            binding,
            parameters,
        }
    }

    /// Return the key-free durable operation binding.
    #[must_use]
    pub const fn binding(&self) -> EspCounterResumeBinding {
        self.binding
    }
}

impl fmt::Debug for EspCounterResumeRecoveryRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspCounterResumeRecoveryRequest")
            .field("binding", &"<redacted>")
            .field("parameters", &"<redacted>")
            .finish()
    }
}

/// Lifecycle point at which a counter receipt is revalidated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EspCounterProofRequirement {
    /// Immediately before committing a new ownership fence.
    BeforeOwnershipCommit,
    /// Immediately before publishing the first successor steering entry.
    BeforeFirstPublication,
    /// After ownership is already committed; the counter may have advanced.
    CommittedRecovery,
}

/// Opaque evidence issued only by the namespace-bound Linux actor.
//
// The receipt has no public constructor and retains no key. It exposes no SPI,
// address, counter, or namespace identity. Its private backend handle re-enters
// the same actor for bounded, exact proof validation.
///
/// ```compile_fail
/// let _forged = opc_ipsec_xfrm::AppliedEspCounterReceipt {};
/// ```
#[derive(Clone)]
pub struct AppliedEspCounterReceipt {
    binding: EspCounterResumeBinding,
    target: OutboundEspCounterTarget,
    backend: NamespaceBoundLinuxXfrmBackend,
}

impl AppliedEspCounterReceipt {
    pub(crate) const fn new(
        binding: EspCounterResumeBinding,
        target: OutboundEspCounterTarget,
        backend: NamespaceBoundLinuxXfrmBackend,
    ) -> Self {
        Self {
            binding,
            target,
            backend,
        }
    }

    async fn validate(
        &self,
        expected_target: &OutboundEspCounterTarget,
        requirement: EspCounterProofRequirement,
    ) -> Result<(), EspCounterResumeError> {
        if !self.target.matches(expected_target)
            || self.binding.outbound_sa != expected_target.outbound_sa
        {
            return Err(EspCounterResumeError::ProofUnavailable {
                code: "esp_counter_receipt_target_mismatch",
            });
        }
        self.backend
            .validate_outbound_esp_counter_receipt(self.binding, requirement)
            .await
    }
}

impl fmt::Debug for AppliedEspCounterReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppliedEspCounterReceipt(<redacted>)")
    }
}

/// Bounded collection of opaque receipts for a multi-SA re-pin plan.
///
/// Every validation also requires the process-local target derived from the
/// intended live [`InstalledOutboundSaBinding`]. A receipt issued for an
/// otherwise identical SA in another actor or network namespace is rejected
/// before that receipt's backend is queried.
#[derive(Clone)]
pub struct EspCounterResumeProofSet {
    receipts: HashMap<EspCounterResumeBinding, AppliedEspCounterReceipt>,
}

impl EspCounterResumeProofSet {
    /// Build a bounded, nonempty proof set without duplicate bindings.
    pub fn new(
        receipts: impl IntoIterator<Item = AppliedEspCounterReceipt>,
    ) -> Result<Self, EspCounterResumeError> {
        let mut collected = HashMap::new();
        for receipt in receipts {
            if collected.len() >= MAX_ESP_COUNTER_PROOF_SET_SIZE {
                return Err(EspCounterResumeError::InvalidRequest {
                    code: "esp_counter_proof_set_too_large",
                });
            }
            if collected.insert(receipt.binding, receipt).is_some() {
                return Err(EspCounterResumeError::InvalidRequest {
                    code: "esp_counter_proof_set_duplicate_binding",
                });
            }
        }
        if collected.is_empty() {
            return Err(EspCounterResumeError::InvalidRequest {
                code: "esp_counter_proof_set_empty",
            });
        }
        Ok(Self {
            receipts: collected,
        })
    }

    /// Build a one-receipt proof set.
    #[must_use]
    pub fn single(receipt: AppliedEspCounterReceipt) -> Self {
        let mut receipts = HashMap::new();
        receipts.insert(receipt.binding, receipt);
        Self { receipts }
    }

    /// Validate the exact operation receipt and live actor target at a
    /// coordinator boundary.
    pub async fn validate_counter_proof(
        &self,
        expected_target: &OutboundEspCounterTarget,
        binding: EspCounterResumeBinding,
        requirement: EspCounterProofRequirement,
    ) -> Result<(), EspCounterResumeError> {
        let receipt =
            self.receipts
                .get(&binding)
                .ok_or(EspCounterResumeError::ProofUnavailable {
                    code: "esp_counter_receipt_absent_or_stale",
                })?;
        receipt.validate(expected_target, requirement).await
    }
}

impl fmt::Debug for EspCounterResumeProofSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspCounterResumeProofSet")
            .field("receipt_count", &self.receipts.len())
            .finish_non_exhaustive()
    }
}

/// Redaction-safe failure from the sealed ESP counter boundary.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EspCounterResumeError {
    /// The durable request cannot represent a safe outbound sequence.
    #[error("invalid ESP counter resume request ({code})")]
    InvalidRequest {
        /// Stable payload-free diagnostic code.
        code: &'static str,
    },
    /// No matching live actor-issued receipt exists.
    #[error("ESP counter resume proof is unavailable ({code})")]
    ProofUnavailable {
        /// Stable payload-free diagnostic code.
        code: &'static str,
    },
    /// Exact kernel state did not match the opaque binding or receipt.
    #[error("ESP counter resume readback was rejected ({code})")]
    ReadbackRejected {
        /// Stable payload-free diagnostic code.
        code: &'static str,
    },
    /// The live kernel counter is already beyond the requested floor. No
    /// mutation was attempted.
    #[error("ESP counter is already beyond the requested floor ({code})")]
    AlreadyAdvanced {
        /// Stable payload-free diagnostic code.
        code: &'static str,
    },
    /// The actor or Linux operation failed.
    #[error("ESP counter resume backend operation failed ({code})")]
    Backend {
        /// Stable payload-free diagnostic code.
        code: &'static str,
    },
}

impl EspCounterResumeError {
    /// Return the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest { code }
            | Self::ProofUnavailable { code }
            | Self::ReadbackRejected { code }
            | Self::AlreadyAdvanced { code }
            | Self::Backend { code } => code,
        }
    }
}

impl fmt::Debug for EspCounterResumeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspCounterResumeError")
            .field("code", &self.code())
            .finish()
    }
}

pub(crate) struct CounterResumeActorRequest {
    pub(crate) authority: InstalledOutboundSaBinding,
    pub(crate) expected_id: OutboundSaBindingId,
    pub(crate) request: EspCounterResumeApplyRequest,
}

impl fmt::Debug for CounterResumeActorRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CounterResumeActorRequest(<redacted>)")
    }
}

pub(crate) struct CounterRecoveryActorRequest {
    pub(crate) authority: InstalledOutboundSaBinding,
    pub(crate) expected_id: OutboundSaBindingId,
    pub(crate) request: EspCounterResumeRecoveryRequest,
}

impl fmt::Debug for CounterRecoveryActorRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CounterRecoveryActorRequest(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReceiptAuthority {
    Applied,
    CommittedRecoveryOnly,
}

#[derive(Clone)]
struct CounterReceiptRecord {
    binding: EspCounterResumeBinding,
    expectation: OutboundSaPolicyExpectation,
    requested_last: u64,
    observed_last: u64,
    esn: bool,
    authority: ReceiptAuthority,
    fingerprint: [u8; 32],
    expires_at: Instant,
}

/// Actor-local bounded receipt journal. It deliberately retains no key
/// material and is unavailable to mock or arbitrary [`XfrmBackend`] values.
#[derive(Default)]
pub(crate) struct EspCounterReceiptRegistry {
    records: HashMap<EspCounterResumeBinding, CounterReceiptRecord>,
    order: VecDeque<EspCounterResumeBinding>,
}

impl EspCounterReceiptRegistry {
    pub(crate) fn invalidate_all(&mut self) {
        self.records.clear();
        self.order.clear();
    }

    pub(crate) async fn apply(
        &mut self,
        backend: &LinuxXfrmBackend,
        actor: &NamespaceActorBinding,
        actor_request: CounterResumeActorRequest,
    ) -> Result<(), EspCounterResumeError> {
        let CounterResumeActorRequest {
            authority,
            expected_id,
            request,
        } = actor_request;
        if request.binding.outbound_sa != expected_id {
            return Err(EspCounterResumeError::InvalidRequest {
                code: "esp_counter_binding_id_mismatch",
            });
        }
        let expectation = authority
            .validated_expectation_for_actor(actor, &request.parameters, expected_id)
            .map_err(map_binding_error)?;
        validate_requested_counter(&request, expectation.replay_esn())?;

        self.remove_binding(request.binding);
        self.remove_outbound_sa(expected_id);
        let observed_last = apply_and_read_back(
            backend,
            &expectation,
            request.parameters,
            request.binding.requested_last_assigned(),
        )
        .await?;
        let esn = expectation.replay_esn();
        let record = CounterReceiptRecord {
            binding: request.binding,
            expectation,
            requested_last: request.binding.requested_last_assigned(),
            observed_last,
            esn,
            authority: ReceiptAuthority::Applied,
            fingerprint: receipt_fingerprint(
                request.binding,
                observed_last,
                esn,
                ReceiptAuthority::Applied,
            ),
            expires_at: Instant::now() + ESP_COUNTER_RECEIPT_MAX_AGE,
        };
        self.activate(record);
        Ok(())
    }

    pub(crate) async fn recover_committed(
        &mut self,
        backend: &LinuxXfrmBackend,
        actor: &NamespaceActorBinding,
        actor_request: CounterRecoveryActorRequest,
    ) -> Result<(), EspCounterResumeError> {
        let CounterRecoveryActorRequest {
            authority,
            expected_id,
            request,
        } = actor_request;
        if request.binding.outbound_sa != expected_id {
            return Err(EspCounterResumeError::InvalidRequest {
                code: "esp_counter_binding_id_mismatch",
            });
        }
        let expectation = authority
            .validated_expectation_for_actor(actor, &request.parameters, expected_id)
            .map_err(map_binding_error)?;
        let validation_request =
            EspCounterResumeApplyRequest::new(request.binding, request.parameters.clone());
        validate_requested_counter(&validation_request, expectation.replay_esn())?;

        self.remove_binding(request.binding);
        self.remove_outbound_sa(expected_id);
        let observed = backend
            .read_outbound_sa_binding(&expectation, &request.parameters)
            .await
            .map_err(map_binding_error)?;
        let observed_last = outbound_last_assigned(&observed, expectation.replay_esn())?;
        let requested_last = request.binding.requested_last_assigned();
        if observed_last < requested_last {
            return Err(EspCounterResumeError::ReadbackRejected {
                code: "esp_counter_committed_recovery_below_floor",
            });
        }
        let esn = expectation.replay_esn();
        let record = CounterReceiptRecord {
            binding: request.binding,
            expectation,
            requested_last,
            observed_last,
            esn,
            authority: ReceiptAuthority::CommittedRecoveryOnly,
            fingerprint: receipt_fingerprint(
                request.binding,
                observed_last,
                esn,
                ReceiptAuthority::CommittedRecoveryOnly,
            ),
            expires_at: Instant::now() + ESP_COUNTER_RECEIPT_MAX_AGE,
        };
        self.activate(record);
        Ok(())
    }

    pub(crate) async fn validate(
        &mut self,
        backend: &LinuxXfrmBackend,
        binding: EspCounterResumeBinding,
        requirement: EspCounterProofRequirement,
    ) -> Result<(), EspCounterResumeError> {
        self.validate_with_clock(backend, binding, requirement, Instant::now)
            .await
    }

    async fn validate_with_clock<C>(
        &mut self,
        backend: &LinuxXfrmBackend,
        binding: EspCounterResumeBinding,
        requirement: EspCounterProofRequirement,
        now: C,
    ) -> Result<(), EspCounterResumeError>
    where
        C: Fn() -> Instant,
    {
        let record =
            self.records
                .get(&binding)
                .cloned()
                .ok_or(EspCounterResumeError::ProofUnavailable {
                    code: "esp_counter_receipt_absent_or_stale",
                })?;
        if now() >= record.expires_at
            || record.fingerprint
                != receipt_fingerprint(binding, record.observed_last, record.esn, record.authority)
        {
            self.remove_binding(binding);
            return Err(EspCounterResumeError::ProofUnavailable {
                code: "esp_counter_receipt_absent_or_stale",
            });
        }
        if record.authority == ReceiptAuthority::CommittedRecoveryOnly
            && requirement != EspCounterProofRequirement::CommittedRecovery
        {
            return Err(EspCounterResumeError::ProofUnavailable {
                code: "esp_counter_recovered_receipt_cannot_fence",
            });
        }

        let result = validate_receipt_readback(backend, &record, requirement).await;
        let expired = now() >= record.expires_at;
        match result {
            Err(error) => {
                self.remove_binding(binding);
                Err(error)
            }
            Ok(()) if expired => {
                self.remove_binding(binding);
                Err(EspCounterResumeError::ProofUnavailable {
                    code: "esp_counter_receipt_absent_or_stale",
                })
            }
            Ok(()) => Ok(()),
        }
    }

    fn activate(&mut self, record: CounterReceiptRecord) {
        self.remove_binding(record.binding);
        self.remove_outbound_sa(record.binding.outbound_sa);
        while self.records.len() >= MAX_ESP_COUNTER_RECEIPTS {
            let Some(oldest) = self.order.pop_front() else {
                self.records.clear();
                break;
            };
            self.records.remove(&oldest);
        }
        self.order.push_back(record.binding);
        self.records.insert(record.binding, record);
    }

    fn remove_binding(&mut self, binding: EspCounterResumeBinding) {
        self.records.remove(&binding);
        self.order.retain(|candidate| *candidate != binding);
    }

    fn remove_outbound_sa(&mut self, outbound_sa: OutboundSaBindingId) {
        let stale: Vec<_> = self
            .records
            .keys()
            .filter(|binding| binding.outbound_sa == outbound_sa)
            .copied()
            .collect();
        for binding in stale {
            self.remove_binding(binding);
        }
    }
}

fn validate_requested_counter(
    request: &EspCounterResumeApplyRequest,
    expected_esn: bool,
) -> Result<(), EspCounterResumeError> {
    if request.parameters.id.protocol != 50 || request.parameters.id.spi == 0 {
        return Err(EspCounterResumeError::InvalidRequest {
            code: "esp_counter_sa_not_esp",
        });
    }
    let declared_esn = sa_uses_esn(&request.parameters);
    if declared_esn != expected_esn {
        return Err(EspCounterResumeError::InvalidRequest {
            code: "esp_counter_replay_mode_mismatch",
        });
    }
    if expected_esn {
        if request.parameters.replay_window == 0 {
            return Err(EspCounterResumeError::InvalidRequest {
                code: "esp_counter_esn_replay_window_zero",
            });
        }
    } else if request.binding.requested_next.get() > u64::from(u32::MAX) {
        return Err(EspCounterResumeError::InvalidRequest {
            code: "esp_counter_legacy_sequence_wrap",
        });
    }
    Ok(())
}

async fn apply_and_read_back(
    backend: &LinuxXfrmBackend,
    expectation: &OutboundSaPolicyExpectation,
    supplied_sa: SaParameters,
    requested_last: u64,
) -> Result<u64, EspCounterResumeError> {
    let before = backend
        .read_outbound_sa_binding(expectation, &supplied_sa)
        .await
        .map_err(map_binding_error)?;
    let before_last = outbound_last_assigned(&before, expectation.replay_esn())?;
    if before_last > requested_last {
        return Err(EspCounterResumeError::AlreadyAdvanced {
            code: "esp_counter_already_advanced",
        });
    }

    let update_error = if before_last < requested_last {
        let replay_state = replay_state_at_floor(
            before.replay_state,
            requested_last,
            expectation.replay_esn(),
        )?;
        backend
            .update_outbound_sa_replay_state(&supplied_sa, &replay_state)
            .await
            .err()
    } else {
        None
    };

    let after = backend
        .read_outbound_sa_binding(expectation, &supplied_sa)
        .await
        .map_err(map_binding_error)?;
    let after_last = outbound_last_assigned(&after, expectation.replay_esn())?;
    if after_last > requested_last {
        return Err(EspCounterResumeError::AlreadyAdvanced {
            code: "esp_counter_advanced_during_apply",
        });
    }
    if after_last < requested_last {
        return Err(update_error.map_or(
            EspCounterResumeError::ReadbackRejected {
                code: "esp_counter_post_apply_below_requested_floor",
            },
            map_backend_error,
        ));
    }
    Ok(after_last)
}

fn replay_state_at_floor(
    mut replay_state: SaReplayState,
    requested_last: u64,
    expected_esn: bool,
) -> Result<SaReplayState, EspCounterResumeError> {
    validate_replay_shape(&replay_state, expected_esn)?;
    if (expected_esn && requested_last == u64::MAX)
        || (!expected_esn && requested_last >= u64::from(u32::MAX))
    {
        return Err(EspCounterResumeError::InvalidRequest {
            code: if expected_esn {
                "esp_counter_sequence_wrap"
            } else {
                "esp_counter_legacy_sequence_wrap"
            },
        });
    }
    replay_state.outbound_sequence = requested_last as u32;
    replay_state.outbound_sequence_hi = if expected_esn {
        (requested_last >> 32) as u32
    } else {
        0
    };
    Ok(replay_state)
}

fn outbound_last_assigned(
    state: &SaState,
    expected_esn: bool,
) -> Result<u64, EspCounterResumeError> {
    validate_replay_shape(&state.replay_state, expected_esn)?;
    if state.replay_window != state.replay_state.replay_window {
        return Err(EspCounterResumeError::ReadbackRejected {
            code: "esp_counter_replay_window_mismatch",
        });
    }
    let last = if expected_esn {
        (u64::from(state.replay_state.outbound_sequence_hi) << 32)
            | u64::from(state.replay_state.outbound_sequence)
    } else {
        u64::from(state.replay_state.outbound_sequence)
    };
    if last == u64::MAX {
        return Err(EspCounterResumeError::ReadbackRejected {
            code: "esp_counter_sequence_exhausted",
        });
    }
    Ok(last)
}

fn validate_replay_shape(
    replay_state: &SaReplayState,
    expected_esn: bool,
) -> Result<(), EspCounterResumeError> {
    if replay_state.esn != expected_esn {
        return Err(EspCounterResumeError::ReadbackRejected {
            code: "esp_counter_replay_mode_mismatch",
        });
    }
    if expected_esn {
        let words = replay_state.replay_window.div_ceil(32).max(1) as usize;
        if replay_state.replay_window == 0 || replay_state.bitmap.len() != words {
            return Err(EspCounterResumeError::ReadbackRejected {
                code: "esp_counter_esn_state_ambiguous",
            });
        }
    } else if replay_state.replay_window > 32
        || replay_state.bitmap.len() > 1
        || replay_state.outbound_sequence_hi != 0
        || replay_state.inbound_sequence_hi != 0
    {
        return Err(EspCounterResumeError::ReadbackRejected {
            code: "esp_counter_legacy_state_ambiguous",
        });
    }
    Ok(())
}

async fn validate_receipt_readback(
    backend: &LinuxXfrmBackend,
    record: &CounterReceiptRecord,
    requirement: EspCounterProofRequirement,
) -> Result<(), EspCounterResumeError> {
    let observed = backend
        .read_outbound_sa_binding_metadata(&record.expectation)
        .await
        .map_err(map_binding_error)?;
    let observed_last = outbound_last_assigned(&observed, record.esn)?;
    match requirement {
        EspCounterProofRequirement::BeforeOwnershipCommit
        | EspCounterProofRequirement::BeforeFirstPublication
            if observed_last != record.observed_last =>
        {
            Err(EspCounterResumeError::ReadbackRejected {
                code: "esp_counter_receipt_exact_state_changed",
            })
        }
        EspCounterProofRequirement::CommittedRecovery if observed_last < record.requested_last => {
            Err(EspCounterResumeError::ReadbackRejected {
                code: "esp_counter_receipt_below_applied_floor",
            })
        }
        EspCounterProofRequirement::BeforeOwnershipCommit
        | EspCounterProofRequirement::BeforeFirstPublication
        | EspCounterProofRequirement::CommittedRecovery => Ok(()),
    }
}

fn receipt_fingerprint(
    binding: EspCounterResumeBinding,
    observed_last: u64,
    esn: bool,
    authority: ReceiptAuthority,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"opc-xfrm-applied-outbound-counter-receipt-v1\0");
    digest.update(binding.operation_id.get().to_be_bytes());
    digest.update(binding.fence_generation.get().to_be_bytes());
    digest.update(binding.outbound_sa.to_bytes());
    digest.update(binding.requested_last_assigned().to_be_bytes());
    digest.update(observed_last.to_be_bytes());
    digest.update([
        esn as u8,
        match authority {
            ReceiptAuthority::Applied => 1,
            ReceiptAuthority::CommittedRecoveryOnly => 2,
        },
    ]);
    digest.finalize().into()
}

fn map_binding_error(error: OutboundSaBindingError) -> EspCounterResumeError {
    match error {
        OutboundSaBindingError::InvalidRequest { .. } => {
            EspCounterResumeError::InvalidRequest { code: error.code() }
        }
        OutboundSaBindingError::ReadbackRejected { .. } => {
            EspCounterResumeError::ReadbackRejected { code: error.code() }
        }
        OutboundSaBindingError::Install { .. }
        | OutboundSaBindingError::Commit { .. }
        | OutboundSaBindingError::Readback { .. } => {
            EspCounterResumeError::Backend { code: error.code() }
        }
    }
}

pub(crate) fn map_backend_error(error: XfrmError) -> EspCounterResumeError {
    let code = match error {
        XfrmError::UnsupportedPlatform => "esp_counter_backend_unsupported_platform",
        XfrmError::UnsupportedFeature { .. } => "esp_counter_backend_unsupported_feature",
        XfrmError::InvalidConfig { .. } => "esp_counter_backend_invalid_config",
        XfrmError::Io { .. } => "esp_counter_backend_io",
        XfrmError::StateIndeterminate { .. } => "esp_counter_backend_state_indeterminate",
        XfrmError::StateMismatch { .. } => "esp_counter_backend_state_mismatch",
        XfrmError::NotFound => "esp_counter_backend_sa_not_found",
        XfrmError::AlreadyExists => "esp_counter_backend_sa_already_exists",
        XfrmError::Unavailable => "esp_counter_backend_unavailable",
    };
    EspCounterResumeError::Backend { code }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};

    use super::*;
    use crate::linux::{
        test_outbound_binding_readback_bodies, LinuxXfrmBackendConfig, LinuxXfrmTransport,
        SensitiveBuffer,
    };
    use crate::outbound_binding::{tests_support::outbound_request, validate_outbound_request};
    use crate::{
        IpAddress, LifetimeConfig, LifetimeCurrent, SaStatistics, XfrmId, XfrmMode, XfrmProbe,
        XfrmRequestId, XfrmSelector,
    };

    type ReadbackResponse = Result<Option<SensitiveBuffer>, XfrmError>;

    #[derive(Clone)]
    struct BlockingReadbackTransport {
        responses: Arc<Mutex<VecDeque<ReadbackResponse>>>,
        calls: Arc<AtomicUsize>,
        readback_blocked: Arc<AtomicBool>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }

    impl BlockingReadbackTransport {
        fn new(responses: impl IntoIterator<Item = ReadbackResponse>) -> Self {
            Self {
                responses: Arc::new(Mutex::new(responses.into_iter().collect())),
                calls: Arc::new(AtomicUsize::new(0)),
                readback_blocked: Arc::new(AtomicBool::new(false)),
                release: Arc::new((Mutex::new(false), Condvar::new())),
            }
        }

        fn release_readback(&self) {
            let (lock, wake) = &*self.release;
            *lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
            wake.notify_all();
        }
    }

    impl fmt::Debug for BlockingReadbackTransport {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("BlockingReadbackTransport(<redacted>)")
        }
    }

    impl LinuxXfrmTransport for BlockingReadbackTransport {
        fn transact(
            &self,
            _operation: &'static str,
            _request: &[u8],
            _expected_sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> ReadbackResponse {
            let call = self.calls.fetch_add(1, Ordering::AcqRel);
            if call == 1 {
                self.readback_blocked.store(true, Ordering::Release);
                let (lock, wake) = &*self.release;
                let mut released = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                while !*released {
                    released = wake
                        .wait(released)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            }
            self.responses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop_front()
                .unwrap_or(Err(XfrmError::Unavailable))
        }

        fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe::unsupported()
        }
    }

    fn state(replay_state: SaReplayState) -> SaState {
        SaState {
            selector: XfrmSelector::new(
                IpAddress::Ipv4([10, 0, 0, 1]),
                IpAddress::Ipv4([10, 0, 0, 2]),
                17,
            ),
            id: XfrmId {
                destination: IpAddress::Ipv4([192, 0, 2, 2]),
                spi: 1,
                protocol: 50,
            },
            source_address: IpAddress::Ipv4([192, 0, 2, 1]),
            request_id: XfrmRequestId::new(1),
            mode: XfrmMode::Tunnel,
            replay_window: replay_state.replay_window,
            replay_state,
            lifetime_config: LifetimeConfig::default(),
            lifetime_current: LifetimeCurrent::default(),
            statistics: SaStatistics::default(),
            output_mark: None,
            egress_dscp: None,
        }
    }

    #[test]
    fn legacy_and_esn_last_assigned_mapping_is_unambiguous() {
        let legacy = SaReplayState::legacy(41, 0, 0);
        assert_eq!(outbound_last_assigned(&state(legacy), false).unwrap(), 41);

        let mut esn = SaReplayState::fresh(64);
        esn.outbound_sequence_hi = 2;
        esn.outbound_sequence = 9;
        assert_eq!(
            outbound_last_assigned(&state(esn), true).unwrap(),
            (2_u64 << 32) | 9
        );
    }

    #[test]
    fn ambiguous_replay_shapes_and_exhaustion_fail_closed() {
        let mut legacy = SaReplayState::legacy(1, 0, 0);
        legacy.outbound_sequence_hi = 1;
        assert_eq!(
            outbound_last_assigned(&state(legacy), false)
                .unwrap_err()
                .code(),
            "esp_counter_legacy_state_ambiguous"
        );

        let mut esn = SaReplayState::fresh(64);
        esn.bitmap.clear();
        assert_eq!(
            outbound_last_assigned(&state(esn), true)
                .unwrap_err()
                .code(),
            "esp_counter_esn_state_ambiguous"
        );

        let mut exhausted = SaReplayState::fresh(64);
        exhausted.outbound_sequence_hi = u32::MAX;
        exhausted.outbound_sequence = u32::MAX;
        assert_eq!(
            outbound_last_assigned(&state(exhausted), true)
                .unwrap_err()
                .code(),
            "esp_counter_sequence_exhausted"
        );
    }

    #[test]
    fn public_values_and_errors_are_redacted() {
        let id = OutboundSaBindingId::from_bytes([0x5a; 32]);
        let binding = EspCounterResumeBinding::new(11, 22, id, 33).unwrap();
        assert_eq!(
            format!("{binding:?}"),
            "EspCounterResumeBinding(<redacted>)"
        );
        let error = EspCounterResumeError::AlreadyAdvanced {
            code: "esp_counter_already_advanced",
        };
        let debug = format!("{error:?}");
        assert!(!debug.contains("11"));
        assert!(!debug.contains("22"));
        assert!(!debug.contains("33"));
    }

    #[test]
    fn requested_next_boundaries_allow_one_final_packet_without_wrap() {
        let id = OutboundSaBindingId::from_bytes([0x5a; 32]);
        let mut legacy_parameters = outbound_request().sa.parameters;
        legacy_parameters.replay_window = 32;
        legacy_parameters.replay_state = None;
        let legacy_last = u64::from(u32::MAX) - 1;
        let legacy = EspCounterResumeApplyRequest::new(
            EspCounterResumeBinding::new(1, 1, id, u64::from(u32::MAX)).unwrap(),
            legacy_parameters.clone(),
        );
        assert!(validate_requested_counter(&legacy, false).is_ok());
        let applied =
            replay_state_at_floor(SaReplayState::legacy(0, 0, 0), legacy_last, false).unwrap();
        assert_eq!(u64::from(applied.outbound_sequence), legacy_last);

        let wrapping_legacy = EspCounterResumeApplyRequest::new(
            EspCounterResumeBinding::new(2, 1, id, u64::from(u32::MAX) + 1).unwrap(),
            legacy_parameters,
        );
        assert_eq!(
            validate_requested_counter(&wrapping_legacy, false)
                .unwrap_err()
                .code(),
            "esp_counter_legacy_sequence_wrap"
        );

        let esn_parameters = outbound_request().sa.parameters;
        let esn = EspCounterResumeApplyRequest::new(
            EspCounterResumeBinding::new(3, 1, id, u64::MAX).unwrap(),
            esn_parameters,
        );
        assert!(validate_requested_counter(&esn, true).is_ok());
        let applied = replay_state_at_floor(SaReplayState::fresh(64), u64::MAX - 1, true).unwrap();
        assert_eq!(applied.outbound_sequence_hi, u32::MAX);
        assert_eq!(applied.outbound_sequence, u32::MAX - 1);
        assert_eq!(
            replay_state_at_floor(applied, u64::MAX, true)
                .unwrap_err()
                .code(),
            "esp_counter_sequence_wrap"
        );
    }

    #[test]
    fn wide_window_explicit_false_snapshot_is_canonical_esn_for_counter_validation() {
        let id = OutboundSaBindingId::from_bytes([0x6b; 32]);
        let mut parameters = outbound_request().sa.parameters;
        let mut contradictory = SaReplayState::fresh(64);
        contradictory.esn = false;
        parameters.replay_state = Some(contradictory);
        let request = EspCounterResumeApplyRequest::new(
            EspCounterResumeBinding::new(1, 1, id, 10).unwrap(),
            parameters,
        );
        assert!(validate_requested_counter(&request, true).is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn receipt_expiring_during_readback_cannot_authorize_the_boundary() {
        let request = outbound_request();
        let expectation = validate_outbound_request(&request).unwrap();
        let binding = EspCounterResumeBinding::new(1, 2, expectation.id(), 50).unwrap();
        let before_expiry = Instant::now();
        let expires_at = before_expiry + Duration::from_secs(1);
        let after_expiry = expires_at + Duration::from_secs(1);
        let authority = ReceiptAuthority::Applied;
        let record = CounterReceiptRecord {
            binding,
            expectation,
            requested_last: 49,
            observed_last: 49,
            esn: true,
            authority,
            fingerprint: receipt_fingerprint(binding, 49, true, authority),
            expires_at,
        };
        let mut registry = EspCounterReceiptRegistry::default();
        registry.activate(record);

        let mut observed = request;
        let mut replay = SaReplayState::fresh(64);
        replay.outbound_sequence = 49;
        observed.sa.parameters.replay_state = Some(replay);
        let (policy, sa) = test_outbound_binding_readback_bodies(&observed).unwrap();
        let transport = BlockingReadbackTransport::new([Ok(Some(policy)), Ok(Some(sa))]);
        let capture = transport.clone();
        let backend = LinuxXfrmBackend::with_transport(transport);
        let expired = Arc::new(AtomicBool::new(false));

        let validation = tokio::spawn({
            let expired = Arc::clone(&expired);
            async move {
                let first = registry
                    .validate_with_clock(
                        &backend,
                        binding,
                        EspCounterProofRequirement::BeforeFirstPublication,
                        move || {
                            if expired.load(Ordering::Acquire) {
                                after_expiry
                            } else {
                                before_expiry
                            }
                        },
                    )
                    .await
                    .unwrap_err();
                let second = registry
                    .validate_with_clock(
                        &backend,
                        binding,
                        EspCounterProofRequirement::BeforeFirstPublication,
                        || after_expiry,
                    )
                    .await
                    .unwrap_err();
                (first.code(), second.code())
            }
        });

        tokio::time::timeout(Duration::from_secs(2), async {
            while !capture.readback_blocked.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("validation reaches the blocked final readback");
        expired.store(true, Ordering::Release);
        capture.release_readback();

        assert_eq!(
            validation.await.unwrap(),
            (
                "esp_counter_receipt_absent_or_stale",
                "esp_counter_receipt_absent_or_stale"
            )
        );
        assert_eq!(capture.calls.load(Ordering::Acquire), 2);
    }
}
