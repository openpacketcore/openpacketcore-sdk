//! Applied ESP outbound-counter proof for same-SPI failover.
//!
//! A numeric "next sequence" value is only a declaration. This module binds
//! that declaration to one exact outbound ESP SA update and authoritative
//! kernel readback. The returned receipt is opaque and constructor-private;
//! [`XfrmEspCounterResumeAuthority`] also retains a bounded, instance-scoped
//! copy so a re-pin coordinator can validate it immediately before publishing
//! traffic.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::num::{NonZeroU128, NonZeroU32, NonZeroU64, NonZeroUsize};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::{
    QuerySaRequest, RekeySaRequest, SaParameters, SaRelocationIdentity, SaRelocationSelector,
    SaReplayState, SaState, XfrmBackend, XfrmError,
};

/// Default maximum number of active ESP counter receipts retained per
/// authority instance.
pub const DEFAULT_ESP_COUNTER_RECEIPT_CAPACITY: usize = 1024;

/// Maximum number of opaque ESP counter receipts admitted into one re-pin
/// proof set.
pub const MAX_ESP_COUNTER_PROOF_SET_SIZE: usize = 64;

/// Correlation binding supplied by the re-pin domain.
//
// This type is deliberately not evidence. It is safe for a caller to build and
// persist because only an authority-issued private receipt can satisfy it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EspCounterResumeBinding {
    operation_id: NonZeroU128,
    predecessor_generation: NonZeroU64,
    spi: NonZeroU32,
    requested_next: NonZeroU64,
}

impl EspCounterResumeBinding {
    /// Build a binding for one re-pin operation and predecessor ownership
    /// generation.
    pub fn new(
        operation_id: u128,
        predecessor_generation: u64,
        spi: u32,
        requested_next: u64,
    ) -> Result<Self, EspCounterResumeError> {
        let operation_id =
            NonZeroU128::new(operation_id).ok_or(EspCounterResumeError::InvalidRequest {
                code: "esp_counter_operation_id_zero",
            })?;
        let predecessor_generation = NonZeroU64::new(predecessor_generation).ok_or(
            EspCounterResumeError::InvalidRequest {
                code: "esp_counter_predecessor_generation_zero",
            },
        )?;
        let spi = NonZeroU32::new(spi).ok_or(EspCounterResumeError::InvalidRequest {
            code: "esp_counter_spi_zero",
        })?;
        let requested_next =
            NonZeroU64::new(requested_next).ok_or(EspCounterResumeError::InvalidRequest {
                code: "esp_counter_requested_next_zero",
            })?;
        Ok(Self {
            operation_id,
            predecessor_generation,
            spi,
            requested_next,
        })
    }

    const fn requested_last_assigned(self) -> u64 {
        // Construction proves requested_next is non-zero.
        self.requested_next.get() - 1
    }
}

impl fmt::Debug for EspCounterResumeBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EspCounterResumeBinding([redacted])")
    }
}

/// Direction associated with one counter application request.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EspCounterResumeDirection {
    /// Outbound ESP state whose sequence is assigned by Linux before output.
    Outbound,
    /// Inbound ESP state. It is representable so the proof boundary can reject
    /// accidental use of an inbound replay field.
    Inbound,
}

/// Complete request for applying and reading back an outbound ESP counter.
#[derive(Clone)]
pub struct EspCounterResumeApplyRequest {
    /// Re-pin operation, predecessor generation, SPI, and requested next value.
    pub binding: EspCounterResumeBinding,
    /// Complete replacement SA parameters, including existing key custody and
    /// the replay state whose outbound sequence must equal `next - 1`.
    pub parameters: SaParameters,
    /// SA traffic direction.
    pub direction: EspCounterResumeDirection,
}

impl fmt::Debug for EspCounterResumeApplyRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspCounterResumeApplyRequest")
            .field("binding", &"[redacted]")
            .field("parameters", &"[redacted]")
            .field("direction", &self.direction)
            .finish()
    }
}

/// Read-only recovery request used after an authoritative ownership grant was
/// already committed before process loss.
//
// This request carries no key material. A recovered receipt is accepted only
// at the coordinator's post-commit boundary; it can never authorize a new
// ownership mutation.
#[derive(Clone)]
pub struct EspCounterResumeRecoveryRequest {
    /// Exact re-pin binding retained by the durable request.
    pub binding: EspCounterResumeBinding,
    /// Exact non-secret SA identity retained by the consumer.
    pub identity: SaRelocationIdentity,
    /// Replay state originally requested by the applied transition.
    pub replay_state: SaReplayState,
}

impl fmt::Debug for EspCounterResumeRecoveryRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspCounterResumeRecoveryRequest")
            .field("binding", &"[redacted]")
            .field("identity", &"[redacted]")
            .field("replay_state", &"[redacted]")
            .finish()
    }
}

/// Validation point requested by the re-pin coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EspCounterProofRequirement {
    /// Exact apply/readback evidence is required before a new ownership fence.
    BeforeOwnershipCommit,
    /// Exact evidence is required after fencing and immediately before the
    /// first steering publication.
    BeforeFirstPublication,
    /// A v3 ownership grant is already authoritative. A recovered receipt may
    /// prove that the kernel sequence has remained at or advanced beyond the
    /// requested floor without rolling it back.
    CommittedRecovery,
}

/// Opaque evidence that an exact outbound ESP update and readback completed.
//
// No public constructor or field exposes the operation, SPI, namespace,
// counter, key material, or addresses. The receipt retains a private handle to
// the issuing authority, whose bounded record is revalidated at every use.
///
/// Receipts cannot be constructed outside this crate:
///
/// ```compile_fail
/// let _receipt = opc_ipsec_xfrm::AppliedEspCounterReceipt {};
/// ```
pub struct AppliedEspCounterReceipt {
    binding: EspCounterResumeBinding,
    validator: Arc<dyn EspCounterReceiptValidator>,
    _private: ReceiptSeal,
}

struct ReceiptSeal;

impl Clone for AppliedEspCounterReceipt {
    fn clone(&self) -> Self {
        Self {
            binding: self.binding,
            validator: self.validator.clone(),
            _private: ReceiptSeal,
        }
    }
}

impl fmt::Debug for AppliedEspCounterReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppliedEspCounterReceipt([redacted])")
    }
}

#[async_trait]
trait EspCounterReceiptValidator: Send + Sync + fmt::Debug {
    async fn validate(
        &self,
        binding: EspCounterResumeBinding,
        requirement: EspCounterProofRequirement,
    ) -> Result<(), EspCounterResumeError>;
}

/// Bounded collection of opaque counter receipts accepted by one re-pin
/// coordinator.
///
/// Callers can build this value only from adapter-issued receipts. A set can
/// cover the default and dedicated ESP SAs of one bounded session plan without
/// making a raw authority or caller-declared counter sufficient evidence.
#[derive(Clone)]
pub struct EspCounterResumeProofSet {
    receipts: HashMap<EspCounterResumeBinding, AppliedEspCounterReceipt>,
}

impl EspCounterResumeProofSet {
    /// Build a proof set from one or more opaque receipts.
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
            let binding = receipt.binding;
            if collected.insert(binding, receipt).is_some() {
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

    /// Build a proof set containing one opaque receipt.
    #[must_use]
    pub fn single(receipt: AppliedEspCounterReceipt) -> Self {
        let binding = receipt.binding;
        let mut receipts = HashMap::new();
        receipts.insert(binding, receipt);
        Self { receipts }
    }

    /// Revalidate the exact receipt at one coordinator lifecycle boundary.
    pub async fn validate_counter_proof(
        &self,
        binding: EspCounterResumeBinding,
        requirement: EspCounterProofRequirement,
    ) -> Result<(), EspCounterResumeError> {
        let receipt =
            self.receipts
                .get(&binding)
                .ok_or(EspCounterResumeError::ProofUnavailable {
                    code: "esp_counter_receipt_absent_or_stale",
                })?;
        receipt.validator.validate(binding, requirement).await
    }
}

impl fmt::Debug for EspCounterResumeProofSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspCounterResumeProofSet")
            .field("receipt_count", &self.receipts.len())
            .finish_non_exhaustive()
    }
}

/// Redaction-safe failure from the ESP counter proof boundary.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EspCounterResumeError {
    /// The request cannot represent a safe outbound ESN state.
    #[error("invalid ESP counter resume request ({code})")]
    InvalidRequest {
        /// Stable payload-free diagnostic code.
        code: &'static str,
    },
    /// No matching authority-issued receipt is active.
    #[error("ESP counter resume proof is unavailable ({code})")]
    ProofUnavailable {
        /// Stable payload-free diagnostic code.
        code: &'static str,
    },
    /// Exact or monotonic kernel readback did not match the receipt.
    #[error("ESP counter resume readback was rejected ({code})")]
    ReadbackRejected {
        /// Stable payload-free diagnostic code.
        code: &'static str,
    },
    /// The backend operation failed without retaining payload-bearing details.
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

/// Bounded XFRM authority that updates one exact SA and verifies GETSA state.
pub struct XfrmEspCounterResumeAuthority<B> {
    backend: Arc<B>,
    operations: Arc<tokio::sync::Mutex<()>>,
    receipts: Arc<Mutex<ReceiptState>>,
    capacity: NonZeroUsize,
}

impl<B> Clone for XfrmEspCounterResumeAuthority<B> {
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            operations: self.operations.clone(),
            receipts: self.receipts.clone(),
            capacity: self.capacity,
        }
    }
}

impl<B> fmt::Debug for XfrmEspCounterResumeAuthority<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let receipt_count = self
            .receipts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .records
            .len();
        f.debug_struct("XfrmEspCounterResumeAuthority")
            .field("capacity", &self.capacity)
            .field("active_receipts", &receipt_count)
            .finish_non_exhaustive()
    }
}

impl<B> XfrmEspCounterResumeAuthority<B>
where
    B: XfrmBackend + 'static,
{
    /// Build an authority with the default bounded receipt capacity.
    #[must_use]
    pub fn new(backend: B) -> Self {
        // The constant is non-zero by construction.
        let capacity =
            NonZeroUsize::new(DEFAULT_ESP_COUNTER_RECEIPT_CAPACITY).unwrap_or(NonZeroUsize::MIN);
        Self::with_capacity(backend, capacity)
    }

    /// Build an authority with an explicit non-zero receipt capacity.
    #[must_use]
    pub fn with_capacity(backend: B, capacity: NonZeroUsize) -> Self {
        Self {
            backend: Arc::new(backend),
            operations: Arc::new(tokio::sync::Mutex::new(())),
            receipts: Arc::new(Mutex::new(ReceiptState::default())),
            capacity,
        }
    }

    /// Apply the requested complete SA state, read back the exact SA, and
    /// activate an opaque receipt only after every check succeeds.
    ///
    /// The adapter deliberately uses the existing `rekey_sa`/`UPDSA` path: a
    /// replacement SA must already exist, and retrying after cancellation
    /// reapplies the same complete state rather than treating `EEXIST` as
    /// success. Key material remains inside the existing request/backend
    /// custody path and is never copied into a receipt.
    ///
    /// # Cancel safety
    ///
    /// On first poll, the complete apply/readback operation moves into an
    /// owned Tokio task. Dropping the observing future does not cancel the
    /// backend mutation, release same-authority serialization, or return a
    /// receipt. A later exact retry waits for that worker, invalidates any
    /// unobserved record it completed, and reapplies/readbacks the same state.
    pub async fn apply_and_read_back(
        &self,
        request: EspCounterResumeApplyRequest,
    ) -> Result<AppliedEspCounterReceipt, EspCounterResumeError> {
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| EspCounterResumeError::Backend {
                code: "esp_counter_runtime_unavailable",
            })?;
        let authority = self.clone();
        runtime
            .spawn(async move { authority.apply_and_read_back_inner(request).await })
            .await
            .map_err(|_| EspCounterResumeError::Backend {
                code: "esp_counter_apply_worker_terminated",
            })?
    }

    async fn apply_and_read_back_inner(
        &self,
        request: EspCounterResumeApplyRequest,
    ) -> Result<AppliedEspCounterReceipt, EspCounterResumeError> {
        let _operation = self.operations.lock().await;
        let namespace = NetworkNamespaceIdentity::current()?;
        let record = ReceiptRecord::from_apply_request(&request, namespace)?;
        self.verify_identity(&record).await?;
        // Once an exact replacement mutation is about to be attempted, no
        // earlier operation for this kernel object may remain authoritative.
        // A failed or cancelled update therefore leaves no stale receipt that
        // could be replayed after an indeterminate outcome.
        self.invalidate_for_attempt(record.binding, record.query);
        record.ensure_current_namespace()?;
        let update = self
            .backend
            .rekey_sa(RekeySaRequest {
                parameters: request.parameters,
            })
            .await;
        record.ensure_current_namespace()?;
        update.map_err(map_backend_error)?;
        self.verify_record(&record, ReadbackMode::Exact).await?;
        let binding = record.binding;
        self.activate(record);
        Ok(AppliedEspCounterReceipt {
            binding,
            validator: Arc::new(self.clone()),
            _private: ReceiptSeal,
        })
    }

    /// Rehydrate a receipt after process loss when ownership already contains
    /// the exact v3 transition grant.
    ///
    /// This performs no mutation and accepts a counter only at or above the
    /// originally applied floor. The resulting receipt is tagged recovered and
    /// therefore cannot authorize a new ownership fence; it is useful only
    /// when [`EspCounterProofRequirement::CommittedRecovery`] is requested.
    pub async fn recover_committed_readback(
        &self,
        request: EspCounterResumeRecoveryRequest,
    ) -> Result<AppliedEspCounterReceipt, EspCounterResumeError> {
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| EspCounterResumeError::Backend {
                code: "esp_counter_runtime_unavailable",
            })?;
        let authority = self.clone();
        runtime
            .spawn(async move { authority.recover_committed_readback_inner(request).await })
            .await
            .map_err(|_| EspCounterResumeError::Backend {
                code: "esp_counter_recovery_worker_terminated",
            })?
    }

    async fn recover_committed_readback_inner(
        &self,
        request: EspCounterResumeRecoveryRequest,
    ) -> Result<AppliedEspCounterReceipt, EspCounterResumeError> {
        let _operation = self.operations.lock().await;
        let namespace = NetworkNamespaceIdentity::current()?;
        let record = ReceiptRecord::from_recovery_request(request, namespace)?;
        self.verify_record(&record, ReadbackMode::Monotonic).await?;
        let binding = record.binding;
        self.activate(record);
        Ok(AppliedEspCounterReceipt {
            binding,
            validator: Arc::new(self.clone()),
            _private: ReceiptSeal,
        })
    }

    async fn verify_identity(&self, record: &ReceiptRecord) -> Result<(), EspCounterResumeError> {
        record.ensure_current_namespace()?;
        let observed = self
            .backend
            .query_sa_relocation_identity(record.query)
            .await;
        record.ensure_current_namespace()?;
        let observed = observed.map_err(map_backend_error)?;
        identity_matches(&record.identity, &observed, record.requested_egress_dscp)
    }

    async fn verify_record(
        &self,
        record: &ReceiptRecord,
        mode: ReadbackMode,
    ) -> Result<(), EspCounterResumeError> {
        self.verify_identity(record).await?;
        record.ensure_current_namespace()?;
        let state = self.backend.query_sa(record.query).await;
        record.ensure_current_namespace()?;
        let state = state.map_err(map_backend_error)?;
        verify_sa_state(record, &state, mode)
    }

    fn activate(&self, record: ReceiptRecord) {
        let mut state = self
            .receipts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.remove_binding(record.binding);
        state.remove_query(record.query);
        while state.records.len() >= self.capacity.get() {
            let Some(oldest) = state.order.pop_front() else {
                state.records.clear();
                break;
            };
            state.records.remove(&oldest);
        }
        state.order.push_back(record.binding);
        state.records.insert(record.binding, record);
    }

    fn invalidate_for_attempt(&self, binding: EspCounterResumeBinding, query: QuerySaRequest) {
        let mut state = self
            .receipts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.remove_binding(binding);
        state.remove_query(query);
    }

    fn receipt(&self, binding: EspCounterResumeBinding) -> Option<ReceiptRecord> {
        self.receipts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .records
            .get(&binding)
            .cloned()
    }

    pub(crate) async fn validate_counter_proof(
        &self,
        binding: EspCounterResumeBinding,
        requirement: EspCounterProofRequirement,
    ) -> Result<(), EspCounterResumeError> {
        let _operation = self.operations.lock().await;
        let record = self
            .receipt(binding)
            .ok_or(EspCounterResumeError::ProofUnavailable {
                code: "esp_counter_receipt_absent_or_stale",
            })?;
        match requirement {
            EspCounterProofRequirement::BeforeOwnershipCommit
            | EspCounterProofRequirement::BeforeFirstPublication
                if record.provenance != ReceiptProvenance::Applied =>
            {
                return Err(EspCounterResumeError::ProofUnavailable {
                    code: "esp_counter_recovered_receipt_cannot_fence",
                });
            }
            EspCounterProofRequirement::BeforeOwnershipCommit
            | EspCounterProofRequirement::BeforeFirstPublication => {
                self.verify_record(&record, ReadbackMode::Exact).await
            }
            EspCounterProofRequirement::CommittedRecovery => {
                self.verify_record(&record, ReadbackMode::Monotonic).await
            }
        }
    }
}

#[async_trait]
impl<B> EspCounterReceiptValidator for XfrmEspCounterResumeAuthority<B>
where
    B: XfrmBackend + 'static,
{
    async fn validate(
        &self,
        binding: EspCounterResumeBinding,
        requirement: EspCounterProofRequirement,
    ) -> Result<(), EspCounterResumeError> {
        self.validate_counter_proof(binding, requirement).await
    }
}

#[derive(Default)]
struct ReceiptState {
    records: HashMap<EspCounterResumeBinding, ReceiptRecord>,
    order: VecDeque<EspCounterResumeBinding>,
}

impl ReceiptState {
    fn remove_binding(&mut self, binding: EspCounterResumeBinding) {
        self.records.remove(&binding);
        self.order.retain(|candidate| *candidate != binding);
    }

    fn remove_query(&mut self, query: QuerySaRequest) {
        let stale: Vec<_> = self
            .records
            .iter()
            .filter_map(|(binding, record)| (record.query == query).then_some(*binding))
            .collect();
        for binding in stale {
            self.remove_binding(binding);
        }
    }
}

#[derive(Clone)]
struct ReceiptRecord {
    binding: EspCounterResumeBinding,
    query: QuerySaRequest,
    identity: SaRelocationIdentity,
    replay_state: SaReplayState,
    requested_egress_dscp: Option<opc_types::DscpCodepoint>,
    namespace: NetworkNamespaceIdentity,
    provenance: ReceiptProvenance,
}

impl ReceiptRecord {
    fn from_apply_request(
        request: &EspCounterResumeApplyRequest,
        namespace: NetworkNamespaceIdentity,
    ) -> Result<Self, EspCounterResumeError> {
        if request.direction != EspCounterResumeDirection::Outbound {
            return Err(EspCounterResumeError::InvalidRequest {
                code: "esp_counter_direction_not_outbound",
            });
        }
        validate_parameters(request.binding, &request.parameters)?;
        let query = QuerySaRequest {
            destination: request.parameters.id.destination,
            protocol: request.parameters.id.protocol,
            spi: request.parameters.id.spi,
            mark: request.parameters.mark,
        };
        Ok(Self {
            binding: request.binding,
            query,
            identity: identity_from_parameters(&request.parameters),
            replay_state: request.parameters.replay_state.clone().ok_or(
                EspCounterResumeError::InvalidRequest {
                    code: "esp_counter_replay_state_missing",
                },
            )?,
            requested_egress_dscp: request.parameters.egress_dscp,
            namespace,
            provenance: ReceiptProvenance::Applied,
        })
    }

    fn from_recovery_request(
        request: EspCounterResumeRecoveryRequest,
        namespace: NetworkNamespaceIdentity,
    ) -> Result<Self, EspCounterResumeError> {
        validate_replay_state(request.binding, &request.replay_state)?;
        if request.identity.id.protocol != 50
            || request.identity.id.spi != request.binding.spi.get()
        {
            return Err(EspCounterResumeError::InvalidRequest {
                code: "esp_counter_recovery_identity_mismatch",
            });
        }
        let query = QuerySaRequest {
            destination: request.identity.id.destination,
            protocol: request.identity.id.protocol,
            spi: request.identity.id.spi,
            mark: request.identity.mark,
        };
        Ok(Self {
            binding: request.binding,
            query,
            identity: request.identity,
            replay_state: request.replay_state,
            requested_egress_dscp: None,
            namespace,
            provenance: ReceiptProvenance::RecoveredCommitted,
        })
    }

    fn ensure_current_namespace(&self) -> Result<(), EspCounterResumeError> {
        if NetworkNamespaceIdentity::current()? != self.namespace {
            return Err(EspCounterResumeError::ProofUnavailable {
                code: "esp_counter_network_namespace_mismatch",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct NetworkNamespaceIdentity {
    device: u64,
    inode: u64,
}

impl NetworkNamespaceIdentity {
    #[cfg(target_os = "linux")]
    fn current() -> Result<Self, EspCounterResumeError> {
        use std::os::unix::fs::MetadataExt;

        let metadata = std::fs::metadata("/proc/thread-self/ns/net").map_err(|_| {
            EspCounterResumeError::Backend {
                code: "esp_counter_network_namespace_identity_unavailable",
            }
        })?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    #[cfg(not(target_os = "linux"))]
    const fn current() -> Result<Self, EspCounterResumeError> {
        Ok(Self {
            device: 0,
            inode: 0,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReceiptProvenance {
    Applied,
    RecoveredCommitted,
}

#[derive(Clone, Copy)]
enum ReadbackMode {
    Exact,
    Monotonic,
}

fn validate_parameters(
    binding: EspCounterResumeBinding,
    parameters: &SaParameters,
) -> Result<(), EspCounterResumeError> {
    if parameters.id.protocol != 50 {
        return Err(EspCounterResumeError::InvalidRequest {
            code: "esp_counter_protocol_not_esp",
        });
    }
    if parameters.id.spi != binding.spi.get() {
        return Err(EspCounterResumeError::InvalidRequest {
            code: "esp_counter_spi_mismatch",
        });
    }
    let replay_state =
        parameters
            .replay_state
            .as_ref()
            .ok_or(EspCounterResumeError::InvalidRequest {
                code: "esp_counter_replay_state_missing",
            })?;
    validate_replay_state(binding, replay_state)
}

fn validate_replay_state(
    binding: EspCounterResumeBinding,
    replay_state: &SaReplayState,
) -> Result<(), EspCounterResumeError> {
    if !replay_state.esn {
        return Err(EspCounterResumeError::InvalidRequest {
            code: "esp_counter_esn_required",
        });
    }
    if replay_state.replay_window == 0 {
        return Err(EspCounterResumeError::InvalidRequest {
            code: "esp_counter_replay_window_zero",
        });
    }
    let required_bitmap_words = replay_state.replay_window.div_ceil(32) as usize;
    if replay_state.bitmap.len() != required_bitmap_words {
        return Err(EspCounterResumeError::InvalidRequest {
            code: "esp_counter_esn_bitmap_ambiguous",
        });
    }
    let observed_last = combine_esn(
        replay_state.outbound_sequence_hi,
        replay_state.outbound_sequence,
    );
    let observed_next =
        observed_last
            .checked_add(1)
            .ok_or(EspCounterResumeError::InvalidRequest {
                code: "esp_counter_sequence_wrap",
            })?;
    if observed_next != binding.requested_next.get() {
        return Err(EspCounterResumeError::InvalidRequest {
            code: "esp_counter_requested_next_mapping_mismatch",
        });
    }
    Ok(())
}

fn identity_from_parameters(parameters: &SaParameters) -> SaRelocationIdentity {
    SaRelocationIdentity {
        selector: SaRelocationSelector::from_selector(&parameters.selector),
        id: parameters.id,
        source_address: parameters.source_address,
        request_id: parameters.request_id,
        mode: parameters.mode,
        encap: parameters.encap,
        mark: parameters.mark,
        if_id: parameters.if_id,
        output_mark: parameters.output_mark,
    }
}

fn identity_matches(
    expected: &SaRelocationIdentity,
    observed: &SaRelocationIdentity,
    requested_egress_dscp: Option<opc_types::DscpCodepoint>,
) -> Result<(), EspCounterResumeError> {
    let output_mark_matches =
        requested_egress_dscp.is_some() || expected.output_mark == observed.output_mark;
    if expected.selector != observed.selector
        || expected.id != observed.id
        || expected.source_address != observed.source_address
        || expected.request_id != observed.request_id
        || expected.mode != observed.mode
        || expected.encap != observed.encap
        || expected.mark != observed.mark
        || expected.if_id != observed.if_id
        || !output_mark_matches
    {
        return Err(EspCounterResumeError::ReadbackRejected {
            code: "esp_counter_exact_sa_identity_mismatch",
        });
    }
    Ok(())
}

fn verify_sa_state(
    record: &ReceiptRecord,
    observed: &SaState,
    mode: ReadbackMode,
) -> Result<(), EspCounterResumeError> {
    if observed.id != record.identity.id
        || observed.selector != record.identity.selector.selector()
        || observed.source_address != record.identity.source_address
        || observed.request_id != record.identity.request_id
        || observed.mode != record.identity.mode
        || observed.replay_window != record.replay_state.replay_window
        || !observed.replay_state.esn
    {
        return Err(EspCounterResumeError::ReadbackRejected {
            code: "esp_counter_sa_state_mismatch",
        });
    }
    if let Some(dscp) = record.requested_egress_dscp {
        if observed.egress_dscp != Some(dscp) {
            return Err(EspCounterResumeError::ReadbackRejected {
                code: "esp_counter_sa_state_mismatch",
            });
        }
    } else if observed.output_mark != record.identity.output_mark {
        return Err(EspCounterResumeError::ReadbackRejected {
            code: "esp_counter_sa_state_mismatch",
        });
    }
    let observed_outbound = combine_esn(
        observed.replay_state.outbound_sequence_hi,
        observed.replay_state.outbound_sequence,
    );
    let observed_next =
        observed_outbound
            .checked_add(1)
            .ok_or(EspCounterResumeError::ReadbackRejected {
                code: "esp_counter_sequence_exhausted",
            })?;
    match mode {
        ReadbackMode::Exact
            if observed_next != record.binding.requested_next.get()
                || observed.replay_state != record.replay_state =>
        {
            Err(EspCounterResumeError::ReadbackRejected {
                code: "esp_counter_exact_replay_state_mismatch",
            })
        }
        ReadbackMode::Monotonic if observed_outbound < record.binding.requested_last_assigned() => {
            Err(EspCounterResumeError::ReadbackRejected {
                code: "esp_counter_readback_below_applied_floor",
            })
        }
        ReadbackMode::Exact | ReadbackMode::Monotonic => Ok(()),
    }
}

const fn combine_esn(high: u32, low: u32) -> u64 {
    (high as u64) << 32 | low as u64
}

fn map_backend_error(error: XfrmError) -> EspCounterResumeError {
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
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

    use super::*;
    use crate::{
        AeadAlgorithm, AllocateSpiRequest, InstallPolicyRequest, InstallSaRequest, IpAddress,
        KeyMaterial, LifetimeConfig, MockXfrmBackend, RekeyPolicyRequest, RelocateSaRequest,
        RemovePolicyRequest, RemoveSaRequest, SpiAllocation, XfrmCapability, XfrmId, XfrmMark,
        XfrmMode, XfrmProbe, XfrmSelector,
    };

    const CONTROL_PASS: u8 = 0;
    const CONTROL_BLOCK: u8 = 1;
    const CONTROL_NOT_FOUND: u8 = 2;
    const CONTROL_FOREIGN: u8 = 3;
    const CONTROL_INDETERMINATE: u8 = 4;
    const CONTROL_UNAVAILABLE: u8 = 5;

    #[derive(Clone)]
    struct ControlledReadbackBackend {
        inner: MockXfrmBackend,
        rekey_mode: Arc<AtomicU8>,
        identity_mode: Arc<AtomicU8>,
        state_mode: Arc<AtomicU8>,
        identity_reads: Arc<AtomicUsize>,
        reached: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    impl fmt::Debug for ControlledReadbackBackend {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("ControlledReadbackBackend([redacted])")
        }
    }

    impl ControlledReadbackBackend {
        fn new(inner: MockXfrmBackend) -> Self {
            Self {
                inner,
                rekey_mode: Arc::new(AtomicU8::new(CONTROL_PASS)),
                identity_mode: Arc::new(AtomicU8::new(CONTROL_PASS)),
                state_mode: Arc::new(AtomicU8::new(CONTROL_PASS)),
                identity_reads: Arc::new(AtomicUsize::new(0)),
                reached: Arc::new(tokio::sync::Notify::new()),
                release: Arc::new(tokio::sync::Notify::new()),
            }
        }

        fn set_rekey_mode(&self, mode: u8) {
            self.rekey_mode.store(mode, Ordering::SeqCst);
        }

        fn set_identity_mode(&self, mode: u8) {
            self.identity_mode.store(mode, Ordering::SeqCst);
        }

        fn set_state_mode(&self, mode: u8) {
            self.state_mode.store(mode, Ordering::SeqCst);
        }

        async fn wait_until_reached(&self) {
            self.reached.notified().await;
        }

        fn release(&self) {
            self.release.notify_waiters();
        }

        async fn maybe_control(&self, mode: u8) -> Result<(), XfrmError> {
            match mode {
                CONTROL_PASS | CONTROL_NOT_FOUND | CONTROL_FOREIGN | CONTROL_UNAVAILABLE => Ok(()),
                CONTROL_BLOCK => {
                    self.reached.notify_one();
                    self.release.notified().await;
                    Ok(())
                }
                CONTROL_INDETERMINATE => Err(XfrmError::StateIndeterminate {
                    operation: "controlled_counter_readback",
                }),
                _ => Err(XfrmError::Unavailable),
            }
        }
    }

    #[async_trait::async_trait]
    impl XfrmBackend for ControlledReadbackBackend {
        async fn allocate_spi(
            &self,
            request: AllocateSpiRequest,
        ) -> Result<SpiAllocation, XfrmError> {
            self.inner.allocate_spi(request).await
        }

        async fn install_sa(&self, request: InstallSaRequest) -> Result<(), XfrmError> {
            self.inner.install_sa(request).await
        }

        async fn query_sa(&self, request: QuerySaRequest) -> Result<SaState, XfrmError> {
            let mode = self.state_mode.load(Ordering::SeqCst);
            match mode {
                CONTROL_NOT_FOUND => Err(XfrmError::NotFound),
                CONTROL_UNAVAILABLE => Err(XfrmError::Unavailable),
                CONTROL_INDETERMINATE => Err(XfrmError::StateIndeterminate {
                    operation: "controlled_counter_getsa",
                }),
                CONTROL_FOREIGN => {
                    let mut state = self.inner.query_sa(request).await?;
                    state.id.spi = state.id.spi.wrapping_add(1).max(1);
                    Ok(state)
                }
                _ => self.inner.query_sa(request).await,
            }
        }

        async fn query_sa_relocation_identity(
            &self,
            request: QuerySaRequest,
        ) -> Result<SaRelocationIdentity, XfrmError> {
            let read = self.identity_reads.fetch_add(1, Ordering::SeqCst);
            if read > 0 {
                self.maybe_control(self.identity_mode.load(Ordering::SeqCst))
                    .await?;
            }
            self.inner.query_sa_relocation_identity(request).await
        }

        async fn rekey_sa(&self, request: RekeySaRequest) -> Result<(), XfrmError> {
            self.maybe_control(self.rekey_mode.load(Ordering::SeqCst))
                .await?;
            self.inner.rekey_sa(request).await
        }

        async fn relocate_sa(&self, request: RelocateSaRequest) -> Result<(), XfrmError> {
            self.inner.relocate_sa(request).await
        }

        async fn sa_relocation_capability(&self) -> Result<XfrmCapability, XfrmError> {
            self.inner.sa_relocation_capability().await
        }

        async fn remove_sa(&self, request: RemoveSaRequest) -> Result<(), XfrmError> {
            self.inner.remove_sa(request).await
        }

        async fn install_policy(&self, request: InstallPolicyRequest) -> Result<(), XfrmError> {
            self.inner.install_policy(request).await
        }

        async fn rekey_policy(&self, request: RekeyPolicyRequest) -> Result<(), XfrmError> {
            self.inner.rekey_policy(request).await
        }

        async fn remove_policy(&self, request: RemovePolicyRequest) -> Result<(), XfrmError> {
            self.inner.remove_policy(request).await
        }

        async fn probe(&self) -> Result<XfrmProbe, XfrmError> {
            self.inner.probe().await
        }
    }

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddress {
        IpAddress::Ipv4([a, b, c, d])
    }

    fn binding(operation: u128, generation: u64, spi: u32, next: u64) -> EspCounterResumeBinding {
        EspCounterResumeBinding::new(operation, generation, spi, next).unwrap()
    }

    fn parameters(spi: u32, next: u64) -> SaParameters {
        let last = next - 1;
        SaParameters {
            selector: XfrmSelector::new(ip(10, 0, 0, 1), ip(10, 0, 0, 2), 17),
            id: XfrmId {
                destination: ip(192, 0, 2, 2),
                spi,
                protocol: 50,
            },
            source_address: ip(192, 0, 2, 1),
            request_id: None,
            auth: None,
            crypt: None,
            aead: Some((
                AeadAlgorithm::rfc4106_gcm_aes(128),
                KeyMaterial::new(vec![0x11; 20]),
            )),
            mode: XfrmMode::Tunnel,
            lifetime: LifetimeConfig::default(),
            replay_window: 64,
            replay_state: Some(SaReplayState {
                esn: true,
                outbound_sequence: last as u32,
                inbound_sequence: 11,
                outbound_sequence_hi: (last >> 32) as u32,
                inbound_sequence_hi: 0,
                replay_window: 64,
                bitmap: vec![1, 0],
            }),
            encap: None,
            mark: None,
            output_mark: None,
            if_id: None,
            egress_dscp: None,
        }
    }

    fn apply_request(
        operation: u128,
        generation: u64,
        spi: u32,
        next: u64,
    ) -> EspCounterResumeApplyRequest {
        EspCounterResumeApplyRequest {
            binding: binding(operation, generation, spi, next),
            parameters: parameters(spi, next),
            direction: EspCounterResumeDirection::Outbound,
        }
    }

    async fn install_initial(backend: &MockXfrmBackend, spi: u32) {
        backend
            .install_sa(InstallSaRequest {
                parameters: parameters(spi, 1),
            })
            .await
            .unwrap();
    }

    async fn installed_authority(
        spi: u32,
        next: u64,
    ) -> (
        MockXfrmBackend,
        XfrmEspCounterResumeAuthority<MockXfrmBackend>,
        AppliedEspCounterReceipt,
    ) {
        let backend = MockXfrmBackend::new();
        let params = parameters(spi, 1);
        backend
            .install_sa(InstallSaRequest { parameters: params })
            .await
            .unwrap();
        let authority = XfrmEspCounterResumeAuthority::new(backend.clone());
        let request = EspCounterResumeApplyRequest {
            binding: binding(7, 3, spi, next),
            parameters: parameters(spi, next),
            direction: EspCounterResumeDirection::Outbound,
        };
        let receipt = authority.apply_and_read_back(request).await.unwrap();
        (backend, authority, receipt)
    }

    #[tokio::test]
    async fn exact_apply_then_readback_issues_non_forgeable_receipt() {
        let (backend, _, receipt) = installed_authority(0x1122_3344, (1_u64 << 32) + 9).await;
        EspCounterResumeProofSet::single(receipt)
            .validate_counter_proof(
                binding(7, 3, 0x1122_3344, (1_u64 << 32) + 9),
                EspCounterProofRequirement::BeforeFirstPublication,
            )
            .await
            .unwrap();
        let operations = backend.operations();
        assert!(operations
            .iter()
            .any(|operation| matches!(operation, crate::MockOperation::RekeySa { .. })));
        assert!(
            operations
                .iter()
                .filter(|operation| matches!(operation, crate::MockOperation::QuerySa { .. }))
                .count()
                >= 4
        );
    }

    #[tokio::test]
    async fn absent_and_mismatched_operation_spi_generation_or_counter_fail_closed() {
        let (_, authority, _) = installed_authority(0x1122_3344, (1_u64 << 32) + 9).await;
        for mismatch in [
            binding(8, 3, 0x1122_3344, (1_u64 << 32) + 9),
            binding(7, 4, 0x1122_3344, (1_u64 << 32) + 9),
            binding(7, 3, 0x1122_3345, (1_u64 << 32) + 9),
            binding(7, 3, 0x1122_3344, (1_u64 << 32) + 10),
        ] {
            let error = authority
                .validate_counter_proof(mismatch, EspCounterProofRequirement::BeforeOwnershipCommit)
                .await
                .unwrap_err();
            assert_eq!(error.code(), "esp_counter_receipt_absent_or_stale");
        }
    }

    #[tokio::test]
    async fn inbound_legacy_and_off_by_one_requests_are_rejected_before_update() {
        let backend = MockXfrmBackend::new();
        let authority = XfrmEspCounterResumeAuthority::new(backend.clone());
        let mut wrong_direction = parameters(9, 100);
        let error = authority
            .apply_and_read_back(EspCounterResumeApplyRequest {
                binding: binding(1, 1, 9, 100),
                parameters: wrong_direction.clone(),
                direction: EspCounterResumeDirection::Inbound,
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), "esp_counter_direction_not_outbound");

        wrong_direction.replay_state.as_mut().unwrap().esn = false;
        let error = authority
            .apply_and_read_back(EspCounterResumeApplyRequest {
                binding: binding(1, 1, 9, 100),
                parameters: wrong_direction,
                direction: EspCounterResumeDirection::Outbound,
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), "esp_counter_esn_required");

        let mut off_by_one = parameters(9, 100);
        off_by_one.replay_state.as_mut().unwrap().outbound_sequence = 100;
        let error = authority
            .apply_and_read_back(EspCounterResumeApplyRequest {
                binding: binding(1, 1, 9, 100),
                parameters: off_by_one,
                direction: EspCounterResumeDirection::Outbound,
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), "esp_counter_requested_next_mapping_mismatch");
        assert!(!backend
            .operations()
            .iter()
            .any(|operation| matches!(operation, crate::MockOperation::RekeySa { .. })));
    }

    #[tokio::test]
    async fn a_new_receipt_for_the_same_exact_sa_invalidates_the_old_operation() {
        let (backend, authority, _) = installed_authority(0x1122_3344, 100).await;
        authority
            .apply_and_read_back(EspCounterResumeApplyRequest {
                binding: binding(8, 4, 0x1122_3344, 200),
                parameters: parameters(0x1122_3344, 200),
                direction: EspCounterResumeDirection::Outbound,
            })
            .await
            .unwrap();
        assert!(authority
            .validate_counter_proof(
                binding(7, 3, 0x1122_3344, 100),
                EspCounterProofRequirement::BeforeOwnershipCommit,
            )
            .await
            .is_err());
        authority
            .validate_counter_proof(
                binding(8, 4, 0x1122_3344, 200),
                EspCounterProofRequirement::BeforeOwnershipCommit,
            )
            .await
            .unwrap();
        assert!(!backend.operations().is_empty());
    }

    #[tokio::test]
    async fn recovered_receipt_is_monotonic_and_cannot_authorize_a_new_fence() {
        let (backend, authority, _) = installed_authority(0x1122_3344, 100).await;
        let mut progressed = parameters(0x1122_3344, 105);
        backend
            .rekey_sa(RekeySaRequest {
                parameters: progressed.clone(),
            })
            .await
            .unwrap();
        let identity = identity_from_parameters(&progressed);
        progressed.replay_state.as_mut().unwrap().outbound_sequence = 99;
        authority
            .recover_committed_readback(EspCounterResumeRecoveryRequest {
                binding: binding(7, 3, 0x1122_3344, 100),
                identity,
                replay_state: progressed.replay_state.unwrap(),
            })
            .await
            .unwrap();
        authority
            .validate_counter_proof(
                binding(7, 3, 0x1122_3344, 100),
                EspCounterProofRequirement::CommittedRecovery,
            )
            .await
            .unwrap();
        let error = authority
            .validate_counter_proof(
                binding(7, 3, 0x1122_3344, 100),
                EspCounterProofRequirement::BeforeOwnershipCommit,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), "esp_counter_recovered_receipt_cannot_fence");
    }

    #[tokio::test]
    async fn marked_identity_and_foreign_state_fail_closed() {
        let backend = MockXfrmBackend::new();
        let mut installed = parameters(9, 1);
        installed.mark = Some(XfrmMark {
            value: 1,
            mask: u32::MAX,
        });
        backend
            .install_sa(InstallSaRequest {
                parameters: installed,
            })
            .await
            .unwrap();
        let authority = XfrmEspCounterResumeAuthority::new(backend);
        let error = authority
            .apply_and_read_back(EspCounterResumeApplyRequest {
                binding: binding(1, 1, 9, 100),
                parameters: parameters(9, 100),
                direction: EspCounterResumeDirection::Outbound,
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), "esp_counter_backend_sa_not_found");
    }

    #[tokio::test]
    async fn absent_foreign_indeterminate_and_unavailable_getsa_never_activate_receipts() {
        for (mode, expected_code) in [
            (CONTROL_NOT_FOUND, "esp_counter_backend_sa_not_found"),
            (CONTROL_FOREIGN, "esp_counter_sa_state_mismatch"),
            (
                CONTROL_INDETERMINATE,
                "esp_counter_backend_state_indeterminate",
            ),
            (CONTROL_UNAVAILABLE, "esp_counter_backend_unavailable"),
        ] {
            let inner = MockXfrmBackend::new();
            install_initial(&inner, 0x1234_5000 + u32::from(mode)).await;
            let backend = ControlledReadbackBackend::new(inner.clone());
            backend.set_state_mode(mode);
            let authority = XfrmEspCounterResumeAuthority::new(backend);
            let spi = 0x1234_5000 + u32::from(mode);
            let exact_binding = binding(1, 1, spi, 100);

            let error = authority
                .apply_and_read_back(apply_request(1, 1, spi, 100))
                .await
                .unwrap_err();
            assert_eq!(error.code(), expected_code);
            let unavailable = authority
                .validate_counter_proof(
                    exact_binding,
                    EspCounterProofRequirement::BeforeOwnershipCommit,
                )
                .await
                .unwrap_err();
            assert_eq!(unavailable.code(), "esp_counter_receipt_absent_or_stale");
            assert!(inner
                .operations()
                .iter()
                .any(|operation| matches!(operation, crate::MockOperation::RekeySa { .. })));
        }
    }

    #[tokio::test]
    async fn cancellation_before_apply_keeps_owned_worker_serialized_until_exact_retry() {
        let inner = MockXfrmBackend::new();
        install_initial(&inner, 0x2233_4455).await;
        let backend = ControlledReadbackBackend::new(inner.clone());
        backend.set_rekey_mode(CONTROL_BLOCK);
        let authority = XfrmEspCounterResumeAuthority::new(backend.clone());
        let request = apply_request(1, 1, 0x2233_4455, 100);
        let task = {
            let authority = authority.clone();
            let request = request.clone();
            tokio::spawn(async move { authority.apply_and_read_back(request).await })
        };
        backend.wait_until_reached().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        let retry = {
            let authority = authority.clone();
            let request = request.clone();
            tokio::spawn(async move { authority.apply_and_read_back(request).await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert!(!inner
            .operations()
            .iter()
            .any(|operation| matches!(operation, crate::MockOperation::RekeySa { .. })));

        backend.set_rekey_mode(CONTROL_PASS);
        backend.release();
        let receipt = retry.await.unwrap().unwrap();
        EspCounterResumeProofSet::single(receipt)
            .validate_counter_proof(
                request.binding,
                EspCounterProofRequirement::BeforeOwnershipCommit,
            )
            .await
            .unwrap();
        assert_eq!(
            inner
                .operations()
                .iter()
                .filter(|operation| matches!(operation, crate::MockOperation::RekeySa { .. }))
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn cancellation_after_apply_keeps_readback_owned_and_invalidates_stale_receipt() {
        let inner = MockXfrmBackend::new();
        install_initial(&inner, 0x3344_5566).await;
        let backend = ControlledReadbackBackend::new(inner.clone());
        let authority = XfrmEspCounterResumeAuthority::new(backend.clone());
        let old = apply_request(1, 1, 0x3344_5566, 50);
        authority.apply_and_read_back(old.clone()).await.unwrap();

        backend.identity_reads.store(0, Ordering::SeqCst);
        backend.set_identity_mode(CONTROL_BLOCK);
        let replacement = apply_request(2, 2, 0x3344_5566, 100);
        let task = {
            let authority = authority.clone();
            let replacement = replacement.clone();
            tokio::spawn(async move { authority.apply_and_read_back(replacement).await })
        };
        backend.wait_until_reached().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        let retry = {
            let authority = authority.clone();
            let replacement = replacement.clone();
            tokio::spawn(async move { authority.apply_and_read_back(replacement).await })
        };
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(10),
            authority.validate_counter_proof(
                old.binding,
                EspCounterProofRequirement::BeforeOwnershipCommit,
            ),
        )
        .await
        .is_err());

        backend.set_identity_mode(CONTROL_PASS);
        backend.release();
        let receipt = retry.await.unwrap().unwrap();

        let old_error = authority
            .validate_counter_proof(
                old.binding,
                EspCounterProofRequirement::BeforeOwnershipCommit,
            )
            .await
            .unwrap_err();
        assert_eq!(old_error.code(), "esp_counter_receipt_absent_or_stale");
        EspCounterResumeProofSet::single(receipt)
            .validate_counter_proof(
                replacement.binding,
                EspCounterProofRequirement::BeforeFirstPublication,
            )
            .await
            .unwrap();
        assert_eq!(
            inner
                .operations()
                .iter()
                .filter(|operation| matches!(operation, crate::MockOperation::RekeySa { .. }))
                .count(),
            3
        );
    }

    #[tokio::test]
    async fn one_authority_serializes_same_sa_apply_and_readback_operations() {
        let inner = MockXfrmBackend::new();
        install_initial(&inner, 0x4455_6677).await;
        let backend = ControlledReadbackBackend::new(inner);
        backend.set_identity_mode(CONTROL_BLOCK);
        let authority = XfrmEspCounterResumeAuthority::new(backend.clone());
        let first_request = apply_request(1, 1, 0x4455_6677, 100);
        let second_request = apply_request(2, 2, 0x4455_6677, 200);

        let first = {
            let authority = authority.clone();
            let request = first_request.clone();
            tokio::spawn(async move { authority.apply_and_read_back(request).await })
        };
        backend.wait_until_reached().await;
        let second = {
            let authority = authority.clone();
            let request = second_request.clone();
            tokio::spawn(async move { authority.apply_and_read_back(request).await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(backend.identity_reads.load(Ordering::SeqCst), 2);

        backend.set_identity_mode(CONTROL_PASS);
        backend.release();
        first.await.unwrap().unwrap();
        second.await.unwrap().unwrap();

        assert!(authority
            .validate_counter_proof(
                first_request.binding,
                EspCounterProofRequirement::BeforeOwnershipCommit,
            )
            .await
            .is_err());
        authority
            .validate_counter_proof(
                second_request.binding,
                EspCounterProofRequirement::BeforeOwnershipCommit,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn receipt_cache_is_bounded_and_authority_instance_scoped() {
        let backend = MockXfrmBackend::new();
        install_initial(&backend, 0x5566_7701).await;
        install_initial(&backend, 0x5566_7702).await;
        let authority = XfrmEspCounterResumeAuthority::with_capacity(
            backend.clone(),
            NonZeroUsize::new(1).unwrap(),
        );
        let first = apply_request(1, 1, 0x5566_7701, 100);
        let second = apply_request(2, 2, 0x5566_7702, 200);
        authority.apply_and_read_back(first.clone()).await.unwrap();
        authority.apply_and_read_back(second.clone()).await.unwrap();
        assert!(authority
            .validate_counter_proof(
                first.binding,
                EspCounterProofRequirement::BeforeOwnershipCommit,
            )
            .await
            .is_err());
        authority
            .validate_counter_proof(
                second.binding,
                EspCounterProofRequirement::BeforeOwnershipCommit,
            )
            .await
            .unwrap();

        let other_instance = XfrmEspCounterResumeAuthority::new(backend);
        let error = other_instance
            .validate_counter_proof(
                second.binding,
                EspCounterProofRequirement::BeforeOwnershipCommit,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), "esp_counter_receipt_absent_or_stale");
    }

    #[tokio::test]
    async fn public_proof_set_rejects_empty_duplicate_and_oversized_receipt_sets() {
        assert_eq!(
            EspCounterResumeProofSet::new(Vec::new())
                .unwrap_err()
                .code(),
            "esp_counter_proof_set_empty"
        );
        let (_, _, receipt) = installed_authority(0x6060_7000, 100).await;
        assert_eq!(
            EspCounterResumeProofSet::new([receipt.clone(), receipt])
                .unwrap_err()
                .code(),
            "esp_counter_proof_set_duplicate_binding"
        );

        let backend = MockXfrmBackend::new();
        let authority = XfrmEspCounterResumeAuthority::new(backend.clone());
        let mut receipts = Vec::new();
        for offset in 0..=MAX_ESP_COUNTER_PROOF_SET_SIZE {
            let offset = u32::try_from(offset).unwrap();
            let spi = 0x7000_0000 + offset;
            install_initial(&backend, spi).await;
            receipts.push(
                authority
                    .apply_and_read_back(apply_request(
                        u128::from(offset) + 1,
                        u64::from(offset) + 1,
                        spi,
                        100,
                    ))
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(
            EspCounterResumeProofSet::new(receipts).unwrap_err().code(),
            "esp_counter_proof_set_too_large"
        );
    }

    #[tokio::test]
    async fn same_network_namespace_receipt_validates_from_another_thread() {
        let (_, _, receipt) = installed_authority(0x6677_8899, 100).await;
        let proofs = EspCounterResumeProofSet::single(receipt);
        let exact_binding = binding(7, 3, 0x6677_8899, 100);
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(proofs.validate_counter_proof(
                exact_binding,
                EspCounterProofRequirement::BeforeFirstPublication,
            ))
        })
        .join()
        .unwrap()
        .unwrap();
    }

    #[tokio::test]
    async fn esn_window_32_is_unambiguous_but_bad_bitmap_and_wrap_fail_closed() {
        let backend = MockXfrmBackend::new();
        install_initial(&backend, 0x7788_9900).await;
        let authority = XfrmEspCounterResumeAuthority::new(backend.clone());
        let mut window_32 = apply_request(1, 1, 0x7788_9900, 100);
        let state = window_32.parameters.replay_state.as_mut().unwrap();
        state.replay_window = 32;
        state.bitmap = vec![1];
        window_32.parameters.replay_window = 32;
        authority.apply_and_read_back(window_32).await.unwrap();

        let mut ambiguous = apply_request(2, 2, 0x7788_9900, 200);
        ambiguous
            .parameters
            .replay_state
            .as_mut()
            .unwrap()
            .bitmap
            .clear();
        let error = authority.apply_and_read_back(ambiguous).await.unwrap_err();
        assert_eq!(error.code(), "esp_counter_esn_bitmap_ambiguous");

        let mut wrapped = apply_request(3, 3, 0x7788_9900, 1);
        let state = wrapped.parameters.replay_state.as_mut().unwrap();
        state.outbound_sequence = u32::MAX;
        state.outbound_sequence_hi = u32::MAX;
        let error = authority.apply_and_read_back(wrapped).await.unwrap_err();
        assert_eq!(error.code(), "esp_counter_sequence_wrap");
        assert_eq!(
            EspCounterResumeBinding::new(3, 3, 0x7788_9900, 0)
                .unwrap_err()
                .code(),
            "esp_counter_requested_next_zero"
        );
    }

    #[tokio::test]
    async fn committed_counter_exhaustion_cannot_reauthorize_publication() {
        let (backend, authority, _) = installed_authority(0x8899_aabb, u64::MAX).await;
        let mut exhausted = parameters(0x8899_aabb, u64::MAX);
        let replay = exhausted.replay_state.as_mut().unwrap();
        replay.outbound_sequence = u32::MAX;
        replay.outbound_sequence_hi = u32::MAX;
        backend
            .rekey_sa(RekeySaRequest {
                parameters: exhausted,
            })
            .await
            .unwrap();
        let error = authority
            .validate_counter_proof(
                binding(7, 3, 0x8899_aabb, u64::MAX),
                EspCounterProofRequirement::CommittedRecovery,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), "esp_counter_sequence_exhausted");
    }

    #[test]
    fn errors_and_debug_are_redaction_safe() {
        let request = EspCounterResumeApplyRequest {
            binding: binding(0xfeed, 7, 0x1122_3344, 0x5566_7788),
            parameters: parameters(0x1122_3344, 0x5566_7788),
            direction: EspCounterResumeDirection::Outbound,
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains("11223344"));
        assert!(!debug.contains("55667788"));
        assert!(!debug.contains("192"));
        let error = EspCounterResumeError::ReadbackRejected {
            code: "esp_counter_exact_replay_state_mismatch",
        };
        assert_eq!(
            format!("{error:?}"),
            "EspCounterResumeError { code: \"esp_counter_exact_replay_state_mismatch\" }"
        );
    }
}
