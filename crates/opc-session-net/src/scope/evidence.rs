//! Configured independent authority readers. Wire references are lookup hints only.
use super::{
    proof::TerminationObservation,
    wire::{AuthorityReference, ScopeBinding},
};
use opc_session_store::scope_authority::{
    ScopeAuthorityStamp, ScopeClosureEvidence, ScopeExecution,
};

/// A bounded refusal from a configured consistent authority/evidence reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ScopeEvidenceError {
    /// The independent record is missing, changed, or does not match the boot.
    #[error("scope evidence mismatch")]
    Mismatch,
    /// The configured source is temporarily unavailable; keep exact retry material.
    #[error("scope evidence unavailable")]
    Unavailable,
    /// A field exceeds its bound or is inconsistent.
    #[error("invalid scope evidence")]
    Invalid,
}

/// Public issuance facts from a trusted consistent reader, never a capability.
#[derive(Clone, PartialEq, Eq)]
pub struct BootAuthorityRecord {
    pub(super) scope: ScopeBinding,
    pub(super) execution: ScopeExecution,
    pub(super) public_key: [u8; 33],
    pub(super) reference: AuthorityReference,
}
impl BootAuthorityRecord {
    /// Decode one configured issuer record. The installed source authenticates it;
    /// construction and client-supplied copies do not establish issuance.
    pub fn new(
        scope: ScopeBinding,
        execution: ScopeExecution,
        public_key: [u8; 33],
        record_uid: Vec<u8>,
        revision: Vec<u8>,
    ) -> Result<Self, ScopeEvidenceError> {
        super::proof::public_key(&public_key).map_err(|_| ScopeEvidenceError::Invalid)?;
        if execution.boot_key() != &super::wire::hash(&public_key) {
            return Err(ScopeEvidenceError::Invalid);
        }
        let reference = AuthorityReference::new(record_uid, revision)
            .map_err(|_| ScopeEvidenceError::Invalid)?;
        Ok(Self {
            scope,
            execution,
            public_key,
            reference,
        })
    }
    /// Issued process binding; independent verification precedes use.
    pub const fn execution(&self) -> &ScopeExecution {
        &self.execution
    }
}

/// Trusted host-installed namespaced issuer reader. Its implementation uses fixed
/// enrollment, authenticated consistent reads and its own credentials. No method
/// accepts a peer-selected URL. Keep records for every unresolved possible boot.
#[async_trait::async_trait]
pub trait ScopeBootAuthority: Send + Sync {
    /// The independently current issuance, including opaque record UID/revision.
    async fn read_current(
        &self,
        scope: &ScopeBinding,
    ) -> Result<BootAuthorityRecord, ScopeEvidenceError>;
    /// Retained issuance facts for proof by an old/unadmitted boot. These facts
    /// alone never admit it or supersede the current committed execution.
    async fn read_known(
        &self,
        scope: &ScopeBinding,
        public_key_digest: [u8; 32],
    ) -> Result<BootAuthorityRecord, ScopeEvidenceError>;
}

/// Exact trusted final-container observation retained by the issuer.
#[derive(Clone)]
pub struct FinalTerminationRecord {
    pub(super) predecessor: ScopeAuthorityStamp,
    pub(super) observation: TerminationObservation,
}
impl FinalTerminationRecord {
    /// Decode the trusted immutable capture. Strings remain exact API bytes;
    /// timestamps never determine ownership or closure by elapsed time. The
    /// complete API message is committed by its SHA-256 hash, without truncation
    /// or a message-length bound, including runtime prefixes and UTF-8 replacement.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        predecessor: ScopeAuthorityStamp,
        namespace: String,
        pod_name: String,
        pod_uid: [u8; 16],
        container_name: String,
        container_id: String,
        exit_code: i32,
        signal: i32,
        reason: String,
        message: String,
        started_at: String,
        finished_at: String,
        record_uid: Vec<u8>,
        revision: Vec<u8>,
    ) -> Result<Self, ScopeEvidenceError> {
        let record = AuthorityReference::new(record_uid, revision)
            .map_err(|_| ScopeEvidenceError::Invalid)?;
        Ok(Self {
            predecessor,
            observation: TerminationObservation {
                namespace,
                pod_name,
                pod_uid,
                container_name,
                container_id,
                exit_code,
                signal,
                reason,
                message,
                started_at,
                finished_at,
                record,
            },
        })
    }
    /// Canonical evidence commitment for the independently captured predecessor.
    pub fn digest(&self) -> Result<[u8; 32], ScopeEvidenceError> {
        if self.observation.pod_uid != *self.predecessor.execution().workload() {
            return Err(ScopeEvidenceError::Mismatch);
        }
        let predecessor = self
            .predecessor
            .encode_canonical()
            .map_err(|_| ScopeEvidenceError::Invalid)?;
        Ok(super::wire::hash(
            &self
                .observation
                .input(&predecessor)
                .map_err(|_| ScopeEvidenceError::Invalid)?,
        ))
    }
}

/// Local fence facts obtained from the installed trusted evidence service.
/// These are public record facts, not a verified closure token.
#[derive(Clone)]
pub struct LocalClosureRecord {
    pub(super) predecessor: ScopeAuthorityStamp,
    pub(super) fence_nonce: [u8; 32],
}
impl LocalClosureRecord {
    /// Exact predecessor recorded by the SDK's drained gate.
    pub const fn predecessor(&self) -> &ScopeAuthorityStamp {
        &self.predecessor
    }
    /// Public nonce to retain alongside the exact predecessor in the trusted
    /// evidence record. Possessing these facts is not a verified closure token.
    pub const fn fence_nonce(&self) -> &[u8; 32] {
        &self.fence_nonce
    }
    /// Read exact facts from the configured trusted record, never from a caller's
    /// request body. The server recomputes their commitment before dispatch.
    pub fn new(
        predecessor: ScopeAuthorityStamp,
        fence_nonce: [u8; 32],
    ) -> Result<Self, ScopeEvidenceError> {
        if fence_nonce == [0; 32] {
            return Err(ScopeEvidenceError::Invalid);
        }
        Ok(Self {
            predecessor,
            fence_nonce,
        })
    }
    /// Canonical commitment to the exact current stamp and both closed paths.
    pub fn digest(&self) -> Result<[u8; 32], ScopeEvidenceError> {
        let predecessor = self
            .predecessor
            .encode_canonical()
            .map_err(|_| ScopeEvidenceError::Invalid)?;
        Ok(super::wire::hash(
            &super::proof::local_quiescence_input(&predecessor, &self.fence_nonce)
                .map_err(|_| ScopeEvidenceError::Invalid)?,
        ))
    }
}

/// Opaque evidence produced only after this SDK process has irreversibly closed
/// and drained its submission gates. It cannot be deserialized or publicly made.
pub struct LocalClosurePublication {
    pub(super) record: LocalClosureRecord,
}
impl LocalClosurePublication {
    /// Public facts to retain in the trusted evidence service.
    pub const fn record(&self) -> &LocalClosureRecord {
        &self.record
    }
}
/// Trusted local publication path installed with the scope endpoint. Its reader
/// counterpart must make the same immutable record independently available to
/// the quorum server before Close is submitted. A failed publication is retried
/// with the same fence before constructing the request; submission paths stay closed.
#[async_trait::async_trait]
pub trait ScopeLocalClosurePublisher: Send + Sync {
    /// Persist the opaque SDK-produced evidence; do not replace another digest.
    async fn publish(&self, evidence: &LocalClosurePublication) -> Result<(), ScopeEvidenceError>;
}
/// Trusted configured reader for positive predecessor evidence. Missing Pods,
/// timeouts and a decoded public Boolean must never produce either record.
#[async_trait::async_trait]
pub trait ScopeClosureSource: Send + Sync {
    /// Read an immutable observation binding the exact process/key/container.
    async fn read_final(
        &self,
        predecessor: &ScopeAuthorityStamp,
        digest: [u8; 32],
    ) -> Result<FinalTerminationRecord, ScopeEvidenceError>;
    /// Independently read the evidence published by the SDK's local gate adapter.
    async fn read_local(
        &self,
        predecessor: &ScopeAuthorityStamp,
        digest: [u8; 32],
    ) -> Result<LocalClosureRecord, ScopeEvidenceError>;
}

pub(super) async fn verify_current_ticket(
    source: &dyn ScopeBootAuthority,
    scope: &ScopeBinding,
    execution: &ScopeExecution,
    public_key: &[u8; 33],
    reference: &AuthorityReference,
) -> Result<BootAuthorityRecord, ScopeEvidenceError> {
    let current = source.read_current(scope).await?;
    if &current.scope != scope
        || &current.execution != execution
        || &current.public_key != public_key
        || &current.reference != reference
        || &super::wire::hash(public_key) != execution.boot_key()
    {
        return Err(ScopeEvidenceError::Mismatch);
    }
    Ok(current)
}
pub(super) async fn verify_closure(
    source: &dyn ScopeClosureSource,
    predecessor: &ScopeAuthorityStamp,
    evidence: &ScopeClosureEvidence,
) -> Result<(), ScopeEvidenceError> {
    use opc_session_store::scope_authority::ScopeClosureKind;
    let exact = match evidence.kind() {
        ScopeClosureKind::FinalTermination => {
            let record = source.read_final(predecessor, *evidence.digest()).await?;
            record.predecessor == *predecessor && record.digest()? == *evidence.digest()
        }
        ScopeClosureKind::LocalQuiescence => {
            let record = source.read_local(predecessor, *evidence.digest()).await?;
            record.predecessor == *predecessor && record.digest()? == *evidence.digest()
        }
        ScopeClosureKind::CommittedClose => false,
    };
    exact.then_some(()).ok_or(ScopeEvidenceError::Mismatch)
}

macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => { $(impl std::fmt::Debug for $ty {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(concat!(stringify!($ty), "([redacted])")) }
    })+ };
}
redacted_debug!(
    BootAuthorityRecord,
    FinalTerminationRecord,
    LocalClosureRecord,
    LocalClosurePublication
);
