//! Volatile process keys with verified OS protection before generation.

use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
use rand::{rngs::SysRng, TryRng};
use std::fmt;

#[cfg(all(test, target_os = "linux"))]
#[path = "boot_tests.rs"]
mod tests;

/// Boot identity initialization or protection failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BootError {
    /// The platform cannot protect the process against same-UID tracing/dumps.
    #[error("unsupported boot-key protection prerequisite")]
    UnsupportedProtection,
    /// The operating-system random source failed.
    #[error("boot entropy unavailable")]
    EntropyUnavailable,
    /// A fork or protection change invalidated this key's signing authority.
    #[error("boot process protection changed")]
    ProtectionChanged,
}

/// Process-owned ephemeral boot key; never serializable or an arbitrary signer.
///
/// ```compile_fail
/// use opc_session_net::scope::BootIdentity;
/// let key = BootIdentity::generate().unwrap();
/// let private = serde_json::to_vec(&key).unwrap();
/// ```
///
/// ```compile_fail
/// use opc_session_net::scope::BootIdentity;
/// let key = BootIdentity::generate().unwrap();
/// key.sign(b"arbitrary signature oracle");
/// ```
pub struct BootIdentity {
    key: SigningKey,
    process: u32,
    nonce: [u8; 16],
    public_key: [u8; 33],
}

impl BootIdentity {
    /// Protect the process, then generate a fresh nonzero nonce and P-256 key.
    /// On Linux this intentionally leaves the entire process non-dumpable.
    pub fn generate() -> Result<Self, BootError> {
        protect_process()?;
        let nonce = random_nonzero()?;
        let key = SigningKey::try_generate_from_rng(&mut SysRng)
            .map_err(|_| BootError::EntropyUnavailable)?;
        let public_key = key
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .try_into()
            .map_err(|_| BootError::EntropyUnavailable)?;
        let identity = Self {
            key,
            process: std::process::id(),
            nonce,
            public_key,
        };
        identity.check_protection()?;
        Ok(identity)
    }
    /// Public nonce identifying this process boot, stable across reconnects.
    pub const fn process_nonce(&self) -> &[u8; 16] {
        &self.nonce
    }
    /// Compressed public P-256 point; no private-key export exists.
    pub const fn public_key(&self) -> &[u8; 33] {
        &self.public_key
    }
    /// SHA-256 commitment to the compressed public key.
    pub fn key_digest(&self) -> [u8; 32] {
        super::wire::hash(&self.public_key)
    }

    pub(super) fn startup_proof<S>(
        &self,
        connection: &opc_tls::ScopeTlsConnection<S>,
        interval: opc_tls::AuthenticationTimeInterval,
        request: &super::proof::StartupRequest,
        mode: super::proof::StartupMode,
        credential: Vec<u8>,
        candidate: Option<&super::lifecycle::CandidateGuard>,
    ) -> Result<super::proof::StartupProof, super::startup::StartupError> {
        use super::{
            proof::{StartupClaims, StartupMode, StartupProof},
            startup::StartupError,
            wire::hash,
        };
        use p256::ecdsa::{signature::Signer, Signature};
        let mut credential = zeroize::Zeroizing::new(credential);
        self.check_protection()
            .map_err(|_| StartupError::GateClosed)?;
        if (mode == StartupMode::Candidate) != candidate.is_some()
            || connection.domain().scope_bytes() != request.scope.encode()
        {
            return Err(StartupError::GateClosed);
        }
        let binding = *connection
            .channel_binding(mode.purpose(), interval)
            .map_err(|_| StartupError::AuthTimeUnavailable)?
            .as_bytes();
        let claims = StartupClaims {
            mode,
            scope: request.scope.clone(),
            workload: request.workload,
            process: self.nonce,
            public_key: self.public_key,
            credential_digest: hash(&credential),
            observation: request.observation,
            challenge: request.challenge,
            binding,
        };
        let input = claims.encode().map_err(|_| StartupError::Invalid)?;
        let signature: Signature = self
            .key
            .try_sign(&input)
            .map_err(|_| StartupError::GateClosed)?;
        self.check_protection()
            .map_err(|_| StartupError::GateClosed)?;
        StartupProof::new(
            std::mem::take(&mut *credential),
            claims,
            signature.normalize_s().to_bytes().into(),
        )
        .map_err(|_| StartupError::Invalid)
    }

    pub(super) fn check_protection(&self) -> Result<(), BootError> {
        if self.process != std::process::id() || !is_protected() {
            return Err(BootError::ProtectionChanged);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn scope_proof<S>(
        &self,
        connection: &opc_tls::ScopeTlsConnection<S>,
        interval: opc_tls::AuthenticationTimeInterval,
        scope: &opc_session_store::scope_authority::ScopeId,
        execution: &opc_session_store::scope_authority::ScopeExecution,
        call: &super::wire::Header,
        nonce: [u8; 32],
        canonical: &[u8],
        authority: Option<super::wire::AuthorityReference>,
        challenge: [u8; 32],
        close: Option<&super::evidence::LocalClosureRecord>,
    ) -> Result<super::proof::PossessionProof, super::rpc::ScopeRpcError> {
        use super::{
            proof::{PossessionClaims, PossessionProof},
            rpc::ScopeRpcError,
            wire::*,
        };
        use opc_session_store::scope_authority::{
            ScopeAuthorityOperation, ScopeAuthorityRequest, ScopeClosureKind,
        };
        use p256::ecdsa::{signature::Signer, Signature};
        self.check_protection()
            .map_err(|_| ScopeRpcError::Unauthorized)?;
        let binding = ScopeBinding::from_scope(scope).map_err(|_| ScopeRpcError::Invalid)?;
        if execution.process() != &self.nonce
            || execution.boot_key() != &self.key_digest()
            || execution.identity().as_str() != connection.local_identity().as_str()
            || connection.domain().scope_bytes() != binding.encode()
            || call.scope != binding.commitment()
            || call.installation != *binding.installation()
        {
            return Err(ScopeRpcError::Unauthorized);
        }
        match call.method {
            Method::AdmitInitial | Method::SucceedClosed | Method::Close => {
                let request = ScopeAuthorityRequest::decode_canonical(canonical)
                    .map_err(|_| ScopeRpcError::Invalid)?;
                if request.scope() != scope
                    || request.request_id() != &call.request_id
                    || request.digest().map_err(|_| ScopeRpcError::Invalid)? != call.digest
                    || request.operation().execution() != execution
                {
                    return Err(ScopeRpcError::Invalid);
                }
                let method = match request.operation() {
                    ScopeAuthorityOperation::AdmitInitial { .. } => Method::AdmitInitial,
                    ScopeAuthorityOperation::SucceedClosed { .. } => Method::SucceedClosed,
                    ScopeAuthorityOperation::Close { current, evidence } => {
                        let local = close.ok_or(ScopeRpcError::Closed)?;
                        if local.predecessor != *current
                            || evidence.kind() != ScopeClosureKind::LocalQuiescence
                            || local.digest().map_err(|_| ScopeRpcError::Invalid)?
                                != *evidence.digest()
                        {
                            return Err(ScopeRpcError::Closed);
                        }
                        Method::Close
                    }
                };
                if method != call.method {
                    return Err(ScopeRpcError::Invalid);
                }
            }
            Method::Current | Method::Outcome => {
                let encoded = scope
                    .encode_canonical()
                    .map_err(|_| ScopeRpcError::Invalid)?;
                let expected = encoded.len()
                    + if call.method == Method::Outcome {
                        48
                    } else {
                        0
                    };
                if canonical.len() != expected
                    || !canonical.starts_with(&encoded)
                    || transport_request_digest(call.method, &call.request_id, canonical)
                        .map_err(|_| ScopeRpcError::Invalid)?
                        != call.digest
                {
                    return Err(ScopeRpcError::Invalid);
                }
            }
            Method::ApplyBatch
            | Method::BatchCancel
            | Method::BatchReopen
            | Method::BatchLookup => {
                let native = super::rpc_server::NativeCall::decode(call, canonical, scope)?;
                if native.execution().is_some_and(|named| named != execution) {
                    return Err(ScopeRpcError::Unauthorized);
                }
            }
            _ => return Err(ScopeRpcError::Invalid),
        }
        let claims = PossessionClaims {
            call: call.clone(),
            caller_nonce: nonce,
            execution: execution
                .transport_digest()
                .map_err(|_| ScopeRpcError::Invalid)?,
            public_key: self.public_key,
            authority,
            challenge,
            binding: *connection
                .channel_binding(opc_tls::ChannelBindingPurpose::ScopeRequest, interval)
                .map_err(|_| ScopeRpcError::AuthTimeUnavailable)?
                .as_bytes(),
        };
        let input = claims.encode().map_err(|_| ScopeRpcError::Invalid)?;
        let signature: Signature = self
            .key
            .try_sign(&input)
            .map_err(|_| ScopeRpcError::Unauthorized)?;
        self.check_protection()
            .map_err(|_| ScopeRpcError::Unauthorized)?;
        Ok(PossessionProof {
            claims,
            signature: signature.normalize_s().to_bytes().into(),
        })
    }
}

// SigningKey implements ZeroizeOnDrop; its secret scalar is not copied or exported.
// Nonces and compressed public points are public protocol data.
pub(super) fn random_nonzero<const N: usize>() -> Result<[u8; N], BootError> {
    for _ in 0..8 {
        let mut bytes = [0; N];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| BootError::EntropyUnavailable)?;
        if bytes.iter().any(|&byte| byte != 0) {
            return Ok(bytes);
        }
    }
    Err(BootError::EntropyUnavailable)
}

#[cfg(target_os = "linux")]
fn protect_process() -> Result<(), BootError> {
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|_| BootError::UnsupportedProtection)?;
    if !is_protected() {
        return Err(BootError::UnsupportedProtection);
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn is_protected() -> bool {
    rustix::process::dumpable_behavior() == Ok(rustix::process::DumpableBehavior::NotDumpable)
}
#[cfg(not(target_os = "linux"))]
fn protect_process() -> Result<(), BootError> {
    Err(BootError::UnsupportedProtection)
}
#[cfg(not(target_os = "linux"))]
fn is_protected() -> bool {
    false
}

impl fmt::Debug for BootIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BootIdentity([redacted])")
    }
}
