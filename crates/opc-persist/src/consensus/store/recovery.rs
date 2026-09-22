//! Exact ordinary-commit recovery without mutation resubmission.

use hmac::{Hmac, Mac};

use super::*;
use crate::consensus::{ConfigConsensusCommand, ConfigConsensusIdentity, ConfigConsensusRequestId};
use crate::AuditKey;

const HANDLE_MAGIC: &[u8; 4] = b"OPCR";
const HANDLE_REVISION: u16 = 1;
const HANDLE_BODY_BYTES: usize = 168;
const HANDLE_BYTES: usize = HANDLE_BODY_BYTES + 32;
const HANDLE_DOMAIN: &[u8] = b"openpacketcore/config-commit-recovery/handle/v1\0";
const CALLER_DOMAIN: &[u8] = b"openpacketcore/config-commit-recovery/caller/v1\0";

/// One immutable ordinary commit with a recovery handle available before send.
///
/// Preparation consumes the encryption claim and finalizes audit metadata once.
/// This value cannot be cloned or reconstructed from a recovery handle. Retain
/// the handle before passing the operation to either prepared append method.
pub struct PreparedConfigCommitOperation {
    intent: ConfigMutationIntent,
    handle: ConfigCommitRecoveryHandle,
}

impl PreparedConfigCommitOperation {
    /// Exact original-operation handle, available before any proposal is sent.
    pub fn recovery_handle(&self) -> &ConfigCommitRecoveryHandle {
        &self.handle
    }
}

impl fmt::Debug for PreparedConfigCommitOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedConfigCommitOperation(<redacted>)")
    }
}

/// Opaque authenticated binding for read-only recovery of one ordinary commit.
///
/// The encoding is exactly 200 bytes. It binds the original request, prepared
/// payload, caller, authority, key epoch and capacity profile. Parsing does not
/// authenticate it; lookup also requires a separately authenticated caller.
/// Retain it securely and do not log its bytes or treat it as a caller identity.
#[derive(Clone, PartialEq, Eq)]
pub struct ConfigCommitRecoveryHandle {
    encoded: [u8; HANDLE_BYTES],
}

impl ConfigCommitRecoveryHandle {
    /// Exact size of the version-one opaque encoding.
    pub const ENCODED_BYTES: usize = HANDLE_BYTES;

    /// Copy one exact, structurally valid handle without granting authority.
    /// Authentication occurs when the store performs recovery.
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, PersistError> {
        let encoded: [u8; HANDLE_BYTES] = encoded.try_into().map_err(|_| invalid_handle())?;
        if &encoded[..4] != HANDLE_MAGIC || encoded[4..6] != HANDLE_REVISION.to_be_bytes() {
            return Err(invalid_handle());
        }
        Ok(Self { encoded })
    }

    /// Opaque bounded encoding suitable for retaining the original operation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    fn issue(
        key: &AuditKey,
        identity: ConfigConsensusIdentity,
        profile: opc_crypto::ConfigCapacityProfile,
        request_id: ConfigConsensusRequestId,
        payload_digest: [u8; 32],
        caller: &str,
    ) -> Result<Self, PersistError> {
        let mut encoded = [0; HANDLE_BYTES];
        encoded[..4].copy_from_slice(HANDLE_MAGIC);
        encoded[4..6].copy_from_slice(&HANDLE_REVISION.to_be_bytes());
        encoded[6..8].copy_from_slice(&profile.revision().to_be_bytes());
        encoded[8..40].copy_from_slice(identity.cluster_id().as_bytes());
        encoded[40..72].copy_from_slice(identity.configuration_id().as_bytes());
        encoded[72..80].copy_from_slice(&identity.configuration_epoch().get().to_be_bytes());
        encoded[80..88].copy_from_slice(&key.epoch().to_be_bytes());
        encoded[88..104].copy_from_slice(request_id.as_bytes());
        encoded[104..136].copy_from_slice(&payload_digest);
        encoded[136..168].copy_from_slice(&caller_mac(key, caller)?.finalize().into_bytes());
        let mut mac = handle_mac(key)?;
        mac.update(&encoded[..HANDLE_BODY_BYTES]);
        encoded[HANDLE_BODY_BYTES..].copy_from_slice(&mac.finalize().into_bytes());
        Ok(Self { encoded })
    }

    fn verify_scope(
        &self,
        key: &AuditKey,
        identity: ConfigConsensusIdentity,
        profile: opc_crypto::ConfigCapacityProfile,
    ) -> Result<(), PersistError> {
        let mut mac = handle_mac(key)?;
        mac.update(&self.encoded[..HANDLE_BODY_BYTES]);
        mac.verify_slice(&self.encoded[HANDLE_BODY_BYTES..])
            .map_err(|_| invalid_handle())?;
        if &self.encoded[..4] != HANDLE_MAGIC
            || self.encoded[4..6] != HANDLE_REVISION.to_be_bytes()
            || self.encoded[6..8] != profile.revision().to_be_bytes()
            || self.encoded[8..40] != *identity.cluster_id().as_bytes()
            || self.encoded[40..72] != *identity.configuration_id().as_bytes()
            || self.encoded[72..80] != identity.configuration_epoch().get().to_be_bytes()
            || self.encoded[80..88] != key.epoch().to_be_bytes()
        {
            return Err(invalid_handle());
        }
        Ok(())
    }

    fn verify_caller(&self, key: &AuditKey, caller: &str) -> Result<(), PersistError> {
        caller_mac(key, caller)?
            .verify_slice(&self.encoded[136..168])
            .map_err(|_| invalid_handle())
    }

    fn request_id(&self) -> ConfigConsensusRequestId {
        let mut bytes = [0; 16];
        bytes.copy_from_slice(&self.encoded[88..104]);
        ConfigConsensusRequestId::from_bytes(bytes)
    }

    fn matches_digest(&self, digest: &[u8; 32]) -> bool {
        self.encoded[104..136] == *digest
    }
}

impl fmt::Debug for ConfigCommitRecoveryHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConfigCommitRecoveryHandle(<redacted>)")
    }
}

/// Quorum-current retained evidence for the exact original ordinary commit.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ConfigCommitRecoveryOutcome {
    /// The retained same-payload operation committed successfully.
    Committed,
    /// The retained same-payload operation was applied and rejected.
    Rejected(PersistError),
    /// No matching retained result is proven. This includes an unsent operation,
    /// expiration and a reused request ID with a different payload. It never
    /// authorizes retrying under another identity or claims non-commit.
    Unresolved,
}

impl ConsensusConfigStore {
    /// Prepare one ordinary append or confirmed-resolution successor exactly once.
    ///
    /// `authenticated_principal` must come from trusted authentication and match
    /// the principal bound into the encrypted record. Preparation performs no
    /// proposal, SQL write or audit admission. Retain `recovery_handle()` before
    /// submission. Existing capacity limits and the original request ID apply.
    pub fn prepare_recoverable_commit(
        &self,
        original_request_id: ConfigConsensusRequestId,
        commit: AttestedConfigCommit,
        authenticated_principal: &str,
    ) -> Result<PreparedConfigCommitOperation, PersistError> {
        self.require_commit_capacity(&commit)?;
        if !crate::types::config_principal_matches_aad(
            &commit.record().principal,
            authenticated_principal,
        ) {
            return Err(invalid_handle());
        }
        let (record, audit, resolution) = commit.into_parts();
        let prepared =
            PreparedConfigCommit::prepare(record, audit, self.inner.backend.audit_key())?;
        let intent = match resolution {
            Some(resolution) => ConfigMutationIntent::ResolveConfirmedAndAppend {
                commit: Box::new(prepared),
                resolution,
            },
            None => ConfigMutationIntent::AppendCommit(Box::new(prepared)),
        };
        let command = ConfigConsensusCommand {
            schema_version: super::super::CONFIG_CONSENSUS_COMMAND_VERSION,
            identity: self.inner.identity,
            request_id: original_request_id,
            logical_time: maximum_encoded_config_timestamp().ok_or_else(consensus_unavailable)?,
            intent,
        };
        command.validate(self.inner.identity)?;
        preflight_config_command_replication_budget(
            command.identity,
            original_request_id,
            &command.intent,
        )
        .map_err(ForwardMutationRejection::into_persist_error)?;
        let handle = ConfigCommitRecoveryHandle::issue(
            self.inner.backend.audit_key(),
            self.inner.identity,
            self.capacity_profile(),
            original_request_id,
            command.payload_digest()?,
            authenticated_principal,
        )?;
        Ok(PreparedConfigCommitOperation {
            intent: command.intent,
            handle,
        })
    }

    /// Submit the exact prepared operation, forwarding to the leader if needed.
    /// Consume it once and recover an ambiguous result with its original handle.
    pub async fn append_prepared_commit(
        &self,
        operation: PreparedConfigCommitOperation,
    ) -> Result<(), PersistError> {
        operation.handle.verify_scope(
            self.inner.backend.audit_key(),
            self.inner.identity,
            self.capacity_profile(),
        )?;
        self.submit_request(operation.handle.request_id(), operation.intent)
            .await?
            .into_result()
    }

    /// Submit the exact prepared operation only on this node's current leader.
    /// An ambiguous result is recovered using the retained original handle.
    pub async fn append_prepared_commit_local(
        &self,
        operation: PreparedConfigCommitOperation,
    ) -> Result<(), PersistError> {
        operation.handle.verify_scope(
            self.inner.backend.audit_key(),
            self.inner.identity,
            self.capacity_profile(),
        )?;
        self.submit_request_on_local_leader(operation.handle.request_id(), operation.intent)
            .await?
            .into_result()
    }

    /// Read the original operation's retained result without proposing a write.
    ///
    /// The caller must be separately authenticated, never decoded from the
    /// handle. One operation deadline covers quorum, local apply and SQLite.
    /// The existing 4,096-applied-sequence retention window is unchanged;
    /// missing or mismatched evidence remains `Unresolved`.
    pub async fn lookup_commit_operation(
        &self,
        handle: &ConfigCommitRecoveryHandle,
        authenticated_principal: &str,
    ) -> Result<ConfigCommitRecoveryOutcome, PersistError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        handle.verify_scope(
            self.inner.backend.audit_key(),
            self.inner.identity,
            self.capacity_profile(),
        )?;
        handle.verify_caller(self.inner.backend.audit_key(), authenticated_principal)?;
        self.linearizable_barrier_until(deadline).await?;
        let outcome = super::super::sqlite::read_commit_outcome_until(
            &self.inner.backend,
            self.inner.identity,
            handle.request_id(),
            deadline,
        )
        .await
        .map_err(|_| consensus_unavailable())?;
        match outcome {
            Some((digest, response)) if handle.matches_digest(&digest) => match response.result {
                Ok(()) => Ok(ConfigCommitRecoveryOutcome::Committed),
                Err(failure) => Ok(ConfigCommitRecoveryOutcome::Rejected(
                    failure.into_persist_error(),
                )),
            },
            Some(_) | None => Ok(ConfigCommitRecoveryOutcome::Unresolved),
        }
    }
}

fn invalid_handle() -> PersistError {
    PersistError::constraint_violation("configuration recovery handle is invalid")
}

fn handle_mac(key: &AuditKey) -> Result<Hmac<Sha256>, PersistError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).map_err(|_| invalid_handle())?;
    mac.update(HANDLE_DOMAIN);
    Ok(mac)
}

fn caller_mac(key: &AuditKey, caller: &str) -> Result<Hmac<Sha256>, PersistError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).map_err(|_| invalid_handle())?;
    mac.update(CALLER_DOMAIN);
    mac.update(&(caller.len() as u64).to_be_bytes());
    mac.update(caller.as_bytes());
    Ok(mac)
}

#[cfg(test)]
mod config_capacity_recovery_tests;
