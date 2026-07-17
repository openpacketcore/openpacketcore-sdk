#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! Ciphertext-only durable adapters for [`opc_config_bus`].
//!
//! [`RaftManagedDatastore`] is a narrow adapter over the existing
//! [`opc_persist::ConsensusConfigStore`]. It never implements or wraps a
//! second consensus algorithm. Plaintext configuration and key-provider
//! access stay in [`opc_config_bus::EncryptingManagedDatastore`], outside this
//! crate and outside the Openraft command, log, snapshot, and transport
//! boundary. Its committed-history read port is follower-local: it exposes
//! only Openraft state-machine-applied rows and does not enter a leader read
//! barrier.

use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

use async_trait::async_trait;
use opc_config_bus::{
    CommitWrite as BusCommitWrite, CommittedRevisionSource, ConfigAuthorityOperation,
    ConfigAuthorityOutcome, ConfigAuthorityPort, ConfigLeaderHint, ConfigProjectionHead,
    ConfirmedCommitResolution as BusConfirmedCommitResolution, ManagedDatastore, SealedConfig,
    StoreError, StoredConfig as BusStoredConfig,
};
use opc_config_model::{
    IdempotencyKey, OpcConfig, RequestId, RequestSource, RollbackTarget as BusRollbackTarget,
    TrustedPrincipal,
};
use opc_persist::{
    AttestedConfigCommit, AuditOpType, AuditRecord, CommitRecord, CommitSource,
    ConfigLocalAuthorityOutcome, ConfigStore,
    ConfirmedCommitResolution as PersistConfirmedCommitResolution, ConsensusConfigStore,
    PersistError, PersistErrorKind, RollbackTarget, CONFIG_ROLLBACK_LABEL_MAX_BYTES,
};
use opc_types::{ConfigVersion, TxId};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

const REPLAY_LOOKUP_DIGEST_HEX_LEN: usize = 64;
const ROOT_AUDIT_PATH: &str = "/";

const _: () = assert!(
    opc_config_bus::MAX_CONFIG_HISTORY_PAGE_ENTRIES == opc_persist::CONFIG_HISTORY_PAGE_MAX_ENTRIES
);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedBusMetadata {
    /// Exact JSON bytes bound into `ConfigAad::principal`, encoded as a JSON
    /// string so persistence never has to reserialize a product model.
    principal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replay_lookup_digest: Option<IdempotencyKey>,
    recovery_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rollback_label: Option<String>,
}

struct DecodedPersistedBusMetadata {
    principal: TrustedPrincipal,
    aad_principal: String,
    replay_lookup_digest: Option<IdempotencyKey>,
    recovery_required: bool,
    rollback_label: Option<String>,
}

fn decode_persisted_bus_metadata(value: &str) -> Result<DecodedPersistedBusMetadata, StoreError> {
    let shape: serde_json::Value = serde_json::from_str(value)
        .map_err(|_| StoreError::internal("stored config principal metadata is invalid"))?;
    let is_metadata_wrapper = shape.as_object().is_some_and(|fields| {
        fields.contains_key("principal")
            || fields.contains_key("replay_lookup_digest")
            || fields.contains_key("recovery_required")
            || fields.contains_key("rollback_label")
    });
    let metadata = if is_metadata_wrapper {
        let metadata: PersistedBusMetadata = serde_json::from_str(value)
            .map_err(|_| StoreError::internal("stored config principal metadata is invalid"))?;
        let principal = serde_json::from_str(&metadata.principal)
            .map_err(|_| StoreError::internal("stored authenticated principal is invalid"))?;
        DecodedPersistedBusMetadata {
            principal,
            aad_principal: metadata.principal,
            replay_lookup_digest: metadata.replay_lookup_digest,
            recovery_required: metadata.recovery_required,
            rollback_label: metadata.rollback_label,
        }
    } else {
        let principal = serde_json::from_str(value)
            .map_err(|_| StoreError::internal("stored authenticated principal is invalid"))?;
        DecodedPersistedBusMetadata {
            principal,
            aad_principal: value.to_owned(),
            replay_lookup_digest: None,
            recovery_required: false,
            rollback_label: None,
        }
    };
    validate_replay_lookup_digest(metadata.replay_lookup_digest.as_ref())?;
    validate_rollback_label(metadata.rollback_label.as_deref())?;
    Ok(metadata)
}

fn validate_replay_lookup_digest(digest: Option<&IdempotencyKey>) -> Result<(), StoreError> {
    let Some(digest) = digest else {
        return Ok(());
    };
    let bytes = digest.as_str().as_bytes();
    if bytes.len() != REPLAY_LOOKUP_DIGEST_HEX_LEN
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(StoreError::internal(
            "sealed config replay lookup value is not a SHA-256 digest",
        ));
    }
    Ok(())
}

fn validate_rollback_label(label: Option<&str>) -> Result<(), StoreError> {
    let Some(label) = label else {
        return Ok(());
    };
    if label.is_empty()
        || label.len() > CONFIG_ROLLBACK_LABEL_MAX_BYTES
        || label.trim() != label
        || label.chars().any(char::is_control)
    {
        return Err(StoreError::internal(
            "rollback label is not canonically representable",
        ));
    }
    Ok(())
}

fn map_persist_error(error: PersistError) -> StoreError {
    match error.kind() {
        PersistErrorKind::RollbackNotFound => {
            StoreError::not_found("durable config target was not found")
        }
        PersistErrorKind::Unavailable
        | PersistErrorKind::DatabaseLocked
        | PersistErrorKind::Io(_)
        | PersistErrorKind::PathNotWritable(_)
        | PersistErrorKind::OutOfSpace { .. }
        | PersistErrorKind::PreflightFailed(_) => {
            StoreError::unavailable("durable config backend is unavailable")
        }
        PersistErrorKind::OutcomeUnknown => {
            StoreError::outcome_unknown("durable config acknowledgement was lost")
        }
        PersistErrorKind::CorruptBlob | PersistErrorKind::AuditChainBroken => {
            StoreError::crypto("durable config integrity validation failed")
        }
        PersistErrorKind::SchemaDigestMismatch { .. } => {
            StoreError::restore_schema_mismatch("durable config schema digest does not match")
        }
        PersistErrorKind::ConfigHistoryCompacted => StoreError::history_compacted(
            "requested committed config history is no longer retained",
        ),
        PersistErrorKind::WalRecoveryFailed
        | PersistErrorKind::InconsistentState(_)
        | PersistErrorKind::ForeignKeyViolation
        | PersistErrorKind::ConstraintViolation(_)
        | PersistErrorKind::RequestIdCollision
        | PersistErrorKind::Sqlite(_)
        | PersistErrorKind::SchemaVersionMismatch { .. } => {
            StoreError::internal("durable config invariant validation failed")
        }
    }
}

fn adapt_stored_config<C: OpcConfig>(
    stored: opc_persist::StoredConfig,
) -> Result<BusStoredConfig<SealedConfig<C>>, StoreError> {
    let metadata = decode_persisted_bus_metadata(&stored.record.principal)?;
    if metadata.rollback_label.is_some() && !stored.record.rollback_point {
        return Err(StoreError::internal(
            "durable rollback label metadata is inconsistent",
        ));
    }
    let source = match stored.record.source {
        CommitSource::Gnmi => RequestSource::Northbound,
        CommitSource::StartupRestore => RequestSource::StartupRecovery,
        _ => RequestSource::Internal,
    };
    let plaintext_digest: [u8; 32] = stored
        .record
        .plaintext_digest
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::internal("invalid plaintext digest length"))?;
    Ok(BusStoredConfig {
        tx_id: stored.record.tx_id,
        parent_tx_id: stored.record.parent_tx_id,
        version: stored.record.version,
        committed_at: stored.record.committed_at,
        principal: metadata.principal,
        source,
        schema_digest: stored.record.schema_digest,
        plaintext_digest: Some(plaintext_digest),
        config: SealedConfig::from_persisted_aad_principal(
            stored.record.schema_digest,
            metadata.aad_principal,
        )?,
        encrypted_blob: stored.record.encrypted_blob,
        idempotency_key: metadata.replay_lookup_digest,
        apply_plan: None,
        request_fingerprint: None,
        request_id: None,
        recovery_required: metadata.recovery_required,
        confirmed_deadline: stored.record.confirmed_deadline,
        rollback_label: metadata.rollback_label,
    })
}

fn root_audit_record(tx_id: TxId) -> Vec<AuditRecord> {
    vec![AuditRecord {
        tx_id,
        sequence: 0,
        yang_path: ROOT_AUDIT_PATH.to_owned(),
        op_type: AuditOpType::Replace,
        previous_value: None,
        new_value: None,
        redaction_applied: true,
        previous_hash: [0_u8; 32],
        entry_hmac: [0_u8; 32],
    }]
}

/// Generic encrypted-record adapter from an [`opc_persist::ConfigStore`] to
/// the config bus [`ManagedDatastore`] port.
///
/// This type implements only `ManagedDatastore<SealedConfig<C>>`. Callers
/// needing plaintext `ManagedDatastore<C>` must place
/// [`opc_config_bus::EncryptingManagedDatastore`] outside it.
pub struct PersistManagedDatastore<C, S: ?Sized> {
    inner: Arc<S>,
    marker: PhantomData<fn() -> C>,
}

impl<C, S: ?Sized> PersistManagedDatastore<C, S> {
    /// Adapt one persistence store. The store receives authenticated
    /// ciphertext records only.
    pub fn new(inner: Arc<S>) -> Self {
        Self {
            inner,
            marker: PhantomData,
        }
    }

    /// Return the wrapped persistence store.
    pub fn inner(&self) -> &Arc<S> {
        &self.inner
    }
}

impl<C, S: ?Sized> Clone for PersistManagedDatastore<C, S> {
    fn clone(&self) -> Self {
        Self::new(Arc::clone(&self.inner))
    }
}

impl<C, S: ?Sized> fmt::Debug for PersistManagedDatastore<C, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistManagedDatastore")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<C, S> ManagedDatastore<SealedConfig<C>> for PersistManagedDatastore<C, S>
where
    C: OpcConfig + Serialize + DeserializeOwned + Send + Sync + 'static,
    S: ConfigStore + ?Sized + 'static,
{
    async fn load_latest(&self) -> Result<Option<BusStoredConfig<SealedConfig<C>>>, StoreError> {
        self.inner
            .load_latest()
            .await
            .map_err(map_persist_error)?
            .map(adapt_stored_config)
            .transpose()
    }

    async fn load_committed_latest(
        &self,
    ) -> Result<Option<BusStoredConfig<SealedConfig<C>>>, StoreError> {
        self.inner
            .load_committed_latest()
            .await
            .map_err(map_persist_error)?
            .map(adapt_stored_config)
            .transpose()
    }

    async fn load_since(
        &self,
        version: ConfigVersion,
        limit: usize,
    ) -> Result<Vec<BusStoredConfig<SealedConfig<C>>>, StoreError> {
        self.inner
            .load_since(version, limit)
            .await
            .map_err(map_persist_error)?
            .into_iter()
            .map(adapt_stored_config)
            .collect()
    }

    async fn wait_for_committed_change(&self, version: ConfigVersion) -> Result<(), StoreError> {
        self.inner
            .wait_for_committed_change(version)
            .await
            .map_err(map_persist_error)
    }

    async fn load_rollback(
        &self,
        target: BusRollbackTarget,
    ) -> Result<BusStoredConfig<SealedConfig<C>>, StoreError> {
        let target = match target {
            BusRollbackTarget::Previous => RollbackTarget::Previous,
            BusRollbackTarget::Version(version) => RollbackTarget::ByVersion(version),
            BusRollbackTarget::TxId(tx_id) => RollbackTarget::ByTxId(tx_id),
            BusRollbackTarget::Label(label) => RollbackTarget::ByLabel(label),
        };
        adapt_stored_config(
            self.inner
                .load_rollback(target)
                .await
                .map_err(map_persist_error)?,
        )
    }

    async fn load_by_idempotency_key(
        &self,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Option<BusStoredConfig<SealedConfig<C>>>, StoreError> {
        validate_replay_lookup_digest(Some(idempotency_key))?;
        self.inner
            .load_by_replay_lookup_digest(idempotency_key.as_str())
            .await
            .map_err(map_persist_error)?
            .map(adapt_stored_config)
            .transpose()
    }

    async fn load_by_legacy_idempotency_key(
        &self,
        _idempotency_key: &IdempotencyKey,
    ) -> Result<Option<BusStoredConfig<SealedConfig<C>>>, StoreError> {
        Ok(None)
    }

    async fn load_by_request_id(
        &self,
        _request_id: RequestId,
    ) -> Result<Option<BusStoredConfig<SealedConfig<C>>>, StoreError> {
        // Current encrypted records are found through the domain-separated
        // digest index before this cleartext compatibility fallback.
        Ok(None)
    }

    async fn append_commit_write(
        &self,
        commit: BusCommitWrite<SealedConfig<C>>,
    ) -> Result<(), StoreError> {
        let (commit, resolution) = commit.into_parts();
        validate_replay_lookup_digest(commit.idempotency_key.as_ref())?;
        validate_rollback_label(commit.rollback_label.as_deref())?;
        if commit.apply_plan.is_some()
            || commit.request_fingerprint.is_some()
            || commit.request_id.is_some()
        {
            return Err(StoreError::internal(
                "sealed config adapter received plaintext replay metadata",
            ));
        }
        let aad_principal = serde_json::to_string(&commit.principal)
            .map_err(|_| StoreError::internal("authenticated principal serialization failed"))?;
        let principal = serde_json::to_string(&PersistedBusMetadata {
            principal: aad_principal,
            replay_lookup_digest: commit.idempotency_key,
            recovery_required: commit.recovery_required,
            rollback_label: commit.rollback_label.clone(),
        })
        .map_err(|_| StoreError::internal("sealed config metadata serialization failed"))?;
        let source = match commit.source {
            RequestSource::Northbound => CommitSource::Gnmi,
            RequestSource::StartupRecovery => CommitSource::StartupRestore,
            _ => CommitSource::LocalOperator,
        };
        let record = CommitRecord {
            tx_id: commit.tx_id,
            parent_tx_id: commit.parent_tx_id,
            version: commit.version,
            committed_at: commit.committed_at,
            principal,
            source,
            schema_digest: commit.schema_digest,
            plaintext_digest: commit
                .plaintext_digest
                .map(|digest| digest.to_vec())
                .unwrap_or_default(),
            encrypted_blob: commit.encrypted_blob,
            rollback_point: commit.rollback_label.is_some(),
            confirmed_deadline: commit.confirmed_deadline,
        };
        let claim = commit.config.claim_fresh_envelope()?;
        if !claim.matches(&record.encrypted_blob) {
            return Err(StoreError::crypto(
                "fresh config envelope bytes do not match durable record",
            ));
        }
        if !claim.matches_plaintext_digest(&record.plaintext_digest) {
            return Err(StoreError::crypto(
                "fresh config envelope digest does not match durable record",
            ));
        }
        let audit = root_audit_record(record.tx_id);
        let commit = match resolution {
            Some(BusConfirmedCommitResolution::Confirm { pending_tx_id }) => {
                AttestedConfigCommit::try_new_resolving(
                    record,
                    audit,
                    claim,
                    PersistConfirmedCommitResolution::Confirm { pending_tx_id },
                )
            }
            Some(BusConfirmedCommitResolution::Rollback { pending_tx_id }) => {
                AttestedConfigCommit::try_new_resolving(
                    record,
                    audit,
                    claim,
                    PersistConfirmedCommitResolution::Rollback { pending_tx_id },
                )
            }
            None => AttestedConfigCommit::try_new(record, audit, claim),
        }
        .map_err(map_persist_error)?;
        self.inner
            .append_attested_commit(commit)
            .await
            .map_err(map_persist_error)
    }

    async fn clear_recovery_required(&self, tx_id: TxId) -> Result<(), StoreError> {
        self.inner
            .clear_recovery_required(tx_id)
            .await
            .map_err(map_persist_error)
    }

    async fn mark_confirmed(&self, tx_id: TxId) -> Result<(), StoreError> {
        self.inner
            .mark_confirmed(tx_id)
            .await
            .map_err(map_persist_error)
    }
}

/// Production config-bus datastore backed exclusively by
/// [`ConsensusConfigStore`].
///
/// The newtype prevents accidentally presenting a process-local SQLite or mock
/// store as a Raft-backed datastore. It implements only
/// `ManagedDatastore<SealedConfig<C>>`, preserving the ciphertext boundary by
/// construction. Its explicit [`CommittedRevisionSource`] implementation lets
/// a read-only Shadow bus serve this node's local committed/applied history
/// without contacting the current writer.
pub struct RaftManagedDatastore<C> {
    adapter: PersistManagedDatastore<C, ConsensusConfigStore>,
}

/// Management authority port backed directly by the config Openraft store.
///
/// The adapter performs a local-only Openraft linearizability/apply check. It
/// never forwards the management request and never creates a parallel
/// leadership signal.
#[derive(Clone)]
pub struct ConsensusConfigAuthority {
    store: Arc<ConsensusConfigStore>,
}

impl ConsensusConfigAuthority {
    /// Binds the authority port to the same consensus store used by the config
    /// bus datastore adapter.
    pub fn new(store: Arc<ConsensusConfigStore>) -> Self {
        Self { store }
    }

    /// Returns the underlying canonical config consensus store.
    pub fn consensus_store(&self) -> &Arc<ConsensusConfigStore> {
        &self.store
    }
}

impl fmt::Debug for ConsensusConfigAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsensusConfigAuthority")
            .finish_non_exhaustive()
    }
}

fn map_config_authority_outcome(outcome: ConfigLocalAuthorityOutcome) -> ConfigAuthorityOutcome {
    match outcome {
        ConfigLocalAuthorityOutcome::LocalAuthority => ConfigAuthorityOutcome::LocalAuthority,
        ConfigLocalAuthorityOutcome::Retry { leader_hint } => {
            let leader_hint = leader_hint
                .and_then(|node_id| ConfigLeaderHint::new(node_id.get().to_string()).ok());
            ConfigAuthorityOutcome::Retry { leader_hint }
        }
        ConfigLocalAuthorityOutcome::Unavailable => ConfigAuthorityOutcome::Unavailable,
        _ => ConfigAuthorityOutcome::Unavailable,
    }
}

fn projection_can_attempt_authority(
    operation: ConfigAuthorityOperation,
    projection: ConfigProjectionHead,
) -> bool {
    match operation {
        ConfigAuthorityOperation::Write => true,
        ConfigAuthorityOperation::LinearizableRead => projection.tx_id().is_some(),
        _ => false,
    }
}

#[async_trait]
impl ConfigAuthorityPort for ConsensusConfigAuthority {
    async fn ensure_local_authority(
        &self,
        operation: ConfigAuthorityOperation,
        projection: ConfigProjectionHead,
    ) -> ConfigAuthorityOutcome {
        if !projection_can_attempt_authority(operation, projection) {
            return ConfigAuthorityOutcome::Unavailable;
        }
        map_config_authority_outcome(
            self.store
                .ensure_local_authority_at_config_head(projection.tx_id(), projection.version())
                .await,
        )
    }
}

impl<C> RaftManagedDatastore<C> {
    /// Wrap the already-open config consensus authority.
    pub fn new(store: Arc<ConsensusConfigStore>) -> Self {
        Self {
            adapter: PersistManagedDatastore::new(store),
        }
    }

    /// Return the sole underlying config consensus authority for lifecycle,
    /// RPC-handler, status, readiness, snapshot, and shutdown operations.
    pub fn consensus_store(&self) -> &Arc<ConsensusConfigStore> {
        self.adapter.inner()
    }

    /// Builds a management authority port over this adapter's exact consensus
    /// store. The returned port can be shared by gNMI and NETCONF servers.
    pub fn config_authority(&self) -> ConsensusConfigAuthority {
        ConsensusConfigAuthority::new(Arc::clone(self.adapter.inner()))
    }
}

impl<C> Clone for RaftManagedDatastore<C> {
    fn clone(&self) -> Self {
        Self {
            adapter: self.adapter.clone(),
        }
    }
}

impl<C> fmt::Debug for RaftManagedDatastore<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RaftManagedDatastore")
            .field("consensus_store", self.consensus_store())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<C> ManagedDatastore<SealedConfig<C>> for RaftManagedDatastore<C>
where
    C: OpcConfig + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    async fn load_latest(&self) -> Result<Option<BusStoredConfig<SealedConfig<C>>>, StoreError> {
        self.adapter.load_latest().await
    }

    async fn load_committed_latest(
        &self,
    ) -> Result<Option<BusStoredConfig<SealedConfig<C>>>, StoreError> {
        self.adapter.load_committed_latest().await
    }

    async fn load_since(
        &self,
        version: ConfigVersion,
        limit: usize,
    ) -> Result<Vec<BusStoredConfig<SealedConfig<C>>>, StoreError> {
        self.adapter.load_since(version, limit).await
    }

    async fn wait_for_committed_change(&self, version: ConfigVersion) -> Result<(), StoreError> {
        self.adapter.wait_for_committed_change(version).await
    }

    async fn load_rollback(
        &self,
        target: BusRollbackTarget,
    ) -> Result<BusStoredConfig<SealedConfig<C>>, StoreError> {
        self.adapter.load_rollback(target).await
    }

    async fn load_by_idempotency_key(
        &self,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Option<BusStoredConfig<SealedConfig<C>>>, StoreError> {
        self.adapter.load_by_idempotency_key(idempotency_key).await
    }

    async fn load_by_legacy_idempotency_key(
        &self,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Option<BusStoredConfig<SealedConfig<C>>>, StoreError> {
        self.adapter
            .load_by_legacy_idempotency_key(idempotency_key)
            .await
    }

    async fn load_by_request_id(
        &self,
        request_id: RequestId,
    ) -> Result<Option<BusStoredConfig<SealedConfig<C>>>, StoreError> {
        self.adapter.load_by_request_id(request_id).await
    }

    async fn append_commit_write(
        &self,
        commit: BusCommitWrite<SealedConfig<C>>,
    ) -> Result<(), StoreError> {
        self.adapter.append_commit_write(commit).await
    }

    async fn clear_recovery_required(&self, tx_id: TxId) -> Result<(), StoreError> {
        self.adapter.clear_recovery_required(tx_id).await
    }

    async fn mark_confirmed(&self, tx_id: TxId) -> Result<(), StoreError> {
        self.adapter.mark_confirmed(tx_id).await
    }
}

impl<C> CommittedRevisionSource<SealedConfig<C>> for RaftManagedDatastore<C> where
    C: OpcConfig + Serialize + DeserializeOwned + Send + Sync + 'static
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_config_model::WorkloadIdentity;
    use opc_persist::ConfigConsensusNodeId;
    use opc_types::TenantId;

    fn encoded_principal() -> String {
        serde_json::to_string(&TrustedPrincipal::new(
            WorkloadIdentity::Internal("config-writer".to_owned()),
            TenantId::new("tenant-a").expect("tenant"),
        ))
        .expect("principal JSON")
    }

    #[test]
    fn malformed_metadata_wrapper_shapes_fail_closed() {
        let principal = encoded_principal();
        let nested_principal: serde_json::Value =
            serde_json::from_str(&principal).expect("principal value");
        let malformed = [
            serde_json::json!({ "principal": encoded_principal() }),
            serde_json::json!({
                "principal": nested_principal,
                "recovery_required": false
            }),
            serde_json::json!({
                "principal": "not-json",
                "recovery_required": false
            }),
            serde_json::json!({
                "principal": principal,
                "recovery_required": "false"
            }),
            serde_json::json!({
                "principal": encoded_principal(),
                "idempotency_lookup_digest": "ABC123",
                "recovery_required": false
            }),
            serde_json::json!({
                "principal": encoded_principal(),
                "recovery_required": false,
                "rollback_label": " leading-space"
            }),
        ];

        for value in malformed {
            let encoded = serde_json::to_string(&value).expect("metadata JSON");
            assert!(decode_persisted_bus_metadata(&encoded).is_err());
        }
    }

    #[test]
    fn wrapper_fields_cannot_hide_inside_a_legacy_principal_shape() {
        let mut principal: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str::<serde_json::Value>(&encoded_principal())
                .expect("principal JSON")
                .as_object()
                .expect("principal object")
                .clone();
        principal.insert(
            "replay_lookup_digest".to_owned(),
            serde_json::Value::String("a".repeat(REPLAY_LOOKUP_DIGEST_HEX_LEN)),
        );
        principal.insert(
            "recovery_required".to_owned(),
            serde_json::Value::Bool(true),
        );
        let encoded = serde_json::Value::Object(principal).to_string();
        assert!(decode_persisted_bus_metadata(&encoded).is_err());
    }

    #[test]
    fn duplicate_metadata_fields_fail_closed() {
        let principal = encoded_principal();
        let duplicate = [
            format!(
                "{{\"principal\":{principal:?},\"principal\":{principal:?},\"recovery_required\":false}}"
            ),
            format!(
                "{{\"principal\":{principal:?},\"replay_lookup_digest\":\"{}\",\"replay_lookup_digest\":\"{}\",\"recovery_required\":false}}",
                "a".repeat(REPLAY_LOOKUP_DIGEST_HEX_LEN),
                "b".repeat(REPLAY_LOOKUP_DIGEST_HEX_LEN)
            ),
            format!(
                "{{\"principal\":{principal:?},\"recovery_required\":true,\"recovery_required\":false}}"
            ),
            format!(
                "{{\"principal\":{principal:?},\"recovery_required\":false,\"rollback_label\":\"one\",\"rollback_label\":\"two\"}}"
            ),
        ];
        for encoded in duplicate {
            assert!(decode_persisted_bus_metadata(&encoded).is_err());
        }
    }

    #[test]
    fn authority_outcome_uses_only_the_stable_numeric_node_id() {
        let node_id = ConfigConsensusNodeId::new(42).expect("node ID");
        let outcome = map_config_authority_outcome(ConfigLocalAuthorityOutcome::Retry {
            leader_hint: Some(node_id),
        });

        let ConfigAuthorityOutcome::Retry {
            leader_hint: Some(hint),
        } = outcome
        else {
            panic!("retry with hint");
        };
        assert_eq!(hint.as_str(), "42");
        assert!(!hint.as_str().contains("ConsensusNodeId"));
    }

    #[test]
    fn authority_outcome_fails_closed_without_a_known_leader() {
        assert_eq!(
            map_config_authority_outcome(ConfigLocalAuthorityOutcome::Retry { leader_hint: None }),
            ConfigAuthorityOutcome::Retry { leader_hint: None }
        );
        assert_eq!(
            map_config_authority_outcome(ConfigLocalAuthorityOutcome::Unavailable),
            ConfigAuthorityOutcome::Unavailable
        );
    }

    #[test]
    fn empty_projection_allows_only_the_genesis_write() {
        let empty = ConfigProjectionHead::new(None, opc_types::ConfigVersion::INITIAL);
        assert!(projection_can_attempt_authority(
            ConfigAuthorityOperation::Write,
            empty
        ));
        assert!(!projection_can_attempt_authority(
            ConfigAuthorityOperation::LinearizableRead,
            empty
        ));
        let durable = ConfigProjectionHead::new(
            Some(opc_types::TxId::new()),
            opc_types::ConfigVersion::new(1),
        );
        assert!(projection_can_attempt_authority(
            ConfigAuthorityOperation::LinearizableRead,
            durable
        ));
    }

    #[test]
    fn compacted_persistence_history_remains_typed_at_the_bus_boundary() {
        let mapped = map_persist_error(PersistError::config_history_compacted());
        assert_eq!(
            opc_config_bus::StoreErrorCode::HistoryCompacted,
            mapped.code
        );
    }
}
