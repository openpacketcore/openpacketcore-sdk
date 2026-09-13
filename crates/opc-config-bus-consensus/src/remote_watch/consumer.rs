//! Durable non-voting consumption of this module's authenticated transport.

use std::fmt;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use opc_config_bus::PublishedSnapshot;
use opc_config_model::OpcConfig;
use opc_persist::{ConsumerCheckpointError, ConsumerCheckpointStore};
use opc_types::{ConfigVersion, SchemaDigest, TxId};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::{ConfigWatchError, RemoteConfigRevisionStream, RemoteConfigWatch};

/// Closed consumer failures; no configuration or identity enters formatting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigConsumerError {
    /// Transport authentication or the exact remote contract rejected recovery.
    #[error("consumer remote recovery failed: {0}")]
    Remote(ConfigWatchError),
    /// Local checkpoint admission, readback or atomic replacement failed.
    #[error("consumer checkpoint failed: {0}")]
    Checkpoint(ConsumerCheckpointError),
    /// Consumer and transport do not share the exact configured binding.
    #[error("consumer scope mismatch")]
    ScopeMismatch,
    /// An authenticated delivery conflicted with the persisted accepted floor.
    #[error("consumer revision conflicts with accepted state")]
    RevisionConflict,
    /// Only the next revision may enter an existing ordered tail.
    #[error("consumer ordered tail contains a gap or reorder")]
    InvalidSequence,
    /// A bounded payload, encoding or operation deadline was exceeded.
    #[error("consumer resource bound exceeded")]
    Limit,
    /// A stored payload has an unknown format or violates complete-state invariants.
    #[error("consumer checkpoint state is invalid")]
    InvalidState,
    /// Current product effects must be read back before another application.
    #[error("consumer requires product readback")]
    ReadbackRequired,
    /// A fresh authenticated snapshot and tail must be recovered explicitly.
    #[error("consumer requires remote snapshot recovery")]
    RemoteRecoveryRequired,
    /// Product effects remain conflicting or indeterminate after readback.
    #[error("consumer runtime effects remain unresolved")]
    RuntimeUnresolved,
}

impl From<ConsumerCheckpointError> for ConfigConsumerError {
    fn from(value: ConsumerCheckpointError) -> Self {
        Self::Checkpoint(value)
    }
}

/// One complete original committed revision, exposed only to product apply and
/// readback. This SDK never assigns its transaction or configuration version.
pub struct ConsumerRevision<C: OpcConfig> {
    transaction: TxId,
    version: ConfigVersion,
    config: C,
}

impl<C: OpcConfig> ConsumerRevision<C> {
    /// Original committed transaction identity, not a local mutation receipt.
    pub fn transaction(&self) -> TxId {
        self.transaction
    }
    /// Original committed version, not the local checkpoint CAS generation.
    pub fn version(&self) -> ConfigVersion {
        self.version
    }
    /// Complete product configuration, without a content-bearing formatter.
    pub fn config(&self) -> &C {
        &self.config
    }
}

impl<C: OpcConfig> fmt::Debug for ConsumerRevision<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConsumerRevision(<redacted>)")
    }
}

/// Exact target and last-known-applied predecessor of one durable apply intent.
/// Product code owns validation, impact planning, concrete effects and readback.
pub struct ConfigApplyIntent<C: OpcConfig> {
    target: ConsumerRevision<C>,
    previous: Option<ConsumerRevision<C>>,
}

impl<C: OpcConfig> ConfigApplyIntent<C> {
    /// Complete target whose intent is already persisted and read back.
    pub fn target(&self) -> &ConsumerRevision<C> {
        &self.target
    }
    /// Last-known-applied revision, if any; never a fabricated parent transaction.
    pub fn previous(&self) -> Option<&ConsumerRevision<C>> {
        self.previous.as_ref()
    }
}

impl<C: OpcConfig> fmt::Debug for ConfigApplyIntent<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfigApplyIntent(<redacted>)")
    }
}

/// Bounded runtime readback request. A pending intent and a historical applied
/// fact are explicitly distinct; neither asserts current live effects.
pub struct ConfigRuntimeReadback<C: OpcConfig> {
    pending: Option<ConfigApplyIntent<C>>,
    last_known_applied: Option<ConsumerRevision<C>>,
}

impl<C: OpcConfig> ConfigRuntimeReadback<C> {
    /// Exact unresolved application, if one may have started.
    pub fn pending(&self) -> Option<&ConfigApplyIntent<C>> {
        self.pending.as_ref()
    }
    /// Historical applied fact to verify when there is no pending application.
    pub fn last_known_applied(&self) -> Option<&ConsumerRevision<C>> {
        self.last_known_applied.as_ref()
    }
}

impl<C: OpcConfig> fmt::Debug for ConfigRuntimeReadback<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfigRuntimeReadback(<redacted>)")
    }
}

/// Product-owned effect outcome. Rejection promises that previous effects remain
/// unchanged; possible partial application must return `Indeterminate`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigApplyOutcome {
    /// Product proved the complete target effect.
    Applied,
    /// Product rejected the candidate before changing any current effect.
    Rejected,
    /// Product cannot prove the target or predecessor; no replay is permitted.
    Indeterminate,
}

/// Read-only product evidence against the complete supplied runtime request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigRuntimeReadbackOutcome {
    /// Complete pending target matches, or (without pending intent) the complete
    /// last-known-applied revision matches. Invalid when neither exists.
    MatchesTarget,
    /// Complete pending predecessor matches; valid only when that predecessor exists.
    MatchesPrevious,
    /// Product proves all configuration-owned effects absent.
    Absent,
    /// Product observed effects that match neither complete expected state.
    Conflict,
    /// Product readback cannot establish a complete result.
    Indeterminate,
}

/// Product effect boundary, serialized by the SDK consumer. The absolute local
/// deadline bounds each call; dropping the future cancels the call. If a dropped
/// apply may have mutated anything, the persisted intent remains unresolved.
#[async_trait]
pub trait ConfigConsumerApplyPort<C: OpcConfig>: Send {
    /// Validate and apply only this already-checkpointed intent. A successful
    /// local result is still checkpointed before the consumer reports application.
    async fn apply(
        &mut self,
        intent: &ConfigApplyIntent<C>,
        deadline: tokio::time::Instant,
    ) -> ConfigApplyOutcome;
    /// Read actual effects without replaying or applying the pending target.
    async fn read_back(
        &mut self,
        expected: &ConfigRuntimeReadback<C>,
        deadline: tokio::time::Instant,
    ) -> ConfigRuntimeReadbackOutcome;
}

/// Value-free checkpoint phase. `Applied` refers only to the exact observed
/// target and proven local effects, never global freshness or serving readiness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigConsumerPhase {
    /// No authenticated remote snapshot has been accepted.
    Unobserved,
    /// An authenticated complete target is durably staged, not locally applied.
    Observed,
    /// A durable application may have started and requires explicit readback.
    ApplyPending,
    /// Local checkpoint or runtime state must be read back before application.
    ReadbackRequired,
    /// Current product effects match the most recently accepted target.
    Applied,
}

/// Bounded operational projection with no revision, transaction, identity or payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigConsumerStatus {
    /// Exact local observed/apply/reconciliation phase.
    pub phase: ConfigConsumerPhase,
    /// A remote snapshot has been revalidated during this consumer lifetime and
    /// no subsequent remote failure has invalidated that observation. This is
    /// not a lease, proof of latest global state or permission to serve traffic.
    pub remote_revalidated: bool,
}

/// Acceptance is reported only after durable checkpoint readback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigAcceptanceOutcome {
    /// A complete authenticated snapshot or ordered revision was checkpointed.
    Accepted,
    /// The exact original transaction/version/canonical payload was already accepted.
    AlreadyAccepted,
}

/// Local application completion, distinct from remote acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigConsumerApplyResult {
    /// Target effects and their applied checkpoint have both been proved.
    Applied,
    /// The observed target already matches proven current local effects.
    AlreadyApplied,
    /// Candidate was rejected without changing the proven predecessor.
    Rejected,
    /// Possible effects require readback; the durable pending intent is retained.
    Indeterminate,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Revision {
    transaction: TxId,
    version: ConfigVersion,
    canonical_config: String,
}

impl Drop for Revision {
    fn drop(&mut self) {
        self.canonical_config.zeroize();
    }
}

impl Revision {
    fn project<C: OpcConfig + DeserializeOwned>(
        &self,
        schema: SchemaDigest,
    ) -> Result<ConsumerRevision<C>, ConfigConsumerError> {
        let config: C = serde_json::from_str(&self.canonical_config)
            .map_err(|_| ConfigConsumerError::InvalidState)?;
        if config.schema_digest() != schema {
            return Err(ConfigConsumerError::ScopeMismatch);
        }
        Ok(ConsumerRevision {
            transaction: self.transaction,
            version: self.version,
            config,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingApply {
    target: Revision,
    previous: Option<Revision>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointState {
    format: u16,
    accepted: Option<Revision>,
    last_known_applied: Option<Revision>,
    pending: Option<PendingApply>,
}

impl Default for CheckpointState {
    fn default() -> Self {
        Self {
            format: 1,
            accepted: None,
            last_known_applied: None,
            pending: None,
        }
    }
}

impl CheckpointState {
    fn validate<C: OpcConfig + DeserializeOwned>(
        &self,
        schema: SchemaDigest,
    ) -> Result<(), ConfigConsumerError> {
        if self.format != 1 {
            return Err(ConfigConsumerError::InvalidState);
        }
        for revision in self
            .accepted
            .iter()
            .chain(self.last_known_applied.iter())
            .chain(self.pending.iter().map(|p| &p.target))
            .chain(self.pending.iter().filter_map(|p| p.previous.as_ref()))
        {
            if revision.version == ConfigVersion::INITIAL {
                return Err(ConfigConsumerError::InvalidState);
            }
            revision.project::<C>(schema)?;
            let accepted = self
                .accepted
                .as_ref()
                .ok_or(ConfigConsumerError::InvalidState)?;
            if revision.version > accepted.version
                || (revision.version == accepted.version && revision != accepted)
            {
                return Err(ConfigConsumerError::InvalidState);
            }
        }
        if let Some(pending) = &self.pending {
            if pending.previous != self.last_known_applied
                || pending
                    .previous
                    .as_ref()
                    .is_some_and(|p| p.version >= pending.target.version)
            {
                return Err(ConfigConsumerError::InvalidState);
            }
        }
        Ok(())
    }
}

/// One SDK-owned remote consumer with one local checkpoint and no voter or
/// configuration-authoring capability. The adapter owns the actual authenticated
/// `RemoteConfigWatch`; caller-constructed snapshots cannot enter its API.
///
/// Reopening always requires product readback and fresh remote revalidation.
/// A coherent rollback of all local storage can still roll back the floor: only
/// independently fresh authority can establish the global target. Neither this
/// consumer nor a follower-local watch proves that global freshness by itself.
pub struct DurableConfigConsumer<C: OpcConfig> {
    remote: RemoteConfigWatch<C>,
    store: ConsumerCheckpointStore,
    state: CheckpointState,
    generation: u64,
    stream: Option<RemoteConfigRevisionStream<C>>,
    timeout: Duration,
    checkpoint_uncertain: bool,
    runtime_proven: bool,
    remote_revalidated: bool,
}

impl<C: OpcConfig> fmt::Debug for DurableConfigConsumer<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DurableConfigConsumer(<redacted>)")
    }
}

impl<C: OpcConfig + Serialize + DeserializeOwned> DurableConfigConsumer<C> {
    /// Attach the authenticated remote to an explicitly provisioned or reopened
    /// SDK checkpoint. Exact scope/schema/consumer checks precede any egress.
    /// Stored applied facts never set current runtime proof during construction.
    pub async fn new(
        remote: RemoteConfigWatch<C>,
        store: ConsumerCheckpointStore,
        timeout: Duration,
    ) -> Result<Self, ConfigConsumerError> {
        if timeout.is_zero() || timeout > Duration::from_secs(3600) {
            return Err(ConfigConsumerError::Limit);
        }
        if !store.binding().matches_consumer(
            &remote.binding.scope,
            remote.binding.schema_digest,
            &remote.binding.local_spiffe_id,
        ) {
            return Err(ConfigConsumerError::ScopeMismatch);
        }
        let mut consumer = Self {
            remote,
            store,
            state: CheckpointState::default(),
            generation: 0,
            stream: None,
            timeout,
            checkpoint_uncertain: true,
            runtime_proven: false,
            remote_revalidated: false,
        };
        consumer.reload_checkpoint().await?;
        Ok(consumer)
    }

    /// Read a value-free local phase. Product readiness remains product-owned.
    pub fn status(&self) -> ConfigConsumerStatus {
        let phase = if self.checkpoint_uncertain {
            ConfigConsumerPhase::ReadbackRequired
        } else if self.state.pending.is_some() {
            ConfigConsumerPhase::ApplyPending
        } else if !self.runtime_proven {
            ConfigConsumerPhase::ReadbackRequired
        } else if self.state.accepted.is_none() {
            ConfigConsumerPhase::Unobserved
        } else if self.state.accepted == self.state.last_known_applied {
            ConfigConsumerPhase::Applied
        } else {
            ConfigConsumerPhase::Observed
        };
        ConfigConsumerStatus {
            phase,
            remote_revalidated: self.remote_revalidated,
        }
    }

    /// Recover a complete snapshot at or above the persisted floor and replace
    /// the tail only after checkpointing acceptance. A forward compaction jump
    /// preserves the old applied fact; skipped revisions are never labelled applied.
    pub async fn replace_snapshot(
        &mut self,
    ) -> Result<ConfigAcceptanceOutcome, ConfigConsumerError> {
        self.require_checkpoint()?;
        self.stream = None;
        self.remote_revalidated = false;
        let floor = self.state.accepted.as_ref().map(|r| r.version);
        let recovery = tokio::time::timeout(self.timeout, self.remote.recover_from(floor))
            .await
            .map_err(|_| ConfigConsumerError::Limit)?
            .map_err(ConfigConsumerError::Remote)?;
        let (snapshot, stream) = recovery.into_parts();
        let outcome = self.accept(snapshot, true).await?;
        self.stream = Some(stream);
        self.remote_revalidated = true;
        Ok(outcome)
    }

    /// Poll one ordered tail item and checkpoint it before returning acceptance.
    /// Cancellation or an uncertain checkpoint retires the in-memory tail; an
    /// explicit snapshot recovery resumes from the actual durable floor.
    pub async fn accept_next(&mut self) -> Result<ConfigAcceptanceOutcome, ConfigConsumerError> {
        self.require_checkpoint()?;
        let mut stream = self
            .stream
            .take()
            .ok_or(ConfigConsumerError::RemoteRecoveryRequired)?;
        self.remote_revalidated = false;
        let item = tokio::time::timeout(self.timeout, stream.next())
            .await
            .map_err(|_| ConfigConsumerError::Limit)?
            .ok_or(ConfigConsumerError::RemoteRecoveryRequired)?
            .map_err(ConfigConsumerError::Remote)?;
        let outcome = self
            .accept(
                PublishedSnapshot {
                    tx_id: Some(item.tx_id),
                    version: item.version,
                    config: Arc::new(item.config),
                },
                false,
            )
            .await?;
        self.stream = Some(stream);
        self.remote_revalidated = true;
        Ok(outcome)
    }

    /// Persist and read back a complete apply intent before invoking product
    /// effects. A cancelled call or interrupted completion leaves that intent
    /// unresolved and cannot be replayed by a subsequent call.
    pub async fn apply_observed<P: ConfigConsumerApplyPort<C>>(
        &mut self,
        port: &mut P,
    ) -> Result<ConfigConsumerApplyResult, ConfigConsumerError> {
        self.require_checkpoint()?;
        if !self.runtime_proven || self.state.pending.is_some() {
            return Err(ConfigConsumerError::ReadbackRequired);
        }
        if !self.remote_revalidated {
            return Err(ConfigConsumerError::RemoteRecoveryRequired);
        }
        let target = self
            .state
            .accepted
            .as_ref()
            .ok_or(ConfigConsumerError::RemoteRecoveryRequired)?
            .clone();
        if self.state.last_known_applied.as_ref() == Some(&target) {
            return Ok(ConfigConsumerApplyResult::AlreadyApplied);
        }
        let pending = PendingApply {
            target,
            previous: self.state.last_known_applied.clone(),
        };
        let intent = self.project_intent(&pending)?;
        let mut staged = self.state.clone();
        staged.pending = Some(pending);
        self.persist(staged).await?;
        // This is deliberately after the durable intent and before any product
        // polling. Dropping the apply future leaves the proven intent intact.
        self.runtime_proven = false;
        let deadline = self.deadline()?;
        let outcome = tokio::time::timeout_at(deadline, port.apply(&intent, deadline))
            .await
            .unwrap_or(ConfigApplyOutcome::Indeterminate);
        if outcome == ConfigApplyOutcome::Indeterminate {
            return Ok(ConfigConsumerApplyResult::Indeterminate);
        }
        let mut completed = self.state.clone();
        let pending = completed
            .pending
            .take()
            .ok_or(ConfigConsumerError::InvalidState)?;
        let result = if outcome == ConfigApplyOutcome::Applied {
            completed.last_known_applied = Some(pending.target);
            ConfigConsumerApplyResult::Applied
        } else {
            ConfigConsumerApplyResult::Rejected
        };
        self.persist(completed).await?;
        self.runtime_proven = true;
        Ok(result)
    }

    /// Reconcile actual runtime effects against durable intent/applied facts.
    /// Never calls `apply`. An absence or exact predecessor proof makes a later
    /// explicit application possible; conflict/ambiguity retains the pending fact.
    pub async fn reconcile_runtime<P: ConfigConsumerApplyPort<C>>(
        &mut self,
        port: &mut P,
    ) -> Result<(), ConfigConsumerError> {
        self.runtime_proven = false;
        self.reload_checkpoint().await?;
        let expected = ConfigRuntimeReadback {
            pending: self
                .state
                .pending
                .as_ref()
                .map(|p| self.project_intent(p))
                .transpose()?,
            last_known_applied: self
                .state
                .last_known_applied
                .as_ref()
                .map(|r| r.project(self.remote.binding.schema_digest))
                .transpose()?,
        };
        let deadline = self.deadline()?;
        let outcome = tokio::time::timeout_at(deadline, port.read_back(&expected, deadline))
            .await
            .unwrap_or(ConfigRuntimeReadbackOutcome::Indeterminate);
        let mut reconciled = self.state.clone();
        match outcome {
            ConfigRuntimeReadbackOutcome::MatchesTarget => {
                if let Some(pending) = reconciled.pending.take() {
                    reconciled.last_known_applied = Some(pending.target);
                } else if reconciled.last_known_applied.is_none() {
                    return Err(ConfigConsumerError::RuntimeUnresolved);
                }
            }
            ConfigRuntimeReadbackOutcome::MatchesPrevious => {
                let pending = reconciled
                    .pending
                    .take()
                    .ok_or(ConfigConsumerError::RuntimeUnresolved)?;
                reconciled.last_known_applied = Some(
                    pending
                        .previous
                        .ok_or(ConfigConsumerError::RuntimeUnresolved)?,
                );
            }
            ConfigRuntimeReadbackOutcome::Absent => {
                reconciled.pending = None;
                reconciled.last_known_applied = None;
            }
            ConfigRuntimeReadbackOutcome::Conflict
            | ConfigRuntimeReadbackOutcome::Indeterminate => {
                return Err(ConfigConsumerError::RuntimeUnresolved)
            }
        }
        if reconciled != self.state {
            self.persist(reconciled).await?;
        }
        self.runtime_proven = true;
        Ok(())
    }

    /// Retire the owned transport tail and wait for checkpoint shutdown. This
    /// does not cancel or erase a durable pending product effect.
    pub async fn shutdown(mut self) -> Result<(), ConfigConsumerError> {
        self.stream = None;
        self.remote_revalidated = false;
        self.store.shutdown().await.map_err(Into::into)
    }

    fn require_checkpoint(&self) -> Result<(), ConfigConsumerError> {
        if self.checkpoint_uncertain {
            Err(ConfigConsumerError::ReadbackRequired)
        } else {
            Ok(())
        }
    }

    fn deadline(&self) -> Result<tokio::time::Instant, ConfigConsumerError> {
        tokio::time::Instant::now()
            .checked_add(self.timeout)
            .ok_or(ConfigConsumerError::Limit)
    }

    fn project_intent(
        &self,
        pending: &PendingApply,
    ) -> Result<ConfigApplyIntent<C>, ConfigConsumerError> {
        let schema = self.remote.binding.schema_digest;
        Ok(ConfigApplyIntent {
            target: pending.target.project(schema)?,
            previous: pending
                .previous
                .as_ref()
                .map(|r| r.project(schema))
                .transpose()?,
        })
    }

    async fn accept(
        &mut self,
        snapshot: PublishedSnapshot<C>,
        replacement: bool,
    ) -> Result<ConfigAcceptanceOutcome, ConfigConsumerError> {
        if snapshot.config.schema_digest() != self.remote.binding.schema_digest {
            return Err(ConfigConsumerError::ScopeMismatch);
        }
        let canonical_config = canonical_config(
            snapshot.config.as_ref(),
            self.store.max_payload_bytes(),
            self.deadline()?,
        )?;
        let revision = Revision {
            transaction: snapshot.tx_id.ok_or(ConfigConsumerError::InvalidState)?,
            version: snapshot.version,
            canonical_config,
        };
        if revision.version == ConfigVersion::INITIAL {
            return Err(ConfigConsumerError::InvalidState);
        }
        if let Some(accepted) = &self.state.accepted {
            if revision.version < accepted.version {
                return Err(ConfigConsumerError::RevisionConflict);
            }
            if revision.version == accepted.version {
                return if revision == *accepted {
                    Ok(ConfigAcceptanceOutcome::AlreadyAccepted)
                } else {
                    Err(ConfigConsumerError::RevisionConflict)
                };
            }
            if !replacement && accepted.version.next() != Some(revision.version) {
                return Err(ConfigConsumerError::InvalidSequence);
            }
        } else if !replacement {
            return Err(ConfigConsumerError::RemoteRecoveryRequired);
        }
        let mut staged = self.state.clone();
        staged.accepted = Some(revision);
        self.persist(staged).await?;
        Ok(ConfigAcceptanceOutcome::Accepted)
    }

    async fn reload_checkpoint(&mut self) -> Result<(), ConfigConsumerError> {
        self.checkpoint_uncertain = true;
        self.remote_revalidated = false;
        // Do not leave an already-polled tail positioned beyond recovered state.
        self.stream = None;
        let (generation, payload) = self.store.read_back().await?.into_parts();
        let state = if payload.is_empty() && generation == 1 {
            CheckpointState::default()
        } else {
            serde_json::from_slice(&payload).map_err(|_| ConfigConsumerError::InvalidState)?
        };
        state.validate::<C>(self.remote.binding.schema_digest)?;
        if generation < self.generation
            || (generation == self.generation && state != self.state)
            || self.state.accepted.as_ref().is_some_and(|old| {
                state.accepted.as_ref().is_none_or(|new| {
                    new.version < old.version || (new.version == old.version && new != old)
                })
            })
        {
            return Err(ConfigConsumerError::InvalidState);
        }
        self.state = state;
        self.generation = generation;
        self.checkpoint_uncertain = false;
        Ok(())
    }

    async fn persist(&mut self, state: CheckpointState) -> Result<(), ConfigConsumerError> {
        state.validate::<C>(self.remote.binding.schema_digest)?;
        let payload = bounded_encode(&state, self.store.max_payload_bytes(), self.deadline()?)?;
        self.checkpoint_uncertain = true;
        let (generation, readback) = self
            .store
            .compare_and_set(self.generation, payload)
            .await?
            .into_parts();
        let verified: CheckpointState =
            serde_json::from_slice(&readback).map_err(|_| ConfigConsumerError::InvalidState)?;
        if generation
            != self
                .generation
                .checked_add(1)
                .ok_or(ConfigConsumerError::Limit)?
            || verified != state
        {
            return Err(ConfigConsumerError::InvalidState);
        }
        self.state = state;
        self.generation = generation;
        self.checkpoint_uncertain = false;
        Ok(())
    }
}

struct BoundedWriter {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
    deadline: tokio::time::Instant,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if tokio::time::Instant::now() >= self.deadline
            || self
                .bytes
                .len()
                .checked_add(bytes.len())
                .is_none_or(|n| n > self.limit)
        {
            return Err(std::io::Error::other("consumer encoding bound exceeded"));
        }
        self.bytes
            .try_reserve_exact(bytes.len())
            .map_err(|_| std::io::Error::other("consumer encoding bound exceeded"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn bounded_encode<T: Serialize>(
    value: &T,
    limit: usize,
    deadline: tokio::time::Instant,
) -> Result<Zeroizing<Vec<u8>>, ConfigConsumerError> {
    let mut writer = BoundedWriter {
        bytes: Zeroizing::new(Vec::new()),
        limit,
        deadline,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| ConfigConsumerError::Limit)?;
    if tokio::time::Instant::now() >= deadline {
        return Err(ConfigConsumerError::Limit);
    }
    Ok(writer.bytes)
}

fn canonical_config<C: Serialize>(
    config: &C,
    limit: usize,
    deadline: tokio::time::Instant,
) -> Result<String, ConfigConsumerError> {
    // Bound the typed serialization before sorting objects. Preserve its number
    // tokens: a serde_json::Value intermediate can coerce integers through f64.
    let serialized = bounded_encode(config, limit, deadline)?;
    let mut writer = BoundedWriter {
        bytes: Zeroizing::new(Vec::new()),
        limit,
        deadline,
    };
    canonical::write(&serialized, &mut writer)?;
    if tokio::time::Instant::now() >= deadline {
        return Err(ConfigConsumerError::Limit);
    }
    String::from_utf8(std::mem::take(&mut *writer.bytes))
        .map_err(|_| ConfigConsumerError::InvalidState)
}

mod canonical;

#[cfg(test)]
mod tests;
