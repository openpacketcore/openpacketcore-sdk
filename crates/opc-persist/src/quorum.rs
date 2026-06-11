use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::error::PersistError;
use crate::preflight::PersistCapabilities;
use crate::types::{AuditRecord, CommitRecord, ConfigStore, RollbackTarget, StoredConfig};
use opc_types::TxId;

/// A wrapper around a ConfigStore replica node that supports epoch-based fencing
/// and simulated network partitions/offline states.
#[derive(Clone)]
pub struct FencedReplica {
    pub id: usize,
    pub inner: Arc<dyn ConfigStore>,
    pub max_epoch: Arc<tokio::sync::Mutex<u64>>,
    pub online: Arc<tokio::sync::Mutex<bool>>,
}

impl FencedReplica {
    pub fn new(id: usize, inner: Arc<dyn ConfigStore>) -> Self {
        Self {
            id,
            inner,
            max_epoch: Arc::new(tokio::sync::Mutex::new(0)),
            online: Arc::new(tokio::sync::Mutex::new(true)),
        }
    }

    pub async fn is_online(&self) -> bool {
        *self.online.lock().await
    }

    pub async fn set_online(&self, online: bool) {
        *self.online.lock().await = online;
    }

    pub async fn get_max_epoch(&self) -> u64 {
        *self.max_epoch.lock().await
    }

    pub async fn set_max_epoch(&self, epoch: u64) {
        *self.max_epoch.lock().await = epoch;
    }

    /// Register a leader's epoch. Fails if the epoch is older than the current max epoch.
    pub async fn register_epoch(&self, epoch: u64) -> Result<(), PersistError> {
        if !self.is_online().await {
            return Err(PersistError::io("replica offline"));
        }
        let mut max_guard = self.max_epoch.lock().await;
        if epoch < *max_guard {
            return Err(PersistError::inconsistent_state(format!(
                "Fenced: epoch {} is older than replica max epoch {}",
                epoch, *max_guard
            )));
        }
        *max_guard = epoch;
        Ok(())
    }
}

/// A replicated ConfigStore that manages writes and reads across multiple replicas
/// using quorum consensus (majority) and leader epoch fencing to guarantee safety
/// under failover and split-brain scenarios.
pub struct QuorumConfigStore {
    replicas: Vec<FencedReplica>,
    leader_epoch: Arc<tokio::sync::Mutex<u64>>,
}

impl QuorumConfigStore {
    pub fn new(replicas: Vec<FencedReplica>, leader_epoch: u64) -> Self {
        Self {
            replicas,
            leader_epoch: Arc::new(tokio::sync::Mutex::new(leader_epoch)),
        }
    }

    pub async fn set_leader_epoch(&self, epoch: u64) {
        let mut guard = self.leader_epoch.lock().await;
        *guard = epoch;
    }

    pub async fn get_leader_epoch(&self) -> u64 {
        *self.leader_epoch.lock().await
    }

    /// Calculate quorum size based on the total configured replicas.
    fn quorum_size(&self) -> usize {
        (self.replicas.len() / 2) + 1
    }

    /// Assert the leader epoch on all online replicas.
    /// Returns the replicas on which registration succeeded if quorum is reached.
    async fn assert_epoch_quorum(&self) -> Result<Vec<FencedReplica>, PersistError> {
        let epoch = self.get_leader_epoch().await;
        let mut successful_replicas = Vec::new();

        for replica in &self.replicas {
            if replica.register_epoch(epoch).await.is_ok() {
                successful_replicas.push(replica.clone());
            }
        }

        if successful_replicas.len() < self.quorum_size() {
            warn!(
                epoch = epoch,
                successful = successful_replicas.len(),
                required = self.quorum_size(),
                "failed to establish leader epoch quorum"
            );
            return Err(PersistError::inconsistent_state(
                "fencing registration failed: leader epoch quorum not reached",
            ));
        }

        Ok(successful_replicas)
    }
}

#[async_trait]
impl ConfigStore for QuorumConfigStore {
    async fn load_latest(&self) -> Result<Option<StoredConfig>, PersistError> {
        let mut votes: HashMap<TxId, (StoredConfig, usize)> = HashMap::new();
        let mut none_votes = 0;
        let mut total_responses = 0;

        for replica in &self.replicas {
            if !replica.is_online().await {
                continue;
            }
            match replica.inner.load_latest().await {
                Ok(Some(config)) => {
                    total_responses += 1;
                    let tx_id = config.record.tx_id;
                    votes
                        .entry(tx_id)
                        .and_modify(|(_, count)| *count += 1)
                        .or_insert((config, 1));
                }
                Ok(None) => {
                    total_responses += 1;
                    none_votes += 1;
                }
                Err(err) => {
                    debug!(replica_id = replica.id, error = ?err, "replica load_latest failed");
                }
            }
        }

        let quorum = self.quorum_size();

        // Check if None has quorum
        if none_votes >= quorum {
            return Ok(None);
        }

        // Find the configuration with the highest version/tx_id that has quorum support
        let mut best_config: Option<StoredConfig> = None;

        for (config, count) in votes.values() {
            if *count >= quorum {
                if let Some(ref current_best) = best_config {
                    if config.record.version.get() > current_best.record.version.get() {
                        best_config = Some(config.clone());
                    }
                } else {
                    best_config = Some(config.clone());
                }
            }
        }

        if let Some(config) = best_config {
            Ok(Some(config))
        } else if total_responses >= quorum {
            // If we have responses but no consensus, return an error
            Err(PersistError::inconsistent_state(
                "no quorum consensus for latest config",
            ))
        } else {
            Err(PersistError::io("quorum of replicas unavailable"))
        }
    }

    async fn load_rollback(&self, target: RollbackTarget) -> Result<StoredConfig, PersistError> {
        let mut votes: HashMap<TxId, (StoredConfig, usize)> = HashMap::new();
        let mut not_found_count = 0;
        let mut total_responses = 0;

        for replica in &self.replicas {
            if !replica.is_online().await {
                continue;
            }
            match replica.inner.load_rollback(target.clone()).await {
                Ok(config) => {
                    total_responses += 1;
                    let tx_id = config.record.tx_id;
                    votes
                        .entry(tx_id)
                        .and_modify(|(_, count)| *count += 1)
                        .or_insert((config, 1));
                }
                Err(err) => {
                    total_responses += 1;
                    if let crate::error::PersistErrorKind::RollbackNotFound = err.kind() {
                        not_found_count += 1;
                    }
                    debug!(replica_id = replica.id, error = ?err, "replica load_rollback failed");
                }
            }
        }

        let quorum = self.quorum_size();

        if not_found_count >= quorum {
            return Err(PersistError::rollback_not_found());
        }

        let mut best_config: Option<StoredConfig> = None;

        for (config, count) in votes.values() {
            if *count >= quorum {
                best_config = Some(config.clone());
                break;
            }
        }

        if let Some(config) = best_config {
            Ok(config)
        } else if total_responses >= quorum {
            Err(PersistError::rollback_not_found())
        } else {
            Err(PersistError::io(
                "quorum of replicas unavailable for rollback",
            ))
        }
    }

    async fn append_commit(
        &self,
        record: CommitRecord,
        audit: Vec<AuditRecord>,
    ) -> Result<(), PersistError> {
        let active_replicas = self.assert_epoch_quorum().await?;
        let mut write_successes = 0;

        for replica in active_replicas {
            if replica
                .inner
                .append_commit(record.clone(), audit.clone())
                .await
                .is_ok()
            {
                write_successes += 1;
            }
        }

        if write_successes < self.quorum_size() {
            return Err(PersistError::inconsistent_state(
                "quorum write failed for append_commit",
            ));
        }

        Ok(())
    }

    async fn mark_confirmed(&self, tx_id: TxId) -> Result<(), PersistError> {
        let active_replicas = self.assert_epoch_quorum().await?;
        let mut write_successes = 0;

        for replica in active_replicas {
            if replica.inner.mark_confirmed(tx_id).await.is_ok() {
                write_successes += 1;
            }
        }

        if write_successes < self.quorum_size() {
            return Err(PersistError::inconsistent_state(
                "quorum write failed for mark_confirmed",
            ));
        }

        Ok(())
    }

    async fn create_rollback_point(
        &self,
        tx_id: TxId,
        label: Option<String>,
    ) -> Result<(), PersistError> {
        let active_replicas = self.assert_epoch_quorum().await?;
        let mut write_successes = 0;

        for replica in active_replicas {
            if replica
                .inner
                .create_rollback_point(tx_id, label.clone())
                .await
                .is_ok()
            {
                write_successes += 1;
            }
        }

        if write_successes < self.quorum_size() {
            return Err(PersistError::inconsistent_state(
                "quorum write failed for create_rollback_point",
            ));
        }

        Ok(())
    }

    async fn preflight(&self) -> Result<PersistCapabilities, PersistError> {
        // Run preflight on all online replicas and return the first successful one
        for replica in &self.replicas {
            if replica.is_online().await {
                if let Ok(caps) = replica.inner.preflight().await {
                    return Ok(caps);
                }
            }
        }
        Err(PersistError::preflight_failed(
            "no online replicas available for preflight",
        ))
    }
}
