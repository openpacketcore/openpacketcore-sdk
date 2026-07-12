use super::{
    ConsensusConfigStore, InstallSnapshotRequest, InstallSnapshotResponse, Role, SnapshotPayload,
};
use crate::backend::SqliteBackend;
use crate::error::PersistError;
use crate::types::ConfigStore;
use std::sync::atomic::Ordering;
use std::time::Instant;

impl ConsensusConfigStore {
    pub async fn compact_logs(&self, up_to_index: u64) -> Result<(), PersistError> {
        let applied_index = self.inner.consensus_get_applied_index().await?;
        if up_to_index != applied_index {
            return Err(PersistError::inconsistent_state(
                "snapshot index must match applied consensus state",
            ));
        }

        let membership = self
            .inner
            .consensus_get_active_membership()
            .await?
            .ok_or_else(|| PersistError::inconsistent_state("membership not found"))?;

        let latest_opt = self.inner.load_latest().await?;
        if let Some(config) = latest_opt {
            let term_opt = self.inner.consensus_get_log_term(up_to_index).await?;
            let term = term_opt.unwrap_or(0);

            let mut payload = SnapshotPayload {
                cluster_id: membership.cluster_id.clone(),
                membership_epoch: membership.epoch,
                last_included_index: up_to_index,
                last_included_term: term,
                config,
                membership,
                payload_hmac: [0u8; 32],
            };
            payload.payload_hmac = payload.calculate_hmac(self.inner.audit_key());

            let snap_data = serde_json::to_vec(&payload)
                .map_err(|e| PersistError::inconsistent_state(e.to_string()))?;

            self.inner
                .consensus_set_snapshot(up_to_index, term, &snap_data)
                .await?;
            self.inner.consensus_compact_logs(up_to_index).await?;
        }
        Ok(())
    }

    pub async fn handle_install_snapshot(
        &self,
        req: InstallSnapshotRequest,
    ) -> Result<InstallSnapshotResponse, PersistError> {
        let mut state = self.state.lock().await;
        if !state.online {
            self.metrics
                .snapshot_failures
                .fetch_add(1, Ordering::Relaxed);
            return Err(PersistError::io("node offline"));
        }

        // SQLite stores every Raft coordinate as a signed INTEGER. Validate
        // all request coordinates before changing the in-memory term or any
        // durable config/membership state; otherwise a one-over-boundary
        // snapshot could wrap only after destructive snapshot installation.
        SqliteBackend::consensus_term_to_sqlite(req.term)?;
        SqliteBackend::consensus_node_id_to_sqlite(req.leader_id)?;
        SqliteBackend::consensus_index_to_sqlite(req.last_included_index)?;
        SqliteBackend::consensus_term_to_sqlite(req.last_included_term)?;
        if req.term > state.current_term {
            self.inner.consensus_set_state(req.term, None).await?;
            state.current_term = req.term;
            state.voted_for = None;
            state.role = Role::Follower;
            state.leader_id = Some(req.leader_id);
        }

        if req.term >= state.current_term {
            state.last_contact = Instant::now();
        }

        if req.term < state.current_term {
            opc_redaction::metrics::METRICS
                .persist_stale_leader_rejections
                .fetch_add(1, Ordering::Relaxed);
            self.metrics
                .snapshot_failures
                .fetch_add(1, Ordering::Relaxed);
            return Ok(InstallSnapshotResponse {
                term: state.current_term,
                success: false,
            });
        }

        state.role = Role::Follower;
        state.leader_id = Some(req.leader_id);

        let applied_index = self.inner.consensus_get_applied_index().await?;
        if req.last_included_index <= applied_index {
            state.commit_index = state.commit_index.max(applied_index);
            state.last_applied = state.last_applied.max(applied_index);
            self.metrics
                .snapshot_installs
                .fetch_add(1, Ordering::Relaxed);
            return Ok(InstallSnapshotResponse {
                term: state.current_term,
                success: true,
            });
        }

        // Parse and validate the new SnapshotPayload
        let payload: SnapshotPayload = match serde_json::from_slice(&req.data) {
            Ok(p) => p,
            Err(e) => {
                self.metrics
                    .snapshot_failures
                    .fetch_add(1, Ordering::Relaxed);
                opc_redaction::metrics::METRICS
                    .persist_snapshot_verify_failures
                    .fetch_add(1, Ordering::Relaxed);
                return Err(PersistError::inconsistent_state(format!(
                    "Corrupt snapshot JSON: {e}"
                )));
            }
        };

        // Validate metadata binds
        let membership = self
            .inner
            .consensus_get_active_membership()
            .await?
            .ok_or_else(|| PersistError::inconsistent_state("membership not found"))?;
        if payload.cluster_id != membership.cluster_id {
            self.metrics
                .snapshot_failures
                .fetch_add(1, Ordering::Relaxed);
            opc_redaction::metrics::METRICS
                .persist_snapshot_verify_failures
                .fetch_add(1, Ordering::Relaxed);
            return Err(PersistError::inconsistent_state(
                "Snapshot cluster_id mismatch",
            ));
        }

        if payload.last_included_index != req.last_included_index
            || payload.last_included_term != req.last_included_term
        {
            self.metrics
                .snapshot_failures
                .fetch_add(1, Ordering::Relaxed);
            opc_redaction::metrics::METRICS
                .persist_snapshot_verify_failures
                .fetch_add(1, Ordering::Relaxed);
            return Err(PersistError::inconsistent_state(
                "Snapshot metadata term/index mismatch",
            ));
        }

        // Validate HMAC
        let computed_hmac = payload.calculate_hmac(self.inner.audit_key());
        if payload.payload_hmac != computed_hmac {
            self.metrics
                .snapshot_failures
                .fetch_add(1, Ordering::Relaxed);
            opc_redaction::metrics::METRICS
                .persist_snapshot_verify_failures
                .fetch_add(1, Ordering::Relaxed);
            return Err(PersistError::inconsistent_state(
                "Snapshot HMAC verification failed",
            ));
        }

        // Validate config audit chain
        if let Err(e) = payload.config.verify_audit_chain(self.inner.audit_key()) {
            self.metrics
                .snapshot_failures
                .fetch_add(1, Ordering::Relaxed);
            opc_redaction::metrics::METRICS
                .persist_snapshot_verify_failures
                .fetch_add(1, Ordering::Relaxed);
            return Err(PersistError::inconsistent_state(format!(
                "Snapshot config audit chain invalid: {e}"
            )));
        }

        // Install the state-machine data and every Raft snapshot marker as one
        // SQLite transaction. A failure at any stage leaves the follower's
        // prior config, audit chain, membership, snapshot, applied index, and
        // log intact for an unambiguous retry.
        let mut follower_membership = payload.membership;
        follower_membership.node_id = self.node_id;
        self.inner
            .consensus_install_snapshot_bundle(
                payload.config,
                &follower_membership,
                req.last_included_index,
                req.last_included_term,
                &req.data,
            )
            .await?;

        state.commit_index = req.last_included_index;
        state.last_applied = req.last_included_index;

        self.metrics
            .snapshot_installs
            .fetch_add(1, Ordering::Relaxed);
        Ok(InstallSnapshotResponse {
            term: state.current_term,
            success: true,
        })
    }
}
