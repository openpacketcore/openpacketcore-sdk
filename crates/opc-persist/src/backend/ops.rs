use async_trait::async_trait;
use rusqlite::{params, OptionalExtension};
use std::str::FromStr;
use std::sync::Arc;
use tracing::debug;

use opc_types::{ConfigVersion, SchemaDigest, Timestamp, TxId};

use crate::error::PersistError;
use crate::preflight::PersistCapabilities;
use crate::types::{
    AlarmAuditEventRecord, AuditKey, AuditOpType, AuditRecord, CommitRecord, CommitSource,
    ConfigStore, ConfirmedCommitResolution, RollbackTarget, StoredConfig,
};

use super::{
    deserialize_audit_op_type, deserialize_commit_source, uuid_from_bytes, validate_uuid_bytes,
    SqliteBackend, StoredConfigRow,
};

type LatestConfigHeadRow = (Vec<u8>, i64, Option<String>, Option<String>, String);

// ─────────────────────────────────────────────────────────────────────────────
// ConfigStore implementation
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl ConfigStore for SqliteBackend {
    async fn load_latest(&self) -> Result<Option<StoredConfig>, PersistError> {
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        let res = Self::load_latest_impl(&guard, self.audit_key.as_ref());
        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .persist_read_success
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        res
    }

    async fn load_committed_latest(&self) -> Result<Option<StoredConfig>, PersistError> {
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        let res = Self::load_committed_latest_impl(&guard, self.audit_key.as_ref());
        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .persist_read_success
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        res
    }

    async fn load_since(
        &self,
        version: ConfigVersion,
        limit: usize,
    ) -> Result<Vec<StoredConfig>, PersistError> {
        if limit > crate::CONFIG_HISTORY_PAGE_MAX_ENTRIES {
            return Err(PersistError::constraint_violation(
                "config history page exceeds the contract bound",
            ));
        }
        if limit == 0 {
            return Ok(Vec::new());
        }
        let requested_version = version;
        let Ok(version) = i64::try_from(version.get()) else {
            return Ok(Vec::new());
        };
        let limit = i64::try_from(limit).map_err(|_| {
            PersistError::constraint_violation("config history page limit is invalid")
        })?;
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        let res = (|| {
            let visible_head = Self::load_committed_latest_impl(&guard, self.audit_key.as_ref())?;
            if visible_head
                .as_ref()
                .is_none_or(|head| requested_version >= head.record.version)
            {
                return Ok(Vec::new());
            }
            let mut statement = guard
                .prepare(
                    "SELECT tx_id FROM config_history WHERE version > ?1 ORDER BY version ASC LIMIT ?2",
                )
                .map_err(|error| PersistError::sqlite(error.to_string()))?;
            let rows = statement
                .query_map(params![version, limit], |row| row.get::<_, Vec<u8>>(0))
                .map_err(|error| PersistError::sqlite(error.to_string()))?;
            let mut records = Vec::new();
            for row in rows {
                let tx_id = row.map_err(|error| PersistError::sqlite(error.to_string()))?;
                let record = Self::load_by_tx_id_bytes(&guard, &tx_id, self.audit_key.as_ref())?
                    .ok_or_else(|| {
                        PersistError::inconsistent_state(
                            "config history row disappeared during a locked page read",
                        )
                    })?;
                if crate::types::config_recovery_required(&record.record.principal)? {
                    break;
                }
                records.push(record);
            }
            Ok(records)
        })();
        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .persist_read_success
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        res
    }

    async fn load_rollback(&self, target: RollbackTarget) -> Result<StoredConfig, PersistError> {
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        let res = Self::load_rollback_impl(&guard, &target, self.audit_key.as_ref());
        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .persist_read_success
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        res
    }

    async fn load_by_replay_lookup_digest(
        &self,
        digest: &str,
    ) -> Result<Option<StoredConfig>, PersistError> {
        crate::types::validate_replay_lookup_digest(digest)?;
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        let res = (|| {
            let tx_id: Option<Vec<u8>> = guard
                .query_row(
                    r#"SELECT tx_id
                       FROM config_history
                       WHERE CASE
                               WHEN json_valid(principal)
                               THEN json_extract(principal, '$.replay_lookup_digest')
                               ELSE NULL
                             END = ?1
                       LIMIT 1"#,
                    [digest],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| PersistError::sqlite(error.to_string()))?;
            tx_id
                .map(|tx_id| {
                    Self::load_by_tx_id_bytes(&guard, &tx_id, self.audit_key.as_ref())
                        .and_then(|record| record.ok_or_else(PersistError::rollback_not_found))
                })
                .transpose()
        })();
        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .persist_read_success
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        res
    }

    async fn append_commit(
        &self,
        record: CommitRecord,
        audit: Vec<AuditRecord>,
    ) -> Result<(), PersistError> {
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        let res = Self::ensure_standalone_write_authority(&guard).and_then(|()| {
            Self::append_commit_impl(&guard, record, audit, None, self.audit_key.as_ref())
        });
        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .persist_write_success
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        res
    }

    async fn append_commit_resolving(
        &self,
        record: CommitRecord,
        audit: Vec<AuditRecord>,
        resolution: ConfirmedCommitResolution,
    ) -> Result<(), PersistError> {
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        let res = Self::ensure_standalone_write_authority(&guard).and_then(|()| {
            Self::append_commit_impl(
                &guard,
                record,
                audit,
                Some(resolution),
                self.audit_key.as_ref(),
            )
        });
        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .persist_write_success
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        res
    }

    async fn clear_recovery_required(&self, tx_id: TxId) -> Result<(), PersistError> {
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        let res = (|| -> Result<(), PersistError> {
            Self::ensure_standalone_write_authority(&guard)?;
            let tx = guard
                .unchecked_transaction()
                .map_err(|error| PersistError::sqlite(error.to_string()))?;
            let tx_id_bytes = tx_id.as_uuid().as_bytes().to_vec();
            let principal: Option<String> = tx
                .query_row(
                    "SELECT principal FROM config_history WHERE tx_id = ?1 AND tx_id = (SELECT tx_id FROM config_history ORDER BY version DESC LIMIT 1)",
                    [&tx_id_bytes],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| PersistError::sqlite(error.to_string()))?;
            let Some(principal) = principal else {
                return Err(PersistError::rollback_not_found());
            };
            let Some(encoded) = crate::types::clear_config_recovery_required(&principal)? else {
                return Ok(());
            };
            let changed = tx
                .execute(
                    "UPDATE config_history SET principal = ?1 WHERE tx_id = ?2 AND tx_id = (SELECT tx_id FROM config_history ORDER BY version DESC LIMIT 1)",
                    params![encoded, &tx_id_bytes],
                )
                .map_err(|error| PersistError::sqlite(error.to_string()))?;
            if changed != 1 {
                return Err(PersistError::constraint_violation(
                    "config recovery marker is no longer current",
                ));
            }
            tx.execute(
                "INSERT INTO config_lifecycle_audit (tx_id, action, principal, occurred_at, details) VALUES (?1, 'CLEAR_RECOVERY_REQUIRED', ?2, ?3, 'config recovery marker cleared')",
                params![&tx_id_bytes, principal, Timestamp::now_utc().to_string()],
            )
            .map_err(|error| PersistError::sqlite(error.to_string()))?;
            tx.commit().map_err(|_| PersistError::outcome_unknown())?;
            Ok(())
        })();
        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .persist_write_success
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        res
    }

    async fn mark_confirmed(&self, tx_id: TxId) -> Result<(), PersistError> {
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        let tx_id_bytes = tx_id.as_uuid().as_bytes().to_vec();
        let now = Timestamp::now_utc().to_string();

        let res = (|| -> Result<(), PersistError> {
            Self::ensure_standalone_write_authority(&guard)?;
            let tx = guard
                .unchecked_transaction()
                .map_err(|e| PersistError::sqlite(e.to_string()))?;
            let principal: Option<String> = tx
                .query_row(
                    "SELECT principal FROM config_history WHERE tx_id = ?1",
                    params![&tx_id_bytes],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| PersistError::sqlite(e.to_string()))?;
            let Some(principal) = principal else {
                return Err(PersistError::rollback_not_found());
            };
            let rows = tx
                .execute(
                    "UPDATE config_history SET confirmed_at = ?1 WHERE tx_id = ?2 AND confirmed_deadline IS NOT NULL AND confirmed_at IS NULL AND tx_id = (SELECT tx_id FROM config_history ORDER BY version DESC LIMIT 1)",
                    params![now, &tx_id_bytes],
                )
                .map_err(|e| PersistError::sqlite(e.to_string()))?;

            if rows != 1 {
                return Err(PersistError::rollback_not_found());
            }
            tx.execute(
                "INSERT INTO config_lifecycle_audit (tx_id, action, principal, occurred_at, details) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    &tx_id_bytes,
                    "MARK_CONFIRMED",
                    principal,
                    Timestamp::now_utc().to_string(),
                    "commit confirmed",
                ],
            )
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
            tx.commit()
                .map_err(|e| PersistError::sqlite(e.to_string()))?;
            debug!(tx_id = %tx_id, "commit marked confirmed");
            Ok(())
        })();

        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .persist_write_success
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        res
    }

    async fn create_rollback_point(
        &self,
        tx_id: TxId,
        label: Option<String>,
    ) -> Result<(), PersistError> {
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        let tx_id_bytes = tx_id.as_uuid().as_bytes().to_vec();

        let res = (|| -> Result<(), PersistError> {
            Self::ensure_standalone_write_authority(&guard)?;
            let tx = guard
                .unchecked_transaction()
                .map_err(|e| PersistError::sqlite(e.to_string()))?;
            let principal: String = tx
                .query_row(
                    "SELECT principal FROM config_history WHERE tx_id = ?1",
                    params![&tx_id_bytes],
                    |row| row.get(0),
                )
                .map_err(|e| PersistError::sqlite(e.to_string()))?;
            let rows = tx
                .execute(
                    "UPDATE config_history SET rollback_point = 1 WHERE tx_id = ?1",
                    params![&tx_id_bytes],
                )
                .map_err(|e| PersistError::sqlite(e.to_string()))?;

            if rows == 0 {
                return Err(PersistError::rollback_not_found());
            }

            if let Some(lbl) = &label {
                tx
                    .execute(
                        "INSERT OR REPLACE INTO rollback_labels (label, tx_id, created_at) VALUES (?1, ?2, ?3)",
                        params![lbl, &tx_id_bytes, Timestamp::now_utc().to_string()],
                    )
                    .map_err(|e| PersistError::sqlite(e.to_string()))?;
            }

            let details = match &label {
                Some(lbl) => format!("rollback point created with label {lbl}"),
                None => "rollback point created".to_string(),
            };
            tx.execute(
                "INSERT INTO config_lifecycle_audit (tx_id, action, principal, occurred_at, details) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    &tx_id_bytes,
                    "CREATE_ROLLBACK_POINT",
                    principal,
                    Timestamp::now_utc().to_string(),
                    details,
                ],
            )
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
            tx.commit()
                .map_err(|e| PersistError::sqlite(e.to_string()))?;
            debug!(tx_id = %tx_id, label = ?label, "rollback point created");
            Ok(())
        })();

        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .persist_write_success
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        res
    }

    async fn preflight(&self) -> Result<PersistCapabilities, PersistError> {
        if let Some(caps) = self.cached_caps.get() {
            return Ok(caps.clone());
        }

        let caps = Self::run_preflight(&self.db_path, self.ephemeral, self.min_free_bytes).await?;
        // Best-effort cache; OnceLock may already be set by open().
        let _ = self.cached_caps.set(caps.clone());
        Ok(caps)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Synchronous helper implementations
// ─────────────────────────────────────────────────────────────────────────────

impl SqliteBackend {
    /// Reject direct local mutation after the atomic Openraft authority claim.
    ///
    /// The consensus initializer and every standalone mutation share the same
    /// SQLite connection mutex and use an immediate transaction, so a racing
    /// local write is either included in the legacy-recovery check or observes
    /// this durable fence and fails closed.
    fn ensure_standalone_write_authority(conn: &rusqlite::Connection) -> Result<(), PersistError> {
        let claimed: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'config_raft_identity')",
                [],
                |row| row.get(0),
            )
            .map_err(|_| PersistError::unavailable())?;
        if claimed {
            return Err(PersistError::inconsistent_state(
                "direct config mutation is disabled after Openraft authority claim",
            ));
        }
        Ok(())
    }

    /// Verify an already-loaded audit chain using this backend's audit key.
    pub fn verify_audit_chain(&self, stored: &StoredConfig) -> Result<(), PersistError> {
        let res = stored.verify_audit_chain(self.audit_key.as_ref());
        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .persist_audit_chain_verification_success
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            opc_redaction::metrics::METRICS
                .persist_audit_chain_verification_failure
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        res
    }

    /// Load the most recent configuration (confirmed or pending).
    fn load_latest_impl(
        conn: &rusqlite::Connection,
        audit_key: &AuditKey,
    ) -> Result<Option<StoredConfig>, PersistError> {
        // Find the highest version (absolute latest)
        let tx_id_bytes: Option<Vec<u8>> = conn
            .query_row(
                r#"
                SELECT tx_id FROM config_history
                ORDER BY version DESC
                LIMIT 1
                "#,
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| PersistError::sqlite(e.to_string()))?;

        let Some(tx_id_bytes) = tx_id_bytes else {
            return Ok(None);
        };

        Self::load_by_tx_id_bytes(conn, &tx_id_bytes, audit_key)
    }

    fn load_committed_latest_impl(
        conn: &rusqlite::Connection,
        audit_key: &AuditKey,
    ) -> Result<Option<StoredConfig>, PersistError> {
        let first_fenced: Option<(Vec<u8>, Option<Vec<u8>>)> = conn
            .query_row(
                r#"SELECT tx_id, parent_tx_id
                   FROM config_history
                   WHERE CASE
                           WHEN json_valid(principal)
                           THEN json_extract(principal, '$.recovery_required')
                           ELSE 0
                         END = 1
                   ORDER BY version ASC
                   LIMIT 1"#,
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| PersistError::sqlite(error.to_string()))?;
        let Some((fenced_tx_id, parent_tx_id)) = first_fenced else {
            return Self::load_latest_impl(conn, audit_key);
        };
        let fenced =
            Self::load_by_tx_id_bytes(conn, &fenced_tx_id, audit_key)?.ok_or_else(|| {
                PersistError::inconsistent_state("fenced config history row disappeared")
            })?;
        if !crate::types::config_recovery_required(&fenced.record.principal)? {
            return Err(PersistError::inconsistent_state(
                "config publication-fence index is inconsistent",
            ));
        }
        let Some(parent_tx_id) = parent_tx_id else {
            return Ok(None);
        };
        Self::load_by_tx_id_bytes(conn, &parent_tx_id, audit_key)?.map_or_else(
            || {
                Err(PersistError::inconsistent_state(
                    "fenced config head has no durable parent",
                ))
            },
            |parent| Ok(Some(parent)),
        )
    }

    /// Load a rollback target.
    fn load_rollback_impl(
        conn: &rusqlite::Connection,
        target: &RollbackTarget,
        audit_key: &AuditKey,
    ) -> Result<StoredConfig, PersistError> {
        let tx_id_bytes = match target {
            RollbackTarget::Previous => {
                // Find the parent_tx_id of the newest confirmed/non-pending commit,
                // then load that parent record — not the newest row itself.
                let parent_bytes: Option<Vec<u8>> = conn
                    .query_row(
                        r#"
                        SELECT parent_tx_id FROM config_history
                        WHERE (confirmed_at IS NOT NULL OR confirmed_deadline IS NULL)
                          AND parent_tx_id IS NOT NULL
                        ORDER BY version DESC
                        LIMIT 1
                        "#,
                        [],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|e| PersistError::sqlite(e.to_string()))?;
                parent_bytes
            }
            RollbackTarget::ByTxId(tx_id) => Some(tx_id.as_uuid().as_bytes().to_vec()),
            RollbackTarget::ByVersion(version) => conn
                .query_row(
                    "SELECT tx_id FROM config_history WHERE version = ?1",
                    [version.get() as i64],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()
                .map_err(|e| PersistError::sqlite(e.to_string()))?,
            RollbackTarget::ByLabel(label) => conn
                .query_row(
                    "SELECT tx_id FROM rollback_labels WHERE label = ?1",
                    [label],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()
                .map_err(|e| PersistError::sqlite(e.to_string()))?,
        };

        let Some(bytes) = tx_id_bytes else {
            return Err(PersistError::rollback_not_found());
        };

        // Reject if target is a pending commit
        let is_pending: bool = conn
            .query_row(
                "SELECT 1 FROM config_history WHERE tx_id = ?1 AND confirmed_deadline IS NOT NULL AND confirmed_at IS NULL",
                [&bytes],
                |_| Ok(true),
            )
            .optional()
            .map_err(|e| PersistError::sqlite(e.to_string()))?
            .unwrap_or(false);
        if is_pending {
            return Err(PersistError::rollback_not_found());
        }

        Self::load_by_tx_id_bytes(conn, &bytes, audit_key)?
            .ok_or_else(PersistError::rollback_not_found)
    }

    /// Append a commit record and its audit trail atomically.
    pub(crate) fn append_commit_raw(
        conn: &rusqlite::Connection,
        record: CommitRecord,
        audit: Vec<AuditRecord>,
        audit_key: &AuditKey,
    ) -> Result<(), PersistError> {
        // Insert commit record
        let tx_id_bytes = record.tx_id.as_uuid().as_bytes().to_vec();
        let parent_tx_id_bytes = record.parent_tx_id.map(|t| t.as_uuid().as_bytes().to_vec());
        // The ordinary append path validates metadata before reaching this
        // raw helper. Preserve the helper's ability to seed externally
        // malformed rows for recovery-integrity tests.
        let rollback_label = crate::types::config_rollback_label(&record.principal)
            .ok()
            .flatten();
        if rollback_label.is_some() && !record.rollback_point {
            return Err(PersistError::constraint_violation(
                "named rollback commit is not marked as a rollback point",
            ));
        }

        let source_str = match record.source {
            CommitSource::Gnmi => "gnmi",
            CommitSource::Netconf => "netconf",
            CommitSource::LocalOperator => "local_operator",
            CommitSource::StartupRestore => "startup_restore",
            CommitSource::Rollback => "rollback",
            CommitSource::CommitConfirmedRestore => "commit_confirmed_restore",
        };

        conn.execute(
            r#"
            INSERT INTO config_history
                (tx_id, parent_tx_id, version, committed_at, principal, source,
                 schema_digest, plaintext_digest, encrypted_blob, rollback_point,
                 rollback_label, confirmed_deadline, audit_count, audit_terminal_hash)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 0, zeroblob(32))
            "#,
            params![
                &tx_id_bytes,
                parent_tx_id_bytes.as_deref(),
                record.version.get() as i64,
                record.committed_at.to_string(),
                &record.principal,
                source_str,
                record.schema_digest.as_bytes(),
                &record.plaintext_digest,
                &record.encrypted_blob,
                record.rollback_point as i32,
                rollback_label.as_deref(),
                record.confirmed_deadline.map(|t| t.to_string()),
            ],
        )
        .map_err(PersistError::from)?;

        if let Some(label) = rollback_label {
            conn.execute(
                "INSERT INTO rollback_labels (label, tx_id, created_at) VALUES (?1, ?2, ?3)",
                params![label, &tx_id_bytes, record.committed_at.to_string()],
            )
            .map_err(PersistError::from)?;
        }

        let tenant = crate::types::extract_tenant(&record.principal);
        let mut prev_hash = [0u8; 32];
        let mut audit = audit;
        let audit_count =
            u32::try_from(audit.len()).map_err(|_| PersistError::audit_chain_broken())?;

        // Insert audit records
        for entry in &mut audit {
            crate::types::redact_entry(
                &entry.yang_path,
                &mut entry.previous_value,
                &mut entry.redaction_applied,
            );
            crate::types::redact_entry(
                &entry.yang_path,
                &mut entry.new_value,
                &mut entry.redaction_applied,
            );

            entry.previous_hash = prev_hash;
            entry.entry_hmac =
                entry.calculate_hmac_with_audit_count(audit_key, &tenant, audit_count);
            prev_hash = entry.entry_hmac;

            let op_type_str = match entry.op_type {
                AuditOpType::Create => "CREATE",
                AuditOpType::Update => "UPDATE",
                AuditOpType::Replace => "REPLACE",
                AuditOpType::Delete => "DELETE",
            };

            conn.execute(
                r#"
                INSERT INTO audit_trail
                    (tx_id, sequence, yang_path, op_type, previous_value, new_value,
                     redaction_applied, previous_hash, entry_hmac)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                "#,
                params![
                    &tx_id_bytes,
                    entry.sequence as i32,
                    &entry.yang_path,
                    op_type_str,
                    &entry.previous_value,
                    &entry.new_value,
                    entry.redaction_applied as i32,
                    &entry.previous_hash[..],
                    &entry.entry_hmac[..],
                ],
            )
            .map_err(PersistError::from)?;
        }

        conn.execute(
            "UPDATE config_history SET audit_count = ?2, audit_terminal_hash = ?3 WHERE tx_id = ?1",
            params![&tx_id_bytes, audit_count as i64, &prev_hash[..]],
        )
        .map_err(PersistError::from)?;
        Ok(())
    }

    fn append_commit_impl(
        conn: &rusqlite::Connection,
        record: CommitRecord,
        audit: Vec<AuditRecord>,
        resolution: Option<ConfirmedCommitResolution>,
        audit_key: &AuditKey,
    ) -> Result<(), PersistError> {
        if !crate::types::config_principal_metadata_is_valid(&record.principal) {
            return Err(PersistError::constraint_violation(
                "config principal metadata is invalid",
            ));
        }
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| PersistError::sqlite(e.to_string()))?;

        let latest: Option<LatestConfigHeadRow> = tx
            .query_row(
                "SELECT tx_id, version, confirmed_deadline, confirmed_at, principal FROM config_history ORDER BY version DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()
            .map_err(|error| PersistError::sqlite(error.to_string()))?;
        match (&latest, record.parent_tx_id) {
            (None, None) => {}
            (Some((latest_tx_id, latest_version, _, _, _)), Some(parent_tx_id))
                if latest_tx_id.as_slice() == parent_tx_id.as_uuid().as_bytes()
                    && u64::try_from(*latest_version)
                        .ok()
                        .and_then(|version| version.checked_add(1))
                        == Some(record.version.get()) => {}
            _ => {
                return Err(PersistError::constraint_violation(
                    "config commit parent is not the applied head",
                ));
            }
        }

        if let Some((_, _, _, _, principal)) = &latest {
            if crate::types::config_recovery_required(principal)? {
                return Err(PersistError::constraint_violation(
                    "config publication fence must clear before another append",
                ));
            }
        }

        let latest_is_pending = latest
            .as_ref()
            .is_some_and(|(_, _, deadline, confirmed, _)| {
                deadline.is_some() && confirmed.is_none()
            });
        match (latest_is_pending, resolution) {
            (false, None) => {}
            (true, Some(ConfirmedCommitResolution::Rollback { pending_tx_id }))
                if record.parent_tx_id == Some(pending_tx_id)
                    && record.confirmed_deadline.is_none() => {}
            (true, Some(ConfirmedCommitResolution::Confirm { pending_tx_id }))
                if record.parent_tx_id == Some(pending_tx_id)
                    && record.confirmed_deadline.is_none() =>
            {
                let pending_tx_id = pending_tx_id.as_uuid().as_bytes().to_vec();
                let principal: String = tx
                    .query_row(
                        "SELECT principal FROM config_history WHERE tx_id = ?1",
                        [&pending_tx_id],
                        |row| row.get(0),
                    )
                    .map_err(|error| PersistError::sqlite(error.to_string()))?;
                let now = Timestamp::now_utc().to_string();
                let rows = tx
                    .execute(
                        "UPDATE config_history SET confirmed_at = ?1 WHERE tx_id = ?2 AND confirmed_deadline IS NOT NULL AND confirmed_at IS NULL",
                        params![&now, &pending_tx_id],
                    )
                    .map_err(|error| PersistError::sqlite(error.to_string()))?;
                if rows != 1 {
                    return Err(PersistError::constraint_violation(
                        "pending commit decision is no longer current",
                    ));
                }
                tx.execute(
                    "INSERT INTO config_lifecycle_audit (tx_id, action, principal, occurred_at, details) VALUES (?1, 'MARK_CONFIRMED', ?2, ?3, 'commit confirmed atomically with successor')",
                    params![&pending_tx_id, principal, &now],
                )
                .map_err(|error| PersistError::sqlite(error.to_string()))?;
            }
            _ => {
                return Err(PersistError::constraint_violation(
                    "pending commit requires one atomic current-parent decision",
                ));
            }
        }

        if let Some(digest) = crate::types::config_replay_lookup_digest(&record.principal)? {
            let duplicate: bool = tx
                .query_row(
                    r#"SELECT EXISTS(
                           SELECT 1 FROM config_history
                           WHERE CASE
                                   WHEN json_valid(principal)
                                   THEN json_extract(principal, '$.replay_lookup_digest')
                                   ELSE NULL
                                 END = ?1
                       )"#,
                    [&digest],
                    |row| row.get(0),
                )
                .map_err(|error| PersistError::sqlite(error.to_string()))?;
            if duplicate {
                return Err(PersistError::constraint_violation(
                    "config replay lookup digest is not unique",
                ));
            }
        }

        Self::append_commit_raw(&tx, record.clone(), audit, audit_key)?;

        tx.commit().map_err(|_| PersistError::outcome_unknown())?;
        Ok(())
    }

    pub(crate) fn load_by_tx_id_bytes(
        conn: &rusqlite::Connection,
        tx_id_bytes: &[u8],
        audit_key: &AuditKey,
    ) -> Result<Option<StoredConfig>, PersistError> {
        // Load raw column values first; do validation after so we can fail closed
        // on corrupt data rather than silently coercing.
        let (
            tx_id_out,
            parent_tx_id_out,
            version,
            committed_at_str,
            principal,
            source_str,
            schema_digest_bytes,
            plaintext_digest,
            encrypted_blob,
            rollback_point,
            _rollback_label,
            confirmed_deadline_str,
            confirmed_at,
            audit_count,
            audit_terminal_hash,
        ): StoredConfigRow = match conn.query_row(
            r#"
            SELECT tx_id, parent_tx_id, version, committed_at, principal, source,
                   schema_digest, plaintext_digest, encrypted_blob, rollback_point,
                   rollback_label, confirmed_deadline, confirmed_at,
                   audit_count, audit_terminal_hash
            FROM config_history
            WHERE tx_id = ?1
            "#,
            [tx_id_bytes],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, i32>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, Vec<u8>>(14)?,
                ))
            },
        ) {
            Ok(v) => v,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(PersistError::sqlite(e.to_string())),
        };

        // Fail closed: validate fixed-size fields
        if tx_id_out.len() != 16 {
            return Err(PersistError::corrupt_blob());
        }
        if schema_digest_bytes.len() != 32 {
            return Err(PersistError::corrupt_blob());
        }
        if audit_count < 0 {
            return Err(PersistError::inconsistent_state(
                "negative audit_count in config_history",
            ));
        }
        let audit_count =
            usize::try_from(audit_count).map_err(|_| PersistError::audit_chain_broken())?;
        if audit_terminal_hash.len() != 32 {
            return Err(PersistError::corrupt_blob());
        }
        let audit_terminal_hash: [u8; 32] = audit_terminal_hash
            .try_into()
            .expect("audit_terminal_hash length validated above");

        // Fail closed: validate timestamp
        let committed_at = Timestamp::from_str(&committed_at_str)
            .map_err(|_| PersistError::inconsistent_state("corrupt timestamp in config_history"))?;

        // Fail closed: validate CommitSource
        let source = deserialize_commit_source(&source_str)?;

        // Fail closed: validate parent_tx_id length (must be exactly 16 bytes if present)
        let parent_tx_id = match parent_tx_id_out {
            Some(ref b) => {
                validate_uuid_bytes("parent_tx_id", b)?;
                Some(TxId::from_uuid(uuid_from_bytes(b)))
            }
            None => None,
        };

        // Fail closed: validate version is non-negative and fits in u64
        let version = if version < 0 {
            return Err(PersistError::inconsistent_state(
                "negative version in config_history",
            ));
        } else {
            ConfigVersion::new(version as u64)
        };

        // Fail closed: confirmed_deadline must be parseable if present
        let mut confirmed_deadline = match confirmed_deadline_str {
            Some(s) => Some(Timestamp::from_str(&s).map_err(|_| {
                PersistError::inconsistent_state("corrupt confirmed_deadline in config_history")
            })?),
            None => None,
        };
        let confirmed_at = match confirmed_at {
            Some(s) => Some(Timestamp::from_str(&s).map_err(|_| {
                PersistError::inconsistent_state("corrupt confirmed_at in config_history")
            })?),
            None => None,
        };
        if confirmed_at.is_some() {
            confirmed_deadline = None;
        }

        let record = CommitRecord {
            tx_id: TxId::from_uuid(uuid_from_bytes(&tx_id_out)),
            parent_tx_id,
            version,
            committed_at,
            principal,
            source,
            schema_digest: SchemaDigest::from_bytes(
                schema_digest_bytes
                    .try_into()
                    .expect("schema_digest length validated above"),
            ),
            plaintext_digest,
            encrypted_blob,
            rollback_point: rollback_point != 0,
            confirmed_deadline,
        };
        if !crate::types::config_principal_metadata_is_valid(&record.principal) {
            return Err(PersistError::corrupt_blob());
        }

        // Load audit trail — use `query` to get rows, validate each in safe Rust,
        // and fail closed on corrupt data rather than silently dropping rows.
        let mut stmt = conn
            .prepare(
                r#"
                SELECT tx_id, sequence, yang_path, op_type, previous_value, new_value,
                       redaction_applied, previous_hash, entry_hmac
                FROM audit_trail
                WHERE tx_id = ?1
                ORDER BY sequence ASC
                "#,
            )
            .map_err(|e| PersistError::sqlite(e.to_string()))?;

        let mut rows = stmt
            .query([tx_id_bytes])
            .map_err(|e| PersistError::sqlite(e.to_string()))?;

        let mut audit = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| PersistError::sqlite(e.to_string()))?
        {
            let tx_id_bytes: Vec<u8> = row
                .get(0)
                .map_err(|e| PersistError::sqlite(e.to_string()))?;
            let sequence: u32 = row
                .get(1)
                .map_err(|e| PersistError::sqlite(e.to_string()))?;
            let yang_path: String = row
                .get(2)
                .map_err(|e| PersistError::sqlite(e.to_string()))?;
            let op_type: String = row
                .get(3)
                .map_err(|e| PersistError::sqlite(e.to_string()))?;
            let previous_value: Option<String> = row
                .get(4)
                .map_err(|e| PersistError::sqlite(e.to_string()))?;
            let new_value: Option<String> = row
                .get(5)
                .map_err(|e| PersistError::sqlite(e.to_string()))?;
            let redaction_applied: i32 = row
                .get(6)
                .map_err(|e| PersistError::sqlite(e.to_string()))?;
            let previous_hash: Vec<u8> = row
                .get(7)
                .map_err(|e| PersistError::sqlite(e.to_string()))?;
            let entry_hmac: Vec<u8> = row
                .get(8)
                .map_err(|e| PersistError::sqlite(e.to_string()))?;

            // Fail closed on corrupt fixed-size hash fields
            if previous_hash.len() != 32 {
                return Err(PersistError::corrupt_blob());
            }
            if entry_hmac.len() != 32 {
                return Err(PersistError::corrupt_blob());
            }

            // Validate audit tx_id length too
            validate_uuid_bytes("audit tx_id", &tx_id_bytes)?;

            audit.push(AuditRecord {
                tx_id: TxId::from_uuid(uuid_from_bytes(&tx_id_bytes)),
                sequence,
                yang_path,
                op_type: deserialize_audit_op_type(&op_type)?,
                previous_value,
                new_value,
                redaction_applied: redaction_applied != 0,
                previous_hash: previous_hash
                    .try_into()
                    .expect("previous_hash length validated above"),
                entry_hmac: entry_hmac
                    .try_into()
                    .expect("entry_hmac length validated above"),
            });
        }

        let stored = StoredConfig { record, audit };
        if stored.audit.len() != audit_count {
            return Err(PersistError::audit_chain_broken());
        }
        stored.verify_audit_chain(audit_key)?;
        let terminal_hash = stored
            .audit
            .last()
            .map(|entry| entry.entry_hmac)
            .unwrap_or([0u8; 32]);
        if terminal_hash != audit_terminal_hash {
            return Err(PersistError::audit_chain_broken());
        }
        Ok(Some(stored))
    }

    /// Records an alarm audit event.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_alarm_audit(
        &self,
        action: &str,
        outcome: &str,
        alarm_id: &str,
        alarm_type: &str,
        probable_cause: &str,
        principal: &str,
        tenant: Option<&str>,
        reason: &str,
        scope: &str,
        correlation_id: Option<&str>,
        occurred_at: &str,
    ) -> Result<(), PersistError> {
        #[cfg(feature = "dangerous-test-hooks")]
        if self
            .alarm_audit_write_fault
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(PersistError::sqlite(
                "alarm audit write fault injected".to_owned(),
            ));
        }
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO alarm_audit (action, outcome, alarm_id, alarm_type, probable_cause, principal, tenant, reason, scope, correlation_id, occurred_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                action,
                outcome,
                alarm_id,
                alarm_type,
                probable_cause,
                principal,
                tenant,
                reason,
                scope,
                correlation_id,
                occurred_at,
            ],
        )
        .map_err(|e| PersistError::sqlite(e.to_string()))?;
        Ok(())
    }

    /// Query recorded alarm audits, sorted by ID ascending.
    pub async fn query_alarm_audits(&self) -> Result<Vec<AlarmAuditEventRecord>, PersistError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn
            .prepare("SELECT action, outcome, alarm_id, alarm_type, probable_cause, principal, tenant, reason, scope, correlation_id, occurred_at FROM alarm_audit ORDER BY id ASC")
            .map_err(|e| PersistError::sqlite(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(AlarmAuditEventRecord {
                    action: row.get(0)?,
                    outcome: row.get(1)?,
                    alarm_id: row.get(2)?,
                    alarm_type: row.get(3)?,
                    probable_cause: row.get(4)?,
                    principal: row.get(5)?,
                    tenant: row.get(6)?,
                    reason: row.get(7)?,
                    scope: row.get(8)?,
                    correlation_id: row.get(9)?,
                    occurred_at: row.get(10)?,
                })
            })
            .map_err(|e| PersistError::sqlite(e.to_string()))?;

        let mut results = Vec::new();
        for r in rows {
            results.push(r.map_err(|e| PersistError::sqlite(e.to_string()))?);
        }
        Ok(results)
    }

    /// Inject an alarm-audit write failure without exposing database authority.
    #[cfg(feature = "dangerous-test-hooks")]
    pub fn inject_alarm_audit_write_failure_for_test(&self) {
        self.alarm_audit_write_fault
            .store(true, std::sync::atomic::Ordering::Release);
    }
}
