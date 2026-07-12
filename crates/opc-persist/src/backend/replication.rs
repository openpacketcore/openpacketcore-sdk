use rusqlite::params;
use std::sync::Arc;

use opc_types::Timestamp;

use crate::consensus::{ClusterMembership, ConsensusOp, LogEntry};
use crate::error::PersistError;
use crate::types::StoredConfig;

use super::SqliteBackend;

impl SqliteBackend {
    pub(crate) fn consensus_index_to_sqlite(index: u64) -> Result<i64, PersistError> {
        i64::try_from(index).map_err(|_| {
            PersistError::inconsistent_state("consensus log index exceeds SQLite integer range")
        })
    }

    pub(crate) fn consensus_term_to_sqlite(term: u64) -> Result<i64, PersistError> {
        i64::try_from(term).map_err(|_| {
            PersistError::inconsistent_state("consensus term exceeds SQLite integer range")
        })
    }

    pub(crate) fn consensus_node_id_to_sqlite(node_id: usize) -> Result<i64, PersistError> {
        i64::try_from(node_id).map_err(|_| {
            PersistError::inconsistent_state("consensus node id exceeds SQLite integer range")
        })
    }

    fn consensus_node_id_from_sqlite(node_id: i64) -> Result<usize, PersistError> {
        usize::try_from(node_id)
            .map_err(|_| PersistError::inconsistent_state("negative consensus node id in SQLite"))
    }

    fn membership_epoch_to_sqlite(epoch: u64) -> Result<i64, PersistError> {
        i64::try_from(epoch).map_err(|_| {
            PersistError::inconsistent_state(
                "consensus membership epoch exceeds SQLite integer range",
            )
        })
    }

    fn membership_epoch_from_sqlite(epoch: i64) -> Result<u64, PersistError> {
        u64::try_from(epoch).map_err(|_| {
            PersistError::inconsistent_state("negative consensus membership epoch in SQLite")
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn membership_from_sqlite_parts(
        cluster_id: String,
        node_id: i64,
        voting_members: String,
        non_voting_members: String,
        old_voting_members: Option<String>,
        removed_members: String,
        epoch: i64,
    ) -> Result<ClusterMembership, PersistError> {
        let invalid = || PersistError::inconsistent_state("invalid consensus membership in SQLite");
        Ok(ClusterMembership {
            cluster_id,
            node_id: Self::consensus_node_id_from_sqlite(node_id)?,
            voting_members: serde_json::from_str(&voting_members).map_err(|_| invalid())?,
            non_voting_members: serde_json::from_str(&non_voting_members).map_err(|_| invalid())?,
            old_voting_members: old_voting_members
                .map(|members| serde_json::from_str(&members).map_err(|_| invalid()))
                .transpose()?,
            removed_members: serde_json::from_str(&removed_members).map_err(|_| invalid())?,
            epoch: Self::membership_epoch_from_sqlite(epoch)?,
        })
    }

    fn consensus_index_from_sqlite(index: i64) -> Result<u64, PersistError> {
        u64::try_from(index)
            .map_err(|_| PersistError::inconsistent_state("negative consensus log index in SQLite"))
    }

    fn consensus_term_from_sqlite(term: i64) -> Result<u64, PersistError> {
        u64::try_from(term)
            .map_err(|_| PersistError::inconsistent_state("negative consensus term in SQLite"))
    }

    /// Return whether `entries` exactly match one bounded contiguous local log range.
    ///
    /// The caller supplies the range, so this never reads an unbounded log tail.
    /// Missing (including compacted) entries fail closed as a mismatch.
    pub(crate) async fn consensus_log_entries_match(
        &self,
        prev_index: u64,
        entries: &[LogEntry],
    ) -> Result<bool, PersistError> {
        let mut expected_index = prev_index
            .checked_add(1)
            .ok_or_else(|| PersistError::inconsistent_state("consensus log index overflow"))?;
        for entry in entries {
            if entry.index != expected_index {
                return Err(PersistError::inconsistent_state(
                    "non-contiguous consensus log replay",
                ));
            }
            expected_index = expected_index
                .checked_add(1)
                .ok_or_else(|| PersistError::inconsistent_state("consensus log index overflow"))?;
        }

        let Some(last_entry) = entries.last() else {
            return Ok(true);
        };
        let first_index = i64::try_from(entries[0].index).map_err(|_| {
            PersistError::inconsistent_state("consensus log index exceeds SQLite integer range")
        })?;
        let last_index = i64::try_from(last_entry.index).map_err(|_| {
            PersistError::inconsistent_state("consensus log index exceeds SQLite integer range")
        })?;

        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        let mut stmt = guard
            .prepare(
                "SELECT log_index, term, payload FROM consensus_log \
                 WHERE log_index >= ?1 AND log_index <= ?2 ORDER BY log_index ASC",
            )
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        let mut rows = stmt
            .query(params![first_index, last_index])
            .map_err(|e| PersistError::sqlite(e.to_string()))?;

        for expected in entries {
            let Some(row) = rows
                .next()
                .map_err(|e| PersistError::sqlite(e.to_string()))?
            else {
                return Ok(false);
            };
            let index = u64::try_from(row.get::<_, i64>(0)?).map_err(|_| {
                PersistError::inconsistent_state("negative consensus log index in SQLite")
            })?;
            let term = u64::try_from(row.get::<_, i64>(1)?).map_err(|_| {
                PersistError::inconsistent_state("negative consensus log term in SQLite")
            })?;
            let payload = row.get::<_, String>(2)?;
            let op: ConsensusOp = serde_json::from_str(&payload)
                .map_err(|e| PersistError::inconsistent_state(e.to_string()))?;
            let actual = LogEntry { index, term, op };
            if actual != *expected {
                return Ok(false);
            }
        }

        Ok(rows
            .next()
            .map_err(|e| PersistError::sqlite(e.to_string()))?
            .is_none())
    }

    pub async fn consensus_get_state(&self) -> Result<(u64, Option<usize>), PersistError> {
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        let mut stmt = guard
            .prepare("SELECT current_term, voted_for FROM consensus_state LIMIT 1")
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        let mut rows = stmt
            .query([])
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        if let Some(row) = rows
            .next()
            .map_err(|e| PersistError::sqlite(e.to_string()))?
        {
            let term: i64 = row.get(0)?;
            let voted_for: Option<i64> = row.get(1)?;
            let term = Self::consensus_term_from_sqlite(term)?;
            let voted_for = voted_for
                .map(|node_id| {
                    usize::try_from(node_id).map_err(|_| {
                        PersistError::inconsistent_state("negative consensus node id in SQLite")
                    })
                })
                .transpose()?;
            Ok((term, voted_for))
        } else {
            Ok((0, None))
        }
    }

    pub async fn consensus_set_state(
        &self,
        term: u64,
        voted_for: Option<usize>,
    ) -> Result<(), PersistError> {
        let term = Self::consensus_term_to_sqlite(term)?;
        let voted_for = voted_for
            .map(Self::consensus_node_id_to_sqlite)
            .transpose()?;
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        guard
            .execute(
                "INSERT OR REPLACE INTO consensus_state (node_id, current_term, voted_for) VALUES (1, ?1, ?2)",
                params![term, voted_for],
            )
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        Ok(())
    }

    pub async fn consensus_get_last_log(&self) -> Result<(u64, u64), PersistError> {
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;

        let log_res = guard.query_row(
            "SELECT log_index, term FROM consensus_log ORDER BY log_index DESC LIMIT 1",
            [],
            |row| {
                let index: i64 = row.get(0)?;
                let term: i64 = row.get(1)?;
                Ok((index, term))
            },
        );
        match log_res {
            Ok((index, term)) => Ok((
                Self::consensus_index_from_sqlite(index)?,
                Self::consensus_term_from_sqlite(term)?,
            )),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                let snap_res = guard.query_row(
                    "SELECT snapshot_index, snapshot_term FROM consensus_snapshot WHERE id = 1",
                    [],
                    |row| {
                        let index: i64 = row.get(0)?;
                        let term: i64 = row.get(1)?;
                        Ok((index, term))
                    },
                );
                match snap_res {
                    Ok((index, term)) => Ok((
                        Self::consensus_index_from_sqlite(index)?,
                        Self::consensus_term_from_sqlite(term)?,
                    )),
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok((0, 0)),
                    Err(e) => Err(PersistError::sqlite(e.to_string())),
                }
            }
            Err(e) => Err(PersistError::sqlite(e.to_string())),
        }
    }

    pub async fn consensus_get_log_term(&self, index: u64) -> Result<Option<u64>, PersistError> {
        let index = Self::consensus_index_to_sqlite(index)?;
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;

        let log_res = guard.query_row(
            "SELECT term FROM consensus_log WHERE log_index = ?1",
            params![index],
            |row| {
                let term: i64 = row.get(0)?;
                Ok(term)
            },
        );
        match log_res {
            Ok(term) => Ok(Some(Self::consensus_term_from_sqlite(term)?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                let snap_res = guard.query_row(
                    "SELECT snapshot_term FROM consensus_snapshot WHERE id = 1 AND snapshot_index = ?1",
                    params![index],
                    |row| {
                        let term: i64 = row.get(0)?;
                        Ok(term)
                    },
                );
                match snap_res {
                    Ok(term) => Ok(Some(Self::consensus_term_from_sqlite(term)?)),
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(PersistError::sqlite(e.to_string())),
                }
            }
            Err(e) => Err(PersistError::sqlite(e.to_string())),
        }
    }

    pub async fn consensus_append_logs(
        &self,
        prev_index: u64,
        entries: Vec<LogEntry>,
    ) -> Result<(), PersistError> {
        if entries.is_empty() {
            return Ok(());
        }

        let prev_index_sql = Self::consensus_index_to_sqlite(prev_index)?;
        let mut expected_index = prev_index
            .checked_add(1)
            .ok_or_else(|| PersistError::inconsistent_state("consensus log index overflow"))?;
        for entry in &entries {
            if entry.index != expected_index {
                return Err(PersistError::inconsistent_state(
                    "non-contiguous consensus log append",
                ));
            }
            expected_index = expected_index
                .checked_add(1)
                .ok_or_else(|| PersistError::inconsistent_state("consensus log index overflow"))?;
            i64::try_from(entry.index).map_err(|_| {
                PersistError::inconsistent_state("consensus log index exceeds SQLite integer range")
            })?;
            i64::try_from(entry.term).map_err(|_| {
                PersistError::inconsistent_state("consensus log term exceeds SQLite integer range")
            })?;
        }

        let conn = Arc::clone(&self.conn);
        let mut guard = conn.lock_owned().await;

        let applied_index: i64 = guard
            .query_row(
                "SELECT applied_index FROM consensus_applied WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        let applied_index = u64::try_from(applied_index).map_err(|_| {
            PersistError::inconsistent_state("negative applied consensus index in SQLite")
        })?;
        if prev_index < applied_index {
            return Err(PersistError::inconsistent_state(
                "cannot overwrite applied consensus log",
            ));
        }

        let tx = guard
            .transaction()
            .map_err(|e| PersistError::sqlite(e.to_string()))?;

        tx.execute(
            "DELETE FROM consensus_log WHERE log_index > ?1",
            params![prev_index_sql],
        )
        .map_err(|e| PersistError::sqlite(e.to_string()))?;

        for entry in entries {
            let payload = serde_json::to_string(&entry.op)
                .map_err(|e| PersistError::inconsistent_state(e.to_string()))?;
            let entry_index = i64::try_from(entry.index).map_err(|_| {
                PersistError::inconsistent_state("consensus log index exceeds SQLite integer range")
            })?;
            let entry_term = i64::try_from(entry.term).map_err(|_| {
                PersistError::inconsistent_state("consensus log term exceeds SQLite integer range")
            })?;
            tx.execute(
                "INSERT OR REPLACE INTO consensus_log (log_index, term, op_type, payload) VALUES (?1, ?2, ?3, ?4)",
                params![entry_index, entry_term, entry.op_name(), payload],
            ).map_err(|e| PersistError::sqlite(e.to_string()))?;
        }

        tx.commit()
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        Ok(())
    }

    pub async fn consensus_truncate_unapplied_after(&self, index: u64) -> Result<(), PersistError> {
        let index_sql = Self::consensus_index_to_sqlite(index)?;
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        let applied_index: i64 = guard
            .query_row(
                "SELECT applied_index FROM consensus_applied WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|e| PersistError::sqlite(e.to_string()))?;

        let applied_index = Self::consensus_index_from_sqlite(applied_index)?;
        if index < applied_index {
            return Err(PersistError::inconsistent_state(
                "cannot truncate applied consensus log",
            ));
        }

        guard
            .execute(
                "DELETE FROM consensus_log WHERE log_index > ?1",
                params![index_sql],
            )
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        Ok(())
    }

    pub async fn consensus_get_entries(
        &self,
        start_index: u64,
    ) -> Result<Vec<LogEntry>, PersistError> {
        let start_index = Self::consensus_index_to_sqlite(start_index)?;
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        let mut stmt = guard
            .prepare("SELECT log_index, term, payload FROM consensus_log WHERE log_index >= ?1 ORDER BY log_index ASC")
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        let rows = stmt
            .query_map(params![start_index], |row| {
                let index: i64 = row.get(0)?;
                let term: i64 = row.get(1)?;
                let payload_str: String = row.get(2)?;
                Ok((index, term, payload_str))
            })
            .map_err(|e| PersistError::sqlite(e.to_string()))?;

        let mut entries = Vec::new();
        for r in rows {
            let (index, term, payload_str) = r.map_err(|e| PersistError::sqlite(e.to_string()))?;
            let op: ConsensusOp = serde_json::from_str(&payload_str)
                .map_err(|e| PersistError::inconsistent_state(e.to_string()))?;
            entries.push(LogEntry {
                index: Self::consensus_index_from_sqlite(index)?,
                term: Self::consensus_term_from_sqlite(term)?,
                op,
            });
        }
        Ok(entries)
    }

    pub async fn consensus_get_applied_index(&self) -> Result<u64, PersistError> {
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        let mut stmt = guard
            .prepare("SELECT applied_index FROM consensus_applied WHERE id = 1")
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        let mut rows = stmt
            .query([])
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        if let Some(row) = rows
            .next()
            .map_err(|e| PersistError::sqlite(e.to_string()))?
        {
            let applied: i64 = row.get(0)?;
            Self::consensus_index_from_sqlite(applied)
        } else {
            Ok(0)
        }
    }

    pub async fn consensus_apply_entries(&self, commit_index: u64) -> Result<(), PersistError> {
        let commit_index_sql = Self::consensus_index_to_sqlite(commit_index)?;
        let conn = Arc::clone(&self.conn);
        let mut guard = conn.lock_owned().await;

        let rows = {
            let applied_index: i64 = guard
                .query_row(
                    "SELECT applied_index FROM consensus_applied WHERE id = 1",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| PersistError::sqlite(e.to_string()))?;

            let applied_index_unsigned = Self::consensus_index_from_sqlite(applied_index)?;
            if commit_index <= applied_index_unsigned {
                return Ok(());
            }

            let mut stmt = guard
                .prepare("SELECT log_index, payload FROM consensus_log WHERE log_index > ?1 AND log_index <= ?2 ORDER BY log_index ASC")
                .map_err(|e| PersistError::sqlite(e.to_string()))?;

            let rows_iter = stmt
                .query_map(params![applied_index, commit_index_sql], |row| {
                    let idx: i64 = row.get(0)?;
                    let payload: String = row.get(1)?;
                    Ok((idx, payload))
                })
                .map_err(|e| PersistError::sqlite(e.to_string()))?;

            let mut temp_rows = Vec::new();
            for r in rows_iter {
                temp_rows.push(r.map_err(|e| PersistError::sqlite(e.to_string()))?);
            }
            temp_rows
        };

        let tx = guard
            .transaction()
            .map_err(|e| PersistError::sqlite(e.to_string()))?;

        for (idx, payload_str) in rows {
            let op: ConsensusOp = serde_json::from_str(&payload_str)
                .map_err(|e| PersistError::inconsistent_state(e.to_string()))?;

            match op {
                ConsensusOp::AppendCommit { record, audit } => {
                    Self::append_commit_raw(&tx, record, audit, self.audit_key.as_ref())?;
                }
                ConsensusOp::MarkConfirmed { tx_id } => {
                    let tx_id_bytes = tx_id.as_uuid().as_bytes().to_vec();
                    let now = Timestamp::now_utc().to_string();
                    let rows = tx
                        .execute(
                            "UPDATE config_history SET confirmed_at = ?1 WHERE tx_id = ?2",
                            params![now, &tx_id_bytes],
                        )
                        .map_err(|e| PersistError::sqlite(e.to_string()))?;
                    if rows == 0 {
                        // The target tx may have been compacted away or never
                        // applied on this node (e.g. restored from an older
                        // snapshot). A committed entry must apply
                        // deterministically and must never wedge the state
                        // machine, so a missing target is a no-op here, not an
                        // error. (The user-facing confirm path still validates
                        // and rejects unknown tx_ids before proposing.)
                        tracing::warn!(
                            log_index = idx,
                            "consensus apply: MarkConfirmed for unknown tx_id; skipping"
                        );
                    }
                }
                ConsensusOp::CreateRollbackPoint { tx_id, label } => {
                    let tx_id_bytes = tx_id.as_uuid().as_bytes().to_vec();
                    let rows = tx
                        .execute(
                            "UPDATE config_history SET rollback_point = 1 WHERE tx_id = ?1",
                            params![&tx_id_bytes],
                        )
                        .map_err(|e| PersistError::sqlite(e.to_string()))?;
                    if rows == 0 {
                        // Missing target: deterministic no-op (see MarkConfirmed
                        // above). Skip the label insert too so it never points
                        // at a non-existent tx_id.
                        tracing::warn!(
                            log_index = idx,
                            "consensus apply: CreateRollbackPoint for unknown tx_id; skipping"
                        );
                    } else if let Some(lbl) = &label {
                        tx.execute(
                            "INSERT OR REPLACE INTO rollback_labels (label, tx_id, created_at) VALUES (?1, ?2, ?3)",
                            params![lbl, &tx_id_bytes, Timestamp::now_utc().to_string()],
                        ).map_err(|e| PersistError::sqlite(e.to_string()))?;
                    }
                }
                ConsensusOp::ChangeMembership { membership } => {
                    let voting_members_str = serde_json::to_string(&membership.voting_members)
                        .map_err(|e| PersistError::inconsistent_state(e.to_string()))?;
                    let non_voting_members_str =
                        serde_json::to_string(&membership.non_voting_members)
                            .map_err(|e| PersistError::inconsistent_state(e.to_string()))?;
                    let old_voting_members_str = membership
                        .old_voting_members
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()
                        .map_err(|e| PersistError::inconsistent_state(e.to_string()))?;
                    let removed_members_str = serde_json::to_string(&membership.removed_members)
                        .map_err(|e| PersistError::inconsistent_state(e.to_string()))?;
                    let membership_node_id = Self::consensus_node_id_to_sqlite(membership.node_id)?;
                    let membership_epoch = Self::membership_epoch_to_sqlite(membership.epoch)?;

                    let local_node_id = match tx.query_row(
                        "SELECT node_id FROM consensus_membership WHERE id = 1",
                        [],
                        |row| row.get::<_, i64>(0),
                    ) {
                        Ok(node_id) => {
                            Self::consensus_node_id_from_sqlite(node_id)?;
                            node_id
                        }
                        Err(rusqlite::Error::QueryReturnedNoRows) => membership_node_id,
                        Err(e) => return Err(PersistError::sqlite(e.to_string())),
                    };

                    let current_epoch = match tx.query_row(
                        "SELECT epoch FROM consensus_membership WHERE id = 1",
                        [],
                        |row| row.get::<_, i64>(0),
                    ) {
                        Ok(epoch) => Self::membership_epoch_from_sqlite(epoch)?,
                        Err(rusqlite::Error::QueryReturnedNoRows) => 0,
                        Err(e) => return Err(PersistError::sqlite(e.to_string())),
                    };
                    if membership.epoch <= current_epoch {
                        return Err(PersistError::inconsistent_state("stale epoch"));
                    }

                    tx.execute(
                        "INSERT OR REPLACE INTO consensus_membership (id, cluster_id, node_id, voting_members, non_voting_members, old_voting_members, removed_members, epoch) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![
                            &membership.cluster_id,
                            local_node_id,
                            voting_members_str,
                            non_voting_members_str,
                            old_voting_members_str,
                            removed_members_str,
                            membership_epoch
                        ],
                    ).map_err(|e| PersistError::sqlite(e.to_string()))?;
                }
                ConsensusOp::NoOp => {}
            }

            tx.execute(
                "UPDATE consensus_applied SET applied_index = ?1 WHERE id = 1",
                params![idx],
            )
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        }

        tx.commit()
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        Ok(())
    }

    pub async fn consensus_get_membership(
        &self,
    ) -> Result<Option<ClusterMembership>, PersistError> {
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        let mut stmt = guard
            .prepare("SELECT cluster_id, node_id, voting_members, non_voting_members, old_voting_members, removed_members, epoch FROM consensus_membership WHERE id = 1")
            .map_err(|e| PersistError::sqlite(e.to_string()))?;

        let res = stmt.query_row([], |row| {
            let cluster_id: String = row.get(0)?;
            let node_id: i64 = row.get(1)?;
            let voting_members_str: String = row.get(2)?;
            let non_voting_members_str: String = row.get(3)?;
            let old_voting_members_str: Option<String> = row.get(4)?;
            let removed_members_str: String = row.get(5)?;
            let epoch: i64 = row.get(6)?;
            Ok((
                cluster_id,
                node_id,
                voting_members_str,
                non_voting_members_str,
                old_voting_members_str,
                removed_members_str,
                epoch,
            ))
        });

        match res {
            Ok((
                cluster_id,
                node_id,
                voting_members_str,
                non_voting_members_str,
                old_voting_members_str,
                removed_members_str,
                epoch,
            )) => Ok(Some(Self::membership_from_sqlite_parts(
                cluster_id,
                node_id,
                voting_members_str,
                non_voting_members_str,
                old_voting_members_str,
                removed_members_str,
                epoch,
            )?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(PersistError::sqlite(e.to_string())),
        }
    }

    pub async fn consensus_get_active_membership(
        &self,
    ) -> Result<Option<ClusterMembership>, PersistError> {
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;

        let log_membership = match guard.query_row(
            "SELECT payload FROM consensus_log WHERE op_type = 'CHANGE_MEMBERSHIP' ORDER BY log_index DESC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        ) {
            Ok(payload) => match serde_json::from_str::<ConsensusOp>(&payload) {
                Ok(ConsensusOp::ChangeMembership { membership }) => Some(membership),
                _ => {
                    return Err(PersistError::inconsistent_state(
                        "invalid consensus membership log entry",
                    ))
                }
            },
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(error) => return Err(PersistError::sqlite(error.to_string())),
        };

        let mut statement = guard
            .prepare("SELECT cluster_id, node_id, voting_members, non_voting_members, old_voting_members, removed_members, epoch FROM consensus_membership WHERE id = 1")
            .map_err(|error| PersistError::sqlite(error.to_string()))?;
        let table_row = statement.query_row([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
            ))
        });
        let table_membership = match table_row {
            Ok((cluster, node, voters, non_voters, old_voters, removed, epoch)) => {
                Some(Self::membership_from_sqlite_parts(
                    cluster, node, voters, non_voters, old_voters, removed, epoch,
                )?)
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(error) => return Err(PersistError::sqlite(error.to_string())),
        };

        let active = match (log_membership, table_membership) {
            (Some(log_m), Some(table_m)) => {
                if table_m.epoch > log_m.epoch {
                    Some(table_m)
                } else {
                    Some(log_m)
                }
            }
            (Some(log_m), None) => Some(log_m),
            (None, Some(table_m)) => Some(table_m),
            (None, None) => None,
        };

        if let Some(m) = active {
            let local_node_id = match guard.query_row(
                "SELECT node_id FROM consensus_membership WHERE id = 1",
                [],
                |row| row.get::<_, i64>(0),
            ) {
                Ok(node_id) => Self::consensus_node_id_from_sqlite(node_id)?,
                Err(rusqlite::Error::QueryReturnedNoRows) => m.node_id,
                Err(error) => return Err(PersistError::sqlite(error.to_string())),
            };
            let mut m_clone = m;
            m_clone.node_id = local_node_id;
            return Ok(Some(m_clone));
        }

        Ok(None)
    }

    pub async fn consensus_get_active_membership_at(
        &self,
        idx: u64,
    ) -> Result<Option<ClusterMembership>, PersistError> {
        let idx = Self::consensus_index_to_sqlite(idx)?;
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;

        let log_membership = match guard.query_row(
            "SELECT payload FROM consensus_log WHERE op_type = 'CHANGE_MEMBERSHIP' AND log_index <= ?1 ORDER BY log_index DESC LIMIT 1",
            params![idx],
            |row| row.get::<_, String>(0),
        ) {
            Ok(payload) => match serde_json::from_str::<ConsensusOp>(&payload) {
                Ok(ConsensusOp::ChangeMembership { membership }) => Some(membership),
                _ => {
                    return Err(PersistError::inconsistent_state(
                        "invalid consensus membership log entry",
                    ))
                }
            },
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(error) => return Err(PersistError::sqlite(error.to_string())),
        };

        let mut statement = guard
            .prepare("SELECT cluster_id, node_id, voting_members, non_voting_members, old_voting_members, removed_members, epoch FROM consensus_membership WHERE id = 1")
            .map_err(|error| PersistError::sqlite(error.to_string()))?;
        let table_row = statement.query_row([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
            ))
        });
        let table_membership = match table_row {
            Ok((cluster, node, voters, non_voters, old_voters, removed, epoch)) => {
                Some(Self::membership_from_sqlite_parts(
                    cluster, node, voters, non_voters, old_voters, removed, epoch,
                )?)
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(error) => return Err(PersistError::sqlite(error.to_string())),
        };

        let active = match (log_membership, table_membership) {
            (Some(log_m), Some(table_m)) => {
                if table_m.epoch > log_m.epoch {
                    Some(table_m)
                } else {
                    Some(log_m)
                }
            }
            (Some(log_m), None) => Some(log_m),
            (None, Some(table_m)) => Some(table_m),
            (None, None) => None,
        };

        if let Some(m) = active {
            let local_node_id = match guard.query_row(
                "SELECT node_id FROM consensus_membership WHERE id = 1",
                [],
                |row| row.get::<_, i64>(0),
            ) {
                Ok(node_id) => Self::consensus_node_id_from_sqlite(node_id)?,
                Err(rusqlite::Error::QueryReturnedNoRows) => m.node_id,
                Err(error) => return Err(PersistError::sqlite(error.to_string())),
            };
            let mut m_clone = m;
            m_clone.node_id = local_node_id;
            return Ok(Some(m_clone));
        }

        Ok(None)
    }

    pub async fn consensus_set_membership(
        &self,
        membership: &ClusterMembership,
    ) -> Result<(), PersistError> {
        let voting_members_str = serde_json::to_string(&membership.voting_members)
            .map_err(|e| PersistError::inconsistent_state(e.to_string()))?;
        let non_voting_members_str = serde_json::to_string(&membership.non_voting_members)
            .map_err(|e| PersistError::inconsistent_state(e.to_string()))?;
        let old_voting_members_str = membership
            .old_voting_members
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| PersistError::inconsistent_state(e.to_string()))?;
        let removed_members_str = serde_json::to_string(&membership.removed_members)
            .map_err(|e| PersistError::inconsistent_state(e.to_string()))?;
        let membership_node_id = Self::consensus_node_id_to_sqlite(membership.node_id)?;
        let membership_epoch = Self::membership_epoch_to_sqlite(membership.epoch)?;

        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;

        let local_node_id = match guard.query_row(
            "SELECT node_id FROM consensus_membership WHERE id = 1",
            [],
            |row| row.get::<_, i64>(0),
        ) {
            Ok(node_id) => {
                if Self::consensus_node_id_from_sqlite(node_id)? != membership.node_id {
                    return Err(PersistError::inconsistent_state("node_id mismatch"));
                }
                node_id
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => membership_node_id,
            Err(e) => return Err(PersistError::sqlite(e.to_string())),
        };

        guard.execute(
            "INSERT OR REPLACE INTO consensus_membership (id, cluster_id, node_id, voting_members, non_voting_members, old_voting_members, removed_members, epoch) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                &membership.cluster_id,
                local_node_id,
                &voting_members_str,
                &non_voting_members_str,
                old_voting_members_str,
                removed_members_str,
                membership_epoch
            ]
        ).map_err(|e| PersistError::sqlite(e.to_string()))?;
        Ok(())
    }

    pub async fn consensus_get_snapshot(
        &self,
    ) -> Result<Option<(u64, u64, Vec<u8>)>, PersistError> {
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        let mut stmt = guard
            .prepare("SELECT snapshot_index, snapshot_term, snapshot_data FROM consensus_snapshot WHERE id = 1")
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        let res = stmt.query_row([], |row| {
            let index: i64 = row.get(0)?;
            let term: i64 = row.get(1)?;
            let data: Vec<u8> = row.get(2)?;
            Ok((index, term, data))
        });
        match res {
            Ok((index, term, data)) => Ok(Some((
                Self::consensus_index_from_sqlite(index)?,
                Self::consensus_term_from_sqlite(term)?,
                data,
            ))),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(PersistError::sqlite(e.to_string())),
        }
    }

    pub async fn consensus_set_snapshot(
        &self,
        index: u64,
        term: u64,
        data: &[u8],
    ) -> Result<(), PersistError> {
        // Validate every signed SQLite coordinate before opening a
        // transaction so a hostile wire value cannot wrap and partially
        // advance the durable snapshot/applied markers.
        let index_sql = Self::consensus_index_to_sqlite(index)?;
        let term_sql = Self::consensus_term_to_sqlite(term)?;
        let conn = Arc::clone(&self.conn);
        let mut guard = conn.lock_owned().await;

        let tx = guard
            .transaction()
            .map_err(|e| PersistError::sqlite(e.to_string()))?;

        tx.execute(
            "INSERT OR REPLACE INTO consensus_snapshot (id, snapshot_index, snapshot_term, snapshot_data) VALUES (1, ?1, ?2, ?3)",
            params![index_sql, term_sql, data]
        ).map_err(|e| PersistError::sqlite(e.to_string()))?;

        tx.execute(
            "UPDATE consensus_applied SET applied_index = max(applied_index, ?1) WHERE id = 1",
            params![index_sql],
        )
        .map_err(|e| PersistError::sqlite(e.to_string()))?;

        tx.commit()
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        Ok(())
    }

    pub async fn consensus_compact_logs(&self, up_to_index: u64) -> Result<(), PersistError> {
        let up_to_index_sql = Self::consensus_index_to_sqlite(up_to_index)?;
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        let applied_index: i64 = guard
            .query_row(
                "SELECT applied_index FROM consensus_applied WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        let applied_index = u64::try_from(applied_index).map_err(|_| {
            PersistError::inconsistent_state("negative applied consensus index in SQLite")
        })?;
        if up_to_index > applied_index {
            return Err(PersistError::inconsistent_state(
                "cannot compact unapplied logs",
            ));
        }

        guard
            .execute(
                "DELETE FROM consensus_log WHERE log_index <= ?1",
                params![up_to_index_sql],
            )
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        Ok(())
    }

    /// Atomically install every durable component carried by a verified Raft snapshot.
    ///
    /// The caller is responsible for authenticating the snapshot payload. This method
    /// validates every value that crosses SQLite's signed-integer boundary before it
    /// starts changing state, preserves the backend's local node identity, and commits
    /// the configuration, audit trail, membership, snapshot marker, applied index, and
    /// log compaction as one transaction.
    pub(crate) async fn consensus_install_snapshot_bundle(
        &self,
        config: StoredConfig,
        membership: &ClusterMembership,
        index: u64,
        term: u64,
        data: &[u8],
    ) -> Result<(), PersistError> {
        let index_sql = Self::consensus_index_to_sqlite(index)?;
        let term_sql = Self::consensus_term_to_sqlite(term)?;
        let membership_node_id = Self::consensus_node_id_to_sqlite(membership.node_id)?;
        let membership_epoch = i64::try_from(membership.epoch).map_err(|_| {
            PersistError::inconsistent_state(
                "consensus membership epoch exceeds SQLite integer range",
            )
        })?;
        i64::try_from(config.record.version.get()).map_err(|_| {
            PersistError::inconsistent_state("config version exceeds SQLite integer range")
        })?;
        u32::try_from(config.audit.len())
            .map_err(|_| PersistError::inconsistent_state("snapshot audit count exceeds range"))?;
        for audit in &config.audit {
            i32::try_from(audit.sequence).map_err(|_| {
                PersistError::inconsistent_state("audit sequence exceeds SQLite integer range")
            })?;
        }

        // Serialize before taking the connection lock so serialization failure cannot
        // occur after the transaction has begun staging destructive replacement work.
        let voting_members = serde_json::to_string(&membership.voting_members)
            .map_err(|e| PersistError::inconsistent_state(e.to_string()))?;
        let non_voting_members = serde_json::to_string(&membership.non_voting_members)
            .map_err(|e| PersistError::inconsistent_state(e.to_string()))?;
        let old_voting_members = membership
            .old_voting_members
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| PersistError::inconsistent_state(e.to_string()))?;
        let removed_members = serde_json::to_string(&membership.removed_members)
            .map_err(|e| PersistError::inconsistent_state(e.to_string()))?;

        let conn = Arc::clone(&self.conn);
        let mut guard = conn.lock_owned().await;
        let tx = guard
            .transaction()
            .map_err(|e| PersistError::sqlite(e.to_string()))?;

        let local_node_id = match tx.query_row(
            "SELECT node_id FROM consensus_membership WHERE id = 1",
            [],
            |row| row.get::<_, i64>(0),
        ) {
            Ok(node_id) => {
                let node_id = usize::try_from(node_id).map_err(|_| {
                    PersistError::inconsistent_state(
                        "negative consensus node id in SQLite membership",
                    )
                })?;
                if node_id != membership.node_id {
                    return Err(PersistError::inconsistent_state("node_id mismatch"));
                }
                Self::consensus_node_id_to_sqlite(node_id)?
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => membership_node_id,
            Err(e) => return Err(PersistError::sqlite(e.to_string())),
        };

        let applied_index_sql = tx
            .query_row(
                "SELECT applied_index FROM consensus_applied WHERE id = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        let applied_index = Self::consensus_index_from_sqlite(applied_index_sql)?;
        if index <= applied_index {
            return Err(PersistError::inconsistent_state(
                "snapshot install must advance applied consensus state",
            ));
        }

        // Raft permits retaining the suffix only when the follower already
        // has the exact snapshot boundary entry. If that index is absent or
        // has another term, the suffix belongs to an unproven fork and must be
        // discarded with the prefix.
        let retain_log_suffix = match tx.query_row(
            "SELECT term FROM consensus_log WHERE log_index = ?1",
            params![index_sql],
            |row| row.get::<_, i64>(0),
        ) {
            Ok(local_term) => Self::consensus_term_from_sqlite(local_term)? == term,
            Err(rusqlite::Error::QueryReturnedNoRows) => false,
            Err(error) => return Err(PersistError::sqlite(error.to_string())),
        };

        tx.execute("DELETE FROM audit_trail", [])
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        tx.execute("DELETE FROM config_lifecycle_audit", [])
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        tx.execute("DELETE FROM rollback_labels", [])
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        tx.execute("DELETE FROM config_history", [])
            .map_err(|e| PersistError::sqlite(e.to_string()))?;

        Self::append_commit_raw(&tx, config.record, config.audit, self.audit_key.as_ref())?;

        tx.execute(
            "INSERT OR REPLACE INTO consensus_membership (id, cluster_id, node_id, voting_members, non_voting_members, old_voting_members, removed_members, epoch) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                &membership.cluster_id,
                local_node_id,
                voting_members,
                non_voting_members,
                old_voting_members,
                removed_members,
                membership_epoch,
            ],
        )
        .map_err(|e| PersistError::sqlite(e.to_string()))?;

        tx.execute(
            "INSERT OR REPLACE INTO consensus_snapshot (id, snapshot_index, snapshot_term, snapshot_data) VALUES (1, ?1, ?2, ?3)",
            params![index_sql, term_sql, data],
        )
        .map_err(|e| PersistError::sqlite(e.to_string()))?;
        tx.execute(
            "UPDATE consensus_applied SET applied_index = ?1 WHERE id = 1",
            params![index_sql],
        )
        .map_err(|e| PersistError::sqlite(e.to_string()))?;
        if retain_log_suffix {
            tx.execute(
                "DELETE FROM consensus_log WHERE log_index <= ?1",
                params![index_sql],
            )
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        } else {
            tx.execute("DELETE FROM consensus_log", [])
                .map_err(|e| PersistError::sqlite(e.to_string()))?;
        }

        tx.commit()
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        Ok(())
    }
}
