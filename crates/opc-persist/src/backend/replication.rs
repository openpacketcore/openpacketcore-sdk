use rusqlite::params;
use std::sync::Arc;

use opc_types::Timestamp;

use crate::consensus::{ClusterMembership, ConsensusOp, LogEntry};
use crate::error::PersistError;
use crate::types::StoredConfig;

use super::SqliteBackend;

impl SqliteBackend {
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
            Ok((term as u64, voted_for.map(|v| v as usize)))
        } else {
            Ok((0, None))
        }
    }

    pub async fn consensus_set_state(
        &self,
        term: u64,
        voted_for: Option<usize>,
    ) -> Result<(), PersistError> {
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        guard
            .execute(
                "INSERT OR REPLACE INTO consensus_state (node_id, current_term, voted_for) VALUES (1, ?1, ?2)",
                params![term as i64, voted_for.map(|v| v as i64)],
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
                Ok((index as u64, term as u64))
            },
        );
        match log_res {
            Ok(value) => Ok(value),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                let snap_res = guard.query_row(
                    "SELECT snapshot_index, snapshot_term FROM consensus_snapshot WHERE id = 1",
                    [],
                    |row| {
                        let index: i64 = row.get(0)?;
                        let term: i64 = row.get(1)?;
                        Ok((index as u64, term as u64))
                    },
                );
                match snap_res {
                    Ok(value) => Ok(value),
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok((0, 0)),
                    Err(e) => Err(PersistError::sqlite(e.to_string())),
                }
            }
            Err(e) => Err(PersistError::sqlite(e.to_string())),
        }
    }

    pub async fn consensus_get_log_term(&self, index: u64) -> Result<Option<u64>, PersistError> {
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;

        let log_res = guard.query_row(
            "SELECT term FROM consensus_log WHERE log_index = ?1",
            params![index as i64],
            |row| {
                let term: i64 = row.get(0)?;
                Ok(term as u64)
            },
        );
        match log_res {
            Ok(term) => Ok(Some(term)),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                let snap_res = guard.query_row(
                    "SELECT snapshot_term FROM consensus_snapshot WHERE id = 1 AND snapshot_index = ?1",
                    params![index as i64],
                    |row| {
                        let term: i64 = row.get(0)?;
                        Ok(term as u64)
                    },
                );
                match snap_res {
                    Ok(term) => Ok(Some(term)),
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
        if prev_index < applied_index as u64 {
            return Err(PersistError::inconsistent_state(
                "cannot overwrite applied consensus log",
            ));
        }

        let tx = guard
            .transaction()
            .map_err(|e| PersistError::sqlite(e.to_string()))?;

        tx.execute(
            "DELETE FROM consensus_log WHERE log_index > ?1",
            params![prev_index as i64],
        )
        .map_err(|e| PersistError::sqlite(e.to_string()))?;

        for entry in entries {
            let payload = serde_json::to_string(&entry.op)
                .map_err(|e| PersistError::inconsistent_state(e.to_string()))?;
            tx.execute(
                "INSERT OR REPLACE INTO consensus_log (log_index, term, op_type, payload) VALUES (?1, ?2, ?3, ?4)",
                params![entry.index as i64, entry.term as i64, entry.op_name(), payload],
            ).map_err(|e| PersistError::sqlite(e.to_string()))?;
        }

        tx.commit()
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        Ok(())
    }

    pub async fn consensus_truncate_unapplied_after(&self, index: u64) -> Result<(), PersistError> {
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        let applied_index: i64 = guard
            .query_row(
                "SELECT applied_index FROM consensus_applied WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|e| PersistError::sqlite(e.to_string()))?;

        if index < applied_index as u64 {
            return Err(PersistError::inconsistent_state(
                "cannot truncate applied consensus log",
            ));
        }

        guard
            .execute(
                "DELETE FROM consensus_log WHERE log_index > ?1",
                params![index as i64],
            )
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        Ok(())
    }

    pub async fn consensus_get_entries(
        &self,
        start_index: u64,
    ) -> Result<Vec<LogEntry>, PersistError> {
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        let mut stmt = guard
            .prepare("SELECT log_index, term, payload FROM consensus_log WHERE log_index >= ?1 ORDER BY log_index ASC")
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        let rows = stmt
            .query_map(params![start_index as i64], |row| {
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
                index: index as u64,
                term: term as u64,
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
            Ok(applied as u64)
        } else {
            Ok(0)
        }
    }

    pub async fn consensus_apply_entries(&self, commit_index: u64) -> Result<(), PersistError> {
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

            if commit_index as i64 <= applied_index {
                return Ok(());
            }

            let mut stmt = guard
                .prepare("SELECT log_index, payload FROM consensus_log WHERE log_index > ?1 AND log_index <= ?2 ORDER BY log_index ASC")
                .map_err(|e| PersistError::sqlite(e.to_string()))?;

            let rows_iter = stmt
                .query_map(params![applied_index, commit_index as i64], |row| {
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
                        return Err(PersistError::rollback_not_found());
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
                        return Err(PersistError::rollback_not_found());
                    }

                    if let Some(lbl) = &label {
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

                    let local_node_id = match tx.query_row(
                        "SELECT node_id FROM consensus_membership WHERE id = 1",
                        [],
                        |row| row.get::<_, i64>(0),
                    ) {
                        Ok(node_id) => node_id,
                        Err(rusqlite::Error::QueryReturnedNoRows) => membership.node_id as i64,
                        Err(e) => return Err(PersistError::sqlite(e.to_string())),
                    };

                    let current_epoch = match tx.query_row(
                        "SELECT epoch FROM consensus_membership WHERE id = 1",
                        [],
                        |row| row.get::<_, i64>(0),
                    ) {
                        Ok(epoch) => epoch as u64,
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
                            membership.epoch as i64
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
            )) => {
                let voting_members: Vec<usize> = serde_json::from_str(&voting_members_str)
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                let non_voting_members: Vec<usize> = serde_json::from_str(&non_voting_members_str)
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                let old_voting_members: Option<Vec<usize>> = old_voting_members_str
                    .map(|s| {
                        serde_json::from_str(&s).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                0,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })
                    })
                    .transpose()?;
                let removed_members: Vec<usize> = serde_json::from_str(&removed_members_str)
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                Ok(Some(ClusterMembership {
                    cluster_id,
                    node_id: node_id as usize,
                    voting_members,
                    non_voting_members,
                    old_voting_members,
                    removed_members,
                    epoch: epoch as u64,
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(PersistError::sqlite(e.to_string())),
        }
    }

    pub async fn consensus_get_active_membership(
        &self,
    ) -> Result<Option<ClusterMembership>, PersistError> {
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;

        let log_membership = {
            let res = guard.query_row(
                "SELECT payload FROM consensus_log WHERE op_type = 'CHANGE_MEMBERSHIP' ORDER BY log_index DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            );
            match res {
                Ok(payload_str) => {
                    if let Ok(op) = serde_json::from_str::<ConsensusOp>(&payload_str) {
                        match op {
                            ConsensusOp::ChangeMembership { membership } => Some(membership),
                            _ => None,
                        }
                    } else {
                        None
                    }
                }
                Err(_) => None,
            }
        };

        let table_membership = {
            let stmt = guard
                .prepare("SELECT cluster_id, node_id, voting_members, non_voting_members, old_voting_members, removed_members, epoch FROM consensus_membership WHERE id = 1");
            match stmt {
                Ok(mut s) => {
                    let res = s.query_row([], |row| {
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
                        )) => {
                            let voting_members: Vec<usize> =
                                serde_json::from_str(&voting_members_str).unwrap_or_default();
                            let non_voting_members: Vec<usize> =
                                serde_json::from_str(&non_voting_members_str).unwrap_or_default();
                            let old_voting_members: Option<Vec<usize>> =
                                old_voting_members_str.and_then(|s| serde_json::from_str(&s).ok());
                            let removed_members: Vec<usize> =
                                serde_json::from_str(&removed_members_str).unwrap_or_default();
                            Some(ClusterMembership {
                                cluster_id,
                                node_id: node_id as usize,
                                voting_members,
                                non_voting_members,
                                old_voting_members,
                                removed_members,
                                epoch: epoch as u64,
                            })
                        }
                        _ => None,
                    }
                }
                _ => None,
            }
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
                Ok(nid) => nid as usize,
                Err(_) => m.node_id,
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
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;

        let log_membership = {
            let res = guard.query_row(
                "SELECT payload FROM consensus_log WHERE op_type = 'CHANGE_MEMBERSHIP' AND log_index <= ?1 ORDER BY log_index DESC LIMIT 1",
                params![idx as i64],
                |row| row.get::<_, String>(0),
            );
            match res {
                Ok(payload_str) => {
                    if let Ok(op) = serde_json::from_str::<ConsensusOp>(&payload_str) {
                        match op {
                            ConsensusOp::ChangeMembership { membership } => Some(membership),
                            _ => None,
                        }
                    } else {
                        None
                    }
                }
                Err(_) => None,
            }
        };

        let table_membership = {
            let stmt = guard
                .prepare("SELECT cluster_id, node_id, voting_members, non_voting_members, old_voting_members, removed_members, epoch FROM consensus_membership WHERE id = 1");
            match stmt {
                Ok(mut s) => {
                    let res = s.query_row([], |row| {
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
                        )) => {
                            let voting_members: Vec<usize> =
                                serde_json::from_str(&voting_members_str).unwrap_or_default();
                            let non_voting_members: Vec<usize> =
                                serde_json::from_str(&non_voting_members_str).unwrap_or_default();
                            let old_voting_members: Option<Vec<usize>> =
                                old_voting_members_str.and_then(|s| serde_json::from_str(&s).ok());
                            let removed_members: Vec<usize> =
                                serde_json::from_str(&removed_members_str).unwrap_or_default();
                            Some(ClusterMembership {
                                cluster_id,
                                node_id: node_id as usize,
                                voting_members,
                                non_voting_members,
                                old_voting_members,
                                removed_members,
                                epoch: epoch as u64,
                            })
                        }
                        _ => None,
                    }
                }
                _ => None,
            }
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
                Ok(nid) => nid as usize,
                Err(_) => m.node_id,
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

        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;

        let local_node_id = match guard.query_row(
            "SELECT node_id FROM consensus_membership WHERE id = 1",
            [],
            |row| row.get::<_, i64>(0),
        ) {
            Ok(node_id) => {
                if node_id as usize != membership.node_id {
                    return Err(PersistError::inconsistent_state("node_id mismatch"));
                }
                node_id
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => membership.node_id as i64,
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
                membership.epoch as i64
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
            Ok((index as u64, term as u64, data))
        });
        match res {
            Ok(val) => Ok(Some(val)),
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
        let conn = Arc::clone(&self.conn);
        let mut guard = conn.lock_owned().await;

        let tx = guard
            .transaction()
            .map_err(|e| PersistError::sqlite(e.to_string()))?;

        tx.execute(
            "INSERT OR REPLACE INTO consensus_snapshot (id, snapshot_index, snapshot_term, snapshot_data) VALUES (1, ?1, ?2, ?3)",
            params![index as i64, term as i64, data]
        ).map_err(|e| PersistError::sqlite(e.to_string()))?;

        tx.execute(
            "UPDATE consensus_applied SET applied_index = max(applied_index, ?1) WHERE id = 1",
            params![index as i64],
        )
        .map_err(|e| PersistError::sqlite(e.to_string()))?;

        tx.commit()
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        Ok(())
    }

    pub async fn consensus_compact_logs(&self, up_to_index: u64) -> Result<(), PersistError> {
        let conn = Arc::clone(&self.conn);
        let guard = conn.lock_owned().await;
        let applied_index: i64 = guard
            .query_row(
                "SELECT applied_index FROM consensus_applied WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        if up_to_index > applied_index as u64 {
            return Err(PersistError::inconsistent_state(
                "cannot compact unapplied logs",
            ));
        }

        guard
            .execute(
                "DELETE FROM consensus_log WHERE log_index <= ?1",
                params![up_to_index as i64],
            )
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        Ok(())
    }

    pub async fn consensus_install_snapshot_state(
        &self,
        config: StoredConfig,
    ) -> Result<(), PersistError> {
        let conn = Arc::clone(&self.conn);
        let mut guard = conn.lock_owned().await;
        let tx = guard
            .transaction()
            .map_err(|e| PersistError::sqlite(e.to_string()))?;

        tx.execute("DELETE FROM audit_trail", [])
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        tx.execute("DELETE FROM config_history", [])
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        tx.execute("DELETE FROM rollback_labels", [])
            .map_err(|e| PersistError::sqlite(e.to_string()))?;

        Self::append_commit_raw(&tx, config.record, config.audit, self.audit_key.as_ref())?;

        tx.commit()
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        Ok(())
    }
}
