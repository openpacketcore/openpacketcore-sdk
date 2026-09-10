//! Explicit cold compatibility export. The caller first captures one native
//! state under its owner and releases that owner before constructing this
//! disposable SQLite image. No command is executed against this connection.

use super::*;
use crate::sqlite::{consensus as sql, ops};
use rusqlite::{params, Connection, Transaction, TransactionBehavior};

fn db(error: rusqlite::Error) -> io::Error {
    io::Error::other(error)
}
fn store(error: StoreError) -> io::Error {
    io::Error::other(error)
}
fn json(value: &impl Serialize) -> io::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(io::Error::other)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose {
    Snapshot,
    InstallBase,
}

impl NativeStorage {
    pub(crate) fn export_cold_snapshot_checked(
        &self,
        conn: &Connection,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        self.export_cold_checked(conn, Purpose::Snapshot, check)
    }

    /// The original snapshot installer must see the complete local predecessor,
    /// including unapplied/covered physical logs and every exact Raft pointer.
    /// A portable snapshot projection cannot establish those local predicates.
    /// The caller owns this disposable image outside the live native owner.
    pub(crate) fn export_cold_install_base_checked(
        &self,
        conn: &Connection,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        self.export_cold_checked(conn, Purpose::InstallBase, check)
    }

    fn export_cold_checked(
        &self,
        conn: &Connection,
        purpose: Purpose,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        check()?;
        let _context_memory =
            crate::consensus::verified_snapshot::VerificationMemory::reserve(512 * 1024)?;
        self.validate_image()?;
        check()?;
        let state = &self.business;
        let frontiers = &state.frontiers;
        let stored_root = sql::roster_snapshot::read_root(conn)
            .map_err(|_| invalid("native snapshot cold roster root is corrupt"))?;
        if stored_root.as_ref() != state.roster_root.as_deref() {
            return Err(invalid(
                "native snapshot configured roster root differs from cold basis",
            ));
        }
        let epoch = i64::try_from(state.identity.configuration_epoch().get())
            .map_err(|_| invalid("native export configuration epoch exceeds SQLite range"))?;
        conn.pragma_update(None, "query_only", false).map_err(db)?;
        let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db)?;
        for (key, value) in &state.keys {
            check()?;
            if let Some(record) = &value.record {
                ops::insert_or_replace_record_sync(&tx, record).map_err(store)?;
            }
            if value.fence > 0 {
                ops::insert_or_replace_fence_sync(&tx, key, value.fence).map_err(store)?;
            }
            if let Some(lease) = &value.lease {
                tx.execute("INSERT INTO leases (tenant,nf_kind,key_type,stable_id,active,credential_id,owner,fence,expires_at_unix_ms,guard_expires_at,acquired_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)", params![key.tenant.as_str(),key.nf_kind.as_str(),key.key_type.to_string(),key.stable_id.as_ref(),lease.active,lease.credential_id,lease.owner.as_str(),lease.fence.get(),lease.expires_at_unix_ms,ops::format_rfc3339_normalized(lease.guard_expires_at),lease.acquired_at.map(ops::format_rfc3339_normalized)]).map_err(db)?;
            }
        }
        tx.execute(
            "UPDATE lease_globals SET val = ?1 WHERE key = 'next_fence'",
            [frontiers.next_fence],
        )
        .map_err(db)?;
        tx.execute(
            "UPDATE lease_globals SET val = ?1 WHERE key = 'next_credential_id'",
            [frontiers.next_credential],
        )
        .map_err(db)?;
        if let Some(origin) = &state.snapshot_origin {
            origin.incarnation().rotate_sync(&tx).map_err(store)?;
        }
        tx.execute(
            "UPDATE restore_scan_state SET revision = ?1 WHERE singleton = 1",
            [frontiers.restore_revision],
        )
        .map_err(db)?;
        tx.execute("UPDATE consensus_machine SET application_sequence=?1,last_digest=?2,logical_time=?3,watch_sequence=?4 WHERE singleton=1 AND configuration_epoch=?5", params![frontiers.sequence,frontiers.digest.as_bytes().as_slice(),frontiers.logical_time.map(ops::format_rfc3339_normalized),frontiers.watch_sequence,epoch]).map_err(db)?;
        tx.execute("INSERT OR REPLACE INTO consensus_membership (singleton,configuration_epoch,membership_json) VALUES (1,?1,?2)", params![epoch,json(&frontiers.membership)?]).map_err(db)?;
        let committed = if purpose == Purpose::InstallBase {
            self.log.committed
        } else {
            frontiers.applied
        };
        let preserve_origin = purpose == Purpose::InstallBase || state.snapshot_origin.is_some();
        let purged = if preserve_origin {
            self.log.purged
        } else {
            None
        };
        for (table, pointer) in [
            ("consensus_applied", frontiers.applied),
            ("consensus_committed", committed),
            ("consensus_purged", purged),
        ] {
            if let Some(pointer) = pointer {
                tx.execute(&format!("INSERT OR REPLACE INTO {table} (singleton,configuration_epoch,term,log_index,log_id_json) VALUES (1,?1,?2,?3,?4)"),params![epoch,pointer.leader_id.term,pointer.index,json(&pointer)?]).map_err(db)?;
            }
        }
        for entry in self.log.entries.values().filter(|entry| {
            purpose == Purpose::InstallBase
                || frontiers
                    .applied
                    .is_some_and(|applied| entry.id().index <= applied.index)
        }) {
            check()?;
            let bytes = entry.read_bytes(state.identity, &state.members, check)?;
            tx.execute("INSERT INTO consensus_log (log_index,configuration_epoch,term,entry_json) VALUES (?1,?2,?3,?4)",params![entry.id().index,epoch,entry.id().leader_id.term,bytes.bytes()]).map_err(db)?;
        }
        if preserve_origin {
            if let Some((meta, name, checksum, length)) = &frontiers.current_snapshot {
                tx.execute("INSERT INTO consensus_snapshot (singleton,configuration_epoch,meta_json,file_name,checksum,byte_length) VALUES (1,?1,?2,?3,?4,?5)",params![epoch,json(meta)?,name,checksum.as_slice(),length]).map_err(db)?;
            }
        }
        if let Some(vote) = self.log.vote {
            tx.execute("INSERT OR REPLACE INTO consensus_vote (singleton,configuration_epoch,term,node_id,vote_json) VALUES (1,?1,?2,?3,?4)",params![epoch,vote.leader_id.term,vote.leader_id.voted_for().map(|node| node.get()),json(&vote)?]).map_err(db)?;
        }
        if let Some(activation) = &frontiers.v1_activation {
            sql::activate_fenced_transition_scope_with_voter_digest_sync(
                &tx,
                state.identity,
                activation.identity,
                &state.members,
                activation.voters,
            )?;
        }
        for (id, receipt) in &state.generic_receipts {
            check()?;
            let encoding_bytes = changes::generic_payload(Some(receipt))?
                .checked_mul(12)
                .and_then(|bytes| bytes.checked_add(64 * 1024))
                .ok_or_else(|| invalid("native snapshot generic encoding reservation overflow"))?;
            let _encoding_memory =
                crate::consensus::verified_snapshot::VerificationMemory::reserve(encoding_bytes)?;
            match &**receipt {
                NativeGenericReceipt::Ordinary(receipt) => {
                    tx.execute("INSERT INTO consensus_request_outcomes (request_id,configuration_epoch,payload_digest,response_json) VALUES (?1,?2,?3,?4)",params![id.as_bytes().as_slice(),epoch,receipt.payload_digest.as_slice(),json(&receipt.response)?]).map_err(db)?;
                }
                NativeGenericReceipt::FencedV1(receipt) => {
                    let until = ops::format_rfc3339_normalized(receipt.retained_until);
                    let binding = sql::fenced_transition_receipt_binding_digest(
                        state.identity,
                        *id,
                        receipt.payload_digest,
                        &until,
                    )?;
                    let encoded = receipt.response.as_deref().map(json).transpose()?;
                    let response_digest = receipt
                        .response
                        .as_deref()
                        .map(|response| {
                            sql::fenced_transition_receipt_response_digest(binding, response)
                        })
                        .transpose()?;
                    tx.execute("INSERT INTO consensus_fenced_transition_receipts (request_id,configuration_epoch,payload_digest,retained_until,binding_digest,response_json,response_digest) VALUES (?1,?2,?3,?4,?5,?6,?7)",params![id.as_bytes().as_slice(),epoch,receipt.payload_digest.as_slice(),until,binding.as_slice(),encoded,response_digest.as_ref().map(|digest| digest.as_slice())]).map_err(db)?;
                }
            }
        }
        if let (Some(history), Some(activation)) = (frontiers.history, &frontiers.activation) {
            sql::activate_fenced_transition_v2_scope_sync(
                &tx,
                state.identity,
                activation.identity,
                &state.members,
                activation.profile,
                crate::FencedTransitionV2HistoryEpoch::new(
                    FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH,
                )
                .map_err(store)?,
            )?;
            let reclaim = history.reclaim_epoch().map(|epoch| epoch.get());
            let cursor = reclaim.map(|_| {
                (FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - history.reclaim_remaining()) as u64
            });
            let remaining = reclaim.map(|_| history.reclaim_remaining() as u64);
            tx.execute("UPDATE consensus_fenced_transition_v2_history SET active_epoch=?1,retired_through_epoch=?2,generation=?3,current_bound_count=?4,reclaimed_entries=?5,reclaim_epoch=?6,reclaim_cursor_ordinal=?7,reclaim_remaining=?8 WHERE singleton=1",params![history.active_epoch().ok_or_else(|| invalid("native cold export active epoch missing"))?.get(),history.retired_through().map_or(0,|epoch| epoch.get()),history.generation(),history.bound_entries() as u64,history.reclaimed_entries(),reclaim,cursor,remaining]).map_err(db)?;
            for (id, receipt) in &state.receipts {
                check()?;
                // This exporter owns an immutable snapshot capture outside
                // State. The manual SQL columns must use the complete cold
                // response too; response=None in the resident index alone
                // cannot distinguish an expired tombstone from a cold body.
                let resolved = receipt
                    .cold_range()
                    .map(|(source, range)| {
                        cold::ReceiptReadTicket::capture(state, *id, source, range)?
                            .resolve(check)?
                            .copy_guarded(state)
                    })
                    .transpose()?;
                let receipt = resolved
                    .as_ref()
                    .map(cold::OwnedReceipt::row)
                    .unwrap_or(receipt);
                let _encoding_memory = crate::consensus::verified_snapshot::VerificationMemory::reserve(3 * crate::fenced_transition::FENCED_TRANSITION_V2_RECEIPT_RESPONSE_MAX_BYTES + 64 * 1024)?;
                let retained_until = ops::format_rfc3339_normalized(receipt.retained_until);
                let binding = sql::fenced_transition_v2_receipt_binding_digest(
                    state.identity,
                    id.to_bytes(),
                    id.epoch().get(),
                    receipt.ordinal,
                    receipt.payload_digest,
                    &retained_until,
                )?;
                let encoded = receipt
                    .response
                    .as_deref()
                    .map(sql::encode_fenced_transition_v2_response)
                    .transpose()?;
                let response_digest = encoded
                    .as_ref()
                    .map(|encoded| {
                        sql::fenced_transition_v2_receipt_response_digest(binding, encoded)
                    })
                    .transpose()?;
                tx.execute("INSERT INTO consensus_fenced_transition_v2_receipts (request_id,history_epoch,ordinal,configuration_epoch,payload_digest,retained_until,binding_digest,response_json,response_digest) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![id.to_bytes().as_slice(),id.epoch().get(),receipt.ordinal,epoch,receipt.payload_digest.as_slice(),retained_until,binding.as_slice(),encoded,response_digest.as_ref().map(|digest| digest.as_slice())]).map_err(db)?;
            }
        }
        for entry in &state.notifications {
            check()?;
            let resolved = entry.read(&state.frontiers, check)?;
            let entry = resolved.entry();
            // JSON numeric bytes use at most four bytes per payload byte;
            // charge old/new String growth before creating that output.
            let encoding_bytes = changes::notification_payload(entry)?
                .checked_mul(12)
                .and_then(|bytes| bytes.checked_add(64 * 1024))
                .ok_or_else(|| {
                    invalid("native snapshot notification encoding reservation overflow")
                })?;
            let _encoding_memory =
                crate::consensus::verified_snapshot::VerificationMemory::reserve(encoding_bytes)?;
            tx.execute("INSERT INTO session_replication_log (sequence,tx_id,entry_json,timestamp) VALUES (?1,?2,?3,?4)",params![entry.sequence,entry.tx_id.as_str(),serde_json::to_string(entry).map_err(io::Error::other)?,ops::format_rfc3339_normalized(entry.timestamp)]).map_err(db)?;
        }
        if frontiers.roster_v1_namespace {
            sql::roster_snapshot::activate_v1(&tx)?;
        }
        if let Some(activation) = &frontiers.roster_v2_activation {
            sql::roster_snapshot::activate_v2(
                &tx,
                state.identity,
                activation.identity,
                &state.members,
                activation.profile,
            )?;
        }
        let scope = roster::fixed_scope(state.identity, &state.members);
        for row in state.roster.rows.values() {
            check()?;
            let root = state
                .roster_root
                .as_deref()
                .ok_or_else(|| invalid("native snapshot roster root missing"))?;
            let hydrated = row.hydrate_detached(root, &scope, check)?;
            sql::roster_snapshot::write_row(&tx, state.identity, &hydrated)?;
        }
        for (key, partition) in &state.roster.partitions {
            check()?;
            sql::roster_snapshot::write_partition(
                &tx,
                state.identity,
                *key,
                partition.floor,
                partition.cursor.as_ref(),
            )?;
        }
        if let Some(witness) = state.roster.witness {
            sql::roster_snapshot::write_witness(&tx, state.identity, witness)?;
        }
        check()?;
        sql::validate_protected_roster_recovery_state_sync(&tx, state.identity)
            .map_err(|_| invalid("native snapshot exported roster recovery validation failed"))?;
        check()?;
        tx.commit().map_err(db)?;
        conn.pragma_update(None, "query_only", true).map_err(db)?;
        check()
    }
}
