//! Explicit cold compatibility export. The caller first captures one native
//! state under its owner and releases that owner before constructing this
//! disposable SQLite image. No command is executed against this connection.

use super::log::NativeLogEntry;
use super::*;
use crate::sqlite::{consensus as sql, ops};
use rusqlite::{params, Connection, Transaction, TransactionBehavior};

// Keep diagnostic output limited to fixed source locations and error codes;
// SQLite messages and StoreError payloads may contain session data.
macro_rules! db {
    ($error:expr) => {{
        let error: rusqlite::Error = $error;
        #[cfg(feature = "test-control")]
        eprintln!(
            "native_snapshot_export_sqlite_failure line={} variant={:?} extended_code={:?}",
            line!(),
            std::mem::discriminant(&error),
            error.sqlite_error().map(|code| code.extended_code),
        );
        sql::db_error(error)
    }};
}
fn store(error: StoreError) -> io::Error {
    #[cfg(feature = "test-control")]
    eprintln!(
        "native_snapshot_export_store_failure variant={:?}",
        std::mem::discriminant(&error),
    );
    io::Error::other(error)
}
fn json(value: &impl Serialize) -> io::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(io::Error::other)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose {
    #[cfg(test)]
    Snapshot,
    PortableSnapshot,
    InstallBase,
}

struct OrderedLogs<'a> {
    rows: Vec<&'a SharedRow<NativeLogEntry>>,
    _memory: crate::consensus::verified_snapshot::VerificationMemory,
}

impl<'a> OrderedLogs<'a> {
    fn new(
        storage: &'a NativeStorage,
        purpose: Purpose,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        check()?;
        // One borrowed pointer per retained log, reserved before allocation.
        // The detached immutable capture keeps every row and its source alive.
        let bytes = storage
            .log
            .entries
            .len()
            .checked_mul(std::mem::size_of::<&SharedRow<NativeLogEntry>>())
            .ok_or_else(|| invalid("native export log order reservation overflow"))?;
        let memory = crate::consensus::verified_snapshot::VerificationMemory::reserve(bytes)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(storage.log.entries.len())
            .map_err(|_| invalid("native export log order allocation failed"))?;
        for entry in storage.log.entries.values().filter(|entry| {
            purpose == Purpose::InstallBase
                || storage
                    .business
                    .frontiers
                    .applied
                    .is_some_and(|applied| entry.id().index <= applied.index)
        }) {
            check()?;
            rows.push(entry);
        }
        // Delta frames use change-map order. Traversing them by Raft index
        // otherwise rereads and rehashes whole blocks for individual rows.
        // SQL insertion order has no authority: retain the exact row view,
        // original full decoder and applied/suffix filter for every purpose.
        rows.sort_unstable_by_key(|entry| entry.cold_read_order());
        check()?;
        Ok(Self {
            rows,
            _memory: memory,
        })
    }
}

struct OrderedReceipts<'a> {
    rows: Vec<(
        &'a FencedTransitionV2RequestId,
        &'a SharedRow<NativeReceipt>,
    )>,
    _memory: crate::consensus::verified_snapshot::VerificationMemory,
}

impl<'a> OrderedReceipts<'a> {
    fn new(state: &'a NativeState, check: &impl Fn() -> io::Result<()>) -> io::Result<Self> {
        check()?;
        if state.receipts.len() != lifecycle::receipt_count(state.frontiers.history)? {
            return Err(invalid("native export receipt cardinality differs"));
        }
        // Only two borrowed pointers per receipt, charged before allocation.
        // The immutable capture owns every row/source until this list drops;
        // sorting does not hydrate or duplicate any historical response.
        let bytes = state
            .receipts
            .len()
            .checked_mul(std::mem::size_of::<(
                &FencedTransitionV2RequestId,
                &SharedRow<NativeReceipt>,
            )>())
            .ok_or_else(|| invalid("native export receipt order reservation overflow"))?;
        let memory = crate::consensus::verified_snapshot::VerificationMemory::reserve(bytes)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(state.receipts.len())
            .map_err(|_| invalid("native export receipt order allocation failed"))?;
        for row in &state.receipts {
            check()?;
            rows.push(row);
        }
        // Hash-map order otherwise repeatedly rehashes a whole verified block
        // for each small receipt. Visit the same selected bytes by source and
        // offset; the exact per-row view, decoder and revision checks below
        // remain the authority. This in-place sort allocates no second list.
        rows.sort_unstable_by_key(|(_, row)| row.cold_read_order());
        check()?;
        Ok(Self {
            rows,
            _memory: memory,
        })
    }
}

impl NativeStorage {
    /// Emit the portable business projection without first allocating pages
    /// for local Raft state that snapshot finalization would discard. Source
    /// validation, including reads of covered selected logs, remains mandatory.
    pub(crate) fn export_cold_portable_snapshot_checked(
        &self,
        conn: &Connection,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        self.export_cold_checked(conn, Purpose::PortableSnapshot, check)
    }

    #[cfg(test)]
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
        conn.pragma_update(None, "query_only", false)
            .map_err(|error| db!(error))?;
        let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
            .map_err(|error| db!(error))?;
        for (key, value) in &state.keys {
            check()?;
            if let Some(record) = &value.record {
                ops::insert_or_replace_record_sync(&tx, record).map_err(store)?;
            }
            if value.fence > 0 {
                ops::insert_or_replace_fence_sync(&tx, key, value.fence).map_err(store)?;
            }
            if let Some(lease) = &value.lease {
                tx.execute("INSERT INTO leases (tenant,nf_kind,key_type,stable_id,active,credential_id,owner,fence,expires_at_unix_ms,guard_expires_at,acquired_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)", params![key.tenant.as_str(),key.nf_kind.as_str(),key.key_type.to_string(),key.stable_id.as_ref(),lease.active,lease.credential_id,lease.owner.as_str(),lease.fence.get(),lease.expires_at_unix_ms,ops::format_rfc3339_normalized(lease.guard_expires_at),lease.acquired_at.map(ops::format_rfc3339_normalized)]).map_err(|error| db!(error))?;
            }
        }
        tx.execute(
            "UPDATE lease_globals SET val = ?1 WHERE key = 'next_fence'",
            [frontiers.next_fence],
        )
        .map_err(|error| db!(error))?;
        tx.execute(
            "UPDATE lease_globals SET val = ?1 WHERE key = 'next_credential_id'",
            [frontiers.next_credential],
        )
        .map_err(|error| db!(error))?;
        if let Some(origin) = &state.snapshot_origin {
            origin.incarnation().rotate_sync(&tx).map_err(store)?;
        }
        tx.execute(
            "UPDATE restore_scan_state SET revision = ?1 WHERE singleton = 1",
            [frontiers.restore_revision],
        )
        .map_err(|error| db!(error))?;
        tx.execute("UPDATE consensus_machine SET application_sequence=?1,last_digest=?2,logical_time=?3,watch_sequence=?4 WHERE singleton=1 AND configuration_epoch=?5", params![frontiers.sequence,frontiers.digest.as_bytes().as_slice(),frontiers.logical_time.map(ops::format_rfc3339_normalized),frontiers.watch_sequence,epoch]).map_err(|error| db!(error))?;
        tx.execute("INSERT OR REPLACE INTO consensus_membership (singleton,configuration_epoch,membership_json) VALUES (1,?1,?2)", params![epoch,json(&frontiers.membership)?]).map_err(|error| db!(error))?;
        let portable = purpose == Purpose::PortableSnapshot;
        let committed = if portable {
            None
        } else if purpose == Purpose::InstallBase {
            self.log.committed
        } else {
            frontiers.applied
        };
        let preserve_origin =
            !portable && (purpose == Purpose::InstallBase || state.snapshot_origin.is_some());
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
                tx.execute(&format!("INSERT OR REPLACE INTO {table} (singleton,configuration_epoch,term,log_index,log_id_json) VALUES (1,?1,?2,?3,?4)"),params![epoch,pointer.leader_id.term,pointer.index,json(&pointer)?]).map_err(|error| db!(error))?;
            }
        }
        let ordered_logs = OrderedLogs::new(self, purpose, check)?;
        NativeLogEntry::visit_export(
            &ordered_logs.rows,
            state.identity,
            &state.members,
            check,
            // Omission from the portable image is not permission to trust an
            // unread selected range. Preserve the raw export's full byte and
            // authority checks even though these pages will not be written.
            &mut |id, bytes| {
                if !portable {
                    tx.prepare_cached("INSERT INTO consensus_log (log_index,configuration_epoch,term,entry_json) VALUES (?1,?2,?3,?4)").map_err(|error| db!(error))?.execute(params![id.index,epoch,id.leader_id.term,bytes]).map_err(|error| db!(error))?;
                }
                Ok(())
            },
        )?;
        drop(ordered_logs);
        if preserve_origin {
            if let Some((meta, name, checksum, length)) = &frontiers.current_snapshot {
                tx.execute("INSERT INTO consensus_snapshot (singleton,configuration_epoch,meta_json,file_name,checksum,byte_length) VALUES (1,?1,?2,?3,?4,?5)",params![epoch,json(meta)?,name,checksum.as_slice(),length]).map_err(|error| db!(error))?;
            }
        }
        if let Some(vote) = self.log.vote.filter(|_| !portable) {
            tx.execute("INSERT OR REPLACE INTO consensus_vote (singleton,configuration_epoch,term,node_id,vote_json) VALUES (1,?1,?2,?3,?4)",params![epoch,vote.leader_id.term,vote.leader_id.voted_for().map(|node| node.get()),json(&vote)?]).map_err(|error| db!(error))?;
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
                    tx.prepare_cached("INSERT INTO consensus_request_outcomes (request_id,configuration_epoch,payload_digest,response_json) VALUES (?1,?2,?3,?4)").map_err(|error| db!(error))?.execute(params![id.as_bytes().as_slice(),epoch,receipt.payload_digest.as_slice(),json(&receipt.response)?]).map_err(|error| db!(error))?;
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
                    tx.execute("INSERT INTO consensus_fenced_transition_receipts (request_id,configuration_epoch,payload_digest,retained_until,binding_digest,response_json,response_digest) VALUES (?1,?2,?3,?4,?5,?6,?7)",params![id.as_bytes().as_slice(),epoch,receipt.payload_digest.as_slice(),until,binding.as_slice(),encoded,response_digest.as_ref().map(|digest| digest.as_slice())]).map_err(|error| db!(error))?;
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
            tx.execute("UPDATE consensus_fenced_transition_v2_history SET active_epoch=?1,retired_through_epoch=?2,generation=?3,current_bound_count=?4,reclaimed_entries=?5,reclaim_epoch=?6,reclaim_cursor_ordinal=?7,reclaim_remaining=?8 WHERE singleton=1",params![history.active_epoch().ok_or_else(|| invalid("native cold export active epoch missing"))?.get(),history.retired_through().map_or(0,|epoch| epoch.get()),history.generation(),history.bound_entries() as u64,history.reclaimed_entries(),reclaim,cursor,remaining]).map_err(|error| db!(error))?;
            let ordered = OrderedReceipts::new(state, check)?;
            let mut insert = tx.prepare("INSERT INTO consensus_fenced_transition_v2_receipts (request_id,history_epoch,ordinal,configuration_epoch,payload_digest,retained_until,binding_digest,response_json,response_digest) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)").map_err(|error| db!(error))?;
            for &(id, receipt) in &ordered.rows {
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
                insert
                    .execute(params![
                        id.to_bytes().as_slice(),
                        id.epoch().get(),
                        receipt.ordinal,
                        epoch,
                        receipt.payload_digest.as_slice(),
                        retained_until,
                        binding.as_slice(),
                        encoded,
                        response_digest.as_ref().map(|digest| digest.as_slice())
                    ])
                    .map_err(|error| db!(error))?;
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
            tx.prepare_cached("INSERT INTO session_replication_log (sequence,tx_id,entry_json,timestamp) VALUES (?1,?2,?3,?4)").map_err(|error| db!(error))?.execute(params![entry.sequence,entry.tx_id.as_str(),serde_json::to_string(entry).map_err(io::Error::other)?,ops::format_rfc3339_normalized(entry.timestamp)]).map_err(|error| db!(error))?;
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
        tx.commit().map_err(|error| db!(error))?;
        conn.pragma_update(None, "query_only", true)
            .map_err(|error| db!(error))?;
        check()
    }
}

#[cfg(test)]
mod tests {
    use super::super::changes::tests::{apply, clock, command, fixture, request, time};
    use super::super::generation::{Catalog, PreparedBase, PreparedDelta, Version};
    use super::*;
    use std::fs::OpenOptions;

    #[test]
    fn native_snapshot_delta_log_export_bounds_block_reads_and_preserves_exact_rows() {
        const BLOCK: usize = 64 * 1024;
        const MAXIMUM: u64 = 64 * 1024 * 1024;
        let (mut original, _, _) = fixture();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("delta-logs.native");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        let prepared = PreparedBase::prepare(
            &original,
            generation::BaseParameters {
                binding: [3; 32],
                file_epoch: 1,
                checkpoint_epoch: 1,
                operation_sequence: 1,
                cut_binding: [4; 32],
                block_bytes: BLOCK,
                maximum: MAXIMUM,
            },
            &|| Ok(()),
        )
        .unwrap();
        let identity = prepared.write_to(&mut file, &|| Ok(())).unwrap();
        file.sync_all().unwrap();
        fn scope(storage: &NativeStorage) -> generation::CatalogScope<'_> {
            generation::CatalogScope {
                identity: storage.business.identity,
                members: &storage.business.members,
                roster_root: None,
            }
        }
        let (mut owner, _) =
            Catalog::open(&path, identity, MAXIMUM, scope(&original), [4; 32], &|| {
                Ok(())
            })
            .unwrap();
        let version = Version::capture(&original).unwrap();
        original.begin_changes().unwrap();
        for first in (2..1026).step_by(64) {
            let entries = (first..first + 64)
                .map(|index| clock(index, time(2)))
                .collect::<Vec<_>>();
            apply(&mut original, &entries);
        }
        // The installation predecessor retains the uncommitted suffix; the
        // portable and raw snapshots validate only their applied projection.
        original
            .log
            .project(
                &sql::wal::Operation::Append(vec![json(&clock(1026, time(2))).unwrap().into()]),
                &original.business,
                None,
            )
            .unwrap();
        let delta = PreparedDelta::prepare(
            owner.current(),
            &version,
            2,
            2,
            [5; 32],
            original.take_changes().unwrap(),
            &|| Ok(()),
        )
        .unwrap();
        let selected = delta.append(&mut owner, &|| Ok(())).unwrap();
        // Reconstruct arbitrary bytes through the cold catalog, independently
        // of the process-local expected-readback admission used by append.
        let (reopened, catalog) = Catalog::open(
            &path,
            selected.identity(),
            MAXIMUM,
            scope(&original),
            [5; 32],
            &|| Ok(()),
        )
        .unwrap();
        let selected = reopened.current();
        let cold = catalog.into_storage(&|| Ok(())).unwrap();
        let blocks = selected.identity().length / BLOCK as u64;
        assert!(
            blocks >= 4,
            "exercise several independently authenticated blocks"
        );
        for purpose in [
            Purpose::InstallBase,
            Purpose::Snapshot,
            Purpose::PortableSnapshot,
        ] {
            let ordered = OrderedLogs::new(&cold, purpose, &|| Ok(())).unwrap();
            let expected_len = if purpose == Purpose::InstallBase {
                1027
            } else {
                1026
            };
            assert_eq!(ordered.rows.len(), expected_len);
            let before = selected.blocks_read();
            let mut indexes = BTreeSet::new();
            for entry in &ordered.rows {
                assert!(indexes.insert(entry.id().index), "visit each full row once");
                let actual = entry
                    .read_bytes(cold.business.identity, &cold.business.members, &|| Ok(()))
                    .unwrap();
                let expected = original.log.entries.get(&entry.id().index).unwrap();
                assert_eq!(actual.bytes(), expected.encoded_for_test().unwrap());
                assert_eq!(
                    sql::decode_consensus_log_entry(actual.bytes()).unwrap(),
                    expected.resident().unwrap().entry,
                    "the complete original decoder and every field remain authoritative",
                );
            }
            let reads = selected.blocks_read() - before;
            eprintln!(
                "native_delta_log_export rows={expected_len} blocks={blocks} block_reads={reads}"
            );
            assert!(reads <= blocks, "export rereads authenticated delta blocks");
            let before = selected.blocks_read();
            let mut emitted = BTreeSet::new();
            NativeLogEntry::visit_export(
                &ordered.rows,
                cold.business.identity,
                &cold.business.members,
                &|| Ok(()),
                &mut |id, bytes| {
                    assert!(emitted.insert(id.index));
                    let expected = original.log.entries.get(&id.index).unwrap();
                    assert_eq!(id, expected.id());
                    assert_eq!(bytes, expected.encoded_for_test().unwrap());
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(emitted, indexes);
            assert!(selected.blocks_read() - before <= blocks);
        }
    }

    #[test]
    fn native_snapshot_receipt_export_reads_each_selected_block_once_with_exact_rows() {
        const BLOCK: usize = 64 * 1024;
        const MAXIMUM: u64 = 64 * 1024 * 1024;
        let (mut original, _, _) = fixture();
        for first in (2..1026).step_by(64) {
            let entries = (first..first + 64)
                .map(|index| command(index, &request(index, None), time(2), false))
                .collect::<Vec<_>>();
            apply(&mut original, &entries);
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("receipts.native");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        let prepared = PreparedBase::prepare(
            &original,
            crate::consensus::native::generation::BaseParameters {
                binding: [3; 32],
                file_epoch: 1,
                checkpoint_epoch: 1,
                operation_sequence: 1,
                cut_binding: [4; 32],
                block_bytes: BLOCK,
                maximum: MAXIMUM,
            },
            &|| Ok(()),
        )
        .unwrap();
        let identity = prepared.write_to(&mut file, &|| Ok(())).unwrap();
        file.sync_all().unwrap();
        let (owner, catalog) = Catalog::open(
            &path,
            identity,
            MAXIMUM,
            crate::consensus::native::generation::CatalogScope {
                identity: original.business.identity,
                members: &original.business.members,
                roster_root: None,
            },
            [4; 32],
            &|| Ok(()),
        )
        .unwrap();
        let selected = owner.current();
        let cold = catalog.into_storage(&|| Ok(())).unwrap();
        assert_eq!(cold.cold_counts_for_test()[0], 1025);
        let resolve_exact = |id: &FencedTransitionV2RequestId, row: &SharedRow<NativeReceipt>| {
            let (source, range) = row.cold_range().unwrap();
            let resolved = cold::ReceiptReadTicket::capture(&cold.business, *id, source, range)
                .unwrap()
                .resolve(&|| Ok(()))
                .unwrap()
                .copy_guarded(&cold.business)
                .unwrap();
            assert_eq!(
                json(resolved.row()).unwrap(),
                json(&**original.business.receipts.get(id).unwrap()).unwrap()
            );
        };
        let before = selected.blocks_read();
        for (id, row) in &cold.business.receipts {
            resolve_exact(id, row);
        }
        let unordered_blocks = selected.blocks_read() - before;
        let ordered = OrderedReceipts::new(&cold.business, &|| Ok(())).unwrap();
        let mut required_blocks = BTreeSet::new();
        for (_, row) in &ordered.rows {
            let (_, range) = row.cold_range().unwrap();
            required_blocks
                .extend(range.offset() / BLOCK as u64..=(range.end() - 1) / BLOCK as u64);
        }
        let before = selected.blocks_read();
        for &(id, row) in &ordered.rows {
            resolve_exact(id, row);
        }
        let ordered_blocks = selected.blocks_read() - before;
        assert!(
            required_blocks.len() >= 4,
            "exercise multiple independently verified blocks"
        );
        assert!(ordered_blocks <= required_blocks.len() as u64);
        assert!(
            unordered_blocks > ordered_blocks * 4,
            "the original hash traversal must expose repeated reads"
        );
        eprintln!(
            "native snapshot receipt block reads: receipts={} original={} ordered={} distinct={}",
            ordered.rows.len(),
            unordered_blocks,
            ordered_blocks,
            required_blocks.len()
        );
    }
}
