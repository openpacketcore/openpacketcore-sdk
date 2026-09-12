//! Two-pass conversion of a detached original SQL image to a complete V4
//! native generation. The exclusive connection borrow and read transaction
//! span validation, counting and encoding. Notification decoding uses only a
//! charged, bounded temporary batch, as does hashing of decoded Unit receipts.
//! No payload cache survives either pass.
//! The caller must sync and cold-admit the result before selecting any file.

use super::*;
use crate::consensus::SessionTopologyMemberBinding;
use crate::fenced_mutation_roster::RosterAttestationTrustRootV1;
use crate::fenced_mutation_roster_storage::ProductionFloorKey;
use crate::readiness::PlacementResiliencePolicy;
use crate::sqlite::{consensus as sql, ops};
use resident::RowFingerprint;
use rusqlite::types::ValueRef;
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use sql::native_snapshot as source;
use std::collections::BTreeMap;

#[path = "generation_sqlite_notifications.rs"]
mod notifications;

#[path = "generation_sqlite_ordinary.rs"]
mod ordinary;

fn db(error: rusqlite::Error) -> io::Error {
    io::Error::other(error)
}
fn stored(error: StoreError) -> io::Error {
    io::Error::other(error)
}

fn bytes<'a>(row: &'a Row<'_>, column: usize, maximum: usize) -> io::Result<&'a [u8]> {
    let value = match row.get_ref(column).map_err(db)? {
        ValueRef::Blob(value) | ValueRef::Text(value) => value,
        _ => return Err(invalid("native SQL source value has invalid type")),
    };
    if value.len() > maximum {
        return Err(invalid("native SQL source value exceeds original bound"));
    }
    Ok(value)
}

fn scalar<const N: usize>(row: &Row<'_>, column: usize) -> io::Result<[u8; N]> {
    bytes(row, column, N)?
        .try_into()
        .map_err(|_| invalid("native SQL source scalar width differs"))
}

fn row_memory(bytes: usize) -> io::Result<VerificationMemory> {
    VerificationMemory::reserve(row_memory_bytes(bytes)?)
}

fn row_memory_bytes(bytes: usize) -> io::Result<usize> {
    bytes
        .checked_mul(12)
        .and_then(|bytes| bytes.checked_add(64 * 1024))
        .ok_or_else(|| invalid("native SQL row reservation overflow"))
}

fn timestamp(value: String) -> io::Result<Timestamp> {
    let parsed = value
        .parse()
        .map_err(|_| invalid("native SQL timestamp invalid"))?;
    if ops::format_rfc3339_normalized(parsed) != value {
        return Err(invalid("native SQL timestamp is not canonical"));
    }
    Ok(parsed)
}

fn account(
    count: &mut usize,
    content: &mut [u8; 32],
    fingerprint: [u8; 32],
    maximum: usize,
) -> io::Result<()> {
    *count = count
        .checked_add(1)
        .filter(|count| *count <= maximum)
        .ok_or_else(|| invalid("native SQL row count exceeds original bound"))?;
    for (left, right) in content.iter_mut().zip(fingerprint) {
        *left ^= right;
    }
    Ok(())
}

const SMALL_BINARY_ROW_BYTES: usize = 4 * 1024;

// One charged buffer is reused by the detached SQL pass. Small rows supply
// their length from the completed encoding; larger rows keep the original
// bounded streaming encoder. The complete context comparison and independent
// cold admission remain mandatory in addition to each bounded row batch.
struct SqliteBinaryRows {
    // Wipe and free the buffer before returning its reservation.
    buffer: Zeroizing<Vec<u8>>,
    _memory: VerificationMemory,
}

impl SqliteBinaryRows {
    fn new() -> io::Result<Self> {
        let memory = VerificationMemory::reserve(SMALL_BINARY_ROW_BYTES)?;
        let mut buffer = Zeroizing::new(Vec::new());
        buffer
            .try_reserve_exact(SMALL_BINARY_ROW_BYTES)
            .map_err(|_| invalid("native SQL row buffer allocation failed"))?;
        buffer.resize(SMALL_BINARY_ROW_BYTES, 0);
        Ok(Self {
            buffer,
            _memory: memory,
        })
    }

    fn write(&mut self, writer: &mut dyn Write, value: &impl Serialize) -> io::Result<()> {
        match postcard::to_slice(value, &mut self.buffer) {
            Ok(bytes) => {
                if bytes.is_empty() {
                    return Err(invalid("native generation binary row empty"));
                }
                write_bytes(writer, bytes, MAX_ITEM)
            }
            Err(postcard::Error::SerializeBufferFull) => write_binary(writer, value),
            Err(_) => Err(invalid(
                "native binary canonical encoding differs or exceeds bound",
            )),
        }
    }
}

pub(crate) struct SqlitePreparedBase<'a> {
    tx: Transaction<'a>,
    root: Option<&'a RosterAttestationTrustRootV1>,
    snapshot_origin: Option<Arc<NativeSnapshotAuthority>>,
    header: BaseHeader,
    payload_bytes: u64,
    length: u64,
    _memory: VerificationMemory,
}

impl<'a> SqlitePreparedBase<'a> {
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(crate) fn prepare(
        conn: &'a mut Connection,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
        bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
        placement: PlacementResiliencePolicy,
        root: Option<&'a RosterAttestationTrustRootV1>,
        binding: [u8; 32],
        file_epoch: u64,
        checkpoint_epoch: u64,
        operation_sequence: u64,
        cut_binding: [u8; 32],
        block_bytes: usize,
        maximum: u64,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        Self::prepare_with_origin(
            conn,
            identity,
            members,
            bindings,
            placement,
            root,
            None,
            binding,
            file_epoch,
            checkpoint_epoch,
            operation_sequence,
            cut_binding,
            block_bytes,
            maximum,
            check,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_with_origin(
        conn: &'a mut Connection,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
        bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
        placement: PlacementResiliencePolicy,
        root: Option<&'a RosterAttestationTrustRootV1>,
        snapshot_origin: Option<Arc<NativeSnapshotAuthority>>,
        binding: [u8; 32],
        file_epoch: u64,
        checkpoint_epoch: u64,
        operation_sequence: u64,
        cut_binding: [u8; 32],
        block_bytes: usize,
        maximum: u64,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        check()?;
        if let Some(origin) = &snapshot_origin {
            origin.require_scope(binding, identity, members, root)?;
            origin.verify()?;
        }
        let memory = VerificationMemory::reserve(HEADER_MEMORY)?;
        conn.pragma_update(None, "query_only", true).map_err(db)?;
        let tx = conn.transaction().map_err(db)?;
        let (metadata, metadata_memory) =
            source::validate(&tx, identity, members, bindings, placement, root, check)?;
        let (sequence, digest, logical_time, watch_sequence) = metadata.machine;
        let global = |name| {
            tx.query_row(
                "SELECT val FROM lease_globals WHERE key=?1",
                [name],
                |row| row.get(0),
            )
            .map_err(db)
        };
        let context = Context {
            business: BusinessContext {
                identity,
                members: members.clone(),
                frontiers: NativeFrontiers(Arc::new(NativeFrontierValues {
                    applied: sql::read_applied_sync(&tx, identity)?,
                    membership: sql::read_membership_sync(&tx, identity)?,
                    sequence,
                    digest,
                    logical_time,
                    watch_sequence,
                    next_fence: global("next_fence")?,
                    next_credential: global("next_credential_id")?,
                    restore_revision: tx
                        .query_row(
                            "SELECT revision FROM restore_scan_state WHERE singleton=1",
                            [],
                            |row| row.get(0),
                        )
                        .map_err(db)?,
                    history: metadata.history,
                    activation: metadata
                        .v2
                        .map(|(identity, voters, profile)| NativeActivation {
                            identity,
                            voters,
                            profile,
                        }),
                    v1_activation: metadata
                        .v1
                        .map(|(identity, voters)| NativeV1Activation { identity, voters }),
                    roster_v1_namespace: metadata.roster_v1,
                    roster_v2_activation: metadata.roster_v2.map(|(identity, voters, profile)| {
                        NativeActivation {
                            identity,
                            voters,
                            profile,
                        }
                    }),
                    current_snapshot: sql::read_current_snapshot_sync(&tx, identity)?,
                })),
                counts: [0; 4],
                content: [[0; 32]; 4],
                roster: Some(RosterContext {
                    root: root.map(RosterAttestationTrustRootV1::fingerprint),
                    counts: [0; 2],
                    content: [[0; 32]; 2],
                    witness: metadata.witness,
                }),
            },
            log: LogContext {
                vote: sql::read_vote_sync(&tx, identity)?,
                committed: sql::read_committed_sync(&tx, identity)?,
                purged: sql::read_purged_sync(&tx, identity)?,
                count: 0,
                content: [0; 32],
                first: None,
                last: None,
            },
        };
        PrefixIdentity {
            binding,
            file_epoch,
            checkpoint_epoch,
            operation_sequence,
            frontiers: context.digest()?,
            length: block_bytes as u64,
            block_bytes,
            digest: [0; 32],
        }
        .blocks(maximum)?;
        let native_restore = snapshot_origin.as_deref().map(BaseRestore::from_origin);
        if let Some(origin) = &snapshot_origin {
            if ops::RestoreScanIncarnation::from_installed_sync(&tx)
                .map_err(stored)?
                .native_image()
                != origin.incarnation().native_image()
            {
                return Err(invalid(
                    "native SQL restore identity differs from original installation",
                ));
            }
        }
        let mut value = Self {
            tx,
            root,
            snapshot_origin,
            header: BaseHeader {
                binding,
                file_epoch,
                checkpoint_epoch,
                operation_sequence,
                block_bytes,
                cut_binding,
                native_restore,
                context,
            },
            payload_bytes: 0,
            length: 0,
            _memory: memory,
        };
        // Raw SQL encodings may contain large amounts of valid JSON padding.
        // Their reservation spans every allocating metadata read above. Prove
        // the retained header's size without another owned buffer before
        // releasing that scratch or cloning the context in the row passes.
        let mut sink = io::sink();
        let mut bounded = base::Output {
            writer: &mut sink,
            hash: Sha256::new(),
            position: 0,
            maximum: MAX_HEADER as u64,
        };
        serde_json::to_writer(&mut bounded, &value.header)
            .map_err(|_| invalid("native SQL generation header exceeds bound"))?;
        check()?;
        drop(metadata_memory);
        let mut rows = Counter { bytes: 0 };
        value.header.context = value.write_rows(&mut rows, check)?;
        catalog::validate_context_header_with_origin(
            &value.header.context,
            binding,
            identity,
            members,
            root,
            value.snapshot_origin.as_deref(),
        )?;
        let header = encode_header(&value.header)?;
        let mut counter = Counter { bytes: 0 };
        counter.write_all(base::MAGIC)?;
        write_bytes(&mut counter, &header, MAX_HEADER)?;
        counter.bytes = counter
            .bytes
            .checked_add(rows.bytes)
            .ok_or_else(|| invalid("native SQL generation extent overflow"))?;
        counter.write_all(END)?;
        value.payload_bytes = counter.bytes;
        let block = block_bytes as u64;
        value.length = counter
            .bytes
            .checked_add(block - 1)
            .map(|bytes| bytes / block * block)
            .ok_or_else(|| invalid("native SQL generation alignment overflow"))?;
        value.identity([0; 32])?.blocks(maximum)?;
        check()?;
        Ok(value)
    }

    fn identity(&self, digest: [u8; 32]) -> io::Result<PrefixIdentity> {
        Ok(PrefixIdentity {
            binding: self.header.binding,
            file_epoch: self.header.file_epoch,
            checkpoint_epoch: self.header.checkpoint_epoch,
            operation_sequence: self.header.operation_sequence,
            frontiers: self.header.context.digest()?,
            length: self.length,
            block_bytes: self.header.block_bytes,
            digest,
        })
    }

    fn key(
        &self,
        key: &SessionKey,
        fence: u64,
        writer: &mut dyn Write,
        context: &mut Context,
    ) -> io::Result<()> {
        let key_type = key.key_type.to_string();
        let arguments = params![
            key.tenant.as_str(),
            key.nf_kind.as_str(),
            key_type,
            key.stable_id.as_ref()
        ];
        let extent:Option<(usize,usize)> = self.tx.query_row("SELECT * FROM session_records WHERE tenant=?1 AND nf_kind=?2 AND key_type=?3 AND stable_id=?4",
            arguments,|row| {
                let mut total = 0usize;
                for column in 0..row.as_ref().column_count() {
                    if let ValueRef::Text(bytes)|ValueRef::Blob(bytes) = row.get_ref(column)? {
                        total = total.checked_add(bytes.len()).ok_or(rusqlite::Error::InvalidQuery)?;
                    }
                }
                let ValueRef::Blob(payload) = row.get_ref("payload")? else { return Err(rusqlite::Error::InvalidQuery); };
                Ok((payload.len(),total))
            }).optional().map_err(db)?;
        let (length, total) = extent.unwrap_or((0, 0));
        if length > crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES {
            return Err(invalid("native SQL record exceeds original payload bound"));
        }
        let _memory = row_memory(total)?;
        let record = ops::get_raw_sync(&self.tx, key).map_err(stored)?;
        let lease = self.tx.query_row("SELECT owner,fence,credential_id,acquired_at,expires_at_unix_ms,guard_expires_at,active FROM leases WHERE tenant=?1 AND nf_kind=?2 AND key_type=?3 AND stable_id=?4",
            arguments,|row| Ok((row.get::<_,String>(0)?,row.get::<_,u64>(1)?,row.get::<_,u64>(2)?,row.get::<_,Option<String>>(3)?,
                row.get::<_,i64>(4)?,row.get::<_,String>(5)?,row.get::<_,bool>(6)?))).optional().map_err(db)?;
        let lease =
            lease
                .map(
                    |(
                        owner,
                        fence,
                        credential_id,
                        acquired,
                        expires_at_unix_ms,
                        expires,
                        active,
                    )|
                     -> io::Result<_> {
                        Ok(NativeLease {
                            owner: ops::persisted_owner_id(owner).map_err(stored)?,
                            fence: crate::FenceToken::new(fence),
                            credential_id,
                            acquired_at: acquired.map(timestamp).transpose()?,
                            expires_at_unix_ms,
                            guard_expires_at: timestamp(expires)?,
                            active,
                        })
                    },
                )
                .transpose()?;
        let row = NativeKeyState {
            record,
            lease,
            fence,
            reserved: source::reserved(&self.tx, key)?,
        };
        validation::validate_key(key, &row, &context.business.frontiers)?;
        account(
            &mut context.business.counts[0],
            &mut context.business.content[0],
            row.row_fingerprint(0, key)?,
            validation::MAX_ITEMS,
        )?;
        writer.write_all(&[0])?;
        write_before(writer, None)?;
        write_binary(writer, &(key, Some(&row)))
    }

    fn rosters(
        &self,
        mut visit: impl FnMut(&roster::carrier::Hydration) -> io::Result<()>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        let context = &self.header.context.business;
        let scope = roster::fixed_scope(context.identity, &context.members);
        for (profile, table) in [
            (roster::Profile::V1, "consensus_protected_roster_rows"),
            (
                roster::Profile::V2,
                "consensus_protected_roster_v2_admissions",
            ),
        ] {
            if profile == roster::Profile::V2 && context.frontiers.roster_v2_activation.is_none() {
                continue;
            }
            let mut statement = self
                .tx
                .prepare(&format!(
                    "SELECT binding,canonical_record FROM {table} ORDER BY binding"
                ))
                .map_err(db)?;
            let mut rows = statement.query([]).map_err(db)?;
            while let Some(row) = rows.next().map_err(db)? {
                check()?;
                let binding =
                    crate::fenced_mutation_roster::RequestBindingKey::from_bytes(scalar(row, 0)?)
                        .map_err(|_| invalid("native SQL roster binding invalid"))?;
                let root = self
                    .root
                    .ok_or_else(|| invalid("native SQL roster configured root absent"))?;
                let hydrated = source::roster(
                    &self.tx,
                    context.identity,
                    profile,
                    binding,
                    bytes(row, 1, roster::carrier::MAX_CANONICAL_BYTES)?,
                    root,
                    &scope,
                )?;
                visit(&hydrated)?;
            }
        }
        check()
    }

    fn write_rows(
        &self,
        writer: &mut dyn Write,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Context> {
        let mut binary_rows = SqliteBinaryRows::new()?;
        let mut context = self.header.context.clone();
        context.business.counts = [0; 4];
        context.business.content = [[0; 32]; 4];
        context.log.count = 0;
        context.log.content = [0; 32];
        context.log.first = None;
        context.log.last = None;
        if let Some(roster) = &mut context.business.roster {
            roster.counts = [0; 2];
            roster.content = [[0; 32]; 2];
        }
        let mut keys = self.tx.prepare("SELECT tenant,nf_kind,key_type,stable_id,fence FROM key_fences ORDER BY tenant,nf_kind,key_type,stable_id").map_err(db)?;
        let mut rows = keys.query([]).map_err(db)?;
        while let Some(row) = rows.next().map_err(db)? {
            check()?;
            let _memory = row_memory(1024)?;
            let key = ops::persisted_session_key(
                row.get(0).map_err(db)?,
                row.get(1).map_err(db)?,
                row.get(2).map_err(db)?,
                row.get(3).map_err(db)?,
            )
            .map_err(stored)?;
            self.key(&key, row.get(4).map_err(db)?, writer, &mut context)?;
        }
        // A live V2 absence reservation can name a never-materialized key.
        // Its zero fence is a real native row, derived from signed admission.
        self.rosters(|row| {
            if let Some(key) = row.reserved_key() {
                let present:bool = self.tx.query_row("SELECT EXISTS(SELECT 1 FROM key_fences WHERE tenant=?1 AND nf_kind=?2 AND key_type=?3 AND stable_id=?4)",
                    params![key.tenant.as_str(),key.nf_kind.as_str(),key.key_type.to_string(),key.stable_id.as_ref()],|row| row.get(0)).map_err(db)?;
                if !present { self.key(key,0,writer,&mut context)?; }
            }
            Ok(())
        },check)?;
        if let Some(history) = context.business.frontiers.history {
            let mut statement = self.tx.prepare("SELECT request_id,ordinal,payload_digest,retained_until,response_json FROM consensus_fenced_transition_v2_receipts ORDER BY request_id").map_err(db)?;
            let mut rows = statement.query([]).map_err(db)?;
            while let Some(row) = rows.next().map_err(db)? {
                check()?;
                let id = cold::receipt_id(scalar(row, 0)?)?;
                let encoded = match row.get_ref(4).map_err(db)? {
                    ValueRef::Null => None,
                    _ => Some(bytes(
                        row,
                        4,
                        crate::fenced_transition::FENCED_TRANSITION_V2_RECEIPT_RESPONSE_MAX_BYTES,
                    )?),
                };
                let _memory = row_memory(encoded.map_or(0, <[u8]>::len))?;
                let receipt = NativeReceipt {
                    ordinal: row.get(1).map_err(db)?,
                    payload_digest: scalar(row, 2)?,
                    retained_until: timestamp(row.get(3).map_err(db)?)?,
                    response: encoded
                        .map(sql::decode_fenced_transition_v2_response)
                        .transpose()?
                        .map(Arc::new),
                    cold: None,
                };
                validation::validate_receipt(
                    context.business.identity,
                    &id,
                    &receipt,
                    &context.business.frontiers,
                    history,
                )?;
                account(
                    &mut context.business.counts[1],
                    &mut context.business.content[1],
                    receipt.row_fingerprint(1, &id)?,
                    crate::fenced_transition::FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_ENTRIES,
                )?;
                writer.write_all(&[1])?;
                write_before(writer, None)?;
                writer.write_all(&id.to_bytes())?;
                writer.write_all(&[1])?;
                let length = cold::write_receipt(&mut io::sink(), id, &receipt, check)?;
                writer.write_all(&(length as u32).to_le_bytes())?;
                if cold::write_receipt(writer, id, &receipt, check)? != length {
                    return Err(invalid("native SQL receipt extent changed"));
                }
            }
        }
        ordinary::write(&self.tx, writer, &mut binary_rows, &mut context, check)?;
        {
            let mut statement = self.tx.prepare("SELECT request_id,COALESCE(length(response_json),0) FROM consensus_fenced_transition_receipts ORDER BY request_id").map_err(db)?;
            let mut rows = statement.query([]).map_err(db)?;
            while let Some(row) = rows.next().map_err(db)? {
                check()?;
                let id = SessionConsensusRequestId::from_bytes(scalar(row, 0)?);
                let length: usize = row.get(1).map_err(db)?;
                if length > MAX_ITEM {
                    return Err(invalid(
                        "native SQL generic response exceeds original bound",
                    ));
                }
                let _memory = row_memory(length)?;
                let (payload_digest, retained_until, response) =
                    source::v1(&self.tx, context.business.identity, id)?;
                let receipt = NativeGenericReceipt::FencedV1(NativeV1Receipt {
                    payload_digest,
                    retained_until,
                    response: response.map(Box::new),
                });
                validation::validate_generic(&id, &receipt, &context.business.frontiers)?;
                account(
                    &mut context.business.counts[2],
                    &mut context.business.content[2],
                    receipt.row_fingerprint(2, &id)?,
                    validation::MAX_ITEMS,
                )?;
                writer.write_all(&[2])?;
                write_before(writer, None)?;
                binary_rows.write(writer, &(id, Some(&receipt)))?;
            }
        }
        notifications::write(&self.tx, writer, &mut binary_rows, &mut context, check)?;
        let mut logs = self.tx.prepare("SELECT log_index,configuration_epoch,term,entry_json FROM consensus_log ORDER BY log_index").map_err(db)?;
        let mut rows = logs.query([]).map_err(db)?;
        while let Some(row) = rows.next().map_err(db)? {
            check()?;
            let index: u64 = row.get(0).map_err(db)?;
            let encoded = bytes(row, 3, sql::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES)?;
            let facts = decode::inspect_log(
                encoded,
                index,
                context.business.identity,
                &context.business.members,
                check,
            )?;
            if row.get::<_, u64>(1).map_err(db)?
                != context.business.identity.configuration_epoch().get()
                || row.get::<_, u64>(2).map_err(db)? != facts.facts.id.leader_id.term
            {
                return Err(invalid("native SQL physical log projection differs"));
            }
            account(
                &mut context.log.count,
                &mut context.log.content,
                facts.content,
                log::MAX_RETAINED_LOG_ENTRIES,
            )?;
            context.log.first.get_or_insert(facts.facts.id);
            context.log.last = Some(facts.facts.id);
            writer.write_all(&[4])?;
            writer.write_all(&index.to_le_bytes())?;
            write_before(writer, None)?;
            writer.write_all(&[1])?;
            write_bytes(writer, encoded, sql::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES)?;
        }
        let mut partitions = self
            .tx
            .prepare("SELECT partition FROM consensus_protected_roster_floors ORDER BY partition")
            .map_err(db)?;
        let mut rows = partitions.query([]).map_err(db)?;
        while let Some(row) = rows.next().map_err(db)? {
            check()?;
            let _memory = row_memory(1024)?;
            let key = ProductionFloorKey::from_bytes(scalar(row, 0)?)
                .map_err(|_| invalid("native SQL floor key invalid"))?;
            let (floor, cursor) = source::partition(&self.tx, context.business.identity, key)?;
            let partition = roster::Partition { floor, cursor };
            let roster = context
                .business
                .roster
                .as_mut()
                .ok_or_else(|| invalid("native SQL roster context absent"))?;
            account(
                &mut roster.counts[1],
                &mut roster.content[1],
                partition.row_fingerprint(5, &key.as_bytes().as_slice())?,
                validation::MAX_ITEMS,
            )?;
            writer.write_all(&[5])?;
            write_before(writer, None)?;
            writer.write_all(key.as_bytes())?;
            writer.write_all(&1u64.to_le_bytes())?;
            writer.write_all(&0u64.to_le_bytes())?;
            writer.write_all(&[0, 1])?;
            let length = roster::frame::write_partition(&mut io::sink(), key, &partition)?;
            writer.write_all(&length.to_le_bytes())?;
            if roster::frame::write_partition(writer, key, &partition)? != length {
                return Err(invalid("native SQL partition extent changed"));
            }
        }
        self.rosters(
            |row| {
                let roster = context
                    .business
                    .roster
                    .as_mut()
                    .ok_or_else(|| invalid("native SQL roster context absent"))?;
                account(
                    &mut roster.counts[0],
                    &mut roster.content[0],
                    roster::Row::hydration_fingerprint(row)?,
                    validation::MAX_ITEMS,
                )?;
                writer.write_all(&[6])?;
                write_before(writer, None)?;
                writer.write_all(&row.binding().to_bytes())?;
                writer.write_all(&1u64.to_le_bytes())?;
                writer.write_all(&0u64.to_le_bytes())?;
                writer.write_all(&[0, 1])?;
                let length = roster::frame::write_hydrated(&mut io::sink(), row)?;
                writer.write_all(&length.to_le_bytes())?;
                if roster::frame::write_hydrated(writer, row)? != length {
                    return Err(invalid("native SQL roster extent changed"));
                }
                Ok(())
            },
            check,
        )?;
        // Match BusinessProof::generation_context after counting every row.
        // A rootless image without roster state has no roster context at all.
        if context.business.roster.as_ref().is_some_and(|roster| {
            roster.root.is_none() && roster.counts == [0; 2] && roster.witness.is_none()
        }) && !context.business.frontiers.roster_v1_namespace
            && context.business.frontiers.roster_v2_activation.is_none()
        {
            context.business.roster = None;
        }
        check()?;
        Ok(context)
    }

    pub(crate) fn write_to(
        &self,
        writer: &mut dyn Write,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<PrefixIdentity> {
        check()?;
        if let Some(origin) = &self.snapshot_origin {
            origin.verify()?;
        }
        let mut output = base::Output {
            writer,
            hash: Sha256::new(),
            position: 0,
            maximum: self.length,
        };
        output.write_all(base::MAGIC)?;
        let header = encode_header(&self.header)?;
        write_bytes(&mut output, &header, MAX_HEADER)?;
        if self.write_rows(&mut output, check)? != self.header.context {
            return Err(invalid("native SQL generation source changed"));
        }
        output.write_all(END)?;
        if output.position != self.payload_bytes {
            return Err(invalid("native SQL generation payload extent changed"));
        }
        let padding = [0; 4096];
        while output.position < self.length {
            check()?;
            let count = usize::try_from(self.length - output.position)
                .unwrap_or(usize::MAX)
                .min(padding.len());
            output.write_all(&padding[..count])?;
        }
        check()?;
        if let Some(origin) = &self.snapshot_origin {
            origin.verify()?;
        }
        self.identity(output.hash.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct Counted<'a, T> {
        calls: &'a Cell<usize>,
        value: T,
    }

    impl<T: Serialize> Serialize for Counted<'_, T> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.calls.set(self.calls.get() + 1);
            self.value.serialize(serializer)
        }
    }

    #[test]
    fn native_sql_small_row_encoding_avoids_duplicate_traversal() {
        let calls = Cell::new(0);
        let row = Counted {
            calls: &calls,
            value: (vec![0xa5_u8; 512], 123_u64, "native SQL row"),
        };
        let expected = postcard::to_stdvec(&row.value).unwrap();
        let mut actual = Vec::new();
        SqliteBinaryRows::new()
            .unwrap()
            .write(&mut actual, &row)
            .unwrap();
        let mut framed = (expected.len() as u32).to_le_bytes().to_vec();
        framed.extend_from_slice(&expected);
        assert_eq!(actual, framed);
        eprintln!(
            "native_sql_small_row serialized_bytes={} serialization_calls={}",
            expected.len(),
            calls.get()
        );
        assert_eq!(
            calls.get(),
            1,
            "small SQL rows must serialize once per pass"
        );
    }

    struct FailAfter(usize);

    impl Write for FailAfter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0 == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "fixed fault",
                ));
            }
            let count = self.0.min(bytes.len());
            self.0 -= count;
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct CannotSerialize;

    impl Serialize for CannotSerialize {
        fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("fixed serialization fault"))
        }
    }

    #[test]
    fn native_sql_row_buffer_preserves_exact_frames_and_write_failures() {
        let mut rows = SqliteBinaryRows::new().unwrap();
        for length in [0, 1, 512, 4090, 4096, 8192] {
            let row = (vec![0xa5_u8; length], 123_u64, "native SQL row");
            let mut expected = Vec::new();
            write_binary(&mut expected, &row).unwrap();
            let mut actual = Vec::new();
            rows.write(&mut actual, &row).unwrap();
            assert_eq!(actual, expected);
            for limit in [0, 1, 3, 4, 17, expected.len() - 1] {
                let error = rows.write(&mut FailAfter(limit), &row).unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            }
        }
        let mut untouched = Vec::new();
        assert!(rows.write(&mut untouched, &()).is_err());
        assert!(rows.write(&mut untouched, &CannotSerialize).is_err());
        assert!(untouched.is_empty());
    }

    #[test]
    fn native_sql_row_buffer_reuses_one_bounded_allocation() {
        let row = (vec![0xa5_u8; 512], 123_u64, "native SQL row");
        let memory = allocation_counter::measure(|| {
            let mut rows = SqliteBinaryRows::new().unwrap();
            for _ in 0..128 {
                rows.write(&mut io::sink(), &row).unwrap();
            }
        });
        eprintln!(
            "native_sql_row_buffer rows=128 allocations={} bytes={} retained={}",
            memory.count_total, memory.bytes_total, memory.bytes_current
        );
        assert_eq!(memory.count_total, 1);
        assert_eq!(memory.bytes_total, SMALL_BINARY_ROW_BYTES as u64);
        assert_eq!(memory.bytes_current, 0);
    }
}
