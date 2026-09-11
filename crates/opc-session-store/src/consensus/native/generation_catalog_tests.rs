use super::super::super::changes::tests::{apply, clock, command, fixture, request, time};
use super::*;
use crate::sqlite::consensus::wal::Operation;
use opc_consensus::engine::{CommittedLeaderId, SnapshotMeta};
use std::fs::OpenOptions;
use std::path::PathBuf;

#[path = "generation_catalog_lifecycle_tests.rs"]
mod lifecycle;

#[path = "generation_roster_tests.rs"]
mod roster_tests;

const BLOCK: usize = 64 * 1024;
const MAXIMUM: u64 = 32 * BLOCK as u64;
const ROOT: [u8; 32] = [0xBD; 32];
const CUT: [u8; 32] = [0xCE; 32];

#[test]
fn native_selected_notification_read_uses_one_bounded_decode() {
    use crate::consensus::native::notification::NativeNotification;

    let (original, _, _) = fixture();
    let (_files, catalog) = Files::new(&original);
    let indexed = &catalog.rows.notifications[0];
    let bytes = row_bytes(&catalog, indexed);
    let selected = |row| {
        NativeNotification::from_admitted_range(
            row,
            Arc::clone(&catalog.source),
            indexed.range.offset,
            indexed.range.length,
        )
        .unwrap()
    };
    let row = selected(indexed.row);
    let frontiers = &original.business.frontiers;
    assert_eq!(
        postcard::to_allocvec(row.read(frontiers, &|| Ok(())).unwrap().entry()).unwrap(),
        bytes,
        "selected reads preserve the complete independently encoded notification",
    );
    for field in 0..3 {
        let mut changed = indexed.row;
        match field {
            0 => changed.content[0] ^= 1,
            1 => changed.facts.sequence += 1,
            _ => changed.facts.timestamp = time(0),
        }
        assert!(selected(changed).read(frontiers, &|| Ok(())).is_err());
    }
    let baseline = allocation_counter::measure(|| {
        drop(decode::owned_notification(&bytes, indexed.row, frontiers, &|| Ok(())).unwrap());
    });
    let actual = allocation_counter::measure(|| {
        drop(row.read(frontiers, &|| Ok(())).unwrap());
    });
    eprintln!(
        "native_selected_notification_decode single_bytes={} selected_bytes={} input_bytes={} single_allocations={} selected_allocations={}",
        baseline.bytes_total, actual.bytes_total, bytes.len(), baseline.count_total, actual.count_total,
    );
    assert_eq!(actual.bytes_current, 0);
    assert!(
        actual.bytes_total <= baseline.bytes_total + bytes.len() as u64,
        "selected reads allocate one bounded input and one complete decode/copy, without decoding the same authenticated bytes again",
    );
}

#[test]
fn native_selected_log_read_uses_one_bounded_decode() {
    let (original, _, _) = fixture();
    let (_files, catalog) = Files::new(&original);
    let cold = catalog.into_storage(&|| Ok(())).unwrap();
    let hot_capture = original.capture_log_read().unwrap();
    let selected_capture = cold.capture_log_read().unwrap();
    for (index, hot) in &original.log.entries {
        let selected = cold.log.entries.get(index).unwrap();
        assert!(selected.is_cold());
        let bytes = hot.encoded_for_test().unwrap();
        let expected = hot_capture
            .resolve(*index, Some(index + 1), Some(1), &|| Ok(()))
            .unwrap();
        let actual = selected_capture
            .resolve(*index, Some(index + 1), Some(1), &|| Ok(()))
            .unwrap();
        assert!(
            actual.entries() == expected.entries(),
            "complete selected and resident results differ"
        );
        drop(actual);
        drop(expected);
        let authority = allocation_counter::measure(|| {
            selected
                .validate_context(
                    *index,
                    original.business.identity,
                    &original.business.members,
                )
                .unwrap();
        });
        let baseline = allocation_counter::measure(|| {
            drop(
                hot_capture
                    .resolve(*index, Some(index + 1), Some(1), &|| Ok(()))
                    .unwrap(),
            );
        });
        let actual = allocation_counter::measure(|| {
            drop(
                selected_capture
                    .resolve(*index, Some(index + 1), Some(1), &|| Ok(()))
                    .unwrap(),
            );
        });
        eprintln!("native_selected_log_decode index={index} resident_bytes={} selected_bytes={} authority_bytes={} input_bytes={} resident_allocations={} selected_allocations={}", baseline.bytes_total, actual.bytes_total, authority.bytes_total, bytes.len(), baseline.count_total, actual.count_total);
        assert_eq!(actual.bytes_current, 0);
        assert!(actual.bytes_total <= baseline.bytes_total + authority.bytes_total + bytes.len() as u64,
            "selected reads allocate the same complete bounded decode/copy plus their exact input and original scope check, without decoding the same log again");
    }
}

#[test]
fn native_selected_log_owned_read_rejects_changed_facts_scope_and_cancellation() {
    let (original, _, _) = fixture();
    let (_files, catalog) = Files::new(&original);
    let identity = original.business.identity;
    let members = &original.business.members;
    for (index, indexed) in &catalog.rows.logs {
        let selected = |row| {
            log::NativeLogEntry::from_admitted_range(
                row,
                Arc::clone(&catalog.source),
                indexed.range.offset,
                indexed.range.length,
                identity,
                members,
            )
            .unwrap()
        };
        let row = selected(indexed.row);
        let actual = row
            .read_owned(*index, identity, members, &|| Ok(()))
            .unwrap();
        assert!(actual.entry() == &original.log.entries[index].resident().unwrap().entry);
        drop(actual);
        for field in 0..3 {
            let mut changed = indexed.row;
            match field {
                0 => changed.content[0] ^= 1,
                1 => {
                    changed.facts.id =
                        LogId::new(CommittedLeaderId::new(2, *members.first().unwrap()), *index);
                }
                _ => {
                    changed.facts.membership = match changed.facts.membership {
                        Some(_) => None,
                        None => Some([0; 32]),
                    };
                }
            }
            assert!(selected(changed)
                .read_owned(*index, identity, members, &|| Ok(()))
                .is_err());
        }
        let mut wrong_members = members.clone();
        wrong_members.pop_first();
        assert!(row
            .read_owned(*index, identity, &wrong_members, &|| Ok(()))
            .is_err());
        assert!(row
            .read_owned(index + 1, identity, members, &|| Ok(()))
            .is_err());
        let error = row
            .read_owned(*index, identity, members, &|| {
                Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
            })
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    }
}

#[test]
fn native_catalog_generic_conversion_bounds_verified_block_reads_and_preserves_every_row() {
    let (mut original, _, _) = fixture();
    for first in (2..1026).step_by(64) {
        let entries = (first..first + 64)
            .map(|index| clock(index, time(2)))
            .collect::<Vec<_>>();
        apply(&mut original, &entries);
    }
    assert_eq!(original.business.generic_receipts.len(), 1024);
    let (files, catalog) = Files::new(&original);
    let selected = files.owner.current();
    let blocks = selected.identity().length / BLOCK as u64;
    assert!(blocks >= 4, "exercise several authenticated blocks");
    let before = selected.blocks_read();
    let started = std::time::Instant::now();
    let cold = catalog.into_storage(&|| Ok(())).unwrap();
    let reads = selected.blocks_read() - before;
    eprintln!(
        "native_generic_conversion rows=1024 blocks={blocks} block_reads={reads} elapsed_us={}",
        started.elapsed().as_micros(),
    );
    cold.validate_image().unwrap();
    assert_eq!(
        Version::capture(&cold).unwrap().context_digest().unwrap(),
        Version::capture(&original)
            .unwrap()
            .context_digest()
            .unwrap(),
    );
    assert_eq!(cold.business.generic_receipts.len(), 1024);
    for (id, expected) in &original.business.generic_receipts {
        assert_eq!(
            serde_json::to_vec(&**cold.business.generic_receipts.get(id).unwrap()).unwrap(),
            serde_json::to_vec(&**expected).unwrap(),
            "the complete independent typed response remains exact",
        );
    }
    // Conversion and complete business/log admission may revisit blocks, but
    // must remain within four complete scans rather than one block per row.
    assert!(
        reads <= 4 * blocks,
        "selected generic conversion rereads blocks"
    );
}

struct Files {
    _directory: tempfile::TempDir,
    path: PathBuf,
    owner: VerifiedAppendOwner,
    version: Version,
    cut: [u8; 32],
}

impl Files {
    fn new(storage: &NativeStorage) -> (Self, Catalog) {
        storage.validate_image().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("catalog.opc");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let prepared = PreparedBase::prepare(
            storage,
            crate::consensus::native::generation::BaseParameters {
                binding: ROOT,
                file_epoch: 4,
                checkpoint_epoch: 11,
                operation_sequence: 18,
                cut_binding: CUT,
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
                identity: storage.business.identity,
                members: &storage.business.members,
                roster_root: storage.business.roster_root.clone(),
            },
            CUT,
            &|| Ok(()),
        )
        .unwrap();
        let files = Self {
            _directory: directory,
            path,
            owner,
            version: Version::capture(storage).unwrap(),
            cut: CUT,
        };
        exact(&catalog, storage);
        (files, catalog)
    }

    fn prepare(&self, storage: &mut NativeStorage, sequence: u64) -> PreparedDelta {
        let checkpoint = self.owner.current().identity().checkpoint_epoch + 1;
        PreparedDelta::prepare(
            self.owner.current(),
            &self.version,
            checkpoint,
            sequence,
            [checkpoint as u8; 32],
            storage.take_changes().unwrap(),
            &|| Ok(()),
        )
        .unwrap()
    }

    fn append(&mut self, storage: &mut NativeStorage, sequence: u64) -> Catalog {
        let prepared = self.prepare(storage, sequence);
        prepared.append(&mut self.owner, &|| Ok(())).unwrap();
        self.version = prepared.target_version();
        self.cut = prepared.header.cut_binding;
        let (_, catalog) = Catalog::open(
            &self.path,
            self.owner.current().identity(),
            MAXIMUM,
            crate::consensus::native::generation::CatalogScope {
                identity: storage.business.identity,
                members: &storage.business.members,
                roster_root: storage.business.roster_root.clone(),
            },
            self.cut,
            &|| Ok(()),
        )
        .unwrap();
        exact(&catalog, storage);
        catalog
    }

    fn bytes(&self) -> Vec<u8> {
        std::fs::read(&self.path).unwrap()
    }
}

fn row_bytes<T>(catalog: &Catalog, row: &Indexed<T>) -> Vec<u8> {
    let mut bytes = vec![0; row.range.length as usize];
    catalog
        .source
        .read_exact_at(row.range.offset, &mut bytes)
        .unwrap();
    bytes
}

// Compare every encoded field with the independently validated full state.
// Counts, summary hashes and response metadata alone are not this oracle.
fn exact(catalog: &Catalog, storage: &NativeStorage) {
    storage.validate_image().unwrap();
    assert!(catalog.rows.context == Version::capture(storage).unwrap().context());
    assert_eq!(catalog.rows.keys.len(), storage.business.keys.len());
    for (key, row) in &storage.business.keys {
        let indexed = &catalog.rows.keys[&facts::KeyId::of(key).unwrap()];
        binary::compare(&(key, Some(&**row)), &row_bytes(catalog, indexed)).unwrap();
    }
    assert_eq!(catalog.rows.receipts.len(), storage.business.receipts.len());
    for (id, row) in &storage.business.receipts {
        let mut expected = Vec::new();
        cold::write_receipt(&mut expected, *id, row, &|| Ok(())).unwrap();
        assert_eq!(row_bytes(catalog, &catalog.rows.receipts[id]), expected);
    }
    assert_eq!(
        catalog.rows.generic.len(),
        storage.business.generic_receipts.len()
    );
    for (id, row) in &storage.business.generic_receipts {
        binary::compare(
            &(id, Some(&**row)),
            &row_bytes(catalog, &catalog.rows.generic[id]),
        )
        .unwrap();
    }
    assert_eq!(
        catalog.rows.notifications.len(),
        storage.business.notifications.len()
    );
    for (indexed, row) in catalog
        .rows
        .notifications
        .iter()
        .zip(&storage.business.notifications)
    {
        binary::compare(
            row.read(&storage.business.frontiers, &|| Ok(()))
                .unwrap()
                .entry(),
            &row_bytes(catalog, indexed),
        )
        .unwrap();
    }
    assert_eq!(catalog.rows.logs.len(), storage.log.entries.len());
    for (index, row) in &storage.log.entries {
        assert_eq!(
            row_bytes(catalog, &catalog.rows.logs[index]),
            row.read_bytes(
                storage.business.identity,
                &storage.business.members,
                &|| Ok(())
            )
            .unwrap()
            .bytes()
        );
    }
    assert_eq!(
        catalog.rows.rosters.rows.len(),
        storage.business.roster.rows.len()
    );
    for (binding, row) in &storage.business.roster.rows {
        let root = storage.business.roster_root.as_deref().unwrap();
        let indexed = &catalog.rows.rosters.rows[binding];
        let mut expected = Vec::new();
        roster::frame::write_row_detached(
            &mut expected,
            row,
            root,
            &roster::fixed_scope(storage.business.identity, &storage.business.members),
            &|| Ok(()),
        )
        .unwrap();
        let mut actual = vec![0; indexed.range.length as usize];
        catalog
            .source
            .read_exact_at(indexed.range.offset, &mut actual)
            .unwrap();
        assert_eq!(actual, expected);
    }
    assert!(catalog.resident_index_allocation_bound().unwrap() >= size_of::<Catalog>());
}

struct Wire<H> {
    header: H,
    body: Vec<u8>,
    body_offset: usize,
}
impl<H: serde::de::DeserializeOwned + Serialize> Wire<H> {
    fn read(bytes: &[u8]) -> Self {
        let length = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let end = bytes.iter().rposition(|byte| *byte != 0).unwrap() + 1;
        assert_eq!(&bytes[end - END.len()..end], END);
        Self {
            header: serde_json::from_slice(&bytes[12..12 + length]).unwrap(),
            body: bytes[12 + length..end].to_vec(),
            body_offset: 12 + length,
        }
    }

    fn replace(&mut self, range: Range, encoded: &[u8]) {
        let offset = range.offset as usize - self.body_offset;
        let mut value = (encoded.len() as u32).to_le_bytes().to_vec();
        value.extend_from_slice(encoded);
        self.body
            .splice(offset - 4..offset + range.length as usize, value);
    }

    fn encode(&self, magic: &[u8; 8], mut prefix: Vec<u8>) -> Vec<u8> {
        prefix.extend_from_slice(magic);
        write_bytes(
            &mut prefix,
            &serde_json::to_vec(&self.header).unwrap(),
            MAX_HEADER,
        )
        .unwrap();
        prefix.extend_from_slice(&self.body);
        prefix.resize(prefix.len().div_ceil(BLOCK) * BLOCK, 0);
        prefix
    }
}

fn replace_hash(summary: &mut [u8; 32], before: [u8; 32], after: [u8; 32]) {
    for ((slot, before), after) in summary.iter_mut().zip(before).zip(after) {
        *slot ^= before ^ after;
    }
}

fn rebound(bytes: &[u8], mut identity: PrefixIdentity, context: &Context) -> PrefixIdentity {
    identity.digest = Sha256::digest(bytes).into();
    identity.length = bytes.len() as u64;
    identity.frontiers = context.digest().unwrap();
    identity
}

fn reject(
    bytes: &[u8],
    identity: PrefixIdentity,
    storage: &NativeStorage,
    cut: [u8; 32],
) -> String {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("crafted.opc");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    match Catalog::open(
        &path,
        identity,
        MAXIMUM,
        crate::consensus::native::generation::CatalogScope {
            identity: storage.business.identity,
            members: &storage.business.members,
            roster_root: storage.business.roster_root.clone(),
        },
        cut,
        &|| Ok(()),
    ) {
        Ok(_) => panic!("crafted catalog unexpectedly admitted"),
        Err(error) => error.to_string(),
    }
}

fn snapshot(storage: &NativeStorage, index: u64, suffix: &str) -> sql::CurrentSnapshot {
    (
        SnapshotMeta {
            last_log_id: Some(storage.log.entries[&index].id()),
            last_membership: storage.business.membership(),
            snapshot_id: format!("{}{suffix}", snapshot_prefix(ROOT)),
        },
        format!("snapshot-{}.opc", uuid::Uuid::new_v4()),
        [0xDF; 32],
        100,
    )
}

#[test]
fn native_catalog_complete_base_deltas_and_expiry_preserve_exact_owned_ranges() {
    let (mut storage, first, outcome) = fixture();
    let original = storage.clone();
    let (mut files, old) = Files::new(&storage);
    storage.begin_changes().unwrap();
    apply(
        &mut storage,
        &[
            command(2, &request(2, Some(&outcome)), time(2), false),
            clock(3, time(3)),
        ],
    );
    let middle_state = storage.clone();
    let middle = files.append(&mut storage, 21);
    let expired_at = retention_deadline(time(1)).unwrap();
    apply(
        &mut storage,
        &[command(4, &first, expired_at, false), clock(5, expired_at)],
    );
    assert_eq!(
        storage.business.status(&first).unwrap(),
        FencedTransitionV2Status::Expired
    );
    assert!(storage.business.receipts[&first.request_id()]
        .response
        .is_none());
    let latest = files.append(&mut storage, 24);
    assert_eq!(latest.identity().checkpoint_epoch, 13);
    exact(&old, &original);
    exact(&middle, &middle_state);
    // Name replacement cannot retarget any catalog's retained descriptor.
    std::fs::rename(&files.path, files.path.with_extension("retained")).unwrap();
    std::fs::write(&files.path, b"replacement").unwrap();
    exact(&old, &original);
    exact(&middle, &middle_state);
    exact(&latest, &storage);
}

#[test]
fn native_catalog_same_sequence_snapshots_reject_clearing_and_regression_with_rebound_hashes() {
    let (mut storage, _, _) = fixture();
    let (mut files, _) = Files::new(&storage);
    storage.begin_changes().unwrap();
    let entry = clock(2, time(2));
    storage
        .log
        .project(
            &Operation::Append(vec![serde_json::to_vec(&entry).unwrap().into()]),
            &storage.business,
            None,
        )
        .unwrap();
    storage
        .log
        .project(
            &Operation::Committed(Some(entry.log_id)),
            &storage.business,
            None,
        )
        .unwrap();
    let logged = files.append(&mut storage, 20);
    storage.business.apply(&[entry]).unwrap();
    let applied = files.append(&mut storage, 20);
    let older = snapshot(&storage, 1, "older");
    storage
        .business
        .set_current_snapshot(older.clone())
        .unwrap();
    let selected = files.append(&mut storage, 20);
    let newer = snapshot(&storage, 2, "newer");
    storage
        .business
        .set_current_snapshot(newer.clone())
        .unwrap();
    let advanced = files.append(&mut storage, 20);
    for catalog in [&logged, &applied, &selected, &advanced] {
        assert_eq!(catalog.identity().operation_sequence, 20);
    }
    assert_eq!(
        [
            logged.identity().checkpoint_epoch,
            applied.identity().checkpoint_epoch,
            selected.identity().checkpoint_epoch,
            advanced.identity().checkpoint_epoch
        ],
        [12, 13, 14, 15]
    );
    assert!(
        storage
            .business
            .set_current_snapshot(older.clone())
            .is_err(),
        "live path shares the monotonic predicate"
    );
    let mut same_index = newer;
    same_index.0.snapshot_id = format!("{}same-index", snapshot_prefix(ROOT));
    same_index.1 = format!("snapshot-{}.opc", uuid::Uuid::new_v4());
    storage.business.set_current_snapshot(same_index).unwrap();
    let previous = files.bytes();
    let start = previous.len();
    let prepared = files.prepare(&mut storage, 20);
    let mut payload = Vec::new();
    prepared.write_payload(&mut payload, &|| Ok(())).unwrap();
    for candidate in [None, Some(older)] {
        let mut wire = Wire::<Header>::read(&payload);
        wire.header.after.business.frontiers.current_snapshot = candidate;
        // Both isolated after-contexts are valid, and no row or table hash
        // changes. Only the transition from the selected predecessor is bad.
        validate_context_header(
            &wire.header.after,
            ROOT,
            storage.business.identity,
            &storage.business.members,
        )
        .unwrap();
        let bytes = wire.encode(MAGIC, previous.clone());
        let mut identity = files.owner.current().identity();
        identity.checkpoint_epoch += 1;
        let identity = rebound(&bytes, identity, &wire.header.after);
        let error = reject(&bytes, identity, &storage, prepared.header.cut_binding);
        assert!(
            error.contains("selected snapshot cleared")
                || error.contains("selected snapshot regressed"),
            "{error}"
        );
    }
    prepared.append(&mut files.owner, &|| Ok(())).unwrap();
    let (_, catalog) = Catalog::open(
        &files.path,
        files.owner.current().identity(),
        MAXIMUM,
        crate::consensus::native::generation::CatalogScope {
            identity: storage.business.identity,
            members: &storage.business.members,
            roster_root: storage.business.roster_root.clone(),
        },
        prepared.header.cut_binding,
        &|| Ok(()),
    )
    .unwrap();
    assert!(catalog.identity().length > start as u64);
    exact(&catalog, &storage);
}

#[test]
fn native_catalog_truncated_and_net_absent_logs_require_unique_delta_indexes() {
    let (mut storage, _, _) = fixture();
    let pending = [clock(2, time(2)), clock(3, time(3))];
    storage
        .log
        .project(
            &Operation::Append(
                pending
                    .iter()
                    .map(|entry| serde_json::to_vec(entry).unwrap().into())
                    .collect(),
            ),
            &storage.business,
            None,
        )
        .unwrap();
    let (mut files, old) = Files::new(&storage);
    let original = storage.clone();
    storage.begin_changes().unwrap();
    storage
        .log
        .project(
            &Operation::Truncate(pending[0].log_id),
            &storage.business,
            None,
        )
        .unwrap();
    files.append(&mut storage, 19);
    storage
        .log
        .project(
            &Operation::Append(vec![serde_json::to_vec(&pending[0]).unwrap().into()]),
            &storage.business,
            None,
        )
        .unwrap();
    storage
        .log
        .project(
            &Operation::Truncate(pending[0].log_id),
            &storage.business,
            None,
        )
        .unwrap();
    let prefix = files.bytes();
    let prepared = files.prepare(&mut storage, 21);
    assert_eq!(prepared.header.changed, [0, 0, 0, 0, 1]);
    let mut payload = Vec::new();
    prepared.write_payload(&mut payload, &|| Ok(())).unwrap();
    let mut wire = Wire::<Header>::read(&payload);
    let frame = wire.body[..wire.body.len() - END.len()].to_vec();
    wire.body.splice(0..0, frame);
    wire.header.changed[4] = 2;
    let bytes = wire.encode(MAGIC, prefix);
    let mut identity = files.owner.current().identity();
    identity.checkpoint_epoch += 1;
    identity.operation_sequence = 21;
    let error = reject(
        &bytes,
        rebound(&bytes, identity, &wire.header.after),
        &storage,
        wire.header.cut_binding,
    );
    assert!(error.contains("repeats a changed log index"), "{error}");
    prepared.append(&mut files.owner, &|| Ok(())).unwrap();
    let (_, catalog) = Catalog::open(
        &files.path,
        files.owner.current().identity(),
        MAXIMUM,
        crate::consensus::native::generation::CatalogScope {
            identity: storage.business.identity,
            members: &storage.business.members,
            roster_root: storage.business.roster_root.clone(),
        },
        prepared.header.cut_binding,
        &|| Ok(()),
    )
    .unwrap();
    exact(&catalog, &storage);
    exact(&old, &original);
}

#[test]
fn native_catalog_recomputes_base_counts_complete_ids_and_global_ordinals() {
    let (mut storage, _, outcome) = fixture();
    apply(
        &mut storage,
        &[command(2, &request(2, Some(&outcome)), time(2), false)],
    );
    let (files, catalog) = Files::new(&storage);
    let original = files.bytes();
    for case in 0..5 {
        let mut wire = Wire::<BaseHeader>::read(&original);
        match case {
            0 => wire.header.context.business.content[0][31] ^= 1,
            1 => wire.header.context.business.counts[0] += 1,
            2 => {
                assert!(wire
                    .header
                    .context
                    .business
                    .members
                    .remove(&SessionConsensusNodeId::new(9).unwrap()));
            }
            3 => {
                let (id, row) = storage
                    .business
                    .receipts
                    .iter()
                    .find(|(_, row)| row.ordinal == 2)
                    .unwrap();
                let mut changed = (**row).clone();
                changed.ordinal = 1;
                validation::validate_receipt(
                    storage.business.identity,
                    id,
                    &changed,
                    &storage.business.frontiers,
                    storage.business.history().unwrap(),
                )
                .unwrap();
                let mut encoded = Vec::new();
                cold::write_receipt(&mut encoded, *id, &changed, &|| Ok(())).unwrap();
                wire.replace(catalog.rows.receipts[id].range, &encoded);
                replace_hash(
                    &mut wire.header.context.business.content[1],
                    catalog.rows.receipts[id].row.content,
                    changes::fingerprint(1, id, &changed).unwrap(),
                );
            }
            4 => {
                let indexed = catalog.rows.keys.values().next().unwrap();
                let start = indexed.range.offset as usize - wire.body_offset - 6;
                let end = indexed.range.offset as usize - wire.body_offset
                    + indexed.range.length as usize;
                let frame = wire.body[start..end].to_vec();
                wire.body.splice(start..start, frame);
                wire.header.context.business.counts[0] += 1;
                replace_hash(
                    &mut wire.header.context.business.content[0],
                    [0; 32],
                    indexed.row.content,
                );
            }
            _ => unreachable!(),
        }
        let bytes = wire.encode(base::MAGIC, Vec::new());
        let error = reject(
            &bytes,
            rebound(&bytes, catalog.identity(), &wire.header.context),
            &storage,
            CUT,
        );
        if case == 3 {
            assert!(error.contains("repeats a receipt ordinal"), "{error}");
        }
        if case == 4 {
            assert!(
                error.contains("duplicate or different predecessor"),
                "{error}"
            );
        }
    }
}

#[test]
fn native_catalog_complete_log_decode_rejects_false_witnesses_term_splices_and_holes() {
    let (mut storage, _, _) = fixture();
    let pending = [clock(2, time(2)), clock(3, time(3))];
    storage
        .log
        .project(
            &Operation::Append(
                pending
                    .iter()
                    .map(|entry| serde_json::to_vec(entry).unwrap().into())
                    .collect(),
            ),
            &storage.business,
            None,
        )
        .unwrap();
    let (files, catalog) = Files::new(&storage);
    let original = files.bytes();
    for case in 0..4 {
        let mut wire = Wire::<BaseHeader>::read(&original);
        let index = if case == 0 { 0 } else { 2 };
        let indexed = &catalog.rows.logs[&index];
        let mut entry = storage.log.entries[&index]
            .resident()
            .unwrap()
            .entry
            .clone();
        match case {
            0 => entry.payload = EntryPayload::Blank,
            1 => entry.log_id.index += 1,
            2 => {
                entry.log_id = LogId::new(
                    CommittedLeaderId::new(2, SessionConsensusNodeId::new(7).unwrap()),
                    2,
                )
            }
            3 => {
                let start = indexed.range.offset as usize - wire.body_offset - 15;
                let end = indexed.range.offset as usize - wire.body_offset
                    + indexed.range.length as usize;
                wire.body.drain(start..end);
                wire.header.context.log.count -= 1;
                replace_hash(
                    &mut wire.header.context.log.content,
                    indexed.row.content,
                    [0; 32],
                );
            }
            _ => unreachable!(),
        }
        if case != 3 {
            let encoded = serde_json::to_vec(&entry).unwrap();
            wire.replace(indexed.range, &encoded);
            replace_hash(
                &mut wire.header.context.log.content,
                indexed.row.content,
                log::fingerprint(index, &encoded),
            );
        }
        let bytes = wire.encode(base::MAGIC, Vec::new());
        let error = reject(
            &bytes,
            rebound(&bytes, catalog.identity(), &wire.header.context),
            &storage,
            CUT,
        );
        let expected = [
            "membership payload differs",
            "index",
            "term regressed",
            "hole or missing prefix",
        ][case];
        assert!(error.contains(expected), "case {case}: {error}");
    }
}

#[test]
fn native_catalog_changed_key_floor_and_receipt_binding_remain_monotonic() {
    let (mut storage, first, _) = fixture();
    let (files, old) = Files::new(&storage);
    storage.begin_changes().unwrap();
    let expired_at = retention_deadline(time(1)).unwrap();
    apply(&mut storage, &[command(2, &first, expired_at, false)]);
    let prepared = files.prepare(&mut storage, 19);
    let mut payload = Vec::new();
    prepared.write_payload(&mut payload, &|| Ok(())).unwrap();
    // The expiry transition is valid in isolation. Changing its immutable
    // retention binding is still invalid even with a recomputed content hash.
    let mut wire = Wire::<Header>::read(&payload);
    let id = first.request_id();
    let row = &storage.business.receipts[&id];
    let mut changed = (**row).clone();
    changed.retained_until = time(1);
    validation::validate_receipt(
        storage.business.identity,
        &id,
        &changed,
        &storage.business.frontiers,
        storage.business.history().unwrap(),
    )
    .unwrap();
    let mut replacement = Vec::new();
    replacement.push(1);
    write_before(&mut replacement, Some(old.rows.receipts[&id].row.content)).unwrap();
    replacement.extend_from_slice(&id.to_bytes());
    replacement.push(1);
    let mut encoded = Vec::new();
    cold::write_receipt(&mut encoded, id, &changed, &|| Ok(())).unwrap();
    write_bytes(&mut replacement, &encoded, cold::MAX_BYTES).unwrap();
    // Expired retry changes only this receipt and one retained log row.
    assert_eq!(wire.header.changed, [0, 1, 0, 0, 1]);
    let old_length = 1 + 33 + 56 + 1 + 4 + {
        let mut encoded = Vec::new();
        cold::write_receipt(&mut encoded, id, row, &|| Ok(())).unwrap();
        encoded.len()
    };
    wire.body.splice(..old_length, replacement);
    replace_hash(
        &mut wire.header.after.business.content[1],
        changes::fingerprint(1, &id, &**row).unwrap(),
        changes::fingerprint(1, &id, &changed).unwrap(),
    );
    let bytes = wire.encode(MAGIC, files.bytes());
    let mut identity = old.identity();
    identity.checkpoint_epoch += 1;
    identity.operation_sequence = 19;
    let error = reject(
        &bytes,
        rebound(&bytes, identity, &wire.header.after),
        &storage,
        wire.header.cut_binding,
    );
    assert!(error.contains("immutable binding"), "{error}");

    // A self-valid fence-only row cannot discard a previous fence floor.
    let mut wire = Wire::<Header>::read(&payload);
    let key = first.lease().key();
    let changed = NativeKeyState::default();
    validation::validate_key(key, &changed, &storage.business.frontiers).unwrap();
    let mut frame = vec![0];
    write_before(
        &mut frame,
        Some(old.rows.keys[&facts::KeyId::of(key).unwrap()].row.content),
    )
    .unwrap();
    write_binary(&mut frame, &(key, Some(&changed))).unwrap();
    wire.body.splice(0..0, frame);
    wire.header.changed[0] = 1;
    replace_hash(
        &mut wire.header.after.business.content[0],
        old.rows.keys[&facts::KeyId::of(key).unwrap()].row.content,
        changes::fingerprint(0, key, &changed).unwrap(),
    );
    let bytes = wire.encode(MAGIC, files.bytes());
    let error = reject(
        &bytes,
        rebound(&bytes, identity, &wire.header.after),
        &storage,
        wire.header.cut_binding,
    );
    assert!(error.contains("key floor regressed"), "{error}");
}

#[test]
fn native_catalog_rebound_checkpoint_chain_padding_and_canonical_headers_reject() {
    let (mut storage, _, _) = fixture();
    let (mut files, old) = Files::new(&storage);
    storage.begin_changes().unwrap();
    apply(&mut storage, &[clock(2, time(2))]);
    let catalog = files.append(&mut storage, 20);
    let original = files.bytes();
    let split = old.identity().length as usize;
    for case in 0..7 {
        let mut wire = Wire::<Header>::read(&original[split..]);
        match case {
            0 => wire.header.previous.digest[31] ^= 1,
            1 => wire.header.before.business.frontiers.next_fence += 1,
            2 => wire.header.checkpoint_epoch += 1,
            3 => wire.header.operation_sequence = 17,
            4 => wire.header.cut_binding[31] ^= 1,
            5 => wire.header.changed[4] = validation::MAX_ITEMS,
            6 => {}
            _ => unreachable!(),
        }
        let mut bytes = wire.encode(MAGIC, original[..split].to_vec());
        if case == 6 {
            *bytes.last_mut().unwrap() = 1;
        }
        let identity = rebound(&bytes, catalog.identity(), &wire.header.after);
        reject(&bytes, identity, &storage, files.cut);
    }
    // A JSON whitespace variant is semantically equal but not canonical.
    let mut bytes = original[..split].to_vec();
    bytes.extend_from_slice(MAGIC);
    let wire = Wire::<Header>::read(&original[split..]);
    let mut header = serde_json::to_vec(&wire.header).unwrap();
    header.push(b' ');
    write_bytes(&mut bytes, &header, MAX_HEADER).unwrap();
    bytes.extend_from_slice(&wire.body);
    bytes.resize(bytes.len().div_ceil(BLOCK) * BLOCK, 0);
    let error = reject(
        &bytes,
        rebound(&bytes, catalog.identity(), &wire.header.after),
        &storage,
        files.cut,
    );
    assert!(error.contains("not canonical"), "{error}");
}

#[test]
fn native_catalog_empty_base_keeps_explicit_format_bounds_and_cancellation() {
    let (fixture, _, _) = fixture();
    let storage =
        NativeStorage::empty(fixture.business.identity, fixture.business.members.clone()).unwrap();
    let (files, catalog) = Files::new(&storage);
    let original = files.bytes();
    assert_eq!(&original[..8], base::MAGIC);
    assert!(NativeStorage::read_image(
        &mut original.as_slice(),
        ROOT,
        18,
        storage.business.identity
    )
    .is_err());
    for magic in [b"OPCNAT01", b"OPCNAT02", b"OPCNAT03", b"OPCNJ001"] {
        let mut bytes = original.clone();
        bytes[..8].copy_from_slice(magic);
        reject(
            &bytes,
            rebound(&bytes, catalog.identity(), &catalog.rows.context),
            &storage,
            CUT,
        );
    }
    for (file_epoch, checkpoint, block, maximum) in [
        (u64::MAX, 11, BLOCK, MAXIMUM),
        (4, u64::MAX, BLOCK, MAXIMUM),
        (4, 11, 0, MAXIMUM),
        (4, 11, BLOCK + 1, MAXIMUM),
        (4, 11, BLOCK, BLOCK as u64 - 1),
    ] {
        assert!(PreparedBase::prepare(
            &storage,
            crate::consensus::native::generation::BaseParameters {
                binding: ROOT,
                file_epoch,
                checkpoint_epoch: checkpoint,
                operation_sequence: 18,
                cut_binding: CUT,
                block_bytes: block,
                maximum
            },
            &|| Ok(()),
        )
        .is_err());
    }
    let cancelled = || {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "cancelled catalog",
        ))
    };
    assert!(PreparedBase::prepare(
        &storage,
        crate::consensus::native::generation::BaseParameters {
            binding: ROOT,
            file_epoch: 4,
            checkpoint_epoch: 11,
            operation_sequence: 18,
            cut_binding: CUT,
            block_bytes: BLOCK,
            maximum: MAXIMUM
        },
        &cancelled,
    )
    .is_err());
    let prepared = PreparedBase::prepare(
        &storage,
        crate::consensus::native::generation::BaseParameters {
            binding: ROOT,
            file_epoch: 4,
            checkpoint_epoch: 11,
            operation_sequence: 18,
            cut_binding: CUT,
            block_bytes: BLOCK,
            maximum: MAXIMUM,
        },
        &|| Ok(()),
    )
    .unwrap();
    let mut output = Vec::new();
    assert!(prepared.write_to(&mut output, &cancelled).is_err());
    assert!(output.is_empty());
    assert!(Catalog::open(
        &files.path,
        catalog.identity(),
        MAXIMUM,
        crate::consensus::native::generation::CatalogScope {
            identity: storage.business.identity,
            members: &storage.business.members,
            roster_root: storage.business.roster_root.clone()
        },
        CUT,
        &cancelled,
    )
    .is_err());
}

#[test]
fn native_catalog_cold_header_preflight_bounds_owned_membership_and_snapshot_metadata() {
    let (mut storage, _, _) = fixture();
    storage
        .business
        .set_current_snapshot(snapshot(&storage, 1, "header"))
        .unwrap();
    let (files, catalog) = Files::new(&storage);
    let original = files.bytes();
    for case in 0..3 {
        let mut wire = Wire::<BaseHeader>::read(&original);
        match case {
            0 => wire
                .header
                .context
                .business
                .members
                .extend([10, 11, 12].map(|id| SessionConsensusNodeId::new(id).unwrap())),
            1 => {
                wire.header
                    .context
                    .business
                    .frontiers
                    .current_snapshot
                    .as_mut()
                    .unwrap()
                    .0
                    .snapshot_id = "x".repeat(257)
            }
            2 => {
                wire.header
                    .context
                    .business
                    .frontiers
                    .current_snapshot
                    .as_mut()
                    .unwrap()
                    .1 = "x".repeat(257)
            }
            _ => unreachable!(),
        }
        let bytes = wire.encode(base::MAGIC, Vec::new());
        let error = reject(
            &bytes,
            rebound(&bytes, catalog.identity(), &wire.header.context),
            &storage,
            CUT,
        );
        assert!(
            error.contains("header allocation shape invalid"),
            "case {case}: {error}"
        );
    }
}
