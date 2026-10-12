use super::*;

struct PurgeFixture {
    storage: NativeStorage,
    files: Files,
    wire: Wire<Header>,
}

impl PurgeFixture {
    fn new() -> Self {
        let (mut storage, _, _) = fixture();
        let mut suffix = [clock(2, time(2)), clock(3, time(3))];
        for entry in &mut suffix {
            entry.log_id.leader_id.term = 2;
        }
        apply(&mut storage, &suffix);
        storage
            .business
            .publish_snapshot_metadata(snapshot(&storage, 3, "purge"))
            .unwrap();
        let (files, catalog) = Files::new(&storage);
        assert_eq!(catalog.rows.logs.len(), 4);
        drop(catalog);
        storage.begin_changes().unwrap();
        let prepared = files.prepare(&mut storage, 19);
        let mut bytes = Vec::new();
        prepared.write_payload(&mut bytes, &|| Ok(())).unwrap();
        let mut wire = Wire::<Header>::read(&bytes);
        assert_eq!(wire.header.changed, [0; 5]);
        let cut = storage.log.entries[&1].id();
        wire.header.after.log.purged = Some(cut);
        wire.header.after.log.count = 2;
        wire.header.after.log.first = Some(storage.log.entries[&2].id());
        wire.header.after.log.content = [0; 32];
        for (index, row) in storage.log.entries.range(2..) {
            replace_hash(
                &mut wire.header.after.log.content,
                [0; 32],
                log::fingerprint(*index, row.encoded_for_test().unwrap()),
            );
        }
        Self {
            storage,
            files,
            wire,
        }
    }

    fn encoded(&self) -> (Vec<u8>, PrefixIdentity) {
        let bytes = self.wire.encode(MAGIC, self.files.bytes());
        let identity = PrefixIdentity {
            checkpoint_epoch: self.wire.header.checkpoint_epoch,
            operation_sequence: self.wire.header.operation_sequence,
            ..self.files.owner.current().identity()
        };
        let identity = rebound(&bytes, identity, &self.wire.header.after);
        (bytes, identity)
    }

    fn admitted_ids(&self) -> io::Result<Vec<LogId<SessionConsensusNodeId>>> {
        let (bytes, identity) = self.encoded();
        admit_ids(
            &bytes,
            identity,
            &self.storage,
            self.wire.header.cut_binding,
        )
    }
}

fn admit_ids(
    bytes: &[u8],
    identity: PrefixIdentity,
    template: &NativeStorage,
    cut: [u8; 32],
) -> io::Result<Vec<LogId<SessionConsensusNodeId>>> {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("purge.opc");
    std::fs::write(&path, bytes).unwrap();
    let result = Catalog::open(
        &path,
        identity,
        MAXIMUM,
        CatalogScope {
            identity: template.business.identity,
            members: &template.business.members,
            roster_root: template.business.roster_root.clone(),
        },
        cut,
        &|| Ok(()),
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        bytes,
        "cold admission never mutates its input"
    );
    let (_, catalog) = result?;
    let storage = catalog.into_storage(&|| Ok(()))?;
    storage.validate_image()?;
    Ok(storage.log.entries.values().map(|row| row.id()).collect())
}

#[test]
fn native_catalog_purge_frontier_removes_rows_without_log_frames() {
    let fixture = PurgeFixture::new();
    assert_eq!(fixture.wire.header.changed[4], 0);
    assert_eq!(
        fixture.admitted_ids().unwrap(),
        [
            fixture.storage.log.entries[&2].id(),
            fixture.storage.log.entries[&3].id()
        ]
    );
}

#[test]
fn native_catalog_purge_checks_exact_predecessor_log_id_before_removing_the_row() {
    let mut fixture = PurgeFixture::new();
    fixture.admitted_ids().unwrap();
    // Both the retained successor and selected applied/snapshot cut are in
    // term two. Every ordering equation allows this forged term; only the
    // exact predecessor row proves that the purge boundary was in term one.
    fixture
        .wire
        .header
        .after
        .log
        .purged
        .as_mut()
        .unwrap()
        .leader_id
        .term = 2;
    assert_eq!(
        fixture.admitted_ids().unwrap_err().to_string(),
        "native log pointer lacks exact retained lineage"
    );
    fixture
        .wire
        .header
        .after
        .log
        .purged
        .as_mut()
        .unwrap()
        .leader_id
        .term = 1;
    fixture.admitted_ids().unwrap();
}

#[test]
fn native_catalog_purge_recomputes_removed_count_and_content() {
    for corrupt_count in [false, true] {
        let mut fixture = PurgeFixture::new();
        fixture.admitted_ids().unwrap();
        if corrupt_count {
            fixture.wire.header.after.log.count += 1;
        } else {
            fixture.wire.header.after.log.content[0] ^= 1;
        }
        assert_eq!(
            fixture.admitted_ids().unwrap_err().to_string(),
            "native catalog recomputed table summary differs"
        );
    }
}

#[test]
fn native_catalog_new_base_refuses_rows_at_or_below_purge_frontier() {
    let fixture = PurgeFixture::new();
    let original = fixture.files.bytes();
    let mut wire = Wire::<BaseHeader>::read(&original);
    let identity = fixture.files.owner.current().identity();
    assert_eq!(
        admit_ids(&original, identity, &fixture.storage, CUT)
            .unwrap()
            .len(),
        4
    );
    wire.header.context.log.purged = fixture.wire.header.after.log.purged;
    let bytes = wire.encode(base::MAGIC, Vec::new());
    assert_eq!(
        admit_ids(
            &bytes,
            rebound(&bytes, identity, &wire.header.context),
            &fixture.storage,
            CUT
        )
        .unwrap_err()
        .to_string(),
        "native retained log extends below its purge frontier"
    );
}

#[test]
fn native_catalog_purge_forbids_even_identical_frames_below_the_new_frontier() {
    let mut fixture = PurgeFixture::new();
    fixture.admitted_ids().unwrap();
    let encoded = fixture.storage.log.entries[&1].encoded_for_test().unwrap();
    let mut frame = vec![4];
    frame.extend_from_slice(&1_u64.to_le_bytes());
    write_before(&mut frame, None).unwrap();
    frame.push(1);
    write_bytes(
        &mut frame,
        encoded,
        sql::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES,
    )
    .unwrap();
    fixture.wire.body.splice(0..0, frame);
    fixture.wire.header.changed[4] = 1;
    assert_eq!(
        fixture.admitted_ids().unwrap_err().to_string(),
        "native generation changes protected log history"
    );
}

#[test]
fn native_catalog_purge_admission_reads_no_blocks_and_worker_reads_only_frontier_witnesses() {
    for count in [3_u64, 64, 4096] {
        let (mut hot, _, _) = fixture();
        for first in (2..count).step_by(64) {
            let entries = (first..(first + 64).min(count))
                .map(|index| Entry {
                    log_id: LogId::new(
                        CommittedLeaderId::new(1, SessionConsensusNodeId::new(7).unwrap()),
                        index,
                    ),
                    payload: EntryPayload::Blank,
                })
                .collect::<Vec<_>>();
            apply(&mut hot, &entries);
        }
        hot.business
            .publish_snapshot_metadata(snapshot(&hot, count - 1, "cold-purge"))
            .unwrap();
        let (files, catalog) = Files::new(&hot);
        let source = files.owner.current();
        let mut storage = catalog.into_storage(&|| Ok(())).unwrap();
        assert!(storage.log.entries.values().all(|row| row.is_cold()));
        storage.begin_changes().unwrap();
        let through = storage.log.entries[&(count - 2)].id();
        let before = source.blocks_read();
        storage
            .log
            .project(
                &Operation::Purge(through),
                &storage.business,
                storage.business.applied(),
            )
            .unwrap();
        let captured = storage.take_changes().unwrap();
        assert_eq!(
            source.blocks_read(),
            before,
            "purge and capture admission do no file reads"
        );
        assert_eq!(storage.log.entries.len(), 1);
        assert_eq!(captured.log.generation_count(), 0);
        captured.validate(&|| Ok(())).unwrap();
        assert!(
            source.blocks_read() - before <= 5,
            "removed rows are verified from admitted facts, not read from the file"
        );
    }
}
