//! Native state parity and exact file-WAL recovery, using the original SQL
//! implementation only as an independent test oracle.

use super::*;
use crate::consensus::native::NativeStorage;
use crate::sqlite::consensus::wal::{IoControl, Limits, Operation, Wal};

mod basis;
mod lifecycle;
mod ordinary;
mod public_reads;
mod roster;
mod v1;

fn fixed_members() -> BTreeSet<SessionConsensusNodeId> {
    members(&[7, 8, 9])
}

fn status(wal: &Wal, request: &FencedTransitionV2Request) -> FencedTransitionV2Status {
    wal.with_native_receipt_read(std::slice::from_ref(request), |state, receipts| {
        match receipts {
            Some(receipts) => state.status_with_receipts(request, receipts),
            None => state.status(request),
        }
        .map_err(|_| io::Error::other("native exact test status"))
    })
    .unwrap()
}

fn formation() -> Entry<SessionRaftTypeConfig> {
    membership_entry_at(0, vec![fixed_members()], fixed_members())
}

fn activation(
    index: u64,
    request: FencedTransitionV2Request,
    now: Timestamp,
) -> Entry<SessionRaftTypeConfig> {
    activating_fenced_transition_v2_authorized_entry(
        index,
        request,
        now,
        node_id(),
        identity(),
        identity(),
        &fixed_members(),
    )
}

fn append(entries: &[Entry<SessionRaftTypeConfig>]) -> Operation {
    Operation::Append(
        entries
            .iter()
            .map(|entry| encode_json(entry).unwrap().into())
            .collect(),
    )
}

struct Fixture {
    wal: Wal,
    oracle: SqliteSessionBackend,
    directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self::with_control(Limits::default(), IoControl::default())
    }

    fn with_control(limits: Limits, control: IoControl) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let oracle = SqliteSessionBackend::open(directory.path().join("oracle.sqlite")).unwrap();
        let conn = oracle.conn.blocking_lock();
        initialize_schema_with_profile(
            &conn,
            identity(),
            &fixed_members(),
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .unwrap();
        let wal = Wal::create_native(
            &directory.path().join("wal"),
            &conn,
            identity(),
            [0xE1; 32],
            limits,
            control,
        )
        .unwrap();
        drop(conn);
        Self {
            wal,
            oracle,
            directory,
        }
    }

    fn append_commit(&self, entries: &[Entry<SessionRaftTypeConfig>]) {
        for chunk in entries.chunks(64) {
            self.wal.submit(append(chunk)).unwrap().wait().unwrap();
        }
        self.wal
            .submit(Operation::Committed(
                entries.last().map(|entry| entry.log_id),
            ))
            .unwrap()
            .wait()
            .unwrap();
    }

    fn parity(&self, entries: &[Entry<SessionRaftTypeConfig>]) -> AppliedBatch {
        self.append_commit(entries);
        let conn = self.oracle.conn.blocking_lock();
        append_logs_with_authority_sync(
            &conn,
            identity(),
            ConsensusAuthorityProfile::FixedImmutable,
            &fixed_members(),
            &test_member_bindings(&fixed_members()),
            FIXED_TEST_PLACEMENT_POLICY,
            entries,
        )
        .unwrap();
        save_committed_with_authority_sync(
            &conn,
            identity(),
            ConsensusAuthorityProfile::FixedImmutable,
            &fixed_members(),
            &test_member_bindings(&fixed_members()),
            FIXED_TEST_PLACEMENT_POLICY,
            entries.last().map(|entry| entry.log_id),
        )
        .unwrap();
        let oracle = apply_entries_with_authority_sync(
            &conn,
            identity(),
            &self.oracle.caps,
            ConsensusAuthorityProfile::FixedImmutable,
            &fixed_members(),
            &test_member_bindings(&fixed_members()),
            FIXED_TEST_PLACEMENT_POLICY,
            entries.to_vec(),
        )
        .unwrap();
        let native = self.wal.native_apply_committed(entries).unwrap();
        assert_eq!(
            encode_json(&native.responses).unwrap(),
            encode_json(&oracle.responses).unwrap(),
            "complete response parity"
        );
        assert_eq!(
            encode_json(&native.notifications).unwrap(),
            encode_json(&oracle.notifications).unwrap(),
            "exact notification parity"
        );
        assert_eq!(
            self.wal
                .with_native_read(|state| Ok(state.applied()))
                .unwrap(),
            read_applied_sync(&conn, identity()).unwrap()
        );
        assert_eq!(
            self.wal
                .with_native_read(|state| Ok(state.logical_time()))
                .unwrap(),
            read_machine_sync(&conn, identity()).unwrap().2
        );
        native
    }

    fn reopened(&self) -> Wal {
        self.wal.shutdown().unwrap();
        Wal::open(
            &self.directory.path().join("wal"),
            self.wal.binding(),
            Limits::default(),
            IoControl::default(),
        )
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.wal.shutdown();
    }
}

#[test]
fn native_real_wal_combined_apply_above_rpc_limit_and_reopen() {
    let fixture = Fixture::new();
    let mut entries = vec![formation()];
    entries.extend((1..=129).map(|index| Entry {
        log_id: log_id(index),
        payload: EntryPayload::Blank,
    }));
    fixture.parity(&entries);
    assert_eq!(
        fixture
            .wal
            .with_native_read(|state| Ok(*state.membership().log_id()))
            .unwrap(),
        Some(log_id(0))
    );
    let reopened = fixture.reopened();
    assert_eq!(
        reopened
            .with_native_read(|state| Ok(state.applied()))
            .unwrap(),
        Some(log_id(129))
    );
    reopened.shutdown().unwrap();
}

#[test]
fn native_v2_complete_response_batch_renew_replay_conflict_and_expiry_parity() {
    let fixture = Fixture::new();
    fixture.parity(&[formation()]);
    let initial = fenced_transition_v2_request(0xE2, 1, "native-activation");
    fixture.parity(&[activation(1, initial.clone(), timestamp(1))]);
    let creates = (0..8)
        .map(|slot| sdk741_component_request(Sdk741Payload::Renew, 1, slot, None))
        .collect::<Vec<_>>();
    let applied = fixture.parity(&[fenced_transition_v2_batch_entry(
        2,
        creates.clone(),
        timestamp(2),
    )]);
    let Ok(SessionMutationOutcome::FencedTransitionV2Batch(outcomes)) =
        &applied.responses[0].result
    else {
        panic!("native batch returns exact outcomes")
    };
    let updates = outcomes
        .iter()
        .enumerate()
        .map(|(slot, outcome)| {
            sdk741_component_request(
                Sdk741Payload::Renew,
                2,
                slot,
                Some(outcome.as_ref().unwrap()),
            )
        })
        .collect::<Vec<_>>();
    fixture.parity(&[fenced_transition_v2_batch_entry(
        3,
        updates.clone(),
        timestamp(3),
    )]);
    roster::export::import::rootless_roundtrip(&fixture.oracle.conn.blocking_lock());
    fixture.parity(&[fenced_transition_v2_batch_entry(
        4,
        updates.clone(),
        timestamp(4),
    )]);
    fixture.parity(&[fenced_transition_v2_authorized_entry(
        5,
        altered_fenced_transition_v2_request(&initial),
        timestamp(5),
        node_id(),
        identity(),
    )]);
    let expiry = timestamp(1)
        .add_seconds(i64::try_from(FENCED_TRANSITION_OUTCOME_RETENTION.as_secs()).unwrap())
        .unwrap();
    fixture.parity(&[fenced_transition_v2_authorized_entry(
        6,
        initial.clone(),
        expiry,
        node_id(),
        identity(),
    )]);
    roster::export::import::rootless_roundtrip(&fixture.oracle.conn.blocking_lock());
    for request in creates
        .iter()
        .chain(&updates)
        .chain(std::iter::once(&initial))
    {
        let native = status(&fixture.wal, request);
        let oracle = read_fenced_transition_v2_status_sync(
            &fixture.oracle.conn.blocking_lock(),
            identity(),
            identity(),
            request,
        )
        .unwrap();
        assert_eq!(native, oracle);
    }
    fixture.wal.checkpoint().unwrap();
    let reopened = fixture.reopened();
    assert_eq!(
        status(&reopened, &initial),
        FencedTransitionV2Status::Expired
    );
    reopened.shutdown().unwrap();
}

#[test]
fn native_selected_basis_retains_unapplied_commit_and_uncommitted_tail() {
    let fixture = Fixture::new();
    fixture.parity(&[formation()]);
    let committed = fenced_transition_v2_request(0xE3, 1, "native-durable-unapplied");
    let uncommitted = sdk741_component_request(Sdk741Payload::Create, 1, 0, None);
    let entries = [
        activation(1, committed.clone(), timestamp(1)),
        fenced_transition_v2_entry(2, uncommitted.clone(), timestamp(2)),
    ];
    fixture
        .wal
        .submit(append(&entries))
        .unwrap()
        .wait()
        .unwrap();
    fixture
        .wal
        .submit(Operation::Committed(Some(log_id(1))))
        .unwrap()
        .wait()
        .unwrap();
    fixture.wal.checkpoint().unwrap();
    let reopened = fixture.reopened();
    assert_eq!(
        reopened
            .with_native_read(|state| Ok(state.applied()))
            .unwrap(),
        Some(log_id(1))
    );
    assert_eq!(
        encode_json(&reopened.read(1, 3).unwrap()).unwrap(),
        encode_json(&entries).unwrap()
    );
    assert!(matches!(
        status(&reopened, &committed),
        FencedTransitionV2Status::Recorded(_)
    ));
    assert_eq!(
        status(&reopened, &uncommitted),
        FencedTransitionV2Status::NotFound
    );
    assert!(reopened
        .with_native_read(|state| Ok(state.get(uncommitted.lease().key())))
        .unwrap()
        .is_none());
    reopened
        .submit(Operation::Truncate(log_id(2)))
        .unwrap()
        .wait()
        .unwrap();
    assert!(reopened.read(2, 3).unwrap().is_empty());
    reopened.shutdown().unwrap();
}

#[test]
fn native_apply_rejects_pending_commit_and_fences_reads() {
    let fixture = Fixture::new();
    fixture
        .wal
        .submit(append(&[formation()]))
        .unwrap()
        .wait()
        .unwrap();
    assert!(fixture.wal.native_apply_committed(&[formation()]).is_err());
    assert!(fixture
        .wal
        .with_native_read(|state| Ok(state.applied()))
        .is_err());
    assert!(fixture.wal.vote().is_err());
    assert!(fixture.wal.submit(Operation::Barrier).is_err());
    assert!(fixture.wal.shutdown().is_err());
}

#[test]
fn native_late_delta_failure_preserves_complete_business_image() {
    let initial = fenced_transition_v2_request(0xE7, 1, "native-atomic-initial");
    let image = native_image(&[formation(), activation(1, initial, timestamp(1))]);
    let mut native =
        NativeStorage::read_image(&mut image.as_slice(), [0xE4; 32], 3, identity()).unwrap();
    let mut before = Vec::new();
    native.write_image(&mut before, [0xE4; 32], 3).unwrap();
    let fresh = sdk741_component_request(Sdk741Payload::Create, 1, 0, None);
    let effect = fenced_transition_v2_entry(2, fresh.clone(), timestamp(2));
    let invalid_later = Entry {
        log_id: log_id(4),
        payload: EntryPayload::Blank,
    };
    assert!(native
        .business
        .apply(&[effect.clone(), invalid_later])
        .is_err());
    let mut after = Vec::new();
    native.write_image(&mut after, [0xE4; 32], 3).unwrap();
    assert_eq!(
        after, before,
        "all business maps, receipts, notifications and frontiers roll back"
    );
    assert_eq!(
        native.business.status(&fresh).unwrap(),
        FencedTransitionV2Status::NotFound
    );
    let applied = native.business.apply(&[effect]).unwrap();
    assert!(applied.responses[0].result.is_ok());
    assert_eq!(
        applied.notifications.len(),
        1,
        "the first entry staged a real business effect"
    );
    assert!(native.business.get(fresh.lease().key()).is_some());
}

#[test]
fn native_selected_basis_decodes_admitted_descriptor_and_rejects_in_place_mutation() {
    use crate::sqlite::consensus::wal::Point;
    use std::sync::atomic::{AtomicBool, Ordering};
    for replace_path in [true, false] {
        let fixture = Fixture::new();
        fixture.parity(&[formation()]);
        fixture.wal.checkpoint().unwrap();
        fixture.wal.shutdown().unwrap();
        let directory = fixture.directory.path().join("wal");
        let basis = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "native")
            })
            .unwrap();
        let before: std::collections::BTreeMap<_, _> = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                (path.clone(), std::fs::read(path).unwrap())
            })
            .collect();
        let admitted = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&admitted);
        let target = basis.clone();
        let control = IoControl {
            hook: Arc::new(move |point| {
                if point == Point::AfterNativeBasisAdmission {
                    observed.store(true, Ordering::SeqCst);
                    let mut bytes = std::fs::read(&target)?;
                    bytes[0] ^= 1;
                    if replace_path {
                        // Keep the displaced descriptor alive independently of
                        // the replaced pathname, without adding a WAL artifact.
                        let displaced = target
                            .parent()
                            .unwrap()
                            .parent()
                            .unwrap()
                            .join("admitted.native");
                        std::fs::rename(&target, displaced)?;
                    }
                    std::fs::write(&target, bytes)?;
                }
                Ok(())
            }),
            ..IoControl::default()
        };
        let reopened = Wal::open(
            &directory,
            fixture.wal.binding(),
            Limits::default(),
            control,
        );
        assert!(admitted.load(Ordering::SeqCst));
        assert!(
            reopened.is_err(),
            "changed bytes or replaced append pathname fail before WAL repair"
        );
        for (path, bytes) in &before {
            if path != &basis {
                assert_eq!(
                    &std::fs::read(path).unwrap(),
                    bytes,
                    "failed recovery preserves other files"
                );
            }
        }
    }
}

#[test]
fn native_fixed_image_decodes_retained_verified_descriptor_after_path_replacement() {
    use crate::consensus::verified_snapshot::VerifiedFile;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fixed.native");
    let image = native_image(&[formation()]);
    assert_eq!(&image[..8], b"OPCNAT02", "original fixed full-image format");
    std::fs::write(&path, &image).unwrap();
    let source = VerifiedFile::capture(
        crate::sqlite::open_regular_read_nofollow(&path).unwrap(),
        image.len() as u64,
    )
    .unwrap();
    std::fs::rename(&path, directory.path().join("retained.native")).unwrap();
    let mut changed = image;
    changed[0] ^= 1;
    std::fs::write(&path, changed).unwrap();
    let native =
        NativeStorage::read_image(&mut source.reader(), [0xE4; 32], 3, identity()).unwrap();
    assert_eq!(
        native.business.applied(),
        Some(log_id(0)),
        "the fixed image decoder reads its admitted descriptor"
    );
}

fn native_image(entries: &[Entry<SessionRaftTypeConfig>]) -> Vec<u8> {
    let mut native = NativeStorage::empty(identity(), fixed_members()).unwrap();
    for chunk in entries.chunks(64) {
        native
            .log
            .project(&append(chunk), &native.business, None)
            .unwrap();
    }
    native
        .log
        .project(
            &Operation::Committed(entries.last().map(|entry| entry.log_id)),
            &native.business,
            None,
        )
        .unwrap();
    native.replay_committed().unwrap();
    let mut image = Vec::new();
    native
        .write_legacy_v2_image_for_test(&mut image, [0xE4; 32], 3)
        .unwrap();
    image
}

fn mutate_image(
    image: &[u8],
    ordinal: usize,
    mutate: impl FnOnce(&mut serde_json::Value),
) -> Vec<u8> {
    mutate_native_frame(image, ordinal, |bytes| {
        let mut value = serde_json::from_slice(bytes).unwrap();
        mutate(&mut value);
        serde_json::to_vec(&value).unwrap()
    })
}

fn legacy_image(image: &[u8]) -> Vec<u8> {
    let native = NativeStorage::read_image(&mut &*image, [0xE4; 32], 3, identity()).unwrap();
    let mut legacy = Vec::new();
    native
        .write_legacy_image_for_test(&mut legacy, [0xE4; 32], 3)
        .unwrap();
    assert_eq!(&legacy[..8], b"OPCNAT01");
    legacy
}

fn mutate_native_frame(
    image: &[u8],
    ordinal: usize,
    mutate: impl FnOnce(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let mut result = image[..8].to_vec();
    let mut offset = 8;
    let mut mutate = Some(mutate);
    let mut current = 0;
    while offset < image.len() {
        let length = u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let bytes = &image[offset..offset + length];
        let changed = if current == ordinal {
            mutate.take().unwrap()(bytes)
        } else {
            bytes.to_vec()
        };
        result.extend_from_slice(&(changed.len() as u32).to_le_bytes());
        result.extend_from_slice(&changed);
        offset += length;
        current += 1;
    }
    assert!(mutate.is_none());
    result
}

#[test]
fn native_clock_only_genesis_image_round_trip_and_strict_schema() {
    let wrong_epoch = fenced_transition_v2_request(0xE5, 2, "native-wrong-initial-epoch");
    let entries = [
        formation(),
        activation(1, wrong_epoch.clone(), timestamp(1)),
    ];
    let fixture = Fixture::new();
    fixture.parity(&entries);
    let image = native_image(&entries);
    let restored =
        NativeStorage::read_image(&mut image.as_slice(), [0xE4; 32], 3, identity()).unwrap();
    assert_eq!(restored.business.applied(), Some(log_id(1)));
    assert_eq!(restored.business.logical_time(), Some(timestamp(1)));
    assert!(restored.business.history().is_none());
    assert!(restored.business.get(wrong_epoch.lease().key()).is_none());
    let extra = mutate_image(&image, 0, |header| {
        header["frontiers"]["unrecognized"] = true.into();
    });
    assert!(NativeStorage::read_image(&mut extra.as_slice(), [0xE4; 32], 3, identity()).is_err());
    let bad_membership = mutate_image(&image, 0, |header| {
        header["frontiers"]["membership"]["log_id"]["leader_id"] = 99.into();
    });
    assert!(
        NativeStorage::read_image(&mut bad_membership.as_slice(), [0xE4; 32], 3, identity())
            .is_err()
    );
}

#[test]
fn native_image_rejects_receipt_corruption_and_premature_compaction() {
    let request = fenced_transition_v2_request(0xE6, 1, "native-image-receipt");
    let image = legacy_image(&native_image(&[
        formation(),
        activation(1, request, timestamp(1)),
    ]));
    // Header then the one touched key, followed by its receipt tuple.
    for kind in 0..4 {
        let changed = mutate_image(&image, 2, |tuple| match kind {
            0 => tuple[1]["payload_digest"][0] = 7.into(),
            1 => tuple[1]["response"] = serde_json::Value::Null,
            2 => tuple[1]["response"]["raft_log_index"] = 99.into(),
            _ => tuple[1]["unrecognized"] = true.into(),
        });
        assert!(
            NativeStorage::read_image(&mut changed.as_slice(), [0xE4; 32], 3, identity()).is_err(),
            "receipt corruption case {kind}"
        );
    }
}

#[test]
fn native_image_v2_preserves_legacy_state_and_rejects_binary_receipt_corruption() {
    let request = fenced_transition_v2_request(0xEA, 1, "native-image-binary");
    let image = native_image(&[formation(), activation(1, request.clone(), timestamp(1))]);
    assert_eq!(&image[..8], b"OPCNAT02");
    let legacy = legacy_image(&image);
    let native =
        NativeStorage::read_image(&mut image.as_slice(), [0xE4; 32], 3, identity()).unwrap();
    let prior =
        NativeStorage::read_image(&mut legacy.as_slice(), [0xE4; 32], 3, identity()).unwrap();
    assert_eq!(
        native.business.status(&request).unwrap(),
        prior.business.status(&request).unwrap()
    );
    assert_eq!(
        native.business.get(request.lease().key()),
        prior.business.get(request.lease().key())
    );
    for (index, entry) in &native.log.entries {
        assert_eq!(
            entry.encoded_for_test().unwrap(),
            prior.log.entries[index].encoded_for_test().unwrap(),
            "original log bytes survive both codecs"
        );
    }
    let mut upgraded = Vec::new();
    prior
        .write_legacy_v2_image_for_test(&mut upgraded, [0xE4; 32], 3)
        .unwrap();
    assert_eq!(&upgraded[..8], b"OPCNAT02");
    assert_eq!(
        NativeStorage::read_image(&mut upgraded.as_slice(), [0xE4; 32], 3, identity())
            .unwrap()
            .business
            .status(&request)
            .unwrap(),
        native.business.status(&request).unwrap()
    );
    // Structs have fixed positional fields in this version. A tuple of those
    // exact field types independently addresses the original receipt cases.
    type WireReceipt = (
        crate::FencedTransitionV2RequestId,
        (u64, [u8; 32], Timestamp, Option<SessionConsensusResponse>),
    );
    for kind in 0..6 {
        let changed = mutate_native_frame(&image, 2, |bytes| {
            let mut tuple: WireReceipt = postcard::from_bytes(bytes).unwrap();
            match kind {
                0 => tuple.1 .1[0] ^= 1,
                1 => tuple.1 .3 = None,
                2 => tuple.1 .3.as_mut().unwrap().raft_log_index = 99,
                3 => {
                    let mut extra = bytes.to_vec();
                    extra.push(0);
                    return extra;
                }
                4 => return bytes[..bytes.len() - 1].to_vec(),
                _ => tuple.1 .0 = 0,
            }
            postcard::to_allocvec(&tuple).unwrap()
        });
        assert!(
            NativeStorage::read_image(&mut changed.as_slice(), [0xE4; 32], 3, identity()).is_err(),
            "binary receipt corruption case {kind}"
        );
    }
    let mut unknown = image.clone();
    unknown[7] = b'3';
    assert!(NativeStorage::read_image(&mut unknown.as_slice(), [0xE4; 32], 3, identity()).is_err());
    let mut oversized = image.clone();
    oversized[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(
        NativeStorage::read_image(&mut oversized.as_slice(), [0xE4; 32], 3, identity()).is_err()
    );
    let mut receipt_offset = 8;
    for _ in 0..2 {
        receipt_offset += 4 + u32::from_le_bytes(
            image[receipt_offset..receipt_offset + 4]
                .try_into()
                .unwrap(),
        ) as usize;
    }
    for length in [0, u32::MAX] {
        let mut malformed = image.clone();
        malformed[receipt_offset..receipt_offset + 4].copy_from_slice(&length.to_le_bytes());
        assert!(
            NativeStorage::read_image(&mut malformed.as_slice(), [0xE4; 32], 3, identity())
                .is_err(),
            "binary frame allocation bound"
        );
    }
    let mut trailing = image.clone();
    trailing.push(0);
    assert!(
        NativeStorage::read_image(&mut trailing.as_slice(), [0xE4; 32], 3, identity()).is_err()
    );
}

#[test]
fn native_shared_rows_keep_captured_image_isolated_from_live_replacement_and_expiry() {
    let initial = sdk741_component_request(Sdk741Payload::Renew, 1, 0, None);
    let image = native_image(&[formation(), activation(1, initial.clone(), timestamp(1))]);
    let mut live =
        NativeStorage::read_image(&mut image.as_slice(), [0xE4; 32], 3, identity()).unwrap();
    let captured = live.clone();
    let original_status = captured.business.status(&initial).unwrap();
    let FencedTransitionV2Status::Recorded(result) = &original_status else {
        panic!("initial recorded response")
    };
    let update = sdk741_component_request(
        Sdk741Payload::Renew,
        2,
        0,
        Some(result.as_ref().as_ref().unwrap()),
    );
    let mut before = Vec::new();
    captured.write_image(&mut before, [0xE4; 32], 3).unwrap();
    let mut before_legacy = Vec::new();
    captured
        .write_legacy_image_for_test(&mut before_legacy, [0xE4; 32], 3)
        .unwrap();
    let updated = fenced_transition_v2_entry(2, update.clone(), timestamp(2));
    live.log
        .project(&append(&[updated]), &live.business, None)
        .unwrap();
    live.log
        .project(&Operation::Committed(Some(log_id(2))), &live.business, None)
        .unwrap();
    live.replay_committed().unwrap();
    assert_ne!(
        live.business.get(initial.lease().key()),
        captured.business.get(initial.lease().key()),
        "a live replacement cannot change the captured key"
    );
    assert_eq!(
        captured.business.status(&update).unwrap(),
        FencedTransitionV2Status::NotFound
    );
    let expiry = timestamp(1)
        .add_seconds(i64::try_from(FENCED_TRANSITION_OUTCOME_RETENTION.as_secs()).unwrap())
        .unwrap();
    let expired =
        fenced_transition_v2_authorized_entry(3, initial.clone(), expiry, node_id(), identity());
    live.log
        .project(&append(&[expired]), &live.business, None)
        .unwrap();
    live.log
        .project(&Operation::Committed(Some(log_id(3))), &live.business, None)
        .unwrap();
    live.replay_committed().unwrap();
    assert_eq!(
        live.business.status(&initial).unwrap(),
        FencedTransitionV2Status::Expired
    );
    assert_eq!(
        captured.business.status(&initial).unwrap(),
        original_status,
        "tombstoning publishes a new receipt allocation"
    );
    assert_eq!(captured.log.entries.len(), 2);
    assert_eq!(live.log.entries.len(), 4);
    let mut changed = Vec::new();
    live.write_image(&mut changed, [0xE4; 32], 3).unwrap();
    assert_ne!(changed, before);
    drop(live);
    let mut after = Vec::new();
    captured.write_image(&mut after, [0xE4; 32], 3).unwrap();
    assert_eq!(
        after, before,
        "all captured rows, frontiers, notifications and original logs remain exact"
    );
    let mut after_legacy = Vec::new();
    captured
        .write_legacy_image_for_test(&mut after_legacy, [0xE4; 32], 3)
        .unwrap();
    assert_eq!(
        after_legacy, before_legacy,
        "shared ownership is transparent to the legacy codec too"
    );
}

#[test]
fn native_image_rejects_older_snapshot_from_different_retained_term() {
    let image = native_image(&[
        formation(),
        Entry {
            log_id: log_id(1),
            payload: EntryPayload::Blank,
        },
        Entry {
            log_id: log_id(2),
            payload: EntryPayload::Blank,
        },
    ]);
    let mut native =
        NativeStorage::read_image(&mut image.as_slice(), [0xE4; 32], 3, identity()).unwrap();
    let meta = opc_consensus::engine::SnapshotMeta {
        last_log_id: Some(log_id(1)),
        last_membership: native.business.membership(),
        snapshot_id: format!(
            "{}fixture",
            crate::consensus::native::snapshot_prefix([0xE4; 32])
        ),
    };
    native
        .business
        .set_current_snapshot((
            meta,
            format!("snapshot-{}.opc", uuid::Uuid::new_v4()),
            [0xE8; 32],
            100,
        ))
        .unwrap();
    let mut image = Vec::new();
    native.write_image(&mut image, [0xE4; 32], 3).unwrap();
    let changed = mutate_image(&image, 0, |header| {
        header["frontiers"]["current_snapshot"][0]["last_log_id"]["leader_id"] = 0.into();
    });
    assert!(
        NativeStorage::read_image(&mut changed.as_slice(), [0xE4; 32], 3, identity()).is_err(),
        "older index must retain its exact term"
    );
}

#[test]
fn native_selected_snapshot_admission_failure_precedes_pending_wal_repair() {
    use crate::sqlite::consensus::wal::native::Opening;
    use crate::sqlite::consensus::wal::Point;
    let fixture = Fixture::new();
    fixture.parity(&[
        formation(),
        Entry {
            log_id: log_id(1),
            payload: EntryPayload::Blank,
        },
    ]);
    let meta = opc_consensus::engine::SnapshotMeta {
        last_log_id: Some(log_id(1)),
        last_membership: fixture
            .wal
            .with_native_read(|state| Ok(state.membership()))
            .unwrap(),
        snapshot_id: fixture.wal.native_snapshot_id().unwrap(),
    };
    let candidate = (
        meta,
        format!("snapshot-{}.opc", uuid::Uuid::new_v4()),
        [0xE9; 32],
        100,
    );
    fixture
        .wal
        .native_publish_snapshot(candidate.clone())
        .unwrap();
    fixture.wal.shutdown().unwrap();
    let directory = fixture.directory.path().join("wal");
    let control = IoControl {
        hook: std::sync::Arc::new(|point| {
            if point == Point::AfterIntentPublish {
                Err(io::Error::other("native pending cleanup fixture"))
            } else {
                Ok(())
            }
        }),
        ..IoControl::default()
    };
    let writer = Wal::open(
        &directory,
        fixture.wal.binding(),
        Limits::default(),
        control,
    )
    .unwrap();
    assert!(writer.submit(Operation::Barrier).unwrap().wait().is_err());
    assert!(writer.shutdown().is_err());
    fn files(directory: &std::path::Path) -> BTreeMap<std::ffi::OsString, Vec<u8>> {
        std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), std::fs::read(entry.path()).unwrap())
            })
            .collect()
    }
    let before = files(&directory);
    assert!(
        before
            .keys()
            .any(|name| name.to_string_lossy().ends_with(".pending")),
        "fixture retains a pending repair proof"
    );
    let opening = Opening::new(
        &directory,
        fixture.wal.binding(),
        None,
        Limits::default(),
        IoControl::default(),
    )
    .unwrap();
    assert_eq!(opening.snapshots(), vec![candidate.clone()]);
    let missing = fixture.directory.path().join(&candidate.1);
    assert!(
        opening
            .finish(|| std::fs::File::open(&missing).map(|_| ()))
            .is_err(),
        "missing selected descriptor rejects startup"
    );
    assert_eq!(
        files(&directory),
        before,
        "rejected descriptor admission performs no repair or owner startup"
    );
}
