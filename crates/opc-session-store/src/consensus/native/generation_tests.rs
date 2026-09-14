use super::super::changes::tests::{apply, clock, command, fixture, request, time};
use super::*;
use crate::sqlite::consensus::wal::Operation;
use std::fs::OpenOptions;

const BLOCK: usize = 64 * 1024;
const ROOT: [u8; 32] = [0xBD; 32];

#[test]
fn native_generation_capture_preserves_business_and_log_admission_boundaries() {
    let (mut storage, _, _) = fixture();
    apply(&mut storage, &[clock(2, time(2))]);
    let version = Version::capture(&storage).unwrap();
    let snapshot = storage.capture_snapshot().unwrap();
    version.require_current(&snapshot.storage).unwrap();
    for case in 0..8 {
        let mut candidate = storage.clone();
        match case {
            0 => candidate.business.members.clear(),
            1 => candidate.business.frontiers.sequence += 1,
            2 => {
                assert!(!candidate.business.keys.is_empty());
                candidate.business.keys.clear();
            }
            3 => {
                assert!(!candidate.business.generic_receipts.is_empty());
                candidate.business.generic_receipts.clear();
            }
            4 => {
                assert!(!candidate.business.notifications.is_empty());
                candidate.business.notifications.clear();
            }
            5 => {
                assert!(candidate.log.committed.is_some());
                candidate.log.committed = None;
            }
            6 => candidate.log.entries.clear(),
            7 => {
                assert_ne!(candidate.log.purged, candidate.log.committed);
                candidate.log.purged = candidate.log.committed;
            }
            _ => unreachable!(),
        }
        assert!(Version::capture(&candidate).is_err(), "case {case}");
        assert!(version.require_current(&candidate).is_err(), "case {case}");
        assert!(candidate.capture_snapshot().is_err(), "case {case}");
        assert!(
            snapshot.require_current_authority(&candidate).is_err(),
            "case {case}"
        );
    }
    // A valid later application keeps export authority but changes the exact
    // generation predecessor. Both contracts must remain independently checked.
    apply(&mut storage, &[clock(3, time(3))]);
    Version::capture(&storage).unwrap();
    storage.capture_snapshot().unwrap();
    assert!(version.require_current(&storage).is_err());
    snapshot.require_current_authority(&storage).unwrap();
    version.require_current(&snapshot.storage).unwrap();
}

struct FileFixture {
    _directory: tempfile::TempDir,
    owner: VerifiedAppendOwner,
    version: Version,
}

impl FileFixture {
    fn new(storage: &NativeStorage) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("basis.fixture");
        let version = Version::capture(storage).unwrap();
        // The isolated transaction fixture seeds its byte owner with a fully
        // admitted old native image. This is not an OPCNJ001 base writer or
        // ordinary generation discovery/selection path.
        let mut bytes = Vec::new();
        storage.write_image(&mut bytes, ROOT, 18).unwrap();
        let image_length = bytes.len();
        bytes.resize(bytes.len().div_ceil(BLOCK) * BLOCK, 0);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        let identity = PrefixIdentity {
            binding: ROOT,
            file_epoch: 4,
            checkpoint_epoch: 11,
            operation_sequence: 18,
            frontiers: version.context_digest().unwrap(),
            length: bytes.len() as u64,
            block_bytes: BLOCK,
            digest: Sha256::digest(&bytes).into(),
        };
        let owner = VerifiedAppendOwner::open(
            &path,
            identity,
            16 * BLOCK as u64,
            || Ok(()),
            |reader| {
                let actual = NativeStorage::read_image(
                    &mut (&mut *reader).take(image_length as u64),
                    ROOT,
                    18,
                    storage.business.identity,
                )?;
                if Version::capture(&actual)?.context_digest()? != identity.frontiers {
                    return Err(invalid("fixture complete cold context differs"));
                }
                let mut padding = Vec::new();
                reader.read_to_end(&mut padding)?;
                if padding.iter().any(|byte| *byte != 0) {
                    return Err(invalid("fixture padding differs"));
                }
                Ok(())
            },
        )
        .unwrap();
        Self {
            _directory: directory,
            owner,
            version,
        }
    }
}

fn changed() -> (NativeStorage, FileFixture, PreparedDelta) {
    let (mut storage, _, previous) = fixture();
    let file = FileFixture::new(&storage);
    storage.begin_changes().unwrap();
    let next = request(2, Some(&previous));
    apply(
        &mut storage,
        &[command(2, &next, time(2), false), clock(3, time(3))],
    );
    let capture = storage.take_changes().unwrap();
    let delta = PreparedDelta::prepare(
        file.owner.current(),
        &file.version,
        12,
        21,
        [0xDE; 32],
        capture,
        &|| Ok(()),
    )
    .unwrap();
    (storage, file, delta)
}

fn encode(delta: &PreparedDelta) -> Vec<u8> {
    let mut bytes = Vec::new();
    delta.write_payload(&mut bytes, &|| Ok(())).unwrap();
    assert_eq!(bytes.len() as u64, delta.payload_bytes());
    bytes
}

#[test]
fn native_generation_complete_afterimages_append_and_readback_preserve_old_prefix() {
    let (storage, mut file, delta) = changed();
    assert_eq!(delta.header.changed, [1, 1, 1, 1, 2]);
    let old = file.owner.current();
    let mut old_bytes = Vec::new();
    old.reader().read_to_end(&mut old_bytes).unwrap();
    let bytes = encode(&delta);
    delta
        .verify_payload(&mut bytes.as_slice(), &|| Ok(()), None)
        .unwrap();
    let next = delta.append(&mut file.owner, &|| Ok(())).unwrap();
    assert_eq!(next.identity().file_epoch, old.identity().file_epoch);
    assert_eq!(next.identity().checkpoint_epoch, 12);
    assert_eq!(next.identity().operation_sequence, 21);
    assert_eq!(
        next.identity().frontiers,
        Version::capture(&storage)
            .unwrap()
            .context_digest()
            .unwrap()
    );
    let mut reread = vec![0; old_bytes.len()];
    old.read_exact_at(0, &mut reread).unwrap();
    assert_eq!(reread, old_bytes);
    let mut extent = vec![0; bytes.len()];
    next.read_exact_at(old.identity().length, &mut extent)
        .unwrap();
    assert_eq!(extent, bytes);
    storage.validate_image().unwrap();
}

#[test]
fn native_generation_later_application_at_same_wal_sequence_has_distinct_checkpoint() {
    let (mut storage, _, _) = fixture();
    let mut file = FileFixture::new(&storage);
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
    let first = PreparedDelta::prepare(
        file.owner.current(),
        &file.version,
        12,
        20,
        [7; 32],
        storage.take_changes().unwrap(),
        &|| Ok(()),
    )
    .unwrap();
    let one = first.append(&mut file.owner, &|| Ok(())).unwrap();
    let version = first.target_version();
    storage.business.apply(&[entry]).unwrap();
    storage.validate_image().unwrap();
    let second = PreparedDelta::prepare(
        one.clone(),
        &version,
        13,
        20,
        [8; 32],
        storage.take_changes().unwrap(),
        &|| Ok(()),
    )
    .unwrap();
    assert_eq!(second.header.changed, [0, 0, 1, 0, 0]);
    let two = second.append(&mut file.owner, &|| Ok(())).unwrap();
    assert_eq!(
        one.identity().operation_sequence,
        two.identity().operation_sequence
    );
    assert_ne!(
        one.identity().checkpoint_epoch,
        two.identity().checkpoint_epoch
    );
    assert_ne!(one.identity().frontiers, two.identity().frontiers);
    assert_ne!(one.identity().digest, two.identity().digest);
}

#[test]
fn native_generation_header_and_row_corruption_reject_before_any_selection() {
    let (_, _, delta) = changed();
    let original = encode(&delta);
    let length = u32::from_le_bytes(original[8..12].try_into().unwrap()) as usize;
    for case in 0..15 {
        let mut header: Header = serde_json::from_slice(&original[12..12 + length]).unwrap();
        match case {
            0 => header.previous.binding[31] ^= 1,
            1 => header.previous.file_epoch += 1,
            2 => header.previous.checkpoint_epoch += 1,
            3 => header.previous.operation_sequence += 1,
            4 => header.previous.length += BLOCK as u64,
            5 => header.previous.block_bytes *= 2,
            6 => header.previous.digest[31] ^= 1,
            7 => header.previous.frontiers[31] ^= 1,
            8 => header.checkpoint_epoch += 1,
            9 => header.operation_sequence += 1,
            10 => header.cut_binding[31] ^= 1,
            11 => header.before.business.frontiers.sequence += 1,
            12 => header.after.business.content[1][31] ^= 1,
            13 => header.after.log.committed = None,
            14 => header.changed[1] += 1,
            _ => unreachable!(),
        }
        let mut bytes = MAGIC.to_vec();
        write_bytes(
            &mut bytes,
            &serde_json::to_vec(&header).unwrap(),
            MAX_HEADER,
        )
        .unwrap();
        bytes.extend_from_slice(&original[12 + length..]);
        assert!(
            delta
                .verify_payload(&mut bytes.as_slice(), &|| Ok(()), None)
                .is_err(),
            "header field {case}"
        );
    }
    for case in 0..7 {
        let mut bytes = original.clone();
        match case {
            0 => bytes[0] ^= 1,
            1 => bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes()),
            2 => bytes[12 + length] ^= 1,
            3 => {
                bytes.pop();
            }
            4 => bytes.push(0),
            5 => {
                let start = bytes
                    .windows(8)
                    .position(|part| part == b"OPCNRC01")
                    .unwrap();
                bytes[start + 63] ^= 1; // Last byte of the complete ID commitment.
            }
            6 => bytes[12 + length + 1] ^= 1, // Exact before-presence marker.
            _ => unreachable!(),
        }
        assert!(
            delta
                .verify_payload(&mut bytes.as_slice(), &|| Ok(()), None)
                .is_err(),
            "row/extent case {case}"
        );
    }
}

#[test]
fn native_generation_readback_failure_fences_views_and_never_publishes_new_prefix() {
    let (_, mut file, delta) = changed();
    let previous = file.owner.current();
    let mut bytes = encode(&delta);
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(file
        .owner
        .append(
            &previous,
            crate::consensus::native::prefix::AppendTransaction {
                checkpoint_epoch: 12,
                operation_sequence: 21,
                frontiers: delta.header.after.digest().unwrap(),
                payload_bytes: bytes.len() as u64,
            },
            || Ok(()),
            |writer| writer.write_all(&bytes),
            |reader| delta.verify_payload(reader, &|| Ok(()), None)
        )
        .is_err());
    assert!(previous.is_failed());
    assert_eq!(file.owner.current().identity(), previous.identity());
}

#[test]
fn native_generation_exact_process_predecessor_and_truncation_tombstones_are_required() {
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
    let mut file = FileFixture::new(&storage);
    storage.begin_changes().unwrap();
    storage
        .log
        .project(
            &Operation::Truncate(pending[0].log_id),
            &storage.business,
            None,
        )
        .unwrap();
    let capture = storage.take_changes().unwrap();
    let delta = PreparedDelta::prepare(
        file.owner.current(),
        &file.version,
        12,
        19,
        [5; 32],
        capture,
        &|| Ok(()),
    )
    .unwrap();
    assert_eq!(delta.header.changed, [0, 0, 0, 0, 2]);
    delta.append(&mut file.owner, &|| Ok(())).unwrap();
    storage.validate_image().unwrap();
    // A separately admitted equal image has different process certificates.
    let (other, _, _) = fixture();
    let other_version = Version::capture(&other).unwrap();
    assert!(PreparedDelta::prepare(
        file.owner.current(),
        &other_version,
        13,
        19,
        [6; 32],
        storage.take_changes().unwrap(),
        &|| Ok(())
    )
    .is_err());
}

#[test]
fn native_history_captured_transient_omission_rejects_before_generation_selection() {
    use super::super::changes::tests::{omit_transient_history_receipt, transient_history_capture};
    use crate::fenced_transition::FencedTransitionV2HistoryEpoch;
    const CHILD: &str = "OPC_NATIVE_TRANSIENT_EXTENT_CHILD";
    const TEST:&str = "consensus::native::generation::tests::native_history_captured_transient_omission_rejects_before_generation_selection";
    if std::env::var_os(CHILD).is_none() {
        // This fixture alone retains an entire coalesced 131072-ID journal.
        // Give it an independent process counter so unrelated parallel unit
        // fixtures cannot consume its remaining budget. The production
        // 128MiB cap, original count, full checks and outer four threads stay.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        println!(
            "native_transient_extent_child={}",
            serde_json::json!({
            "exit_code":output.status.code(),"stdout":stdout,
            "stderr":stderr,"original_process_verification_limit_bytes":128 * 1024 * 1024,
            "original_transient_ids":FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES })
        );
        assert!(
            output.status.success(),
            "original-bound cold-extent subprocess must complete successfully"
        );
        assert!(
            stdout.contains(&format!("test {TEST} ... ok"))
                && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
            "the exact original cold-extent test must execute in the child"
        );
        return;
    }
    let _large_row = super::super::scratch::LARGE_ROW_TEST.lock().unwrap();
    let maximum = crate::consensus::snapshot::SNAPSHOT_DATABASE_MAX_BYTES;
    for omit in [false, true] {
        let (mut storage, _, _) = fixture();
        let history = FencedTransitionV2HistoryState::new(
            Some(FencedTransitionV2HistoryEpoch::new(1).unwrap()),
            None,
            None,
            0,
            0,
            0,
            0,
        )
        .unwrap();
        super::super::lifecycle_tests::seed(&mut storage, history, time(20), None, false);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("transient.opc");
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let base = PreparedBase::prepare(
            &storage,
            crate::consensus::native::generation::BaseParameters {
                binding: ROOT,
                file_epoch: 4,
                checkpoint_epoch: 11,
                operation_sequence: 18,
                cut_binding: [0xE0; 32],
                block_bytes: BLOCK,
                maximum,
            },
            &|| Ok(()),
        )
        .unwrap()
        .legacy_for_test(maximum, &|| Ok(()))
        .unwrap();
        let identity = base.write_to(&mut output, &|| Ok(())).unwrap();
        output.sync_all().unwrap();
        drop(output);
        drop(base);
        assert_eq!(&std::fs::read(&path).unwrap()[..8], b"OPCNJ002");
        let (mut owner, base_catalog) = Catalog::open(
            &path,
            identity,
            maximum,
            crate::consensus::native::generation::CatalogScope {
                identity: storage.business.identity,
                members: &storage.business.members,
                roster_root: storage.business.roster_root.clone(),
            },
            [0xE0; 32],
            &|| Ok(()),
        )
        .unwrap();
        drop(base_catalog);
        let version = Version::capture(&storage).unwrap();
        let selected = owner.current();
        let physical_length = std::fs::metadata(&path).unwrap().len();
        storage.begin_changes().unwrap();
        let mut captured = transient_history_capture(&mut storage);
        if omit {
            omit_transient_history_receipt(&mut captured);
        }
        let prepared = PreparedDelta::prepare(
            selected.clone(),
            &version,
            12,
            18,
            [0xE1; 32],
            captured,
            &|| Ok(()),
        );
        if omit {
            assert_eq!(
                prepared.err().unwrap().to_string(),
                "native history binding and reclamation conservation differs"
            );
            assert_eq!(owner.current().identity(), selected.identity());
            assert_eq!(std::fs::metadata(&path).unwrap().len(), physical_length);
        } else {
            let prepared = prepared.unwrap();
            assert_eq!(
                prepared.header.changed[1],
                FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
            );
            assert!(prepared.payload_bytes() > 0);
            prepared.append(&mut owner, &|| Ok(())).unwrap();
            drop(prepared);
            let final_identity = owner.current().identity();
            let (_, catalog) = Catalog::open(
                &path,
                final_identity,
                maximum,
                crate::consensus::native::generation::CatalogScope {
                    identity: storage.business.identity,
                    members: &storage.business.members,
                    roster_root: storage.business.roster_root.clone(),
                },
                [0xE1; 32],
                &|| Ok(()),
            )
            .unwrap();
            let restored = catalog.into_storage(&|| Ok(())).unwrap();
            assert_eq!(
                Version::capture(&restored)
                    .unwrap()
                    .context_digest()
                    .unwrap(),
                Version::capture(&storage)
                    .unwrap()
                    .context_digest()
                    .unwrap()
            );
            assert_eq!(restored.business.history(), storage.business.history());
            assert_eq!(restored.business.receipt_count(), 0);
            let original = std::fs::read(&path).unwrap();
            let start = selected.identity().length as usize;
            let length =
                u32::from_le_bytes(original[start + 8..start + 12].try_into().unwrap()) as usize;
            let mut malformed: Header =
                serde_json::from_slice(&original[start + 12..start + 12 + length]).unwrap();
            malformed.changed[1] = validation::MAX_ITEMS;
            let encoded = serde_json::to_vec(&malformed).unwrap();
            let mut bad = original[..start + 8].to_vec();
            bad.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            bad.extend_from_slice(&encoded);
            bad.extend_from_slice(&original[start + 12 + length..]);
            bad.resize(bad.len().div_ceil(BLOCK) * BLOCK, 0);
            let bad_path = directory.path().join("impossible-extent.opc");
            std::fs::write(&bad_path, &bad).unwrap();
            let bad_identity = PrefixIdentity {
                length: bad.len() as u64,
                digest: Sha256::digest(&bad).into(),
                ..final_identity
            };
            let error = Catalog::open(
                &bad_path,
                bad_identity,
                maximum,
                crate::consensus::native::generation::CatalogScope {
                    identity: storage.business.identity,
                    members: &storage.business.members,
                    roster_root: storage.business.roster_root.clone(),
                },
                [0xE1; 32],
                &|| Ok(()),
            )
            .err()
            .unwrap();
            assert_eq!(
                error.to_string(),
                "native generation counts exceed selected extent"
            );
            assert_eq!(std::fs::read(&path).unwrap(), original);
            assert_eq!(owner.current().identity(), final_identity);
        }
        assert!(!selected.is_failed());
        storage.validate_image().unwrap();
    }
}

#[test]
fn native_v1_current_delta_over_original_generic_base_preserves_cold_commitments() {
    let (mut storage, _, outcome) = fixture();
    apply(&mut storage, &[clock(2, time(2))]);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("mixed-versions.opc");
    let maximum = crate::consensus::snapshot::SNAPSHOT_DATABASE_MAX_BYTES;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let base = PreparedBase::prepare(
        &storage,
        crate::consensus::native::generation::BaseParameters {
            binding: ROOT,
            file_epoch: 4,
            checkpoint_epoch: 11,
            operation_sequence: 18,
            cut_binding: [0xE0; 32],
            block_bytes: BLOCK,
            maximum,
        },
        &|| Ok(()),
    )
    .unwrap()
    .legacy_for_test(maximum, &|| Ok(()))
    .unwrap();
    let identity = base.write_to(&mut output, &|| Ok(())).unwrap();
    output.sync_all().unwrap();
    drop(output);
    drop(base);
    let original = std::fs::read(&path).unwrap();
    assert_eq!(&original[..8], b"OPCNJ002");
    let (mut owner, catalog) = Catalog::open(
        &path,
        identity,
        maximum,
        crate::consensus::native::generation::CatalogScope {
            identity: storage.business.identity,
            members: &storage.business.members,
            roster_root: storage.business.roster_root.clone(),
        },
        [0xE0; 32],
        &|| Ok(()),
    )
    .unwrap();
    let restored = catalog.into_storage(&|| Ok(())).unwrap();
    assert_eq!(
        Version::capture(&restored)
            .unwrap()
            .context_digest()
            .unwrap(),
        Version::capture(&storage)
            .unwrap()
            .context_digest()
            .unwrap()
    );
    let old_generic = storage
        .business
        .generic_receipts
        .iter()
        .map(|(id, row)| (*id, changes::fingerprint(2, id, &**row).unwrap()))
        .collect::<Vec<_>>();
    let version = Version::capture(&storage).unwrap();
    storage.begin_changes().unwrap();
    let request = super::super::v1::tests::request(901, &request(2, Some(&outcome)));
    apply(
        &mut storage,
        &[super::super::v1::tests::command(3, &request, time(3), true)],
    );
    let delta = PreparedDelta::prepare(
        owner.current(),
        &version,
        12,
        21,
        [0xE1; 32],
        storage.take_changes().unwrap(),
        &|| Ok(()),
    )
    .unwrap();
    delta.append(&mut owner, &|| Ok(())).unwrap();
    let selected = owner.current().identity();
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(&bytes[..original.len()], original.as_slice());
    assert_eq!(&bytes[original.len()..original.len() + 8], b"OPCNJD04");
    let (_, catalog) = Catalog::open(
        &path,
        selected,
        maximum,
        crate::consensus::native::generation::CatalogScope {
            identity: storage.business.identity,
            members: &storage.business.members,
            roster_root: storage.business.roster_root.clone(),
        },
        [0xE1; 32],
        &|| Ok(()),
    )
    .unwrap();
    let restored = catalog.into_storage(&|| Ok(())).unwrap();
    assert_eq!(
        Version::capture(&restored)
            .unwrap()
            .context_digest()
            .unwrap(),
        Version::capture(&storage)
            .unwrap()
            .context_digest()
            .unwrap()
    );
    assert_eq!(
        restored.business.status_v1(&request).unwrap(),
        storage.business.status_v1(&request).unwrap()
    );
    for (id, expected) in old_generic {
        assert_eq!(
            changes::fingerprint(
                2,
                &id,
                &**restored.business.generic_receipts.get(&id).unwrap()
            )
            .unwrap(),
            expected
        );
    }
    let mut mislabeled = bytes.clone();
    mislabeled[original.len()..original.len() + 8].copy_from_slice(b"OPCNJD02");
    let bad_path = directory.path().join("mislabeled.opc");
    std::fs::write(&bad_path, &mislabeled).unwrap();
    let bad_identity = PrefixIdentity {
        digest: Sha256::digest(&mislabeled).into(),
        ..selected
    };
    assert_eq!(
        Catalog::open(
            &bad_path,
            bad_identity,
            maximum,
            crate::consensus::native::generation::CatalogScope {
                identity: storage.business.identity,
                members: &storage.business.members,
                roster_root: storage.business.roster_root.clone()
            },
            [0xE1; 32],
            &|| Ok(()),
        )
        .err()
        .unwrap()
        .to_string(),
        "native V1 context requires generation format three"
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}
