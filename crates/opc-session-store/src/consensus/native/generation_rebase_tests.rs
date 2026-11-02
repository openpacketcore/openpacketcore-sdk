use super::*;

fn pair() -> (
    NativeStorage,
    FileFixture,
    tempfile::TempDir,
    VerifiedAppendOwner,
    PreparedDelta,
) {
    let (mut storage, _, previous) = fixture();
    let file = FileFixture::new(&storage);
    let before = file.owner.current().identity();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("compact.preparing");
    let maximum = 64 * BLOCK as u64;
    let base = StreamingBase::prepare(
        &storage,
        BaseParameters {
            binding: before.binding,
            file_epoch: before.file_epoch + 1,
            checkpoint_epoch: before.checkpoint_epoch,
            operation_sequence: before.operation_sequence,
            cut_binding: [0xE0; 32],
            block_bytes: before.block_bytes,
            maximum,
        },
        &|| Ok(()),
    )
    .unwrap();
    let output = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let created = base.write_new(output, maximum, &|| Ok(())).unwrap();
    created.file().sync_all().unwrap();
    let owner = created.admit(&path, &|| Ok(())).unwrap();
    storage.begin_changes().unwrap();
    let next = request(2, Some(&previous));
    apply(
        &mut storage,
        &[command(2, &next, time(2), false), clock(3, time(3))],
    );
    let delta = PreparedDelta::prepare(
        file.owner.current(),
        &file.version,
        12,
        21,
        [0xDE; 32],
        storage.take_changes().unwrap(),
        &|| Ok(()),
    )
    .unwrap();
    (storage, file, directory, owner, delta)
}

#[test]
fn native_rebase_frame_preserves_the_complete_body_and_cold_admission() {
    let (storage, mut file, directory, mut target, delta) = pair();
    let start = file.owner.current().identity();
    let old = delta.append(&mut file.owner, &|| Ok(())).unwrap();
    let (new, shift) = rebase_frame(
        Arc::clone(&old),
        start,
        delta.payload_bytes(),
        &mut target,
        &|| Ok(()),
    )
    .unwrap();
    let mut original = vec![0; shift.length as usize];
    let mut actual = vec![0; shift.length as usize];
    old.read_exact_at(shift.old_body, &mut original).unwrap();
    new.read_exact_at(shift.new_body, &mut actual).unwrap();
    assert_eq!(actual, original);
    assert_eq!(new.identity().frontiers, old.identity().frontiers);
    assert_eq!(new.identity().file_epoch, start.file_epoch + 1);
    let (_, catalog) = Catalog::open(
        &directory.path().join("compact.preparing"),
        new.identity(),
        64 * BLOCK as u64,
        CatalogScope {
            identity: storage.business.identity,
            members: &storage.business.members,
            roster_root: storage.business.roster_root.clone(),
        },
        [0xDE; 32],
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
}

#[test]
fn native_rebase_frame_rejects_every_predecessor_axis_before_target_mutation() {
    for case in 0..8 {
        let (_, mut file, _directory, mut target, delta) = pair();
        let mut start = file.owner.current().identity();
        let old = delta.append(&mut file.owner, &|| Ok(())).unwrap();
        let before = target.current().identity();
        let mut payload = delta.payload_bytes();
        match case {
            0 => start.binding[0] ^= 1,
            1 => start.file_epoch += 1,
            2 => start.checkpoint_epoch += 1,
            3 => start.operation_sequence += 1,
            4 => start.frontiers[0] ^= 1,
            5 => start.digest[0] ^= 1,
            6 => payload -= 1,
            7 => start.block_bytes = 0,
            _ => unreachable!(),
        }
        assert!(
            rebase_frame(old, start, payload, &mut target, &|| Ok(())).is_err(),
            "case {case}"
        );
        assert_eq!(target.current().identity(), before);
        assert!(!target.current().is_failed());
    }
}

#[test]
fn native_rebase_frame_never_copies_a_corrupt_authenticated_source() {
    use std::os::unix::fs::FileExt;
    let (_, mut file, _directory, mut target, delta) = pair();
    let start = file.owner.current().identity();
    let old = delta.append(&mut file.owner, &|| Ok(())).unwrap();
    let disk = OpenOptions::new()
        .write(true)
        .open(file._directory.path().join("basis.fixture"))
        .unwrap();
    disk.write_all_at(&[0xFF], start.length + 17).unwrap();
    let before = target.current().identity();
    assert!(rebase_frame(
        Arc::clone(&old),
        start,
        delta.payload_bytes(),
        &mut target,
        &|| Ok(())
    )
    .is_err());
    assert!(old.is_failed());
    assert_eq!(target.current().identity(), before);
}

#[test]
fn native_rebase_frame_reserve_rejection_keeps_both_sources_healthy() {
    let (_, mut file, _directory, mut target, delta) = pair();
    let start = file.owner.current().identity();
    let old = delta.append(&mut file.owner, &|| Ok(())).unwrap();
    let before = target.current();
    let result = super::super::rebase::rebase_frame_with_reserve(
        Arc::clone(&old),
        start,
        delta.payload_bytes(),
        &mut target,
        64 * BLOCK as u64,
        &|| Ok(()),
    )
    .unwrap();
    assert!(result.is_none());
    assert_eq!(target.current().identity(), before.identity());
    assert!(!before.is_failed());
    assert!(!old.is_failed());
    let result = super::super::rebase::rebase_frame_with_reserve(
        Arc::clone(&old),
        start,
        delta.payload_bytes(),
        &mut target,
        0,
        &|| Ok(()),
    )
    .unwrap()
    .unwrap();
    assert!(!result.0.is_failed());
    assert!(!old.is_failed());
}

#[test]
fn native_switch_header_growth_bound_covers_every_reencoded_field() {
    let (_, _file, _directory, _target, delta) = pair();
    let bound = delta.switch_payload_bound().unwrap();
    let original = serde_json::to_vec(&delta.header).unwrap();
    for previous in [
        Previous {
            binding: [0; 32],
            file_epoch: 0,
            checkpoint_epoch: 0,
            operation_sequence: 0,
            frontiers: [0; 32],
            length: 0,
            block_bytes: 0,
            digest: [0; 32],
        },
        Previous {
            binding: [255; 32],
            file_epoch: u64::MAX,
            checkpoint_epoch: u64::MAX,
            operation_sequence: u64::MAX,
            frontiers: [255; 32],
            length: u64::MAX,
            block_bytes: usize::MAX,
            digest: [255; 32],
        },
    ] {
        for cut in [[0; 32], [255; 32]] {
            let mut header: Header = serde_json::from_slice(&original).unwrap();
            header.previous = previous;
            header.cut_binding = cut;
            let changed = serde_json::to_vec(&header).unwrap();
            let payload = delta.payload_bytes() - original.len() as u64 + changed.len() as u64;
            assert!(payload <= bound);
        }
    }
}
