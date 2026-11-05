//! Capacity witness for variable-width canonical predecessor headers.
use super::*;

fn canonical_owner(
    storage: &NativeStorage,
    path: &std::path::Path,
    file_epoch: u64,
    checkpoint_epoch: u64,
    cut: [u8; 32],
    sequence: u64,
) -> VerifiedAppendOwner {
    let maximum = 3 * BLOCK as u64;
    let base = StreamingBase::prepare(
        storage,
        BaseParameters {
            binding: ROOT,
            file_epoch,
            checkpoint_epoch,
            operation_sequence: sequence,
            cut_binding: cut,
            block_bytes: BLOCK,
            maximum,
        },
        &|| Ok(()),
    )
    .unwrap();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    let created = base
        .write_new_concurrent(file, maximum, &|| Ok(()))
        .unwrap();
    created.file().sync_all().unwrap();
    created.admit(path, &|| Ok(())).unwrap()
}

fn changed_log(
    storage: &NativeStorage,
    previous: Arc<VerifiedPrefix>,
    version: &Version,
    original: &crate::fenced_transition::FencedTransitionV2Request,
    ciphertext_bytes: usize,
    extra_digit: bool,
) -> (NativeStorage, PreparedDelta) {
    use crate::fenced_transition::{
        FencedTransitionLease, FencedTransitionMutation, FencedTransitionV2Request,
        FencedTransitionV2RequestId,
    };
    #[derive(Serialize)]
    struct Wire<'a> {
        request_id: FencedTransitionV2RequestId,
        lease: &'a FencedTransitionLease,
        mutation: FencedTransitionMutation,
    }
    let mut record = original.mutation().record().unwrap().clone();
    let mut envelope = opc_crypto::CryptoEnvelopeV1::decode(record.payload.as_bytes()).unwrap();
    envelope.ciphertext_and_tag = vec![0; ciphertext_bytes];
    if extra_digit {
        *envelope.ciphertext_and_tag.last_mut().unwrap() = 10;
    }
    record.payload =
        crate::EncryptedSessionPayload::try_envelope(envelope.encode().unwrap()).unwrap();
    // Conflicting request bodies are an existing admitted log vocabulary; the
    // original row-limit regression exercises the same shape. Never apply it.
    let request: FencedTransitionV2Request = postcard::from_bytes(
        &postcard::to_allocvec(&Wire {
            request_id: original.request_id(),
            lease: original.lease(),
            mutation: FencedTransitionMutation::create(record),
        })
        .unwrap(),
    )
    .unwrap();
    let entry = command(2, &request, time(2), false);
    crate::sqlite::consensus::validate_command_for_log(
        match &entry.payload {
            EntryPayload::Normal(command) => command,
            _ => unreachable!(),
        },
        storage.business.identity,
    )
    .unwrap();
    let mut storage = storage.clone();
    storage.begin_changes().unwrap();
    storage
        .log
        .project(
            &Operation::Append(vec![serde_json::to_vec(&entry).unwrap().into()]),
            &storage.business,
            None,
        )
        .unwrap();
    let delta = PreparedDelta::prepare(
        previous,
        version,
        13,
        19,
        [0xD3; 32],
        storage.take_changes().unwrap(),
        &|| Ok(()),
    )
    .unwrap();
    (storage, delta)
}

#[test]
fn native_rollover_rebased_header_growth_preserves_space_for_the_switch() {
    let (mut storage, original, _) = fixture();
    let directory = tempfile::tempdir().unwrap();
    let old_path = directory.path().join("old.native");
    let mut old = canonical_owner(&storage, &old_path, 4, 11, [0xC1; 32], 18);
    storage.begin_changes().unwrap();
    let version = Version::capture(&storage).unwrap();
    let crossing = PreparedDelta::prepare(
        old.current(),
        &version,
        12,
        18,
        [0xC2; 32],
        storage.take_changes().unwrap(),
        &|| Ok(()),
    )
    .unwrap();
    crossing.append(&mut old, &|| Ok(())).unwrap();
    let cut = old.current().identity();
    assert_eq!(cut.length, 2 * BLOCK as u64);
    let (_, small) = changed_log(&storage, old.current(), &version, &original, 16, false);
    let old_header = serde_json::to_vec(&small.header).unwrap();
    let mut choice = None;
    for byte in 0..=64_u8 {
        let path = directory.path().join(format!("new-{byte}.preparing"));
        let owner = canonical_owner(&storage, &path, 5, 12, [byte; 32], 18);
        let mut header: Header = serde_json::from_slice(&old_header).unwrap();
        header.previous = owner.current().identity().into();
        let grown = serde_json::to_vec(&header).unwrap().len();
        if grown > old_header.len() + 2 {
            choice = Some((path, owner, grown - old_header.len()));
            break;
        }
    }
    let (new_path, mut new, header_growth) =
        choice.expect("a canonical predecessor with a wider decimal digest");
    let estimate = 16 + (BLOCK - small.payload_bytes() as usize) / 2;
    drop(small);
    let mut choice = None;
    for length in estimate.saturating_sub(64)..=estimate + 64 {
        for extra in [false, true] {
            let (storage, delta) =
                changed_log(&storage, old.current(), &version, &original, length, extra);
            let size = delta.payload_bytes() as usize;
            if size <= BLOCK && size + header_growth > BLOCK {
                choice = Some((storage, delta));
                break;
            }
        }
        if choice.is_some() {
            break;
        }
    }
    let (mut storage, delta) = choice.expect("a valid admitted log frame at the block boundary");
    let old_payload = delta.payload_bytes();
    let old_view = delta.append(&mut old, &|| Ok(())).unwrap();
    assert_eq!(old_view.identity().length, 3 * BLOCK as u64);
    let (new_view, _) = rebase_frame(
        Arc::clone(&old_view),
        cut,
        old_payload,
        &mut new,
        &|| Ok(()),
    )
    .unwrap();
    assert_eq!(new_view.identity().length, 3 * BLOCK as u64);
    // Both whole files cold-admit. The witness is a capacity defect, not an
    // invalid header, opaque-body bypass or malformed log fixture.
    for (path, view) in [(&old_path, &old_view), (&new_path, &new_view)] {
        let (_, catalog) = Catalog::open(
            path,
            view.identity(),
            3 * BLOCK as u64,
            CatalogScope {
                identity: storage.business.identity,
                members: &storage.business.members,
                roster_root: storage.business.roster_root.clone(),
            },
            [0xD3; 32],
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
    let switch = PreparedDelta::prepare(
        new.current(),
        &Version::capture(&storage).unwrap(),
        14,
        19,
        [0xD4; 32],
        storage.take_changes().unwrap(),
        &|| Ok(()),
    )
    .unwrap();
    let switch_payload = switch.payload_bytes();
    let result = switch.append_switch(&mut new, &|| Ok(())).unwrap();
    assert!(result.is_none(), "capacity rejection must precede append");
    assert!(!old_view.is_failed());
    assert!(!new_view.is_failed());
    new.confirm_named(&new_path).unwrap();
    new.retire();
    std::fs::remove_file(&new_path).unwrap();
    std::fs::File::open(directory.path())
        .unwrap()
        .sync_all()
        .unwrap();
    let mut retained = [0; 8];
    new_view.read_exact_at(0, &mut retained).unwrap();
    assert!(!new_view.is_failed());
    eprintln!("rollover_capacity_checked block={BLOCK} ceiling={} cut={} old_payload={old_payload} header_growth={header_growth} old_head={} candidate_head={} switch_payload={switch_payload} old_failed={} discarded_source_failed={}", 3 * BLOCK, cut.length, old_view.identity().length, new_view.identity().length, old_view.is_failed(), new_view.is_failed());
    // A fresh build at the later selected head fits the very same ceiling.
    // Reuse only the owned preparing name, at a strictly newer selected cut.
    let fresh_path = new_path;
    let mut fresh = canonical_owner(&storage, &fresh_path, 5, 13, [0xF3; 32], 19);
    let fresh_base = fresh.current().identity().length;
    let fresh_switch = PreparedDelta::prepare(
        fresh.current(),
        &Version::capture(&storage).unwrap(),
        14,
        19,
        [0xD4; 32],
        storage.take_changes().unwrap(),
        &|| Ok(()),
    )
    .unwrap();
    let (fresh_view, _) = fresh_switch
        .append_switch(&mut fresh, &|| Ok(()))
        .unwrap()
        .unwrap();
    let (_, catalog) = Catalog::open(
        &fresh_path,
        fresh_view.identity(),
        3 * BLOCK as u64,
        CatalogScope {
            identity: storage.business.identity,
            members: &storage.business.members,
            roster_root: storage.business.roster_root.clone(),
        },
        [0xD4; 32],
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
    eprintln!("rollover_capacity_fresh_build_control base={fresh_base} switched={} ceiling={} old_failed={} fresh_failed={}", fresh_view.identity().length, 3 * BLOCK, old_view.is_failed(), fresh_view.is_failed());
    assert!(result.is_none());
    assert!(!old_view.is_failed());
    assert!(!new_view.is_failed());
    assert!(!fresh_view.is_failed());
}

#[test]
fn native_checkpoint_delta_payload_can_exceed_the_verification_allowance() {
    use crate::consensus::verified_snapshot::{VerificationMemory, PROCESS_VERIFICATION_BYTES};
    use crate::fenced_transition::{
        FencedTransitionLease, FencedTransitionMutation, FencedTransitionV2Request,
        FencedTransitionV2RequestId,
    };
    #[derive(Serialize)]
    struct Wire<'a> {
        request_id: FencedTransitionV2RequestId,
        lease: &'a FencedTransitionLease,
        mutation: FencedTransitionMutation,
    }
    let (mut storage, original, _) = fixture();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bounded-delta.native");
    let maximum = 8 * 1024 * 1024 * 1024;
    let base = StreamingBase::prepare(
        &storage,
        BaseParameters {
            binding: ROOT,
            file_epoch: 4,
            checkpoint_epoch: 11,
            operation_sequence: 18,
            cut_binding: [0xC1; 32],
            block_bytes: BLOCK,
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
    let created = base
        .write_new_concurrent(output, maximum, &|| Ok(()))
        .unwrap();
    created.file().sync_all().unwrap();
    let mut owner = created.admit(&path, &|| Ok(())).unwrap();
    let version = Version::capture(&storage).unwrap();
    storage.begin_changes().unwrap();
    let mut record = original.mutation().record().unwrap().clone();
    let mut envelope = opc_crypto::CryptoEnvelopeV1::decode(record.payload.as_bytes()).unwrap();
    envelope.ciphertext_and_tag = vec![0; 8 * 1024 * 1024 - 16 * 1024];
    record.payload =
        crate::EncryptedSessionPayload::try_envelope(envelope.encode().unwrap()).unwrap();
    let request: FencedTransitionV2Request = postcard::from_bytes(
        &postcard::to_allocvec(&Wire {
            request_id: original.request_id(),
            lease: original.lease(),
            mutation: FencedTransitionMutation::create(record),
        })
        .unwrap(),
    )
    .unwrap();
    let before = VerificationMemory::used_bytes();
    for index in 2..=10 {
        let entry = command(index, &request, time(2), false);
        let bytes = serde_json::to_vec(&entry).unwrap();
        assert!(bytes.len() <= crate::sqlite::consensus::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES);
        storage
            .log
            .project(
                &Operation::Append(vec![bytes.into()]),
                &storage.business,
                None,
            )
            .unwrap();
    }
    let journal = storage.changed_verification_bytes();
    let retained_charge = VerificationMemory::used_bytes().saturating_sub(before);
    let delta = PreparedDelta::prepare(
        owner.current(),
        &version,
        12,
        27,
        [0xD2; 32],
        storage.take_changes().unwrap(),
        &|| Ok(()),
    )
    .unwrap();
    let payload = delta.payload_bytes();
    eprintln!("native_switch_reserve_bound rows=9 payload={payload} journal_charge={journal} retained_charge={retained_charge} verification_cap={PROCESS_VERIFICATION_BYTES} ceiling={maximum}");
    assert!(payload > PROCESS_VERIFICATION_BYTES as u64);
    assert!(journal < 8 * 1024 * 1024);
    assert!(retained_charge < 8 * 1024 * 1024);
    let source = delta.append(&mut owner, &|| Ok(())).unwrap();
    let (_, catalog) = Catalog::open(
        &path,
        source.identity(),
        maximum,
        CatalogScope {
            identity: storage.business.identity,
            members: &storage.business.members,
            roster_root: storage.business.roster_root.clone(),
        },
        [0xD2; 32],
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
    eprintln!(
        "native_switch_reserve_bound cold_admission=passed source_failed={}",
        source.is_failed()
    );
}

#[test]
fn native_rollover_pending_cut_retirement_keeps_old_source_healthy() {
    for mode in [
        crate::SessionPersistenceMode::Durable,
        crate::SessionPersistenceMode::Async,
    ] {
        let (storage, original, _) = fixture();
        let directory = tempfile::tempdir().unwrap();
        let seed_path = directory.path().join("seed.native");
        let seed = canonical_owner(&storage, &seed_path, 3, 12, [0xC0; 32], 18);
        let (mut storage, delta) = changed_log(
            &storage,
            seed.current(),
            &Version::capture(&storage).unwrap(),
            &original,
            70 * 1024,
            false,
        );
        drop(delta);
        let selected_storage = storage.clone();
        let old_path = directory.path().join("selected.native");
        let mut old = canonical_owner(&selected_storage, &old_path, 4, 12, [0xC2; 32], 19);
        let selected = old.current();
        assert_eq!(selected.identity().length, 3 * BLOCK as u64);
        let (_, catalog) = Catalog::open(
            &old_path,
            selected.identity(),
            3 * BLOCK as u64,
            CatalogScope {
                identity: storage.business.identity,
                members: &storage.business.members,
                roster_root: storage.business.roster_root.clone(),
            },
            [0xC2; 32],
            &|| Ok(()),
        )
        .unwrap();
        let reopened = catalog.into_storage(&|| Ok(())).unwrap();
        assert_eq!(
            Version::capture(&reopened)
                .unwrap()
                .context_digest()
                .unwrap(),
            selected.identity().frontiers
        );
        let candidate_path = directory.path().join("candidate.preparing");
        let mut candidate =
            canonical_owner(&selected_storage, &candidate_path, 5, 12, [0xE2; 32], 19);
        assert_eq!(
            candidate.current().identity().length,
            selected.identity().length
        );
        let mut empty = selected_storage.clone();
        empty.begin_changes().unwrap();
        let switch = PreparedDelta::prepare(
            candidate.current(),
            &Version::capture(&selected_storage).unwrap(),
            13,
            19,
            [0xE3; 32],
            empty.take_changes().unwrap(),
            &|| Ok(()),
        )
        .unwrap();
        assert!(switch
            .append_switch(&mut candidate, &|| Ok(()))
            .unwrap()
            .is_none());
        assert!(!candidate.current().is_failed());
        // Grant retirement every opportunity: this is a valid truncation of
        // an unapplied/uncommitted row, even if admission is already held.
        // It makes resident logical state small, without inventing a selected
        // CURRENT or changing any disk/header authority.
        let truncate = storage.log.entries.get(&2).unwrap().id();
        storage
            .log
            .project(&Operation::Truncate(truncate), &storage.business, None)
            .unwrap();
        let retirement = PreparedDelta::prepare(
            old.current(),
            &Version::capture(&selected_storage).unwrap(),
            13,
            20,
            [0xC3; 32],
            storage.take_changes().unwrap(),
            &|| Ok(()),
        )
        .unwrap();
        let actual_fits = old.fits_append(retirement.payload_bytes(), 0);
        let checked = retirement.append_switch(&mut old, &|| Ok(())).unwrap();
        assert!(checked.is_none());
        assert!(!selected.is_failed());
        let retired_path = directory.path().join("retired-but-not-selected.preparing");
        let retired = canonical_owner(&storage, &retired_path, 5, 13, [0xE3; 32], 20);
        let retired_view = retired.current();
        assert_eq!(retired_view.identity().length, BLOCK as u64);
        assert_ne!(
            retired_view.identity().frontiers,
            selected.identity().frontiers
        );
        let (_, catalog) = Catalog::open(
            &retired_path,
            retired_view.identity(),
            3 * BLOCK as u64,
            CatalogScope {
                identity: storage.business.identity,
                members: &storage.business.members,
                roster_root: storage.business.roster_root.clone(),
            },
            [0xE3; 32],
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
        eprintln!("native_live_capacity_cut_witness mode={mode:?} ceiling={} selected_epoch={} selected_sequence={} selected_bytes={} candidate_bytes={} retired_sequence=20 retirement_payload={} actual_old_append_fits={actual_fits} retired_base={} old_failed={} candidate_failed={} retired_failed={}", 3 * BLOCK, selected.identity().checkpoint_epoch, selected.identity().operation_sequence, selected.identity().length, candidate.current().identity().length, retirement.payload_bytes(), retired_view.identity().length, selected.is_failed(), candidate.current().is_failed(), retired_view.is_failed());
        // The approved capacity-only path selects this complete pending-cut
        // base, rather than requiring a delta on the full old selected file.
        // Its header covers exactly the advanced operation and checkpoint cut.
        assert!(!actual_fits);
        assert_eq!(retired_view.identity().checkpoint_epoch, 13);
        assert_eq!(retired_view.identity().operation_sequence, 20);
        assert!(retired_view.identity().length <= 3 * BLOCK as u64);
        Version::require_capture(&retirement.into_capture(), &storage, &|| Ok(())).unwrap();
        assert!(!selected.is_failed());
        assert!(!candidate.current().is_failed());
        assert!(!retired_view.is_failed());
    }
}

#[test]
fn native_rollover_deferred_selected_capture_releases_the_retired_source() {
    let (storage, _, _) = fixture();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("old.native");
    let original = canonical_owner(&storage, &path, 4, 12, [0xA1; 32], 19);
    let (old, catalog) = Catalog::open(
        &path,
        original.current().identity(),
        3 * BLOCK as u64,
        CatalogScope {
            identity: storage.business.identity,
            members: &storage.business.members,
            roster_root: storage.business.roster_root.clone(),
        },
        [0xA1; 32],
        &|| Ok(()),
    )
    .unwrap();
    let weak = old.current().weak_source_for_test();
    let mut live = catalog.into_storage(&|| Ok(())).unwrap();
    // A live owner always has a journal, whose purge predecessor index must
    // release relocated source pins as well as the visible selected rows.
    live.begin_changes().unwrap();
    let mut deferred = live.capture_snapshot().unwrap();
    // Negative control: a logically frozen capture owns its original cold
    // source even after every live row has been relocated.
    let unmirrored = live.capture_snapshot().unwrap();
    let next = canonical_owner(
        &live,
        &directory.path().join("next.native"),
        5,
        13,
        [0xA2; 32],
        19,
    );
    let mut rows =
        Relocations::from_base(live.capture_snapshot().unwrap(), next.current()).unwrap();
    drop(old);
    drop(original);
    while !rows.is_empty() {
        rows.prepare_step(&|| Ok(())).unwrap();
        drop(
            rows.publish_step_mirrored(&mut live, Some(&mut deferred.storage))
                .unwrap(),
        );
    }
    assert!(
        weak.upgrade().is_some(),
        "negative control retains the old source"
    );
    assert_eq!(
        live.cold_counts_for_test(),
        deferred.storage.cold_counts_for_test()
    );
    assert_eq!(
        Version::capture(&live).unwrap().context_digest().unwrap(),
        Version::capture(&deferred.storage)
            .unwrap()
            .context_digest()
            .unwrap()
    );
    drop(unmirrored);
    assert!(
        weak.upgrade().is_none(),
        "the live and deferred roots must both shed old source pins"
    );
    assert!(!next.current().is_failed());
}
