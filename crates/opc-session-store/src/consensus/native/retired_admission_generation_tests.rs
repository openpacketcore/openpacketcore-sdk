use super::*;
use crate::fenced_mutation_roster_executor::{
    AuthorityBinding, AuthorityLeaseMetadata, RecoveryLookup, RecoveryRequest, RecoveryRequestInput,
};
use crate::fenced_mutation_roster_storage::retired_admission_witness_fence_for_test as witness_fence;
use crate::sqlite::consensus::{roster_reads, ProtectedRosterV2ReadResult};
use crate::{FenceToken, Generation, OwnerId};

#[test]
fn retired_admission_witness_native_rebound_generation_rejects_false_maxima_and_omission() {
    let signed = crate::consensus::types::roster_v2_aborted_persistence_fixture();
    let mut storage = configured(&signed);
    let (mut files, _) = Files::new(&storage);
    storage.begin_changes().unwrap();
    apply(
        &mut storage,
        &[
            q1(&signed, 1),
            q2(&signed, 2),
            maintenance(&signed, 3),
            maintenance(&signed, 4),
        ],
    );
    let prepared = files.prepare(&mut storage, 24);
    let mut payload = Vec::new();
    prepared.write_payload(&mut payload, &|| Ok(())).unwrap();
    for maximum in [None, Some(0), Some(8), Some(10)] {
        let mut wire = Wire::<Header>::read(&payload);
        let roster = wire.header.after.business.roster.as_mut().unwrap();
        assert_eq!(witness_fence(roster.witness.unwrap()), Some(9));
        roster.witness = maximum.map(|maximum| {
            let mut value = serde_json::to_value(roster.witness.unwrap()).unwrap();
            value["highest_retired_admission_fence"] = maximum.into();
            serde_json::from_value(value).unwrap()
        });
        let rejected = rejected_delta(&files, &wire, &storage);
        assert!(
            rejected.contains(if maximum.is_none() || maximum == Some(0) {
                "witness"
            } else {
                "exact authenticated closure"
            }),
            "unexpected rejection: {rejected}"
        );
    }
    prepared.append(&mut files.owner, &|| Ok(())).unwrap();
    let (_, catalog) = Catalog::open(
        &files.path,
        files.owner.current().identity(),
        MAXIMUM,
        crate::consensus::native::generation::CatalogScope {
            identity: signed.identity,
            members: &storage.business.members,
            roster_root: storage.business.roster_root.clone(),
        },
        prepared.header.cut_binding,
        &|| Ok(()),
    )
    .unwrap();
    assert_eq!(
        witness_fence(
            catalog
                .into_storage(&|| Ok(()))
                .unwrap()
                .business
                .roster
                .witness
                .unwrap()
        ),
        Some(9)
    );
}

fn retired(checkpoint_admission: bool) -> (Files, NativeStorage, RosterV2PersistenceFixture) {
    let signed = crate::consensus::types::roster_v2_aborted_persistence_fixture();
    let mut storage = configured(&signed);
    let (mut files, _) = Files::new(&storage);
    storage.begin_changes().unwrap();
    let result = apply(&mut storage, &[q1(&signed, 1), q2(&signed, 2)]);
    assert!(matches!(
        result.responses[0].result,
        Ok(SessionMutationOutcome::RosterAdmissionV2(
            ConsensusRosterAdmissionOutcome::Admitted { .. }
        ))
    ));
    assert!(matches!(
        result.responses[1].result,
        Ok(SessionMutationOutcome::RosterTerminalV2(
            ConsensusRosterTerminalOutcome::Committed {
                replayed: false,
                ..
            }
        ))
    ));
    if checkpoint_admission {
        reopen(&mut files, &mut storage, 22);
    }
    let result = apply(
        &mut storage,
        &[maintenance(&signed, 3), maintenance(&signed, 4)],
    );
    assert!(result
        .responses
        .iter()
        .all(|response| response.result.is_ok()));
    assert!(storage.business.roster.rows.is_empty());
    assert!(storage.business.roster.partitions.is_empty());
    assert_eq!(
        storage
            .business
            .roster
            .witness
            .unwrap()
            .retired_terminal_sequence(),
        2
    );
    reopen(&mut files, &mut storage, 24);
    assert!(storage.business.roster.rows.is_empty());
    assert!(!storage.business.keys[signed.authority.key()].reserved);
    (files, storage, signed)
}

#[test]
fn retired_admission_witness_native_generation_deletion_survives_cold_reopen() {
    let (_files, storage, signed) = retired(true);
    assert_eq!(witness_fence(storage.business.roster.witness.unwrap()), Some(signed.authority.fence().get()),
        "a generation removal must persist original authority after the final row and partition disappear");
}

#[test]
fn retired_admission_witness_native_transient_creation_and_deletion_survive_reopen() {
    let (_files, storage, signed) = retired(false);
    assert_eq!(witness_fence(storage.business.roster.witness.unwrap()), Some(signed.authority.fence().get()),
        "coalesced creation and removal within one generation must not erase the retired-fence contribution");
}

#[test]
fn retired_admission_witness_native_compacted_base_preserves_empty_ledger_history() {
    let (_files, storage, signed) = retired(true);
    let (_compacted_files, catalog) = Files::new(&storage);
    drop(storage);
    let reopened = catalog.into_storage(&|| Ok(())).unwrap();
    reopened.validate_image().unwrap();
    assert!(
        reopened.business.roster.rows.is_empty() && reopened.business.roster.partitions.is_empty()
    );
    assert_eq!(
        witness_fence(reopened.business.roster.witness.unwrap()),
        Some(signed.authority.fence().get()),
        "a rewritten native base must not reconstruct the maximum from surviving rows"
    );
}

fn acquire(
    storage: &mut NativeStorage,
    signed: &RosterV2PersistenceFixture,
    index: u64,
    now: Timestamp,
    owner: OwnerId,
) -> LeaseGuard {
    let mut command = entry(
        signed,
        index,
        SessionConsensusRequestId::from_bytes((0xB000 + u128::from(index)).to_be_bytes()),
        SessionMutationIntent::AcquireLease {
            key: signed.authority.key().clone(),
            owner,
            ttl: std::time::Duration::from_secs(60),
        },
    );
    let EntryPayload::Normal(value) = &mut command.payload else {
        unreachable!()
    };
    value.logical_time = now;
    let result = apply(storage, &[command]);
    let Ok(SessionMutationOutcome::Lease(guard)) = &result.responses[0].result else {
        panic!("ordinary native lease acquisition must succeed")
    };
    guard.clone()
}

fn native_absence(original_delta: i64, missing: bool) {
    let (mut files, mut storage, signed) = retired(true);
    let due = signed
        .authority
        .acquired_at()
        .add_seconds(1 + 24 * 60 * 60)
        .unwrap();
    let original = acquire(
        &mut storage,
        &signed,
        5,
        due,
        signed.authority.owner().clone(),
    );
    assert_eq!(original.fence().get(), signed.authority.fence().get() + 1);
    assert!(storage.business.roster.rows.is_empty());
    let now = due.add_seconds(61).unwrap();
    let successor = acquire(
        &mut storage,
        &signed,
        6,
        now,
        OwnerId::new("native-witness-successor").unwrap(),
    );
    assert!(successor.fence() > original.fence());
    reopen(&mut files, &mut storage, 26);
    let authority = AuthorityBinding::from_consensus_parts(
        signed.admission.scope().digest(),
        successor.key().clone(),
        successor.owner().clone(),
        successor.fence(),
        AuthorityLeaseMetadata::new(
            successor.credential_id(),
            Generation::new(1),
            successor.acquired_at(),
            successor.expires_at(),
        ),
    )
    .unwrap();
    let request = RecoveryRequest::new(RecoveryRequestInput::new(
        RecoveryLookup::new(
            signed.admission.scope(),
            crate::fenced_mutation_roster::RosterId::from_bytes([0xE3; 16]).unwrap(),
        ),
        signed.authority.owner().clone(),
        FenceToken::new(
            signed
                .authority
                .fence()
                .get()
                .checked_add_signed(original_delta)
                .unwrap(),
        ),
        authority,
    ))
    .and_then(|request| request.bind_original_key(signed.authority.key().clone()))
    .unwrap();
    let read = storage
        .business
        .with_roster_read(signed.identity, now, &|| Ok(()), |store, at| {
            roster_reads::read_protected_roster_v2_recovery_sync(
                store,
                signed.identity,
                &request,
                at,
            )
        })
        .unwrap();
    if missing {
        assert!(
            matches!(read, ProtectedRosterV2ReadResult::Missing),
            "native cold recovery above the retired original maximum must remain conclusive"
        );
    } else {
        assert!(matches!(
            read,
            ProtectedRosterV2ReadResult::HistoryUnavailable
        ));
    }
}

#[test]
fn retired_admission_witness_native_above_maximum_remains_verified_missing() {
    native_absence(1, true);
}

#[test]
fn retired_admission_witness_native_below_and_equal_are_inconclusive_controls() {
    native_absence(-1, false);
    native_absence(0, false);
}
