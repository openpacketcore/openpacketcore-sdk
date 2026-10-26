#[path = "retired_admission_generation_tests.rs"]
mod retired_admission_tests;

use super::*;
use crate::consensus::native::roster::v1_fixture;
use crate::consensus::types::{
    protected_roster_profile_v2_voter_set_digest, protected_roster_profile_voter_set_digest,
    ConsensusRosterAdmissionCommand, ConsensusRosterAdmissionOutcome,
    ConsensusRosterTerminalOutcome, RosterV2PersistenceFixture,
};
use crate::fenced_mutation_roster::{EstablishedMutation, Phase};
use crate::sqlite::consensus::{
    initialize_protected_roster_v2_recovery_fixture_with_members, native_roster_apply_fixture,
    ProtectedRosterV2RecoveryFixtureState,
};
use opc_consensus::engine::Membership;
use rusqlite::Connection;

fn configured(signed: &RosterV2PersistenceFixture) -> NativeStorage {
    let members = [7, 8, 9]
        .into_iter()
        .map(|id| SessionConsensusNodeId::new(id).unwrap())
        .collect();
    let mut storage = NativeStorage::empty(signed.identity, members).unwrap();
    let state = &mut storage.business;
    state.roster_root = Some(Arc::new(signed.root.clone()));
    state.frontiers.roster_v2_activation = Some(NativeActivation {
        identity: signed.identity,
        voters: protected_roster_profile_v2_voter_set_digest(signed.identity, &state.members),
        profile: crate::fenced_mutation_roster::Profile::v2().digest(),
    });
    state.roster.witness =
        Some(crate::fenced_mutation_roster_storage::GlobalChargeWitness::empty());
    let authority = &signed.authority;
    let guard = LeaseGuard::new(
        authority.key().clone(),
        authority.owner().clone(),
        authority.fence(),
        authority.acquired_at(),
        authority.expires_at(),
        authority.credential_id(),
    );
    state.keys.insert(
        authority.key().clone(),
        SharedRow::new(NativeKeyState {
            record: None,
            lease: Some(NativeLease::from_guard(&guard).unwrap()),
            fence: authority.fence().get(),
            reserved: false,
        })
        .unwrap(),
    );
    state.frontiers.next_fence = authority.fence().get() + 1;
    state.frontiers.next_credential = authority.credential_id() + 1;
    state.frontiers.logical_time = Some(authority.acquired_at().add_seconds(1).unwrap());
    state.admit_business().unwrap();
    storage.log.admit(&storage.business).unwrap();
    let members = storage.business.members.clone();
    apply(
        &mut storage,
        &[Entry {
            log_id: LogId::new(
                CommittedLeaderId::new(1, SessionConsensusNodeId::new(7).unwrap()),
                0,
            ),
            payload: EntryPayload::Membership(Membership::new(vec![members.clone()], members)),
        }],
    );
    storage
}

fn entry(
    signed: &RosterV2PersistenceFixture,
    index: u64,
    id: SessionConsensusRequestId,
    mutation: SessionMutationIntent,
) -> Entry<SessionRaftTypeConfig> {
    let origin = SessionConsensusNodeId::new(7).unwrap();
    Entry {
        log_id: LogId::new(CommittedLeaderId::new(1, origin), index),
        payload: EntryPayload::Normal(SessionConsensusCommand {
            schema_version: crate::consensus::SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: signed.identity,
            request_id: id,
            logical_time: signed.authority.acquired_at().add_seconds(1).unwrap(),
            intent: SessionMutationIntent::Authorized {
                origin,
                authority_identity: signed.identity,
                mutation: Box::new(mutation),
            },
        }),
    }
}

fn q1(signed: &RosterV2PersistenceFixture, index: u64) -> Entry<SessionRaftTypeConfig> {
    let command = ConsensusRosterAdmissionCommand::new_with_provenance_and_ingress_request_id_v2(
        signed.admission.clone(),
        signed.authority.clone(),
        signed.admission_ingress.request_id(),
        signed.admission_ingress.clone(),
        signed.admission_provenance.clone(),
    )
    .unwrap();
    entry(
        signed,
        index,
        command.request_id().unwrap(),
        SessionMutationIntent::RosterAdmissionV2(Box::new(command)),
    )
}

fn q2(signed: &RosterV2PersistenceFixture, index: u64) -> Entry<SessionRaftTypeConfig> {
    entry(
        signed,
        index,
        signed.terminal_command.request_id().unwrap(),
        SessionMutationIntent::RosterTerminalV2(Box::new(signed.terminal_command.clone())),
    )
}

fn maintenance(signed: &RosterV2PersistenceFixture, index: u64) -> Entry<SessionRaftTypeConfig> {
    advance_logical_time(signed, index, 1 + 24 * 60 * 60)
}

/// One ordinary logical-time command at an exact offset from the fixture
/// acquisition time. The roster-maintenance lane proposes exactly this intent;
/// this helper lets tests step to the retention boundary and one tick before it.
fn advance_logical_time(
    signed: &RosterV2PersistenceFixture,
    index: u64,
    offset_seconds: i64,
) -> Entry<SessionRaftTypeConfig> {
    let mut value = entry(
        signed,
        index,
        SessionConsensusRequestId::from_bytes((0xA000 + u128::from(index)).to_be_bytes()),
        SessionMutationIntent::AdvanceLogicalTime,
    );
    let EntryPayload::Normal(command) = &mut value.payload else {
        unreachable!()
    };
    command.logical_time = signed
        .authority
        .acquired_at()
        .add_seconds(offset_seconds)
        .unwrap();
    value
}

fn roster_retained_bindings(storage: &NativeStorage) -> usize {
    storage
        .business
        .roster
        .witness
        .expect("signed roster cycle witness")
        .roster_counters()
        .retained_and_live_bindings()
}

fn roster_durable_bindings(storage: &NativeStorage) -> usize {
    storage
        .business
        .roster
        .witness
        .expect("signed roster cycle witness")
        .roster_counters()
        .durable_epoch_bindings()
}

fn journal_key(signed: &RosterV2PersistenceFixture, stable: &'static [u8]) -> SessionKey {
    let mut key = signed.authority.key().clone();
    key.stable_id = bytes::Bytes::from_static(stable)
        .try_into()
        .expect("stable ID");
    key
}

#[test]
fn native_key_retirement_journal_stages_exact_once_and_publishes() {
    let signed = crate::consensus::types::roster_v2_persistence_fixture();
    let mut storage = configured(&signed);
    let key = journal_key(&signed, b"journal-retire");
    let acquire = entry(
        &signed,
        1,
        SessionConsensusRequestId::from_bytes([0xB8; 16]),
        SessionMutationIntent::AcquireLease {
            key: key.clone(),
            owner: signed.authority.owner().clone(),
            ttl: std::time::Duration::from_secs(60),
        },
    );
    let applied = apply(&mut storage, &[acquire]);
    let lease = match &applied.responses[0].result {
        Ok(SessionMutationOutcome::Lease(lease)) => lease.clone(),
        other => panic!("acquire must succeed before retirement: {other:?}"),
    };
    apply(
        &mut storage,
        &[entry(
            &signed,
            2,
            SessionConsensusRequestId::from_bytes([0xB9; 16]),
            SessionMutationIntent::ReleaseLease(lease),
        )],
    );
    let before = storage.business.keys.len();
    storage
        .business
        .apply_key_retirement(key.clone())
        .expect("exact committed predecessor is staged and published");
    storage
        .validate_image()
        .expect("retirement journal image valid");
    assert!(storage.business.keys.get(&key).is_none());
    assert_eq!(storage.business.keys.len(), before - 1);
    // A stale resident expiry entry would surface as an infrastructure failure
    // on the next prune; acquire a fresh key after the retirement to exercise it.
    let prune_trigger = journal_key(&signed, b"journal-prune-trigger");
    let prune_applied = apply(
        &mut storage,
        &[entry(
            &signed,
            3,
            SessionConsensusRequestId::from_bytes([0xBA; 16]),
            SessionMutationIntent::AcquireLease {
                key: prune_trigger,
                owner: signed.authority.owner().clone(),
                ttl: std::time::Duration::from_secs(60),
            },
        )],
    );
    assert!(matches!(
        prune_applied.responses[0].result,
        Ok(SessionMutationOutcome::Lease(_))
    ));
    // The removal journal is exact once: a second retirement of the same key has
    // no committed predecessor and must fail closed without mutation.
    let error = match storage.business.apply_key_retirement(key.clone()) {
        Err(error) => error,
        Ok(_) => panic!("a retired key has no committed predecessor"),
    };
    assert!(error
        .to_string()
        .contains("native key removal has no exact predecessor"));
    assert!(storage.business.keys.get(&key).is_none());
}

#[test]
fn native_key_retirement_collapses_same_delta_create_update_and_duplicates() {
    let signed = crate::consensus::types::roster_v2_persistence_fixture();
    let mut storage = configured(&signed);

    // Create-then-retire: the key never exists as an endpoint; the candidate
    // change is collapsed and the transient journal entry is dropped.
    let created = journal_key(&signed, b"journal-create-retire");
    storage
        .business
        .apply_key_retirements_in_batch(
            &[entry(
                &signed,
                1,
                SessionConsensusRequestId::from_bytes([0xBB; 16]),
                SessionMutationIntent::AcquireLease {
                    key: created.clone(),
                    owner: signed.authority.owner().clone(),
                    ttl: std::time::Duration::from_secs(60),
                },
            )],
            vec![created.clone()],
        )
        .expect("create-then-retire collapses to no endpoint");
    storage
        .validate_image()
        .expect("create-then-retire image valid");
    assert!(storage.business.keys.get(&created).is_none());

    // Update-then-retire: an existing committed key is updated in the same
    // delta and retired; the net change removes the predecessor row.
    let updated = signed.authority.key().clone();
    storage
        .business
        .apply_key_retirements_in_batch(
            &[entry(
                &signed,
                2,
                SessionConsensusRequestId::from_bytes([0xBC; 16]),
                SessionMutationIntent::AcquireLease {
                    key: updated.clone(),
                    owner: signed.authority.owner().clone(),
                    ttl: std::time::Duration::from_secs(60),
                },
            )],
            vec![updated.clone()],
        )
        .expect("update-then-retire stages one net removal");
    storage
        .validate_image()
        .expect("update-then-retire image valid");
    assert!(storage.business.keys.get(&updated).is_none());

    // Same-delta duplicate removals are deduplicated and staged once.
    let duplicate = journal_key(&signed, b"journal-duplicate");
    let acquire = entry(
        &signed,
        3,
        SessionConsensusRequestId::from_bytes([0xBD; 16]),
        SessionMutationIntent::AcquireLease {
            key: duplicate.clone(),
            owner: signed.authority.owner().clone(),
            ttl: std::time::Duration::from_secs(60),
        },
    );
    apply(&mut storage, &[acquire]);
    storage
        .business
        .apply_key_retirements_in_batch(&[], vec![duplicate.clone(), duplicate.clone()])
        .expect("duplicate removals are staged at most once");
    storage
        .validate_image()
        .expect("duplicate retirement image valid");
    assert!(storage.business.keys.get(&duplicate).is_none());
}

#[test]
fn native_key_retirement_without_exact_predecessor_is_rejected() {
    let signed = crate::consensus::types::roster_v2_persistence_fixture();
    let mut storage = configured(&signed);
    let unknown = journal_key(&signed, b"journal-absent");
    let before = storage.business.keys.len();
    let error = match storage.business.apply_key_retirement(unknown) {
        Err(error) => error,
        Ok(_) => panic!("an absent predecessor cannot be retired"),
    };
    assert!(error
        .to_string()
        .contains("native key removal has no exact predecessor"));
    assert_eq!(storage.business.keys.len(), before);
}

#[test]
fn native_key_capacity_batch_boundary_refuses_without_mutation() {
    let signed = crate::consensus::types::roster_v2_persistence_fixture();
    let mut storage = configured(&signed);
    // One existing committed key from the fixture; allow exactly one more.
    let _limit =
        crate::consensus::native::retention::tests_support::KeyCapacityLimitOverride::new(2);
    let owner = signed.authority.owner().clone();
    let key_a = {
        let mut key = signed.authority.key().clone();
        key.stable_id = bytes::Bytes::from_static(b"key-capacity-a")
            .try_into()
            .expect("stable ID");
        key
    };
    let key_b = {
        let mut key = signed.authority.key().clone();
        key.stable_id = bytes::Bytes::from_static(b"key-capacity-b")
            .try_into()
            .expect("stable ID");
        key
    };
    let acquire = |index: u64, key: crate::model::SessionKey| {
        entry(
            &signed,
            index,
            SessionConsensusRequestId::from_bytes([0xB7; 16]),
            SessionMutationIntent::AcquireLease {
                key,
                owner: owner.clone(),
                ttl: std::time::Duration::from_secs(60),
            },
        )
    };
    let applied = apply(&mut storage, &[acquire(1, key_a), acquire(2, key_b)]);
    assert!(matches!(
        applied.responses[0].result,
        Ok(SessionMutationOutcome::Lease(_))
    ));
    assert_eq!(
        applied.responses[1].result,
        Err(StoreError::KeyCapacityExhausted),
        "the second batch key must hit the typed deterministic capacity refusal"
    );
    assert_eq!(
        storage.business.keys.len(),
        2,
        "a refused capacity admission cannot mutate the key map"
    );
}

#[test]
fn roster_only_advance_logical_time_reclaims_retention_before_the_next_admission() {
    // The roster-maintenance lane exists because Q1/Q2 commands must never fold
    // retention work into their frozen mutation width. This is the exact
    // ordinary command that lane proposes; a roster-only store therefore frees
    // eligible retained capacity before it has to evaluate another admission.
    let signed = crate::consensus::types::roster_v2_persistence_fixture();
    let mut storage = configured(&signed);
    apply(&mut storage, &[q1(&signed, 1)]);
    apply(&mut storage, &[q2(&signed, 2)]);
    assert_eq!(roster_retained_bindings(&storage), 1);
    assert_eq!(roster_durable_bindings(&storage), 1);
    assert_eq!(storage.business.roster.rows.len(), 1);

    // One tick before the exact retention boundary a deterministic maintenance
    // turn must not reclaim the young retained row.
    apply(
        &mut storage,
        &[advance_logical_time(&signed, 3, 24 * 60 * 60)],
    );
    assert_eq!(
        roster_retained_bindings(&storage),
        1,
        "the lane must never reclaim before the exact 24 h boundary"
    );
    assert_eq!(storage.business.roster.rows.len(), 1);

    // At the boundary the same ordinary command reclaims the retained
    // reservation (releasing live-plus-retained capacity), then retires the
    // compact tombstone on the following turn (releasing durable capacity).
    apply(&mut storage, &[maintenance(&signed, 4)]);
    assert_eq!(
        roster_retained_bindings(&storage),
        0,
        "retained admission capacity is reclaimed before the next admission"
    );
    assert_eq!(roster_durable_bindings(&storage), 1);
    apply(&mut storage, &[maintenance(&signed, 5)]);
    assert!(
        storage.business.roster.rows.is_empty(),
        "the compact tombstone is retired so durable capacity is also reclaimed"
    );
    assert_eq!(roster_durable_bindings(&storage), 0);
}

fn exact_rosters(restored: &NativeStorage, expected: &NativeStorage) {
    assert_eq!(
        Version::capture(restored)
            .unwrap()
            .context_digest()
            .unwrap(),
        Version::capture(expected)
            .unwrap()
            .context_digest()
            .unwrap()
    );
    assert_eq!(
        restored.business.roster.rows.len(),
        expected.business.roster.rows.len()
    );
    let root = expected.business.roster_root.as_deref().unwrap();
    let scope = roster::fixed_scope(expected.business.identity, &expected.business.members);
    for (binding, row) in &restored.business.roster.rows {
        assert!(row.is_cold());
        let actual = row.hydrate_detached(root, &scope, &|| Ok(())).unwrap();
        let original = expected.business.roster.rows[binding]
            .hydrate_detached(root, &scope, &|| Ok(()))
            .unwrap();
        assert_eq!(actual.canonical(), original.canonical());
        assert!(actual.projection == original.projection && actual.facts == original.facts);
    }
    assert_eq!(
        restored.business.roster.partitions.len(),
        expected.business.roster.partitions.len()
    );
    for (key, row) in &restored.business.roster.partitions {
        assert!(**row == **expected.business.roster.partitions.get(key).unwrap());
    }
    for (key, row) in &expected.business.keys {
        assert_eq!(
            postcard::to_allocvec(&**restored.business.keys.get(key).unwrap()).unwrap(),
            postcard::to_allocvec(&**row).unwrap()
        );
    }
    assert!(restored.business.roster.witness == expected.business.roster.witness);
    restored.validate_image().unwrap();
}

fn reopen(files: &mut Files, storage: &mut NativeStorage, sequence: u64) {
    let catalog = files.append(storage, sequence);
    let mut restored = catalog.into_storage(&|| Ok(())).unwrap();
    exact_rosters(&restored, storage);
    // A cold reader constructs new process certificates from the complete
    // selected prefix. Rebind the test owner to that exact admitted version.
    files.version = Version::capture(&restored).unwrap();
    restored.begin_changes().unwrap();
    *storage = restored;
}

fn sql_rows(storage: &NativeStorage, path: &Path, signed: &RosterV2PersistenceFixture) {
    let conn = Connection::open(path).unwrap();
    let scope = roster::fixed_scope(storage.business.identity, &storage.business.members);
    for (binding, row) in &storage.business.roster.rows {
        let table = match row.projection().profile {
            roster::Profile::V1 => "consensus_protected_roster_rows",
            roster::Profile::V2 => "consensus_protected_roster_v2_admissions",
        };
        let bytes: Vec<u8> = conn
            .query_row(
                &format!("SELECT canonical_record FROM {table} WHERE binding=?1"),
                [binding.to_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            row.hydrate_detached(&signed.root, &scope, &|| Ok(()))
                .unwrap()
                .canonical(),
            bytes
        );
    }
    let bytes: Vec<u8> = conn
        .query_row(
            "SELECT canonical_witness FROM consensus_protected_roster_witness WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        storage.business.roster.witness
            == Some(
                crate::fenced_mutation_roster_storage::GlobalChargeWitness::from_canonical_bytes(
                    &bytes
                )
                .unwrap()
            )
    );
    assert_eq!(
        storage.business.keys[signed.authority.key()].record,
        crate::sqlite::ops::get_raw_sync(&conn, signed.authority.key()).unwrap()
    );
    let count:i64 = conn.query_row("SELECT (SELECT COUNT(*) FROM consensus_protected_roster_rows)+(SELECT COUNT(*) FROM consensus_protected_roster_v2_admissions)",[],|row| row.get(0)).unwrap();
    assert_eq!(count as usize, storage.business.roster.rows.len());
}

#[test]
fn native_roster_generation_signed_v1_v2_reopen_and_compacted_base_match_sql() {
    for delete in [false, true] {
        for phase in [Phase::Established, Phase::Aborted] {
            let signed = crate::consensus::types::roster_v2_persistence_fixture();
            let mut storage = configured(&signed);
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("generation-oracle.sqlite");
            initialize_protected_roster_v2_recovery_fixture_with_members(
                &path,
                ProtectedRosterV2RecoveryFixtureState::Live,
                storage.business.members.clone(),
            )
            .unwrap();
            let (mut files, base) = Files::new(&storage);
            exact_rosters(&base.into_storage(&|| Ok(())).unwrap(), &storage);
            storage.begin_changes().unwrap();
            let admitted = apply(&mut storage, &[q1(&signed, 1)]);
            assert!(matches!(
                admitted.responses[0].result,
                Ok(SessionMutationOutcome::RosterAdmissionV2(
                    ConsensusRosterAdmissionOutcome::Admitted { .. }
                ))
            ));
            reopen(&mut files, &mut storage, 21);
            sql_rows(&storage, &path, &signed);
            let admission = roster::carrier::tests::signed_v1_command_with_mutation(
                &signed,
                if delete {
                    EstablishedMutation::delete()
                } else {
                    EstablishedMutation::no_op()
                },
            );
            let terminal = v1_fixture::terminal(&signed, &admission, 4, phase);
            let activation = entry(
                &signed,
                3,
                SessionConsensusRequestId::from_bytes([0xC8; 16]),
                SessionMutationIntent::ActivateFencedTransitionCapability {
                    schema_version: crate::fenced_transition::FENCED_TRANSITION_SCHEMA_V1,
                    scope_identity: signed.identity,
                    voter_set_digest: protected_roster_profile_voter_set_digest(
                        signed.identity,
                        &storage.business.members,
                    ),
                },
            );
            let entries = [
                q2(&signed, 2),
                activation,
                entry(
                    &signed,
                    4,
                    admission.request_id().unwrap(),
                    SessionMutationIntent::RosterAdmission(Box::new(admission)),
                ),
                entry(
                    &signed,
                    5,
                    terminal.request_id().unwrap(),
                    SessionMutationIntent::RosterTerminal(Box::new(terminal.clone())),
                ),
            ];
            for value in entries {
                let native = apply(&mut storage, std::slice::from_ref(&value));
                let sql = native_roster_apply_fixture(&path, signed.identity, vec![value.clone()])
                    .unwrap();
                assert_eq!(native.responses, sql.responses);
                assert_eq!(
                    postcard::to_allocvec(&native.notifications).unwrap(),
                    postcard::to_allocvec(&sql.notifications).unwrap()
                );
                reopen(&mut files, &mut storage, 20 + value.log_id.index);
                sql_rows(&storage, &path, &signed);
            }
            let (compacted, base) = Files::new(&storage);
            assert_eq!(&compacted.bytes()[..8], b"OPCNJB\x06\x00");
            exact_rosters(&base.into_storage(&|| Ok(())).unwrap(), &storage);
            let replay = entry(
                &signed,
                6,
                terminal.request_id().unwrap(),
                SessionMutationIntent::RosterTerminal(Box::new(terminal)),
            );
            let native = apply(&mut storage, std::slice::from_ref(&replay));
            let sql = native_roster_apply_fixture(&path, signed.identity, vec![replay]).unwrap();
            assert_eq!(native.responses, sql.responses);
            assert!(native.notifications.is_empty());
            assert!(matches!(
                native.responses[0].result,
                Ok(SessionMutationOutcome::RosterTerminal(
                    ConsensusRosterTerminalOutcome::Committed { replayed: true, .. }
                ))
            ));
            reopen(&mut files, &mut storage, 26);
            for index in 7..11 {
                if storage.business.roster.rows.is_empty() {
                    break;
                }
                let value = maintenance(&signed, index);
                let native = apply(&mut storage, std::slice::from_ref(&value));
                let sql = native_roster_apply_fixture(&path, signed.identity, vec![value]).unwrap();
                assert_eq!(native.responses, sql.responses);
                assert!(native.notifications.is_empty() && sql.notifications.is_empty());
                reopen(&mut files, &mut storage, 20 + index);
                sql_rows(&storage, &path, &signed);
            }
            assert!(
                storage.business.roster.rows.is_empty()
                    && storage.business.roster.partitions.is_empty()
            );
            assert_eq!(
                storage
                    .business
                    .roster
                    .witness
                    .unwrap()
                    .retired_terminal_sequence(),
                5
            );
        }
    }
}

#[test]
fn native_roster_generation_reservation_handoff_and_transient_retirement_preserve_closure() {
    for checkpoint_admission in [false, true] {
        let first = crate::consensus::types::roster_v2_aborted_persistence_fixture();
        let second = crate::consensus::types::roster_v2_aborted_persistence_fixture_for_history(
            [0x92; 16], 3,
        );
        let mut storage = configured(&first);
        let (mut files, _) = Files::new(&storage);
        storage.begin_changes().unwrap();
        apply(&mut storage, &[q1(&first, 1)]);
        if checkpoint_admission {
            reopen(&mut files, &mut storage, 21);
        }
        let results = apply(&mut storage, &[q2(&first, 2), q1(&second, 3)]);
        assert!(matches!(
            results.responses[0].result,
            Ok(SessionMutationOutcome::RosterTerminalV2(
                ConsensusRosterTerminalOutcome::Committed {
                    replayed: false,
                    ..
                }
            ))
        ));
        assert!(matches!(
            results.responses[1].result,
            Ok(SessionMutationOutcome::RosterAdmissionV2(
                ConsensusRosterAdmissionOutcome::Admitted { .. }
            ))
        ));
        let expected = second.admission.binding_key(3).unwrap();
        assert_eq!(
            storage
                .business
                .roster
                .index
                .reservation(first.authority.key()),
            Some(expected)
        );
        if checkpoint_admission {
            reopen(&mut files, &mut storage, 23);
            assert_eq!(
                storage
                    .business
                    .roster
                    .index
                    .reservation(first.authority.key()),
                Some(expected)
            );
        }
        apply(
            &mut storage,
            &[
                q2(&second, 4),
                maintenance(&first, 5),
                maintenance(&first, 6),
                maintenance(&first, 7),
            ],
        );
        assert!(
            storage.business.roster.rows.is_empty()
                && storage.business.roster.partitions.is_empty()
        );
        assert_eq!(
            storage
                .business
                .roster
                .witness
                .unwrap()
                .retired_terminal_sequence(),
            4
        );
        reopen(&mut files, &mut storage, 27);
        assert!(!storage.business.keys[first.authority.key()].reserved);
    }
}

#[test]
fn native_roster_generation_requires_independent_root_and_rejects_rehashed_carriers_and_witnesses()
{
    let signed = crate::consensus::types::roster_v2_persistence_fixture();
    let mut storage = configured(&signed);
    apply(&mut storage, &[q1(&signed, 1)]);
    let (files, catalog) = Files::new(&storage);
    let original = files.bytes();
    let alternate_key = p256::ecdsa::SigningKey::from_bytes((&[0xEF; 32]).into()).unwrap();
    let wrong_root = RosterAttestationTrustRootV1::new(
        signed.root.root_id(),
        alternate_key
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    for root in [None, Some(Arc::new(wrong_root.clone()))] {
        assert!(Catalog::open(
            &files.path,
            catalog.identity(),
            MAXIMUM,
            crate::consensus::native::generation::CatalogScope {
                identity: storage.business.identity,
                members: &storage.business.members,
                roster_root: root
            },
            CUT,
            &|| Ok(()),
        )
        .is_err());
    }
    let mut wire = Wire::<BaseHeader>::read(&original);
    wire.header.context.business.roster.as_mut().unwrap().root = Some(wrong_root.fingerprint());
    let bytes = wire.encode(base::MAGIC, Vec::new());
    let identity = rebound(&bytes, catalog.identity(), &wire.header.context);
    let path = files.path.with_extension("wrong-root");
    std::fs::write(&path, &bytes).unwrap();
    let error = Catalog::open(
        &path,
        identity,
        MAXIMUM,
        crate::consensus::native::generation::CatalogScope {
            identity: storage.business.identity,
            members: &storage.business.members,
            roster_root: Some(Arc::new(wrong_root)),
        },
        CUT,
        &|| Ok(()),
    )
    .err()
    .unwrap();
    assert!(
        error.to_string().contains("carrier authentication"),
        "{error}"
    );
    let binding = signed.admission.binding_key(1).unwrap();
    let range = catalog.rows.rosters.rows[&binding].range;
    let mut wire = Wire::<BaseHeader>::read(&original);
    let mut row =
        original[range.offset as usize..range.offset as usize + range.length as usize].to_vec();
    let last = row.len() - 1;
    row[last] ^= 1;
    wire.replace(range, &row);
    let bytes = wire.encode(base::MAGIC, Vec::new());
    let identity = rebound(&bytes, catalog.identity(), &wire.header.context);
    assert!(reject(&bytes, identity, &storage, CUT).contains("roster"));
    let mut wire = Wire::<BaseHeader>::read(&original);
    wire.header
        .context
        .business
        .roster
        .as_mut()
        .unwrap()
        .witness = Some(crate::fenced_mutation_roster_storage::GlobalChargeWitness::empty());
    let bytes = wire.encode(base::MAGIC, Vec::new());
    let identity = rebound(&bytes, catalog.identity(), &wire.header.context);
    assert!(reject(&bytes, identity, &storage, CUT).contains("witness"));
    for magic in [base::V3_MAGIC, base::LEGACY_MAGIC] {
        let mut bytes = original.clone();
        bytes[..8].copy_from_slice(magic);
        let identity = rebound(
            &bytes,
            catalog.identity(),
            &Version::capture(&storage).unwrap().context(),
        );
        assert!(reject(&bytes, identity, &storage, CUT).contains("native roster context requires"));
    }
    assert_eq!(files.bytes(), original);
    exact_rosters(&catalog.into_storage(&|| Ok(())).unwrap(), &storage);
}

fn business_extent(wire: &Wire<Header>) -> usize {
    let mut input = io::Cursor::new(&wire.body);
    let mut reader = Cursor {
        reader: &mut input,
        position: 0,
        maximum: wire.body.len() as u64,
        hash: Sha256::new(),
    };
    for (tag, count) in wire.header.changed.into_iter().enumerate() {
        for _ in 0..count {
            expect(&mut reader, &[tag as u8]).unwrap();
            match tag {
                0 | 2 => {
                    reader.before().unwrap();
                    Cursor::bytes(&mut reader, MAX_ITEM).unwrap();
                }
                1 => {
                    reader.before().unwrap();
                    reader.scalar::<56>().unwrap();
                    if reader.present().unwrap() {
                        Cursor::bytes(&mut reader, cold::MAX_BYTES).unwrap();
                    }
                }
                3 => {
                    Cursor::bytes(&mut reader, MAX_ITEM).unwrap();
                }
                4 => {
                    reader.scalar::<8>().unwrap();
                    reader.before().unwrap();
                    if reader.present().unwrap() {
                        Cursor::bytes(&mut reader, sql::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES)
                            .unwrap();
                    }
                }
                _ => unreachable!(),
            }
        }
    }
    reader.position as usize
}

fn rejected_delta(files: &Files, wire: &Wire<Header>, storage: &NativeStorage) -> String {
    let bytes = wire.encode(MAGIC, files.bytes());
    let mut identity = files.owner.current().identity();
    identity.checkpoint_epoch = wire.header.checkpoint_epoch;
    identity.operation_sequence = wire.header.operation_sequence;
    let identity = rebound(&bytes, identity, &wire.header.after);
    reject(&bytes, identity, storage, wire.header.cut_binding)
}

#[test]
fn native_roster_generation_omitted_business_release_and_retired_transient_reject_rebound_summaries(
) {
    let signed = crate::consensus::types::roster_v2_aborted_persistence_fixture();
    let mut storage = configured(&signed);
    apply(&mut storage, &[q1(&signed, 1)]);
    let (mut files, _) = Files::new(&storage);
    storage.begin_changes().unwrap();
    apply(&mut storage, &[q2(&signed, 2)]);
    let prepared = files.prepare(&mut storage, 22);
    let mut payload = Vec::new();
    prepared.write_payload(&mut payload, &|| Ok(())).unwrap();
    let mut wire = Wire::<Header>::read(&payload);
    assert_eq!(wire.header.changed[0], 1);
    assert_eq!(&wire.body[..2], &[0, 1]);
    let length = u32::from_le_bytes(wire.body[34..38].try_into().unwrap()) as usize;
    wire.body.drain(..38 + length);
    wire.header.changed[0] = 0;
    // Keep a fully self-consistent stale business table, while the original
    // signed Q2 after-image releases its reservation. The joined predicate
    // must reject even after every affected serialized hash is rebound.
    wire.header.after.business.content[0] = wire.header.before.business.content[0];
    assert!(rejected_delta(&files, &wire, &storage).contains("business summary"));
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
    exact_rosters(&catalog.into_storage(&|| Ok(())).unwrap(), &storage);

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
    assert!(
        storage.business.roster.rows.is_empty() && storage.business.roster.partitions.is_empty()
    );
    let prepared = files.prepare(&mut storage, 24);
    let mut payload = Vec::new();
    prepared.write_payload(&mut payload, &|| Ok(())).unwrap();
    let mut wire = Wire::<Header>::read(&payload);
    assert_eq!(wire.header.roster_changed, Some([1, 1]));
    let extent = business_extent(&wire);
    wire.body.truncate(extent);
    wire.body.extend_from_slice(END);
    wire.header.roster_changed = Some([0, 0]);
    assert!(rejected_delta(&files, &wire, &storage).contains("exact authenticated closure"));
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
    exact_rosters(&catalog.into_storage(&|| Ok(())).unwrap(), &storage);
}

#[test]
fn native_roster_generation_floor_advance_requires_the_original_retired_epoch() {
    use crate::consensus::native::resident::RowFingerprint;
    use crate::fenced_mutation_roster_storage::ProductionFloorKey;
    let first = crate::consensus::types::roster_v2_aborted_persistence_fixture();
    let second =
        crate::consensus::types::roster_v2_aborted_persistence_fixture_for_history([0x92; 16], 3);
    let mut storage = configured(&first);
    let (mut files, _) = Files::new(&storage);
    storage.begin_changes().unwrap();
    apply(
        &mut storage,
        &[
            q1(&first, 1),
            q2(&first, 2),
            q1(&second, 3),
            maintenance(&first, 4),
            maintenance(&first, 5),
        ],
    );
    let key = ProductionFloorKey::from_binding(second.admission.binding_key(3).unwrap()).unwrap();
    assert_eq!(
        storage.business.roster.partitions[&key]
            .floor
            .retired_through(),
        1
    );
    assert_eq!(storage.business.roster.rows.len(), 1);
    reopen(&mut files, &mut storage, 25);
    apply(&mut storage, &[maintenance(&first, 6)]);
    let prepared = files.prepare(&mut storage, 26);
    let mut payload = Vec::new();
    prepared.write_payload(&mut payload, &|| Ok(())).unwrap();
    let mut wire = Wire::<Header>::read(&payload);
    assert_eq!(wire.header.roster_changed, Some([0, 0]));
    let prior = &storage.business.roster.partitions[&key];
    let forged = roster::Partition {
        floor: prior.floor.advance_to(2).unwrap(),
        cursor: None,
    };
    // This floor is below the remaining epoch three row, so isolated full
    // snapshot admission accepts it. Only comparison with the complete
    // selected checkpoint can detect the invented retirement of epoch two.
    let mut isolated = storage.clone();
    isolated
        .business
        .roster
        .partitions
        .insert(key, SharedRow::new(forged.clone()).unwrap());
    isolated.business.admit_business().unwrap();
    isolated.log.admit(&isolated.business).unwrap();
    isolated.validate_image().unwrap();
    let mut frame = Vec::new();
    roster::frame::write_partition(&mut frame, key, &forged).unwrap();
    wire.body.truncate(business_extent(&wire));
    wire.body.push(5);
    write_before(
        &mut wire.body,
        Some(
            prior
                .row_fingerprint(5, &key.as_bytes().as_slice())
                .unwrap(),
        ),
    )
    .unwrap();
    wire.body.extend_from_slice(key.as_bytes());
    wire.body.extend_from_slice(&[0; 16]);
    wire.body.extend_from_slice(&[0, 1]);
    write_bytes(&mut wire.body, &frame, roster::frame::MAX_PARTITION).unwrap();
    wire.body.extend_from_slice(END);
    wire.header.roster_changed = Some([0, 1]);
    wire.header.after = Version::capture(&isolated).unwrap().context();
    assert!(rejected_delta(&files, &wire, &storage)
        .contains("floor lacks authenticated retirement history"));
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
    exact_rosters(&catalog.into_storage(&|| Ok(())).unwrap(), &storage);
}

#[test]
fn native_roster_generation_relocation_preserves_revision_and_skips_a_later_terminal() {
    for later_terminal in [false, true] {
        let signed = crate::consensus::types::roster_v2_aborted_persistence_fixture();
        let mut storage = configured(&signed);
        let (mut files, _) = Files::new(&storage);
        storage.begin_changes().unwrap();
        apply(&mut storage, &[q1(&signed, 1)]);
        let binding = signed.admission.binding_key(1).unwrap();
        let original = storage.business.roster.rows[&binding].clone();
        let prepared = files.prepare(&mut storage, 21);
        let (_, mut relocations) = prepared
            .append_with_relocations(&mut files.owner, &|| Ok(()))
            .unwrap();
        assert!(!original.is_cold() && !storage.business.roster.rows[&binding].is_cold());
        if later_terminal {
            apply(&mut storage, &[q2(&signed, 2)]);
        }
        let proof = Arc::clone(storage.business.require_business_proof().unwrap());
        let roster_proof = Arc::clone(storage.business.roster.certificate().unwrap());
        while !relocations.is_empty() {
            drop(relocations.publish_step(&mut storage).unwrap());
        }
        assert!(Arc::ptr_eq(
            &proof,
            storage.business.require_business_proof().unwrap()
        ));
        assert!(Arc::ptr_eq(
            &roster_proof,
            storage.business.roster.certificate().unwrap()
        ));
        let row = &storage.business.roster.rows[&binding];
        if later_terminal {
            assert!(
                row.facts().state == roster::State::Retained
                    && !row.is_cold()
                    && !row.ptr_eq(&original)
            );
        } else {
            assert!(
                row.facts().state == roster::State::Live && row.is_cold() && row.ptr_eq(&original)
            );
            let result = apply(&mut storage, &[q2(&signed, 2)]);
            assert!(matches!(
                result.responses[0].result,
                Ok(SessionMutationOutcome::RosterTerminalV2(
                    ConsensusRosterTerminalOutcome::Committed {
                        replayed: false,
                        ..
                    }
                ))
            ));
        }
        storage.validate_image().unwrap();
    }
}

#[test]
fn native_roster_generation_empty_activation_and_failed_conversion_expose_no_state() {
    use std::os::unix::fs::FileExt as _;
    for configured_root in [false, true] {
        let signed = crate::consensus::types::roster_v2_persistence_fixture();
        let mut storage = configured(&signed);
        if !configured_root {
            storage.business.roster_root = None;
            storage.business.admit_business().unwrap();
            storage.log.admit(&storage.business).unwrap();
        }
        let (files, catalog) = Files::new(&storage);
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
        assert!(restored.business.roster.rows.is_empty());
        assert_eq!(
            restored.business.roster.witness,
            Some(crate::fenced_mutation_roster_storage::GlobalChargeWitness::empty())
        );
        assert!(files.path.is_file());
    }
    let signed = crate::consensus::types::roster_v2_persistence_fixture();
    let mut storage = configured(&signed);
    apply(&mut storage, &[q1(&signed, 1)]);
    let (files, catalog) = Files::new(&storage);
    let source = Arc::clone(&catalog.source);
    let before = Arc::clone(storage.business.require_business_proof().unwrap());
    let calls = std::cell::Cell::new(0usize);
    let error = catalog
        .into_storage(&|| {
            let next = calls.get() + 1;
            calls.set(next);
            if next == 12 {
                Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "cancelled roster conversion",
                ))
            } else {
                Ok(())
            }
        })
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert!(!source.is_failed());
    let (_, catalog) = Catalog::open(
        &files.path,
        source.identity(),
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
    let binding = signed.admission.binding_key(1).unwrap();
    let offset = catalog.rows.rosters.rows[&binding].range.offset;
    let source = Arc::clone(&catalog.source);
    let file = OpenOptions::new().write(true).open(&files.path).unwrap();
    file.write_at(&[0], offset).unwrap();
    file.sync_all().unwrap();
    assert!(catalog.into_storage(&|| Ok(())).is_err());
    assert!(source.is_failed());
    assert!(Arc::ptr_eq(
        &before,
        storage.business.require_business_proof().unwrap()
    ));
    storage.validate_image().unwrap();
}

#[test]
fn roster_capacity_emergency_signed_v2_survives_q1_q2_and_cold_reopen() {
    use crate::fenced_mutation_roster::AdmissionClass;
    for phase in [Phase::Established, Phase::Aborted] {
        let signed = crate::consensus::types::roster_v2_persistence_fixture_for_class(
            phase,
            AdmissionClass::Emergency,
        );
        let command =
            ConsensusRosterAdmissionCommand::new_with_provenance_and_ingress_request_id_v2(
                signed.admission.clone(),
                signed.authority.clone(),
                signed.admission_ingress.request_id(),
                signed.admission_ingress.clone(),
                signed.admission_provenance.clone(),
            )
            .unwrap();
        let encoded = postcard::to_allocvec(&command).unwrap();
        let decoded: ConsensusRosterAdmissionCommand = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(
            decoded.admission().admission_class(),
            AdmissionClass::Emergency
        );
        assert_eq!(
            decoded.admission().body_commitment(),
            signed.admission.body_commitment()
        );
        assert!(
            signed
                .admission_provenance
                .verify_for(
                    &signed.root,
                    signed.identity,
                    &signed
                        .admission
                        .clone()
                        .with_admission_class(AdmissionClass::Ordinary),
                    &signed.authority,
                    &signed.admission_ingress,
                )
                .is_err(),
            "class substitution cannot reuse the signed admission authority"
        );
        let mut storage = configured(&signed);
        let (mut files, base) = Files::new(&storage);
        exact_rosters(&base.into_storage(&|| Ok(())).unwrap(), &storage);
        storage.begin_changes().unwrap();
        let admitted = apply(&mut storage, &[q1(&signed, 1)]);
        assert!(matches!(
            admitted.responses[0].result,
            Ok(SessionMutationOutcome::RosterAdmissionV2(
                ConsensusRosterAdmissionOutcome::Admitted { .. }
            ))
        ));
        reopen(&mut files, &mut storage, 21);
        let binding = signed.admission.binding_key(1).unwrap();
        let scope = roster::fixed_scope(storage.business.identity, &storage.business.members);
        let row = storage.business.roster.rows[&binding]
            .hydrate_detached(&signed.root, &scope, &|| Ok(()))
            .unwrap();
        let roster::carrier::Body::V2(body) = row.body() else {
            panic!("V2 carrier")
        };
        assert_eq!(
            body.record().admission().unwrap().admission_class(),
            AdmissionClass::Emergency
        );
        drop(row);
        let terminal = apply(&mut storage, &[q2(&signed, 2)]);
        assert!(matches!(
            terminal.responses[0].result,
            Ok(SessionMutationOutcome::RosterTerminalV2(
                ConsensusRosterTerminalOutcome::Committed {
                    replayed: false,
                    ..
                }
            ))
        ));
        assert!(!storage.business.keys[signed.authority.key()].reserved);
        assert_eq!(
            storage.business.keys[signed.authority.key()]
                .record
                .is_some(),
            phase == Phase::Established
        );
        reopen(&mut files, &mut storage, 22);
        let replay = apply(&mut storage, &[q2(&signed, 3)]);
        assert!(matches!(
            replay.responses[0].result,
            Ok(SessionMutationOutcome::RosterTerminalV2(
                ConsensusRosterTerminalOutcome::Committed { replayed: true, .. }
            ))
        ));
        assert!(replay.notifications.is_empty());
        let (compacted, base) = Files::new(&storage);
        exact_rosters(&base.into_storage(&|| Ok(())).unwrap(), &storage);
        assert!(!compacted.bytes().is_empty());
    }
}

#[test]
fn roster_capacity_policy_rejects_old_activation_certificates() {
    use sha2::{Digest, Sha256};
    let signed = crate::consensus::types::roster_v2_persistence_fixture();
    let mut storage = configured(&signed);
    let state = &mut storage.business;
    let scope_digest =
        crate::consensus::types::fenced_transition_voter_set_digest(state.identity, &state.members);
    let mut old = Sha256::new();
    old.update(b"openpacketcore/session-consensus/protected-roster-profile-voter-set/v1\0");
    old.update(scope_digest);
    old.update(crate::fenced_mutation_roster::Profile::v1().digest());
    let old_voters: [u8; 32] = old.finalize().into();
    state.frontiers.roster_v1_namespace = true;
    state.frontiers.v1_activation = Some(NativeV1Activation {
        identity: state.identity,
        voters: old_voters,
    });
    assert!(roster::validate_activation(state.identity, &state.members, &state.frontiers).is_err());
    state.frontiers.v1_activation.as_mut().unwrap().voters =
        protected_roster_profile_voter_set_digest(state.identity, &state.members);
    assert!(roster::validate_activation(state.identity, &state.members, &state.frontiers).is_ok());
    let old_v2_profile = [
        0x38, 0x5e, 0xc6, 0x6c, 0x09, 0x35, 0x6f, 0x9a, 0x0f, 0x8f, 0x85, 0x60, 0xc2, 0x9e, 0x97,
        0x73, 0x61, 0xf5, 0x63, 0x79, 0x5f, 0x41, 0xbb, 0x57, 0xdd, 0x04, 0x9c, 0x55, 0x32, 0x61,
        0x7b, 0x89,
    ];
    let mut old = Sha256::new();
    old.update(b"openpacketcore/session-consensus/protected-roster-profile-voter-set/v2\0");
    old.update(scope_digest);
    old.update(old_v2_profile);
    let old_v2_voters: [u8; 32] = old.finalize().into();
    let fresh = state.frontiers.roster_v2_activation.clone().unwrap();
    state
        .frontiers
        .roster_v2_activation
        .as_mut()
        .unwrap()
        .voters = old_v2_voters;
    assert!(roster::validate_activation(state.identity, &state.members, &state.frontiers).is_err());
    state.frontiers.roster_v2_activation = Some(fresh.clone());
    state
        .frontiers
        .roster_v2_activation
        .as_mut()
        .unwrap()
        .profile = old_v2_profile;
    assert!(roster::validate_activation(state.identity, &state.members, &state.frontiers).is_err());
    state.frontiers.roster_v2_activation = Some(fresh);
    assert!(roster::validate_activation(state.identity, &state.members, &state.frontiers).is_ok());
}

#[test]
fn roster_capacity_emergency_signed_v1_survives_q1_q2_and_cold_reopen() {
    use crate::fenced_mutation_roster::AdmissionClass;
    let signed = crate::consensus::types::roster_v2_persistence_fixture_for_class(
        Phase::Established,
        AdmissionClass::Emergency,
    );
    let mut storage = configured(&signed);
    apply(&mut storage, &[q1(&signed, 1), q2(&signed, 2)]);
    let activation = entry(
        &signed,
        3,
        SessionConsensusRequestId::from_bytes([0xC8; 16]),
        SessionMutationIntent::ActivateFencedTransitionCapability {
            schema_version: crate::fenced_transition::FENCED_TRANSITION_SCHEMA_V1,
            scope_identity: signed.identity,
            voter_set_digest: protected_roster_profile_voter_set_digest(
                signed.identity,
                &storage.business.members,
            ),
        },
    );
    apply(&mut storage, &[activation]);
    let admission = roster::carrier::tests::signed_v1_command_with_mutation(
        &signed,
        EstablishedMutation::no_op(),
    );
    let encoded = postcard::to_allocvec(&admission).unwrap();
    let decoded: ConsensusRosterAdmissionCommand = postcard::from_bytes(&encoded).unwrap();
    assert_eq!(
        decoded.admission().admission_class(),
        AdmissionClass::Emergency
    );
    assert_eq!(
        decoded.admission().body_commitment(),
        admission.admission().body_commitment()
    );
    let terminal = v1_fixture::terminal(&signed, &admission, 4, Phase::Established);
    let binding = admission.admission().binding_key(4).unwrap();
    let (mut files, base) = Files::new(&storage);
    exact_rosters(&base.into_storage(&|| Ok(())).unwrap(), &storage);
    storage.begin_changes().unwrap();
    let admitted = apply(
        &mut storage,
        &[entry(
            &signed,
            4,
            admission.request_id().unwrap(),
            SessionMutationIntent::RosterAdmission(Box::new(admission)),
        )],
    );
    assert!(matches!(
        admitted.responses[0].result,
        Ok(SessionMutationOutcome::RosterAdmission(
            ConsensusRosterAdmissionOutcome::Admitted { .. }
        ))
    ));
    reopen(&mut files, &mut storage, 24);
    let scope = roster::fixed_scope(storage.business.identity, &storage.business.members);
    let row = storage.business.roster.rows[&binding]
        .hydrate_detached(&signed.root, &scope, &|| Ok(()))
        .unwrap();
    let roster::carrier::Body::V1(body) = row.body() else {
        panic!("V1 carrier")
    };
    assert_eq!(
        body.record().admission().unwrap().admission_class(),
        AdmissionClass::Emergency
    );
    drop(row);
    let completed = apply(
        &mut storage,
        &[entry(
            &signed,
            5,
            terminal.request_id().unwrap(),
            SessionMutationIntent::RosterTerminal(Box::new(terminal)),
        )],
    );
    assert!(matches!(
        completed.responses[0].result,
        Ok(SessionMutationOutcome::RosterTerminal(
            ConsensusRosterTerminalOutcome::Committed {
                replayed: false,
                ..
            }
        ))
    ));
    assert!(!storage.business.keys[signed.authority.key()].reserved);
    reopen(&mut files, &mut storage, 25);
    let (compacted, base) = Files::new(&storage);
    exact_rosters(&base.into_storage(&|| Ok(())).unwrap(), &storage);
    assert!(!compacted.bytes().is_empty());
}

#[derive(Default)]
struct CapacityHistoryTimings {
    phases: std::collections::BTreeMap<&'static str, (std::time::Duration, u64)>,
}

impl CapacityHistoryTimings {
    fn record(&mut self, phase: &'static str, elapsed: std::time::Duration) {
        let total = self.phases.entry(phase).or_default();
        total.0 += elapsed;
        total.1 += 1;
        if phase.starts_with("final_") {
            eprintln!("roster history boundary: phase={phase}, elapsed={elapsed:?}");
        }
    }

    fn measure<T>(&mut self, phase: &'static str, operation: impl FnOnce() -> T) -> T {
        let started = std::time::Instant::now();
        let result = operation();
        self.record(phase, started.elapsed());
        result
    }

    fn report(&self, completed: u64) {
        for (phase, (elapsed, calls)) in &self.phases {
            eprintln!(
                "roster history timing: completed={completed}, phase={phase}, calls={calls}, elapsed={elapsed:?}"
            );
        }
    }
}

// Apply the same append/commit and certified business publication as `apply`,
// but validate the complete image at the boundaries below. The generic test
// helper scans all retained history after every entry, which would turn this
// sequential history proof into quadratic work unrelated to admission.
fn capacity_history_apply(
    storage: &mut NativeStorage,
    value: Entry<SessionRaftTypeConfig>,
    timings: &mut CapacityHistoryTimings,
    phases: [&'static str; 4],
) -> NativeApplied {
    let [encode, append, commit, apply] = phases;
    let encoded = timings.measure(encode, || serde_json::to_vec(&value).unwrap());
    timings
        .measure(append, || {
            storage.log.project(
                &Operation::Append(vec![encoded.into()]),
                &storage.business,
                None,
            )
        })
        .unwrap();
    timings
        .measure(commit, || {
            storage.log.project(
                &Operation::Committed(Some(value.log_id)),
                &storage.business,
                None,
            )
        })
        .unwrap();
    timings
        .measure(apply, || storage.business.apply(&[value]))
        .unwrap()
}

fn capacity_history_fixture(ordinal: u64) -> RosterV2PersistenceFixture {
    crate::consensus::types::roster_v2_aborted_single_member_persistence_fixture_for_history(
        u128::from(ordinal).to_be_bytes(),
        ordinal.checked_mul(2).unwrap() - 1,
    )
}

fn capacity_history_complete(
    storage: &mut NativeStorage,
    ordinal: u64,
    timings: &mut CapacityHistoryTimings,
) {
    let signed = timings.measure("fixture", || capacity_history_fixture(ordinal));
    let first_index = ordinal.checked_mul(2).unwrap() - 1;
    let admission = timings.measure("q1_build", || q1(&signed, first_index));
    let admitted = capacity_history_apply(
        storage,
        admission,
        timings,
        ["q1_encode", "q1_append", "q1_commit", "q1_apply"],
    );
    let assertions = std::time::Instant::now();
    assert!(
        matches!(
            admitted.responses[0].result,
            Ok(SessionMutationOutcome::RosterAdmissionV2(
                ConsensusRosterAdmissionOutcome::Admitted { .. }
            ))
        ),
        "ordinary admission must progress with {ordinal} retained rosters"
    );
    timings.record("entry_assertions", assertions.elapsed());
    let terminal = timings.measure("q2_build", || q2(&signed, first_index + 1));
    let completed = capacity_history_apply(
        storage,
        terminal,
        timings,
        ["q2_encode", "q2_append", "q2_commit", "q2_apply"],
    );
    let assertions = std::time::Instant::now();
    assert!(matches!(
        completed.responses[0].result,
        Ok(SessionMutationOutcome::RosterTerminalV2(
            ConsensusRosterTerminalOutcome::Committed {
                replayed: false,
                ..
            }
        ))
    ));
    assert!(completed.notifications.is_empty());
    assert!(!storage.business.keys[signed.authority.key()].reserved);
    assert!(storage.business.keys[signed.authority.key()]
        .record
        .is_none());
    let occupancy = storage
        .business
        .roster
        .witness
        .unwrap()
        .diagnostic_occupancy()
        .unwrap();
    assert_eq!(occupancy.live_reservations, 0);
    assert_eq!(occupancy.retained_reservations, ordinal);
    assert_eq!(occupancy.tombstone_reservations, 0);
    assert_eq!(
        storage.business.roster.rows.len(),
        usize::try_from(ordinal).unwrap()
    );
    assert_eq!(
        storage.business.frontiers.logical_time,
        Some(signed.authority.acquired_at().add_seconds(1).unwrap())
    );
    timings.record("entry_assertions", assertions.elapsed());
}

fn capacity_history_progress_and_reopen(completed: u64) {
    let started = std::time::Instant::now();
    let mut timings = CapacityHistoryTimings::default();
    let signed = timings.measure("setup_fixture", || capacity_history_fixture(1));
    let mut storage = timings.measure("setup_storage", || configured(&signed));
    // Persist completed carriers with the production append/readback and
    // relocation path. Retaining every historical carrier in memory instead
    // would test exhaustion of the unchanged 128 MiB verifier, not the roster
    // admission contract. Relocation preserves every logical row and revision.
    let maximum = crate::consensus::snapshot::SNAPSHOT_DATABASE_MAX_BYTES;
    let (mut files, catalog) = timings.measure("setup_persistence", || {
        Files::with_maximum(&storage, maximum)
    });
    drop(catalog);
    storage.begin_changes().unwrap();
    for ordinal in 1..=completed {
        capacity_history_complete(&mut storage, ordinal, &mut timings);
        if ordinal == 1 || ordinal % 1024 == 0 || ordinal == completed {
            let witness = storage.business.roster.witness;
            let version = Version::capture(&storage).unwrap();
            let prepared = timings.measure("batch_prepare", || {
                files.prepare(&mut storage, 18 + 2 * ordinal)
            });
            let (_, mut relocations) = timings
                .measure("batch_append", || {
                    prepared.append_with_relocations(&mut files.owner, &|| Ok(()))
                })
                .unwrap();
            files.version = prepared.target_version();
            files.cut = prepared.header.cut_binding;
            drop(prepared);
            timings.measure("batch_relocate", || {
                while !relocations.is_empty() {
                    drop(relocations.publish_step(&mut storage).unwrap());
                }
            });
            let assertions = std::time::Instant::now();
            version.require_current(&storage).unwrap();
            assert!(storage.business.roster.witness == witness);
            assert_eq!(storage.business.roster.rows.len(), ordinal as usize);
            assert!(storage
                .business
                .roster
                .rows
                .values()
                .all(|row| row.is_cold()));
            timings.record("batch_assertions", assertions.elapsed());
        }
        if ordinal % 4096 == 0 {
            eprintln!(
                "roster completed history: {ordinal}/{completed}, elapsed={:?}",
                started.elapsed()
            );
            timings.report(ordinal);
        }
    }
    timings
        .measure("final_validate_populated", || storage.validate_image())
        .unwrap();
    let before = timings.measure("final_context_before", || {
        Version::capture(&storage)
            .unwrap()
            .context_digest()
            .unwrap()
    });
    let witness = storage.business.roster.witness.unwrap();
    assert_eq!(witness.retired_terminal_sequence(), 0);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("completed-rosters.opc");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    // This is the production physical snapshot bound, not a test count quota.
    let prepared = timings
        .measure("final_prepare_base", || {
            PreparedBase::prepare(
                &storage,
                crate::consensus::native::generation::BaseParameters {
                    binding: ROOT,
                    file_epoch: 4,
                    checkpoint_epoch: 11,
                    operation_sequence: 18,
                    cut_binding: CUT,
                    block_bytes: BLOCK,
                    maximum,
                },
                &|| Ok(()),
            )
        })
        .unwrap();
    let identity = timings
        .measure("final_write_base", || {
            prepared.write_to(&mut file, &|| Ok(()))
        })
        .unwrap();
    timings
        .measure("final_sync_base", || file.sync_all())
        .unwrap();
    let dropping = std::time::Instant::now();
    drop(file);
    drop(prepared);
    let members = storage.business.members.clone();
    drop(storage);
    drop(files);
    timings.record("final_drop_hot_storage", dropping.elapsed());
    timings
        .measure("final_preflight", || {
            preflight_format(&path, identity, maximum, CUT, &|| Ok(()))
        })
        .unwrap();
    let (_, catalog) = timings
        .measure("final_catalog_open", || {
            Catalog::open(
                &path,
                identity,
                maximum,
                crate::consensus::native::generation::CatalogScope {
                    identity: signed.identity,
                    members: &members,
                    roster_root: Some(Arc::new(signed.root.clone())),
                },
                CUT,
                &|| Ok(()),
            )
        })
        .unwrap();
    let mut restored = timings
        .measure("final_into_storage", || catalog.into_storage(&|| Ok(())))
        .unwrap();
    let assertions = std::time::Instant::now();
    assert_eq!(
        Version::capture(&restored)
            .unwrap()
            .context_digest()
            .unwrap(),
        before
    );
    assert!(restored.business.roster.witness == Some(witness));
    assert_eq!(
        restored.business.roster.rows.len(),
        usize::try_from(completed).unwrap()
    );
    assert!(restored
        .business
        .roster
        .rows
        .values()
        .all(|row| row.is_cold()));
    timings.record("final_reopen_assertions", assertions.elapsed());
    timings
        .measure("final_validate_reopened", || restored.validate_image())
        .unwrap();
    // Reopen is followed by another authenticated admission and completion,
    // still without advancing the clock, retiring a row, or changing a lease.
    capacity_history_complete(&mut restored, completed + 1, &mut timings);
    timings
        .measure("final_validate_continued", || restored.validate_image())
        .unwrap();
    timings.report(completed + 1);
    eprintln!(
        "roster completed history and cold reopen: {completed}, elapsed={:?}",
        started.elapsed()
    );
}

#[test]
fn native_roster_completed_history_storage_smoke() {
    capacity_history_progress_and_reopen(3);
}

#[test]
fn native_roster_completed_history_exceeds_old_capacity_and_cold_reopens() {
    // Literal historical boundary: never lower it using an environment knob.
    capacity_history_progress_and_reopen(131_073);
}
