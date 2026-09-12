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
        .add_seconds(1 + 24 * 60 * 60)
        .unwrap();
    value
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
            assert_eq!(&compacted.bytes()[..8], b"OPCNJ004");
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
