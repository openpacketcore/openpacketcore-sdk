use super::*;
use crate::consensus::types::{
    protected_roster_profile_v2_voter_set_digest, roster_v2_fresh_wal_persistence_fixture,
    ConsensusRosterAdmissionCommand, ConsensusRosterAdmissionOutcome,
    ConsensusRosterTerminalOutcome, RosterV2PersistenceFixture,
};
use crate::fenced_mutation_roster::{Phase, Profile, RosterAttestationTrustRootV1};
use crate::sqlite::consensus::wal::native::Opening;
use std::fs;

pub(super) mod export;

fn entry(
    signed: &RosterV2PersistenceFixture,
    index: u64,
    id: SessionConsensusRequestId,
    intent: SessionMutationIntent,
) -> Entry<SessionRaftTypeConfig> {
    Entry {
        log_id: log_id(index),
        payload: EntryPayload::Normal(SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: signed.identity,
            request_id: id,
            logical_time: signed.authority.acquired_at().add_seconds(1).unwrap(),
            intent: SessionMutationIntent::Authorized {
                origin: node_id(),
                authority_identity: signed.identity,
                mutation: Box::new(intent),
            },
        }),
    }
}

fn ordinary(
    signed: &RosterV2PersistenceFixture,
    index: u64,
    intent: SessionMutationIntent,
) -> Entry<SessionRaftTypeConfig> {
    entry(
        signed,
        index,
        SessionConsensusRequestId::from_bytes((0xD100 + u128::from(index)).to_be_bytes()),
        intent,
    )
}

fn admission(signed: &RosterV2PersistenceFixture) -> Entry<SessionRaftTypeConfig> {
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
        3,
        command.request_id().unwrap(),
        SessionMutationIntent::RosterAdmissionV2(Box::new(command)),
    )
}

fn terminal(signed: &RosterV2PersistenceFixture, index: u64) -> Entry<SessionRaftTypeConfig> {
    entry(
        signed,
        index,
        signed.terminal_command.request_id().unwrap(),
        SessionMutationIntent::RosterTerminalV2(Box::new(signed.terminal_command.clone())),
    )
}

fn initialize(backend: &SqliteSessionBackend, signed: &RosterV2PersistenceFixture) {
    let conn = backend.conn.blocking_lock();
    initialize_schema_with_storage_anchor_and_pending_and_bindings(
        &conn,
        None,
        signed.identity,
        &fixed_members(),
        &test_member_bindings(&fixed_members()),
        None,
        ConsensusAuthorityProfile::FixedImmutable,
        FIXED_TEST_PLACEMENT_POLICY,
        Some(&signed.root),
    )
    .unwrap();
}

fn commit(wal: &Wal, entries: &[Entry<SessionRaftTypeConfig>]) {
    wal.submit(append(entries)).unwrap().wait().unwrap();
    wal.submit(Operation::Committed(
        entries.last().map(|entry| entry.log_id),
    ))
    .unwrap()
    .wait()
    .unwrap();
}

fn sql_apply(
    backend: &SqliteSessionBackend,
    signed: &RosterV2PersistenceFixture,
    entries: &[Entry<SessionRaftTypeConfig>],
) -> AppliedBatch {
    let conn = backend.conn.blocking_lock();
    append_logs_with_authority_sync(
        &conn,
        signed.identity,
        ConsensusAuthorityProfile::FixedImmutable,
        &fixed_members(),
        &test_member_bindings(&fixed_members()),
        FIXED_TEST_PLACEMENT_POLICY,
        entries,
    )
    .unwrap();
    save_committed_with_authority_sync(
        &conn,
        signed.identity,
        ConsensusAuthorityProfile::FixedImmutable,
        &fixed_members(),
        &test_member_bindings(&fixed_members()),
        FIXED_TEST_PLACEMENT_POLICY,
        entries.last().map(|entry| entry.log_id),
    )
    .unwrap();
    apply_entries_with_authority_sync(
        &conn,
        signed.identity,
        &backend.caps,
        ConsensusAuthorityProfile::FixedImmutable,
        &fixed_members(),
        &test_member_bindings(&fixed_members()),
        FIXED_TEST_PLACEMENT_POLICY,
        entries.to_vec(),
    )
    .unwrap()
}

fn parity(
    wal: &Wal,
    backend: &SqliteSessionBackend,
    signed: &RosterV2PersistenceFixture,
    entries: &[Entry<SessionRaftTypeConfig>],
) -> AppliedBatch {
    commit(wal, entries);
    let expected = sql_apply(backend, signed, entries);
    let actual = wal.native_apply_committed(entries).unwrap();
    assert_eq!(
        encode_json(&actual.responses).unwrap(),
        encode_json(&expected.responses).unwrap()
    );
    assert_eq!(
        encode_json(&actual.notifications).unwrap(),
        encode_json(&expected.notifications).unwrap()
    );
    actual
}

fn wrong_root(signed: &RosterV2PersistenceFixture) -> Arc<RosterAttestationTrustRootV1> {
    let key = p256::ecdsa::SigningKey::from_slice(&[0xF2; 32]).unwrap();
    let public = key.verifying_key().to_sec1_point(true);
    Arc::new(
        RosterAttestationTrustRootV1::new(
            signed.root.root_id(),
            public.as_bytes().try_into().unwrap(),
        )
        .unwrap(),
    )
}

fn files(directory: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn collect(root: &Path, directory: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(root, &path, result);
            } else {
                result.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    collect(directory, directory, &mut result);
    result
}

#[test]
fn native_roster_configured_root_signed_wal_replay_and_closed_audit_match_sql() {
    for phase in [Phase::Established, Phase::Aborted] {
        for select_q1 in [false, true] {
            let signed = roster_v2_fresh_wal_persistence_fixture(phase);
            let root = Arc::new(signed.root.clone());
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("wal");
            let backend =
                SqliteSessionBackend::open(directory.path().join("oracle.sqlite")).unwrap();
            initialize(&backend, &signed);
            let wal = Wal::create_native_with_root(
                &path,
                &backend.conn.blocking_lock(),
                signed.identity,
                [0xC1; 32],
                Some(Arc::clone(&root)),
                Limits::default(),
                IoControl::default(),
            )
            .unwrap();
            assert!(wal
                .with_native_read(|state| Ok(Arc::ptr_eq(state.roster_root().unwrap(), &root)))
                .unwrap());
            let mut lease = ordinary(
                &signed,
                1,
                SessionMutationIntent::AcquireLease {
                    key: signed.authority.key().clone(),
                    owner: signed.authority.owner().clone(),
                    ttl: Duration::from_secs(60),
                },
            );
            let EntryPayload::Normal(command) = &mut lease.payload else {
                unreachable!()
            };
            command.logical_time = signed.authority.acquired_at();
            let profile = Profile::v2();
            let activation = ordinary(
                &signed,
                2,
                SessionMutationIntent::ActivateProtectedRosterProfileV2 {
                    schema_version: profile.schema(),
                    consumer_revision: profile.consumer_revision(),
                    scope_identity: signed.identity,
                    voter_set_digest: protected_roster_profile_v2_voter_set_digest(
                        signed.identity,
                        &fixed_members(),
                    ),
                    profile_digest: profile.digest(),
                },
            );
            let setup = parity(&wal, &backend, &signed, &[formation(), lease, activation]);
            for members in [
                fixed_members(),
                BTreeSet::new(),
                BTreeSet::from([node_id()]),
            ] {
                let expected = protected_roster_profile_v2_activation_matches_scope_sync(
                    &backend.conn.blocking_lock(),
                    signed.identity,
                    signed.identity,
                    &members,
                )
                .unwrap();
                assert_eq!(
                    wal.native_public_scalar_read(|state| Ok(
                        state.protected_roster_v2_activation_matches(signed.identity, &members)
                    ))
                    .unwrap(),
                    expected,
                );
            }
            assert!(!wal
                .native_public_scalar_read(|state| Ok(
                    state.protected_roster_activation_matches(signed.identity, &fixed_members())
                ))
                .unwrap());
            assert!(
                matches!(&setup.responses[1].result,Ok(SessionMutationOutcome::Lease(guard))
                if guard.key() == signed.authority.key() && guard.owner() == signed.authority.owner()
                    && guard.fence() == signed.authority.fence() && guard.credential_id() == signed.authority.credential_id()
                    && guard.acquired_at() == signed.authority.acquired_at() && guard.expires_at() == signed.authority.expires_at())
            );
            let q1 = parity(&wal, &backend, &signed, &[admission(&signed)]);
            assert!(matches!(
                &q1.responses[0].result,
                Ok(SessionMutationOutcome::RosterAdmissionV2(
                    ConsensusRosterAdmissionOutcome::Admitted { .. }
                ))
            ));
            if select_q1 {
                wal.checkpoint().unwrap();
            }
            let q2 = terminal(&signed, 4);
            commit(&wal, std::slice::from_ref(&q2));
            let expected = sql_apply(&backend, &signed, std::slice::from_ref(&q2));
            assert!(matches!(
                &expected.responses[0].result,
                Ok(SessionMutationOutcome::RosterTerminalV2(
                    ConsensusRosterTerminalOutcome::Committed {
                        replayed: false,
                        ..
                    }
                ))
            ));
            // Q2 is acknowledged in the WAL but has not run in this process.
            assert_eq!(
                wal.with_native_read(|state| Ok(state.applied())).unwrap(),
                Some(log_id(3))
            );
            wal.shutdown().unwrap();
            let before = files(&path);
            let expected_record =
                ops::get_raw_sync(&backend.conn.blocking_lock(), signed.authority.key()).unwrap();
            wal.native_audit_closed(
                |snapshots, origin| {
                    assert!(snapshots.is_empty());
                    assert!(origin.is_none());
                    Ok(())
                },
                |_| None,
                |_| Ok(()),
                |state| {
                    assert!(Arc::ptr_eq(state.roster_root().unwrap(), &root));
                    assert_eq!(state.applied(), Some(log_id(4)));
                    assert_eq!(state.get(signed.authority.key()), expected_record);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(files(&path), before);
            for configured in [
                None,
                Some(wrong_root(&signed)),
                Some(Arc::new(
                    RosterAttestationTrustRootV1::new(
                        [0xF3; 32],
                        signed.root.compressed_public_key(),
                    )
                    .unwrap(),
                )),
            ] {
                let error = Opening::new(
                    &path,
                    wal.binding(),
                    configured,
                    Limits::default(),
                    IoControl::default(),
                )
                .err()
                .unwrap();
                assert_eq!(
                    error.to_string(),
                    "native configured roster trust root differs from cold basis"
                );
                assert_eq!(files(&path), before);
            }
            let reopened = Opening::new(
                &path,
                wal.binding(),
                Some(Arc::clone(&root)),
                Limits::default(),
                IoControl::default(),
            )
            .unwrap()
            .finish(|| Ok(()))
            .unwrap();
            assert_eq!(
                reopened
                    .with_native_read(|state| Ok(state.applied()))
                    .unwrap(),
                Some(log_id(4))
            );
            assert_eq!(
                reopened
                    .with_native_read(|state| Ok(state.get(signed.authority.key())))
                    .unwrap(),
                expected_record
            );
            let replay = parity(&reopened, &backend, &signed, &[terminal(&signed, 5)]);
            assert!(matches!(
                &replay.responses[0].result,
                Ok(SessionMutationOutcome::RosterTerminalV2(
                    ConsensusRosterTerminalOutcome::Committed { replayed: true, .. }
                ))
            ));
            reopened.checkpoint().unwrap();
            reopened.shutdown().unwrap();
            reopened
                .native_audit_closed(
                    |snapshots, origin| {
                        assert!(snapshots.is_empty());
                        assert!(origin.is_none());
                        Ok(())
                    },
                    |_| None,
                    |_| Ok(()),
                    |state| {
                        assert_eq!(state.applied(), Some(log_id(5)));
                        assert_eq!(state.get(signed.authority.key()), expected_record);
                        Ok(())
                    },
                )
                .unwrap();
            assert_eq!(reopened.native_sql_fallback_count().unwrap(), 0);
        }
    }
}

#[test]
fn native_roster_creation_requires_the_independently_configured_root_before_files() {
    let signed = roster_v2_fresh_wal_persistence_fixture(Phase::Established);
    let directory = tempfile::tempdir().unwrap();
    let backend = SqliteSessionBackend::open(directory.path().join("source.sqlite")).unwrap();
    initialize(&backend, &signed);
    for (index, configured) in [None, Some(wrong_root(&signed))].into_iter().enumerate() {
        let path = directory.path().join(format!("rejected-{index}"));
        let error = Wal::create_native_with_root(
            &path,
            &backend.conn.blocking_lock(),
            signed.identity,
            [0xC2; 32],
            configured,
            Limits::default(),
            IoControl::default(),
        )
        .err()
        .unwrap();
        assert_eq!(
            error.to_string(),
            "native configured roster trust root differs from cold basis"
        );
        assert!(!path.exists());
    }
    let conn = backend.conn.blocking_lock();
    assert!(
        read_roster_attestation_trust_root_sync(&conn)
            .unwrap()
            .as_ref()
            == Some(&signed.root)
    );
    assert!(read_applied_sync(&conn, signed.identity).unwrap().is_none());
    assert!(last_log_sync(&conn, signed.identity).unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_roster_core_configuration_reaches_fresh_and_reopened_owner() {
    let signed = roster_v2_fresh_wal_persistence_fixture(Phase::Established);
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("backend.sqlite");
    let snapshots = directory.path().join("snapshots");
    let fixture = Arc::new(
        crate::sqlite::consensus::wal::integration::PrivateWalTest::new_native(
            directory.path().join("wal"),
            [0xC3; 32],
        ),
    );
    for _ in 0..2 {
        let mut backend = SqliteSessionBackend::open(&database).unwrap();
        let mut core = SqliteConsensusCore::initialize_with_roster_attestation_root(
            &backend,
            snapshots.clone(),
            signed.identity,
            fixed_members(),
            test_member_bindings(&fixed_members()),
            ConsensusAuthorityProfile::FixedImmutable,
            FIXED_TEST_PLACEMENT_POLICY,
            Some(signed.root.clone()),
        )
        .await
        .unwrap();
        fixture.attach(&mut core).await.unwrap();
        backend.private_wal_test = Some(Arc::clone(&fixture));
        let root = core.configured_roster_root.as_ref().unwrap();
        assert!(root.as_ref() == &signed.root);
        let wal = Arc::clone(core.private_wal.as_ref().unwrap());
        assert!(wal
            .with_native_read(|state| Ok(Arc::ptr_eq(state.roster_root().unwrap(), root)))
            .unwrap());
        assert!(wal
            .with_native_read(|state| Ok(state.applied()))
            .unwrap()
            .is_none());
        assert!(!backend
            .consensus_protected_roster_profile_v2_activation_matches_scope(
                signed.identity,
                signed.identity,
                fixed_members(),
            )
            .await
            .unwrap());
        tokio::task::spawn_blocking(move || wal.shutdown())
            .await
            .unwrap()
            .unwrap();
        assert!(backend
            .consensus_protected_roster_profile_v2_activation_matches_scope(
                signed.identity,
                signed.identity,
                fixed_members(),
            )
            .await
            .is_err());
    }
}
