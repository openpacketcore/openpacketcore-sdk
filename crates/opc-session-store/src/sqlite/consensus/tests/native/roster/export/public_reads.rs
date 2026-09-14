use super::*;
use crate::consumer::SessionConsumerRosterCurrentPublicationAuthorityCapsule;
use crate::fenced_mutation_roster_executor::{
    AuthorityLeaseMetadata, RecoveryLookup, RecoveryRequestInput,
};
use crate::sqlite::consensus::roster_reads;

macro_rules! fingerprint {
    ($name:ident, $result:ident) => {
        fn $name(result: Result<$result, StoreError>) -> Result<Vec<Vec<u8>>, StoreError> {
            Ok(match result? {
                $result::Missing => vec![vec![0]],
                $result::Admitted(value) => {
                    let (handle, id, slot) = value.registration.consensus_parts();
                    vec![
                        vec![1],
                        value.admission.to_canonical_bytes().unwrap(),
                        value.admission_provenance.canonical_bytes().unwrap(),
                        handle.to_vec(),
                        id.to_bytes().to_vec(),
                        slot.as_bytes().to_vec(),
                    ]
                }
                $result::Terminalized(value) => {
                    let (handle, id, slot) = value.registration.consensus_parts();
                    assert_eq!(
                        value
                            .committed
                            .to_canonical_bytes(&value.admission)
                            .unwrap(),
                        value.committed_canonical
                    );
                    vec![
                        vec![2],
                        value.admission.to_canonical_bytes().unwrap(),
                        value.admission_provenance.canonical_bytes().unwrap(),
                        handle.to_vec(),
                        id.to_bytes().to_vec(),
                        slot.as_bytes().to_vec(),
                        value.committed_canonical,
                    ]
                }
                $result::Compacted {
                    history_epoch,
                    tombstone,
                } => vec![
                    vec![3],
                    history_epoch.to_be_bytes().to_vec(),
                    tombstone.to_canonical_bytes().unwrap(),
                ],
            })
        }
    };
}
fingerprint!(v1_bytes, ProtectedRosterReadResult);
fingerprint!(v2_bytes, ProtectedRosterV2ReadResult);

fn native<T>(
    wal: &Wal,
    signed: &RosterV2PersistenceFixture,
    read: impl FnOnce(
        &dyn crate::sqlite::consensus::roster_engine::RosterCommandStore,
        Timestamp,
    ) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    wal.native_public_read(&|| Ok(()), |state, check| {
        state.with_roster_read(
            signed.identity,
            signed.authority.acquired_at().add_seconds(1).unwrap(),
            check,
            read,
        )
    })
    .unwrap()
}

fn publication(
    admission: &Admission,
    registration: ([u8; 32], crate::fenced_mutation_roster::RequestId, [u8; 32]),
    authority: &AuthorityBinding,
    terminal: &TerminalRecord,
    receipt: [u8; 32],
) -> SessionConsumerRosterCurrentPublicationAuthorityCapsule {
    SessionConsumerRosterCurrentPublicationAuthorityCapsule::new(
        authority.ingress_scope().digest(),
        admission.key().clone(),
        *admission.roster_id().as_bytes(),
        admission.body_commitment(),
        terminal.body_commitment(),
        receipt,
        admission.logical_owner().clone(),
        admission.admission_fence(),
        registration.0,
        registration.1.to_bytes(),
        registration.2,
        authority.owner().clone(),
        authority.fence(),
        authority.credential_id(),
        authority.generation(),
        authority.acquired_at(),
        authority.expires_at(),
    )
    .unwrap()
}

fn check_v1(
    wal: &Wal,
    backend: &SqliteSessionBackend,
    signed: &RosterV2PersistenceFixture,
    admission: &Admission,
    authority: &AuthorityBinding,
    command: &ConsensusRosterTerminalCommand,
    expected_kind: u8,
) {
    let now = wal
        .with_native_read(|state| Ok(state.logical_time().unwrap()))
        .unwrap();
    let conn = backend.conn.blocking_lock();
    let actual = native(wal, signed, |store, now| {
        roster_reads::read_protected_roster_admission_status_sync(
            store,
            signed.identity,
            admission,
            authority,
            now,
        )
    });
    let expected = read_protected_roster_admission_status_sync(
        &conn,
        signed.identity,
        admission,
        authority,
        now,
    );
    let actual = v1_bytes(actual);
    assert_eq!(actual, v1_bytes(expected));
    assert_eq!(actual.unwrap()[0], [expected_kind]);
    let terminal = TerminalRecord::from_canonical_bytes(command.record_bytes(), admission).unwrap();
    let evidence = command.terminal_evidence().unwrap();
    let request = |now| ProtectedRosterTerminalStatusRequest {
        registration_parts: command.registration_parts(),
        current_authority: authority,
        terminal_body_commitment: terminal.body_commitment(),
        terminal_evidence: &evidence,
        logical_time: now,
    };
    let actual = native(wal, signed, |store, now| {
        roster_reads::read_protected_roster_terminal_status_sync(
            store,
            signed.identity,
            command.binding(),
            request(now),
        )
    });
    let expected = read_protected_roster_terminal_status_sync(
        &conn,
        signed.identity,
        command.binding(),
        request(now),
    );
    assert_eq!(v1_bytes(actual.clone()), v1_bytes(expected));
    if let Ok(ProtectedRosterReadResult::Terminalized(value)) = actual {
        for receipt in [value.committed.receipt_commitment(), [0xEF; 32]] {
            let query = publication(
                admission,
                command.registration_parts(),
                authority,
                &terminal,
                receipt,
            );
            let actual = native(wal, signed, |store, now| {
                roster_reads::read_protected_roster_current_publication_authority_sync(
                    store,
                    signed.identity,
                    &query,
                    now,
                )
            });
            let expected = read_protected_roster_current_publication_authority_sync(
                &conn,
                signed.identity,
                &query,
                now,
            );
            assert_eq!(actual, expected);
            assert_eq!(
                actual.is_ok(),
                receipt == value.committed.receipt_commitment()
            );
        }
    }
}

fn check_v2(
    wal: &Wal,
    backend: &SqliteSessionBackend,
    signed: &RosterV2PersistenceFixture,
    admission: &Admission,
    authority: &AuthorityBinding,
    command: &crate::consensus::types::ConsensusRosterTerminalCommandV2,
    expected_kind: u8,
) {
    let now = wal
        .with_native_read(|state| Ok(state.logical_time().unwrap()))
        .unwrap();
    let conn = backend.conn.blocking_lock();
    let actual = native(wal, signed, |store, now| {
        roster_reads::read_protected_roster_v2_admission_status_sync(
            store,
            signed.identity,
            admission,
            authority,
            now,
        )
    });
    let expected = read_protected_roster_v2_admission_status_sync(
        &conn,
        signed.identity,
        admission,
        authority,
        now,
    );
    let actual = v2_bytes(actual);
    assert_eq!(actual, v2_bytes(expected));
    assert_eq!(actual.unwrap()[0], [expected_kind]);
    let terminal = TerminalRecord::from_canonical_bytes(command.record_bytes(), admission).unwrap();
    let evidence = command.terminal_evidence().unwrap();
    let request = |now| ProtectedRosterV2TerminalStatusRequest {
        registration_parts: command.registration_parts(),
        current_authority: authority,
        terminal_body_commitment: terminal.body_commitment(),
        terminal_evidence: &evidence,
        logical_time: now,
    };
    let actual = native(wal, signed, |store, now| {
        roster_reads::read_protected_roster_v2_terminal_status_sync(
            store,
            signed.identity,
            command.binding(),
            request(now),
        )
    });
    let expected = read_protected_roster_v2_terminal_status_sync(
        &conn,
        signed.identity,
        command.binding(),
        request(now),
    );
    assert_eq!(v2_bytes(actual.clone()), v2_bytes(expected));
    if let Ok(ProtectedRosterV2ReadResult::Terminalized(value)) = actual {
        for receipt in [value.committed.receipt_commitment(), [0xEF; 32]] {
            let query = publication(
                admission,
                command.registration_parts(),
                authority,
                &terminal,
                receipt,
            );
            let actual = native(wal, signed, |store, now| {
                roster_reads::read_protected_roster_v2_current_publication_authority_sync(
                    store,
                    signed.identity,
                    &query,
                    now,
                )
            });
            let expected = read_protected_roster_v2_current_publication_authority_sync(
                &conn,
                signed.identity,
                &query,
                now,
            );
            assert_eq!(actual, expected);
            assert_eq!(
                actual.is_ok(),
                receipt == value.committed.receipt_commitment()
            );
        }
    }
}

#[test]
fn native_public_signed_roster_status_and_publication_match_original_sql_across_cold_reopen() {
    let (directory, backend, signed, mut wal) = fresh(Phase::Established);
    check_v2(
        &wal,
        &backend,
        &signed,
        &signed.admission,
        &signed.authority,
        &signed.terminal_command,
        0,
    );
    parity(&wal, &backend, &signed, &[admission(&signed)]);
    check_v2(
        &wal,
        &backend,
        &signed,
        &signed.admission,
        &signed.authority,
        &signed.terminal_command,
        1,
    );
    wal = reopen(&wal, directory.path(), &signed);
    check_v2(
        &wal,
        &backend,
        &signed,
        &signed.admission,
        &signed.authority,
        &signed.terminal_command,
        1,
    );
    parity(&wal, &backend, &signed, &[terminal(&signed, 4)]);
    check_v2(
        &wal,
        &backend,
        &signed,
        &signed.admission,
        &signed.authority,
        &signed.terminal_command,
        2,
    );
    parity(
        &wal,
        &backend,
        &signed,
        &[ordinary(
            &signed,
            5,
            SessionMutationIntent::ActivateFencedTransitionCapability {
                schema_version: crate::fenced_transition::FENCED_TRANSITION_SCHEMA_V1,
                scope_identity: signed.identity,
                voter_set_digest: protected_roster_profile_voter_set_digest(
                    signed.identity,
                    &fixed_members(),
                ),
            },
        )],
    );
    let q1 = signed_v1_command_with_mutation(&signed, EstablishedMutation::no_op());
    let q2 = v1_fixture::terminal(&signed, &q1, 6, Phase::Established);
    check_v1(
        &wal,
        &backend,
        &signed,
        q1.admission(),
        q1.authority(),
        &q2,
        0,
    );
    parity(
        &wal,
        &backend,
        &signed,
        &[entry(
            &signed,
            6,
            q1.request_id().unwrap(),
            SessionMutationIntent::RosterAdmission(Box::new(q1.clone())),
        )],
    );
    check_v1(
        &wal,
        &backend,
        &signed,
        q1.admission(),
        q1.authority(),
        &q2,
        1,
    );
    wal = reopen(&wal, directory.path(), &signed);
    check_v1(
        &wal,
        &backend,
        &signed,
        q1.admission(),
        q1.authority(),
        &q2,
        1,
    );
    parity(
        &wal,
        &backend,
        &signed,
        &[entry(
            &signed,
            7,
            q2.request_id().unwrap(),
            SessionMutationIntent::RosterTerminal(Box::new(q2.clone())),
        )],
    );
    wal = reopen(&wal, directory.path(), &signed);
    check_v1(
        &wal,
        &backend,
        &signed,
        q1.admission(),
        q1.authority(),
        &q2,
        2,
    );
    check_v2(
        &wal,
        &backend,
        &signed,
        &signed.admission,
        &signed.authority,
        &signed.terminal_command,
        2,
    );
    let original_lease = crate::LeaseGuard::new(
        signed.authority.key().clone(),
        signed.authority.owner().clone(),
        signed.authority.fence(),
        signed.authority.acquired_at(),
        signed.authority.expires_at(),
        signed.authority.credential_id(),
    );
    parity(
        &wal,
        &backend,
        &signed,
        &[ordinary(
            &signed,
            8,
            SessionMutationIntent::ReleaseLease(original_lease),
        )],
    );
    let mut applied = parity(
        &wal,
        &backend,
        &signed,
        &[ordinary(
            &signed,
            9,
            SessionMutationIntent::AcquireLease {
                key: signed.authority.key().clone(),
                owner: OwnerId::new("public-roster-successor").unwrap(),
                ttl: Duration::from_secs(60),
            },
        )],
    );
    let Ok(SessionMutationOutcome::Lease(guard)) = applied.responses.remove(0).result else {
        panic!("successor lease");
    };
    for generation in [1, 0, i64::MAX as u64 + 1, u64::MAX] {
        let authority = AuthorityBinding::from_consensus_parts(
            signed.authority.scope().digest(),
            guard.key().clone(),
            guard.owner().clone(),
            guard.fence(),
            AuthorityLeaseMetadata::new(
                guard.credential_id(),
                Generation::new(generation),
                guard.acquired_at(),
                guard.expires_at(),
            ),
        )
        .unwrap();
        for (admission, v2) in [(q1.admission(), false), (&signed.admission, true)] {
            let recovery = RecoveryRequest::new(RecoveryRequestInput::new(
                RecoveryLookup::new(admission.scope(), admission.roster_id()),
                admission.logical_owner().clone(),
                admission.admission_fence(),
                authority.clone(),
            ))
            .unwrap();
            let now = guard.acquired_at();
            let actual = if v2 {
                v2_bytes(native(&wal, &signed, |store, now| {
                    roster_reads::read_protected_roster_v2_recovery_sync(
                        store,
                        signed.identity,
                        &recovery,
                        now,
                    )
                }))
            } else {
                v1_bytes(native(&wal, &signed, |store, now| {
                    roster_reads::read_protected_roster_recovery_sync(
                        store,
                        signed.identity,
                        &recovery,
                        now,
                    )
                }))
            };
            let conn = backend.conn.blocking_lock();
            let expected = if v2 {
                v2_bytes(read_protected_roster_v2_recovery_sync(
                    &conn,
                    signed.identity,
                    &recovery,
                    now,
                ))
            } else {
                v1_bytes(read_protected_roster_recovery_sync(
                    &conn,
                    signed.identity,
                    &recovery,
                    now,
                ))
            };
            assert_eq!(actual, expected);
            if generation == 1 {
                assert_eq!(actual.unwrap()[0], [2]);
            } else {
                assert!(actual.is_err(), "original positive-i64 and expected-generation validation precedes lineage lookup");
            }
        }
    }
    assert_eq!(wal.native_sql_fallback_count().unwrap(), 0);
    wal.shutdown().unwrap();
}
