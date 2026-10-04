use super::*;
use crate::consensus::native::changes::Publication;
use crate::consensus::types::{
    protected_roster_profile_v2_voter_set_digest, RosterV2PersistenceFixture,
};
use opc_consensus::engine::{CommittedLeaderId, Membership};

fn entry(
    signed: &RosterV2PersistenceFixture,
    index: u64,
    request_id: SessionConsensusRequestId,
    mutation: SessionMutationIntent,
) -> Entry<SessionRaftTypeConfig> {
    let origin = SessionConsensusNodeId::new(7).unwrap();
    Entry {
        log_id: LogId::new(CommittedLeaderId::new(1, origin), index),
        payload: EntryPayload::Normal(SessionConsensusCommand {
            schema_version: crate::consensus::SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: signed.identity,
            request_id,
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
    let command = command(signed);
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

fn configured(signed: &RosterV2PersistenceFixture) -> NativeState {
    let mut state = predecessor(signed, None);
    state.roster_root = Some(Arc::new(signed.root.clone()));
    state.frontiers.roster_v2_activation = Some(NativeActivation {
        identity: signed.identity,
        voters: protected_roster_profile_v2_voter_set_digest(signed.identity, &state.members),
        profile: crate::fenced_mutation_roster::Profile::v2().digest(),
    });
    state.admit_business().unwrap();
    let origin = SessionConsensusNodeId::new(7).unwrap();
    state
        .apply(&[Entry {
            log_id: LogId::new(CommittedLeaderId::new(1, origin), 0),
            payload: EntryPayload::Membership(Membership::new(
                vec![state.members.clone()],
                state.members.clone(),
            )),
        }])
        .unwrap();
    state.begin_changes().unwrap();
    state
}

fn ordinary(signed: &RosterV2PersistenceFixture, index: u64) -> Entry<SessionRaftTypeConfig> {
    entry(
        signed,
        index,
        SessionConsensusRequestId::from_bytes((0x1000 + u128::from(index)).to_be_bytes()),
        SessionMutationIntent::AdvanceLogicalTime,
    )
}

fn selected(state: &mut NativeState) -> Vec<(RequestBindingKey, row_tests::FileFixture)> {
    let delta = state.prepare(&[]).unwrap();
    let check = || Ok(());
    let mut store = Store::for_command(&delta, &check).unwrap();
    let files = row_tests::select_all(&mut store);
    let (ledger, keys, revision) = store.finish();
    assert!(keys.is_empty());
    assert_eq!(revision, state.frontiers.restore_revision);
    assert!(Arc::ptr_eq(
        ledger.certificate().unwrap(),
        state.roster.certificate().unwrap()
    ));
    state.roster = ledger;
    files
}

fn apply_logged(state: &mut NativeState, entry: &Entry<SessionRaftTypeConfig>) -> NativeApplied {
    let bytes = serde_json::to_vec(entry).unwrap();
    let row = log::NativeLogEntry::new(bytes.clone().into(), entry.clone());
    row.validate_full(entry.log_id.index, state.identity, &state.members, &|| {
        Ok(())
    })
    .unwrap();
    let decoded = crate::consensus::native::generation::decode::owned_log(
        &bytes,
        entry.log_id.index,
        state.identity,
        &state.members,
        &|| Ok(()),
    )
    .unwrap();
    assert!(decoded.entry() == entry);
    let applied = state.apply(std::slice::from_ref(decoded.entry())).unwrap();
    for notification in &applied.notifications {
        let bytes = postcard::to_allocvec(notification).unwrap();
        let admitted = crate::consensus::native::generation::decode::inspect_notification(
            &bytes,
            notification.sequence,
            &state.frontiers,
            &|| Ok(()),
        )
        .unwrap();
        let copied = crate::consensus::native::generation::decode::owned_notification(
            &bytes,
            admitted,
            &state.frontiers,
            &|| Ok(()),
        )
        .unwrap();
        assert_eq!(postcard::to_allocvec(copied.entry()).unwrap(), bytes);
    }
    applied
}

#[test]
fn native_roster_logged_v1_and_v2_publication_preserves_signed_sql_results() {
    use crate::consensus::types::protected_roster_profile_voter_set_digest;
    use crate::fenced_mutation_roster::{EstablishedMutation, Phase};
    use crate::sqlite::consensus::native_roster_apply_fixture;
    for delete in [false, true] {
        for phase in [Phase::Established, Phase::Aborted] {
            let signed = crate::consensus::types::roster_v2_persistence_fixture();
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("logged-native-roster.sqlite");
            let mut state = configured(&signed);
            // Complete response digests and activation certificates include
            // membership. Initialize both sides with the same valid native
            // three-voter set through the original SQL fixture apply path.
            let sql_fixture = crate::sqlite::consensus::initialize_protected_roster_v2_recovery_fixture_with_members(
                &path,ProtectedRosterV2RecoveryFixtureState::Established,state.members.clone()).unwrap();
            assert_eq!(sql_fixture.members, state.members);
            apply_logged(&mut state, &q1(&signed, 1));
            apply_logged(&mut state, &q2(&signed, 2));
            let q1 = carrier::tests::signed_v1_command_with_mutation(
                &signed,
                if delete {
                    EstablishedMutation::delete()
                } else {
                    EstablishedMutation::no_op()
                },
            );
            let q2 = v1_fixture::terminal(&signed, &q1, 4, phase);
            let activation = entry(
                &signed,
                3,
                SessionConsensusRequestId::from_bytes([0xC8; 16]),
                SessionMutationIntent::ActivateFencedTransitionCapability {
                    schema_version: crate::fenced_transition::FENCED_TRANSITION_SCHEMA_V1,
                    scope_identity: signed.identity,
                    voter_set_digest: protected_roster_profile_voter_set_digest(
                        signed.identity,
                        &state.members,
                    ),
                },
            );
            let entries = [
                activation,
                entry(
                    &signed,
                    4,
                    q1.request_id().unwrap(),
                    SessionMutationIntent::RosterAdmission(Box::new(q1.clone())),
                ),
                entry(
                    &signed,
                    5,
                    q2.request_id().unwrap(),
                    SessionMutationIntent::RosterTerminal(Box::new(q2.clone())),
                ),
            ];
            let expected_key = state.keys[signed.authority.key()].record.clone();
            for value in &entries {
                let native = apply_logged(&mut state, value);
                let sql = native_roster_apply_fixture(&path, signed.identity, vec![value.clone()])
                    .unwrap();
                assert_eq!(native.responses, sql.responses);
                assert_eq!(
                    postcard::to_allocvec(&native.notifications).unwrap(),
                    postcard::to_allocvec(&sql.notifications).unwrap()
                );
                let sql = Connection::open(&path).unwrap();
                assert_eq!(
                    state.keys[signed.authority.key()].record,
                    crate::sqlite::ops::get_raw_sync(&sql, signed.authority.key()).unwrap()
                );
                if value.log_id.index >= 4 {
                    let binding = q1.admission().binding_key(4).unwrap();
                    let canonical:Vec<u8> = sql.query_row("SELECT canonical_record FROM consensus_protected_roster_rows WHERE binding=?1",
                        [binding.to_bytes().as_slice()],|row| row.get(0)).unwrap();
                    assert_eq!(state.roster.rows[&binding].canonical().unwrap(), canonical);
                    assert!(state.roster.witness == Some(sql_witness(&sql)));
                }
                state.validate_full_business().unwrap();
                state
                    .capture_changes()
                    .unwrap()
                    .validate_captured(&|| Ok(()))
                    .unwrap();
            }
            assert!(
                state.frontiers.roster_v1_namespace
                    && state.frontiers.roster_v2_activation.is_some()
            );
            assert!(!state.keys[signed.authority.key()].reserved);
            assert_eq!(
                state.keys[signed.authority.key()].record,
                if delete && phase == Phase::Established {
                    None
                } else {
                    expected_key
                }
            );
            let terminal = apply_logged(
                &mut state,
                &entry(
                    &signed,
                    6,
                    q2.request_id().unwrap(),
                    SessionMutationIntent::RosterTerminal(Box::new(q2)),
                ),
            );
            assert!(matches!(
                terminal.responses[0].result,
                Ok(SessionMutationOutcome::RosterTerminal(
                    ConsensusRosterTerminalOutcome::Committed { replayed: true, .. }
                ))
            ));
            assert!(terminal.notifications.is_empty());
        }
    }
}

#[test]
fn native_roster_publication_joint_q1_q2_replay_and_capture_match_signed_sql() {
    for established in [true, false] {
        let signed = if established {
            crate::consensus::types::roster_v2_persistence_fixture()
        } else {
            crate::consensus::types::roster_v2_aborted_persistence_fixture()
        };
        let mut state = configured(&signed);
        assert!(state.protected_roster_v2_activation_matches(signed.identity, &state.members));
        let admitted = state.apply(&[q1(&signed, 1)]).unwrap();
        assert!(matches!(
            admitted.responses[0].result,
            Ok(SessionMutationOutcome::RosterAdmissionV2(
                ConsensusRosterAdmissionOutcome::Admitted { .. }
            ))
        ));
        assert!(state.keys[signed.authority.key()].reserved);
        assert_eq!(state.generic_receipts.len(), 0);
        state.validate_full_business().unwrap();
        let detached = state.capture_application().unwrap();
        let terminal = detached
            .prepare(&[q2(&signed, 2)], &|| Ok(()), || Ok(()))
            .unwrap();
        assert!(
            state.keys[signed.authority.key()].reserved,
            "detached evaluation has not published"
        );
        assert!(terminal.is_current(&state).unwrap());
        let terminal = terminal.publish(&mut state).unwrap();
        assert_eq!(terminal.notifications.len(), usize::from(established));
        assert!(!state.keys[signed.authority.key()].reserved);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("joint-oracle.sqlite");
        initialize_protected_roster_v2_recovery_fixture(
            &path,
            if established {
                ProtectedRosterV2RecoveryFixtureState::Established
            } else {
                ProtectedRosterV2RecoveryFixtureState::Aborted
            },
        )
        .unwrap();
        let sql = Connection::open(path).unwrap();
        let binding = signed.admission.binding_key(1).unwrap();
        assert_eq!(
            state.roster.rows[&binding].canonical().unwrap(),
            sql_row(&sql, binding)
        );
        assert!(state.roster.witness == Some(sql_witness(&sql)));
        assert_eq!(
            state.keys[signed.authority.key()].record,
            crate::sqlite::ops::get_raw_sync(&sql, signed.authority.key()).unwrap()
        );
        let certificate = Arc::clone(state.roster.certificate().unwrap());
        let replay = state.apply(&[q2(&signed, 3)]).unwrap();
        assert!(matches!(
            replay.responses[0].result,
            Ok(SessionMutationOutcome::RosterTerminalV2(
                ConsensusRosterTerminalOutcome::Committed { replayed: true, .. }
            ))
        ));
        assert!(replay.notifications.is_empty());
        assert!(Arc::ptr_eq(
            &certificate,
            state.roster.certificate().unwrap()
        ));
        assert_eq!(state.frontiers.sequence, 3);
        assert_eq!(state.generic_receipts.len(), 0);
        state.validate_full_business().unwrap();
        let capture = state.capture_changes().unwrap();
        capture.validate_captured(&|| Ok(())).unwrap();
        state
            .capture_changes()
            .unwrap()
            .validate_captured(&|| Ok(()))
            .unwrap();
        assert!(
            serde_json::to_vec(&state).is_err(),
            "old full-image encoding cannot omit the roster"
        );
    }
}

#[test]
fn native_roster_publication_rejects_omitted_release_business_after_image_before_commit() {
    let signed = crate::consensus::types::roster_v2_aborted_persistence_fixture();
    let mut state = configured(&signed);
    state.apply(&[q1(&signed, 1)]).unwrap();
    let proof = Arc::clone(state.require_business_proof().unwrap());
    let certificate = Arc::clone(state.roster.certificate().unwrap());
    let before_key = state.keys[signed.authority.key()].clone();
    let before_frontiers = serde_json::to_vec(&state.frontiers).unwrap();
    let mut delta = state.prepare(&[q2(&signed, 2)]).unwrap();
    assert!(delta.keys.remove(signed.authority.key()).is_some());
    assert!(Publication::prepare(delta).is_err());
    assert!(Arc::ptr_eq(&proof, state.require_business_proof().unwrap()));
    assert!(Arc::ptr_eq(
        &certificate,
        state.roster.certificate().unwrap()
    ));
    assert!(before_key.ptr_eq(&state.keys[signed.authority.key()]));
    assert_eq!(
        serde_json::to_vec(&state.frontiers).unwrap(),
        before_frontiers
    );
    assert!(state.keys[signed.authority.key()].reserved);
    state
        .capture_changes()
        .unwrap()
        .validate_captured(&|| Ok(()))
        .unwrap();
    state.apply(&[q2(&signed, 2)]).unwrap();
    assert!(!state.keys[signed.authority.key()].reserved);
    state.validate_full_business().unwrap();
    state
        .capture_changes()
        .unwrap()
        .validate_captured(&|| Ok(()))
        .unwrap();
}

#[test]
fn native_roster_publication_release_and_new_reservation_share_one_final_business_view() {
    let first = crate::consensus::types::roster_v2_aborted_persistence_fixture();
    let second =
        crate::consensus::types::roster_v2_aborted_persistence_fixture_for_history([0x92; 16], 3);
    let mut state = configured(&first);
    state.apply(&[q1(&first, 1)]).unwrap();
    let applied = state.apply(&[q2(&first, 2), q1(&second, 3)]).unwrap();
    assert!(matches!(
        applied.responses[0].result,
        Ok(SessionMutationOutcome::RosterTerminalV2(
            ConsensusRosterTerminalOutcome::Committed {
                replayed: false,
                ..
            }
        ))
    ));
    assert!(matches!(
        applied.responses[1].result,
        Ok(SessionMutationOutcome::RosterAdmissionV2(
            ConsensusRosterAdmissionOutcome::Admitted { .. }
        ))
    ));
    assert_eq!(
        state.roster.index.reservation(first.authority.key()),
        Some(second.admission.binding_key(3).unwrap())
    );
    assert!(state.keys[first.authority.key()].reserved);
    assert!(
        state.roster.rows[&first.admission.binding_key(1).unwrap()]
            .facts()
            .state
            == State::Retained
    );
    state.validate_full_business().unwrap();
    state
        .capture_changes()
        .unwrap()
        .validate_captured(&|| Ok(()))
        .unwrap();
    state.apply(&[q2(&second, 4)]).unwrap();
    assert!(!state.keys[first.authority.key()].reserved);
    state.validate_full_business().unwrap();
    state
        .capture_changes()
        .unwrap()
        .validate_captured(&|| Ok(()))
        .unwrap();
}

#[test]
fn native_roster_publication_authority_failure_discards_earlier_entries_and_responses() {
    let signed = crate::consensus::types::roster_v2_aborted_persistence_fixture();
    let mut state = configured(&signed);
    for case in 0..3 {
        let mut invalid = q2(&signed, 2);
        let EntryPayload::Normal(command) = &mut invalid.payload else {
            unreachable!()
        };
        let terminal =
            SessionMutationIntent::RosterTerminalV2(Box::new(signed.terminal_command.clone()));
        let origin = SessionConsensusNodeId::new(7).unwrap();
        command.intent = match case {
            0 => terminal,
            1 => SessionMutationIntent::Authorized {
                origin,
                authority_identity: signed.identity,
                mutation: Box::new(SessionMutationIntent::Authorized {
                    origin,
                    authority_identity: signed.identity,
                    mutation: Box::new(terminal),
                }),
            },
            2 => SessionMutationIntent::Authorized {
                origin: SessionConsensusNodeId::new(10).unwrap(),
                authority_identity: signed.identity,
                mutation: Box::new(terminal),
            },
            _ => unreachable!(),
        };
        let proof = Arc::clone(state.require_business_proof().unwrap());
        let key = state.keys[signed.authority.key()].clone();
        assert!(
            state.apply(&[q1(&signed, 1), invalid]).is_err(),
            "invalid authority {case}"
        );
        assert!(Arc::ptr_eq(&proof, state.require_business_proof().unwrap()));
        assert!(state.keys[signed.authority.key()].ptr_eq(&key));
        assert!(state.roster.rows.is_empty());
        assert_eq!(state.frontiers.sequence, 0);
        assert!(state.notifications.is_empty() && state.generic_receipts.is_empty());
    }
    state.apply(&[q1(&signed, 1), q2(&signed, 2)]).unwrap();
    state.validate_full_business().unwrap();
    state
        .capture_changes()
        .unwrap()
        .validate_captured(&|| Ok(()))
        .unwrap();
}

#[test]
fn native_roster_publication_activation_profiles_and_missing_root_remain_independent() {
    use crate::consensus::types::protected_roster_profile_voter_set_digest;
    for root_configured in [false, true] {
        let signed = crate::consensus::types::roster_v2_persistence_fixture();
        let mut state = configured(&signed).clone();
        state.frontiers.roster_v2_activation = None;
        if !root_configured {
            state.roster_root = None;
        }
        state.admit_business().unwrap();
        state.begin_changes().unwrap();
        let proof = Arc::clone(state.require_business_proof().unwrap());
        assert!(
            state.apply(&[q1(&signed, 1)]).is_err(),
            "unactivated Q1 is not application history"
        );
        assert!(Arc::ptr_eq(&proof, state.require_business_proof().unwrap()));
        let profile = crate::fenced_mutation_roster::Profile::v2();
        let activation = entry(
            &signed,
            1,
            SessionConsensusRequestId::from_bytes([0xE1; 16]),
            SessionMutationIntent::ActivateProtectedRosterProfileV2 {
                schema_version: profile.schema(),
                consumer_revision: profile.consumer_revision(),
                scope_identity: signed.identity,
                voter_set_digest: protected_roster_profile_v2_voter_set_digest(
                    signed.identity,
                    &state.members,
                ),
                profile_digest: profile.digest(),
            },
        );
        assert_eq!(
            state.apply(&[activation]).unwrap().responses[0].result,
            Ok(SessionMutationOutcome::Unit)
        );
        assert!(
            state.frontiers.activation.is_none()
                && state.frontiers.history.is_none()
                && state.frontiers.v1_activation.is_none()
        );
        assert!(!state.frontiers.roster_v1_namespace);
        assert!(state.protected_roster_v2_activation_matches(signed.identity, &state.members));
        let admission = state.apply(&[q1(&signed, 2)]).unwrap();
        if root_configured {
            assert!(matches!(
                admission.responses[0].result,
                Ok(SessionMutationOutcome::RosterAdmissionV2(
                    ConsensusRosterAdmissionOutcome::Admitted { .. }
                ))
            ));
        } else {
            assert!(matches!(
                admission.responses[0].result,
                Ok(SessionMutationOutcome::RosterAdmissionV2(
                    ConsensusRosterAdmissionOutcome::Rejected { .. }
                ))
            ));
            assert!(state.roster.rows.is_empty() && !state.keys[signed.authority.key()].reserved);
            let activation = entry(
                &signed,
                3,
                SessionConsensusRequestId::from_bytes([0xE2; 16]),
                SessionMutationIntent::ActivateFencedTransitionCapability {
                    schema_version: crate::fenced_transition::FENCED_TRANSITION_SCHEMA_V1,
                    scope_identity: signed.identity,
                    voter_set_digest: protected_roster_profile_voter_set_digest(
                        signed.identity,
                        &state.members,
                    ),
                },
            );
            state.apply(&[activation]).unwrap();
            assert!(!state.frontiers.roster_v1_namespace);
            let command = carrier::tests::signed_v1_command(&signed);
            let admission = entry(
                &signed,
                4,
                command.request_id().unwrap(),
                SessionMutationIntent::RosterAdmission(Box::new(command)),
            );
            assert!(matches!(
                state.apply(&[admission]).unwrap().responses[0].result,
                Ok(SessionMutationOutcome::RosterAdmission(
                    ConsensusRosterAdmissionOutcome::Rejected { .. }
                ))
            ));
            assert!(state.frontiers.roster_v1_namespace && state.roster.rows.is_empty());
        }
        state.validate_full_business().unwrap();
        state
            .capture_changes()
            .unwrap()
            .validate_captured(&|| Ok(()))
            .unwrap();
    }
}

#[test]
fn native_roster_publication_selected_cancel_corruption_and_stale_proof_reject_before_commit() {
    let signed = crate::consensus::types::roster_v2_aborted_persistence_fixture();
    let mut state = configured(&signed);
    state.apply(&[q1(&signed, 1)]).unwrap();
    let files = selected(&mut state);
    let proof = Arc::clone(state.require_business_proof().unwrap());
    let captured = state.capture_application().unwrap();
    assert!(captured
        .prepare(
            &[q2(&signed, 2)],
            &|| Err(io::Error::other("cancelled selected application")),
            || Ok(())
        )
        .is_err());
    assert!(Arc::ptr_eq(&proof, state.require_business_proof().unwrap()));
    let captured = state.capture_application().unwrap();
    let publication = captured
        .prepare(&[q2(&signed, 2)], &|| Ok(()), || Ok(()))
        .unwrap();
    let mut changed_root = state.clone();
    changed_root.roster_root = Some(Arc::new(
        RosterAttestationTrustRootV1::new([0xF1; 32], signed.root.compressed_public_key()).unwrap(),
    ));
    assert!(publication.is_current(&changed_root).is_err());
    let mut rebuilt = state.clone();
    rebuilt.admit_business().unwrap();
    assert!(!publication.is_current(&rebuilt).unwrap());
    assert!(publication.publish(&mut rebuilt).is_err());
    assert!(rebuilt.keys[signed.authority.key()].reserved);
    state.apply(&[ordinary(&signed, 2)]).unwrap();
    let proof = Arc::clone(state.require_business_proof().unwrap());
    let captured = state.capture_application().unwrap();
    files[0].1.corrupt_prefix();
    assert!(captured
        .prepare(&[q2(&signed, 3)], &|| Ok(()), || Ok(()))
        .is_err());
    assert!(Arc::ptr_eq(&proof, state.require_business_proof().unwrap()));
    assert!(state.keys[signed.authority.key()].reserved);
    assert_eq!(state.frontiers.sequence, 2);
}

#[test]
fn native_roster_publication_normal_command_maintains_and_captures_retirement() {
    let signed = crate::consensus::types::roster_v2_aborted_persistence_fixture();
    let mut state = configured(&signed);
    state.apply(&[q1(&signed, 1), q2(&signed, 2)]).unwrap();
    let binding = signed.admission.binding_key(1).unwrap();
    for index in [3, 4] {
        let mut maintenance = ordinary(&signed, index);
        let EntryPayload::Normal(command) = &mut maintenance.payload else {
            unreachable!()
        };
        command.logical_time = signed
            .authority
            .acquired_at()
            .add_seconds(1 + 24 * 60 * 60)
            .unwrap();
        state.apply(&[maintenance]).unwrap();
        if index == 3 {
            assert!(state.roster.rows[&binding].facts().state == State::Tombstone);
        } else {
            assert!(state.roster.rows.is_empty() && state.roster.partitions.is_empty());
        }
        state.validate_full_business().unwrap();
        state
            .capture_changes()
            .unwrap()
            .validate_captured(&|| Ok(()))
            .unwrap();
    }
    assert_eq!(state.frontiers.sequence, 4);
    assert_eq!(state.roster.witness.unwrap().retired_terminal_sequence(), 2);
    assert!(!state.keys[signed.authority.key()].reserved);
}
