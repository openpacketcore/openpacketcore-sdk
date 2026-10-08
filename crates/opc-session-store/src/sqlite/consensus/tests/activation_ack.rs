use super::*;

const ACTIVATIONS: [CapabilityActivationKind; 3] = [
    CapabilityActivationKind::FencedTransitionV1,
    CapabilityActivationKind::ProtectedRosterV1,
    CapabilityActivationKind::ProtectedRosterV2,
];

fn marker(activation: CapabilityActivationKind) -> Entry<SessionRaftTypeConfig> {
    let intent = match activation {
        CapabilityActivationKind::FencedTransitionV1 => {
            SessionMutationIntent::ActivateFencedTransitionCapability {
                schema_version: FENCED_TRANSITION_SCHEMA_V1,
                scope_identity: identity(),
                voter_set_digest: fenced_transition_voter_set_digest(
                    identity(),
                    &expected_members(),
                ),
            }
        }
        CapabilityActivationKind::ProtectedRosterV1 => {
            SessionMutationIntent::ActivateFencedTransitionCapability {
                schema_version: FENCED_TRANSITION_SCHEMA_V1,
                scope_identity: identity(),
                voter_set_digest: protected_roster_profile_voter_set_digest(
                    identity(),
                    &expected_members(),
                ),
            }
        }
        CapabilityActivationKind::ProtectedRosterV2 => {
            let profile = crate::fenced_mutation_roster::Profile::v2();
            SessionMutationIntent::ActivateProtectedRosterProfileV2 {
                schema_version: profile.schema(),
                consumer_revision: profile.consumer_revision(),
                scope_identity: identity(),
                voter_set_digest: protected_roster_profile_v2_voter_set_digest(
                    identity(),
                    &expected_members(),
                ),
                profile_digest: profile.digest(),
            }
        }
    };
    Entry {
        log_id: log_id(1),
        payload: EntryPayload::Normal(SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: identity(),
            request_id: SessionConsensusRequestId::from_bytes([0xAC; 16]),
            logical_time: timestamp(1),
            intent: SessionMutationIntent::Authorized {
                origin: node_id(),
                authority_identity: identity(),
                mutation: Box::new(intent),
            },
        }),
    }
}

#[test]
fn activation_ack_sql_snapshot_requires_exact_certificate_and_applied_frontier() {
    for activation in ACTIVATIONS {
        let backend = SqliteSessionBackend::in_memory().unwrap();
        let conn = backend.conn.blocking_lock();
        initialize_schema(&conn, identity(), &expected_members()).unwrap();
        let lookup = |scope, voters: &BTreeSet<_>, kind| {
            capability_activation_applied_index_sync(&conn, identity(), scope, voters, kind)
        };
        for kind in ACTIVATIONS {
            assert_eq!(lookup(identity(), &expected_members(), kind).unwrap(), None);
        }
        let entries = vec![membership_entry(), marker(activation)];
        append_logs_sync(&conn, identity(), &entries).unwrap();
        let applied = apply_entries_sync(&conn, identity(), &backend.caps, entries).unwrap();
        assert_eq!(
            applied.responses[1].result,
            Ok(SessionMutationOutcome::Unit)
        );

        for kind in ACTIVATIONS {
            // The frozen protected-roster V1 certificate also proves generic
            // V1. The independent V2 profile must never satisfy either V1.
            let matches = kind == activation
                || (activation == CapabilityActivationKind::ProtectedRosterV1
                    && kind == CapabilityActivationKind::FencedTransitionV1);
            assert_eq!(
                lookup(identity(), &expected_members(), kind).unwrap(),
                matches.then_some(1)
            );
        }
        let successor = SessionConsensusIdentity::new(
            identity().cluster_id(),
            identity().configuration_id(),
            SessionConsensusConfigurationEpoch::new(identity().configuration_epoch().get() + 1)
                .unwrap(),
        );
        assert_eq!(
            lookup(successor, &expected_members(), activation).unwrap(),
            None
        );
        assert_eq!(
            lookup(identity(), &BTreeSet::new(), activation).unwrap(),
            None
        );
        let mut other_voters = expected_members();
        other_voters.insert(SessionConsensusNodeId::new(99).unwrap());
        assert_eq!(lookup(identity(), &other_voters, activation).unwrap(), None);

        let later = blank_entry(2);
        append_logs_sync(&conn, identity(), std::slice::from_ref(&later)).unwrap();
        apply_entries_sync(&conn, identity(), &backend.caps, vec![later]).unwrap();
        assert_eq!(
            lookup(identity(), &expected_members(), activation).unwrap(),
            Some(2),
            "a later backend frontier still covers the exact certificate"
        );

        conn.execute("DELETE FROM consensus_applied", []).unwrap();
        assert!(
            lookup(identity(), &expected_members(), activation).is_err(),
            "a certificate without its backend applied frontier cannot be acknowledged"
        );
        assert!(
            conn.is_autocommit(),
            "an error must release the read transaction"
        );
    }
}
