//! Codec completeness checks. Runtime authority and process loss are exercised
//! separately; an encoding round trip alone cannot qualify a recovery profile.

use super::{codec::ProfileCodec as Codec, inputs, row::*, wire::Wire};
use bytes::Bytes;
use opc_proto_ikev2::{
    recovery::{
        Ikev2CommittedExchangeRecord as Exchange, Ikev2ReservationRetryPolicy as RetryPolicy,
        Ikev2SyncClock as Clock, Ikev2SyncDisposition as Disposition,
        Ikev2SyncRecoveryPolicy as Policy, Ikev2SyncRecoveryStatus as Status,
    },
    Ikev2EphemeralDhKey as Dh, Ikev2MessageIdSync as Notify, Ikev2MessageIdSyncMode as Mode,
    Ikev2MessageIdSyncPending as Pending,
};

fn round_trip(row: &Row) -> Row {
    let encoded = Codec::encode(row).unwrap();
    let decoded = Codec::decode(&encoded, row.key, row.version, row.sealed_stamp).unwrap();
    // Never include encoded secret fields in assertion diagnostics.
    assert!(Codec::encode(&decoded).unwrap().as_slice() == encoded.as_slice());
    decoded
}

#[test]
fn complete_row_codec_requires_every_field_for_all_profiles_roles_and_modes() {
    let mut cases = 0;
    for (index, profile) in inputs::profiles().enumerate() {
        for (role, direction) in crate::canonical_fixtures::DIRECTIONS
            .into_iter()
            .enumerate()
        {
            for (mode_id, mode) in [Mode::BaseFallback, Mode::Negotiated]
                .into_iter()
                .enumerate()
            {
                let tag = 100_000 + (index * 4 + role * 2 + mode_id) as u64;
                let row = inputs::fresh(tag, profile, direction, mode);
                round_trip(&row);
                let encoded = Codec::encode(&row).unwrap();
                for field in 1..=14 {
                    let omitted = Codec::without_field(&encoded, field);
                    assert!(
                        Codec::decode(&omitted, row.key, row.version, row.sealed_stamp).is_err()
                    );
                }
                for length in [0, 4, 5, encoded.len() - 1] {
                    assert!(Codec::decode(
                        &encoded[..length],
                        row.key,
                        row.version,
                        row.sealed_stamp
                    )
                    .is_err());
                }
                let mut invalid = encoded.clone();
                invalid.extend_from_slice(&[15, 0, 0, 0, 0]);
                assert!(Codec::decode(&invalid, row.key, row.version, row.sealed_stamp).is_err());
                let mut duplicate = encoded.clone();
                duplicate.extend_from_slice(&encoded[6..]);
                assert!(Codec::decode(&duplicate, row.key, row.version, row.sealed_stamp).is_err());
                assert!(
                    Codec::decode(&encoded, row.key, row.version.next(), row.sealed_stamp).is_err()
                );
                assert!(
                    Codec::decode(&encoded, row.key, row.version, row.sealed_stamp + 1).is_err()
                );
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 204);
}

#[test]
fn complete_row_codec_carries_pending_checkpoint_through_unrelated_row_updates() {
    for (index, profile) in inputs::profiles().enumerate() {
        let mut row = inputs::fresh(
            110_000 + index as u64,
            profile,
            crate::canonical_fixtures::DIRECTIONS[index % 2],
            Mode::BaseFallback,
        );
        let mut dh = Dh::generate(profile.dh_group()).unwrap();
        let checkpoint = dh.export_private_checkpoint().unwrap();
        let packet = Wire::new(profile, &row.keys, row.spis, row.direction).seal(
            0,
            false,
            36,
            crate::canonical_fixtures::delete(),
        );
        row.window.generation = 1;
        row.window.outbound = Some(Exchange::from_persisted(packet.clone(), None, None).unwrap());
        row.operations.insert(
            19,
            Operation {
                id: 19,
                kind: KeKind::ChildRekey,
                initiated_here: true,
                group: profile.dh_group(),
                public: dh.public_value().to_vec(),
                nonce_i: vec![0x41; 32],
                nonce_r: Vec::new(),
                spis: (71, 0),
                first_payload: 42,
                transcript: packet,
                checkpoint: Some(checkpoint),
                outcome: Outcome::Pending,
                derived: None,
            },
        );
        drop(dh);
        if let Some(iv) = &mut row.iv {
            iv.end = 64;
            for (operation, attempts) in [(19, 1), (29, 2)] {
                iv.retries.insert(
                    operation,
                    RetryImage {
                        operation,
                        policy: RetryPolicy::new(100, 1_000, 3, 10).unwrap(),
                        attempts,
                        last_attempt: Some(100 + u64::from(attempts) * 10),
                    },
                );
            }
        }
        row.endpoint = Some((0xc000_0201, 4500));
        let decoded = round_trip(&row);
        let candidate = decoded
            .next_write(8, |candidate| {
                candidate.endpoint = Some((0xc000_0202, 4500));
                candidate.window.next_receive = Some(17);
                if let Some(iv) = &mut candidate.iv {
                    iv.end += 64;
                }
            })
            .unwrap();
        let restored = round_trip(&candidate);
        let pending = restored.operations.get(&19).unwrap();
        let imported = Dh::import_private_checkpoint(
            pending.group,
            pending.checkpoint.as_ref().unwrap(),
            &pending.public,
        )
        .unwrap();
        assert!(imported.public_value() == pending.public);
        assert_eq!(restored.window.next_receive, Some(17));
        if let Some(iv) = restored.iv {
            assert_eq!(iv.end, 128);
            assert_eq!(iv.retries[&19].attempts, 1);
            assert_eq!(iv.retries[&29].attempts, 2);
        }
        let mut missing = candidate.clone();
        missing.operations.get_mut(&19).unwrap().checkpoint = None;
        assert!(Codec::encode(&missing).is_err());
        for outcome in [
            Outcome::Success,
            Outcome::CrossedLoss,
            Outcome::RetryBudget,
            Outcome::Abandoned,
            Outcome::Uncertain,
            Outcome::Teardown,
        ] {
            let mut terminal = candidate.clone();
            terminal.operations.get_mut(&19).unwrap().outcome = outcome;
            assert!(Codec::encode(&terminal).is_err());
        }
    }
}

#[test]
fn complete_row_codec_retains_the_original_sync_event_and_attempt_history() {
    for (index, profile) in inputs::profiles().enumerate() {
        let mut row = inputs::fresh(
            120_000 + index as u64,
            profile,
            crate::canonical_fixtures::DIRECTIONS[index % 2],
            Mode::Negotiated,
        );
        row.window.generation = 2;
        row.window.next_send = Some(9);
        row.window.next_receive = Some(11);
        let state = row.window.sync.as_mut().unwrap();
        state.local_proposal = Some(9);
        state.disposition = Disposition::AwaitLocalSync;
        row.window.recovery = Some(RecoveryImage {
            policy: Policy::new(313, Clock::new(100, 17), 1_000, 3, 10).unwrap(),
            observed: 150,
            attempts: [(7, 10, [1, 2, 3, 4], 100), (9, 11, [2, 3, 4, 5], 120)]
                .into_iter()
                .map(|(m, p, nonce, prepared)| AttemptImage {
                    pending: Pending::from_persisted(row.agreement.sa(), Notify::new(nonce, m, p))
                        .unwrap(),
                    prepared,
                    // This test checks data completeness only. The runtime's
                    // checked restore must also authenticate actual sync bytes.
                    request: Bytes::from_static(b"codec attempt data"),
                })
                .collect(),
            status: Status::Pending,
        });
        row.sync_intents[0] = Some(SyncIntent {
            policy: row.window.recovery.as_ref().unwrap().policy,
            observed: 150,
            pending: false,
        });
        row.sync_intents[1] = Some(SyncIntent {
            policy: Policy::new(314, Clock::new(120, 17), 900, 2, 11).unwrap(),
            observed: 160,
            pending: true,
        });
        let restored = round_trip(&row);
        assert!(
            restored.sync_intents[0].as_ref().unwrap().policy
                == row.sync_intents[0].as_ref().unwrap().policy
        );
        assert!(
            restored.sync_intents[1].as_ref().unwrap().policy
                == row.sync_intents[1].as_ref().unwrap().policy
        );
        assert_eq!(restored.sync_intents[1].as_ref().unwrap().observed, 160);
        assert!(restored.sync_intents[1].as_ref().unwrap().pending);
        let event = restored.window.recovery.unwrap();
        assert_eq!(event.policy.operation(), 313);
        assert_eq!(event.policy.started().epoch(), 17);
        assert_eq!(event.attempts.len(), 2);
        let mut omitted = row.clone();
        omitted.window.recovery = None;
        assert!(Codec::encode(&omitted).is_err());
    }
}
