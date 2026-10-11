#![allow(clippy::unwrap_used)]

use super::*;
use crate::recovery::{
    Ikev2CbcEpochInputs, Ikev2CbcEpochRecord as Epoch, Ikev2CommittedWindow as Window,
    Ikev2OrdinaryRequestDisposition as Disposition, Ikev2SyncClock as Clock, Ikev2SyncDisposition,
    Ikev2SyncInitiatorAction as Action, Ikev2SyncRecoveryPolicy,
};
use crate::{
    Ikev2DhGroup, Ikev2ExchangeKind as Exchange, Ikev2IntegrityAlgorithm as Integrity,
    Ikev2PrfAlgorithm as Prf, PayloadChain, PayloadType,
};
use bytes::Bytes;

use crate::recovery::cbc_test_fixtures::*;

#[test]
fn cbc_restore_and_readback_reject_every_immutable_epoch_change() {
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            for change in 0..10 {
                let tag = 48000 + (index * 20 + role * 10 + change) as u64;
                let f = Fixture::new(profile, direction, tag);
                let mut window = f.window();
                let prepared = window
                    .prepare_request(
                        profile,
                        &f.keys,
                        Exchange::Informational,
                        PayloadChain::new(PayloadType::Delete, DELETE),
                    )
                    .unwrap();
                let record = prepared.record().clone();
                drop(prepared);
                let mut values = [
                    f.keys.sk_d().to_vec(),
                    f.keys.sk_ei().to_vec(),
                    f.keys.sk_er().to_vec(),
                    f.keys.sk_ai().to_vec(),
                    f.keys.sk_ar().to_vec(),
                ];
                let mut changed_profile = profile;
                if change < 5 {
                    values[change][8] ^= 0x80;
                }
                if change == 5 {
                    let prf = if profile.prf() == Prf::HmacSha2_256 {
                        Prf::HmacSha2_512
                    } else {
                        Prf::HmacSha2_256
                    };
                    changed_profile = Profile::new_encrypt_then_mac(
                        prf,
                        Ikev2DhGroup::Modp2048,
                        profile.encryption(),
                        profile.integrity().unwrap(),
                    )
                    .unwrap();
                    values[0].resize(prf.output_len(), 0x77);
                }
                if change == 6 {
                    let integrity = if profile.integrity() == Some(Integrity::HmacSha2_256_128) {
                        Integrity::HmacSha2_512_256
                    } else {
                        Integrity::HmacSha2_256_128
                    };
                    changed_profile = Profile::new_encrypt_then_mac(
                        profile.prf(),
                        Ikev2DhGroup::Modp2048,
                        profile.encryption(),
                        integrity,
                    )
                    .unwrap();
                    values[3].resize(integrity.key_len(), 0x22);
                    values[4].resize(integrity.key_len(), 0x33);
                }
                let keys = Keys::from_established_keys(
                    changed_profile,
                    false,
                    &values[0],
                    &values[3],
                    &values[4],
                    &values[1],
                    &values[2],
                    &vec![6; changed_profile.prf().output_len()],
                    &vec![7; changed_profile.prf().output_len()],
                )
                .unwrap();
                let epoch = Epoch::from_persisted(
                    Ikev2CbcEpochInputs {
                        initiator_spi: if change == 7 {
                            0x303
                        } else {
                            f.epoch.initiator_spi()
                        },
                        responder_spi: f.epoch.responder_spi(),
                        sending_direction: if change == 8 {
                            opposite(direction)
                        } else {
                            direction
                        },
                        profile: changed_profile,
                        keys: &keys,
                    },
                    if change == 9 { None } else { Some(1) },
                )
                .unwrap();
                let receive_e = if direction == DIRECTIONS[0] { 2 } else { 1 };
                let receive_a = if direction == DIRECTIONS[0] { 4 } else { 3 };
                if change == 0 || change == 5 || change == receive_e || change == receive_a {
                    // SK_d, PRF and receive-side drift can leave a locally sent
                    // cached packet authentic: the complete descriptor is essential.
                    assert!(crate::recovery::packet::open(
                        &Domain::from_cbc_epoch(&epoch),
                        changed_profile,
                        &keys,
                        record.outbound().unwrap().request(),
                        false
                    )
                    .is_ok());
                }
                assert_eq!(
                    Window::<Cbc>::restore(&f.domain, changed_profile, &keys, &record, &epoch)
                        .unwrap_err(),
                    Error::DomainMismatch
                );
                assert_eq!(
                    window.reconcile(changed_profile, &keys, &record, &epoch),
                    Err(Error::DomainMismatch)
                );
                assert!(window.reconcile_terminal);
                assert!(window.witness.is_none());
                assert_eq!(
                    window.reconcile(profile, &f.keys, &record, &f.epoch),
                    Err(Error::Canonical(CanonicalError::Invalidated))
                );
            }
        }
    }
}

#[test]
fn cbc_ordinary_roundtrip_replay_and_restore_all_profiles_both_directions() {
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            let tag = 40000 + (index * 2 + role) as u64;
            let a = Fixture::new(profile, direction, tag);
            let b = Fixture::new(profile, opposite(direction), tag);
            let mut sender = a.window();
            let mut receiver = b.window();
            let prepared = sender
                .prepare_request(
                    profile,
                    &a.keys,
                    Exchange::Informational,
                    PayloadChain::new(PayloadType::Delete, DELETE),
                )
                .unwrap();
            let stored = prepared.record().clone();
            let commit = prepared.commit_after_durable(&stored).unwrap();
            assert_eq!(sender.apply_committed(commit).unwrap(), None);
            let request = sender.replay_request().unwrap().unwrap().bytes().to_vec();
            assert_eq!(
                a.restore(&stored)
                    .replay_request()
                    .unwrap()
                    .unwrap()
                    .bytes(),
                request
            );
            let opened = receiver.open_peer(profile, &b.keys, &request).unwrap();
            assert_eq!(
                receiver.request_disposition(&opened).unwrap(),
                Disposition::New
            );
            let prepared = receiver
                .prepare_response(
                    profile,
                    &b.keys,
                    &opened,
                    PayloadChain::new(PayloadType::NoNext, &[]),
                    Bytes::from_static(b"result"),
                )
                .unwrap();
            let received = prepared.record().clone();
            let commit = prepared.commit_after_durable(&received).unwrap();
            assert_eq!(
                receiver.apply_committed(commit).unwrap(),
                Some(Bytes::from_static(b"result"))
            );
            let response = receiver.replay_response(&opened).unwrap().bytes().to_vec();
            assert_eq!(
                b.restore(&received)
                    .replay_response(&opened)
                    .unwrap()
                    .bytes(),
                response
            );
            let opened_response = sender.open_peer(profile, &a.keys, &response).unwrap();
            let prepared = sender
                .prepare_completion(&opened_response, Bytes::from_static(b"done"))
                .unwrap();
            let completed = prepared.record().clone();
            let commit = prepared.commit_after_durable(&completed).unwrap();
            assert_eq!(
                sender.apply_committed(commit).unwrap(),
                Some(Bytes::from_static(b"done"))
            );
            assert!(sender.replay_request().unwrap().is_none());
            assert!(a.restore(&completed).replay_request().unwrap().is_none());
            assert_eq!(
                sender
                    .prepare_completion(&opened_response, Bytes::new())
                    .unwrap_err(),
                Error::Drop
            );
        }
    }
}

#[test]
fn cbc_ordinary_uncertainty_accepts_only_exact_candidate_or_acknowledged_record() {
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            for landed in [false, true] {
                let f = Fixture::new(
                    profile,
                    direction,
                    41000 + (index * 4 + role * 2 + usize::from(landed)) as u64,
                );
                let mut window = f.window();
                let old = window.record().clone();
                let prepared = window
                    .prepare_request(
                        profile,
                        &f.keys,
                        Exchange::Informational,
                        PayloadChain::new(PayloadType::Delete, DELETE),
                    )
                    .unwrap();
                let candidate = prepared.record().clone();
                drop(prepared);
                assert_eq!(window.ready(), Err(Error::CommitUncertain));
                let readback = if landed { &candidate } else { &old };
                window
                    .reconcile(profile, &f.keys, readback, &f.epoch)
                    .unwrap();
                assert_eq!(window.record(), readback);
                assert_eq!(window.ready(), Ok(()));
                assert_eq!(window.replay_request().unwrap().is_some(), landed);
                let mut unwitnessed = readback.clone();
                unwitnessed.generation += 1;
                assert_eq!(
                    window.reconcile(profile, &f.keys, &unwitnessed, &f.epoch),
                    Err(Error::InvalidRecord)
                );
                assert_eq!(window.ready(), Err(Error::CommitUncertain));
            }
        }
    }
}

#[test]
fn cbc_canonical_production_enables_checked_fresh_and_restored_windows() {
    use crate::canonical::Ikev2CanonicalPolicy as Policy;
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            for (policy_index, policy) in [
                Policy::default(),
                Policy::explicitly_allow_declared_validated(),
            ]
            .into_iter()
            .enumerate()
            {
                let tag = 42000 + (index * 4 + role * 2 + policy_index) as u64;
                let f = Fixture::new(profile, direction, tag);
                let mut window = f.window();
                let record = window.record().clone();
                drop(window.canonical_replies(policy).unwrap());
                window.enable_empty_replies(policy).unwrap();
                let request = f.request(1, 0);
                let packet = window.reply_empty(&request).unwrap().bytes().to_vec();
                window
                    .reconcile(profile, &f.keys, &record, &f.epoch)
                    .unwrap();
                assert_eq!(window.reply_empty(&request).unwrap().bytes(), packet);
                assert_eq!(window.record(), &record);
                drop(window);
                let mut restored = f.restore(&record);
                restored.enable_empty_replies(policy).unwrap();
                assert_eq!(restored.ready(), Ok(()));
                let reply = restored.reply_empty(&f.request(2, 0)).unwrap();
                assert_eq!(&reply.bytes()[20..24], &2u32.to_be_bytes());
                drop(reply);
                assert_eq!(restored.record(), &record);
                restored.delete();
            }
        }
    }
}

#[test]
fn cbc_sync_both_directions_complete_and_restore_without_iv_floor() {
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            let tag = 43000 + (index * 2 + role) as u64;
            let a = Fixture::new(profile, direction, tag);
            let b = Fixture::new(profile, opposite(direction), tag);
            let mut sender = a.synced();
            let mut receiver = b.synced();
            let clock = Clock::new(100, 1);
            let policy = Ikev2SyncRecoveryPolicy::new(1, clock, 1000, 3, 10).unwrap();
            let prepared = sender
                .begin_sync(policy, clock, None)
                .unwrap()
                .prepare(profile, &a.keys)
                .unwrap();
            let stored = prepared.record().clone();
            let commit = prepared.commit_after_durable(&stored, clock).unwrap();
            let Action::SendRequest(request) = sender.release_sync_action(commit, clock).unwrap()
            else {
                panic!("request");
            };
            assert_eq!(a.restore(&stored).ready(), Err(Error::SyncInProgress));
            let prepared = receiver
                .begin_sync_response(profile, &b.keys, &request, None, None)
                .unwrap()
                .prepare(profile, &b.keys)
                .unwrap();
            let received = prepared.record().clone();
            let commit = prepared.commit_after_durable(&received).unwrap();
            let (response, disposition) =
                receiver.release_sync_response(commit).unwrap().into_parts();
            assert_eq!(disposition, Ikev2SyncDisposition::Continue);
            assert_eq!(b.restore(&received).ready(), Ok(()));
            assert_eq!(
                receiver
                    .begin_sync_response(profile, &b.keys, &request, None, None)
                    .unwrap_err(),
                Error::Drop
            );
            let prepared = sender
                .complete_sync(profile, &a.keys, &response, clock)
                .unwrap();
            let completed = prepared.record().clone();
            let commit = prepared.commit_after_durable(&completed, clock).unwrap();
            assert!(matches!(
                sender.release_sync_action(commit, clock).unwrap(),
                Action::Recovered
            ));
            assert_eq!(a.restore(&completed).ready(), Ok(()));
        }
    }
}
