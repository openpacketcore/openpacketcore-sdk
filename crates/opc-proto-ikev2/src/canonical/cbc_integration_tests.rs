#![allow(clippy::unwrap_used)]

use super::{
    cbc, Ikev2CanonicalEmptyReplies as Canonical, Ikev2CanonicalError as Error,
    Ikev2CanonicalPolicy as Policy,
};
use crate::recovery::{
    cbc_test_fixtures::*, Ikev2CommittedWindowRecord as Record,
    Ikev2EmptyReplyObservation as Observation, Ikev2WindowError as WindowError,
};
use crate::{PayloadChain, PayloadType};
use bytes::Bytes;

#[test]
fn cbc_canonical_window_matrix_has_exact_lengths_headers_and_zero_durable_writes() {
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            let f = Fixture::new(profile, direction, 51000 + (index * 2 + role) as u64);
            let record = Record::initial(f.domain.clone(), 1, 0);
            let mut window = f.restore(&record);
            window.enable_empty_replies(Policy::default()).unwrap();
            let (e, a) = if direction == DIRECTIONS[0] {
                (f.keys.sk_ei(), f.keys.sk_ai())
            } else {
                (f.keys.sk_er(), f.keys.sk_ar())
            };
            let reference = cbc::Recipe::new(cbc::Inputs {
                initiator_spi: f.epoch.initiator_spi(),
                responder_spi: f.epoch.responder_spi(),
                direction,
                profile,
                sk_d: f.keys.sk_d(),
                sk_e: e,
                sk_a: a,
            })
            .unwrap();
            let expected_len = match profile.integrity().unwrap().transform_id() {
                2 => 76,
                12 => 80,
                13 => 88,
                14 => 96,
                _ => unreachable!(),
            };
            for id in [0, 1, 0x8000_0000, u32::MAX] {
                let request = f.request(id, 0);
                let reply = window.reply_empty(&request).unwrap();
                assert_eq!(reply.observation(), Observation::Uncertain);
                let packet = reply.bytes().to_vec();
                assert_eq!(packet.len(), expected_len);
                assert_eq!(packet, reference.seal(id).unwrap().as_slice());
                drop(reply);
                let duplicate = window.reply_empty(&request).unwrap();
                assert_eq!(duplicate.observation(), Observation::Replayed);
                assert_eq!(duplicate.bytes(), packet);
                drop(duplicate);
                assert_eq!(window.next_receive(), id.checked_add(1));
                assert_eq!(
                    window.record(),
                    &record,
                    "stateless exchanges perform zero durable transitions"
                );
                assert_eq!(
                    window.reply_empty(&f.request(id, 0xa5)).unwrap_err(),
                    WindowError::Drop,
                    "same-ID changed peer bytes never replace the pending identity"
                );
            }
            window.delete();
        }
    }
}

#[test]
fn cbc_canonical_header_matches_the_committed_empty_acknowledgement_encoder() {
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            let f = Fixture::new(profile, direction, 52000 + (index * 2 + role) as u64);
            let mut window = f.window();
            let primitive = window.canonical_replies(Policy::default()).unwrap();
            let request = f.request(1, 0);
            let canonical = primitive.reply(&request).unwrap().bytes().to_vec();
            let wire = f.peer_wire(1, PayloadChain::new(PayloadType::Delete, DELETE), 0);
            let work = window.open_peer(profile, &f.keys, &wire).unwrap();
            let prepared = window
                .prepare_response(
                    profile,
                    &f.keys,
                    &work,
                    PayloadChain::new(PayloadType::NoNext, &[]),
                    Bytes::new(),
                )
                .unwrap();
            let record = prepared.record().clone();
            let ordinary = record.inbound().unwrap().response().unwrap();
            assert_eq!(&canonical[..32], &ordinary[..32]);
            let commit = prepared.commit_after_durable(&record).unwrap();
            assert_eq!(window.apply_committed(commit).unwrap(), Some(Bytes::new()));
            assert_eq!(
                f.restore(&record).replay_response(&work).unwrap().bytes(),
                ordinary
            );
            primitive.delete();
        }
    }
}

#[test]
fn cbc_canonical_padding_independence_release_history_and_epoch_deletion() {
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            let f = Fixture::new(profile, direction, 53000 + (index * 2 + role) as u64);
            let window = f.window();
            let capability = window.canonical_replies(Policy::default()).unwrap();
            assert_eq!(
                window.canonical_replies(Policy::default()).unwrap_err(),
                Error::CapabilityActive
            );
            let first = capability.reply(&f.request(7, 0)).unwrap().bytes().to_vec();
            for padding in [0, 0x55, 0xaa, 0xff] {
                assert_eq!(
                    capability.reply(&f.request(7, padding)).unwrap().bytes(),
                    first
                );
            }
            drop(capability);
            let replacement = window.canonical_replies(Policy::default()).unwrap();
            assert_eq!(
                replacement.reply(&f.request(7, 0)).unwrap_err(),
                Error::AlreadyReleased
            );
            replacement.reply(&f.request(8, 0)).unwrap();
            replacement.retire_through(9).unwrap();
            for id in [0, 7, 8, 9] {
                assert_eq!(
                    replacement.reply(&f.request(id, 0)).unwrap_err(),
                    Error::AlreadyReleased
                );
            }
            replacement.reply(&f.request(10, 0)).unwrap();
            replacement.delete();
            assert_eq!(
                window.canonical_replies(Policy::default()).unwrap_err(),
                Error::Invalidated
            );
        }
    }
}

#[test]
fn cbc_canonical_production_replies_reuse_cached_and_release_fresh_packets() {
    let profile = profiles().next().unwrap();
    for (role, direction) in DIRECTIONS.into_iter().enumerate() {
        let f = Fixture::new(profile, direction, 54000 + role as u64);
        let window = f.window();
        drop(Canonical::<Cbc>::from_epoch(&f.epoch, Policy::default()).unwrap());
        let capability = window.canonical_replies(Policy::default()).unwrap();
        for id in [1, 2] {
            let request = f.request(id, 0);
            let packet = capability.reply(&request).unwrap().bytes().to_vec();
            assert_eq!(packet.len(), 76);
            assert_eq!(&packet[20..24], &id.to_be_bytes());
            assert_eq!(
                capability.reply(&request).unwrap().bytes(),
                packet,
                "the production capability reuses identical cached bytes"
            );
        }
        capability.delete();
    }
}

#[test]
fn cbc_canonical_production_replies_work_across_threads() {
    let profile = profiles().next().unwrap();
    for (role, direction) in DIRECTIONS.into_iter().enumerate() {
        let f = Fixture::new(profile, direction, 1_600_000 + role as u64);
        let next = f.request(2, 0);
        let (mut window, request, packet) = std::thread::spawn(move || {
            let mut window = f.window();
            window.enable_empty_replies(Policy::default()).unwrap();
            let request = f.request(1, 0);
            let packet = window.reply_empty(&request).unwrap().bytes().to_vec();
            (window, request, packet)
        })
        .join()
        .unwrap();
        assert_eq!(window.reply_empty(&request).unwrap().bytes(), packet);
        let reply = window.reply_empty(&next).unwrap();
        assert_eq!(reply.bytes().len(), 76);
        assert_eq!(&reply.bytes()[20..24], &2u32.to_be_bytes());
        drop(reply);
        window.delete();
    }
}

#[test]
fn cbc_epoch_deletion_and_unknown_markers_revoke_the_same_traffic_key_ledger() {
    use crate::recovery::{
        Ikev2CbcEpochInputs, Ikev2CbcEpochRecord as Epoch, Ikev2CommittedWindowDomain as Domain,
    };
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            for (case, marker) in [None, Some(0), Some(2), Some(255)].into_iter().enumerate() {
                let f = Fixture::new(
                    profile,
                    direction,
                    55000 + (index * 8 + role * 4 + case) as u64,
                );
                let window = f.window();
                let capability = window.canonical_replies(Policy::default()).unwrap();
                capability.reply(&f.request(1, 0)).unwrap();
                let epoch = Epoch::from_persisted(
                    Ikev2CbcEpochInputs {
                        initiator_spi: f.epoch.initiator_spi(),
                        responder_spi: f.epoch.responder_spi(),
                        sending_direction: direction,
                        profile,
                        keys: &f.keys,
                    },
                    marker,
                )
                .unwrap();
                let domain = Domain::from_cbc_epoch(&epoch);
                let record = Record::initial(domain.clone(), 1, 1);
                let restored = crate::recovery::Ikev2CommittedWindow::restore(
                    &domain, profile, &f.keys, &record, &epoch,
                )
                .unwrap();
                assert_eq!(
                    restored.canonical_replies(Policy::default()).unwrap_err(),
                    Error::FormatUnavailable
                );
                assert_eq!(
                    capability.reply(&f.request(1, 0)).unwrap_err(),
                    Error::Invalidated
                );
            }
            for before in [false, true] {
                let f = Fixture::new(
                    profile,
                    direction,
                    56000 + (index * 4 + role * 2 + usize::from(before)) as u64,
                );
                let mut window = f.window();
                if !before {
                    window.enable_empty_replies(Policy::default()).unwrap();
                }
                Canonical::<Cbc>::delete_cbc_epoch(&f.epoch);
                assert_eq!(
                    window.enable_empty_replies(Policy::default()),
                    Err(WindowError::Canonical(Error::Invalidated))
                );
                window.delete();
            }
        }
    }
}

#[test]
fn cbc_same_sending_keys_cannot_acquire_a_changed_full_binding() {
    use crate::recovery::{
        Ikev2CbcEpochInputs, Ikev2CbcEpochRecord as Epoch, Ikev2CommittedWindow as Window,
        Ikev2CommittedWindowDomain as Domain,
    };
    use crate::{
        Ikev2DhGroup, Ikev2PrfAlgorithm as Prf, Ikev2SaInitCryptoProfile as Profile,
        Ikev2SaInitKeyMaterial as Keys,
    };
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            for change in 0..6 {
                let f = Fixture::new(
                    profile,
                    direction,
                    60000 + (index * 12 + role * 6 + change) as u64,
                );
                let window = f.window();
                let capability = window.canonical_replies(Policy::default()).unwrap();
                let request = f.request(1, 0);
                capability.reply(&request).unwrap();
                let mut keys = [
                    f.keys.sk_d().to_vec(),
                    f.keys.sk_ei().to_vec(),
                    f.keys.sk_er().to_vec(),
                    f.keys.sk_ai().to_vec(),
                    f.keys.sk_ar().to_vec(),
                ];
                let mut changed_profile = profile;
                match change {
                    0 => keys[0][8] ^= 0x80,
                    1 => {
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
                        keys[0].resize(prf.output_len(), 0x44);
                    }
                    2 => keys[if direction == DIRECTIONS[0] { 2 } else { 1 }][8] ^= 0x80,
                    3 => keys[if direction == DIRECTIONS[0] { 4 } else { 3 }][8] ^= 0x80,
                    4 => {}
                    _ => {
                        keys.swap(1, 2);
                        keys.swap(3, 4);
                    }
                }
                let keys = Keys::from_established_keys(
                    changed_profile,
                    false,
                    &keys[0],
                    &keys[3],
                    &keys[4],
                    &keys[1],
                    &keys[2],
                    &vec![0x66; changed_profile.prf().output_len()],
                    &vec![0x77; changed_profile.prf().output_len()],
                )
                .unwrap();
                // Model mixed trusted storage, not a new-key provenance claim.
                let epoch = Epoch::from_persisted(
                    Ikev2CbcEpochInputs {
                        initiator_spi: f.epoch.initiator_spi(),
                        responder_spi: if change == 4 {
                            0x303
                        } else {
                            f.epoch.responder_spi()
                        },
                        sending_direction: if change == 5 {
                            opposite(direction)
                        } else {
                            direction
                        },
                        profile: changed_profile,
                        keys: &keys,
                    },
                    Some(1),
                )
                .unwrap();
                assert_eq!(epoch.ledger_key(), f.epoch.ledger_key());
                assert_ne!(epoch.binding_fingerprint(), f.epoch.binding_fingerprint());
                let domain = Domain::from_cbc_epoch(&epoch);
                let record = Record::initial(domain.clone(), 1, 1);
                let changed =
                    Window::restore(&domain, changed_profile, &keys, &record, &epoch).unwrap();
                assert_eq!(
                    changed.canonical_replies(Policy::default()).unwrap_err(),
                    Error::BindingMismatch
                );
                assert_eq!(capability.reply(&request).unwrap_err(), Error::Invalidated);
                assert_eq!(
                    window.canonical_replies(Policy::default()).unwrap_err(),
                    Error::Invalidated
                );
            }
        }
    }
}
