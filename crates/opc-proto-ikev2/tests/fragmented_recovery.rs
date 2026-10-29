//! RFC 7383 recovery: complete authenticated messages and exact packet replay.

use bytes::Bytes;
use opc_proto_ikev2::recovery::{
    Ikev2CommittedExchangeRecord as ExchangeRecord, Ikev2ProtectedMessage as Message,
    Ikev2WindowError as Error,
};

#[test]
fn packet_collections_preserve_boundaries_and_never_return_only_the_first_fragment() {
    let packets = vec![Bytes::from_static(b"first"), Bytes::from_static(b"second")];
    let message = Message::from_persisted(packets.clone()).unwrap();
    assert_eq!(message.packets(), packets);
    assert_eq!(message.single_packet(), Err(Error::UnsupportedShape));
    let record = ExchangeRecord::from_persisted_messages(message, None, None).unwrap();
    assert_eq!(record.request().packets(), packets);
    assert!(record.response().is_none());
    assert!(record.outcome().is_none());
    let single = Message::from_persisted(vec![packets[0].clone()]).unwrap();
    assert_eq!(single.single_packet(), Ok(b"first".as_slice()));
    assert_eq!(
        ExchangeRecord::from_persisted_messages(single.clone(), Some(single), None),
        Err(Error::InvalidRecord)
    );
}

#[test]
fn persisted_packet_collections_are_bounded_before_authentication() {
    for packets in [
        vec![],
        vec![Bytes::new()],
        vec![Bytes::from_static(b"fragment"); 257],
        vec![Bytes::from(vec![0; 98_305])],
    ] {
        assert_eq!(Message::from_persisted(packets), Err(Error::InvalidRecord));
    }
    assert!(Message::from_persisted(vec![Bytes::from(vec![0; 384]); 256]).is_ok());
}

#[path = "support/canonical.rs"]
mod canonical_fixtures;
#[path = "support/fragmentation.rs"]
mod fragmentation_fixtures;
mod support;
use fragmentation_fixtures::{large_delete, offers};
#[path = "recovery_profile/wire.rs"]
mod wire;

use canonical_fixtures::{empty, opposite, Fixture, ALGORITHMS, DELETE, DIRECTIONS};
use opc_proto_ikev2::{
    recovery::{Ikev2FragmentReceive as Receive, Ikev2OrdinaryRequestDisposition as Disposition},
    Ikev2AesGcmIvPurpose as Purpose, PayloadChain, PayloadType,
};
use std::num::NonZeroU32;

fn enable(f: &mut Fixture) {
    let request = offers(f.spis, false, true);
    let response = offers(f.spis, true, true);
    let prepared = f
        .window
        .prepare_fragmentation(
            f.profile,
            &f.keys,
            &request,
            &response,
            NonZeroU32::new(50).unwrap(),
        )
        .unwrap();
    let record = prepared.record().clone();
    let token = prepared.commit_after_durable(&record).unwrap();
    assert_eq!(f.window.apply_committed(token), Ok(None));
    assert_eq!(
        f.window
            .record()
            .fragmentation()
            .unwrap()
            .reassembly_timeout_ms()
            .get(),
        50
    );
}

#[test]
fn fragmentation_offers_ignore_empty_spi_protocol_id_in_both_original_roles() {
    support::ensure_ike_crypto();
    let mut cases = 0;
    for (role, direction) in DIRECTIONS.into_iter().enumerate() {
        for (index, protocol) in [1, 2, 3, 255].into_iter().enumerate() {
            let mut f = Fixture::new(124400 + (role * 4 + index) as u64, ALGORITHMS[0], direction);
            let mut request = offers(f.spis, false, true);
            let mut response = offers(f.spis, true, true);
            // RFC 7296 section 3.10: the sender emits zero; the receiver ignores it.
            assert_eq!(request[32], 0);
            assert_eq!(response[32], 0);
            if role == 0 {
                response[32] = protocol;
            } else {
                request[32] = protocol;
            }
            let prepared = f
                .window
                .prepare_fragmentation(
                    f.profile,
                    &f.keys,
                    &request,
                    &response,
                    NonZeroU32::new(50).unwrap(),
                )
                .unwrap();
            let record = prepared.record().clone();
            let _commit = prepared.commit_after_durable(&record).unwrap();
            assert!(f.window.record().fragmentation().is_some());
            cases += 1;
        }
    }
    assert_eq!(cases, 8);
}

#[test]
fn cached_empty_fragment_replay_requires_one_empty_identical_packet() {
    use opc_proto_ikev2::canonical::Ikev2CanonicalPolicy;
    support::ensure_ike_crypto();
    for (role, direction) in DIRECTIONS.into_iter().enumerate() {
        for fragmented in [false, true] {
            let mut f = Fixture::new(
                124420 + (role * 2 + usize::from(fragmented)) as u64,
                ALGORITHMS[0],
                direction,
            );
            enable(&mut f);
            f.window
                .enable_empty_replies(Ikev2CanonicalPolicy::default())
                .unwrap();
            let keys = f.keys.clone();
            let peer = wire::Wire::new(f.profile, &keys, f.spis, opposite(direction));
            let original = if fragmented {
                peer.seal_fragment(0, false, 37, (1, 1), empty())
            } else {
                peer.seal(0, false, 37, empty())
            };
            let Receive::Message(request) = receive(&mut f, &original, 0).unwrap() else {
                panic!("complete empty request");
            };
            let response = f.window.reply_empty(&request).unwrap().bytes().to_vec();
            for changed in [
                peer.seal_fragment(0, false, 37, (1, 2), empty()),
                peer.seal_fragment(
                    0,
                    false,
                    37,
                    (1, 1),
                    PayloadChain::new(PayloadType::Delete, DELETE),
                ),
                peer.seal_fragment(
                    0,
                    false,
                    37,
                    (1, 1),
                    PayloadChain::new(PayloadType::Delete, &[]),
                ),
                peer.seal_fragment(0, false, 37, (1, 1), empty()),
                peer.seal_fragment(0, false, 37, (2, 2), empty()),
            ] {
                assert_ne!(changed, original);
                assert!(matches!(receive(&mut f, &changed, 1), Err(Error::Drop)));
                assert_eq!(f.window.next_receive(), Some(1));
            }
            let Receive::Message(repeated) = receive(&mut f, &original, 2).unwrap() else {
                panic!("exact original request replays");
            };
            assert_eq!(f.window.reply_empty(&repeated).unwrap().bytes(), response);
        }
    }
}

#[test]
fn cached_two_fragment_empty_request_drops_single_fragment_replay() {
    use opc_proto_ikev2::canonical::Ikev2CanonicalPolicy;
    support::ensure_ike_crypto();
    for (role, direction) in DIRECTIONS.into_iter().enumerate() {
        let mut f = Fixture::new(124430 + role as u64, ALGORITHMS[0], direction);
        enable(&mut f);
        f.window
            .enable_empty_replies(Ikev2CanonicalPolicy::default())
            .unwrap();
        let keys = f.keys.clone();
        let peer = wire::Wire::new(f.profile, &keys, f.spis, opposite(direction));
        let first = peer.seal_fragment(0, false, 37, (1, 2), empty());
        let second = peer.seal_fragment(0, false, 37, (2, 2), empty());
        assert!(matches!(
            receive(&mut f, &first, 0),
            Ok(Receive::Incomplete)
        ));
        let Receive::Message(request) = receive(&mut f, &second, 1).unwrap() else {
            panic!("complete two-fragment empty request");
        };
        f.window.reply_empty(&request).unwrap();
        let changed = peer.seal_fragment(0, false, 37, (1, 1), empty());
        let result = receive(&mut f, &changed, 2);
        assert!(matches!(result, Err(Error::Drop)), "{result:?}");
        assert_eq!(f.window.next_receive(), Some(1));
    }
}

fn receive<'a>(f: &'a mut Fixture, packet: &[u8], now: u64) -> Result<Receive<'a>, Error> {
    f.window
        .receive_peer_packet(f.profile, &f.keys, packet, now)
}

fn fragments(peer: &wire::Wire<'_>, count: usize, id: u32) -> Vec<Bytes> {
    let width = DELETE.len().div_ceil(count);
    let total = u16::try_from(DELETE.chunks(width).len()).unwrap();
    DELETE
        .chunks(width)
        .enumerate()
        .map(|(index, part)| {
            peer.seal_fragment(
                id,
                false,
                37,
                (u16::try_from(index + 1).unwrap(), total),
                PayloadChain::new(
                    if index == 0 {
                        PayloadType::Delete
                    } else {
                        PayloadType::NoNext
                    },
                    part,
                ),
            )
        })
        .collect()
}

#[test]
fn authenticated_fragments_require_bilateral_negotiation_and_preserve_exact_errors() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(124201, ALGORITHMS[0], DIRECTIONS[0]);
    let peer = wire::Wire::new(f.profile, &f.keys, f.spis, opposite(f.direction));
    let parts = fragments(&peer, 2, 0);
    let mut bad = parts[0].to_vec();
    *bad.last_mut().unwrap() ^= 1;
    assert!(matches!(receive(&mut f, &bad, 0), Err(Error::Drop)));
    assert!(matches!(
        receive(&mut f, &parts[0], 0),
        Err(Error::FragmentationNotNegotiated)
    ));
    let request = offers(f.spis, false, true);
    let response = offers(f.spis, true, false);
    assert!(matches!(
        f.window.prepare_fragmentation(
            f.profile,
            &f.keys,
            &request,
            &response,
            NonZeroU32::new(50).unwrap()
        ),
        Err(Error::FragmentationNotNegotiated)
    ));
    assert_eq!(f.window.record().generation(), 0);
    enable(&mut f);
    assert!(matches!(
        receive(&mut f, &parts[0], 10),
        Ok(Receive::Incomplete)
    ));
}

#[test]
fn reassembly_authenticates_all_parts_before_any_ordinary_admission() {
    support::ensure_ike_crypto();
    for (index, direction) in DIRECTIONS.into_iter().enumerate() {
        let mut f = Fixture::new(124210 + index as u64, ALGORITHMS[0], direction);
        enable(&mut f);
        let peer = wire::Wire::new(f.profile, &f.keys, f.spis, opposite(direction));
        let parts = fragments(&peer, 3, 0);
        assert_eq!(parts.len(), 3);
        assert!(matches!(
            receive(&mut f, &parts[2], 100),
            Ok(Receive::Incomplete)
        ));
        assert_eq!(f.window.fragment_deadline_ms(), Some(150));
        assert!(matches!(receive(&mut f, &parts[2], 110), Err(Error::Drop)));
        let mut forged = parts[0].to_vec();
        *forged.last_mut().unwrap() ^= 1;
        assert!(matches!(receive(&mut f, &forged, 115), Err(Error::Drop)));
        assert!(matches!(
            receive(&mut f, &parts[0], 120),
            Ok(Receive::Incomplete)
        ));
        assert_eq!(f.window.record().next_receive(), Some(0));
        let opened = match receive(&mut f, &parts[1], 125).unwrap() {
            Receive::Message(opened) => opened,
            _ => panic!("expected the complete message"),
        };
        assert_eq!(opened.payloads().first_payload(), PayloadType::Delete);
        assert_eq!(opened.payloads().bytes(), DELETE);
        assert_eq!(f.window.fragment_deadline_ms(), None);
        assert_eq!(f.window.request_disposition(&opened), Ok(Disposition::New));
        assert_eq!(f.window.record().next_receive(), Some(0));
    }
}

#[test]
fn complete_sk_wins_over_an_incomplete_set_and_only_fragment_one_replays_the_result() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(124220, ALGORITHMS[0], DIRECTIONS[0]);
    enable(&mut f);
    let keys = f.keys.clone();
    let peer = wire::Wire::new(f.profile, &keys, f.spis, opposite(f.direction));
    let parts = fragments(&peer, 2, 0);
    assert!(matches!(
        receive(&mut f, &parts[0], 10),
        Ok(Receive::Incomplete)
    ));
    let sk = peer.seal(0, false, 37, PayloadChain::new(PayloadType::Delete, DELETE));
    let opened = match receive(&mut f, &sk, 11).unwrap() {
        Receive::Message(opened) => opened,
        _ => panic!("complete SK"),
    };
    assert_eq!(f.window.fragment_deadline_ms(), None);
    let prepared = f
        .window
        .prepare_response(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
            &opened,
            empty(),
            Bytes::from_static(b"deleted"),
        )
        .unwrap();
    let record = prepared.record().clone();
    let token = prepared.commit_after_durable(&record).unwrap();
    assert_eq!(
        f.window.apply_committed(token).unwrap().as_deref(),
        Some(b"deleted".as_slice())
    );
    assert!(matches!(receive(&mut f, &parts[1], 12), Err(Error::Drop)));
    let replay = match receive(&mut f, &parts[0], 13).unwrap() {
        Receive::Retransmit(replay) => replay,
        _ => panic!("fragment one must replay"),
    };
    assert_eq!(
        replay.packets(),
        record.inbound().unwrap().response().unwrap().packets()
    );
    let opened = peer.open(replay.bytes().unwrap()).unwrap();
    assert_eq!(opened.header.message_id, 0);
    assert_eq!(opened.first, PayloadType::NoNext);
    assert!(opened.body.is_empty());
    assert_eq!(opened.wire.as_ref(), replay.bytes().unwrap());
}

#[test]
fn fragmented_requests_replay_every_packet_after_restore_and_cover_every_iv() {
    use opc_proto_ikev2::{
        recovery::{Ikev2CommittedWindow as Window, Ikev2FragmentationSize as Size},
        Ikev2ExchangeKind as Exchange,
    };
    support::ensure_ike_crypto();
    for (index, direction) in DIRECTIONS.into_iter().enumerate() {
        let mut f = Fixture::new(124230 + index as u64, ALGORITHMS[0], direction);
        enable(&mut f);
        let payload = large_delete();
        let size = Size::ipv4(None, true).unwrap();
        assert_eq!(size.max_ike_packet_bytes(), 544);
        let prepared = f
            .window
            .prepare_fragmented_request(
                f.profile,
                &f.keys,
                &mut f.allocator,
                Purpose::Ordinary,
                Exchange::Informational,
                PayloadChain::new(PayloadType::Delete, &payload),
                size,
            )
            .unwrap();
        let record = prepared.record().clone();
        let token = prepared.commit_after_durable(&record).unwrap();
        assert_eq!(f.window.apply_committed(token), Ok(None));
        let sent: Vec<_> = f
            .window
            .replay_request()
            .unwrap()
            .unwrap()
            .packets()
            .to_vec();
        assert_eq!(sent.len(), 3);
        let peer = wire::Wire::new(f.profile, &f.keys, f.spis, opposite(direction));
        assert_eq!(
            peer.open_message(record.outbound().unwrap().request())
                .unwrap()
                .body
                .as_ref(),
            payload
        );
        let mut assembled = Vec::new();
        for (index, packet) in sent.iter().enumerate() {
            assert!(packet.len() <= 544);
            let (number, total, opened) = peer.open_fragment(packet).unwrap();
            assert_eq!((number, total), (u16::try_from(index + 1).unwrap(), 3));
            assert_eq!(opened.header.message_id, 0);
            assert_eq!(
                opened.first,
                if index == 0 {
                    PayloadType::Delete
                } else {
                    PayloadType::NoNext
                }
            );
            assembled.extend_from_slice(&opened.body);
            assert_eq!(
                u64::from_be_bytes(packet[36..44].try_into().unwrap()),
                index as u64
            );
        }
        assert_eq!(assembled, payload);
        let domain = record.domain().clone();
        drop(f.window);
        drop(f.allocator);
        let restored = Window::restore(&domain, f.profile, &f.keys, &record, &f.iv).unwrap();
        assert_eq!(restored.replay_request().unwrap().unwrap().packets(), sent);
        assert_eq!(
            restored.replay_request().unwrap().unwrap().bytes(),
            Err(Error::UnsupportedShape)
        );
    }
}

#[test]
fn newer_fragment_sets_replace_only_after_authentication_without_extending_the_deadline() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(124240, ALGORITHMS[0], DIRECTIONS[0]);
    enable(&mut f);
    let peer = wire::Wire::new(f.profile, &f.keys, f.spis, opposite(f.direction));
    let old = fragments(&peer, 2, 0);
    let new = fragments(&peer, 3, 0);
    assert!(matches!(
        receive(&mut f, &old[0], 0),
        Ok(Receive::Incomplete)
    ));
    let mut forged = new[2].to_vec();
    *forged.last_mut().unwrap() ^= 1;
    assert!(matches!(receive(&mut f, &forged, 10), Err(Error::Drop)));
    assert_eq!(f.window.fragment_deadline_ms(), Some(50));
    assert!(matches!(
        receive(&mut f, &new[2], 15),
        Ok(Receive::Incomplete)
    ));
    assert!(matches!(receive(&mut f, &old[1], 20), Err(Error::Drop)));
    assert!(matches!(
        receive(&mut f, &new[0], 25),
        Ok(Receive::Incomplete)
    ));
    assert_eq!(f.window.fragment_deadline_ms(), Some(50));
    f.window.expire_fragments(50).unwrap();
    assert_eq!(f.window.fragment_deadline_ms(), None);
    assert!(matches!(
        receive(&mut f, &new[1], 51),
        Ok(Receive::Incomplete)
    ));
    assert!(matches!(
        receive(&mut f, &new[2], 52),
        Ok(Receive::Incomplete)
    ));
    let opened = match receive(&mut f, &new[0], 53).unwrap() {
        Receive::Message(opened) => opened,
        _ => panic!("new complete set"),
    };
    assert_eq!(opened.payloads().bytes(), DELETE);
}

#[test]
fn authenticated_fragment_resource_exhaustion_closes_the_window() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(124241, ALGORITHMS[0], DIRECTIONS[0]);
    enable(&mut f);
    let peer = wire::Wire::new(f.profile, &f.keys, f.spis, opposite(f.direction));
    let packet = peer.seal_fragment(
        0,
        false,
        37,
        (1, 257),
        PayloadChain::new(PayloadType::Delete, &DELETE[..1]),
    );
    assert!(matches!(
        receive(&mut f, &packet, 0),
        Err(Error::FragmentationLimit)
    ));
    assert_eq!(f.window.ready(), Err(Error::FragmentationLimit));
    assert_eq!(f.window.fragment_deadline_ms(), None);
    assert_eq!(
        f.window.expire_fragments(100),
        Err(Error::FragmentationLimit)
    );
}

#[test]
fn partial_sealing_failure_burns_ivs_and_rejects_readback_below_the_last_sealed_fragment() {
    use opc_proto_ikev2::{
        recovery::Ikev2FragmentationSize as Size, Ikev2AesGcmIvReservationError as IvError,
        Ikev2ExchangeKind as Exchange,
    };
    support::ensure_ike_crypto();
    let mut f = Fixture::new(124260, ALGORITHMS[0], DIRECTIONS[0]);
    enable(&mut f);
    for _ in 0..64 {
        drop(f.allocator.allocate(Purpose::Ordinary).unwrap());
    }
    let block = f.allocator.prepare(2, Purpose::Ordinary).unwrap();
    let iv = block.record().clone();
    block.activate_after_commit(&iv).unwrap();
    let before = f.window.record().clone();
    let cleartext = large_delete();
    assert!(matches!(
        f.window.prepare_fragmented_request(
            f.profile,
            &f.keys,
            &mut f.allocator,
            Purpose::Ordinary,
            Exchange::Informational,
            PayloadChain::new(PayloadType::Delete, &cleartext),
            Size::ipv4(None, true).unwrap()
        ),
        Err(Error::Iv(IvError::ReservationRequired))
    ));
    assert_eq!(f.window.record(), &before);
    assert!(f.window.replay_request().unwrap().is_none());
    assert!(matches!(
        f.allocator.allocate(Purpose::Ordinary),
        Err(IvError::ReservationRequired)
    ));
    // The old row covers none of the two newly sealed packets, even though no prepared window escaped.
    assert_eq!(
        f.window.reconcile(f.profile, &f.keys, &before, &f.iv),
        Err(Error::InvalidRecord)
    );
    assert!(f.window.ready().is_err());
}

#[test]
fn restore_rejects_missing_reordered_corrupt_unnegotiated_and_uncovered_fragment_sets() {
    use opc_proto_ikev2::{
        recovery::{
            Ikev2CommittedWindow as Window, Ikev2CommittedWindowRecord as Record,
            Ikev2FragmentationSize as Size,
        },
        Ikev2AesGcmEpochInputs as Inputs, Ikev2AesGcmIvRecord as IvRecord,
        Ikev2ExchangeKind as Exchange,
    };
    support::ensure_ike_crypto();
    for mutation in 0..6 {
        let mut f = Fixture::new(124270 + mutation, ALGORITHMS[0], DIRECTIONS[0]);
        enable(&mut f);
        let cleartext = large_delete();
        let prepared = f
            .window
            .prepare_fragmented_request(
                f.profile,
                &f.keys,
                &mut f.allocator,
                Purpose::Ordinary,
                Exchange::Informational,
                PayloadChain::new(PayloadType::Delete, &cleartext),
                Size::ipv4(None, true).unwrap(),
            )
            .unwrap();
        let original = prepared.record().clone();
        drop(prepared);
        let mut packets = original.outbound().unwrap().request().packets().to_vec();
        match mutation {
            0 => {
                packets.pop();
            }
            1 => {
                packets.swap(0, 1);
            }
            2 => {
                packets[1] = packets[0].clone();
            }
            3 => {
                let mut wire = packets[1].to_vec();
                *wire.last_mut().unwrap() ^= 1;
                packets[1] = wire.into();
            }
            _ => {}
        }
        let record = Record::from_persisted(
            original.domain().clone(),
            original.generation(),
            original.next_send(),
            original.next_receive(),
            Some(
                ExchangeRecord::from_persisted_messages(
                    Message::from_persisted(packets).unwrap(),
                    None,
                    None,
                )
                .unwrap(),
            ),
            None,
            None,
            if mutation == 4 {
                None
            } else {
                original.fragmentation()
            },
        )
        .unwrap();
        let iv = if mutation == 5 {
            IvRecord::from_persisted(
                Inputs {
                    initiator_spi: f.spis.0,
                    responder_spi: f.spis.1,
                    sending_direction: f.direction,
                    profile: f.profile,
                    keys: &f.keys,
                },
                f.iv.limits(),
                2,
                f.iv.canonical_format(),
            )
            .unwrap()
        } else {
            f.iv.clone()
        };
        drop(f.window);
        drop(f.allocator);
        assert!(matches!(
            Window::restore(record.domain(), f.profile, &f.keys, &record, &iv),
            Err(Error::InvalidRecord)
        ));
    }
}

#[test]
fn aggregate_limits_clock_regression_and_deadline_overflow_have_exact_outcomes() {
    support::ensure_ike_crypto();
    for mutation in 0..3 {
        let mut f = Fixture::new(124280 + mutation, ALGORITHMS[0], DIRECTIONS[0]);
        enable(&mut f);
        let keys = f.keys.clone();
        let peer = wire::Wire::new(f.profile, &keys, f.spis, opposite(f.direction));
        if mutation == 0 {
            let body = vec![0; 40_000];
            for number in 1..=2 {
                let part = peer.seal_fragment(
                    0,
                    false,
                    35,
                    (number, 2),
                    PayloadChain::new(
                        if number == 1 {
                            PayloadType::Certificate
                        } else {
                            PayloadType::NoNext
                        },
                        &body,
                    ),
                );
                if number == 1 {
                    assert!(matches!(receive(&mut f, &part, 0), Ok(Receive::Incomplete)));
                } else {
                    assert!(matches!(
                        receive(&mut f, &part, 1),
                        Err(Error::FragmentationLimit)
                    ));
                }
            }
            assert_eq!(f.window.ready(), Err(Error::FragmentationLimit));
            assert_eq!(f.window.fragment_deadline_ms(), None);
        } else {
            let parts = fragments(&peer, 2, 0);
            if mutation == 1 {
                assert!(matches!(
                    receive(&mut f, &parts[0], 20),
                    Ok(Receive::Incomplete)
                ));
                assert!(matches!(receive(&mut f, &parts[1], 19), Err(Error::Drop)));
                assert_eq!(f.window.fragment_deadline_ms(), Some(70));
                assert!(matches!(
                    receive(&mut f, &parts[1], 21),
                    Ok(Receive::Message(_))
                ));
            } else {
                assert!(matches!(
                    receive(&mut f, &parts[0], u64::MAX - 49),
                    Err(Error::FragmentationLimit)
                ));
                assert_eq!(f.window.ready(), Err(Error::FragmentationLimit));
            }
        }
    }
}

#[test]
fn fragments_after_a_volatile_empty_prefix_and_fragmented_probe_responses_preserve_floors() {
    use opc_proto_ikev2::canonical::Ikev2CanonicalPolicy;
    support::ensure_ike_crypto();
    let mut f = Fixture::new(124290, ALGORITHMS[0], DIRECTIONS[0]);
    enable(&mut f);
    f.window
        .enable_empty_replies(Ikev2CanonicalPolicy::default())
        .unwrap();
    let prepared = f.window.prepare_liveness(4).unwrap();
    let row = prepared.record().clone();
    let token = prepared.commit_after_durable(&row).unwrap();
    f.window.apply_committed(token).unwrap();
    let keys = f.keys.clone();
    let peer = wire::Wire::new(f.profile, &keys, f.spis, opposite(f.direction));
    let packet = peer.seal_fragment(0, false, 37, (1, 1), empty());
    let Receive::Message(request) = receive(&mut f, &packet, 0).unwrap() else {
        panic!("empty fragmented message");
    };
    let answer = f.window.reply_empty(&request).unwrap();
    assert_eq!(
        peer.open(answer.bytes()).unwrap().first,
        PayloadType::NoNext
    );
    drop(answer);
    assert_eq!(f.window.next_receive(), Some(1));
    assert_eq!(f.window.record().next_receive(), Some(0));
    let Receive::Message(repeated) = receive(&mut f, &packet, 1).unwrap() else {
        panic!("fragment one must recover the prior empty request");
    };
    assert_eq!(
        f.window.reply_empty(&repeated).unwrap().observation(),
        opc_proto_ikev2::recovery::Ikev2EmptyReplyObservation::Replayed
    );
    let nonfirst = peer.seal_fragment(0, false, 37, (2, 2), empty());
    assert!(matches!(receive(&mut f, &nonfirst, 1), Err(Error::Drop)));
    // Outbound and inbound message-ID windows remain independent.
    let probe = f
        .window
        .start_empty_probe(
            f.profile,
            &f.keys,
            &mut f.allocator,
            opc_proto_ikev2::recovery::Ikev2LivenessProbePolicy::new(100, 3, 10).unwrap(),
            1,
        )
        .unwrap();
    assert_eq!(peer.open(probe.bytes()).unwrap().header.message_id, 0);
    drop(probe);
    let reply = peer.seal_fragment(0, true, 37, (1, 1), empty());
    let Receive::Message(response) = receive(&mut f, &reply, 1).unwrap() else {
        panic!("probe reply");
    };
    assert_eq!(f.window.pending_empty_request_message_id(), Some(0));
    f.window.complete_empty_probe(&response, 2).unwrap();
    assert_eq!(f.window.pending_empty_request_message_id(), None);
    let parts = fragments(&peer, 2, 1);
    assert!(matches!(
        receive(&mut f, &parts[0], 2),
        Ok(Receive::Incomplete)
    ));
    let Receive::Message(work) = receive(&mut f, &parts[1], 3).unwrap() else {
        panic!("next peer work");
    };
    assert_eq!(f.window.request_disposition(&work), Ok(Disposition::New));
}

#[test]
fn fragment_metadata_is_not_a_way_to_admit_foreign_or_sync_messages() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(124300, ALGORITHMS[0], DIRECTIONS[0]);
    enable(&mut f);
    let keys = f.keys.clone();
    let peer = wire::Wire::new(f.profile, &keys, f.spis, opposite(f.direction));
    let foreign = wire::Wire::new(
        f.profile,
        &keys,
        (f.spis.0, f.spis.1 + 1),
        opposite(f.direction),
    );
    let wrong_role = wire::Wire::new(f.profile, &keys, f.spis, f.direction);
    for packet in [
        peer.seal_fragment(1, false, 37, (1, 1), canonical_fixtures::delete()),
        peer.seal_fragment(0, true, 37, (1, 1), canonical_fixtures::delete()),
        peer.seal_fragment(0, false, 34, (1, 1), canonical_fixtures::delete()),
        foreign.seal_fragment(0, false, 37, (1, 1), canonical_fixtures::delete()),
        wrong_role.seal_fragment(0, false, 37, (1, 1), canonical_fixtures::delete()),
        // MESSAGE_ID_SYNC remains a separate unfragmented exchange, RFC 7383 §3.
        peer.seal_fragment(
            0,
            false,
            37,
            (1, 1),
            PayloadChain::new(PayloadType::Notify, &[0, 0, 0, 8, 0, 0, 0x40, 0x26]),
        ),
        peer.seal_fragment(
            0,
            false,
            37,
            (1, 1),
            PayloadChain::new(PayloadType::Encrypted, &[0, 0, 0, 4]),
        ),
    ] {
        assert!(matches!(receive(&mut f, &packet, 0), Err(Error::Drop)));
    }
    assert_eq!(f.window.ready(), Ok(()));
    assert_eq!(f.window.fragment_deadline_ms(), None);
}

#[test]
fn fragmentation_thresholds_include_ip_udp_marker_and_minimum_cipher_overhead() {
    use opc_proto_ikev2::recovery::Ikev2FragmentationSize as Size;
    use std::num::NonZeroU16;
    assert_eq!(Size::ipv4(None, false).unwrap().max_ike_packet_bytes(), 548);
    assert_eq!(
        Size::ipv6(None, false).unwrap().max_ike_packet_bytes(),
        1232
    );
    assert_eq!(Size::ipv6(None, true).unwrap().max_ike_packet_bytes(), 1228);
    assert_eq!(
        Size::ipv6(NonZeroU16::new(1500), true)
            .unwrap()
            .max_ike_packet_bytes(),
        1448
    );
    assert_eq!(
        Size::ipv4(NonZeroU16::new(60), true),
        Err(Error::FragmentationLimit)
    );
    assert_eq!(
        Size::ipv6(NonZeroU16::new(40), false),
        Err(Error::FragmentationLimit)
    );
}

#[test]
fn exact_cleartext_and_fragment_count_bounds_are_accepted_and_tiny_send_budgets_do_not_burn_ivs() {
    use opc_proto_ikev2::{
        recovery::Ikev2FragmentationSize as Size, Ikev2ExchangeKind as Exchange,
    };
    support::ensure_ike_crypto();
    for case in 0..2 {
        let mut f = Fixture::new(124310 + case, ALGORITHMS[0], DIRECTIONS[0]);
        enable(&mut f);
        let keys = f.keys.clone();
        let peer = wire::Wire::new(f.profile, &keys, f.spis, opposite(f.direction));
        let count = if case == 0 { 2 } else { 256 };
        for number in 1..=count {
            let mut body = if case == 0 { vec![0xa5; 32768] } else { vec![] };
            if case == 0 {
                body[..4].copy_from_slice(&[if number == 1 { 43 } else { 0 }, 0, 128, 0]);
            }
            let packet = peer.seal_fragment(
                0,
                false,
                35,
                (number, count),
                PayloadChain::new(
                    if case == 0 && number == 1 {
                        PayloadType::VendorId
                    } else {
                        PayloadType::NoNext
                    },
                    &body,
                ),
            );
            let opened = receive(&mut f, &packet, 0).unwrap();
            if number == count {
                let Receive::Message(message) = opened else {
                    panic!("boundary message");
                };
                assert_eq!(
                    message.payloads().bytes().len(),
                    if case == 0 { 65536 } else { 0 }
                );
            } else {
                assert!(matches!(opened, Receive::Incomplete));
            }
        }
        let payload = large_delete();
        for pmtu in [92, 96] {
            assert!(matches!(
                f.window.prepare_fragmented_request(
                    f.profile,
                    &f.keys,
                    &mut f.allocator,
                    Purpose::Ordinary,
                    Exchange::Informational,
                    PayloadChain::new(PayloadType::Delete, &payload),
                    Size::ipv4(std::num::NonZeroU16::new(pmtu), true).unwrap()
                ),
                Err(Error::FragmentationLimit)
            ));
        }
        assert_eq!(f.window.ready(), Ok(()));
        let prepared = f
            .window
            .prepare_fragmented_request(
                f.profile,
                &f.keys,
                &mut f.allocator,
                Purpose::Ordinary,
                Exchange::Informational,
                PayloadChain::new(PayloadType::Delete, &payload),
                Size::ipv4(None, true).unwrap(),
            )
            .unwrap();
        assert_eq!(
            &prepared.record().outbound().unwrap().request().packets()[0][36..44],
            &0u64.to_be_bytes()
        );
    }
}
