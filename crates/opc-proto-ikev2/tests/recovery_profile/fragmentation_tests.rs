//! Fragmented exchanges use the complete-row codec, fenced CAS and independent peer.

use super::{
    authority::Transport,
    driver::{self, Cut, Runtime, State},
    envelope::Provider,
    fragmentation_fixtures::{large_delete, offers},
    lifecycle::matrix,
    peer::{Event, PeerModel},
    row::WindowImage,
    store::{CasStore, Command},
    wire::Wire,
};
use crate::canonical_fixtures::{empty, opposite};
use bytes::Bytes;
use opc_proto_ikev2::{
    recovery::Ikev2FragmentationSize as Size, Ikev2AesGcmIvPurpose as Purpose,
    Ikev2ExchangeKind as Exchange, Ikev2MessageIdSyncMode as Mode, PayloadChain, PayloadType,
};
use std::num::NonZeroU32;

fn publish(
    runtime: &mut Runtime,
    provider: &Provider,
    store: &mut CasStore,
    image: WindowImage,
) -> Command {
    let row = runtime
        .row
        .next_write(store.stamp(), |row| row.window = image)
        .unwrap();
    let command = driver::command(provider, store, Some(runtime.row.version), &row).unwrap();
    runtime.pending = Some(command.clone());
    assert!(driver::dispatch(store, &command, Cut::Complete).unwrap());
    runtime.resolve(provider, store, &command).unwrap();
    command
}

fn enable(runtime: &mut Runtime, provider: &Provider, store: &mut CasStore) {
    let request = offers(runtime.row.spis, false, true);
    let response = offers(runtime.row.spis, true, true);
    let image = match &mut runtime.state {
        State::Gcm { window, .. } => WindowImage::gcm(
            window
                .prepare_fragmentation(
                    runtime.row.profile,
                    &runtime.row.keys,
                    &request,
                    &response,
                    NonZeroU32::new(50).unwrap(),
                )
                .unwrap()
                .record(),
        ),
        State::Cbc { window, .. } => WindowImage::cbc(
            window
                .prepare_fragmentation(
                    runtime.row.profile,
                    &runtime.row.keys,
                    &request,
                    &response,
                    NonZeroU32::new(50).unwrap(),
                )
                .unwrap()
                .record(),
        ),
    };
    publish(runtime, provider, store, image);
}

#[test]
fn fragmented_requests_replay_from_strict_rows_for_every_profile_role_and_sync_mode() {
    let mut cases = 0;
    matrix(12_420_000, |row| {
        let (provider, mut store, owners, initial, mut runtime) =
            super::liveness_tests::setup(&row);
        enable(&mut runtime, &provider, &mut store);
        let cleartext = large_delete();
        let payload = PayloadChain::new(PayloadType::Delete, &cleartext);
        let image = request_image(&mut runtime, payload);
        let expected = image.outbound.as_ref().unwrap().request().clone();
        assert!(expected.packets().len() >= 3);
        assert!(expected.packets().iter().all(|packet| packet.len() <= 544));
        publish(&mut runtime, &provider, &mut store, image);
        let saved = store.encrypted_snapshot();
        let mut transport = Transport::default();
        assert!(runtime.dispatch_replay(&mut transport).unwrap());
        assert_eq!(transport.submitted, expected.packets());
        assert_eq!(store.encrypted_snapshot(), saved);
        let mut peer = PeerModel::new(
            Wire::new(row.profile, &row.keys, row.spis, opposite(row.direction)),
            0,
            0,
            row.mode == Mode::Negotiated,
        );
        let opened = peer.wire.open_message(&expected).unwrap();
        assert_eq!(opened.body.as_ref(), cleartext);
        assert_eq!(peer.receive_opened(opened), Ok(Event::NewRequest(0)));
        drop(runtime);
        let mut runtime = Runtime::restore(
            &provider,
            &owners,
            &store.fenced_read(&initial, row.key).unwrap(),
            true,
        )
        .unwrap();
        let mut replay = Transport::default();
        assert!(runtime.dispatch_replay(&mut replay).unwrap());
        assert_eq!(replay.submitted, expected.packets());
        assert_eq!(store.encrypted_snapshot(), saved);
        assert_eq!(
            peer.receive_opened(peer.wire.open_message(&expected).unwrap()),
            Ok(Event::Ignored)
        );
        let response = peer.respond(0, empty()).unwrap();
        assert_eq!(
            runtime
                .complete(
                    &provider,
                    &mut store,
                    &response,
                    Bytes::from_static(b"fragmented-complete"),
                    |_| {},
                    Cut::Complete
                )
                .unwrap(),
            Some(Bytes::from_static(b"fragmented-complete"))
        );
        assert!(!runtime.dispatch_replay(&mut Transport::default()).unwrap());
        cases += 1;
    });
    assert_eq!(cases, 204);
}

fn response_image(
    runtime: &mut Runtime,
    request: &[Bytes],
    payload: PayloadChain<'_>,
    outcome: Bytes,
) -> WindowImage {
    use opc_proto_ikev2::recovery::Ikev2FragmentReceive as Receive;
    macro_rules! prepare {
        ($window:ident, $($sealing:expr),*) => {{
            let mut opened = None;
            for packet in request.iter().rev() {
                match $window.receive_peer_packet(runtime.row.profile, &runtime.row.keys, packet, 1).unwrap() {
                    Receive::Incomplete => assert!(opened.is_none()),
                    Receive::Message(message) => opened = Some(message),
                    Receive::Retransmit(_) => panic!("fresh request"),
                }
            }
            let opened = opened.unwrap();
            $window.prepare_fragmented_response(
                runtime.row.profile, &runtime.row.keys, $($sealing,)*
                &opened, payload, outcome, Size::ipv4(None, true).unwrap(),
            ).unwrap()
        }};
    }
    match &mut runtime.state {
        State::Gcm { window, allocator } => {
            WindowImage::gcm(prepare!(window, allocator, Purpose::Ordinary).record())
        }
        State::Cbc { window, .. } => WindowImage::cbc(prepare!(window,).record()),
    }
}

fn replay_fragment(runtime: &mut Runtime, packet: &[u8], transport: &mut Transport) {
    use opc_proto_ikev2::recovery::Ikev2FragmentReceive as Receive;
    let permit = runtime.permit();
    macro_rules! replay {
        ($window:ident) => {
            let Receive::Retransmit(replay) = $window
                .receive_peer_packet(runtime.row.profile, &runtime.row.keys, packet, 2)
                .unwrap()
            else {
                panic!("committed fragment one must replay");
            };
            for packet in replay.packets() {
                transport.submit(&permit, packet).unwrap();
            }
        };
    }
    match &mut runtime.state {
        State::Gcm { window, .. } => {
            replay!(window);
        }
        State::Cbc { window, .. } => {
            replay!(window);
        }
    }
}

#[test]
fn fragmented_auth_responses_survive_restore_with_one_durable_outcome_in_every_profile() {
    use super::effects::{Direction, Effects};
    matrix(12_421_000, |row| {
        let (provider, mut store, owners, initial, mut runtime) =
            super::liveness_tests::setup(&row);
        enable(&mut runtime, &provider, &mut store);
        // Large certificate-shaped payload; authentication semantics belong to the consumer.
        let mut cleartext = vec![0xa5; 2405];
        cleartext[..5].copy_from_slice(&[0, 0, 9, 101, 4]);
        let payload = PayloadChain::new(PayloadType::Certificate, &cleartext);
        let peer = Wire::new(row.profile, &row.keys, row.spis, opposite(row.direction));
        let request = cleartext
            .chunks(802)
            .enumerate()
            .map(|(i, part)| {
                peer.seal_fragment(
                    0,
                    false,
                    35,
                    (u16::try_from(i + 1).unwrap(), 3),
                    PayloadChain::new(
                        if i == 0 {
                            PayloadType::Certificate
                        } else {
                            PayloadType::NoNext
                        },
                        part,
                    ),
                )
            })
            .collect::<Vec<_>>();
        let image = response_image(
            &mut runtime,
            &request,
            payload,
            Bytes::from_static(b"auth-admitted"),
        );
        let expected = image.inbound.as_ref().unwrap().response().unwrap().clone();
        assert!(expected.packets().len() >= 5);
        let commit = publish(&mut runtime, &provider, &mut store, image);
        let mut effects = Effects::default();
        assert!(effects
            .apply(&provider, &store, &commit, &runtime, Direction::Peer)
            .unwrap());
        let saved = store.encrypted_snapshot();
        // An outbound-only uncertain preparation must retain cached peer-response authority.
        let pending_payload = large_delete();
        let _uncommitted = request_image(
            &mut runtime,
            PayloadChain::new(PayloadType::Delete, &pending_payload),
        );
        let mut sent = Transport::default();
        replay_fragment(&mut runtime, &request[0], &mut sent);
        runtime.resolve(&provider, &store, &commit).unwrap();
        assert_eq!(sent.submitted, expected.packets());
        assert_eq!(
            peer.open_message(&expected).unwrap().body.as_ref(),
            cleartext
        );
        drop(runtime);
        let mut runtime = Runtime::restore(
            &provider,
            &owners,
            &store.fenced_read(&initial, row.key).unwrap(),
            true,
        )
        .unwrap();
        let mut replay = Transport::default();
        replay_fragment(&mut runtime, &request[0], &mut replay);
        assert_eq!(replay.submitted, expected.packets());
        assert_eq!(store.encrypted_snapshot(), saved);
        assert!(!effects
            .apply(&provider, &store, &commit, &runtime, Direction::Peer)
            .unwrap());
        assert_eq!(effects.outcomes, [Bytes::from_static(b"auth-admitted")]);
    });
}

#[test]
fn terminal_closure_requires_every_committed_response_fragment_to_be_submitted() {
    let row = super::inputs::fresh(
        12_422_000,
        crate::canonical_fixtures::profile(crate::canonical_fixtures::ALGORITHMS[0]),
        crate::canonical_fixtures::DIRECTIONS[0],
        Mode::BaseFallback,
    );
    let (provider, mut store, _owners, _initial, mut runtime) = super::liveness_tests::setup(&row);
    enable(&mut runtime, &provider, &mut store);
    let peer = Wire::new(row.profile, &row.keys, row.spis, opposite(row.direction));
    let request = peer.seal(0, false, 37, crate::canonical_fixtures::delete());
    // This driver-level safety check covers even a consumer-supplied terminal payload.
    let payload = large_delete();
    let image = response_image(
        &mut runtime,
        &[request],
        PayloadChain::new(PayloadType::Delete, &payload),
        Bytes::from_static(b"ike-deleted"),
    );
    let response = image.inbound.as_ref().unwrap().response().unwrap().clone();
    publish(&mut runtime, &provider, &mut store, image);
    let mut sent = Transport::default();
    sent.submit(&runtime.permit(), &response.packets()[0])
        .unwrap();
    assert_eq!(
        runtime.close_after_delete_reply(&provider, &mut store, &sent, Cut::Complete),
        Err(driver::Error::NotCommittedDelete)
    );
    for packet in &response.packets()[1..] {
        sent.submit(&runtime.permit(), packet).unwrap();
    }
    assert!(runtime
        .close_after_delete_reply(&provider, &mut store, &sent, Cut::Complete)
        .unwrap());
}

fn request_image(runtime: &mut Runtime, payload: PayloadChain<'_>) -> WindowImage {
    let size = Size::ipv4(None, true).unwrap();
    let image = match &mut runtime.state {
        State::Gcm {
            window, allocator, ..
        } => WindowImage::gcm(
            window
                .prepare_fragmented_request(
                    runtime.row.profile,
                    &runtime.row.keys,
                    allocator,
                    Purpose::Ordinary,
                    Exchange::Informational,
                    payload,
                    size,
                )
                .unwrap()
                .record(),
        ),
        State::Cbc { window, .. } => WindowImage::cbc(
            window
                .prepare_fragmented_request(
                    runtime.row.profile,
                    &runtime.row.keys,
                    Exchange::Informational,
                    payload,
                    size,
                )
                .unwrap()
                .record(),
        ),
    };
    image
}

pub fn run_process(root: &std::path::Path, stage: &str, provider: &Provider) {
    use super::{
        authority::EpochOwners,
        crash::{read, write},
        effects::{Direction, Effects},
    };
    matrix(12_423_000, |row| {
        let name = |kind: &str| format!("fragments-{kind}-{}", row.key.0);
        match stage {
            "fragments-partial" => {
                let mut store = CasStore::new(7);
                let owners = EpochOwners::new(7);
                let initial = driver::create(provider, &mut store, &row).unwrap();
                let mut runtime = Runtime::restore(
                    provider,
                    &owners,
                    &store.fenced_read(&initial, row.key).unwrap(),
                    true,
                )
                .unwrap();
                runtime
                    .reserve(
                        provider,
                        &mut store,
                        1,
                        32,
                        100,
                        Cut::Complete,
                        Cut::Complete,
                    )
                    .unwrap();
                enable(&mut runtime, provider, &mut store);
                let cleartext = large_delete();
                let payload = PayloadChain::new(PayloadType::Delete, &cleartext);
                let image = request_image(&mut runtime, payload);
                publish(&mut runtime, provider, &mut store, image);
                let peer = Wire::new(row.profile, &row.keys, row.spis, opposite(row.direction));
                let request = peer.seal_fragment(0, false, 37, (1, 1), payload);
                write(root, &name("peer-request"), &request);
                let image = response_image(
                    &mut runtime,
                    &[request],
                    payload,
                    Bytes::from_static(b"peer-deleted"),
                );
                let committed = publish(&mut runtime, provider, &mut store, image);
                let mut effects = Effects::default();
                assert!(effects
                    .apply(provider, &store, &committed, &runtime, Direction::Peer)
                    .unwrap());
                write(root, &name("effects"), &effects.snapshot());
                let mut sent = Transport::default();
                let permit = runtime.permit();
                macro_rules! partial {
                    ($window:ident) => {
                        let replay = $window.replay_request().unwrap().unwrap();
                        sent.submit(&permit, &replay.packets()[0]).unwrap();
                    };
                }
                match &mut runtime.state {
                    State::Gcm { window, .. } => {
                        partial!(window);
                    }
                    State::Cbc { window, .. } => {
                        partial!(window);
                    }
                }
                write(root, &name("request-first"), &sent.submitted[0]);
                // The response is committed; loss occurs before its second datagram.
                let peer_request = read(root, &name("peer-request"));
                macro_rules! partial_reply {
                    ($window:ident) => {
                        let opc_proto_ikev2::recovery::Ikev2FragmentReceive::Retransmit(replay) =
                            $window
                                .receive_peer_packet(row.profile, &row.keys, &peer_request, 2)
                                .unwrap()
                        else {
                            panic!("cached reply");
                        };
                        sent.submit(&permit, &replay.packets()[0]).unwrap();
                    };
                }
                match &mut runtime.state {
                    State::Gcm { window, .. } => {
                        partial_reply!(window);
                    }
                    State::Cbc { window, .. } => {
                        partial_reply!(window);
                    }
                }
                write(root, &name("response-first"), &sent.submitted[1]);
                write(root, &name("rows"), &store.encrypted_snapshot());
                std::mem::forget((runtime, store, owners));
            }
            "fragments-recover" => {
                let (store, mut cuts) =
                    CasStore::reopen_after_join(&read(root, &name("rows")), 8).unwrap();
                assert_eq!(cuts.len(), 1);
                let cut = cuts.pop().unwrap();
                let owners = EpochOwners::new(8);
                let mut runtime = Runtime::restore(provider, &owners, &cut, true).unwrap();
                let durable = store.encrypted_snapshot();
                let before = (provider.calls(), super::module::counts().entropy);
                let expected = runtime
                    .row
                    .window
                    .outbound
                    .as_ref()
                    .unwrap()
                    .request()
                    .clone();
                assert!(expected.packets().len() >= 3);
                assert_eq!(
                    expected.packets()[0].as_ref(),
                    read(root, &name("request-first"))
                );
                let mut sent = Transport::default();
                assert!(runtime.dispatch_replay(&mut sent).unwrap());
                assert_eq!(sent.submitted, expected.packets());
                let peer = Wire::new(row.profile, &row.keys, row.spis, opposite(row.direction));
                assert_eq!(
                    peer.open_message(&expected).unwrap().body.as_ref(),
                    large_delete()
                );
                let expected_reply = runtime
                    .row
                    .window
                    .inbound
                    .as_ref()
                    .unwrap()
                    .response()
                    .unwrap()
                    .clone();
                assert!(expected_reply.packets().len() >= 3);
                assert_eq!(
                    expected_reply.packets()[0].as_ref(),
                    read(root, &name("response-first"))
                );
                let mut replies = Transport::default();
                replay_fragment(
                    &mut runtime,
                    &read(root, &name("peer-request")),
                    &mut replies,
                );
                assert_eq!(replies.submitted, expected_reply.packets());
                assert_eq!(
                    peer.open_message(&expected_reply).unwrap().body.as_ref(),
                    large_delete()
                );
                assert_eq!(store.encrypted_snapshot(), durable);
                assert_eq!((provider.calls(), super::module::counts().entropy), before);
                let mut effects = Effects::reopen(&read(root, &name("effects"))).unwrap();
                assert!(!effects
                    .recover(provider, &store, &cut, &runtime, Direction::Peer)
                    .unwrap());
                assert_eq!(effects.len(), 1);
                assert!(effects.outcomes.is_empty());
            }
            _ => panic!("unknown fragmentation process stage"),
        }
    });
}

#[test]
fn process_loss_between_request_and_response_fragments_replays_all_packets_without_reencryption() {
    let root = super::crash::RunDir::new();
    super::crash::child(&root.0, "fragments-partial", "all", "1");
    super::crash::child(&root.0, "fragments-recover", "all", "1");
}

#[test]
fn fragmented_responses_complete_pending_requests_and_sync_discards_partial_queues() {
    use opc_proto_ikev2::recovery::{Ikev2FragmentReceive as Receive, Ikev2WindowError as Error};
    matrix(12_425_000, |row| {
        let (provider, mut store, _owners, _initial, mut runtime) =
            super::liveness_tests::setup(&row);
        enable(&mut runtime, &provider, &mut store);
        let cleartext = large_delete();
        let payload = PayloadChain::new(PayloadType::Delete, &cleartext);
        let image = request_image(&mut runtime, payload);
        publish(&mut runtime, &provider, &mut store, image);
        let peer = Wire::new(row.profile, &row.keys, row.spis, opposite(row.direction));
        let parts: Vec<_> = cleartext
            .chunks(403)
            .enumerate()
            .map(|(i, part)| {
                peer.seal_fragment(
                    0,
                    true,
                    37,
                    (u16::try_from(i + 1).unwrap(), 3),
                    PayloadChain::new(
                        if i == 0 {
                            PayloadType::Delete
                        } else {
                            PayloadType::NoNext
                        },
                        part,
                    ),
                )
            })
            .collect();
        macro_rules! complete {
            ($window:ident, $capture:ident) => {{
                assert!(matches!(
                    $window.receive_peer_packet(row.profile, &row.keys, &parts[1], 1),
                    Ok(Receive::Incomplete)
                ));
                let wrong = peer.seal_fragment(
                    1,
                    true,
                    37,
                    (3, 3),
                    PayloadChain::new(PayloadType::NoNext, &cleartext[806..]),
                );
                assert!(matches!(
                    $window.receive_peer_packet(row.profile, &row.keys, &wrong, 1),
                    Err(Error::Drop)
                ));
                assert!(matches!(
                    $window.receive_peer_packet(row.profile, &row.keys, &parts[2], 2),
                    Ok(Receive::Incomplete)
                ));
                let Receive::Message(response) = $window
                    .receive_peer_packet(row.profile, &row.keys, &parts[0], 3)
                    .unwrap()
                else {
                    panic!("complete response");
                };
                assert_eq!(response.payloads().bytes(), cleartext);
                WindowImage::$capture(
                    $window
                        .prepare_completion(&response, Bytes::from_static(b"completed-fragments"))
                        .unwrap()
                        .record(),
                )
            }};
        }
        let image = match &mut runtime.state {
            State::Gcm { window, .. } => complete!(window, gcm),
            State::Cbc { window, .. } => complete!(window, cbc),
        };
        assert_eq!(
            image
                .outbound
                .as_ref()
                .unwrap()
                .response()
                .unwrap()
                .packets(),
            parts
        );
        publish(&mut runtime, &provider, &mut store, image);
        assert!(!runtime.dispatch_replay(&mut Transport::default()).unwrap());
        if row.mode == Mode::Negotiated {
            let partial = peer.seal_fragment(
                0,
                false,
                37,
                (1, 2),
                PayloadChain::new(PayloadType::Delete, &cleartext[..500]),
            );
            macro_rules! queue {
                ($window:ident) => {{
                    assert!(matches!(
                        $window.receive_peer_packet(row.profile, &row.keys, &partial, 4),
                        Ok(Receive::Incomplete)
                    ));
                    assert_eq!($window.fragment_deadline_ms(), Some(54));
                }};
            }
            match &mut runtime.state {
                State::Gcm { window, .. } => queue!(window),
                State::Cbc { window, .. } => queue!(window),
            }
            let mut peer = PeerModel::new(peer, 0, 1, true);
            super::liveness_tests::recover(&mut runtime, &provider, &mut store, &mut peer);
            let deadline = match &runtime.state {
                State::Gcm { window, .. } => window.fragment_deadline_ms(),
                State::Cbc { window, .. } => window.fragment_deadline_ms(),
            };
            assert_eq!(deadline, None);
        }
    });
}
