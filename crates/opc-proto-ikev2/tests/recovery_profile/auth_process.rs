//! Lost final IKE_AUTH replies through real executor process loss in both roles.

use super::{
    auth,
    authority::{EpochOwners, Transport},
    crash::{child, packet_name, read, write, RunDir},
    driver::{self, Cut, Runtime},
    effects::{Direction, Effects, Error as EffectError},
    envelope::Provider,
    lifecycle::matrix,
    peer::{Event, PeerModel},
    row::Row,
    store::CasStore,
    wire::Wire,
};
use bytes::Bytes;
use opc_proto_ikev2::{
    Ikev2ExchangeKind as Exchange, Ikev2MessageIdSyncMode as Mode, PayloadChain,
};
use std::path::Path;

fn rows() -> Vec<Row> {
    let mut rows = Vec::new();
    matrix(700_000, |row| rows.push(auth::before_final(row)));
    assert_eq!(rows.len(), 204);
    rows
}

fn effect_direction(row: &Row) -> Direction {
    if auth::initiator(row) {
        Direction::Local
    } else {
        Direction::Peer
    }
}

pub fn run(root: &Path, stage: &str, provider: &Provider) {
    match stage {
        "auth-start" => {
            let mut store = CasStore::new(7);
            let owners = EpochOwners::new(7);
            let mut effects = Effects::default();
            for row in rows() {
                let initial = driver::create(provider, &mut store, &row).unwrap();
                let mut runtime = Runtime::restore(
                    provider,
                    &owners,
                    &store.fenced_read(&initial, row.key).unwrap(),
                    false,
                )
                .unwrap();
                runtime
                    .reserve(
                        provider,
                        &mut store,
                        19,
                        1,
                        100,
                        Cut::Complete,
                        Cut::Complete,
                    )
                    .unwrap();
                if auth::initiator(&row) {
                    let (first, payload) = auth::payload(&row, false);
                    runtime
                        .publish_request(
                            provider,
                            &mut store,
                            Exchange::IkeAuth,
                            PayloadChain::new(first, &payload),
                            |_| {},
                            Cut::Complete,
                        )
                        .unwrap();
                    let mut transport = Transport::default();
                    runtime.dispatch_replay(&mut transport).unwrap();
                    write(
                        root,
                        &packet_name("auth-request", row.key.0),
                        transport.submitted.last().unwrap(),
                    );
                } else {
                    let request = read(root, &packet_name("auth-request", row.key.0));
                    let packet = Wire::new(row.profile, &row.keys, row.spis, row.direction)
                        .open(&request)
                        .unwrap();
                    auth::verify(&row, &packet, false).unwrap();
                    let (first, response) = auth::payload(&row, true);
                    assert!(runtime
                        .publish_response(
                            provider,
                            &mut store,
                            &request,
                            PayloadChain::new(first, &response),
                            Bytes::from_static(b"attached-child"),
                            |_| {},
                            Cut::Applied
                        )
                        .unwrap()
                        .is_none());
                }
                assert_eq!(
                    effects.apply(provider, &store, &initial, &runtime, effect_direction(&row)),
                    Err(EffectError::NotCommitted)
                );
                assert!(effects.outcomes.is_empty());
            }
            write(root, "auth-start.rows", &store.encrypted_snapshot());
        }
        "auth-finish" => {
            let (mut store, cuts) =
                CasStore::reopen_after_join(&read(root, "auth-start.rows"), 8).unwrap();
            let owners = EpochOwners::new(8);
            let mut effects = Effects::default();
            for cut in cuts {
                let mut runtime = Runtime::restore(provider, &owners, &cut, false).unwrap();
                let mut transport = Transport::default();
                if auth::initiator(&runtime.row) {
                    runtime.dispatch_replay(&mut transport).unwrap();
                    write(
                        root,
                        &packet_name("auth-request-replayed", cut.key().0),
                        transport.submitted.last().unwrap(),
                    );
                    let response = read(root, &packet_name("auth-response", cut.key().0));
                    let row = &runtime.row;
                    let packet = Wire::new(row.profile, &row.keys, row.spis, row.direction)
                        .open(&response)
                        .unwrap();
                    auth::verify(row, &packet, true).unwrap();
                    assert!(runtime
                        .complete(
                            provider,
                            &mut store,
                            &response,
                            Bytes::from_static(b"attached-child"),
                            |_| {},
                            Cut::Applied
                        )
                        .unwrap()
                        .is_none());
                    assert_eq!(
                        effects.recover(provider, &store, &cut, &runtime, Direction::Local),
                        Err(EffectError::NotCommitted)
                    );
                } else {
                    let request = read(root, &packet_name("auth-request", cut.key().0));
                    runtime.replay_response(&request, &mut transport).unwrap();
                    runtime.replay_response(&request, &mut transport).unwrap();
                    assert_eq!(transport.submitted[0], transport.submitted[1]);
                    write(
                        root,
                        &packet_name("auth-response", cut.key().0),
                        &transport.submitted[0],
                    );
                    write(
                        root,
                        &packet_name("auth-response-again", cut.key().0),
                        &transport.submitted[1],
                    );
                }
            }
            assert!(effects.outcomes.is_empty());
            write(root, "auth-finished.rows", &store.encrypted_snapshot());
        }
        "auth-effects" | "auth-after-effects" => {
            let again = stage == "auth-after-effects";
            let snapshot = if again {
                "auth-effects.rows"
            } else {
                "auth-finished.rows"
            };
            let (store, cuts) =
                CasStore::reopen_after_join(&read(root, snapshot), if again { 10 } else { 9 })
                    .unwrap();
            let owners = EpochOwners::new(store.stamp());
            let mut effects = if again {
                Effects::reopen(&read(root, "auth.effects")).unwrap()
            } else {
                Effects::default()
            };
            for cut in cuts {
                let mut runtime = Runtime::restore(provider, &owners, &cut, false).unwrap();
                let direction = effect_direction(&runtime.row);
                assert_eq!(
                    effects
                        .recover(provider, &store, &cut, &runtime, direction)
                        .unwrap(),
                    !again
                );
                assert!(!effects
                    .recover(provider, &store, &cut, &runtime, direction)
                    .unwrap());
                assert!(runtime.row.window.generation >= 1);
                let mut transport = Transport::default();
                if auth::initiator(&runtime.row) {
                    assert_eq!(runtime.row.window.next_send, Some(auth::FINAL_ID + 1));
                    assert_eq!(runtime.row.window.next_receive, Some(0));
                    assert!(!runtime.dispatch_replay(&mut transport).unwrap());
                    assert!(transport.submitted.is_empty());
                } else {
                    assert_eq!(runtime.row.window.next_send, Some(0));
                    assert_eq!(runtime.row.window.next_receive, Some(auth::FINAL_ID + 1));
                    let request = read(root, &packet_name("auth-request", cut.key().0));
                    runtime.replay_response(&request, &mut transport).unwrap();
                    write(
                        root,
                        &packet_name(
                            if again {
                                "auth-response-after-effects"
                            } else {
                                "auth-response-after-completion"
                            },
                            cut.key().0,
                        ),
                        transport.submitted.last().unwrap(),
                    );
                }
            }
            assert_eq!(effects.len(), 204);
            assert_eq!(effects.outcomes.len(), if again { 0 } else { 204 });
            if !again {
                write(root, "auth.effects", &effects.snapshot());
                write(root, "auth-effects.rows", &store.encrypted_snapshot());
            }
        }
        _ => panic!("unknown final authentication stage"),
    }
}

#[test]
fn final_ike_auth_restart_keeps_exact_reply_asymmetric_floors_and_one_attach() {
    let root = RunDir::new();
    let rows = rows();
    let mut peers = Vec::new();
    for row in &rows {
        let (send, receive) = if auth::initiator(row) {
            (0, auth::FINAL_ID)
        } else {
            (auth::FINAL_ID, 0)
        };
        let mut peer = PeerModel::new(
            Wire::new(
                row.profile,
                &row.keys,
                row.spis,
                crate::canonical_fixtures::opposite(row.direction),
            ),
            send,
            receive,
            row.mode == Mode::Negotiated,
        );
        if !auth::initiator(row) {
            let (first, payload) = auth::payload(row, false);
            let request = peer
                .request(35, PayloadChain::new(first, &payload))
                .unwrap();
            write(&root.0, &packet_name("auth-request", row.key.0), &request);
        }
        peers.push(peer);
    }
    child(&root.0, "auth-start", "auth", "handshake-before-loss");
    for (row, peer) in rows.iter().zip(&mut peers) {
        assert!(!root
            .0
            .join(packet_name("auth-response", row.key.0))
            .exists());
        if auth::initiator(row) {
            let request = read(&root.0, &packet_name("auth-request", row.key.0));
            assert_eq!(
                peer.receive(&request),
                Ok(Event::NewRequest(auth::FINAL_ID))
            );
            auth::verify(row, &peer.wire.open(&request).unwrap(), false).unwrap();
            let (first, payload) = auth::payload(row, true);
            let response = peer
                .respond(auth::FINAL_ID, PayloadChain::new(first, &payload))
                .unwrap();
            write(&root.0, &packet_name("auth-response", row.key.0), &response);
        }
    }
    child(&root.0, "auth-finish", "auth", "handshake-completion-loss");
    for (row, peer) in rows.iter().zip(&mut peers) {
        let response = read(&root.0, &packet_name("auth-response", row.key.0));
        if auth::initiator(row) {
            let request = read(&root.0, &packet_name("auth-request-replayed", row.key.0));
            assert_eq!(
                request,
                read(&root.0, &packet_name("auth-request", row.key.0))
            );
            assert_eq!(
                peer.receive(&request),
                Ok(Event::Replay(Bytes::from(response)))
            );
        } else {
            auth::verify(row, &peer.wire.open(&response).unwrap(), true).unwrap();
            assert_eq!(
                peer.receive(&response),
                Ok(Event::Completed(auth::FINAL_ID))
            );
            let duplicate = read(&root.0, &packet_name("auth-response-again", row.key.0));
            assert_eq!(duplicate, response);
            assert_eq!(peer.receive(&duplicate), Ok(Event::Ignored));
        }
    }
    for (stage, packet) in [
        ("auth-effects", "auth-response-after-completion"),
        ("auth-after-effects", "auth-response-after-effects"),
    ] {
        child(&root.0, stage, "auth", "handshake-settled-restart");
        for (row, peer) in rows.iter().zip(&mut peers) {
            if !auth::initiator(row) {
                let response = read(&root.0, &packet_name(packet, row.key.0));
                assert_eq!(
                    response,
                    read(&root.0, &packet_name("auth-response", row.key.0))
                );
                assert_eq!(peer.receive(&response), Ok(Event::Ignored));
            }
            assert!(peer.alive());
        }
    }
}
