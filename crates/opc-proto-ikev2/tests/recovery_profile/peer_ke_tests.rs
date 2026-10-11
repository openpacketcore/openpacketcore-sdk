//! Invalid authenticated peer KE values are protocol failures, not outages.

use super::{
    authority::{EpochOwners, Transport},
    codec::ProfileCodec,
    driver::{self, Cut, Runtime},
    envelope::{self, Fault, Provider},
    handoff, inputs, ke,
    peer::{Event, PeerModel},
    remedy,
    row::{KeKind, Outcome, Row},
    store::{CasStore, RowKey},
    wire::Wire,
};
use opc_proto_ikev2::{
    build_ike_auth_cleartext_payload_chain, Ikev2DhGroup as Group,
    Ikev2IkeAuthPayloadBuild as PayloadBuild, Ikev2MessageIdSyncMode as Mode,
    Ikev2SaInitCryptoProfile as Profile, PayloadChain, PayloadType,
};

fn cases(base: u64, mut test: impl FnMut(Row, KeKind, bool, Cut)) {
    let mut tag = base;
    for source in [
        inputs::profiles().next().unwrap(),
        super::cbc::profiles().next().unwrap(),
    ] {
        let profile = Profile::from_transform_ids(
            source.prf().transform_id(),
            Group::Ecp256.transform_id(),
            source.encryption().transform_id(),
            Some(source.encryption().key_bits()),
            source.integrity().map(|algorithm| algorithm.transform_id()),
        )
        .unwrap();
        for direction in crate::canonical_fixtures::DIRECTIONS {
            for mode in [Mode::BaseFallback, Mode::Negotiated] {
                for kind in ke::KINDS {
                    for short in [false, true] {
                        for cut in [
                            Cut::BeforeDispatch,
                            Cut::Dispatched,
                            Cut::Applied,
                            Cut::Acknowledged,
                            Cut::Complete,
                        ] {
                            tag += 1;
                            test(
                                inputs::fresh(tag, profile, direction, mode),
                                kind,
                                short,
                                cut,
                            );
                        }
                    }
                }
            }
        }
    }
}

fn invalid_payload(
    row: &Row,
    kind: KeKind,
    response: bool,
    short: bool,
) -> (PayloadType, bytes::Bytes) {
    let (first, body) = ke::payload(
        row,
        kind,
        response,
        row.profile.dh_group(),
        if response { 0x5152_5354 } else { 0x3132_3334 },
        if response { &[0x82; 64] } else { &[0x41; 64] },
        &vec![0; row.profile.dh_group().public_value_len()],
    );
    if !short {
        return (first, body);
    }
    let entries = PayloadChain::new(first, &body)
        .iter()
        .map(|entry| {
            let entry = entry.unwrap();
            let mut body = entry.body.to_vec();
            if entry.payload_type == PayloadType::KeyExchange {
                body.truncate(5);
            }
            PayloadBuild {
                payload_type: entry.payload_type,
                body,
            }
        })
        .collect::<Vec<_>>();
    build_ike_auth_cleartext_payload_chain(&entries).unwrap()
}

fn stored(provider: &Provider, store: &CasStore, key: RowKey) -> Row {
    let stored = store.inspect(key).unwrap();
    let plain = envelope::unseal(provider, key, stored).unwrap();
    ProfileCodec::decode(&plain, key, stored.version, stored.sealed_stamp).unwrap()
}

fn land(runtime: &mut Runtime, provider: &Provider, store: &mut CasStore) {
    if let Some(write) = runtime.pending.clone() {
        store.dispatch(write.clone()).unwrap();
        store.apply(write.request()).unwrap();
        runtime.resolve(provider, store, &write).unwrap();
    }
}

#[test]
fn invalid_peer_ke_request_commits_invalid_syntax() {
    cases(9_100_000, |row, kind, short, cut| {
        let provider = Provider::new();
        let mut store = CasStore::new(7);
        let owners = EpochOwners::new(7);
        let initial = driver::create(&provider, &mut store, &row).unwrap();
        let mut runtime = Runtime::restore(
            &provider,
            &owners,
            &store.fenced_read(&initial, row.key).unwrap(),
            false,
        )
        .unwrap();
        runtime
            .reserve(
                &provider,
                &mut store,
                19,
                3,
                100,
                Cut::Complete,
                Cut::Complete,
            )
            .unwrap();
        let mut peer = PeerModel::new(
            Wire::new(
                row.profile,
                &row.keys,
                row.spis,
                crate::canonical_fixtures::opposite(row.direction),
            ),
            0,
            0,
            row.mode == Mode::Negotiated,
        );
        let (first, body) = invalid_payload(&row, kind, false, short);
        let request = peer.request(36, PayloadChain::new(first, &body)).unwrap();
        let successor = RowKey(row.key.0 + 1_000_000);
        let result = if kind == KeKind::IkeRekey {
            handoff::finish_responder(
                &mut runtime,
                &provider,
                &mut store,
                19,
                successor,
                &request,
                cut,
            )
        } else {
            ke::commit_responder(&mut runtime, &provider, &mut store, 19, kind, &request, cut)
                .map(|reply| reply.is_some())
        };
        assert_eq!(
            result,
            Ok(cut == Cut::Complete),
            "invalid peer KE must commit an error response"
        );
        assert!(store.inspect(successor).is_none());
        let image = stored(&provider, &store, row.key);
        assert_eq!(
            image.operations.contains_key(&19),
            matches!(cut, Cut::Applied | Cut::Acknowledged | Cut::Complete)
        );
        let mut blocked = Transport::default();
        if cut != Cut::Complete {
            assert!(runtime.replay_response(&request, &mut blocked).is_err());
            assert!(blocked.submitted.is_empty());
        }
        land(&mut runtime, &provider, &mut store);
        let committed = runtime
            .row
            .window
            .inbound
            .as_ref()
            .unwrap()
            .response()
            .unwrap()
            .to_vec();
        drop(runtime);
        let mut runtime = Runtime::restore(
            &provider,
            &owners,
            &store.fenced_read(&initial, row.key).unwrap(),
            false,
        )
        .unwrap();
        assert!(runtime
            .close_after_invalid_syntax_reply(&provider, &mut store, &blocked, Cut::Complete)
            .is_err());
        let mut transport = Transport::default();
        runtime.replay_response(&request, &mut transport).unwrap();
        let response = transport.submitted.last().unwrap();
        assert_eq!(response.as_ref(), committed);
        assert_eq!(peer.receive(response), Ok(Event::Completed(0)));
        let opened = peer.wire.open(response).unwrap();
        assert_eq!(opened.first, PayloadType::Notify);
        assert_eq!(opened.body.as_ref(), [0, 0, 0, 8, 0, 0, 0, 7]);
        let operation = &runtime.row.operations[&19];
        assert!(!matches!(
            operation.outcome,
            Outcome::Pending | Outcome::Success
        ));
        assert!(operation.checkpoint.is_none() && operation.derived.is_none());
        assert_eq!(operation.outcome, Outcome::InvalidSyntax);
        assert_eq!(operation.spis.1, 0); // No new SA was created.
        assert_eq!(
            runtime.publish_request(
                &provider,
                &mut store,
                opc_proto_ikev2::Ikev2ExchangeKind::Informational,
                crate::canonical_fixtures::empty(),
                |_| {},
                Cut::Complete
            ),
            Err(driver::Error::Closed)
        );
        assert!(!runtime
            .close_after_invalid_syntax_reply(&provider, &mut store, &transport, Cut::Applied)
            .unwrap());
        land(&mut runtime, &provider, &mut store);
        assert!(runtime.row.closed && runtime.permit().check().is_err());
        assert!(stored(&provider, &store, row.key).closed);
    });
}

#[test]
fn invalid_syntax_response_closes_the_ike_sa_without_an_error_loop() {
    cases(9_120_000, |row, kind, short, cut| {
        if short || cut != Cut::Complete {
            return;
        }
        let provider = Provider::new();
        let mut store = CasStore::new(7);
        let owners = EpochOwners::new(7);
        let initial = driver::create(&provider, &mut store, &row).unwrap();
        let mut runtime = Runtime::restore(
            &provider,
            &owners,
            &store.fenced_read(&initial, row.key).unwrap(),
            false,
        )
        .unwrap();
        runtime
            .reserve(
                &provider,
                &mut store,
                19,
                3,
                100,
                Cut::Complete,
                Cut::Complete,
            )
            .unwrap();
        let operation = ke::draft(&runtime.row, 19, kind);
        ke::persist_ke(
            &mut runtime,
            &provider,
            &mut store,
            operation,
            Cut::Complete,
        )
        .unwrap();
        let mut transport = Transport::default();
        runtime.dispatch_replay(&mut transport).unwrap();
        let mut peer = PeerModel::new(
            Wire::new(
                row.profile,
                &row.keys,
                row.spis,
                crate::canonical_fixtures::opposite(row.direction),
            ),
            0,
            0,
            row.mode == Mode::Negotiated,
        );
        assert_eq!(
            peer.receive(transport.submitted.last().unwrap()),
            Ok(Event::NewRequest(0))
        );
        let response = peer
            .respond(
                0,
                PayloadChain::new(PayloadType::Notify, &[0, 0, 0, 8, 0, 0, 0, 7]),
            )
            .unwrap();
        assert!(ke::complete_initiator(
            &mut runtime,
            &provider,
            &mut store,
            19,
            &response,
            Cut::Applied
        )
        .unwrap()
        .is_none());
        land(&mut runtime, &provider, &mut store);
        assert!(runtime.row.closed && runtime.permit().check().is_err());
        assert_eq!(runtime.row.operations[&19].outcome, Outcome::InvalidSyntax);
        assert!(runtime.row.operations[&19].checkpoint.is_none());
        let before = transport.submitted.len();
        assert!(runtime.dispatch_replay(&mut transport).is_err());
        assert_eq!(transport.submitted.len(), before);
        drop(runtime);
        assert!(matches!(
            Runtime::restore(
                &provider,
                &owners,
                &store.fenced_read(&initial, row.key).unwrap(),
                false
            ),
            Err(driver::Error::Closed)
        ));
    });
}

#[test]
fn invalid_peer_ke_response_commits_terminal_outcome() {
    cases(9_110_000, |row, kind, short, cut| {
        let provider = Provider::new();
        let mut store = CasStore::new(7);
        let owners = EpochOwners::new(7);
        let initial = driver::create(&provider, &mut store, &row).unwrap();
        let mut runtime = Runtime::restore(
            &provider,
            &owners,
            &store.fenced_read(&initial, row.key).unwrap(),
            false,
        )
        .unwrap();
        runtime
            .reserve(
                &provider,
                &mut store,
                19,
                3,
                100,
                Cut::Complete,
                Cut::Complete,
            )
            .unwrap();
        let operation = ke::draft(&runtime.row, 19, kind);
        ke::persist_ke(
            &mut runtime,
            &provider,
            &mut store,
            operation,
            Cut::Complete,
        )
        .unwrap();
        let mut peer = PeerModel::new(
            Wire::new(
                row.profile,
                &row.keys,
                row.spis,
                crate::canonical_fixtures::opposite(row.direction),
            ),
            0,
            0,
            row.mode == Mode::Negotiated,
        );
        let mut transport = Transport::default();
        runtime.dispatch_replay(&mut transport).unwrap();
        assert_eq!(
            peer.receive(transport.submitted.last().unwrap()),
            Ok(Event::NewRequest(0))
        );
        let (first, body) = invalid_payload(&row, kind, true, short);
        let response = peer.respond(0, PayloadChain::new(first, &body)).unwrap();
        // Neither unauthenticated input nor an unavailable envelope provider
        // authorizes removal of the last recoverable checkpoint.
        let mut tampered = response.to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(ke::complete_initiator(
            &mut runtime,
            &provider,
            &mut store,
            19,
            &tampered,
            Cut::Complete
        )
        .is_err());
        provider.fail(Fault::Unavailable);
        assert_eq!(
            ke::complete_initiator(
                &mut runtime,
                &provider,
                &mut store,
                19,
                &response,
                Cut::Complete
            ),
            Err(driver::Error::Key(envelope::Error::Backpressure))
        );
        assert!(runtime.row.operations[&19].checkpoint.is_some());
        provider.fail(Fault::Healthy);
        runtime.resolve(&provider, &store, &initial).unwrap();
        let successor = RowKey(row.key.0 + 1_000_000);
        let result = if kind == KeKind::IkeRekey {
            handoff::finish_initiator(
                &mut runtime,
                &provider,
                &mut store,
                19,
                successor,
                &response,
                cut,
            )
        } else {
            ke::complete_initiator(&mut runtime, &provider, &mut store, 19, &response, cut)
                .map(|outcome| outcome.is_some())
        };
        assert_eq!(
            result,
            Ok(cut == Cut::Complete),
            "invalid peer KE must settle the exchange"
        );
        let image = stored(&provider, &store, row.key);
        let landed = matches!(cut, Cut::Applied | Cut::Acknowledged | Cut::Complete);
        assert_eq!(image.operations[&19].checkpoint.is_none(), landed);
        assert_eq!(
            image.operations[&19].outcome,
            if landed {
                Outcome::PeerKeRejected
            } else {
                Outcome::Pending
            }
        );
        assert_eq!(image.closed, landed && kind == KeKind::IkeRekey);
        assert!(store.inspect(successor).is_none());
        let before = transport.submitted.len();
        if cut != Cut::Complete {
            assert!(runtime.dispatch_replay(&mut transport).is_err());
            assert_eq!(transport.submitted.len(), before);
        }
        land(&mut runtime, &provider, &mut store);
        let operation = &runtime.row.operations[&19];
        assert!(!matches!(
            operation.outcome,
            Outcome::Pending | Outcome::Success
        ));
        assert!(operation.checkpoint.is_none() && operation.derived.is_none());
        assert_eq!(runtime.row.closed, kind == KeKind::IkeRekey);
        assert_eq!(operation.outcome, Outcome::PeerKeRejected);
        drop(runtime);
        let current = store.fenced_read(&initial, row.key).unwrap();
        if kind == KeKind::IkeRekey {
            assert!(matches!(
                Runtime::restore(&provider, &owners, &current, false),
                Err(driver::Error::Closed)
            ));
            let remedy::Recovery::Terminal(mut cleanup) =
                remedy::recover(&provider, &owners, current).unwrap()
            else {
                panic!("closed IKE SA revived");
            };
            assert!(cleanup.commit(&mut store, Cut::Complete).unwrap());
            assert!(store.inspect(row.key).is_none() && store.inspect(successor).is_none());
            return;
        }
        let mut runtime = Runtime::restore(&provider, &owners, &current, false).unwrap();
        // The peer installed the requested pair before sending its bad KE.
        // This small SAD is independent of the consumer operation record.
        let mut peer_children = std::collections::BTreeMap::from([
            (0x1112_1314_u32, 0x2122_2324_u32),
            (0x3132_3334, 0x5152_5354),
        ]);
        transport.submitted.clear();
        assert_eq!(
            ke::send_failed_child_delete(
                &mut runtime,
                &provider,
                &mut store,
                19,
                91,
                200,
                cut,
                &mut transport
            )
            .unwrap(),
            cut == Cut::Complete
        );
        if cut != Cut::Complete {
            assert!(transport.submitted.is_empty());
        }
        land(&mut runtime, &provider, &mut store);
        let delete = runtime
            .row
            .window
            .outbound
            .as_ref()
            .unwrap()
            .request()
            .to_vec();
        drop(runtime);
        let mut runtime = Runtime::restore(
            &provider,
            &owners,
            &store.fenced_read(&initial, row.key).unwrap(),
            false,
        )
        .unwrap();
        let publications = store.publications;
        ke::send_failed_child_delete(
            &mut runtime,
            &provider,
            &mut store,
            19,
            91,
            200,
            Cut::Complete,
            &mut transport,
        )
        .unwrap();
        assert_eq!(store.publications, publications);
        assert_eq!(transport.submitted.last().unwrap().as_ref(), delete);
        assert_eq!(peer.receive(&delete), Ok(Event::NewRequest(1)));
        let packet = peer.wire.open(&delete).unwrap();
        assert_eq!(packet.header.exchange_type, 37);
        assert_eq!(packet.first, PayloadType::Delete);
        assert_eq!(
            packet.body.as_ref(),
            [0, 0, 0, 12, 3, 4, 0, 1, 0x31, 0x32, 0x33, 0x34]
        );
        let removed = u32::from_be_bytes(packet.body[8..12].try_into().unwrap());
        assert_eq!(peer_children.remove(&removed), Some(0x5152_5354));
        assert_eq!(
            peer_children,
            std::collections::BTreeMap::from([(0x1112_1314, 0x2122_2324)])
        );
        let paired_delete = [0, 0, 0, 12, 3, 4, 0, 1, 0x51, 0x52, 0x53, 0x54];
        let reply = peer
            .respond(
                1,
                if short {
                    crate::canonical_fixtures::empty()
                } else {
                    PayloadChain::new(PayloadType::Delete, &paired_delete)
                },
            )
            .unwrap();
        assert_eq!(
            ke::finish_failed_child_delete(&mut runtime, &provider, &mut store, 19, &reply, cut)
                .unwrap()
                .is_some(),
            cut == Cut::Complete
        );
        land(&mut runtime, &provider, &mut store);
        drop(runtime);
        let mut runtime = Runtime::restore(
            &provider,
            &owners,
            &store.fenced_read(&initial, row.key).unwrap(),
            false,
        )
        .unwrap();
        assert_eq!(runtime.row.operations[&19].outcome, Outcome::PeerKeDeleted);
        let before = (store.publications, transport.submitted.len());
        assert!(!ke::send_failed_child_delete(
            &mut runtime,
            &provider,
            &mut store,
            19,
            91,
            200,
            Cut::Complete,
            &mut transport
        )
        .unwrap());
        assert_eq!(before, (store.publications, transport.submitted.len()));
        assert!(peer.alive());
    });
}
