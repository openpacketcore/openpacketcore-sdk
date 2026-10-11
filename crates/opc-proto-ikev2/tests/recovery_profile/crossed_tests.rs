//! Crossed IKE rekeys: separate peer-derived keys and packet-driven winner,
//! consumer atomic loser disposition, fenced child transfer and both Deletes.

use super::{
    authority::{EpochOwners, Transport},
    child_owners::ChildOwners,
    driver::{self, Cut, Runtime},
    envelope::Provider,
    handoff, ke,
    lifecycle::{child_delete, matrix},
    peer::{Event, PeerModel},
    peer_epochs::PeerEpochs,
    row::{KeKind, Outcome, Row},
    store::{self, CasStore, RowKey},
    wire::Wire,
};
use bytes::Bytes;
use opc_proto_ikev2::{
    derive_ike_sa_rekey_key_material, Ikev2EphemeralDhKey as Dh, Ikev2ExchangeKind as Exchange,
    Ikev2MessageIdSyncMode as Mode, Ikev2ProtectedPayloadDirection as Direction, PayloadChain,
};

fn delete_epoch(
    mut runtime: Runtime,
    peer: &mut PeerModel<'_>,
    provider: &Provider,
    store: &mut CasStore,
    ledger: &mut PeerEpochs,
    local_creator: bool,
) {
    let key = runtime.row.key;
    let spis = runtime.row.spis;
    let key_material = runtime.row.keys.clone();
    let receiver = Wire::new(
        runtime.row.profile,
        &key_material,
        spis,
        runtime.row.direction,
    );
    runtime
        .reserve_control(provider, store, 99, 1, 1000, Cut::Complete, Cut::Complete)
        .unwrap();
    let mut transport = Transport::default();
    if local_creator {
        let id = peer.counters().1.unwrap();
        runtime
            .publish_control_request(
                provider,
                store,
                Exchange::Informational,
                crate::canonical_fixtures::delete(),
                |_| {},
                Cut::Applied,
            )
            .unwrap();
        let write = runtime.pending.as_ref().unwrap().clone();
        assert!(runtime.dispatch_replay(&mut transport).is_err());
        assert!(transport.submitted.is_empty());
        runtime.resolve(provider, store, &write).unwrap();
        runtime.dispatch_replay(&mut transport).unwrap();
        let request = transport.submitted.last().unwrap();
        assert_eq!(peer.receive(request), Ok(Event::NewRequest(id)));
        ledger.observe(&peer.wire, request).unwrap();
        assert!(ledger.established(spis));
        assert!(store.inspect(key).is_some());
        let response = peer
            .respond(id, crate::canonical_fixtures::empty())
            .unwrap();
        ledger.observe(&receiver, &response).unwrap();
        runtime
            .complete(
                provider,
                store,
                &response,
                Bytes::from_static(b"ike-deleted"),
                |row| row.closed = true,
                Cut::Complete,
            )
            .unwrap();
    } else {
        let id = peer.counters().0.unwrap();
        let request = peer
            .request(37, crate::canonical_fixtures::delete())
            .unwrap();
        ledger.observe(&receiver, &request).unwrap();
        assert!(runtime
            .publish_delete_response(provider, store, &request, Cut::Applied)
            .unwrap()
            .is_none());
        let write = runtime.pending.as_ref().unwrap().clone();
        assert!(runtime.replay_response(&request, &mut transport).is_err());
        runtime.resolve(provider, store, &write).unwrap();
        assert_eq!(
            runtime.close_after_delete_reply(provider, store, &transport, Cut::Complete),
            Err(driver::Error::NotCommittedDelete)
        );
        runtime.replay_response(&request, &mut transport).unwrap();
        let response = transport.submitted.last().unwrap();
        assert_eq!(peer.receive(response), Ok(Event::Completed(id)));
        ledger.observe(&peer.wire, response).unwrap();
        assert_eq!(
            runtime.erase_after_delete(store, Cut::Complete),
            Err(driver::Error::NotCommittedDelete)
        );
        runtime
            .close_after_delete_reply(provider, store, &transport, Cut::Complete)
            .unwrap();
    }
    assert!(runtime.permit().check().is_err());
    assert!(runtime.dispatch_replay(&mut transport).is_err());
    runtime.erase_after_delete(store, Cut::Applied).unwrap();
    let erase = runtime.pending.as_ref().unwrap().clone();
    assert!(store.inspect(key).is_none());
    runtime.resolve_deletion(store, &erase).unwrap();
    runtime.delete().unwrap();
    assert!(!ledger.established(spis));
}

fn case(row: Row, minimum: usize, cut: Cut) {
    let provider = Provider::new();
    let mut store = CasStore::new(7);
    let owners = EpochOwners::new(7);
    let initial = driver::create(&provider, &mut store, &row).unwrap();
    let mut old = Runtime::restore(
        &provider,
        &owners,
        &store.fenced_read(&initial, row.key).unwrap(),
        false,
    )
    .unwrap();
    old.reserve_control(
        &provider,
        &mut store,
        1,
        2,
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
    let local_receiver = Wire::new(row.profile, &row.keys, row.spis, row.direction);
    let mut ledger = PeerEpochs::new(row.spis, &[11, 12]);
    let mut children = ChildOwners::new(&[11, 12], &row);
    let nonces: Vec<_> = (0..3)
        .map(|n| vec![if minimum == n { 5 } else { 0xc0 }; 64])
        .collect();
    let mut draft = ke::draft(&old.row, 31, KeKind::IkeRekey);
    draft.nonce_i = nonces[0].clone();
    let (first, transcript) = ke::payload(
        &row,
        KeKind::IkeRekey,
        false,
        row.profile.dh_group(),
        draft.spis.0,
        &draft.nonce_i,
        &draft.public,
    );
    draft.first_payload = first.as_u8();
    draft.transcript = transcript;
    ke::persist_ke(&mut old, &provider, &mut store, draft, Cut::Complete).unwrap();
    let mut transport = Transport::default();
    old.dispatch_replay(&mut transport).unwrap();
    let local_request = transport.submitted.last().unwrap().clone();
    assert_eq!(peer.receive(&local_request), Ok(Event::NewRequest(0)));
    ledger.observe(&peer.wire, &local_request).unwrap();
    let peer_initiator_dh = Dh::generate(row.profile.dh_group()).unwrap();
    let (first, payload) = ke::payload(
        &row,
        KeKind::IkeRekey,
        false,
        row.profile.dh_group(),
        0x7172_7374_7576_7778,
        &nonces[2],
        peer_initiator_dh.public_value(),
    );
    let peer_request = peer
        .request(36, PayloadChain::new(first, &payload))
        .unwrap();
    ledger.observe(&local_receiver, &peer_request).unwrap();
    let peer_key = RowKey(row.key.0 + 100_000);
    assert!(!handoff::finish_responder(
        &mut old,
        &provider,
        &mut store,
        32,
        peer_key,
        &peer_request,
        Cut::Applied
    )
    .unwrap());
    let responder_write = old.pending.as_ref().unwrap().clone();
    old.resolve(&provider, &store, &responder_write).unwrap();
    assert!(old.row.operations[&31].checkpoint.is_some());
    assert!(old.row.operations[&32].checkpoint.is_none());
    let peer_epoch = Runtime::restore(
        &provider,
        &owners,
        &store.fenced_read(&responder_write, peer_key).unwrap(),
        false,
    )
    .unwrap();
    assert!(children
        .transfer(&provider, &store, &responder_write, &old, &peer_epoch)
        .is_err());
    assert_eq!(children.owner(11), row.key);
    old.replay_response(&peer_request, &mut transport).unwrap();
    let peer_reply = transport.submitted.last().unwrap().clone();
    assert_eq!(peer.receive(&peer_reply), Ok(Event::Completed(0)));
    ledger.observe(&peer.wire, &peer_reply).unwrap();
    assert_eq!(ledger.child_owner(11), row.spis);
    let fields = ke::parts(
        &row,
        KeKind::IkeRekey,
        row.profile.dh_group(),
        &peer.wire.open(&peer_reply).unwrap(),
        true,
    )
    .unwrap();
    let secret = peer_initiator_dh.agree(&fields.public).unwrap();
    let peer_spis: (u64, u64) = (0x7172_7374_7576_7778, fields.spi);
    let peer_keys = derive_ike_sa_rekey_key_material(
        row.profile.prf(),
        row.keys.sk_d(),
        row.profile,
        peer_spis.0.to_be_bytes(),
        peer_spis.1.to_be_bytes(),
        &nonces[2],
        &fields.nonce,
        &secret,
    )
    .unwrap();
    drop(secret);
    drop(peer_initiator_dh);
    let peer_responder_dh = Dh::generate(row.profile.dh_group()).unwrap();
    let fields = ke::parts(
        &row,
        KeKind::IkeRekey,
        row.profile.dh_group(),
        &peer.wire.open(&local_request).unwrap(),
        false,
    )
    .unwrap();
    let secret = peer_responder_dh.agree(&fields.public).unwrap();
    let local_spis: (u64, u64) = (fields.spi, 0x6162_6364_6566_6768);
    let local_keys = derive_ike_sa_rekey_key_material(
        row.profile.prf(),
        row.keys.sk_d(),
        row.profile,
        local_spis.0.to_be_bytes(),
        local_spis.1.to_be_bytes(),
        &fields.nonce,
        &nonces[1],
        &secret,
    )
    .unwrap();
    drop(secret);
    let (first, payload) = ke::payload(
        &row,
        KeKind::IkeRekey,
        true,
        row.profile.dh_group(),
        local_spis.1,
        &nonces[1],
        peer_responder_dh.public_value(),
    );
    let local_reply = peer.respond(0, PayloadChain::new(first, &payload)).unwrap();
    drop(peer_responder_dh);
    ledger.observe(&local_receiver, &local_reply).unwrap();
    let local_key = RowKey(row.key.0 + 200_000);
    let prior = store.inspect(row.key).unwrap().envelope.clone();
    assert!(!handoff::finish_initiator(
        &mut old,
        &provider,
        &mut store,
        31,
        local_key,
        &local_reply,
        cut
    )
    .unwrap());
    let finish = old.pending.as_ref().unwrap().clone();
    assert!(children
        .transfer(&provider, &store, &finish, &old, &peer_epoch)
        .is_err());
    if matches!(cut, Cut::BeforeDispatch | Cut::Dispatched) {
        store.dispatch(finish.clone()).unwrap();
        assert_eq!(
            store.apply_with_cut(finish.request(), true),
            Err(store::Error::InterruptedBeforePublish)
        );
        assert!(store.inspect(local_key).is_none());
        assert!(store.inspect(row.key).unwrap().envelope == prior);
        store.apply(finish.request()).unwrap();
    }
    store.prune(finish.request());
    old.resolve(&provider, &store, &finish).unwrap();
    let local_epoch = Runtime::restore(
        &provider,
        &owners,
        &store.fenced_read(&finish, local_key).unwrap(),
        false,
    )
    .unwrap();
    let local_loses = minimum < 2;
    let loser_id = if local_loses { 31 } else { 32 };
    let winner_id = if local_loses { 32 } else { 31 };
    assert_eq!(old.row.operations[&loser_id].outcome, Outcome::CrossedLoss);
    assert!(old.row.operations[&loser_id].checkpoint.is_none());
    assert!(old.row.operations[&loser_id].derived.is_none());
    assert_eq!(old.row.operations[&winner_id].outcome, Outcome::Success);
    assert!(old.row.operations[&winner_id].checkpoint.is_none());
    let mut local_peer = PeerModel::new(
        Wire::new(
            row.profile,
            &local_keys,
            local_spis,
            Direction::ResponderToInitiator,
        ),
        0,
        0,
        row.mode == Mode::Negotiated,
    );
    let mut remote_peer = PeerModel::new(
        Wire::new(
            row.profile,
            &peer_keys,
            peer_spis,
            Direction::InitiatorToResponder,
        ),
        0,
        0,
        row.mode == Mode::Negotiated,
    );
    let (mut winner, loser, winner_peer, loser_peer, winner_is_local) = if local_loses {
        (
            peer_epoch,
            local_epoch,
            &mut remote_peer,
            &mut local_peer,
            false,
        )
    } else {
        (
            local_epoch,
            peer_epoch,
            &mut local_peer,
            &mut remote_peer,
            true,
        )
    };
    assert_eq!(ledger.loser(), Some(loser.row.spis));
    assert_eq!(ledger.child_owner(11), winner.row.spis);
    assert!(children
        .transfer(&provider, &store, &finish, &old, &loser)
        .is_err());
    assert!(children
        .transfer(&provider, &store, &finish, &old, &winner)
        .unwrap());
    assert!(!children
        .transfer(&provider, &store, &finish, &old, &winner)
        .unwrap());
    assert_eq!(children.owner(11), winner.row.key);
    assert_eq!(children.owner(12), winner.row.key);
    assert_eq!(children.changes, 2);
    winner
        .reserve(
            &provider,
            &mut store,
            91,
            1,
            150,
            Cut::Complete,
            Cut::Complete,
        )
        .unwrap();
    winner
        .publish_request(
            &provider,
            &mut store,
            Exchange::Informational,
            child_delete(),
            |_| {},
            Cut::Complete,
        )
        .unwrap();
    winner.dispatch_replay(&mut transport).unwrap();
    assert_eq!(
        winner_peer.receive(transport.submitted.last().unwrap()),
        Ok(Event::NewRequest(0))
    );
    let reply = winner_peer
        .respond(0, crate::canonical_fixtures::empty())
        .unwrap();
    winner
        .complete(
            &provider,
            &mut store,
            &reply,
            Bytes::from_static(b"child-deleted"),
            |_| {},
            Cut::Complete,
        )
        .unwrap();
    let loser_key = loser.row.key;
    delete_epoch(
        loser,
        loser_peer,
        &provider,
        &mut store,
        &mut ledger,
        !winner_is_local,
    );
    assert!(store.inspect(row.key).is_some());
    assert!(store.inspect(loser_key).is_none());
    assert!(store.inspect(winner.row.key).is_some());
    delete_epoch(
        old,
        &mut peer,
        &provider,
        &mut store,
        &mut ledger,
        winner_is_local,
    );
    assert!(store.inspect(winner.row.key).is_some());
    assert_eq!(ledger.child_owner(12), winner.row.spis);
    assert_eq!(children.owner(12), winner.row.key);
    assert!(winner.permit().check().is_ok());
}

#[test]
fn crossed_rekey_commits_loser_then_transfers_children_once_and_deletes_only_old_and_loser() {
    for minimum in 0..4 {
        for (index, cut) in [
            Cut::BeforeDispatch,
            Cut::Dispatched,
            Cut::Applied,
            Cut::Acknowledged,
        ]
        .into_iter()
        .enumerate()
        {
            matrix(1_200_000 + ((minimum * 4 + index) * 1000) as u64, |row| {
                case(row, minimum, cut)
            });
        }
    }
}

#[test]
fn crossed_rekey_smoke() {
    let mut tag = 1_250_000;
    for minimum in 0..4 {
        for cut in [
            Cut::BeforeDispatch,
            Cut::Dispatched,
            Cut::Applied,
            Cut::Acknowledged,
        ] {
            for profile in [
                crate::canonical_fixtures::profile(crate::canonical_fixtures::ALGORITHMS[0]),
                super::cbc::profiles().next().unwrap(),
            ] {
                for direction in crate::canonical_fixtures::DIRECTIONS {
                    for mode in [Mode::BaseFallback, Mode::Negotiated] {
                        case(
                            super::inputs::fresh(tag, profile, direction, mode),
                            minimum,
                            cut,
                        );
                        tag += 1;
                    }
                }
            }
        }
    }
}
