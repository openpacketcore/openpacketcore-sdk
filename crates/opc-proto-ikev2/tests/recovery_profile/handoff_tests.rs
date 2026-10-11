//! Old-result/new-epoch atomicity and authenticated traffic on both epochs.

use super::{
    authority::{EpochOwners, Transport},
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
    Ikev2MessageIdSyncMode as Mode, Ikev2ProtectedPayloadDirection as Direction,
    Ikev2SaInitKeyMaterial as Keys, PayloadChain,
};

fn expected_keys(
    row: &Row,
    spis: (u64, u64),
    ni: &[u8],
    nr: &[u8],
    dh: &Dh,
    remote: &[u8],
) -> Keys {
    let secret = dh.agree(remote).unwrap();
    derive_ike_sa_rekey_key_material(
        row.profile.prf(),
        row.keys.sk_d(),
        row.profile,
        spis.0.to_be_bytes(),
        spis.1.to_be_bytes(),
        ni,
        nr,
        &secret,
    )
    .unwrap()
}

fn assert_keys(actual: &Keys, expected: &Keys) {
    assert!(actual.sk_d() == expected.sk_d());
    assert!(actual.sk_ai() == expected.sk_ai());
    assert!(actual.sk_ar() == expected.sk_ar());
    assert!(actual.sk_ei() == expected.sk_ei());
    assert!(actual.sk_er() == expected.sk_er());
    assert!(actual.sk_pi() == expected.sk_pi());
    assert!(actual.sk_pr() == expected.sk_pr());
}

fn case(row: Row, local_initiated: bool, cut: Cut) {
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
        11,
        2,
        100,
        Cut::Complete,
        Cut::Complete,
    )
    .unwrap();
    let peer_direction = crate::canonical_fixtures::opposite(row.direction);
    let mut peer = PeerModel::new(
        Wire::new(row.profile, &row.keys, row.spis, peer_direction),
        0,
        0,
        row.mode == Mode::Negotiated,
    );
    let local_wire = Wire::new(row.profile, &row.keys, row.spis, row.direction);
    let mut ledger = PeerEpochs::new(row.spis, &[11, 12]);
    let new_key = RowKey(row.key.0 + 100_000);
    assert!(matches!(
        Runtime::restore(
            &provider,
            &owners,
            &store.fenced_read(&initial, new_key).unwrap(),
            false
        ),
        Err(driver::Error::Closed)
    ));
    assert_eq!(
        old.erase_after_delete(&mut store, Cut::Complete),
        Err(driver::Error::NotCommittedDelete)
    );
    let mut transport = Transport::default();
    let request;
    let mut response = Bytes::new();
    let peer_dh = Dh::generate(row.profile.dh_group()).unwrap();
    let expected;
    let expected_spis;
    if local_initiated {
        let draft = ke::draft(&old.row, 31, KeKind::IkeRekey);
        ke::persist_ke(&mut old, &provider, &mut store, draft, Cut::Complete).unwrap();
        old.dispatch_replay(&mut transport).unwrap();
        request = transport.submitted.last().unwrap().clone();
        assert_eq!(peer.receive(&request), Ok(Event::NewRequest(0)));
        ledger.observe(&peer.wire, &request).unwrap();
        let packet = peer.wire.open(&request).unwrap();
        let fields = ke::parts(
            &row,
            KeKind::IkeRekey,
            row.profile.dh_group(),
            &packet,
            false,
        )
        .unwrap();
        let nr = vec![0x73; 64];
        expected_spis = (fields.spi, 0x6162_6364_6566_6768);
        expected = Some(expected_keys(
            &row,
            expected_spis,
            &fields.nonce,
            &nr,
            &peer_dh,
            &fields.public,
        ));
        let (first, payload) = ke::payload(
            &row,
            KeKind::IkeRekey,
            true,
            row.profile.dh_group(),
            expected_spis.1,
            &nr,
            peer_dh.public_value(),
        );
        response = peer.respond(0, PayloadChain::new(first, &payload)).unwrap();
        ledger.observe(&local_wire, &response).unwrap();
    } else {
        let (first, payload) = ke::payload(
            &row,
            KeKind::IkeRekey,
            false,
            row.profile.dh_group(),
            0x7172_7374_7576_7778,
            &[0x63; 64],
            peer_dh.public_value(),
        );
        request = peer
            .request(36, PayloadChain::new(first, &payload))
            .unwrap();
        ledger.observe(&local_wire, &request).unwrap();
        expected = None;
        expected_spis = (0x7172_7374_7576_7778, 0x5152_5354_5556_5758);
    }
    let prior = store.inspect(row.key).unwrap().clone();
    let publications = store.publications;
    let result = if local_initiated {
        handoff::finish_initiator(&mut old, &provider, &mut store, 31, new_key, &response, cut)
    } else {
        handoff::finish_responder(&mut old, &provider, &mut store, 31, new_key, &request, cut)
    }
    .unwrap();
    assert!(!result);
    let pending = old.pending.as_ref().unwrap().clone();
    assert_eq!(pending.mutations().len(), 2);
    if matches!(cut, Cut::BeforeDispatch | Cut::Dispatched) {
        assert!(store.inspect(new_key).is_none());
        assert!(store.inspect(row.key).unwrap().envelope == prior.envelope);
        assert!(matches!(
            store.fenced_read(&pending, new_key),
            Err(store::Error::PriorMayStillApply)
        ));
        store.dispatch(pending.clone()).unwrap();
        assert_eq!(
            store.apply_with_cut(pending.request(), true),
            Err(store::Error::InterruptedBeforePublish)
        );
        assert!(store.inspect(new_key).is_none());
        assert!(store.inspect(row.key).unwrap().envelope == prior.envelope);
        assert_eq!(store.publications, publications);
        store.apply(pending.request()).unwrap();
    }
    assert_eq!(
        store.publications,
        publications + 1,
        "one atomic publication"
    );
    // Neither raw inspection nor the candidate itself is a runtime capability.
    store.prune(pending.request());
    assert_eq!(store.acknowledge(&pending), Err(store::Error::Unknown));
    old.resolve(&provider, &store, &pending).unwrap();
    assert_eq!(old.row.operations[&31].outcome, Outcome::Success);
    assert!(old.row.operations[&31].checkpoint.is_none());
    assert!(store.inspect(row.key).is_some());
    let next_cut = store.fenced_read(&pending, new_key).unwrap();
    let mut next = Runtime::restore(&provider, &owners, &next_cut, false).unwrap();
    assert_eq!(next.row.spis, expected_spis);
    assert_eq!(
        next.row.direction,
        if local_initiated {
            Direction::InitiatorToResponder
        } else {
            Direction::ResponderToInitiator
        }
    );
    assert_eq!(next.row.mode, row.mode);
    assert_eq!(next.row.agreement.mode(), row.mode);
    assert_eq!(next.row.window.next_send, Some(0));
    assert_eq!(next.row.window.next_receive, Some(0));
    assert!(next.row.window.outbound.is_none() && next.row.window.inbound.is_none());
    assert!(next.row.window.recovery.is_none());
    assert!(next.row.operations.is_empty());
    assert!(next
        .row
        .iv
        .as_ref()
        .is_none_or(|iv| iv.end == 0 && iv.retries.is_empty()));
    assert_eq!(
        (next.row.identity, next.row.namespace, next.row.endpoint),
        (row.identity, row.namespace, row.endpoint)
    );
    let expected = if let Some(keys) = expected {
        keys
    } else {
        old.replay_response(&request, &mut transport).unwrap();
        let reply = transport.submitted.last().unwrap().clone();
        assert_eq!(peer.receive(&reply), Ok(Event::Completed(0)));
        ledger.observe(&peer.wire, &reply).unwrap();
        let packet = peer.wire.open(&reply).unwrap();
        let fields = ke::parts(
            &row,
            KeKind::IkeRekey,
            row.profile.dh_group(),
            &packet,
            true,
        )
        .unwrap();
        old.replay_response(&request, &mut transport).unwrap();
        assert_eq!(transport.submitted.last().unwrap(), &reply);
        assert_eq!(peer.receive(&reply), Ok(Event::Ignored));
        expected_keys(
            &row,
            expected_spis,
            &[0x63; 64],
            &fields.nonce,
            &peer_dh,
            &fields.public,
        )
    };
    drop(peer_dh);
    assert_keys(&next.row.keys, &expected);
    assert!(ledger.established(expected_spis));
    assert!(ledger.established(row.spis));
    assert_eq!(ledger.child_owner(11), expected_spis);
    assert_eq!(ledger.child_owner(12), expected_spis);
    assert_eq!(
        old.erase_after_delete(&mut store, Cut::Complete),
        Err(driver::Error::NotCommittedDelete)
    );
    assert!(!old.dispatch_replay(&mut transport).unwrap());
    let mut peer_new = PeerModel::new(
        Wire::new(
            row.profile,
            &expected,
            expected_spis,
            if local_initiated {
                Direction::ResponderToInitiator
            } else {
                Direction::InitiatorToResponder
            },
        ),
        0,
        0,
        row.mode == Mode::Negotiated,
    );
    next.reserve(
        &provider,
        &mut store,
        91,
        1,
        150,
        Cut::Complete,
        Cut::Complete,
    )
    .unwrap();
    next.publish_request(
        &provider,
        &mut store,
        Exchange::Informational,
        child_delete(),
        |_| {},
        Cut::Complete,
    )
    .unwrap();
    next.dispatch_replay(&mut transport).unwrap();
    let fresh = transport.submitted.last().unwrap();
    assert_eq!(peer_new.receive(fresh), Ok(Event::NewRequest(0)));
    ledger.observe(&peer_new.wire, fresh).unwrap();
    let fresh_response = peer_new
        .respond(0, crate::canonical_fixtures::empty())
        .unwrap();
    next.complete(
        &provider,
        &mut store,
        &fresh_response,
        Bytes::from_static(b"child-deleted"),
        |_| {},
        Cut::Complete,
    )
    .unwrap();
    // Keep the old row/replay until its genuine Delete exchange has a result.
    old.publish_control_request(
        &provider,
        &mut store,
        Exchange::Informational,
        crate::canonical_fixtures::delete(),
        |_| {},
        Cut::Applied,
    )
    .unwrap();
    let deletion = old.pending.as_ref().unwrap().clone();
    assert!(store.inspect(row.key).is_some());
    assert!(old.dispatch_replay(&mut transport).is_err());
    old.resolve(&provider, &store, &deletion).unwrap();
    old.dispatch_replay(&mut transport).unwrap();
    let delete_packet = transport.submitted.last().unwrap().clone();
    let delete_id = u32::from(local_initiated);
    assert_eq!(
        peer.receive(&delete_packet),
        Ok(Event::NewRequest(delete_id))
    );
    ledger.observe(&peer.wire, &delete_packet).unwrap();
    assert!(ledger.established(row.spis));
    assert_eq!(
        old.publish_control_request(
            &provider,
            &mut store,
            Exchange::Informational,
            child_delete(),
            |_| {},
            Cut::Complete
        ),
        Err(driver::Error::Closed)
    );
    let deleted = peer
        .respond(delete_id, crate::canonical_fixtures::empty())
        .unwrap();
    ledger.observe(&local_wire, &deleted).unwrap();
    old.complete(
        &provider,
        &mut store,
        &deleted,
        Bytes::from_static(b"ike-deleted"),
        |row| row.closed = true,
        Cut::Complete,
    )
    .unwrap();
    assert!(old.permit().check().is_err());
    assert!(old.dispatch_replay(&mut transport).is_err());
    assert!(transport.submit(&old.permit(), &delete_packet).is_err());
    assert!(!old.erase_after_delete(&mut store, Cut::Applied).unwrap());
    let erasure = old.pending.as_ref().unwrap().clone();
    assert!(store.inspect(row.key).is_none());
    assert!(store.inspect(new_key).is_some());
    old.resolve_deletion(&store, &erasure).unwrap();
    old.delete().unwrap();
    assert!(!ledger.established(row.spis));
    assert!(ledger.established(expected_spis));
    assert!(next.permit().check().is_ok());
    assert_eq!(ledger.child_owner(12), expected_spis);
}

#[test]
fn atomic_ike_rekey_handoff_preserves_old_epoch_until_committed_delete() {
    for (cut_id, cut) in [
        Cut::BeforeDispatch,
        Cut::Dispatched,
        Cut::Applied,
        Cut::Acknowledged,
    ]
    .into_iter()
    .enumerate()
    {
        for (role, local_initiated) in [true, false].into_iter().enumerate() {
            matrix(900_000 + (cut_id * 2 + role) as u64 * 1000, |row| {
                case(row, local_initiated, cut)
            });
        }
    }
}
