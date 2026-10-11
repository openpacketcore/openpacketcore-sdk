use super::{
    authority::{EpochOwners, Transport},
    driver::{self, Cut, Runtime},
    effects::{Direction, Effects, Error},
    envelope::Provider,
    lifecycle::{child_delete, matrix},
    peer::{Event, PeerModel},
    store::CasStore,
    wire::Wire,
};
use bytes::Bytes;
use opc_proto_ikev2::{Ikev2ExchangeKind as Exchange, Ikev2MessageIdSyncMode as Mode};

#[test]
fn mode_and_effect_authority_requires_current_committed_outcome_once() {
    for (cut_id, cut) in [
        Cut::BeforeDispatch,
        Cut::Dispatched,
        Cut::Applied,
        Cut::Acknowledged,
    ]
    .into_iter()
    .enumerate()
    {
        for (direction_id, direction) in [Direction::Local, Direction::Peer].into_iter().enumerate()
        {
            matrix(
                600_000 + (cut_id * 2 + direction_id) as u64 * 1_000,
                |row| {
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
                    let mut effects = Effects::default();
                    assert_eq!(
                        effects.apply(&provider, &store, &initial, &runtime, direction),
                        Err(Error::NotCommitted)
                    );
                    runtime
                        .reserve(
                            &provider,
                            &mut store,
                            1,
                            1,
                            100,
                            Cut::Complete,
                            Cut::Complete,
                        )
                        .unwrap();
                    let mut transport = Transport::default();
                    let peer_request = match direction {
                        Direction::Local => {
                            runtime
                                .publish_request(
                                    &provider,
                                    &mut store,
                                    Exchange::Informational,
                                    child_delete(),
                                    |_| {},
                                    Cut::Complete,
                                )
                                .unwrap();
                            assert_eq!(
                                effects.apply(&provider, &store, &initial, &runtime, direction),
                                Err(Error::NotCommitted)
                            );
                            runtime.dispatch_replay(&mut transport).unwrap();
                            assert_eq!(
                                peer.receive(transport.submitted.last().unwrap()),
                                Ok(Event::NewRequest(0))
                            );
                            let response = peer.respond(0, child_delete()).unwrap();
                            assert!(runtime
                                .complete(
                                    &provider,
                                    &mut store,
                                    &response,
                                    Bytes::from_static(b"effect-result"),
                                    |_| {},
                                    cut
                                )
                                .unwrap()
                                .is_none());
                            None
                        }
                        Direction::Peer => {
                            let request = peer.request(37, child_delete()).unwrap();
                            assert!(runtime
                                .publish_response(
                                    &provider,
                                    &mut store,
                                    &request,
                                    child_delete(),
                                    Bytes::from_static(b"effect-result"),
                                    |_| {},
                                    cut
                                )
                                .unwrap()
                                .is_none());
                            Some(request)
                        }
                    };
                    let write = runtime.pending.as_ref().unwrap().clone();
                    assert_eq!(
                        effects.apply(&provider, &store, &write, &runtime, direction),
                        Err(Error::NotCommitted)
                    );
                    assert!(effects.outcomes.is_empty());
                    store.dispatch(write.clone()).unwrap();
                    store.apply(write.request()).unwrap();
                    store.prune(write.request());
                    runtime.resolve(&provider, &store, &write).unwrap();
                    assert!(effects
                        .apply(&provider, &store, &write, &runtime, direction)
                        .unwrap());
                    assert!(!effects
                        .apply(&provider, &store, &write, &runtime, direction)
                        .unwrap());
                    assert_eq!(effects.outcomes, [Bytes::from_static(b"effect-result")]);
                    if let Some(request) = &peer_request {
                        runtime.replay_response(request, &mut transport).unwrap();
                        assert_eq!(
                            peer.receive(transport.submitted.last().unwrap()),
                            Ok(Event::Completed(0))
                        );
                        runtime.replay_response(request, &mut transport).unwrap();
                        assert_eq!(
                            peer.receive(transport.submitted.last().unwrap()),
                            Ok(Event::Ignored)
                        );
                    } else {
                        assert!(!runtime.dispatch_replay(&mut transport).unwrap());
                    }
                    // An unrelated complete-row commit never creates a new effect
                    // identity for the retained result.
                    runtime
                        .reserve(
                            &provider,
                            &mut store,
                            2,
                            1,
                            120,
                            Cut::Complete,
                            Cut::Complete,
                        )
                        .unwrap();
                    assert!(!effects
                        .apply(&provider, &store, &write, &runtime, direction)
                        .unwrap());
                    runtime.revoke();
                    assert!(matches!(
                        effects.apply(&provider, &store, &write, &runtime, direction),
                        Err(Error::Driver(driver::Error::Owner(_)))
                    ));
                    drop(runtime);
                    let restored = Runtime::restore(
                        &provider,
                        &owners,
                        &store.fenced_read(&write, row.key).unwrap(),
                        false,
                    )
                    .unwrap();
                    assert!(!effects
                        .apply(&provider, &store, &write, &restored, direction)
                        .unwrap());
                    assert_eq!(effects.outcomes.len(), 1);
                },
            );
        }
    }
}
