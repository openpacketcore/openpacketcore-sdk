use super::{
    authority::{EpochOwners, Transport},
    driver::{self, Cut, Runtime},
    endpoint::{Routes, Topology},
    envelope::Provider,
    lifecycle::{child_delete, matrix},
    module,
    peer::{Event, PeerModel},
    store::CasStore,
    wire::Wire,
};
use bytes::Bytes;
use opc_proto_ikev2::{recovery::Ikev2WindowError as Window, Ikev2MessageIdSyncMode as Mode};
const OLD: (u32, u16) = (0xc0000201, 4500);
const NEW: (u32, u16) = (0xc0000202, 4501);
const CANDIDATE: (u32, u16) = (0xc0000203, 4502);

#[test]
fn endpoint_freshness_separate_cas_and_authenticated_new_request_control_route_changes() {
    matrix(2_700_000, |mut row| {
        row.endpoint = Some(OLD);
        let provider = Provider::new();
        let mut store = CasStore::new(7);
        let owners = EpochOwners::new(7);
        let initial = driver::create(&provider, &mut store, &row).unwrap();
        let joined = store.fenced_read(&initial, row.key).unwrap();
        let mut runtime = Runtime::restore(&provider, &owners, &joined, true).unwrap();
        let mut routes = Routes::default();
        routes.adopt(&provider, &store, &joined, &runtime).unwrap();
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
        let request = peer.request(37, child_delete()).unwrap();
        runtime
            .reserve(
                &provider,
                &mut store,
                19,
                1,
                100,
                Cut::Complete,
                Cut::Complete,
            )
            .unwrap();
        runtime
            .publish_response(
                &provider,
                &mut store,
                &request,
                crate::canonical_fixtures::empty(),
                Bytes::from_static(b"child-deleted"),
                |_| {},
                Cut::Complete,
            )
            .unwrap();
        let mut transport = Transport::default();
        runtime.replay_response(&request, &mut transport).unwrap();
        assert_eq!(
            peer.receive(transport.submitted.last().unwrap()),
            Ok(Event::Completed(0))
        );
        let empty = peer
            .request(37, crate::canonical_fixtures::empty())
            .unwrap();
        let before = (store.publications, provider.calls(), module::counts());
        assert!(!runtime
            .endpoint_empty(
                &provider,
                &mut store,
                &empty,
                NEW,
                Topology::PeerNat,
                Cut::Applied,
                &mut transport
            )
            .unwrap());
        // The empty reply is released, but an unacknowledged endpoint result is not a route.
        assert_eq!(
            peer.receive(transport.submitted.last().unwrap()),
            Ok(Event::Completed(1))
        );
        assert_eq!(store.publications, before.0 + 1);
        assert_eq!(provider.calls(), (before.1 .0 + 1, before.1 .1));
        let after = module::counts();
        assert_eq!(after.entropy, before.2.entropy);
        assert_eq!(routes.get(&runtime), Some(OLD));
        assert!(routes.adopt(&provider, &store, &joined, &runtime).is_err());
        let pending = runtime.pending.as_ref().unwrap().clone();
        store.prune(pending.request());
        runtime.resolve(&provider, &store, &pending).unwrap();
        assert!(routes.adopt(&provider, &store, &joined, &runtime).unwrap());
        assert_eq!(routes.get(&runtime), Some(NEW));
        let before = (
            store.publications,
            provider.calls(),
            module::counts(),
            routes.changes,
        );
        assert!(!runtime
            .endpoint_empty(
                &provider,
                &mut store,
                &empty,
                OLD,
                Topology::PeerNat,
                Cut::Complete,
                &mut transport
            )
            .unwrap());
        assert_eq!(
            (
                store.publications,
                provider.calls(),
                module::counts(),
                routes.changes
            ),
            before
        );
        drop(runtime);
        runtime = Runtime::restore(
            &provider,
            &owners,
            &store.fenced_read(&initial, row.key).unwrap(),
            true,
        )
        .unwrap();
        let unknown = peer
            .request(37, crate::canonical_fixtures::empty())
            .unwrap();
        let before = store.publications;
        assert!(!runtime
            .endpoint_empty(
                &provider,
                &mut store,
                &unknown,
                CANDIDATE,
                Topology::PeerNat,
                Cut::Complete,
                &mut transport
            )
            .unwrap());
        assert_eq!(
            peer.receive(transport.submitted.last().unwrap()),
            Ok(Event::Completed(2))
        );
        assert_eq!(store.publications, before);
        assert_eq!(routes.get(&runtime), Some(NEW));
        runtime
            .reserve(
                &provider,
                &mut store,
                29,
                1,
                150,
                Cut::Complete,
                Cut::Complete,
            )
            .unwrap();
        let probe = runtime
            .begin_probe(
                &provider,
                &mut store,
                CANDIDATE,
                child_delete(),
                Cut::Complete,
            )
            .unwrap()
            .unwrap();
        assert_eq!(routes.get(&runtime), Some(NEW));
        runtime.dispatch_probe(&probe, &mut transport).unwrap();
        assert_eq!(transport.destinations.last(), Some(&Some(CANDIDATE)));
        assert_eq!(
            peer.receive(transport.submitted.last().unwrap()),
            Ok(Event::NewRequest(0))
        );
        let response = peer.respond(0, crate::canonical_fixtures::empty()).unwrap();
        let before = store.publications;
        assert_eq!(
            runtime.complete_probe(&provider, &mut store, &probe, &response, OLD, Cut::Complete),
            Err(driver::Error::Window(Window::Drop))
        );
        let mut corrupt = response.to_vec();
        *corrupt.last_mut().unwrap() ^= 1;
        assert_eq!(
            runtime.complete_probe(
                &provider,
                &mut store,
                &probe,
                &corrupt,
                CANDIDATE,
                Cut::Complete
            ),
            Err(driver::Error::Window(Window::Drop))
        );
        assert_eq!(store.publications, before);
        assert_eq!(routes.get(&runtime), Some(NEW));
        assert!(!runtime
            .complete_probe(
                &provider,
                &mut store,
                &probe,
                &response,
                CANDIDATE,
                Cut::Applied
            )
            .unwrap());
        assert_eq!(routes.get(&runtime), Some(NEW));
        let write = runtime.pending.as_ref().unwrap().clone();
        runtime.resolve(&provider, &store, &write).unwrap();
        routes.adopt(&provider, &store, &joined, &runtime).unwrap();
        assert_eq!(routes.get(&runtime), Some(CANDIDATE));
        assert!(runtime
            .complete_probe(&provider, &mut store, &probe, &response, OLD, Cut::Complete)
            .is_err());
    });
}

#[test]
fn endpoint_pending_or_restored_requests_do_not_become_new_probes() {
    matrix(2_710_000, |mut row| {
        row.endpoint = Some(OLD);
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
                1,
                100,
                Cut::Complete,
                Cut::Complete,
            )
            .unwrap();
        let probe = runtime
            .begin_probe(
                &provider,
                &mut store,
                CANDIDATE,
                child_delete(),
                Cut::Complete,
            )
            .unwrap()
            .unwrap();
        let mut transport = Transport::default();
        runtime.dispatch_probe(&probe, &mut transport).unwrap();
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
        let response = peer.respond(0, crate::canonical_fixtures::empty()).unwrap();
        drop(runtime);
        runtime = Runtime::restore(
            &provider,
            &owners,
            &store.fenced_read(&initial, row.key).unwrap(),
            false,
        )
        .unwrap();
        let before = (
            store.publications,
            provider.calls(),
            module::counts(),
            transport.submitted.len(),
        );
        assert!(matches!(
            runtime.begin_probe(&provider, &mut store, NEW, child_delete(), Cut::Complete),
            Err(driver::Error::Window(Window::RequestOutstanding))
        ));
        assert!(runtime.dispatch_probe(&probe, &mut transport).is_err());
        assert!(runtime
            .complete_probe(
                &provider,
                &mut store,
                &probe,
                &response,
                CANDIDATE,
                Cut::Complete
            )
            .is_err());
        assert_eq!(
            (
                store.publications,
                provider.calls(),
                module::counts(),
                transport.submitted.len()
            ),
            before
        );
        runtime
            .complete(
                &provider,
                &mut store,
                &response,
                Bytes::from_static(b"child-deleted"),
                |row| row.challenge = None,
                Cut::Complete,
            )
            .unwrap();
        assert_eq!(runtime.row.endpoint, Some(OLD));
    });
}

#[test]
fn local_nat_and_mobike_never_use_the_peer_nat_heuristic() {
    for topology in [Topology::LocalNat, Topology::Mobike] {
        matrix(
            2_720_000
                + if topology == Topology::Mobike {
                    1000
                } else {
                    0
                },
            |mut row| {
                row.endpoint = Some(OLD);
                let provider = Provider::new();
                let mut store = CasStore::new(7);
                let owners = EpochOwners::new(7);
                let initial = driver::create(&provider, &mut store, &row).unwrap();
                let mut runtime = Runtime::restore(
                    &provider,
                    &owners,
                    &store.fenced_read(&initial, row.key).unwrap(),
                    true,
                )
                .unwrap();
                let wire = Wire::new(
                    row.profile,
                    &row.keys,
                    row.spis,
                    crate::canonical_fixtures::opposite(row.direction),
                );
                let request = wire.seal(0, false, 37, child_delete());
                runtime
                    .reserve(
                        &provider,
                        &mut store,
                        19,
                        1,
                        100,
                        Cut::Complete,
                        Cut::Complete,
                    )
                    .unwrap();
                runtime
                    .publish_response(
                        &provider,
                        &mut store,
                        &request,
                        crate::canonical_fixtures::empty(),
                        Bytes::from_static(b"child-deleted"),
                        |_| {},
                        Cut::Complete,
                    )
                    .unwrap();
                let empty = wire.seal(1, false, 37, crate::canonical_fixtures::empty());
                let before = store.publications;
                assert!(!runtime
                    .endpoint_empty(
                        &provider,
                        &mut store,
                        &empty,
                        NEW,
                        topology,
                        Cut::Complete,
                        &mut Transport::default()
                    )
                    .unwrap());
                assert_eq!(store.publications, before);
                assert_eq!(runtime.row.endpoint, Some(OLD));
            },
        );
    }
}
