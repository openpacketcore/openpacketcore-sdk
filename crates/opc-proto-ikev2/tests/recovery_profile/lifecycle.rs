//! Store/owner/window compositions. Every released packet is consumed by the
//! independent peer. Process-loss cases extend these schedules separately.

use super::{
    authority::{EpochOwners, Transport},
    driver::{self, Cut, Runtime},
    envelope::Provider,
    inputs, module,
    peer::{Event, PeerModel, REQUEST_TIMEOUT_MS},
    row::Row,
    store::{self, CasStore},
    wire::Wire,
};
use bytes::Bytes;
use opc_proto_ikev2::{
    recovery::{Ikev2OrdinaryRequestDisposition as Disposition, Ikev2WindowError},
    Ikev2ExchangeKind as Exchange, Ikev2MessageIdSyncMode as Mode, PayloadChain, PayloadType,
};

pub fn child_delete() -> PayloadChain<'static> {
    PayloadChain::new(PayloadType::Delete, &[0, 0, 0, 12, 3, 4, 0, 1, 1, 2, 3, 4])
}
fn changed_delete() -> PayloadChain<'static> {
    PayloadChain::new(PayloadType::Delete, &[0, 0, 0, 12, 3, 4, 0, 1, 1, 2, 3, 5])
}
pub fn matrix(base: u64, mut test: impl FnMut(Row)) {
    for (profile_id, profile) in inputs::profiles().enumerate() {
        for (role, direction) in crate::canonical_fixtures::DIRECTIONS
            .into_iter()
            .enumerate()
        {
            for (mode_id, mode) in [Mode::BaseFallback, Mode::Negotiated]
                .into_iter()
                .enumerate()
            {
                test(inputs::fresh(
                    base + (profile_id * 4 + role * 2 + mode_id) as u64,
                    profile,
                    direction,
                    mode,
                ));
            }
        }
    }
}

#[test]
fn committed_row_window_and_peer_exchange_all_profiles_roles_and_modes() {
    matrix(130_000, |row| {
        let provider = Provider::new();
        let mut store = CasStore::new(7);
        let owners = EpochOwners::new(7);
        let initial = driver::create(&provider, &mut store, &row).unwrap();
        let cut = store.fenced_read(&initial, row.key).unwrap();
        let mut runtime = Runtime::restore(&provider, &owners, &cut, true).unwrap();
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
        assert!(!runtime.dispatch_replay(&mut transport).unwrap());
        assert!(transport.submitted.is_empty());
        assert!(runtime
            .reserve(
                &provider,
                &mut store,
                1,
                2,
                100,
                Cut::Complete,
                Cut::Complete
            )
            .unwrap());
        assert!(runtime
            .publish_request(
                &provider,
                &mut store,
                Exchange::Informational,
                child_delete(),
                |_| {},
                Cut::Complete
            )
            .unwrap());
        assert!(runtime.dispatch_replay(&mut transport).unwrap());
        assert_eq!(
            peer.receive(transport.submitted.last().unwrap()),
            Ok(Event::NewRequest(0))
        );
        let response = peer.respond(0, child_delete()).unwrap();
        let outcome = Bytes::from_static(b"child-deleted");
        assert_eq!(
            runtime
                .complete(
                    &provider,
                    &mut store,
                    &response,
                    outcome.clone(),
                    |_| {},
                    Cut::Complete
                )
                .unwrap(),
            Some(outcome)
        );
        assert!(!runtime.dispatch_replay(&mut transport).unwrap());
        let request = peer.request(37, child_delete()).unwrap();
        assert_eq!(
            runtime.request_disposition(&request).unwrap(),
            Disposition::New
        );
        assert_eq!(
            runtime
                .publish_response(
                    &provider,
                    &mut store,
                    &request,
                    crate::canonical_fixtures::empty(),
                    Bytes::from_static(b"peer-child-deleted"),
                    |_| {},
                    Cut::Complete
                )
                .unwrap(),
            Some(Bytes::from_static(b"peer-child-deleted"))
        );
        runtime.replay_response(&request, &mut transport).unwrap();
        assert_eq!(
            peer.receive(transport.submitted.last().unwrap()),
            Ok(Event::Completed(0))
        );
        let before = (
            store.publications,
            provider.calls(),
            module::counts().entropy,
        );
        let dpd = peer
            .request(37, crate::canonical_fixtures::empty())
            .unwrap();
        runtime.reply_empty(&dpd, &mut transport).unwrap();
        assert_eq!(
            peer.receive(transport.submitted.last().unwrap()),
            Ok(Event::Completed(1))
        );
        assert_eq!(
            (
                store.publications,
                provider.calls(),
                module::counts().entropy
            ),
            before
        );
        assert_eq!(runtime.next_receive(), Some(2));
        assert!(!runtime.reconstructing());
        drop(runtime);
        let cut = store.fenced_read(&initial, row.key).unwrap();
        let mut restarted = Runtime::restore(&provider, &owners, &cut, false).unwrap();
        assert!(!restarted.dispatch_replay(&mut transport).unwrap());
        assert_eq!(restarted.next_receive(), Some(1));
    });
}

#[test]
fn delayed_cas_after_readback_cannot_replace_the_peers_committed_request() {
    matrix(131_000, |row| {
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
                1,
                1,
                100,
                Cut::Complete,
                Cut::Complete,
            )
            .unwrap();
        assert!(!runtime
            .publish_request(
                &provider,
                &mut store,
                Exchange::Informational,
                child_delete(),
                |_| {},
                Cut::Dispatched
            )
            .unwrap());
        let first = runtime.pending.as_ref().unwrap().clone();
        assert!(matches!(
            store.fenced_read(&first, row.key),
            Err(store::Error::PriorMayStillApply)
        ));
        runtime.revoke();
        store.succeed(8);
        owners.learn_succession(8);
        drop(runtime);
        let cut = store.fenced_read(&first, row.key).unwrap();
        let mut runtime = Runtime::restore(&provider, &owners, &cut, false).unwrap();
        runtime
            .reserve(
                &provider,
                &mut store,
                1,
                1,
                120,
                Cut::Complete,
                Cut::Complete,
            )
            .unwrap();
        assert!(runtime
            .publish_request(
                &provider,
                &mut store,
                Exchange::Informational,
                changed_delete(),
                |_| {},
                Cut::Complete
            )
            .unwrap());
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
        let expected = transport.submitted.last().unwrap().clone();
        assert_eq!(peer.receive(&expected), Ok(Event::NewRequest(0)));
        assert_eq!(store.apply(first.request()), Err(store::Error::StampFenced));
        // Bypass the outer stamp path deliberately: the child CAS must refuse
        // independently, including after the new request has reached its peer.
        assert_eq!(
            store.apply_child(&first, false),
            Err(store::Error::CasConflict)
        );
        drop(runtime);
        let mut runtime = Runtime::restore(
            &provider,
            &owners,
            &store.fenced_read(&first, row.key).unwrap(),
            false,
        )
        .unwrap();
        runtime.dispatch_replay(&mut transport).unwrap();
        assert_eq!(transport.submitted.last().unwrap(), &expected);
        assert_eq!(
            peer.receive(transport.submitted.last().unwrap()),
            Ok(Event::Ignored)
        );
    });
}

#[test]
fn pruned_outcome_and_duplicate_owner_never_create_a_second_allocator() {
    matrix(132_000, |row| {
        let provider = Provider::new();
        let mut store = CasStore::new(7);
        let owners = EpochOwners::new(7);
        let initial = driver::create(&provider, &mut store, &row).unwrap();
        let cut = store.fenced_read(&initial, row.key).unwrap();
        let mut runtime = Runtime::restore(&provider, &owners, &cut, false).unwrap();
        let counts = module::counts();
        assert!(matches!(
            Runtime::restore(&provider, &owners, &cut, false),
            Err(driver::Error::Owner(
                super::authority::Error::DuplicateOwner
            ))
        ));
        assert_eq!(module::counts(), counts);
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
        runtime
            .publish_request(
                &provider,
                &mut store,
                Exchange::Informational,
                child_delete(),
                |_| {},
                Cut::Dispatched,
            )
            .unwrap();
        let write = runtime.pending.as_ref().unwrap().clone();
        store.prune(write.request());
        assert_eq!(
            runtime.resolve(&provider, &store, &write),
            Err(driver::Error::Store(store::Error::PriorMayStillApply))
        );
        let mut transport = Transport::default();
        assert!(runtime.dispatch_replay(&mut transport).is_err());
        assert!(transport.submitted.is_empty());
        store.apply(write.request()).unwrap();
        store.prune(write.request());
        assert_eq!(store.acknowledge(&write), Err(store::Error::Unknown));
        runtime.resolve(&provider, &store, &write).unwrap();
        assert!(runtime.dispatch_replay(&mut transport).unwrap());
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
        let copied = transport.submitted.last().unwrap().clone();
        let permit = runtime.permit();
        runtime.revoke();
        assert!(transport.submit(&permit, &copied).is_err());
        assert!(matches!(
            Runtime::restore(&provider, &owners, &cut, false),
            Err(driver::Error::Owner(
                super::authority::Error::DuplicateOwner
            ))
        ));
    });
}

#[test]
fn outage_keeps_peer_dpd_alive_and_replays_a_cached_nonempty_response() {
    matrix(133_000, |row| {
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
        runtime
            .reserve(
                &provider,
                &mut store,
                1,
                2,
                100,
                Cut::Complete,
                Cut::Complete,
            )
            .unwrap();
        let request = peer.request(37, child_delete()).unwrap();
        runtime
            .publish_response(
                &provider,
                &mut store,
                &request,
                child_delete(),
                Bytes::from_static(b"deleted"),
                |_| {},
                Cut::Complete,
            )
            .unwrap();
        runtime.replay_response(&request, &mut transport).unwrap();
        let cached = transport.submitted.last().unwrap().clone();
        // Lose the reply; the peer remains pending while local outbound storage stalls.
        runtime
            .publish_request(
                &provider,
                &mut store,
                Exchange::Informational,
                child_delete(),
                |_| {},
                Cut::Dispatched,
            )
            .unwrap();
        let unresolved = runtime.pending.as_ref().unwrap().clone();
        store.set_unavailable(true);
        let before = (
            store.dispatches,
            store.publications,
            provider.calls(),
            module::counts().entropy,
        );
        assert_eq!(
            runtime.request_disposition(&request).unwrap(),
            Disposition::CachedResponse
        );
        runtime.replay_response(&request, &mut transport).unwrap();
        assert_eq!(transport.submitted.last().unwrap(), &cached);
        assert_eq!(peer.receive(&cached), Ok(Event::Completed(0)));
        for id in 1..=6 {
            let dpd = peer
                .request(37, crate::canonical_fixtures::empty())
                .unwrap();
            peer.advance(REQUEST_TIMEOUT_MS - 1);
            runtime.reply_empty(&dpd, &mut transport).unwrap();
            assert_eq!(
                peer.receive(transport.submitted.last().unwrap()),
                Ok(Event::Completed(id))
            );
            assert!(peer.alive());
        }
        assert_eq!(
            (
                store.dispatches,
                store.publications,
                provider.calls(),
                module::counts().entropy
            ),
            before
        );
        assert_eq!(runtime.next_receive(), Some(7));
        assert!(runtime.dispatch_replay(&mut transport).is_err());
        store.set_unavailable(false);
        store.apply(unresolved.request()).unwrap();
        runtime.resolve(&provider, &store, &unresolved).unwrap();
        assert_eq!(runtime.next_receive(), Some(7));
        runtime.dispatch_replay(&mut transport).unwrap();
        assert_eq!(
            peer.receive(transport.submitted.last().unwrap()),
            Ok(Event::NewRequest(0))
        );
    });
}

#[test]
fn lost_prefix_then_nonempty_commits_the_repaired_floor() {
    matrix(134_000, |mut row| {
        row.window.next_receive = Some(2);
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
        let mut peer = PeerModel::new(
            Wire::new(
                row.profile,
                &row.keys,
                row.spis,
                crate::canonical_fixtures::opposite(row.direction),
            ),
            5,
            0,
            row.mode == Mode::Negotiated,
        );
        let mut transport = Transport::default();
        let before = store.publications;
        let dpd = peer
            .request(37, crate::canonical_fixtures::empty())
            .unwrap();
        runtime.reply_empty(&dpd, &mut transport).unwrap();
        assert_eq!(
            peer.receive(transport.submitted.last().unwrap()),
            Ok(Event::Completed(5))
        );
        assert_eq!(store.publications, before);
        assert_eq!(runtime.next_receive(), Some(6));
        runtime
            .reserve(
                &provider,
                &mut store,
                2,
                1,
                100,
                Cut::Complete,
                Cut::Complete,
            )
            .unwrap();
        assert_eq!(runtime.next_receive(), Some(6));
        let request = peer.request(37, child_delete()).unwrap();
        runtime
            .publish_response(
                &provider,
                &mut store,
                &request,
                crate::canonical_fixtures::empty(),
                Bytes::from_static(b"delete-result"),
                |_| {},
                Cut::Complete,
            )
            .unwrap();
        runtime.replay_response(&request, &mut transport).unwrap();
        assert_eq!(
            peer.receive(transport.submitted.last().unwrap()),
            Ok(Event::Completed(6))
        );
        assert_eq!(runtime.row.window.next_receive, Some(7));
        assert!(!runtime.reconstructing());
        assert!(matches!(
            runtime.reply_empty(&dpd, &mut transport),
            Err(driver::Error::Window(Ikev2WindowError::Drop))
        ));
        drop(runtime);
        let mut runtime = Runtime::restore(
            &provider,
            &owners,
            &store.fenced_read(&initial, row.key).unwrap(),
            true,
        )
        .unwrap();
        assert_eq!(runtime.next_receive(), Some(7));
        runtime.replay_response(&request, &mut transport).unwrap();
        assert_eq!(
            peer.receive(transport.submitted.last().unwrap()),
            Ok(Event::Ignored)
        );
    });
}
