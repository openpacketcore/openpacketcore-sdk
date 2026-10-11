//! Real refusal paths select a bounded protocol or scoped storage action.
use super::{
    authority::{EpochOwners, Transport},
    codec::ProfileCodec,
    driver::{self, Cut, Runtime},
    envelope::{self, Fault, Provider},
    lifecycle::matrix,
    module,
    peer::{Event, PeerModel},
    remedy::{self, Recovery, Remedy},
    row::Row,
    store::{CasStore, Command, Mutation},
    sync_tests::policy,
    wire::Wire,
};
use bytes::Bytes;
use opc_proto_ikev2::{
    recovery::{Ikev2SyncClock as Clock, Ikev2WindowError as Window},
    Ikev2MessageIdSyncMode as Mode, PayloadChain, PayloadType,
};

fn finish_repair(
    row: &Row,
    runtime: &mut Runtime,
    provider: &Provider,
    store: &mut CasStore,
    peer: &mut PeerModel<'_>,
    transport: &mut Transport,
) {
    let count = transport.submitted.len();
    assert!(runtime
        .repair_id(
            provider,
            store,
            policy(17),
            Clock::new(100, 9),
            Cut::Complete,
            transport
        )
        .unwrap());
    assert_eq!(transport.submitted.len(), count + 1);
    let packet = transport.submitted.last().unwrap();
    if row.mode == Mode::Negotiated {
        let Event::SyncReply { wire, .. } = peer.receive(packet).unwrap() else {
            panic!("sync remedy was not accepted");
        };
        assert!(runtime
            .sync_complete(
                provider,
                store,
                &wire,
                Clock::new(120, 9),
                Clock::new(120, 9),
                Cut::Complete
            )
            .unwrap());
        assert_eq!(runtime.row.window.next_receive, peer.counters().0);
        assert_eq!(runtime.row.window.next_send, peer.counters().1);
        assert!(peer.alive());
    } else {
        let id = peer.counters().1.unwrap();
        assert_eq!(peer.receive(packet), Ok(Event::NewRequest(id)));
        let opened = peer.wire.open(packet).unwrap();
        assert_eq!(opened.first, PayloadType::Delete);
        assert_eq!(opened.body.as_ref(), crate::canonical_fixtures::DELETE);
        let reply = peer
            .respond(id, crate::canonical_fixtures::empty())
            .unwrap();
        runtime
            .complete(
                provider,
                store,
                &reply,
                Bytes::from_static(b"ike-deleted"),
                |row| row.closed = true,
                Cut::Complete,
            )
            .unwrap();
        assert!(runtime.row.closed && runtime.permit().check().is_err());
        runtime.erase_after_delete(store, Cut::Complete).unwrap();
        assert!(store.inspect(row.key).is_none());
    }
}

#[test]
fn canonical_cache_loss_and_attempt_exhaustion_reach_sync_or_committed_delete() {
    for exhausted in [false, true] {
        matrix(2_600_000 + u64::from(exhausted) * 1000, |row| {
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
            let request = peer
                .request(37, crate::canonical_fixtures::empty())
                .unwrap();
            let mut transport = Transport::default();
            if exhausted {
                for _ in 0..3 {
                    assert_eq!(
                        module::bad_output(|| runtime.classify_empty(&request, &mut transport))
                            .unwrap(),
                        Remedy::EvaluateWithinBudget
                    );
                }
                assert!(transport.submitted.is_empty());
            } else {
                runtime.reply_empty(&request, &mut transport).unwrap();
                assert_eq!(
                    peer.receive(transport.submitted.last().unwrap()),
                    Ok(Event::Completed(0))
                );
                drop(runtime);
                runtime = Runtime::restore(
                    &provider,
                    &owners,
                    &store.fenced_read(&initial, row.key).unwrap(),
                    true,
                )
                .unwrap();
            }
            let before = (
                store.publications,
                provider.calls(),
                module::counts(),
                transport.submitted.len(),
            );
            assert_eq!(
                runtime.classify_empty(&request, &mut transport).unwrap(),
                Remedy::RepairId
            );
            assert_eq!(
                (
                    store.publications,
                    provider.calls(),
                    module::counts(),
                    transport.submitted.len()
                ),
                before
            );
            finish_repair(
                &row,
                &mut runtime,
                &provider,
                &mut store,
                &mut peer,
                &mut transport,
            );
            if row.mode == Mode::BaseFallback {
                runtime.delete().unwrap();
            }
        });
    }
}

#[test]
fn authenticated_unsupported_shape_selects_delete_but_noise_never_does() {
    matrix(2_610_000, |row| {
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
        let fragment = peer.wire.seal_fragment(
            0,
            false,
            37,
            (1, 2),
            PayloadChain::new(PayloadType::Delete, &[0, 0, 0, 12, 3]),
        );
        let mut transport = Transport::default();
        let before = (store.publications, provider.calls(), module::counts());
        for changed in [0, 8, 19, fragment.len() - 1] {
            let mut invalid = fragment.to_vec();
            invalid[changed] ^= 8;
            assert_eq!(
                runtime.classify_empty(&invalid, &mut transport).unwrap(),
                Remedy::Drop
            );
        }
        assert_eq!(
            runtime.classify_empty(&fragment, &mut transport).unwrap(),
            Remedy::Delete
        );
        assert_eq!(
            (store.publications, provider.calls(), module::counts()),
            before
        );
        assert!(transport.submitted.is_empty());
        assert!(!runtime
            .send_scoped_delete(&provider, &mut store, 19, 100, Cut::Applied, &mut transport)
            .unwrap());
        assert!(transport.submitted.is_empty());
        let pending = runtime.pending.as_ref().unwrap().clone();
        store.prune(pending.request());
        runtime.resolve(&provider, &store, &pending).unwrap();
        runtime.dispatch_replay(&mut transport).unwrap();
        let packet = transport.submitted.last().unwrap();
        assert_eq!(peer.receive(packet), Ok(Event::NewRequest(0)));
        assert_eq!(
            peer.wire.open(packet).unwrap().body.as_ref(),
            crate::canonical_fixtures::DELETE
        );
        let reply = peer.respond(0, crate::canonical_fixtures::empty()).unwrap();
        runtime
            .complete(
                &provider,
                &mut store,
                &reply,
                Bytes::from_static(b"ike-deleted"),
                |row| row.closed = true,
                Cut::Complete,
            )
            .unwrap();
        runtime
            .erase_after_delete(&mut store, Cut::Complete)
            .unwrap();
        runtime.delete().unwrap();
    });
}

#[test]
fn transient_recovery_never_selects_erasure_and_positive_loss_erases_exact_epoch() {
    for (fault_id, fault) in [Fault::Missing, Fault::Revoked, Fault::Healthy]
        .into_iter()
        .enumerate()
    {
        matrix(2_620_000 + fault_id as u64 * 1000, |row| {
            let provider = Provider::new();
            let mut store = CasStore::new(7);
            let owners = EpochOwners::new(7);
            let initial = driver::create(&provider, &mut store, &row).unwrap();
            for transient in [Fault::Unavailable, Fault::Timeout, Fault::Throttled] {
                provider.fail(transient);
                let before = store.publications;
                assert!(matches!(
                    remedy::recover(
                        &provider,
                        &owners,
                        store.fenced_read(&initial, row.key).unwrap()
                    ),
                    Err(driver::Error::Key(envelope::Error::Backpressure))
                ));
                assert_eq!(store.publications, before);
                assert!(store.inspect(row.key).is_some());
                provider.fail(Fault::Healthy);
                let Recovery::Runtime(runtime) = remedy::recover(
                    &provider,
                    &owners,
                    store.fenced_read(&initial, row.key).unwrap(),
                )
                .unwrap() else {
                    panic!("transient recovery did not resume");
                };
                assert!(runtime.permit().check().is_ok());
                drop(runtime);
            }
            let prior = if fault == Fault::Healthy {
                let mut bad = store.inspect(row.key).unwrap().clone();
                bad.version = bad.version.next();
                *bad.envelope.last_mut().unwrap() ^= 1;
                let write = Command::new(
                    store.next_request(),
                    vec![Mutation {
                        key: row.key,
                        expected: Some(row.version),
                        value: Some(bad),
                    }],
                )
                .unwrap();
                store.commit(&write).unwrap();
                write
            } else {
                initial.clone()
            };
            provider.fail(fault);
            let Recovery::Terminal(mut cleanup) = remedy::recover(
                &provider,
                &owners,
                store.fenced_read(&prior, row.key).unwrap(),
            )
            .unwrap() else {
                panic!("positive loss was not terminal");
            };
            let before = module::counts();
            assert!(!cleanup.commit(&mut store, Cut::Applied).unwrap());
            let erase = cleanup.command().clone();
            store.prune(erase.request());
            cleanup.resolve(&store).unwrap();
            assert!(store.inspect(row.key).is_none());
            assert_eq!(module::counts(), before);
            // The retired birth cannot erase a new occupant, even at the same key.
            drop(cleanup);
            provider.fail(Fault::Healthy);
            let mut next = row.clone();
            next.version.birth += 10_000;
            next.sealed_stamp = store.stamp();
            let created = driver::create(&provider, &mut store, &next).unwrap();
            assert_eq!(
                store.apply_child(&erase, false),
                Err(super::store::Error::CasConflict)
            );
            assert_eq!(
                store
                    .fenced_read(&created, row.key)
                    .unwrap()
                    .row()
                    .unwrap()
                    .version,
                next.version
            );
            let plain =
                envelope::unseal(&provider, row.key, store.inspect(row.key).unwrap()).unwrap();
            assert!(ProfileCodec::decode(&plain, row.key, next.version, store.stamp()).is_ok());
        });
    }
}

#[test]
fn refusal_classes_preserve_retry_and_trust_boundaries() {
    use opc_proto_ikev2::canonical::Ikev2CanonicalError as C;
    for error in [
        C::Unavailable,
        C::LifecycleBlocked,
        C::CapabilityActive,
        C::NotCommitted,
    ] {
        assert_eq!(remedy::canonical_failure(error), Remedy::Wait);
    }
    for error in [
        C::Invalidated,
        C::BindingMismatch,
        C::FormatUnavailable,
        C::QualificationFailed,
        C::ValidationOptInRequired,
        C::IntegrationReviewRequired,
    ] {
        assert_eq!(remedy::canonical_failure(error), Remedy::RefuseEpoch);
    }
    assert_eq!(remedy::canonical_failure(C::RegistryFull), Remedy::Capacity);
    assert_eq!(remedy::canonical_failure(C::InvalidRequest), Remedy::Drop);
    assert_eq!(
        remedy::canonical_failure(C::InvalidOutput),
        Remedy::EvaluateWithinBudget
    );
    let _ = Window::Drop;
}
