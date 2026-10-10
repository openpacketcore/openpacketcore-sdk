//! Focused public-API regressions before the store/crash composition fixture.
//!
//! Exact cloned acknowledgements stand in for completed storage here. These
//! tests make no CAS, ownership, provider-call-count or process-restart claim.

use bytes::Bytes;
use opc_proto_ikev2::{
    canonical::{
        Ikev2CanonicalEmptyReplies as Canonical, Ikev2CanonicalError as CanonicalError,
        Ikev2CanonicalPolicy as Policy,
    },
    recovery::{
        Ikev2CommittedWindow as Window, Ikev2OrdinaryRequestDisposition as Disposition,
        Ikev2SyncClock as Clock, Ikev2SyncDisposition as SyncDisposition,
        Ikev2SyncRecoveryPolicy as RecoveryPolicy, Ikev2SyncResponderRecord as SyncRecord,
        Ikev2WindowError as Error,
    },
    Ikev2AesGcmIvPurpose as Purpose, Ikev2ExchangeKind as Exchange,
    Ikev2MessageIdSyncAgreement as Agreement, Ikev2MessageIdSyncMode as Mode,
    Ikev2MessageIdSyncRole as Role, Ikev2MessageIdSyncSa as Sa, PayloadChain, PayloadType,
};

use crate::canonical_fixtures::{empty, opposite, Fixture, ALGORITHMS, DIRECTIONS};

use super::peer::{Event, PeerModel, Sync, CACHE_RETENTION_MS, REQUEST_TIMEOUT_MS};
use super::wire::Wire;

fn child_delete() -> PayloadChain<'static> {
    // Delete one ESP Child, so successful completion keeps the IKE SA alive.
    PayloadChain::new(PayloadType::Delete, &[0, 0, 0, 12, 3, 4, 0, 1, 1, 2, 3, 4])
}

fn matrix(base: u64, mut test: impl FnMut(Fixture)) {
    crate::support::ensure_ike_crypto();
    for (algorithm, encryption) in ALGORITHMS.into_iter().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            test(Fixture::new(
                base + (algorithm * 2 + role) as u64,
                encryption,
                direction,
            ));
        }
    }
}

#[test]
fn settled_request_is_suppressed_live_and_after_restore() {
    matrix(70_000, |mut f| {
        let mut peer = PeerModel::new(
            Wire::new(f.profile, &f.keys, f.spis, opposite(f.direction)),
            0,
            0,
            false,
        );
        assert!(f.window.replay_request().unwrap().is_none());
        let prepared = f
            .window
            .prepare_request(
                f.profile,
                &f.keys,
                f.allocator.allocate(Purpose::Ordinary).unwrap(),
                Exchange::Informational,
                child_delete(),
            )
            .unwrap();
        let pending = prepared.record().clone();
        let commit = prepared.commit_after_durable(&pending).unwrap();
        assert_eq!(f.window.apply_committed(commit).unwrap(), None);
        let request = Bytes::copy_from_slice(f.window.replay_request().unwrap().unwrap().bytes());
        assert_eq!(peer.receive(&request), Ok(Event::NewRequest(0)));
        let response = peer.respond(0, child_delete()).unwrap();
        let opened = f.window.open_peer(f.profile, &f.keys, &response).unwrap();
        let outcome = Bytes::from_static(b"child-deleted");
        let prepared = f
            .window
            .prepare_completion(&opened, outcome.clone())
            .unwrap();
        let settled = prepared.record().clone();
        let commit = prepared.commit_after_durable(&settled).unwrap();
        assert_eq!(f.window.apply_committed(commit).unwrap(), Some(outcome));
        peer.advance(CACHE_RETENTION_MS);
        peer.forget_expired_responses();
        assert_eq!(peer.receive(&request), Ok(Event::Ignored));
        assert!(
            peer.alive(),
            "ignoring a settled replay is permitted for a live peer"
        );
        let live_suppressed = f.window.replay_request().unwrap().is_none();
        drop(f.window);
        let restored =
            Window::restore(settled.domain(), f.profile, &f.keys, &settled, &f.iv).unwrap();
        let restored_suppressed = restored.replay_request().unwrap().is_none();
        assert!(live_suppressed && restored_suppressed,
            "settled exchange must never become a probe: live={live_suppressed}, restored={restored_suppressed}");
        restored.delete();
    });
}

#[test]
fn outbound_uncertainty_keeps_new_peer_dpd_alive() {
    empty_outage(false, false, 70_100);
}

#[test]
fn outbound_uncertainty_keeps_cached_peer_dpd_alive() {
    empty_outage(true, false, 70_200);
}

#[test]
fn outbound_completion_uncertainty_keeps_new_peer_dpd_alive() {
    empty_outage(false, true, 70_600);
}

#[test]
fn outbound_completion_uncertainty_keeps_cached_peer_dpd_alive() {
    empty_outage(true, true, 70_700);
}

fn empty_outage(prewarm: bool, completion: bool, base: u64) {
    matrix(base, |mut f| {
        f.window.enable_empty_replies(Policy::default()).unwrap();
        let mut peer = PeerModel::new(
            Wire::new(f.profile, &f.keys, f.spis, opposite(f.direction)),
            0,
            0,
            false,
        );
        let first = peer.request(37, empty()).unwrap();
        let opened = f.window.open_peer(f.profile, &f.keys, &first).unwrap();
        let cached = if prewarm {
            Some(Bytes::copy_from_slice(
                f.window.reply_empty(&opened).unwrap().bytes(),
            ))
        } else {
            None
        };
        let mut before = f.window.record().clone();
        let prepared = f
            .window
            .prepare_request(
                f.profile,
                &f.keys,
                f.allocator.allocate(Purpose::Ordinary).unwrap(),
                Exchange::Informational,
                child_delete(),
            )
            .unwrap();
        let candidate = if completion {
            let request = prepared.record().clone();
            let token = prepared.commit_after_durable(&request).unwrap();
            assert_eq!(f.window.apply_committed(token).unwrap(), None);
            assert_eq!(
                peer.receive(f.window.replay_request().unwrap().unwrap().bytes()),
                Ok(Event::NewRequest(0))
            );
            let response = peer.respond(0, child_delete()).unwrap();
            let response = f.window.open_peer(f.profile, &f.keys, &response).unwrap();
            before = f.window.record().clone();
            let prepared = f
                .window
                .prepare_completion(&response, Bytes::from_static(b"child-deleted"))
                .unwrap();
            let candidate = prepared.record().clone();
            drop(prepared);
            candidate
        } else {
            let candidate = prepared.record().clone();
            drop(prepared);
            candidate
        }; // The store acknowledgement may never arrive.
        assert_eq!(f.window.ready(), Err(Error::CommitUncertain));
        assert!(matches!(
            f.window.replay_request(),
            Err(Error::CommitUncertain)
        ));
        let reply = Bytes::copy_from_slice(
            f.window
                .reply_empty(&opened)
                .expect("outbound-only uncertainty must not silence DPD")
                .bytes(),
        );
        if let Some(cached) = cached {
            assert_eq!(reply, cached);
        }
        assert_eq!(peer.receive(&reply), Ok(Event::Completed(0)));
        // More than the peer's request timeout passes without any store progress.
        // Each new DPD still completes and its duplicate gets identical bytes.
        for id in 1..=4 {
            peer.advance(REQUEST_TIMEOUT_MS / 2);
            let request = peer.request(37, empty()).unwrap();
            let opened = f.window.open_peer(f.profile, &f.keys, &request).unwrap();
            let reply = Bytes::copy_from_slice(f.window.reply_empty(&opened).unwrap().bytes());
            assert_eq!(
                f.window.reply_empty(&opened).unwrap().bytes(),
                reply.as_ref()
            );
            assert_eq!(peer.receive(&reply), Ok(Event::Completed(id)));
            assert!(peer.alive());
            assert_eq!(
                f.window.record(),
                &before,
                "DPD must not publish durable state"
            );
            assert_eq!(f.window.ready(), Err(Error::CommitUncertain));
        }
        // Both possible exact readbacks preserve the volatile receive progress.
        f.window
            .reconcile(
                f.profile,
                &f.keys,
                if prewarm { &candidate } else { &before },
                &f.iv,
            )
            .unwrap();
        assert_eq!(f.window.next_receive(), Some(5));
        assert_eq!(f.window.ready(), Ok(()));
        assert_eq!(
            f.window.replay_request().unwrap().is_some(),
            completion ^ prewarm
        );
        f.window.delete();
    });
}

#[test]
fn outbound_uncertainty_allows_cached_response_disposition() {
    cached_work_outage(true, false, 70_300);
}

#[test]
fn outbound_uncertainty_allows_exact_cached_response() {
    cached_work_outage(false, false, 70_400);
}

#[test]
fn canonical_unavailable_preserves_cached_nonempty_replay_and_revocation() {
    cached_work_outage(true, true, 70_800);
}

fn cached_work_outage(check_disposition: bool, unavailable: bool, base: u64) {
    matrix(base, |mut f| {
        f.window.enable_empty_replies(Policy::default()).unwrap();
        let mut peer = PeerModel::new(
            Wire::new(f.profile, &f.keys, f.spis, opposite(f.direction)),
            0,
            0,
            false,
        );
        let request = peer.request(37, child_delete()).unwrap();
        let opened = f.window.open_peer(f.profile, &f.keys, &request).unwrap();
        assert_eq!(f.window.request_disposition(&opened), Ok(Disposition::New));
        let prepared = f
            .window
            .prepare_response(
                f.profile,
                &f.keys,
                f.allocator.allocate(Purpose::Ordinary).unwrap(),
                &opened,
                child_delete(),
                Bytes::from_static(b"peer-child-deleted"),
            )
            .unwrap();
        let cached = prepared.record().clone();
        let commit = prepared.commit_after_durable(&cached).unwrap();
        assert!(f.window.apply_committed(commit).unwrap().is_some());
        let original = Bytes::copy_from_slice(f.window.replay_response(&opened).unwrap().bytes());
        assert_eq!(peer.receive(&original), Ok(Event::Completed(0)));
        let provider_outage = |window: &Window| {
            super::module::withdraw(opc_crypto_provider::CryptoCapability::IkeEncryption, || {
                assert_eq!(
                    Canonical::preflight(f.profile.encryption(), Policy::default()),
                    Err(CanonicalError::Unavailable)
                );
                assert_eq!(
                    window.request_disposition(&opened),
                    Ok(Disposition::CachedResponse)
                );
                assert_eq!(
                    window.replay_response(&opened).unwrap().bytes(),
                    original.as_ref()
                );
                assert_eq!(window.record(), &cached);
            });
        };
        if unavailable {
            provider_outage(&f.window);
        }
        let prepared = f
            .window
            .prepare_request(
                f.profile,
                &f.keys,
                f.allocator.allocate(Purpose::Ordinary).unwrap(),
                Exchange::Informational,
                child_delete(),
            )
            .unwrap();
        drop(prepared);
        assert_eq!(f.window.ready(), Err(Error::CommitUncertain));
        if unavailable {
            provider_outage(&f.window);
        }
        if check_disposition {
            assert_eq!(
                f.window.request_disposition(&opened),
                Ok(Disposition::CachedResponse),
                "the cached branch must share replay_response admission"
            );
        }
        let reply = f
            .window
            .replay_response(&opened)
            .expect("outbound-only uncertainty must permit the exact committed response");
        assert_eq!(reply.bytes(), original.as_ref());
        assert_eq!(peer.receive(reply.bytes()), Ok(Event::Ignored));
        assert_eq!(f.window.record(), &cached);
        let next = peer.request(37, child_delete()).unwrap();
        let next = f.window.open_peer(f.profile, &f.keys, &next).unwrap();
        assert_eq!(
            f.window.request_disposition(&next),
            Err(Error::CommitUncertain)
        );
        assert!(matches!(
            f.window.prepare_completion(&opened, Bytes::new()),
            Err(Error::CommitUncertain)
        ));
        Canonical::delete_epoch(&f.iv);
        assert!(
            matches!(
                f.window.replay_response(&opened),
                Err(Error::Canonical(CanonicalError::Invalidated))
            ),
            "revocation still blocks a cached response"
        );
        assert_eq!(
            f.window.request_disposition(&opened),
            Err(Error::Canonical(CanonicalError::Invalidated))
        );
        f.window.delete();
    });
}

#[test]
fn reply_exception_refuses_inbound_uncertainty() {
    blocked_reply(0);
}

#[test]
fn reply_exception_refuses_local_sync_uncertainty() {
    blocked_reply(1);
}

#[test]
fn reply_exception_refuses_peer_sync_uncertainty() {
    blocked_reply(2);
}

#[test]
fn reply_exception_refuses_unclassified_quiescence() {
    blocked_reply(3);
}

fn blocked_reply(cause: u64) {
    matrix(70_500 + cause * 10, |mut f| {
        let agreement = Agreement::from_persisted(
            Sa::new(
                f.spis.0,
                f.spis.1,
                if f.direction == DIRECTIONS[0] {
                    Role::Initiator
                } else {
                    Role::Responder
                },
            )
            .unwrap(),
            Mode::Negotiated,
        );
        let record = f
            .window
            .record()
            .clone()
            .with_sync_state(
                SyncRecord::from_persisted(
                    agreement,
                    None,
                    None,
                    None,
                    None,
                    SyncDisposition::Continue,
                    0,
                )
                .unwrap(),
            )
            .unwrap();
        f.window = Window::restore(record.domain(), f.profile, &f.keys, &record, &f.iv).unwrap();
        f.window.enable_empty_replies(Policy::default()).unwrap();
        let mut peer = PeerModel::new(
            Wire::new(f.profile, &f.keys, f.spis, opposite(f.direction)),
            0,
            0,
            true,
        );
        let request = peer.request(37, empty()).unwrap();
        let opened = f.window.open_peer(f.profile, &f.keys, &request).unwrap();
        let reply = f.window.reply_empty(&opened).unwrap();
        assert_eq!(peer.receive(reply.bytes()), Ok(Event::Completed(0)));
        drop(reply);
        let before = f.window.record().clone();
        let clock = Clock::new(100, 1);
        match cause {
            0 => {
                let request = peer.request(37, child_delete()).unwrap();
                let request = f.window.open_peer(f.profile, &f.keys, &request).unwrap();
                drop(
                    f.window
                        .prepare_response(
                            f.profile,
                            &f.keys,
                            f.allocator.allocate(Purpose::Ordinary).unwrap(),
                            &request,
                            child_delete(),
                            Bytes::from_static(b"pending-result"),
                        )
                        .unwrap(),
                );
            }
            1 | 3 => {
                let policy = RecoveryPolicy::new(1, clock, 1000, 3, 10).unwrap();
                let admitted = f.window.begin_sync(policy, clock, None).unwrap();
                if cause == 1 {
                    drop(
                        admitted
                            .prepare(
                                f.profile,
                                &f.keys,
                                f.allocator.allocate(Purpose::Ordinary).unwrap(),
                            )
                            .unwrap(),
                    );
                } else {
                    // Admission without preparation establishes no witness.
                    drop(admitted);
                }
            }
            2 => {
                let request = peer
                    .begin_sync(Sync {
                        nonce: [1; 4],
                        send: 4,
                        receive: 2,
                    })
                    .unwrap();
                let admitted = f
                    .window
                    .begin_sync_response(f.profile, &f.keys, &request, None, None)
                    .unwrap();
                drop(
                    admitted
                        .prepare(
                            f.profile,
                            &f.keys,
                            f.allocator.allocate(Purpose::Ordinary).unwrap(),
                        )
                        .unwrap(),
                );
            }
            _ => unreachable!(),
        }
        assert_eq!(
            f.window.reply_empty(&opened).unwrap_err(),
            Error::CommitUncertain,
            "a non-outbound witness must keep cached empty replies blocked: {cause}"
        );
        assert_eq!(f.window.record(), &before);
        assert_eq!(f.window.next_receive(), Some(1));
        f.window.delete();
    });
}
