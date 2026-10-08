//! Fenced in-process readback preserves RFC 7296 §2.3 response retention.

use bytes::Bytes;
use opc_proto_ikev2::{
    canonical::{Ikev2CanonicalError as CanonicalError, Ikev2CanonicalPolicy as Policy},
    recovery::{
        Ikev2AuthenticatedOrdinary as Request, Ikev2CommittedWindow as Window,
        Ikev2CommittedWindowDomain as Domain, Ikev2CommittedWindowRecord as Record,
        Ikev2EmptyReplyObservation as Observation, Ikev2OrdinaryRequestDisposition as Disposition,
        Ikev2SyncClock as Clock, Ikev2SyncDisposition as SyncDisposition,
        Ikev2SyncInitiatorAction as Action, Ikev2SyncRecoveryPolicy as RecoveryPolicy,
        Ikev2SyncResponderRecord as SyncRecord, Ikev2WindowError as Error,
    },
    Ikev2AesGcmIvLimits as Limits, Ikev2AesGcmIvPurpose as Purpose,
    Ikev2AesGcmIvRecord as IvRecord, Ikev2ExchangeKind as Exchange,
    Ikev2MessageIdSyncAgreement as Agreement, Ikev2MessageIdSyncMode as Mode,
    Ikev2MessageIdSyncRole as Role, Ikev2MessageIdSyncSa as Sa, PayloadChain, PayloadType,
};

#[path = "support/canonical.rs"]
mod canonical_fixtures;
mod support;
use canonical_fixtures::{delete, empty, Fixture, ALGORITHMS, DIRECTIONS};

fn each(tag: u64, mut check: impl FnMut(Fixture)) {
    support::ensure_ike_crypto();
    for (algorithm, encryption) in ALGORITHMS.into_iter().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            check(Fixture::new(
                tag + (algorithm * 2 + role) as u64,
                encryption,
                direction,
            ));
        }
    }
}

fn initial(f: &Fixture, next: u32, sync: bool) -> Record {
    let record = Record::initial(Domain::from_iv_record(&f.iv), 0, next);
    if !sync {
        return record;
    }
    record
        .with_sync_state(
            SyncRecord::from_persisted(
                Agreement::from_persisted(
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
                ),
                None,
                next.checked_sub(1),
                None,
                None,
                SyncDisposition::Continue,
                0,
            )
            .unwrap(),
        )
        .unwrap()
}

fn start(f: &Fixture, next: u32, sync: bool) -> Window {
    let record = initial(f, next, sync);
    let mut window = Window::restore(record.domain(), f.profile, &f.keys, &record, &f.iv).unwrap();
    window.enable_empty_replies(Policy::default()).unwrap();
    window
}

fn work(f: &Fixture, id: u32) -> Request {
    let wire = f.peer(id, false, 37, delete(), 0, 0x2000 + u64::from(id));
    f.window.open_peer(f.profile, &f.keys, &wire).unwrap()
}

fn response(f: &Fixture, id: u32) -> Request {
    let wire = f.peer(id, true, 37, empty(), 0, 0x4000 + u64::from(id));
    f.window.open_peer(f.profile, &f.keys, &wire).unwrap()
}

fn sync_wire(f: &Fixture, reply: bool, nonce: [u8; 4], send: u32, receive: u32) -> Bytes {
    let mut payload = vec![0, 0, 0, 20, 0, 0, 0x40, 0x26];
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&send.to_be_bytes());
    payload.extend_from_slice(&receive.to_be_bytes());
    f.peer(
        0,
        reply,
        37,
        PayloadChain::new(PayloadType::Notify, &payload),
        0,
        0x6000,
    )
}

fn policy() -> RecoveryPolicy {
    RecoveryPolicy::new(1, Clock::new(100, 7), 200, 3, 10).unwrap()
}

fn terminal(window: &mut Window, f: &Fixture, old: &Record, floor: Option<u32>) {
    assert_eq!(
        window.record(),
        old,
        "failed readback must not publish a record"
    );
    assert_eq!(
        window.next_receive(),
        floor,
        "failed readback must not publish a floor"
    );
    assert_eq!(window.ready(), Err(Error::CommitUncertain));
    assert_eq!(
        window.enable_empty_replies(Policy::default()),
        Err(Error::Canonical(CanonicalError::Invalidated))
    );
    assert!(
        window.reconcile(f.profile, &f.keys, old, &f.iv).is_err(),
        "terminal readback cannot be retried"
    );
}

fn assert_next_iv(f: &mut Fixture, next: u64) {
    let prepared = f
        .window
        .prepare_request(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
            Exchange::Informational,
            delete(),
        )
        .unwrap();
    assert_eq!(
        &prepared.record().outbound().unwrap().request()[32..40],
        &next.to_be_bytes()
    );
}

#[test]
fn unchanged_and_outbound_request_readback_retain_exact_last_empty_reply() {
    for landed in [false, true] {
        each(30_000 + u64::from(landed) * 10, |mut f| {
            let mut window = start(&f, 4, false);
            let request = f.request(4);
            let bytes = window.reply_empty(&request).unwrap().bytes().to_vec();
            let old = window.record().clone();
            let prepared = window
                .prepare_request(
                    f.profile,
                    &f.keys,
                    f.allocator.allocate(Purpose::Ordinary).unwrap(),
                    Exchange::Informational,
                    delete(),
                )
                .unwrap();
            let candidate = prepared.record().clone();
            drop(prepared);
            assert_eq!(window.ready(), Err(Error::CommitUncertain));
            let readback = if landed { candidate } else { old };
            for _ in 0..3 {
                window
                    .reconcile(f.profile, &f.keys, &readback, &f.iv)
                    .unwrap();
                assert_eq!(window.record(), &readback);
                assert_eq!(window.next_receive(), Some(5));
                assert!(window.is_reconstructing());
                let duplicate = window.reply_empty(&request).unwrap();
                assert_eq!(duplicate.bytes(), bytes);
                assert_eq!(duplicate.observation(), Observation::Replayed);
            }
            assert_next_iv(&mut f, 1);
            window.delete();
        });
    }
}

#[test]
fn outbound_completion_readback_keeps_strict_phase_and_empty_cache() {
    for landed in [false, true] {
        each(30_100 + u64::from(landed) * 10, |mut f| {
            let mut window = start(&f, 3, false);
            let peer = work(&f, 3);
            let prepared = window
                .prepare_response(
                    f.profile,
                    &f.keys,
                    f.allocator.allocate(Purpose::Ordinary).unwrap(),
                    &peer,
                    empty(),
                    Bytes::new(),
                )
                .unwrap();
            let record = prepared.record().clone();
            let _token = prepared.commit_after_durable(&record).unwrap();
            let prepared = window
                .prepare_request(
                    f.profile,
                    &f.keys,
                    f.allocator.allocate(Purpose::Ordinary).unwrap(),
                    Exchange::Informational,
                    delete(),
                )
                .unwrap();
            let old = prepared.record().clone();
            let _token = prepared.commit_after_durable(&old).unwrap();
            let request = f.request(4);
            let bytes = window.reply_empty(&request).unwrap().bytes().to_vec();
            let prepared = window
                .prepare_completion(&response(&f, 0), Bytes::from_static(b"settled"))
                .unwrap();
            let candidate = prepared.record().clone();
            drop(prepared);
            let readback = if landed { candidate } else { old };
            window
                .reconcile(f.profile, &f.keys, &readback, &f.iv)
                .unwrap();
            assert!(!window.is_reconstructing());
            assert_eq!(window.next_receive(), Some(5));
            assert_eq!(window.request_disposition(&work(&f, 6)), Err(Error::Drop));
            assert_eq!(window.reply_empty(&request).unwrap().bytes(), bytes);
            assert_next_iv(&mut f, 2);
            window.delete();
        });
    }
}

#[test]
fn inbound_readback_adopts_only_the_exact_landed_witness() {
    for landed in [false, true] {
        each(30_200 + u64::from(landed) * 10, |mut f| {
            let mut window = start(&f, 4, false);
            drop(window.reply_empty(&f.request(4)).unwrap());
            let old = window.record().clone();
            let request = work(&f, 5);
            let prepared = window
                .prepare_response(
                    f.profile,
                    &f.keys,
                    f.allocator.allocate(Purpose::Ordinary).unwrap(),
                    &request,
                    empty(),
                    Bytes::from_static(b"outcome"),
                )
                .unwrap();
            let candidate = prepared.record().clone();
            drop(prepared);
            let readback = if landed { candidate } else { old };
            window
                .reconcile(f.profile, &f.keys, &readback, &f.iv)
                .unwrap();
            assert_eq!(window.record(), &readback);
            assert_eq!(window.next_receive(), Some(if landed { 6 } else { 5 }));
            assert_eq!(window.is_reconstructing(), !landed);
            assert_eq!(window.reply_empty(&f.request(4)).unwrap_err(), Error::Drop);
            if landed {
                assert_eq!(
                    window.request_disposition(&request),
                    Ok(Disposition::CachedResponse)
                );
                assert_eq!(
                    window.replay_response(&request).unwrap().bytes(),
                    readback.inbound().unwrap().response().unwrap()
                );
                let bytes = window.reply_empty(&f.request(6)).unwrap().bytes().to_vec();
                window
                    .reconcile(f.profile, &f.keys, &readback, &f.iv)
                    .unwrap();
                assert_eq!(window.next_receive(), Some(7));
                assert_eq!(
                    window.reply_empty(&f.request(6)).unwrap().bytes(),
                    bytes,
                    "acknowledged boundary must not be applied again"
                );
            } else {
                assert_eq!(window.request_disposition(&request), Ok(Disposition::New));
                assert_eq!(
                    window.request_disposition(&work(&f, 6)),
                    Err(Error::Drop),
                    "unlanded witness keeps pending identity"
                );
            }
            window.delete();
        });
    }
}

#[test]
fn pending_identity_and_sync_drop_history_survive_unchanged_readback() {
    each(30_300, |mut f| {
        let mut window = start(&f, 4, true);
        drop(window.reply_empty(&f.request(4)).unwrap());
        let pending = work(&f, 5);
        assert_eq!(window.request_disposition(&pending), Ok(Disposition::New));
        let old = window.record().clone();
        window.reconcile(f.profile, &f.keys, &old, &f.iv).unwrap();
        assert_eq!(window.reply_empty(&f.request(4)).unwrap_err(), Error::Drop);
        assert_eq!(window.request_disposition(&work(&f, 6)), Err(Error::Drop));
        let stale = sync_wire(&f, false, [1, 2, 3, 4], 5, 0);
        assert_eq!(
            window
                .begin_sync_response(f.profile, &f.keys, &stale, None, None)
                .unwrap_err(),
            Error::Drop
        );
        let fresh = sync_wire(&f, false, [2, 3, 4, 5], 6, 0);
        let prepared = window
            .begin_sync_response(f.profile, &f.keys, &fresh, None, None)
            .unwrap()
            .prepare(
                f.profile,
                &f.keys,
                f.allocator.allocate(Purpose::Ordinary).unwrap(),
            )
            .unwrap();
        let candidate = prepared.record().clone();
        drop(prepared);
        window
            .reconcile(f.profile, &f.keys, &candidate, &f.iv)
            .unwrap();
        assert_eq!(
            window.ready(),
            Err(Error::OutcomeUncertain),
            "terminal lifecycle is a successful reconcile"
        );
        window.delete();
    });
}

#[test]
fn responder_witness_is_captured_after_sealing_and_fences_response_tokens() {
    for landed in [false, true] {
        each(30_400 + u64::from(landed) * 10, |mut f| {
            let mut window = start(&f, 4, true);
            let request = f.request(4);
            let bytes = window.reply_empty(&request).unwrap().bytes().to_vec();
            let old = window.record().clone();
            let wire = sync_wire(&f, false, [1, 2, 3, 4], 8, 0);
            let prepared = window
                .begin_sync_response(f.profile, &f.keys, &wire, None, None)
                .unwrap()
                .prepare(
                    f.profile,
                    &f.keys,
                    f.allocator.allocate(Purpose::Ordinary).unwrap(),
                )
                .unwrap();
            let candidate = prepared.record().clone();
            assert_eq!(candidate.sync_state().unwrap().minimum_send_iv_end(), 1);
            drop(prepared);
            let readback = if landed { candidate } else { old };
            window
                .reconcile(f.profile, &f.keys, &readback, &f.iv)
                .unwrap();
            if landed {
                assert_eq!(window.next_receive(), Some(8));
                assert!(!window.is_reconstructing());
                assert_eq!(window.reply_empty(&request).unwrap_err(), Error::Drop);
                assert_eq!(
                    window
                        .begin_sync_response(f.profile, &f.keys, &wire, None, None)
                        .unwrap_err(),
                    Error::Drop
                );
            } else {
                assert_eq!(window.next_receive(), Some(5));
                assert_eq!(window.reply_empty(&request).unwrap().bytes(), bytes);
            }
            let next = sync_wire(&f, false, [5, 6, 7, 8], 9, 0);
            let prepared = window
                .begin_sync_response(f.profile, &f.keys, &next, None, None)
                .unwrap()
                .prepare(
                    f.profile,
                    &f.keys,
                    f.allocator.allocate(Purpose::Ordinary).unwrap(),
                )
                .unwrap();
            let committed = prepared.record().clone();
            let token = prepared.commit_after_durable(&committed).unwrap();
            window
                .reconcile(f.profile, &f.keys, &committed, &f.iv)
                .unwrap();
            assert_eq!(
                window.release_sync_response(token).unwrap_err(),
                Error::StaleCompletion
            );
            assert_next_iv(&mut f, 2);
            window.delete();
        });
    }
}

#[test]
fn cancelled_sync_admission_without_a_witness_preserves_the_last_reply() {
    for responder in [false, true] {
        each(30_500 + u64::from(responder) * 10, |f| {
            let mut window = start(&f, 4, true);
            let request = f.request(4);
            let bytes = window.reply_empty(&request).unwrap().bytes().to_vec();
            let old = window.record().clone();
            if responder {
                drop(
                    window
                        .begin_sync_response(
                            f.profile,
                            &f.keys,
                            &sync_wire(&f, false, [1; 4], 8, 0),
                            None,
                            None,
                        )
                        .unwrap(),
                );
            } else {
                drop(
                    window
                        .begin_sync(policy(), Clock::new(100, 7), None)
                        .unwrap(),
                );
            }
            window.reconcile(f.profile, &f.keys, &old, &f.iv).unwrap();
            assert_eq!(window.next_receive(), Some(5));
            assert_eq!(window.reply_empty(&request).unwrap().bytes(), bytes);
            window.delete();
        });
    }
}

#[test]
fn local_proposal_readback_keeps_pending_lifecycle_and_requires_a_higher_retry() {
    for landed in [false, true] {
        each(30_600 + u64::from(landed) * 10, |mut f| {
            let mut window = start(&f, 4, true);
            let request = f.request(4);
            let bytes = window.reply_empty(&request).unwrap().bytes().to_vec();
            let old = window.record().clone();
            let prepared = window
                .begin_sync(policy(), Clock::new(100, 7), None)
                .unwrap()
                .prepare(
                    f.profile,
                    &f.keys,
                    f.allocator.allocate(Purpose::Ordinary).unwrap(),
                )
                .unwrap();
            let candidate = prepared.record().clone();
            let proposal = candidate
                .sync_recovery()
                .unwrap()
                .pending()
                .unwrap()
                .notification();
            drop(prepared);
            let readback = if landed { candidate } else { old };
            window
                .reconcile(f.profile, &f.keys, &readback, &f.iv)
                .unwrap();
            if landed {
                assert_eq!(window.ready(), Err(Error::SyncInProgress));
                let wire = sync_wire(
                    &f,
                    true,
                    proposal.nonce(),
                    proposal.expected_recv_req_message_id(),
                    proposal.expected_send_req_message_id(),
                );
                assert_eq!(
                    window
                        .complete_sync(f.profile, &f.keys, &wire, Clock::new(101, 7))
                        .unwrap_err(),
                    Error::Drop
                );
                let prepared = window
                    .retry_sync(Clock::new(110, 7))
                    .unwrap()
                    .prepare(
                        f.profile,
                        &f.keys,
                        f.allocator.allocate(Purpose::Ordinary).unwrap(),
                    )
                    .unwrap();
                let retry = prepared
                    .record()
                    .sync_recovery()
                    .unwrap()
                    .pending()
                    .unwrap()
                    .notification();
                assert!(
                    retry.expected_send_req_message_id() > proposal.expected_send_req_message_id()
                );
                assert_ne!(retry.nonce(), proposal.nonce());
            } else {
                assert_eq!(window.ready(), Ok(()));
                assert_eq!(window.reply_empty(&request).unwrap().bytes(), bytes);
            }
            window.delete();
        });
    }
}

fn live_proposal(window: &mut Window, f: &mut Fixture) -> Record {
    let prepared = window
        .begin_sync(policy(), Clock::new(100, 7), None)
        .unwrap()
        .prepare(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
        )
        .unwrap();
    let candidate = prepared.record().clone();
    let token = prepared
        .commit_after_durable(&candidate, Clock::new(100, 7))
        .unwrap();
    assert!(matches!(
        window
            .release_sync_action(token, Clock::new(100, 7))
            .unwrap(),
        Action::SendRequest(_)
    ));
    candidate
}

#[test]
fn recovered_readback_adopts_history_without_a_second_sync_action() {
    for landed in [false, true] {
        each(30_700 + u64::from(landed) * 10, |mut f| {
            let mut window = start(&f, 4, true);
            let old = live_proposal(&mut window, &mut f);
            let proposal = old
                .sync_recovery()
                .unwrap()
                .pending()
                .unwrap()
                .notification();
            let wire = sync_wire(&f, true, proposal.nonce(), 8, 7);
            let prepared = window
                .complete_sync(f.profile, &f.keys, &wire, Clock::new(101, 7))
                .unwrap();
            let candidate = prepared.record().clone();
            drop(prepared);
            let readback = if landed { candidate } else { old };
            window
                .reconcile(f.profile, &f.keys, &readback, &f.iv)
                .unwrap();
            assert_eq!(
                window.ready(),
                if landed {
                    Ok(())
                } else {
                    Err(Error::SyncInProgress)
                }
            );
            assert_eq!(window.next_receive(), Some(if landed { 8 } else { 4 }));
            assert_eq!(
                window
                    .complete_sync(f.profile, &f.keys, &wire, Clock::new(102, 7))
                    .unwrap_err(),
                Error::Drop
            );
            window.delete();
        });
    }
}

#[test]
fn unchanged_readback_fences_an_already_sent_live_sync_proposal() {
    each(30_800, |mut f| {
        let mut window = start(&f, 4, true);
        let old = live_proposal(&mut window, &mut f);
        let proposal = old
            .sync_recovery()
            .unwrap()
            .pending()
            .unwrap()
            .notification();
        window.check_sync_deadline(Clock::new(120, 7)).unwrap();
        window.reconcile(f.profile, &f.keys, &old, &f.iv).unwrap();
        let wire = sync_wire(&f, true, proposal.nonce(), 8, 7);
        assert_eq!(
            window
                .complete_sync(f.profile, &f.keys, &wire, Clock::new(121, 7))
                .unwrap_err(),
            Error::Drop
        );
        window.delete();
    });
}

#[test]
fn unchanged_readback_preserves_observed_sync_clock_and_latched_closure() {
    each(30_810, |mut f| {
        let mut window = start(&f, 4, true);
        let old = live_proposal(&mut window, &mut f);
        window.check_sync_deadline(Clock::new(120, 7)).unwrap();
        window.reconcile(f.profile, &f.keys, &old, &f.iv).unwrap();
        assert_eq!(
            window.check_sync_deadline(Clock::new(119, 7)),
            Err(Error::SyncClosed),
            "readback alone must not erase the observed clock"
        );
        window.reconcile(f.profile, &f.keys, &old, &f.iv).unwrap();
        assert_eq!(
            window.ready(),
            Err(Error::SyncClosed),
            "readback cannot erase latched closure"
        );
        window.delete();
    });
}

#[test]
fn close_readback_preserves_live_floor_and_exhaustion() {
    for exhausted in [false, true] {
        for landed in [false, true] {
            each(
                30_900 + u64::from(exhausted) * 20 + u64::from(landed) * 10,
                |f| {
                    let mut window = start(&f, if exhausted { u32::MAX } else { 0 }, true);
                    if exhausted {
                        drop(window.reply_empty(&f.request(u32::MAX)).unwrap());
                    } else {
                        for id in 0..4 {
                            drop(window.reply_empty(&f.request(id)).unwrap());
                        }
                    }
                    let floor = if exhausted { None } else { Some(4) };
                    let old = window.record().clone();
                    assert_eq!(
                        window
                            .begin_sync(policy(), Clock::new(200, 7), None)
                            .unwrap_err(),
                        Error::SyncClosed
                    );
                    let prepared = window.close_sync().unwrap();
                    let candidate = prepared.record().clone();
                    drop(prepared);
                    let readback = if landed { candidate } else { old };
                    window
                        .reconcile(f.profile, &f.keys, &readback, &f.iv)
                        .unwrap();
                    assert_eq!(window.next_receive(), floor);
                    assert_eq!(window.ready(), Err(Error::SyncClosed));
                    window.delete();
                },
            );
        }
    }
}

#[test]
fn ordinary_and_initiating_completion_tokens_are_fenced_at_unchanged_generation() {
    each(31_000, |mut f| {
        let mut window = start(&f, 4, false);
        let prepared = window
            .prepare_request(
                f.profile,
                &f.keys,
                f.allocator.allocate(Purpose::Ordinary).unwrap(),
                Exchange::Informational,
                delete(),
            )
            .unwrap();
        let record = prepared.record().clone();
        let token = prepared.commit_after_durable(&record).unwrap();
        window
            .reconcile(f.profile, &f.keys, &record, &f.iv)
            .unwrap();
        assert_eq!(window.apply_committed(token), Err(Error::StaleCompletion));
        window.delete();
    });
    each(31_010, |mut f| {
        let mut window = start(&f, 4, true);
        let prepared = window
            .begin_sync(policy(), Clock::new(100, 7), None)
            .unwrap()
            .prepare(
                f.profile,
                &f.keys,
                f.allocator.allocate(Purpose::Ordinary).unwrap(),
            )
            .unwrap();
        let record = prepared.record().clone();
        let token = prepared
            .commit_after_durable(&record, Clock::new(100, 7))
            .unwrap();
        window
            .reconcile(f.profile, &f.keys, &record, &f.iv)
            .unwrap();
        assert_eq!(
            window
                .release_sync_action(token, Clock::new(101, 7))
                .unwrap_err(),
            Error::StaleCompletion
        );
        window.delete();
    });
}

#[test]
fn readback_never_acquires_a_canonical_capability() {
    each(31_100, |f| {
        let record = initial(&f, 4, false);
        let mut owner = start(&f, 4, false);
        let mut checked =
            Window::restore(record.domain(), f.profile, &f.keys, &record, &f.iv).unwrap();
        checked
            .reconcile(f.profile, &f.keys, &record, &f.iv)
            .unwrap();
        assert_eq!(
            checked.reply_empty(&f.request(4)).unwrap_err(),
            Error::EmptyRepliesDisabled
        );
        assert_eq!(
            checked.enable_empty_replies(Policy::default()),
            Err(Error::Canonical(CanonicalError::CapabilityActive))
        );
        drop(owner.reply_empty(&f.request(4)).unwrap());
        drop(owner);
        checked.enable_empty_replies(Policy::default()).unwrap();
        assert_eq!(
            checked.reply_empty(&f.request(5)).unwrap().observation(),
            Observation::Uncertain
        );
        checked.delete();
    });
}

#[test]
fn unknown_successor_from_a_second_runtime_revokes_the_whole_epoch() {
    each(31_200, |mut f| {
        let mut owner = start(&f, 4, false);
        let old = owner.record().clone();
        let prepared = f
            .window
            .prepare_request(
                f.profile,
                &f.keys,
                f.allocator.allocate(Purpose::Ordinary).unwrap(),
                Exchange::Informational,
                delete(),
            )
            .unwrap();
        let foreign_successor = prepared.record().clone();
        let _token = prepared.commit_after_durable(&foreign_successor).unwrap();
        assert_eq!(
            owner.reconcile(f.profile, &f.keys, &foreign_successor, &f.iv),
            Err(Error::InvalidRecord)
        );
        terminal(&mut owner, &f, &old, Some(4));
        assert_eq!(
            f.window.enable_empty_replies(Policy::default()),
            Err(Error::Canonical(CanonicalError::Invalidated))
        );
        owner.delete();
    });
}

#[test]
fn changed_same_generation_rollback_and_window_iv_floor_are_terminal() {
    for mutation in 0..3 {
        each(31_300 + mutation * 10, |mut f| {
            let mut window = start(&f, 4, true);
            let old = window.record().clone();
            let prepared = window
                .prepare_request(
                    f.profile,
                    &f.keys,
                    f.allocator.allocate(Purpose::Ordinary).unwrap(),
                    Exchange::Informational,
                    delete(),
                )
                .unwrap();
            let latest = prepared.record().clone();
            let _token = prepared.commit_after_durable(&latest).unwrap();
            let altered = if mutation == 0 {
                old
            } else {
                let sync = latest.sync_state().unwrap();
                Record::from_persisted(
                    latest.domain().clone(),
                    latest.generation(),
                    latest.next_send(),
                    if mutation == 1 {
                        Some(5)
                    } else {
                        latest.next_receive()
                    },
                    latest.outbound().cloned(),
                    latest.inbound().cloned(),
                )
                .unwrap()
                .with_sync_state(
                    SyncRecord::from_persisted(
                        sync.agreement(),
                        sync.highest_local_request(),
                        sync.highest_peer_request(),
                        sync.highest_local_proposal(),
                        sync.highest_peer_proposal(),
                        sync.disposition(),
                        if mutation == 2 {
                            2
                        } else {
                            sync.minimum_send_iv_end()
                        },
                    )
                    .unwrap(),
                )
                .unwrap()
            };
            assert_eq!(
                window.reconcile(f.profile, &f.keys, &altered, &f.iv),
                Err(Error::InvalidRecord)
            );
            terminal(&mut window, &f, &latest, Some(4));
            window.delete();
        });
    }
}

#[test]
fn only_iv_high_water_can_increase_and_it_cannot_later_fall() {
    each(31_400, |f| {
        let mut window = start(&f, 4, false);
        let old = window.record().clone();
        let raised = f.stored(Some(1), 128);
        window.reconcile(f.profile, &f.keys, &old, &raised).unwrap();
        assert_eq!(
            window.reconcile(f.profile, &f.keys, &old, &f.iv),
            Err(Error::InvalidRecord)
        );
        terminal(&mut window, &f, &old, Some(4));
        window.delete();
    });
    for marker in [false, true] {
        each(31_410 + u64::from(marker) * 10, |f| {
            let mut window = start(&f, 4, false);
            let old = window.record().clone();
            let altered = IvRecord::from_persisted(
                f.inputs(),
                if marker {
                    f.iv.limits()
                } else {
                    Limits::new(1023, 2, 1, 2).unwrap()
                },
                64,
                if marker { None } else { Some(1) },
            )
            .unwrap();
            assert!(window
                .reconcile(f.profile, &f.keys, &old, &altered)
                .is_err());
            terminal(&mut window, &f, &old, Some(4));
            window.delete();
        });
    }
}

#[test]
fn unlanded_witness_iv_must_be_covered_including_responder_reply() {
    for responder in [false, true] {
        each(31_500 + u64::from(responder) * 10, |mut f| {
            let mut window = start(&f, 4, responder);
            let old = window.record().clone();
            for _ in 0..64 {
                drop(f.allocator.allocate(Purpose::Ordinary).unwrap());
            }
            let reservation = f.allocator.prepare(64, Purpose::Ordinary).unwrap();
            let raised = reservation.record().clone();
            reservation.activate_after_commit(&raised).unwrap();
            if responder {
                let prepared = window
                    .begin_sync_response(
                        f.profile,
                        &f.keys,
                        &sync_wire(&f, false, [1; 4], 8, 0),
                        None,
                        None,
                    )
                    .unwrap()
                    .prepare(
                        f.profile,
                        &f.keys,
                        f.allocator.allocate(Purpose::Ordinary).unwrap(),
                    )
                    .unwrap();
                assert_eq!(
                    prepared
                        .record()
                        .sync_state()
                        .unwrap()
                        .minimum_send_iv_end(),
                    65
                );
            } else {
                drop(
                    window
                        .prepare_request(
                            f.profile,
                            &f.keys,
                            f.allocator.allocate(Purpose::Ordinary).unwrap(),
                            Exchange::Informational,
                            delete(),
                        )
                        .unwrap(),
                );
            }
            assert_eq!(
                window.reconcile(f.profile, &f.keys, &old, &f.iv),
                Err(Error::InvalidRecord),
                "an unlanded sealed IV must not vanish from validation"
            );
            terminal(&mut window, &f, &old, Some(4));
            window.delete();
        });
    }
}

#[test]
fn foreign_records_revoke_runtime_and_both_supplied_bindings() {
    each(31_600, |f| {
        let mut owner = start(&f, 4, false);
        let old = owner.record().clone();
        let other = Fixture::new(
            41_600
                + u64::from(f.profile.encryption().key_material_len() as u32) * 2
                + u64::from(f.direction == DIRECTIONS[1]),
            f.profile.encryption(),
            f.direction,
        );
        let mut foreign = start(&other, 4, false);
        let mixed = foreign.record().clone();
        assert_eq!(
            owner.reconcile(f.profile, &f.keys, &mixed, &other.iv),
            Err(Error::DomainMismatch)
        );
        terminal(&mut owner, &f, &old, Some(4));
        assert_eq!(
            foreign.reply_empty(&other.request(4)).unwrap_err(),
            Error::Canonical(CanonicalError::Invalidated)
        );
        owner.delete();
        foreign.delete();
    });
}

#[test]
fn max_empty_reply_survives_unchanged_readback_without_reopening_ids() {
    each(31_700, |f| {
        let mut window = start(&f, u32::MAX, false);
        let request = f.request(u32::MAX);
        let bytes = window.reply_empty(&request).unwrap().bytes().to_vec();
        let old = window.record().clone();
        window.reconcile(f.profile, &f.keys, &old, &f.iv).unwrap();
        assert_eq!(window.next_receive(), None);
        assert_eq!(window.reply_empty(&request).unwrap().bytes(), bytes);
        assert_eq!(window.reply_empty(&f.request(0)).unwrap_err(), Error::Drop);
        window.delete();
    });
}

#[test]
fn readback_revalidates_supplied_keys_even_when_both_records_are_unchanged() {
    each(31_800, |f| {
        let mut window = start(&f, 4, false);
        let old = window.record().clone();
        let changed = canonical_fixtures::key_material(f.profile, 99_999);
        assert_eq!(
            window.reconcile(f.profile, &changed, &old, &f.iv),
            Err(Error::DomainMismatch)
        );
        terminal(&mut window, &f, &old, Some(4));
        window.delete();
    });
}

#[test]
fn mismatching_acknowledgements_keep_each_completion_family_witness() {
    for kind in 0..3 {
        each(31_900 + kind * 10, |mut f| {
            let mut window = start(&f, 4, true);
            let old = window.record().clone();
            let candidate = match kind {
                0 => {
                    let prepared = window
                        .prepare_request(
                            f.profile,
                            &f.keys,
                            f.allocator.allocate(Purpose::Ordinary).unwrap(),
                            Exchange::Informational,
                            delete(),
                        )
                        .unwrap();
                    let candidate = prepared.record().clone();
                    assert_eq!(
                        prepared.commit_after_durable(&old).unwrap_err(),
                        Error::CommitMismatch
                    );
                    candidate
                }
                1 => {
                    let prepared = window
                        .begin_sync(policy(), Clock::new(100, 7), None)
                        .unwrap()
                        .prepare(
                            f.profile,
                            &f.keys,
                            f.allocator.allocate(Purpose::Ordinary).unwrap(),
                        )
                        .unwrap();
                    let candidate = prepared.record().clone();
                    assert_eq!(
                        prepared
                            .commit_after_durable(&old, Clock::new(100, 7))
                            .unwrap_err(),
                        Error::CommitMismatch
                    );
                    candidate
                }
                _ => {
                    let prepared = window
                        .begin_sync_response(
                            f.profile,
                            &f.keys,
                            &sync_wire(&f, false, [1; 4], 8, 0),
                            None,
                            None,
                        )
                        .unwrap()
                        .prepare(
                            f.profile,
                            &f.keys,
                            f.allocator.allocate(Purpose::Ordinary).unwrap(),
                        )
                        .unwrap();
                    let candidate = prepared.record().clone();
                    assert_eq!(
                        prepared.commit_after_durable(&old).unwrap_err(),
                        Error::CommitMismatch
                    );
                    candidate
                }
            };
            assert_eq!(window.ready(), Err(Error::CommitUncertain));
            window
                .reconcile(f.profile, &f.keys, &candidate, &f.iv)
                .unwrap();
            assert_eq!(window.record(), &candidate);
            window.delete();
        });
    }
}
