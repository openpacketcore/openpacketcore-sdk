//! CBC instances of the shared fenced-readback and RFC 6311 lifecycle contract.
#![allow(clippy::unwrap_used)]

use crate::canonical::{Ikev2CanonicalError as CanonicalError, Ikev2CanonicalPolicy};
use crate::recovery::{
    cbc_test_fixtures::*, Ikev2AuthenticatedOrdinary as Ordinary, Ikev2CommittedWindow as Window,
    Ikev2CommittedWindowRecord as Record, Ikev2OrdinaryRequestDisposition as Disposition,
    Ikev2SyncClock as Clock, Ikev2SyncDisposition, Ikev2SyncInitiatorAction as Action,
    Ikev2SyncRecoveryPolicy, Ikev2WindowCommit, Ikev2WindowError as Error,
};
use crate::{Ikev2ExchangeKind as Exchange, Ikev2MessageIdSync as Sync, PayloadChain, PayloadType};
use bytes::Bytes;

fn empty() -> PayloadChain<'static> {
    PayloadChain::new(PayloadType::NoNext, &[])
}

fn work(f: &Fixture, id: u32, padding: u8) -> Ordinary<Cbc> {
    let wire = f.peer_wire(id, PayloadChain::new(PayloadType::Delete, DELETE), padding);
    super::super::packet::open(&f.domain, f.profile, &f.keys, &wire, true).unwrap()
}

fn response(f: &Fixture, id: u32) -> Ordinary<Cbc> {
    let wire = f.peer_packet(id, true, empty(), 0);
    super::super::packet::open(&f.domain, f.profile, &f.keys, &wire, true).unwrap()
}

fn sync_wire(f: &Fixture, response: bool, value: Sync) -> Bytes {
    let mut payload = vec![0, 0, 0, 20, 0, 0, 0x40, 0x26];
    payload.extend_from_slice(&value.nonce());
    payload.extend_from_slice(&value.expected_send_req_message_id().to_be_bytes());
    payload.extend_from_slice(&value.expected_recv_req_message_id().to_be_bytes());
    f.peer_packet(
        0,
        response,
        PayloadChain::new(PayloadType::Notify, &payload),
        0,
    )
}

fn clock(ms: u64) -> Clock {
    Clock::new(ms, 7)
}

fn policy() -> Ikev2SyncRecoveryPolicy {
    Ikev2SyncRecoveryPolicy::new(1, clock(100), 1000, 3, 10).unwrap()
}

fn commit_request(window: &mut Window<Cbc>, f: &Fixture) -> Ikev2WindowCommit {
    let prepared = window
        .prepare_request(
            f.profile,
            &f.keys,
            Exchange::Informational,
            PayloadChain::new(PayloadType::Delete, DELETE),
        )
        .unwrap();
    let record = prepared.record().clone();
    prepared.commit_after_durable(&record).unwrap()
}

// A settled outbound exchange leaves a usable completion token at this exact
// generation. A volatile DPD prefix then runs ahead of the durable receive floor.
fn start(f: &Fixture) -> (Window<Cbc>, Ikev2WindowCommit, Vec<u8>) {
    let mut window = f.synced();
    let token = commit_request(&mut window, f);
    assert_eq!(window.apply_committed(token).unwrap(), None);
    let prepared = window
        .prepare_completion(&response(f, 1), Bytes::from_static(b"settled"))
        .unwrap();
    let record = prepared.record().clone();
    let token = prepared.commit_after_durable(&record).unwrap();
    window
        .enable_empty_replies(Ikev2CanonicalPolicy::default())
        .unwrap();
    let cached = window
        .reply_empty(&f.request(10, 0))
        .unwrap()
        .bytes()
        .to_vec();
    assert_eq!(window.next_receive(), Some(11));
    assert_eq!(window.record().next_receive(), Some(1));
    (window, token, cached)
}

fn live_proposal(window: &mut Window<Cbc>, f: &Fixture) -> Bytes {
    let prepared = window
        .begin_sync(policy(), clock(100), None)
        .unwrap()
        .prepare(f.profile, &f.keys)
        .unwrap();
    let record = prepared.record().clone();
    let token = prepared.commit_after_durable(&record, clock(100)).unwrap();
    let Action::SendRequest(wire) = window.release_sync_action(token, clock(100)).unwrap() else {
        panic!("expected one request");
    };
    wire
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Exposure {
    Request,
    Response,
    Completion,
    SyncResponse,
    SyncInitial,
    SyncRetry,
    SyncComplete,
    SyncClose,
}

const EXPOSURES: [Exposure; 8] = [
    Exposure::Request,
    Exposure::Response,
    Exposure::Completion,
    Exposure::SyncResponse,
    Exposure::SyncInitial,
    Exposure::SyncRetry,
    Exposure::SyncComplete,
    Exposure::SyncClose,
];

fn expose(
    window: &mut Window<Cbc>,
    f: &Fixture,
    exposure: Exposure,
    mismatched_ack: bool,
) -> (Record<Cbc>, Record<Cbc>) {
    macro_rules! candidate {
        ($prepared:expr $(, $clock:expr)?) => {{
            let old = window.record().clone();
            let prepared = $prepared;
            let candidate = prepared.record().clone();
            if mismatched_ack {
                let mut wrong = candidate.clone();
                wrong.generation += 1;
                assert_eq!(
                    prepared.commit_after_durable(&wrong $(, $clock)?).unwrap_err(),
                    Error::CommitMismatch,
                    "{exposure:?} acknowledgement must match every field"
                );
            } else {
                drop(prepared);
            }
            (old, candidate)
        }};
    }
    match exposure {
        Exposure::Request => candidate!(window
            .prepare_request(
                f.profile,
                &f.keys,
                Exchange::Informational,
                PayloadChain::new(PayloadType::Delete, DELETE)
            )
            .unwrap()),
        Exposure::Response => candidate!(window
            .prepare_response(
                f.profile,
                &f.keys,
                &work(f, 11, 0),
                empty(),
                Bytes::from_static(b"inbound")
            )
            .unwrap()),
        Exposure::Completion => {
            drop(commit_request(window, f));
            candidate!(window
                .prepare_completion(&response(f, 2), Bytes::from_static(b"done"))
                .unwrap())
        }
        Exposure::SyncResponse => candidate!(window
            .begin_sync_response(
                f.profile,
                &f.keys,
                &sync_wire(f, false, Sync::new([1; 4], 100, 50)),
                None,
                None
            )
            .unwrap()
            .prepare(f.profile, &f.keys)
            .unwrap()),
        Exposure::SyncInitial => candidate!(
            window
                .begin_sync(policy(), clock(100), None)
                .unwrap()
                .prepare(f.profile, &f.keys)
                .unwrap(),
            clock(100)
        ),
        Exposure::SyncRetry => {
            live_proposal(window, f);
            candidate!(
                window
                    .retry_sync(clock(110))
                    .unwrap()
                    .prepare(f.profile, &f.keys)
                    .unwrap(),
                clock(110)
            )
        }
        Exposure::SyncComplete => {
            live_proposal(window, f);
            let pending = window
                .record()
                .sync_recovery()
                .unwrap()
                .pending()
                .unwrap()
                .notification();
            let wire = sync_wire(f, true, Sync::new(pending.nonce(), 100, 50));
            candidate!(
                window
                    .complete_sync(f.profile, &f.keys, &wire, clock(101))
                    .unwrap(),
                clock(101)
            )
        }
        Exposure::SyncClose => {
            assert_eq!(
                window.begin_sync(policy(), clock(50), None).unwrap_err(),
                Error::SyncClosed
            );
            candidate!(window.close_sync().unwrap(), clock(100))
        }
    }
}

#[test]
fn cbc_all_seven_witnesses_accept_only_exact_cancelled_or_landed_readback() {
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            for (case, exposure) in EXPOSURES.into_iter().enumerate() {
                for landed in [false, true] {
                    let tag = 1_060_000
                        + (index * 32 + role * 16 + case * 2 + usize::from(landed)) as u64;
                    let f = Fixture::new(profile, direction, tag);
                    let (mut window, token, cached) = start(&f);
                    let (old, candidate) = expose(&mut window, &f, exposure, false);
                    assert_eq!(window.ready(), Err(Error::CommitUncertain));
                    let readback = if landed { &candidate } else { &old };
                    window
                        .reconcile(profile, &f.keys, readback, &f.epoch)
                        .unwrap();
                    assert_eq!(window.record(), readback, "{exposure:?}/{landed}");
                    assert_eq!(window.apply_committed(token), Err(Error::StaleCompletion));
                    let boundary =
                        landed && !matches!(exposure, Exposure::Request | Exposure::Completion);
                    let expected = match (exposure, landed) {
                        (Exposure::Response, true) => 12,
                        (Exposure::SyncResponse | Exposure::SyncComplete, true) => 100,
                        _ => 11,
                    };
                    assert_eq!(
                        window.next_receive(),
                        Some(expected),
                        "{exposure:?}/{landed}"
                    );
                    assert_eq!(
                        window.is_reconstructing(),
                        !boundary
                            && !matches!(exposure, Exposure::SyncRetry | Exposure::SyncComplete)
                    );
                    let ready = match exposure {
                        Exposure::SyncClose => Err(Error::SyncClosed),
                        Exposure::SyncRetry => Err(Error::SyncInProgress),
                        Exposure::SyncInitial if landed => Err(Error::SyncInProgress),
                        Exposure::SyncComplete if !landed => Err(Error::SyncInProgress),
                        _ => Ok(()),
                    };
                    assert_eq!(window.ready(), ready, "{exposure:?}/{landed}");
                    if ready.is_ok() {
                        assert_eq!(
                            window.enable_empty_replies(Ikev2CanonicalPolicy::default()),
                            Err(Error::Canonical(CanonicalError::CapabilityActive)),
                            "readback must keep the original owner"
                        );
                        if matches!(exposure, Exposure::Request | Exposure::Completion)
                            || (!landed
                                && matches!(
                                    exposure,
                                    Exposure::SyncResponse | Exposure::SyncInitial
                                ))
                        {
                            assert_eq!(
                                window.reply_empty(&f.request(10, 0)).unwrap().bytes(),
                                cached
                            );
                        } else {
                            assert_eq!(
                                window.reply_empty(&f.request(10, 0)).unwrap_err(),
                                Error::Drop
                            );
                        }
                    }
                    if exposure == Exposure::Response {
                        assert_eq!(
                            window.request_disposition(&work(&f, 11, 0)),
                            Ok(if landed {
                                Disposition::CachedResponse
                            } else {
                                Disposition::New
                            })
                        );
                        if landed {
                            assert_eq!(
                                window.replay_response(&work(&f, 11, 0)).unwrap().bytes(),
                                candidate.inbound().unwrap().response().unwrap()
                            );
                            let bytes = window
                                .reply_empty(&f.request(12, 0))
                                .unwrap()
                                .bytes()
                                .to_vec();
                            window
                                .reconcile(profile, &f.keys, readback, &f.epoch)
                                .unwrap();
                            assert_eq!(
                                window.reply_empty(&f.request(12, 0)).unwrap().bytes(),
                                bytes,
                                "an acknowledged boundary must not be adopted twice"
                            );
                        } else {
                            assert_eq!(
                                window.request_disposition(&work(&f, 11, 1)),
                                Err(Error::Drop)
                            );
                            assert_eq!(
                                window.request_disposition(&work(&f, 12, 0)),
                                Err(Error::Drop)
                            );
                        }
                    }
                    if exposure == Exposure::SyncResponse && landed {
                        assert_eq!(
                            window
                                .begin_sync_response(
                                    profile,
                                    &f.keys,
                                    &sync_wire(&f, false, Sync::new([1; 4], 100, 50)),
                                    None,
                                    None
                                )
                                .unwrap_err(),
                            Error::Drop
                        );
                    }
                    if matches!(exposure, Exposure::SyncInitial | Exposure::SyncRetry) && landed {
                        let pending = readback
                            .sync_recovery()
                            .unwrap()
                            .pending()
                            .unwrap()
                            .notification();
                        assert_eq!(
                            window
                                .complete_sync(
                                    profile,
                                    &f.keys,
                                    &sync_wire(&f, true, Sync::new(pending.nonce(), 100, 50)),
                                    clock(111)
                                )
                                .unwrap_err(),
                            Error::Drop
                        );
                        let prepared = window
                            .retry_sync(clock(120))
                            .unwrap()
                            .prepare(profile, &f.keys)
                            .unwrap();
                        let retry = prepared
                            .record()
                            .sync_recovery()
                            .unwrap()
                            .pending()
                            .unwrap()
                            .notification();
                        assert!(
                            retry.expected_send_req_message_id()
                                > pending.expected_send_req_message_id()
                        );
                        assert_ne!(retry.nonce(), pending.nonce());
                    }
                    window.delete();
                }
            }
        }
    }
}

#[test]
fn cbc_mismatched_acknowledgements_keep_every_witness_but_unwitnessed_readback_revokes() {
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            for (case, exposure) in EXPOSURES.into_iter().enumerate() {
                let tag = 1_062_000 + (index * 16 + role * 8 + case) as u64;
                let f = Fixture::new(profile, direction, tag);
                let (mut window, _, _) = start(&f);
                let (_, candidate) = expose(&mut window, &f, exposure, true);
                assert_eq!(window.ready(), Err(Error::CommitUncertain));
                assert!(window.witness.is_some());
                window
                    .reconcile(profile, &f.keys, &candidate, &f.epoch)
                    .unwrap();
                assert_eq!(window.record(), &candidate);
                assert!(window.witness.is_none());
                let mut unseen = candidate.clone();
                unseen.generation += 1;
                assert_eq!(
                    window.reconcile(profile, &f.keys, &unseen, &f.epoch),
                    Err(Error::InvalidRecord)
                );
                assert_eq!(
                    window.enable_empty_replies(Ikev2CanonicalPolicy::default()),
                    Err(Error::Canonical(CanonicalError::Invalidated))
                );
                assert_eq!(
                    window.reconcile(profile, &f.keys, &candidate, &f.epoch),
                    Err(Error::Canonical(CanonicalError::Invalidated))
                );
                assert_eq!(
                    crate::canonical::Ikev2CanonicalEmptyReplies::<Cbc>::from_epoch(
                        &f.epoch,
                        Ikev2CanonicalPolicy::default()
                    )
                    .unwrap_err(),
                    CanonicalError::Invalidated
                );
                window.delete();
            }
        }
    }
}

#[test]
fn cbc_same_generation_valid_record_cannot_substitute_an_unwitnessed_outcome() {
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            for case in 0..3 {
                let f = Fixture::new(
                    profile,
                    direction,
                    1_070_000 + (index * 6 + role * 3 + case) as u64,
                );
                let (mut window, _, _) = start(&f);
                let mut changed = if case == 0 {
                    window.record().clone()
                } else {
                    expose(
                        &mut window,
                        &f,
                        if case == 1 {
                            Exposure::Response
                        } else {
                            Exposure::Completion
                        },
                        false,
                    )
                    .1
                };
                let entry = if case == 1 {
                    changed.inbound.as_mut()
                } else {
                    changed.outbound.as_mut()
                }
                .unwrap();
                entry.outcome = Some(Bytes::from_static(b"unwitnessed"));
                // Packet authentication and storage validation accept this
                // self-consistent record. Only exact private history rejects it.
                assert_eq!(f.restore(&changed).record(), &changed);
                assert_eq!(
                    window.reconcile(profile, &f.keys, &changed, &f.epoch),
                    Err(Error::InvalidRecord)
                );
                assert_eq!(
                    window.enable_empty_replies(Ikev2CanonicalPolicy::default()),
                    Err(Error::Canonical(CanonicalError::Invalidated))
                );
                window.delete();
            }
        }
    }
}

fn respond(window: &mut Window<Cbc>, f: &Fixture, wire: &[u8]) -> (Bytes, Ikev2SyncDisposition) {
    let prepared = window
        .begin_sync_response(f.profile, &f.keys, wire, None, None)
        .unwrap()
        .prepare(f.profile, &f.keys)
        .unwrap();
    let record = prepared.record().clone();
    let token = prepared.commit_after_durable(&record).unwrap();
    window.release_sync_response(token).unwrap().into_parts()
}

fn complete(window: &mut Window<Cbc>, f: &Fixture, wire: &[u8]) {
    let prepared = window
        .complete_sync(f.profile, &f.keys, wire, clock(101))
        .unwrap();
    let record = prepared.record().clone();
    let token = prepared.commit_after_durable(&record, clock(101)).unwrap();
    assert!(matches!(
        window.release_sync_action(token, clock(101)).unwrap(),
        Action::Recovered
    ));
}

#[test]
fn cbc_crossed_and_withheld_sync_requests_converge_in_both_response_orders() {
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            for order in 0..4 {
                let tag = 1_067_000 + (index * 8 + role * 4 + order) as u64;
                let a = Fixture::new(profile, direction, tag);
                let b = Fixture::new(profile, opposite(direction), tag);
                let declared = if order == 3 { 8 } else { 5 };
                let mut aw = a.synced_at(4, declared);
                let mut bw = b.synced_at(5, 5);
                let ar = live_proposal(&mut aw, &a);
                let br = live_proposal(&mut bw, &b);
                let (reply_a, disposition) = respond(&mut bw, &b, &ar);
                assert_eq!(disposition, Ikev2SyncDisposition::AwaitLocalSync);
                assert_eq!(bw.ready(), Err(Error::SyncInProgress));
                if order >= 2 {
                    complete(&mut aw, &a, &reply_a);
                }
                let (reply_b, disposition) = respond(&mut aw, &a, &br);
                assert_eq!(
                    disposition,
                    if order >= 2 {
                        Ikev2SyncDisposition::Continue
                    } else {
                        Ikev2SyncDisposition::AwaitLocalSync
                    }
                );
                if order == 0 {
                    complete(&mut aw, &a, &reply_a);
                    complete(&mut bw, &b, &reply_b);
                } else {
                    complete(&mut bw, &b, &reply_b);
                    if order == 1 {
                        complete(&mut aw, &a, &reply_a);
                    }
                }
                assert_eq!(
                    (aw.record().next_send(), aw.next_receive()),
                    (Some(5), Some(declared))
                );
                assert_eq!(
                    (bw.record().next_send(), bw.next_receive()),
                    (Some(declared), Some(5))
                );
                for (window, f, peer_request, floor) in
                    [(&mut aw, &a, &br, declared), (&mut bw, &b, &ar, 5)]
                {
                    assert_eq!(window.ready(), Ok(()));
                    assert_eq!(
                        window
                            .begin_sync_response(profile, &f.keys, peer_request, None, None)
                            .unwrap_err(),
                        Error::Drop
                    );
                    assert_eq!(
                        window.request_disposition(&work(f, floor - 1, 0)),
                        Err(Error::Drop)
                    );
                    assert_eq!(
                        window.request_disposition(&work(f, floor + 1, 0)),
                        Err(Error::Drop)
                    );
                    assert_eq!(
                        window.request_disposition(&work(f, floor, 0)),
                        Ok(Disposition::New)
                    );
                    assert_eq!(f.restore(window.record()).ready(), Ok(()));
                }
                aw.delete();
                bw.delete();
            }
        }
    }
}

#[test]
fn cbc_pending_ordinary_work_and_observed_empty_ids_control_peer_sync() {
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            for inbound in [false, true] {
                let f = Fixture::new(
                    profile,
                    direction,
                    1_068_000 + (index * 4 + role * 2 + usize::from(inbound)) as u64,
                );
                let (mut window, _, _) = start(&f);
                if inbound {
                    assert_eq!(
                        window.request_disposition(&work(&f, 11, 0)),
                        Ok(Disposition::New)
                    );
                } else {
                    drop(commit_request(&mut window, &f));
                }
                assert_eq!(
                    window.begin_sync(policy(), clock(100), None).unwrap_err(),
                    Error::RequestOutstanding
                );
                let old = window.record().clone();
                window.reconcile(profile, &f.keys, &old, &f.epoch).unwrap();
                let highest = if inbound { 11 } else { 10 };
                assert_eq!(
                    window
                        .begin_sync_response(
                            profile,
                            &f.keys,
                            &sync_wire(&f, false, Sync::new([1; 4], highest, 50)),
                            None,
                            None
                        )
                        .unwrap_err(),
                    Error::Drop
                );
                let (_, disposition) = respond(
                    &mut window,
                    &f,
                    &sync_wire(&f, false, Sync::new([2; 4], highest + 1, 50)),
                );
                assert_eq!(disposition, Ikev2SyncDisposition::OutcomeUncertain);
                assert_eq!(window.ready(), Err(Error::OutcomeUncertain));
                let record = window.record().clone();
                window
                    .reconcile(profile, &f.keys, &record, &f.epoch)
                    .unwrap();
                assert_eq!(window.ready(), Err(Error::OutcomeUncertain));
                assert_eq!(f.restore(&record).ready(), Err(Error::OutcomeUncertain));
                assert_eq!(window.close_sync().unwrap_err(), Error::OutcomeUncertain);
                window.delete();
            }
        }
    }
}

#[test]
fn cbc_authenticated_wrong_sync_nonce_counters_class_and_notify_shape_drop_without_progress() {
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            let f = Fixture::new(profile, direction, 1_069_000 + (index * 2 + role) as u64);
            let mut window = f.synced_at(2, 3);
            live_proposal(&mut window, &f);
            let record = window.record().clone();
            let nonce = record
                .sync_recovery()
                .unwrap()
                .pending()
                .unwrap()
                .notification()
                .nonce();
            let mut wrong = nonce;
            wrong[0] ^= 1;
            let correct = sync_wire(&f, true, Sync::new(nonce, 3, 2));
            for wire in [
                sync_wire(&f, true, Sync::new(wrong, 3, 2)),
                sync_wire(&f, true, Sync::new(nonce, 2, 2)),
                sync_wire(&f, true, Sync::new(nonce, 3, 1)),
                sync_wire(&f, false, Sync::new(nonce, 3, 2)),
                f.peer_packet(0, true, empty(), 0),
                f.peer_packet(1, true, empty(), 0),
                f.peer_packet(0, true, PayloadChain::new(PayloadType::Delete, DELETE), 0),
            ] {
                assert_eq!(
                    window
                        .complete_sync(profile, &f.keys, &wire, clock(101))
                        .unwrap_err(),
                    Error::Drop
                );
                assert_eq!(window.record(), &record);
            }
            let mut payload = vec![0, 0, 0, 20, 0, 0, 0x40, 0x26];
            payload.extend_from_slice(&nonce);
            payload.extend_from_slice(&3_u32.to_be_bytes());
            payload.extend_from_slice(&2_u32.to_be_bytes());
            let mut duplicate = payload.clone();
            duplicate[0] = PayloadType::Notify.as_u8();
            duplicate.extend_from_slice(&payload);
            let mut malformed = payload;
            malformed[5] = 1;
            for payload in [duplicate, malformed] {
                let wire =
                    f.peer_packet(0, true, PayloadChain::new(PayloadType::Notify, &payload), 0);
                assert_eq!(
                    window
                        .complete_sync(profile, &f.keys, &wire, clock(101))
                        .unwrap_err(),
                    Error::Drop
                );
                assert_eq!(window.record(), &record);
            }
            assert_eq!(
                window.retry_sync(clock(101)).unwrap_err(),
                Error::SyncBackoff
            );
            complete(&mut window, &f, &correct);
            assert_eq!(
                window
                    .complete_sync(profile, &f.keys, &correct, clock(110))
                    .unwrap_err(),
                Error::Drop
            );
            window.delete();
        }
    }
}

#[test]
fn cbc_readback_fences_all_three_completion_types_at_the_same_generation() {
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            for kind in 0..3 {
                let f = Fixture::new(
                    profile,
                    direction,
                    1_064_000 + (index * 6 + role * 3 + kind) as u64,
                );
                let (mut window, ordinary, cached) = start(&f);
                if kind == 0 {
                    let record = window.record().clone();
                    window
                        .reconcile(profile, &f.keys, &record, &f.epoch)
                        .unwrap();
                    assert_eq!(
                        window.apply_committed(ordinary),
                        Err(Error::StaleCompletion)
                    );
                    assert_eq!(
                        window.reply_empty(&f.request(10, 0)).unwrap().bytes(),
                        cached
                    );
                } else if kind == 1 {
                    let prepared = window
                        .begin_sync(policy(), clock(100), None)
                        .unwrap()
                        .prepare(profile, &f.keys)
                        .unwrap();
                    let record = prepared.record().clone();
                    let token = prepared.commit_after_durable(&record, clock(100)).unwrap();
                    window
                        .reconcile(profile, &f.keys, &record, &f.epoch)
                        .unwrap();
                    assert_eq!(
                        window.release_sync_action(token, clock(100)).unwrap_err(),
                        Error::StaleCompletion
                    );
                } else {
                    let prepared = window
                        .begin_sync_response(
                            profile,
                            &f.keys,
                            &sync_wire(&f, false, Sync::new([3; 4], 100, 50)),
                            None,
                            None,
                        )
                        .unwrap()
                        .prepare(profile, &f.keys)
                        .unwrap();
                    let record = prepared.record().clone();
                    let token = prepared.commit_after_durable(&record).unwrap();
                    window
                        .reconcile(profile, &f.keys, &record, &f.epoch)
                        .unwrap();
                    assert_eq!(
                        window.release_sync_response(token).unwrap_err(),
                        Error::StaleCompletion
                    );
                }
                window.delete();
            }
        }
    }
}

#[test]
fn cbc_readback_fences_sent_sync_and_retains_cache_after_unsealed_admission() {
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            for case in 0..3 {
                let f = Fixture::new(
                    profile,
                    direction,
                    1_073_000 + (index * 6 + role * 3 + case) as u64,
                );
                let (mut window, _, cached) = start(&f);
                if case == 2 {
                    live_proposal(&mut window, &f);
                }
                let record = window.record().clone();
                if case == 0 {
                    drop(window.begin_sync(policy(), clock(100), None).unwrap());
                } else if case == 1 {
                    drop(
                        window
                            .begin_sync_response(
                                profile,
                                &f.keys,
                                &sync_wire(&f, false, Sync::new([4; 4], 100, 50)),
                                None,
                                None,
                            )
                            .unwrap(),
                    );
                }
                window
                    .reconcile(profile, &f.keys, &record, &f.epoch)
                    .unwrap();
                assert_eq!(window.record(), &record);
                if case == 2 {
                    let nonce = record
                        .sync_recovery()
                        .unwrap()
                        .pending()
                        .unwrap()
                        .notification()
                        .nonce();
                    assert_eq!(
                        window
                            .complete_sync(
                                profile,
                                &f.keys,
                                &sync_wire(&f, true, Sync::new(nonce, 100, 50)),
                                clock(101)
                            )
                            .unwrap_err(),
                        Error::Drop
                    );
                    assert_eq!(window.ready(), Err(Error::SyncInProgress));
                    assert_eq!(
                        window.retry_sync(clock(109)).unwrap_err(),
                        Error::SyncBackoff
                    );
                } else {
                    assert_eq!(window.ready(), Ok(()));
                    assert_eq!(window.next_receive(), Some(11));
                    assert_eq!(
                        window.reply_empty(&f.request(10, 0)).unwrap().bytes(),
                        cached
                    );
                }
                window.delete();
            }
        }
    }
}

#[test]
fn cbc_readback_retains_sync_clock_rollback_epoch_and_deadline_closures() {
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            for (case, invalid) in [clock(119), Clock::new(121, 8), clock(1100)]
                .into_iter()
                .enumerate()
            {
                let f = Fixture::new(
                    profile,
                    direction,
                    1_065_000 + (index * 6 + role * 3 + case) as u64,
                );
                let mut window = f.synced();
                live_proposal(&mut window, &f);
                let record = window.record().clone();
                window.check_sync_deadline(clock(120)).unwrap();
                window
                    .reconcile(profile, &f.keys, &record, &f.epoch)
                    .unwrap();
                assert_eq!(window.check_sync_deadline(invalid), Err(Error::SyncClosed));
                window
                    .reconcile(profile, &f.keys, &record, &f.epoch)
                    .unwrap();
                assert_eq!(window.ready(), Err(Error::SyncClosed));
                window.delete();
            }
        }
    }
}

#[test]
fn cbc_close_commit_and_readback_preserve_the_exhausted_live_receive_floor() {
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            for mode in 0..3 {
                let f = Fixture::new(
                    profile,
                    direction,
                    1_066_000 + (index * 6 + role * 3 + mode) as u64,
                );
                let mut window = f.synced();
                window
                    .enable_empty_replies(Ikev2CanonicalPolicy::default())
                    .unwrap();
                let old = window.record().clone();
                window.reply_empty(&f.request(u32::MAX, 0)).unwrap();
                assert_eq!(window.next_receive(), None);
                assert_eq!(
                    window.begin_sync(policy(), clock(50), None).unwrap_err(),
                    Error::SyncClosed
                );
                let prepared = window.close_sync().unwrap();
                let candidate = prepared.record().clone();
                if mode == 0 {
                    let token = prepared
                        .commit_after_durable(&candidate, clock(100))
                        .unwrap();
                    assert!(matches!(
                        window.release_sync_action(token, clock(100)).unwrap(),
                        Action::CloseIkeSa
                    ));
                } else {
                    drop(prepared);
                    window
                        .reconcile(
                            profile,
                            &f.keys,
                            if mode == 1 { &old } else { &candidate },
                            &f.epoch,
                        )
                        .unwrap();
                }
                assert_eq!(window.next_receive(), None);
                assert_eq!(window.ready(), Err(Error::SyncClosed));
                window.delete();
            }
        }
    }
}
