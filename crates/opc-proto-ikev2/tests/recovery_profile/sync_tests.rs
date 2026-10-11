//! Consumer sync handlers against independent peer counters and deadlines.

use super::{
    authority::{EpochOwners, Transport},
    driver::{self, Cut, Runtime},
    envelope::Provider,
    ke,
    lifecycle::{child_delete, matrix},
    module,
    peer::{Event, PeerModel, Sync, REQUEST_TIMEOUT_MS},
    row::{KeKind, Outcome, Row},
    store::CasStore,
    sync_driver::Start,
    wire::Wire,
};
use bytes::Bytes;
use opc_proto_ikev2::{
    recovery::{
        Ikev2SyncClock as Clock, Ikev2SyncDisposition as Disposition,
        Ikev2SyncRecoveryPolicy as Policy, Ikev2SyncRecoveryStatus as Status,
        Ikev2WindowError as WindowError,
    },
    Ikev2ExchangeKind as Exchange, Ikev2MessageIdSyncMode as Mode,
};

pub fn policy(id: u64) -> Policy {
    Policy::new(id, Clock::new(100, 9), 1000, 3, 10).unwrap()
}

pub fn set_floors(row: &mut Row, send: u32, receive: u32) {
    row.window.next_send = Some(send);
    row.window.next_receive = Some(receive);
    let sync = row.window.sync.as_mut().unwrap();
    sync.local_request = send.checked_sub(1);
    sync.peer_request = receive.checked_sub(1);
}

fn reply(event: Event) -> Bytes {
    let Event::SyncReply { wire, .. } = event else {
        panic!("expected independent sync reply");
    };
    wire
}

#[test]
fn local_sync_live_completion_and_restart_use_same_event_and_higher_fresh_retry() {
    for restart in [false, true] {
        matrix(2_400_000 + u64::from(restart) * 1000, |mut row| {
            if row.mode != Mode::Negotiated {
                return;
            }
            set_floors(&mut row, 5, 2);
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
                7,
                5,
                true,
            );
            let mut transport = Transport::default();
            runtime
                .sync_request(
                    &provider,
                    &mut store,
                    Start::New(policy(17)),
                    Clock::new(100, 9),
                    Clock::new(100, 9),
                    Cut::Complete,
                    &mut transport,
                )
                .unwrap();
            let first = transport.submitted.last().unwrap().clone();
            let first_reply = reply(peer.receive(&first).unwrap());
            let response = if restart {
                drop(runtime);
                store.succeed(8);
                owners.learn_succession(8);
                runtime = Runtime::restore(
                    &provider,
                    &owners,
                    &store.fenced_read(&initial, row.key).unwrap(),
                    false,
                )
                .unwrap();
                assert!(runtime.row.window.recovery.as_ref().unwrap().policy == policy(17));
                assert_eq!(
                    runtime.row.window.recovery.as_ref().unwrap().attempts.len(),
                    1
                );
                assert!(runtime.dispatch_replay(&mut transport).is_err());
                assert_eq!(transport.submitted.len(), 1);
                assert_eq!(
                    runtime.sync_complete(
                        &provider,
                        &mut store,
                        &first_reply,
                        Clock::new(105, 9),
                        Clock::new(105, 9),
                        Cut::Complete
                    ),
                    Err(driver::Error::Window(WindowError::Drop))
                );
                let before = (store.publications, provider.calls(), module::counts());
                assert_eq!(
                    runtime.sync_request(
                        &provider,
                        &mut store,
                        Start::Retry,
                        Clock::new(109, 9),
                        Clock::new(109, 9),
                        Cut::Complete,
                        &mut transport
                    ),
                    Err(driver::Error::Window(WindowError::SyncBackoff))
                );
                assert_eq!(
                    (store.publications, provider.calls(), module::counts()),
                    before
                );
                runtime
                    .sync_request(
                        &provider,
                        &mut store,
                        Start::Retry,
                        Clock::new(130, 9),
                        Clock::new(130, 9),
                        Cut::Complete,
                        &mut transport,
                    )
                    .unwrap();
                let second = transport.submitted.last().unwrap();
                let first_payload = peer.wire.open(&first).unwrap();
                let second_payload = peer.wire.open(second).unwrap();
                assert_ne!(&first_payload.body[8..12], &second_payload.body[8..12]);
                assert!(
                    u32::from_be_bytes(second_payload.body[12..16].try_into().unwrap())
                        > u32::from_be_bytes(first_payload.body[12..16].try_into().unwrap())
                );
                let response = reply(peer.receive(second).unwrap());
                assert_eq!(
                    runtime.sync_complete(
                        &provider,
                        &mut store,
                        &first_reply,
                        Clock::new(131, 9),
                        Clock::new(131, 9),
                        Cut::Complete
                    ),
                    Err(driver::Error::Window(WindowError::Drop))
                );
                response
            } else {
                first_reply
            };
            assert!(!runtime
                .sync_complete(
                    &provider,
                    &mut store,
                    &response,
                    Clock::new(132, 9),
                    Clock::new(2000, 10),
                    Cut::Applied
                )
                .unwrap());
            let completed = runtime.pending.as_ref().unwrap().clone();
            store.prune(completed.request());
            runtime.resolve(&provider, &store, &completed).unwrap();
            let event = runtime.row.window.recovery.as_ref().unwrap();
            assert!(event.policy == policy(17));
            assert_eq!(event.status, Status::Recovered);
            assert_eq!(event.attempts.len(), if restart { 2 } else { 1 });
            assert_eq!(runtime.row.window.next_send, peer.counters().1);
            assert_eq!(runtime.row.window.next_receive, peer.counters().0);
            let id = peer.counters().1.unwrap();
            runtime
                .reserve(
                    &provider,
                    &mut store,
                    91,
                    1,
                    200,
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
                    Cut::Complete,
                )
                .unwrap();
            runtime.dispatch_replay(&mut transport).unwrap();
            assert_eq!(
                peer.receive(transport.submitted.last().unwrap()),
                Ok(Event::NewRequest(id))
            );
            let response = peer
                .respond(id, crate::canonical_fixtures::empty())
                .unwrap();
            runtime
                .complete(
                    &provider,
                    &mut store,
                    &response,
                    Bytes::from_static(b"child-deleted"),
                    |_| {},
                    Cut::Complete,
                )
                .unwrap();
        });
    }
}

#[test]
fn responder_answers_second_sync_after_closed_event_with_only_dpd_between() {
    for (profile_id, profile) in super::inputs::profiles().enumerate() {
        if ![0, 3].contains(&profile_id) {
            continue;
        }
        for (role, direction) in crate::canonical_fixtures::DIRECTIONS
            .into_iter()
            .enumerate()
        {
            let mut row = super::inputs::fresh(
                2_920_000 + (profile_id * 2 + role) as u64,
                profile,
                direction,
                Mode::Negotiated,
            );
            set_floors(&mut row, 3, 4);
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
                    profile,
                    &row.keys,
                    row.spis,
                    crate::canonical_fixtures::opposite(direction),
                ),
                5,
                0,
                true,
            );
            let mut transport = Transport::default();
            let first = peer
                .begin_sync(Sync {
                    nonce: [1; 4],
                    send: 10,
                    receive: 2,
                })
                .unwrap();
            assert_eq!(
                runtime
                    .sync_response(
                        &provider,
                        &mut store,
                        &first,
                        None,
                        policy(29),
                        Clock::new(100, 9),
                        Cut::Complete,
                        &mut transport
                    )
                    .unwrap(),
                Some(Disposition::Continue)
            );
            assert_eq!(
                peer.receive(transport.submitted.last().unwrap()),
                Ok(Event::Synchronized)
            );
            drop(runtime);
            let mut runtime = Runtime::restore(
                &provider,
                &owners,
                &store.fenced_read(&initial, row.key).unwrap(),
                true,
            )
            .unwrap();
            let before = store.publications;
            let id = peer.counters().0.unwrap();
            let dpd = peer
                .request(37, crate::canonical_fixtures::empty())
                .unwrap();
            runtime.reply_empty(&dpd, &mut transport).unwrap();
            assert_eq!(
                peer.receive(transport.submitted.last().unwrap()),
                Ok(Event::Completed(id))
            );
            assert_eq!(store.publications, before);
            drop(runtime);
            let mut runtime = Runtime::restore(
                &provider,
                &owners,
                &store.fenced_read(&initial, row.key).unwrap(),
                false,
            )
            .unwrap();
            let second = peer
                .begin_sync(Sync {
                    nonce: [2; 4],
                    send: id + 10,
                    receive: peer.counters().1.unwrap(),
                })
                .unwrap();
            let early = Policy::new(30, Clock::new(300, 9), 1500, 3, 10).unwrap();
            assert_eq!(
                runtime.sync_response(
                    &provider,
                    &mut store,
                    &second,
                    None,
                    early,
                    Clock::new(300, 9),
                    Cut::Complete,
                    &mut transport
                ),
                Err(driver::Error::Window(WindowError::InvalidRecord))
            );
            let next = Policy::new(30, Clock::new(1100, 9), 2000, 3, 10).unwrap();
            // Expiry closes the old event; it neither renews its budget nor
            // authenticates a replay as a new peer recovery event.
            assert_eq!(
                runtime.sync_response(
                    &provider,
                    &mut store,
                    &second,
                    None,
                    policy(29),
                    Clock::new(1100, 9),
                    Cut::Complete,
                    &mut transport
                ),
                Err(driver::Error::Window(WindowError::SyncClosed))
            );
            assert_eq!(
                runtime.sync_response(
                    &provider,
                    &mut store,
                    &first,
                    None,
                    next,
                    Clock::new(1100, 9),
                    Cut::Complete,
                    &mut transport
                ),
                Err(driver::Error::Window(WindowError::Drop))
            );
            assert_eq!(store.publications, before);
            assert_eq!(
                runtime
                    .sync_response(
                        &provider,
                        &mut store,
                        &second,
                        None,
                        next,
                        Clock::new(1100, 9),
                        Cut::Complete,
                        &mut transport
                    )
                    .unwrap(),
                Some(Disposition::Continue)
            );
            assert_eq!(
                peer.receive(transport.submitted.last().unwrap()),
                Ok(Event::Synchronized)
            );
            assert_eq!(runtime.row.window.next_send, peer.counters().1);
            assert_eq!(runtime.row.window.next_receive, peer.counters().0);
            assert_eq!(runtime.row.sync_intents[1].as_ref().unwrap().policy, next);
            if let Some(iv) = &runtime.row.iv {
                assert_eq!(iv.retries[&29].policy.deadline_unix_ms(), 1000);
                assert_eq!(iv.retries[&30].policy.deadline_unix_ms(), 2000);
            }
            drop(runtime);
        }
    }
}

#[test]
fn responder_cutover_restart_never_replays_lost_reply_and_requires_higher_peer_proposal() {
    for (index, cut) in [
        Cut::BeforeDispatch,
        Cut::Dispatched,
        Cut::Applied,
        Cut::Acknowledged,
    ]
    .into_iter()
    .enumerate()
    {
        matrix(2_410_000 + index as u64 * 1000, |mut row| {
            if row.mode != Mode::Negotiated {
                return;
            }
            set_floors(&mut row, 3, 4);
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
                5,
                0,
                true,
            );
            let first = peer
                .begin_sync(Sync {
                    nonce: [1; 4],
                    send: 10,
                    receive: 2,
                })
                .unwrap();
            let mut transport = Transport::default();
            assert_eq!(
                runtime
                    .sync_response(
                        &provider,
                        &mut store,
                        &first,
                        None,
                        policy(29),
                        Clock::new(100, 9),
                        cut,
                        &mut transport
                    )
                    .unwrap(),
                None
            );
            assert!(transport.submitted.is_empty());
            let prior = runtime.pending.as_ref().unwrap().clone();
            drop(runtime);
            store.succeed(8);
            owners.learn_succession(8);
            let restored = store.fenced_read(&prior, row.key).unwrap();
            let mut runtime = Runtime::restore(&provider, &owners, &restored, false).unwrap();
            assert!(runtime.row.sync_intents[1].as_ref().unwrap().policy == policy(29));
            let request = if matches!(cut, Cut::Applied | Cut::Acknowledged) {
                let before = (store.publications, provider.calls(), module::counts());
                assert_eq!(
                    runtime.sync_response(
                        &provider,
                        &mut store,
                        &first,
                        None,
                        policy(29),
                        Clock::new(140, 9),
                        Cut::Complete,
                        &mut transport
                    ),
                    Err(driver::Error::Window(WindowError::Drop))
                );
                assert_eq!(
                    (store.publications, provider.calls(), module::counts()),
                    before
                );
                assert!(transport.submitted.is_empty());
                peer.begin_sync(Sync {
                    nonce: [2; 4],
                    send: 11,
                    receive: 2,
                })
                .unwrap()
            } else {
                first
            };
            assert_eq!(
                runtime
                    .sync_response(
                        &provider,
                        &mut store,
                        &request,
                        None,
                        policy(29),
                        Clock::new(150, 9),
                        Cut::Complete,
                        &mut transport
                    )
                    .unwrap(),
                Some(Disposition::Continue)
            );
            assert_eq!(transport.submitted.len(), 1);
            assert_eq!(
                peer.receive(transport.submitted.last().unwrap()),
                Ok(Event::Synchronized)
            );
            assert_eq!(runtime.row.window.next_send, peer.counters().1);
            assert_eq!(runtime.row.window.next_receive, peer.counters().0);
            if let Some(iv) = &runtime.row.iv {
                assert_eq!(iv.retries[&29].attempts, 2);
                assert_eq!(iv.retries[&29].policy.deadline_unix_ms(), 1000);
            }
            let id = peer.counters().0.unwrap();
            let request = peer.request(37, child_delete()).unwrap();
            runtime
                .reserve(
                    &provider,
                    &mut store,
                    91,
                    1,
                    200,
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
            runtime.replay_response(&request, &mut transport).unwrap();
            assert_eq!(
                peer.receive(transport.submitted.last().unwrap()),
                Ok(Event::Completed(id))
            );
            let next = Policy::new(30, Clock::new(300, 9), 1500, 3, 10).unwrap();
            let new_request = peer
                .begin_sync(Sync {
                    nonce: [3; 4],
                    send: id + 10,
                    receive: peer.counters().1.unwrap(),
                })
                .unwrap();
            assert!(runtime
                .sync_response(
                    &provider,
                    &mut store,
                    &new_request,
                    None,
                    next,
                    Clock::new(300, 9),
                    Cut::Complete,
                    &mut transport
                )
                .unwrap()
                .is_some());
            assert_eq!(
                peer.receive(transport.submitted.last().unwrap()),
                Ok(Event::Synchronized)
            );
            assert!(runtime.row.sync_intents[1].as_ref().unwrap().policy == next);
        });
    }
}

#[test]
fn pending_inbound_and_checkpointed_outbound_work_cut_over_to_uncertain_scoped_cleanup() {
    for outbound in [false, true] {
        matrix(2_420_000 + u64::from(outbound) * 1000, |row| {
            if row.mode != Mode::Negotiated {
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
            let mut peer = PeerModel::new(
                Wire::new(
                    row.profile,
                    &row.keys,
                    row.spis,
                    crate::canonical_fixtures::opposite(row.direction),
                ),
                0,
                0,
                true,
            );
            let mut transport = Transport::default();
            let inbound = if outbound {
                runtime
                    .reserve(
                        &provider,
                        &mut store,
                        41,
                        1,
                        100,
                        Cut::Complete,
                        Cut::Complete,
                    )
                    .unwrap();
                let draft = ke::draft(&runtime.row, 31, KeKind::ChildRekey);
                ke::persist_ke(&mut runtime, &provider, &mut store, draft, Cut::Complete).unwrap();
                runtime.dispatch_replay(&mut transport).unwrap();
                assert_eq!(
                    peer.receive(transport.submitted.last().unwrap()),
                    Ok(Event::NewRequest(0))
                );
                let before = (store.publications, provider.calls(), module::counts());
                assert_eq!(
                    runtime.sync_request(
                        &provider,
                        &mut store,
                        Start::New(policy(17)),
                        Clock::new(100, 9),
                        Clock::new(100, 9),
                        Cut::Complete,
                        &mut transport
                    ),
                    Err(driver::Error::Window(WindowError::RequestOutstanding))
                );
                assert_eq!(
                    (store.publications, provider.calls(), module::counts()),
                    before
                );
                None
            } else {
                Some(peer.request(37, child_delete()).unwrap())
            };
            let request = peer
                .begin_sync(Sync {
                    nonce: [3; 4],
                    send: 10,
                    receive: 10,
                })
                .unwrap();
            let before = transport.submitted.len();
            assert_eq!(
                runtime
                    .sync_response(
                        &provider,
                        &mut store,
                        &request,
                        inbound.as_deref(),
                        policy(29),
                        Clock::new(100, 9),
                        Cut::Applied,
                        &mut transport
                    )
                    .unwrap(),
                None
            );
            assert_eq!(transport.submitted.len(), before);
            let committed = runtime.pending.as_ref().unwrap().clone();
            runtime.resolve(&provider, &store, &committed).unwrap();
            if outbound {
                assert_eq!(runtime.row.operations[&31].outcome, Outcome::Uncertain);
                assert!(runtime.row.operations[&31].checkpoint.is_none());
                assert!(runtime.row.operations[&31].derived.is_none());
            }
            assert_eq!(
                runtime.row.window.sync.as_ref().unwrap().disposition,
                Disposition::OutcomeUncertain
            );
            assert!(runtime.dispatch_replay(&mut transport).is_err());
            assert_eq!(
                runtime.sync_response(
                    &provider,
                    &mut store,
                    &request,
                    None,
                    policy(29),
                    Clock::new(150, 9),
                    Cut::Complete,
                    &mut transport
                ),
                Err(driver::Error::Window(WindowError::OutcomeUncertain))
            );
            assert!(!runtime
                .sync_close(&provider, &mut store, Cut::Applied)
                .unwrap());
            let closure = runtime.pending.as_ref().unwrap().clone();
            runtime.resolve(&provider, &store, &closure).unwrap();
            assert!(runtime.row.closed && runtime.permit().check().is_err());
            runtime.delete().unwrap();
            peer.advance(REQUEST_TIMEOUT_MS);
            assert!(!peer.alive());
        });
    }
}

#[test]
fn sync_clock_changes_and_attempt_budget_close_without_fresh_identity_or_transmission() {
    for fault in 0..4 {
        matrix(2_430_000 + fault * 1000, |row| {
            if row.mode != Mode::Negotiated {
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
            let mut peer = PeerModel::new(
                Wire::new(
                    row.profile,
                    &row.keys,
                    row.spis,
                    crate::canonical_fixtures::opposite(row.direction),
                ),
                0,
                0,
                true,
            );
            let mut transport = Transport::default();
            runtime
                .sync_request(
                    &provider,
                    &mut store,
                    Start::New(policy(17)),
                    Clock::new(100, 9),
                    Clock::new(100, 9),
                    Cut::Complete,
                    &mut transport,
                )
                .unwrap();
            reply(peer.receive(transport.submitted.last().unwrap()).unwrap());
            if fault == 3 {
                for now in [120, 140] {
                    runtime
                        .sync_request(
                            &provider,
                            &mut store,
                            Start::Retry,
                            Clock::new(now, 9),
                            Clock::new(now, 9),
                            Cut::Complete,
                            &mut transport,
                        )
                        .unwrap();
                    reply(peer.receive(transport.submitted.last().unwrap()).unwrap());
                }
            }
            drop(runtime);
            store.succeed(8);
            owners.learn_succession(8);
            let mut runtime = Runtime::restore(
                &provider,
                &owners,
                &store.fenced_read(&initial, row.key).unwrap(),
                false,
            )
            .unwrap();
            let clock = match fault {
                0 => Clock::new(99, 9),
                1 => Clock::new(150, 10),
                2 => Clock::new(1000, 9),
                _ => Clock::new(160, 9),
            };
            let before = (
                store.publications,
                provider.calls(),
                module::counts(),
                transport.submitted.len(),
            );
            assert_eq!(
                runtime.sync_request(
                    &provider,
                    &mut store,
                    Start::Retry,
                    clock,
                    clock,
                    Cut::Complete,
                    &mut transport
                ),
                Err(driver::Error::Window(WindowError::SyncClosed))
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
            assert_eq!(
                runtime.sync_deadline(clock),
                Err(driver::Error::Window(WindowError::SyncClosed))
            );
            runtime
                .sync_close(&provider, &mut store, Cut::Complete)
                .unwrap();
            assert!(runtime.row.window.recovery.as_ref().unwrap().policy == policy(17));
            assert_eq!(
                runtime.row.window.recovery.as_ref().unwrap().status,
                Status::Closed
            );
            assert_eq!(
                runtime.row.window.recovery.as_ref().unwrap().attempts.len(),
                if fault == 3 { 3 } else { 1 }
            );
            assert!(runtime.row.closed && runtime.permit().check().is_err());
            runtime.delete().unwrap();
        });
    }
}

#[test]
fn crossed_sync_keeps_both_proposals_and_merges_floors_in_either_reply_order() {
    for local_first in [false, true] {
        matrix(2_440_000 + u64::from(local_first) * 1000, |mut row| {
            if row.mode != Mode::Negotiated {
                return;
            }
            set_floors(&mut row, 5, 2);
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
                7,
                5,
                true,
            );
            let mut transport = Transport::default();
            runtime
                .sync_request(
                    &provider,
                    &mut store,
                    Start::New(policy(17)),
                    Clock::new(100, 9),
                    Clock::new(100, 9),
                    Cut::Complete,
                    &mut transport,
                )
                .unwrap();
            let local_request = transport.submitted.last().unwrap().clone();
            let peer_request = peer
                .begin_sync(Sync {
                    nonce: [9; 4],
                    send: 9,
                    receive: 9,
                })
                .unwrap();
            let local_reply = reply(peer.receive(&local_request).unwrap());
            if local_first {
                assert!(runtime
                    .sync_complete(
                        &provider,
                        &mut store,
                        &local_reply,
                        Clock::new(110, 9),
                        Clock::new(110, 9),
                        Cut::Complete
                    )
                    .unwrap());
            }
            let disposition = runtime
                .sync_response(
                    &provider,
                    &mut store,
                    &peer_request,
                    None,
                    policy(29),
                    Clock::new(120, 9),
                    Cut::Complete,
                    &mut transport,
                )
                .unwrap()
                .unwrap();
            assert_eq!(
                disposition,
                if local_first {
                    Disposition::Continue
                } else {
                    Disposition::AwaitLocalSync
                }
            );
            assert_eq!(
                peer.receive(transport.submitted.last().unwrap()),
                Ok(Event::Synchronized)
            );
            if !local_first {
                assert!(runtime
                    .sync_complete(
                        &provider,
                        &mut store,
                        &local_reply,
                        Clock::new(130, 9),
                        Clock::new(130, 9),
                        Cut::Complete
                    )
                    .unwrap());
            }
            assert_eq!(runtime.row.window.next_send, peer.counters().1);
            assert_eq!(runtime.row.window.next_receive, peer.counters().0);
            assert_eq!(
                runtime.row.window.recovery.as_ref().unwrap().status,
                Status::Recovered
            );
            assert!(peer.alive());
            let before = (
                store.publications,
                provider.calls(),
                module::counts(),
                transport.submitted.len(),
            );
            assert_eq!(
                runtime.sync_response(
                    &provider,
                    &mut store,
                    &peer_request,
                    None,
                    policy(29),
                    Clock::new(150, 9),
                    Cut::Complete,
                    &mut transport
                ),
                Err(driver::Error::Window(WindowError::Drop))
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
        });
    }
}

#[test]
fn preproposal_restart_preserves_event_identity_clock_and_reservation_deadline() {
    matrix(2_450_000, |row| {
        if row.mode != Mode::Negotiated {
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
        provider.fail_on_active_call(2, super::envelope::Fault::Unavailable);
        let mut transport = Transport::default();
        assert_eq!(
            runtime.sync_request(
                &provider,
                &mut store,
                Start::New(policy(17)),
                Clock::new(100, 9),
                Clock::new(100, 9),
                Cut::Complete,
                &mut transport
            ),
            Err(driver::Error::Key(super::envelope::Error::Backpressure))
        );
        assert!(runtime.row.sync_intents[0].as_ref().unwrap().policy == policy(17));
        assert!(runtime.row.window.recovery.is_none());
        assert!(transport.submitted.is_empty());
        drop(runtime);
        store.succeed(8);
        owners.learn_succession(8);
        let mut runtime = Runtime::restore(
            &provider,
            &owners,
            &store.fenced_read(&initial, row.key).unwrap(),
            false,
        )
        .unwrap();
        let before = (store.publications, provider.calls(), module::counts());
        assert_eq!(
            runtime.publish_request(
                &provider,
                &mut store,
                Exchange::Informational,
                child_delete(),
                |_| {},
                Cut::Complete
            ),
            Err(driver::Error::Window(WindowError::SyncInProgress))
        );
        assert_eq!(
            runtime.sync_request(
                &provider,
                &mut store,
                Start::New(policy(18)),
                Clock::new(150, 9),
                Clock::new(150, 9),
                Cut::Complete,
                &mut transport
            ),
            Err(driver::Error::Window(WindowError::InvalidRecord))
        );
        assert_eq!(
            (store.publications, provider.calls(), module::counts()),
            before
        );
        assert!(runtime
            .sync_request(
                &provider,
                &mut store,
                Start::Retry,
                Clock::new(150, 9),
                Clock::new(150, 9),
                Cut::Complete,
                &mut transport
            )
            .unwrap());
        let event = runtime.row.window.recovery.as_ref().unwrap();
        assert!(event.policy == policy(17));
        assert_eq!(event.attempts.len(), 1);
        if let Some(iv) = &runtime.row.iv {
            assert_eq!(iv.retries[&17].attempts, 1);
            assert_eq!(iv.retries[&17].policy.deadline_unix_ms(), 1000);
        }
        let mut peer = PeerModel::new(
            Wire::new(
                row.profile,
                &row.keys,
                row.spis,
                crate::canonical_fixtures::opposite(row.direction),
            ),
            0,
            0,
            true,
        );
        let response = reply(peer.receive(transport.submitted.last().unwrap()).unwrap());
        assert!(runtime
            .sync_complete(
                &provider,
                &mut store,
                &response,
                Clock::new(160, 9),
                Clock::new(160, 9),
                Cut::Complete
            )
            .unwrap());
    });
}

#[test]
fn preproposal_clock_failure_closes_original_event_without_new_work() {
    for (fault, clock) in [Clock::new(99, 9), Clock::new(150, 10), Clock::new(1000, 9)]
        .into_iter()
        .enumerate()
    {
        matrix(2_460_000 + fault as u64 * 1000, |row| {
            if row.mode != Mode::Negotiated {
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
            provider.fail_on_active_call(2, super::envelope::Fault::Unavailable);
            let mut transport = Transport::default();
            assert_eq!(
                runtime.sync_deadline(clock),
                Err(driver::Error::Window(WindowError::Drop))
            );
            assert_eq!(
                runtime.sync_request(
                    &provider,
                    &mut store,
                    Start::New(policy(17)),
                    Clock::new(100, 9),
                    Clock::new(100, 9),
                    Cut::Complete,
                    &mut transport
                ),
                Err(driver::Error::Key(super::envelope::Error::Backpressure))
            );
            drop(runtime);
            store.succeed(8);
            owners.learn_succession(8);
            let mut runtime = Runtime::restore(
                &provider,
                &owners,
                &store.fenced_read(&initial, row.key).unwrap(),
                false,
            )
            .unwrap();
            let before = (store.publications, provider.calls(), module::counts());
            assert_eq!(
                runtime.sync_deadline(clock),
                Err(driver::Error::Window(WindowError::SyncClosed))
            );
            assert_eq!(
                runtime.sync_request(
                    &provider,
                    &mut store,
                    Start::Retry,
                    clock,
                    clock,
                    Cut::Complete,
                    &mut transport
                ),
                Err(driver::Error::Window(WindowError::SyncClosed))
            );
            assert_eq!(
                (store.publications, provider.calls(), module::counts()),
                before
            );
            assert!(transport.submitted.is_empty());
            assert!(!runtime
                .sync_close(&provider, &mut store, Cut::Applied)
                .unwrap());
            let closure = runtime.pending.as_ref().unwrap().clone();
            runtime.resolve(&provider, &store, &closure).unwrap();
            assert!(runtime.row.closed && runtime.permit().check().is_err());
            assert!(runtime.row.sync_intents[0].as_ref().unwrap().policy == policy(17));
            runtime.delete().unwrap();
            assert!(matches!(
                Runtime::restore(
                    &provider,
                    &owners,
                    &store.fenced_read(&closure, row.key).unwrap(),
                    false
                ),
                Err(driver::Error::Closed)
            ));
        });
    }
}
