//! Process loss on both sync roles. The independent peer reconstructs its
//! history from released wire packets; it never imports SDK window transitions.

use super::{
    authority::{EpochOwners, Transport},
    crash::{child, packet_name, read, write, RunDir},
    driver::{self, Cut, Runtime},
    envelope::Provider,
    inputs,
    lifecycle::child_delete,
    module,
    peer::{Event, PeerModel, Sync},
    row::Row,
    store::CasStore,
    sync_driver::Start,
    sync_tests::{policy, set_floors},
    wire::Wire,
};
use bytes::Bytes;
use opc_proto_ikev2::{
    recovery::{
        Ikev2SyncClock as Clock, Ikev2SyncRecoveryStatus as Status, Ikev2WindowError as Error,
    },
    Ikev2ExchangeKind as Exchange, Ikev2MessageIdSyncMode as Mode,
};
use std::path::Path;

struct Case {
    row: Row,
    local: bool,
    cut: Cut,
}
fn cases(selection: &str) -> Vec<Case> {
    let mut result = Vec::new();
    for (fault, cut) in [
        Cut::BeforeDispatch,
        Cut::Dispatched,
        Cut::Applied,
        Cut::Acknowledged,
    ]
    .into_iter()
    .enumerate()
    {
        for (role, local) in [true, false].into_iter().enumerate() {
            for (profile_id, profile) in inputs::profiles().enumerate() {
                if selection == "sync-smoke" && ![0, 3].contains(&profile_id) {
                    continue;
                }
                for (direction_id, direction) in crate::canonical_fixtures::DIRECTIONS
                    .into_iter()
                    .enumerate()
                {
                    let tag = 2_500_000
                        + ((fault * 2 + role) * 1000 + profile_id * 2 + direction_id) as u64;
                    let mut row = inputs::fresh(tag, profile, direction, Mode::Negotiated);
                    set_floors(
                        &mut row,
                        if local { 5 } else { 3 },
                        if local { 2 } else { 4 },
                    );
                    result.push(Case { row, local, cut });
                }
            }
        }
    }
    assert_eq!(
        result.len(),
        if selection == "sync-smoke" { 32 } else { 816 }
    );
    result
}
fn packet(root: &Path, kind: &str, row: &Row) -> Vec<u8> {
    read(root, &packet_name(kind, row.key.0))
}
fn save(root: &Path, kind: &str, row: &Row, bytes: &[u8]) {
    write(root, &packet_name(kind, row.key.0), bytes);
}
fn row_file(stage: &str, row: &Row) -> String {
    format!("{stage}-{}.rows", row.key.0)
}
fn peer(case: &Case) -> PeerModel<'_> {
    PeerModel::new(
        Wire::new(
            case.row.profile,
            &case.row.keys,
            case.row.spis,
            crate::canonical_fixtures::opposite(case.row.direction),
        ),
        if case.local { 7 } else { 5 },
        if case.local { 5 } else { 0 },
        true,
    )
}
fn sync_reply(event: Event) -> Bytes {
    let Event::SyncReply { wire, .. } = event else {
        panic!("expected sync reply");
    };
    wire
}
fn ordinary(
    runtime: &mut Runtime,
    provider: &Provider,
    store: &mut CasStore,
    transport: &mut Transport,
) {
    runtime
        .reserve(provider, store, 91, 1, 200, Cut::Complete, Cut::Complete)
        .unwrap();
    runtime
        .publish_request(
            provider,
            store,
            Exchange::Informational,
            child_delete(),
            |_| {},
            Cut::Complete,
        )
        .unwrap();
    assert!(runtime.dispatch_replay(transport).unwrap());
}

pub fn run(root: &Path, stage: &str, selection: &str, provider: &Provider) {
    for case in cases(selection) {
        let row = &case.row;
        let (mut store, owners, mut runtime) = if stage == "sync-start" {
            let mut store = CasStore::new(7);
            let owners = EpochOwners::new(7);
            let initial = driver::create(provider, &mut store, row).unwrap();
            let runtime = Runtime::restore(
                provider,
                &owners,
                &store.fenced_read(&initial, row.key).unwrap(),
                false,
            )
            .unwrap();
            (store, owners, runtime)
        } else {
            let (previous, stamp) = match stage {
                "sync-retry" => ("sync-start", 8),
                "sync-recover" => ("sync-retry", 9),
                "sync-settle" => ("sync-recover", 10),
                "sync-done" => ("sync-settle", 11),
                _ => panic!("unknown sync process stage"),
            };
            let (store, cuts) =
                CasStore::reopen_after_join(&read(root, &row_file(previous, row)), stamp).unwrap();
            assert_eq!(cuts.len(), 1);
            let owners = EpochOwners::new(stamp);
            let runtime = Runtime::restore(provider, &owners, &cuts[0], false).unwrap();
            (store, owners, runtime)
        };
        let mut transport = Transport::default();
        match stage {
            "sync-start" if case.local => {
                assert!(runtime
                    .sync_request(
                        provider,
                        &mut store,
                        Start::New(policy(17)),
                        Clock::new(100, 9),
                        Clock::new(100, 9),
                        Cut::Complete,
                        &mut transport
                    )
                    .unwrap());
                save(root, "sync-first", row, transport.submitted.last().unwrap());
            }
            "sync-start" => {
                let first = packet(root, "sync-first", row);
                assert!(runtime
                    .sync_response(
                        provider,
                        &mut store,
                        &first,
                        None,
                        policy(29),
                        Clock::new(100, 9),
                        case.cut,
                        &mut transport
                    )
                    .unwrap()
                    .is_none());
                assert!(transport.submitted.is_empty());
            }
            "sync-retry" if case.local => {
                let reply = packet(root, "sync-first-reply", row);
                assert!(runtime.dispatch_replay(&mut transport).is_err());
                assert_eq!(
                    runtime.sync_complete(
                        provider,
                        &mut store,
                        &reply,
                        Clock::new(120, 9),
                        Clock::new(120, 9),
                        Cut::Complete
                    ),
                    Err(driver::Error::Window(Error::Drop))
                );
                assert!(!runtime
                    .sync_request(
                        provider,
                        &mut store,
                        Start::Retry,
                        Clock::new(130, 9),
                        Clock::new(130, 9),
                        case.cut,
                        &mut transport
                    )
                    .unwrap());
                assert!(transport.submitted.is_empty());
            }
            "sync-retry" => {
                assert!(runtime.row.sync_intents[1].as_ref().unwrap().policy == policy(29));
                if matches!(case.cut, Cut::Applied | Cut::Acknowledged) {
                    let before = (store.publications, provider.calls(), module::counts());
                    let first = packet(root, "sync-first", row);
                    assert_eq!(
                        runtime.sync_response(
                            provider,
                            &mut store,
                            &first,
                            None,
                            policy(29),
                            Clock::new(130, 9),
                            Cut::Complete,
                            &mut transport
                        ),
                        Err(driver::Error::Window(Error::Drop))
                    );
                    assert_eq!(
                        (store.publications, provider.calls(), module::counts()),
                        before
                    );
                }
                let higher = packet(root, "sync-higher", row);
                assert!(runtime
                    .sync_response(
                        provider,
                        &mut store,
                        &higher,
                        None,
                        policy(29),
                        Clock::new(150, 9),
                        Cut::Complete,
                        &mut transport
                    )
                    .unwrap()
                    .is_some());
                save(
                    root,
                    "sync-higher-reply",
                    row,
                    transport.submitted.last().unwrap(),
                );
            }
            "sync-recover" if case.local => {
                assert!(runtime.row.window.recovery.as_ref().unwrap().policy == policy(17));
                let prior_attempts = runtime.row.window.recovery.as_ref().unwrap().attempts.len();
                assert_eq!(
                    prior_attempts,
                    if matches!(case.cut, Cut::Applied | Cut::Acknowledged) {
                        2
                    } else {
                        1
                    }
                );
                assert!(runtime.dispatch_replay(&mut transport).is_err());
                assert!(runtime
                    .sync_request(
                        provider,
                        &mut store,
                        Start::Retry,
                        Clock::new(160, 9),
                        Clock::new(160, 9),
                        Cut::Complete,
                        &mut transport
                    )
                    .unwrap());
                let higher = transport.submitted.last().unwrap();
                save(root, "sync-higher", row, higher);
                // Replay only released peer-visible history into an independent
                // wire model. It has no access to the restored SDK counters.
                let mut oracle = peer(&case);
                let first = packet(root, "sync-first", row);
                sync_reply(oracle.receive(&first).unwrap());
                let reply = sync_reply(oracle.receive(higher).unwrap());
                save(root, "sync-higher-reply", row, &reply);
                assert!(!runtime
                    .sync_complete(
                        provider,
                        &mut store,
                        &reply,
                        Clock::new(162, 9),
                        Clock::new(2000, 10),
                        Cut::Applied
                    )
                    .unwrap());
                assert_eq!(
                    runtime.row.window.recovery.as_ref().unwrap().attempts.len(),
                    prior_attempts + 1
                );
                assert_eq!(transport.submitted.len(), 1);
            }
            "sync-recover" => {
                assert!(!runtime.dispatch_replay(&mut transport).unwrap());
                ordinary(&mut runtime, provider, &mut store, &mut transport);
                save(
                    root,
                    "sync-ordinary",
                    row,
                    transport.submitted.last().unwrap(),
                );
            }
            "sync-settle" if case.local => {
                let event = runtime.row.window.recovery.as_ref().unwrap();
                assert_eq!(event.status, Status::Recovered);
                assert!(event.policy == policy(17));
                assert!(!runtime.dispatch_replay(&mut transport).unwrap());
                ordinary(&mut runtime, provider, &mut store, &mut transport);
                save(
                    root,
                    "sync-ordinary",
                    row,
                    transport.submitted.last().unwrap(),
                );
            }
            "sync-settle" | "sync-done" if (stage == "sync-done") == case.local => {
                let reply = packet(root, "sync-ordinary-reply", row);
                assert!(runtime
                    .complete(
                        provider,
                        &mut store,
                        &reply,
                        Bytes::from_static(b"child-deleted"),
                        |_| {},
                        Cut::Applied
                    )
                    .unwrap()
                    .is_none());
                assert!(transport.submitted.is_empty());
            }
            "sync-done" => {
                assert!(!runtime.dispatch_replay(&mut transport).unwrap());
                assert!(runtime
                    .row
                    .window
                    .outbound
                    .as_ref()
                    .unwrap()
                    .response()
                    .is_some());
            }
            _ => panic!("unexpected sync stage and role"),
        }
        write(root, &row_file(stage, row), &store.encrypted_snapshot());
        drop(runtime);
        drop(owners);
    }
}

fn process(selection: &str) {
    let root = RunDir::new();
    let cases = cases(selection);
    let mut peers: Vec<_> = cases.iter().map(peer).collect();
    for (case, peer) in cases.iter().zip(&mut peers) {
        if !case.local {
            let first = peer
                .begin_sync(Sync {
                    nonce: [1; 4],
                    send: 10,
                    receive: 2,
                })
                .unwrap();
            save(&root.0, "sync-first", &case.row, &first);
        }
    }
    child(&root.0, "sync-start", selection, "sync-start-build");
    for (case, peer) in cases.iter().zip(&mut peers) {
        if case.local {
            let first = packet(&root.0, "sync-first", &case.row);
            let reply = sync_reply(peer.receive(&first).unwrap());
            save(&root.0, "sync-first-reply", &case.row, &reply);
        } else {
            let higher = peer
                .begin_sync(Sync {
                    nonce: [2; 4],
                    send: 11,
                    receive: 2,
                })
                .unwrap();
            save(&root.0, "sync-higher", &case.row, &higher);
        }
    }
    child(&root.0, "sync-retry", selection, "sync-retry-build");
    for (case, peer) in cases.iter().zip(&mut peers) {
        if !case.local {
            let reply = packet(&root.0, "sync-higher-reply", &case.row);
            assert_eq!(peer.receive(&reply), Ok(Event::Synchronized));
        }
    }
    child(&root.0, "sync-recover", selection, "sync-recover-build");
    for (case, peer) in cases.iter().zip(&mut peers) {
        if case.local {
            let higher = packet(&root.0, "sync-higher", &case.row);
            let expected = sync_reply(peer.receive(&higher).unwrap());
            let actual = packet(&root.0, "sync-higher-reply", &case.row);
            let local = Wire::new(
                case.row.profile,
                &case.row.keys,
                case.row.spis,
                case.row.direction,
            );
            assert_eq!(
                local.open(&actual).unwrap().body,
                local.open(&expected).unwrap().body
            );
            let first = packet(&root.0, "sync-first", &case.row);
            let a = peer.wire.open(&first).unwrap();
            let b = peer.wire.open(&higher).unwrap();
            assert_ne!(&a.body[8..12], &b.body[8..12]);
            assert!(
                u32::from_be_bytes(b.body[12..16].try_into().unwrap())
                    > u32::from_be_bytes(a.body[12..16].try_into().unwrap())
            );
        } else {
            let request = packet(&root.0, "sync-ordinary", &case.row);
            let id = peer.counters().1.unwrap();
            assert_eq!(peer.receive(&request), Ok(Event::NewRequest(id)));
            let reply = peer
                .respond(id, crate::canonical_fixtures::empty())
                .unwrap();
            save(&root.0, "sync-ordinary-reply", &case.row, &reply);
        }
    }
    child(&root.0, "sync-settle", selection, "sync-settle-build");
    for (case, peer) in cases.iter().zip(&mut peers) {
        if case.local {
            let request = packet(&root.0, "sync-ordinary", &case.row);
            let id = peer.counters().1.unwrap();
            assert_eq!(peer.receive(&request), Ok(Event::NewRequest(id)));
            let reply = peer
                .respond(id, crate::canonical_fixtures::empty())
                .unwrap();
            save(&root.0, "sync-ordinary-reply", &case.row, &reply);
        }
    }
    child(&root.0, "sync-done", selection, "sync-done-build");
    let provider = Provider::new();
    for (case, peer) in cases.iter().zip(peers) {
        let (store, cuts) =
            CasStore::reopen_after_join(&read(&root.0, &row_file("sync-done", &case.row)), 12)
                .unwrap();
        let owners = EpochOwners::new(12);
        let mut runtime = Runtime::restore(&provider, &owners, &cuts[0], false).unwrap();
        assert!(!runtime.dispatch_replay(&mut Transport::default()).unwrap());
        assert_eq!(runtime.row.window.next_send, peer.counters().1);
        assert_eq!(runtime.row.window.next_receive, peer.counters().0);
        let intent = runtime.row.sync_intents[usize::from(!case.local)]
            .as_ref()
            .unwrap();
        assert!(intent.policy == policy(if case.local { 17 } else { 29 }));
        if let Some(iv) = &runtime.row.iv {
            assert_eq!(
                iv.retries[&intent.policy.operation()].attempts,
                if case.local { 3 } else { 2 }
            );
        }
        assert!(peer.alive());
        assert!(store.inspect(case.row.key).is_some());
    }
}

#[test]
fn sync_process_smoke() {
    process("sync-smoke");
}
#[test]
fn sync_process_crashes_across_profiles_roles_and_commit_cuts() {
    process("sync-all");
}
