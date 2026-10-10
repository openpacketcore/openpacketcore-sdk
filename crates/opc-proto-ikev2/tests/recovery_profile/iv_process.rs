//! Durable reservation charge, block and window fault cuts through process loss.

use super::{
    authority::{EpochOwners, Transport},
    codec::ProfileCodec,
    crash::{child, packet_name, read, write, RunDir},
    driver::{self, Cut, Runtime},
    envelope::{self, Provider},
    inputs,
    lifecycle::child_delete,
    module,
    peer::{Event, PeerModel},
    row::{RetryImage, Row},
    store::CasStore,
    wire::Wire,
};
use bytes::Bytes;
use opc_proto_ikev2::{
    recovery::Ikev2ReservationRetryPolicy as RetryPolicy, Ikev2ExchangeKind as Exchange,
    Ikev2MessageIdSyncMode as Mode,
};
use std::path::Path;

#[derive(Clone, Copy)]
enum Boundary {
    Charge(Cut),
    Block(Cut),
    Window(Cut),
    Released,
}

struct Case {
    row: Row,
    boundary: Boundary,
}

fn cases() -> Vec<Case> {
    let cuts = [
        Cut::BeforeDispatch,
        Cut::Dispatched,
        Cut::Applied,
        Cut::Acknowledged,
    ];
    let boundaries = cuts
        .into_iter()
        .map(Boundary::Charge)
        .chain(cuts.into_iter().map(Boundary::Block))
        .chain(cuts.into_iter().map(Boundary::Window))
        .chain([Boundary::Released]);
    let mut rows = Vec::new();
    for (boundary_id, boundary) in boundaries.enumerate() {
        for (profile_id, encryption) in crate::canonical_fixtures::ALGORITHMS
            .into_iter()
            .enumerate()
        {
            for (role_id, direction) in crate::canonical_fixtures::DIRECTIONS
                .into_iter()
                .enumerate()
            {
                for (mode_id, mode) in [Mode::BaseFallback, Mode::Negotiated]
                    .into_iter()
                    .enumerate()
                {
                    let mut row = inputs::fresh(
                        800_000
                            + (boundary_id * 100 + profile_id * 4 + role_id * 2 + mode_id) as u64,
                        crate::canonical_fixtures::profile(encryption),
                        direction,
                        mode,
                    );
                    // This is an existing genuine operation with its original
                    // policy. Even loss before the first charge cannot invent
                    // a later start/deadline for the same operation identity.
                    row.iv.as_mut().unwrap().retries.insert(
                        19,
                        RetryImage {
                            operation: 19,
                            policy: RetryPolicy::new(100, 10_100, 3, 10).unwrap(),
                            attempts: 0,
                            last_attempt: None,
                        },
                    );
                    rows.push(Case { row, boundary });
                }
            }
        }
    }
    assert_eq!(rows.len(), 156);
    rows
}

fn landed(cut: Cut) -> bool {
    matches!(cut, Cut::Applied | Cut::Acknowledged | Cut::Complete)
}

fn expected(boundary: Boundary) -> (u8, u64, bool) {
    match boundary {
        Boundary::Charge(cut) => (if landed(cut) { 2 } else { 1 }, 1, false),
        Boundary::Block(cut) => (2, if landed(cut) { 2 } else { 1 }, false),
        Boundary::Window(cut) => (
            if landed(cut) { 1 } else { 2 },
            if landed(cut) { 1 } else { 2 },
            landed(cut),
        ),
        Boundary::Released => (1, 1, true),
    }
}

pub fn run(root: &Path, stage: &str, provider: &Provider) {
    match stage {
        "gcm-start" => {
            for case in cases() {
                // Independent execution scopes cannot reuse an unknown queued sequence.
                let mut store = CasStore::new(7);
                let owners = EpochOwners::new(7);
                let row = case.row;
                let initial = driver::create(provider, &mut store, &row).unwrap();
                let mut runtime = Runtime::restore(
                    provider,
                    &owners,
                    &store.fenced_read(&initial, row.key).unwrap(),
                    false,
                )
                .unwrap();
                let (charge, block) = match case.boundary {
                    Boundary::Charge(cut) => (cut, Cut::Complete),
                    Boundary::Block(cut) => (Cut::Complete, cut),
                    _ => (Cut::Complete, Cut::Complete),
                };
                let reserved = runtime
                    .reserve(provider, &mut store, 19, 1, 110, charge, block)
                    .unwrap();
                match case.boundary {
                    Boundary::Charge(_) | Boundary::Block(_) => assert!(!reserved),
                    Boundary::Window(cut) => {
                        assert!(reserved);
                        assert!(!runtime
                            .publish_request(
                                provider,
                                &mut store,
                                Exchange::Informational,
                                child_delete(),
                                |_| {},
                                cut
                            )
                            .unwrap());
                        let command = runtime.pending.as_ref().unwrap();
                        let candidate = command.mutations()[0].value.as_ref().unwrap();
                        let plain = envelope::unseal(provider, row.key, candidate).unwrap();
                        let candidate = ProfileCodec::decode(
                            &plain,
                            row.key,
                            candidate.version,
                            candidate.sealed_stamp,
                        )
                        .unwrap();
                        // Ciphertext diagnostic of a sealed candidate, explicitly
                        // not submitted to the transport or the peer.
                        write(
                            root,
                            &packet_name("unreleased-candidate", row.key.0),
                            candidate.window.outbound.as_ref().unwrap().request(),
                        );
                    }
                    Boundary::Released => {
                        assert!(reserved);
                        runtime
                            .publish_request(
                                provider,
                                &mut store,
                                Exchange::Informational,
                                child_delete(),
                                |_| {},
                                Cut::Complete,
                            )
                            .unwrap();
                        let mut transport = Transport::default();
                        runtime.dispatch_replay(&mut transport).unwrap();
                        write(
                            root,
                            &packet_name("before-loss", row.key.0),
                            transport.submitted.last().unwrap(),
                        );
                    }
                }
                write(
                    root,
                    &format!("gcm-start-{}.rows", row.key.0),
                    &store.encrypted_snapshot(),
                );
            }
        }
        "gcm-recover" => {
            for case in cases() {
                let (mut store, mut cuts) = CasStore::reopen_after_join(
                    &read(root, &format!("gcm-start-{}.rows", case.row.key.0)),
                    8,
                )
                .unwrap();
                assert_eq!(cuts.len(), 1);
                let cut = cuts.pop().unwrap();
                let owners = EpochOwners::new(8);
                let mut runtime = Runtime::restore(provider, &owners, &cut, false).unwrap();
                let prior_end = runtime.row.iv.as_ref().unwrap().end;
                let prior_writes = store.publications;
                let pending = runtime.row.window.outbound.is_some();
                if !pending {
                    runtime
                        .reserve(
                            provider,
                            &mut store,
                            19,
                            1,
                            150,
                            Cut::Complete,
                            Cut::Complete,
                        )
                        .unwrap();
                    runtime
                        .publish_request(
                            provider,
                            &mut store,
                            Exchange::Informational,
                            child_delete(),
                            |_| {},
                            Cut::Complete,
                        )
                        .unwrap();
                }
                assert_eq!(
                    store.publications - prior_writes,
                    if pending { 0 } else { 3 }
                );
                let before = (
                    provider.calls(),
                    module::counts().entropy,
                    store.publications,
                );
                let mut transport = Transport::default();
                runtime.dispatch_replay(&mut transport).unwrap();
                runtime.dispatch_replay(&mut transport).unwrap();
                assert_eq!(transport.submitted[0], transport.submitted[1]);
                assert_eq!(
                    (
                        provider.calls(),
                        module::counts().entropy,
                        store.publications
                    ),
                    before
                );
                if !pending {
                    let iv = u64::from_be_bytes(transport.submitted[0][32..40].try_into().unwrap());
                    assert_eq!(iv, prior_end, "restart discards the reserved tail");
                }
                write(
                    root,
                    &packet_name("after-loss", cut.key().0),
                    &transport.submitted[0],
                );
                write(
                    root,
                    &packet_name("after-loss-again", cut.key().0),
                    &transport.submitted[1],
                );
                write(
                    root,
                    &format!("gcm-recovered-{}.rows", cut.key().0),
                    &store.encrypted_snapshot(),
                );
            }
        }
        "gcm-complete" => {
            for case in cases() {
                let (mut store, mut cuts) = CasStore::reopen_after_join(
                    &read(root, &format!("gcm-recovered-{}.rows", case.row.key.0)),
                    9,
                )
                .unwrap();
                assert_eq!(cuts.len(), 1);
                let cut = cuts.pop().unwrap();
                let owners = EpochOwners::new(9);
                let mut runtime = Runtime::restore(provider, &owners, &cut, false).unwrap();
                let response = read(root, &packet_name("peer-response", cut.key().0));
                runtime
                    .complete(
                        provider,
                        &mut store,
                        &response,
                        Bytes::from_static(b"child-deleted"),
                        |_| {},
                        Cut::Complete,
                    )
                    .unwrap();
                assert!(!runtime.dispatch_replay(&mut Transport::default()).unwrap());
                write(
                    root,
                    &format!("gcm-complete-{}.rows", cut.key().0),
                    &store.encrypted_snapshot(),
                );
            }
        }
        _ => panic!("unknown IV crash stage"),
    }
}

#[test]
fn gcm_charge_block_window_crashes_never_reuse_an_iv_or_refund_a_charge() {
    let root = RunDir::new();
    let cases = cases();
    let mut peers: Vec<_> = cases
        .iter()
        .map(|case| {
            let row = &case.row;
            PeerModel::new(
                Wire::new(
                    row.profile,
                    &row.keys,
                    row.spis,
                    crate::canonical_fixtures::opposite(row.direction),
                ),
                0,
                0,
                row.mode == Mode::Negotiated,
            )
        })
        .collect();
    child(&root.0, "gcm-start", "gcm", "iv-before-loss");
    for (case, peer) in cases.iter().zip(&mut peers) {
        if matches!(case.boundary, Boundary::Released) {
            let request = read(&root.0, &packet_name("before-loss", case.row.key.0));
            assert_eq!(peer.receive(&request), Ok(Event::NewRequest(0)));
        }
    }
    child(&root.0, "gcm-recover", "gcm", "iv-after-loss");
    for (case, peer) in cases.iter().zip(&mut peers) {
        let key = case.row.key.0;
        let request = read(&root.0, &packet_name("after-loss", key));
        assert_eq!(
            peer.receive(&request),
            Ok(if matches!(case.boundary, Boundary::Released) {
                Event::Ignored
            } else {
                Event::NewRequest(0)
            })
        );
        let replay = read(&root.0, &packet_name("after-loss-again", key));
        assert_eq!(replay, request);
        assert_eq!(peer.receive(&replay), Ok(Event::Ignored));
        if let Boundary::Window(cut) = case.boundary {
            let candidate = read(&root.0, &packet_name("unreleased-candidate", key));
            if landed(cut) {
                assert_eq!(candidate, request);
            } else {
                assert_ne!(&candidate[32..40], &request[32..40]);
            }
        }
        let response = peer.respond(0, crate::canonical_fixtures::empty()).unwrap();
        write(&root.0, &packet_name("peer-response", key), &response);
    }
    child(&root.0, "gcm-complete", "gcm", "iv-completion-restart");
    let provider = Provider::new();
    for case in cases {
        let (store, _) = CasStore::reopen_after_join(
            &read(&root.0, &format!("gcm-complete-{}.rows", case.row.key.0)),
            10,
        )
        .unwrap();
        let stored = store.inspect(case.row.key).unwrap();
        let plain = envelope::unseal(&provider, case.row.key, stored).unwrap();
        let row = ProfileCodec::decode(&plain, case.row.key, stored.version, stored.sealed_stamp)
            .unwrap();
        let iv = row.iv.unwrap();
        let retry = &iv.retries[&19];
        let (attempts, end, _) = expected(case.boundary);
        assert_eq!(retry.attempts, attempts);
        assert_eq!(iv.end, end);
        assert_eq!(retry.policy, case.row.iv.unwrap().retries[&19].policy);
        assert_eq!(row.window.next_send, Some(1));
        assert_eq!(row.window.next_receive, Some(0));
        assert!(row.window.outbound.unwrap().response().is_some());
    }
}
