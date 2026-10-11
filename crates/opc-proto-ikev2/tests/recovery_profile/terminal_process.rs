//! Each terminal input is replayed by the test controller across a stopped and
//! joined executor. Checkpoint removal and the result are one atomic row cut.
use super::{
    authority::{EpochOwners, Transport},
    codec::ProfileCodec,
    crash::{child, packet_name, read, write, RunDir},
    driver::{self, Cut, Runtime},
    envelope::{self, Provider},
    inputs, ke,
    lifecycle::child_delete,
    peer::{Event, PeerModel, REQUEST_TIMEOUT_MS},
    remedy::{self, Recovery},
    row::{KeKind, Outcome, Row},
    store::CasStore,
    wire::Wire,
};
use bytes::Bytes;
use opc_proto_ikev2::{
    Ikev2EphemeralDhKey as Dh, Ikev2ExchangeKind as Exchange, Ikev2MessageIdSyncMode as Mode,
    PayloadChain,
};
use std::path::Path;
struct Case {
    row: Row,
    outcome: Outcome,
    cut: Cut,
}
fn cases(selection: &str) -> Vec<Case> {
    let mut result = Vec::new();
    for (outcome_id, outcome) in [
        Outcome::CrossedLoss,
        Outcome::RetryBudget,
        Outcome::Abandoned,
        Outcome::Uncertain,
        Outcome::Teardown,
    ]
    .into_iter()
    .enumerate()
    {
        for (cut_id, cut) in [
            Cut::BeforeDispatch,
            Cut::Dispatched,
            Cut::Applied,
            Cut::Acknowledged,
        ]
        .into_iter()
        .enumerate()
        {
            for (profile_id, profile) in inputs::profiles().enumerate() {
                if selection == "terminal-smoke" && ![0, 3].contains(&profile_id) {
                    continue;
                }
                for (role, direction) in crate::canonical_fixtures::DIRECTIONS
                    .into_iter()
                    .enumerate()
                {
                    for (mode_id, mode) in [Mode::BaseFallback, Mode::Negotiated]
                        .into_iter()
                        .enumerate()
                    {
                        let row = inputs::fresh(
                            3_000_000
                                + ((outcome_id * 4 + cut_id) * 1000
                                    + profile_id * 4
                                    + role * 2
                                    + mode_id) as u64,
                            profile,
                            direction,
                            mode,
                        );
                        result.push(Case { row, outcome, cut });
                    }
                }
            }
        }
    }
    assert_eq!(
        result.len(),
        if selection == "terminal-smoke" {
            160
        } else {
            4080
        }
    );
    result
}
fn filename(stage: &str, row: &Row) -> String {
    format!("{stage}-{}.rows", row.key.0)
}
fn finish(
    runtime: &mut Runtime,
    provider: &Provider,
    store: &mut CasStore,
    case: &Case,
    root: &Path,
    cut: Cut,
) {
    if case.outcome == Outcome::CrossedLoss {
        let response = read(root, &packet_name("terminal-reply", case.row.key.0));
        runtime
            .complete(
                provider,
                store,
                &response,
                Bytes::from_static(b"crossed-rekey-lost"),
                |row| ke::finish_operation(row, 31, Outcome::CrossedLoss, None),
                cut,
            )
            .unwrap();
    } else {
        runtime
            .retire_operation(provider, store, 31, case.outcome, cut)
            .unwrap();
    }
}
pub fn run(root: &Path, stage: &str, selection: &str, provider: &Provider) {
    for case in cases(selection) {
        let row = &case.row;
        if stage == "terminal-start" {
            let mut store = CasStore::new(7);
            let owners = EpochOwners::new(7);
            let initial = driver::create(provider, &mut store, row).unwrap();
            let mut runtime = Runtime::restore(
                provider,
                &owners,
                &store.fenced_read(&initial, row.key).unwrap(),
                false,
            )
            .unwrap();
            runtime
                .reserve(
                    provider,
                    &mut store,
                    19,
                    1,
                    100,
                    Cut::Complete,
                    Cut::Complete,
                )
                .unwrap();
            let operation = ke::draft(row, 31, KeKind::ChildRekey);
            ke::persist_ke(&mut runtime, provider, &mut store, operation, Cut::Complete).unwrap();
            let mut transport = Transport::default();
            runtime.dispatch_replay(&mut transport).unwrap();
            write(
                root,
                &packet_name("terminal-request", row.key.0),
                transport.submitted.last().unwrap(),
            );
            write(root, &filename(stage, row), &store.encrypted_snapshot());
            continue;
        }
        let (prior, stamp) = if stage == "terminal-apply" {
            ("terminal-start", 8)
        } else {
            assert_eq!(stage, "terminal-finish");
            ("terminal-apply", 9)
        };
        let (mut store, cuts) =
            CasStore::reopen_after_join(&read(root, &filename(prior, row)), stamp).unwrap();
        let owners = EpochOwners::new(stamp);
        assert_eq!(cuts.len(), 1);
        let stored = store.inspect(row.key).unwrap();
        let plain = envelope::unseal(provider, row.key, stored).unwrap();
        let image =
            ProfileCodec::decode(&plain, row.key, stored.version, stored.sealed_stamp).unwrap();
        if image.operations[&31].outcome == Outcome::Pending {
            let mut runtime = Runtime::restore(provider, &owners, &cuts[0], false).unwrap();
            finish(
                &mut runtime,
                provider,
                &mut store,
                &case,
                root,
                if stage == "terminal-apply" {
                    case.cut
                } else {
                    Cut::Complete
                },
            );
            let mut transport = Transport::default();
            if stage == "terminal-apply" || case.outcome != Outcome::CrossedLoss {
                assert!(runtime.dispatch_replay(&mut transport).is_err());
            } else {
                assert!(!runtime.dispatch_replay(&mut transport).unwrap());
            }
            assert!(transport.submitted.is_empty());
        } else {
            assert_eq!(image.operations[&31].outcome, case.outcome);
            assert!(image.operations[&31].checkpoint.is_none());
        }
        write(root, &filename(stage, row), &store.encrypted_snapshot());
    }
}
fn process(selection: &str) {
    let root = RunDir::new();
    let cases = cases(selection);
    let mut peers: Vec<_> = cases
        .iter()
        .map(|case| {
            PeerModel::new(
                Wire::new(
                    case.row.profile,
                    &case.row.keys,
                    case.row.spis,
                    crate::canonical_fixtures::opposite(case.row.direction),
                ),
                0,
                0,
                case.row.mode == Mode::Negotiated,
            )
        })
        .collect();
    child(
        &root.0,
        "terminal-start",
        selection,
        "terminal-checkpoint-origin",
    );
    for (case, peer) in cases.iter().zip(&mut peers) {
        let request = read(&root.0, &packet_name("terminal-request", case.row.key.0));
        assert_eq!(peer.receive(&request), Ok(Event::NewRequest(0)));
        if case.outcome == Outcome::CrossedLoss {
            let dh = Dh::generate(case.row.profile.dh_group()).unwrap();
            let (first, body) = ke::payload(
                &case.row,
                KeKind::ChildRekey,
                true,
                case.row.profile.dh_group(),
                0x71727374,
                &[0x73; 64],
                dh.public_value(),
            );
            drop(dh);
            let response = peer.respond(0, PayloadChain::new(first, &body)).unwrap();
            write(
                &root.0,
                &packet_name("terminal-reply", case.row.key.0),
                &response,
            );
        }
    }
    child(
        &root.0,
        "terminal-apply",
        selection,
        "terminal-result-worker",
    );
    let provider = Provider::new();
    for case in &cases {
        let (store, _) =
            CasStore::reopen_after_join(&read(&root.0, &filename("terminal-apply", &case.row)), 9)
                .unwrap();
        let stored = store.inspect(case.row.key).unwrap();
        let plain = envelope::unseal(&provider, case.row.key, stored).unwrap();
        let row = ProfileCodec::decode(&plain, case.row.key, stored.version, stored.sealed_stamp)
            .unwrap();
        let landed = matches!(case.cut, Cut::Applied | Cut::Acknowledged);
        assert_eq!(row.operations[&31].checkpoint.is_none(), landed);
        assert_eq!(
            row.operations[&31].outcome,
            if landed {
                case.outcome
            } else {
                Outcome::Pending
            }
        );
        assert_eq!(row.closed, landed && case.outcome != Outcome::CrossedLoss);
    }
    child(
        &root.0,
        "terminal-finish",
        selection,
        "terminal-readback-worker",
    );
    for (case, peer) in cases.iter().zip(&mut peers) {
        let (mut store, mut cuts) = CasStore::reopen_after_join(
            &read(&root.0, &filename("terminal-finish", &case.row)),
            10,
        )
        .unwrap();
        let owners = EpochOwners::new(10);
        let stored = store.inspect(case.row.key).unwrap();
        let plain = envelope::unseal(&provider, case.row.key, stored).unwrap();
        let row = ProfileCodec::decode(&plain, case.row.key, stored.version, stored.sealed_stamp)
            .unwrap();
        assert!(row.operations[&31].checkpoint.is_none());
        assert_eq!(row.operations[&31].outcome, case.outcome);
        if case.outcome == Outcome::CrossedLoss {
            let mut runtime = Runtime::restore(&provider, &owners, &cuts[0], false).unwrap();
            let mut transport = Transport::default();
            assert!(!runtime.dispatch_replay(&mut transport).unwrap());
            runtime
                .reserve(
                    &provider,
                    &mut store,
                    29,
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
                Ok(Event::NewRequest(1))
            );
            let response = peer.respond(1, crate::canonical_fixtures::empty()).unwrap();
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
            assert!(peer.alive());
        } else {
            let Recovery::Terminal(mut cleanup) =
                remedy::recover(&provider, &owners, cuts.pop().unwrap()).unwrap()
            else {
                panic!("closed row resumed");
            };
            assert!(!cleanup.commit(&mut store, Cut::Applied).unwrap());
            let command = cleanup.command().clone();
            store.prune(command.request());
            cleanup.resolve(&store).unwrap();
            assert!(store.inspect(case.row.key).is_none());
            peer.request(37, crate::canonical_fixtures::empty())
                .unwrap();
            peer.advance(REQUEST_TIMEOUT_MS);
            assert!(!peer.alive());
        }
    }
}
#[test]
fn terminal_checkpoint_process_smoke() {
    process("terminal-smoke");
}
#[test]
fn terminal_checkpoint_process_crashes_across_outcomes_profiles_roles_modes_and_cuts() {
    process("terminal-all");
}
