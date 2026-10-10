//! Fresh processes across atomic rekey publication, new-epoch traffic and old
//! Delete cleanup. Only encrypted committed rows cross local process loss.

use super::{
    authority::{EpochOwners, Transport},
    codec::ProfileCodec,
    crash::{child, packet_name, read, write, RunDir},
    driver::{self, Cut, Runtime},
    envelope::{self, Provider},
    handoff, inputs, ke,
    lifecycle::child_delete,
    module,
    peer::{Event, PeerModel},
    peer_epochs::PeerEpochs,
    row::{KeKind, Row},
    store::{CasStore, RowKey},
    wire::Wire,
};
use bytes::Bytes;
use opc_proto_ikev2::{
    derive_ike_sa_rekey_key_material, Ikev2EphemeralDhKey as Dh, Ikev2ExchangeKind as Exchange,
    Ikev2MessageIdSyncMode as Mode, Ikev2ProtectedPayloadDirection as Direction, PayloadChain,
};
use std::path::Path;

struct Case {
    row: Row,
    local: bool,
    cut: Cut,
}
impl Case {
    fn new_key(&self) -> RowKey {
        RowKey(self.row.key.0 + 100_000)
    }
}

fn cases(selection: &str) -> Vec<Case> {
    let mut cases = Vec::new();
    for (cut_id, cut) in [
        Cut::BeforeDispatch,
        Cut::Dispatched,
        Cut::Applied,
        Cut::Acknowledged,
    ]
    .into_iter()
    .enumerate()
    {
        for (local_id, local) in [true, false].into_iter().enumerate() {
            for (profile_id, profile) in inputs::profiles().enumerate() {
                if selection == "handoff-smoke" && ![0, 3].contains(&profile_id) {
                    continue;
                }
                for (direction_id, direction) in crate::canonical_fixtures::DIRECTIONS
                    .into_iter()
                    .enumerate()
                {
                    for (mode_id, mode) in [Mode::BaseFallback, Mode::Negotiated]
                        .into_iter()
                        .enumerate()
                    {
                        let tag = 2_000_000
                            + ((cut_id * 2 + local_id) * 1000
                                + profile_id * 4
                                + direction_id * 2
                                + mode_id) as u64;
                        cases.push(Case {
                            row: inputs::fresh(tag, profile, direction, mode),
                            local,
                            cut,
                        });
                    }
                }
            }
        }
    }
    assert_eq!(
        cases.len(),
        if selection == "handoff-smoke" {
            64
        } else {
            1632
        }
    );
    cases
}

fn name(stage: &str, key: RowKey) -> String {
    format!("handoff-{stage}-{}.rows", key.0)
}

pub fn run(root: &Path, stage: &str, selection: &str, provider: &Provider) {
    for case in cases(selection) {
        let key = case.row.key;
        let next_key = case.new_key();
        if stage == "handoff-start" {
            let mut store = CasStore::new(7);
            let owners = EpochOwners::new(7);
            let initial = driver::create(provider, &mut store, &case.row).unwrap();
            let mut runtime = Runtime::restore(
                provider,
                &owners,
                &store.fenced_read(&initial, key).unwrap(),
                false,
            )
            .unwrap();
            if case.local {
                runtime
                    .reserve_control(
                        provider,
                        &mut store,
                        19,
                        1,
                        100,
                        Cut::Complete,
                        Cut::Complete,
                    )
                    .unwrap();
                let draft = ke::draft(&runtime.row, 31, KeKind::IkeRekey);
                ke::persist_ke(&mut runtime, provider, &mut store, draft, Cut::Complete).unwrap();
                let mut transport = Transport::default();
                runtime.dispatch_replay(&mut transport).unwrap();
                write(
                    root,
                    &packet_name("handoff-request", key.0),
                    transport.submitted.last().unwrap(),
                );
            }
            write(root, &name("start", key), &store.encrypted_snapshot());
            continue;
        }
        let (previous, stamp) = match stage {
            "handoff-commit" => ("start", 8),
            "handoff-recover" => ("commit", 9),
            "handoff-new-result" => ("recover", 10),
            "handoff-delete-result" => ("new-result", 11),
            _ => panic!("unknown handoff stage"),
        };
        let (mut store, cuts) =
            CasStore::reopen_after_join(&read(root, &name(previous, key)), stamp).unwrap();
        let owners = EpochOwners::new(stamp);
        let cut = cuts.iter().find(|cut| cut.key() == key).unwrap();
        let mut old = Runtime::restore(provider, &owners, cut, false).unwrap();
        if stage == "handoff-commit" || stage == "handoff-recover" {
            let prior_counts = module::counts();
            let existed = cuts.iter().any(|cut| cut.key() == next_key);
            if !existed {
                let fault = if stage == "handoff-commit" {
                    case.cut
                } else {
                    Cut::Complete
                };
                if case.local {
                    let reply = read(root, &packet_name("handoff-peer-reply", key.0));
                    handoff::finish_initiator(
                        &mut old, provider, &mut store, 31, next_key, &reply, fault,
                    )
                    .unwrap();
                } else {
                    old.reserve_control(
                        provider,
                        &mut store,
                        19,
                        1,
                        if stage == "handoff-commit" { 100 } else { 150 },
                        Cut::Complete,
                        Cut::Complete,
                    )
                    .unwrap();
                    let request = read(root, &packet_name("handoff-peer-request", key.0));
                    handoff::finish_responder(
                        &mut old, provider, &mut store, 31, next_key, &request, fault,
                    )
                    .unwrap();
                }
                if stage == "handoff-commit" {
                    let write_command = old.pending.as_ref().unwrap();
                    assert_eq!(write_command.mutations().len(), 2);
                    if !case.local {
                        let stored = write_command.mutations()[0].value.as_ref().unwrap();
                        let plain = envelope::unseal(provider, key, stored).unwrap();
                        let candidate =
                            ProfileCodec::decode(&plain, key, stored.version, stored.sealed_stamp)
                                .unwrap();
                        write(
                            root,
                            &packet_name("handoff-unreleased", key.0),
                            candidate
                                .window
                                .inbound
                                .as_ref()
                                .unwrap()
                                .response()
                                .unwrap(),
                        );
                    }
                }
            }
            if stage == "handoff-recover" {
                // Refresh a sibling in the same joined execution scope. Every
                // queued command which could still affect it must be fenced.
                let current = store.current_after_join(cut, next_key).unwrap();
                let mut next = Runtime::restore(provider, &owners, &current, false).unwrap();
                if existed {
                    assert_eq!(module::counts().dh_import, prior_counts.dh_import);
                    assert_eq!(module::counts().dh_generate, prior_counts.dh_generate);
                }
                assert_eq!(next.row.window.next_send, Some(0));
                assert_eq!(next.row.window.next_receive, Some(0));
                assert_eq!(next.row.mode, case.row.mode);
                assert!(next.row.operations.is_empty());
                assert!(old.row.operations[&31].checkpoint.is_none());
                let mut transport = Transport::default();
                if case.local {
                    assert!(!old.dispatch_replay(&mut transport).unwrap());
                } else {
                    let request = read(root, &packet_name("handoff-peer-request", key.0));
                    old.replay_response(&request, &mut transport).unwrap();
                    write(
                        root,
                        &packet_name("handoff-response", key.0),
                        transport.submitted.last().unwrap(),
                    );
                    old.replay_response(&request, &mut transport).unwrap();
                    write(
                        root,
                        &packet_name("handoff-response-again", key.0),
                        transport.submitted.last().unwrap(),
                    );
                }
                next.reserve(
                    provider,
                    &mut store,
                    41,
                    1,
                    200,
                    Cut::Complete,
                    Cut::Complete,
                )
                .unwrap();
                next.publish_request(
                    provider,
                    &mut store,
                    Exchange::Informational,
                    child_delete(),
                    |_| {},
                    Cut::Complete,
                )
                .unwrap();
                next.dispatch_replay(&mut transport).unwrap();
                write(
                    root,
                    &packet_name("handoff-new-request", key.0),
                    transport.submitted.last().unwrap(),
                );
            }
        } else if stage == "handoff-new-result" {
            let next_cut = cuts.iter().find(|cut| cut.key() == next_key).unwrap();
            let mut next = Runtime::restore(provider, &owners, next_cut, false).unwrap();
            let response = read(root, &packet_name("handoff-new-reply", key.0));
            next.complete(
                provider,
                &mut store,
                &response,
                Bytes::from_static(b"child-deleted"),
                |_| {},
                Cut::Complete,
            )
            .unwrap();
            assert!(!next.dispatch_replay(&mut Transport::default()).unwrap());
            old.reserve_control(
                provider,
                &mut store,
                51,
                1,
                250,
                Cut::Complete,
                Cut::Complete,
            )
            .unwrap();
            old.publish_control_request(
                provider,
                &mut store,
                Exchange::Informational,
                crate::canonical_fixtures::delete(),
                |_| {},
                Cut::Complete,
            )
            .unwrap();
            let mut transport = Transport::default();
            old.dispatch_replay(&mut transport).unwrap();
            write(
                root,
                &packet_name("handoff-delete", key.0),
                transport.submitted.last().unwrap(),
            );
            assert!(store.inspect(key).is_some() && store.inspect(next_key).is_some());
        } else {
            let response = read(root, &packet_name("handoff-delete-reply", key.0));
            old.complete(
                provider,
                &mut store,
                &response,
                Bytes::from_static(b"ike-deleted"),
                |row| row.closed = true,
                Cut::Complete,
            )
            .unwrap();
            old.erase_after_delete(&mut store, Cut::Applied).unwrap();
            let erase = old.pending.as_ref().unwrap().clone();
            store.prune(erase.request());
            old.resolve_deletion(&store, &erase).unwrap();
            old.delete().unwrap();
            assert!(store.inspect(key).is_none());
            assert!(store.inspect(next_key).is_some());
        }
        write(
            root,
            &name(stage.strip_prefix("handoff-").unwrap(), key),
            &store.encrypted_snapshot(),
        );
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
    let mut ledgers: Vec<_> = cases
        .iter()
        .map(|case| PeerEpochs::new(case.row.spis, &[11, 12]))
        .collect();
    // These are the independent peer's handles. No local private handle ever
    // leaves the exited child; local initiators resume from their sealed rows.
    let peer_private: Vec<_> = cases
        .iter()
        .map(|case| Dh::generate(case.row.profile.dh_group()).unwrap())
        .collect();
    child(&root.0, "handoff-start", selection, "handoff-initial-build");
    let mut expected = Vec::new();
    for (((case, peer), ledger), dh) in cases
        .iter()
        .zip(&mut peers)
        .zip(&mut ledgers)
        .zip(&peer_private)
    {
        let row = &case.row;
        let receiver = Wire::new(row.profile, &row.keys, row.spis, row.direction);
        if case.local {
            let request = read(&root.0, &packet_name("handoff-request", row.key.0));
            assert_eq!(peer.receive(&request), Ok(Event::NewRequest(0)));
            ledger.observe(&peer.wire, &request).unwrap();
            let parts = ke::parts(
                row,
                KeKind::IkeRekey,
                row.profile.dh_group(),
                &peer.wire.open(&request).unwrap(),
                false,
            )
            .unwrap();
            let spis: (u64, u64) = (parts.spi, 0x6162_6364_6566_6768);
            let secret = dh.agree(&parts.public).unwrap();
            let keys = derive_ike_sa_rekey_key_material(
                row.profile.prf(),
                row.keys.sk_d(),
                row.profile,
                spis.0.to_be_bytes(),
                spis.1.to_be_bytes(),
                &parts.nonce,
                &[0x73; 64],
                &secret,
            )
            .unwrap();
            expected.push(Some((spis, keys)));
            let (first, body) = ke::payload(
                row,
                KeKind::IkeRekey,
                true,
                row.profile.dh_group(),
                spis.1,
                &[0x73; 64],
                dh.public_value(),
            );
            let reply = peer.respond(0, PayloadChain::new(first, &body)).unwrap();
            ledger.observe(&receiver, &reply).unwrap();
            write(
                &root.0,
                &packet_name("handoff-peer-reply", row.key.0),
                &reply,
            );
        } else {
            let (first, body) = ke::payload(
                row,
                KeKind::IkeRekey,
                false,
                row.profile.dh_group(),
                0x7172_7374_7576_7778,
                &[0x63; 64],
                dh.public_value(),
            );
            let request = peer.request(36, PayloadChain::new(first, &body)).unwrap();
            ledger.observe(&receiver, &request).unwrap();
            write(
                &root.0,
                &packet_name("handoff-peer-request", row.key.0),
                &request,
            );
            expected.push(None);
        }
    }
    child(&root.0, "handoff-commit", selection, "handoff-result-build");
    child(
        &root.0,
        "handoff-recover",
        selection,
        "handoff-upgraded-build",
    );
    for ((((case, peer), ledger), dh), expected) in cases
        .iter()
        .zip(&mut peers)
        .zip(&mut ledgers)
        .zip(&peer_private)
        .zip(&mut expected)
    {
        if case.local {
            continue;
        }
        let row = &case.row;
        let reply = read(&root.0, &packet_name("handoff-response", row.key.0));
        assert_eq!(peer.receive(&reply), Ok(Event::Completed(0)));
        ledger.observe(&peer.wire, &reply).unwrap();
        let again = read(&root.0, &packet_name("handoff-response-again", row.key.0));
        assert_eq!(reply, again);
        assert_eq!(peer.receive(&again), Ok(Event::Ignored));
        if matches!(case.cut, Cut::Applied | Cut::Acknowledged) {
            assert_eq!(
                reply,
                read(&root.0, &packet_name("handoff-unreleased", row.key.0))
            );
        }
        let parts = ke::parts(
            row,
            KeKind::IkeRekey,
            row.profile.dh_group(),
            &peer.wire.open(&reply).unwrap(),
            true,
        )
        .unwrap();
        let spis: (u64, u64) = (0x7172_7374_7576_7778, parts.spi);
        let secret = dh.agree(&parts.public).unwrap();
        let keys = derive_ike_sa_rekey_key_material(
            row.profile.prf(),
            row.keys.sk_d(),
            row.profile,
            spis.0.to_be_bytes(),
            spis.1.to_be_bytes(),
            &[0x63; 64],
            &parts.nonce,
            &secret,
        )
        .unwrap();
        *expected = Some((spis, keys));
    }
    drop(peer_private);
    let expected: Vec<_> = expected.into_iter().map(Option::unwrap).collect();
    for ((case, (spis, keys)), ledger) in cases.iter().zip(&expected).zip(&ledgers) {
        let mut peer = PeerModel::new(
            Wire::new(
                case.row.profile,
                keys,
                *spis,
                if case.local {
                    Direction::ResponderToInitiator
                } else {
                    Direction::InitiatorToResponder
                },
            ),
            0,
            0,
            case.row.mode == Mode::Negotiated,
        );
        let request = read(&root.0, &packet_name("handoff-new-request", case.row.key.0));
        assert_eq!(peer.receive(&request), Ok(Event::NewRequest(0)));
        assert_eq!(ledger.child_owner(11), *spis);
        let reply = peer.respond(0, crate::canonical_fixtures::empty()).unwrap();
        write(
            &root.0,
            &packet_name("handoff-new-reply", case.row.key.0),
            &reply,
        );
    }
    child(
        &root.0,
        "handoff-new-result",
        selection,
        "handoff-new-traffic-build",
    );
    for ((case, peer), ledger) in cases.iter().zip(&mut peers).zip(&mut ledgers) {
        let request = read(&root.0, &packet_name("handoff-delete", case.row.key.0));
        let id = u32::from(case.local);
        assert_eq!(peer.receive(&request), Ok(Event::NewRequest(id)));
        ledger.observe(&peer.wire, &request).unwrap();
        assert!(ledger.established(case.row.spis));
        let reply = peer
            .respond(id, crate::canonical_fixtures::empty())
            .unwrap();
        let receiver = Wire::new(
            case.row.profile,
            &case.row.keys,
            case.row.spis,
            case.row.direction,
        );
        ledger.observe(&receiver, &reply).unwrap();
        write(
            &root.0,
            &packet_name("handoff-delete-reply", case.row.key.0),
            &reply,
        );
    }
    child(
        &root.0,
        "handoff-delete-result",
        selection,
        "handoff-cleanup-build",
    );
    let provider = Provider::new();
    for ((case, (spis, _)), ledger) in cases.iter().zip(&expected).zip(&ledgers) {
        let (store, cuts) =
            CasStore::reopen_after_join(&read(&root.0, &name("delete-result", case.row.key)), 12)
                .unwrap();
        assert!(store.inspect(case.row.key).is_none());
        assert_eq!(cuts.len(), 1);
        assert_eq!(cuts[0].key(), case.new_key());
        let owners = EpochOwners::new(12);
        let mut next = Runtime::restore(&provider, &owners, &cuts[0], false).unwrap();
        assert_eq!(next.row.spis, *spis);
        assert!(!next.dispatch_replay(&mut Transport::default()).unwrap());
        assert!(!ledger.established(case.row.spis));
        assert!(ledger.established(*spis));
        assert_eq!(ledger.child_owner(12), *spis);
    }
}

#[test]
fn atomic_rekey_process_smoke() {
    process("handoff-smoke");
}

#[test]
fn atomic_rekey_process_crashes_across_profiles_roles_modes_and_commit_cuts() {
    process("handoff-all");
}
