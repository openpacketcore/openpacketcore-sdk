use super::{
    authority::{EpochOwners, Transport},
    codec::ProfileCodec,
    driver::{self, Cut, Runtime},
    envelope::{self, Error as KeyError, Fault, Provider},
    ke,
    lifecycle::matrix,
    peer::{Event, PeerModel},
    row::Outcome,
    store::CasStore,
    wire::Wire,
};
use opc_proto_ikev2::{Ikev2EphemeralDhKey as Dh, Ikev2MessageIdSyncMode as Mode, PayloadChain};

#[test]
fn checkpoint_failure_and_retirement_backpressures_every_envelope_boundary() {
    for (fault_id, fault) in [Fault::Unavailable, Fault::Timeout, Fault::Throttled]
        .into_iter()
        .enumerate()
    {
        for (kind_id, kind) in ke::KINDS.into_iter().enumerate() {
            matrix(620_000 + (fault_id * 3 + kind_id) as u64 * 1_000, |row| {
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
                        19,
                        3,
                        100,
                        Cut::Complete,
                        Cut::Complete,
                    )
                    .unwrap();
                let operation = ke::draft(&runtime.row, 19, kind);
                let diagnostics = ke::checkpoint_diagnostics(&operation);
                assert!(
                    diagnostics
                        == format!("Operation {{ id: 19, kind: {kind:?}, outcome: Pending, .. }}")
                );
                let before = (store.dispatches, store.publications);
                provider.fail(fault);
                assert_eq!(
                    ke::persist_ke(
                        &mut runtime,
                        &provider,
                        &mut store,
                        operation.clone(),
                        Cut::Complete
                    ),
                    Err(driver::Error::Key(KeyError::Backpressure))
                );
                assert_eq!((store.dispatches, store.publications), before);
                assert!(runtime.permit().check().is_ok());
                let mut transport = Transport::default();
                assert!(runtime.dispatch_replay(&mut transport).is_err());
                assert!(transport.submitted.is_empty());
                provider.fail(Fault::Healthy);
                runtime.resolve(&provider, &store, &initial).unwrap();
                assert!(ke::persist_ke(
                    &mut runtime,
                    &provider,
                    &mut store,
                    operation,
                    Cut::Complete
                )
                .unwrap());
                runtime.dispatch_replay(&mut transport).unwrap();
                let request = transport.submitted.last().unwrap().clone();
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
                assert_eq!(peer.receive(&request), Ok(Event::NewRequest(0)));
                let packet = peer.wire.open(&request).unwrap();
                let fields = ke::parts(&row, kind, row.profile.dh_group(), &packet, false).unwrap();
                drop(runtime);
                let cut = store.fenced_read(&initial, row.key).unwrap();
                provider.fail(fault);
                assert!(matches!(
                    Runtime::restore(&provider, &owners, &cut, false),
                    Err(driver::Error::Key(KeyError::Backpressure))
                ));
                provider.fail(Fault::Healthy);
                let mut runtime = Runtime::restore(&provider, &owners, &cut, false).unwrap();
                assert!(runtime.row.operations[&19].checkpoint.is_some());
                runtime.dispatch_replay(&mut transport).unwrap();
                assert_eq!(transport.submitted.last().unwrap(), &request);
                assert_eq!(
                    peer.receive(transport.submitted.last().unwrap()),
                    Ok(Event::Ignored)
                );
                let private = Dh::generate(row.profile.dh_group()).unwrap();
                let shared = private.agree(&fields.public).unwrap();
                let spi = if kind == super::row::KeKind::IkeRekey {
                    0x6162_6364_6566_6768
                } else {
                    0x6162_6364
                };
                let nonce = [0x65; 64];
                let expected = ke::derive(
                    &row,
                    kind,
                    (fields.spi, spi),
                    &fields.nonce,
                    &nonce,
                    &shared,
                );
                drop(shared);
                let (first, payload) = ke::payload(
                    &row,
                    kind,
                    true,
                    row.profile.dh_group(),
                    spi,
                    &nonce,
                    private.public_value(),
                );
                drop(private);
                let response = peer.respond(0, PayloadChain::new(first, &payload)).unwrap();
                // Keys have been derived, but failure sealing the result leaves
                // the committed checkpoint and healthy forwarding intact.
                provider.fail(fault);
                assert_eq!(
                    ke::complete_initiator(
                        &mut runtime,
                        &provider,
                        &mut store,
                        19,
                        &response,
                        Cut::Complete
                    ),
                    Err(driver::Error::Key(KeyError::Backpressure))
                );
                assert!(runtime.row.operations[&19].checkpoint.is_some());
                assert!(runtime.row.operations[&19].derived.is_none());
                assert!(runtime.permit().check().is_ok());
                provider.fail(Fault::Healthy);
                runtime.resolve(&provider, &store, &initial).unwrap();
                assert!(ke::complete_initiator(
                    &mut runtime,
                    &provider,
                    &mut store,
                    19,
                    &response,
                    Cut::Applied
                )
                .unwrap()
                .is_none());
                let write = runtime.pending.as_ref().unwrap().clone();
                provider.fail(fault);
                assert_eq!(
                    runtime.resolve(&provider, &store, &write),
                    Err(driver::Error::Key(KeyError::Backpressure))
                );
                assert!(runtime.pending.is_some());
                assert!(runtime.row.operations[&19].checkpoint.is_some());
                assert!(runtime.permit().check().is_ok());
                provider.fail(Fault::Healthy);
                runtime.resolve(&provider, &store, &write).unwrap();
                assert!(runtime.row.operations[&19].checkpoint.is_none());
                assert!(
                    runtime.row.operations[&19]
                        .derived
                        .as_ref()
                        .unwrap()
                        .as_slice()
                        == expected.as_slice()
                );
                assert!(!runtime.dispatch_replay(&mut transport).unwrap());
                assert!(peer.alive());
            });
        }
    }
}

#[test]
fn checkpoint_removal_is_atomic_with_every_non_success_terminal_cas() {
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
            matrix(640_000 + (outcome_id * 4 + cut_id) as u64 * 1_000, |row| {
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
                        19,
                        1,
                        100,
                        Cut::Complete,
                        Cut::Complete,
                    )
                    .unwrap();
                let operation = ke::draft(&runtime.row, 19, super::row::KeKind::ChildRekey);
                ke::persist_ke(
                    &mut runtime,
                    &provider,
                    &mut store,
                    operation,
                    Cut::Complete,
                )
                .unwrap();
                let mut transport = Transport::default();
                runtime.dispatch_replay(&mut transport).unwrap();
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
                let closes_sa = outcome != Outcome::CrossedLoss;
                if closes_sa {
                    assert!(!runtime
                        .retire_operation(&provider, &mut store, 19, outcome, cut)
                        .unwrap());
                } else {
                    // A lost crossed Child rekey is an operation result, not
                    // permission to tear down the still-healthy parent IKE SA.
                    let private = Dh::generate(row.profile.dh_group()).unwrap();
                    let (first, payload) = ke::payload(
                        &row,
                        super::row::KeKind::ChildRekey,
                        true,
                        row.profile.dh_group(),
                        0x7172_7374,
                        &[0x73; 64],
                        private.public_value(),
                    );
                    drop(private);
                    let response = peer.respond(0, PayloadChain::new(first, &payload)).unwrap();
                    assert!(runtime
                        .complete(
                            &provider,
                            &mut store,
                            &response,
                            bytes::Bytes::from_static(b"crossed-rekey-lost"),
                            |row| ke::finish_operation(row, 19, outcome, None),
                            cut
                        )
                        .unwrap()
                        .is_none());
                }
                assert!(runtime.row.operations[&19].checkpoint.is_some());
                assert!(runtime.permit().check().is_ok());
                let before_release = transport.submitted.len();
                assert!(runtime.dispatch_replay(&mut transport).is_err());
                assert_eq!(transport.submitted.len(), before_release);
                let write = runtime.pending.as_ref().unwrap().clone();
                let stored = store.inspect(row.key).unwrap();
                let plain = envelope::unseal(&provider, row.key, stored).unwrap();
                let image =
                    ProfileCodec::decode(&plain, row.key, stored.version, stored.sealed_stamp)
                        .unwrap();
                let landed = matches!(cut, Cut::Applied | Cut::Acknowledged);
                assert_eq!(image.closed, landed && closes_sa);
                assert_eq!(image.operations[&19].checkpoint.is_none(), landed);
                assert_eq!(
                    image.operations[&19].outcome,
                    if landed { outcome } else { Outcome::Pending }
                );
                store.dispatch(write.clone()).unwrap();
                store.apply(write.request()).unwrap();
                runtime.resolve(&provider, &store, &write).unwrap();
                assert_eq!(runtime.row.closed, closes_sa);
                assert!(runtime.row.operations[&19].checkpoint.is_none());
                assert_eq!(runtime.row.operations[&19].outcome, outcome);
                assert_eq!(runtime.permit().check().is_err(), closes_sa);
                let before = transport.submitted.len();
                if closes_sa {
                    assert!(runtime.dispatch_replay(&mut transport).is_err());
                } else {
                    assert!(!runtime.dispatch_replay(&mut transport).unwrap());
                }
                assert_eq!(transport.submitted.len(), before);
                drop(runtime);
                let restored = Runtime::restore(
                    &provider,
                    &owners,
                    &store.fenced_read(&write, row.key).unwrap(),
                    false,
                );
                if closes_sa {
                    assert!(matches!(restored, Err(driver::Error::Closed)));
                } else {
                    assert!(restored.is_ok());
                    assert!(peer.alive());
                }
            });
        }
    }
}

#[test]
fn authenticated_ke_without_its_operation_is_incomplete_before_replay() {
    matrix(661_000, |row| {
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
                19,
                1,
                100,
                Cut::Complete,
                Cut::Complete,
            )
            .unwrap();
        let operation = ke::draft(&runtime.row, 19, super::row::KeKind::NewChild);
        ke::persist_ke(
            &mut runtime,
            &provider,
            &mut store,
            operation,
            Cut::Complete,
        )
        .unwrap();
        let partial = runtime
            .row
            .next_write(store.stamp(), |row| row.operations.clear())
            .unwrap();
        let write =
            driver::command(&provider, &store, Some(runtime.row.version), &partial).unwrap();
        store.commit(&write).unwrap();
        drop(runtime);
        assert!(matches!(
            Runtime::restore(
                &provider,
                &owners,
                &store.fenced_read(&write, row.key).unwrap(),
                false
            ),
            Err(driver::Error::Key(KeyError::Format))
        ));
    });
}

#[test]
fn checkpoint_capability_withdrawal_after_restore_backpressures_then_completes() {
    use opc_crypto_provider::CryptoCapability;
    use opc_proto_ikev2::Ikev2CryptoModuleErrorCode;
    for (profile_id, profile) in super::inputs::profiles().enumerate() {
        if ![0, 3].contains(&profile_id) {
            continue;
        }
        for (role, direction) in crate::canonical_fixtures::DIRECTIONS
            .into_iter()
            .enumerate()
        {
            let row = super::inputs::fresh(
                2_910_000 + (profile_id * 2 + role) as u64,
                profile,
                direction,
                Mode::Negotiated,
            );
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
                    19,
                    1,
                    100,
                    Cut::Complete,
                    Cut::Complete,
                )
                .unwrap();
            let kind = super::row::KeKind::ChildRekey;
            let operation = ke::draft(&row, 19, kind);
            ke::persist_ke(
                &mut runtime,
                &provider,
                &mut store,
                operation,
                Cut::Complete,
            )
            .unwrap();
            let mut transport = Transport::default();
            runtime.dispatch_replay(&mut transport).unwrap();
            let request = transport.submitted.last().unwrap().clone();
            let mut peer = PeerModel::new(
                Wire::new(
                    row.profile,
                    &row.keys,
                    row.spis,
                    crate::canonical_fixtures::opposite(direction),
                ),
                0,
                0,
                true,
            );
            assert_eq!(peer.receive(&request), Ok(Event::NewRequest(0)));
            let fields = ke::parts(
                &row,
                kind,
                row.profile.dh_group(),
                &peer.wire.open(&request).unwrap(),
                false,
            )
            .unwrap();
            let private = Dh::generate(row.profile.dh_group()).unwrap();
            let secret = private.agree(&fields.public).unwrap();
            let spi = 0x6162_6364;
            let nonce = [0x65; 64];
            let expected = ke::derive(
                &row,
                kind,
                (fields.spi, spi),
                &fields.nonce,
                &nonce,
                &secret,
            );
            let (first, payload) = ke::payload(
                &row,
                kind,
                true,
                row.profile.dh_group(),
                spi,
                &nonce,
                private.public_value(),
            );
            drop((private, secret));
            let response = peer.respond(0, PayloadChain::new(first, &payload)).unwrap();
            drop(runtime);
            let mut runtime = Runtime::restore(
                &provider,
                &owners,
                &store.fenced_read(&initial, row.key).unwrap(),
                false,
            )
            .unwrap();
            let before = (
                store.publications,
                provider.calls(),
                super::module::counts(),
            );
            let saved = ProfileCodec::encode(&runtime.row).unwrap();
            super::module::withdraw(CryptoCapability::IkeDhCheckpoint, || {
                assert_eq!(
                    Dh::checkpoint_readiness(row.profile.dh_group())
                        .unwrap_err()
                        .code(),
                    Ikev2CryptoModuleErrorCode::CapabilityWithdrawn
                );
                assert!(matches!(
                    ke::try_draft(&row, 20, kind),
                    Err(KeyError::Backpressure)
                ));
                let operation = &runtime.row.operations[&19];
                assert!(matches!(
                    Dh::import_private_checkpoint(operation.group, operation.checkpoint.as_ref().unwrap(), &operation.public),
                    Err(opc_proto_ikev2::Ikev2SaInitCryptoError::CryptoModuleFailure { error })
                        if error.code() == Ikev2CryptoModuleErrorCode::CapabilityWithdrawn
                ));
                assert!(matches!(
                    ke::restore_checkpoint(&runtime, operation),
                    Err(KeyError::Backpressure)
                ));
                assert_eq!(
                    ke::complete_initiator(
                        &mut runtime,
                        &provider,
                        &mut store,
                        19,
                        &response,
                        Cut::Complete
                    ),
                    Err(driver::Error::Key(KeyError::Backpressure))
                );
                assert!(runtime.permit().check().is_ok());
                assert!(runtime.row.operations[&19].checkpoint.is_some());
                assert!(ProfileCodec::encode(&runtime.row).unwrap().as_slice() == saved.as_slice());
                assert_eq!(
                    (
                        store.publications,
                        provider.calls(),
                        super::module::counts()
                    ),
                    before
                );
            });
            assert!(ke::complete_initiator(
                &mut runtime,
                &provider,
                &mut store,
                19,
                &response,
                Cut::Complete
            )
            .unwrap()
            .is_some());
            let completed = &runtime.row.operations[&19];
            assert_eq!(completed.outcome, Outcome::Success);
            assert!(completed.checkpoint.is_none());
            assert!(completed.derived.as_ref().unwrap().as_slice() == expected.as_slice());
            drop(runtime);
        }
    }
}

#[test]
fn actual_checkpoint_export_and_import_preserve_transient_errors_and_terminal_removal() {
    use opc_crypto_provider::CryptoOperationErrorCode as Code;
    for (group_id, group) in ke::GROUPS.into_iter().enumerate() {
        for (profile_id, base) in super::inputs::profiles().enumerate() {
            if ![0, 3].contains(&profile_id) {
                continue;
            }
            let profile = opc_proto_ikev2::Ikev2SaInitCryptoProfile::from_transform_ids(
                base.prf().transform_id(),
                group.transform_id(),
                base.encryption().transform_id(),
                Some(base.encryption().key_bits()),
                base.integrity().map(|i| i.transform_id()),
            )
            .unwrap();
            for (role, direction) in crate::canonical_fixtures::DIRECTIONS
                .into_iter()
                .enumerate()
            {
                for (mode_id, mode) in [Mode::BaseFallback, Mode::Negotiated]
                    .into_iter()
                    .enumerate()
                {
                    let row = super::inputs::fresh(
                        2_900_000 + (group_id * 100 + profile_id * 4 + role * 2 + mode_id) as u64,
                        profile,
                        direction,
                        mode,
                    );
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
                    let before = store.publications;
                    assert!(matches!(
                        super::module::checkpoint_fault(Code::Unavailable, || ke::try_draft(
                            &row,
                            19,
                            super::row::KeKind::ChildRekey
                        )),
                        Err(KeyError::Backpressure)
                    ));
                    assert_eq!(store.publications, before);
                    assert!(runtime.permit().check().is_ok());
                    runtime
                        .reserve(
                            &provider,
                            &mut store,
                            19,
                            1,
                            100,
                            Cut::Complete,
                            Cut::Complete,
                        )
                        .unwrap();
                    let operation = ke::draft(&row, 19, super::row::KeKind::ChildRekey);
                    ke::persist_ke(
                        &mut runtime,
                        &provider,
                        &mut store,
                        operation,
                        Cut::Complete,
                    )
                    .unwrap();
                    let mut transport = Transport::default();
                    runtime.dispatch_replay(&mut transport).unwrap();
                    drop(runtime);
                    runtime = Runtime::restore(
                        &provider,
                        &owners,
                        &store.fenced_read(&initial, row.key).unwrap(),
                        false,
                    )
                    .unwrap();
                    let op = &runtime.row.operations[&19];
                    for code in [
                        Code::Unavailable,
                        Code::EntropyUnavailable,
                        Code::KeyGenerationFailed,
                        Code::UnsupportedAlgorithm,
                    ] {
                        assert!(matches!(
                            super::module::checkpoint_fault(code, || ke::restore_checkpoint(
                                &runtime, op
                            )),
                            Err(KeyError::Backpressure)
                        ));
                    }
                    assert!(op.checkpoint.is_some());
                    assert!(runtime.permit().check().is_ok());
                    let restored = ke::restore_checkpoint(&runtime, op).unwrap();
                    assert!(restored.public_value() == op.public);
                    drop(restored);
                    assert!(matches!(
                        super::module::bad_output(|| ke::restore_checkpoint(&runtime, op)),
                        Err(KeyError::Integrity)
                    ));
                    for code in [Code::InvalidCheckpoint, Code::CheckpointPublicValueMismatch] {
                        assert!(matches!(
                            super::module::checkpoint_fault(code, || ke::restore_checkpoint(
                                &runtime, op
                            )),
                            Err(KeyError::Integrity)
                        ));
                    }
                    let before = transport.submitted.len();
                    assert!(!runtime
                        .retire_operation(
                            &provider,
                            &mut store,
                            19,
                            Outcome::Teardown,
                            Cut::Applied
                        )
                        .unwrap());
                    assert!(runtime.dispatch_replay(&mut transport).is_err());
                    assert_eq!(transport.submitted.len(), before);
                    let terminal = runtime.pending.as_ref().unwrap().clone();
                    runtime.resolve(&provider, &store, &terminal).unwrap();
                    assert!(runtime.row.operations[&19].checkpoint.is_none());
                    assert!(runtime.row.closed);
                    runtime.delete().unwrap();
                }
            }
        }
    }
}
