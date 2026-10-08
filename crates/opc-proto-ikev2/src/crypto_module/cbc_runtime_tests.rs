//! Process-isolated admitted CBC recovery evidence and entropy accounting.

use super::{
    block_on, install_ikev2_crypto_module, policy, Arc, CountingModule, CryptoCapability,
    Ikev2CryptoRequirements, Ordering,
};
use crate::recovery::cbc_test_fixtures::*;
use crate::recovery::{
    Ikev2CommittedWindow as Window, Ikev2SyncClock as Clock, Ikev2SyncInitiatorAction as Action,
    Ikev2SyncRecoveryPolicy, Ikev2WindowError as Error,
};
use crate::{Ikev2ExchangeKind as Exchange, PayloadChain, PayloadType};
use std::process::Command;

#[test]
fn cbc_runtime_keeps_random_iv_and_provider_contracts() {
    for case in [
        "ordinary-ivs",
        "sync-ivs",
        "precheck",
        "canonical",
        "canonical-validated",
        "nonce-budget",
        "precheck-tokens",
    ] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "crypto_module::admission_tests::cbc_runtime_tests::cbc_runtime_child",
                "--nocapture",
            ])
            .env("OPC_CBC_RUNTIME_CASE", case)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "CBC runtime {case}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed; 0 failed")
        );
    }
}

fn canonical_runtime(module: &CountingModule, declared: bool) {
    use crate::canonical::{
        Ikev2CanonicalEmptyReplies as Canonical, Ikev2CanonicalError as CanonicalError,
        Ikev2CanonicalPolicy as Policy,
    };
    for (index, profile) in profiles().enumerate() {
        let policy = if declared {
            Policy::explicitly_allow_declared_validated()
        } else {
            Policy::default()
        };
        Canonical::preflight_cbc(profile, policy).unwrap();
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            let f = Fixture::admitted(profile, direction, 58000 + (index * 2 + role) as u64);
            let mut window = f.window();
            let request = f.request(1, 0);
            if declared {
                assert_eq!(
                    window.enable_empty_replies(Policy::default()),
                    Err(Error::Canonical(CanonicalError::ValidationOptInRequired))
                );
            }
            let before = module.counts.snapshot();
            window.enable_empty_replies(policy).unwrap();
            let after = module.counts.snapshot();
            assert_eq!(
                after[2] - before[2],
                1,
                "derive K_iv once per live capability"
            );
            assert_eq!(after[1], before[1], "capability draws no entropy");
            let before = module.counts.snapshot();
            let packet = window.reply_empty(&request).unwrap().bytes().to_vec();
            let after = module.counts.snapshot();
            assert_eq!(after[2], before[2], "release retains the derived IV key");
            assert_eq!(after[1], before[1], "canonical sealing draws no entropy");
            assert_eq!(
                after[4] - before[4],
                4,
                "two encryptions plus independent IV and traffic decrypt checks"
            );
            assert_eq!(window.reply_empty(&request).unwrap().bytes(), packet);
            assert_eq!(
                module.counts.snapshot(),
                after,
                "cached release executes no crypto"
            );

            let prepared = window
                .prepare_request(
                    profile,
                    &f.keys,
                    Exchange::Informational,
                    PayloadChain::new(PayloadType::Delete, DELETE),
                )
                .unwrap();
            drop(prepared);
            let record = window.record().clone();
            module.reject_prf_support.store(true, Ordering::SeqCst);
            assert_eq!(
                window.reconcile(profile, &f.keys, &record, &f.epoch),
                Err(Error::ReconcileUnavailable)
            );
            module.reject_prf_support.store(false, Ordering::SeqCst);
            window
                .reconcile(profile, &f.keys, &record, &f.epoch)
                .unwrap();
            let before = module.counts.snapshot();
            assert_eq!(window.reply_empty(&request).unwrap().bytes(), packet);
            assert_eq!(
                module.counts.snapshot(),
                before,
                "readback keeps the exact cached bytes and live IV key"
            );

            for capability in [
                CryptoCapability::IkeEncryption,
                CryptoCapability::IkeIntegrity,
                CryptoCapability::IkePrf,
            ] {
                module.set_serviceable(module.capabilities().without(capability));
                assert_eq!(
                    window.reply_empty(&request).unwrap_err(),
                    Error::Canonical(CanonicalError::Unavailable)
                );
                module.set_serviceable(module.capabilities());
                assert_eq!(window.reply_empty(&request).unwrap().bytes(), packet);
            }
            window.delete();

            let f = Fixture::admitted(profile, direction, 59000 + (index * 2 + role) as u64);
            let mut window = f.window();
            window.enable_empty_replies(policy).unwrap();
            let request = f.request(1, 0);
            let next = f.request(2, 0);
            let before = module.counts.snapshot();
            let faults = module.canonical_cbc_iv_faults.load(Ordering::SeqCst);
            module.canonical_cbc_iv_fault.store(true, Ordering::SeqCst);
            for _ in 0..3 {
                assert_eq!(
                    window.reply_empty(&request).unwrap_err(),
                    Error::Canonical(CanonicalError::InvalidOutput)
                );
                assert_eq!(window.next_receive(), Some(1));
            }
            assert_eq!(
                window.reply_empty(&request).unwrap_err(),
                Error::Canonical(CanonicalError::AttemptsExhausted)
            );
            assert_eq!(
                module.canonical_cbc_iv_faults.load(Ordering::SeqCst) - faults,
                3
            );
            module.canonical_cbc_iv_fault.store(false, Ordering::SeqCst);
            assert_eq!(
                window.reply_empty(&request).unwrap_err(),
                Error::Canonical(CanonicalError::AttemptsExhausted)
            );
            let packet = window.reply_empty(&next).unwrap().bytes().to_vec();
            assert_eq!(module.counts.snapshot()[1], before[1]);
            assert_eq!(module.counts.snapshot()[2], before[2]);
            let before = module.counts.snapshot();
            assert_eq!(window.reply_empty(&next).unwrap().bytes(), packet);
            assert_eq!(module.counts.snapshot(), before);
            window.delete();
        }
    }
}

fn ordinary_random_ivs(module: &CountingModule) {
    module.sync_entropy_mode.store(1, Ordering::SeqCst);
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            for (sample, iv_byte) in [0xff, 0, 0xa5, 0xa5].into_iter().enumerate() {
                let f = Fixture::admitted(
                    profile,
                    direction,
                    44000 + (index * 8 + role * 4 + sample) as u64,
                );
                let mut window = f.window();
                module.sync_entropy_byte.store(iv_byte, Ordering::SeqCst);
                let before = module.counts.snapshot();
                let bytes = module.counts.entropy_bytes.load(Ordering::SeqCst);
                let prepared = window
                    .prepare_request(
                        profile,
                        &f.keys,
                        Exchange::Informational,
                        PayloadChain::new(PayloadType::Delete, DELETE),
                    )
                    .unwrap();
                let record = prepared.record().clone();
                let after = module.counts.snapshot();
                assert_eq!(
                    after[1] - before[1],
                    1,
                    "one IV entropy draw, no guard retry"
                );
                assert_eq!(
                    module.counts.entropy_bytes.load(Ordering::SeqCst) - bytes,
                    16
                );
                assert_eq!(after[2], before[2], "ordinary CBC performs no PRF/KDF");
                assert_eq!(after[4] - before[4], 1, "one encrypt, no inverse check");
                assert_eq!(
                    &record.outbound().unwrap().request()[32..48],
                    &[iv_byte; 16]
                );
                drop(prepared);
                window
                    .reconcile(profile, &f.keys, &record, &f.epoch)
                    .unwrap();
                assert_eq!(
                    window.replay_request().unwrap().unwrap().bytes(),
                    record.outbound().unwrap().request()
                );
                assert_eq!(
                    f.restore(&record).record(),
                    &record,
                    "authenticated random IV bytes are never GCM counters"
                );
                let before = module.counts.snapshot();
                let mut restored = f.restore(&record);
                restored
                    .reconcile(profile, &f.keys, &record, &f.epoch)
                    .unwrap();
                assert_eq!(
                    module.counts.snapshot()[1],
                    before[1],
                    "readback/restart draws no entropy"
                );
                assert_eq!(
                    module.counts.snapshot()[2],
                    before[2],
                    "readback derives no IV key"
                );
            }
        }
    }
}

fn sync_random_ivs(module: &CountingModule) {
    for repeated_iv in [false, true] {
        module
            .sync_entropy_mode
            .store(if repeated_iv { 3 } else { 1 }, Ordering::SeqCst);
        for (index, profile) in profiles().enumerate() {
            for (role, direction) in DIRECTIONS.into_iter().enumerate() {
                let f = Fixture::admitted(
                    profile,
                    direction,
                    45000 + (index * 4 + role * 2 + usize::from(repeated_iv)) as u64,
                );
                let mut window = f.synced();
                let policy =
                    Ikev2SyncRecoveryPolicy::new(1, Clock::new(100, 1), 1000, 3, 10).unwrap();
                for (attempt, iv_byte) in [0xff, 0, 0xa5].into_iter().enumerate() {
                    let clock = Clock::new(100 + attempt as u64 * 10, 1);
                    module.sync_entropy_byte.store(iv_byte, Ordering::SeqCst);
                    let before = module.counts.snapshot();
                    let bytes = module.counts.entropy_bytes.load(Ordering::SeqCst);
                    let admitted = if attempt == 0 {
                        window.begin_sync(policy, clock, None).unwrap()
                    } else {
                        window.retry_sync(clock).unwrap()
                    };
                    let prepared = admitted.prepare(profile, &f.keys).unwrap();
                    let record = prepared.record().clone();
                    let after = module.counts.snapshot();
                    assert_eq!(
                        after[1] - before[1],
                        2,
                        "separate nonce and ordinary IV draws"
                    );
                    assert_eq!(
                        module.counts.entropy_bytes.load(Ordering::SeqCst) - bytes,
                        20
                    );
                    assert_eq!(after[2], before[2], "sync derives no canonical IV key");
                    assert_eq!(after[4] - before[4], 1, "one CBC encrypt, no inverse");
                    let commit = prepared.commit_after_durable(&record, clock).unwrap();
                    let Action::SendRequest(request) =
                        window.release_sync_action(commit, clock).unwrap()
                    else {
                        panic!("send");
                    };
                    assert_eq!(
                        &request[32..48],
                        &[if repeated_iv { 0xff } else { iv_byte }; 16]
                    );
                    assert_eq!(
                        record
                            .sync_recovery()
                            .unwrap()
                            .attempts()
                            .last()
                            .unwrap()
                            .pending()
                            .notification()
                            .nonce(),
                        [iv_byte; 4]
                    );
                    window = f.restore(&record);
                    window
                        .reconcile(profile, &f.keys, &record, &f.epoch)
                        .unwrap();
                    assert_eq!(window.ready(), Err(Error::SyncInProgress));
                    assert_eq!(
                        record.sync_recovery().unwrap().attempts().len(),
                        attempt + 1
                    );
                }
                assert_eq!(
                    window.retry_sync(Clock::new(130, 1)).unwrap_err(),
                    Error::SyncClosed
                );
            }
        }
    }
}

fn provider_prechecks(module: &CountingModule) {
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            let f = Fixture::admitted(profile, direction, 46000 + (index * 2 + role) as u64);
            let mut window = f.window();
            let mut negotiation = window.sync_readiness(profile, &f.keys).unwrap().negotiate();
            for capability in [
                CryptoCapability::IkeEncryption,
                CryptoCapability::IkeIntegrity,
                CryptoCapability::ApprovedEntropy,
            ] {
                module.set_serviceable(module.capabilities().without(capability));
                assert_eq!(
                    window.sync_readiness(profile, &f.keys).unwrap_err(),
                    Error::SyncUnavailable
                );
                assert_eq!(negotiation.local_offer(), Err(Error::SyncUnavailable));
                module.set_serviceable(module.capabilities());
            }
            module
                .reject_integrity_support
                .store(true, Ordering::SeqCst);
            assert_eq!(
                window.sync_readiness(profile, &f.keys).unwrap_err(),
                Error::SyncUnavailable
            );
            assert_eq!(negotiation.local_offer(), Err(Error::SyncUnavailable));
            module
                .reject_integrity_support
                .store(false, Ordering::SeqCst);
            assert_eq!(
                negotiation.local_offer().unwrap().is_some(),
                direction == DIRECTIONS[0]
            );
            let prepared = window
                .prepare_request(
                    profile,
                    &f.keys,
                    Exchange::Informational,
                    PayloadChain::new(PayloadType::Delete, DELETE),
                )
                .unwrap();
            let candidate = prepared.record().clone();
            drop(prepared);
            // Deliberately use an unrelated valid epoch while the provider is
            // unavailable: D1 must run before the terminal binding comparison.
            let unrelated =
                Fixture::admitted(profile, direction, 47000 + (index * 2 + role) as u64);
            for refusal in 0..5 {
                match refusal {
                    0 => module.set_serviceable(
                        module
                            .capabilities()
                            .without(CryptoCapability::IkeEncryption),
                    ),
                    1 => module.set_serviceable(
                        module
                            .capabilities()
                            .without(CryptoCapability::IkeIntegrity),
                    ),
                    2 => module
                        .set_serviceable(module.capabilities().without(CryptoCapability::IkePrf)),
                    3 => module
                        .reject_integrity_support
                        .store(true, Ordering::SeqCst),
                    _ => module.reject_prf_support.store(true, Ordering::SeqCst),
                }
                let before = module.counts.snapshot();
                assert_eq!(
                    window.reconcile(profile, &f.keys, &candidate, &unrelated.epoch),
                    Err(Error::ReconcileUnavailable)
                );
                assert_eq!(
                    module.counts.snapshot(),
                    before,
                    "D1 uses no cryptographic operation"
                );
                assert_eq!(window.ready(), Err(Error::CommitUncertain));
                module.set_serviceable(module.capabilities());
                module
                    .reject_integrity_support
                    .store(false, Ordering::SeqCst);
                module.reject_prf_support.store(false, Ordering::SeqCst);
            }
            window
                .reconcile(profile, &f.keys, &candidate, &f.epoch)
                .unwrap();
            assert_eq!(
                window.record(),
                &candidate,
                "retryable checks preserve the exact witness"
            );
            assert_eq!(window.ready(), Ok(()));
            assert_eq!(
                Window::<Cbc>::restore(&f.domain, profile, &f.keys, &candidate, &f.epoch)
                    .unwrap()
                    .record(),
                &candidate
            );
        }
    }
}

fn nonce_budget(module: &CountingModule) {
    module.sync_entropy_mode.store(3, Ordering::SeqCst);
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            let f = Fixture::admitted(profile, direction, 71000 + (index * 2 + role) as u64);
            let mut window = f.synced();
            let clock = Clock::new(100, 1);
            let policy = Ikev2SyncRecoveryPolicy::new(1, clock, 1000, 3, 10).unwrap();
            module.sync_entropy_byte.store(0x55, Ordering::SeqCst);
            let prepared = window
                .begin_sync(policy, clock, None)
                .unwrap()
                .prepare(profile, &f.keys)
                .unwrap();
            let old = prepared.record().clone();
            let token = prepared.commit_after_durable(&old, clock).unwrap();
            assert!(matches!(
                window.release_sync_action(token, clock).unwrap(),
                Action::SendRequest(_)
            ));
            // Restart preserves the nonce history and does not refund an attempt.
            window = f.restore(&old);
            let before = module.counts.snapshot();
            assert_eq!(
                window.retry_sync(Clock::new(109, 1)).unwrap_err(),
                Error::SyncBackoff
            );
            assert_eq!(module.counts.snapshot(), before);
            let entropy = module.counts.entropy_bytes.load(Ordering::SeqCst);
            assert_eq!(
                window
                    .retry_sync(Clock::new(110, 1))
                    .unwrap()
                    .prepare(profile, &f.keys)
                    .unwrap_err(),
                Error::SyncEntropy
            );
            let after = module.counts.snapshot();
            assert_eq!(after[1] - before[1], 4, "bounded nonce-collision redraws");
            assert_eq!(
                module.counts.entropy_bytes.load(Ordering::SeqCst) - entropy,
                16
            );
            assert_eq!(after[4], before[4], "collisions never reach CBC sealing");
            assert_eq!(window.record(), &old);
            assert_eq!(window.ready(), Err(Error::CommitUncertain));
            window.reconcile(profile, &f.keys, &old, &f.epoch).unwrap();
            module.sync_entropy_mode.store(2, Ordering::SeqCst);
            let before = module.counts.snapshot();
            assert_eq!(
                window
                    .retry_sync(Clock::new(110, 1))
                    .unwrap()
                    .prepare(profile, &f.keys)
                    .unwrap_err(),
                Error::SyncEntropy
            );
            assert_eq!(module.counts.snapshot()[1] - before[1], 1);
            assert_eq!(module.counts.snapshot()[4], before[4]);
            window.reconcile(profile, &f.keys, &old, &f.epoch).unwrap();
            module.sync_entropy_mode.store(3, Ordering::SeqCst);
            module.sync_entropy_byte.store(0xaa, Ordering::SeqCst);
            let prepared = window
                .retry_sync(Clock::new(110, 1))
                .unwrap()
                .prepare(profile, &f.keys)
                .unwrap();
            let retry = prepared.record().clone();
            assert_eq!(retry.sync_recovery().unwrap().attempts().len(), 2);
            let old_proposal = old
                .sync_recovery()
                .unwrap()
                .pending()
                .unwrap()
                .notification();
            let proposal = retry
                .sync_recovery()
                .unwrap()
                .pending()
                .unwrap()
                .notification();
            assert!(
                proposal.expected_send_req_message_id()
                    > old_proposal.expected_send_req_message_id()
            );
            assert_eq!(proposal.nonce(), [0xaa; 4]);
            let token = prepared
                .commit_after_durable(&retry, Clock::new(110, 1))
                .unwrap();
            assert!(matches!(
                window
                    .release_sync_action(token, Clock::new(110, 1))
                    .unwrap(),
                Action::SendRequest(_)
            ));
            window.delete();
        }
    }
}

fn precheck_tokens(module: &CountingModule) {
    use crate::canonical::Ikev2CanonicalPolicy;
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            for landed in [false, true] {
                let f = Fixture::admitted(
                    profile,
                    direction,
                    72000 + (index * 4 + role * 2 + usize::from(landed)) as u64,
                );
                let mut window = f.window();
                window
                    .enable_empty_replies(Ikev2CanonicalPolicy::default())
                    .unwrap();
                let request = f.request(1, 0);
                let cached = window.reply_empty(&request).unwrap().bytes().to_vec();
                let prepared = window
                    .prepare_request(
                        profile,
                        &f.keys,
                        Exchange::Informational,
                        PayloadChain::new(PayloadType::Delete, DELETE),
                    )
                    .unwrap();
                let old = prepared.record().clone();
                let token = prepared.commit_after_durable(&old).unwrap();
                let response =
                    f.peer_packet(1, true, PayloadChain::new(PayloadType::NoNext, &[]), 0);
                let opened = window.open_peer(profile, &f.keys, &response).unwrap();
                let prepared = window
                    .prepare_completion(&opened, bytes::Bytes::from_static(b"outcome"))
                    .unwrap();
                let candidate = prepared.record().clone();
                drop(prepared);
                let readback = if landed { &candidate } else { &old };
                module.reject_prf_support.store(true, Ordering::SeqCst);
                assert_eq!(
                    window.reconcile(profile, &f.keys, readback, &f.epoch),
                    Err(Error::ReconcileUnavailable)
                );
                module.reject_prf_support.store(false, Ordering::SeqCst);
                window
                    .reconcile(profile, &f.keys, readback, &f.epoch)
                    .unwrap();
                assert_eq!(window.apply_committed(token), Err(Error::StaleCompletion));
                assert_eq!(window.record(), readback);
                let before = module.counts.snapshot();
                assert_eq!(window.reply_empty(&request).unwrap().bytes(), cached);
                assert_eq!(
                    module.counts.snapshot(),
                    before,
                    "retry retains both cache and IV key"
                );
                window.delete();
            }
        }
    }
}

#[test]
fn cbc_runtime_child() {
    let Ok(case) = std::env::var("OPC_CBC_RUNTIME_CASE") else {
        return;
    };
    let module = Arc::new(CountingModule::new());
    module
        .drift_validation
        .store(case == "canonical-validated", Ordering::SeqCst);
    let requirements = Ikev2CryptoRequirements::all_software_supported();
    let _report = block_on(install_ikev2_crypto_module(
        module.clone(),
        policy(&requirements),
        requirements,
    ))
    .unwrap();
    match case.as_str() {
        "ordinary-ivs" => ordinary_random_ivs(&module),
        "sync-ivs" => sync_random_ivs(&module),
        "precheck" => provider_prechecks(&module),
        "nonce-budget" => nonce_budget(&module),
        "precheck-tokens" => precheck_tokens(&module),
        "canonical" | "canonical-validated" => {
            canonical_runtime(&module, case == "canonical-validated")
        }
        _ => panic!("unknown CBC runtime case"),
    }
}
