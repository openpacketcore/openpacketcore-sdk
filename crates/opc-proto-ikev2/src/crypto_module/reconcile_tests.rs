//! Deterministic provider faults and actual key/nonce monitoring around readback.

use super::{canonical_fixtures, CountingModule, CryptoCapability, Ordering};
use crate::{
    canonical::{Ikev2CanonicalError as CanonicalError, Ikev2CanonicalPolicy as Policy},
    recovery::{
        Ikev2CommittedWindow as Window, Ikev2CommittedWindowRecord as Record,
        Ikev2SyncClock as Clock, Ikev2SyncDisposition as Disposition,
        Ikev2SyncInitiatorAction as Action, Ikev2SyncRecoveryPolicy as RecoveryPolicy,
        Ikev2SyncResponderRecord as SyncRecord, Ikev2WindowError as Error,
    },
    Ikev2AesGcmIvPurpose as Purpose, Ikev2ExchangeKind as Exchange,
    Ikev2MessageIdSyncAgreement as Agreement, Ikev2MessageIdSyncMode as Mode,
    Ikev2MessageIdSyncRole as Role, Ikev2MessageIdSyncSa as Sa, PayloadChain, PayloadType,
};
use bytes::Bytes;
use canonical_fixtures::{delete, empty, Fixture, ALGORITHMS, DIRECTIONS};

fn snapshot(module: &CountingModule) -> (usize, usize, usize) {
    (
        module.canonical_seals.load(Ordering::SeqCst),
        module.observed_aead.lock().unwrap().len(),
        module.counts.entropy.load(Ordering::SeqCst),
    )
}

fn readback(module: &CountingModule, f: &Fixture, window: &mut Window, record: &Record) {
    let before = snapshot(module);
    window.reconcile(f.profile, &f.keys, record, &f.iv).unwrap();
    assert_eq!(
        snapshot(module),
        before,
        "readback must neither seal nor draw entropy"
    );
}

fn cached(module: &CountingModule, f: &Fixture, window: &mut Window, id: u32, bytes: &[u8]) {
    let request = f.request(id);
    let before = snapshot(module);
    assert_eq!(window.reply_empty(&request).unwrap().bytes(), bytes);
    assert_eq!(
        snapshot(module),
        before,
        "a readback retransmission must add zero seals"
    );
}

pub(super) fn provider_failures(module: &CountingModule) {
    for (algorithm, encryption) in ALGORITHMS.into_iter().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            // A provider pre-check must precede even invalid record validation;
            // retry retains the cache and fences tokens at the same generation.
            let mut f = Fixture::new(
                32_100 + (algorithm * 2 + role) as u64,
                encryption,
                direction,
            );
            f.window.enable_empty_replies(Policy::default()).unwrap();
            let request = f.request(0);
            let bytes = f.window.reply_empty(&request).unwrap().bytes().to_vec();
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
            let record = prepared.record().clone();
            let token = prepared.commit_after_durable(&record).unwrap();
            module.set_serviceable(
                module
                    .capabilities()
                    .without(CryptoCapability::IkeEncryption),
            );
            let changed = f.stored(None, 64);
            assert_eq!(
                f.window.reconcile(f.profile, &f.keys, &record, &changed),
                Err(Error::ReconcileUnavailable)
            );
            assert_eq!(f.window.next_receive(), Some(1));
            assert_eq!(f.window.ready(), Err(Error::CommitUncertain));
            module.set_serviceable(module.capabilities());
            f.window
                .reconcile(f.profile, &f.keys, &record, &f.iv)
                .unwrap();
            assert_eq!(f.window.apply_committed(token), Err(Error::StaleCompletion));
            let before = snapshot(module);
            assert_eq!(f.window.reply_empty(&request).unwrap().bytes(), bytes);
            assert_eq!(snapshot(module), before);
            f.window.delete();

            // Readback must not refund withheld attempts under any GCM size/role.
            let mut f = Fixture::new(
                32_700 + (algorithm * 2 + role) as u64,
                encryption,
                direction,
            );
            f.window.enable_empty_replies(Policy::default()).unwrap();
            let request = f.request(0);
            let before = module.canonical_seals.load(Ordering::SeqCst);
            module.canonical_fault.store(1, Ordering::SeqCst);
            module.canonical_failures.store(3, Ordering::SeqCst);
            let record = f.window.record().clone();
            for _ in 0..3 {
                assert_eq!(
                    f.window.reply_empty(&request).unwrap_err(),
                    Error::Canonical(CanonicalError::InvalidOutput)
                );
                f.window
                    .reconcile(f.profile, &f.keys, &record, &f.iv)
                    .unwrap();
            }
            assert_eq!(
                f.window.reply_empty(&request).unwrap_err(),
                Error::Canonical(CanonicalError::AttemptsExhausted)
            );
            assert_eq!(module.canonical_seals.load(Ordering::SeqCst), before + 3);
            module.canonical_fault.store(0, Ordering::SeqCst);
            f.window.delete();

            // The one private witness survives a retryable failure, too.
            let mut f = Fixture::new(
                32_200 + (algorithm * 2 + role) as u64,
                encryption,
                direction,
            );
            f.window.enable_empty_replies(Policy::default()).unwrap();
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
            let candidate = prepared.record().clone();
            drop(prepared);
            module.set_serviceable(
                module
                    .capabilities()
                    .without(CryptoCapability::IkeEncryption),
            );
            assert_eq!(
                f.window.reconcile(f.profile, &f.keys, &candidate, &f.iv),
                Err(Error::ReconcileUnavailable)
            );
            module.set_serviceable(module.capabilities());
            f.window
                .reconcile(f.profile, &f.keys, &candidate, &f.iv)
                .unwrap();
            assert_eq!(f.window.record(), &candidate);
            f.window.delete();

            // Revoke on the successful pre-check, after acquisition. Retirement
            // must observe it before any landed state is published.
            let mut f = Fixture::new(
                32_300 + (algorithm * 2 + role) as u64,
                encryption,
                direction,
            );
            f.window.enable_empty_replies(Policy::default()).unwrap();
            let request = f.request(0);
            drop(f.window.reply_empty(&request).unwrap());
            let old = f.window.record().clone();
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
            let candidate = prepared.record().clone();
            drop(prepared);
            let competing = Window::restore(old.domain(), f.profile, &f.keys, &old, &f.iv).unwrap();
            *module.revoke_on_readiness.lock().unwrap() = Some((f.iv.clone(), competing));
            assert_eq!(
                f.window.reconcile(f.profile, &f.keys, &candidate, &f.iv),
                Err(Error::Canonical(CanonicalError::Invalidated))
            );
            assert_eq!(f.window.record(), &old);
            assert_eq!(f.window.next_receive(), Some(1));
            assert!(f.window.is_reconstructing());
            assert_eq!(f.window.ready(), Err(Error::CommitUncertain));
            assert_eq!(
                f.window.enable_empty_replies(Policy::default()),
                Err(Error::Canonical(CanonicalError::Invalidated))
            );
            assert!(f.window.reconcile(f.profile, &f.keys, &old, &f.iv).is_err());
            f.window.delete();

            // A provider withdrawal after the successful pre-check is terminal:
            // ordinary packet opening cannot classify its cause more finely.
            let mut f = Fixture::new(
                32_400 + (algorithm * 2 + role) as u64,
                encryption,
                direction,
            );
            f.window.enable_empty_replies(Policy::default()).unwrap();
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
            let old = prepared.record().clone();
            let _token = prepared.commit_after_durable(&old).unwrap();
            module.readiness_reads.store(0, Ordering::SeqCst);
            module
                .withdraw_extra_after_first_readiness
                .store(true, Ordering::SeqCst);
            assert_eq!(
                f.window.reconcile(f.profile, &f.keys, &old, &f.iv),
                Err(Error::InvalidRecord)
            );
            module
                .withdraw_extra_after_first_readiness
                .store(false, Ordering::SeqCst);
            module.set_serviceable(module.capabilities());
            assert!(f.window.reconcile(f.profile, &f.keys, &old, &f.iv).is_err());
            assert_eq!(
                f.window.enable_empty_replies(Policy::default()),
                Err(Error::Canonical(CanonicalError::Invalidated))
            );
            f.window.delete();

            // A poisoned ledger cannot turn unchanged readback into readiness.
            let mut f = Fixture::new(
                32_500 + (algorithm * 2 + role) as u64,
                encryption,
                direction,
            );
            f.window.enable_empty_replies(Policy::default()).unwrap();
            let request = f.request(0);
            module.canonical_fault.store(7, Ordering::SeqCst);
            module.canonical_failures.store(1, Ordering::SeqCst);
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                drop(f.window.reply_empty(&request));
            }))
            .is_err());
            module.canonical_fault.store(0, Ordering::SeqCst);
            let old = f.window.record().clone();
            assert_eq!(
                f.window.reconcile(f.profile, &f.keys, &old, &f.iv),
                Err(Error::Canonical(CanonicalError::Unavailable))
            );
            assert_eq!(f.window.next_receive(), Some(0));
            assert_eq!(f.window.ready(), Err(Error::CommitUncertain));
            f.window.delete();
        }
    }
}

fn sync_wire(f: &Fixture, reply: bool, nonce: [u8; 4], send: u32, receive: u32, iv: u64) -> Bytes {
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
        iv,
    )
}

pub(super) fn monitor(module: &CountingModule) {
    module.monitor_aead.store(true, Ordering::SeqCst);
    for (algorithm, encryption) in ALGORITHMS.into_iter().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            let mut f = Fixture::new(
                32_600 + (algorithm * 2 + role) as u64,
                encryption,
                direction,
            );
            let initial = f
                .window
                .record()
                .clone()
                .with_sync_state(
                    SyncRecord::from_persisted(
                        Agreement::from_persisted(
                            Sa::new(
                                f.spis.0,
                                f.spis.1,
                                if direction == DIRECTIONS[0] {
                                    Role::Initiator
                                } else {
                                    Role::Responder
                                },
                            )
                            .unwrap(),
                            Mode::Negotiated,
                        ),
                        None,
                        None,
                        None,
                        None,
                        Disposition::Continue,
                        0,
                    )
                    .unwrap(),
                )
                .unwrap();
            let mut window =
                Window::restore(initial.domain(), f.profile, &f.keys, &initial, &f.iv).unwrap();
            window.enable_empty_replies(Policy::default()).unwrap();
            let bytes = window.reply_empty(&f.request(0)).unwrap().bytes().to_vec();
            readback(module, &f, &mut window, &initial);
            cached(module, &f, &mut window, 0, &bytes);

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
            drop(prepared);
            readback(module, &f, &mut window, &record);
            cached(module, &f, &mut window, 0, &bytes);

            let response = f.peer(0, true, 37, empty(), 0, 0x7000);
            let response = window.open_peer(f.profile, &f.keys, &response).unwrap();
            let prepared = window.prepare_completion(&response, Bytes::new()).unwrap();
            let record = prepared.record().clone();
            drop(prepared);
            readback(module, &f, &mut window, &record);
            cached(module, &f, &mut window, 0, &bytes);

            let request = f.peer(1, false, 37, delete(), 0, 0x7001);
            let request = window.open_peer(f.profile, &f.keys, &request).unwrap();
            let prepared = window
                .prepare_response(
                    f.profile,
                    &f.keys,
                    f.allocator.allocate(Purpose::Ordinary).unwrap(),
                    &request,
                    empty(),
                    Bytes::new(),
                )
                .unwrap();
            let record = prepared.record().clone();
            drop(prepared);
            readback(module, &f, &mut window, &record);
            let bytes = window.reply_empty(&f.request(2)).unwrap().bytes().to_vec();
            readback(module, &f, &mut window, &record);
            cached(module, &f, &mut window, 2, &bytes);

            let wire = sync_wire(&f, false, [1, 2, 3, 4], 10, 1, 0x7002);
            let prepared = window
                .begin_sync_response(f.profile, &f.keys, &wire, None, None)
                .unwrap()
                .prepare(
                    f.profile,
                    &f.keys,
                    f.allocator.allocate(Purpose::Ordinary).unwrap(),
                )
                .unwrap();
            let record = prepared.record().clone();
            drop(prepared);
            readback(module, &f, &mut window, &record);
            let bytes = window.reply_empty(&f.request(10)).unwrap().bytes().to_vec();
            readback(module, &f, &mut window, &record);
            cached(module, &f, &mut window, 10, &bytes);

            let policy = RecoveryPolicy::new(1, Clock::new(100, 7), 200, 3, 10).unwrap();
            let prepared = window
                .begin_sync(policy, Clock::new(100, 7), None)
                .unwrap()
                .prepare(
                    f.profile,
                    &f.keys,
                    f.allocator.allocate(Purpose::Ordinary).unwrap(),
                )
                .unwrap();
            let record = prepared.record().clone();
            drop(prepared);
            readback(module, &f, &mut window, &record);
            assert_eq!(window.ready(), Err(Error::SyncInProgress));
            let prepared = window
                .retry_sync(Clock::new(110, 7))
                .unwrap()
                .prepare(
                    f.profile,
                    &f.keys,
                    f.allocator.allocate(Purpose::Ordinary).unwrap(),
                )
                .unwrap();
            let record = prepared.record().clone();
            let token = prepared
                .commit_after_durable(&record, Clock::new(110, 7))
                .unwrap();
            assert!(matches!(
                window
                    .release_sync_action(token, Clock::new(110, 7))
                    .unwrap(),
                Action::SendRequest(_)
            ));
            let nonce = record
                .sync_recovery()
                .unwrap()
                .pending()
                .unwrap()
                .notification()
                .nonce();
            let wire = sync_wire(&f, true, nonce, 12, 12, 0x7003);
            let prepared = window
                .complete_sync(f.profile, &f.keys, &wire, Clock::new(111, 7))
                .unwrap();
            let record = prepared.record().clone();
            drop(prepared);
            readback(module, &f, &mut window, &record);
            let bytes = window.reply_empty(&f.request(12)).unwrap().bytes().to_vec();
            readback(module, &f, &mut window, &record);
            cached(module, &f, &mut window, 12, &bytes);

            let policy = RecoveryPolicy::new(2, Clock::new(200, 7), 300, 3, 10).unwrap();
            assert_eq!(
                window
                    .begin_sync(policy, Clock::new(300, 7), None)
                    .unwrap_err(),
                Error::SyncClosed
            );
            let prepared = window.close_sync().unwrap();
            let record = prepared.record().clone();
            drop(prepared);
            readback(module, &f, &mut window, &record);
            assert_eq!(window.ready(), Err(Error::SyncClosed));
            // Five ordinary allocations above; none was added by readback.
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
                &5_u64.to_be_bytes()
            );
            drop(prepared);
            window.delete();
        }
    }
}
