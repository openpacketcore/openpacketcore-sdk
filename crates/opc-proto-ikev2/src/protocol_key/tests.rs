#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    cell::RefCell,
    future::{pending, Future},
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};

use super::*;
use crate::{
    derive_ike_sa_init_key_material, test_support::ensure_ike_crypto, Ikev2DhGroup,
    Ikev2EncryptionAlgorithm, Ikev2PrfAlgorithm,
};

thread_local! {
    pub(super) static ZEROIZE_AUDIT: RefCell<Option<Arc<ZeroizeAudit>>> = const { RefCell::new(None) };
}

#[derive(Default)]
pub(super) struct ZeroizeAudit {
    drops: AtomicUsize,
    nonzero: AtomicUsize,
}

impl ZeroizeAudit {
    pub(super) fn observe(&self, bytes: &[u8]) {
        self.drops.fetch_add(1, Ordering::SeqCst);
        self.nonzero.fetch_add(
            usize::from(bytes.iter().any(|byte| *byte != 0)),
            Ordering::SeqCst,
        );
    }

    fn assert_cleared(&self, count: usize) {
        assert_eq!(self.drops.load(Ordering::SeqCst), count);
        assert_eq!(self.nonzero.load(Ordering::SeqCst), 0);
    }
}

fn audit() -> Arc<ZeroizeAudit> {
    let audit = Arc::new(ZeroizeAudit::default());
    ZEROIZE_AUDIT.with(|slot| *slot.borrow_mut() = Some(Arc::clone(&audit)));
    audit
}

fn id(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).unwrap()
}

fn profile() -> Ikev2SaInitCryptoProfile {
    Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_256,
    )
    .unwrap()
}

fn pending_key() -> (
    Ikev2ProtocolKeyAssociation,
    Ikev2ProtocolKeyOperation,
    Ikev2ProtocolKeyHandle,
) {
    ensure_ike_crypto();
    let association = Ikev2ProtocolKeyAssociation::new(id(1));
    let operation = association.begin_ike_auth(id(1), id(1), profile()).unwrap();
    let key = operation
        .import(
            Ikev2ProtocolKeyPurpose::N3iwfMsk,
            Zeroizing::new(vec![0x5a; 32]),
        )
        .unwrap();
    (association, operation, key)
}

fn material() -> Ikev2SaInitKeyMaterial {
    ensure_ike_crypto();
    derive_ike_sa_init_key_material(
        profile(),
        [1; 8],
        [2; 8],
        &[3; 32],
        &[4; 32],
        &[5; 32],
        None,
    )
    .unwrap()
}

fn inputs(peer: Ikev2IkeAuthPeer) -> Ikev2IkeAuthSignedOctets<'static> {
    Ikev2IkeAuthSignedOctets {
        peer,
        ike_sa_init_message: &[0x11; 28],
        peer_nonce: &[0x22; 32],
        identity_payload_body: &[1, 0, 0, 0, 192, 0, 2, 1],
    }
}

fn consume(
    key: &Ikev2ProtocolKeyHandle,
    operation: &Ikev2ProtocolKeyOperation,
) -> Result<Ikev2ProtocolKeyAuth, Ikev2ProtocolKeyError> {
    key.consume_ike_auth(
        operation,
        &material(),
        inputs(Ikev2IkeAuthPeer::Initiator),
        inputs(Ikev2IkeAuthPeer::Responder),
        136,
    )
}

#[test]
fn retirement_zeroizes_before_releasing_each_owned_buffer() {
    for cause in 0..6 {
        let audit = audit();
        let (association, operation, key) = pending_key();
        match cause {
            0 => drop(key),
            1 => drop(operation),
            2 => drop(association),
            3 => operation.cancel(),
            4 => association.release(),
            5 => association.replace_generation(id(1), id(2)).unwrap(),
            _ => unreachable!(),
        }
        audit.assert_cleared(1);
    }
}

#[test]
fn invalid_import_zeroizes_and_retires_its_attempt() {
    ensure_ike_crypto();
    for length in [0, 1, 31, 33, 64, 4096] {
        let audit = audit();
        let association = Ikev2ProtocolKeyAssociation::new(id(1));
        let operation = association.begin_ike_auth(id(1), id(1), profile()).unwrap();
        assert_eq!(
            operation
                .import(
                    Ikev2ProtocolKeyPurpose::N3iwfMsk,
                    Zeroizing::new(vec![0xaa; length])
                )
                .unwrap_err(),
            Ikev2ProtocolKeyError::InvalidKeyLength
        );
        audit.assert_cleared(1);
        assert_eq!(
            operation
                .import(
                    Ikev2ProtocolKeyPurpose::N3iwfMsk,
                    Zeroizing::new(vec![0xaa; 32])
                )
                .unwrap_err(),
            Ikev2ProtocolKeyError::Retired
        );
        audit.assert_cleared(2);
    }
    let audit = audit();
    let association = Ikev2ProtocolKeyAssociation::new(id(1));
    let operation = association.begin_ike_auth(id(1), id(1), profile()).unwrap();
    assert_eq!(
        operation
            .import(
                Ikev2ProtocolKeyPurpose::Unsupported,
                Zeroizing::new(vec![0x5a; 32])
            )
            .unwrap_err(),
        Ikev2ProtocolKeyError::UnsupportedPurpose
    );
    audit.assert_cleared(1);
    assert_eq!(
        operation
            .import(
                Ikev2ProtocolKeyPurpose::N3iwfMsk,
                Zeroizing::new(vec![0x5a; 32])
            )
            .unwrap_err(),
        Ikev2ProtocolKeyError::Retired
    );
    audit.assert_cleared(2);
}

#[test]
fn duplicate_import_cannot_replace_first_key() {
    let audit = audit();
    let (_association, operation, key) = pending_key();
    assert_eq!(
        operation
            .import(
                Ikev2ProtocolKeyPurpose::N3iwfMsk,
                Zeroizing::new(vec![0xaa; 32])
            )
            .unwrap_err(),
        Ikev2ProtocolKeyError::Retired
    );
    audit.assert_cleared(1);
    let auth = consume(&key, &operation).unwrap();
    let expected = compute_ike_auth_shared_key_mic(
        profile(),
        &material(),
        inputs(Ikev2IkeAuthPeer::Initiator),
        &[0x5a; 32],
    )
    .unwrap();
    assert!(auth.authentication_data(Ikev2IkeAuthPeer::Initiator) == expected);
    audit.assert_cleared(2);
}

#[test]
fn numeric_ids_never_authorize_another_association() {
    let audit = audit();
    let (_first, first_op, first_key) = pending_key();
    let (_second, second_op, second_key) = pending_key();
    assert_eq!(
        consume(&first_key, &second_op).unwrap_err(),
        Ikev2ProtocolKeyError::OperationMismatch
    );
    assert_eq!(
        consume(&second_key, &first_op).unwrap_err(),
        Ikev2ProtocolKeyError::OperationMismatch
    );
    audit.assert_cleared(0);
    consume(&first_key, &first_op).unwrap();
    consume(&second_key, &second_op).unwrap();
    audit.assert_cleared(2);
}

#[test]
fn replacement_retires_stale_guards_without_touching_new_custody() {
    let audit = audit();
    let (association, old_op, old_key) = pending_key();
    association.replace_generation(id(1), id(2)).unwrap();
    audit.assert_cleared(1);
    assert_eq!(
        consume(&old_key, &old_op).unwrap_err(),
        Ikev2ProtocolKeyError::GenerationMismatch
    );
    let new_op = association.begin_ike_auth(id(2), id(1), profile()).unwrap();
    let new_key = new_op
        .import(
            Ikev2ProtocolKeyPurpose::N3iwfMsk,
            Zeroizing::new(vec![0x33; 32]),
        )
        .unwrap();
    assert_eq!(
        consume(&old_key, &new_op).unwrap_err(),
        Ikev2ProtocolKeyError::OperationMismatch
    );
    drop(old_op);
    drop(old_key);
    audit.assert_cleared(1);
    consume(&new_key, &new_op).unwrap();
    audit.assert_cleared(2);
}

#[test]
fn cancelled_operation_cannot_retire_its_successor() {
    let audit = audit();
    let (association, old_op, old_key) = pending_key();
    old_op.cancel();
    let new_op = association.begin_ike_auth(id(1), id(2), profile()).unwrap();
    let new_key = new_op
        .import(
            Ikev2ProtocolKeyPurpose::N3iwfMsk,
            Zeroizing::new(vec![0x33; 32]),
        )
        .unwrap();
    assert_eq!(
        consume(&old_key, &old_op).unwrap_err(),
        Ikev2ProtocolKeyError::Retired
    );
    assert_eq!(
        consume(&new_key, &old_op).unwrap_err(),
        Ikev2ProtocolKeyError::OperationMismatch
    );
    drop(old_key);
    drop(old_op);
    audit.assert_cleared(1);
    consume(&new_key, &new_op).unwrap();
    audit.assert_cleared(2);
}

#[test]
fn generation_and_operation_labels_fail_closed_at_boundaries() {
    let (association, operation, key) = pending_key();
    assert_eq!(
        association
            .begin_ike_auth(id(2), id(2), profile())
            .unwrap_err(),
        Ikev2ProtocolKeyError::GenerationMismatch
    );
    assert_eq!(
        association
            .begin_ike_auth(id(1), id(2), profile())
            .unwrap_err(),
        Ikev2ProtocolKeyError::OperationPending
    );
    for (expected, replacement) in [(2, 3), (1, 1)] {
        assert_eq!(
            association.replace_generation(id(expected), id(replacement)),
            Err(Ikev2ProtocolKeyError::GenerationMismatch)
        );
    }
    consume(&key, &operation).unwrap();
    operation.cancel();
    assert_eq!(
        association
            .begin_ike_auth(id(1), id(1), profile())
            .unwrap_err(),
        Ikev2ProtocolKeyError::OperationReused
    );
    let last = association
        .begin_ike_auth(id(1), id(u64::MAX), profile())
        .unwrap();
    drop(last);
    assert_eq!(
        association
            .begin_ike_auth(id(1), id(u64::MAX), profile())
            .unwrap_err(),
        Ikev2ProtocolKeyError::OperationReused
    );
    association.replace_generation(id(1), id(u64::MAX)).unwrap();
    assert_eq!(
        association.replace_generation(id(u64::MAX), id(1)),
        Err(Ikev2ProtocolKeyError::GenerationMismatch)
    );
    association.release();
    association.release();
    assert_eq!(
        association
            .begin_ike_auth(id(u64::MAX), id(1), profile())
            .unwrap_err(),
        Ikev2ProtocolKeyError::Released
    );
    assert_eq!(
        association.replace_generation(id(1), id(2)),
        Err(Ikev2ProtocolKeyError::Released)
    );
}

#[test]
fn one_consumption_zeroizes_and_reuse_cannot_recompute() {
    let audit = audit();
    let (_association, operation, key) = pending_key();
    consume(&key, &operation).unwrap();
    audit.assert_cleared(1);
    assert_eq!(
        consume(&key, &operation).unwrap_err(),
        Ikev2ProtocolKeyError::Retired
    );
    audit.assert_cleared(1);
    assert_eq!(
        operation
            .import(
                Ikev2ProtocolKeyPurpose::N3iwfMsk,
                Zeroizing::new(vec![0xaa; 32])
            )
            .unwrap_err(),
        Ikev2ProtocolKeyError::Retired
    );
    audit.assert_cleared(2);
}

#[test]
fn bound_profile_rejects_wrong_sk_width_before_auth() {
    let audit = audit();
    let (_association, operation, key) = pending_key();
    let wrong_profile = Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_512,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_256,
    )
    .unwrap();
    let wrong_material = derive_ike_sa_init_key_material(
        wrong_profile,
        [1; 8],
        [2; 8],
        &[3; 32],
        &[4; 32],
        &[5; 32],
        None,
    )
    .unwrap();
    assert_eq!(
        key.consume_ike_auth(
            &operation,
            &wrong_material,
            inputs(Ikev2IkeAuthPeer::Initiator),
            inputs(Ikev2IkeAuthPeer::Responder),
            136
        )
        .unwrap_err(),
        Ikev2ProtocolKeyError::InvalidAuthInputs
    );
    audit.assert_cleared(1);
}

#[test]
fn simultaneous_consumers_have_exactly_one_winner() {
    let audit = audit();
    let (_association, operation, key) = pending_key();
    let material = material();
    let start = std::sync::Barrier::new(8);
    let results = std::thread::scope(|scope| {
        (0..8)
            .map(|_| {
                scope.spawn(|| {
                    start.wait();
                    key.consume_ike_auth(
                        &operation,
                        &material,
                        inputs(Ikev2IkeAuthPeer::Initiator),
                        inputs(Ikev2IkeAuthPeer::Responder),
                        136,
                    )
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(Ikev2ProtocolKeyError::Retired)))
            .count(),
        7
    );
    audit.assert_cleared(1);
}

#[test]
fn malformed_and_over_budget_consumptions_retire_without_output() {
    for case in 0..6 {
        let audit = audit();
        let (_association, operation, key) = pending_key();
        let mut initiator = inputs(Ikev2IkeAuthPeer::Initiator);
        let mut responder = inputs(Ikev2IkeAuthPeer::Responder);
        let mut cap = 136;
        match case {
            0 => cap = 135,
            1 => initiator.peer = Ikev2IkeAuthPeer::Responder,
            2 => responder.peer = Ikev2IkeAuthPeer::Initiator,
            3 => initiator.peer_nonce = &[],
            4 => responder.ike_sa_init_message = &[],
            5 => responder.identity_payload_body = &[0, 0, 0, 0, 1],
            _ => unreachable!(),
        }
        let error = key
            .consume_ike_auth(&operation, &material(), initiator, responder, cap)
            .unwrap_err();
        assert_eq!(
            error,
            if case == 0 {
                Ikev2ProtocolKeyError::InputLimit
            } else {
                Ikev2ProtocolKeyError::InvalidAuthInputs
            }
        );
        audit.assert_cleared(1);
        assert_eq!(
            consume(&key, &operation).unwrap_err(),
            Ikev2ProtocolKeyError::Retired
        );
    }
}

#[test]
fn cancelled_future_owning_operation_drops_custody() {
    let audit = audit();
    let (_association, operation, key) = pending_key();
    let mut future = Box::pin(async move {
        let _owned_guard = operation;
        pending::<()>().await;
    });
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    drop(future);
    audit.assert_cleared(1);
    assert!(lock(&key.state).unwrap().pending.is_none());
}

#[test]
fn poisoned_slot_is_cleared_and_cannot_resume() {
    let audit = audit();
    let (association, operation, key) = pending_key();
    let state = Arc::clone(&association.state);
    let result = std::thread::spawn(move || {
        let _guard = state.lock().unwrap();
        panic!("synthetic custody poison");
    })
    .join();
    assert!(result.is_err());
    assert_eq!(
        consume(&key, &operation).unwrap_err(),
        Ikev2ProtocolKeyError::Unavailable
    );
    audit.assert_cleared(1);
    assert_eq!(
        association
            .begin_ike_auth(id(1), id(2), profile())
            .unwrap_err(),
        Ikev2ProtocolKeyError::Unavailable
    );
    drop(association);
    audit.assert_cleared(1);
}

#[test]
fn debug_and_auth_comparison_are_bounded_and_redacted() {
    let (association, operation, key) = pending_key();
    let auth = consume(&key, &operation).unwrap();
    for (value, name) in [
        (
            &association as &dyn fmt::Debug,
            "Ikev2ProtocolKeyAssociation",
        ),
        (&operation, "Ikev2ProtocolKeyOperation"),
        (&key, "Ikev2ProtocolKeyHandle"),
        (&auth, "Ikev2ProtocolKeyAuth"),
    ] {
        assert_eq!(format!("{value:?}"), format!("{name}(<redacted>)"));
        assert_eq!(format!("{value:#?}"), format!("{name}(<redacted>)"));
    }
    for peer in [Ikev2IkeAuthPeer::Initiator, Ikev2IkeAuthPeer::Responder] {
        let data = auth.authentication_data(peer);
        assert_eq!(
            auth.verify(
                peer,
                &Ikev2AuthenticationPayload {
                    auth_method: 2,
                    auth_data: data
                }
            ),
            Ok(())
        );
        for method in [0, 1, 3, 255] {
            assert_eq!(
                auth.verify(
                    peer,
                    &Ikev2AuthenticationPayload {
                        auth_method: method,
                        auth_data: data
                    }
                ),
                Err(Ikev2ProtocolKeyError::AuthenticationFailed)
            );
        }
        for length in [0, 1, 31, 33, 64] {
            assert_eq!(
                auth.verify(
                    peer,
                    &Ikev2AuthenticationPayload {
                        auth_method: 2,
                        auth_data: &vec![0; length]
                    }
                ),
                Err(Ikev2ProtocolKeyError::AuthenticationFailed)
            );
        }
        for bit in 0..256 {
            let mut changed = data.to_vec();
            changed[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                auth.verify(
                    peer,
                    &Ikev2AuthenticationPayload {
                        auth_method: 2,
                        auth_data: &changed
                    }
                ),
                Err(Ikev2ProtocolKeyError::AuthenticationFailed)
            );
        }
    }
}
