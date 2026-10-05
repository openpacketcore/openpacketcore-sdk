use super::support::*;
use opc_crypto::{
    encrypt_attested_envelope_with_handle_and_nonce,
    encrypt_bounded_config_envelope_with_handle_and_nonce,
    encrypt_reserved_bounded_config_envelope, ConfigPreparationPool, CryptoError,
};
use opc_key::{KeyHandle, KeyId, KeyPurpose, Zeroizing};
use opc_persist::{AttestedConfigCommit, ConfirmedCommitResolution};
use opc_types::{TenantId, Timestamp, TxId};
use std::sync::Arc;

#[test]
fn existing_public_types_preserve_all_auto_traits() {
    fn assert_traits<
        T: Send + Sync + Unpin + std::panic::UnwindSafe + std::panic::RefUnwindSafe,
    >() {
    }
    assert_traits::<opc_crypto::AuthenticatedEnvelope>();
    assert_traits::<opc_crypto::AuthenticatedEnvelopeClaim>();
    assert_traits::<AttestedConfigCommit>();
}

#[tokio::test]
async fn exact_record_retains_evidence_and_claim_lease() {
    let pool = ConfigPreparationPool::bounded_v1();
    let foreign = ConfigPreparationPool::bounded_v1();
    let _seven = reserve(&pool, 7);
    let provider = Provider::new(Mode::Ready);
    let envelope = encrypt_reserved_bounded_config_envelope(
        pool.try_reserve().unwrap(),
        &provider,
        &aad("writer"),
        b"null",
    )
    .await
    .unwrap();
    let expected = record(&envelope, b"null");
    let commit = AttestedConfigCommit::try_new(
        expected.clone(),
        vec![],
        envelope.claim_reserved(&pool).unwrap(),
    )
    .unwrap();
    assert_eq!(commit.record(), &expected);
    let evidence = commit.capacity_evidence().unwrap();
    assert_eq!((evidence.logical_bytes(), evidence.replay_bytes()), (4, 0));
    assert!(pool.owns(commit.preparation().unwrap()));
    assert!(!foreign.owns(commit.preparation().unwrap()));
    drop(envelope);
    exhausted(&pool);
    drop(commit);
    let _replacement = pool.try_reserve().unwrap();
    exhausted(&pool);
}

#[test]
fn another_encryption_key_or_plaintext_digest_cannot_take_the_claim() {
    let provider = Provider::new(Mode::Ready);
    let metadata = aad("writer");
    let foreign_key = KeyHandle::new(
        KeyId::new("foreign-key").unwrap(),
        KeyPurpose::Config,
        TenantId::from_static("synthetic"),
        Zeroizing::new([0x31; 32]),
    );
    let foreign_material = KeyHandle::new(
        provider.handle.key_id().clone(),
        KeyPurpose::Config,
        TenantId::from_static("synthetic"),
        Zeroizing::new([0x41; 32]),
    );
    for case in 0..6 {
        let original = encrypt_bounded_config_envelope_with_handle_and_nonce(
            &provider.handle,
            &metadata,
            b"null",
            [5; 12],
        )
        .unwrap();
        let mut substituted = record(&original, b"null");
        match case {
            0 => {
                substituted.encrypted_blob = encrypt_bounded_config_envelope_with_handle_and_nonce(
                    &provider.handle,
                    &metadata,
                    b"null",
                    [6; 12],
                )
                .unwrap()
                .encoded()
                .to_vec()
            }
            1 => {
                substituted.encrypted_blob = encrypt_bounded_config_envelope_with_handle_and_nonce(
                    &foreign_key,
                    &metadata,
                    b"null",
                    [5; 12],
                )
                .unwrap()
                .encoded()
                .to_vec()
            }
            2 => {
                substituted.encrypted_blob = encrypt_bounded_config_envelope_with_handle_and_nonce(
                    &foreign_material,
                    &metadata,
                    b"null",
                    [5; 12],
                )
                .unwrap()
                .encoded()
                .to_vec()
            }
            3 => substituted.plaintext_digest[0] ^= 1,
            4 => substituted.plaintext_digest.clear(),
            5 => {
                substituted.encrypted_blob.pop();
            }
            _ => unreachable!(),
        }
        let error = AttestedConfigCommit::try_new(substituted, vec![], original.claim().unwrap())
            .unwrap_err();
        assert!(matches!(
            error.kind(),
            opc_persist::PersistErrorKind::CorruptBlob
        ));
        assert_eq!(original.claim().unwrap_err(), CryptoError::EncryptionFailed);
    }
}

#[tokio::test]
async fn record_rejection_drops_transferred_claim_but_keeps_live_aliases() {
    let pool = ConfigPreparationPool::bounded_v1();
    let _seven = reserve(&pool, 7);
    let provider = Provider::new(Mode::Ready);
    for keep_alias in [false, true] {
        let envelope = encrypt_reserved_bounded_config_envelope(
            pool.try_reserve().unwrap(),
            &provider,
            &aad("writer"),
            b"null",
        )
        .await
        .unwrap();
        let alias = keep_alias.then(|| envelope.clone());
        let mut wrong = record(&envelope, b"null");
        wrong.plaintext_digest[0] ^= 1;
        let claim = envelope.claim().unwrap();
        drop(envelope);
        assert!(matches!(
            AttestedConfigCommit::try_new(wrong, vec![], claim)
                .unwrap_err()
                .kind(),
            opc_persist::PersistErrorKind::CorruptBlob
        ));
        if keep_alias {
            exhausted(&pool);
        }
        drop(alias);
        let replacement = pool.try_reserve().unwrap();
        exhausted(&pool);
        drop(replacement);
    }
}

#[tokio::test]
async fn confirmed_resolution_transfers_evidence_and_preserves_rejections() {
    let pool = ConfigPreparationPool::bounded_v1();
    let _seven = reserve(&pool, 7);
    let provider = Provider::new(Mode::Ready);
    let parent = TxId::new();
    let resolution = ConfirmedCommitResolution::Confirm {
        pending_tx_id: parent,
    };
    for case in 0..5 {
        let envelope = encrypt_reserved_bounded_config_envelope(
            pool.try_reserve().unwrap(),
            &provider,
            &aad("writer"),
            b"null",
        )
        .await
        .unwrap();
        let mut successor = record(&envelope, b"null");
        successor.parent_tx_id = Some(parent);
        match case {
            1 => successor.parent_tx_id = Some(TxId::new()),
            2 => successor.confirmed_deadline = Some(Timestamp::now_utc()),
            3 => successor.plaintext_digest[0] ^= 1,
            4 => {
                successor.encrypted_blob[0] ^= 1;
            }
            _ => {}
        }
        let claim = envelope.claim().unwrap();
        drop(envelope);
        let result = AttestedConfigCommit::try_new_resolving(successor, vec![], claim, resolution);
        if case == 0 {
            let commit = result.unwrap();
            assert_eq!(commit.confirmed_resolution(), Some(resolution));
            assert_eq!(commit.capacity_evidence().unwrap().logical_bytes(), 4);
            assert!(pool.owns(commit.preparation().unwrap()));
            exhausted(&pool);
            drop(commit);
        } else if case <= 2 {
            assert_eq!(
                result.unwrap_err().to_string(),
                opc_persist::PersistError::constraint_violation(
                    "confirmed resolution does not match a non-pending successor"
                )
                .to_string()
            );
        } else {
            assert!(matches!(
                result.unwrap_err().kind(),
                opc_persist::PersistErrorKind::CorruptBlob
            ));
        }
        let replacement = pool.try_reserve().unwrap();
        exhausted(&pool);
        drop(replacement);
    }
}

#[test]
fn legacy_claim_transfer_preserves_record_and_has_no_bounded_authority() {
    let provider = Provider::new(Mode::Ready);
    for resolving in [false, true] {
        let envelope = encrypt_attested_envelope_with_handle_and_nonce(
            &provider.handle,
            &aad("writer"),
            b"legacy binary\xff",
            [7; 12],
        )
        .unwrap();
        let mut expected = record(&envelope, b"legacy binary\xff");
        let parent = TxId::new();
        expected.parent_tx_id = Some(parent);
        let resolution = ConfirmedCommitResolution::Confirm {
            pending_tx_id: parent,
        };
        let claim = envelope.claim().unwrap();
        let commit = if resolving {
            AttestedConfigCommit::try_new_resolving(expected.clone(), vec![], claim, resolution)
        } else {
            AttestedConfigCommit::try_new(expected.clone(), vec![], claim)
        }
        .unwrap();
        assert_eq!(commit.record(), &expected);
        assert_eq!(
            commit.confirmed_resolution(),
            resolving.then_some(resolution)
        );
        assert!(commit.capacity_evidence().is_none());
        assert!(commit.preparation().is_none());
        assert_eq!(
            envelope.clone().claim().unwrap_err(),
            CryptoError::EncryptionFailed
        );
    }
}

#[tokio::test]
async fn concurrent_aliases_issue_exactly_one_claim() {
    let pool = ConfigPreparationPool::bounded_v1();
    let provider = Provider::new(Mode::Ready);
    let envelope = Arc::new(
        encrypt_reserved_bounded_config_envelope(
            pool.try_reserve().unwrap(),
            &provider,
            &aad("writer"),
            b"null",
        )
        .await
        .unwrap(),
    );
    let barrier = std::sync::Barrier::new(16);
    let claims = std::thread::scope(|scope| {
        let threads: Vec<_> = (0..16)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    envelope.claim_reserved(&pool)
                })
            })
            .collect();
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(claims.iter().filter(|result| result.is_ok()).count(), 1);
    for error in claims.iter().filter_map(|result| result.as_ref().err()) {
        assert_eq!(*error, opc_crypto::ConfigCapacityError::ResourceAdmission);
    }
}
