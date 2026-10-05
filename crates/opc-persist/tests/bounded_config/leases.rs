use super::support::*;
use opc_crypto::{
    encrypt_bounded_config_envelope, encrypt_reserved_bounded_config_envelope, ConfigCapacityError,
    ConfigPreparationPool,
};
use std::sync::{Arc, Barrier};

#[test]
fn ninth_reservation_is_nonwaiting_and_drop_returns_exactly_one_slot() {
    let pool = ConfigPreparationPool::bounded_v1();
    let mut held = reserve(&pool, 8);
    exhausted(&pool);
    drop(held.pop());
    let replacement = pool.try_reserve().unwrap();
    exhausted(&pool);
    drop(held);
    let seven = reserve(&pool, 7);
    exhausted(&pool);
    drop((seven, replacement));
    let _eight = reserve(&pool, 8);
    exhausted(&pool);
}

#[test]
fn concurrent_reservations_obey_eight_slot_limit() {
    let pool = ConfigPreparationPool::bounded_v1();
    let foreign = ConfigPreparationPool::bounded_v1();
    let barrier = Barrier::new(16);
    let reservations = std::thread::scope(|scope| {
        let threads: Vec<_> = (0..16)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    let result = pool.try_reserve();
                    barrier.wait();
                    result
                })
            })
            .collect();
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        reservations.iter().filter(|result| result.is_ok()).count(),
        8
    );
    for result in &reservations {
        match result {
            Ok(lease) => {
                assert!(pool.owns(lease));
                assert!(!foreign.owns(lease));
            }
            Err(error) => assert_eq!(*error, ConfigCapacityError::ResourceAdmission),
        }
    }
    exhausted(&pool);
    drop(reservations);
    let _eight = reserve(&pool, 8);
    exhausted(&pool);
}

#[tokio::test]
async fn claim_and_aliases_hold_one_shared_slot_until_last_drop() {
    let pool = ConfigPreparationPool::bounded_v1();
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
    let aliases = vec![envelope.clone(); 16];
    assert!(aliases
        .iter()
        .all(|alias| std::ptr::eq(alias.encoded(), envelope.encoded())));
    let claim = envelope.claim_reserved(&pool).unwrap();
    for alias in &aliases {
        assert_eq!(
            alias.claim().unwrap_err(),
            opc_crypto::CryptoError::EncryptionFailed
        );
        assert_eq!(
            alias.claim_reserved(&pool).unwrap_err(),
            ConfigCapacityError::ResourceAdmission
        );
    }
    let (evidence, lease) = claim.into_capacity_parts();
    assert_eq!(evidence.unwrap().logical_bytes(), 4);
    let lease = lease.unwrap();
    assert!(pool.owns(&lease));
    drop(envelope);
    exhausted(&pool);
    drop(lease);
    exhausted(&pool);
    drop(aliases);
    let _replacement = pool.try_reserve().unwrap();
    exhausted(&pool);
}

#[tokio::test]
async fn foreign_pool_refusal_does_not_consume_original_claim() {
    let owner = Arc::new(());
    let pool = ConfigPreparationPool::bounded_v1_with_owner(owner.clone());
    let foreign = ConfigPreparationPool::bounded_v1_with_owner(owner);
    let provider = Provider::new(Mode::Ready);
    let envelope = encrypt_reserved_bounded_config_envelope(
        pool.try_reserve().unwrap(),
        &provider,
        &aad("writer"),
        b"null",
    )
    .await
    .unwrap();
    assert_eq!(
        envelope.claim_reserved(&foreign).unwrap_err(),
        ConfigCapacityError::ResourceAdmission
    );
    assert_eq!(provider.calls(), 1);
    let (_, lease) = envelope
        .claim_reserved(&pool)
        .unwrap()
        .into_capacity_parts();
    assert!(pool.owns(lease.as_ref().unwrap()));
    assert!(!foreign.owns(lease.as_ref().unwrap()));
    let unreserved = encrypt_bounded_config_envelope(&provider, &aad("writer"), b"null")
        .await
        .unwrap();
    assert_eq!(
        unreserved.claim_reserved(&pool).unwrap_err(),
        ConfigCapacityError::ResourceAdmission
    );
    assert!(
        unreserved.claim().is_ok(),
        "refusal must preserve the ordinary claim"
    );
}

#[tokio::test]
async fn transferred_sealed_lease_cannot_encrypt_again() {
    let pool = ConfigPreparationPool::bounded_v1();
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
    let (_, lease) = envelope.claim().unwrap().into_capacity_parts();
    let result = encrypt_reserved_bounded_config_envelope(
        lease.unwrap(),
        &provider,
        &aad("writer"),
        b"true",
    )
    .await;
    assert_eq!(result.unwrap_err(), ConfigCapacityError::ResourceAdmission);
    assert_eq!(provider.calls(), 1, "refuse reuse before provider effects");
    exhausted(&pool);
    drop(envelope);
    let _replacement = pool.try_reserve().unwrap();
    exhausted(&pool);
}

#[tokio::test]
async fn unpolled_and_cancelled_encryption_return_the_lease() {
    let pool = ConfigPreparationPool::bounded_v1();
    let _seven = reserve(&pool, 7);
    let provider = Arc::new(Provider::new(Mode::Pending));
    let metadata = aad("writer");
    let unpolled = encrypt_reserved_bounded_config_envelope(
        pool.try_reserve().unwrap(),
        provider.as_ref(),
        &metadata,
        b"null",
    );
    exhausted(&pool);
    drop(unpolled);
    assert_eq!(provider.calls(), 0);
    let lease = pool.try_reserve().unwrap();
    let task_provider = provider.clone();
    let task = tokio::spawn(async move {
        encrypt_reserved_bounded_config_envelope(lease, task_provider.as_ref(), &metadata, b"null")
            .await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        provider.entered.notified(),
    )
    .await
    .unwrap();
    exhausted(&pool);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let _replacement = pool.try_reserve().unwrap();
    exhausted(&pool);
}

#[tokio::test]
async fn preflight_provider_and_encryption_errors_return_the_lease() {
    let pool = ConfigPreparationPool::bounded_v1();
    let _seven = reserve(&pool, 7);
    let mut provider = Provider::new(Mode::Ready);
    assert_eq!(
        encrypt_reserved_bounded_config_envelope(
            pool.try_reserve().unwrap(),
            &provider,
            &aad("writer"),
            b"invalid"
        )
        .await
        .unwrap_err(),
        ConfigCapacityError::InvalidPlaintext
    );
    assert_eq!(provider.calls(), 0);
    provider.mode = Mode::Reject;
    assert_eq!(
        encrypt_reserved_bounded_config_envelope(
            pool.try_reserve().unwrap(),
            &provider,
            &aad("writer"),
            b"null"
        )
        .await
        .unwrap_err(),
        ConfigCapacityError::EncryptionFailed
    );
    assert_eq!(provider.calls(), 1);
    provider.mode = Mode::Ready;
    provider.handle = opc_key::KeyHandle::new(
        opc_key::KeyId::new("foreign").unwrap(),
        opc_key::KeyPurpose::Config,
        opc_types::TenantId::from_static("foreign"),
        opc_key::Zeroizing::new([0x31; 32]),
    );
    assert_eq!(
        encrypt_reserved_bounded_config_envelope(
            pool.try_reserve().unwrap(),
            &provider,
            &aad("writer"),
            b"null"
        )
        .await
        .unwrap_err(),
        ConfigCapacityError::EncryptionFailed
    );
    assert_eq!(provider.calls(), 2);
    let _replacement = pool.try_reserve().unwrap();
    exhausted(&pool);
}

#[tokio::test]
async fn destination_lifetime_survives_pools_and_transfers_without_a_cycle() {
    let owner = Arc::new(());
    let alive = Arc::downgrade(&owner);
    let pool = ConfigPreparationPool::bounded_v1_with_owner(owner.clone());
    let foreign = ConfigPreparationPool::bounded_v1_with_owner(owner);
    let lease = pool.try_reserve().unwrap();
    assert!(!foreign.owns(&lease));
    let provider = Provider::new(Mode::Ready);
    let envelope =
        encrypt_reserved_bounded_config_envelope(lease, &provider, &aad("writer"), b"null")
            .await
            .unwrap();
    let alias = envelope.clone();
    let claim = envelope.claim_reserved(&pool).unwrap();
    drop((pool, foreign, envelope));
    assert!(alive.upgrade().is_some());
    drop(claim);
    assert!(
        alive.upgrade().is_some(),
        "last ciphertext alias retains destination"
    );
    drop(alias);
    assert!(alive.upgrade().is_none());
}

#[test]
fn unencrypted_reservation_retains_destination_after_pool_drop() {
    let owner = Arc::new(());
    let alive = Arc::downgrade(&owner);
    let pool = ConfigPreparationPool::bounded_v1_with_owner(owner);
    let lease = pool.try_reserve().unwrap();
    drop(pool);
    assert!(alive.upgrade().is_some());
    drop(lease);
    assert!(alive.upgrade().is_none());
}
