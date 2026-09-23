//! Preparation ownership controls, not whole-operation memory qualification.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use async_trait::async_trait;
use opc_crypto::{
    encrypt_reserved_bounded_config_envelope, ConfigCapacityError, ConfigPreparationPool,
};
use opc_key::{ConfigAad, EnvelopeAad, KeyError, KeyHandle, KeyId, KeyProvider, KeyPurpose};
use opc_types::{SchemaDigest, TenantId, Timestamp, TxId};

enum ProviderMode {
    Ready,
    Reject,
    Pending,
}

struct Provider {
    mode: ProviderMode,
    calls: AtomicUsize,
    entered: tokio::sync::Notify,
}

impl Provider {
    fn new(mode: ProviderMode) -> Self {
        Self {
            mode,
            calls: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
        }
    }
}

#[async_trait]
impl KeyProvider for Provider {
    async fn get_active_key(&self, _: KeyPurpose, _: &TenantId) -> Result<KeyHandle, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        match self.mode {
            ProviderMode::Ready => Ok(KeyHandle::new(
                KeyId::new("synthetic-preparation").expect("key ID"),
                KeyPurpose::Config,
                TenantId::from_static("synthetic"),
                opc_key::Zeroizing::new([0x67; 32]),
            )),
            ProviderMode::Reject => Err(KeyError::Unavailable),
            ProviderMode::Pending => std::future::pending().await,
        }
    }

    async fn get_key_by_id(&self, _: &KeyId) -> Result<KeyHandle, KeyError> {
        Err(KeyError::Unavailable)
    }

    async fn rotate_key(&self, _: KeyPurpose, _: &TenantId) -> Result<KeyId, KeyError> {
        Err(KeyError::Unavailable)
    }
}

fn aad() -> EnvelopeAad {
    EnvelopeAad::config(
        TenantId::from_static("synthetic"),
        1,
        ConfigAad::new(
            TxId::new(),
            None,
            Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH),
            "synthetic-writer",
            SchemaDigest::from_bytes([0x68; 32]),
            "running",
        )
        .expect("synthetic AAD"),
    )
}

#[test]
fn config_capacity_957_concurrent_pool_is_exact_and_store_specific() {
    let pool = ConfigPreparationPool::bounded_v1();
    let foreign = ConfigPreparationPool::bounded_v1();
    let barrier = Barrier::new(17);
    let admitted = AtomicUsize::new(0);
    let identity_correct = AtomicBool::new(true);
    let observed = std::thread::scope(|scope| {
        for _ in 0..16 {
            scope.spawn(|| {
                barrier.wait();
                let reservation = pool.try_reserve();
                if let Ok(reservation) = &reservation {
                    if !pool.owns(reservation) || foreign.owns(reservation) {
                        identity_correct.store(false, Ordering::SeqCst);
                    }
                    admitted.fetch_add(1, Ordering::SeqCst);
                }
                barrier.wait();
                barrier.wait();
                drop(reservation);
            });
        }
        barrier.wait();
        barrier.wait();
        let count = admitted.load(Ordering::SeqCst);
        let overflow = pool.try_reserve().err();
        barrier.wait();
        (count, overflow)
    });
    assert_eq!(observed, (8, Some(ConfigCapacityError::ResourceAdmission)));
    assert!(
        identity_correct.load(Ordering::SeqCst),
        "private pool identity is required"
    );
    let reservations: Vec<_> = (0..8)
        .map(|_| pool.try_reserve().expect("released exactly once"))
        .collect();
    assert!(pool.try_reserve().is_err());
    drop(reservations);
}

#[tokio::test]
async fn config_capacity_957_envelope_aliases_and_claim_hold_one_slot() {
    let pool = ConfigPreparationPool::bounded_v1();
    let _other: Vec<_> = (0..7)
        .map(|_| pool.try_reserve().expect("other owner"))
        .collect();
    let provider = Provider::new(ProviderMode::Ready);
    let envelope = encrypt_reserved_bounded_config_envelope(
        pool.try_reserve().expect("eighth"),
        &provider,
        &aad(),
        b"null",
    )
    .await
    .expect("reserved encryption");
    let aliases = vec![envelope.clone(); 16];
    assert!(aliases
        .iter()
        .all(|alias| std::ptr::eq(alias.encoded(), envelope.encoded())));
    let claim = envelope.claim().expect("one claim");
    assert!(aliases.iter().all(|alias| alias.claim().is_err()));
    let (evidence, reservation) = claim.into_capacity_parts();
    assert_eq!(evidence.expect("size proof").logical_bytes(), 4);
    let reservation = reservation.expect("transferred reservation");
    assert!(pool.owns(&reservation));
    drop(envelope);
    assert!(pool.try_reserve().is_err());
    drop(reservation);
    assert!(
        pool.try_reserve().is_err(),
        "retained ciphertext aliases still own capacity"
    );
    drop(aliases);
    let _released = pool
        .try_reserve()
        .expect("last owner released the eighth slot");
    assert!(pool.try_reserve().is_err(), "no double release");
}

#[tokio::test]
async fn config_capacity_957_sealed_reservation_cannot_encrypt_again() {
    let pool = ConfigPreparationPool::bounded_v1();
    let provider = Provider::new(ProviderMode::Ready);
    let envelope = encrypt_reserved_bounded_config_envelope(
        pool.try_reserve().expect("reservation"),
        &provider,
        &aad(),
        b"null",
    )
    .await
    .expect("first encryption");
    let (_, reservation) = envelope.claim().expect("claim").into_capacity_parts();
    let error = encrypt_reserved_bounded_config_envelope(
        reservation.expect("sealed reservation"),
        &provider,
        &aad(),
        b"true",
    )
    .await
    .expect_err("one-shot encryption ownership");
    assert_eq!(error, ConfigCapacityError::ResourceAdmission);
    assert_eq!(
        provider.calls.load(Ordering::SeqCst),
        1,
        "refuse before provider access"
    );
}

#[tokio::test]
async fn config_capacity_957_encryption_failure_and_cancellation_release_ownership() {
    let pool = ConfigPreparationPool::bounded_v1();
    let _other: Vec<_> = (0..7)
        .map(|_| pool.try_reserve().expect("other owner"))
        .collect();
    let metadata = aad();
    let rejecting = Provider::new(ProviderMode::Reject);
    let unpolled = encrypt_reserved_bounded_config_envelope(
        pool.try_reserve().expect("eighth"),
        &rejecting,
        &metadata,
        b"null",
    );
    assert!(pool.try_reserve().is_err());
    drop(unpolled);
    assert_eq!(rejecting.calls.load(Ordering::SeqCst), 0);
    let error = encrypt_reserved_bounded_config_envelope(
        pool.try_reserve().expect("unsent released"),
        &rejecting,
        &metadata,
        b"null",
    )
    .await
    .expect_err("provider refusal");
    assert_eq!(error, ConfigCapacityError::EncryptionFailed);

    let provider = Arc::new(Provider::new(ProviderMode::Pending));
    let task_provider = Arc::clone(&provider);
    let reservation = pool.try_reserve().expect("failed encryption released");
    let task = tokio::spawn(async move {
        encrypt_reserved_bounded_config_envelope(
            reservation,
            task_provider.as_ref(),
            &metadata,
            b"null",
        )
        .await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        provider.entered.notified(),
    )
    .await
    .expect("provider reached without sleeping");
    assert!(
        pool.try_reserve().is_err(),
        "provider future retains preparation"
    );
    task.abort();
    assert!(task.await.expect_err("cancelled encryption").is_cancelled());
    let _released = pool.try_reserve().expect("cancelled encryption released");
    assert!(pool.try_reserve().is_err(), "released exactly one slot");
}
