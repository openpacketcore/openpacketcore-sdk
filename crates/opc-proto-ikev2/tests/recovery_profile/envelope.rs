//! Ordinary RFC 003 row envelopes, retaining key-provider error classification.
//! No checkpoint envelope, key-custody adapter or extra key-provider request.

use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use async_trait::async_trait;
use opc_crypto::{
    decrypt_decoded_envelope_with_handle, encrypt_envelope_with_handle, CryptoEnvelopeV1,
};
use opc_key::{
    EnvelopeAad, KeyError, KeyHandle, KeyId, KeyProvider, KeyPurpose, MemoryKeyProvider, SessionAad,
};
use opc_types::TenantId;
use zeroize::Zeroizing;

use super::{
    module::ready,
    store::{RowKey, StoredRow, Version},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Backpressure,
    KeyLost,
    Integrity,
    Format,
    PeerKeyExchange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Fault {
    Healthy,
    Unavailable,
    Timeout,
    Throttled,
    Missing,
    Revoked,
}

/// Timeout and throttling are reported as KeyError::Unavailable, as required by
/// the ordinary provider API. They are injected outcomes, not wall-clock sleeps.
pub struct Provider {
    inner: MemoryKeyProvider,
    fault: AtomicU8,
    active: AtomicUsize,
    historical: AtomicUsize,
    fail_at_active: AtomicUsize,
    scheduled_fault: AtomicU8,
}

impl Provider {
    pub fn new() -> Self {
        let inner = MemoryKeyProvider::new();
        inner
            .insert_active_key(
                KeyId::new("recovery-fixture-envelope").unwrap(),
                KeyPurpose::Session,
                tenant(),
                Zeroizing::new([0x93; 32]),
            )
            .unwrap();
        Self {
            inner,
            fault: AtomicU8::new(0),
            active: AtomicUsize::new(0),
            historical: AtomicUsize::new(0),
            fail_at_active: AtomicUsize::new(usize::MAX),
            scheduled_fault: AtomicU8::new(0),
        }
    }

    pub fn fail(&self, fault: Fault) {
        self.fault.store(fault as u8, Ordering::SeqCst);
    }
    pub fn fail_on_active_call(&self, additional: usize, fault: Fault) {
        assert!(additional > 0);
        self.scheduled_fault.store(fault as u8, Ordering::SeqCst);
        self.fail_at_active.store(
            self.active.load(Ordering::SeqCst) + additional,
            Ordering::SeqCst,
        );
    }
    pub fn calls(&self) -> (usize, usize) {
        (
            self.active.load(Ordering::SeqCst),
            self.historical.load(Ordering::SeqCst),
        )
    }
    fn available(&self) -> Result<(), KeyError> {
        match self.fault.load(Ordering::SeqCst) {
            0 => Ok(()),
            1..=3 => Err(KeyError::Unavailable),
            4..=5 => Err(KeyError::NotFound),
            _ => unreachable!(),
        }
    }
}

#[async_trait]
impl KeyProvider for Provider {
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyHandle, KeyError> {
        let call = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.fail_at_active.load(Ordering::SeqCst) {
            match self.scheduled_fault.load(Ordering::SeqCst) {
                0 => {}
                1..=3 => return Err(KeyError::Unavailable),
                4..=5 => return Err(KeyError::NotFound),
                _ => unreachable!(),
            }
        }
        self.available()?;
        self.inner.get_active_key(purpose, tenant).await
    }
    async fn get_key_by_id(&self, key_id: &KeyId) -> Result<KeyHandle, KeyError> {
        self.historical.fetch_add(1, Ordering::SeqCst);
        self.available()?;
        self.inner.get_key_by_id(key_id).await
    }
    async fn rotate_key(&self, purpose: KeyPurpose, tenant: &TenantId) -> Result<KeyId, KeyError> {
        self.available()?;
        self.inner.rotate_key(purpose, tenant).await
    }
}

fn tenant() -> TenantId {
    TenantId::new("recovery-fixture").unwrap()
}

fn aad(key: RowKey, version: Version, stamp: u64) -> EnvelopeAad {
    EnvelopeAad::session(
        tenant(),
        1,
        SessionAad::new(
            "ike",
            format!("epoch-{}-birth-{}", key.0, version.birth),
            "complete-recovery-profile",
            version.generation,
            stamp,
            "fixture-scope",
        )
        .unwrap(),
    )
}

pub fn classify_key_error(error: KeyError) -> Error {
    match error {
        KeyError::Unavailable => Error::Backpressure,
        KeyError::NotFound => Error::KeyLost,
        _ => Error::Integrity,
    }
}

pub fn seal(
    provider: &Provider,
    key: RowKey,
    version: Version,
    stamp: u64,
    plaintext: &Zeroizing<Vec<u8>>,
) -> Result<StoredRow, Error> {
    let aad = aad(key, version, stamp);
    let handle = ready(provider.get_active_key(KeyPurpose::Session, &tenant()))
        .map_err(classify_key_error)?;
    let envelope =
        encrypt_envelope_with_handle(&handle, &aad, plaintext).map_err(|_| Error::Integrity)?;
    Ok(StoredRow {
        version,
        sealed_stamp: stamp,
        envelope: Zeroizing::new(envelope),
    })
}

pub fn unseal(
    provider: &Provider,
    key: RowKey,
    row: &StoredRow,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let envelope = CryptoEnvelopeV1::decode(&row.envelope).map_err(|_| Error::Integrity)?;
    // Preserve Unavailable before the existing async envelope helper would
    // collapse the key lookup into DecryptionFailed (tracked by issue #1197).
    let handle = ready(provider.get_key_by_id(&envelope.key_id)).map_err(classify_key_error)?;
    decrypt_decoded_envelope_with_handle(
        &handle,
        &aad(key, row.version, row.sealed_stamp),
        &envelope,
    )
    .map_err(|_| Error::Integrity)
}
