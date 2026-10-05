use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use opc_crypto::{
    AuthenticatedEnvelope, ConfigCapacityError, ConfigPreparationPool, ConfigPreparationReservation,
};
use opc_key::{
    ConfigAad, EnvelopeAad, KeyError, KeyHandle, KeyId, KeyProvider, KeyPurpose, Zeroizing,
};
use opc_persist::{CommitRecord, CommitSource};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use sha2::{Digest, Sha256};

pub const MAGIC: &[u8] = b"\x89OPCCFG\x02\r\n\x1a\n";

pub enum Mode {
    Ready,
    Reject,
    Pending,
}

pub struct Provider {
    pub calls: AtomicUsize,
    pub entered: tokio::sync::Notify,
    pub handle: KeyHandle,
    pub mode: Mode,
}

impl Provider {
    pub fn new(mode: Mode) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
            handle: KeyHandle::new(
                KeyId::new("k".repeat(512)).unwrap(),
                KeyPurpose::Config,
                TenantId::from_static("synthetic"),
                Zeroizing::new([0x31; 32]),
            ),
            mode,
        }
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl KeyProvider for Provider {
    async fn get_active_key(&self, _: KeyPurpose, _: &TenantId) -> Result<KeyHandle, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        match self.mode {
            Mode::Ready => Ok(self.handle.clone()),
            Mode::Reject => Err(KeyError::Unavailable),
            Mode::Pending => std::future::pending().await,
        }
    }

    async fn get_key_by_id(&self, _: &KeyId) -> Result<KeyHandle, KeyError> {
        panic!("unexpected historical key lookup")
    }

    async fn rotate_key(&self, _: KeyPurpose, _: &TenantId) -> Result<KeyId, KeyError> {
        panic!("unexpected key rotation")
    }
}

pub fn aad(principal: &str) -> EnvelopeAad {
    EnvelopeAad::config(
        TenantId::from_static("synthetic"),
        1,
        ConfigAad::new(
            TxId::from_str("11111111-1111-4111-8111-111111111111").unwrap(),
            None,
            Timestamp::from_str("2026-01-01T00:00:00Z").unwrap(),
            principal,
            SchemaDigest::from_bytes([0x32; 32]),
            "running",
        )
        .unwrap(),
    )
}

pub fn sized_aad(key: &KeyId, size: usize) -> EnvelopeAad {
    let prefix = "synthetic/\"\\\n\u{1}/🙂/";
    let base = opc_key::serialize_bound_aad(&aad(prefix), key)
        .unwrap()
        .len();
    let metadata = aad(&format!("{prefix}{}", "p".repeat(size - base)));
    assert_eq!(
        opc_key::serialize_bound_aad(&metadata, key).unwrap().len(),
        size
    );
    metadata
}

pub fn logical(size: usize) -> Vec<u8> {
    let mut bytes = vec![b'q'; size];
    bytes[0] = b'"';
    bytes[size - 1] = b'"';
    bytes
}

pub fn framed(value: &[u8], replay: usize) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(b"{\"config\":");
    bytes.extend_from_slice(value);
    bytes.extend_from_slice(b",\"idempotency_key\":\"");
    let padding = replay.checked_sub(bytes.len() - value.len() + 2).unwrap();
    bytes.resize(bytes.len() + padding, b'r');
    bytes.extend_from_slice(b"\"}");
    assert_eq!(bytes.len() - value.len(), replay);
    bytes
}

pub fn reserve(pool: &ConfigPreparationPool, count: usize) -> Vec<ConfigPreparationReservation> {
    (0..count).map(|_| pool.try_reserve().unwrap()).collect()
}

pub fn exhausted(pool: &ConfigPreparationPool) {
    assert_eq!(
        pool.try_reserve().unwrap_err(),
        ConfigCapacityError::ResourceAdmission
    );
}

pub fn record(envelope: &AuthenticatedEnvelope, plaintext: &[u8]) -> CommitRecord {
    CommitRecord {
        tx_id: TxId::from_str("11111111-1111-4111-8111-111111111111").unwrap(),
        parent_tx_id: None,
        version: ConfigVersion::new(1),
        committed_at: Timestamp::from_str("2026-01-01T00:00:00Z").unwrap(),
        principal: "writer".into(),
        source: CommitSource::LocalOperator,
        schema_digest: SchemaDigest::from_bytes([0x32; 32]),
        plaintext_digest: Sha256::digest(plaintext).to_vec(),
        encrypted_blob: envelope.encoded().to_vec(),
        rollback_point: false,
        confirmed_deadline: None,
    }
}
