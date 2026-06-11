use async_trait::async_trait;
use bytes::Bytes;
use opc_crypto::CryptoEnvelopeV1;
use opc_key::{
    KeyError, KeyHandle, KeyId, KeyProvider, KeyPurpose, MemoryKeyProvider, Zeroizing,
    AES_256_GCM_SIV_KEY_LEN,
};
use opc_session_store::{
    BackendCapabilities, CompareAndSet, CompareAndSetResult, EncryptedSessionPayload,
    EncryptingSessionBackend, FakeSessionBackend, FenceToken, Generation, OwnerId, SessionBackend,
    SessionKey, SessionKeyType, SessionLeaseManager, SessionOp, SessionOpResult,
    SessionPayloadEncoding, StateClass, StateType, StoreError, StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, TenantId};
use std::{sync::Arc, time::Duration};
use tokio::sync::Barrier;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn tenant() -> TenantId {
    TenantId::new("tenant-a").expect("tenant")
}

fn test_provider() -> Arc<MemoryKeyProvider> {
    let provider = Arc::new(MemoryKeyProvider::new());
    provider
        .insert_active_key(
            KeyId::new("session-active-2026-01").expect("key id"),
            KeyPurpose::Session,
            tenant(),
            Zeroizing::new([0x22; AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("insert key");
    provider
}

fn test_key() -> SessionKey {
    SessionKey {
        tenant: tenant(),
        nf_kind: NetworkFunctionKind::new("smf").expect("nf kind"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(b"same-id"),
    }
}

fn test_record(
    key: SessionKey,
    generation: u64,
    lease: &opc_session_store::LeaseGuard,
) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(generation),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("smf-pdu-context").expect("state type"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(Bytes::from_static(b"plain-session")),
    }
}

struct BarrierKeyProvider {
    inner: Arc<MemoryKeyProvider>,
    read_barrier: Arc<Barrier>,
}

#[async_trait]
impl KeyProvider for BarrierKeyProvider {
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyHandle, KeyError> {
        self.inner.get_active_key(purpose, tenant).await
    }

    async fn get_key_by_id(&self, key_id: &KeyId) -> Result<KeyHandle, KeyError> {
        self.read_barrier.wait().await;
        self.inner.get_key_by_id(key_id).await
    }

    async fn rotate_key(&self, purpose: KeyPurpose, tenant: &TenantId) -> Result<KeyId, KeyError> {
        self.inner.rotate_key(purpose, tenant).await
    }
}

#[tokio::test]
async fn encrypting_session_backend_round_trips_compare_and_set_get_and_batch_results() {
    let inner = Arc::new(FakeSessionBackend::new());
    let provider = test_provider();
    let backend = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "regional-cache-a",
    );
    let key = test_key();
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("lease");

    let first = test_record(key.clone(), 1, &lease);
    let result = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: first,
        })
        .await
        .expect("write");
    assert_eq!(result, CompareAndSetResult::Success);

    let inner_record = inner.get(&key).await.expect("inner get").expect("stored");
    assert_ne!(inner_record.payload.as_bytes(), b"plain-session");
    let envelope = CryptoEnvelopeV1::decode(inner_record.payload.as_bytes()).expect("envelope");
    let aad: serde_json::Value = serde_json::from_slice(&envelope.aad).expect("aad json");
    let aad_digest = aad["metadata"]["session_key_digest"]
        .as_str()
        .expect("aad session key digest");
    assert_ne!(aad_digest, hex_encode(&key.digest()));

    let round_trip = backend
        .get(&key)
        .await
        .expect("backend get")
        .expect("stored");
    assert_eq!(round_trip.payload.as_bytes(), b"plain-session");

    let conflict = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: test_record(key.clone(), 2, &lease),
        })
        .await
        .expect("conflict result");
    match conflict {
        CompareAndSetResult::Success => panic!("expected conflict"),
        CompareAndSetResult::Conflict { current } => {
            let current = current.expect("current record");
            assert_eq!(current.payload.as_bytes(), b"plain-session");
        }
    }

    let results = backend
        .batch(vec![SessionOp::Get { key: key.clone() }])
        .await
        .expect("batch");
    match &results[0] {
        SessionOpResult::Get(Ok(Some(record))) => {
            assert_eq!(record.payload.as_bytes(), b"plain-session");
        }
        other => panic!("unexpected batch result: {other:?}"),
    }

    let batch_payload = Bytes::from_static(b"plain-session-batch");
    let batch_success = backend
        .batch(vec![SessionOp::CompareAndSet(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(1)),
            new_record: StoredSessionRecord {
                payload: EncryptedSessionPayload::new(batch_payload.clone()),
                ..test_record(key.clone(), 2, &lease)
            },
        })])
        .await
        .expect("batch compare-and-set success");
    assert!(matches!(
        &batch_success[0],
        SessionOpResult::CompareAndSet(Ok(CompareAndSetResult::Success))
    ));

    let inner_record = inner.get(&key).await.expect("inner get").expect("stored");
    assert_ne!(inner_record.payload.as_bytes(), &batch_payload);

    let batch_conflict = backend
        .batch(vec![SessionOp::CompareAndSet(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(1)),
            new_record: test_record(key.clone(), 3, &lease),
        })])
        .await
        .expect("batch compare-and-set conflict");
    match &batch_conflict[0] {
        SessionOpResult::CompareAndSet(Ok(CompareAndSetResult::Conflict {
            current: Some(record),
        })) => {
            assert_eq!(record.payload.as_bytes(), &batch_payload);
        }
        other => panic!("unexpected batch CAS result: {other:?}"),
    }
}

#[tokio::test]
async fn legacy_plaintext_session_records_read_and_reencrypt_on_update() {
    let inner = Arc::new(FakeSessionBackend::new());
    let provider = test_provider();
    let backend = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "regional-cache-a",
    );
    let key = test_key();
    let lease = inner
        .acquire(
            &key,
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("lease");

    inner
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: StoredSessionRecord {
                payload: EncryptedSessionPayload::legacy_plaintext(Bytes::from_static(
                    b"plain-session",
                )),
                ..test_record(key.clone(), 1, &lease)
            },
        })
        .await
        .expect("legacy write");

    let restored = backend
        .get(&key)
        .await
        .expect("legacy get")
        .expect("stored");
    assert_eq!(restored.payload.as_bytes(), b"plain-session");

    let conflict = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: test_record(key.clone(), 2, &lease),
        })
        .await
        .expect("legacy conflict");
    match conflict {
        CompareAndSetResult::Success => panic!("expected conflict"),
        CompareAndSetResult::Conflict { current } => {
            let current = current.expect("current record");
            assert_eq!(current.payload.as_bytes(), b"plain-session");
        }
    }

    let upgraded_payload = Bytes::from_static(b"post-upgrade-session");
    let update = StoredSessionRecord {
        payload: EncryptedSessionPayload::new(upgraded_payload.clone()),
        ..test_record(key.clone(), 2, &lease)
    };
    assert_eq!(
        backend
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: Some(Generation::new(1)),
                new_record: update,
            })
            .await
            .expect("upgrade write"),
        CompareAndSetResult::Success
    );

    let inner_record = inner.get(&key).await.expect("inner get").expect("stored");
    assert_ne!(inner_record.payload.as_bytes(), &upgraded_payload);
    CryptoEnvelopeV1::decode(inner_record.payload.as_bytes()).expect("post-upgrade envelope");

    let round_trip = backend
        .get(&key)
        .await
        .expect("post-upgrade get")
        .expect("stored");
    assert_eq!(round_trip.payload.as_bytes(), &upgraded_payload);
}

#[tokio::test]
async fn decrypts_persisted_envelope_bytes_even_if_adapter_reconstructed_plaintext_wrapper() {
    let inner = Arc::new(FakeSessionBackend::new());
    let provider = test_provider();
    let backend = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "regional-cache-a",
    );
    let key = test_key();
    let lease = inner
        .acquire(
            &key,
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("lease");

    let encrypted = EncryptedSessionPayload::encrypt(
        provider.as_ref(),
        &test_record(key.clone(), 1, &lease),
        "regional-cache-a",
    )
    .await
    .expect("encrypt");

    inner
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: StoredSessionRecord {
                payload: EncryptedSessionPayload::unclassified(encrypted.as_bytes()),
                ..test_record(key.clone(), 1, &lease)
            },
        })
        .await
        .expect("seed unclassified wrapper with envelope bytes");

    let restored = backend
        .get(&key)
        .await
        .expect("read reconstructed envelope")
        .expect("stored");
    assert_eq!(restored.payload.as_bytes(), b"plain-session");
}

#[tokio::test]
async fn legacy_plaintext_marker_bypasses_envelope_probe_for_envelope_shaped_bytes() {
    let inner = Arc::new(FakeSessionBackend::new());
    let provider = test_provider();
    let backend = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "regional-cache-a",
    );
    let key = test_key();
    let lease = inner
        .acquire(
            &key,
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("lease");

    let envelope_bytes = EncryptedSessionPayload::encrypt(
        provider.as_ref(),
        &test_record(key.clone(), 1, &lease),
        "regional-cache-a",
    )
    .await
    .expect("encrypt")
    .as_bytes()
    .to_vec();

    inner
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: StoredSessionRecord {
                payload: EncryptedSessionPayload::legacy_plaintext(envelope_bytes.clone()),
                ..test_record(key.clone(), 1, &lease)
            },
        })
        .await
        .expect("seed legacy payload");

    let restored = backend
        .get(&key)
        .await
        .expect("legacy get")
        .expect("stored");
    assert_eq!(restored.payload.as_bytes(), envelope_bytes.as_slice());
}

#[tokio::test]
async fn malformed_session_envelope_magic_is_not_treated_as_legacy_plaintext() {
    let inner = Arc::new(FakeSessionBackend::new());
    let provider = test_provider();
    let backend = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "regional-cache-a",
    );
    let key = test_key();
    let lease = inner
        .acquire(
            &key,
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("lease");

    inner
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: StoredSessionRecord {
                payload: EncryptedSessionPayload::envelope(Bytes::from_static(b"OPCE")),
                ..test_record(key.clone(), 1, &lease)
            },
        })
        .await
        .expect("write malformed envelope");

    let err = backend.get(&key).await.expect_err("malformed envelope");
    assert_eq!(
        err,
        StoreError::Crypto("session envelope decryption failed".into())
    );
}

#[tokio::test]
async fn corrupted_session_envelope_header_byte_is_not_treated_as_legacy_plaintext() {
    let inner = Arc::new(FakeSessionBackend::new());
    let provider = test_provider();
    let backend = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "regional-cache-a",
    );
    let key = test_key();
    let lease = inner
        .acquire(
            &key,
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("lease");

    let mut encrypted = EncryptedSessionPayload::encrypt(
        provider.as_ref(),
        &test_record(key.clone(), 1, &lease),
        "regional-cache-a",
    )
    .await
    .expect("encrypt");
    let mut corrupted = encrypted.as_bytes().to_vec();
    corrupted[0] ^= 0x01;
    encrypted = EncryptedSessionPayload::envelope(Bytes::from(corrupted));

    inner
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: StoredSessionRecord {
                payload: encrypted,
                ..test_record(key.clone(), 1, &lease)
            },
        })
        .await
        .expect("seed corrupted envelope");

    let err = backend.get(&key).await.expect_err("corrupted envelope");
    assert_eq!(
        err,
        StoreError::Crypto("session envelope decryption failed".into())
    );
}

#[tokio::test]
async fn empty_session_envelope_ciphertext_is_rejected() {
    let inner = Arc::new(FakeSessionBackend::new());
    let provider = test_provider();
    let backend = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "regional-cache-a",
    );
    let key = test_key();
    let lease = inner
        .acquire(
            &key,
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("lease");

    inner
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: StoredSessionRecord {
                payload: EncryptedSessionPayload::envelope(Bytes::new()),
                ..test_record(key.clone(), 1, &lease)
            },
        })
        .await
        .expect("seed empty envelope");

    let err = backend.get(&key).await.expect_err("empty envelope");
    assert_eq!(
        err,
        StoreError::Crypto("session envelope ciphertext is missing".into())
    );
}

#[tokio::test]
async fn compare_and_set_reports_missing_session_key() {
    let inner = Arc::new(FakeSessionBackend::new());
    let provider = Arc::new(MemoryKeyProvider::new());
    let backend = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "regional-cache-a",
    );
    let key = test_key();
    let lease = inner
        .acquire(
            &key,
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("lease");

    let err = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: test_record(key, 1, &lease),
        })
        .await
        .expect_err("CAS must fail without a session key");

    assert_eq!(
        err,
        StoreError::Crypto("session envelope encryption failed".into())
    );
}

#[tokio::test]
async fn get_reports_missing_session_decryption_key() {
    let inner = Arc::new(FakeSessionBackend::new());
    let writer_provider = test_provider();
    let writer = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&writer_provider),
        "regional-cache-a",
    );
    let reader = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::new(MemoryKeyProvider::new()),
        "regional-cache-a",
    );
    let key = test_key();
    let lease = writer
        .acquire(
            &key,
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("lease");

    writer
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: test_record(key.clone(), 1, &lease),
        })
        .await
        .expect("encrypted write");

    let err = reader
        .get(&key)
        .await
        .expect_err("get must fail without the envelope key");
    assert_eq!(
        err,
        StoreError::Crypto("session envelope decryption failed".into())
    );
}

#[tokio::test]
async fn batch_cas_encryption_failure_is_per_operation_result() {
    let inner = Arc::new(FakeSessionBackend::new());
    let provider = Arc::new(MemoryKeyProvider::new());
    let backend = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "regional-cache-a",
    );
    let key = test_key();
    let lease = inner
        .acquire(
            &key,
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("lease");
    inner
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: test_record(key.clone(), 1, &lease),
        })
        .await
        .expect("seed write");

    let results = backend
        .batch(vec![
            SessionOp::RefreshTtl {
                lease: lease.clone(),
                ttl: Duration::from_secs(120),
            },
            SessionOp::CompareAndSet(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: Some(Generation::new(1)),
                new_record: test_record(key.clone(), 2, &lease),
            }),
            SessionOp::DeleteFenced {
                lease: lease.clone(),
            },
        ])
        .await
        .expect("batch should preserve partial failure");

    assert!(matches!(&results[0], SessionOpResult::RefreshTtl(Ok(()))));
    match &results[1] {
        SessionOpResult::CompareAndSet(Err(err)) => {
            assert_eq!(
                err,
                &StoreError::Crypto("session envelope encryption failed".into())
            );
        }
        other => panic!("unexpected CAS result: {other:?}"),
    }
    assert!(matches!(&results[2], SessionOpResult::DeleteFenced(Ok(()))));
    assert!(inner.get(&key).await.expect("inner get").is_none());
}

#[tokio::test]
async fn batch_capability_is_enforced_even_when_all_cas_ops_fail_encryption() {
    let inner = Arc::new(FakeSessionBackend::with_capabilities(BackendCapabilities {
        batch_write: false,
        ..BackendCapabilities::all_enabled()
    }));
    let provider = Arc::new(MemoryKeyProvider::new());
    let backend = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "regional-cache-a",
    );
    let key = test_key();
    let lease = inner
        .acquire(
            &key,
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("lease");

    let err = backend
        .batch(vec![SessionOp::CompareAndSet(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: test_record(key, 1, &lease),
        })])
        .await
        .expect_err("batch capability must be enforced before synthetic CAS results");

    assert_eq!(
        err,
        opc_session_store::StoreError::CapabilityNotSupported("batch_write".into())
    );
}

#[tokio::test]
async fn batch_fans_out_read_side_decrypts_for_gets_and_conflicts() {
    let inner = Arc::new(FakeSessionBackend::new());
    let provider = test_provider();
    let backend = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::new(BarrierKeyProvider {
            inner: Arc::clone(&provider),
            read_barrier: Arc::new(Barrier::new(2)),
        }),
        "regional-cache-a",
    );
    let key = test_key();
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("lease");

    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: test_record(key.clone(), 1, &lease),
        })
        .await
        .expect("seed write");

    let results = tokio::time::timeout(
        Duration::from_millis(250),
        backend.batch(vec![
            SessionOp::Get { key: key.clone() },
            SessionOp::CompareAndSet(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: test_record(key.clone(), 2, &lease),
            }),
        ]),
    )
    .await
    .expect("batch decryption should fan out")
    .expect("batch");

    match &results[0] {
        SessionOpResult::Get(Ok(Some(record))) => {
            assert_eq!(record.payload.as_bytes(), b"plain-session");
        }
        other => panic!("unexpected get result: {other:?}"),
    }
    match &results[1] {
        SessionOpResult::CompareAndSet(Ok(CompareAndSetResult::Conflict {
            current: Some(record),
        })) => {
            assert_eq!(record.payload.as_bytes(), b"plain-session");
        }
        other => panic!("unexpected conflict result: {other:?}"),
    }
}

#[tokio::test]
async fn encrypting_session_backend_rejects_wrong_backend_namespace() {
    let inner = Arc::new(FakeSessionBackend::new());
    let provider = test_provider();
    let writer = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "regional-cache-a",
    );
    let wrong_namespace = EncryptingSessionBackend::new(inner, provider, "regional-cache-b");
    let key = test_key();
    let lease = writer
        .acquire(
            &key,
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("lease");

    writer
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease,
            expected_generation: None,
            new_record: StoredSessionRecord {
                key: key.clone(),
                generation: Generation::new(1),
                owner: OwnerId::new("owner-a").expect("owner"),
                fence: FenceToken::new(1),
                state_class: StateClass::AuthoritativeSession,
                state_type: StateType::new("smf-pdu-context").expect("state type"),
                expires_at: None,
                payload: EncryptedSessionPayload::new(Bytes::from_static(b"plain-session")),
            },
        })
        .await
        .expect("write");

    let err = wrong_namespace
        .get(&key)
        .await
        .expect_err("wrong namespace must fail");
    assert_eq!(
        err,
        StoreError::Crypto("session envelope decryption failed".into())
    );
}

#[tokio::test]
async fn test_refactored_zeroizing_decrypt_hygiene() {
    let inner = Arc::new(FakeSessionBackend::new());
    let provider = test_provider();
    let backend = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "regional-cache-a",
    );
    let key = test_key();
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("lease");

    let plaintext = b"zeroizing-hygiene-plaintext-secret";
    let record = StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(1),
        owner: OwnerId::new("owner-a").expect("owner"),
        fence: FenceToken::new(1),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("smf-pdu-context").expect("state type"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(plaintext),
    };

    // 1. Decrypt round-trip verification
    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .expect("cas success");

    let restored = backend
        .get(&key)
        .await
        .expect("get success")
        .expect("stored");
    assert_eq!(restored.payload.as_bytes(), plaintext);

    // 2. Corrupt envelope fail-closed verification
    let mut raw_record = inner.get(&key).await.expect("inner get").expect("stored");
    let mut corrupted_bytes = raw_record.payload.as_bytes().to_vec();
    if let Some(last) = corrupted_bytes.last_mut() {
        *last ^= 0x55;
    }
    raw_record.payload = EncryptedSessionPayload::envelope(corrupted_bytes);
    raw_record.generation = Generation::new(2); // monotonic increment
    inner
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(1)),
            new_record: raw_record.clone(),
        })
        .await
        .expect("inner write corrupted success");

    let err = backend.get(&key).await.expect_err("should fail closed");
    assert!(matches!(err, StoreError::Crypto(_)));

    // 3. Missing key fail-closed verification
    let empty_provider = Arc::new(opc_key::MemoryKeyProvider::new());
    let bad_backend =
        EncryptingSessionBackend::new(Arc::clone(&inner), empty_provider, "regional-cache-a");
    let err_missing_key = bad_backend.get(&key).await.expect_err("should fail closed");
    assert!(matches!(err_missing_key, StoreError::Crypto(_)));

    // Restore correct record for conflict verification
    // Note: raw_record has generation 2 (which is corrupted). We write a correct decrypted
    // record with generation 3 so that we can verify CAS conflict on generation 2 later.
    let mut correct_record = StoredSessionRecord {
        generation: Generation::new(3),
        ..record.clone()
    };
    correct_record.payload =
        EncryptedSessionPayload::encrypt(provider.as_ref(), &correct_record, "regional-cache-a")
            .await
            .expect("encrypt");
    inner
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(2)),
            new_record: correct_record,
        })
        .await
        .expect("inner write correct success");

    // 4. Batch CAS conflict decrypt verification
    let conflict_batch = backend
        .batch(vec![SessionOp::CompareAndSet(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(2)), // intentionally stale (current is 3)
            new_record: StoredSessionRecord {
                generation: Generation::new(4),
                payload: EncryptedSessionPayload::new(b"new-attempt"),
                ..record.clone()
            },
        })])
        .await
        .expect("batch completed");

    match &conflict_batch[0] {
        SessionOpResult::CompareAndSet(Ok(CompareAndSetResult::Conflict { current })) => {
            let current_record = current.as_ref().expect("conflict current record present");
            // The conflict record returned to caller must be properly decrypted
            assert_eq!(current_record.payload.as_bytes(), plaintext);
        }
        other => panic!("expected conflict result, got {:?}", other),
    }
}

#[tokio::test]
async fn test_classification_seam_regression() {
    let inner = Arc::new(FakeSessionBackend::new());
    let provider = test_provider();
    let backend = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "regional-cache-a",
    );
    let key = test_key();
    let lease = inner
        .acquire(
            &key,
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("lease");

    // Create envelope-shaped bytes (starts with b"OPCE" magic)
    let envelope_bytes = b"OPCE_some_fake_envelope_data_123456";

    // 1. Explicit Plaintext row with envelope-shaped bytes -> returned as-is
    inner
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: StoredSessionRecord {
                payload: EncryptedSessionPayload::new(envelope_bytes),
                ..test_record(key.clone(), 1, &lease)
            },
        })
        .await
        .expect("write plaintext row");

    let restored = backend.get(&key).await.unwrap().unwrap();
    assert_eq!(
        restored.payload.encoding(),
        SessionPayloadEncoding::Plaintext
    );
    assert_eq!(restored.payload.as_bytes(), envelope_bytes);

    // 2. Explicit LegacyPlaintext row with envelope-shaped bytes -> returned as-is
    inner
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(1)),
            new_record: StoredSessionRecord {
                payload: EncryptedSessionPayload::legacy_plaintext(envelope_bytes),
                ..test_record(key.clone(), 2, &lease)
            },
        })
        .await
        .expect("write legacy plaintext row");

    let restored = backend.get(&key).await.unwrap().unwrap();
    assert_eq!(
        restored.payload.encoding(),
        SessionPayloadEncoding::Plaintext
    ); // decrypted / restored payload is returned as Plaintext
    assert_eq!(restored.payload.as_bytes(), envelope_bytes);

    // 3. Unclassified row with envelope-shaped bytes (malformed envelope) -> falls back to plaintext
    inner
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(2)),
            new_record: StoredSessionRecord {
                payload: EncryptedSessionPayload::unclassified(envelope_bytes),
                ..test_record(key.clone(), 3, &lease)
            },
        })
        .await
        .expect("write unclassified row");

    let restored = backend.get(&key).await.unwrap().unwrap();
    assert_eq!(restored.payload.as_bytes(), envelope_bytes);

    // 4. EnvelopeV1 row with malformed envelope bytes -> fails closed!
    inner
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(3)),
            new_record: StoredSessionRecord {
                payload: EncryptedSessionPayload::envelope(envelope_bytes),
                ..test_record(key.clone(), 4, &lease)
            },
        })
        .await
        .expect("write envelope row");

    let err = backend.get(&key).await.unwrap_err();
    assert!(matches!(err, StoreError::Crypto(_)));

    // 5. Unclassified row with VALID envelope bytes -> decrypts correctly!
    let correct_envelope = EncryptedSessionPayload::encrypt(
        provider.as_ref(),
        &test_record(key.clone(), 5, &lease),
        "regional-cache-a",
    )
    .await
    .expect("encrypt");

    inner
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(4)),
            new_record: StoredSessionRecord {
                payload: EncryptedSessionPayload::unclassified(correct_envelope.as_bytes()),
                ..test_record(key.clone(), 5, &lease)
            },
        })
        .await
        .expect("write unclassified valid envelope row");

    let restored = backend.get(&key).await.unwrap().unwrap();
    assert_eq!(restored.payload.as_bytes(), b"plain-session");
}
