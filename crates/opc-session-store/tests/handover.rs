use bytes::Bytes;
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;

use opc_session_store::{
    CompareAndSet, CompareAndSetResult, EncryptedSessionPayload, Generation, HandoverEnvelope,
    HandoverEnvelopeDecodeError, HandoverEnvelopeFormat, HandoverError, HandoverManager,
    HandoverPhase, HandoverTxId, LeaseGuard, OwnerId, SessionBackend, SessionKey, SessionKeyType,
    SessionLeaseManager, SqliteSessionBackend, StateClass, StateType, StoreError,
    StoredSessionRecord, SystemClock, TokioVirtualClock, HANDOVER_ENVELOPE_MAGIC,
    HANDOVER_ENVELOPE_VERSION, HANDOVER_PHASE_HEADER_MAX_BYTES,
};
use opc_types::{NetworkFunctionKind, TenantId};

fn tenant() -> TenantId {
    TenantId::new("tenant-a").expect("tenant")
}

fn test_key(stable_id: &[u8]) -> SessionKey {
    SessionKey {
        tenant: tenant(),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::copy_from_slice(stable_id)
            .try_into()
            .expect("valid stable ID"),
    }
}

#[test]
fn typed_invalid_handover_owner_never_downgrades_to_legacy_stable() {
    let sentinel = "sensitive-owner".repeat(16);
    let phase = serde_json::to_vec(&serde_json::json!({
        "active": { "owner": sentinel.clone() }
    }))
    .expect("phase JSON");
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&(phase.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&phase);
    encoded.extend_from_slice(b"opaque-payload");

    let error = HandoverEnvelope::<Vec<u8>>::unpack_raw(&encoded).unwrap_err();
    assert_eq!(error, HandoverEnvelopeDecodeError::InvalidPhase);
    assert!(!error.to_string().contains(&sentinel));
    assert!(!format!("{error:?}").contains(&sentinel));

    let legacy = b"legacy-bare-payload";
    let decoded = HandoverEnvelope::<Vec<u8>>::unpack_raw(legacy).expect("legacy payload");
    assert_eq!(decoded.phase, HandoverPhase::Stable);
    assert_eq!(decoded.payload, legacy);

    let versioned = HandoverEnvelope {
        phase: HandoverPhase::Stable,
        payload: b"versioned-payload".to_vec(),
    }
    .pack_raw()
    .unwrap();
    assert!(versioned.starts_with(&HANDOVER_ENVELOPE_MAGIC));
    assert_eq!(
        versioned[HANDOVER_ENVELOPE_MAGIC.len()],
        HANDOVER_ENVELOPE_VERSION
    );
    let versioned = HandoverEnvelope::<Vec<u8>>::unpack_raw(&versioned).unwrap();
    assert_eq!(versioned.phase, HandoverPhase::Stable);
    assert_eq!(versioned.payload, b"versioned-payload");

    let legacy_phase = serde_json::to_vec(&HandoverPhase::Stable).unwrap();
    let mut original_format = Vec::new();
    original_format.extend_from_slice(&(legacy_phase.len() as u32).to_be_bytes());
    original_format.extend_from_slice(&legacy_phase);
    original_format.extend_from_slice(b"original-format-payload");
    let original_format = HandoverEnvelope::<Vec<u8>>::unpack_raw(&original_format).unwrap();
    assert_eq!(original_format.phase, HandoverPhase::Stable);
    assert_eq!(original_format.payload, b"original-format-payload");
}

#[test]
fn malformed_claimed_handover_headers_fail_closed() {
    let malformed_phase = b"{not-json";
    let mut malformed = Vec::new();
    malformed.extend_from_slice(&(malformed_phase.len() as u32).to_be_bytes());
    malformed.extend_from_slice(malformed_phase);

    let mut truncated = Vec::new();
    truncated.extend_from_slice(&10_u32.to_be_bytes());
    truncated.extend_from_slice(b"{");

    let mut oversized = Vec::new();
    oversized.extend_from_slice(
        &u32::try_from(HANDOVER_PHASE_HEADER_MAX_BYTES + 1)
            .unwrap()
            .to_be_bytes(),
    );
    oversized.extend_from_slice(b"{");

    let mut wrong_version = Vec::new();
    wrong_version.extend_from_slice(&HANDOVER_ENVELOPE_MAGIC);
    wrong_version.push(HANDOVER_ENVELOPE_VERSION + 1);
    wrong_version.extend_from_slice(&1_u32.to_be_bytes());
    wrong_version.push(b'"');

    let cases = [
        (
            "zero-length",
            vec![0, 0, 0, 0],
            HandoverEnvelopeDecodeError::InvalidHeader,
        ),
        (
            "malformed JSON",
            malformed,
            HandoverEnvelopeDecodeError::InvalidPhase,
        ),
        (
            "truncated",
            truncated,
            HandoverEnvelopeDecodeError::InvalidHeader,
        ),
        (
            "oversized",
            oversized,
            HandoverEnvelopeDecodeError::InvalidHeader,
        ),
        (
            "wrong version",
            wrong_version,
            HandoverEnvelopeDecodeError::InvalidHeader,
        ),
        (
            "truncated versioned prefix",
            HANDOVER_ENVELOPE_MAGIC.to_vec(),
            HandoverEnvelopeDecodeError::InvalidHeader,
        ),
    ];

    for (name, encoded, expected) in cases {
        assert_eq!(
            HandoverEnvelope::<Vec<u8>>::unpack_raw(&encoded),
            Err(expected),
            "{name} header"
        );
    }
}

#[test]
fn ambiguous_bare_handover_payloads_require_product_migration() {
    let bounded_truncated_bare = [0, 0, 0, 1];
    assert_eq!(
        HandoverEnvelope::<Vec<u8>>::unpack_raw(&bounded_truncated_bare),
        Err(HandoverEnvelopeDecodeError::InvalidHeader)
    );

    // This is valid bare JSON, but its first four bytes form an oversized
    // original-format length and the remainder looks like JSON. A product that
    // knows it is bare state must explicitly wrap it before upgrading.
    let ambiguous_json = b"[12345]";
    assert_eq!(
        HandoverEnvelope::<Vec<u8>>::unpack_raw(ambiguous_json),
        Err(HandoverEnvelopeDecodeError::InvalidHeader)
    );
    assert_eq!(
        HandoverEnvelope::<Vec<u8>>::unpack_json(ambiguous_json),
        Err(HandoverEnvelopeDecodeError::InvalidHeader)
    );
}

#[test]
fn preflight_format_is_syntactic_and_exposes_prefix_collisions() {
    let phase = serde_json::to_vec(&HandoverPhase::Stable).unwrap();
    let mut original_looking_bare = Vec::new();
    original_looking_bare.extend_from_slice(&(phase.len() as u32).to_be_bytes());
    original_looking_bare.extend_from_slice(&phase);
    original_looking_bare.extend_from_slice(b"historically-bare-product-bytes");

    let (format, _) =
        HandoverEnvelope::<Vec<u8>>::unpack_raw_with_format(&original_looking_bare).unwrap();
    assert_eq!(format, HandoverEnvelopeFormat::OriginalLengthPrefixed);

    let versioned_looking_bare = HandoverEnvelope {
        phase: HandoverPhase::Stable,
        payload: b"historically-bare-opch-collision".to_vec(),
    }
    .pack_raw()
    .unwrap();
    let (format, _) =
        HandoverEnvelope::<Vec<u8>>::unpack_raw_with_format(&versioned_looking_bare).unwrap();
    assert_eq!(format, HandoverEnvelopeFormat::VersionedV1);

    let (format, _) =
        HandoverEnvelope::<Vec<u8>>::unpack_raw_with_format(b"legacy-bare-payload").unwrap();
    assert_eq!(format, HandoverEnvelopeFormat::Bare);
}

#[tokio::test]
async fn typed_invalid_handover_owner_fails_before_backend_mutation() {
    let backend = Arc::new(SqliteSessionBackend::in_memory().unwrap());
    let key = test_key(b"invalid-envelope-owner");
    let owner = OwnerId::new("owner-a").unwrap();
    let lease = backend
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    let sentinel = "sensitive-owner".repeat(16);
    let phase = serde_json::to_vec(&serde_json::json!({
        "active": { "owner": sentinel.clone() }
    }))
    .expect("phase JSON");
    let mut payload = Vec::new();
    payload.extend_from_slice(&(phase.len() as u32).to_be_bytes());
    payload.extend_from_slice(&phase);
    payload.extend_from_slice(b"opaque-payload");
    let record = StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(1),
        owner,
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("smf-pdu-context").unwrap(),
        expires_at: None,
        payload: EncryptedSessionPayload::new(payload),
    };
    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();

    let manager = HandoverManager::new(Arc::clone(&backend), Arc::new(SystemClock));
    let error = manager
        .prepare_handover(
            &lease,
            Generation::new(1),
            HandoverTxId::new(),
            OwnerId::new("owner-b").unwrap(),
        )
        .await
        .unwrap_err();

    assert_eq!(
        error,
        HandoverError::InvalidEnvelope(HandoverEnvelopeDecodeError::InvalidPhase)
    );
    assert!(!error.to_string().contains(&sentinel));
    let json_error = match manager.get_record_json::<serde_json::Value>(&key).await {
        Ok(_) => panic!("typed-invalid JSON envelope must fail"),
        Err(error) => error,
    };
    assert_eq!(
        json_error,
        HandoverError::InvalidEnvelope(HandoverEnvelopeDecodeError::InvalidPhase)
    );
    assert_eq!(backend.get(&key).await.unwrap(), Some(record));
}

async fn setup_initial_record(
    backend: &Arc<SqliteSessionBackend>,
    key: &SessionKey,
    owner: OwnerId,
    payload: &[u8],
) -> (LeaseGuard, StoredSessionRecord) {
    let lease = backend
        .acquire(key, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    let initial_envelope = HandoverEnvelope {
        phase: HandoverPhase::Stable,
        payload: payload.to_vec(),
    };
    let payload_bytes = initial_envelope.pack_raw().unwrap();
    let record = StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(1),
        owner: owner.clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("smf-pdu-context").expect("state type"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(payload_bytes),
    };
    let cas_res = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();
    assert_eq!(cas_res, CompareAndSetResult::Success);
    (lease, record)
}

async fn setup_legacy_record(
    backend: &Arc<SqliteSessionBackend>,
    key: &SessionKey,
    owner: OwnerId,
    payload: &[u8],
) -> (LeaseGuard, StoredSessionRecord) {
    let lease = backend
        .acquire(key, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    let record = StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(1),
        owner: owner.clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("smf-pdu-context").expect("state type"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(payload),
    };
    let cas_res = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();
    assert_eq!(cas_res, CompareAndSetResult::Success);
    (lease, record)
}

#[tokio::test]
async fn test_happy_path() {
    let backend = Arc::new(SqliteSessionBackend::in_memory().unwrap());
    let manager = HandoverManager::new(backend.clone(), Arc::new(SystemClock));
    let key = test_key(b"happy-path-key");
    let owner_s = OwnerId::new("owner-source").unwrap();
    let owner_t = OwnerId::new("owner-target").unwrap();
    let tx = HandoverTxId::new();

    let (lease_s, record) =
        setup_initial_record(&backend, &key, owner_s.clone(), b"session-payload").await;
    assert_eq!(record.generation, Generation::new(1));

    // 1. Prepare
    manager
        .prepare_handover(&lease_s, Generation::new(1), tx, owner_t.clone())
        .await
        .unwrap();

    let rec = manager.get_record::<Vec<u8>>(&key).await.unwrap().unwrap();
    assert_eq!(
        rec.phase,
        HandoverPhase::Preparing {
            tx,
            target: owner_t.clone()
        }
    );
    assert_eq!(rec.payload, b"session-payload");
    assert_eq!(rec.record.generation, Generation::new(2));

    // Release S's lease so T can acquire
    backend.release(lease_s.clone()).await.unwrap();

    // 2. Mark Prepared
    let lease_t = backend
        .acquire(&key, owner_t.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    assert!(lease_t.fence().get() > lease_s.fence().get());

    manager
        .mark_prepared(&lease_t, Generation::new(2), tx)
        .await
        .unwrap();

    let rec = manager.get_record::<Vec<u8>>(&key).await.unwrap().unwrap();
    assert_eq!(
        rec.phase,
        HandoverPhase::Prepared {
            tx,
            target: owner_t.clone()
        }
    );
    assert_eq!(rec.record.generation, Generation::new(3));

    // 3. Activate
    manager
        .activate_handover(&lease_t, Generation::new(3), tx)
        .await
        .unwrap();

    let rec = manager.get_record::<Vec<u8>>(&key).await.unwrap().unwrap();
    assert_eq!(
        rec.phase,
        HandoverPhase::Activating {
            tx,
            target: owner_t.clone()
        }
    );
    assert_eq!(rec.record.generation, Generation::new(4));

    // 4. Complete
    manager
        .complete_handover(&lease_t, Generation::new(4), tx)
        .await
        .unwrap();

    let rec = manager.get_record::<Vec<u8>>(&key).await.unwrap().unwrap();
    assert_eq!(
        rec.phase,
        HandoverPhase::Active {
            owner: owner_t.clone()
        }
    );
    assert_eq!(rec.payload, b"session-payload");
    assert_eq!(rec.record.generation, Generation::new(5));
}

#[tokio::test]
async fn test_abort_from_preparing() {
    let backend = Arc::new(SqliteSessionBackend::in_memory().unwrap());
    let manager = HandoverManager::new(backend.clone(), Arc::new(SystemClock));
    let key = test_key(b"abort-preparing-key");
    let owner_s = OwnerId::new("owner-source").unwrap();
    let owner_t = OwnerId::new("owner-target").unwrap();
    let tx = HandoverTxId::new();

    let (lease_s, _record) =
        setup_initial_record(&backend, &key, owner_s.clone(), b"payload").await;

    // S prepares
    manager
        .prepare_handover(&lease_s, Generation::new(1), tx, owner_t.clone())
        .await
        .unwrap();

    // S aborts
    manager
        .abort_handover(&lease_s, Generation::new(2), tx)
        .await
        .unwrap();

    let rec = manager.get_record::<Vec<u8>>(&key).await.unwrap().unwrap();
    assert_eq!(rec.phase, HandoverPhase::Aborting { tx });

    // S finalizes abort
    manager
        .finalize_abort(&lease_s, Generation::new(3), tx, owner_s.clone())
        .await
        .unwrap();

    let rec = manager.get_record::<Vec<u8>>(&key).await.unwrap().unwrap();
    assert_eq!(rec.phase, HandoverPhase::Stable);
    assert_eq!(rec.record.owner, owner_s);

    // Release S's lease so T can acquire
    backend.release(lease_s).await.unwrap();

    // Target mark_prepared fails because phase is Stable
    let lease_t = backend
        .acquire(&key, owner_t.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    let res = manager
        .mark_prepared(&lease_t, Generation::new(4), tx)
        .await;
    assert!(matches!(res, Err(HandoverError::PhaseRegression { .. })));
}

#[tokio::test]
async fn test_abort_after_prepared() {
    let backend = Arc::new(SqliteSessionBackend::in_memory().unwrap());
    let manager = HandoverManager::new(backend.clone(), Arc::new(SystemClock));
    let key = test_key(b"abort-prepared-key");
    let owner_s = OwnerId::new("owner-source").unwrap();
    let owner_t = OwnerId::new("owner-target").unwrap();
    let tx = HandoverTxId::new();

    let (lease_s, _record) =
        setup_initial_record(&backend, &key, owner_s.clone(), b"payload").await;

    // S prepares
    manager
        .prepare_handover(&lease_s, Generation::new(1), tx, owner_t.clone())
        .await
        .unwrap();

    // Release S lease so T can acquire
    backend.release(lease_s).await.unwrap();

    // T acquires lease and prepares
    let lease_t = backend
        .acquire(&key, owner_t.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    manager
        .mark_prepared(&lease_t, Generation::new(2), tx)
        .await
        .unwrap();

    // T aborts
    manager
        .abort_handover(&lease_t, Generation::new(3), tx)
        .await
        .unwrap();

    // Release T lease so S can acquire
    backend.release(lease_t.clone()).await.unwrap();

    // S re-acquires lease
    let lease_s_new = backend
        .acquire(&key, owner_s.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    assert!(lease_s_new.fence().get() > lease_t.fence().get());

    // S finalizes abort
    manager
        .finalize_abort(&lease_s_new, Generation::new(4), tx, owner_s.clone())
        .await
        .unwrap();

    let rec = manager.get_record::<Vec<u8>>(&key).await.unwrap().unwrap();
    assert_eq!(rec.phase, HandoverPhase::Stable);

    // T tries to activate, should fail
    let res = manager
        .activate_handover(&lease_t, Generation::new(5), tx)
        .await;
    assert!(matches!(
        res,
        Err(HandoverError::PhaseRegression { .. })
            | Err(HandoverError::FencingMismatch { .. })
            | Err(HandoverError::OwnerConflict { .. })
            | Err(HandoverError::InvalidLease { .. })
    ));
}

#[tokio::test]
async fn test_retry_idempotency() {
    let backend = Arc::new(SqliteSessionBackend::in_memory().unwrap());
    let manager = HandoverManager::new(backend.clone(), Arc::new(SystemClock));
    let key = test_key(b"retry-key");
    let owner_s = OwnerId::new("owner-source").unwrap();
    let owner_t = OwnerId::new("owner-target").unwrap();
    let tx = HandoverTxId::new();

    let (lease_s, _record) =
        setup_initial_record(&backend, &key, owner_s.clone(), b"payload").await;

    // prepare_handover twice
    manager
        .prepare_handover(&lease_s, Generation::new(1), tx, owner_t.clone())
        .await
        .unwrap();
    manager
        .prepare_handover(&lease_s, Generation::new(1), tx, owner_t.clone())
        .await
        .unwrap();

    let rec = manager.get_record::<Vec<u8>>(&key).await.unwrap().unwrap();
    assert_eq!(rec.record.generation, Generation::new(2));

    // Release S lease so T can acquire
    backend.release(lease_s).await.unwrap();

    // mark_prepared twice
    let lease_t = backend
        .acquire(&key, owner_t.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    manager
        .mark_prepared(&lease_t, Generation::new(2), tx)
        .await
        .unwrap();
    manager
        .mark_prepared(&lease_t, Generation::new(2), tx)
        .await
        .unwrap();

    let rec = manager.get_record::<Vec<u8>>(&key).await.unwrap().unwrap();
    assert_eq!(rec.record.generation, Generation::new(3));

    // activate_handover twice
    manager
        .activate_handover(&lease_t, Generation::new(3), tx)
        .await
        .unwrap();
    manager
        .activate_handover(&lease_t, Generation::new(3), tx)
        .await
        .unwrap();

    let rec = manager.get_record::<Vec<u8>>(&key).await.unwrap().unwrap();
    assert_eq!(rec.record.generation, Generation::new(4));

    // complete_handover twice
    manager
        .complete_handover(&lease_t, Generation::new(4), tx)
        .await
        .unwrap();
    manager
        .complete_handover(&lease_t, Generation::new(4), tx)
        .await
        .unwrap();

    let rec = manager.get_record::<Vec<u8>>(&key).await.unwrap().unwrap();
    assert_eq!(rec.record.generation, Generation::new(5));
}

#[tokio::test]
async fn test_stale_source_rejected() {
    let backend = Arc::new(SqliteSessionBackend::in_memory().unwrap());
    let manager = HandoverManager::new(backend.clone(), Arc::new(SystemClock));
    let key = test_key(b"stale-source-key");
    let owner_s = OwnerId::new("owner-source").unwrap();
    let owner_t = OwnerId::new("owner-target").unwrap();
    let tx = HandoverTxId::new();

    let (lease_s, _record) =
        setup_initial_record(&backend, &key, owner_s.clone(), b"payload").await;

    // S prepares
    manager
        .prepare_handover(&lease_s, Generation::new(1), tx, owner_t.clone())
        .await
        .unwrap();

    // Release S lease so T can acquire
    backend.release(lease_s.clone()).await.unwrap();

    // T prepares (and fences out S)
    let lease_t = backend
        .acquire(&key, owner_t.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    manager
        .mark_prepared(&lease_t, Generation::new(2), tx)
        .await
        .unwrap();

    // S tries to write using lease_s, should fail
    let res = manager
        .abort_handover(&lease_s, Generation::new(3), tx)
        .await;
    assert!(matches!(
        res,
        Err(HandoverError::FencingMismatch { .. })
            | Err(HandoverError::Store(StoreError::StaleFence))
            | Err(HandoverError::InvalidLease { .. })
    ));
}

#[tokio::test]
async fn test_competing_transaction_rejected() {
    let backend = Arc::new(SqliteSessionBackend::in_memory().unwrap());
    let manager = HandoverManager::new(backend.clone(), Arc::new(SystemClock));
    let key = test_key(b"competing-key");
    let owner_s = OwnerId::new("owner-source").unwrap();
    let owner_t = OwnerId::new("owner-target").unwrap();
    let tx_1 = HandoverTxId::new();
    let tx_2 = HandoverTxId::new();

    let (lease_s, _record) =
        setup_initial_record(&backend, &key, owner_s.clone(), b"payload").await;

    // S prepares tx_1
    manager
        .prepare_handover(&lease_s, Generation::new(1), tx_1, owner_t.clone())
        .await
        .unwrap();

    // S tries to prepare tx_2, should fail with conflict
    let res = manager
        .prepare_handover(&lease_s, Generation::new(2), tx_2, owner_t.clone())
        .await;
    assert!(matches!(
        res,
        Err(HandoverError::TransactionConflict { .. })
    ));
}

#[tokio::test]
async fn test_durable_sqlite_restart() {
    let temp_file = NamedTempFile::new().unwrap();
    let path = temp_file.path().to_path_buf();

    let tx = HandoverTxId::new();
    let key = test_key(b"durable-key");
    let owner_s = OwnerId::new("owner-source").unwrap();
    let owner_t = OwnerId::new("owner-target").unwrap();

    {
        let backend = Arc::new(SqliteSessionBackend::open(&path).unwrap());
        let manager = HandoverManager::new(backend.clone(), Arc::new(SystemClock));

        let (lease_s, _record) =
            setup_initial_record(&backend, &key, owner_s.clone(), b"payload").await;
        manager
            .prepare_handover(&lease_s, Generation::new(1), tx, owner_t.clone())
            .await
            .unwrap();

        // Release S lease so T can acquire
        backend.release(lease_s).await.unwrap();

        let lease_t = backend
            .acquire(&key, owner_t.clone(), Duration::from_secs(60))
            .await
            .unwrap();
        manager
            .mark_prepared(&lease_t, Generation::new(2), tx)
            .await
            .unwrap();
    } // Connection dropped

    // Restart connection
    {
        let backend = Arc::new(SqliteSessionBackend::open(&path).unwrap());
        let manager = HandoverManager::new(backend.clone(), Arc::new(SystemClock));

        let rec = manager.get_record::<Vec<u8>>(&key).await.unwrap().unwrap();
        assert_eq!(
            rec.phase,
            HandoverPhase::Prepared {
                tx,
                target: owner_t.clone()
            }
        );
        assert_eq!(rec.payload, b"payload");
        assert_eq!(rec.record.generation, Generation::new(3));
    }
}

#[tokio::test]
async fn test_legacy_fallback() {
    let backend = Arc::new(SqliteSessionBackend::in_memory().unwrap());
    let manager = HandoverManager::new(backend.clone(), Arc::new(SystemClock));
    let key = test_key(b"legacy-key");
    let owner_s = OwnerId::new("owner-source").unwrap();

    // Setup a record with legacy raw payload (without envelope)
    let (_lease_s, _record) =
        setup_legacy_record(&backend, &key, owner_s.clone(), b"legacy-payload").await;

    // Get the record via HandoverManager, it should fall back to Stable and retrieve the legacy payload
    let rec = manager.get_record::<Vec<u8>>(&key).await.unwrap().unwrap();
    assert_eq!(rec.phase, HandoverPhase::Stable);
    assert_eq!(rec.payload, b"legacy-payload");
}

#[tokio::test]
async fn test_fence_tokens_boundary_conditions() {
    let backend = Arc::new(SqliteSessionBackend::in_memory().unwrap());
    let manager = HandoverManager::new(backend.clone(), Arc::new(SystemClock));
    let key = test_key(b"fence-boundary-key");
    let owner_s = OwnerId::new("owner-source").unwrap();
    let owner_t = OwnerId::new("owner-target").unwrap();
    let tx = HandoverTxId::new();

    // 1. Target acquires lease_t1 first (fence = 1)
    let lease_t1 = backend
        .acquire(&key, owner_t.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    let fence_t1 = lease_t1.fence();

    backend.release(lease_t1.clone()).await.unwrap();

    // 2. Source acquires lease_s (fence = 2)
    let lease_s_res = backend
        .acquire(&key, owner_s.clone(), Duration::from_secs(60))
        .await;
    let lease_s = lease_s_res.unwrap();

    let initial_envelope = HandoverEnvelope {
        phase: HandoverPhase::Stable,
        payload: b"payload".to_vec(),
    };
    let payload_bytes = initial_envelope.pack_raw().unwrap();
    let record = StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(1),
        owner: owner_s.clone(),
        fence: lease_s.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("smf-pdu-context").expect("state type"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(payload_bytes),
    };
    let cas_res = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease_s.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();
    assert_eq!(cas_res, CompareAndSetResult::Success);

    let fence_s = lease_s.fence();
    assert!(fence_s.get() > fence_t1.get()); // 2 > 1

    // 3. Prepare handover with S's lease (fence = 2)
    manager
        .prepare_handover(&lease_s, Generation::new(1), tx, owner_t.clone())
        .await
        .unwrap();

    // 4. Target tries to mark prepared using lease_t1 (fence = 1)
    // Since fence_t1 <= record.fence (1 <= 2), it should fail with FencingMismatch
    let res = manager
        .mark_prepared(&lease_t1, Generation::new(2), tx)
        .await;
    assert!(
        matches!(res, Err(HandoverError::FencingMismatch { provided, current }) if provided == fence_t1 && current == fence_s),
        "Expected FencingMismatch, got {res:?}"
    );

    // Release lease_s so Target can acquire lease_t2
    backend.release(lease_s.clone()).await.unwrap();

    // 5. Target acquires lease_t2 (fence = 3)
    let lease_t2 = backend
        .acquire(&key, owner_t.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    let fence_t2 = lease_t2.fence();
    assert!(fence_t2.get() > fence_s.get()); // 3 > 2

    // 6. Target successfully marks prepared using lease_t2
    manager
        .mark_prepared(&lease_t2, Generation::new(2), tx)
        .await
        .unwrap();

    // 7. Target tries to activate using lease_t1 (fence = 1)
    // Since fence_t1 < record.fence (1 < 3), it should fail with FencingMismatch
    let res = manager
        .activate_handover(&lease_t1, Generation::new(3), tx)
        .await;
    assert!(
        matches!(res, Err(HandoverError::FencingMismatch { provided, current }) if provided == fence_t1 && current == fence_t2),
        "Expected FencingMismatch, got {res:?}"
    );

    // 8. Target successfully activates using lease_t2
    manager
        .activate_handover(&lease_t2, Generation::new(3), tx)
        .await
        .unwrap();

    // 9. Target tries to complete using lease_t1 (fence = 1)
    // Since fence_t1 < record.fence (1 < 3), it should fail with FencingMismatch
    let res = manager
        .complete_handover(&lease_t1, Generation::new(4), tx)
        .await;
    assert!(
        matches!(res, Err(HandoverError::FencingMismatch { provided, current }) if provided == fence_t1 && current == fence_t2),
        "Expected FencingMismatch, got {res:?}"
    );
    backend.release(lease_t2).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn test_lease_expiration_and_owner_conflict() {
    let clock = Arc::new(TokioVirtualClock::new());
    let backend = Arc::new(
        SqliteSessionBackend::in_memory()
            .unwrap()
            .with_clock(clock.clone()),
    );
    let manager = HandoverManager::new(backend.clone(), clock);
    let key = test_key(b"lease-boundary-key");
    let owner_s = OwnerId::new("owner-source").unwrap();
    let owner_t = OwnerId::new("owner-target").unwrap();
    let owner_wrong = OwnerId::new("owner-wrong").unwrap();
    let tx = HandoverTxId::new();

    // --- Part A: Owner Conflict Tests ---

    // 1. S prepares.
    let (lease_s, _record) =
        setup_initial_record(&backend, &key, owner_s.clone(), b"payload").await;

    // Release lease_s so we can acquire lease_wrong
    backend.release(lease_s.clone()).await.unwrap();

    // Acquire lease_wrong
    let lease_wrong = backend
        .acquire(&key, owner_wrong.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    // S's record is in Stable (owner_s). lease_wrong's owner is owner_wrong.
    // Try to prepare handover -> should fail with OwnerConflict
    let res = manager
        .prepare_handover(&lease_wrong, Generation::new(1), tx, owner_t.clone())
        .await;
    assert!(
        matches!(res, Err(HandoverError::OwnerConflict { .. })),
        "Got {res:?}"
    );

    // Release lease_wrong, re-acquire lease_s
    backend.release(lease_wrong.clone()).await.unwrap();
    let lease_s_new = backend
        .acquire(&key, owner_s.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    // Prepare handover using lease_s_new
    manager
        .prepare_handover(&lease_s_new, Generation::new(1), tx, owner_t.clone())
        .await
        .unwrap();

    // Release lease_s_new, acquire lease_wrong
    backend.release(lease_s_new.clone()).await.unwrap();
    let lease_wrong2 = backend
        .acquire(&key, owner_wrong.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    // 2. Mark Prepared
    // Try to mark prepared using lease_wrong2 -> should fail with OwnerConflict (target is owner_t)
    let res = manager
        .mark_prepared(&lease_wrong2, Generation::new(2), tx)
        .await;
    assert!(
        matches!(res, Err(HandoverError::OwnerConflict { .. })),
        "Got {res:?}"
    );

    // Release lease_wrong2, acquire lease_t
    backend.release(lease_wrong2.clone()).await.unwrap();
    let lease_t = backend
        .acquire(&key, owner_t.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    // Mark Prepared successfully using lease_t
    manager
        .mark_prepared(&lease_t, Generation::new(2), tx)
        .await
        .unwrap();

    // Release lease_t, acquire lease_wrong3
    backend.release(lease_t.clone()).await.unwrap();
    let lease_wrong3 = backend
        .acquire(&key, owner_wrong.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    // 3. Activate
    // Try to activate using lease_wrong3 -> should fail with OwnerConflict (target is owner_t)
    let res = manager
        .activate_handover(&lease_wrong3, Generation::new(3), tx)
        .await;
    assert!(
        matches!(res, Err(HandoverError::OwnerConflict { .. })),
        "Got {res:?}"
    );

    // Release lease_wrong3, acquire lease_t_2
    backend.release(lease_wrong3.clone()).await.unwrap();
    let lease_t_2 = backend
        .acquire(&key, owner_t.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    // Activate successfully using lease_t_2
    manager
        .activate_handover(&lease_t_2, Generation::new(3), tx)
        .await
        .unwrap();

    // Release lease_t_2, acquire lease_wrong4
    backend.release(lease_t_2.clone()).await.unwrap();
    let lease_wrong4 = backend
        .acquire(&key, owner_wrong.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    // 4. Complete
    // Try to complete using lease_wrong4 -> should fail with OwnerConflict (target is owner_t)
    let res = manager
        .complete_handover(&lease_wrong4, Generation::new(4), tx)
        .await;
    assert!(
        matches!(res, Err(HandoverError::OwnerConflict { .. })),
        "Got {res:?}"
    );

    // Release lease_wrong4, acquire lease_t_3
    backend.release(lease_wrong4.clone()).await.unwrap();
    let lease_t_3 = backend
        .acquire(&key, owner_t.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    // Complete successfully using lease_t_3
    manager
        .complete_handover(&lease_t_3, Generation::new(4), tx)
        .await
        .unwrap();

    // --- Part B: Lease Expiration Tests ---
    // Release active lease
    backend.release(lease_t_3).await.unwrap();

    // Acquire a lease with a tiny duration (50ms)
    let lease_short = backend
        .acquire(&key, owner_t.clone(), Duration::from_millis(50))
        .await
        .unwrap();

    // Sleep to ensure lease expires
    tokio::time::advance(Duration::from_millis(100)).await;

    // Test that all methods return InvalidLease when lease is expired
    let res = manager
        .prepare_handover(&lease_short, Generation::new(4), tx, owner_s.clone())
        .await;
    assert!(
        matches!(res, Err(HandoverError::InvalidLease { .. })),
        "Got {res:?}"
    );

    let res = manager
        .mark_prepared(&lease_short, Generation::new(4), tx)
        .await;
    assert!(
        matches!(res, Err(HandoverError::InvalidLease { .. })),
        "Got {res:?}"
    );

    let res = manager
        .activate_handover(&lease_short, Generation::new(4), tx)
        .await;
    assert!(
        matches!(res, Err(HandoverError::InvalidLease { .. })),
        "Got {res:?}"
    );

    let res = manager
        .complete_handover(&lease_short, Generation::new(4), tx)
        .await;
    assert!(
        matches!(res, Err(HandoverError::InvalidLease { .. })),
        "Got {res:?}"
    );

    let res = manager
        .abort_handover(&lease_short, Generation::new(4), tx)
        .await;
    assert!(
        matches!(res, Err(HandoverError::InvalidLease { .. })),
        "Got {res:?}"
    );

    let res = manager
        .finalize_abort(&lease_short, Generation::new(4), tx, owner_s.clone())
        .await;
    assert!(
        matches!(res, Err(HandoverError::InvalidLease { .. })),
        "Got {res:?}"
    );
}

#[tokio::test]
async fn test_transaction_id_mismatch_validation() {
    let backend = Arc::new(SqliteSessionBackend::in_memory().unwrap());
    let manager = HandoverManager::new(backend.clone(), Arc::new(SystemClock));
    let key = test_key(b"tx-mismatch-key");
    let owner_s = OwnerId::new("owner-source").unwrap();
    let owner_t = OwnerId::new("owner-target").unwrap();
    let tx_1 = HandoverTxId::new();
    let tx_2 = HandoverTxId::new();

    let (lease_s, _record) =
        setup_initial_record(&backend, &key, owner_s.clone(), b"payload").await;

    // 1. Prepare with tx_1
    manager
        .prepare_handover(&lease_s, Generation::new(1), tx_1, owner_t.clone())
        .await
        .unwrap();

    // Prepare with tx_2 should fail with TransactionConflict
    let res = manager
        .prepare_handover(&lease_s, Generation::new(2), tx_2, owner_t.clone())
        .await;
    assert!(
        matches!(res, Err(HandoverError::TransactionConflict { active, received }) if active == tx_1 && received == tx_2)
    );

    // Release S lease, acquire T lease
    backend.release(lease_s.clone()).await.unwrap();
    let lease_t = backend
        .acquire(&key, owner_t.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    // 2. Mark Prepared with tx_2 should fail
    let res = manager
        .mark_prepared(&lease_t, Generation::new(2), tx_2)
        .await;
    assert!(
        matches!(res, Err(HandoverError::TransactionConflict { active, received }) if active == tx_1 && received == tx_2)
    );

    // Mark Prepared with tx_1 succeeds
    manager
        .mark_prepared(&lease_t, Generation::new(2), tx_1)
        .await
        .unwrap();

    // Mark Prepared again with tx_2 should fail (in Prepared phase)
    let res = manager
        .mark_prepared(&lease_t, Generation::new(3), tx_2)
        .await;
    assert!(
        matches!(res, Err(HandoverError::TransactionConflict { active, received }) if active == tx_1 && received == tx_2)
    );

    // 3. Activate with tx_2 should fail
    let res = manager
        .activate_handover(&lease_t, Generation::new(3), tx_2)
        .await;
    assert!(
        matches!(res, Err(HandoverError::TransactionConflict { active, received }) if active == tx_1 && received == tx_2)
    );

    // Activate with tx_1 succeeds
    manager
        .activate_handover(&lease_t, Generation::new(3), tx_1)
        .await
        .unwrap();

    // Activate again with tx_2 should fail (in Activating phase)
    let res = manager
        .activate_handover(&lease_t, Generation::new(4), tx_2)
        .await;
    assert!(
        matches!(res, Err(HandoverError::TransactionConflict { active, received }) if active == tx_1 && received == tx_2)
    );

    // 4. Complete with tx_2 should fail
    let res = manager
        .complete_handover(&lease_t, Generation::new(4), tx_2)
        .await;
    assert!(
        matches!(res, Err(HandoverError::TransactionConflict { active, received }) if active == tx_1 && received == tx_2)
    );

    // 5. Abort check with conflict (let's use abort_handover on Activating phase)
    let res = manager
        .abort_handover(&lease_t, Generation::new(4), tx_2)
        .await;
    assert!(
        matches!(res, Err(HandoverError::TransactionConflict { active, received }) if active == tx_1 && received == tx_2)
    );

    // Abort with tx_1 succeeds
    manager
        .abort_handover(&lease_t, Generation::new(4), tx_1)
        .await
        .unwrap();

    // Abort again with tx_2 should fail (in Aborting phase)
    let res = manager
        .abort_handover(&lease_t, Generation::new(5), tx_2)
        .await;
    assert!(
        matches!(res, Err(HandoverError::TransactionConflict { active, received }) if active == tx_1 && received == tx_2)
    );

    // 6. Finalize abort with tx_2 should fail
    // Release T lease, S acquires new lease to finalize rollback
    backend.release(lease_t).await.unwrap();
    let lease_s_new = backend
        .acquire(&key, owner_s.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    let res = manager
        .finalize_abort(&lease_s_new, Generation::new(5), tx_2, owner_s.clone())
        .await;
    assert!(
        matches!(res, Err(HandoverError::TransactionConflict { active, received }) if active == tx_1 && received == tx_2)
    );

    // Finalize abort with tx_1 succeeds
    manager
        .finalize_abort(&lease_s_new, Generation::new(5), tx_1, owner_s.clone())
        .await
        .unwrap();
}

#[tokio::test]
async fn test_concurrent_handover_stress() {
    use std::sync::Arc;
    use tokio::sync::mpsc;

    let backend = Arc::new(SqliteSessionBackend::in_memory().unwrap());
    let manager = Arc::new(HandoverManager::new(backend.clone(), Arc::new(SystemClock)));
    let key = test_key(b"concurrent-stress-key");
    let owner_s = OwnerId::new("owner-source").unwrap();

    // 1. Initial record
    let (lease_s, _record) =
        setup_initial_record(&backend, &key, owner_s.clone(), b"initial-payload").await;
    backend.release(lease_s).await.unwrap();

    // We will run 20 concurrent tasks, each trying to initiate preparation and take over the session
    let num_tasks = 20;
    let (tx_chan, mut rx_chan) = mpsc::channel(num_tasks);

    let mut join_handles = vec![];
    for i in 0..num_tasks {
        let manager_clone = manager.clone();
        let backend_clone = backend.clone();
        let key_clone = key.clone();
        let owner_s_clone = owner_s.clone();
        let tx_sender = tx_chan.clone();

        let handle = tokio::spawn(async move {
            let owner_t = OwnerId::new(format!("owner-target-{i}")).unwrap();
            let tx = HandoverTxId::new();

            // S acquires a temporary lease to prepare on behalf of this target.
            let Ok(lease_s) = backend_clone
                .acquire(&key_clone, owner_s_clone.clone(), Duration::from_secs(5))
                .await
            else {
                return Err("Failed to acquire source lease".to_string());
            };

            // Read current generation
            let rec = manager_clone
                .get_record::<Vec<u8>>(&key_clone)
                .await
                .unwrap()
                .unwrap();
            let gen = rec.record.generation;

            // Try to prepare
            let res = manager_clone
                .prepare_handover(&lease_s, gen, tx, owner_t.clone())
                .await;

            backend_clone.release(lease_s).await.unwrap();

            match res {
                Ok(_) => {
                    // Succeeded in preparing this transaction! Let's notify.
                    tx_sender.send((owner_t, tx)).await.unwrap();
                    Ok(true)
                }
                Err(HandoverError::Store(StoreError::CasConflict))
                | Err(HandoverError::TransactionConflict { .. }) => {
                    // Expected failures due to concurrent prepare
                    Ok(false)
                }
                Err(e) => Err(format!("Unexpected error: {e:?}")),
            }
        });
        join_handles.push(handle);
    }

    // Drop our sender so receiver terminates when all tasks finish
    drop(tx_chan);

    let mut successful_prepares = vec![];
    while let Some(msg) = rx_chan.recv().await {
        successful_prepares.push(msg);
    }

    // Join all tasks and check for any unexpected errors
    let mut success_count = 0;
    for handle in join_handles {
        let task_res = handle.await.unwrap();
        match task_res {
            Ok(succeeded) => {
                if succeeded {
                    success_count += 1;
                }
            }
            Err(e) => panic!("Task failed with error: {e}"),
        }
    }

    // Assert that exactly one prepare succeeded (due to strict locking/CAS)
    assert_eq!(
        success_count, 1,
        "Expected exactly one prepare to succeed, but got {success_count}"
    );
    assert_eq!(successful_prepares.len(), 1);

    let (winning_owner, winning_tx) = &successful_prepares[0];

    // Verify database is in preparing state for winning_owner and winning_tx
    let rec = manager.get_record::<Vec<u8>>(&key).await.unwrap().unwrap();
    assert_eq!(
        rec.phase,
        HandoverPhase::Preparing {
            tx: *winning_tx,
            target: winning_owner.clone()
        }
    );

    // Let the winning owner finish the transition
    let lease_t = backend
        .acquire(&key, winning_owner.clone(), Duration::from_secs(10))
        .await
        .unwrap();
    let gen = rec.record.generation;

    manager
        .mark_prepared(&lease_t, gen, *winning_tx)
        .await
        .unwrap();
    manager
        .activate_handover(&lease_t, gen.next().unwrap(), *winning_tx)
        .await
        .unwrap();
    manager
        .complete_handover(&lease_t, gen.next().unwrap().next().unwrap(), *winning_tx)
        .await
        .unwrap();

    // Verify final active state
    let rec = manager.get_record::<Vec<u8>>(&key).await.unwrap().unwrap();
    assert_eq!(
        rec.phase,
        HandoverPhase::Active {
            owner: winning_owner.clone()
        }
    );
}
