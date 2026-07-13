use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{stream, StreamExt};
use opc_crypto::CryptoEnvelopeV1;
use opc_key::{
    EncryptedPayload, EnvelopeAad, KeyError, KeyHandle, KeyId, KeyProvider, KeyPurpose,
    MemoryKeyProvider, MemoryRemoteSealProvider, RemoteSealProvider, Zeroizing,
    AES_256_GCM_SIV_KEY_LEN,
};
use opc_session_store::{
    BackendCapabilities, CompareAndSet, CompareAndSetResult, EncryptedSessionPayload,
    EncryptingSessionBackend, FakeSessionBackend, FenceToken, Generation, LeaseGuard, OwnerId,
    RemoteSealingSessionBackend, ReplicationEntry, ReplicationOp, RestoreScanRequest,
    SessionBackend, SessionKey, SessionKeyType, SessionLeaseManager, SessionOp, SessionOpResult,
    SessionPayloadEncoding, StateClass, StateType, StoreError, StoredSessionRecord,
    MAX_REPLICATION_OPERATIONS_PER_ENTRY, MAX_REPLICATION_OPERATION_DEPTH, MAX_SESSION_TTL,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::Duration,
};
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

fn test_remote_seal_provider() -> Arc<MemoryRemoteSealProvider> {
    Arc::new(MemoryRemoteSealProvider::new(
        KeyId::new("session-remote-2026-01").expect("key id"),
        KeyPurpose::Session,
        tenant(),
        Zeroizing::new([0x33; AES_256_GCM_SIV_KEY_LEN]),
    ))
}

fn test_key() -> SessionKey {
    SessionKey {
        tenant: tenant(),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(b"same-id")
            .try_into()
            .expect("valid stable ID"),
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

fn test_replication_entry(sequence: u64, tx_id: &str) -> ReplicationEntry {
    let key = test_key();
    ReplicationEntry {
        sequence,
        tx_id: tx_id.try_into().expect("valid transaction ID"),
        op: ReplicationOp::CompareAndSet {
            key: key.clone(),
            expected_generation: None,
            credential_id: 1,
            guard_expires_at: Timestamp::now_utc(),
            new_record: StoredSessionRecord {
                key,
                generation: Generation::new(1),
                owner: OwnerId::new("owner-a").expect("owner"),
                fence: FenceToken::new(1),
                state_class: StateClass::AuthoritativeSession,
                state_type: StateType::new("smf-pdu-context").expect("state type"),
                expires_at: None,
                payload: EncryptedSessionPayload::new(Bytes::from_static(b"plain-session")),
            },
        },
        timestamp: Timestamp::now_utc(),
    }
}

fn crypto_then_invalid_ttl_entry(sequence: u64, tx_id: &str) -> ReplicationEntry {
    let crypto_op = test_replication_entry(sequence, "crypto-canary").op;
    let timestamp = Timestamp::now_utc();
    ReplicationEntry {
        sequence,
        tx_id: tx_id.try_into().expect("valid transaction ID"),
        timestamp,
        op: ReplicationOp::Batch {
            ops: vec![
                crypto_op,
                ReplicationOp::AcquireLease {
                    key: test_key(),
                    owner: OwnerId::new("owner-a").expect("owner"),
                    fence: FenceToken::new(1),
                    credential_id: 1,
                    ttl: MAX_SESSION_TTL
                        .checked_add(Duration::from_nanos(1))
                        .expect("SDK TTL maximum has headroom"),
                    expires_at: timestamp,
                },
            ],
        },
    }
}

fn nested_replication_entry(sequence: u64, tag: &str) -> ReplicationEntry {
    let timestamp = Timestamp::now_utc();
    let key = test_key();
    let owner = OwnerId::new("owner-a").expect("owner");
    let cas = |ordinal: u64| ReplicationOp::CompareAndSet {
        key: key.clone(),
        expected_generation: None,
        credential_id: ordinal,
        guard_expires_at: timestamp,
        new_record: StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(sequence * 10 + ordinal),
            owner: owner.clone(),
            fence: FenceToken::new(ordinal),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("smf-pdu-context").expect("state type"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(Bytes::from(format!("{tag}-plain-{ordinal}"))),
        },
    };

    ReplicationEntry {
        sequence,
        tx_id: format!("{tag}-tx-{sequence}")
            .try_into()
            .expect("valid transaction ID"),
        timestamp,
        op: ReplicationOp::Batch {
            ops: vec![
                ReplicationOp::DeleteFenced {
                    key: key.clone(),
                    owner: owner.clone(),
                    fence: FenceToken::new(1),
                },
                ReplicationOp::Batch {
                    ops: vec![
                        cas(1),
                        ReplicationOp::Batch {
                            ops: vec![
                                ReplicationOp::ReleaseLease {
                                    key: key.clone(),
                                    owner: owner.clone(),
                                    fence: FenceToken::new(2),
                                    credential_id: 2,
                                },
                                cas(2),
                                ReplicationOp::Batch { ops: Vec::new() },
                            ],
                        },
                    ],
                },
                cas(3),
            ],
        },
    }
}

fn boundary_cas_op(sequence: u64, tag: &str) -> ReplicationOp {
    let mut op = test_replication_entry(sequence, tag).op;
    let ReplicationOp::CompareAndSet { new_record, .. } = &mut op else {
        panic!("boundary fixture must be a CAS");
    };
    new_record.payload = EncryptedSessionPayload::new(Bytes::from(format!("{tag}-plaintext")));
    op
}

fn wrap_operation_to_depth(mut op: ReplicationOp, depth: usize) -> ReplicationOp {
    assert!(depth > 0, "root depth is one");
    for _ in 1..depth {
        op = ReplicationOp::Batch { ops: vec![op] };
    }
    op
}

fn boundary_depth_entry(sequence: u64, depth: usize, tag: &str) -> ReplicationEntry {
    ReplicationEntry {
        sequence,
        tx_id: format!("{tag}-tx")
            .try_into()
            .expect("valid transaction ID"),
        op: wrap_operation_to_depth(boundary_cas_op(sequence, tag), depth),
        timestamp: Timestamp::now_utc(),
    }
}

fn boundary_count_entry(sequence: u64, node_count: usize, tag: &str) -> ReplicationEntry {
    assert!(node_count >= 2, "fixture needs a root and CAS child");
    let mut ops = Vec::with_capacity(node_count - 1);
    ops.push(boundary_cas_op(sequence, tag));
    ops.extend((1..(node_count - 1)).map(|_| ReplicationOp::Batch { ops: Vec::new() }));
    ReplicationEntry {
        sequence,
        tx_id: format!("{tag}-tx")
            .try_into()
            .expect("valid transaction ID"),
        op: ReplicationOp::Batch { ops },
        timestamp: Timestamp::now_utc(),
    }
}

fn replication_cas_records(op: &ReplicationOp) -> Vec<&StoredSessionRecord> {
    let mut pending = vec![op];
    let mut records = Vec::new();
    while let Some(op) = pending.pop() {
        match op {
            ReplicationOp::CompareAndSet { new_record, .. } => records.push(new_record),
            ReplicationOp::Batch { ops } => pending.extend(ops.iter().rev()),
            ReplicationOp::DeleteFenced { .. }
            | ReplicationOp::RefreshTtl { .. }
            | ReplicationOp::AcquireLease { .. }
            | ReplicationOp::RenewLease { .. }
            | ReplicationOp::ReleaseLease { .. } => {}
        }
    }
    records
}

#[derive(Default)]
struct CapturingReplicationBackend {
    entries: StdMutex<Vec<ReplicationEntry>>,
    replicate_calls: AtomicUsize,
    rebuild_calls: AtomicUsize,
}

impl CapturingReplicationBackend {
    fn entries(&self) -> Vec<ReplicationEntry> {
        self.entries.lock().expect("capture lock").clone()
    }
}

#[async_trait]
impl SessionBackend for CapturingReplicationBackend {
    async fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::minimal()
    }

    async fn get(&self, _key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "test backend get".into(),
        ))
    }

    async fn compare_and_set(&self, _op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "test backend compare_and_set".into(),
        ))
    }

    async fn delete_fenced(&self, _lease: &LeaseGuard) -> Result<(), StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "test backend delete_fenced".into(),
        ))
    }

    async fn refresh_ttl(&self, _lease: &LeaseGuard, _ttl: Duration) -> Result<(), StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "test backend refresh_ttl".into(),
        ))
    }

    async fn batch(&self, _ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "test backend batch".into(),
        ))
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        Ok(self
            .entries()
            .into_iter()
            .filter(|entry| entry.sequence >= start)
            .take(limit)
            .collect())
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        self.replicate_calls.fetch_add(1, Ordering::SeqCst);
        self.entries.lock().expect("capture lock").push(entry);
        Ok(())
    }

    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        self.rebuild_calls.fetch_add(1, Ordering::SeqCst);
        *self.entries.lock().expect("capture lock") = entries;
        Ok(())
    }

    async fn watch(
        &self,
        start_sequence: u64,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
        StoreError,
    > {
        let entries = self
            .entries()
            .into_iter()
            .filter(move |entry| entry.sequence >= start_sequence)
            .map(Ok);
        Ok(stream::iter(entries).boxed())
    }
}

struct FailOnCallKeyProvider {
    inner: Arc<MemoryKeyProvider>,
    fail_on: usize,
    calls: AtomicUsize,
}

impl FailOnCallKeyProvider {
    fn new(inner: Arc<MemoryKeyProvider>, fail_on: usize) -> Self {
        Self {
            inner,
            fail_on,
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn fail_this_call(&self) -> bool {
        self.calls.fetch_add(1, Ordering::SeqCst) + 1 == self.fail_on
    }
}

#[async_trait]
impl KeyProvider for FailOnCallKeyProvider {
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyHandle, KeyError> {
        if self.fail_this_call() {
            return Err(KeyError::Unavailable);
        }
        self.inner.get_active_key(purpose, tenant).await
    }

    async fn get_key_by_id(&self, key_id: &KeyId) -> Result<KeyHandle, KeyError> {
        if self.fail_this_call() {
            return Err(KeyError::Unavailable);
        }
        self.inner.get_key_by_id(key_id).await
    }

    async fn rotate_key(&self, purpose: KeyPurpose, tenant: &TenantId) -> Result<KeyId, KeyError> {
        if self.fail_this_call() {
            return Err(KeyError::Unavailable);
        }
        self.inner.rotate_key(purpose, tenant).await
    }
}

struct FailOnCallRemoteSealProvider {
    inner: Arc<MemoryRemoteSealProvider>,
    fail_on: usize,
    calls: AtomicUsize,
}

impl FailOnCallRemoteSealProvider {
    fn new(inner: Arc<MemoryRemoteSealProvider>, fail_on: usize) -> Self {
        Self {
            inner,
            fail_on,
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn fail_this_call(&self) -> bool {
        self.calls.fetch_add(1, Ordering::SeqCst) + 1 == self.fail_on
    }
}

#[async_trait]
impl RemoteSealProvider for FailOnCallRemoteSealProvider {
    async fn seal(
        &self,
        aad: &EnvelopeAad,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, KeyError> {
        if self.fail_this_call() {
            return Err(KeyError::Unavailable);
        }
        self.inner.seal(aad, plaintext).await
    }

    async fn unseal(
        &self,
        key_id: &KeyId,
        aad: &EnvelopeAad,
        ciphertext_and_tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        if self.fail_this_call() {
            return Err(KeyError::Unavailable);
        }
        self.inner.unseal(key_id, aad, ciphertext_and_tag).await
    }
}

fn assert_nested_entry_protected(
    original: &ReplicationEntry,
    protected: &ReplicationEntry,
    algorithm: opc_key::AeadAlgorithm,
) {
    assert_eq!(protected.sequence, original.sequence);
    assert_eq!(protected.tx_id, original.tx_id);
    assert_eq!(protected.timestamp, original.timestamp);

    let original_records = replication_cas_records(&original.op);
    let protected_records = replication_cas_records(&protected.op);
    assert_eq!(protected_records.len(), original_records.len());

    for (original_record, protected_record) in original_records.into_iter().zip(protected_records) {
        assert_eq!(
            protected_record.payload.encoding(),
            SessionPayloadEncoding::EnvelopeV1
        );
        assert_ne!(
            protected_record.payload.as_bytes(),
            original_record.payload.as_bytes()
        );
        let envelope = CryptoEnvelopeV1::decode(protected_record.payload.as_bytes())
            .expect("protected nested payload envelope");
        assert_eq!(envelope.algorithm, algorithm);

        let mut normalized = protected_record.clone();
        normalized.payload = original_record.payload.clone();
        assert_eq!(&normalized, original_record);
    }
}

fn corrupt_nth_nested_cas(op: &mut ReplicationOp, target: usize, canary: &'static [u8]) {
    let mut pending = vec![op];
    let mut seen = 0_usize;
    while let Some(op) = pending.pop() {
        match op {
            ReplicationOp::CompareAndSet { new_record, .. } => {
                seen += 1;
                if seen == target {
                    let mut envelope = CryptoEnvelopeV1::decode(new_record.payload.as_bytes())
                        .expect("captured payload is an envelope");
                    envelope.ciphertext_and_tag = canary.to_vec();
                    envelope
                        .ciphertext_and_tag
                        .extend_from_slice(&[0xA5; opc_key::AEAD_TAG_LEN]);
                    new_record.payload = EncryptedSessionPayload::try_envelope(
                        envelope.encode().expect("encode corrupt test envelope"),
                    )
                    .expect("structurally valid corrupt test envelope");
                    return;
                }
            }
            ReplicationOp::Batch { ops } => pending.extend(ops.iter_mut().rev()),
            ReplicationOp::DeleteFenced { .. }
            | ReplicationOp::RefreshTtl { .. }
            | ReplicationOp::AcquireLease { .. }
            | ReplicationOp::RenewLease { .. }
            | ReplicationOp::ReleaseLease { .. } => {}
        }
    }
    panic!("test fixture did not contain requested nested CAS");
}

async fn collect_watch_entries<B: SessionBackend + ?Sized>(
    backend: &B,
    start_sequence: u64,
    expected: usize,
) -> Vec<ReplicationEntry> {
    let mut watch = backend.watch(start_sequence).await.expect("watch");
    let mut entries = Vec::with_capacity(expected);
    for _ in 0..expected {
        entries.push(
            watch
                .next()
                .await
                .expect("watch entry")
                .expect("valid watch entry"),
        );
    }
    entries
}

#[tokio::test]
async fn encrypting_wrapper_protects_every_nested_cas_across_replication_paths() {
    let inner = Arc::new(CapturingReplicationBackend::default());
    let backend = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        test_provider(),
        "recursive-local-boundary",
    );
    let first = nested_replication_entry(1, "local-first-canary");
    let second = nested_replication_entry(2, "local-second-canary");

    backend
        .replicate_entry(first.clone())
        .await
        .expect("replicate nested entry");
    let captured = inner.entries();
    assert_eq!(inner.replicate_calls.load(Ordering::SeqCst), 1);
    assert_nested_entry_protected(&first, &captured[0], opc_key::AeadAlgorithm::Aes256GcmSiv);
    assert_eq!(
        backend
            .get_replication_log(1, 1)
            .await
            .expect("decrypted log"),
        vec![first.clone()]
    );
    assert_eq!(
        collect_watch_entries(&backend, 1, 1).await,
        vec![first.clone()]
    );

    let expected = vec![first, second];
    backend
        .rebuild_replication_state(expected.clone())
        .await
        .expect("rebuild nested entries");
    assert_eq!(inner.rebuild_calls.load(Ordering::SeqCst), 1);
    let captured = inner.entries();
    for (original, protected) in expected.iter().zip(&captured) {
        assert_nested_entry_protected(original, protected, opc_key::AeadAlgorithm::Aes256GcmSiv);
    }
    assert_eq!(
        backend
            .get_replication_log(1, expected.len())
            .await
            .expect("decrypted rebuilt log"),
        expected
    );
    assert_eq!(collect_watch_entries(&backend, 1, 2).await, expected);
}

#[tokio::test]
async fn remote_sealing_wrapper_protects_every_nested_cas_across_replication_paths() {
    let inner = Arc::new(CapturingReplicationBackend::default());
    let backend = RemoteSealingSessionBackend::new(
        Arc::clone(&inner),
        test_remote_seal_provider(),
        "recursive-remote-boundary",
    );
    let first = nested_replication_entry(1, "remote-first-canary");
    let second = nested_replication_entry(2, "remote-second-canary");

    backend
        .replicate_entry(first.clone())
        .await
        .expect("replicate nested entry");
    let captured = inner.entries();
    assert_eq!(inner.replicate_calls.load(Ordering::SeqCst), 1);
    assert_nested_entry_protected(&first, &captured[0], opc_key::AeadAlgorithm::RemoteSeal);
    assert_eq!(
        backend
            .get_replication_log(1, 1)
            .await
            .expect("unsealed log"),
        vec![first.clone()]
    );
    assert_eq!(
        collect_watch_entries(&backend, 1, 1).await,
        vec![first.clone()]
    );

    let expected = vec![first, second];
    backend
        .rebuild_replication_state(expected.clone())
        .await
        .expect("rebuild nested entries");
    assert_eq!(inner.rebuild_calls.load(Ordering::SeqCst), 1);
    let captured = inner.entries();
    for (original, protected) in expected.iter().zip(&captured) {
        assert_nested_entry_protected(original, protected, opc_key::AeadAlgorithm::RemoteSeal);
    }
    assert_eq!(
        backend
            .get_replication_log(1, expected.len())
            .await
            .expect("unsealed rebuilt log"),
        expected
    );
    assert_eq!(collect_watch_entries(&backend, 1, 2).await, expected);
}

#[tokio::test]
async fn both_wrappers_transform_cas_at_the_exact_depth_and_count_limits() {
    let mut expected = (1..=MAX_REPLICATION_OPERATION_DEPTH)
        .map(|depth| {
            boundary_depth_entry(
                u64::try_from(depth).expect("test depth fits u64"),
                depth,
                &format!("depth-{depth}-canary"),
            )
        })
        .collect::<Vec<_>>();
    expected.push(boundary_count_entry(
        u64::try_from(expected.len() + 1).expect("test sequence fits u64"),
        MAX_REPLICATION_OPERATIONS_PER_ENTRY,
        "exact-count-canary",
    ));

    let local_inner = Arc::new(CapturingReplicationBackend::default());
    let local = EncryptingSessionBackend::new(
        Arc::clone(&local_inner),
        test_provider(),
        "exact-local-boundary",
    );
    local
        .rebuild_replication_state(expected.clone())
        .await
        .expect("local wrapper accepts exact structural limits");
    for (original, protected) in expected.iter().zip(local_inner.entries()) {
        assert_nested_entry_protected(original, &protected, opc_key::AeadAlgorithm::Aes256GcmSiv);
    }
    assert_eq!(
        local
            .get_replication_log(1, expected.len())
            .await
            .expect("local exact-limit round trip"),
        expected
    );

    let remote_inner = Arc::new(CapturingReplicationBackend::default());
    let remote = RemoteSealingSessionBackend::new(
        Arc::clone(&remote_inner),
        test_remote_seal_provider(),
        "exact-remote-boundary",
    );
    remote
        .rebuild_replication_state(expected.clone())
        .await
        .expect("remote wrapper accepts exact structural limits");
    for (original, protected) in expected.iter().zip(remote_inner.entries()) {
        assert_nested_entry_protected(original, &protected, opc_key::AeadAlgorithm::RemoteSeal);
    }
    assert_eq!(
        remote
            .get_replication_log(1, expected.len())
            .await
            .expect("remote exact-limit round trip"),
        expected
    );
}

#[tokio::test]
async fn encrypting_wrapper_rejects_structure_limits_before_provider_or_backend_effects() {
    let returned = boundary_depth_entry(
        1,
        MAX_REPLICATION_OPERATION_DEPTH + 1,
        "local-returned-over-depth",
    );
    let provider = Arc::new(CountingKeyProvider::new(test_provider()));
    let inner = Arc::new(ReplicationBoundarySpy::returning(vec![returned]));
    let backend = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "local-structure-rejection",
    );

    let error = backend
        .replicate_entry(boundary_depth_entry(
            1,
            MAX_REPLICATION_OPERATION_DEPTH + 1,
            "local-input-over-depth",
        ))
        .await
        .expect_err("over-depth replicate must fail before encryption");
    assert_eq!(error, StoreError::ReplicationOperationLimitExceeded);
    let error = backend
        .rebuild_replication_state(vec![
            boundary_depth_entry(1, MAX_REPLICATION_OPERATION_DEPTH, "local-prefix-valid"),
            boundary_count_entry(
                2,
                MAX_REPLICATION_OPERATIONS_PER_ENTRY + 1,
                "local-prefix-over-count",
            ),
        ])
        .await
        .expect_err("whole over-count prefix must fail before encryption");
    assert_eq!(error, StoreError::ReplicationOperationLimitExceeded);
    let error = backend
        .get_replication_log(1, 1)
        .await
        .expect_err("over-depth returned log must fail before decryption");
    assert_eq!(error, StoreError::ReplicationOperationLimitExceeded);
    assert_eq!(provider.calls(), 0);
    assert_eq!(inner.replicate_calls.load(Ordering::SeqCst), 0);
    assert_eq!(inner.rebuild_calls.load(Ordering::SeqCst), 0);

    let watch_inner = Arc::new(CapturingReplicationBackend::default());
    watch_inner
        .entries
        .lock()
        .expect("capture lock")
        .push(boundary_count_entry(
            1,
            MAX_REPLICATION_OPERATIONS_PER_ENTRY + 1,
            "local-watch-over-count",
        ));
    let watch_backend = EncryptingSessionBackend::new(
        watch_inner,
        Arc::clone(&provider),
        "local-watch-structure-rejection",
    );
    let mut watch = watch_backend.watch(1).await.expect("watch");
    assert_eq!(
        watch.next().await.expect("watch item"),
        Err(StoreError::ReplicationOperationLimitExceeded)
    );
    assert_eq!(provider.calls(), 0);
}

#[tokio::test]
async fn remote_wrapper_rejects_structure_limits_before_provider_or_backend_effects() {
    let returned = boundary_depth_entry(
        1,
        MAX_REPLICATION_OPERATION_DEPTH + 1,
        "remote-returned-over-depth",
    );
    let provider = Arc::new(CountingRemoteSealProvider::new(test_remote_seal_provider()));
    let inner = Arc::new(ReplicationBoundarySpy::returning(vec![returned]));
    let backend = RemoteSealingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "remote-structure-rejection",
    );

    let error = backend
        .replicate_entry(boundary_depth_entry(
            1,
            MAX_REPLICATION_OPERATION_DEPTH + 1,
            "remote-input-over-depth",
        ))
        .await
        .expect_err("over-depth replicate must fail before sealing");
    assert_eq!(error, StoreError::ReplicationOperationLimitExceeded);
    let error = backend
        .rebuild_replication_state(vec![
            boundary_depth_entry(1, MAX_REPLICATION_OPERATION_DEPTH, "remote-prefix-valid"),
            boundary_count_entry(
                2,
                MAX_REPLICATION_OPERATIONS_PER_ENTRY + 1,
                "remote-prefix-over-count",
            ),
        ])
        .await
        .expect_err("whole over-count prefix must fail before sealing");
    assert_eq!(error, StoreError::ReplicationOperationLimitExceeded);
    let error = backend
        .get_replication_log(1, 1)
        .await
        .expect_err("over-depth returned log must fail before unsealing");
    assert_eq!(error, StoreError::ReplicationOperationLimitExceeded);
    assert_eq!(provider.calls(), 0);
    assert_eq!(inner.replicate_calls.load(Ordering::SeqCst), 0);
    assert_eq!(inner.rebuild_calls.load(Ordering::SeqCst), 0);

    let watch_inner = Arc::new(CapturingReplicationBackend::default());
    watch_inner
        .entries
        .lock()
        .expect("capture lock")
        .push(boundary_count_entry(
            1,
            MAX_REPLICATION_OPERATIONS_PER_ENTRY + 1,
            "remote-watch-over-count",
        ));
    let watch_backend = RemoteSealingSessionBackend::new(
        watch_inner,
        Arc::clone(&provider),
        "remote-watch-structure-rejection",
    );
    let mut watch = watch_backend.watch(1).await.expect("watch");
    assert_eq!(
        watch.next().await.expect("watch item"),
        Err(StoreError::ReplicationOperationLimitExceeded)
    );
    assert_eq!(provider.calls(), 0);
}

#[tokio::test]
async fn late_local_provider_failure_never_delegates_nested_replication() {
    let inner = Arc::new(CapturingReplicationBackend::default());
    let provider = Arc::new(FailOnCallKeyProvider::new(test_provider(), 3));
    let backend = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "late-local-failure",
    );
    let error = backend
        .replicate_entry(nested_replication_entry(1, "local-late-secret-canary"))
        .await
        .expect_err("third nested CAS must fail");
    assert!(matches!(error, StoreError::Crypto(_)));
    assert_eq!(provider.calls(), 3);
    assert_eq!(inner.replicate_calls.load(Ordering::SeqCst), 0);
    assert!(inner.entries().is_empty());
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("local-late-secret-canary"));

    let inner = Arc::new(CapturingReplicationBackend::default());
    let provider = Arc::new(FailOnCallKeyProvider::new(test_provider(), 4));
    let backend = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "late-local-rebuild-failure",
    );
    let error = backend
        .rebuild_replication_state(vec![
            test_replication_entry(1, "local-rebuild-first"),
            nested_replication_entry(2, "local-rebuild-secret-canary"),
        ])
        .await
        .expect_err("final nested CAS must fail rebuild staging");
    assert!(matches!(error, StoreError::Crypto(_)));
    assert_eq!(provider.calls(), 4);
    assert_eq!(inner.rebuild_calls.load(Ordering::SeqCst), 0);
    assert!(inner.entries().is_empty());
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("local-rebuild-secret-canary"));
}

#[tokio::test]
async fn late_remote_provider_failure_never_delegates_nested_replication() {
    let inner = Arc::new(CapturingReplicationBackend::default());
    let provider = Arc::new(FailOnCallRemoteSealProvider::new(
        test_remote_seal_provider(),
        3,
    ));
    let backend = RemoteSealingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "late-remote-failure",
    );
    let error = backend
        .replicate_entry(nested_replication_entry(1, "remote-late-secret-canary"))
        .await
        .expect_err("third nested CAS must fail");
    assert!(matches!(error, StoreError::Crypto(_)));
    assert_eq!(provider.calls(), 3);
    assert_eq!(inner.replicate_calls.load(Ordering::SeqCst), 0);
    assert!(inner.entries().is_empty());
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("remote-late-secret-canary"));

    let inner = Arc::new(CapturingReplicationBackend::default());
    let provider = Arc::new(FailOnCallRemoteSealProvider::new(
        test_remote_seal_provider(),
        4,
    ));
    let backend = RemoteSealingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "late-remote-rebuild-failure",
    );
    let error = backend
        .rebuild_replication_state(vec![
            test_replication_entry(1, "remote-rebuild-first"),
            nested_replication_entry(2, "remote-rebuild-secret-canary"),
        ])
        .await
        .expect_err("final nested CAS must fail rebuild staging");
    assert!(matches!(error, StoreError::Crypto(_)));
    assert_eq!(provider.calls(), 4);
    assert_eq!(inner.rebuild_calls.load(Ordering::SeqCst), 0);
    assert!(inner.entries().is_empty());
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("remote-rebuild-secret-canary"));
}

#[tokio::test]
async fn nested_read_failure_never_returns_partially_unprotected_entries() {
    let local_inner = Arc::new(CapturingReplicationBackend::default());
    let local = EncryptingSessionBackend::new(
        Arc::clone(&local_inner),
        test_provider(),
        "local-read-failure",
    );
    local
        .replicate_entry(nested_replication_entry(1, "local-read-secret-canary"))
        .await
        .expect("seed protected local entry");
    corrupt_nth_nested_cas(
        &mut local_inner.entries.lock().expect("capture lock")[0].op,
        3,
        b"local-corrupt-envelope-canary",
    );
    let error = local
        .get_replication_log(1, 1)
        .await
        .expect_err("late corrupt local CAS must reject whole page");
    assert!(matches!(error, StoreError::Crypto(_)));
    assert!(!format!("{error} {error:?}").contains("local-corrupt-envelope-canary"));
    let mut watch = local.watch(1).await.expect("local watch");
    assert!(matches!(
        watch.next().await.expect("local watch item"),
        Err(StoreError::Crypto(_))
    ));

    let remote_inner = Arc::new(CapturingReplicationBackend::default());
    let remote = RemoteSealingSessionBackend::new(
        Arc::clone(&remote_inner),
        test_remote_seal_provider(),
        "remote-read-failure",
    );
    remote
        .replicate_entry(nested_replication_entry(1, "remote-read-secret-canary"))
        .await
        .expect("seed protected remote entry");
    corrupt_nth_nested_cas(
        &mut remote_inner.entries.lock().expect("capture lock")[0].op,
        3,
        b"remote-corrupt-envelope-canary",
    );
    let error = remote
        .get_replication_log(1, 1)
        .await
        .expect_err("late corrupt remote CAS must reject whole page");
    assert!(matches!(error, StoreError::Crypto(_)));
    assert!(!format!("{error} {error:?}").contains("remote-corrupt-envelope-canary"));
    let mut watch = remote.watch(1).await.expect("remote watch");
    assert!(matches!(
        watch.next().await.expect("remote watch item"),
        Err(StoreError::Crypto(_))
    ));
}

struct BarrierKeyProvider {
    inner: Arc<MemoryKeyProvider>,
    read_barrier: Arc<Barrier>,
}

struct CountingKeyProvider {
    inner: Arc<MemoryKeyProvider>,
    calls: AtomicUsize,
}

impl CountingKeyProvider {
    fn new(inner: Arc<MemoryKeyProvider>) -> Self {
        Self {
            inner,
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl KeyProvider for CountingKeyProvider {
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyHandle, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_active_key(purpose, tenant).await
    }

    async fn get_key_by_id(&self, key_id: &KeyId) -> Result<KeyHandle, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_key_by_id(key_id).await
    }

    async fn rotate_key(&self, purpose: KeyPurpose, tenant: &TenantId) -> Result<KeyId, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.rotate_key(purpose, tenant).await
    }
}

struct CountingRemoteSealProvider {
    inner: Arc<MemoryRemoteSealProvider>,
    calls: AtomicUsize,
}

impl CountingRemoteSealProvider {
    fn new(inner: Arc<MemoryRemoteSealProvider>) -> Self {
        Self {
            inner,
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl RemoteSealProvider for CountingRemoteSealProvider {
    async fn seal(
        &self,
        aad: &EnvelopeAad,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.seal(aad, plaintext).await
    }

    async fn unseal(
        &self,
        key_id: &KeyId,
        aad: &EnvelopeAad,
        ciphertext_and_tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.unseal(key_id, aad, ciphertext_and_tag).await
    }
}

struct ReplicationBoundarySpy {
    returned_entries: Vec<ReplicationEntry>,
    log_reads: AtomicUsize,
    replicate_calls: AtomicUsize,
    rebuild_calls: AtomicUsize,
}

impl ReplicationBoundarySpy {
    fn returning(returned_entries: Vec<ReplicationEntry>) -> Self {
        Self {
            returned_entries,
            log_reads: AtomicUsize::new(0),
            replicate_calls: AtomicUsize::new(0),
            rebuild_calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl SessionBackend for ReplicationBoundarySpy {
    async fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::minimal()
    }

    async fn get(&self, _key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "test backend get".into(),
        ))
    }

    async fn compare_and_set(&self, _op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "test backend compare_and_set".into(),
        ))
    }

    async fn delete_fenced(&self, _lease: &LeaseGuard) -> Result<(), StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "test backend delete_fenced".into(),
        ))
    }

    async fn refresh_ttl(&self, _lease: &LeaseGuard, _ttl: Duration) -> Result<(), StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "test backend refresh_ttl".into(),
        ))
    }

    async fn batch(&self, _ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "test backend batch".into(),
        ))
    }

    async fn get_replication_log(
        &self,
        _start: u64,
        _limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        self.log_reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.returned_entries.clone())
    }

    async fn replicate_entry(&self, _entry: ReplicationEntry) -> Result<(), StoreError> {
        self.replicate_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn rebuild_replication_state(
        &self,
        _entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        self.rebuild_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
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

    let scan_page = backend
        .scan_restore_records(RestoreScanRequest::all(16))
        .await
        .expect("restore scan");
    assert_eq!(scan_page.loaded_count, 1);
    assert_eq!(scan_page.records[0].payload.as_bytes(), &batch_payload);

    let inner_scan_page = inner
        .scan_restore_records(RestoreScanRequest::all(16))
        .await
        .expect("inner restore scan");
    assert_ne!(
        inner_scan_page.records[0].payload.as_bytes(),
        &batch_payload
    );
}

#[tokio::test]
async fn remote_sealing_session_backend_round_trips_compare_and_set_get_and_batch_results() {
    let inner = Arc::new(FakeSessionBackend::new());
    let provider = test_remote_seal_provider();
    let backend = RemoteSealingSessionBackend::new(
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

    let result = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: test_record(key.clone(), 1, &lease),
        })
        .await
        .expect("write");
    assert_eq!(result, CompareAndSetResult::Success);

    let inner_record = inner.get(&key).await.expect("inner get").expect("stored");
    assert_ne!(inner_record.payload.as_bytes(), b"plain-session");
    let envelope = CryptoEnvelopeV1::decode(inner_record.payload.as_bytes()).expect("envelope");
    assert_eq!(envelope.algorithm, opc_key::AeadAlgorithm::RemoteSeal);
    assert!(envelope.nonce.is_empty());

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

    let batch_payload = Bytes::from_static(b"plain-session-batch");
    let results = backend
        .batch(vec![
            SessionOp::Get { key: key.clone() },
            SessionOp::CompareAndSet(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: Some(Generation::new(1)),
                new_record: StoredSessionRecord {
                    payload: EncryptedSessionPayload::new(batch_payload.clone()),
                    ..test_record(key.clone(), 2, &lease)
                },
            }),
        ])
        .await
        .expect("batch");

    match &results[0] {
        SessionOpResult::Get(Ok(Some(record))) => {
            assert_eq!(record.payload.as_bytes(), b"plain-session");
        }
        other => panic!("unexpected get result: {other:?}"),
    }
    assert!(matches!(
        &results[1],
        SessionOpResult::CompareAndSet(Ok(CompareAndSetResult::Success))
    ));

    let scan_page = backend
        .scan_restore_records(RestoreScanRequest::all(16))
        .await
        .expect("restore scan");
    assert_eq!(scan_page.loaded_count, 1);
    assert_eq!(scan_page.records[0].payload.as_bytes(), &batch_payload);
}

#[tokio::test]
async fn remote_sealing_session_backend_reads_before_and_after_rotation() {
    let inner = Arc::new(FakeSessionBackend::new());
    let provider = test_remote_seal_provider();
    let backend = RemoteSealingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "regional-cache-a",
    );
    let before_key = test_key();
    let after_key = SessionKey {
        stable_id: Bytes::from_static(b"after-rotation")
            .try_into()
            .expect("valid stable ID"),
        ..before_key.clone()
    };

    let before_lease = backend
        .acquire(
            &before_key,
            OwnerId::new("owner-before").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("pre-rotation lease");
    backend
        .compare_and_set(CompareAndSet {
            key: before_key.clone(),
            lease: before_lease.clone(),
            expected_generation: None,
            new_record: StoredSessionRecord {
                payload: EncryptedSessionPayload::new(b"before rotation"),
                ..test_record(before_key.clone(), 1, &before_lease)
            },
        })
        .await
        .expect("pre-rotation write");

    let old_key_id = provider.active_key_id().await.expect("old key ID");
    let new_key_id = provider.rotate_key().await.expect("rotate remote key");
    assert_ne!(old_key_id, new_key_id);

    let after_lease = backend
        .acquire(
            &after_key,
            OwnerId::new("owner-after").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("post-rotation lease");
    backend
        .compare_and_set(CompareAndSet {
            key: after_key.clone(),
            lease: after_lease.clone(),
            expected_generation: None,
            new_record: StoredSessionRecord {
                payload: EncryptedSessionPayload::new(b"after rotation"),
                ..test_record(after_key.clone(), 1, &after_lease)
            },
        })
        .await
        .expect("post-rotation write");

    for (key, expected) in [
        (&before_key, b"before rotation".as_slice()),
        (&after_key, b"after rotation".as_slice()),
    ] {
        let restored = backend
            .get(key)
            .await
            .expect("current provider read")
            .expect("stored record");
        assert_eq!(restored.payload.as_bytes(), expected);
    }

    let before_envelope = CryptoEnvelopeV1::decode(
        inner
            .get(&before_key)
            .await
            .expect("raw read")
            .expect("raw before record")
            .payload
            .as_bytes(),
    )
    .expect("before envelope");
    let after_envelope = CryptoEnvelopeV1::decode(
        inner
            .get(&after_key)
            .await
            .expect("raw read")
            .expect("raw after record")
            .payload
            .as_bytes(),
    )
    .expect("after envelope");
    assert_eq!(before_envelope.key_id, old_key_id);
    assert_eq!(after_envelope.key_id, new_key_id);
}

#[tokio::test]
async fn remote_historical_lookup_validates_scope_before_provider_and_redacts_failure() {
    let inner = Arc::new(FakeSessionBackend::new());
    let provider = test_remote_seal_provider();
    let backend = RemoteSealingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "regional-cache-a",
    );
    let key = test_key();
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("historical-owner").expect("owner"),
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
        .expect("seed remote envelope");
    let raw = inner.get(&key).await.expect("raw read").expect("record");

    let counting = CountingRemoteSealProvider::new(Arc::clone(&provider));
    let mut oversized_key_envelope = raw.payload.as_bytes().to_vec();
    let original_key_len = usize::from(u16::from_be_bytes([
        oversized_key_envelope[8],
        oversized_key_envelope[9],
    ]));
    let oversized_key_id = vec![b'k'; 513];
    oversized_key_envelope[8..10].copy_from_slice(&513_u16.to_be_bytes());
    oversized_key_envelope.splice(16..16 + original_key_len, oversized_key_id);
    let malformed = EncryptedSessionPayload::try_envelope(oversized_key_envelope)
        .expect_err("oversized historical key ID must fail canonical decode");
    assert!(matches!(malformed, StoreError::Crypto(_)));
    assert_eq!(counting.calls(), 0, "malformed key ID reached provider");

    let wrong_tenant_key = SessionKey {
        tenant: TenantId::new("tenant-b-sensitive").expect("tenant"),
        ..key.clone()
    };
    let wrong_tenant = raw
        .payload
        .remote_unseal(
            &counting,
            &wrong_tenant_key,
            &raw.state_type,
            raw.generation,
            raw.fence,
            "regional-cache-a",
        )
        .await
        .expect_err("cross-tenant envelope use must fail");
    assert_eq!(counting.calls(), 0, "wrong tenant reached provider");

    let wrong_aad = raw
        .payload
        .remote_unseal(
            &counting,
            &key,
            &raw.state_type,
            raw.generation,
            raw.fence,
            "wrong-sensitive-namespace",
        )
        .await
        .expect_err("wrong AAD must fail");
    assert_eq!(counting.calls(), 0, "wrong AAD reached provider");

    let missing_provider = Arc::new(MemoryRemoteSealProvider::new(
        KeyId::new("unknown-historical-sensitive-id").expect("key ID"),
        KeyPurpose::Session,
        tenant(),
        Zeroizing::new([0x91; AES_256_GCM_SIV_KEY_LEN]),
    ));
    let missing_reader =
        RemoteSealingSessionBackend::new(Arc::clone(&inner), missing_provider, "regional-cache-a");
    let unknown = missing_reader
        .get(&key)
        .await
        .expect_err("unknown historical key must fail closed");

    for error in [wrong_tenant, wrong_aad, unknown] {
        assert_eq!(
            error,
            StoreError::Crypto("session envelope decryption failed".into())
        );
        let rendered = format!("{error} {error:?}");
        for secret in [
            "session-remote-2026-01",
            "tenant-b-sensitive",
            "wrong-sensitive-namespace",
            "unknown-historical-sensitive-id",
            "plain-session",
        ] {
            assert!(!rendered.contains(secret));
        }
    }
}

#[tokio::test]
async fn remote_sealing_session_backend_rejects_local_aead_envelopes() {
    let inner = Arc::new(FakeSessionBackend::new());
    let local_provider = test_provider();
    let local_writer = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&local_provider),
        "regional-cache-a",
    );
    let remote_reader =
        RemoteSealingSessionBackend::new(inner, test_remote_seal_provider(), "regional-cache-a");
    let key = test_key();
    let lease = local_writer
        .acquire(
            &key,
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("lease");

    local_writer
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

    let err = remote_reader
        .get(&key)
        .await
        .expect_err("remote mode must fail closed on local AEAD envelope");
    assert_eq!(
        err,
        StoreError::Crypto("session envelope decryption failed".into())
    );
}

#[tokio::test]
async fn remote_sealing_replication_log_seals_and_unseals_nested_batch_cas_records() {
    let inner = Arc::new(FakeSessionBackend::new());
    let provider = test_remote_seal_provider();
    let backend = RemoteSealingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "regional-cache-a",
    );
    let key = test_key();
    let (_next_fence, credential_id) = backend
        .next_lease_info()
        .await
        .expect("next lease info before acquire");
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("lease");

    backend
        .replicate_entry(ReplicationEntry {
            sequence: 2,
            tx_id: "remote-batch-cas".try_into().expect("valid transaction ID"),
            op: ReplicationOp::Batch {
                ops: vec![ReplicationOp::CompareAndSet {
                    key: key.clone(),
                    expected_generation: None,
                    credential_id,
                    guard_expires_at: lease.expires_at(),
                    new_record: test_record(key.clone(), 1, &lease),
                }],
            },
            timestamp: Timestamp::now_utc(),
        })
        .await
        .expect("replicate batch");

    let inner_entries = inner
        .get_replication_log(2, 1)
        .await
        .expect("inner replication log");
    match &inner_entries[0].op {
        ReplicationOp::Batch { ops } => match &ops[0] {
            ReplicationOp::CompareAndSet { new_record, .. } => {
                assert_ne!(new_record.payload.as_bytes(), b"plain-session");
                let envelope =
                    CryptoEnvelopeV1::decode(new_record.payload.as_bytes()).expect("envelope");
                assert_eq!(envelope.algorithm, opc_key::AeadAlgorithm::RemoteSeal);
            }
            other => panic!("unexpected nested op: {other:?}"),
        },
        other => panic!("unexpected replication op: {other:?}"),
    }

    let wrapper_entries = backend
        .get_replication_log(2, 1)
        .await
        .expect("wrapper replication log");
    match &wrapper_entries[0].op {
        ReplicationOp::Batch { ops } => match &ops[0] {
            ReplicationOp::CompareAndSet { new_record, .. } => {
                assert_eq!(new_record.payload.as_bytes(), b"plain-session");
            }
            other => panic!("unexpected nested op: {other:?}"),
        },
        other => panic!("unexpected replication op: {other:?}"),
    }
}

#[tokio::test]
async fn encrypting_wrapper_rejects_invalid_replication_metadata_before_crypto_or_delegation() {
    let key_provider = test_provider();
    let mut invalid_returned = vec![
        test_replication_entry(100, "returned-after-one"),
        test_replication_entry(101, "returned-after-two"),
    ];
    for entry in &mut invalid_returned {
        let ReplicationOp::CompareAndSet { new_record, .. } = &mut entry.op else {
            panic!("test entry must contain compare-and-set");
        };
        new_record.payload =
            EncryptedSessionPayload::encrypt(key_provider.as_ref(), new_record, "regional-cache-a")
                .await
                .expect("encrypt returned log fixture");
    }

    let provider = Arc::new(CountingKeyProvider::new(key_provider));
    let inner = Arc::new(ReplicationBoundarySpy::returning(invalid_returned));
    let backend = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "regional-cache-a",
    );

    let zero_error = backend
        .replicate_entry(test_replication_entry(0, "invalid-zero"))
        .await
        .expect_err("sequence zero must be rejected");
    assert_eq!(zero_error, StoreError::InvalidReplicationSequence);
    assert_eq!(provider.calls(), 0, "invalid entry reached key provider");
    assert_eq!(
        inner.replicate_calls.load(Ordering::SeqCst),
        0,
        "invalid entry reached wrapped backend"
    );

    let prefix_error = backend
        .rebuild_replication_state(vec![
            test_replication_entry(1, "prefix-one"),
            test_replication_entry(3, "prefix-gap"),
        ])
        .await
        .expect_err("gapped rebuild prefix must be rejected");
    assert_eq!(prefix_error, StoreError::InvalidReplicationSequence);
    assert_eq!(provider.calls(), 0, "invalid prefix reached key provider");
    assert_eq!(
        inner.rebuild_calls.load(Ordering::SeqCst),
        0,
        "invalid prefix reached wrapped backend"
    );

    let ttl_error = backend
        .replicate_entry(crypto_then_invalid_ttl_entry(1, "invalid-ttl"))
        .await
        .expect_err("nested oversized TTL must be rejected");
    assert_eq!(ttl_error, StoreError::InvalidSessionTtl);
    assert_eq!(provider.calls(), 0, "invalid TTL reached key provider");
    assert_eq!(
        inner.replicate_calls.load(Ordering::SeqCst),
        0,
        "invalid TTL reached wrapped backend"
    );

    let ttl_prefix_error = backend
        .rebuild_replication_state(vec![
            test_replication_entry(1, "ttl-prefix-valid"),
            crypto_then_invalid_ttl_entry(2, "ttl-prefix-invalid"),
        ])
        .await
        .expect_err("entire TTL prefix must be validated before encryption");
    assert_eq!(ttl_prefix_error, StoreError::InvalidSessionTtl);
    assert_eq!(
        provider.calls(),
        0,
        "invalid TTL prefix reached key provider"
    );
    assert_eq!(
        inner.rebuild_calls.load(Ordering::SeqCst),
        0,
        "invalid TTL prefix reached wrapped backend"
    );

    assert!(backend
        .get_replication_log(0, 0)
        .await
        .expect("zero-limit range")
        .is_empty());
    assert_eq!(
        backend
            .get_replication_log(u64::MAX, 2)
            .await
            .expect_err("overflowing range must be rejected before delegation"),
        StoreError::InvalidReplicationLogRange
    );
    assert_eq!(inner.log_reads.load(Ordering::SeqCst), 0);
    assert_eq!(provider.calls(), 0);

    let returned_error = backend
        .get_replication_log(1, 2)
        .await
        .expect_err("a contiguous page after the requested range must be rejected");
    assert_eq!(returned_error, StoreError::InvalidReplicationSequence);
    assert_eq!(inner.log_reads.load(Ordering::SeqCst), 1);
    assert_eq!(
        provider.calls(),
        0,
        "invalid returned entry reached decrypt provider"
    );
}

#[tokio::test]
async fn remote_sealing_wrapper_rejects_invalid_replication_metadata_before_provider_or_delegation()
{
    let seal_provider = test_remote_seal_provider();
    let mut invalid_returned = vec![
        test_replication_entry(1, "returned-before-one"),
        test_replication_entry(2, "returned-before-two"),
    ];
    for entry in &mut invalid_returned {
        let ReplicationOp::CompareAndSet { new_record, .. } = &mut entry.op else {
            panic!("test entry must contain compare-and-set");
        };
        new_record.payload = EncryptedSessionPayload::remote_seal(
            seal_provider.as_ref(),
            new_record,
            "regional-cache-a",
        )
        .await
        .expect("seal returned log fixture");
    }

    let provider = Arc::new(CountingRemoteSealProvider::new(seal_provider));
    let inner = Arc::new(ReplicationBoundarySpy::returning(invalid_returned));
    let backend = RemoteSealingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "regional-cache-a",
    );

    let zero_error = backend
        .replicate_entry(test_replication_entry(0, "invalid-zero"))
        .await
        .expect_err("sequence zero must be rejected");
    assert_eq!(zero_error, StoreError::InvalidReplicationSequence);
    assert_eq!(provider.calls(), 0, "invalid entry reached seal provider");
    assert_eq!(
        inner.replicate_calls.load(Ordering::SeqCst),
        0,
        "invalid entry reached wrapped backend"
    );

    let prefix_error = backend
        .rebuild_replication_state(vec![
            test_replication_entry(1, "prefix-one"),
            test_replication_entry(3, "prefix-gap"),
        ])
        .await
        .expect_err("gapped rebuild prefix must be rejected");
    assert_eq!(prefix_error, StoreError::InvalidReplicationSequence);
    assert_eq!(provider.calls(), 0, "invalid prefix reached seal provider");
    assert_eq!(
        inner.rebuild_calls.load(Ordering::SeqCst),
        0,
        "invalid prefix reached wrapped backend"
    );

    let ttl_error = backend
        .replicate_entry(crypto_then_invalid_ttl_entry(1, "invalid-ttl"))
        .await
        .expect_err("nested oversized TTL must be rejected");
    assert_eq!(ttl_error, StoreError::InvalidSessionTtl);
    assert_eq!(provider.calls(), 0, "invalid TTL reached seal provider");
    assert_eq!(
        inner.replicate_calls.load(Ordering::SeqCst),
        0,
        "invalid TTL reached wrapped backend"
    );

    let ttl_prefix_error = backend
        .rebuild_replication_state(vec![
            test_replication_entry(1, "ttl-prefix-valid"),
            crypto_then_invalid_ttl_entry(2, "ttl-prefix-invalid"),
        ])
        .await
        .expect_err("entire TTL prefix must be validated before sealing");
    assert_eq!(ttl_prefix_error, StoreError::InvalidSessionTtl);
    assert_eq!(
        provider.calls(),
        0,
        "invalid TTL prefix reached seal provider"
    );
    assert_eq!(
        inner.rebuild_calls.load(Ordering::SeqCst),
        0,
        "invalid TTL prefix reached wrapped backend"
    );

    assert!(backend
        .get_replication_log(0, 0)
        .await
        .expect("zero-limit range")
        .is_empty());
    assert_eq!(
        backend
            .get_replication_log(u64::MAX, 2)
            .await
            .expect_err("overflowing range must be rejected before delegation"),
        StoreError::InvalidReplicationLogRange
    );
    assert_eq!(inner.log_reads.load(Ordering::SeqCst), 0);
    assert_eq!(provider.calls(), 0);

    let returned_error = backend
        .get_replication_log(2, 2)
        .await
        .expect_err("a contiguous page before the requested range must be rejected");
    assert_eq!(returned_error, StoreError::InvalidReplicationSequence);
    assert_eq!(inner.log_reads.load(Ordering::SeqCst), 1);
    assert_eq!(
        provider.calls(),
        0,
        "invalid returned entry reached unseal provider"
    );
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

#[test]
fn malformed_session_envelope_magic_is_rejected_at_construction() {
    let err = EncryptedSessionPayload::try_envelope(Bytes::from_static(b"OPCE"))
        .expect_err("malformed envelope");
    assert_eq!(
        err,
        StoreError::Crypto("session envelope is invalid".into())
    );
}

#[test]
fn envelope_marker_cannot_be_forged_through_deserialization() {
    let forged = serde_json::json!({
        "bytes": b"plaintext-mislabeled-as-envelope",
        "encoding": "EnvelopeV1"
    });
    let error = serde_json::from_value::<EncryptedSessionPayload>(forged)
        .expect_err("deserialization must validate envelope bytes");
    assert!(!error
        .to_string()
        .contains("plaintext-mislabeled-as-envelope"));
}

#[tokio::test]
async fn corrupted_session_envelope_header_byte_is_not_treated_as_legacy_plaintext() {
    let provider = test_provider();
    let key = test_key();
    let inner = FakeSessionBackend::new();
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
    let mut corrupted = encrypted.as_bytes().to_vec();
    corrupted[0] ^= 0x01;
    let err = EncryptedSessionPayload::try_envelope(Bytes::from(corrupted))
        .expect_err("corrupted header");
    assert_eq!(
        err,
        StoreError::Crypto("session envelope is invalid".into())
    );
}

#[test]
fn empty_session_envelope_ciphertext_is_rejected() {
    let err = EncryptedSessionPayload::try_envelope(Bytes::new()).expect_err("empty envelope");
    assert_eq!(
        err,
        StoreError::Crypto("session envelope is invalid".into())
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
    raw_record.payload = EncryptedSessionPayload::try_envelope(corrupted_bytes)
        .expect("corrupted ciphertext remains structurally valid");
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
        other => panic!("expected conflict result, got {other:?}"),
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

    // 4. Malformed bytes cannot be labelled EnvelopeV1 at all.
    let err = EncryptedSessionPayload::try_envelope(envelope_bytes)
        .expect_err("malformed envelope must fail at construction");
    assert!(matches!(err, StoreError::Crypto(_)));

    // 5. Unclassified row with VALID envelope bytes -> decrypts correctly!
    let correct_envelope = EncryptedSessionPayload::encrypt(
        provider.as_ref(),
        &test_record(key.clone(), 4, &lease),
        "regional-cache-a",
    )
    .await
    .expect("encrypt");

    inner
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(3)),
            new_record: StoredSessionRecord {
                payload: EncryptedSessionPayload::unclassified(correct_envelope.as_bytes()),
                ..test_record(key.clone(), 4, &lease)
            },
        })
        .await
        .expect("write unclassified valid envelope row");

    let restored = backend.get(&key).await.unwrap().unwrap();
    assert_eq!(restored.payload.as_bytes(), b"plain-session");
}
