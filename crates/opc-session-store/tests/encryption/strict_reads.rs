use super::*;
use opc_session_store::{
    AtomicFencedTransitionCapability, EnvelopeReadPolicy, FencedTransitionObservation,
    PreparedFencedTransitionJournal, PreparedFencedTransitionJournalKey,
    ProtectedRosterEstablishedSuccessor, RestoreScanPage, SqliteSessionBackend,
};

const NAMESPACE: &str = "strict-read-synthetic-store";
const APPLICATION_BYTES: &[u8] = br#"{"version":1,"state":"established"}"#;

enum Protection {
    Local(Arc<CountingKeyProvider>),
    Remote(Arc<CountingRemoteSealProvider>),
}

impl Protection {
    fn local() -> Self {
        Self::Local(Arc::new(CountingKeyProvider::new(test_provider())))
    }

    fn remote() -> Self {
        Self::Remote(Arc::new(CountingRemoteSealProvider::new(
            test_remote_seal_provider(),
        )))
    }

    fn calls(&self) -> usize {
        match self {
            Self::Local(provider) => provider.calls(),
            Self::Remote(provider) => provider.calls(),
        }
    }

    async fn sealed(
        &self,
        mut record: StoredSessionRecord,
        namespace: &str,
    ) -> StoredSessionRecord {
        record.payload = match self {
            Self::Local(provider) => {
                EncryptedSessionPayload::encrypt(provider.as_ref(), &record, namespace).await
            }
            Self::Remote(provider) => {
                EncryptedSessionPayload::remote_seal(provider.as_ref(), &record, namespace).await
            }
        }
        .expect("seal synthetic record");
        record
    }

    fn backend<B: SessionBackend + 'static>(
        &self,
        inner: Arc<B>,
        policy: Option<EnvelopeReadPolicy>,
        journal: Option<Arc<PreparedFencedTransitionJournal>>,
    ) -> Arc<dyn SessionBackend> {
        match self {
            Self::Local(provider) => {
                let mut wrapper = EncryptingSessionBackend::new(inner, provider.clone(), NAMESPACE);
                if let Some(policy) = policy {
                    wrapper = wrapper.with_read_policy(policy);
                }
                if let Some(journal) = journal {
                    wrapper = wrapper.with_fenced_transition_journal(journal);
                }
                Arc::new(wrapper.clone())
            }
            Self::Remote(provider) => {
                let mut wrapper =
                    RemoteSealingSessionBackend::new(inner, provider.clone(), NAMESPACE);
                if let Some(policy) = policy {
                    wrapper = wrapper.with_read_policy(policy);
                }
                if let Some(journal) = journal {
                    wrapper = wrapper.with_fenced_transition_journal(journal);
                }
                Arc::new(wrapper.clone())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PhysicalState {
    record: Option<StoredSessionRecord>,
    entries: Vec<ReplicationEntry>,
    mutations: usize,
}

/// A physical adapter with mutable storage and an independent call log.
/// Requested CAS operations conflict with the seeded generation; unexpected
/// writes, deletes, refreshes and replication repairs change the snapshot.
struct PhysicalReads {
    state: StdMutex<PhysicalState>,
    calls: StdMutex<Vec<&'static str>>,
}

impl PhysicalReads {
    fn new(record: StoredSessionRecord) -> Self {
        let mut entry = nested_replication_entry(1, "strict-read");
        let mut pending = vec![&mut entry.op];
        while let Some(op) = pending.pop() {
            match op {
                ReplicationOp::CompareAndSet { new_record, .. } => *new_record = record.clone(),
                ReplicationOp::Batch { ops } => pending.extend(ops.iter_mut()),
                _ => {}
            }
        }
        Self {
            state: StdMutex::new(PhysicalState {
                record: Some(record),
                entries: vec![entry],
                mutations: 0,
            }),
            calls: StdMutex::new(Vec::new()),
        }
    }

    fn snapshot(&self) -> PhysicalState {
        self.state.lock().expect("physical storage").clone()
    }

    fn note(&self, call: &'static str) {
        self.calls.lock().expect("call log").push(call);
    }

    fn apply_cas(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        op.new_record.payload.validate_envelope()?;
        let mut state = self.state.lock().expect("physical storage");
        if state.record.as_ref().map(|record| record.generation) != op.expected_generation {
            return Ok(CompareAndSetResult::Conflict {
                current: state.record.clone(),
            });
        }
        state.record = Some(op.new_record);
        state.mutations += 1;
        Ok(CompareAndSetResult::Success)
    }
}

#[async_trait]
impl SessionBackend for PhysicalReads {
    async fn capabilities(&self) -> BackendCapabilities {
        let mut caps = BackendCapabilities::minimal();
        caps.batch_write = true;
        caps
    }

    async fn get(&self, _key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        self.note("get");
        Ok(self.snapshot().record)
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        self.note("cas");
        self.apply_cas(op)
    }

    async fn delete_fenced(&self, _lease: &LeaseGuard) -> Result<(), StoreError> {
        self.note("delete");
        let mut state = self.state.lock().expect("physical storage");
        state.record = None;
        state.mutations += 1;
        Ok(())
    }

    async fn refresh_ttl(&self, _lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        self.note("refresh");
        let expires_at = checked_session_deadline(Timestamp::now_utc(), ttl)?;
        let mut state = self.state.lock().expect("physical storage");
        if let Some(record) = state.record.as_mut() {
            record.expires_at = Some(expires_at);
        }
        state.mutations += 1;
        Ok(())
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        self.note("batch");
        ops.into_iter()
            .map(|op| match op {
                SessionOp::Get { .. } => Ok(SessionOpResult::Get(Ok(self.snapshot().record))),
                SessionOp::CompareAndSet(cas) => {
                    Ok(SessionOpResult::CompareAndSet(Ok(self.apply_cas(cas)?)))
                }
                _ => panic!("fixture accepts only the requested read and conflicting CAS"),
            })
            .collect()
    }

    async fn scan_restore_records(
        &self,
        _request: RestoreScanRequest,
    ) -> Result<RestoreScanPage, StoreError> {
        self.note("scan");
        Ok(RestoreScanPage::new(
            self.snapshot().record.into_iter().collect(),
            0,
            None,
        ))
    }

    async fn get_replication_log(
        &self,
        _start: u64,
        _limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        self.note("log");
        Ok(self.snapshot().entries)
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        self.note("replicate");
        let mut state = self.state.lock().expect("physical storage");
        if let Some(record) = replication_cas_records(&entry.op).last() {
            state.record = Some((*record).clone());
        }
        state.entries.push(entry);
        state.mutations += 1;
        Ok(())
    }

    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        self.note("rebuild");
        let mut state = self.state.lock().expect("physical storage");
        state.record = entries
            .iter()
            .flat_map(|entry| replication_cas_records(&entry.op))
            .last()
            .cloned();
        state.entries = entries;
        state.mutations += 1;
        Ok(())
    }

    async fn watch(
        &self,
        _start_sequence: u64,
    ) -> Result<stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>, StoreError> {
        self.note("watch");
        Ok(stream::iter(self.snapshot().entries.into_iter().map(Ok)).boxed())
    }

    fn fenced_transition_preserves_protected_payloads(&self) -> bool {
        true
    }

    async fn fenced_transition_capability(
        &self,
    ) -> Result<Option<AtomicFencedTransitionCapability>, StoreError> {
        Ok(Some(AtomicFencedTransitionCapability::V1))
    }

    async fn observe_fenced_transition(
        &self,
        _key: &SessionKey,
    ) -> Result<FencedTransitionObservation, StoreError> {
        self.note("observe");
        let record = self.snapshot().record.expect("seeded physical observation");
        Ok(serde_json::from_value(serde_json::json!({
            "record": record,
            "current_fence": record.fence,
        }))
        .expect("synthetic physical observation"))
    }
}

fn conflict_records(result: CompareAndSetResult) -> Vec<StoredSessionRecord> {
    match result {
        CompareAndSetResult::Conflict { current } => current.into_iter().collect(),
        CompareAndSetResult::Success => panic!("fixture must conflict"),
    }
}

fn entry_records(entry: ReplicationEntry) -> Vec<StoredSessionRecord> {
    replication_cas_records(&entry.op)
        .into_iter()
        .cloned()
        .collect()
}

async fn ordinary_reads(
    backend: Arc<dyn SessionBackend>,
    lease: &LeaseGuard,
) -> Vec<Result<Vec<StoredSessionRecord>, StoreError>> {
    let cas = CompareAndSet {
        key: test_key(),
        lease: lease.clone(),
        expected_generation: None,
        new_record: test_record(test_key(), 2, lease),
    };
    let mut results = vec![backend
        .get(&test_key())
        .await
        .map(|r| r.into_iter().collect())];
    results.push(
        backend
            .compare_and_set(cas.clone())
            .await
            .map(conflict_records),
    );
    let batch = backend
        .batch(vec![
            SessionOp::Get { key: test_key() },
            SessionOp::CompareAndSet(cas),
        ])
        .await
        .expect("batch retains its two result slots");
    assert_eq!(batch.len(), 2);
    for result in batch {
        results.push(match result {
            SessionOpResult::Get(result) => result.map(|r| r.into_iter().collect()),
            SessionOpResult::CompareAndSet(result) => result.map(conflict_records),
            _ => panic!("batch slot shape"),
        });
    }
    results.push(
        backend
            .scan_restore_records(RestoreScanRequest::all(4))
            .await
            .map(|p| p.records),
    );
    results.push(
        backend
            .get_replication_log(1, 1)
            .await
            .map(|entries| entries.into_iter().flat_map(entry_records).collect()),
    );
    let handle = Arc::clone(&backend);
    drop(backend);
    let mut watch = handle.watch(1).await.expect("watch handle");
    drop(handle);
    results.push(watch.next().await.expect("watch item").map(entry_records));
    results
}

fn non_envelopes() -> [EncryptedSessionPayload; 3] {
    // The application bytes themselves are valid; only their physical
    // encoding makes them inadmissible under strict reads.
    serde_json::from_slice::<serde_json::Value>(APPLICATION_BYTES)
        .expect("valid application record");
    [
        EncryptedSessionPayload::new(APPLICATION_BYTES),
        EncryptedSessionPayload::legacy_plaintext(APPLICATION_BYTES),
        EncryptedSessionPayload::unclassified(APPLICATION_BYTES),
    ]
}

async fn rejects_non_envelopes(protection: Protection) {
    let lease = detached_test_lease().await;
    let mut admitted = Vec::new();
    for payload in non_envelopes() {
        let physical = StoredSessionRecord {
            payload,
            ..test_record(test_key(), 1, &lease)
        };
        let inner = Arc::new(PhysicalReads::new(physical));
        let before_storage = inner.snapshot();
        let before_calls = protection.calls();
        let results = ordinary_reads(
            protection.backend(
                inner.clone(),
                Some(EnvelopeReadPolicy::RequireEnvelopeV1),
                None,
            ),
            &lease,
        )
        .await;
        assert_eq!(
            inner.snapshot(),
            before_storage,
            "strict reads changed physical storage"
        );
        // Only the two caller-requested replacement bodies may invoke a
        // provider. No raw read result may reach provider/application decode.
        assert_eq!(protection.calls() - before_calls, 2);
        assert_eq!(
            *inner.calls.lock().expect("calls"),
            ["get", "cas", "batch", "scan", "log", "watch"]
        );
        for result in &results {
            if let Err(error) = result {
                assert_eq!(
                    error,
                    &StoreError::Crypto("session envelope is invalid".into())
                );
                assert_eq!(
                    error.to_string(),
                    "crypto error: session envelope is invalid"
                );
                assert_eq!(
                    format!("{error:?}"),
                    "Crypto(\"session envelope is invalid\")"
                );
            }
        }
        admitted.push(results.iter().map(Result::is_ok).collect::<Vec<_>>());
    }
    assert_eq!(
        admitted,
        vec![vec![false; 7]; 3],
        "strict physical format admission on every surface"
    );
}

async fn compatible_defaults(protection: Protection) {
    assert_eq!(
        EnvelopeReadPolicy::default(),
        EnvelopeReadPolicy::MigrationCompatible
    );
    let lease = detached_test_lease().await;
    for payload in non_envelopes() {
        let inner = Arc::new(PhysicalReads::new(StoredSessionRecord {
            payload,
            ..test_record(test_key(), 1, &lease)
        }));
        for result in ordinary_reads(protection.backend(inner, None, None), &lease).await {
            let records = result.expect("default migration-compatible read");
            assert!(!records.is_empty());
            for record in records {
                assert_eq!(record.payload.encoding(), SessionPayloadEncoding::Plaintext);
                assert_eq!(record.payload.as_bytes(), APPLICATION_BYTES);
            }
        }
    }
}

#[tokio::test]
async fn local_strict_read_policy_rejects_every_non_envelope_surface() {
    rejects_non_envelopes(Protection::local()).await;
}

#[tokio::test]
async fn remote_strict_read_policy_rejects_every_non_envelope_surface() {
    rejects_non_envelopes(Protection::remote()).await;
}

#[tokio::test]
async fn local_strict_read_policy_preserves_compatible_defaults() {
    compatible_defaults(Protection::local()).await;
}

#[tokio::test]
async fn remote_strict_read_policy_preserves_compatible_defaults() {
    compatible_defaults(Protection::remote()).await;
}

fn application_record(lease: &LeaseGuard, generation: u64) -> StoredSessionRecord {
    StoredSessionRecord {
        payload: EncryptedSessionPayload::new(APPLICATION_BYTES),
        ..test_record(test_key(), generation, lease)
    }
}

fn assert_closed_crypto_error(error: &StoreError) {
    let StoreError::Crypto(message) = error else {
        panic!("expected closed crypto error, got {error:?}");
    };
    assert!(matches!(
        message.as_str(),
        "session envelope is invalid"
            | "session envelope decryption failed"
            | "session envelope AAD construction failed"
    ));
    assert_eq!(error.to_string(), format!("crypto error: {message}"));
    assert_eq!(format!("{error:?}"), format!("Crypto({message:?})"));
}

async fn unauthentic_records(
    protection: &Protection,
    plaintext: &StoredSessionRecord,
    sealed: &StoredSessionRecord,
) -> Vec<StoredSessionRecord> {
    let mut corrupt = sealed.clone();
    let mut envelope = CryptoEnvelopeV1::decode(corrupt.payload.as_bytes()).expect("envelope");
    envelope.ciphertext_and_tag[0] ^= 1;
    corrupt.payload = EncryptedSessionPayload::try_envelope(envelope.encode().expect("encode"))
        .expect("tag corruption retains canonical structure");
    let mut records = vec![
        corrupt,
        protection
            .sealed(plaintext.clone(), "other-synthetic-namespace")
            .await,
    ];
    for field in 0..6 {
        let mut spliced = sealed.clone();
        match field {
            0 => spliced.key.stable_id = Bytes::from_static(b"different-key").try_into().unwrap(),
            1 => spliced.key.tenant = TenantId::new("different-tenant").unwrap(),
            2 => spliced.key.nf_kind = NetworkFunctionKind::from_static("amf"),
            3 => spliced.state_type = StateType::new("different-state").unwrap(),
            4 => spliced.generation = Generation::new(sealed.generation.get() + 1),
            5 => spliced.fence = FenceToken::new(sealed.fence.get() + 1),
            _ => unreachable!(),
        }
        records.push(spliced);
    }
    for record in &records {
        record
            .payload
            .validate_envelope()
            .expect("authentication negative is structurally valid");
    }
    records
}

#[derive(Clone, Copy)]
enum OpaquePosition {
    Expected,
    Successor,
    Create,
}

fn opaque_op(
    position: OpaquePosition,
    candidate: StoredSessionRecord,
    expected: &StoredSessionRecord,
    successor: &StoredSessionRecord,
    lease: &LeaseGuard,
) -> ReplicationOp {
    // A takeover's current authority intentionally differs from the exact
    // admission records. Authentication must use each record's own header.
    let owner = OwnerId::new("takeover-owner").unwrap();
    let fence = FenceToken::new(50);
    match position {
        OpaquePosition::Expected | OpaquePosition::Successor => {
            let (expected_record, successor) = match position {
                OpaquePosition::Expected => (candidate, successor.clone()),
                OpaquePosition::Successor => (expected.clone(), candidate),
                OpaquePosition::Create => unreachable!(),
            };
            ReplicationOp::ProtectedRosterEstablished {
                key: test_key(),
                expected_record,
                successor: Box::new(ProtectedRosterEstablishedSuccessor::Put {
                    record: Box::new(successor),
                }),
                owner,
                fence,
                credential_id: lease.credential_id(),
                guard_acquired_at: lease.acquired_at(),
                guard_expires_at: lease.expires_at(),
            }
        }
        OpaquePosition::Create => ReplicationOp::ProtectedRosterEstablishedCreate {
            key: test_key(),
            record: candidate,
            owner,
            fence,
            credential_id: lease.credential_id(),
            guard_acquired_at: lease.acquired_at(),
            guard_expires_at: lease.expires_at(),
        },
    }
}

fn mixed_entry(ordinary: &StoredSessionRecord, late: ReplicationOp) -> ReplicationEntry {
    let mut entry = test_replication_entry(1, "strict-mixed-entry");
    let ReplicationOp::CompareAndSet { new_record, .. } = &mut entry.op else {
        unreachable!();
    };
    *new_record = ordinary.clone();
    entry.op = ReplicationOp::Batch {
        ops: vec![entry.op, ReplicationOp::Batch { ops: vec![late] }],
    };
    entry.validate().expect("valid mixed replication fixture");
    entry
}

async fn log_and_watch(
    protection: &Protection,
    entry: &ReplicationEntry,
    policy: Option<EnvelopeReadPolicy>,
) -> [Result<ReplicationEntry, StoreError>; 2] {
    let inner = Arc::new(CapturingReplicationBackend::default());
    *inner.entries.lock().unwrap() = vec![entry.clone()];
    let backend = protection.backend(inner.clone(), policy, None);
    let log = backend.get_replication_log(1, 1).await.map(|mut entries| {
        assert_eq!(entries.len(), 1);
        entries.remove(0)
    });
    let handle = Arc::clone(&backend);
    drop(backend);
    let mut watch = handle.watch(1).await.expect("watch");
    drop(handle);
    let watched = watch.next().await.expect("watch item");
    assert_eq!(inner.entries(), vec![entry.clone()]);
    assert_eq!(inner.replicate_calls.load(Ordering::SeqCst), 0);
    assert_eq!(inner.rebuild_calls.load(Ordering::SeqCst), 0);
    [log, watched]
}

async fn rejects_opaque_fields(protection: Protection) {
    let lease = detached_test_lease().await;
    let plaintext = application_record(&lease, 1);
    let plain_successor = application_record(&lease, 2);
    let expected = protection.sealed(plaintext.clone(), NAMESPACE).await;
    let successor = protection.sealed(plain_successor.clone(), NAMESPACE).await;
    let mut admitted = Vec::new();
    for position in [
        OpaquePosition::Expected,
        OpaquePosition::Successor,
        OpaquePosition::Create,
    ] {
        let (plain, sealed) = match position {
            OpaquePosition::Successor => (&plain_successor, &successor),
            _ => (&plaintext, &expected),
        };
        let mut candidates: Vec<_> = non_envelopes()
            .into_iter()
            .map(|payload| StoredSessionRecord {
                payload,
                ..plain.clone()
            })
            .collect();
        candidates.extend(unauthentic_records(&protection, plain, sealed).await);
        for candidate in candidates {
            let entry = mixed_entry(
                &expected,
                opaque_op(position, candidate, &expected, &successor, &lease),
            );
            let results = log_and_watch(
                &protection,
                &entry,
                Some(EnvelopeReadPolicy::RequireEnvelopeV1),
            )
            .await;
            for result in &results {
                if let Err(error) = result {
                    assert_closed_crypto_error(error);
                }
            }
            admitted.extend(results.iter().map(Result::is_ok));
        }
    }
    assert_eq!(
        admitted,
        vec![false; 3 * 11 * 2],
        "strict admission includes every opaque protected record"
    );
}

async fn authenticates_opaque_without_normalizing(protection: Protection) {
    let lease = detached_test_lease().await;
    let plain = application_record(&lease, 1);
    let expected = protection.sealed(plain.clone(), NAMESPACE).await;
    let successor = protection
        .sealed(application_record(&lease, 2), NAMESPACE)
        .await;
    let mut authenticated_counts = Vec::new();
    for position in [
        OpaquePosition::Expected,
        OpaquePosition::Successor,
        OpaquePosition::Create,
    ] {
        let record = match position {
            OpaquePosition::Successor => successor.clone(),
            _ => expected.clone(),
        };
        let opaque = opaque_op(position, record, &expected, &successor, &lease);
        let entry = mixed_entry(&expected, opaque.clone());
        let mut caller_entry = entry.clone();
        let ReplicationOp::Batch { ops } = &mut caller_entry.op else {
            unreachable!()
        };
        let ReplicationOp::CompareAndSet { new_record, .. } = &mut ops[0] else {
            unreachable!()
        };
        *new_record = plain.clone();
        for policy in [None, Some(EnvelopeReadPolicy::RequireEnvelopeV1)] {
            let before = protection.calls();
            for result in log_and_watch(&protection, &entry, policy).await {
                // Equality includes the opaque predecessor and successor's
                // exact physical encodings, ciphertext, and original headers.
                assert_eq!(result.expect("authenticated mixed entry"), caller_entry);
            }
            let calls = protection.calls() - before;
            if policy.is_none() {
                assert_eq!(calls, 2, "default only decodes the ordinary CAS");
            } else {
                authenticated_counts.push(calls);
            }
        }
    }
    assert_eq!(
        authenticated_counts,
        [6, 6, 4],
        "strict reads also authenticate each opaque record"
    );
}

async fn rejects_late_ordinary_record(protection: Protection) {
    let lease = detached_test_lease().await;
    let plain = application_record(&lease, 1);
    let sealed = protection.sealed(plain.clone(), NAMESPACE).await;
    let mut admitted = Vec::new();
    for payload in non_envelopes() {
        let mut late = test_replication_entry(1, "late-raw-cas").op;
        let ReplicationOp::CompareAndSet { new_record, .. } = &mut late else {
            unreachable!()
        };
        *new_record = StoredSessionRecord {
            payload,
            ..plain.clone()
        };
        let entry = mixed_entry(&sealed, late);
        let results = log_and_watch(
            &protection,
            &entry,
            Some(EnvelopeReadPolicy::RequireEnvelopeV1),
        )
        .await;
        for result in &results {
            if let Err(error) = result {
                assert_closed_crypto_error(error);
            }
        }
        admitted.extend(results.iter().map(Result::is_ok));
    }
    assert_eq!(
        admitted,
        vec![false; 6],
        "a late raw CAS rejects the complete entry"
    );
}

async fn seed_replication_log(inner: &SqliteSessionBackend) {
    let now = inner
        .record_expiry_reference()
        .expect("standalone authority clock");
    let mut key = test_key();
    key.stable_id = Bytes::from_static(b"strict-read-replication-canary")
        .try_into()
        .unwrap();
    let ttl = Duration::from_secs(60);
    let entry = ReplicationEntry {
        sequence: 1,
        tx_id: "strict-read-replication-canary".try_into().unwrap(),
        timestamp: now,
        op: ReplicationOp::AcquireLease {
            key,
            owner: OwnerId::new("replication-canary").unwrap(),
            fence: FenceToken::new(100),
            credential_id: 100,
            ttl,
            expires_at: checked_session_deadline(now, ttl).unwrap(),
        },
    };
    inner.replicate_entry(entry.clone()).await.unwrap();
    assert_eq!(inner.max_replication_sequence().await.unwrap(), 1);
    assert_eq!(inner.get_replication_log(1, 8).await.unwrap(), vec![entry]);
}

async fn batch_preserves_sibling_results(protection: Protection) {
    let inner = Arc::new(SqliteSessionBackend::in_memory().expect("SQLite batch backend"));
    let mut good_key = test_key();
    good_key.stable_id = Bytes::from_static(b"good-sibling").try_into().unwrap();
    let raw_lease = inner
        .acquire(
            &test_key(),
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let good_lease = inner
        .acquire(
            &good_key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let raw_record = application_record(&raw_lease, 1);
    assert_eq!(
        inner
            .compare_and_set(CompareAndSet {
                key: test_key(),
                lease: raw_lease.clone(),
                expected_generation: None,
                new_record: raw_record.clone(),
            })
            .await
            .unwrap(),
        CompareAndSetResult::Success
    );
    let backend = protection.backend(
        inner.clone(),
        Some(EnvelopeReadPolicy::RequireEnvelopeV1),
        None,
    );
    let good_record = test_record(good_key.clone(), 1, &good_lease);
    assert_eq!(
        backend
            .compare_and_set(CompareAndSet {
                key: good_key.clone(),
                lease: good_lease.clone(),
                expected_generation: None,
                new_record: good_record.clone(),
            })
            .await
            .unwrap(),
        CompareAndSetResult::Success
    );
    seed_replication_log(inner.as_ref()).await;
    let sequence = inner.max_replication_sequence().await.unwrap();
    let log = inner.get_replication_log(1, 8).await.unwrap();
    let updated_record = test_record(good_key.clone(), 2, &good_lease);
    let results = backend
        .batch(vec![
            SessionOp::Get { key: test_key() },
            SessionOp::Get {
                key: good_key.clone(),
            },
            SessionOp::CompareAndSet(CompareAndSet {
                key: test_key(),
                lease: raw_lease.clone(),
                expected_generation: None,
                new_record: application_record(&raw_lease, 2),
            }),
            SessionOp::CompareAndSet(CompareAndSet {
                key: good_key.clone(),
                lease: good_lease.clone(),
                expected_generation: Some(Generation::new(1)),
                new_record: updated_record.clone(),
            }),
        ])
        .await
        .expect("per-slot read admission");
    assert_eq!(results.len(), 4);
    assert_eq!(results[1], SessionOpResult::Get(Ok(Some(good_record))));
    assert_eq!(
        results[3],
        SessionOpResult::CompareAndSet(Ok(CompareAndSetResult::Success))
    );
    assert_eq!(inner.get(&test_key()).await.unwrap(), Some(raw_record));
    assert_eq!(
        inner.max_replication_sequence().await.unwrap(),
        sequence,
        "strict batch changed the replication sequence"
    );
    assert_eq!(
        inner.get_replication_log(1, 8).await.unwrap(),
        log,
        "strict batch changed the replication log"
    );
    assert_eq!(backend.get(&good_key).await.unwrap(), Some(updated_record));
    assert_eq!(
        results[0],
        SessionOpResult::Get(Err(StoreError::Crypto(
            "session envelope is invalid".into()
        )))
    );
    assert_eq!(
        results[2],
        SessionOpResult::CompareAndSet(Err(StoreError::Crypto(
            "session envelope is invalid".into()
        )))
    );
}

#[tokio::test]
async fn local_strict_read_policy_rejects_opaque_protected_fields() {
    rejects_opaque_fields(Protection::local()).await;
}

#[tokio::test]
async fn remote_strict_read_policy_rejects_opaque_protected_fields() {
    rejects_opaque_fields(Protection::remote()).await;
}

#[tokio::test]
async fn local_strict_read_policy_authenticates_opaque_bytes_in_place() {
    authenticates_opaque_without_normalizing(Protection::local()).await;
}

#[tokio::test]
async fn remote_strict_read_policy_authenticates_opaque_bytes_in_place() {
    authenticates_opaque_without_normalizing(Protection::remote()).await;
}

#[tokio::test]
async fn local_strict_read_policy_rejects_late_nested_cas() {
    rejects_late_ordinary_record(Protection::local()).await;
}

#[tokio::test]
async fn remote_strict_read_policy_rejects_late_nested_cas() {
    rejects_late_ordinary_record(Protection::remote()).await;
}

#[tokio::test]
async fn local_strict_read_policy_retains_batch_sibling_effects_and_results() {
    batch_preserves_sibling_results(Protection::local()).await;
}

#[tokio::test]
async fn remote_strict_read_policy_retains_batch_sibling_effects_and_results() {
    batch_preserves_sibling_results(Protection::remote()).await;
}

async fn ordinary_envelope_controls(protection: Protection) {
    let lease = detached_test_lease().await;
    let plain = application_record(&lease, 1);
    let sealed = protection.sealed(plain.clone(), NAMESPACE).await;
    let inner = Arc::new(PhysicalReads::new(sealed.clone()));
    let before_storage = inner.snapshot();
    for result in ordinary_reads(
        protection.backend(
            inner.clone(),
            Some(EnvelopeReadPolicy::RequireEnvelopeV1),
            None,
        ),
        &lease,
    )
    .await
    {
        let records = result.expect("strict authenticated read");
        assert!(!records.is_empty());
        for record in records {
            assert_eq!(record, plain);
        }
    }
    assert_eq!(
        inner.snapshot(),
        before_storage,
        "authenticated reads changed physical storage"
    );
    for invalid in unauthentic_records(&protection, &plain, &sealed).await {
        for result in ordinary_reads(
            protection.backend(
                Arc::new(PhysicalReads::new(invalid)),
                Some(EnvelopeReadPolicy::RequireEnvelopeV1),
                None,
            ),
            &lease,
        )
        .await
        {
            assert_closed_crypto_error(
                &result.expect_err("canonical envelope still needs authentication"),
            );
        }
    }
}

async fn rejects_misclassified_envelopes(protection: Protection) {
    let lease = detached_test_lease().await;
    let plain = application_record(&lease, 1);
    let sealed = protection.sealed(plain.clone(), NAMESPACE).await;
    let mut admitted = Vec::new();
    let mut provider_calls = Vec::new();
    for payload in [
        EncryptedSessionPayload::new(sealed.payload.as_bytes()),
        EncryptedSessionPayload::legacy_plaintext(sealed.payload.as_bytes()),
        EncryptedSessionPayload::unclassified(sealed.payload.as_bytes()),
    ] {
        let inner = Arc::new(PhysicalReads::new(StoredSessionRecord {
            payload,
            ..plain.clone()
        }));
        let before = protection.calls();
        let results = ordinary_reads(
            protection.backend(inner, Some(EnvelopeReadPolicy::RequireEnvelopeV1), None),
            &lease,
        )
        .await;
        provider_calls.push(protection.calls() - before);
        for result in &results {
            if let Err(error) = result {
                assert_closed_crypto_error(error);
            }
        }
        admitted.extend(results.iter().map(Result::is_ok));
    }
    assert_eq!(
        provider_calls,
        [2, 2, 2],
        "strict reads must not probe an Unclassified envelope"
    );
    assert_eq!(
        admitted,
        vec![false; 21],
        "canonical bytes do not override physical encoding"
    );
}

async fn protected_observation_controls(protection: Protection) {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private journal directory");
    }
    let journal = Arc::new(
        PreparedFencedTransitionJournal::create_new(
            directory.path().join("observation.sqlite"),
            PreparedFencedTransitionJournalKey::from_bytes([0x55; 32]),
        )
        .expect("private observation journal"),
    );
    let lease = detached_test_lease().await;
    let plain = application_record(&lease, 1);
    let sealed = protection.sealed(plain.clone(), NAMESPACE).await;
    for policy in [None, Some(EnvelopeReadPolicy::RequireEnvelopeV1)] {
        let backend = protection.backend(
            Arc::new(PhysicalReads::new(sealed.clone())),
            policy,
            Some(journal.clone()),
        );
        let observed = backend
            .observe_fenced_transition(&test_key())
            .await
            .expect("protected observation");
        assert_eq!(observed.record(), Some(&plain));
        assert_eq!(observed.current_fence(), plain.fence);
        for payload in non_envelopes() {
            let physical = StoredSessionRecord {
                payload,
                ..plain.clone()
            };
            let inner = Arc::new(PhysicalReads::new(physical));
            let before_storage = inner.snapshot();
            let before = protection.calls();
            let error = protection
                .backend(inner.clone(), policy, Some(journal.clone()))
                .observe_fenced_transition(&test_key())
                .await
                .expect_err("existing stronger physical guard");
            assert_eq!(
                inner.snapshot(),
                before_storage,
                "protected observation changed physical storage"
            );
            assert_eq!(
                error,
                StoreError::CapabilityNotSupported("atomic_fenced_transition_v2".into())
            );
            assert_eq!(protection.calls(), before);
            assert_eq!(*inner.calls.lock().unwrap(), ["observe"]);
        }
        for record in unauthentic_records(&protection, &plain, &sealed).await {
            let error = protection
                .backend(
                    Arc::new(PhysicalReads::new(record)),
                    policy,
                    Some(journal.clone()),
                )
                .observe_fenced_transition(&test_key())
                .await
                .expect_err("observation authentication");
            assert_closed_crypto_error(&error);
        }
    }
}

fn stored_sqlite_row(connection: &rusqlite::Connection) -> Vec<rusqlite::types::Value> {
    let mut statement = connection.prepare("SELECT * FROM session_records").unwrap();
    let width = statement.column_count();
    statement
        .query_row([], |row| (0..width).map(|column| row.get(column)).collect())
        .unwrap()
}

async fn sqlite_preserves_unexpired_raw_record(protection: Protection) {
    for payload in non_envelopes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("unexpired.sqlite");
        let now = Timestamp::now_utc();
        let inner = Arc::new(
            SqliteSessionBackend::open(&path)
                .unwrap()
                .with_clock(Arc::new(FixedAuthorityClock(now))),
        );
        let lease = inner
            .acquire(
                &test_key(),
                OwnerId::new("owner-a").unwrap(),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        let physical = StoredSessionRecord {
            payload,
            expires_at: Some(checked_session_deadline(now, Duration::from_secs(3600)).unwrap()),
            ..test_record(test_key(), 1, &lease)
        };
        assert_eq!(
            inner
                .compare_and_set(CompareAndSet {
                    key: test_key(),
                    lease,
                    expected_generation: None,
                    new_record: physical.clone(),
                })
                .await
                .unwrap(),
            CompareAndSetResult::Success
        );
        let connection = rusqlite::Connection::open(&path).unwrap();
        seed_replication_log(inner.as_ref()).await;
        let before = stored_sqlite_row(&connection);
        let log = inner.get_replication_log(1, 8).await.unwrap();
        let sequence = inner.max_replication_sequence().await.unwrap();
        let before_calls = protection.calls();
        let backend = protection.backend(
            inner.clone(),
            Some(EnvelopeReadPolicy::RequireEnvelopeV1),
            None,
        );
        assert_closed_crypto_error(
            &backend
                .get(&test_key())
                .await
                .expect_err("strict physical SQLite read"),
        );
        assert_closed_crypto_error(
            &backend
                .scan_restore_records(RestoreScanRequest::all(4))
                .await
                .expect_err("strict SQLite restore"),
        );
        assert_eq!(protection.calls(), before_calls);
        assert_eq!(stored_sqlite_row(&connection), before);
        assert_eq!(inner.get(&test_key()).await.unwrap(), Some(physical));
        assert_eq!(
            inner.max_replication_sequence().await.unwrap(),
            sequence,
            "strict SQLite reads changed the replication sequence"
        );
        assert_eq!(
            inner.get_replication_log(1, 8).await.unwrap(),
            log,
            "strict SQLite reads changed the replication log"
        );
    }
}

async fn malformed_sqlite_envelope_ingress(protection: Protection) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("malformed.sqlite");
    let inner = Arc::new(SqliteSessionBackend::open(&path).unwrap());
    let lease = inner
        .acquire(
            &test_key(),
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let sealed = protection
        .sealed(application_record(&lease, 1), NAMESPACE)
        .await;
    assert_eq!(
        inner
            .compare_and_set(CompareAndSet {
                key: test_key(),
                lease,
                expected_generation: None,
                new_record: sealed.clone(),
            })
            .await
            .unwrap(),
        CompareAndSetResult::Success
    );
    let mut noncanonical = CryptoEnvelopeV1::decode(sealed.payload.as_bytes()).unwrap();
    noncanonical.aad = serde_json::to_vec_pretty(
        &serde_json::from_slice::<serde_json::Value>(&noncanonical.aad).unwrap(),
    )
    .unwrap();
    let mut truncated = CryptoEnvelopeV1::decode(sealed.payload.as_bytes()).unwrap();
    truncated
        .ciphertext_and_tag
        .truncate(opc_key::AEAD_TAG_LEN - 1);
    let connection = rusqlite::Connection::open(&path).unwrap();
    let backend = protection.backend(
        inner.clone(),
        Some(EnvelopeReadPolicy::RequireEnvelopeV1),
        None,
    );
    for malformed in [
        b"OPCE".to_vec(),
        noncanonical.encode().unwrap(),
        truncated.encode().unwrap(),
    ] {
        // Public EnvelopeV1 construction/deserialization already rejects
        // malformed structure. Corrupt the physical row directly to exercise
        // that adapter ingress, without claiming this reaches wrapper crypto.
        assert!(EncryptedSessionPayload::try_envelope(&malformed).is_err());
        connection
            .execute(
                "UPDATE session_records SET payload = ?1, encoding = 2",
                [&malformed],
            )
            .unwrap();
        let before = stored_sqlite_row(&connection);
        let before_calls = protection.calls();
        assert_closed_crypto_error(
            &backend
                .get(&test_key())
                .await
                .expect_err("malformed persisted envelope"),
        );
        assert_closed_crypto_error(
            &backend
                .scan_restore_records(RestoreScanRequest::all(4))
                .await
                .expect_err("malformed restore envelope"),
        );
        assert_eq!(protection.calls(), before_calls);
        assert_eq!(stored_sqlite_row(&connection), before);
    }
}

#[tokio::test]
async fn local_strict_read_policy_retains_authentication_and_plaintext_results() {
    ordinary_envelope_controls(Protection::local()).await;
}

#[tokio::test]
async fn remote_strict_read_policy_retains_authentication_and_plaintext_results() {
    ordinary_envelope_controls(Protection::remote()).await;
}

#[tokio::test]
async fn local_strict_read_policy_rejects_misclassified_envelope_bytes() {
    rejects_misclassified_envelopes(Protection::local()).await;
}

#[tokio::test]
async fn remote_strict_read_policy_rejects_misclassified_envelope_bytes() {
    rejects_misclassified_envelopes(Protection::remote()).await;
}

#[tokio::test]
async fn local_strict_read_policy_preserves_protected_observation_guards() {
    protected_observation_controls(Protection::local()).await;
}

#[tokio::test]
async fn remote_strict_read_policy_preserves_protected_observation_guards() {
    protected_observation_controls(Protection::remote()).await;
}

#[tokio::test]
async fn local_strict_read_policy_preserves_unexpired_sqlite_row() {
    sqlite_preserves_unexpired_raw_record(Protection::local()).await;
}

#[tokio::test]
async fn remote_strict_read_policy_preserves_unexpired_sqlite_row() {
    sqlite_preserves_unexpired_raw_record(Protection::remote()).await;
}

#[tokio::test]
async fn local_strict_read_policy_rejects_malformed_envelopes_at_sqlite_ingress() {
    malformed_sqlite_envelope_ingress(Protection::local()).await;
}

#[tokio::test]
async fn remote_strict_read_policy_rejects_malformed_envelopes_at_sqlite_ingress() {
    malformed_sqlite_envelope_ingress(Protection::remote()).await;
}
