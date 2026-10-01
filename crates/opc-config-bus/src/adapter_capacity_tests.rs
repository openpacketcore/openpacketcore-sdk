//! Original-owner tests; all evidence assertions run after actual cleanup.

use super::*;
use crate::capacity_observation::{
    capture_current, scope, AllocationIdentity, BufferEvent, BufferKind, BufferObservation,
};
use opc_config_model::{
    ConfigError, TrustedPrincipal, ValidationContext, ValidationError, WorkloadIdentity,
};
use opc_crypto::{AuthenticatedEnvelope, AuthenticatedEnvelopeClaim, ConfigPreparationPool};
use opc_key::{KeyError, KeyHandle, KeyId, KeyPurpose};
use opc_types::{SchemaDigest, TenantId, Timestamp};
use serde::ser::SerializeStruct;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use tokio::sync::Semaphore;

#[derive(Default)]
struct Inspection {
    plaintext_checks: usize,
    transfer_checks: usize,
    mismatch: bool,
    reservation_ids: Vec<AllocationIdentity>,
    encoded_checkpoints: usize,
    encoded_missing_ciphertext: bool,
    peak_data_capacity: usize,
}

tokio::task_local! {
    static INSPECTION: Arc<Mutex<Inspection>>;
}

fn exact(kind: BufferKind, identity: AllocationIdentity, length: usize, capacity: usize) -> bool {
    capture_current(|snapshot| {
        !snapshot.overflowed
            && snapshot.buffers.iter().flatten().any(|row| {
                row.kind == kind
                    && row.identity == identity
                    && row.length == length
                    && row.capacity == capacity
            })
    })
    .unwrap_or(false)
}

pub(super) fn inspect_plaintext(original: &Vec<u8>) {
    let _ = INSPECTION.try_with(|state| {
        let matches = exact(
            BufferKind::AdapterPlaintext,
            AllocationIdentity::of(original),
            original.len(),
            original.capacity(),
        );
        let mut state = state.lock().unwrap();
        state.plaintext_checks += 1;
        state.mismatch |= !matches || original.capacity() < original.len();
    });
}

pub(super) fn inspect_transfer(blob: &Vec<u8>, envelope: &AuthenticatedEnvelope) {
    let _ = INSPECTION.try_with(|state| {
        let matches = exact(
            BufferKind::RecordBlob,
            AllocationIdentity::of(blob),
            blob.len(),
            blob.capacity(),
        ) && exact(
            BufferKind::EnvelopeArc,
            AllocationIdentity::of(envelope.encoded()),
            envelope.encoded().len(),
            envelope.encoded().len(),
        );
        let mut state = state.lock().unwrap();
        state.transfer_checks += 1;
        state.mismatch |= !matches || blob.as_ptr() == envelope.encoded().as_ptr();
    });
}

#[derive(Clone, serde::Deserialize)]
struct ProbeConfig {
    payload: String,
    #[serde(skip)]
    serializations: Arc<AtomicUsize>,
}

impl Serialize for ProbeConfig {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.serializations.fetch_add(1, Ordering::SeqCst);
        let mut state = serializer.serialize_struct("ProbeConfig", 1)?;
        state.serialize_field("payload", &self.payload)?;
        state.end()
    }
}

impl OpcConfig for ProbeConfig {
    type Delta = String;
    fn schema_digest(&self) -> SchemaDigest {
        SchemaDigest::from_bytes([0xC1; 32])
    }
    fn diff(&self, _: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
        Ok(Vec::new())
    }
    fn changed_paths(
        &self,
        _: &Self,
        _: &[Self::Delta],
    ) -> Result<Vec<opc_config_model::YangPath>, ConfigError> {
        Ok(Vec::new())
    }
    fn apply_delta(&mut self, delta: Self::Delta) -> Result<(), ConfigError> {
        self.payload = delta;
        Ok(())
    }
    fn validate_syntax(&self) -> Result<(), ValidationError> {
        Ok(())
    }
    fn validate_semantics(&self, _: &ValidationContext<Self>) -> Result<(), ValidationError> {
        Ok(())
    }
}

struct Provider {
    key: KeyHandle,
    calls: AtomicUsize,
    arrived: Semaphore,
    release: Semaphore,
    reject: bool,
}

#[async_trait]
impl KeyProvider for Provider {
    async fn get_active_key(&self, _: KeyPurpose, _: &TenantId) -> Result<KeyHandle, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.arrived.add_permits(1);
        self.release
            .acquire()
            .await
            .map_err(|_| KeyError::Unavailable)?
            .forget();
        if self.reject {
            Err(KeyError::Unavailable)
        } else {
            Ok(self.key.clone())
        }
    }
    async fn get_key_by_id(&self, _: &KeyId) -> Result<KeyHandle, KeyError> {
        Ok(self.key.clone())
    }
    async fn rotate_key(&self, _: KeyPurpose, _: &TenantId) -> Result<KeyId, KeyError> {
        Err(KeyError::Unavailable)
    }
}

type SealedRecord = StoredConfig<SealedConfig<ProbeConfig>>;

struct Sink {
    pool: ConfigPreparationPool,
    records: Mutex<Vec<(SealedRecord, AuthenticatedEnvelopeClaim)>>,
}

#[async_trait]
impl ManagedDatastore<SealedConfig<ProbeConfig>> for Sink {
    fn config_capacity_profile(&self) -> ConfigCapacityProfile {
        ConfigCapacityProfile::BoundedV1
    }
    fn try_reserve_config_preparation(
        &self,
    ) -> Result<Option<opc_crypto::ConfigPreparationReservation>, StoreError> {
        self.pool
            .try_reserve()
            .map(Some)
            .map_err(|_| StoreError::unavailable("capacity occupied"))
    }
    async fn load_latest(&self) -> Result<Option<SealedRecord>, StoreError> {
        Ok(None)
    }
    async fn load_rollback(&self, _: RollbackTarget) -> Result<SealedRecord, StoreError> {
        Err(StoreError::not_found("empty fixture"))
    }
    async fn load_by_idempotency_key(
        &self,
        _: &IdempotencyKey,
    ) -> Result<Option<SealedRecord>, StoreError> {
        Ok(None)
    }
    async fn clear_recovery_required(&self, _: TxId) -> Result<(), StoreError> {
        Ok(())
    }
    async fn append_commit_write(
        &self,
        commit: CommitWrite<SealedConfig<ProbeConfig>>,
    ) -> Result<(), StoreError> {
        let (record, _) = commit.into_parts();
        let claim = record.config.claim_fresh_envelope()?;
        if !claim.matches(&record.encrypted_blob) || claim.capacity_evidence().is_none() {
            return Err(StoreError::crypto("unattested fixture"));
        }
        self.records.lock().unwrap().push((record, claim));
        Ok(())
    }
}

type Adapter = EncryptingManagedDatastore<ProbeConfig, Provider, Sink>;

fn fixture(reject: bool) -> (Arc<Sink>, Arc<Provider>, Arc<Adapter>) {
    let sink = Arc::new(Sink {
        pool: ConfigPreparationPool::bounded_v1(),
        records: Mutex::new(Vec::new()),
    });
    let provider = Arc::new(Provider {
        key: KeyHandle::new(
            KeyId::new("capacity-test-key").unwrap(),
            KeyPurpose::Config,
            TenantId::from_static("test"),
            Zeroizing::new([0xB7; 32]),
        ),
        calls: AtomicUsize::new(0),
        arrived: Semaphore::new(0),
        release: Semaphore::new(0),
        reject,
    });
    let adapter = Arc::new(EncryptingManagedDatastore::new(
        Arc::clone(&sink),
        Arc::clone(&provider),
    ));
    (sink, provider, adapter)
}

fn input(bytes: usize, serializations: Arc<AtomicUsize>) -> StoredConfig<ProbeConfig> {
    let config = ProbeConfig {
        payload: "q".repeat(bytes - b"{\"payload\":\"\"}".len()),
        serializations,
    };
    StoredConfig {
        tx_id: TxId::new(),
        parent_tx_id: None,
        version: ConfigVersion::new(1),
        committed_at: Timestamp::from_offset_datetime(
            time::OffsetDateTime::from_unix_timestamp(1_900_000_000).unwrap(),
        ),
        principal: TrustedPrincipal::new(
            WorkloadIdentity::Internal("capacity-test".into()),
            TenantId::from_static("test"),
        ),
        source: RequestSource::Internal,
        schema_digest: config.schema_digest(),
        plaintext_digest: None,
        config,
        encrypted_blob: Vec::new(),
        idempotency_key: None,
        apply_plan: None,
        request_fingerprint: None,
        request_id: None,
        recovery_required: false,
        confirmed_deadline: None,
        rollback_label: None,
    }
}

fn observer(state: &Arc<Mutex<Inspection>>) -> Arc<BufferObservation> {
    let state = Arc::clone(state);
    Arc::new(BufferObservation::new(move |event, snapshot| {
        let mut state = state.lock().unwrap();
        state.peak_data_capacity = state.peak_data_capacity.max(snapshot.data_capacity());
        state.mismatch |= snapshot.overflowed;
        if let BufferEvent::Reservation { identity, .. } = event {
            state.reservation_ids.push(identity);
        }
        if event == BufferEvent::Checkpoint("envelope-encoded") {
            state.encoded_checkpoints += 1;
            state.encoded_missing_ciphertext |= !snapshot
                .buffers
                .iter()
                .flatten()
                .any(|row| row.kind == BufferKind::Ciphertext);
        }
    }))
}

async fn arrived(provider: &Provider, count: u32) {
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        provider.arrived.acquire_many(count),
    )
    .await
    .unwrap()
    .unwrap()
    .forget();
}

fn pool_is_released(pool: &ConfigPreparationPool) -> bool {
    let reservations: Vec<_> = (0..8).filter_map(|_| pool.try_reserve().ok()).collect();
    reservations.len() == 8 && pool.try_reserve().is_err()
}

#[tokio::test]
async fn eight_at_limit_original_buffers_transfer_and_release() {
    let (sink, provider, adapter) = fixture(false);
    let inspection = Arc::new(Mutex::new(Inspection::default()));
    let observation = observer(&inspection);
    let serializations = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for operation in 1..=8 {
        let adapter = Arc::clone(&adapter);
        let record = input(
            opc_crypto::CONFIG_CAPACITY_V1_LOGICAL_BYTES,
            Arc::clone(&serializations),
        );
        tasks.push(tokio::spawn(INSPECTION.scope(
            Arc::clone(&inspection),
            scope(Arc::clone(&observation), operation, async move {
                adapter.append_commit(record).await
            }),
        )));
    }
    arrived(&provider, 8).await;
    let plateau = observation.capture(|snapshot| {
        let rows: Vec<_> = snapshot
            .buffers
            .iter()
            .flatten()
            .filter(|row| row.kind == BufferKind::AdapterPlaintext)
            .collect();
        rows.len() == 8
            && rows.iter().all(|row| {
                row.kind == BufferKind::AdapterPlaintext
                    && row.capacity >= opc_crypto::CONFIG_CAPACITY_V1_PLAINTEXT_BYTES
                    && row.length > opc_crypto::CONFIG_CAPACITY_V1_LOGICAL_BYTES
            })
    });
    let refused_serializations = Arc::new(AtomicUsize::new(0));
    let refused = scope(
        Arc::clone(&observation),
        9,
        adapter.append_commit(input(32, Arc::clone(&refused_serializations))),
    )
    .await
    .is_err();
    provider.release.add_permits(8);
    let mut completed = true;
    for task in tasks {
        completed &= task.await.unwrap().is_ok();
    }
    let aliases_live = observation.capture(|snapshot| {
        snapshot.allocations() == 8
            && snapshot
                .buffers
                .iter()
                .flatten()
                .all(|row| row.kind == BufferKind::EnvelopeArc && row.aliases == 2)
    });
    let reservation_held = sink.pool.try_reserve().is_err();
    let records = std::mem::take(&mut *sink.records.lock().unwrap());
    let mut claims = Vec::new();
    for (record, claim) in records {
        drop(record);
        claims.push(claim);
    }
    let claim_only_live = observation.capture(|snapshot| {
        snapshot.allocations() == 8
            && snapshot
                .buffers
                .iter()
                .flatten()
                .all(|row| row.aliases == 1)
    });
    drop(claims);
    let drained = observation.capture(|snapshot| snapshot.allocations() == 0);
    let released = pool_is_released(&sink.pool);
    let state = inspection.lock().unwrap();
    println!("CONFIG_CAPACITY_ADAPTER_LIFECYCLE completed={completed} drained={drained} reservations_released={released} peak_observed_data_capacity={} metadata_bytes={}", state.peak_data_capacity, BufferObservation::fixed_metadata_bytes());
    assert!(drained && released, "CONFIG_CAPACITY_ADAPTER_CLEANUP");
    assert!(plateau, "CONFIG_CAPACITY_ADAPTER_HELD_PLAINTEXT: eight real reservations must keep original plaintext borrows live across the provider await");
    assert!(!state.mismatch && state.plaintext_checks == 8 && state.transfer_checks == 8 && !state.encoded_missing_ciphertext && state.encoded_checkpoints == 8, "CONFIG_CAPACITY_ADAPTER_EXACT_ORIGINALS: original addresses, lengths, capacities, and encoding temporaries must match");
    let mut reservation_ids = state.reservation_ids.clone();
    reservation_ids.sort_unstable();
    reservation_ids.dedup();
    assert_eq!(reservation_ids.len(), 8, "eight distinct original leases");
    assert!(completed && refused && reservation_held && aliases_live && claim_only_live);
    assert_eq!(serializations.load(Ordering::SeqCst), 8);
    assert_eq!(refused_serializations.load(Ordering::SeqCst), 0);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 8);
}

#[tokio::test]
async fn cancellation_provider_rejection_and_oversize_release_original_owners() {
    for reject in [false, true] {
        let (sink, provider, adapter) = fixture(reject);
        let observation = Arc::new(BufferObservation::new(|_, _| {}));
        let scoped = Arc::clone(&observation);
        let task = tokio::spawn(async move {
            scope(
                scoped,
                1,
                adapter.append_commit(input(128, Arc::new(AtomicUsize::new(0)))),
            )
            .await
        });
        arrived(&provider, 1).await;
        let held = observation.capture(|snapshot| {
            snapshot
                .buffers
                .iter()
                .flatten()
                .filter(|row| row.kind == BufferKind::AdapterPlaintext)
                .count()
                == 1
        });
        if reject {
            provider.release.add_permits(1);
            assert!(task.await.unwrap().is_err());
        } else {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
        let drained = observation.capture(|snapshot| snapshot.allocations() == 0);
        let released = pool_is_released(&sink.pool);
        assert!(held && drained && released);
    }
    for bytes in [
        opc_crypto::CONFIG_CAPACITY_V1_LOGICAL_BYTES + 1,
        opc_crypto::CONFIG_CAPACITY_V1_PLAINTEXT_BYTES + 1,
    ] {
        let (sink, provider, adapter) = fixture(false);
        let observation = Arc::new(BufferObservation::new(|_, _| {}));
        let rejected = scope(
            Arc::clone(&observation),
            1,
            adapter.append_commit(input(bytes, Arc::new(AtomicUsize::new(0)))),
        )
        .await
        .is_err();
        assert!(rejected && pool_is_released(&sink.pool));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        assert_eq!(observation.capture(|snapshot| snapshot.allocations()), 0);
    }
}

#[tokio::test]
async fn bounded_metadata_rejects_before_sdk_copies_and_preserves_legacy_bytes() {
    for (principal, store_kind) in [
        (
            "p".repeat(opc_crypto::CONFIG_CAPACITY_V1_AAD_BYTES + 1),
            "running".to_owned(),
        ),
        (
            "\n".repeat(opc_crypto::CONFIG_CAPACITY_V1_AAD_BYTES / 2),
            "running".to_owned(),
        ),
        (
            "writer".to_owned(),
            "s".repeat(opc_crypto::CONFIG_CAPACITY_V1_AAD_BYTES + 1),
        ),
        (
            "writer".to_owned(),
            "\n".repeat(opc_crypto::CONFIG_CAPACITY_V1_AAD_BYTES / 2) + "s",
        ),
    ] {
        let (sink, provider, _) = fixture(false);
        let adapter = EncryptingManagedDatastore::with_store_kind(
            Arc::clone(&sink),
            Arc::clone(&provider),
            store_kind,
        );
        let copies = Arc::new(AtomicUsize::new(0));
        let observe_copies = Arc::clone(&copies);
        let observation = Arc::new(BufferObservation::new(move |event, _| {
            if event == BufferEvent::Registered(BufferKind::AadPrincipal) {
                observe_copies.fetch_add(1, Ordering::SeqCst);
            }
        }));
        let mut record = input(128, Arc::new(AtomicUsize::new(0)));
        record.principal = TrustedPrincipal::new(
            WorkloadIdentity::Internal(principal),
            TenantId::from_static("test"),
        );
        let legacy = build_config_envelope_aad(&record, adapter.store_kind(), None).unwrap();
        let legacy_principal = serde_json::to_string(&record.principal).unwrap();
        let opc_key::EnvelopeMetadata::Config(metadata) = legacy.metadata() else {
            unreachable!()
        };
        let legacy_preserved = metadata.principal() == legacy_principal
            && metadata.store_kind() == adapter.store_kind();
        drop(legacy);
        let rejected = scope(Arc::clone(&observation), 1, adapter.append_commit(record))
            .await
            .is_err();
        let drained = observation.capture(|snapshot| snapshot.allocations() == 0);
        let released = pool_is_released(&sink.pool);
        println!("CONFIG_CAPACITY_METADATA_LIFECYCLE rejected={rejected} drained={drained} reservations_released={released}");
        assert!(rejected && drained && released && legacy_preserved);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        assert_eq!(copies.load(Ordering::SeqCst), 0, "CONFIG_CAPACITY_METADATA_BEFORE_COPY: rejected oversized metadata must not construct SDK-owned AAD strings");
    }
    // Largest accepted bound-AAD principal for this real key and record. Its
    // binary boundary is found without guessing serde or framing overhead.
    let (sink, provider, adapter) = fixture(false);
    let mut record = input(128, Arc::new(AtomicUsize::new(0)));
    let mut low = 0;
    let mut high = opc_crypto::CONFIG_CAPACITY_V1_AAD_BYTES;
    while low < high {
        let size = (low + high).div_ceil(2);
        record.principal = TrustedPrincipal::new(
            WorkloadIdentity::Internal("p".repeat(size)),
            TenantId::from_static("test"),
        );
        let aad = build_config_envelope_aad(&record, adapter.store_kind(), None).unwrap();
        let length = opc_key::serialize_bound_aad(&aad, provider.key.key_id())
            .unwrap()
            .len();
        if length <= opc_crypto::CONFIG_CAPACITY_V1_AAD_BYTES {
            low = size;
        } else {
            high = size - 1;
        }
    }
    record.principal = TrustedPrincipal::new(
        WorkloadIdentity::Internal("p".repeat(low)),
        TenantId::from_static("test"),
    );
    let legacy = build_config_envelope_aad(&record, adapter.store_kind(), None).unwrap();
    let bounded = build_bounded_config_envelope_aad(&record, adapter.store_kind()).unwrap();
    let old_bytes = opc_key::serialize_bound_aad(&legacy, provider.key.key_id()).unwrap();
    let new_bytes = opc_key::serialize_bound_aad(&bounded, provider.key.key_id()).unwrap();
    assert_eq!(old_bytes.len(), opc_crypto::CONFIG_CAPACITY_V1_AAD_BYTES);
    assert_eq!(
        old_bytes, new_bytes,
        "canonical at-limit AAD bytes remain exact"
    );
    provider.release.add_permits(1);
    adapter.append_commit(record).await.unwrap();
    sink.records.lock().unwrap().clear();
    assert!(pool_is_released(&sink.pool));
}
