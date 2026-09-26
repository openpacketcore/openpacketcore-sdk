//! A public audited caller must release its authenticated preflight ledger
//! before native apply allocates an independent ledger. This observes real
//! payload capacities; it does not measure allocator/RSS or transport buffers.

use super::*;
use crate::audit_authority::ledger::{HandleBody, LedgerState};
use crate::audit_authority::{
    AuditAdmission, AuditCaller, AuditLedgerLimits, AuditOperationBinding, AuditOperationHandle,
    AuditOperationReceipt, AuditOperationState, AuditPrivacyKey, AuditPrivacyProjection,
    AuditPrivacyPurpose, PreparedAuditedMutation, ProjectedAuditEvent,
};
use crate::consensus::audit_mutation::{
    AuditedConfigCommand, AuditedConfigEffect, AuditedMutationFields,
};
use crate::consensus::config_capacity_simultaneous_working_tests::ledger::Sample;
use crate::consensus::ConfigConsensusIdentity;
use crate::{AuditKey, RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions};
use opc_crypto::ConfigCapacityProfile;
use opc_key::{ConfigAad, EnvelopeAad, KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use std::mem::size_of;

const OPERATION_BYTES: usize = 33_554_432;
const METADATA_BYTES: usize = 196_608;

/// The registry retains counters only. The wrapper owns the very ledger moved
/// out of the real quorum read, without cloning it or changing its drop scope.
pub(crate) mod observation {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::ops::Deref;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, LazyLock, Mutex, Weak};

    use opc_consensus::engine::{Entry, EntryPayload};
    use opc_consensus::ConsensusRequestId;

    use crate::audit_authority::ledger::LedgerState;
    use crate::consensus::config_capacity_simultaneous_working_tests::ledger::{
        self, Observation, ObservationGuard, Sample,
    };
    use crate::consensus::{ConfigMutationIntent, ConfigRaftTypeConfig};

    struct Shared {
        base: Sample,
        original_payload: usize,
        caller_bytes: AtomicUsize,
        caller_reads: AtomicUsize,
        caller_drops: AtomicUsize,
        native_calls: AtomicUsize,
        result: Mutex<Option<Observation>>,
    }

    type Registry = HashMap<ConsensusRequestId, Weak<Shared>>;
    static OBSERVERS: LazyLock<Mutex<Registry>> = LazyLock::new(|| Mutex::new(HashMap::new()));
    thread_local! {
        static ACTIVE: RefCell<Option<Arc<Shared>>> = const { RefCell::new(None) };
    }

    fn find(request: ConsensusRequestId) -> Option<Arc<Shared>> {
        OBSERVERS
            .lock()
            .expect("caller ledger registry")
            .get(&request)
            .and_then(Weak::upgrade)
    }

    pub(crate) struct Registration {
        request: ConsensusRequestId,
        shared: Arc<Shared>,
    }

    impl Registration {
        pub(crate) fn new(
            request: ConsensusRequestId,
            base: Sample,
            prepared: &crate::consensus::audit_mutation::AuditedConfigCommand,
        ) -> Self {
            let shared = Arc::new(Shared {
                base,
                original_payload: std::ptr::from_ref(&**prepared) as usize,
                caller_bytes: AtomicUsize::new(0),
                caller_reads: AtomicUsize::new(0),
                caller_drops: AtomicUsize::new(0),
                native_calls: AtomicUsize::new(0),
                result: Mutex::new(None),
            });
            assert!(OBSERVERS
                .lock()
                .expect("caller ledger registry")
                .insert(request, Arc::downgrade(&shared))
                .is_none());
            Self { request, shared }
        }

        pub(crate) fn finish(&self) -> Observation {
            assert_eq!(self.shared.caller_reads.load(Ordering::SeqCst), 1);
            assert_eq!(self.shared.caller_drops.load(Ordering::SeqCst), 1);
            assert_eq!(self.shared.caller_bytes.load(Ordering::SeqCst), 0);
            assert_eq!(self.shared.native_calls.load(Ordering::SeqCst), 1);
            self.shared
                .result
                .lock()
                .expect("native ledger result")
                .expect("actual native apply completed its observation")
        }
    }

    impl Drop for Registration {
        fn drop(&mut self) {
            OBSERVERS
                .lock()
                .expect("caller ledger registry")
                .remove(&self.request);
        }
    }

    pub(crate) struct CallerLedger {
        ledger: LedgerState,
        shared: Option<Arc<Shared>>,
    }

    impl CallerLedger {
        pub(crate) fn observe(request: ConsensusRequestId, ledger: LedgerState) -> Self {
            let shared = find(request);
            if let Some(shared) = &shared {
                let bytes = ledger::ledger_heap(&ledger);
                assert_eq!(
                    ledger.operations.len(),
                    1024,
                    "real admitted operation ceiling"
                );
                assert_eq!(
                    ledger.entries.len(),
                    3070,
                    "real retained transition prefix"
                );
                assert!(bytes > 0);
                assert_eq!(shared.caller_bytes.swap(bytes, Ordering::SeqCst), 0);
                shared.caller_reads.fetch_add(1, Ordering::SeqCst);
            }
            Self { ledger, shared }
        }
    }

    impl Deref for CallerLedger {
        type Target = LedgerState;

        fn deref(&self) -> &Self::Target {
            &self.ledger
        }
    }

    impl Drop for CallerLedger {
        fn drop(&mut self) {
            if let Some(shared) = &self.shared {
                // Stop observing before Rust drops the actual ledger fields.
                // Neither the registry nor the SQL observer retains this owner.
                shared.caller_bytes.store(0, Ordering::SeqCst);
                shared.caller_drops.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    pub(crate) fn current_bytes() -> usize {
        ACTIVE.with(|slot| {
            slot.borrow()
                .as_ref()
                .map_or(0, |shared| shared.caller_bytes.load(Ordering::SeqCst))
        })
    }

    pub(crate) struct NativeApply {
        shared: Arc<Shared>,
        guard: Option<ObservationGuard>,
    }

    impl NativeApply {
        pub(crate) fn start(entries: &Vec<Entry<ConfigRaftTypeConfig>>) -> Option<Self> {
            let (command, shared) = entries.iter().find_map(|entry| {
                let EntryPayload::Normal(command) = &entry.payload else {
                    return None;
                };
                find(command.request_id).map(|shared| (command, shared))
            })?;
            assert_eq!(
                entries.len(),
                1,
                "the measured page contains the exact submitted entry"
            );
            let ConfigMutationIntent::AuditedMutation(prepared) = &command.intent else {
                panic!("registered public audited effect");
            };
            assert_ne!(
                std::ptr::from_ref(&**prepared) as usize,
                shared.original_payload,
                "NATIVE_PAGE_OWNER: native apply must own a distinct decoded command"
            );
            let mut base = shared.base;
            base.apply_page = entries.capacity()
                * std::mem::size_of::<Entry<ConfigRaftTypeConfig>>()
                + super::command_heap(prepared);
            assert_eq!(shared.native_calls.fetch_add(1, Ordering::SeqCst), 0);
            ACTIVE.with(|slot| {
                assert!(slot.borrow_mut().replace(Arc::clone(&shared)).is_none());
            });
            Some(Self {
                shared,
                guard: Some(ObservationGuard::start(base)),
            })
        }
    }

    impl Drop for NativeApply {
        fn drop(&mut self) {
            let result = self
                .guard
                .take()
                .expect("native observation guard")
                .finish();
            *self.shared.result.lock().expect("native ledger result") = Some(result);
            ACTIVE.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }
}

fn command_heap(command: &AuditedConfigCommand) -> usize {
    let AuditedConfigEffect::BoundedAppend { commit, .. } = &command.effect else {
        panic!("bounded append fixture");
    };
    // Distinct Arc payloads and owned Vec/String capacities, each counted once.
    // Small Arc headers/reservation bookkeeping are omitted from this lower bound.
    size_of::<AuditedMutationFields>()
        + size_of::<PreparedConfigCommit>()
        + commit.record.encrypted_blob.capacity()
        + commit.record.plaintext_digest.capacity()
        + commit.record.principal.capacity()
        + commit.audit.capacity() * size_of::<crate::AuditRecord>()
        + commit
            .audit
            .iter()
            .map(|entry| {
                entry.yang_path.capacity()
                    + entry.previous_value.as_ref().map_or(0, String::capacity)
                    + entry.new_value.as_ref().map_or(0, String::capacity)
            })
            .sum::<usize>()
}

fn event(number: u64, principal: &str) -> crate::ManagementAuditEventRecord {
    let mut request = [0x95; 16];
    request[..8].copy_from_slice(&number.to_be_bytes());
    crate::ManagementAuditEventRecord::try_new(
        request,
        crate::ManagementAuditInstant::try_new(
            100,
            999_999_999,
            1,
            crate::ManagementAuditTimeSourceCode::NodeClock,
        )
        .expect("synthetic event time"),
        "test",
        principal,
        crate::ManagementAuditTransportCode::Gnmi,
        crate::ManagementAuditOperationCode::Update,
        crate::ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/fixture:configuration"],
        Some("synthetic-allocation-control"),
    )
    .expect("synthetic event")
}

fn retained_prefix(
    identity: ConfigConsensusIdentity,
    key: &AuditKey,
    privacy: &AuditPrivacyKey,
) -> LedgerState {
    let mut ledger = LedgerState::new(
        identity,
        privacy
            .project(AuditPrivacyPurpose::KeyIdentity, &[])
            .expect("projection identity"),
        AuditLedgerLimits::new(4096, 1024).expect("unchanged ledger limits"),
    );
    // Finite component setup before the core starts. Every historical operation
    // follows real authenticated admission, rejection and terminal transitions.
    // The final operation below is publicly prepared, admitted and submitted.
    for number in 0..1023_u64 {
        let projected = ProjectedAuditEvent::project(
            privacy,
            &event(
                number,
                "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/0",
            ),
        )
        .expect("real projection");
        let binding = AuditOperationBinding::project(privacy, &projected, 0, &[0x96; 32])
            .expect("real binding");
        let mut nonce = [0x95; 16];
        nonce[..8].copy_from_slice(&number.to_be_bytes());
        let handle = AuditOperationHandle::issue(
            HandleBody {
                version: 1,
                identity,
                binding,
                event: projected,
                issued_at: 100,
                expires_at: 160,
                nonce,
                key_epoch: key.epoch(),
                mutation: None,
            },
            key,
        )
        .expect("authenticated historical operation");
        ledger.admit(key, &handle, 100).expect("historical Intent");
        ledger
            .resolve(key, &handle, AuditOperationState::Rejected)
            .expect("historical rejection");
        ledger
            .acknowledge_terminal(key, &handle)
            .expect("historical terminal");
    }
    ledger
        .validate(key, identity)
        .expect("full authenticated prefix validation");
    assert_eq!(
        (ledger.operations.len(), ledger.entries.len()),
        (1023, 3069)
    );
    ledger
}

fn applied(admission: AuditAdmission) -> AuditOperationReceipt {
    match admission {
        AuditAdmission::Applied(receipt) => receipt,
        other => panic!("expected real durable receipt: {other:?}"),
    }
}

async fn ready(store: &ConsensusConfigStore) {
    assert_eq!(store.capacity_profile(), ConfigCapacityProfile::BoundedV1);
    store
        .initialize_cluster()
        .await
        .expect("initialize singleton");
    let deadline = tokio::time::Instant::now() + store.inner.operation_timeout;
    store
        .wait_for_known_leader(deadline)
        .await
        .expect("natural leadership");
    assert!(matches!(
        store.local_read_barrier(deadline).await,
        ReadBarrierReply::Ready(_)
    ));
}

#[tokio::test]
async fn config_capacity_957_public_audited_caller_ledger_lifetime() {
    let scratch = std::env::var_os("TMPDIR")
        .or_else(|| {
            (std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true"))
                .then(|| std::env::var_os("RUNNER_TEMP"))
                .flatten()
        })
        .expect("explicit disk scratch root");
    let root = tempfile::Builder::new()
        .prefix("config-capacity-caller-")
        .tempdir_in(scratch)
        .expect("private disk fixture")
        .keep();
    let filesystem = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(&root)
        .output()
        .expect("filesystem detector");
    assert!(filesystem.status.success());
    let filesystem = std::str::from_utf8(&filesystem.stdout)
        .expect("filesystem name")
        .trim();
    assert!(!filesystem.is_empty() && !matches!(filesystem, "tmpfs" | "ramfs"));
    let topology = topology();
    let identity = topology.identity();
    let key = AuditKey::new([0x93; 32]).expect("synthetic key");
    let privacy = AuditPrivacyKey::new([0x94; 32]).expect("synthetic privacy key");
    let options = RetainedConfigOptions::new(
        root.join("config.sqlite"),
        RetainedConfigBinding::new(topology.clone(), [0x91; 32], [0x92; 32])
            .expect("retained binding")
            .with_capacity_profile(ConfigCapacityProfile::BoundedV1),
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        DURABLE_CONSENSUS_OPERATION_TIMEOUT,
    )
    .expect("unchanged native limits");
    let backend = SqliteBackend::provision_config_authority(options.clone(), key.clone())
        .await
        .expect("real retained authority");
    let prefix = retained_prefix(identity, &key, &privacy);
    let setup_key = key.clone();
    crate::consensus::run_backend_sqlite_with_timeout(
        &backend,
        DURABLE_CONSENSUS_OPERATION_TIMEOUT,
        move |conn, cancellation| {
            cancellation.check_io()?;
            crate::consensus::audit::write_sync(conn, &setup_key, identity, Some(prefix), false)
        },
    )
    .await
    .expect("canonical authenticated component preseed before core open");
    let store = ConsensusConfigStore::open(
        topology.clone(),
        backend,
        root.join("snapshots"),
        BTreeMap::new(),
    )
    .await
    .expect("full native validation of retained prefix");
    ready(&store).await;
    store
        .initialize_audit_authority(
            &privacy,
            AuditLedgerLimits::new(4096, 1024).expect("original limits"),
        )
        .await
        .expect("public authority initialization agrees with retained prefix");

    let reservation = store
        .try_reserve_config_preparation()
        .expect("public destination admission")
        .expect("bounded reservation before input allocation");
    let tx_id = TxId::from_uuid(uuid::Uuid::from_u128(0x9800));
    let committed_at: Timestamp = "1970-01-01T00:01:40Z"
        .parse()
        .expect("synthetic record time");
    let principal_prefix =
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/";
    let principal = format!(
        "{principal_prefix}{}",
        "p".repeat(16_384 - principal_prefix.len())
    );
    let schema_digest = SchemaDigest::from_bytes([0x99; 32]);
    let key_id = KeyId::new("k".repeat(512)).expect("maximum key ID");
    let provider = MemoryKeyProvider::new();
    provider
        .insert_active_key(
            key_id.clone(),
            KeyPurpose::Config,
            TenantId::from_static("test"),
            Zeroizing::new([0x9A; 32]),
        )
        .expect("synthetic provider");
    let make_aad = |name: &str| {
        EnvelopeAad::config(
            TenantId::from_static("test"),
            1,
            ConfigAad::new(tx_id, None, committed_at, &principal, schema_digest, name)
                .expect("real bound metadata"),
        )
    };
    let mut name = String::from("synthetic-\"\\é-");
    let initial = opc_key::serialize_bound_aad(&make_aad(&name), &key_id)
        .expect("base AAD")
        .len();
    name.extend(std::iter::repeat_n('s', 65_536 - initial));
    let aad = make_aad(&name);
    assert_eq!(
        opc_key::serialize_bound_aad(&aad, &key_id)
            .expect("maximum AAD")
            .len(),
        65_536
    );
    let mut plaintext = b"\x89OPCCFG\x02\r\n\x1a\n{\"config\":\"".to_vec();
    plaintext.extend(std::iter::repeat_n(b'x', 1_572_864 - 2));
    plaintext.extend_from_slice(b"\",\"source\":null,\"idempotency_key\":\"");
    plaintext.resize(1_572_864 + 65_536 - 2, b'r');
    plaintext.extend_from_slice(b"\"}");
    assert_eq!(plaintext.len(), 1_638_400);
    let envelope = opc_crypto::encrypt_reserved_bounded_config_envelope(
        reservation,
        &provider,
        &aad,
        &plaintext,
    )
    .await
    .expect("real at-limit encryption with destination reservation");
    let mut encrypted_blob = envelope.encoded().to_vec();
    encrypted_blob.reserve_exact(14 * 1024 * 1024 - encrypted_blob.len());
    let record = CommitRecord {
        tx_id,
        parent_tx_id: None,
        version: ConfigVersion::new(1),
        committed_at,
        principal,
        source: crate::CommitSource::Gnmi,
        schema_digest,
        plaintext_digest: Sha256::digest(&plaintext).to_vec(),
        encrypted_blob,
        rollback_point: false,
        confirmed_deadline: None,
    };
    let audit = (0..22)
        .map(|sequence| crate::AuditRecord {
            tx_id,
            sequence,
            yang_path: format!(
                "/fixture:{}",
                "x".repeat(if sequence == 21 { 128 } else { 8192 } - 9)
            ),
            op_type: crate::types::AuditOpType::Update,
            previous_value: Some("synthetic-before".to_owned()),
            new_value: Some("synthetic-after".to_owned()),
            redaction_applied: false,
            previous_hash: [0; 32],
            entry_hmac: [0; 32],
        })
        .collect();
    // The retained record's canonical principal metadata and the management
    // caller projection have independent size contracts; keep both valid.
    let caller_principal =
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/0";
    let event = event(1023, caller_principal);
    let caller = AuditCaller::project(&privacy, "test", caller_principal).expect("trusted caller");
    let attested =
        AttestedConfigCommit::try_new(record, audit, envelope.claim().expect("original claim"))
            .expect("exact plaintext attestation");
    let evidence = attested.capacity_evidence().expect("genuine size evidence");
    assert_eq!(
        (evidence.logical_bytes(), evidence.replay_bytes()),
        (1_572_864, 65_536)
    );
    let prepared = store
        .prepare_audited_commit(&privacy, &event, attested, Duration::from_secs(60))
        .expect("public bounded audited preparation admits real spare capacity");
    let handle = prepared.handle().clone();
    let request = derive_durable_request_id(identity, b"audit-config", &handle.mac);
    let probe = ConfigConsensusCommandSizeProbe {
        schema_version: 8,
        identity,
        request_id: request,
        logical_time: maximum_encoded_config_timestamp().expect("real preflight time"),
        intent: &ConfigMutationIntent::AuditedMutation(prepared.command().clone()),
    };
    let metadata =
        config_command_encoded_size(&probe).expect("real command size") - envelope.encoded().len();
    assert!((METADATA_BYTES - 8192..=METADATA_BYTES).contains(&metadata));
    let admitted = applied(store.admit_audit_operation_local(&handle, caller).await);
    assert_eq!(admitted.state(), AuditOperationState::Intent);
    let recovery = prepared.encode().expect("real original recovery encoding");
    let base = Sample {
        command: command_heap(prepared.command()),
        encryption_alias: envelope.encoded().len(),
        recovery: recovery.capacity(),
        ..Sample::default()
    };
    let observation = observation::Registration::new(request, base, prepared.command());
    let receipt = applied(
        store
            .submit_audited_mutation_local(&prepared, &admitted, caller)
            .await,
    );
    assert_eq!(
        receipt.state(),
        AuditOperationState::Committed { version: 1 }
    );
    let terminal = applied(store.finish_audit_operation(&handle, caller).await);
    assert!(terminal.terminal_recorded());
    assert_eq!(terminal.state(), receipt.state());
    verify(&store, &provider, &aad, &plaintext, &prepared, caller).await;
    store.shutdown().await.expect("join native owners");
    drop(store);
    let backend = SqliteBackend::reopen_config_authority(options, key)
        .await
        .expect("full original retained authority validation");
    let reopened =
        ConsensusConfigStore::open(topology, backend, root.join("snapshots"), BTreeMap::new())
            .await
            .expect("real retained engine reopen");
    ready(&reopened).await;
    verify(&reopened, &provider, &aad, &plaintext, &prepared, caller).await;
    reopened.shutdown().await.expect("join reopened owners");
    let measured = observation.finish();
    // These legal original owners actually survive the measured native apply.
    // Test-only plaintext/decryption witnesses are outside the production inventory.
    assert!(!recovery.is_empty());
    let AuditedConfigEffect::BoundedAppend { commit, .. } = &prepared.command().effect else {
        panic!("bounded effect");
    };
    assert!(
        envelope.encoded() == commit.record.encrypted_blob,
        "exact original envelope alias"
    );
    assert!(commit.record.encrypted_blob.capacity() >= 14 * 1024 * 1024);
    assert!(measured.apply_reads >= 2 && measured.writes == 1);
    assert_eq!(measured.derived_len, 1024);
    assert!(
        measured.peak.apply_page > 0
            && measured.peak.decoded_ledger > 0
            && measured.peak.row_json > 0
    );
    println!("CONFIG_CAPACITY_PUBLIC_CALLER_LEDGER metadata={metadata} exact_readback=true original_recovery=true retained_reopen=true measured={measured:?}");
    assert!(measured.peak.total <= OPERATION_BYTES,
        "CONFIG_CAPACITY_PUBLIC_CALLER_LEDGER_BOUND: real public caller and native apply payloads exceed 32 MiB: {:?}", measured.peak);
}

async fn verify(
    store: &ConsensusConfigStore,
    provider: &MemoryKeyProvider,
    aad: &EnvelopeAad,
    plaintext: &[u8],
    prepared: &PreparedAuditedMutation,
    caller: AuditCaller,
) {
    let AuditedConfigEffect::BoundedAppend { commit, .. } = &prepared.command().effect else {
        panic!("bounded effect");
    };
    let before = store.inner.raft.metrics().borrow().last_log_index;
    let actual = store
        .load_latest()
        .await
        .expect("real native readback")
        .expect("committed head");
    assert!(actual.record == commit.record, "exact retained record");
    assert!(
        actual.audit == commit.audit,
        "exact retained audit metadata"
    );
    let decoded = opc_crypto::decrypt_envelope(provider, aad, &actual.record.encrypted_blob)
        .await
        .expect("authenticate exact encrypted record");
    assert!(
        decoded.as_slice() == plaintext,
        "exact authenticated plaintext"
    );
    let receipt = store
        .lookup_audit_operation(prepared.handle(), caller)
        .await
        .expect("authenticated original-handle recovery")
        .expect("retained original operation");
    assert_eq!(receipt.handle(), prepared.handle());
    assert_eq!(
        receipt.state(),
        AuditOperationState::Committed { version: 1 }
    );
    assert!(receipt.terminal_recorded());
    assert_eq!(
        store.inner.raft.metrics().borrow().last_log_index,
        before,
        "readback appends no proposal"
    );
}
