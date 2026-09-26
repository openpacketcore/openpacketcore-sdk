//! Joint encryption/replay maxima through native storage and real mTLS.

use super::*;
use opc_crypto::CryptoEnvelopeRef;
use opc_persist::audit_authority::{
    AuditAdmission, AuditAuthorityError, AuditCaller, AuditLedgerLimits, AuditOperationHandle,
    AuditOperationState, AuditPrivacyKey,
};
use opc_persist::{
    AuditOpType, AuditRecord, ManagementAuditEventRecord, ManagementAuditInstant,
    ManagementAuditOperationCode, ManagementAuditOutcomeCode, ManagementAuditTimeSourceCode,
    ManagementAuditTransportCode, StoredConfig,
};

#[path = "joint_metadata/reopen_trace.rs"]
mod reopen_trace;

const REPLAY_BYTES: usize = 65_536;
const AAD_BYTES: usize = 65_536;
const ENVELOPE_BYTES: usize = 1_704_492;
const AUDIT_RECORDS: usize = 21;
const AUDIT_PATH_BYTES: usize = 8_192;

fn key() -> KeyHandle {
    KeyHandle::new(
        KeyId::new("k".repeat(512)).expect("maximum supported key ID"),
        KeyPurpose::Config,
        TenantId::from_static("test"),
        Zeroizing::new([0xB2; 32]),
    )
}

#[derive(Default)]
struct JointProvider {
    active_calls: AtomicUsize,
}

#[async_trait]
impl KeyProvider for JointProvider {
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyHandle, KeyError> {
        self.active_calls.fetch_add(1, Ordering::SeqCst);
        let handle = key();
        if purpose == handle.purpose() && tenant == handle.tenant() {
            Ok(handle)
        } else {
            Err(KeyError::Unavailable)
        }
    }

    async fn get_key_by_id(&self, id: &KeyId) -> Result<KeyHandle, KeyError> {
        let handle = key();
        if id == handle.key_id() {
            Ok(handle)
        } else {
            Err(KeyError::Unavailable)
        }
    }

    async fn rotate_key(&self, _: KeyPurpose, _: &TenantId) -> Result<KeyId, KeyError> {
        Err(KeyError::Unavailable)
    }
}

fn principal(audited: bool) -> String {
    let bytes = if audited {
        assert_eq!(opc_persist::MANAGEMENT_AUDIT_MAX_PRINCIPAL_BYTES, 1_024);
        1_024
    } else {
        16_384
    };
    format!("{CALLER}{}", "p".repeat(bytes - CALLER.len()))
}

fn plaintext_lengths(logical_bytes: usize, replay_bytes: usize) -> Vec<u8> {
    assert_eq!(CONFIG_CAPACITY_V1_LOGICAL_BYTES, 1_572_864);
    assert!(logical_bytes >= 2);
    let mut value = b"\x89OPCCFG\x02\r\n\x1a\n{\"config\":\"".to_vec();
    value.extend(std::iter::repeat_n(b'x', logical_bytes - 2));
    value.extend_from_slice(b"\",\"source\":null,\"idempotency_key\":\"");
    assert!(value.len() + 2 <= logical_bytes + replay_bytes);
    value.resize(logical_bytes + replay_bytes - 2, b'r');
    value.extend_from_slice(b"\"}");
    assert_eq!(value.len(), logical_bytes + replay_bytes);
    value
}

fn plaintext(replay_extra: usize) -> Vec<u8> {
    plaintext_lengths(BOUNDED_LOGICAL_BYTES, REPLAY_BYTES + replay_extra)
}

fn aad(record: &CommitRecord, extra: usize) -> EnvelopeAad {
    let make = |store: &str| {
        EnvelopeAad::config(
            TenantId::from_static("test"),
            record.version.get(),
            ConfigAad::new(
                record.tx_id,
                record.parent_tx_id,
                record.committed_at,
                &record.principal,
                record.schema_digest,
                store,
            )
            .expect("valid joint AAD fields"),
        )
    };
    let mut store = String::from("synthetic-\"\\é-");
    let size = opc_key::serialize_bound_aad(&make(&store), key().key_id())
        .expect("canonical base AAD")
        .len();
    store.extend(std::iter::repeat_n('s', AAD_BYTES + extra - size));
    let aad = make(&store);
    assert_eq!(
        opc_key::serialize_bound_aad(&aad, key().key_id())
            .expect("actual canonical bound AAD")
            .len(),
        AAD_BYTES + extra
    );
    aad
}

fn record(version: u64, parent: Option<TxId>, principal: &str) -> CommitRecord {
    CommitRecord {
        tx_id: TxId::new(),
        parent_tx_id: parent,
        version: ConfigVersion::new(version),
        committed_at: Timestamp::from_offset_datetime(
            time::OffsetDateTime::from_unix_timestamp(1_900_000_000).expect("synthetic time"),
        ),
        principal: principal.into(),
        source: CommitSource::LocalOperator,
        schema_digest: SchemaDigest::from_bytes([0xB3; 32]),
        plaintext_digest: Vec::new(),
        encrypted_blob: Vec::new(),
        rollback_point: false,
        confirmed_deadline: None,
    }
}

#[derive(Clone, Copy)]
enum CommitMode {
    Ordinary,
    Pending,
    Resolve(opc_persist::ConfirmedCommitResolution),
}

async fn input(
    store: &ConsensusConfigStore,
    version: u64,
    parent: Option<TxId>,
    principal: &str,
    path_extra: usize,
) -> (AttestedConfigCommit, EnvelopeAad, Vec<u8>) {
    input_mode(
        store,
        version,
        parent,
        principal,
        path_extra,
        CommitMode::Ordinary,
    )
    .await
}

async fn input_mode(
    store: &ConsensusConfigStore,
    version: u64,
    parent: Option<TxId>,
    principal: &str,
    path_extra: usize,
    mode: CommitMode,
) -> (AttestedConfigCommit, EnvelopeAad, Vec<u8>) {
    let reservation = store
        .try_reserve_config_preparation()
        .expect("joint destination preparation admission")
        .expect("bounded destination reservation");
    let mut record = record(version, parent, principal);
    if matches!(mode, CommitMode::Pending) {
        record.confirmed_deadline = Some(Timestamp::from_offset_datetime(
            time::OffsetDateTime::from_unix_timestamp(1_900_000_060)
                .expect("synthetic pending deadline"),
        ));
    }
    let aad = aad(&record, 0);
    let plaintext = plaintext(0);
    let provider = JointProvider::default();
    let envelope = opc_crypto::encrypt_reserved_bounded_config_envelope(
        reservation,
        &provider,
        &aad,
        &plaintext,
    )
    .await
    .expect("actual joint maximum encryption");
    assert_eq!(provider.active_calls.load(Ordering::SeqCst), 1);
    assert_eq!(envelope.encoded().len(), ENVELOPE_BYTES);
    let parsed = CryptoEnvelopeRef::decode(envelope.encoded()).expect("actual encrypted envelope");
    assert_eq!(parsed.aad.len(), AAD_BYTES);
    assert_eq!(parsed.key_id.as_str().len(), 512);
    assert_eq!(parsed.nonce.len(), 12);
    assert_eq!(parsed.ciphertext_and_tag.len(), plaintext.len() + 16);
    record.encrypted_blob = envelope.encoded().to_vec();
    record.plaintext_digest = Sha256::digest(&plaintext).to_vec();
    let audit = (0..AUDIT_RECORDS)
        .map(|index| {
            let length = AUDIT_PATH_BYTES + usize::from(index == 0) * path_extra;
            let prefix = "/fixture:";
            AuditRecord {
                tx_id: record.tx_id,
                sequence: index as u32,
                yang_path: format!("{prefix}{}", "a".repeat(length - prefix.len())),
                op_type: AuditOpType::Update,
                previous_value: Some("synthetic-before".into()),
                new_value: Some("synthetic-after".into()),
                redaction_applied: false,
                previous_hash: [0; 32],
                entry_hmac: [0; 32],
            }
        })
        .collect();
    let claim = envelope.claim().expect("fresh exact encryption claim");
    let commit = match mode {
        CommitMode::Resolve(resolution) => {
            AttestedConfigCommit::try_new_resolving(record, audit, claim, resolution)
        }
        CommitMode::Ordinary | CommitMode::Pending => {
            AttestedConfigCommit::try_new(record, audit, claim)
        }
    }
    .expect("exact paired record evidence");
    (commit, aad, plaintext)
}

fn assert_readback(
    value: &StoredConfig,
    record: &CommitRecord,
    aad: &EnvelopeAad,
    plaintext: &[u8],
) {
    assert!(value.record == *record, "complete joint encrypted record");
    assert!(
        opc_crypto::decrypt_envelope_with_handle(&key(), aad, &value.record.encrypted_blob)
            .expect("authenticate complete expected joint AAD")
            .as_slice()
            == plaintext,
        "exact logical configuration plus complete encrypted replay and framing"
    );
    assert!(value.record.plaintext_digest == Sha256::digest(plaintext).as_slice());
    assert_eq!(value.audit.len(), AUDIT_RECORDS);
    assert!(value.audit.iter().enumerate().all(|(index, audit)| {
        audit.tx_id == record.tx_id
            && audit.sequence == index as u32
            && audit.op_type == AuditOpType::Update
            && audit.yang_path.len() == AUDIT_PATH_BYTES
            && audit.previous_value.as_deref() == Some("\"<redacted>\"")
            && audit.new_value.as_deref() == Some("\"<redacted>\"")
            && audit.redaction_applied
    }));
    value
        .verify_audit_chain(&AuditKey::new([0xD9; 32]).expect("original fixture audit key"))
        .expect("complete atomic audit chain");
}

fn privacy() -> AuditPrivacyKey {
    AuditPrivacyKey::new([0xB4; 32]).expect("synthetic projection key")
}

fn caller(principal: &str) -> AuditCaller {
    AuditCaller::project(&privacy(), "test", principal).expect("supported audited caller")
}

fn event(version: u64, principal: &str) -> ManagementAuditEventRecord {
    ManagementAuditEventRecord::try_new(
        [u8::try_from(version).expect("fixture version"); 16],
        ManagementAuditInstant::try_new(100, 0, 1, ManagementAuditTimeSourceCode::NodeClock)
            .expect("synthetic event time"),
        "test",
        principal,
        ManagementAuditTransportCode::Gnmi,
        ManagementAuditOperationCode::Update,
        ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/fixture:config"],
        Some("synthetic-joint-capacity"),
    )
    .expect("bounded real audit event")
}

async fn reject_crypto_one_over(
    store: &ConsensusConfigStore,
    databases: &[PathBuf; 3],
    faults: &[Arc<Fault>; 3],
    principal: &str,
) {
    let before = databases.each_ref().map(|path| effect_counts(path));
    // Keep the original joint-total negative, then isolate each independently
    // reachable logical/replay boundary at the unchanged total plaintext cap.
    let cases = [
        (
            BOUNDED_LOGICAL_BYTES,
            REPLAY_BYTES + 1,
            0,
            0,
            ConfigCapacityError::PlaintextBytes,
        ),
        (
            BOUNDED_LOGICAL_BYTES - 1,
            REPLAY_BYTES + 1,
            0,
            0,
            ConfigCapacityError::ReplayBytes,
        ),
        (
            BOUNDED_LOGICAL_BYTES + 1,
            REPLAY_BYTES - 1,
            0,
            0,
            ConfigCapacityError::LogicalBytes,
        ),
        (
            BOUNDED_LOGICAL_BYTES,
            REPLAY_BYTES,
            1,
            1,
            ConfigCapacityError::AadBytes,
        ),
    ];
    for (logical_bytes, replay_bytes, aad_extra, expected_calls, expected_error) in cases {
        let reservation = store
            .try_reserve_config_preparation()
            .expect("negative admission")
            .expect("bounded negative reservation");
        let provider = JointProvider::default();
        let aad = aad(&record(1, None, principal), aad_extra);
        let value = plaintext_lengths(logical_bytes, replay_bytes);
        let result = opc_crypto::encrypt_reserved_bounded_config_envelope(
            reservation,
            &provider,
            &aad,
            &value,
        )
        .await
        .expect_err("one-over encryption boundary rejects before proposal");
        assert_eq!(result, expected_error);
        assert_eq!(provider.active_calls.load(Ordering::SeqCst), expected_calls);
        assert_eq!(databases.each_ref().map(|path| effect_counts(path)), before);
        assert!(faults
            .iter()
            .all(|fault| fault.actual_forwards.load(Ordering::SeqCst) == 0));
        let reservations = (0..8)
            .map(|_| {
                store
                    .try_reserve_config_preparation()
                    .expect("all preparation capacity restored")
                    .expect("real bounded slot")
            })
            .collect::<Vec<_>>();
        assert!(store.try_reserve_config_preparation().is_err());
        drop(reservations);
    }
}

enum Recovery {
    Ordinary(ConfigCommitRecoveryHandle),
    Audited(Box<AuditOperationHandle>),
}

async fn recover(store: &ConsensusConfigStore, handle: &Recovery, principal: &str, version: u64) {
    match handle {
        Recovery::Ordinary(handle) => assert!(matches!(
            store
                .lookup_commit_operation(handle, principal)
                .await
                .expect("original ordinary lookup"),
            ConfigCommitRecoveryOutcome::Committed
        )),
        Recovery::Audited(handle) => assert_eq!(
            store
                .lookup_audit_operation(handle, caller(principal))
                .await
                .expect("original audited lookup")
                .expect("retained exact audited operation")
                .state(),
            AuditOperationState::Committed { version }
        ),
    }
}

native_case!(
    config_capacity_957_joint_envelope_ordinary_native_routes_and_reopen,
    {
        run(false).await;
    }
);

native_case!(
    config_capacity_957_joint_envelope_audited_native_routes_and_reopen,
    {
        run(true).await;
    }
);

async fn run(audited: bool) {
    let directory = disk_fixture();
    let pki = Pki::new();
    let manifest = manifest();
    let addresses = [0, 1, 2].map(|_| Arc::new(RwLock::new(None)));
    let faults = [0, 1, 2].map(|_| Arc::new(Fault::default()));
    let databases = [0, 1, 2].map(|index| directory.join(format!("config-{index}.sqlite")));
    let profile = ConfigCapacityProfile::BoundedV1;
    let stores = open_members(
        &directory, &manifest, &pki, &addresses, &faults, false, profile,
    )
    .await;
    let principal = principal(audited);
    reject_crypto_one_over(&stores[0], &databases, &faults, &principal).await;
    let (servers, released) = snapshot::listen(&stores, &pki, &manifest, &addresses).await;
    snapshot::ready(&stores).await;
    let leader_id = stores[0].status().leader_id.expect("joint fixture leader");
    let leader = stores
        .iter()
        .position(|store| store.status().node_id == leader_id)
        .expect("joint fixture leader membership");
    let follower = (leader + 1) % 3;
    if audited {
        stores[leader]
            .initialize_audit_authority(
                &privacy(),
                AuditLedgerLimits::new(12, 4).expect("unchanged fixture ledger limits"),
            )
            .await
            .expect("real replicated audit authority");
    }
    let mut parent = None;
    let mut committed = Vec::new();
    for (version, source) in [(1, leader), (2, follower)] {
        let local = source == leader;
        let (rejected, _, _) = input(&stores[source], version, parent, &principal, 1).await;
        let before = databases.each_ref().map(|path| effect_counts(path));
        if audited {
            assert!(matches!(
                stores[source].prepare_audited_commit(
                    &privacy(),
                    &event(version, &principal),
                    rejected,
                    Duration::from_secs(60)
                ),
                Err(AuditAuthorityError::InvalidInput)
            ));
        } else {
            let error = stores[source]
                .prepare_recoverable_commit(
                    ConfigConsensusRequestId::from_bytes([0xB5; 16]),
                    rejected,
                    &principal,
                )
                .expect_err("audit path one-over must reject before sending");
            assert!(matches!(
                error.kind(),
                PersistErrorKind::ConstraintViolation(_)
            ));
        }
        assert_eq!(databases.each_ref().map(|path| effect_counts(path)), before);

        let (input, aad, plaintext) = input(&stores[source], version, parent, &principal, 0).await;
        let expected = input.record().clone();
        let forwards = faults[source].actual_forwards.load(Ordering::SeqCst);
        let handle = if audited {
            let prepared = stores[source]
                .prepare_audited_commit(
                    &privacy(),
                    &event(version, &principal),
                    input,
                    Duration::from_secs(60),
                )
                .expect("joint maximum audited preparation");
            let handle = prepared.handle().clone();
            let admission = if local {
                stores[source]
                    .admit_audit_operation_local(&handle, caller(&principal))
                    .await
            } else {
                stores[source]
                    .admit_audit_operation(&handle, caller(&principal))
                    .await
            };
            let AuditAdmission::Applied(admission) = admission else {
                panic!("joint maximum intent must have a real authoritative receipt");
            };
            assert_eq!(admission.state(), AuditOperationState::Intent);
            let result = if local {
                stores[source]
                    .submit_audited_mutation_local(&prepared, &admission, caller(&principal))
                    .await
            } else {
                stores[source]
                    .submit_audited_mutation(&prepared, &admission, caller(&principal))
                    .await
            };
            let AuditAdmission::Applied(result) = result else {
                panic!("joint maximum audited mutation must be durably committed");
            };
            assert_eq!(result.state(), AuditOperationState::Committed { version });
            Recovery::Audited(Box::new(handle))
        } else {
            let prepared = stores[source]
                .prepare_recoverable_commit(
                    ConfigConsensusRequestId::from_bytes([0xB5 + version as u8; 16]),
                    input,
                    &principal,
                )
                .expect("joint maximum ordinary preparation");
            let handle = prepared.recovery_handle().clone();
            if local {
                stores[source].append_prepared_commit_local(prepared).await
            } else {
                stores[source].append_prepared_commit(prepared).await
            }
            .expect("joint maximum ordinary durable acknowledgement");
            Recovery::Ordinary(handle)
        };
        assert_eq!(
            faults[source].actual_forwards.load(Ordering::SeqCst) - forwards,
            if local {
                0
            } else if audited {
                2
            } else {
                1
            }
        );
        for store in &stores {
            let value = store
                .load_latest()
                .await
                .expect("joint quorum read")
                .expect("joint committed record");
            assert_readback(&value, &expected, &aad, &plaintext);
            recover(store, &handle, &principal, version).await;
        }
        for path in &databases {
            let counts = effect_counts(path);
            assert_eq!(counts[0], version as i64);
            assert_eq!(counts[1], (version as usize * AUDIT_RECORDS) as i64);
        }
        parent = Some(expected.tx_id);
        committed.push((handle, expected, aad, plaintext));
    }
    snapshot::stop(stores, servers, released, &addresses).await;
    let authority_before = databases.each_ref().map(|path| {
        let counts = effect_counts(path);
        [counts[0], counts[1], counts[3]]
    });
    let stores = open_members(
        &directory, &manifest, &pki, &addresses, &faults, true, profile,
    )
    .await;
    assert_eq!(
        databases.each_ref().map(|path| {
            let counts = effect_counts(path);
            [counts[0], counts[1], counts[3]]
        }),
        authority_before,
        "original retained authority survives before transport starts"
    );
    let (servers, released) = snapshot::listen(&stores, &pki, &manifest, &addresses).await;
    snapshot::ready(&stores).await;
    let effects_before = databases.each_ref().map(|path| effect_counts(path));
    let forwards_before: usize = faults
        .iter()
        .map(|fault| fault.actual_forwards.load(Ordering::SeqCst))
        .sum();
    for store in &stores {
        for (handle, record, _, _) in &committed {
            recover(store, handle, &principal, record.version.get()).await;
        }
        let (_, expected, aad, plaintext) = committed.last().expect("exact final record");
        let value = store
            .load_latest()
            .await
            .expect("retained quorum read")
            .expect("retained joint record");
        assert_readback(&value, expected, aad, plaintext);
    }
    assert_eq!(
        databases.each_ref().map(|path| effect_counts(path)),
        effects_before
    );
    assert_eq!(
        faults
            .iter()
            .map(|fault| fault.actual_forwards.load(Ordering::SeqCst))
            .sum::<usize>(),
        forwards_before
    );
    snapshot::stop(stores, servers, released, &addresses).await;
    println!("CONFIG_CAPACITY_JOINT_NATIVE audited={audited} logical=1572864 replay=65536 aad=65536 key_id=512 envelope=1704492 audit_paths=21 local=true forwarded=true atomic=true original_paths=true original_handles=true resubmitted=false");
}

#[path = "joint_metadata/resolutions.rs"]
mod resolutions;

#[path = "joint_metadata/audited_recovery.rs"]
mod audited_recovery;

#[path = "joint_metadata/process_loss.rs"]
mod process_loss;

#[path = "joint_metadata/history_capacity.rs"]
mod history_capacity;

#[path = "joint_metadata/remote_history.rs"]
mod remote_history;

#[path = "joint_metadata/audited_snapshot.rs"]
mod audited_snapshot;
