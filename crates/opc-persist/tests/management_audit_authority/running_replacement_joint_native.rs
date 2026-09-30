//! Native Durable execution for the independently selected bounded Running subset.
//! These detectors also compile against the frozen closed baseline: selecting the
//! newly named profile must then fail, never silently choose an older family.

use super::*;
use crate::audit_authority::PreparedTargetMutation;
use crate::consensus::sqlite::SqliteWorkCancellation;
use crate::consensus::{ConfigMutationIntent, RetainedConfigMode};
use opc_consensus::engine::raft::{AppendEntriesRequest, InstallSnapshotRequest, VoteRequest};
use opc_consensus::engine::storage::RaftStateMachine;
use opc_consensus::engine::{RaftSnapshotBuilder, StoredMembership, Vote};

#[path = "running_replacement_cleanup_admission.rs"]
mod cleanup_admission;

fn profile() -> RetainedConfigProfile {
    serde_json::from_str("\"netconf-running-v1\"").expect("JOINT_NATIVE_EXPLICIT_PROFILE")
}
fn durability() -> RetainedConfigDurability {
    RetainedConfigDurability::Durable {
        min_free_bytes: 128 * 1024 * 1024,
    }
}
fn require_disk_scratch() {
    let scratch = std::env::var_os("TMPDIR").expect("explicit private disk TMPDIR");
    let output = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(scratch)
        .output()
        .unwrap();
    assert!(output.status.success());
    let kind = std::str::from_utf8(&output.stdout).unwrap().trim();
    assert!(!kind.is_empty() && !matches!(kind, "tmpfs" | "ramfs"));
}
fn policy(checkpoint: Arc<Checkpoint>) -> AuditContinuityPolicy {
    AuditContinuityPolicy::new(
        AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x52; 32]).unwrap()]).unwrap(),
        checkpoint,
        1,
        1,
    )
    .unwrap()
}
fn topology(f: &Fixture) -> ConfigConsensusTopology {
    ConfigConsensusTopology::try_new(
        f.store.inner.identity,
        f.store.inner.local_node_id,
        BTreeSet::from([f.store.inner.local_node_id]),
    )
    .unwrap()
}
fn options(f: &Fixture) -> RetainedConfigOptions {
    RetainedConfigOptions::new(
        f.dir.path().join("authority.sqlite"),
        f.store.inner.backend.retained_binding.clone().unwrap(),
        durability(),
        256 * 1024 * 1024,
        Duration::from_secs(30),
    )
    .unwrap()
}
async fn fixture() -> Fixture {
    require_disk_scratch();
    let dir = tempfile::tempdir().unwrap();
    let node = crate::consensus::ConfigConsensusNodeId::new(1).unwrap();
    let identity = crate::consensus::ConfigConsensusIdentity::new(
        crate::consensus::ConfigConsensusClusterId::from_bytes([0x31; 32]),
        crate::consensus::ConfigConsensusConfigurationId::from_bytes([0x32; 32]),
        crate::consensus::ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let topology =
        ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node])).unwrap();
    let backend = SqliteBackend::provision_config_authority(
        RetainedConfigOptions::new(
            dir.path().join("authority.sqlite"),
            RetainedConfigBinding::new(topology.clone(), [0x41; 32], [0x42; 32])
                .unwrap()
                .with_profile(profile())
                .with_capacity_profile(opc_crypto::ConfigCapacityProfile::BoundedV1),
            durability(),
            256 * 1024 * 1024,
            Duration::from_secs(30),
        )
        .unwrap(),
        AuditKey::new([0x51; 32]).unwrap(),
    )
    .await
    .unwrap();
    let checkpoint = Arc::new(Checkpoint::default());
    let policy = AuditContinuityPolicy::new(
        AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x52; 32]).unwrap()]).unwrap(),
        checkpoint.clone(),
        1,
        1,
    )
    .unwrap();
    let store = ConsensusConfigStore::open_with_audit_continuity(
        topology,
        backend,
        dir.path().join("snapshots"),
        BTreeMap::new(),
        policy,
    )
    .await
    .unwrap();
    store.initialize_cluster().await.unwrap();
    store
        .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(96, 32).unwrap())
        .await
        .unwrap();
    let prepared = store
        .prepare_netconf_device(
            &privacy(),
            &event(1, ManagementAuditOperationCode::Exec, None),
            LIFETIME,
        )
        .await
        .unwrap();
    let intent = applied(
        store
            .admit_netconf_target_local(prepared.mutation(), caller())
            .await,
    );
    let receipt = applied(
        store
            .submit_netconf_target_local(prepared.mutation(), &intent, caller())
            .await,
    );
    store
        .complete_required_audit_outcome(&receipt, caller())
        .await
        .unwrap();
    let device = store
        .claim_netconf_device_owner(&prepared, &receipt, caller())
        .await
        .unwrap();
    let provider = opc_key::MemoryKeyProvider::new();
    provider
        .insert_active_key(
            opc_key::KeyId::new("synthetic-running-key").unwrap(),
            opc_key::KeyPurpose::Config,
            TenantId::new(TENANT).unwrap(),
            zeroize::Zeroizing::new([0x61; 32]),
        )
        .unwrap();
    Fixture {
        store,
        device,
        checkpoint,
        provider,
        dir,
    }
}

async fn prepare(
    f: &Fixture,
    session: &NetconfSessionOwner,
    request: u8,
    plaintext: &[u8],
) -> (PreparedTargetMutation, CommitRecord) {
    prepare_with_marker(f, session, request, plaintext, false).await
}

async fn prepare_with_marker(
    f: &Fixture,
    session: &NetconfSessionOwner,
    request: u8,
    plaintext: &[u8],
    recovery_required: bool,
) -> (PreparedTargetMutation, CommitRecord) {
    let frozen = f.store.read_netconf_running_edit(session).await.unwrap();
    // Reserve before this SDK-owned record/encryption allocation, with the
    // destination's actual public pool; a provider claim alone cannot admit it.
    let reservation = f.store.try_reserve_config_preparation().unwrap().unwrap();
    let mut record = CommitRecord {
        tx_id: TxId::new(),
        parent_tx_id: frozen.tx_id(),
        version: ConfigVersion::new(frozen.running_base_version() + 1),
        committed_at: Timestamp::now_utc(),
        principal: if recovery_required {
            serde_json::json!({"principal": PRINCIPAL, "recovery_required": true}).to_string()
        } else {
            PRINCIPAL.to_owned()
        },
        source: crate::CommitSource::Netconf,
        schema_digest: SchemaDigest::from_bytes([0x62; 32]),
        plaintext_digest: Sha256::digest(plaintext).to_vec(),
        encrypted_blob: Vec::new(),
        rollback_point: false,
        confirmed_deadline: None,
    };
    let aad = EnvelopeAad::config(
        TenantId::new(TENANT).unwrap(),
        record.version.get(),
        ConfigAad::new(
            record.tx_id,
            record.parent_tx_id,
            record.committed_at,
            PRINCIPAL,
            record.schema_digest,
            "running",
        )
        .unwrap(),
    );
    let encrypted = opc_crypto::encrypt_reserved_bounded_config_envelope(
        reservation,
        &f.provider,
        &aad,
        plaintext,
    )
    .await
    .unwrap();
    record.encrypted_blob = encrypted.encoded().to_vec();
    let commit =
        AttestedConfigCommit::try_new(record.clone(), Vec::new(), encrypted.claim().unwrap())
            .unwrap();
    let prepared = f
        .store
        .prepare_netconf_running_replacement(
            session,
            &frozen,
            commit,
            &privacy(),
            &event(
                request,
                ManagementAuditOperationCode::Replace,
                Some(record.tx_id),
            ),
            LIFETIME,
        )
        .await
        .expect("JOINT_NATIVE_RUNNING_PREPARATION");
    assert_eq!(
        &prepared
            .command()
            .bounded_running()
            .unwrap()
            .commit()
            .record,
        &record,
        "JOINT_NATIVE_CANONICAL_PREPARED_RECORD"
    );
    assert_eq!(
        prepared.encode().unwrap(),
        serde_json::to_vec(prepared.command()).unwrap(),
        "JOINT_NATIVE_CANONICAL_ORIGINAL_BYTES"
    );
    (prepared, record)
}

#[path = "running_replacement_publication.rs"]
mod publication;

async fn readback(
    store: &ConsensusConfigStore,
    provider: &opc_key::MemoryKeyProvider,
    expected: &CommitRecord,
    plaintext: &[u8],
) {
    let actual = store.load_latest().await.unwrap().unwrap();
    assert_eq!(&actual.record, expected, "JOINT_NATIVE_EXACT_RECORD");
    let envelope = opc_crypto::CryptoEnvelopeRef::decode(&actual.record.encrypted_blob).unwrap();
    let (aad, _) = opc_key::decode_bound_aad(envelope.aad).unwrap();
    let recovered = opc_crypto::decrypt_envelope(provider, &aad, &actual.record.encrypted_blob)
        .await
        .unwrap();
    assert_eq!(
        recovered.as_slice(),
        plaintext,
        "JOINT_NATIVE_AEAD_READBACK"
    );
}

async fn schema_and_proof(
    backend: &SqliteBackend,
    identity: crate::ConfigConsensusIdentity,
    expected: usize,
) {
    let shared = backend.conn();
    let conn = shared.lock().await;
    assert!(
        crate::schema::verify_wal_mode(&conn).unwrap(),
        "JOINT_NATIVE_WAL"
    );
    assert!(
        crate::schema::verify_synchronous_extra(&conn).unwrap(),
        "JOINT_NATIVE_DURABLE"
    );
    let revision: u16 = conn
        .query_row(
            "SELECT schema_version FROM config_raft_identity WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(revision, 8, "JOINT_NATIVE_SCHEMA_IDENTITY");
    let history: Vec<u8> = conn
        .query_row(
            "SELECT state_json FROM config_raft_history_retention WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let history: serde_json::Value = serde_json::from_slice(&history).unwrap();
    assert_eq!(history["format_version"], 2);
    assert_eq!(
        history["capacity_profile"],
        opc_crypto::ConfigCapacityProfile::BoundedV1.revision()
    );
    let mode = backend.retained_binding.as_ref().unwrap().mode().unwrap();
    crate::consensus::history::validate_access_for_profile_sync(
        &conn,
        backend.audit_key(),
        true,
        Some(identity),
        mode,
        &SqliteWorkCancellation::audit_test(),
    )
    .expect("JOINT_NATIVE_AUTHENTICATED_SCAN");
    let counts: (usize, usize) = conn.query_row(
        "SELECT (SELECT COUNT(*) FROM config_history),(SELECT COUNT(*) FROM config_raft_capacity_records)",
        [], |r| Ok((r.get(0)?,r.get(1)?))).unwrap();
    assert_eq!(
        counts,
        (expected, expected),
        "JOINT_NATIVE_ONE_PROOF_PER_RECORD"
    );
}

async fn effect_rows(
    store: &ConsensusConfigStore,
) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    let shared = store.inner.backend.conn();
    let conn = shared.lock().await;
    [
        "config_history",
        "config_raft_capacity_records",
        "config_raft_history_retention",
        "config_raft_management_audit",
        "config_netconf_profile",
        "config_netconf_targets",
        "config_netconf_lifecycle",
    ]
    .into_iter()
    .map(|table| {
        let mut query = conn
            .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
            .unwrap();
        let columns = query.column_count();
        let rows = query
            .query_map([], |r| {
                (0..columns)
                    .map(|i| r.get(i))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        (table.to_owned(), rows)
    })
    .collect()
}

#[tokio::test]
async fn joint_native_running_intent_apply_terminal_debt_reopens_exact_original() {
    let started = std::time::Instant::now();
    let applied_in_phase = |phase: &str, value: AuditAdmission| {
        eprintln!(
            "JOINT_NATIVE_PHASE {phase} elapsed_ms={}",
            started.elapsed().as_millis()
        );
        match value {
            AuditAdmission::Applied(receipt) => receipt,
            other => panic!(
                "JOINT_NATIVE_PHASE {phase}: expected original authoritative result: {other:?}"
            ),
        }
    };
    let f = fixture().await;
    f.store
        .inner
        .durable_progress
        .append_observed_from
        .set(started)
        .expect("one native apply phase observer");
    schema_and_proof(&f.store.inner.backend, f.store.inner.identity, 0).await;
    let session = f.session().await;
    // Exercise the exact logical limit of the explicitly selected capacity profile.
    let mut plaintext = vec![b'x'; opc_crypto::CONFIG_CAPACITY_V1_LOGICAL_BYTES];
    plaintext[0] = b'"';
    *plaintext.last_mut().unwrap() = b'"';
    let (prepared, record) = prepare(&f, &session, 2, &plaintext).await;
    let bytes = prepared.encode().unwrap();
    let handle = prepared.handle().clone();
    let forwarded = ForwardMutationRequest {
        request_id: opc_consensus::ConsensusRequestId::from_bytes([0xB2; 16]),
        intent: ConfigMutationIntent::ManagementAudit(Box::new(
            crate::consensus::audit::AuditCommand::NetconfTarget(Box::new(
                crate::consensus::audit_mutation::TargetAuditCommandV1::Admit(
                    prepared.command().clone(),
                ),
            )),
        )),
        compatibility: f.store.peer_compatibility(),
        budget: ForwardedBudget {
            remaining_nanos: 2_000_000_000,
        },
    };
    let wire = encode_config_wire_for_profile(f.store.mode(), &forwarded).unwrap();
    let decoded =
        decode_forward_mutation(f.store.mode(), &wire).expect("JOINT_NATIVE_EXACT_WIRE10_DECODER");
    assert_eq!(
        decoded.intent, forwarded.intent,
        "JOINT_NATIVE_CANONICAL_WIRE10_RECORD"
    );
    drop(decoded);
    drop(wire);
    drop(forwarded);
    assert!(
        f.store.load_latest().await.unwrap().is_none(),
        "preparation has no effect"
    );
    let intent = applied_in_phase(
        "intent",
        f.store
            .admit_netconf_running_replacement_local(&session, &prepared, caller())
            .await,
    );
    assert_eq!(
        intent.state(),
        AuditOperationState::Intent,
        "JOINT_NATIVE_REQUIRED_INTENT"
    );
    assert!(
        f.store.load_latest().await.unwrap().is_none(),
        "JOINT_NATIVE_INTENT_NO_EFFECT"
    );
    let original = f
        .store
        .recover_netconf_target(&handle, caller())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        original.encode().unwrap(),
        bytes,
        "JOINT_NATIVE_INTENT_RETAINED_ORIGINAL"
    );
    drop(original);
    let apply_watch = crate::consensus::audit_targets::history_gate_tests::apply_original_tests::ApplyWatch::start(&handle);
    let receipt = applied_in_phase(
        "apply",
        f.store
            .submit_netconf_target_local(&prepared, &intent, caller())
            .await,
    );
    assert!(
        matches!(receipt.state(), AuditOperationState::TargetV1(_)),
        "JOINT_NATIVE_KNOWN_APPLY"
    );
    assert!(!receipt.terminal_recorded());
    readback(&f.store, &f.provider, &record, &plaintext).await;
    schema_and_proof(&f.store.inner.backend, f.store.inner.identity, 1).await;
    f.checkpoint.unavailable.store(true, Ordering::Release);
    assert!(
        f.store
            .complete_required_audit_outcome(&receipt, caller())
            .await
            .is_err(),
        "real independent persistence failure leaves original debt"
    );
    let truthful = applied_in_phase(
        "replay_after_checkpoint_failure",
        f.store
            .submit_netconf_target_local(&prepared, &receipt, caller())
            .await,
    );
    assert_eq!(
        truthful.state(),
        receipt.state(),
        "JOINT_NATIVE_TRUTHFUL_COMMIT_AFTER_REPORT_FAILURE"
    );
    f.checkpoint.unavailable.store(false, Ordering::Release);
    let next = f
        .store
        .prepare_netconf_lock_acquisition(
            &session,
            NetconfLockDatastore::Running,
            &privacy(),
            &event(4, ManagementAuditOperationCode::Exec, None),
            LIFETIME,
        )
        .await;
    assert!(
        matches!(next, Err(AuditAuthorityError::RecoveryRequired)),
        "JOINT_NATIVE_DEBT_FENCES_NEXT_INTENT"
    );
    drop(session);
    drop(prepared);
    let retained_options = options(&f);
    let topology = topology(&f);
    let expected_rows = effect_rows(&f.store).await;
    let Fixture {
        store,
        device,
        checkpoint,
        provider,
        dir,
    } = f;
    drop(device);
    store.shutdown().await.unwrap();
    drop(store);
    let backend = SqliteBackend::reopen_config_authority(
        retained_options.clone(),
        AuditKey::new([0x51; 32]).unwrap(),
    )
    .await
    .expect("JOINT_NATIVE_RETAINED_REOPEN");
    schema_and_proof(&backend, topology.identity(), 1).await;
    let store = ConsensusConfigStore::open_with_audit_continuity(
        topology.clone(),
        backend,
        dir.path().join("snapshots"),
        BTreeMap::new(),
        policy(checkpoint.clone()),
    )
    .await
    .unwrap();
    store.initialize_cluster().await.unwrap();
    readback(&store, &provider, &record, &plaintext).await;
    assert_eq!(
        effect_rows(&store).await,
        expected_rows,
        "JOINT_NATIVE_EXACT_REOPENED_STATE"
    );
    let recovered = store
        .recover_netconf_target(&handle, caller())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        recovered.encode().unwrap(),
        bytes,
        "JOINT_NATIVE_EXACT_REOPENED_ORIGINAL"
    );
    let known = store
        .lookup_audit_operation(&handle, caller())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(known.state(), receipt.state());
    assert!(!known.terminal_recorded());
    store
        .complete_required_audit_outcome(&known, caller())
        .await
        .unwrap();
    let terminal = store
        .lookup_audit_operation(&handle, caller())
        .await
        .unwrap()
        .unwrap();
    assert!(
        terminal.terminal_recorded(),
        "JOINT_NATIVE_REOPENED_TERMINAL_SETTLED"
    );
    assert_eq!(terminal.state(), receipt.state());
    let independent = checkpoint.load(topology.identity()).await.unwrap().unwrap();
    independent
        .verify(
            &AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x52; 32]).unwrap()]).unwrap(),
            topology.identity(),
        )
        .unwrap();
    assert!(independent.sequence() >= terminal.sequence);
    drop(recovered);
    store.shutdown().await.unwrap();
    drop(store);
    let backend = SqliteBackend::reopen_config_authority(
        retained_options,
        AuditKey::new([0x51; 32]).unwrap(),
    )
    .await
    .expect("JOINT_NATIVE_REOPENED_SETTLED");
    schema_and_proof(&backend, topology.identity(), 1).await;
    let shared = backend.conn();
    let conn = shared.lock().await;
    let ledger = crate::consensus::audit::read_with_keys_sync(
        &conn,
        backend.audit_key(),
        Some(&AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x52; 32]).unwrap()]).unwrap()),
        topology.identity(),
    )
    .unwrap()
    .unwrap();
    let final_receipt = ledger
        .lookup(backend.audit_key(), &handle, caller())
        .unwrap()
        .unwrap();
    assert_eq!(final_receipt.state(), receipt.state());
    assert!(final_receipt.terminal_recorded());
    drop(conn);
    drop(shared);
    drop(backend);
    drop(dir);
    apply_watch.assert_native_after_cleanup(bytes.len());
}

#[tokio::test]
async fn joint_native_running_rejects_unsupported_and_unadmitted_without_effect() {
    let f = fixture().await;
    schema_and_proof(&f.store.inner.backend, f.store.inner.identity, 0).await;
    let session = f.session().await;
    let before = effect_rows(&f.store).await;
    for target in [
        NetconfLockDatastore::Candidate,
        NetconfLockDatastore::Startup,
    ] {
        assert!(
            f.store
                .prepare_netconf_lock_acquisition(
                    &session,
                    target,
                    &privacy(),
                    &event(2, ManagementAuditOperationCode::Exec, None),
                    LIFETIME
                )
                .await
                .is_err(),
            "JOINT_NATIVE_UNSUPPORTED_TARGET_CLOSED"
        );
    }
    assert!(
        f.store
            .submit_request_on_local_leader(
                opc_consensus::ConsensusRequestId::from_bytes([0xB1; 16]),
                ConfigMutationIntent::MarkConfirmed { tx_id: TxId::new() },
            )
            .await
            .is_err(),
        "JOINT_NATIVE_UNSUPPORTED_MATCHING_FAMILY_CLOSED"
    );
    assert_eq!(effect_rows(&f.store).await, before);
    let (prepared, record) = prepare(&f, &session, 3, br#"{"running":true}"#).await;
    let foreign = AuditCaller::project(
        &privacy(),
        TENANT,
        "spiffe://test.invalid/tenant/synthetic-running/other",
    )
    .unwrap();
    refused(
        f.store
            .admit_netconf_running_replacement_local(&session, &prepared, foreign)
            .await,
    );
    assert!(
        f.store
            .lookup_audit_operation(prepared.handle(), caller())
            .await
            .unwrap()
            .is_none(),
        "JOINT_NATIVE_REJECTED_INTENT_ABSENT"
    );
    assert_eq!(
        effect_rows(&f.store).await,
        before,
        "JOINT_NATIVE_REJECTED_INTENT_NO_EFFECT"
    );
    let wrong = f
        .commit_at(None, 1, br#"{"bypass":true}"#, "running", TENANT)
        .await;
    assert!(
        f.store.append_attested_commit(wrong).await.is_err(),
        "JOINT_NATIVE_UNAUDITED_CLOSED"
    );
    let intent = applied(
        f.store
            .admit_netconf_running_replacement_local(&session, &prepared, caller())
            .await,
    );
    f.checkpoint.unavailable.store(true, Ordering::Release);
    let refusal = f
        .store
        .submit_netconf_target_local(&prepared, &intent, caller())
        .await;
    refused(refusal);
    assert!(
        f.store.load_latest().await.unwrap().is_none(),
        "JOINT_NATIVE_UNCHECKPOINTED_INTENT_NO_EFFECT"
    );
    f.checkpoint.unavailable.store(false, Ordering::Release);
    let receipt = applied(
        f.store
            .submit_netconf_target_local(&prepared, &intent, caller())
            .await,
    );
    assert!(matches!(receipt.state(), AuditOperationState::TargetV1(_)));
    f.settle(&receipt).await;
    readback(&f.store, &f.provider, &record, br#"{"running":true}"#).await;
    // Running lock acquire/release are the supported fixed lifecycle commands.
    let lease = f.lock(&session, 4).await;
    f.unlock(&session, &lease, 5).await;
    drop(lease);
    drop(prepared);
    drop(session);
    f.close().await;
}

#[tokio::test]
async fn joint_native_running_old_peer_families_are_rejected_before_effect() {
    let f = fixture().await;
    schema_and_proof(&f.store.inner.backend, f.store.inner.identity, 0).await;
    let before = effect_rows(&f.store).await;
    let status = f.store.status();
    let sender = f.store.inner.local_node_id;
    for old in [
        RetainedConfigMode::Legacy,
        RetainedConfigMode::BoundedV1,
        RetainedConfigMode::NetconfTargetsV1,
    ] {
        let vote = Vote::new_committed(status.term + 1, sender);
        for family in [
            ConsensusRpcFamily::Vote,
            ConsensusRpcFamily::AppendEntries,
            ConsensusRpcFamily::InstallSnapshot,
            ConsensusRpcFamily::ForwardMutation,
            ConsensusRpcFamily::ReadBarrier,
        ] {
            let payload = match family {
                ConsensusRpcFamily::Vote => encode_config_wire_for_profile(
                    old,
                    &VoteRequest {
                        vote,
                        last_log_id: None,
                    },
                ),
                ConsensusRpcFamily::AppendEntries => encode_config_wire_for_profile(
                    old,
                    &AppendEntriesRequest::<ConfigRaftTypeConfig> {
                        vote,
                        prev_log_id: None,
                        entries: Vec::new(),
                        leader_commit: None,
                    },
                ),
                ConsensusRpcFamily::InstallSnapshot => encode_config_wire_for_profile(
                    old,
                    &InstallSnapshotRequest::<ConfigRaftTypeConfig> {
                        vote,
                        meta: opc_consensus::engine::SnapshotMeta {
                            last_log_id: None,
                            last_membership: StoredMembership::default(),
                            snapshot_id: "synthetic-old-peer".into(),
                        },
                        offset: 0,
                        data: vec![0xA7; 32],
                        done: false,
                    },
                ),
                ConsensusRpcFamily::ForwardMutation => encode_config_wire_for_profile(
                    old,
                    &ForwardMutationRequest {
                        request_id: opc_consensus::ConsensusRequestId::from_bytes([0xA8; 16]),
                        intent: ConfigMutationIntent::ClearRecoveryRequired { tx_id: TxId::new() },
                        compatibility: f.store.peer_compatibility(),
                        budget: ForwardedBudget {
                            remaining_nanos: 2_000_000_000,
                        },
                    },
                ),
                ConsensusRpcFamily::ReadBarrier => encode_config_wire_for_profile(
                    old,
                    &ReadBarrierRequest {
                        compatibility: f.store.peer_compatibility(),
                        compatibility_probe: true,
                        budget: ForwardedBudget {
                            remaining_nanos: 2_000_000_000,
                        },
                    },
                ),
                _ => unreachable!(),
            }
            .unwrap();
            let reply = f
                .store
                .rpc_handler()
                .handle(
                    sender,
                    ConsensusWireRequest::try_new(f.store.inner.identity, sender, family, payload)
                        .unwrap(),
                )
                .await;
            assert!(
                matches!(reply.result, Err(ConsensusPeerError::Protocol)),
                "JOINT_NATIVE_OLD_PEER_CLOSED"
            );
            assert_eq!(effect_rows(&f.store).await, before);
            assert_eq!(f.store.status().term, status.term);
            assert_eq!(f.store.status().applied_index, status.applied_index);
        }
    }
    f.close().await;
}

#[tokio::test]
async fn joint_native_running_snapshot_retains_original_and_capacity_proof() {
    let f = fixture().await;
    let session = f.session().await;
    let (prepared, record) = prepare(&f, &session, 2, br#"{"snapshot":true}"#).await;
    let receipt = f.apply(&session, &prepared).await;
    f.settle(&receipt).await;
    readback(&f.store, &f.provider, &record, br#"{"snapshot":true}"#).await;
    schema_and_proof(&f.store.inner.backend, f.store.inner.identity, 1).await;
    let original = prepared.encode().unwrap();
    let handle = prepared.handle().clone();
    let topology = topology(&f);
    let source = f.store.inner.backend.clone();
    let source_dir = f.dir.path().join("snapshots");
    drop(prepared);
    drop(session);
    let Fixture {
        store,
        device,
        checkpoint,
        provider,
        dir,
    } = f;
    drop(device);
    store.shutdown().await.unwrap();
    drop(store);
    let mut storage = crate::consensus::storage::open(
        &source,
        source_dir,
        topology.identity(),
        topology.members().clone(),
    )
    .await
    .unwrap();
    let snapshot = storage
        .1
        .get_snapshot_builder()
        .await
        .build_snapshot()
        .await
        .expect("JOINT_NATIVE_SNAPSHOT_BUILD");
    let target_options = RetainedConfigOptions::new(
        dir.path().join("replica.sqlite"),
        RetainedConfigBinding::new(topology.clone(), [0x71; 32], [0x72; 32])
            .unwrap()
            .with_profile(profile())
            .with_capacity_profile(opc_crypto::ConfigCapacityProfile::BoundedV1),
        durability(),
        256 * 1024 * 1024,
        Duration::from_secs(30),
    )
    .unwrap();
    let target = SqliteBackend::provision_config_member_repair(
        target_options.clone(),
        AuditKey::new([0x51; 32]).unwrap(),
    )
    .await
    .unwrap();
    target
        .attach_management_audit_keys(Arc::new(
            AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x52; 32]).unwrap()]).unwrap(),
        ))
        .unwrap();
    let binding: Vec<u8> = target
        .conn()
        .lock()
        .await
        .query_row(
            "SELECT record FROM consensus_retained_binding WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let target_dir = dir.path().join("replica-snapshots");
    let mut target_storage = crate::consensus::storage::open(
        &target,
        target_dir.clone(),
        topology.identity(),
        topology.members().clone(),
    )
    .await
    .unwrap();
    let mut incoming = target_storage.1.begin_receiving_snapshot().await.unwrap();
    let mut file = tokio::fs::File::open(snapshot.snapshot.path())
        .await
        .unwrap();
    tokio::io::copy(&mut file, incoming.as_mut()).await.unwrap();
    target_storage
        .1
        .install_snapshot(&snapshot.meta, incoming)
        .await
        .expect("JOINT_NATIVE_SNAPSHOT_INSTALL");
    schema_and_proof(&target, topology.identity(), 1).await;
    let retained_binding: Vec<u8> = target
        .conn()
        .lock()
        .await
        .query_row(
            "SELECT record FROM consensus_retained_binding WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        binding, retained_binding,
        "JOINT_NATIVE_SNAPSHOT_RECEIVER_IDENTITY"
    );
    assert_eq!(
        target_storage.1.applied_state().await.unwrap().0,
        snapshot.meta.last_log_id
    );
    drop(file);
    drop(snapshot);
    drop(storage);
    drop(source);
    drop(target_storage);
    drop(target);
    let target =
        SqliteBackend::reopen_config_authority(target_options, AuditKey::new([0x51; 32]).unwrap())
            .await
            .expect("JOINT_NATIVE_SNAPSHOT_REOPEN");
    schema_and_proof(&target, topology.identity(), 1).await;
    let store = ConsensusConfigStore::open_with_audit_continuity(
        topology,
        target,
        target_dir,
        BTreeMap::new(),
        policy(checkpoint),
    )
    .await
    .unwrap();
    store.initialize_cluster().await.unwrap();
    readback(&store, &provider, &record, br#"{"snapshot":true}"#).await;
    let recovered = store
        .recover_netconf_target(&handle, caller())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        recovered.encode().unwrap(),
        original,
        "JOINT_NATIVE_SNAPSHOT_RETAINED_ORIGINAL"
    );
    let retained = store
        .lookup_audit_operation(&handle, caller())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retained.state(), receipt.state());
    assert!(retained.terminal_recorded());
    drop(recovered);
    store.shutdown().await.unwrap();
    drop(store);
    drop(dir);
}

#[tokio::test]
async fn joint_native_running_retained_admission_rejects_missing_capacity_proof() {
    let f = fixture().await;
    let session = f.session().await;
    let (prepared, record) = prepare(&f, &session, 2, br#"{"retained":true}"#).await;
    let receipt = f.apply(&session, &prepared).await;
    f.settle(&receipt).await;
    readback(&f.store, &f.provider, &record, br#"{"retained":true}"#).await;
    schema_and_proof(&f.store.inner.backend, f.store.inner.identity, 1).await;
    let options = options(&f);
    drop(session);
    drop(prepared);
    let Fixture {
        store, device, dir, ..
    } = f;
    drop(device);
    store.shutdown().await.unwrap();
    drop(store);
    // Independent offline damage follows the positive authenticated readback.
    let conn = rusqlite::Connection::open(dir.path().join("authority.sqlite")).unwrap();
    assert_eq!(
        conn.execute("DELETE FROM config_raft_capacity_records", [])
            .unwrap(),
        1
    );
    drop(conn);
    let result =
        SqliteBackend::reopen_config_authority(options, AuditKey::new([0x51; 32]).unwrap()).await;
    assert!(
        result.is_err(),
        "JOINT_NATIVE_AUTHENTICATED_REOPEN_REJECTS_DAMAGE"
    );
    drop(result);
    drop(dir);
}
