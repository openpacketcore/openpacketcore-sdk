//! Supported retained originals, followed by a small public Running lock. The
//! observer borrows real owners inside transactional preflight. Large fixture
//! expectations live on disk while that preflight executes, not in extra Vecs.

use super::*;
use crate::audit_authority::ledger::workspace_probe::Observation;
use std::path::PathBuf;
use std::time::Instant;

const OPERATION_BYTES: usize = 32 * 1024 * 1024;
const PREPARATIONS: usize = 8;

fn phase(request: u8, name: &str, started: Instant) {
    eprintln!(
        "BOUNDED_TARGET_WORKSPACE_PHASE request={request} phase={name} elapsed_ms={}",
        started.elapsed().as_millis(),
    );
}

async fn original_receipt_in_phase(
    store: &ConsensusConfigStore,
    original: &AuditOperationHandle,
    request: u8,
    name: &str,
    started: Instant,
    admission: AuditAdmission,
) -> AuditOperationReceipt {
    let class = match &admission {
        AuditAdmission::Applied(_) => "applied",
        AuditAdmission::Unknown(_) => "unknown",
        AuditAdmission::Rejected(_) => "rejected",
    };
    eprintln!(
        "BOUNDED_TARGET_WORKSPACE_PHASE request={request} phase={name} \
         elapsed_ms={} decision={class}",
        started.elapsed().as_millis(),
    );
    let receipt = match admission {
        AuditAdmission::Applied(receipt) => receipt,
        AuditAdmission::Unknown(handle) => {
            assert_eq!(&handle, original, "Unknown must retain the exact original");
            // A response deadline cannot retract accepted native work. Keep the
            // fixture alive for one authenticated quorum lookup of that same
            // original; never enqueue again or extend its fixed expiry.
            let recovered = store.lookup_audit_operation(original, caller()).await;
            let class = match &recovered {
                Ok(Some(_)) => "found",
                Ok(None) => "missing",
                Err(_) => "error",
            };
            eprintln!(
                "BOUNDED_TARGET_WORKSPACE_PHASE request={request} phase={name}_lookup \
                 elapsed_ms={} decision={class}",
                started.elapsed().as_millis(),
            );
            recovered
                .unwrap_or_else(|error| {
                    panic!(
                        "BOUNDED_TARGET_WORKSPACE_SETUP: request={request} phase={name} original lookup failed: {error:?}"
                    )
                })
                .unwrap_or_else(|| {
                    panic!(
                        "BOUNDED_TARGET_WORKSPACE_SETUP: request={request} phase={name} original receipt absent"
                    )
                })
        }
        other => panic!(
            "BOUNDED_TARGET_WORKSPACE_SETUP: request={request} phase={name} expected original authoritative result: {other:?}"
        ),
    };
    assert_eq!(
        receipt.handle(),
        original,
        "receipt must match the exact original"
    );
    receipt
}

async fn settle_in_phase(
    f: &Fixture,
    request: u8,
    started: Instant,
    receipt: &AuditOperationReceipt,
) {
    let completion = f
        .store
        .complete_required_audit_outcome(receipt, caller())
        .await;
    let class = match &completion {
        Ok(()) => "complete",
        Err(AuditAuthorityError::Unavailable) => "unavailable",
        Err(_) => "error",
    };
    eprintln!(
        "BOUNDED_TARGET_WORKSPACE_PHASE request={request} phase=terminal_completion \
         elapsed_ms={} decision={class}",
        started.elapsed().as_millis(),
    );
    let covered_sequence = match completion {
        Ok(()) => receipt.sequence,
        Err(AuditAuthorityError::Unavailable) => {
            // Completion debt belongs to the known original. Recover its real
            // terminal receipt before resuming only that terminal/checkpoint
            // obligation through the documented public completion API.
            let terminal = f
                .store
                .lookup_audit_operation(receipt.handle(), caller())
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "BOUNDED_TARGET_WORKSPACE_SETUP: request={request} terminal lookup failed: {error:?}"
                    )
                })
                .expect("original terminal receipt is retained");
            assert_eq!(terminal.handle(), receipt.handle());
            assert_eq!(terminal.state(), receipt.state());
            assert!(terminal.terminal_recorded());
            phase(request, "terminal_original_lookup", started);
            let resumed = f
                .store
                .complete_required_audit_outcome(&terminal, caller())
                .await;
            let class = if resumed.is_ok() { "complete" } else { "error" };
            eprintln!(
                "BOUNDED_TARGET_WORKSPACE_PHASE request={request} phase=terminal_completion_resume \
                 elapsed_ms={} decision={class}",
                started.elapsed().as_millis(),
            );
            resumed.unwrap_or_else(|error| {
                panic!(
                    "BOUNDED_TARGET_WORKSPACE_SETUP: request={request} original terminal completion failed: {error:?}"
                )
            });
            terminal.sequence
        }
        Err(error) => panic!(
            "BOUNDED_TARGET_WORKSPACE_SETUP: request={request} terminal completion failed: {error:?}"
        ),
    };
    let checkpoint = f
        .checkpoint
        .load(f.store.inner.identity)
        .await
        .unwrap()
        .unwrap();
    assert!(checkpoint.sequence() >= covered_sequence);
}

fn maximum_plaintext(fill: u8) -> Vec<u8> {
    let mut bytes = b"\x89OPCCFG\x02\r\n\x1a\n{\"config\":\"".to_vec();
    bytes.extend(std::iter::repeat_n(
        fill,
        opc_crypto::CONFIG_CAPACITY_V1_LOGICAL_BYTES - 2,
    ));
    bytes.extend_from_slice(b"\",\"source\":null,\"idempotency_key\":\"");
    bytes.resize(opc_crypto::CONFIG_CAPACITY_V1_PLAINTEXT_BYTES - 2, b'r');
    bytes.extend_from_slice(b"\"}");
    bytes
}

struct Seed {
    known: AuditOperationReceipt,
    record: PathBuf,
    original: PathBuf,
    fill: u8,
}

async fn seed_maximum(f: &Fixture, session: &NetconfSessionOwner, request: u8) -> Seed {
    let started = Instant::now();
    phase(request, "seed_start", started);
    let plaintext = maximum_plaintext(request);
    let frozen = f.store.read_netconf_running_edit(session).await.unwrap();
    let reservation = f.store.try_reserve_config_preparation().unwrap().unwrap();
    let mut record = CommitRecord {
        tx_id: TxId::new(),
        parent_tx_id: frozen.tx_id(),
        version: ConfigVersion::new(frozen.running_base_version() + 1),
        committed_at: Timestamp::now_utc(),
        principal: PRINCIPAL.to_owned(),
        source: crate::CommitSource::Netconf,
        schema_digest: SchemaDigest::from_bytes([0x63; 32]),
        plaintext_digest: Sha256::digest(&plaintext).to_vec(),
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
        &plaintext,
    )
    .await
    .unwrap();
    phase(request, "encrypted", started);
    let claim = encrypted.claim().unwrap();
    let evidence = claim.capacity_evidence().unwrap();
    assert_eq!(
        evidence.logical_bytes(),
        opc_crypto::CONFIG_CAPACITY_V1_LOGICAL_BYTES
    );
    assert_eq!(
        evidence.replay_bytes(),
        opc_crypto::CONFIG_CAPACITY_V1_REPLAY_BYTES
    );
    record.encrypted_blob = encrypted.encoded().to_vec();
    let commit = AttestedConfigCommit::try_new(record.clone(), Vec::new(), claim).unwrap();
    drop(encrypted);
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
        .unwrap();
    phase(request, "prepared", started);
    drop(frozen);
    let intent = original_receipt_in_phase(
        &f.store,
        prepared.handle(),
        request,
        "seed_intent",
        started,
        f.store
            .admit_netconf_running_replacement_local(session, &prepared, caller())
            .await,
    )
    .await;
    assert_eq!(intent.state(), AuditOperationState::Intent);
    let receipt = original_receipt_in_phase(
        &f.store,
        prepared.handle(),
        request,
        "seed_apply",
        started,
        f.store
            .submit_netconf_target_local(&prepared, &intent, caller())
            .await,
    )
    .await;
    assert!(matches!(receipt.state(), AuditOperationState::TargetV1(_)));
    settle_in_phase(f, request, started, &receipt).await;
    phase(request, "terminal_checkpoint", started);
    readback(&f.store, &f.provider, &record, &plaintext).await;
    phase(request, "readback", started);
    let known = f
        .store
        .lookup_audit_operation(prepared.handle(), caller())
        .await
        .unwrap()
        .unwrap();
    assert!(known.terminal_recorded());
    assert_eq!(known.state(), receipt.state());
    let checkpoint = f
        .checkpoint
        .load(f.store.inner.identity)
        .await
        .unwrap()
        .unwrap();
    assert!(checkpoint.sequence() >= known.sequence);
    let expected_record = f.dir.path().join(format!("expected-record-{request}.json"));
    let expected_original = f
        .dir
        .path()
        .join(format!("expected-original-{request}.json"));
    serde_json::to_writer(std::fs::File::create(&expected_record).unwrap(), &record).unwrap();
    serde_json::to_writer(
        std::fs::File::create(&expected_original).unwrap(),
        prepared.command(),
    )
    .unwrap();
    // None of these large fixture owners crosses into the selected preflight.
    drop(prepared);
    drop(record);
    drop(plaintext);
    phase(request, "seed_complete", started);
    Seed {
        known,
        record: expected_record,
        original: expected_original,
        fill: request,
    }
}

async fn drain(store: &ConsensusConfigStore) {
    let native = tokio::time::timeout(
        WAIT,
        store
            .inner
            .proposal_admission
            .clone()
            .acquire_many_owned(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS as u32),
    )
    .await
    .expect("native accepted owners drain")
    .unwrap();
    drop(native);
    let reservations: Vec<_> = (0..PREPARATIONS)
        .map(|_| store.try_reserve_config_preparation().unwrap().unwrap())
        .collect();
    assert!(store.try_reserve_config_preparation().is_err());
    drop(reservations);
}

async fn audit_digest(store: &ConsensusConfigStore) -> Vec<u8> {
    let connection = store.inner.backend.conn();
    let connection = connection.lock().await;
    connection
        .query_row(
            "SELECT state_hmac FROM config_raft_management_audit WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

fn cleanup_event() -> ManagementAuditEventRecord {
    ManagementAuditEventRecord::try_new(
        [0x75; 16],
        ManagementAuditInstant::try_new(100, 0, 1, ManagementAuditTimeSourceCode::NodeClock)
            .unwrap(),
        TENANT,
        PRINCIPAL,
        ManagementAuditTransportCode::Internal,
        ManagementAuditOperationCode::Exec,
        ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/synthetic:configuration"],
        None::<&str>,
    )
    .unwrap()
}

#[tokio::test]
async fn bounded_running_target_preflight_counts_retained_workspace() {
    let started = Instant::now();
    phase(0, "fixture_start", started);
    let f = fixture().await;
    f.store
        .inner
        .durable_progress
        .append_observed_from
        .set(started)
        .expect("one native phase diagnostic origin");
    let session = f.session().await;
    phase(0, "fixture_ready", started);
    let seeds = [
        seed_maximum(&f, &session, b'x').await,
        seed_maximum(&f, &session, b'y').await,
    ];
    drain(&f.store).await;
    phase(0, "seeds_drained", started);
    let lock_event = event(0x73, ManagementAuditOperationCode::Exec, None);
    let projected = ProjectedAuditEvent::project(&privacy(), &lock_event).unwrap();
    let observation = Observation::start(f.store.inner.identity, projected.request);
    let acquisition = f
        .store
        .prepare_netconf_lock_acquisition(
            &session,
            NetconfLockDatastore::Running,
            &privacy(),
            &lock_event,
            LIFETIME,
        )
        .await;
    phase(0x73, "lock_preflight_returned", started);
    let observed = observation.finish();
    let acquisition = acquisition.expect("supported small lock preparation after two maxima");
    let intent = original_receipt_in_phase(
        &f.store,
        acquisition.mutation().handle(),
        0x73,
        "lock_intent",
        started,
        f.store
            .admit_netconf_target_local(acquisition.mutation(), caller())
            .await,
    )
    .await;
    let receipt = original_receipt_in_phase(
        &f.store,
        acquisition.mutation().handle(),
        0x73,
        "lock_apply",
        started,
        f.store
            .submit_netconf_target_local(acquisition.mutation(), &intent, caller())
            .await,
    )
    .await;
    settle_in_phase(&f, 0x73, started, &receipt).await;
    phase(0x73, "lock_terminal_checkpoint", started);
    let lease = f
        .store
        .claim_netconf_lock_lease(&acquisition, &receipt, caller())
        .await
        .unwrap();
    phase(0x74, "lock_release_start", started);
    let release = f
        .store
        .prepare_netconf_lock_release(
            &session,
            &lease,
            &privacy(),
            &event(0x74, ManagementAuditOperationCode::Exec, None),
            LIFETIME,
        )
        .await
        .unwrap();
    let intent = original_receipt_in_phase(
        &f.store,
        release.mutation().handle(),
        0x74,
        "release_intent",
        started,
        f.store
            .admit_netconf_target_local(release.mutation(), caller())
            .await,
    )
    .await;
    let receipt = original_receipt_in_phase(
        &f.store,
        release.mutation().handle(),
        0x74,
        "release_apply",
        started,
        f.store
            .submit_netconf_target_local(release.mutation(), &intent, caller())
            .await,
    )
    .await;
    settle_in_phase(&f, 0x74, started, &receipt).await;
    drop(release);
    phase(0x74, "lock_release_complete", started);
    let known_lock = f
        .store
        .lookup_audit_operation(acquisition.mutation().handle(), caller())
        .await
        .unwrap()
        .unwrap();
    assert!(known_lock.terminal_recorded());
    let before_replay = audit_digest(&f.store).await;
    let replay = original_receipt_in_phase(
        &f.store,
        acquisition.mutation().handle(),
        0x73,
        "lock_replay",
        started,
        f.store
            .submit_netconf_target_local(acquisition.mutation(), &known_lock, caller())
            .await,
    )
    .await;
    assert_eq!(replay, known_lock);
    assert_eq!(audit_digest(&f.store).await, before_replay);
    drop(lease);
    drop(acquisition);
    session.invalidate();
    let cleanup = f
        .store
        .prepare_netconf_session_cleanup(&session, &privacy(), &cleanup_event(), LIFETIME)
        .await
        .unwrap();
    phase(0x75, "cleanup_prepared", started);
    let intent = original_receipt_in_phase(
        &f.store,
        cleanup.handle(),
        0x75,
        "cleanup_intent",
        started,
        f.store.admit_netconf_target_local(&cleanup, caller()).await,
    )
    .await;
    let receipt = original_receipt_in_phase(
        &f.store,
        cleanup.handle(),
        0x75,
        "cleanup_apply",
        started,
        f.store
            .submit_netconf_target_local(&cleanup, &intent, caller())
            .await,
    )
    .await;
    settle_in_phase(&f, 0x75, started, &receipt).await;
    phase(0x75, "cleanup_terminal_checkpoint", started);
    drop(cleanup);
    drop(session);
    drain(&f.store).await;
    let retained_options = options(&f);
    let topology = topology(&f);
    let expected_audit_digest = audit_digest(&f.store).await;
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
    phase(0, "first_shutdown", started);
    let backend = SqliteBackend::reopen_config_authority(
        retained_options,
        AuditKey::new([0x51; 32]).unwrap(),
    )
    .await
    .unwrap();
    let store = ConsensusConfigStore::open_with_audit_continuity(
        topology,
        backend,
        dir.path().join("snapshots"),
        BTreeMap::new(),
        policy(checkpoint.clone()),
    )
    .await
    .unwrap();
    store.initialize_cluster().await.unwrap();
    phase(0, "reopened", started);
    assert_eq!(audit_digest(&store).await, expected_audit_digest);
    for seed in &seeds {
        let known = store
            .lookup_audit_operation(&seed.known.handle, caller())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(known, seed.known);
        let original = store
            .recover_netconf_target(&seed.known.handle, caller())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            original.encode().unwrap(),
            std::fs::read(&seed.original).unwrap()
        );
        let confirmed = checkpoint
            .load(store.inner.identity)
            .await
            .unwrap()
            .unwrap();
        assert!(confirmed.sequence() >= known.sequence);
    }
    let last = seeds.last().unwrap();
    let expected: CommitRecord =
        serde_json::from_reader(std::fs::File::open(&last.record).unwrap()).unwrap();
    readback(&store, &provider, &expected, &maximum_plaintext(last.fill)).await;
    drop(expected);
    drain(&store).await;
    store.shutdown().await.unwrap();
    phase(0, "final_shutdown", started);
    drop(store);
    drop(provider);
    drop(checkpoint);
    drop(seeds);
    drop(dir);
    eprintln!(
        "BOUNDED_TARGET_PREFLIGHT_WORKSPACE logical={} replay={} observed={observed:?} \
         native_drained=true reopened=true cleanup_complete=true",
        opc_crypto::CONFIG_CAPACITY_V1_LOGICAL_BYTES,
        opc_crypto::CONFIG_CAPACITY_V1_REPLAY_BYTES,
    );
    assert_eq!(observed.preflight_scopes, 1);
    assert_eq!(observed.active_scopes, 0);
    assert_eq!(observed.samples.len(), 1);
    let sample = &observed.samples[0];
    assert!(sample.distinct_ledger_roots && sample.distinct_ledger_allocations);
    assert!(sample.consistent_extents);
    assert_eq!(sample.large_recovery_allocations, [2; 3]);
    for index in 0..3 {
        assert!(sample.recovery_allocations[index] >= 2);
        assert!(
            sample.ledger_owned_bytes[index]
                >= sample.recovery_owned_bytes[index] + sample.recovery_owner_bytes[index]
        );
        assert!(sample.recovery_owned_bytes[index] >= sample.large_recovery_bytes[index]);
    }
    assert!(sample.incoming_owned_bytes > 0);
    assert_eq!(
        sample.live_owned_bytes + sample.shared_owned_bytes,
        sample.ledger_owned_bytes.iter().sum::<usize>() + sample.incoming_owned_bytes,
    );
    assert!(sample.unique_large_recovery_bytes <= sample.live_owned_bytes);
    assert!(
        sample.live_owned_bytes <= OPERATION_BYTES,
        "BOUNDED_TARGET_PREFLIGHT_WORKSPACE: simultaneous retained ledger owners exceed 32 MiB; actual={}",
        sample.live_owned_bytes,
    );
    // These sharing checks follow the unchanged bound so restoring the actual
    // deep clones fails on their real simultaneous workspace first.
    assert!(sample.shared_owned_bytes > 0);
    assert_eq!(sample.unique_large_recovery_allocations, 2);
    assert_eq!(
        sample.unique_large_recovery_bytes,
        sample.large_recovery_bytes[0]
    );
    assert_eq!(
        sample.unique_recovery_allocations,
        sample.recovery_allocations[0] + 1
    );
    assert!(
        sample.unique_recovery_owner_bytes
            >= 4 * (std::mem::size_of::<String>() + 2 * std::mem::size_of::<usize>())
    );
}
