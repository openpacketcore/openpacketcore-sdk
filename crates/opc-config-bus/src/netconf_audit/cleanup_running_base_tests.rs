//! Running-only drift through the actual public audited commit and worker paths.
use super::*;
use opc_key::{ConfigAad, EnvelopeAad, KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing};
use opc_persist::{AttestedConfigCommit, CommitRecord, CommitSource};
use opc_types::{ConfigVersion, SchemaDigest, Timestamp, TxId};
use sha2::{Digest, Sha256};

async fn ordinary_running(fixture: &Fixture, value: u8) -> CommitRecord {
    let previous = fixture
        .store
        .load_latest()
        .await
        .unwrap()
        .map(|stored| stored.record);
    let base = previous.as_ref().map_or(0, |record| record.version.get());
    let parent = previous.as_ref().map(|record| record.tx_id);
    let owner = principal();
    let descriptor = serde_json::to_string(&owner).unwrap();
    let tx_id = TxId::new();
    let committed_at = Timestamp::now_utc();
    let schema = SchemaDigest::from_bytes([0x74; 32]);
    let aad = EnvelopeAad::config(
        owner.tenant.clone(),
        base + 1,
        ConfigAad::new(tx_id, parent, committed_at, &descriptor, schema, "running").unwrap(),
    );
    let provider = MemoryKeyProvider::new();
    provider
        .insert_active_key(
            KeyId::new("synthetic-retirement-running-key").unwrap(),
            KeyPurpose::Config,
            owner.tenant.clone(),
            Zeroizing::new([0x75; 32]),
        )
        .unwrap();
    let plaintext = [value; 32];
    let encrypted = opc_crypto::encrypt_attested_envelope(&provider, &aad, &plaintext)
        .await
        .unwrap();
    let record = CommitRecord {
        tx_id,
        parent_tx_id: parent,
        version: ConfigVersion::new(base + 1),
        committed_at,
        principal: descriptor,
        source: CommitSource::Netconf,
        schema_digest: schema,
        plaintext_digest: Sha256::digest(plaintext).to_vec(),
        encrypted_blob: encrypted.encoded().to_vec(),
        rollback_point: false,
        confirmed_deadline: None,
    };
    let attested =
        AttestedConfigCommit::try_new(record.clone(), Vec::new(), encrypted.claim().unwrap())
            .unwrap();
    let event = super::super::super::event::convert_event(&AuditEvent::new(
        RequestId::new(),
        &owner,
        TransportType::Internal,
        AuditOperation::Exec,
        AuditOutcome::Intent,
    ))
    .unwrap();
    let prepared = fixture
        .store
        .prepare_audited_commit(fixture.privacy.as_ref(), &event, attested, LIFETIME)
        .unwrap();
    let intent = applied(
        fixture
            .store
            .admit_audit_operation_local(prepared.handle(), fixture.caller)
            .await,
    );
    assert_eq!(intent.state(), AuditOperationState::Intent);
    let known = applied(
        fixture
            .store
            .submit_audited_mutation_local(&prepared, &intent, fixture.caller)
            .await,
    );
    assert_eq!(
        known.state(),
        AuditOperationState::Committed { version: base + 1 }
    );
    fixture
        .store
        .complete_required_audit_outcome(&known, fixture.caller)
        .await
        .unwrap();
    let terminal = fixture
        .store
        .lookup_audit_operation(prepared.handle(), fixture.caller)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(terminal.state(), known.state());
    assert!(terminal.terminal_recorded());
    assert_eq!(
        fixture
            .store
            .reconcile_audit_obligations(32)
            .await
            .unwrap()
            .inspected,
        0,
        "ordinary Running must settle its actual terminal/checkpoint debt"
    );
    let stored = fixture.store.load_latest().await.unwrap().unwrap().record;
    assert_eq!(stored.tx_id, record.tx_id);
    assert_eq!(stored.version, record.version);
    assert_eq!(stored.parent_tx_id, record.parent_tx_id);
    assert_eq!(stored.encrypted_blob, record.encrypted_blob);
    assert_eq!(stored.plaintext_digest, record.plaintext_digest);
    assert_eq!(
        opc_crypto::decrypt_envelope(&provider, &aad, &stored.encrypted_blob)
            .await
            .unwrap()
            .as_slice(),
        plaintext
    );
    record
}

fn frozen(prepared: &PreparedTargetMutation) -> (serde_json::Value, u64) {
    let effect: serde_json::Value = serde_json::from_slice(&prepared.encode().unwrap()).unwrap();
    let destination = effect["effect"]["destination"].clone();
    assert!(destination["lifecycle"]["state_digest"].is_array());
    let handle: serde_json::Value =
        serde_json::from_slice(&prepared.handle().encode().unwrap()).unwrap();
    let base = handle["body"]["binding"]["base_version"].as_u64().unwrap();
    (destination, base)
}

async fn unchanged_running(fixture: &Fixture, expected: &CommitRecord) {
    let current = fixture.store.load_latest().await.unwrap().unwrap().record;
    assert_eq!(current.tx_id, expected.tx_id);
    assert_eq!(current.version, expected.version);
    assert_eq!(current.parent_tx_id, expected.parent_tx_id);
    assert_eq!(current.encrypted_blob, expected.encrypted_blob);
    assert_eq!(current.plaintext_digest, expected.plaintext_digest);
}

#[tokio::test]
async fn native_cleanup_running_base_only_retires_then_drains_fixed_successor() {
    let fixture = Fixture::new(&principal()).await;
    let first = ordinary_running(&fixture, 0x76).await;
    assert_eq!(first.version.get(), 1);
    let (mut worker, original) = worker_with_original(&fixture).await;
    let (lifecycle, base) = frozen(&original.prepared);
    assert_eq!(base, 1);
    assert!(fixture
        .store
        .lookup_audit_operation(&original.handle, fixture.caller)
        .await
        .unwrap()
        .is_none());
    let current = ordinary_running(&fixture, 0x77).await;
    assert_eq!(current.version.get(), 2);
    assert_eq!(current.parent_tx_id, Some(first.tx_id));
    assert!(fixture.port.verify_current().await.is_ok());
    let normal = fixture
        .store
        .admit_netconf_target_local(&original.prepared, fixture.caller)
        .await;
    assert!(matches!(
        normal,
        AuditAdmission::Rejected(AuditAuthorityError::BindingMismatch)
    ));
    assert!(fixture
        .store
        .lookup_audit_operation(&original.handle, fixture.caller)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        fixture
            .store
            .reconcile_audit_obligations(32)
            .await
            .unwrap()
            .inspected,
        0
    );
    println!("CLEANUP_RUNNING_BASE_WORKER_PRECONDITION base=1 current=2 original_absent=true competing_debt=false normal_admit_refused=true");

    // Retirement's terminal checkpoint is the first real advance. Stop only
    // the successor Intent checkpoint, to inspect it before any cleanup effect.
    // The old reducer refuses before even the first advance: its RED has no
    // checkpoint outage or remaining ordinary-commit debt as a cause.
    fixture
        .checkpoint
        .advances_since_arm
        .store(0, Ordering::Release);
    fixture
        .checkpoint
        .fail_completion
        .store(true, Ordering::Release);
    tokio::time::timeout(WAIT, worker.cleanup()).await.unwrap();
    let retired = fixture
        .store
        .lookup_audit_operation(&original.handle, fixture.caller)
        .await
        .unwrap();
    if !retired.as_ref().is_some_and(|receipt| {
        receipt.state() == AuditOperationState::Rejected && receipt.terminal_recorded()
    }) {
        // Require the specific old-guard failure before emitting the RED marker.
        assert!(retired.is_none());
        assert_eq!(
            fixture
                .checkpoint
                .advances_since_arm
                .load(Ordering::Acquire),
            0
        );
        let attempt = worker
            .sessions
            .revoked()
            .next()
            .unwrap()
            .cleanup_attempt()
            .unwrap();
        assert!(attempt.handle() == &original.handle);
        assert!(matches!(
            attempt.retained_reply(),
            TargetReply::Refused(AuditAuthorityError::BindingMismatch)
        ));
        fixture
            .checkpoint
            .fail_completion
            .store(false, Ordering::Release);
        let exit = joined(worker).await;
        assert_eq!(exit, WorkerExit::RecoveryRequired);
        assert!(fixture
            .store
            .lookup_audit_operation(&original.handle, fixture.caller)
            .await
            .unwrap()
            .is_none());
        unchanged_running(&fixture, &current).await;
        fixture.close().await;
        panic!("CLEANUP_RUNNING_BASE_WORKER_RETIREMENT: native worker refused stale running base, retained the absent predecessor and could not drain; checkpoint advances=0");
    }
    assert!(fixture.checkpoint.advances_since_arm.load(Ordering::Acquire) >= 2,
        "RUNNING_BASE_SUCCESSOR_CHECKPOINT_BOUNDARY: retirement must checkpoint before the held successor Intent");
    let Slot::Owned(session) = &worker.sessions.entries[0] else {
        panic!("real successor must remain owned until its checkpoint and effect settle")
    };
    let next_handle = session.cleanup.as_ref().unwrap().handle().clone();
    let next_event = session.context.cleanup.clone();
    let next = fixture
        .store
        .retained_netconf_session_cleanup(
            &original.owner,
            fixture.caller,
            fixture.privacy.as_ref(),
            &super::super::super::event::convert_event(&next_event).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert!(next.handle() == &next_handle && next_handle != original.handle);
    assert_eq!(frozen(&next), (lifecycle, 2),
        "RUNNING_BASE_ONLY_SUCCESSOR: the lifecycle digest stays identical while the authenticated base advances");
    assert_eq!(expiry(&next), expiry(&original.prepared));
    let successor = Original {
        handle: next_handle,
        prepared: next,
        owner: original.owner.clone(),
        event: next_event,
    };
    exact_intent(&fixture, &successor).await;
    assert!(
        fixture
            .store
            .recover_netconf_target(&original.handle, fixture.caller)
            .await
            .unwrap()
            .unwrap()
            == original.prepared
    );
    unchanged_running(&fixture, &current).await;
    fixture
        .checkpoint
        .fail_completion
        .store(false, Ordering::Release);
    tokio::time::timeout(WAIT, worker.cleanup()).await.unwrap();
    assert!(settled(&fixture, &successor).await);
    assert!(worker.sessions.is_empty());
    assert_eq!(joined(worker).await, WorkerExit::Drained);
    let predecessor = fixture
        .store
        .lookup_audit_operation(&original.handle, fixture.caller)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(predecessor.state(), AuditOperationState::Rejected);
    assert!(predecessor.terminal_recorded());
    assert_eq!(
        fixture
            .store
            .reconcile_audit_obligations(32)
            .await
            .unwrap()
            .inspected,
        0
    );
    unchanged_running(&fixture, &current).await;
    fixture.close().await;
    println!("CLEANUP_RUNNING_BASE_WORKER_COMPLETE lifecycle_unchanged=true predecessor_rejected=true mandatory_checkpoint=true successor_fixed_expiry=true successor_applied=true running_unchanged=true drain=Drained");
}
