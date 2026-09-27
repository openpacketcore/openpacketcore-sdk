//! Worker composition of native Running admission and acknowledged recovery.
//! The independent native quorum-wait detector remains in opc-persist. Here
//! real checkpoint operations provide deterministic gates without supplying an
//! operation, receipt, effect, key, or replacement authority to production.

use super::*;
use opc_persist::audit_authority::{
    AuditOperationHandle, AuditOperationState, ProjectedAuditEvent,
};
use std::path::Path;

const WAIT: Duration = opc_consensus::DURABLE_CONSENSUS_OPERATION_TIMEOUT;

#[derive(Default)]
pub(super) struct CheckpointControls {
    arm_after_preparation: AtomicBool,
    loads_remaining: AtomicUsize,
    observed_loads: AtomicUsize,
    admission_gate: Arc<Gate>,
    admission_gate_returned: AtomicBool,
    intent_gate: Arc<Gate>,
    intent_gate_returned: AtomicBool,
    fail_intent_checkpoint: AtomicBool,
    proposed_intent_checkpoint: Mutex<Option<AuditCheckpoint>>,
    prepared_tx: Mutex<Option<TxId>>,
}

impl CheckpointControls {
    fn arm_before_admission(&self) -> ReleaseGate {
        assert!(!self.arm_after_preparation.swap(true, Ordering::AcqRel));
        self.admission_gate.arm()
    }

    pub(super) fn after_preparation(&self, tx_id: TxId) {
        *self.prepared_tx.lock().unwrap() = Some(tx_id);
        if self.arm_after_preparation.swap(false, Ordering::AcqRel) {
            // Pinned source sequence AFTER genuine encryption/attestation:
            // 1. prepare_netconf_running_replacement -> target preflight;
            // 2. admit_netconf_target_with_session -> target preflight;
            // 3. audit_operation_command_with_session -> read_audit_ledger.
            // Each invokes checkpoint.load exactly once. All local/session
            // entry checks precede #3; the final native enqueue guard follows.
            // The native guard-removal RED must fail the refusal assertion,
            // otherwise this sequence no longer qualifies the intended gate.
            self.observed_loads.store(0, Ordering::Release);
            assert_eq!(self.loads_remaining.swap(3, Ordering::AcqRel), 0);
        }
    }

    pub(super) async fn before_load(&self) {
        if let Ok(previous) =
            self.loads_remaining
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                    remaining.checked_sub(1)
                })
        {
            self.observed_loads.fetch_add(1, Ordering::AcqRel);
            if previous == 1 {
                self.admission_gate.hold().await;
                self.admission_gate_returned.store(true, Ordering::Release);
            }
        }
    }

    pub(super) async fn before_advance(
        &self,
        next: &AuditCheckpoint,
    ) -> Result<(), AuditAuthorityError> {
        let gated = self.intent_gate.armed.load(Ordering::Acquire);
        if gated {
            *self.proposed_intent_checkpoint.lock().unwrap() = Some(next.clone());
        }
        self.intent_gate.hold().await;
        if gated {
            self.intent_gate_returned.store(true, Ordering::Release);
        }
        if self.fail_intent_checkpoint.load(Ordering::Acquire) {
            return Err(AuditAuthorityError::Unavailable);
        }
        Ok(())
    }
}

struct OriginalObservation {
    handle: AuditOperationHandle,
    state: AuditOperationState,
    terminal_recorded: bool,
    matches_request: bool,
    first_sequence: u64,
    last_sequence: u64,
}

fn privacy() -> AuditPrivacyKey {
    AuditPrivacyKey::new([0x39; 32]).unwrap()
}

fn caller() -> AuditCaller {
    AuditCaller::project(
        &privacy(),
        principal().tenant.as_str(),
        &opc_mgmt_audit::principal_descriptor(&principal()),
    )
    .unwrap()
}

// SQL observes only. A decoded handle is subsequently authenticated by the real
// SDK lookup/recover APIs before the test treats the original as authoritative.
// No prepared target, receipt, mutation, or database row is constructed here.
// Count every same-caller Replace in this one-request fixture, including any
// incorrectly minted fresh request. Legitimate Exec cleanup has a distinct kind.
fn originals(database: &Path, event: &AuditEvent) -> Vec<OriginalObservation> {
    let conn =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let encoded: Vec<u8> = conn
        .query_row(
            "SELECT state_json FROM config_raft_management_audit WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let stored: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    let projected =
        serde_json::to_value(ProjectedAuditEvent::project(&privacy(), &sdk_event(event)).unwrap())
            .unwrap();
    stored["ledger"]["operations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|operation| {
            let event = &operation["handle"]["body"]["event"];
            event["operation"] == projected["operation"] && event["caller"] == projected["caller"]
        })
        .map(|operation| OriginalObservation {
            handle: AuditOperationHandle::decode(
                &serde_json::to_vec(&operation["handle"]).unwrap(),
            )
            .unwrap(),
            state: serde_json::from_value(operation["state"].clone()).unwrap(),
            terminal_recorded: operation["terminal_recorded"].as_bool().unwrap(),
            matches_request: operation["handle"]["body"]["event"]["request"]
                == projected["request"],
            first_sequence: operation["first_sequence"].as_u64().unwrap(),
            last_sequence: operation["last_sequence"].as_u64().unwrap(),
        })
        .collect()
}

fn persisted_history_count(database: &Path) -> u64 {
    let conn =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    conn.query_row("SELECT count(*) FROM config_history", [], |row| row.get(0))
        .unwrap()
}

#[tokio::test]
async fn running_worker_final_owner_drop_before_native_admission_refuses_without_intent() {
    let f = Fixture::new().await;
    let w = Worker::new(&f).await;
    let owner = w.audit.open_session(&principal()).await.unwrap();
    let database = f.directory.path().join("authority.sqlite");
    let request = request(0);
    let request_id = request.request_id;
    let event = request_event(&request);
    let authenticated = principal();
    let before = f.rows();
    let release = f.checkpoint.revocation.arm_before_admission();
    let mut call =
        Box::pin(
            w.audit
                .replace_running(&owner, &authenticated, request, event.clone()),
        );
    let reached = tokio::time::timeout(WAIT, async {
        tokio::select! {
            _ = f.checkpoint.revocation.admission_gate.entered() => true,
            _ = &mut call => false,
        }
    })
    .await
    .unwrap_or(false);
    let held_loads = f
        .checkpoint
        .revocation
        .observed_loads
        .load(Ordering::Acquire);
    let held_unchanged = f.rows() == before;
    let held_absent = originals(&database, &event).is_empty();
    let encrypted_once = f.provider.active.load(Ordering::Acquire) == 1;
    assert!(!f
        .checkpoint
        .revocation
        .admission_gate_returned
        .load(Ordering::Acquire));
    // The queued reference and retained SDK clone must not keep the transport
    // ownership layer alive. Drop the borrowed call before the actual last owner.
    drop(call);
    drop(owner);
    drop(release);
    let recovered =
        tokio::time::timeout(WAIT, w.audit.recover_request(request_id, &authenticated)).await;
    let refused = matches!(
        &recovered,
        Ok(Ok(Some(NetconfMutationResult::Refused(error))))
            if error.code == CommitErrorCode::AdmissionRejected
    );
    let snapshot = w.bus.current_snapshot();
    let exit = w.audit.shutdown().await;
    drop(w);
    drop(f.encrypted);
    drop(f.raft);
    let native_shutdown = f.store.shutdown().await;
    // Observe persisted absence only after worker and native engine join. A
    // delayed effect or admission cannot turn an early read into a false pass.
    let after = originals(&database, &event);
    let history = persisted_history_count(&database);
    let encryption_count = f.provider.active.load(Ordering::Acquire);
    let gate_returned = f
        .checkpoint
        .revocation
        .admission_gate_returned
        .load(Ordering::Acquire);
    drop(f.store);
    drop(f.directory);

    assert!(reached, "RUNNING_WORKER_FINAL_GUARD_SETUP_REACHED");
    assert_eq!(held_loads, 3, "RUNNING_WORKER_FINAL_GUARD_LOAD_SEQUENCE");
    assert!(gate_returned, "RUNNING_WORKER_FINAL_GUARD_NOT_CANCELLED");
    assert!(held_unchanged && held_absent && encrypted_once);
    assert!(refused, "RUNNING_WORKER_REVOKED_FINAL_GUARD_REFUSAL");
    assert!(
        after.is_empty(),
        "RUNNING_WORKER_REVOKED_NO_ORIGINAL_INTENT"
    );
    assert_eq!(history, 0, "RUNNING_WORKER_REVOKED_NO_EFFECT");
    assert_eq!(snapshot.version, ConfigVersion::INITIAL);
    assert!(snapshot.tx_id.is_none());
    assert_eq!(encryption_count, 1);
    native_shutdown.unwrap();
    assert_eq!(exit.unwrap(), NetconfWorkerExit::Drained);
}

#[tokio::test]
async fn running_worker_acknowledged_intent_survives_owner_drop_before_apply_once() {
    let f = Fixture::new().await;
    let w = Worker::new(&f).await;
    let owner = w.audit.open_session(&principal()).await.unwrap();
    let database = f.directory.path().join("authority.sqlite");
    let request = request(0);
    let request_id = request.request_id;
    let event = request_event(&request);
    let authenticated = principal();
    let original_checkpoint = f.checkpoint.current.lock().unwrap().clone().unwrap();
    let release = f.checkpoint.revocation.intent_gate.arm();
    f.checkpoint
        .revocation
        .fail_intent_checkpoint
        .store(true, Ordering::Release);
    let mut call =
        Box::pin(
            w.audit
                .replace_running(&owner, &authenticated, request, event.clone()),
        );
    let reached = tokio::time::timeout(WAIT, async {
        tokio::select! {
            _ = f.checkpoint.revocation.intent_gate.entered() => true,
            _ = &mut call => false,
        }
    })
    .await
    .unwrap_or(false);
    assert!(reached, "RUNNING_WORKER_ACKNOWLEDGED_INTENT_GATE");
    // This CAS is reached only from submit_netconf_target_local after the
    // worker received Applied(Intent) and retained its genuine acknowledgement.
    // The gate is before CAS and before Apply, not post-effect readback.
    let held = originals(&database, &event);
    assert_eq!(held.len(), 1, "RUNNING_WORKER_ONE_ACKNOWLEDGED_ORIGINAL");
    let original = &held[0];
    assert!(original.matches_request);
    assert_eq!(original.state, AuditOperationState::Intent);
    assert!(!original.terminal_recorded);
    assert_eq!(history_count(&f), 0, "RUNNING_WORKER_ACK_BEFORE_EFFECT");
    assert_eq!(w.bus.current_snapshot().version, ConfigVersion::INITIAL);
    let native_intent = f
        .store
        .lookup_audit_operation(&original.handle, caller())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(native_intent.state(), AuditOperationState::Intent);
    assert!(!native_intent.terminal_recorded());
    let prepared = f
        .store
        .recover_netconf_target(&original.handle, caller())
        .await
        .unwrap()
        .unwrap();
    let original_bytes = prepared.encode().unwrap();
    let handle_bytes = original.handle.encode().unwrap();
    let fixed: serde_json::Value = serde_json::from_slice(&handle_bytes).unwrap();
    assert_eq!(
        fixed["body"]["expires_at"].as_i64().unwrap()
            - fixed["body"]["issued_at"].as_i64().unwrap(),
        LIFETIME.as_secs() as i64,
        "RUNNING_WORKER_ORIGINAL_FIXED_LIFETIME"
    );
    let proposed = f
        .checkpoint
        .revocation
        .proposed_intent_checkpoint
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert!(original_checkpoint.sequence() < original.first_sequence);
    assert!(proposed.sequence() >= original.first_sequence);
    let prepared_tx = f.checkpoint.revocation.prepared_tx.lock().unwrap().unwrap();
    assert_eq!(f.provider.active.load(Ordering::Acquire), 1);
    assert!(!f
        .checkpoint
        .revocation
        .intent_gate_returned
        .load(Ordering::Acquire));
    drop(call);
    drop(owner);
    drop(release);

    // Keep the real checkpoint unavailable through the initial Apply attempt
    // and its immediate recovery. The worker must expose the retained Unknown,
    // rather than relying solely on uninterrupted initial-call continuation.
    let pending = tokio::time::timeout(WAIT, w.audit.recover_request(request_id, &authenticated))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let retained_unknown = match &pending {
        NetconfMutationResult::Unknown(handle) => handle.encode().unwrap() == handle_bytes,
        _ => false,
    };
    let before_resume_history = history_count(&f);
    let before_resume = originals(&database, &event);
    let checkpoint_unchanged =
        f.checkpoint.current.lock().unwrap().as_ref() == Some(&original_checkpoint);
    f.checkpoint
        .revocation
        .fail_intent_checkpoint
        .store(false, Ordering::Release);
    let recovered = tokio::time::timeout(WAIT, w.audit.recover_request(request_id, &authenticated))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let applied = matches!(&recovered, NetconfMutationResult::Applied(_));
    if let NetconfMutationResult::Applied(receipt) = &recovered {
        assert!(receipt.terminal_recorded());
        assert!(!receipt.completion_pending());
        assert!(!receipt.publication_pending());
        assert!(receipt.recovery_handle().encode().unwrap() == handle_bytes);
        exact_readback(&f, &w, receipt, "revision-1").await;
        assert_eq!(receipt.published_commit().unwrap().tx_id, prepared_tx);
        let again = known(
            w.audit
                .recover(receipt.recovery_handle(), &authenticated)
                .await,
        );
        assert_eq!(again.outcome(), receipt.outcome());
        assert!(again.recovery_handle().encode().unwrap() == handle_bytes);
        let native = f
            .store
            .lookup_audit_operation(&original.handle, caller())
            .await
            .unwrap()
            .unwrap();
        assert!(native.terminal_recorded(), "RUNNING_WORKER_NATIVE_TERMINAL");
        assert!(matches!(
            native.state(),
            AuditOperationState::TargetV1(result) if result.outcome() == receipt.outcome()
        ));
        let same = f
            .store
            .recover_netconf_target(&original.handle, caller())
            .await
            .unwrap()
            .unwrap();
        assert!(
            same.encode().unwrap() == original_bytes,
            "RUNNING_WORKER_NO_NEW_IDENTITY_CRYPTO_OR_EXPIRY"
        );
    }
    let exit = w.audit.shutdown().await;
    drop(w);
    drop(f.encrypted);
    drop(f.raft);
    let native_shutdown = f.store.shutdown().await;
    let after = originals(&database, &event);
    let history = persisted_history_count(&database);
    let final_checkpoint = f.checkpoint.current.lock().unwrap().clone().unwrap();
    let encryption_count = f.provider.active.load(Ordering::Acquire);
    let rotations = f.provider.rotations.load(Ordering::Acquire);
    let gate_returned = f
        .checkpoint
        .revocation
        .intent_gate_returned
        .load(Ordering::Acquire);
    drop(f.store);
    drop(f.directory);

    assert!(gate_returned, "RUNNING_WORKER_INTENT_GATE_NOT_CANCELLED");
    assert!(retained_unknown, "RUNNING_WORKER_REVOKED_ORIGINAL_RETAINED");
    assert_eq!(
        before_resume_history, 0,
        "RUNNING_WORKER_NO_APPLY_WITHOUT_INTENT_CHECKPOINT"
    );
    assert!(checkpoint_unchanged);
    assert_eq!(before_resume.len(), 1);
    assert_eq!(before_resume[0].state, AuditOperationState::Intent);
    assert!(
        before_resume[0].handle.encode().unwrap() == handle_bytes,
        "RUNNING_WORKER_ORIGINAL_RETAINED_BEFORE_RESUME"
    );
    assert!(
        applied,
        "RUNNING_WORKER_ACKNOWLEDGED_ORIGINAL_RESUMES_AFTER_DROP"
    );
    assert_eq!(after.len(), 1, "RUNNING_WORKER_NO_REPLACEMENT_INTENT");
    assert!(after[0].matches_request);
    assert!(after[0].handle.encode().unwrap() == handle_bytes);
    assert!(after[0].terminal_recorded);
    assert!(final_checkpoint.sequence() >= after[0].last_sequence);
    assert_eq!(history, 1, "RUNNING_WORKER_ORIGINAL_EFFECT_EXACTLY_ONCE");
    assert_eq!(encryption_count, 1, "RUNNING_WORKER_NO_FRESH_ENCRYPTION");
    assert_eq!(rotations, 0);
    native_shutdown.unwrap();
    assert_eq!(exit.unwrap(), NetconfWorkerExit::Drained);
}
