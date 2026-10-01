//! The protocol's real 30-second request budget is shorter than the unchanged
//! prepared handle lifetime. A live owner cannot turn expiry into new admission;
//! an already acknowledged original still owns its completion after expiry.

use super::*;

const REQUEST_BUDGET: Duration = Duration::from_secs(30);

// Spend the earlier part of the unchanged request budget in real key-provider
// preparation. Checkpoint I/O has its own shorter operation timeout, so holding
// a checkpoint for the entire request budget would test adapter timeout instead
// of the final admission guard. Leave half that I/O budget for native admission.
const ADMISSION_WINDOW: Duration = Duration::from_secs(WAIT.as_secs() / 2);

#[tokio::test]
async fn running_worker_expired_live_request_cannot_enter_native_admission() {
    let f = Fixture::new().await;
    let w = Worker::new(&f).await;
    let owner = w.audit.open_session(&principal()).await.unwrap();
    let authenticated = principal();
    let database = f.directory.path().join("authority.sqlite");
    let mut request = request(0);
    request.deadline = Instant::now() + REQUEST_BUDGET;
    let deadline = request.deadline;
    let request_id = request.request_id;
    let event = request_event(&request);
    let before = f.rows();
    let preparation_release = f.provider.encrypt_gate.arm();
    let release = f.checkpoint.revocation.arm_before_admission();
    let mut call =
        Box::pin(
            w.audit
                .replace_running(&owner, &authenticated, request, event.clone()),
        );
    let preparing = tokio::time::timeout(WAIT, async {
        tokio::select! {
            _ = f.provider.encrypt_gate.entered() => true,
            _ = &mut call => false,
        }
    })
    .await
    .unwrap_or(false);
    tokio::time::sleep_until(tokio::time::Instant::from_std(deadline - ADMISSION_WINDOW)).await;
    drop(preparation_release);
    // An early reply may have completed `call`; never poll it again. The
    // common tail still releases both gates and joins before reporting setup.
    let reached = if preparing {
        tokio::time::timeout(WAIT, async {
            tokio::select! {
                _ = f.checkpoint.revocation.admission_gate.entered() => true,
                _ = &mut call => false,
            }
        })
        .await
        .unwrap_or(false)
    } else {
        false
    };
    let reached_before_expiry = Instant::now() < deadline;
    let held_loads = f
        .checkpoint
        .revocation
        .observed_loads
        .load(Ordering::Acquire);
    let held_unchanged = f.rows() == before;
    let held_absent = originals(&database, &event).is_empty();
    let held_history = history_count(&f);
    let encrypted_once = f.provider.active.load(Ordering::Acquire) == 1;
    let held_not_returned = !f
        .checkpoint
        .revocation
        .admission_gate_returned
        .load(Ordering::Acquire);

    // Keep the real transport owner AND its call alive. Neither cancellation
    // nor session revocation may satisfy this detector. No clock is advanced or
    // deadline extended; release while the independently fixed handle is live.
    tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
    let expired = Instant::now() >= deadline;
    // Account for whole-second handle timestamps without changing either TTL.
    let handle_still_live =
        Instant::now() < deadline + (LIFETIME - REQUEST_BUDGET) - Duration::from_secs(1);
    drop(release);
    let reply = if reached {
        Some(tokio::time::timeout(WAIT, &mut call).await)
    } else {
        None
    };
    let refused = matches!(&reply, Some(Ok(Ok(NetconfMutationResult::Refused(error))))
        if error.code == CommitErrorCode::AdmissionRejected);
    drop(call);
    let recovered =
        tokio::time::timeout(WAIT, w.audit.recover_request(request_id, &authenticated)).await;
    let same_refusal = matches!(&recovered, Ok(Ok(Some(NetconfMutationResult::Refused(error))))
        if error.code == CommitErrorCode::AdmissionRejected);
    let snapshot = w.bus.current_snapshot();
    // The owner is deliberately retained until after the result and readback.
    drop(owner);
    let exit = w.audit.shutdown().await;
    drop(w);
    drop(f.encrypted);
    drop(f.raft);
    let native_shutdown = f.store.shutdown().await;
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

    native_shutdown.unwrap();
    assert_eq!(exit.unwrap(), NetconfWorkerExit::Drained);
    eprintln!("RUNNING_DEADLINE_CLEANUP_COMPLETE: originals={} history={history} encrypted={encryption_count}", after.len());
    assert!(
        preparing && reached && reached_before_expiry,
        "RUNNING_DEADLINE_GATE_SETUP"
    );
    assert_eq!(held_loads, 3, "RUNNING_DEADLINE_LOAD_SEQUENCE");
    assert!(held_unchanged && held_absent && held_history == 0 && encrypted_once);
    assert!(
        held_not_returned && gate_returned && expired && handle_still_live,
        "RUNNING_DEADLINE_GATE_LIFETIME: held={held_not_returned} returned={gate_returned} expired={expired} handle_live={handle_still_live}"
    );
    assert!(
        refused && same_refusal,
        "RUNNING_EXPIRED_NATIVE_ADMISSION_REFUSAL"
    );
    assert!(after.is_empty(), "RUNNING_EXPIRED_NO_ORIGINAL_INTENT");
    assert_eq!(history, 0, "RUNNING_EXPIRED_NO_EFFECT");
    assert_eq!(snapshot.version, ConfigVersion::INITIAL);
    assert!(snapshot.tx_id.is_none());
    assert_eq!(encryption_count, 1);
}

#[tokio::test]
async fn running_worker_acknowledged_original_completes_after_request_deadline() {
    let f = Fixture::new().await;
    let w = Worker::new(&f).await;
    let owner = w.audit.open_session(&principal()).await.unwrap();
    let authenticated = principal();
    let database = f.directory.path().join("authority.sqlite");
    let mut request = request(0);
    request.deadline = Instant::now() + REQUEST_BUDGET;
    let deadline = request.deadline;
    let request_id = request.request_id;
    let event = request_event(&request);
    let preparation_release = f.provider.encrypt_gate.arm();
    let release = f.checkpoint.revocation.intent_gate.arm();
    let mut call =
        Box::pin(
            w.audit
                .replace_running(&owner, &authenticated, request, event.clone()),
        );
    let preparing = tokio::time::timeout(WAIT, async {
        tokio::select! {
            _ = f.provider.encrypt_gate.entered() => true,
            _ = &mut call => false,
        }
    })
    .await
    .unwrap_or(false);
    tokio::time::sleep_until(tokio::time::Instant::from_std(deadline - ADMISSION_WINDOW)).await;
    drop(preparation_release);
    // Preserve explicit cleanup if preparation returned before entering its
    // gate instead of polling an already completed reply future.
    let reached = if preparing {
        tokio::time::timeout(WAIT, async {
            tokio::select! {
                _ = f.checkpoint.revocation.intent_gate.entered() => true,
                _ = &mut call => false,
            }
        })
        .await
        .unwrap_or(false)
    } else {
        false
    };
    let reached_before_expiry = Instant::now() < deadline;
    let held = originals(&database, &event);
    let held_history = history_count(&f);
    let handle_bytes = held
        .first()
        .map(|original| original.handle.encode().unwrap());
    let authenticated_intent = if let Some(original) = held.first() {
        f.store
            .lookup_audit_operation(&original.handle, caller())
            .await
            .is_ok_and(|receipt| {
                receipt.is_some_and(|receipt| {
                    receipt.state() == AuditOperationState::Intent && !receipt.terminal_recorded()
                })
            })
    } else {
        false
    };

    // Admission has already been acknowledged. Expiry cannot undo that original
    // or its independently checkpointed completion, and cannot mint a successor.
    tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
    let expired = Instant::now() >= deadline;
    // Account for whole-second handle timestamps without changing either TTL.
    let handle_still_live =
        Instant::now() < deadline + (LIFETIME - REQUEST_BUDGET) - Duration::from_secs(1);
    drop(release);
    let reply = if reached {
        Some(tokio::time::timeout(WAIT, &mut call).await)
    } else {
        None
    };
    let published = match &reply {
        Some(Ok(Ok(NetconfMutationResult::Applied(receipt)))) => {
            receipt.published_commit().map(|commit| {
                (
                    commit.tx_id,
                    receipt.recovery_handle().encode().unwrap(),
                    receipt.terminal_recorded()
                        && !receipt.completion_pending()
                        && !receipt.publication_pending(),
                )
            })
        }
        _ => None,
    };
    drop(call);
    let recovered =
        tokio::time::timeout(WAIT, w.audit.recover_request(request_id, &authenticated)).await;
    let same_recovery = matches!(&recovered, Ok(Ok(Some(NetconfMutationResult::Applied(receipt))))
        if Some(receipt.recovery_handle().encode().unwrap()) == handle_bytes
            && receipt.published_commit().is_some());
    let decoded = f.encrypted.load_latest().await;
    let snapshot = w.bus.current_snapshot();
    drop(owner);
    let exit = w.audit.shutdown().await;
    drop(w);
    drop(f.encrypted);
    drop(f.raft);
    let native_shutdown = f.store.shutdown().await;
    let after = originals(&database, &event);
    let history = persisted_history_count(&database);
    let encryption_count = f.provider.active.load(Ordering::Acquire);
    let checkpoint = f.checkpoint.current.lock().unwrap().clone().unwrap();
    let gate_returned = f
        .checkpoint
        .revocation
        .intent_gate_returned
        .load(Ordering::Acquire);
    drop(f.store);
    drop(f.directory);

    native_shutdown.unwrap();
    assert_eq!(exit.unwrap(), NetconfWorkerExit::Drained);
    eprintln!("RUNNING_ACK_DEADLINE_CLEANUP_COMPLETE: originals={} history={history} encrypted={encryption_count}", after.len());
    assert!(
        preparing && reached && reached_before_expiry && expired && gate_returned && handle_still_live,
        "RUNNING_ACK_DEADLINE_GATE_LIFETIME: preparing={preparing} reached={reached} before_expiry={reached_before_expiry} returned={gate_returned} expired={expired} handle_live={handle_still_live}"
    );
    assert_eq!(held.len(), 1);
    assert!(held[0].matches_request && authenticated_intent);
    assert_eq!(held_history, 0);
    let (tx_id, applied_handle, settled) =
        published.expect("RUNNING_ACK_DEADLINE_EXACT_PUBLICATION");
    assert_eq!(Some(applied_handle), handle_bytes);
    assert!(settled && same_recovery, "RUNNING_ACK_DEADLINE_RECOVERY");
    let decoded = decoded.unwrap().unwrap();
    assert_eq!(decoded.tx_id, tx_id);
    assert_eq!(decoded.config.label, "revision-1");
    assert!(!decoded.recovery_required);
    assert_eq!(snapshot.tx_id, Some(tx_id));
    assert_eq!(snapshot.version, decoded.version);
    assert_eq!(snapshot.config.as_ref(), &decoded.config);
    assert_eq!(after.len(), 1, "RUNNING_ACK_DEADLINE_NO_REPLACEMENT");
    assert_eq!(Some(after[0].handle.encode().unwrap()), handle_bytes);
    assert!(after[0].matches_request && after[0].terminal_recorded);
    assert!(checkpoint.sequence() >= after[0].last_sequence);
    assert_eq!(history, 1);
    assert_eq!(
        encryption_count, 1,
        "RUNNING_ACK_DEADLINE_NO_NEW_ENCRYPTION"
    );
}
