//! Real retained cleanup originals over the existing worker/session components.
//! Checkpoint faults only stop real I/O; they never supply an admission receipt.
use std::{num::NonZeroUsize, sync::atomic::Ordering, time::Duration};

use opc_config_model::{RequestId, TransportType, TrustedPrincipal, WorkloadIdentity};
use opc_mgmt_audit::{AuditEvent, AuditOperation, AuditOutcome};
use opc_persist::audit_authority::{
    AuditAdmission, AuditAuthorityError, AuditCaller, AuditOperationHandle, AuditOperationReceipt,
    AuditOperationState, NetconfAppliedOutcome, NetconfSessionOwner, PreparedTargetMutation,
};
use opc_persist::ConfigStore;
use opc_types::TenantId;
use tokio::sync::oneshot;

use super::super::{
    native_fixture::{Checkpoint, Fixture},
    session_lifetime::SessionWake,
    store::TargetReply,
    worker::TargetWorker,
    worker_join::{WorkerExit, WorkerJoin},
};
use super::Slot;

const WAIT: Duration = Duration::from_secs(10);
const LIFETIME: Duration = Duration::from_secs(60);

fn principal() -> TrustedPrincipal {
    TrustedPrincipal::new(
        WorkloadIdentity::User("synthetic-cleanup-owner".into()),
        TenantId::from_static("synthetic-cleanup"),
    )
}

struct Original {
    handle: AuditOperationHandle,
    prepared: PreparedTargetMutation,
    owner: NetconfSessionOwner,
    event: AuditEvent,
}

// Retain the genuine SDK preparation before invoking the worker's admission
// path. This is the same owner, event, slot and preparation as cleanup_revoked;
// exposing this boundary in the fixture permits a deterministic I/O fault.
async fn worker_with_original(fixture: &Fixture) -> (TargetWorker, Original) {
    let mut worker = TargetWorker::new(
        fixture.port.clone(),
        NonZeroUsize::new(1).unwrap(),
        SessionWake::new(),
    );
    let (reply, receiver) = oneshot::channel();
    worker
        .sessions
        .open_in_worker(&fixture.port, principal(), reply)
        .await;
    let transport = receiver.await.unwrap().unwrap();
    drop(transport);
    let Slot::Owned(session) = &mut worker.sessions.entries[0] else {
        panic!("real session owner must remain in the worker")
    };
    assert!(session.lifetime.is_revoked());
    let owner = session.lifetime.owner().clone();
    let event = session.context.cleanup.clone();
    let attempt = fixture
        .port
        .prepare_cleanup(&owner, &principal(), &event)
        .await
        .unwrap();
    let handle = attempt.handle().clone();
    session.cleanup = Some(attempt);
    let prepared = fixture
        .store
        .prepare_netconf_session_cleanup(
            &owner,
            fixture.privacy.as_ref(),
            &super::super::event::convert_event(&event).unwrap(),
            LIFETIME,
        )
        .await
        .unwrap();
    assert!(prepared.handle() == &handle);
    (
        worker,
        Original {
            handle,
            prepared,
            owner,
            event,
        },
    )
}

async fn joined(worker: TargetWorker) -> WorkerExit {
    // Own and join the actual TargetWorker drain future. This is a component
    // detector; the production ConfigBus still owns its sole worker task.
    let join = WorkerJoin::new(tokio::spawn(async move {
        let mut worker = worker;
        worker.finish_drain().await
    }));
    let exit = tokio::time::timeout(WAIT, join.join())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(join.join().await.unwrap(), exit);
    exit
}

async fn exact_intent(fixture: &Fixture, original: &Original) {
    let receipt = fixture
        .store
        .lookup_audit_operation(&original.handle, fixture.caller)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.state(), AuditOperationState::Intent, "CLEANUP_UNKNOWN_IS_NOT_ADMISSION: original Intent must not be retired or applied without its acknowledged/stale boundary");
    assert!(!receipt.terminal_recorded());
    let recovered = fixture
        .store
        .recover_netconf_target(&original.handle, fixture.caller)
        .await
        .unwrap()
        .unwrap();
    assert!(recovered == original.prepared);
    let cached = fixture
        .store
        .retained_netconf_session_cleanup(
            &original.owner,
            fixture.caller,
            fixture.privacy.as_ref(),
            &super::super::event::convert_event(&original.event).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert!(cached == original.prepared);
}

async fn settled(fixture: &Fixture, original: &Original) -> bool {
    let Some(receipt) = fixture
        .store
        .lookup_audit_operation(&original.handle, fixture.caller)
        .await
        .unwrap()
    else {
        return false;
    };
    let recovered = fixture
        .store
        .recover_netconf_target(&original.handle, fixture.caller)
        .await
        .unwrap()
        .unwrap();
    assert!(recovered == original.prepared);
    let progress = fixture.store.reconcile_audit_obligations(32).await.unwrap();
    // With no unsettled operations the authenticated pass performs no repair.
    receipt.terminal_recorded()
        && matches!(receipt.state(), AuditOperationState::TargetV1(result)
            if matches!(result.outcome(), NetconfAppliedOutcome::Lifecycle { .. }))
        && progress.inspected == 0
        && fixture.port.verify_current().await.is_ok()
}

#[tokio::test]
async fn native_cleanup_acknowledged_intent_recovers_exact_original() {
    let fixture = Fixture::new(&principal()).await;
    let (mut worker, original) = worker_with_original(&fixture).await;
    fixture
        .checkpoint
        .fail_intent_checkpoint
        .store(true, Ordering::Release);
    worker.cleanup().await;
    // Admission completed normally; stopping Intent checkpointing prevents the
    // effect. This must retain the real acknowledgement in worker-owned state.
    exact_intent(&fixture, &original).await;
    assert!(matches!(
        worker
            .sessions
            .revoked()
            .next()
            .unwrap()
            .cleanup_attempt()
            .unwrap()
            .retained_reply(),
        TargetReply::Unknown
    ));
    fixture
        .checkpoint
        .fail_intent_checkpoint
        .store(false, Ordering::Release);
    let exit = joined(worker).await;
    let complete = settled(&fixture, &original).await;
    let still_revoked = fixture
        .store
        .verify_netconf_session_owner(&original.owner, fixture.caller)
        .await
        .is_err();
    fixture.close().await;
    assert!(
        exit == WorkerExit::Drained && complete && still_revoked,
        "CLEANUP_ACKNOWLEDGED_ORIGINAL: the exact admitted cleanup must finish after checkpoint restoration"
    );
}

#[tokio::test]
async fn native_cleanup_definite_refusal_retries_same_original() {
    let fixture = Fixture::new(&principal()).await;
    let (mut worker, original) = worker_with_original(&fixture).await;
    fixture
        .checkpoint
        .unavailable
        .store(true, Ordering::Release);
    worker.cleanup().await;
    assert!(matches!(
        worker
            .sessions
            .revoked()
            .next()
            .unwrap()
            .cleanup_attempt()
            .unwrap()
            .retained_reply(),
        TargetReply::Refused(AuditAuthorityError::Unavailable)
    ));
    fixture
        .checkpoint
        .unavailable
        .store(false, Ordering::Release);
    assert!(fixture
        .store
        .lookup_audit_operation(&original.handle, fixture.caller)
        .await
        .unwrap()
        .is_none());
    let exit = joined(worker).await;
    let complete = settled(&fixture, &original).await;
    fixture.close().await;
    assert!(
        exit == WorkerExit::Drained && complete,
        "CLEANUP_DEFINITE_REFUSAL: a definite refusal must not poison later recovery of the unchanged original"
    );
}

#[tokio::test]
async fn native_cleanup_unknown_admission_never_becomes_effect_authority() {
    let fixture = Fixture::new(&principal()).await;
    let (mut worker, original) = worker_with_original(&fixture).await;
    // Current SDK sequence: target preflight, command preflight, then receipt
    // refresh after native consensus admission. Fail only the third real read.
    // The assertions below fail setup if that SDK sequence changes.
    let fail_at = fixture.checkpoint.loads.load(Ordering::Acquire) + 3;
    fixture
        .checkpoint
        .fail_load_at
        .store(fail_at, Ordering::Release);
    worker.cleanup().await;
    assert_eq!(
        fixture.checkpoint.failed_load.load(Ordering::Acquire),
        fail_at
    );
    exact_intent(&fixture, &original).await;
    assert!(matches!(
        worker
            .sessions
            .revoked()
            .next()
            .unwrap()
            .cleanup_attempt()
            .unwrap()
            .retained_reply(),
        TargetReply::Unknown
    ));
    let exit = joined(worker).await;
    let receipt = fixture
        .store
        .lookup_audit_operation(&original.handle, fixture.caller)
        .await
        .unwrap()
        .unwrap();
    let recovered = fixture
        .store
        .recover_netconf_target(&original.handle, fixture.caller)
        .await
        .unwrap()
        .unwrap();
    let progress = fixture.store.reconcile_audit_obligations(32).await.unwrap();
    fixture.close().await;
    assert!(
        exit == WorkerExit::RecoveryRequired
            && receipt.state() == AuditOperationState::Intent
            && !receipt.terminal_recorded()
            && recovered == original.prepared
            && progress.pending == 1
            && progress.completed == 0,
        "CLEANUP_UNKNOWN_IS_NOT_ADMISSION: an Intent lookup cannot replace the lost admission acknowledgement"
    );
}

struct ReleaseAdvance<'a>(&'a Checkpoint);
impl Drop for ReleaseAdvance<'_> {
    fn drop(&mut self) {
        self.0.release.notify_one();
    }
}

fn applied(admission: AuditAdmission) -> AuditOperationReceipt {
    match admission {
        AuditAdmission::Applied(receipt) => receipt,
        other => panic!("expected authenticated native outcome: {other:?}"),
    }
}

fn expiry(prepared: &PreparedTargetMutation) -> serde_json::Value {
    let value = serde_json::from_slice::<serde_json::Value>(&prepared.handle().encode().unwrap())
        .unwrap()["body"]["expires_at"]
        .clone();
    assert!(
        value.is_i64(),
        "fixed expiry must be present in the real signed handle"
    );
    value
}

fn successor_event() -> AuditEvent {
    AuditEvent::new(
        RequestId::new(),
        &principal(),
        TransportType::Internal,
        AuditOperation::Exec,
        AuditOutcome::Intent,
    )
}

async fn exact_rejected(fixture: &Fixture, original: &Original, terminal: bool) {
    let receipt = fixture
        .store
        .lookup_audit_operation(&original.handle, fixture.caller)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.state(), AuditOperationState::Rejected);
    assert_eq!(receipt.terminal_recorded(), terminal);
    assert!(
        fixture
            .store
            .recover_netconf_target(&original.handle, fixture.caller)
            .await
            .unwrap()
            .unwrap()
            == original.prepared
    );
    assert!(fixture.store.load_latest().await.unwrap().is_none());
}

#[tokio::test]
async fn native_concurrent_cleanup_retires_stale_original_then_joins_both() {
    let fixture = Fixture::new(&principal()).await;
    let (mut first, a) = worker_with_original(&fixture).await;
    let (mut second, b) = worker_with_original(&fixture).await;
    fixture
        .checkpoint
        .pause_advance
        .store(true, Ordering::Release);
    let release = ReleaseAdvance(&fixture.checkpoint);
    let mut first_cleanup = Box::pin(first.cleanup());
    tokio::time::timeout(WAIT, async {
        tokio::select! {
            _ = fixture.checkpoint.entered.notified() => {}
            _ = first_cleanup.as_mut() => panic!("first original must reach its real Intent checkpoint"),
        }
    }).await.unwrap();
    exact_intent(&fixture, &a).await;
    tokio::time::timeout(WAIT, second.cleanup()).await.unwrap();
    assert!(fixture
        .store
        .lookup_audit_operation(&b.handle, fixture.caller)
        .await
        .unwrap()
        .is_none());
    assert!(matches!(
        second
            .sessions
            .revoked()
            .next()
            .unwrap()
            .cleanup_attempt()
            .unwrap()
            .retained_reply(),
        TargetReply::Refused(AuditAuthorityError::RecoveryRequired)
    ));
    drop(release);
    tokio::time::timeout(WAIT, first_cleanup.as_mut())
        .await
        .unwrap();
    drop(first_cleanup);
    assert!(settled(&fixture, &a).await);

    // A new bounded pass can now retire B. Stop only the successor's genuine
    // Intent checkpoint: retirement's terminal checkpoint is the first advance.
    fixture
        .checkpoint
        .advances_since_arm
        .store(0, Ordering::Release);
    fixture
        .checkpoint
        .fail_completion
        .store(true, Ordering::Release);
    second.cleanup().await;
    let retired = fixture
        .store
        .lookup_audit_operation(&b.handle, fixture.caller)
        .await
        .unwrap();
    assert!(retired.as_ref().is_some_and(|r| r.state() == AuditOperationState::Rejected && r.terminal_recorded()),
        "CLEANUP_DURABLE_RETIREMENT: stale missing Intent must become a real settled rejection before replacement");
    exact_rejected(&fixture, &b, true).await;
    let Slot::Owned(session) = &second.sessions.entries[0] else {
        panic!("successor must remain owned while its real checkpoint is unavailable")
    };
    let next_handle = session.cleanup.as_ref().unwrap().handle().clone();
    let next_event = session.context.cleanup.clone();
    let next = fixture
        .store
        .retained_netconf_session_cleanup(
            &b.owner,
            fixture.caller,
            fixture.privacy.as_ref(),
            &super::super::event::convert_event(&next_event).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert!(next.handle() == &next_handle && next_handle != b.handle,
        "CLEANUP_SEPARATE_SUCCESSOR: exact retired predecessor must not be relabelled as an applied cleanup");
    assert_eq!(
        expiry(&next),
        expiry(&b.prepared),
        "CLEANUP_FIXED_CLOSING_WINDOW"
    );
    let successor = Original {
        handle: next_handle,
        prepared: next,
        owner: b.owner.clone(),
        event: next_event,
    };
    exact_intent(&fixture, &successor).await;
    fixture
        .checkpoint
        .fail_completion
        .store(false, Ordering::Release);
    // Settle the held successor in the existing bounded cleanup pass before
    // either final join reads the shared authority. A concurrent one-pass drain
    // is allowed to report RecoveryRequired while the other owner owes work.
    second.cleanup().await;
    let completed = settled(&fixture, &successor).await;
    assert!(completed && second.sessions.is_empty());
    let (first_exit, second_exit) = tokio::join!(joined(first), joined(second));
    exact_rejected(&fixture, &b, true).await;
    let replay = applied(
        fixture
            .store
            .admit_netconf_target_local(&b.prepared, fixture.caller)
            .await,
    );
    let replay = applied(
        fixture
            .store
            .submit_netconf_target_local(&b.prepared, &replay, fixture.caller)
            .await,
    );
    assert_eq!(
        replay.state(),
        AuditOperationState::Rejected,
        "CLEANUP_RETIRED_NEVER_REVIVES"
    );
    fixture.close().await;
    assert!(first_exit == WorkerExit::Drained && second_exit == WorkerExit::Drained && completed,
        "CLEANUP_BOUNDED_CONVERGENCE: two retained workers must join after authentic retirement, successor effect and checkpoints");
}

#[tokio::test]
async fn native_cleanup_retirement_refuses_foreign_session_caller_and_payload() {
    let fixture = Fixture::new(&principal()).await;
    let (first, a) = worker_with_original(&fixture).await;
    let (second, b) = worker_with_original(&fixture).await;
    assert_eq!(joined(first).await, WorkerExit::Drained);
    let foreign = AuditCaller::project(
        fixture.privacy.as_ref(),
        "synthetic-other",
        "synthetic-other",
    )
    .unwrap();
    let mut encoded: serde_json::Value =
        serde_json::from_slice(&b.prepared.encode().unwrap()).unwrap();
    let byte = encoded["effect"]["resolution"]["end-session"]["session"][0]
        .as_u64()
        .unwrap() as u8;
    encoded["effect"]["resolution"]["end-session"]["session"][0] = byte.wrapping_add(1).into();
    let changed = PreparedTargetMutation::decode(&serde_json::to_vec(&encoded).unwrap()).unwrap();
    assert!(changed != b.prepared);
    for (owner, prepared, caller) in [
        (&a.owner, &b.prepared, fixture.caller),
        (&b.owner, &b.prepared, foreign),
        (&b.owner, &changed, fixture.caller),
    ] {
        let result = fixture
            .store
            .retire_netconf_session_cleanup_local(owner, prepared, caller)
            .await;
        assert!(
            matches!(
                result,
                AuditAdmission::Rejected(AuditAuthorityError::BindingMismatch)
            ),
            "CLEANUP_RETIREMENT_BINDING: another session/caller/payload must be definitely refused"
        );
        assert!(fixture
            .store
            .lookup_audit_operation(&b.handle, fixture.caller)
            .await
            .unwrap()
            .is_none());
        assert!(fixture.store.load_latest().await.unwrap().is_none());
        assert!(fixture.port.verify_current().await.is_ok());
    }
    let event = super::super::event::convert_event(&successor_event()).unwrap();
    assert!(
        fixture
            .store
            .prepare_netconf_session_cleanup_after_retirement(
                &b.owner,
                &b.prepared,
                fixture.privacy.as_ref(),
                &event
            )
            .await
            .is_err(),
        "CLEANUP_ABSENT_IS_NOT_REJECTED"
    );
    // Lose a genuine retirement reply, then recover the exact durable result.
    applied(
        fixture
            .store
            .retire_netconf_session_cleanup_local(&b.owner, &b.prepared, fixture.caller)
            .await,
    );
    exact_rejected(&fixture, &b, false).await;
    let recovered = applied(
        fixture
            .store
            .retire_netconf_session_cleanup_local(&b.owner, &b.prepared, fixture.caller)
            .await,
    );
    assert_eq!(recovered.state(), AuditOperationState::Rejected);
    assert!(
        fixture
            .store
            .prepare_netconf_session_cleanup_after_retirement(
                &b.owner,
                &b.prepared,
                fixture.privacy.as_ref(),
                &event
            )
            .await
            .is_err(),
        "CLEANUP_REJECTION_REQUIRES_TERMINAL"
    );
    let exit = joined(second).await;
    fixture.close().await;
    assert_eq!(
        exit,
        WorkerExit::Drained,
        "CLEANUP_LOST_RETIREMENT_REPLY_RECOVERS_ORIGINAL"
    );
}

#[tokio::test]
async fn native_cleanup_cancelled_retirement_completion_keeps_checkpoint_debt() {
    let fixture = Fixture::new(&principal()).await;
    let (first, _) = worker_with_original(&fixture).await;
    let (mut second, original) = worker_with_original(&fixture).await;
    assert_eq!(joined(first).await, WorkerExit::Drained);
    fixture
        .checkpoint
        .pause_advance
        .store(true, Ordering::Release);
    let release = ReleaseAdvance(&fixture.checkpoint);
    let mut cleanup = Box::pin(second.cleanup());
    tokio::time::timeout(WAIT, async {
        tokio::select! {
            _ = fixture.checkpoint.entered.notified() => {}
            _ = cleanup.as_mut() => panic!("retirement must hold its real terminal checkpoint"),
        }
    })
    .await
    .unwrap();
    exact_rejected(&fixture, &original, true).await;
    drop(cleanup);
    drop(release);
    let event = super::super::event::convert_event(&successor_event()).unwrap();
    let refused = fixture
        .store
        .prepare_netconf_session_cleanup_after_retirement(
            &original.owner,
            &original.prepared,
            fixture.privacy.as_ref(),
            &event,
        )
        .await;
    assert!(
        matches!(refused, Err(AuditAuthorityError::RecoveryRequired)),
        "CLEANUP_RETIREMENT_CHECKPOINT: terminal alone must never authorize a successor"
    );
    let attempt = second
        .sessions
        .revoked()
        .next()
        .unwrap()
        .cleanup_attempt()
        .unwrap();
    assert!(
        attempt.handle() == &original.handle
            && matches!(
                attempt.retained_reply(),
                TargetReply::Known {
                    completion_pending: true,
                    ..
                }
            ),
        "CLEANUP_CANCELLED_RETIREMENT_OWNS_ORIGINAL"
    );
    fixture
        .checkpoint
        .unavailable
        .store(true, Ordering::Release);
    second.cleanup().await;
    assert!(
        second
            .sessions
            .revoked()
            .next()
            .unwrap()
            .cleanup_attempt()
            .unwrap()
            .handle()
            == &original.handle
    );
    fixture
        .checkpoint
        .unavailable
        .store(false, Ordering::Release);
    let exit = joined(second).await;
    let settled_original = fixture
        .store
        .lookup_audit_operation(&original.handle, fixture.caller)
        .await
        .unwrap()
        .unwrap();
    assert!(
        settled_original.terminal_recorded()
            && settled_original.state() == AuditOperationState::Rejected
    );
    fixture.close().await;
    assert_eq!(
        exit,
        WorkerExit::Drained,
        "CLEANUP_RESTORED_RETIREMENT_COMPLETION"
    );
}

#[tokio::test]
async fn native_cleanup_apply_winner_survives_retirement_read_race() {
    let fixture = Fixture::new(&principal()).await;
    let (worker, original) = worker_with_original(&fixture).await;
    let intent = applied(
        fixture
            .store
            .admit_netconf_target_local(&original.prepared, fixture.caller)
            .await,
    );
    assert_eq!(intent.state(), AuditOperationState::Intent);
    fixture.checkpoint.pause.store(true, Ordering::Release);
    let release = ReleaseAdvance(&fixture.checkpoint);
    let mut retirement = Box::pin(fixture.store.retire_netconf_session_cleanup_local(
        &original.owner,
        &original.prepared,
        fixture.caller,
    ));
    tokio::time::timeout(WAIT, async {
        tokio::select! {
            _ = fixture.checkpoint.entered.notified() => {}
            result = retirement.as_mut() => panic!("retirement must hold authenticated read: {result:?}"),
        }
    }).await.unwrap();
    let applied_first = applied(
        fixture
            .store
            .submit_netconf_target_local(&original.prepared, &intent, fixture.caller)
            .await,
    );
    assert!(matches!(
        applied_first.state(),
        AuditOperationState::TargetV1(_)
    ));
    assert!(!applied_first.terminal_recorded());
    drop(release);
    let replay = applied(
        tokio::time::timeout(WAIT, retirement.as_mut())
            .await
            .unwrap(),
    );
    drop(retirement);
    assert_eq!(replay.state(), applied_first.state(), "CLEANUP_APPLY_WINNER: retirement must preserve the exact effect and its outstanding audit debt");
    assert!(!replay.terminal_recorded());
    let exit = joined(worker).await;
    let complete = settled(&fixture, &original).await;
    fixture.close().await;
    assert!(
        exit == WorkerExit::Drained && complete,
        "CLEANUP_APPLY_WINNER_COMPLETION"
    );
}

#[tokio::test]
async fn native_cleanup_retirement_retries_outer_refusal_after_authenticated_revision() {
    let fixture = Fixture::new(&principal()).await;
    let (first, _) = worker_with_original(&fixture).await;
    let (second, b) = worker_with_original(&fixture).await;
    assert_eq!(joined(first).await, WorkerExit::Drained);
    let (third, c) = worker_with_original(&fixture).await;
    // Three real reads in this pinned API: initial exact lookup, retirement
    // preflight, then command preflight. The gate holds that last authenticated
    // ledger read before enqueue, so C can win the actual admission transaction.
    let gate_at = fixture.checkpoint.loads.load(Ordering::Acquire) + 3;
    fixture
        .checkpoint
        .pause_load_at
        .store(gate_at, Ordering::Release);
    let release = ReleaseAdvance(&fixture.checkpoint);
    let mut retire = Box::pin(fixture.store.retire_netconf_session_cleanup_local(
        &b.owner,
        &b.prepared,
        fixture.caller,
    ));
    tokio::time::timeout(WAIT, async {
        tokio::select! {
            _ = fixture.checkpoint.entered.notified() => {}
            result = retire.as_mut() => panic!("retirement pre-enqueue read did not hold: {result:?}"),
        }
    }).await.unwrap();
    assert_eq!(fixture.checkpoint.loads.load(Ordering::Acquire), gate_at);
    let admitted = applied(
        fixture
            .store
            .admit_netconf_target_local(&c.prepared, fixture.caller)
            .await,
    );
    exact_intent(&fixture, &c).await;
    drop(release);
    let refused = tokio::time::timeout(WAIT, retire.as_mut()).await.unwrap();
    drop(retire);
    assert!(
        matches!(refused, AuditAdmission::Rejected(_)),
        "RETIREMENT_BUSY_RACE: competing Intent must cause a definite no-effect refusal"
    );
    assert!(fixture
        .store
        .lookup_audit_operation(&b.handle, fixture.caller)
        .await
        .unwrap()
        .is_none());
    let result = applied(
        fixture
            .store
            .submit_netconf_target_local(&c.prepared, &admitted, fixture.caller)
            .await,
    );
    fixture
        .store
        .complete_required_audit_outcome(&result, fixture.caller)
        .await
        .unwrap();
    let retried = fixture
        .store
        .retire_netconf_session_cleanup_local(&b.owner, &b.prepared, fixture.caller)
        .await;
    assert!(matches!(&retried, AuditAdmission::Applied(receipt) if receipt.state() == AuditOperationState::Rejected),
        "CLEANUP_OUTER_REFUSAL_RETRY: a changed authenticated ledger may retry retirement without replacing its signed audit original");
    exact_rejected(&fixture, &b, false).await;
    let retired = applied(retried);
    fixture
        .store
        .complete_required_audit_outcome(&retired, fixture.caller)
        .await
        .unwrap();
    // Complete these joins in sequence; simultaneous one-pass clean shutdown
    // while another owner still owes a checkpoint is not the contract.
    assert_eq!(joined(third).await, WorkerExit::Drained);
    assert_eq!(joined(second).await, WorkerExit::Drained);
    fixture.close().await;
}

#[tokio::test]
async fn native_cleanup_cancelled_retirement_read_retains_unknown_original() {
    let fixture = Fixture::new(&principal()).await;
    let (first, _) = worker_with_original(&fixture).await;
    let (mut second, original) = worker_with_original(&fixture).await;
    assert_eq!(joined(first).await, WorkerExit::Drained);
    // The stale admission's preflight is read one. Read two is retirement's
    // original lookup, after the worker must retain its pending retirement.
    let gate_at = fixture.checkpoint.loads.load(Ordering::Acquire) + 2;
    fixture
        .checkpoint
        .pause_load_at
        .store(gate_at, Ordering::Release);
    let release = ReleaseAdvance(&fixture.checkpoint);
    let mut cleanup = Box::pin(second.cleanup());
    tokio::time::timeout(WAIT, async {
        tokio::select! {
            _ = fixture.checkpoint.entered.notified() => {}
            _ = cleanup.as_mut() => panic!("retirement read must be held after stale admission refusal"),
        }
    }).await.unwrap();
    assert_eq!(fixture.checkpoint.loads.load(Ordering::Acquire), gate_at);
    drop(cleanup);
    drop(release);
    let attempt = second
        .sessions
        .revoked()
        .next()
        .unwrap()
        .cleanup_attempt()
        .unwrap();
    assert!(attempt.handle() == &original.handle && matches!(attempt.retained_reply(), TargetReply::Unknown)
        && !attempt.admission_refused(), "CLEANUP_CANCELLED_RETIREMENT_UNKNOWN: an earlier refusal cannot hide a later cancelled retirement");
    fixture
        .checkpoint
        .unavailable
        .store(true, Ordering::Release);
    second.cleanup().await;
    assert!(
        matches!(
            second
                .sessions
                .revoked()
                .next()
                .unwrap()
                .cleanup_attempt()
                .unwrap()
                .retained_reply(),
            TargetReply::Unknown
        ),
        "CLEANUP_CANCELLED_RETIREMENT_UNKNOWN: a later unavailable read cannot clear uncertainty"
    );
    fixture
        .checkpoint
        .unavailable
        .store(false, Ordering::Release);
    assert!(fixture
        .store
        .lookup_audit_operation(&original.handle, fixture.caller)
        .await
        .unwrap()
        .is_none());
    // Lose a genuine retirement reply outside the cancelled worker future.
    // Recovery must authenticate this result and keep it ahead of the worker's
    // older stale-admission refusal on every later pass.
    let retired = applied(
        fixture
            .store
            .retire_netconf_session_cleanup_local(
                &original.owner,
                &original.prepared,
                fixture.caller,
            )
            .await,
    );
    assert_eq!(retired.state(), AuditOperationState::Rejected);
    for _ in 0..2 {
        let Slot::Owned(session) = &mut second.sessions.entries[0] else {
            panic!("cancelled retirement must retain its worker slot")
        };
        let reply = fixture
            .port
            .recover_target(session.cleanup.as_mut().unwrap())
            .await;
        assert!(matches!(reply, TargetReply::Known { receipt, completion_pending: false }
            if receipt.state() == AuditOperationState::Rejected),
            "CLEANUP_CANCELLED_RETIREMENT_RECOVERY: authenticated known outcome must precede the older refusal");
    }
    let exit = joined(second).await;
    exact_rejected(&fixture, &original, true).await;
    fixture.close().await;
    assert_eq!(
        exit,
        WorkerExit::Drained,
        "CLEANUP_CANCELLED_RETIREMENT_RECOVERY"
    );
}

#[tokio::test]
async fn native_cleanup_cancelled_accepted_retirement_reply_recovers_original() {
    let fixture = Fixture::new(&principal()).await;
    let (first, _) = worker_with_original(&fixture).await;
    let (mut second, original) = worker_with_original(&fixture).await;
    assert_eq!(joined(first).await, WorkerExit::Drained);
    assert!(fixture
        .store
        .lookup_audit_operation(&original.handle, fixture.caller)
        .await
        .unwrap()
        .is_none());
    let successor = successor_event();
    let successor_record = super::super::event::convert_event(&successor).unwrap();

    // The first cleanup made this original stale. Hold only the actual SDK
    // retirement reply, after native execution and before accept_known stores it
    // in the worker. An earlier read or a fabricated receipt cannot enter here.
    let reply_gate = fixture.port.hold_retirement_reply(&original.handle);
    let mut cleanup = Box::pin(second.cleanup());
    tokio::time::timeout(WAIT, async {
        tokio::select! {
            _ = reply_gate.entered() => {}
            _ = cleanup.as_mut() => panic!("CLEANUP_ACCEPTED_REPLY_BOUNDARY: native retirement reply was not held"),
        }
    })
    .await
    .unwrap();
    // These are independent quorum/authenticated reads of the actual command's
    // result while its worker-facing reply is still held. They do not complete
    // the terminal obligation or inject the result into the worker.
    exact_rejected(&fixture, &original, false).await;
    assert!(matches!(
        fixture
            .store
            .prepare_netconf_session_cleanup_after_retirement(
                &original.owner,
                &original.prepared,
                fixture.privacy.as_ref(),
                &successor_record,
            )
            .await,
        Err(AuditAuthorityError::RecoveryRequired)
    ), "CLEANUP_ACCEPTED_REPLY_TERMINAL: real Rejected without terminal must not authorize a successor");
    drop(cleanup);
    assert!(reply_gate.was_cancelled(), "CLEANUP_ACCEPTED_REPLY_CANCELLED: cancellation must drop the real held reply before worker retention");
    drop(reply_gate);

    let Slot::Owned(session) = &second.sessions.entries[0] else {
        panic!("accepted retirement cancellation must retain the worker slot")
    };
    let attempt = session.cleanup.as_ref().unwrap();
    assert!(attempt.handle() == &original.handle
        && matches!(attempt.retained_reply(), TargetReply::Unknown)
        && !attempt.admission_refused()
        && session.cleanup_successor.is_none(),
        "CLEANUP_ACCEPTED_REPLY_UNKNOWN: a cancelled accepted retirement cannot restore stale definite refusal or authorize replacement");
    let cached = fixture
        .store
        .retained_netconf_session_cleanup(
            &original.owner,
            fixture.caller,
            fixture.privacy.as_ref(),
            &super::super::event::convert_event(&original.event).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert!(
        cached == original.prepared,
        "CLEANUP_ACCEPTED_REPLY_ORIGINAL: cancellation must retain the exact signed original"
    );

    fixture
        .checkpoint
        .unavailable
        .store(true, Ordering::Release);
    second.cleanup().await;
    let Slot::Owned(session) = &second.sessions.entries[0] else {
        panic!("unavailable recovery must retain the accepted original")
    };
    let attempt = session.cleanup.as_ref().unwrap();
    assert!(attempt.handle() == &original.handle
        && matches!(attempt.retained_reply(), TargetReply::Unknown)
        && !attempt.admission_refused()
        && session.cleanup_successor.is_none(),
        "CLEANUP_ACCEPTED_REPLY_UNKNOWN: unavailable authenticated recovery must not clear accepted uncertainty");
    fixture
        .checkpoint
        .unavailable
        .store(false, Ordering::Release);

    // Resume through the actual worker recovery path. It must authenticate the
    // original result and append its real terminal, then stop at the existing
    // independent checkpoint I/O gate before any successor can be prepared.
    fixture
        .checkpoint
        .pause_advance
        .store(true, Ordering::Release);
    let release = ReleaseAdvance(&fixture.checkpoint);
    let mut recovery = Box::pin(second.cleanup());
    tokio::time::timeout(WAIT, async {
        tokio::select! {
            _ = fixture.checkpoint.entered.notified() => {}
            _ = recovery.as_mut() => panic!("CLEANUP_ACCEPTED_REPLY_CHECKPOINT_BOUNDARY: original terminal checkpoint was not held"),
        }
    })
    .await
    .unwrap();
    exact_rejected(&fixture, &original, true).await;
    assert!(matches!(
        fixture
            .store
            .prepare_netconf_session_cleanup_after_retirement(
                &original.owner,
                &original.prepared,
                fixture.privacy.as_ref(),
                &successor_record,
            )
            .await,
        Err(AuditAuthorityError::RecoveryRequired)
    ), "CLEANUP_ACCEPTED_REPLY_CHECKPOINT: an authenticated terminal without its covering checkpoint cannot authorize replacement");
    drop(recovery);
    drop(release);
    let Slot::Owned(session) = &second.sessions.entries[0] else {
        panic!("checkpoint debt must retain the original worker slot")
    };
    let attempt = session.cleanup.as_ref().unwrap();
    assert!(attempt.handle() == &original.handle
        && matches!(attempt.retained_reply(), TargetReply::Known { receipt, completion_pending: true }
            if receipt.handle() == &original.handle && receipt.state() == AuditOperationState::Rejected)
        && !attempt.rejected_cleanup_settled()
        && session.cleanup_successor.is_none(),
        "CLEANUP_ACCEPTED_REPLY_KNOWN_DEBT: authenticated recovery must preserve Rejected and its completion debt");

    fixture
        .checkpoint
        .unavailable
        .store(true, Ordering::Release);
    second.cleanup().await;
    let Slot::Owned(session) = &second.sessions.entries[0] else {
        panic!("checkpoint outage cannot release the original worker slot")
    };
    assert!(session.cleanup.as_ref().unwrap().handle() == &original.handle
        && matches!(session.cleanup.as_ref().unwrap().retained_reply(), TargetReply::Known { receipt, completion_pending: true }
            if receipt.state() == AuditOperationState::Rejected)
        && session.cleanup_successor.is_none(),
        "CLEANUP_ACCEPTED_REPLY_KNOWN_DEBT: later outage cannot erase Rejected or permit a successor");
    fixture
        .checkpoint
        .unavailable
        .store(false, Ordering::Release);

    // Permit the original terminal checkpoint (advance zero), then stop only
    // the successor's real Intent checkpoint (advance one). This exposes the
    // genuine successor retained by the same worker without granting its effect.
    fixture
        .checkpoint
        .advances_since_arm
        .store(0, Ordering::Release);
    fixture
        .checkpoint
        .fail_completion
        .store(true, Ordering::Release);
    second.cleanup().await;
    assert!(fixture.checkpoint.advances_since_arm.load(Ordering::Acquire) >= 2,
        "CLEANUP_ACCEPTED_REPLY_SETTLEMENT_ORDER: original checkpoint must succeed before the held successor checkpoint");
    exact_rejected(&fixture, &original, true).await;
    let Slot::Owned(session) = &second.sessions.entries[0] else {
        panic!("successor Intent checkpoint debt must remain worker-owned")
    };
    let next_handle = session.cleanup.as_ref().unwrap().handle().clone();
    let next_event = session.context.cleanup.clone();
    let next = fixture
        .store
        .retained_netconf_session_cleanup(
            &original.owner,
            fixture.caller,
            fixture.privacy.as_ref(),
            &super::super::event::convert_event(&next_event).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert!(next.handle() == &next_handle && next_handle != original.handle,
        "CLEANUP_ACCEPTED_REPLY_SUCCESSOR: only settled authentic rejection permits a distinct cleanup original");
    assert_eq!(
        expiry(&next),
        expiry(&original.prepared),
        "CLEANUP_ACCEPTED_REPLY_FIXED_EXPIRY"
    );
    let next = Original {
        handle: next_handle,
        prepared: next,
        owner: original.owner.clone(),
        event: next_event,
    };
    exact_intent(&fixture, &next).await;
    fixture
        .checkpoint
        .fail_completion
        .store(false, Ordering::Release);
    let exit = joined(second).await;
    let complete = settled(&fixture, &next).await;
    exact_rejected(&fixture, &original, true).await;
    fixture.close().await;
    assert!(exit == WorkerExit::Drained && complete,
        "CLEANUP_ACCEPTED_REPLY_RECOVERED_DRAIN: original rejection and successor cleanup must settle before the owned worker joins");
}

#[path = "cleanup_running_base_tests.rs"]
mod running_base;
