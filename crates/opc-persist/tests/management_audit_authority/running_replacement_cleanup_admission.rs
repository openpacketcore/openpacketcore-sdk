//! Cleanup retirement uses the real bounded Durable authority, destination pool
//! and native log. Holding SQLite apply changes timing, never the command result.

use super::*;
use crate::consensus::audit::AuditCommand;
use crate::consensus::audit_mutation::TargetAuditCommandV1;
use opc_consensus::engine::EntryPayload;

const PREPARATIONS: usize = 8;

fn cleanup_event(request: u8) -> ManagementAuditEventRecord {
    ManagementAuditEventRecord::try_new(
        [request; 16],
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

fn reserve(f: &Fixture, count: usize) -> Vec<opc_crypto::ConfigPreparationReservation> {
    (0..count)
        .map(|_| f.store.try_reserve_config_preparation().unwrap().unwrap())
        .collect()
}

async fn drain_native_owners(f: &Fixture) {
    let drained = tokio::time::timeout(
        WAIT,
        f.store
            .inner
            .proposal_admission
            .clone()
            .acquire_many_owned(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS as u32),
    )
    .await
    .expect("native accepted completion must drain")
    .unwrap();
    drop(drained);
}

async fn stale_cleanup(f: &Fixture) -> (NetconfSessionOwner, PreparedTargetMutation) {
    let first = f.session().await;
    let second = f.session().await;
    first.invalidate();
    second.invalidate();
    let first_original = f
        .store
        .prepare_netconf_session_cleanup(&first, &privacy(), &cleanup_event(201), LIFETIME)
        .await
        .unwrap();
    let second_original = f
        .store
        .prepare_netconf_session_cleanup(&second, &privacy(), &cleanup_event(202), LIFETIME)
        .await
        .unwrap();
    let intent = applied(
        f.store
            .admit_netconf_target_local(&first_original, caller())
            .await,
    );
    let receipt = applied(
        f.store
            .submit_netconf_target_local(&first_original, &intent, caller())
            .await,
    );
    f.settle(&receipt).await;
    assert!(matches!(
        f.store
            .admit_netconf_target_local(&second_original, caller())
            .await,
        AuditAdmission::Rejected(AuditAuthorityError::BindingMismatch)
    ));
    assert!(f
        .store
        .lookup_audit_operation(second_original.handle(), caller())
        .await
        .unwrap()
        .is_none());
    drain_native_owners(f).await;
    (second, second_original)
}

async fn settle_and_replay(
    f: &Fixture,
    session: &NetconfSessionOwner,
    original: &PreparedTargetMutation,
) {
    let receipt = applied(
        f.store
            .retire_netconf_session_cleanup_local(session, original, caller())
            .await,
    );
    assert_eq!(receipt.state(), AuditOperationState::Rejected);
    f.settle(&receipt).await;
    let known = f
        .store
        .lookup_audit_operation(original.handle(), caller())
        .await
        .unwrap()
        .unwrap();
    assert!(known.terminal_recorded());
    let checkpoint = f
        .checkpoint
        .load(f.store.inner.identity)
        .await
        .unwrap()
        .unwrap();
    assert!(checkpoint.sequence() >= known.sequence);
    let before_replay = f.rows().await;
    let replay = applied(
        f.store
            .retire_netconf_session_cleanup_local(session, original, caller())
            .await,
    );
    assert_eq!(replay, known, "retirement must preserve the exact original");
    assert_eq!(
        f.rows().await,
        before_replay,
        "replay cannot append new rows"
    );
    assert!(f.store.load_latest().await.unwrap().is_none());
    drain_native_owners(f).await;
}

#[tokio::test]
async fn bounded_cleanup_retirement_refuses_full_pool_before_ledger_read() {
    let f = fixture().await;
    let (session, original) = stale_cleanup(&f).await;
    let original_bytes = original.encode().unwrap();
    let held = reserve(&f, PREPARATIONS);
    let before_loads = f.checkpoint.loads.load(Ordering::Acquire);
    let decision = f
        .store
        .retire_netconf_session_cleanup_local(&session, &original, caller())
        .await;
    let no_ledger_read = f.checkpoint.loads.load(Ordering::Acquire) == before_loads;
    let refused_full_pool = matches!(
        decision,
        AuditAdmission::Rejected(AuditAuthorityError::Unavailable)
    );
    let no_original_intent = f
        .store
        .lookup_audit_operation(original.handle(), caller())
        .await
        .unwrap()
        .is_none();
    drop(held);
    // The identical original progresses when capacity returns. This also drains
    // a mutant that improperly retired it while the pool was full.
    settle_and_replay(&f, &session, &original).await;
    assert_eq!(original.encode().unwrap(), original_bytes);
    drop(reserve(&f, PREPARATIONS));
    f.close().await;
    eprintln!(
        "BOUNDED_CLEANUP_RETIREMENT_RESERVATION refused={refused_full_pool} \
         no_ledger_read={no_ledger_read} no_original_intent={no_original_intent} drained=true"
    );
    assert!(
        refused_full_pool && no_ledger_read && no_original_intent,
        "BOUNDED_CLEANUP_RETIREMENT_RESERVATION: full pool must refuse before read or Intent; actual={decision:?}"
    );
}

#[tokio::test]
async fn bounded_cleanup_retirement_keeps_slot_after_accepted_caller_cancellation() {
    let f = fixture().await;
    let (session, original) = stale_cleanup(&f).await;
    let original_bytes = original.encode().unwrap();
    let held = reserve(&f, PREPARATIONS - 1);
    let apply_gate = f
        .store
        .inner
        .backend
        .consensus_apply_gate
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    let mut metrics = f.store.inner.raft.metrics();
    let before_index = metrics.borrow().last_log_index.unwrap();
    let store = f.store.clone();
    let submitting_session = session.clone();
    let submitting_original = original.clone();
    let task = tokio::spawn(async move {
        store
            .retire_netconf_session_cleanup_local(
                &submitting_session,
                &submitting_original,
                caller(),
            )
            .await
    });
    let accepted_index = tokio::time::timeout(WAIT, async {
        loop {
            let index = metrics.borrow().last_log_index.unwrap();
            if index > before_index {
                break index;
            }
            metrics.changed().await.unwrap();
        }
    })
    .await
    .expect("retirement must reach native append before caller cancellation");
    let entries = {
        let connection = f.store.inner.backend.conn();
        let connection = connection.lock().await;
        crate::consensus::sqlite::read_log_range_sync(
            &connection,
            f.store.inner.identity,
            &BTreeSet::from([f.store.inner.local_node_id]),
            before_index + 1,
            Some(accepted_index + 1),
            None,
            RetainedConfigMode::NetconfRunningV1,
        )
        .unwrap()
    };
    assert!(
        entries.iter().any(|entry| {
            matches!(&entry.payload, EntryPayload::Normal(command)
            if matches!(&command.intent, ConfigMutationIntent::ManagementAudit(audit)
                if matches!(audit.as_ref(), AuditCommand::NetconfTarget(target)
                    if matches!(target.as_ref(), TargetAuditCommandV1::RetireCleanup(prepared)
                        if prepared == original.command()))))
        }),
        "the actual native log must contain this exact retirement"
    );
    drop(entries);
    assert!(!task.is_finished(), "native apply is still held");
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let retained_after_cancel = f.store.try_reserve_config_preparation().is_err();
    drop(apply_gate);
    drain_native_owners(&f).await;
    let returned = reserve(&f, 1);
    let exactly_one_returned = f.store.try_reserve_config_preparation().is_err();
    drop(returned);
    settle_and_replay(&f, &session, &original).await;
    assert_eq!(original.encode().unwrap(), original_bytes);
    drop(held);
    drop(reserve(&f, PREPARATIONS));
    f.close().await;
    eprintln!(
        "BOUNDED_CLEANUP_RETIREMENT_ACCEPTED_OWNERSHIP native_original=true \
         caller_cancelled=true retained={retained_after_cancel} \
         exactly_one_returned={exactly_one_returned} drained=true"
    );
    assert!(
        retained_after_cancel && exactly_one_returned,
        "BOUNDED_CLEANUP_RETIREMENT_ACCEPTED_OWNERSHIP: accepted work must retain its slot until native completion"
    );
}

#[tokio::test]
async fn bounded_cleanup_retirement_keeps_slot_in_cancelled_ledger_workers() {
    use crate::consensus::store::audit::target_recovery_worker_tests::{
        worker_drained, Point, Registration,
    };

    let f = fixture().await;
    let (session, original) = stale_cleanup(&f).await;
    let original_bytes = original.encode().unwrap();
    let before = f.rows().await;
    let held = reserve(&f, PREPARATIONS - 1);
    let mut observed = Vec::new();
    // Lookup, transactional retirement preflight, and the shared command
    // preflight each decode a real ledger before any native command is queued.
    for (ordinal, phase) in [(1, "lookup"), (2, "retirement"), (3, "command")] {
        let registration = Registration::nth(&f.store.inner.backend, Point::AfterDecode, ordinal);
        let store = f.store.clone();
        let submitting_session = session.clone();
        let submitting_original = original.clone();
        let task = tokio::spawn(async move {
            store
                .retire_netconf_session_cleanup_local(
                    &submitting_session,
                    &submitting_original,
                    caller(),
                )
                .await
        });
        registration.entered().await;
        assert!(
            registration.decoded(),
            "hold actual authenticated ledger bytes"
        );
        let owned_before_cancel = f.store.try_reserve_config_preparation().is_err();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let retained_after_cancel = f.store.try_reserve_config_preparation().is_err();
        registration.release();
        registration.drained().await;
        worker_drained(&f.store.inner.backend).await;
        let returned = reserve(&f, 1);
        let exactly_one_returned = f.store.try_reserve_config_preparation().is_err();
        drop(returned);
        assert!(f
            .store
            .lookup_audit_operation(original.handle(), caller())
            .await
            .unwrap()
            .is_none());
        assert_eq!(f.rows().await, before, "cancelled preflight has no effect");
        eprintln!(
            "BOUNDED_CLEANUP_RETIREMENT_WORKER_DRAINED phase={phase} \
             owned_before={owned_before_cancel} retained={retained_after_cancel} \
             exactly_one_returned={exactly_one_returned} drained=true"
        );
        observed.push((
            owned_before_cancel,
            retained_after_cancel,
            exactly_one_returned,
        ));
    }
    settle_and_replay(&f, &session, &original).await;
    assert_eq!(original.encode().unwrap(), original_bytes);
    drop(held);
    drop(reserve(&f, PREPARATIONS));
    f.close().await;
    assert!(
        observed.iter().all(|&(before, retained, returned)| before && retained && returned),
        "BOUNDED_CLEANUP_RETIREMENT_WORKER_OWNERSHIP: cancellation must retain the slot through every actual ledger worker and returned allocation"
    );
}

#[tokio::test]
async fn bounded_cleanup_checkpoint_keeps_slot_in_cancelled_ledger_worker() {
    use crate::consensus::store::audit::target_recovery_worker_tests::{
        worker_drained, Point, Registration,
    };

    let f = fixture().await;
    let (session, original) = stale_cleanup(&f).await;
    let receipt = applied(
        f.store
            .retire_netconf_session_cleanup_local(&session, &original, caller())
            .await,
    );
    assert_eq!(receipt.state(), AuditOperationState::Rejected);
    let terminal = applied(
        f.store
            .finish_audit_operation(original.handle(), caller())
            .await,
    );
    assert!(terminal.terminal_recorded());
    drain_native_owners(&f).await;
    let before = f.rows().await;
    let held = reserve(&f, PREPARATIONS - 1);
    // Public completion first replays the exact terminal through the shared
    // command preflight; its next ledger worker belongs to checkpointing.
    let registration = Registration::nth(&f.store.inner.backend, Point::AfterDecode, 2);
    let store = f.store.clone();
    let submitting_receipt = receipt.clone();
    let task = tokio::spawn(async move {
        store
            .complete_required_audit_outcome(&submitting_receipt, caller())
            .await
    });
    registration.entered().await;
    assert!(
        registration.decoded(),
        "hold actual checkpoint ledger bytes"
    );
    let owned_before_cancel = f.store.try_reserve_config_preparation().is_err();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let retained_after_cancel = f.store.try_reserve_config_preparation().is_err();
    registration.release();
    registration.drained().await;
    worker_drained(&f.store.inner.backend).await;
    let returned = reserve(&f, 1);
    let exactly_one_returned = f.store.try_reserve_config_preparation().is_err();
    drop(returned);
    assert_eq!(
        f.rows().await,
        before,
        "cancelled checkpoint read has no effect"
    );
    let ledger = f.store.read_audit_ledger().await.unwrap();
    let operation = ledger
        .operations
        .iter()
        .find(|operation| operation.handle == *original.handle())
        .unwrap();
    assert!(operation.terminal_recorded);
    assert!(ledger.mutation_outcome_needs_checkpoint(operation));
    drop(ledger);
    // With only one free slot, retry must cover both the decode and the native
    // checkpoint transition without a second simultaneous reservation.
    f.store
        .complete_required_audit_outcome(&receipt, caller())
        .await
        .unwrap();
    settle_and_replay(&f, &session, &original).await;
    drop(held);
    drop(reserve(&f, PREPARATIONS));
    f.close().await;
    eprintln!(
        "BOUNDED_CLEANUP_CHECKPOINT_WORKER_DRAINED owned_before={owned_before_cancel} \
         retained={retained_after_cancel} exactly_one_returned={exactly_one_returned} drained=true"
    );
    assert!(
        owned_before_cancel && retained_after_cancel && exactly_one_returned,
        "BOUNDED_CLEANUP_CHECKPOINT_WORKER_OWNERSHIP: public outcome completion must retain checkpoint decode ownership through cancellation"
    );
}
