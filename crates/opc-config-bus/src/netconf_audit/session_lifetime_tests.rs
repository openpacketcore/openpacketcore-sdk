//! Focused session component and single-member worker detectors.
//!
//! Local detectors cover slots and Tokio cancellation/join. Native detectors
//! use a real retained authority, device and independent checkpoint through
//! the existing bounded ConfigBus worker. They never mint mock owners or
//! invent authority receipts. The actual NETCONF runner has a separate test.

use std::{future::pending, num::NonZeroUsize, time::Duration};

use futures_util::{poll, FutureExt};
use opc_config_model::{TrustedPrincipal, WorkloadIdentity};
use opc_persist::{
    audit_authority::{AuditAuthorityError, AuditCaller, NetconfDeviceOwner},
    ConsensusConfigStore,
};
use opc_types::TenantId;
use tokio::sync::oneshot;

use super::{
    session_lifetime::{OwnedSessionLifetime, SessionWake},
    session_registry::{SessionOpenError, SessionRegistry},
    worker_join::{WorkerExit, WorkerJoin, WorkerLost},
};

fn principal() -> TrustedPrincipal {
    TrustedPrincipal::new(
        WorkloadIdentity::User("synthetic-session".into()),
        TenantId::from_static("synthetic-session"),
    )
}

#[tokio::test]
async fn cancellation_before_mint_releases_only_the_reserved_slot() {
    let mut registry = SessionRegistry::new(NonZeroUsize::new(1).unwrap(), SessionWake::new());
    let mut opening = Box::pin(async {
        let _reservation = registry.reserve(principal()).unwrap();
        // This is the cancellation point of an uncompleted authority open.
        // No SDK token or effect has been returned to the worker here.
        pending::<()>().await;
    });
    assert!(poll!(opening.as_mut()).is_pending());
    drop(opening);
    assert!(registry.is_empty());
    let reservation = registry.reserve(principal()).unwrap();
    drop(reservation);
    assert!(registry.is_empty());
}

#[test]
fn draining_refuses_open_without_claiming_a_new_session() {
    let mut registry = SessionRegistry::new(NonZeroUsize::new(1).unwrap(), SessionWake::new());
    registry.begin_drain();
    assert!(matches!(
        registry.reserve(principal()),
        Err(SessionOpenError::Draining)
    ));
    assert!(registry.is_empty());
}

#[tokio::test]
async fn cancelled_join_waiter_leaves_the_actual_worker_joinable() {
    let (release, ready) = oneshot::channel();
    let task = tokio::spawn(async move {
        ready.await.unwrap();
        WorkerExit::Drained
    });
    let join = WorkerJoin::new(task);
    let mut waiting = Box::pin(join.join());
    assert!(poll!(waiting.as_mut()).is_pending());
    drop(waiting);
    // If the join future consumed and then lost the handle, the second join
    // cannot observe the real worker result. No sleeps or timing races needed.
    release.send(()).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), join.join())
        .await
        .unwrap();
    assert_eq!(result, Ok(WorkerExit::Drained));
    assert_eq!(join.clone().join().await, result);
}

#[tokio::test]
async fn recovery_required_exit_is_not_reported_as_drained() {
    let task = tokio::spawn(async { WorkerExit::RecoveryRequired });
    let join = WorkerJoin::new(task);
    assert_eq!(join.join().await, Ok(WorkerExit::RecoveryRequired));
    assert_eq!(join.join().await, Ok(WorkerExit::RecoveryRequired));
}

#[tokio::test]
async fn worker_loss_is_not_a_completed_drain() {
    let task = tokio::spawn(pending::<WorkerExit>());
    let abort = task.abort_handle();
    let join = WorkerJoin::new(task);
    abort.abort();
    assert_eq!(join.join().await, Err(WorkerLost));
    assert_eq!(join.join().await, Err(WorkerLost));
}

/// Caller/device must be independently provisioned by the real fixture. This
/// tests actual SDK clone invalidation and a Notify permit latched before poll.
pub(super) async fn assert_final_transport_drop_revokes_sdk_owner(
    store: &ConsensusConfigStore,
    device: &NetconfDeviceOwner,
    caller: AuditCaller,
) {
    let owner = store.open_netconf_session(device, caller).await.unwrap();
    let wake = SessionWake::new();
    let (owned, transport) = OwnedSessionLifetime::new(owner.clone(), &wake);
    let queued_reference = transport.reference();
    let last_transport = transport.clone();
    assert!(owned.owns(&last_transport));
    assert!(!last_transport.belongs_to(&SessionWake::new()));
    drop(transport);
    assert!(!owned.is_revoked());
    store
        .verify_netconf_session_owner(&owner, caller)
        .await
        .unwrap();

    drop(last_transport);
    // `owned` and `owner` remain alive. Neither suppresses final transport drop.
    assert!(owned.is_revoked());
    assert!(owned.owns_reference(&queued_reference));
    assert!(wake.notified().now_or_never().is_some());
    assert!(matches!(
        store.verify_netconf_session_owner(&owner, caller).await,
        Err(AuditAuthorityError::BindingMismatch)
    ));
    owned.revoke();
    assert!(wake.notified().now_or_never().is_none());
}

/// Both a failed send and a successfully queued reply lost before receipt must
/// retain the worker owner, original cleanup request and bounded cleanup debt.
pub(super) async fn assert_lost_opening_replies_revoke_without_eviction(
    store: &ConsensusConfigStore,
    device: &NetconfDeviceOwner,
    caller: AuditCaller,
    principal: TrustedPrincipal,
) {
    for lose_before_send in [true, false] {
        let owner = store.open_netconf_session(device, caller).await.unwrap();
        let wake = SessionWake::new();
        let mut registry = SessionRegistry::new(NonZeroUsize::new(1).unwrap(), wake.clone());
        let reservation = registry.reserve(principal.clone()).unwrap();
        let (reply, receiver) = oneshot::channel();
        if lose_before_send {
            drop(receiver);
            reservation.publish(owner.clone(), reply);
        } else {
            reservation.publish(owner.clone(), reply);
            drop(receiver);
        }
        assert!(registry.has_revoked());
        assert!(!registry.is_empty());
        let cleanup_request = registry
            .revoked()
            .next()
            .unwrap()
            .cleanup_event()
            .request_id;
        assert!(wake.notified().now_or_never().is_some());
        assert!(matches!(
            registry.reserve(principal.clone()),
            Err(SessionOpenError::Full)
        ));
        assert_eq!(
            registry
                .revoked()
                .next()
                .unwrap()
                .cleanup_event()
                .request_id,
            cleanup_request
        );
        assert!(matches!(
            store.verify_netconf_session_owner(&owner, caller).await,
            Err(AuditAuthorityError::BindingMismatch)
        ));
    }
}

/// Draining and losing the owning worker both revoke a remaining transport
/// clone; neither is evidence that retained cleanup or rollback completed.
pub(super) async fn assert_drain_and_worker_loss_revoke_live_transports(
    store: &ConsensusConfigStore,
    device: &NetconfDeviceOwner,
    caller: AuditCaller,
    principal: TrustedPrincipal,
) {
    let wake = SessionWake::new();
    let mut registry = SessionRegistry::new(NonZeroUsize::new(1).unwrap(), wake.clone());
    let owner = store.open_netconf_session(device, caller).await.unwrap();
    let (reply, receiver) = oneshot::channel();
    registry
        .reserve(principal.clone())
        .unwrap()
        .publish(owner.clone(), reply);
    let transport = receiver.await.unwrap().unwrap();
    let reference = transport.reference();
    assert!(registry.session(&reference).is_some());
    registry.begin_drain();
    assert!(registry.session(&reference).is_none());
    assert!(registry.has_revoked());
    assert!(!registry.is_empty());
    assert!(matches!(
        registry.reserve(principal),
        Err(SessionOpenError::Draining)
    ));
    assert!(matches!(
        store.verify_netconf_session_owner(&owner, caller).await,
        Err(AuditAuthorityError::BindingMismatch)
    ));
    drop(transport);

    let owner = store.open_netconf_session(device, caller).await.unwrap();
    let wake = SessionWake::new();
    let (owned, transport) = OwnedSessionLifetime::new(owner.clone(), &wake);
    drop(owned);
    assert!(wake.notified().now_or_never().is_some());
    assert!(transport.belongs_to(&wake));
    assert!(matches!(
        store.verify_netconf_session_owner(&owner, caller).await,
        Err(AuditAuthorityError::BindingMismatch)
    ));
    drop(transport);
}

#[tokio::test]
async fn native_revocation_refuses_new_intent_and_preserves_admitted_original_without_effect() {
    use std::sync::atomic::Ordering;

    let principal = principal();
    let fixture = super::native_fixture::Fixture::new(&principal).await;
    let wake = SessionWake::new();
    let event = || {
        opc_mgmt_audit::AuditEvent::new(
            opc_config_model::RequestId::new(),
            &principal,
            opc_config_model::TransportType::NetconfTls,
            opc_mgmt_audit::AuditOperation::Exec,
            opc_mgmt_audit::AuditOutcome::Intent,
        )
    };

    let owner = fixture.port.open_session(&principal).await.unwrap();
    let (owned, transport) = OwnedSessionLifetime::new(owner, &wake);
    let mut original = fixture
        .port
        .prepare_lock(
            owned.owner(),
            &principal,
            &event(),
            opc_persist::audit_authority::NetconfLockDatastore::Running,
        )
        .await
        .unwrap();
    original.bind_session(transport.reference());
    drop(transport);
    let loads = fixture.checkpoint.loads.load(Ordering::Acquire);
    assert!(matches!(
        fixture.port.execute_target(&mut original).await,
        super::store::TargetReply::Refused(AuditAuthorityError::BindingMismatch)
    ));
    assert_eq!(
        fixture.checkpoint.loads.load(Ordering::Acquire),
        loads,
        "revocation before admission must not poll a new SDK Intent"
    );
    drop(owned);

    let owner = fixture.port.open_session(&principal).await.unwrap();
    let (owned, transport) = OwnedSessionLifetime::new(owner, &wake);
    let mut original = fixture
        .port
        .prepare_lock(
            owned.owner(),
            &principal,
            &event(),
            opc_persist::audit_authority::NetconfLockDatastore::Running,
        )
        .await
        .unwrap();
    original.bind_session(transport.reference());
    let handle = original.handle().clone();
    fixture.checkpoint.pause.store(true, Ordering::Release);
    let mut executing = Box::pin(fixture.port.execute_target(&mut original));
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            _ = fixture.checkpoint.entered.notified() => {},
            _ = &mut executing => panic!("Intent admission must stop at the checkpoint boundary"),
        }
    })
    .await
    .unwrap();
    drop(transport);
    fixture.checkpoint.release.notify_one();
    assert!(
        matches!(executing.await, super::store::TargetReply::Unknown),
        "revocation during Intent admission must refuse effect submission"
    );
    let receipt = fixture
        .store
        .lookup_audit_operation(&handle, fixture.caller)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        receipt.state(),
        opc_persist::audit_authority::AuditOperationState::Intent
    ));
    assert!(matches!(
        fixture.port.recover_target(&mut original).await,
        super::store::TargetReply::Unknown
    ));
    assert_eq!(original.handle(), &handle);
    assert!(fixture.port.verify_current().await.is_err());
    drop(owned);
    fixture.close().await;
}

#[tokio::test]
async fn native_session_owner_loss_retains_cleanup_and_retires_only_after_checkpoint() {
    let fixture = super::native_fixture::Fixture::new(&principal()).await;
    assert_final_transport_drop_revokes_sdk_owner(&fixture.store, &fixture.device, fixture.caller)
        .await;
    assert_lost_opening_replies_revoke_without_eviction(
        &fixture.store,
        &fixture.device,
        fixture.caller,
        principal(),
    )
    .await;
    assert_drain_and_worker_loss_revoke_live_transports(
        &fixture.store,
        &fixture.device,
        fixture.caller,
        principal(),
    )
    .await;

    let mut worker = super::worker::TargetWorker::new(
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
    let reference = transport.reference();
    let before_full_open = fixture
        .checkpoint
        .loads
        .load(std::sync::atomic::Ordering::Acquire);
    let (full_reply, full_receiver) = oneshot::channel();
    worker
        .sessions
        .open_in_worker(&fixture.port, principal(), full_reply)
        .await;
    assert!(matches!(
        full_receiver.await.unwrap(),
        Err(SessionOpenError::Full)
    ));
    assert_eq!(
        fixture
            .checkpoint
            .loads
            .load(std::sync::atomic::Ordering::Acquire),
        before_full_open,
        "a full registry must refuse before polling the SDK open boundary"
    );
    let event = opc_mgmt_audit::AuditEvent::new(
        opc_config_model::RequestId::new(),
        &principal(),
        opc_config_model::TransportType::NetconfTls,
        opc_mgmt_audit::AuditOperation::Exec,
        opc_mgmt_audit::AuditOutcome::Intent,
    );
    let mut another_worker = super::worker::TargetWorker::new(
        fixture.port.clone(),
        NonZeroUsize::new(1).unwrap(),
        SessionWake::new(),
    );
    assert!(another_worker
        .acquire_lock(
            &reference,
            &principal(),
            &event,
            opc_persist::audit_authority::NetconfLockDatastore::Running
        )
        .await
        .is_err());
    let mut foreign = principal();
    foreign.tenant = TenantId::from_static("synthetic-foreign");
    assert!(worker
        .acquire_lock(
            &reference,
            &foreign,
            &event,
            opc_persist::audit_authority::NetconfLockDatastore::Running
        )
        .await
        .is_err());
    let original = worker
        .acquire_lock(
            &reference,
            &principal(),
            &event,
            opc_persist::audit_authority::NetconfLockDatastore::Running,
        )
        .await
        .ok()
        .unwrap();
    assert!(matches!(
        super::result::from_original(original),
        super::NetconfMutationResult::Applied(_)
    ));
    drop(transport);
    let event = opc_mgmt_audit::AuditEvent::new(
        opc_config_model::RequestId::new(),
        &principal(),
        opc_config_model::TransportType::NetconfTls,
        opc_mgmt_audit::AuditOperation::Exec,
        opc_mgmt_audit::AuditOutcome::Intent,
    );
    assert!(worker
        .acquire_lock(
            &reference,
            &principal(),
            &event,
            opc_persist::audit_authority::NetconfLockDatastore::Candidate
        )
        .await
        .is_err());
    fixture
        .checkpoint
        .unavailable
        .store(true, std::sync::atomic::Ordering::Release);
    assert_eq!(worker.finish_drain().await, WorkerExit::RecoveryRequired);
    assert!(!worker.sessions.is_empty());
    fixture
        .checkpoint
        .unavailable
        .store(false, std::sync::atomic::Ordering::Release);
    fixture
        .checkpoint
        .fail_completion
        .store(true, std::sync::atomic::Ordering::Release);
    assert_eq!(worker.finish_drain().await, WorkerExit::RecoveryRequired);
    assert!(
        !worker.sessions.is_empty(),
        "known cleanup with owed checkpoint must retain its slot"
    );
    assert!(
        matches!(worker.sessions.revoked().next().unwrap().cleanup_attempt().unwrap().retained_reply(),
        super::store::TargetReply::Known { receipt, completion_pending: true }
            if matches!(receipt.state(), opc_persist::audit_authority::AuditOperationState::TargetV1(_))),
        "the injected outage must occur after authenticated cleanup application"
    );
    fixture
        .checkpoint
        .fail_completion
        .store(false, std::sync::atomic::Ordering::Release);
    assert_eq!(worker.finish_drain().await, WorkerExit::Drained);
    assert!(worker.sessions.is_empty());
    let successor_session = fixture.port.open_session(&principal()).await.unwrap();
    assert!(
        fixture
            .port
            .prepare_lock(
                &successor_session,
                &principal(),
                &event,
                opc_persist::audit_authority::NetconfLockDatastore::Running
            )
            .await
            .is_ok(),
        "authenticated EndSession must release the retained lock, not just the local slot"
    );
    successor_session.invalidate();
    fixture.close().await;
}

#[tokio::test]
async fn native_cancelled_open_and_shutdown_waiters_leave_existing_worker_owned() {
    use std::sync::atomic::Ordering;
    let fixture = super::native_fixture::Fixture::new(&principal()).await;
    let bus = fixture.bus(1);
    let audit = bus.required_netconf_audit().unwrap();
    fixture.checkpoint.pause.store(true, Ordering::Release);
    let principal = principal();
    let mut opening = Box::pin(audit.open_session(&principal));
    assert!(poll!(opening.as_mut()).is_pending());
    tokio::time::timeout(
        Duration::from_secs(10),
        fixture.checkpoint.entered.notified(),
    )
    .await
    .unwrap();
    drop(opening);
    fixture.checkpoint.release.notify_one();
    // The next message runs after the cancelled opening. Its lost delivery must
    // revoke and clean up the installed slot before the next open can succeed.
    let transport = tokio::time::timeout(Duration::from_secs(10), audit.open_session(&principal))
        .await
        .unwrap()
        .unwrap();
    fixture.checkpoint.pause.store(true, Ordering::Release);
    let mut joining = Box::pin(audit.shutdown());
    assert!(poll!(joining.as_mut()).is_pending());
    tokio::time::timeout(
        Duration::from_secs(10),
        fixture.checkpoint.entered.notified(),
    )
    .await
    .unwrap();
    drop(joining);
    fixture.checkpoint.release.notify_one();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), audit.shutdown())
            .await
            .unwrap(),
        Ok(WorkerExit::Drained)
    );
    assert_eq!(audit.shutdown().await, Ok(WorkerExit::Drained));
    assert!(audit.open_session(&principal).await.is_err());
    drop(transport);
    drop(audit);
    drop(bus);
    fixture.close().await;
}

#[tokio::test]
async fn native_lost_effect_reply_retains_original_and_full_queue_cannot_block_drain() {
    use opc_config_model::{RequestId, TransportType};
    use opc_mgmt_audit::{AuditEvent, AuditOperation, AuditOutcome};
    use opc_persist::audit_authority::NetconfLockDatastore;
    use std::sync::atomic::Ordering;
    let fixture = super::native_fixture::Fixture::new(&principal()).await;
    let bus = fixture.bus(1);
    let audit = bus.required_netconf_audit().unwrap();
    let actor = principal();
    let transport = audit.open_session(&actor).await.unwrap();
    let request = RequestId::new();
    let event = AuditEvent::new(
        request,
        &actor,
        TransportType::NetconfTls,
        AuditOperation::Exec,
        AuditOutcome::Intent,
    );
    fixture.checkpoint.pause.store(true, Ordering::Release);
    let mut effect =
        Box::pin(audit.acquire_lock(&transport, &actor, event, NetconfLockDatastore::Running));
    assert!(poll!(effect.as_mut()).is_pending());
    tokio::time::timeout(
        Duration::from_secs(10),
        fixture.checkpoint.entered.notified(),
    )
    .await
    .unwrap();
    drop(effect);
    fixture.checkpoint.release.notify_one();
    let recovered = audit
        .recover_request(request, &actor)
        .await
        .unwrap()
        .unwrap();
    let super::NetconfMutationResult::Applied(receipt) = recovered else {
        panic!("lost RPC reply must preserve original applied result")
    };
    assert!(!receipt.completion_pending());
    let handle = receipt.recovery_handle().clone();
    let recovered = audit.recover(&handle, &actor).await;
    assert!(
        matches!(recovered, super::NetconfMutationResult::Applied(receipt) if receipt.recovery_handle() == &handle)
    );

    fixture.checkpoint.pause.store(true, Ordering::Release);
    let event = AuditEvent::new(
        RequestId::new(),
        &actor,
        TransportType::NetconfTls,
        AuditOperation::Exec,
        AuditOutcome::Intent,
    );
    let mut effect =
        Box::pin(audit.acquire_lock(&transport, &actor, event, NetconfLockDatastore::Candidate));
    assert!(poll!(effect.as_mut()).is_pending());
    tokio::time::timeout(
        Duration::from_secs(10),
        fixture.checkpoint.entered.notified(),
    )
    .await
    .unwrap();
    let mut queued = Box::pin(audit.open_session(&actor));
    assert!(poll!(queued.as_mut()).is_pending());
    assert!(
        audit.open_session(&actor).await.is_err(),
        "existing commit channel is full"
    );
    let mut join = Box::pin(audit.shutdown());
    assert!(poll!(join.as_mut()).is_pending());
    drop(join);
    fixture.checkpoint.release.notify_one();
    assert!(matches!(
        effect.await.unwrap(),
        super::NetconfMutationResult::Applied(_)
    ));
    assert!(
        queued.await.is_err(),
        "drain must refuse a queued unopened session"
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), audit.shutdown())
            .await
            .unwrap(),
        Ok(WorkerExit::Drained)
    );
    drop(transport);
    drop(audit);
    drop(bus);
    fixture.close().await;
}
