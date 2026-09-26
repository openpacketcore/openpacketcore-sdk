//! Lock leases are authenticated SDK capabilities retained by the one worker.

use super::{
    native_fixture::Fixture, NetconfLockDatastore, NetconfMutationResult, NetconfWorkerExit,
};
use futures_util::poll;
use opc_config_model::{RequestId, TransportType, TrustedPrincipal, WorkloadIdentity};
use opc_mgmt_audit::{AuditEvent, AuditOperation, AuditOutcome};
use opc_persist::audit_authority::AuditAuthorityError;
use std::{sync::atomic::Ordering, time::Duration};

fn principal(name: &str) -> TrustedPrincipal {
    TrustedPrincipal::new(
        WorkloadIdentity::User(name.into()),
        opc_types::TenantId::from_static("synthetic-lock"),
    )
}

fn intent(actor: &TrustedPrincipal) -> AuditEvent {
    AuditEvent::new(
        RequestId::new(),
        actor,
        TransportType::NetconfTls,
        AuditOperation::Exec,
        AuditOutcome::Intent,
    )
}

fn assert_ready(result: NetconfMutationResult) {
    let NetconfMutationResult::Applied(receipt) = result else {
        panic!("expected authenticated applied lock transition")
    };
    assert!(!receipt.completion_pending());
    assert!(receipt.terminal_recorded());
    assert!(
        receipt.lock_ready(),
        "typed lease publication must precede acknowledgement"
    );
}

async fn assert_available(fixture: &Fixture, actor: &TrustedPrincipal, available: bool) {
    let owner = fixture.port.open_session(actor).await.unwrap();
    let result = fixture
        .port
        .prepare_lock(&owner, actor, &intent(actor), NetconfLockDatastore::Running)
        .await;
    owner.invalidate();
    if available {
        assert!(
            result.is_ok(),
            "retained authority must permit a new owner after release"
        );
    } else {
        assert!(
            matches!(result, Err(AuditAuthorityError::BindingMismatch)),
            "retained authority must report the held lock"
        );
    }
}

#[tokio::test]
async fn native_lost_lock_and_unlock_replies_preserve_typed_lease_and_original() {
    let actor = principal("owner");
    let fixture = Fixture::new(&actor).await;
    let bus = fixture.bus(4);
    let audit = bus.required_netconf_audit().unwrap();
    let owner = audit.open_session(&actor).await.unwrap();
    let other = audit.open_session(&actor).await.unwrap();
    let alien = principal("other-principal");
    let alien_session = audit.open_session(&alien).await.unwrap();
    let foreign_bus = fixture.bus(1);
    let foreign = foreign_bus.required_netconf_audit().unwrap();
    assert!(
        matches!(
            audit
                .acquire_lock(
                    &owner,
                    &actor,
                    intent(&alien),
                    NetconfLockDatastore::Running
                )
                .await
                .unwrap(),
            NetconfMutationResult::Refused(_)
        ),
        "an audit event cannot substitute its own authenticated principal"
    );

    // Drop each reply waiter while the actual worker is paused. It must retain
    // both the original operation and its typed acquire/release preparation.
    for release in [false, true] {
        let event = intent(&actor);
        let request = event.request_id;
        fixture.checkpoint.pause.store(true, Ordering::Release);
        let mut waiting = Box::pin(async {
            if release {
                audit
                    .release_lock(&owner, &actor, event, NetconfLockDatastore::Running)
                    .await
            } else {
                audit
                    .acquire_lock(&owner, &actor, event, NetconfLockDatastore::Running)
                    .await
            }
        });
        assert!(poll!(waiting.as_mut()).is_pending());
        tokio::time::timeout(
            Duration::from_secs(10),
            fixture.checkpoint.entered.notified(),
        )
        .await
        .unwrap();
        drop(waiting);
        fixture.checkpoint.release.notify_one();
        let recovered = audit
            .recover_request(request, &actor)
            .await
            .unwrap()
            .unwrap();
        assert_ready(recovered);
        assert!(audit
            .recover_request(request, &alien)
            .await
            .unwrap()
            .is_none());
        assert_available(&fixture, &actor, release).await;

        if !release {
            for (session, caller) in [(&other, &actor), (&alien_session, &alien), (&owner, &alien)]
            {
                assert!(matches!(
                    audit
                        .release_lock(
                            session,
                            caller,
                            intent(caller),
                            NetconfLockDatastore::Running
                        )
                        .await
                        .unwrap(),
                    NetconfMutationResult::Refused(_)
                ));
            }
            assert!(foreign
                .release_lock(
                    &owner,
                    &actor,
                    intent(&actor),
                    NetconfLockDatastore::Running
                )
                .await
                .is_err());
            assert!(foreign
                .acquire_lock(
                    &owner,
                    &actor,
                    intent(&actor),
                    NetconfLockDatastore::Running
                )
                .await
                .is_err());
            assert!(matches!(
                audit
                    .acquire_lock(
                        &other,
                        &actor,
                        intent(&actor),
                        NetconfLockDatastore::Running
                    )
                    .await
                    .unwrap(),
                NetconfMutationResult::Refused(_)
            ));
            assert_available(&fixture, &actor, false).await;
        }
    }
    assert_ready(
        audit
            .acquire_lock(
                &other,
                &actor,
                intent(&actor),
                NetconfLockDatastore::Running,
            )
            .await
            .unwrap(),
    );
    assert_ready(
        audit
            .release_lock(
                &other,
                &actor,
                intent(&actor),
                NetconfLockDatastore::Running,
            )
            .await
            .unwrap(),
    );
    drop((owner, other, alien_session));
    assert_eq!(audit.shutdown().await, Ok(NetconfWorkerExit::Drained));
    assert_eq!(foreign.shutdown().await, Ok(NetconfWorkerExit::Drained));
    drop((audit, foreign, bus, foreign_bus));
    fixture.close().await;
}

#[tokio::test]
async fn native_lock_completion_outage_preserves_known_original_without_ready_lease() {
    let actor = principal("owner");
    let fixture = Fixture::new(&actor).await;
    let bus = fixture.bus(2);
    let audit = bus.required_netconf_audit().unwrap();
    let owner = audit.open_session(&actor).await.unwrap();
    for release in [false, true] {
        fixture
            .checkpoint
            .advances_since_arm
            .store(0, Ordering::Release);
        fixture
            .checkpoint
            .fail_completion
            .store(true, Ordering::Release);
        let event = intent(&actor);
        let request = event.request_id;
        let result = if release {
            audit
                .release_lock(&owner, &actor, event, NetconfLockDatastore::Running)
                .await
        } else {
            audit
                .acquire_lock(&owner, &actor, event, NetconfLockDatastore::Running)
                .await
        }
        .unwrap();
        let NetconfMutationResult::Applied(receipt) = result else {
            panic!("fault must occur after the known effect")
        };
        assert!(receipt.completion_pending());
        assert!(!receipt.lock_ready());
        let handle = receipt.recovery_handle().clone();
        assert!(matches!(
            audit
                .acquire_lock(
                    &owner,
                    &actor,
                    intent(&actor),
                    NetconfLockDatastore::Running
                )
                .await
                .unwrap(),
            NetconfMutationResult::Refused(_)
        ));
        fixture
            .checkpoint
            .fail_completion
            .store(false, Ordering::Release);
        let recovered = audit.recover(&handle, &actor).await;
        assert_ready(recovered);
        assert_ready(
            audit
                .recover_request(request, &actor)
                .await
                .unwrap()
                .unwrap(),
        );
        assert_available(&fixture, &actor, release).await;
    }
    drop(owner);
    assert_eq!(audit.shutdown().await, Ok(NetconfWorkerExit::Drained));
    drop((audit, bus));
    fixture.close().await;
}
