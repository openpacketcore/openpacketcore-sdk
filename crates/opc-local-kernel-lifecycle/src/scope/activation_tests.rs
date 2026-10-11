use super::activation::{TestFault, TestPause};
use super::*;
use crate::native_quorum::{child_key, execution, Quorum};
use crate::ScopeKernelAuthority;
use opc_linux_gtpu_sys::tc::{ContainmentBank, LocalHookSpec, TcSlot};
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

// These opening tests own an empty private SAD/SPD. Real backends and complete
// data graphs are exercised by the GTP-U combined native fixture.
struct EmptyXfrm(LocalKernelScope);
#[async_trait]
impl LocalXfrmReset for EmptyXfrm {
    fn local_scope(&self) -> &LocalKernelScope {
        &self.0
    }
    async fn is_empty(&self) -> Result<bool, Error> {
        self.0.verify()?;
        for table in ["state", "policy"] {
            let output = std::process::Command::new("ip")
                .args(["xfrm", table, "list"])
                .output()
                .map_err(|_| Error::Indeterminate)?;
            if !output.status.success() || !output.stdout.is_empty() {
                return Ok(false);
            }
        }
        Ok(true)
    }
    async fn reset_contained(&self, contained: &ContainedScope) -> Result<(), Error> {
        contained.recheck()?;
        if self.is_empty().await? {
            Ok(())
        } else {
            Err(Error::Indeterminate)
        }
    }
}
struct Cleanup(std::path::PathBuf, std::path::PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}
fn count(scope: &LocalKernelScope) -> usize {
    scope
        .inventory()
        .unwrap()
        .iter()
        .flat_map(|dump| dump.entries())
        .filter(|entry| !entry.is_summary())
        .count()
}
async fn online(quorum: &Quorum) {
    quorum.set_available(true);
    while quorum
        .authority
        .current(execution().identity())
        .await
        .is_err()
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
async fn settled(lifecycle: &LocalKernelLifecycle) {
    while !lifecycle.cleanup_progress().unwrap().is_empty() {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
#[test]
#[ignore = "requires private network/mount namespaces, bpffs and CAP_NET_ADMIN"]
fn native_opening_owns_interrupted_filter_removal_and_publication() {
    assert_eq!(std::env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let root = std::path::PathBuf::from(format!("/sys/fs/bpf/opc-open-{}", std::process::id()));
    let locks = std::env::temp_dir().join(format!("opc-open-{}", std::process::id()));
    let _cleanup = Cleanup(root.clone(), locks.clone());
    for path in [&root, &locks] {
        std::fs::create_dir(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    assert!(std::process::Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status()
        .unwrap()
        .success());
    let ifindex = opc_linux_gtpu_sys::ifindex_by_name("lo").unwrap();
    let hooks = [TcHook::Ingress, TcHook::Egress]
        .map(|hook| {
            let slot =
                |priority, protocol| TcSlot::new(ifindex, hook, 0, protocol, priority, 1).unwrap();
            LocalHookSpec::new(
                ContainmentBank::new(slot(1, 0x806), slot(2, 3)).unwrap(),
                ContainmentBank::new(slot(3, 0x806), slot(4, 3)).unwrap(),
            )
            .unwrap()
        })
        .to_vec();
    let scope = LocalKernelScope::open(
        LocalScopeSpec::new(root, locks.join("guard"), [83; 16], hooks, vec![]).unwrap(),
    )
    .unwrap();
    let lifecycle =
        LocalKernelLifecycle::new(scope.clone(), vec![], vec![], vec![ifindex]).unwrap();
    let participants = || {
        LocalResetParticipants::new(
            Arc::new(EmptyXfrm(scope.clone())),
            Arc::new(opc_route_steering::LinuxRouteSteeringBackend::new()),
            Arc::new(NoLocalCompanions::new(scope.clone())),
        )
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let quorum = Quorum::open().await;
            lifecycle.reset(participants()).await.unwrap();
            let authority = ScopeKernelAuthority::new(
                lifecycle.clone(),
                execution(),
                quorum.committed.clone(),
                quorum.authority.clone(),
                quorum.batches.clone(),
            )
            .await
            .unwrap();
            // Resolve a genuinely lost committed response before local opening.
            let request = quorum.create_request(89).await;
            quorum.lose_next_commit_reply();
            assert!(authority
                .commit_activation(request.clone(), child_key(89))
                .await
                .is_err());
            assert!(quorum.lost_commit_reply());
            online(&quorum).await;
            authority
                .commit_activation(request, child_key(89))
                .await
                .unwrap();

            for step in 1..=4 {
                let reset = lifecycle.reset(participants()).await.unwrap();
                assert_eq!(count(&scope), 4);
                let id = 90 + step as u8;
                let effect = authority
                    .commit_activation(quorum.create_request(id).await, child_key(id))
                    .await
                    .unwrap();
                *lifecycle.inner.open_fault.lock().unwrap() = Some(TestFault::LostAck(step));
                assert!(lifecycle.open(&reset, effect).await.is_err());
                reset.contained.recheck().unwrap();
                assert_eq!(
                    count(&scope),
                    4,
                    "lost acknowledgement requires verified closure before a terminal error"
                );
            }
            let reset = lifecycle.reset(participants()).await.unwrap();
            let expired = authority
                .commit_activation(quorum.create_request(104).await, child_key(104))
                .await
                .unwrap();
            *lifecycle.inner.open_fault.lock().unwrap() =
                Some(TestFault::AttemptExpiredAfterDelete);
            assert_eq!(
                lifecycle.open(&reset, expired).await.unwrap_err(),
                Error::OpeningAttemptExpired
            );
            reset.contained.recheck().unwrap();
            assert_eq!(
                count(&scope),
                4,
                "a terminal budget failure must have re-contained every hook"
            );
            settled(&lifecycle).await;

            let reset = lifecycle.reset(participants()).await.unwrap();
            let effect = authority
                .commit_activation(quorum.create_request(95).await, child_key(95))
                .await
                .unwrap();
            *lifecycle.inner.open_fault.lock().unwrap() = Some(TestFault::PanicAfterDelete(3));
            assert!(lifecycle.open(&reset, effect).await.is_err());
            reset.contained.recheck().unwrap();

            for cancel in [false, true] {
                let reset = lifecycle.reset(participants()).await.unwrap();
                let id = if cancel { 97 } else { 96 };
                let effect = authority
                    .commit_activation(quorum.create_request(id).await, child_key(id))
                    .await
                    .unwrap();
                let pause = Arc::new(TestPause::default());
                *lifecycle.inner.open_fault.lock().unwrap() = Some(if cancel {
                    TestFault::PauseAfterDelete(pause.clone())
                } else {
                    TestFault::LostAckHoldClosure(pause.clone())
                });
                let (owner, receipt) = (lifecycle.clone(), reset.clone());
                let operation = tokio::spawn(async move { owner.open(&receipt, effect).await });
                pause.entered.notified().await;
                assert_eq!(
                    count(&scope),
                    3,
                    "the interruption follows a real filter deletion"
                );
                assert!(!operation.is_finished());
                assert!(
                    lifecycle.inner.barrier.try_write().is_err(),
                    "unresolved closure retains the reset barrier"
                );
                quorum.set_available(false);
                if cancel {
                    operation.abort();
                    assert!(operation.await.unwrap_err().is_cancelled());
                    pause.resume();
                } else {
                    pause.resume();
                    assert!(operation.await.unwrap().is_err());
                }
                settled(&lifecycle).await;
                reset.contained.recheck().unwrap();
                online(&quorum).await;
            }
            for (id, fault) in [
                (98, TestFault::DropReply),
                (99, TestFault::PanicAfterPublication),
            ] {
                let reset = lifecycle.reset(participants()).await.unwrap();
                let effect = authority
                    .commit_activation(quorum.create_request(id).await, child_key(id))
                    .await
                    .unwrap();
                *lifecycle.inner.open_fault.lock().unwrap() = Some(fault);
                assert!(
                    lifecycle.open(&reset, effect.clone()).await.is_err(),
                    "post-publication failure settles the observer without undo"
                );
                settled(&lifecycle).await;
                assert_eq!(count(&scope), 0);
                quorum.set_available(false);
                lifecycle
                    .open(&reset, effect)
                    .await
                    .unwrap()
                    .recheck()
                    .unwrap();
                online(&quorum).await;
            }
            authority.shutdown_local(participants()).await.unwrap();
            quorum.close().await;
        });
}
