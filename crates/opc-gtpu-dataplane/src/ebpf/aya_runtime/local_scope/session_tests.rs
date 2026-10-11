use super::fresh_tests::session_request;
use super::sessions::{TestFault, TestPause};
use super::*;
use crate::local_scope_quorum::{child_key, execution, Quorum};
use crate::{EbpfGtpuDataplaneBackend, GtpuSessionDeviceId, ScopedGtpuReceipt};
use opc_local_kernel_lifecycle::{LocalInstalledGraph, ScopeKernelAuthority};
use std::time::Duration;

type Groups =
    BpfHashMap<MapData, [u8; GTPU_SESSION_GROUP_ID_LEN], [u8; GTPU_SESSION_GROUP_VALUE_LEN]>;
fn groups(backend: &EbpfGtpuDataplaneBackend) -> Groups {
    let binding = backend.inner.local_scope.as_ref().unwrap();
    let path = binding
        .local_scope()
        .spec()
        .pin_root()
        .join(binding.artifact().directory())
        .join(MAP_SESSION_GROUPS);
    Groups::try_from(Map::HashMap(MapData::from_pin(path).unwrap())).unwrap()
}
fn absent(backend: &EbpfGtpuDataplaneBackend, id: u8) {
    assert!(
        matches!(
            groups(backend).get(&[id; 16], 0),
            Err(MapError::KeyNotFound)
        ),
        "failed/cancelled group must be absent"
    );
}
async fn settled(backend: &EbpfGtpuDataplaneBackend) {
    while !backend.scoped_cleanup_progress().await.unwrap().is_empty() {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
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
pub(super) struct Fixture<'a> {
    pub(super) backend: &'a EbpfGtpuDataplaneBackend,
    pub(super) graph: &'a LocalInstalledGraph,
    pub(super) authority: &'a ScopeKernelAuthority,
    pub(super) quorum: &'a Quorum,
    pub(super) device: GtpuSessionDeviceId,
    pub(super) ifindex: u32,
}
pub(super) async fn exercise(
    fixture: Fixture<'_>,
    healthy: &ScopedGtpuReceipt,
    sibling: ScopedGtpuReceipt,
) -> ScopedGtpuReceipt {
    let Fixture {
        backend,
        graph,
        authority,
        quorum,
        device,
        ifindex,
    } = fixture;
    let runtime = backend.inner.local_runtime.as_ref().unwrap();
    let mut completed = Vec::new();
    for id in 100..116 {
        let activation = quorum.create_request(id).await;
        let effect = authority
            .commit_activation(activation.clone(), child_key(id))
            .await
            .unwrap();
        let request = session_request(device, ifindex, id, id);
        let receipt = backend
            .install_scoped(graph, effect.clone(), request.clone())
            .await
            .unwrap();
        backend.remove_scoped(&receipt).await.unwrap();
        backend.remove_scoped(&receipt).await.unwrap();
        assert!(!backend.read_scoped(&receipt).await.unwrap());
        let replay = authority
            .commit_activation(activation, child_key(id))
            .await
            .unwrap();
        assert!(backend
            .install_scoped(graph, replay, request)
            .await
            .is_err());
        completed.push((effect, receipt));
        assert_eq!(
            runtime.retained().await,
            2,
            "completed churn must not increase memory or lookup work"
        );
    }
    for (id, fault) in [
        (80, TestFault::PanicAfterIndex),
        (81, TestFault::PanicAfterGroup),
    ] {
        let effect = authority
            .commit_activation(quorum.create_request(id).await, child_key(id))
            .await
            .unwrap();
        runtime.fault(fault).await.unwrap();
        assert!(backend
            .install_scoped(graph, effect, session_request(device, ifindex, id, id))
            .await
            .is_err());
        absent(backend, id);
        assert!(backend.read_scoped(healthy).await.unwrap());
        assert!(backend.read_scoped(&sibling).await.unwrap());
    }
    let pause = Arc::new(TestPause::default());
    runtime
        .fault(TestFault::PauseAfterGroup(pause.clone()))
        .await
        .unwrap();
    let effect = authority
        .commit_activation(quorum.create_request(82).await, child_key(82))
        .await
        .unwrap();
    let (worker_backend, worker_graph) = (backend.clone(), graph.clone());
    let install = tokio::spawn(async move {
        worker_backend
            .install_scoped(
                &worker_graph,
                effect,
                session_request(device, ifindex, 82, 82),
            )
            .await
    });
    pause.entered.notified().await;
    assert!(
        groups(backend).get(&[82; 16], 0).is_ok(),
        "cancellation occurs after a real kernel group mutation"
    );
    install.abort();
    assert!(install.await.unwrap_err().is_cancelled());
    pause.resume.notify_one();
    settled(backend).await;
    absent(backend, 82);
    assert!(backend.read_scoped(healthy).await.unwrap());

    for (id, fault) in [
        (83, TestFault::PanicAfterPublication),
        (84, TestFault::DropPublishedReply),
    ] {
        let effect = authority
            .commit_activation(quorum.create_request(id).await, child_key(id))
            .await
            .unwrap();
        let request = session_request(device, ifindex, id, id);
        runtime.fault(fault).await.unwrap();
        assert!(backend
            .install_scoped(graph, effect.clone(), request.clone())
            .await
            .is_err());
        quorum.set_available(false);
        let receipt = backend
            .install_scoped(graph, effect, request)
            .await
            .expect("published exact retry survives panic/reply loss and store outage");
        assert!(backend.read_scoped(&receipt).await.unwrap());
        backend.remove_scoped(&receipt).await.unwrap();
        online(quorum).await;
    }

    let effect = authority
        .commit_activation(quorum.create_request(85).await, child_key(85))
        .await
        .unwrap();
    let receipt = backend
        .install_scoped(graph, effect, session_request(device, ifindex, 85, 85))
        .await
        .unwrap();
    let expected = groups(backend).get(&[85; 16], 0).unwrap();
    let mut changed = expected;
    changed[2] ^= 1;
    groups(backend).insert([85; 16], changed, 0).unwrap();
    assert!(backend.read_scoped(&receipt).await.is_err());
    let worker = backend.clone();
    let remove = tokio::spawn(async move { worker.remove_scoped(&receipt).await });
    while !backend
        .scoped_cleanup_progress()
        .await
        .unwrap()
        .iter()
        .any(|progress| progress.first_failure_age.is_some())
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        groups(backend).get(&[85; 16], 0).unwrap(),
        changed,
        "changed value is never removed"
    );
    assert!(backend.read_scoped(healthy).await.unwrap());
    remove.abort();
    let _ = remove.await;
    groups(backend).insert([85; 16], expected, 0).unwrap();
    settled(backend).await;
    absent(backend, 85);

    let effect = authority
        .commit_activation(quorum.create_request(86).await, child_key(86))
        .await
        .unwrap();
    let (worker, ready) = (backend.clone(), graph.clone());
    let pending = tokio::spawn(async move {
        worker
            .install_scoped(&ready, effect, session_request(device, ifindex, 86, 2))
            .await
    });
    while !backend
        .scoped_cleanup_progress()
        .await
        .unwrap()
        .iter()
        .any(|progress| progress.attempts != 0)
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        !pending.is_finished(),
        "an occupied selector waits instead of rejecting the attach"
    );
    assert!(backend.read_scoped(healthy).await.unwrap());
    backend.remove_scoped(&sibling).await.unwrap();
    let successor = pending.await.unwrap().unwrap();
    backend.remove_scoped(&sibling).await.unwrap();
    assert!(
        backend.read_scoped(&successor).await.unwrap(),
        "retired receipt cannot remove the successor"
    );
    successor
}
