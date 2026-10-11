//! A configuration Fence is temporary unavailability, not stale business authority.
use super::*;
use futures_util::FutureExt;
use opc_session_store::scope_batch::{
    ScopeBatchError, ScopeBatchStore, ScopeChildKey, ScopeChildReadError,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_child_read_reports_unavailable_between_fence_and_successor_admission() {
    let mut fleet = DynamicFleet::start_three().await;
    let result =
        std::panic::AssertUnwindSafe(async {
            let identity = fleet.stores[0]
                .consumer_scope()
                .unwrap()
                .consensus_identity();
            let scope = ScopeId::new(
                identity,
                TenantId::from_static("child-read-membership"),
                NetworkFunctionKind::smf(),
                [0x35; 32],
            )
            .unwrap();
            let authority = ScopeAuthorityStore::new(
                Arc::new(fleet.stores[0].clone()),
                scope.clone(),
                Arc::new(Admission),
            )
            .unwrap();
            let initial = authority
                .execute(
                    &principal("worker-1"),
                    &ScopeAuthorityRequest::new(
                        scope.clone(),
                        [1; 16],
                        0,
                        ScopeAuthorityOperation::AdmitInitial {
                            execution: execution(1),
                        },
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            let stamp = initial.stamp().unwrap().clone();
            let key = ScopeChildKey::new([0x36; 32]).unwrap();
            let services = fleet
                .stores
                .iter()
                .map(|store| {
                    ScopeBatchStore::new(
                        Arc::new(store.clone()),
                        stamp.namespace().clone(),
                        Arc::new(Admission),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            for service in &services {
                assert_eq!(
                    service
                        .read_current(&principal("worker-1"), &stamp, &[key])
                        .await,
                    Ok(vec![None])
                );
            }

            let expanded = [0, 1, 2, 3, 4];
            let transition = fleet.transition_request(1, &expanded, 0xC8);
            fleet.provision_expansion(&transition).await;
            let proof = fleet.prepare(&transition, &expanded).await;
            // Prepare alone still permits the active predecessor's scope reads.
            // Hold every transport's actual finalization callback after durable
            // Fence and uniform membership, before local successor admission.
            let leader = fleet.wait_transition_caller(&[0, 1, 2]).await;
            for transport in &fleet.transports {
                transport.block_next_finalization();
            }
            let commit_store = fleet.stores[leader].clone();
            let commit_request = transition.clone();
            let commit_proof = proof.clone();
            let committing = tokio::spawn(async move {
                commit_store.commit_topology_transition(&commit_request, &commit_proof).await
            });
            tokio::time::timeout(TEST_DEADLINE, async {
                loop {
                    let mut all_finalizing = true;
                    for store in &fleet.stores {
                        all_finalizing &= matches!(
                            store.topology_transition_status(&transition).await,
                            Ok(Some(status)) if status.phase() == SessionTopologyTransitionPhase::Finalizing
                        );
                    }
                    if all_finalizing { break; }
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
            }).await.expect("every replica applies the durable Fence and uniform membership before successor admission");
            wait_application_authority_fenced(&fleet.stores).await;
            let before = fleet.stores[leader].status().last_log_index;
            for service in &services {
                assert_eq!(service.read_current(&principal("worker-1"), &stamp, &[key]).await,
                Err(ScopeChildReadError::Batch(ScopeBatchError::Unavailable)),
                "the actual committed configuration Fence cannot be misreported as StaleAuthority");
            }
            assert_eq!(
                fleet.stores[leader].status().last_log_index,
                before,
                "unavailable point reads append no command"
            );
            for transport in &fleet.transports {
                transport.release_finalization();
            }
            match committing.await.unwrap() {
                Ok(status) => assert_eq!(status.phase(), SessionTopologyTransitionPhase::Completed),
                Err(SessionTopologyTransitionError::NotLeader
                    | SessionTopologyTransitionError::Unavailable
                    | SessionTopologyTransitionError::DeadlineExceededResumable) => {
                    fleet.commit(&transition, &proof, &expanded).await;
                }
                Err(error) => panic!("exact held transition failed: {error:?}"),
            }
            wait_completed_and_admitted(&fleet.stores, &transition, &expanded, &[]).await;
            assert_ne!(
                fleet.stores[0]
                    .consumer_scope()
                    .unwrap()
                    .consensus_identity(),
                identity
            );
            assert_eq!(
                authority
                    .current(&principal("worker-1"))
                    .await
                    .unwrap()
                    .stamp(),
                Some(&stamp),
                "configuration replacement leaves the active business stamp unchanged"
            );
            for service in &services {
                assert_eq!(
                    service
                        .read_current(&principal("worker-1"), &stamp, &[key])
                        .await,
                    Ok(vec![None]),
                    "the original service and stamp recover after successor admission"
                );
            }
        })
        .catch_unwind()
        .await;
    for transport in &fleet.transports {
        transport.release_finalization();
    }
    for store in &fleet.stores {
        store.shutdown().await.unwrap();
    }
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
