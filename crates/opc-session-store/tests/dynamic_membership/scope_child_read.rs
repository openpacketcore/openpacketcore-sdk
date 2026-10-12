//! A configuration Fence is temporary unavailability, not stale business authority.
use super::*;
use futures_util::FutureExt;
use opc_session_store::scope_batch::{
    ScopeBatchError, ScopeBatchStore, ScopeChildKey, ScopeChildReadError,
};

#[cfg(feature = "test-control")]
use opc_session_store::scope_batch::{
    ScopeBatchRequest, ScopeChildMutation, ScopeChildReadStage, ScopeSealedValue,
};

#[cfg(feature = "test-control")]
async fn held_read_scope(
    fleet: &DynamicFleet,
    seed: u8,
) -> (ScopeAuthorityStamp, Vec<ScopeBatchStore>) {
    let scope = ScopeId::new(
        fleet.stores[0]
            .consumer_scope()
            .unwrap()
            .consensus_identity(),
        TenantId::from_static("held-child-read"),
        NetworkFunctionKind::smf(),
        [seed; 32],
    )
    .unwrap();
    let authority = ScopeAuthorityStore::new(
        Arc::new(fleet.stores[0].clone()),
        scope.clone(),
        Arc::new(Admission),
    )
    .unwrap();
    let admitted = authority
        .execute(
            &principal("worker-1"),
            &ScopeAuthorityRequest::new(
                scope,
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
    let stamp = admitted.stamp().unwrap().clone();
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
        .collect();
    (stamp, services)
}

#[cfg(feature = "test-control")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_child_read_held_across_configuration_fence_returns_no_rows() {
    for stage in [
        ScopeChildReadStage::AfterCapture,
        ScopeChildReadStage::BetweenKeys,
    ] {
        let mut fleet = DynamicFleet::start_three().await;
        let result = std::panic::AssertUnwindSafe(async {
            let (stamp, services) = held_read_scope(&fleet, 0x47).await;
            let keys = [ScopeChildKey::new([1; 32]).unwrap(), ScopeChildKey::new([2; 32]).unwrap()];
            let expanded = [0, 1, 2, 3, 4];
            let transition = fleet.transition_request(1, &expanded, 0xCA);
            fleet.provision_expansion(&transition).await;
            let proof = fleet.prepare(&transition, &expanded).await;
            let leader = fleet.wait_transition_caller(&[0, 1, 2]).await;
            let pause = fleet.stores[leader].pause_next_scope_child_read_for_test(stage);
            let service = services[leader].clone();
            let read = tokio::spawn(async move {
                service.read_current(&principal("worker-1"), &stamp, &keys).await
            });
            tokio::time::timeout(TEST_DEADLINE, pause.reached()).await.unwrap();
            for transport in &fleet.transports {
                transport.block_next_finalization();
            }
            let store = fleet.stores[leader].clone();
            let request = transition.clone();
            let proof_for_commit = proof.clone();
            let committing = tokio::spawn(async move {
                store.commit_topology_transition(&request, &proof_for_commit).await
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
            }).await.expect("the committed Fence precedes held-read release");
            wait_application_authority_fenced(&fleet.stores).await;
            assert!(!read.is_finished(), "the read must span the committed Fence at {stage:?}");
            pause.release();
            assert_eq!(
                read.await.unwrap(),
                Err(ScopeChildReadError::Batch(ScopeBatchError::Unavailable)),
                "a captured predecessor cut must return no rows after the Fence at {stage:?}"
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
                Err(error) => panic!("held-read transition failed: {error:?}"),
            }
            wait_completed_and_admitted(&fleet.stores, &transition, &expanded, &[]).await;
        }).catch_unwind().await;
        for transport in &fleet.transports {
            transport.release_finalization();
        }
        for store in &fleet.stores {
            store.shutdown().await.unwrap();
        }
        result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    }
}

#[cfg(feature = "test-control")]
fn held_read_value(byte: u8) -> ScopeSealedValue {
    ScopeSealedValue::new(
        CryptoEnvelopeV1 {
            algorithm: AeadAlgorithm::Aes256GcmSiv,
            key_id: KeyId::new("synthetic-held-read-key").unwrap(),
            nonce: vec![byte; 12],
            aad: vec![byte; 32],
            ciphertext_and_tag: vec![byte; 32],
        }
        .encode()
        .unwrap(),
    )
    .unwrap()
}

#[cfg(feature = "test-control")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_child_read_held_across_leader_change_never_returns_later_rows() {
    for stage in [
        ScopeChildReadStage::AfterCapture,
        ScopeChildReadStage::BetweenKeys,
    ] {
        let fleet = DynamicFleet::start_three().await;
        let result = std::panic::AssertUnwindSafe(async {
            let (stamp, services) = held_read_scope(&fleet, 0x48).await;
            let keys = [
                ScopeChildKey::new([1; 32]).unwrap(),
                ScopeChildKey::new([2; 32]).unwrap(),
            ];
            let original_value = held_read_value(1);
            let later_value = held_read_value(2);
            let leader = fleet.wait_transition_caller(&[0, 1, 2]).await;
            let created = services[leader]
                .execute(
                    &principal("worker-1"),
                    &ScopeBatchRequest::in_lane(
                        &stamp,
                        [2; 16],
                        0,
                        1,
                        keys.iter()
                            .map(|&key| ScopeChildMutation::Create {
                                key,
                                value: original_value.clone(),
                                claims: vec![],
                            })
                            .collect(),
                        vec![],
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            let pause = fleet.stores[leader].pause_next_scope_child_read_for_test(stage);
            let reader = services[leader].clone();
            let read_stamp = stamp.clone();
            let read = tokio::spawn(async move {
                reader
                    .read_current(&principal("worker-1"), &read_stamp, &keys)
                    .await
            });
            tokio::time::timeout(TEST_DEADLINE, pause.reached())
                .await
                .unwrap();
            fleet.network.isolate(leader);
            let retained = (0..3).filter(|&index| index != leader).collect::<Vec<_>>();
            let successor = fleet.wait_transition_caller(&retained).await;
            assert_ne!(successor, leader);
            let replaced = services[successor]
                .execute(
                    &principal("worker-1"),
                    &ScopeBatchRequest::in_lane(
                        &stamp,
                        [3; 16],
                        0,
                        2,
                        keys.iter()
                            .enumerate()
                            .map(|(index, &key)| ScopeChildMutation::CompareAndSet {
                                key,
                                expected: created.rows()[index],
                                value: later_value.clone(),
                                claims: vec![],
                            })
                            .collect(),
                        vec![],
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            assert!(replaced.revision() > created.revision());
            // Let the old voter see the new leader and the newer committed rows
            // before releasing the original capture.
            fleet.network.heal(leader);
            assert_eq!(
                services[leader]
                    .read_current(&principal("worker-1"), &stamp, &keys)
                    .await
                    .unwrap()
                    .iter()
                    .map(|row| row.as_ref().unwrap().value().unwrap())
                    .collect::<Vec<_>>(),
                vec![&later_value, &later_value]
            );
            pause.release();
            match read.await.unwrap() {
                Ok(rows) => {
                    assert_eq!(rows.len(), 2);
                    for (index, row) in rows.into_iter().enumerate() {
                        let row = row.unwrap();
                        assert_eq!(row.key(), keys[index]);
                        assert_eq!(row.revision(), created.rows()[index]);
                        assert_eq!(row.batch_revision(), created.revision());
                        assert_eq!(
                            row.value(),
                            Some(&original_value),
                            "original cut at {stage:?}"
                        );
                    }
                }
                Err(error) => assert_eq!(
                    error,
                    ScopeChildReadError::Batch(ScopeBatchError::Unavailable)
                ),
            }
        })
        .catch_unwind()
        .await;
        for index in 0..3 {
            fleet.network.heal(index);
        }
        for store in &fleet.stores {
            store.shutdown().await.unwrap();
        }
        result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    }
}

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
