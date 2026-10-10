//! Actual authenticated restore admission on both durable backend kinds.

use super::scope_authority::Admission;
use super::*;
use crate::scope_authority::tests::{execution, identity};
use crate::scope_authority::*;
use crate::scope_batch::tests::{claim, create, key};
use crate::scope_batch::*;
use crate::scope_scan::{
    ScopeScanDisposition, ScopeScanError, ScopeScanLookupKey, ScopeScanPageLimits,
    ScopeScanPageStatus, ScopeScanStore,
};
use crate::scope_scheduler::ScopeWorkClass;

#[derive(Clone, Copy)]
enum Case {
    Initial,
    Successor,
    WrongCaller,
    OtherNamespace,
    Stale,
    Paging,
    PageAuthorization,
    PageStale,
    PageClosed,
    Lookup,
    Client,
    RemoteOpen,
    RemoteOpenForged,
    LocalGuard,
    LocalGuardClass,
    ConfigurationChanged,
    CapacityRefused,
}

fn boot(generation: u64) -> ScopeExecution {
    let process = u128::from(generation).to_le_bytes();
    let mut key = [0; 32];
    key[..16].copy_from_slice(&process);
    key[16..].copy_from_slice(&process);
    ScopeExecution::new(identity("worker-1"), generation, [1; 16], process, key).unwrap()
}

async fn run(native: bool, case: Case) {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let snapshots =
        tempfile::tempdir_in(std::env::var_os("OPC_FS_VERITY_SNAPSHOT_ROOT").unwrap()).unwrap();
    let mut fleet = Fleet::new_with_mode("scope_scan_facade", native);
    if matches!(case, Case::CapacityRefused) {
        fleet.scan_limits = Some(
            crate::scope_scan::ScopeScanLimits::new(
                4,
                4,
                1,
                1024 * 1024 * 1024,
                Duration::from_secs(30),
            )
            .unwrap(),
        );
    }
    fleet.snapshot_root = Some(snapshots.path().to_path_buf());
    fleet.open().await;
    let result = AssertUnwindSafe(async {
        let store = Arc::new(fleet.stores[0].clone());
        let scope = ScopeId::new(
            fleet.topologies[0].consensus_identity().unwrap(),
            TenantId::from_static("scope-scan"),
            NetworkFunctionKind::smf(),
            [1; 32],
        )
        .unwrap();
        let authority =
            ScopeAuthorityStore::new(Arc::clone(&store), scope.clone(), Arc::new(Admission))
                .unwrap();
        let initial = authority
            .admit(
                &identity("worker-1"),
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
        let scans = ScopeScanStore::new(
            Arc::clone(&store),
            initial.stamp().namespace().clone(),
            Arc::new(Admission),
        )
        .unwrap();
        if matches!(case, Case::Initial) {
            assert!(
                matches!(
                    scans.open_restore(&identity("worker-1"), &initial).await,
                    Err(ScopeScanError::HandoverRequired)
                ),
                "initial admission cannot restore a historical cohort"
            );
            assert_eq!(scans.metrics().active_views, 0);
            return;
        }
        let batches = ScopeBatchStore::new(
            Arc::clone(&store),
            initial.stamp().namespace().clone(),
            Arc::new(Admission),
        )
        .unwrap();
        batches
            .execute(
                &identity("worker-1"),
                &ScopeBatchRequest::new(
                    initial.stamp(),
                    [2; 16],
                    0,
                    vec![create(
                        1,
                        if matches!(case, Case::Paging) {
                            &[7]
                        } else {
                            &[]
                        },
                    )],
                    vec![ScopeCounterMutation::new(0, 0, 7).unwrap()],
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let succession_request = ScopeAuthorityRequest::new(
            scope.clone(),
            [3; 16],
            1,
            ScopeAuthorityOperation::SucceedClosed {
                predecessor: initial.stamp().clone(),
                execution: boot(2),
                evidence: ScopeClosureEvidence::new(ScopeClosureKind::FinalTermination, [3; 32])
                    .unwrap(),
            },
        )
        .unwrap();
        let successor = authority
            .admit(&identity("worker-1"), &succession_request)
            .await
            .unwrap();
        match case {
            Case::Initial => unreachable!(),
            Case::CapacityRefused => {
                let failure = scans
                    .open_restore(&identity("worker-1"), &successor)
                    .await
                    .expect_err("one byte cannot reserve a view");
                assert_eq!(failure, ScopeScanError::CapacityRefused);
                let mut sink = ClientSink {
                    cut: None,
                    count: 0,
                    discarded: false,
                };
                let client = scans.client(identity("worker-1"), successor.clone());
                assert!(matches!(
                    client
                        .restore(
                            &mut sink,
                            tokio::time::Instant::now() + std::time::Duration::from_secs(60)
                        )
                        .await,
                    Err(crate::scope_scan::ScopeScanClientError::Request(
                        ScopeScanError::CapacityRefused
                    ))
                ));
                assert_eq!(scans.metrics().active_views, 0);
                assert_eq!(scans.metrics().waiting_views, 0);
            }
            Case::ConfigurationChanged => {
                let view = scans
                    .open_restore(&identity("worker-1"), &successor)
                    .await
                    .unwrap();
                let first = scans
                    .page(&identity("worker-1"), &view, view.initial_cursor())
                    .await
                    .unwrap();
                assert!(view.is_retained());
                let (old, mut members) = store.current_scope().unwrap();
                let local = store.inner.local_node_id;
                let removed = *members.iter().find(|node| **node != local).unwrap();
                members.remove(&removed);
                let added = SessionConsensusNodeId::new(777).unwrap();
                assert!(members.insert(added));
                let next = SessionConsensusIdentity::new(
                    old.cluster_id(),
                    crate::consensus::SessionConsensusConfigurationId::from_bytes([0xD3; 32]),
                    crate::consensus::SessionConsensusConfigurationEpoch::new(
                        old.configuration_epoch().get() + 1,
                    )
                    .unwrap(),
                );
                let peers = members
                    .iter()
                    .copied()
                    .filter(|node| *node != local)
                    .map(|node| {
                        let peer: Arc<dyn SessionConsensusPeer> =
                            Arc::new(ChangedConfigurationPeer {
                                node,
                                identity: next,
                            });
                        (node, peer)
                    })
                    .collect();
                let transition =
                    crate::membership::SessionTopologyTransitionId::from_bytes([0xD3; 16]);
                let digest =
                    crate::membership::SessionTopologyTransitionDigest::from_bytes([0xD4; 32]);
                let directory = &store.inner.peer_directory;
                // Use the production directory's exact stage/finalize boundary.
                // This tests configuration publication, not consensus progress.
                directory
                    .stage(
                        transition,
                        digest,
                        old.configuration_epoch(),
                        next,
                        members.clone(),
                        peers,
                    )
                    .unwrap();
                directory
                    .finalize(transition, digest, old.configuration_epoch(), &members)
                    .unwrap();
                assert_eq!(store.current_scope().unwrap().0, next);
                let barriers = store.scope_read_barrier_count_for_test();
                assert!(
                    matches!(
                        scans
                            .page(&identity("worker-1"), &view, view.initial_cursor())
                            .await,
                        Err(ScopeScanError::RestartRequired)
                    ),
                    "a published configuration change must invalidate even the cached page"
                );
                assert_eq!(
                    view.retry_cause(),
                    Some(crate::scope_scan::ScopeScanRetryCause::ConfigurationChanged)
                );
                assert!(!view.is_retained());
                assert_eq!(
                    scans.metrics().active_views,
                    0,
                    "obsolete configuration must release its capture"
                );
                assert_eq!(store.scope_read_barrier_count_for_test(), barriers);
                drop(first);
            }
            Case::LocalGuard => {
                let before = store.scope_read_barrier_count_for_test();
                scans
                    .validate_current(&identity("worker-1"), successor.stamp())
                    .await
                    .expect(
                        "an own-boot stamp can be revalidated locally without opening a capture",
                    );
                scans
                    .validate_classification_current(&identity("worker-1"), successor.stamp())
                    .await
                    .unwrap();
                assert_eq!(
                    store.scope_read_barrier_count_for_test(),
                    before,
                    "stamp guards perform no quorum read"
                );
                assert_eq!(scans.metrics().active_views, 0);
                assert_eq!(scans.metrics().waiting_views, 0);
                for denied in [identity("controller"), identity("worker-2")] {
                    assert!(matches!(
                        scans.validate_current(&denied, successor.stamp()).await,
                        Err(ScopeScanError::Unauthorized)
                    ));
                }
                let next = authority
                    .admit(
                        &identity("worker-1"),
                        &ScopeAuthorityRequest::new(
                            scope.clone(),
                            [6; 16],
                            successor.stamp().revision(),
                            ScopeAuthorityOperation::SucceedClosed {
                                predecessor: successor.stamp().clone(),
                                execution: boot(3),
                                evidence: ScopeClosureEvidence::new(
                                    ScopeClosureKind::FinalTermination,
                                    [6; 32],
                                )
                                .unwrap(),
                            },
                        )
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                let after = store.scope_read_barrier_count_for_test();
                assert!(matches!(
                    scans
                        .validate_current(&identity("worker-1"), successor.stamp())
                        .await,
                    Err(ScopeScanError::StaleAuthority)
                ));
                assert!(matches!(
                    scans
                        .validate_classification_current(&identity("worker-1"), successor.stamp())
                        .await,
                    Err(ScopeScanError::StaleAuthority)
                ));
                scans
                    .validate_current(&identity("worker-1"), next.stamp())
                    .await
                    .unwrap();
                assert_eq!(store.scope_read_barrier_count_for_test(), after);
                assert_eq!(scans.metrics().active_views, 0);
            }
            Case::LocalGuardClass => {
                let scheduling_key = super::super::scheduling::scope_key(&scope);
                let mut held = Vec::new();
                for _ in 0..crate::scope_scheduler::ScopeSchedulerBudgets::default()
                    .normal
                    .running
                    .div_ceil(2)
                {
                    held.push(
                        store
                            .inner
                            .proposal_admission
                            .reserve_for(scheduling_key, ScopeWorkClass::Normal)
                            .await
                            .unwrap()
                            .start()
                            .await
                            .unwrap(),
                    );
                }
                let caller = identity("worker-1");
                let mut normal = Box::pin(scans.validate_current(&caller, successor.stamp()));
                assert!(
                    matches!(
                        futures_util::poll!(normal.as_mut()),
                        std::task::Poll::Pending
                    ),
                    "Normal validation waits for its own execution credits"
                );
                let before = store.scope_read_barrier_count_for_test();
                tokio::time::timeout(
                    crate::DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
                    scans.validate_classification_current(&caller, successor.stamp()),
                )
                .await
                .expect("classification has independent execution credits")
                .unwrap();
                assert_eq!(store.scope_read_barrier_count_for_test(), before);
                assert_eq!(scans.metrics().active_views, 0);
                drop(held);
                normal.await.unwrap();
            }
            Case::RemoteOpen => {
                let request = crate::scope_scan::ScopeScanOpenRequest::new(
                    &successor,
                    &succession_request,
                    ScopeScanPageLimits::default(),
                )
                .unwrap();
                let view = scans
                    .open_restore_request(&identity("worker-1"), &request)
                    .await
                    .expect("exact committed succession claims open the actual coherent cut");
                assert_eq!(view.authority().stamp(), Some(successor.stamp()));
                assert_eq!(view.checkpoint().counters()[0], 7);
                let page = scans
                    .page(&identity("worker-1"), &view, view.initial_cursor())
                    .await
                    .unwrap();
                assert_eq!(page.items().len(), 1);
                assert_eq!(page.items().next().unwrap().child().unwrap().key(), key(1));
                for denied in [identity("controller"), identity("worker-2")] {
                    assert!(matches!(
                        scans.open_restore_request(&denied, &request).await,
                        Err(ScopeScanError::Unauthorized)
                    ));
                }
                view.close().await;
                assert_eq!(scans.metrics().active_views, 0);
            }
            Case::RemoteOpenForged => {
                for changed_id in [true, false] {
                    let operation = if changed_id {
                        succession_request.operation().clone()
                    } else {
                        ScopeAuthorityOperation::SucceedClosed {
                            predecessor: initial.stamp().clone(),
                            execution: boot(2),
                            evidence: ScopeClosureEvidence::new(
                                ScopeClosureKind::FinalTermination,
                                [9; 32],
                            )
                            .unwrap(),
                        }
                    };
                    let forged = ScopeAuthorityRequest::new(
                        scope.clone(),
                        if changed_id { [9; 16] } else { [3; 16] },
                        1,
                        operation,
                    )
                    .unwrap();
                    let request = crate::scope_scan::ScopeScanOpenRequest::new(
                        &successor,
                        &forged,
                        ScopeScanPageLimits::default(),
                    )
                    .unwrap();
                    assert!(
                        matches!(
                            scans
                                .open_restore_request(&identity("worker-1"), &request)
                                .await,
                            Err(ScopeScanError::HandoverRequired)
                        ),
                        "a current stamp cannot replace exact committed handover evidence"
                    );
                    assert_eq!(scans.metrics().active_views, 0);
                }
            }
            Case::Client => {
                let mut sink = ClientSink {
                    cut: None,
                    count: 0,
                    discarded: false,
                };
                let client = scans
                    .client(identity("worker-1"), successor.clone())
                    .with_limits(
                        ScopeScanPageLimits::new(
                            1,
                            crate::RESTORE_SCAN_MAX_LOCAL_PAGE_PAYLOAD_BYTES,
                        )
                        .unwrap(),
                        crate::scope_scan::ScopeScanRetryPolicy::default(),
                    );
                assert_eq!(
                    client
                        .restore(
                            &mut sink,
                            tokio::time::Instant::now() + std::time::Duration::from_secs(60)
                        )
                        .await
                        .unwrap(),
                    1
                );
                assert!(!sink.discarded);
                assert_eq!(
                    scans.metrics().active_views,
                    0,
                    "a completed SDK restore closes the actual capture"
                );
            }
            Case::Successor => {
                let view = scans
                    .open_restore(&identity("worker-1"), &successor)
                    .await
                    .expect("a committed same-cohort closed successor can open restore");
                assert_eq!(view.authority().stamp(), Some(successor.stamp()));
                assert_eq!(view.cut().namespace(), successor.stamp().namespace());
                assert_eq!(view.cut().authority_revision(), 2);
                assert_eq!(view.cut().batch_revision(), 1);
                assert_eq!(view.checkpoint().revision(), 1);
                assert_eq!(view.checkpoint().birth_floor(), 1);
                assert_eq!(view.checkpoint().counters()[0], 7);
                assert!(view.cut().applied_log_index() > 0);
                assert_eq!(scans.metrics().active_views, 1);
                let second = scans
                    .open_restore(&identity("worker-1"), &successor)
                    .await
                    .unwrap();
                assert_ne!(
                    view.cut(),
                    second.cut(),
                    "capture identity cannot alias another view"
                );
                view.close().await;
                view.close().await;
                drop(second);
                assert_eq!(scans.metrics().active_views, 0);
            }
            Case::WrongCaller => {
                assert!(
                    matches!(
                        scans
                            .open_restore(&identity("controller"), &successor)
                            .await,
                        Err(ScopeScanError::Unauthorized)
                    ),
                    "a controller never inherits the successor's worker capability"
                );
                assert!(matches!(
                    scans.open_restore(&identity("worker-2"), &successor).await,
                    Err(ScopeScanError::Unauthorized)
                ));
                assert_eq!(scans.metrics().active_views, 0);
            }
            Case::OtherNamespace => {
                let other = ScopeNamespace::new(scope, ScopeIncarnation::new(2).unwrap()).unwrap();
                let scans =
                    ScopeScanStore::new(Arc::clone(&store), other, Arc::new(Admission)).unwrap();
                assert!(
                    matches!(
                        scans.open_restore(&identity("worker-1"), &successor).await,
                        Err(ScopeScanError::Unauthorized)
                    ),
                    "positive closure cannot restore a different incarnation"
                );
                assert_eq!(scans.metrics().active_views, 0);
            }
            Case::Paging => {
                let view = scans
                    .open_restore_with_limits(
                        &identity("worker-1"),
                        &successor,
                        ScopeScanPageLimits::new(
                            1,
                            crate::RESTORE_SCAN_MAX_LOCAL_PAGE_PAYLOAD_BYTES,
                        )
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                let first = scans
                    .page(&identity("worker-1"), &view, view.initial_cursor())
                    .await
                    .unwrap();
                assert_eq!(first.items().len(), 1);
                assert_eq!(first.items().next().unwrap().child().unwrap().key(), key(1));
                assert_eq!(
                    first.items().next().unwrap().disposition(),
                    ScopeScanDisposition::LiveChild
                );
                batches
                    .execute(
                        &identity("worker-1"),
                        &ScopeBatchRequest::new(
                            successor.stamp(),
                            [11; 16],
                            1,
                            vec![
                                ScopeChildMutation::Delete {
                                    key: key(1),
                                    expected: ScopeChildRevision::new(1, 1).unwrap(),
                                },
                                create(2, &[8]),
                            ],
                            vec![],
                        )
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                let replay = scans
                    .page(&identity("worker-1"), &view, view.initial_cursor())
                    .await
                    .unwrap();
                assert!(
                    Arc::ptr_eq(&first, &replay),
                    "a lost reply is not rebuilt after a write"
                );
                let old_child = scans
                    .lookup(
                        &identity("worker-1"),
                        &view,
                        ScopeScanLookupKey::Child(key(1)),
                    )
                    .await
                    .unwrap();
                assert_eq!(old_child.cut(), view.cut());
                assert_eq!(
                    old_child.item().disposition(),
                    ScopeScanDisposition::LiveChild
                );
                assert!(old_child.item().child().unwrap().value().is_some());
                let missing = scans
                    .lookup(
                        &identity("worker-1"),
                        &view,
                        ScopeScanLookupKey::Child(key(2)),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    missing.item().disposition(),
                    ScopeScanDisposition::MissingAtCut
                );
                let second = scans
                    .page(&identity("worker-1"), &view, first.continuation().unwrap())
                    .await
                    .unwrap();
                assert_eq!(second.items().len(), 1);
                let item = second.items().next().unwrap();
                assert_eq!(item.claim().unwrap().key(), claim(7));
                assert!(matches!(
                    item.disposition(),
                    ScopeScanDisposition::ClaimHeld(_)
                ));
                assert_eq!(second.cut(), view.cut());
                assert!(matches!(
                    scans
                        .page(&identity("worker-1"), &view, view.initial_cursor())
                        .await,
                    Err(ScopeScanError::InvalidCursor)
                ));
                let terminal = scans
                    .page(&identity("worker-1"), &view, second.continuation().unwrap())
                    .await
                    .unwrap();
                assert_eq!(terminal.status(), ScopeScanPageStatus::Complete);
                assert_eq!(terminal.summary().unwrap().examined_items(), 2);
                let fresh = scans
                    .open_restore(&identity("worker-1"), &successor)
                    .await
                    .unwrap();
                assert_eq!(fresh.cut().batch_revision(), 2);
                let page = scans
                    .page(&identity("worker-1"), &fresh, fresh.initial_cursor())
                    .await
                    .unwrap();
                assert_eq!(page.items().len(), 4);
                let verdicts: Vec<_> = page.items().map(|item| item.disposition()).collect();
                assert_eq!(verdicts[0], ScopeScanDisposition::ChildTombstone);
                assert_eq!(verdicts[1], ScopeScanDisposition::LiveChild);
                assert_eq!(verdicts[2], ScopeScanDisposition::ClaimReleased);
                assert!(matches!(verdicts[3], ScopeScanDisposition::ClaimHeld(_)));
                let done = scans
                    .page(&identity("worker-1"), &fresh, page.continuation().unwrap())
                    .await
                    .unwrap();
                assert_eq!(done.summary().unwrap().examined_items(), 4);
                assert_eq!(done.summary().unwrap().failed_items(), 0);
                view.close().await;
                fresh.close().await;
            }
            Case::PageAuthorization => {
                let view = scans
                    .open_restore(&identity("worker-1"), &successor)
                    .await
                    .unwrap();
                for caller in [identity("worker-2"), identity("controller")] {
                    assert!(matches!(
                        scans.page(&caller, &view, view.initial_cursor()).await,
                        Err(ScopeScanError::Unauthorized)
                    ));
                    assert!(matches!(
                        scans
                            .lookup(&caller, &view, ScopeScanLookupKey::Child(key(1)))
                            .await,
                        Err(ScopeScanError::Unauthorized)
                    ));
                    assert!(matches!(
                        scans
                            .classify(&caller, &view, ScopeScanLookupKey::Child(key(1)))
                            .await,
                        Err(ScopeScanError::Unauthorized)
                    ));
                }
                let foreign = ScopeScanStore::new(
                    Arc::new(fleet.stores[1].clone()),
                    successor.stamp().namespace().clone(),
                    Arc::new(Admission),
                )
                .unwrap();
                assert!(matches!(
                    foreign
                        .page(&identity("worker-1"), &view, view.initial_cursor())
                        .await,
                    Err(ScopeScanError::Unauthorized)
                ));
                let other = scans
                    .open_restore(&identity("worker-1"), &successor)
                    .await
                    .unwrap();
                assert!(matches!(
                    scans
                        .page(&identity("worker-1"), &view, other.initial_cursor())
                        .await,
                    Err(ScopeScanError::InvalidCursor)
                ));
                view.close().await;
                other.close().await;
            }
            Case::PageClosed => {
                let view = scans
                    .open_restore(&identity("worker-1"), &successor)
                    .await
                    .unwrap();
                let reply = scans
                    .page(&identity("worker-1"), &view, view.initial_cursor())
                    .await
                    .unwrap();
                let weak = Arc::downgrade(&reply);
                drop(reply);
                assert!(
                    weak.upgrade().is_some(),
                    "the view retains its unacknowledged reply"
                );
                view.close().await;
                assert!(
                    weak.upgrade().is_none(),
                    "close must drop the actual cached payload while the outer view handle lives"
                );
                assert_eq!(scans.metrics().active_views, 0);
                assert!(matches!(
                    scans
                        .page(&identity("worker-1"), &view, view.initial_cursor())
                        .await,
                    Err(ScopeScanError::RestartRequired)
                ));
                assert!(matches!(
                    scans
                        .lookup(
                            &identity("worker-1"),
                            &view,
                            ScopeScanLookupKey::Child(key(1))
                        )
                        .await,
                    Err(ScopeScanError::RestartRequired)
                ));
            }
            Case::Lookup => {
                let view = scans
                    .open_restore(&identity("worker-1"), &successor)
                    .await
                    .unwrap();
                let found = scans
                    .classify(
                        &identity("worker-1"),
                        &view,
                        ScopeScanLookupKey::Child(key(1)),
                    )
                    .await
                    .unwrap();
                assert_eq!(found.cut(), view.cut());
                assert_eq!(found.item().disposition(), ScopeScanDisposition::LiveChild);
                for requested in [
                    ScopeScanLookupKey::Child(key(99)),
                    ScopeScanLookupKey::Claim(claim(99)),
                ] {
                    let normal = scans
                        .lookup(&identity("worker-1"), &view, requested)
                        .await
                        .unwrap();
                    let classified = scans
                        .classify(&identity("worker-1"), &view, requested)
                        .await
                        .unwrap();
                    assert_eq!(
                        normal.item().disposition(),
                        ScopeScanDisposition::MissingAtCut
                    );
                    assert_eq!(
                        classified.item().disposition(),
                        ScopeScanDisposition::MissingAtCut
                    );
                    assert_eq!(normal.cut(), classified.cut());
                }
                view.close().await;
            }
            Case::Stale | Case::PageStale => {
                let retained = if matches!(case, Case::PageStale) {
                    let view = scans
                        .open_restore(&identity("worker-1"), &successor)
                        .await
                        .unwrap();
                    scans
                        .page(&identity("worker-1"), &view, view.initial_cursor())
                        .await
                        .unwrap();
                    Some(view)
                } else {
                    None
                };
                authority
                    .admit(
                        &identity("worker-1"),
                        &ScopeAuthorityRequest::new(
                            successor.stamp().scope().clone(),
                            [4; 16],
                            2,
                            ScopeAuthorityOperation::SucceedClosed {
                                predecessor: successor.stamp().clone(),
                                execution: boot(3),
                                evidence: ScopeClosureEvidence::new(
                                    ScopeClosureKind::FinalTermination,
                                    [4; 32],
                                )
                                .unwrap(),
                            },
                        )
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                assert!(
                    matches!(
                        scans.open_restore(&identity("worker-1"), &successor).await,
                        Err(ScopeScanError::StaleAuthority)
                    ),
                    "an opaque but superseded grant is not current restore admission"
                );
                if let Some(view) = retained {
                    assert!(
                        matches!(
                            scans
                                .page(&identity("worker-1"), &view, view.initial_cursor())
                                .await,
                            Err(ScopeScanError::StaleAuthority)
                        ),
                        "cached replies require current authority too"
                    );
                    assert!(matches!(
                        scans
                            .lookup(
                                &identity("worker-1"),
                                &view,
                                ScopeScanLookupKey::Child(key(1))
                            )
                            .await,
                        Err(ScopeScanError::StaleAuthority)
                    ));
                    view.close().await;
                }
                assert_eq!(scans.metrics().active_views, 0);
            }
        }
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

macro_rules! cases {
    ($($name:ident, $native:expr, $case:ident;)+) => { $(
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn $name() { run($native, Case::$case).await; }
    )+ };
}
cases! {
    scope_scan_native_capacity_refusal_is_final_without_queueing, true, CapacityRefused;
    scope_scan_native_configuration_change_invalidates_cached_cut, true, ConfigurationChanged;
    scope_scan_sqlite_configuration_change_invalidates_cached_cut, false, ConfigurationChanged;
    scope_scan_initial_native_has_no_handover, true, Initial;
    scope_scan_initial_sqlite_has_no_handover, false, Initial;
    scope_scan_successor_native_opens_exact_headers, true, Successor;
    scope_scan_successor_sqlite_opens_exact_headers, false, Successor;
    scope_scan_native_refuses_wrong_caller, true, WrongCaller;
    scope_scan_sqlite_refuses_wrong_caller, false, WrongCaller;
    scope_scan_native_refuses_other_namespace, true, OtherNamespace;
    scope_scan_sqlite_refuses_other_namespace, false, OtherNamespace;
    scope_scan_native_refuses_superseded_grant, true, Stale;
    scope_scan_sqlite_refuses_superseded_grant, false, Stale;
    scope_scan_native_pages_and_lookups_keep_one_cut_across_atomic_writes, true, Paging;
    scope_scan_sqlite_pages_and_lookups_keep_one_cut_across_atomic_writes, false, Paging;
    scope_scan_native_page_rechecks_caller_view_and_cursor, true, PageAuthorization;
    scope_scan_sqlite_page_rechecks_caller_view_and_cursor, false, PageAuthorization;
    scope_scan_native_cached_page_refuses_superseded_boot, true, PageStale;
    scope_scan_sqlite_cached_page_refuses_superseded_boot, false, PageStale;
    scope_scan_native_close_drops_actual_reply_with_view_handle_retained, true, PageClosed;
    scope_scan_sqlite_close_drops_actual_reply_with_view_handle_retained, false, PageClosed;
    scope_scan_native_classification_and_lookup_are_final_at_the_cut, true, Lookup;
    scope_scan_sqlite_classification_and_lookup_are_final_at_the_cut, false, Lookup;
    scope_scan_native_local_boot_guard_uses_no_barrier_or_capture, true, LocalGuard;
    scope_scan_sqlite_local_boot_guard_uses_no_barrier_or_capture, false, LocalGuard;
    scope_scan_native_classification_guard_keeps_its_own_execution_budget, true, LocalGuardClass;
    scope_scan_sqlite_classification_guard_keeps_its_own_execution_budget, false, LocalGuardClass;
    scope_scan_native_remote_open_verifies_exact_committed_handover, true, RemoteOpen;
    scope_scan_sqlite_remote_open_verifies_exact_committed_handover, false, RemoteOpen;
    scope_scan_native_remote_open_refuses_forged_handover_claims, true, RemoteOpenForged;
    scope_scan_sqlite_remote_open_refuses_forged_handover_claims, false, RemoteOpenForged;
    scope_scan_native_client_streams_and_closes_the_actual_retained_cut, true, Client;
    scope_scan_sqlite_client_streams_and_closes_the_actual_retained_cut, false, Client;
}

struct ClientSink {
    cut: Option<crate::scope_scan::ScopeCut>,
    count: usize,
    discarded: bool,
}
#[async_trait::async_trait]
impl crate::scope_scan::ScopeScanSink for ClientSink {
    type Error = &'static str;
    type Output = usize;
    async fn begin(
        &mut self,
        cut: &crate::scope_scan::ScopeCut,
        authority: &ScopeAuthorityView,
        checkpoint: &crate::scope_scan::ScopeScanCheckpoint,
    ) -> Result<(), Self::Error> {
        assert_eq!(authority.revision(), cut.authority_revision());
        assert_eq!(checkpoint.revision(), cut.batch_revision());
        assert_eq!(checkpoint.counters()[0], 7);
        self.cut = Some(cut.clone());
        Ok(())
    }
    async fn stage(
        &mut self,
        reply: &crate::scope_scan::ScopeScanReply,
    ) -> Result<(), Self::Error> {
        assert_eq!(Some(reply.cut()), self.cut.as_ref());
        for item in reply.items() {
            assert_eq!(item.disposition(), ScopeScanDisposition::LiveChild);
            assert_eq!(item.child().unwrap().key(), key(1));
            self.count += 1;
        }
        Ok(())
    }
    async fn finish(
        &mut self,
        reply: &crate::scope_scan::ScopeScanReply,
    ) -> Result<usize, Self::Error> {
        assert_eq!(Some(reply.cut()), self.cut.as_ref());
        assert_eq!(reply.summary().unwrap().examined_items(), self.count as u64);
        Ok(self.count)
    }
    fn discard(&mut self, _: &crate::scope_scan::ScopeCut) {
        self.discarded = true;
        self.cut = None;
        self.count = 0;
    }
}

#[derive(Debug)]
struct ChangedConfigurationPeer {
    node: SessionConsensusNodeId,
    identity: SessionConsensusIdentity,
}
#[async_trait::async_trait]
impl SessionConsensusPeer for ChangedConfigurationPeer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.node
    }
    fn scope_identity(&self) -> Option<SessionConsensusIdentity> {
        Some(self.identity)
    }
    async fn call(
        &self,
        _: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        Err(SessionConsensusPeerError::Unavailable)
    }
}
