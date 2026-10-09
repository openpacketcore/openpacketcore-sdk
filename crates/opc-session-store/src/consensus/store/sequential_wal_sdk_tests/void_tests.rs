use super::*;
use crate::{FencedTransitionV2Capability, FencedTransitionV2Profile, StoreError};

async fn baseline_readiness_without_profile_probes(behavior: u8) {
    let mut fleet = Fleet::new("baseline-readiness-no-profile-probe");
    fleet
        .open_void_profiles_with_persistence([FencedTransitionV2Profile::V2; 3], false)
        .await;
    let result = AssertUnwindSafe(async {
        let leader = fleet
            .stores
            .iter()
            .position(|store| store.status().leader_id == Some(store.status().node_id))
            .unwrap();
        let peer = &fleet.peers[(leader + 1) % 3];
        peer.profile_probe_behavior
            .store(behavior, Ordering::SeqCst);
        for peer in &fleet.peers {
            peer.profile_probes.store(0, Ordering::SeqCst);
        }
        // The peer still serves barriers. Only the new profile RPC rejects or
        // never answers; neither is part of baseline readiness on main.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let report = tokio::time::timeout(
            Duration::from_millis(500),
            fleet.stores[leader].probe_fixed_quorum_readiness_before(deadline),
        )
        .await
        .expect("baseline readiness completes at barrier speed");
        assert_eq!(report.state(), crate::DurableReadinessState::Ready);
        assert_eq!(
            fleet
                .peers
                .iter()
                .map(|peer| peer.profile_probes.load(Ordering::SeqCst))
                .sum::<usize>(),
            0
        );
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn baseline_readiness_ignores_a_peer_that_rejects_profile_probes() {
    baseline_readiness_without_profile_probes(1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn baseline_readiness_ignores_a_peer_that_never_answers_profile_probes() {
    baseline_readiness_without_profile_probes(2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn baseline_capability_prefers_unavailable_to_unsupported_before_activation() {
    let mut fleet = Fleet::new("baseline-capability-error-order");
    fleet
        .open_void_profiles_with_persistence([FencedTransitionV2Profile::V2; 3], false)
        .await;
    let result = AssertUnwindSafe(async {
        let leader = fleet
            .stores
            .iter()
            .position(|store| store.status().leader_id == Some(store.status().node_id))
            .unwrap();
        let store = &fleet.stores[leader];
        let (identity, voters) = store.current_scope().unwrap();
        assert!(!store
            .inner
            .backend
            .consensus_fenced_transition_v2_activation_matches_scope(
                store.inner.storage_identity,
                identity,
                voters,
                FencedTransitionV2Profile::V2.digest(),
            )
            .await
            .unwrap());
        fleet.peers[(leader + 1) % 3]
            .profile_probe_behavior
            .store(1, Ordering::SeqCst);
        let absent = &fleet.peers[(leader + 2) % 3];
        let handler = absent.handler.write().await.take();
        let capability = store.fenced_transition_v2_capability().await;
        *absent.handler.write().await = handler;
        assert_eq!(
            capability,
            Err(StoreError::BackendUnavailable(
                "session consensus quorum is unavailable".into(),
            ))
        );
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn void_readiness_reuses_proof_while_activation_lookup_is_blocked() {
    let mut fleet = Fleet::new("void-readiness-cached-slow-lookup");
    fleet
        .open_void_profiles_with_persistence([FencedTransitionV2Profile::V2WithVoid; 3], true)
        .await;
    let result = AssertUnwindSafe(async {
        let leader = fleet
            .stores
            .iter()
            .position(|store| store.status().leader_id == Some(store.status().node_id))
            .unwrap();
        let store = &fleet.stores[leader];
        assert!(
            !store.inner.private_wal.as_ref().unwrap().is_native(),
            "exercise the queued SQLite lookup"
        );
        assert!(store
            .inner
            .fenced_transition_profile_admission
            .lock()
            .unwrap()
            .is_some());
        let backend = &store.inner.backend;
        let _held = backend
            .fenced_transition_v2_activation_lookup_gate
            .acquire()
            .await
            .unwrap();
        let lookups = backend
            .fenced_transition_v2_activation_lookup_count
            .load(Ordering::SeqCst);
        let report = tokio::time::timeout(
            Duration::from_millis(500),
            store.probe_fixed_quorum_readiness_before(
                tokio::time::Instant::now() + Duration::from_secs(2),
            ),
        )
        .await
        .expect("cached proof avoids the blocked activation lookup");
        assert_eq!(report.state(), crate::DurableReadinessState::Ready);
        assert_eq!(
            backend
                .fenced_transition_v2_activation_lookup_count
                .load(Ordering::SeqCst),
            lookups
        );
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn void_readiness_loads_a_slow_activation_once_outside_the_probe_budget() {
    let mut fleet = Fleet::new("void-readiness-activated-slow-lookup");
    fleet
        .open_void_profiles_with_persistence([FencedTransitionV2Profile::V2WithVoid; 3], true)
        .await;
    let result = AssertUnwindSafe(async {
        let leader = fleet
            .stores
            .iter()
            .position(|store| store.status().leader_id == Some(store.status().node_id))
            .unwrap();
        let store = &fleet.stores[leader];
        assert!(
            !store.inner.private_wal.as_ref().unwrap().is_native(),
            "exercise the queued SQLite lookup"
        );
        let request = v2_create_request(
            305,
            FencedTransitionV2HistoryEpoch::new(1).unwrap(),
            FenceToken::new(0),
            &provider(),
        )
        .await;
        assert_eq!(
            store.fenced_transition_v2_void(&request).await.unwrap(),
            FencedTransitionV2Status::Recorded(Box::new(Err(StoreError::FencedTransitionVoided)))
        );
        *store
            .inner
            .fenced_transition_profile_admission
            .lock()
            .unwrap() = None;
        let backend = &store.inner.backend;
        let held = backend
            .fenced_transition_v2_activation_lookup_gate
            .acquire()
            .await
            .unwrap();
        let lookups = backend
            .fenced_transition_v2_activation_lookup_count
            .load(Ordering::SeqCst);
        let lookup_delay = async {
            let mut progress = backend.test_progress.subscribe();
            progress
                .wait_for(|()| {
                    backend
                        .fenced_transition_v2_activation_lookup_count
                        .load(Ordering::SeqCst)
                        != lookups
                })
                .await
                .expect("test retains its backend publisher");
            tokio::time::sleep(Duration::from_millis(350)).await;
            drop(held);
        };
        let (report, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                store.probe_fixed_quorum_readiness_before(
                    tokio::time::Instant::now() + Duration::from_secs(2)
                ),
                lookup_delay
            )
        })
        .await
        .expect("slow lookup remains within the caller's readiness deadline");
        assert_eq!(report.state(), crate::DurableReadinessState::Ready);
        assert_eq!(
            backend
                .fenced_transition_v2_activation_lookup_count
                .load(Ordering::SeqCst),
            lookups + 1
        );
        let _held = backend
            .fenced_transition_v2_activation_lookup_gate
            .acquire()
            .await
            .unwrap();
        let report = tokio::time::timeout(
            Duration::from_millis(500),
            store.probe_fixed_quorum_readiness_before(
                tokio::time::Instant::now() + Duration::from_secs(2),
            ),
        )
        .await
        .expect("the loaded activation is cached for this exact scope");
        assert_eq!(report.state(), crate::DurableReadinessState::Ready);
        assert_eq!(
            backend
                .fenced_transition_v2_activation_lookup_count
                .load(Ordering::SeqCst),
            lookups + 1
        );
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn void_readiness_bounds_unanswered_probes_and_reuses_the_exact_scope_proof() {
    let mut fleet = Fleet::new("void-readiness-profile-proof");
    fleet
        .open_void_profiles_with_persistence([FencedTransitionV2Profile::V2WithVoid; 3], false)
        .await;
    let result = AssertUnwindSafe(async {
        let leader = fleet
            .stores
            .iter()
            .position(|store| store.status().leader_id == Some(store.status().node_id))
            .unwrap();
        let store = &fleet.stores[leader];
        let peer = &fleet.peers[(leader + 1) % 3];
        let proof = store
            .inner
            .fenced_transition_profile_admission
            .lock()
            .unwrap()
            .take();
        assert!(proof.is_some());
        peer.profile_probe_behavior.store(2, Ordering::SeqCst);
        peer.profile_probes.store(0, Ordering::SeqCst);
        // No activation or process-local proof: every voter must answer.
        // The probe has its own bound, leaving time for readiness's scope work.
        let report = tokio::time::timeout(
            Duration::from_millis(750),
            store.probe_fixed_quorum_readiness_before(
                tokio::time::Instant::now() + Duration::from_secs(2),
            ),
        )
        .await
        .expect("profile probe has a short independent deadline");
        assert_eq!(report.state(), crate::DurableReadinessState::NoQuorum);
        assert_eq!(peer.profile_probes.load(Ordering::SeqCst), 1);
        *store
            .inner
            .fenced_transition_profile_admission
            .lock()
            .unwrap() = proof;
        peer.profile_probes.store(0, Ordering::SeqCst);
        let report = tokio::time::timeout(
            Duration::from_millis(500),
            store.probe_fixed_quorum_readiness_before(
                tokio::time::Instant::now() + Duration::from_secs(2),
            ),
        )
        .await
        .expect("certified quorum remains ready within the normal bound");
        assert_eq!(report.state(), crate::DurableReadinessState::Ready);
        assert_eq!(peer.profile_probes.load(Ordering::SeqCst), 0);
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn void_readiness_before_first_activation_needs_every_voters_proof() {
    let mut fleet = Fleet::new("void-readiness-before-activation");
    fleet
        .open_void_profiles_with_persistence([FencedTransitionV2Profile::V2WithVoid; 3], false)
        .await;
    let result = AssertUnwindSafe(async {
        let leader = fleet
            .stores
            .iter()
            .position(|store| store.status().leader_id == Some(store.status().node_id))
            .unwrap();
        let absent = (leader + 1) % 3;
        for store in &fleet.stores {
            let (identity, voters) = store.current_scope().unwrap();
            assert!(!store
                .inner
                .backend
                .consensus_fenced_transition_v2_activation_matches_scope(
                    store.inner.storage_identity,
                    identity,
                    voters,
                    FencedTransitionV2Profile::V2WithVoid.digest(),
                )
                .await
                .unwrap());
            *store
                .inner
                .fenced_transition_profile_admission
                .lock()
                .unwrap() = None;
        }
        let handler = fleet.peers[absent].handler.write().await.take();
        let reports = join_all(
            fleet
                .stores
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != absent)
                .map(|(_, store)| {
                    store.probe_fixed_quorum_readiness_before(
                        tokio::time::Instant::now() + Duration::from_secs(2),
                    )
                }),
        )
        .await;
        *fleet.peers[absent].handler.write().await = handler;
        for report in reports {
            assert_eq!(
                report.state(),
                crate::DurableReadinessState::NoQuorum,
                "a reachable majority alone cannot first admit the immutable void profile"
            );
        }
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

impl Fleet {
    async fn change_void_leader(&self) {
        let old = self
            .stores
            .iter()
            .position(|store| store.status().leader_id == Some(store.status().node_id))
            .unwrap();
        let successor = &self.stores[(old + 1) % self.stores.len()];
        successor.inner.raft.trigger().elect().await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if self
                    .stores
                    .iter()
                    .all(|store| store.status().leader_id == Some(successor.status().node_id))
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("successor leader on every voter");
    }

    async fn snapshot_void_receipts(&self) {
        for store in &self.stores {
            let before = store.status().completed_snapshot_count;
            store.inner.raft.trigger().snapshot().await.unwrap();
            tokio::time::timeout(Duration::from_secs(10), async {
                while store.status().completed_snapshot_count == before {
                    assert!(store.inner.raft.metrics().borrow().running_state.is_ok());
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("extended-profile snapshot completes");
        }
    }

    async fn open_void_profiles(&mut self, profiles: [crate::FencedTransitionV2Profile; 3]) {
        self.open_void_profiles_with_persistence(profiles, true)
            .await;
    }

    async fn open_void_profiles_with_persistence(
        &mut self,
        profiles: [crate::FencedTransitionV2Profile; 3],
        private_wal: bool,
    ) {
        assert!(self.stores.is_empty());
        self.incarnation += 1;
        for (index, profile) in profiles.into_iter().enumerate() {
            let mut backend = SqliteSessionBackend::open_with_fenced_transition_v2_profile(
                self.directory.path().join(format!("node-{index}.sqlite")),
                profile,
            )
            .expect("real SDK database");
            if private_wal {
                backend.private_wal_test = Some(Arc::clone(&self.tests[index]));
            }
            let peers = self
                .peers
                .iter()
                .enumerate()
                .filter(|(peer, _)| *peer != index)
                .map(|(_, peer)| {
                    let transport: Arc<dyn SessionConsensusPeer> = peer.clone();
                    (peer.node, transport)
                })
                .collect::<BTreeMap<_, _>>();
            let snapshot_directory = self
                .snapshot_root
                .as_deref()
                .unwrap_or(self.directory.path())
                .join(format!("snapshots-{index}"));
            let snapshot_integrity = if self.snapshot_root.is_some() {
                SnapshotIntegrityPolicy::FsVerity
            } else {
                SnapshotIntegrityPolicy::PortableVerified
            };
            let result =
                ConsensusSessionStore::open_fixed_durable_quorum_with_clock_and_snapshot_integrity(
                    self.topologies[index].clone(),
                    backend,
                    snapshot_directory,
                    peers,
                    self.clock
                        .clone()
                        .unwrap_or_else(|| Arc::new(crate::SystemClock)),
                    crate::DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
                    snapshot_integrity,
                )
                .await;
            match result {
                Ok(store) => self.stores.push(store),
                Err(error) => {
                    self.close().await;
                    panic!("private WAL SDK node {index} open failed: {error:?}");
                }
            }
        }
        for (peer, store) in self.peers.iter().zip(&self.stores) {
            *peer.handler.write().await = Some(store.rpc_handler());
            if private_wal {
                assert!(
                    store.inner.private_wal.is_some(),
                    "actual SDK store selected the private WAL"
                );
            }
        }
        // Every new store starts with local traffic admission disabled.
        // This existing API also verifies and admits nonpristine members;
        // persisted Raft membership alone cannot replace that SDK step.
        let results = join_all(
            self.stores
                .iter()
                .map(ConsensusSessionStore::initialize_cluster),
        )
        .await;
        if let Some(error) = results.iter().find_map(|result| result.as_ref().err()) {
            let error = format!("{error:?}");
            self.close().await;
            panic!("private WAL SDK admission failed: {error}");
        }
        let mixed = profiles.iter().any(|profile| *profile != profiles[0]);
        let ready = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let reports = join_all(
                    self.stores
                        .iter()
                        .map(|store| store.probe_fixed_durable_quorum_readiness()),
                )
                .await;
                if reports.iter().zip(profiles).all(|(report, profile)| {
                    if mixed && profile == FencedTransitionV2Profile::V2WithVoid {
                        report.durable_readiness().reason_code()
                            == "fenced_transition_profile_mismatch"
                    } else {
                        report.traffic_authority() == FixedQuorumTrafficAuthority::Granted
                    }
                }) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        if ready.is_err() {
            let metrics = self
                .stores
                .iter()
                .map(|store| format!("{:?}", *store.inner.raft.metrics().borrow()))
                .collect::<Vec<_>>();
            self.close().await;
            panic!("private WAL SDK readiness failed: {metrics:?}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_inspection_accepts_real_void_profile_replicas() {
    let mut fleet = Fleet::new("void-recovery-inspection");
    fleet
        .open_void_profiles_with_persistence([FencedTransitionV2Profile::V2WithVoid; 3], false)
        .await;
    let request = v2_create_request(
        307,
        FencedTransitionV2HistoryEpoch::new(1).unwrap(),
        FenceToken::new(0),
        &provider(),
    )
    .await;
    let result = AssertUnwindSafe(async {
        let expected =
            FencedTransitionV2Status::Recorded(Box::new(Err(StoreError::FencedTransitionVoided)));
        assert_eq!(
            fleet.stores[0]
                .fenced_transition_v2_void(&request)
                .await
                .unwrap(),
            expected
        );
        for store in &fleet.stores {
            assert_eq!(
                store.fenced_transition_v2_status(&request).await.unwrap(),
                expected
            );
        }
        fleet.snapshot_void_receipts().await;
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    for (index, topology) in fleet.topologies.iter().enumerate() {
        crate::recovery::inspect_consensus_replica_for_test(
            topology,
            &fleet.directory.path().join(format!("node-{index}.sqlite")),
            &fleet.directory.path().join(format!("snapshots-{index}")),
        )
        .expect("a healthy drained void-profile voter is healthy in offline recovery");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_three_voter_void_decides_before_original_and_survives_restart() {
    let mut fleet = Fleet::new_native("void-before-original");
    let profiles = [FencedTransitionV2Profile::V2WithVoid; 3];
    fleet.open_void_profiles(profiles).await;
    let result = AssertUnwindSafe(async {
        let request = v2_create_request(
            301,
            FencedTransitionV2HistoryEpoch::new(1).unwrap(),
            FenceToken::new(0),
            &provider(),
        )
        .await;
        let expected =
            FencedTransitionV2Status::Recorded(Box::new(Err(StoreError::FencedTransitionVoided)));
        assert_eq!(
            fleet.stores[0]
                .fenced_transition_v2_capability()
                .await
                .unwrap(),
            Some(FencedTransitionV2Capability::V2)
        );
        assert_eq!(
            fleet.stores[0]
                .fenced_transition_v2_void(&request)
                .await
                .unwrap(),
            expected
        );
        fleet.change_void_leader().await;
        for store in &fleet.stores {
            assert_eq!(
                store.fenced_transition_v2_status(&request).await.unwrap(),
                expected
            );
            assert_eq!(
                store.fenced_transition_v2(request.clone()).await,
                Err(StoreError::FencedTransitionVoided)
            );
            assert!(store.get(request.lease().key()).await.unwrap().is_none());
        }
        fleet.snapshot_void_receipts().await;
        fleet.close().await;
        fleet.open_void_profiles(profiles).await;
        for store in &fleet.stores {
            assert_eq!(
                store.fenced_transition_v2_void(&request).await.unwrap(),
                expected
            );
            assert_eq!(
                store.fenced_transition_v2(request.clone()).await,
                Err(StoreError::FencedTransitionVoided)
            );
            assert!(store.get(request.lease().key()).await.unwrap().is_none());
        }
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_three_voter_original_receipt_wins_over_later_void() {
    let mut fleet = Fleet::new_native("original-before-void");
    fleet
        .open_void_profiles([FencedTransitionV2Profile::V2WithVoid; 3])
        .await;
    let result = AssertUnwindSafe(async {
        let request = v2_create_request(
            302,
            FencedTransitionV2HistoryEpoch::new(1).unwrap(),
            FenceToken::new(0),
            &provider(),
        )
        .await;
        let outcome = fleet.stores[0]
            .fenced_transition_v2(request.clone())
            .await
            .unwrap();
        let expected = FencedTransitionV2Status::Recorded(Box::new(Ok(outcome)));
        fleet.change_void_leader().await;
        for store in &fleet.stores {
            assert_eq!(
                store.fenced_transition_v2_void(&request).await.unwrap(),
                expected
            );
            assert_eq!(
                store.fenced_transition_v2_status(&request).await.unwrap(),
                expected
            );
            assert_eq!(
                store
                    .get(request.lease().key())
                    .await
                    .unwrap()
                    .unwrap()
                    .generation,
                Generation::new(1)
            );
        }
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_three_voter_void_requires_every_voters_created_profile() {
    let mut fleet = Fleet::new_native("void-mixed-profiles");
    fleet
        .open_void_profiles([
            FencedTransitionV2Profile::V2WithVoid,
            FencedTransitionV2Profile::V2WithVoid,
            FencedTransitionV2Profile::V2,
        ])
        .await;
    let result = AssertUnwindSafe(async {
        let request = v2_create_request(
            303,
            FencedTransitionV2HistoryEpoch::new(1).unwrap(),
            FenceToken::new(0),
            &provider(),
        )
        .await;
        assert!(matches!(
            fleet.stores[0].fenced_transition_v2_void(&request).await,
            Err(StoreError::CapabilityNotSupported(_))
        ));
        for store in &fleet.stores {
            assert_eq!(
                store
                    .probe_fixed_durable_quorum_readiness()
                    .await
                    .durable_readiness()
                    .reason_code(),
                if store.inner.backend.fenced_transition_profile
                    == FencedTransitionV2Profile::V2WithVoid
                {
                    "fenced_transition_profile_mismatch"
                } else {
                    "ready"
                }
            );
            assert!(store.get(request.lease().key()).await.unwrap().is_none());
            let scope = store.inner.storage_identity;
            assert_eq!(
                store
                    .inner
                    .backend
                    .consensus_fenced_transition_v2_history_state(scope, scope)
                    .await
                    .unwrap()
                    .bound_entries(),
                0
            );
        }
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_three_voter_void_replays_the_deciding_receipt_without_a_second_effect() {
    for void_first in [false, true] {
        let mut fleet = Fleet::new("sql-void-ordering");
        fleet
            .open_void_profiles([FencedTransitionV2Profile::V2WithVoid; 3])
            .await;
        let result = AssertUnwindSafe(async {
            let request = v2_create_request(
                304,
                FencedTransitionV2HistoryEpoch::new(1).unwrap(),
                FenceToken::new(0),
                &provider(),
            )
            .await;
            let expected = if void_first {
                fleet.stores[0]
                    .fenced_transition_v2_void(&request)
                    .await
                    .unwrap()
            } else {
                FencedTransitionV2Status::Recorded(Box::new(Ok(fleet.stores[0]
                    .fenced_transition_v2(request.clone())
                    .await
                    .unwrap())))
            };
            for store in &fleet.stores {
                assert_eq!(
                    store.fenced_transition_v2_void(&request).await.unwrap(),
                    expected
                );
                let actual = store.fenced_transition_v2(request.clone()).await;
                if void_first {
                    assert_eq!(actual, Err(StoreError::FencedTransitionVoided));
                    assert!(store.get(request.lease().key()).await.unwrap().is_none());
                } else {
                    assert_eq!(
                        FencedTransitionV2Status::Recorded(Box::new(actual)),
                        expected
                    );
                    assert_eq!(
                        store
                            .get(request.lease().key())
                            .await
                            .unwrap()
                            .unwrap()
                            .generation,
                        Generation::new(1)
                    );
                }
                assert_eq!(
                    store.fenced_transition_v2_status(&request).await.unwrap(),
                    expected
                );
            }
        })
        .catch_unwind()
        .await;
        fleet.close().await;
        result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_three_voter_void_uses_quorum_after_exact_profile_activation() {
    let mut fleet = Fleet::new_native("void-activated-voter-unavailable");
    fleet
        .open_void_profiles([FencedTransitionV2Profile::V2WithVoid; 3])
        .await;
    let result = AssertUnwindSafe(async {
        let epoch = FencedTransitionV2HistoryEpoch::new(1).unwrap();
        let first = v2_create_request(305, epoch, FenceToken::new(0), &provider()).await;
        fleet.stores[0]
            .fenced_transition_v2(first.clone())
            .await
            .unwrap();
        for store in &fleet.stores {
            assert!(matches!(
                store.fenced_transition_v2_status(&first).await.unwrap(),
                FencedTransitionV2Status::Recorded(_)
            ));
        }
        let request = v2_create_request(306, epoch, FenceToken::new(0), &provider()).await;
        let leader = fleet
            .stores
            .iter()
            .position(|store| store.status().leader_id == Some(store.status().node_id))
            .unwrap();
        let absent = (leader + 1) % 3;
        let handler = fleet.peers[absent].handler.write().await.take();
        let outcome = fleet.stores[leader]
            .fenced_transition_v2_void(&request)
            .await;
        *fleet.peers[absent].handler.write().await = handler;
        assert_eq!(
            outcome.unwrap(),
            FencedTransitionV2Status::Recorded(Box::new(Err(StoreError::FencedTransitionVoided)))
        );
        for store in &fleet.stores {
            assert_eq!(
                store.fenced_transition_v2_status(&request).await.unwrap(),
                FencedTransitionV2Status::Recorded(Box::new(Err(
                    StoreError::FencedTransitionVoided
                )))
            );
            assert!(store.get(request.lease().key()).await.unwrap().is_none());
        }
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_reclaim_memory_void_fenced_voter_keeps_readiness_and_activation_bounded() {
    use crate::sqlite::consensus::wal::Point;

    let mut fleet = Fleet::new_native("void-fenced-voter-before-activation");
    let armed = Arc::new(AtomicUsize::new(usize::MAX));
    for (index, test) in fleet.tests.iter_mut().enumerate() {
        let armed = Arc::clone(&armed);
        *test = Arc::new(PrivateWalTest::new_native_with_hook(
            fleet.directory.path().join(format!("wal-{index}")),
            [index as u8 + 1; 32],
            Arc::new(move |point| {
                if point == Point::BeforeNativeApplyPrepare && armed.load(Ordering::SeqCst) == index
                {
                    // A terminal apply error takes the same native owner fence
                    // as retirement's no-progress timeout. The separate WAL
                    // test exercises that timeout under actual memory pressure.
                    Err(std::io::Error::other("test terminal native apply failure"))
                } else {
                    Ok(())
                }
            }),
        ));
    }
    fleet
        .open_void_profiles([FencedTransitionV2Profile::V2WithVoid; 3])
        .await;
    let result = AssertUnwindSafe(async {
        let leader = fleet
            .stores
            .iter()
            .position(|store| store.status().leader_id == Some(store.status().node_id))
            .unwrap();
        let failed = (leader + 1) % 3;
        let store = &fleet.stores[leader];
        let (identity, voters) = store.current_scope().unwrap();
        assert!(!store
            .inner
            .backend
            .consensus_fenced_transition_v2_activation_matches_scope(
                store.inner.storage_identity,
                identity,
                voters,
                FencedTransitionV2Profile::V2WithVoid.digest(),
            )
            .await
            .unwrap());
        armed.store(failed, Ordering::SeqCst);
        let encrypted = EncryptingSessionBackend::new(
            Arc::new(store.clone()),
            provider(),
            "void-fenced-readiness",
        );
        encrypted
            .acquire(
                &key(401),
                OwnerId::new("void-fenced-readiness").unwrap(),
                Duration::from_secs(60),
            )
            .await
            .expect("the two healthy voters can commit an ordinary lease");
        tokio::time::timeout(Duration::from_secs(5), async {
            while fleet.stores[failed]
                .inner
                .raft
                .metrics()
                .borrow()
                .running_state
                .is_ok()
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the failed apply fences the local consensus owner");
        let report = tokio::time::timeout(
            Duration::from_secs(3),
            fleet.stores[failed].probe_fixed_quorum_readiness_before(
                tokio::time::Instant::now() + Duration::from_secs(2),
            ),
        )
        .await
        .expect("local fenced readiness is bounded even with a cached proof");
        assert_ne!(report.state(), crate::DurableReadinessState::Ready);

        *store
            .inner
            .fenced_transition_profile_admission
            .lock()
            .unwrap() = None;
        // Capability describes the immutable profile, not liveness. The
        // fenced process can still answer it while its handler is installed.
        let report = tokio::time::timeout(
            Duration::from_secs(3),
            store.probe_fixed_quorum_readiness_before(
                tokio::time::Instant::now() + Duration::from_secs(2),
            ),
        )
        .await
        .unwrap();
        assert_eq!(report.state(), crate::DurableReadinessState::Ready);
        let proof = store
            .inner
            .fenced_transition_profile_admission
            .lock()
            .unwrap()
            .take();
        assert!(proof.is_some());
        *fleet.peers[failed].handler.write().await = None;
        for _ in 0..2 {
            let report = tokio::time::timeout(
                Duration::from_millis(750),
                store.probe_fixed_quorum_readiness_before(
                    tokio::time::Instant::now() + Duration::from_secs(2),
                ),
            )
            .await
            .expect("an absent pre-activation proof never leaves a call waiting");
            assert_eq!(report.state(), crate::DurableReadinessState::NoQuorum);
        }
        let request = v2_create_request(
            402,
            FencedTransitionV2HistoryEpoch::new(1).unwrap(),
            FenceToken::new(0),
            &provider(),
        )
        .await;
        let unavailable = tokio::time::timeout(
            crate::DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT + Duration::from_secs(2),
            store.fenced_transition_v2_void(&request),
        )
        .await
        .expect("first activation without every proof returns within its operation budget");
        assert!(matches!(
            unavailable,
            Err(StoreError::BackendUnavailable(_))
        ));
        *store
            .inner
            .fenced_transition_profile_admission
            .lock()
            .unwrap() = proof;
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(3),
                store.fenced_transition_v2_void(&request),
            )
            .await
            .expect("the exact-scope proof permits activation on the healthy quorum")
            .unwrap(),
            FencedTransitionV2Status::Recorded(Box::new(Err(StoreError::FencedTransitionVoided)))
        );
        assert!(store.get(request.lease().key()).await.unwrap().is_none());
    })
    .catch_unwind()
    .await;
    let shutdowns = join_all(fleet.stores.iter().map(ConsensusSessionStore::shutdown)).await;
    for peer in &fleet.peers {
        *peer.handler.write().await = None;
    }
    fleet.stores.clear();
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    assert_eq!(shutdowns.iter().filter(|result| result.is_err()).count(), 1);
}
