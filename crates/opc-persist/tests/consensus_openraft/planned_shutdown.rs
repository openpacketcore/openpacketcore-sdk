use super::*;
use opc_consensus::{PlannedShutdownFallback, PlannedShutdownOutcome};

pub(super) struct TransferGate {
    captured: tokio::sync::mpsc::Sender<ConsensusWireRequest>,
    release: tokio::sync::watch::Receiver<bool>,
}

impl TransferGate {
    pub(super) async fn before_delivery(&self, request: &ConsensusWireRequest) {
        self.captured.send(request.clone()).await.unwrap();
        let mut release = self.release.clone();
        release.wait_for(|released| *released).await.unwrap();
    }
}

fn hold_transfer(
    cluster: &ThreeNodeCluster,
    leader: usize,
) -> (
    tokio::sync::mpsc::Receiver<ConsensusWireRequest>,
    tokio::sync::watch::Sender<bool>,
) {
    let (captured, receiver) = tokio::sync::mpsc::channel(8);
    let (release, released) = tokio::sync::watch::channel(false);
    let gate = Arc::new(TransferGate {
        captured,
        release: released,
    });
    for ((source, _), peer) in &cluster.paths {
        if *source == leader {
            *peer.transfer_gate.lock().unwrap() = Some(gate.clone());
        }
    }
    (receiver, release)
}

/// Keep disk work off the protocol clock. Even the earliest ordinary election
/// needs the unchanged eight-second lease plus five-second election timeout.
/// A planned stop must hand off while its authenticated transport is still up.
#[tokio::test(start_paused = true)]
async fn planned_leader_stop_preserves_write_stream_within_operation_budget() {
    scripted_election::schedule::with_frozen_time(async {
        let budget = DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout();
        let cluster = ThreeNodeCluster::build_with_operation_timeout(
            [[0x55; 32]; 3],
            FixtureStorage::Legacy,
            None,
            None,
            Duration::ZERO,
            budget,
        )
        .await;
        let (one, two, three) = tokio::join!(
            cluster.stores[0].initialize_cluster(),
            cluster.stores[1].initialize_cluster(),
            cluster.stores[2].initialize_cluster(),
        );
        one.unwrap();
        two.unwrap();
        three.unwrap();
        cluster.wait_ready().await;
        let leader = cluster.leader();
        let survivors: Vec<_> = (0..3).filter(|index| *index != leader).collect();
        let first = TxId::new();
        cluster.stores[leader]
            .append_attested_commit(attested(commit(first, None, 1, 10), audit(first)))
            .await
            .unwrap();

        // The second write is accepted and replicated, but its original client
        // response is in flight when shutdown begins. Retain its ID for recovery.
        let second = TxId::new();
        let request = ConfigConsensusRequestId::from_bytes([0x81; 16]);
        let second_record = commit(second, Some(first), 2, 11);
        let second_audit = audit(second);
        let accepted = attested(second_record.clone(), second_audit.clone());
        let path = &cluster.paths[&(survivors[0], leader)];
        path.pause_forward_response.store(true, Ordering::SeqCst);
        let caller = cluster.stores[survivors[0]].clone();
        let in_flight = tokio::spawn(async move {
            let started_at = tokio::time::Instant::now();
            let result = caller
                .append_commit_idempotent(
                    request,
                    accepted,
                )
                .await;
            (result, started_at, tokio::time::Instant::now())
        });
        path.forward_response_ready.notified().await;
        let (lagged, mut lag) = tokio::sync::mpsc::unbounded_channel();
        for ((source, _), path) in &cluster.paths {
            if *source == leader {
                *path.transfer_lag.lock().unwrap() = Some(lagged.clone());
            }
        }
        let stopped_at = tokio::time::Instant::now();
        let shutdown = cluster.stores[leader].shutdown();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                result = &mut shutdown => {
                    result.unwrap();
                    break;
                }
                Some((node, required)) = lag.recv() => {
                    // A real LogNotApplied response starts the store's retry
                    // wait. Let disk/apply work finish without consuming its
                    // budget, then advance only the bounded control retry.
                    let target = cluster.stores.iter().find(|store| store.status().node_id == node).unwrap();
                    while target.status().applied_index.is_none_or(|applied| applied < required) {
                        tokio::task::yield_now().await;
                    }
                    tokio::time::advance(Duration::from_millis(100)).await;
                }
            }
        }
        assert!(stopped_at.elapsed() < budget, "handoff preserves the original operation budget");
        cluster.isolate(leader);

        let mut parent = second;
        let mut version = 3;
        let mut outages = Vec::new();
        // Exercise every surviving local authority route once per second,
        // through an instant strictly beyond the complete operation budget.
        // A failed proposal is never silently retried as a different request.
        for tick in 0..=11 {
            if tick > 0 {
                tokio::time::advance(Duration::from_secs(1)).await;
            }
            let tx = TxId::new();
            let record = commit(tx, Some(parent), version, 12);
            let audit = audit(tx);
            let mut committed = false;
            for survivor in &survivors {
                let result = cluster.stores[*survivor]
                    .append_attested_commit_local(attested(
                        record.clone(),
                        audit.clone(),
                    ))
                    .await;
                if result.is_ok() {
                    committed = true;
                    parent = tx;
                    version += 1;
                    break;
                }
            }
            if !committed {
                outages.push(stopped_at.elapsed());
            }
        }
        let (result, started_at, completed_at) = in_flight.await.unwrap();
        result.expect("same-ID retry recovers the applied result from the successor");
        let elapsed = completed_at.duration_since(started_at);
        assert!(elapsed < budget, "same-ID recovery preserves the original operation budget: {elapsed:?}");
        eprintln!(
            "planned stop: in_flight=applied, elapsed={elapsed:?}, operation_budget={budget:?}, unavailable_at={outages:?}",
        );
        assert!(
            outages.is_empty(),
            "planned shutdown returned without a writable successor; outages={outages:?}, budget={budget:?}"
        );
        cluster.stores[survivors[0]]
            .append_commit_idempotent(
                request,
                attested(second_record, second_audit),
            )
            .await
            .expect("same-ID recovery finds the accepted write after handoff");

        let successor = survivors.iter().copied().find(|index| {
            let status = cluster.stores[*index].status();
            status.leader_id == Some(status.node_id)
        }).expect("surviving leader after the write stream");
        let history = cluster.stores[successor]
            .load_since(ConfigVersion::INITIAL, 64)
            .await
            .expect("committed history after automatic and explicit same-ID retries");
        assert_eq!(history.len() as u64, version - 1);
        assert_eq!(history[1].record.tx_id, second);
        assert_eq!(history[1].record.version, ConfigVersion::new(2));
        assert_eq!(history.last().unwrap().record.tx_id, parent);
        let applied_sequence: u64 = rusqlite::Connection::open(cluster.database_path(successor))
            .expect("open successor for effect-count inspection")
            .query_row(
                "SELECT application_sequence FROM config_raft_machine WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("read the durable application effect count");
        assert_eq!(applied_sequence, version - 1, "same-ID retries must not apply the accepted write twice");
        cluster.shutdown().await;
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn cancelled_shutdown_observer_keeps_one_handoff_and_rejects_forged_requests() {
    scripted_election::schedule::with_frozen_time(async {
        let cluster = ThreeNodeCluster::start().await;
        let leader = cluster.leader();
        let leader_id = cluster.stores[leader].status().node_id;
        let term = cluster.stores[leader].status().term;
        let survivors: Vec<_> = (0..3).filter(|index| *index != leader).collect();
        let (mut captured, release) = hold_transfer(&cluster, leader);
        let store = cluster.stores[leader].clone();
        let observer = tokio::spawn(async move { store.shutdown_with_report().await });
        let exact = captured
            .recv()
            .await
            .expect("owned handoff reached transport");
        observer.abort();
        assert!(observer.await.unwrap_err().is_cancelled());
        assert!(!cluster.stores[leader].status().admitted);
        let tx = TxId::new();
        assert!(
            cluster.stores[leader]
                .append_attested_commit_local(attested(commit(tx, None, 1, 10), audit(tx)))
                .await
                .is_err(),
            "cancelled observer cannot reopen proposal admission"
        );

        let handler = cluster.stores[survivors[0]].rpc_handler();
        let other_id = cluster.stores[survivors[1]].status().node_id;
        for (sender, request, compatibility) in [
            (other_id, exact.clone(), handler.compatibility()),
            (
                other_id,
                ConsensusWireRequest {
                    sender: other_id,
                    ..exact.clone()
                },
                handler.compatibility(),
            ),
            (
                leader_id,
                ConsensusWireRequest {
                    identity: topology().identity(),
                    ..exact.clone()
                },
                handler.compatibility(),
            ),
            (leader_id, exact.clone(), Some([0; 32])),
        ] {
            assert_eq!(
                handler
                    .handle_with_compatibility(sender, request, compatibility)
                    .await
                    .result,
                Err(ConsensusPeerError::ScopeMismatch)
            );
        }
        assert_eq!(
            handler
                .handle_with_compatibility(
                    leader_id,
                    ConsensusWireRequest {
                        payload: Vec::new(),
                        ..exact.clone()
                    },
                    handler.compatibility()
                )
                .await
                .result,
            Err(ConsensusPeerError::Protocol)
        );
        assert!(cluster
            .stores
            .iter()
            .all(|store| store.status().term == term));
        release.send_replace(true);
        let report = cluster.stores[leader].shutdown_with_report().await.unwrap();
        let PlannedShutdownOutcome::LeaderTransferred { successor } = report else {
            panic!("expected a confirmed successor: {report:?}");
        };
        assert_ne!(successor, leader_id);
        assert_eq!(captured.try_recv().unwrap(), exact);
        assert!(captured.try_recv().is_err());
        assert_eq!(
            cluster.stores[leader].shutdown_with_report().await.unwrap(),
            report
        );
        assert!(
            captured.try_recv().is_err(),
            "a clone observes the retained result"
        );
        assert!(!cluster.stores[leader].status().admitted);

        let response = handler
            .handle_with_compatibility(leader_id, exact, handler.compatibility())
            .await;
        let (_, stale): (
            u16,
            Result<
                (),
                opc_consensus::engine::error::RaftError<
                    ConfigConsensusNodeId,
                    opc_consensus::engine::raft::TransferLeaderError,
                >,
            >,
        ) = opc_consensus::decode_bounded(&response.result.unwrap()).unwrap();
        assert_eq!(
            stale,
            Err(opc_consensus::engine::error::RaftError::APIError(
                opc_consensus::engine::raft::TransferLeaderError::VoteChanged
            ))
        );
        cluster.isolate(leader);
        let successor = cluster
            .stores
            .iter()
            .position(|store| store.status().node_id == successor)
            .unwrap();
        cluster.stores[successor]
            .append_attested_commit_local(attested(commit(tx, None, 1, 10), audit(tx)))
            .await
            .unwrap();
        cluster.shutdown().await;
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn stalled_handoff_falls_back_once_within_the_original_shutdown_budget() {
    scripted_election::schedule::with_frozen_time(async {
        let cluster = ThreeNodeCluster::start().await;
        let leader = cluster.leader();
        let (mut captured, _release) = hold_transfer(&cluster, leader);
        let store = cluster.stores[leader].clone();
        let started = tokio::time::Instant::now();
        let stopping = tokio::spawn(async move { store.shutdown_with_report().await });
        captured
            .recv()
            .await
            .expect("handoff entered its owned deadline");
        let handoff_budget = opc_consensus::planned_shutdown_timeout(Duration::from_secs(3));
        tokio::time::advance(handoff_budget + Duration::from_millis(1)).await;
        let report = stopping
            .await
            .unwrap()
            .expect("fallback still joins the engine");
        assert_eq!(
            report,
            PlannedShutdownOutcome::Fallback {
                reason: PlannedShutdownFallback::SurvivingQuorumUnavailable,
            }
        );
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(!cluster.stores[leader].status().admitted);
        assert_eq!(
            cluster.stores[leader].shutdown_with_report().await.unwrap(),
            report
        );
        assert!(
            captured.try_recv().is_err(),
            "failed handoff is never restarted"
        );
        cluster.shutdown().await;
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn failed_listener_drain_suppresses_handoff_across_cancelled_clones() {
    use futures_util::FutureExt;
    scripted_election::schedule::with_frozen_time(async {
        let cluster = ThreeNodeCluster::start().await;
        let leader = cluster.leader();
        let (mut captured, release) = hold_transfer(&cluster, leader);
        release.send_replace(true);
        // Join/remove the failed inbound listener while leaving outbound calls
        // visible, so a forbidden handoff cannot hide behind a blocked link.
        for ((_, target), peer) in &cluster.paths {
            if *target == leader {
                *peer.handler.write().await = None;
            }
        }
        assert!(cluster.stores[leader]
            .shutdown_unplanned()
            .now_or_never()
            .is_none());
        assert!(!cluster.stores[leader].status().admitted);
        let observer = cluster.stores[leader].clone();
        assert_eq!(
            observer.shutdown_with_report().await.unwrap(),
            PlannedShutdownOutcome::Fallback {
                reason: PlannedShutdownFallback::Unplanned
            }
        );
        assert!(
            captured.try_recv().is_err(),
            "failed listener drain sends no leadership transfer"
        );
        let tx = TxId::new();
        assert!(observer
            .append_attested_commit_local(attested(commit(tx, None, 1, 10), audit(tx)))
            .await
            .is_err());
        observer.shutdown_unplanned().await.unwrap();
        assert!(
            captured.try_recv().is_err(),
            "repeated observers cannot restart handoff"
        );
        cluster.shutdown().await;
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn unplanned_drain_cancels_an_outstanding_handoff_before_joining() {
    scripted_election::schedule::with_frozen_time(async {
        let cluster = ThreeNodeCluster::start().await;
        let leader = cluster.leader();
        let (mut captured, _release) = hold_transfer(&cluster, leader);
        let store = cluster.stores[leader].clone();
        let planned = tokio::spawn(async move { store.shutdown_with_report().await });
        captured
            .recv()
            .await
            .expect("original preparation reached transport");
        cluster.stores[leader].shutdown_unplanned().await.unwrap();
        assert_eq!(
            planned.await.unwrap().unwrap(),
            PlannedShutdownOutcome::Fallback {
                reason: PlannedShutdownFallback::Unplanned
            }
        );
        assert!(
            captured.try_recv().is_err(),
            "cancellation never starts the successor transfer"
        );
        assert!(!cluster.stores[leader].status().admitted);
        cluster.shutdown().await;
    })
    .await;
}
