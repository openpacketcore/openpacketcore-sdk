//! One OS process per voter; the test process owns only clients and workload.

use super::*;
use opc_session_testkit::qualification::{
    QualificationIsolatedPersistence, QualificationIsolatedScaleConfig,
    QualificationIsolatedScaleReadiness, QualificationIsolatedScaleWorkload,
};

impl Fleet {
    fn shutdown_isolated_scale_joined(&mut self) {
        self.shutdown();
        for node in &mut self.nodes {
            assert!(
                node.child
                    .try_wait()
                    .expect("joined voter exit")
                    .expect("voter exited")
                    .success(),
                "clean shutdown must not hide a forced kill"
            );
        }
    }

    fn reopen_isolated_boundary(&mut self, scale: QualificationIsolatedScaleConfig) {
        assert_eq!(
            scale.workload,
            QualificationIsolatedScaleWorkload::BoundaryControl
        );
        self.verify_snapshot_namespace();
        let deadline = Instant::now() + Duration::from_secs(10);
        for index in 0..self.nodes.len() {
            assert!(self.nodes[index]
                .child
                .try_wait()
                .unwrap()
                .unwrap()
                .success());
            let previous_pid = self.nodes[index].process_id();
            let closed_stderr = self.stderr_paths[index].with_file_name("closed-live-stderr.log");
            assert!(!closed_stderr.exists());
            fs::copy(&self.stderr_paths[index], closed_stderr).expect("preserve live voter stderr");
            let address = self.members[index]
                .dial_addr
                .expect("exact configured voter address");
            let (node, actual) = ChildNode::spawn_bound_until(
                &self.config_paths[index],
                index,
                &self.stderr_paths[index],
                address,
                deadline,
                self._snapshot_leaves.get(index),
            );
            assert_eq!(actual, address);
            assert_ne!(node.process_id(), previous_pid);
            self.nodes[index] = node;
        }
        for node in &mut self.nodes {
            node.send(&QualificationNodeCommand::Configure);
        }
        for (index, node) in self.nodes.iter_mut().enumerate() {
            assert!(
                matches!(node.receive_until(deadline), QualificationNodeReply::Started {
                node_index,
            } if node_index == index)
            );
        }
        for node in &mut self.nodes {
            node.send(&QualificationNodeCommand::Initialize);
        }
        for node in &mut self.nodes {
            let reply = node.receive_until(deadline);
            match scale.persistence {
                QualificationIsolatedPersistence::Durable => {
                    assert!(matches!(reply, QualificationNodeReply::Initialized));
                }
                QualificationIsolatedPersistence::Async => {
                    assert!(matches!(
                        reply,
                        QualificationNodeReply::Error {
                            code: QualificationNodeErrorCode::InitializationUnavailable,
                        }
                    ));
                }
            }
        }
        self.verify_snapshot_namespace();
    }

    fn isolated_scale_reports(&mut self) -> Vec<QualificationIsolatedScaleReadiness> {
        let deadline = Instant::now() + Duration::from_secs(10);
        self.isolated_scale_reports_by(deadline)
    }

    fn isolated_scale_reports_by(
        &mut self,
        deadline: Instant,
    ) -> Vec<QualificationIsolatedScaleReadiness> {
        for node in &mut self.nodes {
            node.send(&QualificationNodeCommand::IsolatedScaleProbe);
        }
        self.nodes
            .iter_mut()
            .map(|node| match node.receive_until(deadline) {
                QualificationNodeReply::IsolatedScaleReadiness { status } => status,
                reply => panic!("explicit scale readiness failed: {reply:?}"),
            })
            .collect()
    }

    fn wait_isolated_scale_ready(&mut self, scale: QualificationIsolatedScaleConfig) -> usize {
        let deadline = Instant::now() + Duration::from_secs(10);
        let expected_ids = self
            .stateless_consumer_voter_authorities()
            .iter()
            .map(|authority| authority.node_id().get())
            .collect::<Vec<_>>();
        let mut expected_ids = expected_ids;
        expected_ids.sort_unstable();
        loop {
            let reports = self.isolated_scale_reports_by(deadline);
            for report in &reports {
                assert_eq!(report.persistence, scale.persistence);
                assert_eq!(report.configured_voter_ids, expected_ids);
                assert!(!report.storage_failed);
            }
            if let Some(leader) = reports[0].leader_id {
                if reports.iter().all(|report| {
                    report.ready
                        && report.engine_running
                        && report.leader_id == Some(leader)
                        && report.committed_index.is_some()
                        && report.applied_index >= report.committed_index
                }) {
                    return reports
                        .iter()
                        .position(|report| report.node_id == leader)
                        .expect("leader is an exact configured voter");
                }
            }
            assert!(
                Instant::now() < deadline,
                "original ten-second setup deadline"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn run_isolated_scale_boundary(persistence: QualificationIsolatedPersistence) {
    let scale = QualificationIsolatedScaleConfig {
        persistence,
        workload: QualificationIsolatedScaleWorkload::BoundaryControl,
    };
    let mut fleet = Fleet::start_with_settings(3, scale.schedule_sha256(), None, Some(scale));
    let leader = fleet.wait_isolated_scale_ready(scale);
    let process_ids = fleet
        .nodes
        .iter()
        .map(ChildNode::process_id)
        .collect::<Vec<_>>();
    assert_eq!(
        process_ids
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3
    );
    assert!(process_ids.iter().all(|pid| *pid != std::process::id()));
    // The legacy probe must retain its durable-acknowledgement meaning.
    if persistence == QualificationIsolatedPersistence::Async {
        assert!(matches!(
            fleet.nodes[leader].invoke(&QualificationNodeCommand::Probe),
            QualificationNodeReply::Readiness { ready: false, .. }
        ));
    }
    let identities = (0..12).map(stateless_consumer_identity).collect::<Vec<_>>();
    let (endpoint, scope) = fleet.start_stateless_consumer(leader, identities.clone());
    let endpoints = Arc::new(Mutex::new(vec![endpoint; 3]));
    let authority = fleet.stateless_consumer_voter_authorities()[leader].clone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("isolated scale driver runtime");
    let (identity_source, client) = qualification_persistent_v2_client(
        endpoints,
        leader,
        authority,
        fleet.pki.consumer_identity_state(&identities[0]),
        PersistentSessionConsumerConfig::default(),
        Some(Duration::from_millis(800)),
    );
    let (request, outcome) = runtime.block_on(async {
        client
            .prewarm_v2()
            .await
            .expect("real scale consumer mTLS lanes");
        let request = qualification_fenced_transition_v2_request(3, 0).await;
        let started = Instant::now();
        let result = client
            .execute_v2(&SessionConsumerV2Request::new(
                scope,
                SessionConsumerV2Operation::FencedTransitionV2 {
                    request: Box::new(request.clone()),
                },
            ))
            .await
            .expect("public scale boundary mutation");
        assert!(
            started.elapsed() < Duration::from_millis(800),
            "original batch deadline"
        );
        let outcome = match result {
            SessionConsumerV2Response::FencedTransitionV2(Ok(outcome)) => outcome,
            response => panic!("scale mutation must have an exact typed outcome: {response:?}"),
        };
        assert!(outcome.matches_v2_request(&request));
        assert!(
            matches!(client.execute_v2(&SessionConsumerV2Request::new(scope,
                SessionConsumerV2Operation::FencedTransitionV2Status { request: Box::new(request.clone()) },
            )).await.expect("public exact scale receipt"),
                SessionConsumerV2Response::FencedTransitionV2Status(Ok(
                    SessionConsumerV2FencedTransitionStatus::Recorded(result)
                )) if result.as_ref() == &Ok(outcome.clone())
            )
        );
        client.shutdown().await;
        (request, outcome)
    });
    drop(identity_source);
    let state =
        match fleet.nodes[leader].invoke(&QualificationNodeCommand::IsolatedScaleHistoryState) {
            QualificationNodeReply::IsolatedScaleHistory { state } => state,
            reply => panic!("exact scale history state: {reply:?}"),
        };
    assert_eq!(state.bound_entries(), 1);
    assert!(
        matches!(fleet.nodes[leader].invoke(&QualificationNodeCommand::IsolatedScaleMaintainHistory {
        expected_state: state,
    }), QualificationNodeReply::IsolatedScaleHistory { state: after } if after == state)
    );
    let reports = fleet.isolated_scale_reports();
    assert!(reports
        .iter()
        .all(|report| report.ready && !report.storage_failed));
    fleet.shutdown_isolated_scale_joined();
    fleet.reopen_isolated_boundary(scale);
    let cold_process_ids = fleet
        .nodes
        .iter()
        .map(ChildNode::process_id)
        .collect::<Vec<_>>();
    assert!(cold_process_ids
        .iter()
        .all(|pid| !process_ids.contains(pid)));
    match persistence {
        QualificationIsolatedPersistence::Durable => {
            let leader = fleet.wait_isolated_scale_ready(scale);
            let (endpoint, cold_scope) = fleet.start_stateless_consumer(leader, identities.clone());
            assert_eq!(cold_scope, scope);
            let (source, client) = qualification_persistent_v2_client(
                Arc::new(Mutex::new(vec![endpoint; 3])),
                leader,
                fleet.stateless_consumer_voter_authorities()[leader].clone(),
                fleet.pki.consumer_identity_state(&identities[0]),
                PersistentSessionConsumerConfig::default(),
                Some(Duration::from_millis(800)),
            );
            runtime.block_on(async {
                client.prewarm_v2().await.expect("cold durable consumer lanes");
                let status = client.execute_v2(&SessionConsumerV2Request::new(scope,
                    SessionConsumerV2Operation::FencedTransitionV2Status { request: Box::new(request.clone()) },
                )).await.expect("cold durable exact receipt");
                assert!(matches!(status, SessionConsumerV2Response::FencedTransitionV2Status(Ok(
                    SessionConsumerV2FencedTransitionStatus::Recorded(result)
                )) if result.as_ref() == &Ok(outcome.clone())));
                let started = Instant::now();
                let replay = client.execute_v2(&SessionConsumerV2Request::new(scope,
                    SessionConsumerV2Operation::FencedTransitionV2 { request: Box::new(request.clone()) },
                )).await.expect("cold durable exact replay");
                assert!(started.elapsed() < Duration::from_millis(800));
                assert!(matches!(replay, SessionConsumerV2Response::FencedTransitionV2(Ok(result)) if result == outcome));
                client.shutdown().await;
            });
            drop(source);
        }
        QualificationIsolatedPersistence::Async => {
            // Persisted Async roots retain their recovery quarantine even
            // after joined shutdown. Three cold roots cannot attest a live quorum.
            let negative_guard = Instant::now() + Duration::from_secs(1);
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let cold = fleet.isolated_scale_reports_by(deadline);
                assert!(cold.iter().all(|report| !report.ready
                    && report.awaiting_live_quorum
                    && !report.storage_failed));
                if Instant::now() >= negative_guard {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
    let cold_reports = fleet.isolated_scale_reports();
    fleet.shutdown_isolated_scale_joined();
    eprintln!(
        "sdk_isolated_scale_boundary={}",
        serde_json::json!({
            "configuration": scale, "driver_pid": std::process::id(), "voter_pids": process_ids,
            "workspace": fleet.workspace.path(), "reports": reports, "joined_shutdown": true,
            "cold_voter_pids": cold_process_ids, "cold_reports": cold_reports,
            "cold_durable_receipt_and_replay": persistence == QualificationIsolatedPersistence::Durable,
            "cold_async_quarantined": persistence == QualificationIsolatedPersistence::Async,
            "full_cardinality": false, "performance_acceptance": false,
        })
    );
}

#[test]
fn isolated_async_voters_preserve_public_receipts_and_joined_shutdown() {
    run_isolated_scale_boundary(QualificationIsolatedPersistence::Async);
}

#[test]
fn isolated_durable_voters_preserve_public_receipts_and_joined_shutdown() {
    run_isolated_scale_boundary(QualificationIsolatedPersistence::Durable);
}
