//! One OS process per voter; the test process owns only clients and workload.

#[path = "isolated_scale/majority_recovery.rs"]
mod majority_recovery;
#[path = "isolated_scale/original.rs"]
mod original;

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
            assert!(matches!(
                node.receive_until(deadline),
                QualificationNodeReply::Initialized
            ));
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
                _ => panic!("explicit scale readiness reply has the wrong type"),
            })
            .collect()
    }

    fn wait_isolated_scale_ready(&mut self, scale: QualificationIsolatedScaleConfig) -> usize {
        let deadline = Instant::now() + Duration::from_secs(10);
        let expected_ids =
            if scale.workload == QualificationIsolatedScaleWorkload::RetainedRecoveryControl {
                let topology =
                    fixed_voter_topology_for_configuration_with_root(&self.members, "v1", 1, None);
                self.members
                    .iter()
                    .map(|member| {
                        topology
                            .consensus_node_id(&ReplicaId::new(member.replica_id.clone()).unwrap())
                            .unwrap()
                            .get()
                    })
                    .collect::<Vec<_>>()
            } else {
                self.stateless_consumer_voter_authorities()
                    .iter()
                    .map(|authority| authority.node_id().get())
                    .collect::<Vec<_>>()
            };
        let mut expected_ids = expected_ids;
        expected_ids.sort_unstable();
        loop {
            let reports = self.isolated_scale_reports_by(deadline);
            for report in &reports {
                assert_eq!(report.persistence, scale.persistence);
                assert!(report.configured_voter_ids == expected_ids);
                assert!(!report.storage_failed);
            }
            let term = reports
                .iter()
                .map(|report| report.term)
                .max()
                .expect("configured voter reports");
            if let Some(leader) = reports[0].leader_id {
                if reports.iter().all(|report| {
                    report.ready
                        && report.engine_running
                        && report.term == term
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
            _ => panic!("scale mutation must have an exact successful outcome"),
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
            _ => panic!("exact scale history reply has the wrong type"),
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
    // Every prior OS process completed public shutdown on its retained root.
    // Async must consume that proof and regain usable authority as Durable does.
    // This does not model unclean process loss or lost acknowledged history.
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
        client.prewarm_v2().await.expect("reopened consumer lanes");
        let status = client.execute_v2(&SessionConsumerV2Request::new(scope,
            SessionConsumerV2Operation::FencedTransitionV2Status { request: Box::new(request.clone()) },
        )).await.expect("reopened exact receipt");
        assert!(matches!(status, SessionConsumerV2Response::FencedTransitionV2Status(Ok(
            SessionConsumerV2FencedTransitionStatus::Recorded(result)
        )) if result.as_ref() == &Ok(outcome.clone())));
        let started = Instant::now();
        let replay = client.execute_v2(&SessionConsumerV2Request::new(scope,
            SessionConsumerV2Operation::FencedTransitionV2 { request: Box::new(request.clone()) },
        )).await.expect("reopened exact replay");
        assert!(started.elapsed() < Duration::from_millis(800));
        assert!(matches!(replay, SessionConsumerV2Response::FencedTransitionV2(Ok(result)) if result == outcome));
        let next = qualification_fenced_transition_v2_request(3, 1).await;
        let started = Instant::now();
        let response = client.execute_v2(&SessionConsumerV2Request::new(scope,
            SessionConsumerV2Operation::FencedTransitionV2 { request: Box::new(next.clone()) },
        )).await.expect("new operation after retained-root recovery");
        assert!(started.elapsed() < Duration::from_millis(800));
        let result = match response {
            SessionConsumerV2Response::FencedTransitionV2(Ok(result)) => result,
            _ => panic!("new operation must have an exact successful outcome"),
        };
        assert!(result.matches_v2_request(&next));
        let status = client.execute_v2(&SessionConsumerV2Request::new(scope,
            SessionConsumerV2Operation::FencedTransitionV2Status { request: Box::new(next) },
        )).await.expect("new operation has a committed receipt");
        assert!(matches!(status, SessionConsumerV2Response::FencedTransitionV2Status(Ok(
            SessionConsumerV2FencedTransitionStatus::Recorded(recorded)
        )) if recorded.as_ref() == &Ok(result)));
        client.shutdown().await;
    });
    drop(source);
    let cold_reports = fleet.isolated_scale_reports();
    assert!(cold_reports
        .iter()
        .all(|report| report.ready && !report.storage_failed));
    fleet.shutdown_isolated_scale_joined();
    eprintln!(
        "sdk_isolated_scale_boundary={}",
        serde_json::json!({
            "configuration": scale, "driver_pid": std::process::id(), "voter_pids": process_ids,
            "workspace": fleet.workspace.path(), "live_ready_voters": reports.len(), "joined_shutdown": true,
            "cold_voter_pids": cold_process_ids, "cold_ready_voters": cold_reports.len(),
            "cold_durable_receipt_and_replay": persistence == QualificationIsolatedPersistence::Durable,
            "cold_receipt_and_replay": true, "post_reopen_operation": true,
            "cold_async_quarantined": false,
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
