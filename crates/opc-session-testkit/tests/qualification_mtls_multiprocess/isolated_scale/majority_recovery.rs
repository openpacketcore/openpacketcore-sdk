//! Abrupt OS-process loss with retained roots and production mTLS replication.
//! These functional controls do not qualify packet continuity or performance.

use super::*;

fn recover_unclean(fleet: &mut Fleet, scale: QualificationIsolatedScaleConfig) -> usize {
    let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    loop {
        for node in &mut fleet.nodes {
            node.send(&QualificationNodeCommand::Initialize);
        }
        let mut initialized = true;
        for node in &mut fleet.nodes {
            match node.receive_until(deadline) {
                QualificationNodeReply::Initialized => {}
                QualificationNodeReply::Error {
                    code: QualificationNodeErrorCode::InitializationUnavailable,
                } => initialized = false,
                _ => panic!("recovery initialization returned an unexpected classification"),
            }
        }
        if initialized {
            let reports = fleet.isolated_scale_reports_by(deadline);
            if reports.iter().all(|report| {
                report.ready
                    && (scale.persistence == QualificationIsolatedPersistence::Durable
                        || report.async_active)
            }) {
                return fleet.wait_isolated_scale_ready(scale);
            }
        }
        assert!(
            Instant::now() < deadline,
            "original cluster transition deadline"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn unclean_return(
    all_cold: bool,
    persistence: QualificationIsolatedPersistence,
    workload: QualificationIsolatedScaleWorkload,
) {
    unclean_return_with_tail(all_cold, persistence, workload, false);
}

fn unclean_return_with_tail(
    all_cold: bool,
    persistence: QualificationIsolatedPersistence,
    workload: QualificationIsolatedScaleWorkload,
    volatile_q1: bool,
) {
    let scale = QualificationIsolatedScaleConfig {
        persistence,
        workload,
    };
    let mut fleet = Fleet::start_with_settings(3, scale.schedule_sha256(), None, Some(scale));
    let survivor = fleet.wait_isolated_scale_ready(scale);
    let original_process = fleet.nodes[survivor].process_id();
    let before = fleet.isolated_scale_reports();
    let provider = (workload == QualificationIsolatedScaleWorkload::ProtectedRecoveryControl
        && persistence == QualificationIsolatedPersistence::Async)
        .then(|| {
            let identity =
                stateless_consumer_voter_topology_for_configuration(&fleet.members, "v1", 1)
                    .consensus_identity()
                    .expect("same protected scope");
            opc_session_testkit::qualification::protected_recovery::Journal::open(
                fleet.workspace.path(),
                identity,
            )
            .expect("retained external owner")
        });
    let old_issued_at = Instant::now();
    let old_fence = match fleet.nodes[survivor].invoke(&QualificationNodeCommand::Acquire {
        lease_handle: "recovery-old".to_owned(),
        stable_id: "recovery-key".to_owned(),
        owner: "recovery-before".to_owned(),
        ttl_millis: 60_000,
    }) {
        QualificationNodeReply::LeaseAcquired { fence } => fence,
        _ => panic!("initial authority acquisition failed"),
    };
    if let Some(provider) = &provider {
        provider
            .effect(1, old_fence, false)
            .expect("retained prepared external intent");
        provider
            .effect(2, old_fence, true)
            .expect("external effect whose Q1 may be absent");
    }
    assert!(matches!(
        fleet.nodes[survivor].invoke(&QualificationNodeCommand::CompareAndSet {
            lease_handle: "recovery-old".to_owned(),
            stable_id: "recovery-key".to_owned(),
            expected_generation: None,
            new_generation: 1,
            value: "before".to_owned(),
        }),
        QualificationNodeReply::CompareAndSet {
            applied: true,
            current_generation: Some(1)
        }
    ));
    if persistence == QualificationIsolatedPersistence::Durable {
        // Durable restart preserves acknowledged authority. Revoke the old
        // lease explicitly, retaining its handle for the delayed-write probe.
        assert!(matches!(
            fleet.nodes[survivor].invoke(&QualificationNodeCommand::Release {
                lease_handle: "recovery-old".to_owned(),
            }),
            QualificationNodeReply::Released
        ));
    }
    if volatile_q1 {
        assert!(all_cold && provider.is_some());
        // Complete the earlier generation before faulting the real writer.
        let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
        let applied = fleet
            .isolated_scale_reports()
            .iter()
            .filter_map(|r| r.applied_index)
            .max();
        loop {
            if fleet
                .isolated_scale_reports_by(deadline)
                .iter()
                .all(|r| r.completed_applied_index >= applied)
            {
                break;
            }
            assert!(Instant::now() < deadline);
        }
        fs::write(
            fleet.workspace.path().join("fail-async-generations"),
            b"synthetic ENOSPC before native generation publication",
        )
        .unwrap();
    }
    let mut prepared_roster = provider.as_ref().map(|provider| {
        super::protected_roster::Prepared::start(&mut fleet, survivor, provider.clone())
    });
    if volatile_q1 {
        prepared_roster.as_mut().unwrap().execute_one();
    }
    let admission_applied = fleet
        .isolated_scale_reports()
        .iter()
        .map(|report| report.applied_index)
        .max()
        .flatten();
    // Establish that the healthy membership reached background persistence.
    // This deliberately does not assert that the last acknowledged operation
    // is durable: its presence is checked, and reconciled, after recovery.
    let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    if persistence == QualificationIsolatedPersistence::Async {
        loop {
            let reports = fleet.isolated_scale_reports_by(deadline);
            if volatile_q1 {
                if reports.iter().all(|report| report.background_failed) {
                    assert!(
                        reports
                            .iter()
                            .all(|report| report.completed_applied_index < admission_applied),
                        "no selected generation contains acknowledged Q1"
                    );
                    break;
                }
                assert!(Instant::now() < deadline);
                continue;
            }
            if reports.iter().zip(&before).all(|(after, prior)| {
                after.completed_generation > prior.completed_generation
                    && !after.background_failed
                    && (prepared_roster.is_none()
                        || after.completed_applied_index >= admission_applied)
            }) {
                break;
            }
            assert!(Instant::now() < deadline);
        }
    }
    let returning = (0..3)
        .filter(|index| all_cold || *index != survivor)
        .collect::<Vec<_>>();
    let mut replacements = Vec::new();
    for &index in &returning {
        replacements.push((index, fleet.kill_node_unclean(index)));
        let native = PathBuf::from(format!(
            "{}.native-wal",
            fleet.database_paths[index].display()
        ));
        assert!(
            !native.join("ASYNC-CLOSED").exists(),
            "abrupt loss cannot mint completed-shutdown evidence"
        );
        if persistence == QualificationIsolatedPersistence::Async {
            assert!(native.join("ASYNC-AUTHORITY").is_file());
        }
    }
    if volatile_q1 {
        // Remove only the injected I/O failure after every writer was killed;
        // retain all voter roots, provider journals and authority evidence.
        fs::remove_file(fleet.workspace.path().join("fail-async-generations")).unwrap();
    }
    if !all_cold {
        assert!(
            matches!(fleet.nodes[survivor].invoke(&QualificationNodeCommand::IsolatedScaleProbe),
            QualificationNodeReply::IsolatedScaleReadiness { status } if !status.ready)
        );
    }
    // Reopen every original address/root before driving initialization. The
    // existing one-at-a-time helper intentionally expects a live majority.
    let deadline = Instant::now() + CHILD_TIMEOUT;
    for (index, (address, prior_pid)) in replacements {
        fs::copy(
            &fleet.stderr_paths[index],
            fleet.stderr_paths[index].with_file_name("unclean-stderr.log"),
        )
        .expect("preserve predecessor diagnostic evidence");
        let (node, actual) = ChildNode::spawn_bound_until(
            &fleet.config_paths[index],
            index,
            &fleet.stderr_paths[index],
            address,
            deadline,
            fleet._snapshot_leaves.get(index),
        );
        assert_eq!(actual, address);
        assert_ne!(node.process_id(), prior_pid);
        fleet.nodes[index] = node;
    }
    for &index in &returning {
        fleet.nodes[index].send(&QualificationNodeCommand::Configure);
    }
    for &index in &returning {
        assert!(matches!(fleet.nodes[index].receive_until(deadline),
            QualificationNodeReply::Started { node_index } if node_index == index));
    }
    let leader = recover_unclean(&mut fleet, scale);
    if !all_cold {
        assert_eq!(fleet.nodes[survivor].process_id(), original_process);
    }
    let retained = match fleet.nodes[leader].invoke(&QualificationNodeCommand::Get {
        stable_id: "recovery-key".to_owned(),
    }) {
        QualificationNodeReply::Record {
            present: true,
            generation: Some(1),
            ..
        } => Some(1),
        QualificationNodeReply::Record {
            present: false,
            generation: None,
            ..
        } => None,
        _ => panic!("recovered record must be the retained version or permitted Async loss"),
    };
    if persistence == QualificationIsolatedPersistence::Durable {
        assert_eq!(retained, Some(1));
    }
    let next_fence = match fleet.nodes[leader].invoke(&QualificationNodeCommand::Acquire {
        lease_handle: "recovery-new".to_owned(),
        stable_id: "recovery-key".to_owned(),
        owner: "recovery-after".to_owned(),
        ttl_millis: 60_000,
    }) {
        QualificationNodeReply::LeaseAcquired { fence } => fence,
        _ => panic!("subsequent usable authority acquisition failed"),
    };
    assert!(next_fence > old_fence);
    if let Some(provider) = &provider {
        let (floor, writes, retired) = provider.progress().expect("reopen durable completion");
        assert!(floor >= old_fence && next_fence > floor);
        assert_eq!((writes, retired), if volatile_q1 { (2, 6) } else { (1, 7) });
        provider
            .effect(3, next_fence, true)
            .expect("successor external effect");
        assert!(
            provider.effect(1, old_fence, true).is_err(),
            "delayed prepared execute must be fenced"
        );
        assert!(
            provider.effect(4, old_fence, true).is_err(),
            "unknown old binding must also be fenced"
        );
        assert_eq!(
            provider.progress().expect("read successor effect").1,
            if volatile_q1 { 3 } else { 2 }
        );
    }

    assert!(matches!(
        fleet.nodes[leader].invoke(&QualificationNodeCommand::CompareAndSet {
            lease_handle: "recovery-new".to_owned(),
            stable_id: "recovery-key".to_owned(),
            expected_generation: retained,
            new_generation: 2,
            value: "after".to_owned(),
        }),
        QualificationNodeReply::CompareAndSet {
            applied: true,
            current_generation: Some(2)
        }
    ));
    if !all_cold {
        // The unchanged survivor still holds the real, unexpired predecessor
        // guard. It cannot modify the successor even when it remains leader.
        assert!(
            old_issued_at.elapsed() < Duration::from_millis(60_000),
            "the stale-authority control must precede old lease expiry"
        );
        assert!(matches!(
            fleet.nodes[survivor].invoke(&QualificationNodeCommand::CompareAndSet {
                lease_handle: "recovery-old".to_owned(),
                stable_id: "recovery-key".to_owned(),
                expected_generation: Some(2),
                new_generation: 3,
                value: "stale".to_owned(),
            }),
            QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::MutationRejected
            }
        ));
    }
    for node in &mut fleet.nodes {
        assert!(
            matches!(node.invoke(&QualificationNodeCommand::Get { stable_id: "recovery-key".to_owned() }),
            QualificationNodeReply::Record { present: true, generation: Some(2), fence: Some(fence), .. } if fence == next_fence)
        );
    }
    if let Some(prepared) = prepared_roster {
        prepared.recover(&mut fleet, returning[0], volatile_q1);
    }
    fleet.shutdown_isolated_scale_joined();
}

#[test]
fn isolated_async_two_voters_killed_recover_without_restarting_survivor() {
    unclean_return(
        false,
        QualificationIsolatedPersistence::Async,
        QualificationIsolatedScaleWorkload::RetainedRecoveryControl,
    );
}

#[test]
fn isolated_async_all_voters_killed_recover_with_new_usable_authority() {
    unclean_return(
        true,
        QualificationIsolatedPersistence::Async,
        QualificationIsolatedScaleWorkload::RetainedRecoveryControl,
    );
}

#[test]
fn protected_async_majority_return_recovers_successor_authority() {
    unclean_return(
        false,
        QualificationIsolatedPersistence::Async,
        QualificationIsolatedScaleWorkload::ProtectedRecoveryControl,
    );
}

#[test]
fn protected_async_all_cold_return_recovers_successor_authority() {
    unclean_return(
        true,
        QualificationIsolatedPersistence::Async,
        QualificationIsolatedScaleWorkload::ProtectedRecoveryControl,
    );
}

#[test]
fn protected_durable_majority_return_recovers_successor_authority() {
    unclean_return(
        false,
        QualificationIsolatedPersistence::Durable,
        QualificationIsolatedScaleWorkload::ProtectedRecoveryControl,
    );
}

#[test]
fn protected_durable_all_cold_return_recovers_successor_authority() {
    unclean_return(
        true,
        QualificationIsolatedPersistence::Durable,
        QualificationIsolatedScaleWorkload::ProtectedRecoveryControl,
    );
}

#[cfg(feature = "test-control")]
#[test]
fn protected_async_all_cold_loses_acknowledged_q1_but_retires_durable_effects() {
    unclean_return_with_tail(
        true,
        QualificationIsolatedPersistence::Async,
        QualificationIsolatedScaleWorkload::ProtectedRecoveryControl,
        true,
    );
}
