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
            if reports
                .iter()
                .all(|report| report.ready && report.async_active)
            {
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

fn unclean_return(all_cold: bool) {
    let scale = QualificationIsolatedScaleConfig {
        persistence: QualificationIsolatedPersistence::Async,
        workload: QualificationIsolatedScaleWorkload::RetainedRecoveryControl,
    };
    let mut fleet = Fleet::start_with_settings(3, scale.schedule_sha256(), None, Some(scale));
    let survivor = fleet.wait_isolated_scale_ready(scale);
    let original_process = fleet.nodes[survivor].process_id();
    let before = fleet.isolated_scale_reports();
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
    // Establish that the healthy membership reached background persistence.
    // This deliberately does not assert that the last acknowledged operation
    // is durable: its presence is checked, and reconciled, after recovery.
    let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    loop {
        let reports = fleet.isolated_scale_reports_by(deadline);
        if reports.iter().zip(&before).all(|(after, prior)| {
            after.completed_generation > prior.completed_generation && !after.background_failed
        }) {
            break;
        }
        assert!(Instant::now() < deadline);
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
        assert!(native.join("ASYNC-AUTHORITY").is_file());
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
    fleet.shutdown_isolated_scale_joined();
}

#[test]
fn isolated_async_two_voters_killed_recover_without_restarting_survivor() {
    unclean_return(false);
}

#[test]
fn isolated_async_all_voters_killed_recover_with_new_usable_authority() {
    unclean_return(true);
}
