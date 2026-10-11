use super::*;

pub(super) async fn prepared_fleet() -> (Fleet, ConsensusSessionStore, VoterSlotDurableState) {
    let mut fleet = Fleet::open().await;
    let leader = fleet.nodes[0].clone();
    fleet
        .network
        .handlers
        .write()
        .unwrap()
        .remove(&member(3, 1).identity.node_id());
    fleet.nodes.pop().unwrap().shutdown().await.unwrap();
    tokio::time::sleep(VOTER_RECENT_TRAFFIC_WINDOW + Duration::from_millis(100)).await;
    let prepared = leader
        .replace_voter(verified_request(&genesis(), 3))
        .await
        .unwrap();
    (fleet, leader, prepared)
}

pub(super) async fn add_candidate(
    fleet: &mut Fleet,
    prepared: &VoterSlotDurableState,
) -> ConsensusSessionStore {
    let directory = tempfile::tempdir().unwrap();
    let candidate = ConsensusSessionStore::open_with_voter_slots_and_integrity(
        topology(3),
        prepared.table().clone(),
        member(3, 2).identity.node_id(),
        SqliteSessionBackend::open(directory.path().join("session.sqlite")).unwrap(),
        directory.path().join("snapshots"),
        Arc::new(Resolver(fleet.network.clone())),
        crate::consensus::SnapshotIntegrityPolicy::PortableVerified,
    )
    .await
    .unwrap();
    fleet
        .network
        .handlers
        .write()
        .unwrap()
        .insert(member(3, 2).identity.node_id(), candidate.rpc_handler());
    fleet.nodes.push(candidate.clone());
    fleet.directories.push(directory);
    candidate
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_absent_candidate_reuses_one_snapshot_for_two_minutes() {
    let (fleet, leader, _) = prepared_fleet().await;
    let observation = leader
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .core
        .snapshot_observation
        .clone();
    let builds_before = observation.snapshot().3;
    let attempts_before = fleet.network.probe_snapshot_rpcs.load(Ordering::SeqCst);
    let log_before = leader.inner.raft.metrics().borrow().last_log_index;
    let until = tokio::time::Instant::now() + Duration::from_secs(120);
    let mut builds;
    let mut attempts;
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        builds = observation.snapshot().3 - builds_before;
        attempts = fleet.network.probe_snapshot_rpcs.load(Ordering::SeqCst) - attempts_before;
        if builds > 1 || attempts > 40 || tokio::time::Instant::now() >= until {
            break;
        }
    }
    let log_after = leader.inner.raft.metrics().borrow().last_log_index;
    fleet.close().await;
    assert!(
        builds <= 1,
        "absent candidate caused {builds} complete snapshot builds"
    );
    assert!(
        attempts <= 40,
        "retry backoff did not bound RPC work: {attempts}"
    );
    assert_eq!(
        log_after, log_before,
        "an absent Pending candidate must not generate log entries"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_unreachable_learner_reuses_one_marker_for_two_minutes() {
    let (mut fleet, leader, prepared) = prepared_fleet().await;
    // The initial snapshot is delivered, but no subsequent log entry can reach
    // the learner. This holds the catch-up barrier before its first reply.
    fleet
        .network
        .paused_nonempty_append_to
        .store(member(3, 2).identity.node_id().get(), Ordering::SeqCst);
    let _candidate = add_candidate(&mut fleet, &prepared).await;
    let marker = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(state) = published_voter_state(&leader) {
                if let Some(learner) = state
                    .table()
                    .replacement
                    .as_ref()
                    .and_then(|op| op.evidence.learner)
                {
                    let marker = learner.index + 1;
                    if leader
                        .inner
                        .raft
                        .metrics()
                        .borrow()
                        .last_applied
                        .is_some_and(|cut| cut.index >= marker)
                    {
                        break marker;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the first catch-up Marker must commit");
    let until = tokio::time::Instant::now() + Duration::from_secs(120);
    let mut last;
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        last = leader.inner.raft.metrics().borrow().last_log_index;
        if last != Some(marker) || tokio::time::Instant::now() >= until {
            break;
        }
    }
    fleet
        .network
        .paused_nonempty_append_to
        .store(0, Ordering::SeqCst);
    let recovered = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if published_voter_state(&leader)
                .is_some_and(|state| state.table().replacement.is_none())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok();
    fleet.close().await;
    assert_eq!(
        last,
        Some(marker),
        "an unreachable learner appended another catch-up Marker"
    );
    assert!(
        recovered,
        "the retained marker must complete when the candidate returns"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_snapshot_transfer_exceeds_ten_seconds_and_resumes_its_offset() {
    let (mut fleet, leader, prepared) = prepared_fleet().await;
    fleet
        .network
        .probe_snapshot_delay_ms
        .store(6_000, Ordering::SeqCst);
    fleet
        .network
        .fail_nonzero_snapshot_once
        .store(1, Ordering::SeqCst);
    let _candidate = add_candidate(&mut fleet, &prepared).await;
    let started = std::time::Instant::now();
    let advanced = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if published_voter_state(&leader).is_some_and(|state| {
                state
                    .table()
                    .replacement
                    .as_ref()
                    .is_none_or(|op| op.phase > VoterReplacementPhase::Prepared)
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok();
    let elapsed = started.elapsed();
    let received = fleet
        .network
        .received_snapshot_offsets
        .lock()
        .unwrap()
        .clone();
    let failed_chunk = fleet
        .network
        .fail_nonzero_snapshot_once
        .load(Ordering::SeqCst)
        == 0;
    fleet
        .network
        .probe_snapshot_delay_ms
        .store(0, Ordering::SeqCst);
    fleet.close().await;
    assert!(
        advanced,
        "a progressing snapshot longer than the client operation timeout never completed"
    );
    assert!(
        elapsed > Duration::from_secs(10),
        "fixture must exceed the original whole-pass budget"
    );
    assert!(failed_chunk, "fixture must lose one nonzero-offset chunk");
    assert_eq!(
        received.iter().filter(|(_, offset)| *offset == 0).count(),
        1,
        "transfer restarted instead of resuming: {received:?}"
    );
    assert!(received.iter().any(|(_, offset)| *offset > 0));
    assert!(
        received.iter().all(|(id, _)| id == &received[0].0),
        "snapshot artifact changed across retries"
    );
}
