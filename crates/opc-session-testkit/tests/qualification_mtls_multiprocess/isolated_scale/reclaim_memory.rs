//! SDK #1122: full public history retirement with one real budget per voter.
//!
//! Run alone with `--release --features test-control --ignored --exact
//! --test-threads=1 --nocapture`. No history rows, capacity constants, memory
//! limits or verification policies are overridden. Crash cuts request ordinary
//! checkpoints and restart one voter while the surviving quorum serves.

use super::*;
use opc_session_store::{
    FencedTransitionV2HistoryState, FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES,
    FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS, FENCED_TRANSITION_V2_RECLAIM_BATCH,
};

const BATCH: usize = 64;
// The complete million-receipt selected history is decoded and audited at
// each cold open. Its measured 52-second reopen exceeds the ordinary small
// child fixture's 45-second guard; keep this explicit scale-only hang bound.
const FULL_HISTORY_REOPEN_TIMEOUT: Duration = Duration::from_secs(120);

fn history(node: &mut ChildNode) -> FencedTransitionV2HistoryState {
    match node.invoke(&QualificationNodeCommand::IsolatedScaleHistoryState) {
        QualificationNodeReply::IsolatedScaleHistory { state } => state,
        reply => panic!("public history read unavailable: {reply:?}"),
    }
}

fn maintain(
    node: &mut ChildNode,
    expected: FencedTransitionV2HistoryState,
) -> QualificationNodeReply {
    node.invoke(&QualificationNodeCommand::IsolatedScaleMaintainHistory {
        expected_state: expected,
    })
}

fn request_in_epoch(
    template: &FencedTransitionV2Request,
    epoch: FencedTransitionV2HistoryEpoch,
    nonce: usize,
) -> FencedTransitionV2Request {
    FencedTransitionV2Request::new(
        epoch,
        FencedTransitionV2CallerNonce::from_bytes((nonce as u128).to_be_bytes()),
        template.lease().clone(),
        template.mutation().clone(),
    )
    .expect("fresh public request identity")
}

fn failure_diagnostics(fleet: &mut Fleet) {
    // Preserve the first reservation error before trying any potentially
    // failed process. Both log reads and status probes are best-effort.
    for (voter, path) in fleet.stderr_paths.iter().enumerate() {
        if let Ok(log) = fs::read_to_string(path) {
            for line in log
                .lines()
                .filter(|line| line.contains("verification_memory_admission_failure"))
            {
                eprintln!("reclaim_memory_voter={voter} {line}");
            }
        }
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    for (voter, node) in fleet.nodes.iter_mut().enumerate() {
        if node.pending.is_some() {
            eprintln!("reclaim_memory_probe voter={voter} pending=true");
            continue;
        }
        let sent = node.stdin.as_mut().is_some_and(|input| {
            write_json_line(input, &QualificationNodeCommand::IsolatedScaleProbe).is_ok()
        });
        if !sent {
            eprintln!("reclaim_memory_probe voter={voter} sent=false");
            continue;
        }
        match receive_qualification_reply_until(&node.replies, deadline) {
            Ok(ReaderMessage::Reply(reply)) => {
                eprintln!("reclaim_memory_probe voter={voter} reply={reply:?}")
            }
            _ => eprintln!("reclaim_memory_probe voter={voter} available=false"),
        }
    }
}

fn crash_and_rejoin(
    fleet: &mut Fleet,
    scale: QualificationIsolatedScaleConfig,
    leader: usize,
    cut: &str,
    mut consumer_progress: impl FnMut(),
) -> PathBuf {
    let follower = (leader + 1) % 3;
    let armed = fleet
        .workspace
        .path()
        .join(format!("reclaim-cut-{follower}"));
    let entered = armed.with_extension("entered");
    if cut != "retirement" {
        fs::write(&armed, cut).expect("arm one test-only checkpoint cut");
        fleet.nodes[follower].send(&QualificationNodeCommand::IsolatedScaleCheckpoint);
        let deadline = Instant::now() + CHILD_TIMEOUT;
        while !entered.try_exists().expect("checkpoint cut marker") {
            assert!(Instant::now() < deadline, "checkpoint reached {cut}");
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(fs::read_to_string(&entered).unwrap(), cut);
        consumer_progress();
    }
    assert!(
        !armed.with_extension("timed_out").exists(),
        "cut must still be held, not fenced by the hook timeout"
    );
    let (address, previous_pid) = fleet.kill_node_unclean(follower);
    assert!(
        !armed.with_extension("timed_out").exists(),
        "voter reached SIGKILL while held at {cut}"
    );
    consumer_progress();
    let saved =
        fleet.stderr_paths[follower].with_file_name(format!("reclaim-{cut}-{previous_pid}.log"));
    fs::copy(&fleet.stderr_paths[follower], &saved).expect("retain crashed voter diagnostics");
    if cut != "retirement" {
        // Only disarm the harness fault. Recovery receives the untouched
        // database, WAL, generation and CURRENT files from the killed voter.
        fs::remove_file(&armed).unwrap();
        fs::remove_file(&entered).unwrap();
    }
    let reopened = Instant::now();
    fleet.spawn_node_at_manifest_address_by(
        follower,
        address,
        previous_pid,
        reopened + FULL_HISTORY_REOPEN_TIMEOUT,
    );
    assert!(matches!(
        fleet.nodes[follower].invoke(&QualificationNodeCommand::IsolatedScaleExpireHistoryClock),
        QualificationNodeReply::IsolatedScaleHistoryClockExpired
    ));
    assert_eq!(fleet.wait_isolated_scale_ready(scale), leader);
    consumer_progress();
    eprintln!(
        "reclaim_memory_rejoined cut={cut} voter={follower} previous_pid={previous_pid} pid={} reopen_ms={}",
        fleet.nodes[follower].process_id(),
        reopened.elapsed().as_millis()
    );
    saved
}

fn measured_peaks(paths: impl IntoIterator<Item = PathBuf>) -> (usize, usize, bool, bool) {
    let mut fill_peak = 0;
    let mut retirement_peak = 0;
    let mut admission_engaged = false;
    let mut memory_checkpoint = false;
    for path in paths {
        let log = fs::read_to_string(path).expect("retained reservation diagnostics");
        assert!(!log.contains("verification_memory_admission_failure"));
        let mut retirement = false;
        let mut observed = false;
        for line in log.lines() {
            if line.starts_with("native_verification_phase retirement") {
                retirement = true;
            }
            if retirement {
                admission_engaged |= line == "native_retirement_admission_wait";
                memory_checkpoint |= line.starts_with("native_retirement_memory_checkpoint");
            }
            let phase = line.strip_prefix("native_retirement_peak bytes=");
            let fill = (!retirement)
                .then(|| line.strip_prefix("native_verification_peak bytes="))
                .flatten();
            if let Some(value) = phase.or(fill) {
                let (bytes, limit) = value.split_once(" limit=").expect("closed peak vocabulary");
                let bytes = bytes.parse::<usize>().unwrap();
                assert_eq!(limit.parse::<usize>().unwrap(), 128 * 1024 * 1024);
                if phase.is_some() {
                    retirement_peak = retirement_peak.max(bytes);
                    observed = true;
                } else {
                    fill_peak = fill_peak.max(bytes);
                }
            }
        }
        assert!(
            observed,
            "each incarnation reports its actual retirement peak, including cold reopen"
        );
    }
    assert!(
        retirement_peak < 64 * 1024 * 1024,
        "retirement must leave half the cap unused: {retirement_peak}"
    );
    (
        fill_peak,
        retirement_peak,
        admission_engaged,
        memory_checkpoint,
    )
}

#[test]
#[ignore = "full public retained history: 1,048,576 receipts, real mTLS, three voter processes and crash cuts"]
fn isolated_durable_full_epoch_reclaim_stays_available() {
    let started = Instant::now();
    let scale = QualificationIsolatedScaleConfig {
        persistence: QualificationIsolatedPersistence::Durable,
        workload: QualificationIsolatedScaleWorkload::BoundaryControl,
    };
    let mut fleet = Fleet::start_with_settings(3, scale.schedule_sha256(), None, Some(scale));
    let mut leader = fleet.wait_isolated_scale_ready(scale);
    let pids = fleet
        .nodes
        .iter()
        .map(ChildNode::process_id)
        .collect::<Vec<_>>();
    assert_eq!(
        pids.iter().collect::<std::collections::BTreeSet<_>>().len(),
        3
    );
    assert!(!pids.contains(&std::process::id()));
    eprintln!(
        "reclaim_memory_start workspace={} voter_pids={pids:?}",
        fleet.workspace.path().display()
    );
    let identities = (0..12).map(stateless_consumer_identity).collect::<Vec<_>>();
    let (endpoint, scope) = fleet.start_stateless_consumer(leader, identities.clone());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("consumer runtime");
    let (mut source, mut client) = qualification_persistent_v2_client(
        Arc::new(Mutex::new(vec![endpoint; 3])),
        leader,
        fleet.stateless_consumer_voter_authorities()[leader].clone(),
        fleet.pki.consumer_identity_state(&identities[0]),
        PersistentSessionConsumerConfig::default(),
        None,
    );
    let template = runtime.block_on(async {
        client.prewarm_v2().await.expect("real consumer mTLS lanes");
        qualification_fenced_transition_v2_request(3, 0).await
    });

    // One synthetic record keeps business state minimal. The first create
    // succeeds; each new identity after it records StaleFence. Every binding
    // still traverses the public consumer, Raft, native WAL and verifier.
    for epoch_number in 1..=FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS {
        let epoch = FencedTransitionV2HistoryEpoch::new(epoch_number as u64).expect("epoch");
        for offset in (0..FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES).step_by(BATCH) {
            let first = (epoch_number - 1) * FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES + offset;
            let requests = (first..first + BATCH)
                .map(|nonce| request_in_epoch(&template, epoch, nonce))
                .collect::<Vec<_>>();
            let response = runtime
                .block_on(client.execute_v2(&SessionConsumerV2Request::new(
                    scope,
                    SessionConsumerV2Operation::FencedTransitionV2Batch {
                        requests: requests.clone(),
                    },
                )))
                .expect("public history-fill batch transport");
            let SessionConsumerV2Response::FencedTransitionV2Batch(Ok(results)) = response else {
                panic!("history-fill batch must return exact outcomes at epoch={epoch_number} offset={offset}");
            };
            assert_eq!(results.len(), requests.len());
            for (index, (result, request)) in results.iter().zip(&requests).enumerate() {
                assert_eq!(result.request_id(), request.request_id());
                if first + index == 0 {
                    assert!(result
                        .result()
                        .as_ref()
                        .is_ok_and(|outcome| outcome.matches_v2_request(request)));
                } else {
                    assert!(matches!(
                        result.result(),
                        Err(SessionConsumerV2FencedTransitionError::Store(
                            SessionConsumerStoreError::StaleFence
                        ))
                    ));
                }
            }
        }
        let full = history(&mut fleet.nodes[leader]);
        assert_eq!(full.active_epoch(), Some(epoch));
        assert_eq!(
            full.bound_entries(),
            FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
        );
        assert_eq!(full.retired_through(), None);
        let QualificationNodeReply::IsolatedScaleHistory { state: rotated } =
            maintain(&mut fleet.nodes[leader], full)
        else {
            panic!("public full epoch rotation must complete");
        };
        assert_eq!(
            rotated.active_epoch().map(|epoch| epoch.get()),
            Some(epoch_number as u64 + 1)
        );
        assert_eq!(rotated.bound_entries(), 0);
        assert_eq!(rotated.generation(), epoch_number as u64);
        assert_eq!(rotated, history(&mut fleet.nodes[leader]));
        eprintln!(
            "reclaim_memory_rotated epoch={epoch_number} elapsed_ms={}",
            started.elapsed().as_millis()
        );
    }

    let young = history(&mut fleet.nodes[leader]);
    assert_eq!(young.reclaim_epoch(), None);
    assert_eq!(young.reclaimed_entries(), 0);
    assert!(
        matches!(maintain(&mut fleet.nodes[leader], young), QualificationNodeReply::IsolatedScaleHistory { state } if state == young)
    );
    let active = young.active_epoch().expect("active successor");
    // Fill the eighth epoch to the actual retained-profile boundary, leaving
    // one slot for a fresh consumer witness after the clock advances.
    for first in (0..FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - 1).step_by(BATCH) {
        let end = (first + BATCH).min(FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - 1);
        let requests = (first..end)
            .map(|nonce| request_in_epoch(&template, active, nonce))
            .collect::<Vec<_>>();
        let response = runtime
            .block_on(client.execute_v2(&SessionConsumerV2Request::new(
                scope,
                SessionConsumerV2Operation::FencedTransitionV2Batch {
                    requests: requests.clone(),
                },
            )))
            .expect("public retained-boundary batch transport");
        let SessionConsumerV2Response::FencedTransitionV2Batch(Ok(results)) = response else {
            panic!("retained-boundary batch must return exact outcomes");
        };
        assert_eq!(results.len(), requests.len());
        for (result, request) in results.iter().zip(requests) {
            assert_eq!(result.request_id(), request.request_id());
            assert!(matches!(
                result.result(),
                Err(SessionConsumerV2FencedTransitionError::Store(
                    SessionConsumerStoreError::StaleFence
                ))
            ));
        }
    }
    assert_eq!(
        history(&mut fleet.nodes[leader]).bound_entries(),
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - 1
    );
    let before = fleet.isolated_scale_reports();
    assert!(before
        .iter()
        .all(|report| report.ready && report.engine_running && !report.storage_failed));
    assert!(
        before
            .iter()
            .all(|report| report.completed_snapshot_count > 0),
        "ordinary snapshots must be exercised"
    );
    eprintln!(
        "reclaim_memory_before_retirement={}",
        serde_json::to_string(&before).unwrap()
    );

    fs::write(
        fleet.workspace.path().join("reclaim-retirement-phase"),
        b"retirement",
    )
    .unwrap();
    // This changes only the SDK Clock. Tokio, TLS and all operation deadlines
    // retain real time. Each child acknowledges the same retention boundary.
    for node in &mut fleet.nodes {
        assert!(matches!(
            node.invoke(&QualificationNodeCommand::IsolatedScaleExpireHistoryClock),
            QualificationNodeReply::IsolatedScaleHistoryClockExpired
        ));
    }
    let sentinel = runtime.block_on(async {
        let template = qualification_fenced_transition_v2_request(3, 1).await;
        let request = request_in_epoch(&template, active, 0);
        let response = client
            .execute_v2(&SessionConsumerV2Request::new(
                scope,
                SessionConsumerV2Operation::FencedTransitionV2 {
                    request: Box::new(request.clone()),
                },
            ))
            .await
            .expect("fresh active-epoch consumer operation before reclaim");
        let SessionConsumerV2Response::FencedTransitionV2(Ok(outcome)) = response else {
            panic!("active-epoch create must succeed");
        };
        assert!(outcome.matches_v2_request(&request));
        (request, outcome)
    });
    let retirement_started = Instant::now();
    let consumer_progress = |client: &PersistentSessionConsumerClient| {
        runtime.block_on(async {
        let response = client.execute_v2(&SessionConsumerV2Request::new(scope,
            SessionConsumerV2Operation::FencedTransitionV2Status { request: Box::new(sentinel.0.clone()) },
        )).await.expect("consumer read during retirement");
        assert!(matches!(response, SessionConsumerV2Response::FencedTransitionV2Status(Ok(SessionConsumerV2FencedTransitionStatus::Recorded(result))) if result.as_ref() == &Ok(sentinel.1.clone())));
        let replay = client.execute_v2(&SessionConsumerV2Request::new(scope,
            SessionConsumerV2Operation::FencedTransitionV2 { request: Box::new(sentinel.0.clone()) },
        )).await.expect("consumer replay during retirement");
        assert!(matches!(replay, SessionConsumerV2Response::FencedTransitionV2(Ok(outcome)) if outcome == sentinel.1));
    })
    };
    let mut saved_stderr = Vec::new();
    let mut current = history(&mut fleet.nodes[leader]);
    for batch in 1..=FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES / FENCED_TRANSITION_V2_RECLAIM_BATCH {
        let reply = maintain(&mut fleet.nodes[leader], current);
        let next = match reply {
            QualificationNodeReply::IsolatedScaleHistory { state } => state,
            reply => {
                eprintln!("reclaim_memory_failure batch={batch} reclaimed={} remaining={} retirement_ms={} total_ms={} reply={reply:?}",
                    current.reclaimed_entries(), current.reclaim_remaining(), retirement_started.elapsed().as_millis(), started.elapsed().as_millis());
                failure_diagnostics(&mut fleet);
                panic!(
                    "a full epoch must retire within the unchanged per-process verification budget"
                );
            }
        };
        assert_eq!(next.active_epoch(), Some(active));
        assert_eq!(next.retired_through().map(|epoch| epoch.get()), Some(1));
        assert_eq!(
            next.bound_entries(),
            FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
        );
        assert_eq!(
            next.reclaimed_entries(),
            (batch * FENCED_TRANSITION_V2_RECLAIM_BATCH) as u64
        );
        assert_eq!(
            next.reclaim_remaining(),
            FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - batch * FENCED_TRANSITION_V2_RECLAIM_BATCH
        );
        assert_eq!(next, history(&mut fleet.nodes[leader]));
        if batch % 16 == 0 {
            consumer_progress(&client);
            eprintln!(
                "reclaim_memory_progress reclaimed={} retirement_ms={}",
                next.reclaimed_entries(),
                retirement_started.elapsed().as_millis()
            );
        }
        if let Some(cut) = match batch {
            16 => Some("retirement"),
            40 => Some("capture"),
            56 => Some("before_append"),
            72 => Some("append"),
            104 => Some("selection"),
            116 => Some("reclaim_covered"),
            _ => None,
        } {
            let recovered = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                crash_and_rejoin(&mut fleet, scale, leader, cut, || {
                    consumer_progress(&client)
                })
            }));
            match recovered {
                Ok(path) => saved_stderr.push(path),
                Err(failure) => {
                    failure_diagnostics(&mut fleet);
                    std::panic::resume_unwind(failure);
                }
            }
            for node in &mut fleet.nodes {
                assert_eq!(
                    history(node),
                    next,
                    "recovered voter retains the exact retirement cursor"
                );
            }
        }
        current = next;
    }
    assert_eq!(current.reclaim_epoch(), None);
    let after = fleet.isolated_scale_reports();
    assert!(after
        .iter()
        .all(|report| report.ready && report.engine_running && !report.storage_failed));
    for node in &mut fleet.nodes {
        assert_eq!(
            history(node),
            current,
            "every voter observes complete retirement"
        );
    }
    // Kill the serving leader as well. Election and exact consumer replay
    // complete on the surviving quorum before the old process is reopened.
    let old_leader = leader;
    let old_leader_id = fleet.readiness_reports(&[leader])[0].node_id;
    let (address, previous_pid) = fleet.kill_node_unclean(old_leader);
    let saved =
        fleet.stderr_paths[old_leader].with_file_name(format!("reclaim-leader-{previous_pid}.log"));
    fs::copy(&fleet.stderr_paths[old_leader], &saved).unwrap();
    saved_stderr.push(saved);
    let survivors = (0..3)
        .filter(|node| *node != old_leader)
        .collect::<Vec<_>>();
    let election_deadline = Instant::now() + STATELESS_CONSUMER_LEADER_RECOVERY_TIMEOUT;
    leader = loop {
        let reports = fleet.readiness_reports(&survivors);
        if let Some(report) = reports.iter().find(|report| {
            report.ready
                && report.leader_id == Some(report.node_id)
                && report.node_id != old_leader_id
        }) {
            break report.node_index;
        }
        assert!(
            Instant::now() < election_deadline,
            "surviving quorum elects a ready leader"
        );
        thread::sleep(Duration::from_millis(50));
    };
    let (endpoint, recovered_scope) = fleet.start_stateless_consumer(leader, identities.clone());
    assert_eq!(recovered_scope, scope);
    let (next_source, next_client) = qualification_persistent_v2_client(
        Arc::new(Mutex::new(vec![endpoint; 3])),
        leader,
        fleet.stateless_consumer_voter_authorities()[leader].clone(),
        fleet.pki.consumer_identity_state(&identities[0]),
        PersistentSessionConsumerConfig::default(),
        None,
    );
    runtime
        .block_on(next_client.prewarm_v2())
        .expect("replacement leader mTLS");
    consumer_progress(&next_client);
    runtime.block_on(client.shutdown());
    drop(source);
    source = next_source;
    client = next_client;
    let reopened = Instant::now();
    fleet.spawn_node_at_manifest_address_by(
        old_leader,
        address,
        previous_pid,
        reopened + FULL_HISTORY_REOPEN_TIMEOUT,
    );
    assert!(matches!(
        fleet.nodes[old_leader].invoke(&QualificationNodeCommand::IsolatedScaleExpireHistoryClock),
        QualificationNodeReply::IsolatedScaleHistoryClockExpired
    ));
    assert_eq!(fleet.wait_isolated_scale_ready(scale), leader);
    consumer_progress(&client);
    for node in &mut fleet.nodes {
        assert_eq!(history(node), current);
    }
    eprintln!("reclaim_memory_rejoined cut=leader voter={old_leader} replacement_leader={leader} reopen_ms={}", reopened.elapsed().as_millis());
    let QualificationNodeReply::IsolatedScaleHistory { state: successor } =
        maintain(&mut fleet.nodes[leader], current)
    else {
        panic!("full active epoch rotates after reclamation frees the retained boundary");
    };
    assert_eq!(successor.active_epoch().unwrap().get(), active.get() + 1);
    assert_eq!(successor.bound_entries(), 0);
    runtime.block_on(async {
        let template = qualification_fenced_transition_v2_request(3, 2).await;
        let request = request_in_epoch(&template, successor.active_epoch().unwrap(), 0);
        let result = client.execute_v2(&SessionConsumerV2Request::new(scope,
            SessionConsumerV2Operation::FencedTransitionV2 { request: Box::new(request.clone()) }
        )).await.expect("new public work after retained-boundary rotation");
        assert!(matches!(result, SessionConsumerV2Response::FencedTransitionV2(Ok(outcome)) if outcome.matches_v2_request(&request)));
    });
    consumer_progress(&client);
    runtime.block_on(client.shutdown());
    drop(source);
    fleet.shutdown_isolated_scale_joined();
    let (fill_peak, retirement_peak, admission_engaged, memory_checkpoint) = measured_peaks(
        saved_stderr
            .into_iter()
            .chain(fleet.stderr_paths.iter().cloned()),
    );
    // One epoch's 128 single-command journals total about 17.3 MiB, below
    // the 24 MiB stop, and these checkpoints shorten the suffix further.
    // The dedicated committed-wait regression forces the 80 MiB admission
    // line with a real reservation and asserts its wait counter/progress.
    eprintln!(
        "reclaim_memory_complete total_ms={} retirement_ms={} fill_peak_bytes={fill_peak} retirement_peak_bytes={retirement_peak} admission_engaged={admission_engaged} memory_checkpoint={memory_checkpoint}",
        started.elapsed().as_millis(),
        retirement_started.elapsed().as_millis()
    );
}
