//! Leader loss in a voter set that mixes the previous release with this one.
//!
//! A rolling upgrade, or the rollback of one, replaces one voter at a time, so
//! for a while some voters run the previous release's node binary beside
//! voters of this build. These tests start such fleets from the binary named by
//! `OPC_SESSION_QUORUM_NODE_PREVIOUS_RELEASE` and require that an unplanned
//! leader loss still elects a leader, that every streamed write applies
//! exactly once, and that no voter is left rejecting votes. The rolling-upgrade
//! lane builds that binary from the base revision and runs these ignored tests
//! explicitly.

use super::unplanned_leader_loss::{
    assert_stream_committed_exactly_once, leader_node_index, settled_leader_reports,
    stream_fenced_writes_on, FencedStreamWrite, StreamProgress, WriterRoute,
    WARM_WRITES_BEFORE_FAULT,
};
use super::*;

/// Names the previous release's `opc-session-quorum-node` binary.
const PREVIOUS_RELEASE_NODE_ENV: &str = "OPC_SESSION_QUORUM_NODE_PREVIOUS_RELEASE";

/// How long the lagging voters stay cut off before the leader is lost. The
/// others keep committing entries they never receive. The window is shorter
/// than either release's leader lease, 5 s for this build and 8 s for the
/// previous release, so a cut-off voter never campaigns.
const PREVIOUS_RELEASE_LAG_WINDOW: Duration = Duration::from_secs(4);

/// Writes the stream must commit after the roll finished.
const WRITES_AFTER_ROLL: usize = 4;

/// The previous release's fixed timing: a 2 s heartbeat whose engine tick is
/// three halves of it, elections sampled below 8 s, and a follower lease of
/// that full 8 s maximum. A previous-release voter campaigns once the lease
/// and a sampled timeout have both passed since its last leader contact, on
/// its next tick.
const PREVIOUS_RELEASE_ENGINE_TICK: Duration = Duration::from_millis(3_000);
const PREVIOUS_RELEASE_ELECTION_TIMEOUT_MAX: Duration = Duration::from_millis(8_000);

fn previous_release_node_binary() -> PathBuf {
    let path = env::var_os(PREVIOUS_RELEASE_NODE_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!(
                "{PREVIOUS_RELEASE_NODE_ENV} must name the previous release's \
                 opc-session-quorum-node binary"
            )
        });
    assert!(
        path.is_absolute() && path.is_file(),
        "{PREVIOUS_RELEASE_NODE_ENV} must name an existing absolute path"
    );
    path
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Release {
    Previous,
    Current,
}

impl Release {
    fn binary(self) -> PathBuf {
        match self {
            Self::Previous => previous_release_node_binary(),
            Self::Current => current_release_node_binary(),
        }
    }
}

/// One fleet plus the consumer endpoints, scope, and stream clients the tests
/// drive it with.
struct MixedFleet {
    fleet: Fleet,
    releases: Vec<Release>,
    consumer_identities: Vec<String>,
    endpoints: Vec<SocketAddr>,
    scope: SessionConsumerScope,
    authorities: Vec<SessionConsumerVoterAuthority>,
    // Keep every client identity source alive for the whole test.
    identity_sources: Vec<watch::Sender<Option<IdentityState>>>,
    runtime: tokio::runtime::Runtime,
}

impl MixedFleet {
    fn start(releases: Vec<Release>) -> Self {
        let mut fleet = Fleet::start_with_node_binaries(
            releases.iter().map(|release| release.binary()).collect(),
        );
        let consumer_identities = (0..12).map(stateless_consumer_identity).collect::<Vec<_>>();
        let mut endpoints = Vec::with_capacity(releases.len());
        let mut scope = None;
        for node_index in 0..releases.len() {
            let (endpoint, node_scope) =
                fleet.start_stateless_consumer(node_index, consumer_identities.clone());
            assert!(
                scope.is_none_or(|expected| expected == node_scope),
                "every voter must serve the same consumer scope"
            );
            scope = Some(node_scope);
            endpoints.push(endpoint);
        }
        let authorities = fleet.stateless_consumer_voter_authorities();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("mixed-release consumer runtime");
        Self {
            fleet,
            releases,
            consumer_identities,
            endpoints,
            scope: scope.expect("one consumer scope per fleet"),
            authorities,
            identity_sources: Vec::new(),
            runtime,
        }
    }

    fn member_count(&self) -> usize {
        self.releases.len()
    }

    /// A prewarmed persistent V2 consumer attached to one voter.
    fn client(&mut self, node_index: usize) -> PersistentSessionConsumerClient {
        let (identity_source, identity_receiver) = watch::channel(Some(
            self.fleet
                .pki
                .consumer_identity_state(&self.consumer_identities[0]),
        ));
        self.identity_sources.push(identity_source);
        let tls = TlsConfigBuilder::new(identity_receiver)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("stream consumer mTLS configuration");
        let endpoint = self.endpoints[node_index];
        let client = PersistentSessionConsumerClient::try_from_stateless(
            StatelessSessionConsumerClient::new(
                endpoint,
                rustls_pki_types::ServerName::IpAddress(endpoint.ip().into()),
                self.authorities[node_index].clone(),
                tls,
            ),
            PersistentSessionConsumerConfig::default(),
        )
        .expect("fixed persistent stream consumer configuration");
        self.runtime
            .block_on(client.prewarm_v2())
            .expect("prewarm the stream consumer");
        client
    }

    /// Restart one voter's consumer listener after the voter was respawned.
    fn restart_consumer(&mut self, node_index: usize) {
        let (endpoint, scope) = self
            .fleet
            .start_stateless_consumer(node_index, self.consumer_identities.clone());
        assert_eq!(scope, self.scope);
        self.endpoints[node_index] = endpoint;
    }

    /// Respawn voter `node_index` from `release` after it was killed.
    fn respawn_killed(&mut self, node_index: usize, killed: (SocketAddr, u32), release: Release) {
        self.fleet.set_node_binary(node_index, release.binary());
        self.fleet
            .spawn_node_at_manifest_address(node_index, killed.0, killed.1);
        self.releases[node_index] = release;
        self.restart_consumer(node_index);
    }

    /// Replace voter `node_index` with `release` through its own shutdown.
    fn roll(&mut self, node_index: usize, release: Release) {
        self.fleet.set_node_binary(node_index, release.binary());
        self.fleet.roll_node_at_manifest_address(node_index);
        self.releases[node_index] = release;
        self.restart_consumer(node_index);
    }

    /// Move leadership to a voter of this build by restarting each
    /// previous-release leader in place until one of this build leads.
    fn steer_leader_to_current_release(&mut self) -> usize {
        for _ in 0..self.member_count() {
            let reports = settled_leader_reports(&mut self.fleet);
            let leader = leader_node_index(&reports);
            if self.releases[leader] == Release::Current {
                return leader;
            }
            let killed = self.fleet.kill_node_unclean(leader);
            self.respawn_killed(leader, killed, Release::Previous);
            self.fleet.wait_ready();
        }
        panic!("leadership never moved to a voter of this build")
    }
}

/// Wait until every voter is ready and reports the same leader and term.
///
/// Unlike [`settled_leader_reports`], this tolerates a log that keeps
/// advancing under the write stream.
fn agreed_leader_reports(fleet: &mut Fleet) -> Vec<FleetReadiness> {
    let all = (0..fleet.member_count()).collect::<Vec<_>>();
    let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    loop {
        let reports = fleet.readiness_reports(&all);
        let first = &reports[0];
        if first.leader_id.is_some()
            && reports.iter().all(|report| {
                report.ready
                    && report.reason_code == QualificationReadinessCode::Ready
                    && report.term == first.term
                    && report.leader_id == first.leader_id
            })
        {
            return reports;
        }
        assert!(
            Instant::now() < deadline,
            "the voters did not agree on one ready leader: reports={reports:?}"
        );
        thread::sleep(Duration::from_millis(100));
    }
}

/// Time from a fault until the first write issued after it commits. A write
/// already in flight may still commit through the lost leader just before it
/// dies, so it does not measure the outage.
fn outage_after(writes: &[FencedStreamWrite], fault_at: Instant) -> Option<Duration> {
    writes
        .iter()
        .find(|write| write.issued_at >= fault_at)
        .map(|write| write.completed_at.saturating_duration_since(fault_at))
}

/// One leader loss observed by a mixed-release test.
#[derive(Debug)]
struct LeaderLoss {
    label: &'static str,
    lost_release: Release,
    releases: Vec<Release>,
    fault_at: Instant,
    elected_after: Duration,
    old_term: u64,
    new_term: u64,
}

/// Poll the survivors until every one reports the same leader in a term above
/// `old_term`. Returns the time of that first observation, or the last reports
/// once `deadline` passes.
fn wait_for_successor(
    fleet: &mut Fleet,
    survivors: &[usize],
    old_term: u64,
    deadline: Instant,
) -> Result<(Instant, u64), Vec<FleetReadiness>> {
    loop {
        let reports = fleet.readiness_reports(survivors);
        let first = &reports[0];
        if first.leader_id.is_some()
            && first.term > old_term
            && reports
                .iter()
                .all(|report| report.leader_id == first.leader_id && report.term == first.term)
        {
            return Ok((Instant::now(), first.term));
        }
        if Instant::now() >= deadline {
            return Err(reports);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// The previous-release voters of the lagging-voter topologies are the last
/// ones: this build keeps a majority without them, and its leader is lost.
fn lagging_voter_releases(member_count: usize) -> Vec<Release> {
    match member_count {
        3 => vec![Release::Current, Release::Current, Release::Previous],
        5 => vec![
            Release::Current,
            Release::Current,
            Release::Current,
            Release::Previous,
            Release::Previous,
        ],
        _ => unreachable!("qualification fleets have 3 or 5 voters"),
    }
}

/// Lose the leader of this build while every other voter of release
/// `lagging` lags.
///
/// The lagging voters miss the entries the others committed while they were
/// cut off, so only a survivor of the other release holds the most up-to-date
/// log and can win.
///
/// - With previous-release voters lagging, a survivor of this build must win.
///   It can only win with a previous-release voter's vote, which that voter can
///   grant but never as a Pre-Vote: the survivor learns this from the protocol
///   the connection negotiates and runs the classic election instead. The
///   previous-release voters campaign with the classic vote too, but cannot
///   win: their logs are behind.
/// - With this build's survivors lagging, a previous-release voter must win, by
///   its own slower timers. This build's survivors run the classic election,
///   because a previous-release voter cannot answer Pre-Vote, and each such
///   campaign votes for itself in its next term. A previous-release candidate
///   that meets such a self-vote in its term is refused, and the survivor of
///   this build then defers its own next campaign, so that the next
///   previous-release campaign finds no new self-vote.
fn run_leader_loss_with_lagging_voters(member_count: usize, lagging: Release) {
    let mut mixed = MixedFleet::start(lagging_voter_releases(member_count));
    let leader = mixed.steer_leader_to_current_release();
    let before = settled_leader_reports(&mut mixed.fleet);
    let old_term = before[0].term;
    assert_eq!(leader_node_index(&before), leader);
    let writer_voter = (0..member_count)
        .find(|node_index| *node_index != leader && mixed.releases[*node_index] != lagging)
        .expect("a surviving voter that does not lag");
    let client = mixed.client(writer_voter);
    let progress = Arc::new(StreamProgress::default());
    let writer = mixed.runtime.spawn(stream_fenced_writes_on(
        WriterRoute::new(client.clone()),
        mixed.scope,
        member_count,
        Arc::clone(&progress),
    ));
    let warm_deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    while progress.committed.load(Ordering::SeqCst) < WARM_WRITES_BEFORE_FAULT {
        assert!(
            !writer.is_finished() && Instant::now() < warm_deadline,
            "the stream did not commit its warm writes"
        );
        thread::sleep(Duration::from_millis(5));
    }

    let lagging_voters = (0..member_count)
        .filter(|node_index| *node_index != leader && mixed.releases[*node_index] == lagging)
        .collect::<Vec<_>>();
    for node_index in &lagging_voters {
        mixed.fleet.set_consensus_rpc_availability(
            *node_index,
            QualificationConsensusRpcAvailability::Unavailable,
        );
    }
    let committed_before_lag = progress.committed.load(Ordering::SeqCst);
    thread::sleep(PREVIOUS_RELEASE_LAG_WINDOW);
    assert!(
        progress.committed.load(Ordering::SeqCst) >= committed_before_lag + 3,
        "the voters that do not lag must keep committing while the others lag"
    );

    // Lose the leader first, so the lagging voters cannot catch up from it.
    let fault_at = Instant::now();
    *progress
        .fault_at
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(fault_at);
    let _ = mixed.fleet.kill_node_unclean(leader);
    for node_index in &lagging_voters {
        mixed.fleet.set_consensus_rpc_availability(
            *node_index,
            QualificationConsensusRpcAvailability::Available,
        );
    }
    let survivors = (0..member_count)
        .filter(|node_index| *node_index != leader)
        .collect::<Vec<_>>();
    let bound = mixed_release_election_bound();
    let (elected_at, new_term) =
        match wait_for_successor(&mut mixed.fleet, &survivors, old_term, fault_at + bound) {
            Ok(elected) => elected,
            Err(reports) => {
                progress.stop.store(true, Ordering::SeqCst);
                panic!(
                    "{member_count}-voter mixed-release fleet elected no successor within the \
                     documented {}ms mixed-release bound after losing its leader while the \
                     {lagging:?}-release voters lagged: survivors={reports:?}",
                    bound.as_millis()
                )
            }
        };

    let writes = match mixed.runtime.block_on(writer).expect("stream task joins") {
        Ok(writes) => writes,
        Err((writes, failure)) => panic!(
            "{member_count}-voter mixed-release stream failed after the leader loss: {failure}; \
             committed writes: {writes:#?}"
        ),
    };
    let outage = outage_after(&writes, fault_at).expect("a write issued after the fault commits");
    let outage_bound = mixed_release_write_stall_bound();
    eprintln!(
        "mixed-release leader loss with lagging {lagging:?}-release voters: voters={member_count} \
         releases={:?} old_term={old_term} new_term={new_term} elected_ms={} outage_ms={} \
         election_bound_ms={} outage_bound_ms={}",
        mixed.releases,
        elected_at.saturating_duration_since(fault_at).as_millis(),
        outage.as_millis(),
        bound.as_millis(),
        outage_bound.as_millis(),
    );
    assert_stream_committed_exactly_once(&writes, mixed.scope, &client, &mixed.runtime);
    assert!(
        outage <= outage_bound,
        "{member_count}-voter mixed-release outage was {}ms, above the documented {}ms bound: \
         {writes:#?}",
        outage.as_millis(),
        outage_bound.as_millis()
    );
    // No voter is left rejecting votes: every survivor, the lagging voters
    // included, follows the successor and has applied the committed log.
    let survivors_after = mixed.fleet.readiness_reports(&survivors);
    assert!(
        survivors_after.iter().all(|report| report.ready
            && report.term == new_term
            && report.leader_id == survivors_after[0].leader_id
            && report.applied_index == survivors_after[0].applied_index),
        "every survivor follows the successor with the committed log applied: {survivors_after:?}"
    );
}

#[test]
#[ignore = "requires OPC_SESSION_QUORUM_NODE_PREVIOUS_RELEASE; run by the rolling-upgrade lane"]
fn three_process_mixed_release_leader_loss_with_a_lagging_previous_release_voter() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_leader_loss_with_lagging_voters(3, Release::Previous);
}

#[test]
#[ignore = "requires OPC_SESSION_QUORUM_NODE_PREVIOUS_RELEASE; run by the rolling-upgrade lane"]
fn five_process_mixed_release_leader_loss_with_lagging_previous_release_voters() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_leader_loss_with_lagging_voters(5, Release::Previous);
}

#[test]
#[ignore = "requires OPC_SESSION_QUORUM_NODE_PREVIOUS_RELEASE; run by the rolling-upgrade lane"]
fn three_process_mixed_release_leader_loss_with_a_lagging_current_release_voter() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_leader_loss_with_lagging_voters(3, Release::Current);
}

#[test]
#[ignore = "requires OPC_SESSION_QUORUM_NODE_PREVIOUS_RELEASE; run by the rolling-upgrade lane"]
fn five_process_mixed_release_leader_loss_with_lagging_current_release_voters() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_leader_loss_with_lagging_voters(5, Release::Current);
}

/// Bound on electing a successor while a voter of the previous release is a
/// member.
///
/// A voter of this build that reaches such a voter runs the classic election
/// for that campaign, as the previous release does, so the voter set elects as
/// the previous release would. When only previous-release voters can win, one
/// first campaigns within its 8 s lease, its maximum election timeout and one
/// tick of its last leader contact, and a split vote adds one more
/// previous-release election timeout and tick. When a voter of this build can
/// win, it first campaigns within its own maximum election timeout and tick of
/// its last leader contact, after at most one cold connection that tells it a
/// voter cannot answer Pre-Vote. A previous-release lease, 8 s at most, may
/// reject that campaign; it campaigns again within one more of its election
/// timeouts and a tick, after every such lease has run out. The longer of the
/// two paths is the bound.
fn mixed_release_election_bound() -> Duration {
    let previous_release_lease = PREVIOUS_RELEASE_ELECTION_TIMEOUT_MAX;
    let previous_release_round =
        PREVIOUS_RELEASE_ELECTION_TIMEOUT_MAX + PREVIOUS_RELEASE_ENGINE_TICK;
    let previous_release_path = previous_release_lease + previous_release_round * 2;
    let current_release_round =
        Duration::from_millis(DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_max_millis)
            + DURABLE_CONSENSUS_TIMING_PROFILE.engine_tick();
    let current_release_path =
        DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout() + current_release_round * 2;
    // A retried campaign of this build starts at least two of its minimum
    // election timeouts after its last leader contact: after every
    // previous-release lease.
    assert!(
        Duration::from_millis(DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_min_millis) * 2
            >= previous_release_lease,
        "a retried campaign of this build starts after every previous-release lease"
    );
    previous_release_path.max(current_release_path)
}

/// Bound on a write in flight at a leader loss while a voter of the previous
/// release is still needed for a quorum: the mixed-release election bound,
/// then the same rounds after the first successful campaign as the
/// documented stall of this release.
fn mixed_release_write_stall_bound() -> Duration {
    mixed_release_election_bound()
        + DURABLE_CONSENSUS_TIMING_PROFILE
            .unplanned_leader_loss_write_stall()
            .saturating_sub(DURABLE_CONSENSUS_TIMING_PROFILE.leader_loss_first_campaign_bound())
}

/// Kill the current leader under the stream and wait for its successor.
fn lose_leader(
    mixed: &mut MixedFleet,
    label: &'static str,
) -> (usize, (SocketAddr, u32), LeaderLoss) {
    let before = agreed_leader_reports(&mut mixed.fleet);
    let old_term = before[0].term;
    let leader = leader_node_index(&before);
    let lost_release = mixed.releases[leader];
    let releases = mixed.releases.clone();
    let fault_at = Instant::now();
    let killed = mixed.fleet.kill_node_unclean(leader);
    let survivors = (0..mixed.member_count())
        .filter(|node_index| *node_index != leader)
        .collect::<Vec<_>>();
    let bound = mixed_release_election_bound();
    let (elected_at, new_term) =
        match wait_for_successor(&mut mixed.fleet, &survivors, old_term, fault_at + bound) {
            Ok(elected) => elected,
            Err(reports) => panic!(
                "{label}: no successor within the {}ms mixed-release bound after losing a \
                 {lost_release:?} leader of {releases:?}: survivors={reports:?}",
                bound.as_millis()
            ),
        };
    (
        leader,
        killed,
        LeaderLoss {
            label,
            lost_release,
            releases,
            fault_at,
            elected_after: elected_at.saturating_duration_since(fault_at),
            old_term,
            new_term,
        },
    )
}

/// Point the stream at a running voter other than `avoid`.
fn move_writer_off(
    mixed: &mut MixedFleet,
    route: &WriterRoute,
    writer_voter: &mut usize,
    avoid: usize,
) {
    if *writer_voter != avoid {
        return;
    }
    let next = (0..mixed.member_count())
        .find(|node_index| *node_index != avoid)
        .expect("another voter");
    route.replace(mixed.client(next));
    *writer_voter = next;
}

/// Roll every voter from release `from` to release `to`, one at a time, under
/// a continuous stream of fenced writes: an upgrade, or the rollback of one.
/// The leader is killed once while it still runs `from`, and once more when
/// the voter set is mixed.
fn run_rolling_restart_under_fenced_writes(member_count: usize, from: Release, to: Release) {
    let mut mixed = MixedFleet::start(vec![from; member_count]);
    let before = settled_leader_reports(&mut mixed.fleet);
    let leader = leader_node_index(&before);
    let mut writer_voter = (0..member_count)
        .find(|node_index| *node_index != leader)
        .expect("a follower");
    let route = WriterRoute::new(mixed.client(writer_voter));
    let progress = Arc::new(StreamProgress::default());
    let writer = mixed.runtime.spawn(stream_fenced_writes_on(
        Arc::clone(&route),
        mixed.scope,
        member_count,
        Arc::clone(&progress),
    ));
    let await_commits = |progress: &StreamProgress, target: usize| {
        let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
        while progress.committed.load(Ordering::SeqCst) < target {
            assert!(
                Instant::now() < deadline,
                "the stream did not reach {target} committed writes"
            );
            thread::sleep(Duration::from_millis(5));
        }
    };
    await_commits(&progress, WARM_WRITES_BEFORE_FAULT);

    let mut losses = Vec::new();
    // Roll followers first, leaving the leader on `from`: one of three
    // voters, or two of five.
    let first_rolled = member_count / 2;
    for _ in 0..first_rolled {
        let reports = agreed_leader_reports(&mut mixed.fleet);
        let leader = leader_node_index(&reports);
        let follower = (0..member_count)
            .find(|node_index| *node_index != leader && mixed.releases[*node_index] == from)
            .expect("a follower still on the outgoing release");
        move_writer_off(&mut mixed, &route, &mut writer_voter, follower);
        mixed.roll(follower, to);
        mixed.fleet.wait_ready();
        let committed = progress.committed.load(Ordering::SeqCst);
        await_commits(&progress, committed + 2);
    }

    // The leader still runs the outgoing release: kill it, and replace it
    // with the incoming one.
    let reports = agreed_leader_reports(&mut mixed.fleet);
    let leader = leader_node_index(&reports);
    assert_eq!(
        mixed.releases[leader], from,
        "rolling followers must leave the outgoing leader in place: {:?}",
        mixed.releases
    );
    move_writer_off(&mut mixed, &route, &mut writer_voter, leader);
    let (lost, killed, loss) = lose_leader(&mut mixed, "outgoing-release leader");
    losses.push(loss);
    mixed.respawn_killed(lost, killed, to);
    mixed.fleet.wait_ready();
    let committed = progress.committed.load(Ordering::SeqCst);
    await_commits(&progress, committed + 2);

    // Mid-roll: lose whichever voter leads the mixed set, and replace it with
    // the incoming release.
    assert!(mixed.releases.contains(&from));
    let reports = agreed_leader_reports(&mut mixed.fleet);
    move_writer_off(
        &mut mixed,
        &route,
        &mut writer_voter,
        leader_node_index(&reports),
    );
    let (lost, killed, loss) = lose_leader(&mut mixed, "mid-roll leader");
    losses.push(loss);
    mixed.respawn_killed(lost, killed, to);
    mixed.fleet.wait_ready();
    let committed = progress.committed.load(Ordering::SeqCst);
    await_commits(&progress, committed + 2);

    // Roll the remaining outgoing voters through their own shutdown.
    while let Some(node_index) =
        (0..member_count).find(|node_index| mixed.releases[*node_index] == from)
    {
        move_writer_off(&mut mixed, &route, &mut writer_voter, node_index);
        mixed.roll(node_index, to);
        mixed.fleet.wait_ready();
        let committed = progress.committed.load(Ordering::SeqCst);
        await_commits(&progress, committed + 2);
    }
    assert!(mixed.releases.iter().all(|release| *release == to));
    let committed = progress.committed.load(Ordering::SeqCst);
    await_commits(&progress, committed + WRITES_AFTER_ROLL);
    progress.stop.store(true, Ordering::SeqCst);

    let writes = match mixed.runtime.block_on(writer).expect("stream task joins") {
        Ok(writes) => writes,
        Err((writes, failure)) => panic!(
            "{member_count}-voter rolling restart from {from:?} to {to:?} failed: {failure}; \
             committed writes: {writes:#?}"
        ),
    };
    let outages = losses
        .iter()
        .map(|loss| outage_after(&writes, loss.fault_at))
        .collect::<Vec<_>>();
    for (loss, outage) in losses.iter().zip(&outages) {
        eprintln!(
            "rolling restart {from:?}->{to:?}: voters={member_count} {} lost={:?} releases={:?} old_term={} \
             new_term={} elected_ms={} outage_ms={:?} election_bound_ms={}",
            loss.label,
            loss.lost_release,
            loss.releases,
            loss.old_term,
            loss.new_term,
            loss.elected_after.as_millis(),
            outage.map(|outage| outage.as_millis()),
            mixed_release_election_bound().as_millis(),
        );
    }
    let client = route.client();
    assert_stream_committed_exactly_once(&writes, mixed.scope, &client, &mixed.runtime);
    let slowest: Option<&FencedStreamWrite> = writes.iter().max_by_key(|write| write.stall());
    eprintln!(
        "rolling restart {from:?}->{to:?}: voters={member_count} writes={} slowest_write={:?}",
        writes.len(),
        slowest.map(|write| (write.index, write.stall().as_millis(), write.attempts))
    );
    // No voter is left rejecting votes: the upgraded set agrees on one ready
    // leader and term.
    mixed.fleet.wait_ready();
    let all = mixed
        .fleet
        .readiness_reports(&(0..member_count).collect::<Vec<_>>());
    assert!(
        all.iter().all(|report| report.ready
            && report.term == all[0].term
            && report.leader_id == all[0].leader_id),
        "the rolled voter set agrees on one leader: {all:?}"
    );
}

#[test]
#[ignore = "requires OPC_SESSION_QUORUM_NODE_PREVIOUS_RELEASE; run by the rolling-upgrade lane"]
fn three_process_rolling_upgrade_from_the_previous_release_under_fenced_writes() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_rolling_restart_under_fenced_writes(3, Release::Previous, Release::Current);
}

#[test]
#[ignore = "requires OPC_SESSION_QUORUM_NODE_PREVIOUS_RELEASE; run by the rolling-upgrade lane"]
fn five_process_rolling_upgrade_from_the_previous_release_under_fenced_writes() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_rolling_restart_under_fenced_writes(5, Release::Previous, Release::Current);
}

#[test]
#[ignore = "requires OPC_SESSION_QUORUM_NODE_PREVIOUS_RELEASE; run by the rolling-upgrade lane"]
fn three_process_rolling_downgrade_to_the_previous_release_under_fenced_writes() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_rolling_restart_under_fenced_writes(3, Release::Current, Release::Previous);
}

#[test]
#[ignore = "requires OPC_SESSION_QUORUM_NODE_PREVIOUS_RELEASE; run by the rolling-upgrade lane"]
fn five_process_rolling_downgrade_to_the_previous_release_under_fenced_writes() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_rolling_restart_under_fenced_writes(5, Release::Current, Release::Previous);
}
