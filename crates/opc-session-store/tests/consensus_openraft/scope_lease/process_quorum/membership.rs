//! Membership, lease and batch control uses the same real voter processes.
//! Campaigns use the existing engine hook; natural election timing is #1156.

use super::*;
use opc_session_store::{
    SessionConsensusStorageAnchor, SessionTopologyAbortAdmissionProof,
    SessionTopologyCandidateBootstrap, SessionTopologyCandidateRetirementProof,
    SessionTopologyJointCommitAdmissionProof, SessionTopologyLearnersReadyAdmissionProof,
    SessionTopologyPrePrepareUnstageProof, SessionTopologyTransitionError,
    SessionTopologyTransitionId, SessionTopologyTransitionPeers, SessionTopologyTransitionPhase,
    SessionTopologyTransitionRequest, SessionTopologyTransportAdmission,
    SessionTopologyTransportAdmissionError, SessionTopologyUniformCommitAdmissionProof,
};

pub(super) const CONFIG_ENV: &str = "OPC_SCOPE_PROCESS_MEMBERSHIP";

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Transition {
    current: Vec<usize>,
    desired: Vec<usize>,
    epoch: u64,
    seed: u8,
}

fn identity(indices: &[usize], epoch: u64) -> ConsensusIdentity {
    consensus_identity_for_cluster(
        &indices.iter().copied().map(member).collect::<Vec<_>>(),
        "session-openraft-integration-tests",
        epoch,
    )
}

fn node(index: usize) -> SessionConsensusNodeId {
    opc_consensus::derive_node_id(
        identity(&[0, 1, 2], 1).cluster_id(),
        replica_id(index).as_str().as_bytes(),
    )
    .unwrap()
}

impl Transition {
    fn request(&self) -> SessionTopologyTransitionRequest {
        SessionTopologyTransitionRequest::try_new(
            SessionTopologyTransitionId::from_bytes([self.seed; 16]),
            identity(&self.current, self.epoch).cluster_id(),
            ConsensusConfigurationEpoch::new(self.epoch).unwrap(),
            ConsensusConfigurationEpoch::new(self.epoch + 1).unwrap(),
            self.desired.iter().copied().map(member).collect(),
            Duration::from_secs(30),
        )
        .unwrap()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Configuration {
    current: Vec<usize>,
    epoch: u64,
    pub(super) candidate: Option<(SessionConsensusStorageAnchor, Transition)>,
    staged: Option<Transition>,
}

impl Configuration {
    pub(super) fn initializes(&self) -> bool {
        self.candidate.is_none() && self.staged.is_none()
    }

    pub(super) fn from_environment() -> Option<Self> {
        std::env::var(CONFIG_ENV)
            .ok()
            .and_then(|json| serde_json::from_str(&json).unwrap())
    }
}

fn peers(
    index: usize,
    indices: &[usize],
    scope: ConsensusIdentity,
    addresses: &[SocketAddr],
    votes: &Arc<VoteControl>,
) -> SessionTopologyTransitionPeers {
    indices
        .iter()
        .copied()
        .filter(|n| *n != index)
        .map(|n| {
            let peer: Arc<dyn SessionConsensusPeer> = Arc::new(Peer {
                node: node(n),
                source: node(index),
                address: addresses[n],
                votes: votes.clone(),
                scope: Some(scope),
            });
            (node(n), peer)
        })
        .collect()
}

#[derive(Debug)]
struct Transport;

fn admitted(valid: bool) -> Result<(), SessionTopologyTransportAdmissionError> {
    valid
        .then_some(())
        .ok_or(SessionTopologyTransportAdmissionError::Rejected)
}

#[async_trait]
impl SessionTopologyTransportAdmission for Transport {
    async fn unstage_successor_before_prepare(
        &self,
        request: &SessionTopologyTransitionRequest,
        proof: &SessionTopologyPrePrepareUnstageProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError> {
        admitted(proof.validates_request(request))
    }
    async fn retire_aborted_candidate(
        &self,
        request: &SessionTopologyTransitionRequest,
        proof: &SessionTopologyCandidateRetirementProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError> {
        admitted(proof.validates_request(request))
    }
    async fn admit_successor_voting(
        &self,
        request: &SessionTopologyTransitionRequest,
        proof: &SessionTopologyJointCommitAdmissionProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError> {
        admitted(proof.validates_request(request))
    }
    async fn finalize_successor(
        &self,
        request: &SessionTopologyTransitionRequest,
        proof: &SessionTopologyUniformCommitAdmissionProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError> {
        admitted(proof.validates_request(request))
    }
    async fn abort_successor(
        &self,
        request: &SessionTopologyTransitionRequest,
        proof: &SessionTopologyAbortAdmissionProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError> {
        admitted(proof.validates_request(request))
    }
}

pub(super) async fn open_voter(
    index: usize,
    root: &Path,
    snapshots: &Path,
    addresses: &[SocketAddr],
    votes: Arc<VoteControl>,
    configuration: &Configuration,
) -> ConsensusSessionStore {
    let backend = SqliteSessionBackend::open(root.join(format!("voter-{index}.sqlite"))).unwrap();
    let current_identity = identity(&configuration.current, configuration.epoch);
    let store = if let Some((anchor, transition)) = &configuration.candidate {
        let request = transition.request();
        let bootstrap = SessionTopologyCandidateBootstrap::try_new(
            *anchor,
            current_identity,
            configuration.current.iter().copied().map(member).collect(),
            request.clone(),
            member(index),
        )
        .unwrap();
        ConsensusSessionStore::open_membership_candidate_with_clock(
            bootstrap,
            backend,
            snapshots.join(format!("voter-{index}")),
            peers(
                index,
                &transition.desired,
                request.desired_identity(),
                addresses,
                &votes,
            ),
            Arc::new(SystemClock),
            DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
        )
        .await
        .unwrap()
    } else {
        let topology = ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
            replica_id(index),
            configuration.current.iter().copied().map(member).collect(),
            current_identity,
        ))
        .unwrap();
        ConsensusSessionStore::open_with_clock(
            topology,
            backend,
            snapshots.join(format!("voter-{index}")),
            peers(
                index,
                &configuration.current,
                current_identity,
                addresses,
                &votes,
            ),
            Arc::new(SystemClock),
            DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
        )
        .await
        .unwrap()
    };
    store.set_automatic_election_for_test(false);
    store
        .bind_topology_transport_admission(Arc::new(Transport))
        .unwrap();
    if let Some(transition) = &configuration.staged {
        let request = transition.request();
        store
            .stage_topology_transition_peers(
                &request,
                peers(
                    index,
                    &transition.desired,
                    request.desired_identity(),
                    addresses,
                    &votes,
                ),
            )
            .unwrap();
    }
    store
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(super) enum Step {
    Stage,
    Prepare,
    Commit,
    Abort,
    AbortedSettled,
    PreparedBeforeMarker,
    Settled,
}

#[derive(Serialize, Deserialize)]
pub(super) enum Control {
    Anchor,
    Topology { transition: Transition, step: Step },
    RejectProfileProbes,
    LoseReplies,
    PausePrepare,
    WaitPreparePaused,
    LoseCertificateReply,
    ObserveVotes { peer: SessionConsensusNodeId },
    Evidence,
}

#[derive(Serialize, Deserialize)]
pub(super) enum ControlReply {
    Done,
    Anchor(SessionConsensusStorageAnchor),
    Transition {
        error: String,
        retryable: bool,
    },
    Evidence {
        probes: usize,
        rejected_probes: usize,
        lost_lease: usize,
        lost_batch: usize,
        certificates: u64,
        certificate_index: Option<u64>,
        lost_certificate: usize,
        snapshot_requests: usize,
        snapshot_index: Option<u64>,
    },
}

#[derive(Default)]
pub(super) struct Controls {
    proofs: tokio::sync::Mutex<BTreeMap<u8, SessionTopologyLearnersReadyAdmissionProof>>,
    reject: AtomicBool,
    probes: AtomicUsize,
    rejected_probes: AtomicUsize,
    lose_lease: AtomicBool,
    lose_batch: AtomicBool,
    lost_lease: AtomicUsize,
    lost_batch: AtomicUsize,
    snapshot_requests: AtomicUsize,
    lost_certificate: AtomicUsize,
    prepare_entered:
        tokio::sync::Mutex<Option<tokio::sync::oneshot::Receiver<tokio::time::Instant>>>,
    prepare_release: StdMutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl Controls {
    pub(super) fn observe_snapshot(&self, request: &SessionConsensusWireRequest) {
        if request.family == SessionConsensusRpcFamily::InstallSnapshot {
            self.snapshot_requests.fetch_add(1, Ordering::SeqCst);
        }
    }

    pub(super) fn reject_profile_probe(&self, request: &SessionConsensusWireRequest) -> bool {
        // Decode the barrier's fixed identity prefix and enum tag. Tag 8 is
        // ConfirmScopeProfile with its exact 32-byte profile digest. The test
        // asserts that these probes were seen before enabling rejection.
        let profile_probe = request.family == SessionConsensusRpcFamily::TopologyAdmissionBarrier
            && matches!(postcard::take_from_bytes::<([u8; 16], [u8; 32], u32)>(&request.payload),
                Ok(((_, _, 8), digest)) if digest.len() == 32);
        if !profile_probe {
            return false;
        }
        self.probes.fetch_add(1, Ordering::SeqCst);
        let reject = self.reject.load(Ordering::SeqCst);
        if reject {
            self.rejected_probes.fetch_add(1, Ordering::SeqCst);
        }
        reject
    }
    pub(super) fn lose_lease_reply(&self) -> bool {
        let lose = self.lose_lease.swap(false, Ordering::SeqCst);
        if lose {
            self.lost_lease.fetch_add(1, Ordering::SeqCst);
        }
        lose
    }
    pub(super) fn lose_batch_reply(&self) -> bool {
        let lose = self.lose_batch.swap(false, Ordering::SeqCst);
        if lose {
            self.lost_batch.fetch_add(1, Ordering::SeqCst);
        }
        lose
    }
    pub(super) async fn handle(
        &self,
        store: &ConsensusSessionStore,
        index: usize,
        addresses: &[SocketAddr],
        votes: &Arc<VoteControl>,
        database: &Path,
        control: Control,
    ) -> ControlReply {
        match control {
            Control::Anchor => ControlReply::Anchor(store.storage_anchor()),
            Control::RejectProfileProbes => {
                self.reject.store(true, Ordering::SeqCst);
                ControlReply::Done
            }
            Control::LoseReplies => {
                self.lose_lease.store(true, Ordering::SeqCst);
                self.lose_batch.store(true, Ordering::SeqCst);
                ControlReply::Done
            }
            Control::PausePrepare => {
                let (entered, release) =
                    opc_session_store::test_support::pause_next_scope_continuation_reply_for_test(
                        store,
                    )
                    .unwrap();
                *self.prepare_entered.lock().await = Some(entered);
                *self.prepare_release.lock().unwrap() = Some(release);
                ControlReply::Done
            }
            Control::LoseCertificateReply => {
                // Dropping the completion channel makes the real coordinator
                // observe Unavailable after the certificate's durable effect.
                drop(self.prepare_release.lock().unwrap().take().unwrap());
                self.lost_certificate.fetch_add(1, Ordering::SeqCst);
                ControlReply::Done
            }
            Control::WaitPreparePaused => {
                let entered = self.prepare_entered.lock().await.take().unwrap();
                tokio::time::timeout(Duration::from_secs(30), entered)
                    .await
                    .unwrap()
                    .unwrap();
                ControlReply::Done
            }
            Control::ObserveVotes { peer } => {
                *votes.state.lock().unwrap() = VoteState {
                    peer: Some(peer),
                    ..VoteState::default()
                };
                votes.released.send_replace(true);
                ControlReply::Done
            }
            Control::Evidence => {
                let conn = rusqlite::Connection::open(database).unwrap();
                let certificates = conn.query_row("SELECT COUNT(*) FROM session_records WHERE key_type = 'opc-scope-continuation'", [], |row| row.get(0)).unwrap();
                let certificate_index = conn.query_row("SELECT MAX(generation) FROM session_records WHERE key_type = 'opc-scope-continuation'", [], |row| row.get(0)).unwrap();
                ControlReply::Evidence {
                    probes: self.probes.load(Ordering::SeqCst),
                    rejected_probes: self.rejected_probes.load(Ordering::SeqCst),
                    lost_lease: self.lost_lease.load(Ordering::SeqCst),
                    lost_batch: self.lost_batch.load(Ordering::SeqCst),
                    certificates,
                    certificate_index,
                    lost_certificate: self.lost_certificate.load(Ordering::SeqCst),
                    snapshot_requests: self.snapshot_requests.load(Ordering::SeqCst),
                    snapshot_index: opc_session_store::consensus::test_support::consensus_local_durable_progress_for_test(store).snapshot_index,
                }
            }
            Control::Topology { transition, step } => {
                let request = transition.request();
                let result = match step {
                    Step::PreparedBeforeMarker => {
                        let status = store.topology_transition_status(&request).await;
                        status.and_then(|status| {
                            if status.is_some_and(|status| {
                                status.phase() == SessionTopologyTransitionPhase::Prepared
                            }) {
                                Ok(())
                            } else {
                                Err(SessionTopologyTransitionError::Unavailable)
                            }
                        })
                    }
                    Step::AbortedSettled => {
                        let status = store.topology_transition_status(&request).await;
                        status.and_then(|status| {
                            let local =
                                opc_session_store::test_support::topology_admission_state_for_test(
                                    store, &request,
                                )?;
                            if status.is_some_and(|status| {
                                status.phase() == SessionTopologyTransitionPhase::Aborted
                            }) && store.status().admitted
                                && !local.staged
                            {
                                Ok(())
                            } else {
                                Err(SessionTopologyTransitionError::Unavailable)
                            }
                        })
                    }
                    Step::Settled => {
                        let status = store.topology_transition_status(&request).await;
                        status.and_then(|status| {
                            let local =
                                opc_session_store::test_support::topology_admission_state_for_test(
                                    store, &request,
                                )?;
                            if status.is_some_and(|status| {
                                status.phase() == SessionTopologyTransitionPhase::Completed
                            }) && store.status().admitted
                                && !local.staged
                            {
                                Ok(())
                            } else {
                                Err(SessionTopologyTransitionError::Unavailable)
                            }
                        })
                    }
                    Step::Stage => store.stage_topology_transition_peers(
                        &request,
                        peers(
                            index,
                            &transition.desired,
                            request.desired_identity(),
                            addresses,
                            votes,
                        ),
                    ),
                    Step::Abort => store.abort_topology_transition(&request).await.map(|_| ()),
                    Step::Prepare => match store
                        .prepare_topology_transition(
                            &request,
                            peers(
                                index,
                                &transition.desired,
                                request.desired_identity(),
                                addresses,
                                votes,
                            ),
                        )
                        .await
                    {
                        Ok(proof) => {
                            self.proofs.lock().await.insert(transition.seed, proof);
                            Ok(())
                        }
                        Err(error) => Err(error),
                    },
                    Step::Commit => {
                        let proof = self
                            .proofs
                            .lock()
                            .await
                            .get(&transition.seed)
                            .cloned()
                            .unwrap();
                        store
                            .commit_topology_transition(&request, &proof)
                            .await
                            .map(|_| ())
                    }
                };
                match result {
                    Ok(()) => ControlReply::Done,
                    Err(error) => ControlReply::Transition {
                        retryable: matches!(
                            error,
                            SessionTopologyTransitionError::NotLeader
                                | SessionTopologyTransitionError::Unavailable
                                | SessionTopologyTransitionError::DeadlineExceededResumable
                        ),
                        error: format!(
                            "{error:?}; local={:?}; admitted={}",
                            opc_session_store::test_support::topology_admission_state_for_test(
                                store, &request,
                            ),
                            store.status().admitted,
                        ),
                    },
                }
            }
        }
    }
}

impl Processes {
    fn start_membership(root: &Path, snapshots: &Path) -> Self {
        let listeners = (0..5)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect::<Vec<_>>();
        let addresses = listeners
            .iter()
            .map(|listener| listener.local_addr().unwrap())
            .collect();
        drop(listeners);
        let mut fleet = Self {
            children: (0..5).map(|_| None).collect(),
            addresses,
            root: root.to_owned(),
            snapshots: snapshots.to_owned(),
            configurations: vec![
                Some(Configuration {
                    current: vec![0, 1, 2],
                    epoch: 1,
                    candidate: None,
                    staged: None
                });
                5
            ],
        };
        for n in 0..3 {
            fleet.spawn(n);
        }
        fleet
    }

    async fn membership_control(&self, index: usize, control: Control) -> ControlReply {
        match call(self.addresses[index], Request::Membership(control))
            .await
            .unwrap()
        {
            Reply::Membership(reply) => reply,
            _ => panic!("membership reply expected"),
        }
    }

    async fn topology(&self, index: usize, transition: &Transition, step: Step) {
        eprintln!(
            "scope_membership_step epoch={} voter={index} step={step:?} started",
            transition.epoch
        );
        let mut last_error = None;
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                match self
                    .membership_control(
                        index,
                        Control::Topology {
                            transition: transition.clone(),
                            step,
                        },
                    )
                    .await
                {
                    ControlReply::Done => return,
                    ControlReply::Transition {
                        error,
                        retryable: false,
                    } => panic!(
                        "transition epoch {} step {step:?} on voter {index} rejected: {error}",
                        transition.epoch
                    ),
                    ControlReply::Transition { error, .. } => {
                        last_error = Some(error);
                        tokio::time::sleep(POLL_INTERVAL).await;
                    }
                    _ => panic!("transition reply expected"),
                }
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "transition epoch {} step {step:?} on voter {index} exceeded the existing 30 second bound; last={last_error:?}",
                transition.epoch
            )
        });
        eprintln!(
            "scope_membership_step epoch={} voter={index} step={step:?} completed",
            transition.epoch
        );
    }

    async fn listening(&self, indices: &[usize]) {
        tokio::time::timeout(Duration::from_secs(30), async {
            for n in indices {
                while !matches!(
                    call(self.addresses[*n], Request::Status).await,
                    Ok(Reply::Status { .. })
                ) {
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
            }
        })
        .await
        .expect("child listeners start");
    }

    async fn campaign(&self, indices: &[usize], old_term: u64) -> usize {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        self.listening(indices).await;
        // The pinned engine's EngineConfig::new sets leader_lease to
        // election_timeout_max. Even a forced campaign must respect that
        // lease. With the old process confirmed exited and automatic
        // elections disabled, let this known lease expire inside the same
        // 30-second bound, then trigger exactly one ordinary campaign.
        tokio::time::timeout_at(
            deadline,
            tokio::time::sleep(Duration::from_millis(
                DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_max_millis,
            )),
        )
        .await
        .unwrap();
        let mut positions = Vec::new();
        for index in indices {
            if let Reply::Status {
                last_log, leader, ..
            } = call(self.addresses[*index], Request::Status).await.unwrap()
            {
                // Prefer a follower on an equal log frontier. A recovered
                // incumbent may already be leader and need no new campaign.
                positions.push((last_log, leader != Some(node(*index)), *index));
            }
        }
        let candidate = positions.iter().max().unwrap().2;
        let peer = *indices.iter().find(|n| **n != candidate).unwrap();
        self.membership_control(candidate, Control::ObserveVotes { peer: node(peer) })
            .await;
        self.control(
            candidate,
            Request::ElectionControl {
                automatic: false,
                campaign: true,
            },
        )
        .await;
        let result = tokio::time::timeout_at(deadline, async {
            loop {
                let mut agreed = true;
                for index in indices {
                    agreed &= matches!(call(self.addresses[*index], Request::Status).await,
                        Ok(Reply::Status { leader: Some(leader), term, .. }) if leader == node(candidate) && term > old_term);
                }
                let votes = self.votes(candidate).await;
                if agreed && votes.latest.as_ref().is_some_and(|exchange|
                    exchange.request.vote.leader_id.term > old_term && exchange.response.as_ref().is_ok_and(|response| response.vote_granted)) {
                    // All survivors observe a newer term and leader, and an
                    // independent process has granted the actual campaign.
                    return;
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        }).await;
        if result.is_err() {
            eprintln!(
                "campaign candidate={candidate} old_term={old_term} votes={:?}",
                self.votes(candidate).await
            );
            for index in indices {
                eprintln!(
                    "voter {index}: {}",
                    std::fs::read_to_string(self.root.join(format!("voter-{index}.log"))).unwrap()
                );
                if let Ok(Reply::Status {
                    leader,
                    term,
                    last_log,
                    admitted,
                    ..
                }) = call(self.addresses[*index], Request::Status).await
                {
                    eprintln!("voter {index}: leader={leader:?} term={term} last_log={last_log:?} admitted={admitted}");
                }
            }
            panic!("real survivor campaign and peer grant exceeded the existing 30 second bound");
        }
        candidate
    }
}

fn now(start: Instant) -> u64 {
    start.elapsed().as_secs() + 1
}
fn bounds(second: u64) -> ScopeClockBounds {
    let clock = BoundedClock(AtomicU64::new(second));
    clock.bounds().unwrap()
}

struct Progress {
    view: ScopeLeaseView,
    outcome: Option<ScopeBatchOutcome>,
    last_batch: Option<ScopeBatchRequest>,
    rounds: usize,
    closed_replies: usize,
    connection_failures: usize,
    other_io_failures: usize,
    last_renewal: Instant,
    phase: &'static str,
    campaign_active: bool,
    campaign_gap_pending: bool,
    gaps: BTreeMap<&'static str, (Duration, Duration)>,
}

// Learner catch-up and coordinator resumption must not suspend renewals.
// The process fixture allows 2 s between successful renewals
// including local scheduling and durable SQLite I/O. Only a confirmed leader
// loss followed by the real campaign hook has the larger budget: the pinned
// 8 s leader lease plus 4 s for the granted campaign and first exact retry.
const RENEWAL_GAP_BUDGET: Duration = Duration::from_secs(2);
const CAMPAIGN_GAP_BUDGET: Duration = Duration::from_secs(12);

impl Progress {
    fn record_io_failure(&mut self, error: std::io::Error) {
        match error.kind() {
            std::io::ErrorKind::ConnectionRefused => self.connection_failures += 1,
            std::io::ErrorKind::UnexpectedEof => self.closed_replies += 1,
            _ => self.other_io_failures += 1,
        }
    }

    fn renewed(&mut self) {
        let now = Instant::now();
        let gap = now.duration_since(self.last_renewal);
        self.last_renewal = now;
        let campaign = self.campaign_active || self.campaign_gap_pending;
        if !self.campaign_active {
            self.campaign_gap_pending = false;
        }
        let (normal, election) = self.gaps.entry(self.phase).or_default();
        let (longest, budget) = if campaign {
            (election, CAMPAIGN_GAP_BUDGET)
        } else {
            (normal, RENEWAL_GAP_BUDGET)
        };
        *longest = (*longest).max(gap);
        assert!(
            gap <= budget,
            "{} renewal gap {gap:?} exceeds {budget:?}; campaign={campaign}",
            self.phase
        );
    }

    fn report_gaps(&self, injected_lease: usize, injected_batch: usize) {
        for (phase, (normal, campaign)) in &self.gaps {
            eprintln!("scope_membership_renewal_gap phase={phase} longest_ms={} normal_ms={} campaign_ms={} normal_budget_ms={} campaign_budget_ms={}", normal.max(campaign).as_millis(), normal.as_millis(), campaign.as_millis(), RENEWAL_GAP_BUDGET.as_millis(), CAMPAIGN_GAP_BUDGET.as_millis());
        }
        eprintln!("scope_membership_reply_loss injected_lease={injected_lease} injected_batch={injected_batch} closed_replies={} connection_failures={} other_io_failures={}", self.closed_replies, self.connection_failures, self.other_io_failures);
    }
}

async fn pump(
    addresses: Vec<SocketAddr>,
    preferred: Arc<AtomicUsize>,
    stopped: Arc<AtomicBool>,
    progress: Arc<StdMutex<Progress>>,
    start: Instant,
) {
    let mut serial = 0_u128;
    loop {
        if stopped.load(Ordering::SeqCst) {
            return;
        }
        serial += 1;
        let view = progress.lock().unwrap().view.clone();
        let lease = ScopeLeaseRequest::new(
            view.scope().clone(),
            (0x5000 + serial).to_be_bytes(),
            view.revision(),
            ScopeLeaseOperation::Renew {
                permit: view.permit().unwrap().clone(),
            },
        )
        .unwrap();
        let renewed = loop {
            assert!(
                view.permit().unwrap().is_live_at(bounds(now(start))),
                "membership must never exhaust the prior permit"
            );
            let reply = call(
                addresses[preferred.load(Ordering::SeqCst)],
                Request::Execute {
                    at: now(start),
                    actor: "worker-1".into(),
                    request: Box::new(lease.clone()),
                    crash_after_commit: false,
                },
            )
            .await;
            match reply {
                Ok(Reply::Scope(result)) => match *result {
                    Ok(view) => break view,
                    Err(
                        ScopeLeaseError::Unavailable
                        | ScopeLeaseError::OutcomeUnknown
                        | ScopeLeaseError::ProfileNotActivated,
                    ) => (),
                    Err(error) => panic!("renewal was violated: {error:?}"),
                },
                Err(error) => {
                    progress.lock().unwrap().record_io_failure(error);
                }
                _ => panic!("scope reply expected"),
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        };
        progress.lock().unwrap().renewed();
        assert_eq!(renewed.grant_floor(), 1);
        assert_eq!(
            renewed.permit().unwrap().execution(),
            view.permit().unwrap().execution()
        );
        let previous = progress.lock().unwrap().outcome.clone();
        let revision = previous.as_ref().map_or(0, ScopeBatchOutcome::revision);
        let mutation = previous.as_ref().map_or_else(
            || create_child(1, 1),
            |outcome| ScopeChildMutation::CompareAndSet {
                key: child_key(1),
                expected: outcome.rows()[0],
                value: child_value(1),
                claims: vec![child_claim(1)],
            },
        );
        let batch = ScopeBatchRequest::new(
            renewed.permit().unwrap(),
            (0x6000 + serial).to_be_bytes(),
            revision,
            vec![mutation],
            vec![ScopeCounterMutation::new(0, revision, revision + 1).unwrap()],
        )
        .unwrap();
        let outcome = loop {
            assert!(
                renewed.permit().unwrap().is_live_at(bounds(now(start))),
                "batch retries must remain covered by a live permit"
            );
            match call(
                addresses[preferred.load(Ordering::SeqCst)],
                Request::ExecuteBatch {
                    at: now(start),
                    actor: "worker-1".into(),
                    request: Box::new(batch.clone()),
                    crash_after_commit: false,
                },
            )
            .await
            {
                Ok(Reply::Batch(result)) => match *result {
                    Ok(outcome) => break outcome,
                    Err(
                        ScopeBatchError::Unavailable
                        | ScopeBatchError::OutcomeUnknown
                        | ScopeBatchError::Scope(
                            ScopeLeaseError::Unavailable
                            | ScopeLeaseError::OutcomeUnknown
                            | ScopeLeaseError::ProfileNotActivated,
                        ),
                    ) => (),
                    Err(error) => panic!("batch was violated: {error:?}"),
                },
                Err(error) => {
                    progress.lock().unwrap().record_io_failure(error);
                }
                _ => panic!("batch reply expected"),
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        };
        assert_eq!(outcome.revision(), revision + 1);
        assert_eq!(outcome.rows()[0].birth(), 1);
        assert_eq!(outcome.rows()[0].generation(), revision + 1);
        {
            let mut state = progress.lock().unwrap();
            state.view = renewed;
            state.outcome = Some(outcome);
            state.last_batch = Some(batch);
            state.rounds += 1;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn progressed(progress: &StdMutex<Progress>, rounds: usize) {
    tokio::time::timeout(Duration::from_secs(30), async {
        while progress.lock().unwrap().rounds < rounds {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("renewals and batches resume before permit expiry");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_profile_processes_carry_activation_through_membership_and_leader_loss() {
    let _permit = TestCluster::acquire_test_permit().await;
    let _snapshot_permit = ELECTION_AND_SNAPSHOT_TEST_PERMIT.acquire().await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let snapshots = fs_verity_snapshot_tempdir("scope-membership-processes-");
    let mut fleet = Processes::start_membership(root.path(), snapshots.path());
    // Initial formation explicitly initializes Raft. It can already have a
    // leader without a new vote exchange; automatic elections are disabled.
    let (leader, term) = fleet.ready(&[0, 1, 2], None).await;
    let scope = fleet.current(leader).await.scope().clone();
    fleet
        .execute(
            leader,
            0,
            "controller",
            request(
                &scope,
                0,
                1,
                ScopeLeaseOperation::Select {
                    execution: execution(1),
                },
            ),
        )
        .await
        .unwrap();
    let view = fleet
        .execute(
            leader,
            0,
            "worker-1",
            request(
                &scope,
                1,
                2,
                ScopeLeaseOperation::Acquire {
                    execution: execution(1),
                    selection: 1,
                },
            ),
        )
        .await
        .unwrap();
    let start = Instant::now();
    let preferred = Arc::new(AtomicUsize::new(leader));
    let stopped = Arc::new(AtomicBool::new(false));
    let progress = Arc::new(StdMutex::new(Progress {
        view,
        outcome: None,
        last_batch: None,
        rounds: 0,
        closed_replies: 0,
        connection_failures: 0,
        other_io_failures: 0,
        last_renewal: start,
        phase: "initial",
        campaign_active: false,
        campaign_gap_pending: false,
        gaps: BTreeMap::new(),
    }));
    let work = tokio::spawn(pump(
        fleet.addresses.clone(),
        preferred.clone(),
        stopped.clone(),
        progress.clone(),
        start,
    ));
    fleet.membership_control(leader, Control::LoseReplies).await;
    progressed(&progress, 2).await;
    let (mut injected_lease, mut injected_batch) =
        match fleet.membership_control(leader, Control::Evidence).await {
            ControlReply::Evidence {
                lost_lease,
                lost_batch,
                ..
            } => (lost_lease, lost_batch),
            _ => panic!("leader reply-loss evidence expected"),
        };
    assert_eq!((injected_lease, injected_batch), (1, 1));

    let anchor = match fleet.membership_control(leader, Control::Anchor).await {
        ControlReply::Anchor(anchor) => anchor,
        _ => panic!("anchor expected"),
    };
    let expand = Transition {
        current: vec![0, 1, 2],
        desired: vec![0, 1, 2, 3, 4],
        epoch: 1,
        seed: 0xA3,
    };
    progress.lock().unwrap().phase = "expansion";
    for index in [3, 4] {
        fleet.configurations[index] = Some(Configuration {
            current: expand.current.clone(),
            epoch: 1,
            candidate: Some((anchor, expand.clone())),
            staged: Some(expand.clone()),
        });
        fleet.spawn(index);
    }
    fleet.listening(&expand.desired).await;
    for index in &expand.desired {
        fleet.topology(*index, &expand, Step::Stage).await;
    }
    // Leave one current voter behind before the new certificate exists. The
    // remaining current quorum still commits Prepare and its attestation.
    let lagger = (0..3).find(|index| *index != leader).unwrap();
    fleet.crash(lagger);
    fleet
        .membership_control(leader, Control::PausePrepare)
        .await;
    let preparing = {
        let address = fleet.addresses[leader];
        let transition = expand.clone();
        tokio::spawn(async move {
            call(
                address,
                Request::Membership(Control::Topology {
                    transition,
                    step: Step::Prepare,
                }),
            )
            .await
        })
    };
    fleet
        .membership_control(leader, Control::WaitPreparePaused)
        .await;
    fleet
        .topology(leader, &expand, Step::PreparedBeforeMarker)
        .await;
    let certificate_index = match fleet.membership_control(leader, Control::Evidence).await {
        ControlReply::Evidence {
            certificates: 1,
            certificate_index: Some(index),
            ..
        } => index,
        _ => panic!("certificate must be durable before pausing the coordinator"),
    };
    let before = progress.lock().unwrap().rounds;
    progressed(&progress, before + 2).await;
    for index in [3, 4] {
        assert!(matches!(
            fleet.membership_control(index, Control::Evidence).await,
            ControlReply::Evidence {
                probes: 1,
                certificates: 0,
                ..
            }
        ));
        fleet
            .membership_control(index, Control::RejectProfileProbes)
            .await;
    }

    // Compact past the certificate while the lagger is down, then require a
    // real InstallSnapshot RPC and the certificate's exact row generation on
    // that voter. Its pre-crash database cannot supply this row itself.
    let snapshot_cut = match call(fleet.addresses[leader], Request::Snapshot)
        .await
        .unwrap()
    {
        Reply::Snapshot {
            applied, purged, ..
        } => {
            assert!(purged >= applied && applied >= certificate_index);
            applied
        }
        _ => panic!("snapshot evidence expected"),
    };
    fleet.configurations[lagger].as_mut().unwrap().staged = Some(expand.clone());
    fleet.spawn(lagger);
    fleet.listening(&[lagger]).await;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if matches!(fleet.membership_control(lagger, Control::Evidence).await,
                ControlReply::Evidence { snapshot_requests, snapshot_index: Some(cut), certificates: 1, certificate_index: Some(index), .. }
                    if snapshot_requests > 0 && cut >= snapshot_cut && index == certificate_index) {
                break;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }).await.expect("snapshot installation carries the exact continuation row to the lagger");
    eprintln!("scope_membership_snapshot carried_certificate_index={certificate_index} snapshot_cut={snapshot_cut} lagger={lagger}");

    // No marker, volatile probe or caller proof survives this loss inside
    // Prepare. The survivor must recover solely from the replicated row.
    {
        let mut state = progress.lock().unwrap();
        state.campaign_active = true;
        state.campaign_gap_pending = true;
    }
    fleet.crash(leader);
    assert!(
        preparing.await.unwrap().is_err(),
        "the process exited before replying to Prepare"
    );
    let survivors = (0..3).filter(|index| *index != leader).collect::<Vec<_>>();
    let successor = fleet.campaign(&survivors, term).await;
    preferred.store(successor, Ordering::SeqCst);
    progress.lock().unwrap().campaign_active = false;
    fleet.configurations[leader].as_mut().unwrap().staged = Some(expand.clone());
    fleet.spawn(leader);
    fleet.listening(&[leader]).await;
    fleet.topology(successor, &expand, Step::Prepare).await;
    assert!(
        matches!(fleet.membership_control(successor, Control::Evidence).await,
        ControlReply::Evidence { certificate_index: Some(index), .. } if index == certificate_index)
    );
    fleet.topology(successor, &expand, Step::Commit).await;
    for index in &expand.desired {
        fleet.topology(*index, &expand, Step::Settled).await;
    }
    fleet.ready(&expand.desired, None).await;
    for index in [3, 4] {
        assert!(
            matches!(
                fleet.membership_control(index, Control::Evidence).await,
                ControlReply::Evidence {
                    probes: 1,
                    rejected_probes: 0,
                    certificates: 1,
                    ..
                }
            ),
            "the new leader must use committed profile evidence without probing again"
        );
    }

    let unavailable = expand
        .desired
        .iter()
        .copied()
        .filter(|index| *index != successor)
        .take(2)
        .collect::<Vec<_>>();
    let before = progress.lock().unwrap().rounds;
    for index in &unavailable {
        fleet.crash(*index);
    }
    progressed(&progress, before + 2).await;
    for index in unavailable {
        fleet.configurations[index] = Some(Configuration {
            current: expand.desired.clone(),
            epoch: 2,
            candidate: None,
            staged: None,
        });
        fleet.spawn(index);
    }
    fleet.ready(&expand.desired, None).await;
    let retained = std::iter::once(successor)
        .chain(
            expand
                .desired
                .iter()
                .copied()
                .filter(|index| *index != successor)
                .take(2),
        )
        .collect::<Vec<_>>();
    progress.lock().unwrap().phase = "abort";
    let abort = Transition {
        current: expand.desired.clone(),
        desired: retained.clone(),
        epoch: 2,
        seed: 0xA4,
    };
    for index in &abort.current {
        fleet.topology(*index, &abort, Step::Stage).await;
    }
    fleet.topology(successor, &abort, Step::Prepare).await;
    let before = progress.lock().unwrap().rounds;
    progressed(&progress, before + 2).await;
    fleet.topology(successor, &abort, Step::Abort).await;
    for index in &abort.current {
        fleet.topology(*index, &abort, Step::AbortedSettled).await;
    }
    let before = progress.lock().unwrap().rounds;
    progressed(&progress, before + 2).await;

    progress.lock().unwrap().phase = "contraction";
    let contract = Transition {
        seed: 0xA5,
        ..abort
    };
    for index in &contract.current {
        fleet.topology(*index, &contract, Step::Stage).await;
    }
    fleet
        .membership_control(successor, Control::PausePrepare)
        .await;
    let preparing = {
        let address = fleet.addresses[successor];
        let transition = contract.clone();
        tokio::spawn(async move {
            call(
                address,
                Request::Membership(Control::Topology {
                    transition,
                    step: Step::Prepare,
                }),
            )
            .await
        })
    };
    fleet
        .membership_control(successor, Control::WaitPreparePaused)
        .await;
    fleet
        .topology(successor, &contract, Step::PreparedBeforeMarker)
        .await;
    let lost_certificate_index = match fleet.membership_control(successor, Control::Evidence).await
    {
        ControlReply::Evidence {
            certificates: 1,
            certificate_index: Some(index),
            ..
        } => index,
        _ => panic!("lost reply must follow a committed certificate"),
    };
    fleet
        .membership_control(successor, Control::LoseCertificateReply)
        .await;
    assert!(
        matches!(
            preparing.await.unwrap().unwrap(),
            Reply::Membership(ControlReply::Transition {
                retryable: true,
                ..
            })
        ),
        "the lost certificate acknowledgement reaches the coordinator as retryable uncertainty"
    );
    fleet.topology(successor, &contract, Step::Prepare).await;
    assert!(
        matches!(fleet.membership_control(successor, Control::Evidence).await,
        ControlReply::Evidence { lost_certificate: 1, certificate_index: Some(index), .. } if index == lost_certificate_index)
    );
    fleet.topology(successor, &contract, Step::Commit).await;
    for index in &retained {
        fleet.topology(*index, &contract, Step::Settled).await;
    }
    fleet.ready(&retained, None).await;
    let before = progress.lock().unwrap().rounds;
    fleet.crash(retained[2]);
    fleet
        .membership_control(successor, Control::LoseReplies)
        .await;
    progressed(&progress, before + 2).await;
    let (successor_lost_lease, successor_lost_batch) =
        match fleet.membership_control(successor, Control::Evidence).await {
            ControlReply::Evidence {
                lost_lease,
                lost_batch,
                lost_certificate: 1,
                ..
            } => (lost_lease, lost_batch),
            _ => panic!("successor reply-loss and certificate evidence expected"),
        };
    assert_eq!(
        (successor_lost_lease, successor_lost_batch),
        (1, 1),
        "the successor must actually inject both contraction reply losses"
    );
    injected_lease += successor_lost_lease;
    injected_batch += successor_lost_batch;

    // Removed processes are fenced, but Raft no longer replicates to them and
    // need not deliver terminal cleanup. Re-adding retained process storage
    // needs a separate reintegration fixture; the exact new-certificate rule
    // is covered by the SQLite removed-voter readdition regression.
    let (_, successor_term) = fleet.ready(&retained[..2], None).await;
    for index in (0..5).filter(|index| !retained.contains(index)) {
        assert!(matches!(
            call(fleet.addresses[index], Request::Status).await.unwrap(),
            Reply::Status {
                admitted: false,
                ..
            }
        ));
        fleet.crash(index);
    }
    stopped.store(true, Ordering::SeqCst);
    work.await.unwrap();
    let (view, last_batch, outcome) = {
        let state = progress.lock().unwrap();
        assert_eq!(state.view.grant_floor(), 1);
        assert!(state.view.permit().unwrap().is_live_at(bounds(now(start))));
        assert!(state.closed_replies >= 4);
        // Exact injected-loss counts were read from the responsible process
        // after each phase. Connection failures cannot satisfy those checks.
        state.report_gaps(injected_lease, injected_batch);
        (
            state.view.clone(),
            state.last_batch.clone().unwrap(),
            state.outcome.clone().unwrap(),
        )
    };
    assert!(fleet
        .execute(
            successor,
            now(start),
            "worker-2",
            request(
                &scope,
                view.revision(),
                9,
                ScopeLeaseOperation::Acquire {
                    execution: execution(2),
                    selection: 1
                }
            )
        )
        .await
        .is_err());
    assert_eq!(
        fleet.current(successor).await,
        view,
        "remote acquire cannot interrupt the live grant"
    );

    // Compact and restart the surviving quorum. The third voter stays down:
    // startup cannot obtain unanimous reactivation, even accidentally.
    for index in &retained[..2] {
        assert!(matches!(
            fleet.membership_control(*index, Control::Evidence).await,
            ControlReply::Evidence {
                certificates: 1,
                ..
            }
        ));
        assert_eq!(
            fleet
                .batch(*index, now(start), "worker-1", last_batch.clone())
                .await
                .unwrap(),
            outcome
        );
        assert!(matches!(
            call(fleet.addresses[*index], Request::Snapshot)
                .await
                .unwrap(),
            Reply::Snapshot { .. }
        ));
    }
    for index in &retained[..2] {
        fleet.crash(*index);
    }
    {
        let mut state = progress.lock().unwrap();
        state.phase = "compacted_restart";
        state.campaign_gap_pending = true;
    }
    for index in &retained[..2] {
        fleet.configurations[*index] = Some(Configuration {
            current: retained.clone(),
            epoch: 3,
            candidate: None,
            staged: None,
        });
        fleet.spawn(*index);
    }
    let restarted = fleet.campaign(&retained[..2], successor_term).await;
    fleet.ready(&retained[..2], None).await;
    let renewed = fleet
        .execute(
            restarted,
            now(start),
            "worker-1",
            request(
                &scope,
                view.revision(),
                10,
                ScopeLeaseOperation::Renew {
                    permit: view.permit().unwrap().clone(),
                },
            ),
        )
        .await
        .unwrap();
    assert_eq!(renewed.grant_floor(), 1);
    {
        let mut state = progress.lock().unwrap();
        state.renewed();
        state.report_gaps(injected_lease, injected_batch);
    }
    assert_eq!(
        fleet
            .batch(restarted, now(start), "worker-1", last_batch)
            .await
            .unwrap(),
        outcome
    );
    eprintln!("membership continuity: one grant; live permits; lease/batch replies lost and resolved; durable certificate recovered with one voter down");
}
