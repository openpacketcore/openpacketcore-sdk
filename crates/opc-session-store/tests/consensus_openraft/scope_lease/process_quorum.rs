//! Each voter owns its own process, SQLite root, listener and Raft runtime.
//! The local test control channel injects trusted admission/time fixtures; it
//! is not a production consumer transport or an authentication implementation.

use super::*;
use opc_consensus::engine::raft::{VoteRequest, VoteResponse};
use opc_session_store::scope_batch::{
    ScopeBatchError, ScopeBatchOutcome, ScopeBatchRequest, ScopeBatchStore, ScopeChildKey,
    ScopeChildMutation, ScopeChildRecord, ScopeClaimKey, ScopeCounterMutation, ScopeSealedValue,
    SCOPE_COUNTERS,
};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const NODE_ENV: &str = "OPC_SCOPE_PROCESS_NODE";
const TEST_NAME: &str = "scope_lease::process_quorum::scope_quorum_processes_fail_over_race_and_recover_compacted_authority";
const FRAME_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
enum Request {
    Rpc {
        sender: SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    },
    Status,
    PrepareSplitVote {
        peer: SessionConsensusNodeId,
    },
    VoteState,
    ReleaseSplitVote,
    ElectionControl {
        automatic: bool,
        campaign: bool,
    },
    Current,
    Execute {
        at: u64,
        actor: String,
        request: Box<ScopeLeaseRequest>,
        crash_after_commit: bool,
    },
    ExecuteBatch {
        at: u64,
        actor: String,
        request: Box<ScopeBatchRequest>,
        crash_after_commit: bool,
    },
    ReadBatch {
        keys: Vec<ScopeChildKey>,
    },
    Snapshot,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct BatchState {
    revision: u64,
    counters: [u64; SCOPE_COUNTERS],
    rows: Vec<Option<ScopeChildRecord>>,
}

#[derive(Serialize, Deserialize)]
enum Reply {
    Rpc(SessionConsensusWireResponse),
    Controlled,
    VoteState(Box<VoteState>),
    Status {
        pid: u32,
        node: SessionConsensusNodeId,
        leader: Option<SessionConsensusNodeId>,
        term: u64,
        applied: Option<u64>,
        last_log: Option<u64>,
        admitted: bool,
        health: String,
    },
    Scope(Box<Result<ScopeLeaseView, ScopeLeaseError>>),
    Batch(Box<Result<ScopeBatchOutcome, ScopeBatchError>>),
    BatchState(Box<BatchState>),
    Snapshot {
        applied: u64,
        snapshot: u64,
        purged: u64,
        rows: u64,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct VoteExchange {
    request: VoteRequest<SessionConsensusNodeId>,
    response: Result<VoteResponse<SessionConsensusNodeId>, String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct VoteState {
    peer: Option<SessionConsensusNodeId>,
    first: Option<VoteRequest<SessionConsensusNodeId>>,
    split: Option<VoteExchange>,
    latest: Option<VoteExchange>,
}

#[derive(Debug)]
struct VoteControl {
    state: StdMutex<VoteState>,
    released: tokio::sync::watch::Sender<bool>,
}

async fn write_frame<T: Serialize>(stream: &mut TcpStream, value: &T) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    if bytes.len() > FRAME_LIMIT {
        return Err(std::io::Error::other("oversize test frame"));
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await
}

async fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut TcpStream) -> std::io::Result<T> {
    let length = stream.read_u32().await? as usize;
    if length > FRAME_LIMIT {
        return Err(std::io::Error::other("oversize test frame"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(std::io::Error::other)
}

async fn call(address: SocketAddr, request: Request) -> std::io::Result<Reply> {
    tokio::time::timeout(Duration::from_secs(45), async {
        let mut stream = TcpStream::connect(address).await?;
        write_frame(&mut stream, &request).await?;
        read_frame(&mut stream).await
    })
    .await
    .map_err(std::io::Error::other)?
}

#[derive(Debug)]
struct Peer {
    node: SessionConsensusNodeId,
    source: SessionConsensusNodeId,
    address: SocketAddr,
    votes: Arc<VoteControl>,
}

#[async_trait]
impl SessionConsensusPeer for Peer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.node
    }
    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        let observed = {
            let mut state = self.votes.state.lock().unwrap();
            if request.family == SessionConsensusRpcFamily::Vote && state.peer == Some(self.node) {
                let vote = decode_bounded::<VoteRequest<SessionConsensusNodeId>>(&request.payload)
                    .expect("decode controlled vote");
                let first = state.first.is_none();
                if first {
                    state.first = Some(vote.clone());
                }
                Some((vote, first))
            } else {
                None
            }
        };
        if observed.as_ref().is_some_and(|(_, first)| *first) {
            // Both processes must have persisted their own natural campaign
            // before either request reaches its peer. The latched release
            // prevents losing the parent's notification between polls.
            self.votes
                .released
                .subscribe()
                .wait_for(|released| *released)
                .await
                .unwrap();
        }
        let result = match call(
            self.address,
            Request::Rpc {
                sender: self.source,
                request,
            },
        )
        .await
        {
            Ok(Reply::Rpc(reply)) => Ok(reply),
            _ => Err(SessionConsensusPeerError::Unavailable),
        };
        if let Some((request, first)) = observed {
            let response = result
                .as_ref()
                .map_err(|error| format!("{error:?}"))
                .and_then(|reply| reply.result.as_ref().map_err(|error| format!("{error:?}")))
                .and_then(|payload| {
                    decode_bounded::<
                        Result<
                            VoteResponse<SessionConsensusNodeId>,
                            RaftError<SessionConsensusNodeId>,
                        >,
                    >(payload)
                    .map_err(|error| format!("{error:?}"))
                })
                .and_then(|reply| reply.map_err(|error| format!("{error:?}")));
            let exchange = VoteExchange { request, response };
            let mut state = self.votes.state.lock().unwrap();
            if first {
                state.split = Some(exchange.clone());
            }
            state.latest = Some(exchange);
        }
        result
    }
}

async fn run_voter(index: usize, root: &Path, snapshots: &Path, addresses: &[SocketAddr]) {
    let listener = TcpListener::bind(addresses[index]).await.unwrap();
    let members = (0..MEMBER_COUNT).map(member).collect::<Vec<_>>();
    let identity = consensus_identity(&members);
    let topologies = (0..MEMBER_COUNT)
        .map(|n| {
            ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
                replica_id(n),
                members.clone(),
                identity,
            ))
            .unwrap()
        })
        .collect::<Vec<_>>();
    let nodes = topologies
        .iter()
        .map(|topology| topology.local_consensus_node_id().unwrap())
        .collect::<Vec<_>>();
    let votes = Arc::new(VoteControl {
        state: StdMutex::new(VoteState::default()),
        released: tokio::sync::watch::channel(false).0,
    });
    let peers = (0..MEMBER_COUNT)
        .filter(|n| *n != index)
        .map(|n| {
            let peer: Arc<dyn SessionConsensusPeer> = Arc::new(Peer {
                node: nodes[n],
                source: nodes[index],
                address: addresses[n],
                votes: votes.clone(),
            });
            (nodes[n], peer)
        })
        .collect();
    let database = root.join(format!("voter-{index}.sqlite"));
    let store = ConsensusSessionStore::open_with_clock(
        topologies[index].clone(),
        SqliteSessionBackend::open(&database).unwrap(),
        snapshots.join(format!("voter-{index}")),
        peers,
        Arc::new(SystemClock),
        DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
    )
    .await
    .unwrap();
    let initializing = store.clone();
    let clock = Arc::new(BoundedClock(AtomicU64::new(0)));
    let authority = Arc::new(tokio::sync::OnceCell::new());
    let initialized = authority.clone();
    let initial_clock = clock.clone();
    tokio::spawn(async move {
        initializing.initialize_cluster().await.unwrap();
        initialized
            .set(service(&initializing, initial_clock))
            .unwrap();
    });
    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        let store = store.clone();
        let authority = authority.clone();
        let clock = clock.clone();
        let database = database.clone();
        let votes = votes.clone();
        tokio::spawn(async move {
            let Ok(request) = read_frame::<Request>(&mut socket).await else {
                return;
            };
            let reply = match request {
                Request::Rpc { sender, request } => {
                    Reply::Rpc(store.rpc_handler().handle(sender, request).await)
                }
                Request::PrepareSplitVote { peer } => {
                    *votes.state.lock().unwrap() = VoteState {
                        peer: Some(peer),
                        ..VoteState::default()
                    };
                    votes.released.send_replace(false);
                    Reply::Controlled
                }
                Request::VoteState => {
                    Reply::VoteState(Box::new(votes.state.lock().unwrap().clone()))
                }
                Request::ReleaseSplitVote => {
                    votes.released.send_replace(true);
                    Reply::Controlled
                }
                Request::ElectionControl {
                    automatic,
                    campaign,
                } => {
                    store.set_automatic_election_for_test(automatic);
                    if campaign {
                        store.trigger_election_for_test().await.unwrap();
                    }
                    Reply::Controlled
                }
                Request::Status => {
                    let status = store.status();
                    Reply::Status {
                        pid: std::process::id(),
                        node: status.node_id,
                        leader: status.leader_id,
                        term: status.term,
                        applied: status.applied_index,
                        last_log: status.last_log_index,
                        admitted: status.admitted,
                        health: format!("{:?}", store.persistence_health()),
                    }
                }
                Request::Current => Reply::Scope(Box::new(match authority.get() {
                    Some(authority) => authority.current(&principal("worker-1")).await,
                    None => Err(ScopeLeaseError::Unavailable),
                })),
                Request::Execute {
                    at,
                    actor,
                    request,
                    crash_after_commit,
                } => {
                    clock.0.store(at, Ordering::SeqCst);
                    let result = match authority.get() {
                        Some(authority) => authority.execute(&principal(&actor), &request).await,
                        None => Err(ScopeLeaseError::Unavailable),
                    };
                    if crash_after_commit {
                        assert!(
                            result.is_ok(),
                            "crash must follow the durable effect: {result:?}"
                        );
                        // Deliberate process loss before the reply, with the other
                        // two voter processes still running and serving Raft.
                        std::process::exit(77);
                    }
                    Reply::Scope(Box::new(result))
                }
                Request::ExecuteBatch {
                    at,
                    actor,
                    request,
                    crash_after_commit,
                } => {
                    clock.0.store(at, Ordering::SeqCst);
                    let scope = authority
                        .get()
                        .unwrap()
                        .current(&principal("worker-1"))
                        .await
                        .unwrap()
                        .scope()
                        .clone();
                    let batch = batch_service(&store, clock, &scope);
                    let result = batch.execute(&principal(&actor), &request).await;
                    if crash_after_commit {
                        assert!(
                            result.is_ok(),
                            "crash must follow a committed batch: {result:?}"
                        );
                        std::process::exit(77);
                    }
                    Reply::Batch(Box::new(result))
                }
                Request::ReadBatch { keys } => {
                    let scope = authority
                        .get()
                        .unwrap()
                        .current(&principal("worker-1"))
                        .await
                        .unwrap()
                        .scope()
                        .clone();
                    let batch = batch_service(&store, clock, &scope);
                    let view = batch.current(&principal("worker-1")).await.unwrap();
                    let mut rows = Vec::new();
                    for key in keys {
                        rows.push(batch.read(&principal("worker-1"), key).await.unwrap());
                    }
                    Reply::BatchState(Box::new(BatchState {
                        revision: view.revision(),
                        counters: *view.counters(),
                        rows,
                    }))
                }
                Request::Snapshot => {
                    use opc_session_store::consensus::test_support::{
                        consensus_local_durable_progress_for_test,
                        trigger_consensus_log_purge_through_for_test,
                        trigger_consensus_snapshot_for_test,
                    };
                    authority
                        .get()
                        .unwrap()
                        .current(&principal("worker-1"))
                        .await
                        .unwrap();
                    let applied = store.status().applied_index.unwrap();
                    trigger_consensus_snapshot_for_test(&store).await.unwrap();
                    tokio::time::timeout(Duration::from_secs(30), async {
                        while consensus_local_durable_progress_for_test(&store)
                            .snapshot_index
                            .is_none_or(|cut| cut < applied)
                        {
                            tokio::time::sleep(POLL_INTERVAL).await;
                        }
                    })
                    .await
                    .unwrap();
                    trigger_consensus_log_purge_through_for_test(&store, applied)
                        .await
                        .unwrap();
                    tokio::time::timeout(Duration::from_secs(30), async {
                        while consensus_local_durable_progress_for_test(&store)
                            .purged_index
                            .is_none_or(|cut| cut < applied)
                        {
                            tokio::time::sleep(POLL_INTERVAL).await;
                        }
                    })
                    .await
                    .unwrap();
                    let progress = consensus_local_durable_progress_for_test(&store);
                    let conn = rusqlite::Connection::open(database).unwrap();
                    let rows = conn
                        .query_row(
                            "SELECT COUNT(*) FROM consensus_request_outcomes",
                            [],
                            |row| row.get(0),
                        )
                        .unwrap();
                    Reply::Snapshot {
                        applied,
                        snapshot: progress.snapshot_index.unwrap(),
                        purged: progress.purged_index.unwrap(),
                        rows,
                    }
                }
            };
            let _ = write_frame(&mut socket, &reply).await;
        });
    }
}

struct Processes {
    children: Vec<Option<Child>>,
    addresses: Vec<SocketAddr>,
    root: PathBuf,
    snapshots: PathBuf,
}

impl Processes {
    fn start(root: &Path, snapshots: &Path) -> Self {
        let listeners = (0..MEMBER_COUNT)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect::<Vec<_>>();
        let addresses = listeners
            .iter()
            .map(|listener| listener.local_addr().unwrap())
            .collect();
        drop(listeners);
        let mut fleet = Self {
            children: (0..MEMBER_COUNT).map(|_| None).collect(),
            addresses,
            root: root.to_path_buf(),
            snapshots: snapshots.to_path_buf(),
        };
        for n in 0..MEMBER_COUNT {
            fleet.spawn(n);
        }
        fleet
    }
    fn spawn(&mut self, index: usize) {
        assert!(self.children[index].is_none());
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join(format!("voter-{index}.log")))
            .unwrap();
        self.children[index] = Some(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
                .env(NODE_ENV, index.to_string())
                .env(ROOT_ENV, &self.root)
                .env(SNAPSHOT_ENV, &self.snapshots)
                .env(
                    "OPC_SCOPE_PROCESS_ADDRESSES",
                    serde_json::to_string(&self.addresses).unwrap(),
                )
                .stdin(Stdio::null())
                .stdout(Stdio::from(log.try_clone().unwrap()))
                .stderr(Stdio::from(log))
                .spawn()
                .unwrap(),
        );
    }
    fn crash(&mut self, index: usize) {
        if let Some(mut child) = self.children[index].take() {
            let _ = child.kill();
            child.wait().unwrap();
        }
    }
    async fn ready(&self, active: &[usize], after_term: Option<u64>) -> (usize, u64) {
        self.ready_until(
            active,
            after_term,
            tokio::time::Instant::now() + Duration::from_secs(30),
        )
        .await
    }
    async fn ready_until(
        &self,
        active: &[usize],
        after_term: Option<u64>,
        deadline: tokio::time::Instant,
    ) -> (usize, u64) {
        let mut last_status = Vec::new();
        let mut last_reads = Vec::new();
        tokio::time::timeout_at(deadline, async {
            loop {
                let statuses = futures_util::future::join_all(
                    active
                        .iter()
                        .map(|n| call(self.addresses[*n], Request::Status)),
                )
                .await;
                last_status = active.iter().zip(&statuses).map(|(index, reply)| match reply {
                    Ok(Reply::Status { pid, node, leader, term, applied, last_log, admitted, health }) => {
                        format!("voter={index} pid={pid} node={node:?} leader={leader:?} term={term} applied={applied:?} last_log={last_log:?} admitted={admitted} health={health}")
                    }
                    Ok(_) => format!("voter={index} unexpected status reply"),
                    Err(error) => format!("voter={index} status transport error: {error}"),
                }).collect();
                let mut observations = Vec::new();
                let mut pids = std::collections::BTreeSet::new();
                for (n, status) in active.iter().zip(statuses) {
                    if let Ok(Reply::Status {
                        pid,
                        node,
                        leader: Some(leader),
                        term,
                        ..
                    }) = status
                    {
                        assert_ne!(pid, std::process::id());
                        pids.insert(pid);
                        observations.push((*n, node, leader, term));
                    }
                }
                if observations.len() == active.len() && pids.len() == active.len() {
                    let leader = observations[0].2;
                    let term = observations[0].3;
                    if after_term.is_none_or(|old| term > old)
                        && observations
                            .iter()
                            .all(|item| item.2 == leader && item.3 == term)
                    {
                        if let Some((index, _, _, _)) =
                            observations.iter().find(|item| item.1 == leader)
                        {
                            let reads = futures_util::future::join_all(
                                active
                                    .iter()
                                    .map(|n| call(self.addresses[*n], Request::Current)),
                            )
                            .await;
                            last_reads = reads
                                .iter()
                                .map(|reply| match reply {
                                    Ok(Reply::Scope(result)) => format!("{result:?}"),
                                    Ok(_) => "unexpected reply".to_owned(),
                                    Err(error) => error.to_string(),
                                })
                                .collect::<Vec<_>>();
                            if reads.iter().all(
                                |reply| matches!(reply, Ok(Reply::Scope(result)) if result.is_ok()),
                            ) {
                                return (*index, term);
                            }
                        }
                    }
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            eprintln!("last quorum status: {last_status:?}; reads: {last_reads:?}");
            for n in active {
                eprintln!(
                    "voter {n}: {}",
                    std::fs::read_to_string(self.root.join(format!("voter-{n}.log"))).unwrap()
                );
            }
            panic!("multi-process quorum did not become ready");
        })
    }
    async fn control(&self, index: usize, request: Request) {
        assert!(matches!(
            call(self.addresses[index], request).await.unwrap(),
            Reply::Controlled
        ));
    }
    async fn votes(&self, index: usize) -> VoteState {
        match call(self.addresses[index], Request::VoteState)
            .await
            .unwrap()
        {
            Reply::VoteState(state) => *state,
            _ => panic!("vote state expected"),
        }
    }
    async fn prepare_survivor_split(&self, leader: usize) {
        let mut survivors = Vec::new();
        for index in (0..MEMBER_COUNT).filter(|index| *index != leader) {
            match call(self.addresses[index], Request::Status).await.unwrap() {
                Reply::Status { node, .. } => survivors.push((index, node)),
                _ => panic!("survivor status expected"),
            }
        }
        for (source, target) in [(0, 1), (1, 0)] {
            self.control(
                survivors[source].0,
                Request::PrepareSplitVote {
                    peer: survivors[target].1,
                },
            )
            .await;
        }
    }
    async fn ready_after_split(&self, alive: &[usize], old_term: u64) -> (usize, u64) {
        assert_eq!(alive.len(), 2);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut states = Vec::new();
        let candidate = tokio::time::timeout_at(deadline, async {
            loop {
                states = futures_util::future::join_all(alive.iter().map(|n| self.votes(*n))).await;
                if states.iter().all(|state| state.first.is_some()) {
                    break;
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
            let first = states[0].first.as_ref().unwrap();
            let second = states[1].first.as_ref().unwrap();
            assert_eq!(first.vote.leader_id.term, second.vote.leader_id.term);
            for (index, state) in alive.iter().zip(&states) {
                let vote = &state.first.as_ref().unwrap().vote;
                assert!(vote.leader_id.term > old_term && !vote.committed);
                match call(self.addresses[*index], Request::Status).await.unwrap() {
                    Reply::Status {
                        node, leader, term, ..
                    } => {
                        assert_eq!(leader, None, "both survivors must observe leader loss");
                        assert_eq!(term, vote.leader_id.term);
                        assert_eq!(vote.leader_id.voted_for, Some(node));
                    }
                    _ => panic!("survivor status expected"),
                }
                // Once both natural campaigns are observed, freeze automatic
                // retries so only the explicitly selected follow-up can win.
                self.control(
                    *index,
                    Request::ElectionControl {
                        automatic: false,
                        campaign: false,
                    },
                )
                .await;
            }
            for index in alive {
                self.control(*index, Request::ReleaseSplitVote).await;
            }
            loop {
                states = futures_util::future::join_all(alive.iter().map(|n| self.votes(*n))).await;
                if states.iter().all(|state| state.split.is_some()) {
                    break;
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
            for state in &states {
                let split = state.split.as_ref().unwrap();
                let response = split
                    .response
                    .as_ref()
                    .expect("real peer handles split vote");
                assert!(!response.vote_granted, "both self-votes reject the rival");
                assert_eq!(
                    response.vote.leader_id.term,
                    split.request.vote.leader_id.term
                );
                assert_eq!(response.vote.leader_id.voted_for, state.peer);
            }
            eprintln!("confirmed survivor split votes: {states:?}");

            // These fixtures qualify scope recovery through a real quorum.
            // Natural retry timing after repeated splits is covered by #1154;
            // one normal engine campaign must fit the existing fixture bound.
            let candidate = states
                .iter()
                .enumerate()
                .max_by_key(|(_, state)| state.first.as_ref().unwrap().last_log_id)
                .map(|(index, _)| index)
                .unwrap();
            let split_term = states[candidate]
                .first
                .as_ref()
                .unwrap()
                .vote
                .leader_id
                .term;
            self.control(
                alive[candidate],
                Request::ElectionControl {
                    automatic: false,
                    campaign: true,
                },
            )
            .await;
            loop {
                states[candidate] = self.votes(alive[candidate]).await;
                if let Some(exchange) = &states[candidate].latest {
                    if exchange.request.vote.leader_id.term > split_term {
                        let response = exchange
                            .response
                            .as_ref()
                            .expect("surviving peer answers the follow-up campaign");
                        assert!(
                            response.vote_granted,
                            "the other survivor must grant its vote"
                        );
                        assert_eq!(response.vote.leader_id, exchange.request.vote.leader_id);
                        eprintln!("confirmed survivor campaign grant: {exchange:?}");
                        break;
                    }
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
            alive[candidate]
        })
        .await
        .unwrap_or_else(|error| panic!("survivor split/campaign: {error}; votes={states:?}"));
        let elected = self.ready_until(alive, Some(old_term), deadline).await;
        assert_eq!(elected.0, candidate);
        tokio::time::timeout_at(deadline, async {
            for index in alive {
                self.control(
                    *index,
                    Request::ElectionControl {
                        automatic: true,
                        campaign: false,
                    },
                )
                .await;
            }
        })
        .await
        .expect("restore automatic elections within the unchanged failover deadline");
        elected
    }
    async fn current(&self, index: usize) -> ScopeLeaseView {
        match call(self.addresses[index], Request::Current).await.unwrap() {
            Reply::Scope(result) => (*result).unwrap(),
            _ => panic!("scope reply expected"),
        }
    }
    async fn execute(
        &self,
        index: usize,
        at: u64,
        actor: &str,
        request: ScopeLeaseRequest,
    ) -> Result<ScopeLeaseView, ScopeLeaseError> {
        match call(
            self.addresses[index],
            Request::Execute {
                at,
                actor: actor.into(),
                request: Box::new(request),
                crash_after_commit: false,
            },
        )
        .await
        .unwrap()
        {
            Reply::Scope(result) => *result,
            _ => panic!("scope reply expected"),
        }
    }

    async fn batch(
        &self,
        index: usize,
        at: u64,
        actor: &str,
        request: ScopeBatchRequest,
    ) -> Result<ScopeBatchOutcome, ScopeBatchError> {
        match call(
            self.addresses[index],
            Request::ExecuteBatch {
                at,
                actor: actor.into(),
                request: Box::new(request),
                crash_after_commit: false,
            },
        )
        .await
        .unwrap()
        {
            Reply::Batch(result) => *result,
            _ => panic!("batch reply expected"),
        }
    }

    async fn batch_state(&self, index: usize) -> BatchState {
        match call(
            self.addresses[index],
            Request::ReadBatch {
                keys: (1..=3).map(child_key).collect(),
            },
        )
        .await
        .unwrap()
        {
            Reply::BatchState(state) => *state,
            _ => panic!("batch state expected"),
        }
    }

    async fn applied(&self, index: usize) -> u64 {
        match call(self.addresses[index], Request::Status).await.unwrap() {
            Reply::Status {
                applied: Some(index),
                ..
            } => index,
            _ => panic!("applied index expected"),
        }
    }
}
impl Drop for Processes {
    fn drop(&mut self) {
        for n in 0..self.children.len() {
            self.crash(n);
        }
    }
}

fn batch_service(
    store: &ConsensusSessionStore,
    clock: Arc<BoundedClock>,
    scope: &ScopeLeaseId,
) -> ScopeBatchStore {
    ScopeBatchStore::new(
        Arc::new(store.clone()),
        scope.clone(),
        clock,
        Arc::new(Admission(scope.clone())),
    )
    .unwrap()
}

fn child_key(n: u8) -> ScopeChildKey {
    ScopeChildKey::new([n; 32]).unwrap()
}

fn child_claim(n: u8) -> ScopeClaimKey {
    ScopeClaimKey::new([n; 32]).unwrap()
}

fn child_value(n: u8) -> ScopeSealedValue {
    ScopeSealedValue::new(
        opc_crypto::CryptoEnvelopeV1 {
            algorithm: opc_key::AeadAlgorithm::Aes256GcmSiv,
            key_id: opc_key::KeyId::new("synthetic-scope-key").unwrap(),
            nonce: vec![n; 12],
            aad: vec![n; 32],
            ciphertext_and_tag: vec![n; 32],
        }
        .encode()
        .unwrap(),
    )
    .unwrap()
}

fn create_child(n: u8, claim: u8) -> ScopeChildMutation {
    ScopeChildMutation::Create {
        key: child_key(n),
        value: child_value(n),
        claims: vec![child_claim(claim)],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_batch_processes_fail_over_fence_and_recover_compacted_children() {
    let _permit = TestCluster::acquire_test_permit().await;
    let _snapshot_permit = ELECTION_AND_SNAPSHOT_TEST_PERMIT.acquire().await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let snapshots = fs_verity_snapshot_tempdir("scope-batch-processes-");
    let mut fleet = Processes::start(root.path(), snapshots.path());
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
    let displaced = view.permit().unwrap().clone();
    let first = ScopeBatchRequest::new(
        &displaced,
        [3; 16],
        0,
        vec![create_child(1, 1), create_child(2, 2)],
        vec![ScopeCounterMutation::new(0, 0, 2).unwrap()],
    )
    .unwrap();
    fleet.prepare_survivor_split(leader).await;
    assert!(call(
        fleet.addresses[leader],
        Request::ExecuteBatch {
            at: 1,
            actor: "worker-1".into(),
            request: Box::new(first.clone()),
            crash_after_commit: true,
        },
    )
    .await
    .is_err());
    assert_eq!(
        fleet.children[leader]
            .as_mut()
            .unwrap()
            .wait()
            .unwrap()
            .code(),
        Some(77)
    );
    fleet.children[leader] = None;
    let alive = (0..MEMBER_COUNT)
        .filter(|n| *n != leader)
        .collect::<Vec<_>>();
    let (successor, successor_term) = fleet.ready_after_split(&alive, term).await;
    assert_ne!(successor, leader);
    assert!(successor_term > term);
    let before_replay = fleet.applied(successor).await;
    let first_outcome = fleet.batch(successor, 2, "worker-1", first).await.unwrap();
    assert_eq!(
        fleet.applied(successor).await,
        before_replay,
        "exact retry appends no command"
    );
    let first_state = fleet.batch_state(successor).await;
    assert_eq!(first_state.revision, 1);
    assert_eq!(first_state.counters[0], 2);
    assert_eq!(&first_state.counters[1..], &[0; SCOPE_COUNTERS - 1]);
    for (index, record) in first_state.rows[..2].iter().enumerate() {
        let record = record.as_ref().unwrap();
        assert_eq!(record.revision(), first_outcome.rows()[index]);
        assert_eq!(record.revision().birth(), index as u64 + 1);
        assert_eq!(record.revision().generation(), 1);
        assert_eq!(record.value(), Some(&child_value(index as u8 + 1)));
        assert_eq!(record.claims(), &[child_claim(index as u8 + 1)]);
    }
    assert!(first_state.rows[2].is_none());
    let stale = ScopeBatchRequest::new(
        &displaced,
        [4; 16],
        1,
        vec![ScopeChildMutation::CompareAndSet {
            key: child_key(1),
            expected: first_outcome.rows()[0],
            value: child_value(9),
            claims: vec![child_claim(1)],
        }],
        vec![ScopeCounterMutation::new(0, 2, 3).unwrap()],
    )
    .unwrap();
    assert_eq!(
        fleet.batch(successor, 78, "worker-1", stale.clone()).await,
        Err(ScopeBatchError::Scope(ScopeLeaseError::Expired))
    );
    assert_eq!(fleet.batch_state(successor).await, first_state);
    let handover = (displaced
        .excluded_until()
        .as_offset_datetime()
        .unix_timestamp()
        - 1_800_000_000) as u64;
    let selected = fleet
        .execute(
            successor,
            handover,
            "controller",
            request(
                &scope,
                view.revision(),
                5,
                ScopeLeaseOperation::Select {
                    execution: execution(2),
                },
            ),
        )
        .await
        .unwrap();
    let granted = fleet
        .execute(
            successor,
            handover,
            "worker-2",
            request(
                &scope,
                selected.revision(),
                6,
                ScopeLeaseOperation::Acquire {
                    execution: execution(2),
                    selection: 2,
                },
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        fleet
            .batch(successor, handover + 1, "worker-1", stale)
            .await,
        Err(ScopeBatchError::Scope(ScopeLeaseError::StalePermit))
    );
    assert_eq!(fleet.batch_state(successor).await, first_state);
    let second = ScopeBatchRequest::new(
        granted.permit().unwrap(),
        [7; 16],
        1,
        vec![
            ScopeChildMutation::CompareAndSet {
                key: child_key(1),
                expected: first_outcome.rows()[0],
                value: child_value(7),
                claims: vec![child_claim(1)],
            },
            ScopeChildMutation::Delete {
                key: child_key(2),
                expected: first_outcome.rows()[1],
            },
            create_child(3, 2),
        ],
        vec![ScopeCounterMutation::new(0, 2, 4).unwrap()],
    )
    .unwrap();
    let outcome = fleet
        .batch(successor, handover + 1, "worker-2", second.clone())
        .await
        .unwrap();
    let expected = fleet.batch_state(successor).await;
    assert_eq!(expected.revision, 2);
    assert_eq!(expected.counters[0], 4);
    assert_eq!(expected.rows[0].as_ref().unwrap().revision().birth(), 1);
    assert_eq!(
        expected.rows[0].as_ref().unwrap().revision().generation(),
        2
    );
    assert_eq!(
        expected.rows[0].as_ref().unwrap().value(),
        Some(&child_value(7))
    );
    assert!(expected.rows[1].is_none());
    assert_eq!(expected.rows[2].as_ref().unwrap().revision().birth(), 3);
    assert_eq!(
        expected.rows[2].as_ref().unwrap().claims(),
        &[child_claim(2)]
    );

    fleet.spawn(leader);
    fleet.ready(&[0, 1, 2], None).await;
    for n in 0..MEMBER_COUNT {
        assert_eq!(fleet.batch_state(n).await, expected);
        match call(fleet.addresses[n], Request::Snapshot).await.unwrap() {
            Reply::Snapshot {
                applied,
                snapshot,
                purged,
                rows,
            } => {
                assert!(snapshot >= applied && purged >= applied);
                assert_eq!(rows, 1, "batches add no generic request receipts");
            }
            _ => panic!("snapshot reply expected"),
        }
    }
    for n in 0..MEMBER_COUNT {
        fleet.crash(n);
    }
    for n in 0..MEMBER_COUNT {
        fleet.spawn(n);
    }
    let (restarted_leader, _) = fleet.ready(&[0, 1, 2], None).await;
    for n in 0..MEMBER_COUNT {
        assert_eq!(fleet.batch_state(n).await, expected);
    }
    let before_replay = fleet.applied(restarted_leader).await;
    assert_eq!(
        fleet
            .batch(restarted_leader, handover + 2, "worker-2", second)
            .await
            .unwrap(),
        outcome,
        "batch outcome survives leader loss, all-process restart and log compaction"
    );
    assert_eq!(fleet.applied(restarted_leader).await, before_replay);
    let conflict = ScopeBatchRequest::new(
        granted.permit().unwrap(),
        [8; 16],
        2,
        vec![create_child(2, 2)],
        vec![ScopeCounterMutation::new(0, 4, 5).unwrap()],
    )
    .unwrap();
    assert!(
        matches!(
            fleet.batch(restarted_leader, handover + 2, "worker-2", conflict).await,
            Err(ScopeBatchError::Conflict(conflicts)) if conflicts.claims == vec![child_claim(2)]
        ),
        "recovered claim ownership must still reject a competing birth"
    );
    assert_eq!(fleet.batch_state(restarted_leader).await, expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_quorum_processes_fail_over_race_and_recover_compacted_authority() {
    if let Ok(index) = std::env::var(NODE_ENV) {
        run_voter(
            index.parse().unwrap(),
            Path::new(&std::env::var(ROOT_ENV).unwrap()),
            Path::new(&std::env::var(SNAPSHOT_ENV).unwrap()),
            &serde_json::from_str::<Vec<SocketAddr>>(
                &std::env::var("OPC_SCOPE_PROCESS_ADDRESSES").unwrap(),
            )
            .unwrap(),
        )
        .await;
        return;
    }
    let _permit = TestCluster::acquire_test_permit().await;
    let _snapshot_permit = ELECTION_AND_SNAPSHOT_TEST_PERMIT.acquire().await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let snapshots = fs_verity_snapshot_tempdir("scope-real-processes-");
    let mut fleet = Processes::start(root.path(), snapshots.path());
    let (leader, term) = fleet.ready(&[0, 1, 2], None).await;
    let initial = fleet.current(leader).await;
    let scope = initial.scope().clone();
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
    let acquire = request(
        &scope,
        1,
        2,
        ScopeLeaseOperation::Acquire {
            execution: execution(1),
            selection: 1,
        },
    );
    fleet.prepare_survivor_split(leader).await;
    assert!(call(
        fleet.addresses[leader],
        Request::Execute {
            at: 0,
            actor: "worker-1".into(),
            request: Box::new(acquire.clone()),
            crash_after_commit: true
        }
    )
    .await
    .is_err());
    let status = fleet.children[leader].as_mut().unwrap().wait().unwrap();
    assert_eq!(
        status.code(),
        Some(77),
        "leader dies between durable grant and its reply"
    );
    fleet.children[leader] = None;
    let alive = (0..MEMBER_COUNT)
        .filter(|n| *n != leader)
        .collect::<Vec<_>>();
    let (new_leader, new_term) = fleet.ready_after_split(&alive, term).await;
    assert_ne!(leader, new_leader);
    assert!(new_term > term);
    let mut view = fleet
        .execute(alive[0], 50, "worker-1", acquire)
        .await
        .unwrap();
    assert_eq!(
        view.permit().unwrap().issued_at(),
        BoundedClock(AtomicU64::new(0)).bounds().unwrap().latest()
    );
    view = fleet
        .execute(
            alive[1],
            51,
            "worker-1",
            request(
                &scope,
                view.revision(),
                3,
                ScopeLeaseOperation::Renew {
                    permit: view.permit().unwrap().clone(),
                },
            ),
        )
        .await
        .unwrap();
    let latest_pre_race = view.permit().unwrap().clone();
    let renewal = request(
        &scope,
        view.revision(),
        4,
        ScopeLeaseOperation::Renew {
            permit: latest_pre_race,
        },
    );
    let selection = request(
        &scope,
        view.revision(),
        5,
        ScopeLeaseOperation::Select {
            execution: execution(2),
        },
    );
    let (a, b) = tokio::join!(
        fleet.execute(alive[0], 128, "worker-1", renewal),
        fleet.execute(alive[1], 129, "controller", selection)
    );
    assert_eq!(
        usize::from(a.is_ok()) + usize::from(b.is_ok()),
        1,
        "Renew and Select cannot both win the same predecessor"
    );
    assert_eq!(
        a.as_ref().err().or(b.as_ref().err()),
        Some(&ScopeLeaseError::Conflict)
    );
    view = a.or(b).unwrap();
    // Capture the CURRENT old permit after any successful renewal, then let
    // another execution acquire with NO release. This assertion is sensitive
    // to the intervening-grant guard, unlike a pre-renewal permit fixture.
    let displaced = view.permit().unwrap().clone();
    assert_eq!(fleet.current(alive[0]).await.permit(), Some(&displaced));
    let expiry = (displaced
        .excluded_until()
        .as_offset_datetime()
        .unix_timestamp()
        - 1_800_000_000) as u64;
    if view.selection() == 1 {
        view = fleet
            .execute(
                alive[0],
                expiry,
                "controller",
                request(
                    &scope,
                    view.revision(),
                    6,
                    ScopeLeaseOperation::Select {
                        execution: execution(2),
                    },
                ),
            )
            .await
            .unwrap();
    }
    view = fleet
        .execute(
            alive[1],
            expiry,
            "worker-2",
            request(
                &scope,
                view.revision(),
                7,
                ScopeLeaseOperation::Acquire {
                    execution: execution(2),
                    selection: 2,
                },
            ),
        )
        .await
        .unwrap();
    assert_eq!(view.grant_floor(), 2);
    assert_eq!(
        fleet
            .execute(
                alive[0],
                expiry + 1,
                "worker-1",
                request(
                    &scope,
                    view.revision(),
                    8,
                    ScopeLeaseOperation::ResumeSameExecution { permit: displaced }
                )
            )
            .await,
        Err(ScopeLeaseError::StalePermit)
    );
    assert_eq!(
        fleet
            .execute(
                alive[1],
                expiry + 1,
                "controller",
                request(
                    &scope,
                    view.revision(),
                    9,
                    ScopeLeaseOperation::Select {
                        execution: execution(1)
                    }
                )
            )
            .await,
        Err(ScopeLeaseError::Superseded)
    );
    let release = request(
        &scope,
        view.revision(),
        10,
        ScopeLeaseOperation::Release {
            closed: ScopeGateClosed::after_gate_closed(view.permit().unwrap().clone()),
        },
    );
    let released = fleet
        .execute(alive[0], expiry + 1, "worker-2", release.clone())
        .await
        .unwrap();
    fleet.spawn(leader);
    fleet.ready(&[0, 1, 2], None).await;
    for n in 0..MEMBER_COUNT {
        assert_eq!(fleet.current(n).await, released);
        match call(fleet.addresses[n], Request::Snapshot).await.unwrap() {
            Reply::Snapshot {
                applied,
                snapshot,
                purged,
                rows,
            } => {
                assert!(snapshot >= applied && purged >= applied);
                assert_eq!(
                    rows, 1,
                    "scope operations leave one checkpoint on every voter"
                );
            }
            _ => panic!("snapshot reply expected"),
        }
    }
    for n in 0..MEMBER_COUNT {
        fleet.crash(n);
    }
    for n in 0..MEMBER_COUNT {
        fleet.spawn(n);
    }
    fleet.ready(&[0, 1, 2], None).await;
    assert_eq!(
        fleet
            .execute(0, expiry + 2, "worker-2", release)
            .await
            .unwrap(),
        released,
        "release replay survives independent process loss and log compaction"
    );
}
