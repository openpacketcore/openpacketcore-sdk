//! Each voter owns its own process, SQLite root, listener and Raft runtime.
//! The local test control channel injects trusted admission/time fixtures; it
//! is not a production consumer transport or an authentication implementation.

use super::*;
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
    Current,
    Execute {
        at: u64,
        actor: String,
        request: Box<ScopeLeaseRequest>,
        crash_after_commit: bool,
    },
    Snapshot,
}

#[derive(Serialize, Deserialize)]
enum Reply {
    Rpc(SessionConsensusWireResponse),
    Status {
        pid: u32,
        node: SessionConsensusNodeId,
        leader: Option<SessionConsensusNodeId>,
        term: u64,
    },
    Scope(Box<Result<ScopeLeaseView, ScopeLeaseError>>),
    Snapshot {
        applied: u64,
        snapshot: u64,
        purged: u64,
        rows: u64,
    },
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
        match call(
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
        }
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
    let peers = (0..MEMBER_COUNT)
        .filter(|n| *n != index)
        .map(|n| {
            let peer: Arc<dyn SessionConsensusPeer> = Arc::new(Peer {
                node: nodes[n],
                source: nodes[index],
                address: addresses[n],
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
        tokio::spawn(async move {
            let Ok(request) = read_frame::<Request>(&mut socket).await else {
                return;
            };
            let reply = match request {
                Request::Rpc { sender, request } => {
                    Reply::Rpc(store.rpc_handler().handle(sender, request).await)
                }
                Request::Status => {
                    let status = store.status();
                    Reply::Status {
                        pid: std::process::id(),
                        node: status.node_id,
                        leader: status.leader_id,
                        term: status.term,
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
        let mut last_status = Vec::new();
        let mut last_reads = Vec::new();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let statuses = futures_util::future::join_all(
                    active
                        .iter()
                        .map(|n| call(self.addresses[*n], Request::Status)),
                )
                .await;
                let mut observations = Vec::new();
                let mut pids = std::collections::BTreeSet::new();
                for (n, status) in active.iter().zip(statuses) {
                    if let Ok(Reply::Status {
                        pid,
                        node,
                        leader: Some(leader),
                        term,
                    }) = status
                    {
                        assert_ne!(pid, std::process::id());
                        pids.insert(pid);
                        observations.push((*n, node, leader, term));
                    }
                }
                last_status.clone_from(&observations);
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
}
impl Drop for Processes {
    fn drop(&mut self) {
        for n in 0..self.children.len() {
            self.crash(n);
        }
    }
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
    let (new_leader, new_term) = fleet.ready(&alive, Some(term)).await;
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
        fleet.execute(alive[0], 111, "worker-1", renewal),
        fleet.execute(alive[1], 112, "controller", selection)
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
