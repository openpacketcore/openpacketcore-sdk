//! Scope command accounting and real multi-process quorum qualification.

use super::*;
use opc_session_store::scope_lease::{
    ScopeClockBounds, ScopeExecution, ScopeGateClosed, ScopeLeaseAction, ScopeLeaseAdmission,
    ScopeLeaseClock, ScopeLeaseError, ScopeLeaseId, ScopeLeaseOperation, ScopeLeaseRequest,
    ScopeLeaseStore, ScopeLeaseView,
};
use opc_session_store::SessionConsumerIdentity;

const ROOT_ENV: &str = "OPC_SCOPE_LEASE_TEST_ROOT";
const SNAPSHOT_ENV: &str = "OPC_SCOPE_LEASE_TEST_SNAPSHOTS";

fn principal(name: &str) -> SessionConsumerIdentity {
    SessionConsumerIdentity::new(format!("spiffe://scope.test/{name}")).unwrap()
}

fn execution(n: u8) -> ScopeExecution {
    ScopeExecution::new(
        principal(&format!("worker-{n}")),
        u64::from(n),
        [n; 16],
        [n; 16],
        [n; 16],
    )
    .unwrap()
}

struct BoundedClock(AtomicU64);

impl ScopeLeaseClock for BoundedClock {
    fn bounds(&self) -> Result<ScopeClockBounds, ScopeLeaseError> {
        let time = opc_types::Timestamp::from_offset_datetime(
            time::OffsetDateTime::from_unix_timestamp(
                1_800_000_000 + self.0.load(Ordering::SeqCst) as i64,
            )
            .unwrap(),
        );
        ScopeClockBounds::new(time, time)
    }
}

struct Admission(ScopeLeaseId);

#[async_trait]
impl ScopeLeaseAdmission for Admission {
    async fn authorize(
        &self,
        authenticated: &SessionConsumerIdentity,
        scope: &ScopeLeaseId,
        claim: Option<&ScopeExecution>,
        action: ScopeLeaseAction,
    ) -> Result<(), ScopeLeaseError> {
        if scope != &self.0
            || claim.is_some_and(|claim| claim != &execution(1) && claim != &execution(2))
        {
            return Err(ScopeLeaseError::Unauthorized);
        }
        let authorized = match action {
            ScopeLeaseAction::Select => authenticated == &principal("controller"),
            ScopeLeaseAction::Read | ScopeLeaseAction::Mutate => {
                authenticated == &principal("worker-1") || authenticated == &principal("worker-2")
            }
        };
        authorized
            .then_some(())
            .ok_or(ScopeLeaseError::Unauthorized)
    }
}

struct Fleet {
    stores: Vec<ConsensusSessionStore>,
    paths: BTreeMap<(usize, usize), Arc<LoopbackPeer>>,
}

impl Fleet {
    async fn open(root: &Path, snapshots: &Path) -> Self {
        let members = (0..MEMBER_COUNT).map(member).collect::<Vec<_>>();
        let identity = consensus_identity(&members);
        let topologies = (0..MEMBER_COUNT)
            .map(|index| {
                ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
                    replica_id(index),
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
        let mut paths = BTreeMap::new();
        for source in 0..MEMBER_COUNT {
            for (target, node) in nodes.iter().enumerate() {
                if source != target {
                    paths.insert((source, target), Arc::new(LoopbackPeer::new(*node)));
                }
            }
        }
        let mut stores = Vec::new();
        for index in 0..MEMBER_COUNT {
            let backend =
                SqliteSessionBackend::open(root.join(format!("voter-{index}.sqlite"))).unwrap();
            let peers = (0..MEMBER_COUNT)
                .filter(|target| *target != index)
                .map(|target| {
                    let peer: Arc<dyn SessionConsensusPeer> = paths[&(index, target)].clone();
                    (nodes[target], peer)
                })
                .collect();
            stores.push(
                ConsensusSessionStore::open_with_clock(
                    topologies[index].clone(),
                    backend,
                    snapshots.join(format!("voter-{index}")),
                    peers,
                    Arc::new(SystemClock),
                    DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
                )
                .await
                .unwrap(),
            );
        }
        for ((_, target), peer) in &paths {
            peer.install(stores[*target].rpc_handler());
        }
        for result in futures_util::future::join_all(
            stores.iter().map(ConsensusSessionStore::initialize_cluster),
        )
        .await
        {
            result.unwrap();
        }
        tokio::time::timeout(CLUSTER_START_TIMEOUT, async {
            loop {
                if futures_util::future::join_all(
                    stores
                        .iter()
                        .map(ConsensusSessionStore::probe_durable_readiness),
                )
                .await
                .iter()
                .all(|report| report.is_ready())
                {
                    break;
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        })
        .await
        .expect("persistent scope quorum becomes ready");
        Self { stores, paths }
    }

    async fn close(self) {
        for peer in self.paths.values() {
            peer.clear_handler();
        }
        for result in
            futures_util::future::join_all(self.stores.iter().map(ConsensusSessionStore::shutdown))
                .await
        {
            result.unwrap();
        }
    }
}

fn service(store: &ConsensusSessionStore, clock: Arc<BoundedClock>) -> ScopeLeaseStore {
    let scope = ScopeLeaseId::new(
        store.consumer_scope().unwrap().consensus_identity(),
        TenantId::new("scope-quorum-test").unwrap(),
        NetworkFunctionKind::new("test").unwrap(),
        [1; 32],
    )
    .unwrap();
    ScopeLeaseStore::new(
        Arc::new(store.clone()),
        scope.clone(),
        clock,
        Arc::new(Admission(scope)),
    )
    .unwrap()
}

fn request(
    scope: &ScopeLeaseId,
    revision: u64,
    id: u8,
    operation: ScopeLeaseOperation,
) -> ScopeLeaseRequest {
    ScopeLeaseRequest::new(scope.clone(), [id; 16], revision, operation).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_operations_each_commit_one_command_without_receipt_history() {
    let _permit = TestCluster::acquire_test_permit().await;
    let root = tempfile::tempdir().unwrap();
    let snapshots = fs_verity_snapshot_tempdir("scope-command-accounting-");
    let fleet = Fleet::open(root.path(), snapshots.path()).await;
    // Initial unanimous profile activation is a cluster prerequisite. The
    // scope operations below each still append exactly one command.
    fleet.stores[0].activate_scope_profile().await.unwrap();
    let clock = Arc::new(BoundedClock(AtomicU64::new(0)));
    let authority = service(&fleet.stores[0], clock.clone());
    let scope = authority
        .current(&principal("worker-1"))
        .await
        .unwrap()
        .scope()
        .clone();
    let conn = rusqlite::Connection::open(root.path().join("voter-0.sqlite")).unwrap();
    let sequence = async || {
        // A forwarded reply may arrive before this follower applies it.
        // ReadIndex catches the observed database up without a command.
        authority.current(&principal("worker-1")).await.unwrap();
        conn.query_row(
            "SELECT application_sequence FROM consensus_machine WHERE singleton = 1",
            [],
            |row| row.get::<_, u64>(0),
        )
        .unwrap()
    };
    let mut deltas = Vec::new();
    let before = sequence().await;
    let selected = authority
        .execute(
            &principal("controller"),
            &request(
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
    deltas.push(sequence().await - before);
    let before = sequence().await;
    let mut view = authority
        .execute(
            &principal("worker-1"),
            &request(
                &scope,
                selected.revision(),
                2,
                ScopeLeaseOperation::Acquire {
                    execution: execution(1),
                    selection: 1,
                },
            ),
        )
        .await
        .unwrap();
    deltas.push(sequence().await - before);
    for (id, seconds, resume) in [(3, 1, false), (4, 100, true)] {
        clock.0.store(seconds, Ordering::SeqCst);
        let permit = view.permit().unwrap().clone();
        let operation = if resume {
            ScopeLeaseOperation::ResumeSameExecution { permit }
        } else {
            ScopeLeaseOperation::Renew { permit }
        };
        let before = sequence().await;
        view = authority
            .execute(
                &principal("worker-1"),
                &request(&scope, view.revision(), id, operation),
            )
            .await
            .unwrap();
        deltas.push(sequence().await - before);
    }
    let before = sequence().await;
    authority
        .execute(
            &principal("worker-1"),
            &request(
                &scope,
                view.revision(),
                5,
                ScopeLeaseOperation::Release {
                    closed: ScopeGateClosed::after_gate_closed(view.permit().unwrap().clone()),
                },
            ),
        )
        .await
        .unwrap();
    deltas.push(sequence().await - before);
    fleet.close().await;
    assert_eq!(
        deltas,
        [1, 1, 1, 1, 1],
        "Select, Acquire, Renew, Resume, Release each require exactly one application command"
    );
}

#[path = "scope_lease/process_quorum.rs"]
mod process_quorum;
