//! Scope command accounting and real multi-process quorum qualification.

use super::*;
use opc_session_store::scope_authority::*;
use opc_session_store::SessionConsumerIdentity;

const ROOT_ENV: &str = "OPC_SCOPE_AUTHORITY_TEST_ROOT";
const SNAPSHOT_ENV: &str = "OPC_SCOPE_AUTHORITY_TEST_SNAPSHOTS";

fn principal(name: &str) -> SessionConsumerIdentity {
    SessionConsumerIdentity::new(format!("spiffe://scope.test/{name}")).unwrap()
}

fn execution(n: u8) -> ScopeExecution {
    ScopeExecution::new(
        principal(&format!("worker-{n}")),
        u64::from(n),
        [n; 16],
        [n; 16],
        [n; 32],
    )
    .unwrap()
}

struct Admission(ScopeId);
#[async_trait]
impl ScopeAuthorityAdmission for Admission {
    async fn authorize(
        &self,
        authenticated: &SessionConsumerIdentity,
        scope: &ScopeId,
        claim: Option<&ScopeExecution>,
        _: ScopeAuthorityAction,
        _: Option<[u8; 32]>,
    ) -> Result<ScopeAuthorityRole, ScopeAuthorityError> {
        if scope != &self.0
            || claim.is_some_and(|value| value != &execution(1) && value != &execution(2))
        {
            return Err(ScopeAuthorityError::Unauthorized);
        }
        if authenticated == &principal("observer") {
            return Ok(ScopeAuthorityRole::Observer);
        }
        if authenticated == &principal("controller") {
            return Ok(ScopeAuthorityRole::ScopeController);
        }
        if (authenticated == &principal("worker-1") || authenticated == &principal("worker-2"))
            && claim.is_none_or(|value| value.identity() == authenticated)
        {
            return Ok(ScopeAuthorityRole::Worker);
        }
        Err(ScopeAuthorityError::Unauthorized)
    }
    // This local fixture injects trusted closure facts; transport verification
    // is tested at the service boundary and supplied by the real host policy.
    async fn verify_closure(
        &self,
        _: &SessionConsumerIdentity,
        _: &ScopeAuthorityStamp,
        _: &ScopeClosureEvidence,
        _: [u8; 32],
    ) -> Result<(), ScopeAuthorityError> {
        Ok(())
    }
}
fn closed_proof(n: u8) -> ScopeClosureEvidence {
    ScopeClosureEvidence::new(ScopeClosureKind::LocalQuiescence, [n; 32]).unwrap()
}
fn termination_proof(n: u8) -> ScopeClosureEvidence {
    ScopeClosureEvidence::new(ScopeClosureKind::FinalTermination, [n; 32]).unwrap()
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

fn service(store: &ConsensusSessionStore) -> ScopeAuthorityStore {
    let scope = ScopeId::new(
        store.consumer_scope().unwrap().consensus_identity(),
        TenantId::new("scope-quorum-test").unwrap(),
        NetworkFunctionKind::new("test").unwrap(),
        [1; 32],
    )
    .unwrap();
    ScopeAuthorityStore::new(
        Arc::new(store.clone()),
        scope.clone(),
        Arc::new(Admission(scope)),
    )
    .unwrap()
}

fn request(
    scope: &ScopeId,
    revision: u64,
    id: u8,
    operation: ScopeAuthorityOperation,
) -> ScopeAuthorityRequest {
    ScopeAuthorityRequest::new(scope.clone(), [id; 16], revision, operation).unwrap()
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
    let authority = service(&fleet.stores[0]);
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
    let initial = request(
        &scope,
        0,
        1,
        ScopeAuthorityOperation::AdmitInitial {
            execution: execution(1),
        },
    );
    let view = authority
        .execute(&principal("worker-1"), &initial)
        .await
        .unwrap();
    deltas.push(sequence().await - before);
    let before = sequence().await;
    assert_eq!(
        authority
            .execute(&principal("worker-1"), &initial)
            .await
            .unwrap(),
        view
    );
    deltas.push(sequence().await - before);
    let before = sequence().await;
    let closed = authority
        .execute(
            &principal("worker-1"),
            &request(
                &scope,
                view.revision(),
                2,
                ScopeAuthorityOperation::Close {
                    current: view.stamp().unwrap().clone(),
                    evidence: closed_proof(2),
                },
            ),
        )
        .await
        .unwrap();
    deltas.push(sequence().await - before);
    let before = sequence().await;
    let next = request(
        &scope,
        closed.revision(),
        3,
        ScopeAuthorityOperation::SucceedClosed {
            predecessor: closed.stamp().unwrap().clone(),
            execution: execution(2),
            evidence: closed.closed_evidence().unwrap(),
        },
    );
    let view = authority
        .execute(&principal("controller"), &next)
        .await
        .unwrap();
    deltas.push(sequence().await - before);
    let before = sequence().await;
    let token = authority
        .admit(&principal("worker-2"), &next)
        .await
        .unwrap();
    assert_eq!(token.stamp(), view.stamp().unwrap());
    deltas.push(sequence().await - before);
    fleet.close().await;
    assert_eq!(
        deltas,
        [1, 0, 1, 1, 0],
        "each authority change commits once; exact recovery only reads"
    );
}

#[path = "scope_authority/process_quorum.rs"]
mod process_quorum;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn successor_and_scope_readers_resolve_predecessor_outcomes_without_resubmission() {
    use opc_session_store::scope_batch::{
        ScopeBatchError, ScopeBatchRequest, ScopeBatchResolution, ScopeBatchStore,
        ScopeCounterMutation,
    };
    let _permit = TestCluster::acquire_test_permit().await;
    let root = tempfile::tempdir().unwrap();
    let snapshots = fs_verity_snapshot_tempdir("scope-outcome-resolution-");
    let fleet = Fleet::open(root.path(), snapshots.path()).await;
    let authority = service(&fleet.stores[0]);
    let scope = authority
        .current(&principal("worker-1"))
        .await
        .unwrap()
        .scope()
        .clone();
    let first = authority
        .admit(
            &principal("worker-1"),
            &request(
                &scope,
                0,
                1,
                ScopeAuthorityOperation::AdmitInitial {
                    execution: execution(1),
                },
            ),
        )
        .await
        .unwrap();
    let batches = ScopeBatchStore::new(
        Arc::new(fleet.stores[0].clone()),
        first.stamp().namespace().clone(),
        Arc::new(Admission(scope.clone())),
    )
    .unwrap();
    let committed = ScopeBatchRequest::new(
        first.stamp(),
        [2; 16],
        0,
        vec![],
        vec![ScopeCounterMutation::new(0, 0, 7).unwrap()],
    )
    .unwrap();
    let outcome = batches
        .execute(&principal("worker-1"), &committed)
        .await
        .unwrap();
    let pending = ScopeBatchRequest::new(
        first.stamp(),
        [3; 16],
        1,
        vec![],
        vec![ScopeCounterMutation::new(0, 7, 8).unwrap()],
    )
    .unwrap();
    assert_eq!(
        batches
            .predecessor_outcome(&principal("worker-1"), first.stamp(), &pending)
            .await,
        Err(ScopeBatchError::InvalidRequest),
        "absence cannot prove NotApplied while its authority remains current"
    );
    let next = request(
        &scope,
        1,
        4,
        ScopeAuthorityOperation::SucceedClosed {
            predecessor: first.stamp().clone(),
            execution: execution(2),
            evidence: termination_proof(2),
        },
    );
    authority
        .execute(&principal("controller"), &next)
        .await
        .unwrap();
    let successor = authority
        .admit(&principal("worker-2"), &next)
        .await
        .unwrap();
    let before = fleet.stores[0].status().applied_index;
    for actor in ["worker-2", "observer", "controller"] {
        assert_eq!(
            batches
                .predecessor_outcome(&principal(actor), successor.stamp(), &committed)
                .await
                .unwrap_or_else(|error| panic!("{actor} outcome read failed: {error}")),
            ScopeBatchResolution::Applied(Box::new(outcome.clone()))
        );
        assert_eq!(
            batches
                .predecessor_outcome(&principal(actor), successor.stamp(), &pending)
                .await
                .unwrap_or_else(|error| panic!("{actor} outcome read failed: {error}")),
            ScopeBatchResolution::NotApplied
        );
    }
    assert_eq!(
        fleet.stores[0].status().applied_index,
        before,
        "resolution is read-only"
    );
    assert_eq!(
        batches.execute(&principal("worker-1"), &pending).await,
        Err(ScopeBatchError::Scope(ScopeAuthorityError::StaleAuthority))
    );
    assert_eq!(
        batches
            .current(&principal("observer"))
            .await
            .unwrap()
            .counters()[0],
        7
    );
    let replacement = ScopeBatchRequest::new(
        successor.stamp(),
        [5; 16],
        1,
        vec![],
        vec![ScopeCounterMutation::new(0, 7, 8).unwrap()],
    )
    .unwrap();
    batches
        .execute(&principal("worker-2"), &replacement)
        .await
        .unwrap();
    assert_eq!(
        batches
            .predecessor_outcome(&principal("observer"), successor.stamp(), &committed)
            .await
            .unwrap(),
        ScopeBatchResolution::Unknown
    );
    fleet.close().await;
}
