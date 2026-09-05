use opc_consensus::{
    derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity,
};
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
#[cfg(all(target_os = "linux", feature = "test-control"))]
use opc_session_store::test_support::trigger_consensus_snapshot_for_test;
use opc_session_store::{
    derive_fixed_durable_quorum_consensus_identity, ConsensusSessionStore,
    ConsensusSessionStoreOpenError, FixedQuorumTrafficAuthority, ObservedPhysicalNodeIdentity,
    OwnerId, PlacementResilienceDisposition, PlacementResiliencePolicy, QuorumReplicaDescriptor,
    QuorumTopologyAttestor, QuorumTopologyConfig, QuorumTopologyError, QuorumTopologyMode,
    ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity,
    SessionBackend, SessionConsensusNodeId, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRpcHandler, SessionConsensusWireRequest, SessionConsensusWireResponse,
    SessionConsumerAuthorizationGrant, SessionConsumerIdentity, SessionConsumerRejection,
    SessionConsumerTenantNfScope, SessionKey, SessionKeyType, SessionLeaseManager,
    SessionQuorumConsumer, SessionTopologyAbortAdmissionProof,
    SessionTopologyCandidateRetirementProof, SessionTopologyJointCommitAdmissionProof,
    SessionTopologyPrePrepareUnstageProof, SessionTopologyTransitionError,
    SessionTopologyTransitionId, SessionTopologyTransitionRequest,
    SessionTopologyTransportAdmission, SessionTopologyTransportAdmissionError,
    SessionTopologyUniformCommitAdmissionProof, SnapshotIntegrityPolicy, SqliteSessionBackend,
    TopologyAttestationClaims, TopologyAttestationEvidence, TopologyAttestationPolicy,
    TopologyAttestationProvenance, TopologyAttestationTime, TopologyAttestationVerificationError,
    TopologyAttestationVerificationInput, TopologyCollectorId, ValidatedQuorumTopology,
};
use opc_types::{NetworkFunctionKind, SpiffeId, TenantId};

#[cfg(all(target_os = "linux", feature = "test-control"))]
fn fixed_verity_available_for_test() -> bool {
    use std::os::fd::AsFd as _;

    let directory = fs_verity_snapshot_tempdir("fixed-quorum-verity-probe-");
    let path = directory.path().join("probe");
    let file = std::fs::File::create(&path).expect("create fs-verity capability probe");
    let result = opc_fs_verity_sys::measure(file.as_fd());
    drop(file);
    match result {
        Err(opc_fs_verity_sys::Error::Measure(error))
            if error.raw_os_error() == Some(libc::ENODATA) =>
        {
            true
        }
        Err(opc_fs_verity_sys::Error::Measure(error))
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOTTY) | Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS)
            ) =>
        {
            assert!(
                !fs_verity_qualification_required(),
                "required fs-verity qualification is unsupported at the prepared snapshot root: {error:?}"
            );
            false
        }
        other => panic!("unexpected fs-verity capability probe result: {other:?}"),
    }
}

#[cfg(all(target_os = "linux", feature = "test-control"))]
fn fs_verity_qualification_required() -> bool {
    std::env::var_os("OPC_FS_VERITY_QUALIFICATION").as_deref()
        == Some(std::ffi::OsStr::new("required"))
}

/// Fixed snapshot artifacts must use CI's dedicated fs-verity-capable root.
/// Keep SQLite databases in ordinary temporary storage: they are mutable and
/// the CI root is intentionally only for immutable snapshot artifacts.
#[cfg(all(target_os = "linux", feature = "test-control"))]
fn fs_verity_snapshot_tempdir(prefix: &str) -> tempfile::TempDir {
    const SNAPSHOT_ROOT_ENV: &str = "OPC_FS_VERITY_SNAPSHOT_ROOT";

    let qualification_required = fs_verity_qualification_required();
    match std::env::var_os(SNAPSHOT_ROOT_ENV) {
        Some(root) => {
            let root = PathBuf::from(root);
            assert!(
                root.is_absolute(),
                "{SNAPSHOT_ROOT_ENV} must be an absolute fs-verity snapshot root"
            );
            tempfile::Builder::new()
                .prefix(prefix)
                .tempdir_in(root)
                .expect("create fs-verity snapshot fixture directory")
        }
        None if qualification_required => {
            panic!("required fs-verity qualification requires {SNAPSHOT_ROOT_ENV}")
        }
        None => tempfile::Builder::new()
            .prefix(prefix)
            .tempdir()
            .expect("create local fs-verity snapshot fixture directory"),
    }
}

#[cfg(all(target_os = "linux", feature = "test-control"))]
fn fixed_current_snapshot_path(
    database: &std::path::Path,
    snapshot_directory: &std::path::Path,
) -> PathBuf {
    let connection = rusqlite::Connection::open(database).expect("open fixed snapshot metadata");
    let file_name: String = connection
        .query_row(
            "SELECT file_name FROM consensus_snapshot WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("read fixed current snapshot name");
    snapshot_directory.join(file_name)
}

#[cfg(all(target_os = "linux", feature = "test-control"))]
fn assert_unsealed_snapshot(path: &std::path::Path) {
    use std::os::fd::AsFd as _;

    let file = std::fs::File::open(path).expect("open unsealed fixed snapshot");
    assert!(
        matches!(
            opc_fs_verity_sys::measure(file.as_fd()),
            Err(opc_fs_verity_sys::Error::Measure(error))
                if error.raw_os_error() == Some(libc::ENODATA)
        ),
        "fixture selected snapshot must be exactly unsealed"
    );
}

#[cfg(all(target_os = "linux", feature = "test-control"))]
fn assert_sealed_snapshot(path: &std::path::Path) {
    use std::os::fd::AsFd as _;

    let file = std::fs::File::open(path).expect("open sealed fixed successor");
    opc_fs_verity_sys::measure_exact_profile(file.as_fd())
        .expect("fixed successor must have the exact fs-verity profile");
}

#[derive(Clone, Copy, Debug)]
enum ReleasedCursorOnlyOperatorRecoverySchema {
    Direct,
    AddOn,
    Migrated,
}

fn replace_operator_recovery_with_released_cursor_only_schema(
    database: &std::path::Path,
    schema: ReleasedCursorOnlyOperatorRecoverySchema,
) {
    let connection = rusqlite::Connection::open(database).expect("open fixed-voter schema fixture");
    connection
        .execute_batch(
            "CREATE TEMP TABLE released_cursor_only_recovery AS \
             SELECT singleton, configuration_epoch, recovery_epoch, last_plan_digest, \
                    pending_epoch, pending_plan_digest, watch_cursor_invalidation_floor \
             FROM consensus_operator_recovery; \
             DROP TABLE consensus_operator_recovery;",
        )
        .expect("preserve fixed-voter recovery row");
    match schema {
        ReleasedCursorOnlyOperatorRecoverySchema::Direct => connection
            .execute_batch(
                r#"
                CREATE TABLE consensus_operator_recovery (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
                    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
                    last_plan_digest BLOB NOT NULL CHECK (length(last_plan_digest) = 32),
                    pending_epoch INTEGER CHECK (pending_epoch > recovery_epoch),
                    pending_plan_digest BLOB CHECK (
                        pending_plan_digest IS NULL OR length(pending_plan_digest) = 32
                    ),
                    watch_cursor_invalidation_floor INTEGER NOT NULL CHECK (watch_cursor_invalidation_floor >= 0),
                    CHECK (
                        (pending_epoch IS NULL AND pending_plan_digest IS NULL)
                        OR (pending_epoch IS NOT NULL AND pending_plan_digest IS NOT NULL)
                    ),
                    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
                );
                "#,
            )
            .expect("install released direct cursor-only schema"),
        ReleasedCursorOnlyOperatorRecoverySchema::AddOn => connection
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS consensus_operator_recovery (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
                    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
                    last_plan_digest BLOB NOT NULL CHECK (length(last_plan_digest) = 32),
                    pending_epoch INTEGER CHECK (pending_epoch > recovery_epoch),
                    pending_plan_digest BLOB CHECK (
                        pending_plan_digest IS NULL OR length(pending_plan_digest) = 32
                    ),
                    watch_cursor_invalidation_floor INTEGER NOT NULL DEFAULT 0 CHECK (watch_cursor_invalidation_floor >= 0),
                    CHECK (
                        (pending_epoch IS NULL AND pending_plan_digest IS NULL)
                        OR (pending_epoch IS NOT NULL AND pending_plan_digest IS NOT NULL)
                    ),
                    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
                );
                "#,
            )
            .expect("install released add-on cursor-only schema"),
        ReleasedCursorOnlyOperatorRecoverySchema::Migrated => connection
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS consensus_operator_recovery (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
                    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
                    last_plan_digest BLOB NOT NULL CHECK (length(last_plan_digest) = 32),
                    pending_epoch INTEGER CHECK (pending_epoch > recovery_epoch),
                    pending_plan_digest BLOB CHECK (
                        pending_plan_digest IS NULL OR length(pending_plan_digest) = 32
                    ),
                    CHECK (
                        (pending_epoch IS NULL AND pending_plan_digest IS NULL)
                        OR (pending_epoch IS NOT NULL AND pending_plan_digest IS NOT NULL)
                    ),
                    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
                );
                ALTER TABLE consensus_operator_recovery
                    ADD COLUMN watch_cursor_invalidation_floor INTEGER NOT NULL DEFAULT 0
                    CHECK (watch_cursor_invalidation_floor >= 0);
                "#,
            )
            .expect("install released migrated cursor-only schema"),
    }
    connection
        .execute_batch(
            "INSERT INTO consensus_operator_recovery \
                (singleton, configuration_epoch, recovery_epoch, last_plan_digest, \
                 pending_epoch, pending_plan_digest, watch_cursor_invalidation_floor) \
             SELECT singleton, configuration_epoch, recovery_epoch, last_plan_digest, \
                    pending_epoch, pending_plan_digest, watch_cursor_invalidation_floor \
             FROM released_cursor_only_recovery; \
             DROP TABLE released_cursor_only_recovery;",
        )
        .expect("restore fixed-voter released recovery row");
}

fn fixed_consumer_identity() -> SessionConsumerIdentity {
    SessionConsumerIdentity::new(
        "spiffe://test/tenant/fixed-consumer/ns/default/sa/store/nf/smf/instance/one",
    )
    .expect("canonical fixed consumer identity")
}

fn fixed_consumer_grant() -> SessionConsumerAuthorizationGrant {
    SessionConsumerAuthorizationGrant::try_new(
        SpiffeId::new(
            "spiffe://test/tenant/fixed-consumer/ns/default/sa/store/nf/smf/instance/one",
        )
        .expect("canonical fixed consumer SPIFFE ID"),
        [SessionConsumerTenantNfScope::new(
            TenantId::from_static("fixed-consumer"),
            NetworkFunctionKind::smf(),
        )],
    )
    .expect("fixed consumer grant")
}

#[derive(Debug)]
struct UnscopedPeer {
    node_id: SessionConsensusNodeId,
}

#[async_trait]
impl SessionConsensusPeer for UnscopedPeer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.node_id
    }

    async fn call(
        &self,
        _request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        Err(SessionConsensusPeerError::Unavailable)
    }
}

#[derive(Clone)]
struct ScopedLoopbackPeer {
    node_id: SessionConsensusNodeId,
    identity: ConsensusIdentity,
    handler: Arc<tokio::sync::RwLock<Option<Arc<dyn SessionConsensusRpcHandler>>>>,
    enabled: Arc<AtomicBool>,
}

impl ScopedLoopbackPeer {
    fn new(node_id: SessionConsensusNodeId, identity: ConsensusIdentity) -> Self {
        Self {
            node_id,
            identity,
            handler: Arc::new(tokio::sync::RwLock::new(None)),
            enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    async fn install(&self, handler: Arc<dyn SessionConsensusRpcHandler>) {
        *self.handler.write().await = Some(handler);
    }

    async fn clear(&self) {
        *self.handler.write().await = None;
    }

    fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
    }
}

impl fmt::Debug for ScopedLoopbackPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopedLoopbackPeer")
            .field("node_id", &self.node_id)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SessionConsensusPeer for ScopedLoopbackPeer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.node_id
    }

    fn scope_identity(&self) -> Option<ConsensusIdentity> {
        Some(self.identity)
    }

    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        if !self.enabled.load(Ordering::SeqCst) {
            return Err(SessionConsensusPeerError::Unavailable);
        }
        let handler = self
            .handler
            .read()
            .await
            .clone()
            .ok_or(SessionConsensusPeerError::Unavailable)?;
        Ok(handler.handle(request.sender, request).await)
    }
}

#[derive(Debug)]
struct DigestTopologyAttestor;

impl QuorumTopologyAttestor for DigestTopologyAttestor {
    fn verify(
        &self,
        input: TopologyAttestationVerificationInput<'_>,
    ) -> Result<(), TopologyAttestationVerificationError> {
        (input.proof() == input.canonical_digest())
            .then_some(())
            .ok_or(TopologyAttestationVerificationError::InvalidProof)
    }
}

#[derive(Debug)]
struct NoopTopologyTransport;

#[async_trait]
impl SessionTopologyTransportAdmission for NoopTopologyTransport {
    async fn unstage_successor_before_prepare(
        &self,
        _request: &SessionTopologyTransitionRequest,
        _proof: &SessionTopologyPrePrepareUnstageProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError> {
        Ok(())
    }

    async fn retire_aborted_candidate(
        &self,
        _request: &SessionTopologyTransitionRequest,
        _proof: &SessionTopologyCandidateRetirementProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError> {
        Ok(())
    }

    async fn admit_successor_voting(
        &self,
        _request: &SessionTopologyTransitionRequest,
        _proof: &SessionTopologyJointCommitAdmissionProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError> {
        Ok(())
    }

    async fn finalize_successor(
        &self,
        _request: &SessionTopologyTransitionRequest,
        _proof: &SessionTopologyUniformCommitAdmissionProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError> {
        Ok(())
    }

    async fn abort_successor(
        &self,
        _request: &SessionTopologyTransitionRequest,
        _proof: &SessionTopologyAbortAdmissionProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError> {
        Ok(())
    }
}

fn replica_id(index: usize) -> ReplicaId {
    ReplicaId::new(format!("fixed-voter-{index}")).expect("test replica ID")
}

fn descriptor(
    index: usize,
    failure_domain: usize,
    tls_identity: usize,
    backing_identity: usize,
) -> QuorumReplicaDescriptor {
    QuorumReplicaDescriptor::new(
        replica_id(index),
        ReplicaEndpoint::new(format!("fixed-voter-{index}.test.invalid"), 7443)
            .expect("test endpoint"),
        ReplicaTlsIdentity::new(format!("spiffe://test/fixed-voter/{tls_identity}"))
            .expect("test TLS identity"),
        ReplicaFailureDomain::new(format!("test-failure-domain-{failure_domain}"))
            .expect("test failure domain"),
        ReplicaBackingIdentity::new(format!("test-backing-{backing_identity}"))
            .expect("test backing identity"),
    )
}

fn consensus_identity(members: &[QuorumReplicaDescriptor]) -> ConsensusIdentity {
    let cluster_id =
        ConsensusClusterId::new("fixed-quorum-authority-tests").expect("test cluster ID");
    let epoch = ConsensusConfigurationEpoch::new(1).expect("test configuration epoch");
    let fingerprints = members
        .iter()
        .map(QuorumReplicaDescriptor::configuration_fingerprint)
        .collect::<Vec<_>>();
    let configuration_id = derive_configuration_id(cluster_id, epoch, &fingerprints);
    ConsensusIdentity::new(cluster_id, configuration_id, epoch)
}

fn fixed_consensus_identity(
    members: &[QuorumReplicaDescriptor],
    placement_policy: PlacementResiliencePolicy,
) -> ConsensusIdentity {
    let cluster_id =
        ConsensusClusterId::new("fixed-quorum-authority-tests").expect("test cluster ID");
    let epoch = ConsensusConfigurationEpoch::new(1).expect("test configuration epoch");
    let fingerprints = members
        .iter()
        .map(QuorumReplicaDescriptor::configuration_fingerprint)
        .collect::<Vec<_>>();
    derive_fixed_durable_quorum_consensus_identity(
        cluster_id,
        epoch,
        &fingerprints,
        placement_policy,
    )
}

fn fixed_topology(
    members: Vec<QuorumReplicaDescriptor>,
) -> Result<ValidatedQuorumTopology, QuorumTopologyError> {
    fixed_topology_with_policy(members, PlacementResiliencePolicy::default())
}

fn fixed_topology_with_policy(
    members: Vec<QuorumReplicaDescriptor>,
    placement_policy: PlacementResiliencePolicy,
) -> Result<ValidatedQuorumTopology, QuorumTopologyError> {
    fixed_topology_for_local(0, members, placement_policy)
}

fn fixed_topology_for_local(
    local_index: usize,
    members: Vec<QuorumReplicaDescriptor>,
    placement_policy: PlacementResiliencePolicy,
) -> Result<ValidatedQuorumTopology, QuorumTopologyError> {
    ValidatedQuorumTopology::try_from_fixed_durable_quorum_with_placement_policy(
        QuorumTopologyConfig::new_consensus(
            replica_id(local_index),
            members.clone(),
            fixed_consensus_identity(&members, placement_policy),
        ),
        placement_policy,
    )
}

#[tokio::test]
async fn fixed_placement_policy_changes_authenticated_scope_before_durable_open() {
    for voter_count in [3, 5] {
        let members = fixed_members(voter_count);
        let strict = fixed_topology_for_local(
            0,
            members.clone(),
            PlacementResiliencePolicy::RequireIndependentFailureDomains,
        )
        .expect("strict fixed topology");
        let reduced = fixed_topology_for_local(
            0,
            members,
            PlacementResiliencePolicy::AllowReducedResilience,
        )
        .expect("reduced fixed topology");

        assert_ne!(
            strict.consensus_identity(),
            reduced.consensus_identity(),
            "fixed {voter_count}-voter policies must not share an authenticated scope"
        );
        let dynamic_members = fixed_members(voter_count);
        let dynamic = ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
            replica_id(0),
            dynamic_members.clone(),
            consensus_identity(&dynamic_members),
        ))
        .expect("dynamic topology");
        assert_ne!(
            strict.consensus_identity(),
            dynamic.consensus_identity(),
            "fixed {voter_count}-voter authority must not share the dynamic profile scope"
        );

        let directory = tempfile::tempdir().expect("fixed policy test directory");
        let database_path = directory.path().join("voter.sqlite");
        let result = ConsensusSessionStore::open_fixed_durable_quorum(
            strict.clone(),
            SqliteSessionBackend::open(&database_path).expect("file-backed voter store"),
            directory.path().join("snapshots"),
            scoped_peers(&reduced),
        )
        .await;
        assert!(matches!(
            result,
            Err(ConsensusSessionStoreOpenError::PeerSetMismatch)
        ));

        let connection = rusqlite::Connection::open(database_path).expect("open voter database");
        let durable_raft_rows: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'consensus_identity'",
                [],
                |row| row.get(0),
            )
            .expect("query durable raft schema");
        assert_eq!(
            durable_raft_rows, 0,
            "mixed policies must fail before durable Raft initialization"
        );

        let dynamic_database_path = directory.path().join("dynamic-voter.sqlite");
        let dynamic_result = ConsensusSessionStore::open_fixed_durable_quorum(
            strict,
            SqliteSessionBackend::open(&dynamic_database_path).expect("file-backed voter store"),
            directory.path().join("dynamic-snapshots"),
            scoped_peers(&dynamic),
        )
        .await;
        assert!(matches!(
            dynamic_result,
            Err(ConsensusSessionStoreOpenError::PeerSetMismatch)
        ));
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn strict_snapshot_admission_fails_before_raft_and_portable_is_explicit() {
    use opc_session_store::SnapshotIntegrityPolicy;
    let directory = tempfile::Builder::new()
        .prefix("snapshot-admission-")
        .tempdir_in("/dev/shm")
        .expect("filesystem without fs-verity");
    let database = directory.path().join("voter.sqlite");
    let snapshots = directory.path().join("snapshots");
    let topology = fixed_topology_for_local(
        0,
        fixed_members(3),
        PlacementResiliencePolicy::RequireIndependentFailureDomains,
    )
    .expect("fixed topology");
    for legacy in [true, false] {
        let backend = SqliteSessionBackend::open(&database).expect("backend");
        let result = if legacy {
            ConsensusSessionStore::open_fixed_durable_quorum(
                topology.clone(),
                backend,
                &snapshots,
                scoped_peers(&topology),
            )
            .await
        } else {
            ConsensusSessionStore::open_fixed_durable_quorum_with_snapshot_integrity(
                topology.clone(),
                backend,
                &snapshots,
                scoped_peers(&topology),
                SnapshotIntegrityPolicy::FsVerity,
            )
            .await
        };
        assert_eq!(
            ConsensusSessionStoreOpenError::SnapshotIntegrityUnavailable,
            result.expect_err("strict policy must fail during admission")
        );
        let conn = rusqlite::Connection::open(&database).expect("inspect failed admission");
        let initialized: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'consensus_identity')",
                [],
                |row| row.get(0),
            )
            .expect("inspect consensus initialization");
        assert!(
            !initialized,
            "strict capability failure precedes durable Raft initialization"
        );
        assert_eq!(
            0,
            std::fs::read_dir(&snapshots)
                .expect("probe cleanup")
                .count()
        );
    }
    let store = ConsensusSessionStore::open_fixed_durable_quorum_with_snapshot_integrity(
        topology.clone(),
        SqliteSessionBackend::open(&database).expect("portable backend"),
        &snapshots,
        scoped_peers(&topology),
        SnapshotIntegrityPolicy::PortableVerified,
    )
    .await
    .expect("explicit portable admission on the same filesystem");
    assert_eq!(
        Some(SnapshotIntegrityPolicy::PortableVerified),
        store.snapshot_integrity_policy()
    );
    store.shutdown().await.expect("shutdown portable admission");
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn fixed_durable_quorum_rejects_unsupported_platform_before_durable_initialization() {
    let members = fixed_members(3);
    let topology = fixed_topology(members).expect("fixed topology admission");
    let directory = tempfile::tempdir().expect("fixed platform test directory");
    let snapshot_dir = directory.path().join("must-not-exist");
    // A file-backed backend performs Linux-only recovery-latch admission
    // before the public fixed-quorum platform guard. Use the ephemeral
    // backend so this test reaches that public guard and still proves that
    // unsupported construction creates no snapshot or durable Raft state.
    let backend = SqliteSessionBackend::in_memory().expect("ephemeral backend");

    let result = ConsensusSessionStore::open_fixed_durable_quorum(
        topology.clone(),
        backend,
        snapshot_dir.clone(),
        scoped_peers(&topology),
    )
    .await;
    assert!(matches!(
        result,
        Err(ConsensusSessionStoreOpenError::FixedQuorumUnsupportedPlatform)
    ));
    assert!(
        !snapshot_dir.exists(),
        "unsupported fixed quorum must fail before snapshot initialization"
    );
}

fn fixed_members(count: usize) -> Vec<QuorumReplicaDescriptor> {
    (0..count)
        .map(|index| descriptor(index, index, index, index))
        .collect()
}

fn scoped_peers(
    topology: &ValidatedQuorumTopology,
) -> BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>> {
    let local_node_id = topology
        .local_consensus_node_id()
        .expect("fixed local node ID");
    let identity = topology.consensus_identity().expect("consensus identity");
    topology
        .members()
        .iter()
        .filter_map(|member| topology.consensus_node_id(member.replica_id()))
        .filter(|node_id| *node_id != local_node_id)
        .map(|node_id| {
            let peer: Arc<dyn SessionConsensusPeer> =
                Arc::new(ScopedLoopbackPeer::new(node_id, identity));
            (node_id, peer)
        })
        .collect()
}

async fn open_fixed_cluster(
    member_count: usize,
    placement_policy: PlacementResiliencePolicy,
) -> (tempfile::TempDir, Vec<PathBuf>, Vec<ConsensusSessionStore>) {
    let (directory, database_paths, stores, _) =
        open_fixed_cluster_with_paths(member_count, placement_policy).await;
    (directory, database_paths, stores)
}

async fn open_fixed_cluster_with_members(
    members: Vec<QuorumReplicaDescriptor>,
    placement_policy: PlacementResiliencePolicy,
) -> (tempfile::TempDir, Vec<ConsensusSessionStore>) {
    let member_count = members.len();
    let directory = tempfile::tempdir().expect("fixed cluster directory");
    let identity = fixed_consensus_identity(&members, placement_policy);
    let topologies = (0..member_count)
        .map(|index| {
            fixed_topology_for_local(index, members.clone(), placement_policy)
                .map(|topology| (index, topology))
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("fixed cluster topologies");
    let node_ids = topologies
        .iter()
        .map(|(_, topology)| {
            topology
                .local_consensus_node_id()
                .expect("fixed local node ID")
        })
        .collect::<Vec<_>>();
    let mut paths = BTreeMap::new();
    for source in 0..member_count {
        for (target, node_id) in node_ids.iter().copied().enumerate() {
            if source != target {
                paths.insert(
                    (source, target),
                    Arc::new(ScopedLoopbackPeer::new(node_id, identity)),
                );
            }
        }
    }
    let mut stores = Vec::new();
    for (source, topology) in topologies {
        let peers = (0..member_count)
            .filter(|target| *target != source)
            .map(|target| {
                let peer: Arc<dyn SessionConsensusPeer> = paths
                    .get(&(source, target))
                    .expect("fixed scoped path")
                    .clone();
                (node_ids[target], peer)
            })
            .collect::<BTreeMap<_, _>>();
        stores.push(
            ConsensusSessionStore::open_fixed_durable_quorum_with_snapshot_integrity(
                topology,
                SqliteSessionBackend::open(directory.path().join(format!("voter-{source}.sqlite")))
                    .expect("file-backed voter store"),
                directory.path().join(format!("snapshots-{source}")),
                peers,
                SnapshotIntegrityPolicy::PortableVerified,
            )
            .await
            .expect("open fixed cluster voter"),
        );
    }
    for ((_, target), peer) in &paths {
        peer.install(stores[*target].rpc_handler()).await;
    }
    for result in
        futures_util::future::join_all(stores.iter().map(ConsensusSessionStore::initialize_cluster))
            .await
    {
        result.expect("initialize fixed cluster membership");
    }
    (directory, stores)
}

async fn open_fixed_cluster_with_paths(
    member_count: usize,
    placement_policy: PlacementResiliencePolicy,
) -> (
    tempfile::TempDir,
    Vec<PathBuf>,
    Vec<ConsensusSessionStore>,
    BTreeMap<(usize, usize), Arc<ScopedLoopbackPeer>>,
) {
    let directory = tempfile::tempdir().expect("fixed cluster directory");
    let (database_paths, stores, paths) =
        open_fixed_cluster_in_with_paths(directory.path(), member_count, placement_policy).await;
    (directory, database_paths, stores, paths)
}

async fn open_fixed_cluster_in_with_paths(
    directory: &std::path::Path,
    member_count: usize,
    placement_policy: PlacementResiliencePolicy,
) -> (
    Vec<PathBuf>,
    Vec<ConsensusSessionStore>,
    BTreeMap<(usize, usize), Arc<ScopedLoopbackPeer>>,
) {
    // Authority tests run on ordinary storage with an explicit policy;
    // dedicated sealed-snapshot tests use the strict wrapper below.
    open_fixed_cluster_in_separate_paths_with_integrity(
        directory,
        directory,
        member_count,
        placement_policy,
        SnapshotIntegrityPolicy::PortableVerified,
    )
    .await
}

async fn open_fixed_cluster_in_separate_paths(
    database_directory: &std::path::Path,
    snapshot_directory: &std::path::Path,
    member_count: usize,
    placement_policy: PlacementResiliencePolicy,
) -> (
    Vec<PathBuf>,
    Vec<ConsensusSessionStore>,
    BTreeMap<(usize, usize), Arc<ScopedLoopbackPeer>>,
) {
    open_fixed_cluster_in_separate_paths_with_integrity(
        database_directory,
        snapshot_directory,
        member_count,
        placement_policy,
        SnapshotIntegrityPolicy::FsVerity,
    )
    .await
}

async fn open_fixed_cluster_in_separate_paths_with_integrity(
    database_directory: &std::path::Path,
    snapshot_directory: &std::path::Path,
    member_count: usize,
    placement_policy: PlacementResiliencePolicy,
    snapshot_integrity: SnapshotIntegrityPolicy,
) -> (
    Vec<PathBuf>,
    Vec<ConsensusSessionStore>,
    BTreeMap<(usize, usize), Arc<ScopedLoopbackPeer>>,
) {
    let members = fixed_members(member_count);
    let identity = fixed_consensus_identity(&members, placement_policy);
    let topologies = (0..member_count)
        .map(|index| {
            fixed_topology_for_local(index, members.clone(), placement_policy)
                .map(|topology| (index, topology))
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("fixed cluster topologies");
    let database_paths = (0..member_count)
        .map(|index| database_directory.join(format!("fixed-voter-{index}.sqlite")))
        .collect::<Vec<_>>();
    let node_ids = topologies
        .iter()
        .map(|(_, topology)| {
            topology
                .local_consensus_node_id()
                .expect("fixed local node ID")
        })
        .collect::<Vec<_>>();
    let mut paths = BTreeMap::new();
    for source in 0..member_count {
        for (target, node_id) in node_ids.iter().copied().enumerate() {
            if source != target {
                paths.insert(
                    (source, target),
                    Arc::new(ScopedLoopbackPeer::new(node_id, identity)),
                );
            }
        }
    }
    let mut stores = Vec::new();
    for (source, topology) in topologies {
        let peers = (0..member_count)
            .filter(|target| *target != source)
            .map(|target| {
                let peer: Arc<dyn SessionConsensusPeer> = paths
                    .get(&(source, target))
                    .expect("fixed scoped path")
                    .clone();
                (node_ids[target], peer)
            })
            .collect::<BTreeMap<_, _>>();
        let store = ConsensusSessionStore::open_fixed_durable_quorum_with_snapshot_integrity(
            topology,
            SqliteSessionBackend::open(&database_paths[source]).expect("file-backed voter store"),
            snapshot_directory.join(format!("snapshots-{source}")),
            peers,
            snapshot_integrity,
        )
        .await
        .expect("open fixed cluster voter");
        stores.push(store);
    }
    for ((_, target), peer) in &paths {
        peer.install(stores[*target].rpc_handler()).await;
    }
    for result in
        futures_util::future::join_all(stores.iter().map(ConsensusSessionStore::initialize_cluster))
            .await
    {
        result.expect("initialize fixed cluster membership");
    }
    (database_paths, stores, paths)
}

#[cfg(all(target_os = "linux", feature = "test-control"))]
async fn reopen_single_fixed_voter_for_test(
    database_directory: &std::path::Path,
    snapshot_directory: &std::path::Path,
    local_index: usize,
) -> Result<ConsensusSessionStore, ConsensusSessionStoreOpenError> {
    let members = fixed_members(3);
    let identity =
        fixed_consensus_identity(&members, PlacementResiliencePolicy::AllowReducedResilience);
    let topology = fixed_topology_for_local(
        local_index,
        members.clone(),
        PlacementResiliencePolicy::AllowReducedResilience,
    )
    .expect("fixed voter reopen topology");
    let local_node_id = topology
        .local_consensus_node_id()
        .expect("fixed voter reopen local node ID");
    let peers = members
        .iter()
        .filter_map(|member| topology.consensus_node_id(member.replica_id()))
        .filter(|node_id| *node_id != local_node_id)
        .map(|node_id| {
            let peer: Arc<dyn SessionConsensusPeer> =
                Arc::new(ScopedLoopbackPeer::new(node_id, identity));
            (node_id, peer)
        })
        .collect::<BTreeMap<_, _>>();
    ConsensusSessionStore::open_fixed_durable_quorum(
        topology,
        SqliteSessionBackend::open(
            database_directory.join(format!("fixed-voter-{local_index}.sqlite")),
        )
        .expect("file-backed fixed voter reopen backend"),
        snapshot_directory.join(format!("snapshots-{local_index}")),
        peers,
    )
    .await
}

async fn shutdown_fixed_cluster_for_reopen(
    stores: &[ConsensusSessionStore],
    paths: &BTreeMap<(usize, usize), Arc<ScopedLoopbackPeer>>,
) {
    for path in paths.values() {
        path.clear().await;
    }
    for result in
        futures_util::future::join_all(stores.iter().map(ConsensusSessionStore::shutdown)).await
    {
        result.expect("fully drain fixed consensus engine before durable reopen");
    }
}

fn successor_request(identity: ConsensusIdentity) -> SessionTopologyTransitionRequest {
    SessionTopologyTransitionRequest::try_new(
        SessionTopologyTransitionId::from_bytes([0x71; 16]),
        identity.cluster_id(),
        identity.configuration_epoch(),
        ConsensusConfigurationEpoch::new(2).expect("successor epoch"),
        fixed_members(3),
        Duration::from_secs(1),
    )
    .expect("valid successor request")
}

fn fixed_attested_topology(
    local_index: usize,
    members: &[QuorumReplicaDescriptor],
    identity: ConsensusIdentity,
    evidence: Vec<TopologyAttestationEvidence>,
    policy: &TopologyAttestationPolicy,
    admitted_at: TopologyAttestationTime,
) -> ValidatedQuorumTopology {
    ValidatedQuorumTopology::try_from_fixed_durable_quorum_with_authenticated_placement(
        QuorumTopologyConfig::new_consensus(replica_id(local_index), members.to_vec(), identity),
        PlacementResiliencePolicy::default(),
        evidence,
        policy,
        &DigestTopologyAttestor,
        admitted_at,
    )
    .expect("fixed authenticated placement topology")
}

fn authenticated_placement_evidence(
    members: &[QuorumReplicaDescriptor],
    identity: ConsensusIdentity,
    collector: &TopologyCollectorId,
    observed_at: TopologyAttestationTime,
    expires_at: TopologyAttestationTime,
) -> Vec<TopologyAttestationEvidence> {
    members
        .iter()
        .enumerate()
        .map(|(index, descriptor)| {
            let claims = TopologyAttestationClaims::new(
                descriptor.replica_id().clone(),
                descriptor.tls_identity().clone(),
                ObservedPhysicalNodeIdentity::new(format!("fixed-physical-node-{index}"))
                    .expect("physical node identity"),
                descriptor.failure_domain().clone(),
                descriptor.backing_identity().clone(),
                descriptor.configuration_fingerprint(),
                identity,
                collector.clone(),
                TopologyAttestationProvenance::AuthenticatedPlatform,
                observed_at,
                expires_at,
            );
            let proof = claims.canonical_digest().to_vec();
            TopologyAttestationEvidence::try_new(claims, proof).expect("bounded placement evidence")
        })
        .collect()
}

#[test]
fn fixed_quorum_authority_and_placement_resilience_are_separate_typed_results() {
    let authority = FixedQuorumTrafficAuthority::Granted;
    let strict = PlacementResiliencePolicy::default().evaluate_unverified();
    let reduced = PlacementResiliencePolicy::AllowReducedResilience.evaluate_unverified();

    assert!(authority.is_granted());
    assert_eq!(
        strict.disposition(),
        PlacementResilienceDisposition::IndependentPlacementWithheld,
    );
    assert_eq!(
        reduced.disposition(),
        PlacementResilienceDisposition::ReducedResilience,
    );
    assert!(!reduced.disposition().is_independent_placement_qualified());
}

#[test]
fn fixed_durable_quorum_admits_correlated_descriptors_without_claiming_independence() {
    let members = (0..3)
        .map(|index| descriptor(index, 0, index, index))
        .collect::<Vec<_>>();

    let strict = fixed_topology(members.clone());
    assert!(matches!(
        strict,
        Err(QuorumTopologyError::DuplicateFailureDomain)
    ));

    let fixed = fixed_topology_with_policy(
        members.clone(),
        PlacementResiliencePolicy::AllowReducedResilience,
    )
    .expect("fixed topology admission");
    assert_eq!(
        fixed.summary().mode(),
        QuorumTopologyMode::FixedDurableQuorum,
    );
    assert_eq!(fixed.summary().configured_members(), 3);
    assert_eq!(
        fixed.summary().fixed_durable_placement_policy(),
        Some(PlacementResiliencePolicy::AllowReducedResilience),
    );

    let descriptor_only = ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
        replica_id(0),
        members.clone(),
        consensus_identity(&members),
    ));
    assert!(matches!(
        descriptor_only,
        Err(QuorumTopologyError::DuplicateFailureDomain)
    ));
}

#[tokio::test]
async fn reduced_policy_forms_a_live_correlated_fixed_three_voter_quorum() {
    let members = (0..3)
        .map(|index| descriptor(index, 0, index, index))
        .collect::<Vec<_>>();
    assert!(matches!(
        fixed_topology_with_policy(
            members.clone(),
            PlacementResiliencePolicy::RequireIndependentFailureDomains,
        ),
        Err(QuorumTopologyError::DuplicateFailureDomain)
    ));

    let (_directory, stores) =
        open_fixed_cluster_with_members(members, PlacementResiliencePolicy::AllowReducedResilience)
            .await;
    let readiness = stores[0]
        .probe_fixed_durable_quorum_readiness_at(TopologyAttestationTime::from_unix_seconds(1))
        .await;
    assert_eq!(
        readiness.traffic_authority(),
        FixedQuorumTrafficAuthority::Granted,
    );
    assert_eq!(
        readiness.placement_resilience().disposition(),
        PlacementResilienceDisposition::ReducedResilience,
    );
}

#[test]
fn fixed_durable_quorum_requires_exact_three_or_five_voters() {
    for count in [1_usize, 4, 7] {
        let members = (0..count)
            .map(|index| descriptor(index, index, index, index))
            .collect::<Vec<_>>();
        assert!(matches!(
            fixed_topology(members),
            Err(QuorumTopologyError::FixedQuorumMemberCount { configured }) if configured == count
        ));
    }
}

#[test]
fn fixed_durable_quorum_keeps_authenticated_identity_and_backing_bindings_distinct() {
    let duplicate_tls = vec![
        descriptor(0, 0, 0, 0),
        descriptor(1, 1, 0, 1),
        descriptor(2, 2, 2, 2),
    ];
    assert!(matches!(
        fixed_topology(duplicate_tls),
        Err(QuorumTopologyError::DuplicateTlsIdentity)
    ));

    let duplicate_backing = vec![
        descriptor(0, 0, 0, 0),
        descriptor(1, 1, 1, 0),
        descriptor(2, 2, 2, 2),
    ];
    assert!(matches!(
        fixed_topology(duplicate_backing),
        Err(QuorumTopologyError::DuplicateBackingIdentity)
    ));
}

#[test]
fn fixed_quorum_rejections_redact_descriptor_values() {
    let canary = "fixed-quorum-redaction-canary";
    let members = vec![
        QuorumReplicaDescriptor::new(
            replica_id(0),
            ReplicaEndpoint::new(format!("{canary}.test.invalid"), 7443).expect("test endpoint"),
            ReplicaTlsIdentity::new(format!("spiffe://test/{canary}")).expect("test TLS identity"),
            ReplicaFailureDomain::new(canary).expect("test failure domain"),
            ReplicaBackingIdentity::new(canary).expect("test backing identity"),
        ),
        QuorumReplicaDescriptor::new(
            replica_id(1),
            ReplicaEndpoint::new("second.test.invalid", 7443).expect("test endpoint"),
            ReplicaTlsIdentity::new("spiffe://test/second").expect("test TLS identity"),
            ReplicaFailureDomain::new("test-failure-domain-second").expect("test failure domain"),
            ReplicaBackingIdentity::new(canary).expect("test backing identity"),
        ),
        descriptor(2, 2, 2, 2),
    ];
    let error = match fixed_topology(members) {
        Err(error) => error,
        Ok(_) => panic!("duplicate backing must be rejected"),
    };

    assert_eq!(error, QuorumTopologyError::DuplicateBackingIdentity);
    assert!(!format!("{error:?}").contains(canary));
    assert!(!error.to_string().contains(canary));
}

#[tokio::test]
async fn fixed_durable_quorum_rejects_unscoped_peer_before_engine_start() {
    let members = (0..3)
        .map(|index| descriptor(index, index, index, index))
        .collect::<Vec<_>>();
    let topology = fixed_topology(members).expect("fixed topology admission");
    let local_node_id = topology
        .local_consensus_node_id()
        .expect("fixed local node ID");
    let peers = topology
        .members()
        .iter()
        .filter_map(|member| topology.consensus_node_id(member.replica_id()))
        .filter(|node_id| *node_id != local_node_id)
        .map(|node_id| {
            (
                node_id,
                Arc::new(UnscopedPeer { node_id }) as Arc<dyn SessionConsensusPeer>,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let snapshots = tempfile::tempdir().expect("snapshot directory");
    let database = snapshots.path().join("fixed-voter.sqlite");

    let result = ConsensusSessionStore::open_fixed_durable_quorum(
        topology,
        SqliteSessionBackend::open(database).expect("file-backed voter store"),
        snapshots.path(),
        peers,
    )
    .await;

    assert!(matches!(
        result,
        Err(ConsensusSessionStoreOpenError::PeerSetMismatch)
    ));
}

#[tokio::test]
async fn fixed_durable_quorum_rejects_ephemeral_storage() {
    let members = (0..3)
        .map(|index| descriptor(index, index, index, index))
        .collect::<Vec<_>>();
    let topology = fixed_topology(members).expect("fixed topology admission");
    let local_node_id = topology
        .local_consensus_node_id()
        .expect("fixed local node ID");
    let identity = topology.consensus_identity().expect("consensus identity");
    let peers = topology
        .members()
        .iter()
        .filter_map(|member| topology.consensus_node_id(member.replica_id()))
        .filter(|node_id| *node_id != local_node_id)
        .map(|node_id| {
            let peer: Arc<dyn SessionConsensusPeer> =
                Arc::new(ScopedLoopbackPeer::new(node_id, identity));
            (node_id, peer)
        })
        .collect::<BTreeMap<_, _>>();
    let snapshots = tempfile::tempdir().expect("snapshot directory");

    let result = ConsensusSessionStore::open_fixed_durable_quorum(
        topology,
        SqliteSessionBackend::in_memory().expect("in-memory backend"),
        snapshots.path(),
        peers,
    )
    .await;

    assert!(matches!(
        result,
        Err(ConsensusSessionStoreOpenError::StorageUnavailable)
    ));
}

#[tokio::test]
async fn file_backed_fixed_five_voter_quorum_reaches_granted_authority() {
    let members = fixed_members(5);
    let identity =
        fixed_consensus_identity(&members, PlacementResiliencePolicy::AllowReducedResilience);
    let topologies = (0..5)
        .map(|index| {
            fixed_topology_for_local(
                index,
                members.clone(),
                PlacementResiliencePolicy::AllowReducedResilience,
            )
            .map(|topology| (index, topology))
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("fixed five-voter topologies");
    let directory = tempfile::tempdir().expect("fixed five-voter directory");
    let node_ids = topologies
        .iter()
        .map(|(_, topology)| {
            topology
                .local_consensus_node_id()
                .expect("fixed local node ID")
        })
        .collect::<Vec<_>>();
    let mut paths = BTreeMap::new();
    for source in 0..5 {
        for (target, node_id) in node_ids.iter().copied().enumerate() {
            if source != target {
                paths.insert(
                    (source, target),
                    Arc::new(ScopedLoopbackPeer::new(node_id, identity)),
                );
            }
        }
    }
    let mut stores = Vec::new();
    for (source, topology) in topologies {
        let peers = (0..5)
            .filter(|target| *target != source)
            .map(|target| {
                let peer: Arc<dyn SessionConsensusPeer> = paths
                    .get(&(source, target))
                    .expect("fixed scoped path")
                    .clone();
                (node_ids[target], peer)
            })
            .collect::<BTreeMap<_, _>>();
        let store = ConsensusSessionStore::open_fixed_durable_quorum_with_snapshot_integrity(
            topology,
            SqliteSessionBackend::open(
                directory
                    .path()
                    .join(format!("fixed-voter-{source}.sqlite")),
            )
            .expect("file-backed voter store"),
            directory.path().join(format!("snapshots-{source}")),
            peers,
            SnapshotIntegrityPolicy::PortableVerified,
        )
        .await
        .expect("open fixed five-voter store");
        stores.push(store);
    }
    for ((_, target), peer) in &paths {
        peer.install(stores[*target].rpc_handler()).await;
    }
    for result in
        futures_util::future::join_all(stores.iter().map(ConsensusSessionStore::initialize_cluster))
            .await
    {
        result.expect("initialize fixed five-voter membership");
    }

    let readiness = stores[0]
        .probe_fixed_durable_quorum_readiness_at(TopologyAttestationTime::from_unix_seconds(1))
        .await;
    assert_eq!(
        readiness.traffic_authority(),
        FixedQuorumTrafficAuthority::Granted,
    );
    assert!(readiness.traffic_authority().is_granted());
}

#[tokio::test]
async fn initialized_fixed_three_voter_cluster_reopens_with_durable_authority_and_rpc_readiness() {
    let (directory, _database_paths, stores, paths) =
        open_fixed_cluster_with_paths(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    shutdown_fixed_cluster_for_reopen(&stores, &paths).await;
    drop(stores);
    drop(paths);

    let (_database_paths, reopened, reopened_paths) = open_fixed_cluster_in_with_paths(
        directory.path(),
        3,
        PlacementResiliencePolicy::AllowReducedResilience,
    )
    .await;
    assert!(
        reopened.iter().all(|store| store.status().admitted),
        "reopened fixed voters must retain exact durable admission"
    );
    assert!(
        reopened[0]
            .probe_fixed_durable_quorum_readiness_at(TopologyAttestationTime::from_unix_seconds(1))
            .await
            .traffic_authority()
            .is_granted(),
        "reopened fixed quorum RPC path must recover durable traffic authority"
    );
    shutdown_fixed_cluster_for_reopen(&reopened, &reopened_paths).await;
}

#[tokio::test]
async fn fixed_quorum_reopen_migrates_each_released_cursor_only_recovery_schema() {
    let (directory, database_paths, stores, paths) =
        open_fixed_cluster_with_paths(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    shutdown_fixed_cluster_for_reopen(&stores, &paths).await;
    drop(stores);
    drop(paths);

    for (database, schema) in database_paths.iter().zip([
        ReleasedCursorOnlyOperatorRecoverySchema::Direct,
        ReleasedCursorOnlyOperatorRecoverySchema::AddOn,
        ReleasedCursorOnlyOperatorRecoverySchema::Migrated,
    ]) {
        replace_operator_recovery_with_released_cursor_only_schema(database, schema);
    }

    let (_database_paths, reopened, reopened_paths) = open_fixed_cluster_in_with_paths(
        directory.path(),
        3,
        PlacementResiliencePolicy::AllowReducedResilience,
    )
    .await;
    assert!(
        reopened.iter().all(|store| store.status().admitted),
        "reopened fixed voters must retain exact durable admission"
    );
    assert!(
        reopened[0]
            .probe_fixed_durable_quorum_readiness_at(TopologyAttestationTime::from_unix_seconds(1))
            .await
            .traffic_authority()
            .is_granted(),
        "reopened fixed quorum must recover durable traffic authority"
    );
    shutdown_fixed_cluster_for_reopen(&reopened, &reopened_paths).await;

    for database in &database_paths {
        let connection = rusqlite::Connection::open(database).expect("open migrated fixed voter");
        let has_activation_marker: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('consensus_operator_recovery') \
                 WHERE name = 'recovery_v2_activated')",
                [],
                |row| row.get(0),
            )
            .expect("read migrated recovery activation marker");
        assert!(
            has_activation_marker,
            "fixed-voter reopen must migrate schema"
        );
    }
}

#[cfg(all(target_os = "linux", feature = "test-control"))]
#[tokio::test]
async fn portable_fixed_three_voter_quorum_snapshots_and_reopens_with_authority() {
    let policy = PlacementResiliencePolicy::AllowReducedResilience;
    let (directory, database_paths, stores, paths) = open_fixed_cluster_with_paths(3, policy).await;
    for store in &stores {
        assert_eq!(
            Some(SnapshotIntegrityPolicy::PortableVerified),
            store.snapshot_integrity_policy()
        );
        trigger_consensus_snapshot_for_test(store)
            .await
            .expect("capture portable fixed snapshot");
    }
    // The engine trigger acknowledges scheduling, not durable publication.
    // Require every voter to finish publishing before inspecting its image.
    tokio::time::timeout(Duration::from_secs(5), async {
        for database in &database_paths {
            loop {
                let connection = rusqlite::Connection::open(database)
                    .expect("inspect portable snapshot publication");
                let published: bool = connection
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM consensus_snapshot WHERE singleton = 1)",
                        [],
                        |row| row.get(0),
                    )
                    .expect("read portable publication state");
                drop(connection);
                if published {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    })
    .await
    .expect("all portable fixed snapshots must publish within the test deadline");
    let selected = database_paths
        .iter()
        .enumerate()
        .map(|(index, database)| {
            let path = fixed_current_snapshot_path(
                database,
                &directory.path().join(format!("snapshots-{index}")),
            );
            let bytes = std::fs::read(&path).expect("published portable image");
            (path, bytes)
        })
        .collect::<Vec<_>>();
    shutdown_fixed_cluster_for_reopen(&stores, &paths).await;
    drop(stores);
    drop(paths);
    let (_, reopened, paths) = open_fixed_cluster_in_with_paths(directory.path(), 3, policy).await;
    for store in &reopened {
        assert_eq!(
            Some(SnapshotIntegrityPolicy::PortableVerified),
            store.snapshot_integrity_policy()
        );
        assert_eq!(
            FixedQuorumTrafficAuthority::Granted,
            store
                .probe_fixed_durable_quorum_readiness_at(
                    TopologyAttestationTime::from_unix_seconds(1)
                )
                .await
                .traffic_authority(),
            "verified snapshot reopen preserves fixed-quorum traffic authority"
        );
    }
    for (path, bytes) in selected {
        assert_eq!(bytes, std::fs::read(path).expect("reopened selected image"));
    }
    shutdown_fixed_cluster_for_reopen(&reopened, &paths).await;
}

/// Exercise the public fixed-quorum open path against the exact predecessor
/// shape that needs compatibility.  The first old artifact is a byte-identical
/// selected `OPCSNP01` envelope without fs-verity; the remaining two are
/// deliberately corrupted regular unsealed files. The current database
/// carries one of the three released cursor-only recovery layouts.
/// Compatibility may rebuild a successor from durable DB/log state, never
/// from any old payload.
#[cfg(all(target_os = "linux", feature = "test-control"))]
#[tokio::test]
async fn fixed_quorum_public_reopen_reseeds_each_released_cursor_only_unsealed_selected_snapshot() {
    // Some developer and container filesystems do not implement the ioctl.
    // They cannot create a fixed sealed predecessor, so leave the real
    // descriptor-level regression to fs-verity-enabled Linux CI.
    if !fixed_verity_available_for_test() {
        return;
    }

    let database_directory = tempfile::tempdir().expect("fixed quorum database directory");
    let snapshot_root = fs_verity_snapshot_tempdir("fixed-quorum-reseed-snapshots-");
    let (database_paths, stores, paths) = open_fixed_cluster_in_separate_paths(
        database_directory.path(),
        snapshot_root.path(),
        3,
        PlacementResiliencePolicy::AllowReducedResilience,
    )
    .await;
    for store in &stores {
        trigger_consensus_snapshot_for_test(store)
            .await
            .expect("capture sealed fixed selected snapshot");
    }
    shutdown_fixed_cluster_for_reopen(&stores, &paths).await;
    drop(stores);
    drop(paths);

    let old_selected = database_paths
        .iter()
        .enumerate()
        .map(|(index, database)| {
            let snapshot_directory = snapshot_root.path().join(format!("snapshots-{index}"));
            let path = fixed_current_snapshot_path(database, &snapshot_directory);
            let bytes = std::fs::read(&path).expect("read sealed selected fixed snapshot");
            assert!(
                bytes.len() >= 48,
                "selected fixed snapshot has a complete OPCSNP01 footer"
            );
            assert_eq!(
                &bytes[bytes.len() - 48..bytes.len() - 40],
                b"OPCSNP01",
                "old selected envelope format is OPCSNP01"
            );
            std::fs::remove_file(&path).expect("remove sealed selected fixed snapshot");
            let old_payload = match index {
                // Keep one source byte-identical to prove the released
                // physical shape itself is admitted.
                0 => bytes,
                // The other two deliberately retain only untrusted regular
                // inode data. The reseed path must not read, hash, parse, or
                // use them as authority before rebuilding from DB/log state.
                1 => b"truncated old selected snapshot".to_vec(),
                2 => b"corrupt old selected snapshot".to_vec(),
                _ => unreachable!("three-voter fixture"),
            };
            std::fs::write(&path, old_payload).expect("write unsealed old snapshot fixture");
            assert_unsealed_snapshot(&path);
            path
        })
        .collect::<Vec<_>>();

    for (database, schema) in database_paths.iter().zip([
        ReleasedCursorOnlyOperatorRecoverySchema::Direct,
        ReleasedCursorOnlyOperatorRecoverySchema::AddOn,
        ReleasedCursorOnlyOperatorRecoverySchema::Migrated,
    ]) {
        replace_operator_recovery_with_released_cursor_only_schema(database, schema);
    }

    let (_database_paths, reopened, reopened_paths) = open_fixed_cluster_in_separate_paths(
        database_directory.path(),
        snapshot_root.path(),
        3,
        PlacementResiliencePolicy::AllowReducedResilience,
    )
    .await;
    assert!(
        reopened.iter().all(|store| store.status().admitted),
        "reseeded fixed voters must retain exact durable admission"
    );
    assert!(
        reopened[0]
            .probe_fixed_durable_quorum_readiness_at(TopologyAttestationTime::from_unix_seconds(1))
            .await
            .traffic_authority()
            .is_granted(),
        "reseeded quorum must retain live fixed traffic authority"
    );
    shutdown_fixed_cluster_for_reopen(&reopened, &reopened_paths).await;
    drop(reopened);
    drop(reopened_paths);

    for (index, (database, old_path)) in database_paths.iter().zip(old_selected).enumerate() {
        let snapshot_directory = snapshot_root.path().join(format!("snapshots-{index}"));
        let successor = fixed_current_snapshot_path(database, &snapshot_directory);
        assert_ne!(
            successor, old_path,
            "reseed must publish a distinct selected successor"
        );
        assert_sealed_snapshot(&successor);
        assert!(
            !old_path.exists(),
            "post-successor preflight must reclaim the old unsealed selected artifact"
        );
        let connection = rusqlite::Connection::open(database).expect("open reseeded fixed voter");
        let journal_present: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master \
                 WHERE type = 'table' AND name = 'consensus_legacy_fixed_snapshot_reseed')",
                [],
                |row| row.get(0),
            )
            .expect("read reseed journal presence");
        assert!(
            !journal_present,
            "sealed successor metadata transaction must clear the one-time journal"
        );
    }

    // A second public reopen proves that neither the journal nor the old
    // namespace artifact remains necessary after the atomic metadata switch.
    let (_database_paths, reopened, reopened_paths) = open_fixed_cluster_in_separate_paths(
        database_directory.path(),
        snapshot_root.path(),
        3,
        PlacementResiliencePolicy::AllowReducedResilience,
    )
    .await;
    assert!(reopened.iter().all(|store| store.status().admitted));
    shutdown_fixed_cluster_for_reopen(&reopened, &reopened_paths).await;
}

/// A byte-identical unsealed replacement is not an old-pin upgrade candidate
/// unless the pre-migration database proved one of the exact legacy DDLs and
/// created the journal in the same transaction. This reaches the public open
/// path and its retained directory lease rather than the unit-only validator.
#[cfg(all(target_os = "linux", feature = "test-control"))]
#[tokio::test]
async fn fixed_quorum_public_reopen_rejects_unsealed_current_schema_selected_snapshot() {
    if !fixed_verity_available_for_test() {
        return;
    }

    let database_directory = tempfile::tempdir().expect("fixed quorum database directory");
    let snapshot_root = fs_verity_snapshot_tempdir("fixed-quorum-unsealed-snapshots-");
    let (database_paths, stores, paths) = open_fixed_cluster_in_separate_paths(
        database_directory.path(),
        snapshot_root.path(),
        3,
        PlacementResiliencePolicy::AllowReducedResilience,
    )
    .await;
    trigger_consensus_snapshot_for_test(&stores[0])
        .await
        .expect("capture sealed fixed selected snapshot");
    shutdown_fixed_cluster_for_reopen(&stores, &paths).await;
    drop(stores);
    drop(paths);

    let snapshot_directory = snapshot_root.path().join("snapshots-0");
    let selected = fixed_current_snapshot_path(&database_paths[0], &snapshot_directory);
    let bytes = std::fs::read(&selected).expect("read sealed selected snapshot");
    std::fs::remove_file(&selected).expect("remove sealed selected snapshot");
    std::fs::write(&selected, bytes).expect("replace with byte-identical unsealed snapshot");
    assert_unsealed_snapshot(&selected);

    let result =
        reopen_single_fixed_voter_for_test(database_directory.path(), snapshot_root.path(), 0)
            .await;
    assert!(
        matches!(
            result,
            Err(ConsensusSessionStoreOpenError::RecoveryRequired)
        ),
        "current-schema unsealed selected artifact must fail closed before fixed quorum opens"
    );
    let connection = rusqlite::Connection::open(&database_paths[0])
        .expect("open rejected current-schema fixed voter");
    let journal_present: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master \
             WHERE type = 'table' AND name = 'consensus_legacy_fixed_snapshot_reseed')",
            [],
            |row| row.get(0),
        )
        .expect("read current-schema reseed journal presence");
    assert!(
        !journal_present,
        "current schema must not mint a compatibility journal for an unsealed replacement"
    );
}

#[tokio::test]
async fn fixed_durable_quorum_reopen_rejects_placement_policy_mismatch() {
    for (initial, reopened) in [
        (
            PlacementResiliencePolicy::RequireIndependentFailureDomains,
            PlacementResiliencePolicy::AllowReducedResilience,
        ),
        (
            PlacementResiliencePolicy::AllowReducedResilience,
            PlacementResiliencePolicy::RequireIndependentFailureDomains,
        ),
    ] {
        let (directory, database_paths, stores, paths) =
            open_fixed_cluster_with_paths(3, initial).await;
        shutdown_fixed_cluster_for_reopen(&stores, &paths).await;
        drop(stores);
        drop(paths);
        let members = fixed_members(3);
        let topology = fixed_topology_for_local(0, members, reopened).expect("reopen topology");
        let error = ConsensusSessionStore::open_fixed_durable_quorum_with_snapshot_integrity(
            topology.clone(),
            SqliteSessionBackend::open(&database_paths[0]).expect("reopen backend"),
            directory.path().join("snapshots-0"),
            scoped_peers(&topology),
            SnapshotIntegrityPolicy::PortableVerified,
        )
        .await
        .expect_err("fixed placement policy must be durably bound");
        assert_eq!(
            ConsensusSessionStoreOpenError::DurableIdentityMismatch,
            error
        );
    }
}

#[tokio::test]
async fn fixed_five_voter_store_without_a_majority_reports_no_quorum() {
    let topology = fixed_topology(fixed_members(5)).expect("fixed five-voter topology");
    let peers = scoped_peers(&topology);
    let directory = tempfile::tempdir().expect("fixed five-voter directory");
    let store = ConsensusSessionStore::open_fixed_durable_quorum_with_snapshot_integrity(
        topology,
        SqliteSessionBackend::open(directory.path().join("fixed-voter.sqlite"))
            .expect("file-backed voter store"),
        directory.path().join("snapshots"),
        peers,
        SnapshotIntegrityPolicy::PortableVerified,
    )
    .await
    .expect("open fixed five-voter store");

    let readiness = tokio::time::timeout(
        Duration::from_secs(1),
        store
            .probe_fixed_durable_quorum_readiness_at(TopologyAttestationTime::from_unix_seconds(1)),
    )
    .await
    .expect("no-majority readiness must remain bounded");
    assert_eq!(
        readiness.traffic_authority(),
        FixedQuorumTrafficAuthority::NoQuorum,
    );
}

#[tokio::test]
async fn store_issued_consumer_manifest_retains_authoritative_node_to_tls_pairs() {
    let placement_policy = PlacementResiliencePolicy::AllowReducedResilience;
    let members = fixed_members(3);
    let topology = fixed_topology_for_local(0, members, placement_policy)
        .expect("fixed topology with canonical node IDs");
    let expected_scope = topology
        .consensus_identity()
        .expect("fixed consensus identity");
    let expected_pairs = topology
        .members()
        .iter()
        .map(|descriptor| {
            (
                topology
                    .consensus_node_id(descriptor.replica_id())
                    .expect("canonical topology node ID")
                    .get(),
                descriptor.tls_identity().as_str().to_owned(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let (_directory, _database_paths, stores) = open_fixed_cluster(3, placement_policy).await;

    let manifest = stores[0]
        .consumer_authorization_manifest([fixed_consumer_grant()])
        .await
        .expect("admitted fixed store issues its consumer roster");
    let actual_pairs = manifest
        .consensus_members()
        .map(|member| (member.node_id().get(), member.tls_identity().to_owned()))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(manifest.scope().consensus_identity(), expected_scope);
    assert_eq!(actual_pairs, expected_pairs);
}

#[tokio::test]
async fn persisted_fixed_binding_drift_revokes_consumer_and_traffic_authority() {
    let (_directory, database_paths, stores) =
        open_fixed_cluster(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    stores[0]
        .consumer_authorization_manifest([fixed_consumer_grant()])
        .await
        .expect("exact fixed store grants consumer authorization");

    let connection =
        rusqlite::Connection::open(&database_paths[0]).expect("open fixed voter database");
    let encoded: Vec<u8> = connection
        .query_row(
            "SELECT current_bindings_json FROM consensus_membership_scope WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("read fixed bindings");
    let mut bindings: serde_json::Value =
        serde_json::from_slice(&encoded).expect("decode fixed bindings");
    let first_descriptor_octet = bindings
        .as_array_mut()
        .and_then(|entries| entries.first_mut())
        .and_then(serde_json::Value::as_array_mut)
        .and_then(|entry| entry.get_mut(1))
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|binding| binding.get_mut("descriptor"))
        .and_then(serde_json::Value::as_array_mut)
        .and_then(|digest| digest.first_mut())
        .expect("descriptor binding octet");
    let changed = first_descriptor_octet
        .as_u64()
        .expect("numeric descriptor octet")
        .wrapping_add(1)
        % 256;
    *first_descriptor_octet = serde_json::Value::from(changed);
    connection
        .execute(
            "UPDATE consensus_membership_scope SET current_bindings_json = ?1 WHERE singleton = 1",
            [serde_json::to_vec(&bindings).expect("encode changed fixed bindings")],
        )
        .expect("persist fixed binding drift");
    drop(connection);

    assert!(stores[0]
        .consumer_authorization_manifest([fixed_consumer_grant()])
        .await
        .is_err());
    let readiness = stores[0]
        .probe_fixed_durable_quorum_readiness_at(TopologyAttestationTime::from_unix_seconds(1))
        .await;
    assert_eq!(
        readiness.traffic_authority(),
        FixedQuorumTrafficAuthority::StructuralRecoveryRequired,
    );
}

#[tokio::test]
async fn running_fixed_scope_drift_revokes_linearizable_readiness_authority() {
    let (_directory, database_paths, stores) =
        open_fixed_cluster(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    for database_path in database_paths {
        let connection =
            rusqlite::Connection::open(database_path).expect("open fixed voter database");
        connection
            .execute(
                "UPDATE consensus_membership_scope SET application_authority_epoch = application_authority_epoch + 1 WHERE singleton = 1",
                [],
            )
            .expect("persist fixed structural scope drift");
    }

    let readiness = stores[0].probe_durable_readiness().await;
    assert!(
        !readiness.is_ready(),
        "a linearizable read barrier must not report authority after durable fixed-scope drift"
    );
}

#[tokio::test]
async fn running_fixed_profile_drift_revokes_traffic_authority() {
    let (_directory, database_paths, stores) =
        open_fixed_cluster(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    for database_path in database_paths {
        let connection =
            rusqlite::Connection::open(database_path).expect("open fixed voter database");
        connection
            .execute(
                "UPDATE consensus_identity SET authority_profile = 1 WHERE singleton = 1",
                [],
            )
            .expect("persist fixed authority profile drift");
    }

    assert!(
        stores[0]
            .consumer_authorization_manifest([fixed_consumer_grant()])
            .await
            .is_err(),
        "consumer authority must fail closed after fixed-profile drift"
    );
    assert!(
        SessionBackend::batch(&stores[0], Vec::new()).await.is_err(),
        "mutation authority must fail closed after fixed-profile drift"
    );
    assert!(
        !stores[0].status().admitted,
        "status must not retain admission after fixed-profile drift"
    );
    let readiness = stores[0]
        .probe_fixed_durable_quorum_readiness_at(TopologyAttestationTime::from_unix_seconds(1))
        .await;
    assert_eq!(
        readiness.traffic_authority(),
        FixedQuorumTrafficAuthority::StructuralRecoveryRequired,
    );
}

#[tokio::test]
async fn running_fixed_placement_policy_drift_revokes_live_authority() {
    for (configured_policy, drifted_policy) in [
        (
            PlacementResiliencePolicy::RequireIndependentFailureDomains,
            PlacementResiliencePolicy::AllowReducedResilience,
        ),
        (
            PlacementResiliencePolicy::AllowReducedResilience,
            PlacementResiliencePolicy::RequireIndependentFailureDomains,
        ),
    ] {
        let (_directory, database_paths, stores) = open_fixed_cluster(3, configured_policy).await;
        stores[0]
            .consumer_authorization_manifest([fixed_consumer_grant()])
            .await
            .expect("exact fixed policy grants consumer authority");
        assert!(
            stores[0].status().admitted,
            "exact fixed policy is admitted"
        );
        let start_sequence = stores[0]
            .status()
            .last_log_index
            .map_or(0, |index| index.saturating_add(1));
        let mut watch = SessionBackend::watch(&stores[0], start_sequence)
            .await
            .expect("open idle generic watch before policy drift");

        let connection =
            rusqlite::Connection::open(&database_paths[0]).expect("open fixed voter database");
        let stored_policy = match drifted_policy {
            PlacementResiliencePolicy::RequireIndependentFailureDomains => 1_i64,
            PlacementResiliencePolicy::AllowReducedResilience => 2_i64,
            _ => unreachable!("test policy must have a durable encoding"),
        };
        connection
            .execute(
                "UPDATE consensus_identity SET fixed_placement_policy = ?1 WHERE singleton = 1",
                [stored_policy],
            )
            .expect("persist fixed placement policy drift");
        drop(connection);

        assert!(
            !stores[0].status().admitted,
            "status must revoke admission after fixed policy drift"
        );
        assert!(
            stores[0]
                .consumer_authorization_manifest([fixed_consumer_grant()])
                .await
                .is_err(),
            "consumer authority must fail closed after fixed policy drift"
        );
        assert!(
            SessionBackend::batch(&stores[0], Vec::new()).await.is_err(),
            "mutation authority must fail closed after fixed policy drift"
        );
        let readiness = stores[0]
            .probe_fixed_durable_quorum_readiness_at(TopologyAttestationTime::from_unix_seconds(1))
            .await;
        assert_eq!(
            readiness.traffic_authority(),
            FixedQuorumTrafficAuthority::StructuralRecoveryRequired,
            "fixed policy drift must revoke traffic authority"
        );
        let item = tokio::time::timeout(Duration::from_secs(1), watch.next())
            .await
            .expect("idle watch must revalidate fixed policy promptly")
            .expect("idle watch must emit a terminal authority failure");
        assert!(
            item.is_err(),
            "idle watch must fail closed after fixed policy drift"
        );
        assert!(
            watch.next().await.is_none(),
            "watch must terminate after fixed policy revocation"
        );
    }
}

#[tokio::test]
async fn running_fixed_applied_membership_drift_revokes_status_and_mutation_authority() {
    let (_directory, database_paths, stores) =
        open_fixed_cluster(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    let connection =
        rusqlite::Connection::open(&database_paths[0]).expect("open fixed voter database");
    connection
        .execute(
            "UPDATE consensus_membership SET membership_json = x'00' WHERE singleton = 1",
            [],
        )
        .expect("persist malformed applied membership drift");
    drop(connection);

    assert!(
        !stores[0].status().admitted,
        "status must fail closed when the persisted applied membership is not exact"
    );
    assert!(
        SessionBackend::batch(&stores[0], Vec::new()).await.is_err(),
        "mutation authority must fail closed when the persisted applied membership is not exact"
    );
}

#[tokio::test]
async fn running_fixed_scope_drift_terminates_an_already_open_generic_watch() {
    let (_directory, database_paths, stores) =
        open_fixed_cluster(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    let key = SessionKey {
        tenant: TenantId::new("fixed-watch-drift").expect("test tenant"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: b"fixed-watch-drift"
            .as_slice()
            .try_into()
            .expect("bounded stable ID"),
    };
    stores[0]
        .acquire(
            &key,
            OwnerId::new("fixed-watch-owner").expect("test owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("create watched consensus entry");
    let mut watch = SessionBackend::watch(&stores[0], 0)
        .await
        .expect("open generic watch before drift");

    let connection =
        rusqlite::Connection::open(&database_paths[0]).expect("open fixed voter database");
    connection
        .execute(
            "UPDATE consensus_membership_scope SET application_authority_epoch = application_authority_epoch + 1 WHERE singleton = 1",
            [],
        )
        .expect("persist fixed structural scope drift");

    assert!(
        watch
            .next()
            .await
            .expect("watch must observe its queued entry")
            .is_err(),
        "an already-open fixed watch must not expose entries after durable scope drift"
    );
    assert!(
        watch.next().await.is_none(),
        "watch must terminate after revocation"
    );
}

#[tokio::test]
async fn running_fixed_scope_drift_terminates_an_idle_generic_watch_promptly() {
    let (_directory, database_paths, stores) =
        open_fixed_cluster(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    let start_sequence = stores[0]
        .status()
        .last_log_index
        .map_or(0, |index| index.saturating_add(1));
    let mut watch = SessionBackend::watch(&stores[0], start_sequence)
        .await
        .expect("open idle generic watch before drift");

    let connection =
        rusqlite::Connection::open(&database_paths[0]).expect("open fixed voter database");
    connection
        .execute(
            "UPDATE consensus_membership_scope SET application_authority_epoch = application_authority_epoch + 1 WHERE singleton = 1",
            [],
        )
        .expect("persist fixed structural scope drift");
    drop(connection);

    let item = tokio::time::timeout(Duration::from_secs(1), watch.next())
        .await
        .expect("idle watch must revalidate durable authority promptly")
        .expect("idle watch must emit a terminal authority failure");
    assert!(
        item.is_err(),
        "idle watch must fail closed after durable drift"
    );
    assert!(
        watch.next().await.is_none(),
        "watch must terminate after revocation"
    );
}

#[tokio::test]
async fn fixed_majority_loss_terminates_an_idle_generic_watch_without_an_event() {
    let (_directory, _database_paths, stores, paths) =
        open_fixed_cluster_with_paths(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    let start_sequence = stores[0]
        .status()
        .last_log_index
        .map_or(0, |index| index.saturating_add(1));
    let mut watch = SessionBackend::watch(&stores[0], start_sequence)
        .await
        .expect("open idle generic watch before majority loss");

    paths
        .get(&(0, 1))
        .expect("fixed voter one path")
        .set_enabled(false);
    paths
        .get(&(0, 2))
        .expect("fixed voter two path")
        .set_enabled(false);

    let item = tokio::time::timeout(Duration::from_secs(12), watch.next())
        .await
        .expect("idle watch must re-establish majority authority within one bounded operation")
        .expect("idle watch must emit a terminal majority-authority failure");
    assert!(
        item.is_err(),
        "an idle fixed watch must fail closed after majority loss without a queued event"
    );
    assert!(
        watch.next().await.is_none(),
        "watch must terminate after majority authority is lost"
    );
}

#[tokio::test]
async fn fixed_scoped_consumer_watch_is_rejected_before_stream_admission() {
    let (_directory, _database_paths, stores, _paths) =
        open_fixed_cluster_with_paths(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    let scope = stores[0]
        .consumer_scope()
        .expect("fixed consumer scope before majority loss");
    let start_sequence = stores[0]
        .status()
        .last_log_index
        .map_or(0, |index| index.saturating_add(1));
    let identity = fixed_consumer_identity();
    let manifest = stores[0]
        .consumer_authorization_manifest([fixed_consumer_grant()])
        .await
        .expect("fixed consumer authorization manifest");
    let authorization = manifest
        .authorize(&identity)
        .expect("fixed consumer authorization");
    let rejection = match stores[0]
        .consumer_service()
        .watch(&authorization, scope, start_sequence)
        .await
    {
        Ok(_) => panic!("a global watch must not be admitted for a scoped consumer"),
        Err(rejection) => rejection,
    };
    assert_eq!(
        rejection,
        SessionConsumerRejection::Unauthorized,
        "denial occurs before a stream can expose foreign-tenant timing or sequence movement"
    );
}

#[tokio::test]
async fn fixed_majority_loss_revokes_readiness_reads_and_stale_lease_owner_mutations() {
    let (_directory, _database_paths, stores, paths) =
        open_fixed_cluster_with_paths(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    let key = SessionKey {
        tenant: TenantId::new("fixed-majority-fence").expect("test tenant"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: b"fixed-majority-fence"
            .as_slice()
            .try_into()
            .expect("bounded stable ID"),
    };
    let lease = stores[0]
        .acquire(
            &key,
            OwnerId::new("fixed-majority-owner").expect("test owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("acquire lease before majority loss");

    paths
        .get(&(0, 1))
        .expect("fixed voter one path")
        .set_enabled(false);
    paths
        .get(&(0, 2))
        .expect("fixed voter two path")
        .set_enabled(false);

    let readiness = tokio::time::timeout(
        Duration::from_secs(12),
        stores[0]
            .probe_fixed_durable_quorum_readiness_at(TopologyAttestationTime::from_unix_seconds(1)),
    )
    .await
    .expect("fixed readiness must remain bounded after majority loss");
    assert_eq!(
        readiness.traffic_authority(),
        FixedQuorumTrafficAuthority::NoQuorum,
        "a previously healthy fixed member must withdraw traffic authority after majority loss"
    );

    let (read, renewal, release) = tokio::join!(
        tokio::time::timeout(
            Duration::from_secs(12),
            SessionBackend::get(&stores[0], &key),
        ),
        tokio::time::timeout(
            Duration::from_secs(12),
            SessionLeaseManager::renew(&stores[0], &lease, Duration::from_secs(30)),
        ),
        tokio::time::timeout(
            Duration::from_secs(12),
            SessionLeaseManager::release(&stores[0], lease.clone()),
        ),
    );
    assert!(
        read.expect("read must remain bounded after majority loss")
            .is_err(),
        "a fixed member without majority must not serve a linearizable read"
    );
    assert!(
        renewal
            .expect("lease renewal must remain bounded after majority loss")
            .is_err(),
        "a stale fixed lease owner must not renew without majority authority"
    );
    assert!(
        release
            .expect("lease release must remain bounded after majority loss")
            .is_err(),
        "a stale fixed lease owner must not release without majority authority"
    );
}

#[tokio::test]
async fn fixed_recovery_latch_terminates_an_idle_generic_watch_without_an_event() {
    let (_directory, database_paths, stores) =
        open_fixed_cluster(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    let start_sequence = stores[0]
        .status()
        .last_log_index
        .map_or(0, |index| index.saturating_add(1));
    let mut watch = SessionBackend::watch(&stores[0], start_sequence)
        .await
        .expect("open idle generic watch before recovery latch activation");

    let connection =
        rusqlite::Connection::open(&database_paths[0]).expect("open fixed voter database");
    connection
        .execute(
            "UPDATE consensus_operator_recovery \
             SET pending_epoch = recovery_epoch + 1, pending_plan_digest = zeroblob(32) \
             WHERE singleton = 1",
            [],
        )
        .expect("activate durable fixed recovery latch");
    drop(connection);

    let item = tokio::time::timeout(Duration::from_secs(1), watch.next())
        .await
        .expect("idle watch must recheck the durable recovery latch promptly")
        .expect("idle watch must emit a terminal recovery-authority failure");
    assert!(
        item.is_err(),
        "an idle fixed watch must fail closed after recovery latch activation without a queued event"
    );
    assert!(
        watch.next().await.is_none(),
        "watch must terminate after recovery authority is revoked"
    );
}

#[tokio::test]
async fn fixed_recovery_latch_during_readiness_barrier_never_grants_traffic() {
    let (_directory, database_paths, stores, paths) =
        open_fixed_cluster_with_paths(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    let admitted_at = TopologyAttestationTime::from_unix_seconds(1);
    assert!(
        stores[0]
            .probe_fixed_durable_quorum_readiness_at(admitted_at)
            .await
            .traffic_authority()
            .is_granted(),
        "the detector requires an initially healthy fixed quorum"
    );

    for target in 1..3 {
        paths
            .get(&(0, target))
            .expect("fixed outbound path")
            .set_enabled(false);
    }
    let probe_store = stores[0].clone();
    let readiness_probe = tokio::spawn(async move {
        probe_store
            .probe_fixed_durable_quorum_readiness_at(admitted_at)
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !readiness_probe.is_finished(),
        "the detector must hold readiness inside its quorum barrier"
    );

    let connection =
        rusqlite::Connection::open(&database_paths[0]).expect("open fixed voter database");
    connection
        .execute(
            "UPDATE consensus_operator_recovery \
             SET pending_epoch = recovery_epoch + 1, pending_plan_digest = zeroblob(32) \
             WHERE singleton = 1",
            [],
        )
        .expect("activate durable fixed recovery latch during readiness barrier");
    drop(connection);
    for target in 1..3 {
        paths
            .get(&(0, target))
            .expect("fixed outbound path")
            .set_enabled(true);
    }

    let readiness = tokio::time::timeout(Duration::from_secs(12), readiness_probe)
        .await
        .expect("readiness must remain bounded after Recovery activation")
        .expect("readiness task must not panic");
    assert_eq!(
        readiness.traffic_authority(),
        FixedQuorumTrafficAuthority::RecoveryRequired,
        "Recovery activated during a quorum barrier must revoke traffic before readiness returns"
    );
}

#[tokio::test]
async fn fixed_recovery_latch_during_ordinary_read_barrier_never_returns_data() {
    let (_directory, database_paths, stores, paths) =
        open_fixed_cluster_with_paths(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    let key = SessionKey {
        tenant: TenantId::new("fixed-recovery-read-race").expect("test tenant"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: b"fixed-recovery-read-race"
            .as_slice()
            .try_into()
            .expect("bounded stable ID"),
    };

    for target in 1..3 {
        paths
            .get(&(0, target))
            .expect("fixed outbound path")
            .set_enabled(false);
    }
    let read_store = stores[0].clone();
    let read_key = key.clone();
    let read = tokio::spawn(async move { SessionBackend::get(&read_store, &read_key).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !read.is_finished(),
        "the detector must hold the ordinary read inside its quorum barrier"
    );

    let connection =
        rusqlite::Connection::open(&database_paths[0]).expect("open fixed voter database");
    connection
        .execute(
            "UPDATE consensus_operator_recovery \
             SET pending_epoch = recovery_epoch + 1, pending_plan_digest = zeroblob(32) \
             WHERE singleton = 1",
            [],
        )
        .expect("activate durable fixed recovery latch during ordinary read barrier");
    drop(connection);
    for target in 1..3 {
        paths
            .get(&(0, target))
            .expect("fixed outbound path")
            .set_enabled(true);
    }

    assert!(
        tokio::time::timeout(Duration::from_secs(12), read)
            .await
            .expect("ordinary read must remain bounded after Recovery activation")
            .expect("ordinary read task must not panic")
            .is_err(),
        "Recovery activated during a quorum barrier must revoke an ordinary read before return"
    );
}

#[tokio::test]
async fn fixed_recovery_latch_during_mutation_barrier_never_admits_new_lease() {
    let (_directory, database_paths, stores, paths) =
        open_fixed_cluster_with_paths(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    let key = SessionKey {
        tenant: TenantId::new("fixed-recovery-mutation-race").expect("test tenant"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: b"fixed-recovery-mutation-race"
            .as_slice()
            .try_into()
            .expect("bounded stable ID"),
    };

    for target in 1..3 {
        paths
            .get(&(0, target))
            .expect("fixed outbound path")
            .set_enabled(false);
    }
    let mutation_store = stores[0].clone();
    let mutation = tokio::spawn(async move {
        mutation_store
            .acquire(
                &key,
                OwnerId::new("fixed-recovery-mutation-owner").expect("test owner"),
                Duration::from_secs(30),
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !mutation.is_finished(),
        "the detector must hold the mutation inside its quorum barrier"
    );

    let connection =
        rusqlite::Connection::open(&database_paths[0]).expect("open fixed voter database");
    connection
        .execute(
            "UPDATE consensus_operator_recovery \
             SET pending_epoch = recovery_epoch + 1, pending_plan_digest = zeroblob(32) \
             WHERE singleton = 1",
            [],
        )
        .expect("activate durable fixed recovery latch during mutation barrier");
    drop(connection);
    for target in 1..3 {
        paths
            .get(&(0, target))
            .expect("fixed outbound path")
            .set_enabled(true);
    }

    assert!(
        tokio::time::timeout(Duration::from_secs(12), mutation)
            .await
            .expect("mutation must remain bounded after Recovery activation")
            .expect("mutation task must not panic")
            .is_err(),
        "Recovery activated during a quorum barrier must revoke mutation before proposal"
    );
    let connection =
        rusqlite::Connection::open(&database_paths[0]).expect("reopen fixed voter database");
    let record_count: u64 = connection
        .query_row("SELECT COUNT(*) FROM session_records", [], |row| row.get(0))
        .expect("count durable session records after rejected mutation");
    assert_eq!(
        record_count, 0,
        "rejected mutation must have no durable effect"
    );
}

#[tokio::test]
async fn fixed_quorum_rejects_every_dynamic_transition_entry_point() {
    let topology = fixed_topology(fixed_members(3)).expect("fixed topology admission");
    let identity = topology.consensus_identity().expect("consensus identity");
    let peers = scoped_peers(&topology);
    let directory = tempfile::tempdir().expect("fixed quorum directory");
    let store = ConsensusSessionStore::open_fixed_durable_quorum_with_snapshot_integrity(
        topology,
        SqliteSessionBackend::open(directory.path().join("fixed-voter.sqlite"))
            .expect("file-backed voter store"),
        directory.path().join("snapshots"),
        peers,
        SnapshotIntegrityPolicy::PortableVerified,
    )
    .await
    .expect("open fixed durable quorum");
    let request = successor_request(identity);

    assert_eq!(
        store.bind_topology_transport_admission(Arc::new(NoopTopologyTransport)),
        Err(SessionTopologyTransitionError::ImmutableFixedQuorum),
    );
    assert_eq!(
        store.stage_topology_transition_peers(&request, BTreeMap::new()),
        Err(SessionTopologyTransitionError::ImmutableFixedQuorum),
    );
    assert_eq!(
        store.unstage_topology_transition_peers(&request).await,
        Err(SessionTopologyTransitionError::ImmutableFixedQuorum),
    );
    assert_eq!(
        store
            .prepare_topology_transition(&request, BTreeMap::new())
            .await,
        Err(SessionTopologyTransitionError::ImmutableFixedQuorum),
    );
    assert_eq!(
        store.topology_transition_status(&request).await,
        Err(SessionTopologyTransitionError::ImmutableFixedQuorum),
    );
    assert_eq!(
        store.abort_topology_transition(&request).await,
        Err(SessionTopologyTransitionError::ImmutableFixedQuorum),
    );
}

#[tokio::test]
async fn fixed_authority_profile_persists_across_reopen_and_rejects_profile_changes() {
    let members = fixed_members(3);
    let fixed = fixed_topology(members.clone()).expect("fixed topology admission");
    let dynamic = ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
        replica_id(0),
        members.clone(),
        consensus_identity(&members),
    ))
    .expect("dynamic topology admission");
    let directory = tempfile::tempdir().expect("authority-profile directory");
    let fixed_database = directory.path().join("fixed.sqlite");
    let dynamic_database = directory.path().join("dynamic.sqlite");

    let fixed_store = ConsensusSessionStore::open_fixed_durable_quorum_with_snapshot_integrity(
        fixed.clone(),
        SqliteSessionBackend::open(&fixed_database).expect("file-backed fixed store"),
        directory.path().join("fixed-snapshots"),
        scoped_peers(&fixed),
        SnapshotIntegrityPolicy::PortableVerified,
    )
    .await
    .expect("open fixed store");
    fixed_store
        .shutdown()
        .await
        .expect("drain fixed store before durable reopen");
    drop(fixed_store);
    let fixed_reopened = ConsensusSessionStore::open_fixed_durable_quorum_with_snapshot_integrity(
        fixed.clone(),
        SqliteSessionBackend::open(&fixed_database).expect("file-backed fixed store"),
        directory.path().join("fixed-snapshots"),
        scoped_peers(&fixed),
        SnapshotIntegrityPolicy::PortableVerified,
    )
    .await
    .expect("reopen fixed store with its persisted authority profile");
    fixed_reopened
        .shutdown()
        .await
        .expect("drain reopened fixed store before profile mismatch probe");
    drop(fixed_reopened);
    let fixed_as_dynamic = ConsensusSessionStore::open(
        dynamic.clone(),
        SqliteSessionBackend::open(&fixed_database).expect("file-backed fixed store"),
        directory.path().join("fixed-snapshots"),
        scoped_peers(&dynamic),
    )
    .await;
    assert!(matches!(
        fixed_as_dynamic,
        Err(ConsensusSessionStoreOpenError::DurableIdentityMismatch)
    ));

    let dynamic_store = ConsensusSessionStore::open(
        dynamic,
        SqliteSessionBackend::open(&dynamic_database).expect("file-backed dynamic store"),
        directory.path().join("dynamic-snapshots"),
        scoped_peers(&fixed),
    )
    .await
    .expect("open dynamic store");
    dynamic_store
        .shutdown()
        .await
        .expect("drain dynamic store before profile mismatch probe");
    drop(dynamic_store);
    let dynamic_as_fixed =
        ConsensusSessionStore::open_fixed_durable_quorum_with_snapshot_integrity(
            fixed.clone(),
            SqliteSessionBackend::open(dynamic_database).expect("file-backed dynamic store"),
            directory.path().join("dynamic-snapshots"),
            scoped_peers(&fixed),
            SnapshotIntegrityPolicy::PortableVerified,
        )
        .await;
    assert!(matches!(
        dynamic_as_fixed,
        Err(ConsensusSessionStoreOpenError::DurableIdentityMismatch)
    ));
}

#[tokio::test]
async fn placement_expiry_downgrades_only_the_fixed_quorum_placement_result() {
    let members = (0..3)
        .map(|index| descriptor(index, index, index, index))
        .collect::<Vec<_>>();
    let identity = fixed_consensus_identity(&members, PlacementResiliencePolicy::default());
    let observed_at = TopologyAttestationTime::from_unix_seconds(100);
    let admitted_at = TopologyAttestationTime::from_unix_seconds(110);
    let expires_at = TopologyAttestationTime::from_unix_seconds(200);
    let collector = TopologyCollectorId::new("fixed-placement-attestor").expect("collector ID");
    let policy = TopologyAttestationPolicy::try_new(
        TopologyAttestationProvenance::AuthenticatedPlatform,
        vec![collector.clone()],
        Duration::from_secs(300),
    )
    .expect("placement policy");
    let evidence =
        authenticated_placement_evidence(&members, identity, &collector, observed_at, expires_at);
    let topologies = (0..3)
        .map(|index| {
            fixed_attested_topology(
                index,
                &members,
                identity,
                evidence.clone(),
                &policy,
                admitted_at,
            )
        })
        .collect::<Vec<_>>();
    let refreshed_at = TopologyAttestationTime::from_unix_seconds(210);
    let refreshed_placement = topologies[0]
        .verify_fixed_durable_quorum_placement_evidence(
            authenticated_placement_evidence(
                &members,
                identity,
                &collector,
                TopologyAttestationTime::from_unix_seconds(205),
                TopologyAttestationTime::from_unix_seconds(400),
            ),
            &policy,
            &DigestTopologyAttestor,
            refreshed_at,
        )
        .expect("refreshed fixed placement evidence");
    let directory = tempfile::tempdir().expect("fixed quorum directory");
    let node_ids = topologies
        .iter()
        .map(|topology| {
            topology
                .local_consensus_node_id()
                .expect("fixed local node ID")
        })
        .collect::<Vec<_>>();
    let mut paths = BTreeMap::new();
    for source in 0..3 {
        for (target, node_id) in node_ids.iter().copied().enumerate() {
            if source != target {
                paths.insert(
                    (source, target),
                    Arc::new(ScopedLoopbackPeer::new(node_id, identity)),
                );
            }
        }
    }
    let mut stores = Vec::new();
    for (source, topology) in topologies.iter().cloned().enumerate() {
        let peers = (0..3)
            .filter(|target| *target != source)
            .map(|target| {
                let peer: Arc<dyn SessionConsensusPeer> = paths
                    .get(&(source, target))
                    .expect("fixed scoped path")
                    .clone();
                (node_ids[target], peer)
            })
            .collect::<BTreeMap<_, _>>();
        let backend = SqliteSessionBackend::open(
            directory
                .path()
                .join(format!("fixed-voter-{source}.sqlite")),
        )
        .expect("file-backed voter store");
        let store = ConsensusSessionStore::open_fixed_durable_quorum_with_snapshot_integrity(
            topology,
            backend,
            directory.path().join(format!("snapshots-{source}")),
            peers,
            SnapshotIntegrityPolicy::PortableVerified,
        )
        .await
        .expect("open fixed durable quorum voter");
        stores.push(store);
    }
    for ((_, target), peer) in &paths {
        peer.install(stores[*target].rpc_handler()).await;
    }
    for result in
        futures_util::future::join_all(stores.iter().map(ConsensusSessionStore::initialize_cluster))
            .await
    {
        result.expect("initialize fixed quorum membership");
    }

    let successor_epoch = ConsensusConfigurationEpoch::new(2).expect("successor epoch");
    let transition = SessionTopologyTransitionRequest::try_new(
        SessionTopologyTransitionId::from_bytes([0x71; 16]),
        identity.cluster_id(),
        identity.configuration_epoch(),
        successor_epoch,
        (3..6)
            .map(|index| descriptor(index, index, index, index))
            .collect(),
        Duration::from_secs(30),
    )
    .expect("valid successor request");
    assert_eq!(
        stores[0].stage_topology_transition_peers(&transition, BTreeMap::new()),
        Err(SessionTopologyTransitionError::ImmutableFixedQuorum),
    );

    let before_expiry = stores[0]
        .probe_fixed_durable_quorum_readiness_at(admitted_at)
        .await;
    assert_eq!(
        before_expiry.traffic_authority(),
        FixedQuorumTrafficAuthority::Granted,
    );
    assert_eq!(
        before_expiry.placement_resilience().disposition(),
        PlacementResilienceDisposition::IndependentPlacementQualified,
    );

    let expired = stores[0]
        .probe_fixed_durable_quorum_readiness_at(expires_at)
        .await;
    assert_eq!(
        expired.traffic_authority(),
        FixedQuorumTrafficAuthority::Granted
    );
    assert_eq!(
        expired.placement_resilience().disposition(),
        PlacementResilienceDisposition::IndependentPlacementWithheld,
    );

    let refreshed = stores[0]
        .probe_fixed_durable_quorum_readiness_with_placement_attestation_at(
            &refreshed_placement,
            refreshed_at,
        )
        .await;
    assert_eq!(
        refreshed.traffic_authority(),
        FixedQuorumTrafficAuthority::Granted,
    );
    assert_eq!(
        refreshed.placement_resilience().disposition(),
        PlacementResilienceDisposition::IndependentPlacementQualified,
    );
}

#[tokio::test]
async fn fixed_five_voter_authenticated_placement_expiry_preserves_traffic_authority() {
    let members = fixed_members(5);
    let identity = fixed_consensus_identity(&members, PlacementResiliencePolicy::default());
    let observed_at = TopologyAttestationTime::from_unix_seconds(100);
    let qualified_at = TopologyAttestationTime::from_unix_seconds(110);
    let expires_at = TopologyAttestationTime::from_unix_seconds(200);
    let collector =
        TopologyCollectorId::new("fixed-five-placement-attestor").expect("collector ID");
    let policy = TopologyAttestationPolicy::try_new(
        TopologyAttestationProvenance::AuthenticatedPlatform,
        vec![collector.clone()],
        Duration::from_secs(300),
    )
    .expect("placement policy");
    let topology =
        fixed_topology_for_local(0, members.clone(), PlacementResiliencePolicy::default())
            .expect("fixed five-voter topology");
    let placement = topology
        .verify_fixed_durable_quorum_placement_evidence(
            authenticated_placement_evidence(
                &members,
                identity,
                &collector,
                observed_at,
                expires_at,
            ),
            &policy,
            &DigestTopologyAttestor,
            qualified_at,
        )
        .expect("authenticated placement");
    let (_directory, _database_paths, stores) =
        open_fixed_cluster(5, PlacementResiliencePolicy::default()).await;

    let qualified = stores[0]
        .probe_fixed_durable_quorum_readiness_with_placement_attestation_at(
            &placement,
            qualified_at,
        )
        .await;
    assert_eq!(
        qualified.traffic_authority(),
        FixedQuorumTrafficAuthority::Granted,
    );
    assert_eq!(
        qualified.placement_resilience().disposition(),
        PlacementResilienceDisposition::IndependentPlacementQualified,
    );

    let expired = stores[0]
        .probe_fixed_durable_quorum_readiness_with_placement_attestation_at(&placement, expires_at)
        .await;
    assert_eq!(
        expired.traffic_authority(),
        FixedQuorumTrafficAuthority::Granted,
    );
    assert_eq!(
        expired.placement_resilience().disposition(),
        PlacementResilienceDisposition::IndependentPlacementWithheld,
    );
}
