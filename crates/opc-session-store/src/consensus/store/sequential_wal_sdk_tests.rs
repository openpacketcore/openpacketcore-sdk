//! Real fixed-quorum SDK calls through the private WAL opt-in. The peer
//! transport is in-process; this does not qualify remote TLS or snapshots.

use std::collections::BTreeMap;
use std::fmt;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{future::join_all, FutureExt};
use opc_consensus::{ConsensusClusterId, ConsensusConfigurationEpoch};
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing};
use opc_types::{NetworkFunctionKind, TenantId};

use super::ConsensusSessionStore;
use crate::backend::{
    CompareAndSet, CompareAndSetResult, EncryptingSessionBackend, SessionBackend,
};
use crate::consensus::{
    SessionConsensusIdentity, SessionConsensusNodeId, SessionConsensusPeer,
    SessionConsensusPeerError, SessionConsensusRpcHandler, SessionConsensusWireRequest,
    SessionConsensusWireResponse,
};
use crate::fenced_transition::{
    FencedTransitionLease, FencedTransitionMutation, FencedTransitionMutationResult,
    FencedTransitionOutcome, FencedTransitionV2CallerNonce, FencedTransitionV2HistoryEpoch,
    FencedTransitionV2Request, FencedTransitionV2Status,
};
use crate::lease::{LeaseGuard, SessionLeaseManager};
use crate::model::{
    FenceToken, Generation, OwnerId, SessionKey, SessionKeyType, StateClass, StateType,
};
use crate::record::{EncryptedSessionPayload, StoredSessionRecord};
use crate::sqlite::consensus::wal::integration::PrivateWalTest;
use crate::sqlite::consensus::wal::Wal;
use crate::sqlite::SqliteSessionBackend;
use crate::topology::{
    QuorumReplicaDescriptor, QuorumTopologyConfig, ReplicaBackingIdentity, ReplicaEndpoint,
    ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity, ValidatedQuorumTopology,
};
use crate::{FixedQuorumTrafficAuthority, PlacementResiliencePolicy, SnapshotIntegrityPolicy};

struct Peer {
    node: SessionConsensusNodeId,
    identity: SessionConsensusIdentity,
    handler: tokio::sync::RwLock<Option<Arc<dyn SessionConsensusRpcHandler>>>,
}

impl fmt::Debug for Peer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateWalSdkPeer")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SessionConsensusPeer for Peer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.node
    }

    fn scope_identity(&self) -> Option<SessionConsensusIdentity> {
        Some(self.identity)
    }

    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        let handler = self
            .handler
            .read()
            .await
            .clone()
            .ok_or(SessionConsensusPeerError::Unavailable)?;
        Ok(handler.handle(request.sender, request).await)
    }
}

struct Fleet {
    case: &'static str,
    incarnation: u64,
    directory: tempfile::TempDir,
    snapshot_root: Option<std::path::PathBuf>,
    clock: Option<Arc<dyn crate::Clock>>,
    topologies: Vec<ValidatedQuorumTopology>,
    tests: Vec<Arc<PrivateWalTest>>,
    peers: Vec<Arc<Peer>>,
    stores: Vec<ConsensusSessionStore>,
}

impl Fleet {
    fn new(case: &'static str) -> Self {
        Self::new_with_mode(case, false)
    }

    fn new_native(case: &'static str) -> Self {
        Self::new_with_mode(case, true)
    }

    fn new_with_mode(case: &'static str, native: bool) -> Self {
        let directory = tempfile::tempdir().expect("private WAL SDK directory");
        let members = (0..3)
            .map(|index| {
                QuorumReplicaDescriptor::new(
                    ReplicaId::new(format!("private-wal-sdk-{index}")).expect("replica"),
                    ReplicaEndpoint::new(format!("private-wal-sdk-{index}.invalid"), 7443)
                        .expect("endpoint"),
                    ReplicaTlsIdentity::new(format!("spiffe://test/private-wal/{index}"))
                        .expect("identity"),
                    ReplicaFailureDomain::new(format!("private-wal-zone-{index}")).expect("zone"),
                    ReplicaBackingIdentity::new(format!("private-wal-disk-{index}")).expect("disk"),
                )
            })
            .collect::<Vec<_>>();
        let placement = PlacementResiliencePolicy::AllowReducedResilience;
        let identity = crate::derive_fixed_durable_quorum_consensus_identity(
            ConsensusClusterId::new("private-wal-sdk-fixed").expect("cluster"),
            ConsensusConfigurationEpoch::new(1).expect("epoch"),
            &members
                .iter()
                .map(QuorumReplicaDescriptor::configuration_fingerprint)
                .collect::<Vec<_>>(),
            placement,
        );
        let topologies = members
            .iter()
            .map(|member| {
                ValidatedQuorumTopology::try_from_fixed_durable_quorum_with_placement_policy(
                    QuorumTopologyConfig::new_consensus(
                        member.replica_id().clone(),
                        members.clone(),
                        identity,
                    ),
                    placement,
                )
                .expect("fixed topology")
            })
            .collect::<Vec<_>>();
        let peers = topologies
            .iter()
            .map(|topology| {
                Arc::new(Peer {
                    node: topology.local_consensus_node_id().expect("node"),
                    identity,
                    handler: tokio::sync::RwLock::new(None),
                })
            })
            .collect();
        let tests = (0..3)
            .map(|index| {
                let path = directory.path().join(format!("wal-{index}"));
                Arc::new(if native {
                    PrivateWalTest::new_native(path, [index as u8 + 1; 32])
                } else {
                    PrivateWalTest::new(path, [index as u8 + 1; 32])
                })
            })
            .collect();
        Self {
            case,
            incarnation: 0,
            directory,
            snapshot_root: None,
            clock: None,
            topologies,
            tests,
            peers,
            stores: Vec::new(),
        }
    }

    async fn open(&mut self) {
        assert!(self.stores.is_empty());
        self.incarnation += 1;
        for index in 0..3 {
            let mut backend = SqliteSessionBackend::open(
                self.directory.path().join(format!("node-{index}.sqlite")),
            )
            .expect("real SDK database");
            backend.private_wal_test = Some(Arc::clone(&self.tests[index]));
            let peers = self
                .peers
                .iter()
                .enumerate()
                .filter(|(peer, _)| *peer != index)
                .map(|(_, peer)| {
                    let transport: Arc<dyn SessionConsensusPeer> = peer.clone();
                    (peer.node, transport)
                })
                .collect::<BTreeMap<_, _>>();
            let snapshot_directory = self
                .snapshot_root
                .as_deref()
                .unwrap_or(self.directory.path())
                .join(format!("snapshots-{index}"));
            let snapshot_integrity = if self.snapshot_root.is_some() {
                SnapshotIntegrityPolicy::FsVerity
            } else {
                SnapshotIntegrityPolicy::PortableVerified
            };
            let result =
                ConsensusSessionStore::open_fixed_durable_quorum_with_clock_and_snapshot_integrity(
                    self.topologies[index].clone(),
                    backend,
                    snapshot_directory,
                    peers,
                    self.clock
                        .clone()
                        .unwrap_or_else(|| Arc::new(crate::SystemClock)),
                    super::DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
                    snapshot_integrity,
                )
                .await;
            match result {
                Ok(store) => self.stores.push(store),
                Err(error) => {
                    self.close().await;
                    panic!("private WAL SDK node {index} open failed: {error:?}");
                }
            }
        }
        for (peer, store) in self.peers.iter().zip(&self.stores) {
            *peer.handler.write().await = Some(store.rpc_handler());
            assert!(
                store.inner.private_wal.is_some(),
                "actual SDK store selected the private WAL"
            );
        }
        // Every new store starts with local traffic admission disabled.
        // This existing API also verifies and admits nonpristine members;
        // persisted Raft membership alone cannot replace that SDK step.
        let results = join_all(
            self.stores
                .iter()
                .map(ConsensusSessionStore::initialize_cluster),
        )
        .await;
        if let Some(error) = results.iter().find_map(|result| result.as_ref().err()) {
            let error = format!("{error:?}");
            self.close().await;
            panic!("private WAL SDK admission failed: {error}");
        }
        let ready = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let reports = join_all(self.stores.iter().map(|store| async {
                    store
                        .probe_fixed_durable_quorum_readiness()
                        .await
                        .traffic_authority()
                }))
                .await;
                if reports
                    .iter()
                    .all(|report| *report == FixedQuorumTrafficAuthority::Granted)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        if ready.is_err() {
            let metrics = self
                .stores
                .iter()
                .map(|store| format!("{:?}", *store.inner.raft.metrics().borrow()))
                .collect::<Vec<_>>();
            self.close().await;
            panic!("private WAL SDK readiness failed: {metrics:?}");
        }
    }

    fn observe_costs(&self, phase: &str) {
        // These cumulative snapshots are taken outside each public timer.
        // They do not wait for a follower or exclude unrelated Raft work.
        for (voter, store) in self.stores.iter().enumerate() {
            let costs = store
                .inner
                .private_wal
                .as_ref()
                .expect("private WAL")
                .integration_cost_snapshot()
                .expect("private SDK phase costs");
            eprintln!(
                "private_wal_sdk_phase={}",
                serde_json::json!({
                    "case": self.case, "incarnation": self.incarnation,
                    "phase": phase, "voter": voter, "costs": costs,
                })
            );
        }
    }

    async fn close(&mut self) -> Vec<Arc<Wal>> {
        let wals = self
            .stores
            .iter()
            .filter_map(|store| store.inner.private_wal.clone())
            .collect::<Vec<_>>();
        let results = join_all(self.stores.iter().map(ConsensusSessionStore::shutdown)).await;
        for peer in &self.peers {
            *peer.handler.write().await = None;
        }
        self.stores.clear();
        for (index, wal) in wals.iter().enumerate() {
            let mut observations = wal
                .integration_observations()
                .expect("private WAL observations");
            observations["case"] = serde_json::json!(self.case);
            observations["incarnation"] = serde_json::json!(self.incarnation);
            eprintln!("private_wal_sdk_voter_{index}={observations}");
            assert_eq!(
                observations["writer_joined"], true,
                "SDK shutdown joined its WAL writer"
            );
        }
        for result in results {
            result.expect("private WAL SDK orderly shutdown");
        }
        wals
    }
}

fn tenant() -> TenantId {
    TenantId::new("private-wal-sdk").expect("tenant")
}

fn provider() -> Arc<MemoryKeyProvider> {
    let provider = Arc::new(MemoryKeyProvider::new());
    provider
        .insert_active_key(
            KeyId::new("private-wal-sdk-key").expect("key ID"),
            KeyPurpose::Session,
            tenant(),
            Zeroizing::new([0x53; 32]),
        )
        .expect("install actual AEAD key");
    provider
}

fn key(index: usize) -> SessionKey {
    SessionKey {
        tenant: tenant(),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from(format!("private-wal-sdk-session-{index}"))
            .try_into()
            .expect("key"),
    }
}

fn record(key: SessionKey, lease: &LeaseGuard, generation: u64) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(generation),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("private-wal-sdk"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(b"private WAL real SDK plaintext round trip"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixed_three_voter_public_lease_cas_reads_and_orderly_reopen() {
    let mut fleet = Fleet::new("ordinary");
    fleet.open().await;
    let provider = provider();
    let result = AssertUnwindSafe(async {
        fleet.observe_costs("fresh_ready");
        let leader = fleet
            .stores
            .iter()
            .position(|store| {
                let status = store.status();
                status.leader_id == Some(status.node_id)
            })
            .expect("fixed leader");
        let follower = (leader + 1) % 3;
        eprintln!("private_wal_sdk_ordinary_ingress={follower};leader={leader}");
        let encrypted = EncryptingSessionBackend::new(
            Arc::new(fleet.stores[follower].clone()),
            provider.clone(),
            "private-wal-sdk",
        );
        let mut requests = Vec::new();
        for index in 0..8 {
            let key = key(index);
            let started = Instant::now();
            let lease = encrypted
                .acquire(
                    &key,
                    OwnerId::new(format!("private-wal-sdk-owner-{index}")).expect("owner"),
                    Duration::from_secs(60),
                )
                .await
                .expect("ordinary SDK lease");
            eprintln!(
                "private_wal_sdk_lease_{index}_us={}",
                started.elapsed().as_micros()
            );
            requests.push(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: record(key, &lease, 1),
            });
        }
        fleet.observe_costs("leases_complete");
        let started = Instant::now();
        let results = join_all(
            requests
                .iter()
                .cloned()
                .map(|request| encrypted.compare_and_set(request)),
        )
        .await;
        eprintln!(
            "private_wal_sdk_eight_cas_us={}",
            started.elapsed().as_micros()
        );
        fleet.observe_costs("eight_cas_complete");
        for result in results {
            assert_eq!(
                result.expect("ordinary SDK concurrent CAS"),
                CompareAndSetResult::Success
            );
        }
        for (index, store) in fleet.stores.iter().enumerate() {
            let encrypted = EncryptingSessionBackend::new(
                Arc::new(store.clone()),
                provider.clone(),
                "private-wal-sdk",
            );
            for request in &requests {
                let started = Instant::now();
                assert_eq!(
                    encrypted
                        .get(&request.key)
                        .await
                        .expect("ordinary SDK read"),
                    Some(request.new_record.clone())
                );
                eprintln!(
                    "private_wal_sdk_read_voter_{index}_us={}",
                    started.elapsed().as_micros()
                );
            }
        }
        fleet.observe_costs("initial_reads_complete");
        requests
    })
    .catch_unwind()
    .await;
    let initial_wals = fleet.close().await;
    let requests = result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));

    // The retained test token supplies the original binding. This proves
    // orderly SDK reopen without claiming on-disk migration selection.
    fleet.open().await;
    let result = AssertUnwindSafe(async {
        fleet.observe_costs("reopened_ready");
        for (index, store) in fleet.stores.iter().enumerate() {
            let encrypted = EncryptingSessionBackend::new(
                Arc::new(store.clone()),
                provider.clone(),
                "private-wal-sdk",
            );
            for request in &requests {
                let started = Instant::now();
                assert_eq!(
                    encrypted
                        .get(&request.key)
                        .await
                        .expect("reopened SDK read"),
                    Some(request.new_record.clone())
                );
                eprintln!(
                    "private_wal_sdk_reopened_read_voter_{index}_us={}",
                    started.elapsed().as_micros()
                );
            }
        }
        fleet.observe_costs("reopened_reads_complete");
        let encrypted = EncryptingSessionBackend::new(
            Arc::new(fleet.stores[0].clone()),
            provider.clone(),
            "private-wal-sdk",
        );
        let mut successor = requests[0].clone();
        successor.expected_generation = Some(Generation::new(1));
        successor.new_record.generation = Generation::new(2);
        let started = Instant::now();
        assert_eq!(
            encrypted
                .compare_and_set(successor.clone())
                .await
                .expect("continue after orderly reopen"),
            CompareAndSetResult::Success
        );
        eprintln!(
            "private_wal_sdk_reopened_single_cas_us={}",
            started.elapsed().as_micros()
        );
        assert_eq!(
            encrypted
                .get(&successor.key)
                .await
                .expect("successor SDK read"),
            Some(successor.new_record)
        );
        fleet.observe_costs("successor_complete");
        for wal in &initial_wals {
            assert_eq!(
                wal.integration_observations().expect("old joined writer")["writer_joined"],
                true
            );
        }
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

async fn v2_create_request(
    index: usize,
    epoch: FencedTransitionV2HistoryEpoch,
    fence: FenceToken,
    provider: &MemoryKeyProvider,
) -> FencedTransitionV2Request {
    let key = key(100 + index);
    let owner = OwnerId::new(format!("private-wal-sdk-v2-owner-{index}")).expect("V2 owner");
    let lease =
        FencedTransitionLease::acquire(key.clone(), owner.clone(), fence, Duration::from_secs(60))
            .expect("public V2 lease request");
    let mut record = StoredSessionRecord {
        key,
        generation: Generation::new(1),
        owner,
        fence: FenceToken::new(fence.get() + 1),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("private-wal-sdk"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(b"private WAL real SDK V2 plaintext round trip"),
    };
    record.payload = EncryptedSessionPayload::encrypt(provider, &record, "private-wal-sdk")
        .await
        .expect("real AEAD V2 payload");
    FencedTransitionV2Request::new(
        epoch,
        FencedTransitionV2CallerNonce::from_bytes((index as u128).to_be_bytes()),
        lease,
        FencedTransitionMutation::create(record),
    )
    .expect("self-authenticating public V2 request")
}

fn assert_v2_create(request: &FencedTransitionV2Request, outcome: &FencedTransitionOutcome) {
    assert!(
        outcome.matches_v2_request(request),
        "exact complete V2 result correlation"
    );
    assert_eq!(outcome.mutation(), FencedTransitionMutationResult::Created);
    assert_eq!(outcome.committed_generation(), Generation::new(1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixed_three_voter_public_eight_item_v2_batches_with_full_activation() {
    let mut fleet = Fleet::new("v2_batch");
    fleet.open().await;
    let result = AssertUnwindSafe(async {
        let leader = fleet.stores.iter().position(|store| {
            let status = store.status();
            status.leader_id == Some(status.node_id)
        }).expect("fixed V2 leader");
        let store = &fleet.stores[leader];
        let provider = provider();
        let epoch = FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch");
        eprintln!("private_wal_sdk_v2_ingress={leader};leader={leader}");
        fleet.observe_costs("fresh_ready");
        let mut retained = Vec::new();
        for (batch, phase) in ["cold", "warm"].into_iter().enumerate() {
            let mut requests = Vec::new();
            for index in (batch * 8)..((batch + 1) * 8) {
                let observation = store.observe_fenced_transition(&key(100 + index))
                    .await.expect("public V2 fence observation");
                requests.push(v2_create_request(index, epoch, observation.current_fence(), &provider).await);
            }
            fleet.observe_costs(&format!("{phase}_batch_before"));
            let before = store.diagnostic_snapshot();
            let started = Instant::now();
            let outcomes = store.fenced_transition_v2_batch(requests.clone())
                .await.expect("public eight-item V2 batch");
            let elapsed_us = started.elapsed().as_micros();
            let after = store.diagnostic_snapshot();
            eprintln!("private_wal_sdk_eight_v2_{phase}_us={elapsed_us}");
            fleet.observe_costs(&format!("{phase}_batch_after"));
            assert_eq!(outcomes.len(), 8);
            for (request, outcome) in requests.into_iter().zip(outcomes) {
                let outcome = outcome.expect("individual public V2 create result");
                assert_v2_create(&request, &outcome);
                retained.push((request, outcome));
            }
            // The first public batch must retain the original unanimous
            // capability/history admission, singleton activation and suffix.
            // The second batch uses the existing warmed eight-item proposal.
            let cold = u64::from(batch == 0);
            assert_eq!(after.public_raw_v2_cold_admissions - before.public_raw_v2_cold_admissions, cold);
            assert_eq!(after.public_raw_v2_history_reads - before.public_raw_v2_history_reads, cold);
            assert_eq!(after.fixed_raw_v2_acceptance_snapshots - before.fixed_raw_v2_acceptance_snapshots, 1 + cold);
            assert_eq!(after.fixed_raw_v2_proposals - before.fixed_raw_v2_proposals, 1);
        }
        for voter in &fleet.stores {
            let history = voter.fenced_transition_v2_history_state().await.expect("all-voter V2 history");
            assert_eq!(history.active_epoch(), Some(epoch));
            assert_eq!(history.bound_entries(), 16);
            let encrypted = EncryptingSessionBackend::new(Arc::new(voter.clone()), provider.clone(), "private-wal-sdk");
            for (request, outcome) in &retained {
                assert!(matches!(
                    voter.fenced_transition_v2_status(request).await.expect("exact all-voter V2 receipt"),
                    FencedTransitionV2Status::Recorded(result) if result.as_ref() == &Ok(outcome.clone())
                ));
                let FencedTransitionMutation::Create { record } = request.mutation() else {
                    panic!("fixture request must remain a create");
                };
                let mut expected = record.as_ref().clone();
                expected.payload = EncryptedSessionPayload::new(b"private WAL real SDK V2 plaintext round trip");
                assert_eq!(encrypted.get(&record.key).await.expect("V2 encrypted SDK read"), Some(expected));
            }
        }
        fleet.observe_costs("all_voter_results_verified");
    }).catch_unwind().await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

mod native_flow;
mod paced_viability;

#[derive(Debug)]
struct QuorumAuthorityClock(crate::Timestamp);

impl crate::Clock for QuorumAuthorityClock {
    fn now_utc(&self) -> crate::Timestamp {
        self.0
    }
}

fn quorum_authority_expected(topology: &ValidatedQuorumTopology) -> serde_json::Value {
    use sha2::{Digest, Sha256};
    let identity = topology.consensus_identity().expect("fixture identity");
    let mut bindings = BTreeMap::new();
    for member in topology.members() {
        let node = topology
            .consensus_node_id(member.replica_id())
            .expect("fixture node");
        let mut endpoint = Sha256::new();
        endpoint.update(b"openpacketcore/session-store/topology-endpoint-binding/v1\0");
        endpoint.update(Sha256::digest(member.endpoint().host().as_bytes()));
        endpoint.update(member.endpoint().port().to_be_bytes());
        let mut tls = Sha256::new();
        tls.update(b"openpacketcore/session-store/topology-tls-binding/v1\0");
        tls.update(Sha256::digest(member.tls_identity().as_str().as_bytes()));
        let mut backing = Sha256::new();
        backing.update(b"openpacketcore/session-store/topology-backing-binding/v1\0");
        backing.update(member.backing_identity().fingerprint());
        bindings.insert(
            node,
            serde_json::json!({
                "descriptor": member.configuration_fingerprint(),
                "endpoint": endpoint.finalize().to_vec(),
                "tls_identity": tls.finalize().to_vec(),
                "backing_identity": backing.finalize().to_vec(),
            }),
        );
    }
    let voters = bindings
        .keys()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let mut digest = Sha256::new();
    digest.update(b"openpacketcore/session-consensus/fenced-transition-voter-set/v1\0");
    digest.update(identity.cluster_id().as_bytes());
    digest.update(identity.configuration_id().as_bytes());
    digest.update(identity.configuration_epoch().get().to_be_bytes());
    for voter in &voters {
        digest.update(voter.get().to_be_bytes());
    }
    let profile = [
        0x8a_u8, 0x0b, 0x70, 0xb5, 0x46, 0x54, 0xc7, 0x25, 0x0c, 0xf5, 0x46, 0x9d, 0xb6, 0xe1,
        0xe5, 0x45, 0xf3, 0x5e, 0x38, 0xe9, 0x77, 0x8d, 0x5f, 0x50, 0x0f, 0xea, 0x67, 0x06, 0x96,
        0xc4, 0xbd, 0xc3,
    ];
    assert_eq!(crate::fenced_transition_v2_profile_digest(), profile);
    serde_json::json!({
        "identity": identity, "voters": voters,
        "bindings": bindings.into_iter().collect::<Vec<_>>(),
        "activation": {"identity": identity, "voters": digest.finalize().to_vec(), "profile": profile},
        "history": crate::FencedTransitionV2HistoryState::new(
            Some(FencedTransitionV2HistoryEpoch::new(1).expect("fixture epoch")),
            None, None, 0, 0, 2, 0,
        ).expect("two exact successful fixture requests"),
    })
}

fn quorum_authority_assert_native(facts: &serde_json::Value, expected: &serde_json::Value) {
    for field in ["binding_identity", "scope_identity"] {
        assert_eq!(facts[field], expected["identity"]);
    }
    for field in [
        "authority_members",
        "scope_members",
        "application_authority_members",
    ] {
        assert_eq!(facts[field], expected["voters"]);
    }
    for field in ["authority_bindings", "scope_bindings"] {
        assert_eq!(facts[field], expected["bindings"]);
    }
    assert_eq!(facts["authority_profile"], 2);
    assert_eq!(facts["placement"], 2);
    assert_eq!(facts["application_authority_epoch"], 1);
    for field in ["predecessor_present", "pending_present", "terminal_present"] {
        assert_eq!(facts[field], false);
    }
    for field in ["history_depth", "terminal_history_depth"] {
        assert_eq!(facts[field], 0);
    }
    let business = &facts["business"];
    assert_eq!(business["identity"], expected["identity"]);
    assert_eq!(business["members"], expected["voters"]);
    assert_eq!(business["activation"], expected["activation"]);
    assert_eq!(business["history"], expected["history"]);
    assert_eq!(business["receipt_count"], 2);
    assert!(!business["membership_log_id"].is_null());
    assert_eq!(
        business["membership_configs"],
        serde_json::json!([expected["voters"]])
    );
    assert_eq!(business["membership_nodes"], expected["voters"]);
    assert!(!facts["durable_committed"].is_null());
    assert_eq!(business["applied"], facts["durable_committed"]);
}

fn quorum_authority_sql_position(
    tx: &rusqlite::Transaction<'_>,
    table: &str,
) -> Option<opc_consensus::engine::LogId<SessionConsensusNodeId>> {
    use rusqlite::OptionalExtension;
    assert!(matches!(table, "consensus_applied" | "consensus_committed"));
    tx.query_row(&format!("SELECT configuration_epoch, term, log_index, log_id_json FROM {table} WHERE singleton = 1"), [], |row| {
        Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?, row.get::<_, u64>(2)?, row.get::<_, Vec<u8>>(3)?))
    }).optional().expect("independent SQL full LogId row").map(|(epoch, term, index, bytes)| {
        let id: opc_consensus::engine::LogId<SessionConsensusNodeId> = serde_json::from_slice(&bytes).expect("SQL LogId encoding");
        assert_eq!(epoch, 1);
        assert_eq!(term, id.leader_id.term);
        assert_eq!(index, id.index);
        id
    })
}

fn quorum_authority_sql_connection(path: &std::path::Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("independent SQL connection");
    conn.busy_timeout(Duration::ZERO)
        .expect("bounded SQL witness lock");
    conn
}

fn quorum_authority_timestamp(timestamp: crate::Timestamp) -> String {
    let time = timestamp
        .as_offset_datetime()
        .to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second(),
        time.nanosecond()
    )
}

fn quorum_authority_sql_witness(
    path: &std::path::Path,
    expected: &serde_json::Value,
    retained: &[(FencedTransitionV2Request, FencedTransitionOutcome)],
) -> serde_json::Value {
    use sha2::{Digest, Sha256};
    let conn = quorum_authority_sql_connection(path);
    let tx = conn
        .unchecked_transaction()
        .expect("one SQL witness transaction");
    let identity: SessionConsensusIdentity =
        serde_json::from_value(expected["identity"].clone()).expect("fixture identity");
    let stored = tx.query_row("SELECT schema_version, cluster_id, configuration_id, configuration_epoch, authority_profile, fixed_placement_policy FROM consensus_identity WHERE singleton = 1", [], |row| {
        Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?, row.get::<_, u64>(3)?, row.get::<_, u64>(4)?, row.get::<_, u64>(5)?))
    }).expect("raw SQL identity");
    assert_eq!(
        stored,
        (
            3,
            identity.cluster_id().as_bytes().to_vec(),
            identity.configuration_id().as_bytes().to_vec(),
            1,
            2,
            2
        )
    );
    let scope = tx.query_row("SELECT storage_configuration_epoch, current_configuration_id, current_configuration_epoch, current_members_json, current_bindings_json, application_authority_epoch, application_authority_members_json, predecessor_configuration_id IS NULL AND pending_transition_id IS NULL AND terminal_transition_id IS NULL FROM consensus_membership_scope WHERE singleton = 1", [], |row| {
        Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, u64>(2)?, row.get::<_, Vec<u8>>(3)?, row.get::<_, Vec<u8>>(4)?, row.get::<_, u64>(5)?, row.get::<_, Vec<u8>>(6)?, row.get::<_, bool>(7)?))
    }).expect("raw SQL application authority");
    assert_eq!(
        (scope.0, scope.1, scope.2, scope.5, scope.7),
        (
            1,
            identity.configuration_id().as_bytes().to_vec(),
            1,
            1,
            true
        )
    );
    for members in [&scope.3, &scope.6] {
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(members).expect("raw SQL voters"),
            expected["voters"]
        );
    }
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&scope.4).expect("raw SQL bindings"),
        expected["bindings"]
    );
    for (table, count) in [
        ("consensus_membership_history", 0),
        ("consensus_membership_terminal_history", 0),
        ("consensus_fenced_transition_v2_activation", 1),
        ("consensus_fenced_transition_v2_history", 1),
        ("consensus_fenced_transition_v2_receipts", 2),
        ("session_records", 2),
        ("key_fences", 2),
        ("leases", 2),
    ] {
        assert!(tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
                [table],
                |row| row.get::<_, bool>(0)
            )
            .expect("independent SQL table presence"));
        assert_eq!(
            tx.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                .get::<_, u64>(0))
                .expect("independent SQL cardinality"),
            count
        );
    }
    let certificate = tx.query_row("SELECT storage_configuration_epoch, scope_configuration_id, scope_configuration_epoch, voter_set_digest, profile_digest FROM consensus_fenced_transition_v2_activation WHERE singleton = 1", [], |row| {
        Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, u64>(2)?, row.get::<_, Vec<u8>>(3)?, row.get::<_, Vec<u8>>(4)?))
    }).expect("independent SQL certificate");
    assert_eq!(
        (certificate.0, certificate.1, certificate.2),
        (1, identity.configuration_id().as_bytes().to_vec(), 1)
    );
    assert_eq!(
        serde_json::json!(certificate.3),
        expected["activation"]["voters"]
    );
    assert_eq!(
        serde_json::json!(certificate.4),
        expected["activation"]["profile"]
    );
    let history = tx.query_row("SELECT storage_configuration_epoch, profile_digest, active_epoch, retired_through_epoch, generation, current_bound_count, reclaim_epoch, reclaim_remaining, reclaimed_entries FROM consensus_fenced_transition_v2_history WHERE singleton = 1", [], |row| {
        Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, u64>(2)?, row.get::<_, u64>(3)?, row.get::<_, u64>(4)?, row.get::<_, u64>(5)?, row.get::<_, Option<u64>>(6)?, row.get::<_, Option<u64>>(7)?, row.get::<_, u64>(8)?))
    }).expect("independent SQL history");
    assert_eq!(
        serde_json::json!(history.1),
        expected["activation"]["profile"]
    );
    assert_eq!(
        (history.0, history.2, history.3, history.4, history.5, history.6, history.7, history.8),
        (1, 1, 0, 0, 2, None, None, 0)
    );
    assert!(tx.query_row("SELECT pending_epoch IS NULL AND pending_plan_digest IS NULL FROM consensus_operator_recovery WHERE singleton = 1", [], |row| row.get::<_, bool>(0)).expect("SQL recovery clear"));
    let applied = quorum_authority_sql_position(&tx, "consensus_applied").expect("SQL applied cut");
    assert_eq!(
        quorum_authority_sql_position(&tx, "consensus_committed"),
        Some(applied)
    );
    let mut receipts = Vec::new();
    let mut records = Vec::new();
    let profile: [u8; 32] = serde_json::from_value(expected["activation"]["profile"].clone())
        .expect("fixed receipt profile");
    let receipt_prefix = |domain: &[u8], id: &[u8]| {
        let mut digest = Sha256::new();
        digest.update(domain);
        digest.update(2_u16.to_be_bytes());
        digest.update(profile);
        digest.update(identity.cluster_id().as_bytes());
        digest.update(identity.configuration_id().as_bytes());
        digest.update(identity.configuration_epoch().get().to_be_bytes());
        digest.update(id);
        digest
    };
    for (index, (request, outcome)) in retained.iter().enumerate() {
        let id = request.request_id().to_bytes();
        let receipt = tx.query_row("SELECT history_epoch, ordinal, configuration_epoch, payload_digest, retained_until, binding_digest, response_json, response_digest FROM consensus_fenced_transition_v2_receipts WHERE request_id = ?1", [id.as_slice()], |row| {
            Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?, row.get::<_, u64>(2)?, row.get::<_, Vec<u8>>(3)?, row.get::<_, String>(4)?, row.get::<_, Vec<u8>>(5)?, row.get::<_, Vec<u8>>(6)?, row.get::<_, Vec<u8>>(7)?))
        }).expect("complete independent SQL receipt");
        assert_eq!((receipt.0, receipt.1, receipt.2), (1, index as u64 + 1, 1));
        assert!(
            receipt.4 == quorum_authority_timestamp(outcome.retained_until()),
            "exact receipt retention differs"
        );
        let payload: [u8; 32] = receipt_prefix(
            b"openpacketcore/session-consensus/fenced-transition-v2/payload/v1\0",
            &id,
        )
        .finalize()
        .into();
        assert_eq!(receipt.3.as_slice(), payload.as_slice());
        let mut binding = receipt_prefix(
            b"openpacketcore/session-consensus/fenced-transition-v2-receipt-binding/v1\0",
            &id,
        );
        binding.update(receipt.0.to_be_bytes());
        binding.update(receipt.1.to_be_bytes());
        binding.update(&receipt.3);
        binding.update((receipt.4.len() as u64).to_be_bytes());
        binding.update(receipt.4.as_bytes());
        let binding: [u8; 32] = binding.finalize().into();
        assert_eq!(receipt.5.as_slice(), binding.as_slice());
        let mut response_digest = Sha256::new();
        response_digest
            .update(b"openpacketcore/session-consensus/fenced-transition-v2-receipt-response/v1\0");
        response_digest.update(&receipt.5);
        response_digest.update((receipt.6.len() as u64).to_be_bytes());
        response_digest.update(&receipt.6);
        let response_digest: [u8; 32] = response_digest.finalize().into();
        assert_eq!(receipt.7.as_slice(), response_digest.as_slice());
        let response = crate::sqlite::consensus::decode_fenced_transition_v2_response(&receipt.6)
            .expect("bounded SQL receipt decoding");
        assert!(
            matches!(&response.result, Ok(crate::consensus::types::SessionMutationOutcome::FencedTransition(found)) if found == outcome),
            "exact SQL outcome differs"
        );
        assert!(response.raft_log_index > 0 && response.raft_log_index <= applied.index);
        assert!(
            crate::sqlite::consensus::encode_fenced_transition_v2_response(&response)
                .expect("bounded canonical response")
                == receipt.6,
            "SQL receipt response is canonical"
        );
        receipts.push(
            Sha256::digest(
                serde_json::to_vec(&(id.as_slice(), &receipt))
                    .expect("complete receipt commitment"),
            )
            .to_vec(),
        );
        let FencedTransitionMutation::Create { record } = request.mutation() else {
            panic!("fixture create");
        };
        let key = &record.key;
        let params = rusqlite::params![
            key.tenant.as_str(),
            key.nf_kind.as_str(),
            key.key_type.as_str(),
            key.stable_id.as_ref()
        ];
        let raw = tx.query_row("SELECT generation, owner, fence, state_class, state_type, expires_at, payload, encoding FROM session_records WHERE tenant = ?1 AND nf_kind = ?2 AND key_type = ?3 AND stable_id = ?4", params, |row| {
            Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?, row.get::<_, u64>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, Option<String>>(5)?, row.get::<_, Vec<u8>>(6)?, row.get::<_, u64>(7)?))
        }).expect("raw SQL stored record");
        assert!(
            raw == (
                record.generation.get(),
                record.owner.as_str().to_owned(),
                record.fence.get(),
                record.state_class.to_string(),
                record.state_type.as_str().to_owned(),
                None,
                record.payload.as_bytes().to_vec(),
                2
            ),
            "complete encrypted SQL record differs"
        );
        assert_eq!(tx.query_row("SELECT fence FROM key_fences WHERE tenant = ?1 AND nf_kind = ?2 AND key_type = ?3 AND stable_id = ?4", params, |row| row.get::<_, u64>(0)).expect("raw SQL fence"), record.fence.get());
        let lease = outcome.lease();
        let stored_lease = tx.query_row("SELECT active, credential_id, owner, fence, expires_at_unix_ms, guard_expires_at, acquired_at FROM leases WHERE tenant = ?1 AND nf_kind = ?2 AND key_type = ?3 AND stable_id = ?4", params, |row| {
            Ok((row.get::<_, bool>(0)?, row.get::<_, u64>(1)?, row.get::<_, String>(2)?, row.get::<_, u64>(3)?, row.get::<_, i64>(4)?, row.get::<_, String>(5)?, row.get::<_, String>(6)?))
        }).expect("complete independent SQL lease");
        assert!(
            stored_lease
                == (
                    true,
                    lease.credential_id(),
                    lease.owner().as_str().to_owned(),
                    lease.fence().get(),
                    (lease
                        .expires_at()
                        .as_offset_datetime()
                        .unix_timestamp_nanos()
                        / 1_000_000) as i64,
                    quorum_authority_timestamp(lease.expires_at()),
                    quorum_authority_timestamp(lease.acquired_at())
                ),
            "complete stored lease differs from the exact result"
        );
        records.push(Sha256::digest(serde_json::to_vec(&raw).expect("record commitment")).to_vec());
    }
    serde_json::json!({"applied": applied, "committed": applied, "receipt_digests": receipts, "record_digests": records})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quorum_authority_native_durable_cut_and_independent_sql_cold_reconstruction() {
    let provider = provider();
    let epoch = FencedTransitionV2HistoryEpoch::new(1).expect("initial history");
    let requests = vec![
        v2_create_request(0, epoch, FenceToken::new(0), &provider).await,
        v2_create_request(1, epoch, FenceToken::new(0), &provider).await,
    ];
    let now = crate::Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000).expect("fixed witness time"),
    );
    let strict_root = std::env::var_os("OPC_FS_VERITY_SNAPSHOT_ROOT")
        .expect("fresh strict snapshot root required");
    let mut snapshots =
        tempfile::tempdir_in(strict_root).expect("independent strict witness namespace");
    snapshots.disable_cleanup(true);
    let mut independent_outcomes = None;
    for native in [false, true] {
        let mut fleet = if native {
            Fleet::new_native("quorum_authority_native")
        } else {
            Fleet::new("quorum_authority_sql")
        };
        fleet.directory.disable_cleanup(true);
        fleet.clock = Some(Arc::new(QuorumAuthorityClock(now)));
        if native {
            fleet.snapshot_root = Some(snapshots.path().to_path_buf());
        }
        let expected = quorum_authority_expected(&fleet.topologies[0]);
        fleet.open().await;
        let result = AssertUnwindSafe(async {
            for store in &fleet.stores {
                assert_eq!(store.inner.private_wal.as_ref().expect("selected owner").is_native(), native);
            }
            let leader = fleet.stores.iter().position(|store| store.status().leader_id == Some(store.status().node_id)).expect("fixture leader");
            let mut retained = Vec::new();
            for request in &requests {
                let effect = fleet.stores[leader].fenced_transition_v2_batch_effect(vec![request.clone()]).await;
                let crate::fenced_transition::FencedTransitionV2Effect::Resolved(Ok(mut outcomes)) = effect else { panic!("healthy typed effect must resolve"); };
                assert_eq!(outcomes.len(), 1);
                let outcome = outcomes.remove(0).expect("healthy exact result");
                assert_v2_create(request, &outcome);
                retained.push((request.clone(), outcome));
            }
            let outcomes = retained.iter().map(|(_, outcome)| outcome.clone()).collect::<Vec<_>>();
            if let Some(expected) = &independent_outcomes {
                assert!(&outcomes == expected, "native outcomes differ from independent SQL execution");
            } else { independent_outcomes = Some(outcomes); }
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            let live = loop {
                let facts = fleet.stores.iter().enumerate().map(|(slot, store)| {
                    if native {
                        store.inner.private_wal.as_ref().expect("native ownership")
                            .native_activation_facts_for_test().expect("bounded raw native facts")
                    } else {
                        let conn = quorum_authority_sql_connection(&fleet.directory.path().join(format!("node-{slot}.sqlite")));
                        let tx = conn.unchecked_transaction().expect("SQL cut observation");
                        serde_json::json!({
                            "durable_committed": quorum_authority_sql_position(&tx, "consensus_committed"),
                            "business": {"applied": quorum_authority_sql_position(&tx, "consensus_applied")},
                        })
                    }
                }).collect::<Vec<_>>();
                let cut = &facts[leader]["business"]["applied"];
                if !cut.is_null() && facts.iter().all(|fact| fact["business"]["applied"] == *cut && fact["durable_committed"] == *cut) {
                    break facts;
                }
                assert!(tokio::time::Instant::now() < deadline, "all-voter exact durable cut deadline: {facts}", facts = serde_json::json!(facts));
                tokio::time::timeout_at(deadline, tokio::time::sleep(Duration::from_millis(10))).await.expect("unchanged cut setup budget");
            };
            let sql = if native {
                for fact in &live {
                    assert_eq!(fact["owner_running"], true);
                    quorum_authority_assert_native(fact, &expected);
                }
                Vec::new()
            } else {
                (0..3).map(|slot| quorum_authority_sql_witness(&fleet.directory.path().join(format!("node-{slot}.sqlite")), &expected, &retained)).collect::<Vec<_>>()
            };
            eprintln!("QUORUM_AUTHORITY_WITNESS {}", serde_json::json!({
                "phase": "all_voters_live_exact_cut", "native": native, "directory": fleet.directory.path(),
                "live": live, "sql": sql,
            }));
            if native {
                // Publish normal authenticated snapshots so the later clean
                // reconstruction must actually read selected cold receipts.
                for (slot, store) in fleet.stores.iter().enumerate() {
                    let before = store.status().completed_snapshot_count;
                    store.inner.raft.trigger().snapshot().await.expect("normal witness snapshot trigger");
                    tokio::time::timeout(Duration::from_secs(30), async {
                        while store.status().completed_snapshot_count == before {
                            assert!(store.inner.raft.metrics().borrow().running_state.is_ok(), "snapshot must keep the voter running");
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }).await.expect("normal strict witness snapshot completed");
                    let selected = store.inner.private_wal.as_ref().expect("native owner")
                        .with_native_read(|state| Ok(state.current_snapshot())).expect("selected snapshot observation")
                        .expect("strict witness selected snapshot");
                    assert!(selected.0.snapshot_id.starts_with("native-"));
                    let after = store.inner.private_wal.as_ref().expect("same native owner")
                        .native_activation_facts_for_test().expect("post-snapshot raw witness");
                    assert_eq!(after, live[slot], "snapshot publication preserves every captured authority/cut/business fact");
                }
            }
            (retained, live, sql)
        }).catch_unwind().await;
        let closed = fleet.close().await;
        let (retained, live, sql) = result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        assert_eq!(
            closed.len(),
            3,
            "every voter and writer joined before cold evidence"
        );
        for (slot, wal) in closed.iter().enumerate() {
            if native {
                let mut expected_cold = live[slot].clone();
                expected_cold["owner_running"] = serde_json::json!(false);
                wal.native_audit_closed(
                    |current, origin| native_flow::admit_native_snapshots(&snapshots.path().join(format!("snapshots-{slot}")), current, origin),
                    native_flow::AdmittedNativeSnapshots::install_source,
                    native_flow::AdmittedNativeSnapshots::verify,
                    |state| {
                        let cold = state.owner_facts_for_test()?;
                        assert_eq!(cold, expected_cold);
                        quorum_authority_assert_native(&cold, &expected);
                        assert_eq!(state.durable_committed(), state.applied());
                        assert_eq!(state.cold_receipt_count_for_test(), retained.len(), "every exact receipt came from selected cold bytes");
                        for (request, outcome) in &retained {
                            assert!(matches!(state.status(request)?, FencedTransitionV2Status::Recorded(found) if found.as_ref() == &Ok(outcome.clone())), "cold exact receipt differs");
                            let FencedTransitionMutation::Create { record } = request.mutation() else { panic!("fixture create"); };
                            assert!(state.get(&record.key).as_ref() == Some(record.as_ref()), "cold encrypted record differs");
                            assert_eq!(state.key_fence_for_test(&record.key), record.fence.get());
                        }
                        Ok(())
                    },
                ).expect("independent joined cold reconstruction with authenticated snapshot admission");
            } else {
                assert_eq!(
                    quorum_authority_sql_witness(
                        &fleet.directory.path().join(format!("node-{slot}.sqlite")),
                        &expected,
                        &retained
                    ),
                    sql[slot]
                );
            }
        }
        eprintln!(
            "QUORUM_AUTHORITY_WITNESS {}",
            serde_json::json!({
                "phase": "joined_cold_reconstruction_exact", "native": native, "voters": closed.len(),
                "directory": fleet.directory.path(), "persistent_fault_injected": false,
            })
        );
    }
}
