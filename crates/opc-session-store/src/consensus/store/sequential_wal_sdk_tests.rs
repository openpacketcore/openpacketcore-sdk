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
