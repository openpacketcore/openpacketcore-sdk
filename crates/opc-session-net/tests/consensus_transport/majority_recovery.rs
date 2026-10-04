//! Retained-root restart acceptance over the production mutual-TLS adapter.

use std::panic::AssertUnwindSafe;

use futures_util::{future::join_all, FutureExt};
use opc_session_net::SessionConsensusServerHandle;
use opc_session_store::{
    Clock, SessionPersistenceMode, SnapshotIntegrityPolicy, StoreError,
    DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
};
use opc_types::Timestamp;

use super::*;

// Lease expiry is a scenario input, not an extra one-second disk-performance
// requirement on initial setup. Raft timers and operation deadlines stay real.
#[derive(Debug)]
struct LeaseClock(StdMutex<Timestamp>);

impl Clock for LeaseClock {
    fn now_utc(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}

struct Fleet {
    directory: tempfile::TempDir,
    pki: TestPki,
    manifest: Arc<SessionReplicationManifest>,
    topologies: Vec<ValidatedQuorumTopology>,
    addresses: Vec<Arc<StdRwLock<Option<SocketAddr>>>>,
    stores: Vec<Option<ConsensusSessionStore>>,
    servers: Vec<Option<SessionConsensusServerHandle>>,
    mode: SessionPersistenceMode,
    clock: Arc<LeaseClock>,
}

impl Fleet {
    fn new(mode: SessionPersistenceMode) -> Self {
        let manifest = manifest("majority-recovery", 1, 1);
        let members = (1..=3)
            .map(|replica| descriptor(replica, 1))
            .collect::<Vec<_>>();
        let topologies = (1..=3)
            .map(|replica| {
                ValidatedQuorumTopology::try_from_fixed_durable_quorum(
                    QuorumTopologyConfig::new_consensus(
                        replica_id(replica),
                        members.clone(),
                        manifest.fixed_durable_quorum_consensus_identity(),
                    ),
                )
                .expect("fixed topology")
            })
            .collect();
        Self {
            directory: tempfile::tempdir().expect("private disk-backed fixture"),
            pki: TestPki::new(),
            manifest,
            topologies,
            addresses: (0..3).map(|_| Arc::new(StdRwLock::new(None))).collect(),
            stores: vec![None; 3],
            servers: (0..3).map(|_| None).collect(),
            mode,
            clock: Arc::new(LeaseClock(StdMutex::new(Timestamp::now_utc()))),
        }
    }

    fn store(&self, index: usize) -> &ConsensusSessionStore {
        self.stores[index].as_ref().expect("running fixture voter")
    }

    async fn open(&mut self, index: usize) {
        assert!(self.stores[index].is_none());
        let replica = u16::try_from(index + 1).expect("fixture member");
        let local = self
            .manifest
            .bind_fixed_durable_quorum_local(replica_id(replica))
            .expect("fixed authenticated binding");
        let peers = (0..3)
            .filter(|target| *target != index)
            .map(|target| {
                let remote = local
                    .bind_remote(replica_id(u16::try_from(target + 1).unwrap()))
                    .expect("fixed authenticated peer");
                let node = remote.remote_consensus_node_id();
                let peer = RemoteSessionConsensusPeer::new_profiled_with_resolver(
                    remote,
                    deferred_resolver(
                        Arc::clone(&self.addresses[target]),
                        Arc::new(AtomicBool::new(true)),
                    ),
                    self.pki.client_config(replica),
                );
                (node, Arc::new(peer) as Arc<dyn SessionConsensusPeer>)
            })
            .collect();
        let store = ConsensusSessionStore::open_fixed_quorum_with_clock_and_persistence(
            self.topologies[index].clone(),
            SqliteSessionBackend::open(self.directory.path().join(format!("voter-{index}.sqlite")))
                .expect("retained database"),
            self.directory.path().join(format!("snapshots-{index}")),
            peers,
            self.clock.clone(),
            DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
            SnapshotIntegrityPolicy::PortableVerified,
            self.mode,
        )
        .await
        .expect("open retained fixed root");
        let (server, address) = SessionConsensusServer::new(
            store.rpc_handler(),
            self.pki.server_config(replica),
            local,
        )
        .listen("127.0.0.1:0".parse().unwrap())
        .await
        .expect("mTLS listener");
        *self.addresses[index].write().unwrap() = Some(address);
        self.servers[index] = Some(server);
        self.stores[index] = Some(store);
    }

    async fn close(&mut self, index: usize) {
        *self.addresses[index].write().unwrap() = None;
        if let Some(server) = self.servers[index].take() {
            server.abort_and_wait().await;
        }
        if let Some(store) = self.stores[index].take() {
            store
                .shutdown()
                .await
                .expect("join storage and engine owner");
        }
    }

    async fn admit(&self) -> bool {
        let deadline = tokio::time::Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
        loop {
            let initialized = join_all(
                self.stores
                    .iter()
                    .flatten()
                    .map(ConsensusSessionStore::initialize_cluster),
            )
            .await;
            if initialized.iter().all(Result::is_ok) {
                let ready = join_all(
                    self.stores
                        .iter()
                        .flatten()
                        .map(ConsensusSessionStore::probe_fixed_quorum_readiness),
                )
                .await;
                if ready
                    .iter()
                    .all(|report| report.traffic_authority().is_granted())
                {
                    return true;
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn absence(&self, authority: OldAuthority) {
        tokio::time::sleep(Duration::from_millis(1200)).await;
        if matches!(authority, OldAuthority::Expired) {
            let mut time = self.clock.0.lock().unwrap();
            *time = Timestamp::from_offset_datetime(
                *time.as_offset_datetime() + time::Duration::milliseconds(1200),
            );
        }
    }
}

#[derive(Clone, Copy)]
enum Restart {
    Sequential,
    Majority,
    AllCold,
}

#[derive(Clone, Copy)]
enum OldAuthority {
    Expired,
    Revoked,
}

async fn retained_roots_return(
    mode: SessionPersistenceMode,
    restart: Restart,
    authority: OldAuthority,
) {
    let mut fleet = Fleet::new(mode);
    let result = AssertUnwindSafe(async {
        for index in 0..3 {
            fleet.open(index).await;
        }
        assert!(fleet.admit().await, "initial fixed quorum must be usable");
        let survivor = (0..3)
            .find(|index| {
                let status = fleet.store(*index).status();
                status.leader_id == Some(status.node_id)
            })
            .expect("initial leader");
        let original = fleet.store(survivor).clone();
        let key = restore_key(b"majority-recovery");
        let provider = MemoryKeyProvider::new();
        provider
            .insert_active_key(
                KeyId::new("majority-recovery-key").unwrap(),
                KeyPurpose::Session,
                key.tenant.clone(),
                Zeroizing::new([0x47; AES_256_GCM_SIV_KEY_LEN]),
            )
            .unwrap();
        let old = original
            .acquire(
                &key,
                OwnerId::new("before-restart").unwrap(),
                Duration::from_secs(1),
            )
            .await
            .expect("initial authority");
        let mut before = restore_record(key.clone(), &old, b"before restart");
        before.payload = EncryptedSessionPayload::encrypt(&provider, &before, "majority-recovery")
            .await
            .unwrap();
        assert_eq!(
            original
                .compare_and_set(CompareAndSet {
                    key: key.clone(),
                    lease: old.clone(),
                    expected_generation: None,
                    new_record: before,
                })
                .await
                .unwrap(),
            CompareAndSetResult::Success
        );
        if matches!(authority, OldAuthority::Revoked) {
            original
                .release(old.clone())
                .await
                .expect("revoke the still-unexpired predecessor");
        }
        if mode == SessionPersistenceMode::Async {
            for store in fleet.stores.iter().flatten() {
                store
                    .drain_async_persistence()
                    .await
                    .expect("fully persisted baseline");
            }
        }
        // A retired store clone still owns its backing handle. Keep the
        // original handle only in the scenario that preserves that process.
        let original = if matches!(restart, Restart::Majority) {
            Some(original)
        } else {
            drop(original);
            None
        };
        match restart {
            Restart::Sequential => {
                for index in 0..3 {
                    fleet.close(index).await;
                    fleet.open(index).await;
                    assert!(
                        fleet.admit().await,
                        "each sequential return must recover authority"
                    );
                }
                fleet.absence(authority).await;
            }
            Restart::Majority | Restart::AllCold => {
                let returning = (0..3)
                    .filter(|index| matches!(restart, Restart::AllCold) || *index != survivor)
                    .collect::<Vec<_>>();
                for index in &returning {
                    fleet.close(*index).await;
                }
                fleet.absence(authority).await;
                if let Some(original) = &original {
                    assert!(
                        !original
                            .probe_fixed_quorum_readiness()
                            .await
                            .traffic_authority()
                            .is_granted(),
                        "absence of a majority must withhold fresh quorum authority"
                    );
                } else {
                    assert!(fleet.stores.iter().all(Option::is_none));
                }
                for index in &returning {
                    fleet.open(*index).await;
                }
                assert!(
                    fleet.admit().await,
                    "retained voter return must recover safe usable authority"
                );
                if let Some(original) = &original {
                    assert!(
                        original.persistence_health().engine_running,
                        "the original survivor must remain in the same engine incarnation"
                    );
                }
            }
        }
        let recovered = fleet.store(survivor);
        let next = recovered
            .acquire(
                &key,
                OwnerId::new("after-restart").unwrap(),
                Duration::from_secs(60),
            )
            .await
            .expect("subsequent authority acquisition");
        assert!(
            next.fence() > old.fence(),
            "recovery cannot reuse an issued fence"
        );
        let mut after = restore_record(key.clone(), &next, b"after restart");
        after.generation = Generation::new(2);
        after.payload = EncryptedSessionPayload::encrypt(&provider, &after, "majority-recovery")
            .await
            .unwrap();
        assert_eq!(
            recovered
                .compare_and_set(CompareAndSet {
                    key: key.clone(),
                    lease: next,
                    expected_generation: Some(Generation::new(1)),
                    new_record: after.clone(),
                })
                .await
                .unwrap(),
            CompareAndSetResult::Success
        );
        let expected = match authority {
            OldAuthority::Expired => {
                assert!(old.expires_at() <= fleet.clock.now_utc());
                StoreError::LeaseExpired
            }
            OldAuthority::Revoked => {
                assert!(old.expires_at() > fleet.clock.now_utc());
                StoreError::StaleFence
            }
        };
        assert_eq!(
            recovered.delete_fenced(&old).await,
            Err(expected),
            "old authority must be rejected explicitly while the successor is usable"
        );
        assert!(
            recovered
                .get(&key)
                .await
                .unwrap()
                .is_some_and(|record| record == after),
            "successor operation must survive stale-owner rejection"
        );
    })
    .catch_unwind()
    .await;
    for index in 0..3 {
        fleet.close(index).await;
    }
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[test]
fn async_two_of_three_retained_roots_recover_over_mtls() {
    run_openraft_fleet_test(
        4,
        retained_roots_return(
            SessionPersistenceMode::Async,
            Restart::Majority,
            OldAuthority::Expired,
        ),
    );
}

#[test]
fn durable_two_of_three_retained_roots_recover_over_mtls() {
    run_openraft_fleet_test(
        4,
        retained_roots_return(
            SessionPersistenceMode::Durable,
            Restart::Majority,
            OldAuthority::Expired,
        ),
    );
}

#[test]
fn async_sequential_retained_roots_recover_over_mtls() {
    run_openraft_fleet_test(
        4,
        retained_roots_return(
            SessionPersistenceMode::Async,
            Restart::Sequential,
            OldAuthority::Expired,
        ),
    );
}

#[test]
fn async_all_cold_retained_roots_recover_over_mtls() {
    run_openraft_fleet_test(
        4,
        retained_roots_return(
            SessionPersistenceMode::Async,
            Restart::AllCold,
            OldAuthority::Expired,
        ),
    );
}

#[test]
fn durable_all_cold_retained_roots_recover_over_mtls() {
    run_openraft_fleet_test(
        4,
        retained_roots_return(
            SessionPersistenceMode::Durable,
            Restart::AllCold,
            OldAuthority::Expired,
        ),
    );
}

#[test]
fn async_majority_restart_preserves_unexpired_credential_revocation_over_mtls() {
    run_openraft_fleet_test(
        4,
        retained_roots_return(
            SessionPersistenceMode::Async,
            Restart::Majority,
            OldAuthority::Revoked,
        ),
    );
}

#[test]
fn async_all_cold_restart_preserves_unexpired_credential_revocation_over_mtls() {
    run_openraft_fleet_test(
        4,
        retained_roots_return(
            SessionPersistenceMode::Async,
            Restart::AllCold,
            OldAuthority::Revoked,
        ),
    );
}
