//! Real snapshot transfer and restoration for the bounded ordinary profile.

use super::*;
use opc_consensus::engine::error::{InstallSnapshotError, RaftError};
use opc_consensus::engine::raft::InstallSnapshotResponse;
use opc_consensus::engine::{EmptyNode, SnapshotMeta, Vote};
use opc_persist::{ConfigHistoryLimits, ConfigHistoryRetention};
use opc_session_net::SessionConsensusServerHandle;
use rusqlite::OptionalExtension;
use serde::Deserialize;

type Meta = SnapshotMeta<ConsensusNodeId, EmptyNode>;
type SnapshotReply = Result<
    InstallSnapshotResponse<ConsensusNodeId>,
    RaftError<ConsensusNodeId, InstallSnapshotError>,
>;

#[derive(Deserialize)]
struct Wire<T> {
    revision: u16,
    value: T,
}

// Match the public engine request's field order without depending on the
// persistence crate's private Raft application type. This is observation only;
// the original request still passes through the production transport unchanged.
#[derive(Deserialize)]
struct Chunk {
    vote: Vote<ConsensusNodeId>,
    meta: Meta,
    offset: u64,
    data: Vec<u8>,
    done: bool,
}

pub(super) struct PendingChunk {
    vote: Vote<ConsensusNodeId>,
    snapshot: [u8; 32],
    offset: u64,
    bytes: usize,
    digest: [u8; 32],
    done: bool,
}

#[derive(Debug, Default)]
struct Transfer {
    chunks: BTreeMap<u64, (usize, [u8; 32])>,
    total: Option<u64>,
}

#[derive(Debug, Default)]
pub(super) struct Observation {
    pub(super) enabled: AtomicBool,
    transfers: Mutex<BTreeMap<[u8; 32], Transfer>>,
}

impl Observation {
    pub(super) fn capture(&self, request: &ConsensusWireRequest) -> Option<PendingChunk> {
        if !self.enabled.load(Ordering::SeqCst)
            || request.family != ConsensusRpcFamily::InstallSnapshot
        {
            return None;
        }
        let chunk: Wire<Chunk> =
            opc_consensus::decode_bounded(&request.payload).expect("bounded snapshot observation");
        assert_eq!(chunk.revision, 8);
        assert!(
            chunk.value.data.len() as u64
                <= opc_consensus::DURABLE_OPENRAFT_PROFILE.snapshot_chunk_bytes
        );
        Some(PendingChunk {
            vote: chunk.value.vote,
            snapshot: Sha256::digest(chunk.value.meta.snapshot_id.as_bytes()).into(),
            offset: chunk.value.offset,
            bytes: chunk.value.data.len(),
            digest: Sha256::digest(&chunk.value.data).into(),
            done: chunk.value.done,
        })
    }

    pub(super) fn record(&self, chunk: PendingChunk, response: &ConsensusWireResponse) {
        let Ok(payload) = &response.result else {
            return;
        };
        let reply: Wire<SnapshotReply> =
            opc_consensus::decode_bounded(payload).expect("authenticated snapshot reply");
        assert_eq!(reply.revision, 8);
        let Ok(reply) = reply.value else {
            return;
        };
        if reply.vote != chunk.vote {
            return;
        }
        let mut transfers = self.transfers.lock().expect("snapshot observation lock");
        let transfer = transfers.entry(chunk.snapshot).or_default();
        let value = (chunk.bytes, chunk.digest);
        if let Some(previous) = transfer.chunks.insert(chunk.offset, value) {
            assert!(
                previous == value,
                "repeated chunk preserves the exact bytes"
            );
        }
        if chunk.done {
            let total = chunk
                .offset
                .checked_add(chunk.bytes as u64)
                .expect("bounded final offset");
            if let Some(previous) = transfer.total.replace(total) {
                assert_eq!(previous, total, "repeated final chunk preserves length");
            }
        }
    }

    pub(super) fn complete(&self, snapshot: [u8; 32], length: u64) -> Option<usize> {
        let transfers = self.transfers.lock().expect("snapshot observation lock");
        let transfer = transfers.get(&snapshot)?;
        if transfer.total != Some(length) || transfer.chunks.len() < 2 {
            return None;
        }
        let mut expected = 0;
        for (offset, (bytes, _)) in &transfer.chunks {
            if *offset != expected {
                return None;
            }
            expected = expected.checked_add(*bytes as u64)?;
        }
        (expected == length).then_some(transfer.chunks.len())
    }
}

fn read_only(database: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("read-only retained state observation")
}

pub(super) fn purged_beyond(database: &Path, index: u64) -> bool {
    read_only(database)
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM config_raft_purged WHERE log_index > ?1)",
            [index],
            |row| row.get(0),
        )
        .expect("production purged prefix observation")
}

pub(super) fn current_snapshot(database: &Path) -> Option<([u8; 32], u64)> {
    let row: Option<(Vec<u8>, u64)> = read_only(database)
        .query_row(
            "SELECT meta_json, byte_length FROM config_raft_snapshot WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .expect("production installed snapshot observation");
    row.map(|(bytes, length)| {
        let meta: Meta = serde_json::from_slice(&bytes).expect("stored engine snapshot metadata");
        (Sha256::digest(meta.snapshot_id.as_bytes()).into(), length)
    })
}

pub(super) fn authority_counts(databases: &[PathBuf; 3]) -> [[i64; 3]; 3] {
    std::array::from_fn(|index| {
        let counts = effect_counts(&databases[index]);
        [counts[0], counts[1], counts[3]]
    })
}

type Listeners = (
    Vec<Option<SessionConsensusServerHandle>>,
    Vec<tokio::sync::oneshot::Receiver<()>>,
);

pub(super) async fn listen(
    stores: &[ConsensusConfigStore],
    pki: &Pki,
    manifest: &Arc<SessionReplicationManifest>,
    addresses: &[Arc<RwLock<Option<SocketAddr>>>; 3],
) -> Listeners {
    let mut servers = Vec::new();
    let mut released_handlers = Vec::new();
    for source in 0..3 {
        let (handler, released) = observed_handler(&stores[source]);
        released_handlers.push(released);
        let (server, address) = SessionConsensusServer::new(
            handler,
            pki.server(source),
            manifest
                .bind_local(replica_id(source))
                .expect("original snapshot voter binding"),
        )
        .listen("127.0.0.1:0".parse().expect("loopback socket"))
        .await
        .expect("real snapshot mTLS listener");
        *addresses[source]
            .write()
            .expect("snapshot listener address") = Some(address);
        servers.push(Some(server));
    }
    (servers, released_handlers)
}

pub(super) async fn ready(stores: &[ConsensusConfigStore]) {
    tokio::time::timeout(DURABLE_CONSENSUS_OPERATION_TIMEOUT, async {
        let (a, b, c) = tokio::join!(
            stores[0].initialize_cluster(),
            stores[1].initialize_cluster(),
            stores[2].initialize_cluster(),
        );
        a.expect("first snapshot voter admission");
        b.expect("second snapshot voter admission");
        c.expect("third snapshot voter admission");
        let (a, b, c) = tokio::join!(
            stores[0].probe_durable_readiness(),
            stores[1].probe_durable_readiness(),
            stores[2].probe_durable_readiness(),
        );
        a.expect("first snapshot voter ready");
        b.expect("second snapshot voter ready");
        c.expect("third snapshot voter ready");
    })
    .await
    .expect("snapshot voter admission inside original operation budget");
}

pub(super) async fn stop(
    stores: Vec<ConsensusConfigStore>,
    servers: Vec<Option<SessionConsensusServerHandle>>,
    released_handlers: Vec<tokio::sync::oneshot::Receiver<()>>,
    addresses: &[Arc<RwLock<Option<SocketAddr>>>; 3],
) {
    for (store, server) in stores.iter().zip(servers) {
        if let Some(server) = server {
            server.abort_and_wait().await;
            store.shutdown().await.expect("stop snapshot voter");
        }
    }
    all_handlers_released(released_handlers).await;
    drop(stores);
    for address in addresses {
        *address.write().expect("retire snapshot listener") = None;
    }
}

async fn recover_exact(
    stores: &[ConsensusConfigStore],
    handle: &ConfigCommitRecoveryHandle,
    expected: &CommitRecord,
    aad: &EnvelopeAad,
    plaintext: &[u8],
) {
    for store in stores {
        assert!(
            matches!(
                store
                    .lookup_commit_operation(handle, CALLER)
                    .await
                    .expect("read-only original snapshot operation recovery"),
                ConfigCommitRecoveryOutcome::Committed
            ),
            "CONFIG_CAPACITY_SNAPSHOT_RECOVERY_RED: exact original result survives snapshot"
        );
        let readback = store
            .load_latest()
            .await
            .expect("snapshot-backed quorum read")
            .expect("snapshot-backed configuration");
        assert!(
            readback.record == *expected,
            "complete snapshot-backed record"
        );
        assert_decrypted(&readback.record, aad, plaintext);
    }
}

native_case!(
    config_capacity_957_at_limit_snapshot_transfer_restore_and_exact_recovery,
    {
        let profile = ConfigCapacityProfile::BoundedV1;
        let directory = disk_fixture();
        let pki = Pki::new();
        let manifest = manifest();
        let addresses = [0, 1, 2].map(|_| Arc::new(RwLock::new(None)));
        let faults = [0, 1, 2].map(|_| Arc::new(Fault::default()));
        let databases = [0, 1, 2].map(|index| directory.join(format!("config-{index}.sqlite")));
        let stores = open_members(
            &directory, &manifest, &pki, &addresses, &faults, false, profile,
        )
        .await;
        let (mut servers, released_handlers) = listen(&stores, &pki, &manifest, &addresses).await;
        ready(&stores).await;
        let leader_id = stores[0].status().leader_id.expect("snapshot leader");
        let leader = stores
            .iter()
            .position(|store| store.status().node_id == leader_id)
            .expect("snapshot leader membership");
        let follower = (leader + 1) % 3;
        let lagging = (leader + 2) % 3;

        let (first, _, _) = commit(&stores[leader], 1, None).await;
        let parent = first.record().tx_id;
        let first = stores[leader]
            .prepare_recoverable_commit(
                ConfigConsensusRequestId::from_bytes([0xE7; 16]),
                first,
                CALLER,
            )
            .expect("snapshot leader-local preparation");
        stores[leader]
            .append_prepared_commit_local(first)
            .await
            .expect("snapshot leader-local at-limit commit");
        let (second, aad, plaintext) = commit(&stores[follower], 2, Some(parent)).await;
        let expected = second.record().clone();
        let second = stores[follower]
            .prepare_recoverable_commit(
                ConfigConsensusRequestId::from_bytes([0xE8; 16]),
                second,
                CALLER,
            )
            .expect("snapshot forwarded preparation");
        let retained_handle = second.recovery_handle().as_bytes().to_vec();
        stores[follower]
            .append_prepared_commit(second)
            .await
            .expect("snapshot forwarded at-limit commit");
        let handle = ConfigCommitRecoveryHandle::from_bytes(&retained_handle)
            .expect("original snapshot operation handle");
        recover_exact(&stores, &handle, &expected, &aad, &plaintext).await;
        assert_eq!(faults[follower].actual_forwards.load(Ordering::SeqCst), 1);
        assert!(current_snapshot(&databases[lagging]).is_none());

        servers[lagging]
            .take()
            .expect("lagging listener")
            .abort_and_wait()
            .await;
        stores[lagging]
            .shutdown()
            .await
            .expect("stop lagging voter on its original storage");
        *addresses[lagging].write().expect("retire lagging listener") = None;
        let lagging_index = stores[lagging]
            .status()
            .applied_index
            .expect("lagging voter original applied prefix");
        let lagging_counts = effect_counts(&databases[lagging]);

        let retention = ConfigHistoryRetention::new(
            expected.tx_id,
            ConfigVersion::new(2),
            ConfigVersion::new(1),
            ConfigVersion::new(1),
            ConfigHistoryLimits::new(2, 16 * 1024 * 1024).expect("bounded two-record history"),
        )
        .expect("exact-head no-pruning retention decision");
        let retention_id = ConfigConsensusRequestId::from_bytes([0xE9; 16]);
        // Replaying this one acknowledged decision advances real native Raft logs
        // without adding large configurations or changing the retained-log budget.
        let engine_profile = opc_consensus::durable_openraft_config(
            opc_consensus::DurableOpenraftDomain::ConfigurationState,
        )
        .expect("unchanged production snapshot and purge profile");
        let advance =
            engine_profile.max_in_snapshot_log_to_keep + engine_profile.purge_batch_size + 16;
        assert!(
            advance < 4096 - 4,
            "original result stays inside its recovery window"
        );
        for _ in 0..advance {
            stores[leader]
                .retain_history_idempotent(retention_id, retention.clone())
                .await
                .expect("same retention decision advances real committed log");
        }
        for index in [leader, follower] {
            stores[index]
                .probe_durable_readiness()
                .await
                .expect("surviving snapshot voter applied prefix");
            stores[index]
                .trigger_snapshot()
                .await
                .expect("production snapshot trigger");
        }
        tokio::time::timeout(DURABLE_CONSENSUS_OPERATION_TIMEOUT, async {
            loop {
                if [leader, follower]
                    .iter()
                    .all(|index| purged_beyond(&databases[*index], lagging_index))
                {
                    break;
                }
                // Use the real event-driven read barrier while compaction finishes.
                // No sleep or production deadline adjustment is used by the fixture.
                stores[leader]
                    .probe_durable_readiness()
                    .await
                    .expect("quorum remains available during production compaction");
            }
        })
        .await
        .expect("both production snapshots purge beyond the offline voter");
        assert_eq!(effect_counts(&databases[lagging]), lagging_counts);
        assert!(current_snapshot(&databases[lagging]).is_none());
        let before_reopen = authority_counts(&databases);
        assert_ne!(before_reopen[lagging], before_reopen[leader]);
        stop(stores, servers, released_handlers, &addresses).await;

        // Read original retained state before any listener or transport catch-up.
        let stores = open_members(
            &directory, &manifest, &pki, &addresses, &faults, true, profile,
        )
        .await;
        assert_eq!(authority_counts(&databases), before_reopen);
        assert!(current_snapshot(&databases[lagging]).is_none());
        for fault in &faults {
            fault.snapshots[lagging]
                .enabled
                .store(true, Ordering::SeqCst);
        }
        let (servers, released_handlers) = listen(&stores, &pki, &manifest, &addresses).await;
        ready(&stores).await;
        recover_exact(&stores, &handle, &expected, &aad, &plaintext).await;
        let (snapshot, length) = current_snapshot(&databases[lagging])
            .expect("lagging original store installed a production snapshot");
        assert!(length > (2 * BOUNDED_LOGICAL_BYTES) as u64);
        let chunks = tokio::time::timeout(DURABLE_CONSENSUS_OPERATION_TIMEOUT, async {
            loop {
                if let Some(chunks) = faults
                    .iter()
                    .find_map(|fault| fault.snapshots[lagging].complete(snapshot, length))
                {
                    break chunks;
                }
                stores[lagging]
                    .probe_durable_readiness()
                    .await
                    .expect("snapshot recipient remains ready through final acknowledgement");
            }
        })
        .await
        .expect("observed contiguous acknowledged chunks match the installed snapshot");
        let installed_counts = authority_counts(&databases);
        assert!(installed_counts
            .iter()
            .all(|counts| *counts == before_reopen[leader]));
        stop(stores, servers, released_handlers, &addresses).await;

        // Reopen the installed snapshot and every original native authority again.
        // Exact recovery remains read-only and uses the original operation handle.
        let stores = open_members(
            &directory, &manifest, &pki, &addresses, &faults, true, profile,
        )
        .await;
        assert_eq!(authority_counts(&databases), installed_counts);
        assert!(
            current_snapshot(&databases[lagging]) == Some((snapshot, length)),
            "the installed snapshot identity and complete length survive reopen"
        );
        let (servers, released_handlers) = listen(&stores, &pki, &manifest, &addresses).await;
        ready(&stores).await;
        let before_recovery = databases.each_ref().map(|database| effect_counts(database));
        let handle = ConfigCommitRecoveryHandle::from_bytes(&retained_handle)
            .expect("only original retained operation handle");
        recover_exact(&stores, &handle, &expected, &aad, &plaintext).await;
        assert_eq!(
            databases.each_ref().map(|database| effect_counts(database)),
            before_recovery,
            "snapshot restoration and exact lookup preserve all four effect tables"
        );
        assert_eq!(
            faults
                .iter()
                .map(|fault| fault.actual_forwards.load(Ordering::SeqCst))
                .sum::<usize>(),
            1,
            "snapshot transfer and retained restore never resubmit the configuration"
        );
        stop(stores, servers, released_handlers, &addresses).await;
        println!(
        "CONFIG_CAPACITY_SNAPSHOT logical_bytes={} chunks={} installed_bytes={} native_wal=true mtls=true original_paths=true original_handle=true resubmitted=false",
        BOUNDED_LOGICAL_BYTES, chunks, length,
    );
    }
);
