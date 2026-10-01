//! Native Durable follower opened through the public store/profile path.
//! A committed prefix crosses the production apply-page boundary through its
//! actual RPC handler; direct injection is not multi-node or mTLS transport proof.

use super::*;
use crate::consensus::{sqlite, ConfigConsensusTopology};
use crate::types::ConfigStore;
use crate::{
    ConsensusConfigStore, RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions,
    SqliteBackend,
};
use opc_consensus::engine::error::RaftError;
use opc_consensus::engine::raft::AppendEntriesResponse;
use opc_consensus::{
    ConsensusPeer, ConsensusPeerError, ConsensusRpcFamily, ConsensusRpcHandler,
    ConsensusWireRequest, ConsensusWireResponse, DURABLE_CONSENSUS_OPERATION_TIMEOUT,
};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug)]
struct OfflinePeer(ConsensusNodeId);

#[async_trait::async_trait]
impl ConsensusPeer for OfflinePeer {
    fn node_id(&self) -> ConsensusNodeId {
        self.0
    }

    async fn call(
        &self,
        _request: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        Err(ConsensusPeerError::Unavailable)
    }
}

async fn append_prefix(
    handler: &dyn ConsensusRpcHandler,
    sender: ConsensusNodeId,
    request: AppendEntriesRequest<ConfigRaftTypeConfig>,
    deadline: tokio::time::Instant,
) -> bool {
    let payload = encode_config_wire_for_profile(PROFILE, &request).unwrap();
    let wire = ConsensusWireRequest::try_new(
        identity(),
        sender,
        ConsensusRpcFamily::AppendEntries,
        payload,
    )
    .unwrap();
    let response = tokio::time::timeout_at(deadline, handler.handle(sender, wire))
        .await
        .expect("native component call finishes inside existing operation guard");
    let Ok(payload) = response.result else {
        return false;
    };
    let result = crate::consensus::types::decode_config_wire_for_profile::<
        Result<AppendEntriesResponse<ConsensusNodeId>, RaftError<ConsensusNodeId>>,
    >(PROFILE, &payload)
    .expect("native component response framing");
    matches!(result, Ok(AppendEntriesResponse::Success))
}

async fn committed_prefix_crosses_batch_boundary(count: usize) -> usize {
    let scratch = std::env::var_os("TMPDIR").expect("explicit disk scratch root");
    let root = tempfile::Builder::new()
        .prefix("config-capacity-commit-prefix-")
        .tempdir_in(scratch)
        .expect("private native fixture")
        .keep();
    let filesystem = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(&root)
        .output()
        .expect("disk filesystem detector");
    assert!(filesystem.status.success());
    let filesystem = std::str::from_utf8(&filesystem.stdout).unwrap().trim();
    assert!(!filesystem.is_empty() && !matches!(filesystem, "tmpfs" | "ramfs"));
    let local = ConsensusNodeId::new(1).unwrap();
    let leader = ConsensusNodeId::new(2).unwrap();
    let third = ConsensusNodeId::new(3).unwrap();
    let members = BTreeSet::from([local, leader, third]);
    let topology = ConfigConsensusTopology::try_new(identity(), local, members.clone()).unwrap();
    let binding = RetainedConfigBinding::new(topology.clone(), [0xB7; 32], [0xB8; 32])
        .unwrap()
        .with_capacity_profile(PROFILE);
    let options = RetainedConfigOptions::new(
        root.join("config.sqlite"),
        binding,
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        DURABLE_CONSENSUS_OPERATION_TIMEOUT,
    )
    .unwrap();
    let backend = SqliteBackend::provision_config_authority(options, key())
        .await
        .expect("native capacity-bound backend");
    let peers: BTreeMap<_, Arc<dyn ConsensusPeer>> = [leader, third]
        .into_iter()
        .map(|id| (id, Arc::new(OfflinePeer(id)) as Arc<dyn ConsensusPeer>))
        .collect();
    // Consume the production profile selector, rather than repeating the
    // desired page limit in a test-only Openraft configuration.
    let store =
        ConsensusConfigStore::open(topology, backend.clone(), root.join("snapshots"), peers)
            .await
            .expect("public native capacity-bound store");
    assert_eq!(store.capacity_profile(), PROFILE);
    let progress = Arc::clone(&store.inner.durable_progress);
    let raft = store.inner.raft.clone();
    let handler = store.rpc_handler();
    let make_id = |index| LogId::new(CommittedLeaderId::new(1, leader), index);
    let vote = Vote::new_committed(1, leader);
    let deadline = tokio::time::Instant::now() + DURABLE_CONSENSUS_OPERATION_TIMEOUT;
    let membership_entry = Entry {
        log_id: make_id(0),
        payload: EntryPayload::Membership(Membership::new(vec![members], ())),
    };
    assert!(
        append_prefix(
            handler.as_ref(),
            leader,
            AppendEntriesRequest {
                vote,
                prev_log_id: None,
                entries: vec![membership_entry],
                leader_commit: None,
            },
            deadline,
        )
        .await,
        "valid uncommitted membership append"
    );
    let last_index = u64::try_from(count - 1).unwrap();
    let mut first = 1;
    while first < last_index {
        let end = (first + 64).min(last_index);
        let entries = (first..end)
            .map(|index| Entry {
                log_id: make_id(index),
                payload: EntryPayload::Blank,
            })
            .collect();
        assert!(
            append_prefix(
                handler.as_ref(),
                leader,
                AppendEntriesRequest {
                    vote,
                    prev_log_id: Some(make_id(first - 1)),
                    entries,
                    leader_commit: None,
                },
                deadline,
            )
            .await,
            "every small uncommitted replication batch is accepted"
        );
        first = end;
    }
    let last_command = command(128);
    let ConfigMutationIntent::BoundedAppend { commit, .. } = &last_command.intent else {
        unreachable!()
    };
    let expected = commit.record.clone();
    assert!(
        append_prefix(
            handler.as_ref(),
            leader,
            AppendEntriesRequest {
                vote,
                prev_log_id: Some(make_id(last_index - 1)),
                entries: vec![Entry {
                    log_id: make_id(last_index),
                    payload: EntryPayload::Normal(last_command),
                }],
                leader_commit: None,
            },
            deadline,
        )
        .await,
        "genuine encrypted configuration remains an admitted singleton"
    );
    {
        let conn = backend.conn().lock_owned().await;
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM config_raft_log", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, count as i64);
        assert!(sqlite::read_committed_sync(&conn, identity())
            .unwrap()
            .is_none());
        assert!(sqlite::read_applied_sync(&conn, identity())
            .unwrap()
            .is_none());
        assert!(crate::schema::verify_wal_mode(&conn).unwrap());
        assert!(crate::schema::verify_synchronous_extra(&conn).unwrap());
    }
    let mut metrics = raft.metrics();
    let acknowledgement = append_prefix(
        handler.as_ref(),
        leader,
        AppendEntriesRequest {
            vote,
            prev_log_id: Some(make_id(last_index)),
            entries: Vec::new(),
            leader_commit: Some(make_id(last_index)),
        },
        deadline,
    )
    .await;
    let applied = tokio::time::timeout_at(deadline, async {
        loop {
            {
                let observed = metrics.borrow_and_update();
                if observed.last_applied == Some(make_id(last_index)) {
                    break true;
                }
                if observed.running_state.is_err() {
                    break false;
                }
            }
            if metrics.changed().await.is_err() {
                break false;
            }
        }
    })
    .await
    .expect("native apply/fatal observation inside unchanged operation guard");
    assert_eq!(progress.committed_index(), Some(last_index));
    let readback = backend.load_latest().await;
    let exact = matches!(readback, Ok(Some(value)) if value.record == expected);
    eprintln!(
        "config capacity native prefix: entries={count} append_ack={acknowledgement} applied={applied} exact_readback={exact}"
    );
    drop(handler);
    store.shutdown().await.expect("native store owners join");
    drop(store);
    drop(raft);
    drop(metrics);
    progress
        .wait_for_storage_release()
        .await
        .expect("native owners release");
    assert!(
        applied && exact,
        "CONFIG_CAPACITY_COMMITTED_PREFIX: individually admitted native entries must apply across the per-call batch boundary"
    );
    progress
        .native_read_max_entries
        .load(std::sync::atomic::Ordering::Acquire)
}

#[tokio::test]
async fn capacity_native_committed_prefix_at_batch_limit_applies() {
    committed_prefix_crosses_batch_boundary(1024).await;
}

#[tokio::test]
async fn capacity_native_committed_prefix_across_batch_limit_applies() {
    committed_prefix_crosses_batch_boundary(1025).await;
}

// Production apply-read population uses the admitted store profile and its
// unchanged byte target. Observe real native reader output before engine
// ownership; this does not qualify aggregate heap or retained startup replay.
#[tokio::test]
async fn capacity_native_apply_read_at_entry_bound_is_complete() {
    let maximum = committed_prefix_crosses_batch_boundary(64).await;
    assert!(maximum > 0, "native read observation must execute");
    assert!(maximum <= 64, "CONFIG_CAPACITY_NATIVE_READ: load only a bounded apply page while preserving the complete committed prefix");
}

#[tokio::test]
async fn capacity_native_apply_read_over_entry_bound_is_complete() {
    let maximum = committed_prefix_crosses_batch_boundary(65).await;
    assert!(maximum > 0, "native read observation must execute");
    assert!(maximum <= 64, "CONFIG_CAPACITY_NATIVE_READ: load only a bounded apply page while preserving the complete committed prefix");
}
