//! Real native Durable singleton storage with direct handler injection.
//! This tests profile rejection, not authenticated multi-node transport.

#![cfg(target_os = "linux")]

use super::*;
use crate::{
    AuditKey, ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, ConfigConsensusIdentity, RetainedConfigBinding,
    RetainedConfigDurability, RetainedConfigOptions,
};
use opc_consensus::engine::raft::{AppendEntriesRequest, InstallSnapshotRequest, VoteRequest};
use opc_consensus::engine::{SnapshotMeta, Vote};
use opc_crypto::ConfigCapacityProfile;

async fn native_singleton() -> (ConsensusConfigStore, PathBuf) {
    let scratch = std::env::var_os("TMPDIR")
        .or_else(|| {
            (std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true"))
                .then(|| std::env::var_os("RUNNER_TEMP"))
                .flatten()
        })
        .expect("explicit local or hosted scratch root is required");
    let root = tempfile::Builder::new()
        .prefix("config-capacity-rpc-")
        .tempdir_in(scratch)
        .expect("private retained fixture")
        .keep();
    let filesystem = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(&root)
        .output()
        .expect("filesystem detector required");
    assert!(filesystem.status.success());
    let filesystem = std::str::from_utf8(&filesystem.stdout)
        .expect("filesystem encoding")
        .trim();
    assert!(!filesystem.is_empty() && !matches!(filesystem, "tmpfs" | "ramfs"));
    let node = ConsensusNodeId::new(1).expect("synthetic node");
    let identity = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0xF1; 32]),
        ConfigConsensusConfigurationId::from_bytes([0xF2; 32]),
        ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
    );
    let topology =
        ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node])).expect("topology");
    let binding =
        RetainedConfigBinding::new(topology.clone(), [0xF3; 32], [0xF4; 32]).expect("binding");
    let options = RetainedConfigOptions::new(
        root.join("config.sqlite"),
        binding,
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        Duration::from_secs(10),
    )
    .expect("retained options");
    let backend =
        SqliteBackend::provision_config_authority(options, AuditKey::new([0xF5; 32]).expect("key"))
            .await
            .expect("retained native Durable authority");
    let store =
        ConsensusConfigStore::open(topology, backend, root.join("snapshots"), BTreeMap::new())
            .await
            .expect("open native singleton");
    store
        .initialize_cluster()
        .await
        .expect("initialize singleton");
    store
        .append_attested_commit(super::tests::sized_attested_commit(128))
        .await
        .expect("committed control");
    (store, root)
}

async fn counts(store: &ConsensusConfigStore) -> [i64; 5] {
    let connection = store.inner.backend.conn();
    let connection = connection.lock().await;
    [
        "config_history",
        "audit_trail",
        "config_raft_log",
        "config_raft_request_outcomes",
        "config_raft_snapshot",
    ]
    .map(|table| {
        connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("effect count")
    })
}

async fn rejects_wrong_profile(family: ConsensusRpcFamily) {
    let (store, root) = native_singleton().await;
    let before_record = store
        .load_latest()
        .await
        .expect("control read")
        .expect("head");
    let before_counts = counts(&store).await;
    let before_status = store.status();
    let before_files: BTreeSet<_> = std::fs::read_dir(root.join("snapshots"))
        .expect("snapshot directory")
        .map(|entry| entry.expect("snapshot entry").file_name())
        .collect();
    let sender = store.inner.local_node_id;
    let profile = ConfigCapacityProfile::BoundedV1;
    let vote = Vote::new_committed(before_status.term + 1, sender);
    let payload = match family {
        ConsensusRpcFamily::Vote => encode_config_wire_for_profile(
            profile,
            &VoteRequest {
                vote,
                last_log_id: None,
            },
        ),
        ConsensusRpcFamily::AppendEntries => encode_config_wire_for_profile(
            profile,
            &AppendEntriesRequest::<ConfigRaftTypeConfig> {
                vote,
                prev_log_id: None,
                entries: Vec::new(),
                leader_commit: None,
            },
        ),
        ConsensusRpcFamily::InstallSnapshot => encode_config_wire_for_profile(
            profile,
            &InstallSnapshotRequest::<ConfigRaftTypeConfig> {
                vote,
                meta: SnapshotMeta {
                    last_log_id: None,
                    last_membership: StoredMembership::default(),
                    snapshot_id: "synthetic-profile".into(),
                },
                offset: 0,
                data: vec![0xF6; 32],
                done: false,
            },
        ),
        ConsensusRpcFamily::ForwardMutation => encode_config_wire_for_profile(
            profile,
            &ForwardMutationRequest {
                request_id: opc_consensus::ConsensusRequestId::from_bytes([0xF7; 16]),
                intent: ConfigMutationIntent::CreateRollbackPoint {
                    tx_id: before_record.record.tx_id,
                    label: None,
                },
                compatibility: store.peer_compatibility(),
                budget: ForwardedBudget {
                    remaining_nanos: 2_000_000_000,
                },
            },
        ),
        ConsensusRpcFamily::ReadBarrier => encode_config_wire_for_profile(
            profile,
            &ReadBarrierRequest {
                compatibility: store.peer_compatibility(),
                compatibility_probe: true,
                budget: ForwardedBudget {
                    remaining_nanos: 2_000_000_000,
                },
            },
        ),
        _ => panic!("unsupported fixture family"),
    }
    .expect("complete mismatched-profile RPC");
    let response = store
        .rpc_handler()
        .handle(
            sender,
            ConsensusWireRequest::try_new(store.inner.identity, sender, family, payload)
                .expect("valid outer scope"),
        )
        .await;
    assert!(
        matches!(response.result, Err(ConsensusPeerError::Protocol)),
        "profile rejection must precede engine or proposal effects"
    );
    assert_eq!(
        counts(&store).await,
        before_counts,
        "observed durable effect counts unchanged"
    );
    let after_status = store.status();
    assert_eq!(
        after_status.term, before_status.term,
        "wrong profile cannot change the vote term"
    );
    assert_eq!(after_status.applied_index, before_status.applied_index);
    assert_eq!(after_status.committed_index, before_status.committed_index);
    let after_record = store
        .load_latest()
        .await
        .expect("retained read")
        .expect("head");
    assert!(
        after_record.record == before_record.record,
        "exact committed record unchanged"
    );
    let after_files: BTreeSet<_> = std::fs::read_dir(root.join("snapshots"))
        .expect("snapshot directory")
        .map(|entry| entry.expect("snapshot entry").file_name())
        .collect();
    assert!(
        after_files == before_files,
        "wrong profile cannot start snapshot staging"
    );
    store.shutdown().await.expect("shutdown fixture");
}

#[tokio::test]
async fn capacity_profile_vote_rejects_before_effects() {
    rejects_wrong_profile(ConsensusRpcFamily::Vote).await;
}
#[tokio::test]
async fn capacity_profile_append_rejects_before_effects() {
    rejects_wrong_profile(ConsensusRpcFamily::AppendEntries).await;
}
#[tokio::test]
async fn capacity_profile_snapshot_rejects_before_effects() {
    rejects_wrong_profile(ConsensusRpcFamily::InstallSnapshot).await;
}
#[tokio::test]
async fn capacity_profile_forward_rejects_before_effects() {
    rejects_wrong_profile(ConsensusRpcFamily::ForwardMutation).await;
}
#[tokio::test]
async fn capacity_profile_read_barrier_rejects_before_effects() {
    rejects_wrong_profile(ConsensusRpcFamily::ReadBarrier).await;
}
