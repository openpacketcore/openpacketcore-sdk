//! Native Durable checks for ownership retained by a detached SQLite worker.
//! These isolate worker lifetime after caller cancellation. They do not qualify
//! larger configurations, whole-store shutdown, or unclean restart.

use super::*;
use crate::consensus::{
    ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch, ConfigConsensusConfigurationId,
    ConfigConsensusTopology,
};
use crate::types::ConfigStore;
use crate::{AuditKey, RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions};
use std::collections::BTreeSet;
use std::future::{poll_fn, Future};
use std::task::Poll;
use std::time::Duration;

#[derive(Clone, Copy)]
enum WorkerEntry {
    AbsoluteDeadline,
    Duration,
}

#[tokio::test]
async fn config_capacity_957_cancelled_absolute_worker_retains_native_owner() {
    cancelled_worker_retains_native_owner(WorkerEntry::AbsoluteDeadline).await;
}

#[tokio::test]
async fn config_capacity_957_cancelled_duration_worker_retains_native_owner() {
    cancelled_worker_retains_native_owner(WorkerEntry::Duration).await;
}

async fn cancelled_worker_retains_native_owner(entry: WorkerEntry) {
    let scratch = std::env::var_os("TMPDIR")
        .or_else(|| {
            (std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true"))
                .then(|| std::env::var_os("RUNNER_TEMP"))
                .flatten()
        })
        .expect("explicit disk scratch root");
    let root = tempfile::Builder::new()
        .prefix("config-capacity-worker-")
        .tempdir_in(scratch)
        .expect("private native worker fixture")
        .keep();
    let filesystem = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(&root)
        .output()
        .expect("filesystem detector");
    assert!(filesystem.status.success());
    let filesystem = std::str::from_utf8(&filesystem.stdout)
        .expect("filesystem name")
        .trim();
    assert!(!filesystem.is_empty() && !matches!(filesystem, "tmpfs" | "ramfs"));

    let identity = ConsensusIdentity::new(
        ConfigConsensusClusterId::new("config-capacity-worker-tests").expect("cluster"),
        ConfigConsensusConfigurationId::from_bytes([0x61; 32]),
        ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
    );
    let node = ConsensusNodeId::new(9).expect("node");
    let topology = ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node]))
        .expect("singleton topology");
    let options = RetainedConfigOptions::new(
        root.join("config.sqlite"),
        RetainedConfigBinding::new(topology.clone(), [0x62; 32], [0x63; 32]).expect("binding"),
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        Duration::from_secs(10),
    )
    .expect("native storage limits");
    let key = AuditKey::new([0x64; 32]).expect("synthetic audit key");
    let backend = SqliteBackend::provision_config_authority(options.clone(), key.clone())
        .await
        .expect("native retained authority");
    let (log, state_machine, progress) = open(
        &backend,
        root.join("snapshots"),
        identity,
        topology.members().clone(),
    )
    .await
    .expect("native storage adapters");
    drop(state_machine);
    let core = log.core.clone();
    drop(log);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (cancelled_tx, cancelled_rx) = tokio::sync::oneshot::channel();
    let caller = tokio::spawn(async move {
        let operation =
            move |conn: &rusqlite::Connection,
                  cancellation: &Arc<sqlite::SqliteWorkCancellation>| {
                let count = conn
                    .query_row("SELECT COUNT(*) FROM config_history", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .map_err(|_| sqlite::invalid_data("native worker read failed"))?;
                started_tx
                    .send(count)
                    .map_err(|_| sqlite::invalid_data("native worker start observer dropped"))?;
                // This gate isolates a real blocking worker after its caller drops.
                // Disconnect/timeout terminates setup; neither can count as RED.
                let remaining = deadline
                    .into_std()
                    .saturating_duration_since(std::time::Instant::now());
                release_rx
                    .recv_timeout(remaining)
                    .map_err(|_| sqlite::invalid_data("native worker release gate failed"))?;
                cancelled_tx
                    .send(cancellation.is_cancelled())
                    .map_err(|_| sqlite::invalid_data("native cancellation observer dropped"))?;
                cancellation.check_io()
            };
        match entry {
            WorkerEntry::AbsoluteDeadline => {
                core.run_sqlite_cancellable_until(deadline, operation).await
            }
            WorkerEntry::Duration => {
                core.run_sqlite_with_test_timeout_controlled(Duration::from_secs(10), operation)
                    .await
            }
        }
    });
    assert_eq!(
        tokio::time::timeout_at(deadline, started_rx)
            .await
            .expect("native worker starts inside operation bound")
            .expect("actual worker start signal"),
        0,
        "native read precedes cancellation"
    );
    caller.abort();
    assert!(caller
        .await
        .expect_err("original caller is cancelled")
        .is_cancelled());
    // All core values are now dropped. Only the blocked worker may retain the
    // engine-storage owner; the backend remains separately caller-owned.
    let mut released = Box::pin(progress.wait_for_storage_release());
    let early = poll_fn(|context| {
        let mut probe = tokio::task::unconstrained(released.as_mut());
        Poll::Ready(std::pin::Pin::new(&mut probe).poll(context))
    })
    .await;
    let returned_before_release = early.is_ready();
    release_tx.send(()).expect("release exact original worker");
    match early {
        Poll::Ready(result) => result.expect("observed early owner-release result"),
        Poll::Pending => tokio::time::timeout_at(deadline, released.as_mut())
            .await
            .expect("native worker owner released inside operation bound")
            .expect("complete storage-owner release"),
    }
    drop(released);
    assert!(
        tokio::time::timeout_at(deadline, cancelled_rx)
            .await
            .expect("original worker reports cancellation")
            .expect("actual cancellation observation"),
        "cancelled caller reaches the actual SQLite cancellation guard"
    );
    // Drain the real worker connection even under the omission mutation before
    // checking the intended rejection. This read makes no shutdown claim.
    {
        let connection = tokio::time::timeout_at(deadline, backend.conn().lock_owned())
            .await
            .expect("original worker releases native connection");
        for table in [
            "config_history",
            "audit_trail",
            "config_raft_log",
            "config_raft_request_outcomes",
        ] {
            let count = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("unchanged native effects");
            assert_eq!(count, 0, "read-only cancelled worker leaves no effects");
        }
    }
    assert!(
        !returned_before_release,
        "CONFIG_CAPACITY_SQLITE_OWNER_RED: cancelled caller released the owner of a still-blocked native worker"
    );
    drop(progress);
    drop(backend);
    let reopened = SqliteBackend::reopen_config_authority(options, key)
        .await
        .expect("native retained reopen after worker ownership completes");
    assert!(reopened
        .load_latest()
        .await
        .expect("retained native read")
        .is_none());
}
