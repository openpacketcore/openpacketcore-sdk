//! Native shutdown ownership detector under the unchanged Legacy profile.
//! The existing apply gate holds one real accepted operation. No timing retry,
//! engine replacement, admission unlock or larger-profile claim is involved.

use super::*;
use crate::{AuditKey, RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions};
use std::future::{poll_fn, Future};
use std::task::Poll;

#[tokio::test]
async fn config_capacity_957_shutdown_waits_for_native_state_machine_owner() {
    let scratch = std::env::var_os("TMPDIR")
        .or_else(|| {
            (std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true"))
                .then(|| std::env::var_os("RUNNER_TEMP"))
                .flatten()
        })
        .expect("explicit disk scratch root");
    let root = tempfile::Builder::new()
        .prefix("config-capacity-shutdown-")
        .tempdir_in(scratch)
        .expect("private disk fixture")
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
    let topology = topology();
    let options = RetainedConfigOptions::new(
        root.join("config.sqlite"),
        RetainedConfigBinding::new(topology.clone(), [0x69; 32], [0x6A; 32]).expect("binding"),
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        Duration::from_secs(10),
    )
    .expect("native limits");
    let key = AuditKey::new([0x6B; 32]).expect("audit key");
    let backend = SqliteBackend::provision_config_authority(options.clone(), key.clone())
        .await
        .expect("native retained backend");
    let store =
        ConsensusConfigStore::open(topology, backend, root.join("snapshots"), BTreeMap::new())
            .await
            .expect("legacy native store");
    store
        .initialize_cluster()
        .await
        .expect("initialize singleton");
    let formation_deadline = tokio::time::Instant::now()
        .checked_add(store.inner.operation_timeout)
        .expect("unchanged formation budget");
    store
        .wait_for_known_leader(formation_deadline)
        .await
        .expect("natural singleton leadership");
    assert!(matches!(
        store.local_read_barrier(formation_deadline).await,
        ReadBarrierReply::Ready(_)
    ));

    let commit = sized_attested_commit(32);
    let expected = commit.record().clone();
    let operation = store
        .prepare_recoverable_commit(
            opc_consensus::ConsensusRequestId::from_bytes([0x74; 16]),
            commit,
            &expected.principal,
        )
        .expect("prepare exact ordinary operation");
    let held_apply = Arc::clone(&store.inner.backend.consensus_apply_gate)
        .acquire_owned()
        .await
        .expect("hold this native state-machine apply");
    let metrics = store.inner.raft.metrics();
    let mut entered = store.inner.durable_progress.apply_entered.subscribe();
    let before = metrics
        .borrow()
        .last_log_index
        .expect("initialized native log");
    let deadline = tokio::time::Instant::now() + store.inner.operation_timeout;
    let mut applied = store.inner.durable_progress.subscribe_applied();
    let task_store = store.clone();
    let caller =
        tokio::spawn(async move { task_store.append_prepared_commit_local(operation).await });
    tokio::time::timeout_at(deadline, entered.changed())
        .await
        .expect("accepted operation enters native state machine inside original budget")
        .expect("original apply entry notification");
    let committed = tokio::time::timeout_at(
        deadline,
        store.inner.raft.with_raft_state(|state| state.committed),
    )
    .await
    .expect("read-only core observation inside original budget")
    .expect("live original core")
    .expect("committed native entry");
    assert!(committed.index > before, "exact new entry reached commit");
    assert!(
        metrics
            .borrow()
            .last_applied
            .is_some_and(|log| log.index <= before),
        "held apply has not installed the accepted entry"
    );
    assert!(store
        .inner
        .backend
        .load_latest()
        .await
        .expect("pre-apply read")
        .is_none());
    caller.abort();
    assert!(caller
        .await
        .expect_err("cancelled original caller")
        .is_cancelled());

    // End the core first to isolate its distinct storage-task lifetime. The
    // SDK shutdown is idempotent and still promises to stop engine tasks.
    tokio::time::timeout_at(deadline, store.inner.raft.shutdown())
        .await
        .expect("original core stops inside operation bound")
        .expect("core shutdown");
    let mut shutdown = Box::pin(store.shutdown());
    // A single explicit poll, without cooperative-budget interference, asks
    // whether shutdown has already returned while apply is provably held.
    let early = poll_fn(|context| {
        let mut probe = tokio::task::unconstrained(shutdown.as_mut());
        Poll::Ready(std::pin::Pin::new(&mut probe).poll(context))
    })
    .await;
    let returned_before_release = early.is_ready();
    drop(held_apply);
    match early {
        Poll::Ready(result) => result.expect("observed early shutdown result"),
        Poll::Pending => tokio::time::timeout_at(deadline, shutdown.as_mut())
            .await
            .expect("storage shutdown inside original operation bound")
            .expect("complete store shutdown"),
    }
    drop(shutdown);
    // Drain the held operation even on the old implementation, so the intended
    // rejection assertion cannot abandon a worker or its retained authority.
    tokio::time::timeout_at(deadline, applied.changed())
        .await
        .expect("released native apply completes inside original budget")
        .expect("original apply notification");
    let readback = store
        .inner
        .backend
        .load_latest()
        .await
        .expect("authenticated native readback")
        .expect("accepted record");
    assert!(
        readback.record == expected,
        "exact accepted encrypted record survives"
    );
    assert!(
        !returned_before_release,
        "CONFIG_CAPACITY_SHUTDOWN_OWNER_RED: shutdown returned while native state-machine apply still owned authority"
    );
    drop(entered);
    drop(applied);
    drop(metrics);
    drop(store);
    let reopened = SqliteBackend::reopen_config_authority(options, key)
        .await
        .expect("retained reopen after all engine storage owners finish");
    assert!(
        reopened
            .load_latest()
            .await
            .expect("retained authenticated read")
            .expect("retained accepted record")
            .record
            == expected,
        "accepted record survives native retained reopen"
    );
}
