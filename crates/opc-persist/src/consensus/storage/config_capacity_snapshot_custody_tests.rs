//! Promoted snapshot cleanup must follow the actual SQLite commit decision.
//! Explicitly dropping the storage future isolates runtime-teardown ownership;
//! it does not claim ordinary RPC cancellation aborts Openraft storage work.

use super::*;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::sync::{mpsc, Mutex, OnceLock, Weak};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::consensus::storage) enum Phase {
    BeforeWrite,
    AfterCommit,
}

struct Entered {
    file_name: String,
    cancellation: Arc<sqlite::SqliteWorkCancellation>,
}

struct Signals {
    entered: tokio::sync::oneshot::Sender<Entered>,
    release: mpsc::Receiver<()>,
    resumed: tokio::sync::oneshot::Sender<bool>,
}

pub(in crate::consensus::storage) struct Observer {
    phase: Phase,
    deadline: tokio::time::Instant,
    signals: Mutex<Option<Signals>>,
}

fn observers() -> &'static Mutex<BTreeMap<PathBuf, Weak<Observer>>> {
    static OBSERVERS: OnceLock<Mutex<BTreeMap<PathBuf, Weak<Observer>>>> = OnceLock::new();
    OBSERVERS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(in crate::consensus::storage) fn observer(path: &Path) -> Option<Arc<Observer>> {
    observers()
        .lock()
        .expect("snapshot observer registry")
        .get(path)
        .and_then(Weak::upgrade)
}

pub(in crate::consensus::storage) fn checkpoint(
    observer: &Option<Arc<Observer>>,
    phase: Phase,
    file_name: &str,
    cancellation: &Arc<sqlite::SqliteWorkCancellation>,
) -> io::Result<()> {
    let Some(observer) = observer.as_ref().filter(|observer| observer.phase == phase) else {
        return Ok(());
    };
    let signals = observer
        .signals
        .lock()
        .expect("snapshot observer signals")
        .take()
        .ok_or_else(|| sqlite::invalid_data("snapshot custody checkpoint repeated"))?;
    signals
        .entered
        .send(Entered {
            file_name: file_name.to_owned(),
            cancellation: cancellation.clone(),
        })
        .map_err(|_| sqlite::invalid_data("snapshot custody entry observer dropped"))?;
    let remaining = observer
        .deadline
        .into_std()
        .saturating_duration_since(std::time::Instant::now());
    let released = signals.release.recv_timeout(remaining).is_ok();
    signals
        .resumed
        .send(released)
        .map_err(|_| sqlite::invalid_data("snapshot custody release observer dropped"))?;
    if !released {
        return Err(sqlite::invalid_data("snapshot custody release gate failed"));
    }
    Ok(())
}

struct Pause {
    path: PathBuf,
    phase: Phase,
    deadline: tokio::time::Instant,
    _observer: Arc<Observer>,
    entered: tokio::sync::oneshot::Receiver<Entered>,
    release: Option<mpsc::Sender<()>>,
    resumed: tokio::sync::oneshot::Receiver<bool>,
}

impl Pause {
    fn new(path: &Path, phase: Phase) -> Self {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let (entered_tx, entered) = tokio::sync::oneshot::channel();
        let (release, release_rx) = mpsc::channel();
        let (resumed_tx, resumed) = tokio::sync::oneshot::channel();
        let observer = Arc::new(Observer {
            phase,
            deadline,
            signals: Mutex::new(Some(Signals {
                entered: entered_tx,
                release: release_rx,
                resumed: resumed_tx,
            })),
        });
        assert!(observers()
            .lock()
            .expect("snapshot observer registry")
            .insert(path.to_path_buf(), Arc::downgrade(&observer))
            .is_none());
        Self {
            path: path.to_path_buf(),
            phase,
            deadline,
            _observer: observer,
            entered,
            release: Some(release),
            resumed,
        }
    }
}

impl Drop for Pause {
    fn drop(&mut self) {
        observers()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.path);
    }
}

async fn cancel_and_drain<T>(
    caller: tokio::task::JoinHandle<T>,
    mut pause: Pause,
    progress: &ConfigDurableProgress,
    backend: &SqliteBackend,
) -> String {
    let entered = tokio::time::timeout_at(pause.deadline, &mut pause.entered)
        .await
        .expect("snapshot reaches the bounded worker checkpoint")
        .expect("actual snapshot worker entry signal");
    assert!(
        pause.path.join(&entered.file_name).is_file(),
        "snapshot was promoted before the controlled cancellation"
    );
    caller.abort();
    match tokio::time::timeout_at(pause.deadline, caller)
        .await
        .expect("storage future cancellation completes within the gate bound")
    {
        Err(error) => assert!(error.is_cancelled(), "actual storage future cancellation"),
        Ok(_) => panic!("paused storage future unexpectedly completed"),
    }
    // After a real commit, CancelOnDrop must lose; before the write it must win.
    assert_eq!(
        entered.cancellation.is_cancelled(),
        pause.phase == Phase::BeforeWrite,
        "cancellation observation comes from the original SQLite worker"
    );
    pause
        .release
        .take()
        .expect("exact worker release sender")
        .send(())
        .expect("release original snapshot worker");
    assert!(
        tokio::time::timeout_at(pause.deadline, &mut pause.resumed)
            .await
            .expect("worker acknowledges release within the gate bound")
            .expect("actual worker release acknowledgement"),
        "a gate timeout or disconnect is a setup failure, not a custody regression"
    );
    tokio::time::timeout_at(pause.deadline, progress.wait_for_storage_release())
        .await
        .expect("original worker drains within the gate bound")
        .expect("all storage ownership released");
    // The native connection must also be free before checking the durable result.
    drop(
        tokio::time::timeout_at(pause.deadline, backend.conn().lock_owned())
            .await
            .expect("original SQLite worker releases its connection"),
    );
    entered.file_name
}

#[derive(Clone, Copy)]
enum Operation {
    Build,
    Install,
}

impl Operation {
    fn durable_marker(self) -> &'static str {
        match self {
            Self::Build => "CONFIG_SNAPSHOT_BUILD_CUSTODY_RED",
            Self::Install => "CONFIG_SNAPSHOT_INSTALL_CUSTODY_RED",
        }
    }

    fn cleanup_marker(self) -> &'static str {
        match self {
            Self::Build => "CONFIG_SNAPSHOT_BUILD_PRECOMMIT_CLEANUP",
            Self::Install => "CONFIG_SNAPSHOT_INSTALL_PRECOMMIT_CLEANUP",
        }
    }
}

fn membership_entry() -> Entry<ConfigRaftTypeConfig> {
    Entry {
        log_id: LogId::new(
            CommittedLeaderId::new(1, ConsensusNodeId::new(1).expect("node")),
            0,
        ),
        payload: EntryPayload::Membership(Membership::new(vec![members()], None)),
    }
}

fn directory_entries(path: &Path) -> BTreeSet<OsString> {
    std::fs::read_dir(path)
        .expect("snapshot directory entries")
        .map(|entry| entry.expect("snapshot directory entry").file_name())
        .collect()
}

async fn cancelled_snapshot(operation: Operation, phase: Phase, profile: ConfigCapacityProfile) {
    let mode =
        crate::consensus::RetainedConfigMode::try_from(profile).expect("supported fixture mode");
    let root = disk_fixture();
    let options = options(&root.join("target.sqlite"), profile, 0xA3);
    let backend = match operation {
        Operation::Build => SqliteBackend::provision_config_authority(options.clone(), key()).await,
        Operation::Install => {
            SqliteBackend::provision_config_member_repair(options.clone(), key()).await
        }
    }
    .expect("native Durable authority");
    let snapshot_dir = root.join("target-snapshots");
    let (mut log, mut state_machine, progress) =
        open(&backend, &snapshot_dir, identity(0x92), members())
            .await
            .expect("native snapshot adapters");
    if matches!(operation, Operation::Build) {
        log.core
            .run_sqlite(move |conn| {
                sqlite::append_logs_sync(
                    conn,
                    identity(0x92),
                    &members(),
                    &[membership_entry()],
                    mode,
                )
            })
            .await
            .expect("native membership log");
        log.save_committed(Some(membership_entry().log_id))
            .await
            .expect("durable membership commitment");
        state_machine
            .apply([membership_entry()])
            .await
            .expect("apply committed membership");
    }
    drop(log);
    let before = authority_digest(&backend).await;
    let local_binding = binding(&backend).await;
    let mut expected_files = directory_entries(&snapshot_dir);
    let install = if matches!(operation, Operation::Install) {
        let (source, source_storage, snapshot) = source_snapshot(&root, profile).await;
        let mut incoming = state_machine
            .begin_receiving_snapshot()
            .await
            .expect("native incoming snapshot");
        let mut file = tokio::fs::File::open(snapshot.snapshot.path())
            .await
            .expect("authenticated source snapshot");
        tokio::io::copy(&mut file, incoming.as_mut())
            .await
            .expect("finite synthetic snapshot transfer");
        let meta = snapshot.meta.clone();
        drop(file);
        drop(snapshot);
        drop(source_storage);
        drop(source);
        Some((meta, incoming))
    } else {
        None
    };
    let pause = Pause::new(&state_machine.core.snapshot_binding_path, phase);
    let caller = if let Some((meta, incoming)) = install {
        tokio::spawn(async move { state_machine.install_snapshot(&meta, incoming).await })
    } else {
        let mut builder = state_machine.get_snapshot_builder().await;
        drop(state_machine);
        tokio::spawn(async move { builder.build_snapshot().await.map(|_| ()) })
    };
    let file_name = cancel_and_drain(caller, pause, &progress, &backend).await;
    let current = {
        let connection = backend.conn();
        let connection = connection.lock().await;
        sqlite::read_current_snapshot_sync(&connection, identity(0x92), &members(), mode)
            .expect("read actual native snapshot reference after worker drain")
    };
    let committed_meta = if phase == Phase::AfterCommit {
        let (meta, referenced_file, _, _) =
            current.expect("the paused worker really committed the SQL snapshot reference");
        assert_eq!(referenced_file, file_name);
        assert!(
            snapshot_dir.join(&referenced_file).is_file(),
            "{}: cancelled async owner unlinked the durably referenced snapshot",
            operation.durable_marker()
        );
        assert_eq!(meta.last_log_id, Some(membership_entry().log_id));
        expected_files.insert(OsString::from(referenced_file.as_str()));
        Some(meta)
    } else {
        assert!(
            current.is_none(),
            "cancelled precommit worker created no reference"
        );
        assert_eq!(authority_digest(&backend).await, before);
        assert!(
            !snapshot_dir.join(&file_name).exists(),
            "{}: uncommitted promoted snapshot was not cleaned up",
            operation.cleanup_marker()
        );
        None
    };
    assert_eq!(directory_entries(&snapshot_dir), expected_files);
    assert_eq!(binding(&backend).await, local_binding);
    drop(progress);
    drop(backend);

    let reopened = SqliteBackend::reopen_config_authority(options, key())
        .await
        .expect("native retained reopen after cancelled snapshot owner");
    let mut storage = open(&reopened, &snapshot_dir, identity(0x92), members())
        .await
        .expect("reopen snapshot adapters and authenticated binding");
    let restored = storage
        .1
        .get_current_snapshot()
        .await
        .expect("reopen validates referenced snapshot bytes and footer");
    match committed_meta {
        Some(meta) => {
            let restored = restored.expect("committed snapshot survives native reopen");
            assert_eq!(restored.meta, meta);
            assert_eq!(
                restored.snapshot.path(),
                storage.1.core.snapshot_dir.join(&file_name)
            );
            assert_eq!(
                storage.0.read_committed().await.expect("retained commit"),
                Some(membership_entry().log_id)
            );
            assert_eq!(
                storage.1.applied_state().await.expect("retained apply").0,
                Some(membership_entry().log_id)
            );
        }
        None => {
            assert!(
                restored.is_none(),
                "no uncommitted snapshot appears on reopen"
            );
            assert_eq!(authority_digest(&reopened).await, before);
        }
    }
    assert_eq!(binding(&reopened).await, local_binding);
}

#[tokio::test]
async fn config_capacity_957_snapshot_custody_build_committed_legacy() {
    cancelled_snapshot(
        Operation::Build,
        Phase::AfterCommit,
        ConfigCapacityProfile::Legacy,
    )
    .await;
}

#[tokio::test]
async fn config_capacity_957_snapshot_custody_build_committed_bounded_v1() {
    cancelled_snapshot(
        Operation::Build,
        Phase::AfterCommit,
        ConfigCapacityProfile::BoundedV1,
    )
    .await;
}

#[tokio::test]
async fn config_capacity_957_snapshot_custody_build_precommit_legacy() {
    cancelled_snapshot(
        Operation::Build,
        Phase::BeforeWrite,
        ConfigCapacityProfile::Legacy,
    )
    .await;
}

#[tokio::test]
async fn config_capacity_957_snapshot_custody_build_precommit_bounded_v1() {
    cancelled_snapshot(
        Operation::Build,
        Phase::BeforeWrite,
        ConfigCapacityProfile::BoundedV1,
    )
    .await;
}

#[tokio::test]
async fn config_capacity_957_snapshot_custody_install_committed_legacy() {
    cancelled_snapshot(
        Operation::Install,
        Phase::AfterCommit,
        ConfigCapacityProfile::Legacy,
    )
    .await;
}

#[tokio::test]
async fn config_capacity_957_snapshot_custody_install_committed_bounded_v1() {
    cancelled_snapshot(
        Operation::Install,
        Phase::AfterCommit,
        ConfigCapacityProfile::BoundedV1,
    )
    .await;
}

#[tokio::test]
async fn config_capacity_957_snapshot_custody_install_precommit_legacy() {
    cancelled_snapshot(
        Operation::Install,
        Phase::BeforeWrite,
        ConfigCapacityProfile::Legacy,
    )
    .await;
}

#[tokio::test]
async fn config_capacity_957_snapshot_custody_install_precommit_bounded_v1() {
    cancelled_snapshot(
        Operation::Install,
        Phase::BeforeWrite,
        ConfigCapacityProfile::BoundedV1,
    )
    .await;
}
