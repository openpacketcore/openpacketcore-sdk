//! Explicit opt-in for private, real-Raft unit fixtures only.
//!
//! The retained test token supplies the independently remembered basis binding
//! on orderly reopen. It is not a disk selector, migration implementation or
//! production format detector. Ordinary constructors never create this token.

use std::io;
#[cfg(test)]
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(test)]
use std::sync::{Mutex, Weak};
use std::time::Duration;

#[cfg(test)]
use super::super as consensus;
use super::super::SqliteConsensusCore;
use super::{invalid_data, Wal};
#[cfg(test)]
use super::{Binding, IoControl, Limits};

/// Constant-space totals for this writer incarnation. Detailed samples below
/// are recent groups bounded by retained request count; totals never reset at
/// a checkpoint or pretend those samples cover the owner's whole lifetime.
#[derive(Default)]
pub(super) struct FlushCosts {
    groups: u64,
    requests: u64,
    appended_entries: u64,
    sync_calls: u64,
    maximum_group_requests: usize,
    admission_us: u128,
    admission_lock_wait_us: u128,
    projection_us: u128,
    write_us: u128,
    intent_us: u128,
    data_sync_us: u128,
    publication_us: u128,
    queue_wait_us: u128,
    queue_wait_maximum_us: u128,
    submit_to_callback_us: u128,
    write_maximum_us: u128,
    intent_maximum_us: u128,
    data_sync_maximum_us: u128,
    publication_maximum_us: u128,
    slowest_request: SlowestFlushRequest,
}

#[derive(Default)]
struct SlowestFlushRequest {
    operation: &'static str,
    queue_wait_us: u128,
    submit_to_callback_us: u128,
    rollover_us: u128,
    write_us: u128,
    intent_us: u128,
    data_sync_us: u128,
    publication_us: u128,
}

impl SlowestFlushRequest {
    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "operation": self.operation,
            "queue_wait_us": self.queue_wait_us,
            "submit_to_callback_us": self.submit_to_callback_us,
            "rollover_us": self.rollover_us,
            "write_us": self.write_us,
            "intent_us": self.intent_us,
            "data_sync_us": self.data_sync_us,
            "publication_us": self.publication_us,
        })
    }
}

impl FlushCosts {
    pub(super) fn record(&mut self, group: &super::FlushObservation) {
        self.groups += 1;
        self.requests += group.admission.len() as u64;
        self.appended_entries += group
            .admission
            .iter()
            .map(|value| value.entries as u64)
            .sum::<u64>();
        self.sync_calls += group.sync_calls as u64;
        self.maximum_group_requests = self.maximum_group_requests.max(group.admission.len());
        self.admission_us += group
            .admission
            .iter()
            .map(|value| value.total.as_micros())
            .sum::<u128>();
        self.admission_lock_wait_us += group
            .admission
            .iter()
            .map(|value| value.lock_wait.as_micros())
            .sum::<u128>();
        self.projection_us += group
            .admission
            .iter()
            .map(|value| value.projection.as_micros())
            .sum::<u128>();
        self.write_us += group.write.as_micros();
        self.intent_us += group.intent.as_micros();
        self.data_sync_us += group.data_sync.as_micros();
        self.publication_us += group.publication.as_micros();
        self.write_maximum_us = self.write_maximum_us.max(group.write.as_micros());
        self.intent_maximum_us = self.intent_maximum_us.max(group.intent.as_micros());
        self.data_sync_maximum_us = self.data_sync_maximum_us.max(group.data_sync.as_micros());
        self.publication_maximum_us = self
            .publication_maximum_us
            .max(group.publication.as_micros());
        for ((admission, queue_wait), submit_to_callback) in group
            .admission
            .iter()
            .zip(&group.queue_wait)
            .zip(&group.submit_to_callback)
        {
            let queue_wait_us = queue_wait.as_micros();
            let submit_to_callback_us = submit_to_callback.as_micros();
            self.queue_wait_us += queue_wait_us;
            self.queue_wait_maximum_us = self.queue_wait_maximum_us.max(queue_wait_us);
            self.submit_to_callback_us += submit_to_callback_us;
            if submit_to_callback_us > self.slowest_request.submit_to_callback_us {
                self.slowest_request = SlowestFlushRequest {
                    operation: admission.operation,
                    queue_wait_us,
                    submit_to_callback_us,
                    rollover_us: group.rollover.as_micros(),
                    write_us: group.write.as_micros(),
                    intent_us: group.intent.as_micros(),
                    data_sync_us: group.data_sync.as_micros(),
                    publication_us: group.publication.as_micros(),
                };
            }
        }
    }
}

// Constant-space totals for private cost observations. They never authorize
// an operation, change an error, reset a guard, or delay a durability callback.
#[derive(Default)]
pub(super) struct CacheCosts {
    pub(super) calls: u64,
    pub(super) guard_failures: u64,
    pub(super) lock_wait: Duration,
    pub(super) validation: Duration,
    pub(super) read: Duration,
    pub(super) total: Duration,
}

impl CacheCosts {
    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "calls": self.calls,
            "guard_failures": self.guard_failures,
            "lock_wait_us": self.lock_wait.as_micros(),
            "validation_us": self.validation.as_micros(),
            "read_body_us": self.read.as_micros(),
            "total_us": self.total.as_micros(),
        })
    }
}

#[derive(Default)]
pub(super) struct ApplicationCosts {
    pub(super) successful_nonempty_batches: u64,
    pub(super) entries: u64,
    pub(super) lock_wait: Duration,
    pub(super) preflight: Duration,
    pub(super) sqlite_apply: Duration,
    pub(super) native_apply: Duration,
    pub(super) sqlite_commit_and_return: Duration,
    pub(super) projection_apply: Duration,
    pub(super) verification: Duration,
    pub(super) total: Duration,
}

impl ApplicationCosts {
    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "successful_nonempty_batches": self.successful_nonempty_batches,
            "entries": self.entries,
            "lock_wait_us": self.lock_wait.as_micros(),
            "preflight_us": self.preflight.as_micros(),
            "sqlite_apply_us": self.sqlite_apply.as_micros(),
            "native_apply_us": self.native_apply.as_micros(),
            // A subset of sqlite_apply, from the end of our before-commit
            // hook through the original apply helper's successful return.
            "sqlite_commit_and_return_us": self.sqlite_commit_and_return.as_micros(),
            "projection_apply_us": self.projection_apply.as_micros(),
            "verification_us": self.verification.as_micros(),
            "total_us": self.total.as_micros(),
        })
    }
}

#[derive(Default)]
pub(super) struct CheckpointCosts {
    pub(super) automatic_requests: u64,
    pub(super) completed: u64,
    pub(super) failures: u64,
    pub(super) elapsed: Duration,
    pub(super) maximum: Duration,
    pub(super) native_basis_count: u64,
    pub(super) native_basis_bytes: u64,
    pub(super) native_serialize: Duration,
    pub(super) native_file_sync: Duration,
    pub(super) native_proof: Duration,
    pub(super) native_decode_validate: Duration,
    pub(super) native_file_publish: Duration,
    pub(super) native_capture: Duration,
    pub(super) native_owner_publish: Duration,
    pub(super) native_owner_maximum: Duration,
    pub(super) native_select_io: Duration,
    pub(super) native_select_io_maximum: Duration,
    pub(super) native_reclaim_io: Duration,
    pub(super) native_reclaim_io_maximum: Duration,
}

#[cfg(test)]
pub(crate) struct PrivateWalTest {
    native: bool,
    directory: PathBuf,
    generation: [u8; 32],
    binding: Mutex<Option<Binding>>,
    current: Mutex<Weak<Wal>>,
    control: IoControl,
}

#[cfg(test)]
impl PrivateWalTest {
    pub(crate) fn new(directory: PathBuf, generation: [u8; 32]) -> Self {
        Self {
            native: false,
            directory,
            generation,
            binding: Mutex::new(None),
            current: Mutex::new(Weak::new()),
            control: IoControl::default(),
        }
    }

    pub(crate) fn new_native(directory: PathBuf, generation: [u8; 32]) -> Self {
        Self {
            native: true,
            ..Self::new(directory, generation)
        }
    }

    pub(crate) fn new_native_with_hook(
        directory: PathBuf,
        generation: [u8; 32],
        hook: Arc<dyn Fn(super::Point) -> io::Result<()> + Send + Sync>,
    ) -> Self {
        let mut test = Self::new_native(directory, generation);
        test.control.hook = hook;
        test
    }

    pub(crate) fn is_native(&self) -> bool {
        self.native
    }

    pub(crate) fn with_snapshot_failure(
        directory: PathBuf,
        generation: [u8; 32],
        point: super::Point,
        occurrence: usize,
    ) -> Self {
        let mut test = Self::new(directory, generation);
        let hits = std::sync::atomic::AtomicUsize::new(0);
        test.control.hook = Arc::new(move |actual| {
            if actual == point
                && hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 == occurrence
            {
                Err(io::Error::from_raw_os_error(libc::EIO))
            } else {
                Ok(())
            }
        });
        test
    }

    pub(crate) fn with_snapshot_hook(
        directory: PathBuf,
        generation: [u8; 32],
        hook: Arc<dyn Fn(super::Point) -> io::Result<()> + Send + Sync>,
    ) -> Self {
        let mut test = Self::new(directory, generation);
        test.control.hook = hook;
        test
    }

    pub(crate) async fn attach(&self, core: &mut SqliteConsensusCore) -> io::Result<()> {
        self.attach_with_descriptors(
            core,
            |snapshots, install| async move {
                if !snapshots.is_empty() || install.is_some() {
                    return Err(invalid_data(
                        "private WAL snapshots require the admitted directory",
                    ));
                }
                Ok(())
            },
            |()| Ok(()),
            |()| None,
        )
        .await
    }

    pub(crate) async fn attach_with_descriptors<V, F>(
        &self,
        core: &mut SqliteConsensusCore,
        validate: impl FnOnce(Vec<consensus::CurrentSnapshot>, Option<consensus::CurrentSnapshot>) -> F,
        verify: impl FnOnce(&V) -> io::Result<()>,
        install_source: impl FnOnce(&V) -> Option<&super::snapshot::InstallSource>,
    ) -> io::Result<()>
    where
        F: std::future::Future<Output = io::Result<V>>,
    {
        if core.private_wal.is_some() || core.database_file.is_none() {
            return Err(invalid_data(
                "private WAL requires an unattached file-backed core",
            ));
        }
        let conn = core.conn.lock().await;
        let expected = *self
            .binding
            .lock()
            .map_err(|_| invalid_data("private WAL fixture binding poisoned"))?;
        if self.native {
            let wal = if let Some(binding) = expected {
                if binding.identity != core.storage_identity || !binding.native {
                    return Err(invalid_data("native fixture binding differs"));
                }
                let opening = super::native::Opening::new(
                    &self.directory,
                    binding,
                    core.configured_roster_root.clone(),
                    Limits::default(),
                    self.control.clone(),
                )?;
                let descriptors =
                    validate(opening.snapshots(), opening.install_candidate()).await?;
                opening.finish_with_install_source(install_source(&descriptors), || {
                    verify(&descriptors)
                })?
            } else {
                let descriptors = validate(Vec::new(), None).await?;
                verify(&descriptors)?;
                Wal::create_native_with_root(
                    &self.directory,
                    &conn,
                    core.storage_identity,
                    self.generation,
                    core.configured_roster_root.clone(),
                    Limits::default(),
                    self.control.clone(),
                )?
            };
            *self
                .binding
                .lock()
                .map_err(|_| invalid_data("native fixture binding poisoned"))? =
                Some(wal.binding());
            core.applied_progress
                .send_replace(wal.with_native_read(|state| Ok(state.applied()))?);
            let wal = Arc::new(wal);
            *self
                .current
                .lock()
                .map_err(|_| invalid_data("native current owner poisoned"))? = Arc::downgrade(&wal);
            core.private_wal = Some(wal);
            return Ok(());
        }
        let wal = if let Some(binding) = expected {
            if binding.identity != core.storage_identity {
                return Err(invalid_data("private WAL fixture storage identity differs"));
            }
            let opening = super::snapshot::Opening::new(
                &self.directory,
                binding,
                Limits::default(),
                self.control.clone(),
            )?;
            let descriptors = validate(opening.snapshots(), opening.install_candidate()).await?;
            opening.finish_with_install_source(
                &conn,
                &core.caps,
                install_source(&descriptors),
                || verify(&descriptors),
            )?
        } else {
            // Initial integration deliberately requires an empty log. A
            // legacy database with acknowledged suffix needs the separately
            // reviewed migration/interlock, even in this opt-in fixture.
            if consensus::read_current_snapshot_sync(&conn, core.storage_identity)?.is_some()
                || consensus::last_log_sync(&conn, core.storage_identity)?.is_some()
                || consensus::read_applied_sync(&conn, core.storage_identity)?.is_some()
                || consensus::read_committed_sync(&conn, core.storage_identity)?.is_some()
            {
                return Err(invalid_data(
                    "private WAL fixture requires a fresh database",
                ));
            }
            let descriptors = validate(Vec::new(), None).await?;
            verify(&descriptors)?;
            let wal = Wal::create(
                &self.directory,
                &conn,
                core.storage_identity,
                self.generation,
                Limits::default(),
                self.control.clone(),
            )?;
            *self
                .binding
                .lock()
                .map_err(|_| invalid_data("private WAL fixture binding poisoned"))? =
                Some(wal.binding());
            wal.restore_application(&conn, &core.caps)?;
            wal
        };
        let wal = Arc::new(wal);
        *self
            .current
            .lock()
            .map_err(|_| invalid_data("private WAL current owner poisoned"))? =
            Arc::downgrade(&wal);
        core.private_wal = Some(wal);
        Ok(())
    }

    pub(crate) fn current(&self) -> io::Result<Arc<Wal>> {
        self.current
            .lock()
            .map_err(|_| invalid_data("private WAL current owner poisoned"))?
            .upgrade()
            .ok_or_else(|| invalid_data("private WAL cache has no current owner"))
    }
}

impl SqliteConsensusCore {
    pub(crate) async fn private_wal_log_store(
        &self,
    ) -> io::Result<Option<super::adapter::WalLogStore>> {
        let Some(wal) = self.private_wal.as_ref() else {
            return Ok(None);
        };
        if wal.is_native() {
            wal.with_native_read(|_| Ok(()))?;
            return Ok(Some(super::adapter::WalLogStore::new(Arc::clone(wal))));
        }
        let conn = self.conn.lock().await;
        wal.validate_application_cache(&conn)?;
        Ok(Some(super::adapter::WalLogStore::new(Arc::clone(wal))))
    }

    pub(crate) async fn validate_private_wal_snapshot_cache(&self) -> io::Result<()> {
        if let Some(wal) = &self.private_wal {
            if wal.is_native() {
                return wal.with_native_read(|_| Ok(()));
            }
            let conn = self.conn.lock().await;
            wal.validate_application_cache(&conn)?;
        }
        Ok(())
    }
}

impl Wal {
    pub(crate) fn integration_cost_snapshot(&self) -> io::Result<serde_json::Value> {
        let state = super::lock_state(&self.shared)?;
        Ok(self.integration_cost_snapshot_locked(&state))
    }

    fn integration_cost_snapshot_locked(&self, state: &super::State) -> serde_json::Value {
        let totals = &state.observation_totals;
        let checkpoint = serde_json::json!({
            "selected_epoch": state.checkpoint_epoch,
            "automatic_requests": state.checkpoint_costs.automatic_requests,
            "completed": state.checkpoint_costs.completed,
            "failures": state.checkpoint_costs.failures,
            "elapsed_us": state.checkpoint_costs.elapsed.as_micros(),
            "maximum_us": state.checkpoint_costs.maximum.as_micros(),
            "native_basis": {
                "count": state.checkpoint_costs.native_basis_count,
                "bytes": state.checkpoint_costs.native_basis_bytes,
                "serialize_us": state.checkpoint_costs.native_serialize.as_micros(),
                "file_sync_us": state.checkpoint_costs.native_file_sync.as_micros(),
                "proof_us": state.checkpoint_costs.native_proof.as_micros(),
                "decode_validate_us": state.checkpoint_costs.native_decode_validate.as_micros(),
                "file_publish_us": state.checkpoint_costs.native_file_publish.as_micros(),
                "capture_us": state.checkpoint_costs.native_capture.as_micros(),
                "owner_publish_us": state.checkpoint_costs.native_owner_publish.as_micros(),
                "owner_maximum_us": state.checkpoint_costs.native_owner_maximum.as_micros(),
                "select_io_us": state.checkpoint_costs.native_select_io.as_micros(),
                "select_io_maximum_us": state.checkpoint_costs.native_select_io_maximum.as_micros(),
                "reclaim_io_us": state.checkpoint_costs.native_reclaim_io.as_micros(),
                "reclaim_io_maximum_us": state.checkpoint_costs.native_reclaim_io_maximum.as_micros(),
            },
        });
        serde_json::json!({
            "scope": "current_writer_incarnation",
            "native_memory": state.native.is_some(),
            "native_live_sql_fallbacks": state.native_sql_fallbacks,
            "groups": totals.groups,
            "requests": totals.requests,
            "appended_entries": totals.appended_entries,
            "sync_calls": totals.sync_calls,
            "maximum_group_requests": totals.maximum_group_requests,
            "admission_us": totals.admission_us,
            "admission_lock_wait_us": totals.admission_lock_wait_us,
            "projection_us": totals.projection_us,
            "write_us": totals.write_us,
            "intent_us": totals.intent_us,
            "data_sync_us": totals.data_sync_us,
            "publication_us": totals.publication_us,
            "queue_wait_us": totals.queue_wait_us,
            "queue_wait_maximum_us": totals.queue_wait_maximum_us,
            "submit_to_callback_us": totals.submit_to_callback_us,
            "write_maximum_us": totals.write_maximum_us,
            "intent_maximum_us": totals.intent_maximum_us,
            "data_sync_maximum_us": totals.data_sync_maximum_us,
            "publication_maximum_us": totals.publication_maximum_us,
            "slowest_request": totals.slowest_request.json(),
            "retained_groups": state.observations.len(),
            "retained_requests": state.observation_requests,
            "retained_request_limit": self.limits.history_count,
            "live_retained_requests": state.sequence - state.base_sequence,
            "live_retained_bytes": state.history_bytes,
            "checkpoint": checkpoint,
            "discarded_groups": totals.groups - state.observations.len() as u64,
            "discarded_requests": totals.requests - state.observation_requests as u64,
            "cache_validation": state.cache_validation_costs.json(),
            "cache_read": state.cache_read_costs.json(),
            "application": state.application_costs.json(),
        })
    }

    pub(crate) fn integration_observations(&self) -> io::Result<serde_json::Value> {
        let mut observation = {
            let state = super::lock_state(&self.shared)?;
            serde_json::json!({
            "costs": self.integration_cost_snapshot_locked(&state),
            "groups": state.observations.iter().map(|group| serde_json::json!({
                "first": group.first,
                "last": group.last,
                "bytes": group.bytes,
                "sync_calls": group.sync_calls,
                "queue_wait_us": group.queue_wait.iter().map(std::time::Duration::as_micros).collect::<Vec<_>>(),
                "admission_us": group.admission.iter().map(|value| value.total.as_micros()).collect::<Vec<_>>(),
                "operation": group.admission.iter().map(|value| value.operation).collect::<Vec<_>>(),
                "entries": group.admission.iter().map(|value| value.entries).collect::<Vec<_>>(),
                "encode_us": group.admission.iter().map(|value| value.encode.as_micros()).collect::<Vec<_>>(),
                "admission_lock_wait_us": group.admission.iter().map(|value| value.lock_wait.as_micros()).collect::<Vec<_>>(),
                "projection_us": group.admission.iter().map(|value| value.projection.as_micros()).collect::<Vec<_>>(),
                "submit_to_callback_us": group.submit_to_callback.iter().map(std::time::Duration::as_micros).collect::<Vec<_>>(),
                "data_sync_us": group.data_sync.as_micros(),
                "intent_us": group.intent.as_micros(),
                "publication_us": group.publication.as_micros(),
                "write_us": group.write.as_micros(),
                "rollover_us": group.rollover.as_micros(),
                "callback_delay_us": group.callback_delay.as_micros(),
            })).collect::<Vec<_>>(),
            })
        };
        observation["writer_joined"] = serde_json::json!(self
            .writer
            .lock()
            .map_err(|_| invalid_data("private WAL writer join poisoned"))?
            .is_none());
        Ok(observation)
    }
}
