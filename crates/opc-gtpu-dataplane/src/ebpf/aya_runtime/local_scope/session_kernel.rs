//! Exact current-image map operations through the sole scoped runtime's FDs.
use super::runtime::{Loaded, Shared};
use super::*;
use crate::ebpf::local_scope::session_effect::{self, Readback};
use crate::ebpf::{
    grouped_active_indexes, grouped_record_from_model, GroupedIndexElement, GroupedIndexKey,
};
use crate::{GtpDevice, GtpuSessionGroup};
use opc_gtpu_ebpf_common::{GtpuSessionGeneration, GtpuSessionGroupRecord};
use opc_local_kernel_lifecycle::{
    CleanupAttempt, CommittedScopeEffect, LocalInstalledGraph, LocalOperation,
};

pub(super) fn uncertain() -> GtpuError {
    state_indeterminate("ebpf_local_session")
}
pub(super) fn mismatch() -> GtpuError {
    state_indeterminate("ebpf_local_session_identity")
}
pub(super) struct Request {
    pub(super) model: GtpuSessionGroup,
    pub(super) record: GtpuSessionGroupRecord,
    pub(super) indexes: Vec<GroupedIndexElement>,
}
impl Request {
    pub(super) fn new(
        shared: &Shared,
        graph: &LocalInstalledGraph,
        model: GtpuSessionGroup,
    ) -> Result<Self, GtpuError> {
        let state = shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let loaded = state.as_ref().ok_or_else(mismatch)?;
        if !loaded.ready.is_same(graph) {
            return Err(mismatch());
        }
        loaded.readback()?;
        let device = GtpDevice {
            name: loaded.request.device().name.clone(),
            ifindex: sys::ifindex_by_name(&loaded.request.device().name).map_err(|_| mismatch())?,
        };
        model
            .validate_attachment(
                loaded.request.device_id(),
                &device,
                loaded.request.local_endpoints(),
            )
            .map_err(|_| {
                GtpuError::invalid_config(
                    "local_scope.session",
                    "group does not match the current device and endpoint set",
                )
            })?;
        let record =
            grouped_record_from_model(&model, GtpuSessionGeneration::INITIAL).ok_or_else(|| {
                GtpuError::invalid_config(
                    "local_scope.session",
                    "group is not encodable by the current image",
                )
            })?;
        let indexes = grouped_active_indexes(record).ok_or_else(mismatch)?;
        // Refuse the unsupported kernel before installing a row whose exact
        // teardown would later depend on this reader-grace primitive.
        AyaGtpuRuntime::new().synchronize_grouped_readers()?;
        Ok(Self {
            model,
            record,
            indexes,
        })
    }
}
pub(super) struct NativeKernel<'a> {
    #[cfg(test)]
    pub(super) fault: &'a mut Option<super::sessions::TestFault>,
    pub(super) shared: &'a Shared,
    pub(super) graph: &'a LocalInstalledGraph,
    pub(super) guard: &'a LocalOperation,
    pub(super) effect: &'a CommittedScopeEffect,
    pub(super) request: &'a Request,
    pub(super) attempt: CleanupAttempt,
}
impl NativeKernel<'_> {
    #[cfg(test)]
    pub(super) fn after_publication(&mut self) {
        if matches!(
            self.fault,
            Some(super::sessions::TestFault::PanicAfterPublication)
        ) {
            *self.fault = None;
            panic!("injected GTP-U panic after publication");
        }
    }
    fn with_loaded<T>(
        &self,
        work: impl FnOnce(&mut Loaded) -> Result<T, GtpuError>,
    ) -> Result<T, GtpuError> {
        use session_effect::Kernel;
        self.local()?;
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let loaded = state.as_mut().ok_or_else(mismatch)?;
        if !loaded.ready.is_same(self.graph) {
            return Err(mismatch());
        }
        loaded.readback()?;
        self.local()?;
        work(loaded)
    }
}
fn read<const K: usize, const V: usize>(
    ebpf: &Ebpf,
    name: &str,
    key: [u8; K],
) -> Result<Option<[u8; V]>, GtpuError> {
    let hash = BpfHashMap::<_, [u8; K], [u8; V]>::try_from(ebpf.map(name).ok_or_else(mismatch)?)
        .map_err(|error| map_error("ebpf_local_session_map", error))?;
    match hash.get(&key, 0) {
        Ok(value) => Ok(Some(value)),
        Err(MapError::KeyNotFound) => Ok(None),
        Err(error) => Err(map_error("ebpf_local_session_read", error)),
    }
}
fn insert<const K: usize, const V: usize>(
    ebpf: &mut Ebpf,
    name: &str,
    key: [u8; K],
    value: [u8; V],
) -> Result<(), GtpuError> {
    let mut hash =
        BpfHashMap::<_, [u8; K], [u8; V]>::try_from(ebpf.map_mut(name).ok_or_else(mismatch)?)
            .map_err(|error| map_error("ebpf_local_session_map", error))?;
    hash.insert(key, value, 1)
        .map_err(|error| map_error("ebpf_local_session_insert", error))
}
fn remove<const K: usize, const V: usize>(
    ebpf: &mut Ebpf,
    name: &str,
    key: [u8; K],
    expected: [u8; V],
    recheck: impl FnOnce() -> Result<(), GtpuError>,
) -> Result<(), GtpuError> {
    match read(ebpf, name, key)? {
        None => return Ok(()),
        Some(value) if value == expected => {}
        Some(_) => return Err(mismatch()),
    }
    let mut hash =
        BpfHashMap::<_, [u8; K], [u8; V]>::try_from(ebpf.map_mut(name).ok_or_else(mismatch)?)
            .map_err(|error| map_error("ebpf_local_session_map", error))?;
    recheck()?;
    match hash.remove(&key) {
        Ok(()) | Err(MapError::KeyNotFound) => Ok(()),
        Err(error) => Err(map_error("ebpf_local_session_remove", error)),
    }
}
fn compare<const N: usize>(
    actual: Option<[u8; N]>,
    expected: [u8; N],
) -> Result<Readback, GtpuError> {
    match actual {
        None => Ok(Readback::Absent),
        Some(value) if value == expected => Ok(Readback::Exact),
        Some(_) => Err(mismatch()),
    }
}
#[async_trait::async_trait]
impl session_effect::Kernel for NativeKernel<'_> {
    fn index_count(&self) -> usize {
        self.request.indexes.len()
    }
    fn local(&self) -> Result<(), GtpuError> {
        if !self.attempt.has_budget()
            || !self.effect.matches_operation(self.guard)
            || !self.graph.epoch().is_same(self.guard.epoch())
        {
            return Err(uncertain());
        }
        self.guard.recheck().map_err(|_| mismatch())
    }
    fn publication(&self) -> Result<(), GtpuError> {
        self.local()?;
        self.effect
            .recheck_local_execution()
            .map_err(|_| uncertain())
    }
    async fn current(&self) -> Result<(), GtpuError> {
        self.local()?;
        self.effect.recheck().await.map_err(|_| uncertain())
    }
    fn group(&self) -> Result<Readback, GtpuError> {
        self.with_loaded(|loaded| {
            compare(
                read(
                    &loaded.ebpf,
                    MAP_SESSION_GROUPS,
                    self.request.model.id().to_bytes(),
                )?,
                self.request.record.encode(),
            )
        })
    }
    fn index(&self, index: usize) -> Result<Readback, GtpuError> {
        let expected = self.request.indexes.get(index).ok_or_else(mismatch)?;
        self.with_loaded(|loaded| {
            compare(
                match expected.key {
                    GroupedIndexKey::Uplink(key) => {
                        read(&loaded.ebpf, MAP_SESSION_UPLINK_INDEX, key)?
                    }
                    GroupedIndexKey::Downlink(key) => {
                        read(&loaded.ebpf, MAP_SESSION_DOWNLINK_INDEX, key)?
                    }
                },
                expected.value,
            )
        })
    }
    fn create_index(&mut self, index: usize) -> Result<(), GtpuError> {
        let expected = self.request.indexes.get(index).ok_or_else(mismatch)?;
        let result = self.with_loaded(|loaded| match expected.key {
            GroupedIndexKey::Uplink(key) => insert(
                &mut loaded.ebpf,
                MAP_SESSION_UPLINK_INDEX,
                key,
                expected.value,
            ),
            GroupedIndexKey::Downlink(key) => insert(
                &mut loaded.ebpf,
                MAP_SESSION_DOWNLINK_INDEX,
                key,
                expected.value,
            ),
        });
        #[cfg(test)]
        if matches!(
            self.fault,
            Some(super::sessions::TestFault::PanicAfterIndex)
        ) {
            *self.fault = None;
            panic!("injected GTP-U panic after selector creation");
        }
        result
    }
    async fn create_group(&mut self) -> Result<(), GtpuError> {
        let result = self.with_loaded(|loaded| {
            insert(
                &mut loaded.ebpf,
                MAP_SESSION_GROUPS,
                self.request.model.id().to_bytes(),
                self.request.record.encode(),
            )
        });
        #[cfg(test)]
        match self.fault {
            Some(super::sessions::TestFault::PanicAfterGroup) => {
                *self.fault = None;
                panic!("injected GTP-U panic after group creation");
            }
            Some(super::sessions::TestFault::PauseAfterGroup(pause)) => {
                pause.entered.notify_one();
                pause.resume.notified().await;
                *self.fault = None;
            }
            _ => {}
        }
        result
    }
    fn remove_group(&mut self) -> Result<(), GtpuError> {
        self.with_loaded(|loaded| {
            remove(
                &mut loaded.ebpf,
                MAP_SESSION_GROUPS,
                self.request.model.id().to_bytes(),
                self.request.record.encode(),
                || self.local(),
            )
        })
    }
    fn remove_index(&mut self, index: usize) -> Result<(), GtpuError> {
        let expected = self.request.indexes.get(index).ok_or_else(mismatch)?;
        self.with_loaded(|loaded| match expected.key {
            GroupedIndexKey::Uplink(key) => remove(
                &mut loaded.ebpf,
                MAP_SESSION_UPLINK_INDEX,
                key,
                expected.value,
                || self.local(),
            ),
            GroupedIndexKey::Downlink(key) => remove(
                &mut loaded.ebpf,
                MAP_SESSION_DOWNLINK_INDEX,
                key,
                expected.value,
                || self.local(),
            ),
        })
    }
    fn synchronize_readers(&self) -> Result<(), GtpuError> {
        self.local()?;
        AyaGtpuRuntime::new().synchronize_grouped_readers()?;
        self.local()
    }
}
