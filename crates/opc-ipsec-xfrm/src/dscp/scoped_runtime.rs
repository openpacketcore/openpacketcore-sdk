//! Fresh structural loading for a held local scope. Readiness never repairs.

use super::{
    aya_runtime::{AyaXfrmDscpRuntime, DATAPATH_OBJECT},
    LinuxXfrmDscpMarkingConfig, XfrmDscpRuntime,
};
use crate::{XfrmCapability, XfrmError};
use aya::{programs::SchedClassifier, Ebpf, EbpfLoader};
use opc_ipsec_xfrm_ebpf_common::PROG_EGRESS_DSCP;
use opc_linux_gtpu_sys::{self as sys, tc::PinDirectory};
use opc_local_kernel_lifecycle::{
    LocalGraphActorRegistration, LocalInstalledGraph, LocalKernelLifecycle, LocalLifecycleError,
    LocalRebuildGuard, LocalScopeResetReceipt,
};
use std::os::fd::AsFd;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

pub(crate) struct ScopedRuntime {
    lifecycle: LocalKernelLifecycle,
    loaded: Mutex<BTreeMap<u32, Loaded>>,
    registrations: Mutex<BTreeMap<u32, LocalGraphActorRegistration>>,
}
struct Loaded {
    config: LinuxXfrmDscpMarkingConfig,
    ebpf: Ebpf,
    directory: PinDirectory,
    ready: LocalInstalledGraph,
}
impl std::fmt::Debug for ScopedRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScopedDscpRuntime")
    }
}
impl ScopedRuntime {
    pub(crate) fn new(lifecycle: LocalKernelLifecycle) -> Self {
        Self {
            lifecycle,
            loaded: Mutex::new(BTreeMap::new()),
            registrations: Mutex::new(BTreeMap::new()),
        }
    }
}
fn uncertain() -> XfrmError {
    XfrmError::StateIndeterminate {
        operation: "local_scope_dscp",
    }
}
impl Loaded {
    fn readback(&self, config: &LinuxXfrmDscpMarkingConfig) -> Result<(), XfrmError> {
        if self.config != *config {
            return Err(uncertain());
        }
        self.ready.recheck().map_err(|_| uncertain())?;
        self.directory.recheck().map_err(|_| uncertain())?;
        if AyaXfrmDscpRuntime::read_profile(&self.ebpf)? != config.profile()?.encode() {
            return Err(uncertain());
        }
        Ok(())
    }
}
impl XfrmDscpRuntime for ScopedRuntime {
    fn fresh_namespace_runtime(&self) -> Arc<dyn XfrmDscpRuntime> {
        // A local scope is bound to one namespace. Binding verifies that exact
        // namespace before this empty instance can perform any operation.
        Arc::new(Self::new(self.lifecycle.clone()))
    }
    fn ensure_ready(&self, config: &LinuxXfrmDscpMarkingConfig) -> Result<(), XfrmError> {
        self.lifecycle
            .local_scope()
            .verify()
            .map_err(|_| uncertain())?;
        let loaded = self
            .loaded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for interface in &config.egress_interfaces {
            let index = sys::ifindex_by_name(interface).map_err(|_| uncertain())?;
            loaded.get(&index).ok_or_else(uncertain)?.readback(config)?;
        }
        Ok(())
    }
    fn capability(&self, config: &LinuxXfrmDscpMarkingConfig) -> XfrmCapability {
        if self.ensure_ready(config).is_ok() {
            XfrmCapability::Available
        } else {
            XfrmCapability::UnknownUntilUse
        }
    }
    fn scoped_graph(
        &self,
        reset: &LocalScopeResetReceipt,
        config: &LinuxXfrmDscpMarkingConfig,
        ifindex: u32,
    ) -> Result<Option<LocalInstalledGraph>, XfrmError> {
        let loaded = self
            .loaded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(entry) = loaded
            .get(&ifindex)
            .filter(|entry| entry.ready.matches_reset(reset))
        else {
            return Ok(None);
        };
        entry.readback(config)?;
        Ok(Some(entry.ready.clone()))
    }
    fn build_scoped_graph(
        &self,
        guard: &LocalRebuildGuard,
        config: &LinuxXfrmDscpMarkingConfig,
        observer_closed: &dyn Fn() -> bool,
    ) -> Result<LocalInstalledGraph, LocalLifecycleError> {
        let invalid = |_| LocalLifecycleError::Indeterminate;
        guard.recheck()?;
        let slot = guard
            .artifact()
            .slots()
            .next()
            .ok_or(LocalLifecycleError::InvalidPlan)?;
        {
            let mut registrations = self
                .registrations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let std::collections::btree_map::Entry::Vacant(entry) =
                registrations.entry(slot.ifindex())
            {
                entry.insert(
                    self.lifecycle
                        .bind_graph(guard.artifact())?
                        .register_actor()?,
                );
            }
        }
        // begin_rebuild proved this epoch is contained and locally empty.
        // An old request cannot discard the currently serving runtime.
        self.loaded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&slot.ifindex());
        let directory = guard.pin_directory()?;
        if !directory.entries()?.is_empty() {
            return Err(LocalLifecycleError::Stale);
        }
        let path = directory.descriptor_path()?;
        guard.recheck()?;
        let mut ebpf = EbpfLoader::new()
            .default_map_pin_directory(&path)
            .load(DATAPATH_OBJECT)
            .map_err(|_| LocalLifecycleError::Indeterminate)?;
        guard.recheck()?;
        AyaXfrmDscpRuntime::write_profile(&mut ebpf, config.profile().map_err(invalid)?)
            .map_err(invalid)?;
        if AyaXfrmDscpRuntime::read_profile(&ebpf).map_err(invalid)?
            != config.profile().map_err(invalid)?.encode()
        {
            return Err(LocalLifecycleError::Indeterminate);
        }
        guard.recheck()?;
        let program: &mut SchedClassifier = ebpf
            .program_mut(PROG_EGRESS_DSCP)
            .ok_or(LocalLifecycleError::Indeterminate)?
            .try_into()
            .map_err(|_| LocalLifecycleError::Indeterminate)?;
        program
            .load()
            .map_err(|_| LocalLifecycleError::Indeterminate)?;
        let held = sys::bpf::ProgramHandle::from_fd(
            program
                .fd()
                .map_err(|_| LocalLifecycleError::Indeterminate)?
                .as_fd(),
        )
        .map_err(|_| LocalLifecycleError::Indeterminate)?;
        guard.recheck()?;
        directory.recheck()?;
        program
            .pin(path.join(PROG_EGRESS_DSCP))
            .map_err(|_| LocalLifecycleError::Indeterminate)?;
        guard.attach_program(slot, &held, PROG_EGRESS_DSCP)?;
        if observer_closed() {
            return Err(LocalLifecycleError::Indeterminate);
        }
        let mut loaded = self
            .loaded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let maps = ebpf
            .maps()
            .map(|(_, map)| {
                let aya::maps::Map::Array(data) = map else {
                    return Err(LocalLifecycleError::Indeterminate);
                };
                sys::bpf::MapHandle::from_fd(data.fd().as_fd())
                    .map_err(|_| LocalLifecycleError::Indeterminate)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let ready = guard.complete(vec![held], maps)?;
        loaded.insert(
            slot.ifindex(),
            Loaded {
                config: config.clone(),
                ebpf,
                directory,
                ready: ready.clone(),
            },
        );
        Ok(ready)
    }
}
