//! Fresh scoped runtime. No legacy adoption, object journal or auto-detach link.
use super::*;
use crate::ebpf::{
    grouped_device_config, require_ebpf_executable_pmtu_policy, validate_interface_name,
};
use crate::CreateGtpDeviceEndpointSetRequest;
use opc_local_kernel_lifecycle::{
    LocalGraphActorRegistration, LocalGraphBinding, LocalInstalledGraph, LocalLifecycleError,
    LocalRebuildGuard, LocalScopeResetReceipt,
};
use std::os::fd::AsFd;

// This fresh map graph has no predecessor source or generation to adopt. Its
// current image requires an odd gate to execute packet effects. Containment,
// committed per-session authority and activation-bound opening govern access;
// this constant has no clock, expiry, remote ownership or renewal semantics.
const FRESH_PACKET_GATE: u64 = 3;

pub(in super::super::super) struct Runtime {
    shared: Arc<Shared>,
    installs: tokio::sync::mpsc::Sender<super::sessions::Install>,
    controls: tokio::sync::mpsc::Sender<super::sessions::Control>,
    admission: Arc<tokio::sync::Semaphore>,
    serial: Arc<tokio::sync::Mutex<()>>,
}
pub(super) struct Shared {
    _registration: LocalGraphActorRegistration,
    pub(super) state: Mutex<Option<Loaded>>,
}
pub(super) struct Loaded {
    pub(super) request: CreateGtpDeviceEndpointSetRequest,
    pub(super) ebpf: Ebpf,
    directory: sys::tc::PinDirectory,
    pub(super) ready: LocalInstalledGraph,
}
impl Runtime {
    #[cfg(test)]
    pub(in super::super::super) async fn retained(&self) -> usize {
        let (reply, observed) = tokio::sync::oneshot::channel();
        self.controls
            .send(super::sessions::Control::Retained(reply))
            .await
            .unwrap();
        observed.await.unwrap()
    }

    #[cfg(test)]
    pub(in super::super::super) async fn fault(
        &self,
        fault: super::sessions::TestFault,
    ) -> Result<(), GtpuError> {
        let (reply, observed) = tokio::sync::oneshot::channel();
        self.controls
            .send(super::sessions::Control::Fault(fault, reply))
            .await
            .map_err(|_| state_indeterminate("ebpf_local_actor"))?;
        observed
            .await
            .map_err(|_| state_indeterminate("ebpf_local_actor"))?
    }
    pub(in super::super::super) fn new(
        registration: LocalGraphActorRegistration,
    ) -> Result<Self, GtpuError> {
        let shared = Arc::new(Shared {
            _registration: registration,
            state: Mutex::new(None),
        });
        let (installs, controls) = super::sessions::start(shared.clone())?;
        Ok(Self {
            shared,
            installs,
            controls,
            admission: Arc::new(tokio::sync::Semaphore::new(64)),
            serial: Arc::new(tokio::sync::Mutex::new(())),
        })
    }
    pub(in super::super::super) async fn install(
        &self,
        graph: &LocalInstalledGraph,
        effect: opc_local_kernel_lifecycle::CommittedScopeEffect,
        request: crate::GtpuSessionGroup,
    ) -> Result<crate::ScopedGtpuReceipt, GtpuError> {
        let permit = self
            .admission
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| state_indeterminate("ebpf_local_actor"))?;
        let guard = graph.begin_operation().await.map_err(local_error)?;
        let (reply, observed) = tokio::sync::oneshot::channel();
        self.installs
            .send(super::sessions::Install {
                graph: graph.clone(),
                effect,
                request,
                guard,
                permit,
                reply,
            })
            .await
            .map_err(|_| state_indeterminate("ebpf_local_actor"))?;
        observed
            .await
            .map_err(|_| state_indeterminate("ebpf_local_actor"))?
    }
    pub(in super::super::super) async fn read(
        &self,
        receipt: &crate::ScopedGtpuReceipt,
    ) -> Result<bool, GtpuError> {
        let guard = receipt
            .binding
            .graph
            .begin_operation()
            .await
            .map_err(local_error)?;
        let (reply, observed) = tokio::sync::oneshot::channel();
        self.controls
            .send(super::sessions::Control::Read {
                receipt: receipt.clone(),
                guard,
                reply,
            })
            .await
            .map_err(|_| state_indeterminate("ebpf_local_actor"))?;
        observed
            .await
            .map_err(|_| state_indeterminate("ebpf_local_actor"))?
    }
    pub(in super::super::super) async fn remove(
        &self,
        receipt: &crate::ScopedGtpuReceipt,
    ) -> Result<(), GtpuError> {
        let guard = receipt
            .binding
            .graph
            .begin_operation()
            .await
            .map_err(local_error)?;
        let (reply, observed) = tokio::sync::oneshot::channel();
        self.controls
            .send(super::sessions::Control::Remove {
                receipt: receipt.clone(),
                guard,
                reply,
            })
            .await
            .map_err(|_| state_indeterminate("ebpf_local_actor"))?;
        observed
            .await
            .map_err(|_| state_indeterminate("ebpf_local_actor"))?
    }
    pub(in super::super::super) async fn progress(
        &self,
    ) -> Result<Vec<opc_local_kernel_lifecycle::CleanupProgress>, GtpuError> {
        let (reply, observed) = tokio::sync::oneshot::channel();
        self.controls
            .send(super::sessions::Control::Progress(reply))
            .await
            .map_err(|_| state_indeterminate("ebpf_local_actor"))?;
        observed
            .await
            .map_err(|_| state_indeterminate("ebpf_local_actor"))?
    }
    pub(in super::super::super) async fn rebuild(
        self: &Arc<Self>,
        binding: &LocalGraphBinding,
        reset: &LocalScopeResetReceipt,
        request: CreateGtpDeviceEndpointSetRequest,
    ) -> Result<LocalInstalledGraph, GtpuError> {
        validate_interface_name(&request.device().name)?;
        require_ebpf_executable_pmtu_policy(request.device().uplink_mtu_policy)?;
        let ifindex = sys::ifindex_by_name(&request.device().name)
            .map_err(|error| GtpuError::io("local_graph_interface", error))?;
        if binding
            .artifact()
            .slots()
            .any(|slot| slot.ifindex() != ifindex)
            || request.device().bind_port != 2152
            || request.device().role != crate::GtpRole::Ggsn
        {
            return Err(GtpuError::invalid_config(
                "local_graph.request",
                "scope interface and GGSN/2152 profile must match",
            ));
        }
        let serial = self.serial.clone().lock_owned().await;
        {
            let state = self
                .shared
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(loaded) = state
                .as_ref()
                .filter(|loaded| loaded.ready.matches_reset(reset))
            {
                if loaded.request != request {
                    return Err(GtpuError::AlreadyExists);
                }
                loaded.readback()?;
                return Ok(loaded.ready.clone());
            }
        }
        let guard = binding.begin_rebuild(reset).await.map_err(local_error)?;
        let runtime = self.clone();
        guard
            .supervise(move |guard, observer_closed| {
                let _serial = serial;
                // Clear the previous runtime only after the completed reset and
                // fresh empty graph were proved. A stale request cannot discard it.
                *runtime
                    .shared
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
                let (ebpf, directory) =
                    load(guard, &request).map_err(|_| LocalLifecycleError::Indeterminate)?;
                if observer_closed() {
                    return Err(LocalLifecycleError::Indeterminate);
                }
                let mut state = runtime
                    .shared
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let (programs, maps) =
                    loaded_objects(&ebpf).map_err(|_| LocalLifecycleError::Indeterminate)?;
                let ready = guard.complete(programs, maps)?;
                *state = Some(Loaded {
                    request,
                    ebpf,
                    directory,
                    ready: ready.clone(),
                });
                Ok(ready)
            })
            .await
            .map_err(local_error)
    }
}
fn local_error(_: LocalLifecycleError) -> GtpuError {
    state_indeterminate("ebpf_local_graph")
}
impl Loaded {
    pub(super) fn readback(&self) -> Result<(), GtpuError> {
        self.ready.recheck().map_err(local_error)?;
        self.directory
            .recheck()
            .map_err(|_| state_indeterminate("ebpf_local_graph_pins"))?;
        let ifindex = sys::ifindex_by_name(&self.request.device().name)
            .map_err(|error| GtpuError::io("local_graph_interface", error))?;
        let expected = grouped_device_config(
            self.request.device_id(),
            ifindex,
            self.request.local_endpoints(),
        )
        .ok_or_else(|| state_indeterminate("ebpf_local_graph_config"))?;
        if AyaGtpuRuntime::grouped_config_read(&self.ebpf)? != expected.encode()
            || AyaGtpuRuntime::grouped_schema_read(&self.ebpf)? != GTPU_SESSION_SCHEMA_MARKER_VALUE
            || AyaGtpuRuntime::traffic_observation_source_enabled_gate(&self.ebpf)?
                != FRESH_PACKET_GATE
        {
            return Err(state_indeterminate("ebpf_local_graph_config"));
        }
        let pmtu = self
            .request
            .device()
            .uplink_mtu_policy
            .map_or([0; UPLINK_PMTU_VALUE_LEN], |policy| policy.map_value());
        let array = Array::<_, [u8; UPLINK_PMTU_VALUE_LEN]>::try_from(
            self.ebpf.map(MAP_UPLINK_PMTU).ok_or(GtpuError::NotFound)?,
        )
        .map_err(|error| map_error("ebpf_local_pmtu", error))?;
        if array
            .get(&0, 0)
            .map_err(|error| map_error("ebpf_local_pmtu", error))?
            != pmtu
        {
            return Err(state_indeterminate("ebpf_local_pmtu"));
        }
        Ok(())
    }
}
fn load(
    guard: &LocalRebuildGuard,
    request: &CreateGtpDeviceEndpointSetRequest,
) -> Result<(Ebpf, sys::tc::PinDirectory), GtpuError> {
    guard.recheck().map_err(local_error)?;
    let directory = guard.pin_directory().map_err(local_error)?;
    if !directory
        .entries()
        .map_err(|_| state_indeterminate("ebpf_local_graph_pins"))?
        .is_empty()
    {
        return Err(GtpuError::AlreadyExists);
    }
    let path = directory
        .descriptor_path()
        .map_err(|_| state_indeterminate("ebpf_local_graph_pins"))?;
    guard.recheck().map_err(local_error)?;
    let mut ebpf = EbpfLoader::new()
        .default_map_pin_directory(&path)
        .load(DATAPATH_OBJECT)
        .map_err(|_| state_indeterminate("ebpf_local_graph_load"))?;
    let ifindex = guard
        .artifact()
        .slots()
        .next()
        .ok_or_else(|| state_indeterminate("ebpf_local_graph"))?
        .ifindex();
    let config = grouped_device_config(request.device_id(), ifindex, request.local_endpoints())
        .ok_or_else(|| state_indeterminate("ebpf_local_graph_config"))?;
    guard.recheck().map_err(local_error)?;
    AyaGtpuRuntime::grouped_config_write_verified(&mut ebpf, config.encode())?;
    guard.recheck().map_err(local_error)?;
    AyaGtpuRuntime::grouped_schema_write_verified(&mut ebpf)?;
    let pmtu = request
        .device()
        .uplink_mtu_policy
        .map_or([0; UPLINK_PMTU_VALUE_LEN], |policy| policy.map_value());
    {
        guard.recheck().map_err(local_error)?;
        let mut array = Array::<_, [u8; UPLINK_PMTU_VALUE_LEN]>::try_from(
            ebpf.map_mut(MAP_UPLINK_PMTU).ok_or(GtpuError::NotFound)?,
        )
        .map_err(|error| map_error("ebpf_local_pmtu", error))?;
        array
            .set(0, pmtu, 0)
            .map_err(|error| map_error("ebpf_local_pmtu", error))?;
        if array
            .get(&0, 0)
            .map_err(|error| map_error("ebpf_local_pmtu", error))?
            != pmtu
        {
            return Err(state_indeterminate("ebpf_local_pmtu"));
        }
    }
    for slot in guard.artifact().slots() {
        guard.recheck().map_err(local_error)?;
        let name = if slot.hook() == TcHook::Egress {
            PROG_UPLINK
        } else {
            PROG_DOWNLINK
        };
        load_program(&mut ebpf, name)?;
        let held = sys::bpf::ProgramHandle::from_fd(
            ebpf.program(name)
                .ok_or(GtpuError::NotFound)?
                .fd()
                .map_err(|error| program_error("ebpf_local_program", &error))?
                .as_fd(),
        )
        .map_err(|_| state_indeterminate("ebpf_local_program"))?;
        guard.recheck().map_err(local_error)?;
        directory
            .recheck()
            .map_err(|_| state_indeterminate("ebpf_local_graph_pins"))?;
        let program: &mut SchedClassifier = ebpf
            .program_mut(name)
            .ok_or(GtpuError::NotFound)?
            .try_into()
            .map_err(|error| program_error("ebpf_local_program", &error))?;
        program
            .pin(path.join(name))
            .map_err(|_| state_indeterminate("ebpf_local_program_pin"))?;
        guard
            .attach_program(slot, &held, name)
            .map_err(local_error)?;
    }
    guard.recheck().map_err(local_error)?;
    AyaGtpuRuntime::enable_traffic_observation_source(&mut ebpf, FRESH_PACKET_GATE)?;
    guard.recheck().map_err(local_error)?;
    Ok((ebpf, directory))
}

pub(super) fn loaded_objects(
    ebpf: &Ebpf,
) -> Result<(Vec<sys::bpf::ProgramHandle>, Vec<sys::bpf::MapHandle>), GtpuError> {
    let programs = ebpf
        .programs()
        .map(|(_, program)| {
            let fd = program
                .fd()
                .map_err(|error| program_error("ebpf_local_program", &error))?;
            sys::bpf::ProgramHandle::from_fd(fd.as_fd())
                .map_err(|_| state_indeterminate("ebpf_local_program"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let maps = ebpf
        .maps()
        .map(|(_, map)| {
            // Every type in the embedded image is explicit. New map kinds require
            // a reviewed catalog/loader change rather than ID-based reconstruction.
            let data = match map {
                aya::maps::Map::Array(data)
                | aya::maps::Map::HashMap(data)
                | aya::maps::Map::PerCpuArray(data)
                | aya::maps::Map::RingBuf(data) => data,
                _ => return Err(state_indeterminate("ebpf_local_map")),
            };
            sys::bpf::MapHandle::from_fd(data.fd().as_fd())
                .map_err(|_| state_indeterminate("ebpf_local_map"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((programs, maps))
}
