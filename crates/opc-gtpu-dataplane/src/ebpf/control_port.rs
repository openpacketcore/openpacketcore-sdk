//! Backend-owned IPv4 control socket, serialized with attachment mutation.

use std::sync::Weak;

use super::*;
use crate::control_port::{
    GtpuControlDatagram, GtpuControlPort, GtpuControlPortError, GtpuControlSendPlan,
};

#[derive(Default)]
pub(super) struct ControlSocketState {
    socket: Option<crate::GtpuReassemblySocket>,
    retired: bool,
    /// Value-free counters of this registration's downlink consumer.
    downlink_counters: crate::GtpuDownlinkCounters,
    /// Per-registration in-tunnel Packet Too Big rate limit.
    too_big_limiter: crate::reassembly::PacketTooBigLimiter,
}

impl ControlSocketState {
    #[cfg(test)]
    pub(super) fn is_unopened(&self) -> bool {
        self.socket.is_none()
    }

    fn retire(&mut self) {
        self.retired = true;
        self.socket = None;
    }
}

type SocketSlot = Mutex<ControlSocketState>;

struct BackendControlPort {
    backend: Weak<EbpfGtpuDataplaneBackendInner>,
    socket: Weak<SocketSlot>,
    ifindex: u32,
}

impl fmt::Debug for BackendControlPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EbpfGtpuControlPort(<redacted>)")
    }
}

impl BackendControlPort {
    fn with_socket<T>(
        &self,
        operation: impl FnOnce(&crate::GtpuReassemblySocket) -> Result<T, GtpuControlPortError>,
    ) -> Result<T, GtpuControlPortError> {
        self.with_attachment(|_, state, _| {
            let socket = state
                .socket
                .as_ref()
                .ok_or(GtpuControlPortError::Unavailable)?;
            operation(socket)
        })
    }

    /// Run one operation under the attachment mutation guard with the exact
    /// live socket state and the attachment's authority scope.
    fn with_attachment<T>(
        &self,
        operation: impl FnOnce(
            &EbpfGtpuDataplaneBackend,
            &mut ControlSocketState,
            super::reassembled_downlink::DownlinkAuthorityScope,
        ) -> Result<T, GtpuControlPortError>,
    ) -> Result<T, GtpuControlPortError> {
        let unavailable = || GtpuControlPortError::Unavailable;
        let inner = self.backend.upgrade().ok_or_else(unavailable)?;
        let backend = EbpfGtpuDataplaneBackend { inner };
        let _operation = backend
            .inner
            .operation_lock
            .try_lock()
            .map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => GtpuControlPortError::Busy,
                std::sync::TryLockError::Poisoned(_) => unavailable(),
            })?;
        let slot = self.socket.upgrade().ok_or_else(unavailable)?;
        let devices = backend.devices().map_err(|_| unavailable())?;
        let managed = devices.get(&self.ifindex).ok_or_else(unavailable)?;
        if !Arc::ptr_eq(&slot, &managed.control_socket)
            || managed.cleanup_only
            || managed.successor_pending
        {
            slot.lock().map_err(|_| unavailable())?.retire();
            return Err(unavailable());
        }
        let name = managed.name.clone();
        let scope = super::reassembled_downlink::DownlinkAuthorityScope {
            ifindex: self.ifindex,
            grouped_config: managed.grouped.and_then(|grouped| {
                grouped_device_config(grouped.device_id, self.ifindex, grouped.local_endpoints)
            }),
        };
        if managed.grouped.is_some() && scope.grouped_config.is_none() {
            slot.lock().map_err(|_| unavailable())?.retire();
            return Err(unavailable());
        }
        drop(devices);
        if backend.inner.runtime.ifindex_by_name(&name).ok() != Some(self.ifindex)
            || !backend
                .inner
                .runtime
                .pdp_readback_datapath_usable(self.ifindex)
        {
            slot.lock().map_err(|_| unavailable())?.retire();
            return Err(unavailable());
        }
        let mut state = slot.lock().map_err(|_| unavailable())?;
        if state.retired || state.socket.is_none() {
            return Err(unavailable());
        }
        // Keep the mutation guard across the nonblocking syscall and every
        // authority read: removal, replacement and cleanup-only adoption may
        // linearize before or after this operation, never midway through it.
        operation(&backend, &mut state, scope)
    }
}

impl GtpuControlPort for BackendControlPort {
    fn try_receive_datagram(
        &self,
        maximum_bytes: usize,
    ) -> Result<Option<GtpuControlDatagram>, GtpuControlPortError> {
        self.with_socket(|socket| socket.try_receive_datagram(maximum_bytes))
    }

    fn send_control_response(
        &self,
        plan: GtpuControlSendPlan,
    ) -> Result<usize, GtpuControlPortError> {
        self.with_socket(|socket| socket.send_control_response(plan))
    }

    fn try_receive_downlink(
        &self,
        maximum_bytes: usize,
    ) -> Result<Option<crate::GtpuDownlinkEvent>, GtpuControlPortError> {
        self.with_attachment(|backend, state, scope| {
            let socket = state
                .socket
                .as_ref()
                .ok_or(GtpuControlPortError::Unavailable)?;
            let Some(datagram) = socket.try_receive_datagram(maximum_bytes)? else {
                return Ok(None);
            };
            let plan = match super::reassembled_downlink::process_downlink_datagram(
                backend.inner.runtime.as_ref(),
                scope,
                datagram,
                &mut state.downlink_counters,
            ) {
                super::reassembled_downlink::ProcessedDownlink::Event(event) => {
                    return Ok(Some(event));
                }
                super::reassembled_downlink::ProcessedDownlink::PacketTooBig(plan) => plan,
            };
            // Exactly one error per offending packet, subject to the limit.
            // It is always carried in the session's uplink G-PDU; nothing is
            // ever sent unencapsulated.
            let signal = if !state.too_big_limiter.admit(std::time::Instant::now()) {
                crate::GtpuPacketTooBigSignal::RateLimited
            } else {
                let (local, peer) = plan.endpoints();
                match plan.build_uplink_gpdu() {
                    Some(gpdu) if socket.send_in_tunnel_error(local, peer, &gpdu).is_ok() => {
                        crate::GtpuPacketTooBigSignal::Sent
                    }
                    Some(_) | None => crate::GtpuPacketTooBigSignal::Unsendable,
                }
            };
            let counters = &mut state.downlink_counters;
            let slot = match signal {
                crate::GtpuPacketTooBigSignal::Sent => &mut counters.packet_too_big_signalled,
                crate::GtpuPacketTooBigSignal::RateLimited => {
                    &mut counters.packet_too_big_rate_limited
                }
                crate::GtpuPacketTooBigSignal::Unsendable => {
                    &mut counters.packet_too_big_unsendable
                }
            };
            *slot = slot.saturating_add(1);
            Ok(Some(crate::GtpuDownlinkEvent::PacketTooBig(
                crate::GtpuDownlinkPacketTooBig::new(
                    crate::GtpAddressFamily::Ipv4,
                    plan.mtu(),
                    signal,
                ),
            )))
        })
    }

    fn set_packet_too_big_rate_limit(
        &self,
        limit: crate::GtpuPacketTooBigRateLimit,
    ) -> Result<(), GtpuControlPortError> {
        self.with_attachment(|_, state, _| {
            state.too_big_limiter = crate::reassembly::PacketTooBigLimiter::new(limit);
            Ok(())
        })
    }

    fn downlink_counters(&self) -> Result<crate::GtpuDownlinkCounters, GtpuControlPortError> {
        self.with_attachment(|_, state, _| Ok(state.downlink_counters))
    }
}

impl EbpfGtpuDataplaneBackend {
    /// Caller holds the attachment mutation guard and the exact namespace
    /// effect lease through all pre/post checks and this nonblocking send.
    pub(super) fn send_retired_n3_end_marker_under_guard(
        &self,
        device: &GtpDevice,
        local: Ipv4Addr,
        peer: Ipv4Addr,
        teid: crate::Teid,
        current: impl Fn() -> bool,
    ) -> Result<(), GtpuError> {
        let unavailable = || state_indeterminate("ebpf_n3_end_marker_socket");
        let devices = self.devices()?;
        let managed = devices.get(&device.ifindex).ok_or_else(unavailable)?;
        if managed.name != device.name
            || managed.cleanup_only
            || managed.successor_pending
            || managed
                .grouped
                .and_then(|grouped| grouped.local_endpoints.ipv4())
                != Some(local)
        {
            return Err(unavailable());
        }
        let slot = Arc::clone(&managed.control_socket);
        drop(devices);
        if self.inner.runtime.ifindex_by_name(&device.name)? != device.ifindex
            || !self
                .inner
                .runtime
                .pdp_readback_datapath_usable(device.ifindex)
        {
            slot.lock().map_err(|_| unavailable())?.retire();
            return Err(unavailable());
        }
        let mut state = slot.lock().map_err(|_| unavailable())?;
        if state.retired {
            return Err(unavailable());
        }
        if state.socket.is_none() {
            state.socket = Some(
                crate::GtpuReassemblySocket::bind(local, &device.name)
                    .map_err(|_| unavailable())?,
            );
        }
        let socket = state.socket.as_ref().ok_or_else(unavailable)?;
        if !current() {
            return Err(unavailable());
        }
        socket
            .send_retired_n3_end_marker(local, peer, teid)
            .map_err(|_| unavailable())?;
        if !current() {
            return Err(unavailable());
        }
        Ok(())
    }

    pub(super) fn open_control_port_sync(
        &self,
        device: GtpDevice,
    ) -> Result<Arc<dyn GtpuControlPort>, GtpuError> {
        let _operation = self.operation_guard()?;
        let unavailable = || GtpuError::StateIndeterminate {
            operation: "ebpf_control_port_attachment",
        };
        let devices = self.devices()?;
        let managed = devices.get(&device.ifindex).ok_or(GtpuError::NotFound)?;
        if managed.name != device.name {
            return Err(GtpuError::NotFound);
        }
        if managed.cleanup_only || managed.successor_pending {
            return Err(unavailable());
        }
        let local_ip = managed
            .local_ip
            .or_else(|| {
                managed
                    .grouped
                    .and_then(|grouped| grouped.local_endpoints.ipv4())
            })
            .ok_or(GtpuError::UnsupportedFeature {
                feature: "gtpu_control_port_ipv6",
            })?;
        let slot = Arc::clone(&managed.control_socket);
        drop(devices);
        if self.inner.runtime.ifindex_by_name(&device.name)? != device.ifindex
            || !self
                .inner
                .runtime
                .pdp_readback_datapath_usable(device.ifindex)
        {
            slot.lock()
                .map_err(|_| GtpuError::io("ebpf_control_port_state", poisoned_lock()))?
                .retire();
            return Err(unavailable());
        }
        let mut socket = slot
            .lock()
            .map_err(|_| GtpuError::io("ebpf_control_port_state", poisoned_lock()))?;
        if socket.retired {
            return Err(unavailable());
        }
        if socket.socket.is_none() {
            // This is the sole backend-owned queue. An existing external
            // listener produces a normal bind error, never SO_REUSEPORT.
            socket.socket = Some(
                crate::GtpuReassemblySocket::bind(local_ip, &device.name)
                    .map_err(|error| GtpuError::io("ebpf_control_port_bind", error))?,
            );
        }
        Ok(Arc::new(BackendControlPort {
            backend: Arc::downgrade(&self.inner),
            socket: Arc::downgrade(&slot),
            ifindex: device.ifindex,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_port_does_not_wait_for_a_mutating_writer() {
        let backend = EbpfGtpuDataplaneBackend::new();
        let port = BackendControlPort {
            backend: Arc::downgrade(&backend.inner),
            socket: Weak::new(),
            ifindex: 731,
        };
        let guard = backend.operation_guard().unwrap();
        assert_eq!(
            port.try_receive_datagram(8).unwrap_err(),
            GtpuControlPortError::Busy
        );
        drop(guard);
        assert_eq!(
            port.try_receive_datagram(8).unwrap_err(),
            GtpuControlPortError::Unavailable
        );
        drop(backend);
        assert_eq!(
            port.try_receive_datagram(8).unwrap_err(),
            GtpuControlPortError::Unavailable
        );
    }

    #[test]
    fn downlink_consumer_is_serialized_with_attachment_mutation() {
        let backend = EbpfGtpuDataplaneBackend::new();
        let port = BackendControlPort {
            backend: Arc::downgrade(&backend.inner),
            socket: Weak::new(),
            ifindex: 731,
        };
        let guard = backend.operation_guard().unwrap();
        assert_eq!(
            port.try_receive_downlink(2048).unwrap_err(),
            GtpuControlPortError::Busy
        );
        assert_eq!(
            port.downlink_counters().unwrap_err(),
            GtpuControlPortError::Busy
        );
        drop(guard);
        assert_eq!(
            port.try_receive_downlink(2048).unwrap_err(),
            GtpuControlPortError::Unavailable
        );
        drop(backend);
        assert_eq!(
            port.try_receive_downlink(2048).unwrap_err(),
            GtpuControlPortError::Unavailable
        );
    }

    #[test]
    fn poisoned_backend_cannot_receive_or_publish_a_port() {
        let backend = EbpfGtpuDataplaneBackend::new();
        let port = BackendControlPort {
            backend: Arc::downgrade(&backend.inner),
            socket: Weak::new(),
            ifindex: 731,
        };
        let inner = Arc::clone(&backend.inner);
        assert!(std::thread::spawn(move || {
            let _guard = inner.operation_lock.lock().unwrap();
            panic!("synthetic writer failure");
        })
        .join()
        .is_err());
        assert_eq!(
            port.try_receive_datagram(8).unwrap_err(),
            GtpuControlPortError::Unavailable
        );
        assert!(backend
            .open_control_port_sync(GtpDevice {
                name: "sentinel".into(),
                ifindex: 731
            })
            .is_err());
    }
}
