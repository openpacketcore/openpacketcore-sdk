//! Attachment-bound control receive and Error Indication response surface for
//! the retained Linux kernel-GTP userspace socket.
//!
//! The Linux `gtp` driver passes every datagram that is not a G-PDU and every
//! G-PDU whose TEID selects no PDP context back to the userspace socket passed
//! as `IFLA_GTP_FD1`. That is exactly the TS 29.281 7.3.1 unknown-tunnel
//! trigger. This port exposes that queue without creating, duplicating or
//! rebinding a socket: the backend's retained descriptor stays the only
//! socket owner, and every received datagram, response plan and operation is
//! bound to this exact attachment generation.
//!
//! Receipt is an observation. It does not authorize a tunnel, a peer, a PDP
//! context or an automatic answer: the caller decides whether the G-PDU really
//! has no tunnel and whether to plan one Error Indication. Controls, unmodelled
//! messages and unsupported-required-extension events are returned as
//! `Control` (so the existing notification planners still work); only
//! malformed framing is a drop. Receive and response are non-blocking with
//! respect to attachment mutation: contention returns the typed `Busy`
//! outcome. A response pins its transmitted IP source with an `IP_PKTINFO`
//! cmsg to the original local destination, so a wildcard bind on a multi-homed
//! endpoint keeps the packet's ingress address.

use super::*;
use crate::control_port::{socket_io, GtpuControlProvenance};
use crate::control_port::{
    GtpuControlDatagram, GtpuControlPort, GtpuControlPortError, GtpuControlSendPlan,
    GTPU_CONTROL_MAX_DATAGRAM,
};
use crate::GtpuDownlinkEvent;
use bytes::Bytes;
use std::net::SocketAddr;
use std::os::fd::BorrowedFd;
use std::sync::{Arc, Weak};

/// Backend-owned control port over one retained Linux kernel-GTP socket.
pub(super) struct LinuxControlPort {
    backend: Weak<LinuxGtpuDataplaneBackendInner>,
    slot: Arc<ControlSlot>,
}

impl fmt::Debug for LinuxControlPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxControlPort")
            .field("ifindex", &self.slot.ifindex)
            .field("values", &"<redacted>")
            .finish()
    }
}

fn io_error(error: std::io::Error) -> GtpuControlPortError {
    error.into()
}

/// Open (or re-open) the shared control queue of one retained userspace socket.
///
/// Reopening shares the same socket but publishes a new attachment generation
/// and retires the previous slot (single-consumer semantics); it never binds,
/// duplicates or reopens a descriptor. A concurrent attachment mutation makes
/// this return a typed `WouldBlock` I/O class instead of waiting. Only an
/// ordinary (non-recoverable) creation keeps a userspace descriptor: a
/// kernel-owned recoverable attachment has no userspace queue and returns
/// `UnsupportedFeature`.
pub(super) fn open(
    backend: &LinuxGtpuDataplaneBackend,
    device: GtpDevice,
) -> Result<Arc<dyn GtpuControlPort>, GtpuError> {
    let _operation = match backend.inner.pdp_operation_lock.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::WouldBlock) => {
            return Err(GtpuError::io(
                "gtpu_control_port_open",
                std::io::Error::from(std::io::ErrorKind::WouldBlock),
            ));
        }
        Err(std::sync::TryLockError::Poisoned(_)) => {
            return Err(GtpuError::io("gtpu_control_port_open", poisoned_lock()));
        }
    };
    let sockets = backend
        .inner
        .device_sockets
        .lock()
        .map_err(|_| GtpuError::io("gtpu_control_port_state", poisoned_lock()))?;
    let Some(owned) = sockets.userspace.get(&device.ifindex) else {
        if sockets
            .kernel
            .iter()
            .any(|(ifindex, _)| *ifindex == device.ifindex)
        {
            return Err(GtpuError::UnsupportedFeature {
                feature: "gtpu_control_port_kernel_owned",
            });
        }
        return Err(GtpuError::NotFound);
    };
    if owned.name != device.name {
        return Err(GtpuError::NotFound);
    }
    if backend.inner.transport.ifindex_by_name(&device.name).ok() != Some(device.ifindex) {
        return Err(GtpuError::StateIndeterminate {
            operation: "gtpu_control_port_attachment",
        });
    }
    let namespace = backend.inner.transport.current_namespace_identity().ok();
    if owned.namespace.is_none() || owned.namespace != namespace {
        return Err(GtpuError::StateIndeterminate {
            operation: "gtpu_control_port_attachment",
        });
    }
    if owned.bind_port != GTPU_PORT {
        return Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_control_port_port",
        });
    }
    let OwnedGtpuSocket::Userspace(handle) = &owned.socket else {
        return Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_control_port_kernel_owned",
        });
    };
    let (socket_cookie, identity) = if handle.is_real() {
        let fd = handle.linux_as_fd().ok_or(GtpuError::UnsupportedFeature {
            feature: "gtpu_control_port",
        })?;
        socket_io::set_packet_info(fd, owned.bind_address.is_ipv6())
            .map_err(|error| GtpuError::io("gtpu_control_port_packet_info", error))?;
        let cookie = opc_linux_gtpu_sys::socket_kernel_identity(fd)
            .map(|identity| identity.socket_cookie())
            .map_err(|error| GtpuError::io("gtpu_control_port_identity", error))?;
        (Some(cookie), Arc::new(()))
    } else {
        (None, Arc::new(()))
    };
    let slot = Arc::new(ControlSlot {
        ifindex: device.ifindex,
        name: owned.name.clone(),
        namespace: owned.namespace,
        bind_address: owned.bind_address,
        bind_port: owned.bind_port,
        socket_cookie,
        identity,
        active: AtomicBool::new(true),
    });
    // Lock order everywhere is device_sockets, then control_ports, so a
    // replacement cannot retire a slot while an operation holds the sockets.
    let mut ports = backend
        .inner
        .control_ports
        .lock()
        .map_err(|_| GtpuError::io("gtpu_control_port_state", poisoned_lock()))?;
    if let Some(previous) = ports.insert(device.ifindex, Arc::clone(&slot)) {
        previous.active.store(false, Ordering::SeqCst);
    }
    drop(sockets);
    Ok(Arc::new(LinuxControlPort {
        backend: Arc::downgrade(&backend.inner),
        slot,
    }))
}

/// Exact live socket binding for one operation, re-read under the backend's
/// device-socket lock and compared with the generation captured at open.
fn with_binding<T>(
    port: &LinuxControlPort,
    operation: impl FnOnce(&ControlSlot, SocketAddr, BorrowedFd<'_>) -> Result<T, GtpuControlPortError>,
) -> Result<T, GtpuControlPortError> {
    let unavailable = || {
        port.slot.active.store(false, Ordering::SeqCst);
        GtpuControlPortError::Unavailable
    };
    let inner = port.backend.upgrade().ok_or_else(unavailable)?;
    let backend = LinuxGtpuDataplaneBackend { inner };
    let _operation = match backend.inner.pdp_operation_lock.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::WouldBlock) => return Err(GtpuControlPortError::Busy),
        Err(std::sync::TryLockError::Poisoned(_)) => return Err(unavailable()),
    };
    let sockets = backend
        .inner
        .device_sockets
        .lock()
        .map_err(|_| unavailable())?;
    let owned = sockets
        .userspace
        .get(&port.slot.ifindex)
        .ok_or_else(unavailable)?;
    if owned.name != port.slot.name
        || owned.namespace != port.slot.namespace
        || owned.bind_address != port.slot.bind_address
        || owned.bind_port != port.slot.bind_port
    {
        return Err(unavailable());
    }
    if backend
        .inner
        .transport
        .ifindex_by_name(&port.slot.name)
        .ok()
        != Some(port.slot.ifindex)
    {
        return Err(unavailable());
    }
    let OwnedGtpuSocket::Userspace(handle) = &owned.socket else {
        return Err(unavailable());
    };
    let fd = handle.linux_as_fd().ok_or_else(unavailable)?;
    if handle.is_real() {
        let cookie = opc_linux_gtpu_sys::socket_kernel_identity(fd)
            .map(|identity| identity.socket_cookie())
            .map_err(|_| unavailable())?;
        if port.slot.socket_cookie != Some(cookie) {
            return Err(unavailable());
        }
    }
    if backend.inner.transport.current_namespace_identity().ok() != port.slot.namespace {
        return Err(unavailable());
    }
    {
        let ports = backend
            .inner
            .control_ports
            .lock()
            .map_err(|_| unavailable())?;
        match ports.get(&port.slot.ifindex) {
            Some(current)
                if Arc::ptr_eq(current, &port.slot) && port.slot.active.load(Ordering::SeqCst) => {}
            _ => return Err(unavailable()),
        }
    }
    operation(
        &port.slot,
        SocketAddr::new(port.slot.bind_address, port.slot.bind_port),
        fd,
    )
}

impl GtpuControlPort for LinuxControlPort {
    fn send_echo_request(
        &self,
        source: SocketAddr,
        peer: SocketAddr,
        sequence: u16,
    ) -> Result<usize, GtpuControlPortError> {
        with_binding(self, |_slot, local, fd| {
            if source.is_ipv4() != local.is_ipv4() {
                return Err(GtpuControlPortError::InvalidTuple);
            }
            if !local.ip().is_unspecified() && source != local {
                return Err(GtpuControlPortError::InvalidTuple);
            }
            let bytes = crate::control_port::echo_request_bytes(source, peer, sequence)?;
            socket_io::send(fd, source, peer, &bytes).map_err(io_error)
        })
    }

    fn try_receive_datagram(
        &self,
        maximum_bytes: usize,
    ) -> Result<Option<GtpuControlDatagram>, GtpuControlPortError> {
        if !(8..=GTPU_CONTROL_MAX_DATAGRAM).contains(&maximum_bytes) {
            return Err(GtpuControlPortError::InvalidLimits);
        }
        let mut buffer = vec![0_u8; maximum_bytes];
        with_binding(self, |slot, _local, fd| {
            let Some(received) =
                socket_io::receive(fd, &mut buffer, nix::sys::socket::MsgFlags::MSG_DONTWAIT)?
            else {
                return Ok(None);
            };
            // Kernel-GTP is not device-bound: pktinfo names the arrival path,
            // while the slot proves the tunnel attachment independently.
            let provenance = GtpuControlProvenance::new(
                received.peer,
                socket_io::local_tuple(received.local, GTPU_PORT, received.ifindex),
                received.ifindex,
            )
            .ok_or_else(|| {
                io_error(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "non-canonical provenance",
                ))
            })?;
            let bytes = Bytes::copy_from_slice(&buffer[..received.length]);
            Ok(Some(GtpuControlDatagram::received(
                bytes,
                provenance,
                Arc::clone(&slot.identity),
            )))
        })
    }

    fn send_control_response(
        &self,
        plan: GtpuControlSendPlan,
    ) -> Result<usize, GtpuControlPortError> {
        if !Arc::ptr_eq(&plan.socket_identity, &self.slot.identity) {
            return Err(GtpuControlPortError::SocketMismatch);
        }
        with_binding(self, |_slot, local, fd| {
            if plan.source.port() != GTPU_PORT
                || plan.source.is_ipv4() != local.is_ipv4()
                || (!local.ip().is_unspecified() && plan.source != local)
            {
                return Err(GtpuControlPortError::InvalidTuple);
            }
            socket_io::send(fd, plan.source, plan.peer, &plan.bytes).map_err(io_error)
        })
    }

    fn try_receive_downlink(
        &self,
        maximum_bytes: usize,
    ) -> Result<Option<GtpuDownlinkEvent>, GtpuControlPortError> {
        let Some(datagram) = self.try_receive_datagram(maximum_bytes)? else {
            return Ok(None);
        };
        Ok(Some(crate::control_port::downlink_event(datagram)))
    }
}
