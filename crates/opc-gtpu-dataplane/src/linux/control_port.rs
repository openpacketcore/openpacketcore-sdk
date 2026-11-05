//! Attachment-bound control receive and Error Indication response surface for
//! the retained Linux kernel-GTP userspace socket.
//!
//! The Linux `gtp` driver passes every datagram that is not a G-PDU and every
//! G-PDU it declines back to the userspace socket passed as `IFLA_GTP_FD1`,
//! including known TEIDs with an incorrect inner MS binding. Stable backend
//! PDP readback must establish absence before reporting `UnknownTunnel`.
//! This port exposes that queue without creating, duplicating or
//! rebinding a socket: the backend's retained descriptor stays the only
//! socket owner, and every received datagram, response plan and operation is
//! bound to this exact attachment generation.
//!
//! Receipt is an observation. It does not authorize a tunnel, a peer, a PDP
//! context or an automatic answer: the caller decides whether the G-PDU really
//! has no tunnel and whether to plan one Error Indication. Controls, unmodelled
//! messages and unsupported-required-extension events are returned as
//! `Control` (so the existing notification planners still work); only
//! malformed framing is a drop. Receive and classification are serialized
//! per attachment: contention returns `Busy` before dequeue. Responses do not
//! contend with receive or PDP observation. A response pins its IP source with an `IP_PKTINFO`
//! cmsg to the original local destination, so a wildcard bind on a multi-homed
//! endpoint keeps the packet's ingress address.

use super::*;
use crate::control_port::{
    socket_io, GtpuControlDatagram, GtpuControlPort, GtpuControlPortError, GtpuControlProvenance,
    GtpuControlSendPlan, GTPU_CONTROL_MAX_DATAGRAM,
};
use crate::GtpuDownlinkEvent;
use bytes::Bytes;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::{Arc, Weak};

/// Backend-owned control port over one retained Linux kernel-GTP socket.
pub(super) struct LinuxControlPort {
    backend: Weak<LinuxGtpuDataplaneBackendInner>,
    slot: Arc<ControlSlot>,
}

impl fmt::Debug for LinuxControlPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LinuxControlPort(<redacted>)")
    }
}

fn unavailable() -> GtpuControlPortError {
    GtpuControlPortError::Unavailable
}

fn io_error(error: std::io::Error) -> GtpuControlPortError {
    error.into()
}

/// Open (or re-open) the shared control queue of one retained userspace socket.
///
/// Reopening shares the same socket and attachment generation. Only an
/// ordinary creation retains a userspace descriptor; a recoverable kernel-
/// owned attachment has no userspace queue and remains unsupported.
pub(super) fn open(
    backend: &LinuxGtpuDataplaneBackend,
    device: GtpDevice,
) -> Result<Arc<dyn GtpuControlPort>, GtpuError> {
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
        // An unattached backend has no qualified control-port capability,
        // preserving the trait's fail-closed unsupported contract.
        return Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_control_port",
        });
    };
    if owned.name != device.name {
        return Err(GtpuError::NotFound);
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
        if backend.inner.transport.ifindex_by_name(&owned.name).ok() != Some(device.ifindex)
            || socket_address(fd).ok() != Some(SocketAddr::new(owned.bind_address, owned.bind_port))
        {
            drop(backend.retire_control_port_locked(device.ifindex));
            return Err(GtpuError::StateIndeterminate {
                operation: "gtpu_control_port_attachment",
            });
        }
        socket_io::set_packet_info(fd, owned.bind_address.is_ipv6())
            .map_err(|error| GtpuError::io("gtpu_control_port_packet_info", error))?;
        let cookie = handle
            .socket_cookie()
            .map_err(|error| GtpuError::io("gtpu_control_port_identity", error))?;
        (Some(cookie), Arc::new(()))
    } else {
        (None, Arc::new(()))
    };
    // Registry publication uses device_sockets, then control_ports. Live I/O
    // pins its descriptor through this slot without retaining either lock.
    let mut ports = backend
        .inner
        .control_ports
        .lock()
        .map_err(|_| GtpuError::io("gtpu_control_port_state", poisoned_lock()))?;
    if let Some(current) = ports.get(&device.ifindex).filter(|slot| {
        slot.active.load(Ordering::Acquire)
            && slot.name == owned.name
            && slot.namespace == owned.namespace
            && slot.bind_address == owned.bind_address
            && slot.bind_port == owned.bind_port
            && slot.socket_cookie == socket_cookie
            && slot.socket.ptr_eq(&Arc::downgrade(handle))
    }) {
        return Ok(Arc::new(LinuxControlPort {
            backend: Arc::downgrade(&backend.inner),
            slot: Arc::clone(current),
        }));
    }
    let slot = Arc::new(ControlSlot {
        ifindex: device.ifindex,
        name: owned.name.clone(),
        namespace: owned.namespace,
        bind_address: owned.bind_address,
        bind_port: owned.bind_port,
        socket_cookie,
        socket: Arc::downgrade(handle),
        identity,
        active: AtomicBool::new(true),
        operations: std::sync::RwLock::new(()),
        receive: Mutex::new(()),
        #[cfg(test)]
        after_receive: Mutex::new(None),
    });
    if let Some(previous) = ports.insert(device.ifindex, Arc::clone(&slot)) {
        previous.active.store(false, Ordering::SeqCst);
    }
    drop(sockets);
    Ok(Arc::new(LinuxControlPort {
        backend: Arc::downgrade(&backend.inner),
        slot,
    }))
}

/// Pin and verify this attachment's exact socket for one operation. No
/// backend-wide registry guard is held across socket I/O or PDP observation.
fn with_binding<T>(
    port: &LinuxControlPort,
    operation: impl FnOnce(
        &LinuxGtpuDataplaneBackend,
        &ControlSlot,
        SocketAddr,
        BorrowedFd<'_>,
    ) -> Result<T, GtpuControlPortError>,
) -> Result<T, GtpuControlPortError> {
    let inner = port.backend.upgrade().ok_or_else(unavailable)?;
    let backend = LinuxGtpuDataplaneBackend { inner };
    // Only retirement takes the write guard, after announcing active=false.
    // Therefore a failed acquisition is a lost binding, never retryable Busy.
    // In particular, sending an affine plan cannot lose it to receive contention.
    let _operation = port.slot.operations.try_read().map_err(|_| unavailable())?;
    let handle = port.slot.socket.upgrade().ok_or_else(unavailable)?;
    let fd = handle.linux_as_fd().ok_or_else(unavailable)?;
    let local = SocketAddr::new(port.slot.bind_address, port.slot.bind_port);
    let verify = || {
        let matches = port.slot.active.load(Ordering::Acquire)
            && !backend.inner.device_sockets.is_poisoned()
            && !backend.inner.control_ports.is_poisoned()
            && backend.inner.transport.current_namespace_identity().ok() == port.slot.namespace
            && backend
                .inner
                .transport
                .ifindex_by_name(&port.slot.name)
                .ok()
                == Some(port.slot.ifindex)
            && socket_address(fd).ok() == Some(local)
            && handle.socket_cookie().ok() == port.slot.socket_cookie;
        if matches {
            Ok(())
        } else {
            port.slot.active.store(false, Ordering::Release);
            Err(unavailable())
        }
    };
    verify()?;
    let result = operation(&backend, &port.slot, local, fd);
    verify()?;
    result
}

fn receive_guard(
    port: &LinuxControlPort,
) -> Result<std::sync::MutexGuard<'_, ()>, GtpuControlPortError> {
    match port.slot.receive.try_lock() {
        Ok(guard) => Ok(guard),
        Err(std::sync::TryLockError::WouldBlock) => Err(GtpuControlPortError::Busy),
        Err(std::sync::TryLockError::Poisoned(_)) => Err(unavailable()),
    }
}

fn socket_address(fd: BorrowedFd<'_>) -> std::io::Result<SocketAddr> {
    use nix::sys::socket::{getsockname, SockaddrStorage};
    let address = getsockname::<SockaddrStorage>(fd.as_raw_fd()).map_err(std::io::Error::from)?;
    if let Some(v4) = address.as_sockaddr_in() {
        return Ok((*v4).into());
    }
    if let Some(v6) = address.as_sockaddr_in6() {
        return Ok((*v6).into());
    }
    Err(std::io::Error::from(std::io::ErrorKind::InvalidData))
}

fn receive_bound(
    slot: &ControlSlot,
    bound: SocketAddr,
    fd: BorrowedFd<'_>,
    buffer: &mut [u8],
    consumed: &mut bool,
) -> Result<Option<GtpuControlDatagram>, GtpuControlPortError> {
    let Some(received) = socket_io::receive_tracked(
        fd,
        buffer,
        nix::sys::socket::MsgFlags::MSG_DONTWAIT,
        consumed,
    )?
    else {
        return Ok(None);
    };
    if !bound.ip().is_unspecified() && bound.ip() != received.local {
        return Err(unavailable());
    }
    // Packet info identifies the arrival path, not the kernel GTP device.
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
    Ok(Some(GtpuControlDatagram::received(
        Bytes::copy_from_slice(&buffer[..received.length]),
        provenance,
        Arc::clone(&slot.identity),
    )))
}

/// Require two equal reads in each inner-family table. The received payload
/// cannot choose which table owns its TEID (TS 29.281 sections 6 and 7.3.1).
fn context_absent(
    backend: &LinuxGtpuDataplaneBackend,
    slot: &ControlSlot,
    teid: Teid,
) -> Result<bool, GtpuError> {
    // All netlink sockets are nonblocking. One receive attempt with no delay
    // either supplies immediate evidence or fails closed; the try-call never
    // waits for a response and never takes the PDP mutation mutex.
    let config = LinuxGtpuDataplaneBackendConfig {
        receive_attempts: 1,
        retry_delay: Duration::ZERO,
        ..backend.inner.config
    };
    let family_id = backend.resolve_gtp_family_id_with_config(config)?;
    let mut absent = true;
    for family in [GtpAddressFamily::Ipv4, GtpAddressFamily::Ipv6] {
        let selector = PdpContextSelector::LocalTeid(
            PdpContextLocalTeidSelector::new(slot.ifindex, GtpVersion::V1, family, teid).ok_or(
                GtpuError::StateIndeterminate {
                    operation: "gtpu_control_port_attachment",
                },
            )?,
        );
        let readback = backend.get_pdp_context_stable_with_config(family_id, &selector, config)?;
        absent &= matches!(readback, PdpContextReadback::Absent);
    }
    Ok(absent)
}

impl GtpuControlPort for LinuxControlPort {
    fn send_echo_request(
        &self,
        source: SocketAddr,
        peer: SocketAddr,
        sequence: u16,
    ) -> Result<usize, GtpuControlPortError> {
        with_binding(self, |_, _slot, local, fd| {
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
        let _receive = receive_guard(self)?;
        let mut buffer = vec![0_u8; maximum_bytes];
        let mut consumed = false;
        with_binding(self, |_, slot, bound, fd| {
            receive_bound(slot, bound, fd, &mut buffer, &mut consumed)
        })
    }

    fn send_control_response(
        &self,
        plan: GtpuControlSendPlan,
    ) -> Result<usize, GtpuControlPortError> {
        if !Arc::ptr_eq(&plan.socket_identity, &self.slot.identity) {
            return Err(GtpuControlPortError::SocketMismatch);
        }
        with_binding(self, |_, _slot, local, fd| {
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
        if !(8..=GTPU_CONTROL_MAX_DATAGRAM).contains(&maximum_bytes) {
            return Err(GtpuControlPortError::InvalidLimits);
        }
        // This is the only acquisition that can return Busy, before recvmsg.
        let _receive = receive_guard(self)?;
        let mut buffer = vec![0_u8; maximum_bytes];
        let mut consumed = false;
        let result = with_binding(self, |backend, slot, bound, fd| {
            let Some(datagram) = receive_bound(slot, bound, fd, &mut buffer, &mut consumed)? else {
                return Ok(None);
            };
            #[cfg(test)]
            if let Some(hook) = slot.after_receive.lock().unwrap().clone() {
                hook();
            }
            let event = crate::control_port::downlink_event(datagram);
            let GtpuDownlinkEvent::UnknownTunnel(datagram) = event else {
                return Ok(Some(event));
            };
            let teid = datagram
                .received_teid()
                .and_then(|value| Teid::new(value.get()))
                .ok_or_else(unavailable)?;
            // A known TEID may reach this socket because the driver declined
            // its inner binding. Preserve framing and never infer authority
            // from that untrusted payload's IP-version nibble.
            let outcome = match context_absent(backend, slot, teid) {
                Ok(true) => GtpuDownlinkEvent::UnknownTunnel(datagram),
                Ok(false) => {
                    GtpuDownlinkEvent::Dropped(crate::GtpuDownlinkDrop::DestinationMismatch)
                }
                Err(_) => GtpuDownlinkEvent::Dropped(crate::GtpuDownlinkDrop::StateUnavailable),
            };
            Ok(Some(outcome))
        });
        match result {
            Err(GtpuControlPortError::Unavailable) if consumed => Ok(Some(
                GtpuDownlinkEvent::Dropped(crate::GtpuDownlinkDrop::StateUnavailable),
            )),
            outcome => outcome,
        }
    }
}
