//! Non-clone socket owner for the kernel fence lifecycle.

use std::{cell::Cell, fmt, io, net::SocketAddr};

#[cfg(test)]
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use opc_runtime::{
    UdpDestinationMetadataSocket, UdpDestinationMetadataSupport, UdpReceivedDatagram,
};
use opc_session_store::{LeaseGuard, OwnerId, SessionKey};

use crate::lifecycle::{
    EgressFenceLeaseAuthority, FenceError, LeaseBoundFence, LeaseFenceError, LeaseFenceTiming,
    RenewalWait,
};

/// UDP socket whose only send path is protected by the lease-bound kernel
/// fence.
///
/// The wrapper is intentionally non-clone, is not [`Sync`], requires exclusive
/// mutable access for both receive and send, and never exposes its raw socket,
/// file descriptor, cookie, or inner fence. Move it into one guardian task and
/// route every inbound and outbound operation through that task's supervised
/// channel.
///
/// ```compile_fail
/// use std::sync::Arc;
/// use opc_egress_fence::FencedUdpSocket;
///
/// fn require_send<T: Send>() {}
/// require_send::<Arc<FencedUdpSocket>>();
/// ```
///
/// Forking after construction, descriptor duplication, descriptor passing,
/// and constructing any alternate sender for the protected local endpoint are
/// forbidden. Linux does not promise eternal `SO_COOKIE` non-reuse; safe
/// tombstone reclamation therefore depends on this wrapper's exclusive fd
/// ownership and close-before-reclaim ordering. Admission requires an
/// unconnected exact bind with `SO_REUSEADDR`, `SO_REUSEPORT`, `FREEBIND`, and
/// `TRANSPARENT` disabled; IPv6 additionally requires `IPV6_V6ONLY`.
/// A production loader must create and immediately consume the socket because
/// Linux has no race-free API that proves a file description was never
/// duplicated before admission.
pub struct FencedUdpSocket {
    socket: Option<UdpDestinationMetadataSocket>,
    fence: LeaseBoundFence,
    protected_local_endpoint: SocketAddr,
    #[cfg(test)]
    send_barrier: Option<Arc<TestSendBarrier>>,
    // A fenced socket is movable into its one guardian, but cannot be shared
    // through Arc or references between concurrent tasks.
    _guardian_exclusive: Cell<()>,
}

impl FencedUdpSocket {
    pub(crate) fn from_unregistered(
        socket: UdpDestinationMetadataSocket,
        fence: LeaseBoundFence,
        protected_local_endpoint: SocketAddr,
    ) -> Result<Self, FenceError> {
        if !valid_protected_local_endpoint(protected_local_endpoint)
            || !exclusive_unconnected_socket(&socket)
            || socket
                .local_addr()
                .map_or(true, |actual| actual != protected_local_endpoint)
        {
            return Err(FenceError::KernelReadback);
        }
        Ok(Self {
            socket: Some(socket),
            fence,
            protected_local_endpoint,
            #[cfg(test)]
            send_barrier: None,
            _guardian_exclusive: Cell::new(()),
        })
    }

    /// Return whether durable authority and the kernel gate were activated.
    ///
    /// This is informational only. The root cgroup classifier independently
    /// evaluates every packet against its suspend-aware deadline.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.socket.is_some() && self.fence.is_active()
    }

    /// Return the local socket address.
    ///
    /// # Errors
    ///
    /// Returns a value-free `NotConnected` error after terminal closure, or
    /// the operating-system query error.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.live_socket()?.local_addr()
    }

    /// Report the destination-metadata mechanism of the owned socket.
    ///
    /// # Errors
    ///
    /// Returns a value-free `NotConnected` error after terminal closure.
    pub fn destination_metadata_support(&self) -> io::Result<UdpDestinationMetadataSupport> {
        Ok(self.live_socket()?.destination_metadata_support())
    }

    /// Receive one datagram with its concrete local-destination metadata.
    ///
    /// # Errors
    ///
    /// Returns a value-free `NotConnected` error after terminal closure, or a
    /// receive error from the runtime socket.
    pub(crate) async fn recv_from_with_destination(
        &mut self,
        buffer: &mut [u8],
    ) -> io::Result<UdpReceivedDatagram> {
        self.live_socket()?.recv_from_with_destination(buffer).await
    }

    /// Send one datagram from the immutable protected local source.
    ///
    /// A userspace-active state only permits the syscall. Callers cannot supply
    /// or override the packet-info source. The root cgroup gate still
    /// independently requires the full-width socket cookie, current durable
    /// token, attachment identity, and BOOTTIME deadline.
    ///
    /// # Errors
    ///
    /// Returns a value-free `PermissionDenied` error before activation or
    /// after terminal closure, otherwise the runtime socket's send error.
    pub(crate) async fn send_to(&mut self, buffer: &[u8], peer: SocketAddr) -> io::Result<usize> {
        if self.fence.preflight_send().is_err() {
            self.close_socket();
            return Err(socket_error(
                io::ErrorKind::PermissionDenied,
                "egress_fence_send_preflight",
            ));
        }
        #[cfg(test)]
        if let Some(barrier) = self.send_barrier.as_ref() {
            barrier.pause().await;
        }
        self.live_socket()?
            .send_to_from(buffer, peer, self.protected_local_endpoint)
            .await
    }

    /// Acquire durable authority and activate this socket.
    ///
    /// The socket file descriptor and kernel cookie are synchronously closed
    /// on authority failure, clock failure, cancellation after polling, or any
    /// kernel ambiguity.
    pub(crate) async fn acquire<A>(
        &mut self,
        authority: &A,
        key: &SessionKey,
        owner: OwnerId,
        timing: LeaseFenceTiming,
    ) -> Result<LeaseGuard, LeaseFenceError<A::Error>>
    where
        A: EgressFenceLeaseAuthority + ?Sized,
    {
        let mut close_on_failure = SocketCloseOnDrop::new(&mut self.socket);
        let result = self.fence.acquire(authority, key, owner, timing).await;
        if result.is_ok() {
            close_on_failure.disarm();
        }
        result
    }

    /// Renew durable authority and refresh the kernel deadline.
    ///
    /// This consumes the prior guard. The returned guard must replace it; every
    /// synchronous failure returns the exact unreleased guard inside
    /// [`LeaseFenceError`]. Failure and cancellation terminal-close the kernel
    /// entry and socket fd without releasing durable authority.
    pub(crate) async fn renew<A>(
        &mut self,
        authority: &A,
        current: LeaseGuard,
        timing: LeaseFenceTiming,
    ) -> Result<LeaseGuard, LeaseFenceError<A::Error>>
    where
        A: EgressFenceLeaseAuthority + ?Sized,
    {
        let mut close_on_failure = SocketCloseOnDrop::new(&mut self.socket);
        let result = self.fence.renew(authority, current, timing).await;
        if result.is_ok() {
            close_on_failure.disarm();
        }
        result
    }

    /// Build an owned suspend-aware wait for this socket's next safe renewal
    /// point.
    ///
    /// The wait is derived from the operation-start-based kernel deadline, not
    /// from userspace completion time. It therefore becomes immediately ready
    /// after a near-budget acquisition and reports expiry after a suspend that
    /// crosses the kernel deadline.
    pub(crate) fn renewal_wait(
        &mut self,
        timing: LeaseFenceTiming,
    ) -> Result<RenewalWait, FenceError> {
        self.fence.renewal_wait(timing)
    }

    #[cfg(test)]
    pub(crate) fn set_send_barrier(&mut self, barrier: Arc<TestSendBarrier>) {
        self.send_barrier = Some(barrier);
    }

    #[cfg(test)]
    pub(crate) fn test_drop_private_mutation_program_fd(&self) -> Result<(), FenceError> {
        self.fence.test_drop_private_mutation_program_fd()
    }

    #[cfg(test)]
    pub(crate) fn test_drop_private_view_program_fd(&self) -> Result<(), FenceError> {
        self.fence.test_drop_private_view_program_fd()
    }

    /// Close/read back the kernel gate, close the socket fd, publish the
    /// pre-reserved retirement token, reclaim the now-noncurrent tuple, then
    /// release durable authority.
    ///
    /// If kernel closure is uncertain, the authority is not contacted and the
    /// returned error retains the unreleased guard for conservative expiry
    /// handling. Cancellation during authority release is safe because both
    /// kernel gate and fd are already closed.
    pub(crate) async fn close_then_release<A>(
        &mut self,
        authority: &A,
        lease: LeaseGuard,
    ) -> Result<(), RetireFenceError<A::Error>>
    where
        A: EgressFenceLeaseAuthority + ?Sized,
    {
        let pending = match self.fence.prepare_release(&lease) {
            Ok(pending) => pending,
            Err(error) => {
                self.close_socket();
                return Err(RetireFenceError::Fence { error, lease });
            }
        };
        self.close_socket();
        let evidence = match self.fence.reclaim_after_socket_close(pending) {
            Ok(evidence) => evidence,
            Err(error) => return Err(RetireFenceError::Fence { error, lease }),
        };
        authority
            .release_with_terminal(lease, evidence)
            .await
            .map_err(RetireFenceError::Authority)
    }

    fn live_socket(&self) -> io::Result<&UdpDestinationMetadataSocket> {
        self.socket
            .as_ref()
            .ok_or_else(|| socket_error(io::ErrorKind::NotConnected, "egress_fence_socket_closed"))
    }

    fn close_socket(&mut self) {
        drop(self.socket.take());
    }
}

#[cfg(test)]
pub(crate) struct TestSendBarrier {
    entered: AtomicBool,
    released: AtomicBool,
    entered_notification: tokio::sync::Notify,
    release_notification: tokio::sync::Notify,
}

#[cfg(test)]
impl TestSendBarrier {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: AtomicBool::new(false),
            released: AtomicBool::new(false),
            entered_notification: tokio::sync::Notify::new(),
            release_notification: tokio::sync::Notify::new(),
        })
    }

    async fn pause(&self) {
        self.entered.store(true, Ordering::Release);
        self.entered_notification.notify_waiters();
        while !self.released.load(Ordering::Acquire) {
            self.release_notification.notified().await;
        }
    }

    pub(crate) async fn wait_until_entered(&self) {
        while !self.entered.load(Ordering::Acquire) {
            self.entered_notification.notified().await;
        }
    }

    pub(crate) fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.release_notification.notify_waiters();
    }
}

impl fmt::Debug for FencedUdpSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FencedUdpSocket")
            .field("socket_open", &self.socket.is_some())
            .field("active", &self.is_active())
            .field("protected_local_endpoint_present", &true)
            .finish()
    }
}

impl Drop for FencedUdpSocket {
    fn drop(&mut self) {
        let _ = self.fence.terminal_close();
        self.close_socket();
    }
}

/// Orderly-retirement failure.
pub enum RetireFenceError<E> {
    /// Kernel closure was not proven. The guard is retained and was not
    /// released.
    Fence {
        /// Value-free fence failure.
        error: FenceError,
        /// Unreleased durable guard.
        lease: LeaseGuard,
    },
    /// Kernel and fd were closed, but durable release failed or became
    /// uncertain.
    Authority(E),
}

impl<E> RetireFenceError<E> {
    /// Recover the unreleased guard only when kernel closure failed.
    pub fn into_unreleased_lease(self) -> Option<LeaseGuard> {
        match self {
            Self::Fence { lease, .. } => Some(lease),
            Self::Authority(_) => None,
        }
    }

    /// Return the value-free fence error when closure was not proven.
    #[must_use]
    pub const fn fence_error(&self) -> Option<FenceError> {
        match self {
            Self::Fence { error, .. } => Some(*error),
            Self::Authority(_) => None,
        }
    }
}

impl<E> fmt::Debug for RetireFenceError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fence { error, .. } => formatter
                .debug_struct("RetireFenceError::Fence")
                .field("error", error)
                .field("lease", &"<redacted>")
                .finish(),
            Self::Authority(_) => formatter.write_str("RetireFenceError::Authority(<redacted>)"),
        }
    }
}

impl<E> fmt::Display for RetireFenceError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fence { error, .. } => fmt::Display::fmt(error, formatter),
            Self::Authority(_) => formatter.write_str("egress_fence_authority_release"),
        }
    }
}

impl<E> std::error::Error for RetireFenceError<E> where E: Send + Sync + 'static {}

struct SocketCloseOnDrop<'a> {
    socket: &'a mut Option<UdpDestinationMetadataSocket>,
    armed: bool,
}

impl<'a> SocketCloseOnDrop<'a> {
    fn new(socket: &'a mut Option<UdpDestinationMetadataSocket>) -> Self {
        Self {
            socket,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SocketCloseOnDrop<'_> {
    fn drop(&mut self) {
        if self.armed {
            drop(self.socket.take());
        }
    }
}

fn socket_error(kind: io::ErrorKind, code: &'static str) -> io::Error {
    io::Error::new(kind, code)
}

fn exclusive_unconnected_socket(socket: &UdpDestinationMetadataSocket) -> bool {
    #[cfg(target_os = "linux")]
    {
        socket.verify_fence_admission().is_ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

fn valid_protected_local_endpoint(endpoint: SocketAddr) -> bool {
    if endpoint.port() == 0 || endpoint.ip().is_unspecified() || endpoint.ip().is_multicast() {
        return false;
    }
    match endpoint {
        SocketAddr::V4(address) => !address.ip().is_broadcast(),
        SocketAddr::V6(address) => {
            address.ip().to_ipv4_mapped().is_none()
                && !address.ip().is_unicast_link_local()
                && address.scope_id() == 0
                && address.flowinfo() == 0
        }
    }
}

#[cfg(test)]
mod source_contract_tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn protected_endpoint_must_be_canonical_nonzero_unicast() {
        let valid_v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 41), 31_337));
        let valid_v6 = SocketAddr::V6(SocketAddrV6::new(
            "2001:db8:0:7::41".parse().expect("documentation IPv6"),
            31_337,
            0,
            0,
        ));
        assert!(valid_protected_local_endpoint(valid_v4));
        assert!(valid_protected_local_endpoint(valid_v6));

        for invalid in [
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 31_337)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 41), 0)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 1), 31_337)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, 31_337)),
            SocketAddr::V6(SocketAddrV6::new(
                "::ffff:192.0.2.41".parse().expect("mapped fixture"),
                31_337,
                0,
                0,
            )),
            SocketAddr::V6(SocketAddrV6::new(
                "fe80::41".parse().expect("link-local fixture"),
                31_337,
                0,
                7,
            )),
            SocketAddr::V6(SocketAddrV6::new(
                "2001:db8:0:7::41".parse().expect("scoped global fixture"),
                31_337,
                0,
                7,
            )),
            SocketAddr::V6(SocketAddrV6::new(
                "2001:db8:0:7::41".parse().expect("flow-labelled fixture"),
                31_337,
                1,
                0,
            )),
        ] {
            assert!(!valid_protected_local_endpoint(invalid));
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn runtime_bind_is_exclusive_and_exposes_no_raw_send_surface() {
        use opc_runtime::bind_udp_socket_with_destination_metadata;

        let exclusive = bind_udp_socket_with_destination_metadata(
            "127.0.0.1:0".parse().expect("loopback fixture"),
        )
        .expect("exclusive bound socket");
        assert!(exclusive_unconnected_socket(&exclusive));
    }
}
