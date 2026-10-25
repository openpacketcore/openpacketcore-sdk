//! SDK-owned readiness source for the backend-owned downlink queues.
//!
//! The control port keeps ownership of every receive socket. A readiness
//! source registers those sockets in a private epoll instance owned by the
//! SDK and exposes only that epoll descriptor, so a consumer can wait with
//! `epoll(7)`, `tokio::io::unix::AsyncFd` or [`GtpuControlReadiness::wait`]
//! without polling, and cannot read, close or duplicate a socket descriptor,
//! or bypass attachment invalidation.
//!
//! Readiness is advisory. It never consumes a datagram and grants no
//! forwarding authority; the consumer still calls
//! [`crate::control_port::GtpuControlPort::try_receive_downlink`] (or
//! `try_receive_datagram`) exactly as before, and the queue service order of
//! that call is unchanged.
//!
//! A readiness source is bound to one control port registration. When the
//! attachment is removed, replaced, fenced or its readback fails, the port
//! revokes every outstanding source: wait and receive return
//! [`GtpuControlPortError::Unavailable`] and the source never becomes
//! readable again. A consumer must drop the source and reopen the port through
//! the backend after a fresh registration.

use std::fmt;
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout};

use super::GtpuControlPortError;

/// One backend-owned downlink receive queue.
///
/// The variants name the same three queues that
/// [`crate::control_port::GtpuControlPort::try_receive_downlink`] serves, in
/// its service order: the shared UDP/2152 queue first, then the two hand-off
/// queues, which alternate between themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GtpuControlQueue {
    /// Shared UDP/2152 queue: Echo, reassembled outer-fragmented G-PDUs and
    /// unknown-TEID hand-offs.
    Shared,
    /// UDP/2153 queue for tc-steered over-MTU Don't Fragment G-PDUs.
    PacketTooBig,
    /// UDP/2154 queue for tc-steered inner-fragment G-PDUs.
    InnerFragment,
}

impl GtpuControlQueue {
    /// Every queue this SDK exposes, in downlink service order.
    pub const ALL: [Self; 3] = [Self::Shared, Self::PacketTooBig, Self::InnerFragment];

    const fn index(self) -> usize {
        match self {
            Self::Shared => 0,
            Self::PacketTooBig => 1,
            Self::InnerFragment => 2,
        }
    }

    const fn from_epoll_data(data: u64) -> Option<Self> {
        match data {
            0 => Some(Self::Shared),
            1 => Some(Self::PacketTooBig),
            2 => Some(Self::InnerFragment),
            _ => None,
        }
    }
}

/// Value-free readiness snapshot of the queues one source watches.
///
/// An empty snapshot means no queued datagram was reported at the instant of
/// the call. It reserves and consumes nothing, so a datagram reported ready
/// remains available to the matching receive call.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct GtpuDownlinkReadiness {
    bits: u8,
}

impl GtpuDownlinkReadiness {
    /// Whether no watched queue reported readiness.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    /// Whether `queue` reported readiness.
    #[must_use]
    pub const fn is_ready(self, queue: GtpuControlQueue) -> bool {
        self.bits & (1 << queue.index()) != 0
    }

    /// The ready queues, in [`GtpuControlQueue::ALL`] order.
    pub fn queues(self) -> impl Iterator<Item = GtpuControlQueue> {
        GtpuControlQueue::ALL
            .into_iter()
            .filter(move |queue| self.is_ready(*queue))
    }

    fn insert(&mut self, queue: GtpuControlQueue) {
        self.bits |= 1 << queue.index();
    }
}

impl fmt::Debug for GtpuDownlinkReadiness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_list()
            .entries(self.queues().map(|queue| format!("{queue:?}")))
            .finish()
    }
}

/// SDK-owned readiness source for one control port registration.
///
/// The handle owns only a private epoll instance; the port keeps ownership of
/// every socket. Use [`AsFd`] to register the SDK's epoll descriptor with the
/// consumer's own epoll instance or `tokio::io::unix::AsyncFd`. Every wake
/// must be consumed through [`Self::try_readiness`] (or [`Self::wait`]), which
/// also reports the queue classes that were ready; then drain with
/// `try_receive_downlink`, which preserves the existing queue priority.
///
/// Readiness does not consume a datagram and is not a readiness or forwarding
/// proof for any session. Attachment removal, replacement, readback failure or
/// fencing revokes the source: [`GtpuControlPortError::Unavailable`] is
/// returned and it never becomes readable again.
pub struct GtpuControlReadiness {
    inner: Arc<ReadinessInner>,
}

impl fmt::Debug for GtpuControlReadiness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuControlReadiness(<redacted>)")
    }
}

impl AsFd for GtpuControlReadiness {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.epoll.0.as_fd()
    }
}

impl GtpuControlReadiness {
    /// Create a source over `queues`, keeping a weak liveness token for an
    /// owner without an explicit revocation path.
    pub(crate) fn new<'a>(
        queues: impl IntoIterator<Item = (GtpuControlQueue, BorrowedFd<'a>)>,
        liveness: Option<Weak<()>>,
    ) -> Result<Self, GtpuControlPortError> {
        let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).map_err(|error| {
            GtpuControlPortError::Io {
                kind: std::io::Error::from(error).kind(),
            }
        })?;
        let mut watched = Vec::new();
        for (queue, descriptor) in queues {
            if watched.contains(&queue) {
                return Err(GtpuControlPortError::InvalidLimits);
            }
            let event = EpollEvent::new(EpollFlags::EPOLLIN, queue.index() as u64);
            epoll
                .add(descriptor, event)
                .map_err(|error| GtpuControlPortError::Io {
                    kind: std::io::Error::from(error).kind(),
                })?;
            watched.push(queue);
        }
        if watched.is_empty() {
            return Err(GtpuControlPortError::InvalidLimits);
        }
        Ok(Self {
            inner: Arc::new(ReadinessInner {
                epoll,
                liveness,
                revoked: AtomicBool::new(false),
            }),
        })
    }

    /// Report the currently ready queues without blocking.
    ///
    /// An empty result means that no watched queue reported readiness at this
    /// instant; it never means that a subsequent receive would find nothing.
    ///
    /// # Errors
    /// Returns [`GtpuControlPortError::Unavailable`] after the port revoked
    /// this source, and [`GtpuControlPortError::Io`] for an epoll failure.
    pub fn try_readiness(&self) -> Result<GtpuDownlinkReadiness, GtpuControlPortError> {
        self.collect(EpollTimeout::ZERO)
    }

    /// Wait at most `timeout` for a watched queue to report readiness.
    ///
    /// The call is advisory exactly like [`Self::try_readiness`]; an empty
    /// result is a timeout, not a refusal.
    ///
    /// # Errors
    /// Returns [`GtpuControlPortError::Unavailable`] after revocation,
    /// [`GtpuControlPortError::InvalidLimits`] for a timeout outside the
    /// kernel's bound, and [`GtpuControlPortError::Io`] for an epoll failure.
    pub fn wait(&self, timeout: Duration) -> Result<GtpuDownlinkReadiness, GtpuControlPortError> {
        let timeout =
            EpollTimeout::try_from(timeout).map_err(|_| GtpuControlPortError::InvalidLimits)?;
        self.collect(timeout)
    }

    /// Weak reference used by the owning port to revoke this source.
    pub(crate) fn weak_inner(&self) -> Weak<ReadinessInner> {
        Arc::downgrade(&self.inner)
    }

    fn collect(
        &self,
        timeout: EpollTimeout,
    ) -> Result<GtpuDownlinkReadiness, GtpuControlPortError> {
        if self.inner.is_revoked() {
            return Err(GtpuControlPortError::Unavailable);
        }
        let mut events = [EpollEvent::empty(); GtpuControlQueue::ALL.len()];
        let count = self
            .inner
            .epoll
            .wait(&mut events, timeout)
            .map_err(|error| GtpuControlPortError::Io {
                kind: std::io::Error::from(error).kind(),
            })?;
        let mut readiness = GtpuDownlinkReadiness::default();
        for event in &events[..count] {
            if let Some(queue) = GtpuControlQueue::from_epoll_data(event.data()) {
                readiness.insert(queue);
            }
        }
        // Revocation may race the wait; never report readiness for a withdrawn
        // registration.
        if self.inner.is_revoked() {
            return Err(GtpuControlPortError::Unavailable);
        }
        Ok(readiness)
    }
}

/// Shared state behind one readiness source.
pub(crate) struct ReadinessInner {
    epoll: Epoll,
    liveness: Option<Weak<()>>,
    revoked: AtomicBool,
}

impl ReadinessInner {
    pub(crate) fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
    }

    pub(crate) fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
            || self
                .liveness
                .as_ref()
                .is_some_and(|liveness| liveness.upgrade().is_none())
    }
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    use super::*;

    fn bound() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").expect("bind loopback socket")
    }

    fn send_to(socket: &UdpSocket, target: &UdpSocket, payload: &[u8]) {
        socket
            .send_to(payload, target.local_addr().unwrap())
            .unwrap();
    }

    fn wait_ready(readiness: &GtpuControlReadiness) -> GtpuDownlinkReadiness {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let mask = readiness.try_readiness().expect("readiness stays live");
            if !mask.is_empty() {
                return mask;
            }
            assert!(std::time::Instant::now() < deadline, "readiness deadline");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn readiness_reports_the_ready_queue_and_preserves_the_datagram() {
        let shared = bound();
        let hand_off = bound();
        let readiness = GtpuControlReadiness::new(
            [
                (GtpuControlQueue::Shared, shared.as_fd()),
                (GtpuControlQueue::PacketTooBig, hand_off.as_fd()),
            ],
            None,
        )
        .unwrap();
        assert!(readiness.try_readiness().unwrap().is_empty());

        let peer = bound();
        send_to(&peer, &shared, b"control");
        let mask = wait_ready(&readiness);
        assert!(mask.is_ready(GtpuControlQueue::Shared));
        assert!(!mask.is_ready(GtpuControlQueue::PacketTooBig));
        assert_eq!(
            mask.queues().collect::<Vec<_>>(),
            vec![GtpuControlQueue::Shared]
        );

        // Readiness is advisory: the datagram is still queued for the receive.
        let mut buffer = [0_u8; 32];
        let (count, _) = shared.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..count], b"control");

        let peer = bound();
        send_to(&peer, &hand_off, b"hand-off");
        let mask = wait_ready(&readiness);
        assert!(mask.is_ready(GtpuControlQueue::PacketTooBig));
        assert!(!mask.is_ready(GtpuControlQueue::Shared));
        assert_eq!(readiness.wait(Duration::from_millis(1)).unwrap(), mask);
        let mut buffer = [0_u8; 32];
        let (count, _) = hand_off.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..count], b"hand-off");
        assert!(readiness.try_readiness().unwrap().is_empty());
    }

    #[test]
    fn readiness_can_be_waited_on_with_epoll_and_is_not_a_socket() {
        let shared = bound();
        let readiness =
            GtpuControlReadiness::new([(GtpuControlQueue::Shared, shared.as_fd())], None).unwrap();
        // The exposed descriptor is the SDK's private epoll instance, not the
        // receive socket: a consumer cannot read or close a socket through it.
        assert_eq!(
            nix::sys::socket::getsockname::<nix::sys::socket::SockaddrStorage>(
                readiness.as_fd().as_raw_fd()
            )
            .unwrap_err(),
            nix::errno::Errno::ENOTSOCK
        );
        // A consumer registers the readiness descriptor with its own epoll.
        let outer = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();
        outer
            .add(&readiness, EpollEvent::new(EpollFlags::EPOLLIN, 0xfeed))
            .unwrap();
        let mut events = [EpollEvent::empty(); 1];
        assert_eq!(outer.wait(&mut events, EpollTimeout::ZERO).unwrap(), 0);

        let peer = bound();
        send_to(&peer, &shared, b"wake");
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let count = outer
                .wait(
                    &mut events,
                    EpollTimeout::try_from(Duration::from_millis(10)).unwrap(),
                )
                .unwrap();
            if count == 1 {
                assert_eq!(events[0].data(), 0xfeed);
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "epoll readiness deadline"
            );
        }
    }

    #[tokio::test]
    async fn readiness_wakes_an_async_fd_without_busy_polling() {
        let shared = bound();
        let readiness =
            GtpuControlReadiness::new([(GtpuControlQueue::Shared, shared.as_fd())], None).unwrap();
        // The consumer wraps the borrowed readiness descriptor; the handle
        // keeps the socket and the SDK epoll instance alive.
        let async_fd = tokio::io::unix::AsyncFd::new(readiness.as_fd()).unwrap();
        let peer = bound();
        send_to(&peer, &shared, b"async-wake");
        let mask = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let mut guard = async_fd.readable().await.unwrap();
                let mask = readiness.try_readiness().unwrap();
                if mask.is_ready(GtpuControlQueue::Shared) {
                    break mask;
                }
                guard.clear_ready();
            }
        })
        .await
        .expect("async readiness deadline");
        assert!(mask.is_ready(GtpuControlQueue::Shared));
    }

    #[test]
    fn revocation_makes_readiness_unavailable_and_takes_effect_before_the_queues_close() {
        let shared = bound();
        let readiness =
            GtpuControlReadiness::new([(GtpuControlQueue::Shared, shared.as_fd())], None).unwrap();
        let peer = bound();
        send_to(&peer, &shared, b"stale");
        assert!(!wait_ready(&readiness).is_empty());
        readiness.inner.revoke();
        assert_eq!(
            readiness.try_readiness().unwrap_err(),
            GtpuControlPortError::Unavailable
        );
        assert_eq!(
            readiness.wait(Duration::from_millis(1)).unwrap_err(),
            GtpuControlPortError::Unavailable
        );
        // A replacement source on the still-open queue is unaffected.
        let replacement =
            GtpuControlReadiness::new([(GtpuControlQueue::Shared, shared.as_fd())], None).unwrap();
        assert!(!replacement.try_readiness().unwrap().is_empty());
    }

    #[test]
    fn readiness_without_a_queue_is_refused() {
        assert_eq!(
            GtpuControlReadiness::new(
                std::iter::empty::<(GtpuControlQueue, BorrowedFd<'_>)>(),
                None
            )
            .unwrap_err(),
            GtpuControlPortError::InvalidLimits
        );
    }

    #[test]
    fn liveness_token_close_is_reported_as_unavailable() {
        let shared = bound();
        let token = std::sync::Arc::new(());
        let readiness = GtpuControlReadiness::new(
            [(GtpuControlQueue::Shared, shared.as_fd())],
            Some(std::sync::Arc::downgrade(&token)),
        )
        .unwrap();
        assert!(readiness.try_readiness().is_ok());
        drop(token);
        assert_eq!(
            readiness.try_readiness().unwrap_err(),
            GtpuControlPortError::Unavailable
        );
    }

    #[test]
    fn readiness_queues_keep_the_documented_priority_order() {
        assert_eq!(
            GtpuControlQueue::ALL,
            [
                GtpuControlQueue::Shared,
                GtpuControlQueue::PacketTooBig,
                GtpuControlQueue::InnerFragment,
            ]
        );
        let mut mask = GtpuDownlinkReadiness::default();
        for queue in GtpuControlQueue::ALL {
            mask.insert(queue);
        }
        assert_eq!(
            mask.queues().collect::<Vec<_>>(),
            GtpuControlQueue::ALL.to_vec()
        );
        assert!(!mask.is_empty());
    }
}
