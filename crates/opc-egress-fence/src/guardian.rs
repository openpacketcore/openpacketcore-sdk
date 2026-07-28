//! Single-owner queue boundary for all fenced UDP input and output.

use std::{cmp, fmt, io, net::SocketAddr, num::NonZeroUsize, time::Duration};

use opc_runtime::UdpLocalDestination;
use opc_session_store::{LeaseGuard, OwnerId, SessionKey};
use tokio::sync::{mpsc, oneshot, watch};

use crate::{
    EgressFenceLeaseAuthority, FencedUdpSocket, LeaseFenceError, LeaseFenceTiming, RetireFenceError,
};

const MAX_RECEIVE_DATAGRAM_BYTES: usize = u16::MAX as usize;

/// Product-facing value channels for one fenced UDP guardian.
///
/// This type contains no socket or raw descriptor. Cloning [`Self::sender`]
/// creates another producer for the same single guardian queue; it never
/// creates an alternate kernel send path.
pub struct FencedUdpChannels {
    sender: FencedUdpSender,
    inbound: mpsc::Receiver<FencedUdpInboundDatagram>,
}

impl FencedUdpChannels {
    /// Return a clonable sender for this exact guardian queue.
    #[must_use]
    pub fn sender(&self) -> FencedUdpSender {
        self.sender.clone()
    }

    /// Receive one value-owned inbound datagram.
    ///
    /// `None` means the guardian stopped and no further datagrams can arrive.
    pub async fn recv(&mut self) -> Option<FencedUdpInboundDatagram> {
        self.inbound.recv().await
    }
}

impl fmt::Debug for FencedUdpChannels {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedUdpChannels(<redacted>)")
    }
}

/// Clonable producer for the one supervised fenced-socket guardian.
#[derive(Clone)]
pub struct FencedUdpSender {
    outbound: mpsc::Sender<OutboundRequest>,
}

impl FencedUdpSender {
    /// Queue and await one datagram send through the owning guardian.
    ///
    /// The payload and both endpoints are value-owned by the request. Failure
    /// strings are stable codes and never contain endpoint or packet data.
    ///
    /// # Errors
    ///
    /// Returns `BrokenPipe` if the guardian has stopped, or the guarded
    /// socket's value-free send error.
    pub async fn send(
        &self,
        payload: Vec<u8>,
        peer: SocketAddr,
        local_source: SocketAddr,
    ) -> io::Result<usize> {
        let (completion, result) = oneshot::channel();
        let request = OutboundRequest {
            payload,
            peer,
            local_source,
            completion,
        };
        self.outbound
            .send(request)
            .await
            .map_err(|_| guardian_io_error(io::ErrorKind::BrokenPipe, "guardian_closed"))?;
        result
            .await
            .map_err(|_| guardian_io_error(io::ErrorKind::BrokenPipe, "guardian_closed"))?
    }
}

impl fmt::Debug for FencedUdpSender {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedUdpSender(<redacted>)")
    }
}

/// One value-owned datagram received by the fenced guardian.
pub struct FencedUdpInboundDatagram {
    payload: Vec<u8>,
    source: SocketAddr,
    local_destination: UdpLocalDestination,
}

impl FencedUdpInboundDatagram {
    /// Consume the datagram into payload, source, and local-destination values.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, SocketAddr, UdpLocalDestination) {
        (self.payload, self.source, self.local_destination)
    }

    /// Payload length without exposing packet bytes.
    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }
}

impl fmt::Debug for FencedUdpInboundDatagram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FencedUdpInboundDatagram")
            .field("payload_len", &self.payload.len())
            .field("source_present", &true)
            .field("local_destination_present", &true)
            .finish()
    }
}

/// Guardian-only channel endpoints consumed by [`run_fenced_udp_guardian`].
///
/// The fields are private so product code cannot dequeue and replay outbound
/// requests through any other socket.
pub struct FencedUdpGuardianPorts {
    outbound: mpsc::Receiver<OutboundRequest>,
    inbound: mpsc::Sender<FencedUdpInboundDatagram>,
}

impl fmt::Debug for FencedUdpGuardianPorts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedUdpGuardianPorts(<redacted>)")
    }
}

/// Build bounded product and guardian channel endpoints.
///
/// Every producer returned through [`FencedUdpChannels::sender`] converges on
/// the same guardian-owned socket. The capacity must be nonzero by type.
#[must_use]
pub fn fenced_udp_channels(capacity: NonZeroUsize) -> (FencedUdpChannels, FencedUdpGuardianPorts) {
    let (outbound_tx, outbound_rx) = mpsc::channel(capacity.get());
    let (inbound_tx, inbound_rx) = mpsc::channel(capacity.get());
    (
        FencedUdpChannels {
            sender: FencedUdpSender {
                outbound: outbound_tx,
            },
            inbound: inbound_rx,
        },
        FencedUdpGuardianPorts {
            outbound: outbound_rx,
            inbound: inbound_tx,
        },
    )
}

/// Run the only receive/send owner for a fenced UDP socket.
///
/// This function consumes the non-shareable socket, acquires durable
/// authority before serving either queue, renews at half the lease TTL, and
/// closes the kernel capability before releasing authority on orderly stop.
/// A send that exceeds the bounded cancellation budget is outcome-unknown:
/// the socket is terminal-closed and the exact lease remains unreleased for
/// conservative expiry.
///
/// `shutdown == true`, closure of the shutdown sender, closure of every
/// outbound producer, or closure of the inbound consumer requests orderly
/// retirement.
///
/// # Errors
///
/// Returns a redaction-safe stage error while retaining an exact unreleased
/// lease whenever safe release was not proven.
pub async fn run_fenced_udp_guardian<A>(
    mut socket: FencedUdpSocket,
    authority: &A,
    key: &SessionKey,
    owner: OwnerId,
    timing: LeaseFenceTiming,
    mut ports: FencedUdpGuardianPorts,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), FencedUdpGuardianError<A::Error>>
where
    A: EgressFenceLeaseAuthority + ?Sized,
{
    if *shutdown.borrow() {
        return Ok(());
    }

    let mut lease = socket
        .acquire(authority, key, owner, timing)
        .await
        .map_err(FencedUdpGuardianError::Transition)?;
    let renew_after = timing.ttl() / 2;
    let send_budget = bounded_send_budget(timing);
    let renew_sleep = tokio::time::sleep(renew_after);
    tokio::pin!(renew_sleep);
    let mut buffer = vec![0_u8; MAX_RECEIVE_DATAGRAM_BYTES];

    loop {
        tokio::select! {
            biased;

            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow_and_update() {
                    break;
                }
            }
            () = &mut renew_sleep => {
                lease = socket
                    .renew(authority, lease, timing)
                    .await
                    .map_err(FencedUdpGuardianError::Transition)?;
                renew_sleep.as_mut().reset(tokio::time::Instant::now() + renew_after);
            }
            request = ports.outbound.recv() => {
                let Some(request) = request else {
                    break;
                };
                let OutboundRequest {
                    payload,
                    peer,
                    local_source,
                    completion,
                } = request;
                match tokio::time::timeout(
                    send_budget,
                    socket.send_to_from(&payload, peer, local_source),
                )
                .await
                {
                    Ok(result) => {
                        let _ = completion.send(result);
                    }
                    Err(_) => {
                        drop(completion);
                        return Err(FencedUdpGuardianError::SendOutcomeUnknown { lease });
                    }
                }
            }
            received = socket.recv_from_with_destination(&mut buffer) => {
                let received = match received {
                    Ok(received) => received,
                    Err(error) => {
                        return Err(FencedUdpGuardianError::Receive { error, lease });
                    }
                };
                let payload = buffer[..received.bytes()].to_vec();
                let inbound = FencedUdpInboundDatagram {
                    payload,
                    source: received.source(),
                    local_destination: received.local_destination(),
                };
                match ports.inbound.try_send(inbound) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        return retire_with_operational_error(
                            socket,
                            authority,
                            lease,
                            GuardianOperationalError::InboundBackpressure,
                        )
                        .await;
                    }
                }
            }
        }
    }

    socket
        .close_then_release(authority, lease)
        .await
        .map_err(FencedUdpGuardianError::Retirement)
}

async fn retire_with_operational_error<A>(
    mut socket: FencedUdpSocket,
    authority: &A,
    lease: LeaseGuard,
    operational: GuardianOperationalError,
) -> Result<(), FencedUdpGuardianError<A::Error>>
where
    A: EgressFenceLeaseAuthority + ?Sized,
{
    socket
        .close_then_release(authority, lease)
        .await
        .map_err(FencedUdpGuardianError::Retirement)?;
    Err(FencedUdpGuardianError::Operational(operational))
}

fn bounded_send_budget(timing: LeaseFenceTiming) -> Duration {
    cmp::max(
        Duration::from_nanos(1),
        cmp::min(timing.safety_margin() / 2, timing.ttl() / 4),
    )
}

struct OutboundRequest {
    payload: Vec<u8>,
    peer: SocketAddr,
    local_source: SocketAddr,
    completion: oneshot::Sender<io::Result<usize>>,
}

impl fmt::Debug for OutboundRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundRequest")
            .field("payload_len", &self.payload.len())
            .field("peer_present", &true)
            .field("local_source_present", &true)
            .finish()
    }
}

/// Terminal result from the fenced guardian.
pub enum FencedUdpGuardianError<E> {
    /// Durable/kernel lease transition failed. Post-grant variants retain the
    /// exact unreleased lease.
    Transition(LeaseFenceError<E>),
    /// A receive syscall failed. The socket is terminal-closed on drop and the
    /// lease is retained until expiry.
    Receive {
        /// Value-free receive error.
        error: io::Error,
        /// Exact unreleased lease.
        lease: LeaseGuard,
    },
    /// A bounded guardian invariant failed after orderly retirement.
    Operational(GuardianOperationalError),
    /// Send completion became ambiguous. The socket is terminal-closed on
    /// drop and the lease is retained until expiry.
    SendOutcomeUnknown {
        /// Exact unreleased lease.
        lease: LeaseGuard,
    },
    /// Terminal kernel closure or durable terminal release failed.
    Retirement(RetireFenceError<E>),
}

impl<E> fmt::Debug for FencedUdpGuardianError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transition(error) => formatter.debug_tuple("Transition").field(error).finish(),
            Self::Receive { .. } => formatter.write_str("FencedUdpGuardianError::Receive"),
            Self::Operational(error) => formatter.debug_tuple("Operational").field(error).finish(),
            Self::SendOutcomeUnknown { .. } => {
                formatter.write_str("FencedUdpGuardianError::SendOutcomeUnknown(<redacted>)")
            }
            Self::Retirement(error) => formatter.debug_tuple("Retirement").field(error).finish(),
        }
    }
}

impl<E> fmt::Display for FencedUdpGuardianError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transition(_) => formatter.write_str("egress_fence_guardian_transition"),
            Self::Receive { .. } => formatter.write_str("egress_fence_guardian_receive"),
            Self::Operational(error) => fmt::Display::fmt(error, formatter),
            Self::SendOutcomeUnknown { .. } => {
                formatter.write_str("egress_fence_guardian_send_outcome_unknown")
            }
            Self::Retirement(_) => formatter.write_str("egress_fence_guardian_retirement"),
        }
    }
}

impl<E> std::error::Error for FencedUdpGuardianError<E> where E: Send + Sync + 'static {}

/// Redaction-safe bounded guardian invariant failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardianOperationalError {
    /// The bounded inbound queue could not accept a datagram without stalling
    /// lease supervision.
    InboundBackpressure,
}

impl fmt::Display for GuardianOperationalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InboundBackpressure => {
                formatter.write_str("egress_fence_guardian_inbound_backpressure")
            }
        }
    }
}

impl std::error::Error for GuardianOperationalError {}

fn guardian_io_error(kind: io::ErrorKind, code: &'static str) -> io::Error {
    io::Error::new(kind, code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_handles_and_datagrams_are_redaction_safe() {
        let (channels, ports) =
            fenced_udp_channels(NonZeroUsize::new(1).expect("nonzero capacity"));
        assert_eq!(format!("{channels:?}"), "FencedUdpChannels(<redacted>)");
        assert_eq!(
            format!("{:?}", channels.sender()),
            "FencedUdpSender(<redacted>)"
        );
        assert_eq!(format!("{ports:?}"), "FencedUdpGuardianPorts(<redacted>)");

        let datagram = FencedUdpInboundDatagram {
            payload: vec![0xde, 0xad, 0xbe, 0xef],
            source: "192.0.2.41:31337".parse().expect("documentation source"),
            local_destination: UdpLocalDestination::socket_addr(
                "192.0.2.42:31337"
                    .parse()
                    .expect("documentation destination"),
            ),
        };
        let debug = format!("{datagram:?}");
        assert!(debug.contains("payload_len: 4"));
        for secret in ["deadbeef", "192.0.2.41", "192.0.2.42", "31337"] {
            assert!(!debug.contains(secret));
        }
    }

    #[test]
    fn send_budget_is_nonzero_and_bounded_by_supervision_margin() {
        let timing =
            LeaseFenceTiming::new(Duration::from_secs(20), Duration::from_secs(4)).expect("timing");
        assert_eq!(bounded_send_budget(timing), Duration::from_secs(2));

        let tiny = LeaseFenceTiming::new(Duration::from_nanos(3), Duration::from_nanos(1))
            .expect("tiny timing");
        assert_eq!(bounded_send_budget(tiny), Duration::from_nanos(1));
    }
}
