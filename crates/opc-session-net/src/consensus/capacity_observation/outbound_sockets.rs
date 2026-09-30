//! Detached outbound attempts and connected TCP owners are distinct categories.
//!
//! Attempts begin at the real spawn's owned future, before its first poll. A
//! connected endpoint begins only after the original TcpStream::connect returns
//! successfully. Connect internals, DNS/material allocations and TLS capacities
//! are not measured. No observer owns a socket, payload or material snapshot.

use std::future::Future;
use std::io::{self, IoSlice};
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use opc_consensus::ConsensusNodeId;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use super::ConsensusBufferObservation;

/// Last entered checkpoint of one actual shared detached attempt future.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboundAttemptPhase {
    /// Registered synchronously at spawn; the future may not have been polled.
    Spawned,
    /// Entered the unchanged reconnect admission/deadline checks.
    ReconnectAdmission,
    /// Entered the existing material-controlled TLS handshake operation.
    MaterialAdmission,
    /// Entered the real target resolver, including each material retry.
    Resolving,
    /// Entered the original TCP connect future; its internal sockets are excluded.
    Connecting,
    /// A connected TCP stream entered the real client TLS handshake.
    TlsHandshake,
    /// Plaintext or authenticated TLS entered consensus Hello/Ack.
    Bootstrap,
    /// Entered terminal or Ready publication, including coordinator lock waits.
    Publishing,
    /// The detached task is monitoring its unclaimed Ready connection.
    ReadyMonitor,
}

/// One detached future, independent of how many logical callers await it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutboundAttemptOwner {
    /// Observer-local numeric identity from the common checked ID sequence.
    pub attempt_id: u64,
    /// Actual spawning peer's local binding ordinal; no remote authentication claim.
    pub source: ConsensusNodeId,
    /// Actual spawning peer's remote binding ordinal.
    pub target: ConsensusNodeId,
    /// Last entered checkpoint, not a byte count or a precise allocation phase.
    pub phase: OutboundAttemptPhase,
}

/// Last reached ownership checkpoint for one successfully connected endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboundSocketPhase {
    /// The original TCP connect returned successfully, before socket configuration.
    Connected,
    /// The same TCP owner entered the real TLS connect operation.
    TlsHandshake,
    /// Split plaintext or authenticated TLS is performing consensus bootstrap.
    Bootstrap,
    /// Bootstrap succeeded; the returned connection has not been published Ready.
    Returned,
    /// The coordinator owns the published, unclaimed connection.
    Ready,
    /// A caller claimed the Ready connection, before negotiated dispatch.
    Claimed,
    /// A real negotiated call owns this endpoint, including cache reuse.
    Active,
    /// A complete reusable response returned this endpoint to its pool lane.
    Cached,
}

/// One TCP endpoint across TLS, split halves, Ready, active calls and lane reuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutboundSocketOwner {
    /// Unique endpoint identity; shared split halves do not create extra rows.
    pub socket_id: u64,
    /// Originating detached attempt, even after that attempt's future has ended.
    /// Material retries can create distinct sequential endpoints for one attempt.
    pub attempt_id: u64,
    /// Originating peer's numeric local binding ordinal.
    pub source: ConsensusNodeId,
    /// Originating peer's numeric remote binding ordinal.
    pub target: ConsensusNodeId,
    /// Last reached checkpoint, retained until the real TCP owner's destruction.
    pub phase: OutboundSocketPhase,
}

/// One locked sample of explicitly enrolled outbound attempts and TCP owners.
///
/// The categories overlap and must not be added as distinct network connections
/// or TLS allocations. This is not a kernel-FD or byte census. A TCP row can
/// conservatively survive in the synchronous destructor/observer-lock tail after
/// TCP destruction; private TLS fields can outlive that row. An attempt row
/// similarly survives destruction of its owned future before guard removal.
/// Enrollment belongs to the peer clone that actually spawns setup. Observed
/// callers joining an older, unenrolled pool attempt cannot retroactively enroll
/// it or its sockets. Separate pools, builders and processes require inventory.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OutboundSocketCensus {
    /// Unique live detached futures, including those with no connected TCP yet.
    pub attempts: Vec<OutboundAttemptOwner>,
    /// Unique connected endpoint owners, including cached endpoints after setup.
    pub sockets: Vec<OutboundSocketOwner>,
    /// True permanently marks an incomplete census after either ID allocation fails.
    pub registration_exhausted: bool,
}

impl ConsensusBufferObservation {
    /// Take one same-instant sample of both outbound categories under one mutex.
    pub fn outbound_socket_snapshot(&self) -> OutboundSocketCensus {
        let state = self.state();
        OutboundSocketCensus {
            attempts: state.outbound_attempts.values().copied().collect(),
            sockets: state.outbound_sockets.values().copied().collect(),
            registration_exhausted: state.outbound_registration_exhausted,
        }
    }

    /// Wait for currently enrolled outbound futures and TCP owners to drain.
    ///
    /// Stop producers and drop peer pools first for a final barrier. Empty rows
    /// do not forbid later spawns, prove drain after ID exhaustion, or join TLS
    /// private-field tails. This does not cancel work or alter production gates.
    pub async fn wait_for_no_outbound_owners(&self) {
        let mut changed = self.changed.subscribe();
        loop {
            {
                let state = self.state();
                if state.outbound_attempts.is_empty() && state.outbound_sockets.is_empty() {
                    return;
                }
            }
            if changed.changed().await.is_err() {
                return;
            }
        }
    }
}

#[derive(Clone)]
struct AttemptContext {
    observation: Arc<ConsensusBufferObservation>,
    id: u64,
    source: ConsensusNodeId,
    target: ConsensusNodeId,
}

tokio::task_local! { static OUTBOUND_ATTEMPT: AttemptContext; }

struct AttemptRegistration(AttemptContext);

impl Drop for AttemptRegistration {
    fn drop(&mut self) {
        self.0
            .observation
            .state()
            .outbound_attempts
            .remove(&self.0.id);
        self.0.observation.changed.send_replace(());
    }
}

// Field order is deliberate: destroy the owned future before removing its row,
// including a future cancelled before its first poll. Boxing supplies safe pin
// projection without unsafe code or another dependency in this hidden feature.
pub(crate) struct ObservedOutboundAttempt<F> {
    future: Pin<Box<F>>,
    registration: Option<AttemptRegistration>,
}

impl<F: Future> Future for ObservedOutboundAttempt<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match &this.registration {
            Some(registration) => OUTBOUND_ATTEMPT
                .sync_scope(registration.0.clone(), || this.future.as_mut().poll(cx)),
            None => this.future.as_mut().poll(cx),
        }
    }
}

pub(crate) fn observe_outbound_attempt<F: Future>(
    observation: Option<&Arc<ConsensusBufferObservation>>,
    source: ConsensusNodeId,
    target: ConsensusNodeId,
    future: F,
) -> ObservedOutboundAttempt<F> {
    let registration = observation.and_then(|observation| {
        let mut state = observation.state();
        let Some(id) = state.next_id.checked_add(1) else {
            state.outbound_registration_exhausted = true;
            return None;
        };
        state.next_id = id;
        let owner = OutboundAttemptOwner {
            attempt_id: id,
            source,
            target,
            phase: OutboundAttemptPhase::Spawned,
        };
        state.outbound_attempts.insert(id, owner);
        Some(AttemptRegistration(AttemptContext {
            observation: Arc::clone(observation),
            id,
            source,
            target,
        }))
    });
    ObservedOutboundAttempt {
        future: Box::pin(future),
        registration,
    }
}

pub(crate) fn outbound_tls_material() -> Option<super::tls_allocations::TlsOwner> {
    OUTBOUND_ATTEMPT
        .try_with(|context| {
            context
                .observation
                .open_tls_source(super::TlsAllocationSource::OutboundMaterial(context.id))
        })
        .ok()
        .flatten()
}

pub(crate) fn outbound_attempt_phase(phase: OutboundAttemptPhase) {
    let _ = OUTBOUND_ATTEMPT.try_with(|context| {
        let mut state = context.observation.state();
        if let Some(owner) = state.outbound_attempts.get_mut(&context.id) {
            owner.phase = phase;
        }
    });
}

#[derive(Clone)]
pub(crate) struct OutboundSocketContext {
    observation: Arc<ConsensusBufferObservation>,
    id: u64,
}

impl OutboundSocketContext {
    pub(crate) fn phase(&self, phase: OutboundSocketPhase) {
        let mut state = self.observation.state();
        if let Some(owner) = state.outbound_sockets.get_mut(&self.id) {
            owner.phase = phase;
        }
    }
}

struct SocketRegistration(OutboundSocketContext);

impl Drop for SocketRegistration {
    fn drop(&mut self) {
        self.0
            .observation
            .state()
            .outbound_sockets
            .remove(&self.0.id);
        self.0.observation.changed.send_replace(());
    }
}

// The concrete TCP field drops before its one registration. Context clones
// carry only numeric metadata and an Arc to the observer; they cannot close or
// retain TCP. The containing TLS object's later fields are a separate lifetime.
pub(crate) struct OutboundSocket {
    stream: TcpStream,
    registration: Option<SocketRegistration>,
}

impl OutboundSocket {
    pub(crate) fn new(stream: TcpStream) -> Self {
        let registration = OUTBOUND_ATTEMPT
            .try_with(|attempt| {
                let mut state = attempt.observation.state();
                let Some(id) = state.next_id.checked_add(1) else {
                    state.outbound_registration_exhausted = true;
                    return None;
                };
                state.next_id = id;
                let owner = OutboundSocketOwner {
                    socket_id: id,
                    attempt_id: attempt.id,
                    source: attempt.source,
                    target: attempt.target,
                    phase: OutboundSocketPhase::Connected,
                };
                state.outbound_sockets.insert(id, owner);
                Some(SocketRegistration(OutboundSocketContext {
                    observation: Arc::clone(&attempt.observation),
                    id,
                }))
            })
            .ok()
            .flatten();
        Self {
            stream,
            registration,
        }
    }

    pub(crate) fn context(&self) -> Option<OutboundSocketContext> {
        self.registration.as_ref().map(|owner| owner.0.clone())
    }

    pub(crate) fn tls_owner(&self) -> Option<super::tls_allocations::TlsOwner> {
        let registration = self.registration.as_ref()?;
        registration
            .0
            .observation
            .open_tls(super::TlsEndpoint::Outbound(registration.0.id))
    }
}

impl Deref for OutboundSocket {
    type Target = TcpStream;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl AsyncRead for OutboundSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buffer)
    }
}

impl AsyncWrite for OutboundSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write_vectored(cx, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpolled_attempt_is_registered_until_owned_future_drop() {
        let observation = Arc::new(ConsensusBufferObservation::default());
        let future = observe_outbound_attempt(
            Some(&observation),
            ConsensusNodeId::new(1).expect("source"),
            ConsensusNodeId::new(2).expect("target"),
            std::future::pending::<()>(),
        );
        let queued = observation.outbound_socket_snapshot();
        drop(future);
        let drained = observation.outbound_socket_snapshot();
        assert!(drained.attempts.is_empty());
        assert!(drained.sockets.is_empty());
        assert!(!drained.registration_exhausted);
        assert_eq!(
            queued.attempts.len(),
            1,
            "CONFIG_CAPACITY_OUTBOUND_ATTEMPT_OMISSION_RED"
        );
        assert_eq!(queued.attempts[0].phase, OutboundAttemptPhase::Spawned);
    }

    #[test]
    fn exhausted_attempt_identity_marks_the_census_incomplete() {
        let observation = Arc::new(ConsensusBufferObservation::default());
        observation.state().next_id = u64::MAX;
        let future = observe_outbound_attempt(
            Some(&observation),
            ConsensusNodeId::new(1).expect("source"),
            ConsensusNodeId::new(2).expect("target"),
            std::future::pending::<()>(),
        );
        let exhausted = observation.outbound_socket_snapshot();
        drop(future);
        assert!(exhausted.registration_exhausted);
        assert!(exhausted.attempts.is_empty());
        assert!(exhausted.sockets.is_empty());
        assert!(
            observation
                .outbound_socket_snapshot()
                .registration_exhausted
        );
    }

    #[tokio::test]
    async fn exhausted_connected_identity_keeps_real_io_and_marks_incomplete() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;

        let observation = Arc::new(ConsensusBufferObservation::default());
        observation.state().next_id = u64::MAX - 1;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let guard = tokio::time::Instant::now()
            + opc_consensus::DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout();
        let task = tokio::spawn(observe_outbound_attempt(
            Some(&observation),
            ConsensusNodeId::new(1).expect("source"),
            ConsensusNodeId::new(2).expect("target"),
            async move {
                OutboundSocket::new(TcpStream::connect(address).await.expect("actual connect"))
            },
        ));
        let (mut remote, _) = tokio::time::timeout_at(guard, listener.accept())
            .await
            .expect("accept guard")
            .expect("actual accepted TCP");
        let socket = tokio::time::timeout_at(guard, task)
            .await
            .expect("join guard")
            .expect("attempt actually joined");
        let exhausted = observation.outbound_socket_snapshot();
        drop(socket);
        let mut byte = [0_u8];
        let eof = tokio::time::timeout_at(guard, remote.read(&mut byte)).await;
        drop(remote);
        drop(listener);
        assert!(
            matches!(eof, Ok(Ok(0))),
            "unregistered real TCP was still destroyed"
        );
        assert!(exhausted.registration_exhausted);
        assert!(exhausted.attempts.is_empty() && exhausted.sockets.is_empty());
        assert!(
            observation
                .outbound_socket_snapshot()
                .registration_exhausted
        );
    }
}
