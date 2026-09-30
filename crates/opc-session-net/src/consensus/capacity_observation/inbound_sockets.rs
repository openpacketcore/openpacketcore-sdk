//! Accepted inbound TCP endpoint ownership, separate from TLS allocation bytes.
//!
//! The single registration lives inside the real TCP stream's wrapper, below
//! TLS and Tokio's shared split. Its guard follows moves and ends only after
//! the TCP stream field is destroyed. It does not claim that all private TLS
//! fields have been destroyed at that boundary. No I/O is gated here.

use std::future::Future;
use std::io::{self, IoSlice};
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use super::ConsensusBufferObservation;

/// Last reached server checkpoint; this is not a count of TLS allocations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboundSocketPhase {
    /// Accept returned; registration precedes registry locking and child spawn.
    Accepted,
    /// The accepted task entered material/TLS setup, before application Hello.
    TlsSetup,
    /// Plaintext or authenticated TLS entered consensus bootstrap.
    Bootstrap,
    /// A bootstrap rejection or retirement write was selected.
    Refusing,
    /// Accepted was fully written and the negotiated request loop was entered.
    Negotiated,
}

/// One accepted endpoint, counted once through moves and shared split halves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InboundSocketOwner {
    /// Observer-local identity from the common registration sequence.
    pub socket_id: u64,
    /// Last reached real checkpoint, retained until TCP-owner destruction.
    /// Cancellation need not advance the phase before destroying the owner.
    pub phase: InboundSocketPhase,
}

/// One locked sample of this observer's explicitly scoped inbound listeners.
///
/// These are endpoint owners, not network connections or allocated TLS bytes.
/// Outbound sockets, connect/accept internals, backlog and listener sockets are
/// excluded. No source/peer authentication is inferred from an accepted socket.
/// A row can conservatively remain during the post-TCP destructor tail until
/// deregistration gets the observer lock. This is not an exact kernel-FD census.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InboundSocketCensus {
    /// Unique currently registered endpoint owners, including unauthenticated
    /// and refusing streams. Rows survive cancellation until actual TCP drop.
    pub owners: Vec<InboundSocketOwner>,
    /// True means registration identity exhaustion made this census incomplete.
    pub registration_exhausted: bool,
}

tokio::task_local! {
    static INBOUND_LISTENER_OBSERVATION: Arc<ConsensusBufferObservation>;
    static INBOUND_SOCKET_CONTEXT: SocketContext;
}

impl ConsensusBufferObservation {
    /// Explicitly opt listeners started by this future into inbound TCP census.
    ///
    /// Listener tasks capture numeric observation context when they start.
    /// Existing listeners and separately spawned futures are not implicitly
    /// enrolled. This adds no gate and never retains a stream or TLS material.
    pub async fn scope_inbound_sockets<F: Future>(self: &Arc<Self>, future: F) -> F::Output {
        INBOUND_LISTENER_OBSERVATION
            .scope(Arc::clone(self), future)
            .await
    }

    /// Copy one coherent current inbound-endpoint sample, never a sum of peaks.
    pub fn inbound_socket_snapshot(&self) -> InboundSocketCensus {
        let state = self.state();
        InboundSocketCensus {
            owners: state.inbound_sockets.values().copied().collect(),
            registration_exhausted: state.inbound_socket_registration_exhausted,
        }
    }

    /// Wait for the currently registered inbound TCP owners to drain.
    ///
    /// Stop the listeners first when using this as a final barrier: an empty
    /// sample does not prevent a running listener from accepting another peer.
    /// This does not wait for detached handlers or private TLS allocation tails.
    /// An exhausted registration sequence cannot supply complete drain evidence.
    pub async fn wait_for_no_inbound_sockets(&self) {
        let mut changed = self.changed.subscribe();
        loop {
            if self.state().inbound_sockets.is_empty() {
                return;
            }
            if changed.changed().await.is_err() {
                return;
            }
        }
    }
}

pub(crate) fn current_inbound_listener() -> Option<Arc<ConsensusBufferObservation>> {
    INBOUND_LISTENER_OBSERVATION.try_with(Arc::clone).ok()
}

#[derive(Clone)]
pub(crate) struct SocketContext {
    observation: Arc<ConsensusBufferObservation>,
    id: u64,
}

pub(crate) async fn scope_inbound_socket<F: Future>(
    context: Option<SocketContext>,
    future: F,
) -> F::Output {
    match context {
        Some(context) => INBOUND_SOCKET_CONTEXT.scope(context, future).await,
        None => future.await,
    }
}

pub(crate) fn inbound_socket_phase(phase: InboundSocketPhase) {
    let _ = INBOUND_SOCKET_CONTEXT.try_with(|context| {
        let mut state = context.observation.state();
        if let Some(owner) = state.inbound_sockets.get_mut(&context.id) {
            owner.phase = phase;
        }
    });
}

struct SocketRegistration(SocketContext);

impl Drop for SocketRegistration {
    fn drop(&mut self) {
        self.0
            .observation
            .state()
            .inbound_sockets
            .remove(&self.0.id);
        self.0.observation.changed.send_replace(());
    }
}

// Field order is the destruction contract: drop TCP before removing its row.
// A context clone holds numeric metadata only and cannot remove the row.
pub(crate) struct InboundSocket {
    stream: TcpStream,
    registration: Option<SocketRegistration>,
}

impl InboundSocket {
    pub(crate) fn new(
        stream: TcpStream,
        observation: Option<&Arc<ConsensusBufferObservation>>,
    ) -> Self {
        let registration = observation.and_then(|observation| {
            let mut state = observation.state();
            let Some(id) = state.next_id.checked_add(1) else {
                state.inbound_socket_registration_exhausted = true;
                return None;
            };
            state.next_id = id;
            state.inbound_sockets.insert(
                id,
                InboundSocketOwner {
                    socket_id: id,
                    phase: InboundSocketPhase::Accepted,
                },
            );
            Some(SocketRegistration(SocketContext {
                observation: Arc::clone(observation),
                id,
            }))
        });
        Self {
            stream,
            registration,
        }
    }

    pub(crate) fn context(&self) -> Option<SocketContext> {
        self.registration.as_ref().map(|owner| owner.0.clone())
    }
}

impl Deref for InboundSocket {
    type Target = TcpStream;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl AsyncRead for InboundSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buffer)
    }
}

impl AsyncWrite for InboundSocket {
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
