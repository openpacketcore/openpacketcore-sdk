//! Synchronous qualification scopes around the original TLS implementation.
//!
//! No allocator is selected by the library. An explicitly installed observer
//! may assign Rust allocation provenance while each operation executes. A scope
//! never crosses Pending or an await. TCP polling/destruction is a separate
//! category. Frozen per-attempt material has a separate source group; shared
//! controller/provider material created before that scope is outside it. Native
//! crypto allocations and kernel storage are outside this API.

use std::future::Future;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::ConsensusBufferObservation;

/// The actual endpoint enrolled by an existing TCP observer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsEndpoint {
    /// Socket identity in this observer's accepted-endpoint census.
    Inbound(u64),
    /// Socket identity in this observer's connected-endpoint census.
    Outbound(u64),
}

/// Allocation origin. Material source IDs are distinct for each retry, even
/// when the original detached attempt or material epoch is unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsAllocationSource {
    /// Private TLS state for this actual connected or accepted endpoint.
    Connection(TlsEndpoint),
    /// Frozen config created for this accepted endpoint.
    InboundMaterial(u64),
    /// Frozen config created during this detached outbound attempt.
    OutboundMaterial(u64),
}

/// One synchronous call boundary, not an application payload or byte estimate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsAllocationPhase {
    /// Config clone, name/ALPN construction and original connect/accept call.
    Construct,
    /// One poll of the original handshake future.
    HandshakePoll,
    /// Destruction of that future, including cancellation and error paths.
    HandshakeDrop,
    /// One established-stream read poll.
    Read,
    /// One established-stream write or vectored-write poll.
    Write,
    /// One established-stream flush poll.
    Flush,
    /// One established-stream shutdown poll.
    Shutdown,
    /// Destruction of the complete TLS stream after its last split owner.
    StreamDrop,
    /// Nested TCP I/O and runtime bookkeeping; excluded from TLS object bytes.
    SocketPoll,
    /// Nested TCP destruction and socket-observer bookkeeping.
    SocketDrop,
    /// Frozen config construction, after shared-controller reconciliation.
    MaterialConstruct,
    /// Original Tokio split container, including inline TLS state and Arc metadata.
    OwnerStorage,
}

/// Qualification-only allocation context with no transport ownership.
///
/// Implementations must retain only numeric metadata. `scope` must invoke its
/// callback synchronously, and release all thread-local guards before returning.
/// The library protects the actual operation from a missing or repeated callback:
/// it executes exactly once, falling back to an unobserved call if necessary.
/// Observers must report incomplete enrollment and receipt-table saturation.
/// No observer callback may wait for another connection or retain the callback.
pub trait TlsAllocationObserver: Send + Sync {
    /// Register an allocation source. None means unobserved.
    fn open(&self, source: TlsAllocationSource) -> Option<u64>;

    /// Link a connection to the separately registered frozen-material source.
    /// The material source can have live receipts after its constructor closed.
    fn link_material(&self, connection: u64, material: u64);

    /// Execute one synchronous TLS or nested socket operation under its group.
    fn scope(&self, owner: u64, phase: TlsAllocationPhase, operation: &mut dyn FnMut());

    /// The original handshake returned its established stream to the wrapper.
    fn established(&self, owner: u64);

    /// The material constructor, handshake future, or stream has finished.
    /// Outstanding allocation receipts must survive this notification until free.
    fn close(&self, owner: u64);
}

impl ConsensusBufferObservation {
    /// Attach a qualification observer before enrolling listeners/peer clones.
    ///
    /// Existing TLS owners retain their original numeric observer context.
    /// This does not choose an allocator or retrofit existing connections.
    pub fn set_tls_allocation_observer(&self, observer: Arc<dyn TlsAllocationObserver>) {
        self.state().tls_allocations = Some(observer);
    }

    pub(super) fn open_tls(&self, endpoint: TlsEndpoint) -> Option<TlsOwner> {
        self.open_tls_source(TlsAllocationSource::Connection(endpoint))
    }

    pub(super) fn open_tls_source(&self, source: TlsAllocationSource) -> Option<TlsOwner> {
        // Release the common observer lock before calling another observer.
        let observer = self.state().tls_allocations.clone()?;
        let id = observer.open(source)?;
        Some(TlsOwner {
            context: TlsContext { observer, id },
        })
    }
}

// Clones carry only an observer and numeric identity. They cannot close an
// owner and do not retain a socket, future, TLS session, payload or config.
#[derive(Clone)]
pub(crate) struct TlsContext {
    observer: Arc<dyn TlsAllocationObserver>,
    id: u64,
}

fn within<R>(
    context: Option<&TlsContext>,
    phase: TlsAllocationPhase,
    mut operation: impl FnMut() -> R,
) -> R {
    let Some(context) = context else {
        return operation();
    };
    let mut output = None;
    context.observer.scope(context.id, phase, &mut || {
        if output.is_none() {
            output = Some(operation());
        }
    });
    output.unwrap_or_else(operation)
}

/// Unique registration, moved from handshake to stream without re-enrollment.
pub(crate) struct TlsOwner {
    context: TlsContext,
}

impl TlsOwner {
    pub(crate) fn context(&self) -> TlsContext {
        self.context.clone()
    }

    pub(crate) fn link_material(owner: Option<&Self>, material: Option<&TlsContext>) {
        if let (Some(owner), Some(material)) = (owner, material) {
            if Arc::ptr_eq(&owner.context.observer, &material.observer) {
                owner
                    .context
                    .observer
                    .link_material(owner.context.id, material.id);
            }
        }
    }

    pub(crate) fn run<R>(
        owner: Option<&Self>,
        phase: TlsAllocationPhase,
        operation: impl FnMut() -> R,
    ) -> R {
        within(owner.map(|owner| &owner.context), phase, operation)
    }
}

impl Drop for TlsOwner {
    fn drop(&mut self) {
        self.context.observer.close(self.context.id);
    }
}

// No boxing is necessary: the pinned tokio-rustls connect/accept futures are
// Unpin for our concrete Unpin TCP wrapper. Option::take provides safe Drop.
pub(crate) struct TlsHandshake<F> {
    future: Option<F>,
    owner: Option<TlsOwner>,
}

impl<F> TlsHandshake<F> {
    pub(crate) fn new(future: F, owner: Option<TlsOwner>) -> Self {
        Self {
            future: Some(future),
            owner,
        }
    }
}

impl<F, S> Future for TlsHandshake<F>
where
    F: Future<Output = io::Result<S>> + Unpin,
{
    type Output = io::Result<TlsStream<S>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let result = TlsOwner::run(
            this.owner.as_ref(),
            TlsAllocationPhase::HandshakePoll,
            || match this.future.as_mut() {
                Some(future) => Pin::new(future).poll(cx),
                None => Poll::Pending,
            },
        );
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                TlsOwner::run(
                    this.owner.as_ref(),
                    TlsAllocationPhase::HandshakeDrop,
                    || drop(this.future.take()),
                );
                match result {
                    Ok(stream) => {
                        if let Some(owner) = &this.owner {
                            owner.context.observer.established(owner.context.id);
                        }
                        Poll::Ready(Ok(TlsStream {
                            inner: Some(stream),
                            owner: this.owner.take(),
                        }))
                    }
                    Err(error) => {
                        // Source-group receipts for an allocation-bearing error
                        // remain valid after this owner closes.
                        drop(this.owner.take());
                        Poll::Ready(Err(error))
                    }
                }
            }
        }
    }
}

impl<F> Drop for TlsHandshake<F> {
    fn drop(&mut self) {
        TlsOwner::run(
            self.owner.as_ref(),
            TlsAllocationPhase::HandshakeDrop,
            || drop(self.future.take()),
        );
        // The owner field drops only after the complete future was destroyed.
    }
}

pub(crate) struct TlsStream<S> {
    inner: Option<S>,
    owner: Option<TlsOwner>,
}

impl<S> TlsStream<S> {
    pub(crate) fn inner(&self) -> Option<&S> {
        self.inner.as_ref()
    }

    pub(crate) fn split(self) -> Option<(tokio::io::ReadHalf<Self>, tokio::io::WriteHalf<Self>)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let context = self.allocation_context();
        let mut stream = Some(self);
        within(context.as_ref(), TlsAllocationPhase::OwnerStorage, || {
            stream.take().map(tokio::io::split)
        })
    }

    fn allocation_context(&self) -> Option<TlsContext> {
        self.owner.as_ref().map(|owner| owner.context.clone())
    }
}

impl<S> Drop for TlsStream<S> {
    fn drop(&mut self) {
        TlsOwner::run(self.owner.as_ref(), TlsAllocationPhase::StreamDrop, || {
            drop(self.inner.take())
        });
    }
}

pub(crate) struct TlsIo<S> {
    inner: Option<S>,
    context: Option<TlsContext>,
}

impl<S> TlsIo<S> {
    fn allocation_context(&self) -> Option<TlsContext> {
        self.context.clone()
    }

    pub(crate) fn new(inner: S, owner: Option<&TlsOwner>) -> Self {
        Self {
            inner: Some(inner),
            context: owner.map(|owner| owner.context.clone()),
        }
    }
}

impl<S> Drop for TlsIo<S> {
    fn drop(&mut self) {
        within(
            self.context.as_ref(),
            TlsAllocationPhase::SocketDrop,
            || drop(self.inner.take()),
        );
    }
}

// The two wrappers differ only in classification. Keep the forwarding methods
// explicit so no TLS I/O capability silently bypasses a scope.
macro_rules! scoped_io {
    ($wrapper:ident, $read:expr, $write:expr, $flush:expr, $shutdown:expr) => {
        impl<S: AsyncRead + Unpin> AsyncRead for $wrapper<S> {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buffer: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let this = self.get_mut();
                let context = this.allocation_context();
                within(context.as_ref(), $read, || match this.inner.as_mut() {
                    Some(inner) => Pin::new(inner).poll_read(cx, buffer),
                    None => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
                })
            }
        }

        impl<S: AsyncWrite + Unpin> AsyncWrite for $wrapper<S> {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buffer: &[u8],
            ) -> Poll<io::Result<usize>> {
                let this = self.get_mut();
                let context = this.allocation_context();
                within(context.as_ref(), $write, || match this.inner.as_mut() {
                    Some(inner) => Pin::new(inner).poll_write(cx, buffer),
                    None => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
                })
            }

            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                let this = self.get_mut();
                let context = this.allocation_context();
                within(context.as_ref(), $flush, || match this.inner.as_mut() {
                    Some(inner) => Pin::new(inner).poll_flush(cx),
                    None => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
                })
            }

            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                let this = self.get_mut();
                let context = this.allocation_context();
                within(context.as_ref(), $shutdown, || match this.inner.as_mut() {
                    Some(inner) => Pin::new(inner).poll_shutdown(cx),
                    None => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
                })
            }

            fn poll_write_vectored(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buffers: &[IoSlice<'_>],
            ) -> Poll<io::Result<usize>> {
                let this = self.get_mut();
                let context = this.allocation_context();
                within(context.as_ref(), $write, || match this.inner.as_mut() {
                    Some(inner) => Pin::new(inner).poll_write_vectored(cx, buffers),
                    None => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
                })
            }

            fn is_write_vectored(&self) -> bool {
                self.inner
                    .as_ref()
                    .is_some_and(AsyncWrite::is_write_vectored)
            }
        }
    };
}

scoped_io!(
    TlsStream,
    TlsAllocationPhase::Read,
    TlsAllocationPhase::Write,
    TlsAllocationPhase::Flush,
    TlsAllocationPhase::Shutdown
);
scoped_io!(
    TlsIo,
    TlsAllocationPhase::SocketPoll,
    TlsAllocationPhase::SocketPoll,
    TlsAllocationPhase::SocketPoll,
    TlsAllocationPhase::SocketPoll
);
