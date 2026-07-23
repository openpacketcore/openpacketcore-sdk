//! Complete-frame seam between protected transports and the peer runtime.

use std::future::Future;
use std::net::Shutdown;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

use crate::frame::{read_runtime_wire_frame, write_wire_frame};
use crate::{DiameterFrameLimits, DiameterTlsError};

pub(crate) type FrameTransportFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, DiameterTlsError>> + Send + 'a>>;

/// Receive side of one protected transport that preserves complete Diameter
/// message boundaries.
///
/// Implementations must not return a partial message, must reject a protected
/// frame larger than `limits` before allocating that declared size, and must
/// enforce `completion_timeout` once a fragmented/stream frame starts. The
/// runtime independently enforces `hard_deadline` and validates the returned
/// Diameter header, exact declared length, and decode result. Cancellation may
/// leave the underlying transport unusable; the runtime synchronously closes
/// the associated [`ProtectedFrameTransportClose`] whenever a submitted
/// operation is abandoned.
pub(crate) trait ProtectedFrameReceiver: Send {
    fn receive_frame(
        &mut self,
        limits: DiameterFrameLimits,
        completion_timeout: Duration,
        hard_deadline: Instant,
    ) -> FrameTransportFuture<'_, Bytes>;
}

/// Send side of one protected transport that emits one complete Diameter
/// message per call.
///
/// Implementations must preserve the one-call/one-frame boundary and honor the
/// supplied deadline. `Ok(())` is the runtime's emission linearization point:
/// it is permitted only after the complete single protected record or user
/// message has been accepted and flushed by the transport, never after a
/// partial write or merely queuing work in a background task. An error or
/// cancellation after this method is polled may mean that delivery is
/// uncertain. The runtime independently enforces the deadline, never retries
/// on this connection, and synchronously closes the complete transport before
/// publishing failure.
pub(crate) trait ProtectedFrameSender: Send {
    fn send_frame<'a>(
        &'a mut self,
        wire: &'a [u8],
        limits: DiameterFrameLimits,
        deadline: Instant,
    ) -> FrameTransportFuture<'a, ()>;
}

/// Synchronous full-close authority shared by every runtime lifetime guard.
///
/// `close` must be idempotent, prevent later frame emission, and interrupt
/// in-flight receive and send operations. It must return promptly, must not
/// wait for asynchronous cleanup, and must not expose peer, credential, or
/// payload details.
pub(crate) trait ProtectedFrameTransportClose: Send + Sync {
    fn close(&self);
}

/// Independently owned receive, send, and full-close capabilities for one
/// protected complete-frame transport.
pub(crate) struct ProtectedFrameTransportParts {
    receiver: Box<dyn ProtectedFrameReceiver>,
    sender: Box<dyn ProtectedFrameSender>,
    close: Arc<dyn ProtectedFrameTransportClose>,
}

impl ProtectedFrameTransportParts {
    /// Adapt a protected byte stream into complete Diameter frame operations.
    pub(crate) fn from_stream<T>(io: T, close: Arc<dyn ProtectedFrameTransportClose>) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (reader, writer) = tokio::io::split(io);
        Self::new(
            Box::new(StreamFrameReceiver { reader }),
            Box::new(StreamFrameSender { writer }),
            close,
        )
    }

    pub(crate) fn new(
        receiver: Box<dyn ProtectedFrameReceiver>,
        sender: Box<dyn ProtectedFrameSender>,
        close: Arc<dyn ProtectedFrameTransportClose>,
    ) -> Self {
        Self {
            receiver,
            sender,
            close,
        }
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Box<dyn ProtectedFrameReceiver>,
        Box<dyn ProtectedFrameSender>,
        Arc<dyn ProtectedFrameTransportClose>,
    ) {
        (self.receiver, self.sender, self.close)
    }
}

struct StreamFrameReceiver<R> {
    reader: R,
}

impl<R> ProtectedFrameReceiver for StreamFrameReceiver<R>
where
    R: AsyncRead + Unpin + Send,
{
    fn receive_frame(
        &mut self,
        limits: DiameterFrameLimits,
        completion_timeout: Duration,
        hard_deadline: Instant,
    ) -> FrameTransportFuture<'_, Bytes> {
        Box::pin(read_runtime_wire_frame(
            &mut self.reader,
            limits,
            completion_timeout,
            hard_deadline,
        ))
    }
}

struct StreamFrameSender<W> {
    writer: W,
}

impl<W> ProtectedFrameSender for StreamFrameSender<W>
where
    W: AsyncWrite + Unpin + Send,
{
    fn send_frame<'a>(
        &'a mut self,
        wire: &'a [u8],
        limits: DiameterFrameLimits,
        deadline: Instant,
    ) -> FrameTransportFuture<'a, ()> {
        Box::pin(write_wire_frame(&mut self.writer, wire, limits, deadline))
    }
}

impl ProtectedFrameTransportClose for std::net::TcpStream {
    fn close(&self) {
        let _ = self.shutdown(Shutdown::Both);
    }
}
