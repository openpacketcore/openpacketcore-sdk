//! mTLS receiving server feeding a standby [`SaMirrorSink`].

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};

use crate::error::SaMirrorError;
use crate::keymat::{KeyEpoch, SaCounterCheckpoint};
use crate::ports::SaMirrorSink;
use crate::wire::{
    install_from_wire, read_frame_within, write_frame, MirrorRequest, MirrorResponse,
    CONTRACT_VERSION, DEFAULT_MAX_FRAME_SIZE,
};

/// Default per-frame read deadline for accepted connections.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Handle to a running [`SaMirrorReceiver`].
#[derive(Debug)]
pub struct ReceiverHandle {
    abort_handle: tokio::task::AbortHandle,
    _shutdown_tx: tokio::sync::mpsc::Sender<()>,
    connection_handles: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
}

impl ReceiverHandle {
    /// Abort the server task and all in-flight connection handlers.
    pub fn abort(&self) {
        self.abort_handle.abort();
        let handles = self.connection_handles.clone();
        tokio::spawn(async move {
            let mut guard = handles.lock().await;
            for handle in guard.drain(..) {
                handle.abort();
            }
        });
    }

    /// Request graceful shutdown.
    pub fn shutdown(self) {
        drop(self._shutdown_tx);
    }
}

/// mTLS server that places received mirror frames into a [`SaMirrorSink`].
///
/// There is deliberately no plaintext constructor, not even behind a test
/// feature: mirror frames carry live traffic keys (RFC 015 §7.1). The sink
/// port is not a session-store trait, so this plane cannot be pointed at a
/// persisting backend.
pub struct SaMirrorReceiver {
    sink: Arc<dyn SaMirrorSink>,
    tls_config: Arc<opc_tls::ServerConfig>,
    max_connections: usize,
    max_frame_size: usize,
    idle_timeout: Duration,
}

impl fmt::Debug for SaMirrorReceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SaMirrorReceiver")
            .field("max_connections", &self.max_connections)
            .field("max_frame_size", &self.max_frame_size)
            .field("idle_timeout", &self.idle_timeout)
            .finish_non_exhaustive()
    }
}

impl SaMirrorReceiver {
    /// Create a new mTLS mirror receiver.
    #[must_use]
    pub fn new(sink: Arc<dyn SaMirrorSink>, tls_config: Arc<opc_tls::ServerConfig>) -> Self {
        Self {
            sink,
            tls_config,
            max_connections: 128,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }

    /// Set the per-frame read deadline for accepted connections.
    #[must_use]
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set the maximum number of concurrent connections.
    #[must_use]
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Set the maximum frame header/secret size in bytes.
    #[must_use]
    pub fn with_max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        self
    }

    /// Bind and start accepting connections.
    pub async fn listen(
        self,
        bind_addr: SocketAddr,
    ) -> std::io::Result<(ReceiverHandle, SocketAddr)> {
        let listener = TcpListener::bind(bind_addr).await?;
        let bound_addr = listener.local_addr()?;
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
        let sem = Arc::new(Semaphore::new(self.max_connections));
        let sink = self.sink.clone();
        let tls_config = self.tls_config.clone();
        let max_frame_size = self.max_frame_size;
        let idle_timeout = self.idle_timeout;
        let connection_handles = Arc::new(Mutex::new(Vec::new()));
        let connection_handles_clone = connection_handles.clone();

        let handle = tokio::spawn(async move {
            loop {
                let permit = match sem.clone().acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => break,
                };

                tokio::select! {
                    biased;
                    _ = shutdown_rx.recv() => break,
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((stream, peer)) => {
                                let sink = sink.clone();
                                let tls_config = tls_config.clone();
                                let handles = connection_handles_clone.clone();
                                tracing::debug!(%peer, "accepted mirror connection");
                                let conn_handle = tokio::spawn(async move {
                                    let _permit = permit;
                                    if let Err(error) = handle_connection(
                                        sink,
                                        stream,
                                        tls_config,
                                        max_frame_size,
                                        idle_timeout,
                                    )
                                    .await
                                    {
                                        tracing::debug!(%peer, error = ?error, "mirror connection handler exited");
                                    }
                                });
                                handles.lock().await.push(conn_handle.abort_handle());
                            }
                            Err(error) => {
                                tracing::warn!(error = ?error, "mirror accept failed");
                            }
                        }
                    }
                }
            }
        });

        Ok((
            ReceiverHandle {
                abort_handle: handle.abort_handle(),
                _shutdown_tx: shutdown_tx,
                connection_handles,
            },
            bound_addr,
        ))
    }
}

async fn handle_connection(
    sink: Arc<dyn SaMirrorSink>,
    stream: TcpStream,
    tls_config: Arc<opc_tls::ServerConfig>,
    max_frame_size: usize,
    idle_timeout: Duration,
) -> Result<(), SaMirrorError> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
    let tls_stream = tokio::time::timeout(idle_timeout, acceptor.accept(stream))
        .await
        .map_err(|_| SaMirrorError::Io {
            operation: "tls_accept",
            kind: std::io::ErrorKind::TimedOut,
            raw_os_error: None,
        })?
        .map_err(|error| SaMirrorError::io("tls_accept", error))?;
    let (mut reader, mut writer) = tokio::io::split(tls_stream);
    serve_stream(
        sink.as_ref(),
        &mut reader,
        &mut writer,
        max_frame_size,
        idle_timeout,
    )
    .await
}

/// Serve one framed mirror connection until EOF or a protocol violation.
///
/// Application-level rejections (stale epoch, capacity, ...) answer with a
/// redaction-safe code and keep the connection; protocol violations (secret
/// tails on non-install frames, malformed headers, version skew) fail the
/// connection closed.
pub(crate) async fn serve_stream<R, W>(
    sink: &dyn SaMirrorSink,
    reader: &mut R,
    writer: &mut W,
    max_frame_size: usize,
    idle_timeout: Duration,
) -> Result<(), SaMirrorError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    // Hello handshake — bounded so a peer that connects and stalls is reaped.
    let (hello, secret): (MirrorRequest, _) =
        read_frame_within(reader, max_frame_size, idle_timeout).await?;
    let MirrorRequest::Hello {
        contract_version, ..
    } = hello
    else {
        return Err(SaMirrorError::protocol("expected Hello request"));
    };
    if !secret.is_empty() {
        return Err(SaMirrorError::protocol(
            "Hello must not carry a secret tail",
        ));
    }
    write_frame(
        writer,
        &MirrorResponse::HelloAck {
            contract_version: CONTRACT_VERSION,
        },
        &[],
        max_frame_size,
    )
    .await?;
    if contract_version != CONTRACT_VERSION {
        return Err(SaMirrorError::VersionMismatch {
            local: CONTRACT_VERSION,
            remote: contract_version,
        });
    }

    loop {
        let (request, secret): (MirrorRequest, _) =
            match read_frame_within(reader, max_frame_size, idle_timeout).await {
                Ok(frame) => frame,
                Err(SaMirrorError::Io {
                    kind: std::io::ErrorKind::UnexpectedEof,
                    ..
                }) => break,
                Err(error) => return Err(error),
            };

        let outcome = match request {
            MirrorRequest::Hello { .. } => {
                return Err(SaMirrorError::protocol("duplicate Hello"));
            }
            MirrorRequest::Install {
                sa,
                epoch,
                format,
                send_iv_next,
                replay_highest_accepted,
            } => match install_from_wire(
                sa,
                epoch,
                format,
                send_iv_next,
                replay_highest_accepted,
                secret,
            ) {
                Ok(install) => sink.accept_install(install).await,
                Err(error) => Err(error),
            },
            MirrorRequest::Checkpoint {
                sa,
                epoch,
                send_iv_next,
                replay_highest_accepted,
            } => {
                if !secret.is_empty() {
                    return Err(SaMirrorError::protocol(
                        "Checkpoint must not carry a secret tail",
                    ));
                }
                match KeyEpoch::new(epoch) {
                    Ok(epoch) => {
                        sink.accept_checkpoint(SaCounterCheckpoint {
                            sa: sa.into(),
                            epoch,
                            send_iv_next,
                            replay_highest_accepted,
                        })
                        .await
                    }
                    Err(error) => Err(error),
                }
            }
            MirrorRequest::Withdraw { sa, epoch } => {
                if !secret.is_empty() {
                    return Err(SaMirrorError::protocol(
                        "Withdraw must not carry a secret tail",
                    ));
                }
                match KeyEpoch::new(epoch) {
                    Ok(epoch) => sink.accept_withdraw(sa.into(), epoch).await,
                    Err(error) => Err(error),
                }
            }
        };

        let response = match outcome {
            Ok(()) => MirrorResponse::Accepted,
            Err(error) => MirrorResponse::Rejected {
                code: error.code().to_string(),
            },
        };
        write_frame(writer, &response, &[], max_frame_size).await?;
    }

    Ok(())
}
