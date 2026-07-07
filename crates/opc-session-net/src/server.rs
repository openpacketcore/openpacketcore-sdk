use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::StreamExt;
use opc_session_store::quorum::SessionStoreBackend;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use tracing;

use crate::error::ProtocolError;
use crate::protocol::{
    read_frame_within, write_frame, Request, Response, CONTRACT_VERSION, DEFAULT_MAX_FRAME_SIZE,
};

/// Handle to a running [`SessionReplicationServer`].
#[derive(Debug)]
pub struct ServerHandle {
    abort_handle: tokio::task::AbortHandle,
    _shutdown_tx: tokio::sync::mpsc::Sender<()>,
    connection_handles: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
}

impl ServerHandle {
    /// Abort the server task and all in-flight connection handlers immediately.
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

/// Default per-frame read deadline for accepted connections.
const DEFAULT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Networked session replication server.
pub struct SessionReplicationServer {
    backend: Arc<dyn SessionStoreBackend>,
    tls_config: Option<Arc<opc_tls::ServerConfig>>,
    max_connections: usize,
    max_frame_size: usize,
    idle_timeout: std::time::Duration,
}

impl fmt::Debug for SessionReplicationServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionReplicationServer")
            .field("tls_config", &self.tls_config.is_some())
            .field("max_connections", &self.max_connections)
            .field("max_frame_size", &self.max_frame_size)
            .finish()
    }
}

impl SessionReplicationServer {
    /// Create a new mTLS server.
    ///
    /// Production session replication must run over authenticated TLS. Use
    /// [`SessionReplicationServer::new_insecure`] only in test builds that
    /// explicitly enable the `insecure-test` feature.
    pub fn new(
        backend: Arc<dyn SessionStoreBackend>,
        tls_config: Arc<opc_tls::ServerConfig>,
    ) -> Self {
        Self {
            backend,
            tls_config: Some(tls_config),
            max_connections: 128,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }

    /// Create a new plaintext server (requires `insecure-test` feature).
    #[cfg(feature = "insecure-test")]
    pub fn new_insecure(backend: Arc<dyn SessionStoreBackend>) -> Self {
        Self {
            backend,
            tls_config: None,
            max_connections: 128,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }

    /// Set the per-frame read deadline for accepted connections. A peer that
    /// does not deliver a complete frame within this window is disconnected,
    /// freeing its connection slot.
    pub fn with_idle_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set the maximum number of concurrent connections.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Set the maximum frame size in bytes.
    pub fn with_max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        self
    }

    /// Bind and start accepting connections.
    pub async fn listen(
        self,
        bind_addr: SocketAddr,
    ) -> std::io::Result<(ServerHandle, SocketAddr)> {
        let listener = TcpListener::bind(bind_addr).await?;
        let bound_addr = listener.local_addr()?;
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
        let sem = Arc::new(Semaphore::new(self.max_connections));
        let tls_config = self.tls_config.clone();
        let backend = self.backend.clone();
        let max_frame_size = self.max_frame_size;
        let idle_timeout = self.idle_timeout;
        let connection_handles = Arc::new(Mutex::new(Vec::new()));
        let connection_handles_clone = connection_handles.clone();

        let handle = tokio::spawn(async move {
            loop {
                let permit = match sem.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };

                tokio::select! {
                    biased;
                    _ = shutdown_rx.recv() => break,
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((stream, peer)) => {
                                let backend = backend.clone();
                                let tls_config = tls_config.clone();
                                let handles = connection_handles_clone.clone();
                                tracing::debug!(%peer, "accepted connection");
                                let conn_handle = tokio::spawn(async move {
                                    let _permit = permit;
                                    if let Err(e) = handle_connection(
                                        backend,
                                        stream,
                                        tls_config,
                                        max_frame_size,
                                        idle_timeout,
                                    )
                                    .await
                                    {
                                        tracing::debug!(%peer, error = ?e, "connection handler exited");
                                    }
                                });
                                handles.lock().await.push(conn_handle.abort_handle());
                            }
                            Err(e) => {
                                tracing::warn!(error = ?e, "accept failed");
                            }
                        }
                    }
                }
            }
        });

        Ok((
            ServerHandle {
                abort_handle: handle.abort_handle(),
                _shutdown_tx: shutdown_tx,
                connection_handles,
            },
            bound_addr,
        ))
    }
}

async fn handle_connection(
    backend: Arc<dyn SessionStoreBackend>,
    stream: TcpStream,
    tls_config: Option<Arc<opc_tls::ServerConfig>>,
    max_frame_size: usize,
    idle_timeout: std::time::Duration,
) -> Result<(), ProtocolError> {
    if let Some(tls_config) = tls_config {
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
        let tls_stream = tokio::time::timeout(idle_timeout, acceptor.accept(stream))
            .await
            .map_err(|_| {
                ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "TLS handshake timed out",
                ))
            })?
            .map_err(ProtocolError::Io)?;
        let (mut r, mut w) = tokio::io::split(tls_stream);
        dispatch(backend, &mut r, &mut w, max_frame_size, idle_timeout).await
    } else {
        let (mut r, mut w) = tokio::io::split(stream);
        dispatch(backend, &mut r, &mut w, max_frame_size, idle_timeout).await
    }
}

async fn dispatch<R, W>(
    backend: Arc<dyn SessionStoreBackend>,
    reader: &mut R,
    writer: &mut W,
    max_frame_size: usize,
    idle_timeout: std::time::Duration,
) -> Result<(), ProtocolError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    // Hello handshake — bounded so a peer that connects and stalls is reaped.
    let hello: Request = read_frame_within(reader, max_frame_size, idle_timeout).await?;
    match hello {
        Request::Hello {
            contract_version, ..
        } => {
            if contract_version != CONTRACT_VERSION {
                return Err(ProtocolError::VersionMismatch {
                    local: CONTRACT_VERSION,
                    remote: contract_version,
                });
            }
            write_frame(
                writer,
                &Response::HelloAck {
                    contract_version: CONTRACT_VERSION,
                },
            )
            .await?;
        }
        _ => {
            return Err(ProtocolError::BackendUnavailable(
                "expected Hello request".into(),
            ));
        }
    }

    // Dispatch loop
    loop {
        let req: Request = match read_frame_within(reader, max_frame_size, idle_timeout).await {
            Ok(r) => r,
            Err(ProtocolError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };

        match req {
            Request::Capabilities => {
                let caps = backend.capabilities().await;
                write_frame(writer, &Response::Capabilities(caps)).await?;
            }
            Request::Get { key } => {
                let res = backend.get(&key).await;
                write_frame(writer, &Response::Get(res)).await?;
            }
            Request::CompareAndSet { op } => {
                let res = backend.compare_and_set(op).await;
                write_frame(writer, &Response::CompareAndSet(res)).await?;
            }
            Request::DeleteFenced { lease } => {
                let res = backend.delete_fenced(&lease).await;
                write_frame(writer, &Response::DeleteFenced(res)).await?;
            }
            Request::RefreshTtl { lease, ttl } => {
                let res = backend.refresh_ttl(&lease, ttl).await;
                write_frame(writer, &Response::RefreshTtl(res)).await?;
            }
            Request::Batch { ops } => {
                let res = backend.batch(ops).await;
                write_frame(writer, &Response::Batch(res)).await?;
            }
            Request::MaxReplicationSequence => {
                let res = backend.max_replication_sequence().await;
                write_frame(writer, &Response::MaxReplicationSequence(res)).await?;
            }
            Request::GetReplicationLog { start, limit } => {
                let res = backend.get_replication_log(start, limit).await;
                write_frame(writer, &Response::GetReplicationLog(res)).await?;
            }
            Request::ReplicateEntry { entry } => {
                let res = backend.replicate_entry(entry).await;
                write_frame(writer, &Response::ReplicateEntry(res)).await?;
            }
            Request::RebuildReplicationState { entries } => {
                let res = backend.rebuild_replication_state(entries).await;
                write_frame(writer, &Response::RebuildReplicationState(res)).await?;
            }
            Request::Watch { start_sequence } => match backend.watch(start_sequence).await {
                Ok(mut stream) => {
                    write_frame(writer, &Response::WatchStream).await?;
                    while let Some(item) = stream.next().await {
                        if write_frame(writer, &Response::WatchEntry(item))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
                Err(e) => {
                    write_frame(writer, &Response::WatchEntry(Err(e))).await?;
                }
            },
            Request::NextLeaseInfo => {
                let res = backend.next_lease_info().await;
                write_frame(writer, &Response::NextLeaseInfo(res)).await?;
            }
            Request::AcquireLease { key, owner, ttl } => {
                let res = backend.acquire(&key, owner, ttl).await;
                write_frame(writer, &Response::AcquireLease(res)).await?;
            }
            Request::RenewLease { lease, ttl } => {
                let res = backend.renew(&lease, ttl).await;
                write_frame(writer, &Response::RenewLease(res)).await?;
            }
            Request::ReleaseLease { lease } => {
                let res = backend.release(lease).await;
                write_frame(writer, &Response::ReleaseLease(res)).await?;
            }
            Request::Hello { .. } => {
                write_frame(
                    writer,
                    &Response::Error {
                        message: "duplicate Hello".into(),
                    },
                )
                .await?;
            }
        }
    }

    Ok(())
}
