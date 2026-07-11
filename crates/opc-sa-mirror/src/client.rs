//! mTLS producer client mirroring live keymat to a designated standby.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::future::BoxFuture;
use opc_ipsec_lb::SaId;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::error::SaMirrorError;
use crate::keymat::{KeyEpoch, SaCounterCheckpoint, SaMirrorInstall};
use crate::ports::SaMirrorProducer;
use crate::wire::{
    read_frame, write_frame, MirrorRequest, MirrorResponse, CONTRACT_VERSION,
    DEFAULT_MAX_FRAME_SIZE,
};

/// Resolver callback used by [`RemoteMirrorProducer::new_with_resolver`].
pub type MirrorAddrResolver =
    Arc<dyn Fn() -> BoxFuture<'static, io::Result<SocketAddr>> + Send + Sync>;

struct Connection {
    reader: Box<dyn AsyncRead + Unpin + Send>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
}

#[derive(Clone)]
enum RemoteTarget {
    Pinned(SocketAddr),
    Resolved {
        server_name: Arc<str>,
        resolve: MirrorAddrResolver,
    },
}

impl RemoteTarget {
    async fn resolve(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Pinned(addr) => Ok(*addr),
            Self::Resolved { resolve, .. } => resolve().await,
        }
    }

    fn tls_server_name(
        &self,
        resolved_addr: SocketAddr,
    ) -> Result<rustls_pki_types::ServerName<'static>, SaMirrorError> {
        match self {
            Self::Pinned(_) => Ok(rustls_pki_types::ServerName::IpAddress(
                resolved_addr.ip().into(),
            )),
            Self::Resolved { server_name, .. } => {
                rustls_pki_types::ServerName::try_from(server_name.to_string())
                    .map_err(|_| SaMirrorError::protocol("invalid TLS server name"))
            }
        }
    }
}

impl fmt::Debug for RemoteTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pinned(addr) => f.debug_tuple("Pinned").field(addr).finish(),
            Self::Resolved { server_name, .. } => f
                .debug_struct("Resolved")
                .field("server_name", server_name)
                .finish_non_exhaustive(),
        }
    }
}

/// mTLS [`SaMirrorProducer`] adapter targeting one designated standby.
///
/// The client keeps a single connection with one in-flight request; clones
/// share the connection. There is deliberately no plaintext constructor
/// (RFC 015 §7.1). Transient I/O failures retry with backoff inside the
/// per-call deadline; the standby-side epoch and idempotency rules make those
/// retries safe.
#[derive(Clone)]
pub struct RemoteMirrorProducer {
    target: RemoteTarget,
    tls_config: Arc<opc_tls::ClientConfig>,
    deadline: Duration,
    max_frame_size: usize,
    node_id: String,
    conn: Arc<Mutex<Option<Connection>>>,
}

impl fmt::Debug for RemoteMirrorProducer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteMirrorProducer")
            .field("target", &self.target)
            .field("deadline", &self.deadline)
            .field("max_frame_size", &self.max_frame_size)
            .field("node_id", &self.node_id)
            .finish_non_exhaustive()
    }
}

impl RemoteMirrorProducer {
    /// Create a new mTLS producer client pinned to `addr`.
    ///
    /// `deadline` bounds every producer method end-to-end, including
    /// reconnect retries with backoff (default 2s when `None`).
    #[must_use]
    pub fn new(
        addr: SocketAddr,
        tls_config: Arc<opc_tls::ClientConfig>,
        deadline: Option<Duration>,
    ) -> Self {
        Self::from_transport(RemoteTarget::Pinned(addr), tls_config, deadline)
    }

    /// Create a new mTLS producer client that re-resolves the standby address
    /// before each new connection.
    ///
    /// TLS verification keeps using `server_name`; it is not changed to the
    /// resolved IP address.
    #[must_use]
    pub fn new_with_resolver(
        server_name: String,
        resolve: MirrorAddrResolver,
        tls_config: Arc<opc_tls::ClientConfig>,
        deadline: Option<Duration>,
    ) -> Self {
        Self::from_transport(
            RemoteTarget::Resolved {
                server_name: Arc::<str>::from(server_name),
                resolve,
            },
            tls_config,
            deadline,
        )
    }

    fn from_transport(
        target: RemoteTarget,
        tls_config: Arc<opc_tls::ClientConfig>,
        deadline: Option<Duration>,
    ) -> Self {
        Self {
            target,
            tls_config,
            deadline: deadline.unwrap_or(Duration::from_secs(2)),
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            node_id: format!("opc-sa-mirror/{}", std::process::id()),
            conn: Arc::new(Mutex::new(None)),
        }
    }

    /// Set the maximum frame header/secret size.
    #[must_use]
    pub fn with_max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        self
    }

    async fn connect(&self) -> Result<Connection, SaMirrorError> {
        let addr = self
            .target
            .resolve()
            .await
            .map_err(|error| SaMirrorError::io("resolve", error))?;
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|error| SaMirrorError::io("connect", error))?;
        let server_name = self.target.tls_server_name(addr)?;
        let connector = tokio_rustls::TlsConnector::from(self.tls_config.clone());
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|error| SaMirrorError::io("tls_connect", error))?;
        let (reader, writer) = tokio::io::split(tls);
        let mut conn = Connection {
            reader: Box::new(reader),
            writer: Box::new(writer),
        };

        write_frame(
            &mut conn.writer,
            &MirrorRequest::Hello {
                contract_version: CONTRACT_VERSION,
                node_id: self.node_id.clone(),
            },
            &[],
            self.max_frame_size,
        )
        .await?;
        let (ack, secret): (MirrorResponse, _) =
            read_frame(&mut conn.reader, self.max_frame_size).await?;
        if !secret.is_empty() {
            return Err(SaMirrorError::protocol(
                "response must not carry a secret tail",
            ));
        }
        let MirrorResponse::HelloAck { contract_version } = ack else {
            return Err(SaMirrorError::protocol("expected HelloAck response"));
        };
        if contract_version != CONTRACT_VERSION {
            return Err(SaMirrorError::VersionMismatch {
                local: CONTRACT_VERSION,
                remote: contract_version,
            });
        }
        Ok(conn)
    }

    async fn do_request(
        &self,
        request: &MirrorRequest,
        secret: &[u8],
    ) -> Result<MirrorResponse, SaMirrorError> {
        let mut guard = self.conn.lock().await;

        // Take the connection out of the slot for the duration of the
        // exchange: if this future is cancelled between writing a request and
        // reading its response, a connection left in the slot would deliver
        // the stale response to the next caller. Taking it means cancellation
        // (and any error) drops the connection and the next request
        // reconnects cleanly.
        let mut conn = match guard.take() {
            Some(conn) => conn,
            None => self.connect().await?,
        };

        let exchange = async {
            write_frame(&mut conn.writer, request, secret, self.max_frame_size).await?;
            let (response, tail): (MirrorResponse, _) =
                read_frame(&mut conn.reader, self.max_frame_size).await?;
            if !tail.is_empty() {
                return Err(SaMirrorError::protocol(
                    "response must not carry a secret tail",
                ));
            }
            Ok(response)
        };
        let response = exchange.await?;
        *guard = Some(conn);
        Ok(response)
    }

    async fn send_with_retry(
        &self,
        request: &MirrorRequest,
        secret: &[u8],
    ) -> Result<(), SaMirrorError> {
        let attempts = async {
            let mut backoff_ms = 50_u64;
            loop {
                match self.do_request(request, secret).await {
                    Ok(MirrorResponse::Accepted) => return Ok(()),
                    Ok(MirrorResponse::Rejected { code }) => {
                        return Err(SaMirrorError::from_remote_code(&code));
                    }
                    Ok(MirrorResponse::HelloAck { .. }) => {
                        return Err(SaMirrorError::protocol("unexpected HelloAck response"));
                    }
                    // Only transport failures retry; the standby's epoch and
                    // idempotency rules make replaying the frame safe.
                    Err(SaMirrorError::Io { .. }) => {
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        backoff_ms = (backoff_ms * 2).min(1000);
                    }
                    Err(error) => return Err(error),
                }
            }
        };
        match tokio::time::timeout(self.deadline, attempts).await {
            Ok(result) => result,
            Err(_elapsed) => Err(SaMirrorError::DeadlineExceeded),
        }
    }
}

#[async_trait]
impl SaMirrorProducer for RemoteMirrorProducer {
    async fn mirror_install(&self, install: SaMirrorInstall) -> Result<(), SaMirrorError> {
        install.validate()?;
        let header = MirrorRequest::install_header(&install);
        self.send_with_retry(&header, install.keymat.expose_secret_bytes())
            .await
    }

    async fn mirror_checkpoint(
        &self,
        checkpoint: SaCounterCheckpoint,
    ) -> Result<(), SaMirrorError> {
        checkpoint.validate()?;
        let header = MirrorRequest::checkpoint_header(&checkpoint);
        self.send_with_retry(&header, &[]).await
    }

    async fn mirror_withdraw(&self, sa: SaId, epoch: KeyEpoch) -> Result<(), SaMirrorError> {
        crate::keymat::validate_sa(sa)?;
        let header = MirrorRequest::Withdraw {
            sa: sa.into(),
            epoch: epoch.get(),
        };
        self.send_with_retry(&header, &[]).await
    }
}
