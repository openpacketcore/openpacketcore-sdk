//! Authenticated follower-served committed-config recovery and watch transport.

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::future::Future;
use std::io;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::{self, BoxStream};
use futures_util::StreamExt;
use opc_config_bus::{
    AuthorityMode, CommittedConfigHistoryEntry, ConfigBus, ConfigHistoryPage, ConfigRevisionCursor,
    PublishedSnapshot, StoreError, StoreErrorCode, MAX_CONFIG_HISTORY_PAGE_ENTRIES,
};
use opc_config_model::OpcConfig;
use opc_persist::ConfigConsensusIdentity;
use opc_tls::{
    peer_tls_identity_from_client_connection, peer_tls_identity_from_server_connection,
    AuthenticatedClientConfig, AuthenticatedServerConfig, TlsAdmittedConnection,
    TlsClientHandshake, TlsHandshakeRunError, TlsMaterialAvailability, TlsMaterialError,
};
use opc_types::{ConfigVersion, SchemaDigest, SpiffeId, TxId};
use rustls_pki_types::ServerName;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};

/// Dedicated ALPN for the read-only committed-config watch protocol.
pub const CONFIG_WATCH_ALPN: &[u8] = b"opc-config-watch/1";
/// Exact protocol/profile revision implemented by this SDK build.
pub const CONFIG_WATCH_WIRE_REVISION: u16 = 2;
/// Largest encoded bootstrap or operation request accepted before allocation.
pub const CONFIG_WATCH_MAX_REQUEST_FRAME_BYTES: usize = 16 * 1024;
/// Largest encoded snapshot or history-page response accepted before allocation.
pub const CONFIG_WATCH_MAX_RESPONSE_FRAME_BYTES: usize = 8 * 1024 * 1024;
/// Largest server-side long poll admitted by one page request.
pub const CONFIG_WATCH_MAX_LONG_POLL: Duration = Duration::from_secs(30);
/// Maximum exact client identities admitted by one server binding.
pub const CONFIG_WATCH_MAX_CLIENT_IDENTITIES: usize = 256;
/// Maximum concurrent authenticated connections retained by one server.
pub const CONFIG_WATCH_MAX_CONCURRENT_CONNECTIONS: usize = 32;

const CONFIG_WATCH_ERROR_SET_REVISION: u16 = 1;
const HANDSHAKE_FRAME_BYTES: usize = 16 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const BACKEND_TIMEOUT: Duration = Duration::from_secs(10);
const RECONNECT_BACKOFF_MIN: Duration = Duration::from_millis(50);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(1);
const INITIAL_ENCODED_CHUNK_BYTES: usize = 4 * 1024;
const ENCODED_CHUNK_BYTES: usize = 64 * 1024;

/// Exact semantic and resource profile proved before any read is dispatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigWatchContractProfile {
    /// Revision of request/response DTOs.
    pub wire_revision: u16,
    /// Revision of the closed, redaction-safe error set.
    pub error_set_revision: u16,
    /// Largest encoded request frame.
    pub max_request_frame_bytes: u32,
    /// Largest encoded response frame.
    pub max_response_frame_bytes: u32,
    /// Largest history page by record count.
    pub max_page_entries: u16,
    /// Largest server-side long poll in milliseconds.
    pub max_long_poll_millis: u32,
}

impl ConfigWatchContractProfile {
    /// Whether this is the exact profile implemented by this SDK build.
    pub const fn is_current(self) -> bool {
        self.wire_revision == CURRENT_CONFIG_WATCH_CONTRACT_PROFILE.wire_revision
            && self.error_set_revision == CURRENT_CONFIG_WATCH_CONTRACT_PROFILE.error_set_revision
            && self.max_request_frame_bytes
                == CURRENT_CONFIG_WATCH_CONTRACT_PROFILE.max_request_frame_bytes
            && self.max_response_frame_bytes
                == CURRENT_CONFIG_WATCH_CONTRACT_PROFILE.max_response_frame_bytes
            && self.max_page_entries == CURRENT_CONFIG_WATCH_CONTRACT_PROFILE.max_page_entries
            && self.max_long_poll_millis
                == CURRENT_CONFIG_WATCH_CONTRACT_PROFILE.max_long_poll_millis
    }
}

/// The one config-watch contract profile supported by this SDK build.
pub const CURRENT_CONFIG_WATCH_CONTRACT_PROFILE: ConfigWatchContractProfile =
    ConfigWatchContractProfile {
        wire_revision: CONFIG_WATCH_WIRE_REVISION,
        error_set_revision: CONFIG_WATCH_ERROR_SET_REVISION,
        max_request_frame_bytes: CONFIG_WATCH_MAX_REQUEST_FRAME_BYTES as u32,
        max_response_frame_bytes: CONFIG_WATCH_MAX_RESPONSE_FRAME_BYTES as u32,
        max_page_entries: MAX_CONFIG_HISTORY_PAGE_ENTRIES as u16,
        max_long_poll_millis: CONFIG_WATCH_MAX_LONG_POLL.as_millis() as u32,
    };

const _: () = {
    assert!(CONFIG_WATCH_MAX_REQUEST_FRAME_BYTES <= u32::MAX as usize);
    assert!(CONFIG_WATCH_MAX_RESPONSE_FRAME_BYTES <= u32::MAX as usize);
    assert!(MAX_CONFIG_HISTORY_PAGE_ENTRIES <= u16::MAX as usize);
    assert!(CONFIG_WATCH_MAX_LONG_POLL.as_millis() <= u32::MAX as u128);
};

/// Redaction-safe remote watch failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConfigWatchError {
    /// Mutual TLS or exact certificate identity validation failed.
    #[error("config watch authentication failed")]
    Authentication,
    /// The peer presented a different config consensus identity or endpoint scope.
    #[error("config watch scope mismatch")]
    ScopeMismatch,
    /// The peer does not implement the exact same bounded wire profile.
    #[error("config watch contract mismatch")]
    ContractMismatch,
    /// A frame or response violated the closed wire grammar.
    #[error("config watch protocol violation")]
    Protocol,
    /// An encoded request, snapshot, or page exceeded the fixed byte budget.
    #[error("config watch frame exceeds the contract limit")]
    FrameTooLarge,
    /// A finite transport or operation deadline elapsed.
    #[error("config watch operation timed out")]
    Timeout,
    /// The selected follower or its local applied store is temporarily unavailable.
    #[error("config watch follower is unavailable")]
    Unavailable,
    /// No committed configuration exists on the selected follower.
    #[error("committed config snapshot was not found")]
    NotFound,
    /// The requested cursor predates retained history and requires recovery.
    #[error("committed config history was compacted")]
    HistoryCompacted,
    /// The requested cursor is newer than the selected follower's applied head.
    #[error("committed config cursor is ahead of the follower")]
    HistoryCursorAhead,
    /// A decoded history page contained a duplicate, gap, or reorder.
    #[error("committed config history sequence is invalid")]
    InvalidHistorySequence,
    /// A committed row is not yet safe for publication.
    #[error("committed config publication remains fenced")]
    RecoveryRequired,
    /// Stored or decoded configuration integrity validation failed.
    #[error("committed config integrity validation failed")]
    Integrity,
    /// A non-retryable local invariant failed without exposing backend detail.
    #[error("config watch internal invariant failed")]
    Internal,
    /// The authenticated connection retired during material rotation.
    #[error("config watch connection retired")]
    ConnectionRetired,
}

impl ConfigWatchError {
    fn retryable(self) -> bool {
        matches!(
            self,
            Self::Timeout | Self::Unavailable | Self::ConnectionRetired
        )
    }
}

fn map_store_error(error: StoreError) -> ConfigWatchError {
    match error.code {
        StoreErrorCode::NotFound => ConfigWatchError::NotFound,
        StoreErrorCode::Unavailable | StoreErrorCode::OutcomeUnknown => {
            ConfigWatchError::Unavailable
        }
        StoreErrorCode::Crypto | StoreErrorCode::RestoreSchemaMismatch => {
            ConfigWatchError::Integrity
        }
        StoreErrorCode::RestoreRecoveryRequired => ConfigWatchError::RecoveryRequired,
        StoreErrorCode::HistoryPageTooLarge => ConfigWatchError::FrameTooLarge,
        StoreErrorCode::InvalidHistorySequence => ConfigWatchError::InvalidHistorySequence,
        StoreErrorCode::HistoryCompacted => ConfigWatchError::HistoryCompacted,
        StoreErrorCode::HistoryCursorAhead => ConfigWatchError::HistoryCursorAhead,
        StoreErrorCode::Internal
        | StoreErrorCode::RestoreConfirmedDeadline
        | StoreErrorCode::StartupSyntaxValidationFailed
        | StoreErrorCode::StartupSemanticValidationFailed
        | StoreErrorCode::StartupValidationTaskFailed => ConfigWatchError::Internal,
    }
}

/// Fail-closed construction error for an authenticated server binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigWatchBindingError {
    /// At least one exact client identity is required.
    #[error("config watch client identity set is empty")]
    EmptyClientIdentities,
    /// The configured exact client identity set exceeds its contract bound.
    #[error("config watch client identity set is too large")]
    TooManyClientIdentities,
    /// The same client identity was configured more than once.
    #[error("config watch client identity set contains a duplicate")]
    DuplicateClientIdentity,
}

/// Fail-closed construction error for a committed-config watch server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigWatchServerError {
    /// Only an explicitly trusted, read-only Shadow bus may be served.
    #[error("config watch server requires a shadow config bus")]
    AuthoritativeBus,
}

/// Immutable server-side binding of consensus scope and exact SPIFFE identities.
#[derive(Clone)]
pub struct ConfigWatchServerBinding {
    scope: ConfigConsensusIdentity,
    local_spiffe_id: SpiffeId,
    allowed_clients: Arc<HashSet<SpiffeId>>,
}

impl ConfigWatchServerBinding {
    /// Validates an exact, bounded set of clients allowed to read this scope.
    pub fn try_new(
        scope: ConfigConsensusIdentity,
        local_spiffe_id: SpiffeId,
        allowed_clients: Vec<SpiffeId>,
    ) -> Result<Self, ConfigWatchBindingError> {
        if allowed_clients.is_empty() {
            return Err(ConfigWatchBindingError::EmptyClientIdentities);
        }
        if allowed_clients.len() > CONFIG_WATCH_MAX_CLIENT_IDENTITIES {
            return Err(ConfigWatchBindingError::TooManyClientIdentities);
        }
        let expected_len = allowed_clients.len();
        let allowed_clients = allowed_clients.into_iter().collect::<HashSet<_>>();
        if allowed_clients.len() != expected_len {
            return Err(ConfigWatchBindingError::DuplicateClientIdentity);
        }
        Ok(Self {
            scope,
            local_spiffe_id,
            allowed_clients: Arc::new(allowed_clients),
        })
    }
}

impl fmt::Debug for ConfigWatchServerBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigWatchServerBinding")
            .field("scope", &self.scope)
            .field("local_spiffe_id", &"<redacted>")
            .field("allowed_client_count", &self.allowed_clients.len())
            .finish()
    }
}

/// Immutable client-side binding of consensus scope, schema, and peer identities.
#[derive(Clone)]
pub struct ConfigWatchClientBinding {
    scope: ConfigConsensusIdentity,
    local_spiffe_id: SpiffeId,
    expected_server_spiffe_id: SpiffeId,
    schema_digest: SchemaDigest,
}

impl ConfigWatchClientBinding {
    /// Binds one consumer, product schema, and expected follower to a config scope.
    pub const fn new(
        scope: ConfigConsensusIdentity,
        local_spiffe_id: SpiffeId,
        expected_server_spiffe_id: SpiffeId,
        schema_digest: SchemaDigest,
    ) -> Self {
        Self {
            scope,
            local_spiffe_id,
            expected_server_spiffe_id,
            schema_digest,
        }
    }
}

impl fmt::Debug for ConfigWatchClientBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigWatchClientBinding")
            .field("scope", &self.scope)
            .field("local_spiffe_id", &"<redacted>")
            .field("expected_server_spiffe_id", &"<redacted>")
            .field("schema_digest", &self.schema_digest)
            .finish()
    }
}

/// Async endpoint resolver used before every authenticated connection attempt.
pub type ConfigWatchAddrResolver =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = io::Result<SocketAddr>> + Send>> + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapHello {
    profile: ConfigWatchContractProfile,
    scope: ConfigConsensusIdentity,
    schema_digest: SchemaDigest,
    client_spiffe_id: SpiffeId,
    expected_server_spiffe_id: SpiffeId,
    nonce: uuid::Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum BootstrapRequest {
    Hello(BootstrapHello),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum BootstrapResponse {
    Accepted {
        profile: ConfigWatchContractProfile,
        scope: ConfigConsensusIdentity,
        schema_digest: SchemaDigest,
        server_spiffe_id: SpiffeId,
        accepted_client_spiffe_id: SpiffeId,
        nonce: uuid::Uuid,
    },
    Rejected(ConfigWatchError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum WireRequest {
    Recover {
        known: Option<ConfigVersion>,
    },
    Page {
        after: ConfigRevisionCursor,
        limit: u16,
        wait_millis: u32,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSnapshot<C> {
    tx_id: TxId,
    version: ConfigVersion,
    config: C,
}

impl<C> fmt::Debug for WireSnapshot<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WireSnapshot")
            .field("tx_id", &self.tx_id)
            .field("version", &self.version)
            .field("config", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    bound(
        serialize = "C: Serialize + OpcConfig",
        deserialize = "C: Deserialize<'de> + OpcConfig"
    )
)]
enum WireResponse<C: OpcConfig> {
    Recovery(WireSnapshot<C>),
    Page(ConfigHistoryPage<C>),
    Error(ConfigWatchError),
}

impl<C: OpcConfig> fmt::Debug for WireResponse<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recovery(snapshot) => formatter.debug_tuple("Recovery").field(snapshot).finish(),
            Self::Page(page) => formatter.debug_tuple("Page").field(page).finish(),
            Self::Error(error) => formatter.debug_tuple("Error").field(error).finish(),
        }
    }
}

#[derive(Debug)]
enum FrameError {
    Io,
    Timeout,
    TooLarge,
    Serialization,
    Invalid,
}

impl FrameError {
    fn public(&self) -> ConfigWatchError {
        match self {
            Self::Timeout => ConfigWatchError::Timeout,
            Self::TooLarge => ConfigWatchError::FrameTooLarge,
            Self::Io => ConfigWatchError::Unavailable,
            Self::Serialization | Self::Invalid => ConfigWatchError::Protocol,
        }
    }
}

struct EncodedChunk {
    bytes: Box<[u8]>,
    initialized: usize,
}

struct EncodedFrame {
    chunks: Vec<EncodedChunk>,
    len: usize,
}

struct BoundedFrameWriter {
    frame: EncodedFrame,
    retained: usize,
    max: usize,
    deadline: tokio::time::Instant,
    too_large: bool,
    timed_out: bool,
}

impl BoundedFrameWriter {
    fn new(max: usize, deadline: tokio::time::Instant) -> Self {
        Self {
            frame: EncodedFrame {
                chunks: Vec::new(),
                len: 0,
            },
            retained: 0,
            max,
            deadline,
            too_large: false,
            timed_out: false,
        }
    }

    fn check_deadline(&mut self) -> io::Result<()> {
        if tokio::time::Instant::now() >= self.deadline {
            self.timed_out = true;
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "frame encoding deadline elapsed",
            ))
        } else {
            Ok(())
        }
    }

    fn allocate_chunk(&mut self) -> io::Result<()> {
        let remaining = self.max.saturating_sub(self.retained);
        if remaining == 0 {
            self.too_large = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "encoded frame exceeds limit",
            ));
        }
        let preferred = if self.frame.chunks.is_empty() {
            INITIAL_ENCODED_CHUNK_BYTES
        } else {
            ENCODED_CHUNK_BYTES
        };
        let size = preferred.min(remaining);
        self.frame.chunks.push(EncodedChunk {
            bytes: vec![0_u8; size].into_boxed_slice(),
            initialized: 0,
        });
        self.retained += size;
        Ok(())
    }
}

impl io::Write for BoundedFrameWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.check_deadline()?;
        let Some(attempted) = self.frame.len.checked_add(bytes.len()) else {
            self.too_large = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "encoded frame length overflowed",
            ));
        };
        if attempted > self.max {
            self.too_large = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "encoded frame exceeds limit",
            ));
        }

        let mut remaining = bytes;
        while !remaining.is_empty() {
            self.check_deadline()?;
            let needs_chunk = self
                .frame
                .chunks
                .last()
                .is_none_or(|chunk| chunk.initialized == chunk.bytes.len());
            if needs_chunk {
                self.allocate_chunk()?;
            }
            let Some(chunk) = self.frame.chunks.last_mut() else {
                return Err(io::Error::other("frame chunk allocation failed"));
            };
            let available = chunk.bytes.len() - chunk.initialized;
            let copied = available.min(remaining.len());
            chunk.bytes[chunk.initialized..chunk.initialized + copied]
                .copy_from_slice(&remaining[..copied]);
            chunk.initialized += copied;
            remaining = &remaining[copied..];
        }
        self.frame.len = attempted;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_frame<T: Serialize>(
    value: &T,
    max: usize,
    deadline: tokio::time::Instant,
) -> Result<EncodedFrame, FrameError> {
    let mut writer = BoundedFrameWriter::new(max, deadline);
    if serde_json::to_writer(&mut writer, value).is_err() {
        if writer.too_large {
            return Err(FrameError::TooLarge);
        }
        if writer.timed_out {
            return Err(FrameError::Timeout);
        }
        return Err(FrameError::Serialization);
    }
    writer.check_deadline().map_err(|_| FrameError::Timeout)?;
    Ok(writer.frame)
}

async fn write_frame_until<W, T>(
    writer: &mut W,
    value: &T,
    max: usize,
    deadline: tokio::time::Instant,
) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let frame = encode_frame(value, max, deadline)?;
    let len = u32::try_from(frame.len).map_err(|_| FrameError::TooLarge)?;
    let write = async {
        writer
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|_| FrameError::Io)?;
        for chunk in &frame.chunks {
            writer
                .write_all(&chunk.bytes[..chunk.initialized])
                .await
                .map_err(|_| FrameError::Io)?;
        }
        writer.flush().await.map_err(|_| FrameError::Io)
    };
    tokio::time::timeout_at(deadline, write)
        .await
        .map_err(|_| FrameError::Timeout)?
}

async fn read_frame_until<R, T>(
    reader: &mut R,
    max: usize,
    deadline: tokio::time::Instant,
) -> Result<T, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let read = async {
        let mut prefix = [0_u8; 4];
        reader
            .read_exact(&mut prefix)
            .await
            .map_err(|_| FrameError::Io)?;
        let len = u32::from_be_bytes(prefix) as usize;
        if len == 0 {
            return Err(FrameError::Invalid);
        }
        if len > max {
            return Err(FrameError::TooLarge);
        }
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(len)
            .map_err(|_| FrameError::TooLarge)?;
        payload.resize(len, 0);
        reader
            .read_exact(&mut payload)
            .await
            .map_err(|_| FrameError::Io)?;
        serde_json::from_slice(&payload).map_err(|_| FrameError::Serialization)
    };
    tokio::time::timeout_at(deadline, read)
        .await
        .map_err(|_| FrameError::Timeout)?
}

fn deadline_after(duration: Duration) -> Result<tokio::time::Instant, ConfigWatchError> {
    tokio::time::Instant::now()
        .checked_add(duration)
        .ok_or(ConfigWatchError::Internal)
}

fn material_is_current(
    config: &AuthenticatedServerConfig,
    admission: TlsAdmittedConnection,
) -> bool {
    let status = config.material_status();
    matches!(
        status.availability(),
        TlsMaterialAvailability::Ready | TlsMaterialAvailability::RetainingLastGood
    ) && status.epoch() == admission.epoch()
}

fn client_material_is_current(
    config: &AuthenticatedClientConfig,
    admission: TlsAdmittedConnection,
) -> bool {
    let status = config.material_status();
    matches!(
        status.availability(),
        TlsMaterialAvailability::Ready | TlsMaterialAvailability::RetainingLastGood
    ) && status.epoch() == admission.epoch()
}

fn map_tls_material_error(error: TlsMaterialError) -> ConfigWatchError {
    match error {
        TlsMaterialError::Unavailable => ConfigWatchError::Unavailable,
        TlsMaterialError::EpochChanged | TlsMaterialError::EpochRetryLimit => {
            ConfigWatchError::ConnectionRetired
        }
        TlsMaterialError::Configuration => ConfigWatchError::Authentication,
    }
}

fn classify_tls_connect_error(error: &io::Error) -> ConfigWatchError {
    use tokio_rustls::rustls::AlertDescription;
    use tokio_rustls::rustls::Error as RustlsError;

    let Some(error) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<RustlsError>())
    else {
        return ConfigWatchError::Unavailable;
    };
    match error {
        RustlsError::InvalidCertificate(_)
        | RustlsError::InvalidCertRevocationList(_)
        | RustlsError::NoCertificatesPresented
        | RustlsError::UnsupportedNameType => ConfigWatchError::Authentication,
        RustlsError::AlertReceived(
            AlertDescription::NoCertificate
            | AlertDescription::BadCertificate
            | AlertDescription::UnsupportedCertificate
            | AlertDescription::CertificateRevoked
            | AlertDescription::CertificateExpired
            | AlertDescription::CertificateUnknown
            | AlertDescription::UnknownCA
            | AlertDescription::CertificateUnobtainable
            | AlertDescription::BadCertificateStatusResponse
            | AlertDescription::BadCertificateHashValue
            | AlertDescription::CertificateRequired,
        ) => ConfigWatchError::Authentication,
        _ => ConfigWatchError::Protocol,
    }
}

fn validate_bootstrap_response(
    response: BootstrapResponse,
    binding: &ConfigWatchClientBinding,
    nonce: uuid::Uuid,
) -> Result<(), ConfigWatchError> {
    match response {
        BootstrapResponse::Rejected(error) => Err(error),
        BootstrapResponse::Accepted {
            profile,
            scope,
            schema_digest,
            server_spiffe_id,
            accepted_client_spiffe_id,
            nonce: echoed_nonce,
        } => {
            if !profile.is_current() || schema_digest != binding.schema_digest {
                return Err(ConfigWatchError::ContractMismatch);
            }
            if scope != binding.scope {
                return Err(ConfigWatchError::ScopeMismatch);
            }
            if server_spiffe_id != binding.expected_server_spiffe_id
                || accepted_client_spiffe_id != binding.local_spiffe_id
            {
                return Err(ConfigWatchError::Authentication);
            }
            if echoed_nonce != nonce {
                return Err(ConfigWatchError::Protocol);
            }
            Ok(())
        }
    }
}

fn validate_response_schema<C: OpcConfig>(
    response: &WireResponse<C>,
    expected: SchemaDigest,
) -> Result<(), ConfigWatchError> {
    let matches = match response {
        WireResponse::Recovery(snapshot) => snapshot.config.schema_digest() == expected,
        WireResponse::Page(page) => page
            .entries()
            .iter()
            .all(|entry| entry.config.schema_digest() == expected),
        WireResponse::Error(_) => true,
    };
    if matches {
        Ok(())
    } else {
        Err(ConfigWatchError::ContractMismatch)
    }
}

/// Read-only authenticated server over one follower's local applied config view.
pub struct ConfigWatchServer<C: OpcConfig> {
    bus: Arc<ConfigBus<C>>,
    tls_config: AuthenticatedServerConfig,
    binding: ConfigWatchServerBinding,
    schema_digest: SchemaDigest,
}

impl<C: OpcConfig> fmt::Debug for ConfigWatchServer<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigWatchServer")
            .field("binding", &self.binding)
            .field("schema_digest", &self.schema_digest)
            .field("tls_config", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl<C> ConfigWatchServer<C>
where
    C: OpcConfig + Serialize + DeserializeOwned,
{
    /// Creates a server that exposes only recovery and committed-history reads.
    ///
    /// The supplied bus must be a `Shadow` bus restored over the local
    /// Openraft follower's [`opc_config_bus::CommittedRevisionSource`]. This
    /// transport never accepts a mutation and never implements a consensus
    /// peer or voter port.
    pub fn new(
        bus: Arc<ConfigBus<C>>,
        tls_config: AuthenticatedServerConfig,
        binding: ConfigWatchServerBinding,
    ) -> Result<Self, ConfigWatchServerError> {
        if bus.authority_mode() != AuthorityMode::Shadow {
            return Err(ConfigWatchServerError::AuthoritativeBus);
        }
        let schema_digest = bus.current_snapshot().config.schema_digest();
        Ok(Self {
            bus,
            tls_config,
            binding,
            schema_digest,
        })
    }

    /// Binds and starts a bounded authenticated listener.
    pub async fn listen(
        self,
        address: SocketAddr,
    ) -> io::Result<(ConfigWatchServerHandle, SocketAddr)> {
        let listener = TcpListener::bind(address).await?;
        let local_address = listener.local_addr()?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(run_server(
            listener,
            self.bus,
            self.tls_config,
            self.binding,
            self.schema_digest,
            shutdown_rx,
        ));
        Ok((
            ConfigWatchServerHandle {
                shutdown_tx,
                task: Some(task),
            },
            local_address,
        ))
    }
}

/// Lifecycle handle for a running [`ConfigWatchServer`].
pub struct ConfigWatchServerHandle {
    shutdown_tx: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl fmt::Debug for ConfigWatchServerHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigWatchServerHandle")
            .finish_non_exhaustive()
    }
}

impl ConfigWatchServerHandle {
    /// Stops accepting connections, cancels active long polls, and waits for exit.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(mut task) = self.task.take() {
            if tokio::time::timeout(IO_TIMEOUT, &mut task).await.is_err() {
                task.abort();
                let _ = task.await;
            }
        }
    }
}

impl Drop for ConfigWatchServerHandle {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn run_server<C>(
    listener: TcpListener,
    bus: Arc<ConfigBus<C>>,
    tls_config: AuthenticatedServerConfig,
    binding: ConfigWatchServerBinding,
    schema_digest: SchemaDigest,
    mut shutdown: watch::Receiver<bool>,
) where
    C: OpcConfig + Serialize + DeserializeOwned,
{
    let slots = Arc::new(Semaphore::new(CONFIG_WATCH_MAX_CONCURRENT_CONNECTIONS));
    let mut tasks = tokio::task::JoinSet::new();

    loop {
        while tasks.try_join_next().is_some() {}
        let permit = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            permit = Arc::clone(&slots).acquire_owned() => {
                match permit {
                    Ok(permit) => permit,
                    Err(_) => break,
                }
            }
        };
        let accepted = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, _peer_address)) = accepted else {
            break;
        };
        let bus = Arc::clone(&bus);
        let tls_config = tls_config.clone();
        let binding = binding.clone();
        tasks.spawn(async move {
            let _permit: OwnedSemaphorePermit = permit;
            let _ = handle_connection(stream, bus, tls_config, binding, schema_digest).await;
        });
    }

    tasks.shutdown().await;
}

async fn write_bootstrap_rejection(
    stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    error: ConfigWatchError,
) {
    let Ok(deadline) = deadline_after(IO_TIMEOUT) else {
        return;
    };
    let _ = write_frame_until(
        stream,
        &BootstrapResponse::Rejected(error),
        HANDSHAKE_FRAME_BYTES,
        deadline,
    )
    .await;
}

async fn handle_connection<C>(
    tcp: TcpStream,
    bus: Arc<ConfigBus<C>>,
    tls_config: AuthenticatedServerConfig,
    binding: ConfigWatchServerBinding,
    schema_digest: SchemaDigest,
) -> Result<(), ConfigWatchError>
where
    C: OpcConfig + Serialize + DeserializeOwned,
{
    let handshake = tls_config
        .begin_handshake()
        .map_err(map_tls_material_error)?;
    let mut rustls_config = handshake.rustls_config().as_ref().clone();
    rustls_config.alpn_protocols = vec![CONFIG_WATCH_ALPN.to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(rustls_config));
    let mut stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp))
        .await
        .map_err(|_| ConfigWatchError::Timeout)?
        .map_err(|_| ConfigWatchError::Authentication)?;
    if stream.get_ref().1.alpn_protocol() != Some(CONFIG_WATCH_ALPN) {
        return Err(ConfigWatchError::ContractMismatch);
    }
    let peer = peer_tls_identity_from_server_connection(stream.get_ref().1)
        .map_err(|_| ConfigWatchError::Authentication)?;

    let hello_deadline = deadline_after(HANDSHAKE_TIMEOUT)?;
    let hello: BootstrapRequest =
        read_frame_until(&mut stream, HANDSHAKE_FRAME_BYTES, hello_deadline)
            .await
            .map_err(|error| error.public())?;
    let BootstrapRequest::Hello(hello) = hello;

    let authenticated_client = peer.spiffe_id();
    if authenticated_client != &hello.client_spiffe_id
        || !binding.allowed_clients.contains(authenticated_client)
    {
        write_bootstrap_rejection(&mut stream, ConfigWatchError::Authentication).await;
        return Err(ConfigWatchError::Authentication);
    }
    if !hello.profile.is_current() || hello.schema_digest != schema_digest {
        write_bootstrap_rejection(&mut stream, ConfigWatchError::ContractMismatch).await;
        return Err(ConfigWatchError::ContractMismatch);
    }
    if hello.scope != binding.scope || hello.expected_server_spiffe_id != binding.local_spiffe_id {
        write_bootstrap_rejection(&mut stream, ConfigWatchError::ScopeMismatch).await;
        return Err(ConfigWatchError::ScopeMismatch);
    }

    let admission = handshake.admit().map_err(map_tls_material_error)?;
    if !material_is_current(&tls_config, admission) {
        return Err(ConfigWatchError::ConnectionRetired);
    }
    let accepted = BootstrapResponse::Accepted {
        profile: CURRENT_CONFIG_WATCH_CONTRACT_PROFILE,
        scope: binding.scope,
        schema_digest,
        server_spiffe_id: binding.local_spiffe_id.clone(),
        accepted_client_spiffe_id: hello.client_spiffe_id,
        nonce: hello.nonce,
    };
    let ack_deadline = deadline_after(IO_TIMEOUT)?;
    write_frame_until(&mut stream, &accepted, HANDSHAKE_FRAME_BYTES, ack_deadline)
        .await
        .map_err(|error| error.public())?;
    if !material_is_current(&tls_config, admission) {
        return Err(ConfigWatchError::ConnectionRetired);
    }

    let request_deadline = deadline_after(IO_TIMEOUT)?;
    let request: WireRequest = read_frame_until(
        &mut stream,
        CONFIG_WATCH_MAX_REQUEST_FRAME_BYTES,
        request_deadline,
    )
    .await
    .map_err(|error| error.public())?;
    if !material_is_current(&tls_config, admission) {
        return Err(ConfigWatchError::ConnectionRetired);
    }

    let operation_timeout = request_operation_timeout(request)?;
    let operation = dispatch_request(Arc::clone(&bus), request);
    tokio::pin!(operation);
    let mut peer_input = [0_u8; 1];
    let response = tokio::select! {
        result = tokio::time::timeout(operation_timeout, &mut operation) => {
            result.map_err(|_| ConfigWatchError::Timeout)?
        }
        read = stream.read(&mut peer_input) => {
            return match read {
                Ok(0) => Err(ConfigWatchError::Unavailable),
                Ok(_) => Err(ConfigWatchError::Protocol),
                Err(_) => Err(ConfigWatchError::Unavailable),
            };
        }
    };
    if !material_is_current(&tls_config, admission) {
        return Err(ConfigWatchError::ConnectionRetired);
    }

    let response_deadline = deadline_after(IO_TIMEOUT)?;
    match write_frame_until(
        &mut stream,
        &response,
        CONFIG_WATCH_MAX_RESPONSE_FRAME_BYTES,
        response_deadline,
    )
    .await
    {
        Ok(()) => Ok(()),
        Err(FrameError::TooLarge) => {
            let fallback_deadline = deadline_after(IO_TIMEOUT)?;
            write_frame_until(
                &mut stream,
                &WireResponse::<C>::Error(ConfigWatchError::FrameTooLarge),
                CONFIG_WATCH_MAX_RESPONSE_FRAME_BYTES,
                fallback_deadline,
            )
            .await
            .map_err(|error| error.public())
        }
        Err(FrameError::Serialization) => {
            let fallback_deadline = deadline_after(IO_TIMEOUT)?;
            write_frame_until(
                &mut stream,
                &WireResponse::<C>::Error(ConfigWatchError::Internal),
                CONFIG_WATCH_MAX_RESPONSE_FRAME_BYTES,
                fallback_deadline,
            )
            .await
            .map_err(|error| error.public())
        }
        Err(error) => Err(error.public()),
    }
}

fn request_operation_timeout(request: WireRequest) -> Result<Duration, ConfigWatchError> {
    let wait = match request {
        WireRequest::Recover { .. } => Duration::ZERO,
        WireRequest::Page { wait_millis, .. } => Duration::from_millis(u64::from(wait_millis)),
    };
    if wait > CONFIG_WATCH_MAX_LONG_POLL {
        return Err(ConfigWatchError::Protocol);
    }
    BACKEND_TIMEOUT
        .checked_add(wait)
        .ok_or(ConfigWatchError::Internal)
}

async fn dispatch_request<C>(bus: Arc<ConfigBus<C>>, request: WireRequest) -> WireResponse<C>
where
    C: OpcConfig + Serialize + DeserializeOwned,
{
    match request {
        WireRequest::Recover { known } => match bus.recover_from(known).await {
            Ok(recovery) => {
                let (snapshot, stream) = recovery.into_parts();
                drop(stream);
                let Some(tx_id) = snapshot.tx_id else {
                    return WireResponse::Error(ConfigWatchError::Internal);
                };
                WireResponse::Recovery(WireSnapshot {
                    tx_id,
                    version: snapshot.version,
                    config: snapshot.config.as_ref().clone(),
                })
            }
            Err(error) => WireResponse::Error(map_store_error(error)),
        },
        WireRequest::Page {
            after,
            limit,
            wait_millis,
        } => {
            let limit = usize::from(limit);
            let wait = Duration::from_millis(u64::from(wait_millis));
            if limit == 0
                || limit > MAX_CONFIG_HISTORY_PAGE_ENTRIES
                || wait > CONFIG_WATCH_MAX_LONG_POLL
            {
                return WireResponse::Error(ConfigWatchError::Protocol);
            }
            match long_poll_page(bus.as_ref(), after, limit, wait).await {
                Ok(page) => WireResponse::Page(page),
                Err(error) => WireResponse::Error(map_store_error(error)),
            }
        }
    }
}

async fn long_poll_page<C: OpcConfig>(
    bus: &ConfigBus<C>,
    cursor: ConfigRevisionCursor,
    limit: usize,
    wait: Duration,
) -> Result<ConfigHistoryPage<C>, StoreError> {
    let immediate = bus.load_committed_page(cursor, limit).await?;
    if cursor.version().next().is_none() {
        // A terminal cursor has no successor to wait for. Recovery performs
        // the durable head/future-cursor check and produces an already-empty
        // local tail at `ConfigVersion::MAX`; no change wait is opened.
        let recovery = bus.recover_from(Some(cursor.version())).await?;
        drop(recovery);
        return Ok(immediate);
    }
    if !immediate.is_empty() || wait.is_zero() {
        if immediate.is_empty() {
            // `load_committed_page` alone cannot distinguish a future cursor.
            // Opening the applied-only watch performs that head check without
            // contacting the writer or a read-index path.
            let watch = bus.watch_committed(cursor.version()).await?;
            drop(watch);
        }
        return Ok(immediate);
    }

    let mut watch = bus.watch_committed(cursor.version()).await?;
    match tokio::time::timeout(wait, watch.next()).await {
        Err(_) => Ok(immediate),
        Ok(Some(Ok(_entry))) => bus.load_committed_page(cursor, limit).await,
        Ok(Some(Err(error))) => Err(error),
        Ok(None) => Err(StoreError::internal(
            "committed config watch ended before its applied source",
        )),
    }
}

/// Creates a resolver that always returns one already-resolved endpoint.
pub fn fixed_config_watch_endpoint(address: SocketAddr) -> ConfigWatchAddrResolver {
    Arc::new(move || Box::pin(async move { Ok(address) }))
}

/// Remote, read-only client for one follower-served committed-config feed.
pub struct RemoteConfigWatch<C: OpcConfig> {
    binding: ConfigWatchClientBinding,
    resolver: ConfigWatchAddrResolver,
    tls_config: AuthenticatedClientConfig,
    marker: PhantomData<fn() -> C>,
}

impl<C: OpcConfig> Clone for RemoteConfigWatch<C> {
    fn clone(&self) -> Self {
        Self {
            binding: self.binding.clone(),
            resolver: Arc::clone(&self.resolver),
            tls_config: self.tls_config.clone(),
            marker: PhantomData,
        }
    }
}

impl<C: OpcConfig> fmt::Debug for RemoteConfigWatch<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteConfigWatch")
            .field("binding", &self.binding)
            .field("resolver", &"<redacted>")
            .field("tls_config", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Gap-free remote stream of locally applied committed config revisions.
pub type RemoteConfigRevisionStream<C> =
    BoxStream<'static, Result<CommittedConfigHistoryEntry<C>, ConfigWatchError>>;

/// Remote atomic recovery result: install its snapshot, then consume its tail.
pub struct RemoteConfigRecovery<C: OpcConfig> {
    snapshot: PublishedSnapshot<C>,
    stream: RemoteConfigRevisionStream<C>,
}

impl<C: OpcConfig> fmt::Debug for RemoteConfigRecovery<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteConfigRecovery")
            .field("tx_id", &self.snapshot.tx_id)
            .field("version", &self.snapshot.version)
            .field("config", &"<redacted>")
            .field("stream", &"<remote-config-revision-stream>")
            .finish()
    }
}

impl<C: OpcConfig> RemoteConfigRecovery<C> {
    /// Complete follower-applied snapshot to install before polling the tail.
    pub const fn snapshot(&self) -> &PublishedSnapshot<C> {
        &self.snapshot
    }

    /// Consumes the recovery value into its snapshot and exactly positioned tail.
    pub fn into_parts(self) -> (PublishedSnapshot<C>, RemoteConfigRevisionStream<C>) {
        (self.snapshot, self.stream)
    }
}

struct RemoteWatchState<C: OpcConfig> {
    remote: RemoteConfigWatch<C>,
    cursor: ConfigRevisionCursor,
    backlog: VecDeque<CommittedConfigHistoryEntry<C>>,
    page_limit: usize,
    reconnect_backoff: Duration,
    terminal: bool,
}

impl<C> RemoteConfigWatch<C>
where
    C: OpcConfig + Serialize + DeserializeOwned,
{
    /// Creates a client that re-resolves and re-authenticates every bounded page.
    pub fn new(
        binding: ConfigWatchClientBinding,
        resolver: ConfigWatchAddrResolver,
        tls_config: AuthenticatedClientConfig,
    ) -> Self {
        Self {
            binding,
            resolver,
            tls_config,
            marker: PhantomData,
        }
    }

    /// Recovers a complete follower-applied snapshot and a tail after it.
    ///
    /// `known` is a monotonic floor. A lagging follower returns
    /// [`ConfigWatchError::HistoryCursorAhead`] rather than moving the caller
    /// backward. The response contains no in-memory subscription token: the
    /// tail repages durable local applied history from the snapshot version,
    /// closing the snapshot/subscribe race without contacting the leader.
    pub async fn recover_from(
        &self,
        known: Option<ConfigVersion>,
    ) -> Result<RemoteConfigRecovery<C>, ConfigWatchError> {
        let response = self
            .execute_with_bounded_retries(WireRequest::Recover { known })
            .await?;
        let WireResponse::Recovery(snapshot) = response else {
            return match response {
                WireResponse::Error(error) => Err(error),
                WireResponse::Page(_) => Err(ConfigWatchError::Protocol),
                WireResponse::Recovery(_) => Err(ConfigWatchError::Internal),
            };
        };
        if known.is_some_and(|known| known > snapshot.version) {
            return Err(ConfigWatchError::Protocol);
        }
        let version = snapshot.version;
        let published = PublishedSnapshot {
            tx_id: Some(snapshot.tx_id),
            version,
            config: Arc::new(snapshot.config),
        };
        Ok(RemoteConfigRecovery {
            snapshot: published,
            stream: self.stream_from(version, VecDeque::new()),
        })
    }

    /// Opens a remote committed-history stream strictly after `from`.
    ///
    /// An initial non-waiting page validates that `from` is not ahead of this
    /// follower and has not been compacted. Subsequent connections long-poll
    /// for at most [`CONFIG_WATCH_MAX_LONG_POLL`] and reconnect with bounded
    /// backoff. The cursor advances one item at a time, only when that complete
    /// validated item becomes caller-visible.
    pub async fn watch_committed(
        &self,
        from: ConfigVersion,
    ) -> Result<RemoteConfigRevisionStream<C>, ConfigWatchError> {
        let cursor = ConfigRevisionCursor::after(from);
        let page = self
            .load_page_with_bounded_retries(cursor, MAX_CONFIG_HISTORY_PAGE_ENTRIES, Duration::ZERO)
            .await?;
        Ok(self.stream_from(from, page.into_entries().into()))
    }

    /// Loads one exact, bounded page from the selected follower.
    pub async fn load_committed_page(
        &self,
        cursor: ConfigRevisionCursor,
        limit: usize,
        wait: Duration,
    ) -> Result<ConfigHistoryPage<C>, ConfigWatchError> {
        self.load_page_with_bounded_retries(cursor, limit, wait)
            .await
    }

    fn stream_from(
        &self,
        from: ConfigVersion,
        backlog: VecDeque<CommittedConfigHistoryEntry<C>>,
    ) -> RemoteConfigRevisionStream<C> {
        let state = RemoteWatchState {
            remote: self.clone(),
            cursor: ConfigRevisionCursor::after(from),
            backlog,
            page_limit: MAX_CONFIG_HISTORY_PAGE_ENTRIES,
            reconnect_backoff: RECONNECT_BACKOFF_MIN,
            terminal: false,
        };
        stream::unfold(state, |mut state| async move {
            loop {
                if state.terminal {
                    return None;
                }
                if let Some(entry) = state.backlog.pop_front() {
                    let expected = state.cursor.version().next();
                    if expected != Some(entry.version) {
                        state.terminal = true;
                        return Some((Err(ConfigWatchError::InvalidHistorySequence), state));
                    }
                    state.cursor = ConfigRevisionCursor::after(entry.version);
                    return Some((Ok(entry), state));
                }
                state.cursor.version().next()?;

                match state
                    .remote
                    .load_page_adaptive(state.cursor, state.page_limit, CONFIG_WATCH_MAX_LONG_POLL)
                    .await
                {
                    Ok((page, page_limit)) => {
                        state.page_limit = page_limit;
                        state.reconnect_backoff = RECONNECT_BACKOFF_MIN;
                        state.backlog = page.into_entries().into();
                        if state.backlog.is_empty() {
                            tokio::time::sleep(RECONNECT_BACKOFF_MIN).await;
                        }
                    }
                    Err(error)
                        if error.retryable() || error == ConfigWatchError::HistoryCursorAhead =>
                    {
                        tokio::time::sleep(state.reconnect_backoff).await;
                        state.reconnect_backoff = state
                            .reconnect_backoff
                            .saturating_mul(2)
                            .min(RECONNECT_BACKOFF_MAX);
                    }
                    Err(error) => {
                        state.terminal = true;
                        return Some((Err(error), state));
                    }
                }
            }
        })
        .boxed()
    }

    async fn load_page_adaptive(
        &self,
        cursor: ConfigRevisionCursor,
        initial_limit: usize,
        wait: Duration,
    ) -> Result<(ConfigHistoryPage<C>, usize), ConfigWatchError> {
        let mut limit = initial_limit.clamp(1, MAX_CONFIG_HISTORY_PAGE_ENTRIES);
        loop {
            match self.load_page_once(cursor, limit, wait).await {
                Err(ConfigWatchError::FrameTooLarge) if limit > 1 => {
                    limit = (limit / 2).max(1);
                }
                result => return result.map(|page| (page, limit)),
            }
        }
    }

    async fn load_page_with_bounded_retries(
        &self,
        cursor: ConfigRevisionCursor,
        limit: usize,
        wait: Duration,
    ) -> Result<ConfigHistoryPage<C>, ConfigWatchError> {
        if limit == 0 || limit > MAX_CONFIG_HISTORY_PAGE_ENTRIES {
            return Err(ConfigWatchError::Protocol);
        }
        if wait > CONFIG_WATCH_MAX_LONG_POLL {
            return Err(ConfigWatchError::Protocol);
        }
        let mut backoff = RECONNECT_BACKOFF_MIN;
        for attempt in 0..3 {
            match self.load_page_adaptive(cursor, limit, wait).await {
                Ok((page, _effective_limit)) => return Ok(page),
                Err(error) if error.retryable() && attempt < 2 => {
                    tokio::time::sleep(backoff).await;
                    backoff = backoff.saturating_mul(2).min(RECONNECT_BACKOFF_MAX);
                }
                Err(error) => return Err(error),
            }
        }
        Err(ConfigWatchError::Unavailable)
    }

    async fn load_page_once(
        &self,
        cursor: ConfigRevisionCursor,
        limit: usize,
        wait: Duration,
    ) -> Result<ConfigHistoryPage<C>, ConfigWatchError> {
        if limit == 0
            || limit > MAX_CONFIG_HISTORY_PAGE_ENTRIES
            || wait > CONFIG_WATCH_MAX_LONG_POLL
        {
            return Err(ConfigWatchError::Protocol);
        }
        let limit = u16::try_from(limit).map_err(|_| ConfigWatchError::Protocol)?;
        let wait_millis =
            u32::try_from(wait.as_millis()).map_err(|_| ConfigWatchError::Protocol)?;
        let response = self
            .execute(WireRequest::Page {
                after: cursor,
                limit,
                wait_millis,
            })
            .await?;
        match response {
            WireResponse::Page(page) => {
                if page.requested_from() != cursor || page.len() > usize::from(limit) {
                    return Err(ConfigWatchError::InvalidHistorySequence);
                }
                Ok(page)
            }
            WireResponse::Error(error) => Err(error),
            WireResponse::Recovery(_) => Err(ConfigWatchError::Protocol),
        }
    }

    async fn execute_with_bounded_retries(
        &self,
        request: WireRequest,
    ) -> Result<WireResponse<C>, ConfigWatchError> {
        let mut backoff = RECONNECT_BACKOFF_MIN;
        for attempt in 0..3 {
            match self.execute(request).await {
                Ok(WireResponse::Error(error)) if error.retryable() && attempt < 2 => {
                    tokio::time::sleep(backoff).await;
                    backoff = backoff.saturating_mul(2).min(RECONNECT_BACKOFF_MAX);
                }
                Ok(response) => return Ok(response),
                Err(error) if error.retryable() && attempt < 2 => {
                    tokio::time::sleep(backoff).await;
                    backoff = backoff.saturating_mul(2).min(RECONNECT_BACKOFF_MAX);
                }
                Err(error) => return Err(error),
            }
        }
        Err(ConfigWatchError::Unavailable)
    }

    async fn execute(&self, request: WireRequest) -> Result<WireResponse<C>, ConfigWatchError> {
        let (mut stream, admission) = self.connect_authenticated().await?;
        if !client_material_is_current(&self.tls_config, admission) {
            return Err(ConfigWatchError::ConnectionRetired);
        }
        let operation_timeout = request_operation_timeout(request)?;
        let total_timeout = operation_timeout
            .checked_add(IO_TIMEOUT)
            .ok_or(ConfigWatchError::Internal)?;
        let operation_deadline = deadline_after(total_timeout)?;
        write_frame_until(
            &mut stream,
            &request,
            CONFIG_WATCH_MAX_REQUEST_FRAME_BYTES,
            operation_deadline,
        )
        .await
        .map_err(|error| error.public())?;
        let response = read_frame_until(
            &mut stream,
            CONFIG_WATCH_MAX_RESPONSE_FRAME_BYTES,
            operation_deadline,
        )
        .await
        .map_err(|error| error.public())?;
        validate_response_schema(&response, self.binding.schema_digest)?;
        if !client_material_is_current(&self.tls_config, admission) {
            return Err(ConfigWatchError::ConnectionRetired);
        }
        Ok(response)
    }

    async fn connect_authenticated(
        &self,
    ) -> Result<
        (
            tokio_rustls::client::TlsStream<TcpStream>,
            TlsAdmittedConnection,
        ),
        ConfigWatchError,
    > {
        let deadline = deadline_after(HANDSHAKE_TIMEOUT)?;
        let binding = self.binding.clone();
        let resolver = Arc::clone(&self.resolver);
        let handshake = self.tls_config.run_handshake(move |attempt| {
            let binding = binding.clone();
            let resolver = Arc::clone(&resolver);
            async move { connect_client_attempt(attempt, binding, resolver, deadline).await }
        });
        let outcome = tokio::time::timeout_at(deadline, handshake)
            .await
            .map_err(|_| ConfigWatchError::Timeout)?
            .map_err(|error| match error {
                TlsHandshakeRunError::Material(error) => map_tls_material_error(error),
                TlsHandshakeRunError::Operation(error) => error,
            })?;
        Ok(outcome.into_parts())
    }
}

async fn connect_client_attempt(
    handshake: TlsClientHandshake,
    binding: ConfigWatchClientBinding,
    resolver: ConfigWatchAddrResolver,
    deadline: tokio::time::Instant,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ConfigWatchError> {
    let address = tokio::time::timeout_at(deadline, resolver())
        .await
        .map_err(|_| ConfigWatchError::Timeout)?
        .map_err(|_| ConfigWatchError::Unavailable)?;
    let tcp = tokio::time::timeout_at(deadline, TcpStream::connect(address))
        .await
        .map_err(|_| ConfigWatchError::Timeout)?
        .map_err(|_| ConfigWatchError::Unavailable)?;
    let _ = tcp.set_nodelay(true);
    let mut rustls_config = handshake.rustls_config().as_ref().clone();
    rustls_config.alpn_protocols = vec![CONFIG_WATCH_ALPN.to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(rustls_config));
    let server_name = ServerName::IpAddress(address.ip().into());
    let mut stream = tokio::time::timeout_at(deadline, connector.connect(server_name, tcp))
        .await
        .map_err(|_| ConfigWatchError::Timeout)?
        .map_err(|error| classify_tls_connect_error(&error))?;
    if stream.get_ref().1.alpn_protocol() != Some(CONFIG_WATCH_ALPN) {
        return Err(ConfigWatchError::ContractMismatch);
    }
    let peer = peer_tls_identity_from_client_connection(stream.get_ref().1)
        .map_err(|_| ConfigWatchError::Authentication)?;
    if peer.spiffe_id() != &binding.expected_server_spiffe_id {
        return Err(ConfigWatchError::Authentication);
    }

    let nonce = uuid::Uuid::new_v4();
    let hello = BootstrapRequest::Hello(BootstrapHello {
        profile: CURRENT_CONFIG_WATCH_CONTRACT_PROFILE,
        scope: binding.scope,
        schema_digest: binding.schema_digest,
        client_spiffe_id: binding.local_spiffe_id.clone(),
        expected_server_spiffe_id: binding.expected_server_spiffe_id.clone(),
        nonce,
    });
    write_frame_until(&mut stream, &hello, HANDSHAKE_FRAME_BYTES, deadline)
        .await
        .map_err(|error| error.public())?;
    let response: BootstrapResponse =
        read_frame_until(&mut stream, HANDSHAKE_FRAME_BYTES, deadline)
            .await
            .map_err(|error| error.public())?;
    validate_bootstrap_response(response, &binding, nonce)?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use futures_util::StreamExt;
    use opc_config_bus::{
        CommitWrite, CommittedRevisionSource, ManagedDatastore, MockManagedDatastore, StoredConfig,
    };
    use opc_config_model::{
        ConfigError, IdempotencyKey, RequestId, RequestSource, RollbackTarget, TrustedPrincipal,
        ValidationContext, ValidationError, WorkloadIdentity, YangPath,
    };
    use opc_identity::{
        build_identity_state, parse_certs_pem, parse_key_pem, IdentityState, TrustBundle,
        TrustBundleSet, TrustDomain,
    };
    use opc_persist::{
        ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch, ConfigConsensusConfigurationId,
    };
    use opc_tls::TlsConfigBuilder;
    use opc_types::{SchemaDigest, TenantId, Timestamp};
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, SanType};
    use tokio::sync::Notify;

    use super::*;

    const TEST_SCHEMA_DIGEST: SchemaDigest = SchemaDigest::from_bytes([0x56; 32]);
    const ALTERNATE_SCHEMA_DIGEST: SchemaDigest = SchemaDigest::from_bytes([0xa7; 32]);

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct TestConfig {
        value: String,
    }

    impl TestConfig {
        fn new(value: impl Into<String>) -> Self {
            Self {
                value: value.into(),
            }
        }
    }

    impl OpcConfig for TestConfig {
        type Delta = String;

        fn schema_digest(&self) -> SchemaDigest {
            TEST_SCHEMA_DIGEST
        }

        fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
            if self == previous {
                Ok(Vec::new())
            } else {
                Ok(vec![self.value.clone()])
            }
        }

        fn changed_paths(
            &self,
            _previous: &Self,
            deltas: &[Self::Delta],
        ) -> Result<Vec<YangPath>, ConfigError> {
            if deltas.is_empty() {
                Ok(Vec::new())
            } else {
                YangPath::new("/system/value")
                    .map(|path| vec![path])
                    .map_err(|error| ConfigError::new("path", error.message()))
            }
        }

        fn apply_delta(&mut self, delta: Self::Delta) -> Result<(), ConfigError> {
            self.value = delta;
            Ok(())
        }

        fn validate_syntax(&self) -> Result<(), ValidationError> {
            Ok(())
        }

        fn validate_semantics(
            &self,
            _context: &ValidationContext<Self>,
        ) -> Result<(), ValidationError> {
            Ok(())
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct AlternateConfig {
        value: String,
    }

    impl OpcConfig for AlternateConfig {
        type Delta = String;

        fn schema_digest(&self) -> SchemaDigest {
            ALTERNATE_SCHEMA_DIGEST
        }

        fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
            if self == previous {
                Ok(Vec::new())
            } else {
                Ok(vec![self.value.clone()])
            }
        }

        fn changed_paths(
            &self,
            _previous: &Self,
            deltas: &[Self::Delta],
        ) -> Result<Vec<YangPath>, ConfigError> {
            if deltas.is_empty() {
                Ok(Vec::new())
            } else {
                YangPath::new("/system/value")
                    .map(|path| vec![path])
                    .map_err(|error| ConfigError::new("path", error.message()))
            }
        }

        fn apply_delta(&mut self, delta: Self::Delta) -> Result<(), ConfigError> {
            self.value = delta;
            Ok(())
        }

        fn validate_syntax(&self) -> Result<(), ValidationError> {
            Ok(())
        }

        fn validate_semantics(
            &self,
            _context: &ValidationContext<Self>,
        ) -> Result<(), ValidationError> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct AppliedStore {
        inner: Arc<MockManagedDatastore<TestConfig>>,
        compacted: bool,
        probe: Option<Arc<AppliedStoreProbe>>,
    }

    #[derive(Default)]
    struct AppliedStoreProbe {
        active_waits: AtomicUsize,
        max_active_waits: AtomicUsize,
        wait_calls: AtomicUsize,
        changed: Notify,
    }

    impl AppliedStoreProbe {
        fn begin_wait(self: &Arc<Self>) -> AppliedWaitGuard {
            let active = self.active_waits.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active_waits.fetch_max(active, Ordering::SeqCst);
            self.wait_calls.fetch_add(1, Ordering::SeqCst);
            self.changed.notify_waiters();
            AppliedWaitGuard {
                probe: Arc::clone(self),
            }
        }

        async fn wait_for_active_at_least(&self, expected: usize) {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let changed = self.changed.notified();
                    if self.active_waits.load(Ordering::SeqCst) >= expected {
                        return;
                    }
                    changed.await;
                }
            })
            .await
            .expect("active datastore wait deadline");
        }

        async fn wait_for_active_exactly(&self, expected: usize) {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let changed = self.changed.notified();
                    if self.active_waits.load(Ordering::SeqCst) == expected {
                        return;
                    }
                    changed.await;
                }
            })
            .await
            .expect("exact active datastore wait deadline");
        }

        async fn wait_for_calls_at_least(&self, expected: usize) {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let changed = self.changed.notified();
                    if self.wait_calls.load(Ordering::SeqCst) >= expected {
                        return;
                    }
                    changed.await;
                }
            })
            .await
            .expect("datastore wait-call deadline");
        }
    }

    struct AppliedWaitGuard {
        probe: Arc<AppliedStoreProbe>,
    }

    impl Drop for AppliedWaitGuard {
        fn drop(&mut self) {
            self.probe.active_waits.fetch_sub(1, Ordering::SeqCst);
            self.probe.changed.notify_waiters();
        }
    }

    #[async_trait]
    impl ManagedDatastore<TestConfig> for AppliedStore {
        async fn load_latest(&self) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
            self.inner.load_latest().await
        }

        async fn load_committed_latest(
            &self,
        ) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
            self.inner.load_committed_latest().await
        }

        async fn load_since(
            &self,
            after: ConfigVersion,
            limit: usize,
        ) -> Result<Vec<StoredConfig<TestConfig>>, StoreError> {
            if self.compacted {
                return Err(StoreError::history_compacted(
                    "test committed history was compacted",
                ));
            }
            self.inner.load_since(after, limit).await
        }

        async fn wait_for_committed_change(&self, after: ConfigVersion) -> Result<(), StoreError> {
            let _guard = self.probe.as_ref().map(AppliedStoreProbe::begin_wait);
            self.inner.wait_for_committed_change(after).await
        }

        async fn load_rollback(
            &self,
            target: RollbackTarget,
        ) -> Result<StoredConfig<TestConfig>, StoreError> {
            self.inner.load_rollback(target).await
        }

        async fn load_by_idempotency_key(
            &self,
            key: &IdempotencyKey,
        ) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
            self.inner.load_by_idempotency_key(key).await
        }

        async fn load_by_request_id(
            &self,
            request_id: RequestId,
        ) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
            self.inner.load_by_request_id(request_id).await
        }

        async fn append_commit_write(
            &self,
            write: CommitWrite<TestConfig>,
        ) -> Result<(), StoreError> {
            self.inner.append_commit_write(write).await
        }

        async fn clear_recovery_required(&self, tx_id: TxId) -> Result<(), StoreError> {
            self.inner.clear_recovery_required(tx_id).await
        }

        async fn mark_confirmed(&self, tx_id: TxId) -> Result<(), StoreError> {
            self.inner.mark_confirmed(tx_id).await
        }
    }

    impl CommittedRevisionSource<TestConfig> for AppliedStore {}

    fn scope(seed: u8) -> ConfigConsensusIdentity {
        let cluster = ConfigConsensusClusterId::new(format!("config-watch-tests-{seed}"))
            .expect("test cluster");
        let epoch = ConfigConsensusConfigurationEpoch::new(1).expect("test epoch");
        ConfigConsensusIdentity::new(
            cluster,
            ConfigConsensusConfigurationId::from_bytes([seed; 32]),
            epoch,
        )
    }

    fn principal() -> TrustedPrincipal {
        TrustedPrincipal::new(
            WorkloadIdentity::Internal("config-watch-test".to_owned()),
            TenantId::new("test").expect("tenant"),
        )
    }

    fn record(
        version: u64,
        tx_id: TxId,
        parent_tx_id: Option<TxId>,
        value: &str,
    ) -> StoredConfig<TestConfig> {
        StoredConfig {
            tx_id,
            parent_tx_id,
            version: ConfigVersion::new(version),
            committed_at: Timestamp::from_str("2026-07-16T00:00:00Z").expect("fixed timestamp"),
            principal: principal(),
            source: RequestSource::Internal,
            schema_digest: SchemaDigest::from_bytes([0x56; 32]),
            plaintext_digest: None,
            config: TestConfig::new(value),
            encrypted_blob: Vec::new(),
            idempotency_key: None,
            apply_plan: None,
            request_fingerprint: None,
            request_id: None,
            recovery_required: false,
            confirmed_deadline: None,
            rollback_label: None,
        }
    }

    async fn seeded_shadow(
        values: &[&str],
    ) -> (
        Arc<ConfigBus<TestConfig>>,
        Arc<MockManagedDatastore<TestConfig>>,
        Vec<TxId>,
    ) {
        seeded_shadow_with_probe(values, None).await
    }

    async fn seeded_shadow_with_probe(
        values: &[&str],
        probe: Option<Arc<AppliedStoreProbe>>,
    ) -> (
        Arc<ConfigBus<TestConfig>>,
        Arc<MockManagedDatastore<TestConfig>>,
        Vec<TxId>,
    ) {
        let store = Arc::new(MockManagedDatastore::new());
        let mut parent = None;
        let mut tx_ids = Vec::new();
        for (index, value) in values.iter().enumerate() {
            let tx_id = TxId::new();
            store
                .seed(record((index + 1) as u64, tx_id, parent, value))
                .await;
            tx_ids.push(tx_id);
            parent = Some(tx_id);
        }
        let bus = ConfigBus::restore_shadow(AppliedStore {
            inner: Arc::clone(&store),
            compacted: false,
            probe,
        })
        .await
        .expect("restore shadow bus");
        (Arc::new(bus), store, tx_ids)
    }

    struct TestCa {
        issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
        pem: String,
    }

    impl TestCa {
        fn new() -> Self {
            let mut params = CertificateParams::default();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params
                .distinguished_name
                .push(DnType::CommonName, "config watch test CA");
            let key = rcgen::KeyPair::generate().expect("CA key");
            let issuer = rcgen::CertifiedIssuer::self_signed(params, key)
                .expect("CA certificate and issuer");
            let pem = issuer.pem();
            Self { issuer, pem }
        }

        fn issue_material(&self, spiffe_id: &SpiffeId) -> (String, String) {
            let mut params = CertificateParams::default();
            params
                .distinguished_name
                .push(DnType::CommonName, "config watch workload");
            params.subject_alt_names.push(SanType::URI(
                rcgen::string::Ia5String::try_from(spiffe_id.as_str()).expect("SPIFFE URI"),
            ));
            let now = time::OffsetDateTime::now_utc();
            params.not_before = now - time::Duration::days(1);
            params.not_after = now + time::Duration::days(1);
            let key = rcgen::KeyPair::generate().expect("leaf key");
            let certificate = params
                .signed_by(&key, &self.issuer)
                .expect("leaf certificate");

            (certificate.pem(), key.serialize_pem())
        }

        fn identity_state(&self, spiffe_id: &SpiffeId) -> IdentityState {
            let (certificate, key) = self.issue_material(spiffe_id);
            identity_state_from_pem(&certificate, &key, &self.pem)
        }
    }

    fn identity_state_from_pem(certificate: &str, key: &str, ca: &str) -> IdentityState {
        let mut bundles = TrustBundleSet::new();
        bundles.insert(TrustBundle {
            trust_domain: TrustDomain::new("test-domain").expect("trust domain"),
            certificates: parse_certs_pem(ca).expect("CA PEM"),
        });
        build_identity_state(
            parse_certs_pem(certificate).expect("leaf PEM"),
            parse_key_pem(key).expect("leaf key PEM"),
            bundles,
        )
        .expect("identity state")
    }

    struct TestTls {
        ca: TestCa,
        server_spiffe_id: SpiffeId,
        client_spiffe_id: SpiffeId,
        server_tx: watch::Sender<Option<IdentityState>>,
        client_tx: watch::Sender<Option<IdentityState>>,
        server_config: AuthenticatedServerConfig,
        client_config: AuthenticatedClientConfig,
    }

    impl TestTls {
        fn new(seed: u8) -> Self {
            let ca = TestCa::new();
            let server_spiffe_id = SpiffeId::new(format!(
                "spiffe://test-domain/tenant/test/ns/default/sa/config-watch/nf/smf/instance/server-{seed}"
            ))
            .expect("server SPIFFE ID");
            let client_spiffe_id = SpiffeId::new(format!(
                "spiffe://test-domain/tenant/test/ns/default/sa/config-watch/nf/smf/instance/client-{seed}"
            ))
            .expect("client SPIFFE ID");
            let (server_tx, server_rx) = watch::channel(Some(ca.identity_state(&server_spiffe_id)));
            let (client_tx, client_rx) = watch::channel(Some(ca.identity_state(&client_spiffe_id)));
            let server_config = TlsConfigBuilder::new(server_rx)
                .with_local_spiffe_id(server_spiffe_id.clone())
                .allow_any_trusted_peer()
                .build_authenticated_server_config()
                .expect("server TLS config");
            let client_config = TlsConfigBuilder::new(client_rx)
                .with_local_spiffe_id(client_spiffe_id.clone())
                .allow_any_trusted_peer()
                .build_authenticated_client_config()
                .expect("client TLS config");
            Self {
                ca,
                server_spiffe_id,
                client_spiffe_id,
                server_tx,
                client_tx,
                server_config,
                client_config,
            }
        }

        fn rotate(&self) {
            self.server_tx
                .send_replace(Some(self.ca.identity_state(&self.server_spiffe_id)));
            self.client_tx
                .send_replace(Some(self.ca.identity_state(&self.client_spiffe_id)));
        }

        fn server_binding(&self, scope: ConfigConsensusIdentity) -> ConfigWatchServerBinding {
            ConfigWatchServerBinding::try_new(
                scope,
                self.server_spiffe_id.clone(),
                vec![self.client_spiffe_id.clone()],
            )
            .expect("server binding")
        }

        fn remote(
            &self,
            scope: ConfigConsensusIdentity,
            address: SocketAddr,
        ) -> RemoteConfigWatch<TestConfig> {
            RemoteConfigWatch::new(
                ConfigWatchClientBinding::new(
                    scope,
                    self.client_spiffe_id.clone(),
                    self.server_spiffe_id.clone(),
                    TEST_SCHEMA_DIGEST,
                ),
                fixed_config_watch_endpoint(address),
                self.client_config.clone(),
            )
        }
    }

    async fn start_server(
        bus: Arc<ConfigBus<TestConfig>>,
        tls: &TestTls,
        scope: ConfigConsensusIdentity,
    ) -> (ConfigWatchServerHandle, SocketAddr) {
        ConfigWatchServer::new(bus, tls.server_config.clone(), tls.server_binding(scope))
            .expect("shadow config watch server")
            .listen("127.0.0.1:0".parse().expect("listen address"))
            .await
            .expect("start config watch server")
    }

    async fn attempt_wrong_alpn(tls: &TestTls, address: SocketAddr) {
        let handshake = tls
            .client_config
            .begin_handshake()
            .expect("client handshake material");
        let mut config = handshake.rustls_config().as_ref().clone();
        config.alpn_protocols = vec![b"not-opc-config-watch".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tcp = TcpStream::connect(address).await.expect("raw TCP connect");
        let result = connector
            .connect(ServerName::IpAddress(address.ip().into()), tcp)
            .await;
        if let Ok(stream) = result {
            assert_ne!(stream.get_ref().1.alpn_protocol(), Some(CONFIG_WATCH_ALPN));
        }
    }

    async fn connect_raw_watch(
        tls: &TestTls,
        address: SocketAddr,
    ) -> tokio_rustls::client::TlsStream<TcpStream> {
        let handshake = tls
            .client_config
            .begin_handshake()
            .expect("raw client handshake material");
        let mut config = handshake.rustls_config().as_ref().clone();
        config.alpn_protocols = vec![CONFIG_WATCH_ALPN.to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tcp = TcpStream::connect(address).await.expect("raw TCP connect");
        let stream = connector
            .connect(ServerName::IpAddress(address.ip().into()), tcp)
            .await
            .expect("raw TLS connect");
        handshake.admit().expect("raw TLS admission");
        stream
    }

    fn deterministic_tx_id(version: u64) -> TxId {
        TxId::from_uuid(uuid::Uuid::from_u128(u128::from(version)))
    }

    struct ChildWatchProcess {
        child: std::process::Child,
        directory: tempfile::TempDir,
        address: SocketAddr,
    }

    impl ChildWatchProcess {
        async fn shutdown(&mut self) {
            std::fs::write(self.directory.path().join("stop"), b"stop").expect("signal child stop");
            for _ in 0..250 {
                if let Some(status) = self.child.try_wait().expect("poll child") {
                    assert!(status.success(), "child server exited unsuccessfully");
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            self.child.kill().expect("kill timed-out child");
            let _ = self.child.wait();
            panic!("child server did not stop within its test deadline");
        }
    }

    impl Drop for ChildWatchProcess {
        fn drop(&mut self) {
            if self.child.try_wait().ok().flatten().is_none() {
                let _ = std::fs::write(self.directory.path().join("stop"), b"stop");
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }

    async fn spawn_child_watch_server(
        ca: &TestCa,
        server_spiffe_id: &SpiffeId,
        client_spiffe_id: &SpiffeId,
        values: &[&str],
        scope_seed: u8,
    ) -> ChildWatchProcess {
        use std::process::{Command, Stdio};

        let directory = tempfile::tempdir().expect("child server directory");
        let (certificate, key) = ca.issue_material(server_spiffe_id);
        std::fs::write(directory.path().join("server-cert.pem"), certificate)
            .expect("write child certificate");
        std::fs::write(directory.path().join("server-key.pem"), key)
            .expect("write child private key");
        std::fs::write(directory.path().join("ca.pem"), &ca.pem).expect("write child CA");
        let values = serde_json::to_string(values).expect("encode child values");
        let mut child = Command::new(std::env::current_exe().expect("unit-test executable"))
            .arg("--exact")
            .arg("remote_watch::tests::multiprocess_config_watch_server_child")
            .arg("--nocapture")
            .env("OPC_CONFIG_WATCH_CHILD", "1")
            .env("OPC_CONFIG_WATCH_CHILD_DIR", directory.path())
            .env("OPC_CONFIG_WATCH_CHILD_VALUES", values)
            .env(
                "OPC_CONFIG_WATCH_CHILD_SERVER_SPIFFE",
                server_spiffe_id.as_str(),
            )
            .env(
                "OPC_CONFIG_WATCH_CHILD_CLIENT_SPIFFE",
                client_spiffe_id.as_str(),
            )
            .env("OPC_CONFIG_WATCH_CHILD_SCOPE_SEED", scope_seed.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn config-watch child process");

        let address_path = directory.path().join("address");
        let mut address = None;
        for _ in 0..250 {
            if let Ok(encoded) = std::fs::read_to_string(&address_path) {
                address = Some(encoded.parse().expect("child listen address"));
                break;
            }
            if let Some(status) = child.try_wait().expect("poll starting child") {
                panic!("child server exited before readiness: {status}");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let address = address.expect("child server readiness deadline");
        ChildWatchProcess {
            child,
            directory,
            address,
        }
    }

    #[test]
    fn multiprocess_config_watch_server_child() {
        if std::env::var_os("OPC_CONFIG_WATCH_CHILD").is_none() {
            return;
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("child Tokio runtime");
        runtime.block_on(async {
            let directory = std::path::PathBuf::from(
                std::env::var_os("OPC_CONFIG_WATCH_CHILD_DIR")
                    .expect("child directory environment"),
            );
            let values: Vec<String> = serde_json::from_str(
                &std::env::var("OPC_CONFIG_WATCH_CHILD_VALUES").expect("child values environment"),
            )
            .expect("decode child values");
            let server_spiffe_id = SpiffeId::new(
                std::env::var("OPC_CONFIG_WATCH_CHILD_SERVER_SPIFFE")
                    .expect("child server identity environment"),
            )
            .expect("child server identity");
            let client_spiffe_id = SpiffeId::new(
                std::env::var("OPC_CONFIG_WATCH_CHILD_CLIENT_SPIFFE")
                    .expect("child client identity environment"),
            )
            .expect("child client identity");
            let scope_seed: u8 = std::env::var("OPC_CONFIG_WATCH_CHILD_SCOPE_SEED")
                .expect("child scope seed environment")
                .parse()
                .expect("child scope seed");
            let state = identity_state_from_pem(
                &std::fs::read_to_string(directory.join("server-cert.pem"))
                    .expect("read child certificate"),
                &std::fs::read_to_string(directory.join("server-key.pem"))
                    .expect("read child private key"),
                &std::fs::read_to_string(directory.join("ca.pem")).expect("read child CA"),
            );
            let (_identity_tx, identity_rx) = watch::channel(Some(state));
            let tls_config = TlsConfigBuilder::new(identity_rx)
                .with_local_spiffe_id(server_spiffe_id.clone())
                .allow_any_trusted_peer()
                .build_authenticated_server_config()
                .expect("child TLS config");

            let store = Arc::new(MockManagedDatastore::new());
            let mut parent = None;
            for (index, value) in values.iter().enumerate() {
                let version = (index + 1) as u64;
                let tx_id = deterministic_tx_id(version);
                store.seed(record(version, tx_id, parent, value)).await;
                parent = Some(tx_id);
            }
            let bus = Arc::new(
                ConfigBus::restore_shadow(AppliedStore {
                    inner: store,
                    compacted: false,
                    probe: None,
                })
                .await
                .expect("child follower bus"),
            );
            let binding = ConfigWatchServerBinding::try_new(
                scope(scope_seed),
                server_spiffe_id,
                vec![client_spiffe_id],
            )
            .expect("child server binding");
            let (handle, address) = ConfigWatchServer::new(bus, tls_config, binding)
                .expect("child shadow config watch server")
                .listen("127.0.0.1:0".parse().expect("child listen address"))
                .await
                .expect("child server listen");
            std::fs::write(directory.join("address"), address.to_string())
                .expect("publish child address");
            while !directory.join("stop").exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            handle.shutdown().await;
        });
    }

    #[test]
    fn profile_and_binding_bounds_are_exact() {
        assert!(CURRENT_CONFIG_WATCH_CONTRACT_PROFILE.is_current());
        assert_eq!(2, CURRENT_CONFIG_WATCH_CONTRACT_PROFILE.wire_revision);
        assert_eq!(
            ConfigWatchError::Unavailable,
            map_tls_material_error(TlsMaterialError::Unavailable)
        );
        assert_eq!(
            ConfigWatchError::ConnectionRetired,
            map_tls_material_error(TlsMaterialError::EpochChanged)
        );
        assert_eq!(
            ConfigWatchError::ConnectionRetired,
            map_tls_material_error(TlsMaterialError::EpochRetryLimit)
        );
        let server_id = SpiffeId::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/config-watch/nf/smf/instance/server-bounds",
        )
        .expect("server ID");
        let clients = (0..CONFIG_WATCH_MAX_CLIENT_IDENTITIES)
            .map(|index| {
                SpiffeId::new(format!(
                    "spiffe://test-domain/tenant/test/ns/default/sa/config-watch/nf/smf/instance/client-{index}"
                ))
                .expect("bounded client ID")
            })
            .collect::<Vec<_>>();
        assert!(
            ConfigWatchServerBinding::try_new(scope(1), server_id.clone(), clients.clone(),)
                .is_ok()
        );
        assert_eq!(
            ConfigWatchBindingError::EmptyClientIdentities,
            ConfigWatchServerBinding::try_new(scope(1), server_id.clone(), Vec::new(),)
                .expect_err("empty clients fail")
        );
        assert_eq!(
            ConfigWatchBindingError::DuplicateClientIdentity,
            ConfigWatchServerBinding::try_new(
                scope(1),
                server_id.clone(),
                vec![clients[0].clone(), clients[0].clone()],
            )
            .expect_err("duplicate clients fail")
        );
        let mut too_many = clients;
        too_many.push(
            SpiffeId::new(
                "spiffe://test-domain/tenant/test/ns/default/sa/config-watch/nf/smf/instance/client-over-limit",
            )
            .expect("over-limit client ID"),
        );
        assert_eq!(
            ConfigWatchBindingError::TooManyClientIdentities,
            ConfigWatchServerBinding::try_new(scope(1), server_id, too_many)
                .expect_err("over-limit clients fail")
        );
    }

    #[tokio::test]
    async fn server_rejects_authoritative_bus_and_accepts_marker_gated_shadow() {
        let tls = TestTls::new(12);
        let identity = scope(12);
        let authoritative = Arc::new(
            ConfigBus::new_dev_only(
                TestConfig::new("authoritative"),
                MockManagedDatastore::new(),
            )
            .await
            .expect("authoritative bus"),
        );
        let rejected = ConfigWatchServer::new(
            authoritative,
            tls.server_config.clone(),
            tls.server_binding(identity),
        )
        .expect_err("authoritative bus must not be remotely served");
        assert_eq!(ConfigWatchServerError::AuthoritativeBus, rejected);

        let (shadow, _store, _tx_ids) = seeded_shadow(&["shadow"]).await;
        assert!(ConfigWatchServer::new(
            shadow,
            tls.server_config.clone(),
            tls.server_binding(identity),
        )
        .is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn schema_digest_mismatch_fails_snapshot_page_and_decoded_payloads() {
        let (bus, _store, _tx_ids) = seeded_shadow(&["v1"]).await;
        let tls = TestTls::new(13);
        let identity = scope(13);
        let (handle, address) = start_server(bus, &tls, identity).await;
        let incompatible = RemoteConfigWatch::<AlternateConfig>::new(
            ConfigWatchClientBinding::new(
                identity,
                tls.client_spiffe_id.clone(),
                tls.server_spiffe_id.clone(),
                ALTERNATE_SCHEMA_DIGEST,
            ),
            fixed_config_watch_endpoint(address),
            tls.client_config.clone(),
        );
        assert_eq!(
            ConfigWatchError::ContractMismatch,
            incompatible
                .recover_from(None)
                .await
                .expect_err("snapshot schema negotiation must fail")
        );
        assert_eq!(
            ConfigWatchError::ContractMismatch,
            incompatible
                .load_committed_page(
                    ConfigRevisionCursor::after(ConfigVersion::INITIAL),
                    1,
                    Duration::ZERO,
                )
                .await
                .expect_err("page schema negotiation must fail")
        );

        let snapshot = WireResponse::Recovery(WireSnapshot {
            tx_id: deterministic_tx_id(1),
            version: ConfigVersion::new(1),
            config: TestConfig::new("v1"),
        });
        let encoded = serde_json::to_vec(&snapshot).expect("encode compatible snapshot shape");
        let decoded: WireResponse<AlternateConfig> =
            serde_json::from_slice(&encoded).expect("decode compatible snapshot shape");
        assert_eq!(
            Err(ConfigWatchError::ContractMismatch),
            validate_response_schema(&decoded, TEST_SCHEMA_DIGEST)
        );

        let page = ConfigHistoryPage::try_new(
            ConfigRevisionCursor::after(ConfigVersion::INITIAL),
            vec![CommittedConfigHistoryEntry {
                tx_id: deterministic_tx_id(1),
                version: ConfigVersion::new(1),
                config: TestConfig::new("v1"),
            }],
        )
        .expect("test page");
        let encoded =
            serde_json::to_vec(&WireResponse::Page(page)).expect("encode compatible page shape");
        let decoded: WireResponse<AlternateConfig> =
            serde_json::from_slice(&encoded).expect("decode compatible page shape");
        assert_eq!(
            Err(ConfigWatchError::ContractMismatch),
            validate_response_schema(&decoded, TEST_SCHEMA_DIGEST)
        );
        handle.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mismatched_wire_profile_and_bootstrap_echo_fail_closed() {
        let (bus, _store, _tx_ids) = seeded_shadow(&["v1"]).await;
        let tls = TestTls::new(14);
        let identity = scope(14);
        let (handle, address) = start_server(bus, &tls, identity).await;
        let mut stream = connect_raw_watch(&tls, address).await;
        let nonce = uuid::Uuid::new_v4();
        let mut mismatched = CURRENT_CONFIG_WATCH_CONTRACT_PROFILE;
        mismatched.wire_revision = mismatched.wire_revision.saturating_add(1);
        let hello = BootstrapRequest::Hello(BootstrapHello {
            profile: mismatched,
            scope: identity,
            schema_digest: TEST_SCHEMA_DIGEST,
            client_spiffe_id: tls.client_spiffe_id.clone(),
            expected_server_spiffe_id: tls.server_spiffe_id.clone(),
            nonce,
        });
        let deadline = deadline_after(Duration::from_secs(2)).expect("bootstrap deadline");
        write_frame_until(&mut stream, &hello, HANDSHAKE_FRAME_BYTES, deadline)
            .await
            .expect("write mismatched profile");
        let response: BootstrapResponse =
            read_frame_until(&mut stream, HANDSHAKE_FRAME_BYTES, deadline)
                .await
                .expect("read profile rejection");
        assert_eq!(
            BootstrapResponse::Rejected(ConfigWatchError::ContractMismatch),
            response
        );

        let binding = ConfigWatchClientBinding::new(
            identity,
            tls.client_spiffe_id.clone(),
            tls.server_spiffe_id.clone(),
            TEST_SCHEMA_DIGEST,
        );
        let wrong_echo = BootstrapResponse::Accepted {
            profile: CURRENT_CONFIG_WATCH_CONTRACT_PROFILE,
            scope: identity,
            schema_digest: TEST_SCHEMA_DIGEST,
            server_spiffe_id: tls.server_spiffe_id.clone(),
            accepted_client_spiffe_id: tls.client_spiffe_id.clone(),
            nonce: uuid::Uuid::new_v4(),
        };
        assert_eq!(
            Err(ConfigWatchError::Protocol),
            validate_bootstrap_response(wrong_echo, &binding, nonce)
        );
        handle.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_mtls_recovery_and_watch_are_gap_free_and_follower_local() {
        let (bus, store, tx_ids) = seeded_shadow(&["v1", "v2"]).await;
        let tls = TestTls::new(1);
        let identity = scope(1);
        let (handle, address) = start_server(bus, &tls, identity).await;
        let remote = tls.remote(identity, address);

        let recovery = remote.recover_from(None).await.expect("remote recovery");
        assert_eq!(ConfigVersion::new(2), recovery.snapshot().version);
        assert_eq!("v2", recovery.snapshot().config.value);
        let (_snapshot, mut tail) = recovery.into_parts();
        let next = tokio::spawn(async move { tail.next().await });
        tokio::task::yield_now().await;

        let third = TxId::new();
        store
            .seed(record(3, third, tx_ids.last().copied(), "v3"))
            .await;
        let delivered = tokio::time::timeout(Duration::from_secs(5), next)
            .await
            .expect("remote tail deadline")
            .expect("tail task")
            .expect("tail item")
            .expect("tail success");
        assert_eq!(ConfigVersion::new(3), delivered.version);
        assert_eq!("v3", delivered.config.value);

        let mut history = remote
            .watch_committed(ConfigVersion::INITIAL)
            .await
            .expect("remote history");
        for (version, value) in [(1, "v1"), (2, "v2"), (3, "v3")] {
            let entry = history
                .next()
                .await
                .expect("history item")
                .expect("history");
            assert_eq!(ConfigVersion::new(version), entry.version);
            assert_eq!(value, entry.config.value);
        }
        handle.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exact_identity_and_consensus_scope_fail_closed() {
        let (bus, _store, _tx_ids) = seeded_shadow(&["v1"]).await;
        let tls = TestTls::new(2);
        let identity = scope(2);
        let (handle, address) = start_server(bus, &tls, identity).await;

        let wrong_client = SpiffeId::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/config-watch/nf/smf/instance/wrong",
        )
        .expect("wrong client ID");
        let identity_mismatch = RemoteConfigWatch::<TestConfig>::new(
            ConfigWatchClientBinding::new(
                identity,
                wrong_client,
                tls.server_spiffe_id.clone(),
                TEST_SCHEMA_DIGEST,
            ),
            fixed_config_watch_endpoint(address),
            tls.client_config.clone(),
        );
        assert_eq!(
            ConfigWatchError::Authentication,
            identity_mismatch
                .recover_from(None)
                .await
                .expect_err("claimed client must match mTLS certificate")
        );

        let scope_mismatch = tls.remote(scope(9), address);
        assert_eq!(
            ConfigWatchError::ScopeMismatch,
            scope_mismatch
                .recover_from(None)
                .await
                .expect_err("consensus scope mismatch")
        );
        handle.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wrong_alpn_is_never_admitted_and_does_not_poison_the_listener() {
        let (bus, _store, _tx_ids) = seeded_shadow(&["v1"]).await;
        let tls = TestTls::new(4);
        let identity = scope(4);
        let (handle, address) = start_server(bus, &tls, identity).await;

        attempt_wrong_alpn(&tls, address).await;
        let recovered = tls
            .remote(identity, address)
            .recover_from(None)
            .await
            .expect("listener remains healthy after wrong ALPN");
        assert_eq!(ConfigVersion::new(1), recovered.snapshot().version);
        handle.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn transient_tls_reset_retries_but_bad_certificate_is_terminal() {
        let (bus, _store, _tx_ids) = seeded_shadow(&["v1"]).await;
        let tls = TestTls::new(17);
        let identity = scope(17);
        let (handle, address) = start_server(Arc::clone(&bus), &tls, identity).await;
        let reset_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reset listener");
        let reset_address = reset_listener.local_addr().expect("reset address");
        let reset_task = tokio::spawn(async move {
            let (stream, _) = reset_listener.accept().await.expect("reset accept");
            drop(stream);
        });
        let attempts = Arc::new(AtomicUsize::new(0));
        let resolver_attempts = Arc::clone(&attempts);
        let resolver: ConfigWatchAddrResolver = Arc::new(move || {
            let attempt = resolver_attempts.fetch_add(1, Ordering::SeqCst);
            let selected = if attempt == 0 { reset_address } else { address };
            Box::pin(async move { Ok(selected) })
        });
        let remote = RemoteConfigWatch::<TestConfig>::new(
            ConfigWatchClientBinding::new(
                identity,
                tls.client_spiffe_id.clone(),
                tls.server_spiffe_id.clone(),
                TEST_SCHEMA_DIGEST,
            ),
            resolver,
            tls.client_config.clone(),
        );
        let recovery = remote
            .recover_from(None)
            .await
            .expect("ordinary TLS reset must retry");
        assert_eq!(ConfigVersion::new(1), recovery.snapshot().version);
        assert_eq!(2, attempts.load(Ordering::SeqCst));
        reset_task.await.expect("reset task");
        handle.shutdown().await;

        let untrusted_server = TestTls::new(18);
        let (handle, address) = start_server(bus, &untrusted_server, identity).await;
        let attempts = Arc::new(AtomicUsize::new(0));
        let resolver_attempts = Arc::clone(&attempts);
        let resolver: ConfigWatchAddrResolver = Arc::new(move || {
            resolver_attempts.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(address) })
        });
        let remote = RemoteConfigWatch::<TestConfig>::new(
            ConfigWatchClientBinding::new(
                identity,
                tls.client_spiffe_id.clone(),
                untrusted_server.server_spiffe_id.clone(),
                TEST_SCHEMA_DIGEST,
            ),
            resolver,
            tls.client_config.clone(),
        );
        assert_eq!(
            ConfigWatchError::Authentication,
            remote
                .recover_from(None)
                .await
                .expect_err("untrusted certificate must be terminal")
        );
        assert_eq!(1, attempts.load(Ordering::SeqCst));
        handle.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn epoch_change_during_failed_tls_retries_inside_run_handshake() {
        let (bus, _store, _tx_ids) = seeded_shadow(&["v1"]).await;
        let tls = TestTls::new(19);
        let identity = scope(19);
        let (handle, address) = start_server(bus, &tls, identity).await;
        let reset_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("epoch reset listener");
        let reset_address = reset_listener.local_addr().expect("epoch reset address");
        let reset_task = tokio::spawn(async move {
            let (stream, _) = reset_listener.accept().await.expect("epoch reset accept");
            drop(stream);
        });
        let rotated = tls.ca.identity_state(&tls.client_spiffe_id);
        let client_tx = tls.client_tx.clone();
        let attempts = Arc::new(AtomicUsize::new(0));
        let resolver_attempts = Arc::clone(&attempts);
        let resolver: ConfigWatchAddrResolver = Arc::new(move || {
            let attempt = resolver_attempts.fetch_add(1, Ordering::SeqCst);
            let selected = if attempt == 0 {
                client_tx.send_replace(Some(rotated.clone()));
                reset_address
            } else {
                address
            };
            Box::pin(async move { Ok(selected) })
        });
        let remote = RemoteConfigWatch::<TestConfig>::new(
            ConfigWatchClientBinding::new(
                identity,
                tls.client_spiffe_id.clone(),
                tls.server_spiffe_id.clone(),
                TEST_SCHEMA_DIGEST,
            ),
            resolver,
            tls.client_config.clone(),
        );
        let (stream, _admission) = remote
            .connect_authenticated()
            .await
            .expect("epoch retry must complete inside one run_handshake call");
        drop(stream);
        assert_eq!(2, attempts.load(Ordering::SeqCst));
        reset_task.await.expect("epoch reset task");
        handle.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn client_run_handshake_retains_the_shared_concurrency_bound() {
        let tls = TestTls::new(20);
        let probe = Arc::new(AppliedStoreProbe::default());
        let gate = Arc::new(Notify::new());
        let resolver_probe = Arc::clone(&probe);
        let resolver_gate = Arc::clone(&gate);
        let resolver: ConfigWatchAddrResolver = Arc::new(move || {
            let guard = resolver_probe.begin_wait();
            let gate = Arc::clone(&resolver_gate);
            Box::pin(async move {
                let _guard = guard;
                gate.notified().await;
                Err(io::Error::new(io::ErrorKind::Interrupted, "test gate"))
            })
        });
        let remote = RemoteConfigWatch::<TestConfig>::new(
            ConfigWatchClientBinding::new(
                scope(20),
                tls.client_spiffe_id.clone(),
                tls.server_spiffe_id.clone(),
                TEST_SCHEMA_DIGEST,
            ),
            resolver,
            tls.client_config.clone(),
        );
        let mut tasks = Vec::new();
        for _ in 0..=opc_tls::MAX_TLS_CONCURRENT_HANDSHAKES {
            let remote = remote.clone();
            tasks.push(tokio::spawn(
                async move { remote.connect_authenticated().await },
            ));
        }
        probe
            .wait_for_active_at_least(opc_tls::MAX_TLS_CONCURRENT_HANDSHAKES)
            .await;
        tokio::task::yield_now().await;
        assert_eq!(
            opc_tls::MAX_TLS_CONCURRENT_HANDSHAKES,
            probe.active_waits.load(Ordering::SeqCst)
        );
        assert_eq!(
            opc_tls::MAX_TLS_CONCURRENT_HANDSHAKES,
            probe.max_active_waits.load(Ordering::SeqCst)
        );
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
        probe.wait_for_active_exactly(0).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn future_and_compacted_cursors_preserve_typed_remote_errors() {
        let (bus, _store, _tx_ids) = seeded_shadow(&["v1"]).await;
        let tls = TestTls::new(5);
        let identity = scope(5);
        let (handle, address) = start_server(bus, &tls, identity).await;
        let future = tls.remote(identity, address);
        assert_eq!(
            ConfigWatchError::HistoryCursorAhead,
            future
                .watch_committed(ConfigVersion::new(9))
                .await
                .err()
                .expect("future cursor must fail")
        );
        assert_eq!(
            ConfigWatchError::HistoryCursorAhead,
            future
                .watch_committed(ConfigVersion::new(u64::MAX))
                .await
                .err()
                .expect("future maximum cursor must fail")
        );
        handle.shutdown().await;

        let store = Arc::new(MockManagedDatastore::new());
        let first = TxId::new();
        store.seed(record(1, first, None, "v1")).await;
        let compacted_bus = Arc::new(
            ConfigBus::restore_shadow(AppliedStore {
                inner: store,
                compacted: true,
                probe: None,
            })
            .await
            .expect("restore compacted follower head"),
        );
        let tls = TestTls::new(6);
        let identity = scope(6);
        let (handle, address) = start_server(compacted_bus, &tls, identity).await;
        assert_eq!(
            ConfigWatchError::HistoryCompacted,
            tls.remote(identity, address)
                .watch_committed(ConfigVersion::INITIAL)
                .await
                .err()
                .expect("compacted cursor must require recovery")
        );
        handle.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn maximum_config_version_terminates_watch_and_recovery_cleanly() {
        let probe = Arc::new(AppliedStoreProbe::default());
        let store = Arc::new(MockManagedDatastore::new());
        let before_max = TxId::new();
        let at_max = TxId::new();
        store
            .seed(record(u64::MAX - 1, before_max, None, "before-max"))
            .await;
        store
            .seed(record(u64::MAX, at_max, Some(before_max), "at-max"))
            .await;
        let bus = Arc::new(
            ConfigBus::restore_shadow(AppliedStore {
                inner: store,
                compacted: false,
                probe: Some(Arc::clone(&probe)),
            })
            .await
            .expect("restore max-version shadow"),
        );
        let tls = TestTls::new(15);
        let identity = scope(15);
        let (handle, address) = start_server(bus, &tls, identity).await;
        let remote = tls.remote(identity, address);

        let mut direct = remote
            .watch_committed(ConfigVersion::new(u64::MAX))
            .await
            .expect("watch at maximum version");
        assert!(direct.next().await.is_none());

        let recovery = remote.recover_from(None).await.expect("recover at maximum");
        assert_eq!(ConfigVersion::new(u64::MAX), recovery.snapshot().version);
        let (_snapshot, mut recovered_tail) = recovery.into_parts();
        assert!(recovered_tail.next().await.is_none());

        let mut from_before = remote
            .watch_committed(ConfigVersion::new(u64::MAX - 1))
            .await
            .expect("watch before maximum");
        let final_entry = from_before
            .next()
            .await
            .expect("maximum entry")
            .expect("maximum entry success");
        assert_eq!(ConfigVersion::new(u64::MAX), final_entry.version);
        assert!(from_before.next().await.is_none());
        assert_eq!(0, probe.wait_calls.load(Ordering::SeqCst));
        handle.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn oversized_snapshot_returns_typed_error_before_any_partial_frame() {
        let oversized = "x".repeat(CONFIG_WATCH_MAX_RESPONSE_FRAME_BYTES + 1_024);
        let (bus, _store, _tx_ids) = seeded_shadow(&[&oversized]).await;
        let tls = TestTls::new(7);
        let identity = scope(7);
        let (handle, address) = start_server(bus, &tls, identity).await;
        assert_eq!(
            ConfigWatchError::FrameTooLarge,
            tls.remote(identity, address)
                .recover_from(None)
                .await
                .expect_err("oversized snapshot must not be partially emitted")
        );
        handle.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn oversized_full_page_adapts_and_continues_at_the_exact_cursor() {
        let store = Arc::new(MockManagedDatastore::new());
        let payload = "x".repeat(192 * 1024);
        let mut parent = None;
        for version in 1..=MAX_CONFIG_HISTORY_PAGE_ENTRIES as u64 {
            let tx_id = deterministic_tx_id(version);
            store
                .seed(record(
                    version,
                    tx_id,
                    parent,
                    &format!("{version:02}-{payload}"),
                ))
                .await;
            parent = Some(tx_id);
        }
        let bus = Arc::new(
            ConfigBus::restore_shadow(AppliedStore {
                inner: store,
                compacted: false,
                probe: None,
            })
            .await
            .expect("restore large-page shadow"),
        );
        let tls = TestTls::new(16);
        let identity = scope(16);
        let (handle, address) = start_server(bus, &tls, identity).await;
        let remote = tls.remote(identity, address);
        let initial_cursor = ConfigRevisionCursor::after(ConfigVersion::INITIAL);
        let (first, reduced_limit) = remote
            .load_page_adaptive(
                initial_cursor,
                MAX_CONFIG_HISTORY_PAGE_ENTRIES,
                Duration::ZERO,
            )
            .await
            .expect("adaptive first page");
        assert!(reduced_limit < MAX_CONFIG_HISTORY_PAGE_ENTRIES);
        assert!(!first.is_empty());
        for (index, entry) in first.entries().iter().enumerate() {
            assert_eq!(ConfigVersion::new((index + 1) as u64), entry.version);
        }
        let first_len = first.len();
        let (second, _second_limit) = remote
            .load_page_adaptive(
                first.next_cursor(),
                MAX_CONFIG_HISTORY_PAGE_ENTRIES,
                Duration::ZERO,
            )
            .await
            .expect("adaptive continuation page");
        assert_eq!(MAX_CONFIG_HISTORY_PAGE_ENTRIES, first_len + second.len());
        for (index, entry) in second.entries().iter().enumerate() {
            assert_eq!(
                ConfigVersion::new((first_len + index + 1) as u64),
                entry.version
            );
        }
        handle.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn active_long_poll_reauthenticates_after_material_rotation() {
        let probe = Arc::new(AppliedStoreProbe::default());
        let (bus, store, tx_ids) =
            seeded_shadow_with_probe(&["v1"], Some(Arc::clone(&probe))).await;
        let tls = TestTls::new(3);
        let identity = scope(3);
        let (handle, address) = start_server(bus, &tls, identity).await;
        let remote = tls.remote(identity, address);
        let mut stream = remote
            .watch_committed(ConfigVersion::new(1))
            .await
            .expect("watch at head");
        let next = tokio::spawn(async move { stream.next().await });
        probe.wait_for_active_at_least(1).await;

        tls.rotate();
        let second = TxId::new();
        store
            .seed(record(2, second, tx_ids.last().copied(), "v2"))
            .await;
        let entry = tokio::time::timeout(Duration::from_secs(8), next)
            .await
            .expect("rotation recovery deadline")
            .expect("watch task")
            .expect("watch item")
            .expect("watch success");
        assert_eq!(ConfigVersion::new(2), entry.version);
        assert_eq!("v2", entry.config.value);
        handle.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cancelled_long_polls_release_their_bounded_server_slots() {
        let probe = Arc::new(AppliedStoreProbe::default());
        let (bus, _store, _tx_ids) =
            seeded_shadow_with_probe(&["v1"], Some(Arc::clone(&probe))).await;
        let tls = TestTls::new(8);
        let identity = scope(8);
        let (handle, address) = start_server(bus, &tls, identity).await;
        let remote = tls.remote(identity, address);

        let mut streams = Vec::new();
        for _ in 0..=CONFIG_WATCH_MAX_CONCURRENT_CONNECTIONS {
            streams.push(
                remote
                    .watch_committed(ConfigVersion::new(1))
                    .await
                    .expect("watch at head"),
            );
        }
        let extra_stream = streams.pop().expect("extra stream");
        let mut stalled = Vec::new();
        for mut stream in streams {
            stalled.push(tokio::spawn(async move { stream.next().await }));
        }
        probe
            .wait_for_active_at_least(CONFIG_WATCH_MAX_CONCURRENT_CONNECTIONS)
            .await;

        let extra = tokio::spawn(async move {
            let mut stream = extra_stream;
            stream.next().await
        });
        assert!(
            tokio::time::timeout(
                Duration::from_millis(200),
                probe.wait_for_calls_at_least(CONFIG_WATCH_MAX_CONCURRENT_CONNECTIONS + 1),
            )
            .await
            .is_err(),
            "the next connection must remain blocked while all server slots are occupied"
        );
        assert!(!extra.is_finished());
        assert_eq!(
            CONFIG_WATCH_MAX_CONCURRENT_CONNECTIONS,
            probe.max_active_waits.load(Ordering::SeqCst)
        );

        stalled[0].abort();
        let _ = (&mut stalled[0]).await;
        probe
            .wait_for_calls_at_least(CONFIG_WATCH_MAX_CONCURRENT_CONNECTIONS + 1)
            .await;
        assert_eq!(
            CONFIG_WATCH_MAX_CONCURRENT_CONNECTIONS,
            probe.active_waits.load(Ordering::SeqCst)
        );

        for task in &stalled[1..] {
            task.abort();
        }
        extra.abort();
        for task in stalled.into_iter().skip(1) {
            let _ = task.await;
        }
        let _ = extra.await;
        probe.wait_for_active_exactly(0).await;
        handle.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn real_tcp_follower_switch_resumes_without_gap_or_reorder() {
        let first_tx = TxId::new();
        let second_tx = TxId::new();
        let third_tx = TxId::new();
        let history = [
            record(1, first_tx, None, "v1"),
            record(2, second_tx, Some(first_tx), "v2"),
        ];
        let first_store = Arc::new(MockManagedDatastore::new());
        let second_store = Arc::new(MockManagedDatastore::new());
        for entry in &history {
            first_store.seed(entry.clone()).await;
            second_store.seed(entry.clone()).await;
        }
        let first_bus = Arc::new(
            ConfigBus::restore_shadow(AppliedStore {
                inner: Arc::clone(&first_store),
                compacted: false,
                probe: None,
            })
            .await
            .expect("first follower bus"),
        );
        let second_bus = Arc::new(
            ConfigBus::restore_shadow(AppliedStore {
                inner: Arc::clone(&second_store),
                compacted: false,
                probe: None,
            })
            .await
            .expect("second follower bus"),
        );
        let identity = scope(9);
        let first_tls = TestTls::new(9);
        let second_tls = TestTls::new(10);
        let (first_handle, first_address) = start_server(first_bus, &first_tls, identity).await;
        let (second_handle, second_address) = start_server(second_bus, &second_tls, identity).await;

        let mut first_feed = first_tls
            .remote(identity, first_address)
            .watch_committed(ConfigVersion::INITIAL)
            .await
            .expect("first follower feed");
        for expected in [
            (ConfigVersion::new(1), first_tx),
            (ConfigVersion::new(2), second_tx),
        ] {
            let entry = first_feed
                .next()
                .await
                .expect("first follower item")
                .expect("first follower success");
            assert_eq!(expected, (entry.version, entry.tx_id));
        }
        first_handle.shutdown().await;

        second_store
            .seed(record(3, third_tx, Some(second_tx), "v3"))
            .await;
        let mut resumed = second_tls
            .remote(identity, second_address)
            .watch_committed(ConfigVersion::new(2))
            .await
            .expect("resume from second follower");
        let entry = resumed
            .next()
            .await
            .expect("resumed item")
            .expect("resumed success");
        assert_eq!(
            (ConfigVersion::new(3), third_tx),
            (entry.version, entry.tx_id)
        );
        assert_eq!("v3", entry.config.value);
        second_handle.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multiprocess_follower_switch_resumes_from_last_visible_cursor() {
        let ca = TestCa::new();
        let client_spiffe_id = SpiffeId::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/config-watch/nf/smf/instance/multiprocess-client",
        )
        .expect("multiprocess client ID");
        let first_server_spiffe_id = SpiffeId::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/config-watch/nf/smf/instance/multiprocess-server-a",
        )
        .expect("first multiprocess server ID");
        let second_server_spiffe_id = SpiffeId::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/config-watch/nf/smf/instance/multiprocess-server-b",
        )
        .expect("second multiprocess server ID");
        let (client_certificate, client_key) = ca.issue_material(&client_spiffe_id);
        let (client_tx, client_rx) = watch::channel(Some(identity_state_from_pem(
            &client_certificate,
            &client_key,
            &ca.pem,
        )));
        let client_config = TlsConfigBuilder::new(client_rx)
            .with_local_spiffe_id(client_spiffe_id.clone())
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("multiprocess client config");
        let identity = scope(11);

        let mut first = spawn_child_watch_server(
            &ca,
            &first_server_spiffe_id,
            &client_spiffe_id,
            &["v1", "v2"],
            11,
        )
        .await;
        let first_remote = RemoteConfigWatch::<TestConfig>::new(
            ConfigWatchClientBinding::new(
                identity,
                client_spiffe_id.clone(),
                first_server_spiffe_id,
                TEST_SCHEMA_DIGEST,
            ),
            fixed_config_watch_endpoint(first.address),
            client_config.clone(),
        );
        let mut first_feed = first_remote
            .watch_committed(ConfigVersion::INITIAL)
            .await
            .expect("first process feed");
        for version in 1..=2 {
            let entry = first_feed
                .next()
                .await
                .expect("first process item")
                .expect("first process success");
            assert_eq!(ConfigVersion::new(version), entry.version);
            assert_eq!(deterministic_tx_id(version), entry.tx_id);
        }
        first.shutdown().await;

        let mut second = spawn_child_watch_server(
            &ca,
            &second_server_spiffe_id,
            &client_spiffe_id,
            &["v1", "v2", "v3"],
            11,
        )
        .await;
        let second_remote = RemoteConfigWatch::<TestConfig>::new(
            ConfigWatchClientBinding::new(
                identity,
                client_spiffe_id,
                second_server_spiffe_id,
                TEST_SCHEMA_DIGEST,
            ),
            fixed_config_watch_endpoint(second.address),
            client_config,
        );
        let mut resumed = second_remote
            .watch_committed(ConfigVersion::new(2))
            .await
            .expect("second process resume");
        let entry = resumed
            .next()
            .await
            .expect("second process item")
            .expect("second process success");
        assert_eq!(ConfigVersion::new(3), entry.version);
        assert_eq!(deterministic_tx_id(3), entry.tx_id);
        assert_eq!("v3", entry.config.value);
        second.shutdown().await;
        drop(client_tx);
    }

    #[tokio::test]
    async fn oversized_prefix_and_half_frame_fail_before_unbounded_read() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer
            .write_all(&65_u32.to_be_bytes())
            .await
            .expect("write oversized prefix");
        let oversized = read_frame_until::<_, WireRequest>(
            &mut reader,
            64,
            deadline_after(Duration::from_secs(1)).expect("deadline"),
        )
        .await;
        assert!(matches!(oversized, Err(FrameError::TooLarge)));

        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer
            .write_all(&8_u32.to_be_bytes())
            .await
            .expect("write half-frame prefix");
        writer.write_all(b"{}").await.expect("write half frame");
        drop(writer);
        let half = read_frame_until::<_, WireRequest>(
            &mut reader,
            64,
            deadline_after(Duration::from_secs(1)).expect("deadline"),
        )
        .await;
        assert!(matches!(half, Err(FrameError::Io)));
    }
}
