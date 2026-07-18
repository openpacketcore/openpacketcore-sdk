//! Authenticated control-plane manifest and TLS exporter bootstrap.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use opc_session_store::OwnerId;
use opc_tls::{
    peer_tls_identity_from_client_connection, peer_tls_identity_from_server_connection,
    TlsAdmittedConnection, TlsClientHandshake, TlsServerHandshake,
};
use opc_types::{SpiffeId, Timestamp};
use rand::{rngs::SysRng, TryRng};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use zeroize::Zeroizing;

use super::{
    authenticated_epoch_deadline, canonical_routing_domains, sender_identity_digest,
    IngressRedirectBootstrap, IngressRedirectError, IngressRedirectPeerSession,
    IngressRedirectPendingRotation, IngressRedirectProfile, IngressRedirectProtectionEpoch,
    IngressRedirectSecurityMode, RoutingDomainTag,
};

const MANIFEST_MAGIC: [u8; 4] = *b"OPCM";
const MANIFEST_VERSION: u8 = 2;
const MANIFEST_MAX_BYTES: usize = 8 * 1024;
const SPIFFE_ID_MAX_BYTES: usize = 2 * 1024;
const CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(10);
const READY_MAGIC: [u8; 4] = *b"OPCA";
const READY_BYTES: usize = READY_MAGIC.len() + 32;
const ROTATION_MESSAGE_BYTES: usize = 4 + 8 + 32;
const ROTATION_STAGED_MAGIC: [u8; 4] = *b"OPCS";
const ROTATION_STAGED_ACK_MAGIC: [u8; 4] = *b"OPCK";
const ROTATION_ACTIVATED_MAGIC: [u8; 4] = *b"OPCV";
const ROTATION_FINAL_MAGIC: [u8; 4] = *b"OPCF";
const INITIAL_INSTALLED_MAGIC: [u8; 4] = *b"OPCI";
const INITIAL_INSTALLED_ACK_MAGIC: [u8; 4] = *b"OPCJ";
const RECONCILIATION_STATE_MAGIC: [u8; 4] = *b"OPCU";
const RECONCILIATION_STATE_BYTES: usize = 4 + 8 + 8 + 32;
const RECONCILIATION_TARGET_MAGIC: [u8; 4] = *b"OPCT";
const RECONCILIATION_TARGET_ACK_MAGIC: [u8; 4] = *b"OPCN";
const RECONCILIATION_ACTIVATED_MAGIC: [u8; 4] = *b"OPCY";
const RECONCILIATION_FINAL_MAGIC: [u8; 4] = *b"OPCZ";
const EXPORTER_LABEL: &[u8] = b"EXPORTER-openpacketcore-ingress-redirect-v1";
const EXPORTER_BYTES: usize = 80;
const BOOTSTRAP_NONCE_BYTES: usize = 32;

/// Dedicated application protocol for authenticated ingress redirect control.
pub const INGRESS_REDIRECT_CONTROL_ALPN: &[u8] = b"opc-ipsec-ingress-redirect/1";

/// Versioned peer contract authenticated by the completed SPIFFE mTLS channel.
///
/// Both peers must advertise the same profile and routing-domain allowlist.
/// The identity must exactly match the peer certificate and the owner/endpoint
/// must exactly match the caller's configured expectation. Debug output never
/// exposes identities, owners, endpoints, or routing-domain values.
#[derive(Clone, PartialEq, Eq)]
pub struct IngressRedirectPeerManifest {
    spiffe_id: SpiffeId,
    owner: OwnerId,
    udp_endpoint: SocketAddr,
    profile: IngressRedirectProfile,
    routing_domains: Arc<[RoutingDomainTag]>,
}

impl IngressRedirectPeerManifest {
    /// Construct a bounded canonical control manifest.
    pub fn new(
        spiffe_id: SpiffeId,
        owner: OwnerId,
        udp_endpoint: SocketAddr,
        profile: IngressRedirectProfile,
        routing_domains: impl IntoIterator<Item = RoutingDomainTag>,
    ) -> Result<Self, IngressRedirectError> {
        profile
            .validate()
            .map_err(|_| IngressRedirectError::InvalidPeerManifest)?;
        validate_udp_endpoint(udp_endpoint)?;
        if spiffe_id.as_str().len() > SPIFFE_ID_MAX_BYTES {
            return Err(IngressRedirectError::InvalidPeerManifest);
        }
        let routing_domains: Vec<_> = routing_domains.into_iter().collect();
        let routing_domains = canonical_routing_domains(&routing_domains)?;
        Ok(Self {
            spiffe_id,
            owner,
            udp_endpoint,
            profile,
            routing_domains,
        })
    }

    /// SPIFFE identity that must match the manifest sender's certificate.
    #[must_use]
    pub const fn spiffe_id(&self) -> &SpiffeId {
        &self.spiffe_id
    }

    /// Fenced owner identifier represented by this peer.
    #[must_use]
    pub const fn owner(&self) -> &OwnerId {
        &self.owner
    }

    /// UDP endpoint for protected redirect frames.
    #[must_use]
    pub const fn udp_endpoint(&self) -> SocketAddr {
        self.udp_endpoint
    }

    /// Exact negotiated redirect profile.
    #[must_use]
    pub const fn profile(&self) -> IngressRedirectProfile {
        self.profile
    }

    /// Canonical sorted routing-domain allowlist.
    #[must_use]
    pub fn routing_domains(&self) -> &[RoutingDomainTag] {
        &self.routing_domains
    }

    fn encode(&self) -> Result<Vec<u8>, IngressRedirectError> {
        let identity = self.spiffe_id.as_str().as_bytes();
        let owner = self.owner.as_str().as_bytes();
        let identity_len =
            u16::try_from(identity.len()).map_err(|_| IngressRedirectError::InvalidPeerManifest)?;
        let owner_len =
            u16::try_from(owner.len()).map_err(|_| IngressRedirectError::InvalidPeerManifest)?;
        let domain_count = u16::try_from(self.routing_domains.len())
            .map_err(|_| IngressRedirectError::InvalidPeerManifest)?;
        let rotation_millis = u32::try_from(self.profile.rotation_overlap.as_millis())
            .map_err(|_| IngressRedirectError::InvalidPeerManifest)?;
        let queue_packets = u32::try_from(self.profile.queue_packets.get())
            .map_err(|_| IngressRedirectError::InvalidPeerManifest)?;
        let queue_bytes = u32::try_from(self.profile.queue_bytes.get())
            .map_err(|_| IngressRedirectError::InvalidPeerManifest)?;
        let receipt_cache_entries = u32::try_from(self.profile.receipt_cache_entries.get())
            .map_err(|_| IngressRedirectError::InvalidPeerManifest)?;
        let receipt_millis = u32::try_from(self.profile.receipt_timeout.as_millis())
            .map_err(|_| IngressRedirectError::InvalidPeerManifest)?;
        let maximum_authentication_age_millis =
            u32::try_from(self.profile.maximum_authentication_age.as_millis())
                .map_err(|_| IngressRedirectError::InvalidPeerManifest)?;

        let mut encoded = Vec::with_capacity(64 + identity.len() + owner.len());
        encoded.extend_from_slice(&MANIFEST_MAGIC);
        encoded.push(MANIFEST_VERSION);
        encoded.push(self.profile.security_mode as u8);
        encoded.push(self.profile.hop_limit.get());
        encoded.push(self.profile.max_retries);
        encoded.extend_from_slice(&self.profile.steering_path_mtu.get().to_be_bytes());
        encoded.extend_from_slice(&self.profile.replay_window.get().to_be_bytes());
        encoded.extend_from_slice(&rotation_millis.to_be_bytes());
        encoded.extend_from_slice(&queue_packets.to_be_bytes());
        encoded.extend_from_slice(&queue_bytes.to_be_bytes());
        encoded.extend_from_slice(&receipt_cache_entries.to_be_bytes());
        encoded.extend_from_slice(&receipt_millis.to_be_bytes());
        encoded.extend_from_slice(&maximum_authentication_age_millis.to_be_bytes());
        encode_endpoint(self.udp_endpoint, &mut encoded)?;
        encoded.extend_from_slice(&identity_len.to_be_bytes());
        encoded.extend_from_slice(&owner_len.to_be_bytes());
        encoded.extend_from_slice(&domain_count.to_be_bytes());
        encoded.extend_from_slice(identity);
        encoded.extend_from_slice(owner);
        for domain in self.routing_domains.iter() {
            encoded.extend_from_slice(&domain.get().to_be_bytes());
        }
        if encoded.len() > MANIFEST_MAX_BYTES {
            return Err(IngressRedirectError::InvalidPeerManifest);
        }
        Ok(encoded)
    }

    fn decode(encoded: &[u8]) -> Result<Self, IngressRedirectError> {
        if encoded.is_empty() || encoded.len() > MANIFEST_MAX_BYTES {
            return Err(IngressRedirectError::InvalidPeerManifest);
        }
        let mut cursor = ManifestCursor::new(encoded);
        if cursor.read_array::<4>()? != MANIFEST_MAGIC || cursor.read_u8()? != MANIFEST_VERSION {
            return Err(IngressRedirectError::InvalidPeerManifest);
        }
        let security_mode = match cursor.read_u8()? {
            value if value == IngressRedirectSecurityMode::Aes256Gcm as u8 => {
                IngressRedirectSecurityMode::Aes256Gcm
            }
            value if value == IngressRedirectSecurityMode::HmacSha256 as u8 => {
                IngressRedirectSecurityMode::HmacSha256
            }
            _ => return Err(IngressRedirectError::InvalidPeerManifest),
        };
        let hop_limit = cursor.read_u8()?;
        let max_retries = cursor.read_u8()?;
        let path_mtu = cursor.read_u16()?;
        let replay_window = cursor.read_u16()?;
        let rotation_overlap = Duration::from_millis(u64::from(cursor.read_u32()?));
        let queue_packets = usize::try_from(cursor.read_u32()?)
            .map_err(|_| IngressRedirectError::InvalidPeerManifest)?;
        let queue_bytes = usize::try_from(cursor.read_u32()?)
            .map_err(|_| IngressRedirectError::InvalidPeerManifest)?;
        let receipt_cache_entries = usize::try_from(cursor.read_u32()?)
            .map_err(|_| IngressRedirectError::InvalidPeerManifest)?;
        let receipt_timeout = Duration::from_millis(u64::from(cursor.read_u32()?));
        let maximum_authentication_age = Duration::from_millis(u64::from(cursor.read_u32()?));
        let udp_endpoint = decode_endpoint(&mut cursor)?;
        let identity_len = usize::from(cursor.read_u16()?);
        let owner_len = usize::from(cursor.read_u16()?);
        let domain_count = usize::from(cursor.read_u16()?);
        if identity_len == 0
            || identity_len > SPIFFE_ID_MAX_BYTES
            || owner_len == 0
            || owner_len > OwnerId::MAX_BYTES
        {
            return Err(IngressRedirectError::InvalidPeerManifest);
        }
        let expected_tail = identity_len
            .checked_add(owner_len)
            .and_then(|value| value.checked_add(domain_count.checked_mul(8)?))
            .ok_or(IngressRedirectError::InvalidPeerManifest)?;
        if cursor.remaining() != expected_tail {
            return Err(IngressRedirectError::InvalidPeerManifest);
        }
        let identity = std::str::from_utf8(cursor.read_slice(identity_len)?)
            .map_err(|_| IngressRedirectError::InvalidPeerManifest)?;
        let spiffe_id = SpiffeId::new(identity.to_owned())
            .map_err(|_| IngressRedirectError::InvalidPeerManifest)?;
        let owner = std::str::from_utf8(cursor.read_slice(owner_len)?)
            .map_err(|_| IngressRedirectError::InvalidPeerManifest)?;
        let owner = OwnerId::new(owner.to_owned())
            .map_err(|_| IngressRedirectError::InvalidPeerManifest)?;
        let mut routing_domains = Vec::with_capacity(domain_count);
        for _ in 0..domain_count {
            routing_domains.push(RoutingDomainTag::new(cursor.read_u64()?));
        }
        if cursor.remaining() != 0 {
            return Err(IngressRedirectError::InvalidPeerManifest);
        }

        let profile = IngressRedirectProfile::production(path_mtu)?
            .with_security_mode(security_mode)
            .with_hop_limit(hop_limit)?
            .with_replay_window(replay_window)?
            .with_rotation_overlap(rotation_overlap)?
            .with_queue_limits(queue_packets, queue_bytes)?
            .with_receipt_cache_entries(receipt_cache_entries)?
            .with_receipt_policy(receipt_timeout, max_retries)?
            .with_maximum_authentication_age(maximum_authentication_age)?;
        Self::new(spiffe_id, owner, udp_endpoint, profile, routing_domains)
    }
}

impl fmt::Debug for IngressRedirectPeerManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IngressRedirectPeerManifest")
            .field("spiffe_id", &"[redacted]")
            .field("owner", &"[redacted]")
            .field("udp_endpoint", &"[redacted]")
            .field("profile", &self.profile)
            .field("routing_domain_count", &self.routing_domains.len())
            .finish()
    }
}

/// Exact configured identity, owner, and data endpoint expected from a peer.
#[derive(Clone, PartialEq, Eq)]
pub struct IngressRedirectPeerExpectation {
    spiffe_id: SpiffeId,
    owner: OwnerId,
    udp_endpoint: SocketAddr,
}

impl IngressRedirectPeerExpectation {
    /// Construct an exact fail-closed expectation for one configured peer.
    pub fn new(
        spiffe_id: SpiffeId,
        owner: OwnerId,
        udp_endpoint: SocketAddr,
    ) -> Result<Self, IngressRedirectError> {
        validate_udp_endpoint(udp_endpoint)?;
        if spiffe_id.as_str().len() > SPIFFE_ID_MAX_BYTES {
            return Err(IngressRedirectError::InvalidPeerManifest);
        }
        Ok(Self {
            spiffe_id,
            owner,
            udp_endpoint,
        })
    }

    /// Expected peer SPIFFE ID.
    #[must_use]
    pub const fn spiffe_id(&self) -> &SpiffeId {
        &self.spiffe_id
    }

    /// Expected fenced owner identifier.
    #[must_use]
    pub const fn owner(&self) -> &OwnerId {
        &self.owner
    }

    /// Expected protected-datagram endpoint.
    #[must_use]
    pub const fn udp_endpoint(&self) -> SocketAddr {
        self.udp_endpoint
    }
}

impl fmt::Debug for IngressRedirectPeerExpectation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IngressRedirectPeerExpectation")
            .field("spiffe_id", &"[redacted]")
            .field("owner", &"[redacted]")
            .field("udp_endpoint", &"[redacted]")
            .finish()
    }
}

/// Clone one coherent client-handshake configuration and constrain it to the
/// dedicated redirect-control ALPN with resumption and early data disabled.
#[must_use]
pub fn ingress_redirect_client_tls_config(
    handshake: &TlsClientHandshake,
) -> Arc<rustls::ClientConfig> {
    let mut config = handshake.rustls_config().as_ref().clone();
    config.alpn_protocols = vec![INGRESS_REDIRECT_CONTROL_ALPN.to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Arc::new(config)
}

/// Clone one coherent server-handshake configuration and constrain it to the
/// dedicated redirect-control ALPN with tickets and early data disabled.
#[must_use]
pub fn ingress_redirect_server_tls_config(
    handshake: &TlsServerHandshake,
) -> Arc<rustls::ServerConfig> {
    let mut config = handshake.rustls_config().as_ref().clone();
    config.alpn_protocols = vec![INGRESS_REDIRECT_CONTROL_ALPN.to_vec()];
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.ticketer = Arc::new(DisabledSessionTickets);
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    Arc::new(config)
}

#[derive(Debug)]
struct DisabledSessionTickets;

impl rustls::server::ProducesTickets for DisabledSessionTickets {
    fn enabled(&self) -> bool {
        false
    }

    fn lifetime(&self) -> u32 {
        0
    }

    fn encrypt(&self, _plain: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn decrypt(&self, _cipher: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

#[async_trait]
trait RotationControl: Send {
    async fn write(
        &mut self,
        magic: [u8; 4],
        epoch: IngressRedirectProtectionEpoch,
        transcript: [u8; 32],
    ) -> Result<(), IngressRedirectError>;

    async fn read(
        &mut self,
        magic: [u8; 4],
        epoch: IngressRedirectProtectionEpoch,
        transcript: [u8; 32],
    ) -> Result<(), IngressRedirectError>;

    fn admit(&mut self) -> Result<(), IngressRedirectError>;
}

struct ClientRotationControl<'a, IO> {
    stream: &'a mut tokio_rustls::client::TlsStream<IO>,
    handshake: &'a TlsClientHandshake,
}

#[async_trait]
impl<IO> RotationControl for ClientRotationControl<'_, IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn write(
        &mut self,
        magic: [u8; 4],
        epoch: IngressRedirectProtectionEpoch,
        transcript: [u8; 32],
    ) -> Result<(), IngressRedirectError> {
        write_rotation_message(self.stream, magic, epoch, transcript).await
    }

    async fn read(
        &mut self,
        magic: [u8; 4],
        epoch: IngressRedirectProtectionEpoch,
        transcript: [u8; 32],
    ) -> Result<(), IngressRedirectError> {
        read_rotation_message(self.stream, magic, epoch, transcript).await
    }

    fn admit(&mut self) -> Result<(), IngressRedirectError> {
        self.handshake
            .admit()
            .map(|_| ())
            .map_err(|_| IngressRedirectError::TlsBootstrapFailed)
    }
}

struct ServerRotationControl<'a, IO> {
    stream: &'a mut tokio_rustls::server::TlsStream<IO>,
    handshake: &'a TlsServerHandshake,
}

#[async_trait]
impl<IO> RotationControl for ServerRotationControl<'_, IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn write(
        &mut self,
        magic: [u8; 4],
        epoch: IngressRedirectProtectionEpoch,
        transcript: [u8; 32],
    ) -> Result<(), IngressRedirectError> {
        write_rotation_message(self.stream, magic, epoch, transcript).await
    }

    async fn read(
        &mut self,
        magic: [u8; 4],
        epoch: IngressRedirectProtectionEpoch,
        transcript: [u8; 32],
    ) -> Result<(), IngressRedirectError> {
        read_rotation_message(self.stream, magic, epoch, transcript).await
    }

    fn admit(&mut self) -> Result<(), IngressRedirectError> {
        self.handshake
            .admit()
            .map(|_| ())
            .map_err(|_| IngressRedirectError::TlsBootstrapFailed)
    }
}

/// Owns an initial session until every peer-visible installation boundary is
/// acknowledged.
///
/// The guard is armed immediately before the first control read or write. Once
/// armed, an explicit failure is classified as
/// [`IngressRedirectError::InitialOutcomeUnknown`], while cancellation drops
/// the guard and therefore retires the unreturned local session. Only
/// [`Self::release`] can transfer a session to the caller.
#[must_use = "dropping an armed initial-session guard retires an outcome-unknown session"]
struct InitialSessionGuard {
    session: Option<IngressRedirectPeerSession>,
    peer_visible: bool,
}

impl InitialSessionGuard {
    fn new(session: IngressRedirectPeerSession) -> Self {
        Self {
            session: Some(session),
            peer_visible: false,
        }
    }

    fn before_peer_visible_boundary(&mut self) {
        self.peer_visible = true;
    }

    fn retire_as_unknown(mut self) -> IngressRedirectError {
        drop(self.session.take());
        IngressRedirectError::InitialOutcomeUnknown
    }

    fn ensure_current_authentication_valid(&self) -> Result<(), IngressRedirectError> {
        self.session
            .as_ref()
            .ok_or(IngressRedirectError::InitialOutcomeUnknown)?
            .ensure_current_authentication_valid_at(std::time::Instant::now())
    }

    fn release(mut self) -> Result<IngressRedirectPeerSession, IngressRedirectError> {
        if !self.peer_visible {
            return Err(self.retire_as_unknown());
        }
        self.session
            .take()
            .ok_or(IngressRedirectError::InitialOutcomeUnknown)
    }
}

impl Drop for InitialSessionGuard {
    fn drop(&mut self) {
        if self.peer_visible {
            // A cancelled control future cannot return an error to its caller.
            // Owning and dropping the session here is the local retirement
            // action for the InitialOutcomeUnknown disposition.
            drop(self.session.take());
        }
    }
}

async fn complete_initial_client<C>(
    control: &mut C,
    session: IngressRedirectPeerSession,
    epoch: IngressRedirectProtectionEpoch,
    transcript: [u8; 32],
) -> Result<IngressRedirectPeerSession, IngressRedirectError>
where
    C: RotationControl,
{
    let mut guard = InitialSessionGuard::new(session);
    guard.before_peer_visible_boundary();
    if control
        .write(INITIAL_INSTALLED_MAGIC, epoch, transcript)
        .await
        .is_err()
    {
        return Err(guard.retire_as_unknown());
    }
    guard.before_peer_visible_boundary();
    if control
        .read(INITIAL_INSTALLED_ACK_MAGIC, epoch, transcript)
        .await
        .is_err()
    {
        return Err(guard.retire_as_unknown());
    }
    if control.admit().is_err() {
        return Err(guard.retire_as_unknown());
    }
    if guard.ensure_current_authentication_valid().is_err() {
        return Err(guard.retire_as_unknown());
    }
    guard.release()
}

async fn complete_initial_server<C>(
    control: &mut C,
    session: IngressRedirectPeerSession,
    epoch: IngressRedirectProtectionEpoch,
    transcript: [u8; 32],
) -> Result<IngressRedirectPeerSession, IngressRedirectError>
where
    C: RotationControl,
{
    let mut guard = InitialSessionGuard::new(session);
    guard.before_peer_visible_boundary();
    if control
        .read(INITIAL_INSTALLED_MAGIC, epoch, transcript)
        .await
        .is_err()
    {
        return Err(guard.retire_as_unknown());
    }
    guard.before_peer_visible_boundary();
    if control
        .write(INITIAL_INSTALLED_ACK_MAGIC, epoch, transcript)
        .await
        .is_err()
    {
        return Err(guard.retire_as_unknown());
    }
    if control.admit().is_err() {
        return Err(guard.retire_as_unknown());
    }
    if guard.ensure_current_authentication_valid().is_err() {
        return Err(guard.retire_as_unknown());
    }
    guard.release()
}

async fn complete_rotation_client<C>(
    control: &mut C,
    session: &IngressRedirectPeerSession,
    guard: PendingRotationGuard<'_>,
    transcript: [u8; 32],
) -> Result<IngressRedirectProtectionEpoch, IngressRedirectError>
where
    C: RotationControl,
{
    let epoch = guard.epoch()?;
    // The first write can be partially peer-visible. Retain local receive
    // state before it begins so every cancellation/failure is reconcilable.
    let token = guard.retain_pending()?;
    if control
        .write(ROTATION_STAGED_MAGIC, epoch, transcript)
        .await
        .is_err()
    {
        return Err(IngressRedirectError::RotationOutcomeUnknown);
    }
    control
        .read(ROTATION_STAGED_ACK_MAGIC, epoch, transcript)
        .await
        .map_err(|_| IngressRedirectError::RotationOutcomeUnknown)?;
    control
        .admit()
        .map_err(|_| IngressRedirectError::RotationOutcomeUnknown)?;

    let activated = session
        .activate_rotation(&token)
        .map_err(|_| IngressRedirectError::RotationOutcomeUnknown)?;
    if control
        .write(ROTATION_ACTIVATED_MAGIC, activated, transcript)
        .await
        .is_err()
    {
        return Err(IngressRedirectError::RotationOutcomeUnknown);
    }
    if control
        .read(ROTATION_FINAL_MAGIC, activated, transcript)
        .await
        .is_err()
    {
        return Err(IngressRedirectError::RotationOutcomeUnknown);
    }
    control
        .admit()
        .map_err(|_| IngressRedirectError::RotationOutcomeUnknown)?;
    session
        .ensure_current_epoch_authentication_valid_at(activated, Instant::now())
        .map_err(|_| IngressRedirectError::RotationOutcomeUnknown)?;
    Ok(activated)
}

async fn complete_rotation_server<C>(
    control: &mut C,
    session: &IngressRedirectPeerSession,
    guard: PendingRotationGuard<'_>,
    transcript: [u8; 32],
) -> Result<IngressRedirectProtectionEpoch, IngressRedirectError>
where
    C: RotationControl,
{
    let epoch = guard.epoch()?;
    // The peer's staged write can be partial, so retain before the first read.
    let token = guard.retain_pending()?;
    if control
        .read(ROTATION_STAGED_MAGIC, epoch, transcript)
        .await
        .is_err()
    {
        return Err(IngressRedirectError::RotationOutcomeUnknown);
    }
    control
        .admit()
        .map_err(|_| IngressRedirectError::RotationOutcomeUnknown)?;
    if control
        .write(ROTATION_STAGED_ACK_MAGIC, epoch, transcript)
        .await
        .is_err()
    {
        return Err(IngressRedirectError::RotationOutcomeUnknown);
    }
    if control
        .read(ROTATION_ACTIVATED_MAGIC, epoch, transcript)
        .await
        .is_err()
    {
        return Err(IngressRedirectError::RotationOutcomeUnknown);
    }
    control
        .admit()
        .map_err(|_| IngressRedirectError::RotationOutcomeUnknown)?;
    let activated = session
        .activate_rotation(&token)
        .map_err(|_| IngressRedirectError::RotationOutcomeUnknown)?;
    if control
        .write(ROTATION_FINAL_MAGIC, activated, transcript)
        .await
        .is_err()
    {
        return Err(IngressRedirectError::RotationOutcomeUnknown);
    }
    control
        .admit()
        .map_err(|_| IngressRedirectError::RotationOutcomeUnknown)?;
    session
        .ensure_current_epoch_authentication_valid_at(activated, Instant::now())
        .map_err(|_| IngressRedirectError::RotationOutcomeUnknown)?;
    Ok(activated)
}

async fn complete_reconciliation_client<C>(
    control: &mut C,
    session: &IngressRedirectPeerSession,
    target: IngressRedirectProtectionEpoch,
    transcript: [u8; 32],
) -> Result<IngressRedirectProtectionEpoch, IngressRedirectError>
where
    C: RotationControl,
{
    complete_reconciliation_client_with(
        control,
        session,
        target,
        transcript,
        IngressRedirectPeerSession::reconcile_authenticated_epoch,
    )
    .await
}

async fn complete_reconciliation_client_with<C, R>(
    control: &mut C,
    session: &IngressRedirectPeerSession,
    target: IngressRedirectProtectionEpoch,
    transcript: [u8; 32],
    reconcile: R,
) -> Result<IngressRedirectProtectionEpoch, IngressRedirectError>
where
    C: RotationControl,
    R: FnOnce(
        &IngressRedirectPeerSession,
        IngressRedirectProtectionEpoch,
    ) -> Result<IngressRedirectProtectionEpoch, IngressRedirectError>,
{
    control
        .admit()
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?;
    control
        .write(RECONCILIATION_TARGET_MAGIC, target, transcript)
        .await?;
    control
        .read(RECONCILIATION_TARGET_ACK_MAGIC, target, transcript)
        .await?;

    let reconciled =
        reconcile(session, target).map_err(|_| IngressRedirectError::RotationOutcomeUnknown)?;
    if control
        .write(RECONCILIATION_ACTIVATED_MAGIC, reconciled, transcript)
        .await
        .is_err()
    {
        return Err(IngressRedirectError::RotationOutcomeUnknown);
    }
    if control
        .read(RECONCILIATION_FINAL_MAGIC, reconciled, transcript)
        .await
        .is_err()
    {
        return Err(IngressRedirectError::RotationOutcomeUnknown);
    }
    control
        .admit()
        .map_err(|_| IngressRedirectError::RotationOutcomeUnknown)?;
    session
        .ensure_current_epoch_authentication_valid_at(reconciled, Instant::now())
        .map_err(|_| IngressRedirectError::RotationOutcomeUnknown)?;
    Ok(reconciled)
}

async fn complete_reconciliation_server<C>(
    control: &mut C,
    session: &IngressRedirectPeerSession,
    target: IngressRedirectProtectionEpoch,
    transcript: [u8; 32],
) -> Result<IngressRedirectProtectionEpoch, IngressRedirectError>
where
    C: RotationControl,
{
    complete_reconciliation_server_with(
        control,
        session,
        target,
        transcript,
        IngressRedirectPeerSession::reconcile_authenticated_epoch,
    )
    .await
}

async fn complete_reconciliation_server_with<C, R>(
    control: &mut C,
    session: &IngressRedirectPeerSession,
    target: IngressRedirectProtectionEpoch,
    transcript: [u8; 32],
    reconcile: R,
) -> Result<IngressRedirectProtectionEpoch, IngressRedirectError>
where
    C: RotationControl,
    R: FnOnce(
        &IngressRedirectPeerSession,
        IngressRedirectProtectionEpoch,
    ) -> Result<IngressRedirectProtectionEpoch, IngressRedirectError>,
{
    control
        .read(RECONCILIATION_TARGET_MAGIC, target, transcript)
        .await?;
    control
        .admit()
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?;
    if control
        .write(RECONCILIATION_TARGET_ACK_MAGIC, target, transcript)
        .await
        .is_err()
    {
        return Err(IngressRedirectError::RotationOutcomeUnknown);
    }
    if control
        .read(RECONCILIATION_ACTIVATED_MAGIC, target, transcript)
        .await
        .is_err()
    {
        return Err(IngressRedirectError::RotationOutcomeUnknown);
    }

    let reconciled =
        reconcile(session, target).map_err(|_| IngressRedirectError::RotationOutcomeUnknown)?;
    if control
        .write(RECONCILIATION_FINAL_MAGIC, reconciled, transcript)
        .await
        .is_err()
    {
        return Err(IngressRedirectError::RotationOutcomeUnknown);
    }
    control
        .admit()
        .map_err(|_| IngressRedirectError::RotationOutcomeUnknown)?;
    session
        .ensure_current_epoch_authentication_valid_at(reconciled, Instant::now())
        .map_err(|_| IngressRedirectError::RotationOutcomeUnknown)?;
    Ok(reconciled)
}

/// Establish a fresh client SPIFFE mTLS connection from the supplied coherent
/// handshake snapshot, negotiate the redirect contract, and derive one
/// exporter epoch.
///
/// This function owns TLS construction so the stream cannot come from an
/// unrelated rustls configuration. Each invocation performs a new full
/// handshake and exchanges fresh CSPRNG nonces bound into the exporter
/// context. No raw packet-protection key is returned. If installation or its
/// acknowledgement becomes ambiguous, [`IngressRedirectError::InitialOutcomeUnknown`]
/// is returned with no session. Discard local state, retire or replace any
/// potentially installed remote association through the product connection
/// lifecycle, and only then attempt another fresh full handshake. Cancelling
/// this future after the initial-install write begins has the same
/// outcome-unknown disposition: the SDK retires the unreturned local session,
/// and the caller must apply that remote-association lifecycle before retrying.
pub async fn establish_ingress_redirect_client<IO>(
    io: IO,
    server_name: rustls::pki_types::ServerName<'static>,
    handshake: TlsClientHandshake,
    local: &IngressRedirectPeerManifest,
    expected_peer: &IngressRedirectPeerExpectation,
) -> Result<IngressRedirectPeerSession, IngressRedirectError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
{
    let connector =
        tokio_rustls::TlsConnector::from(ingress_redirect_client_tls_config(&handshake));
    let mut stream = timeout(CONTROL_IO_TIMEOUT, connector.connect(server_name, io))
        .await
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?;
    let negotiated = bootstrap_client_stream(&mut stream, &handshake, local, expected_peer).await?;
    let epoch = negotiated.bootstrap.epoch;
    let session = IngressRedirectPeerSession::from_bootstrap(negotiated.bootstrap)?;
    let mut control = ClientRotationControl {
        stream: &mut stream,
        handshake: &handshake,
    };
    complete_initial_client(&mut control, session, epoch, negotiated.transcript).await
}

/// Accept a fresh server SPIFFE mTLS connection from the supplied coherent
/// handshake snapshot, negotiate the redirect contract, and derive one
/// exporter epoch.
///
/// This function owns TLS construction so the stream cannot come from an
/// unrelated rustls configuration. Each invocation performs a new full
/// handshake and exchanges fresh CSPRNG nonces bound into the exporter
/// context. No raw packet-protection key is returned. A successful return
/// proves that the acknowledgement was emitted and the local material snapshot
/// remained current; it is not by itself product dataplane-readiness evidence.
/// Ambiguous installation returns [`IngressRedirectError::InitialOutcomeUnknown`].
/// Cancelling this future while awaiting the peer's install message or while
/// emitting its acknowledgement retires the unreturned local session and must
/// be treated by the caller as the same outcome-unknown disposition.
pub async fn establish_ingress_redirect_server<IO>(
    io: IO,
    handshake: TlsServerHandshake,
    local: &IngressRedirectPeerManifest,
    expected_peer: &IngressRedirectPeerExpectation,
) -> Result<IngressRedirectPeerSession, IngressRedirectError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
{
    let acceptor = tokio_rustls::TlsAcceptor::from(ingress_redirect_server_tls_config(&handshake));
    let mut stream = timeout(CONTROL_IO_TIMEOUT, acceptor.accept(io))
        .await
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?;
    let negotiated = bootstrap_server_stream(&mut stream, &handshake, local, expected_peer).await?;
    let epoch = negotiated.bootstrap.epoch;
    let session = IngressRedirectPeerSession::from_bootstrap(negotiated.bootstrap)?;
    let mut control = ServerRotationControl {
        stream: &mut stream,
        handshake: &handshake,
    };
    complete_initial_server(&mut control, session, epoch, negotiated.transcript).await
}

/// Establish a fresh authenticated client control channel, stage its exporter
/// epoch for receive, and perform an acknowledged two-phase send cutover.
///
/// Both peers install the new receive epoch before either changes its send
/// epoch. The previous receive epoch remains accepted only for the bounded
/// overlap and never past its hard authentication deadline. After
/// [`IngressRedirectError::RotationOutcomeUnknown`], keep the session idle and
/// use [`reconcile_ingress_redirect_client`] on a fresh full TLS connection.
pub async fn rotate_ingress_redirect_client<IO>(
    io: IO,
    server_name: rustls::pki_types::ServerName<'static>,
    handshake: TlsClientHandshake,
    local: &IngressRedirectPeerManifest,
    expected_peer: &IngressRedirectPeerExpectation,
    session: &IngressRedirectPeerSession,
) -> Result<IngressRedirectProtectionEpoch, IngressRedirectError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
{
    let _control_operation = session.begin_control_operation()?;
    let connector =
        tokio_rustls::TlsConnector::from(ingress_redirect_client_tls_config(&handshake));
    let mut stream = timeout(CONTROL_IO_TIMEOUT, connector.connect(server_name, io))
        .await
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?;
    let negotiated = bootstrap_client_stream(&mut stream, &handshake, local, expected_peer).await?;
    let guard = PendingRotationGuard::new(session, session.stage_rotation(negotiated.bootstrap)?);
    let mut control = ClientRotationControl {
        stream: &mut stream,
        handshake: &handshake,
    };
    complete_rotation_client(&mut control, session, guard, negotiated.transcript).await
}

/// Accept a fresh authenticated server control channel, stage its exporter
/// epoch for receive, and perform an acknowledged two-phase send cutover.
/// Ambiguous state remains bounded and must be resolved through
/// [`reconcile_ingress_redirect_server`] before further rotation.
pub async fn rotate_ingress_redirect_server<IO>(
    io: IO,
    handshake: TlsServerHandshake,
    local: &IngressRedirectPeerManifest,
    expected_peer: &IngressRedirectPeerExpectation,
    session: &IngressRedirectPeerSession,
) -> Result<IngressRedirectProtectionEpoch, IngressRedirectError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
{
    let _control_operation = session.begin_control_operation()?;
    let acceptor = tokio_rustls::TlsAcceptor::from(ingress_redirect_server_tls_config(&handshake));
    let mut stream = timeout(CONTROL_IO_TIMEOUT, acceptor.accept(io))
        .await
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?;
    let negotiated = bootstrap_server_stream(&mut stream, &handshake, local, expected_peer).await?;
    let guard = PendingRotationGuard::new(session, session.stage_rotation(negotiated.bootstrap)?);
    let mut control = ServerRotationControl {
        stream: &mut stream,
        handshake: &handshake,
    };
    complete_rotation_server(&mut control, session, guard, negotiated.transcript).await
}

/// Reconcile an idle client association after an ambiguous rotation outcome.
///
/// A fresh, non-resumed SPIFFE mTLS channel exchanges authenticated
/// current/pending epoch state. Matching current/pending evidence selects one
/// already-derived epoch; no caller-provided epoch or raw key is accepted. The
/// caller must keep the association idle until this operation resolves.
pub async fn reconcile_ingress_redirect_client<IO>(
    io: IO,
    server_name: rustls::pki_types::ServerName<'static>,
    handshake: TlsClientHandshake,
    local: &IngressRedirectPeerManifest,
    expected_peer: &IngressRedirectPeerExpectation,
    session: &IngressRedirectPeerSession,
) -> Result<IngressRedirectProtectionEpoch, IngressRedirectError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
{
    let _control_operation = session.begin_control_operation()?;
    let connector =
        tokio_rustls::TlsConnector::from(ingress_redirect_client_tls_config(&handshake));
    let mut stream = timeout(CONTROL_IO_TIMEOUT, connector.connect(server_name, io))
        .await
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?;
    let negotiated = bootstrap_client_stream(&mut stream, &handshake, local, expected_peer).await?;
    let transcript = negotiated.transcript;
    drop(negotiated.bootstrap);

    let local_state = ReconciliationState::from_session(session)?;
    write_reconciliation_state(&mut stream, local_state, transcript).await?;
    let peer_state = read_reconciliation_state(&mut stream, transcript).await?;
    let target = reconciliation_target(local_state, peer_state)?;
    let mut control = ClientRotationControl {
        stream: &mut stream,
        handshake: &handshake,
    };
    complete_reconciliation_client(&mut control, session, target, transcript).await
}

/// Reconcile an idle server association after an ambiguous rotation outcome.
/// The caller must keep the association idle until this fresh authenticated
/// operation resolves.
pub async fn reconcile_ingress_redirect_server<IO>(
    io: IO,
    handshake: TlsServerHandshake,
    local: &IngressRedirectPeerManifest,
    expected_peer: &IngressRedirectPeerExpectation,
    session: &IngressRedirectPeerSession,
) -> Result<IngressRedirectProtectionEpoch, IngressRedirectError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
{
    let _control_operation = session.begin_control_operation()?;
    let acceptor = tokio_rustls::TlsAcceptor::from(ingress_redirect_server_tls_config(&handshake));
    let mut stream = timeout(CONTROL_IO_TIMEOUT, acceptor.accept(io))
        .await
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?;
    let negotiated = bootstrap_server_stream(&mut stream, &handshake, local, expected_peer).await?;
    let transcript = negotiated.transcript;
    drop(negotiated.bootstrap);

    let peer_state = read_reconciliation_state(&mut stream, transcript).await?;
    let local_state = ReconciliationState::from_session(session)?;
    write_reconciliation_state(&mut stream, local_state, transcript).await?;
    let target = reconciliation_target(peer_state, local_state)?;
    let mut control = ServerRotationControl {
        stream: &mut stream,
        handshake: &handshake,
    };
    complete_reconciliation_server(&mut control, session, target, transcript).await
}

#[derive(Clone, Copy)]
struct ReconciliationState {
    current: IngressRedirectProtectionEpoch,
    pending: Option<IngressRedirectProtectionEpoch>,
}

impl ReconciliationState {
    fn from_session(session: &IngressRedirectPeerSession) -> Result<Self, IngressRedirectError> {
        let state = session.rotation_status()?;
        Ok(Self {
            current: state.current(),
            pending: state.pending_receive(),
        })
    }
}

fn reconciliation_target(
    client: ReconciliationState,
    server: ReconciliationState,
) -> Result<IngressRedirectProtectionEpoch, IngressRedirectError> {
    if client.current == server.current {
        return match (client.pending, server.pending) {
            (Some(client_pending), Some(server_pending)) if client_pending == server_pending => {
                Ok(client_pending)
            }
            _ => Ok(client.current),
        };
    }
    if server.pending == Some(client.current) {
        return Ok(client.current);
    }
    if client.pending == Some(server.current) {
        return Ok(server.current);
    }
    Err(IngressRedirectError::RotationNotStaged)
}

struct NegotiatedBootstrap {
    bootstrap: IngressRedirectBootstrap,
    transcript: [u8; 32],
}

struct PendingRotationGuard<'a> {
    session: &'a IngressRedirectPeerSession,
    token: Option<IngressRedirectPendingRotation>,
}

impl<'a> PendingRotationGuard<'a> {
    fn new(session: &'a IngressRedirectPeerSession, token: IngressRedirectPendingRotation) -> Self {
        Self {
            session,
            token: Some(token),
        }
    }

    fn epoch(&self) -> Result<IngressRedirectProtectionEpoch, IngressRedirectError> {
        self.token
            .as_ref()
            .map(IngressRedirectPendingRotation::epoch)
            .ok_or(IngressRedirectError::RotationNotStaged)
    }

    fn retain_pending(mut self) -> Result<IngressRedirectPendingRotation, IngressRedirectError> {
        let token = self
            .token
            .as_ref()
            .ok_or(IngressRedirectError::RotationNotStaged)?;
        self.session.retain_pending_for_reconciliation(token)?;
        self.token
            .take()
            .ok_or(IngressRedirectError::RotationNotStaged)
    }
}

impl Drop for PendingRotationGuard<'_> {
    fn drop(&mut self) {
        if let Some(token) = self.token.as_ref() {
            let _ = self.session.abort_rotation(token);
        }
    }
}

async fn bootstrap_client_stream<IO>(
    stream: &mut tokio_rustls::client::TlsStream<IO>,
    handshake: &TlsClientHandshake,
    local: &IngressRedirectPeerManifest,
    expected_peer: &IngressRedirectPeerExpectation,
) -> Result<NegotiatedBootstrap, IngressRedirectError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    if stream.get_ref().1.alpn_protocol() != Some(INGRESS_REDIRECT_CONTROL_ALPN) {
        return Err(IngressRedirectError::TlsBootstrapFailed);
    }
    let authenticated_peer = peer_tls_identity_from_client_connection(stream.get_ref().1)
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?;
    require_expected_tls_peer(authenticated_peer.spiffe_id(), expected_peer)?;

    let client_nonce = fresh_bootstrap_nonce()?;
    write_bootstrap_nonce(stream, client_nonce).await?;
    let local_encoded = local.encode()?;
    write_control_frame(stream, &local_encoded).await?;
    let server_nonce = read_bootstrap_nonce(stream).await?;
    if server_nonce == client_nonce {
        return Err(IngressRedirectError::TlsBootstrapFailed);
    }
    let peer_encoded = read_control_frame(stream).await?;
    let peer = IngressRedirectPeerManifest::decode(&peer_encoded)?;
    validate_peer_contract(local, &peer, authenticated_peer.spiffe_id(), expected_peer)?;

    let transcript = transcript_digest(&client_nonce, &local_encoded, &server_nonce, &peer_encoded);
    let material = export_client_material(stream.get_ref().1, &transcript)?;
    write_ready(stream, transcript).await?;
    read_ready(stream, transcript).await?;
    let admission = handshake
        .admit()
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?;
    let bootstrap = bootstrap_from_exporter(
        local,
        &peer,
        material,
        ExporterRole::Client,
        admission,
        authenticated_peer.certificate_chain_expires_at(),
        Timestamp::now_utc(),
        std::time::Instant::now(),
    )?;
    Ok(NegotiatedBootstrap {
        bootstrap,
        transcript,
    })
}

async fn bootstrap_server_stream<IO>(
    stream: &mut tokio_rustls::server::TlsStream<IO>,
    handshake: &TlsServerHandshake,
    local: &IngressRedirectPeerManifest,
    expected_peer: &IngressRedirectPeerExpectation,
) -> Result<NegotiatedBootstrap, IngressRedirectError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    if stream.get_ref().1.alpn_protocol() != Some(INGRESS_REDIRECT_CONTROL_ALPN) {
        return Err(IngressRedirectError::TlsBootstrapFailed);
    }
    let authenticated_peer = peer_tls_identity_from_server_connection(stream.get_ref().1)
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?;
    require_expected_tls_peer(authenticated_peer.spiffe_id(), expected_peer)?;

    let client_nonce = read_bootstrap_nonce(stream).await?;
    let peer_encoded = read_control_frame(stream).await?;
    let peer = IngressRedirectPeerManifest::decode(&peer_encoded)?;
    validate_peer_contract(local, &peer, authenticated_peer.spiffe_id(), expected_peer)?;
    let server_nonce = fresh_bootstrap_nonce()?;
    if server_nonce == client_nonce {
        return Err(IngressRedirectError::TlsBootstrapFailed);
    }
    write_bootstrap_nonce(stream, server_nonce).await?;
    let local_encoded = local.encode()?;
    write_control_frame(stream, &local_encoded).await?;

    let transcript = transcript_digest(&client_nonce, &peer_encoded, &server_nonce, &local_encoded);
    let material = export_server_material(stream.get_ref().1, &transcript)?;
    read_ready(stream, transcript).await?;
    write_ready(stream, transcript).await?;
    let admission = handshake
        .admit()
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?;
    let bootstrap = bootstrap_from_exporter(
        local,
        &peer,
        material,
        ExporterRole::Server,
        admission,
        authenticated_peer.certificate_chain_expires_at(),
        Timestamp::now_utc(),
        std::time::Instant::now(),
    )?;
    Ok(NegotiatedBootstrap {
        bootstrap,
        transcript,
    })
}

fn require_expected_tls_peer(
    authenticated_peer: &SpiffeId,
    expected_peer: &IngressRedirectPeerExpectation,
) -> Result<(), IngressRedirectError> {
    if authenticated_peer != &expected_peer.spiffe_id {
        return Err(IngressRedirectError::PeerIdentityMismatch);
    }
    Ok(())
}

fn validate_peer_contract(
    local: &IngressRedirectPeerManifest,
    peer: &IngressRedirectPeerManifest,
    authenticated_peer: &SpiffeId,
    expected_peer: &IngressRedirectPeerExpectation,
) -> Result<(), IngressRedirectError> {
    if &peer.spiffe_id != authenticated_peer
        || peer.spiffe_id != expected_peer.spiffe_id
        || peer.owner != expected_peer.owner
        || peer.udp_endpoint != expected_peer.udp_endpoint
        || peer.profile != local.profile
        || peer.routing_domains != local.routing_domains
    {
        return Err(IngressRedirectError::PeerIdentityMismatch);
    }
    Ok(())
}

fn export_client_material(
    connection: &rustls::ClientConnection,
    transcript: &[u8; 32],
) -> Result<Zeroizing<[u8; EXPORTER_BYTES]>, IngressRedirectError> {
    connection
        .export_keying_material(
            Zeroizing::new([0_u8; EXPORTER_BYTES]),
            EXPORTER_LABEL,
            Some(transcript),
        )
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)
}

fn export_server_material(
    connection: &rustls::ServerConnection,
    transcript: &[u8; 32],
) -> Result<Zeroizing<[u8; EXPORTER_BYTES]>, IngressRedirectError> {
    connection
        .export_keying_material(
            Zeroizing::new([0_u8; EXPORTER_BYTES]),
            EXPORTER_LABEL,
            Some(transcript),
        )
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)
}

#[derive(Clone, Copy)]
enum ExporterRole {
    Client,
    Server,
}

struct ExporterDirections {
    epoch: IngressRedirectProtectionEpoch,
    send_key: Zeroizing<[u8; 32]>,
    receive_key: Zeroizing<[u8; 32]>,
    send_nonce_prefix: [u8; 4],
    receive_nonce_prefix: [u8; 4],
}

fn exporter_directions(
    material: Zeroizing<[u8; EXPORTER_BYTES]>,
    role: ExporterRole,
) -> Result<ExporterDirections, IngressRedirectError> {
    let mut client_to_server_key = Zeroizing::new([0_u8; 32]);
    client_to_server_key.copy_from_slice(&material[..32]);
    let mut server_to_client_key = Zeroizing::new([0_u8; 32]);
    server_to_client_key.copy_from_slice(&material[32..64]);
    let client_to_server_nonce = copy_array::<4>(&material[64..68])?;
    let server_to_client_nonce = copy_array::<4>(&material[68..72])?;
    let epoch = u64::from_be_bytes(copy_array::<8>(&material[72..80])?);
    if epoch == 0 {
        return Err(IngressRedirectError::TlsBootstrapFailed);
    }
    let (send_key, receive_key, send_nonce_prefix, receive_nonce_prefix) = match role {
        ExporterRole::Client => (
            client_to_server_key,
            server_to_client_key,
            client_to_server_nonce,
            server_to_client_nonce,
        ),
        ExporterRole::Server => (
            server_to_client_key,
            client_to_server_key,
            server_to_client_nonce,
            client_to_server_nonce,
        ),
    };
    Ok(ExporterDirections {
        epoch: IngressRedirectProtectionEpoch(epoch),
        send_key,
        receive_key,
        send_nonce_prefix,
        receive_nonce_prefix,
    })
}

// This is the single narrow conversion boundary from authenticated TLS
// evidence plus exporter material into an executable redirect session.
#[allow(clippy::too_many_arguments)]
fn bootstrap_from_exporter(
    local: &IngressRedirectPeerManifest,
    peer: &IngressRedirectPeerManifest,
    material: Zeroizing<[u8; EXPORTER_BYTES]>,
    role: ExporterRole,
    local_admission: TlsAdmittedConnection,
    peer_certificate_chain_expires_at: Timestamp,
    authenticated_at: Timestamp,
    monotonic_now: std::time::Instant,
) -> Result<IngressRedirectBootstrap, IngressRedirectError> {
    let directions = exporter_directions(material, role)?;
    let hard_authenticated_deadline = authenticated_epoch_deadline(
        monotonic_now,
        authenticated_at,
        local_admission.certificate_chain_expires_at(),
        peer_certificate_chain_expires_at,
        local.profile.maximum_authentication_age,
    )?;
    Ok(IngressRedirectBootstrap {
        profile: local.profile,
        local_owner: local.owner.clone(),
        peer_owner: peer.owner.clone(),
        local_sender_digest: sender_identity_digest(local.spiffe_id.as_str()),
        peer_sender_digest: sender_identity_digest(peer.spiffe_id.as_str()),
        routing_domains: Arc::clone(&local.routing_domains),
        local_udp_endpoint: local.udp_endpoint,
        peer_udp_endpoint: peer.udp_endpoint,
        epoch: directions.epoch,
        send_key: directions.send_key,
        receive_key: directions.receive_key,
        send_nonce_prefix: directions.send_nonce_prefix,
        receive_nonce_prefix: directions.receive_nonce_prefix,
        authentication_evidence: super::EpochAuthenticationEvidence::Tls {
            local_admission,
            peer_certificate_chain_expires_at,
            authenticated_at,
        },
        hard_authenticated_deadline,
    })
}

async fn write_control_frame<W>(writer: &mut W, payload: &[u8]) -> Result<(), IngressRedirectError>
where
    W: AsyncWrite + Unpin,
{
    if payload.is_empty() || payload.len() > MANIFEST_MAX_BYTES {
        return Err(IngressRedirectError::InvalidPeerManifest);
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| IngressRedirectError::InvalidPeerManifest)?
        .to_be_bytes();
    timeout(CONTROL_IO_TIMEOUT, async {
        writer.write_all(&length).await?;
        writer.write_all(payload).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?
    .map_err(|_| IngressRedirectError::TlsBootstrapFailed)
}

async fn read_control_frame<R>(reader: &mut R) -> Result<Vec<u8>, IngressRedirectError>
where
    R: AsyncRead + Unpin,
{
    timeout(CONTROL_IO_TIMEOUT, async {
        let mut length = [0_u8; 4];
        reader.read_exact(&mut length).await?;
        let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid control frame")
        })?;
        if length == 0 || length > MANIFEST_MAX_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid control frame",
            ));
        }
        let mut payload = vec![0_u8; length];
        reader.read_exact(&mut payload).await?;
        Ok(payload)
    })
    .await
    .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?
    .map_err(|_| IngressRedirectError::TlsBootstrapFailed)
}

fn fresh_bootstrap_nonce() -> Result<[u8; BOOTSTRAP_NONCE_BYTES], IngressRedirectError> {
    let mut nonce = [0_u8; BOOTSTRAP_NONCE_BYTES];
    SysRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?;
    Ok(nonce)
}

async fn write_bootstrap_nonce<W>(
    writer: &mut W,
    nonce: [u8; BOOTSTRAP_NONCE_BYTES],
) -> Result<(), IngressRedirectError>
where
    W: AsyncWrite + Unpin,
{
    timeout(CONTROL_IO_TIMEOUT, async {
        writer.write_all(&nonce).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?
    .map_err(|_| IngressRedirectError::TlsBootstrapFailed)
}

async fn read_bootstrap_nonce<R>(
    reader: &mut R,
) -> Result<[u8; BOOTSTRAP_NONCE_BYTES], IngressRedirectError>
where
    R: AsyncRead + Unpin,
{
    let mut nonce = [0_u8; BOOTSTRAP_NONCE_BYTES];
    timeout(CONTROL_IO_TIMEOUT, reader.read_exact(&mut nonce))
        .await
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?;
    Ok(nonce)
}

async fn write_ready<W>(writer: &mut W, transcript: [u8; 32]) -> Result<(), IngressRedirectError>
where
    W: AsyncWrite + Unpin,
{
    let mut ready = [0_u8; READY_BYTES];
    ready[..READY_MAGIC.len()].copy_from_slice(&READY_MAGIC);
    ready[READY_MAGIC.len()..].copy_from_slice(&transcript);
    timeout(CONTROL_IO_TIMEOUT, async {
        writer.write_all(&ready).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?
    .map_err(|_| IngressRedirectError::TlsBootstrapFailed)
}

async fn read_ready<R>(reader: &mut R, transcript: [u8; 32]) -> Result<(), IngressRedirectError>
where
    R: AsyncRead + Unpin,
{
    let mut ready = [0_u8; READY_BYTES];
    timeout(CONTROL_IO_TIMEOUT, reader.read_exact(&mut ready))
        .await
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?;
    if ready[..READY_MAGIC.len()] != READY_MAGIC || ready[READY_MAGIC.len()..] != transcript {
        return Err(IngressRedirectError::TlsBootstrapFailed);
    }
    Ok(())
}

async fn write_rotation_message<W>(
    writer: &mut W,
    magic: [u8; 4],
    epoch: IngressRedirectProtectionEpoch,
    transcript: [u8; 32],
) -> Result<(), IngressRedirectError>
where
    W: AsyncWrite + Unpin,
{
    let mut message = [0_u8; ROTATION_MESSAGE_BYTES];
    message[..4].copy_from_slice(&magic);
    message[4..12].copy_from_slice(&epoch.get().to_be_bytes());
    message[12..].copy_from_slice(&transcript);
    timeout(CONTROL_IO_TIMEOUT, async {
        writer.write_all(&message).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?
    .map_err(|_| IngressRedirectError::TlsBootstrapFailed)
}

async fn read_rotation_message<R>(
    reader: &mut R,
    expected_magic: [u8; 4],
    expected_epoch: IngressRedirectProtectionEpoch,
    expected_transcript: [u8; 32],
) -> Result<(), IngressRedirectError>
where
    R: AsyncRead + Unpin,
{
    let mut message = [0_u8; ROTATION_MESSAGE_BYTES];
    timeout(CONTROL_IO_TIMEOUT, reader.read_exact(&mut message))
        .await
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?;
    if message[..4] != expected_magic
        || message[4..12] != expected_epoch.get().to_be_bytes()
        || message[12..] != expected_transcript
    {
        return Err(IngressRedirectError::TlsBootstrapFailed);
    }
    Ok(())
}

async fn write_reconciliation_state<W>(
    writer: &mut W,
    state: ReconciliationState,
    transcript: [u8; 32],
) -> Result<(), IngressRedirectError>
where
    W: AsyncWrite + Unpin,
{
    let mut message = [0_u8; RECONCILIATION_STATE_BYTES];
    message[..4].copy_from_slice(&RECONCILIATION_STATE_MAGIC);
    message[4..12].copy_from_slice(&state.current.get().to_be_bytes());
    message[12..20].copy_from_slice(
        &state
            .pending
            .map_or(0, IngressRedirectProtectionEpoch::get)
            .to_be_bytes(),
    );
    message[20..].copy_from_slice(&transcript);
    timeout(CONTROL_IO_TIMEOUT, async {
        writer.write_all(&message).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?
    .map_err(|_| IngressRedirectError::TlsBootstrapFailed)
}

async fn read_reconciliation_state<R>(
    reader: &mut R,
    transcript: [u8; 32],
) -> Result<ReconciliationState, IngressRedirectError>
where
    R: AsyncRead + Unpin,
{
    let mut message = [0_u8; RECONCILIATION_STATE_BYTES];
    timeout(CONTROL_IO_TIMEOUT, reader.read_exact(&mut message))
        .await
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?;
    if message[..4] != RECONCILIATION_STATE_MAGIC || message[20..] != transcript {
        return Err(IngressRedirectError::TlsBootstrapFailed);
    }
    let current = u64::from_be_bytes(
        message[4..12]
            .try_into()
            .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?,
    );
    let pending = u64::from_be_bytes(
        message[12..20]
            .try_into()
            .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?,
    );
    if current == 0 || pending == current {
        return Err(IngressRedirectError::TlsBootstrapFailed);
    }
    Ok(ReconciliationState {
        current: IngressRedirectProtectionEpoch(current),
        pending: (pending != 0).then_some(IngressRedirectProtectionEpoch(pending)),
    })
}

fn transcript_digest(
    client_nonce: &[u8; BOOTSTRAP_NONCE_BYTES],
    client_manifest: &[u8],
    server_nonce: &[u8; BOOTSTRAP_NONCE_BYTES],
    server_manifest: &[u8],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"opc-ipsec-lb/ingress-redirect/control-transcript/v1");
    digest.update(client_nonce);
    digest.update((client_manifest.len() as u64).to_be_bytes());
    digest.update(client_manifest);
    digest.update(server_nonce);
    digest.update((server_manifest.len() as u64).to_be_bytes());
    digest.update(server_manifest);
    digest.finalize().into()
}

fn validate_udp_endpoint(endpoint: SocketAddr) -> Result<(), IngressRedirectError> {
    if endpoint.port() == 0 || endpoint.ip().is_unspecified() || endpoint.ip().is_multicast() {
        return Err(IngressRedirectError::InvalidPeerManifest);
    }
    match endpoint {
        SocketAddr::V4(address) if address.ip().is_broadcast() => {
            Err(IngressRedirectError::InvalidPeerManifest)
        }
        SocketAddr::V6(address) if address.flowinfo() != 0 || address.scope_id() != 0 => {
            Err(IngressRedirectError::InvalidPeerManifest)
        }
        _ => Ok(()),
    }
}

fn encode_endpoint(
    endpoint: SocketAddr,
    encoded: &mut Vec<u8>,
) -> Result<(), IngressRedirectError> {
    validate_udp_endpoint(endpoint)?;
    match endpoint.ip() {
        IpAddr::V4(address) => {
            encoded.push(4);
            encoded.extend_from_slice(&[0_u8; 12]);
            encoded.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            encoded.push(6);
            encoded.extend_from_slice(&address.octets());
        }
    }
    encoded.extend_from_slice(&endpoint.port().to_be_bytes());
    Ok(())
}

fn decode_endpoint(cursor: &mut ManifestCursor<'_>) -> Result<SocketAddr, IngressRedirectError> {
    let family = cursor.read_u8()?;
    let address = cursor.read_array::<16>()?;
    let port = cursor.read_u16()?;
    let endpoint = match family {
        4 if address[..12].iter().all(|byte| *byte == 0) => SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                address[12],
                address[13],
                address[14],
                address[15],
            )),
            port,
        ),
        6 => SocketAddr::new(IpAddr::V6(Ipv6Addr::from(address)), port),
        _ => return Err(IngressRedirectError::InvalidPeerManifest),
    };
    validate_udp_endpoint(endpoint)?;
    Ok(endpoint)
}

fn copy_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], IngressRedirectError> {
    bytes
        .try_into()
        .map_err(|_| IngressRedirectError::TlsBootstrapFailed)
}

struct ManifestCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ManifestCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn read_slice(&mut self, length: usize) -> Result<&'a [u8], IngressRedirectError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(IngressRedirectError::InvalidPeerManifest)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(IngressRedirectError::InvalidPeerManifest)?;
        self.offset = end;
        Ok(value)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], IngressRedirectError> {
        self.read_slice(N)?
            .try_into()
            .map_err(|_| IngressRedirectError::InvalidPeerManifest)
    }

    fn read_u8(&mut self) -> Result<u8, IngressRedirectError> {
        self.read_array::<1>().map(|value| value[0])
    }

    fn read_u16(&mut self) -> Result<u16, IngressRedirectError> {
        self.read_array::<2>().map(u16::from_be_bytes)
    }

    fn read_u32(&mut self) -> Result<u32, IngressRedirectError> {
        self.read_array::<4>().map(u32::from_be_bytes)
    }

    fn read_u64(&mut self) -> Result<u64, IngressRedirectError> {
        self.read_array::<8>().map(u64::from_be_bytes)
    }
}

impl From<super::IngressRedirectConfigError> for IngressRedirectError {
    fn from(_: super::IngressRedirectConfigError) -> Self {
        Self::InvalidPeerManifest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    use zeroize::Zeroizing;

    fn spiffe(instance: &str) -> SpiffeId {
        SpiffeId::new(format!(
            "spiffe://example.test/tenant/acme/ns/core/sa/epdg/nf/epdg/instance/{instance}"
        ))
        .unwrap_or_else(|error| panic!("valid SPIFFE ID: {error}"))
    }

    fn profile() -> IngressRedirectProfile {
        IngressRedirectProfile::production(1_500)
            .unwrap_or_else(|error| panic!("valid profile: {error}"))
    }

    fn rotation_session() -> IngressRedirectPeerSession {
        IngressRedirectPeerSession::for_test(
            profile(),
            OwnerId::new("owner-a").unwrap_or_else(|error| panic!("valid owner: {error}")),
            OwnerId::new("owner-b").unwrap_or_else(|error| panic!("valid owner: {error}")),
            9,
            [0x11; 32],
            [0x22; 32],
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            super::super::sender_identity_digest("spiffe://example.test/a"),
            super::super::sender_identity_digest("spiffe://example.test/b"),
        )
    }

    fn rotation_bootstrap(
        session: &IngressRedirectPeerSession,
        epoch: u64,
    ) -> IngressRedirectBootstrap {
        IngressRedirectBootstrap {
            profile: session.profile,
            local_owner: session.local_owner.clone(),
            peer_owner: session.peer_owner.clone(),
            local_sender_digest: session.local_sender_digest,
            peer_sender_digest: session.peer_sender_digest,
            routing_domains: Arc::clone(&session.routing_domains),
            local_udp_endpoint: session.local_udp_endpoint,
            peer_udp_endpoint: session.peer_udp_endpoint,
            epoch: IngressRedirectProtectionEpoch(epoch),
            send_key: Zeroizing::new([0x33; 32]),
            receive_key: Zeroizing::new([0x44; 32]),
            send_nonce_prefix: [9, 10, 11, 12],
            receive_nonce_prefix: [13, 14, 15, 16],
            authentication_evidence: super::super::EpochAuthenticationEvidence::TestOnly,
            hard_authenticated_deadline: Instant::now()
                .checked_add(Duration::from_secs(60 * 60))
                .unwrap_or_else(|| panic!("valid hard deadline")),
        }
    }

    fn pending_guard(session: &IngressRedirectPeerSession, epoch: u64) -> PendingRotationGuard<'_> {
        let token = session
            .stage_rotation(rotation_bootstrap(session, epoch))
            .unwrap_or_else(|error| panic!("stage test rotation: {error}"));
        PendingRotationGuard::new(session, token)
    }

    fn expire_current_epoch(session: &IngressRedirectPeerSession) {
        let mut state = session
            .epochs
            .write()
            .unwrap_or_else(|error| panic!("epoch state: {error}"));
        let current =
            Arc::get_mut(&mut state.current).unwrap_or_else(|| panic!("unshared current epoch"));
        current.hard_authenticated_deadline = Instant::now();
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RecordedControlAction {
        Write([u8; 4]),
        Read([u8; 4]),
        Admit,
    }

    struct FakeRotationControl<'a> {
        next_action: usize,
        fail_at: Option<usize>,
        hang_at: Option<usize>,
        callback: Option<(usize, Box<dyn FnOnce() + Send + 'a>)>,
        recorded: Vec<RecordedControlAction>,
    }

    impl FakeRotationControl<'_> {
        fn succeeds() -> Self {
            Self {
                next_action: 0,
                fail_at: None,
                hang_at: None,
                callback: None,
                recorded: Vec::new(),
            }
        }

        fn fails_at(action: usize) -> Self {
            Self {
                fail_at: Some(action),
                ..Self::succeeds()
            }
        }

        fn hangs_at(action: usize) -> Self {
            Self {
                hang_at: Some(action),
                ..Self::succeeds()
            }
        }

        fn run_callback(&mut self, action: usize) {
            if self.callback.as_ref().is_some_and(|(at, _)| *at == action) {
                if let Some((_, callback)) = self.callback.take() {
                    callback();
                }
            }
        }

        async fn async_action(
            &mut self,
            recorded: RecordedControlAction,
        ) -> Result<(), IngressRedirectError> {
            let action = self.next_action;
            self.next_action = self.next_action.saturating_add(1);
            self.recorded.push(recorded);
            self.run_callback(action);
            if self.hang_at == Some(action) {
                return std::future::pending().await;
            }
            if self.fail_at == Some(action) {
                Err(IngressRedirectError::TlsBootstrapFailed)
            } else {
                Ok(())
            }
        }

        fn sync_action(
            &mut self,
            recorded: RecordedControlAction,
        ) -> Result<(), IngressRedirectError> {
            let action = self.next_action;
            self.next_action = self.next_action.saturating_add(1);
            self.recorded.push(recorded);
            self.run_callback(action);
            if self.fail_at == Some(action) || self.hang_at == Some(action) {
                Err(IngressRedirectError::TlsBootstrapFailed)
            } else {
                Ok(())
            }
        }
    }

    #[async_trait]
    impl RotationControl for FakeRotationControl<'_> {
        async fn write(
            &mut self,
            magic: [u8; 4],
            _epoch: IngressRedirectProtectionEpoch,
            _transcript: [u8; 32],
        ) -> Result<(), IngressRedirectError> {
            self.async_action(RecordedControlAction::Write(magic)).await
        }

        async fn read(
            &mut self,
            magic: [u8; 4],
            _epoch: IngressRedirectProtectionEpoch,
            _transcript: [u8; 32],
        ) -> Result<(), IngressRedirectError> {
            self.async_action(RecordedControlAction::Read(magic)).await
        }

        fn admit(&mut self) -> Result<(), IngressRedirectError> {
            self.sync_action(RecordedControlAction::Admit)
        }
    }

    #[test]
    fn public_control_futures_are_send() {
        fn assert_send<T: Send>(_: T) {}

        #[allow(clippy::too_many_arguments)]
        fn check<IO>(
            initial_client_io: IO,
            initial_server_io: IO,
            rotation_client_io: IO,
            rotation_server_io: IO,
            reconciliation_client_io: IO,
            reconciliation_server_io: IO,
            server_name: rustls::pki_types::ServerName<'static>,
            client_handshake: TlsClientHandshake,
            server_handshake: TlsServerHandshake,
            local: &IngressRedirectPeerManifest,
            expected_peer: &IngressRedirectPeerExpectation,
            session: &IngressRedirectPeerSession,
        ) where
            IO: AsyncRead + AsyncWrite + Unpin + Send,
        {
            assert_send(establish_ingress_redirect_client(
                initial_client_io,
                server_name.clone(),
                client_handshake.clone(),
                local,
                expected_peer,
            ));
            assert_send(establish_ingress_redirect_server(
                initial_server_io,
                server_handshake.clone(),
                local,
                expected_peer,
            ));
            assert_send(rotate_ingress_redirect_client(
                rotation_client_io,
                server_name.clone(),
                client_handshake.clone(),
                local,
                expected_peer,
                session,
            ));
            assert_send(rotate_ingress_redirect_server(
                rotation_server_io,
                server_handshake.clone(),
                local,
                expected_peer,
                session,
            ));
            assert_send(reconcile_ingress_redirect_client(
                reconciliation_client_io,
                server_name,
                client_handshake,
                local,
                expected_peer,
                session,
            ));
            assert_send(reconcile_ingress_redirect_server(
                reconciliation_server_io,
                server_handshake,
                local,
                expected_peer,
                session,
            ));
        }

        let _ = check::<tokio::io::DuplexStream>;
    }

    #[test]
    fn manifest_round_trip_is_canonical_and_redacted() {
        let manifest = IngressRedirectPeerManifest::new(
            spiffe("a"),
            OwnerId::new("owner-a").unwrap_or_else(|error| panic!("valid owner: {error}")),
            "192.0.2.10:7444"
                .parse()
                .unwrap_or_else(|error| panic!("valid endpoint: {error}")),
            profile(),
            [
                RoutingDomainTag::new(9),
                RoutingDomainTag::new(7),
                RoutingDomainTag::new(9),
            ],
        )
        .unwrap_or_else(|error| panic!("valid manifest: {error}"));
        assert_eq!(
            manifest.routing_domains(),
            &[RoutingDomainTag::new(7), RoutingDomainTag::new(9)]
        );
        let encoded = manifest
            .encode()
            .unwrap_or_else(|error| panic!("encode manifest: {error}"));
        let decoded = IngressRedirectPeerManifest::decode(&encoded)
            .unwrap_or_else(|error| panic!("decode manifest: {error}"));
        assert_eq!(decoded, manifest);
        let debug = format!("{manifest:?}");
        assert!(!debug.contains("owner-a"));
        assert!(!debug.contains("192.0.2.10"));
        assert!(!debug.contains("example.test"));
    }

    #[test]
    fn manifest_rejects_trailing_data_invalid_endpoint_and_profile() {
        let manifest = IngressRedirectPeerManifest::new(
            spiffe("a"),
            OwnerId::new("owner-a").unwrap_or_else(|error| panic!("valid owner: {error}")),
            "192.0.2.10:7444"
                .parse()
                .unwrap_or_else(|error| panic!("valid endpoint: {error}")),
            profile(),
            [RoutingDomainTag::new(7)],
        )
        .unwrap_or_else(|error| panic!("valid manifest: {error}"));
        let mut encoded = manifest
            .encode()
            .unwrap_or_else(|error| panic!("encode manifest: {error}"));
        encoded.push(0);
        assert_eq!(
            IngressRedirectPeerManifest::decode(&encoded),
            Err(IngressRedirectError::InvalidPeerManifest)
        );
        assert_eq!(
            IngressRedirectPeerExpectation::new(
                spiffe("b"),
                OwnerId::new("owner-b").unwrap_or_else(|error| panic!("valid owner: {error}")),
                "0.0.0.0:7444"
                    .parse()
                    .unwrap_or_else(|error| panic!("parse endpoint: {error}")),
            ),
            Err(IngressRedirectError::InvalidPeerManifest)
        );
        assert_eq!(
            profile().with_hop_limit(1),
            Err(super::super::IngressRedirectConfigError::InvalidHopLimit)
        );
    }

    #[test]
    fn transcript_role_derivation_is_directionally_symmetric() {
        let mut bytes = [0_u8; EXPORTER_BYTES];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::try_from(index + 1)
                .unwrap_or_else(|error| panic!("bounded test index: {error}"));
        }
        let client_directions = exporter_directions(Zeroizing::new(bytes), ExporterRole::Client)
            .unwrap_or_else(|error| panic!("client material: {error}"));
        let server_directions = exporter_directions(Zeroizing::new(bytes), ExporterRole::Server)
            .unwrap_or_else(|error| panic!("server material: {error}"));
        assert_eq!(
            client_directions.send_key.as_ref(),
            server_directions.receive_key.as_ref()
        );
        assert_eq!(
            client_directions.receive_key.as_ref(),
            server_directions.send_key.as_ref()
        );
        assert_eq!(client_directions.epoch, server_directions.epoch);
    }

    #[test]
    fn fresh_nonce_changes_the_exporter_context_for_identical_manifests() {
        let manifest = b"same manifest";
        let first = transcript_digest(&[1; 32], manifest, &[2; 32], manifest);
        let second = transcript_digest(&[3; 32], manifest, &[2; 32], manifest);
        assert_ne!(first, second);
    }

    #[test]
    fn reconciliation_target_handles_split_and_asymmetric_pending_state() {
        let old = IngressRedirectProtectionEpoch(9);
        let new = IngressRedirectProtectionEpoch(10);
        assert_eq!(
            reconciliation_target(
                ReconciliationState {
                    current: new,
                    pending: None,
                },
                ReconciliationState {
                    current: old,
                    pending: Some(new),
                },
            ),
            Ok(new)
        );
        assert_eq!(
            reconciliation_target(
                ReconciliationState {
                    current: old,
                    pending: Some(new),
                },
                ReconciliationState {
                    current: old,
                    pending: Some(new),
                },
            ),
            Ok(new)
        );
        assert_eq!(
            reconciliation_target(
                ReconciliationState {
                    current: old,
                    pending: Some(new),
                },
                ReconciliationState {
                    current: old,
                    pending: None,
                },
            ),
            Ok(old)
        );
        assert_eq!(
            reconciliation_target(
                ReconciliationState {
                    current: old,
                    pending: Some(IngressRedirectProtectionEpoch(11)),
                },
                ReconciliationState {
                    current: old,
                    pending: Some(new),
                },
            ),
            Ok(old)
        );
    }

    #[tokio::test]
    async fn initial_install_maps_every_ack_boundary_to_unknown_outcome() {
        for fail_at in 0..3 {
            let session = rotation_session();
            let epoch = session
                .rotation_status()
                .unwrap_or_else(|error| panic!("initial status: {error}"))
                .current();
            let mut control = FakeRotationControl::fails_at(fail_at);
            assert!(
                matches!(
                    complete_initial_client(&mut control, session, epoch, [0x55; 32]).await,
                    Err(IngressRedirectError::InitialOutcomeUnknown)
                ),
                "client action {fail_at}"
            );

            let session = rotation_session();
            let epoch = session
                .rotation_status()
                .unwrap_or_else(|error| panic!("initial status: {error}"))
                .current();
            let mut control = FakeRotationControl::fails_at(fail_at);
            assert!(
                matches!(
                    complete_initial_server(&mut control, session, epoch, [0x55; 32]).await,
                    Err(IngressRedirectError::InitialOutcomeUnknown)
                ),
                "server action {fail_at}"
            );
        }
    }

    #[tokio::test]
    async fn initial_install_retires_session_that_expires_before_final_admission() {
        for client in [true, false] {
            let mut session = rotation_session();
            let epoch = session
                .rotation_status()
                .unwrap_or_else(|error| panic!("initial status: {error}"))
                .current();
            let state = session
                .epochs
                .get_mut()
                .unwrap_or_else(|_| panic!("epoch state"));
            let current = Arc::get_mut(&mut state.current)
                .unwrap_or_else(|| panic!("unshared current epoch"));
            current.hard_authenticated_deadline = Instant::now();
            let mut control = FakeRotationControl::succeeds();
            let result = if client {
                complete_initial_client(&mut control, session, epoch, [0x58; 32]).await
            } else {
                complete_initial_server(&mut control, session, epoch, [0x59; 32]).await
            };
            assert!(matches!(
                result,
                Err(IngressRedirectError::InitialOutcomeUnknown)
            ));
        }
    }

    #[tokio::test]
    async fn initial_install_cancellation_retires_unreturned_session_at_every_async_boundary() {
        for hang_at in 0..2 {
            let session = rotation_session();
            let retirement_witness = Arc::downgrade(&session.metrics);
            let epoch = session
                .rotation_status()
                .unwrap_or_else(|error| panic!("initial status: {error}"))
                .current();
            let mut control = FakeRotationControl::hangs_at(hang_at);
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(1),
                    complete_initial_client(&mut control, session, epoch, [0x56; 32]),
                )
                .await
                .is_err(),
                "client action {hang_at}"
            );
            assert!(
                retirement_witness.upgrade().is_none(),
                "client action {hang_at} retained an outcome-unknown session"
            );

            let session = rotation_session();
            let retirement_witness = Arc::downgrade(&session.metrics);
            let epoch = session
                .rotation_status()
                .unwrap_or_else(|error| panic!("initial status: {error}"))
                .current();
            let mut control = FakeRotationControl::hangs_at(hang_at);
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(1),
                    complete_initial_server(&mut control, session, epoch, [0x57; 32]),
                )
                .await
                .is_err(),
                "server action {hang_at}"
            );
            assert!(
                retirement_witness.upgrade().is_none(),
                "server action {hang_at} retained an outcome-unknown session"
            );
        }
    }

    #[tokio::test]
    async fn client_rotation_failure_at_every_boundary_retains_reconcilable_state() {
        for fail_at in 0..6 {
            let session = rotation_session();
            let old = session
                .rotation_status()
                .unwrap_or_else(|error| panic!("old status: {error}"))
                .current();
            let guard = pending_guard(&session, 10);
            let mut control = FakeRotationControl::fails_at(fail_at);
            assert_eq!(
                complete_rotation_client(&mut control, &session, guard, [0x66; 32]).await,
                Err(IngressRedirectError::RotationOutcomeUnknown),
                "client action {fail_at}"
            );
            let status = session
                .rotation_status()
                .unwrap_or_else(|error| panic!("post-failure status: {error}"));
            if fail_at <= 2 {
                assert_eq!(status.current(), old, "client action {fail_at}");
                assert_eq!(
                    status.pending_receive(),
                    Some(IngressRedirectProtectionEpoch(10)),
                    "client action {fail_at}"
                );
            } else {
                assert_eq!(
                    status.current(),
                    IngressRedirectProtectionEpoch(10),
                    "client action {fail_at}"
                );
                assert_eq!(status.pending_receive(), None, "client action {fail_at}");
            }
        }
    }

    #[tokio::test]
    async fn server_rotation_failure_at_every_boundary_retains_reconcilable_state() {
        for fail_at in 0..7 {
            let session = rotation_session();
            let old = session
                .rotation_status()
                .unwrap_or_else(|error| panic!("old status: {error}"))
                .current();
            let guard = pending_guard(&session, 10);
            let mut control = FakeRotationControl::fails_at(fail_at);
            assert_eq!(
                complete_rotation_server(&mut control, &session, guard, [0x77; 32]).await,
                Err(IngressRedirectError::RotationOutcomeUnknown),
                "server action {fail_at}"
            );
            let status = session
                .rotation_status()
                .unwrap_or_else(|error| panic!("post-failure status: {error}"));
            if fail_at <= 4 {
                assert_eq!(status.current(), old, "server action {fail_at}");
                assert_eq!(
                    status.pending_receive(),
                    Some(IngressRedirectProtectionEpoch(10)),
                    "server action {fail_at}"
                );
            } else {
                assert_eq!(
                    status.current(),
                    IngressRedirectProtectionEpoch(10),
                    "server action {fail_at}"
                );
                assert_eq!(status.pending_receive(), None, "server action {fail_at}");
            }
        }
    }

    #[tokio::test]
    async fn rotation_cancellation_before_and_after_activation_preserves_readback() {
        for (hang_at, activated) in [(0, false), (3, true)] {
            let session = rotation_session();
            let guard = pending_guard(&session, 10);
            let mut control = FakeRotationControl::hangs_at(hang_at);
            assert!(tokio::time::timeout(
                Duration::from_millis(1),
                complete_rotation_client(&mut control, &session, guard, [0x88; 32]),
            )
            .await
            .is_err());
            let status = session
                .rotation_status()
                .unwrap_or_else(|error| panic!("client cancel status: {error}"));
            if activated {
                assert_eq!(status.current(), IngressRedirectProtectionEpoch(10));
                assert_eq!(status.pending_receive(), None);
            } else {
                assert_eq!(status.current(), IngressRedirectProtectionEpoch(9));
                assert_eq!(
                    status.pending_receive(),
                    Some(IngressRedirectProtectionEpoch(10))
                );
            }
        }

        for (hang_at, activated) in [(0, false), (5, true)] {
            let session = rotation_session();
            let guard = pending_guard(&session, 10);
            let mut control = FakeRotationControl::hangs_at(hang_at);
            assert!(tokio::time::timeout(
                Duration::from_millis(1),
                complete_rotation_server(&mut control, &session, guard, [0x99; 32]),
            )
            .await
            .is_err());
            let status = session
                .rotation_status()
                .unwrap_or_else(|error| panic!("server cancel status: {error}"));
            if activated {
                assert_eq!(status.current(), IngressRedirectProtectionEpoch(10));
                assert_eq!(status.pending_receive(), None);
            } else {
                assert_eq!(status.current(), IngressRedirectProtectionEpoch(9));
                assert_eq!(
                    status.pending_receive(),
                    Some(IngressRedirectProtectionEpoch(10))
                );
            }
        }
    }

    #[tokio::test]
    async fn activation_state_failure_is_always_an_ambiguous_rotation_outcome() {
        let client = rotation_session();
        let client_guard = pending_guard(&client, 10);
        let mut client_control = FakeRotationControl::succeeds();
        client_control.callback = Some((
            2,
            Box::new(|| {
                client
                    .epochs
                    .write()
                    .unwrap_or_else(|error| panic!("client epoch state: {error}"))
                    .pending = None;
            }),
        ));
        assert_eq!(
            complete_rotation_client(&mut client_control, &client, client_guard, [0xa1; 32],).await,
            Err(IngressRedirectError::RotationOutcomeUnknown)
        );

        let server = rotation_session();
        let server_guard = pending_guard(&server, 10);
        let mut server_control = FakeRotationControl::succeeds();
        server_control.callback = Some((
            4,
            Box::new(|| {
                server
                    .epochs
                    .write()
                    .unwrap_or_else(|error| panic!("server epoch state: {error}"))
                    .pending = None;
            }),
        ));
        assert_eq!(
            complete_rotation_server(&mut server_control, &server, server_guard, [0xa2; 32],).await,
            Err(IngressRedirectError::RotationOutcomeUnknown)
        );
    }

    #[tokio::test]
    async fn every_rotation_and_reconciliation_path_rechecks_activated_epoch_expiry() {
        let rotation_client = rotation_session();
        let guard = pending_guard(&rotation_client, 10);
        let mut control = FakeRotationControl::succeeds();
        control.callback = Some((5, Box::new(|| expire_current_epoch(&rotation_client))));
        assert_eq!(
            complete_rotation_client(&mut control, &rotation_client, guard, [0xc1; 32]).await,
            Err(IngressRedirectError::RotationOutcomeUnknown)
        );

        let rotation_server = rotation_session();
        let guard = pending_guard(&rotation_server, 10);
        let mut control = FakeRotationControl::succeeds();
        control.callback = Some((6, Box::new(|| expire_current_epoch(&rotation_server))));
        assert_eq!(
            complete_rotation_server(&mut control, &rotation_server, guard, [0xc2; 32]).await,
            Err(IngressRedirectError::RotationOutcomeUnknown)
        );

        let reconciliation_client = rotation_session();
        pending_guard(&reconciliation_client, 10)
            .retain_pending()
            .unwrap_or_else(|error| panic!("retain client pending: {error}"));
        let mut control = FakeRotationControl::succeeds();
        control.callback = Some((5, Box::new(|| expire_current_epoch(&reconciliation_client))));
        assert_eq!(
            complete_reconciliation_client(
                &mut control,
                &reconciliation_client,
                IngressRedirectProtectionEpoch(10),
                [0xc3; 32],
            )
            .await,
            Err(IngressRedirectError::RotationOutcomeUnknown)
        );

        let reconciliation_server = rotation_session();
        pending_guard(&reconciliation_server, 10)
            .retain_pending()
            .unwrap_or_else(|error| panic!("retain server pending: {error}"));
        let mut control = FakeRotationControl::succeeds();
        control.callback = Some((5, Box::new(|| expire_current_epoch(&reconciliation_server))));
        assert_eq!(
            complete_reconciliation_server(
                &mut control,
                &reconciliation_server,
                IngressRedirectProtectionEpoch(10),
                [0xc4; 32],
            )
            .await,
            Err(IngressRedirectError::RotationOutcomeUnknown)
        );
    }

    #[tokio::test]
    async fn post_activation_reconciliation_expiry_maps_to_outcome_unknown() {
        for server in [false, true] {
            let session = rotation_session();
            pending_guard(&session, 10)
                .retain_pending()
                .unwrap_or_else(|error| panic!("retain pending: {error}"));
            let activation_now = Instant::now();
            let completion_now = activation_now
                .checked_add(Duration::from_secs(2 * 60 * 60))
                .unwrap_or_else(|| panic!("valid completion time"));
            let mut control = FakeRotationControl::succeeds();
            let reconcile = |session: &IngressRedirectPeerSession,
                             target: IngressRedirectProtectionEpoch| {
                session.reconcile_authenticated_epoch_at(target, activation_now, || completion_now)
            };
            let result = if server {
                complete_reconciliation_server_with(
                    &mut control,
                    &session,
                    IngressRedirectProtectionEpoch(10),
                    [0xd1; 32],
                    reconcile,
                )
                .await
            } else {
                complete_reconciliation_client_with(
                    &mut control,
                    &session,
                    IngressRedirectProtectionEpoch(10),
                    [0xd2; 32],
                    reconcile,
                )
                .await
            };
            assert_eq!(
                result,
                Err(IngressRedirectError::RotationOutcomeUnknown),
                "server={server}"
            );
            assert_eq!(
                session
                    .rotation_status()
                    .unwrap_or_else(|error| panic!("rotation status: {error}"))
                    .current(),
                IngressRedirectProtectionEpoch(10),
                "server={server}"
            );
        }
    }

    #[tokio::test]
    async fn successful_rotation_uses_exact_logical_message_order() {
        let client = rotation_session();
        let guard = pending_guard(&client, 10);
        let mut client_control = FakeRotationControl::succeeds();
        assert_eq!(
            complete_rotation_client(&mut client_control, &client, guard, [0xaa; 32]).await,
            Ok(IngressRedirectProtectionEpoch(10))
        );
        assert_eq!(
            client_control.recorded,
            vec![
                RecordedControlAction::Write(ROTATION_STAGED_MAGIC),
                RecordedControlAction::Read(ROTATION_STAGED_ACK_MAGIC),
                RecordedControlAction::Admit,
                RecordedControlAction::Write(ROTATION_ACTIVATED_MAGIC),
                RecordedControlAction::Read(ROTATION_FINAL_MAGIC),
                RecordedControlAction::Admit,
            ]
        );

        let server = rotation_session();
        let guard = pending_guard(&server, 10);
        let mut server_control = FakeRotationControl::succeeds();
        assert_eq!(
            complete_rotation_server(&mut server_control, &server, guard, [0xbb; 32]).await,
            Ok(IngressRedirectProtectionEpoch(10))
        );
        assert_eq!(
            server_control.recorded,
            vec![
                RecordedControlAction::Read(ROTATION_STAGED_MAGIC),
                RecordedControlAction::Admit,
                RecordedControlAction::Write(ROTATION_STAGED_ACK_MAGIC),
                RecordedControlAction::Read(ROTATION_ACTIVATED_MAGIC),
                RecordedControlAction::Admit,
                RecordedControlAction::Write(ROTATION_FINAL_MAGIC),
                RecordedControlAction::Admit,
            ]
        );
    }
}
