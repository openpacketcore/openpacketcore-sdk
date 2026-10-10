//! Connection-owned RFC026 TLS exporters. No raw exporter input is authority.

use crate::{
    peer_tls_identity, presented_certificate_chain_validity, CertificateValidity, PeerTlsIdentity,
    TlsClientHandshake, TlsServerHandshake,
};
use opc_types::{SpiffeId, Timestamp};
use sha2::{Digest, Sha256};
use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const ALPN: &[u8] = b"opc-scope/1";
const LABEL: &[u8] = b"EXPERIMENTAL-openpacketcore-channel-binding-v1";
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);

/// A trusted clock's complete authentication uncertainty interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticationTimeInterval {
    earliest: Timestamp,
    latest: Timestamp,
}

impl AuthenticationTimeInterval {
    /// Reject reversed/unknown time bounds; time never grants scope ownership.
    pub fn new(earliest: Timestamp, latest: Timestamp) -> Result<Self, ScopeTlsError> {
        if earliest > latest {
            return Err(ScopeTlsError::AuthTimeUnavailable);
        }
        Ok(Self { earliest, latest })
    }

    /// Check the whole interval, including both endpoints.
    pub fn is_within(self, not_before: Timestamp, not_after: Timestamp) -> bool {
        self.earliest >= not_before && self.latest <= not_after
    }
}

/// One locally configured installation and scope, fixed for a connection.
#[derive(Clone)]
pub struct ChannelBindingDomain {
    installation: [u8; 32],
    scope: Vec<u8>,
}

impl ChannelBindingDomain {
    /// Validate the exact RFC026 scope encoding and installation prefix.
    pub fn new(installation: [u8; 32], scope: Vec<u8>) -> Result<Self, ScopeTlsError> {
        let invalid = || ScopeTlsError::InvalidDomain;
        if scope.len() > 260 || scope.get(..32) != Some(installation.as_slice()) {
            return Err(invalid());
        }
        let mut rest = &scope[32..];
        for limit in [128, 64] {
            let length = u16::from_be_bytes(
                rest.get(..2)
                    .ok_or_else(invalid)?
                    .try_into()
                    .map_err(|_| invalid())?,
            ) as usize;
            rest = &rest[2..];
            if length == 0 || length > limit {
                return Err(invalid());
            }
            let value = std::str::from_utf8(rest.get(..length).ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
            if value.chars().any(char::is_control) {
                return Err(invalid());
            }
            rest = &rest[length..];
        }
        if rest.len() != 32 || rest.iter().all(|&byte| byte == 0) {
            return Err(invalid());
        }
        Ok(Self {
            installation,
            scope,
        })
    }

    /// Canonical exporter context bytes; their SHA-256 is passed to TLS.
    pub fn context_bytes(
        &self,
        purpose: ChannelBindingPurpose,
        client: &SpiffeId,
        server: &SpiffeId,
    ) -> Result<Vec<u8>, ScopeTlsError> {
        if client.as_str().len() > 2048 || server.as_str().len() > 2048 {
            return Err(ScopeTlsError::InvalidDomain);
        }
        let mut result = Vec::new();
        for field in [
            ALPN,
            purpose.name(),
            client.as_str().as_bytes(),
            server.as_str().as_bytes(),
            &self.installation,
            &self.scope,
        ] {
            // Both identities and the scope were bounded before writing lengths.
            let length = u16::try_from(field.len()).map_err(|_| ScopeTlsError::InvalidDomain)?;
            result.extend_from_slice(&length.to_be_bytes());
            result.extend_from_slice(field);
        }
        Ok(result)
    }

    /// Exact transport scope bytes fixed on this connection.
    pub fn scope_bytes(&self) -> &[u8] {
        &self.scope
    }

    /// Installation identity fixed on this connection.
    pub const fn installation(&self) -> &[u8; 32] {
        &self.installation
    }
}

impl fmt::Debug for ChannelBindingDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChannelBindingDomain([redacted])")
    }
}

/// RFC026 scope purposes; voter management is a separate transport profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelBindingPurpose {
    /// Client's scope request proof.
    ScopeRequest,
    /// Server's correlated scope result.
    ScopeResponse,
    /// Worker's startup liveness proof.
    BootLiveness,
    /// Worker's startup exclusion-guard proof.
    BootCandidate,
}

impl ChannelBindingPurpose {
    const ALL: [Self; 4] = [
        Self::ScopeRequest,
        Self::ScopeResponse,
        Self::BootLiveness,
        Self::BootCandidate,
    ];

    const fn name(self) -> &'static [u8] {
        match self {
            Self::ScopeRequest => b"scope-request",
            Self::ScopeResponse => b"scope-response",
            Self::BootLiveness => b"boot-liveness",
            Self::BootCandidate => b"boot-candidate",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::ScopeRequest => 0,
            Self::ScopeResponse => 1,
            Self::BootLiveness => 2,
            Self::BootCandidate => 3,
        }
    }
}

/// A regular TLS 1.3 exporter derived by the connection itself.
pub struct TlsChannelBinding([u8; 32]);

impl TlsChannelBinding {
    /// Bytes for the fixed protocol's signed input, never a construction API.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for TlsChannelBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TlsChannelBinding([redacted])")
    }
}

/// Authentication failure. These refusals do not close or supersede execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ScopeTlsError {
    /// Invalid scope or installation context.
    #[error("invalid channel binding domain")]
    InvalidDomain,
    /// TLS did not complete under the prescribed profile.
    #[error("scope TLS handshake failed")]
    HandshakeFailed,
    /// The completed connection has the wrong protocol or ALPN.
    #[error("scope TLS protocol mismatch")]
    ProtocolMismatch,
    /// The connection's local material is no longer current.
    #[error("scope TLS material changed")]
    MaterialChanged,
    /// The complete trusted time interval is not inside certificate validity.
    #[error("authentication time unavailable")]
    AuthTimeUnavailable,
    /// A peer identity could not be obtained from the completed connection.
    #[error("scope TLS peer identity unavailable")]
    PeerIdentityUnavailable,
    /// The regular TLS exporter could not be produced.
    #[error("scope TLS exporter unavailable")]
    ExporterUnavailable,
}

#[derive(Clone)]
enum Material {
    Client(TlsClientHandshake),
    Server(TlsServerHandshake),
}

impl Material {
    fn admit(&self) -> Result<(), ScopeTlsError> {
        match self {
            Self::Client(handshake) => handshake.admit(),
            Self::Server(handshake) => handshake.admit(),
        }
        .map(|_| ())
        .map_err(|_| ScopeTlsError::MaterialChanged)
    }

    fn snapshot(&self) -> &crate::material::TlsMaterialSnapshot {
        match self {
            Self::Client(handshake) => handshake.scope_snapshot(),
            Self::Server(handshake) => handshake.scope_snapshot(),
        }
    }
}

/// TLS stream whose snapshot, identities, scope and exporters cannot be replaced.
///
/// Construct through [`TlsClientHandshake::connect_scope`] or
/// [`TlsServerHandshake::accept_scope`]. There is intentionally no constructor
/// from a raw rustls connection or a caller-provided exporter.
pub struct ScopeTlsConnection<S> {
    stream: tokio_rustls::TlsStream<S>,
    peer: PeerTlsIdentity,
    local_validity: CertificateValidity,
    material: Material,
    domain: ChannelBindingDomain,
    bindings: [TlsChannelBinding; 4],
}

impl<S: AsyncRead + AsyncWrite + Unpin> ScopeTlsConnection<S> {
    fn admit(
        stream: tokio_rustls::TlsStream<S>,
        material: Material,
        domain: ChannelBindingDomain,
    ) -> Result<Self, ScopeTlsError> {
        UnboundScopeTlsConnection::admit(stream, material)?.bind_scope(domain)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> UnboundScopeTlsConnection<S> {
    fn admit(
        stream: tokio_rustls::TlsStream<S>,
        material: Material,
    ) -> Result<Self, ScopeTlsError> {
        material.admit()?;
        let (_, connection) = stream.get_ref();
        if connection.is_handshaking() {
            return Err(ScopeTlsError::HandshakeFailed);
        }
        if connection.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
            || connection.alpn_protocol() != Some(ALPN)
        {
            return Err(ScopeTlsError::ProtocolMismatch);
        }
        let peer = peer_tls_identity(false, connection.peer_certificates())
            .map_err(|_| ScopeTlsError::PeerIdentityUnavailable)?;
        let local_validity =
            presented_certificate_chain_validity(&material.snapshot().state.svid.cert_chain)
                .map_err(|_| ScopeTlsError::AuthTimeUnavailable)?;
        Ok(Self {
            stream,
            material,
            peer,
            local_validity,
        })
    }
    /// Consume the unbound stream, permanently fixing its scope and exporters.
    pub fn bind_scope(
        self,
        domain: ChannelBindingDomain,
    ) -> Result<ScopeTlsConnection<S>, ScopeTlsError> {
        let Self {
            stream,
            material,
            peer,
            local_validity,
        } = self;
        material.admit()?;
        let local = &material.snapshot().state.identity.spiffe_id;
        let (client, server) = match material {
            Material::Client(_) => (local, peer.spiffe_id()),
            Material::Server(_) => (peer.spiffe_id(), local),
        };
        let mut bindings = std::array::from_fn(|_| TlsChannelBinding([0; 32]));
        for purpose in ChannelBindingPurpose::ALL {
            let context = Sha256::digest(domain.context_bytes(purpose, client, server)?);
            let output = &mut bindings[purpose.index()].0;
            match &stream {
                tokio_rustls::TlsStream::Client(stream) => stream
                    .get_ref()
                    .1
                    .export_keying_material(output, LABEL, Some(&context)),
                tokio_rustls::TlsStream::Server(stream) => stream
                    .get_ref()
                    .1
                    .export_keying_material(output, LABEL, Some(&context)),
            }
            .map_err(|_| ScopeTlsError::ExporterUnavailable)?;
        }
        // A reload racing exporter construction must not publish old bindings.
        material.admit()?;
        Ok(ScopeTlsConnection {
            stream,
            peer,
            local_validity,
            material,
            domain,
            bindings,
        })
    }
}

impl<S> ScopeTlsConnection<S> {
    /// The local identity actually presented on this exact stream.
    pub fn local_identity(&self) -> &SpiffeId {
        &self.material.snapshot().state.identity.spiffe_id
    }
    /// Retain only the connection's authentication checks across an awaited
    /// service call. This is not proof of possession or committed authority.
    pub fn authentication_state(
        &self,
        time: AuthenticationTimeInterval,
    ) -> Result<ScopeTlsAuthentication, ScopeTlsError> {
        let state = ScopeTlsAuthentication {
            material: self.material.clone(),
            local_validity: self.local_validity,
            peer_validity: CertificateValidity {
                not_before: self.peer.certificate_chain_valid_from(),
                not_after: self.peer.certificate_chain_expires_at(),
            },
        };
        state.revalidate(time)?;
        Ok(state)
    }
    /// The peer authenticated on this exact stream.
    pub const fn peer_identity(&self) -> &PeerTlsIdentity {
        &self.peer
    }

    /// The scope configured locally before this connection began.
    pub const fn domain(&self) -> &ChannelBindingDomain {
        &self.domain
    }

    /// Obtain the purpose binding after rechecking material and interval admission.
    pub fn channel_binding(
        &self,
        purpose: ChannelBindingPurpose,
        time: AuthenticationTimeInterval,
    ) -> Result<&TlsChannelBinding, ScopeTlsError> {
        self.material.admit()?;
        if !time.is_within(
            self.local_validity.not_before,
            self.local_validity.not_after,
        ) || !time.is_within(
            self.peer.certificate_chain_valid_from(),
            self.peer.certificate_chain_expires_at(),
        ) {
            return Err(ScopeTlsError::AuthTimeUnavailable);
        }
        Ok(&self.bindings[purpose.index()])
    }
}

/// Authentication state captured only from an owned, admitted scope connection.
/// It rechecks material publication and both whole-chain validity intervals;
/// retaining it does not retain the stream or authorize any application call.
#[derive(Clone)]
pub struct ScopeTlsAuthentication {
    material: Material,
    local_validity: CertificateValidity,
    peer_validity: CertificateValidity,
}
impl ScopeTlsAuthentication {
    /// Recheck authentication immediately before and after awaited verification.
    pub fn revalidate(&self, time: AuthenticationTimeInterval) -> Result<(), ScopeTlsError> {
        self.material.admit()?;
        if !time.is_within(
            self.local_validity.not_before,
            self.local_validity.not_after,
        ) || !time.is_within(self.peer_validity.not_before, self.peer_validity.not_after)
        {
            return Err(ScopeTlsError::AuthTimeUnavailable);
        }
        Ok(())
    }
}
impl fmt::Debug for ScopeTlsAuthentication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeTlsAuthentication([redacted])")
    }
}

impl<S> fmt::Debug for ScopeTlsConnection<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeTlsConnection([redacted])")
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ScopeTlsConnection<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ScopeTlsConnection<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl TlsClientHandshake {
    /// Complete TLS with the scope ALPN and own the resulting TLS 1.3 connection.
    /// Capacity waits apply backpressure; the active handshake has a five-second deadline.
    pub async fn connect_scope<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: S,
        domain: ChannelBindingDomain,
    ) -> Result<ScopeTlsConnection<S>, ScopeTlsError> {
        self.validate_scope_profile()?;
        let _permit = self
            .scope_handshake_permit()
            .await
            .map_err(|_| ScopeTlsError::MaterialChanged)?;
        tokio::time::timeout(HANDSHAKE_DEADLINE, async {
            self.admit().map_err(|_| ScopeTlsError::MaterialChanged)?;
            let mut config = (*self.rustls_config()).clone();
            config.alpn_protocols = vec![ALPN.to_vec()];
            config.enable_early_data = false;
            config.resumption = rustls::client::Resumption::disabled();
            // SPIFFE peer policy authenticates the endpoint; DNS is not identity.
            let name = rustls_pki_types::ServerName::try_from("scope.invalid")
                .map_err(|_| ScopeTlsError::HandshakeFailed)?;
            let stream = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
                .connect(name, io)
                .await
                .map_err(|_| ScopeTlsError::HandshakeFailed)?;
            ScopeTlsConnection::admit(stream.into(), Material::Client(self.clone()), domain)
        })
        .await
        .map_err(|_| ScopeTlsError::HandshakeFailed)?
    }
}

impl TlsServerHandshake {
    /// Complete mutual TLS, permanently fixing the local scope.
    pub async fn accept_scope<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: S,
        domain: ChannelBindingDomain,
    ) -> Result<ScopeTlsConnection<S>, ScopeTlsError> {
        self.accept_scope_unbound(io).await?.bind_scope(domain)
    }
    /// Authenticate before selecting scope from a bounded application header.
    /// Capacity waits apply backpressure; the active handshake has a five-second deadline.
    pub async fn accept_scope_unbound<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: S,
    ) -> Result<UnboundScopeTlsConnection<S>, ScopeTlsError> {
        self.validate_scope_profile()?;
        let _permit = self
            .scope_handshake_permit()
            .await
            .map_err(|_| ScopeTlsError::MaterialChanged)?;
        tokio::time::timeout(HANDSHAKE_DEADLINE, async {
            self.admit().map_err(|_| ScopeTlsError::MaterialChanged)?;
            let mut config = (*self.rustls_config()).clone();
            config.alpn_protocols = vec![ALPN.to_vec()];
            config.max_early_data_size = 0;
            config.send_tls13_tickets = 0;
            config.session_storage = std::sync::Arc::new(rustls::server::NoServerSessionStorage {});
            let stream = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config))
                .accept(io)
                .await
                .map_err(|_| ScopeTlsError::HandshakeFailed)?;
            UnboundScopeTlsConnection::admit(stream.into(), Material::Server(self.clone()))
        })
        .await
        .map_err(|_| ScopeTlsError::HandshakeFailed)?
    }
}

/// Authenticated TLS stream awaiting one locally checked scope routing decision.
pub struct UnboundScopeTlsConnection<S> {
    stream: tokio_rustls::TlsStream<S>,
    peer: PeerTlsIdentity,
    local_validity: CertificateValidity,
    material: Material,
}
impl<S> UnboundScopeTlsConnection<S> {
    /// Identity authenticated by this stream's immutable material snapshot.
    pub const fn peer_identity(&self) -> &PeerTlsIdentity {
        &self.peer
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for UnboundScopeTlsConnection<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl crate::AuthenticatedClientConfig {
    /// Reject transport profiles inappropriate for scope endpoints before I/O.
    pub fn validate_scope_profile(&self) -> Result<(), ScopeTlsError> {
        if self.compat_mode
            || self.allow_unconstrained_peer_policy
            || self.policy.is_unconstrained()
        {
            return Err(ScopeTlsError::ProtocolMismatch);
        }
        Ok(())
    }
}
impl crate::AuthenticatedServerConfig {
    /// Reject transport profiles inappropriate for scope endpoints before I/O.
    pub fn validate_scope_profile(&self) -> Result<(), ScopeTlsError> {
        if self.compat_mode
            || self.allow_unconstrained_peer_policy
            || self.policy.is_unconstrained()
        {
            return Err(ScopeTlsError::ProtocolMismatch);
        }
        Ok(())
    }
}
