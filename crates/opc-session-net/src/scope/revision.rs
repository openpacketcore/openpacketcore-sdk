//! Local revision diagnostics. No diagnostic state participates in admission.
use super::{
    rpc::ScopeRpcError,
    startup::StartupError,
    wire::{Header, Method, WireError, HEADER_BYTES},
};
use opc_tls::{ScopeTlsAuthentication, ScopeTlsError};
use std::{
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};

/// Counter exported by the SDK metrics registry with fixed role, purpose and
/// direction labels. The diagnostic snapshots retain authentication and recovery state.
pub const SCOPE_TRANSPORT_REVISION_MISMATCH_COUNTER: &str =
    "scope_transport_revision_mismatch_total";

/// Local endpoint role, never a claimed peer identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeTransportRole {
    /// Process-bound worker client.
    Worker,
    /// Read-only observer or controller client.
    Observer,
    /// Durable quorum RPC server.
    Quorum,
    /// Bootstrap proof issuer client.
    Issuer,
    /// Bootstrap proof responder.
    Responder,
}
impl ScopeTransportRole {
    const ALL: [Self; 5] = [
        Self::Worker,
        Self::Observer,
        Self::Quorum,
        Self::Issuer,
        Self::Responder,
    ];
    const fn label(self) -> &'static str {
        match self {
            Self::Worker => "worker",
            Self::Observer => "observer",
            Self::Quorum => "quorum",
            Self::Issuer => "issuer",
            Self::Responder => "responder",
        }
    }
}

/// Bounded purpose of the refused handshake or authenticated frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeTransportPurpose {
    /// No application purpose was authenticated during ALPN negotiation.
    Handshake,
    /// Incoming scope call or possession proof.
    ScopeRequest,
    /// Incoming scope challenge or result.
    ScopeResponse,
    /// Startup liveness call or proof.
    BootLiveness,
    /// Startup candidate call, proof or retained ticket notice.
    BootCandidate,
}
impl ScopeTransportPurpose {
    const ALL: [Self; 5] = [
        Self::Handshake,
        Self::ScopeRequest,
        Self::ScopeResponse,
        Self::BootLiveness,
        Self::BootCandidate,
    ];
    const fn label(self) -> &'static str {
        match self {
            Self::Handshake => "handshake",
            Self::ScopeRequest => "scope-request",
            Self::ScopeResponse => "scope-response",
            Self::BootLiveness => "boot-liveness",
            Self::BootCandidate => "boot-candidate",
        }
    }
}

/// Whether the local endpoint accepted or initiated the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeTransportDirection {
    /// Local endpoint accepted the connection.
    Inbound,
    /// Local endpoint initiated the connection.
    Outbound,
}
impl ScopeTransportDirection {
    const ALL: [Self; 2] = [Self::Inbound, Self::Outbound];
    const fn label(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

/// One process-wide counter bucket. No peer or request values are retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopeTransportRevisionDiagnostic {
    /// Local endpoint role.
    pub role: ScopeTransportRole,
    /// Handshake or application purpose.
    pub purpose: ScopeTransportPurpose,
    /// Connection direction from the local endpoint.
    pub direction: ScopeTransportDirection,
    /// All mismatch signals, including unauthenticated ALPN alerts.
    pub total: u64,
    /// Signals proven by a revision-one frame on an authenticated connection.
    pub authenticated: u64,
    /// Diagnostic condition since the last authenticated revision-two handshake.
    /// This value never prevents a later call or grants an application outcome.
    pub active: bool,
}

/// Read all 50 fixed role/purpose/direction counters for metrics export.
/// Recovery clears only the diagnostic condition, preserving counters and the
/// thirty-second log limiter. These snapshots are never admission authority.
pub fn scope_transport_revision_diagnostics() -> [ScopeTransportRevisionDiagnostic; 50] {
    DiagnosticContext::all().map(|context| DIAGNOSTICS.snapshot(context))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DiagnosticContext {
    pub(super) role: ScopeTransportRole,
    pub(super) purpose: ScopeTransportPurpose,
    pub(super) direction: ScopeTransportDirection,
}
impl DiagnosticContext {
    pub(super) const fn new(
        role: ScopeTransportRole,
        purpose: ScopeTransportPurpose,
        direction: ScopeTransportDirection,
    ) -> Self {
        Self {
            role,
            purpose,
            direction,
        }
    }
    pub(super) fn all() -> [Self; 50] {
        std::array::from_fn(|index| Self {
            role: ScopeTransportRole::ALL[index / 10],
            purpose: ScopeTransportPurpose::ALL[(index / 2) % 5],
            direction: ScopeTransportDirection::ALL[index % 2],
        })
    }
    const fn index(self) -> usize {
        (self.role as usize * 5 + self.purpose as usize) * 2 + self.direction as usize
    }
    fn record(self, proven: bool) {
        opc_redaction::metrics::METRICS.record_scope_transport_revision_mismatch(
            self.role.label(),
            self.purpose.label(),
            self.direction.label(),
        );
        if DIAGNOSTICS.record(self, proven, Instant::now()) {
            tracing::warn!(
                reason = "scope_transport_revision_mismatch",
                role = self.role.label(),
                purpose = self.purpose.label(),
                direction = self.direction.label(),
                authenticated_frame = proven,
                "scope transport revision mismatch"
            );
        }
    }
}

pub(super) const WORKER_RESPONSE: DiagnosticContext = DiagnosticContext::new(
    ScopeTransportRole::Worker,
    ScopeTransportPurpose::ScopeResponse,
    ScopeTransportDirection::Outbound,
);
pub(super) const OBSERVER_RESPONSE: DiagnosticContext = DiagnosticContext::new(
    ScopeTransportRole::Observer,
    ScopeTransportPurpose::ScopeResponse,
    ScopeTransportDirection::Outbound,
);
pub(super) const QUORUM_REQUEST: DiagnosticContext = DiagnosticContext::new(
    ScopeTransportRole::Quorum,
    ScopeTransportPurpose::ScopeRequest,
    ScopeTransportDirection::Inbound,
);
pub(super) const ISSUER_PROOF: DiagnosticContext = DiagnosticContext::new(
    ScopeTransportRole::Issuer,
    ScopeTransportPurpose::BootCandidate,
    ScopeTransportDirection::Outbound,
);
pub(super) const RESPONDER_CALL: DiagnosticContext = DiagnosticContext::new(
    ScopeTransportRole::Responder,
    ScopeTransportPurpose::BootCandidate,
    ScopeTransportDirection::Inbound,
);

#[derive(Clone, Copy, Default)]
struct Entry {
    total: u64,
    authenticated: u64,
    active: bool,
    last_log: Option<Instant>,
}
pub(super) struct Diagnostics(Mutex<[Entry; 50]>);
impl Default for Diagnostics {
    fn default() -> Self {
        Self(Mutex::new([Entry::default(); 50]))
    }
}
static DIAGNOSTICS: LazyLock<Diagnostics> = LazyLock::new(Diagnostics::default);
impl Diagnostics {
    pub(super) fn record(&self, context: DiagnosticContext, proven: bool, now: Instant) -> bool {
        let mut entries = self.0.lock().unwrap_or_else(|error| error.into_inner());
        let entry = &mut entries[context.index()];
        entry.total = entry.total.saturating_add(1);
        entry.authenticated = entry.authenticated.saturating_add(u64::from(proven));
        entry.active = true;
        if entry
            .last_log
            .is_some_and(|last| now.saturating_duration_since(last) < Duration::from_secs(30))
        {
            return false;
        }
        entry.last_log = Some(now);
        true
    }
    pub(super) fn authenticated(
        &self,
        role: ScopeTransportRole,
        direction: ScopeTransportDirection,
    ) {
        let mut entries = self.0.lock().unwrap_or_else(|error| error.into_inner());
        for purpose in ScopeTransportPurpose::ALL {
            entries[DiagnosticContext::new(role, purpose, direction).index()].active = false;
        }
    }
    pub(super) fn snapshot(&self, context: DiagnosticContext) -> ScopeTransportRevisionDiagnostic {
        let entries = self.0.lock().unwrap_or_else(|error| error.into_inner());
        let entry = entries[context.index()];
        ScopeTransportRevisionDiagnostic {
            role: context.role,
            purpose: context.purpose,
            direction: context.direction,
            total: entry.total,
            authenticated: entry.authenticated,
            active: entry.active,
        }
    }
}

pub(super) fn authenticated_handshake(context: DiagnosticContext, _: &ScopeTlsAuthentication) {
    DIAGNOSTICS.authenticated(context.role, context.direction);
}

fn handshake_mismatch(context: DiagnosticContext, error: ScopeTlsError) -> bool {
    if error != ScopeTlsError::TransportRevisionMismatch {
        return false;
    }
    DiagnosticContext {
        purpose: ScopeTransportPurpose::Handshake,
        ..context
    }
    .record(false);
    true
}
pub(super) fn rpc_handshake_error(
    context: DiagnosticContext,
    error: ScopeTlsError,
    fallback: ScopeRpcError,
) -> ScopeRpcError {
    if handshake_mismatch(context, error) {
        ScopeRpcError::TransportRevisionMismatch
    } else {
        fallback
    }
}
pub(super) fn startup_handshake_error(
    context: DiagnosticContext,
    error: ScopeTlsError,
) -> StartupError {
    if handshake_mismatch(context, error) {
        StartupError::TransportRevisionMismatch
    } else {
        StartupError::Unavailable
    }
}

enum HeaderError {
    Invalid,
    Revision,
}
fn decode_header(
    fixed: &[u8; HEADER_BYTES],
    _authentication: &ScopeTlsAuthentication,
    mut context: DiagnosticContext,
) -> Result<Header, HeaderError> {
    if fixed[4..6] == 1_u16.to_be_bytes() {
        // Validate the entire fixed header without allocating or reading a body.
        let mut current = *fixed;
        current[4..6].copy_from_slice(&2_u16.to_be_bytes());
        let header = Header::decode(&current).map_err(|WireError| HeaderError::Invalid)?;
        context.purpose = match header.method {
            Method::Liveness => ScopeTransportPurpose::BootLiveness,
            Method::Candidate => ScopeTransportPurpose::BootCandidate,
            _ => context.purpose,
        };
        context.record(true);
        return Err(HeaderError::Revision);
    }
    Header::decode(fixed).map_err(|WireError| HeaderError::Invalid)
}
pub(super) fn rpc_header(
    fixed: &[u8; HEADER_BYTES],
    context: DiagnosticContext,
    malformed: ScopeRpcError,
    authenticate: impl FnOnce() -> Result<ScopeTlsAuthentication, ScopeRpcError>,
) -> Result<Header, ScopeRpcError> {
    // Current-revision headers are bounded claims. Parsing them must still let
    // the server return its existing correlated authentication-time refusal.
    // Only claiming a proven old revision requires authentication at this point.
    if fixed[4..6] != 1_u16.to_be_bytes() {
        return Header::decode(fixed).map_err(|_| malformed);
    }
    let authentication = authenticate()?;
    decode_header(fixed, &authentication, context).map_err(|error| match error {
        HeaderError::Invalid => malformed,
        HeaderError::Revision => ScopeRpcError::TransportRevisionMismatch,
    })
}
pub(super) fn startup_header(
    fixed: &[u8; HEADER_BYTES],
    authentication: &ScopeTlsAuthentication,
    context: DiagnosticContext,
) -> Result<Header, StartupError> {
    decode_header(fixed, authentication, context).map_err(|error| match error {
        HeaderError::Invalid => StartupError::Invalid,
        HeaderError::Revision => StartupError::TransportRevisionMismatch,
    })
}
