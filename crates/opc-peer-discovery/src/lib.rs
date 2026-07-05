//! Transport-neutral packet-core peer discovery and deterministic selection.
//!
//! This crate deliberately does not perform live DNS. Products inject a
//! resolver that can implement A/AAAA, S-NAPTR, SRV, NRF-backed discovery, or a
//! deterministic test table. The SDK owns the shared mechanics around static
//! peers, resolver timeouts, negative caching, priority/weight ordering, and
//! redaction-safe selection evidence.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

mod cache;
mod resolve;

pub use cache::{CachedPeers, PeerAddressCache};
pub use resolve::{AddressLookup, AddressLookupError, AddressPeerResolver, StdAddressLookup};

/// Stable SDK profile label for this discovery contract.
pub const TELCO_PEER_DISCOVERY_PROFILE: &str = "opc-peer-discovery+transport-neutral-v1";

/// Redaction-safe product-owned label for a peer or service.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerLabel(String);

impl PeerLabel {
    /// Create a label that is safe to expose in evidence.
    ///
    /// # Errors
    ///
    /// Returns [`PeerDiscoveryErrorCode::InvalidLabel`] when the label is empty
    /// or contains characters outside `[A-Za-z0-9._:-]`.
    pub fn new(value: impl Into<String>) -> Result<Self, PeerDiscoveryError> {
        let value = value.into();
        if value.is_empty()
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
        {
            return Err(PeerDiscoveryError::new(
                PeerDiscoveryErrorCode::InvalidLabel,
                PeerDiscoveryEvidence::default(),
            ));
        }
        Ok(Self(value))
    }

    /// Borrow the safe label string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PeerLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PeerLabel").field(&self.0).finish()
    }
}

impl fmt::Display for PeerLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Transport carried by a selected endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeerTransport {
    /// UDP transport.
    Udp,
    /// TCP transport.
    Tcp,
    /// SCTP transport.
    Sctp,
}

impl PeerTransport {
    fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Sctp => "sctp",
        }
    }
}

/// Discovery mechanism requested by a product-owned policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ServiceDiscoveryMode {
    /// Resolve A/AAAA records for a host-like target.
    Address,
    /// Resolve service records such as DNS SRV.
    Service,
    /// Resolve DNS S-NAPTR and any resulting service/address records.
    Snaptr,
}

impl ServiceDiscoveryMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Address => "address",
            Self::Service => "service",
            Self::Snaptr => "snaptr",
        }
    }
}

/// Redacted discovery target.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DiscoveryTarget(String);

impl DiscoveryTarget {
    /// Create a target such as a DNS name, realm, or service discovery key.
    ///
    /// The raw target is never exposed in [`Debug`] or error text.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the raw target for resolver implementations.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn redacted_key(&self) -> String {
        stable_key("target", &self.0)
    }
}

impl fmt::Debug for DiscoveryTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiscoveryTarget")
            .field("key", &self.redacted_key())
            .finish()
    }
}

/// One resolver input selected by product policy.
#[derive(Clone, PartialEq, Eq)]
pub struct ServiceDiscoveryInput {
    /// Safe service label such as `s2b-pgwc` or `diameter-s6b`.
    pub service: PeerLabel,
    /// Redacted resolver target.
    pub target: DiscoveryTarget,
    /// Discovery mechanism to invoke.
    pub mode: ServiceDiscoveryMode,
    /// Transport to use for resolved endpoints.
    pub transport: PeerTransport,
    /// Optional default port for A/AAAA style resolution.
    pub default_port: Option<u16>,
}

impl ServiceDiscoveryInput {
    /// Create one resolver input.
    pub fn new(
        service: PeerLabel,
        target: DiscoveryTarget,
        mode: ServiceDiscoveryMode,
        transport: PeerTransport,
        default_port: Option<u16>,
    ) -> Self {
        Self {
            service,
            target,
            mode,
            transport,
            default_port,
        }
    }

    /// Redaction-safe deterministic cache/evidence key.
    pub fn cache_key(&self) -> DiscoveryCacheKey {
        let material = format!(
            "{}|{}|{}|{}|{:?}",
            self.service.as_str(),
            self.target.as_str(),
            self.mode.as_str(),
            self.transport.as_str(),
            self.default_port
        );
        DiscoveryCacheKey(stable_key("discovery", &material))
    }
}

impl fmt::Debug for ServiceDiscoveryInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceDiscoveryInput")
            .field("service", &self.service)
            .field("target", &self.target)
            .field("mode", &self.mode)
            .field("transport", &self.transport)
            .field("default_port", &self.default_port)
            .finish()
    }
}

/// Redaction-safe discovery cache key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DiscoveryCacheKey(String);

impl DiscoveryCacheKey {
    /// Borrow the stable key.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Candidate origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeerCandidateSource {
    /// Operator-configured static peer.
    Static,
    /// Resolver-produced peer.
    Resolver(ServiceDiscoveryMode),
}

impl PeerCandidateSource {
    fn rank(self) -> u8 {
        match self {
            Self::Static => 0,
            Self::Resolver(_) => 1,
        }
    }
}

/// One selectable peer endpoint.
#[derive(Clone, PartialEq, Eq)]
pub struct PeerCandidate {
    /// Redaction-safe operator label for this candidate.
    pub label: PeerLabel,
    /// Resolved IP-literal endpoint.
    pub endpoint: SocketAddr,
    /// Endpoint transport.
    pub transport: PeerTransport,
    /// Lower values are preferred.
    pub priority: u16,
    /// Higher values are preferred within the same priority.
    pub weight: u16,
    /// Source of the candidate.
    pub source: PeerCandidateSource,
}

impl PeerCandidate {
    /// Build a static candidate.
    pub fn static_peer(
        label: PeerLabel,
        endpoint: SocketAddr,
        transport: PeerTransport,
        priority: u16,
        weight: u16,
    ) -> Self {
        Self {
            label,
            endpoint,
            transport,
            priority,
            weight,
            source: PeerCandidateSource::Static,
        }
    }

    /// Build a resolver candidate.
    pub fn resolved(
        label: PeerLabel,
        endpoint: SocketAddr,
        transport: PeerTransport,
        mode: ServiceDiscoveryMode,
        priority: u16,
        weight: u16,
    ) -> Self {
        Self {
            label,
            endpoint,
            transport,
            priority,
            weight,
            source: PeerCandidateSource::Resolver(mode),
        }
    }

    /// Redaction-safe deterministic endpoint key.
    pub fn endpoint_key(&self) -> String {
        stable_key(
            "endpoint",
            &format!("{}|{}", self.transport.as_str(), self.endpoint),
        )
    }
}

impl fmt::Debug for PeerCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerCandidate")
            .field("label", &self.label)
            .field("endpoint_key", &self.endpoint_key())
            .field("transport", &self.transport)
            .field("priority", &self.priority)
            .field("weight", &self.weight)
            .field("source", &self.source)
            .finish()
    }
}

/// Resolver output for one discovery input.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResolvedPeers {
    /// Resolved candidate endpoints.
    pub candidates: Vec<PeerCandidate>,
}

impl ResolvedPeers {
    /// Build a resolver output from candidates.
    pub fn new(candidates: Vec<PeerCandidate>) -> Self {
        Self { candidates }
    }
}

/// Stable resolver failure kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerResolverError {
    /// Resolver timed out before producing an answer.
    Timeout,
    /// Resolver backend was unavailable.
    Unavailable,
    /// Resolver produced no records. `negative_ttl` controls negative caching.
    NotFound {
        /// How long this negative result can be cached.
        negative_ttl: Duration,
    },
    /// Resolver answer could not be accepted.
    InvalidAnswer,
}

/// Resolver injected by the product or test harness.
pub trait PeerResolver {
    /// Resolve one discovery input within the caller-provided timeout budget.
    ///
    /// # Errors
    ///
    /// Returns [`PeerResolverError`] for timeout, unavailable, not-found, or
    /// invalid-answer outcomes. Error values are intentionally redaction-safe.
    fn resolve(
        &mut self,
        input: &ServiceDiscoveryInput,
        timeout: Duration,
    ) -> Result<ResolvedPeers, PeerResolverError>;
}

/// Monotonic time represented as milliseconds for deterministic tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PeerDiscoveryTime(u64);

impl PeerDiscoveryTime {
    /// Construct a timestamp from monotonic milliseconds.
    pub const fn from_millis(value: u64) -> Self {
        Self(value)
    }

    fn checked_add(self, ttl: Duration) -> Option<Self> {
        let ttl_millis = u64::try_from(ttl.as_millis()).ok()?;
        self.0.checked_add(ttl_millis).map(Self)
    }
}

/// Negative cache for resolver not-found outcomes.
#[derive(Debug, Clone, Default)]
pub struct PeerNegativeCache {
    entries: HashMap<DiscoveryCacheKey, PeerDiscoveryTime>,
}

impl PeerNegativeCache {
    /// Return true if `input` has a live negative-cache entry.
    pub fn contains(&mut self, input: &ServiceDiscoveryInput, now: PeerDiscoveryTime) -> bool {
        let key = input.cache_key();
        match self.entries.get(&key).copied() {
            Some(expires_at) if now < expires_at => true,
            Some(_) => {
                self.entries.remove(&key);
                false
            }
            None => false,
        }
    }

    /// Record a negative result. Zero TTLs are ignored.
    pub fn record(&mut self, input: &ServiceDiscoveryInput, now: PeerDiscoveryTime, ttl: Duration) {
        if ttl.is_zero() {
            return;
        }
        if let Some(expires_at) = now.checked_add(ttl) {
            self.entries.insert(input.cache_key(), expires_at);
        }
    }
}

/// Selection request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDiscoveryRequest {
    /// Static peer candidates, in operator order.
    pub static_peers: Vec<PeerCandidate>,
    /// Product-owned discovery inputs, in policy order.
    pub discovery: Vec<ServiceDiscoveryInput>,
    /// Optional preferred safe peer label.
    pub preferred_peer: Option<PeerLabel>,
    /// Timeout budget passed to the injected resolver.
    pub resolver_timeout: Duration,
    /// Current deterministic time for negative-cache decisions.
    pub now: PeerDiscoveryTime,
}

impl Default for PeerDiscoveryRequest {
    fn default() -> Self {
        Self {
            static_peers: Vec::new(),
            discovery: Vec::new(),
            preferred_peer: None,
            resolver_timeout: Duration::from_secs(1),
            now: PeerDiscoveryTime::default(),
        }
    }
}

/// Stable selection/rejection reason for one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CandidateDecision {
    /// This candidate was selected.
    Selected,
    /// A preferred label was configured and this candidate did not match it.
    NotPreferred,
    /// Candidate lost by lower priority.
    LowerPriority,
    /// Candidate lost by lower weight within the selected priority.
    LowerWeight,
    /// Candidate lost by deterministic stable tie-break.
    StableTieBreak,
}

impl CandidateDecision {
    /// Stable machine-readable reason code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Selected => "selected",
            Self::NotPreferred => "not-preferred",
            Self::LowerPriority => "lower-priority",
            Self::LowerWeight => "lower-weight",
            Self::StableTieBreak => "stable-tie-break",
        }
    }
}

/// Redaction-safe evidence for one candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCandidateEvidence {
    /// Candidate safe label.
    pub label: PeerLabel,
    /// Redaction-safe endpoint key.
    pub endpoint_key: String,
    /// Candidate source.
    pub source: PeerCandidateSource,
    /// Selection decision.
    pub decision: CandidateDecision,
    /// Priority used for ordering.
    pub priority: u16,
    /// Weight used for ordering.
    pub weight: u16,
}

/// Stable discovery resolver outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiscoveryDecision {
    /// Resolver returned usable candidates.
    Resolved,
    /// Resolver was skipped due to negative cache.
    NegativeCacheHit,
    /// Resolver returned not found and was recorded in negative cache.
    NegativeCached,
    /// Resolver timed out.
    Timeout,
    /// Resolver backend was unavailable.
    Unavailable,
    /// Resolver returned an invalid answer.
    InvalidAnswer,
}

impl DiscoveryDecision {
    /// Stable machine-readable reason code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::NegativeCacheHit => "negative-cache-hit",
            Self::NegativeCached => "negative-cached",
            Self::Timeout => "resolver-timeout",
            Self::Unavailable => "resolver-unavailable",
            Self::InvalidAnswer => "resolver-invalid-answer",
        }
    }
}

/// Redaction-safe evidence for one resolver input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryEvidence {
    /// Safe service label.
    pub service: PeerLabel,
    /// Redaction-safe discovery key.
    pub discovery_key: DiscoveryCacheKey,
    /// Discovery mode.
    pub mode: ServiceDiscoveryMode,
    /// Outcome.
    pub decision: DiscoveryDecision,
}

/// Redaction-safe evidence for a selection attempt.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeerDiscoveryEvidence {
    /// Candidate ordering/evaluation evidence.
    pub candidates: Vec<PeerCandidateEvidence>,
    /// Resolver input evidence.
    pub discovery: Vec<DiscoveryEvidence>,
}

/// Selected endpoint plus redaction-safe evidence.
#[derive(Clone, PartialEq, Eq)]
pub struct SelectedPeer {
    /// Safe label of the selected peer.
    pub label: PeerLabel,
    /// Socket address to dial. Its [`Debug`] output is redacted by this type.
    pub endpoint: SocketAddr,
    /// Transport to use.
    pub transport: PeerTransport,
    /// Redaction-safe endpoint key.
    pub endpoint_key: String,
    /// Candidate source.
    pub source: PeerCandidateSource,
    /// Selection priority.
    pub priority: u16,
    /// Selection weight.
    pub weight: u16,
    /// Evidence for candidates and discovery inputs.
    pub evidence: PeerDiscoveryEvidence,
}

impl fmt::Debug for SelectedPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SelectedPeer")
            .field("label", &self.label)
            .field("endpoint_key", &self.endpoint_key)
            .field("transport", &self.transport)
            .field("source", &self.source)
            .field("priority", &self.priority)
            .field("weight", &self.weight)
            .field("evidence", &self.evidence)
            .finish()
    }
}

/// Stable peer discovery failure codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerDiscoveryErrorCode {
    /// A safe label was malformed.
    InvalidLabel,
    /// No static or resolved candidate was selectable.
    NoPeerCandidates,
    /// Every discovery input was skipped by negative cache.
    NegativeCacheHit,
    /// Resolver timed out and no candidate was available.
    ResolverTimeout,
    /// Resolver was unavailable and no candidate was available.
    ResolverUnavailable,
    /// Resolver answer was invalid and no candidate was available.
    ResolverInvalidAnswer,
}

impl PeerDiscoveryErrorCode {
    /// Stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidLabel => "invalid-label",
            Self::NoPeerCandidates => "no-peer-candidates",
            Self::NegativeCacheHit => "negative-cache-hit",
            Self::ResolverTimeout => "resolver-timeout",
            Self::ResolverUnavailable => "resolver-unavailable",
            Self::ResolverInvalidAnswer => "resolver-invalid-answer",
        }
    }
}

/// Redaction-safe peer discovery error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("peer discovery failed: {code}")]
pub struct PeerDiscoveryError {
    /// Stable error code.
    pub code: PeerDiscoveryErrorCode,
    /// Redaction-safe evidence collected before failure.
    pub evidence: PeerDiscoveryEvidence,
}

impl PeerDiscoveryError {
    fn new(code: PeerDiscoveryErrorCode, evidence: PeerDiscoveryEvidence) -> Self {
        Self { code, evidence }
    }

    /// Stable machine-readable error code.
    pub const fn code(&self) -> &'static str {
        self.code.as_str()
    }
}

impl fmt::Display for PeerDiscoveryErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Resolve and select one peer using the injected resolver and negative cache.
///
/// # Errors
///
/// Returns [`PeerDiscoveryError`] when no candidate can be selected. Error
/// values carry only safe labels, stable keys, and stable reason codes.
pub fn discover_and_select(
    request: PeerDiscoveryRequest,
    resolver: &mut impl PeerResolver,
    negative_cache: &mut PeerNegativeCache,
) -> Result<SelectedPeer, PeerDiscoveryError> {
    let mut evidence = PeerDiscoveryEvidence::default();
    let mut candidates = request.static_peers;
    let mut last_error = None;
    let mut cache_hits = 0usize;

    for input in &request.discovery {
        let discovery_key = input.cache_key();
        if negative_cache.contains(input, request.now) {
            cache_hits += 1;
            evidence.discovery.push(DiscoveryEvidence {
                service: input.service.clone(),
                discovery_key,
                mode: input.mode,
                decision: DiscoveryDecision::NegativeCacheHit,
            });
            continue;
        }

        match resolver.resolve(input, request.resolver_timeout) {
            Ok(mut resolved) => {
                evidence.discovery.push(DiscoveryEvidence {
                    service: input.service.clone(),
                    discovery_key,
                    mode: input.mode,
                    decision: DiscoveryDecision::Resolved,
                });
                candidates.append(&mut resolved.candidates);
            }
            Err(PeerResolverError::NotFound { negative_ttl }) => {
                negative_cache.record(input, request.now, negative_ttl);
                evidence.discovery.push(DiscoveryEvidence {
                    service: input.service.clone(),
                    discovery_key,
                    mode: input.mode,
                    decision: DiscoveryDecision::NegativeCached,
                });
            }
            Err(PeerResolverError::Timeout) => {
                last_error = Some(PeerDiscoveryErrorCode::ResolverTimeout);
                evidence.discovery.push(DiscoveryEvidence {
                    service: input.service.clone(),
                    discovery_key,
                    mode: input.mode,
                    decision: DiscoveryDecision::Timeout,
                });
            }
            Err(PeerResolverError::Unavailable) => {
                last_error = Some(PeerDiscoveryErrorCode::ResolverUnavailable);
                evidence.discovery.push(DiscoveryEvidence {
                    service: input.service.clone(),
                    discovery_key,
                    mode: input.mode,
                    decision: DiscoveryDecision::Unavailable,
                });
            }
            Err(PeerResolverError::InvalidAnswer) => {
                last_error = Some(PeerDiscoveryErrorCode::ResolverInvalidAnswer);
                evidence.discovery.push(DiscoveryEvidence {
                    service: input.service.clone(),
                    discovery_key,
                    mode: input.mode,
                    decision: DiscoveryDecision::InvalidAnswer,
                });
            }
        }
    }

    if let Some(preferred) = &request.preferred_peer {
        if candidates
            .iter()
            .any(|candidate| &candidate.label == preferred)
        {
            candidates.retain(|candidate| &candidate.label == preferred);
        }
    }

    let Some((selected_index, selected)) = select_candidate(&candidates) else {
        let code = if !request.discovery.is_empty() && cache_hits == request.discovery.len() {
            PeerDiscoveryErrorCode::NegativeCacheHit
        } else {
            last_error.unwrap_or(PeerDiscoveryErrorCode::NoPeerCandidates)
        };
        return Err(PeerDiscoveryError::new(code, evidence));
    };

    evidence.candidates = candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| PeerCandidateEvidence {
            label: candidate.label.clone(),
            endpoint_key: candidate.endpoint_key(),
            source: candidate.source,
            decision: candidate_decision(
                index,
                selected_index,
                candidate,
                selected,
                request.preferred_peer.as_ref(),
            ),
            priority: candidate.priority,
            weight: candidate.weight,
        })
        .collect();

    Ok(SelectedPeer {
        label: selected.label.clone(),
        endpoint: selected.endpoint,
        transport: selected.transport,
        endpoint_key: selected.endpoint_key(),
        source: selected.source,
        priority: selected.priority,
        weight: selected.weight,
        evidence,
    })
}

fn select_candidate(candidates: &[PeerCandidate]) -> Option<(usize, &PeerCandidate)> {
    candidates.iter().enumerate().min_by(|(_, a), (_, b)| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| b.weight.cmp(&a.weight))
            .then_with(|| a.source.rank().cmp(&b.source.rank()))
            .then_with(|| a.label.cmp(&b.label))
            .then_with(|| a.endpoint_key().cmp(&b.endpoint_key()))
    })
}

fn candidate_decision(
    index: usize,
    selected_index: usize,
    candidate: &PeerCandidate,
    selected: &PeerCandidate,
    preferred: Option<&PeerLabel>,
) -> CandidateDecision {
    if index == selected_index {
        return CandidateDecision::Selected;
    }
    if preferred.is_some_and(|label| &candidate.label != label) {
        return CandidateDecision::NotPreferred;
    }
    if candidate.priority > selected.priority {
        return CandidateDecision::LowerPriority;
    }
    if candidate.priority == selected.priority && candidate.weight < selected.weight {
        return CandidateDecision::LowerWeight;
    }
    CandidateDecision::StableTieBreak
}

fn stable_key(prefix: &str, material: &str) -> String {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = FNV_OFFSET;
    for byte in material.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{prefix}:{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeResolver {
        responses: HashMap<DiscoveryCacheKey, Result<ResolvedPeers, PeerResolverError>>,
        calls: usize,
        last_timeout: Option<Duration>,
    }

    impl FakeResolver {
        fn insert(
            &mut self,
            input: &ServiceDiscoveryInput,
            result: Result<ResolvedPeers, PeerResolverError>,
        ) {
            self.responses.insert(input.cache_key(), result);
        }
    }

    impl PeerResolver for FakeResolver {
        fn resolve(
            &mut self,
            input: &ServiceDiscoveryInput,
            timeout: Duration,
        ) -> Result<ResolvedPeers, PeerResolverError> {
            self.calls += 1;
            self.last_timeout = Some(timeout);
            self.responses
                .get(&input.cache_key())
                .cloned()
                .unwrap_or_else(|| {
                    Err(PeerResolverError::NotFound {
                        negative_ttl: Duration::from_secs(30),
                    })
                })
        }
    }

    fn label(value: &str) -> PeerLabel {
        PeerLabel::new(value).expect("valid label")
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 10], port))
    }

    fn input(target: &str, mode: ServiceDiscoveryMode) -> ServiceDiscoveryInput {
        ServiceDiscoveryInput::new(
            label("s2b-pgwc"),
            DiscoveryTarget::new(target),
            mode,
            PeerTransport::Udp,
            Some(2123),
        )
    }

    #[test]
    fn static_peers_select_by_priority_weight_and_preference() {
        let preferred = label("pgw-b");
        let static_peers = vec![
            PeerCandidate::static_peer(label("pgw-a"), addr(2123), PeerTransport::Udp, 10, 100),
            PeerCandidate::static_peer(preferred.clone(), addr(2124), PeerTransport::Udp, 20, 1),
        ];
        let request = PeerDiscoveryRequest {
            static_peers,
            preferred_peer: Some(preferred),
            ..Default::default()
        };

        let selected = discover_and_select(
            request,
            &mut FakeResolver::default(),
            &mut PeerNegativeCache::default(),
        )
        .expect("selected");

        assert_eq!(selected.label.as_str(), "pgw-b");
        assert_eq!(selected.endpoint, addr(2124));
        assert_eq!(selected.evidence.candidates.len(), 1);
        assert_eq!(
            selected.evidence.candidates[0].decision,
            CandidateDecision::Selected
        );
        let debug = format!("{selected:?}");
        assert!(!debug.contains("192.0.2.10"));
        assert!(!debug.contains("2124"));
        assert!(debug.contains("endpoint:"));
    }

    #[test]
    fn resolver_candidates_use_stable_priority_weight_ordering() {
        let query = input("pgw-control.example.invalid", ServiceDiscoveryMode::Snaptr);
        let mut resolver = FakeResolver::default();
        resolver.insert(
            &query,
            Ok(ResolvedPeers::new(vec![
                PeerCandidate::resolved(
                    label("pgw-low"),
                    addr(2123),
                    PeerTransport::Udp,
                    ServiceDiscoveryMode::Snaptr,
                    10,
                    10,
                ),
                PeerCandidate::resolved(
                    label("pgw-high"),
                    addr(2124),
                    PeerTransport::Udp,
                    ServiceDiscoveryMode::Snaptr,
                    10,
                    20,
                ),
            ])),
        );
        let request = PeerDiscoveryRequest {
            discovery: vec![query],
            resolver_timeout: Duration::from_millis(250),
            ..Default::default()
        };

        let selected =
            discover_and_select(request, &mut resolver, &mut PeerNegativeCache::default())
                .expect("selected");

        assert_eq!(selected.label.as_str(), "pgw-high");
        assert_eq!(
            selected.source,
            PeerCandidateSource::Resolver(ServiceDiscoveryMode::Snaptr)
        );
        assert_eq!(
            selected.evidence.discovery[0].decision,
            DiscoveryDecision::Resolved
        );
        assert_eq!(resolver.last_timeout, Some(Duration::from_millis(250)));
        assert!(selected
            .evidence
            .candidates
            .iter()
            .any(|candidate| candidate.decision == CandidateDecision::LowerWeight));
    }

    #[test]
    fn negative_cache_skips_resolver_without_leaking_target() {
        let query = input("sensitive.realm.example", ServiceDiscoveryMode::Address);
        let mut resolver = FakeResolver::default();
        resolver.insert(
            &query,
            Err(PeerResolverError::NotFound {
                negative_ttl: Duration::from_secs(60),
            }),
        );
        let mut cache = PeerNegativeCache::default();

        let first = discover_and_select(
            PeerDiscoveryRequest {
                discovery: vec![query.clone()],
                now: PeerDiscoveryTime::from_millis(1_000),
                ..Default::default()
            },
            &mut resolver,
            &mut cache,
        )
        .expect_err("not found");
        assert_eq!(first.code(), "no-peer-candidates");
        assert_eq!(
            first.evidence.discovery[0].decision,
            DiscoveryDecision::NegativeCached
        );
        assert_eq!(resolver.calls, 1);

        let second = discover_and_select(
            PeerDiscoveryRequest {
                discovery: vec![query],
                now: PeerDiscoveryTime::from_millis(2_000),
                ..Default::default()
            },
            &mut resolver,
            &mut cache,
        )
        .expect_err("negative cache hit");
        assert_eq!(second.code(), "negative-cache-hit");
        assert_eq!(
            second.evidence.discovery[0].decision,
            DiscoveryDecision::NegativeCacheHit
        );
        assert_eq!(resolver.calls, 1);
        let debug = format!("{second:?}");
        assert!(!debug.contains("sensitive.realm.example"));
    }

    #[test]
    fn resolver_timeout_returns_stable_error_code() {
        let query = input("timeout.example.invalid", ServiceDiscoveryMode::Service);
        let mut resolver = FakeResolver::default();
        resolver.insert(&query, Err(PeerResolverError::Timeout));

        let err = discover_and_select(
            PeerDiscoveryRequest {
                discovery: vec![query],
                ..Default::default()
            },
            &mut resolver,
            &mut PeerNegativeCache::default(),
        )
        .expect_err("timeout");

        assert_eq!(err.code(), "resolver-timeout");
        assert_eq!(
            err.evidence.discovery[0].decision,
            DiscoveryDecision::Timeout
        );
        assert_eq!(err.to_string(), "peer discovery failed: resolver-timeout");
    }

    #[test]
    fn static_peer_can_win_over_resolver_by_priority() {
        let query = input("pgw.example.invalid", ServiceDiscoveryMode::Address);
        let mut resolver = FakeResolver::default();
        resolver.insert(
            &query,
            Ok(ResolvedPeers::new(vec![PeerCandidate::resolved(
                label("resolved"),
                addr(2125),
                PeerTransport::Udp,
                ServiceDiscoveryMode::Address,
                20,
                100,
            )])),
        );

        let selected = discover_and_select(
            PeerDiscoveryRequest {
                static_peers: vec![PeerCandidate::static_peer(
                    label("static"),
                    addr(2123),
                    PeerTransport::Udp,
                    10,
                    1,
                )],
                discovery: vec![query],
                ..Default::default()
            },
            &mut resolver,
            &mut PeerNegativeCache::default(),
        )
        .expect("selected");

        assert_eq!(selected.label.as_str(), "static");
        assert!(selected
            .evidence
            .candidates
            .iter()
            .any(|candidate| candidate.decision == CandidateDecision::LowerPriority));
    }

    #[test]
    fn invalid_label_is_rejected_without_echoing_value() {
        let err = PeerLabel::new("bad label with spaces").expect_err("invalid label");
        assert_eq!(err.code(), "invalid-label");
        assert!(!format!("{err:?}").contains("bad label"));
    }
}
