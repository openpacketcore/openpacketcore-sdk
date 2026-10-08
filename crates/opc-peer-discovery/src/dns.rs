//! Additive DNS contracts. The legacy resolver and selection structs retain
//! their original shape; these types carry DNS identity, TTLs and provenance.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::{DiscoveryTarget, PeerCandidate, PeerDiscoveryTime, ServiceDiscoveryInput};

/// Canonical absolute ASCII DNS name, redacted in diagnostics.
///
/// Names are lowercased and have exactly one terminal dot. IDNA conversion is
/// the caller's responsibility. Underscores are accepted for service labels.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DnsName(String);

impl DnsName {
    /// Canonicalize a DNS name.
    ///
    /// # Errors
    /// Returns [`DnsError::InvalidQuery`] for empty, non-ASCII or oversized
    /// names, empty interior labels, or characters outside letters/digits/`_-`.
    pub fn new(value: impl AsRef<str>) -> Result<Self, DnsError> {
        let value = value.as_ref();
        if value == "." {
            return Ok(Self(value.to_owned()));
        }
        let value = value.strip_suffix('.').unwrap_or(value);
        if value.is_empty()
            || value.len() > 253
            || value.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            })
        {
            return Err(DnsError::InvalidQuery);
        }
        Ok(Self(format!("{}.", value.to_ascii_lowercase())))
    }

    /// Borrow the name for DNS encoding; never use it as a metric label.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DnsName([redacted])")
    }
}

macro_rules! opaque_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Default, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            /// Create an opaque identity. The empty identity means the default.
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// Borrow the identifier for resolver configuration lookup only.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

opaque_id!(
    ResolverProfileId,
    "Opaque resolver configuration identity, never a diagnostic label."
);
opaque_id!(
    SourcePlaneId,
    "Opaque source address/plane configuration identity, never a diagnostic label."
);

/// Address families allowed by the consumer. Dual stack uses the documented
/// destination-only subset of RFC 6724; it does not assert reachability.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AddressFamilyPolicy {
    /// Accept IPv4 and IPv6.
    #[default]
    DualStack,
    /// Accept IPv4 and IPv4-mapped IPv6 socket addresses only.
    Ipv4Only,
    /// Accept IPv6 socket addresses except IPv4-mapped addresses.
    Ipv6Only,
}

impl AddressFamilyPolicy {
    pub(crate) fn accepts(self, address: SocketAddr) -> bool {
        let ipv4 = match address.ip() {
            IpAddr::V4(_) => true,
            IpAddr::V6(ip) => ip.to_ipv4_mapped().is_some(),
        };
        match self {
            Self::DualStack => true,
            Self::Ipv4Only => ipv4,
            Self::Ipv6Only => !ipv4,
        }
    }
}

/// Complete DNS query identity. Changing any policy field creates a distinct
/// cache key. Profile and plane IDs name caller-owned immutable configurations;
/// give a changed configuration a new ID or remove its old cache entries.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DnsQuery {
    input: ServiceDiscoveryInput,
    name: DnsName,
    resolver_profile: ResolverProfileId,
    source_plane: SourcePlaneId,
    address_family: AddressFamilyPolicy,
}

impl DnsQuery {
    /// Build a DNS query using the default resolver, source and family policy.
    ///
    /// # Errors
    /// Returns [`DnsError::InvalidQuery`] for an invalid DNS name or an IP
    /// literal. Configure IP-literal endpoints as static peers instead.
    pub fn new(mut input: ServiceDiscoveryInput) -> Result<Self, DnsError> {
        let name = DnsName::new(input.target.as_str())?;
        if name
            .as_str()
            .trim_end_matches('.')
            .parse::<IpAddr>()
            .is_ok()
        {
            return Err(DnsError::InvalidQuery);
        }
        input.target = DiscoveryTarget::new(name.as_str());
        Ok(Self {
            input,
            name,
            resolver_profile: ResolverProfileId::default(),
            source_plane: SourcePlaneId::default(),
            address_family: AddressFamilyPolicy::default(),
        })
    }

    /// Set the opaque resolver profile identity.
    pub fn with_resolver_profile(mut self, profile: ResolverProfileId) -> Self {
        self.resolver_profile = profile;
        self
    }

    /// Set the opaque source plane identity.
    pub fn with_source_plane(mut self, plane: SourcePlaneId) -> Self {
        self.source_plane = plane;
        self
    }

    /// Set the address-family policy.
    pub fn with_address_family(mut self, policy: AddressFamilyPolicy) -> Self {
        self.address_family = policy;
        self
    }

    /// Canonical DNS name to encode on the wire.
    pub fn name(&self) -> &DnsName {
        &self.name
    }

    /// Canonicalized service, mode, transport and port input.
    pub fn input(&self) -> &ServiceDiscoveryInput {
        &self.input
    }

    /// Resolver profile identity.
    pub fn resolver_profile(&self) -> &ResolverProfileId {
        &self.resolver_profile
    }

    /// Source plane identity.
    pub fn source_plane(&self) -> &SourcePlaneId {
        &self.source_plane
    }

    /// Address-family policy.
    pub fn address_family(&self) -> AddressFamilyPolicy {
        self.address_family
    }

    /// Collision-safe key retaining all query fields for equality checks.
    pub fn cache_key(&self) -> DnsCacheKey {
        DnsCacheKey(self.clone())
    }
}

impl fmt::Debug for DnsQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsQuery")
            .field("mode", &self.input.mode)
            .field("transport", &self.input.transport)
            .field("address_family", &self.address_family)
            .finish_non_exhaustive()
    }
}

/// Exact DNS cache identity, redacted in diagnostics. Equality compares the
/// complete query, not a digest that could alias two resolver/source contexts.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DnsCacheKey(pub(crate) DnsQuery);

impl DnsCacheKey {
    /// Borrow the complete query when driving a key returned by
    /// [`crate::DnsCache::refresh_due`]. Raw fields are for resolver use only.
    pub fn query(&self) -> &DnsQuery {
        &self.0
    }
}

impl fmt::Debug for DnsCacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DnsCacheKey([redacted])")
    }
}

/// Type of a DNS record used to reach an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DnsRecordType {
    /// IPv4 address record.
    A,
    /// IPv6 address record.
    Aaaa,
    /// Canonical-name indirection.
    Cname,
    /// Service target record.
    Srv,
    /// Naming-authority pointer record.
    Naptr,
}

/// Provenance of one record in traversal order, including its own observation
/// time. A multi-query traversal must not restart earlier records' TTLs.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DnsRecord {
    /// Canonical record owner; access only for resolver/consumer logic.
    pub owner: DnsName,
    /// Record type in the chain.
    pub kind: DnsRecordType,
    /// Remaining record TTL in seconds as received from the resolver.
    pub ttl: u32,
    /// Time at which this remaining TTL was observed, in the cache clock domain.
    pub observed_at: PeerDiscoveryTime,
}

impl DnsRecord {
    /// Record provenance from a validated DNS response. Wire parsing and chain
    /// validation belong to the resolver; this type does not authenticate DNS.
    pub fn new(
        owner: DnsName,
        kind: DnsRecordType,
        ttl: u32,
        observed_at: PeerDiscoveryTime,
    ) -> Self {
        Self {
            owner,
            kind,
            ttl,
            observed_at,
        }
    }

    /// Absolute expiry; unrepresentable deadlines fail stale at observation.
    /// High-bit TTLs are zero under this API's conservative
    /// [RFC 2181 section 8](https://www.rfc-editor.org/rfc/rfc2181.html#section-8)
    /// policy. The original TTL remains available in the provenance.
    pub fn expires_at(&self) -> PeerDiscoveryTime {
        self.observed_at
            .checked_add(record_ttl(self.ttl))
            .unwrap_or(self.observed_at)
    }
}

fn record_ttl(ttl: u32) -> Duration {
    Duration::from_secs(if ttl & 0x8000_0000 == 0 {
        u64::from(ttl)
    } else {
        0
    })
}

impl fmt::Debug for DnsRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsRecord")
            .field("kind", &self.kind)
            .field("ttl", &self.ttl)
            .field("observed_at", &self.observed_at)
            .finish_non_exhaustive()
    }
}

/// Endpoint and every record used to reach it. `None` provenance explicitly
/// denotes a legacy lookup that supplied no DNS records or TTLs.
#[derive(Clone, PartialEq, Eq)]
pub struct DnsCandidate {
    peer: PeerCandidate,
    records: Option<Box<[DnsRecord]>>,
}

impl DnsCandidate {
    /// Maximum retained record count per candidate, including the terminal
    /// address record. Oversized chains are rejected, never truncated.
    pub const MAX_RECORDS: usize = 16;

    /// Build a candidate from a validated record chain ending in A or AAAA.
    ///
    /// # Errors
    /// Returns [`DnsError::MalformedAnswer`] for an empty or oversized chain,
    /// or a terminal type that does not match the endpoint's address family.
    pub fn new(peer: PeerCandidate, records: Vec<DnsRecord>) -> Result<Self, DnsError> {
        let terminal = if peer.endpoint.is_ipv4() {
            DnsRecordType::A
        } else {
            DnsRecordType::Aaaa
        };
        if records.len() > Self::MAX_RECORDS || records.last().is_none_or(|r| r.kind != terminal) {
            return Err(DnsError::MalformedAnswer);
        }
        Ok(Self {
            peer,
            records: Some(records.into_boxed_slice()),
        })
    }

    /// Wrap a legacy candidate without inventing DNS provenance or TTLs.
    pub fn without_ttl(peer: PeerCandidate) -> Self {
        Self {
            peer,
            records: None,
        }
    }

    /// Endpoint metadata for the consumer. Its raw fields must not be logged.
    pub fn peer(&self) -> &PeerCandidate {
        &self.peer
    }

    /// Traversed records, or `None` when the adapter cannot supply them.
    pub fn records(&self) -> Option<&[DnsRecord]> {
        self.records.as_deref()
    }
}

impl fmt::Debug for DnsCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsCandidate")
            .field(
                "record_count",
                &self.records.as_ref().map(|records| records.len()),
            )
            .finish_non_exhaustive()
    }
}

/// Nonempty resolved candidate set with per-candidate chain provenance.
#[derive(Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    candidates: Box<[DnsCandidate]>,
}

impl DnsAnswer {
    /// Maximum retained candidate count per answer, matching the address
    /// adapter's limit. Oversized DNS answers are rejected, never truncated.
    pub const MAX_CANDIDATES: usize = 16;

    /// Build a positive answer. An empty set is malformed, never a positive
    /// replacement for a last-good answer or an inferred authoritative denial.
    ///
    /// # Errors
    /// Returns [`DnsError::MalformedAnswer`] when `candidates` is empty or
    /// exceeds [`Self::MAX_CANDIDATES`]. Unused vector capacity is not retained.
    pub fn new(candidates: Vec<DnsCandidate>) -> Result<Self, DnsError> {
        if candidates.is_empty() || candidates.len() > Self::MAX_CANDIDATES {
            return Err(DnsError::MalformedAnswer);
        }
        Ok(Self {
            candidates: candidates.into_boxed_slice(),
        })
    }

    /// Borrow candidates in resolver selection order.
    pub fn candidates(&self) -> &[DnsCandidate] {
        &self.candidates
    }

    /// Earliest expiry over every record of every candidate. `None` means at
    /// least one candidate lacks TTL provenance, so no fresh lifetime is known.
    /// This describes record provenance without cache caps. For scheduling,
    /// use [`crate::DnsCacheStatus::fresh_until`] and its retry/refresh state.
    pub fn expires_at(&self) -> Option<PeerDiscoveryTime> {
        let mut earliest = None;
        for candidate in &self.candidates {
            for record in candidate.records.as_ref()? {
                let expires = record.expires_at();
                earliest =
                    Some(earliest.map_or(expires, |old: PeerDiscoveryTime| old.min(expires)));
            }
        }
        earliest
    }
}

impl fmt::Debug for DnsAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsAnswer")
            .field("candidate_count", &self.candidates.len())
            .field("expires_at", &self.expires_at())
            .finish_non_exhaustive()
    }
}

/// SOA timing from a validated authoritative negative response (possibly
/// relayed by a recursive resolver). It carries no owner or server identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegativeSoa {
    record_ttl: u32,
    minimum: u32,
    observed_at: PeerDiscoveryTime,
    chain_expires_at: Option<PeerDiscoveryTime>,
}

impl NegativeSoa {
    /// Record the remaining SOA TTL and SOA.MINIMUM in seconds, and the time
    /// this TTL was observed. Deferred publication does not restart its TTL.
    pub const fn new(record_ttl: u32, minimum: u32, observed_at: PeerDiscoveryTime) -> Self {
        Self {
            record_ttl,
            minimum,
            observed_at,
            chain_expires_at: None,
        }
    }

    /// RFC 2308 sections 3 and 5: the smaller of SOA TTL and SOA.MINIMUM.
    /// Each high-bit TTL-valued field is treated as zero per this API's
    /// RFC 2181 section 8 policy, before taking the minimum.
    pub fn ttl(self) -> Duration {
        record_ttl(self.record_ttl).min(record_ttl(self.minimum))
    }

    /// Bound a denial reached through aliases by their earliest absolute
    /// record expiry in the cache clock domain. Repeated calls only shorten
    /// this bound. The resolver must supply every traversed chain's minimum;
    /// it must not restart an alias TTL when it observes the final SOA.
    pub fn with_chain_expiry(mut self, expires_at: PeerDiscoveryTime) -> Self {
        self.chain_expires_at = Some(
            self.chain_expires_at
                .map_or(expires_at, |old| old.min(expires_at)),
        );
        self
    }

    /// Time the remaining SOA TTL was received, in the cache's clock domain.
    pub const fn observed_at(self) -> PeerDiscoveryTime {
        self.observed_at
    }

    /// Absolute expiry of the denial; overflow fails expired at observation.
    pub fn expires_at(self) -> PeerDiscoveryTime {
        let expires_at = self
            .observed_at
            .checked_add(self.ttl())
            .unwrap_or(self.observed_at);
        self.chain_expires_at
            .map_or(expires_at, |chain| chain.min(expires_at))
    }
}

/// DNS failure classes. No variant contains queried names, addresses or raw
/// backend error text. Only [`Self::code`] is suitable as a metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
#[non_exhaustive]
pub enum DnsError {
    /// Invalid caller configuration, such as a name, IP-literal query or port.
    InvalidQuery,
    /// Authoritative absence of the name. Without a validated SOA, do not cache.
    NxDomain {
        /// Validated negative SOA timing, if supplied.
        soa: Option<NegativeSoa>,
    },
    /// Authoritative absence of the requested data, distinct from NXDOMAIN.
    NoData {
        /// Validated negative SOA timing, if supplied.
        soa: Option<NegativeSoa>,
    },
    /// The lookup budget elapsed.
    Timeout,
    /// DNS RCODE SERVFAIL.
    ServFail,
    /// Socket or transport failure.
    Transport,
    /// Malformed, inconsistent or otherwise unacceptable answer.
    MalformedAnswer,
    /// The requested source address or plane cannot be used.
    SourceUnavailable,
    /// The requested mode or resolver profile is unsupported/unavailable.
    Unavailable,
    /// Ambiguous legacy system-resolver failure, not an authoritative denial.
    LegacyNotFound,
}

impl DnsError {
    /// Stable, low-cardinality code for errors and metrics.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidQuery => "dns-invalid-query",
            Self::NxDomain { .. } => "dns-nxdomain",
            Self::NoData { .. } => "dns-nodata",
            Self::Timeout => "dns-timeout",
            Self::ServFail => "dns-servfail",
            Self::Transport => "dns-transport",
            Self::MalformedAnswer => "dns-malformed-answer",
            Self::SourceUnavailable => "dns-source-unavailable",
            Self::Unavailable => "dns-unavailable",
            Self::LegacyNotFound => "dns-legacy-not-found",
        }
    }

    pub(crate) fn soa(self) -> Option<NegativeSoa> {
        match self {
            Self::NxDomain { soa } | Self::NoData { soa } => soa,
            _ => None,
        }
    }
}

/// Filter and stably order address records using the destination-only subset
/// of RFC 6724 section 6: default-table precedence (rule 6), smaller scope
/// (rule 8), then input order (rule 10). IPv4 uses the mapped-address policy.
///
/// Without a routing table and selected source addresses, the library cannot
/// apply reachability, source scope/label matching, deprecation, home-address,
/// native transport or longest source-prefix rules (1–5, 7, 9). Consumers must
/// handle failed connection attempts and may apply host-specific policy.
/// This is not complete RFC 6724 sorting or Happy Eyeballs.
pub fn order_dns_addresses(addresses: &mut Vec<SocketAddr>, family: AddressFamilyPolicy) {
    addresses.retain(|address| family.accepts(*address));
    addresses.sort_by_key(|address| destination_rank(address.ip()));
}

fn destination_rank(ip: IpAddr) -> (std::cmp::Reverse<u8>, u8) {
    let (precedence, scope) = match ip {
        IpAddr::V4(ip) => (
            35,
            if ip.is_loopback() || ip.is_link_local() {
                2
            } else {
                14
            },
        ),
        IpAddr::V6(ip) => {
            let s = ip.segments();
            let precedence = if ip.is_loopback() {
                50
            } else if ip.to_ipv4_mapped().is_some() {
                35
            } else if s[0] == 0x2002 {
                30
            } else if s[0] == 0x2001 && s[1] == 0 {
                5
            } else if s[0] & 0xfe00 == 0xfc00 {
                3
            } else if s[..6] == [0; 6] || s[0] & 0xffc0 == 0xfec0 || s[0] == 0x3ffe {
                1
            } else {
                40
            };
            let scope = if let Some(ip) = ip.to_ipv4_mapped() {
                if ip.is_loopback() || ip.is_link_local() {
                    2
                } else {
                    14
                }
            } else if ip.is_multicast() {
                (s[0] & 0xf) as u8
            } else if ip.is_loopback() || s[0] & 0xffc0 == 0xfe80 {
                2
            } else if s[0] & 0xffc0 == 0xfec0 {
                5
            } else {
                14
            };
            (precedence, scope)
        }
    };
    (std::cmp::Reverse(precedence), scope)
}
