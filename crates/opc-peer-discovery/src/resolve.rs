//! Address-mode ([`ServiceDiscoveryMode::Address`]) resolver implementation.
//!
//! [`AddressPeerResolver`] satisfies the [`PeerResolver`] port for A/AAAA
//! resolution of FQDN peers, so any CNF may configure an AAA, S2b, or other
//! packet-core peer by hostname instead of an IP literal.
//!
//! The DNS lookup itself is a small injected port ([`AddressLookup`]) so the
//! resolver is deterministic under test (a fake lookup, no real network) and so
//! the blocking system resolver ([`StdAddressLookup`]) can be swapped for an
//! async/TTL-aware backend without touching the resolver logic. Because
//! [`StdAddressLookup`] blocks (`getaddrinfo` has no cancellation), callers MUST
//! drive it off the async executor (e.g. `spawn_blocking` at warmup with an
//! outer deadline) and cache the result — never on a per-request hot path.
//!
//! Service ([`ServiceDiscoveryMode::Service`], DNS SRV) and S-NAPTR
//! ([`ServiceDiscoveryMode::Snaptr`], TS 29.303 / RFC 6408) modes use
//! [`crate::DnsClient`]. This address adapter reports [`PeerResolverError::Unavailable`]
//! for those modes.
//!
//! Redaction: the resolver never logs or embeds the target hostname or resolved
//! addresses; failures surface only as the crate's stable [`PeerResolverError`]
//! kinds, and candidate `Debug` is the crate's redacted endpoint key.

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use crate::{
    PeerCandidate, PeerResolver, PeerResolverError, ResolvedPeers, ServiceDiscoveryInput,
    ServiceDiscoveryMode,
};

/// Upper bound on resolved addresses accepted from one lookup, to bound the
/// candidate set a single FQDN can expand into.
const MAX_RESOLVED_ADDRESSES: usize = 16;

/// Negative-cache TTL applied when a lookup returns no records, so the caller's
/// [`PeerNegativeCache`](crate::PeerNegativeCache) suppresses repeated failing
/// lookups without pinning a stale negative result: a refresh retries after the
/// TTL rather than failing closed permanently.
const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_secs(5);

/// Stable, redaction-safe failure kinds from an [`AddressLookup`].
///
/// These mirror the crate's plain-enum resolver-error idiom
/// ([`PeerResolverError`]): a small, stable set of kinds with no embedded
/// hostname or address material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddressLookupError {
    /// The lookup exceeded its time budget.
    Timeout,
    /// The lookup completed but returned no usable address.
    NotFound,
    /// The resolver backend was unavailable (e.g. no resolver configured).
    Unavailable,
}

/// Injected host-to-address lookup port.
///
/// Implementations resolve a host label plus port to zero or more socket
/// addresses. The `timeout` is a best-effort budget; backends that cannot honor
/// it (the blocking system resolver) rely on the caller's outer deadline.
pub trait AddressLookup {
    /// Resolve `host`:`port` to socket addresses within `timeout`.
    ///
    /// # Errors
    ///
    /// Returns [`AddressLookupError`] on timeout, no-records, or backend
    /// unavailability. Error values are redaction-safe.
    fn lookup(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<Vec<SocketAddr>, AddressLookupError>;
}

/// Blocking system-resolver (`getaddrinfo`) lookup.
///
/// Legacy system adapter: supplies no DNS TTL, SOA, CNAME provenance or
/// reliable DNS error classification. [`AddressPeerResolver::resolve_dns`]
/// exposes that absence explicitly through the new DNS contracts.
///
/// `getaddrinfo` has no cancellation, so `timeout` is not enforced here; callers
/// MUST run this off the async executor with their own deadline.
#[derive(Debug, Clone, Copy, Default)]
pub struct StdAddressLookup;

impl AddressLookup for StdAddressLookup {
    fn lookup(
        &self,
        host: &str,
        port: u16,
        _timeout: Duration,
    ) -> Result<Vec<SocketAddr>, AddressLookupError> {
        match (host, port).to_socket_addrs() {
            Ok(addrs) => {
                let resolved: Vec<SocketAddr> = addrs.collect();
                if resolved.is_empty() {
                    Err(AddressLookupError::NotFound)
                } else {
                    Ok(resolved)
                }
            }
            // getaddrinfo failures do not portably distinguish NXDOMAIN from a
            // resolver outage; treat both as not-found so the negative cache
            // applies and a later refresh retries rather than pinning a hard
            // failure.
            Err(_error) => Err(AddressLookupError::NotFound),
        }
    }
}

/// [`PeerResolver`] implementation for A/AAAA (address) discovery.
///
/// Resolves the [`ServiceDiscoveryInput`] target through the injected
/// [`AddressLookup`] and returns one resolved [`PeerCandidate`] per address.
/// Non-address discovery modes (SRV, S-NAPTR) report
/// [`PeerResolverError::Unavailable`]; use [`crate::DnsClient`] for those modes.
pub struct AddressPeerResolver<L> {
    lookup: L,
}

impl<L: AddressLookup> AddressPeerResolver<L> {
    /// Build a resolver over an injected [`AddressLookup`].
    #[must_use]
    pub fn new(lookup: L) -> Self {
        Self { lookup }
    }

    /// Adapt the legacy address lookup to the DNS contracts without inventing
    /// TTLs or authoritative negative results. Filters by address family before
    /// the 16-candidate cap and preserves the system resolver's source-aware
    /// ordering. The original [`PeerResolver`] path retains its existing
    /// lookup ordering and legacy five-second negative retry.
    ///
    /// The default profile/plane denotes the system resolver. It cannot bind
    /// DNS sockets to a source plane or configure an alternate resolver.
    /// `StdAddressLookup` remains blocking and cannot enforce cancellation.
    ///
    /// # Errors
    /// Returns typed [`crate::DnsError`] codes. Non-default source planes are
    /// refused, never silently resolved via another source.
    pub fn resolve_dns(
        &mut self,
        query: &crate::DnsQuery,
        timeout: Duration,
    ) -> Result<crate::DnsAnswer, crate::DnsError> {
        use crate::{DnsAnswer, DnsCandidate, DnsError};
        if !query.source_plane().as_str().is_empty() {
            return Err(DnsError::SourceUnavailable);
        }
        if !query.resolver_profile().as_str().is_empty()
            || query.input().mode != ServiceDiscoveryMode::Address
        {
            return Err(DnsError::Unavailable);
        }
        let input = query.input();
        let port = input.default_port.ok_or(DnsError::InvalidQuery)?;
        let mut addresses = self
            .lookup
            .lookup(query.name().as_str(), port, timeout)
            .map_err(|error| match error {
                AddressLookupError::Timeout => DnsError::Timeout,
                AddressLookupError::NotFound => DnsError::LegacyNotFound,
                AddressLookupError::Unavailable => DnsError::Unavailable,
            })?;
        addresses.retain(|address| query.address_family().accepts(*address));
        if addresses.is_empty() {
            return Err(DnsError::LegacyNotFound);
        }
        DnsAnswer::new(
            addresses
                .into_iter()
                .take(MAX_RESOLVED_ADDRESSES)
                .enumerate()
                .map(|(index, endpoint)| {
                    let weight = crate::dns::selection_weight(index);
                    DnsCandidate::without_ttl(PeerCandidate::resolved(
                        input.service.clone(),
                        endpoint,
                        input.transport,
                        input.mode,
                        0,
                        weight,
                    ))
                })
                .collect(),
        )
    }
}

impl<L: AddressLookup> PeerResolver for AddressPeerResolver<L> {
    fn resolve(
        &mut self,
        input: &ServiceDiscoveryInput,
        timeout: Duration,
    ) -> Result<ResolvedPeers, PeerResolverError> {
        // This adapter only resolves addresses. SRV and S-NAPTR require the
        // separate DNS client; do not reinterpret them as address questions.
        if input.mode != ServiceDiscoveryMode::Address {
            return Err(PeerResolverError::Unavailable);
        }
        // Address resolution needs a port to form an endpoint; a missing default
        // port is a caller construction error, not a DNS outcome.
        let port = input.default_port.ok_or(PeerResolverError::InvalidAnswer)?;

        let addresses = self
            .lookup
            .lookup(input.target.as_str(), port, timeout)
            .map_err(|error| match error {
                AddressLookupError::Timeout => PeerResolverError::Timeout,
                AddressLookupError::Unavailable => PeerResolverError::Unavailable,
                AddressLookupError::NotFound => PeerResolverError::NotFound {
                    negative_ttl: DEFAULT_NEGATIVE_TTL,
                },
            })?;

        let candidates: Vec<PeerCandidate> = addresses
            .into_iter()
            .take(MAX_RESOLVED_ADDRESSES)
            .enumerate()
            .map(|(index, endpoint)| {
                // A/AAAA records carry no DNS priority, so assign a uniform
                // priority and a stable descending weight by resolution order:
                // multi-address results then select deterministically.
                let weight = crate::dns::selection_weight(index);
                PeerCandidate::resolved(
                    input.service.clone(),
                    endpoint,
                    input.transport,
                    ServiceDiscoveryMode::Address,
                    0,
                    weight,
                )
            })
            .collect();

        if candidates.is_empty() {
            return Err(PeerResolverError::NotFound {
                negative_ttl: DEFAULT_NEGATIVE_TTL,
            });
        }
        Ok(ResolvedPeers::new(candidates))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DiscoveryTarget, PeerCandidateSource, PeerLabel, PeerTransport};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    /// Deterministic fake lookup: maps a host to a fixed result, never touching
    /// the network.
    #[derive(Default)]
    struct FakeLookup {
        answers: HashMap<String, Result<Vec<SocketAddr>, AddressLookupError>>,
    }

    impl FakeLookup {
        fn with(mut self, host: &str, result: Result<Vec<SocketAddr>, AddressLookupError>) -> Self {
            self.answers.insert(host.to_string(), result);
            self
        }
    }

    impl AddressLookup for FakeLookup {
        fn lookup(
            &self,
            host: &str,
            _port: u16,
            _timeout: Duration,
        ) -> Result<Vec<SocketAddr>, AddressLookupError> {
            self.answers
                .get(host)
                .cloned()
                .unwrap_or(Err(AddressLookupError::NotFound))
        }
    }

    fn addr(last_octet: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last_octet)), port)
    }

    fn address_input(host: &str, port: u16) -> ServiceDiscoveryInput {
        ServiceDiscoveryInput::new(
            PeerLabel::new("aaa-primary").expect("valid label"),
            DiscoveryTarget::new(host),
            ServiceDiscoveryMode::Address,
            PeerTransport::Sctp,
            Some(port),
        )
    }

    #[test]
    fn resolves_multi_address_fqdn_into_ordered_resolved_candidates() {
        let host = "aaa.epc.mnc001.mcc001.3gppnetwork.org";
        let mut resolver = AddressPeerResolver::new(
            FakeLookup::default().with(host, Ok(vec![addr(10, 3868), addr(11, 3868)])),
        );

        let resolved = resolver
            .resolve(&address_input(host, 3868), Duration::from_secs(1))
            .expect("address resolution succeeds");

        assert_eq!(resolved.candidates.len(), 2);
        // Every candidate is a resolver candidate (not static) at the A/AAAA mode.
        for candidate in &resolved.candidates {
            assert_eq!(
                candidate.source,
                PeerCandidateSource::Resolver(ServiceDiscoveryMode::Address)
            );
        }
        // Resolution order is stable via descending weight.
        assert_eq!(resolved.candidates[0].endpoint, addr(10, 3868));
        assert_eq!(resolved.candidates[1].endpoint, addr(11, 3868));
        assert!(resolved.candidates[0].weight > resolved.candidates[1].weight);
    }

    #[test]
    fn empty_and_not_found_lookups_map_to_not_found_with_negative_ttl() {
        let host = "unknown.example.org";
        let mut resolver = AddressPeerResolver::new(
            FakeLookup::default().with(host, Err(AddressLookupError::NotFound)),
        );
        let error = resolver
            .resolve(&address_input(host, 3868), Duration::from_secs(1))
            .expect_err("not-found lookup is an error");
        assert_eq!(
            error,
            PeerResolverError::NotFound {
                negative_ttl: DEFAULT_NEGATIVE_TTL
            }
        );

        // An Ok(empty) lookup is also not-found (defensive: no usable endpoint).
        let mut empty_resolver =
            AddressPeerResolver::new(FakeLookup::default().with(host, Ok(Vec::new())));
        let empty_error = empty_resolver
            .resolve(&address_input(host, 3868), Duration::from_secs(1))
            .expect_err("empty lookup is not-found");
        assert!(matches!(empty_error, PeerResolverError::NotFound { .. }));
    }

    #[test]
    fn lookup_error_kinds_map_to_stable_resolver_errors() {
        let host = "peer.example.org";
        for (lookup_error, expected) in [
            (AddressLookupError::Timeout, PeerResolverError::Timeout),
            (
                AddressLookupError::Unavailable,
                PeerResolverError::Unavailable,
            ),
        ] {
            let mut resolver =
                AddressPeerResolver::new(FakeLookup::default().with(host, Err(lookup_error)));
            let error = resolver
                .resolve(&address_input(host, 3868), Duration::from_secs(1))
                .expect_err("lookup error surfaces");
            assert_eq!(error, expected);
        }
    }

    #[test]
    fn non_address_modes_are_unavailable_through_the_address_adapter() {
        let host = "peer.example.org";
        for mode in [ServiceDiscoveryMode::Service, ServiceDiscoveryMode::Snaptr] {
            let input = ServiceDiscoveryInput::new(
                PeerLabel::new("aaa-primary").expect("valid label"),
                DiscoveryTarget::new(host),
                mode,
                PeerTransport::Sctp,
                Some(3868),
            );
            let mut resolver = AddressPeerResolver::new(
                FakeLookup::default().with(host, Ok(vec![addr(10, 3868)])),
            );
            let error = resolver
                .resolve(&input, Duration::from_secs(1))
                .expect_err("non-address modes are not supported yet");
            assert_eq!(error, PeerResolverError::Unavailable);
        }
    }

    #[test]
    fn address_input_without_default_port_is_invalid_answer() {
        let host = "peer.example.org";
        let input = ServiceDiscoveryInput::new(
            PeerLabel::new("aaa-primary").expect("valid label"),
            DiscoveryTarget::new(host),
            ServiceDiscoveryMode::Address,
            PeerTransport::Sctp,
            None,
        );
        let mut resolver =
            AddressPeerResolver::new(FakeLookup::default().with(host, Ok(vec![addr(10, 3868)])));
        let error = resolver
            .resolve(&input, Duration::from_secs(1))
            .expect_err("address mode without a port cannot form an endpoint");
        assert_eq!(error, PeerResolverError::InvalidAnswer);
    }

    #[test]
    fn resolved_candidate_count_is_bounded() {
        let host = "many.example.org";
        let many: Vec<SocketAddr> = (0..(MAX_RESOLVED_ADDRESSES as u16 + 8))
            .map(|i| addr(u8::try_from(i % 250).unwrap_or(0), 3868))
            .collect();
        let mut resolver = AddressPeerResolver::new(FakeLookup::default().with(host, Ok(many)));
        let resolved = resolver
            .resolve(&address_input(host, 3868), Duration::from_secs(1))
            .expect("resolution succeeds");
        assert_eq!(resolved.candidates.len(), MAX_RESOLVED_ADDRESSES);
    }
}
