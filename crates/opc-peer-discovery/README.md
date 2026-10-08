# opc-peer-discovery

## Purpose

`opc-peer-discovery` provides transport-neutral peer discovery and deterministic
endpoint selection for packet-core CNFs. It owns static-peer ordering,
resolver-result selection, redaction-safe evidence, negative caching, and a
pure stale-while-revalidate address cache.

The crate includes an address-mode resolver over an injected lookup port.
Service/SRV and S-NAPTR modes are modeled but currently report unavailable.

## API Shape

- Selection: `discover_and_select`, `PeerDiscoveryRequest`, `SelectedPeer`,
  `PeerCandidate`, `PeerCandidateSource`, `CandidateDecision`, and
  `PeerDiscoveryEvidence`.
- Resolver port: `PeerResolver`, `PeerResolverError`, `ServiceDiscoveryInput`,
  `ServiceDiscoveryMode`, `DiscoveryTarget`, `ResolvedPeers`, and
  `DiscoveryEvidence`.
- Address resolver: `AddressLookup`, `AddressLookupError`,
  `AddressPeerResolver`, and `StdAddressLookup`.
- Caches: `PeerNegativeCache`, `PeerAddressCache`, `CachedPeers`,
  `DiscoveryCacheKey`, and `PeerDiscoveryTime`.
- DNS identity and provenance: `DnsQuery`, `DnsName`, `DnsCacheKey`,
  `ResolverProfileId`, `SourcePlaneId`, `AddressFamilyPolicy`, `DnsAnswer`,
  `DnsCandidate`, `DnsRecord`, `DnsRecordType`, and `NegativeSoa`.
- DNS cache driving: `DnsCache`, `DnsCacheStatus`, `DnsCachedResult`,
  `DnsRetryPolicy`, `DnsRefresh`, and `DnsRefreshToken`.
- DNS failures: `DnsError` and `DnsCacheError` expose stable, redacted codes.
- Identity and transport: `PeerLabel`, `PeerTransport`, and
  `TELCO_PEER_DISCOVERY_PROFILE`.
- Errors: `PeerDiscoveryError` and `PeerDiscoveryErrorCode` carry only safe
  labels, stable keys, and stable reason codes.

## Usage

```rust,no_run
use std::time::Duration;

use opc_peer_discovery::{
    discover_and_select, PeerCandidate, PeerDiscoveryRequest, PeerDiscoveryTime,
    PeerLabel, PeerNegativeCache, PeerResolver, PeerResolverError, PeerTransport,
    ResolvedPeers, ServiceDiscoveryInput,
};

struct NoopResolver;

impl PeerResolver for NoopResolver {
    fn resolve(
        &mut self,
        _input: &ServiceDiscoveryInput,
        _timeout: Duration,
    ) -> Result<ResolvedPeers, PeerResolverError> {
        Err(PeerResolverError::Unavailable)
    }
}

let request = PeerDiscoveryRequest {
    static_peers: vec![PeerCandidate::static_peer(
        PeerLabel::new("pgw-a").unwrap(),
        "127.0.0.1:2123".parse().unwrap(),
        PeerTransport::Udp,
        10,
        100,
    )],
    now: PeerDiscoveryTime::from_millis(1_000),
    ..PeerDiscoveryRequest::default()
};

let mut resolver = NoopResolver;
let mut negative_cache = PeerNegativeCache::default();
let selected = discover_and_select(request, &mut resolver, &mut negative_cache).unwrap();
assert_eq!(selected.label.as_str(), "pgw-a");
```

## Relationships

- Product crates inject resolvers for DNS, NRF, static inventory, or tests.
- `StdAddressLookup` uses the blocking system resolver; async callers should
  run it off the request hot path and cache results with `PeerAddressCache`.
- SBI/NRF-specific discovery logic belongs in `opc-sbi`; this crate remains
  transport-neutral.

## Status And Limits

- `AddressPeerResolver` supports `ServiceDiscoveryMode::Address` with a default
  port and caps one lookup to 16 candidates.
- `Service` and `Snaptr` modes are not implemented yet and return
  `PeerResolverError::Unavailable`.
- Selection is deterministic: lower priority wins, then higher weight, then a
  stable tie-break.
- `Debug` for targets, endpoints, and selected peers avoids raw host/address
  disclosure.

## Roadmap

- Add SRV and S-NAPTR resolvers without changing the resolver port.
- Keep asynchronous lookup driving outside the pure selection/cache core.
- Preserve redaction-safe evidence as new resolver modes are added.

## Verification

```sh
cargo test -p opc-peer-discovery
```

## DNS contracts and cache

The additive DNS API uses `DnsQuery`, `DnsAnswer`, `DnsError` and `DnsCache`.
The original `ServiceDiscoveryInput`, `ResolvedPeers`, `PeerResolver`,
`PeerNegativeCache` and `PeerAddressCache` interfaces retain their behavior.
The latter is a **legacy caller-TTL cache** with oldest-entry eviction; use
`DnsCache` when a consumer needs the DNS contracts below.

`DnsQuery::new` canonicalizes ASCII DNS names to lowercase with a terminal dot.
Its exact cache identity includes the query, discovery mode, service,
transport, default port, opaque resolver profile, opaque source plane, and
address-family policy. Equality compares all fields, not a digest. IDs identify
immutable caller-owned configurations; use a new ID or explicitly remove old
keys when configuration changes. DNS names are absolute: this API does not use
system search-domain expansion or perform IDNA conversion. Invalid caller names,
IP-literal queries and missing address-mode ports return `InvalidQuery`, separate
from malformed DNS answers. Configure IP literals as static peers.

A `DnsCandidate` retains the endpoint and every `DnsRecord` used to reach it,
in traversal order. Each record carries its canonical owner, type, remaining
TTL and monotonic observation time. CNAME, SRV and NAPTR provenance can be
represented before their resolvers exist. The cache uses the earliest absolute
expiry of every record in every candidate chain; completing a traversal never
restarts earlier TTLs. Zero TTL is immediately stale. A missing TTL remains
unknown and gains no fresh lifetime. High-bit record TTLs and SOA TTL-valued
fields are treated as zero under the conservative
[RFC 2181 section 8](https://www.rfc-editor.org/rfc/rfc2181.html#section-8)
policy. [RFC 8767 section 4](https://www.rfc-editor.org/rfc/rfc8767.html#section-4)
updates RFC 2181 to interpret high-bit TTLs as positive unsigned values.
This API keeps the older zero rule, which is permitted because a TTL is an
upper bound on caching, while adopting RFC 8767's cap guidance.
Timestamp overflow fails stale. The resolver is responsible for validating
wire responses and chain relationships;
these contracts do not authenticate DNS.

`DnsCache::with_ttl_caps` sets tunable positive and negative lifetime caps for
subsequent publications. Both caps clamp to 2^31 - 1 seconds, the largest
usable TTL under this API's conservative policy; even `Duration::MAX` keeps
ordinary answers cacheable. The positive default is seven days, recommended by
[RFC 8767 section 4](https://www.rfc-editor.org/rfc/rfc8767.html#section-4).
At publication the cache limits freshness to the earlier of the record-chain
deadline and publication time plus this cap. The cap does not rewrite record
provenance. This is an application endpoint cache, not a recursive DNS server
implementing RFC 8767's stale-answer protocol.

`DnsCacheStatus::fresh_until` exposes the effective positive deadline, including
the cap, and retains it after expiry or a failed refresh. It is `None` when no
positive answer exists; unknown TTL uses publication time and stays stale.
Use this deadline with `retry_at` and refresh state when scheduling cache work.
`DnsAnswer::expires_at()` describes uncapped record provenance and must not be
used as the cache's next wakeup time.

`DnsError` distinguishes authoritative NXDOMAIN, authoritative NODATA, timeout,
SERVFAIL, transport failure, malformed answers, unavailable source planes,
unavailable resolver/mode, and ambiguous legacy lookup failure. Only the stable
`code()` belongs in metric labels. The new DNS types' `Debug` output contains
codes, counts and timing, never names, endpoints or opaque configuration IDs.
Raw accessors are for resolver and connection logic, not diagnostics.

A cold authoritative denial is cached until the observed SOA timing expires:
`min(SOA TTL, SOA.MINIMUM)`, as specified by
[RFC 2308 sections 3 and 5](https://www.rfc-editor.org/rfc/rfc2308.html#section-5).
SOA observation time prevents a deferred result from gaining a fresh TTL.
The negative cap defaults to three hours, within the one-to-three-hour range in
[RFC 2308 section 5](https://www.rfc-editor.org/rfc/rfc2308.html#section-5),
and is always clamped to the positive cap. Its deadline is the earlier of the
SOA expiry and publication time plus the negative cap. A zero cap disables
fresh caching. For a denial reached through CNAMEs, the resolver must pass their
earliest absolute expiry to `NegativeSoa::with_chain_expiry`; this only shortens
the negative deadline. Absent SOA, expired chain timing and zero negative TTL
grant no negative cache lifetime. Negatives
are isolated by the complete query key; this cache deliberately does not
synthesize a denial across query modes or families. Transient errors use
bounded exponential retry with equal jitter (half to all of the current cap),
with default caps of 1–30 seconds. A caller can supply bounds and a seed for
deterministic clock tests. Configured base and cap never exceed five minutes,
the limit for failure suppression in
[RFC 2308 sections 7.1 and 7.2](https://www.rfc-editor.org/rfc/rfc2308.html#section-7).
Backoff resets after success or a cacheable authoritative denial.

Uncacheable negatives use transient backoff but stay `Miss`. A successful zero,
unknown or already-expired TTL answer remains `Stale` and uses an independent
refresh interval. `DnsCache::with_refresh_interval` sets it for subsequent
publications, defaulting to five seconds with equal jitter from half to all of
the interval (2.5–5 seconds by default). It is clamped to 1 ms–2^31 - 1 seconds
at millisecond precision. Changing it leaves existing retry deadlines and
failure backoff unchanged. Pacing is separate from freshness and negative
authority:
`refresh_due` cannot cause a same-instant retry loop after these outcomes.

A later error, including an authoritative denial, never overwrites a positive
last-good answer. `DnsCache::lookup` exposes fresh/stale status, stale age and
the last error. Positive entries have no retention deadline. The consumer must
call `remove` when it no longer needs a positive key. At capacity, admission
first reclaims expired cold failures with no answer or in-flight refresh.
Live negatives, live backoff and in-flight keys remain protected; if no slot
is available the new key is rejected. No capacity reclamation removes last-good
data. A reclaimed cold key leaves `refresh_due` and loses its last error;
`lookup` then reports `Miss` with no error. Drivers must retain their configured
key set separately and re-admit keys they still need. Constructors reject more
than 16 candidates per answer or 16 records per candidate, including its terminal
address record. These bounds limit retained
DNS payloads; unused vector capacity is discarded. Public enums and public-field
structs are non-exhaustive so later DNS slices can extend the contracts.

The cache is a deterministic state machine, with no threads or I/O. A driver:

1. Serializes access to `begin_refresh`, using a caller-owned lock if shared.
2. Launches I/O only for `DnsRefresh::Start`, after releasing that lock.
   `Pending` callers share the eventual cached answer; `Suppressed` means the
   answer is fresh or a retry/negative deadline remains in force.
3. Publishes through `finish_refresh` with the one-use token and current time.
   Errors retain last-good data. Late, foreign or removed-key tokens cannot
   publish. `refresh_due` or another admission reaps abandoned attempt leases
   as timeouts, so cancellation cannot permanently suppress a key.
4. Wakes its waiting callers and schedules due keys according to its runtime.
   Use `fresh_until` for fresh data and honor `retry_at` for failures and stale
   successes. A due key exposes `query()` for the next admission. Zero/unknown
   TTL answers are paced by the cache without granting fresh lifetime.
5. Re-admits missing configured keys after capacity reclamation. `refresh_due`
   scans only retained entries and cannot replace the driver's configured key set.

All times must share one monotonic domain. Runtime wakeups, background pacing,
shutdown and ownership of resolver sockets belong to the driver. The cache is
in-memory: process restart starts cold and requires no durable cleanup.

## Destination address policy

`order_dns_addresses` filters the requested families and applies the default
precedence table, smaller destination scope, and stable input-order tie-break
from [RFC 6724 section 6](https://www.rfc-editor.org/rfc/rfc6724.html#section-6)
(rules 6, 8 and 10). IPv4-mapped IPv6 addresses follow the IPv4 family policy.
IPv4 uses the IPv4-mapped precedence; loopback, transition,
ULA and deprecated prefixes retain their specified table entries. The legacy
adapter's DNS bridge preserves the system resolver's source-aware ordering,
filtering by family before its 16-address cap, and encodes the retained order
in candidate weights for the existing deterministic selector. It does not
apply the weaker destination-only sorter to the host's result.

This is a destination-only subset. Without a routing table and selected source
addresses, it cannot determine usability, matching source scope/label,
deprecation, home addresses, native transport, or source-prefix match
(rules 1–5, 7 and 9). It neither promises reachability nor implements Happy
Eyeballs. DNS backends must apply this helper (or an explicitly documented
host policy) to address RRsets, then truncate to `DnsAnswer::MAX_CANDIDATES`
before constructing their answer; record provenance stays attached to the
corresponding candidate. Wire parsers must map invalid record-owner names from
`DnsName::new` to `MalformedAnswer`, since those names came from a response.
SRV priority and weighted target selection are separate later work.

## Legacy system adapter and next slices

`AddressPeerResolver::resolve_dns` bridges `AddressLookup`, including
`StdAddressLookup`, to `DnsAnswer` with explicitly absent TTL/provenance. It
uses the canonical name, family filtering and host answer order; a legacy not-found result
is a transient `LegacyNotFound`, never authoritative NXDOMAIN or NODATA. The
system adapter cannot configure a resolver profile or source-bound sockets:
non-default profiles are unavailable and non-default planes return
`SourceUnavailable`. It still blocks in `getaddrinfo` and cannot cancel the
underlying call. Drive it off the executor with an outer budget.

The original `PeerResolver::resolve` path retains system answer ordering and
its five-second legacy not-found suppression for compatibility. That interval
is a retry policy, not an SOA-derived DNS negative TTL.

The next slice supplies asynchronous DNS wire I/O, actual record/SOA timing,
system or explicit server configuration, and source-bound UDP/TCP sockets.
Subsequent slices add SRV priority/weighted target selection and port handling,
then bounded S-NAPTR traversal. They should publish through the same cache
admission tokens and retain each record's original observation time.
