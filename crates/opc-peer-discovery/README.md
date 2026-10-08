# opc-peer-discovery

## Purpose

`opc-peer-discovery` provides transport-neutral peer discovery and deterministic
endpoint selection for packet-core CNFs. It owns static-peer ordering,
resolver-result selection, redaction-safe evidence, negative caching, and a
pure stale-while-revalidate address cache.

The crate includes an address-mode resolver over an injected lookup port and
an async DNS client for A/AAAA and RFC 2782 SRV. S-NAPTR remains unavailable.

## API Shape

- Selection: `discover_and_select`, `PeerDiscoveryRequest`, `SelectedPeer`,
  `PeerCandidate`, `PeerCandidateSource`, `CandidateDecision`, and
  `PeerDiscoveryEvidence`.
- Resolver port: `PeerResolver`, `PeerResolverError`, `ServiceDiscoveryInput`,
  `ServiceDiscoveryMode`, `DiscoveryTarget`, `ResolvedPeers`, and
  `DiscoveryEvidence`.
- Address resolver: `AddressLookup`, `AddressLookupError`,
  `AddressPeerResolver`, and `StdAddressLookup`.
- Async DNS client: `DnsClient`, `DnsClientConfig`, `DnsClientResponse`,
  `DnsResponseSource`, `DnsQueryOutcome`, `DnsTransport`, and `DnsClientStats`.
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
- The legacy address resolver returns `PeerResolverError::Unavailable` for
  `Service` and `Snaptr`. `DnsClient` supports `Address` and `Service`.
- Selection is deterministic: lower priority wins, then higher weight, then a
  stable tie-break.
- `Debug` for targets, endpoints, and selected peers avoids raw host/address
  disclosure.

## Roadmap

- Add bounded S-NAPTR traversal using the DNS contracts.
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
TTL and monotonic observation time. NAPTR provenance can be represented before
its resolver exists. The cache uses the earliest absolute
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
`DnsAnswer::expires_at()` combines record provenance with any resolver freshness
bound, before cache caps, and must not be used as the cache's next wakeup time.
`with_freshness_bound(deadline)` only shortens known freshness and leaves record
TTLs intact. It cannot grant fresh lifetime to unknown-TTL answers.
Use `with_negative_freshness_bound(deadline)` for a denied component of a
partial positive answer: the cache also applies its tunable negative TTL cap.
This bounds positive freshness without granting negative-cache authority.

`DnsError` distinguishes authoritative NXDOMAIN, authoritative NODATA, timeout,
SERVFAIL, REFUSED, full client admission, service unavailability, exceeded bounds,
transport failure, malformed answers, unavailable source planes,
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
synthesize a denial across query modes or families. A sole SRV root target
is a separate explicit withdrawal: `ServiceUnavailable { expires_at }` carries
the SRV/CNAME deadline without an SOA. The same negative cap bounds it, a cold
entry is `Negative`, and a warm entry retains `Stale` data with that error.
Consumers should inspect `last_error` for this withdrawal when deciding whether
to reuse stale endpoints. Transient errors use
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
SRV applies priority and weighted selection before expanding target addresses;
its numeric-address tie-break is documented below.

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

`DnsClient` supplies asynchronous DNS wire I/O, actual record/SOA timing,
system or explicit server configuration, and source-bound UDP/TCP sockets.
Its SRV mode adds priority/weighted target selection and port handling. Bounded
S-NAPTR traversal is a follow-up using the same cache admission tokens and
original record observation times.

## Async DNS client

`DnsClient::new` validates one immutable `DnsClientConfig`. Set `servers`
explicitly, or load `DnsClientConfig::from_system()` during setup. The latter
performs a bounded synchronous read of `/etc/resolv.conf`; use a blocking
executor if necessary. `from_resolv_conf` is the pure parser for injected text.
Only nameservers and `options timeout:N attempts:N` are honored; the parser
uses the usual defaults of five seconds and two passes, capped at 30 seconds
and five passes. Missing servers fail closed, without inventing a localhost
fallback. Server names must be IP literals. This is a DNS client, not an NSS
replacement: it does not consult `/etc/hosts`, mDNS or resolver environment
variables.

Scoped link-local `nameserver` lines, such as `fe80::1%eth0`, are unsupported
and skipped; other usable servers are retained. With no usable server,
configuration returns `Unavailable`. Invalid unscoped values still fail closed.

Queries use the absolute `DnsQuery` name. Search lists, domain and ndots are
ignored so a peer identity cannot change with host search configuration or
leak into another zone ([RFC 1034 section 3.1](https://www.rfc-editor.org/rfc/rfc1034.html#section-3.1)).
Profile/plane IDs must exactly match the client configuration. New
configuration requires a new ID or removal of the old cache keys.

`resolve(&query, now).await` runs within an I/O/time-enabled Tokio runtime.
The callback supplies the caller's monotonic cache clock and is invoked for
each validated response and terminal transport failure. Publish `response.result` through the cache token
using a fresh clock observation. Do not hold the cache lock during I/O. If the
cache lease is shorter than the maximum client resolution duration, the driver
should also cancel the lookup at its lease deadline. SRV's total I/O budget is
`srv_refresh_timeout`, including the initial question, all retries and target
lookups. Its default value of zero selects `timeout * (servers.len() + 1)`,
capped at 300 seconds, using the final configuration passed to `DnsClient::new`.
For example, three servers with a five-second exchange timeout get 20 seconds,
so two silent leading servers leave time for the live server and target work.
A nonzero value overrides that calculation and must be 1 ms–300 seconds.
Use a lease longer than the effective budget with room for runtime scheduling
and publication; bounded decoding
and a stalled runtime or clock callback are not hard real-time guarantees.
Schedule subsequent work
from `DnsCacheStatus::fresh_until`, `retry_at` and the in-flight refresh state.
Successful zero or unknown TTLs use the cache's separate refresh interval:
five seconds by default, with equal jitter from 2.5 to 5 seconds. The client
does not own a refresh loop. The separate, redacted
`response.sources` identifies the final responding server, question owner,
record type, transport and observation time for each question, including negative
and RCODE results. Failures without a validated response have no source.
Raw server addresses and question owners are for programmatic access, never diagnostics.
`response.outcomes` exposes a redacted terminal result and observation time for
each resolved family, including timeouts that have no response source. SRV mode
also reports its initial question and each visited target's requested families,
including additional data, budget failures and alias rejection. Partial success
is visible there even though the combined result is positive.

The client sends UDP with a root OPT advertising 1232 bytes by default,
following [RFC 6891 sections 6.1 and 6.2](https://www.rfc-editor.org/rfc/rfc6891.html#section-6).
FORMERR retries once without OPT only when the echoed question matches. A
questionless FORMERR is dropped under the strict RFC 5452 matching rule and
cannot trigger fallback. A validated TC response retries TCP at the
same configured server, with the length prefix from
[RFC 1035 section 4.2.2](https://www.rfc-editor.org/rfc/rfc1035.html#section-4.2.2)
and [RFC 7766 sections 4–5](https://www.rfc-editor.org/rfc/rfc7766.html#section-4).
Length and query bytes are submitted together, following
[RFC 7766 section 8](https://www.rfc-editor.org/rfc/rfc7766.html#section-8).
Fallback shares the original server-attempt deadline; it cannot extend the
budget. Each exchange opens fresh sockets and uses OS randomness for the full
query-ID range. Binding port zero delegates source-port selection to the host's
ephemeral allocator. On Linux this honors `ip_local_port_range` and
`ip_local_reserved_ports`, so operators can reserve ports for other services
([kernel IP sysctl documentation](https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html#ip-local-port-range-2-integers)).
Ports below 1024 are refused. Address-in-use and permission-denied bind errors
retry with a fresh socket, within 32 attempts. Port unpredictability depends on
the kernel's allocator; Linux behavior is exercised by the loopback tests.
UDP sockets bind a concrete
local address, selected through the route if none is configured. Replies must
match remote address/port, ID, and the case-insensitive question name/type/class
([RFC 5452 sections 9.1–9.2](https://www.rfc-editor.org/rfc/rfc5452.html#section-9)).
Mismatch counters contain no query or address labels. No packet capture or raw
backend error is logged.

`local_address` binds UDP and TCP; incompatible server families fail with
`SourceUnavailable`. Linux additionally supports `interface` through
`SO_BINDTODEVICE`. Missing interfaces and permission failures are typed source
errors; the client never silently retries unbound. Kernels before Linux 5.7
require `CAP_NET_RAW` for interface binding. Other targets support local
IP binding but reject interface binding explicitly. FreeBSD and Apple are
compile-checked; runtime qualification remains Linux-only.

CNAME traversal is limited to records in the answer. It rejects loops,
conflicting targets, and simultaneous alias/data at one owner. It never follows
referrals or contacts NS/glue addresses. Each candidate retains its complete
CNAME-to-address chain, whose earliest expiry determines freshness
([RFC 1034 section 3.6.2](https://www.rfc-editor.org/rfc/rfc1034.html#section-3.6.2),
[RFC 2181 section 10.1](https://www.rfc-editor.org/rfc/rfc2181.html#section-10.1)).
Configured servers' inconsistent RRset TTLs are normalized to the lowest
effective TTL under [RFC 2181 sections 5.2 and 8](https://www.rfc-editor.org/rfc/rfc2181.html#section-5.2),
with the high-bit rule applied before comparison. SOA timing is accepted only
from an enclosing authority zone and retains any earlier alias deadline;
negatives without such an SOA remain uncacheable. NS-only referrals are
unavailable, not NODATA ([RFC 2308 sections 2.2 and 5](https://www.rfc-editor.org/rfc/rfc2308.html#section-5)).
A CNAME chain ending without terminal data or an SOA returns uncacheable
NODATA. The stub does not issue another query for that canonical name; it
expects the configured recursive server to complete the chain.

Address mode with dual stack queries A then AAAA. It returns any usable family even if the other
fails, orders all usable candidates with the documented destination-only policy,
then retains the first 16. A partial result is bounded by the failed family's
observed SOA expiry after a denial, or `partial_failure_ttl` after a failure
or SOA-less denial. At publication, partial SOA denials also obey the cache's
negative TTL cap (three hours by default, tunable through `with_ttl_caps`),
as well as the positive cap and record deadlines. The failure interval defaults
to 300 seconds and accepts zero or 1–300 seconds, following
[RFC 2308 sections 5, 7.1 and 7.2](https://www.rfc-editor.org/rfc/rfc2308.html#section-7).
The bound only shortens the positive records' lifetimes; zero makes the partial
answer immediately stale under the cache's existing paced-refresh policy.
The complete RRset determines each retained address's TTL, including records
excluded by the candidate cap. A caller requiring separate
family refresh schedules and last-good retention should use separate family
query keys. Retaining A and AAAA independently under a dual-stack key is a
follow-up; the current merged partial answer replaces the previous candidate
set, while its bounded freshness ensures the missing family is retried. If neither
family succeeds, a transient failure takes precedence over a denial; two
negatives use the earliest expiry, and either missing SOA prevents caching.
SERVFAIL, REFUSED, timeouts and unusable responses fail over in configured
server order. Source provenance retains only final per-family outcomes.
Families are queried sequentially, with no shared dead-server memory. A dead
first server before a working fallback costs one full timeout per family
(ten seconds total with the default five-second timeout).

| Resource | Default | Accepted bound |
|---|---:|---:|
| Servers | Explicit configuration | 1–8 |
| resolv.conf input | — | 64 KiB |
| Server-attempt deadline, including fallbacks | 5 seconds | 1 ms–30 seconds |
| Passes through all servers, per family | 2 | 1–5 |
| DNS response size | 65535 bytes | 512–65535 bytes |
| EDNS UDP payload | 1232 bytes | 512–4096, no larger than response bound |
| Records in one response | 128 | 128 |
| Expanded name / parser steps per name | — | 255 bytes / 256 steps |
| CNAME links per candidate | 15 | 0–15 |
| Temporary address candidates across both families | — | 256 |
| Address candidates per result | 16 | First 16 after ordering both families |
| In-flight resolutions across clones | 64 | 1–1024, excess returns `Busy` |
| Discarded messages per exchange | 32 | 1–1024 |
| Ephemeral port bind attempts per socket | 32 | 32 |
| Partial failure freshness interval | 300 seconds | Zero or 1–300 seconds |

A dual-stack call makes at most `2 * attempts * servers.len()` server attempts.
There is no internal task or waiting queue. Cancellation drops sockets and
releases admission immediately. Process exit/crash closes sockets; a new
process opens fresh ones without durable state, node cleanup, or operator
action. Configuration can be replaced live using a new client and identity.
The library neither owns nor terminates application sessions.

The wire codec deliberately covers the bounded stub-client subset. It validates
compression against previously decoded label boundaries, parses legacy
name-bearing RDATA for those boundaries, and skips unknown length-delimited
records/options. Wire names follow [RFC 2181 section 11](https://www.rfc-editor.org/rfc/rfc2181.html#section-11):
binary labels in unrelated owners and unused name-bearing fields, including
SOA RNAME, are accepted after framing validation. Such owners cannot match an
ASCII query. Caller names still follow the public ASCII `DnsName` contract;
a required CNAME target outside that contract is unusable. Literal dots inside
wire labels cannot forge label boundaries. Pointer targets inside unsupported
opaque RDATA are unusable.
There is **no DNSSEC validation**, including no trust in the AD bit. S-NAPTR,
DNS over TLS and DNS over HTTPS are separate work.

The deterministic suite uses loopback fake servers and spec-authored wire
fixtures, including malformed inputs. No test contacts a system or public DNS
server. [ADR 0031](../../docs/adr/0031-source-bound-dns-client.md) records the
codec and dependency decisions.

## SRV service discovery

For `ServiceDiscoveryMode::Service`, use the complete
`_service._proto.domain.` as `DiscoveryTarget`. The DNS service label is
separate from the operator's `PeerLabel`. The protocol must match `Tcp`, `Udp`
or `Sctp`. Domain and target host labels use ASCII letters, digits and hyphens,
with no leading/trailing hyphen or IP literal; leading digits are accepted
([RFC 1123 section 2.1](https://www.rfc-editor.org/rfc/rfc1123.html#section-2.1)).
No search expansion occurs. The final "else" branch of
[RFC 2782's Usage rules](https://www.rfc-editor.org/rfc/rfc2782.html) describes
an A lookup of the domain when SRV data is absent. Callers needing that fallback
issue an explicit Address-mode query with the domain and default service port.

The client orders lower priorities first. Within each priority, it shuffles
the initial order, places zero-weight records first, draws inclusively from
zero to the sum of weights, selects the first running sum at least that draw,
and repeats without replacement. This implements
[RFC 2782's Priority, Weight and Usage rules](https://www.rfc-editor.org/rfc/rfc2782.html),
including the small chance for a zero-weight record to precede positive weights.
All-zero groups are shuffled. Duplicate RRs do not multiply a target's weight.
`resolve_with_seed(&query, now, seed)` gives repeatable selection independent
of RR wire order; `resolve` seeds selection from OS entropy. Query IDs use
independent OS entropy; source ports follow kernel allocation policy. Candidate priority preserves
SRV priority; candidate weight encodes the chosen order for the deterministic
legacy selector and is not the raw SRV weight.
The weighted draw happens once per refresh. Selections from the same cached
answer reuse its first target until the next refresh; the draw distributes
load across independently refreshed clients, rather than per connection.

Endpoints use the SRV port; `default_port` is ignored. Port-zero records are
skipped because zero is reserved ([RFC 6335 section 6](https://www.rfc-editor.org/rfc/rfc6335.html#section-6)).
A single root target returns `ServiceUnavailable { expires_at }`, using the
minimum SRV and service-owner CNAME deadline. The cache applies its negative
TTL cap and schedules `retry_at` at that bounded deadline. Expired, zero or
high-bit TTLs grant no negative lifetime and use paced failure retries.
An unusable host name or a root mixed with other targets skips only that
record; structurally malformed messages still fail validation. Targets must
not be aliases. Receivers decompress SRV targets under the normal pointer
bounds, following [RFC 3597 section 4](https://www.rfc-editor.org/rfc/rfc3597.html#section-4),
which covers legacy senders despite RFC 2782's sender restriction. A CNAME
invalidates that whole target, including previously obtained addresses from
another family. Other targets can still succeed. Aliases at the service owner
use the bounded in-answer traversal, limited to 14 links to reserve provenance
slots for SRV and A/AAAA.

Exact-target IN A/AAAA additional records are used first. Missing families
use fresh queries to configured servers with the same profile, plane and
transport validation. Repeated target names reuse address work across ports.
Additional data has the lowest DNS credibility rank
([RFC 2181 section 5.4.1](https://www.rfc-editor.org/rfc/rfc2181.html#section-5.4.1)).
This stub trusts its configured recursive server after strict response matching:
that server already supplies the SRV targets themselves. An exact target may
lie outside the service's zone; its additional addresses are used only for this
service result, never to populate another cache key or nominate a DNS server.
Address order within a target uses destination precedence/scope and preserves
the server's order for ties ([RFC 6724 section 6, rule 10](https://www.rfc-editor.org/rfc/rfc6724.html#section-6)),
so DNS address rotation is retained. Target selection order always takes
precedence over address ordering. Return at most 16 distinct endpoints and stop
starting work when the selected prefix can fill that cap. Already-started
lookups finish within the overall deadline and retain their outcomes.
Ordinary per-family or per-target failures retain
other usable addresses. Such partial successes inherit the address client's
freshness bound: `partial_failure_ttl` (at most five minutes) after a transient
or local failure, or the SOA deadline after a denial. Partial SOA denials also
obey the cache's negative TTL cap at publication. Target outcomes preserve
the original error; an alias invalidates any earlier success for that target.
A target NXDOMAIN/NODATA cannot confer negative-cache
authority on the service query; service-question negatives use the existing
RFC 2308 handling. If no target is usable, return a typed failure and let the
cache retain last-good data with paced retries.

Each candidate retains the complete service-alias, SRV and address chain.
The full SRV RRset supplies its minimum TTL before deduplication, and address
RRsets retain their own minima before truncation (RFC 2181 section 5.2).
Additional data shares the initial response observation; fresh address replies
retain their later observations. Neither step restarts the SRV lifetime.
`fresh_until` includes the earliest chain deadline and the configured cache cap.

| SRV resource | Default | Accepted bound |
|---|---:|---:|
| Distinct valid SRV records expanded after ordering | 32 | 1–128 |
| Distinct target names expanded per refresh | 16 | 1–32 |
| Address lookups per refresh | 32 | 0–64 |
| Concurrent target exchanges per refresh | 4 | 1–32 |
| Overall SRV I/O budget | Automatic: timeout × (servers + 1), capped at 300 s | 0 (automatic) or 1 ms–300 s |
| Memoized addresses per target | 16 | 16 |
| Final candidates / records per candidate | 16 / 16 | 16 / 16 |
| Retained terminal response sources | — | 1 + address lookup budget |
| Retained terminal resolution outcomes | — | 1 + 2 × distinct-target limit |

The complete valid SRV RRset is ordered first, within the parser's 128-record
message limit. Record and target limits cap expansion of that order; larger
pools still return candidates. `skipped_srv_records` and `skipped_srv_targets`
report distinct valid records and targets omitted by work/candidate limits.
Records that were attempted and failed are not counted as skipped. The address
budget is reserved in target/family order and stops further queries while
preserving available candidates; zero permits additional data only. A fully
budget-blocked target is counted as skipped and records `LimitExceeded` family
outcomes. Aliases or expiry may leave reserved allowance unused.

Targets run concurrently within `max_srv_concurrent_targets`; each target's
missing families run A then AAAA. A free slot is immediately reused. A server
that times out moves behind other configured servers in subsequent SRV lookups
and refreshes, shared by clones of the same client. It remains eligible if those
servers fail. Each hint expires five minutes after that server's latest timeout,
using Tokio's monotonic clock independently of the cache clock; a matched reply
clears it sooner. This bounded ordering hint never supplies a cached DNS failure
for another name or removes a server from failover ([RFC 2308 section 7.2](https://www.rfc-editor.org/rfc/rfc2308.html#section-7.2)).
Address-mode queries retain configured server order.
Retry counts still bound amplification to
`(1 + max_srv_address_lookups) * attempts * servers.len()` server attempts,
while `srv_refresh_timeout` bounds the total I/O duration. At that deadline,
completed families survive and unfinished selected families receive `Timeout`
outcomes with the normal partial-failure freshness bound. Logical result and
outcome ordering is independent of completion order.

One admission permit covers the entire refresh. Open DNS sockets can reach
`max_in_flight * max_srv_concurrent_targets` (256 with the defaults).
Cancellation closes all
its sockets and releases that permit. No worker task, new dependency,
durable state or operator cleanup is introduced.
[ADR 0032](../../docs/adr/0032-bounded-dns-srv.md) records these choices.

For the next S-NAPTR slice, an "S" flag's REPLACEMENT is the exact SRV query
name ([RFC 3958 section 2.2.3](https://www.rfc-editor.org/rfc/rfc3958.html#section-2.2.3));
it need not have the `_service._proto.domain.` shape. Keep that validation at
the direct Service-mode entry point, and reuse the generic SRV decoder and
ordering for S-NAPTR replacements. NAPTR traversal and its own chain timing
and work bounds remain follow-up work.
