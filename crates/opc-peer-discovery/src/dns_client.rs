//! Bounded Tokio DNS stub client. The pure cache and legacy getaddrinfo bridge
//! do not own this client or its sockets.

use std::fmt;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, UdpSocket};
use tokio::sync::Semaphore;

use crate::dns_wire::{self, DecodeError, Message};
use crate::{
    AddressFamilyPolicy, DnsAnswer, DnsCandidate, DnsError, DnsQuery, DnsRecordType,
    PeerDiscoveryTime, ResolverProfileId, ServiceDiscoveryMode, SourcePlaneId,
};

const MAX_CONFIG_BYTES: usize = 65_536;
const MAX_SERVERS: usize = 8;
const PORT_BIND_ATTEMPTS: usize = 32;

#[path = "dns_order.rs"]
mod order;
#[path = "dns_snaptr.rs"]
mod snaptr;
#[path = "dns_srv.rs"]
mod srv;

/// Immutable configuration for one resolver profile and source plane.
///
/// Defaults provide bounds but no servers: supply explicit addresses or call
/// [`Self::from_system`]. No environment variable, search domain, referral or
/// glue record can introduce another server. Ports other than 53 are allowed
/// for explicitly configured proxies and loopback tests.
#[derive(Clone)]
#[non_exhaustive]
pub struct DnsClientConfig {
    /// One to eight configured recursive servers, in failover order.
    pub servers: Vec<SocketAddr>,
    /// One server attempt's total UDP/EDNS fallback/TCP budget (1 ms–30 s).
    pub timeout: Duration,
    /// Complete passes through the server list per record type (1–5).
    pub attempts: u8,
    /// Maximum freshness after a partial-family failure without an SOA
    /// (zero or 1–300 seconds, default 300). Zero makes partial answers immediately
    /// stale and uses the cache's refresh pacing. SOA denials use their observed
    /// negative deadline and the cache's negative TTL cap instead.
    pub partial_failure_ttl: Duration,
    /// Maximum DNS message size, excluding the TCP length prefix (512–65535).
    pub max_response_size: usize,
    /// Advertised EDNS UDP payload (512–4096, at most `max_response_size`).
    pub edns_payload_size: u16,
    /// Maximum CNAME links per answer (0–15); an address uses one more record.
    /// SRV reserves two terminal slots, so its service-owner chain is at most 14.
    pub max_cname_chain: usize,
    /// Simultaneous resolutions shared by all client clones (1–1024).
    /// Excess callers receive [`DnsError::Busy`]; there is no waiting queue.
    /// Open DNS sockets can reach `max_in_flight * max_srv_concurrent_targets`
    /// for SRV or S-NAPTR refreshes (256 with the defaults).
    pub max_in_flight: usize,
    /// Maximum discarded packets/frames per exchange before failing over
    /// (1–1024). Bounds work even during a continuous mismatch flood.
    pub max_discarded_responses: usize,
    /// Maximum distinct SRV records expanded after ordering the complete
    /// parsed RRset (1–128, default 32). Remaining records are skipped.
    /// S-NAPTR shares this allowance across all logical SRV record paths.
    pub max_srv_records: usize,
    /// Maximum unique target names expanded per refresh (1–32, default 16).
    /// S-NAPTR shares this allowance across its address and SRV terminals.
    pub max_srv_targets: usize,
    /// Maximum A/AAAA target lookups per SRV refresh (0–64, default 32).
    /// Retries/fallbacks inside each lookup retain the usual attempt bounds.
    /// Zero permits only addresses supplied in the additional section.
    /// S-NAPTR shares this budget across all terminals; memoized address data
    /// avoids new wire lookups but still consumes its logical lookup allowance.
    /// Direct SRV reserves allowances in selection order; S-NAPTR admits the
    /// best-ranked currently ready paths as their ancestors become available.
    /// Aliases or deadline expiry may leave reserved work unused.
    pub max_srv_address_lookups: usize,
    /// Total SRV refresh budget, including the initial question and all target
    /// lookups. Zero (the default) derives `timeout * (servers.len() + 1)`,
    /// capped at 300 s, from the final configuration in [`DnsClient::new`].
    /// A nonzero override must be 1 ms–300 s. Expiry returns completed candidates
    /// and Timeout outcomes for unfinished families. Size the cache lease above
    /// the effective budget, allowing time for scheduling and publication.
    pub srv_refresh_timeout: Duration,
    /// Target resolutions polled concurrently under one admission permit
    /// (1–32, default 4). Each target queries its missing families in order,
    /// so at most this many transport exchanges are live per SRV refresh.
    /// S-NAPTR uses this ceiling for concurrent logical questions across sibling
    /// branches. In-flight duplicates share an exchange and each occupy a slot.
    /// A free slot immediately admits the best-ranked ready continuation.
    pub max_srv_concurrent_targets: usize,
    /// Maximum NAPTR records per path (1–14, default 8).
    pub max_snaptr_depth: usize,
    /// Maximum eligible NAPTR expansions across one refresh (1–1024, default 128).
    pub max_snaptr_records: usize,
    /// Logical NAPTR/SRV/address evaluations, including memoized visits (1–256).
    pub max_snaptr_lookups: usize,
    /// Whole S-NAPTR refresh deadline. Zero derives the same automatic budget
    /// as SRV; an explicit value must be 1 ms–300 s. While a ready branch
    /// needs a new network question queued behind the concurrency limit,
    /// a non-root question reserves
    /// `min(timeout, remaining_on_admission / 2)` at the end for backtracking.
    /// If no alternative remains, it keeps the full deadline and configured
    /// retries without restarting its exchange. A backtracking cap may cut
    /// retries or EDNS/TCP fallback short; root discovery is never capped.
    pub snaptr_refresh_timeout: Duration,
    /// Optional concrete local IP for both UDP and TCP. Servers from another
    /// address family cannot be reached using this source and are skipped.
    pub local_address: Option<IpAddr>,
    /// Optional Linux `SO_BINDTODEVICE` interface name, at most 15 bytes.
    /// Non-Linux targets return [`DnsError::SourceUnavailable`] when set.
    /// Socket permission/device errors also fail closed with that code.
    pub interface: Option<String>,
    /// Exact query profile identity accepted by this client.
    pub resolver_profile: ResolverProfileId,
    /// Exact query source-plane identity accepted by this client.
    pub source_plane: SourcePlaneId,
}

impl Default for DnsClientConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            timeout: Duration::from_secs(5),
            attempts: 2,
            partial_failure_ttl: Duration::from_secs(300),
            max_response_size: 65_535,
            edns_payload_size: 1232,
            max_cname_chain: 15,
            max_in_flight: 64,
            max_discarded_responses: 32,
            max_srv_records: 32,
            max_srv_targets: 16,
            max_srv_address_lookups: 32,
            srv_refresh_timeout: Duration::ZERO,
            max_srv_concurrent_targets: 4,
            max_snaptr_depth: 8,
            max_snaptr_records: 128,
            max_snaptr_lookups: 64,
            snaptr_refresh_timeout: Duration::ZERO,
            local_address: None,
            interface: None,
            resolver_profile: ResolverProfileId::default(),
            source_plane: SourcePlaneId::default(),
        }
    }
}

impl fmt::Debug for DnsClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsClientConfig")
            .field("server_count", &self.servers.len())
            .field("timeout", &self.timeout)
            .field("attempts", &self.attempts)
            .field("max_response_size", &self.max_response_size)
            .field("max_in_flight", &self.max_in_flight)
            .finish_non_exhaustive()
    }
}

impl DnsClientConfig {
    /// Parse `nameserver`, `options timeout:N` and `options attempts:N` from
    /// resolv.conf text. Timeout/attempt values are clamped to 1–30 seconds
    /// and 1–5 passes respectively, matching common resolv.conf limits.
    /// Unknown directives/options are ignored; invalid recognized values
    /// fail closed. Scoped link-local nameservers are unsupported and skipped;
    /// at least one usable server is required. Other nameservers must be literal IPs.
    ///
    /// Names are always absolute (RFC 1034 section 3.1). Search/domain/ndots
    /// expansion is deliberately absent: an infrastructure peer's identity
    /// must not change with host search configuration or leak to other zones.
    ///
    /// # Errors
    /// Returns [`DnsError::InvalidQuery`] for oversized or invalid input and
    /// [`DnsError::Unavailable`] when no servers are supplied. Input is capped
    /// at 64 KiB and eight nameserver entries, including duplicates.
    pub fn from_resolv_conf(text: &str) -> Result<Self, DnsError> {
        if text.len() > MAX_CONFIG_BYTES {
            return Err(DnsError::InvalidQuery);
        }
        let mut config = Self::default();
        let mut nameservers = 0;
        for line in text.lines() {
            let mut fields = line
                .split(['#', ';'])
                .next()
                .unwrap_or("")
                .split_whitespace();
            match fields.next() {
                Some("nameserver") => {
                    nameservers += 1;
                    if nameservers > MAX_SERVERS {
                        return Err(DnsError::InvalidQuery);
                    }
                    let value = fields.next().ok_or(DnsError::InvalidQuery)?;
                    if fields.next().is_some() {
                        return Err(DnsError::InvalidQuery);
                    }
                    if let Some((ip, scope)) = value.split_once('%') {
                        if ip
                            .parse::<Ipv6Addr>()
                            .is_ok_and(|ip| ip.is_unicast_link_local())
                            && !scope.is_empty()
                            && !scope.contains('%')
                        {
                            // Interface-scope resolution is outside this parser.
                            // Keep other usable servers instead of rejecting all.
                            continue;
                        }
                        return Err(DnsError::InvalidQuery);
                    }
                    let ip: IpAddr = value.parse().map_err(|_| DnsError::InvalidQuery)?;
                    config.servers.push(SocketAddr::new(ip, 53));
                }
                Some("options") => {
                    for field in fields {
                        if let Some(value) = field.strip_prefix("timeout:") {
                            let value: u64 = value.parse().map_err(|_| DnsError::InvalidQuery)?;
                            config.timeout = Duration::from_secs(value.clamp(1, 30));
                        } else if let Some(value) = field.strip_prefix("attempts:") {
                            let value: u64 = value.parse().map_err(|_| DnsError::InvalidQuery)?;
                            config.attempts = value.clamp(1, 5) as u8;
                        }
                    }
                }
                _ => {}
            }
        }
        config.validate()?;
        Ok(config)
    }

    /// Read at most 64 KiB from `/etc/resolv.conf` once during configuration.
    /// This bounded filesystem read is synchronous; call it during setup or
    /// on a blocking executor. Non-Unix targets should configure servers
    /// explicitly. Changes require a new client/configuration identity.
    ///
    /// # Errors
    /// Returns [`DnsError::Unavailable`] if the file cannot be read, or the
    /// same parse/validation errors as [`Self::from_resolv_conf`].
    pub fn from_system() -> Result<Self, DnsError> {
        let file = std::fs::File::open("/etc/resolv.conf").map_err(|_| DnsError::Unavailable)?;
        let mut text = String::new();
        file.take((MAX_CONFIG_BYTES + 1) as u64)
            .read_to_string(&mut text)
            .map_err(|_| DnsError::Unavailable)?;
        Self::from_resolv_conf(&text)
    }

    fn validate(&self) -> Result<(), DnsError> {
        if self.servers.is_empty() {
            return Err(DnsError::Unavailable);
        }
        if self.servers.len() > MAX_SERVERS
            || self
                .servers
                .iter()
                .any(|s| s.port() == 0 || !unicast(s.ip()))
            || !(Duration::from_millis(1)..=Duration::from_secs(30)).contains(&self.timeout)
            || !(1..=5).contains(&self.attempts)
            || (!self.partial_failure_ttl.is_zero()
                && !(Duration::from_secs(1)..=Duration::from_secs(300))
                    .contains(&self.partial_failure_ttl))
            || !(512..=65_535).contains(&self.max_response_size)
            || !(512..=4096).contains(&self.edns_payload_size)
            || usize::from(self.edns_payload_size) > self.max_response_size
            || self.max_cname_chain >= DnsCandidate::MAX_RECORDS
            || !(1..=1024).contains(&self.max_in_flight)
            || !(1..=1024).contains(&self.max_discarded_responses)
            || !(1..=128).contains(&self.max_srv_records)
            || !(1..=32).contains(&self.max_srv_targets)
            || self.max_srv_address_lookups > 64
            || (!self.srv_refresh_timeout.is_zero()
                && !(Duration::from_millis(1)..=Duration::from_secs(300))
                    .contains(&self.srv_refresh_timeout))
            || !(1..=32).contains(&self.max_srv_concurrent_targets)
            || !(1..=14).contains(&self.max_snaptr_depth)
            || !(1..=1024).contains(&self.max_snaptr_records)
            || !(1..=256).contains(&self.max_snaptr_lookups)
            || (!self.snaptr_refresh_timeout.is_zero()
                && !(Duration::from_millis(1)..=Duration::from_secs(300))
                    .contains(&self.snaptr_refresh_timeout))
            || self.local_address.is_some_and(|ip| !unicast(ip))
            || self
                .interface
                .as_ref()
                .is_some_and(|name| name.is_empty() || name.len() > 15 || name.contains('\0'))
        {
            return Err(DnsError::InvalidQuery);
        }
        #[cfg(not(target_os = "linux"))]
        if self.interface.is_some() {
            return Err(DnsError::SourceUnavailable);
        }
        Ok(())
    }
}

fn unicast(ip: IpAddr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast() && !matches!(ip, IpAddr::V4(ip) if ip.is_broadcast())
}

/// Transport used by a validated DNS response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DnsTransport {
    /// A UDP response.
    Udp,
    /// A length-prefixed TCP response after UDP truncation.
    Tcp,
}

/// Source of a terminal question response, redacted in diagnostics.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DnsResponseSource {
    /// Configured server that supplied the validated response. Raw access is
    /// for resolver policy/evidence storage, never logging or metric labels.
    pub server: SocketAddr,
    /// Canonical question owner, for programmatic correlation only.
    pub owner: crate::DnsName,
    /// Question record type (A, AAAA, SRV or NAPTR).
    pub record_type: DnsRecordType,
    /// Response transport.
    pub transport: DnsTransport,
    /// Observation in the caller's monotonic cache clock domain.
    pub observed_at: PeerDiscoveryTime,
}

impl fmt::Debug for DnsResponseSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsResponseSource")
            .field("record_type", &self.record_type)
            .field("transport", &self.transport)
            .field("observed_at", &self.observed_at)
            .finish_non_exhaustive()
    }
}

/// One terminal resolution outcome, including failures with no response source.
/// SRV target-family outcomes also cover additional data, lookup-budget failures
/// and whole-target alias rejection, without requiring a separate wire query.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DnsQueryOutcome {
    /// Canonical question owner for programmatic correlation, redacted in Debug.
    pub owner: crate::DnsName,
    /// Requested record type.
    pub record_type: DnsRecordType,
    /// Success or typed failure for this owner and type, before combining families.
    /// SRV target aliases invalidate previously successful families of that target.
    pub result: Result<(), DnsError>,
    /// Response observation or terminal local/transport failure time in the cache clock.
    pub observed_at: PeerDiscoveryTime,
}

/// Resolution result plus bounded terminal response sources: at most two for
/// address mode, `1 + max_srv_address_lookups` for SRV, or at most
/// `max_snaptr_lookups` for S-NAPTR.
/// Transport/timeouts without a validated reply carry no response source.
/// Publish `result` directly through [`crate::DnsCache::finish_refresh`].
/// Schedule subsequent cache work using [`crate::DnsCacheStatus::fresh_until`],
/// [`crate::DnsCacheStatus::retry_at`] and the in-flight refresh state.
/// Successful zero/unknown TTLs use [`crate::DnsCache::with_refresh_interval`],
/// whose default is five seconds with equal jitter (2.5–5 seconds).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DnsClientResponse {
    /// Existing DNS contract consumed by the cache and selection driver.
    pub result: Result<DnsAnswer, DnsError>,
    /// Terminal sources in logical query order, including negative/RCODE replies.
    /// SRV target order follows selection, irrespective of concurrent completion.
    /// Additional-section addresses share their SRV response source. No retry
    /// trace is retained, and names are redacted in Debug.
    pub sources: Vec<DnsResponseSource>,
    /// Terminal outcomes in A-then-AAAA order, at most two for address mode.
    /// SRV mode starts with the SRV question, then records requested families
    /// once per visited target: at most `1 + 2 * max_srv_targets` entries.
    /// This exposes partial failures even when `result` has usable candidates.
    pub outcomes: Vec<DnsQueryOutcome>,
    /// Distinct valid SRV records not expanded because a record, target,
    /// lookup or candidate limit stopped their work. Zero for address mode.
    /// An attempted target's DNS failure is not a skipped record. In S-NAPTR
    /// mode, records count logical SRV paths across all terminals.
    pub skipped_srv_records: usize,
    /// Distinct valid SRV targets whose address resolution was entirely
    /// skipped by those limits. A target reused by any expanded record counts
    /// as visited. Fully budget-blocked targets may still have LimitExceeded
    /// family outcomes; targets beyond the other work limits have none.
    pub skipped_srv_targets: usize,
    /// Bounded branch refusals/failures in traversal order; not retained by the cache.
    pub snaptr_branches: Vec<crate::SnaptrBranchOutcome>,
    pub(crate) snaptr_root: Option<crate::SnaptrRootObservation>,
}

impl DnsClientResponse {
    /// Diagnostic root classification. Root no-match decisions also travel in
    /// `result`, so existing `finish_refresh` drivers preserve them.
    pub fn snaptr_root(&self) -> Option<&crate::SnaptrRootObservation> {
        self.snaptr_root.as_ref()
    }

    fn error(error: DnsError) -> Self {
        Self {
            result: Err(error),
            sources: Vec::new(),
            outcomes: Vec::new(),
            skipped_srv_records: 0,
            skipped_srv_targets: 0,
            snaptr_branches: Vec::new(),
            snaptr_root: None,
        }
    }
}

/// Cumulative, saturating discard counts shared by every client clone.
/// Counters have no address, name, profile or plane labels.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DnsClientStats {
    /// UDP packets whose source IP or port differs from the configured server.
    pub source_mismatches: u64,
    /// Packets/frames with another query ID.
    pub id_mismatches: u64,
    /// Packets/frames without exactly the matching name, type and IN class.
    pub question_mismatches: u64,
    /// Structurally malformed or semantically unusable responses.
    pub malformed_responses: u64,
    /// UDP messages or TCP frame lengths exceeding the receive bound.
    pub oversized_responses: u64,
}

#[derive(Default)]
struct Counters {
    source: AtomicU64,
    id: AtomicU64,
    question: AtomicU64,
    malformed: AtomicU64,
    oversized: AtomicU64,
}

fn increment(counter: &AtomicU64) {
    // compare_exchange_weak keeps this saturating counter compatible with
    // the MSRV as well as toolchains deprecating fetch_update.
    let mut old = counter.load(Ordering::Relaxed);
    while old != u64::MAX {
        match counter.compare_exchange_weak(old, old + 1, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(current) => old = current,
        }
    }
}

/// An ordering hint only: every configured server remains fallback eligible.
/// At most eight timestamps are shared by SRV calls on this client/profile.
#[derive(Default)]
struct ServerTimeouts {
    until: Mutex<[Option<tokio::time::Instant>; MAX_SERVERS]>,
}

impl ServerTimeouts {
    fn mask(&self, now: tokio::time::Instant) -> u64 {
        self.until
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .enumerate()
            .fold(0, |mask, (index, until)| {
                mask | if until.is_some_and(|until| now < until) {
                    1 << index
                } else {
                    0
                }
            })
    }

    fn timed_out(&self, index: usize, now: tokio::time::Instant) {
        // RFC 2308 section 7.2: do not retain a dead-server hint over five minutes.
        self.until
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)[index] =
            now.checked_add(Duration::from_secs(300));
    }

    fn responded(&self, index: usize) {
        self.until
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)[index] = None;
    }
}

struct Inner {
    config: DnsClientConfig,
    permits: Semaphore,
    counters: Counters,
    server_timeouts: ServerTimeouts,
    #[cfg(test)]
    test_datagram: Option<Arc<TestDatagram>>,
}

// Unit fixtures keep datagrams in-process so paused time cannot race kernel
// readiness. The parser, retries, shared refresh deadline and traversal stay
// unchanged. Integration fixtures exercise the real socket transport.
#[cfg(test)]
type TestDatagram = dyn Fn(Vec<u8>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<u8>> + Send>>
    + Send
    + Sync;

/// Async A/AAAA/SRV/S-NAPTR stub resolver with bounded, cancellation-safe sockets.
///
/// Only configured servers are contacted; there is no recursive traversal,
/// DNSSEC validation, DoT or DoH. Uses Tokio networking and timers;
/// call [`Self::resolve`] inside an I/O/time-enabled Tokio runtime. Dropping
/// its future closes its sockets and releases admission without a worker task.
/// There is no durable/node state or operator cleanup on restart or crash.
///
/// Each exchange uses OS randomness for the full 16-bit ID and the kernel's
/// automatic ephemeral-port allocation, honoring its range and reservations
/// (32 bounded bind attempts; ports below 1024 are refused), per
/// [RFC 5452 sections 9.1–9.2](https://www.rfc-editor.org/rfc/rfc5452.html#section-9).
/// UDP binds a concrete source IP, verifies the configured remote IP/port,
/// ID and question, and counts mismatches. TCP uses a bound socket to the
/// same configured server and applies the same ID/question checks.
#[derive(Clone)]
pub struct DnsClient {
    inner: Arc<Inner>,
}

impl fmt::Debug for DnsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsClient")
            .field("config", &self.inner.config)
            .field("stats", &self.stats())
            .finish()
    }
}

impl DnsClient {
    /// Validate and retain an immutable configuration; opens no sockets.
    ///
    /// # Errors
    /// Returns [`DnsError::InvalidQuery`] for invalid bounds/addresses,
    /// [`DnsError::Unavailable`] for no servers, or
    /// [`DnsError::SourceUnavailable`] for non-Linux interface binding.
    pub fn new(mut config: DnsClientConfig) -> Result<Self, DnsError> {
        config.validate()?;
        if config.srv_refresh_timeout.is_zero() {
            // Validation bounds the server count to eight before this conversion.
            config.srv_refresh_timeout = config
                .timeout
                .saturating_mul((config.servers.len() + 1) as u32)
                .min(Duration::from_secs(300));
        }
        if config.snaptr_refresh_timeout.is_zero() {
            config.snaptr_refresh_timeout = config
                .timeout
                .saturating_mul((config.servers.len() + 1) as u32)
                .min(Duration::from_secs(300));
        }
        Ok(Self {
            inner: Arc::new(Inner {
                permits: Semaphore::new(config.max_in_flight),
                config,
                counters: Counters::default(),
                server_timeouts: ServerTimeouts::default(),
                #[cfg(test)]
                test_datagram: None,
            }),
        })
    }

    /// Snapshot counters (individually atomic, with no cross-counter ordering).
    pub fn stats(&self) -> DnsClientStats {
        let counters = &self.inner.counters;
        DnsClientStats {
            source_mismatches: counters.source.load(Ordering::Relaxed),
            id_mismatches: counters.id.load(Ordering::Relaxed),
            question_mismatches: counters.question.load(Ordering::Relaxed),
            malformed_responses: counters.malformed.load(Ordering::Relaxed),
            oversized_responses: counters.oversized.load(Ordering::Relaxed),
        }
    }

    /// Resolve an absolute address, SRV or filtered S-NAPTR query. `now` is called when each
    /// validated response arrives or a transport failure completes, in the cache clock;
    /// it must be fast and must not block. Earlier TTL observations are never
    /// restarted when a second family completes.
    ///
    /// UDP advertises bounded EDNS(0); FORMERR retries once without it within
    /// the same attempt deadline ([RFC 6891 sections 6.1, 6.2.2–6.2.3](https://www.rfc-editor.org/rfc/rfc6891.html#section-6)).
    /// A matched truncated reply retries TCP at the same server, including
    /// its two-octet framing ([RFC 1035 section 4.2.2](https://www.rfc-editor.org/rfc/rfc1035.html#section-4.2.2),
    /// [RFC 2181 section 9](https://www.rfc-editor.org/rfc/rfc2181.html#section-9),
    /// [RFC 7766 sections 4–5](https://www.rfc-editor.org/rfc/rfc7766.html#section-4)).
    /// Prefix and query are submitted in one write ([RFC 7766 section 8](https://www.rfc-editor.org/rfc/rfc7766.html#section-8)).
    /// A FORMERR without the echoed question is dropped; it cannot trigger fallback.
    ///
    /// CNAMEs are followed only inside the answer, with loop/conflict/depth
    /// checks ([RFC 1034 section 3.6.2](https://www.rfc-editor.org/rfc/rfc1034.html#section-3.6.2),
    /// [RFC 2181 section 10.1](https://www.rfc-editor.org/rfc/rfc2181.html#section-10.1)).
    /// RRsets use the lowest effective TTL ([RFC 2181 sections 5.2, 8](https://www.rfc-editor.org/rfc/rfc2181.html#section-5.2)).
    /// The resulting records feed the cache's existing lifetime caps. Enclosing
    /// authority SOAs supply negative timing bounded by the CNAME chain
    /// ([RFC 2308 sections 2.2, 5](https://www.rfc-editor.org/rfc/rfc2308.html#section-5)).
    /// Referrals never add destinations; NXDOMAIN/NODATA without SOA are uncacheable.
    ///
    /// Address-mode dual stack queries A then AAAA, retaining usable data if the other
    /// family fails; positives take precedence over contradictory negatives.
    /// The result is ordered using the destination-only RFC 6724 subset in
    /// [`crate::order_dns_addresses`]. Negative caching is allowed only when
    /// both families return negatives; their shortest deadline wins. Transient
    /// errors take precedence over a single-family denial.
    /// Partial positives retain per-family [`DnsQueryOutcome`]s and expire no
    /// later than a failed family's observed SOA deadline or configured
    /// [`DnsClientConfig::partial_failure_ttl`] ([RFC 2308 sections 5, 7.1–7.2](https://www.rfc-editor.org/rfc/rfc2308.html#section-7)).
    /// At publication the cache also applies its negative TTL cap to partial
    /// SOA denials, in addition to the positive cap and record deadlines.
    /// Separate family last-good retention is a follow-up; use separate family
    /// query keys when that isolation is needed now. Families run sequentially,
    /// so an unreachable server incurs its attempt timeout again for each family.
    ///
    /// SERVFAIL, REFUSED, malformed/unsupported replies and timeouts advance
    /// to the next configured server. Each family makes at most
    /// `attempts * servers.len()` attempts, each bounded by `timeout` including
    /// fallback. Final failures use stable [`DnsError`] variants. No request
    /// is queued when admission is full. All usable candidates from the bounded
    /// responses (at most 128 per family) are ordered before retaining 16.
    ///
    /// Service mode requires `_service._proto.domain.` with a protocol matching
    /// the input transport. Host labels use ASCII letters, digits and hyphens,
    /// including a leading digit ([RFC 1123 section 2.1](https://www.rfc-editor.org/rfc/rfc1123.html#section-2.1)).
    /// SRV uses lowest priority first, then the inclusive weighted draw with
    /// zero weights first ([RFC 2782, Priority, Weight and Usage rules](https://www.rfc-editor.org/rfc/rfc2782.html)).
    /// A sole root target returns [`DnsError::ServiceUnavailable`] with its
    /// SRV/CNAME deadline; the cache applies its negative TTL cap and retains
    /// last-good data as stale. Mixed root entries, invalid hosts and port-zero
    /// records are skipped ([RFC 6335 section 6](https://www.rfc-editor.org/rfc/rfc6335.html#section-6)).
    /// Receivers accept bounded target compression ([RFC 3597 section 4](https://www.rfc-editor.org/rfc/rfc3597.html#section-4)).
    /// The SRV port is used and `default_port` is ignored. Candidate weights
    /// encode one draw per refresh, so selections from the same cache entry
    /// reuse that order until the next refresh. The legacy selector does not
    /// reapply raw SRV weights.
    ///
    /// Exact-target additional A/AAAA records avoid fresh queries; missing
    /// families use the same transport and source policy. A CNAME invalidates
    /// its whole target; it is never followed ([RFC 2782, Target and Usage rules](https://www.rfc-editor.org/rfc/rfc2782.html)).
    /// Other targets and usable families survive failures. A target's denial
    /// cannot negatively cache the service name. Only an SRV-question denial
    /// supplies that authority. Each chain retains its SRV and address timing;
    /// freshness follows [`crate::DnsCacheStatus::fresh_until`]. Partial results
    /// use the same failure/SOA freshness bounds as address mode, and preserve
    /// each visited target's family outcomes in [`DnsClientResponse::outcomes`].
    ///
    /// One admission permit covers the whole refresh, with at most
    /// [`DnsClientConfig::max_srv_concurrent_targets`] target exchanges active.
    /// Timed-out servers are tried after other configured servers across SRV
    /// refreshes and client clones for up to five minutes; a matched reply clears
    /// the hint sooner ([RFC 2308 section 7.2](https://www.rfc-editor.org/rfc/rfc2308.html#section-7.2)).
    /// The hint uses Tokio's monotonic clock, independently of the cache clock.
    /// All configured servers remain fallback eligible; no DNS failure is cached.
    /// The total I/O budget is [`DnsClientConfig::srv_refresh_timeout`], including
    /// the SRV question. Expiry retains completed families and records Timeout
    /// for unfinished ones. Cancellation drops all sockets with the caller's future.
    ///
    /// The complete valid RRset is ordered before applying record, target,
    /// lookup and candidate limits. [`DnsClientResponse::skipped_srv_records`]
    /// and [`DnsClientResponse::skipped_srv_targets`] expose omitted work.
    /// Return at most 16 distinct endpoints, ordered by target selection then
    /// destination rank, preserving DNS address order for ties ([RFC 6724
    /// section 6, rule 10](https://www.rfc-editor.org/rfc/rfc6724.html#section-6)).
    ///
    /// S-NAPTR requires [`crate::SnaptrFilter`] and a nonzero service-defined
    /// default port, validated before admission. It traverses empty/`s`/`a`
    /// replacement records concurrently, refusing nonempty regexps and isolating
    /// semantic failures to their branch. The filter and ordering profile are
    /// part of the cache key. NAPTR and SRV selection remain separate, with
    /// complete primary/alternate provenance and a bounded host view for the
    /// consumer's topology policy. No implicit service/transport fallback occurs.
    /// One permit, absolute deadline and shared work budgets cover the refresh.
    /// [`DnsClientConfig::max_srv_concurrent_targets`] bounds active questions;
    /// each non-root question also has the cap documented on
    /// [`DnsClientConfig::snaptr_refresh_timeout`]. Completed paths retain their
    /// full ancestral selection order regardless of response arrival order.
    /// A cap retains the best completed endpoint prefix; a 16-endpoint-only
    /// truncation does not shorten record-derived freshness. Cached coverage
    /// retains refusal/failure and omission counts.
    ///
    /// Root no-match errors carry an actionable [`crate::SnaptrNoMatch`] kind
    /// and RRset/alias deadline through ordinary `finish_refresh` publication.
    /// A root NXDOMAIN/NODATA retains its original SOA timing; child failures
    /// cannot authorize root absence fallback. [`DnsClientResponse::snaptr_root`]
    /// is diagnostic context, not another cache lifecycle. RFC 6408 relay
    /// records match any Diameter application at their own order/preference;
    /// abandoning a matchless protocol does not prevent independent queries
    /// for other supported protocols.
    pub async fn resolve(
        &self,
        query: &DnsQuery,
        now: impl Fn() -> PeerDiscoveryTime,
    ) -> DnsClientResponse {
        self.resolve_inner(query, &now, None).await
    }

    /// Resolve using an injected SRV/S-NAPTR selection seed. Identical SRV RRsets and
    /// seeds produce the same target order regardless of wire order. This
    /// affects only service selection; query IDs still use OS entropy and
    /// source ports follow independent kernel allocation policy. Address mode
    /// ignores the seed.
    ///
    /// SRV uses lowest priority first and the inclusive, zero-weight-aware
    /// algorithm in [RFC 2782, Weight and Usage rules](https://www.rfc-editor.org/rfc/rfc2782.html).
    pub async fn resolve_with_seed(
        &self,
        query: &DnsQuery,
        now: impl Fn() -> PeerDiscoveryTime,
        seed: u64,
    ) -> DnsClientResponse {
        self.resolve_inner(query, &now, Some(seed)).await
    }

    async fn resolve_inner(
        &self,
        query: &DnsQuery,
        now: &impl Fn() -> PeerDiscoveryTime,
        seed: Option<u64>,
    ) -> DnsClientResponse {
        let config = &self.inner.config;
        if query.resolver_profile() != &config.resolver_profile {
            return DnsClientResponse::error(DnsError::Unavailable);
        }
        if query.source_plane() != &config.source_plane {
            return DnsClientResponse::error(DnsError::SourceUnavailable);
        }
        if (matches!(
            query.input().mode,
            ServiceDiscoveryMode::Address | ServiceDiscoveryMode::Snaptr
        ) && query.input().default_port.is_none_or(|port| port == 0))
            || (query.input().mode == ServiceDiscoveryMode::Service && !srv::valid_query(query))
            || (query.input().mode == ServiceDiscoveryMode::Snaptr
                && query.snaptr_filter().is_none())
        {
            return DnsClientResponse::error(DnsError::InvalidQuery);
        }
        let Ok(_permit) = self.inner.permits.try_acquire() else {
            return DnsClientResponse::error(DnsError::Busy);
        };
        if query.input().mode == ServiceDiscoveryMode::Service {
            return self.resolve_srv(query, now, seed).await;
        }
        if query.input().mode == ServiceDiscoveryMode::Snaptr {
            return self.resolve_snaptr(query, now, seed).await;
        }
        let kinds: &[u16] = match query.address_family() {
            AddressFamilyPolicy::Ipv4Only => &[1],
            AddressFamilyPolicy::Ipv6Only => &[28],
            AddressFamilyPolicy::DualStack => &[1, 28],
        };
        let mut candidates = Vec::new();
        let mut sources = Vec::new();
        let mut outcomes = Vec::new();
        let mut freshness_bound: Option<PeerDiscoveryTime> = None;
        let mut negative_freshness_bound: Option<PeerDiscoveryTime> = None;
        let mut error = None;
        for kind in kinds {
            let (result, source) = self
                .lookup(query, *kind, now, |message, observed_at| {
                    message.resolve(query, *kind, observed_at, config.max_cname_chain)
                })
                .await;
            let observed_at = source.as_ref().map(|s| s.observed_at).unwrap_or_else(&now);
            outcomes.push(DnsQueryOutcome {
                owner: query.name().clone(),
                record_type: if *kind == 1 {
                    DnsRecordType::A
                } else {
                    DnsRecordType::Aaaa
                },
                result: result.as_ref().map(|_| ()).map_err(|error| *error),
                observed_at,
            });
            if let Some(source) = source {
                sources.push(source);
            }
            match result {
                Ok(mut found) => candidates.append(&mut found),
                Err(found) => {
                    let deadline = self.failure_deadline(found, observed_at);
                    let bound = if found.soa().is_some() {
                        &mut negative_freshness_bound
                    } else {
                        &mut freshness_bound
                    };
                    *bound = Some(bound.map_or(deadline, |old| old.min(deadline)));
                    error = Some(error.map_or(found, |old| combine_errors(old, found)));
                }
            }
        }
        if candidates.is_empty() {
            return DnsClientResponse {
                result: Err(error.unwrap_or(DnsError::MalformedAnswer)),
                sources,
                outcomes,
                skipped_srv_records: 0,
                skipped_srv_targets: 0,
                snaptr_branches: Vec::new(),
                snaptr_root: None,
            };
        }
        candidates
            .sort_by_key(|candidate| crate::dns::destination_rank(candidate.peer().endpoint.ip()));
        candidates.truncate(DnsAnswer::MAX_CANDIDATES);
        // Address-mode ordering is encoded using the legacy selection weight.
        for (index, candidate) in candidates.iter_mut().enumerate() {
            candidate.peer.weight = crate::dns::selection_weight(index);
        }
        DnsClientResponse {
            result: DnsAnswer::new(candidates).map(|mut answer| {
                if let Some(bound) = freshness_bound {
                    answer = answer.with_freshness_bound(bound);
                }
                if let Some(bound) = negative_freshness_bound {
                    answer = answer.with_negative_freshness_bound(bound);
                }
                answer
            }),
            sources,
            outcomes,
            skipped_srv_records: 0,
            skipped_srv_targets: 0,
            snaptr_branches: Vec::new(),
            snaptr_root: None,
        }
    }

    fn failure_deadline(
        &self,
        error: DnsError,
        observed_at: PeerDiscoveryTime,
    ) -> PeerDiscoveryTime {
        error.soa().map_or_else(
            || {
                observed_at
                    .checked_add(self.inner.config.partial_failure_ttl)
                    .unwrap_or(observed_at)
            },
            |soa| soa.expires_at(),
        )
    }

    async fn lookup<T>(
        &self,
        query: &DnsQuery,
        kind: u16,
        now: &impl Fn() -> PeerDiscoveryTime,
        parse: impl Fn(Message, PeerDiscoveryTime) -> Result<T, DnsError>,
    ) -> (Result<T, DnsError>, Option<DnsResponseSource>) {
        self.lookup_with_history(query, kind, now, parse, None)
            .await
    }

    async fn lookup_with_history<T>(
        &self,
        query: &DnsQuery,
        kind: u16,
        now: &impl Fn() -> PeerDiscoveryTime,
        parse: impl Fn(Message, PeerDiscoveryTime) -> Result<T, DnsError>,
        timed_out: Option<&ServerTimeouts>,
    ) -> (Result<T, DnsError>, Option<DnsResponseSource>) {
        let record_type = match dns_wire::record_type(kind) {
            Ok(value) => value,
            Err(error) => return (Err(error), None),
        };
        let config = &self.inner.config;
        let mut last = (Err(DnsError::Unavailable), None);
        for _ in 0..config.attempts {
            let failed = timed_out.map_or(0, |history| history.mask(tokio::time::Instant::now()));
            let mut order: Vec<_> = (0..config.servers.len()).collect();
            // Keep configured order within each group. SRV timeout hints span
            // refreshes on this client; address-mode calls pass no history.
            order.sort_by_key(|index| failed & (1 << index) != 0);
            for index in order {
                let server = &config.servers[index];
                match tokio::time::timeout(config.timeout, self.exchange(query, kind, *server))
                    .await
                {
                    Ok(Ok((message, transport))) => {
                        if let Some(history) = timed_out {
                            history.responded(index);
                        }
                        let observed_at = now();
                        let result = parse(message, observed_at);
                        if matches!(&result, Err(DnsError::MalformedAnswer)) {
                            increment(&self.inner.counters.malformed);
                        }
                        let terminal = matches!(
                            result,
                            Ok(_)
                                | Err(DnsError::NxDomain { .. }
                                    | DnsError::NoData { .. }
                                    | DnsError::ServiceUnavailable { .. }
                                    | DnsError::LimitExceeded
                                    | DnsError::Snaptr { .. })
                        );
                        last = (
                            result,
                            Some(DnsResponseSource {
                                server: *server,
                                owner: query.name().clone(),
                                record_type,
                                transport,
                                observed_at,
                            }),
                        );
                        if terminal {
                            return last;
                        }
                    }
                    Ok(Err(error)) => {
                        if error == DnsError::Timeout {
                            if let Some(history) = timed_out {
                                history.timed_out(index, tokio::time::Instant::now());
                            }
                        }
                        last = (Err(error), None);
                    }
                    Err(_) => {
                        if let Some(history) = timed_out {
                            history.timed_out(index, tokio::time::Instant::now());
                        }
                        last = (Err(DnsError::Timeout), None);
                    }
                }
            }
        }
        last
    }

    async fn exchange(
        &self,
        query: &DnsQuery,
        kind: u16,
        server: SocketAddr,
    ) -> Result<(Message, DnsTransport), DnsError> {
        let mut edns = Some(self.inner.config.edns_payload_size);
        // At most one FORMERR retry. TCP retry shares this outer deadline.
        for _ in 0..2 {
            let id = random_u16()?;
            let bytes = dns_wire::encode(id, query.name(), kind, edns);
            let udp = self.udp(query, kind, server, id, &bytes, edns).await?;
            let (message, transport) = if udp.truncated {
                (
                    self.tcp(query, kind, server, id, &bytes).await?,
                    DnsTransport::Tcp,
                )
            } else {
                (udp, DnsTransport::Udp)
            };
            if message.rcode == 1 && edns.take().is_some() {
                continue;
            }
            return Ok((message, transport));
        }
        Err(DnsError::MalformedAnswer)
    }

    async fn udp(
        &self,
        query: &DnsQuery,
        kind: u16,
        server: SocketAddr,
        id: u16,
        bytes: &[u8],
        edns: Option<u16>,
    ) -> Result<Message, DnsError> {
        #[cfg(test)]
        if let Some(respond) = &self.inner.test_datagram {
            let response = respond(bytes.to_vec()).await;
            return self
                .decode(&response, query, kind, id)?
                .ok_or(DnsError::MalformedAnswer);
        }
        let config = &self.inner.config;
        // Select the route's concrete local IP without sending a packet. The
        // receiving socket binds that IP, so a packet to a different local
        // destination cannot satisfy RFC 5452 9.1's destination-address check.
        let local = if let Some(ip) = config.local_address {
            ip
        } else {
            let route = self.socket(server, Type::DGRAM, Protocol::UDP)?;
            route
                .connect(&server.into())
                .map_err(|_| DnsError::Transport)?;
            route
                .local_addr()
                .map_err(|_| DnsError::Transport)?
                .as_socket()
                .ok_or(DnsError::Transport)?
                .ip()
        };
        let socket = self.bound_socket(server, Type::DGRAM, Protocol::UDP, local)?;
        let socket = UdpSocket::from_std(socket.into()).map_err(|_| DnsError::Transport)?;
        socket
            .send_to(bytes, server)
            .await
            .map_err(|_| DnsError::Transport)?;
        let limit = usize::from(edns.unwrap_or(512)).min(config.max_response_size);
        let mut buffer = vec![0; limit + 1]; // one sentinel byte detects UDP truncation
        for _ in 0..config.max_discarded_responses {
            let (size, source) = socket
                .recv_from(&mut buffer)
                .await
                .map_err(|_| DnsError::Transport)?;
            if source != server {
                increment(&self.inner.counters.source);
                continue;
            }
            if size > limit {
                increment(&self.inner.counters.oversized);
                if u16::from_be_bytes([buffer[0], buffer[1]]) != id {
                    increment(&self.inner.counters.id);
                }
                continue;
            }
            if let Some(message) = self.decode(&buffer[..size], query, kind, id)? {
                return Ok(message);
            }
        }
        Err(DnsError::MalformedAnswer)
    }

    async fn tcp(
        &self,
        query: &DnsQuery,
        kind: u16,
        server: SocketAddr,
        id: u16,
        bytes: &[u8],
    ) -> Result<Message, DnsError> {
        let local = self
            .inner
            .config
            .local_address
            .unwrap_or_else(|| unspecified(server));
        let socket = self.bound_socket(server, Type::STREAM, Protocol::TCP, local)?;
        let socket = TcpSocket::from_std_stream(socket.into());
        let mut stream = socket
            .connect(server)
            .await
            .map_err(|_| DnsError::Transport)?;
        // RFC 7766 section 8: submit the length and message together.
        let mut frame = Vec::with_capacity(bytes.len() + 2);
        frame.extend((bytes.len() as u16).to_be_bytes());
        frame.extend_from_slice(bytes);
        stream
            .write_all(&frame)
            .await
            .map_err(|_| DnsError::Transport)?;
        for _ in 0..self.inner.config.max_discarded_responses {
            let size = usize::from(stream.read_u16().await.map_err(|_| DnsError::Transport)?);
            if size > self.inner.config.max_response_size {
                increment(&self.inner.counters.oversized);
                return Err(DnsError::MalformedAnswer);
            }
            let mut buffer = vec![0; size];
            stream
                .read_exact(&mut buffer)
                .await
                .map_err(|_| DnsError::Transport)?;
            if let Some(message) = self.decode(&buffer, query, kind, id)? {
                if message.truncated {
                    increment(&self.inner.counters.malformed);
                    return Err(DnsError::MalformedAnswer);
                }
                return Ok(message);
            }
        }
        Err(DnsError::MalformedAnswer)
    }

    fn decode(
        &self,
        bytes: &[u8],
        query: &DnsQuery,
        kind: u16,
        id: u16,
    ) -> Result<Option<Message>, DnsError> {
        match dns_wire::decode(bytes, id, query.name(), kind) {
            Ok(message) => Ok(Some(message)),
            Err(DecodeError::Id) => {
                increment(&self.inner.counters.id);
                Ok(None)
            }
            Err(DecodeError::Question) => {
                increment(&self.inner.counters.question);
                Ok(None)
            }
            Err(DecodeError::Malformed) => {
                increment(&self.inner.counters.malformed);
                Err(DnsError::MalformedAnswer)
            }
        }
    }

    fn socket(
        &self,
        server: SocketAddr,
        kind: Type,
        protocol: Protocol,
    ) -> Result<Socket, DnsError> {
        let socket = Socket::new(Domain::for_address(server), kind, Some(protocol))
            .map_err(|_| DnsError::Transport)?;
        socket
            .set_nonblocking(true)
            .map_err(|_| DnsError::Transport)?;
        #[cfg(target_os = "linux")]
        if let Some(interface) = &self.inner.config.interface {
            socket
                .bind_device(Some(interface.as_bytes()))
                .map_err(|_| DnsError::SourceUnavailable)?;
        }
        Ok(socket)
    }

    fn bound_socket(
        &self,
        server: SocketAddr,
        kind: Type,
        protocol: Protocol,
        local: IpAddr,
    ) -> Result<Socket, DnsError> {
        if local.is_ipv4() != server.is_ipv4() {
            return Err(DnsError::SourceUnavailable);
        }
        for _ in 0..PORT_BIND_ATTEMPTS {
            // Automatic allocation honors the kernel's ephemeral range and
            // reserved-port policy (RFC 5452 section 9.2). Never explicitly
            // bind a random port outside that policy.
            let socket = self.socket(server, kind, protocol)?;
            match socket.bind(&SocketAddr::new(local, 0).into()) {
                Ok(()) => {
                    let port = socket
                        .local_addr()
                        .map_err(|_| DnsError::SourceUnavailable)?
                        .as_socket()
                        .ok_or(DnsError::SourceUnavailable)?
                        .port();
                    if port >= 1024 {
                        return Ok(socket);
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
                    ) =>
                {
                    continue
                }
                Err(_) => return Err(DnsError::SourceUnavailable),
            }
        }
        Err(DnsError::SourceUnavailable)
    }
}

fn random_u16() -> Result<u16, DnsError> {
    let mut bytes = [0; 2];
    getrandom::fill(&mut bytes).map_err(|_| DnsError::Unavailable)?;
    Ok(u16::from_ne_bytes(bytes))
}

fn unspecified(server: SocketAddr) -> IpAddr {
    if server.is_ipv4() {
        Ipv4Addr::UNSPECIFIED.into()
    } else {
        Ipv6Addr::UNSPECIFIED.into()
    }
}

fn combine_errors(first: DnsError, second: DnsError) -> DnsError {
    let negative = |error| matches!(error, DnsError::NxDomain { .. } | DnsError::NoData { .. });
    match (negative(first), negative(second)) {
        (false, _) => first,
        (true, false) => second,
        (true, true) => {
            let soa = match (first.soa(), second.soa()) {
                (Some(a), Some(b)) => Some(if a.expires_at() <= b.expires_at() {
                    a
                } else {
                    b
                }),
                _ => None,
            };
            // NXDOMAIN asserts the whole name is absent: mixed family
            // denials support only the weaker, query-scoped NODATA result.
            if matches!(
                (first, second),
                (DnsError::NxDomain { .. }, DnsError::NxDomain { .. })
            ) {
                DnsError::NxDomain { soa }
            } else {
                DnsError::NoData { soa }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn srv_timeout_history_expires_per_server_and_clears_after_response() {
        let history = ServerTimeouts::default();
        let start = tokio::time::Instant::now();
        history.timed_out(0, start);
        assert_eq!(history.mask(start), 1);
        history.timed_out(1, start + Duration::from_secs(5));
        assert_eq!(history.mask(start + Duration::from_millis(299_999)), 3);
        assert_eq!(history.mask(start + Duration::from_secs(300)), 2);
        assert_eq!(history.mask(start + Duration::from_secs(305)), 0);

        history.timed_out(0, start + Duration::from_secs(306));
        history.timed_out(1, start + Duration::from_secs(307));
        history.responded(0);
        assert_eq!(history.mask(start + Duration::from_secs(307)), 2);
        history.responded(1);
        assert_eq!(history.mask(start + Duration::from_secs(307)), 0);
    }

    #[test]
    fn automatic_srv_budget_covers_a_server_pass_and_target_work() {
        for (servers, seconds, expected) in [(1, 5, 10), (3, 5, 20), (8, 30, 270)] {
            let mut config = DnsClientConfig {
                servers: vec!["127.0.0.1:53".parse().unwrap(); servers],
                timeout: Duration::from_secs(seconds),
                ..DnsClientConfig::default()
            };
            let client = DnsClient::new(config.clone()).unwrap();
            assert_eq!(
                client.inner.config.srv_refresh_timeout,
                Duration::from_secs(expected)
            );
            config.srv_refresh_timeout = Duration::from_secs(10);
            assert_eq!(
                DnsClient::new(config)
                    .unwrap()
                    .inner
                    .config
                    .srv_refresh_timeout,
                Duration::from_secs(10),
                "an explicit budget must take precedence over the derived default"
            );
        }
    }

    #[test]
    fn automatic_srv_budget_uses_final_resolv_conf_transport_settings() {
        let mut config = DnsClientConfig::from_resolv_conf(
            "nameserver 192.0.2.1\nnameserver 192.0.2.2\noptions timeout:30\n",
        )
        .unwrap();
        assert_eq!(
            DnsClient::new(config.clone())
                .unwrap()
                .inner
                .config
                .srv_refresh_timeout,
            Duration::from_secs(90)
        );
        config.timeout = Duration::from_secs(4);
        config.servers.push("192.0.2.3:53".parse().unwrap());
        assert_eq!(
            DnsClient::new(config)
                .unwrap()
                .inner
                .config
                .srv_refresh_timeout,
            Duration::from_secs(16)
        );
    }
}
