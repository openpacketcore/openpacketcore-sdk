//! Runtime-independent DNS cache. Serialize access with a caller-owned lock,
//! release it before I/O, and publish with the returned refresh token. No task,
//! runtime, resolver socket, or blocking operation is owned by this cache.

use std::collections::HashMap;
use std::fmt;
use std::hash::{BuildHasher, Hasher};
use std::sync::Arc;
use std::time::Duration;

use crate::{DnsAnswer, DnsCacheKey, DnsError, DnsQuery, PeerDiscoveryTime};

// The conservative RFC 2181 section 8 policy bounds all usable record TTLs.
const MAX_TTL: Duration = Duration::from_secs(0x7fff_ffff);

/// Bounded exponential retry with equal jitter (half to all of the current
/// exponential cap). Millisecond precision; both bounds are at least 1 ms.
/// The seed is caller-supplied for reproducible tests or deployment entropy.
#[derive(Clone)]
pub struct DnsRetryPolicy {
    base_ms: u64,
    max_ms: u64,
    random: u64,
}

impl DnsRetryPolicy {
    /// Configure retry bounds. Both are clamped to 1 ms–300 s, with `max` at
    /// least `base`. The ceiling follows the failure-suppression limit in
    /// [RFC 2308 sections 7.1–7.2](https://www.rfc-editor.org/rfc/rfc2308.html#section-7).
    pub fn new(base: Duration, max: Duration, seed: u64) -> Self {
        let base_ms = millis(base).clamp(1, 300_000);
        Self {
            base_ms,
            max_ms: millis(max).clamp(base_ms, 300_000),
            random: seed,
        }
    }

    fn delay(&mut self, failures: u32) -> Duration {
        let multiplier = 1u64 << failures.saturating_sub(1).min(63);
        let cap = self.base_ms.saturating_mul(multiplier).min(self.max_ms);
        self.jitter(cap)
    }

    fn jitter(&mut self, cap: u64) -> Duration {
        // SplitMix64 is deterministic jitter, not security randomness.
        self.random = self.random.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.random;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^= value >> 31;
        let floor = (cap / 2).max(1);
        Duration::from_millis(floor + value % (cap - floor + 1))
    }
}

impl fmt::Debug for DnsRetryPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsRetryPolicy")
            .field("base_ms", &self.base_ms)
            .field("max_ms", &self.max_ms)
            .finish_non_exhaustive()
    }
}

impl Default for DnsRetryPolicy {
    fn default() -> Self {
        // Standard-library randomized state avoids synchronized default caches.
        let seed = std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish();
        Self::new(Duration::from_secs(1), Duration::from_secs(30), seed)
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn deadline(now: PeerDiscoveryTime, duration: Duration) -> PeerDiscoveryTime {
    // Overflow must never accidentally create an immortal positive/negative.
    now.checked_add(duration).unwrap_or(now)
}

/// Serving result. A positive last-good answer always takes precedence over a
/// later negative or transient failure, even after arbitrarily long outages.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DnsCachedResult {
    /// All record deadlines and the cache's positive cap remain in the future.
    Fresh(DnsAnswer),
    /// Retained last-good answer with no fresh lifetime remaining.
    Stale {
        /// Last successful resolution, including provenance.
        answer: DnsAnswer,
        /// Time since effective expiry (record deadline or cache cap), or
        /// acceptance for unknown TTLs.
        age: Duration,
    },
    /// A cold authoritative denial or SRV service withdrawal within its
    /// observed deadline and the cache's negative TTL cap.
    Negative(DnsError),
    /// No positive answer or currently live authoritative denial.
    Miss,
}

/// Redacted cache snapshot for serving and operational observation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DnsCacheStatus {
    /// Answer to serve, if any.
    pub result: DnsCachedResult,
    /// Effective positive freshness deadline, including the publication cap.
    /// Retained after expiry or failure; `None` if there is no positive answer.
    /// Unknown TTLs use publication time and never become fresh. Use this for
    /// cache scheduling instead of the uncapped [`DnsAnswer::expires_at`]; also
    /// honor [`Self::retry_at`] and in-flight refreshes.
    pub fresh_until: Option<PeerDiscoveryTime>,
    /// Most recent failure; cleared by success, removal or cold-key reclamation.
    pub last_error: Option<DnsError>,
    /// Next allowed attempt after a failure or uncacheable success, even if
    /// that time has elapsed. This does not imply fresh or negative data.
    pub retry_at: Option<PeerDiscoveryTime>,
    /// Whether a refresh remains within its budget at observation time.
    pub refreshing: bool,
}

/// Admission result. Pending callers share the eventual cached result; the
/// driver owns wakeups and must never hold its cache lock over resolver I/O.
#[derive(Debug)]
#[non_exhaustive]
#[must_use = "start the admitted refresh or explicitly drop its token"]
pub enum DnsRefresh {
    /// This caller owns the one allowed refresh for this key.
    Start(DnsRefreshToken),
    /// Another refresh is in flight; serve the cache or await driver notification.
    Pending,
    /// The entry is fresh or its retry/negative TTL has not elapsed.
    Suppressed,
}

/// One-use publication token. Dropping it does not erase last-good data: its
/// bounded lease expires and a subsequent admission observes a timeout.
#[must_use = "publish the refresh result or explicitly drop the token to abandon it"]
pub struct DnsRefreshToken {
    key: DnsCacheKey,
    identity: Arc<()>,
}

impl fmt::Debug for DnsRefreshToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DnsRefreshToken([redacted])")
    }
}

/// Cache admission errors, separate from DNS response/error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DnsCacheError {
    /// All slots belong to keys retained by consumers. Remove obsolete keys.
    #[error("dns-cache-capacity")]
    Capacity,
}

struct Flight {
    identity: Arc<()>,
    deadline: PeerDiscoveryTime,
}

#[derive(Default)]
struct Entry {
    answer: Option<DnsAnswer>,
    expires_at: Option<PeerDiscoveryTime>,
    last_error: Option<DnsError>,
    retry_at: Option<PeerDiscoveryTime>,
    negative_expires_at: Option<PeerDiscoveryTime>,
    failures: u32,
    flight: Option<Flight>,
}

impl Entry {
    fn fresh(&self, now: PeerDiscoveryTime) -> bool {
        self.answer.is_some() && self.expires_at.is_some_and(|expiry| now < expiry)
    }

    fn due(&self, now: PeerDiscoveryTime) -> bool {
        self.flight.is_none() && !self.fresh(now) && self.retry_at.is_none_or(|retry| now >= retry)
    }

    fn failure(
        &mut self,
        error: DnsError,
        now: PeerDiscoveryTime,
        retry: &mut DnsRetryPolicy,
        max_negative_ttl: Duration,
    ) {
        self.flight = None;
        self.last_error = Some(error);
        // Retry pacing is separate from authority: an uncacheable denial must
        // remain a miss even while its next attempt is suppressed.
        self.negative_expires_at = error
            .negative_deadline()
            .map(|expiry| expiry.min(deadline(now, max_negative_ttl)))
            .filter(|expiry| now < *expiry);
        let retry_at = if let Some(expiry) = self.negative_expires_at {
            self.failures = 0;
            expiry
        } else {
            self.failures = self.failures.saturating_add(1);
            deadline(now, retry.delay(self.failures))
        };
        self.retry_at = Some(retry_at);
    }

    fn expire_flight(
        &mut self,
        now: PeerDiscoveryTime,
        retry: &mut DnsRetryPolicy,
        max_negative_ttl: Duration,
    ) {
        if let Some(expired_at) = self
            .flight
            .as_ref()
            .map(|flight| flight.deadline)
            .filter(|d| now >= *d)
        {
            self.failure(DnsError::Timeout, expired_at, retry, max_negative_ttl);
        }
    }
}

/// DNS-aware, caller-clock cache with bounded admission. Consumers explicitly
/// remove obsolete keys with positive data; capacity pressure never discards a
/// last-good answer. Expired cold failures without a flight can be reclaimed.
/// Reclaimed keys lose their error and leave [`Self::refresh_due`]; drivers
/// must retain their configured key set and re-admit keys they still need.
///
/// Callers serialize mutations, admit one refresh, do I/O outside their lock,
/// and finish using its token. Tokens from removed/recreated keys, other caches
/// or expired attempts cannot publish. Use one monotonic clock domain for all
/// observations and resolver records; the cache owns no tasks or sockets.
pub struct DnsCache {
    entries: HashMap<DnsCacheKey, Entry>,
    capacity: usize,
    retry: DnsRetryPolicy,
    max_ttl: Duration,
    max_negative_ttl: Duration,
    refresh_interval: Duration,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(256, DnsRetryPolicy::default())
    }
}

impl fmt::Debug for DnsCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsCache")
            .field("entry_count", &self.entries.len())
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl DnsCache {
    /// Create a cache. Capacity is clamped to at least one.
    pub fn new(capacity: usize, retry: DnsRetryPolicy) -> Self {
        Self {
            entries: HashMap::new(),
            capacity: capacity.max(1),
            retry,
            max_ttl: Duration::from_secs(7 * 24 * 60 * 60),
            max_negative_ttl: Duration::from_secs(3 * 60 * 60),
            refresh_interval: Duration::from_secs(5),
        }
    }

    /// Set lifetime caps for subsequent publications. The default positive
    /// cap is seven days, as recommended by
    /// [RFC 8767 section 4](https://www.rfc-editor.org/rfc/rfc8767.html#section-4).
    /// The default negative cap is three hours, within the range suggested by
    /// [RFC 2308 section 5](https://www.rfc-editor.org/rfc/rfc2308.html#section-5).
    /// Both caps are clamped to 2^31 - 1 seconds under this API's conservative
    /// [RFC 2181 section 8](https://www.rfc-editor.org/rfc/rfc2181.html#section-8)
    /// policy; the negative cap is at most the positive cap. Zero disables fresh
    /// caching but preserves retry pacing and positive last-good retention.
    /// Caps never extend record deadlines or rewrite their provenance.
    /// The negative cap also bounds positive answers with a partial denial
    /// recorded using [`DnsAnswer::with_negative_freshness_bound`].
    pub fn with_ttl_caps(mut self, max_ttl: Duration, max_negative_ttl: Duration) -> Self {
        self.max_ttl = max_ttl.min(MAX_TTL);
        self.max_negative_ttl = max_negative_ttl.min(self.max_ttl);
        self
    }

    /// Set refresh pacing for subsequent successful publications with zero,
    /// unknown or expired effective TTLs. The default interval is five seconds,
    /// with equal jitter from half to all of the interval. This does not grant
    /// freshness or change failure backoff. Clamped to 1 ms–2^31 - 1 seconds,
    /// at millisecond precision, so zero and unrepresentable values cannot
    /// produce immediate retry loops. Previously scheduled retries are kept.
    pub fn with_refresh_interval(mut self, interval: Duration) -> Self {
        self.refresh_interval = interval.clamp(Duration::from_millis(1), MAX_TTL);
        self
    }

    /// Number of retained keys, including cold failures and in-flight entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no keys are retained.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Explicitly retire an obsolete key and fence all of its outstanding work.
    pub fn remove(&mut self, key: &DnsCacheKey) -> bool {
        self.entries.remove(key).is_some()
    }

    /// Read a snapshot without I/O or eviction. An abandoned attempt is reaped
    /// by [`Self::begin_refresh`] or [`Self::refresh_due`], not by this read.
    pub fn lookup(&self, key: &DnsCacheKey, now: PeerDiscoveryTime) -> DnsCacheStatus {
        let Some(entry) = self.entries.get(key) else {
            return DnsCacheStatus {
                result: DnsCachedResult::Miss,
                fresh_until: None,
                last_error: None,
                retry_at: None,
                refreshing: false,
            };
        };
        let result = if let Some(answer) = &entry.answer {
            if entry.fresh(now) {
                DnsCachedResult::Fresh(answer.clone())
            } else {
                DnsCachedResult::Stale {
                    answer: answer.clone(),
                    age: Duration::from_millis(
                        now.0.saturating_sub(entry.expires_at.unwrap_or(now).0),
                    ),
                }
            }
        } else if let Some(error) = entry
            .last_error
            .filter(|_| entry.negative_expires_at.is_some_and(|expiry| now < expiry))
        {
            DnsCachedResult::Negative(error)
        } else {
            DnsCachedResult::Miss
        };
        DnsCacheStatus {
            result,
            fresh_until: entry.expires_at,
            last_error: entry.last_error,
            retry_at: entry.retry_at,
            refreshing: entry
                .flight
                .as_ref()
                .is_some_and(|flight| now < flight.deadline),
        }
    }

    /// Atomically admit one refresh. The attempt budget is clamped to 1 ms;
    /// driver cancellation should finish the token with a timeout/error.
    ///
    /// # Errors
    /// Returns [`DnsCacheError::Capacity`] for a new key at capacity after
    /// reclaiming expired cold failures without a flight. Positive last-good
    /// data, live negatives/backoffs and in-flight work are never evicted.
    pub fn begin_refresh(
        &mut self,
        query: &DnsQuery,
        now: PeerDiscoveryTime,
        timeout: Duration,
    ) -> Result<DnsRefresh, DnsCacheError> {
        let key = query.cache_key();
        if !self.entries.contains_key(&key) && self.entries.len() >= self.capacity {
            self.entries.retain(|_, entry| {
                entry.expire_flight(now, &mut self.retry, self.max_negative_ttl);
                entry.answer.is_some()
                    || entry.flight.is_some()
                    || entry.retry_at.is_none_or(|retry| now < retry)
            });
            if self.entries.len() >= self.capacity {
                return Err(DnsCacheError::Capacity);
            }
        }
        let entry = self.entries.entry(key.clone()).or_default();
        entry.expire_flight(now, &mut self.retry, self.max_negative_ttl);
        if entry.flight.is_some() {
            return Ok(DnsRefresh::Pending);
        }
        if !entry.due(now) {
            return Ok(DnsRefresh::Suppressed);
        }
        let identity = Arc::new(());
        entry.flight = Some(Flight {
            identity: Arc::clone(&identity),
            deadline: deadline(now, timeout.max(Duration::from_millis(1))),
        });
        Ok(DnsRefresh::Start(DnsRefreshToken { key, identity }))
    }

    /// Finish the admitted attempt. Returns false for an expired, foreign or
    /// removed token; a late answer can never overwrite newer state. A valid
    /// failure updates retry/error metadata and preserves every last-good byte.
    /// Future-dated record observations (including retained alternate paths),
    /// disallowed families, or mismatched S-NAPTR origin/filter are malformed.
    #[must_use = "check whether this attempt still owned publication"]
    pub fn finish_refresh(
        &mut self,
        token: DnsRefreshToken,
        result: Result<DnsAnswer, DnsError>,
        now: PeerDiscoveryTime,
    ) -> bool {
        let Some(entry) = self.entries.get_mut(&token.key) else {
            return false;
        };
        if !entry
            .flight
            .as_ref()
            .is_some_and(|flight| Arc::ptr_eq(&flight.identity, &token.identity))
        {
            return false;
        }
        entry.expire_flight(now, &mut self.retry, self.max_negative_ttl);
        if entry.flight.is_none() {
            return false;
        }
        let result = result
            .map_err(|error| {
                if error.soa().is_some_and(|soa| soa.observed_at() > now) {
                    DnsError::MalformedAnswer
                } else {
                    error
                }
            })
            .and_then(|answer| {
                if answer.candidates().iter().any(|candidate| {
                    !token
                        .key
                        .0
                        .address_family()
                        .accepts(candidate.peer().endpoint)
                        || candidate.all_records().any(|r| r.observed_at > now)
                        || candidate.snaptr().is_some_and(|provenance| {
                            provenance.origin() != token.key.0.name()
                                || Some(provenance.filter()) != token.key.0.snaptr_filter()
                                || candidate.peer().transport != token.key.0.input().transport
                        })
                }) {
                    Err(DnsError::MalformedAnswer)
                } else {
                    Ok(answer)
                }
            });
        match result {
            Ok(answer) => {
                let expires_at = answer
                    .capped_expires_at(
                        deadline(now, self.max_ttl),
                        deadline(now, self.max_negative_ttl),
                    )
                    .unwrap_or(now);
                entry.expires_at = Some(expires_at);
                entry.answer = Some(answer);
                entry.last_error = None;
                entry.negative_expires_at = None;
                entry.retry_at = if expires_at <= now {
                    // A successful but immediately stale result still needs
                    // pacing. It resets failure backoff without granting TTL.
                    Some(deadline(
                        now,
                        self.retry.jitter(millis(self.refresh_interval)),
                    ))
                } else {
                    None
                };
                entry.failures = 0;
                entry.flight = None;
            }
            Err(error) => entry.failure(error, now, &mut self.retry, self.max_negative_ttl),
        }
        true
    }

    /// Reap expired refresh leases and return all retained keys due for retry.
    /// Order is unspecified. Admission still requires [`Self::begin_refresh`].
    /// Reclaimed cold keys are absent, along with their last errors. Drivers
    /// must separately track configured keys and re-admit any they still need.
    pub fn refresh_due(&mut self, now: PeerDiscoveryTime) -> Vec<DnsCacheKey> {
        self.entries
            .iter_mut()
            .filter_map(|(key, entry)| {
                entry.expire_flight(now, &mut self.retry, self.max_negative_ttl);
                entry.due(now).then(|| key.clone())
            })
            .collect()
    }
}
