//! [`PeerAddressCache`] — a pure sync cache of resolved peer candidates.
//!
//! The cache holds the last-known-good [`PeerCandidate`]s for each
//! [`DiscoveryCacheKey`] together with a TTL, so a product's async driver can
//! serve resolved peers without re-resolving on every request and can refresh
//! them off any request hot path. It is mode-generic: nothing here is specific
//! to A/AAAA resolution, so a future SRV or S-NAPTR resolver reuses it unchanged.
//!
//! Like [`PeerNegativeCache`](crate::PeerNegativeCache) it is a deterministic
//! state machine: all time flows in through [`PeerDiscoveryTime`], there are no
//! threads and no interior clock, and it performs no I/O. The async driving loop
//! (blocking-lookup offload, timeouts, periodic refresh) stays product-side by
//! design.
//!
//! Serving vs. refreshing are separate concerns:
//!
//! - [`PeerAddressCache::get`] answers *what to serve now* with a three-state
//!   [`CachedPeers`] (`Fresh` / `Stale` / `Miss`), enabling stale-while-
//!   revalidate: a caller may serve `Stale` last-known-good candidates while a
//!   refresh is in flight.
//! - [`PeerAddressCache::refresh_due`] answers *what to re-resolve now* (expired
//!   TTL, or a failed-refresh backoff that has elapsed).
//!
//! A refresh failure never evicts the last-known-good candidates
//! ([`PeerAddressCache::record_failure`]); it only arms a backoff so
//! [`PeerAddressCache::refresh_due`] does not hot-loop against a dead resolver.

use std::collections::HashMap;
use std::time::Duration;

use crate::{DiscoveryCacheKey, PeerCandidate, PeerDiscoveryTime, ResolvedPeers};

/// Default entry capacity. Configured packet-core peers are few, so this is
/// generous headroom; the hard cap only guards against unbounded growth if
/// discovery inputs churn.
const DEFAULT_CAPACITY: usize = 256;

/// Default backoff before a failed refresh is retried, matching the
/// address resolver's negative-cache TTL so a dead resolver is polled at the
/// same cadence rather than hot-looping.
const DEFAULT_RETRY_BACKOFF: Duration = Duration::from_secs(5);

/// Result of a [`PeerAddressCache::get`] lookup.
///
/// The `Stale` variant still carries the last-known-good candidates so a caller
/// can serve them while a refresh is scheduled (stale-while-revalidate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CachedPeers {
    /// A live entry: candidates are within their TTL.
    Fresh(Vec<PeerCandidate>),
    /// An expired entry whose last-known-good candidates are still available.
    Stale(Vec<PeerCandidate>),
    /// No entry for the key.
    Miss,
}

impl CachedPeers {
    /// Borrow the cached candidates for `Fresh`/`Stale`, or `None` on `Miss`.
    #[must_use]
    pub fn candidates(&self) -> Option<&[PeerCandidate]> {
        match self {
            Self::Fresh(candidates) | Self::Stale(candidates) => Some(candidates),
            Self::Miss => None,
        }
    }

    /// True only for `Miss`.
    #[must_use]
    pub fn is_miss(&self) -> bool {
        matches!(self, Self::Miss)
    }
}

/// One cached resolution.
#[derive(Debug, Clone)]
struct CacheEntry {
    candidates: Vec<PeerCandidate>,
    /// TTL expiry (`resolved_at + ttl`); `None` when the addition overflowed the
    /// monotonic clock, in which case the entry is treated as non-expiring.
    expires_at: Option<PeerDiscoveryTime>,
    /// When set, the last refresh failed and re-resolution is suppressed until
    /// this time so a dead resolver is not polled on every tick.
    retry_at: Option<PeerDiscoveryTime>,
    /// Monotonic write sequence, used for deterministic oldest-first eviction.
    seq: u64,
}

impl CacheEntry {
    fn is_fresh(&self, now: PeerDiscoveryTime) -> bool {
        match self.expires_at {
            Some(expires_at) => now < expires_at,
            None => true,
        }
    }

    fn is_expired(&self, now: PeerDiscoveryTime) -> bool {
        match self.expires_at {
            Some(expires_at) => now >= expires_at,
            None => false,
        }
    }

    fn is_refresh_due(&self, now: PeerDiscoveryTime) -> bool {
        match self.retry_at {
            // A failed refresh is suppressed until the backoff elapses.
            Some(retry_at) => now >= retry_at,
            // Otherwise a refresh is due once the TTL has expired.
            None => self.is_expired(now),
        }
    }
}

/// Pure sync cache of resolved peer candidates, keyed by [`DiscoveryCacheKey`].
///
/// Bounded to a fixed capacity with deterministic oldest-first (least-recently-
/// recorded) eviction; see the module docs for the serving vs. refreshing model.
#[derive(Debug, Clone)]
pub struct PeerAddressCache {
    entries: HashMap<DiscoveryCacheKey, CacheEntry>,
    capacity: usize,
    retry_backoff: Duration,
    seq: u64,
}

impl Default for PeerAddressCache {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY, DEFAULT_RETRY_BACKOFF)
    }
}

impl PeerAddressCache {
    /// Build a cache with an explicit `capacity` and failed-refresh
    /// `retry_backoff`.
    ///
    /// `capacity` is clamped to at least one so the cache can always hold a
    /// resolution. A zero `retry_backoff` disables failure suppression (a failed
    /// entry is due again on the next [`refresh_due`](Self::refresh_due) poll).
    #[must_use]
    pub fn new(capacity: usize, retry_backoff: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            capacity: capacity.max(1),
            retry_backoff,
            seq: 0,
        }
    }

    /// Number of cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Configured hard capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Look up the entry for `key` at `now`.
    ///
    /// Returns [`CachedPeers::Fresh`] within the TTL, [`CachedPeers::Stale`] with
    /// the last-known-good candidates once the TTL has expired, or
    /// [`CachedPeers::Miss`] when nothing is cached. Serving never prunes: a
    /// stale entry is retained until a refresh replaces it.
    #[must_use]
    pub fn get(&self, key: &DiscoveryCacheKey, now: PeerDiscoveryTime) -> CachedPeers {
        match self.entries.get(key) {
            Some(entry) if entry.is_fresh(now) => CachedPeers::Fresh(entry.candidates.clone()),
            Some(entry) => CachedPeers::Stale(entry.candidates.clone()),
            None => CachedPeers::Miss,
        }
    }

    /// Record a successful resolution, replacing any prior entry for `key`.
    ///
    /// Clears any pending failure backoff and (re)arms the TTL from `now`. When a
    /// new key would exceed the capacity, the least-recently-recorded entry is
    /// evicted first.
    pub fn record_success(
        &mut self,
        key: DiscoveryCacheKey,
        resolved: ResolvedPeers,
        now: PeerDiscoveryTime,
        ttl: Duration,
    ) {
        self.seq += 1;
        let entry = CacheEntry {
            candidates: resolved.candidates,
            expires_at: now.checked_add(ttl),
            retry_at: None,
            seq: self.seq,
        };
        if !self.entries.contains_key(&key) && self.entries.len() >= self.capacity {
            self.evict_oldest();
        }
        self.entries.insert(key, entry);
    }

    /// Record a failed refresh for `key`.
    ///
    /// Keeps the last-known-good candidates untouched (never evicts on a refresh
    /// failure) and arms a backoff so the entry is not re-marked
    /// [`refresh_due`](Self::refresh_due) until `retry_backoff` has elapsed. A
    /// failure for an unknown key is a no-op: there is no prior success to
    /// preserve, so it stays a [`CachedPeers::Miss`] for the caller to handle.
    pub fn record_failure(&mut self, key: &DiscoveryCacheKey, now: PeerDiscoveryTime) {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.retry_at = now.checked_add(self.retry_backoff);
        }
    }

    /// Keys whose entries need re-resolution at `now`: an expired TTL, or a
    /// failed-refresh backoff that has elapsed.
    ///
    /// The result is sorted by key for deterministic ordering.
    #[must_use]
    pub fn refresh_due(&self, now: PeerDiscoveryTime) -> Vec<DiscoveryCacheKey> {
        let mut due: Vec<DiscoveryCacheKey> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.is_refresh_due(now))
            .map(|(key, _)| key.clone())
            .collect();
        due.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        due
    }

    /// Remove the least-recently-recorded entry (smallest write sequence).
    fn evict_oldest(&mut self) {
        if let Some(oldest) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.seq)
            .map(|(key, _)| key.clone())
        {
            self.entries.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DiscoveryTarget, PeerLabel, PeerTransport, ServiceDiscoveryInput, ServiceDiscoveryMode,
    };
    use std::net::SocketAddr;

    fn label(value: &str) -> PeerLabel {
        PeerLabel::new(value).expect("valid label")
    }

    fn key(target: &str) -> DiscoveryCacheKey {
        ServiceDiscoveryInput::new(
            label("s2b-pgwc"),
            DiscoveryTarget::new(target),
            ServiceDiscoveryMode::Address,
            PeerTransport::Udp,
            Some(2123),
        )
        .cache_key()
    }

    fn candidates(port: u16) -> ResolvedPeers {
        ResolvedPeers::new(vec![PeerCandidate::resolved(
            label("s2b-pgwc"),
            SocketAddr::from(([192, 0, 2, 10], port)),
            PeerTransport::Udp,
            ServiceDiscoveryMode::Address,
            0,
            u16::MAX,
        )])
    }

    fn t(millis: u64) -> PeerDiscoveryTime {
        PeerDiscoveryTime::from_millis(millis)
    }

    #[test]
    fn miss_before_any_record() {
        let cache = PeerAddressCache::default();
        assert_eq!(cache.get(&key("peer.invalid"), t(0)), CachedPeers::Miss);
        assert!(cache.is_empty());
    }

    #[test]
    fn fresh_then_stale_across_ttl_expiry() {
        let mut cache = PeerAddressCache::default();
        let k = key("peer.invalid");
        cache.record_success(
            k.clone(),
            candidates(2123),
            t(1_000),
            Duration::from_secs(10),
        );

        // Within the TTL the entry is fresh.
        match cache.get(&k, t(5_000)) {
            CachedPeers::Fresh(c) => assert_eq!(c.len(), 1),
            other => panic!("expected fresh, got {other:?}"),
        }
        // At and after expiry it is stale but still carries last-known-good.
        assert!(matches!(cache.get(&k, t(11_000)), CachedPeers::Stale(_)));
        assert_eq!(
            cache.get(&k, t(50_000)).candidates().map(<[_]>::len),
            Some(1)
        );
    }

    #[test]
    fn refresh_due_only_after_ttl_expiry() {
        let mut cache = PeerAddressCache::default();
        let k = key("peer.invalid");
        cache.record_success(
            k.clone(),
            candidates(2123),
            t(1_000),
            Duration::from_secs(10),
        );

        assert!(cache.refresh_due(t(5_000)).is_empty());
        assert_eq!(cache.refresh_due(t(11_000)), vec![k]);
    }

    #[test]
    fn failure_keeps_last_known_good_and_backs_off() {
        let mut cache = PeerAddressCache::new(8, Duration::from_secs(30));
        let k = key("peer.invalid");
        cache.record_success(k.clone(), candidates(2123), t(0), Duration::from_secs(10));

        // TTL has expired: entry is stale and refresh is due.
        assert!(matches!(cache.get(&k, t(20_000)), CachedPeers::Stale(_)));
        assert_eq!(cache.refresh_due(t(20_000)), vec![k.clone()]);

        // The refresh fails. Last-known-good candidates survive...
        cache.record_failure(&k, t(20_000));
        assert_eq!(
            cache.get(&k, t(20_000)).candidates().map(<[_]>::len),
            Some(1)
        );
        // ...and the backoff suppresses another refresh until it elapses.
        assert!(cache.refresh_due(t(40_000)).is_empty());
        assert!(cache.refresh_due(t(49_999)).is_empty());
        assert_eq!(cache.refresh_due(t(50_000)), vec![k.clone()]);

        // A later success clears the backoff and re-arms the TTL.
        cache.record_success(
            k.clone(),
            candidates(2124),
            t(50_000),
            Duration::from_secs(10),
        );
        assert!(matches!(cache.get(&k, t(55_000)), CachedPeers::Fresh(_)));
        assert!(cache.refresh_due(t(55_000)).is_empty());
    }

    #[test]
    fn refresh_due_is_sorted_for_determinism() {
        let mut cache = PeerAddressCache::default();
        let mut keys: Vec<DiscoveryCacheKey> = ["c.invalid", "a.invalid", "b.invalid"]
            .iter()
            .map(|host| {
                let k = key(host);
                cache.record_success(k.clone(), candidates(2123), t(0), Duration::from_secs(1));
                k
            })
            .collect();
        keys.sort_by(|a, b| a.as_str().cmp(b.as_str()));

        // All TTLs have expired; the due list must match the sorted key order.
        assert_eq!(cache.refresh_due(t(2_000)), keys);
    }

    #[test]
    fn eviction_is_deterministic_oldest_first() {
        let mut cache = PeerAddressCache::new(2, Duration::from_secs(5));
        let first = key("first.invalid");
        let second = key("second.invalid");
        let third = key("third.invalid");

        cache.record_success(first.clone(), candidates(1), t(0), Duration::from_secs(10));
        cache.record_success(second.clone(), candidates(2), t(1), Duration::from_secs(10));
        // Inserting a third key at capacity evicts the oldest (first) entry.
        cache.record_success(third.clone(), candidates(3), t(2), Duration::from_secs(10));

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(&first, t(3)), CachedPeers::Miss);
        assert!(matches!(cache.get(&second, t(3)), CachedPeers::Fresh(_)));
        assert!(matches!(cache.get(&third, t(3)), CachedPeers::Fresh(_)));
    }

    #[test]
    fn re_recording_a_key_refreshes_its_eviction_age() {
        let mut cache = PeerAddressCache::new(2, Duration::from_secs(5));
        let first = key("first.invalid");
        let second = key("second.invalid");
        let third = key("third.invalid");

        cache.record_success(first.clone(), candidates(1), t(0), Duration::from_secs(10));
        cache.record_success(second.clone(), candidates(2), t(1), Duration::from_secs(10));
        // Touch `first` so it is now the most-recently-recorded entry.
        cache.record_success(first.clone(), candidates(1), t(2), Duration::from_secs(10));
        // The next insert must therefore evict `second`, not `first`.
        cache.record_success(third.clone(), candidates(3), t(3), Duration::from_secs(10));

        assert_eq!(cache.len(), 2);
        assert!(matches!(cache.get(&first, t(4)), CachedPeers::Fresh(_)));
        assert_eq!(cache.get(&second, t(4)), CachedPeers::Miss);
        assert!(matches!(cache.get(&third, t(4)), CachedPeers::Fresh(_)));
    }

    #[test]
    fn record_failure_on_unknown_key_is_a_noop() {
        let mut cache = PeerAddressCache::default();
        let k = key("peer.invalid");
        cache.record_failure(&k, t(0));
        assert!(cache.is_empty());
        assert_eq!(cache.get(&k, t(0)), CachedPeers::Miss);
    }

    #[test]
    fn capacity_is_clamped_to_at_least_one() {
        let mut cache = PeerAddressCache::new(0, Duration::from_secs(5));
        assert_eq!(cache.capacity(), 1);
        let k = key("peer.invalid");
        cache.record_success(k.clone(), candidates(2123), t(0), Duration::from_secs(10));
        assert!(matches!(cache.get(&k, t(1)), CachedPeers::Fresh(_)));
    }

    #[test]
    fn stale_candidates_are_redaction_safe_in_debug() {
        let mut cache = PeerAddressCache::default();
        let k = key("sensitive.realm.example");
        cache.record_success(k.clone(), candidates(2123), t(0), Duration::from_secs(1));
        let debug = format!("{:?}", cache.get(&k, t(5_000)));
        assert!(!debug.contains("192.0.2.10"));
        assert!(!debug.contains("sensitive.realm.example"));
    }
}
