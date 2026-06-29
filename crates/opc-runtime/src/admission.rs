//! Listener admission helpers for bounded per-source throttling.
//!
//! Products own their admission policy values, but the mechanics for
//! concurrent source-key token buckets, first-throttle signaling, deterministic
//! eviction, and redaction-safe diagnostics are reusable runtime plumbing.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use thiserror::Error;

const DEFAULT_SHARD_COUNT: usize = 16;

/// Admission decision returned by [`SourceTokenBucket::admit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceAdmissionDecision {
    /// The source had a token available and the listener may accept the event.
    Allowed,
    /// The source is throttled, and this is the first denied event since the
    /// last accepted event for this source.
    FirstThrottled,
    /// The source remains throttled after a previous denied event.
    Throttled,
}

/// Policy for a sharded bounded source-key token bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceTokenBucketPolicy {
    refill_tokens: NonZeroU32,
    refill_interval: Duration,
    burst_tokens: NonZeroU32,
    max_entries: NonZeroUsize,
    shard_count: NonZeroUsize,
}

impl SourceTokenBucketPolicy {
    /// Build a source-key token bucket policy.
    ///
    /// `refill_tokens` are added every `refill_interval`, capped at
    /// `burst_tokens`. `max_entries` bounds the number of remembered source
    /// keys across all shards, and `shard_count` must not exceed it.
    pub fn new(
        refill_tokens: NonZeroU32,
        refill_interval: Duration,
        burst_tokens: NonZeroU32,
        max_entries: NonZeroUsize,
        shard_count: NonZeroUsize,
    ) -> Result<Self, SourceTokenBucketPolicyError> {
        if refill_interval.is_zero() {
            return Err(SourceTokenBucketPolicyError::ZeroRefillInterval);
        }
        if shard_count.get() > max_entries.get() {
            return Err(SourceTokenBucketPolicyError::ShardCountExceedsMaxEntries);
        }

        Ok(Self {
            refill_tokens,
            refill_interval,
            burst_tokens,
            max_entries,
            shard_count,
        })
    }

    /// Build a per-second token bucket policy with a bounded default shard count.
    pub fn per_second(
        refill_per_second: NonZeroU32,
        burst_tokens: NonZeroU32,
        max_entries: NonZeroUsize,
    ) -> Self {
        let shard_count = NonZeroUsize::new(DEFAULT_SHARD_COUNT.min(max_entries.get()))
            .expect("default shard count is non-zero");
        Self::new(
            refill_per_second,
            Duration::from_secs(1),
            burst_tokens,
            max_entries,
            shard_count,
        )
        .expect("per-second policy uses non-zero interval and bounded shards")
    }

    /// Tokens added per refill interval.
    pub const fn refill_tokens(self) -> NonZeroU32 {
        self.refill_tokens
    }

    /// Refill interval for the bucket.
    pub const fn refill_interval(self) -> Duration {
        self.refill_interval
    }

    /// Maximum tokens that can accumulate for one source.
    pub const fn burst_tokens(self) -> NonZeroU32 {
        self.burst_tokens
    }

    /// Maximum remembered source entries across all shards.
    pub const fn max_entries(self) -> NonZeroUsize {
        self.max_entries
    }

    /// Number of shards used to reduce hot-listener lock contention.
    pub const fn shard_count(self) -> NonZeroUsize {
        self.shard_count
    }
}

/// Redaction-safe policy construction error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SourceTokenBucketPolicyError {
    /// Refill interval must be non-zero.
    #[error("source token bucket refill interval must be non-zero")]
    ZeroRefillInterval,
    /// Shard count must not exceed max entries.
    #[error("source token bucket shard count exceeds max entries")]
    ShardCountExceedsMaxEntries,
}

impl SourceTokenBucketPolicyError {
    /// Stable machine-readable error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::ZeroRefillInterval => "zero_refill_interval",
            Self::ShardCountExceedsMaxEntries => "shard_count_exceeds_max_entries",
        }
    }
}

/// Sharded bounded source-key token bucket.
///
/// The key type is caller-owned and can be `IpAddr`, a socket peer key, or a
/// product-neutral source identity. `Debug` never prints source keys.
pub struct SourceTokenBucket<K> {
    policy: SourceTokenBucketPolicy,
    shards: Arc<Vec<ShardCell<K>>>,
}

impl<K> Clone for SourceTokenBucket<K> {
    fn clone(&self) -> Self {
        Self {
            policy: self.policy,
            shards: Arc::clone(&self.shards),
        }
    }
}

impl<K> SourceTokenBucket<K>
where
    K: Clone + Eq + Hash,
{
    /// Construct an empty source-key token bucket.
    pub fn new(policy: SourceTokenBucketPolicy) -> Self {
        let shard_count = policy.shard_count.get();
        let max_entries = policy.max_entries.get();
        let base_capacity = max_entries / shard_count;
        let remainder = max_entries % shard_count;
        let shards = (0..shard_count)
            .map(|idx| {
                let capacity = base_capacity + usize::from(idx < remainder);
                ShardCell::new(capacity)
            })
            .collect();

        Self {
            policy,
            shards: Arc::new(shards),
        }
    }

    /// Return the policy used by this limiter.
    pub const fn policy(&self) -> SourceTokenBucketPolicy {
        self.policy
    }

    /// Admit or throttle one event for `key` at caller-supplied monotonic time.
    pub fn admit(&self, key: K, now: Instant) -> SourceAdmissionDecision {
        let shard_index = self.shard_index(&key);
        let shard = &self.shards[shard_index];
        let mut state = shard.lock_state();
        let sequence = state.next_sequence();

        if state.entries.contains_key(&key) {
            let decision = {
                let bucket = state
                    .entries
                    .get_mut(&key)
                    .expect("entry existence checked above");
                bucket.admit(now, self.policy)
            };
            state.mark_access(key, sequence);
            return decision;
        }

        if state.entries.len() >= shard.capacity {
            state.evict_one();
        }

        let mut bucket = BucketState::new(now, self.policy.burst_tokens.get());
        let decision = bucket.admit(now, self.policy);
        bucket.last_access_sequence = sequence;
        state.mark_access(key.clone(), sequence);
        state.entries.insert(key, bucket);
        decision
    }

    /// Number of source entries currently retained across all shards.
    pub fn entry_count(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.lock_state().entries.len())
            .sum()
    }

    /// Returns `true` when no source entries are retained.
    pub fn is_empty(&self) -> bool {
        self.entry_count() == 0
    }

    /// Clear all retained source entries.
    pub fn clear(&self) {
        for shard in self.shards.iter() {
            let mut state = shard.lock_state();
            state.entries.clear();
            state.access_order.clear();
        }
    }

    fn shard_index(&self, key: &K) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.shards.len()
    }
}

impl<K> fmt::Debug for SourceTokenBucket<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceTokenBucket")
            .field("policy", &self.policy)
            .field("shard_count", &self.shards.len())
            .finish_non_exhaustive()
    }
}

struct ShardCell<K> {
    capacity: usize,
    state: Mutex<ShardState<K>>,
}

impl<K> ShardCell<K> {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            state: Mutex::new(ShardState::default()),
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, ShardState<K>> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

struct ShardState<K> {
    entries: HashMap<K, BucketState>,
    access_order: VecDeque<(K, u64)>,
    next_sequence: u64,
}

impl<K> Default for ShardState<K> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            access_order: VecDeque::new(),
            next_sequence: 0,
        }
    }
}

impl<K> ShardState<K>
where
    K: Clone + Eq + Hash,
{
    fn next_sequence(&mut self) -> u64 {
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.next_sequence
    }

    fn mark_access(&mut self, key: K, sequence: u64) {
        if let Some(bucket) = self.entries.get_mut(&key) {
            bucket.last_access_sequence = sequence;
        }
        self.access_order.push_back((key, sequence));
    }

    fn evict_one(&mut self) {
        while let Some((key, sequence)) = self.access_order.pop_front() {
            if self
                .entries
                .get(&key)
                .is_some_and(|bucket| bucket.last_access_sequence == sequence)
            {
                self.entries.remove(&key);
                return;
            }
        }
    }
}

struct BucketState {
    tokens: u32,
    last_refill: Instant,
    last_access_sequence: u64,
    throttled: bool,
}

impl BucketState {
    fn new(now: Instant, burst_tokens: u32) -> Self {
        Self {
            tokens: burst_tokens,
            last_refill: now,
            last_access_sequence: 0,
            throttled: false,
        }
    }

    fn admit(&mut self, now: Instant, policy: SourceTokenBucketPolicy) -> SourceAdmissionDecision {
        self.refill(now, policy);
        if self.tokens > 0 {
            self.tokens -= 1;
            self.throttled = false;
            return SourceAdmissionDecision::Allowed;
        }

        if self.throttled {
            SourceAdmissionDecision::Throttled
        } else {
            self.throttled = true;
            SourceAdmissionDecision::FirstThrottled
        }
    }

    fn refill(&mut self, now: Instant, policy: SourceTokenBucketPolicy) {
        let Some(elapsed) = now.checked_duration_since(self.last_refill) else {
            return;
        };
        let interval_ns = policy.refill_interval.as_nanos();
        let intervals = elapsed.as_nanos() / interval_ns;
        if intervals == 0 {
            return;
        }

        let refill = intervals.saturating_mul(u128::from(policy.refill_tokens.get()));
        let refill = refill.min(u128::from(u32::MAX)) as u32;
        self.tokens = self
            .tokens
            .saturating_add(refill)
            .min(policy.burst_tokens.get());

        let advanced_ns = intervals.saturating_mul(interval_ns);
        if let Ok(advanced_ns) = u64::try_from(advanced_ns) {
            if let Some(next_refill) = self
                .last_refill
                .checked_add(Duration::from_nanos(advanced_ns))
            {
                self.last_refill = next_refill;
                return;
            }
        }
        self.last_refill = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn nonzero_u32(value: u32) -> NonZeroU32 {
        NonZeroU32::new(value).expect("non-zero u32")
    }

    fn nonzero_usize(value: usize) -> NonZeroUsize {
        NonZeroUsize::new(value).expect("non-zero usize")
    }

    fn policy() -> SourceTokenBucketPolicy {
        SourceTokenBucketPolicy::new(
            nonzero_u32(1),
            Duration::from_secs(1),
            nonzero_u32(2),
            nonzero_usize(8),
            nonzero_usize(2),
        )
        .expect("valid policy")
    }

    #[test]
    fn token_bucket_reports_allowed_first_throttled_and_throttled() {
        let limiter = SourceTokenBucket::new(policy());
        let now = Instant::now();
        let key = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

        assert_eq!(limiter.admit(key, now), SourceAdmissionDecision::Allowed);
        assert_eq!(limiter.admit(key, now), SourceAdmissionDecision::Allowed);
        assert_eq!(
            limiter.admit(key, now),
            SourceAdmissionDecision::FirstThrottled
        );
        assert_eq!(limiter.admit(key, now), SourceAdmissionDecision::Throttled);

        let later = now + Duration::from_secs(1);
        assert_eq!(limiter.admit(key, later), SourceAdmissionDecision::Allowed);
        assert_eq!(
            limiter.admit(key, later),
            SourceAdmissionDecision::FirstThrottled
        );
    }

    #[test]
    fn injected_time_is_deterministic_and_ignores_clock_rewind() {
        let limiter = SourceTokenBucket::new(policy());
        let start = Instant::now();
        let key = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));

        assert_eq!(limiter.admit(key, start), SourceAdmissionDecision::Allowed);
        assert_eq!(limiter.admit(key, start), SourceAdmissionDecision::Allowed);
        assert_eq!(
            limiter.admit(key, start - Duration::from_millis(1)),
            SourceAdmissionDecision::FirstThrottled
        );
        assert_eq!(
            limiter.admit(key, start + Duration::from_millis(999)),
            SourceAdmissionDecision::Throttled
        );
        assert_eq!(
            limiter.admit(key, start + Duration::from_secs(1)),
            SourceAdmissionDecision::Allowed
        );
    }

    #[test]
    fn bounded_eviction_is_lru_deterministic_within_shard() {
        let policy = SourceTokenBucketPolicy::new(
            nonzero_u32(1),
            Duration::from_secs(60),
            nonzero_u32(1),
            nonzero_usize(2),
            nonzero_usize(1),
        )
        .expect("valid policy");
        let limiter = SourceTokenBucket::new(policy);
        let now = Instant::now();

        assert_eq!(limiter.admit("a", now), SourceAdmissionDecision::Allowed);
        assert_eq!(limiter.admit("b", now), SourceAdmissionDecision::Allowed);
        assert_eq!(
            limiter.admit("a", now),
            SourceAdmissionDecision::FirstThrottled
        );
        assert_eq!(limiter.admit("c", now), SourceAdmissionDecision::Allowed);
        assert_eq!(limiter.entry_count(), 2);

        assert_eq!(limiter.admit("b", now), SourceAdmissionDecision::Allowed);
    }

    #[test]
    fn policy_validation_fails_closed() {
        let zero_interval = SourceTokenBucketPolicy::new(
            nonzero_u32(1),
            Duration::ZERO,
            nonzero_u32(1),
            nonzero_usize(1),
            nonzero_usize(1),
        )
        .expect_err("zero interval rejected");
        assert_eq!(zero_interval.code(), "zero_refill_interval");

        let too_many_shards = SourceTokenBucketPolicy::new(
            nonzero_u32(1),
            Duration::from_secs(1),
            nonzero_u32(1),
            nonzero_usize(1),
            nonzero_usize(2),
        )
        .expect_err("too many shards rejected");
        assert_eq!(too_many_shards.code(), "shard_count_exceeds_max_entries");
    }

    #[test]
    fn poisoned_lock_recovers_without_panicking() {
        let limiter = SourceTokenBucket::<IpAddr>::new(policy());
        let poisoned = catch_unwind(AssertUnwindSafe(|| {
            let _guard = limiter.shards[0].state.lock().expect("lock shard");
            panic!("poison shard");
        }));
        assert!(poisoned.is_err());

        let decision = limiter.admit(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)), Instant::now());
        assert_eq!(decision, SourceAdmissionDecision::Allowed);
    }

    #[test]
    fn debug_does_not_expose_source_keys() {
        let limiter = SourceTokenBucket::new(policy());
        let now = Instant::now();
        let key = "subscriber-secret-source";

        assert_eq!(limiter.admit(key, now), SourceAdmissionDecision::Allowed);
        let debug = format!("{limiter:?}");

        assert!(debug.contains("SourceTokenBucket"));
        assert!(!debug.contains(key));
    }

    #[test]
    fn clear_removes_all_retained_entries() {
        let limiter = SourceTokenBucket::new(policy());
        let now = Instant::now();

        assert_eq!(limiter.admit("a", now), SourceAdmissionDecision::Allowed);
        assert_eq!(limiter.admit("b", now), SourceAdmissionDecision::Allowed);
        assert!(!limiter.is_empty());

        limiter.clear();

        assert!(limiter.is_empty());
    }
}
