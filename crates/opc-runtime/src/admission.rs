//! Listener admission helpers for bounded source and aggregate throttling.
//!
//! Products own their admission policy values, but the mechanics for
//! concurrent source-key token buckets, a churn-resistant aggregate rate and
//! in-flight ceiling, deterministic eviction, cancellation-safe permits, and
//! redaction-safe diagnostics are reusable runtime plumbing.

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

/// Configuration for a process-wide aggregate admission budget.
///
/// The token bucket bounds the total admission rate across every source, while
/// `max_in_flight` bounds work that has been admitted but not yet completed.
/// All numeric limits are non-zero fixed-width values, so construction cannot
/// create an unbounded table or queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AggregateAdmissionConfig {
    refill_tokens: NonZeroU32,
    refill_interval: Duration,
    burst_tokens: NonZeroU32,
    max_in_flight: NonZeroU32,
}

impl AggregateAdmissionConfig {
    /// Build an aggregate rate and in-flight admission configuration.
    ///
    /// `refill_tokens` are added every `refill_interval`, capped at
    /// `burst_tokens`. `max_in_flight` is the number of simultaneously held
    /// [`AggregateAdmissionPermit`] values.
    pub fn new(
        refill_tokens: NonZeroU32,
        refill_interval: Duration,
        burst_tokens: NonZeroU32,
        max_in_flight: NonZeroU32,
    ) -> Result<Self, AggregateAdmissionConfigError> {
        if refill_interval.is_zero() {
            return Err(AggregateAdmissionConfigError::ZeroRefillInterval);
        }

        Ok(Self {
            refill_tokens,
            refill_interval,
            burst_tokens,
            max_in_flight,
        })
    }

    /// Build a per-second aggregate budget.
    pub const fn per_second(
        refill_per_second: NonZeroU32,
        burst_tokens: NonZeroU32,
        max_in_flight: NonZeroU32,
    ) -> Self {
        Self {
            refill_tokens: refill_per_second,
            refill_interval: Duration::from_secs(1),
            burst_tokens,
            max_in_flight,
        }
    }

    /// Tokens added per refill interval.
    pub const fn refill_tokens(self) -> NonZeroU32 {
        self.refill_tokens
    }

    /// Interval between token refills.
    pub const fn refill_interval(self) -> Duration {
        self.refill_interval
    }

    /// Maximum aggregate tokens that can accumulate.
    pub const fn burst_tokens(self) -> NonZeroU32 {
        self.burst_tokens
    }

    /// Maximum number of simultaneously held permits.
    pub const fn max_in_flight(self) -> NonZeroU32 {
        self.max_in_flight
    }
}

/// Redaction-safe aggregate admission configuration error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AggregateAdmissionConfigError {
    /// Refill interval must be non-zero.
    #[error("aggregate admission refill interval must be non-zero")]
    ZeroRefillInterval,
}

impl AggregateAdmissionConfigError {
    /// Stable machine-readable error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::ZeroRefillInterval => "zero_refill_interval",
        }
    }
}

/// Redaction-safe reason an aggregate admission attempt was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AggregateAdmissionError {
    /// No aggregate rate token is currently available.
    #[error("aggregate admission rate budget exhausted")]
    RateExhausted,
    /// Every aggregate in-flight slot is currently held.
    #[error("aggregate admission in-flight budget exhausted")]
    InFlightExhausted,
}

impl AggregateAdmissionError {
    /// Stable machine-readable error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::RateExhausted => "rate_exhausted",
            Self::InFlightExhausted => "in_flight_exhausted",
        }
    }
}

/// Fixed-cardinality point-in-time aggregate admission metrics.
///
/// Total counters saturate at `u64::MAX`. The snapshot contains no source key,
/// peer identity, packet content, or other caller-controlled label.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AggregateAdmissionMetricsSnapshot {
    /// Successful admissions.
    pub admitted_total: u64,
    /// Admissions rejected because the global rate was exhausted.
    pub rate_exhausted_total: u64,
    /// Admissions rejected because the in-flight ceiling was exhausted.
    pub in_flight_exhausted_total: u64,
    /// Permits released through normal drop or task cancellation.
    pub released_total: u64,
    /// Permits currently held.
    pub in_flight: u32,
    /// Highest observed number of simultaneously held permits.
    pub peak_in_flight: u32,
}

/// Process-wide aggregate rate and in-flight admission budget.
///
/// This budget stores no source keys and has no eviction path. Rotating through
/// new source identities therefore cannot replenish its global token bucket.
/// Clone values share the same budget and fixed-cardinality metrics.
///
/// Compose it after [`SourceTokenBucket`]: first require
/// [`SourceAdmissionDecision::Allowed`], then call [`Self::try_acquire`] and
/// hold the returned permit for the complete expensive operation.
#[derive(Clone)]
pub struct AggregateAdmissionBudget {
    inner: Arc<AggregateAdmissionInner>,
}

impl AggregateAdmissionBudget {
    /// Construct a full-burst aggregate budget with no in-flight work.
    pub fn new(config: AggregateAdmissionConfig) -> Self {
        Self {
            inner: Arc::new(AggregateAdmissionInner {
                config,
                state: Mutex::new(AggregateAdmissionState::new(config)),
            }),
        }
    }

    /// Return the immutable configuration shared by this budget.
    pub fn config(&self) -> AggregateAdmissionConfig {
        self.inner.config
    }

    /// Attempt to consume one global rate token and one in-flight slot.
    ///
    /// This method never waits. A successful call consumes one rate token and
    /// returns a permit that releases its in-flight slot on drop, including
    /// when an async task is cancelled. Rejections never consume a rate token.
    pub fn try_acquire(
        &self,
        now: Instant,
    ) -> Result<AggregateAdmissionPermit, AggregateAdmissionError> {
        let mut state = self.inner.lock_state();
        state.refill(now, self.inner.config);

        if state.in_flight >= self.inner.config.max_in_flight.get() {
            state.in_flight_exhausted_total = state.in_flight_exhausted_total.saturating_add(1);
            return Err(AggregateAdmissionError::InFlightExhausted);
        }

        if state.tokens == 0 {
            state.rate_exhausted_total = state.rate_exhausted_total.saturating_add(1);
            return Err(AggregateAdmissionError::RateExhausted);
        }

        state.tokens -= 1;
        state.in_flight += 1;
        state.peak_in_flight = state.peak_in_flight.max(state.in_flight);
        state.admitted_total = state.admitted_total.saturating_add(1);

        Ok(AggregateAdmissionPermit {
            inner: Arc::clone(&self.inner),
        })
    }

    /// Return a fixed-cardinality point-in-time metrics snapshot.
    pub fn metrics(&self) -> AggregateAdmissionMetricsSnapshot {
        let state = self.inner.lock_state();
        AggregateAdmissionMetricsSnapshot {
            admitted_total: state.admitted_total,
            rate_exhausted_total: state.rate_exhausted_total,
            in_flight_exhausted_total: state.in_flight_exhausted_total,
            released_total: state.released_total,
            in_flight: state.in_flight,
            peak_in_flight: state.peak_in_flight,
        }
    }
}

impl fmt::Debug for AggregateAdmissionBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AggregateAdmissionBudget")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

/// RAII guard for one aggregate in-flight admission slot.
///
/// Hold this value until the admitted operation has completed. Dropping it
/// releases the slot synchronously; this also occurs when an owning future is
/// cancelled. Deliberately leaking the value also deliberately leaks the slot
/// and causes the budget to fail closed once its ceiling is reached.
#[must_use = "hold the permit until the admitted operation completes"]
pub struct AggregateAdmissionPermit {
    inner: Arc<AggregateAdmissionInner>,
}

impl fmt::Debug for AggregateAdmissionPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AggregateAdmissionPermit")
            .finish_non_exhaustive()
    }
}

impl Drop for AggregateAdmissionPermit {
    fn drop(&mut self) {
        self.inner.release();
    }
}

struct AggregateAdmissionInner {
    config: AggregateAdmissionConfig,
    state: Mutex<AggregateAdmissionState>,
}

impl AggregateAdmissionInner {
    fn lock_state(&self) -> MutexGuard<'_, AggregateAdmissionState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn release(&self) {
        let mut state = self.lock_state();
        if state.in_flight > 0 {
            state.in_flight -= 1;
            state.released_total = state.released_total.saturating_add(1);
        }
    }
}

struct AggregateAdmissionState {
    tokens: u32,
    last_refill: Option<Instant>,
    admitted_total: u64,
    rate_exhausted_total: u64,
    in_flight_exhausted_total: u64,
    released_total: u64,
    in_flight: u32,
    peak_in_flight: u32,
}

impl AggregateAdmissionState {
    fn new(config: AggregateAdmissionConfig) -> Self {
        Self {
            tokens: config.burst_tokens.get(),
            last_refill: None,
            admitted_total: 0,
            rate_exhausted_total: 0,
            in_flight_exhausted_total: 0,
            released_total: 0,
            in_flight: 0,
            peak_in_flight: 0,
        }
    }

    fn refill(&mut self, now: Instant, config: AggregateAdmissionConfig) {
        let Some(last_refill) = self.last_refill.as_mut() else {
            self.last_refill = Some(now);
            return;
        };

        refill_token_count(
            &mut self.tokens,
            last_refill,
            now,
            config.refill_tokens.get(),
            config.refill_interval,
            config.burst_tokens.get(),
        );
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
        refill_token_count(
            &mut self.tokens,
            &mut self.last_refill,
            now,
            policy.refill_tokens.get(),
            policy.refill_interval,
            policy.burst_tokens.get(),
        );
    }
}

fn refill_token_count(
    tokens: &mut u32,
    last_refill: &mut Instant,
    now: Instant,
    refill_tokens: u32,
    refill_interval: Duration,
    burst_tokens: u32,
) {
    let Some(elapsed) = now.checked_duration_since(*last_refill) else {
        return;
    };
    let interval_ns = refill_interval.as_nanos();
    if interval_ns == 0 {
        return;
    }
    let intervals = elapsed.as_nanos() / interval_ns;
    if intervals == 0 {
        return;
    }

    let refill = intervals.saturating_mul(u128::from(refill_tokens));
    let refill = refill.min(u128::from(u32::MAX)) as u32;
    *tokens = tokens.saturating_add(refill).min(burst_tokens);

    let advanced_ns = intervals.saturating_mul(interval_ns);
    if let Ok(advanced_ns) = u64::try_from(advanced_ns) {
        if let Some(next_refill) = last_refill.checked_add(Duration::from_nanos(advanced_ns)) {
            *last_refill = next_refill;
            return;
        }
    }
    *last_refill = now;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::{mpsc, Barrier};

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

    fn aggregate_config(
        refill_tokens: u32,
        refill_interval: Duration,
        burst_tokens: u32,
        max_in_flight: u32,
    ) -> AggregateAdmissionConfig {
        AggregateAdmissionConfig::new(
            nonzero_u32(refill_tokens),
            refill_interval,
            nonzero_u32(burst_tokens),
            nonzero_u32(max_in_flight),
        )
        .expect("valid aggregate admission config")
    }

    #[test]
    fn aggregate_config_is_typed_and_rejects_zero_refill_interval() {
        let error = AggregateAdmissionConfig::new(
            nonzero_u32(1),
            Duration::ZERO,
            nonzero_u32(2),
            nonzero_u32(3),
        )
        .expect_err("zero refill interval rejected");
        assert_eq!(error.code(), "zero_refill_interval");

        let config =
            AggregateAdmissionConfig::per_second(nonzero_u32(4), nonzero_u32(5), nonzero_u32(6));
        assert_eq!(config.refill_tokens().get(), 4);
        assert_eq!(config.refill_interval(), Duration::from_secs(1));
        assert_eq!(config.burst_tokens().get(), 5);
        assert_eq!(config.max_in_flight().get(), 6);
    }

    #[test]
    fn aggregate_rate_exhaustion_and_refill_use_injected_time() {
        let config = aggregate_config(2, Duration::from_secs(1), 2, 4);
        let budget = AggregateAdmissionBudget::new(config);
        let origin = Instant::now();
        let start = origin + Duration::from_secs(10);

        let first = budget.try_acquire(start).expect("first token");
        let second = budget.try_acquire(start).expect("second token");
        drop(first);
        drop(second);

        let rate_error = budget
            .try_acquire(start)
            .expect_err("empty rate budget rejected");
        assert_eq!(rate_error, AggregateAdmissionError::RateExhausted);
        assert_eq!(rate_error.code(), "rate_exhausted");
        assert_eq!(
            budget
                .try_acquire(start + Duration::from_millis(999))
                .expect_err("partial interval does not refill"),
            AggregateAdmissionError::RateExhausted
        );
        assert_eq!(
            budget
                .try_acquire(origin + Duration::from_secs(9))
                .expect_err("clock rewind does not refill"),
            AggregateAdmissionError::RateExhausted
        );

        let refilled = budget
            .try_acquire(start + Duration::from_secs(1))
            .expect("interval refills tokens");
        drop(refilled);

        let metrics = budget.metrics();
        assert_eq!(metrics.admitted_total, 3);
        assert_eq!(metrics.rate_exhausted_total, 3);
        assert_eq!(metrics.in_flight_exhausted_total, 0);
        assert_eq!(metrics.released_total, 3);
        assert_eq!(metrics.in_flight, 0);
        assert_eq!(metrics.peak_in_flight, 2);
    }

    #[test]
    fn in_flight_rejection_does_not_consume_rate_token() {
        let config = aggregate_config(1, Duration::from_secs(60), 2, 1);
        let budget = AggregateAdmissionBudget::new(config);
        let now = Instant::now();

        let first = budget.try_acquire(now).expect("first permit");
        let in_flight_error = budget
            .try_acquire(now)
            .expect_err("in-flight ceiling rejects");
        assert_eq!(in_flight_error, AggregateAdmissionError::InFlightExhausted);
        assert_eq!(in_flight_error.code(), "in_flight_exhausted");
        drop(first);

        let second = budget
            .try_acquire(now)
            .expect("in-flight rejection preserves second token");
        drop(second);
        assert_eq!(
            budget
                .try_acquire(now)
                .expect_err("both burst tokens consumed"),
            AggregateAdmissionError::RateExhausted
        );

        let metrics = budget.metrics();
        assert_eq!(metrics.admitted_total, 2);
        assert_eq!(metrics.in_flight_exhausted_total, 1);
        assert_eq!(metrics.rate_exhausted_total, 1);
        assert_eq!(metrics.released_total, 2);
        assert_eq!(metrics.in_flight, 0);
        assert_eq!(metrics.peak_in_flight, 1);
    }

    #[test]
    fn source_churn_cannot_replenish_aggregate_rate() {
        let source_policy = SourceTokenBucketPolicy::new(
            nonzero_u32(1),
            Duration::from_secs(60),
            nonzero_u32(1),
            nonzero_usize(2),
            nonzero_usize(1),
        )
        .expect("valid source policy");
        let sources = SourceTokenBucket::new(source_policy);
        let aggregate =
            AggregateAdmissionBudget::new(aggregate_config(1, Duration::from_secs(60), 3, 10));
        let now = Instant::now();

        for source in ["source-a", "source-b", "source-c"] {
            assert_eq!(sources.admit(source, now), SourceAdmissionDecision::Allowed);
            let permit = aggregate
                .try_acquire(now)
                .expect("aggregate burst admits first three sources");
            drop(permit);
        }

        assert_eq!(
            sources.admit("source-d", now),
            SourceAdmissionDecision::Allowed
        );
        assert_eq!(sources.entry_count(), 2);
        assert_eq!(
            aggregate
                .try_acquire(now)
                .expect_err("source churn does not replenish aggregate rate"),
            AggregateAdmissionError::RateExhausted
        );
    }

    #[test]
    fn concurrent_acquisition_never_exceeds_in_flight_ceiling() {
        const THREADS: usize = 32;
        const MAX_IN_FLIGHT: usize = 4;

        let budget = AggregateAdmissionBudget::new(aggregate_config(
            64,
            Duration::from_secs(60),
            64,
            MAX_IN_FLIGHT as u32,
        ));
        let barrier = std::sync::Arc::new(Barrier::new(THREADS));
        let (tx, rx) = mpsc::channel();
        let now = Instant::now();
        let mut workers = Vec::with_capacity(THREADS);

        for _ in 0..THREADS {
            let worker_budget = budget.clone();
            let worker_barrier = std::sync::Arc::clone(&barrier);
            let worker_tx = tx.clone();
            workers.push(std::thread::spawn(move || {
                worker_barrier.wait();
                worker_tx
                    .send(worker_budget.try_acquire(now))
                    .expect("collector remains alive");
            }));
        }
        drop(tx);

        let mut permits = Vec::with_capacity(MAX_IN_FLIGHT);
        let mut in_flight_rejections = 0;
        for result in rx {
            match result {
                Ok(permit) => permits.push(permit),
                Err(AggregateAdmissionError::InFlightExhausted) => {
                    in_flight_rejections += 1;
                }
                Err(error) => panic!("unexpected aggregate admission error: {error}"),
            }
        }
        for worker in workers {
            worker.join().expect("worker completes");
        }

        assert_eq!(permits.len(), MAX_IN_FLIGHT);
        assert_eq!(in_flight_rejections, THREADS - MAX_IN_FLIGHT);
        let held_metrics = budget.metrics();
        assert_eq!(held_metrics.in_flight, MAX_IN_FLIGHT as u32);
        assert_eq!(held_metrics.peak_in_flight, MAX_IN_FLIGHT as u32);

        drop(permits);
        let released_metrics = budget.metrics();
        assert_eq!(released_metrics.in_flight, 0);
        assert_eq!(released_metrics.released_total, MAX_IN_FLIGHT as u64);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn task_cancellation_releases_aggregate_permit() {
        let budget =
            AggregateAdmissionBudget::new(aggregate_config(1, Duration::from_secs(60), 2, 1));
        let worker_budget = budget.clone();
        let now = Instant::now();
        let (acquired_tx, acquired_rx) = tokio::sync::oneshot::channel();

        let task = tokio::spawn(async move {
            let permit = worker_budget
                .try_acquire(now)
                .expect("worker acquires permit");
            let _ = acquired_tx.send(());
            std::future::pending::<()>().await;
            drop(permit);
        });

        acquired_rx.await.expect("worker reports acquisition");
        assert_eq!(budget.metrics().in_flight, 1);
        task.abort();
        let join_error = task.await.expect_err("task is cancelled");
        assert!(join_error.is_cancelled());

        let cancelled_metrics = budget.metrics();
        assert_eq!(cancelled_metrics.in_flight, 0);
        assert_eq!(cancelled_metrics.released_total, 1);

        let next = budget
            .try_acquire(now)
            .expect("cancelled task returned its in-flight slot");
        drop(next);
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
