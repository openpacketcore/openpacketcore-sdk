//! Discovery cache with TTL, negative caching, stale-if-error, and config-version
//! invalidation.
//!
//! The cache is intentionally synchronous (no async lock). Production use will
//! typically wrap it in an `RwLock` or shard it across tasks.

use super::{CacheKey, NfProfile};
use opc_types::ConfigVersion;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Cached entry for a single discovery query.
#[derive(Debug, Clone)]
struct CacheEntry {
    value: CacheValue,
    inserted_at: Instant,
    config_version: ConfigVersion,
    /// Monotonic sequence number for FIFO eviction.
    sequence: u64,
}

#[derive(Debug, Clone)]
enum CacheValue {
    Positive(Vec<NfProfile>),
    Negative,
}

/// Lookup result from the discovery cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheLookup {
    /// Fresh entry within TTL.
    Hit(Vec<NfProfile>),
    /// Entry expired but within stale-if-error window.
    Stale(Vec<NfProfile>),
    /// Explicit negative cached result.
    Negative,
    /// No entry (or fully expired).
    Miss,
}

/// In-memory discovery cache for NRF results.
///
/// # Design
///
/// - **TTL**: positive entries are served fresh for `ttl`.
/// - **Negative TTL**: `NotFound` responses are cached for `negative_ttl` to
///   avoid hammering a struggling NRF.
/// - **Stale-if-error**: after TTL expires, a positive entry remains usable as
///   a stale fallback for `stale_if_error` additional time. Callers should
///   attempt a background refresh but may continue routing using the stale
///   data when the NRF is unavailable.
/// - **Config-version invalidation**: any `ConfigVersion` change that affects
///   peers, PLMN, slice, trust anchors, or routing mode bumps the version;
///   entries with a mismatched version are treated as misses.
/// - **Bounded capacity**: when `max_entries` is set, the oldest entries are
///   evicted on insert to keep memory bounded.
#[derive(Debug, Clone)]
pub struct DiscoveryCache {
    entries: HashMap<CacheKey, CacheEntry>,
    ttl: Duration,
    negative_ttl: Duration,
    stale_if_error: Duration,
    config_version: ConfigVersion,
    max_entries: Option<usize>,
    next_sequence: u64,
}

impl DiscoveryCache {
    /// Create a new empty cache.
    pub fn new(
        ttl: Duration,
        negative_ttl: Duration,
        stale_if_error: Duration,
        config_version: ConfigVersion,
    ) -> Self {
        Self {
            entries: HashMap::new(),
            ttl,
            negative_ttl,
            stale_if_error,
            config_version,
            max_entries: None,
            next_sequence: 0,
        }
    }

    /// Set a maximum entry count and return `self` for chaining.
    pub fn with_max_entries(mut self, max: usize) -> Self {
        self.max_entries = Some(max);
        self
    }

    /// Insert a positive discovery result at the current time.
    pub fn insert(&mut self, key: CacheKey, profiles: Vec<NfProfile>) {
        self.insert_at(key, profiles, Instant::now());
    }

    /// Insert a positive discovery result at a specific instant.
    pub fn insert_at(&mut self, key: CacheKey, profiles: Vec<NfProfile>, now: Instant) {
        let seq = self.next_sequence;
        self.next_sequence += 1;
        self.entries.insert(
            key,
            CacheEntry {
                value: CacheValue::Positive(profiles),
                inserted_at: now,
                config_version: self.config_version,
                sequence: seq,
            },
        );
        self.maybe_evict();
    }

    /// Insert a negative (not-found) discovery result at the current time.
    pub fn insert_negative(&mut self, key: CacheKey) {
        self.insert_negative_at(key, Instant::now());
    }

    /// Insert a negative (not-found) discovery result at a specific instant.
    pub fn insert_negative_at(&mut self, key: CacheKey, now: Instant) {
        let seq = self.next_sequence;
        self.next_sequence += 1;
        self.entries.insert(
            key,
            CacheEntry {
                value: CacheValue::Negative,
                inserted_at: now,
                config_version: self.config_version,
                sequence: seq,
            },
        );
        self.maybe_evict();
    }

    /// Remove an entry explicitly.
    pub fn remove(&mut self, key: &CacheKey) {
        self.entries.remove(key);
    }

    /// Look up a key at the current instant.
    pub fn lookup(&self, key: &CacheKey) -> CacheLookup {
        self.lookup_at(key, Instant::now())
    }

    /// Look up a key at a specific instant (useful for deterministic testing).
    pub fn lookup_at(&self, key: &CacheKey, now: Instant) -> CacheLookup {
        let entry = match self.entries.get(key) {
            Some(e) => e,
            None => return CacheLookup::Miss,
        };

        // Config-version mismatch => treat as miss (forces re-discovery).
        if entry.config_version != self.config_version {
            return CacheLookup::Miss;
        }

        let age = now.duration_since(entry.inserted_at);

        match &entry.value {
            CacheValue::Positive(profiles) => {
                if age < self.ttl {
                    CacheLookup::Hit(profiles.clone())
                } else if age < self.ttl.saturating_add(self.stale_if_error) {
                    CacheLookup::Stale(profiles.clone())
                } else {
                    CacheLookup::Miss
                }
            }
            CacheValue::Negative => {
                if age < self.negative_ttl {
                    CacheLookup::Negative
                } else {
                    CacheLookup::Miss
                }
            }
        }
    }

    /// Invalidate stale entries and bump the canonical config version.
    ///
    /// Entries whose `config_version` differs from the new version become
    /// misses on the next lookup; they are also physically removed to bound
    /// memory.
    pub fn invalidate(&mut self, new_config_version: ConfigVersion) {
        self.config_version = new_config_version;
        self.entries
            .retain(|_, entry| entry.config_version == self.config_version);
    }

    /// Return the current config version tracked by the cache.
    pub fn config_version(&self) -> ConfigVersion {
        self.config_version
    }

    /// Return the configured TTL.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Return the configured negative TTL.
    pub fn negative_ttl(&self) -> Duration {
        self.negative_ttl
    }

    /// Return the configured stale-if-error duration.
    pub fn stale_if_error(&self) -> Duration {
        self.stale_if_error
    }

    /// Number of entries currently stored.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn maybe_evict(&mut self) {
        let max = match self.max_entries {
            Some(m) => m,
            None => return,
        };
        while self.entries.len() > max {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.sequence)
                .map(|(k, _)| k.clone());
            if let Some(key) = oldest {
                self.entries.remove(&key);
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_types::{NfInstanceId, NfType, PlmnId, Snssai};

    fn sample_profile(id: &str, nf_type: &str) -> NfProfile {
        NfProfile {
            nf_instance_id: NfInstanceId::new(id).unwrap(),
            nf_type: NfType::new(nf_type).unwrap(),
            nf_status: super::super::NfStatus::Registered,
            ipv4_addresses: vec!["10.0.0.1".into()],
            fqdn: None,
            plmn_list: vec![PlmnId::new("001", "01").unwrap()],
            s_nssais: vec![Snssai::new(1, Some("010203")).unwrap()],
            nf_services: vec![],
            priority: 10,
            capacity: 100,
        }
    }

    fn sample_key(tag: &str) -> CacheKey {
        CacheKey {
            target_nf_type: NfType::new(tag).unwrap(),
            requester_nf_instance_id: None,
            plmn: None,
            s_nssai: None,
            service_names: vec![],
        }
    }

    #[test]
    fn nrf_cache_hit_within_ttl() {
        let mut cache = DiscoveryCache::new(
            Duration::from_secs(60),
            Duration::from_secs(10),
            Duration::from_secs(30),
            ConfigVersion::INITIAL,
        );
        let profile = sample_profile("amf-01", "amf");
        let key = sample_key("amf");
        cache.insert(key.clone(), vec![profile.clone()]);

        assert_eq!(cache.lookup(&key), CacheLookup::Hit(vec![profile]));
    }

    #[test]
    fn nrf_cache_miss_after_ttl_and_stale_window() {
        let mut cache = DiscoveryCache::new(
            Duration::from_secs(5),
            Duration::from_secs(1),
            Duration::from_secs(5),
            ConfigVersion::INITIAL,
        );
        let profile = sample_profile("smf-01", "smf");
        let key = sample_key("smf");
        cache.insert(key.clone(), vec![profile.clone()]);

        // Immediately: hit.
        let now = Instant::now();
        assert!(matches!(cache.lookup_at(&key, now), CacheLookup::Hit(_)));

        // After TTL but before stale-if-error: stale.
        let later = now + Duration::from_secs(7);
        assert!(matches!(
            cache.lookup_at(&key, later),
            CacheLookup::Stale(_)
        ));

        // After TTL + stale-if-error: miss.
        let expired = now + Duration::from_secs(11);
        assert_eq!(cache.lookup_at(&key, expired), CacheLookup::Miss);
    }

    #[test]
    fn nrf_cache_negative_caching() {
        let mut cache = DiscoveryCache::new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(30),
            ConfigVersion::INITIAL,
        );
        let key = sample_key("nrf");
        cache.insert_negative(key.clone());

        let now = Instant::now();
        assert_eq!(cache.lookup_at(&key, now), CacheLookup::Negative);

        // After negative TTL: miss.
        let later = now + Duration::from_secs(6);
        assert_eq!(cache.lookup_at(&key, later), CacheLookup::Miss);
    }

    #[test]
    fn nrf_cache_invalidation_on_config_version_change() {
        let mut cache = DiscoveryCache::new(
            Duration::from_secs(60),
            Duration::from_secs(10),
            Duration::from_secs(30),
            ConfigVersion::INITIAL,
        );
        let profile = sample_profile("pcf-01", "pcf");
        let key = sample_key("pcf");
        cache.insert(key.clone(), vec![profile.clone()]);

        // Before invalidation: hit.
        assert!(matches!(cache.lookup(&key), CacheLookup::Hit(_)));

        // Bump config version.
        cache.invalidate(ConfigVersion::new(1));

        // After invalidation: miss, and entry should be removed.
        assert_eq!(cache.lookup(&key), CacheLookup::Miss);
        assert!(cache.is_empty());
    }

    #[test]
    fn nrf_cache_stale_if_error_serves_expired_data() {
        let mut cache = DiscoveryCache::new(
            Duration::from_secs(10),
            Duration::from_secs(2),
            Duration::from_secs(20),
            ConfigVersion::INITIAL,
        );
        let profile = sample_profile("ausf-01", "ausf");
        let key = sample_key("ausf");
        cache.insert(key.clone(), vec![profile.clone()]);

        let now = Instant::now();
        let after_ttl = now + Duration::from_secs(15);

        // After TTL but well within stale-if-error: still usable.
        let lookup = cache.lookup_at(&key, after_ttl);
        assert!(
            matches!(lookup, CacheLookup::Stale(ref p) if p[0].nf_instance_id.as_str() == "ausf-01"),
            "expected Stale hit for ausf-01, got {lookup:?}"
        );
    }

    #[test]
    fn nrf_cache_new_entries_use_current_config_version() {
        let mut cache = DiscoveryCache::new(
            Duration::from_secs(60),
            Duration::from_secs(10),
            Duration::from_secs(30),
            ConfigVersion::new(3),
        );
        let profile = sample_profile("udm-01", "udm");
        let key = sample_key("udm");
        cache.insert(key.clone(), vec![profile.clone()]);

        // Bump version, then insert a new entry.
        cache.invalidate(ConfigVersion::new(4));
        let profile2 = sample_profile("udm-02", "udm");
        cache.insert(key.clone(), vec![profile2.clone()]);

        // The new entry should be a hit.
        assert_eq!(cache.lookup(&key), CacheLookup::Hit(vec![profile2]));
    }

    #[test]
    fn nrf_cache_max_entries_evicts_oldest() {
        let mut cache = DiscoveryCache::new(
            Duration::from_secs(60),
            Duration::from_secs(10),
            Duration::from_secs(30),
            ConfigVersion::INITIAL,
        )
        .with_max_entries(2);

        let key_a = CacheKey {
            target_nf_type: NfType::new("amf").unwrap(),
            requester_nf_instance_id: None,
            plmn: None,
            s_nssai: None,
            service_names: vec![],
        };
        let key_b = CacheKey {
            target_nf_type: NfType::smf(),
            requester_nf_instance_id: None,
            plmn: None,
            s_nssai: None,
            service_names: vec![],
        };
        let key_c = CacheKey {
            target_nf_type: NfType::new("pcf").unwrap(),
            requester_nf_instance_id: None,
            plmn: None,
            s_nssai: None,
            service_names: vec![],
        };

        cache.insert(key_a.clone(), vec![sample_profile("amf-01", "amf")]);
        cache.insert(key_b.clone(), vec![sample_profile("smf-01", "smf")]);
        assert_eq!(cache.len(), 2);

        // Inserting a third entry should evict the oldest (a).
        cache.insert(key_c.clone(), vec![sample_profile("pcf-01", "pcf")]);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.lookup(&key_a), CacheLookup::Miss);
        assert!(matches!(cache.lookup(&key_b), CacheLookup::Hit(_)));
        assert!(matches!(cache.lookup(&key_c), CacheLookup::Hit(_)));
    }
}
