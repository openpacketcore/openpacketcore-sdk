//! Mock NRF for deterministic SBI testing.
//!
//! Provides:
//! - `MockNrf`: in-memory NRF that handles registration, heartbeat, discovery,
//!   and access-token issuance.
//! - `TokenFixture`: pre-canned bearer tokens for auth tests.
//!
//! The mock is `Send` and can be shared across tasks via `Arc`.

use crate::headers::BearerToken;
use crate::nrf::{CacheKey, DiscoveryQuery, DiscoveryResult, NfProfile, NfStatus};
use opc_types::NfInstanceId;
use std::collections::{HashMap, HashSet};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};
use std::time::Duration;
use thiserror::Error;

/// Errors returned by the mock NRF.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MockNrfError {
    /// `register` was called for an NF instance ID that is already
    /// registered; the mock requires `update` for profile changes instead
    /// of silently overwriting.
    #[error("NF instance already registered")]
    AlreadyRegistered,
    /// The targeted NF instance ID is not registered (update, deregister,
    /// or heartbeat against an unknown/removed NF).
    #[error("NF instance not found")]
    NotFound,
    /// Reserved for heartbeat rejection after repeated failures; current
    /// mock paths report unknown NFs as `NotFound` while tracking the
    /// degradation flag separately.
    #[error("heartbeat rejected: repeated failures")]
    HeartbeatRejected,
    /// Fault injection via `set_unavailable(true)` is active: every mock
    /// operation fails with this error until cleared, simulating a down
    /// NRF (RFC 007 §18.3).
    #[error("NRF is unavailable")]
    Unavailable,
}

/// Per-NF heartbeat tracking state.
#[derive(Debug, Clone, Default)]
struct HeartbeatState {
    failures: u32,
    degraded: bool,
}

/// In-memory mock NRF for SBI tests.
///
/// # Example
///
/// ```rust
/// use opc_sbi::testkit::MockNrf;
/// use opc_sbi::nrf::{NfProfile, NfStatus};
/// use opc_types::{NfInstanceId, NfType};
///
/// let nrf = MockNrf::new();
/// let profile = NfProfile {
///     nf_instance_id: NfInstanceId::new("amf-01").unwrap(),
///     nf_type: NfType::new("amf").unwrap(),
///     nf_status: NfStatus::Registered,
///     ipv4_addresses: vec!["10.0.0.1".into()],
///     fqdn: None,
///     plmn_list: vec![],
///     s_nssais: vec![],
///     nf_services: vec![],
///     priority: 10,
///     capacity: 100,
/// };
/// nrf.register(profile).unwrap();
/// ```
#[derive(Debug)]
pub struct MockNrf {
    state: Mutex<MockNrfState>,
    token_counter: AtomicU64,
    max_heartbeat_failures: u32,
}

#[derive(Debug, Clone)]
struct MockNrfState {
    registered: HashMap<String, NfProfile>,
    heartbeat_state: HashMap<String, HeartbeatState>,
    unavailable: bool,
    discovery_overrides: HashMap<CacheKey, DiscoveryResult>,
}

impl MockNrf {
    /// Create a new mock NRF.
    ///
    /// `max_heartbeat_failures` defaults to 3.
    pub fn new() -> Self {
        Self::with_max_heartbeat_failures(3)
    }

    /// Create a mock NRF with a custom heartbeat failure threshold.
    pub fn with_max_heartbeat_failures(max: u32) -> Self {
        Self {
            state: Mutex::new(MockNrfState {
                registered: HashMap::new(),
                heartbeat_state: HashMap::new(),
                unavailable: false,
                discovery_overrides: HashMap::new(),
            }),
            token_counter: AtomicU64::new(0),
            max_heartbeat_failures: max,
        }
    }

    // ------------------------------------------------------------------
    // Registration
    // ------------------------------------------------------------------

    /// Register an NF profile with the mock NRF.
    pub fn register(&self, profile: NfProfile) -> Result<(), MockNrfError> {
        let mut state = self.state.lock().unwrap();
        if state.unavailable {
            return Err(MockNrfError::Unavailable);
        }
        let key = profile.nf_instance_id.as_str().to_owned();
        if state.registered.contains_key(&key) {
            return Err(MockNrfError::AlreadyRegistered);
        }
        state.registered.insert(key.clone(), profile);
        // Initialize heartbeat state for this NF.
        state.heartbeat_state.entry(key).or_default();
        Ok(())
    }

    /// Update an existing NF profile.
    pub fn update(&self, profile: NfProfile) -> Result<(), MockNrfError> {
        let mut state = self.state.lock().unwrap();
        if state.unavailable {
            return Err(MockNrfError::Unavailable);
        }
        let key = profile.nf_instance_id.as_str().to_owned();
        if !state.registered.contains_key(&key) {
            return Err(MockNrfError::NotFound);
        }
        state.registered.insert(key.clone(), profile);
        Ok(())
    }

    /// Deregister an NF instance.
    pub fn deregister(&self, nf_instance_id: &NfInstanceId) -> Result<(), MockNrfError> {
        let mut state = self.state.lock().unwrap();
        if state.unavailable {
            return Err(MockNrfError::Unavailable);
        }
        let key = nf_instance_id.as_str();
        if state.registered.remove(key).is_none() {
            return Err(MockNrfError::NotFound);
        }
        state.heartbeat_state.remove(key);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Heartbeat
    // ------------------------------------------------------------------

    /// Receive a heartbeat from an NF instance.
    ///
    /// After `max_heartbeat_failures` consecutive rejected heartbeats the
    /// mock marks **that specific NF** as degraded. This models TS 29.510
    /// behaviour where repeated heartbeat loss causes the NRF to consider
    /// the individual NF unhealthy.
    pub fn heartbeat(&self, nf_instance_id: &NfInstanceId) -> Result<(), MockNrfError> {
        let mut state = self.state.lock().unwrap();
        if state.unavailable {
            return Err(MockNrfError::Unavailable);
        }
        let key = nf_instance_id.as_str();
        let is_registered = state.registered.contains_key(key);
        let hb = state.heartbeat_state.entry(key.to_owned()).or_default();
        if !is_registered {
            hb.failures += 1;
            if hb.failures >= self.max_heartbeat_failures {
                hb.degraded = true;
            }
            return Err(MockNrfError::NotFound);
        }
        // Successful heartbeat resets failure counter and degradation for THIS NF.
        hb.failures = 0;
        hb.degraded = false;
        Ok(())
    }

    /// Query whether a specific NF instance is degraded.
    pub fn is_degraded(&self, nf_instance_id: &NfInstanceId) -> bool {
        let state = self.state.lock().unwrap();
        state
            .heartbeat_state
            .get(nf_instance_id.as_str())
            .map(|hb| hb.degraded)
            .unwrap_or(false)
    }

    /// Query whether **any** NF instance is currently degraded.
    pub fn any_degraded(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.heartbeat_state.values().any(|hb| hb.degraded)
    }

    /// Inject a heartbeat failure for a specific NF without changing registered state.
    pub fn inject_heartbeat_failure(&self, nf_instance_id: &NfInstanceId) {
        let mut state = self.state.lock().unwrap();
        let key = nf_instance_id.as_str().to_owned();
        let hb = state.heartbeat_state.entry(key).or_default();
        hb.failures += 1;
        if hb.failures >= self.max_heartbeat_failures {
            hb.degraded = true;
        }
    }

    /// Reset the heartbeat failure counter and degraded flag for a specific NF.
    pub fn reset_heartbeat_state(&self, nf_instance_id: &NfInstanceId) {
        let mut state = self.state.lock().unwrap();
        if let Some(hb) = state.heartbeat_state.get_mut(nf_instance_id.as_str()) {
            hb.failures = 0;
            hb.degraded = false;
        }
    }

    // ------------------------------------------------------------------
    // Discovery
    // ------------------------------------------------------------------

    /// Discover NF instances matching the query.
    ///
    /// If a discovery override has been pre-configured via
    /// `set_discovery_response`, that result is returned verbatim.
    /// Otherwise the mock filters its registered profiles by
    /// `target_nf_type`, `plmn`, `s_nssai`, and advertised `nf_services`.
    pub fn discover(&self, query: &DiscoveryQuery) -> DiscoveryResult {
        let state = self.state.lock().unwrap();
        if state.unavailable {
            return DiscoveryResult::Error("nrf unavailable".into());
        }

        let cache_key = query.to_cache_key();
        if let Some(override_result) = state.discovery_overrides.get(&cache_key) {
            return override_result.clone();
        }

        let requested_services: HashSet<&str> =
            query.service_names.iter().map(|s| s.as_str()).collect();

        let mut matches: Vec<NfProfile> = state
            .registered
            .values()
            .filter(|p| p.nf_type == query.target_nf_type)
            .filter(|p| matches!(p.nf_status, NfStatus::Registered))
            .filter(|p| {
                query
                    .plmn
                    .as_ref()
                    .is_none_or(|plmn| p.plmn_list.contains(plmn))
            })
            .filter(|p| {
                query
                    .s_nssai
                    .as_ref()
                    .is_none_or(|snssai| p.s_nssais.contains(snssai))
            })
            .filter(|p| {
                // If the query requests specific services, the NF must advertise at least one.
                if requested_services.is_empty() {
                    return true;
                }
                p.nf_services
                    .iter()
                    .any(|svc| requested_services.contains(svc.as_str()))
            })
            .cloned()
            .collect();

        if matches.is_empty() {
            return DiscoveryResult::NotFound;
        }

        // Sort by priority ascending, then capacity descending.
        matches.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then_with(|| b.capacity.cmp(&a.capacity))
        });

        DiscoveryResult::Found(matches)
    }

    /// Pre-configure a discovery response for a specific query key.
    pub fn set_discovery_response(&self, query_key: CacheKey, result: DiscoveryResult) {
        let mut state = self.state.lock().unwrap();
        state.discovery_overrides.insert(query_key, result);
    }

    /// Clear all discovery overrides.
    pub fn clear_discovery_overrides(&self) {
        let mut state = self.state.lock().unwrap();
        state.discovery_overrides.clear();
    }

    // ------------------------------------------------------------------
    // Access Token
    // ------------------------------------------------------------------

    /// Issue a fresh bearer token.
    pub fn issue_token(&self) -> BearerToken {
        let counter = self.token_counter.fetch_add(1, Ordering::SeqCst);
        // Use a deterministic base64url-safe string.
        let token_str = format!("mock-token-{counter}");
        BearerToken::new(token_str).expect("mock token is always valid")
    }

    // ------------------------------------------------------------------
    // Fault injection
    // ------------------------------------------------------------------

    /// Make the mock NRF return `Unavailable` on every operation.
    pub fn set_unavailable(&self, unavailable: bool) {
        let mut state = self.state.lock().unwrap();
        state.unavailable = unavailable;
    }

    /// Check whether the mock is currently simulating unavailability.
    pub fn is_unavailable(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.unavailable
    }
}

#[async_trait::async_trait]
impl crate::nrf::NrfDeregNotifier for MockNrf {
    async fn deregister(
        &self,
        nf_instance_id: &opc_types::NfInstanceId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.deregister(nf_instance_id)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }
}

#[async_trait::async_trait]
impl crate::nrf::NrfOperations for MockNrf {
    async fn register(&self, profile: &NfProfile) -> Result<Duration, String> {
        self.register(profile.clone())
            .map(|_| Duration::from_secs(5))
            .map_err(|e| e.to_string())
    }

    async fn deregister(&self, instance_id: &opc_types::NfInstanceId) -> Result<(), String> {
        self.deregister(instance_id).map_err(|e| e.to_string())
    }

    async fn heartbeat(&self, instance_id: &opc_types::NfInstanceId) -> Result<Duration, String> {
        self.heartbeat(instance_id)
            .map(|_| Duration::from_secs(5))
            .map_err(|e| e.to_string())
    }

    async fn discover(&self, query: &DiscoveryQuery) -> Result<DiscoveryResult, String> {
        Ok(self.discover(query))
    }
}

impl Default for MockNrf {
    fn default() -> Self {
        Self::new()
    }
}

/// Pre-canned bearer-token fixtures for auth tests.
///
/// All tokens are structurally valid (`BearerToken::new` accepts them).
/// Semantic validity (expiry, signature) is determined by the test.
pub struct TokenFixture;

impl TokenFixture {
    /// A token that appears structurally valid.
    pub fn valid() -> BearerToken {
        BearerToken::new("eyJhbGciOiJIUzI1NiJ9.valid").unwrap()
    }

    /// A token that is structurally valid but semantically expired.
    pub fn expired() -> BearerToken {
        BearerToken::new("eyJhbGciOiJIUzI1NiJ9.expired").unwrap()
    }

    /// A token with a different claim set (useful for scope-mismatch tests).
    pub fn wrong_scope() -> BearerToken {
        BearerToken::new("eyJhbGciOiJIUzI1NiJ9.wrong-scope").unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nrf::{DiscoveryQuery, NfStatus};
    use opc_types::{NfInstanceId, NfType, PlmnId, Snssai};

    fn sample_profile(id: &str, nf_type: &str, priority: u16, capacity: u16) -> NfProfile {
        NfProfile {
            nf_instance_id: NfInstanceId::new(id).unwrap(),
            nf_type: NfType::new(nf_type).unwrap(),
            nf_status: NfStatus::Registered,
            ipv4_addresses: vec!["10.0.0.1".into()],
            fqdn: None,
            plmn_list: vec![PlmnId::new("001", "01").unwrap()],
            s_nssais: vec![Snssai::new(1, Some("010203")).unwrap()],
            nf_services: vec![],
            priority,
            capacity,
        }
    }

    fn profile_with_services(id: &str, nf_type: &str, services: &[&str]) -> NfProfile {
        NfProfile {
            nf_instance_id: NfInstanceId::new(id).unwrap(),
            nf_type: NfType::new(nf_type).unwrap(),
            nf_status: NfStatus::Registered,
            ipv4_addresses: vec!["10.0.0.1".into()],
            fqdn: None,
            plmn_list: vec![PlmnId::new("001", "01").unwrap()],
            s_nssais: vec![Snssai::new(1, Some("010203")).unwrap()],
            nf_services: services.iter().map(|s| s.to_string()).collect(),
            priority: 10,
            capacity: 100,
        }
    }

    #[test]
    fn nrf_mock_registration_and_deregistration() {
        let nrf = MockNrf::new();
        let profile = sample_profile("amf-01", "amf", 10, 100);

        nrf.register(profile.clone()).unwrap();
        assert!(nrf.heartbeat(&profile.nf_instance_id).is_ok());

        nrf.deregister(&profile.nf_instance_id).unwrap();
        assert_eq!(
            nrf.heartbeat(&profile.nf_instance_id),
            Err(MockNrfError::NotFound)
        );
    }

    #[test]
    fn nrf_mock_heartbeat_failure_degradation_signal() {
        let nrf = MockNrf::with_max_heartbeat_failures(3);
        let id = NfInstanceId::new("smf-01").unwrap();

        assert!(!nrf.is_degraded(&id));

        // Three consecutive failures for an unknown NF.
        nrf.inject_heartbeat_failure(&id);
        assert!(!nrf.is_degraded(&id));
        nrf.inject_heartbeat_failure(&id);
        assert!(!nrf.is_degraded(&id));
        nrf.inject_heartbeat_failure(&id);
        assert!(nrf.is_degraded(&id), "should be degraded after 3 failures");

        // Register and heartbeat successfully resets degradation for THIS NF.
        let profile = sample_profile("smf-01", "smf", 10, 100);
        nrf.register(profile).unwrap();
        nrf.heartbeat(&id).unwrap();
        assert!(
            !nrf.is_degraded(&id),
            "successful heartbeat should clear degradation"
        );
    }

    #[test]
    fn nrf_mock_heartbeat_degradation_is_per_nf() {
        let nrf = MockNrf::with_max_heartbeat_failures(3);
        let id_a = NfInstanceId::new("amf-01").unwrap();
        let id_b = NfInstanceId::new("smf-01").unwrap();

        // Degrade amf-01 through repeated failures.
        nrf.inject_heartbeat_failure(&id_a);
        nrf.inject_heartbeat_failure(&id_a);
        nrf.inject_heartbeat_failure(&id_a);
        assert!(nrf.is_degraded(&id_a));
        assert!(
            !nrf.is_degraded(&id_b),
            "smf-01 should not be degraded by amf-01 failures"
        );

        // Successful heartbeat from smf-01 must not heal amf-01.
        let profile_b = sample_profile("smf-01", "smf", 10, 100);
        nrf.register(profile_b).unwrap();
        nrf.heartbeat(&id_b).unwrap();
        assert!(
            nrf.is_degraded(&id_a),
            "amf-01 should remain degraded after smf-01 heartbeat"
        );
        assert!(!nrf.is_degraded(&id_b));
    }

    #[test]
    fn nrf_mock_discovery_filters_by_type_and_plmn() {
        let nrf = MockNrf::new();
        nrf.register(sample_profile("amf-01", "amf", 5, 100))
            .unwrap();
        nrf.register(sample_profile("smf-01", "smf", 5, 100))
            .unwrap();
        nrf.register(sample_profile("amf-02", "amf", 3, 80))
            .unwrap();

        let query = DiscoveryQuery {
            target_nf_type: NfType::new("amf").unwrap(),
            requester_nf_instance_id: None,
            plmn: Some(PlmnId::new("001", "01").unwrap()),
            s_nssai: None,
            service_names: vec![],
        };

        let result = nrf.discover(&query);
        match result {
            DiscoveryResult::Found(profiles) => {
                assert_eq!(profiles.len(), 2);
                // Lower priority first, then higher capacity.
                assert_eq!(profiles[0].nf_instance_id.as_str(), "amf-02");
                assert_eq!(profiles[1].nf_instance_id.as_str(), "amf-01");
            }
            other => panic!("expected Found, got {:?}", other),
        }
    }

    #[test]
    fn nrf_mock_discovery_filters_by_service_name() {
        let nrf = MockNrf::new();
        nrf.register(profile_with_services(
            "amf-01",
            "amf",
            &["namf-comm", "namf-mt"],
        ))
        .unwrap();
        nrf.register(profile_with_services(
            "amf-02",
            "amf",
            &["namf-comm", "namf-location"],
        ))
        .unwrap();
        nrf.register(profile_with_services("smf-01", "smf", &["nsmf-pdusession"]))
            .unwrap();

        // Query for NAMF-COMM should return both AMFs.
        let query_comm = DiscoveryQuery {
            target_nf_type: NfType::new("amf").unwrap(),
            requester_nf_instance_id: None,
            plmn: Some(PlmnId::new("001", "01").unwrap()),
            s_nssai: None,
            service_names: vec!["namf-comm".into()],
        };
        match nrf.discover(&query_comm) {
            DiscoveryResult::Found(profiles) => {
                assert_eq!(profiles.len(), 2);
            }
            other => panic!("expected Found 2 AMFs, got {:?}", other),
        }

        // Query for NAMF-MT should return only amf-01.
        let query_mt = DiscoveryQuery {
            target_nf_type: NfType::new("amf").unwrap(),
            requester_nf_instance_id: None,
            plmn: Some(PlmnId::new("001", "01").unwrap()),
            s_nssai: None,
            service_names: vec!["namf-mt".into()],
        };
        match nrf.discover(&query_mt) {
            DiscoveryResult::Found(profiles) => {
                assert_eq!(profiles.len(), 1);
                assert_eq!(profiles[0].nf_instance_id.as_str(), "amf-01");
            }
            other => panic!("expected Found 1 AMF, got {:?}", other),
        }

        // Query for NSMF-PDUSESSION with target NF type SMF should return smf-01.
        let query_smf = DiscoveryQuery {
            target_nf_type: NfType::new("smf").unwrap(),
            requester_nf_instance_id: None,
            plmn: Some(PlmnId::new("001", "01").unwrap()),
            s_nssai: None,
            service_names: vec!["nsmf-pdusession".into()],
        };
        match nrf.discover(&query_smf) {
            DiscoveryResult::Found(profiles) => {
                assert_eq!(profiles.len(), 1);
                assert_eq!(profiles[0].nf_instance_id.as_str(), "smf-01");
            }
            other => panic!("expected Found 1 SMF, got {:?}", other),
        }

        // Query for a non-existent service should return NotFound.
        let query_missing = DiscoveryQuery {
            target_nf_type: NfType::new("amf").unwrap(),
            requester_nf_instance_id: None,
            plmn: Some(PlmnId::new("001", "01").unwrap()),
            s_nssai: None,
            service_names: vec!["nbsf-management".into()],
        };
        assert_eq!(nrf.discover(&query_missing), DiscoveryResult::NotFound);
    }

    #[test]
    fn nrf_mock_discovery_override() {
        let nrf = MockNrf::new();
        let query = DiscoveryQuery {
            target_nf_type: NfType::new("nrf").unwrap(),
            requester_nf_instance_id: None,
            plmn: None,
            s_nssai: None,
            service_names: vec![],
        };

        nrf.set_discovery_response(
            query.to_cache_key(),
            DiscoveryResult::Error("injected".into()),
        );

        assert_eq!(
            nrf.discover(&query),
            DiscoveryResult::Error("injected".into())
        );
    }

    #[test]
    fn nrf_mock_unavailable_returns_errors() {
        let nrf = MockNrf::new();
        nrf.set_unavailable(true);

        let profile = sample_profile("amf-01", "amf", 10, 100);
        assert_eq!(nrf.register(profile), Err(MockNrfError::Unavailable));

        let query = DiscoveryQuery {
            target_nf_type: NfType::new("amf").unwrap(),
            requester_nf_instance_id: None,
            plmn: None,
            s_nssai: None,
            service_names: vec![],
        };
        assert_eq!(
            nrf.discover(&query),
            DiscoveryResult::Error("nrf unavailable".into())
        );
    }

    #[test]
    fn nrf_token_fixture_validation() {
        let valid = TokenFixture::valid();
        assert_eq!(valid.expose(), "eyJhbGciOiJIUzI1NiJ9.valid");

        let expired = TokenFixture::expired();
        assert_eq!(expired.expose(), "eyJhbGciOiJIUzI1NiJ9.expired");

        let wrong = TokenFixture::wrong_scope();
        assert_eq!(wrong.expose(), "eyJhbGciOiJIUzI1NiJ9.wrong-scope");
    }

    #[test]
    fn nrf_mock_issue_token_increments() {
        let nrf = MockNrf::new();
        let t1 = nrf.issue_token();
        let t2 = nrf.issue_token();
        assert_ne!(t1.expose(), t2.expose());
    }
}
