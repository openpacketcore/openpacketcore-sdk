//! NRF testkit integration tests.
//!
//! Covers:
//! - Discovery cache TTL, negative caching, stale-if-error
//! - Heartbeat failure degradation signal (per-NF)
//! - Token fixture validation
//! - Cache invalidation on config version change
//! - Service-name discovery filtering
//! - Cache key collision safety

use opc_sbi::nrf::{
    CacheKey, CacheLookup, DiscoveryCache, DiscoveryQuery, DiscoveryResult, NfProfile, NfStatus,
};
use opc_sbi::testkit::{MockNrf, TokenFixture};
use opc_types::{ConfigVersion, NfInstanceId, NfType, PlmnId, Snssai};
use std::time::{Duration, Instant};

fn make_profile(id: &str, nf_type: &str, priority: u16, capacity: u16) -> NfProfile {
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

fn make_key(tag: &str) -> CacheKey {
    CacheKey {
        target_nf_type: NfType::new(tag).unwrap(),
        requester_nf_instance_id: None,
        plmn: None,
        s_nssai: None,
        service_names: vec![],
    }
}

#[test]
fn nrf_integration_discovery_cache_ttl_and_stale_if_error() {
    let mut cache = DiscoveryCache::new(
        Duration::from_secs(10),
        Duration::from_secs(2),
        Duration::from_secs(20),
        ConfigVersion::INITIAL,
    );
    let profile = make_profile("amf-01", "amf", 10, 100);
    let key = make_key("amf");
    cache.insert(key.clone(), vec![profile.clone()]);

    let now = Instant::now();

    // Fresh hit.
    assert!(
        matches!(cache.lookup_at(&key, now), CacheLookup::Hit(_)),
        "expected fresh hit"
    );

    // After TTL: stale but usable.
    let stale = now + Duration::from_secs(15);
    let lookup = cache.lookup_at(&key, stale);
    assert!(
        matches!(lookup, CacheLookup::Stale(ref p) if p[0].nf_instance_id.as_str() == "amf-01"),
        "expected stale fallback, got {:?}",
        lookup
    );

    // After TTL + stale-if-error: miss.
    let expired = now + Duration::from_secs(31);
    assert_eq!(
        cache.lookup_at(&key, expired),
        CacheLookup::Miss,
        "expected miss after stale window expires"
    );
}

#[test]
fn nrf_integration_negative_caching_avoids_rediscovery() {
    let mut cache = DiscoveryCache::new(
        Duration::from_secs(60),
        Duration::from_secs(5),
        Duration::from_secs(30),
        ConfigVersion::INITIAL,
    );
    let key = make_key("smf");
    cache.insert_negative(key.clone());

    let now = Instant::now();
    assert_eq!(cache.lookup_at(&key, now), CacheLookup::Negative);

    // Just before negative TTL expiry: still negative.
    let just_before = now + Duration::from_secs(4);
    assert_eq!(cache.lookup_at(&key, just_before), CacheLookup::Negative);

    // After negative TTL: miss, caller should retry NRF.
    let after = now + Duration::from_secs(6);
    assert_eq!(cache.lookup_at(&key, after), CacheLookup::Miss);
}

#[test]
fn nrf_integration_heartbeat_failure_degradation_signal() {
    let nrf = MockNrf::with_max_heartbeat_failures(3);
    let id = NfInstanceId::new("pcf-01").unwrap();

    // Before any failures: not degraded.
    assert!(!nrf.is_degraded(&id));

    // Simulate repeated heartbeat failures (NF not registered).
    assert_eq!(
        nrf.heartbeat(&id),
        Err(opc_sbi::testkit::MockNrfError::NotFound)
    );
    assert_eq!(
        nrf.heartbeat(&id),
        Err(opc_sbi::testkit::MockNrfError::NotFound)
    );
    assert!(!nrf.is_degraded(&id), "2 failures should not yet degrade");

    assert_eq!(
        nrf.heartbeat(&id),
        Err(opc_sbi::testkit::MockNrfError::NotFound)
    );
    assert!(
        nrf.is_degraded(&id),
        "3 failures should trigger degradation signal"
    );

    // Register the NF and send a successful heartbeat.
    let profile = make_profile("pcf-01", "pcf", 10, 100);
    nrf.register(profile).unwrap();
    assert!(nrf.heartbeat(&id).is_ok());
    assert!(
        !nrf.is_degraded(&id),
        "successful heartbeat should clear degradation"
    );
}

#[test]
fn nrf_integration_heartbeat_degradation_is_isolated_per_nf() {
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
    let profile_b = make_profile("smf-01", "smf", 10, 100);
    nrf.register(profile_b).unwrap();
    nrf.heartbeat(&id_b).unwrap();
    assert!(
        nrf.is_degraded(&id_a),
        "amf-01 should remain degraded after smf-01 heartbeat"
    );
    assert!(!nrf.is_degraded(&id_b));
}

#[test]
fn nrf_integration_token_fixture_structurally_valid() {
    // All fixtures must be accepted by BearerToken::new.
    let valid = TokenFixture::valid();
    let expired = TokenFixture::expired();
    let wrong_scope = TokenFixture::wrong_scope();

    assert!(!valid.expose().is_empty());
    assert!(!expired.expose().is_empty());
    assert!(!wrong_scope.expose().is_empty());

    // BearerToken rejects whitespace and control characters;
    // these fixtures contain only visible ASCII and valid b64token chars.
    for token in [&valid, &expired, &wrong_scope] {
        let s = token.expose();
        assert!(
            s.bytes()
                .all(|b| b.is_ascii_graphic() || b == b'.' || b == b'-'),
            "token fixture contains invalid chars: {}",
            s
        );
    }
}

#[test]
fn nrf_integration_cache_invalidation_on_config_version_change() {
    let mut cache = DiscoveryCache::new(
        Duration::from_secs(300),
        Duration::from_secs(60),
        Duration::from_secs(120),
        ConfigVersion::new(7),
    );
    let profile = make_profile("udm-01", "udm", 10, 100);
    let key = make_key("udm");
    cache.insert(key.clone(), vec![profile.clone()]);

    // Fresh lookup under version 7.
    assert!(matches!(cache.lookup(&key), CacheLookup::Hit(_)));

    // Simulate a config change that bumps the version.
    cache.invalidate(ConfigVersion::new(8));

    // Old entries are now misses.
    assert_eq!(
        cache.lookup(&key),
        CacheLookup::Miss,
        "cache should invalidate on config version change"
    );
    assert_eq!(cache.len(), 0, "old entries should be physically removed");

    // New entries use the updated version.
    let profile2 = make_profile("udm-02", "udm", 5, 80);
    cache.insert(key.clone(), vec![profile2.clone()]);
    assert_eq!(cache.lookup(&key), CacheLookup::Hit(vec![profile2]));
}

#[test]
fn nrf_integration_stale_if_error_with_mock_nrf_down() {
    let nrf = MockNrf::new();
    let mut cache = DiscoveryCache::new(
        Duration::from_secs(10),
        Duration::from_secs(2),
        Duration::from_secs(30),
        ConfigVersion::INITIAL,
    );

    // Seed the cache from a healthy NRF.
    let profile = make_profile("ausf-01", "ausf", 10, 100);
    nrf.register(profile.clone()).unwrap();
    let query = DiscoveryQuery {
        target_nf_type: NfType::new("ausf").unwrap(),
        requester_nf_instance_id: None,
        plmn: Some(PlmnId::new("001", "01").unwrap()),
        s_nssai: None,
        service_names: vec![],
    };
    let result = nrf.discover(&query);
    if let DiscoveryResult::Found(ref profiles) = result {
        cache.insert(query.to_cache_key(), profiles.clone());
    }

    // NRF goes down.
    nrf.set_unavailable(true);

    // After TTL expires, cache still serves stale data.
    let now = Instant::now();
    let after_ttl = now + Duration::from_secs(15);
    let lookup = cache.lookup_at(&query.to_cache_key(), after_ttl);
    assert!(
        matches!(lookup, CacheLookup::Stale(_)),
        "expected stale fallback when NRF is down, got {:?}",
        lookup
    );

    // Caller can use the stale profile to keep routing.
    if let CacheLookup::Stale(profiles) = lookup {
        assert_eq!(profiles[0].nf_instance_id.as_str(), "ausf-01");
    }
}

#[test]
fn nrf_integration_mock_register_discover_round_trip() {
    let nrf = MockNrf::new();

    let amf1 = make_profile("amf-01", "amf", 5, 100);
    let amf2 = make_profile("amf-02", "amf", 3, 200);
    let smf1 = make_profile("smf-01", "smf", 10, 50);

    nrf.register(amf1).unwrap();
    nrf.register(amf2).unwrap();
    nrf.register(smf1).unwrap();

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
            // Sorted by priority ascending.
            assert_eq!(profiles[0].nf_instance_id.as_str(), "amf-02");
            assert_eq!(profiles[1].nf_instance_id.as_str(), "amf-01");
        }
        other => panic!("expected Found, got {:?}", other),
    }
}

#[test]
fn nrf_integration_discovery_filters_by_service_name() {
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
fn nrf_integration_cache_key_collisions_are_impossible() {
    // Regression test: distinct query shapes must never collide.
    let q1 = DiscoveryQuery {
        target_nf_type: NfType::new("amf").unwrap(),
        requester_nf_instance_id: Some(NfInstanceId::new("req1").unwrap()),
        plmn: None,
        s_nssai: None,
        service_names: vec!["svc1".into()],
    };
    let q2 = DiscoveryQuery {
        target_nf_type: NfType::new("amf").unwrap(),
        requester_nf_instance_id: None,
        plmn: None,
        s_nssai: None,
        service_names: vec!["req1".into(), "svc1".into()],
    };

    let k1 = q1.to_cache_key();
    let k2 = q2.to_cache_key();
    assert_ne!(
        k1, k2,
        "cache keys for different query shapes must not collide"
    );

    // Prove the cache can hold both entries independently.
    let mut cache = DiscoveryCache::new(
        Duration::from_secs(60),
        Duration::from_secs(10),
        Duration::from_secs(30),
        ConfigVersion::INITIAL,
    );
    let p1 = make_profile("amf-01", "amf", 10, 100);
    let p2 = make_profile("amf-02", "amf", 20, 200);
    cache.insert(k1.clone(), vec![p1.clone()]);
    cache.insert(k2.clone(), vec![p2.clone()]);

    assert_eq!(cache.lookup(&k1), CacheLookup::Hit(vec![p1]));
    assert_eq!(cache.lookup(&k2), CacheLookup::Hit(vec![p2]));
}

#[test]
fn nrf_integration_cache_max_entries_evicts_oldest() {
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
        target_nf_type: NfType::new("smf").unwrap(),
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

    cache.insert(key_a.clone(), vec![make_profile("amf-01", "amf", 10, 100)]);
    cache.insert(key_b.clone(), vec![make_profile("smf-01", "smf", 10, 100)]);
    assert_eq!(cache.len(), 2);

    // Inserting a third entry should evict the oldest (a).
    cache.insert(key_c.clone(), vec![make_profile("pcf-01", "pcf", 10, 100)]);
    assert_eq!(cache.len(), 2);
    assert_eq!(cache.lookup(&key_a), CacheLookup::Miss);
    assert!(matches!(cache.lookup(&key_b), CacheLookup::Hit(_)));
    assert!(matches!(cache.lookup(&key_c), CacheLookup::Hit(_)));
}
