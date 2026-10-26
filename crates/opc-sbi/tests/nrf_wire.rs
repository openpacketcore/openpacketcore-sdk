use http::StatusCode;
use opc_sbi::nrf::{
    DiscoveryQuery, DiscoveryResult, NfProfile, NfStatus, NrfClient, NrfOperations,
};
use opc_sbi::testkit::MockProducer;
use opc_types::{NfInstanceId, NfType, PlmnId, Snssai};
use serde_json::json;
use std::{collections::HashMap, time::Duration};

const ID: &str = "ee3ad0bb-d33a-4c70-b9ee-91b1c1c6f667";

fn profile() -> NfProfile {
    NfProfile {
        nf_instance_id: NfInstanceId::new(ID).unwrap(),
        nf_type: NfType::new("amf").unwrap(),
        nf_status: NfStatus::Registered,
        ipv4_addresses: vec!["192.0.2.1".into()],
        fqdn: None,
        plmn_list: vec![PlmnId::new("001", "01").unwrap().into()],
        s_nssais: vec![Snssai::new(1, Some("010203")).unwrap().into()],
        nf_services: vec![],
        priority: 10,
        capacity: 100,
    }
}

fn query() -> DiscoveryQuery {
    DiscoveryQuery {
        target_nf_type: NfType::new("amf").unwrap(),
        requester_nf_type: NfType::new("smf").unwrap(),
        requester_nf_instance_id: Some(NfInstanceId::new(ID).unwrap()),
        plmn: Some(PlmnId::new("001", "01").unwrap()),
        s_nssai: Some(Snssai::new(1, Some("010203")).unwrap()),
        service_names: vec!["namf-comm".into(), "namf-mt".into()],
    }
}

#[tokio::test]
async fn nrf_registration_sends_standard_profile_json() {
    let server = MockProducer::start().await;
    let client = NrfClient::with_default_client(server.url()).unwrap();
    client.register(&profile()).await.unwrap();
    let requests = server.get_requests();
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(requests[0].method, "PUT");
    assert_eq!(body["nfType"], "AMF");
    assert_eq!(body["nfStatus"], "REGISTERED");
    assert_eq!(body["plmnList"], json!([{"mcc":"001","mnc":"01"}]));
    assert_eq!(body["sNssais"], json!([{"sst":1,"sd":"010203"}]));
    assert!(body.get("fqdn").is_none());
    assert!(body.get("nfServices").is_none());
}

#[tokio::test]
async fn nrf_uses_standard_heart_beat_timer_spelling() {
    let server = MockProducer::start().await;
    server.set_override(
        &format!("/nnrf-nfm/v1/nf-instances/{ID}"),
        StatusCode::OK,
        HashMap::new(),
        br#"{"heartBeatTimer":17}"#.to_vec(),
    );
    let client = NrfClient::with_default_client(server.url()).unwrap();
    assert_eq!(
        client.register(&profile()).await.unwrap(),
        Duration::from_secs(17)
    );
    assert_eq!(
        client
            .heartbeat(&NfInstanceId::new(ID).unwrap())
            .await
            .unwrap(),
        Duration::from_secs(17)
    );
}

#[tokio::test]
async fn nrf_discovery_reads_literal_standard_search_results() {
    let server = MockProducer::start().await;
    server.set_override(
        "/nnrf-disc/v1/nf-instances",
        StatusCode::OK,
        HashMap::new(),
        json!({"validityPeriod":30,"nfInstances":[{
            "nfInstanceId":ID,"nfType":"AMF","nfStatus":"REGISTERED"
        }]})
        .to_string()
        .into_bytes(),
    );
    let client = NrfClient::with_default_client(server.url()).unwrap();
    assert!(
        matches!(client.discover(&query()).await.unwrap(), DiscoveryResult::Found { profiles, .. } if profiles.len() == 1)
    );
}

#[tokio::test]
async fn nrf_malformed_search_result_is_not_a_cacheable_not_found() {
    let server = MockProducer::start().await;
    server.set_override(
        "/nnrf-disc/v1/nf-instances",
        StatusCode::OK,
        HashMap::new(),
        b"{}".to_vec(),
    );
    let client = NrfClient::with_default_client(server.url()).unwrap();
    assert!(client.discover(&query()).await.is_err());
}

#[tokio::test]
async fn nrf_discovery_sends_all_filters_in_standard_wire_shapes() {
    let server = MockProducer::start().await;
    server.set_override(
        "/nnrf-disc/v1/nf-instances",
        StatusCode::OK,
        HashMap::new(),
        br#"{"validityPeriod":30,"nfInstances":[]}"#.to_vec(),
    );
    let client = NrfClient::with_default_client(server.url()).unwrap();
    client.discover(&query()).await.unwrap();
    let requests = server.get_requests();
    let query = requests[0].query.as_deref().unwrap();
    let fields = query
        .split('&')
        .map(|part| part.split_once('=').unwrap())
        .collect::<HashMap<_, _>>();
    assert_eq!(fields.len(), 6);
    assert_eq!(fields["target-nf-type"], "AMF");
    assert_eq!(fields["requester-nf-type"], "SMF");
    assert_eq!(fields["requester-nf-instance-id"], ID);
    assert_eq!(
        fields["target-plmn-list"],
        "%5B%7B%22mcc%22%3A%22001%22%2C%22mnc%22%3A%2201%22%7D%5D"
    );
    assert_eq!(
        fields["snssais"],
        "%5B%7B%22sst%22%3A1%2C%22sd%22%3A%22010203%22%7D%5D"
    );
    assert_eq!(fields["service-names"], "namf-comm,namf-mt");
}

#[tokio::test]
async fn nrf_registration_service_metadata_is_an_object_and_omits_absent_attributes() {
    let server = MockProducer::start().await;
    let client = NrfClient::with_default_client(server.url()).unwrap();
    let mut profile = profile();
    profile.nf_services.push(opc_sbi::nrf::NfService::new(
        "amf-comm-1".into(),
        "namf-comm".into(),
        vec![opc_sbi::nrf::NfServiceVersion {
            api_full_version: "1.0.0".into(),
            api_version_in_uri: "v1".into(),
            expiry: None,
        }],
        "https".into(),
        opc_sbi::nrf::NfServiceStatus::Registered,
    ));
    client.register(&profile).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&server.get_requests()[0].body).unwrap();
    assert_eq!(
        body["nfServices"],
        json!([{
            "serviceInstanceId":"amf-comm-1", "serviceName":"namf-comm",
            "versions":[{"apiFullVersion":"1.0.0","apiVersionInUri":"v1"}],
            "scheme":"https", "nfServiceStatus":"REGISTERED"
        }])
    );
}

#[tokio::test]
async fn nrf_cache_honors_server_no_store_and_zero_validity() {
    use opc_sbi::nrf::{CachedDiscoveryClient, DiscoveryCache};
    use std::sync::{Arc, Mutex};
    for (headers, validity) in [
        (
            HashMap::from([("cache-control".into(), "no-store, max-age=600".into())]),
            600,
        ),
        (
            HashMap::from([("cache-control".into(), "no-cache".into())]),
            600,
        ),
        (HashMap::new(), 0),
    ] {
        let server = MockProducer::start().await;
        server.set_override(
            "/nnrf-disc/v1/nf-instances",
            StatusCode::OK,
            headers,
            json!({"validityPeriod":validity,"nfInstances":[{
                "nfInstanceId":ID,"nfType":"AMF","nfStatus":"REGISTERED"
            }]})
            .to_string()
            .into_bytes(),
        );
        let cache = Arc::new(Mutex::new(DiscoveryCache::new(
            Duration::from_secs(600),
            Duration::from_secs(600),
            Duration::from_secs(600),
            opc_types::ConfigVersion::new(1),
        )));
        let client = CachedDiscoveryClient::new(
            Arc::new(NrfClient::with_default_client(server.url()).unwrap()),
            cache.clone(),
            true,
        );
        for _ in 0..2 {
            assert_eq!(client.discover(&query()).await.unwrap().len(), 1);
        }
        assert_eq!(server.get_requests().len(), 2);
        assert!(cache.lock().unwrap().is_empty());
    }
}

#[test]
fn nrf_server_lifetime_caps_both_fresh_and_stale_cache_reuse() {
    use opc_sbi::nrf::{CacheLookup, DiscoveryCache};
    use std::time::Instant;
    let now = Instant::now();
    let mut cache = DiscoveryCache::new(
        Duration::from_secs(10),
        Duration::from_secs(10),
        Duration::from_secs(600),
        opc_types::ConfigVersion::new(1),
    );
    let key = query().to_cache_key();
    cache.insert_with_validity_at(key.clone(), vec![profile()], Duration::from_secs(15), now);
    assert!(matches!(
        cache.lookup_at(&key, now + Duration::from_secs(9)),
        CacheLookup::Hit(_)
    ));
    assert!(matches!(
        cache.lookup_at(&key, now + Duration::from_secs(12)),
        CacheLookup::Stale(_)
    ));
    assert_eq!(
        cache.lookup_at(&key, now + Duration::from_secs(15)),
        CacheLookup::Miss
    );
    cache.insert_negative_with_validity_at(key.clone(), Duration::from_secs(2), now);
    assert_eq!(
        cache.lookup_at(&key, now + Duration::from_secs(1)),
        CacheLookup::Negative
    );
    assert_eq!(
        cache.lookup_at(&key, now + Duration::from_secs(2)),
        CacheLookup::Miss
    );
    cache.insert_with_validity_at(key.clone(), vec![profile()], Duration::ZERO, now);
    assert!(cache.is_empty());
    let mut other_requester = query();
    other_requester.requester_nf_type = NfType::new("pcf").unwrap();
    assert_ne!(key, other_requester.to_cache_key());
}

#[tokio::test]
async fn nrf_authoritative_absence_replaces_a_stale_positive() {
    use opc_sbi::nrf::{CacheLookup, CachedDiscoveryClient, DiscoveryCache};
    use std::{
        sync::{Arc, Mutex},
        time::Instant,
    };
    let server = MockProducer::start().await;
    server.set_override(
        "/nnrf-disc/v1/nf-instances",
        StatusCode::OK,
        HashMap::new(),
        br#"{"validityPeriod":30,"nfInstances":[]}"#.to_vec(),
    );
    let query = query();
    let key = query.to_cache_key();
    let mut cache = DiscoveryCache::new(
        Duration::from_secs(1),
        Duration::from_secs(30),
        Duration::from_secs(600),
        opc_types::ConfigVersion::new(1),
    );
    cache.insert_at(
        key.clone(),
        vec![profile()],
        Instant::now() - Duration::from_secs(2),
    );
    assert!(matches!(cache.lookup(&key), CacheLookup::Stale(_)));
    let cache = Arc::new(Mutex::new(cache));
    let client = CachedDiscoveryClient::new(
        Arc::new(NrfClient::with_default_client(server.url()).unwrap()),
        cache.clone(),
        true,
    );
    assert!(client.discover(&query).await.is_err());
    assert_eq!(cache.lock().unwrap().lookup(&key), CacheLookup::Negative);
}
