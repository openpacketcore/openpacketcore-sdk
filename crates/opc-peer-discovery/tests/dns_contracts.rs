use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use opc_peer_discovery::*;

fn t(ms: u64) -> PeerDiscoveryTime {
    PeerDiscoveryTime::from_millis(ms)
}

fn input(name: &str) -> ServiceDiscoveryInput {
    ServiceDiscoveryInput::new(
        PeerLabel::new("example-service").unwrap(),
        DiscoveryTarget::new(name),
        ServiceDiscoveryMode::Address,
        PeerTransport::Tcp,
        Some(443),
    )
}

fn query(name: &str) -> DnsQuery {
    DnsQuery::new(input(name)).unwrap()
}

fn record(name: &str, kind: DnsRecordType, ttl: u32, observed: u64) -> DnsRecord {
    DnsRecord::new(DnsName::new(name).unwrap(), kind, ttl, t(observed))
}

fn candidate(ip: &str) -> PeerCandidate {
    PeerCandidate::resolved(
        PeerLabel::new("example-service").unwrap(),
        SocketAddr::new(ip.parse::<IpAddr>().unwrap(), 443),
        PeerTransport::Tcp,
        ServiceDiscoveryMode::Address,
        0,
        0,
    )
}

fn answer(ttl: u32, observed: u64) -> DnsAnswer {
    DnsAnswer::new(vec![DnsCandidate::new(
        candidate("192.0.2.1"),
        vec![record("peer.example", DnsRecordType::A, ttl, observed)],
    )
    .unwrap()])
    .unwrap()
}

fn start(cache: &mut DnsCache, q: &DnsQuery, now: u64) -> DnsRefreshToken {
    match cache
        .begin_refresh(q, t(now), Duration::from_secs(1))
        .unwrap()
    {
        DnsRefresh::Start(token) => token,
        other => panic!("unexpected refresh state: {other:?}"),
    }
}

fn seed(cache: &mut DnsCache, q: &DnsQuery, ttl: u32) {
    let token = start(cache, q, 0);
    assert!(cache.finish_refresh(token, Ok(answer(ttl, 0)), t(0)));
}

#[test]
fn names_are_canonical_and_every_query_dimension_separates_keys() {
    let q = query("PEER.Example.");
    assert_eq!(q.cache_key(), query("peer.example").cache_key());
    assert_eq!(q.name().as_str(), "peer.example.");
    assert_eq!(DnsName::new(".").unwrap().as_str(), ".");
    for invalid in [
        "",
        "peer..example",
        "peer.example..",
        "peer example",
        "é.example",
    ] {
        assert!(DnsName::new(invalid).is_err());
    }
    let mut alternatives = vec![query("other.example")];
    for mode in [ServiceDiscoveryMode::Service, ServiceDiscoveryMode::Snaptr] {
        let mut i = input("peer.example");
        i.mode = mode;
        alternatives.push(DnsQuery::new(i).unwrap());
    }
    let mut i = input("peer.example");
    i.transport = PeerTransport::Udp;
    alternatives.push(DnsQuery::new(i).unwrap());
    let mut i = input("peer.example");
    i.service = PeerLabel::new("other-service").unwrap();
    alternatives.push(DnsQuery::new(i).unwrap());
    let mut i = input("peer.example");
    i.default_port = Some(8443);
    alternatives.push(DnsQuery::new(i).unwrap());
    alternatives.push(
        q.clone()
            .with_resolver_profile(ResolverProfileId::new("profile-a")),
    );
    alternatives.push(q.clone().with_source_plane(SourcePlaneId::new("plane-a")));
    for family in [AddressFamilyPolicy::Ipv4Only, AddressFamilyPolicy::Ipv6Only] {
        alternatives.push(q.clone().with_address_family(family));
    }
    let mut cache = DnsCache::default();
    seed(&mut cache, &q, 60);
    for other in alternatives {
        assert_ne!(q.cache_key(), other.cache_key());
        assert!(matches!(
            cache.lookup(&other.cache_key(), t(0)).result,
            DnsCachedResult::Miss
        ));
        let _ = start(&mut cache, &other, 0);
    }
}

#[test]
fn freshness_uses_shortest_record_deadline_across_chains() {
    let q = query("peer.example");
    let mut cache = DnsCache::default();
    let token = start(&mut cache, &q, 900);
    let records = vec![
        record("peer.example", DnsRecordType::Naptr, 8, 0),
        record("_service._tcp.example", DnsRecordType::Srv, 7, 100),
        record("alias.example", DnsRecordType::Cname, 2, 0),
        record("host.example", DnsRecordType::A, 30, 900),
    ];
    let first = DnsCandidate::new(candidate("192.0.2.1"), records.clone()).unwrap();
    let second = DnsCandidate::new(
        candidate("2001:db8::1"),
        vec![record("host.example", DnsRecordType::Aaaa, 60, 900)],
    )
    .unwrap();
    let resolved = DnsAnswer::new(vec![first, second]).unwrap();
    assert_eq!(resolved.candidates()[0].records(), Some(records.as_slice()));
    assert_eq!(resolved.expires_at(), Some(t(2_000)));
    assert!(cache.finish_refresh(token, Ok(resolved), t(1_000)));
    assert!(matches!(
        cache.lookup(&q.cache_key(), t(1_999)).result,
        DnsCachedResult::Fresh(_)
    ));
    match cache.lookup(&q.cache_key(), t(2_001)).result {
        DnsCachedResult::Stale { age, answer } => {
            assert_eq!(age, Duration::from_millis(1));
            assert_eq!(answer.candidates().len(), 2);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn zero_ttl_never_becomes_fresh_and_overflow_cannot_create_infinite_freshness() {
    let q = query("peer.example");
    let mut cache = DnsCache::default();
    seed(&mut cache, &q, 0);
    assert!(
        matches!(cache.lookup(&q.cache_key(), t(0)).result, DnsCachedResult::Stale { age, .. } if age.is_zero())
    );
    assert!(matches!(
        cache
            .begin_refresh(&q, t(0), Duration::from_secs(1))
            .unwrap(),
        DnsRefresh::Suppressed
    ));
    assert_eq!(answer(1, u64::MAX - 1).expires_at(), Some(t(u64::MAX - 1)));
}

#[test]
fn authoritative_negatives_use_soa_minimum_and_expire_at_boundary() {
    for error in [
        DnsError::NxDomain {
            soa: Some(NegativeSoa::new(12, 3, t(0))),
        },
        DnsError::NoData {
            soa: Some(NegativeSoa::new(3, 12, t(0))),
        },
    ] {
        let q = query("missing.example");
        let mut cache = DnsCache::default();
        let token = start(&mut cache, &q, 0);
        assert!(cache.finish_refresh(token, Err(error), t(0)));
        assert_eq!(
            cache.lookup(&q.cache_key(), t(2_999)).result,
            DnsCachedResult::Negative(error)
        );
        assert!(matches!(
            cache
                .begin_refresh(&q, t(2_999), Duration::from_secs(1))
                .unwrap(),
            DnsRefresh::Suppressed
        ));
        assert!(matches!(
            cache.lookup(&q.cache_key(), t(3_000)).result,
            DnsCachedResult::Miss
        ));
        let _ = start(&mut cache, &q, 3_000);
    }
}

#[test]
fn absent_soa_and_zero_negative_ttl_are_not_cached_as_denials() {
    for error in [
        DnsError::NxDomain { soa: None },
        DnsError::NoData {
            soa: Some(NegativeSoa::new(0, 30, t(0))),
        },
        DnsError::NxDomain {
            soa: Some(NegativeSoa::new(30, 0, t(0))),
        },
    ] {
        let mut cache = DnsCache::default();
        let q = query("missing.example");
        let token = start(&mut cache, &q, 0);
        assert!(cache.finish_refresh(token, Err(error), t(0)));
        assert_eq!(
            cache.lookup(&q.cache_key(), t(0)).result,
            DnsCachedResult::Miss
        );
        assert!(cache.refresh_due(t(0)).is_empty());
        let retry = cache.lookup(&q.cache_key(), t(0)).retry_at.unwrap();
        let _ = start(&mut cache, &q, retry.as_millis());
    }
}

#[test]
fn retries_are_bounded_jittered_and_reset_by_success() {
    let policy = DnsRetryPolicy::new(Duration::from_secs(1), Duration::from_secs(8), 17);
    let mut cache = DnsCache::new(16, policy);
    let q = query("peer.example");
    let mut now = 0;
    let mut delays = Vec::new();
    for attempt in 0..6 {
        let token = start(&mut cache, &q, now);
        assert!(cache.finish_refresh(token, Err(DnsError::ServFail), t(now)));
        let due = cache
            .lookup(&q.cache_key(), t(now))
            .retry_at
            .unwrap()
            .as_millis();
        let cap = (1_000u64 << attempt).min(8_000);
        assert!((cap / 2..=cap).contains(&(due - now)));
        assert!(matches!(
            cache
                .begin_refresh(&q, t(due - 1), Duration::from_secs(1))
                .unwrap(),
            DnsRefresh::Suppressed
        ));
        delays.push(due - now);
        now = due;
    }
    assert_ne!(delays[3], delays[4]);
    let token = start(&mut cache, &q, now);
    assert!(cache.finish_refresh(token, Ok(answer(0, now)), t(now)));
    assert_eq!(cache.lookup(&q.cache_key(), t(now)).last_error, None);
    now = cache
        .lookup(&q.cache_key(), t(now))
        .retry_at
        .unwrap()
        .as_millis();
    let token = start(&mut cache, &q, now);
    assert!(cache.finish_refresh(token, Err(DnsError::Timeout), t(now)));
    let delay = cache
        .lookup(&q.cache_key(), t(now))
        .retry_at
        .unwrap()
        .as_millis()
        - now;
    assert!((500..=1_000).contains(&delay));
    let mut other = DnsCache::new(
        16,
        DnsRetryPolicy::new(Duration::from_secs(1), Duration::from_secs(8), 18),
    );
    let token = start(&mut other, &q, 0);
    assert!(other.finish_refresh(token, Err(DnsError::ServFail), t(0)));
    assert_ne!(
        other
            .lookup(&q.cache_key(), t(0))
            .retry_at
            .unwrap()
            .as_millis(),
        delays[0]
    );
}

#[test]
fn every_failure_preserves_last_good_without_time_cutoff() {
    for error in [
        DnsError::Timeout,
        DnsError::ServFail,
        DnsError::Transport,
        DnsError::MalformedAnswer,
        DnsError::SourceUnavailable,
        DnsError::Unavailable,
        DnsError::LegacyNotFound,
        DnsError::NxDomain {
            soa: Some(NegativeSoa::new(3, 4, t(0))),
        },
        DnsError::NoData {
            soa: Some(NegativeSoa::new(3, 4, t(0))),
        },
    ] {
        let mut cache = DnsCache::default();
        let q = query("peer.example");
        seed(&mut cache, &q, 1);
        let token = start(&mut cache, &q, 1_000);
        assert!(cache.finish_refresh(token, Err(error), t(1_000)));
        let status = cache.lookup(&q.cache_key(), t(u64::MAX));
        assert_eq!(status.last_error, Some(error));
        assert!(
            matches!(status.result, DnsCachedResult::Stale { answer: a, .. } if a == answer(1, 0))
        );
    }
}

#[test]
fn capacity_never_evicts_a_needed_key_and_removed_results_cannot_return() {
    let mut cache = DnsCache::new(1, DnsRetryPolicy::default());
    let q = query("peer.example");
    seed(&mut cache, &q, 0);
    assert_eq!(
        cache
            .begin_refresh(&query("other.example"), t(0), Duration::from_secs(1))
            .unwrap_err(),
        DnsCacheError::Capacity
    );
    let due = cache
        .lookup(&q.cache_key(), t(0))
        .retry_at
        .unwrap()
        .as_millis();
    let old = start(&mut cache, &q, due);
    assert!(cache.remove(&q.cache_key()));
    let new = start(&mut cache, &q, due);
    assert!(!cache.finish_refresh(old, Ok(answer(60, 0)), t(due)));
    assert!(cache.finish_refresh(new, Ok(answer(5, 0)), t(due)));
    assert!(cache.remove(&q.cache_key()));
    assert!(cache.is_empty());
}

#[test]
fn concurrent_callers_share_one_refresh_and_completion() {
    let cache = Arc::new(Mutex::new(DnsCache::default()));
    let barrier = Arc::new(Barrier::new(12));
    let handles: Vec<_> = (0..12)
        .map(|_| {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                cache
                    .lock()
                    .unwrap()
                    .begin_refresh(&query("peer.example"), t(0), Duration::from_secs(1))
                    .unwrap()
            })
        })
        .collect();
    let mut tokens = Vec::new();
    for handle in handles {
        match handle.join().unwrap() {
            DnsRefresh::Start(token) => tokens.push(token),
            DnsRefresh::Pending => (),
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(tokens.len(), 1);
    let mut cache = cache.lock().unwrap();
    assert!(cache.finish_refresh(tokens.pop().unwrap(), Ok(answer(60, 0)), t(0)));
    assert!(matches!(
        cache
            .lookup(&query("peer.example").cache_key(), t(0))
            .result,
        DnsCachedResult::Fresh(_)
    ));
}

#[test]
fn abandoned_refresh_times_out_and_late_completion_cannot_replace_success() {
    let mut cache = DnsCache::default();
    let q = query("peer.example");
    seed(&mut cache, &q, 0);
    let first_due = cache
        .lookup(&q.cache_key(), t(0))
        .retry_at
        .unwrap()
        .as_millis();
    let old = start(&mut cache, &q, first_due);
    let expired_at = first_due + 1_000;
    assert!(matches!(
        cache
            .begin_refresh(&q, t(expired_at), Duration::from_secs(1))
            .unwrap(),
        DnsRefresh::Suppressed
    ));
    let status = cache.lookup(&q.cache_key(), t(expired_at));
    assert_eq!(status.last_error, Some(DnsError::Timeout));
    assert!(
        matches!(status.result, DnsCachedResult::Stale { answer: retained, age }
        if retained == answer(0, 0) && age == Duration::from_millis(expired_at))
    );
    let due = status.retry_at.unwrap().as_millis();
    let new = start(&mut cache, &q, due);
    assert!(cache.finish_refresh(new, Ok(answer(60, due)), t(due)));
    assert!(!cache.finish_refresh(old, Ok(answer(1, 0)), t(due)));
    assert!(matches!(
        cache.lookup(&q.cache_key(), t(due)).result,
        DnsCachedResult::Fresh(_)
    ));
}

#[test]
fn destination_policy_uses_rfc_precedence_then_scope_and_stable_input_order() {
    let mut addresses = vec![
        "192.0.2.1:443",
        "[::ffff:192.0.2.2]:443",
        "[2001:db8::1]:443",
        "[::1]:443",
        "[fc00::1]:443",
        "[2002:c000:201::1]:443",
        "[2001:db8::2]:443",
    ]
    .into_iter()
    .map(|s| s.parse().unwrap())
    .collect::<Vec<SocketAddr>>();
    order_dns_addresses(&mut addresses, AddressFamilyPolicy::DualStack);
    assert_eq!(
        addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec![
            "[::1]:443",
            "[2001:db8::1]:443",
            "[2001:db8::2]:443",
            "192.0.2.1:443",
            "[::ffff:192.0.2.2]:443",
            "[2002:c000:201::1]:443",
            "[fc00::1]:443"
        ]
    );
    order_dns_addresses(&mut addresses, AddressFamilyPolicy::Ipv4Only);
    assert_eq!(
        addresses,
        vec![
            "192.0.2.1:443".parse::<SocketAddr>().unwrap(),
            "[::ffff:192.0.2.2]:443".parse().unwrap()
        ]
    );
}

#[test]
fn legacy_address_adapter_reports_unknown_ttl_and_obeys_family_policy() {
    struct Lookup;
    impl AddressLookup for Lookup {
        fn lookup(
            &self,
            _: &str,
            _: u16,
            _: Duration,
        ) -> Result<Vec<SocketAddr>, AddressLookupError> {
            Ok(vec![
                "192.0.2.1:443".parse().unwrap(),
                "[2001:db8::1]:443".parse().unwrap(),
            ])
        }
    }
    let q = query("peer.example");
    let mut adapter = AddressPeerResolver::new(Lookup);
    let resolved = adapter.resolve_dns(&q, Duration::from_secs(1)).unwrap();
    assert_eq!(resolved.expires_at(), None);
    assert!(resolved.candidates().iter().all(|c| c.records().is_none()));
    assert!(resolved.candidates()[0].peer().endpoint.is_ipv4());
    let v4 = adapter
        .resolve_dns(
            &q.clone().with_address_family(AddressFamilyPolicy::Ipv4Only),
            Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(v4.candidates().len(), 1);
    let mut cache = DnsCache::default();
    let token = start(&mut cache, &q, 0);
    assert!(cache.finish_refresh(token, Ok(resolved), t(0)));
    assert!(matches!(
        cache.lookup(&q.cache_key(), t(0)).result,
        DnsCachedResult::Stale { .. }
    ));
    assert_eq!(
        adapter
            .resolve_dns(
                &q.with_source_plane(SourcePlaneId::new("plane-a")),
                Duration::from_secs(1)
            )
            .unwrap_err(),
        DnsError::SourceUnavailable
    );
}

#[test]
fn diagnostics_contain_only_codes_counts_and_timing() {
    let q = query("sensitive.example")
        .with_resolver_profile(ResolverProfileId::new("profile-sensitive.example"))
        .with_source_plane(SourcePlaneId::new("plane-sensitive.example"));
    let a = answer(30, 0);
    let mut cache = DnsCache::default();
    let token = start(&mut cache, &q, 0);
    let debug = format!(
        "{q:?} {:?} {:?} {a:?} {:?} {token:?} {cache:?}",
        q.cache_key(),
        q.name(),
        a.candidates()
    );
    for secret in [
        "sensitive.example",
        "peer.example",
        "192.0.2.1",
        "profile-sensitive",
        "plane-sensitive",
    ] {
        assert!(!debug.contains(secret), "disclosed {secret}");
    }
    assert_ne!(
        DnsError::NxDomain { soa: None }.code(),
        DnsError::NoData { soa: None }.code()
    );
    assert_eq!(DnsError::Transport.to_string(), "dns-transport");
}

#[test]
fn delayed_negative_publication_does_not_restart_soa_ttl() {
    let q = query("missing.example");
    let mut cache = DnsCache::default();
    let token = start(&mut cache, &q, 500);
    let error = DnsError::NxDomain {
        soa: Some(NegativeSoa::new(1, 10, t(0))),
    };
    assert!(cache.finish_refresh(token, Err(error), t(900)));
    assert_eq!(
        cache.lookup(&q.cache_key(), t(999)).result,
        DnsCachedResult::Negative(error)
    );
    assert_eq!(
        cache.lookup(&q.cache_key(), t(1_000)).result,
        DnsCachedResult::Miss
    );
    let _ = start(&mut cache, &q, 1_000);
}

#[test]
fn malformed_empty_future_and_wrong_family_answers_preserve_last_good() {
    assert_eq!(
        DnsAnswer::new(vec![]).unwrap_err(),
        DnsError::MalformedAnswer
    );
    assert_eq!(
        DnsCandidate::new(candidate("192.0.2.1"), vec![]).unwrap_err(),
        DnsError::MalformedAnswer
    );
    assert_eq!(
        DnsCandidate::new(
            candidate("192.0.2.1"),
            vec![record("peer.example", DnsRecordType::Aaaa, 1, 0)]
        )
        .unwrap_err(),
        DnsError::MalformedAnswer
    );
    let q = query("peer.example").with_address_family(AddressFamilyPolicy::Ipv4Only);
    let v6 = DnsAnswer::new(vec![DnsCandidate::new(
        candidate("2001:db8::1"),
        vec![record("peer.example", DnsRecordType::Aaaa, 60, 1_000)],
    )
    .unwrap()])
    .unwrap();
    for bad in [
        Ok(answer(60, 2_000)),
        Ok(v6),
        Err(DnsError::NoData {
            soa: Some(NegativeSoa::new(1, 10, t(2_000))),
        }),
    ] {
        let mut cache = DnsCache::default();
        seed(&mut cache, &q, 1);
        let token = start(&mut cache, &q, 1_000);
        assert!(cache.finish_refresh(token, bad, t(1_000)));
        let status = cache.lookup(&q.cache_key(), t(1_000));
        assert_eq!(status.last_error, Some(DnsError::MalformedAnswer));
        assert!(
            matches!(status.result, DnsCachedResult::Stale { answer: a, .. } if a == answer(1, 0))
        );
    }
}

#[test]
fn due_keys_respect_freshness_in_flight_backoff_and_explicit_removal() {
    let q = query("peer.example");
    let mut cache = DnsCache::default();
    seed(&mut cache, &q, 1);
    assert!(cache.refresh_due(t(999)).is_empty());
    assert_eq!(cache.refresh_due(t(1_000)), vec![q.cache_key()]);
    let token = start(&mut cache, &q, 1_000);
    assert!(cache.refresh_due(t(1_999)).is_empty());
    // Completion exactly at the attempt deadline is late, and records timeout.
    assert!(!cache.finish_refresh(token, Ok(answer(60, 2_000)), t(2_000)));
    let status = cache.lookup(&q.cache_key(), t(2_000));
    assert_eq!(status.last_error, Some(DnsError::Timeout));
    let due = status.retry_at.unwrap();
    assert!(cache.refresh_due(t(due.as_millis() - 1)).is_empty());
    assert_eq!(cache.refresh_due(due), vec![q.cache_key()]);
    cache.remove(&q.cache_key());
    assert!(cache.refresh_due(t(u64::MAX)).is_empty());
}

#[test]
fn cache_tokens_cannot_publish_to_another_cache() {
    let q = query("peer.example");
    let mut first = DnsCache::default();
    let mut second = DnsCache::default();
    let first_token = start(&mut first, &q, 0);
    let second_token = start(&mut second, &q, 0);
    assert!(!second.finish_refresh(first_token, Ok(answer(60, 0)), t(0)));
    assert!(second.finish_refresh(second_token, Ok(answer(1, 0)), t(0)));
    assert!(first.refresh_due(t(1_000)).is_empty());
    assert_eq!(
        first.lookup(&q.cache_key(), t(1_000)).last_error,
        Some(DnsError::Timeout)
    );
}

#[test]
fn legacy_not_found_is_a_retry_never_an_authoritative_negative() {
    struct Lookup;
    impl AddressLookup for Lookup {
        fn lookup(
            &self,
            _: &str,
            _: u16,
            _: Duration,
        ) -> Result<Vec<SocketAddr>, AddressLookupError> {
            Err(AddressLookupError::NotFound)
        }
    }
    let q = query("missing.example");
    let error = AddressPeerResolver::new(Lookup)
        .resolve_dns(&q, Duration::from_secs(1))
        .unwrap_err();
    assert_eq!(error, DnsError::LegacyNotFound);
    let mut cache = DnsCache::default();
    let token = start(&mut cache, &q, 0);
    assert!(cache.finish_refresh(token, Err(error), t(0)));
    let status = cache.lookup(&q.cache_key(), t(0));
    assert_eq!(status.result, DnsCachedResult::Miss);
    assert!(status.retry_at.unwrap() > t(0));
}

#[test]
fn destination_policy_implements_remaining_prefix_and_scope_rules() {
    let mut addresses = [
        "[2001:db8::2]:443",
        "[fe80::1]:443",
        "[fc00::1]:443",
        "[2001::1]:443",
        "[::ffff:192.0.2.1]:443",
        "[::192.0.2.2]:443",
        "[fec0::1]:443",
        "[3ffe::1]:443",
    ]
    .into_iter()
    .map(|s| s.parse().unwrap())
    .collect();
    order_dns_addresses(&mut addresses, AddressFamilyPolicy::Ipv6Only);
    assert_eq!(
        addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec![
            "[fe80::1]:443",
            "[2001:db8::2]:443",
            "[2001::1]:443",
            "[fc00::1]:443",
            "[fec0::1]:443",
            "[::c000:202]:443",
            "[3ffe::1]:443"
        ]
    );
    let mut v4 = ["192.0.2.1:443", "169.254.1.1:443", "127.0.0.1:443"]
        .into_iter()
        .map(|s| s.parse().unwrap())
        .collect();
    order_dns_addresses(&mut v4, AddressFamilyPolicy::Ipv4Only);
    assert_eq!(
        v4.iter().map(ToString::to_string).collect::<Vec<_>>(),
        vec!["169.254.1.1:443", "127.0.0.1:443", "192.0.2.1:443"]
    );
}
