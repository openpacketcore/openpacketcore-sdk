//! Boundary regressions for DNS cache lifetimes and resolver adaptation.

use std::net::SocketAddr;
use std::time::Duration;

use opc_peer_discovery::*;

const DAY: u64 = 86_400_000;

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

fn peer() -> PeerCandidate {
    PeerCandidate::resolved(
        PeerLabel::new("example-service").unwrap(),
        "192.0.2.1:443".parse().unwrap(),
        PeerTransport::Tcp,
        ServiceDiscoveryMode::Address,
        0,
        0,
    )
}

fn rec(kind: DnsRecordType, ttl: u32, observed: u64) -> DnsRecord {
    DnsRecord::new(
        DnsName::new("peer.example").unwrap(),
        kind,
        ttl,
        t(observed),
    )
}

fn answer(ttl: u32, observed: u64) -> DnsAnswer {
    DnsAnswer::new(vec![DnsCandidate::new(
        peer(),
        vec![rec(DnsRecordType::A, ttl, observed)],
    )
    .unwrap()])
    .unwrap()
}

fn cache() -> DnsCache {
    DnsCache::new(
        16,
        DnsRetryPolicy::new(Duration::from_secs(1), Duration::from_secs(30), 7),
    )
}

#[test]
fn answer_freshness_bound_only_shortens_known_lifetimes() {
    let bounded = answer(3600, 1_000)
        .with_freshness_bound(t(301_000))
        .with_freshness_bound(t(601_000));
    assert_eq!(bounded.expires_at(), Some(t(301_000)));
    assert_eq!(bounded.candidates()[0].records().unwrap()[0].ttl, 3600);
    assert_eq!(
        bounded.with_freshness_bound(t(2_000)).expires_at(),
        Some(t(2_000))
    );
    assert_eq!(
        answer(1, 1_000)
            .with_freshness_bound(t(301_000))
            .expires_at(),
        Some(t(2_000))
    );
    let unknown = DnsAnswer::new(vec![DnsCandidate::without_ttl(peer())]).unwrap();
    assert_eq!(unknown.with_freshness_bound(t(301_000)).expires_at(), None);
}

#[test]
fn denial_bounds_preserve_ttls_and_apply_only_the_negative_cap_to_denials() {
    let partial = answer(172_800, 1_000)
        .with_negative_freshness_bound(t(86_401_000))
        .with_negative_freshness_bound(t(172_801_000));
    assert_eq!(partial.expires_at(), Some(t(86_401_000)));
    assert_eq!(partial.candidates()[0].records().unwrap()[0].ttl, 172_800);
    assert_eq!(
        partial.with_freshness_bound(t(301_000)).expires_at(),
        Some(t(301_000))
    );

    for denial in [false, true] {
        let q = query("peer.example");
        let mut cache = cache().with_ttl_caps(Duration::from_secs(3600), Duration::from_secs(60));
        let token = start(&mut cache, &q, 1_000);
        let answer = if denial {
            answer(3600, 1_000).with_negative_freshness_bound(t(301_000))
        } else {
            answer(3600, 1_000).with_freshness_bound(t(301_000))
        };
        assert!(cache.finish_refresh(token, Ok(answer), t(1_000)));
        assert_eq!(
            cache.lookup(&q.cache_key(), t(1_000)).fresh_until,
            Some(t(if denial { 61_000 } else { 301_000 }))
        );
    }

    let q = query("peer.example");
    let mut cache = cache();
    let token = start(&mut cache, &q, 1_000);
    let unknown = DnsAnswer::new(vec![DnsCandidate::without_ttl(peer())])
        .unwrap()
        .with_negative_freshness_bound(t(86_401_000));
    assert_eq!(unknown.expires_at(), None);
    assert!(cache.finish_refresh(token, Ok(unknown), t(1_000)));
    let status = cache.lookup(&q.cache_key(), t(1_000));
    assert!(matches!(status.result, DnsCachedResult::Stale { .. }));
    assert!(status.retry_at.is_some_and(|retry| retry > t(1_000)));
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

#[test]
fn high_bit_record_ttls_are_zero_in_every_chain_position() {
    for ttl in [0x8000_0000, u32::MAX] {
        for records in [
            vec![rec(DnsRecordType::A, ttl, 0)],
            vec![
                rec(DnsRecordType::Cname, ttl, 0),
                rec(DnsRecordType::A, 60, 0),
            ],
        ] {
            let q = query("peer.example");
            let mut cache = cache();
            let token = start(&mut cache, &q, 0);
            let answer = DnsAnswer::new(vec![DnsCandidate::new(peer(), records).unwrap()]).unwrap();
            assert_eq!(answer.expires_at(), Some(t(0)));
            assert!(cache.finish_refresh(token, Ok(answer), t(0)));
            assert!(matches!(
                cache.lookup(&q.cache_key(), t(0)).result,
                DnsCachedResult::Stale { .. }
            ));
            assert!(!cache.refresh_due(t(60 * 365 * DAY)).is_empty());
        }
    }
}

#[test]
fn positive_ttl_defaults_to_seven_days_without_losing_last_good() {
    let q = query("peer.example");
    let mut cache = cache();
    let token = start(&mut cache, &q, 0);
    let answer = answer(0x7fff_ffff, 0);
    assert!(cache.finish_refresh(token, Ok(answer.clone()), t(0)));
    assert!(matches!(
        cache.lookup(&q.cache_key(), t(7 * DAY - 1)).result,
        DnsCachedResult::Fresh(_)
    ));
    match cache.lookup(&q.cache_key(), t(7 * DAY)).result {
        DnsCachedResult::Stale {
            answer: retained,
            age,
        } => {
            assert_eq!(retained, answer);
            assert!(age.is_zero());
        }
        other => panic!("expected capped freshness, got {other:?}"),
    }
    let _ = start(&mut cache, &q, 7 * DAY);
}

#[test]
fn negative_ttl_defaults_to_three_hours_with_and_without_last_good() {
    for last_good in [false, true] {
        for error in [
            DnsError::NxDomain {
                soa: Some(NegativeSoa::new(86_400, 86_400, t(1_000))),
            },
            DnsError::NoData {
                soa: Some(NegativeSoa::new(86_400, 86_400, t(1_000))),
            },
        ] {
            let q = query("peer.example");
            let mut cache = cache();
            if last_good {
                let token = start(&mut cache, &q, 0);
                assert!(cache.finish_refresh(token, Ok(answer(1, 0)), t(0)));
            }
            let token = start(&mut cache, &q, 1_000);
            assert!(cache.finish_refresh(token, Err(error), t(1_000)));
            let expiry = 1_000 + 3 * 3_600_000;
            assert_eq!(
                cache.lookup(&q.cache_key(), t(1_000)).retry_at,
                Some(t(expiry))
            );
            assert!(cache.refresh_due(t(expiry - 1)).is_empty());
            assert_eq!(cache.refresh_due(t(expiry)), vec![q.cache_key()]);
            if last_good {
                assert!(matches!(
                    cache.lookup(&q.cache_key(), t(expiry)).result,
                    DnsCachedResult::Stale { .. }
                ));
            } else {
                assert_eq!(
                    cache.lookup(&q.cache_key(), t(expiry)).result,
                    DnsCachedResult::Miss
                );
            }
        }
    }
}

#[test]
fn unusable_soa_timing_never_becomes_an_authoritative_cache_hit() {
    for (ttl, minimum) in [
        (0, 30),
        (30, 0),
        (0x8000_0000, 30),
        (30, 0x8000_0000),
        (u32::MAX, u32::MAX),
    ] {
        let soa = NegativeSoa::new(ttl, minimum, t(0));
        assert!(soa.ttl().is_zero());
        assert_eq!(soa.expires_at(), t(0));
    }
}

#[test]
fn uncacheable_results_are_paced_without_inventing_freshness_or_denials() {
    let unknown = DnsAnswer::new(vec![DnsCandidate::without_ttl(peer())]).unwrap();
    for result in [
        Ok(answer(0, 0)),
        Ok(answer(1, 0)),
        Ok(unknown),
        Err(DnsError::NxDomain { soa: None }),
        Err(DnsError::NoData { soa: None }),
        Err(DnsError::NxDomain {
            soa: Some(NegativeSoa::new(0, 30, t(0))),
        }),
        Err(DnsError::NoData {
            soa: Some(NegativeSoa::new(30, 0, t(0))),
        }),
    ] {
        let q = query("peer.example");
        let mut cache = cache();
        let mut now = 2_000;
        // A few deterministic rounds replace a tight-loop load probe.
        for attempt in 0..4 {
            let token = start(&mut cache, &q, now);
            assert!(cache.finish_refresh(token, result.clone(), t(now)));
            let status = cache.lookup(&q.cache_key(), t(now));
            assert!(matches!(
                status.result,
                DnsCachedResult::Stale { .. } | DnsCachedResult::Miss
            ));
            let due = status
                .retry_at
                .expect("uncacheable results must be paced")
                .as_millis();
            let cap = if result.is_ok() {
                5_000
            } else {
                1_000 << attempt
            };
            assert!((cap / 2..=cap).contains(&(due - now)));
            assert!(cache.refresh_due(t(now)).is_empty());
            assert!(matches!(
                cache
                    .begin_refresh(&q, t(now), Duration::from_secs(1))
                    .unwrap(),
                DnsRefresh::Suppressed
            ));
            assert!(cache.refresh_due(t(due - 1)).is_empty());
            assert_eq!(cache.refresh_due(t(due)), vec![q.cache_key()]);
            now = due;
        }
    }
}

struct SystemOrder;

impl AddressLookup for SystemOrder {
    fn lookup(&self, _: &str, _: u16, _: Duration) -> Result<Vec<SocketAddr>, AddressLookupError> {
        Ok(vec![
            "192.0.2.1:443".parse().unwrap(),
            "[::ffff:192.0.2.2]:443".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
        ])
    }
}

#[test]
fn legacy_bridge_preserves_host_order_after_family_filtering() {
    for (family, expected) in [
        (
            AddressFamilyPolicy::DualStack,
            vec![
                "192.0.2.1:443",
                "[::ffff:192.0.2.2]:443",
                "[2001:db8::1]:443",
            ],
        ),
        (
            AddressFamilyPolicy::Ipv4Only,
            vec!["192.0.2.1:443", "[::ffff:192.0.2.2]:443"],
        ),
        (AddressFamilyPolicy::Ipv6Only, vec!["[2001:db8::1]:443"]),
    ] {
        let answer = AddressPeerResolver::new(SystemOrder)
            .resolve_dns(
                &query("peer.example").with_address_family(family),
                Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            answer
                .candidates()
                .iter()
                .map(|c| c.peer().endpoint.to_string())
                .collect::<Vec<_>>(),
            expected
        );
        assert!(answer
            .candidates()
            .windows(2)
            .all(|pair| pair[0].peer().weight > pair[1].peer().weight));
    }
}

#[test]
fn mapped_addresses_follow_ipv4_family_policy() {
    let mapped = "[::ffff:192.0.2.1]:443".parse().unwrap();
    let mut addresses = vec![mapped];
    order_dns_addresses(&mut addresses, AddressFamilyPolicy::Ipv6Only);
    assert!(addresses.is_empty());
    addresses.push(mapped);
    order_dns_addresses(&mut addresses, AddressFamilyPolicy::Ipv4Only);
    assert_eq!(addresses, vec![mapped]);
}

#[test]
fn input_errors_are_distinct_from_malformed_answers() {
    for name in ["bad name", "2001:db8::1", "192.0.2.1"] {
        assert_eq!(
            DnsQuery::new(input(name)).unwrap_err().code(),
            "dns-invalid-query"
        );
    }
    let mut no_port = input("peer.example");
    no_port.default_port = None;
    assert_eq!(
        AddressPeerResolver::new(SystemOrder)
            .resolve_dns(&DnsQuery::new(no_port).unwrap(), Duration::from_secs(1))
            .unwrap_err()
            .code(),
        "dns-invalid-query"
    );
}

#[test]
fn candidate_and_chain_cardinality_are_bounded_at_construction() {
    let c = DnsCandidate::new(peer(), vec![rec(DnsRecordType::A, 60, 0)]).unwrap();
    assert!(DnsAnswer::new(vec![c.clone(); 16]).is_ok());
    assert!(DnsAnswer::new(vec![c; 17]).is_err());
    let mut chain = vec![rec(DnsRecordType::Cname, 60, 0); 15];
    chain.push(rec(DnsRecordType::A, 60, 0));
    assert!(DnsCandidate::new(peer(), chain.clone()).is_ok());
    chain.insert(0, rec(DnsRecordType::Cname, 60, 0));
    assert!(DnsCandidate::new(peer(), chain).is_err());
}

#[test]
fn custom_retry_bounds_cannot_exceed_five_minutes() {
    for base in [
        Duration::from_secs(1),
        Duration::from_secs(3_600),
        Duration::MAX,
    ] {
        let mut cache = DnsCache::new(16, DnsRetryPolicy::new(base, Duration::MAX, 5));
        let q = query("peer.example");
        let mut now = 0;
        for _ in 0..14 {
            let token = start(&mut cache, &q, now);
            assert!(cache.finish_refresh(token, Err(DnsError::ServFail), t(now)));
            let due = cache
                .lookup(&q.cache_key(), t(now))
                .retry_at
                .unwrap()
                .as_millis();
            assert!((1..=300_000).contains(&(due - now)));
            now = due;
        }
    }
}

#[test]
fn capacity_reclaims_expired_cold_failures_but_keeps_live_backoff() {
    let mut cache = DnsCache::new(
        2,
        DnsRetryPolicy::new(Duration::from_secs(1), Duration::from_secs(1), 1),
    );
    for name in ["gone-a.example", "gone-b.example"] {
        let q = query(name);
        let token = start(&mut cache, &q, 0);
        assert!(cache.finish_refresh(token, Err(DnsError::Timeout), t(0)));
    }
    let q = query("needed.example");
    assert_eq!(
        cache
            .begin_refresh(&q, t(0), Duration::from_secs(1))
            .unwrap_err(),
        DnsCacheError::Capacity
    );
    let _ = start(&mut cache, &q, DAY);
    assert!(cache.len() <= 2);
}

#[test]
fn authoritative_negative_resets_transient_backoff() {
    for negative in [
        DnsError::NxDomain {
            soa: Some(NegativeSoa::new(1, 1, t(100_000))),
        },
        DnsError::NoData {
            soa: Some(NegativeSoa::new(1, 1, t(100_000))),
        },
    ] {
        let mut cache = cache();
        let q = query("peer.example");
        let mut now = 0;
        for _ in 0..5 {
            let token = start(&mut cache, &q, now);
            assert!(cache.finish_refresh(token, Err(DnsError::ServFail), t(now)));
            now = cache
                .lookup(&q.cache_key(), t(now))
                .retry_at
                .unwrap()
                .as_millis();
        }
        let token = start(&mut cache, &q, 100_000);
        assert!(cache.finish_refresh(token, Err(negative), t(100_000)));
        let token = start(&mut cache, &q, 101_000);
        assert!(cache.finish_refresh(token, Err(DnsError::ServFail), t(101_000)));
        let delay = cache
            .lookup(&q.cache_key(), t(101_000))
            .retry_at
            .unwrap()
            .as_millis()
            - 101_000;
        assert!((500..=1_000).contains(&delay));
    }
}

#[test]
fn adapter_rejects_unsupported_profiles_and_modes() {
    let mut adapter = AddressPeerResolver::new(SystemOrder);
    assert_eq!(
        adapter
            .resolve_dns(
                &query("peer.example").with_resolver_profile(ResolverProfileId::new("profile-a")),
                Duration::from_secs(1)
            )
            .unwrap_err(),
        DnsError::Unavailable
    );
    for mode in [ServiceDiscoveryMode::Service, ServiceDiscoveryMode::Snaptr] {
        let mut input = input("peer.example");
        input.mode = mode;
        assert_eq!(
            adapter
                .resolve_dns(&DnsQuery::new(input).unwrap(), Duration::from_secs(1))
                .unwrap_err(),
            DnsError::Unavailable
        );
    }
}

#[test]
fn record_diagnostics_redact_names_and_name_length_boundaries_are_checked() {
    let record = rec(DnsRecordType::Cname, 60, 0);
    assert!(!format!("{record:?}").contains("peer.example"));
    assert!(DnsName::new("a".repeat(63)).is_ok());
    assert!(DnsName::new("a".repeat(64)).is_err());
    let longest = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(longest.len(), 253);
    assert_eq!(
        DnsName::new(&longest).unwrap(),
        DnsName::new(format!("{longest}.")).unwrap()
    );
    assert!(DnsName::new(format!("{longest}e")).is_err());
}

#[test]
fn refreshing_status_tracks_admission_deadline_and_publication() {
    let q = query("peer.example");
    let mut cache = cache();
    assert!(!cache.lookup(&q.cache_key(), t(0)).refreshing);
    let token = start(&mut cache, &q, 0);
    assert!(cache.lookup(&q.cache_key(), t(0)).refreshing);
    assert!(!cache.lookup(&q.cache_key(), t(1_000)).refreshing);
    assert!(!cache.finish_refresh(token, Ok(answer(60, 1_000)), t(1_000)));
    let token = start(&mut cache, &q, 5_000);
    assert!(cache.finish_refresh(token, Ok(answer(60, 5_000)), t(5_000)));
    assert!(!cache.lookup(&q.cache_key(), t(5_000)).refreshing);
}

#[test]
fn tunable_caps_bound_publication_without_restarting_record_deadlines() {
    let q = query("peer.example");
    for (record_ttl, expected_expiry) in [(60, 2_500), (2, 2_000)] {
        let mut cache = cache().with_ttl_caps(Duration::from_secs(2), Duration::from_secs(20));
        let token = start(&mut cache, &q, 0);
        assert!(cache.finish_refresh(token, Ok(answer(record_ttl, 0)), t(500)));
        assert!(matches!(
            cache.lookup(&q.cache_key(), t(expected_expiry - 1)).result,
            DnsCachedResult::Fresh(_)
        ));
        assert!(
            matches!(cache.lookup(&q.cache_key(), t(expected_expiry)).result, DnsCachedResult::Stale { age, .. } if age.is_zero())
        );
    }
    for (soa_ttl, expected_expiry) in [(60, 2_500), (2, 2_000)] {
        let mut cache = cache().with_ttl_caps(Duration::from_secs(2), Duration::from_secs(20));
        let token = start(&mut cache, &q, 0);
        let error = DnsError::NoData {
            soa: Some(NegativeSoa::new(soa_ttl, soa_ttl, t(0))),
        };
        assert!(cache.finish_refresh(token, Err(error), t(500)));
        assert_eq!(
            cache.lookup(&q.cache_key(), t(500)).retry_at,
            Some(t(expected_expiry))
        );
    }
    let mut cache = cache().with_ttl_caps(Duration::ZERO, Duration::from_secs(60));
    let token = start(&mut cache, &q, 0);
    assert!(cache.finish_refresh(token, Ok(answer(60, 0)), t(0)));
    assert!(matches!(
        cache.lookup(&q.cache_key(), t(0)).result,
        DnsCachedResult::Stale { .. }
    ));
    assert!(cache.refresh_due(t(0)).is_empty());
    let now = cache
        .lookup(&q.cache_key(), t(0))
        .retry_at
        .unwrap()
        .as_millis();
    let token = start(&mut cache, &q, now);
    assert!(cache.finish_refresh(
        token,
        Err(DnsError::NoData {
            soa: Some(NegativeSoa::new(60, 60, t(now)))
        }),
        t(now)
    ));
    assert!(cache.refresh_due(t(now)).is_empty());
}

#[test]
fn alias_chain_expiry_bounds_negative_answers_and_expired_results_are_paced() {
    let q = query("alias.example");
    let alias = rec(DnsRecordType::Cname, 1, 0);
    let soa = NegativeSoa::new(60, 60, t(500))
        .with_chain_expiry(alias.expires_at())
        .with_chain_expiry(t(2_000));
    assert_eq!(soa.expires_at(), t(1_000));
    let mut cache = cache();
    let token = start(&mut cache, &q, 500);
    let error = DnsError::NxDomain { soa: Some(soa) };
    assert!(cache.finish_refresh(token, Err(error), t(500)));
    assert_eq!(
        cache.lookup(&q.cache_key(), t(999)).result,
        DnsCachedResult::Negative(error)
    );
    assert_eq!(
        cache.lookup(&q.cache_key(), t(1_000)).result,
        DnsCachedResult::Miss
    );
    let token = start(&mut cache, &q, 1_000);
    assert!(cache.finish_refresh(token, Err(error), t(1_000)));
    assert_eq!(
        cache.lookup(&q.cache_key(), t(1_000)).result,
        DnsCachedResult::Miss
    );
    assert!(cache.refresh_due(t(1_000)).is_empty());
}

#[test]
fn expired_negatives_can_leave_capacity_without_evicting_positive_or_in_flight_keys() {
    let needed = query("needed.example");
    for positive in [false, true] {
        let q = query("peer.example");
        let mut cache = DnsCache::new(1, DnsRetryPolicy::default());
        let token = start(&mut cache, &q, 0);
        assert_eq!(
            cache
                .begin_refresh(&needed, t(0), Duration::from_secs(1))
                .unwrap_err(),
            DnsCacheError::Capacity
        );
        if positive {
            assert!(cache.finish_refresh(token, Ok(answer(1, 0)), t(0)));
        } else {
            assert!(cache.finish_refresh(
                token,
                Err(DnsError::NoData {
                    soa: Some(NegativeSoa::new(1, 1, t(0)))
                }),
                t(0)
            ));
        }
        assert_eq!(
            cache
                .begin_refresh(&needed, t(999), Duration::from_secs(1))
                .unwrap_err(),
            DnsCacheError::Capacity
        );
        if positive {
            assert_eq!(
                cache
                    .begin_refresh(&needed, t(DAY), Duration::from_secs(1))
                    .unwrap_err(),
                DnsCacheError::Capacity
            );
        } else {
            let _ = start(&mut cache, &needed, 1_000);
            assert_eq!(
                cache.lookup(&q.cache_key(), t(1_000)).result,
                DnsCachedResult::Miss
            );
            assert_eq!(cache.lookup(&q.cache_key(), t(1_000)).last_error, None);
            assert!(!cache.refresh_due(t(1_000)).contains(&q.cache_key()));
            assert!(cache.remove(&needed.cache_key()));
            let _ = start(&mut cache, &q, 1_000);
        }
    }
}

#[test]
fn mapped_address_cache_publication_uses_the_traffic_family() {
    let mut peer = peer();
    peer.endpoint = "[::ffff:192.0.2.1]:443".parse().unwrap();
    let answer = DnsAnswer::new(vec![DnsCandidate::new(
        peer,
        vec![rec(DnsRecordType::Aaaa, 60, 0)],
    )
    .unwrap()])
    .unwrap();
    for (family, accepted) in [
        (AddressFamilyPolicy::Ipv4Only, true),
        (AddressFamilyPolicy::Ipv6Only, false),
    ] {
        let mut cache = cache();
        let q = query("peer.example").with_address_family(family);
        let token = start(&mut cache, &q, 0);
        assert!(cache.finish_refresh(token, Ok(answer.clone()), t(0)));
        let status = cache.lookup(&q.cache_key(), t(0));
        if accepted {
            assert!(matches!(status.result, DnsCachedResult::Fresh(_)));
        } else {
            assert_eq!(status.result, DnsCachedResult::Miss);
            assert_eq!(status.last_error, Some(DnsError::MalformedAnswer));
        }
    }
}

#[test]
fn capacity_recovers_an_abandoned_cold_refresh_after_its_backoff() {
    let q = query("abandoned.example");
    let needed = query("needed.example");
    let mut cache = DnsCache::new(
        1,
        DnsRetryPolicy::new(Duration::from_secs(1), Duration::from_secs(1), 1),
    );
    let old = start(&mut cache, &q, 0);
    assert_eq!(
        cache
            .begin_refresh(&needed, t(1_000), Duration::from_secs(1))
            .unwrap_err(),
        DnsCacheError::Capacity
    );
    assert_eq!(
        cache.lookup(&q.cache_key(), t(1_000)).last_error,
        Some(DnsError::Timeout)
    );
    let _ = start(&mut cache, &needed, 2_000);
    assert!(!cache.finish_refresh(old, Ok(answer(60, 0)), t(2_000)));
}

#[test]
fn oversized_ttl_caps_preserve_positive_and_negative_caching() {
    for cap in [Duration::MAX, Duration::from_secs(1 << 31)] {
        let mut cache = cache().with_ttl_caps(cap, cap);
        let q = query("peer.example");
        let token = start(&mut cache, &q, 0);
        assert!(cache.finish_refresh(token, Ok(answer(60, 0)), t(500)));
        assert!(matches!(
            cache.lookup(&q.cache_key(), t(59_999)).result,
            DnsCachedResult::Fresh(_)
        ));
        assert!(matches!(
            cache.lookup(&q.cache_key(), t(60_000)).result,
            DnsCachedResult::Stale { .. }
        ));

        for error in [
            DnsError::NxDomain {
                soa: Some(NegativeSoa::new(60, 60, t(0))),
            },
            DnsError::NoData {
                soa: Some(NegativeSoa::new(60, 60, t(0))),
            },
        ] {
            assert!(cache.remove(&q.cache_key()));
            let token = start(&mut cache, &q, 0);
            assert!(cache.finish_refresh(token, Err(error), t(500)));
            assert_eq!(
                cache.lookup(&q.cache_key(), t(59_999)).result,
                DnsCachedResult::Negative(error)
            );
            assert_eq!(
                cache.lookup(&q.cache_key(), t(500)).retry_at,
                Some(t(60_000))
            );
            assert_eq!(
                cache.lookup(&q.cache_key(), t(60_000)).result,
                DnsCachedResult::Miss
            );
        }
    }
}

#[test]
fn capacity_keeps_last_good_after_failure_backoff_elapses() {
    let mut cache = DnsCache::new(
        1,
        DnsRetryPolicy::new(Duration::from_secs(1), Duration::from_secs(1), 7),
    );
    let q = query("peer.example");
    let needed = query("needed.example");
    let last_good = answer(1, 0);
    let token = start(&mut cache, &q, 0);
    assert!(cache.finish_refresh(token, Ok(last_good.clone()), t(0)));
    let token = start(&mut cache, &q, 1_000);
    assert!(cache.finish_refresh(token, Err(DnsError::Timeout), t(1_000)));
    let due = cache.lookup(&q.cache_key(), t(1_000)).retry_at.unwrap();
    assert_eq!(cache.refresh_due(due), vec![q.cache_key()]);
    assert!(!cache.lookup(&q.cache_key(), due).refreshing);
    assert_eq!(
        cache
            .begin_refresh(&needed, due, Duration::from_secs(1))
            .unwrap_err(),
        DnsCacheError::Capacity
    );
    let status = cache.lookup(&q.cache_key(), due);
    assert_eq!(status.last_error, Some(DnsError::Timeout));
    assert!(matches!(status.result, DnsCachedResult::Stale { answer, .. } if answer == last_good));
}

#[test]
fn uncacheable_success_default_cadence_is_independent_of_failure_backoff() {
    let q = query("peer.example");
    let bridge_answer = AddressPeerResolver::new(SystemOrder)
        .resolve_dns(&q, Duration::from_secs(1))
        .unwrap();
    for response in [answer(0, 0), answer(1, 0), bridge_answer] {
        let mut cache = DnsCache::new(
            1,
            DnsRetryPolicy::new(Duration::from_millis(1), Duration::from_secs(30), 7),
        );
        let mut now = 2_000;
        let mut gaps = Vec::new();
        for _ in 0..4 {
            let token = start(&mut cache, &q, now);
            assert!(cache.finish_refresh(token, Ok(response.clone()), t(now)));
            let status = cache.lookup(&q.cache_key(), t(now));
            assert!(matches!(status.result, DnsCachedResult::Stale { .. }));
            let due = status.retry_at.unwrap().as_millis();
            assert!((2_500..=5_000).contains(&(due - now)));
            assert!(cache.refresh_due(t(due - 1)).is_empty());
            gaps.push(due - now);
            now = due;
        }
        assert!(
            gaps.windows(2).any(|pair| pair[0] != pair[1]),
            "refresh pacing must retain jitter"
        );
        let token = start(&mut cache, &q, now);
        assert!(cache.finish_refresh(token, Err(DnsError::ServFail), t(now)));
        assert_eq!(
            cache.lookup(&q.cache_key(), t(now)).retry_at,
            Some(t(now + 1))
        );
    }
}

#[test]
fn retry_policy_debug_hides_seed_and_random_state() {
    let seed = 1_234_567_890_123_456_789;
    let policy = DnsRetryPolicy::new(Duration::from_secs(1), Duration::from_secs(30), seed);
    let other = DnsRetryPolicy::new(Duration::from_secs(1), Duration::from_secs(30), 42);
    let debug = format!("{policy:?}");
    assert_eq!(debug, format!("{other:?}"));
    assert!(!debug.contains(&seed.to_string()));
    assert!(!debug.contains("random"));
}

#[test]
fn custom_success_refresh_interval_does_not_change_failure_backoff() {
    let q = query("peer.example");
    let mut cache = DnsCache::new(
        1,
        DnsRetryPolicy::new(Duration::from_millis(1), Duration::from_millis(1), 7),
    )
    .with_refresh_interval(Duration::from_secs(10));
    let mut now = 0;
    for _ in 0..4 {
        let token = start(&mut cache, &q, now);
        assert!(cache.finish_refresh(token, Ok(answer(0, now)), t(now)));
        let status = cache.lookup(&q.cache_key(), t(now));
        assert!(matches!(status.result, DnsCachedResult::Stale { .. }));
        let due = status.retry_at.unwrap().as_millis();
        assert!((5_000..=10_000).contains(&(due - now)));
        assert!(cache.refresh_due(t(due - 1)).is_empty());
        now = due;
    }
    let token = start(&mut cache, &q, now);
    assert!(cache.finish_refresh(token, Err(DnsError::Timeout), t(now)));
    assert_eq!(
        cache.lookup(&q.cache_key(), t(now)).retry_at,
        Some(t(now + 1))
    );
}

#[test]
fn success_refresh_interval_bounds_prevent_immediate_retries() {
    for (interval, low, high) in [
        (Duration::ZERO, 1, 1),
        (Duration::MAX, 1_073_741_823_500, 2_147_483_647_000),
    ] {
        let mut cache = cache().with_refresh_interval(interval);
        let q = query("peer.example");
        let token = start(&mut cache, &q, 0);
        assert!(cache.finish_refresh(token, Ok(answer(0, 0)), t(0)));
        let due = cache
            .lookup(&q.cache_key(), t(0))
            .retry_at
            .unwrap()
            .as_millis();
        assert!((low..=high).contains(&due));
        assert!(cache.refresh_due(t(0)).is_empty());
    }
}

#[test]
fn cache_status_exposes_effective_positive_deadline_through_expiry_and_failure() {
    let q = query("peer.example");
    for (record_ttl, expected) in [(60, 2_500), (2, 2_000)] {
        let mut cache = cache().with_ttl_caps(Duration::from_secs(2), Duration::from_secs(1));
        assert_eq!(cache.lookup(&q.cache_key(), t(0)).fresh_until, None);
        let token = start(&mut cache, &q, 0);
        assert_eq!(cache.lookup(&q.cache_key(), t(0)).fresh_until, None);
        assert!(cache.finish_refresh(token, Ok(answer(record_ttl, 0)), t(500)));
        let status = cache.lookup(&q.cache_key(), t(500));
        assert_eq!(status.fresh_until, Some(t(expected)));
        let DnsCachedResult::Fresh(answer) = status.result else {
            panic!("expected fresh answer")
        };
        assert_eq!(answer.expires_at(), Some(t(u64::from(record_ttl) * 1_000)));
        assert!(cache.refresh_due(t(expected - 1)).is_empty());
        assert_eq!(cache.refresh_due(t(expected)), vec![q.cache_key()]);
        let token = start(&mut cache, &q, expected);
        assert!(cache.finish_refresh(token, Err(DnsError::Timeout), t(expected)));
        let status = cache.lookup(&q.cache_key(), t(expected + 1_000));
        assert_eq!(status.fresh_until, Some(t(expected)));
        assert!(
            matches!(status.result, DnsCachedResult::Stale { age, .. } if age == Duration::from_secs(1))
        );
        assert!(cache.remove(&q.cache_key()));
        let token = start(&mut cache, &q, expected);
        assert!(cache.finish_refresh(
            token,
            Err(DnsError::NoData {
                soa: Some(NegativeSoa::new(60, 60, t(expected)))
            }),
            t(expected)
        ));
        let status = cache.lookup(&q.cache_key(), t(expected));
        assert_eq!(status.fresh_until, None);
        assert_eq!(status.retry_at, Some(t(expected + 1_000)));
    }
    for answer in [
        answer(0, 0),
        DnsAnswer::new(vec![DnsCandidate::without_ttl(peer())]).unwrap(),
    ] {
        let mut cache = cache();
        let token = start(&mut cache, &q, 0);
        assert!(cache.finish_refresh(token, Ok(answer), t(0)));
        let status = cache.lookup(&q.cache_key(), t(0));
        assert_eq!(status.fresh_until, Some(t(0)));
        assert!(matches!(status.result, DnsCachedResult::Stale { .. }));
        assert!(status.retry_at.unwrap() > t(0));
    }
}
