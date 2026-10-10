//! Independent RFC 3403/3958/6408 wire fixtures; no production encoders or DNS.

mod support;

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opc_peer_discovery::*;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

#[path = "support/snaptr_wire.rs"]
mod wire;
use wire::*;

struct FakeDns {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<(String, u16)>>>,
    task: JoinHandle<()>,
    _tcp: TcpListener,
}

impl FakeDns {
    async fn new(respond: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static) -> Self {
        Self::new_async(move |q| std::future::ready(respond(&q))).await
    }

    async fn new_async<F, R>(respond: F) -> Self
    where
        F: Fn(Vec<u8>) -> R + Send + 'static,
        R: std::future::Future<Output = Option<Vec<u8>>> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (listener, socket) = support::bind_dns_pair(listener).await.unwrap();
        let address = socket.local_addr().unwrap();
        let socket = Arc::new(socket);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let task = tokio::spawn(async move {
            let mut buffer = [0; 65_535];
            let mut replies = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    received = socket.recv_from(&mut buffer) => {
                        let (len, peer) = received.unwrap();
                        let q = &buffer[..len];
                        let (owner, kind, _) = question(q);
                        seen.lock().unwrap().push((owner, kind));
                        let response = respond(q.to_vec());
                        let socket = socket.clone();
                        replies.spawn(async move {
                            if let Some(response) = response.await {
                                socket.send_to(&response, peer).await.unwrap();
                            }
                        });
                    }
                    result = replies.join_next(), if !replies.is_empty() => {
                        result.unwrap().unwrap();
                    }
                }
            }
        });
        Self {
            address,
            requests,
            task,
            _tcp: listener,
        }
    }

    fn seen(&self) -> Vec<(String, u16)> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for FakeDns {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn mixed_delegation_srv_and_address_preserve_path_rank_port_and_ttl() {
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let (answers, additional) = match (owner.as_str(), kind) {
            (ROOT, 35) => (
                vec![
                    naptr(ROOT, 20, 0, "A", SERVICE, "", OTHER, 60),
                    naptr(ROOT, 10, 99, "", SERVICE, "", CHILD, 60),
                ],
                vec![],
            ),
            (CHILD, 35) => (
                vec![naptr(
                    CHILD,
                    90,
                    50,
                    "S",
                    SERVICE,
                    "",
                    "service.example.invalid.",
                    7,
                )],
                vec![],
            ),
            ("service.example.invalid.", 33) => (
                vec![srv("service.example.invalid.", 20, 18, 7777, HOST, 40)],
                vec![address(HOST, "192.0.2.1", 90)],
            ),
            (OTHER, 1) => (vec![address(OTHER, "192.0.2.2", 30)], vec![]),
            _ => panic!("unexpected question: {owner} {kind}"),
        };
        Some(reply(q, 0, &answers, &[], &additional))
    })
    .await;
    let response = DnsClient::new(config(dns.address))
        .unwrap()
        .resolve_with_seed(&query(), now, 7)
        .await;
    let answer = response.result.as_ref().unwrap();
    assert_eq!(
        answer
            .candidates()
            .iter()
            .map(|c| c.peer().endpoint.to_string())
            .collect::<Vec<_>>(),
        ["192.0.2.1:7777", "192.0.2.2:2123"]
    );
    assert_eq!(answer.expires_at(), Some(time(8_000)));
    let first = &answer.candidates()[0];
    assert_eq!(
        first
            .records()
            .unwrap()
            .iter()
            .map(|r| r.kind)
            .collect::<Vec<_>>(),
        [
            DnsRecordType::Naptr,
            DnsRecordType::Naptr,
            DnsRecordType::Srv,
            DnsRecordType::A
        ]
    );
    let path = &first.snaptr().unwrap().paths()[0];
    assert_eq!(
        path.hops()
            .iter()
            .map(|hop| (hop.order(), hop.preference()))
            .collect::<Vec<_>>(),
        [(10, 99), (90, 50)]
    );
    assert_eq!(path.srv().unwrap().weight(), 18);
    assert_eq!(path.srv().unwrap().priority(), 20);
    assert_eq!(first.peer().priority, 0);
    assert_eq!(first.peer().weight, u16::MAX);
    assert_eq!(answer.candidates()[1].peer().weight, u16::MAX - 1);
    assert_eq!(answer.snaptr_hosts().unwrap().len(), 2);
    assert_eq!(
        response
            .sources
            .iter()
            .map(|s| s.record_type)
            .collect::<Vec<_>>(),
        [
            DnsRecordType::Naptr,
            DnsRecordType::Naptr,
            DnsRecordType::Srv,
            DnsRecordType::A
        ]
    );
    assert_eq!(response.snaptr_root().unwrap().kind, SnaptrRootKind::Match);
    assert_eq!(dns.seen().len(), 4);
}

#[tokio::test]
async fn refused_branches_and_unrelated_services_do_not_hide_healthy_paths() {
    let dns = FakeDns::new(|q| {
        let answers = if question(q).1 == 35 {
            vec![
                naptr(ROOT, 0, 0, "u", "E2U+sip", "!^.*$!sip:example!", ".", 90),
                naptr(ROOT, 0, 0, "u", "AAA+D2S", "ignored", ".", 90),
                naptr(ROOT, 0, 0, "u", "unrelated:!bad!", "ignored", ".", 90),
                naptr(ROOT, 1, 0, "u", SERVICE, "", HOST, 90),
                naptr(ROOT, 2, 0, "a", SERVICE, "!bad!", HOST, 90),
                naptr(ROOT, 3, 0, "a", SERVICE, "", HOST, 90),
            ]
        } else {
            vec![address(HOST, "192.0.2.1", 90)]
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let mut cfg = config(dns.address);
    cfg.partial_failure_ttl = Duration::from_secs(3);
    let response = DnsClient::new(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    let answer = response.result.unwrap();
    assert_eq!(answer.candidates().len(), 1);
    assert_eq!(answer.expires_at(), Some(time(4_000)));
    assert_eq!(answer.snaptr_coverage().unwrap().refused_branches, 2);
    assert_eq!(answer.snaptr_coverage().unwrap().filtered_records, 3);
    assert!(response.snaptr_branches.iter().any(|b| matches!(
        b.error,
        DnsError::Snaptr {
            reason: SnaptrFailure::RegexpNotEmpty,
            ..
        }
    )));
    assert!(response.snaptr_branches.iter().any(|b| matches!(
        b.error,
        DnsError::Snaptr {
            reason: SnaptrFailure::UnsupportedFlag,
            ..
        }
    )));
    let mut cache = DnsCache::default();
    let token = start(&mut cache, &query(), now());
    assert!(cache.finish_refresh(token, Ok(answer), now()));
    let DnsCachedResult::Fresh(cached) = cache.lookup(&query().cache_key(), now()).result else {
        panic!("expected fresh partial answer")
    };
    assert_eq!(cached.snaptr_coverage().unwrap().refused_branches, 2);
}

#[tokio::test]
async fn root_no_match_classification_survives_finish_refresh_and_paces_retry() {
    for (services, expected) in [
        (
            "aaa+ap6:diameter.sctp",
            SnaptrNoMatch::ExtendedPresentNoMatch,
        ),
        (
            "aaa+ap16777264:diameter.tcp",
            SnaptrNoMatch::ExtendedPresentNoMatch,
        ),
        ("aaa:diameter.sctp", SnaptrNoMatch::LegacyOnly),
        ("AAA+D2S", SnaptrNoMatch::LegacyOnly),
        ("E2U+sip", SnaptrNoMatch::NotAdvertised),
    ] {
        let dns = FakeDns::new(move |q| {
            Some(reply(
                q,
                0,
                &[naptr(REALM, 1, 0, "a", services, "", HOST, 60)],
                &[],
                &[],
            ))
        })
        .await;
        let q = query_for(REALM, "aaa+ap16777264", "diameter.sctp");
        let response = DnsClient::new(config(dns.address))
            .unwrap()
            .resolve_with_seed(&q, now, 0)
            .await;
        let error = response.result.unwrap_err();
        assert_eq!(
            error,
            DnsError::Snaptr {
                reason: SnaptrFailure::NoMatchingService(expected),
                expires_at: Some(time(61_000))
            }
        );
        let mut cache =
            DnsCache::default().with_ttl_caps(Duration::from_secs(120), Duration::from_secs(20));
        let token = start(&mut cache, &q, now());
        assert!(cache.finish_refresh(token, Err(error), now()));
        let status = cache.lookup(&q.cache_key(), time(15_000));
        assert_eq!(status.result, DnsCachedResult::Negative(error));
        assert_eq!(status.retry_at, Some(time(21_000)));
        assert!(matches!(
            cache
                .begin_refresh(&q, time(15_000), Duration::from_secs(1))
                .unwrap(),
            DnsRefresh::Suppressed
        ));
        assert!(matches!(
            cache.lookup(&q.cache_key(), time(21_000)).result,
            DnsCachedResult::Miss
        ));
        assert_eq!(dns.seen().len(), 1);
    }
}

#[tokio::test]
async fn relay_matches_any_diameter_application_at_its_own_rank() {
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let answers: Vec<Vec<u8>> = if kind == 35 {
            vec![
                naptr(
                    REALM,
                    20,
                    0,
                    "a",
                    "aaa+ap16777264:diameter.sctp",
                    "",
                    OTHER,
                    60,
                ),
                naptr(
                    REALM,
                    10,
                    99,
                    "a",
                    "aaa+ap4294967295:diameter.sctp",
                    "",
                    HOST,
                    60,
                ),
            ]
        } else {
            vec![address(
                &owner,
                if owner == HOST {
                    "192.0.2.1"
                } else {
                    "192.0.2.2"
                },
                60,
            )]
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let q = query_for(REALM, "aaa+ap16777264", "diameter.sctp");
    let answer = DnsClient::new(config(dns.address))
        .unwrap()
        .resolve_with_seed(&q, now, 2)
        .await
        .result
        .unwrap();
    assert_eq!(answer.candidates().len(), 2);
    assert_eq!(
        answer.candidates()[0].peer().endpoint.to_string(),
        "192.0.2.1:3868"
    );
    assert_eq!(
        answer.candidates()[0].snaptr().unwrap().paths()[0].hops()[0].order(),
        10
    );
}

#[tokio::test]
async fn endpoint_cap_alone_preserves_record_freshness_and_best_host_prefix() {
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let answers: Vec<Vec<u8>> = if kind == 35 {
            (1..=9)
                .rev()
                .map(|i| {
                    naptr(
                        ROOT,
                        i,
                        0,
                        "a",
                        SERVICE,
                        "",
                        &format!("host{i}.example.invalid."),
                        900,
                    )
                })
                .collect()
        } else {
            let i: u8 = owner
                .strip_prefix("host")
                .unwrap()
                .split('.')
                .next()
                .unwrap()
                .parse()
                .unwrap();
            vec![address(
                &owner,
                &if kind == 1 {
                    format!("192.0.2.{i}")
                } else {
                    format!("2001:db8::{i}")
                },
                900,
            )]
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let q = query().with_address_family(AddressFamilyPolicy::DualStack);
    let mut cfg = config(dns.address);
    cfg.partial_failure_ttl = Duration::ZERO;
    let answer = DnsClient::new(cfg)
        .unwrap()
        .resolve_with_seed(&q, now, 0)
        .await
        .result
        .unwrap();
    assert_eq!(answer.candidates().len(), 16);
    assert_eq!(answer.snaptr_hosts().unwrap().len(), 8);
    assert_eq!(answer.expires_at(), Some(time(901_000)));
    assert!(answer.snaptr_coverage().unwrap().incomplete);
    assert_eq!(
        answer
            .snaptr_hosts()
            .unwrap()
            .iter()
            .map(|host| host.name().as_str())
            .collect::<Vec<_>>(),
        (1..=8)
            .map(|i| format!("host{i}.example.invalid."))
            .collect::<Vec<_>>()
    );
    for (i, candidate) in answer.candidates().iter().enumerate() {
        assert_eq!(candidate.peer().weight, u16::MAX - i as u16);
    }
}

#[tokio::test]
async fn root_denials_keep_authority_but_child_denials_do_not() {
    for rcode in [0, 3] {
        let dns = FakeDns::new(move |q| {
            Some(reply(q, rcode, &[], &[soa("3gppnetwork.org.", 30, 7)], &[]))
        })
        .await;
        let response = DnsClient::new(config(dns.address))
            .unwrap()
            .resolve_with_seed(&query(), now, 0)
            .await;
        assert_eq!(
            response.snaptr_root().unwrap().kind,
            SnaptrRootKind::NoNaptr
        );
        match response.result.unwrap_err() {
            DnsError::NxDomain { soa: Some(value) } if rcode == 3 => {
                assert_eq!(value.expires_at(), time(8_000))
            }
            DnsError::NoData { soa: Some(value) } if rcode == 0 => {
                assert_eq!(value.expires_at(), time(8_000))
            }
            other => panic!("root error lost: {other:?}"),
        }
    }
    let dns = FakeDns::new(|q| {
        if question(q).0 == ROOT {
            Some(reply(
                q,
                0,
                &[naptr(ROOT, 1, 0, "", SERVICE, "", CHILD, 90)],
                &[],
                &[],
            ))
        } else {
            Some(reply(q, 3, &[], &[soa("example.invalid.", 30, 7)], &[]))
        }
    })
    .await;
    let response = DnsClient::new(config(dns.address))
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    assert_eq!(response.snaptr_root().unwrap().kind, SnaptrRootKind::Match);
    assert_eq!(
        response.result,
        Err(DnsError::Snaptr {
            reason: SnaptrFailure::NoUsablePath,
            expires_at: None
        })
    );
    assert!(response
        .outcomes
        .iter()
        .any(|o| matches!(o.result, Err(DnsError::NxDomain { .. }))));
}

#[tokio::test]
async fn loops_depth_and_regexp_have_distinct_typed_refusals() {
    for (replacement, regexp, depth, reason) in [
        (ROOT, "", 8, SnaptrFailure::Loop),
        (CHILD, "", 1, SnaptrFailure::DepthLimit),
        (CHILD, "!.*!", 8, SnaptrFailure::RegexpNotEmpty),
    ] {
        let dns = FakeDns::new(move |q| {
            Some(reply(
                q,
                0,
                &[naptr(
                    &question(q).0,
                    1,
                    0,
                    "",
                    SERVICE,
                    regexp,
                    replacement,
                    60,
                )],
                &[],
                &[],
            ))
        })
        .await;
        let mut cfg = config(dns.address);
        cfg.max_snaptr_depth = depth;
        let response = DnsClient::new(cfg)
            .unwrap()
            .resolve_with_seed(&query(), now, 0)
            .await;
        assert_eq!(
            response.result,
            Err(DnsError::Snaptr {
                reason,
                expires_at: None
            })
        );
        assert!(dns.seen().len() <= 2);
    }
}

#[tokio::test]
async fn child_servfail_is_partial_but_root_servfail_is_unclassified() {
    for root_failure in [true, false] {
        let dns = FakeDns::new(move |q| {
            let (owner, kind, _) = question(q);
            if root_failure || owner == CHILD {
                return Some(reply(q, 2, &[], &[], &[]));
            }
            let answers: Vec<Vec<u8>> = if kind == 35 {
                vec![
                    naptr(ROOT, 1, 0, "", SERVICE, "", CHILD, 90),
                    naptr(ROOT, 2, 0, "a", SERVICE, "", HOST, 90),
                ]
            } else {
                vec![address(HOST, "192.0.2.1", 90)]
            };
            Some(reply(q, 0, &answers, &[], &[]))
        })
        .await;
        let mut cfg = config(dns.address);
        cfg.partial_failure_ttl = Duration::from_secs(2);
        let response = DnsClient::new(cfg)
            .unwrap()
            .resolve_with_seed(&query(), now, 0)
            .await;
        if root_failure {
            assert_eq!(response.result, Err(DnsError::ServFail));
            assert!(response.snaptr_root().is_none());
        } else {
            let answer = response.result.unwrap();
            assert_eq!(answer.expires_at(), Some(time(3_000)));
            assert_eq!(answer.snaptr_coverage().unwrap().failed_branches, 1);
            assert!(response
                .outcomes
                .iter()
                .any(|o| o.owner.as_str() == CHILD && o.result == Err(DnsError::ServFail)));
        }
    }
}

#[test]
fn filter_validation_and_query_identity_are_explicit() {
    for (service, protocol) in [
        ("", "diameter.sctp"),
        ("1bad", "x-good"),
        ("x-good", ""),
        ("aaa+ap016777264", "diameter.sctp"),
        ("aaa+ap4294967296", "diameter.sctp"),
        ("aaa+ap+1", "diameter.sctp"),
        ("aaa+ap", "diameter.sctp"),
        ("x-3gpp-pgw", "x-s2b-gtp+ue"),
        ("x-3gpp-pgw", "x-s2b-gtp+nc"),
        ("x-3gpp-pgw", "x-good:other"),
        ("é", "x-good"),
    ] {
        assert_eq!(
            SnaptrFilter::new(service, protocol, SnaptrOrdering::Rfc3958),
            Err(DnsError::InvalidQuery)
        );
    }
    assert!(SnaptrFilter::new(&"a".repeat(33), "x-good", SnaptrOrdering::Rfc3958).is_err());
    let q = query();
    let same = q
        .clone()
        .with_snaptr_filter(
            SnaptrFilter::new("X-3GPP-PGW", "X-S2B-GTP", SnaptrOrdering::Rfc3958).unwrap(),
        )
        .unwrap();
    assert_eq!(q.cache_key(), same.cache_key());
    for filter in [
        SnaptrFilter::new("x-other", "x-s2b-gtp", SnaptrOrdering::Rfc3958).unwrap(),
        SnaptrFilter::new("x-3gpp-pgw", "x-other", SnaptrOrdering::Rfc3958).unwrap(),
        SnaptrFilter::new("x-3gpp-pgw", "x-s2b-gtp", SnaptrOrdering::ThreeGpp).unwrap(),
    ] {
        assert_ne!(
            q.cache_key(),
            q.clone().with_snaptr_filter(filter).unwrap().cache_key()
        );
    }
    let mut input = q.input().clone();
    input.mode = ServiceDiscoveryMode::Address;
    assert_eq!(
        DnsQuery::new(input)
            .unwrap()
            .with_snaptr_filter(q.snaptr_filter().unwrap().clone()),
        Err(DnsError::InvalidQuery)
    );
}

#[tokio::test]
async fn invalid_ports_filters_profiles_and_bounds_send_no_questions() {
    let dns = FakeDns::new(|_| panic!("invalid input reached DNS")).await;
    let client = DnsClient::new(config(dns.address)).unwrap();
    for port in [None, Some(0)] {
        let mut input = query().input().clone();
        input.default_port = port;
        let q = DnsQuery::new(input)
            .unwrap()
            .with_snaptr_filter(query().snaptr_filter().unwrap().clone())
            .unwrap();
        assert_eq!(
            client.resolve(&q, now).await.result,
            Err(DnsError::InvalidQuery)
        );
    }
    let q = DnsQuery::new(query().input().clone()).unwrap();
    assert_eq!(
        client.resolve(&q, now).await.result,
        Err(DnsError::InvalidQuery)
    );
    assert_eq!(
        client
            .resolve(
                &query().with_resolver_profile(ResolverProfileId::new("other")),
                now
            )
            .await
            .result,
        Err(DnsError::Unavailable)
    );
    assert_eq!(
        client
            .resolve(&query().with_source_plane(SourcePlaneId::new("other")), now)
            .await
            .result,
        Err(DnsError::SourceUnavailable)
    );
    for (depth, records, lookups, timeout) in [
        (0, 128, 64, 1_000),
        (15, 128, 64, 1_000),
        (8, 0, 64, 1_000),
        (8, 1025, 64, 1_000),
        (8, 128, 0, 1_000),
        (8, 128, 257, 1_000),
        (8, 128, 64, 300_001),
    ] {
        let mut cfg = config(dns.address);
        cfg.max_snaptr_depth = depth;
        cfg.max_snaptr_records = records;
        cfg.max_snaptr_lookups = lookups;
        cfg.snaptr_refresh_timeout = Duration::from_millis(timeout);
        assert!(matches!(DnsClient::new(cfg), Err(DnsError::InvalidQuery)));
    }
    assert!(dns.seen().is_empty());
}

#[tokio::test]
async fn shared_child_is_memoized_per_refresh_without_becoming_a_loop() {
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let answers = match (owner.as_str(), kind) {
            (ROOT, 35) => vec![
                naptr(ROOT, 1, 0, "", SERVICE, "", CHILD, 90),
                naptr(ROOT, 2, 0, "", SERVICE, "", CHILD, 90),
                naptr(ROOT, 3, 0, "a", SERVICE, "", OTHER, 90),
            ],
            (CHILD, 35) => vec![naptr(CHILD, 1, 0, "a", SERVICE, "", HOST, 4)],
            (HOST, 1) | (OTHER, 1) => vec![address(&owner, "192.0.2.1", 90)],
            _ => panic!("unexpected question {owner} {kind}"),
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let q = query();
    let response = DnsClient::new(config(dns.address))
        .unwrap()
        .resolve_with_seed(&q, now, 4)
        .await;
    assert_eq!(dns.seen().len(), 4);
    assert_eq!(response.sources.len(), 4);
    assert_eq!(response.outcomes.len(), 6);
    let answer = response.result.unwrap();
    assert_eq!(answer.candidates().len(), 1);
    assert_eq!(answer.candidates()[0].snaptr().unwrap().paths().len(), 3);
    assert_eq!(answer.snaptr_hosts().unwrap().len(), 2);
    assert_eq!(
        answer.snaptr_hosts().unwrap()[0].addresses()[0].path_indices(),
        [0, 1]
    );
    assert_eq!(
        answer.snaptr_hosts().unwrap()[1].addresses()[0].candidate_index(),
        0
    );
    assert_eq!(
        answer.snaptr_hosts().unwrap()[1].addresses()[0].path_indices(),
        [2]
    );
    assert_eq!(answer.expires_at(), Some(time(5_000)));
    assert!(!answer.snaptr_coverage().unwrap().incomplete);
    let mut cache = DnsCache::default();
    let token = start(&mut cache, &q, now());
    assert!(cache.finish_refresh(token, Ok(answer.clone()), now()));
    assert_eq!(
        cache.lookup(&q.cache_key(), now()).result,
        DnsCachedResult::Fresh(answer)
    );
}

#[tokio::test]
async fn duplicate_paths_do_not_fill_the_endpoint_pool_and_alternates_are_bounded() {
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let answers: Vec<Vec<u8>> = if kind == 35 {
            // Two hosts, four addresses each, reached by six distinct paths.
            // A third host with a fifth address expands the endpoint pool to 13.
            (0..6)
                .map(|i| {
                    naptr(
                        ROOT,
                        i,
                        0,
                        "a",
                        SERVICE,
                        "",
                        if i % 2 == 0 { HOST } else { OTHER },
                        120,
                    )
                })
                .chain(std::iter::once(naptr(
                    ROOT,
                    9,
                    0,
                    "a",
                    SERVICE,
                    "",
                    "third.example.invalid.",
                    120,
                )))
                .collect()
        } else {
            let start = if owner == HOST {
                1
            } else if owner == OTHER {
                5
            } else {
                9
            };
            let count = if start == 9 { 5 } else { 4 };
            (start..start + count)
                .map(|i| address(&owner, &format!("192.0.2.{i}"), 120))
                .collect()
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let answer = DnsClient::new(config(dns.address))
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await
        .result
        .unwrap();
    assert_eq!(answer.candidates().len(), 13);
    assert_eq!(answer.snaptr_hosts().unwrap().len(), 3);
    assert_eq!(answer.candidates()[0].snaptr().unwrap().paths().len(), 3);
    assert_eq!(dns.seen().len(), 4);

    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let answers: Vec<Vec<u8>> = if kind == 35 {
            (0..7)
                .map(|i| {
                    naptr(
                        ROOT,
                        i,
                        0,
                        "a",
                        SERVICE,
                        "",
                        &format!("path{i}.example.invalid."),
                        90,
                    )
                })
                .collect()
        } else {
            vec![address(&owner, "192.0.2.1", 90)]
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let mut cfg = config(dns.address);
    cfg.partial_failure_ttl = Duration::ZERO;
    let answer = DnsClient::new(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await
        .result
        .unwrap();
    assert_eq!(answer.candidates().len(), 1);
    assert_eq!(answer.candidates()[0].snaptr().unwrap().paths().len(), 4);
    assert_eq!(answer.snaptr_hosts().unwrap().len(), 4);
    assert_eq!(answer.snaptr_coverage().unwrap().omitted_paths, 3);
    assert_eq!(answer.snaptr_coverage().unwrap().omitted_hosts, 3);
    assert_eq!(answer.expires_at(), Some(time(91_000)));
}

#[tokio::test]
async fn rrset_ttl_is_normalized_before_filtering_and_duplicate_removal() {
    for ttl in [0, 1, 0x8000_0000] {
        let dns = FakeDns::new(move |q| {
            let answers = if question(q).1 == 35 {
                vec![
                    naptr(ROOT, 1, 0, "a", SERVICE, "", HOST, 90),
                    naptr(ROOT, 1, 0, "A", "X-3GPP-PGW:X-S2B-GTP", "", HOST, 90),
                    naptr(ROOT, 9, 0, "u", "E2U+sip", "ignored", ".", ttl),
                ]
            } else {
                vec![address(HOST, "192.0.2.1", 90)]
            };
            Some(reply(q, 0, &answers, &[], &[]))
        })
        .await;
        let answer = DnsClient::new(config(dns.address))
            .unwrap()
            .resolve_with_seed(&query(), now, 0)
            .await
            .result
            .unwrap();
        let expiry = if ttl == 1 { 2_000 } else { 1_000 };
        assert_eq!(answer.expires_at(), Some(time(expiry)));
        assert_eq!(answer.candidates()[0].snaptr().unwrap().paths().len(), 1);
        let mut cache = DnsCache::default();
        let token = start(&mut cache, &query(), now());
        assert!(cache.finish_refresh(token, Ok(answer), now()));
        if ttl != 1 {
            let status = cache.lookup(&query().cache_key(), now());
            assert!(matches!(status.result, DnsCachedResult::Stale { .. }));
            assert!(status.retry_at.unwrap() > now());
        }
    }
}

#[tokio::test]
async fn retained_alternate_paths_keep_their_original_observation_and_shorter_expiry() {
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let answers = match (owner.as_str(), kind) {
            (ROOT, 35) => vec![
                naptr(ROOT, 1, 0, "a", SERVICE, "", HOST, 100),
                naptr(ROOT, 2, 0, "", SERVICE, "", CHILD, 100),
            ],
            (CHILD, 35) => vec![naptr(CHILD, 1, 0, "a", SERVICE, "", HOST, 1)],
            (HOST, 1) => vec![address(HOST, "192.0.2.1", 100)],
            _ => panic!("unexpected question"),
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let clock = std::cell::Cell::new(1_000u64);
    let response = DnsClient::new(config(dns.address))
        .unwrap()
        .resolve_with_seed(
            &query(),
            || {
                let at = clock.get();
                clock.set(at + 100);
                time(at)
            },
            0,
        )
        .await;
    let answer = response.result.unwrap();
    let paths = answer.candidates()[0].snaptr().unwrap().paths();
    assert_eq!(paths.len(), 2);
    let primary_address = paths[0].records().last().unwrap();
    assert_eq!(primary_address, paths[1].records().last().unwrap());
    let child = paths[1]
        .records()
        .iter()
        .find(|r| r.owner.as_str() == CHILD)
        .unwrap();
    assert_eq!(
        answer.expires_at(),
        Some(time(child.observed_at.as_millis() + 1_000))
    );
    let mut cache = DnsCache::default();
    let token = start(&mut cache, &query(), now());
    assert!(cache.finish_refresh(token, Ok(answer.clone()), time(clock.get())));
    assert_eq!(
        cache
            .lookup(&query().cache_key(), time(clock.get()))
            .fresh_until,
        answer.expires_at()
    );
    assert_eq!(dns.seen().len(), 3);
}

#[tokio::test]
async fn every_global_work_cap_retains_already_assembled_endpoints() {
    for bound in ["naptr-records", "lookups", "targets", "address-lookups"] {
        for healthy in [true, false] {
            let dns = FakeDns::new(move |q| {
                let (owner, kind, _) = question(q);
                let answers: Vec<Vec<u8>> = if kind == 35 {
                    vec![
                        naptr(
                            ROOT,
                            1,
                            0,
                            if healthy { "a" } else { "u" },
                            SERVICE,
                            "",
                            HOST,
                            60,
                        ),
                        naptr(ROOT, 2, 0, "a", SERVICE, "", OTHER, 60),
                    ]
                } else {
                    vec![address(
                        &owner,
                        if owner == HOST {
                            "192.0.2.1"
                        } else {
                            "192.0.2.2"
                        },
                        60,
                    )]
                };
                Some(reply(q, 0, &answers, &[], &[]))
            })
            .await;
            let mut cfg = config(dns.address);
            cfg.partial_failure_ttl = Duration::from_secs(2);
            match bound {
                "naptr-records" => cfg.max_snaptr_records = 1,
                "lookups" => cfg.max_snaptr_lookups = if healthy { 2 } else { 1 },
                "targets" => cfg.max_srv_targets = 1,
                "address-lookups" => cfg.max_srv_address_lookups = if healthy { 1 } else { 0 },
                _ => unreachable!(),
            }
            let response = DnsClient::new(cfg)
                .unwrap()
                .resolve_with_seed(&query(), now, 0)
                .await;
            if healthy {
                let answer = response.result.unwrap();
                assert_eq!(answer.candidates().len(), 1, "{bound}");
                assert_eq!(
                    answer.candidates()[0].peer().endpoint.to_string(),
                    "192.0.2.1:2123"
                );
                assert!(answer.snaptr_coverage().unwrap().incomplete);
                assert_eq!(answer.expires_at(), Some(time(3_000)));
            } else if bound == "targets" {
                // A semantic refusal performs no target expansion; the one
                // remaining slot is still available to its healthy sibling.
                assert!(response.result.is_ok());
            } else {
                assert_eq!(response.result, Err(DnsError::LimitExceeded), "{bound}");
            }
        }
    }
}

#[tokio::test]
async fn application_only_matches_but_a_child_cannot_switch_protocols() {
    for child_services in [
        "aaa+ap16777264",
        "aaa+ap16777264:diameter.sctp",
        "aaa+ap16777264:diameter.tcp",
    ] {
        let dns = FakeDns::new(move |q| {
            let (owner, kind, _) = question(q);
            let answers = match (owner.as_str(), kind) {
                (REALM, 35) => vec![naptr(REALM, 1, 0, "", "AAA+AP16777264", "", CHILD, 90)],
                (CHILD, 35) => vec![naptr(CHILD, 1, 0, "a", child_services, "", HOST, 90)],
                (HOST, 1) => vec![address(HOST, "192.0.2.1", 90)],
                _ => panic!("unexpected question"),
            };
            Some(reply(q, 0, &answers, &[], &[]))
        })
        .await;
        let q = query_for(REALM, "aaa+ap16777264", "diameter.sctp");
        let response = DnsClient::new(config(dns.address))
            .unwrap()
            .resolve_with_seed(&q, now, 0)
            .await;
        assert_eq!(response.snaptr_root().unwrap().kind, SnaptrRootKind::Match);
        if child_services.ends_with("tcp") && !child_services.ends_with("sctp") {
            assert_eq!(
                response.result,
                Err(DnsError::Snaptr {
                    reason: SnaptrFailure::NoUsablePath,
                    expires_at: None
                })
            );
            assert!(!dns.seen().iter().any(|(_, kind)| *kind == 1));
        } else {
            let answer = response.result.unwrap();
            let hops = answer.candidates()[0].snaptr().unwrap().paths()[0].hops();
            assert!(!hops[0].protocol_advertised());
            assert_eq!(hops[1].protocol_advertised(), child_services.contains(':'));
        }
    }
}

#[tokio::test]
async fn root_classification_precedence_and_malformed_services_are_exact() {
    for (services, reason) in [
        (
            "aaa+ap016777264:diameter.sctp",
            SnaptrNoMatch::ExtendedPresentNoMatch,
        ),
        (
            "aaa+ap4294967296:diameter.sctp",
            SnaptrNoMatch::ExtendedPresentNoMatch,
        ),
        (
            "aaa+ap16777264:diameter.sctp-extra",
            SnaptrNoMatch::ExtendedPresentNoMatch,
        ),
        (
            "aaa+ap16777264::diameter.sctp",
            SnaptrNoMatch::MalformedRequestedService,
        ),
        (
            "aaa+ap16777264:!bad",
            SnaptrNoMatch::MalformedRequestedService,
        ),
    ] {
        let dns = FakeDns::new(move |q| {
            Some(reply(
                q,
                0,
                &[
                    naptr(REALM, 1, 0, "a", services, "", HOST, 90),
                    naptr(REALM, 2, 0, "a", "AAA+D2S", "", OTHER, 90),
                ],
                &[],
                &[],
            ))
        })
        .await;
        let q = query_for(REALM, "aaa+ap16777264", "diameter.sctp");
        let response = DnsClient::new(config(dns.address))
            .unwrap()
            .resolve_with_seed(&q, now, 0)
            .await;
        assert_eq!(
            response.snaptr_root().unwrap().kind,
            SnaptrRootKind::PresentNoMatch(reason)
        );
        let expected = if reason == SnaptrNoMatch::MalformedRequestedService {
            DnsError::Snaptr {
                reason: SnaptrFailure::MalformedService,
                expires_at: None,
            }
        } else {
            DnsError::Snaptr {
                reason: SnaptrFailure::NoMatchingService(reason),
                expires_at: Some(time(91_000)),
            }
        };
        assert_eq!(response.result, Err(expected));
        assert_eq!(dns.seen().len(), 1);
    }
}

#[tokio::test]
async fn abandon_is_per_protocol_and_filters_remain_separate_in_cache() {
    let dns = FakeDns::new(|q| {
        let answers = if question(q).1 == 35 {
            vec![naptr(
                REALM,
                1,
                0,
                "a",
                "aaa+ap16777264:diameter.tcp",
                "",
                HOST,
                90,
            )]
        } else {
            vec![address(HOST, "192.0.2.1", 90)]
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let sctp = query_for(REALM, "aaa+ap16777264", "diameter.sctp");
    let mut input = sctp.input().clone();
    input.transport = PeerTransport::Tcp;
    let tcp = DnsQuery::new(input)
        .unwrap()
        .with_address_family(AddressFamilyPolicy::Ipv4Only)
        .with_snaptr_filter(
            SnaptrFilter::new("aaa+ap16777264", "diameter.tcp", SnaptrOrdering::Rfc3958).unwrap(),
        )
        .unwrap();
    let client = DnsClient::new(config(dns.address)).unwrap();
    let mut cache = DnsCache::default();
    for q in [&sctp, &tcp] {
        let token = start(&mut cache, q, now());
        assert!(cache.finish_refresh(
            token,
            client.resolve_with_seed(q, now, 0).await.result,
            now()
        ));
    }
    assert!(matches!(
        cache.lookup(&sctp.cache_key(), now()).result,
        DnsCachedResult::Negative(DnsError::Snaptr {
            reason: SnaptrFailure::NoMatchingService(SnaptrNoMatch::ExtendedPresentNoMatch),
            ..
        })
    ));
    assert!(matches!(
        cache.lookup(&tcp.cache_key(), now()).result,
        DnsCachedResult::Fresh(_)
    ));
}

#[tokio::test]
async fn cache_validates_alternate_observation_times_and_provenance_identity() {
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let answers = match (owner.as_str(), kind) {
            (ROOT, 35) => vec![
                naptr(ROOT, 1, 0, "a", SERVICE, "", HOST, 100),
                naptr(ROOT, 2, 0, "", SERVICE, "", CHILD, 100),
            ],
            (CHILD, 35) => vec![naptr(CHILD, 1, 0, "a", SERVICE, "", HOST, 100)],
            (HOST, 1) => vec![address(HOST, "192.0.2.1", 100)],
            _ => panic!("unexpected question"),
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let calls = std::cell::Cell::new(0usize);
    let q = query();
    let answer = DnsClient::new(config(dns.address))
        .unwrap()
        .resolve_with_seed(
            &q,
            || {
                let call = calls.get();
                calls.set(call + 1);
                if call < 2 {
                    now()
                } else {
                    time(9_000)
                }
            },
            0,
        )
        .await
        .result
        .unwrap();
    assert!(answer.candidates()[0]
        .records()
        .unwrap()
        .iter()
        .all(|r| r.observed_at <= now()));
    assert!(answer.candidates()[0].snaptr().unwrap().paths()[1]
        .records()
        .iter()
        .any(|r| r.observed_at > now()));
    let mut cache = DnsCache::default();
    let token = start(&mut cache, &q, now());
    assert!(cache.finish_refresh(token, Ok(answer.clone()), now()));
    assert_eq!(
        cache.lookup(&q.cache_key(), now()).last_error,
        Some(DnsError::MalformedAnswer)
    );
    assert!(matches!(
        cache.lookup(&q.cache_key(), now()).result,
        DnsCachedResult::Miss
    ));
    let other = q
        .clone()
        .with_snaptr_filter(
            SnaptrFilter::new("x-other", "x-s2b-gtp", SnaptrOrdering::Rfc3958).unwrap(),
        )
        .unwrap();
    let token = start(&mut cache, &other, time(10_000));
    assert!(cache.finish_refresh(token, Ok(answer), time(10_000)));
    assert_eq!(
        cache.lookup(&other.cache_key(), time(10_000)).last_error,
        Some(DnsError::MalformedAnswer)
    );
}

#[tokio::test]
async fn overlong_address_chain_is_one_branch_refusal_with_its_prefix_ttl() {
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let answers: Vec<Vec<u8>> = if kind == 35 {
            vec![
                naptr(ROOT, 1, 0, "a", SERVICE, "", HOST, 90),
                naptr(ROOT, 2, 0, "a", SERVICE, "", OTHER, 90),
            ]
        } else if owner == HOST {
            vec![address(HOST, "192.0.2.1", 90)]
        } else {
            let mut records = vec![rr(OTHER, 5, 2, &name("alias1.example.invalid."))];
            for i in 1..15 {
                records.push(rr(
                    &format!("alias{i}.example.invalid."),
                    5,
                    90,
                    &name(&format!("alias{}.example.invalid.", i + 1)),
                ));
            }
            for i in 2..=21 {
                records.push(address(
                    "alias15.example.invalid.",
                    &format!("192.0.2.{i}"),
                    90,
                ));
            }
            records
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let mut cfg = config(dns.address);
    cfg.max_snaptr_records = 2;
    cfg.max_snaptr_lookups = 3;
    cfg.edns_payload_size = 4096;
    cfg.partial_failure_ttl = Duration::from_secs(30);
    let response = DnsClient::new(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    let answer = response.result.unwrap();
    assert_eq!(answer.candidates().len(), 1);
    assert_eq!(answer.expires_at(), Some(time(3_000)));
    assert_eq!(answer.snaptr_coverage().unwrap().refused_branches, 1);
    assert_eq!(response.snaptr_branches.len(), 1);
    assert_eq!(
        response.snaptr_branches[0].error,
        DnsError::Snaptr {
            reason: SnaptrFailure::ProvenanceLimit,
            expires_at: None
        }
    );
    assert_eq!(response.snaptr_branches[0].records.len(), 16);
}

#[tokio::test]
async fn host_rank_and_address_references_follow_the_best_retained_endpoint() {
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let (answers, additional) = match (owner.as_str(), kind) {
            (ROOT, 35) => (
                vec![
                    naptr(ROOT, 1, 0, "a", SERVICE, "", HOST, 90),
                    naptr(ROOT, 2, 0, "s", SERVICE, "", CHILD, 90),
                    naptr(ROOT, 3, 0, "a", SERVICE, "", OTHER, 90),
                ],
                vec![],
            ),
            (HOST, 1) => (vec![address(HOST, "192.0.2.1", 90)], vec![]),
            (CHILD, 33) => (
                vec![srv(CHILD, 0, 0, 2123, OTHER, 90)],
                vec![address(OTHER, "192.0.2.2", 90)],
            ),
            (OTHER, 1) => (
                vec![
                    address(OTHER, "192.0.2.1", 90),
                    address(OTHER, "192.0.2.2", 90),
                ],
                vec![],
            ),
            _ => panic!("unexpected question"),
        };
        Some(reply(q, 0, &answers, &[], &additional))
    })
    .await;
    let answer = DnsClient::new(config(dns.address))
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await
        .result
        .unwrap();
    assert_eq!(answer.candidates().len(), 2);
    let other = answer
        .snaptr_hosts()
        .unwrap()
        .iter()
        .find(|host| host.name().as_str() == OTHER)
        .unwrap();
    assert_eq!(other.rank(), 0);
    assert_eq!(
        other
            .addresses()
            .iter()
            .map(SnaptrHostAddress::candidate_index)
            .collect::<Vec<_>>(),
        [0, 1]
    );
    for reference in other.addresses() {
        for index in reference.path_indices() {
            let path = &answer.candidates()[reference.candidate_index()]
                .snaptr()
                .unwrap()
                .paths()[*index];
            assert_eq!(path.terminal_host().as_str(), OTHER);
        }
    }
}

#[tokio::test]
async fn two_node_case_and_alias_cycles_are_refused_but_shared_paths_are_not() {
    for alias in [false, true] {
        let dns = FakeDns::new(move |q| {
            let owner = question(q).0;
            let answers = if owner == ROOT {
                vec![naptr(ROOT, 1, 0, "", SERVICE, "", CHILD, 90)]
            } else if alias {
                vec![
                    rr(CHILD, 5, 90, &name(ROOT)),
                    naptr(ROOT, 1, 0, "a", SERVICE, "", HOST, 90),
                ]
            } else {
                vec![naptr(
                    CHILD,
                    1,
                    0,
                    "",
                    SERVICE,
                    "",
                    &ROOT.to_ascii_uppercase(),
                    90,
                )]
            };
            Some(reply(q, 0, &answers, &[], &[]))
        })
        .await;
        let response = DnsClient::new(config(dns.address))
            .unwrap()
            .resolve_with_seed(&query(), now, 0)
            .await;
        assert_eq!(
            response.result,
            Err(DnsError::Snaptr {
                reason: SnaptrFailure::Loop,
                expires_at: None
            })
        );
        assert_eq!(dns.seen().len(), 2);
    }
}

#[tokio::test]
async fn exact_depth_and_provenance_boundary_includes_terminal_records() {
    for (depth, extra_alias, expected) in [
        (14, false, Ok(())),
        (13, false, Err(SnaptrFailure::DepthLimit)),
        (14, true, Err(SnaptrFailure::ProvenanceLimit)),
    ] {
        let dns = FakeDns::new(move |q| {
            let (owner, kind, _) = question(q);
            let (answers, additional) = match kind {
                35 => {
                    let index = if owner == ROOT {
                        0
                    } else {
                        owner
                            .trim_start_matches("step")
                            .split('.')
                            .next()
                            .unwrap()
                            .parse::<u16>()
                            .unwrap()
                    };
                    let replacement = if index == 13 {
                        "service.example.invalid.".to_owned()
                    } else {
                        format!("step{}.example.invalid.", index + 1)
                    };
                    (
                        vec![naptr(
                            &owner,
                            index,
                            0,
                            if index == 13 { "s" } else { "" },
                            SERVICE,
                            "",
                            &replacement,
                            90,
                        )],
                        vec![],
                    )
                }
                33 => {
                    let mut answers = Vec::new();
                    let service = if extra_alias {
                        "alias-service.example.invalid."
                    } else {
                        "service.example.invalid."
                    };
                    if extra_alias {
                        answers.push(rr(&owner, 5, 90, &name(service)));
                    }
                    answers.push(srv(service, 0, 0, 2123, HOST, 90));
                    (answers, vec![address(HOST, "192.0.2.1", 90)])
                }
                _ => panic!("additional address unexpectedly queried"),
            };
            Some(reply(q, 0, &answers, &[], &additional))
        })
        .await;
        let mut cfg = config(dns.address);
        cfg.max_snaptr_depth = depth;
        let response = DnsClient::new(cfg)
            .unwrap()
            .resolve_with_seed(&query(), now, 0)
            .await;
        match expected {
            Ok(()) => {
                let answer = response.result.unwrap();
                assert_eq!(answer.candidates()[0].records().unwrap().len(), 16);
                assert_eq!(
                    answer.candidates()[0].snaptr().unwrap().paths()[0]
                        .hops()
                        .len(),
                    14
                );
            }
            Err(reason) => assert_eq!(
                response.result,
                Err(DnsError::Snaptr {
                    reason,
                    expires_at: None
                })
            ),
        }
        assert!(dns.seen().len() <= 15);
    }
}

#[tokio::test]
async fn root_transport_failures_never_authorize_absence_fallback() {
    for (rcode, error) in [
        (Some(2), DnsError::ServFail),
        (Some(5), DnsError::Refused),
        (None, DnsError::Timeout),
    ] {
        let dns = FakeDns::new(move |q| rcode.map(|rcode| reply(q, rcode, &[], &[], &[]))).await;
        let mut cfg = config(dns.address);
        cfg.timeout = Duration::from_millis(80);
        let response = DnsClient::new(cfg)
            .unwrap()
            .resolve_with_seed(&query_for(REALM, "aaa+ap16777264", "diameter.sctp"), now, 0)
            .await;
        assert_eq!(response.result, Err(error));
        assert!(response.snaptr_root().is_none());
    }
}

#[tokio::test]
async fn child_timeouts_and_refused_answers_keep_match_without_promoting_the_error() {
    for rcode in [Some(2), Some(5), None] {
        let dns = FakeDns::new(move |q| {
            if question(q).0 == ROOT {
                Some(reply(
                    q,
                    0,
                    &[naptr(ROOT, 1, 0, "", SERVICE, "", CHILD, 90)],
                    &[],
                    &[],
                ))
            } else {
                rcode.map(|rcode| reply(q, rcode, &[], &[], &[]))
            }
        })
        .await;
        let mut cfg = config(dns.address);
        cfg.timeout = Duration::from_millis(80);
        let response = DnsClient::new(cfg)
            .unwrap()
            .resolve_with_seed(&query(), now, 0)
            .await;
        assert_eq!(response.snaptr_root().unwrap().kind, SnaptrRootKind::Match);
        assert_eq!(
            response.result,
            Err(DnsError::Snaptr {
                reason: SnaptrFailure::NoUsablePath,
                expires_at: None
            })
        );
        assert!(response.outcomes[1].result.is_err());
    }
}

#[tokio::test]
async fn root_decision_ttls_aliases_and_absent_soa_never_create_immortal_entries() {
    for ttl in [0, 1, 0x8000_0000] {
        let dns = FakeDns::new(move |q| {
            Some(reply(
                q,
                0,
                &[
                    rr(REALM, 5, ttl, &name(CHILD)),
                    naptr(CHILD, 1, 0, "u", "E2U+sip", "ignored", ".", 60),
                ],
                &[],
                &[],
            ))
        })
        .await;
        let q = query_for(REALM, "aaa+ap16777264", "diameter.sctp");
        let response = DnsClient::new(config(dns.address))
            .unwrap()
            .resolve_with_seed(&q, now, 0)
            .await;
        let expected = if ttl == 1 { time(2_000) } else { now() };
        let error = DnsError::Snaptr {
            reason: SnaptrFailure::NoMatchingService(SnaptrNoMatch::NotAdvertised),
            expires_at: Some(expected),
        };
        assert_eq!(response.result, Err(error));
        let mut cache = DnsCache::default();
        let token = start(&mut cache, &q, now());
        assert!(cache.finish_refresh(token, Err(error), now()));
        let status = cache.lookup(&q.cache_key(), now());
        if ttl == 1 {
            assert_eq!(status.result, DnsCachedResult::Negative(error));
            assert_eq!(status.retry_at, Some(expected));
        } else {
            assert!(matches!(status.result, DnsCachedResult::Miss));
            assert!(status.retry_at.unwrap() > now());
        }
    }
    for authority in [vec![], vec![soa("unrelated.invalid.", 90, 90)]] {
        let dns = FakeDns::new(move |q| Some(reply(q, 0, &[], &authority, &[]))).await;
        let q = query();
        let response = DnsClient::new(config(dns.address))
            .unwrap()
            .resolve_with_seed(&q, now, 0)
            .await;
        assert_eq!(response.result, Err(DnsError::NoData { soa: None }));
        assert_eq!(response.snaptr_root().unwrap().expires_at, None);
        let mut cache = DnsCache::default();
        let token = start(&mut cache, &q, now());
        assert!(cache.finish_refresh(token, response.result, now()));
        assert!(matches!(
            cache.lookup(&q.cache_key(), now()).result,
            DnsCachedResult::Miss
        ));
    }
}

#[tokio::test]
async fn no_match_uses_existing_last_good_fencing_and_clearing_lifecycle() {
    use std::sync::atomic::{AtomicU8, Ordering};
    let phase = Arc::new(AtomicU8::new(0));
    let current = phase.clone();
    let dns = FakeDns::new(move |q| {
        let answers = match (current.load(Ordering::Relaxed), question(q).1) {
            (0, 35) => vec![naptr(
                REALM,
                1,
                0,
                "a",
                "aaa+ap16777264:diameter.sctp",
                "",
                HOST,
                1,
            )],
            (0, 1) => vec![address(HOST, "192.0.2.1", 1)],
            (1, _) => vec![naptr(REALM, 1, 0, "u", "E2U+sip", "ignored", ".", 60)],
            _ => return Some(reply(q, 2, &[], &[], &[])),
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let q = query_for(REALM, "aaa+ap16777264", "diameter.sctp");
    let client = DnsClient::new(config(dns.address)).unwrap();
    let mut cache =
        DnsCache::default().with_ttl_caps(Duration::from_secs(120), Duration::from_secs(10));
    let answer = client.resolve_with_seed(&q, now, 0).await.result.unwrap();
    let token = start(&mut cache, &q, now());
    assert!(cache.finish_refresh(token, Ok(answer.clone()), now()));
    phase.store(1, Ordering::Relaxed);
    let response = client.resolve_with_seed(&q, || time(3_000), 0).await;
    let token = start(&mut cache, &q, time(3_000));
    assert!(cache.finish_refresh(token, response.result, time(3_000)));
    let status = cache.lookup(&q.cache_key(), time(3_000));
    assert!(
        matches!(status.result,DnsCachedResult::Stale{answer:ref retained,..} if retained==&answer)
    );
    assert_eq!(status.retry_at, Some(time(13_000)));
    assert!(matches!(
        status.last_error,
        Some(DnsError::Snaptr {
            reason: SnaptrFailure::NoMatchingService(SnaptrNoMatch::NotAdvertised),
            ..
        })
    ));
    phase.store(2, Ordering::Relaxed);
    let token = start(&mut cache, &q, time(13_000));
    assert!(cache.finish_refresh(
        token,
        client
            .resolve_with_seed(&q, || time(13_000), 0)
            .await
            .result,
        time(13_000)
    ));
    assert_eq!(
        cache.lookup(&q.cache_key(), time(13_000)).last_error,
        Some(DnsError::ServFail)
    );
    let old = start(&mut cache, &q, time(60_000));
    assert!(cache.remove(&q.cache_key()));
    let new = start(&mut cache, &q, time(60_000));
    assert!(!cache.finish_refresh(
        old,
        Err(DnsError::Snaptr {
            reason: SnaptrFailure::NoMatchingService(SnaptrNoMatch::NotAdvertised),
            expires_at: Some(time(90_000))
        }),
        time(60_000)
    ));
    assert!(cache.finish_refresh(new, Err(DnsError::Refused), time(60_000)));
    assert_eq!(
        cache.lookup(&q.cache_key(), time(60_000)).last_error,
        Some(DnsError::Refused)
    );
}

#[tokio::test]
async fn child_negative_and_srv_withdrawal_use_negative_caps_on_partial_answers() {
    for denial in ["soa", "no-soa", "withdrawal"] {
        let dns = FakeDns::new(move |q| {
            let (owner, kind, _) = question(q);
            if owner == CHILD {
                return Some(if denial == "withdrawal" {
                    reply(q, 0, &[srv(CHILD, 0, 0, 0, ".", 7)], &[], &[])
                } else {
                    reply(
                        q,
                        3,
                        &[],
                        &if denial == "soa" {
                            vec![soa("example.invalid.", 30, 7)]
                        } else {
                            vec![]
                        },
                        &[],
                    )
                });
            }
            let answers = if kind == 35 {
                vec![
                    naptr(
                        ROOT,
                        1,
                        0,
                        if denial == "withdrawal" { "s" } else { "" },
                        SERVICE,
                        "",
                        CHILD,
                        90,
                    ),
                    naptr(ROOT, 2, 0, "a", SERVICE, "", HOST, 90),
                ]
            } else {
                vec![address(HOST, "192.0.2.1", 90)]
            };
            Some(reply(q, 0, &answers, &[], &[]))
        })
        .await;
        let mut cfg = config(dns.address);
        cfg.partial_failure_ttl = Duration::from_secs(1);
        let q = query();
        let response = DnsClient::new(cfg)
            .unwrap()
            .resolve_with_seed(&q, now, 0)
            .await;
        let answer = response.result.unwrap();
        assert_eq!(
            answer.expires_at(),
            Some(time(if denial == "no-soa" { 2_000 } else { 8_000 }))
        );
        let mut cache =
            DnsCache::default().with_ttl_caps(Duration::from_secs(120), Duration::from_secs(2));
        let token = start(&mut cache, &q, now());
        assert!(cache.finish_refresh(token, Ok(answer), now()));
        assert_eq!(
            cache.lookup(&q.cache_key(), now()).fresh_until,
            Some(time(if denial == "no-soa" { 2_000 } else { 3_000 }))
        );
    }
}

#[tokio::test]
async fn one_admission_permit_covers_delegation_and_cancellation_releases_it() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let proceed = Arc::new(AtomicBool::new(false));
    let flag = proceed.clone();
    let received = Arc::new(tokio::sync::Notify::new());
    let signal = received.clone();
    let dns = FakeDns::new(move |q| {
        let (owner, kind, _) = question(q);
        if owner == CHILD && !flag.load(Ordering::Relaxed) {
            signal.notify_one();
            return None;
        }
        let answers = match (owner.as_str(), kind) {
            (ROOT, 35) => vec![naptr(ROOT, 1, 0, "", SERVICE, "", CHILD, 90)],
            (CHILD, 35) => vec![naptr(CHILD, 1, 0, "a", SERVICE, "", HOST, 90)],
            (HOST, 1) => vec![address(HOST, "192.0.2.1", 90)],
            _ => panic!("unexpected question"),
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let mut cfg = config(dns.address);
    cfg.timeout = Duration::from_millis(80);
    cfg.max_in_flight = 1;
    let client = DnsClient::new(cfg).unwrap();
    let q = query();
    let mut pending = Box::pin(client.resolve_with_seed(&q, now, 0));
    tokio::select! {_=&mut pending=>panic!("delegation completed unexpectedly"),_=received.notified()=>{},_=tokio::time::sleep(Duration::from_secs(2))=>panic!("no delegated question")}
    assert_eq!(
        client.resolve_with_seed(&q, now, 0).await.result,
        Err(DnsError::Busy)
    );
    drop(pending);
    proceed.store(true, Ordering::Relaxed);
    assert!(client.resolve_with_seed(&q, now, 0).await.result.is_ok());
    assert_eq!(dns.seen().len(), 5);
}

#[tokio::test]
async fn three_gpp_draws_are_weighted_repeatable_and_independent_of_wire_order() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let reverse = Arc::new(AtomicBool::new(false));
    let current = reverse.clone();
    let dns = FakeDns::new(move |q| {
        let (owner, kind, _) = question(q);
        let mut answers = if kind == 35 {
            vec![
                naptr(ROOT, 10, 100, "a", SERVICE, "", HOST, 90),
                naptr(ROOT, 10, 60000, "a", SERVICE, "", OTHER, 90),
                naptr(ROOT, 20, 0, "a", SERVICE, "", "last.example.invalid.", 90),
            ]
        } else {
            vec![address(
                &owner,
                if owner == HOST {
                    "192.0.2.1"
                } else if owner == OTHER {
                    "192.0.2.2"
                } else {
                    "192.0.2.3"
                },
                90,
            )]
        };
        if current.load(Ordering::Relaxed) {
            answers.reverse();
        }
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let q = query()
        .with_snaptr_filter(
            SnaptrFilter::new("x-3gpp-pgw", "x-s2b-gtp", SnaptrOrdering::ThreeGpp).unwrap(),
        )
        .unwrap();
    let mut preferred = 0;
    for seed in 0..128 {
        let mut orders = Vec::new();
        for reversed in [false, true] {
            reverse.store(reversed, Ordering::Relaxed);
            let mut cfg = config(dns.address);
            cfg.max_srv_concurrent_targets = if reversed { 1 } else { 4 };
            let answer = DnsClient::new(cfg)
                .unwrap()
                .resolve_with_seed(&q, now, seed)
                .await
                .result
                .unwrap();
            orders.push(
                answer
                    .candidates()
                    .iter()
                    .map(|c| c.peer().endpoint)
                    .collect::<Vec<_>>(),
            );
        }
        assert_eq!(orders[0], orders[1]);
        assert_eq!(orders[0][2].ip().to_string(), "192.0.2.3");
        preferred += usize::from(orders[0][0].ip().to_string() == "192.0.2.1");
    }
    // A fixed seed corpus exercises both alternatives and strongly prefers
    // weight 65435 over 5535. Sorting preference alone never selects OTHER.
    assert!(
        (100..128).contains(&preferred),
        "preferred first {preferred}/128"
    );
    let rfc = DnsClient::new(config(dns.address))
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await
        .result
        .unwrap();
    assert_eq!(
        rfc.candidates()[0].peer().endpoint.ip().to_string(),
        "192.0.2.1"
    );
}

#[tokio::test]
async fn three_gpp_zero_and_maximum_preferences_keep_zero_weight_alternatives() {
    for first_preference in [0, 65535] {
        let dns = FakeDns::new(move |q| {
            let (owner, kind, _) = question(q);
            let answers = if kind == 35 {
                vec![
                    naptr(ROOT, 1, first_preference, "a", SERVICE, "", HOST, 90),
                    naptr(ROOT, 1, 65535, "a", SERVICE, "", OTHER, 90),
                ]
            } else {
                vec![address(
                    &owner,
                    if owner == HOST {
                        "192.0.2.1"
                    } else {
                        "192.0.2.2"
                    },
                    90,
                )]
            };
            Some(reply(q, 0, &answers, &[], &[]))
        })
        .await;
        let q = query()
            .with_snaptr_filter(
                SnaptrFilter::new("x-3gpp-pgw", "x-s2b-gtp", SnaptrOrdering::ThreeGpp).unwrap(),
            )
            .unwrap();
        let mut first_hosts = std::collections::HashSet::new();
        for seed in 0..16 {
            let answer = DnsClient::new(config(dns.address))
                .unwrap()
                .resolve_with_seed(&q, now, seed)
                .await
                .result
                .unwrap();
            assert_eq!(answer.candidates().len(), 2);
            first_hosts.insert(answer.candidates()[0].peer().endpoint.ip());
        }
        if first_preference == 65535 {
            assert_eq!(first_hosts.len(), 2);
        } else {
            assert_eq!(first_hosts.len(), 1);
            assert!(first_hosts.contains(&"192.0.2.1".parse().unwrap()));
        }
    }
}

#[tokio::test]
async fn cross_response_alias_loop_retains_its_observed_prefix_deadline() {
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let answers = match (owner.as_str(), kind) {
            (ROOT, 35) => vec![
                naptr(ROOT, 1, 0, "", SERVICE, "", CHILD, 90),
                naptr(ROOT, 2, 0, "a", SERVICE, "", HOST, 90),
            ],
            (CHILD, 35) => vec![
                rr(CHILD, 5, 1, &name(ROOT)),
                naptr(ROOT, 1, 0, "a", SERVICE, "", HOST, 90),
            ],
            (HOST, 1) => vec![address(HOST, "192.0.2.1", 90)],
            _ => panic!("unexpected question"),
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let response = DnsClient::new(config(dns.address))
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    assert_eq!(response.result.unwrap().expires_at(), Some(time(2_000)));
    assert!(response.snaptr_branches[0]
        .records
        .iter()
        .any(|r| r.owner.as_str() == CHILD && r.kind == DnsRecordType::Cname));
}

#[tokio::test]
async fn primary_hosts_take_precedence_over_alternate_names_without_dangling_references() {
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let answers: Vec<Vec<u8>> = if kind == 35 {
            (0..32)
                .map(|i| {
                    naptr(
                        ROOT,
                        i,
                        0,
                        "a",
                        SERVICE,
                        "",
                        &format!("host{i}.example.invalid."),
                        90,
                    )
                })
                .collect()
        } else {
            let i = owner
                .trim_start_matches("host")
                .split('.')
                .next()
                .unwrap()
                .parse::<u8>()
                .unwrap();
            vec![address(
                &owner,
                &format!("192.0.2.{}", if i < 16 { 1 } else { i - 14 }),
                90,
            )]
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let mut cfg = config(dns.address);
    cfg.edns_payload_size = 4096;
    cfg.max_srv_targets = 32;
    cfg.partial_failure_ttl = Duration::ZERO;
    let answer = DnsClient::new(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await
        .result
        .unwrap();
    assert_eq!(answer.candidates().len(), 16);
    assert_eq!(answer.snaptr_hosts().unwrap().len(), 16);
    assert_eq!(answer.candidates()[0].snaptr().unwrap().paths().len(), 1);
    let coverage = answer.snaptr_coverage().unwrap();
    // The last host can already be in flight when the endpoint pool fills.
    // Count it as either an unvisited branch or an observed omitted address.
    assert_eq!(coverage.omitted_hosts, 15 + coverage.omitted_addresses);
    assert_eq!(answer.snaptr_coverage().unwrap().omitted_paths, 15);
    assert_eq!(coverage.unvisited_branches + coverage.omitted_addresses, 1);
    assert_eq!(answer.expires_at(), Some(time(91_000)));
    for host in answer.snaptr_hosts().unwrap() {
        assert_eq!(host.addresses().len(), 1);
        let address = &host.addresses()[0];
        assert_eq!(address.path_indices(), [0]);
        assert_eq!(
            answer.candidates()[address.candidate_index()]
                .snaptr()
                .unwrap()
                .paths()[0]
                .terminal_host(),
            host.name()
        );
    }
    assert_eq!(
        answer
            .snaptr_hosts()
            .unwrap()
            .iter()
            .map(|host| host.name().as_str())
            .collect::<Vec<_>>(),
        std::iter::once(0)
            .chain(16..31)
            .map(|i| format!("host{i}.example.invalid."))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn srv_record_budget_is_shared_across_naptr_terminals() {
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let (answers, additional) = match (owner.as_str(), kind) {
            (ROOT, 35) => (
                vec![
                    naptr(ROOT, 1, 0, "s", SERVICE, "", CHILD, 90),
                    naptr(ROOT, 2, 0, "s", SERVICE, "", OTHER, 90),
                ],
                vec![],
            ),
            (CHILD, 33) => (
                vec![srv(CHILD, 1, 3, 1111, HOST, 90)],
                vec![address(HOST, "192.0.2.1", 90)],
            ),
            (OTHER, 33) => (
                vec![srv(OTHER, 1, 9, 2222, "last.example.invalid.", 90)],
                vec![address("last.example.invalid.", "192.0.2.2", 90)],
            ),
            _ => panic!("additional data should avoid address queries"),
        };
        Some(reply(q, 0, &answers, &[], &additional))
    })
    .await;
    let mut cfg = config(dns.address);
    cfg.max_srv_records = 1;
    cfg.max_srv_address_lookups = 0;
    cfg.partial_failure_ttl = Duration::from_secs(2);
    let response = DnsClient::new(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    let answer = response.result.unwrap();
    assert_eq!(answer.candidates().len(), 1);
    assert_eq!(
        answer.candidates()[0].peer().endpoint.to_string(),
        "192.0.2.1:1111"
    );
    assert_eq!(answer.expires_at(), Some(time(3_000)));
    assert_eq!(response.skipped_srv_records, 1);
    assert!(response
        .snaptr_branches
        .iter()
        .any(|b| b.error == DnsError::LimitExceeded));
    assert_eq!(dns.seen().len(), 3);
}

#[tokio::test]
async fn srv_target_alias_rejects_earlier_family_data_and_keeps_other_branches() {
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let (answers, additional) = match (owner.as_str(), kind) {
            (ROOT, 35) => (
                vec![
                    naptr(ROOT, 1, 0, "s", SERVICE, "", CHILD, 90),
                    naptr(ROOT, 2, 0, "a", SERVICE, "", OTHER, 90),
                ],
                vec![],
            ),
            (CHILD, 33) => (
                vec![srv(CHILD, 0, 0, 2123, HOST, 90)],
                vec![address(HOST, "192.0.2.1", 90)],
            ),
            (HOST, 28) => (
                vec![
                    rr(HOST, 5, 90, &name("alias.example.invalid.")),
                    address("alias.example.invalid.", "2001:db8::1", 90),
                ],
                vec![],
            ),
            (OTHER, 1) => (vec![address(OTHER, "192.0.2.2", 90)], vec![]),
            (OTHER, 28) => (vec![address(OTHER, "2001:db8::2", 90)], vec![]),
            _ => panic!("unexpected question {owner} {kind}"),
        };
        Some(reply(q, 0, &answers, &[], &additional))
    })
    .await;
    let response = DnsClient::new(config(dns.address))
        .unwrap()
        .resolve_with_seed(
            &query().with_address_family(AddressFamilyPolicy::DualStack),
            now,
            0,
        )
        .await;
    let answer = response.result.unwrap();
    assert_eq!(answer.candidates().len(), 2);
    assert!(answer
        .candidates()
        .iter()
        .all(|c| c.peer().endpoint.ip().to_string().ends_with('2')));
    assert!(response
        .outcomes
        .iter()
        .filter(|o| o.owner.as_str() == HOST)
        .all(|o| o.result == Err(DnsError::MalformedAnswer)));
    assert_eq!(answer.snaptr_coverage().unwrap().failed_branches, 1);
}

#[tokio::test]
async fn snaptr_reuses_edns_retry_tcp_fallback_and_concrete_source_binding() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (listener, socket) = support::bind_dns_pair(listener).await.unwrap();
    let server = socket.local_addr().unwrap();
    let udp = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        for i in 0..3 {
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            assert_eq!(peer.ip().to_string(), "127.0.0.2");
            let q = &buffer[..len];
            let response = match i {
                0 => {
                    assert_eq!(question(q).1, 35);
                    assert_eq!(q[11], 1);
                    reply(q, 1, &[], &[], &[])
                }
                1 => {
                    assert_eq!(question(q).1, 35);
                    assert_eq!(q[11], 0);
                    let mut truncated = reply(q, 0, &[], &[], &[]);
                    truncated[2] |= 2;
                    truncated
                }
                _ => {
                    assert_eq!(question(q).1, 1);
                    reply(q, 0, &[address(HOST, "192.0.2.1", 90)], &[], &[])
                }
            };
            socket.send_to(&response, peer).await.unwrap();
        }
    });
    let tcp = tokio::spawn(async move {
        let (mut stream, peer) = listener.accept().await.unwrap();
        assert_eq!(peer.ip().to_string(), "127.0.0.2");
        let len = stream.read_u16().await.unwrap();
        let mut q = vec![0; usize::from(len)];
        stream.read_exact(&mut q).await.unwrap();
        assert_eq!(question(&q).1, 35);
        let response = reply(
            &q,
            0,
            &[naptr(ROOT, 1, 0, "a", SERVICE, "", HOST, 90)],
            &[],
            &[],
        );
        stream.write_u16(response.len() as u16).await.unwrap();
        stream.write_all(&response).await.unwrap();
    });
    let mut cfg = config(server);
    cfg.local_address = Some("127.0.0.2".parse().unwrap());
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        DnsClient::new(cfg)
            .unwrap()
            .resolve_with_seed(&query(), now, 0),
    )
    .await
    .unwrap();
    assert!(response.result.is_ok());
    assert_eq!(response.sources[0].record_type, DnsRecordType::Naptr);
    assert_eq!(response.sources[0].transport, DnsTransport::Tcp);
    assert_eq!(response.sources[1].record_type, DnsRecordType::A);
    assert_eq!(response.sources[1].transport, DnsTransport::Udp);
    udp.await.unwrap();
    tcp.await.unwrap();
}

#[tokio::test]
async fn secure_service_port_is_configured_and_raw_service_strings_are_redacted() {
    let dns = FakeDns::new(|q| {
        let answers = if question(q).1 == 35 {
            vec![naptr(
                REALM,
                1,
                0,
                "a",
                "aaa+ap16777264:diameter.tls.tcp",
                "",
                HOST,
                90,
            )]
        } else {
            vec![address(HOST, "192.0.2.1", 90)]
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let mut input = query_for(REALM, "aaa+ap16777264", "diameter.tls.tcp")
        .input()
        .clone();
    input.transport = PeerTransport::Tcp;
    input.default_port = Some(5658);
    let q = DnsQuery::new(input)
        .unwrap()
        .with_address_family(AddressFamilyPolicy::Ipv4Only)
        .with_snaptr_filter(
            SnaptrFilter::new(
                "aaa+ap16777264",
                "diameter.tls.tcp",
                SnaptrOrdering::Rfc3958,
            )
            .unwrap(),
        )
        .unwrap();
    let response = DnsClient::new(config(dns.address))
        .unwrap()
        .resolve_with_seed(&q, now, 0)
        .await;
    let answer = response.result.as_ref().unwrap();
    assert_eq!(
        answer.candidates()[0].peer().endpoint.to_string(),
        "192.0.2.1:5658"
    );
    let debug = format!(
        "{response:?} {q:?} {:?} {:?} {:?}",
        q.snaptr_filter(),
        answer.snaptr_hosts(),
        answer.candidates()[0].snaptr()
    );
    for raw in [
        REALM,
        HOST,
        "192.0.2.1",
        "aaa+ap16777264",
        "diameter.tls.tcp",
    ] {
        assert!(!debug.contains(raw), "leaked {raw}");
    }
}

#[tokio::test]
async fn omitted_srv_targets_are_distinct_and_counted_when_the_endpoint_cap_stops_work() {
    for candidate_cap in [false, true] {
        let dns = FakeDns::new(move |q| {
            let (answers, additional) = if question(q).1 == 35 {
                (vec![naptr(ROOT, 1, 0, "s", SERVICE, "", CHILD, 90)], vec![])
            } else {
                (
                    vec![
                        srv(CHILD, 0, 0, 2123, HOST, 90),
                        srv(CHILD, 1, 0, 1111, OTHER, 90),
                        srv(CHILD, 2, 0, 2222, OTHER, 90),
                    ],
                    (1..=if candidate_cap { 16 } else { 1 })
                        .map(|i| address(HOST, &format!("192.0.2.{i}"), 90))
                        .collect(),
                )
            };
            Some(reply(q, 0, &answers, &[], &additional))
        })
        .await;
        let mut cfg = config(dns.address);
        cfg.edns_payload_size = 4096;
        cfg.max_srv_targets = 1;
        cfg.max_srv_address_lookups = 0;
        let response = DnsClient::new(cfg)
            .unwrap()
            .resolve_with_seed(&query(), now, 0)
            .await;
        let answer = response.result.unwrap();
        assert_eq!(
            answer.candidates().len(),
            if candidate_cap { 16 } else { 1 }
        );
        assert_eq!(response.skipped_srv_records, 2);
        assert_eq!(response.skipped_srv_targets, 1);
        assert_eq!(answer.snaptr_coverage().unwrap().unexpanded_srv_records, 2);
        assert_eq!(answer.snaptr_coverage().unwrap().unexpanded_srv_targets, 1);
    }
}

#[tokio::test]
async fn unexpanded_known_host_path_marks_the_retained_host_incomplete() {
    let dns = FakeDns::new(|q| {
        let answers = if question(q).1 == 35 {
            vec![
                naptr(ROOT, 1, 0, "a", SERVICE, "", HOST, 90),
                naptr(ROOT, 2, 0, "a", SERVICE, "", HOST, 90),
            ]
        } else {
            vec![address(HOST, "192.0.2.1", 90)]
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let mut cfg = config(dns.address);
    cfg.max_snaptr_records = 1;
    let answer = DnsClient::new(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await
        .result
        .unwrap();
    assert_eq!(answer.snaptr_hosts().unwrap().len(), 1);
    assert!(!answer.snaptr_hosts().unwrap()[0].complete());
    assert_eq!(answer.snaptr_coverage().unwrap().unexpanded_records, 1);
}

#[tokio::test]
async fn bounded_branch_trace_keeps_all_failure_counts_in_cached_coverage() {
    let dns = FakeDns::new(|q| {
        let (answers, additional) = if question(q).1 == 35 {
            (vec![naptr(ROOT, 1, 0, "s", SERVICE, "", CHILD, 90)], vec![])
        } else {
            let mut additional = (0..5)
                .map(|i| rr(&format!("alias{i}.example.invalid."), 5, 90, &name(OTHER)))
                .collect::<Vec<_>>();
            additional.push(address(HOST, "192.0.2.1", 90));
            (
                (0..5)
                    .map(|i| srv(CHILD, i, 0, 2123, &format!("alias{i}.example.invalid."), 90))
                    .chain(std::iter::once(srv(CHILD, 5, 0, 2123, HOST, 90)))
                    .collect(),
                additional,
            )
        };
        Some(reply(q, 0, &answers, &[], &additional))
    })
    .await;
    let mut cfg = config(dns.address);
    cfg.edns_payload_size = 4096;
    cfg.max_snaptr_records = 1;
    cfg.max_snaptr_lookups = 3;
    let q = query();
    let response = DnsClient::new(cfg)
        .unwrap()
        .resolve_with_seed(&q, now, 0)
        .await;
    assert_eq!(response.snaptr_branches.len(), 3);
    let answer = response.result.unwrap();
    assert_eq!(answer.snaptr_coverage().unwrap().failed_branches, 5);
    assert_eq!(answer.snaptr_coverage().unwrap().omitted_branch_outcomes, 2);
    let mut cache = DnsCache::default();
    let token = start(&mut cache, &q, now());
    assert!(cache.finish_refresh(token, Ok(answer), now()));
    let DnsCachedResult::Fresh(answer) = cache.lookup(&q.cache_key(), now()).result else {
        panic!("lost cached partial answer")
    };
    assert_eq!(answer.snaptr_coverage().unwrap().failed_branches, 5);
    assert_eq!(answer.snaptr_coverage().unwrap().omitted_branch_outcomes, 2);
}

#[tokio::test]
async fn every_chain_position_keeps_its_absolute_ttl_across_staggered_observations() {
    for shortest in 0..4 {
        let dns = FakeDns::new(move |q| {
            let (owner, kind, _) = question(q);
            let ttl = |position| if shortest == position { 1 } else { 90 };
            let answers = match (owner.as_str(), kind) {
                (ROOT, 35) => vec![naptr(ROOT, 1, 0, "", SERVICE, "", CHILD, ttl(0))],
                (CHILD, 35) => vec![naptr(
                    CHILD,
                    1,
                    0,
                    "s",
                    SERVICE,
                    "",
                    "service.example.invalid.",
                    ttl(1),
                )],
                ("service.example.invalid.", 33) => {
                    vec![srv("service.example.invalid.", 0, 0, 2123, HOST, ttl(2))]
                }
                (HOST, 1) => vec![address(HOST, "192.0.2.1", ttl(3))],
                _ => panic!("unexpected question"),
            };
            Some(reply(q, 0, &answers, &[], &[]))
        })
        .await;
        let clock = std::cell::Cell::new(0u64);
        let q = query();
        let answer = DnsClient::new(config(dns.address))
            .unwrap()
            .resolve_with_seed(
                &q,
                || {
                    clock.set(clock.get() + 1_000);
                    time(clock.get())
                },
                0,
            )
            .await
            .result
            .unwrap();
        assert_eq!(
            answer.candidates()[0]
                .records()
                .unwrap()
                .iter()
                .map(|r| r.observed_at.as_millis())
                .collect::<Vec<_>>(),
            [1_000, 2_000, 3_000, 4_000]
        );
        assert_eq!(answer.expires_at(), Some(time((shortest + 2) * 1_000)));
        let mut cache = DnsCache::default();
        let token = start(&mut cache, &q, time(clock.get()));
        assert!(cache.finish_refresh(token, Ok(answer), time(clock.get())));
        assert!(matches!(
            cache.lookup(&q.cache_key(), time(clock.get())).result,
            DnsCachedResult::Stale { .. }
        ));
    }
}

#[tokio::test]
async fn relay_only_realm_is_a_match_and_never_a_no_match_fallback_decision() {
    for services in ["aaa+ap4294967295:diameter.sctp", "aaa+ap4294967295"] {
        let dns = FakeDns::new(move |q| {
            let answers = if question(q).1 == 35 {
                vec![naptr(REALM, 1, 0, "a", services, "", HOST, 90)]
            } else {
                vec![address(HOST, "192.0.2.1", 90)]
            };
            Some(reply(q, 0, &answers, &[], &[]))
        })
        .await;
        let response = DnsClient::new(config(dns.address))
            .unwrap()
            .resolve_with_seed(&query_for(REALM, "aaa+ap16777264", "diameter.sctp"), now, 0)
            .await;
        assert_eq!(response.snaptr_root().unwrap().kind, SnaptrRootKind::Match);
        assert_eq!(response.result.unwrap().candidates().len(), 1);
    }
}
