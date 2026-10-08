//! Independent RFC 2782/RFC 1035 loopback fixtures. No production wire helpers.

mod support;

use std::cell::Cell;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use opc_peer_discovery::{
    AddressFamilyPolicy, DiscoveryTarget, DnsCache, DnsCachedResult, DnsClient, DnsClientConfig,
    DnsError, DnsQuery, DnsRecordType, DnsRefresh, PeerCandidateSource, PeerDiscoveryTime,
    PeerLabel, PeerTransport, ServiceDiscoveryInput, ServiceDiscoveryMode,
};
use support::bind_dns_pair;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

const SERVICE: &str = "_svc._tcp.example.invalid.";
const FIRST: &str = "one.example.invalid.";
const SECOND: &str = "two.example.invalid.";
const THIRD: &str = "three.example.invalid.";

fn now() -> PeerDiscoveryTime {
    PeerDiscoveryTime::from_millis(1_000)
}

fn query() -> DnsQuery {
    DnsQuery::new(ServiceDiscoveryInput::new(
        PeerLabel::new("test").unwrap(),
        DiscoveryTarget::new(SERVICE),
        ServiceDiscoveryMode::Service,
        PeerTransport::Tcp,
        Some(9999),
    ))
    .unwrap()
    .with_address_family(AddressFamilyPolicy::Ipv4Only)
}

fn config(server: SocketAddr) -> DnsClientConfig {
    let mut value = DnsClientConfig::default();
    value.servers = vec![server];
    value.timeout = Duration::from_millis(300);
    value.attempts = 1;
    value
}

fn name(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for label in value
        .trim_end_matches('.')
        .split('.')
        .filter(|s| !s.is_empty())
    {
        bytes.push(u8::try_from(label.len()).unwrap());
        bytes.extend(label.as_bytes());
    }
    bytes.push(0);
    bytes
}

fn question(q: &[u8]) -> (String, u16, usize) {
    let mut at = 12;
    let mut text = String::new();
    while q[at] != 0 {
        let len = usize::from(q[at]);
        text.push_str(std::str::from_utf8(&q[at + 1..at + 1 + len]).unwrap());
        text.push('.');
        at += 1 + len;
    }
    (text, u16::from_be_bytes([q[at + 1], q[at + 2]]), at + 5)
}

fn rr(owner: &str, kind: u16, ttl: u32, data: &[u8]) -> Vec<u8> {
    let mut bytes = name(owner);
    bytes.extend(kind.to_be_bytes());
    bytes.extend(1u16.to_be_bytes());
    bytes.extend(ttl.to_be_bytes());
    bytes.extend(u16::try_from(data.len()).unwrap().to_be_bytes());
    bytes.extend(data);
    bytes
}

fn srv(owner: &str, priority: u16, weight: u16, port: u16, target: &str, ttl: u32) -> Vec<u8> {
    let mut data = Vec::new();
    for value in [priority, weight, port] {
        data.extend(value.to_be_bytes());
    }
    data.extend(name(target));
    rr(owner, 33, ttl, &data)
}

fn address(owner: &str, ip: &str, ttl: u32) -> Vec<u8> {
    match ip.parse::<IpAddr>().unwrap() {
        IpAddr::V4(ip) => rr(owner, 1, ttl, &ip.octets()),
        IpAddr::V6(ip) => rr(owner, 28, ttl, &ip.octets()),
    }
}

fn soa() -> Vec<u8> {
    let mut data = name("ns.example.invalid.");
    data.extend(name("hostmaster.example.invalid."));
    for value in [1u32, 2, 3, 4, 7] {
        data.extend(value.to_be_bytes());
    }
    rr("example.invalid.", 6, 20, &data)
}

fn reply(
    q: &[u8],
    rcode: u16,
    answers: &[Vec<u8>],
    authority: &[Vec<u8>],
    additional: &[Vec<u8>],
) -> Vec<u8> {
    let mut bytes = q[..question(q).2].to_vec();
    bytes[2..4].copy_from_slice(&(0x8180 | rcode).to_be_bytes());
    for (offset, records) in [(6, answers), (8, authority), (10, additional)] {
        bytes[offset..offset + 2]
            .copy_from_slice(&u16::try_from(records.len()).unwrap().to_be_bytes());
    }
    for record in answers.iter().chain(authority).chain(additional) {
        bytes.extend(record);
    }
    bytes
}

async fn server<F>(count: usize, respond: F) -> (Arc<UdpSocket>, JoinHandle<()>)
where
    F: Fn(usize, &[u8]) -> Vec<u8> + Send + 'static,
{
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let task_socket = socket.clone();
    let task = tokio::spawn(async move {
        let mut buffer = [0; 8192];
        for i in 0..count {
            let (len, peer) =
                tokio::time::timeout(Duration::from_secs(3), task_socket.recv_from(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
            task_socket
                .send_to(&respond(i, &buffer[..len]), peer)
                .await
                .unwrap();
        }
    });
    (socket, task)
}

#[tokio::test]
async fn dns_port_pair_reallocates_when_the_udp_port_is_occupied() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (listener, occupied_udp) = bind_dns_pair(listener).await.unwrap();
    let occupied_address = occupied_udp.local_addr().unwrap();

    let (replacement, socket) = bind_dns_pair(listener).await.unwrap();
    let replacement_address = replacement.local_addr().unwrap();
    assert_ne!(replacement_address, occupied_address);
    assert_eq!(socket.local_addr().unwrap(), replacement_address);
    // The conflict remains held: success must come from allocating another pair.
    assert_eq!(occupied_udp.local_addr().unwrap(), occupied_address);
}

#[tokio::test]
async fn additional_data_preserves_priority_port_provenance_and_ttl() {
    let (socket, task) = server(1, |_, q| {
        assert_eq!((question(q).0.as_str(), question(q).1), (SERVICE, 33));
        reply(
            q,
            0,
            &[
                srv(SERVICE, 20, 65_535, 9090, SECOND, 120),
                srv(SERVICE, 5, 1, 8080, FIRST, 60),
            ],
            &[],
            &[
                address(SECOND, "192.0.2.2", 90),
                address(SECOND, "2001:db8::2", 90),
                address(FIRST, "192.0.2.1", 10),
                address(FIRST, "2001:db8::1", 30),
                address("unrelated.invalid.", "192.0.2.99", 1),
            ],
        )
    })
    .await;
    let q = query().with_address_family(AddressFamilyPolicy::DualStack);
    let mut cfg = config(socket.local_addr().unwrap());
    cfg.max_srv_address_lookups = 0;
    let response = DnsClient::new(cfg)
        .unwrap()
        .resolve_with_seed(&q, now, 7)
        .await;
    assert_eq!(response.sources.len(), 1);
    assert_eq!(response.sources[0].record_type, DnsRecordType::Srv);
    assert_eq!(response.sources[0].owner.as_str(), SERVICE);
    assert_eq!(response.outcomes.len(), 5);
    assert!(response
        .outcomes
        .iter()
        .all(|outcome| outcome.result.is_ok()));
    assert_eq!(response.outcomes[0].record_type, DnsRecordType::Srv);
    assert_eq!(response.outcomes[1].owner.as_str(), FIRST);
    assert_eq!(response.outcomes[1].record_type, DnsRecordType::A);
    assert_eq!(response.outcomes[2].record_type, DnsRecordType::Aaaa);
    let answer = response.result.unwrap();
    let endpoints: Vec<_> = answer
        .candidates()
        .iter()
        .map(|c| c.peer().endpoint.to_string())
        .collect();
    assert_eq!(
        endpoints,
        [
            "[2001:db8::1]:8080",
            "192.0.2.1:8080",
            "[2001:db8::2]:9090",
            "192.0.2.2:9090"
        ]
    );
    for (i, candidate) in answer.candidates().iter().enumerate() {
        assert_eq!(candidate.peer().priority, if i < 2 { 5 } else { 20 });
        assert_eq!(
            candidate.peer().source,
            PeerCandidateSource::Resolver(ServiceDiscoveryMode::Service)
        );
        let chain = candidate.records().unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].kind, DnsRecordType::Srv);
        assert_eq!(chain[0].ttl, 60); // Whole SRV RRset minimum, not wire order.
        assert_eq!(chain[0].observed_at, now());
        assert_eq!(chain[1].observed_at, now());
    }
    assert_eq!(
        answer.expires_at(),
        Some(PeerDiscoveryTime::from_millis(11_000))
    );
    let mut cache =
        DnsCache::default().with_ttl_caps(Duration::from_secs(5), Duration::from_secs(5));
    let DnsRefresh::Start(token) = cache
        .begin_refresh(&q, now(), Duration::from_secs(1))
        .unwrap()
    else {
        panic!("admission")
    };
    assert!(cache.finish_refresh(token, Ok(answer), now()));
    assert_eq!(
        cache.lookup(&q.cache_key(), now()).fresh_until,
        Some(PeerDiscoveryTime::from_millis(6_000))
    );
    task.await.unwrap();
    assert!(socket.try_recv_from(&mut [0; 512]).is_err());
}

#[tokio::test]
async fn missing_additional_queries_both_families_without_restarting_srv_ttl() {
    let (socket, task) = server(3, |i, q| {
        let (owner, kind, _) = question(q);
        if i == 0 {
            assert_eq!((owner.as_str(), kind), (SERVICE, 33));
            reply(q, 0, &[srv(SERVICE, 0, 0, 443, FIRST, 2)], &[], &[])
        } else {
            assert_eq!(owner, FIRST);
            assert_eq!(kind, if i == 1 { 1 } else { 28 });
            reply(
                q,
                0,
                &[address(
                    FIRST,
                    if kind == 1 {
                        "192.0.2.1"
                    } else {
                        "2001:db8::1"
                    },
                    120,
                )],
                &[],
                &[],
            )
        }
    })
    .await;
    let clock = Cell::new(1_000);
    let response = DnsClient::new(config(socket.local_addr().unwrap()))
        .unwrap()
        .resolve_with_seed(
            &query().with_address_family(AddressFamilyPolicy::DualStack),
            || {
                let value = clock.get();
                clock.set(value + 1_000);
                PeerDiscoveryTime::from_millis(value)
            },
            7,
        )
        .await;
    assert_eq!(response.sources.len(), 3);
    assert_eq!(response.sources[1].owner.as_str(), FIRST);
    assert_eq!(response.sources[2].owner.as_str(), FIRST);
    let answer = response.result.unwrap();
    assert_eq!(
        answer.expires_at(),
        Some(PeerDiscoveryTime::from_millis(3_000))
    );
    for candidate in answer.candidates() {
        let chain = candidate.records().unwrap();
        assert_eq!(chain[0].observed_at, now());
        assert_eq!(
            chain[1].observed_at.as_millis(),
            if candidate.peer().endpoint.is_ipv4() {
                2_000
            } else {
                3_000
            }
        );
    }
    task.await.unwrap();
}

#[tokio::test]
async fn partial_additional_queries_missing_family_once_for_repeated_targets() {
    let (socket, task) = server(2, |i, q| {
        if i == 0 {
            reply(
                q,
                0,
                &[
                    srv(SERVICE, 0, 1, 443, FIRST, 60),
                    srv(SERVICE, 1, 1, 8443, FIRST, 60),
                ],
                &[],
                &[address(FIRST, "192.0.2.1", 30)],
            )
        } else {
            assert_eq!((question(q).0.as_str(), question(q).1), (FIRST, 28));
            reply(q, 0, &[address(FIRST, "2001:db8::1", 40)], &[], &[])
        }
    })
    .await;
    let mut cfg = config(socket.local_addr().unwrap());
    cfg.max_srv_address_lookups = 1;
    let response = DnsClient::new(cfg)
        .unwrap()
        .resolve_with_seed(
            &query().with_address_family(AddressFamilyPolicy::DualStack),
            now,
            42,
        )
        .await;
    let answer = response.result.unwrap();
    assert_eq!(answer.candidates().len(), 4);
    assert_eq!(
        answer
            .candidates()
            .iter()
            .map(|c| c.peer().endpoint.port())
            .collect::<Vec<_>>(),
        [443, 443, 8443, 8443]
    );
    assert_eq!(response.sources.len(), 2);
    assert_eq!(response.outcomes.len(), 3); // One entry per family, not per port.
    task.await.unwrap();
    assert!(socket.try_recv_from(&mut [0; 512]).is_err());
}

#[tokio::test]
async fn partial_target_family_results_bound_freshness_and_expose_each_failure() {
    for failed_kind in [1, 28] {
        for additional in [false, true] {
            for case in 0..7 {
                let (socket, task) = server(if additional { 2 } else { 3 }, move |_, q| {
                    let (owner, kind, _) = question(q);
                    let healthy_ip = if failed_kind == 1 {
                        "2001:db8::1"
                    } else {
                        "192.0.2.1"
                    };
                    if kind == 33 {
                        reply(
                            q,
                            0,
                            &[srv(SERVICE, 0, 0, 443, FIRST, 3600)],
                            &[],
                            &if additional {
                                vec![address(FIRST, healthy_ip, 3600)]
                            } else {
                                vec![]
                            },
                        )
                    } else {
                        assert_eq!(owner, FIRST);
                        if kind != failed_kind {
                            reply(q, 0, &[address(FIRST, healthy_ip, 3600)], &[], &[])
                        } else {
                            let mut bytes = reply(
                                q,
                                match case {
                                    0 | 5 => 2,
                                    1 => 5,
                                    2 => 3,
                                    _ => 0,
                                },
                                &[],
                                &if matches!(case, 2 | 3) {
                                    vec![soa()]
                                } else {
                                    vec![]
                                },
                                &[],
                            );
                            if case == 6 {
                                bytes[0] ^= 1; // Drop this unmatched reply, then time out.
                            }
                            bytes
                        }
                    }
                })
                .await;
                let mut cfg = config(socket.local_addr().unwrap());
                cfg.timeout = if case == 6 {
                    Duration::from_millis(500)
                } else {
                    Duration::from_secs(2)
                };
                // Only the exchange timeout is under test, not the refresh deadline.
                cfg.srv_refresh_timeout = Duration::from_secs(10);
                if case == 4 {
                    cfg.partial_failure_ttl = Duration::from_secs(17);
                }
                if case == 5 {
                    cfg.partial_failure_ttl = Duration::ZERO;
                }
                let q = query().with_address_family(AddressFamilyPolicy::DualStack);
                let response = DnsClient::new(cfg)
                    .unwrap()
                    .resolve_with_seed(&q, now, 7)
                    .await;
                let answer = response.result.unwrap_or_else(|error| {
                    panic!("family {failed_kind}, additional {additional}, case {case}: {error:?}")
                });
                let seconds = match case {
                    2 | 3 => 7,
                    4 => 17,
                    5 => 0,
                    _ => 300,
                };
                let deadline = PeerDiscoveryTime::from_millis(1_000 + seconds * 1_000);
                assert_eq!(
                    answer.expires_at(),
                    Some(deadline),
                    "family {failed_kind}, additional {additional}, case {case}"
                );
                assert_eq!(answer.candidates().len(), 1);
                assert!(answer.candidates()[0]
                    .records()
                    .unwrap()
                    .iter()
                    .all(|record| record.ttl == 3600));
                assert_eq!(response.outcomes.len(), 3);
                assert_eq!(response.outcomes[0].record_type, DnsRecordType::Srv);
                assert!(response.outcomes[0].result.is_ok());
                let failed_type = if failed_kind == 1 {
                    DnsRecordType::A
                } else {
                    DnsRecordType::Aaaa
                };
                let failed = response
                    .outcomes
                    .iter()
                    .find(|outcome| outcome.record_type == failed_type)
                    .unwrap();
                assert_eq!(failed.owner.as_str(), FIRST);
                assert_eq!(failed.observed_at, now());
                assert!(matches!(
                    (case, failed.result),
                    (0 | 5, Err(DnsError::ServFail))
                        | (1, Err(DnsError::Refused))
                        | (2, Err(DnsError::NxDomain { soa: Some(_) }))
                        | (3, Err(DnsError::NoData { soa: Some(_) }))
                        | (4, Err(DnsError::NoData { soa: None }))
                        | (6, Err(DnsError::Timeout))
                ));
                assert_eq!(
                    response
                        .outcomes
                        .iter()
                        .filter(|outcome| outcome.result.is_ok())
                        .count(),
                    2
                );
                let mut cache = DnsCache::default();
                let DnsRefresh::Start(token) = cache
                    .begin_refresh(&q, now(), Duration::from_secs(1))
                    .unwrap()
                else {
                    panic!("admission")
                };
                assert!(cache.finish_refresh(token, Ok(answer), now()));
                assert_eq!(
                    cache.lookup(&q.cache_key(), now()).fresh_until,
                    Some(deadline)
                );
                task.await.unwrap();
            }
        }
    }
}

#[tokio::test]
async fn unusable_targets_bound_other_targets_without_inventing_negative_authority() {
    for case in 0..3 {
        let (socket, task) = server(1, move |_, q| {
            let mut additional = vec![address(
                SECOND,
                if case == 2 {
                    "2001:db8::2"
                } else {
                    "192.0.2.2"
                },
                3600,
            )];
            match case {
                0 => additional.push(rr(FIRST, 5, 3600, &name(THIRD))),
                2 => additional.push(address(FIRST, "::ffff:192.0.2.1", 3600)),
                _ => {}
            }
            reply(
                q,
                0,
                &[
                    srv(SERVICE, 0, 0, 443, FIRST, 3600),
                    srv(SERVICE, 1, 0, 443, SECOND, 3600),
                ],
                &[],
                &additional,
            )
        })
        .await;
        let mut cfg = config(socket.local_addr().unwrap());
        cfg.max_srv_address_lookups = 0;
        let q = if case == 2 {
            query().with_address_family(AddressFamilyPolicy::Ipv6Only)
        } else {
            query()
        };
        let response = DnsClient::new(cfg)
            .unwrap()
            .resolve_with_seed(&q, now, 3)
            .await;
        let answer = response.result.unwrap();
        assert_eq!(answer.candidates().len(), 1);
        assert_eq!(answer.candidates()[0].peer().priority, 1);
        assert_eq!(
            answer.expires_at(),
            Some(PeerDiscoveryTime::from_millis(301_000))
        );
        assert_eq!(response.outcomes.len(), 3);
        assert_eq!(response.outcomes[1].owner.as_str(), FIRST);
        assert_eq!(
            response.outcomes[1].result,
            Err(match case {
                0 => DnsError::MalformedAnswer,
                1 => DnsError::LimitExceeded,
                _ => DnsError::Unavailable,
            })
        );
        assert_eq!(response.outcomes[2].result, Ok(()));
        task.await.unwrap();
        assert!(socket.try_recv_from(&mut [0; 512]).is_err());
    }
}

#[tokio::test]
async fn fixed_seed_weight_distribution_respects_priority_and_wire_order_independence() {
    const SAMPLES: usize = 2_000;
    let (socket, task) = server(2 * SAMPLES + 2, |i, q| {
        let mut records = vec![
            srv(SERVICE, 0, 1_000, 1001, FIRST, 60),
            srv(SERVICE, 0, 3_000, 1002, SECOND, 60),
            srv(SERVICE, 10, 65_535, 1003, THIRD, 60),
        ];
        if i % 2 != 0 {
            records.reverse();
        }
        reply(
            q,
            0,
            &records,
            &[],
            &[
                address(FIRST, "192.0.2.1", 60),
                address(SECOND, "192.0.2.2", 60),
                address(THIRD, "192.0.2.3", 60),
            ],
        )
    })
    .await;
    let client = DnsClient::new(config(socket.local_addr().unwrap())).unwrap();
    let first = client
        .resolve_with_seed(&query(), now, 99)
        .await
        .result
        .unwrap();
    let repeated = client
        .resolve_with_seed(&query(), now, 99)
        .await
        .result
        .unwrap();
    assert_eq!(first, repeated);
    let mut hits = 0;
    for seed in 0..SAMPLES as u64 {
        let answer = client
            .resolve_with_seed(&query(), now, seed)
            .await
            .result
            .unwrap();
        let reversed = client
            .resolve_with_seed(&query(), now, seed)
            .await
            .result
            .unwrap();
        assert_eq!(answer, reversed, "wire order affected seed {seed}");
        assert_eq!(answer.candidates()[0].peer().priority, 0);
        assert_eq!(answer.candidates()[2].peer().priority, 10);
        assert!(answer.candidates()[0].peer().weight > answer.candidates()[1].peer().weight);
        hits += usize::from(answer.candidates()[0].peer().endpoint.port() == 1001);
    }
    // Fixed seeds make this reproducible. Distinguishes 1:3 weighting from
    // equal, reversed, or deterministic-largest-weight selection.
    assert!(
        (420..=580).contains(&hits),
        "first target selected {hits} times"
    );
    task.await.unwrap();
}

#[tokio::test]
async fn all_zero_weights_are_shuffled_and_mixed_zero_weights_can_be_selected() {
    const ALL_ZERO: usize = 64;
    const MIXED: usize = 2_500;
    let (socket, task) = server(ALL_ZERO + MIXED, |i, q| {
        reply(
            q,
            0,
            &[
                srv(SERVICE, 0, 0, 1001, FIRST, 60),
                srv(
                    SERVICE,
                    0,
                    if i < ALL_ZERO { 0 } else { 100 },
                    1002,
                    SECOND,
                    60,
                ),
            ],
            &[],
            &[
                address(FIRST, "192.0.2.1", 60),
                address(SECOND, "192.0.2.2", 60),
            ],
        )
    })
    .await;
    let client = DnsClient::new(config(socket.local_addr().unwrap())).unwrap();
    let mut all_zero_hits = 0;
    let mut mixed_hits = 0;
    for seed in 0..(ALL_ZERO + MIXED) as u64 {
        let answer = client
            .resolve_with_seed(&query(), now, seed)
            .await
            .result
            .unwrap();
        if answer.candidates()[0].peer().endpoint.port() == 1001 {
            if seed < ALL_ZERO as u64 {
                all_zero_hits += 1;
            } else {
                mixed_hits += 1;
            }
        }
    }
    assert!((16..=48).contains(&all_zero_hits));
    assert!(
        (1..=60).contains(&mixed_hits),
        "zero weight selected {mixed_hits} times"
    );
    task.await.unwrap();
}

#[tokio::test]
async fn sole_root_is_unavailable_and_unusable_records_do_not_hide_good_targets() {
    for case in 0..4 {
        let (socket, task) = server(1, move |_, q| {
            let records = match case {
                0 => vec![srv(SERVICE, 0, 0, 0, ".", 30)],
                1 => vec![
                    srv(SERVICE, 0, 0, 0, ".", 30),
                    srv(SERVICE, 0, 0, 443, FIRST, 30),
                ],
                // RFC 3597 section 4: receivers decompress legacy SRV targets.
                2 => vec![rr(SERVICE, 33, 30, &[0, 0, 0, 0, 1, 187, 0xc0, 22])],
                _ => vec![
                    srv(SERVICE, 0, 0, 443, "-bad.example.invalid.", 30),
                    srv(SERVICE, 0, 0, 443, FIRST, 30),
                ],
            };
            reply(
                q,
                0,
                &records,
                &[],
                &[
                    address("example.invalid.", "192.0.2.1", 30),
                    address(FIRST, "192.0.2.2", 30),
                ],
            )
        })
        .await;
        let result = DnsClient::new(config(socket.local_addr().unwrap()))
            .unwrap()
            .resolve_with_seed(&query(), now, 1)
            .await
            .result;
        if case == 0 {
            assert_eq!(
                result,
                Err(DnsError::ServiceUnavailable {
                    expires_at: PeerDiscoveryTime::from_millis(31_000),
                })
            );
        } else {
            let answer = result.unwrap();
            assert_eq!(answer.candidates().len(), 1);
            assert_eq!(
                answer.candidates()[0].peer().endpoint.to_string(),
                if case == 2 {
                    "192.0.2.1:443"
                } else {
                    "192.0.2.2:443"
                }
            );
        }
        task.await.unwrap();
        assert!(socket.try_recv_from(&mut [0; 512]).is_err());
    }
}

#[tokio::test]
async fn invalid_service_queries_fail_before_sending() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = DnsClient::new(config(socket.local_addr().unwrap())).unwrap();
    for owner in [
        "example.invalid.",
        "_svc.tcp.example.invalid.",
        "_svc._udp.example.invalid.",
        "_svc._tcp.-bad.invalid.",
        "_svc._tcp.bad_.invalid.",
        "_svc._tcp.192.0.2.1.",
        "_svc._tcp.",
    ] {
        let input = ServiceDiscoveryInput::new(
            PeerLabel::new("test").unwrap(),
            DiscoveryTarget::new(owner),
            ServiceDiscoveryMode::Service,
            PeerTransport::Tcp,
            None,
        );
        let query = DnsQuery::new(input).unwrap();
        assert_eq!(
            client.resolve_with_seed(&query, now, 1).await.result,
            Err(DnsError::InvalidQuery)
        );
    }
    assert!(socket.try_recv_from(&mut [0; 512]).is_err());
}

#[tokio::test]
async fn cname_target_is_not_followed_and_other_targets_survive() {
    for case in 0..4 {
        let (socket, task) = server(if case == 0 || case == 3 { 1 } else { 2 }, move |i, q| {
            if i == 0 {
                let mut additional = vec![address(SECOND, "192.0.2.2", 60)];
                if case != 1 {
                    additional.push(address(FIRST, "192.0.2.1", 60));
                }
                if case == 0 {
                    additional.push(rr(FIRST, 5, 60, &name(THIRD)));
                }
                if case == 2 {
                    additional.push(address(SECOND, "2001:db8::2", 60));
                }
                let mut records = vec![
                    srv(SERVICE, 0, 0, 443, FIRST, 60),
                    srv(SERVICE, 1, 0, 443, SECOND, 60),
                ];
                if case == 3 {
                    records.push(rr(FIRST, 5, 30, &name(THIRD)));
                }
                reply(q, 0, &records, &[], &additional)
            } else {
                assert_eq!(question(q).0, FIRST);
                let ip = if question(q).1 == 1 {
                    "192.0.2.99"
                } else {
                    "2001:db8::99"
                };
                reply(
                    q,
                    0,
                    &[rr(FIRST, 5, 30, &name(THIRD)), address(THIRD, ip, 60)],
                    &[],
                    &[],
                )
            }
        })
        .await;
        let q = if case == 2 {
            query().with_address_family(AddressFamilyPolicy::DualStack)
        } else {
            query()
        };
        let response = DnsClient::new(config(socket.local_addr().unwrap()))
            .unwrap()
            .resolve_with_seed(&q, now, 7)
            .await;
        assert_eq!(response.outcomes.len(), if case == 2 { 5 } else { 3 });
        assert!(response
            .outcomes
            .iter()
            .filter(|outcome| outcome.owner.as_str() == FIRST)
            .all(|outcome| outcome.result == Err(DnsError::MalformedAnswer)));
        let answer = response.result.unwrap();
        assert!(answer.candidates().iter().all(|c| c.peer().priority == 1));
        task.await.unwrap();
        assert!(socket.try_recv_from(&mut [0; 512]).is_err());
    }
}

#[tokio::test]
async fn target_negative_soa_never_negatively_caches_the_service_name() {
    for usable in [true, false] {
        let (socket, task) = server(2, move |i, q| {
            if i == 0 {
                let mut records = vec![srv(SERVICE, 0, 1, 443, FIRST, 60)];
                let mut additional = vec![];
                if usable {
                    records.push(srv(SERVICE, 1, 1, 443, SECOND, 60));
                    additional.push(address(SECOND, "192.0.2.2", 60));
                }
                reply(q, 0, &records, &[], &additional)
            } else {
                assert_eq!(question(q).0, FIRST);
                reply(q, 3, &[], &[soa()], &[])
            }
        })
        .await;
        let response = DnsClient::new(config(socket.local_addr().unwrap()))
            .unwrap()
            .resolve_with_seed(&query(), now, 9)
            .await;
        let mut cache = DnsCache::default();
        let DnsRefresh::Start(token) = cache
            .begin_refresh(&query(), now(), Duration::from_secs(1))
            .unwrap()
        else {
            panic!("admission")
        };
        if usable {
            assert_eq!(
                response.result.as_ref().unwrap().expires_at(),
                Some(PeerDiscoveryTime::from_millis(8_000))
            );
            assert_eq!(
                response.result.as_ref().unwrap().candidates()[0]
                    .peer()
                    .endpoint
                    .ip()
                    .to_string(),
                "192.0.2.2"
            );
        } else {
            assert_eq!(response.result, Err(DnsError::Unavailable));
        }
        assert!(matches!(
            response.outcomes[1].result,
            Err(DnsError::NxDomain { soa: Some(_) })
        ));
        assert!(cache.finish_refresh(token, response.result, now()));
        assert!(!matches!(
            cache.lookup(&query().cache_key(), now()).result,
            DnsCachedResult::Negative(_)
        ));
        task.await.unwrap();
    }
}

#[tokio::test]
async fn partial_srv_denials_obey_cache_negative_cap() {
    for failed_target in [false, true] {
        for rcode in [0, 3] {
            let (socket, task) = server(2, move |i, q| {
                if i == 0 {
                    let mut records = vec![srv(SERVICE, 0, 0, 443, FIRST, 172_800)];
                    if failed_target {
                        records.push(srv(SERVICE, 1, 0, 443, SECOND, 172_800));
                    }
                    reply(
                        q,
                        0,
                        &records,
                        &[],
                        &[address(
                            if failed_target { SECOND } else { FIRST },
                            "192.0.2.1",
                            172_800,
                        )],
                    )
                } else {
                    assert_eq!(
                        (question(q).0.as_str(), question(q).1),
                        (FIRST, if failed_target { 1 } else { 28 })
                    );
                    let mut data = name("ns.example.invalid.");
                    data.extend(name("hostmaster.example.invalid."));
                    for value in [1u32, 2, 3, 4, 86_400] {
                        data.extend(value.to_be_bytes());
                    }
                    reply(
                        q,
                        rcode,
                        &[],
                        &[rr("example.invalid.", 6, 86_400, &data)],
                        &[],
                    )
                }
            })
            .await;
            let q = if failed_target {
                query()
            } else {
                query().with_address_family(AddressFamilyPolicy::DualStack)
            };
            let response = DnsClient::new(config(socket.local_addr().unwrap()))
                .unwrap()
                .resolve_with_seed(&q, now, 3)
                .await;
            let answer = response.result.unwrap();
            assert_eq!(answer.candidates().len(), 1);
            assert_eq!(
                answer.expires_at(),
                Some(PeerDiscoveryTime::from_millis(86_401_000))
            );
            assert!(answer.candidates()[0]
                .records()
                .unwrap()
                .iter()
                .all(|record| record.ttl == 172_800));
            assert_eq!(
                response
                    .outcomes
                    .iter()
                    .filter(|outcome| outcome.result.is_err())
                    .count(),
                1
            );
            let mut cache = DnsCache::default()
                .with_ttl_caps(Duration::from_secs(604_800), Duration::from_secs(600));
            let DnsRefresh::Start(token) = cache
                .begin_refresh(&q, now(), Duration::from_secs(1))
                .unwrap()
            else {
                panic!("admission")
            };
            assert!(cache.finish_refresh(token, Ok(answer), now()));
            assert_eq!(
                cache.lookup(&q.cache_key(), now()).fresh_until,
                Some(PeerDiscoveryTime::from_millis(601_000))
            );
            assert!(matches!(
                cache
                    .lookup(&q.cache_key(), PeerDiscoveryTime::from_millis(601_000))
                    .result,
                DnsCachedResult::Stale { .. }
            ));
            task.await.unwrap();
        }
    }
}

#[tokio::test]
async fn service_negatives_preserve_soa_and_alias_deadlines() {
    for (rcode, has_soa, alias) in [
        (0, true, false),
        (3, true, false),
        (0, false, false),
        (3, false, false),
        (3, true, true),
    ] {
        let (socket, task) = server(1, move |_, q| {
            let answers = if alias {
                vec![rr(SERVICE, 5, 3, &name("_alt._tcp.example.invalid."))]
            } else {
                vec![]
            };
            reply(
                q,
                rcode,
                &answers,
                &if has_soa { vec![soa()] } else { vec![] },
                &[],
            )
        })
        .await;
        let response = DnsClient::new(config(socket.local_addr().unwrap()))
            .unwrap()
            .resolve_with_seed(&query(), now, 3)
            .await;
        assert_eq!(response.sources[0].record_type, DnsRecordType::Srv);
        assert_eq!(response.outcomes.len(), 1);
        assert_eq!(
            response.outcomes[0].result,
            response.result.as_ref().map(|_| ()).map_err(|error| *error)
        );
        let soa = match response.result {
            Err(DnsError::NxDomain { soa }) if rcode == 3 => soa,
            Err(DnsError::NoData { soa }) if rcode == 0 => soa,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(
            soa.map(|s| s.expires_at().as_millis()),
            has_soa.then_some(if alias { 4_000 } else { 8_000 })
        );
        task.await.unwrap();
    }
}

#[tokio::test]
async fn record_target_and_lookup_bounds_are_enforced_without_extra_queries() {
    for case in 0..4 {
        let count = match case {
            0 | 1 => 3,
            2 => 2,
            _ => 1,
        };
        let (socket, task) = server(count, |i, q| {
            if i == 0 {
                reply(
                    q,
                    0,
                    &[
                        srv(SERVICE, 0, 0, 443, FIRST, 30),
                        srv(SERVICE, 1, 0, 443, SECOND, 30),
                    ],
                    &[],
                    &[],
                )
            } else {
                assert_eq!(question(q).0, FIRST);
                let ip = if question(q).1 == 1 {
                    "192.0.2.1"
                } else {
                    "2001:db8::1"
                };
                reply(q, 0, &[address(FIRST, ip, 30)], &[], &[])
            }
        })
        .await;
        let mut cfg = config(socket.local_addr().unwrap());
        match case {
            0 => cfg.max_srv_records = 1,
            1 => cfg.max_srv_targets = 1,
            2 => cfg.max_srv_address_lookups = 1,
            _ => cfg.max_srv_address_lookups = 0,
        }
        let response = DnsClient::new(cfg)
            .unwrap()
            .resolve_with_seed(
                &query().with_address_family(AddressFamilyPolicy::DualStack),
                now,
                0,
            )
            .await;
        assert_eq!(response.skipped_srv_records, if case == 3 { 2 } else { 1 });
        assert_eq!(response.skipped_srv_targets, if case == 3 { 2 } else { 1 });
        if case < 3 {
            assert_eq!(
                response.result.unwrap().candidates().len(),
                if case == 2 { 1 } else { 2 }
            );
            assert_eq!(response.sources.len(), count);
            assert_eq!(response.outcomes.len(), if case == 2 { 5 } else { 3 });
            assert_eq!(
                response
                    .outcomes
                    .iter()
                    .filter(|outcome| outcome.result == Err(DnsError::LimitExceeded))
                    .count(),
                if case == 2 { 3 } else { 0 }
            );
        } else {
            assert_eq!(response.result, Err(DnsError::LimitExceeded));
        }
        task.await.unwrap();
        assert!(socket.try_recv_from(&mut [0; 512]).is_err());
    }
}

#[tokio::test]
async fn large_srv_pools_are_ordered_before_record_and_target_work_limits() {
    const SEEDS: usize = 32;
    for size in [17, 40] {
        let (socket, task) = server(3 * SEEDS, move |_, q| {
            let records: Vec<_> = (0..size)
                .map(|i| srv(SERVICE, 0, 1, 1000 + i, &format!("p{i}.invalid."), 60))
                .collect();
            let additional: Vec<_> = (0..size)
                .map(|i| address(&format!("p{i}.invalid."), &format!("192.0.2.{}", i + 1), 60))
                .collect();
            reply(q, 0, &records, &[], &additional)
        })
        .await;
        let mut cfg = config(socket.local_addr().unwrap());
        cfg.edns_payload_size = 4096;
        let all = DnsClient::new(cfg.clone()).unwrap();
        let mut record_cfg = cfg.clone();
        record_cfg.max_srv_records = 1;
        let record_limited = DnsClient::new(record_cfg).unwrap();
        cfg.max_srv_targets = 1;
        let target_limited = DnsClient::new(cfg).unwrap();
        let mut selected_beyond_default_record_limit = false;
        for seed in 0..SEEDS as u64 {
            let response = all.resolve_with_seed(&query(), now, seed).await;
            assert_eq!(response.skipped_srv_records, usize::from(size) - 16);
            assert_eq!(response.skipped_srv_targets, usize::from(size) - 16);
            let full = response.result.unwrap();
            assert_eq!(full.candidates().len(), 16);
            selected_beyond_default_record_limit |=
                full.candidates()[0].peer().endpoint.port() >= 1032;
            for client in [&record_limited, &target_limited] {
                let response = client.resolve_with_seed(&query(), now, seed).await;
                assert_eq!(response.skipped_srv_records, usize::from(size) - 1);
                assert_eq!(response.skipped_srv_targets, usize::from(size) - 1);
                let limited = response.result.unwrap();
                assert_eq!(limited.candidates().len(), 1);
                assert_eq!(limited.candidates()[0], full.candidates()[0]);
            }
        }
        if size == 40 {
            assert!(selected_beyond_default_record_limit);
        }
        task.await.unwrap();
        assert!(socket.try_recv_from(&mut [0; 512]).is_err());
    }
}

#[tokio::test]
async fn record_budget_is_applied_after_deduplicating_the_complete_rrset() {
    let (socket, task) = server(1, |_, q| {
        let records: Vec<_> = (0..40)
            .map(|i| srv(SERVICE, 0, 0, 443, FIRST, 60 - i))
            .collect();
        reply(q, 0, &records, &[], &[address(FIRST, "192.0.2.1", 60)])
    })
    .await;
    let mut cfg = config(socket.local_addr().unwrap());
    cfg.edns_payload_size = 4096;
    cfg.max_srv_records = 1;
    let answer = DnsClient::new(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await
        .result
        .unwrap();
    assert_eq!(answer.candidates().len(), 1);
    assert_eq!(
        answer.expires_at(),
        Some(PeerDiscoveryTime::from_millis(22_000))
    );
    task.await.unwrap();
}

#[tokio::test]
async fn service_admission_covers_the_target_lookup_and_cancellation() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let task_socket = socket.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut buf = [0; 4096];
        let (len, peer) = task_socket.recv_from(&mut buf).await.unwrap();
        task_socket
            .send_to(
                &reply(
                    &buf[..len],
                    0,
                    &[srv(SERVICE, 0, 0, 443, FIRST, 30)],
                    &[],
                    &[],
                ),
                peer,
            )
            .await
            .unwrap();
        let (len, _) = task_socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(
            (question(&buf[..len]).0.as_str(), question(&buf[..len]).1),
            (FIRST, 1)
        );
        ready_tx.send(()).unwrap();
    });
    let mut cfg = config(socket.local_addr().unwrap());
    cfg.max_in_flight = 1;
    cfg.timeout = Duration::from_secs(3);
    let client = DnsClient::new(cfg).unwrap();
    let active = client.clone();
    let lookup = tokio::spawn(async move { active.resolve_with_seed(&query(), now, 0).await });
    ready_rx.await.unwrap();
    assert_eq!(
        client.resolve_with_seed(&query(), now, 0).await.result,
        Err(DnsError::Busy)
    );
    lookup.abort();
    assert!(lookup.await.unwrap_err().is_cancelled());
    server.await.unwrap();
    assert!(socket.try_recv_from(&mut [0; 512]).is_err());
    // The permit is released: an invalid response now reaches the source,
    // instead of a cancelled refresh permanently consuming admission.
    let responder = socket.clone();
    let response = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        let (len, peer) = responder.recv_from(&mut bytes).await.unwrap();
        responder
            .send_to(
                &reply(
                    &bytes[..len],
                    0,
                    &[srv(SERVICE, 0, 0, 0, ".", 30)],
                    &[],
                    &[],
                ),
                peer,
            )
            .await
            .unwrap();
    });
    assert_eq!(
        client.resolve_with_seed(&query(), now, 0).await.result,
        Err(DnsError::ServiceUnavailable {
            expires_at: PeerDiscoveryTime::from_millis(31_000),
        })
    );
    response.await.unwrap();
}

#[test]
fn srv_configuration_bounds_are_validated() {
    for case in 0..9 {
        let mut cfg = config("127.0.0.1:53".parse().unwrap());
        match case {
            0 => cfg.max_srv_records = 0,
            1 => cfg.max_srv_records = 129,
            2 => cfg.max_srv_targets = 0,
            3 => cfg.max_srv_targets = 33,
            4 => cfg.max_srv_address_lookups = 65,
            5 => cfg.srv_refresh_timeout = Duration::from_nanos(1),
            6 => cfg.srv_refresh_timeout = Duration::from_secs(301),
            7 => cfg.max_srv_concurrent_targets = 0,
            _ => cfg.max_srv_concurrent_targets = 33,
        }
        assert!(matches!(DnsClient::new(cfg), Err(DnsError::InvalidQuery)));
    }
    for (duration, concurrent) in [
        (Duration::ZERO, 4),
        (Duration::from_millis(1), 1),
        (Duration::from_secs(300), 32),
    ] {
        let mut cfg = config("127.0.0.1:53".parse().unwrap());
        cfg.srv_refresh_timeout = duration;
        cfg.max_srv_concurrent_targets = concurrent;
        assert!(DnsClient::new(cfg).is_ok());
    }
}

#[tokio::test]
async fn service_owner_aliases_preserve_timing_and_reserve_two_terminal_records() {
    for depth in [1, 14, 15] {
        let (socket, task) = server(1, move |_, q| {
            let mut records = Vec::new();
            let mut owner = SERVICE.to_owned();
            for i in 0..depth {
                let target = format!("_svc._tcp.alias{i}.example.invalid.");
                records.push(rr(&owner, 5, 2, &name(&target)));
                owner = target;
            }
            records.push(srv(&owner, 0, 1, 443, FIRST, 30));
            reply(q, 0, &records, &[], &[address(FIRST, "192.0.2.1", 60)])
        })
        .await;
        let mut cfg = config(socket.local_addr().unwrap());
        cfg.edns_payload_size = 4096;
        let result = DnsClient::new(cfg)
            .unwrap()
            .resolve_with_seed(&query(), now, 0)
            .await
            .result;
        if depth == 15 {
            assert_eq!(result, Err(DnsError::MalformedAnswer));
        } else {
            let answer = result.unwrap();
            let chain = answer.candidates()[0].records().unwrap();
            assert_eq!(chain.len(), depth + 2);
            assert!(chain[..depth]
                .iter()
                .all(|r| r.kind == DnsRecordType::Cname));
            assert_eq!(chain[depth].kind, DnsRecordType::Srv);
            assert_eq!(chain[depth + 1].kind, DnsRecordType::A);
            assert_eq!(
                answer.expires_at(),
                Some(PeerDiscoveryTime::from_millis(3_000))
            );
        }
        task.await.unwrap();
    }
}

#[tokio::test]
async fn duplicate_srv_records_do_not_multiply_weight_but_do_shorten_rrset_ttl() {
    let (socket, task) = server(64, |i, q| {
        let mut records = vec![
            srv(SERVICE, 0, 1, 443, FIRST, 30),
            srv(SERVICE, 0, 3, 443, SECOND, 30),
        ];
        if i % 2 == 1 {
            records.push(srv(SERVICE, 0, 1, 443, FIRST, 0x8000_0000));
        }
        reply(
            q,
            0,
            &records,
            &[],
            &[
                address(FIRST, "192.0.2.1", 60),
                address(SECOND, "192.0.2.2", 60),
            ],
        )
    })
    .await;
    let client = DnsClient::new(config(socket.local_addr().unwrap())).unwrap();
    for seed in 0..32 {
        let original = client
            .resolve_with_seed(&query(), now, seed)
            .await
            .result
            .unwrap();
        let duplicate = client
            .resolve_with_seed(&query(), now, seed)
            .await
            .result
            .unwrap();
        assert_eq!(original.candidates().len(), 2);
        assert_eq!(duplicate.candidates().len(), 2);
        for (a, b) in original.candidates().iter().zip(duplicate.candidates()) {
            assert_eq!(a.peer(), b.peer());
        }
        assert_eq!(
            original.expires_at(),
            Some(PeerDiscoveryTime::from_millis(31_000))
        );
        assert_eq!(duplicate.expires_at(), Some(now()));
    }
    task.await.unwrap();
}

#[tokio::test]
async fn candidate_cap_follows_target_order_and_full_address_rrset_ttl() {
    let (socket, task) = server(1, |_, q| {
        let additional: Vec<_> = (1..=18)
            .map(|i| address(FIRST, &format!("192.0.2.{i}"), if i == 18 { 0 } else { 60 }))
            .collect();
        reply(
            q,
            0,
            &[
                srv(SERVICE, 0, 0, 443, FIRST, 30),
                srv(SERVICE, 1, 0, 8443, SECOND, 30),
            ],
            &[],
            &additional,
        )
    })
    .await;
    let mut cfg = config(socket.local_addr().unwrap());
    cfg.edns_payload_size = 4096;
    let answer = DnsClient::new(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await
        .result
        .unwrap();
    assert_eq!(answer.candidates().len(), 16);
    assert!(answer
        .candidates()
        .iter()
        .all(|c| c.peer().priority == 0 && c.peer().endpoint.port() == 443));
    assert_eq!(answer.expires_at(), Some(now()));
    task.await.unwrap();
    assert!(socket.try_recv_from(&mut [0; 512]).is_err());
}

#[tokio::test]
async fn service_protocols_and_leading_digits_are_preserved_but_zero_ports_are_skipped() {
    for (protocol, transport) in [
        ("tcp", PeerTransport::Tcp),
        ("udp", PeerTransport::Udp),
        ("sctp", PeerTransport::Sctp),
    ] {
        let service = format!("_svc._{protocol}.3example.invalid.");
        let expected = service.clone();
        let (socket, task) = server(1, move |_, q| {
            assert_eq!(question(q).0, expected);
            reply(
                q,
                0,
                &[
                    srv(&expected, 0, 0, 0, "3target.example.invalid.", 30),
                    srv(&expected, 0, 0, 443, "3target.example.invalid.", 30),
                ],
                &[],
                &[address("3target.example.invalid.", "2001:db8::1", 60)],
            )
        })
        .await;
        let q = DnsQuery::new(ServiceDiscoveryInput::new(
            PeerLabel::new("test").unwrap(),
            DiscoveryTarget::new(service),
            ServiceDiscoveryMode::Service,
            transport,
            None,
        ))
        .unwrap()
        .with_address_family(AddressFamilyPolicy::Ipv6Only);
        let answer = DnsClient::new(config(socket.local_addr().unwrap()))
            .unwrap()
            .resolve(&q, now)
            .await
            .result
            .unwrap();
        assert_eq!(answer.candidates().len(), 1);
        assert_eq!(answer.candidates()[0].peer().endpoint.port(), 443);
        assert_eq!(answer.candidates()[0].peer().transport, transport);
        task.await.unwrap();
    }
}

#[tokio::test]
async fn target_alias_in_fresh_additional_data_invalidates_the_target() {
    let (socket, task) = server(2, |i, q| {
        if i == 0 {
            reply(q, 0, &[srv(SERVICE, 0, 0, 443, FIRST, 30)], &[], &[])
        } else {
            reply(
                q,
                0,
                &[address(FIRST, "192.0.2.1", 60)],
                &[],
                &[rr(FIRST, 5, 30, &name(SECOND))],
            )
        }
    })
    .await;
    let client = DnsClient::new(config(socket.local_addr().unwrap())).unwrap();
    let response = client.resolve_with_seed(&query(), now, 0).await;
    assert_eq!(response.result, Err(DnsError::MalformedAnswer));
    assert_eq!(client.stats().malformed_responses, 1);
    task.await.unwrap();
}

#[tokio::test]
async fn srv_reuses_edns_fallback_tcp_and_source_binding() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (listener, socket) = bind_dns_pair(listener).await.unwrap();
    let server_address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        for i in 0..2 {
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            assert_eq!(peer.ip().to_string(), "127.0.0.2");
            assert_eq!(question(&buffer[..len]).1, 33);
            assert_eq!(buffer[11], if i == 0 { 1 } else { 0 });
            let mut bytes = reply(&buffer[..len], if i == 0 { 1 } else { 0 }, &[], &[], &[]);
            if i == 1 {
                bytes[2] |= 2;
            }
            socket.send_to(&bytes, peer).await.unwrap();
        }
        let (mut stream, peer) = listener.accept().await.unwrap();
        assert_eq!(peer.ip().to_string(), "127.0.0.2");
        let len = usize::from(stream.read_u16().await.unwrap());
        stream.read_exact(&mut buffer[..len]).await.unwrap();
        assert_eq!(question(&buffer[..len]).1, 33);
        assert_eq!(buffer[11], 0);
        let bytes = reply(
            &buffer[..len],
            0,
            &[srv(SERVICE, 0, 0, 443, FIRST, 30)],
            &[],
            &[address(FIRST, "192.0.2.1", 60)],
        );
        stream.write_u16(bytes.len() as u16).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
    });
    let mut cfg = config(server_address);
    cfg.local_address = Some("127.0.0.2".parse().unwrap());
    let response = DnsClient::new(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    assert!(response.result.is_ok());
    assert_eq!(
        response.sources[0].transport,
        opc_peer_discovery::DnsTransport::Tcp
    );
    let diagnostic = format!("{response:?}");
    for secret in [SERVICE, FIRST, "192.0.2.1", "127.0.0.1", "127.0.0.2"] {
        assert!(!diagnostic.contains(secret));
    }
    server.await.unwrap();
}

#[tokio::test]
async fn compressed_srv_additional_data_does_not_break_address_mode() {
    let (socket, task) = server(1, |_, q| {
        assert_eq!((question(q).0.as_str(), question(q).1), (FIRST, 1));
        reply(
            q,
            0,
            &[address(FIRST, "192.0.2.1", 30)],
            &[],
            &[rr(SERVICE, 33, 30, &[0, 0, 0, 0, 1, 187, 0xc0, 12])],
        )
    })
    .await;
    let q = DnsQuery::new(ServiceDiscoveryInput::new(
        PeerLabel::new("test").unwrap(),
        DiscoveryTarget::new(FIRST),
        ServiceDiscoveryMode::Address,
        PeerTransport::Tcp,
        Some(443),
    ))
    .unwrap()
    .with_address_family(AddressFamilyPolicy::Ipv4Only);
    let answer = DnsClient::new(config(socket.local_addr().unwrap()))
        .unwrap()
        .resolve(&q, now)
        .await
        .result
        .unwrap();
    assert_eq!(
        answer.candidates()[0].peer().endpoint.to_string(),
        "192.0.2.1:443"
    );
    task.await.unwrap();
}

#[tokio::test]
async fn target_addresses_keep_dns_order_within_equal_precedence() {
    for additional in [false, true] {
        let (socket, task) = server(if additional { 2 } else { 4 }, move |i, q| {
            let refresh = if additional { i } else { i / 2 };
            let mut addresses = vec![
                address(FIRST, "192.0.2.20", 30),
                address(FIRST, "192.0.2.10", 30),
            ];
            if refresh == 1 {
                addresses.reverse();
            }
            if question(q).1 == 33 {
                reply(
                    q,
                    0,
                    &[srv(SERVICE, 0, 0, 443, FIRST, 30)],
                    &[],
                    if additional { &addresses } else { &[] },
                )
            } else {
                reply(q, 0, &addresses, &[], &[])
            }
        })
        .await;
        let client = DnsClient::new(config(socket.local_addr().unwrap())).unwrap();
        for first in ["192.0.2.20:443", "192.0.2.10:443"] {
            let answer = client
                .resolve_with_seed(&query(), now, 0)
                .await
                .result
                .unwrap();
            assert_eq!(answer.candidates()[0].peer().endpoint.to_string(), first);
        }
        task.await.unwrap();
    }
}

#[tokio::test]
async fn repeated_endpoints_do_not_displace_distinct_candidates() {
    let (socket, task) = server(1, |_, q| {
        reply(
            q,
            0,
            &[
                srv(SERVICE, 0, 1, 443, FIRST, 30),
                srv(SERVICE, 1, 3, 443, FIRST, 20),
                srv(SERVICE, 2, 1, 8443, FIRST, 30),
            ],
            &[],
            &[address(FIRST, "192.0.2.1", 60)],
        )
    })
    .await;
    let answer = DnsClient::new(config(socket.local_addr().unwrap()))
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await
        .result
        .unwrap();
    assert_eq!(answer.candidates().len(), 2);
    assert_eq!(answer.candidates()[0].peer().priority, 0);
    assert_eq!(answer.candidates()[0].peer().endpoint.port(), 443);
    assert_eq!(answer.candidates()[1].peer().endpoint.port(), 8443);
    assert_eq!(
        answer.expires_at(),
        Some(PeerDiscoveryTime::from_millis(21_000))
    );
    task.await.unwrap();
}

#[tokio::test]
async fn zero_weight_first_rule_has_the_inclusive_half_probability() {
    let (socket, task) = server(400, |_, q| {
        reply(
            q,
            0,
            &[
                srv(SERVICE, 0, 0, 1001, FIRST, 60),
                srv(SERVICE, 0, 1, 1002, SECOND, 60),
            ],
            &[],
            &[
                address(FIRST, "192.0.2.1", 60),
                address(SECOND, "192.0.2.2", 60),
            ],
        )
    })
    .await;
    let client = DnsClient::new(config(socket.local_addr().unwrap())).unwrap();
    let mut hits = 0;
    for seed in 0..400 {
        let answer = client
            .resolve_with_seed(&query(), now, seed)
            .await
            .result
            .unwrap();
        hits += usize::from(answer.candidates()[0].peer().endpoint.port() == 1001);
    }
    assert!(
        (160..=240).contains(&hits),
        "zero weight selected {hits} times"
    );
    task.await.unwrap();
}

#[tokio::test]
async fn nxdomain_with_srv_data_is_malformed() {
    let (socket, task) = server(1, |_, q| {
        reply(
            q,
            3,
            &[srv(SERVICE, 0, 0, 443, FIRST, 60)],
            &[soa()],
            &[address(FIRST, "192.0.2.1", 60)],
        )
    })
    .await;
    let result = DnsClient::new(config(socket.local_addr().unwrap()))
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await
        .result;
    assert_eq!(result, Err(DnsError::MalformedAnswer));
    task.await.unwrap();
}

#[tokio::test]
async fn root_withdrawal_uses_its_deadline_for_cold_and_last_good_cache_entries() {
    for warm in [false, true] {
        for (ttl, alias_ttl, cap, publication, expected) in [
            (3600, None, 600, 3000, Some(603_000)),
            (3600, Some(20), 600, 3000, Some(22_000)),
            (5, None, 600, 3000, Some(7000)),
            (0, None, 600, 3000, None),
            (0x8000_0000, None, 600, 3000, None),
            (1, None, 600, 4000, None),
            (3600, None, 0, 3000, None),
        ] {
            let (socket, task) = server(if warm { 2 } else { 1 }, move |i, q| {
                if warm && i == 0 {
                    return reply(
                        q,
                        0,
                        &[srv(SERVICE, 0, 0, 443, FIRST, 1)],
                        &[],
                        &[address(FIRST, "192.0.2.1", 1)],
                    );
                }
                let records = if let Some(alias_ttl) = alias_ttl {
                    vec![
                        rr(SERVICE, 5, alias_ttl, &name(SECOND)),
                        srv(SECOND, 0, 0, 0, ".", ttl),
                    ]
                } else {
                    vec![srv(SERVICE, 0, 0, 0, ".", ttl)]
                };
                reply(q, 0, &records, &[], &[])
            })
            .await;
            let client = DnsClient::new(config(socket.local_addr().unwrap())).unwrap();
            let q = query();
            let mut cache = DnsCache::default()
                .with_ttl_caps(Duration::from_secs(86_400), Duration::from_secs(cap));
            let mut last_good = None;
            if warm {
                let start = PeerDiscoveryTime::from_millis(0);
                let DnsRefresh::Start(token) = cache
                    .begin_refresh(&q, start, Duration::from_secs(10))
                    .unwrap()
                else {
                    panic!("admission")
                };
                let answer = client
                    .resolve_with_seed(&q, || start, 0)
                    .await
                    .result
                    .unwrap();
                last_good = Some(answer.clone());
                assert!(cache.finish_refresh(token, Ok(answer), start));
            }
            let observed = PeerDiscoveryTime::from_millis(2000);
            let DnsRefresh::Start(token) = cache
                .begin_refresh(&q, observed, Duration::from_secs(10))
                .unwrap()
            else {
                panic!("admission")
            };
            let error = client
                .resolve_with_seed(&q, || observed, 0)
                .await
                .result
                .unwrap_err();
            assert_eq!(error.code(), "dns-service-unavailable");
            let effective_ttl = if ttl & 0x8000_0000 != 0 { 0 } else { ttl };
            let effective_ttl = alias_ttl.map_or(effective_ttl, |alias| alias.min(effective_ttl));
            assert_eq!(
                error,
                DnsError::ServiceUnavailable {
                    expires_at: PeerDiscoveryTime::from_millis(
                        2000 + u64::from(effective_ttl) * 1000
                    ),
                }
            );
            let published = PeerDiscoveryTime::from_millis(publication);
            assert!(cache.finish_refresh(token, Err(error), published));
            let status = cache.lookup(&q.cache_key(), published);
            assert_eq!(status.last_error, Some(error));
            if let Some(last_good) = &last_good {
                assert!(
                    matches!(&status.result, DnsCachedResult::Stale { answer, .. } if answer == last_good)
                );
            } else if expected.is_some() {
                assert_eq!(status.result, DnsCachedResult::Negative(error));
            } else {
                assert_eq!(status.result, DnsCachedResult::Miss);
            }
            if let Some(expected) = expected {
                let deadline = PeerDiscoveryTime::from_millis(expected);
                assert_eq!(status.retry_at, Some(deadline));
                assert!(matches!(
                    cache
                        .begin_refresh(&q, published, Duration::from_secs(1))
                        .unwrap(),
                    DnsRefresh::Suppressed
                ));
                assert!(matches!(
                    cache
                        .begin_refresh(&q, deadline, Duration::from_secs(1))
                        .unwrap(),
                    DnsRefresh::Start(_)
                ));
            } else {
                let retry = status.retry_at.unwrap().as_millis();
                assert!((publication + 1..=publication + 1000).contains(&retry));
            }
            task.await.unwrap();
        }
    }
}

#[tokio::test]
async fn dead_servers_are_remembered_across_srv_refreshes_and_client_clones() {
    for family in [
        AddressFamilyPolicy::Ipv4Only,
        AddressFamilyPolicy::DualStack,
    ] {
        let lookups = if family == AddressFamilyPolicy::DualStack {
            16
        } else {
            8
        };
        let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second_dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (socket, task) = server(2 * (1 + lookups), |_, q| {
            let (owner, kind, _) = question(q);
            if kind == 33 {
                let records: Vec<_> = (0..8)
                    .map(|i| srv(SERVICE, i, 0, 443, &format!("p{i}.invalid."), 3600))
                    .collect();
                reply(q, 0, &records, &[], &[])
            } else {
                let ip = if kind == 1 {
                    "192.0.2.1"
                } else {
                    "2001:db8::1"
                };
                reply(q, 0, &[address(&owner, ip, 3600)], &[], &[])
            }
        })
        .await;
        let mut cfg = config(socket.local_addr().unwrap());
        cfg.servers.insert(0, dead.local_addr().unwrap());
        cfg.servers.insert(1, second_dead.local_addr().unwrap());
        cfg.timeout = Duration::from_millis(100);
        let client = DnsClient::new(cfg).unwrap();
        for refresh in 0..2 {
            let cloned = client.clone();
            let started = std::time::Instant::now();
            let response = cloned
                .resolve_with_seed(&query().with_address_family(family), now, 0)
                .await;
            assert!(response.result.is_ok());
            assert!(
                started.elapsed() < Duration::from_millis(500),
                "dead server cost repeated across targets: {:?}",
                started.elapsed()
            );
            for silent in [&dead, &second_dead] {
                let mut packets = 0;
                while silent.try_recv_from(&mut [0; 512]).is_ok() {
                    packets += 1;
                }
                assert_eq!(
                    packets,
                    usize::from(refresh == 0),
                    "only the first refresh may retry the dead servers"
                );
            }
        }
        task.await.unwrap();
    }
}

#[tokio::test]
async fn remembered_srv_servers_remain_fallbacks_and_recover_their_preference() {
    let primary = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let success = |q: &[u8]| {
        reply(
            q,
            0,
            &[srv(SERVICE, 0, 0, 443, FIRST, 60)],
            &[],
            &[address(FIRST, "192.0.2.1", 60)],
        )
    };
    let (secondary, secondary_task) = server(3, move |attempt, q| {
        if attempt == 1 {
            reply(q, 2, &[], &[], &[])
        } else {
            success(q)
        }
    })
    .await;
    let mut cfg = config(secondary.local_addr().unwrap());
    cfg.servers.insert(0, primary.local_addr().unwrap());
    cfg.timeout = Duration::from_millis(200);
    let client = DnsClient::new(cfg).unwrap();
    let first = client.resolve_with_seed(&query(), now, 0).await;
    assert!(first.result.is_ok());
    assert_eq!(first.sources[0].server, secondary.local_addr().unwrap());
    primary.recv_from(&mut [0; 512]).await.unwrap(); // Discard the timed-out query.

    let responder = primary.clone();
    let primary_task = tokio::spawn(async move {
        for _ in 0..2 {
            let mut bytes = [0; 512];
            let (len, peer) = responder.recv_from(&mut bytes).await.unwrap();
            responder
                .send_to(&success(&bytes[..len]), peer)
                .await
                .unwrap();
        }
    });
    for _ in 0..2 {
        // First use primary as fallback after secondary's SERVFAIL. Its matched
        // reply must then restore configured preference for the next refresh.
        let response = client.resolve_with_seed(&query(), now, 0).await;
        assert!(response.result.is_ok());
        assert_eq!(response.sources[0].server, primary.local_addr().unwrap());
    }
    secondary_task.abort();
    primary_task.await.unwrap();
}

#[tokio::test]
async fn four_targets_can_make_progress_concurrently_under_one_admission_permit() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let responder = socket.clone();
    let task = tokio::spawn(async move {
        let mut buf = [0; 4096];
        let (len, peer) = responder.recv_from(&mut buf).await.unwrap();
        let records: Vec<_> = (0..4)
            .map(|i| srv(SERVICE, i, 0, 443, &format!("p{i}.invalid."), 60))
            .collect();
        responder
            .send_to(&reply(&buf[..len], 0, &records, &[], &[]), peer)
            .await
            .unwrap();
        let mut pending = Vec::new();
        for _ in 0..4 {
            let (len, peer) = responder.recv_from(&mut buf).await.unwrap();
            pending.push((buf[..len].to_vec(), peer));
        }
        for (bytes, peer) in pending.into_iter().rev() {
            let owner = question(&bytes).0;
            responder
                .send_to(
                    &reply(&bytes, 0, &[address(&owner, "192.0.2.1", 60)], &[], &[]),
                    peer,
                )
                .await
                .unwrap();
        }
    });
    let mut cfg = config(socket.local_addr().unwrap());
    cfg.timeout = Duration::from_secs(3);
    cfg.max_in_flight = 1;
    let client = DnsClient::new(cfg).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        client.resolve_with_seed(&query(), now, 0),
    )
    .await;
    task.abort();
    assert!(
        result.is_ok(),
        "four targets must start before any target replies"
    );
    let response = result.unwrap();
    assert_eq!(response.sources.len(), 5);
    assert!(response
        .outcomes
        .iter()
        .all(|outcome| outcome.result.is_ok()));
    // Duplicate addresses at the same port collapse to the first selected target.
    assert_eq!(response.result.unwrap().candidates()[0].peer().priority, 0);
}

#[tokio::test]
async fn srv_deadline_keeps_completed_families_and_marks_every_unfinished_family() {
    for additional in [false, true] {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let responder = socket.clone();
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = requests.clone();
        let task = tokio::spawn(async move {
            let mut buf = [0; 4096];
            loop {
                let (len, peer) = responder.recv_from(&mut buf).await.unwrap();
                count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let (owner, kind, _) = question(&buf[..len]);
                let response = if kind == 33 {
                    let mut records = vec![srv(SERVICE, 0, 0, 443, FIRST, 3600)];
                    records.extend(
                        (1..8).map(|i| srv(SERVICE, i, 0, 443, &format!("p{i}.invalid."), 3600)),
                    );
                    let glue = if additional {
                        vec![address(FIRST, "192.0.2.1", 3600)]
                    } else {
                        vec![]
                    };
                    reply(&buf[..len], 0, &records, &[], &glue)
                } else if owner == FIRST && kind == 1 {
                    reply(
                        &buf[..len],
                        0,
                        &[address(FIRST, "192.0.2.1", 3600)],
                        &[],
                        &[],
                    )
                } else {
                    continue;
                };
                responder.send_to(&response, peer).await.unwrap();
            }
        });
        let mut cfg = config(socket.local_addr().unwrap());
        cfg.timeout = Duration::from_secs(2);
        cfg.attempts = 5;
        cfg.srv_refresh_timeout = Duration::from_millis(80);
        cfg.max_srv_concurrent_targets = 2;
        cfg.partial_failure_ttl = Duration::from_secs(30);
        let started = std::time::Instant::now();
        let client = DnsClient::new(cfg).unwrap();
        let response = tokio::time::timeout(
            Duration::from_millis(500),
            client.resolve_with_seed(
                &query().with_address_family(AddressFamilyPolicy::DualStack),
                || PeerDiscoveryTime::from_millis(1000 + started.elapsed().as_millis() as u64),
                0,
            ),
        )
        .await;
        task.abort();
        let _ = task.await;
        let response = response.expect("overall deadline must return partial results");
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(
            requests.load(std::sync::atomic::Ordering::Relaxed),
            if additional { 3 } else { 4 }
        );
        assert_eq!(response.outcomes.len(), 17);
        assert_eq!(
            response
                .outcomes
                .iter()
                .filter(|o| o.result == Err(DnsError::Timeout))
                .count(),
            15
        );
        assert!(response.outcomes[..2].iter().all(|o| o.result.is_ok()));
        assert_eq!(response.sources.len(), if additional { 1 } else { 2 });
        let answer = response.result.unwrap();
        assert_eq!(answer.candidates().len(), 1);
        assert_eq!(
            answer.candidates()[0].peer().endpoint.to_string(),
            "192.0.2.1:443"
        );
        assert!((31_000..31_500).contains(&answer.expires_at().unwrap().as_millis()));
    }
}

#[tokio::test]
async fn srv_deadline_includes_the_initial_question_and_releases_admission() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let mut cfg = config(socket.local_addr().unwrap());
    cfg.timeout = Duration::from_secs(2);
    cfg.srv_refresh_timeout = Duration::from_millis(40);
    cfg.max_in_flight = 1;
    let client = DnsClient::new(cfg).unwrap();
    let start = std::time::Instant::now();
    let response = tokio::time::timeout(
        Duration::from_millis(500),
        client.resolve_with_seed(&query(), now, 0),
    )
    .await
    .expect("overall deadline must bound the initial question");
    assert!(start.elapsed() < Duration::from_millis(500));
    assert_eq!(response.result, Err(DnsError::Timeout));
    assert_eq!(response.outcomes.len(), 1);
    assert_eq!(response.outcomes[0].record_type, DnsRecordType::Srv);
    assert_eq!(response.outcomes[0].result, Err(DnsError::Timeout));
    assert!(response.sources.is_empty());
    assert!(socket.try_recv_from(&mut [0; 512]).is_ok());
    assert!(socket.try_recv_from(&mut [0; 512]).is_err());
    let responder = socket.clone();
    let task = tokio::spawn(async move {
        let mut buf = [0; 4096];
        let (len, peer) = responder.recv_from(&mut buf).await.unwrap();
        responder
            .send_to(
                &reply(&buf[..len], 0, &[srv(SERVICE, 0, 0, 0, ".", 30)], &[], &[]),
                peer,
            )
            .await
            .unwrap();
    });
    assert!(matches!(
        client.resolve_with_seed(&query(), now, 0).await.result,
        Err(DnsError::ServiceUnavailable { .. })
    ));
    task.await.unwrap();
}

#[tokio::test]
async fn one_silent_target_does_not_block_reusing_other_concurrency_slots() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let responder = socket.clone();
    let task = tokio::spawn(async move {
        let mut buf = [0; 4096];
        loop {
            let (len, peer) = responder.recv_from(&mut buf).await.unwrap();
            let (owner, kind, _) = question(&buf[..len]);
            let response = if kind == 33 {
                reply(
                    &buf[..len],
                    0,
                    &[
                        srv(SERVICE, 0, 0, 443, FIRST, 60),
                        srv(SERVICE, 1, 0, 443, SECOND, 60),
                        srv(SERVICE, 2, 0, 443, THIRD, 60),
                    ],
                    &[],
                    &[],
                )
            } else if owner == FIRST {
                continue;
            } else {
                reply(
                    &buf[..len],
                    0,
                    &[address(
                        &owner,
                        if owner == SECOND {
                            "192.0.2.2"
                        } else {
                            "192.0.2.3"
                        },
                        60,
                    )],
                    &[],
                    &[],
                )
            };
            responder.send_to(&response, peer).await.unwrap();
        }
    });
    let mut cfg = config(socket.local_addr().unwrap());
    cfg.timeout = Duration::from_secs(2);
    cfg.srv_refresh_timeout = Duration::from_millis(80);
    cfg.max_srv_concurrent_targets = 2;
    let response = DnsClient::new(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    task.abort();
    let _ = task.await;
    let answer = response.result.unwrap();
    assert_eq!(
        answer.candidates().len(),
        2,
        "a free slot must start the third target before the first times out"
    );
    assert_eq!(
        response
            .outcomes
            .iter()
            .filter(|outcome| outcome.result == Err(DnsError::Timeout))
            .count(),
        1
    );
    assert_eq!(answer.candidates()[0].peer().priority, 1);
    assert_eq!(answer.candidates()[1].peer().priority, 2);
}

#[tokio::test]
async fn concurrent_candidate_cap_stops_new_work_and_keeps_completed_priority_order() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let responder = socket.clone();
    let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = requests.clone();
    let task = tokio::spawn(async move {
        let mut buf = [0; 4096];
        loop {
            let (len, peer) = responder.recv_from(&mut buf).await.unwrap();
            count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let (owner, kind, _) = question(&buf[..len]);
            let response = if kind == 33 {
                let records: Vec<_> = (0..21)
                    .map(|i| srv(SERVICE, i, 0, 443, &format!("p{i}.invalid."), 60))
                    .collect();
                reply(&buf[..len], 0, &records, &[], &[])
            } else if owner == "p0.invalid." {
                continue;
            } else {
                let index: u8 = owner[1..].split('.').next().unwrap().parse().unwrap();
                reply(
                    &buf[..len],
                    0,
                    &[address(&owner, &format!("192.0.2.{index}"), 60)],
                    &[],
                    &[],
                )
            };
            responder.send_to(&response, peer).await.unwrap();
        }
    });
    let mut cfg = config(socket.local_addr().unwrap());
    cfg.edns_payload_size = 4096;
    cfg.timeout = Duration::from_secs(3);
    cfg.srv_refresh_timeout = Duration::from_millis(300);
    cfg.max_srv_concurrent_targets = 2;
    cfg.max_srv_targets = 32;
    cfg.max_srv_records = 128;
    let response = DnsClient::new(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    task.abort();
    let _ = task.await;
    assert_eq!(requests.load(std::sync::atomic::Ordering::Relaxed), 18);
    assert_eq!(response.skipped_srv_records, 4);
    assert_eq!(response.skipped_srv_targets, 4);
    assert_eq!(response.outcomes.len(), 18);
    let answer = response.result.unwrap();
    assert_eq!(answer.candidates().len(), 16);
    for (index, candidate) in answer.candidates().iter().enumerate() {
        assert_eq!(usize::from(candidate.peer().priority), index + 1);
    }
}

#[tokio::test]
async fn repeated_target_ports_cannot_skip_an_earlier_unstarted_target() {
    let (socket, task) = server(2, |i, q| {
        if i == 0 {
            let mut records = vec![
                srv(SERVICE, 0, 0, 1000, FIRST, 60),
                srv(SERVICE, 1, 0, 2000, SECOND, 60),
            ];
            records.extend((2..21).map(|i| srv(SERVICE, i, 0, 1000 + i, FIRST, 60)));
            reply(q, 0, &records, &[], &[address(FIRST, "192.0.2.1", 60)])
        } else {
            assert_eq!(question(q).0, SECOND);
            reply(q, 0, &[address(SECOND, "192.0.2.2", 60)], &[], &[])
        }
    })
    .await;
    let mut cfg = config(socket.local_addr().unwrap());
    cfg.edns_payload_size = 4096;
    let answer = DnsClient::new(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await
        .result
        .unwrap();
    assert_eq!(answer.candidates().len(), 16);
    assert_eq!(answer.candidates()[0].peer().endpoint.port(), 1000);
    assert_eq!(answer.candidates()[1].peer().endpoint.port(), 2000);
    task.await.unwrap();
}

#[tokio::test]
async fn cancelling_concurrent_targets_releases_the_single_refresh_permit() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let responder = socket.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let mut buf = [0; 4096];
        let (len, peer) = responder.recv_from(&mut buf).await.unwrap();
        let records = [
            srv(SERVICE, 0, 0, 443, FIRST, 60),
            srv(SERVICE, 1, 0, 443, SECOND, 60),
            srv(SERVICE, 2, 0, 443, THIRD, 60),
        ];
        responder
            .send_to(&reply(&buf[..len], 0, &records, &[], &[]), peer)
            .await
            .unwrap();
        for _ in 0..2 {
            responder.recv_from(&mut buf).await.unwrap();
        }
        ready_tx.send(()).unwrap();
    });
    let mut cfg = config(socket.local_addr().unwrap());
    cfg.timeout = Duration::from_secs(3);
    cfg.max_in_flight = 1;
    cfg.max_srv_concurrent_targets = 2;
    let client = DnsClient::new(cfg).unwrap();
    let active = client.clone();
    let lookup = tokio::spawn(async move { active.resolve_with_seed(&query(), now, 0).await });
    tokio::time::timeout(Duration::from_secs(1), ready_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        client.resolve_with_seed(&query(), now, 0).await.result,
        Err(DnsError::Busy)
    );
    lookup.abort();
    assert!(lookup.await.unwrap_err().is_cancelled());
    task.await.unwrap();
    assert!(socket.try_recv_from(&mut [0; 512]).is_err());
    let responder = socket.clone();
    let task = tokio::spawn(async move {
        let mut buf = [0; 4096];
        let (len, peer) = responder.recv_from(&mut buf).await.unwrap();
        assert_eq!(question(&buf[..len]).1, 33);
        responder
            .send_to(
                &reply(&buf[..len], 0, &[srv(SERVICE, 0, 0, 0, ".", 30)], &[], &[]),
                peer,
            )
            .await
            .unwrap();
    });
    assert!(matches!(
        client.resolve_with_seed(&query(), now, 0).await.result,
        Err(DnsError::ServiceUnavailable { .. })
    ));
    task.await.unwrap();
}
