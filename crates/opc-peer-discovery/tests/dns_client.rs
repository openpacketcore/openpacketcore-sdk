//! Loopback-only DNS fixtures, authored from RFC 1035 sections 4.1 and 4.2,
//! RFC 3596 section 2.2, and RFC 6891 section 6.1. No production codec helpers.

mod support;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use opc_peer_discovery::{
    AddressFamilyPolicy, DiscoveryTarget, DnsCache, DnsCachedResult, DnsClient, DnsClientConfig,
    DnsError, DnsQuery, DnsRecordType, DnsRefresh, DnsTransport, PeerDiscoveryTime, PeerLabel,
    PeerTransport, ResolverProfileId, ServiceDiscoveryInput, ServiceDiscoveryMode, SourcePlaneId,
};
use support::bind_dns_pair;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

const HOST: &str = "peer.example.invalid.";
const ALIAS: &str = "alias.example.invalid.";

fn now() -> PeerDiscoveryTime {
    PeerDiscoveryTime::from_millis(1_000)
}

fn query() -> DnsQuery {
    DnsQuery::new(ServiceDiscoveryInput::new(
        PeerLabel::new("test").unwrap(),
        DiscoveryTarget::new(HOST),
        ServiceDiscoveryMode::Address,
        PeerTransport::Udp,
        Some(1234),
    ))
    .unwrap()
    .with_address_family(AddressFamilyPolicy::Ipv4Only)
}

fn config(servers: Vec<SocketAddr>) -> DnsClientConfig {
    let mut config = DnsClientConfig::default();
    config.servers = servers;
    config.timeout = Duration::from_secs(2);
    config.attempts = 1;
    config
}

fn name(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for label in value
        .trim_end_matches('.')
        .split('.')
        .filter(|s| !s.is_empty())
    {
        bytes.push(u8::try_from(label.len()).unwrap());
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes
}

fn question_end(query: &[u8]) -> usize {
    let mut offset = 12;
    while query[offset] != 0 {
        offset += 1 + usize::from(query[offset]);
    }
    offset + 5
}

fn rr(owner: &str, kind: u16, ttl: u32, data: &[u8]) -> Vec<u8> {
    let mut bytes = name(owner);
    bytes.extend(kind.to_be_bytes());
    bytes.extend(1u16.to_be_bytes()); // IN
    bytes.extend(ttl.to_be_bytes());
    bytes.extend(u16::try_from(data.len()).unwrap().to_be_bytes());
    bytes.extend(data);
    bytes
}

fn a(owner: &str, ttl: u32, last: u8) -> Vec<u8> {
    rr(owner, 1, ttl, &[192, 0, 2, last])
}

fn cname(owner: &str, target: &str, ttl: u32) -> Vec<u8> {
    rr(owner, 5, ttl, &name(target))
}

fn soa(ttl: u32, minimum: u32) -> Vec<u8> {
    let mut data = name("ns.example.invalid.");
    data.extend(name("hostmaster.example.invalid."));
    for value in [1u32, 2, 3, 4, minimum] {
        data.extend(value.to_be_bytes());
    }
    rr("example.invalid.", 6, ttl, &data)
}

fn reply(query: &[u8], flags: u16, answers: &[Vec<u8>], authority: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = query[..question_end(query)].to_vec();
    bytes[2..4].copy_from_slice(&flags.to_be_bytes());
    bytes[6..8].copy_from_slice(&u16::try_from(answers.len()).unwrap().to_be_bytes());
    bytes[8..10].copy_from_slice(&u16::try_from(authority.len()).unwrap().to_be_bytes());
    bytes[10..12].fill(0);
    for record in answers.iter().chain(authority) {
        bytes.extend(record);
    }
    bytes
}

async fn udp_server<F>(respond: F) -> (SocketAddr, JoinHandle<()>)
where
    F: FnOnce(&[u8]) -> Vec<u8> + Send + 'static,
{
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        socket
            .send_to(&respond(&buffer[..len]), peer)
            .await
            .unwrap();
    });
    (address, handle)
}

#[tokio::test]
async fn sends_spec_question_and_edns_and_feeds_cache_with_real_ttls() {
    let (address, server) = udp_server(|q| {
        // RFC 1035 4.1: RD, one A/IN question. RFC 6891 6.1: one root OPT,
        // 1232-byte advertised payload, version zero, no flags or options.
        assert_eq!(&q[2..12], &[1, 0, 0, 1, 0, 0, 0, 0, 0, 1]);
        assert_eq!(&q[12..], b"\x04peer\x07example\x07invalid\x00\x00\x01\x00\x01\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00");
        reply(q, 0x8180, &[a(HOST, 300, 1)], &[])
    }).await;
    let client = DnsClient::new(config(vec![address])).unwrap();
    let response = client.resolve(&query(), now).await;
    assert_eq!(response.sources.len(), 1);
    assert_eq!(response.sources[0].server, address);
    assert_eq!(response.sources[0].record_type, DnsRecordType::A);
    assert_eq!(response.sources[0].transport, DnsTransport::Udp);
    let answer = response.result.unwrap();
    assert_eq!(
        answer.expires_at(),
        Some(PeerDiscoveryTime::from_millis(301_000))
    );
    assert_eq!(
        answer.candidates()[0].peer().endpoint,
        "192.0.2.1:1234".parse().unwrap()
    );
    let mut cache =
        DnsCache::default().with_ttl_caps(Duration::from_secs(10), Duration::from_secs(5));
    let DnsRefresh::Start(token) = cache
        .begin_refresh(&query(), now(), Duration::from_secs(1))
        .unwrap()
    else {
        panic!("admission")
    };
    assert!(cache.finish_refresh(token, Ok(answer), now()));
    let status = cache.lookup(&query().cache_key(), now());
    assert_eq!(
        status.fresh_until,
        Some(PeerDiscoveryTime::from_millis(11_000))
    );
    assert!(matches!(status.result, DnsCachedResult::Fresh(_)));
    assert!(matches!(
        cache
            .lookup(&query().cache_key(), status.fresh_until.unwrap())
            .result,
        DnsCachedResult::Stale { .. }
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn truncated_udp_retries_tcp_and_binds_both_transports() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (tcp, udp) = bind_dns_pair(tcp).await.unwrap();
    let address = tcp.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        let (len, peer) = udp.recv_from(&mut buffer).await.unwrap();
        assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));
        assert!(peer.port() >= 1024);
        let mut truncated = reply(&buffer[..len], 0x8380, &[], &[]);
        truncated[7] = 1; // TC permits an incomplete answer section.
        truncated.push(0xc0);
        udp.send_to(&truncated, peer).await.unwrap();
        let (mut stream, peer) = tcp.accept().await.unwrap();
        assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));
        assert!(peer.port() >= 1024);
        let len = stream.read_u16().await.unwrap() as usize;
        stream.read_exact(&mut buffer[..len]).await.unwrap();
        let bytes = reply(&buffer[..len], 0x8180, &[a(HOST, 20, 2)], &[]);
        stream.write_u16(bytes.len() as u16).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
    });
    let mut cfg = config(vec![address]);
    cfg.local_address = Some("127.0.0.2".parse().unwrap());
    let response = DnsClient::new(cfg).unwrap().resolve(&query(), now).await;
    assert_eq!(response.sources[0].transport, DnsTransport::Tcp);
    assert!(response.result.is_ok());
    server.await.unwrap();
}

#[tokio::test]
async fn formerr_retries_once_without_edns() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[10..12], &[0, 1]);
        socket
            .send_to(&reply(&buffer[..len], 0x8181, &[], &[]), peer)
            .await
            .unwrap();
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[10..12], &[0, 0]);
        assert_eq!(len, question_end(&buffer[..len]));
        socket
            .send_to(&reply(&buffer[..len], 0x8180, &[a(HOST, 20, 3)], &[]), peer)
            .await
            .unwrap();
    });
    let response = DnsClient::new(config(vec![address]))
        .unwrap()
        .resolve(&query(), now)
        .await;
    assert!(response.result.is_ok());
    server.await.unwrap();
}

#[tokio::test]
async fn mismatched_source_port_address_id_and_question_are_dropped_and_counted() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let valid = reply(&buffer[..len], 0x8180, &[a(HOST, 20, 4)], &[]);
        let rogue_port = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        rogue_port.send_to(&valid, peer).await.unwrap();
        let rogue_address = UdpSocket::bind(SocketAddr::new(
            "127.0.0.2".parse().unwrap(),
            address.port(),
        ))
        .await
        .unwrap();
        rogue_address.send_to(&valid, peer).await.unwrap();
        let mut wrong = valid.clone();
        wrong[0] ^= 1;
        socket.send_to(&wrong, peer).await.unwrap();
        let mut wrong = valid.clone();
        wrong[13] = b'x';
        socket.send_to(&wrong, peer).await.unwrap();
        let mut wrong = valid.clone();
        let end = question_end(&buffer[..len]);
        wrong[end - 3] = 28;
        socket.send_to(&wrong, peer).await.unwrap();
        let mut wrong = valid.clone();
        wrong[end - 1] = 3;
        socket.send_to(&wrong, peer).await.unwrap();
        socket.send_to(&valid, peer).await.unwrap();
    });
    let client = DnsClient::new(config(vec![address])).unwrap();
    assert!(client.resolve(&query(), now).await.result.is_ok());
    let stats = client.stats();
    assert_eq!(stats.source_mismatches, 2);
    assert_eq!(stats.id_mismatches, 1);
    assert_eq!(stats.question_mismatches, 3);
    server.await.unwrap();
}

#[tokio::test]
async fn cname_chain_and_rrset_minimum_ttls_are_preserved() {
    let (address, server) = udp_server(|q| {
        reply(
            q,
            0x8180,
            &[
                a(ALIAS, 60, 1),
                cname(HOST, ALIAS, 30),
                a(ALIAS, 40, 2),
                a("unrelated.invalid.", 1, 99),
            ],
            &[],
        )
    })
    .await;
    let answer = DnsClient::new(config(vec![address]))
        .unwrap()
        .resolve(&query(), now)
        .await
        .result
        .unwrap();
    assert_eq!(answer.candidates().len(), 2);
    assert_eq!(
        answer.expires_at(),
        Some(PeerDiscoveryTime::from_millis(31_000))
    );
    for candidate in answer.candidates() {
        let records = candidate.records().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, DnsRecordType::Cname);
        assert_eq!(records[0].ttl, 30);
        assert_eq!(records[1].ttl, 40);
    }
    server.await.unwrap();
}

#[tokio::test]
async fn high_bit_ttl_in_rrset_cannot_be_hidden_by_unsigned_minimum() {
    let (address, server) =
        udp_server(|q| reply(q, 0x8180, &[a(HOST, 60, 1), a(HOST, 0x8000_0000, 2)], &[])).await;
    let answer = DnsClient::new(config(vec![address]))
        .unwrap()
        .resolve(&query(), now)
        .await
        .result
        .unwrap();
    assert_eq!(answer.expires_at(), Some(now()));
    let mut cache = DnsCache::default();
    let DnsRefresh::Start(token) = cache
        .begin_refresh(&query(), now(), Duration::from_secs(1))
        .unwrap()
    else {
        panic!("admission")
    };
    assert!(cache.finish_refresh(token, Ok(answer), now()));
    let status = cache.lookup(&query().cache_key(), now());
    assert_eq!(status.fresh_until, Some(now()));
    assert!(matches!(status.result, DnsCachedResult::Stale { .. }));
    // Success refresh uses the separate five-second interval with equal
    // jitter, even though this zero TTL is never fresh.
    let retry_at = status.retry_at.unwrap();
    assert!((3_500..=6_000).contains(&retry_at.as_millis()));
    assert!(cache.refresh_due(now()).is_empty());
    assert_eq!(cache.refresh_due(retry_at), vec![query().cache_key()]);
    server.await.unwrap();
}

#[tokio::test]
async fn cname_loops_conflicts_and_chain_limit_are_rejected() {
    for records in [
        vec![cname(HOST, ALIAS, 30), cname(ALIAS, HOST, 30)],
        vec![cname(HOST, ALIAS, 30), a(HOST, 30, 1)],
        vec![cname(HOST, ALIAS, 30), cname(HOST, "other.invalid.", 30)],
        vec![
            cname(HOST, ALIAS, 30),
            cname(ALIAS, "other.invalid.", 30),
            a("other.invalid.", 30, 1),
        ],
    ] {
        let (address, server) = udp_server(move |q| reply(q, 0x8180, &records, &[])).await;
        let mut cfg = config(vec![address]);
        cfg.max_cname_chain = 1;
        assert_eq!(
            DnsClient::new(cfg)
                .unwrap()
                .resolve(&query(), now)
                .await
                .result,
            Err(DnsError::MalformedAnswer)
        );
        server.await.unwrap();
    }
}

#[tokio::test]
async fn negative_answers_with_and_without_soa_and_alias_expiry() {
    for rcode in [0u16, 3] {
        for with_soa in [false, true] {
            let (address, server) = udp_server(move |q| {
                reply(
                    q,
                    0x8180 | rcode,
                    &[cname(HOST, ALIAS, 7)],
                    &if with_soa { vec![soa(60, 20)] } else { vec![] },
                )
            })
            .await;
            let response = DnsClient::new(config(vec![address]))
                .unwrap()
                .resolve(&query(), now)
                .await;
            assert_eq!(response.sources[0].server, address);
            let error = response.result.unwrap_err();
            let negative = match (rcode, error) {
                (0, DnsError::NoData { soa }) | (3, DnsError::NxDomain { soa }) => soa,
                _ => panic!("wrong error: {error:?}"),
            };
            assert_eq!(negative.is_some(), with_soa);
            if let Some(negative) = negative {
                assert_eq!(negative.ttl(), Duration::from_secs(20));
                assert_eq!(negative.expires_at(), PeerDiscoveryTime::from_millis(8_000));
            }
            server.await.unwrap();
        }
    }
}

#[tokio::test]
async fn servfail_refused_and_malformed_answers_advance_to_configured_next_server() {
    for rcode in [2u16, 5, 1] {
        let (first, s1) = udp_server(move |q| reply(q, 0x8180 | rcode, &[], &[])).await;
        let (second, s2) = udp_server(|q| reply(q, 0x8180, &[a(HOST, 10, 1)], &[])).await;
        let mut cfg = config(vec![first, second]);
        // FORMERR fallback also has a finite budget, even if the server closes.
        cfg.timeout = Duration::from_millis(50);
        let response = DnsClient::new(cfg).unwrap().resolve(&query(), now).await;
        assert!(response.result.is_ok());
        assert_eq!(response.sources[0].server, second);
        s1.await.unwrap();
        s2.await.unwrap();
    }
}

#[tokio::test]
async fn exhausted_servfail_and_refused_remain_typed() {
    for (rcode, expected) in [(2, DnsError::ServFail), (5, DnsError::Refused)] {
        let (address, server) = udp_server(move |q| reply(q, 0x8180 | rcode, &[], &[])).await;
        let response = DnsClient::new(config(vec![address]))
            .unwrap()
            .resolve(&query(), now)
            .await;
        assert_eq!(response.result, Err(expected));
        assert_eq!(response.sources[0].server, address);
        server.await.unwrap();
    }
}

#[tokio::test]
async fn timeout_attempts_and_in_flight_admission_are_bounded_and_cancel_safe() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut cfg = config(vec![socket.local_addr().unwrap()]);
    cfg.timeout = Duration::from_secs(10);
    cfg.attempts = 2;
    cfg.max_in_flight = 1;
    let client = DnsClient::new(cfg).unwrap();
    let first_client = client.clone();
    let first = tokio::spawn(async move { first_client.resolve(&query(), now).await });
    let mut buffer = [0; 4096];
    socket.recv_from(&mut buffer).await.unwrap(); // Admission is now held.
    assert_eq!(
        client.resolve(&query(), now).await.result,
        Err(DnsError::Busy)
    );
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    let mut cfg = config(vec![socket.local_addr().unwrap()]);
    cfg.timeout = Duration::from_millis(30);
    cfg.attempts = 2;
    let second_client = DnsClient::new(cfg).unwrap();
    let second = tokio::spawn(async move { second_client.resolve(&query(), now).await });
    for _ in 0..2 {
        socket.recv_from(&mut buffer).await.unwrap();
    }
    assert_eq!(second.await.unwrap().result, Err(DnsError::Timeout));
    assert!(socket.try_recv_from(&mut buffer).is_err());
    // The cancelled query released the original client's admission slot.
    let retry_client = client.clone();
    let retry = tokio::spawn(async move { retry_client.resolve(&query(), now).await });
    let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
    socket
        .send_to(&reply(&buffer[..len], 0x8180, &[a(HOST, 10, 1)], &[]), peer)
        .await
        .unwrap();
    assert!(retry.await.unwrap().result.is_ok());
}

#[tokio::test]
async fn ipv6_transport_supports_aaaa_and_source_binding() {
    let socket = UdpSocket::bind("[::1]:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        assert_eq!(peer.ip(), "::1".parse::<IpAddr>().unwrap());
        let q = &buffer[..len];
        assert_eq!(&q[question_end(q) - 4..question_end(q)], &[0, 28, 0, 1]);
        let record = rr(
            HOST,
            28,
            30,
            &"2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        socket
            .send_to(&reply(q, 0x8180, &[record], &[]), peer)
            .await
            .unwrap();
    });
    let mut cfg = config(vec![address]);
    cfg.local_address = Some("::1".parse().unwrap());
    let answer = DnsClient::new(cfg)
        .unwrap()
        .resolve(
            &query().with_address_family(AddressFamilyPolicy::Ipv6Only),
            now,
        )
        .await
        .result
        .unwrap();
    assert_eq!(
        answer.candidates()[0].peer().endpoint,
        "[2001:db8::1]:1234".parse().unwrap()
    );
    server.await.unwrap();
}

#[tokio::test]
async fn referrals_cannot_redirect_queries_or_create_cached_denials() {
    let rogue = UdpSocket::bind("127.0.0.2:0").await.unwrap();
    let (first, s1) = udp_server(|q| {
        let mut response = reply(
            q,
            0x8180,
            &[],
            &[rr("example.invalid.", 2, 30, &name("ns.example.invalid."))],
        );
        response[11] = 1;
        response.extend(rr("ns.example.invalid.", 1, 30, &[127, 0, 0, 2]));
        response
    })
    .await;
    let (second, s2) = udp_server(|q| reply(q, 0x8180, &[a(HOST, 20, 1)], &[])).await;
    let response = DnsClient::new(config(vec![first, second]))
        .unwrap()
        .resolve(&query(), now)
        .await;
    assert!(response.result.is_ok());
    assert_eq!(response.sources[0].server, second);
    assert!(rogue.try_recv_from(&mut [0; 512]).is_err());
    s1.await.unwrap();
    s2.await.unwrap();
}

#[tokio::test]
async fn unrelated_soa_cannot_give_negative_cache_authority() {
    let (address, server) = udp_server(|q| {
        let mut unrelated = soa(30, 10);
        // Same wire length, different zone.
        unrelated[1] = b'x';
        reply(q, 0x8183, &[], &[unrelated])
    })
    .await;
    assert_eq!(
        DnsClient::new(config(vec![address]))
            .unwrap()
            .resolve(&query(), now)
            .await
            .result,
        Err(DnsError::NxDomain { soa: None })
    );
    server.await.unwrap();
}

#[tokio::test]
async fn malformed_answer_and_timeout_both_fail_over() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (bad, s1) = udp_server(|q| reply(q, 0x8180, &[rr(HOST, 1, 30, &[192, 0, 2])], &[])).await;
    let (good, s2) = udp_server(|q| reply(q, 0x8180, &[a(HOST, 30, 1)], &[])).await;
    let mut cfg = config(vec![silent.local_addr().unwrap(), bad, good]);
    cfg.timeout = Duration::from_millis(50);
    let client = DnsClient::new(cfg).unwrap();
    let response = client.resolve(&query(), now).await;
    assert!(response.result.is_ok());
    assert_eq!(response.sources[0].server, good);
    assert_eq!(client.stats().malformed_responses, 1);
    assert!(silent.try_recv_from(&mut [0; 512]).is_ok());
    s1.await.unwrap();
    s2.await.unwrap();
}

#[tokio::test]
async fn mismatch_flood_has_a_finite_receive_budget() {
    let (address, server) = udp_server(|q| {
        let mut bad = reply(q, 0x8180, &[a(HOST, 30, 1)], &[]);
        bad[0] ^= 1;
        bad
    })
    .await;
    let mut cfg = config(vec![address]);
    cfg.max_discarded_responses = 1;
    let client = DnsClient::new(cfg).unwrap();
    assert_eq!(
        client.resolve(&query(), now).await.result,
        Err(DnsError::MalformedAnswer)
    );
    assert_eq!(client.stats().id_mismatches, 1);
    server.await.unwrap();
}

#[tokio::test]
async fn tcp_checks_identity_before_accepting_a_frame() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (tcp, udp) = bind_dns_pair(tcp).await.unwrap();
    let address = tcp.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        let (len, peer) = udp.recv_from(&mut buffer).await.unwrap();
        udp.send_to(&reply(&buffer[..len], 0x8380, &[], &[]), peer)
            .await
            .unwrap();
        let (mut stream, _) = tcp.accept().await.unwrap();
        let len = stream.read_u16().await.unwrap() as usize;
        stream.read_exact(&mut buffer[..len]).await.unwrap();
        let valid = reply(&buffer[..len], 0x8180, &[a(HOST, 30, 1)], &[]);
        let mut wrong_id = valid.clone();
        wrong_id[0] ^= 1;
        let mut wrong_name = valid.clone();
        wrong_name[13] = b'x';
        for frame in [wrong_id, wrong_name, valid] {
            stream.write_u16(frame.len() as u16).await.unwrap();
            stream.write_all(&frame).await.unwrap();
        }
    });
    let client = DnsClient::new(config(vec![address])).unwrap();
    assert!(client.resolve(&query(), now).await.result.is_ok());
    assert_eq!(client.stats().id_mismatches, 1);
    assert_eq!(client.stats().question_mismatches, 1);
    server.await.unwrap();
}

#[tokio::test]
async fn dual_stack_outcomes_do_not_cache_partial_negatives() {
    for case in 0..5 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            for _ in 0..2 {
                let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
                let q = &buffer[..len];
                let kind = q[question_end(q) - 3];
                let bytes = match (case, kind) {
                    (0, 1) => reply(q, 0x8180, &[a(HOST, 30, 1)], &[]),
                    (0 | 1, 28) => reply(q, 0x8182, &[], &[]),
                    (2, 28) => reply(q, 0x8183, &[], &[]),
                    (3, 28) => reply(q, 0x8180, &[], &[soa(20, 7)]),
                    (_, 28) => reply(q, 0x8183, &[], &[soa(20, 7)]),
                    _ => reply(q, 0x8183, &[], &[soa(30, 20)]),
                };
                socket.send_to(&bytes, peer).await.unwrap();
            }
        });
        let response = DnsClient::new(config(vec![address]))
            .unwrap()
            .resolve(
                &query().with_address_family(AddressFamilyPolicy::DualStack),
                now,
            )
            .await;
        match (case, response.result) {
            (0, Ok(answer)) => assert_eq!(answer.candidates().len(), 1),
            (1, Err(DnsError::ServFail)) | (2, Err(DnsError::NxDomain { soa: None })) => {}
            (
                3,
                Err(DnsError::NoData {
                    soa: Some(negative),
                }),
            )
            | (
                4,
                Err(DnsError::NxDomain {
                    soa: Some(negative),
                }),
            ) => {
                assert_eq!(negative.expires_at(), PeerDiscoveryTime::from_millis(8_000));
            }
            (_, result) => panic!("unexpected case {case}: {result:?}"),
        }
        server.await.unwrap();
    }
}

#[tokio::test]
async fn partial_refresh_exposes_family_failures_and_bounds_cache_freshness() {
    for failed_kind in [1, 28] {
        for case in 0..8 {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = socket.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let mut buffer = [0; 4096];
                for index in 0..4 {
                    let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
                    let q = &buffer[..len];
                    let kind = u16::from(q[question_end(q) - 3]);
                    let bytes = if index < 2 || kind != failed_kind {
                        let ttl = if index < 2 && kind == failed_kind {
                            10
                        } else {
                            3600
                        };
                        let record = if kind == 1 {
                            a(HOST, ttl, 1)
                        } else {
                            rr(
                                HOST,
                                28,
                                ttl,
                                &"2001:db8::1"
                                    .parse::<std::net::Ipv6Addr>()
                                    .unwrap()
                                    .octets(),
                            )
                        };
                        reply(q, 0x8180, &[record], &[])
                    } else {
                        match case {
                            0 | 6 => reply(q, 0x8182, &[], &[]),
                            1 => reply(q, 0x8180, &[], &[soa(120, 60)]),
                            2 => reply(q, 0x8183, &[], &[soa(120, 60)]),
                            3 => reply(q, 0x8180, &[], &[]),
                            4 => continue, // One lost family reply.
                            5 => reply(q, 0x8185, &[], &[]),
                            _ => reply(q, 0x8180, &[], &[soa(120, 0)]),
                        }
                    };
                    socket.send_to(&bytes, peer).await.unwrap();
                }
            });
            let mut cfg = config(vec![address]);
            if case == 4 {
                // Allow healthy replies scheduling room while the dropped family times out.
                cfg.timeout = Duration::from_millis(500);
            }
            if case == 6 {
                cfg.partial_failure_ttl = Duration::from_secs(10);
            }
            let client = DnsClient::new(cfg).unwrap();
            let q = query().with_address_family(AddressFamilyPolicy::DualStack);
            let mut cache = DnsCache::default();
            let DnsRefresh::Start(token) = cache
                .begin_refresh(&q, now(), Duration::from_secs(1))
                .unwrap()
            else {
                panic!("admission")
            };
            let initial = client.resolve(&q, now).await.result.unwrap();
            assert_eq!(
                initial.candidates().len(),
                2,
                "initial case {case}, failed family {failed_kind}"
            );
            assert!(cache.finish_refresh(token, Ok(initial), now()));
            let refresh_time = PeerDiscoveryTime::from_millis(11_000);
            let DnsRefresh::Start(token) = cache
                .begin_refresh(&q, refresh_time, Duration::from_secs(1))
                .unwrap()
            else {
                panic!("refresh")
            };
            let response = client.resolve(&q, || refresh_time).await;
            assert_eq!(response.outcomes.len(), 2);
            let failed_type = if failed_kind == 1 {
                DnsRecordType::A
            } else {
                DnsRecordType::Aaaa
            };
            let failed = response
                .outcomes
                .iter()
                .find(|r| r.record_type == failed_type)
                .unwrap();
            assert!(failed.result.is_err());
            if case == 4 {
                assert_eq!(failed.result, Err(DnsError::Timeout));
            }
            assert_eq!(failed.owner, *q.name());
            assert_eq!(failed.observed_at, refresh_time);
            let healthy = response
                .outcomes
                .iter()
                .find(|r| r.record_type != failed_type)
                .unwrap();
            assert!(
                healthy.result.is_ok(),
                "case {case}, failed family {failed_kind}: {:?}",
                healthy.result
            );
            let deadline = PeerDiscoveryTime::from_millis(match case {
                1 | 2 => 71_000,
                6 => 21_000,
                7 => 11_000,
                _ => 311_000,
            });
            let answer = response.result.unwrap();
            assert_eq!(answer.candidates().len(), 1);
            assert_eq!(answer.candidates()[0].records().unwrap()[0].ttl, 3600);
            assert_eq!(answer.expires_at(), Some(deadline));
            assert!(cache.finish_refresh(token, Ok(answer), refresh_time));
            assert_eq!(
                cache.lookup(&q.cache_key(), refresh_time).fresh_until,
                Some(deadline)
            );
            assert!(matches!(
                cache.lookup(&q.cache_key(), deadline).result,
                DnsCachedResult::Stale { .. }
            ));
            server.await.unwrap();
        }
    }
}

#[test]
fn partial_failure_ttl_rejects_nonzero_subsecond_and_over_five_minutes() {
    for ttl in [
        Duration::from_nanos(1),
        Duration::from_millis(1),
        Duration::from_millis(999),
        Duration::from_secs(300) + Duration::from_nanos(1),
        Duration::from_secs(301),
    ] {
        let mut cfg = config(vec!["127.0.0.1:53".parse().unwrap()]);
        cfg.partial_failure_ttl = ttl;
        assert!(
            matches!(DnsClient::new(cfg), Err(DnsError::InvalidQuery)),
            "{ttl:?}"
        );
    }
    for ttl in [
        Duration::ZERO,
        Duration::from_secs(1),
        Duration::from_secs(300),
    ] {
        let mut cfg = config(vec!["127.0.0.1:53".parse().unwrap()]);
        cfg.partial_failure_ttl = ttl;
        assert!(DnsClient::new(cfg).is_ok(), "{ttl:?}");
    }
}

#[tokio::test]
async fn partial_denial_obeys_soa_and_cache_negative_cap() {
    for failed_kind in [1, 28] {
        for rcode in [0x8180, 0x8183] {
            // The one-day SOA must obey the same 600-second cap as a fully
            // negative entry. Neither that cap nor publication can extend TTLs.
            for (soa_ttl, positive_ttl, cap, expected_ms) in [
                (86_400, 172_800, Some(600), 601_000),
                (86_400, 172_800, None, 10_801_000),
                (60, 172_800, Some(600), 61_000),
                (86_400, 30, Some(600), 31_000),
                (86_400, 172_800, Some(0), 1_000),
            ] {
                let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let server_address = socket.local_addr().unwrap();
                let server = tokio::spawn(async move {
                    let mut buffer = [0; 4096];
                    for _ in 0..2 {
                        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
                        let q = &buffer[..len];
                        let kind = u16::from(q[question_end(q) - 3]);
                        let bytes = if kind == failed_kind {
                            reply(q, rcode, &[], &[soa(soa_ttl, soa_ttl)])
                        } else {
                            let record = if kind == 1 {
                                a(HOST, positive_ttl, 1)
                            } else {
                                rr(
                                    HOST,
                                    28,
                                    positive_ttl,
                                    &"2001:db8::1"
                                        .parse::<std::net::Ipv6Addr>()
                                        .unwrap()
                                        .octets(),
                                )
                            };
                            reply(q, 0x8180, &[record], &[])
                        };
                        socket.send_to(&bytes, peer).await.unwrap();
                    }
                });
                let q = query().with_address_family(AddressFamilyPolicy::DualStack);
                let response = DnsClient::new(config(vec![server_address]))
                    .unwrap()
                    .resolve(&q, now)
                    .await;
                let answer = response.result.unwrap();
                assert_eq!(answer.candidates().len(), 1);
                assert_eq!(
                    answer.candidates()[0].records().unwrap()[0].ttl,
                    positive_ttl
                );
                assert_eq!(
                    response
                        .outcomes
                        .iter()
                        .filter(|outcome| outcome.result.is_err())
                        .count(),
                    1
                );
                let mut cache = DnsCache::default();
                if let Some(cap) = cap {
                    cache =
                        cache.with_ttl_caps(Duration::from_secs(604_800), Duration::from_secs(cap));
                }
                let DnsRefresh::Start(token) = cache
                    .begin_refresh(&q, now(), Duration::from_secs(1))
                    .unwrap()
                else {
                    panic!("admission")
                };
                assert!(cache.finish_refresh(token, Ok(answer), now()));
                assert_eq!(
                    cache.lookup(&q.cache_key(), now()).fresh_until,
                    Some(PeerDiscoveryTime::from_millis(expected_ms))
                );
                assert!(matches!(
                    cache
                        .lookup(&q.cache_key(), PeerDiscoveryTime::from_millis(expected_ms))
                        .result,
                    DnsCachedResult::Stale { .. }
                ));
                if cap == Some(0) {
                    assert!(cache
                        .lookup(&q.cache_key(), now())
                        .retry_at
                        .is_some_and(|retry| retry > now()));
                }
                server.await.unwrap();
            }
        }
    }
}

#[tokio::test]
async fn candidate_limit_applies_after_ordering_and_full_rrset_ttl_calculation() {
    let (address, server) = udp_server(|q| {
        let mut records = (1..=16).map(|last| a(HOST, 30, last)).collect::<Vec<_>>();
        // The preferred, smaller-scope address appears after the output cap.
        records.push(rr(HOST, 1, 30, &[127, 0, 0, 7]));
        // An address outside the retained set still bounds the whole RRset TTL.
        records.push(a(HOST, 3, 99));
        reply(q, 0x8180, &records, &[])
    })
    .await;
    let client = DnsClient::new(config(vec![address])).unwrap();
    let answer = client.resolve(&query(), now).await.result.unwrap();
    let mut expected = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 7))];
    expected.extend((1..=15).map(|last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))));
    assert_eq!(
        answer
            .candidates()
            .iter()
            .map(|candidate| candidate.peer().endpoint.ip())
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        answer.expires_at(),
        Some(PeerDiscoveryTime::from_millis(4_000))
    );
    assert_eq!(client.stats().malformed_responses, 0);
    server.await.unwrap();
}

#[tokio::test]
async fn candidate_limit_orders_both_families_before_retaining_sixteen() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        for _ in 0..2 {
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let end = question_end(&buffer[..len]);
            let kind = u16::from_be_bytes([buffer[end - 4], buffer[end - 3]]);
            let records = match kind {
                1 => (1..=16).map(|last| a(HOST, 30, last)).collect::<Vec<_>>(),
                28 => {
                    let mut records = (1..=16)
                        .map(|last| {
                            let ip = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last);
                            rr(HOST, 28, 30, &ip.octets())
                        })
                        .collect::<Vec<_>>();
                    records.push(rr(HOST, 28, 30, &std::net::Ipv6Addr::LOCALHOST.octets()));
                    records
                }
                _ => panic!("unsupported question"),
            };
            socket
                .send_to(&reply(&buffer[..len], 0x8180, &records, &[]), peer)
                .await
                .unwrap();
        }
    });
    let response = DnsClient::new(config(vec![address]))
        .unwrap()
        .resolve(
            &query().with_address_family(AddressFamilyPolicy::DualStack),
            now,
        )
        .await;
    let answer = response.result.unwrap();
    let mut expected = vec![IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)];
    expected.extend(
        (1..=15)
            .map(|last| IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last))),
    );
    assert_eq!(
        answer
            .candidates()
            .iter()
            .map(|candidate| candidate.peer().endpoint.ip())
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(response.sources.len(), 2);
    for (index, candidate) in answer.candidates().iter().enumerate() {
        assert_eq!(candidate.peer().weight, u16::MAX - index as u16);
    }
    server.await.unwrap();
}

#[tokio::test]
async fn wire_name_failures_are_malformed_answers() {
    for case in 0..3 {
        let (address, server) = udp_server(move |q| {
            let mut response = reply(q, 0x8180, &[a(HOST, 30, 1)], &[]);
            match case {
                0 => response[12] = 0x40,              // Reserved question label tag.
                1 => response[question_end(q)] = 0x40, // Reserved answer-owner tag.
                _ => {
                    response = reply(q, 0x8180, &[cname(HOST, "bad!.example.invalid.", 30)], &[]);
                }
            }
            response
        })
        .await;
        let mut cfg = config(vec![address]);
        cfg.timeout = Duration::from_millis(200);
        let client = DnsClient::new(cfg).unwrap();
        assert_eq!(
            client.resolve(&query(), now).await.result,
            Err(DnsError::MalformedAnswer),
            "wire name case {case}"
        );
        assert_eq!(client.stats().malformed_responses, 1);
        assert_eq!(client.stats().question_mismatches, 0);
        server.await.unwrap();
    }
}

#[tokio::test]
async fn unavailable_source_does_not_fall_back_to_a_different_local_address() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut cfg = config(vec![socket.local_addr().unwrap()]);
    cfg.local_address = Some("::1".parse().unwrap());
    assert_eq!(
        DnsClient::new(cfg)
            .unwrap()
            .resolve(&query(), now)
            .await
            .result,
        Err(DnsError::SourceUnavailable)
    );
    assert!(socket.try_recv_from(&mut [0; 512]).is_err());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn nonexistent_interface_is_a_typed_source_failure() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut cfg = config(vec![socket.local_addr().unwrap()]);
    cfg.interface = Some("opc-dns-missing".into());
    assert_eq!(
        DnsClient::new(cfg)
            .unwrap()
            .resolve(&query(), now)
            .await
            .result,
        Err(DnsError::SourceUnavailable)
    );
    assert!(socket.try_recv_from(&mut [0; 512]).is_err());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_interface_binding_is_applied_to_udp_and_tcp() {
    let probe = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .unwrap();
    let permitted = probe.bind_device(Some(b"lo")).is_ok();
    drop(probe);
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (tcp, udp) = bind_dns_pair(tcp).await.unwrap();
    let address = tcp.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        let (len, peer) = udp.recv_from(&mut buffer).await.unwrap();
        udp.send_to(&reply(&buffer[..len], 0x8380, &[], &[]), peer)
            .await
            .unwrap();
        let (mut stream, _) = tcp.accept().await.unwrap();
        let len = stream.read_u16().await.unwrap() as usize;
        stream.read_exact(&mut buffer[..len]).await.unwrap();
        let frame = reply(&buffer[..len], 0x8180, &[a(HOST, 30, 1)], &[]);
        stream.write_u16(frame.len() as u16).await.unwrap();
        stream.write_all(&frame).await.unwrap();
    });
    let mut cfg = config(vec![address]);
    cfg.interface = Some("lo".into());
    let response = DnsClient::new(cfg).unwrap().resolve(&query(), now).await;
    // Linux can deny SO_BINDTODEVICE to an unprivileged process. That must
    // fail closed, never retry unbound. The companion missing-device test
    // exercises the same error mapping even on hosts permitting this call.
    if !permitted {
        assert_eq!(response.result, Err(DnsError::SourceUnavailable));
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    } else {
        assert!(response.result.is_ok());
        assert_eq!(response.sources[0].transport, DnsTransport::Tcp);
        server.await.unwrap();
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn non_linux_interface_binding_fails_explicitly() {
    let mut cfg = config(vec!["127.0.0.1:53".parse().unwrap()]);
    cfg.interface = Some("loopback".into());
    assert!(matches!(
        DnsClient::new(cfg),
        Err(DnsError::SourceUnavailable)
    ));
}

#[tokio::test]
async fn client_response_and_source_debug_redact_names_and_addresses() {
    let (address, server) = udp_server(|q| reply(q, 0x8180, &[a(HOST, 30, 1)], &[])).await;
    let client = DnsClient::new(config(vec![address])).unwrap();
    let response = client.resolve(&query(), now).await;
    let text = format!("{client:?} {response:?} {:?}", response.sources);
    for secret in [HOST, "192.0.2.1", "127.0.0.1"] {
        assert!(!text.contains(secret));
    }
    server.await.unwrap();
}

#[tokio::test]
async fn udp_and_tcp_response_limits_reject_oversized_frames() {
    let (address, server) = udp_server(|q| {
        let mut response = reply(q, 0x8180, &[a(HOST, 20, 1)], &[]);
        response.resize(513, 0);
        response
    })
    .await;
    let mut cfg = config(vec![address]);
    cfg.edns_payload_size = 512;
    cfg.max_response_size = 512;
    cfg.timeout = Duration::from_millis(30);
    let client = DnsClient::new(cfg).unwrap();
    assert_eq!(
        client.resolve(&query(), now).await.result,
        Err(DnsError::Timeout)
    );
    assert_eq!(client.stats().oversized_responses, 1);
    server.await.unwrap();

    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (tcp, udp) = bind_dns_pair(tcp).await.unwrap();
    let address = tcp.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        let (len, peer) = udp.recv_from(&mut buffer).await.unwrap();
        udp.send_to(&reply(&buffer[..len], 0x8380, &[], &[]), peer)
            .await
            .unwrap();
        let (mut stream, _) = tcp.accept().await.unwrap();
        let len = stream.read_u16().await.unwrap() as usize;
        stream.read_exact(&mut buffer[..len]).await.unwrap();
        stream.write_u16(513).await.unwrap(); // No body: reject before allocation/read.
    });
    let mut cfg = config(vec![address]);
    cfg.edns_payload_size = 512;
    cfg.max_response_size = 512;
    let client = DnsClient::new(cfg).unwrap();
    assert_eq!(
        client.resolve(&query(), now).await.result,
        Err(DnsError::MalformedAnswer)
    );
    assert_eq!(client.stats().oversized_responses, 1);
    server.await.unwrap();
}

#[tokio::test]
async fn dual_stack_queries_aaaa_and_a_and_retains_observation_times() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        let mut kinds = Vec::new();
        for _ in 0..2 {
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let end = question_end(&buffer[..len]);
            let kind = u16::from_be_bytes([buffer[end - 4], buffer[end - 3]]);
            kinds.push(kind);
            let record = match kind {
                1 => a(HOST, 30, 1),
                28 => rr(
                    HOST,
                    28,
                    60,
                    &"2001:db8::1"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets(),
                ),
                _ => panic!("unsupported question"),
            };
            socket
                .send_to(&reply(&buffer[..len], 0x8180, &[record], &[]), peer)
                .await
                .unwrap();
        }
        kinds.sort();
        assert_eq!(kinds, [1, 28]);
    });
    let observation = std::cell::Cell::new(1_000);
    let response = DnsClient::new(config(vec![address]))
        .unwrap()
        .resolve(
            &query().with_address_family(AddressFamilyPolicy::DualStack),
            || {
                let time = observation.get();
                observation.set(time + 1_000);
                PeerDiscoveryTime::from_millis(time)
            },
        )
        .await;
    assert_eq!(response.sources.len(), 2);
    let answer = response.result.unwrap();
    assert_eq!(answer.candidates().len(), 2);
    assert!(answer.candidates()[0].peer().endpoint.is_ipv6());
    let ipv4 = answer
        .candidates()
        .iter()
        .find(|c| c.peer().endpoint.is_ipv4())
        .unwrap();
    assert_eq!(ipv4.records().unwrap()[0].observed_at, now());
    assert_eq!(
        answer.expires_at(),
        Some(PeerDiscoveryTime::from_millis(31_000))
    );
    server.await.unwrap();
}

#[test]
fn resolv_conf_is_bounded_and_search_is_never_used() {
    let parsed = DnsClientConfig::from_resolv_conf("# local configuration\nnameserver 192.0.2.53\nnameserver 2001:db8::53 ; comment\nsearch private.invalid\ndomain private.invalid\noptions ndots:5 timeout:3 attempts:4 rotate\n").unwrap();
    assert_eq!(
        parsed.servers,
        [
            "192.0.2.53:53".parse().unwrap(),
            "[2001:db8::53]:53".parse().unwrap()
        ]
    );
    assert_eq!(parsed.timeout, Duration::from_secs(3));
    assert_eq!(parsed.attempts, 4);
    assert!(DnsClientConfig::from_resolv_conf("search example.invalid").is_err());
    assert!(DnsClientConfig::from_resolv_conf("nameserver not-an-ip").is_err());
    assert!(DnsClientConfig::from_resolv_conf(&"x".repeat(65_537)).is_err());
    assert!(DnsClientConfig::from_resolv_conf(&"nameserver 192.0.2.53\n".repeat(9)).is_err());
}

#[test]
fn client_rejects_invalid_resource_limits() {
    let base = config(vec!["127.0.0.1:53".parse().unwrap()]);
    let mut invalid = Vec::new();
    let mut cfg = base.clone();
    cfg.servers.clear();
    invalid.push(cfg);
    let mut cfg = base.clone();
    cfg.timeout = Duration::ZERO;
    invalid.push(cfg);
    let mut cfg = base.clone();
    cfg.attempts = 0;
    invalid.push(cfg);
    let mut cfg = base.clone();
    cfg.max_in_flight = 0;
    invalid.push(cfg);
    let mut cfg = base.clone();
    cfg.max_in_flight = usize::MAX;
    invalid.push(cfg);
    let mut cfg = base.clone();
    cfg.max_response_size = usize::MAX;
    invalid.push(cfg);
    let mut cfg = base.clone();
    cfg.max_cname_chain = 16;
    invalid.push(cfg);
    let mut cfg = base.clone();
    cfg.edns_payload_size = 511;
    invalid.push(cfg);
    let mut cfg = base;
    cfg.servers[0].set_port(0);
    invalid.push(cfg);
    for cfg in invalid {
        assert!(DnsClient::new(cfg).is_err());
    }
}

#[tokio::test]
async fn profiles_planes_and_missing_snaptr_filter_fail_before_io() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = DnsClient::new(config(vec![socket.local_addr().unwrap()])).unwrap();
    let different = query().with_resolver_profile(ResolverProfileId::new("different"));
    assert_eq!(
        client.resolve(&different, now).await.result,
        Err(DnsError::Unavailable)
    );
    let different = query().with_source_plane(SourcePlaneId::new("different"));
    assert_eq!(
        client.resolve(&different, now).await.result,
        Err(DnsError::SourceUnavailable)
    );
    let mut input = query().input().clone();
    input.mode = ServiceDiscoveryMode::Snaptr;
    assert_eq!(
        client
            .resolve(&DnsQuery::new(input).unwrap(), now)
            .await
            .result,
        Err(DnsError::InvalidQuery)
    );
    assert!(socket.try_recv_from(&mut [0; 512]).is_err());
}

#[test]
fn config_debug_redacts_addresses_and_identity() {
    let mut cfg = config(vec!["192.0.2.53:53".parse().unwrap()]);
    cfg.local_address = Some("127.0.0.2".parse().unwrap());
    cfg.interface = Some("private-device".into());
    cfg.resolver_profile = ResolverProfileId::new("private-profile");
    cfg.source_plane = SourcePlaneId::new("private-plane");
    let rendered = format!("{cfg:?}");
    for secret in [
        "192.0.2.53",
        "127.0.0.2",
        "private-device",
        "private-profile",
        "private-plane",
    ] {
        assert!(!rendered.contains(secret));
    }
}

#[tokio::test]
async fn query_ids_and_ports_are_unpredictable_and_follow_host_port_policy() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        let mut ids = Vec::new();
        let mut ports = Vec::new();
        for _ in 0..32 {
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            ids.push(u16::from_be_bytes([buffer[0], buffer[1]]));
            ports.push(peer.port());
            assert!(peer.port() >= 1024);
            socket
                .send_to(&reply(&buffer[..len], 0x8180, &[a(HOST, 30, 1)], &[]), peer)
                .await
                .unwrap();
        }
        (ids, ports)
    });
    let client = DnsClient::new(config(vec![address])).unwrap();
    for _ in 0..32 {
        assert!(client.resolve(&query(), now).await.result.is_ok());
    }
    let (ids, ports) = server.await.unwrap();
    for (label, values) in [("query IDs", &ids), ("source ports", &ports)] {
        assert!(
            values.iter().any(|value| *value != values[0]),
            "fixed entropy source"
        );
        // Parallel tests can consume intervening values from a shared
        // sequential allocator. Unequal gaps must not hide that sequence.
        let descents = values.windows(2).filter(|pair| pair[1] < pair[0]).count();
        assert!((2..=29).contains(&descents), "{label}: {descents} descents");
    }
    #[cfg(target_os = "linux")]
    {
        let range = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").unwrap();
        let range: Vec<u16> = range
            .split_whitespace()
            .map(|s| s.parse().unwrap())
            .collect();
        assert!(ports
            .iter()
            .all(|port| (range[0]..=range[1]).contains(port)));
        let reserved =
            std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_reserved_ports").unwrap();
        for segment in reserved.trim().split(',').filter(|s| !s.is_empty()) {
            let (first, last) = segment.split_once('-').unwrap_or((segment, segment));
            let reserved = first.parse::<u16>().unwrap()..=last.parse::<u16>().unwrap();
            assert!(ports.iter().all(|port| !reserved.contains(port)));
        }
    }
}

#[tokio::test]
async fn replies_to_another_local_destination_are_not_accepted() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let mut wrong_destination = peer;
        wrong_destination.set_ip("127.0.0.2".parse().unwrap());
        socket
            .send_to(
                &reply(&buffer[..len], 0x8180, &[a(HOST, 30, 66)], &[]),
                wrong_destination,
            )
            .await
            .unwrap();
        socket
            .send_to(&reply(&buffer[..len], 0x8180, &[a(HOST, 30, 1)], &[]), peer)
            .await
            .unwrap();
    });
    let answer = DnsClient::new(config(vec![address]))
        .unwrap()
        .resolve(&query(), now)
        .await
        .result
        .unwrap();
    assert_eq!(
        answer.candidates()[0].peer().endpoint.ip().to_string(),
        "192.0.2.1"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn truncation_over_tcp_is_rejected() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (tcp, udp) = bind_dns_pair(tcp).await.unwrap();
    let address = tcp.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        let (len, peer) = udp.recv_from(&mut buffer).await.unwrap();
        udp.send_to(&reply(&buffer[..len], 0x8380, &[], &[]), peer)
            .await
            .unwrap();
        let (mut stream, _) = tcp.accept().await.unwrap();
        let len = usize::from(stream.read_u16().await.unwrap());
        stream.read_exact(&mut buffer[..len]).await.unwrap();
        let bytes = reply(&buffer[..len], 0x8380, &[a(HOST, 30, 1)], &[]);
        stream.write_u16(bytes.len() as u16).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
    });
    let client = DnsClient::new(config(vec![address])).unwrap();
    assert_eq!(
        client.resolve(&query(), now).await.result,
        Err(DnsError::MalformedAnswer)
    );
    assert_eq!(client.stats().malformed_responses, 1);
    server.await.unwrap();
}

#[tokio::test]
async fn cname_cycle_is_rejected_with_the_default_chain_limit() {
    let (address, server) = udp_server(|q| {
        reply(
            q,
            0x8180,
            &[cname(HOST, ALIAS, 30), cname(ALIAS, HOST, 30)],
            &[],
        )
    })
    .await;
    assert_eq!(
        DnsClient::new(config(vec![address]))
            .unwrap()
            .resolve(&query(), now)
            .await
            .result,
        Err(DnsError::MalformedAnswer)
    );
    server.await.unwrap();
}

#[tokio::test]
async fn oversized_udp_packets_are_dropped_before_a_valid_reply() {
    for matching_id in [false, true] {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let valid = reply(&buffer[..len], 0x8180, &[a(HOST, 30, 1)], &[]);
            let mut oversized = valid.clone();
            if !matching_id {
                oversized[0] ^= 1;
            }
            oversized.resize(1300, 0);
            socket.send_to(&oversized, peer).await.unwrap();
            socket.send_to(&valid, peer).await.unwrap();
        });
        let client = DnsClient::new(config(vec![address])).unwrap();
        assert!(client.resolve(&query(), now).await.result.is_ok());
        assert_eq!(client.stats().oversized_responses, 1);
        server.await.unwrap();
    }
}

#[test]
fn scoped_link_local_nameservers_are_skipped_without_discarding_other_servers() {
    let config = DnsClientConfig::from_resolv_conf(
        "nameserver fe80::1%eth0\nnameserver 192.0.2.53\nnameserver fe80::2%3\n",
    )
    .unwrap();
    assert_eq!(config.servers, ["192.0.2.53:53".parse().unwrap()]);
    assert!(matches!(
        DnsClientConfig::from_resolv_conf("nameserver fe80::1%eth0\n"),
        Err(DnsError::Unavailable)
    ));
    assert!(matches!(
        DnsClientConfig::from_resolv_conf("nameserver not-an-ip%eth0\n"),
        Err(DnsError::InvalidQuery)
    ));
}

#[tokio::test]
async fn binary_soa_names_and_unrelated_owners_preserve_negative_authority() {
    let (address, server) = udp_server(|q| {
        // RFC 2181 section 11 allows binary labels, including a literal dot
        // in RNAME's first label and non-UTF8 bytes in unused MNAME labels.
        let mut data = vec![3, 0xff, 0, 0x80, 0];
        data.extend([9, b'd', b'n', b's', b'.', b'a', b'd', b'm', b'i', b'n']);
        data.extend(name("example.invalid."));
        for value in [1u32, 2, 3, 4, 7] {
            data.extend(value.to_be_bytes());
        }
        reply(
            q,
            0x8183,
            &[a("unrelated+.example.invalid.", 60, 99)],
            &[rr("example.invalid.", 6, 30, &data)],
        )
    })
    .await;
    let client = DnsClient::new(config(vec![address])).unwrap();
    let response = client.resolve(&query(), now).await;
    assert!(
        matches!(response.result, Err(DnsError::NxDomain { soa: Some(soa) }) if soa.expires_at() == PeerDiscoveryTime::from_millis(8_000))
    );
    assert_eq!(client.stats().malformed_responses, 0);
    server.await.unwrap();
}

#[tokio::test]
async fn literal_dots_inside_owner_labels_cannot_alias_question_labels() {
    let (address, server) = udp_server(|q| {
        let mut owner = vec![20];
        owner.extend(b"peer.example.invalid");
        owner.push(0);
        owner.extend([0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 66]);
        reply(q, 0x8180, &[owner, a(HOST, 30, 1)], &[])
    })
    .await;
    let answer = DnsClient::new(config(vec![address]))
        .unwrap()
        .resolve(&query(), now)
        .await
        .result
        .unwrap();
    assert_eq!(answer.candidates().len(), 1);
    assert_eq!(
        answer.candidates()[0].peer().endpoint.ip().to_string(),
        "192.0.2.1"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn binary_question_mismatch_is_dropped_without_poisoning_the_exchange() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let valid = reply(&buffer[..len], 0x8180, &[a(HOST, 30, 1)], &[]);
        let mut mismatch = valid.clone();
        mismatch[13] = 0xff;
        socket.send_to(&mismatch, peer).await.unwrap();
        socket.send_to(&valid, peer).await.unwrap();
    });
    let client = DnsClient::new(config(vec![address])).unwrap();
    assert!(client.resolve(&query(), now).await.result.is_ok());
    assert_eq!(client.stats().question_mismatches, 1);
    assert_eq!(client.stats().malformed_responses, 0);
    server.await.unwrap();
}
