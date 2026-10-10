use super::*;

pub(super) const ROOT: &str = "ims.apn.epc.mnc001.mcc001.3gppnetwork.org.";
pub(super) const REALM: &str = "nai.epc.mnc001.mcc001.3gppnetwork.org.";
pub(super) const CHILD: &str = "delegated.example.invalid.";
pub(super) const HOST: &str = "pgw.example.invalid.";
pub(super) const OTHER: &str = "other.example.invalid.";
pub(super) const SERVICE: &str = "x-3gpp-pgw:x-s2b-gtp";

pub(super) fn time(ms: u64) -> PeerDiscoveryTime {
    PeerDiscoveryTime::from_millis(ms)
}

pub(super) fn now() -> PeerDiscoveryTime {
    time(1_000)
}

pub(super) fn query_for(root: &str, service: &str, protocol: &str) -> DnsQuery {
    DnsQuery::new(ServiceDiscoveryInput::new(
        PeerLabel::new("discovery-test").unwrap(),
        DiscoveryTarget::new(root),
        ServiceDiscoveryMode::Snaptr,
        if service.starts_with("aaa") {
            PeerTransport::Sctp
        } else {
            PeerTransport::Udp
        },
        Some(if service.starts_with("aaa") {
            3868
        } else {
            2123
        }),
    ))
    .unwrap()
    .with_address_family(AddressFamilyPolicy::Ipv4Only)
    .with_snaptr_filter(SnaptrFilter::new(service, protocol, SnaptrOrdering::Rfc3958).unwrap())
    .unwrap()
}

pub(super) fn query() -> DnsQuery {
    query_for(ROOT, "x-3gpp-pgw", "x-s2b-gtp")
}

// Match external callers of this non-exhaustive public configuration.
#[allow(clippy::field_reassign_with_default)]
pub(super) fn config(server: SocketAddr) -> DnsClientConfig {
    let mut config = DnsClientConfig::default();
    config.servers = vec![server];
    config.timeout = Duration::from_secs(2);
    config.attempts = 1;
    config.snaptr_refresh_timeout = Duration::from_secs(2);
    config
}

pub(super) fn name(value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in value
        .trim_end_matches('.')
        .split('.')
        .filter(|s| !s.is_empty())
    {
        out.push(u8::try_from(label.len()).unwrap());
        out.extend(label.as_bytes());
    }
    out.push(0);
    out
}

pub(super) fn question(bytes: &[u8]) -> (String, u16, usize) {
    let mut pos = 12;
    let mut owner = String::new();
    while bytes[pos] != 0 {
        let len = usize::from(bytes[pos]);
        owner.push_str(std::str::from_utf8(&bytes[pos + 1..pos + 1 + len]).unwrap());
        owner.push('.');
        pos += len + 1;
    }
    (
        owner,
        u16::from_be_bytes([bytes[pos + 1], bytes[pos + 2]]),
        pos + 5,
    )
}

pub(super) fn rr(owner: &str, kind: u16, ttl: u32, data: &[u8]) -> Vec<u8> {
    let mut out = name(owner);
    out.extend(kind.to_be_bytes());
    out.extend(1u16.to_be_bytes());
    out.extend(ttl.to_be_bytes());
    out.extend(u16::try_from(data.len()).unwrap().to_be_bytes());
    out.extend(data);
    out
}

#[allow(clippy::too_many_arguments)]
pub(super) fn naptr(
    owner: &str,
    order: u16,
    preference: u16,
    flags: &str,
    services: &str,
    regexp: &str,
    replacement: &str,
    ttl: u32,
) -> Vec<u8> {
    let mut data = order.to_be_bytes().to_vec();
    data.extend(preference.to_be_bytes());
    for value in [flags, services, regexp] {
        data.push(u8::try_from(value.len()).unwrap());
        data.extend(value.as_bytes());
    }
    data.extend(name(replacement));
    rr(owner, 35, ttl, &data)
}

pub(super) fn address(owner: &str, ip: &str, ttl: u32) -> Vec<u8> {
    match ip.parse::<IpAddr>().unwrap() {
        IpAddr::V4(ip) => rr(owner, 1, ttl, &ip.octets()),
        IpAddr::V6(ip) => rr(owner, 28, ttl, &ip.octets()),
    }
}

pub(super) fn srv(
    owner: &str,
    priority: u16,
    weight: u16,
    port: u16,
    target: &str,
    ttl: u32,
) -> Vec<u8> {
    let mut data = priority.to_be_bytes().to_vec();
    data.extend(weight.to_be_bytes());
    data.extend(port.to_be_bytes());
    data.extend(name(target));
    rr(owner, 33, ttl, &data)
}

pub(super) fn soa(zone: &str, ttl: u32, minimum: u32) -> Vec<u8> {
    let mut data = name("ns.example.invalid.");
    data.extend(name("hostmaster.example.invalid."));
    for value in [1, 2, 3, 4, minimum] {
        data.extend(value.to_be_bytes());
    }
    rr(zone, 6, ttl, &data)
}

pub(super) fn reply(
    q: &[u8],
    rcode: u16,
    answers: &[Vec<u8>],
    authority: &[Vec<u8>],
    additional: &[Vec<u8>],
) -> Vec<u8> {
    let mut out = q[..question(q).2].to_vec();
    out[2..4].copy_from_slice(&(0x8180 | rcode).to_be_bytes());
    for (offset, records) in [(6, answers), (8, authority), (10, additional)] {
        out[offset..offset + 2]
            .copy_from_slice(&u16::try_from(records.len()).unwrap().to_be_bytes());
    }
    for record in answers.iter().chain(authority).chain(additional) {
        out.extend(record);
    }
    out
}

pub(super) fn start(
    cache: &mut DnsCache,
    query: &DnsQuery,
    at: PeerDiscoveryTime,
) -> DnsRefreshToken {
    match cache
        .begin_refresh(query, at, Duration::from_secs(3))
        .unwrap()
    {
        DnsRefresh::Start(token) => token,
        other => panic!("unexpected admission: {other:?}"),
    }
}
