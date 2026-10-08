//! Minimal, bounded stub-client codec, not a recursive resolver or DNSSEC
//! validator. RFC 1035 sections 4.1.1–4.1.4 define the envelope/compression;
//! RFC 3596 section 2.2 defines AAAA; RFC 6891 section 6.1 defines OPT.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::{
    DnsCandidate, DnsError, DnsName, DnsQuery, DnsRecord, DnsRecordType, NegativeSoa,
    PeerCandidate, PeerDiscoveryTime,
};

const MAX_RECORDS: usize = 128;
const MAX_NAME_STEPS: usize = 256;

#[path = "dns_wire_srv.rs"]
mod srv;
pub(crate) use srv::{valid_host, SrvAnswer, SrvRecord};

pub(crate) fn encode(id: u16, name: &DnsName, kind: u16, edns: Option<u16>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(288);
    for field in [id, 0x0100, 1, 0, 0, u16::from(edns.is_some())] {
        bytes.extend(field.to_be_bytes());
    }
    for label in name
        .as_str()
        .trim_end_matches('.')
        .split('.')
        .filter(|s| !s.is_empty())
    {
        // DnsName validates the RFC 1035 section 2.3.4 63-octet label limit.
        bytes.push(label.len() as u8);
        bytes.extend(label.as_bytes());
    }
    bytes.push(0);
    bytes.extend(kind.to_be_bytes());
    bytes.extend(1u16.to_be_bytes());
    if let Some(size) = edns {
        bytes.extend([0, 0, 41]); // root owner, OPT
        bytes.extend(size.to_be_bytes());
        bytes.extend([0; 6]); // extended RCODE, version, flags, RDLEN
    }
    bytes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecodeError {
    Id,
    Question,
    Malformed,
}

pub(crate) struct Message {
    pub(crate) truncated: bool,
    pub(crate) rcode: u16,
    answers: Vec<Record>,
    authority: Vec<Record>,
    additional: Vec<Record>,
}

struct Record {
    // None is a well-framed binary name outside the public query-name
    // alphabet. It cannot match an ASCII query owner (RFC 2181 section 11).
    owner: Option<DnsName>,
    kind: u16,
    class: u16,
    ttl: u32,
    data: Data,
}

enum Data {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(Option<DnsName>),
    Soa {
        minimum: u32,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: Option<DnsName>,
    },
    Other,
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
    // Compression offsets have 14 bits. Retain a fixed-size bitmap of actual
    // decoded label boundaries, never accept offsets into scalar/RDATA bytes.
    labels: [u8; 2048],
}

impl Reader<'_> {
    fn take(&mut self, len: usize) -> Result<&[u8], DecodeError> {
        let end = self.pos.checked_add(len).ok_or(DecodeError::Malformed)?;
        let value = self
            .bytes
            .get(self.pos..end)
            .ok_or(DecodeError::Malformed)?;
        self.pos = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn name(&mut self) -> Result<Option<DnsName>, DecodeError> {
        let mut cursor = self.pos;
        let mut end = None;
        let mut text = Some(String::new());
        let mut wire_len = 1;
        for _ in 0..MAX_NAME_STEPS {
            let tag = *self.bytes.get(cursor).ok_or(DecodeError::Malformed)?;
            if cursor < 16_384 {
                self.labels[cursor / 8] |= 1 << (cursor % 8);
            }
            match tag & 0xc0 {
                0xc0 => {
                    let low = *self.bytes.get(cursor + 1).ok_or(DecodeError::Malformed)?;
                    let target = (usize::from(tag & 0x3f) << 8) | usize::from(low);
                    // RFC 1035 4.1.4: a pointer replaces a *prior* occurrence.
                    // Disallow header/forward pointers; the step limit also
                    // bounds cycles involving labels followed by pointers.
                    if target < 12
                        || target >= cursor
                        || self.labels[target / 8] & (1 << (target % 8)) == 0
                    {
                        return Err(DecodeError::Malformed);
                    }
                    end.get_or_insert(cursor + 2);
                    cursor = target;
                }
                0 => {
                    cursor += 1;
                    if tag == 0 {
                        self.pos = end.unwrap_or(cursor);
                        return text
                            .map(|text| DnsName::new(if text.is_empty() { "." } else { &text }))
                            .transpose()
                            .map_err(|_| DecodeError::Malformed);
                    }
                    let len = usize::from(tag);
                    wire_len += len + 1;
                    if wire_len > 255 {
                        return Err(DecodeError::Malformed);
                    }
                    let label = self
                        .bytes
                        .get(cursor..cursor + len)
                        .ok_or(DecodeError::Malformed)?;
                    // RFC 2181 section 11 allows arbitrary label bytes. Keep
                    // framing/compression validation for every name, but only
                    // project representable names into the public ASCII type.
                    // In particular, a literal dot cannot forge a label boundary.
                    if !label
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
                    {
                        text = None;
                    } else if let Some(text) = &mut text {
                        if !text.is_empty() {
                            text.push('.');
                        }
                        text.extend(label.iter().copied().map(char::from));
                    }
                    cursor += len;
                }
                _ => return Err(DecodeError::Malformed),
            }
        }
        Err(DecodeError::Malformed)
    }

    fn record(&mut self) -> Result<Record, DecodeError> {
        let owner = self.name()?;
        let kind = self.u16()?;
        let class = self.u16()?;
        let ttl = self.u32()?;
        let len = usize::from(self.u16()?);
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(DecodeError::Malformed)?;
        let data = match (kind, class) {
            (1, 1) if len == 4 => {
                let bytes = self.take(4)?;
                Data::A(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
            }
            (28, 1) if len == 16 => {
                let mut bytes = [0; 16];
                bytes.copy_from_slice(self.take(16)?);
                Data::Aaaa(Ipv6Addr::from(bytes))
            }
            (1 | 28, 1) => return Err(DecodeError::Malformed),
            (5, 1) => Data::Cname(self.name()?),
            // RFC 3597 section 4: receive legacy compressed SRV targets,
            // despite the sender restriction in RFC 2782. All normal pointer
            // boundary, backward-reference and expansion limits still apply.
            (33, 1) => Data::Srv {
                priority: self.u16()?,
                weight: self.u16()?,
                port: self.u16()?,
                target: self.name()?,
            },
            // Parse name-bearing legacy RDATA even when its semantics are
            // unused, so subsequent compression can reference its labels.
            // RFC 1035 3.3 and RFC 1183 1–3. Only CNAME redirects.
            (2 | 3 | 4 | 7 | 8 | 9 | 12, 1) => {
                self.name()?;
                Data::Other
            }
            (14 | 17, 1) => {
                self.name()?;
                self.name()?;
                Data::Other
            }
            (15 | 18 | 21, 1) => {
                self.u16()?;
                self.name()?;
                Data::Other
            }
            (6, 1) => {
                self.name()?; // MNAME
                self.name()?; // RNAME
                self.take(16)?; // SERIAL, REFRESH, RETRY, EXPIRE
                Data::Soa {
                    minimum: self.u32()?,
                }
            }
            (41, _) => {
                // RFC 6891 6.1.2: skip unknown options, but validate their
                // length-delimited framing without allocating option data.
                while self.pos < end {
                    self.u16()?;
                    let len = usize::from(self.u16()?);
                    self.take(len)?;
                }
                Data::Other
            }
            _ => {
                self.take(len)?;
                Data::Other
            }
        };
        if self.pos != end {
            return Err(DecodeError::Malformed);
        }
        Ok(Record {
            owner,
            kind,
            class,
            ttl,
            data,
        })
    }
}

pub(crate) fn decode(
    bytes: &[u8],
    id: u16,
    name: &DnsName,
    kind: u16,
) -> Result<Message, DecodeError> {
    let mut reader = Reader {
        bytes,
        pos: 0,
        labels: [0; 2048],
    };
    if reader.u16()? != id {
        return Err(DecodeError::Id);
    }
    let flags = reader.u16()?;
    if flags & 0xf840 != 0x8000 {
        return Err(DecodeError::Malformed);
    }
    if reader.u16()? != 1 {
        return Err(DecodeError::Question);
    }
    let answers = usize::from(reader.u16()?);
    let authority = usize::from(reader.u16()?);
    let additional = usize::from(reader.u16()?);
    if reader.name()?.as_ref() != Some(name) || reader.u16()? != kind || reader.u16()? != 1 {
        return Err(DecodeError::Question);
    }
    let mut message = Message {
        truncated: flags & 0x0200 != 0,
        rcode: flags & 15,
        answers: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
    };
    // The question is mandatory even for FORMERR and TC. Never use an
    // unauthenticated/mismatched packet to trigger another transport.
    if message.truncated {
        return Ok(message);
    }
    if answers + authority + additional > MAX_RECORDS {
        return Err(DecodeError::Malformed);
    }
    for _ in 0..answers {
        let record = reader.record()?;
        if record.kind == 41 {
            return Err(DecodeError::Malformed);
        }
        message.answers.push(record);
    }
    for _ in 0..authority {
        let record = reader.record()?;
        if record.kind == 41 {
            return Err(DecodeError::Malformed);
        }
        message.authority.push(record);
    }
    let mut opt_seen = false;
    for _ in 0..additional {
        let record = reader.record()?;
        if record.kind == 41 {
            if opt_seen
                || record.owner.as_ref().map(DnsName::as_str) != Some(".")
                || record.ttl & 0x00ff_0000 != 0
            {
                return Err(DecodeError::Malformed);
            }
            opt_seen = true;
            message.rcode |= ((record.ttl >> 24) as u16) << 4;
        } else {
            message.additional.push(record);
        }
    }
    if reader.pos != bytes.len() {
        return Err(DecodeError::Malformed);
    }
    Ok(message)
}

impl Message {
    pub(crate) fn resolve(
        &self,
        query: &DnsQuery,
        kind: u16,
        observed_at: PeerDiscoveryTime,
        max_chain: usize,
    ) -> Result<Vec<DnsCandidate>, DnsError> {
        let canonical = self.canonical(query.name(), observed_at, max_chain)?;
        if self.rcode == 3 && canonical.records.iter().any(|r| r.kind == kind) {
            return Err(DnsError::MalformedAnswer);
        }
        let candidates = addresses(
            &canonical.records,
            query,
            kind,
            observed_at,
            &canonical.chain,
        )?;
        if !candidates.is_empty() {
            return Ok(candidates);
        }
        Err(self.negative(canonical.owner, &canonical.chain, observed_at)?)
    }

    fn canonical<'a>(
        &'a self,
        name: &'a DnsName,
        observed_at: PeerDiscoveryTime,
        max_chain: usize,
    ) -> Result<CanonicalRrset<'a>, DnsError> {
        match self.rcode {
            0 | 3 => {}
            2 => return Err(DnsError::ServFail),
            5 => return Err(DnsError::Refused),
            1 => return Err(DnsError::MalformedAnswer),
            _ => return Err(DnsError::Unavailable),
        }
        let mut owner = name;
        let mut chain = Vec::new();
        let mut visited = Vec::new();
        loop {
            if visited.contains(&owner) {
                return Err(DnsError::MalformedAnswer);
            }
            visited.push(owner);
            let rrset: Vec<_> = self
                .answers
                .iter()
                .filter(|r| r.class == 1 && r.owner.as_ref() == Some(owner))
                .collect();
            let aliases: Vec<_> = rrset.iter().filter(|r| r.kind == 5).collect();
            if let Some(alias) = aliases.first() {
                let Data::Cname(Some(target)) = &alias.data else {
                    return Err(DnsError::MalformedAnswer);
                };
                // RFC 2181 10.1: one canonical target and no other data,
                // except the DNSSEC metadata allowed at an alias owner.
                if chain.len() >= max_chain
                    || aliases
                        .iter()
                        .any(|r| !matches!(&r.data, Data::Cname(Some(other)) if other == target))
                    || rrset
                        .iter()
                        .any(|r| !matches!(r.kind, 5 | 24 | 25 | 30 | 46 | 47))
                {
                    return Err(DnsError::MalformedAnswer);
                }
                chain.push(DnsRecord::new(
                    owner.clone(),
                    DnsRecordType::Cname,
                    rrset_ttl(&rrset, 5),
                    observed_at,
                ));
                owner = target;
                continue;
            }
            return Ok(CanonicalRrset {
                owner,
                records: rrset,
                chain,
            });
        }
    }

    pub(crate) fn target_is_alias(&self, name: &DnsName) -> bool {
        matches!(self.rcode, 0 | 3)
            && self
                .answers
                .iter()
                .chain(&self.additional)
                .any(|r| r.class == 1 && r.kind == 5 && r.owner.as_ref() == Some(name))
    }

    fn negative(
        &self,
        owner: &DnsName,
        chain: &[DnsRecord],
        observed_at: PeerDiscoveryTime,
    ) -> Result<DnsError, DnsError> {
        let mut soa_record: Option<&Record> = None;
        for record in self
            .authority
            .iter()
            .filter(|r| r.class == 1 && r.kind == 6)
        {
            let Some(zone) = record.owner.as_ref().map(DnsName::as_str) else {
                continue;
            };
            let name = owner.as_str();
            let encloses = zone == "."
                || name == zone
                || name
                    .strip_suffix(zone)
                    .is_some_and(|prefix| prefix.ends_with('.'));
            if !encloses {
                continue;
            }
            if soa_record.is_some_and(|old| old.owner == record.owner) {
                return Err(DnsError::MalformedAnswer);
            }
            if soa_record.is_none_or(|old| {
                zone.len() > old.owner.as_ref().map_or(0, |name| name.as_str().len())
            }) {
                soa_record = Some(record);
            }
        }
        let mut soa = soa_record.and_then(|r| match r.data {
            Data::Soa { minimum } => Some(NegativeSoa::new(r.ttl, minimum, observed_at)),
            _ => None,
        });
        // RFC 2308 2.2: NOERROR plus NS without SOA is a referral, not
        // NODATA. A stub never contacts NS/glue destinations from a reply.
        if self.rcode == 0
            && soa.is_none()
            && self.authority.iter().any(|r| r.class == 1 && r.kind == 2)
        {
            return Err(DnsError::Unavailable);
        }
        if let Some(expiry) = chain.iter().map(DnsRecord::expires_at).min() {
            soa = soa.map(|value| value.with_chain_expiry(expiry));
        }
        Ok(if self.rcode == 3 {
            DnsError::NxDomain { soa }
        } else {
            DnsError::NoData { soa }
        })
    }
}

struct CanonicalRrset<'a> {
    owner: &'a DnsName,
    records: Vec<&'a Record>,
    chain: Vec<DnsRecord>,
}

fn addresses(
    rrset: &[&Record],
    query: &DnsQuery,
    kind: u16,
    observed_at: PeerDiscoveryTime,
    chain: &[DnsRecord],
) -> Result<Vec<DnsCandidate>, DnsError> {
    // At most MAX_RECORDS addresses per decoded message. Calculate the TTL
    // before any address filtering, ordering or final candidate cap.
    let ttl = rrset_ttl(rrset, kind);
    let mut candidates: Vec<DnsCandidate> = Vec::new();
    for record in rrset.iter().filter(|r| r.kind == kind) {
        let (ip, record_type) = match record.data {
            Data::A(ip) => (IpAddr::V4(ip), DnsRecordType::A),
            Data::Aaaa(ip) => (IpAddr::V6(ip), DnsRecordType::Aaaa),
            _ => return Err(DnsError::MalformedAnswer),
        };
        let endpoint = SocketAddr::new(
            ip,
            query.input().default_port.ok_or(DnsError::InvalidQuery)?,
        );
        if !query.address_family().accepts(endpoint)
            || candidates.iter().any(|c| c.peer().endpoint == endpoint)
        {
            continue;
        }
        let mut records = chain.to_vec();
        records.push(DnsRecord::new(
            record.owner.clone().ok_or(DnsError::MalformedAnswer)?,
            record_type,
            ttl,
            observed_at,
        ));
        candidates.push(DnsCandidate::new(
            PeerCandidate::resolved(
                query.input().service.clone(),
                endpoint,
                query.input().transport,
                query.input().mode,
                0,
                0,
            ),
            records,
        )?);
    }
    Ok(candidates)
}

fn rrset_ttl(records: &[&Record], kind: u16) -> u32 {
    // Configured recursive servers count as authoritative for this purpose:
    // RFC 2181 5.2 requires using the lowest TTL for an inconsistent RRset.
    // Apply S1's RFC 2181 8 high-bit-as-zero rule BEFORE comparing TTLs.
    records
        .iter()
        .filter(|r| r.kind == kind)
        .min_by_key(|r| if r.ttl & 0x8000_0000 == 0 { r.ttl } else { 0 })
        .map_or(0, |r| r.ttl)
}

#[cfg(test)]
#[path = "dns_wire_tests.rs"]
mod tests;
