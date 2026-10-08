//! SRV semantics over the same bounded, fully parsed DNS message.

use super::*;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SrvRecord {
    pub(crate) priority: u16,
    pub(crate) weight: u16,
    pub(crate) port: u16,
    pub(crate) target: DnsName,
}

pub(crate) struct SrvAnswer {
    pub(crate) records: Vec<SrvRecord>,
    pub(crate) chain: Vec<DnsRecord>,
    additional: Vec<Record>,
    aliases: Vec<DnsName>,
    pub(crate) observed_at: PeerDiscoveryTime,
}

impl Message {
    pub(crate) fn srv(
        self,
        query: &DnsQuery,
        observed_at: PeerDiscoveryTime,
        max_chain: usize,
    ) -> Result<SrvAnswer, DnsError> {
        // Reserve one provenance slot each for SRV and the terminal address.
        let canonical = self.canonical(
            query.name(),
            observed_at,
            max_chain.min(DnsCandidate::MAX_RECORDS - 2),
        )?;
        let rrset: Vec<_> = canonical
            .records
            .iter()
            .filter(|r| r.kind == 33)
            .copied()
            .collect();
        if rrset.is_empty() {
            return Err(self.negative(canonical.owner, &canonical.chain, observed_at)?);
        }
        if self.rcode == 3 {
            return Err(DnsError::MalformedAnswer);
        }
        let ttl = rrset_ttl(&rrset, 33);
        let only_root = rrset.iter().all(|record| {
            matches!(&record.data, Data::Srv { target: Some(target), .. } if target.as_str() == ".")
        });
        let mut chain = canonical.chain;
        chain.push(DnsRecord::new(
            canonical.owner.clone(),
            DnsRecordType::Srv,
            ttl,
            observed_at,
        ));
        let mut records = Vec::new();
        for record in rrset {
            let Data::Srv {
                priority,
                weight,
                port,
                target,
            } = &record.data
            else {
                return Err(DnsError::MalformedAnswer);
            };
            let Some(target) = target.as_ref() else {
                continue;
            };
            if target.as_str() != "." && !valid_host(target.as_str()) {
                continue;
            }
            let value = SrvRecord {
                priority: *priority,
                weight: *weight,
                port: *port,
                target: target.clone(),
            };
            // A duplicate wire record must not multiply a server's weight.
            if !records.contains(&value) {
                records.push(value);
            }
        }
        if only_root && records.len() == 1 {
            return Err(DnsError::ServiceUnavailable {
                expires_at: chain
                    .iter()
                    .map(DnsRecord::expires_at)
                    .min()
                    .unwrap_or(observed_at),
            });
        }
        // RFC 2782 only defines the sole-root withdrawal. Ignore a root
        // mixed with hosts and port 0 (reserved by RFC 6335 section 6).
        records.retain(|record| record.target.as_str() != "." && record.port != 0);
        if records.is_empty() {
            return Err(DnsError::Unavailable);
        }
        // Preserve known target aliases from either answer or additional data.
        // The list cannot exceed the bounded SRV RRset, including shared hosts.
        let aliases = records
            .iter()
            .filter(|record| self.target_is_alias(&record.target))
            .map(|record| record.target.clone())
            .collect();
        Ok(SrvAnswer {
            records,
            chain,
            additional: self.additional,
            aliases,
            observed_at,
        })
    }
}

impl SrvAnswer {
    pub(crate) fn has_addresses(&self, target: &DnsName, kind: u16) -> bool {
        self.additional.iter().any(|record| {
            record.class == 1 && record.owner.as_ref() == Some(target) && record.kind == kind
        })
    }

    pub(crate) fn target_is_alias(&self, target: &DnsName) -> bool {
        self.aliases.contains(target)
    }

    pub(crate) fn addresses(
        &self,
        query: &DnsQuery,
        kind: u16,
    ) -> Option<Result<Vec<DnsCandidate>, DnsError>> {
        let rrset: Vec<_> = self
            .additional
            .iter()
            .filter(|r| r.class == 1 && r.owner.as_ref() == Some(query.name()))
            .collect();
        if !rrset.iter().any(|r| r.kind == kind) {
            return None;
        }
        Some(addresses(&rrset, query, kind, self.observed_at, &[]))
    }
}

/// RFC 1123 section 2.1: host labels admit leading digits, use ASCII LDH,
/// and do not start/end with a hyphen. IP literals are not DNS host targets.
pub(crate) fn valid_host(name: &str) -> bool {
    let name = name.trim_end_matches('.');
    !name.is_empty()
        && name.parse::<IpAddr>().is_err()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
