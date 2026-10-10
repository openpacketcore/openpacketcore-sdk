//! NAPTR framing and RRset timing; per-record semantics belong to traversal.

use super::*;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct NaptrRecord {
    pub(crate) order: u16,
    pub(crate) preference: u16,
    pub(crate) flags: Box<[u8]>,
    pub(crate) services: Box<[u8]>,
    pub(crate) regexp: Box<[u8]>,
    pub(crate) replacement: Option<DnsName>,
}

pub(crate) struct NaptrAnswer {
    pub(crate) records: Vec<NaptrRecord>,
    pub(crate) chain: Vec<DnsRecord>,
}

impl Message {
    pub(crate) fn naptr(
        &self,
        query: &DnsQuery,
        observed_at: PeerDiscoveryTime,
        max_chain: usize,
    ) -> Result<NaptrAnswer, DnsError> {
        let canonical = self.canonical_with_loop_error(
            query.name(),
            observed_at,
            max_chain,
            DnsError::Snaptr {
                reason: crate::SnaptrFailure::Loop,
                expires_at: None,
            },
        )?;
        let rrset: Vec<_> = canonical
            .records
            .iter()
            .filter(|r| r.kind == 35)
            .copied()
            .collect();
        if rrset.is_empty() {
            return Err(self.negative(canonical.owner, &canonical.chain, observed_at)?);
        }
        if self.rcode == 3 {
            return Err(DnsError::MalformedAnswer);
        }
        // Normalize the complete RRset before service filtering or deduplication.
        let ttl = rrset_ttl(&rrset, 35);
        let mut records = Vec::with_capacity(rrset.len());
        for record in rrset {
            let Data::Naptr(value) = &record.data else {
                return Err(DnsError::MalformedAnswer);
            };
            records.push(value.clone());
        }
        let mut chain = canonical.chain;
        chain.push(DnsRecord::new(
            canonical.owner.clone(),
            DnsRecordType::Naptr,
            ttl,
            observed_at,
        ));
        Ok(NaptrAnswer { records, chain })
    }
}
