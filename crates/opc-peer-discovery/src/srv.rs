//! Retained paths from direct SRV discovery, independent of endpoint deduplication.

use std::fmt;
use std::sync::Arc;

use crate::{DnsName, DnsRecord, SnaptrSrv};

/// One complete direct SRV derivation of an endpoint, including timed records.
/// Selection rank is retained privately so consumer policy never redraws weights.
#[derive(Clone)]
#[non_exhaustive]
pub struct SrvPath {
    pub(crate) rank: (usize, usize),
    pub(crate) records: Arc<[DnsRecord]>,
    pub(crate) record: SnaptrSrv,
}

impl PartialEq for SrvPath {
    fn eq(&self, other: &Self) -> bool {
        self.records == other.records && self.record == other.record
    }
}

impl Eq for SrvPath {}

impl fmt::Debug for SrvPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SrvPath")
            .field("records", &self.records)
            .field("record", &self.record)
            .finish()
    }
}

impl SrvPath {
    /// Every timed service-owner alias, SRV and terminal address record.
    pub fn records(&self) -> &[DnsRecord] {
        &self.records
    }

    /// Canonical owner of the SRV RRset, after service-owner aliases.
    pub fn owner(&self) -> &DnsName {
        self.record.owner()
    }

    /// Advertised host; consumer authentication policy must check this identity.
    pub fn target(&self) -> &DnsName {
        self.record.target()
    }

    /// Advertised SRV port.
    pub fn port(&self) -> u16 {
        self.record.port()
    }

    /// Raw SRV priority.
    pub fn priority(&self) -> u16 {
        self.record.priority()
    }

    /// Raw SRV weight, distinct from a candidate's encoded selection rank.
    pub fn weight(&self) -> u16 {
        self.record.weight()
    }
}

/// Original direct SRV query and its complete retained paths to one endpoint.
/// At most 128 record paths survive the resolver's configured work limits;
/// each path has at most [`crate::DnsCandidate::MAX_RECORDS`] timed records.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SrvProvenance {
    pub(crate) origin: DnsName,
    pub(crate) paths: Box<[SrvPath]>,
}

impl SrvProvenance {
    /// Original service query name, before aliases.
    pub fn origin(&self) -> &DnsName {
        &self.origin
    }

    /// Best path first, in the original RFC 2782 seeded traversal order.
    pub fn paths(&self) -> &[SrvPath] {
        &self.paths
    }
}
