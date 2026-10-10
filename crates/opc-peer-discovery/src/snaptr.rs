//! Bounded S-NAPTR policy and retained provenance, separate from wire I/O.

use std::fmt;
use std::sync::Arc;

use crate::{DnsError, DnsName, DnsRecord, PeerDiscoveryTime, PeerTransport};

/// Explicit ordering policy; never inferred from a service or domain name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SnaptrOrdering {
    /// Ascending order, then ascending preference (RFC 3958).
    Rfc3958,
    /// Ascending order, with weight `65535 - preference` (TS 29.303 Annex B.2).
    ThreeGpp,
}

/// One supported service/protocol pair. Tags are canonical ASCII lowercase.
/// The operator's [`crate::PeerLabel`] remains independent of these DNS tags.
#[derive(Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SnaptrFilter {
    service: String,
    protocol: String,
    ordering: SnaptrOrdering,
}

impl SnaptrFilter {
    /// Validate exact RFC 3958 tags and an explicit ordering policy.
    ///
    /// # Errors
    /// Returns [`DnsError::InvalidQuery`] for malformed tags, a noncanonical
    /// Diameter application ID, or unsupported `+ue`/`+nc` qualifiers.
    pub fn new(service: &str, protocol: &str, ordering: SnaptrOrdering) -> Result<Self, DnsError> {
        let service = service.to_ascii_lowercase();
        let protocol = protocol.to_ascii_lowercase();
        if !valid_tag(service.as_bytes())
            || !valid_tag(protocol.as_bytes())
            || [&service, &protocol]
                .iter()
                .any(|tag| tag.contains("+ue") || tag.contains("+nc"))
            || service.strip_prefix("aaa+ap").is_some_and(|id| {
                id.parse::<u32>().is_err()
                    || (id.len() > 1 && id.starts_with('0'))
                    || !id.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            return Err(DnsError::InvalidQuery);
        }
        Ok(Self {
            service,
            protocol,
            ordering,
        })
    }

    /// Canonical application service tag, for consumer logic rather than logs.
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Canonical protocol tag; its punctuation does not imply a namespace.
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// Ordering selected by the caller.
    pub fn ordering(&self) -> SnaptrOrdering {
        self.ordering
    }

    pub(crate) fn diameter(&self) -> bool {
        self.service.starts_with("aaa+ap")
    }
}

impl fmt::Debug for SnaptrFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnaptrFilter")
            .field("ordering", &self.ordering)
            .finish_non_exhaustive()
    }
}

pub(crate) fn valid_tag(tag: &[u8]) -> bool {
    (1..=32).contains(&tag.len())
        && tag[0].is_ascii_alphabetic()
        && tag
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

/// Root NAPTR presence with no match for this query's one protocol.
/// Abandoning one protocol does not prevent querying another supported protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SnaptrNoMatch {
    /// Extended Diameter data exists; no automatic downgrade (RFC 6408 5(b)/(c)).
    ExtendedPresentNoMatch,
    /// Only legacy Diameter data exists; caller owns 5(d)/(e) compatibility.
    LegacyOnly,
    /// Only unrelated applications exist; caller may use 5(f) SRV fallback.
    NotAdvertised,
    /// Non-Diameter application/protocol pair was not advertised.
    ServiceNotOffered,
    /// The requested service token occurred with malformed SERVICES syntax.
    MalformedRequestedService,
}

/// Semantic refusal of one S-NAPTR branch, or failure of the complete traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SnaptrFailure {
    /// Flag was neither empty, `a`, nor `s` (ASCII case insensitive).
    UnsupportedFlag,
    /// S-NAPTR only supports an empty regexp and replacement-name traversal.
    RegexpNotEmpty,
    /// Matching application's SERVICES field violates the RFC 3958 grammar.
    MalformedService,
    /// Replacement is root, an IP literal, or not a representable DNS name.
    InvalidReplacement,
    /// A name repeats on this active delegation/alias path.
    Loop,
    /// This path exceeded the configured NAPTR depth.
    DepthLimit,
    /// This path cannot retain every record within the provenance bound.
    ProvenanceLimit,
    /// Root records exist but offer no usable application/protocol match.
    NoMatchingService(SnaptrNoMatch),
    /// Root matched, but every child failed; child authority is not root authority.
    NoUsablePath,
}

impl SnaptrFailure {
    /// Stable low-cardinality code; contains no queried names or service strings.
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedFlag => "dns-snaptr-unsupported-flag",
            Self::RegexpNotEmpty => "dns-snaptr-regexp-not-empty",
            Self::MalformedService => "dns-snaptr-malformed-service",
            Self::InvalidReplacement => "dns-snaptr-invalid-replacement",
            Self::Loop => "dns-snaptr-loop",
            Self::DepthLimit => "dns-snaptr-depth-limit",
            Self::ProvenanceLimit => "dns-snaptr-provenance-limit",
            Self::NoMatchingService(_) => "dns-snaptr-no-matching-service",
            Self::NoUsablePath => "dns-snaptr-no-usable-path",
        }
    }
}

/// Diagnostic root classification, independent of endpoint success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SnaptrRootKind {
    /// Original NAPTR question returned NXDOMAIN/NODATA.
    NoNaptr,
    /// Root NAPTR data exists, but this application/protocol does not match.
    PresentNoMatch(SnaptrNoMatch),
    /// Root advertised a match, even if subsequent traversal failed.
    Match,
}

/// Root diagnostics. Actionable fallback decisions also survive publication
/// in [`DnsError`], so this metadata does not introduce a cache lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SnaptrRootObservation {
    /// Root classification; an unobserved root has no observation at all.
    pub kind: SnaptrRootKind,
    /// Time of the root response in the consumer clock domain.
    pub observed_at: PeerDiscoveryTime,
    /// Root RRset/alias or SOA deadline, before the cache's negative TTL cap.
    pub expires_at: Option<PeerDiscoveryTime>,
}

/// Supported replacement-only NAPTR transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SnaptrFlag {
    /// Another NAPTR question.
    Delegation,
    /// SRV question at the exact replacement.
    Service,
    /// Address questions using the configured service default port.
    Address,
}

/// Raw NAPTR selection inputs from one accepted hop. Timings live in the path's
/// record chain. Debug deliberately omits SERVICES and replacement names.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SnaptrHop {
    pub(crate) order: u16,
    pub(crate) preference: u16,
    pub(crate) flag: SnaptrFlag,
    pub(crate) services: Box<str>,
    pub(crate) replacement: DnsName,
    pub(crate) protocol_advertised: bool,
}

impl SnaptrHop {
    /// Raw NAPTR order.
    pub fn order(&self) -> u16 {
        self.order
    }
    /// Raw NAPTR preference, independent of SRV selection.
    pub fn preference(&self) -> u16 {
        self.preference
    }
    /// Accepted transition flag.
    pub fn flag(&self) -> SnaptrFlag {
        self.flag
    }
    /// Original SERVICES bytes, validated as ASCII, for consumer logic only.
    pub fn services(&self) -> &str {
        &self.services
    }
    /// Canonical replacement name, for consumer logic only.
    pub fn replacement(&self) -> &DnsName {
        &self.replacement
    }
    /// False for a Diameter application-only record using caller configuration.
    pub fn protocol_advertised(&self) -> bool {
        self.protocol_advertised
    }
}

impl fmt::Debug for SnaptrHop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnaptrHop")
            .field("order", &self.order)
            .field("preference", &self.preference)
            .field("flag", &self.flag)
            .field("protocol_advertised", &self.protocol_advertised)
            .finish_non_exhaustive()
    }
}

/// Raw SRV selection data, separate from all NAPTR order/preference fields.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SnaptrSrv {
    pub(crate) owner: DnsName,
    pub(crate) priority: u16,
    pub(crate) weight: u16,
    pub(crate) port: u16,
    pub(crate) target: DnsName,
}

impl SnaptrSrv {
    /// Canonical SRV owner.
    pub fn owner(&self) -> &DnsName {
        &self.owner
    }
    /// Raw SRV priority.
    pub fn priority(&self) -> u16 {
        self.priority
    }
    /// Raw SRV weight, never the legacy selection weight.
    pub fn weight(&self) -> u16 {
        self.weight
    }
    /// Advertised SRV port.
    pub fn port(&self) -> u16 {
        self.port
    }
    /// Advertised terminal host.
    pub fn target(&self) -> &DnsName {
        &self.target
    }
}

/// One complete derivation of an endpoint. At most 16 records and 14 NAPTR hops.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SnaptrPath {
    pub(crate) records: Arc<[DnsRecord]>,
    pub(crate) hops: Box<[SnaptrHop]>,
    pub(crate) terminal_host: DnsName,
    pub(crate) srv: Option<SnaptrSrv>,
}

impl SnaptrPath {
    /// Every timed record, including aliases and the terminal address.
    pub fn records(&self) -> &[DnsRecord] {
        &self.records
    }
    /// NAPTR hops in ancestor-first order.
    pub fn hops(&self) -> &[SnaptrHop] {
        &self.hops
    }
    /// Advertised host before any permitted address-owner CNAME traversal.
    pub fn terminal_host(&self) -> &DnsName {
        &self.terminal_host
    }
    /// Raw SRV data for an `s` terminal, absent for an `a` terminal.
    pub fn srv(&self) -> Option<&SnaptrSrv> {
        self.srv.as_ref()
    }
}

/// Original query and up to four complete paths for one deduplicated endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SnaptrProvenance {
    pub(crate) origin: DnsName,
    pub(crate) filter: SnaptrFilter,
    pub(crate) paths: Box<[SnaptrPath]>,
}

impl SnaptrProvenance {
    /// Original query name; authentication remains consumer policy.
    pub fn origin(&self) -> &DnsName {
        &self.origin
    }
    /// Requested application/protocol and ordering policy.
    pub fn filter(&self) -> &SnaptrFilter {
        &self.filter
    }
    /// Best path first, followed by at most three alternate paths.
    pub fn paths(&self) -> &[SnaptrPath] {
        &self.paths
    }
}

/// Reference to one endpoint and the actual retained paths for this host.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SnaptrHostAddress {
    pub(crate) candidate_index: usize,
    pub(crate) path_indices: Box<[usize]>,
}

impl SnaptrHostAddress {
    /// Index into [`crate::DnsAnswer::candidates`].
    pub fn candidate_index(&self) -> usize {
        self.candidate_index
    }
    /// Indices into that candidate's [`SnaptrProvenance::paths`], at most four.
    pub fn path_indices(&self) -> &[usize] {
        &self.path_indices
    }
}

/// Host grouping for consumer-owned topology/collocation selection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SnaptrHost {
    pub(crate) name: DnsName,
    pub(crate) transport: PeerTransport,
    pub(crate) port: u16,
    pub(crate) rank: usize,
    pub(crate) addresses: Box<[SnaptrHostAddress]>,
    pub(crate) complete: bool,
}

impl SnaptrHost {
    /// Advertised terminal name. Different names sharing an endpoint stay distinct.
    pub fn name(&self) -> &DnsName {
        &self.name
    }
    /// Configured endpoint transport.
    pub fn transport(&self) -> PeerTransport {
        self.transport
    }
    /// Service default or explicit SRV port.
    pub fn port(&self) -> u16 {
        self.port
    }
    /// First retained endpoint's rank in final selection order.
    pub fn rank(&self) -> usize {
        self.rank
    }
    /// At most 16 address references; indices never refer to omitted data.
    pub fn addresses(&self) -> &[SnaptrHostAddress] {
        &self.addresses
    }
    /// Whether all observed addresses/paths for this host fit and completed.
    /// This does not assert that unvisited subtrees cannot name the same host.
    pub fn complete(&self) -> bool {
        self.complete
    }
}

/// Bounded counters retained with a cached S-NAPTR answer. Counts cover observed
/// work only; an unvisited subtree has unknown cardinality.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SnaptrCoverage {
    /// Some work or metadata is omitted, refused, or failed.
    pub incomplete: bool,
    /// Records filtered by application/protocol, before semantic traversal.
    pub filtered_records: usize,
    /// Observed eligible NAPTR records not expanded due to limits.
    pub unexpanded_records: usize,
    /// Observed SRV record paths not expanded across all NAPTR terminals.
    pub unexpanded_srv_records: usize,
    /// Distinct observed SRV targets whose address expansion was entirely skipped.
    pub unexpanded_srv_targets: usize,
    /// Observed addresses beyond the endpoint limit.
    pub omitted_addresses: usize,
    /// Alternate paths beyond retained path/host limits.
    pub omitted_paths: usize,
    /// Distinct observed host groups that could not be retained.
    pub omitted_hosts: usize,
    /// Known pending branches not visited; their descendant counts are unknown.
    pub unvisited_branches: usize,
    /// Semantic refusals, including higher-ranked branches excluded from results.
    pub refused_branches: usize,
    /// Failed branch questions/families, retaining visibility through the cache.
    pub failed_branches: usize,
    /// Logical questions prevented by the overall work/deadline allowance.
    pub unfinished_lookups: usize,
    /// Later branch details omitted from the bounded response trace. Refusal
    /// and failure counters above still include those branches.
    pub omitted_branch_outcomes: usize,
}

/// One refused or failed branch, retained only in the response, not the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SnaptrBranchOutcome {
    /// Typed failure; child DNS denials remain child diagnostics.
    pub error: DnsError,
    /// Timed prefix before the failed step, bounded to 16 records.
    pub records: Box<[DnsRecord]>,
    /// Observation or local failure time in the cache clock domain.
    pub observed_at: PeerDiscoveryTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DnsAnswer, DnsCandidate, DnsRecordType, PeerCandidate, PeerLabel, ServiceDiscoveryMode,
    };
    use std::mem::{size_of, size_of_val};

    fn long_name(index: usize) -> DnsName {
        DnsName::new(format!(
            "h{index:03}{}.{}.{}.{}.",
            "n".repeat(59),
            "n".repeat(63),
            "n".repeat(63),
            "n".repeat(61)
        ))
        .unwrap()
    }

    #[test]
    fn maximum_retained_metadata_fits_the_documented_payload_bound() {
        let filter =
            SnaptrFilter::new(&"s".repeat(32), &"p".repeat(32), SnaptrOrdering::ThreeGpp).unwrap();
        let services = std::iter::once("s".repeat(32))
            .chain(std::iter::repeat_n("p".repeat(32), 6))
            .chain(std::iter::once("p".repeat(24)))
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(services.len(), 255);
        let mut candidates = Vec::new();
        for endpoint in 0..16 {
            let mut paths = Vec::new();
            for alternate in 0..4 {
                let records = (0..16)
                    .map(|i| {
                        DnsRecord::new(
                            long_name(i),
                            if i < 14 {
                                DnsRecordType::Naptr
                            } else if i == 14 {
                                DnsRecordType::Srv
                            } else {
                                DnsRecordType::A
                            },
                            90,
                            PeerDiscoveryTime::from_millis(1_000),
                        )
                    })
                    .collect::<Vec<_>>();
                let hops = (0..14)
                    .map(|i| SnaptrHop {
                        order: i,
                        preference: u16::MAX,
                        flag: if i == 13 {
                            SnaptrFlag::Service
                        } else {
                            SnaptrFlag::Delegation
                        },
                        services: services.clone().into_boxed_str(),
                        replacement: long_name(usize::from(i)),
                        protocol_advertised: true,
                    })
                    .collect();
                let host = long_name((endpoint + alternate) % 16);
                paths.push(SnaptrPath {
                    records: records.into(),
                    hops,
                    terminal_host: host.clone(),
                    srv: Some(SnaptrSrv {
                        owner: long_name(15),
                        priority: u16::MAX,
                        weight: u16::MAX,
                        port: 2123,
                        target: host,
                    }),
                });
            }
            let peer = PeerCandidate::resolved(
                PeerLabel::new("l".repeat(128)).unwrap(),
                format!("192.0.2.{}:2123", endpoint + 1).parse().unwrap(),
                PeerTransport::Udp,
                ServiceDiscoveryMode::Snaptr,
                0,
                crate::dns::selection_weight(endpoint),
            );
            let mut candidate = DnsCandidate::new(peer, paths[0].records.to_vec()).unwrap();
            candidate.records = Some(paths[0].records.clone());
            candidate.snaptr = Some(SnaptrProvenance {
                origin: long_name(0),
                filter: filter.clone(),
                paths: paths.into_boxed_slice(),
            });
            candidates.push(candidate);
        }
        let mut answer = DnsAnswer::new(candidates).unwrap();
        answer.snaptr_hosts = Some(
            (0..16)
                .map(|host| SnaptrHost {
                    name: long_name(host),
                    transport: PeerTransport::Udp,
                    port: 2123,
                    rank: 0,
                    complete: true,
                    addresses: (0..4)
                        .map(|path| SnaptrHostAddress {
                            candidate_index: (host + 16 - path) % 16,
                            path_indices: vec![path].into_boxed_slice(),
                        })
                        .collect(),
                })
                .collect(),
        );
        answer.snaptr_coverage = Some(SnaptrCoverage::default());
        let mut bytes = size_of::<DnsAnswer>() + size_of_val(answer.candidates());
        let mut labels = 0;
        for candidate in answer.candidates() {
            labels += candidate.peer().label.0.capacity();
            let provenance = candidate.snaptr().unwrap();
            bytes += provenance.origin.retained_capacity()
                + provenance.filter.service.capacity()
                + provenance.filter.protocol.capacity();
            bytes += size_of_val(provenance.paths());
            for path in provenance.paths() {
                // One Arc allocation per path; primary records share this
                // allocation with DnsCandidate rather than retaining a copy.
                bytes += 2 * size_of::<usize>() + size_of_val(path.records());
                bytes += path
                    .records()
                    .iter()
                    .map(|r| r.owner.retained_capacity())
                    .sum::<usize>();
                bytes += size_of_val(path.hops()) + path.terminal_host.retained_capacity();
                bytes += path
                    .hops()
                    .iter()
                    .map(|h| h.services.len() + h.replacement.retained_capacity())
                    .sum::<usize>();
                let srv = path.srv().unwrap();
                bytes += srv.owner.retained_capacity() + srv.target.retained_capacity();
            }
        }
        let hosts = answer.snaptr_hosts().unwrap();
        bytes += size_of_val(hosts);
        for host in hosts {
            bytes += host.name.retained_capacity() + size_of_val(host.addresses());
            bytes += host
                .addresses()
                .iter()
                .map(|a| size_of_val(a.path_indices()))
                .sum::<usize>();
        }
        // Conservatively add a *second* fully populated 16x16 reference grid.
        // Real host references are constrained further by the 64 actual paths.
        bytes += 16 * 16 * (size_of::<SnaptrHostAddress>() + 4 * size_of::<usize>());
        eprintln!("maximal retained DNS metadata plus conservative reference allowance: {bytes} bytes; caller labels: {labels} bytes");
        assert!(
            bytes < 2 * 1024 * 1024,
            "retained DNS payload {bytes} exceeds 2 MiB"
        );
        assert_eq!(labels, 16 * 128);
    }
}
