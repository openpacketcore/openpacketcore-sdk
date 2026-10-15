//! Consumer selection views of retained S-NAPTR discovery data.
use super::{selection_weight, DnsAnswer, DnsCandidate, DnsError};
use crate::{
    PeerCandidateSource, ServiceDiscoveryMode, SnaptrHost, SnaptrHostAddress, SnaptrPath,
    SnaptrProvenance,
};

impl DnsAnswer {
    /// Retain S-NAPTR paths accepted by a consumer's current selection policy.
    ///
    /// Calls `keep` exactly once per retained path, in the original seeded
    /// traversal order. Each endpoint is ranked by its best surviving path;
    /// that path becomes `candidate.snaptr().unwrap().paths()[0]` and supplies
    /// `candidate.records()`. Endpoint weights and all host references are
    /// rebuilt. Filtering does not draw again or issue DNS queries.
    ///
    /// Records keep their observation times and TTLs. Coverage, host completeness
    /// and both existing freshness bounds describe the original discovery and
    /// are preserved. In particular, this does not reconsider failures below an
    /// originally full endpoint prefix or backfill omitted paths.
    ///
    /// `Ok(None)` means local policy excluded every retained path; it is not an
    /// authoritative DNS absence or permission for protocol fallback. Publish
    /// the original answer to the shared cache, then filter after lookup. A
    /// filtered answer's expiry never replaces the cache's `fresh_until` or
    /// retry state. Apply a less restrictive policy to the original answer,
    /// since a filtered view no longer contains previously excluded paths.
    ///
    /// Keeping every path returns an equal answer. For pure predicates,
    /// successive filtering is equivalent to their conjunction.
    ///
    /// # Errors
    /// Returns [`DnsError::InvalidQuery`] before calling `keep` if any candidate
    /// lacks complete resolver-produced S-NAPTR metadata, including retained
    /// traversal ranks and host groups. Address, SRV, legacy and mixed answers
    /// cannot be filtered by this operation.
    pub fn filter_snaptr_paths<F>(&self, mut keep: F) -> Result<Option<Self>, DnsError>
    where
        F: FnMut(&SnaptrPath) -> bool,
    {
        let original_hosts = self.snaptr_hosts.as_deref().ok_or(DnsError::InvalidQuery)?;
        if self.snaptr_coverage.is_none() || original_hosts.is_empty() {
            return Err(DnsError::InvalidQuery);
        }
        let mut visits = Vec::new();
        let mut accepted = Vec::with_capacity(self.candidates.len());
        // Finish validation of the whole answer before any callback effects.
        for (candidate_index, candidate) in self.candidates.iter().enumerate() {
            let provenance = candidate.snaptr.as_ref().ok_or(DnsError::InvalidQuery)?;
            if candidate.peer.source != PeerCandidateSource::Resolver(ServiceDiscoveryMode::Snaptr)
                || provenance.paths.is_empty()
                || provenance.paths.len() > 4
            {
                return Err(DnsError::InvalidQuery);
            }
            accepted.push(vec![false; provenance.paths.len()]);
            for (path_index, path) in provenance.paths.iter().enumerate() {
                if path.rank.is_empty()
                    || path.rank.len() > DnsCandidate::MAX_RECORDS
                    || !original_hosts.iter().any(|host| {
                        host.name == path.terminal_host
                            && host.port == candidate.peer.endpoint.port()
                            && host.transport == candidate.peer.transport
                    })
                {
                    return Err(DnsError::InvalidQuery);
                }
                visits.push((candidate_index, path_index, path));
            }
        }
        visits.sort_by(|a, b| a.2.rank.cmp(&b.2.rank));
        for (candidate, path_index, path) in visits {
            accepted[candidate][path_index] = keep(path);
        }
        let mut retained = Vec::new();
        for (candidate, accepted) in self.candidates.iter().zip(accepted) {
            let provenance = candidate.snaptr.as_ref().ok_or(DnsError::InvalidQuery)?;
            let mut paths: Vec<_> = provenance
                .paths
                .iter()
                .zip(accepted)
                .filter(|(_, keep)| *keep)
                .map(|(path, _)| path.clone())
                .collect();
            paths.sort_by(|a, b| a.rank.cmp(&b.rank));
            let Some(first) = paths.first() else {
                continue;
            };
            retained.push((
                first.rank.clone(),
                DnsCandidate {
                    peer: candidate.peer.clone(),
                    records: Some(first.records.clone()),
                    srv: None,
                    snaptr: Some(SnaptrProvenance {
                        origin: provenance.origin.clone(),
                        filter: provenance.filter.clone(),
                        paths: paths.into_boxed_slice(),
                    }),
                },
            ));
        }
        if retained.is_empty() {
            return Ok(None);
        }
        retained.sort_by(|a, b| a.0.cmp(&b.0));
        let candidates: Vec<_> = retained
            .into_iter()
            .enumerate()
            .map(|(index, (_, mut candidate))| {
                candidate.peer.weight = selection_weight(index);
                candidate
            })
            .collect();
        let mut hosts = Vec::new();
        // Match discovery's primary-host reservation order, including stable
        // ties between host groups whose first address is the same endpoint.
        for (candidate_index, candidate) in candidates.iter().enumerate() {
            add_host(&mut hosts, original_hosts, candidate, candidate_index, 0)?;
        }
        for (candidate_index, candidate) in candidates.iter().enumerate() {
            let provenance = candidate.snaptr.as_ref().ok_or(DnsError::InvalidQuery)?;
            for path_index in 1..provenance.paths.len() {
                add_host(
                    &mut hosts,
                    original_hosts,
                    candidate,
                    candidate_index,
                    path_index,
                )?;
            }
        }
        hosts.sort_by_key(|host| host.rank);
        Ok(Some(Self {
            candidates: candidates.into_boxed_slice(),
            freshness_bound: self.freshness_bound,
            negative_freshness_bound: self.negative_freshness_bound,
            snaptr_coverage: self.snaptr_coverage,
            srv_coverage: self.srv_coverage,
            snaptr_hosts: Some(
                hosts
                    .into_iter()
                    .map(|mut host| {
                        host.addresses.sort_by_key(|(candidate, _)| *candidate);
                        SnaptrHost {
                            name: host.original.name.clone(),
                            transport: host.original.transport,
                            port: host.original.port,
                            rank: host.rank,
                            complete: host.original.complete,
                            addresses: host
                                .addresses
                                .into_iter()
                                .map(|(candidate_index, paths)| SnaptrHostAddress {
                                    candidate_index,
                                    path_indices: paths.into_boxed_slice(),
                                })
                                .collect(),
                        }
                    })
                    .collect(),
            ),
        }))
    }
}

struct Host<'a> {
    original: &'a SnaptrHost,
    rank: usize,
    addresses: Vec<(usize, Vec<usize>)>,
}

fn add_host<'a>(
    hosts: &mut Vec<Host<'a>>,
    originals: &'a [SnaptrHost],
    candidate: &DnsCandidate,
    candidate_index: usize,
    path_index: usize,
) -> Result<(), DnsError> {
    let path = candidate
        .snaptr
        .as_ref()
        .and_then(|p| p.paths.get(path_index))
        .ok_or(DnsError::InvalidQuery)?;
    let matches = |host: &SnaptrHost| {
        host.name == path.terminal_host
            && host.port == candidate.peer.endpoint.port()
            && host.transport == candidate.peer.transport
    };
    let index = if let Some(index) = hosts.iter().position(|host| matches(host.original)) {
        index
    } else {
        let original = originals
            .iter()
            .find(|host| matches(host))
            .ok_or(DnsError::InvalidQuery)?;
        hosts.push(Host {
            original,
            rank: candidate_index,
            addresses: Vec::new(),
        });
        hosts.len() - 1
    };
    let host = &mut hosts[index];
    host.rank = host.rank.min(candidate_index);
    if let Some((_, paths)) = host
        .addresses
        .iter_mut()
        .find(|(index, _)| *index == candidate_index)
    {
        paths.push(path_index);
    } else {
        host.addresses.push((candidate_index, vec![path_index]));
    }
    Ok(())
}
