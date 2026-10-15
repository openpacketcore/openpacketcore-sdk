//! Consumer policy over retained direct SRV paths.

use super::{selection_weight, DnsAnswer, DnsError};
use crate::{PeerCandidateSource, ServiceDiscoveryMode, SrvPath};

impl DnsAnswer {
    /// Retain direct SRV paths accepted by the consumer's current policy.
    ///
    /// Calls `keep` once per retained path in its original seeded traversal
    /// order, without DNS queries or another weighted draw. Each endpoint is
    /// ranked by its best surviving path, which supplies its records and SRV
    /// priority. Candidate weights encode the resulting endpoint order.
    ///
    /// Original record times, TTLs and both failure freshness bounds survive.
    /// No omitted work is backfilled. Keeping every path returns an equal
    /// answer; successive pure predicates are equivalent to their conjunction.
    /// `Ok(None)` means policy excluded every retained path, not DNS absence.
    ///
    /// Cache the original answer, then filter a lookup snapshot. A view's
    /// expiry must not replace cache freshness or retry state. Apply a changed
    /// policy to the original answer to recover previously excluded paths.
    ///
    /// # Errors
    /// Returns [`DnsError::InvalidQuery`] before invoking `keep` if any candidate
    /// lacks resolver-produced direct SRV provenance. Address, S-NAPTR, legacy
    /// and mixed answers are rejected.
    pub fn filter_srv_paths<F>(&self, mut keep: F) -> Result<Option<Self>, DnsError>
    where
        F: FnMut(&SrvPath) -> bool,
    {
        let mut visits = Vec::new();
        let mut accepted = Vec::new();
        for (candidate_index, candidate) in self.candidates.iter().enumerate() {
            let provenance = candidate.srv.as_ref().ok_or(DnsError::InvalidQuery)?;
            if candidate.peer.source != PeerCandidateSource::Resolver(ServiceDiscoveryMode::Service)
                || candidate.snaptr.is_some()
                || provenance.paths.is_empty()
                || provenance.paths.len() > 128
            {
                return Err(DnsError::InvalidQuery);
            }
            accepted.push(vec![false; provenance.paths.len()]);
            for (path_index, path) in provenance.paths.iter().enumerate() {
                visits.push((candidate_index, path_index, path));
            }
        }
        visits.sort_by_key(|(_, _, path)| path.rank);
        for (candidate, path_index, path) in visits {
            accepted[candidate][path_index] = keep(path);
        }
        let mut retained = Vec::new();
        for (candidate, accepted) in self.candidates.iter().zip(accepted) {
            let mut candidate = candidate.clone();
            let provenance = candidate.srv.as_mut().ok_or(DnsError::InvalidQuery)?;
            provenance.paths = provenance
                .paths
                .iter()
                .zip(accepted)
                .filter(|(_, keep)| *keep)
                .map(|(path, _)| path.clone())
                .collect();
            let Some(first) = provenance.paths.first() else {
                continue;
            };
            candidate.peer.priority = first.priority();
            candidate.records = Some(first.records.clone());
            retained.push((first.rank, candidate));
        }
        if retained.is_empty() {
            return Ok(None);
        }
        retained.sort_by_key(|(rank, _)| *rank);
        let mut answer = self.clone();
        answer.candidates = retained
            .into_iter()
            .enumerate()
            .map(|(index, (_, mut candidate))| {
                candidate.peer.weight = selection_weight(index);
                candidate
            })
            .collect();
        Ok(Some(answer))
    }
}
