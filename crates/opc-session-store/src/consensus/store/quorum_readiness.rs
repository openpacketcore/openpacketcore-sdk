//! Mode-aware fixed-quorum probes; disk progress never substitutes for quorum.

use super::*;

impl ConsensusSessionStore {
    /// Probe exact fixed-quorum authority under the configured persistence mode.
    ///
    /// Granted requires Recovery clearance, admitted exact membership, a fresh
    /// majority barrier and local application under the original operation
    /// deadline. Async does not wait for its background disk generation.
    pub async fn probe_fixed_quorum_readiness(&self) -> SessionQuorumReadinessReport {
        let deadline = self.operation_deadline_from(tokio::time::Instant::now());
        let report = self.probe_fixed_quorum_readiness_before(deadline).await;
        let policy = self
            .inner
            .topology
            .fixed_durable_placement_policy()
            .unwrap_or_default();
        let placement = TopologyAttestationTime::now()
            .ok()
            .and_then(|now| self.fixed_quorum_placement_resilience_at(policy, now))
            .unwrap_or_else(|| policy.evaluate_unverified());
        self.quorum_readiness_report(placement, report)
    }

    /// Deterministic placement-time form of [`Self::probe_fixed_quorum_readiness`].
    /// `now` affects placement evidence only, never quorum authority or deadlines.
    pub async fn probe_fixed_quorum_readiness_at(
        &self,
        now: TopologyAttestationTime,
    ) -> SessionQuorumReadinessReport {
        let deadline = self.operation_deadline_from(tokio::time::Instant::now());
        let report = self.probe_fixed_quorum_readiness_before(deadline).await;
        let policy = self
            .inner
            .topology
            .fixed_durable_placement_policy()
            .unwrap_or_default();
        let placement = self
            .fixed_quorum_placement_resilience_at(policy, now)
            .unwrap_or_else(|| policy.evaluate_unverified());
        self.quorum_readiness_report(placement, report)
    }

    /// Probe configured quorum authority with replacement authenticated placement
    /// evidence. Placement expiry affects only the separate resilience result.
    pub async fn probe_fixed_quorum_readiness_with_placement_attestation(
        &self,
        attestation: &VerifiedQuorumTopologyAttestation,
    ) -> SessionQuorumReadinessReport {
        let deadline = self.operation_deadline_from(tokio::time::Instant::now());
        let report = self.probe_fixed_quorum_readiness_before(deadline).await;
        let policy = self
            .inner
            .topology
            .fixed_durable_placement_policy()
            .unwrap_or_default();
        let placement = TopologyAttestationTime::now()
            .ok()
            .and_then(|now| {
                self.refreshed_fixed_quorum_placement_attestation_valid_for_at(attestation, now)
            })
            .map(|_| PlacementResilienceReport::qualified(policy))
            .unwrap_or_else(|| policy.evaluate_unverified());
        self.quorum_readiness_report(placement, report)
    }

    /// Deterministic placement-time form of
    /// [`Self::probe_fixed_quorum_readiness_with_placement_attestation`].
    pub async fn probe_fixed_quorum_readiness_with_placement_attestation_at(
        &self,
        attestation: &VerifiedQuorumTopologyAttestation,
        now: TopologyAttestationTime,
    ) -> SessionQuorumReadinessReport {
        let deadline = self.operation_deadline_from(tokio::time::Instant::now());
        let report = self.probe_fixed_quorum_readiness_before(deadline).await;
        let policy = self
            .inner
            .topology
            .fixed_durable_placement_policy()
            .unwrap_or_default();
        let placement = self
            .refreshed_fixed_quorum_placement_attestation_valid_for_at(attestation, now)
            .map(|_| PlacementResilienceReport::qualified(policy))
            .unwrap_or_else(|| policy.evaluate_unverified());
        self.quorum_readiness_report(placement, report)
    }

    fn quorum_readiness_report(
        &self,
        placement: PlacementResilienceReport,
        report: DurableReadinessReport,
    ) -> SessionQuorumReadinessReport {
        let barrier = report.committed_barrier_index();
        let authority = self
            .fixed_durable_quorum_readiness_report(placement, report)
            .traffic_authority();
        SessionQuorumReadinessReport::new(authority, placement, barrier, self.persistence_health())
    }
}
