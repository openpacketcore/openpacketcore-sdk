//! Verified platform-fact admission for quorum topology.
//!
//! The SDK owns canonical claims, bounds, binding checks, freshness checks,
//! and redaction. A consumer-selected [`QuorumTopologyAttestor`] remains the
//! trust boundary that authenticates an opaque platform proof. This module
//! deliberately does not claim that constructing a Rust value authenticates
//! Kubernetes, cloud, storage, workload-identity, or hardware facts.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::consensus::SessionConsensusIdentity;
use crate::topology::{
    QuorumTopologyError, QuorumTopologyMode, ReplicaBackingIdentity, ReplicaFailureDomain,
    ReplicaId, ReplicaTlsIdentity, ValidatedQuorumTopology, QUORUM_TOPOLOGY_MAX_MEMBERS,
    REPLICA_IDENTITY_MAX_BYTES,
};

/// Maximum opaque proof size accepted for one replica observation.
pub const TOPOLOGY_ATTESTATION_MAX_PROOF_BYTES: usize = 64 * 1024;

/// Maximum number of independently configured trusted collectors.
pub const TOPOLOGY_ATTESTATION_MAX_TRUSTED_COLLECTORS: usize = 32;

/// Hard upper bound on one evidence token's validity window.
pub const TOPOLOGY_ATTESTATION_MAX_VALIDITY: Duration = Duration::from_secs(60 * 60);

const TOPOLOGY_COLLECTOR_ID_DOMAIN: &[u8] =
    b"openpacketcore/session-store/topology-collector-id/v1\0";
const TOPOLOGY_PHYSICAL_NODE_ID_DOMAIN: &[u8] =
    b"openpacketcore/session-store/topology-physical-node-id/v1\0";
const TOPOLOGY_ATTESTATION_CLAIMS_DOMAIN: &[u8] =
    b"openpacketcore/session-store/topology-attestation-claims/v1\0";

/// Trust/provenance class asserted by an evidence collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TopologyAttestationProvenance {
    /// Facts authenticated by a consumer-selected production platform adapter.
    AuthenticatedPlatform,
    /// Deterministic evidence intended only for conformance and test harnesses.
    DeterministicConformance,
    /// Unverified descriptor strings; never accepted by an attestation policy.
    UnverifiedConfiguration,
}

impl TopologyAttestationProvenance {
    /// Stable low-cardinality status code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticatedPlatform => "authenticated-platform",
            Self::DeterministicConformance => "deterministic-conformance",
            Self::UnverifiedConfiguration => "unverified-configuration",
        }
    }

    /// Whether this class can support production topology readiness.
    pub const fn is_production_eligible(self) -> bool {
        matches!(self, Self::AuthenticatedPlatform)
    }
}

fn digest_opaque_identity(
    value: &str,
    domain: &[u8],
) -> Result<[u8; 32], TopologyAttestationBuildError> {
    if value.is_empty()
        || value.len() > REPLICA_IDENTITY_MAX_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(TopologyAttestationBuildError::InvalidIdentity);
    }
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value.as_bytes());
    Ok(hasher.finalize().into())
}

/// Opaque stable identity of a configured evidence collector.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TopologyCollectorId([u8; 32]);

impl TopologyCollectorId {
    /// Validate and hash a non-secret stable collector identity.
    pub fn new(value: impl AsRef<str>) -> Result<Self, TopologyAttestationBuildError> {
        digest_opaque_identity(value.as_ref(), TOPOLOGY_COLLECTOR_ID_DOMAIN).map(Self)
    }

    /// Fixed-width identity used by policy and canonical claim binding.
    pub const fn fingerprint(&self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for TopologyCollectorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TopologyCollectorId(<redacted>)")
    }
}

/// Opaque stable identity of the physical node hosting one logical voter.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ObservedPhysicalNodeIdentity([u8; 32]);

impl ObservedPhysicalNodeIdentity {
    /// Validate and hash an attestor-observed physical node identity.
    pub fn new(value: impl AsRef<str>) -> Result<Self, TopologyAttestationBuildError> {
        digest_opaque_identity(value.as_ref(), TOPOLOGY_PHYSICAL_NODE_ID_DOMAIN).map(Self)
    }

    /// Fixed-width identity used for uniqueness and canonical claim binding.
    pub const fn fingerprint(&self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for ObservedPhysicalNodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ObservedPhysicalNodeIdentity(<redacted>)")
    }
}

/// Deterministic wall-clock instant used for attestation freshness.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TopologyAttestationTime(u64);

impl TopologyAttestationTime {
    /// Construct from whole seconds since the Unix epoch.
    pub const fn from_unix_seconds(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Read the current system time at whole-second precision.
    pub fn now() -> Result<Self, TopologyAttestationBuildError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TopologyAttestationBuildError::ClockBeforeUnixEpoch)?;
        Ok(Self(elapsed.as_secs()))
    }

    /// Whole seconds since the Unix epoch.
    pub const fn unix_seconds(self) -> u64 {
        self.0
    }

    fn checked_add(self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration.as_secs()).map(Self)
    }

    fn saturating_duration_since(self, earlier: Self) -> Duration {
        Duration::from_secs(self.0.saturating_sub(earlier.0))
    }
}

impl fmt::Debug for TopologyAttestationTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TopologyAttestationTime(<redacted>)")
    }
}

/// Failure to construct bounded attestation input or policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TopologyAttestationBuildError {
    /// An opaque collector or physical-node identity was malformed.
    #[error("invalid topology attestation identity")]
    InvalidIdentity,
    /// A proof was empty or exceeded the fixed SDK bound.
    #[error("invalid topology attestation proof length")]
    InvalidProofLength,
    /// A trust policy had no collectors, duplicate collectors, or invalid bounds.
    #[error("invalid topology attestation policy")]
    InvalidPolicy,
    /// The platform clock could not be represented relative to the Unix epoch.
    #[error("topology attestation clock is invalid")]
    ClockBeforeUnixEpoch,
}

/// Stable verifier failure returned by a consumer-selected attestor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TopologyAttestationVerificationError {
    /// Authentication or signature verification failed.
    #[error("topology attestation proof authentication failed")]
    InvalidProof,
    /// The evidence encoding or version is unsupported.
    #[error("topology attestation proof format is unsupported")]
    UnsupportedEvidence,
    /// The external verification authority was unavailable.
    #[error("topology attestation verifier is unavailable")]
    VerifierUnavailable,
}

impl TopologyAttestationVerificationError {
    /// Stable low-cardinality failure code.
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidProof => "invalid_proof",
            Self::UnsupportedEvidence => "unsupported_evidence",
            Self::VerifierUnavailable => "verifier_unavailable",
        }
    }
}

/// Canonical facts that an attestor binds into one replica proof.
///
/// Constructing claims does not authenticate them. The selected attestor must
/// verify a proof over [`Self::canonical_digest`] before admission succeeds.
#[derive(Clone)]
pub struct TopologyAttestationClaims {
    member_id: ReplicaId,
    authenticated_service_identity: ReplicaTlsIdentity,
    physical_node_identity: ObservedPhysicalNodeIdentity,
    failure_domain_identity: ReplicaFailureDomain,
    durable_backing_identity: ReplicaBackingIdentity,
    descriptor_fingerprint: [u8; 32],
    consensus_identity: SessionConsensusIdentity,
    collector_id: TopologyCollectorId,
    provenance: TopologyAttestationProvenance,
    observed_at: TopologyAttestationTime,
    expires_at: TopologyAttestationTime,
}

impl TopologyAttestationClaims {
    /// Construct canonical claims from facts observed by a platform adapter.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        member_id: ReplicaId,
        authenticated_service_identity: ReplicaTlsIdentity,
        physical_node_identity: ObservedPhysicalNodeIdentity,
        failure_domain_identity: ReplicaFailureDomain,
        durable_backing_identity: ReplicaBackingIdentity,
        descriptor_fingerprint: [u8; 32],
        consensus_identity: SessionConsensusIdentity,
        collector_id: TopologyCollectorId,
        provenance: TopologyAttestationProvenance,
        observed_at: TopologyAttestationTime,
        expires_at: TopologyAttestationTime,
    ) -> Self {
        Self {
            member_id,
            authenticated_service_identity,
            physical_node_identity,
            failure_domain_identity,
            durable_backing_identity,
            descriptor_fingerprint,
            consensus_identity,
            collector_id,
            provenance,
            observed_at,
            expires_at,
        }
    }

    /// Domain-separated, architecture-independent digest an attestor signs.
    pub fn canonical_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(TOPOLOGY_ATTESTATION_CLAIMS_DOMAIN);
        hasher.update(Sha256::digest(self.member_id.as_str().as_bytes()));
        hasher.update(Sha256::digest(
            self.authenticated_service_identity.as_str().as_bytes(),
        ));
        hasher.update(self.physical_node_identity.fingerprint());
        hasher.update(Sha256::digest(
            self.failure_domain_identity.as_str().as_bytes(),
        ));
        hasher.update(self.durable_backing_identity.fingerprint());
        hasher.update(self.descriptor_fingerprint);
        hasher.update(self.consensus_identity.cluster_id().as_bytes());
        hasher.update(self.consensus_identity.configuration_id().as_bytes());
        hasher.update(
            self.consensus_identity
                .configuration_epoch()
                .get()
                .to_be_bytes(),
        );
        hasher.update(self.collector_id.fingerprint());
        hasher.update([match self.provenance {
            TopologyAttestationProvenance::AuthenticatedPlatform => 1,
            TopologyAttestationProvenance::DeterministicConformance => 2,
            TopologyAttestationProvenance::UnverifiedConfiguration => 3,
        }]);
        hasher.update(self.observed_at.unix_seconds().to_be_bytes());
        hasher.update(self.expires_at.unix_seconds().to_be_bytes());
        hasher.finalize().into()
    }
}

impl fmt::Debug for TopologyAttestationClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TopologyAttestationClaims")
            .field("provenance", &self.provenance)
            .field(
                "configuration_epoch",
                &self.consensus_identity.configuration_epoch().get(),
            )
            .field(
                "validity_seconds",
                &self.expires_at.0.saturating_sub(self.observed_at.0),
            )
            .finish_non_exhaustive()
    }
}

/// One bounded opaque proof plus the canonical claims it authenticates.
#[derive(Clone)]
pub struct TopologyAttestationEvidence {
    claims: TopologyAttestationClaims,
    proof: Vec<u8>,
}

impl TopologyAttestationEvidence {
    /// Bind canonical claims to a bounded opaque platform proof.
    pub fn try_new(
        claims: TopologyAttestationClaims,
        proof: Vec<u8>,
    ) -> Result<Self, TopologyAttestationBuildError> {
        if proof.is_empty() || proof.len() > TOPOLOGY_ATTESTATION_MAX_PROOF_BYTES {
            return Err(TopologyAttestationBuildError::InvalidProofLength);
        }
        Ok(Self { claims, proof })
    }

    /// Canonical digest that the opaque proof must authenticate.
    pub fn canonical_digest(&self) -> [u8; 32] {
        self.claims.canonical_digest()
    }
}

impl fmt::Debug for TopologyAttestationEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TopologyAttestationEvidence")
            .field("provenance", &self.claims.provenance)
            .field(
                "configuration_epoch",
                &self.claims.consensus_identity.configuration_epoch().get(),
            )
            .field(
                "validity_seconds",
                &self
                    .claims
                    .expires_at
                    .0
                    .saturating_sub(self.claims.observed_at.0),
            )
            .field("result", &"unverified")
            .finish()
    }
}

/// Redaction-safe input passed to a consumer-selected proof verifier.
#[derive(Clone, Copy)]
pub struct TopologyAttestationVerificationInput<'a> {
    canonical_digest: [u8; 32],
    proof: &'a [u8],
    collector_id: &'a TopologyCollectorId,
    provenance: TopologyAttestationProvenance,
}

impl TopologyAttestationVerificationInput<'_> {
    /// Exact SDK-canonical claims digest the proof must authenticate.
    pub const fn canonical_digest(&self) -> [u8; 32] {
        self.canonical_digest
    }

    /// Bounded opaque proof bytes supplied by the platform adapter.
    pub const fn proof(&self) -> &[u8] {
        self.proof
    }

    /// Opaque collector identity selected by the trust policy.
    pub const fn collector_id(&self) -> &TopologyCollectorId {
        self.collector_id
    }

    /// Explicit provenance class selected by the trust policy.
    pub const fn provenance(&self) -> TopologyAttestationProvenance {
        self.provenance
    }
}

impl fmt::Debug for TopologyAttestationVerificationInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TopologyAttestationVerificationInput")
            .field("provenance", &self.provenance)
            .finish_non_exhaustive()
    }
}

/// Consumer-selected port that authenticates platform evidence.
///
/// A production implementation must verify the opaque proof against the
/// canonical digest and configured collector trust roots. Returning `Ok(())`
/// is an explicit trust decision; the SDK independently rechecks every claim's
/// topology binding, uniqueness, epoch, and freshness afterward.
pub trait QuorumTopologyAttestor: Send + Sync {
    /// Authenticate one bounded evidence token.
    fn verify(
        &self,
        input: TopologyAttestationVerificationInput<'_>,
    ) -> Result<(), TopologyAttestationVerificationError>;
}

/// Explicit trust policy for one topology admission.
#[derive(Clone)]
pub struct TopologyAttestationPolicy {
    provenance: TopologyAttestationProvenance,
    trusted_collectors: Vec<TopologyCollectorId>,
    maximum_observation_age: Duration,
}

impl TopologyAttestationPolicy {
    /// Construct a bounded policy for one provenance class and collector set.
    pub fn try_new(
        provenance: TopologyAttestationProvenance,
        trusted_collectors: Vec<TopologyCollectorId>,
        maximum_observation_age: Duration,
    ) -> Result<Self, TopologyAttestationBuildError> {
        if provenance == TopologyAttestationProvenance::UnverifiedConfiguration
            || trusted_collectors.is_empty()
            || trusted_collectors.len() > TOPOLOGY_ATTESTATION_MAX_TRUSTED_COLLECTORS
            || maximum_observation_age.is_zero()
            || maximum_observation_age.subsec_nanos() != 0
            || maximum_observation_age > TOPOLOGY_ATTESTATION_MAX_VALIDITY
        {
            return Err(TopologyAttestationBuildError::InvalidPolicy);
        }
        let unique = trusted_collectors.iter().collect::<HashSet<_>>();
        if unique.len() != trusted_collectors.len() {
            return Err(TopologyAttestationBuildError::InvalidPolicy);
        }
        Ok(Self {
            provenance,
            trusted_collectors,
            maximum_observation_age,
        })
    }

    /// Required provenance class.
    pub const fn provenance(&self) -> TopologyAttestationProvenance {
        self.provenance
    }

    /// Maximum age of the oldest observation at admission/readiness.
    pub const fn maximum_observation_age(&self) -> Duration {
        self.maximum_observation_age
    }

    fn trusts(&self, collector_id: &TopologyCollectorId) -> bool {
        self.trusted_collectors.contains(collector_id)
    }
}

impl fmt::Debug for TopologyAttestationPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TopologyAttestationPolicy")
            .field("provenance", &self.provenance)
            .field("trusted_collector_count", &self.trusted_collectors.len())
            .field("maximum_observation_age", &self.maximum_observation_age)
            .finish()
    }
}

/// Point-in-time result of topology evidence evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TopologyAttestationResult {
    /// Every member carried a wall-clock-fresh authenticated proof.
    ///
    /// Production authority additionally requires the store's monotonic expiry
    /// and nondecreasing clock checks.
    Verified,
    /// Topology contains configuration descriptors only and is lab-labelled.
    DescriptorOnlyLab,
    /// One or more previously admitted observations are now expired.
    Expired,
    /// Evaluation preceded the observation window and fails closed.
    NotYetValid,
}

impl TopologyAttestationResult {
    /// Stable low-cardinality result code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::DescriptorOnlyLab => "descriptor-only-lab",
            Self::Expired => "expired",
            Self::NotYetValid => "not-yet-valid",
        }
    }

    /// Whether authenticated evidence is currently fresh.
    pub const fn is_verified(self) -> bool {
        matches!(self, Self::Verified)
    }
}

/// Redaction-safe freshness bounds for an admitted evidence set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TopologyAttestationFreshness {
    oldest_observation_age: Duration,
    valid_for: Duration,
}

impl TopologyAttestationFreshness {
    /// Age of the oldest member observation at evaluation time.
    pub const fn oldest_observation_age(self) -> Duration {
        self.oldest_observation_age
    }

    /// Wall-clock time until the first member observation becomes stale or
    /// expires. This diagnostic does not include monotonic expiry.
    pub const fn valid_for(self) -> Duration {
        self.valid_for
    }
}

/// Redaction-safe topology evidence status.
///
/// The summary exposes only provenance, configuration epoch, freshness, and
/// result. It never contains member, collector, endpoint, TLS, node, failure
/// domain, backing, proof, or canonical-digest material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TopologyAttestationSummary {
    provenance: TopologyAttestationProvenance,
    configuration_epoch: u64,
    freshness: Option<TopologyAttestationFreshness>,
    result: TopologyAttestationResult,
}

/// Opaque result of authenticating one complete evidence set.
///
/// The value is bound to one exact consensus identity and can be supplied to a
/// later production readiness probe. This lets long-running consumers refresh
/// expiring platform evidence without changing membership or reopening the
/// consensus engine. Its `Debug` output is limited to the redaction-safe
/// summary contract.
///
/// The token is deliberately process-local and implements neither
/// `serde::Serialize` nor `serde::Deserialize`; it cannot carry its monotonic
/// anchor across a process restart. The consumer must authenticate evidence
/// again against current time after restart. A still-unexpired underlying proof
/// may be re-presented only when its adapter-defined replay policy permits it;
/// otherwise the consumer collects replacement evidence. This type-level
/// property does not itself make an opaque proof single-use:
///
/// ```compile_fail
/// fn assert_serialize<T: serde::Serialize>() {}
/// assert_serialize::<opc_session_store::VerifiedQuorumTopologyAttestation>();
/// ```
///
/// ```compile_fail
/// fn assert_deserialize<T: serde::de::DeserializeOwned>() {}
/// assert_deserialize::<opc_session_store::VerifiedQuorumTopologyAttestation>();
/// ```
#[derive(Clone)]
pub struct VerifiedQuorumTopologyAttestation {
    consensus_identity: SessionConsensusIdentity,
    admission: TopologyAttestationAdmission,
    verified_at: TopologyAttestationTime,
}

impl VerifiedQuorumTopologyAttestation {
    /// Evaluate wall-clock provenance and freshness at `now` for diagnostics.
    ///
    /// This summary is not production authority: only the store's production
    /// profile/readiness methods also enforce the token's monotonic lifetime,
    /// nondecreasing per-store time authority, and exact consensus identity.
    pub fn summary_at(&self, now: TopologyAttestationTime) -> TopologyAttestationSummary {
        self.admission.summary_at(now)
    }

    pub(crate) const fn consensus_identity(&self) -> SessionConsensusIdentity {
        self.consensus_identity
    }

    pub(crate) fn admission(&self) -> &TopologyAttestationAdmission {
        &self.admission
    }
}

impl fmt::Debug for VerifiedQuorumTopologyAttestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.summary_at(self.verified_at).fmt(f)
    }
}

impl TopologyAttestationSummary {
    /// Evidence provenance class.
    pub const fn provenance(self) -> TopologyAttestationProvenance {
        self.provenance
    }

    /// Consensus configuration/topology epoch bound into the evidence.
    pub const fn configuration_epoch(self) -> u64 {
        self.configuration_epoch
    }

    /// Current freshness bounds, when evidence exists.
    pub const fn freshness(self) -> Option<TopologyAttestationFreshness> {
        self.freshness
    }

    /// Point-in-time evidence result.
    pub const fn result(self) -> TopologyAttestationResult {
        self.result
    }

    /// Whether the wall-clock summary is production-eligible.
    ///
    /// This diagnostic alone cannot authorize traffic; use the store's
    /// production profile and readiness methods for the complete authority
    /// check.
    pub const fn is_production_verified(self) -> bool {
        self.result.is_verified() && self.provenance.is_production_eligible()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum TopologyAttestationAdmission {
    DescriptorOnly {
        configuration_epoch: u64,
    },
    Verified {
        provenance: TopologyAttestationProvenance,
        configuration_epoch: u64,
        oldest_observed_at: TopologyAttestationTime,
        latest_observed_at: TopologyAttestationTime,
        earliest_effective_expiry: TopologyAttestationTime,
        verified_at: TopologyAttestationTime,
        monotonic_expires_at: Instant,
    },
}

impl fmt::Debug for TopologyAttestationAdmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DescriptorOnly {
                configuration_epoch,
            } => f
                .debug_struct("TopologyAttestationAdmission")
                .field(
                    "provenance",
                    &TopologyAttestationProvenance::UnverifiedConfiguration,
                )
                .field("configuration_epoch", configuration_epoch)
                .field("freshness", &Option::<TopologyAttestationFreshness>::None)
                .field("result", &TopologyAttestationResult::DescriptorOnlyLab)
                .finish(),
            Self::Verified {
                provenance,
                configuration_epoch,
                oldest_observed_at,
                earliest_effective_expiry,
                ..
            } => f
                .debug_struct("TopologyAttestationAdmission")
                .field("provenance", provenance)
                .field("configuration_epoch", configuration_epoch)
                .field(
                    "freshness",
                    &earliest_effective_expiry
                        .0
                        .saturating_sub(oldest_observed_at.0),
                )
                .field("result", &TopologyAttestationResult::Verified)
                .finish(),
        }
    }
}

impl TopologyAttestationAdmission {
    pub(crate) const fn descriptor_only(configuration_epoch: u64) -> Self {
        Self::DescriptorOnly {
            configuration_epoch,
        }
    }

    pub(crate) fn summary_at(&self, now: TopologyAttestationTime) -> TopologyAttestationSummary {
        match self {
            Self::DescriptorOnly {
                configuration_epoch,
            } => TopologyAttestationSummary {
                provenance: TopologyAttestationProvenance::UnverifiedConfiguration,
                configuration_epoch: *configuration_epoch,
                freshness: None,
                result: TopologyAttestationResult::DescriptorOnlyLab,
            },
            Self::Verified {
                provenance,
                configuration_epoch,
                oldest_observed_at,
                latest_observed_at,
                earliest_effective_expiry,
                ..
            } => {
                let result = if now < *latest_observed_at {
                    TopologyAttestationResult::NotYetValid
                } else if now >= *earliest_effective_expiry {
                    TopologyAttestationResult::Expired
                } else {
                    TopologyAttestationResult::Verified
                };
                TopologyAttestationSummary {
                    provenance: *provenance,
                    configuration_epoch: *configuration_epoch,
                    freshness: Some(TopologyAttestationFreshness {
                        oldest_observation_age: now.saturating_duration_since(*oldest_observed_at),
                        valid_for: earliest_effective_expiry.saturating_duration_since(now),
                    }),
                    result,
                }
            }
        }
    }

    pub(crate) const fn production_verified_at(&self) -> Option<TopologyAttestationTime> {
        match self {
            Self::Verified {
                provenance: TopologyAttestationProvenance::AuthenticatedPlatform,
                verified_at,
                ..
            } => Some(*verified_at),
            Self::DescriptorOnly { .. } | Self::Verified { .. } => None,
        }
    }

    pub(crate) fn production_valid_for_at(
        &self,
        now: TopologyAttestationTime,
        monotonic_now: Instant,
    ) -> Option<Duration> {
        let summary = self.summary_at(now);
        if !summary.is_production_verified() {
            return None;
        }
        let wall_valid_for = summary.freshness()?.valid_for();
        let monotonic_valid_for = match self {
            Self::Verified {
                monotonic_expires_at,
                ..
            } => monotonic_expires_at.checked_duration_since(monotonic_now)?,
            Self::DescriptorOnly { .. } => return None,
        };
        (!wall_valid_for.is_zero() && !monotonic_valid_for.is_zero())
            .then_some(wall_valid_for.min(monotonic_valid_for))
    }
}

pub(crate) fn verify_topology_attestations(
    topology: &ValidatedQuorumTopology,
    evidence: Vec<TopologyAttestationEvidence>,
    policy: &TopologyAttestationPolicy,
    attestor: &dyn QuorumTopologyAttestor,
    now: TopologyAttestationTime,
) -> Result<VerifiedQuorumTopologyAttestation, QuorumTopologyError> {
    let monotonic_verified_at = Instant::now();
    if topology.summary().mode() != QuorumTopologyMode::AttestedHa {
        return Err(QuorumTopologyError::TopologyEvidenceRequiresAttestedHa);
    }
    if evidence.len() != topology.members().len() || evidence.len() > QUORUM_TOPOLOGY_MAX_MEMBERS {
        return Err(QuorumTopologyError::TopologyEvidenceCountMismatch);
    }
    let identity = topology
        .consensus_identity()
        .ok_or(QuorumTopologyError::MissingConsensusIdentity)?;
    let members = topology
        .members()
        .iter()
        .map(|descriptor| (descriptor.replica_id(), descriptor))
        .collect::<HashMap<_, _>>();
    let mut seen_members = HashSet::with_capacity(evidence.len());
    let mut physical_nodes = HashSet::with_capacity(evidence.len());
    let mut failure_domains = HashSet::with_capacity(evidence.len());
    let mut backing_identities = HashSet::with_capacity(evidence.len());
    let mut oldest_observed_at = now;
    let mut latest_observed_at = TopologyAttestationTime::from_unix_seconds(0);
    let mut earliest_effective_expiry: Option<TopologyAttestationTime> = None;

    for token in &evidence {
        let claims = &token.claims;
        if !seen_members.insert(claims.member_id.clone()) {
            return Err(QuorumTopologyError::DuplicateTopologyEvidenceMember);
        }
        let descriptor = members
            .get(&claims.member_id)
            .copied()
            .ok_or(QuorumTopologyError::UnexpectedTopologyEvidenceMember)?;
        if claims.provenance != policy.provenance {
            return Err(QuorumTopologyError::TopologyEvidenceProvenanceMismatch);
        }
        if !policy.trusts(&claims.collector_id) {
            return Err(QuorumTopologyError::UntrustedTopologyEvidenceCollector);
        }
        if claims.consensus_identity != identity {
            return Err(QuorumTopologyError::TopologyEvidenceEpochMismatch);
        }
        if claims.observed_at > now {
            return Err(QuorumTopologyError::TopologyEvidenceNotYetValid);
        }
        let validity = claims
            .expires_at
            .0
            .checked_sub(claims.observed_at.0)
            .filter(|seconds| *seconds > 0)
            .map(Duration::from_secs)
            .ok_or(QuorumTopologyError::TopologyEvidenceValidityInvalid)?;
        if validity > TOPOLOGY_ATTESTATION_MAX_VALIDITY {
            return Err(QuorumTopologyError::TopologyEvidenceValidityInvalid);
        }
        let age = now.saturating_duration_since(claims.observed_at);
        if claims.expires_at <= now || age >= policy.maximum_observation_age {
            return Err(QuorumTopologyError::TopologyEvidenceExpired);
        }

        attestor
            .verify(TopologyAttestationVerificationInput {
                canonical_digest: token.canonical_digest(),
                proof: &token.proof,
                collector_id: &claims.collector_id,
                provenance: claims.provenance,
            })
            .map_err(|_| QuorumTopologyError::TopologyEvidenceVerificationFailed)?;

        if !physical_nodes.insert(claims.physical_node_identity.clone()) {
            return Err(QuorumTopologyError::DuplicateObservedPhysicalNode);
        }
        if !failure_domains.insert(claims.failure_domain_identity.clone()) {
            return Err(QuorumTopologyError::DuplicateObservedFailureDomain);
        }
        if !backing_identities.insert(claims.durable_backing_identity.clone()) {
            return Err(QuorumTopologyError::DuplicateObservedBackingIdentity);
        }
        if claims.descriptor_fingerprint != descriptor.configuration_fingerprint() {
            return Err(QuorumTopologyError::TopologyEvidenceDescriptorMismatch);
        }
        if claims.authenticated_service_identity != *descriptor.tls_identity() {
            return Err(QuorumTopologyError::TopologyEvidenceTlsIdentityMismatch);
        }
        if claims.failure_domain_identity != *descriptor.failure_domain() {
            return Err(QuorumTopologyError::TopologyEvidenceFailureDomainMismatch);
        }
        if claims.durable_backing_identity != *descriptor.backing_identity() {
            return Err(QuorumTopologyError::TopologyEvidenceBackingIdentityMismatch);
        }

        oldest_observed_at = oldest_observed_at.min(claims.observed_at);
        latest_observed_at = latest_observed_at.max(claims.observed_at);
        let age_expiry = claims
            .observed_at
            .checked_add(policy.maximum_observation_age)
            .ok_or(QuorumTopologyError::TopologyEvidenceValidityInvalid)?;
        let effective_expiry = claims.expires_at.min(age_expiry);
        earliest_effective_expiry = Some(
            earliest_effective_expiry
                .map_or(effective_expiry, |current| current.min(effective_expiry)),
        );
    }

    if seen_members.len() != members.len() {
        return Err(QuorumTopologyError::TopologyEvidenceCountMismatch);
    }
    let earliest_effective_expiry =
        earliest_effective_expiry.ok_or(QuorumTopologyError::TopologyEvidenceCountMismatch)?;
    let remaining_validity = earliest_effective_expiry.saturating_duration_since(now);
    let monotonic_expires_at = monotonic_verified_at
        .checked_add(remaining_validity)
        .ok_or(QuorumTopologyError::TopologyEvidenceValidityInvalid)?;
    if Instant::now() >= monotonic_expires_at {
        return Err(QuorumTopologyError::TopologyEvidenceExpired);
    }
    Ok(VerifiedQuorumTopologyAttestation {
        consensus_identity: identity,
        admission: TopologyAttestationAdmission::Verified {
            provenance: policy.provenance,
            configuration_epoch: identity.configuration_epoch().get(),
            oldest_observed_at,
            latest_observed_at,
            earliest_effective_expiry,
            verified_at: now,
            monotonic_expires_at,
        },
        verified_at: now,
    })
}
