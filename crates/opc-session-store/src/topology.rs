//! Validated identity and membership for replicated session stores.
//!
//! Descriptor admission is deliberately separate from backend capabilities
//! and runtime readiness. It proves that configured votes are distinct and
//! that exactly one member is local. Production callers add the verifier port
//! in [`crate::topology_attestation`] to bind observed physical facts to the
//! exact configuration epoch. Neither path proves current peer reachability,
//! durable commit authority, or repair safety.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::net::IpAddr;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::capability::SessionStorePlatformProfile;
use crate::consensus::{SessionConsensusIdentity, SessionConsensusNodeId};
use crate::consumer::{SessionConsumerRoster, SessionConsumerRosterError, SessionConsumerScope};
use crate::readiness::PlacementResiliencePolicy;
use crate::topology_attestation::{
    verify_topology_attestations, QuorumTopologyAttestor, TopologyAttestationAdmission,
    TopologyAttestationEvidence, TopologyAttestationPolicy, TopologyAttestationSummary,
    TopologyAttestationTime, VerifiedQuorumTopologyAttestation,
};

/// Maximum encoded length of a logical replica ID.
pub const REPLICA_ID_MAX_BYTES: usize = 253;

/// Maximum encoded length of a TLS, failure-domain, or backing-store identity.
pub const REPLICA_IDENTITY_MAX_BYTES: usize = 2_048;

/// Maximum number of configured members admitted into one topology.
///
/// Production quorum sets are expected to be small odd groups. This ceiling
/// bounds validation memory and CPU for operator-controlled configuration.
pub const QUORUM_TOPOLOGY_MAX_MEMBERS: usize = 31;

/// A field in a configured replica descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReplicaTopologyField {
    /// Stable logical replica identifier.
    ReplicaId,
    /// Network endpoint host or port.
    Endpoint,
    /// Expected TLS server or SPIFFE identity.
    TlsIdentity,
    /// Independently failing placement identity.
    FailureDomain,
    /// Caller-declared canonical physical backing-store identity.
    BackingIdentity,
}

impl fmt::Display for ReplicaTopologyField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReplicaId => "replica-id",
            Self::Endpoint => "endpoint",
            Self::TlsIdentity => "tls-identity",
            Self::FailureDomain => "failure-domain",
            Self::BackingIdentity => "backing-identity",
        })
    }
}

/// Redaction-safe reason that a topology field was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReplicaTopologyFieldError {
    /// The field was empty.
    Empty,
    /// The field exceeded its documented byte limit.
    TooLong,
    /// The field was not in the canonical format required by its type.
    Malformed,
}

impl fmt::Display for ReplicaTopologyFieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "empty",
            Self::TooLong => "too-long",
            Self::Malformed => "malformed",
        })
    }
}

/// Failure to validate a quorum or lab-singleton topology.
///
/// Errors intentionally omit raw endpoints, TLS identities, and backing-store
/// identifiers so they are safe for status and operator logs.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum QuorumTopologyError {
    /// One descriptor field was empty, oversized, or non-canonical.
    #[error("invalid replica topology field {field}: {reason}")]
    InvalidField {
        /// Rejected field category.
        field: ReplicaTopologyField,
        /// Stable rejection reason.
        reason: ReplicaTopologyFieldError,
    },
    /// An HA topology contained fewer than three configured members.
    #[error("validated HA topology requires at least three members; configured {configured}")]
    HaMemberCountTooSmall {
        /// Number of configured members.
        configured: usize,
    },
    /// An HA topology contained an even number of configured members.
    #[error("validated HA topology requires an odd member count; configured {configured}")]
    HaMemberCountMustBeOdd {
        /// Number of configured members.
        configured: usize,
    },
    /// A fixed durable quorum did not contain exactly three or five voters.
    #[error(
        "fixed durable quorum requires exactly three or five members; configured {configured}"
    )]
    FixedQuorumMemberCount {
        /// Number of configured members.
        configured: usize,
    },
    /// A topology exceeded the bounded configured membership limit.
    #[error("session topology has too many members; configured {configured}, maximum {max}")]
    MemberCountTooLarge {
        /// Number of configured members.
        configured: usize,
        /// Maximum admitted member count.
        max: usize,
    },
    /// A lab topology did not contain exactly one member.
    #[error("lab singleton topology requires exactly one member; configured {configured}")]
    LabMemberCount {
        /// Number of configured members.
        configured: usize,
    },
    /// The exact local logical ID did not identify any configured member.
    #[error("local replica ID does not identify a configured member")]
    MissingLocalReplica,
    /// The local logical ID identified more than one configured member.
    #[error("local replica ID is ambiguous across {matches} configured members")]
    AmbiguousLocalReplica {
        /// Number of members matching the local logical ID.
        matches: usize,
    },
    /// Two members declared the same stable logical replica ID.
    #[error("configured members contain a duplicate logical replica ID")]
    DuplicateReplicaId,
    /// Two members declared the same canonical network endpoint.
    #[error("configured members contain a duplicate network endpoint")]
    DuplicateEndpoint,
    /// Two members declared the same expected TLS identity.
    #[error("configured members contain a duplicate TLS identity")]
    DuplicateTlsIdentity,
    /// Two votes occupy the same declared failure domain.
    #[error("configured members contain a duplicate failure domain")]
    DuplicateFailureDomain,
    /// Two votes target the same declared physical backing identity.
    #[error("configured members contain a duplicate backing identity")]
    DuplicateBackingIdentity,
    /// An HA topology omitted the identity that scopes persisted consensus
    /// state and authenticated RPCs.
    #[error("validated HA topology is missing a consensus identity")]
    MissingConsensusIdentity,
    /// The supplied configuration digest did not cover the admitted member
    /// descriptor set under the supplied cluster and epoch.
    #[error("consensus configuration identity does not match admitted topology")]
    ConsensusConfigurationIdMismatch,
    /// Two logical member identities derived the same fixed-width Openraft
    /// node ID. Admission fails rather than aliasing votes.
    #[error("configured members contain a duplicate consensus node ID")]
    DuplicateConsensusNodeId,
    /// The evidence set did not contain exactly one token per admitted member.
    #[error("topology evidence count does not match admitted membership")]
    TopologyEvidenceCountMismatch,
    /// A descriptor-only or singleton topology attempted to verify refreshed
    /// production evidence. Evidence can refresh only an originally attested
    /// immutable HA topology; it cannot upgrade a lab topology after admission.
    #[error("topology evidence refresh requires an attested HA topology")]
    TopologyEvidenceRequiresAttestedHa,
    /// More than one evidence token claimed the same logical member.
    #[error("topology evidence contains a duplicate logical member")]
    DuplicateTopologyEvidenceMember,
    /// Evidence claimed a member outside the exact admitted configuration.
    #[error("topology evidence names an unexpected logical member")]
    UnexpectedTopologyEvidenceMember,
    /// Evidence provenance did not match the explicitly selected trust policy.
    #[error("topology evidence provenance does not match admission policy")]
    TopologyEvidenceProvenanceMismatch,
    /// Evidence came from a collector outside the explicit trust policy.
    #[error("topology evidence collector is not trusted")]
    UntrustedTopologyEvidenceCollector,
    /// Evidence was bound to another cluster, configuration, or epoch.
    #[error("topology evidence does not match the consensus epoch")]
    TopologyEvidenceEpochMismatch,
    /// Evidence begins after the admission evaluation time.
    #[error("topology evidence is not yet valid")]
    TopologyEvidenceNotYetValid,
    /// Evidence had an empty, overflowing, or excessive validity window.
    #[error("topology evidence validity window is invalid")]
    TopologyEvidenceValidityInvalid,
    /// Evidence was expired or older than the selected freshness policy.
    #[error("topology evidence is expired")]
    TopologyEvidenceExpired,
    /// The selected attestor did not authenticate the opaque proof.
    #[error("topology evidence verification failed")]
    TopologyEvidenceVerificationFailed,
    /// Two logical votes were observed on the same physical node.
    #[error("topology evidence contains a duplicate physical node")]
    DuplicateObservedPhysicalNode,
    /// Two logical votes were observed in the same failure domain.
    #[error("topology evidence contains a duplicate failure domain")]
    DuplicateObservedFailureDomain,
    /// Two logical votes were observed on the same durable backing store.
    #[error("topology evidence contains a duplicate backing identity")]
    DuplicateObservedBackingIdentity,
    /// Evidence did not cover the exact configured member descriptor.
    #[error("topology evidence does not match the member descriptor")]
    TopologyEvidenceDescriptorMismatch,
    /// The authenticated service identity did not match the configured member.
    #[error("topology evidence does not match the member TLS identity")]
    TopologyEvidenceTlsIdentityMismatch,
    /// The observed failure domain did not match the configured member.
    #[error("topology evidence does not match the member failure domain")]
    TopologyEvidenceFailureDomainMismatch,
    /// The observed durable backing did not match the configured member.
    #[error("topology evidence does not match the member backing identity")]
    TopologyEvidenceBackingIdentityMismatch,
}

fn validate_opaque(
    value: String,
    field: ReplicaTopologyField,
    max_bytes: usize,
) -> Result<String, QuorumTopologyError> {
    if value.is_empty() {
        return Err(QuorumTopologyError::InvalidField {
            field,
            reason: ReplicaTopologyFieldError::Empty,
        });
    }
    if value.len() > max_bytes {
        return Err(QuorumTopologyError::InvalidField {
            field,
            reason: ReplicaTopologyFieldError::TooLong,
        });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(QuorumTopologyError::InvalidField {
            field,
            reason: ReplicaTopologyFieldError::Malformed,
        });
    }
    Ok(value)
}

macro_rules! opaque_identity {
    ($(#[$meta:meta])* $name:ident, $field:expr, $max:expr) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// Maximum encoded input length accepted by [`Self::new`].
            pub const MAX_BYTES: usize = $max;

            /// Validate and construct the identity.
            ///
            /// The input must be non-empty, no longer than
            /// [`Self::MAX_BYTES`], free of control characters, and have no
            /// surrounding whitespace.
            pub fn new(value: impl Into<String>) -> Result<Self, QuorumTopologyError> {
                validate_opaque(value.into(), $field, $max).map(Self)
            }

            /// Return the validated identity text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

opaque_identity!(
    /// Stable logical identity of one configured voting replica.
    ReplicaId,
    ReplicaTopologyField::ReplicaId,
    REPLICA_ID_MAX_BYTES
);

opaque_identity!(
    /// Expected TLS server identity or SPIFFE ID for a configured replica.
    ReplicaTlsIdentity,
    ReplicaTopologyField::TlsIdentity,
    REPLICA_IDENTITY_MAX_BYTES
);

opaque_identity!(
    /// Placement identity that must fail independently from every other vote.
    ReplicaFailureDomain,
    ReplicaTopologyField::FailureDomain,
    REPLICA_IDENTITY_MAX_BYTES
);

/// Canonical TCP endpoint for a configured replica.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReplicaEndpoint {
    host: String,
    port: u16,
}

impl ReplicaEndpoint {
    /// Maximum canonical IP or DNS host length after removing a root dot.
    pub const MAX_CANONICAL_HOST_BYTES: usize = 253;

    /// Build a canonical IP or DNS endpoint.
    ///
    /// DNS names are lower-cased and a single absolute-name trailing dot is
    /// removed. Names are never shortened, resolved, or compared with the
    /// logical [`ReplicaId`]. Ambiguous legacy IPv4 spellings and one-to-four
    /// label numeric names are rejected instead of being treated as DNS.
    /// Canonical hosts may contain at most
    /// [`Self::MAX_CANONICAL_HOST_BYTES`]; an absolute DNS input may contain
    /// one additional trailing root dot.
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, QuorumTopologyError> {
        let host = host.into();
        if port == 0 {
            return Err(QuorumTopologyError::InvalidField {
                field: ReplicaTopologyField::Endpoint,
                reason: ReplicaTopologyFieldError::Malformed,
            });
        }

        let host = validate_opaque(
            host,
            ReplicaTopologyField::Endpoint,
            Self::MAX_CANONICAL_HOST_BYTES + 1,
        )?;
        if host.len() > Self::MAX_CANONICAL_HOST_BYTES && !host.ends_with('.') {
            return Err(QuorumTopologyError::InvalidField {
                field: ReplicaTopologyField::Endpoint,
                reason: ReplicaTopologyFieldError::TooLong,
            });
        }
        let host = if let Ok(ip) = host.parse::<IpAddr>() {
            ip.to_string()
        } else if looks_like_legacy_ipv4_literal(&host) {
            return Err(QuorumTopologyError::InvalidField {
                field: ReplicaTopologyField::Endpoint,
                reason: ReplicaTopologyFieldError::Malformed,
            });
        } else {
            canonical_dns_name(&host)?
        };

        Ok(Self { host, port })
    }

    /// Canonical endpoint host without a trailing dot.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// TCP port for the replica service.
    pub const fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Debug for ReplicaEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplicaEndpoint(<redacted>)")
    }
}

fn looks_like_legacy_ipv4_literal(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    let mut labels = host.split('.');
    let mut count = 0;
    let all_numeric = labels.all(|label| {
        count += 1;
        !label.is_empty()
            && (label.bytes().all(|byte| byte.is_ascii_digit())
                || label
                    .strip_prefix("0x")
                    .or_else(|| label.strip_prefix("0X"))
                    .is_some_and(|hex| {
                        !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                    }))
    });
    all_numeric && (1..=4).contains(&count)
}

fn canonical_dns_name(host: &str) -> Result<String, QuorumTopologyError> {
    let canonical = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    let malformed = canonical.is_empty()
        || !canonical.is_ascii()
        || canonical.len() > ReplicaEndpoint::MAX_CANONICAL_HOST_BYTES
        || canonical.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || !label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || !label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        });
    if malformed {
        return Err(QuorumTopologyError::InvalidField {
            field: ReplicaTopologyField::Endpoint,
            reason: ReplicaTopologyFieldError::Malformed,
        });
    }
    Ok(canonical)
}

/// Opaque canonical identity of the physical store behind one vote.
///
/// Callers should use a stable non-secret value such as a PVC UID, database
/// cluster member ID, or authenticated replica ID. The SDK retains only a
/// SHA-256 digest so errors and debug output cannot reveal the supplied value.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ReplicaBackingIdentity([u8; 32]);

impl ReplicaBackingIdentity {
    /// Maximum encoded input length accepted by [`Self::new`].
    pub const MAX_BYTES: usize = REPLICA_IDENTITY_MAX_BYTES;

    /// Validate and digest a canonical backing-store identity.
    ///
    /// The input follows the same non-empty, no-surrounding-whitespace, and
    /// no-control-character contract as the other opaque identities.
    pub fn new(value: impl Into<String>) -> Result<Self, QuorumTopologyError> {
        let value = validate_opaque(
            value.into(),
            ReplicaTopologyField::BackingIdentity,
            Self::MAX_BYTES,
        )?;
        Ok(Self(Sha256::digest(value.as_bytes()).into()))
    }

    /// Return the fixed-width opaque fingerprint used by topology admission.
    ///
    /// The original caller-supplied identity is never retained. Recovery
    /// tooling uses this fingerprint to prove that two logical votes do not
    /// name the same admitted physical backing store.
    pub const fn fingerprint(&self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for ReplicaBackingIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplicaBackingIdentity(<redacted>)")
    }
}

/// Immutable declared identity of one configured voting member.
#[derive(Clone, PartialEq, Eq)]
pub struct QuorumReplicaDescriptor {
    replica_id: ReplicaId,
    endpoint: ReplicaEndpoint,
    tls_identity: ReplicaTlsIdentity,
    failure_domain: ReplicaFailureDomain,
    backing_identity: ReplicaBackingIdentity,
}

const REPLICA_DESCRIPTOR_FINGERPRINT_DOMAIN: &[u8] =
    b"openpacketcore/session-store/quorum-replica-descriptor/v1\0";
const FIXED_QUORUM_AUTHORITY_PROFILE_DOMAIN: &[u8] =
    b"openpacketcore/session-store/fixed-quorum-authority-profile/v1\0";
const FIXED_QUORUM_POLICY_BINDING_DOMAIN: &[u8] =
    b"openpacketcore/session-store/fixed-quorum-placement-policy/v1\0";

/// Derive the authenticated scope for one immutable fixed durable quorum.
///
/// Dynamic consensus identities continue to derive directly from the member
/// descriptor fingerprints. Fixed quorum authority additionally commits both
/// its fixed authority-profile marker and explicit placement-resilience policy
/// under distinct domains, preventing dynamic and fixed deployments (or fixed
/// deployments that make different resilience claims) from sharing peers,
/// durable state, snapshots, or Openraft traffic.
pub fn derive_fixed_durable_quorum_consensus_identity(
    cluster_id: crate::consensus::SessionConsensusClusterId,
    configuration_epoch: crate::consensus::SessionConsensusConfigurationEpoch,
    member_fingerprints: &[[u8; 32]],
    placement_policy: PlacementResiliencePolicy,
) -> SessionConsensusIdentity {
    let mut profile_hasher = Sha256::new();
    profile_hasher.update(FIXED_QUORUM_AUTHORITY_PROFILE_DOMAIN);
    profile_hasher.update([1_u8]);
    let profile_binding: [u8; 32] = profile_hasher.finalize().into();
    let policy_tag = match placement_policy {
        PlacementResiliencePolicy::RequireIndependentFailureDomains => 1_u8,
        PlacementResiliencePolicy::AllowReducedResilience => 2_u8,
    };
    let mut policy_hasher = Sha256::new();
    policy_hasher.update(FIXED_QUORUM_POLICY_BINDING_DOMAIN);
    policy_hasher.update([policy_tag]);
    let policy_binding: [u8; 32] = policy_hasher.finalize().into();

    let mut authority_components = member_fingerprints.to_vec();
    authority_components.push(profile_binding);
    authority_components.push(policy_binding);
    let configuration_id = opc_consensus::derive_configuration_id(
        cluster_id,
        configuration_epoch,
        &authority_components,
    );
    SessionConsensusIdentity::new(cluster_id, configuration_id, configuration_epoch)
}

fn update_configuration_fingerprint_field(hasher: &mut Sha256, tag: u8, value: &[u8]) {
    // Each variable-width field is independently hashed before entering the
    // outer domain-separated digest. This gives every field a fixed-width
    // boundary without target-width length encodings or delimiter ambiguity.
    hasher.update([tag]);
    hasher.update(Sha256::digest(value));
}

impl QuorumReplicaDescriptor {
    /// Construct a descriptor from independently validated identity fields.
    pub fn new(
        replica_id: ReplicaId,
        endpoint: ReplicaEndpoint,
        tls_identity: ReplicaTlsIdentity,
        failure_domain: ReplicaFailureDomain,
        backing_identity: ReplicaBackingIdentity,
    ) -> Self {
        Self {
            replica_id,
            endpoint,
            tls_identity,
            failure_domain,
            backing_identity,
        }
    }

    /// Stable logical member identity.
    pub fn replica_id(&self) -> &ReplicaId {
        &self.replica_id
    }

    /// Canonical dial endpoint, independent from the logical member ID.
    pub fn endpoint(&self) -> &ReplicaEndpoint {
        &self.endpoint
    }

    /// Declared expected TLS identity.
    pub fn tls_identity(&self) -> &ReplicaTlsIdentity {
        &self.tls_identity
    }

    /// Independently failing placement identity.
    pub fn failure_domain(&self) -> &ReplicaFailureDomain {
        &self.failure_domain
    }

    /// Opaque caller-declared physical backing-store identity.
    pub fn backing_identity(&self) -> &ReplicaBackingIdentity {
        &self.backing_identity
    }

    /// Deterministic fixed-width fingerprint of every descriptor field.
    ///
    /// The digest is domain-separated and architecture-independent. It covers
    /// the logical replica ID, canonical endpoint host and port, TLS identity,
    /// failure domain, and already-digested physical backing identity. It is
    /// suitable for detecting composition drift, but it is not proof that the
    /// caller-declared physical placement or backing store is genuine.
    pub fn configuration_fingerprint(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(REPLICA_DESCRIPTOR_FINGERPRINT_DOMAIN);
        update_configuration_fingerprint_field(&mut hasher, 1, self.replica_id.0.as_bytes());
        update_configuration_fingerprint_field(&mut hasher, 2, self.endpoint.host.as_bytes());
        update_configuration_fingerprint_field(&mut hasher, 3, &self.endpoint.port.to_be_bytes());
        update_configuration_fingerprint_field(&mut hasher, 4, self.tls_identity.0.as_bytes());
        update_configuration_fingerprint_field(&mut hasher, 5, self.failure_domain.0.as_bytes());
        update_configuration_fingerprint_field(&mut hasher, 6, &self.backing_identity.0);
        hasher.finalize().into()
    }
}

impl fmt::Debug for QuorumReplicaDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuorumReplicaDescriptor")
            .field("replica_id", &self.replica_id)
            .field("endpoint", &self.endpoint)
            .field("tls_identity", &self.tls_identity)
            .field("failure_domain", &self.failure_domain)
            .field("backing_identity", &self.backing_identity)
            .finish()
    }
}

/// Unvalidated requested HA topology.
#[derive(Clone)]
pub struct QuorumTopologyConfig {
    local_replica_id: ReplicaId,
    members: Vec<QuorumReplicaDescriptor>,
    consensus_identity: Option<SessionConsensusIdentity>,
}

impl QuorumTopologyConfig {
    /// Define a legacy membership set without durable consensus scope.
    ///
    /// Conversion to validated HA fails closed. This constructor remains only
    /// so older callers receive a typed admission error instead of silently
    /// entering the retired per-replica sequencing protocol.
    #[deprecated(
        since = "0.2.0",
        note = "use QuorumTopologyConfig::new_consensus for HA"
    )]
    pub fn new(local_replica_id: ReplicaId, members: Vec<QuorumReplicaDescriptor>) -> Self {
        Self {
            local_replica_id,
            members,
            consensus_identity: None,
        }
    }

    /// Define an HA membership set scoped to one exact consensus identity.
    ///
    /// Converting this value with [`ValidatedQuorumTopology::try_from`] is the
    /// descriptor-only lab/compatibility path. Production admission passes the
    /// same value to [`ValidatedQuorumTopology::try_from_attested`].
    pub fn new_consensus(
        local_replica_id: ReplicaId,
        members: Vec<QuorumReplicaDescriptor>,
        consensus_identity: SessionConsensusIdentity,
    ) -> Self {
        Self {
            local_replica_id,
            members,
            consensus_identity: Some(consensus_identity),
        }
    }
}

/// Admission mode of a constructed session topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum QuorumTopologyMode {
    /// Descriptor-only odd membership used by labs and compatibility callers.
    ///
    /// The descriptors are distinct but carry no observed platform proof.
    ValidatedHa,
    /// Odd membership whose platform facts were authenticated and bound to the
    /// exact consensus epoch.
    AttestedHa,
    /// Exact fixed 3- or 5-voter durable quorum.
    ///
    /// This admission retains descriptor, endpoint, TLS-identity, and backing
    /// uniqueness, but intentionally does not treat a caller-declared failure
    /// domain as physical-placement proof. The fixed-quorum readiness API
    /// reports placement resilience separately under an explicit policy.
    FixedDurableQuorum,
    /// Explicit one-member lab profile; never an HA claim.
    LabSingleton,
}

impl QuorumTopologyMode {
    /// Stable diagnostic code for this topology mode.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ValidatedHa => "descriptor-only-lab-ha",
            Self::AttestedHa => "attested-ha",
            Self::FixedDurableQuorum => "fixed-durable-quorum",
            Self::LabSingleton => "lab-singleton",
        }
    }

    /// Static platform capability this topology is allowed to advertise.
    ///
    /// HA provenance is time-bound, so neither descriptor-only nor attested HA
    /// can safely advertise a static quorum capability. Consumers must use the
    /// constructed store's time-aware production profile methods. The explicit
    /// lab singleton remains a stable single-replica profile.
    pub const fn platform_profile(self) -> SessionStorePlatformProfile {
        match self {
            Self::ValidatedHa | Self::AttestedHa | Self::FixedDurableQuorum => {
                SessionStorePlatformProfile::Unknown
            }
            Self::LabSingleton => SessionStorePlatformProfile::SingleReplica,
        }
    }
}

/// Redaction-safe summary of admitted topology shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumTopologySummary {
    mode: QuorumTopologyMode,
    configured_members: usize,
    required_quorum: usize,
    local_replica_id: Option<ReplicaId>,
    fixed_durable_placement_policy: Option<PlacementResiliencePolicy>,
    attestation: TopologyAttestationAdmission,
}

impl QuorumTopologySummary {
    /// Admitted topology mode.
    pub const fn mode(&self) -> QuorumTopologyMode {
        self.mode
    }

    /// Immutable number of configured voting members.
    pub const fn configured_members(&self) -> usize {
        self.configured_members
    }

    /// Immutable number of distinct votes required for an operation.
    pub const fn required_quorum(&self) -> usize {
        self.required_quorum
    }

    /// Exact local logical ID. Validated constructors always populate it; the
    /// optional shape is retained for source compatibility with readiness code.
    pub fn local_replica_id(&self) -> Option<&ReplicaId> {
        self.local_replica_id.as_ref()
    }

    /// Immutable fixed-durable placement policy, when this is a fixed quorum.
    ///
    /// The policy describes only the physical-placement resilience claim. It
    /// cannot alter Openraft membership, durable authority, or sequencing.
    pub const fn fixed_durable_placement_policy(&self) -> Option<PlacementResiliencePolicy> {
        self.fixed_durable_placement_policy
    }

    /// Evaluate redaction-safe wall-clock platform-fact status for diagnostics.
    ///
    /// This summary does not apply the store's monotonic expiry or
    /// nondecreasing clock authority and therefore cannot authorize production
    /// traffic.
    pub fn attestation_at(&self, now: TopologyAttestationTime) -> TopologyAttestationSummary {
        self.attestation.summary_at(now)
    }

    pub(crate) const fn attestation_admission(&self) -> &TopologyAttestationAdmission {
        &self.attestation
    }
}

/// Immutable topology that passed descriptor or attested HA/singleton admission.
///
/// Storage backends and network clients are deliberately absent. A consensus
/// node receives its one local backend and exact remote peer map separately,
/// so topology data cannot expose a second mutation surface.
#[derive(Clone)]
pub struct ValidatedQuorumTopology {
    summary: QuorumTopologySummary,
    members: Vec<QuorumReplicaDescriptor>,
    consensus_identity: Option<SessionConsensusIdentity>,
    consensus_node_ids: BTreeMap<ReplicaId, SessionConsensusNodeId>,
}

impl ValidatedQuorumTopology {
    /// Validate HA descriptors and authenticate one fresh platform-fact token
    /// for every exact member.
    ///
    /// `attestor` is the consumer-selected trust boundary. The SDK then
    /// independently enforces exact descriptor, TLS, physical-node,
    /// failure-domain, backing-store, collector, configuration-epoch, and
    /// freshness bindings. The resulting admission has an absolute monotonic
    /// lifetime anchored at verification. That process-local anchor cannot be
    /// persisted across restart: the consumer must authenticate an evidence
    /// set again against current time (or collect replacement evidence) before
    /// reopening production traffic. Whether an adapter may re-present a
    /// still-unexpired proof is owned by that proof format and its replay
    /// policy. Dynamic membership remains a separate API.
    pub fn try_from_attested(
        config: QuorumTopologyConfig,
        evidence: Vec<TopologyAttestationEvidence>,
        policy: &TopologyAttestationPolicy,
        attestor: &dyn QuorumTopologyAttestor,
        now: TopologyAttestationTime,
    ) -> Result<Self, QuorumTopologyError> {
        let mut topology = validate_topology(
            config.local_replica_id,
            config.members,
            QuorumTopologyMode::AttestedHa,
            config.consensus_identity,
            false,
            None,
        )?;
        let verified = verify_topology_attestations(&topology, evidence, policy, attestor, now)?;
        topology.summary.attestation = verified.admission().clone();
        Ok(topology)
    }

    /// Authenticate a replacement evidence set for this exact immutable
    /// topology without changing membership.
    ///
    /// The returned opaque value can gate later production readiness after the
    /// evidence stored at construction expires. It cannot change the cluster,
    /// descriptor set, configuration epoch, member count, or Openraft voter
    /// state; those remain outside this refresh boundary. Replacement evidence
    /// receives a new monotonic lifetime at verification and is process-local.
    pub fn verify_attestation_evidence(
        &self,
        evidence: Vec<TopologyAttestationEvidence>,
        policy: &TopologyAttestationPolicy,
        attestor: &dyn QuorumTopologyAttestor,
        now: TopologyAttestationTime,
    ) -> Result<VerifiedQuorumTopologyAttestation, QuorumTopologyError> {
        if self.summary.mode != QuorumTopologyMode::AttestedHa {
            return Err(QuorumTopologyError::TopologyEvidenceRequiresAttestedHa);
        }
        verify_topology_attestations(self, evidence, policy, attestor, now)
    }

    /// Validate an explicit one-member lab topology backed by Openraft.
    ///
    /// This remains a single-replica platform profile, but exercises the same
    /// consensus engine, durable metadata, and deterministic state machine as
    /// HA instead of a second sequencing implementation.
    pub fn try_new_consensus_lab_singleton(
        local_replica_id: ReplicaId,
        members: Vec<QuorumReplicaDescriptor>,
        consensus_identity: SessionConsensusIdentity,
    ) -> Result<Self, QuorumTopologyError> {
        validate_topology(
            local_replica_id,
            members,
            QuorumTopologyMode::LabSingleton,
            Some(consensus_identity),
            false,
            None,
        )
    }

    /// Validate the exact fixed 3- or 5-voter durable-quorum topology.
    ///
    /// Logical replica IDs, endpoints, TLS identities, backing identities, and
    /// declared failure domains must remain unique. Declared failure domains
    /// are descriptors rather than authenticated physical facts; callers must
    /// use the fixed-quorum readiness report to distinguish the strict
    /// descriptor admission from independently verified physical placement.
    pub fn try_from_fixed_durable_quorum(
        config: QuorumTopologyConfig,
    ) -> Result<Self, QuorumTopologyError> {
        Self::try_from_fixed_durable_quorum_with_placement_policy(
            config,
            PlacementResiliencePolicy::default(),
        )
    }

    /// Validate a fixed durable quorum under an explicit physical-placement
    /// resilience policy.
    ///
    /// The default constructor requires distinct declared failure domains.
    /// `AllowReducedResilience` admits correlation but records that explicit
    /// reduction in the immutable topology summary. It never turns descriptor
    /// values into authenticated physical-placement proof.
    pub fn try_from_fixed_durable_quorum_with_placement_policy(
        config: QuorumTopologyConfig,
        placement_policy: PlacementResiliencePolicy,
    ) -> Result<Self, QuorumTopologyError> {
        validate_topology(
            config.local_replica_id,
            config.members,
            QuorumTopologyMode::FixedDurableQuorum,
            config.consensus_identity,
            matches!(
                placement_policy,
                PlacementResiliencePolicy::AllowReducedResilience
            ),
            Some(placement_policy),
        )
    }

    /// Validate a fixed durable quorum and authenticate its physical-placement
    /// evidence.
    ///
    /// This is additive placement evidence only. Its freshness and expiry do
    /// not change fixed durable quorum traffic authority, membership, recovery,
    /// fencing, or sequencing; they only determine whether the separate
    /// placement-resilience report may assert independence.
    #[allow(clippy::too_many_arguments)]
    pub fn try_from_fixed_durable_quorum_with_authenticated_placement(
        config: QuorumTopologyConfig,
        placement_policy: PlacementResiliencePolicy,
        evidence: Vec<TopologyAttestationEvidence>,
        policy: &TopologyAttestationPolicy,
        attestor: &dyn QuorumTopologyAttestor,
        now: TopologyAttestationTime,
    ) -> Result<Self, QuorumTopologyError> {
        let mut topology =
            Self::try_from_fixed_durable_quorum_with_placement_policy(config, placement_policy)?;
        let verified = verify_topology_attestations(&topology, evidence, policy, attestor, now)?;
        topology.summary.attestation = verified.admission().clone();
        Ok(topology)
    }

    /// Authenticate replacement placement evidence for this exact immutable
    /// fixed durable quorum.
    ///
    /// The returned proof can refresh only the separate placement-resilience
    /// result. It cannot change the fixed voter set, traffic authority, or
    /// local durable voter-store binding.
    pub fn verify_fixed_durable_quorum_placement_evidence(
        &self,
        evidence: Vec<TopologyAttestationEvidence>,
        policy: &TopologyAttestationPolicy,
        attestor: &dyn QuorumTopologyAttestor,
        now: TopologyAttestationTime,
    ) -> Result<VerifiedQuorumTopologyAttestation, QuorumTopologyError> {
        if self.summary.mode != QuorumTopologyMode::FixedDurableQuorum {
            return Err(QuorumTopologyError::TopologyEvidenceRequiresAttestedHa);
        }
        verify_topology_attestations(self, evidence, policy, attestor, now)
    }

    /// Redaction-safe admitted shape.
    pub fn summary(&self) -> &QuorumTopologySummary {
        &self.summary
    }

    /// Static, fail-closed platform profile admitted from topology shape.
    ///
    /// HA evidence is time-bound, so this method returns
    /// [`SessionStorePlatformProfile::Unknown`] for both descriptor-only and
    /// attested HA. Use [`QuorumTopologySummary::attestation_at`] and the
    /// constructed store's production capability/readiness methods for a
    /// production claim.
    pub const fn platform_profile(&self) -> SessionStorePlatformProfile {
        self.summary.mode.platform_profile()
    }

    /// Validated configured member descriptors.
    pub fn members(&self) -> &[QuorumReplicaDescriptor] {
        &self.members
    }

    /// Consensus cluster/configuration/epoch scope, when this topology uses
    /// the production sequencing engine.
    pub const fn consensus_identity(&self) -> Option<SessionConsensusIdentity> {
        self.consensus_identity
    }

    /// Stable cluster-scoped Openraft node ID for one admitted logical member.
    pub fn consensus_node_id(&self, replica_id: &ReplicaId) -> Option<SessionConsensusNodeId> {
        self.consensus_node_ids.get(replica_id).copied()
    }

    /// Stable Openraft node ID of the exact admitted local member.
    pub fn local_consensus_node_id(&self) -> Option<SessionConsensusNodeId> {
        self.summary
            .local_replica_id
            .as_ref()
            .and_then(|replica_id| self.consensus_node_id(replica_id))
    }

    /// Derive the exact canonical application-consumer voter roster from this
    /// validated topology. The commitment is identical on every member and
    /// contains the complete sorted SDK node-to-TLS identity mapping.
    pub fn session_consumer_roster(
        &self,
    ) -> Result<SessionConsumerRoster, SessionConsumerRosterError> {
        let identity = self
            .consensus_identity
            .ok_or(SessionConsumerRosterError::MissingConsensusIdentity)?;
        let expected_members = self
            .consensus_node_ids
            .values()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        let descriptors = self.members.iter().map(|descriptor| {
            let node_id = self
                .consensus_node_ids
                .get(descriptor.replica_id())
                .expect("validated topology retains every member node ID");
            (node_id.get(), descriptor.clone())
        });
        SessionConsumerRoster::try_new(
            SessionConsumerScope::new(identity),
            &expected_members,
            descriptors,
        )
    }
}

impl TryFrom<QuorumTopologyConfig> for ValidatedQuorumTopology {
    type Error = QuorumTopologyError;

    fn try_from(config: QuorumTopologyConfig) -> Result<Self, Self::Error> {
        validate_topology(
            config.local_replica_id,
            config.members,
            QuorumTopologyMode::ValidatedHa,
            config.consensus_identity,
            false,
            None,
        )
    }
}

fn validate_topology(
    local_replica_id: ReplicaId,
    members: Vec<QuorumReplicaDescriptor>,
    mode: QuorumTopologyMode,
    consensus_identity: Option<SessionConsensusIdentity>,
    allow_correlated_failure_domains: bool,
    fixed_durable_placement_policy: Option<PlacementResiliencePolicy>,
) -> Result<ValidatedQuorumTopology, QuorumTopologyError> {
    if members.len() > QUORUM_TOPOLOGY_MAX_MEMBERS {
        return Err(QuorumTopologyError::MemberCountTooLarge {
            configured: members.len(),
            max: QUORUM_TOPOLOGY_MAX_MEMBERS,
        });
    }

    match mode {
        QuorumTopologyMode::ValidatedHa | QuorumTopologyMode::AttestedHa if members.len() < 3 => {
            return Err(QuorumTopologyError::HaMemberCountTooSmall {
                configured: members.len(),
            });
        }
        QuorumTopologyMode::ValidatedHa | QuorumTopologyMode::AttestedHa
            if members.len().is_multiple_of(2) =>
        {
            return Err(QuorumTopologyError::HaMemberCountMustBeOdd {
                configured: members.len(),
            });
        }
        QuorumTopologyMode::FixedDurableQuorum if !matches!(members.len(), 3 | 5) => {
            return Err(QuorumTopologyError::FixedQuorumMemberCount {
                configured: members.len(),
            });
        }
        QuorumTopologyMode::LabSingleton if members.len() != 1 => {
            return Err(QuorumTopologyError::LabMemberCount {
                configured: members.len(),
            });
        }
        _ => {}
    }

    let self_matches = members
        .iter()
        .filter(|descriptor| descriptor.replica_id == local_replica_id)
        .count();
    match self_matches {
        0 => return Err(QuorumTopologyError::MissingLocalReplica),
        1 => {}
        matches => return Err(QuorumTopologyError::AmbiguousLocalReplica { matches }),
    }

    let mut replica_ids = HashSet::with_capacity(members.len());
    let mut endpoints = HashSet::with_capacity(members.len());
    let mut tls_identities = HashSet::with_capacity(members.len());
    let mut failure_domains = HashSet::with_capacity(members.len());
    let mut backing_identities = HashSet::with_capacity(members.len());
    for descriptor in &members {
        if !replica_ids.insert(descriptor.replica_id.clone()) {
            return Err(QuorumTopologyError::DuplicateReplicaId);
        }
        if !endpoints.insert(descriptor.endpoint.clone()) {
            return Err(QuorumTopologyError::DuplicateEndpoint);
        }
        if !tls_identities.insert(descriptor.tls_identity.clone()) {
            return Err(QuorumTopologyError::DuplicateTlsIdentity);
        }
        if !allow_correlated_failure_domains
            && !failure_domains.insert(descriptor.failure_domain.clone())
        {
            return Err(QuorumTopologyError::DuplicateFailureDomain);
        }
        if !backing_identities.insert(descriptor.backing_identity.clone()) {
            return Err(QuorumTopologyError::DuplicateBackingIdentity);
        }
    }

    let configured_members = members.len();
    let mut consensus_node_ids = BTreeMap::new();
    if let Some(identity) = consensus_identity {
        let component_fingerprints = members
            .iter()
            .map(QuorumReplicaDescriptor::configuration_fingerprint)
            .collect::<Vec<_>>();
        let expected_identity = match (mode, fixed_durable_placement_policy) {
            (QuorumTopologyMode::FixedDurableQuorum, Some(placement_policy)) => {
                derive_fixed_durable_quorum_consensus_identity(
                    identity.cluster_id(),
                    identity.configuration_epoch(),
                    &component_fingerprints,
                    placement_policy,
                )
            }
            _ => SessionConsensusIdentity::new(
                identity.cluster_id(),
                opc_consensus::derive_configuration_id(
                    identity.cluster_id(),
                    identity.configuration_epoch(),
                    &component_fingerprints,
                ),
                identity.configuration_epoch(),
            ),
        };
        if identity != expected_identity {
            return Err(QuorumTopologyError::ConsensusConfigurationIdMismatch);
        }

        let mut admitted_node_ids = HashSet::with_capacity(members.len());
        for descriptor in &members {
            let node_id = opc_consensus::derive_node_id(
                identity.cluster_id(),
                descriptor.replica_id().as_str().as_bytes(),
            )
            .map_err(|_| QuorumTopologyError::DuplicateConsensusNodeId)?;
            if !admitted_node_ids.insert(node_id) {
                return Err(QuorumTopologyError::DuplicateConsensusNodeId);
            }
            consensus_node_ids.insert(descriptor.replica_id().clone(), node_id);
        }
    } else if matches!(
        mode,
        QuorumTopologyMode::ValidatedHa
            | QuorumTopologyMode::AttestedHa
            | QuorumTopologyMode::FixedDurableQuorum
    ) {
        return Err(QuorumTopologyError::MissingConsensusIdentity);
    }

    let required_quorum = (configured_members / 2) + 1;
    let configuration_epoch = consensus_identity
        .map(|identity| identity.configuration_epoch().get())
        .unwrap_or(0);
    Ok(ValidatedQuorumTopology {
        summary: QuorumTopologySummary {
            mode,
            configured_members,
            required_quorum,
            local_replica_id: Some(local_replica_id),
            fixed_durable_placement_policy,
            attestation: TopologyAttestationAdmission::descriptor_only(configuration_epoch),
        },
        members,
        consensus_identity,
        consensus_node_ids,
    })
}
